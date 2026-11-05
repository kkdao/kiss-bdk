//! Two wallets, two signers, one silent payment.
//!
//! Neither signer holds every input key, so each adds one BIP-375 ECDH share
//! per input it owns, and the coordinator derives the output script from all
//! of them. These tests run that from the first message to the finished
//! transaction, and then try to break it at every point where something
//! arrives from outside.
//!
//! The signers are `support/ref_signer.rs`, written from the contract and
//! sharing no checking code with the coordinator. The tests whose names begin
//! with `real_signers` run the same flow against the two real signers'
//! desktop bridges instead; they are `#[ignore]`d because they need those
//! programs, named in `KISS_INTEROP_SIGNER` and `KRUX_INTEROP_SIGNER`.

#[path = "support/ref_signer.rs"]
mod ref_signer;

use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

use bdk_wallet::Wallet;
use bdk_wallet::bitcoin::hashes::Hash;
use bdk_wallet::bitcoin::secp256k1::{Message as SecpMessage, PublicKey, Secp256k1, SecretKey};
use bdk_wallet::bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bdk_wallet::bitcoin::{
    Amount, CompressedPublicKey, FeeRate, Network, OutPoint, Psbt, ScriptBuf, Transaction, TxOut,
    ecdsa,
};
use bdk_wallet::coin_selection::LargestFirstCoinSelection;
use bdk_wallet::test_utils::new_wallet_and_funding_update;
use kiss_bdk::dirtransport::DirTransport;
use kiss_bdk::shared::{self, Kind, Message, Newest, Pass, Received, Role, Session, Stage};
use kiss_bdk::sharedflow::{self, Flow, Progress, SignerLink, Store, Terms, Visit, WalletLink};
use kiss_bdk::sp::{self, SilentPaymentAddress};
use kiss_bdk::spreceive::ScanKeys;
use kiss_bdk::spsend::{placeholder_script, serialize_v2};
use kiss_bdk::{split_kiss_descriptor, spscan};
use psbt_v2::v2::Psbt as PsbtV2;

use ref_signer::{Outcome, RefSigner};

const SATS: u64 = 10_001;
const FEE_RATE: u64 = 2;

// ---------------------------------------------------------------------------
// The cast

/// The person being paid, with the private scan key so a test can look for
/// the payment the way their wallet would.
struct Payee {
    keys: ScanKeys,
    address: String,
    parsed: SilentPaymentAddress,
}

fn payee() -> Payee {
    let secp = Secp256k1::new();
    let keys = ScanKeys {
        scan: SecretKey::from_slice(&[0x5c; 32]).unwrap(),
        spend: SecretKey::from_slice(&[0x5e; 32])
            .unwrap()
            .public_key(&secp),
    };
    let address = keys.code(Network::Signet).to_string();
    assert!(address.starts_with("tsp1"), "{address}");
    let parsed = sp::decode(&address).unwrap();
    assert_eq!(parsed.scan, keys.scan.public_key(&secp));
    assert_eq!(parsed.spend, keys.spend);
    Payee {
        keys,
        address,
        parsed,
    }
}

/// A wallet holding one 50 000 sat coin, with its whole previous transaction.
fn funded(descriptor: &str) -> Wallet {
    let (external, internal) = split_kiss_descriptor(descriptor).unwrap();
    let (mut wallet, _, funding) = new_wallet_and_funding_update(&external, Some(&internal));
    wallet.apply_update(funding).unwrap();
    wallet
}

/// What a wallet builds for its half: an ordinary BDK transaction paying its
/// share to the recipient's placeholder script.
fn half(wallet: &mut Wallet, recipient: &SilentPaymentAddress, sats: u64, fee_rate: u64) -> Psbt {
    let mut builder = wallet.build_tx().coin_selection(LargestFirstCoinSelection);
    builder
        .add_recipient(placeholder_script(recipient), Amount::from_sat(sats))
        .fee_rate(FeeRate::from_sat_per_vb(fee_rate).unwrap());
    builder.finish().unwrap()
}

fn signer_a() -> RefSigner {
    RefSigner::new(&[0xa1; 32])
}

fn signer_b() -> RefSigner {
    RefSigner::new(&[0xb2; 32]).trimmed()
}

/// Both wallets, both signers, and each side's session.
struct Table {
    payee: Payee,
    signer_a: RefSigner,
    signer_b: RefSigner,
    a: Session,
    b: Session,
}

fn message(text: &str) -> Message {
    Message::parse(text).unwrap()
}

/// Hand everything in `from`'s outbox to `to`, as a channel would.
fn deliver(from: &mut Session, to: &mut Session) -> Vec<Received> {
    let sent: Vec<String> = from.outbox.drain(..).collect();
    assert!(!sent.is_empty(), "nothing was waiting to be sent");
    sent.iter()
        .map(|text| to.receive(&message(text)).unwrap())
        .collect()
}

/// Proposal and join: the transaction is fixed, nothing is signed.
fn joined() -> Table {
    let payee = payee();
    let (signer_a, signer_b) = (signer_a(), signer_b());
    let me_a = signer_a.fingerprint().to_string();
    let me_b = signer_b.fingerprint().to_string();

    let mut wallet_a = funded(&signer_a.descriptor());
    let half_a = half(
        &mut wallet_a,
        &payee.parsed,
        shared::share_of(SATS, Role::Start),
        FEE_RATE,
    );
    let mut a = Session::propose(
        &me_a,
        &shared::session_id(b"table"),
        &half_a,
        &payee.address,
        SATS,
        FEE_RATE,
    )
    .unwrap();
    let proposal = shared::read_proposal(&message(&a.outbox.remove(0)), &me_b).unwrap();

    let mut wallet_b = funded(&signer_b.descriptor());
    let half_b = half(
        &mut wallet_b,
        &proposal.recipient,
        shared::share_of(proposal.sats, Role::Join),
        proposal.fee_rate,
    );
    let b = Session::join(&me_b, &proposal, &half_b).unwrap();
    Table {
        payee,
        signer_a,
        signer_b,
        a,
        b,
    }
}

/// One trip to a signer, returning what it said and what the coordinator
/// checked.
fn visit(session: &mut Session, signer: &RefSigner) -> (Outcome, Vec<String>) {
    let outcome = signer.sign(&session.request().unwrap()).unwrap();
    let lines = session.respond(outcome.bytes()).unwrap();
    (outcome, lines)
}

/// B's signer has added its share and A knows.
fn after_first_visit() -> Table {
    let mut table = joined();
    let (outcome, _) = visit(&mut table.b, &table.signer_b);
    assert!(matches!(outcome, Outcome::Share(_)));
    deliver(&mut table.b, &mut table.a);
    table
}

/// A's signer has completed the shares and signed, and B knows.
fn after_second_visit() -> Table {
    let mut table = after_first_visit();
    let (outcome, _) = visit(&mut table.a, &table.signer_a);
    assert!(matches!(outcome, Outcome::Signed(_)));
    deliver(&mut table.a, &mut table.b);
    table
}

/// Parse, change, and serialize again: what a tampering party would do.
fn edited(bytes: &[u8], change: impl FnOnce(&mut PsbtV2)) -> Vec<u8> {
    let mut psbt = PsbtV2::deserialize(bytes).unwrap();
    change(&mut psbt);
    serialize_v2(&psbt).unwrap()
}

/// The same, for the PSBT inside a message.
fn edited_message(text: &str, change: impl FnOnce(&mut PsbtV2)) -> Message {
    let mut altered = message(text);
    let mut psbt = shared::decode(altered.psbt.as_deref().unwrap()).unwrap();
    change(&mut psbt);
    altered.psbt = Some(shared::encode(&psbt).unwrap());
    altered
}

fn error_of<T: std::fmt::Debug>(result: anyhow::Result<T>) -> String {
    format!("{:#}", result.unwrap_err())
}

/// A share with one byte changed that is still a point on the curve, so it
/// gets past the parser and has to be caught by its proof.
fn flipped_share(share: &CompressedPublicKey) -> CompressedPublicKey {
    let original = share.to_bytes();
    for position in 1..33 {
        let mut bytes = original;
        bytes[position] ^= 0x01;
        if let Ok(point) = CompressedPublicKey::from_slice(&bytes) {
            return point;
        }
    }
    unreachable!("half of all x coordinates are on the curve");
}

// ---------------------------------------------------------------------------
// What a finished transaction has to be

/// The coins a transaction spends, read from the state it was built from.
fn prevouts(state: &PsbtV2) -> Vec<TxOut> {
    state
        .inputs
        .iter()
        .map(|input| input.witness_utxo.clone().unwrap())
        .collect()
}

/// Every input is a P2WPKH spend whose witness key hashes to the coin's
/// program and whose signature verifies against this very transaction.
fn assert_signatures_verify(tx: &Transaction, prevouts: &[TxOut]) {
    let secp = Secp256k1::verification_only();
    assert_eq!(tx.input.len(), prevouts.len());
    for (index, (input, spent)) in tx.input.iter().zip(prevouts).enumerate() {
        let witness: Vec<&[u8]> = input.witness.iter().collect();
        assert_eq!(witness.len(), 2, "input {index} is not a P2WPKH spend");
        let signature = ecdsa::Signature::from_slice(witness[0]).unwrap();
        assert_eq!(signature.sighash_type, EcdsaSighashType::All);
        let key = PublicKey::from_slice(witness[1]).unwrap();
        assert_eq!(
            ScriptBuf::new_p2wpkh(&CompressedPublicKey(key).wpubkey_hash()),
            spent.script_pubkey,
            "input {index} is signed by a key its coin does not pay"
        );
        let hash = SighashCache::new(tx)
            .p2wpkh_signature_hash(
                index,
                &spent.script_pubkey,
                spent.value,
                signature.sighash_type,
            )
            .unwrap();
        secp.verify_ecdsa(&SecpMessage::from(hash), &signature.signature, &key)
            .unwrap_or_else(|error| panic!("input {index}: {error}"));
    }
}

/// The fee rate is at least what was asked for and not far above it.
fn assert_fee_rate(tx: &Transaction, prevouts: &[TxOut], fee_rate: u64) -> u64 {
    let spent: u64 = prevouts.iter().map(|out| out.value.to_sat()).sum();
    let paid: u64 = tx.output.iter().map(|out| out.value.to_sat()).sum();
    let fee = spent - paid;
    let vsize = tx.vsize() as u64;
    assert!(
        fee >= fee_rate * vsize,
        "{fee} sats for {vsize} vB is under {fee_rate} sat/vB"
    );
    assert!(
        fee * 100 <= fee_rate * vsize * 105,
        "{fee} sats for {vsize} vB is more than 5% over {fee_rate} sat/vB"
    );
    fee
}

/// The silent payment output is the one BIP-352 gives a lone sender holding
/// every input's private key, and the payee's own scan finds it.
fn assert_pays(
    tx: &Transaction,
    prevouts: &[TxOut],
    private_keys: &[SecretKey],
    payee: &Payee,
    sats: u64,
) {
    let outpoints: Vec<OutPoint> = tx.input.iter().map(|input| input.previous_output).collect();
    let expected = ref_signer::script_from_private_keys(
        private_keys,
        &outpoints,
        &payee.parsed.scan,
        &payee.parsed.spend,
        0,
    );
    let paying: Vec<&TxOut> = tx
        .output
        .iter()
        .filter(|out| out.script_pubkey == expected)
        .collect();
    assert_eq!(
        paying.len(),
        1,
        "no output carries the script derived from the private keys"
    );
    assert_eq!(paying[0].value, Amount::from_sat(sats));
    assert!(
        !tx.output
            .iter()
            .any(|out| out.script_pubkey == placeholder_script(&payee.parsed)),
        "the placeholder script reached the transaction"
    );

    let found = spscan::scan_transaction(&spscan::scanner(&payee.keys), tx, prevouts, 100).unwrap();
    assert_eq!(found.len(), 1, "the payee's scan does not find the payment");
    assert_eq!(found[0].out.amount, Amount::from_sat(sats));
    assert_eq!(found[0].out.script_pubkey, expected);
}

/// The private keys behind a state's inputs, from whichever signer owns each.
fn private_keys(state: &PsbtV2, signers: &[&RefSigner]) -> Vec<SecretKey> {
    state
        .inputs
        .iter()
        .map(|input| {
            signers
                .iter()
                .find_map(|signer| signer.own_key(input))
                .expect("every input belongs to one of the signers")
        })
        .collect()
}

// ---------------------------------------------------------------------------
// The flow, step by step

#[test]
fn two_signers_on_different_seeds_pay_one_silent_payment() {
    let mut table = joined();

    // The proposal is half a transaction: A's coin against the whole amount.
    assert_eq!(table.a.stage, Stage::Proposed);
    assert!(!table.a.my_turn().unwrap());
    assert!(error_of(table.a.request()).contains("never shown to a signer"));

    // B just joined, so B's signer goes first, and can only add its share.
    assert_eq!(table.b.newest, Newest::Joined);
    assert!(table.b.my_turn().unwrap());
    assert_eq!(table.b.pass().unwrap(), Pass::ShareOnly);
    let joined_state = table.b.state().unwrap();
    assert_eq!(joined_state.global.tx_modifiable_flags, 0);
    assert_eq!(joined_state.inputs.len(), 2);
    assert_eq!(joined_state.outputs.len(), 3);

    let (outcome, lines) = visit(&mut table.b, &table.signer_b);
    assert!(matches!(outcome, Outcome::Share(_)), "{outcome:?}");
    assert!(
        lines
            .iter()
            .any(|line| line.starts_with("input 1 share proof OK")),
        "{lines:?}"
    );
    assert!(
        !lines.iter().any(|line| line.contains("signature")),
        "{lines:?}"
    );
    assert!(!table.b.my_turn().unwrap(), "B waits for A after its share");

    // A learns of the join and of B's share in one message.
    let received = deliver(&mut table.b, &mut table.a);
    let Received::Applied(lines) = &received[0] else {
        panic!("{received:?}");
    };
    assert!(
        lines[0].contains("joined: 2 inputs, 3 outputs"),
        "{lines:?}"
    );
    assert!(
        lines
            .iter()
            .any(|line| line.starts_with("input 1 share proof OK"))
    );
    assert_eq!(table.a.stage, Stage::Active);
    assert_eq!(table.a.peer.as_deref(), Some(table.b.me.as_str()));
    assert!(table.a.my_turn().unwrap());
    assert_eq!(table.a.pass().unwrap(), Pass::Sign);

    // A's signer completes the shares, derives the script and signs.
    let (outcome, lines) = visit(&mut table.a, &table.signer_a);
    assert!(matches!(outcome, Outcome::Signed(_)), "{outcome:?}");
    let sp_output = joined_state
        .outputs
        .iter()
        .position(|output| output.sp_v0_info.is_some())
        .unwrap();
    for expected in [
        "input 0 share proof OK".to_string(),
        format!("output {sp_output} script derived from 2 shares"),
        format!("output {sp_output} script from the signer matches"),
        "input 0 signature OK".to_string(),
    ] {
        assert!(
            lines.iter().any(|line| line.starts_with(&expected)),
            "missing {expected:?} in {lines:?}"
        );
    }
    assert!(!table.a.ready().unwrap(), "B has not signed yet");

    // B checks A's share, script and signature, then its signer signs.
    let received = deliver(&mut table.a, &mut table.b);
    let Received::Applied(lines) = &received[0] else {
        panic!("{received:?}");
    };
    assert!(
        lines
            .iter()
            .any(|line| line.starts_with("input 0 signature OK"))
    );
    assert_eq!(table.b.pass().unwrap(), Pass::Sign);
    let (outcome, lines) = visit(&mut table.b, &table.signer_b);
    assert!(matches!(outcome, Outcome::Signed(_)), "{outcome:?}");
    assert!(
        lines
            .iter()
            .any(|line| line.starts_with("input 1 signature OK"))
    );

    // Every input is signed: finalize and extract.
    assert!(table.b.ready().unwrap());
    let state = table.b.state().unwrap();
    let tx = table.b.finalize().unwrap();
    let coins = prevouts(&state);
    assert_signatures_verify(&tx, &coins);
    assert_fee_rate(&tx, &coins, FEE_RATE);
    let keys = private_keys(&state, &[&table.signer_a, &table.signer_b]);
    assert_pays(&tx, &coins, &keys, &table.payee, SATS);

    // A gets B's full state and then the news, and agrees on the transaction.
    table.b.finish(&tx.compute_txid()).unwrap();
    let received = deliver(&mut table.b, &mut table.a);
    assert!(matches!(received[0], Received::Applied(_)), "{received:?}");
    assert_eq!(received[1], Received::Done(tx.compute_txid().to_string()));
    assert_eq!(table.a.stage, Stage::Done);
    assert_eq!(table.a.finalize().unwrap(), tx, "either side can finish");
}

#[test]
fn each_wallet_pays_its_half_and_its_own_part_of_the_fee() {
    let table = after_second_visit();
    let state = table.a.state().unwrap();
    let mine: Vec<bool> = state
        .inputs
        .iter()
        .map(|input| table.signer_a.own_key(input).is_some())
        .collect();
    assert_eq!(mine, [true, false], "A's coin comes first, B's after it");

    // Output 0 or 1 is the payment; A's change kept its place and B's is last.
    let payment = state
        .outputs
        .iter()
        .position(|output| output.sp_v0_info.is_some())
        .unwrap();
    assert_eq!(state.outputs[payment].amount, Amount::from_sat(SATS));
    let change_a = 1 - payment;
    let change_b = 2;

    let spent = |index: usize| {
        state.inputs[index]
            .witness_utxo
            .as_ref()
            .unwrap()
            .value
            .to_sat()
    };
    let paid_by_a = spent(0) - state.outputs[change_a].amount.to_sat();
    let paid_by_b = spent(1) - state.outputs[change_b].amount.to_sat();
    let fee = shared::fee(&state).unwrap().to_sat();
    assert_eq!(paid_by_a + paid_by_b, SATS + fee);

    // The odd satoshi is A's, and the fee parts differ by at most the rounding
    // of two identical halves.
    let fee_a = paid_by_a - shared::share_of(SATS, Role::Start);
    let fee_b = paid_by_b - shared::share_of(SATS, Role::Join);
    assert_eq!(shared::share_of(SATS, Role::Start), SATS / 2 + 1);
    assert!(fee_a.abs_diff(fee_b) <= 1, "{fee_a} against {fee_b}");
    assert_eq!(fee_a + fee_b, fee);
}

#[test]
fn a_signer_request_never_carries_the_other_signers_signature() {
    let table = after_second_visit();

    // B holds A's verified signature, and would pass it on in an update.
    let state = table.b.state().unwrap();
    assert_eq!(shared::signed_inputs(&state), [0].into());
    assert!(!state.inputs[0].partial_sigs.is_empty());

    // But the request for B's signer has none of it, and everything else.
    let request = PsbtV2::deserialize(&table.b.request().unwrap()).unwrap();
    for (index, input) in request.inputs.iter().enumerate() {
        assert!(input.partial_sigs.is_empty(), "input {index}");
        assert!(input.tap_key_sig.is_none(), "input {index}");
        assert!(input.final_script_witness.is_none(), "input {index}");
        assert_eq!(input.sp_ecdh_shares.len(), 1, "input {index}");
        assert_eq!(input.sp_dleq_proofs.len(), 1, "input {index}");
        assert!(input.witness_utxo.is_some(), "input {index}");
        assert!(input.non_witness_utxo.is_some(), "input {index}");
        assert!(!input.bip32_derivations.is_empty(), "input {index}");
    }
    assert_eq!(request.global.tx_modifiable_flags, 0);
    assert!(
        request
            .outputs
            .iter()
            .all(|out| !out.script_pubkey.is_empty())
    );

    // The same holds for what A's signer was shown on its own visit: B had
    // not signed, and A's request is rebuilt from a state with no signature.
    let earlier = after_first_visit();
    let request = PsbtV2::deserialize(&earlier.a.request().unwrap()).unwrap();
    assert!(
        request
            .inputs
            .iter()
            .all(|input| input.partial_sigs.is_empty())
    );
    assert!(
        request
            .outputs
            .iter()
            .any(|out| out.script_pubkey.is_empty()),
        "the script is absent until A's signer derives it"
    );
}

#[test]
fn a_request_before_the_script_is_derived_has_no_out_script_field() {
    // BIP-375: PSBT_OUT_SCRIPT is absent on a silent payment output until it
    // is derived. Absent, not empty.
    let table = joined();
    let request = table.b.request().unwrap();
    assert!(
        !request
            .windows(3)
            .any(|window| window == [0x01, 0x04, 0x00]),
        "an empty PSBT_OUT_SCRIPT reached the signer"
    );
    let proposal = shared::decode(&table.a.psbt).unwrap();
    assert_eq!(proposal.global.tx_modifiable_flags, 0x03);
}

// ---------------------------------------------------------------------------
// Things that must be refused, each by name

#[test]
fn refuses_a_flipped_byte_in_a_share() {
    // From this wallet's own signer.
    let mut table = joined();
    let answer = table.signer_b.sign(&table.b.request().unwrap()).unwrap();
    let tampered = edited(answer.bytes(), |psbt| {
        let (scan, share) = psbt.inputs[1].sp_ecdh_shares.iter().next().unwrap();
        let (scan, share) = (*scan, flipped_share(share));
        psbt.inputs[1].sp_ecdh_shares.insert(scan, share);
    });
    let before = table.b.clone();
    let error = error_of(table.b.respond(&tampered));
    assert!(error.contains("input 1"), "{error}");
    assert!(
        error.contains(&table.signer_b.fingerprint().to_string()),
        "{error}"
    );
    assert!(error.contains("ECDH share"), "{error}");
    assert!(error.contains("DLEQ proof"), "{error}");
    assert_eq!(table.b, before, "a refused answer changes nothing");

    // A byte flipped in the raw bytes either stops being a point or fails its
    // proof. Both are refusals.
    let share = PsbtV2::deserialize(answer.bytes()).unwrap().inputs[1]
        .sp_ecdh_shares
        .values()
        .next()
        .unwrap()
        .to_bytes();
    let at = answer
        .bytes()
        .windows(33)
        .position(|window| window == share)
        .unwrap();
    for offset in [1, 16, 32] {
        let mut raw = answer.bytes().to_vec();
        raw[at + offset] ^= 0x40;
        let error = error_of(table.b.respond(&raw));
        assert!(
            error.contains("DLEQ proof") || error.contains("not a valid PSBTv2"),
            "{error}"
        );
    }

    // From the other wallet.
    table.b.respond(answer.bytes()).unwrap();
    let update = edited_message(&table.b.outbox[0], |psbt| {
        let (scan, share) = psbt.inputs[1].sp_ecdh_shares.iter().next().unwrap();
        let (scan, share) = (*scan, flipped_share(share));
        psbt.inputs[1].sp_ecdh_shares.insert(scan, share);
    });
    let before = table.a.clone();
    let error = error_of(table.a.receive(&update));
    assert!(error.contains("input 1"), "{error}");
    assert!(
        error.contains(&table.signer_b.fingerprint().to_string()),
        "{error}"
    );
    assert!(error.contains("the other wallet"), "{error}");
    assert!(error.contains("DLEQ proof"), "{error}");
    assert_eq!(table.a, before, "a refused message changes nothing");
}

#[test]
fn refuses_a_flipped_byte_in_a_proof() {
    let mut table = joined();
    let answer = table.signer_b.sign(&table.b.request().unwrap()).unwrap();
    for position in [0, 31, 32, 63] {
        let tampered = edited(answer.bytes(), |psbt| {
            let (scan, proof) = psbt.inputs[1].sp_dleq_proofs.iter().next().unwrap();
            let mut bytes = *proof.as_bytes();
            bytes[position] ^= 0x01;
            let scan = *scan;
            psbt.inputs[1].sp_dleq_proofs.insert(scan, bytes.into());
        });
        let error = error_of(table.b.respond(&tampered));
        assert!(error.contains("input 1"), "byte {position}: {error}");
        assert!(error.contains("DLEQ proof"), "byte {position}: {error}");
    }

    table.b.respond(answer.bytes()).unwrap();
    let update = edited_message(&table.b.outbox[0], |psbt| {
        let (scan, proof) = psbt.inputs[1].sp_dleq_proofs.iter().next().unwrap();
        let mut bytes = *proof.as_bytes();
        bytes[40] ^= 0x01;
        let scan = *scan;
        psbt.inputs[1].sp_dleq_proofs.insert(scan, bytes.into());
    });
    let error = error_of(table.a.receive(&update));
    assert!(
        error.contains("input 1") && error.contains("DLEQ proof"),
        "{error}"
    );
    assert_eq!(table.a.stage, Stage::Proposed, "nothing was taken from it");
}

#[test]
fn refuses_a_share_moved_to_the_wrong_input() {
    // B's share is honest, and so is its proof. On A's input it proves
    // nothing: the proof is for B's key, and input 0 pays A's.
    let mut table = joined();
    visit(&mut table.b, &table.signer_b);
    let update = edited_message(&table.b.outbox[0], |psbt| {
        let shares = std::mem::take(&mut psbt.inputs[1].sp_ecdh_shares);
        let proofs = std::mem::take(&mut psbt.inputs[1].sp_dleq_proofs);
        psbt.inputs[0].sp_ecdh_shares = shares;
        psbt.inputs[0].sp_dleq_proofs = proofs;
    });
    let error = error_of(table.a.receive(&update));
    assert!(error.contains("input 0"), "{error}");
    assert!(
        error.contains(&table.signer_a.fingerprint().to_string()),
        "{error}"
    );
    assert!(error.contains("for this input's key"), "{error}");

    // The same when it comes back from this wallet's own signer: after the
    // real update, A's signer answers with its share on B's input.
    deliver(&mut table.b, &mut table.a);
    let answer = table.signer_a.sign(&table.a.request().unwrap()).unwrap();
    let swapped = edited(answer.bytes(), |psbt| {
        let (first, second) = psbt.inputs.split_at_mut(1);
        std::mem::swap(&mut first[0].sp_ecdh_shares, &mut second[0].sp_ecdh_shares);
        std::mem::swap(&mut first[0].sp_dleq_proofs, &mut second[0].sp_dleq_proofs);
    });
    let error = error_of(table.a.respond(&swapped));
    assert!(error.contains("for this input's key"), "{error}");
    assert!(error.contains("the signer"), "{error}");
}

#[test]
fn refuses_a_wrong_script_from_a_signer() {
    let mut table = after_first_visit();
    let answer = table.signer_a.sign(&table.a.request().unwrap()).unwrap();
    let redirected = edited(answer.bytes(), |psbt| {
        let output = psbt
            .outputs
            .iter_mut()
            .find(|output| output.sp_v0_info.is_some())
            .unwrap();
        let mut script = output.script_pubkey.to_bytes();
        *script.last_mut().unwrap() ^= 0x01;
        output.script_pubkey = script.into();
    });
    let before = table.a.clone();
    let error = error_of(table.a.respond(&redirected));
    assert!(
        error.contains("does not pay the silent payment address"),
        "{error}"
    );
    assert!(error.contains("the signer"), "{error}");
    assert_eq!(table.a, before);

    // And once the script is known, a different one from B's signer.
    let mut table = after_second_visit();
    let answer = table.signer_b.sign(&table.b.request().unwrap()).unwrap();
    let redirected = edited(answer.bytes(), |psbt| {
        let output = psbt
            .outputs
            .iter_mut()
            .find(|output| output.sp_v0_info.is_some())
            .unwrap();
        output.script_pubkey = placeholder_script(&payee().parsed);
    });
    let error = error_of(table.b.respond(&redirected));
    assert!(
        error.contains("does not pay the silent payment address"),
        "{error}"
    );
}

#[test]
fn refuses_a_script_that_arrives_before_every_share() {
    // B's signer cannot know the script on its first visit. One that turns up
    // anyway was not derived from the shares.
    let mut table = joined();
    let answer = table.signer_b.sign(&table.b.request().unwrap()).unwrap();
    let early = edited(answer.bytes(), |psbt| {
        let output = psbt
            .outputs
            .iter_mut()
            .find(|output| output.sp_v0_info.is_some())
            .unwrap();
        output.script_pubkey = placeholder_script(&payee().parsed);
    });
    let error = error_of(table.b.respond(&early));
    assert!(error.contains("input 0 has no ECDH share yet"), "{error}");
    assert!(
        error.contains("a script cannot exist before every share does"),
        "{error}"
    );
}

#[test]
fn refuses_a_changed_amount_or_recipient_in_a_peer_update() {
    let payment = |psbt: &PsbtV2| {
        psbt.outputs
            .iter()
            .position(|output| output.sp_v0_info.is_some())
            .unwrap()
    };

    // In the update that tells A about the join.
    let mut table = joined();
    visit(&mut table.b, &table.signer_b);
    let text = table.b.outbox[0].clone();

    let less = edited_message(&text, |psbt| {
        let index = payment(psbt);
        psbt.outputs[index].amount = Amount::from_sat(SATS - 1);
    });
    let error = error_of(table.a.receive(&less));
    assert!(
        error.contains("recipient or amount that was not agreed"),
        "{error}"
    );

    let elsewhere = edited_message(&text, |psbt| {
        let index = payment(psbt);
        psbt.outputs[index].sp_v0_info.as_mut().unwrap()[40] ^= 0x01;
    });
    let error = error_of(table.a.receive(&elsewhere));
    assert!(
        error.contains("recipient or amount that was not agreed"),
        "{error}"
    );

    let robbed = edited_message(&text, |psbt| {
        let change = 1 - payment(psbt);
        psbt.outputs[change].amount -= Amount::from_sat(1_000);
    });
    let error = error_of(table.a.receive(&robbed));
    assert!(error.contains("this wallet's change output"), "{error}");

    let dropped = edited_message(&text, |psbt| {
        psbt.inputs.remove(0);
        psbt.global.input_count = 1;
    });
    let error = error_of(table.a.receive(&dropped));
    assert!(
        error.contains("dropped one of this wallet's coins"),
        "{error}"
    );
    assert_eq!(table.a.stage, Stage::Proposed);

    // And in a later update, when the transaction is fixed.
    let mut table = after_first_visit();
    visit(&mut table.a, &table.signer_a);
    let text = table.a.outbox[0].clone();

    let less = edited_message(&text, |psbt| {
        let index = payment(psbt);
        psbt.outputs[index].amount = Amount::from_sat(SATS - 1);
    });
    let error = error_of(table.b.receive(&less));
    assert!(
        error.contains("the other wallet changed the amount of output"),
        "{error}"
    );

    let elsewhere = edited_message(&text, |psbt| {
        let index = payment(psbt);
        psbt.outputs[index].sp_v0_info.as_mut().unwrap()[40] ^= 0x01;
    });
    let error = error_of(table.b.receive(&elsewhere));
    assert!(
        error.contains("the other wallet changed the silent payment recipient of output"),
        "{error}"
    );

    let rerouted = edited_message(&text, |psbt| {
        psbt.outputs[2].script_pubkey = ScriptBuf::new_p2wpkh(
            &bdk_wallet::bitcoin::WPubkeyHash::from_byte_array([0x11; 20]),
        );
    });
    let error = error_of(table.b.receive(&rerouted));
    assert!(
        error.contains("the other wallet changed the script of output 2"),
        "{error}"
    );

    let before = table.b.clone();
    assert!(table.b.receive(&less).is_err());
    assert_eq!(table.b, before, "a refused message changes nothing");
}

#[test]
fn refuses_to_finalize_with_a_share_missing() {
    let mut table = after_second_visit();
    visit(&mut table.b, &table.signer_b);
    assert!(table.b.ready().unwrap());
    let complete = table.b.state().unwrap();
    shared::finalize(&complete).unwrap();

    for input in [0, 1] {
        let mut missing = complete.clone();
        missing.inputs[input].sp_ecdh_shares.clear();
        missing.inputs[input].sp_dleq_proofs.clear();
        let error = error_of(shared::finalize(&missing));
        assert!(error.contains(&format!("input {input}")), "{error}");
        assert!(error.contains("no ECDH share"), "{error}");
    }

    // The other things a finished state must still prove, one at a time.
    let mut unsigned = complete.clone();
    unsigned.inputs[1].partial_sigs.clear();
    let error = error_of(shared::finalize(&unsigned));
    assert!(
        error.contains("input 1") && error.contains("is not signed yet"),
        "{error}"
    );

    let mut repaid = complete.clone();
    repaid.outputs[2].amount += Amount::from_sat(1);
    let error = error_of(shared::finalize(&repaid));
    assert!(
        error.contains("signature is not valid for this transaction"),
        "{error}"
    );

    let mut inflated = complete.clone();
    inflated.inputs[0].witness_utxo.as_mut().unwrap().value += Amount::from_sat(1);
    let error = error_of(shared::finalize(&inflated));
    assert!(
        error.contains("is not the output its previous transaction created"),
        "{error}"
    );
}

#[test]
fn refuses_a_signature_that_is_not_for_this_transaction() {
    // A's signer signs a transaction with one satoshi moved. The share and the
    // script are right, so only the signature check can catch it.
    let mut table = after_first_visit();
    let request = edited(&table.a.request().unwrap(), |psbt| {
        psbt.outputs[2].amount -= Amount::from_sat(1);
    });
    let forged = table.signer_a.sign(&request).unwrap();
    let answer = edited(forged.bytes(), |psbt| {
        psbt.outputs[2].amount += Amount::from_sat(1);
    });
    let error = error_of(table.a.respond(&answer));
    assert!(error.contains("input 0"), "{error}");
    assert!(
        error.contains("signature is not valid for this transaction"),
        "{error}"
    );

    // The same signature relayed by the other wallet.
    let mut table = after_first_visit();
    visit(&mut table.a, &table.signer_a);
    let update = edited_message(&table.a.outbox[0], |psbt| {
        let (key, signature) = psbt.inputs[0].partial_sigs.iter().next().unwrap();
        let mut bytes = signature.signature.serialize_compact();
        bytes[40] ^= 0x01;
        let mut broken = *signature;
        broken.signature =
            bdk_wallet::bitcoin::secp256k1::ecdsa::Signature::from_compact(&bytes).unwrap();
        let key = *key;
        psbt.inputs[0].partial_sigs.insert(key, broken);
    });
    let error = error_of(table.b.receive(&update));
    assert!(error.contains("input 0"), "{error}");
    assert!(error.contains("signature is not valid"), "{error}");
}

#[test]
fn refuses_a_signers_signature_on_a_coin_that_is_not_its_wallets() {
    // The request never carries A's signature, so one in B's signer's answer
    // was put there by someone.
    let mut table = after_second_visit();
    let held = table.b.state().unwrap().inputs[0].partial_sigs.clone();
    let answer = table.signer_b.sign(&table.b.request().unwrap()).unwrap();
    let padded = edited(answer.bytes(), |psbt| {
        psbt.inputs[0].partial_sigs = held;
    });
    let error = error_of(table.b.respond(&padded));
    assert!(
        error.contains("signature for input 0, which is not this wallet's coin"),
        "{error}"
    );
}

#[test]
fn refuses_an_answer_that_adds_nothing_and_ignores_stale_messages() {
    let mut table = joined();
    let request = table.b.request().unwrap();
    let error = error_of(table.b.respond(&request));
    assert!(error.contains("adds nothing"), "{error}");

    // The proposal again, a message for another send, and B's own message.
    let (_, _) = visit(&mut table.b, &table.signer_b);
    let update = table.b.outbox[0].clone();
    assert!(matches!(
        table.b.receive(&message(&update)).unwrap(),
        Received::Ignored(_)
    ));
    let mut other = message(&update);
    other.session = "ffffffffffffffff".into();
    assert!(matches!(
        table.a.receive(&other).unwrap(),
        Received::Ignored(_)
    ));

    // The same update twice: applied once, then nothing new.
    assert!(matches!(
        table.a.receive(&message(&update)).unwrap(),
        Received::Applied(_)
    ));
    let before = table.a.clone();
    assert!(matches!(
        table.a.receive(&message(&update)).unwrap(),
        Received::Ignored(_)
    ));
    assert_eq!(table.a, before);

    // An older state after a newer one: A has signed, B's first update comes
    // round again. It must not hand the turn back to A or drop anything.
    visit(&mut table.a, &table.signer_a);
    let before = table.a.clone();
    assert!(matches!(
        table.a.receive(&message(&update)).unwrap(),
        Received::Ignored(_)
    ));
    assert_eq!(table.a, before);
    assert!(!table.a.my_turn().unwrap());

    // A third wallet speaking in this session is not the one that joined.
    let mut stranger = message(&update);
    stranger.from = "0badf00d".into();
    assert!(matches!(
        table.a.receive(&stranger).unwrap(),
        Received::Ignored(_)
    ));
}

#[test]
fn refuses_news_of_a_different_transaction() {
    let mut table = after_second_visit();
    visit(&mut table.b, &table.signer_b);
    let tx = table.b.finalize().unwrap();
    table.b.finish(&tx.compute_txid()).unwrap();
    let done = message(table.b.outbox.last().unwrap());
    assert_eq!(done.kind, Kind::Done);

    let mut lie = done.clone();
    lie.txid = Some("11".repeat(32));
    let before = table.a.clone();
    let error = error_of(table.a.receive(&lie));
    assert!(
        error.contains("this shared send's transaction is"),
        "{error}"
    );
    assert_eq!(table.a, before);

    // The honest one, even without the update before it: it carries the state.
    assert_eq!(
        table.a.receive(&done).unwrap(),
        Received::Done(tx.compute_txid().to_string())
    );
    assert_eq!(
        table.a.txid.as_deref(),
        Some(tx.compute_txid().to_string().as_str())
    );
    assert!(matches!(
        table.a.receive(&done).unwrap(),
        Received::Ignored(_)
    ));
    assert!(table.a.receive(&lie).is_err());
}

#[test]
fn refuses_a_proposal_that_does_not_say_what_its_message_says() {
    let table = joined();
    let me_b = table.b.me.clone();
    let mut a = table.a.clone();
    a.stage = Stage::Proposed;
    let text = a.proposal_message().unwrap().encode();
    shared::read_proposal(&message(&text), &me_b).unwrap();

    let mut more = message(&text);
    more.sats = Some(SATS + 1);
    let error = error_of(shared::read_proposal(&more, &me_b));
    assert!(error.contains("not the 10002 it names"), "{error}");

    let mut elsewhere = message(&text);
    let other = ScanKeys {
        scan: SecretKey::from_slice(&[0x61; 32]).unwrap(),
        spend: table.payee.keys.spend,
    };
    elsewhere.to = Some(other.code(Network::Signet).to_string());
    let error = error_of(shared::read_proposal(&elsewhere, &me_b));
    assert!(
        error.contains("does not pay the recipient it names"),
        "{error}"
    );

    let closed = edited_message(&text, |psbt| psbt.global.tx_modifiable_flags = 0);
    let error = error_of(shared::read_proposal(&closed, &me_b));
    assert!(error.contains("not open for another wallet"), "{error}");

    let unproven = edited_message(&text, |psbt| psbt.inputs[0].non_witness_utxo = None);
    let error = error_of(shared::read_proposal(&unproven, &me_b));
    assert!(
        error.contains("does not carry its previous transaction"),
        "{error}"
    );

    let inflated = edited_message(&text, |psbt| {
        psbt.inputs[0].witness_utxo.as_mut().unwrap().value += Amount::from_sat(1);
    });
    let error = error_of(shared::read_proposal(&inflated, &me_b));
    assert!(
        error.contains("is not the output its previous transaction created"),
        "{error}"
    );

    let unbound = edited_message(&text, |psbt| psbt.inputs[0].bip32_derivations.clear());
    let error = error_of(shared::read_proposal(&unbound, &me_b));
    assert!(error.contains("no BIP-32 derivation key"), "{error}");

    let mine = error_of(shared::read_proposal(&message(&text), &a.me));
    assert!(mine.contains("two wallets with different seeds"), "{mine}");
}

#[test]
fn refuses_a_half_that_leaves_the_fee_short() {
    // A's half with its change raised: A pays less than its part, so the two
    // halves together miss the rate. B is the one who can see it.
    let table = joined();
    let mut a = table.a.clone();
    a.stage = Stage::Proposed;
    let text = a.proposal_message().unwrap().encode();
    let greedy = edited_message(&text, |psbt| {
        let change = psbt
            .outputs
            .iter()
            .position(|output| output.sp_v0_info.is_none())
            .unwrap();
        psbt.outputs[change].amount += Amount::from_sat(200);
    });
    let proposal = shared::read_proposal(&greedy, &table.b.me).unwrap();
    let mut wallet_b = funded(&table.signer_b.descriptor());
    let half_b = half(
        &mut wallet_b,
        &proposal.recipient,
        shared::share_of(proposal.sats, Role::Join),
        proposal.fee_rate,
    );
    let error = error_of(Session::join(&table.b.me, &proposal, &half_b));
    assert!(error.contains("do not pay the agreed fee"), "{error}");
    assert!(error.contains("less than the"), "{error}");

    // And A sees it when B's half is the short one.
    let mut table = joined();
    visit(&mut table.b, &table.signer_b);
    let greedy = edited_message(&table.b.outbox[0], |psbt| {
        psbt.outputs[2].amount += Amount::from_sat(200);
    });
    let error = error_of(table.a.receive(&greedy));
    assert!(error.contains("the half the other wallet added"), "{error}");
}

#[test]
fn one_seed_on_both_sides_is_not_a_shared_send() {
    let payee = payee();
    let signer = signer_a();
    let me = signer.fingerprint().to_string();
    let mut wallet = funded(&signer.descriptor());
    let half_a = half(
        &mut wallet,
        &payee.parsed,
        shared::share_of(SATS, Role::Start),
        FEE_RATE,
    );
    let mut a = Session::propose(
        &me,
        "0011223344556677",
        &half_a,
        &payee.address,
        SATS,
        FEE_RATE,
    )
    .unwrap();
    let text = a.outbox.remove(0);

    // The same wallet answering its own proposal.
    let error = error_of(shared::read_proposal(&message(&text), &me));
    assert!(error.contains("different seeds"), "{error}");

    // Another coordinator with the same seed and so the same coin.
    let mut relabelled = message(&text);
    relabelled.from = "0badf00d".into();
    let proposal = shared::read_proposal(&relabelled, &me).unwrap();
    let mut twin = funded(&signer.descriptor());
    let half_b = half(
        &mut twin,
        &payee.parsed,
        shared::share_of(SATS, Role::Join),
        FEE_RATE,
    );
    let error = error_of(Session::join(&me, &proposal, &half_b));
    assert!(error.contains("two different wallets"), "{error}");
}

#[test]
fn a_session_survives_being_written_down_and_read_back_at_every_step() {
    let scratch = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let store = Store::in_wallet(scratch.path());
    assert_eq!(store.load().unwrap(), sharedflow::Saved::default());

    let reload = |session: &Session| {
        store
            .save(&sharedflow::Saved {
                inbox: vec!["kept".into()],
                session: Some(session.clone()),
            })
            .unwrap();
        let saved = store.load().unwrap();
        assert_eq!(saved.inbox, ["kept"]);
        let back = saved.session.unwrap();
        assert_eq!(back, *session);
        back
    };

    let mut table = joined();
    table.a = reload(&table.a);
    table.b = reload(&table.b);
    visit(&mut table.b, &table.signer_b);
    table.b = reload(&table.b);
    assert_eq!(table.b.outbox.len(), 1, "the unsent update is in the file");
    deliver(&mut table.b, &mut table.a);
    table.a = reload(&table.a);
    assert!(table.a.my_turn().unwrap());
    visit(&mut table.a, &table.signer_a);
    table.a = reload(&table.a);
    deliver(&mut table.a, &mut table.b);
    table.b = reload(&table.b);
    visit(&mut table.b, &table.signer_b);
    table.b = reload(&table.b);
    assert!(table.b.ready().unwrap());
    let tx = table.b.finalize().unwrap();
    table.b.finish(&tx.compute_txid()).unwrap();
    table.b = reload(&table.b);
    assert_eq!(table.b.stage, Stage::Done);

    // A finished session is moved aside, not lost, when a new one starts.
    let mut saved = store.load().unwrap();
    let kept = store.retire(&mut saved).unwrap().unwrap();
    assert!(saved.session.is_none());
    assert_eq!(store.load().unwrap().session, None);
    let record: sharedflow::Saved = serde_json::from_slice(&std::fs::read(kept).unwrap()).unwrap();
    assert_eq!(record.session.unwrap().txid, table.b.txid);
}

#[test]
fn says_where_a_shared_send_stands() {
    let table = joined();
    let lines = table.a.describe().unwrap().join("\n");
    assert!(
        lines.contains("state: proposed, waiting for the other wallet to join"),
        "{lines}"
    );
    let lines = table.b.describe().unwrap().join("\n");
    assert!(
        lines.contains("to add its share (nothing is signed in this step)"),
        "{lines}"
    );
    assert!(
        lines.contains("input 0: 50000 sats, other wallet"),
        "{lines}"
    );
    assert!(
        lines.contains("input 1: 50000 sats, this wallet"),
        "{lines}"
    );
    assert!(lines.contains("share missing, not signed"), "{lines}");
    assert!(
        lines.contains("silent payment script not derived yet"),
        "{lines}"
    );

    let table = after_second_visit();
    let lines = table.a.describe().unwrap().join("\n");
    assert!(
        lines.contains("state: waiting for the other wallet"),
        "{lines}"
    );
    let lines = table.b.describe().unwrap().join("\n");
    assert!(
        lines.contains("input 0: 50000 sats, other wallet"),
        "{lines}"
    );
    assert!(lines.contains("share verified, signed"), "{lines}");
    assert!(lines.contains("silent payment script derived"), "{lines}");
    assert!(
        lines.contains("this wallet's signer goes next, to review and sign"),
        "{lines}"
    );
}

// ---------------------------------------------------------------------------
// The same send as the commands run it: session files and a channel folder

/// A wallet as a [`Flow`] sees it: one funded BDK wallet, and a list that
/// stands in for the network.
struct TestWallet {
    wallet: Wallet,
    sent: Rc<RefCell<Vec<Transaction>>>,
}

impl WalletLink for TestWallet {
    fn fund(
        &mut self,
        recipient: &SilentPaymentAddress,
        sats: u64,
        fee_rate: u64,
    ) -> anyhow::Result<Psbt> {
        Ok(half(&mut self.wallet, recipient, sats, fee_rate))
    }

    fn broadcast(&mut self, tx: &Transaction) -> anyhow::Result<()> {
        self.sent.borrow_mut().push(tx.clone());
        Ok(())
    }
}

/// A reference signer behind the [`SignerLink`] a flow talks to, counting
/// its visits.
struct TestSigner {
    signer: RefSigner,
    visits: Vec<Pass>,
}

impl SignerLink for TestSigner {
    fn sign(&mut self, request: &[u8], visit: &Visit) -> anyhow::Result<Vec<u8>> {
        self.visits.push(visit.pass);
        let outcome = self
            .signer
            .sign(request)
            .map_err(|refusal| anyhow::anyhow!("the signer refused: {}", refusal.0))?;
        Ok(outcome.bytes().to_vec())
    }
}

/// Step one side until it has nothing more to do without the other side.
fn run_until_idle(flow: &mut Flow<'_>) -> Option<String> {
    for _ in 0..50 {
        match flow.step(Duration::ZERO).unwrap() {
            Progress::Moved => {}
            Progress::Waiting => return None,
            Progress::Done(txid) => return Some(txid),
        }
    }
    panic!("a flow kept moving without ever waiting");
}

#[test]
fn two_signers_pay_one_silent_payment_over_a_channel_folder() {
    let payee = payee();
    let sent = Rc::new(RefCell::new(Vec::new()));
    let channel = tempfile::tempdir().unwrap();
    let (dir_a, dir_b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (store_a, store_b) = (
        Store::in_wallet(dir_a.path()),
        Store::in_wallet(dir_b.path()),
    );

    let mut signer_a = TestSigner {
        signer: signer_a(),
        visits: Vec::new(),
    };
    let mut signer_b = TestSigner {
        signer: signer_b(),
        visits: Vec::new(),
    };
    let me_a = signer_a.signer.fingerprint().to_string();
    let me_b = signer_b.signer.fingerprint().to_string();
    let mut wallet_a = TestWallet {
        wallet: funded(&signer_a.signer.descriptor()),
        sent: sent.clone(),
    };
    let mut wallet_b = TestWallet {
        wallet: funded(&signer_b.signer.descriptor()),
        sent: sent.clone(),
    };
    let mut channel_a = DirTransport::open(channel.path(), &me_a).unwrap();
    let mut channel_b = DirTransport::open(channel.path(), &me_b).unwrap();

    assert!(
        sharedflow::begin(
            &store_a,
            &mut wallet_a,
            &me_a,
            &payee.address,
            SATS,
            FEE_RATE,
            b"dir"
        )
        .unwrap()
    );
    // Running the same command again carries the same send on.
    assert!(
        !sharedflow::begin(
            &store_a,
            &mut wallet_a,
            &me_a,
            &payee.address,
            SATS,
            FEE_RATE,
            b"dir"
        )
        .unwrap()
    );

    let mut said_a = Vec::new();
    let mut said_b = Vec::new();
    let mut say_a = |line: &str| said_a.push(line.to_string());
    let mut say_b = |line: &str| said_b.push(line.to_string());
    let mut flow_a = Flow {
        store: &store_a,
        me: me_a.clone(),
        transport: &mut channel_a,
        wallet: &mut wallet_a,
        signer: &mut signer_a,
        say: &mut say_a,
        grace: Duration::ZERO,
        terms: None,
        waited: false,
    };
    let mut flow_b = Flow {
        store: &store_b,
        me: me_b.clone(),
        transport: &mut channel_b,
        wallet: &mut wallet_b,
        signer: &mut signer_b,
        say: &mut say_b,
        grace: Duration::ZERO,
        terms: Some(Terms {
            to: Some(payee.address.clone()),
            sats: Some(SATS),
        }),
        waited: false,
    };

    let mut done = (None, None);
    for _ in 0..10 {
        if done.0.is_none() {
            done.0 = run_until_idle(&mut flow_a);
        }
        if done.1.is_none() {
            done.1 = run_until_idle(&mut flow_b);
        }
        if done.0.is_some() && done.1.is_some() {
            break;
        }
    }
    drop((flow_a, flow_b));
    let (Some(txid_a), Some(txid_b)) = done else {
        panic!("the send did not finish: {said_a:?} {said_b:?}");
    };
    assert_eq!(txid_a, txid_b);

    // Three signer visits in the order the contract gives, one broadcast.
    assert_eq!(signer_b.visits, vec![Pass::ShareOnly, Pass::Sign]);
    assert_eq!(signer_a.visits, vec![Pass::Sign]);
    let sent = sent.borrow();
    assert_eq!(
        sent.len(),
        1,
        "the transaction was broadcast more than once"
    );
    let tx = &sent[0];
    assert_eq!(tx.compute_txid().to_string(), txid_a);
    assert!(
        said_b
            .iter()
            .any(|line| line.starts_with(&format!("broadcast: {txid_a}")))
    );
    assert!(
        said_a
            .iter()
            .any(|line| line.contains("the other wallet broadcast the payment"))
    );
    assert!(
        said_a
            .iter()
            .any(|line| line.starts_with("input 1 share proof OK")),
        "{said_a:?}"
    );

    let state = store_b.load().unwrap().session.unwrap().state().unwrap();
    let coins = prevouts(&state);
    assert_signatures_verify(tx, &coins);
    assert_fee_rate(tx, &coins, FEE_RATE);
    let keys = private_keys(&state, &[&signer_a.signer, &signer_b.signer]);
    assert_pays(tx, &coins, &keys, &payee, SATS);

    // Both session files agree, and a restarted command has nothing to do.
    for store in [&store_a, &store_b] {
        let saved = store.load().unwrap();
        assert!(saved.inbox.is_empty());
        let session = saved.session.unwrap();
        assert_eq!(session.stage, Stage::Done);
        assert_eq!(session.txid.as_deref(), Some(txid_a.as_str()));
        assert!(session.outbox.is_empty());
    }
}

// ---------------------------------------------------------------------------
// The same send through the command line's file steps

fn kiss_bdk(wallet_dir: &std::path::Path, args: &[&str]) -> String {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_kiss-bdk"))
        .arg("--wallet-dir")
        .arg(wallet_dir)
        .args(args)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{args:?} failed: {stdout}{stderr}");
    stdout
}

/// A regtest wallet folder made by `init`, holding the same 50 000 sat coin
/// the other tests use.
fn wallet_folder(root: &std::path::Path, name: &str, signer: &RefSigner) -> std::path::PathBuf {
    let dir = root.join(name);
    let descriptor = signer.descriptor();
    kiss_bdk(
        &dir,
        &[
            "init",
            "--network",
            "regtest",
            "--descriptor",
            &descriptor,
            "--esplora",
            "http://127.0.0.1:1",
        ],
    );
    let (external, internal) = split_kiss_descriptor(&descriptor).unwrap();
    let mut connection = bdk_wallet::rusqlite::Connection::open(dir.join("wallet.sqlite")).unwrap();
    let mut wallet = Wallet::load()
        .descriptor(bdk_wallet::KeychainKind::External, Some(external.clone()))
        .descriptor(bdk_wallet::KeychainKind::Internal, Some(internal.clone()))
        .load_wallet(&mut connection)
        .unwrap()
        .unwrap();
    let (_, _, funding) = new_wallet_and_funding_update(&external, Some(&internal));
    wallet.apply_update(funding).unwrap();
    wallet.persist(&mut connection).unwrap();
    dir
}

/// Take a request file to a reference signer and leave its answer beside it.
fn sign_file(signer: &RefSigner, request: &std::path::Path, answer: &std::path::Path) {
    let outcome = signer.sign(&std::fs::read(request).unwrap()).unwrap();
    std::fs::write(answer, outcome.bytes()).unwrap();
}

#[test]
fn two_signers_pay_one_silent_payment_through_the_file_steps() {
    let payee = payee();
    let (signer_a, signer_b) = (signer_a(), signer_b());
    let root = tempfile::tempdir().unwrap();
    let a = wallet_folder(root.path(), "a", &signer_a);
    let b = wallet_folder(root.path(), "b", &signer_b);
    let file = |name: &str| root.path().join(name);
    let path = |name: &str| file(name).to_str().unwrap().to_string();
    let sats = SATS.to_string();
    let fee_rate = FEE_RATE.to_string();

    kiss_bdk(
        &a,
        &[
            "shared",
            "propose",
            "--to",
            &payee.address,
            "--sats",
            &sats,
            "--fee-rate",
            &fee_rate,
            "--out",
            &path("proposal.json"),
        ],
    );
    let joined = kiss_bdk(&b, &["shared", "accept", &path("proposal.json")]);
    assert!(joined.contains("joined shared send"), "{joined}");
    let status = kiss_bdk(&b, &["shared", "status"]);
    assert!(status.contains("share missing, not signed"), "{status}");

    // B's signer: share only.
    let said = kiss_bdk(&b, &["shared", "request", "--out", &path("b1.psbt")]);
    assert!(said.contains("only adds your signer's share"), "{said}");
    sign_file(&signer_b, &file("b1.psbt"), &file("b1-signed.psbt"));
    let said = kiss_bdk(
        &b,
        &[
            "shared",
            "answer",
            &path("b1-signed.psbt"),
            "--out",
            &path("b1.json"),
        ],
    );
    assert!(said.contains("input 1 share proof OK"), "{said}");

    // A's signer: completes the shares and signs.
    let said = kiss_bdk(&a, &["shared", "receive", &path("b1.json")]);
    assert!(said.contains("joined: 2 inputs, 3 outputs"), "{said}");
    let said = kiss_bdk(&a, &["shared", "request", "--out", &path("a1.psbt")]);
    assert!(said.contains("reviews and signs"), "{said}");
    sign_file(&signer_a, &file("a1.psbt"), &file("a1-signed.psbt"));
    let said = kiss_bdk(
        &a,
        &[
            "shared",
            "answer",
            &path("a1-signed.psbt"),
            "--out",
            &path("a1.json"),
        ],
    );
    assert!(said.contains("input 0 signature OK"), "{said}");

    // B's signer: checks everything and signs.
    kiss_bdk(&b, &["shared", "receive", &path("a1.json")]);
    kiss_bdk(&b, &["shared", "request", "--out", &path("b2.psbt")]);
    sign_file(&signer_b, &file("b2.psbt"), &file("b2-signed.psbt"));
    let said = kiss_bdk(
        &b,
        &[
            "shared",
            "answer",
            &path("b2-signed.psbt"),
            "--out",
            &path("b2.json"),
        ],
    );
    assert!(said.contains("input 1 signature OK"), "{said}");

    // Either side can finalize the same transaction.
    let printed = kiss_bdk(
        &b,
        &[
            "shared",
            "broadcast",
            "--dry-run",
            "--out",
            &path("done.json"),
        ],
    );
    let hex = printed.lines().next().unwrap();
    let tx: Transaction = bdk_wallet::bitcoin::consensus::encode::deserialize_hex(hex).unwrap();
    kiss_bdk(&a, &["shared", "receive", &path("b2.json")]);
    let from_a = kiss_bdk(
        &a,
        &[
            "shared",
            "broadcast",
            "--dry-run",
            "--out",
            &path("done-a.json"),
        ],
    );
    assert_eq!(from_a.lines().next().unwrap(), hex);

    let saved: sharedflow::Saved =
        serde_json::from_slice(&std::fs::read(b.join(sharedflow::SESSION_FILE)).unwrap()).unwrap();
    let state = saved.session.unwrap().state().unwrap();
    let coins = prevouts(&state);
    assert_signatures_verify(&tx, &coins);
    assert_fee_rate(&tx, &coins, FEE_RATE);
    let keys = private_keys(&state, &[&signer_a, &signer_b]);
    assert_pays(&tx, &coins, &keys, &payee, SATS);
}

// ---------------------------------------------------------------------------
// The BIP-375 test vectors

/// A vector's PSBT, with every P2WPKH coin's script made to pay the key in
/// its BIP-32 derivation.
///
/// The vectors' P2WPKH scripts are placeholders that do not hash to the key
/// beside them, and section 2 of the contract refuses exactly that. The
/// script takes no part in the share maths (the input hash uses outpoints
/// and keys), so binding it leaves what each vector tests intact.
fn bound_vector(text: &str) -> anyhow::Result<PsbtV2> {
    let mut psbt = shared::decode(text)?;
    for input in &mut psbt.inputs {
        let key = input.bip32_derivations.keys().next().copied();
        if let (Some(utxo), Some(key)) = (input.witness_utxo.as_mut(), key)
            && utxo.script_pubkey.is_p2wpkh()
        {
            utxo.script_pubkey =
                ScriptBuf::new_p2wpkh(&CompressedPublicKey(key.inner).wpubkey_hash());
        }
    }
    Ok(psbt)
}

/// What the coordinator's PSBT check says about each vector: `Ok(true)` when
/// every share is there and checks out, `Ok(false)` when some are still
/// missing, or the error.
fn audit_vector(case: &serde_json::Value) -> Result<bool, String> {
    bound_vector(case["psbt"].as_str().unwrap())
        .and_then(|psbt| shared::audit(&psbt))
        .map(|shares| shares.complete())
        .map_err(|error| format!("{error:#}"))
}

#[test]
fn agrees_with_the_bip375_vectors_it_can_express() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/bip375-vectors.json")).unwrap();
    let valid = fixture["valid"].as_array().unwrap();
    let invalid = fixture["invalid"].as_array().unwrap();

    // Per-input shares, every one proven, every script matching.
    for index in [3, 7, 8, 13, 14, 15] {
        assert_eq!(audit_vector(&valid[index]), Ok(true), "valid {index}");
    }
    // In progress: shares still missing and no script yet.
    for index in [16, 17, 18] {
        assert_eq!(audit_vector(&valid[index]), Ok(false), "valid {index}");
    }
    // Valid in BIP-375 but outside a version 1 shared send, which refuses a
    // global share and any coin that is not P2WPKH or P2TR key path.
    for (index, reason) in [
        (0, "neither P2WPKH nor P2TR"),
        (1, "no witness UTXO"),
        (2, "global ECDH share"),
        (4, "global ECDH share"),
        (5, "global ECDH share"),
        (6, "global ECDH share"),
        (10, "no witness UTXO"),
        (11, "global ECDH share"),
        (12, "only be spent through a script"),
        (19, "neither P2WPKH nor P2TR"),
    ] {
        let error = audit_vector(&valid[index]).unwrap_err();
        assert!(error.contains(reason), "valid {index}: {error}");
    }
    // Two labels of one address: the vector gives k in output order, while
    // sorting the labelled spend keys gives the other order. A shared send
    // pays one unlabelled address, so this stays a known difference.
    let error = audit_vector(&valid[9]).unwrap_err();
    assert!(
        error.contains("not the one the shares derive"),
        "valid 9: {error}"
    );

    for (index, reason) in [
        (0, "not a valid PSBTv2"),
        (1, "not a valid PSBTv2"),
        (2, "not a valid PSBTv2"),
        (3, "not a valid PSBTv2"),
        (4, "not a valid PSBTv2"),
        (5, "open to changes"),
        (6, "not a valid PSBTv2"),
        (7, "no witness UTXO"),
        (8, "input 0 has no ECDH share for its scan key"),
        (9, "not a valid PSBTv2"),
        (10, "not a valid PSBTv2"),
        (
            11,
            "input 0 (signer 00000080): the ECDH share does not match its DLEQ proof",
        ),
        (12, "global ECDH share"),
        (13, "no BIP-32 derivation key"),
        (14, "output 1 has a script, but input 0 has no ECDH share"),
        (15, "output 1 has a script, but input 1 has no ECDH share"),
        (16, "output 0 has a script, but input 1 has no ECDH share"),
        (17, "neither P2WPKH nor P2TR"),
        (18, "sighash type 2"),
        (19, "only be spent through a script"),
        (20, "output 0 does not pay the silent payment address"),
        (21, "output 0 does not pay the silent payment address"),
        (22, "output 1 does not pay the silent payment address"),
    ] {
        let error = audit_vector(&invalid[index]).unwrap_err();
        assert!(error.contains(reason), "invalid {index}: {error}");
    }
    assert_eq!(valid.len(), 20);
    assert_eq!(invalid.len(), 23);
}

/// The reference signer's GenerateProof gives the BIP-374 vectors' proofs,
/// so the coordinator's checks are tested against proofs made the BIP's way.
#[test]
fn the_reference_signer_makes_the_bip374_proofs() {
    use bdk_wallet::bitcoin::hex::FromHex;

    let hex = |text: &str| Vec::<u8>::from_hex(text).unwrap();
    let rows = include_str!("fixtures/bip374-generate-proof.csv");
    let mut made = 0;
    for row in rows.lines().skip(1) {
        let field: Vec<&str> = row.split(',').collect();
        let (g, a, b, r, m, proof, comment) = (
            field[1], field[2], field[3], field[4], field[5], field[6], field[7],
        );
        let key = SecretKey::from_slice(&hex(a));
        // The point at infinity is written as a word, not as hex.
        let scan = Vec::<u8>::from_hex(b)
            .ok()
            .and_then(|bytes| PublicKey::from_slice(&bytes).ok());
        if comment.starts_with("Failure") {
            assert!(key.is_err() || scan.is_none(), "{comment}");
            continue;
        }
        let g = PublicKey::from_slice(&hex(g)).unwrap();
        let r: [u8; 32] = hex(r).try_into().unwrap();
        let m: Option<[u8; 32]> = (!m.is_empty()).then(|| hex(m).try_into().unwrap());
        let made_proof =
            ref_signer::generate_proof(&key.unwrap(), &scan.unwrap(), &r, Some(&g), m.as_ref())
                .unwrap();
        assert_eq!(made_proof.to_vec(), hex(proof), "{comment}");
        made += 1;
    }
    assert_eq!(made, 8);
}
