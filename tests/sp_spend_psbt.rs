//! The BIP-376 PSBTv2 this coordinator hands KISS to spend a received silent
//! payment.
//!
//! The signer stops on *any* key-value pair it does not recognise, so the input
//! it is given is a whitelist rather than a best effort. These are contract
//! points, checked on the serialized bytes: what is present, what is absent,
//! and that the whole thing round-trips through a signature.

use std::collections::BTreeMap;

use bdk_wallet::bitcoin::bip32::Fingerprint;
use bdk_wallet::bitcoin::hashes::Hash;
use bdk_wallet::bitcoin::secp256k1::{Keypair, Message, PublicKey, Scalar, Secp256k1, SecretKey};
use bdk_wallet::bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bdk_wallet::bitcoin::{
    Address, Amount, FeeRate, OutPoint, Psbt, ScriptBuf, Sequence, Txid, taproot,
};
use bdk_wallet::test_utils::new_wallet_and_funding_update;
use kiss_bdk::spsend::{AnyPsbt, build_v2, to_v0};
use kiss_bdk::spspend::{
    self, PSBT_IN_SP_SPEND_BIP32_DERIVATION, PSBT_IN_SP_TWEAK, SATISFACTION_WEIGHT, SpCoin,
};
use kiss_bdk::spstore::StoredOut;
use psbt_v2::v2::Psbt as PsbtV2;
use std::str::FromStr;

const KISS_DESC: &str = "wpkh([73c5da0a/84h/1h/0h]tpubDC8msFGeGuwnKG9Upg7DM2b4DaRqg3CUZa5g8v2SRQ6K4NSkxUgd7HsL2XVWbVm39yBA4LAxysQAm397zwQSQoQgewGiYZqrA9DsP4zbQ1M/<0;1>/*)";
const DESTINATION: &str = "tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl";

/// This repo's own throwaway silent payment keys, the pair `tests/cli.rs` pairs
/// with. Unlike the signer's published vectors the *private* spend key is known
/// here, which is what makes an offline signature round trip possible.
const SPEND_PRIV: [u8; 32] = [0x22; 32];
const TWEAK: [u8; 32] = [0x03; 32];

fn spend_keys() -> (SecretKey, PublicKey) {
    let secp = Secp256k1::new();
    let secret = SecretKey::from_slice(&SPEND_PRIV).unwrap();
    let public = secret.public_key(&secp);
    (secret, public)
}

/// A stored output that really pays `B_spend + t·G`, as a scan would have found
/// it.
fn stored(vout: u32, sats: u64) -> StoredOut {
    let (_, spend) = spend_keys();
    let tweak = SecretKey::from_slice(&TWEAK).unwrap();
    let key = spspend::output_key(&spend, &tweak).unwrap();
    let mut script = vec![0x51, 0x20];
    script.extend_from_slice(&key.serialize());
    StoredOut {
        outpoint: OutPoint::new(Txid::from_byte_array([0xcd; 32]), vout),
        tweak,
        script_pubkey: ScriptBuf::from_bytes(script),
        amount: Amount::from_sat(sats),
        label: None,
        height: 200,
    }
}

/// Build the spend the way `create --from-sp` does: silent payment coins as
/// foreign UTXOs, nothing from the descriptor wallet, out as a PSBTv2.
fn spend_psbt(coins: &[SpCoin], sats: u64) -> (Psbt, Vec<u8>) {
    let (_, spend) = spend_keys();
    let origin = spspend::spend_origin(Fingerprint::from_str("73c5da0a").unwrap());
    let (external, internal) = kiss_bdk::split_kiss_descriptor(KISS_DESC).unwrap();
    let (mut wallet, _, funding) = new_wallet_and_funding_update(&external, Some(&internal));
    wallet.apply_update(funding).unwrap();

    let destination = Address::from_str(DESTINATION)
        .unwrap()
        .assume_checked()
        .script_pubkey();

    let mut builder = wallet.build_tx();
    for coin in coins {
        builder
            .add_foreign_utxo_with_sequence(
                coin.outpoint,
                spspend::psbt_input(coin, &spend, &origin),
                SATISFACTION_WEIGHT,
                Sequence::ENABLE_RBF_NO_LOCKTIME,
            )
            .unwrap();
    }
    builder.manually_selected_only();
    builder
        .add_recipient(destination, Amount::from_sat(sats))
        .fee_rate(FeeRate::from_sat_per_vb(2).unwrap());
    let v0 = builder.finish().unwrap();
    let bytes = build_v2(&v0, &[]).unwrap();
    (v0, bytes)
}

fn coins(n: u32, sats: u64) -> Vec<SpCoin> {
    let (_, spend) = spend_keys();
    (0..n)
        .map(|vout| SpCoin::checked(&stored(vout, sats), &spend).unwrap())
        .collect()
}

/// Walk the raw PSBT and return the key type and key-data length of every pair,
/// per map. The device measures the whole key including its type byte, so the
/// reported key length here is `1 + key_data`.
fn maps(bytes: &[u8]) -> Vec<Vec<(u8, usize, usize)>> {
    assert_eq!(&bytes[..5], b"psbt\xff");
    let mut at = 5;
    let compact = |at: &mut usize| -> usize {
        let first = bytes[*at];
        *at += 1;
        let width = match first {
            0xfd => 2,
            0xfe => 4,
            0xff => 8,
            _ => return usize::from(first),
        };
        let mut value = 0_u64;
        for (index, byte) in bytes[*at..*at + width].iter().enumerate() {
            value |= u64::from(*byte) << (8 * index);
        }
        *at += width;
        value as usize
    };

    let mut out = Vec::new();
    while at < bytes.len() {
        let mut map = Vec::new();
        loop {
            let key_len = compact(&mut at);
            if key_len == 0 {
                break;
            }
            let type_value = bytes[at];
            at += key_len;
            let value_len = compact(&mut at);
            at += value_len;
            map.push((type_value, key_len, value_len));
        }
        out.push(map);
    }
    out
}

#[test]
fn writes_exactly_the_input_fields_the_signer_recognises() {
    let (v0, bytes) = spend_psbt(&coins(1, 100_000), 50_000);
    assert_eq!(v0.inputs.len(), 1, "no descriptor coin may be pulled in");

    let maps = maps(&bytes);
    let input = &maps[1];

    // Ordering is the *serialized* one, not the ascending order of the signer's
    // own reference vector: psbt-v2 writes unknowns last. libwally checks for
    // duplicate keys and not for ordering, so this is fine — pinned here
    // deliberately rather than discovered on a device.
    assert_eq!(
        input,
        &vec![
            (0x0e, 1, 32), // PSBT_IN_PREVIOUS_TXID
            (0x0f, 1, 4),  // PSBT_IN_OUTPUT_INDEX
            (0x10, 1, 4),  // PSBT_IN_SEQUENCE
            (0x01, 1, 43), // PSBT_IN_WITNESS_UTXO
            (PSBT_IN_SP_SPEND_BIP32_DERIVATION, 34, 24),
            (PSBT_IN_SP_TWEAK, 1, 32),
        ],
        "an unrecognised pair is a hard stop on the device"
    );
}

#[test]
fn leaves_out_every_field_that_would_break_signing() {
    let (_, bytes) = spend_psbt(&coins(1, 100_000), 50_000);
    let present: Vec<u8> = maps(&bytes)[1].iter().map(|(kind, ..)| *kind).collect();

    // A BIP-32 derivation naming the device's fingerprint sends libwally down
    // its ordinary taproot path, where it looks the key up among leaf hashes
    // that do not exist, and the whole signing fails.
    assert!(!present.contains(&0x06), "PSBT_IN_BIP32_DERIVATION");
    assert!(!present.contains(&0x16), "PSBT_IN_TAP_BIP32_DERIVATION");
    // A sighash type turns the 64-byte signature into 65 over another message.
    assert!(!present.contains(&0x03), "PSBT_IN_SIGHASH_TYPE");
    // Ignored by the signer, and 4096 bytes is the whole budget.
    assert!(!present.contains(&0x00), "PSBT_IN_NON_WITNESS_UTXO");
}

#[test]
fn leaves_as_a_v2_because_a_v0_would_load_green_and_fail_to_sign() {
    let (_, bytes) = spend_psbt(&coins(1, 100_000), 50_000);
    let v2 = PsbtV2::deserialize(&bytes).expect("must parse strictly as a PSBTv2");
    assert_eq!(v2.global.version, psbt_v2::V2);
    assert!(matches!(AnyPsbt::parse(&bytes).unwrap(), AnyPsbt::V2(_)));
}

/// `add_foreign_utxo` defaults to `Sequence::MAX`, and the foreign value wins
/// over the one BDK would set. Left alone that turns RBF off and disables this
/// input's nLockTime while the transaction still carries one — invisible in
/// every other assertion here.
#[test]
fn keeps_the_sequence_bdk_intended_rather_than_the_foreign_default() {
    let (v0, _) = spend_psbt(&coins(2, 100_000), 150_000);
    for txin in &v0.unsigned_tx.input {
        assert_eq!(txin.sequence, Sequence::ENABLE_RBF_NO_LOCKTIME);
    }
}

#[test]
fn spends_only_silent_payments_because_kiss_refuses_a_mix() {
    let (v0, _) = spend_psbt(&coins(2, 100_000), 150_000);
    let sp: Vec<OutPoint> = coins(2, 100_000).iter().map(|c| c.outpoint).collect();
    assert_eq!(v0.unsigned_tx.input.len(), 2);
    for txin in &v0.unsigned_tx.input {
        assert!(
            sp.contains(&txin.previous_output),
            "a descriptor coin was selected alongside a silent payment"
        );
    }
}

/// The whole round trip with no device: build, sign as KISS would, verify the
/// signature the way `broadcast` does, finalize, extract.
#[test]
fn signs_verifies_finalizes_and_extracts_offline() {
    let (spend_priv, spend_pub) = spend_keys();
    let coins = coins(1, 100_000);
    let (_, bytes) = spend_psbt(&coins, 50_000);

    let signed = sign_as_kiss(&bytes, &spend_priv);
    let mut psbt = to_v0(&signed).unwrap();
    let sp = spspend::sp_inputs(&psbt, &coins).unwrap();
    assert_eq!(sp.len(), 1);
    assert_eq!(
        sp[&0],
        spspend::output_key(&spend_pub, &SecretKey::from_slice(&TWEAK).unwrap()).unwrap()
    );

    spspend::verify_signatures(&psbt, &sp).expect("KISS's signature must verify");
    spspend::finalize(&mut psbt, &sp).unwrap();

    let witness = psbt.inputs[0].final_script_witness.as_ref().unwrap();
    assert_eq!(witness.len(), 1, "a key-path spend is one signature");
    assert_eq!(witness.iter().next().unwrap().len(), 64, "SIGHASH_DEFAULT");
    // The tweak names a key and has no business in a broadcast-ready PSBT.
    assert!(psbt.inputs[0].unknown.is_empty());

    psbt.extract_tx().expect("must extract");
}

#[test]
fn refuses_a_signature_from_the_wrong_key() {
    let coins = coins(1, 100_000);
    let (_, bytes) = spend_psbt(&coins, 50_000);
    // Sign with the untweaked spend key: the right curve, the wrong point.
    let signed = sign_as_kiss(&bytes, &SecretKey::from_slice(&SPEND_PRIV).unwrap());
    let psbt = to_v0(&signed).unwrap();
    let mut sp = spspend::sp_inputs(&psbt, &coins).unwrap();
    let wrong = spend_keys().1.x_only_public_key().0;
    sp.insert(0, wrong);
    assert!(spspend::verify_signatures(&psbt, &sp).is_err());
}

#[test]
fn refuses_a_flipped_signature_byte() {
    let (spend_priv, _) = spend_keys();
    let coins = coins(1, 100_000);
    let (_, bytes) = spend_psbt(&coins, 50_000);
    let mut signed = sign_as_kiss(&bytes, &spend_priv);
    let mut sig = signed.inputs[0].tap_key_sig.unwrap().signature.serialize();
    sig[10] ^= 0x01;
    signed.inputs[0].tap_key_sig = Some(taproot::Signature {
        signature: bdk_wallet::bitcoin::secp256k1::schnorr::Signature::from_slice(&sig).unwrap(),
        sighash_type: TapSighashType::Default,
    });
    let psbt = to_v0(&signed).unwrap();
    let sp = spspend::sp_inputs(&psbt, &coins).unwrap();
    assert!(spspend::verify_signatures(&psbt, &sp).is_err());
}

#[test]
fn refuses_a_sighash_all_signature_signed_over_another_message() {
    let (spend_priv, _) = spend_keys();
    let coins = coins(1, 100_000);
    let (_, bytes) = spend_psbt(&coins, 50_000);
    let mut signed = sign_as_kiss(&bytes, &spend_priv);
    signed.inputs[0].tap_key_sig = Some(taproot::Signature {
        signature: signed.inputs[0].tap_key_sig.unwrap().signature,
        sighash_type: TapSighashType::All,
    });
    let psbt = to_v0(&signed).unwrap();
    let sp = spspend::sp_inputs(&psbt, &coins).unwrap();
    let error = spspend::verify_signatures(&psbt, &sp)
        .unwrap_err()
        .to_string();
    assert!(error.contains("sighash"), "{error}");
}

/// What `sign_sp_spends` does on the device: derive `d = b_spend + t`, hash the
/// BIP-341 key-path message, and write a 64-byte signature into
/// `PSBT_IN_TAP_KEY_SIG`. Nothing else about the PSBT changes.
fn sign_as_kiss(bytes: &[u8], spend_priv: &SecretKey) -> PsbtV2 {
    let secp = Secp256k1::new();
    let mut v2 = PsbtV2::deserialize(bytes).unwrap();
    let v0 = to_v0(&v2).unwrap();

    let prevouts: Vec<_> = v0
        .inputs
        .iter()
        .map(|input| input.witness_utxo.clone().unwrap())
        .collect();
    let mut cache = SighashCache::new(&v0.unsigned_tx);

    let mut tweaked: BTreeMap<usize, SecretKey> = BTreeMap::new();
    for (index, input) in v2.inputs.iter().enumerate() {
        let Some(tweak) = input
            .unknowns
            .iter()
            .find_map(|(key, value)| (key.type_value == PSBT_IN_SP_TWEAK).then(|| value.clone()))
        else {
            continue;
        };
        let tweak = SecretKey::from_slice(&tweak).unwrap();
        tweaked.insert(index, spend_priv.add_tweak(&Scalar::from(tweak)).unwrap());
    }

    for (index, secret) in tweaked {
        let sighash = cache
            .taproot_key_spend_signature_hash(
                index,
                &Prevouts::All(&prevouts),
                TapSighashType::Default,
            )
            .unwrap();
        let keypair = Keypair::from_secret_key(&secp, &secret);
        let signature =
            secp.sign_schnorr_no_aux_rand(&Message::from_digest(sighash.to_byte_array()), &keypair);
        v2.inputs[index].tap_key_sig = Some(taproot::Signature {
            signature,
            sighash_type: TapSighashType::Default,
        });
    }
    v2
}

/// Silent payment change: BIP-376 inputs and BIP-375 outputs in one PSBT.
///
/// The signer's own source calls this "the ordinary shape of an SP wallet's
/// transaction, not a corner case". Until it existed, spending a received
/// payment sent the remainder to a descriptor address, walking the coin back
/// out of the keyspace the silent payment was for.
mod silent_payment_change {
    use super::*;
    use kiss_bdk::sp::SilentPaymentAddress;
    use kiss_bdk::spsend::{placeholder_count, placeholder_script, resolve_sp_outputs};

    fn code(scan: u8, spend: u8) -> SilentPaymentAddress {
        let secp = Secp256k1::new();
        SilentPaymentAddress {
            scan: SecretKey::from_slice(&[scan; 32]).unwrap().public_key(&secp),
            spend: SecretKey::from_slice(&[spend; 32]).unwrap().public_key(&secp),
            mainnet: false,
        }
    }

    /// The real thing, through BDK: silent payment inputs, a silent payment
    /// recipient, and change pointed at a code of our own with `drain_to`.
    fn sp_to_sp(payee: &SilentPaymentAddress, ours: &SilentPaymentAddress, sats: u64) -> Psbt {
        let (_, spend) = spend_keys();
        let origin = spspend::spend_origin(Fingerprint::from_str("73c5da0a").unwrap());
        let (external, internal) = kiss_bdk::split_kiss_descriptor(KISS_DESC).unwrap();
        let (mut wallet, _, funding) = new_wallet_and_funding_update(&external, Some(&internal));
        wallet.apply_update(funding).unwrap();

        let mut builder = wallet.build_tx();
        for coin in &coins(1, 100_000) {
            builder
                .add_foreign_utxo_with_sequence(
                    coin.outpoint,
                    spspend::psbt_input(coin, &spend, &origin),
                    SATISFACTION_WEIGHT,
                    Sequence::ENABLE_RBF_NO_LOCKTIME,
                )
                .unwrap();
        }
        builder.manually_selected_only();
        builder.drain_to(placeholder_script(ours));
        builder
            .add_recipient(placeholder_script(payee), Amount::from_sat(sats))
            .fee_rate(FeeRate::from_sat_per_vb(2).unwrap());
        builder.finish().unwrap()
    }

    #[test]
    fn change_lands_on_a_silent_payment_output_not_a_descriptor_address() {
        let payee = code(0x33, 0x44);
        let ours = code(0x11, 0x22);
        let psbt = sp_to_sp(&payee, &ours, 40_000);

        assert_eq!(psbt.unsigned_tx.output.len(), 2, "payment and change");
        assert_eq!(placeholder_count(&psbt, &ours), 1, "change is ours");
        assert_eq!(placeholder_count(&psbt, &payee), 1);
        for out in &psbt.unsigned_tx.output {
            assert!(
                out.script_pubkey.is_p2tr(),
                "both outputs are derived, so both are taproot: {out:?}"
            );
        }
    }

    /// Both outputs reach the wire carrying their recipient and no script: it
    /// is the signer that derives the real one.
    #[test]
    fn both_derived_outputs_carry_their_recipient_and_no_script() {
        let payee = code(0x33, 0x44);
        let ours = code(0x11, 0x22);
        let psbt = sp_to_sp(&payee, &ours, 40_000);

        let resolved = resolve_sp_outputs(&psbt, &[payee, ours]).unwrap();
        assert_eq!(resolved.len(), 2);
        let v2 = PsbtV2::deserialize(&build_v2(&psbt, &resolved).unwrap())
            .expect("the PSBT must parse strictly");

        assert_eq!(v2.outputs.len(), 2);
        for output in &v2.outputs {
            assert!(
                output.script_pubkey.is_empty(),
                "a derived output must not carry the placeholder"
            );
            let info = output
                .sp_v0_info
                .as_ref()
                .expect("every derived output needs PSBT_OUT_SP_V0_INFO");
            assert_eq!(info.len(), 66, "scan and spend keys, compressed");
        }
    }

    /// Paying your own code puts two identical placeholders in one transaction.
    /// They used to be refused as ambiguous; they are interchangeable, and each
    /// must be claimed exactly once.
    #[test]
    fn two_outputs_to_one_code_are_claimed_once_each() {
        let ours = code(0x11, 0x22);
        let psbt = sp_to_sp(&ours, &ours, 40_000);

        assert_eq!(placeholder_count(&psbt, &ours), 2);
        let resolved = resolve_sp_outputs(&psbt, &[ours, ours]).unwrap();
        assert_ne!(
            resolved[0].index, resolved[1].index,
            "each output must be claimed once, never twice"
        );
    }

    /// A code with no output of its own must be refused rather than guessed at:
    /// an exact-amount spend leaves no change, and so nothing to claim.
    #[test]
    fn a_code_with_no_output_is_refused_rather_than_guessed() {
        let payee = code(0x33, 0x44);
        let ours = code(0x11, 0x22);
        let (psbt, _) = spend_psbt(&coins(1, 100_000), 40_000);

        assert_eq!(placeholder_count(&psbt, &ours), 0);
        assert!(resolve_sp_outputs(&psbt, &[ours]).is_err());
        assert!(resolve_sp_outputs(&psbt, &[payee]).is_err());
        assert!(resolve_sp_outputs(&psbt, &[]).unwrap().is_empty());
    }
}
