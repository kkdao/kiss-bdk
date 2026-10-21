//! The BIP-375 PSBTv2 this coordinator hands KISS for a silent payment.
//!
//! KISS refuses a silent payment in a PSBTv0 outright, and refuses one whose
//! modifiable flags are still set, so those are contract points rather than
//! implementation details.

use bdk_wallet::bitcoin::{Amount, FeeRate};
use bdk_wallet::test_utils::new_wallet_and_funding_update;
use kiss_bdk::sp;
use kiss_bdk::spsend::{SpOutput, build_v2, placeholder_index, placeholder_script};
use psbt_v2::v2::Psbt as PsbtV2;

const KISS_DESC: &str = "wpkh([73c5da0a/84h/1h/0h]tpubDC8msFGeGuwnKG9Upg7DM2b4DaRqg3CUZa5g8v2SRQ6K4NSkxUgd7HsL2XVWbVm39yBA4LAxysQAm397zwQSQoQgewGiYZqrA9DsP4zbQ1M/<0;1>/*)";
const SP_ADDRESS: &str = "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv";

/// Build the v0 PSBT BDK would produce for a payment, with a P2TR placeholder
/// standing in for the silent payment output.
fn placeholder_psbt() -> bdk_wallet::bitcoin::Psbt {
    let (external, internal) = kiss_bdk::split_kiss_descriptor(KISS_DESC).unwrap();
    let (mut wallet, _, funding) = new_wallet_and_funding_update(&external, Some(&internal));
    wallet.apply_update(funding).unwrap();

    // A real silent payment output is a 34-byte P2TR script, so a P2TR
    // placeholder keeps BDK's fee and change arithmetic exact.
    let placeholder = placeholder_script(&sp::decode(SP_ADDRESS).unwrap());
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(placeholder, Amount::from_sat(10_000))
        .fee_rate(FeeRate::from_sat_per_vb(2).unwrap())
        .only_witness_utxo();
    builder.finish().unwrap()
}

#[test]
fn builds_a_bip375_psbtv2_kiss_will_accept() {
    let v0 = placeholder_psbt();
    let recipient = sp::decode(SP_ADDRESS).unwrap();
    let sp_index = placeholder_index(&v0, &recipient).unwrap();
    let bytes = build_v2(
        &v0,
        &[SpOutput {
            index: sp_index,
            recipient,
        }],
    )
    .unwrap();

    let v2 = PsbtV2::deserialize(&bytes).expect("must re-parse as a PSBTv2");
    assert_eq!(
        v2.global.version,
        psbt_v2::V2,
        "KISS rejects SP in a PSBTv0"
    );
    assert_eq!(v2.inputs.len(), v0.inputs.len());
    assert_eq!(v2.outputs.len(), v0.unsigned_tx.output.len());

    // BIP-375: the recipient's keys travel in the PSBT; the script does not
    // exist yet because only the signer can derive it.
    let sp_out = &v2.outputs[sp_index];
    assert_eq!(
        sp_out.sp_v0_info.as_deref(),
        Some(&recipient.sp_v0_info()[..]),
        "PSBT_OUT_SP_V0_INFO must carry scan || spend"
    );
    assert_eq!(sp_out.sp_v0_info.as_ref().unwrap().len(), 66);
    assert!(
        sp_out.script_pubkey.is_empty(),
        "the placeholder script must not survive into the signed request"
    );

    // The change output keeps its real script and its derivation path, or KISS
    // cannot recognise it as the wallet's own.
    let change = &v2.outputs[1 - sp_index];
    assert!(change.sp_v0_info.is_none());
    assert!(!change.script_pubkey.is_empty());
    assert!(!change.bip32_derivations.is_empty());
}

#[test]
fn omits_the_empty_out_script_bip375_forbids() {
    let v0 = placeholder_psbt();
    let recipient = sp::decode(SP_ADDRESS).unwrap();
    let sp_index = placeholder_index(&v0, &recipient).unwrap();
    let bytes = build_v2(
        &v0,
        &[SpOutput {
            index: sp_index,
            recipient,
        }],
    )
    .unwrap();

    // psbt-v2 0.3.0 writes PSBT_OUT_SCRIPT unconditionally; a zero-length one
    // on a silent payment output is exactly what the official vectors omit.
    let empty_out_script = [0x01, 0x04, 0x00];
    assert!(
        !bytes.windows(3).any(|w| w == empty_out_script),
        "an empty PSBT_OUT_SCRIPT survived into the request"
    );
}

#[test]
fn locks_the_modifiable_flags_bip375_requires_clear() {
    let v0 = placeholder_psbt();
    let recipient = sp::decode(SP_ADDRESS).unwrap();
    let sp_index = placeholder_index(&v0, &recipient).unwrap();
    let v2 = PsbtV2::deserialize(
        &build_v2(
            &v0,
            &[SpOutput {
                index: sp_index,
                recipient,
            }],
        )
        .unwrap(),
    )
    .unwrap();

    // Once an SP output is present nothing may be added or removed, otherwise a
    // coordinator could change the inputs the signer derived the output from.
    assert_eq!(
        v2.global.tx_modifiable_flags, 0,
        "KISS rejects a modifiable PSBT carrying silent payment outputs"
    );
}

#[test]
fn rejects_an_out_of_range_silent_payment_output() {
    let v0 = placeholder_psbt();
    let recipient = sp::decode(SP_ADDRESS).unwrap();
    assert!(
        build_v2(
            &v0,
            &[SpOutput {
                index: 99,
                recipient
            }]
        )
        .is_err()
    );
}

#[path = "support/sp_signer.rs"]
mod sp_signer;

/// Offline BDK -> actual C signer -> independent Rust verification.
#[test]
#[ignore = "requires KISS_INTEROP_SIGNER built from kiss-signer; no network or device"]
fn c_signer_bip375_round_trip_and_tampering() {
    use kiss_bdk::{spsend::to_v0, spverify, verify_psbt_signatures};
    use std::collections::BTreeMap;
    let v0 = placeholder_psbt();
    let recipient = sp::decode(SP_ADDRESS).unwrap();
    let index = placeholder_index(&v0, &recipient).unwrap();
    let request = build_v2(&v0, &[SpOutput { index, recipient }]).unwrap();
    let original = PsbtV2::deserialize(&request).unwrap();
    let signed_bytes = sp_signer::sign(&request, 0).unwrap();
    let signed = PsbtV2::deserialize(&signed_bytes).unwrap();
    let checked = spverify::verify(&original, &signed).unwrap();
    assert_eq!(checked.len(), 1);
    assert_eq!(checked[0].index, index);
    let signed_v0 = to_v0(&signed).unwrap();
    verify_psbt_signatures(&signed_v0, &BTreeMap::new()).unwrap();

    let mut bad_proof = signed.clone();
    let key = *bad_proof.global.sp_dleq_proofs.keys().next().unwrap();
    let mut proof = *bad_proof.global.sp_dleq_proofs[&key].as_bytes();
    proof[0] ^= 1;
    bad_proof.global.sp_dleq_proofs.insert(key, proof.into());
    assert!(spverify::verify(&original, &bad_proof).is_err());

    let mut redirected = signed.clone();
    let mut script = redirected.outputs[index].script_pubkey.to_bytes();
    *script.last_mut().unwrap() ^= 1;
    redirected.outputs[index].script_pubkey = script.into();
    assert!(spverify::verify(&original, &redirected).is_err());

    // Change the signed message while retaining the actual C signature.
    let mut changed = signed_v0.clone();
    changed.unsigned_tx.output[index].value = Amount::from_sat(1);
    assert!(verify_psbt_signatures(&changed, &BTreeMap::new()).is_err());
    let mut missing = signed_v0;
    missing.inputs[0].partial_sigs.clear();
    assert!(verify_psbt_signatures(&missing, &BTreeMap::new()).is_err());
}
