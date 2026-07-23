use std::str::FromStr;

use bdk_wallet::bitcoin::bip32::Fingerprint;
use bdk_wallet::bitcoin::hashes::Hash;
use bdk_wallet::bitcoin::{Amount, FeeRate, ScriptBuf, WPubkeyHash};
use bdk_wallet::test_utils::new_wallet_and_funding_update;
use kiss_bdk::split_kiss_descriptor;

const KISS_MAX_PSBT_BYTES: usize = 4096;

#[test]
fn bdk_psbt_matches_the_kiss_signer_contract() {
    // Public test vector descriptor shape; the test utility supplies fake chain data.
    let combined = "wpkh([73c5da0a/84h/1h/0h]tpubDC8msFGeGuwnKG9Upg7DM2b4DaRqg3CUZa5g8v2SRQ6K4NSkxUgd7HsL2XVWbVm39yBA4LAxysQAm397zwQSQoQgewGiYZqrA9DsP4zbQ1M/<0;1>/*)";
    let (external, internal) = split_kiss_descriptor(combined).unwrap();
    let (mut wallet, _, funding) = new_wallet_and_funding_update(&external, Some(&internal));
    wallet.apply_update(funding).unwrap();

    let destination = ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([0x11; 20]));
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(destination, Amount::from_sat(10_000))
        .fee_rate(FeeRate::from_sat_per_vb(2).unwrap())
        .only_witness_utxo();
    let psbt = builder.finish().unwrap();

    assert_eq!(psbt.version, 0, "KISS's simplest path is standard PSBTv0");
    assert!(!psbt.inputs.is_empty());
    assert!(psbt.inputs.iter().all(|input| input.witness_utxo.is_some()));
    assert!(
        psbt.inputs
            .iter()
            .all(|input| input.non_witness_utxo.is_none())
    );
    assert!(
        psbt.inputs
            .iter()
            .all(|input| !input.bip32_derivation.is_empty())
    );
    assert!(psbt.inputs.iter().all(|input| input.unknown.is_empty()));
    assert!(psbt.inputs.iter().all(|input| input.proprietary.is_empty()));
    assert!(psbt.inputs.iter().all(|input| input.sighash_type.is_none()));
    let expected_fingerprint = Fingerprint::from_str("73c5da0a").unwrap();
    for input in &psbt.inputs {
        for (fingerprint, path) in input.bip32_derivation.values() {
            assert_eq!(*fingerprint, expected_fingerprint);
            assert!(path.to_string().starts_with("84'/1'/0'/0/"));
        }
    }
    assert!(
        psbt.outputs
            .iter()
            .any(|output| !output.bip32_derivation.is_empty()),
        "change must carry its derivation so KISS can re-derive it"
    );
    for change in psbt
        .outputs
        .iter()
        .filter(|output| !output.bip32_derivation.is_empty())
    {
        for (fingerprint, path) in change.bip32_derivation.values() {
            assert_eq!(*fingerprint, expected_fingerprint);
            assert!(path.to_string().starts_with("84'/1'/0'/1/"));
        }
    }
    assert!(psbt.outputs.iter().all(|output| output.unknown.is_empty()));
    assert!(
        psbt.outputs
            .iter()
            .all(|output| output.proprietary.is_empty())
    );
    assert!(psbt.unknown.is_empty());
    assert!(psbt.proprietary.is_empty());
    assert!(psbt.serialize().len() <= KISS_MAX_PSBT_BYTES);
}
