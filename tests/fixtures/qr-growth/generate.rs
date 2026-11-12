use bdk_wallet::bitcoin::{
    Amount, FeeRate, ScriptBuf, Transaction, TxIn, TxOut, absolute, transaction,
};
use bdk_wallet::test_utils::new_wallet_and_funding_update;
use kiss_bdk::sp;
use kiss_bdk::spsend::{SpOutput, build_v2, placeholder_index, placeholder_script};
use psbt_v2::v2::Psbt as PsbtV2;
use std::collections::BTreeMap;

const KISS_DESC: &str = "wpkh([73c5da0a/84h/1h/0h]tpubDC8msFGeGuwnKG9Upg7DM2b4DaRqg3CUZa5g8v2SRQ6K4NSkxUgd7HsL2XVWbVm39yBA4LAxysQAm397zwQSQoQgewGiYZqrA9DsP4zbQ1M/<0;1>/*)";
const SP_ADDRESS: &str = "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv";

fn request_with_padding(padding: usize) -> Vec<u8> {
    let (external, internal) = kiss_bdk::split_kiss_descriptor(KISS_DESC).unwrap();
    let (mut wallet, _, funding) = new_wallet_and_funding_update(&external, Some(&internal));
    wallet.apply_update(funding).unwrap();
    let recipient = sp::decode(SP_ADDRESS).unwrap();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(placeholder_script(&recipient), Amount::from_sat(10000))
        .fee_rate(FeeRate::from_sat_per_vb(2).unwrap())
        .only_witness_utxo()
        .ordering(bdk_wallet::TxOrdering::Untouched);
    let mut psbt = builder.finish().unwrap();
    assert_eq!(psbt.inputs.len(), 1);
    // The known non_witness_utxo field deliberately holds a large synthetic
    // previous transaction, not unrecognized/proprietary PSBT padding. The
    // selected output's amount/script still match the witness_utxo, and the
    // request's outpoint is updated to this previous transaction's true txid.
    let previous = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn::default()],
        output: vec![
            psbt.inputs[0].witness_utxo.clone().unwrap(),
            TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::from_bytes([vec![0x6a], vec![0x00; padding]].concat()),
            },
        ],
    };
    psbt.unsigned_tx.input[0].previous_output.txid = previous.compute_txid();
    psbt.unsigned_tx.input[0].previous_output.vout = 0;
    psbt.inputs[0].non_witness_utxo = Some(previous);
    let index = placeholder_index(&psbt, &recipient).unwrap();
    build_v2(&psbt, &[SpOutput { index, recipient }]).unwrap()
}

fn main() {
    let mut args = std::env::args_os().skip(1);
    let signer = args
        .next()
        .expect("usage: qr-growth-fixture <signer> <output-directory>");
    let output = std::path::PathBuf::from(args.next().expect("output directory"));
    assert!(args.next().is_none());
    std::fs::create_dir_all(&output).unwrap();
    let target = 4096;
    let base = request_with_padding(3000);
    let request = request_with_padding(3000 + target - base.len());
    assert_eq!(request.len(), target);
    let work = tempfile::tempdir().unwrap();
    let req = work.path().join("request.psbt");
    let signed_path = work.path().join("signed.psbt");
    std::fs::write(&req, &request).unwrap();
    let result = std::process::Command::new(signer)
        .env_remove("SP_BRIDGE_MNEMONIC")
        .env_remove("SP_BRIDGE_PASSPHRASE")
        .env("KISS_SIM_TMP", work.path())
        .arg(&req)
        .arg(&signed_path)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "signer exit {:?}: {}",
        result.status.code(),
        String::from_utf8_lossy(&result.stderr)
    );
    let signed = std::fs::read(&signed_path).unwrap();
    assert!(signed.len() > target && signed.len() <= 9108);
    let original = PsbtV2::deserialize(&request).unwrap();
    let signed_psbt = PsbtV2::deserialize(&signed).unwrap();
    assert_eq!(
        kiss_bdk::spverify::verify(&original, &signed_psbt)
            .unwrap()
            .len(),
        1
    );
    let signed_v0 = kiss_bdk::spsend::to_v0(&signed_psbt).unwrap();
    kiss_bdk::verify_psbt_signatures(&signed_v0, &BTreeMap::new()).unwrap();
    kiss_bdk::write_new_file(&output.join("request.psbt"), &request).unwrap();
    kiss_bdk::write_new_file(&output.join("signed.psbt"), &signed).unwrap();
    println!(
        "actual C signer: {} -> {} bytes; Rust intent/DLEQ/script/signature verification passed",
        request.len(),
        signed.len()
    );
}
