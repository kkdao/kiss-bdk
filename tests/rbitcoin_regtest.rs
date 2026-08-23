//! The tweak stream against a real node, end to end, on a chain we control.
//!
//! [`electrum_stream`](./electrum_stream.rs) proves the client handles the
//! protocol; it proves it against a socket this repo also wrote, which cannot
//! show that the protocol was read correctly in the first place. This runs the
//! same client against `rbitcoin --sptweaks`, which is the server the format
//! was taken from.
//!
//! Regtest rather than signet, for one reason: the node only serves Electrum
//! once it has caught up to its peers, and a full signet archive is tens of
//! gigabytes. A chain we mine ourselves is at its tip immediately, and every
//! part under test is the same code — the node's real BIP-352 index, its real
//! `blockchain.tweaks.subscribe`, and a real payment nobody told the scanner
//! about.
//!
//! The payment is genuine, not planted: a P2WPKH coinbase is spent to a taproot
//! output derived from the sender's own input key and the recipient's code, so
//! the node computes the tweak from the transaction the way it computes every
//! other one. The scanner is given the recipient's keys and nothing else.
//!
//! ```sh
//! DIR=/tmp/rb-regtest
//! rbitcoin-node --datadir "$DIR" --network regtest --no-seeds \
//!   --shindex --sptweaks \
//!   --rpc-listen 127.0.0.1:18443 \
//!   --electrum-listen 127.0.0.1:50002 \
//!   --esplora-listen 127.0.0.1:3002 &
//!
//! KISS_RBITCOIN_DATADIR="$DIR" \
//!   cargo test --test rbitcoin_regtest -- --ignored --nocapture
//! ```

use std::path::Path;
use std::process::Command;
use std::str::FromStr;

use base64::Engine;
use bdk_wallet::bitcoin::bech32::primitives::iter::{ByteIterExt, Fe32IterExt};
use bdk_wallet::bitcoin::bech32::{Bech32m, Fe32, Hrp};
use bdk_wallet::bitcoin::consensus::encode::serialize_hex;
use bdk_wallet::bitcoin::hashes::Hash;
use bdk_wallet::bitcoin::secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use bdk_wallet::bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bdk_wallet::bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness, absolute,
    transaction,
};
use kiss_bdk::electrum::Electrum;
use kiss_bdk::sp::derive;
use kiss_bdk::spreceive::ScanKeys;
use kiss_bdk::spscan::{Candidate, scan_candidate, scanner};
use serde_json::{Value, json};

const ELECTRUM: &str = "127.0.0.1:50002";
const ESPLORA: &str = "http://127.0.0.1:3002";
const RPC: &str = "http://127.0.0.1:18443";

/// The same throwaway recipient `live_scan.rs` uses, so the `tsp1` code this
/// pays is one already written down in this repo.
fn recipient() -> ScanKeys {
    let secp = Secp256k1::new();
    ScanKeys {
        scan: SecretKey::from_slice(&[0x11; 32]).unwrap(),
        spend: SecretKey::from_slice(&[0x22; 32])
            .unwrap()
            .public_key(&secp),
    }
}

/// The sender. Its key is the one BIP-352 sums, so it is what the node's
/// published tweak is computed from.
fn sender() -> (SecretKey, PublicKey) {
    let secp = Secp256k1::new();
    let key = SecretKey::from_slice(&[0x77; 32]).unwrap();
    let public = key.public_key(&secp);
    (key, public)
}

fn sender_script() -> ScriptBuf {
    let (_, public) = sender();
    ScriptBuf::new_p2wpkh(
        &bdk_wallet::bitcoin::CompressedPublicKey(public)
            .wpubkey_hash(),
    )
}

fn datadir() -> String {
    std::env::var("KISS_RBITCOIN_DATADIR")
        .expect("set KISS_RBITCOIN_DATADIR to the running node's datadir")
}

fn rpc(method: &str, params: Value) -> Value {
    let cookie = std::fs::read_to_string(format!("{}/.cookie", datadir()))
        .expect("the node's .cookie file");
    let auth = base64::engine::general_purpose::STANDARD.encode(cookie.trim());

    let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
    let response = minreq::post(RPC)
        .with_header("Authorization", format!("Basic {auth}"))
        .with_header("Content-Type", "application/json")
        .with_timeout(120)
        .with_body(body.to_string())
        .send()
        .unwrap_or_else(|e| panic!("{method}: {e}"));

    let parsed: Value = serde_json::from_str(response.as_str().unwrap())
        .unwrap_or_else(|e| panic!("{method} answered unparseable JSON: {e}"));
    assert!(
        parsed["error"].is_null(),
        "{method} failed: {}",
        parsed["error"]
    );
    parsed["result"].clone()
}

fn get(path: &str) -> String {
    let url = format!("{ESPLORA}{path}");
    let response = minreq::get(&url)
        .with_timeout(60)
        .send()
        .unwrap_or_else(|e| panic!("GET {url}: {e}"));
    assert!(
        (200..300).contains(&response.status_code),
        "GET {url} → {} {}",
        response.status_code,
        response.as_str().unwrap_or("")
    );
    response.as_str().unwrap().trim().to_string()
}

/// Mine to the sender's own script, so the coinbase it produces is spendable
/// here without a wallet on the node.
fn mine(blocks: u32) {
    rpc(
        "generatetodescriptor",
        json!([blocks, format!("raw({})", sender_script().to_hex_string())]),
    );
}

fn tip() -> u32 {
    get("/blocks/tip/height").parse().unwrap()
}

fn coinbase_of(height: u32) -> Txid {
    let hash = get(&format!("/block-height/{height}"));
    let txids: Vec<String> = serde_json::from_str(&get(&format!("/block/{hash}/txids"))).unwrap();
    Txid::from_str(&txids[0]).unwrap()
}

/// A real silent payment, mined, with everything the recipient should be able
/// to work out for itself afterwards.
struct Payment {
    txid: Txid,
    outpoint: OutPoint,
    sats: u64,
    height: u32,
    script: ScriptBuf,
    /// `input_hash · A`, computed from the sender's key rather than read from
    /// the node, so the node's own answer can be held against it.
    tweak: PublicKey,
}

/// Mine a coinbase, spend it to a silent payment, mine that.
fn a_fresh_payment() -> Payment {
    let secp = Secp256k1::new();
    let keys = recipient();
    let (sender_sk, sender_pk) = sender();

    // 101 blocks makes the first of them mature: a coinbase at height h is
    // spendable once the tip reaches h + 100.
    let before = tip();
    mine(101);
    let funded = before + 1;
    assert_eq!(tip(), before + 101, "the node must have mined what was asked");

    let previous = OutPoint::new(coinbase_of(funded), 0);
    let subsidy = Amount::from_sat(50 * 100_000_000);
    let fee = Amount::from_sat(1_000);

    // The sender's half of BIP-352: an ECDH share from its own input key and
    // the recipient's scan key, bound to this exact input set by the hash.
    let share = keys
        .scan
        .public_key(&secp)
        .mul_tweak(
            &secp,
            &bdk_wallet::bitcoin::secp256k1::Scalar::from(sender_sk),
        )
        .expect("the ECDH share stays on the curve");
    let input_hash = derive::input_hash(&[previous], &sender_pk).unwrap();
    let payment = derive::output_script(&share, &keys.spend, &input_hash, 0).unwrap();

    let mut tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: previous,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: subsidy - fee,
            script_pubkey: payment.clone(),
        }],
    };

    let sighash = SighashCache::new(&tx)
        .p2wpkh_signature_hash(0, &sender_script(), subsidy, EcdsaSighashType::All)
        .unwrap();
    let signature = secp.sign_ecdsa(
        &Message::from_digest(sighash.to_byte_array()),
        &sender_sk,
    );
    let mut serialized = signature.serialize_der().to_vec();
    serialized.push(EcdsaSighashType::All as u8);
    tx.input[0].witness = Witness::from_slice(&[serialized, sender_pk.serialize().to_vec()]);

    let txid = tx.compute_txid();
    let accepted = minreq::post(format!("{ESPLORA}/tx"))
        .with_timeout(60)
        .with_body(serialize_hex(&tx))
        .send()
        .expect("broadcasting through the node");
    assert!(
        (200..300).contains(&accepted.status_code),
        "the node refused the payment: {}",
        accepted.as_str().unwrap_or("")
    );

    mine(1);

    Payment {
        txid,
        outpoint: OutPoint::new(txid, 0),
        sats: (subsidy - fee).to_sat(),
        height: tip(),
        script: payment,
        tweak: sender_pk
            .mul_tweak(
                &secp,
                &bdk_wallet::bitcoin::secp256k1::Scalar::from(
                    SecretKey::from_slice(&input_hash).unwrap(),
                ),
            )
            .unwrap(),
    }
}

#[test]
#[ignore = "needs a local rbitcoin regtest node; see the module comment"]
fn a_payment_this_node_indexed_is_found_through_its_tweak_stream() {
    let keys = recipient();
    let payment = a_fresh_payment();
    let (txid, height) = (payment.txid, payment.height);

    // Everything above is the sender. From here nothing knows the sender's key
    // or the transaction — only the recipient's keys and what the node says.
    let mut server = Electrum::connect(ELECTRUM).unwrap();
    let mut streamed: Vec<Candidate> = Vec::new();
    let delivered = server
        .tweaks(height, 1, |at, candidates| {
            assert_eq!(at, height);
            streamed = candidates;
            Ok(())
        })
        .unwrap();
    assert_eq!(delivered, 1, "one height was asked for and served");

    let candidate = streamed
        .iter()
        .find(|c| c.txid == txid)
        .unwrap_or_else(|| panic!("the node did not flag {txid} as a candidate"));

    // The node computed the tweak from the transaction; the sender computed it
    // from its own key. They are the same value or the index is wrong.
    assert_eq!(
        candidate.tweak, payment.tweak,
        "the node's published tweak must be input_hash · A"
    );

    let found = scan_candidate(&keys, &scanner(&keys), candidate, height).unwrap();
    assert_eq!(found.len(), 1, "the scan must find the payment");
    assert_eq!(found[0].out.outpoint, payment.outpoint);
    assert_eq!(found[0].out.script_pubkey, payment.script);
    assert_eq!(found[0].out.amount, Amount::from_sat(payment.sats));
    assert_eq!(found[0].height, height);

    println!(
        "found {} sats at {} in block {height}, streamed from {ELECTRUM}",
        found[0].out.amount.to_sat(),
        found[0].out.outpoint
    );
}

/// The same proof through the command a person actually types.
///
/// The test above drives the library, which leaves the parts only `sp-scan`
/// has untested: the genesis check that refuses the wrong chain, the watermark,
/// and the on-chain confirmation of every amount the stream claimed. Those are
/// the parts that decide whether a coin is spendable later, so they get a run
/// against the real node too.
#[test]
#[ignore = "needs a local rbitcoin regtest node; see the module comment"]
fn the_sp_scan_command_finds_it_over_the_same_stream() {
    // The wallet's own descriptor is irrelevant to a silent payment scan — the
    // scan key is what finds these — but `init` needs one.
    const DESCRIPTOR: &str = "wpkh([73c5da0a/84h/1h/0h]tpubDC8msFGeGuwnKG9Upg7DM2b4DaRqg3CUZa5g8v2SRQ6K4NSkxUgd7HsL2XVWbVm39yBA4LAxysQAm397zwQSQoQgewGiYZqrA9DsP4zbQ1M/<0;1>/*)";

    let payment = a_fresh_payment();
    let tmp = tempfile::tempdir().unwrap();
    let wallet = tmp.path().join("wallet");

    let (ok, _, stderr) = cli(
        &wallet,
        &[
            "init",
            "--network",
            "regtest",
            "--descriptor",
            DESCRIPTOR,
            "--esplora",
            ESPLORA,
        ],
    );
    assert!(ok, "init: {stderr}");

    let (ok, _, stderr) = cli(&wallet, &["sp-pair", "--key", &scan_export()]);
    assert!(ok, "sp-pair: {stderr}");

    let from = payment.height.to_string();
    let (ok, stdout, stderr) = cli(
        &wallet,
        &["sp-scan", "--electrum", ELECTRUM, "--from", &from],
    );
    assert!(ok, "sp-scan: {stderr}");
    assert!(
        stdout.contains(&payment.outpoint.to_string()),
        "sp-scan did not report the payment:\n{stdout}"
    );
    assert!(
        stdout.contains(&payment.sats.to_string()),
        "sp-scan reported the wrong amount:\n{stdout}"
    );

    let (ok, stdout, stderr) = cli(&wallet, &["sp-balance"]);
    assert!(ok, "sp-balance: {stderr}");
    assert!(
        stdout.contains(&payment.outpoint.to_string()),
        "the payment was not stored:\n{stdout}"
    );

    // Pointing the same wallet at a chain the node is not on has to be refused
    // rather than scanned: heights would be read against the wrong blocks.
    let other = tmp.path().join("signet-wallet");
    cli(
        &other,
        &[
            "init",
            "--network",
            "signet",
            "--descriptor",
            DESCRIPTOR,
            "--esplora",
            ESPLORA,
        ],
    );
    cli(&other, &["sp-pair", "--key", &scan_export()]);
    let (ok, _, stderr) = cli(&other, &["sp-scan", "--electrum", ELECTRUM]);
    assert!(!ok, "a signet wallet must refuse a regtest node");
    assert!(stderr.contains("genesis"), "{stderr}");
}

fn cli(wallet_dir: &Path, args: &[&str]) -> (bool, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_kiss-bdk"))
        .arg("--wallet-dir")
        .arg(wallet_dir)
        .env("MUTINYNET_FAUCET_TOKEN", "")
        .args(args)
        .output()
        .unwrap();
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// The `tspscan1…` KISS would export for [`recipient`].
///
/// `scan_priv ‖ spend_pub` under a zero version group, which is what
/// `spreceive::parse_scan_export` reads.
fn scan_export() -> String {
    let keys = recipient();
    let mut payload = keys.scan.secret_bytes().to_vec();
    payload.extend_from_slice(&keys.spend.serialize());
    payload
        .into_iter()
        .bytes_to_fes()
        .with_checksum::<Bech32m>(&Hrp::parse("tspscan").unwrap())
        .with_witness_version(Fe32::Q)
        .chars()
        .collect()
}

/// A wallet the payment was not addressed to must find nothing in the same
/// stream — otherwise the test above would pass on any taproot output.
#[test]
#[ignore = "needs a local rbitcoin regtest node; see the module comment"]
fn a_different_wallet_finds_nothing_in_the_same_stream() {
    let secp = Secp256k1::new();
    let stranger = ScanKeys {
        scan: SecretKey::from_slice(&[0x31; 32]).unwrap(),
        spend: SecretKey::from_slice(&[0x41; 32])
            .unwrap()
            .public_key(&secp),
    };

    let height = tip();
    let mut server = Electrum::connect(ELECTRUM).unwrap();
    let mut total = 0;
    server
        .tweaks(height.saturating_sub(4), 5, |at, candidates| {
            for candidate in &candidates {
                total += scan_candidate(&stranger, &scanner(&stranger), candidate, at)?.len();
            }
            Ok(())
        })
        .unwrap();
    assert_eq!(total, 0, "a stranger's keys must match nothing");
}
