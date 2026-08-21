//! The receive path against the real chain.
//!
//! Every other test here runs offline, which is the right default: a test that
//! needs a third-party server fails for reasons that have nothing to do with
//! the code. But the whole point of this feature is finding a payment nobody
//! told us about, and that cannot be shown against a fixture we wrote
//! ourselves — a fixture proves the derivation agrees with itself.
//!
//! So this one is real, and `#[ignore]`d. The transaction it looks for was
//! broadcast by this coordinator: KISS derived the output, and the recipient
//! `tsp1` code belongs to throwaway keys (scan `0x11`×32, spend `0x22`×32) that
//! live in this file, which is what makes the expected answer knowable.
//!
//! ```sh
//! cargo test --test live_scan -- --ignored --nocapture
//! ```

use bdk_wallet::bitcoin::consensus::deserialize;
use bdk_wallet::bitcoin::secp256k1::{Secp256k1, SecretKey};
use bdk_wallet::bitcoin::{Address, Block, Network};
use kiss_bdk::blindbit::BlindbitClient;
use kiss_bdk::spreceive::ScanKeys;
use kiss_bdk::spscan::{scan_block, scanner};

const BLINDBIT: &str = "https://silentpayments.dev/blindbit/signet";
const ESPLORA: &str = "https://mempool.space/signet/api";
const HEIGHT: u32 = 318745;
const TXID: &str = "3a6801e9b5a7398406621299aefc8a2c915d20de612f21a26011972aa90cd12a";
const EXPECTED_SCRIPT: &str = "tb1p74frpnrdrq2mt09xdnrje0ewvctp4g2wzra0a8xpdmuc3lhuafast97k48";
const EXPECTED_CODE: &str = "tsp1qqd8n2k7uklxq4aegau7vawtptkgxsja4kt99lpv6krctwpq8tpc65qjxd4lu4etruh9sngx3su9mtqp5fqzxz7re59y5nnez9p03ht3lyudgq8ux";

fn test_keys() -> ScanKeys {
    let secp = Secp256k1::new();
    ScanKeys {
        scan: SecretKey::from_slice(&[0x11; 32]).unwrap(),
        spend: SecretKey::from_slice(&[0x22; 32])
            .unwrap()
            .public_key(&secp),
    }
}

fn get(url: String) -> Vec<u8> {
    minreq::get(&url)
        .with_timeout(60)
        .send()
        .unwrap_or_else(|e| panic!("fetching {url}: {e}"))
        .into_bytes()
}

#[test]
#[ignore = "needs the network and a third-party tweak server"]
fn finds_the_silent_payment_this_coordinator_broadcast() {
    let keys = test_keys();

    // The code must match the address the payment was actually sent to, or the
    // rest of the test is checking the wrong wallet.
    assert_eq!(keys.code(Network::Signet).to_string(), EXPECTED_CODE);

    let blindbit = BlindbitClient::new(BLINDBIT);
    let info = blindbit.info().expect("BlindBit info");
    assert_eq!(info.network, "signet", "wrong network served");
    assert!(
        info.height >= HEIGHT,
        "server has only indexed to {}, below the block under test",
        info.height
    );

    let tweaks = blindbit.tweaks(HEIGHT).expect("tweaks");
    assert!(!tweaks.is_empty(), "block {HEIGHT} should carry tweaks");

    let hash = String::from_utf8(get(format!("{ESPLORA}/block-height/{HEIGHT}")))
        .unwrap()
        .trim()
        .to_string();
    let block: Block = deserialize(&get(format!("{ESPLORA}/block/{hash}/raw"))).expect("raw block");

    let found = scan_block(&keys, &scanner(&keys), &tweaks, &block, HEIGHT).expect("scan");

    eprintln!(
        "{} tweaks over {} transactions found {} output(s)",
        tweaks.len(),
        block.txdata.len(),
        found.len()
    );

    assert_eq!(found.len(), 1, "exactly one payment belongs to these keys");
    let out = &found[0].out;
    assert_eq!(found[0].height, HEIGHT);
    assert_eq!(out.outpoint.txid.to_string(), TXID);
    assert_eq!(out.amount.to_sat(), 10_000);
    assert_eq!(
        Address::from_script(&out.script_pubkey, Network::Signet)
            .unwrap()
            .to_string(),
        EXPECTED_SCRIPT
    );
}
