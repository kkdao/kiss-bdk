use std::path::Path;
use std::process::Command;

const PUBLIC_TEST_DESCRIPTOR: &str = "wpkh([73c5da0a/84h/1h/0h]tpubDC8msFGeGuwnKG9Upg7DM2b4DaRqg3CUZa5g8v2SRQ6K4NSkxUgd7HsL2XVWbVm39yBA4LAxysQAm397zwQSQoQgewGiYZqrA9DsP4zbQ1M/<0;1>/*)";

/// The first address that descriptor derives. It is the same on every Bitcoin
/// test network, which is why Signet needs no change on the signer.
const KISS_FIRST_ADDRESS: &str = "tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl";

fn run(wallet_dir: &Path, args: &[&str]) -> (bool, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_kiss-bdk"))
        .arg("--wallet-dir")
        .arg(wallet_dir)
        // Blanked so no test can reach a real faucet from an ambient token.
        .env("MUTINYNET_FAUCET_TOKEN", "")
        .args(args)
        .output()
        .unwrap();
    (
        output.status.success(),
        String::from_utf8(output.stdout).unwrap(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn init_watch_only(wallet_dir: &Path, network: &str) {
    let (ok, _, stderr) = run(
        wallet_dir,
        &[
            "init",
            "--network",
            network,
            "--descriptor",
            PUBLIC_TEST_DESCRIPTOR,
            "--esplora",
            "http://127.0.0.1:1",
        ],
    );
    assert!(ok, "init {network} failed: {stderr}");
}

#[test]
fn initializes_watch_only_testnet4_wallet_and_matches_kiss_address() {
    let tmp = tempfile::tempdir().unwrap();
    let wallet_dir = tmp.path().join("wallet");
    init_watch_only(&wallet_dir, "testnet4");

    let (ok, stdout, stderr) = run(&wallet_dir, &["address"]);
    assert!(ok, "{stderr}");
    assert!(stdout.contains(KISS_FIRST_ADDRESS), "{stdout}");

    // Asking again returns the same unused address rather than silently skipping one.
    let (_, stdout, _) = run(&wallet_dir, &["address"]);
    assert!(stdout.contains(KISS_FIRST_ADDRESS), "{stdout}");
}

#[test]
fn every_test_network_derives_the_same_kiss_address() {
    let tmp = tempfile::tempdir().unwrap();
    for network in ["testnet4", "signet", "mutinynet"] {
        let wallet_dir = tmp.path().join(network);
        init_watch_only(&wallet_dir, network);
        let (ok, stdout, stderr) = run(&wallet_dir, &["address"]);
        assert!(ok, "{network}: {stderr}");
        assert!(
            stdout.contains(KISS_FIRST_ADDRESS),
            "{network} derived a different address: {stdout}"
        );
    }
}

#[test]
fn init_records_the_chosen_network_and_its_default_backend() {
    let tmp = tempfile::tempdir().unwrap();
    let wallet_dir = tmp.path().join("wallet");
    let (ok, stdout, stderr) = run(
        &wallet_dir,
        &[
            "init",
            "--network",
            "mutinynet",
            "--descriptor",
            PUBLIC_TEST_DESCRIPTOR,
        ],
    );
    assert!(ok, "{stderr}");
    assert!(stdout.contains("Mutinynet"), "{stdout}");
    assert!(stdout.contains("https://mutinynet.com/api"), "{stdout}");

    let config = std::fs::read_to_string(wallet_dir.join("config.json")).unwrap();
    assert!(config.contains("\"network\": \"signet\""), "{config}");
    assert!(config.contains("\"chain\": \"mutinynet\""), "{config}");

    // The wallet database is pinned to the network it was created on.
    let (ok, stdout, _) = run(&wallet_dir, &["balance"]);
    assert!(ok);
    assert!(stdout.contains("Mutinynet"), "{stdout}");
}

#[test]
fn rejects_mainnet_and_unknown_networks() {
    let tmp = tempfile::tempdir().unwrap();
    let wallet_dir = tmp.path().join("wallet");
    for network in ["bitcoin", "mainnet", "regtest"] {
        let (ok, _, _) = run(
            &wallet_dir,
            &[
                "init",
                "--network",
                network,
                "--descriptor",
                PUBLIC_TEST_DESCRIPTOR,
            ],
        );
        assert!(!ok, "init accepted --network {network}");
    }
}

#[test]
fn faucet_on_captcha_only_networks_explains_itself_without_claiming() {
    let tmp = tempfile::tempdir().unwrap();
    let wallet_dir = tmp.path().join("wallet");
    init_watch_only(&wallet_dir, "signet");

    let (ok, stdout, stderr) = run(&wallet_dir, &["faucet", "--sats", "10000"]);
    assert!(ok, "{stderr}");
    assert!(stdout.contains(KISS_FIRST_ADDRESS), "{stdout}");
    assert!(stdout.contains("captcha-protected"), "{stdout}");
    assert!(stdout.contains("bitcoinsignetfaucet.com"), "{stdout}");
}

#[test]
fn faucet_on_mutinynet_explains_how_to_get_a_token() {
    let tmp = tempfile::tempdir().unwrap();
    let wallet_dir = tmp.path().join("wallet");
    init_watch_only(&wallet_dir, "mutinynet");

    let (ok, stdout, stderr) = run(&wallet_dir, &["faucet", "--sats", "10000"]);
    assert!(!ok, "faucet claimed without a token");
    // The address is still shown so it can be pasted into the faucet page.
    assert!(stdout.contains(KISS_FIRST_ADDRESS), "{stdout}");
    assert!(stderr.contains("requires a token"), "{stderr}");
    assert!(stderr.contains("MUTINYNET_FAUCET_TOKEN"), "{stderr}");
}

#[test]
fn faucet_rejects_amounts_the_mutinynet_api_would_refuse() {
    let tmp = tempfile::tempdir().unwrap();
    let wallet_dir = tmp.path().join("wallet");
    init_watch_only(&wallet_dir, "mutinynet");

    let (ok, _, stderr) = run(&wallet_dir, &["faucet", "--sats", "1000001"]);
    assert!(!ok, "faucet accepted more than the API maximum");
    assert!(stderr.contains("1000000"), "{stderr}");
}
