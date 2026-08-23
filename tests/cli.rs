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

/// KISS's scan-key export for throwaway keys (scan `0x11`×32, spend `0x22`×32),
/// in the `sp([origin]tspscan1…)` shape `kiss_session_sp_scan_export` prints.
const SCAN_EXPORT: &str = "sp([73c5da0a/352h/1h/0h]tspscan1qzyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsy3nd0l9w2cl9evy6p5v8pw6cqdzgq3shs7dpf9yu7g3gtud6u0e8sykkkg)";

/// The silent payment code those keys receive on.
const SCAN_EXPORT_CODE: &str = "tsp1qqd8n2k7uklxq4aegau7vawtptkgxsja4kt99lpv6krctwpq8tpc65qjxd4lu4etruh9sngx3su9mtqp5fqzxz7re59y5nnez9p03ht3lyudgq8ux";

#[test]
fn pairing_a_scan_key_yields_the_address_it_receives_on() {
    let tmp = tempfile::tempdir().unwrap();
    let wallet_dir = tmp.path().join("wallet");
    init_watch_only(&wallet_dir, "signet");

    let (ok, stdout, stderr) = run(&wallet_dir, &["sp-pair", "--key", SCAN_EXPORT]);
    assert!(ok, "{stderr}");
    assert!(stdout.contains(SCAN_EXPORT_CODE), "{stdout}");
    // Importing a private key must say so rather than leave it to the docs.
    assert!(stdout.contains("scan private key"), "{stdout}");

    // The address must survive the round trip through storage unchanged.
    let (ok, stdout, stderr) = run(&wallet_dir, &["sp-address"]);
    assert!(ok, "{stderr}");
    assert!(stdout.contains(SCAN_EXPORT_CODE), "{stdout}");
}

#[test]
fn an_unpaired_wallet_says_what_to_run_rather_than_failing_obscurely() {
    let tmp = tempfile::tempdir().unwrap();
    let wallet_dir = tmp.path().join("wallet");
    init_watch_only(&wallet_dir, "signet");

    for command in [vec!["sp-address"], vec!["sp-scan"]] {
        let (ok, _, stderr) = run(&wallet_dir, &command);
        assert!(!ok, "{command:?} should fail without keys");
        assert!(stderr.contains("sp-pair"), "{command:?}: {stderr}");
    }
}

#[test]
fn a_chain_with_no_known_oracle_refuses_rather_than_guessing() {
    let tmp = tempfile::tempdir().unwrap();
    let wallet_dir = tmp.path().join("wallet");
    init_watch_only(&wallet_dir, "testnet4");
    run(&wallet_dir, &["sp-pair", "--key", SCAN_EXPORT]);

    // Signet's oracle would answer confidently about heights that mean nothing
    // on another chain, so there is deliberately no shared default.
    let (ok, _, stderr) = run(&wallet_dir, &["sp-scan"]);
    assert!(!ok, "testnet4 has no tweak oracle");
    assert!(stderr.contains("--blindbit"), "{stderr}");
}

#[test]
fn sp_balance_reports_an_empty_wallet_without_a_scan() {
    let tmp = tempfile::tempdir().unwrap();
    let wallet_dir = tmp.path().join("wallet");
    init_watch_only(&wallet_dir, "signet");

    let (ok, stdout, stderr) = run(&wallet_dir, &["sp-balance"]);
    assert!(ok, "{stderr}");
    assert!(stdout.contains("never"), "{stdout}");
    assert!(stdout.contains("silent payment total: 0 sats"), "{stdout}");
}

#[test]
fn spending_silent_payments_needs_a_pairing_before_it_needs_coins() {
    let tmp = tempfile::tempdir().unwrap();
    let wallet_dir = tmp.path().join("wallet");
    init_watch_only(&wallet_dir, "signet");

    // "insufficient funds" would be true and useless: nothing has been paired,
    // so there is no key with which a payment could ever have been found.
    let (ok, _, stderr) = run(
        &wallet_dir,
        &[
            "create",
            "--to",
            KISS_FIRST_ADDRESS,
            "--sats",
            "10000",
            "--from-sp",
        ],
    );
    assert!(!ok, "an unpaired wallet cannot spend silent payments");
    assert!(stderr.contains("sp-pair"), "{stderr}");
}

#[test]
fn spending_silent_payments_says_to_scan_before_it_reaches_the_network() {
    let tmp = tempfile::tempdir().unwrap();
    let wallet_dir = tmp.path().join("wallet");
    init_watch_only(&wallet_dir, "signet");
    run(&wallet_dir, &["sp-pair", "--key", SCAN_EXPORT]);

    // Esplora points at a dead port here, so reaching it would hang or fail
    // obscurely. With nothing found there is nothing to ask about, and the
    // answer names the command that would change that.
    let (ok, _, stderr) = run(
        &wallet_dir,
        &[
            "create",
            "--to",
            KISS_FIRST_ADDRESS,
            "--sats",
            "10000",
            "--from-sp",
        ],
    );
    assert!(!ok, "no silent payments have been found yet");
    assert!(stderr.contains("sp-scan"), "{stderr}");
}
