use std::process::Command;

const PUBLIC_TEST_DESCRIPTOR: &str = "wpkh([73c5da0a/84h/1h/0h]tpubDC8msFGeGuwnKG9Upg7DM2b4DaRqg3CUZa5g8v2SRQ6K4NSkxUgd7HsL2XVWbVm39yBA4LAxysQAm397zwQSQoQgewGiYZqrA9DsP4zbQ1M/<0;1>/*)";

#[test]
fn initializes_watch_only_testnet4_wallet_and_matches_kiss_address() {
    let tmp = tempfile::tempdir().unwrap();
    let wallet_dir = tmp.path().join("wallet");
    let bin = env!("CARGO_BIN_EXE_kiss-bdk");

    let init = Command::new(bin)
        .arg("--wallet-dir")
        .arg(&wallet_dir)
        .args([
            "init",
            "--descriptor",
            PUBLIC_TEST_DESCRIPTOR,
            "--esplora",
            "http://127.0.0.1:1",
        ])
        .output()
        .unwrap();
    assert!(
        init.status.success(),
        "{}",
        String::from_utf8_lossy(&init.stderr)
    );

    let address = Command::new(bin)
        .arg("--wallet-dir")
        .arg(&wallet_dir)
        .arg("address")
        .output()
        .unwrap();
    assert!(
        address.status.success(),
        "{}",
        String::from_utf8_lossy(&address.stderr)
    );
    let stdout = String::from_utf8(address.stdout).unwrap();
    assert!(stdout.contains("tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl"));

    // Asking again returns the same unused address rather than silently skipping one.
    let again = Command::new(bin)
        .arg("--wallet-dir")
        .arg(&wallet_dir)
        .arg("address")
        .output()
        .unwrap();
    assert!(
        String::from_utf8(again.stdout)
            .unwrap()
            .contains("tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl")
    );
}
