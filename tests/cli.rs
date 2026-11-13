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
    // Regtest is not in this list any more: it is a chain you run yourself, so
    // it carries none of the risk mainnet does. Mainnet stays refused.
    for network in ["bitcoin", "mainnet", "testnet3"] {
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
fn initializes_a_regtest_wallet_against_a_local_node() {
    let tmp = tempfile::tempdir().unwrap();
    let wallet_dir = tmp.path().join("wallet");
    init_watch_only(&wallet_dir, "regtest");

    let (ok, stdout, stderr) = run(&wallet_dir, &["address"]);
    assert!(ok, "{stderr}");
    // Same descriptor, same keys — but regtest says so in the address, which is
    // what stops a regtest coin being confused for a testnet one.
    assert!(stdout.contains("bcrt1"), "{stdout}");

    // No faucet exists for a chain of your own, and the command should say how
    // to get coins rather than point at a website that cannot help.
    let (ok, stdout, stderr) = run(&wallet_dir, &["faucet", "--sats", "10000"]);
    assert!(ok, "{stderr}");
    assert!(stdout.contains("generatetodescriptor"), "{stdout}");
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
    // "spendable" rather than a stored total: the store records what a scan
    // found, and a coin can be spent or replaced afterwards without the table
    // ever hearing about it.
    assert!(stdout.contains("spendable: 0 sats"), "{stdout}");
}

#[test]
fn spending_silent_payments_needs_a_pairing_before_it_needs_coins() {
    let tmp = tempfile::tempdir().unwrap();
    let wallet_dir = tmp.path().join("wallet");
    init_watch_only(&wallet_dir, "signet");

    // "insufficient funds" would be true and useless: nothing has been paired,
    // so there is no key with which a payment could ever have been found.
    // `--out` inside the temp directory on purpose: the default is relative to
    // the working directory, so without it these tests fail whenever the repo
    // root happens to hold an `unsigned.psbt` from real use.
    let out = tmp.path().join("unsigned.psbt");
    let (ok, _, stderr) = run(
        &wallet_dir,
        &[
            "create",
            "--to",
            KISS_FIRST_ADDRESS,
            "--sats",
            "10000",
            "--from-sp",
            "--fee-rate",
            "2",
            "--out",
            out.to_str().unwrap(),
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
    // `--out` inside the temp directory on purpose: the default is relative to
    // the working directory, so without it these tests fail whenever the repo
    // root happens to hold an `unsigned.psbt` from real use.
    let out = tmp.path().join("unsigned.psbt");
    let (ok, _, stderr) = run(
        &wallet_dir,
        &[
            "create",
            "--to",
            KISS_FIRST_ADDRESS,
            "--sats",
            "10000",
            "--from-sp",
            "--fee-rate",
            "2",
            "--out",
            out.to_str().unwrap(),
        ],
    );
    assert!(!ok, "no silent payments have been found yet");
    assert!(stderr.contains("sp-scan"), "{stderr}");
}

/// The default signet genesis, which the fake node below says it is on.
const SIGNET_GENESIS: &str = "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6";

/// A port that counts every connection made to it and answers none.
fn counting_listener() -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let hits = Arc::new(AtomicUsize::new(0));
    let seen = hits.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            seen.fetch_add(1, Ordering::SeqCst);
            drop(stream);
        }
    });
    (url, hits)
}

/// One Electrum connection that knows one transaction, unspent.
fn fake_node(tx_hex: String) -> String {
    fake_node_answering(Ok(tx_hex))
}

/// One Electrum connection whose transaction lookup returns `tx`: the hex,
/// or a refusal with that message.
fn fake_node_answering(tx: Result<String, String>) -> String {
    use std::io::{BufRead, BufReader, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    std::thread::spawn(move || {
        let Ok((socket, _)) = listener.accept() else {
            return;
        };
        let mut writer = socket.try_clone().unwrap();
        let mut reader = BufReader::new(socket);
        let mut line = String::new();
        while reader.read_line(&mut line).unwrap_or(0) > 0 {
            let request: serde_json::Value = serde_json::from_str(&line).unwrap();
            let id = request["id"].as_u64().unwrap();
            let method = request["method"].as_str().unwrap();
            let reply = match (method, &tx) {
                ("blockchain.transaction.get", Err(message)) => serde_json::json!({
                    "jsonrpc": "2.0", "id": id,
                    "error": { "code": -32600, "message": message },
                }),
                _ => {
                    let result = match method {
                        "server.version" => serde_json::json!(["fake", "1.6"]),
                        "server.features" => {
                            serde_json::json!({ "genesis_hash": SIGNET_GENESIS })
                        }
                        "blockchain.transaction.get" => serde_json::json!(tx.clone().unwrap()),
                        "blockchain.outpoint.get_status" => serde_json::json!({ "spent": false }),
                        _ => serde_json::Value::Null,
                    };
                    serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": result })
                }
            };
            if writeln!(writer, "{reply}").is_err() {
                return;
            }
            line.clear();
        }
    });
    address
}

/// A wallet holding one found silent payment, with `node` remembered as the
/// owner's Electrum node, and Esplora pointed at `esplora`.
fn wallet_with_a_coin(wallet_dir: &Path, esplora: &str, node: &str) -> String {
    wallet_with_a_coin_at(wallet_dir, esplora, node, 100)
}

/// The same, with the coin recorded at `height` (0 for one seen unconfirmed).
fn wallet_with_a_coin_at(wallet_dir: &Path, esplora: &str, node: &str, height: u32) -> String {
    use bdk_wallet::bitcoin::consensus::encode::serialize_hex;
    use bdk_wallet::bitcoin::secp256k1::SecretKey;
    use bdk_wallet::bitcoin::{
        Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness, absolute,
        transaction,
    };
    let (ok, _, stderr) = run(
        wallet_dir,
        &[
            "init",
            "--network",
            "signet",
            "--descriptor",
            PUBLIC_TEST_DESCRIPTOR,
            "--esplora",
            esplora,
        ],
    );
    assert!(ok, "init failed: {stderr}");
    let tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(21_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51, 0x20, 0x01]),
        }],
    };
    let mut connection =
        bdk_wallet::rusqlite::Connection::open(wallet_dir.join("wallet.sqlite")).unwrap();
    kiss_bdk::spstore::migrate(&mut connection).unwrap();
    kiss_bdk::spstore::put_found(
        &mut connection,
        &[kiss_bdk::spscan::Found {
            height,
            out: bdk_sp::receive::SpOut {
                outpoint: OutPoint::new(tx.compute_txid(), 0),
                tweak: SecretKey::from_slice(&[0x33; 32]).unwrap(),
                script_pubkey: tx.output[0].script_pubkey.clone(),
                amount: tx.output[0].value,
                label: None,
            },
        }],
    )
    .unwrap();
    kiss_bdk::spstore::set_node(&connection, node).unwrap();
    serialize_hex(&tx)
}

/// The privacy property, through the real command: with a node remembered,
/// sp-balance asks it about the coin and makes no request to Esplora at all.
#[test]
fn sp_balance_asks_the_remembered_node_and_never_esplora() {
    use std::sync::atomic::Ordering;
    let tmp = tempfile::tempdir().unwrap();
    let wallet_dir = tmp.path().join("wallet");
    let (esplora, hits) = counting_listener();

    // The node's address is only known once it is listening, and the coin's
    // transaction only once the wallet holds it, so the wallet is built first
    // with a placeholder node and then pointed at the real one.
    let tx_hex = wallet_with_a_coin(&wallet_dir, &esplora, "127.0.0.1:1");
    let node = fake_node(tx_hex);
    let connection =
        bdk_wallet::rusqlite::Connection::open(wallet_dir.join("wallet.sqlite")).unwrap();
    kiss_bdk::spstore::set_node(&connection, &node).unwrap();
    drop(connection);

    let (ok, stdout, stderr) = run(&wallet_dir, &["sp-balance"]);
    assert!(ok, "{stderr}");
    assert!(stdout.contains("21000 sats at"), "{stdout}");
    assert!(stdout.contains("(spendable, block 100)"), "{stdout}");
    assert!(stdout.contains("spendable: 21000 sats"), "{stdout}");
    assert!(!stdout.contains("note: asking"), "{stdout}");
    assert_eq!(hits.load(Ordering::SeqCst), 0, "Esplora was contacted");

    // The control: the same wallet told to ask Esplora does contact it, so the
    // zero above is the command keeping quiet, not a listener that hears nothing.
    let (_, stdout, _) = run(&wallet_dir, &["sp-balance", "--esplora-lookups"]);
    assert!(stdout.contains("note: asking"), "{stdout}");
    assert!(
        hits.load(Ordering::SeqCst) > 0,
        "the listener never heard the control"
    );
}

/// A remembered node that cannot be reached stops the command instead of
/// quietly asking Esplora.
#[test]
fn an_unreachable_node_is_an_error_not_a_quiet_fallback() {
    use std::sync::atomic::Ordering;
    let tmp = tempfile::tempdir().unwrap();
    let wallet_dir = tmp.path().join("wallet");
    let (esplora, hits) = counting_listener();
    wallet_with_a_coin(&wallet_dir, &esplora, "127.0.0.1:1");

    let (ok, _, stderr) = run(&wallet_dir, &["sp-balance"]);
    assert!(!ok, "an unreachable node was not reported");
    assert!(stderr.contains("--esplora-lookups"), "{stderr}");
    assert_eq!(hits.load(Ordering::SeqCst), 0, "fell back to Esplora");
}

/// An unconfirmed coin the node does not know is reported and kept, whatever
/// the node says: one node's "not found" does not prove a payment was
/// replaced, and an unrelated error says nothing about it at all.
#[test]
fn a_node_never_makes_sp_balance_forget_a_coin() {
    for (answer, says) in [
        ("tx not found", "unknown to"),
        ("Method not found", "(unverified)"),
        ("No such database table", "(unverified)"),
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let wallet_dir = tmp.path().join("wallet");
        let (esplora, _) = counting_listener();
        wallet_with_a_coin_at(&wallet_dir, &esplora, "127.0.0.1:1", 0);

        for _ in 0..2 {
            let node = fake_node_answering(Err(answer.to_string()));
            let connection =
                bdk_wallet::rusqlite::Connection::open(wallet_dir.join("wallet.sqlite")).unwrap();
            kiss_bdk::spstore::set_node(&connection, &node).unwrap();
            drop(connection);

            let (ok, stdout, stderr) = run(&wallet_dir, &["sp-balance"]);
            assert!(ok, "{answer}: {stderr}");
            assert!(!stdout.contains("forgot"), "{answer}: {stdout}");
            assert!(stdout.contains(says), "{answer}: {stdout}");
            assert!(
                stdout.contains("21000 sats at"),
                "{answer}: the coin is gone: {stdout}"
            );
        }
        let connection =
            bdk_wallet::rusqlite::Connection::open(wallet_dir.join("wallet.sqlite")).unwrap();
        assert_eq!(
            kiss_bdk::spstore::outputs(&connection).unwrap().len(),
            1,
            "{answer}: the row was deleted"
        );
    }
}

/// An Esplora that answers every request with `body` as JSON, forever.
fn fee_server(body: &'static str) -> String {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buffer = [0_u8; 2048];
            let _ = stream.read(&mut buffer);
            let reply = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(reply.as_bytes());
        }
    });
    url
}

/// The real create, against a backend that asks for an absurd fee rate: it
/// stops before writing anything, and says how to pay that rate on purpose.
#[test]
fn create_refuses_a_backend_fee_estimate_above_the_ceiling() {
    let tmp = tempfile::tempdir().unwrap();
    for (body, refused) in [(r#"{"1":50.0}"#, true), (r#"{"1":3.0}"#, false)] {
        let wallet_dir = tmp.path().join(format!("wallet-{refused}"));
        let esplora = fee_server(body);
        let (ok, _, stderr) = run(
            &wallet_dir,
            &[
                "init",
                "--network",
                "signet",
                "--descriptor",
                PUBLIC_TEST_DESCRIPTOR,
                "--esplora",
                &esplora,
            ],
        );
        assert!(ok, "init failed: {stderr}");
        let out = wallet_dir.join("unsigned.psbt");
        let (ok, stdout, stderr) = run(
            &wallet_dir,
            &[
                "create",
                "--to",
                KISS_FIRST_ADDRESS,
                "--sats",
                "1000",
                "--out",
                out.to_str().unwrap(),
            ],
        );
        assert!(!ok, "an empty wallet cannot pay anyway");
        assert!(!out.exists(), "a PSBT was written");
        if refused {
            assert!(stderr.contains("--fee-rate 50"), "{stderr}");
            assert!(!stdout.contains("fee rate:"), "{stdout}");
        } else {
            // Past the fee step: the 3 sat/vB estimate was taken, and what
            // stops it is the empty wallet.
            assert!(stdout.contains("fee rate: 3 sat/vB"), "{stdout}");
            assert!(!stderr.contains("--fee-rate"), "{stderr}");
        }
    }
}
