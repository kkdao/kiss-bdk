//! The Electrum tweak stream's state machine, against a scripted server.
//!
//! Unit tests in the module cover one height map at a time. What they cannot
//! cover is the shape of the conversation, which is where this protocol is
//! unusual: `blockchain.tweaks.subscribe` answers with only the *first* height
//! and pushes every other one as an unsolicited notification, ending on a
//! sentinel rather than a count. A client that treats it as request/response
//! reads one height and calls the scan complete.
//!
//! So the server here is a socket that replays exactly that, including the
//! parts that must be ignored and the ways it can go wrong. No node needed.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::sync::mpsc;
use std::thread;

use kiss_bdk::electrum::Electrum;
use serde_json::Value;

/// The default signet genesis, which is the chain these tests pretend to be on.
const SIGNET_GENESIS: &str = "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6";

/// A responder line that hangs up instead of being sent, for the tests about
/// what a client does when the socket dies under it.
const HANG_UP: &str = "<hang up>";

/// Serve one connection, answering each request line with canned lines.
///
/// Returns the address to connect to. The listener is bound before the thread
/// starts, so there is no window in which a test can connect too early.
fn serve(responder: impl Fn(&str, u64) -> Vec<String> + Send + 'static) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
    let address = listener.local_addr().unwrap().to_string();

    thread::spawn(move || {
        let Ok((socket, _)) = listener.accept() else {
            return;
        };
        let mut writer = socket.try_clone().unwrap();
        let mut reader = BufReader::new(socket);
        let mut line = String::new();
        while reader.read_line(&mut line).unwrap_or(0) > 0 {
            let request: Value = serde_json::from_str(&line).expect("the client sent JSON");
            let method = request["method"].as_str().expect("a method").to_string();
            let id = request["id"].as_u64().expect("an id");
            for reply in responder(&method, id) {
                if reply == HANG_UP {
                    let _ = writer.flush();
                    return;
                }
                if writeln!(writer, "{reply}").is_err() {
                    return;
                }
            }
            let _ = writer.flush();
            line.clear();
        }
    });
    address
}

fn result(id: u64, value: &str) -> String {
    format!(r#"{{"jsonrpc":"2.0","id":{id},"result":{value}}}"#)
}

fn notify(map: &str) -> String {
    format!(r#"{{"jsonrpc":"2.0","method":"blockchain.tweaks.subscribe","params":[{map}]}}"#)
}

fn done() -> String {
    notify(r#"{"message":"done"}"#)
}

/// One height carrying one candidate, so a delivered height can be told apart
/// from an empty one. On one line, because the protocol is line-delimited.
fn height_with_a_candidate(height: u32) -> String {
    format!(
        r#"{{"{height}":{{"0185a62484ca086b1a620552c770f852fb2303ff26f85849beb66f767da4e078":{{"tweak":"02d092672ad97a476b27c7e58ff229d94dc2f644517913d316f0cd873132d57b26","output_pubkeys":{{"1":["5f94ca3effa19817039eda99ebce0be1a2a338dad1eb87961ef036a025e8dd7f",5410]}}}}}}}}"#
    )
}

fn standard(method: &str, id: u64) -> Option<Vec<String>> {
    match method {
        "server.features" => Some(vec![result(
            id,
            &format!(
                r#"{{"genesis_hash":"{SIGNET_GENESIS}","server_version":"rbitcoin-electrs"}}"#
            ),
        )]),
        "blockchain.headers.subscribe" => Some(vec![result(id, r#"{"height":102,"hex":"00"}"#)]),
        _ => None,
    }
}

#[test]
fn the_genesis_hash_and_tip_read_back() {
    let address = serve(|method, id| standard(method, id).unwrap_or_default());
    let mut server = Electrum::connect(&address).unwrap();
    assert_eq!(server.genesis_hash().unwrap().to_string(), SIGNET_GENESIS);
    assert_eq!(server.tip_height().unwrap(), 102);
}

#[test]
fn every_height_arrives_not_only_the_one_in_the_result() {
    let address = serve(|method, id| {
        if let Some(canned) = standard(method, id) {
            return canned;
        }
        vec![
            result(id, &height_with_a_candidate(100)),
            notify(r#"{"101":{}}"#),
            notify(&height_with_a_candidate(102)),
            done(),
        ]
    });

    let mut seen = Vec::new();
    let delivered = Electrum::connect(&address)
        .unwrap()
        .tweaks(100, 3, |height, candidates| {
            seen.push((height, candidates.len()));
            Ok(())
        })
        .unwrap();

    assert_eq!(delivered, 3, "the result is a height too, not a preamble");
    assert_eq!(seen, [(100, 1), (101, 0), (102, 1)]);
}

/// An empty height is not a non-event: it is what lets the watermark advance,
/// so a scan interrupted over a quiet stretch resumes there and not before it.
#[test]
fn empty_heights_are_delivered_rather_than_skipped() {
    let address = serve(|method, id| {
        if let Some(canned) = standard(method, id) {
            return canned;
        }
        vec![
            result(id, r#"{"100":{}}"#),
            notify(r#"{"101":{}}"#),
            notify(r#"{"102":{}}"#),
            done(),
        ]
    });

    let mut seen = Vec::new();
    Electrum::connect(&address)
        .unwrap()
        .tweaks(100, 3, |height, _| {
            seen.push(height);
            Ok(())
        })
        .unwrap();
    assert_eq!(seen, [100, 101, 102]);
}

/// The tip subscription shares the socket, so a block found mid-scan arrives in
/// the middle of the stream. It is not ours to read and not a reason to stop.
#[test]
fn a_header_notification_mid_stream_is_stepped_over() {
    let address = serve(|method, id| {
        if let Some(canned) = standard(method, id) {
            return canned;
        }
        vec![
            result(id, r#"{"100":{}}"#),
            r#"{"jsonrpc":"2.0","method":"blockchain.headers.subscribe","params":[{"height":103,"hex":"00"}]}"#.to_string(),
            notify(r#"{"101":{}}"#),
            done(),
        ]
    });

    let mut seen = Vec::new();
    Electrum::connect(&address)
        .unwrap()
        .tweaks(100, 2, |height, _| {
            seen.push(height);
            Ok(())
        })
        .unwrap();
    assert_eq!(seen, [100, 101]);
}

#[test]
fn a_refused_scan_is_reported_rather_than_read_as_empty() {
    let address = serve(|method, id| {
        if let Some(canned) = standard(method, id) {
            return canned;
        }
        vec![format!(
            r#"{{"jsonrpc":"2.0","id":{id},"error":{{"code":1,"message":"no such height"}}}}"#
        )]
    });

    let error = Electrum::connect(&address)
        .unwrap()
        .tweaks(100, 1, |_, _| Ok(()))
        .unwrap_err()
        .to_string();
    assert!(error.contains("no such height"), "{error}");
}

/// The sentinel is the only thing that says a range was fully served. Without
/// it, a socket that closes early would otherwise look like a completed scan
/// and the watermark would move past blocks nobody searched.
#[test]
fn a_stream_cut_short_is_an_error_not_a_short_scan() {
    let address = serve(|method, id| {
        if let Some(canned) = standard(method, id) {
            return canned;
        }
        // Two heights of a three-height range, then the connection drops.
        vec![
            result(id, r#"{"100":{}}"#),
            notify(r#"{"101":{}}"#),
            HANG_UP.to_string(),
        ]
    });

    let mut seen = Vec::new();
    let error = Electrum::connect(&address)
        .unwrap()
        .tweaks(100, 3, |height, _| {
            seen.push(height);
            Ok(())
        })
        .unwrap_err()
        .to_string();
    assert_eq!(seen, [100, 101], "what did arrive was still handled");
    assert!(error.contains("closed the connection"), "{error}");
}

/// A store write can fail mid-scan. It has to stop the stream there rather than
/// be swallowed, or the watermark advances over a height that was not stored.
#[test]
fn a_failing_callback_stops_the_scan() {
    let (sent, received) = mpsc::channel();
    let address = serve(move |method, id| {
        if let Some(canned) = standard(method, id) {
            return canned;
        }
        let _ = sent.send(());
        vec![result(id, r#"{"100":{}}"#), notify(r#"{"101":{}}"#), done()]
    });

    let error = Electrum::connect(&address)
        .unwrap()
        .tweaks(100, 2, |height, _| {
            anyhow::bail!("the database is locked at {height}")
        })
        .unwrap_err()
        .to_string();
    assert!(error.contains("the database is locked at 100"), "{error}");
    received.recv().expect("the server did answer");
}

/// The three calls that prove a match read a real server's replies: the raw
/// transaction, the merkle branch as reversed hex like a txid (what rbitcoin's
/// `hash_hex_rev` writes), and the 80 byte header.
#[test]
fn a_match_is_proven_over_the_same_server() {
    use bdk_wallet::bitcoin::block::{Header, Version};
    use bdk_wallet::bitcoin::consensus::encode::serialize_hex;
    use bdk_wallet::bitcoin::hashes::{Hash, sha256d};
    use bdk_wallet::bitcoin::{
        Amount, BlockHash, CompactTarget, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
        TxMerkleNode, TxOut, Witness, absolute, transaction,
    };
    use kiss_bdk::electrum::InclusionSource;

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
    let txid = tx.compute_txid();
    let sibling = TxMerkleNode::from_byte_array([0x42; 32]);
    let mut pair = [0_u8; 64];
    pair[..32].copy_from_slice(&sibling.to_byte_array());
    pair[32..].copy_from_slice(&txid.to_byte_array());
    let header = Header {
        version: Version::TWO,
        prev_blockhash: BlockHash::from_byte_array([0x01; 32]),
        merkle_root: TxMerkleNode::from_byte_array(sha256d::Hash::hash(&pair).to_byte_array()),
        time: 1,
        bits: CompactTarget::from_consensus(0x207f_ffff),
        nonce: 2,
    };

    let (tx_hex, header_hex, sibling_hex) = (
        serialize_hex(&tx),
        serialize_hex(&header),
        sibling.to_string(),
    );
    let (asked_tx, asked) = mpsc::channel();
    let address = serve(move |method, id| {
        asked_tx.send(method.to_string()).unwrap();
        match method {
            "blockchain.transaction.get" => vec![result(id, &format!("\"{tx_hex}\""))],
            "blockchain.transaction.get_merkle" => vec![result(
                id,
                &format!(r#"{{"block_height":7,"merkle":["{sibling_hex}"],"pos":1}}"#),
            )],
            "blockchain.block.header" => vec![result(id, &format!("\"{header_hex}\""))],
            _ => Vec::new(),
        }
    });

    let mut server = Electrum::connect(&address).unwrap();
    assert_eq!(server.header(7).unwrap(), header);
    let (got_tx, pos, branch) = server.placement(&txid, 7).unwrap();
    assert_eq!(got_tx, tx);
    assert_eq!(pos, 1);
    assert_eq!(branch, [sibling], "branch hashes are read as reversed hex");
    assert_eq!(
        asked.try_iter().collect::<Vec<_>>(),
        [
            "blockchain.block.header",
            "blockchain.transaction.get",
            "blockchain.transaction.get_merkle"
        ]
    );
}

/// A transaction with one output, the stored coin at vout 0, as hex.
fn one_output_tx() -> (bdk_wallet::bitcoin::Transaction, String) {
    use bdk_wallet::bitcoin::consensus::encode::serialize_hex;
    use bdk_wallet::bitcoin::{
        Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness, absolute,
        transaction,
    };
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
    let hex = serialize_hex(&tx);
    (tx, hex)
}

/// Whether a stored coin is spent, against each answer a server can give.
#[test]
fn a_coin_lookup_reads_both_dialects_and_refuses_anything_else() {
    use bdk_wallet::bitcoin::OutPoint;

    let (tx, hex) = one_output_tx();
    let ours = OutPoint::new(tx.compute_txid(), 0);
    let script = tx.output[0].script_pubkey.clone();
    let spender = "0185a62484ca086b1a620552c770f852fb2303ff26f85849beb66f767da4e078";
    let cases: Vec<(String, Option<bool>)> = vec![
        // rbitcoin's own shape
        (r#"{"spent":false,"vout":0}"#.into(), Some(false)),
        (r#"{"spent":true,"height":0}"#.into(), Some(true)),
        (
            format!(r#"{{"spent":true,"height":0,"spending_txid":"{spender}"}}"#),
            Some(true),
        ),
        // protocol 1.7
        (r#"{"funder_height":100}"#.into(), Some(false)),
        (
            format!(r#"{{"funder_height":100,"spender_txhash":"{spender}","spender_height":101}}"#),
            Some(true),
        ),
        // malformed or self-contradicting: refused, never read as unspent
        (r#"{}"#.into(), None),
        (r#"{"height":null}"#.into(), None),
        (r#"{"height":"broken"}"#.into(), None),
        (r#"{"spent":"no"}"#.into(), None),
        (
            format!(r#"{{"spent":false,"spender_txhash":"{spender}","spender_height":101}}"#),
            None,
        ),
        (
            format!(r#"{{"spent":false,"spending_txid":"{spender}"}}"#),
            None,
        ),
        (r#"{"funder_height":"x"}"#.into(), None),
        (
            r#"{"funder_height":100,"spender_txhash":"not a txid"}"#.into(),
            None,
        ),
        (r#"[]"#.into(), None),
        // a spender half there: refused, not read as unspent
        (r#"{"funder_height":100,"spender_height":101}"#.into(), None),
        (
            r#"{"funder_height":100,"spender_txhash":null,"spender_height":101}"#.into(),
            None,
        ),
        (r#"{"spent":false,"spender_height":101}"#.into(), None),
        (
            format!(r#"{{"funder_height":100,"spender_txhash":"{spender}"}}"#),
            None,
        ),
        (
            format!(r#"{{"funder_height":100,"spending_txid":"{spender}"}}"#),
            None,
        ),
        (r#"{"spent":true,"spending_txid":null}"#.into(), None),
    ];
    for (status_reply, want) in cases {
        let tx_reply = format!("\"{hex}\"");
        let reply = status_reply.clone();
        let address = serve(move |method, id| match method {
            "blockchain.transaction.get" => vec![result(id, &tx_reply)],
            "blockchain.outpoint.get_status" => vec![result(id, &reply)],
            _ => Vec::new(),
        });
        let got = Electrum::connect(&address)
            .unwrap()
            .output_status(&ours, &script);
        match want {
            Some(want) => assert_eq!(got.unwrap(), Some(want), "{status_reply}"),
            None => assert!(got.is_err(), "{status_reply} was read as {got:?}"),
        }
    }
}

/// The status request carries the 1.7 spk_hint, and the version handshake
/// reads the protocol the server picked.
#[test]
fn the_status_request_carries_the_script_and_the_version_is_agreed() {
    use bdk_wallet::bitcoin::OutPoint;
    use std::io::{BufRead, BufReader, Write};

    let (tx, hex) = one_output_tx();
    let script = tx.output[0].script_pubkey.clone();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let (sent_tx, sent) = mpsc::channel();
    thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        let mut writer = socket.try_clone().unwrap();
        let mut reader = BufReader::new(socket);
        let mut line = String::new();
        while reader.read_line(&mut line).unwrap_or(0) > 0 {
            let request: Value = serde_json::from_str(&line).unwrap();
            sent_tx.send(request.clone()).unwrap();
            let id = request["id"].as_u64().unwrap();
            let reply = match request["method"].as_str().unwrap() {
                "server.version" => r#"["rbitcoin 0.5", "1.6"]"#.to_string(),
                "blockchain.transaction.get" => format!("\"{hex}\""),
                _ => r#"{"spent":false}"#.to_string(),
            };
            writeln!(writer, "{}", result(id, &reply)).unwrap();
            line.clear();
        }
    });

    let mut node = Electrum::connect(&address).unwrap();
    assert_eq!(node.negotiate().unwrap(), "1.6");
    node.output_status(&OutPoint::new(tx.compute_txid(), 0), &script)
        .unwrap();
    let requests: Vec<Value> = sent.try_iter().collect();
    assert_eq!(requests[0]["method"], "server.version");
    assert_eq!(requests[0]["params"][1], serde_json::json!(["1.4", "1.7"]));
    let status = requests
        .iter()
        .find(|r| r["method"] == "blockchain.outpoint.get_status")
        .unwrap();
    assert_eq!(status["params"][0], tx.compute_txid().to_string());
    assert_eq!(status["params"][1], 0);
    assert_eq!(status["params"][2], script.to_hex_string());
}

#[test]
fn a_coin_is_only_gone_when_its_transaction_is() {
    use bdk_wallet::bitcoin::OutPoint;

    let (tx, hex) = one_output_tx();
    let script = tx.output[0].script_pubkey.clone();
    let refusal = |id: u64, message: &str| {
        format!(r#"{{"jsonrpc":"2.0","id":{id},"error":{{"code":-32600,"message":"{message}"}}}}"#)
    };

    // The two wordings for an unknown transaction: gone, and the outpoint is
    // not asked about at all.
    for message in ["tx not found", "No such mempool or blockchain transaction"] {
        let (asked_tx, asked) = mpsc::channel();
        let address = serve(move |method, id| {
            asked_tx.send(method.to_string()).unwrap();
            vec![refusal(id, message)]
        });
        let got = Electrum::connect(&address)
            .unwrap()
            .output_status(&OutPoint::new(tx.compute_txid(), 0), &script);
        assert_eq!(got.unwrap(), None, "{message}");
        assert_eq!(
            asked.try_iter().collect::<Vec<_>>(),
            ["blockchain.transaction.get"]
        );
    }

    // Refusals that say nothing about the transaction are errors, so the
    // caller marks the coin unverified instead of treating it as gone.
    for message in ["Method not found", "No such database table", "server busy"] {
        let address = serve(move |_, id| vec![refusal(id, message)]);
        assert!(
            Electrum::connect(&address)
                .unwrap()
                .output_status(&OutPoint::new(tx.compute_txid(), 0), &script)
                .is_err(),
            "{message} was read as not found"
        );
    }

    // An output past the end of a transaction that exists: gone.
    let hex2 = hex.clone();
    let address = serve(move |_, id| vec![result(id, &format!("\"{hex2}\""))]);
    assert_eq!(
        Electrum::connect(&address)
            .unwrap()
            .output_status(&OutPoint::new(tx.compute_txid(), 5), &script)
            .unwrap(),
        None
    );

    // A server answering with some other transaction is refused.
    let address = serve(move |_, id| vec![result(id, &format!("\"{hex}\""))]);
    let other = OutPoint::new(
        "0185a62484ca086b1a620552c770f852fb2303ff26f85849beb66f767da4e078"
            .parse()
            .unwrap(),
        0,
    );
    assert!(
        Electrum::connect(&address)
            .unwrap()
            .output_status(&other, &script)
            .is_err()
    );
}

/// A version reply outside what was offered, or not shaped like one, stops
/// the lookup before anything is asked.
#[test]
fn a_version_reply_outside_the_offer_is_refused() {
    for reply in [
        r#"["server", "9.0"]"#,
        r#"[null, "garbage"]"#,
        r#"["server", "1.3"]"#,
        r#"["server", "1.8"]"#,
        r#"["server", "1."]"#,
        r#"["server"]"#,
        r#""1.6""#,
    ] {
        let address = serve(move |_, id| vec![result(id, reply)]);
        assert!(
            Electrum::connect(&address).unwrap().negotiate().is_err(),
            "{reply} was accepted"
        );
    }
    for (reply, agreed) in [
        (r#"["rbitcoin 0.5", "1.6"]"#, "1.6"),
        (r#"["Fulcrum 2.0", "1.7"]"#, "1.7"),
        (r#"["electrs", "1.4.2"]"#, "1.4.2"),
    ] {
        let address = serve(move |_, id| vec![result(id, reply)]);
        assert_eq!(
            Electrum::connect(&address).unwrap().negotiate().unwrap(),
            agreed
        );
    }
}
