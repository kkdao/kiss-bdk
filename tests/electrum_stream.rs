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
