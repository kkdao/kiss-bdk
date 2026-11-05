//! Two wallets in one process talk through a real Marmot group (MDK) over
//! a nostr relay started inside the test.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use kiss_bdk::marmot::{LocalRelay, Marmot};
use kiss_bdk::transport::Transport;

const WAIT: Duration = Duration::from_secs(15);

fn fresh_dir(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("marmot-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Collect exactly `n` messages, failing if they take too long.
fn receive_n(t: &mut Marmot, n: usize) -> Vec<String> {
    let start = Instant::now();
    let mut got = Vec::new();
    while got.len() < n {
        assert!(start.elapsed() < WAIT * 2, "only got {got:?}");
        got.extend(t.receive(WAIT).unwrap());
    }
    assert_eq!(got.len(), n, "more messages than sent: {got:?}");
    got
}

#[test]
fn two_wallets_share_one_group() {
    let relay = LocalRelay::start(0).unwrap();
    let relays = vec![relay.url().to_string()];
    let dir_a = fresh_dir("a");
    let dir_b = fresh_dir("b");

    let mut a = Marmot::open(&dir_a, &relays).unwrap();
    let mut b = Marmot::open(&dir_b, &relays).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir_a.join("marmot/identity.key"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    // Group setup: B publishes a key package, A invites B, B accepts.
    b.publish_key_package().unwrap();
    a.invite(&b.npub()).unwrap();
    assert_eq!(b.accept(WAIT).unwrap(), Some(a.npub()));

    // One message each way.
    a.send("hello from A").unwrap();
    assert_eq!(receive_n(&mut b, 1), ["hello from A"]);
    b.send("hello from B").unwrap();
    assert_eq!(receive_n(&mut a, 1), ["hello from B"]);

    // Ordering: several messages sent within the same second.
    for i in 0..5 {
        a.send(&format!("m{i}")).unwrap();
    }
    assert_eq!(receive_n(&mut b, 5), ["m0", "m1", "m2", "m3", "m4"]);

    // Nobody gets their own messages back.
    assert!(a.receive(Duration::from_secs(1)).unwrap().is_empty());

    // Restart B between messages, with the relays taken from its folder.
    drop(b);
    a.send("while B was away").unwrap();
    let mut b = Marmot::open(&dir_b, &[]).unwrap();
    assert_eq!(receive_n(&mut b, 1), ["while B was away"]);
    b.send("B is back").unwrap();
    assert_eq!(receive_n(&mut a, 1), ["B is back"]);

    // A payload the size of a PSBT.
    let psbt: String = (0..2048).map(|i| (b'A' + (i % 26) as u8) as char).collect();
    a.send(&psbt).unwrap();
    assert_eq!(receive_n(&mut b, 1), [psbt]);

    // Duplicates: the relay still serves every old event, and neither a
    // running instance nor a restarted one returns them again.
    assert!(b.receive(Duration::from_secs(1)).unwrap().is_empty());
    drop(b);
    let mut b = Marmot::open(&dir_b, &[]).unwrap();
    assert!(b.receive(Duration::from_secs(1)).unwrap().is_empty());
    drop(a);
    let mut a = Marmot::open(&dir_a, &[]).unwrap();
    assert!(a.receive(Duration::from_secs(1)).unwrap().is_empty());

    // Both sides still work after their restarts.
    a.send("last").unwrap();
    assert_eq!(receive_n(&mut b, 1), ["last"]);

    drop(a);
    drop(b);
    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);
}
