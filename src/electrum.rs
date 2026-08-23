//! An Electrum tweak-stream client, for a node you run yourself.
//!
//! [`blindbit`](crate::blindbit) reads the same facts over HTTP from a server
//! someone else operates. This reads them over the Electrum protocol from one
//! you operate — `rbitcoin --sptweaks` is what it was written against, and any
//! server answering Cake's `blockchain.tweaks.subscribe` will do.
//!
//! Only three methods are spoken, so this is not a general Electrum client:
//!
//! | Method | Why |
//! | --- | --- |
//! | `server.features` | its `genesis_hash`, to refuse the wrong chain |
//! | `blockchain.headers.subscribe` | the tip, which is the scan ceiling |
//! | `blockchain.tweaks.subscribe` | the tweaks themselves |
//!
//! The last one is not request/response. The JSON-RPC result carries only the
//! *first* height of the requested window; every height after it arrives as a
//! notification on the same socket, and `{"message":"done"}` ends the run. So
//! one call streams a whole range, which is the shape [`Electrum::tweaks`]
//! exposes — a callback per height rather than a returned list, because the
//! range can be the entire chain and none of it needs to be held at once.
//!
//! What arrives is also richer than BlindBit's. BlindBit publishes a bare list
//! of tweaks per block, so finding the transaction each one belongs to means
//! fetching the whole block from Esplora. Here every tweak comes with its txid
//! and the taproot outputs that transaction created, which is exactly what the
//! match needs — so scanning makes no block requests at all.
//!
//! Trusting those amounts would be a step backwards, though, and the caller
//! must not: an output's value ends up in the `witness_utxo` of the BIP-376
//! spend that moves it, and BIP-341 signs over it. A wrong one is a signature
//! over a lie. `sp-scan` checks a found output against Esplora before storing
//! it — one request per payment, not per block.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use bdk_wallet::bitcoin::secp256k1::{PublicKey, XOnlyPublicKey};
use bdk_wallet::bitcoin::{Amount, BlockHash};
use serde_json::{Value, json};

use crate::spscan::{Candidate, TaprootOut};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Generous, because a single wave can cover 128 heights and the server reads
/// them off disk before it writes anything. Too short turns a slow node into a
/// scan that stops halfway with no explanation.
const READ_TIMEOUT: Duration = Duration::from_secs(180);

/// A height dense with taproot outputs is still only a few hundred kilobytes,
/// so this is far above anything legitimate. It exists so that a wrong port —
/// an HTTP server, a TLS handshake, a log tail — fails instead of being read
/// into memory forever.
const MAX_LINE: u64 = 32 * 1024 * 1024;

pub struct Electrum {
    /// Kept for writing. `BufReader` owns its own clone of the socket.
    socket: TcpStream,
    reader: BufReader<TcpStream>,
    next_id: u64,
}

impl Electrum {
    /// Connect and set both timeouts.
    ///
    /// `address` is `host:port`; there is no default port, because the one a
    /// node listens on is an operator's choice and guessing 50001 would make a
    /// typo look like a refused connection.
    pub fn connect(address: &str) -> Result<Self> {
        let resolved = address
            .to_socket_addrs()
            .with_context(|| format!("{address:?} is not a host:port this machine can resolve"))?
            .next()
            .with_context(|| format!("{address:?} resolved to no addresses"))?;

        let socket = TcpStream::connect_timeout(&resolved, CONNECT_TIMEOUT)
            .with_context(|| format!("connecting to the tweak server at {address}"))?;
        socket.set_read_timeout(Some(READ_TIMEOUT))?;
        socket.set_nodelay(true)?;

        let reader = BufReader::new(socket.try_clone()?);
        Ok(Self {
            socket,
            reader,
            next_id: 0,
        })
    }

    /// The chain the server is on.
    ///
    /// Checked before scanning because heights mean different things on
    /// different chains, and a server answering confidently about the wrong one
    /// produces a scan that finds nothing and says so as though that settled it.
    pub fn genesis_hash(&mut self) -> Result<BlockHash> {
        let features = self.call("server.features", json!([]))?;
        let hex = features
            .get("genesis_hash")
            .and_then(Value::as_str)
            .context("the server's features carry no genesis_hash")?;
        BlockHash::from_str(hex).with_context(|| format!("genesis_hash {hex:?} is not a block hash"))
    }

    /// The highest block the server has.
    ///
    /// This subscribes, in the sense that the server may later push new
    /// headers down the socket. Nothing here reads them — [`Self::tweaks`]
    /// ignores any notification that is not its own — but it is why the scan
    /// ceiling is taken once, up front, rather than re-read mid-run.
    pub fn tip_height(&mut self) -> Result<u32> {
        let header = self.call("blockchain.headers.subscribe", json!([]))?;
        let height = header
            .get("height")
            .and_then(Value::as_u64)
            .context("the server's tip carries no height")?;
        u32::try_from(height).context("the server's tip height does not fit a block height")
    }

    /// Stream `start ..= start + count - 1`, clamped by the server to its tip.
    ///
    /// `on_height` is called once per height in order, including heights with
    /// nothing in them — that is what lets a caller advance a watermark as it
    /// goes, so an interrupted scan resumes where it stopped rather than at the
    /// beginning.
    ///
    /// Returns the number of heights delivered.
    pub fn tweaks(
        &mut self,
        start: u32,
        count: u32,
        mut on_height: impl FnMut(u32, Vec<Candidate>) -> Result<()>,
    ) -> Result<u32> {
        let id = self.send("blockchain.tweaks.subscribe", json!([start, count, false]))?;

        // The result is the first height; the rest are notifications. Both are
        // the same shape once unwrapped, so this loop does not care which it is
        // looking at until the sentinel arrives.
        let mut delivered = 0_u32;
        loop {
            let line = self.read_line()?;
            let message: Value = serde_json::from_str(&line)
                .with_context(|| format!("the server sent {}", snippet(&line)))?;

            if let Some(error) = message.get("error").filter(|e| !e.is_null()) {
                bail!("the tweak server refused the scan: {error}");
            }

            let map = if message.get("id").and_then(Value::as_u64) == Some(id) {
                message
                    .get("result")
                    .context("the server answered the scan with no result")?
            } else if message.get("method").and_then(Value::as_str)
                == Some("blockchain.tweaks.subscribe")
            {
                message
                    .get("params")
                    .and_then(|p| p.get(0))
                    .context("a tweak notification carried no height map")?
            } else {
                // A header notification, or anything else the server decides to
                // push. Not ours to interpret, and not a reason to stop.
                continue;
            };

            if map.get("message").is_some() {
                return Ok(delivered);
            }
            for (height, candidates) in parse_height_map(map)? {
                on_height(height, candidates)?;
                delivered += 1;
            }
        }
    }

    /// A plain request/response call.
    fn call(&mut self, method: &str, params: Value) -> Result<Value> {
        let id = self.send(method, params)?;
        loop {
            let line = self.read_line()?;
            let message: Value = serde_json::from_str(&line)
                .with_context(|| format!("the server sent {}", snippet(&line)))?;
            // Notifications can arrive before the answer does.
            if message.get("id").and_then(Value::as_u64) != Some(id) {
                continue;
            }
            if let Some(error) = message.get("error").filter(|e| !e.is_null()) {
                bail!("the server refused {method}: {error}");
            }
            return message
                .get("result")
                .cloned()
                .with_context(|| format!("the server's answer to {method} carried no result"));
        }
    }

    fn send(&mut self, method: &str, params: Value) -> Result<u64> {
        self.next_id += 1;
        let id = self.next_id;
        let request = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        writeln!(self.socket, "{request}").with_context(|| format!("sending {method}"))?;
        self.socket.flush()?;
        Ok(id)
    }

    fn read_line(&mut self) -> Result<String> {
        let mut buffer = Vec::new();
        let read = self
            .reader
            .by_ref()
            .take(MAX_LINE)
            .read_until(b'\n', &mut buffer)
            .context("reading from the tweak server")?;
        if read == 0 {
            bail!("the tweak server closed the connection mid-scan");
        }
        if read as u64 == MAX_LINE && !buffer.ends_with(b"\n") {
            bail!("the tweak server sent an oversized line; is this an Electrum port?");
        }
        String::from_utf8(buffer).context("the tweak server sent a line that is not UTF-8")
    }
}

/// Turn one `{"<height>": {...}}` object into candidates.
///
/// Split out with no socket in sight so the wire format can be tested against
/// the server's own fixtures.
pub fn parse_height_map(map: &Value) -> Result<Vec<(u32, Vec<Candidate>)>> {
    let object = map
        .as_object()
        .with_context(|| format!("a height map was {}", snippet(&map.to_string())))?;

    let mut heights = Vec::with_capacity(object.len());
    for (key, transactions) in object {
        let height: u32 = key
            .parse()
            .with_context(|| format!("{key:?} is not a block height"))?;
        let transactions = transactions
            .as_object()
            .with_context(|| format!("height {height} did not carry a transaction map"))?;

        let mut candidates = Vec::with_capacity(transactions.len());
        for (txid, entry) in transactions {
            candidates.push(
                parse_candidate(txid, entry)
                    .with_context(|| format!("reading {txid} at height {height}"))?,
            );
        }
        heights.push((height, candidates));
    }
    // A JSON object has no order to rely on, and the watermark this feeds does.
    heights.sort_by_key(|(height, _)| *height);
    Ok(heights)
}

fn parse_candidate(txid: &str, entry: &Value) -> Result<Candidate> {
    let tweak = entry
        .get("tweak")
        .and_then(Value::as_str)
        .context("no tweak")?;
    let tweak = PublicKey::from_slice(&decode_hex(tweak).context("the tweak is not hex")?)
        .context("the tweak is not a public key")?;

    let published = entry
        .get("output_pubkeys")
        .and_then(Value::as_object)
        .context("no output_pubkeys")?;

    let mut outputs = Vec::with_capacity(published.len());
    for (vout, pair) in published {
        let vout: u32 = vout
            .parse()
            .with_context(|| format!("{vout:?} is not an output index"))?;
        let pair = pair
            .as_array()
            .with_context(|| format!("output {vout} is not a [key, value] pair"))?;
        let key = pair
            .first()
            .and_then(Value::as_str)
            .with_context(|| format!("output {vout} carries no key"))?;
        let key = XOnlyPublicKey::from_slice(&decode_hex(key).context("the key is not hex")?)
            .with_context(|| format!("output {vout} is not an x-only key"))?;
        let sats = pair
            .get(1)
            .and_then(Value::as_u64)
            .with_context(|| format!("output {vout} carries no amount"))?;
        outputs.push(TaprootOut {
            vout,
            key,
            amount: Amount::from_sat(sats),
        });
    }
    // Same reason as the heights: bdk_sp walks a transaction's outputs in
    // index order and the derivation order it assigns depends on it.
    outputs.sort_by_key(|out| out.vout);

    Ok(Candidate {
        txid: txid.parse().context("not a txid")?,
        tweak,
        outputs,
    })
}

fn decode_hex(hex: &str) -> Result<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        bail!("odd number of hex digits");
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).context("invalid hex digit"))
        .collect()
}

/// Keep a wrong port from pasting a whole HTML page into the terminal.
fn snippet(body: &str) -> String {
    const MAX: usize = 120;
    let flat = body.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() > MAX {
        format!("{:?}…", flat.chars().take(MAX).collect::<String>())
    } else {
        format!("{flat:?}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-for-byte `crates/rbitcoin-electrum/tests/fixtures/
    /// tweaks_cake_850000_sample.json` from rbitcoin v0.5.1 — the server's own
    /// golden output, so this test fails if either side moves.
    const SAMPLE: &str = r#"{
      "850000": {
        "0185a62484ca086b1a620552c770f852fb2303ff26f85849beb66f767da4e078": {
          "output_pubkeys": {
            "1": [
              "5f94ca3effa19817039eda99ebce0be1a2a338dad1eb87961ef036a025e8dd7f",
              5410
            ]
          },
          "tweak": "02d092672ad97a476b27c7e58ff229d94dc2f644517913d316f0cd873132d57b26"
        }
      }
    }"#;

    fn parse(json: &str) -> Vec<(u32, Vec<Candidate>)> {
        parse_height_map(&serde_json::from_str(json).unwrap()).unwrap()
    }

    #[test]
    fn reads_the_servers_own_sample_block() {
        let heights = parse(SAMPLE);
        assert_eq!(heights.len(), 1);
        let (height, candidates) = &heights[0];
        assert_eq!(*height, 850_000);
        assert_eq!(candidates.len(), 1);

        let candidate = &candidates[0];
        assert_eq!(
            candidate.txid.to_string(),
            "0185a62484ca086b1a620552c770f852fb2303ff26f85849beb66f767da4e078"
        );
        assert_eq!(
            candidate.tweak.serialize()[..2],
            [0x02, 0xd0],
            "the tweak must survive as a compressed key"
        );
        assert_eq!(candidate.outputs.len(), 1);
        assert_eq!(candidate.outputs[0].vout, 1);
        assert_eq!(candidate.outputs[0].amount, Amount::from_sat(5410));
    }

    /// `getTweaks`' probe is `[0, 1, false]` and the answer is `{"0": {}}`.
    #[test]
    fn the_probe_answer_is_an_empty_height_not_an_error() {
        let heights = parse(r#"{"0": {}}"#);
        assert_eq!(heights.len(), 1);
        assert_eq!(heights[0].0, 0);
        assert!(heights[0].1.is_empty());
    }

    #[test]
    fn heights_come_back_in_order_whatever_the_object_says() {
        let heights = parse(r#"{"12": {}, "10": {}, "11": {}}"#);
        assert_eq!(
            heights.iter().map(|(h, _)| *h).collect::<Vec<_>>(),
            [10, 11, 12],
            "a watermark advanced out of order would skip a block"
        );
    }

    #[test]
    fn outputs_come_back_in_index_order() {
        let json = r#"{"1": {"aa16a1c1d33f6e8e0ec20f61c4bf5ff7e6d68e7f6e2f1e1e1e1e1e1e1e1e1e1e": {
            "tweak": "02d092672ad97a476b27c7e58ff229d94dc2f644517913d316f0cd873132d57b26",
            "output_pubkeys": {
              "7": ["5f94ca3effa19817039eda99ebce0be1a2a338dad1eb87961ef036a025e8dd7f", 3],
              "2": ["5f94ca3effa19817039eda99ebce0be1a2a338dad1eb87961ef036a025e8dd7f", 1]
            }}}}"#;
        let outputs = &parse(json)[0].1[0].outputs;
        assert_eq!(
            outputs.iter().map(|o| o.vout).collect::<Vec<_>>(),
            [2, 7],
            "derivation order follows output order, so this cannot be arbitrary"
        );
    }

    #[test]
    fn a_tweak_that_is_not_a_key_is_refused() {
        let json = r#"{"1": {"aa16a1c1d33f6e8e0ec20f61c4bf5ff7e6d68e7f6e2f1e1e1e1e1e1e1e1e1e1e": {
            "tweak": "0000000000000000000000000000000000000000000000000000000000000000ff",
            "output_pubkeys": {}}}}"#;
        assert!(parse_height_map(&serde_json::from_str(json).unwrap()).is_err());
    }

    #[test]
    fn a_web_page_in_place_of_a_height_map_gives_a_readable_error() {
        let error = parse_height_map(&json!("<!DOCTYPE html>".to_string() + &"x".repeat(5000)))
            .unwrap_err()
            .to_string();
        assert!(
            error.chars().count() < 200,
            "a whole page must not reach the terminal: {error}"
        );
        assert!(error.contains("DOCTYPE"), "but it should still be shown");
    }
}
