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
//! over a lie. So a found output is proven before it is stored, and proven
//! without telling the public backend which transaction was found:
//!
//! * at every height, matched or not, the server's block header must hash to
//!   the block hash the public backend gives for that height
//!   (`blockchain.block.header`);
//! * for a match, the transaction and its merkle branch come from the same
//!   server (`blockchain.transaction.get`, `.get_merkle`), and the amount and
//!   script are read from the transaction bytes the branch ties to that header.
//!
//! The public backend sees one block hash lookup per height and nothing else,
//! and a hash that disagrees with the header stops the scan at that height
//! whether or not anything there was ours. See [`verify_inclusion`].
//!
//! The tweak server does learn which transactions matched, because it is
//! asked to prove them. That is why this client is for a node you run
//! yourself: a third party running it learns every payment the wallet finds.
//! And a proof is only as good as the two sources agreeing; a tweak server and
//! a public backend that lie together can still invent a payment, which no
//! check here can tell from a real one without validating the chain itself.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use bdk_sp::receive::scan::Scanner;
use bdk_wallet::bitcoin::block::Header;
use bdk_wallet::bitcoin::consensus::deserialize;
use bdk_wallet::bitcoin::hashes::{Hash, sha256d};
use bdk_wallet::bitcoin::secp256k1::{PublicKey, XOnlyPublicKey};
use bdk_wallet::bitcoin::{Amount, BlockHash, OutPoint, Transaction, TxMerkleNode, Txid};
use serde_json::{Value, json};

use crate::spreceive::ScanKeys;
use crate::spscan::{Candidate, Found, TaprootOut, scan_candidate};

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
        BlockHash::from_str(hex)
            .with_context(|| format!("genesis_hash {hex:?} is not a block hash"))
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

impl Electrum {
    /// Agree a protocol version, as the protocol asks a client to do first.
    ///
    /// 1.7 is where `blockchain.outpoint.get_status` is defined; a server that
    /// tops out lower (rbitcoin is 1.4 to 1.6) can still answer it as an
    /// extension, so the range is offered rather than 1.7 demanded.
    pub fn negotiate(&mut self) -> Result<String> {
        let reply = self.call("server.version", json!(["kiss-bdk", ["1.4", "1.7"]]))?;
        let version = parse_version_reply(&reply).with_context(|| {
            format!("the server's version reply {reply} is not a protocol between 1.4 and 1.7")
        })?;
        Ok(version.to_owned())
    }

    /// Whether a stored output is spent, asked of the owner's own node.
    ///
    /// `Ok(None)` only when the node says, in one of the two wordings servers
    /// use for exactly this, that the transaction does not exist, or when the
    /// output is past the end of the transaction it sent. Any other failure is
    /// an error. Even `Ok(None)` is one node's word: callers report it and
    /// keep the coin, never forget it.
    ///
    /// Two calls, because `blockchain.outpoint.get_status` answers an
    /// outpoint of a transaction it never saw the same as an unspent one on
    /// some servers (rbitcoin among them), and only fetching the transaction
    /// tells those apart. `script` is passed as the 1.7 `spk_hint`.
    pub fn output_status(
        &mut self,
        outpoint: &OutPoint,
        script: &bdk_wallet::bitcoin::ScriptBuf,
    ) -> Result<Option<bool>> {
        let txid = outpoint.txid.to_string();
        let tx = match self.call("blockchain.transaction.get", json!([txid, false])) {
            Ok(tx) => tx,
            Err(error) if says_not_found(&format!("{error:#}")) => return Ok(None),
            Err(error) => return Err(error),
        };
        let raw = tx
            .as_str()
            .context("the server sent a transaction that is not a hex string")?;
        let tx: Transaction = deserialize(&decode_hex(raw)?)
            .with_context(|| format!("the server's copy of {txid} does not parse"))?;
        if tx.compute_txid() != outpoint.txid {
            bail!("the server sent another transaction when asked for {txid}");
        }
        if outpoint.vout as usize >= tx.output.len() {
            return Ok(None);
        }
        let status = self.call(
            "blockchain.outpoint.get_status",
            json!([txid, outpoint.vout, script.to_hex_string()]),
        )?;
        parse_outpoint_status(&status)
            .with_context(|| format!("the server's status for {outpoint} says neither way"))
            .map(Some)
    }
}

/// Whether a server's refusal says the transaction is not known to it.
///
/// Only the two wordings servers use for exactly this: rbitcoin's "tx not
/// found" and the "No such mempool or blockchain transaction" Fulcrum and
/// electrs pass on from bitcoind. Anything looser also catches "Method not
/// found" and "No such table", which say nothing about the transaction.
fn says_not_found(error: &str) -> bool {
    let error = error.to_ascii_lowercase();
    error.contains("tx not found") || error.contains("no such mempool or blockchain transaction")
}

/// `blockchain.outpoint.get_status` in either form a server gives it, or
/// `None` for anything malformed or self-contradicting.
///
/// * rbitcoin: `{"spent": bool}`, with `height` and `spending_txid` only
///   when spent.
/// * protocol 1.7: `{"funder_height": h}` while unspent, with
///   `spender_txhash` (and `spender_height`) once spent.
///
/// A reply that says unspent while naming a spender, a height that is not a
/// number, or one that matches neither form is refused rather than read as
/// unspent: unspent is the answer that puts a coin into a transaction.
pub fn parse_outpoint_status(status: &Value) -> Option<bool> {
    let object = status.as_object()?;
    // A field is either absent or of its type; null is neither, and the
    // protocol omits a field rather than nulling it.
    let txid_field = |key: &str| match object.get(key) {
        None => Some(false),
        Some(Value::String(hex)) if hex.len() == 64 && Txid::from_str(hex).is_ok() => Some(true),
        Some(_) => None,
    };
    let number_field = |key: &str| match object.get(key) {
        None => Some(false),
        Some(value) if value.is_i64() || value.is_u64() => Some(true),
        Some(_) => None,
    };
    let spending_txid = txid_field("spending_txid")?;
    let spender_txhash = txid_field("spender_txhash")?;
    let spender_height = number_field("spender_height")?;
    number_field("height")?;

    if let Some(spent) = object.get("spent") {
        let spent = spent.as_bool()?;
        // Any word of a spender beside "unspent" is a contradiction.
        if !spent && (spending_txid || spender_txhash || spender_height) {
            return None;
        }
        return Some(spent);
    }
    // 1.7: a funding height is what says the outpoint is known at all, and
    // the spender's txid and height come together or not at all.
    if !number_field("funder_height")? || spending_txid || spender_txhash != spender_height {
        return None;
    }
    Some(spender_txhash)
}

/// The protocol a `server.version` reply agreed, if it is one this client
/// offered: `[server name, "1.x"]` or `"1.x.y"`, with 1.x from 1.4 to 1.7.
pub fn parse_version_reply(reply: &Value) -> Option<&str> {
    let [name, version] = reply.as_array()?.as_slice() else {
        return None;
    };
    name.as_str()?;
    let version = version.as_str()?;
    let parts: Vec<u32> = version
        .split('.')
        .map(|part| {
            (!part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
                .then(|| part.parse().ok())
                .flatten()
        })
        .collect::<Option<_>>()?;
    let in_range =
        matches!(parts.as_slice(), [1, minor] | [1, minor, _] if (4..=7).contains(minor));
    in_range.then_some(version)
}

/// What a server offers as proof that a transaction is in a block.
///
/// None of it is taken on trust; [`verify_inclusion`] checks every part.
#[derive(Debug, Clone)]
pub struct Inclusion {
    pub tx: Transaction,
    /// The transaction's position in its block.
    pub pos: u32,
    /// Sibling hashes from the transaction up to the merkle root.
    pub branch: Vec<TxMerkleNode>,
    /// The header of the block the server says holds it.
    pub header: Header,
}

/// A transaction, its position in its block and its merkle branch.
pub type Placement = (Transaction, u32, Vec<TxMerkleNode>);

/// Where proofs come from. [`Electrum`] is the real one: the server the tweaks
/// came from, which learns which transactions matched when asked to prove
/// them, so it must be one the wallet's owner runs.
pub trait InclusionSource {
    /// The block header the server has at `height`. Asked at every height.
    fn header(&mut self, height: u32) -> Result<Header>;
    /// `txid` with its position and merkle branch. Asked only for a match.
    fn placement(&mut self, txid: &Txid, height: u32) -> Result<Placement>;
}

impl InclusionSource for Electrum {
    fn header(&mut self, height: u32) -> Result<Header> {
        let header = self.call("blockchain.block.header", json!([height]))?;
        let header = header
            .as_str()
            .context("the server sent a header that is not a hex string")?;
        deserialize(&decode_hex(header)?)
            .with_context(|| format!("the server's header for block {height} does not parse"))
    }

    fn placement(&mut self, txid: &Txid, height: u32) -> Result<Placement> {
        let raw = self.call(
            "blockchain.transaction.get",
            json!([txid.to_string(), false]),
        )?;
        let raw = raw
            .as_str()
            .context("the server sent a transaction that is not a hex string")?;
        let tx: Transaction = deserialize(&decode_hex(raw)?)
            .with_context(|| format!("the server's copy of {txid} does not parse"))?;

        let merkle = self.call(
            "blockchain.transaction.get_merkle",
            json!([txid.to_string(), height]),
        )?;
        let pos = merkle
            .get("pos")
            .and_then(Value::as_u64)
            .context("the server's merkle proof carries no position")?;
        let pos = u32::try_from(pos).context("the server's merkle position is out of range")?;
        let branch = merkle
            .get("merkle")
            .and_then(Value::as_array)
            .context("the server's merkle proof carries no branch")?
            .iter()
            .map(|node| {
                node.as_str()
                    .context("a merkle branch entry is not a string")?
                    .parse::<TxMerkleNode>()
                    .context("a merkle branch entry is not a hash")
            })
            .collect::<Result<Vec<_>>>()?;
        Ok((tx, pos, branch))
    }
}

/// Check a found output against a proof of inclusion, trusting none of it.
///
/// `block_hash` is what the public backend says is at `found.height`. The
/// rest comes from the tweak server, so each part is tied to the next:
///
/// 1. the header hashes to `block_hash`, so it is the block the chain has
///    at that height and not one the server made up;
/// 2. the transaction hashes to the found output's txid;
/// 3. the branch, walked from that txid by `pos`, reaches the header's merkle
///    root, so the transaction is in that block;
/// 4. the output at the found index has the found script and amount.
///
/// A transaction of exactly 64 bytes without witnesses is refused: it can pose
/// as an inner node of the merkle tree and so "prove" a transaction that is
/// not in the block (the attack Bitcoin Core closes the same way).
pub fn verify_inclusion(found: &Found, proof: &Inclusion, block_hash: &BlockHash) -> Result<()> {
    let outpoint = found.out.outpoint;
    let height = found.height;
    if proof.header.block_hash() != *block_hash {
        bail!(
            "the tweak server's header for block {height} is not the block the chain has \
             at that height"
        );
    }
    let txid = proof.tx.compute_txid();
    if txid != outpoint.txid {
        bail!(
            "the tweak server sent {txid} when asked for {}",
            outpoint.txid
        );
    }
    if proof.tx.base_size() == 64 {
        bail!("{txid} is 64 bytes without witnesses, which a merkle proof cannot vouch for");
    }
    // A block of 2^31 transactions would weigh far more than any block can,
    // so a longer branch is a lie, and refusing it here keeps every shift
    // below inside a u32.
    if proof.branch.len() > 31 {
        bail!("the merkle branch for {txid} is deeper than any block");
    }
    if u64::from(proof.pos) >> proof.branch.len() != 0 {
        bail!("the merkle position for {txid} does not fit its branch");
    }

    let mut node = txid.to_byte_array();
    for (level, sibling) in proof.branch.iter().enumerate() {
        let mut pair = [0_u8; 64];
        if (proof.pos >> level) & 1 == 1 {
            pair[..32].copy_from_slice(&sibling.to_byte_array());
            pair[32..].copy_from_slice(&node);
        } else {
            pair[..32].copy_from_slice(&node);
            pair[32..].copy_from_slice(&sibling.to_byte_array());
        }
        node = sha256d::Hash::hash(&pair).to_byte_array();
    }
    if node != proof.header.merkle_root.to_byte_array() {
        bail!("the merkle proof does not place {txid} in block {height}");
    }

    let txout = proof
        .tx
        .output
        .get(outpoint.vout as usize)
        .with_context(|| format!("{outpoint} is past the end of its transaction"))?;
    if txout.script_pubkey != found.out.script_pubkey {
        bail!("{outpoint} does not pay the script the tweak server published");
    }
    if txout.value != found.out.amount {
        bail!(
            "{outpoint} holds {} on chain, not the {} the tweak server published",
            txout.value,
            found.out.amount
        );
    }
    Ok(())
}

/// One height of an Electrum scan: match its candidates and prove every match.
///
/// `block_hash` reaches the public backend. It is asked once per height, first,
/// with nothing but the height, and the tweak server's header for that height
/// must match it before any candidate is looked at. Both happen whether or not
/// anything here turns out to be ours, so a backend that lies about a hash
/// sees the scan stop at the same height either way and learns nothing from
/// where it stopped. Everything specific to a match goes to `proofs`, the
/// server the candidates came from. Returns the hash, for the watermark, and
/// the proven outputs. A match whose proof fails fails the height rather than
/// being dropped, so a bad proof for a candidate the server did send stops
/// the scan. A server that leaves a matching candidate out entirely hides that
/// payment, and nothing here can tell; that is the trust a tweak server holds.
pub fn scan_height(
    keys: &ScanKeys,
    scanner: &Scanner,
    height: u32,
    candidates: &[Candidate],
    block_hash: impl FnOnce(u32) -> Result<BlockHash>,
    proofs: &mut impl InclusionSource,
) -> Result<(BlockHash, Vec<Found>)> {
    let hash = block_hash(height).with_context(|| format!("looking up block {height}"))?;
    let header = proofs
        .header(height)
        .with_context(|| format!("asking the tweak server for block {height}'s header"))?;
    if header.block_hash() != hash {
        bail!(
            "the tweak server and the block backend disagree about block {height}; \
             one of them is on another chain or lying"
        );
    }
    let mut proven = Vec::new();
    for candidate in candidates {
        let found = scan_candidate(keys, scanner, candidate, height)?;
        if found.is_empty() {
            continue;
        }
        let (tx, pos, branch) = proofs
            .placement(&candidate.txid, height)
            .with_context(|| format!("asking the tweak server to prove {}", candidate.txid))?;
        let proof = Inclusion {
            tx,
            pos,
            branch,
            header,
        };
        for item in &found {
            verify_inclusion(item, &proof, &hash)?;
        }
        proven.extend(found);
    }
    Ok((hash, proven))
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
    use crate::spscan::scanner;
    use bdk_wallet::bitcoin::block::Version;
    use bdk_wallet::bitcoin::secp256k1::{Secp256k1, SecretKey};
    use bdk_wallet::bitcoin::{CompactTarget, ScriptBuf, TxOut, absolute, transaction};

    fn keys() -> ScanKeys {
        let secp = Secp256k1::new();
        ScanKeys {
            scan: SecretKey::from_slice(&[0x11; 32]).unwrap(),
            spend: SecretKey::from_slice(&[0x22; 32])
                .unwrap()
                .public_key(&secp),
        }
    }

    fn tweak() -> PublicKey {
        SecretKey::from_slice(&[0x33; 32])
            .unwrap()
            .public_key(&Secp256k1::new())
    }

    fn tx(lock_time: u32, output: Vec<TxOut>) -> Transaction {
        Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::from_consensus(lock_time),
            input: Vec::new(),
            output,
        }
    }

    /// A transaction paying this wallet at vout 1, and the candidate the
    /// stream would publish for it.
    fn payment(amount: u64) -> (Transaction, Candidate) {
        let ours = scanner(&keys()).get_spks_from_tweak(&tweak(), 0).remove(0);
        let paying = tx(
            1,
            vec![
                TxOut {
                    value: Amount::from_sat(5_000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x00, 0x14, 0x77]),
                },
                TxOut {
                    value: Amount::from_sat(amount),
                    script_pubkey: ours,
                },
            ],
        );
        let candidate = candidate_for(&paying, amount);
        (paying, candidate)
    }

    fn candidate_for(paying: &Transaction, published_amount: u64) -> Candidate {
        Candidate {
            txid: paying.compute_txid(),
            tweak: tweak(),
            outputs: vec![TaprootOut {
                vout: 1,
                key: XOnlyPublicKey::from_slice(&paying.output[1].script_pubkey.as_bytes()[2..])
                    .unwrap(),
                amount: Amount::from_sat(published_amount),
            }],
        }
    }

    /// A block holding `txs`, its header, and the merkle branch for `pos`.
    fn block(txs: &[Transaction], pos: usize) -> (Header, Vec<TxMerkleNode>) {
        let mut level: Vec<[u8; 32]> = txs
            .iter()
            .map(|tx| tx.compute_txid().to_byte_array())
            .collect();
        let mut branch = Vec::new();
        let mut index = pos;
        while level.len() > 1 {
            if level.len() % 2 == 1 {
                level.push(*level.last().unwrap());
            }
            branch.push(TxMerkleNode::from_byte_array(level[index ^ 1]));
            level = level
                .chunks(2)
                .map(|pair| {
                    let mut both = [0_u8; 64];
                    both[..32].copy_from_slice(&pair[0]);
                    both[32..].copy_from_slice(&pair[1]);
                    sha256d::Hash::hash(&both).to_byte_array()
                })
                .collect();
            index /= 2;
        }
        let header = Header {
            version: Version::TWO,
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::from_byte_array(level[0]),
            time: 0,
            bits: CompactTarget::from_consensus(0),
            nonce: 0,
        };
        (header, branch)
    }

    /// The honest case: the paying transaction at position 1 of three.
    fn honest(amount: u64) -> (Found, Inclusion, BlockHash) {
        let (paying, candidate) = payment(amount);
        let txs = [tx(10, Vec::new()), paying.clone(), tx(11, Vec::new())];
        let (header, branch) = block(&txs, 1);
        let keys = keys();
        let found = scan_candidate(&keys, &scanner(&keys), &candidate, 7)
            .unwrap()
            .remove(0);
        let hash = header.block_hash();
        let proof = Inclusion {
            tx: paying,
            pos: 1,
            branch,
            header,
        };
        (found, proof, hash)
    }

    #[test]
    fn an_honest_proof_is_accepted() {
        let (found, proof, hash) = honest(21_000);
        verify_inclusion(&found, &proof, &hash).unwrap();
    }

    #[test]
    fn every_forged_part_of_a_proof_is_refused() {
        let (found, proof, hash) = honest(21_000);

        // The stream claimed more than the chain holds.
        let (_, inflated) = payment(21_000);
        let keys = keys();
        let mut lie = inflated.clone();
        lie.outputs[0].amount = Amount::from_sat(99_000);
        // A different amount changes no key, so the match still happens; the
        // proof is what has to catch it.
        let mut forged = Vec::new();
        let mut claimed = scan_candidate(&keys, &scanner(&keys), &lie, 7)
            .unwrap()
            .remove(0);
        claimed.out.outpoint = found.out.outpoint;
        forged.push(("amount", claimed, proof.clone(), hash));

        let mut wrong_script = Found {
            height: found.height,
            out: found.out.clone(),
        };
        wrong_script.out.script_pubkey = ScriptBuf::from_bytes(vec![0x51, 0x20, 0x01]);
        forged.push(("script", wrong_script, proof.clone(), hash));

        // A transaction that pays the claimed amount but is not the one found.
        let mut other_tx = proof.clone();
        other_tx.tx.output[1].value = Amount::from_sat(99_000);
        forged.push(("transaction", copy(&found), other_tx, hash));

        let mut bad_branch = proof.clone();
        bad_branch.branch[0] = TxMerkleNode::from_byte_array([0x42; 32]);
        forged.push(("branch", copy(&found), bad_branch, hash));

        let mut bad_pos = proof.clone();
        bad_pos.pos = 0;
        forged.push(("position", copy(&found), bad_pos, hash));

        let mut too_wide = proof.clone();
        too_wide.pos = 1 << proof.branch.len();
        forged.push(("position past the branch", copy(&found), too_wide, hash));

        // A header the server made up around the transaction it wants to sell:
        // its merkle root is right, but it is not the block the chain has.
        let (made_up, branch) = block(std::slice::from_ref(&proof.tx), 0);
        let invented = Inclusion {
            tx: proof.tx.clone(),
            pos: 0,
            branch,
            header: made_up,
        };
        forged.push(("header", copy(&found), invented, hash));

        // The right proof against a different block at that height.
        forged.push((
            "block hash",
            copy(&found),
            proof.clone(),
            BlockHash::from_byte_array([0x24; 32]),
        ));

        for (what, found, proof, hash) in forged {
            assert!(
                verify_inclusion(&found, &proof, &hash).is_err(),
                "a forged {what} was accepted"
            );
        }
    }

    fn copy(found: &Found) -> Found {
        Found {
            height: found.height,
            out: found.out.clone(),
        }
    }

    #[test]
    fn a_64_byte_transaction_is_refused_even_with_a_matching_proof() {
        let ours = scanner(&keys()).get_spks_from_tweak(&tweak(), 0).remove(0);
        // 4 version + 1 + 1 counts + (8 + 1 + 34) + (8 + 1 + 2) + 4 lock time
        let small = tx(
            0,
            vec![
                TxOut {
                    value: Amount::from_sat(1),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x6a, 0x00]),
                },
                TxOut {
                    value: Amount::from_sat(21_000),
                    script_pubkey: ours,
                },
            ],
        );
        assert_eq!(small.base_size(), 64);
        let candidate = candidate_for(&small, 21_000);
        let keys = keys();
        let found = scan_candidate(&keys, &scanner(&keys), &candidate, 7)
            .unwrap()
            .remove(0);
        let (header, branch) = block(&[tx(10, Vec::new()), small.clone()], 1);
        let hash = header.block_hash();
        let proof = Inclusion {
            tx: small,
            pos: 1,
            branch,
            header,
        };
        assert!(verify_inclusion(&found, &proof, &hash).is_err());
    }

    /// Stands in for the tweak server's proof calls and records them. Height
    /// 7 holds `proof`; every other height has a header of its own.
    struct Prover {
        proof: Inclusion,
        headers: Vec<u32>,
        asked: Vec<(Txid, u32)>,
    }

    fn other_header(height: u32) -> Header {
        let (mut header, _) = block(&[tx(height, Vec::new())], 0);
        header.nonce = height;
        header
    }

    impl InclusionSource for Prover {
        fn header(&mut self, height: u32) -> Result<Header> {
            self.headers.push(height);
            Ok(if height == 7 {
                self.proof.header
            } else {
                other_header(height)
            })
        }

        fn placement(&mut self, txid: &Txid, height: u32) -> Result<Placement> {
            self.asked.push((*txid, height));
            Ok((
                self.proof.tx.clone(),
                self.proof.pos,
                self.proof.branch.clone(),
            ))
        }
    }

    /// Scan heights 6 to 8 and return what each side was asked.
    fn scan(
        pay_at_7: bool,
        proof: Inclusion,
        hash_at_7: BlockHash,
    ) -> (Vec<u32>, Prover, Result<usize>) {
        let keys = keys();
        let scanner = scanner(&keys);
        let (_, candidate) = payment(21_000);
        // A candidate that is not ours, so a height with traffic but no match
        // looks the same as one with nothing.
        let stranger = Candidate {
            tweak: SecretKey::from_slice(&[0x44; 32])
                .unwrap()
                .public_key(&Secp256k1::new()),
            ..candidate.clone()
        };
        let mut public: Vec<u32> = Vec::new();
        let mut prover = Prover {
            proof,
            headers: Vec::new(),
            asked: Vec::new(),
        };
        let mut found = 0;
        for height in 6..=8 {
            let candidates = if height == 7 && pay_at_7 {
                vec![stranger.clone(), candidate.clone()]
            } else {
                vec![stranger.clone()]
            };
            let result = scan_height(
                &keys,
                &scanner,
                height,
                &candidates,
                |h| {
                    public.push(h);
                    Ok(if h == 7 {
                        hash_at_7
                    } else {
                        other_header(h).block_hash()
                    })
                },
                &mut prover,
            );
            match result {
                Ok((_, proven)) => found += proven.len(),
                Err(error) => return (public, prover, Err(error)),
            }
        }
        (public, prover, Ok(found))
    }

    #[test]
    fn the_public_backend_learns_the_same_thing_whether_or_not_we_were_paid() {
        let (_, proof, hash) = honest(21_000);

        let (paid, prover, found) = scan(true, proof.clone(), hash);
        assert_eq!(found.unwrap(), 1, "the payment must be found and proven");
        let (unpaid, idle, found) = scan(false, proof.clone(), hash);
        assert_eq!(found.unwrap(), 0);

        // One request per height, holding only the height, in the same order.
        assert_eq!(paid, [6, 7, 8]);
        assert_eq!(
            paid, unpaid,
            "a match must not change what Esplora is asked"
        );
        // What identifies the payment went to the tweak server only.
        assert_eq!(prover.asked, [(proof.tx.compute_txid(), 7)]);
        assert!(
            idle.asked.is_empty(),
            "no proof is asked for without a match"
        );
        // Every height's header is checked, matched or not.
        assert_eq!(prover.headers, [6, 7, 8]);
        assert_eq!(idle.headers, [6, 7, 8]);
    }

    #[test]
    fn a_lying_block_hash_stops_the_scan_at_the_same_height_either_way() {
        // The backend gives a wrong hash at 7. If only a match checked it, a
        // paid wallet would stop at 7 and an unpaid one would carry on to 8,
        // and the backend would learn which block paid it.
        let (_, proof, _) = honest(21_000);
        let wrong = BlockHash::from_byte_array([0x24; 32]);
        let (paid, _, found) = scan(true, proof.clone(), wrong);
        assert!(found.is_err());
        let (unpaid, _, found) = scan(false, proof, wrong);
        assert!(
            found.is_err(),
            "a wrong hash must stop a scan with no match too"
        );
        assert_eq!(paid, [6, 7]);
        assert_eq!(paid, unpaid);
    }

    #[test]
    fn a_branch_deeper_than_any_block_is_refused_not_a_panic() {
        let (found, mut proof, hash) = honest(21_000);
        proof.branch = vec![TxMerkleNode::from_byte_array([0x42; 32]); 33];
        assert!(verify_inclusion(&found, &proof, &hash).is_err());
        proof.branch.truncate(32);
        assert!(verify_inclusion(&found, &proof, &hash).is_err());
    }

    #[test]
    fn a_tweak_server_that_lies_about_the_amount_stops_the_scan() {
        // The stream says 21,000 sats; the proven transaction holds 20,000.
        let (_, mut proof, _) = honest(21_000);
        proof.tx.output[1].value = Amount::from_sat(20_000);
        let txs = [tx(10, Vec::new()), proof.tx.clone(), tx(11, Vec::new())];
        let (header, branch) = block(&txs, 1);
        proof.branch = branch;
        proof.header = header;
        let hash = proof.header.block_hash();
        let (public, _, found) = scan(true, proof, hash);
        assert!(
            found.is_err(),
            "an amount the chain does not hold was stored"
        );
        assert_eq!(public, [6, 7], "the scan stops at the height that lied");
    }

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
