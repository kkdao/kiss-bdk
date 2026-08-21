//! A BlindBit tweak oracle client.
//!
//! Finding a silent payment means testing every block against the scan key, and
//! the test needs one public key per candidate transaction — the sum of its
//! input keys times the input hash. Deriving that requires every input's
//! previous output, which an Esplora backend will only serve one request at a
//! time. A BlindBit server has a full node behind it and publishes the tweaks
//! per block instead, which is what makes scanning practical here.
//!
//! The server learns which heights are being scanned, but never which outputs
//! matched: the matching happens locally against keys it does not have.
//!
//! `bdk-sp` ships a client for this in its `oracles` crate. That one is
//! unpublished and built on tokio, `reqwest` and `redb`, so this reimplements
//! the three endpoints against `minreq`, which the faucet already uses.

use anyhow::{Context, Result, bail};
use bdk_wallet::bitcoin::secp256k1::PublicKey;
use serde::Deserialize;

const TIMEOUT_SECS: u64 = 30;

/// BIP-352 lets a wallet ignore dust; the value matches what `bdk-sp` asks for.
const DUST_LIMIT_SATS: u64 = 1000;

pub struct BlindbitClient {
    base: String,
}

/// What the server says about itself, used to catch a wrong-network URL before
/// a scan quietly finds nothing.
#[derive(Debug, Deserialize)]
pub struct Info {
    pub network: String,
    pub height: u32,
}

#[derive(Deserialize)]
struct BlockHeight {
    // The deployed server spells this `block_height`; the type in bdk-sp's own
    // client calls it `height`. Accept either rather than depend on which
    // build is answering.
    #[serde(alias = "height")]
    block_height: u32,
}

impl BlindbitClient {
    pub fn new(base: &str) -> Self {
        Self {
            base: base.trim_end_matches('/').to_string(),
        }
    }

    /// The highest block the server has indexed.
    ///
    /// This is the scan ceiling, not the chain tip: the server may lag, and
    /// scanning past what it has indexed would silently skip payments.
    pub fn block_height(&self) -> Result<u32> {
        let body = self.get("block-height")?;
        let parsed: BlockHeight = serde_json::from_str(&body)
            .with_context(|| format!("BlindBit block height was {}", snippet(&body)))?;
        Ok(parsed.block_height)
    }

    pub fn info(&self) -> Result<Info> {
        let body = self.get("info")?;
        serde_json::from_str(&body)
            .with_context(|| format!("BlindBit server info was {}", snippet(&body)))
    }

    /// The candidate tweaks for one block.
    pub fn tweaks(&self, height: u32) -> Result<Vec<PublicKey>> {
        let body = self.get(&format!("tweaks/{height}?dustLimit={DUST_LIMIT_SATS}"))?;
        parse_tweaks(&body)
    }

    fn get(&self, path: &str) -> Result<String> {
        let url = format!("{}/{path}", self.base);
        let response = minreq::get(&url)
            .with_timeout(TIMEOUT_SECS)
            .send()
            .with_context(|| format!("contacting the BlindBit server at {url}"))?;
        let status = response.status_code;
        let text = response
            .as_str()
            .unwrap_or("<non-UTF-8 response>")
            .trim()
            .to_string();
        if !(200..300).contains(&status) {
            bail!("BlindBit server returned HTTP {status}: {}", snippet(&text));
        }
        Ok(text)
    }
}

/// Keep an error readable when a URL that is not a tweak oracle answers with a
/// web page. Pasting a whole HTML document into the terminal buries the point,
/// which is that the URL is wrong.
fn snippet(body: &str) -> String {
    const MAX: usize = 120;
    let flat = body.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() > MAX {
        format!("{:?}…", flat.chars().take(MAX).collect::<String>())
    } else {
        format!("{flat:?}")
    }
}

/// Split out so the wire format can be tested without a server.
fn parse_tweaks(body: &str) -> Result<Vec<PublicKey>> {
    let hexes: Vec<String> = serde_json::from_str(body)
        .with_context(|| format!("BlindBit tweak list was {}", snippet(body)))?;
    hexes
        .iter()
        .map(|hex| {
            let bytes = decode_hex(hex).with_context(|| format!("tweak {hex:?} is not hex"))?;
            PublicKey::from_slice(&bytes).with_context(|| format!("tweak {hex:?} is not a key"))
        })
        .collect()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_block_height_the_deployed_server_sends() {
        let parsed: BlockHeight = serde_json::from_str(r#"{"block_height":318744}"#).unwrap();
        assert_eq!(parsed.block_height, 318744);
    }

    #[test]
    fn also_reads_the_spelling_bdk_sps_own_client_uses() {
        let parsed: BlockHeight = serde_json::from_str(r#"{"height":318744}"#).unwrap();
        assert_eq!(parsed.block_height, 318744);
    }

    #[test]
    fn parses_a_tweak_list() {
        let body = r#"["02f781db64f5d97b844ba815b4638bfffd9aa25ea5019ab81ffa6d830efb8cf383","029fef17a5a3b826a516997ce7c1e27d6b8bdfad81910128ab2ca4e0a72675e709"]"#;
        let tweaks = parse_tweaks(body).unwrap();
        assert_eq!(tweaks.len(), 2);
        assert_eq!(
            tweaks[0].serialize()[..2],
            [0x02, 0xf7],
            "tweaks must survive as compressed keys"
        );
    }

    #[test]
    fn an_empty_block_is_not_an_error() {
        assert!(parse_tweaks("[]").unwrap().is_empty());
    }

    #[test]
    fn rejects_a_tweak_that_is_not_a_key() {
        let body = r#"["0000000000000000000000000000000000000000000000000000000000000000ff"]"#;
        assert!(parse_tweaks(body).is_err());
    }

    #[test]
    fn reads_the_info_a_wrong_network_check_needs() {
        let info: Info = serde_json::from_str(
            r#"{"network":"signet","height":318737,"tweaks_only":false,"tweaks_full_with_dust_filter":true}"#,
        )
        .unwrap();
        assert_eq!(info.network, "signet");
        assert_eq!(info.height, 318737);
    }

    #[test]
    fn a_web_page_in_place_of_json_gives_a_readable_error() {
        let html = format!("<!DOCTYPE html><html>{}</html>", "x".repeat(5000));
        let error = parse_tweaks(&html).unwrap_err().to_string();
        assert!(
            error.chars().count() < 200,
            "a whole page must not reach the terminal: {error}"
        );
        assert!(error.contains("DOCTYPE"), "but it should still be shown");
    }

    #[test]
    fn trims_a_trailing_slash_so_paths_do_not_double_up() {
        let client = BlindbitClient::new("https://example.invalid/blindbit/signet/");
        assert_eq!(client.base, "https://example.invalid/blindbit/signet");
    }
}
