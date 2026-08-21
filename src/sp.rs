//! BIP-352 silent payment addresses.
//!
//! Only the sending half lives here: decoding a recipient's `sp1`/`tsp1`
//! address into the two public keys BIP-375 carries in a PSBT. Receiving needs
//! whole-block tweak scanning, which the Esplora backend cannot serve.
//!
//! KISS's own encoder (`main/kiss_sp.c`) is the reference this must agree with:
//! bech32m, a version group that must be zero, and a 66-byte payload of two
//! compressed public keys.

use anyhow::{Context, Result, bail};
use bdk_wallet::bitcoin::bech32::Bech32m;
use bdk_wallet::bitcoin::bech32::primitives::decode::CheckedHrpstring;
use bdk_wallet::bitcoin::secp256k1::PublicKey;

/// Two compressed public keys: `scan || spend`.
const SP_PAYLOAD_BYTES: usize = 66;
const MAINNET_HRP: &str = "sp";
const TESTNET_HRP: &str = "tsp";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SilentPaymentAddress {
    pub scan: PublicKey,
    pub spend: PublicKey,
    pub mainnet: bool,
}

impl SilentPaymentAddress {
    /// The `PSBT_OUT_SP_V0_INFO` value BIP-375 puts on the output.
    pub fn sp_v0_info(&self) -> Vec<u8> {
        let mut value = Vec::with_capacity(SP_PAYLOAD_BYTES);
        value.extend_from_slice(&self.scan.serialize());
        value.extend_from_slice(&self.spend.serialize());
        value
    }
}

/// Cheap prefix test so `create` can route a destination before parsing it.
pub fn looks_like_silent_payment(destination: &str) -> bool {
    let lower = destination.trim().to_ascii_lowercase();
    lower.starts_with("sp1") || lower.starts_with("tsp1")
}

/// Decode a BIP-352 v0 address.
pub fn decode(address: &str) -> Result<SilentPaymentAddress> {
    let address = address.trim();
    // Strict bech32m: the permissive helper also accepts a plain bech32
    // checksum, which would let a mistyped address through.
    let checked = CheckedHrpstring::new::<Bech32m>(address)
        .context("silent payment address is not valid bech32m")?;

    let hrp = checked.hrp().to_lowercase();
    let mainnet = match hrp.as_str() {
        MAINNET_HRP => true,
        TESTNET_HRP => false,
        other => bail!("{other:?} is not a silent payment address prefix"),
    };

    let groups: Vec<u8> = checked
        .fe32_iter::<core::iter::Empty<u8>>()
        .map(u8::from)
        .collect();
    let (version, payload_groups) = groups
        .split_first()
        .context("silent payment address carries no data")?;
    if *version != 0 {
        bail!("unsupported silent payment address version {version}");
    }

    let payload = from_base32(payload_groups)?;
    if payload.len() != SP_PAYLOAD_BYTES {
        bail!(
            "silent payment address carries {} payload bytes, expected {SP_PAYLOAD_BYTES}",
            payload.len()
        );
    }

    let scan = PublicKey::from_slice(&payload[..33]).context("invalid silent payment scan key")?;
    let spend =
        PublicKey::from_slice(&payload[33..]).context("invalid silent payment spend key")?;
    Ok(SilentPaymentAddress {
        scan,
        spend,
        mainnet,
    })
}

/// Regroup 5-bit values into bytes, rejecting non-zero padding so two distinct
/// strings can never decode to the same keys.
fn from_base32(groups: &[u8]) -> Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(groups.len() * 5 / 8);
    let mut accumulator: u32 = 0;
    let mut bits: u32 = 0;
    for &group in groups {
        accumulator = (accumulator << 5) | u32::from(group);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            bytes.push((accumulator >> bits) as u8);
        }
    }
    if bits >= 5 {
        bail!("silent payment address has an incomplete final group");
    }
    if accumulator & ((1 << bits) - 1) != 0 {
        bail!("silent payment address has non-zero padding bits");
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    // BIP-352 test vector recipient (bitcoin/bips, bip-0352 test vectors).
    const MAINNET: &str = "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv";

    #[test]
    fn decodes_a_bip352_mainnet_address() {
        let sp = decode(MAINNET).unwrap();
        assert!(sp.mainnet);
        assert_eq!(sp.sp_v0_info().len(), SP_PAYLOAD_BYTES);
        assert_eq!(&sp.sp_v0_info()[..33], &sp.scan.serialize()[..]);
    }

    #[test]
    fn rejects_corrupted_and_foreign_addresses() {
        // Flipping one payload character breaks the bech32m checksum.
        let mut bad: Vec<char> = MAINNET.chars().collect();
        bad[10] = if bad[10] == 'q' { 'p' } else { 'q' };
        assert!(decode(&bad.into_iter().collect::<String>()).is_err());

        assert!(decode("tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl").is_err());
        assert!(decode("").is_err());
    }

    #[test]
    fn recognizes_silent_payment_prefixes() {
        assert!(looks_like_silent_payment(MAINNET));
        assert!(looks_like_silent_payment("tsp1qq..."));
        assert!(looks_like_silent_payment("  SP1QQ...  "));
        assert!(!looks_like_silent_payment(
            "tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl"
        ));
        assert!(!looks_like_silent_payment("spam"));
    }
}
