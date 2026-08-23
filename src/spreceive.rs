//! Importing the receive-side keys KISS exports.
//!
//! BIP-352 splits a recipient into two keys on purpose: the *scan* key finds
//! payments and the *spend* key moves them. Only the scan key has to be online,
//! so KISS exports that one and keeps the spend key. The export carries a
//! private key, which is why the coordinator refuses a mainnet one outright —
//! every chain this CLI speaks is a test network.
//!
//! `main/kiss_sp.c` (`sp_scan_encode`) is the reference: bech32m, a version
//! group that must be zero, and a 65-byte payload of `scan_priv || spend_pub`,
//! wrapped as `sp([fingerprint/352h/coinh/0h]tspscan1…)` by
//! `kiss_session_sp_scan_export`.

use anyhow::{Context, Result, bail};
use bdk_sp::encoding::SilentPaymentCode;
use bdk_wallet::bitcoin::Network;
use bdk_wallet::bitcoin::bech32::Bech32m;
use bdk_wallet::bitcoin::bech32::primitives::decode::CheckedHrpstring;
use bdk_wallet::bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};

/// A 32-byte scan private key followed by a 33-byte compressed spend key.
const SCAN_PAYLOAD_BYTES: usize = 65;
const MAINNET_HRP: &str = "spscan";
const TESTNET_HRP: &str = "tspscan";

/// The key pair a watch-only scanner needs: the scan key to find payments, the
/// spend key only to recognise them. The spend *private* key never leaves KISS.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScanKeys {
    pub scan: SecretKey,
    pub spend: PublicKey,
}

impl ScanKeys {
    /// The `tsp1…` code that receives payments to this wallet.
    ///
    /// Built rather than parsed on purpose: `bdk_sp`'s own decoder maps the
    /// `tsp` prefix to `Network::Testnet` and never to `Signet`, so a code that
    /// went out through a round trip would come back on the wrong network.
    pub fn code(&self, network: Network) -> SilentPaymentCode {
        let secp = Secp256k1::new();
        SilentPaymentCode::new_v0(self.scan.public_key(&secp), self.spend, network)
    }
}

/// Parse KISS's scan-key export.
///
/// Accepts either the whole `sp([…]tspscan1…)` descriptor KISS shows or the
/// bare `tspscan1…` key inside it, since one is what the QR carries and the
/// other is what a person retypes.
pub fn parse_scan_export(export: &str) -> Result<ScanKeys> {
    let key = strip_descriptor(export.trim())?;

    // Strict bech32m: the permissive helper also accepts a plain bech32
    // checksum, which would let a mistyped key through.
    let checked =
        CheckedHrpstring::new::<Bech32m>(key).context("scan key export is not valid bech32m")?;

    let hrp = checked.hrp().to_lowercase();
    match hrp.as_str() {
        TESTNET_HRP => {}
        MAINNET_HRP => {
            bail!("that is a mainnet scan key; this coordinator only speaks test networks")
        }
        other => bail!("{other:?} is not a scan key export prefix"),
    }

    let groups: Vec<u8> = checked
        .fe32_iter::<core::iter::Empty<u8>>()
        .map(u8::from)
        .collect();
    let (version, payload_groups) = groups
        .split_first()
        .context("scan key export carries no data")?;
    if *version != 0 {
        bail!("unsupported scan key export version {version}");
    }

    let payload = crate::sp::from_base32(payload_groups).context("decoding the scan key export")?;
    if payload.len() != SCAN_PAYLOAD_BYTES {
        bail!(
            "scan key export carries {} payload bytes, expected {SCAN_PAYLOAD_BYTES}",
            payload.len()
        );
    }

    let scan = SecretKey::from_slice(&payload[..32]).context("invalid scan private key")?;
    let spend = PublicKey::from_slice(&payload[32..]).context("invalid spend public key")?;
    Ok(ScanKeys { scan, spend })
}

/// The two keys as any device can state them: scan private, spend public.
///
/// BIP-352 does not standardise how a signing device hands its scan key over,
/// and [`parse_scan_export`] reads the one format KISS emits. Anything else has
/// the two keys and no agreed envelope for them, so this takes them raw: 32
/// bytes of scan private key and a 33-byte compressed spend public key, hex,
/// separated by a colon.
///
/// The lengths are what tells the two apart, so a swapped pair is refused
/// rather than silently paired to a wallet that can never see a payment.
pub fn parse_scan_hex(pair: &str) -> Result<ScanKeys> {
    let (scan, spend) = pair
        .trim()
        .split_once(':')
        .context("expected SCAN_PRIVATE_HEX:SPEND_PUBLIC_HEX, 64 hex digits then 66")?;

    let scan = decode_hex(scan.trim()).context("the scan private key is not hex")?;
    let spend = decode_hex(spend.trim()).context("the spend public key is not hex")?;

    if scan.len() != 32 {
        bail!(
            "the scan private key is {} bytes, expected 32; are the two the wrong way round?",
            scan.len()
        );
    }
    if spend.len() != 33 {
        bail!(
            "the spend public key is {} bytes, expected a 33-byte compressed key",
            spend.len()
        );
    }

    Ok(ScanKeys {
        scan: SecretKey::from_slice(&scan).context("the scan private key is not a key")?,
        spend: PublicKey::from_slice(&spend).context("the spend public key is not a key")?,
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

/// Unwrap `sp([origin]key)` down to the key, leaving a bare key alone.
fn strip_descriptor(export: &str) -> Result<&str> {
    let Some(rest) = export
        .strip_prefix("sp(")
        .or_else(|| export.strip_prefix("SP("))
    else {
        return Ok(export);
    };
    let inner = rest
        .strip_suffix(')')
        .context("scan key descriptor is missing its closing parenthesis")?;

    // The key origin is informational here; the fingerprint belongs to KISS's
    // master key, which this coordinator has no copy of to check it against.
    let Some(after) = inner.strip_prefix('[') else {
        return Ok(inner);
    };
    let (_origin, key) = after
        .split_once(']')
        .context("scan key descriptor has an unterminated key origin")?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Re-implements `sp_scan_encode` so the tests exercise the same shape KISS
    /// produces without needing the device in the loop.
    fn encode(hrp: &str, payload: &[u8], version: u8) -> String {
        const CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
        fn polymod(values: &[u8]) -> u32 {
            const GEN: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
            let mut chk: u32 = 1;
            for v in values {
                let b = chk >> 25;
                chk = ((chk & 0x1ffffff) << 5) ^ u32::from(*v);
                for (i, g) in GEN.iter().enumerate() {
                    if (b >> i) & 1 == 1 {
                        chk ^= g;
                    }
                }
            }
            chk
        }
        let mut data = vec![version];
        let (mut acc, mut bits) = (0u32, 0u32);
        for &b in payload {
            acc = (acc << 8) | u32::from(b);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                data.push(((acc >> bits) & 31) as u8);
            }
        }
        if bits > 0 {
            data.push(((acc << (5 - bits)) & 31) as u8);
        }
        let mut values: Vec<u8> = hrp.bytes().map(|c| c >> 5).collect();
        values.push(0);
        values.extend(hrp.bytes().map(|c| c & 31));
        values.extend_from_slice(&data);
        values.extend_from_slice(&[0; 6]);
        let pm = polymod(&values) ^ 0x2bc830a3;
        let mut out = format!("{hrp}1");
        for d in &data {
            out.push(CHARSET[*d as usize] as char);
        }
        for i in 0..6 {
            out.push(CHARSET[((pm >> (5 * (5 - i))) & 31) as usize] as char);
        }
        out
    }

    fn payload() -> Vec<u8> {
        let secp = Secp256k1::new();
        let scan = SecretKey::from_slice(&[0x11; 32]).unwrap();
        let spend = SecretKey::from_slice(&[0x22; 32]).unwrap();
        let mut bytes = scan.secret_bytes().to_vec();
        bytes.extend_from_slice(&spend.public_key(&secp).serialize());
        bytes
    }

    fn export() -> String {
        format!(
            "sp([73c5da0a/352h/1h/0h]{})",
            encode(TESTNET_HRP, &payload(), 0)
        )
    }

    #[test]
    fn parses_the_export_kiss_shows() {
        let keys = parse_scan_export(&export()).unwrap();
        assert_eq!(keys.scan.secret_bytes(), [0x11; 32]);

        let secp = Secp256k1::new();
        let spend = SecretKey::from_slice(&[0x22; 32])
            .unwrap()
            .public_key(&secp);
        assert_eq!(keys.spend, spend);
    }

    #[test]
    fn accepts_the_bare_key_a_person_would_retype() {
        let bare = encode(TESTNET_HRP, &payload(), 0);
        assert_eq!(
            parse_scan_export(&bare).unwrap(),
            parse_scan_export(&export()).unwrap()
        );
    }

    #[test]
    fn refuses_a_mainnet_scan_key() {
        let mainnet = encode(MAINNET_HRP, &payload(), 0);
        let error = parse_scan_export(&mainnet).unwrap_err().to_string();
        assert!(error.contains("mainnet"), "unexpected error: {error}");
    }

    #[test]
    fn rejects_a_future_version() {
        let future = encode(TESTNET_HRP, &payload(), 1);
        assert!(parse_scan_export(&future).is_err());
    }

    #[test]
    fn rejects_a_payload_of_the_wrong_length() {
        let short = encode(TESTNET_HRP, &payload()[..64], 0);
        assert!(parse_scan_export(&short).is_err());
    }

    #[test]
    fn rejects_a_corrupted_checksum() {
        let mut bad: Vec<char> = encode(TESTNET_HRP, &payload(), 0).chars().collect();
        let last = bad.len() - 1;
        bad[last] = if bad[last] == 'q' { 'p' } else { 'q' };
        assert!(parse_scan_export(&bad.into_iter().collect::<String>()).is_err());
    }

    #[test]
    fn builds_a_signet_code_rather_than_round_tripping_one() {
        let keys = parse_scan_export(&export()).unwrap();
        let code = keys.code(Network::Signet);
        assert_eq!(code.network, Network::Signet);
        assert!(code.to_string().starts_with("tsp1"));
    }

    fn hex_of(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn hex_pair() -> String {
        let keys = parse_scan_export(&export()).unwrap();
        format!(
            "{}:{}",
            hex_of(&keys.scan.secret_bytes()),
            hex_of(&keys.spend.serialize())
        )
    }

    /// The point of the raw form: it reaches the same wallet KISS's own export
    /// does, so a device with no `tspscan1…` to give is not a second wallet.
    #[test]
    fn raw_hex_pairs_to_the_same_wallet_as_the_export() {
        assert_eq!(
            parse_scan_hex(&hex_pair()).unwrap(),
            parse_scan_export(&export()).unwrap()
        );
    }

    #[test]
    fn raw_hex_tolerates_surrounding_whitespace() {
        let padded = format!("  {}  ", hex_pair().replace(':', " : "));
        assert_eq!(
            parse_scan_hex(&padded).unwrap(),
            parse_scan_hex(&hex_pair()).unwrap()
        );
    }

    /// Both keys are hex of a similar shape, so the only thing standing between
    /// a transposed pair and a wallet that silently finds nothing is the length.
    #[test]
    fn refuses_the_two_keys_the_wrong_way_round() {
        let keys = parse_scan_export(&export()).unwrap();
        let swapped = format!(
            "{}:{}",
            hex_of(&keys.spend.serialize()),
            hex_of(&keys.scan.secret_bytes())
        );
        let error = parse_scan_hex(&swapped).unwrap_err().to_string();
        assert!(error.contains("33 bytes"), "{error}");
    }

    #[test]
    fn refuses_a_pair_with_no_separator() {
        assert!(parse_scan_hex(&hex_pair().replace(':', "")).is_err());
    }

    #[test]
    fn refuses_hex_that_is_not_a_key() {
        let bad = format!("{}:{}", "00".repeat(32), "ff".repeat(33));
        assert!(parse_scan_hex(&bad).is_err());
    }
}
