use std::fs;
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result, bail};
use base64::Engine;
use bdk_wallet::bitcoin::Psbt;
use bdk_wallet::bitcoin::secp256k1::Secp256k1;
use bdk_wallet::bitcoin::sighash::SighashCache;
use bdk_wallet::miniscript::Descriptor;
use bdk_wallet::miniscript::descriptor::{DescriptorPublicKey, checksum};

mod k_quirc;
pub mod qr;

/// Split the two-path descriptor emitted by KISS (`/<0;1>/*`) into the
/// external and internal descriptors expected by BDK.
pub fn split_kiss_descriptor(descriptor: &str) -> Result<(String, String)> {
    let descriptor = descriptor.trim();
    if descriptor.is_empty() {
        bail!("descriptor is empty");
    }

    // A checksum belongs to the multipath form and is invalid after splitting.
    // Verify it first, then let BDK parse the two checksum-free descriptors.
    let (body, supplied_checksum) = descriptor
        .split_once('#')
        .map_or((descriptor, None), |(body, sum)| (body, Some(sum)));
    if let Some(supplied) = supplied_checksum {
        if supplied.contains('#') {
            bail!("descriptor contains more than one checksum separator");
        }
        let expected = checksum::desc_checksum(body).context("checking descriptor checksum")?;
        if supplied != expected {
            bail!("descriptor checksum is invalid");
        }
    }
    if body.matches("<0;1>").count() != 1 {
        bail!("expected a KISS descriptor containing exactly one <0;1>");
    }

    // KISS emits one of exactly three single-key account descriptors. Keeping
    // this strict makes it impossible to accidentally initialize the online
    // coordinator with a mainnet key, a private key, or the wrong account.
    let (purpose, inner) = if let Some(inner) = body
        .strip_prefix("wpkh([")
        .and_then(|value| value.strip_suffix(')'))
    {
        (84, inner)
    } else if let Some(inner) = body
        .strip_prefix("sh(wpkh([")
        .and_then(|value| value.strip_suffix("))"))
    {
        (49, inner)
    } else if let Some(inner) = body
        .strip_prefix("pkh([")
        .and_then(|value| value.strip_suffix(')'))
    {
        (44, inner)
    } else {
        bail!("expected a KISS pkh, sh(wpkh), or wpkh descriptor");
    };

    let (origin, key_and_paths) = inner
        .split_once(']')
        .context("KISS descriptor is missing its key origin")?;
    let expected_origin_suffix = format!("/{purpose}h/1h/0h");
    let fingerprint = origin
        .strip_suffix(&expected_origin_suffix)
        .context("descriptor is not KISS's Testnet account")?;
    if fingerprint.len() != 8 || !fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("descriptor has an invalid master fingerprint");
    }
    let account_key = key_and_paths
        .strip_suffix("/<0;1>/*")
        .context("descriptor does not end with KISS's <0;1> paths")?;
    if !account_key.starts_with("tpub") {
        bail!("descriptor must contain a public Testnet account key (tpub)");
    }
    if !account_key.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
        bail!("descriptor contains an invalid Testnet account key");
    }

    let split = (
        body.replacen("<0;1>", "0", 1),
        body.replacen("<0;1>", "1", 1),
    );
    split
        .0
        .parse::<Descriptor<DescriptorPublicKey>>()
        .context("parsing KISS receive descriptor")?;
    split
        .1
        .parse::<Descriptor<DescriptorPublicKey>>()
        .context("parsing KISS change descriptor")?;
    Ok(split)
}

/// Read either the binary PSBT written by KISS or a base64 text PSBT.
pub fn read_psbt(path: &Path) -> Result<Psbt> {
    let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let raw = if bytes.starts_with(b"psbt\xff") {
        bytes
    } else {
        let text =
            std::str::from_utf8(&bytes).context("PSBT is neither binary nor UTF-8 base64 text")?;
        let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        base64::engine::general_purpose::STANDARD
            .decode(compact)
            .context("decoding base64 PSBT")?
    };
    Psbt::deserialize(&raw).context("parsing PSBT")
}

pub fn write_psbt(path: &Path, psbt: &Psbt) -> Result<()> {
    write_new_file(path, &psbt.serialize())
}

/// Atomically create a new file without replacing an existing path.
pub fn write_new_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temp = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("creating a temporary file beside {}", path.display()))?;
    temp.write_all(bytes)
        .with_context(|| format!("writing temporary file for {}", path.display()))?;
    temp.as_file()
        .sync_all()
        .with_context(|| format!("syncing temporary file for {}", path.display()))?;
    temp.persist_noclobber(path)
        .map_err(|error| error.error)
        .with_context(|| format!("creating {}; refusing to overwrite it", path.display()))?;
    Ok(())
}

/// Cryptographically verify every ECDSA partial signature carried by a
/// KISS-signed PSBT before BDK turns those signatures into final scripts.
pub fn verify_psbt_ecdsa_signatures(psbt: &Psbt) -> Result<()> {
    let secp = Secp256k1::verification_only();
    let mut sighash_cache = SighashCache::new(&psbt.unsigned_tx);
    for index in 0..psbt.inputs.len() {
        let (message, expected_sighash) = psbt
            .sighash_ecdsa(index, &mut sighash_cache)
            .with_context(|| format!("calculating signature hash for input {index}"))?;
        let signatures = &psbt.inputs[index].partial_sigs;
        if signatures.is_empty() {
            bail!("input {index} has no KISS ECDSA signature");
        }
        for (public_key, signature) in signatures {
            if signature.sighash_type != expected_sighash {
                bail!("input {index} signature uses an unexpected sighash type");
            }
            public_key
                .verify(&secp, &message, signature)
                .with_context(|| format!("verifying KISS signature for input {index}"))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const KISS_DESC: &str = "wpkh([73c5da0a/84h/1h/0h]tpubDC8msFGeGuwnKG9Upg7DM2b4DaRqg3CUZa5g8v2SRQ6K4NSkxUgd7HsL2XVWbVm39yBA4LAxysQAm397zwQSQoQgewGiYZqrA9DsP4zbQ1M/<0;1>/*)";

    #[test]
    fn splits_kiss_multipath_descriptor() {
        let (external, internal) = split_kiss_descriptor(KISS_DESC).unwrap();
        assert!(external.ends_with("/0/*)"));
        assert!(internal.ends_with("/1/*)"));
        assert!(!external.contains("<0;1>"));
    }

    #[test]
    fn strips_multipath_checksum_before_split() {
        let sum = checksum::desc_checksum(KISS_DESC).unwrap();
        let (external, internal) = split_kiss_descriptor(&format!("{KISS_DESC}#{sum}")).unwrap();
        assert!(!external.contains('#'));
        assert!(!internal.contains('#'));
    }

    #[test]
    fn rejects_non_kiss_descriptor_shape() {
        assert!(split_kiss_descriptor("wpkh(tpub/0/*)").is_err());
        assert!(split_kiss_descriptor("").is_err());
    }

    #[test]
    fn rejects_private_mainnet_and_wrong_account_descriptors() {
        assert!(split_kiss_descriptor(&KISS_DESC.replace("tpub", "tprv")).is_err());
        assert!(split_kiss_descriptor(&KISS_DESC.replace("tpub", "xpub")).is_err());
        assert!(split_kiss_descriptor(&KISS_DESC.replace("/1h/", "/0h/")).is_err());
        assert!(split_kiss_descriptor(&format!("{KISS_DESC}#deadbeef")).is_err());
    }

    #[test]
    fn creates_files_atomically_without_overwriting() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("signed.psbt");
        write_new_file(&path, b"complete").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"complete");
        assert!(write_new_file(&path, b"replacement").is_err());
        assert_eq!(fs::read(&path).unwrap(), b"complete");
    }
}
