//! BIP-374 discrete logarithm equality proofs.
//!
//! When KISS derives a silent payment output it also returns an ECDH share and
//! a proof that the share was computed from the same input keys that fund the
//! transaction. Verifying it is the coordinator's only protection against a
//! signer that quietly sends the money somewhere else: without it, the output
//! script would have to be taken on trust.
//!
//! `main/kiss_sp.c` (`sp_dleq_verify`) is the implementation this must agree
//! with. psbt-v2 carries the 64-byte proof but does not verify it.

use anyhow::{Context, Result, bail};
use bdk_wallet::bitcoin::hashes::{Hash, sha256};
use bdk_wallet::bitcoin::secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};

/// The secp256k1 generator in compressed form, hashed into the challenge.
const GENERATOR: [u8; 33] = [
    0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
    0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17,
    0x98,
];

/// Verify that `share` is `a·B` for the same `a` behind `a_pub = a·G`.
///
/// * `a_pub` — sum of the input public keys funding the transaction
/// * `b` — the recipient's scan key, taken from their address
/// * `share` — the ECDH share the signer returned
pub fn verify(a_pub: &PublicKey, b: &PublicKey, share: &PublicKey, proof: &[u8; 64]) -> Result<()> {
    // from_slice rejects zero and anything >= the curve order, which covers the
    // spec's range checks on both halves of the proof.
    let challenge =
        SecretKey::from_slice(&proof[..32]).context("DLEQ challenge is out of range")?;
    let response = SecretKey::from_slice(&proof[32..]).context("DLEQ response is out of range")?;

    let secp = Secp256k1::new();
    let negated = challenge.negate();

    // R1 = s·G + (-e)·A
    let r1 = PublicKey::from_secret_key(&secp, &response)
        .combine(&multiply(&secp, a_pub, &negated)?)
        .context("DLEQ R1 is the point at infinity")?;
    // R2 = s·B + (-e)·C
    let r2 = multiply(&secp, b, &response)?
        .combine(&multiply(&secp, share, &negated)?)
        .context("DLEQ R2 is the point at infinity")?;

    let expected = challenge_hash(a_pub, b, share, &r1, &r2);
    // The challenge is a hash, so a plain comparison is not a timing concern.
    if expected != proof[..32] {
        bail!("DLEQ proof does not match the ECDH share the signer returned");
    }
    Ok(())
}

fn multiply(
    secp: &Secp256k1<bdk_wallet::bitcoin::secp256k1::All>,
    point: &PublicKey,
    scalar: &SecretKey,
) -> Result<PublicKey> {
    point
        .mul_tweak(secp, &Scalar::from(*scalar))
        .context("DLEQ scalar multiplication left the curve")
}

fn challenge_hash(
    a_pub: &PublicKey,
    b: &PublicKey,
    share: &PublicKey,
    r1: &PublicKey,
    r2: &PublicKey,
) -> [u8; 32] {
    let mut message = Vec::with_capacity(33 * 6);
    message.extend_from_slice(&a_pub.serialize());
    message.extend_from_slice(&b.serialize());
    message.extend_from_slice(&share.serialize());
    message.extend_from_slice(&GENERATOR);
    message.extend_from_slice(&r1.serialize());
    message.extend_from_slice(&r2.serialize());
    tagged_hash("BIP0374/challenge", &message)
}

/// BIP-340 style tagged hash: `sha256(sha256(tag) || sha256(tag) || message)`.
pub(crate) fn tagged_hash(tag: &str, message: &[u8]) -> [u8; 32] {
    let tag_hash = sha256::Hash::hash(tag.as_bytes());
    let mut engine = Vec::with_capacity(64 + message.len());
    engine.extend_from_slice(tag_hash.as_byte_array());
    engine.extend_from_slice(tag_hash.as_byte_array());
    engine.extend_from_slice(message);
    sha256::Hash::hash(&engine).to_byte_array()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Prove the round trip against a locally generated proof, following the
    /// same construction KISS uses in `sp_dleq_prove`.
    fn prove(a: &SecretKey, b: &PublicKey, k: &SecretKey) -> ([u8; 64], PublicKey, PublicKey) {
        let secp = Secp256k1::new();
        let a_pub = PublicKey::from_secret_key(&secp, a);
        let share = b.mul_tweak(&secp, &Scalar::from(*a)).unwrap();
        let r1 = PublicKey::from_secret_key(&secp, k);
        let r2 = b.mul_tweak(&secp, &Scalar::from(*k)).unwrap();

        let e = challenge_hash(&a_pub, b, &share, &r1, &r2);
        let e_key = SecretKey::from_slice(&e).unwrap();
        // s = k + e*a
        let s = e_key
            .mul_tweak(&Scalar::from(*a))
            .unwrap()
            .add_tweak(&Scalar::from(*k))
            .unwrap();

        let mut proof = [0_u8; 64];
        proof[..32].copy_from_slice(&e);
        proof[32..].copy_from_slice(&s.secret_bytes());
        (proof, a_pub, share)
    }

    fn keys() -> (SecretKey, PublicKey, SecretKey) {
        let secp = Secp256k1::new();
        let a = SecretKey::from_slice(&[0x11; 32]).unwrap();
        let b_secret = SecretKey::from_slice(&[0x22; 32]).unwrap();
        let k = SecretKey::from_slice(&[0x33; 32]).unwrap();
        (a, PublicKey::from_secret_key(&secp, &b_secret), k)
    }

    #[test]
    fn accepts_an_honest_proof() {
        let (a, b, k) = keys();
        let (proof, a_pub, share) = prove(&a, &b, &k);
        verify(&a_pub, &b, &share, &proof).unwrap();
    }

    #[test]
    fn rejects_a_share_the_proof_does_not_cover() {
        let (a, b, k) = keys();
        let (proof, a_pub, _) = prove(&a, &b, &k);
        // A signer sending the money elsewhere would produce a different share.
        let secp = Secp256k1::new();
        let other = SecretKey::from_slice(&[0x44; 32]).unwrap();
        let wrong_share = b.mul_tweak(&secp, &Scalar::from(other)).unwrap();
        assert!(verify(&a_pub, &b, &wrong_share, &proof).is_err());
    }

    #[test]
    fn rejects_a_tampered_proof() {
        let (a, b, k) = keys();
        let (proof, a_pub, share) = prove(&a, &b, &k);
        for index in [0, 31, 32, 63] {
            let mut broken = proof;
            broken[index] ^= 0x01;
            assert!(
                verify(&a_pub, &b, &share, &broken).is_err(),
                "flipping byte {index} was accepted"
            );
        }
    }

    #[test]
    fn rejects_a_proof_made_for_different_inputs() {
        let (a, b, k) = keys();
        let (proof, _, share) = prove(&a, &b, &k);
        let secp = Secp256k1::new();
        let other = SecretKey::from_slice(&[0x55; 32]).unwrap();
        let wrong_a_pub = PublicKey::from_secret_key(&secp, &other);
        assert!(verify(&wrong_a_pub, &b, &share, &proof).is_err());
    }
}
