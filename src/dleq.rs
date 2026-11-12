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

/// The secp256k1 group order `n`, big endian.
const ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// Verify that `share` is `a·B` for the same `a` behind `a_pub = a·G`.
///
/// * `a_pub` — sum of the input public keys funding the transaction
/// * `b` — the recipient's scan key, taken from their address
/// * `share` — the ECDH share the signer returned
///
/// BIP-374 VerifyProof, 0.3.0 and later: `e` and `s` must both be below `n`,
/// and `e` is compared with the challenge hash reduced mod `n`. Zero is a
/// valid value of either; it only stands for the point at infinity in the
/// sums below.
pub fn verify(a_pub: &PublicKey, b: &PublicKey, share: &PublicKey, proof: &[u8; 64]) -> Result<()> {
    let e: [u8; 32] = proof[..32].try_into().expect("32 bytes");
    let s: [u8; 32] = proof[32..].try_into().expect("32 bytes");
    // Refused, never reduced: an e of n or more is the unreduced encoding of a
    // smaller one, which a conforming prover never writes.
    if e >= ORDER {
        bail!("DLEQ challenge is out of range");
    }
    if s >= ORDER {
        bail!("DLEQ response is out of range");
    }

    let secp = Secp256k1::new();
    // None stands for zero, whose multiples are the point at infinity.
    let response = SecretKey::from_slice(&s).ok();
    let negated = SecretKey::from_slice(&e).ok().map(SecretKey::negate);

    // R1 = s·G + (-e)·A
    let r1 = add(
        response.map(|s| PublicKey::from_secret_key(&secp, &s)),
        negated.map(|e| multiply(&secp, a_pub, &e)).transpose()?,
    )
    .context("DLEQ R1 is the point at infinity")?;
    // R2 = s·B + (-e)·C
    let r2 = add(
        response.map(|s| multiply(&secp, b, &s)).transpose()?,
        negated.map(|e| multiply(&secp, share, &e)).transpose()?,
    )
    .context("DLEQ R2 is the point at infinity")?;

    let expected = challenge(a_pub, b, share, &r1, &r2);
    // The challenge is a hash, so a plain comparison is not a timing concern.
    if expected != e {
        bail!("DLEQ proof does not match the ECDH share the signer returned");
    }
    Ok(())
}

/// `p + q`, where `None` is the point at infinity. `None` back means the sum
/// is the point at infinity too.
fn add(p: Option<PublicKey>, q: Option<PublicKey>) -> Option<PublicKey> {
    match (p, q) {
        (Some(p), Some(q)) => p.combine(&q).ok(),
        (one, None) | (None, one) => one,
    }
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

#[cfg(test)]
thread_local! {
    /// Test only: stands in for the challenge hash, because a real one lands
    /// at or above `n` about once in 2^128 tries.
    static CHALLENGE_HASH: std::cell::Cell<Option<[u8; 32]>> = const { std::cell::Cell::new(None) };
}

/// `e = int(hash_BIP0374/challenge(A || B || C || G || R1 || R2)) mod n`.
fn challenge(
    a_pub: &PublicKey,
    b: &PublicKey,
    share: &PublicKey,
    r1: &PublicKey,
    r2: &PublicKey,
) -> [u8; 32] {
    let hash = challenge_hash(a_pub, b, share, r1, r2);
    #[cfg(test)]
    let hash = CHALLENGE_HASH.with(std::cell::Cell::get).unwrap_or(hash);
    reduce(hash)
}

/// `value mod n` for any 32 byte value. `n` is above 2^255, so one
/// subtraction is always enough.
fn reduce(value: [u8; 32]) -> [u8; 32] {
    if value < ORDER {
        return value;
    }
    let mut out = [0_u8; 32];
    let mut borrow = 0_i16;
    for index in (0..32).rev() {
        let difference = i16::from(value[index]) - i16::from(ORDER[index]) - borrow;
        borrow = i16::from(difference < 0);
        out[index] = (difference + 256 * borrow) as u8;
    }
    out
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

        let e = challenge(&a_pub, b, &share, &r1, &r2);
        // s = k + e*a mod n; e = 0 leaves s = k, and s itself may come out 0
        let mut s = [0_u8; 32];
        let ea = SecretKey::from_slice(&e)
            .ok()
            .map(|e| e.mul_tweak(&Scalar::from(*a)).unwrap());
        match ea {
            None => s = k.secret_bytes(),
            Some(ea) => {
                if let Ok(sum) = ea.add_tweak(&Scalar::from(*k)) {
                    s = sum.secret_bytes();
                }
            }
        }

        let mut proof = [0_u8; 64];
        proof[..32].copy_from_slice(&e);
        proof[32..].copy_from_slice(&s);
        (proof, a_pub, share)
    }

    /// Run `body` with the challenge hash pinned to `hash`.
    fn with_challenge<T>(hash: [u8; 32], body: impl FnOnce() -> T) -> T {
        CHALLENGE_HASH.with(|cell| cell.set(Some(hash)));
        let out = body();
        CHALLENGE_HASH.with(|cell| cell.set(None));
        out
    }

    /// `n + small`, which still fits 32 bytes for small values.
    fn order_plus(small: u8) -> [u8; 32] {
        let mut out = ORDER;
        let mut carry = u16::from(small);
        for byte in out.iter_mut().rev() {
            let sum = u16::from(*byte) + carry;
            *byte = sum as u8;
            carry = sum >> 8;
        }
        out
    }

    fn scalar(last: u8) -> [u8; 32] {
        let mut out = [0_u8; 32];
        out[31] = last;
        out
    }

    #[test]
    fn a_challenge_hash_at_or_above_n_is_written_reduced_and_verifies() {
        let (a, b, k) = keys();
        // (hash, the e it must reduce to)
        let all_ones = [0xff_u8; 32];
        for (hash, want) in [
            (ORDER, scalar(0)),
            (order_plus(5), scalar(5)),
            (all_ones, reduce(all_ones)),
        ] {
            let (proof, a_pub, share) = with_challenge(hash, || prove(&a, &b, &k));
            assert_eq!(proof[..32], want, "e must be the hash mod n");
            with_challenge(hash, || verify(&a_pub, &b, &share, &proof))
                .expect("the reduced proof verifies");

            // The same proof with e left unreduced is what a prover before
            // BIP-374 0.3.0 wrote, and is refused.
            let mut unreduced = proof;
            unreduced[..32].copy_from_slice(&hash);
            assert!(
                with_challenge(hash, || verify(&a_pub, &b, &share, &unreduced)).is_err(),
                "an e of n or more must be refused"
            );
        }
    }

    #[test]
    fn a_zero_response_is_a_valid_proof() {
        // s = k + e·a = 0 when k = -(e·a). Pinning the challenge is what makes
        // k choosable; with a real hash nobody can aim for this.
        let (a, b, _) = keys();
        let e = scalar(7);
        let k = SecretKey::from_slice(&e)
            .unwrap()
            .mul_tweak(&Scalar::from(a))
            .unwrap()
            .negate();
        let (proof, a_pub, share) = with_challenge(e, || prove(&a, &b, &k));
        assert_eq!(proof[32..], [0_u8; 32]);
        with_challenge(e, || verify(&a_pub, &b, &share, &proof)).expect("s = 0 is below n");
    }

    #[test]
    fn e_or_s_at_or_above_n_is_refused() {
        let (a, b, k) = keys();
        let (proof, a_pub, share) = prove(&a, &b, &k);
        verify(&a_pub, &b, &share, &proof).unwrap();
        for (half, value) in [
            (0, ORDER),
            (0, [0xff; 32]),
            (32, ORDER),
            (32, order_plus(1)),
        ] {
            let mut broken = proof;
            broken[half..half + 32].copy_from_slice(&value);
            assert!(
                verify(&a_pub, &b, &share, &broken).is_err(),
                "a half at offset {half} of n or more was accepted"
            );
        }
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
