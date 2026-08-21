//! BIP-374 verification checked against the official BIP-375 test vectors.
//!
//! The proofs in these vectors were produced by a different implementation, so
//! agreeing with them is the evidence that this verifier implements the spec
//! rather than merely being self-consistent.

use bdk_wallet::bitcoin::secp256k1::PublicKey;
use kiss_bdk::dleq;
use psbt_v2::v2::Psbt;

const FIXTURE: &str = include_str!("fixtures/bip375-dleq.json");

/// The sum of the input public keys the silent payment was derived from.
///
/// Taproot inputs contribute their even-Y key; everything else contributes the
/// key in its BIP-32 derivation. Inputs that expose neither are not eligible to
/// fund a silent payment under BIP-352 and are skipped, which is what the
/// mixed-input vectors exercise.
fn input_key_sum(psbt: &Psbt) -> Option<PublicKey> {
    let mut keys: Vec<PublicKey> = Vec::new();
    for input in &psbt.inputs {
        let taproot = input.witness_utxo.as_ref().and_then(|utxo| {
            let script = utxo.script_pubkey.as_bytes();
            (script.len() == 34 && script[0] == 0x51 && script[1] == 0x20).then(|| {
                let mut even_y = vec![0x02_u8];
                even_y.extend_from_slice(&script[2..]);
                even_y
            })
        });
        match taproot {
            Some(even_y) => keys.extend(PublicKey::from_slice(&even_y).ok()),
            None => keys.extend(input.bip32_derivations.keys().next().map(|key| key.inner)),
        }
    }
    let borrowed: Vec<&PublicKey> = keys.iter().collect();
    PublicKey::combine_keys(&borrowed).ok()
}

fn check(bucket: &str, expected: bool) {
    let fixture: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
    let mut checked = 0;
    for item in fixture[bucket].as_array().unwrap() {
        let description = item["description"].as_str().unwrap();
        let psbt: Psbt = item["psbt"].as_str().unwrap().parse().unwrap();
        let a_pub = input_key_sum(&psbt).expect("vector must expose its input keys");
        for (scan, proof) in &psbt.global.sp_dleq_proofs {
            let share = &psbt.global.sp_ecdh_shares[scan];
            let verified = dleq::verify(&a_pub, &scan.0, &share.0, proof.as_bytes()).is_ok();
            assert_eq!(verified, expected, "{description}");
            checked += 1;
        }
    }
    assert!(checked > 0, "no {bucket} DLEQ proofs were exercised");
}

#[test]
fn accepts_the_proofs_in_the_valid_vectors() {
    check("valid", true);
}

#[test]
fn rejects_the_deliberately_invalid_proof() {
    check("invalid", false);
}
