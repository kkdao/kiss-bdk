//! What the coordinator checks before broadcasting a silent payment.
//!
//! The signer legitimately changes the transaction — it fills in output scripts
//! the coordinator could not compute. These tests pin down that it may change
//! exactly that and nothing else, using the official BIP-375 vectors as the
//! "signed" side and a stripped copy of each as the "original".

use kiss_bdk::spverify;
use psbt_v2::bitcoin::Amount;
use psbt_v2::v2::Psbt;

const FIXTURE: &str = include_str!("fixtures/bip375-dleq.json");

/// Signed vectors that carry a global ECDH share and a derived output.
fn signed_vectors() -> Vec<Psbt> {
    let fixture: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
    fixture["valid"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["psbt"].as_str().unwrap().parse::<Psbt>().unwrap())
        .filter(|psbt| {
            !psbt.global.sp_dleq_proofs.is_empty()
                && psbt
                    .outputs
                    .iter()
                    .any(|out| out.sp_v0_info.is_some() && !out.script_pubkey.is_empty())
        })
        .collect()
}

/// Undo the signer's work: the request the coordinator would have sent.
fn as_sent(signed: &Psbt) -> Psbt {
    let mut original = signed.clone();
    original.global.sp_ecdh_shares.clear();
    original.global.sp_dleq_proofs.clear();
    for output in &mut original.outputs {
        if output.sp_v0_info.is_some() {
            output.script_pubkey = Default::default();
        }
    }
    original
}

#[test]
fn accepts_a_signer_that_only_filled_in_the_scripts() {
    let vectors = signed_vectors();
    assert!(!vectors.is_empty(), "fixture must contain signed vectors");
    for signed in &vectors {
        let verified = spverify::verify(&as_sent(signed), signed).unwrap();
        assert!(!verified.is_empty());
    }
}

#[test]
fn accepts_a_signer_that_trimmed_its_input_derivations() {
    // Krux sends its signed PSBT back without the inputs' BIP-32 derivations;
    // the coordinator's own copy still has them.
    for signed in &signed_vectors() {
        let original = as_sent(signed);
        let mut trimmed = signed.clone();
        for input in &mut trimmed.inputs {
            input.bip32_derivations.clear();
        }
        assert!(!spverify::verify(&original, &trimmed).unwrap().is_empty());
    }
}

#[test]
fn rejects_a_signer_that_redirected_the_payment() {
    // The whole point of the check: a script that is not what the share derives
    // to means the money is going somewhere the user did not ask for.
    for signed in &signed_vectors() {
        let original = as_sent(signed);
        let mut tampered = signed.clone();
        let target = tampered
            .outputs
            .iter_mut()
            .find(|out| out.sp_v0_info.is_some())
            .unwrap();
        let mut bytes = target.script_pubkey.to_bytes();
        *bytes.last_mut().unwrap() ^= 0x01;
        target.script_pubkey = bytes.into();

        let error = spverify::verify(&original, &tampered).unwrap_err();
        assert!(
            error.to_string().contains("does not pay"),
            "unexpected error: {error}"
        );
    }
}

#[test]
fn rejects_a_signer_that_moved_the_money_or_the_inputs() {
    for signed in &signed_vectors() {
        let original = as_sent(signed);

        let mut amount_changed = signed.clone();
        amount_changed.outputs[0].amount = Amount::from_sat(1);
        assert!(spverify::verify(&original, &amount_changed).is_err());

        let mut input_dropped = signed.clone();
        input_dropped.inputs.pop();
        assert!(spverify::verify(&original, &input_dropped).is_err());

        let mut recipient_changed = signed.clone();
        if let Some(info) = recipient_changed
            .outputs
            .iter_mut()
            .find_map(|o| o.sp_v0_info.as_mut())
        {
            info[40] ^= 0x01; // a different spend key
        }
        assert!(spverify::verify(&original, &recipient_changed).is_err());
    }
}

#[test]
fn rejects_a_forged_dleq_proof() {
    for signed in &signed_vectors() {
        let original = as_sent(signed);
        let mut forged = signed.clone();
        let key = *forged.global.sp_dleq_proofs.keys().next().unwrap();
        let mut bytes = *forged.global.sp_dleq_proofs[&key].as_bytes();
        bytes[0] ^= 0x01;
        forged
            .global
            .sp_dleq_proofs
            .insert(key, psbt_v2::v2::dleq::DleqProof::from(bytes));
        assert!(spverify::verify(&original, &forged).is_err());
    }
}

#[test]
fn rejects_a_missing_share() {
    for signed in &signed_vectors() {
        let original = as_sent(signed);
        let mut stripped = signed.clone();
        stripped.global.sp_ecdh_shares.clear();
        let error = spverify::verify(&original, &stripped).unwrap_err();
        assert!(
            error.to_string().contains("no ECDH share"),
            "unexpected error: {error}"
        );
    }
}

const BIP375: &str = include_str!("fixtures/bip375-vectors.json");

/// The official BIP-375 vectors of one kind that this crate's PSBT parser reads.
fn official(kind: &str) -> Vec<(String, Psbt)> {
    let fixture: serde_json::Value = serde_json::from_str(BIP375).unwrap();
    fixture[kind]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|item| {
            let psbt = item["psbt"].as_str()?.parse::<Psbt>().ok()?;
            Some((item["description"].as_str().unwrap().to_string(), psbt))
        })
        .collect()
}

/// Whether BIP-375's k differs from counting in output order for any output.
fn order_matters(psbt: &Psbt) -> bool {
    use kiss_bdk::sp::derive;
    use psbt_v2::bitcoin::secp256k1::PublicKey;
    let recipients: Vec<(usize, PublicKey, PublicKey)> = psbt
        .outputs
        .iter()
        .enumerate()
        .filter_map(|(index, output)| {
            let info = output.sp_v0_info.as_ref()?;
            Some((
                index,
                PublicKey::from_slice(&info[..33]).unwrap(),
                PublicKey::from_slice(&info[33..]).unwrap(),
            ))
        })
        .collect();
    let ks = derive::k_values(&recipients);
    let mut seen = Vec::new();
    recipients.iter().any(|(index, scan, _)| {
        let in_output_order = seen.iter().filter(|other| *other == scan).count() as u32;
        seen.push(*scan);
        ks[index] != in_output_order
    })
}

/// A signed vector the single-signer check can express: one global share per
/// scan key and every silent payment script already derived.
fn single_signer_shape(psbt: &Psbt) -> bool {
    let sp: Vec<_> = psbt
        .outputs
        .iter()
        .filter(|out| out.sp_v0_info.is_some())
        .collect();
    !sp.is_empty()
        && sp.iter().all(|out| !out.script_pubkey.is_empty())
        && sp.iter().all(|out| {
            let scan = &out.sp_v0_info.as_ref().unwrap()[..33];
            psbt.global
                .sp_dleq_proofs
                .keys()
                .any(|key| key.to_bytes() == scan)
        })
}

#[test]
fn counts_k_in_bip375_order_on_the_official_vectors() {
    let mut checked = 0;
    let mut reordered = 0;
    for (description, signed) in official("valid") {
        let signed = lift_single_input_shares(signed);
        if !single_signer_shape(&signed) {
            continue;
        }
        if let Err(error) = spverify::verify(&as_sent(&signed), &signed) {
            panic!("{description}: {error:#}");
        }
        checked += 1;
        if order_matters(&signed) {
            reordered += 1;
        }
    }
    assert!(
        checked > 0,
        "no official vector had the single-signer shape"
    );
    assert!(
        reordered > 0,
        "no official vector puts a scan key group out of output order, so this \
         test would not catch output-order counting"
    );

    // The two vectors that exist to catch the wrong order.
    let mut refused = 0;
    for (description, signed) in official("invalid") {
        if !(description.contains("not sorted lexicographically")
            || description.contains("k values assigned to wrong output"))
        {
            continue;
        }
        let signed = lift_single_input_shares(signed);
        if !single_signer_shape(&signed) {
            continue;
        }
        assert!(
            spverify::verify(&as_sent(&signed), &signed).is_err(),
            "{description} was accepted"
        );
        refused += 1;
    }
    assert_eq!(refused, 2, "both ordering vectors must reach the check");
}

/// With one input, that input's share and proof are the global ones: `A_sum`
/// is its key. The vectors that put several codes under one scan key all have
/// one input and per-input shares, so this is how they reach the
/// single-signer check, which reads global shares only.
fn lift_single_input_shares(mut psbt: Psbt) -> Psbt {
    if psbt.inputs.len() == 1 && psbt.global.sp_ecdh_shares.is_empty() {
        let input = &mut psbt.inputs[0];
        psbt.global.sp_ecdh_shares = std::mem::take(&mut input.sp_ecdh_shares);
        psbt.global.sp_dleq_proofs = std::mem::take(&mut input.sp_dleq_proofs);
    }
    psbt
}
