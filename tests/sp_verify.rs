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
