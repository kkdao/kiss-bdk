//! Checking a signer's silent payment work before the money moves.
//!
//! For an ordinary payment the coordinator built the output itself, so it knows
//! where the money goes. A silent payment output is derived by the signer from
//! keys the coordinator does not hold, so it has to be checked instead:
//!
//! 1. the transaction the signer returned is the one that was sent to it,
//!    except for the silent payment scripts it was asked to fill in;
//! 2. the BIP-374 proof shows the ECDH share came from these inputs;
//! 3. re-deriving the output from that share reproduces the script the signer
//!    wrote.
//!
//! Only all three together show the payment reaches the address the user typed.

use anyhow::{Context, Result, bail};
use bdk_wallet::bitcoin::secp256k1::PublicKey as SecpPublicKey;
use bdk_wallet::bitcoin::{CompressedPublicKey, OutPoint};
use psbt_v2::v2::Psbt as PsbtV2;

use crate::dleq;
use crate::sp::derive;

/// A silent payment output whose script has been independently reproduced.
#[derive(Debug)]
pub struct VerifiedOutput {
    pub index: usize,
    pub scan: SecpPublicKey,
}

/// Verify every silent payment output in `signed` against `original`.
///
/// Returns the outputs that were checked, so a caller can report them.
pub fn verify(original: &PsbtV2, signed: &PsbtV2) -> Result<Vec<VerifiedOutput>> {
    same_transaction(original, signed)?;

    let outpoints = outpoints(signed);
    let a_sum = input_key_sum(signed)?;
    let input_hash = derive::input_hash(&outpoints, &a_sum)?;

    let mut verified = Vec::new();
    let mut group_order: Vec<SecpPublicKey> = Vec::new();
    for (index, output) in signed.outputs.iter().enumerate() {
        let Some(info) = &output.sp_v0_info else {
            continue;
        };
        let scan = SecpPublicKey::from_slice(&info[..33]).context("bad silent payment scan key")?;
        let spend =
            SecpPublicKey::from_slice(&info[33..]).context("bad silent payment spend key")?;

        // Recipients sharing a scan key form a group; k is the position in it.
        let k = group_order.iter().filter(|other| **other == scan).count() as u32;
        group_order.push(scan);

        let key = CompressedPublicKey(scan);
        let share = signed.global.sp_ecdh_shares.get(&key).with_context(|| {
            format!("output {index} has no ECDH share; the signer did not complete it")
        })?;
        let proof = signed
            .global
            .sp_dleq_proofs
            .get(&key)
            .with_context(|| format!("output {index} has an ECDH share but no DLEQ proof"))?;

        dleq::verify(&a_sum, &scan, &share.0, proof.as_bytes())
            .with_context(|| format!("verifying the DLEQ proof for output {index}"))?;

        let expected = derive::output_script(&share.0, &spend, &input_hash, k)?;
        if expected != output.script_pubkey {
            bail!(
                "output {index} does not pay the silent payment address it was built for; \
                 the signer returned a different script"
            );
        }
        verified.push(VerifiedOutput { index, scan });
    }

    if verified.is_empty() {
        bail!("this PSBT carries no silent payment outputs to verify");
    }
    Ok(verified)
}

/// The signer may fill in silent payment scripts. It may change nothing else.
fn same_transaction(original: &PsbtV2, signed: &PsbtV2) -> Result<()> {
    if original.global.tx_version != signed.global.tx_version {
        bail!("the signer returned a different transaction version");
    }
    if outpoints(original) != outpoints(signed) {
        bail!("the signer returned different inputs");
    }
    if original.outputs.len() != signed.outputs.len() {
        bail!("the signer returned a different number of outputs");
    }
    for (index, (before, after)) in original
        .outputs
        .iter()
        .zip(signed.outputs.iter())
        .enumerate()
    {
        if before.amount != after.amount {
            bail!("the signer changed the amount of output {index}");
        }
        if before.sp_v0_info != after.sp_v0_info {
            bail!("the signer changed the silent payment recipient of output {index}");
        }
        // A silent payment script is expected to appear; anything else must not move.
        let filling_in = before.sp_v0_info.is_some() && before.script_pubkey.is_empty();
        if !filling_in && before.script_pubkey != after.script_pubkey {
            bail!("the signer changed the script of output {index}");
        }
    }
    Ok(())
}

fn outpoints(psbt: &PsbtV2) -> Vec<OutPoint> {
    psbt.inputs
        .iter()
        .map(|input| OutPoint {
            txid: input.previous_txid,
            vout: input.spent_output_index,
        })
        .collect()
}

/// Sum of the public keys of the inputs funding the payment.
///
/// A taproot input contributes its even-Y output key, everything else the key
/// in its BIP-32 derivation. KISS only co-signs a silent payment from native
/// segwit inputs, but handling both keeps this checkable against the BIP-375
/// vectors, which mix input types.
pub fn input_key_sum(psbt: &PsbtV2) -> Result<SecpPublicKey> {
    let keys: Vec<SecpPublicKey> = psbt
        .inputs
        .iter()
        .filter_map(|input| match taproot_output_key(input) {
            Some(key) => Some(key),
            None => input.bip32_derivations.keys().next().map(|key| key.inner),
        })
        .collect();
    // BIP-352 sums only the eligible inputs. An input exposing neither an
    // output key nor a derivation cannot fund a silent payment and contributes
    // nothing; a wallet of this coordinator's own UTXOs never hits that case.
    if keys.is_empty() {
        bail!("no input exposes a public key, so no silent payment can be verified");
    }
    let borrowed: Vec<&SecpPublicKey> = keys.iter().collect();
    SecpPublicKey::combine_keys(&borrowed).context("summing the input public keys")
}

fn taproot_output_key(input: &psbt_v2::v2::Input) -> Option<SecpPublicKey> {
    let script = input.witness_utxo.as_ref()?.script_pubkey.clone();
    let bytes = script.as_bytes();
    if bytes.len() != 34 || bytes[0] != 0x51 || bytes[1] != 0x20 {
        return None;
    }
    let mut even_y = vec![0x02_u8];
    even_y.extend_from_slice(&bytes[2..]);
    SecpPublicKey::from_slice(&even_y).ok()
}
