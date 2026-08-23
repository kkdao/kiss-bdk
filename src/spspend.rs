//! BIP-376: spending a silent payment this wallet received.
//!
//! `spsend` is the other direction — paying *to* someone's silent payment
//! address. This one moves a coin that arrived at ours.
//!
//! A received silent payment pays `P = B_spend + t·G`, where `B_spend` is the
//! spend key that never leaves KISS and `t` is the tweak the scan found. So the
//! private key is `b_spend + t`, which is not a BIP-32 child of anything: no
//! derivation path names it and no descriptor can hold it. That is why these
//! coins sit in their own table rather than in BDK's wallet, and why spending
//! one means handing the signer the tweak and asking it to add.
//!
//! The tweak travels as `PSBT_IN_SP_TWEAK`, and the signer does not take it on
//! trust: it recomputes `(b_spend + t)·G` and refuses unless the x-coordinate is
//! the output key actually being spent. A wrong tweak would otherwise steer a
//! signature onto a key the wallet does not own. This module makes the same
//! check before the PSBT is written, so a store that disagrees with the paired
//! device is caught here rather than on a screen across the room.
//!
//! Two rules from the signer shape everything below, and both are refusals
//! rather than warnings:
//!
//! 1. **Every input must be a silent payment, or none of them.** BIP-143 commits
//!    only to the amount of the input being signed, so with two or more inputs a
//!    coordinator can run two individually-truthful signing sessions and combine
//!    them into a transaction paying a fee neither screen showed. BIP-341 hashes
//!    every input amount, so an all-taproot spend is immune — and this wallet's
//!    descriptor is `wpkh`/`sh(wpkh)`/`pkh`, so an ordinary input never is. The
//!    signer refuses the mix outright.
//! 2. **The PSBT must be v2.** A v0 carrying tweaks loads green and then fails
//!    to sign, because the signer's taproot sighash is computed only from the
//!    transaction view it extracts from a v2's own fields.
//!
//! `bdk_sp` ships a dormant `psbt_sp_spend` feature that looks like exactly what
//! this needs. It is not: it writes a *proprietary* key with prefix `bip352`,
//! and the signer counts every proprietary key as unknown data and stops. Leave
//! it off.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, bail};
use bdk_wallet::bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint, KeySource};
use bdk_wallet::bitcoin::hashes::Hash;
use bdk_wallet::bitcoin::psbt::raw;
use bdk_wallet::bitcoin::secp256k1::{
    Message, PublicKey, Scalar, Secp256k1, SecretKey, XOnlyPublicKey,
};
use bdk_wallet::bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bdk_wallet::bitcoin::{
    Amount, FeeRate, OutPoint, Psbt, ScriptBuf, TxOut, Weight, Witness, psbt,
};

use crate::spstore::StoredOut;

/// `PSBT_IN_SP_TWEAK`. The key is this byte alone; the value is the 32-byte
/// BIP-352 tweak. The signer checks both lengths exactly.
pub const PSBT_IN_SP_TWEAK: u8 = 0x20;

/// `PSBT_IN_SP_SPEND_BIP32_DERIVATION`. The key is this byte plus the 33-byte
/// spend pubkey; the value is a 4-byte fingerprint followed by little-endian
/// path elements.
///
/// KISS ignores the contents and derives its own spend key, but it does check
/// the shape, and other BIP-376 signers need it to know which account a coin
/// belongs to. It is also what makes a spend PSBT self-describing to a human
/// reading `inspect`.
pub const PSBT_IN_SP_SPEND_BIP32_DERIVATION: u8 = 0x1f;

/// BIP-352's account, on the only coin type this coordinator can address.
///
/// All three chains here are coin type 1, and mainnet is unrepresentable rather
/// than merely rejected, so the path has no network-dependent part.
const SPEND_PATH: [u32; 5] = [352, 1, 0, 0, 0];

/// A taproot key-path witness: one item, one length byte, a 64-byte signature.
///
/// What `add_foreign_utxo` needs in order to price the input. Wrong here means a
/// fee that is quietly too low or too high, so it is arithmetic rather than a
/// remembered number.
pub const SATISFACTION_WEIGHT: Weight = Weight::from_wu(1 + 1 + 64);

/// One whole input: outpoint 36, sequence 4, empty scriptSig length 1, all
/// non-witness, plus the witness above.
pub const INPUT_WEIGHT: Weight = Weight::from_wu((36 + 4 + 1) * 4 + 1 + 1 + 64);

/// Everything in a transaction that is not an input, generously.
///
/// Version, locktime, the segwit marker, the two counts, a 43-byte recipient
/// output and a 31-byte change output. Selection only has to avoid coming up
/// short — BDK computes the fee that is actually paid, and anything
/// over-selected lands in change rather than being lost.
const OVERHEAD_WEIGHT: Weight = Weight::from_wu((4 + 4 + 1 + 1 + 43 + 31) * 4 + 2);

/// Consensus cap, matching the signer's own defence against a corrupt amount.
const MAX_MONEY_SATS: u64 = 2_100_000_000_000_000;

/// A stored output whose tweak has been proven to reproduce its own script.
///
/// The only constructor is [`SpCoin::checked`], so a coin this wallet cannot
/// prove it owns cannot be built, let alone spent.
#[derive(Debug, Clone)]
pub struct SpCoin {
    pub outpoint: OutPoint,
    pub amount: Amount,
    pub height: u32,
    tweak: SecretKey,
    script_pubkey: ScriptBuf,
    output_key: XOnlyPublicKey,
}

impl SpCoin {
    /// Re-derive the output key from the tweak and the paired spend key, and
    /// accept the coin only if it reproduces the script that was stored.
    ///
    /// This is the signer's own theft guard, run early. It also catches a case
    /// that is not hypothetical: `sp-pair` replaces the key row but leaves every
    /// output found with the previous device, so after pairing to a different
    /// KISS the store still lists coins that device cannot sign. Caught here it
    /// says so; caught on the device it says "not this wallet's".
    pub fn checked(stored: &StoredOut, spend: &PublicKey) -> Result<Self> {
        if stored.amount.to_sat() > MAX_MONEY_SATS {
            bail!(
                "silent payment {} claims {} sats, which is over the 21M cap; \
                 the store is corrupt",
                stored.outpoint,
                stored.amount.to_sat()
            );
        }

        // A label shifts the tweak rather than the check: bdk_sp stores
        // `t_k + label_tweak`, so `P = B_spend + tweak*G` holds either way and
        // the signer's `d = b + t` needs no special case. Nothing to do here.
        let output_key = output_key(spend, &stored.tweak).with_context(|| {
            format!(
                "deriving the output key for silent payment {}",
                stored.outpoint
            )
        })?;
        let expected = p2tr_script(&output_key);
        if expected != stored.script_pubkey {
            bail!(
                "silent payment {} does not re-derive: its tweak and this wallet's \
                 spend key produce {}, but the output pays {}. If this wallet was \
                 re-paired to a different KISS, the outputs found with the old one \
                 are not spendable here.",
                stored.outpoint,
                expected.to_hex_string(),
                stored.script_pubkey.to_hex_string()
            );
        }

        Ok(SpCoin {
            outpoint: stored.outpoint,
            amount: stored.amount,
            height: stored.height,
            tweak: stored.tweak,
            script_pubkey: stored.script_pubkey.clone(),
            output_key,
        })
    }

    /// The previous output, as a witness UTXO.
    pub fn txout(&self) -> TxOut {
        TxOut {
            value: self.amount,
            script_pubkey: self.script_pubkey.clone(),
        }
    }

    /// The x-only key a signature over this input must verify against.
    pub fn output_key(&self) -> XOnlyPublicKey {
        self.output_key
    }
}

/// `P = B_spend + t·G`, x-only: the key a silent payment output pays to.
///
/// The coordinator's copy of the signer's `sp_spend_signing_key` check. It
/// derives the public half; the private half stays on the device.
pub fn output_key(spend: &PublicKey, tweak: &SecretKey) -> Result<XOnlyPublicKey> {
    let secp = Secp256k1::new();
    let point = spend
        .add_exp_tweak(&secp, &Scalar::from(*tweak))
        .context("the tweaked spend key left the curve")?;
    Ok(point.x_only_public_key().0)
}

/// The 34-byte P2TR script for an x-only key.
fn p2tr_script(key: &XOnlyPublicKey) -> ScriptBuf {
    let mut script = Vec::with_capacity(34);
    script.push(0x51); // OP_1: taproot witness version
    script.push(0x20); // 32-byte program
    script.extend_from_slice(&key.serialize());
    ScriptBuf::from_bytes(script)
}

/// The BIP-352 spend key's origin, `m/352h/1h/0h/0h/0`.
pub fn spend_origin(master: Fingerprint) -> KeySource {
    let path: DerivationPath = SPEND_PATH
        .iter()
        .enumerate()
        .map(|(depth, index)| {
            // Only the last element is unhardened, which is what the signer
            // derives and what its own reference vector carries.
            if depth + 1 == SPEND_PATH.len() {
                ChildNumber::from_normal_idx(*index)
            } else {
                ChildNumber::from_hardened_idx(*index)
            }
            .expect("BIP-352's path elements are all in range")
        })
        .collect();
    (master, path)
}

/// The BIP-376 input for one coin, as BDK will carry it through unchanged.
///
/// What is *absent* matters as much as what is present. A `PSBT_IN_BIP32_
/// DERIVATION` or `PSBT_IN_TAP_BIP32_DERIVATION` naming the device's
/// fingerprint makes libwally take its ordinary taproot path, look the key up
/// among leaf hashes that do not exist, and fail the whole signing. A sighash
/// type turns the returned 64-byte signature into 65 bytes over a different
/// message. A `non_witness_utxo` is ignored and only eats the 4096-byte budget.
/// So this builds the input field by field rather than starting from anything
/// BDK produced.
pub fn psbt_input(coin: &SpCoin, spend: &PublicKey, origin: &KeySource) -> psbt::Input {
    let mut input = psbt::Input {
        witness_utxo: Some(coin.txout()),
        ..Default::default()
    };

    input.unknown.insert(
        raw::Key {
            type_value: PSBT_IN_SP_TWEAK,
            key: Vec::new(),
        },
        coin.tweak.secret_bytes().to_vec(),
    );
    input.unknown.insert(
        raw::Key {
            type_value: PSBT_IN_SP_SPEND_BIP32_DERIVATION,
            key: spend.serialize().to_vec(),
        },
        origin_value(origin),
    );
    input
}

/// A key origin on the wire: the fingerprint, then one little-endian word per
/// path element, hardened bit included.
fn origin_value((fingerprint, path): &KeySource) -> Vec<u8> {
    let mut value = Vec::with_capacity(4 + path.len() * 4);
    value.extend_from_slice(fingerprint.as_bytes());
    for child in path.into_iter() {
        value.extend_from_slice(&u32::from(*child).to_le_bytes());
    }
    value
}

/// Coins this spend will use, oldest first.
///
/// Selection is ours rather than BDK's, for a reason worth stating: everything
/// handed to `add_foreign_utxo` becomes a *required* input
/// (`bdk_wallet` `wallet/mod.rs:1431`), so adding every candidate would sweep
/// the whole silent payment balance into one transaction instead of choosing.
/// BDK still computes the fee that is actually paid; this only has to avoid
/// coming up short, and anything over-selected returns as change.
pub fn select(
    candidates: Vec<SpCoin>,
    target: Amount,
    fee_rate: FeeRate,
    max_inputs: usize,
) -> Result<Vec<SpCoin>> {
    let mut chosen: Vec<SpCoin> = Vec::new();
    let mut total = Amount::ZERO;
    let mut skipped = 0_usize;

    // A coin worth less than it costs to spend is a loss, not a contribution.
    let marginal = fee_rate * INPUT_WEIGHT;

    for coin in candidates {
        if coin.amount <= marginal {
            skipped += 1;
            continue;
        }
        if chosen.len() == max_inputs {
            break;
        }
        total = total
            .checked_add(coin.amount)
            .context("silent payment balance overflows")?;
        chosen.push(coin);
        if total >= needed(target, fee_rate, chosen.len()) {
            return Ok(chosen);
        }
    }

    if chosen.is_empty() && skipped > 0 {
        bail!(
            "every silent payment output is worth less than it costs to spend at \
             {} sat/vB",
            fee_rate.to_sat_per_vb_ceil()
        );
    }
    let short = needed(target, fee_rate, chosen.len().max(1));
    bail!(
        "silent payment balance is {} sats across {} spendable output(s); this \
         spend needs about {} sats including fee.\n\
         KISS refuses a transaction that mixes silent payment inputs with ordinary \
         ones: BIP-341 hashes every input amount into the signature so an \
         all-taproot spend proves its own fee, and a P2WPKH input does not. So the \
         ordinary wallet balance cannot make up the difference here. Send less, or \
         send twice.",
        total.to_sat(),
        chosen.len(),
        short.to_sat()
    );
}

/// What `n` inputs must cover: the payment plus a conservative fee.
fn needed(target: Amount, fee_rate: FeeRate, inputs: usize) -> Amount {
    let weight = OVERHEAD_WEIGHT + INPUT_WEIGHT * inputs as u64;
    target + fee_rate * weight
}

/// Which PSBT inputs are silent payments, and the key each must have signed
/// with.
///
/// Built from the coins this coordinator selected, never from the PSBT's own
/// tweak field — reading the tweak back out of a PSBT a signer touched would
/// verify a signature against whatever key that PSBT asked for.
pub fn sp_inputs(psbt: &Psbt, coins: &[SpCoin]) -> Result<BTreeMap<usize, XOnlyPublicKey>> {
    let by_outpoint: BTreeMap<OutPoint, &SpCoin> =
        coins.iter().map(|coin| (coin.outpoint, coin)).collect();

    let mut found = BTreeMap::new();
    for (index, txin) in psbt.unsigned_tx.input.iter().enumerate() {
        if let Some(coin) = by_outpoint.get(&txin.previous_output) {
            found.insert(index, coin.output_key());
        }
    }
    if found.len() != coins.len() {
        let missing: BTreeSet<OutPoint> = coins
            .iter()
            .map(|coin| coin.outpoint)
            .filter(|outpoint| {
                !psbt
                    .unsigned_tx
                    .input
                    .iter()
                    .any(|txin| txin.previous_output == *outpoint)
            })
            .collect();
        bail!("selected silent payment outputs are missing from the transaction: {missing:?}");
    }
    Ok(found)
}

/// Check KISS's signature on every silent payment input.
///
/// The analogue of the DLEQ check on the sending side: the coordinator cannot
/// produce this signature, so it re-derives the message and the key and
/// verifies rather than trusting that a signature-shaped field is a signature.
pub fn verify_signatures(psbt: &Psbt, sp: &BTreeMap<usize, XOnlyPublicKey>) -> Result<()> {
    if sp.is_empty() {
        return Ok(());
    }

    // A taproot sighash commits to every prevout's script and amount, so all of
    // them must be present and none may be reconstructed from somewhere else:
    // a witness UTXO and a previous transaction that disagreed would hash two
    // different messages.
    let mut prevouts = Vec::with_capacity(psbt.inputs.len());
    for (index, input) in psbt.inputs.iter().enumerate() {
        let utxo = input
            .witness_utxo
            .clone()
            .with_context(|| format!("input {index} has no witness UTXO to hash"))?;
        prevouts.push(utxo);
    }

    let secp = Secp256k1::new();
    let mut cache = SighashCache::new(&psbt.unsigned_tx);
    for (index, expected) in sp {
        let signature = psbt.inputs[*index]
            .tap_key_sig
            .with_context(|| format!("silent payment input {index} carries no signature"))?;
        // 64 bytes means SIGHASH_DEFAULT. The signer appends a hash-type byte
        // only when the PSBT asked for one, so 65 bytes back means a sighash
        // field survived into the request and the message hashed here is not
        // the message that was signed.
        if signature.sighash_type != TapSighashType::Default {
            bail!(
                "silent payment input {index} was signed with sighash {:?}; \
                 this coordinator only ever asks for the default",
                signature.sighash_type
            );
        }
        let sighash = cache
            .taproot_key_spend_signature_hash(
                *index,
                &Prevouts::All(&prevouts),
                TapSighashType::Default,
            )
            .with_context(|| format!("hashing silent payment input {index}"))?;
        secp.verify_schnorr(
            &signature.signature,
            &Message::from_digest(sighash.to_byte_array()),
            expected,
        )
        .with_context(|| {
            format!(
                "input {index} is not signed by the key that owns it; KISS returned \
                 a signature this wallet cannot verify"
            )
        })?;
    }
    Ok(())
}

/// Turn each verified signature into a final witness.
///
/// BDK cannot: finalizing goes through a descriptor, and no descriptor matches
/// a silent payment script. Its own finalizer skips an input that already has a
/// witness, so doing these first and handing it the rest composes.
pub fn finalize(psbt: &mut Psbt, sp: &BTreeMap<usize, XOnlyPublicKey>) -> Result<usize> {
    for index in sp.keys() {
        let input = psbt
            .inputs
            .get_mut(*index)
            .with_context(|| format!("input {index} is not in this PSBT"))?;
        let signature = input
            .tap_key_sig
            .with_context(|| format!("silent payment input {index} carries no signature"))?;
        input.final_script_witness = Some(Witness::p2tr_key_spend(&signature));
        // Finalizer hygiene, and not only tidiness: the tweak names a key, and
        // a PSBT that is ready to broadcast has no reason to keep carrying it.
        input.tap_key_sig = None;
        input.unknown.clear();
    }
    Ok(sp.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bdk_wallet::bitcoin::Txid;
    use bdk_wallet::bitcoin::hashes::Hash;
    use std::str::FromStr;

    /// The abandon-seed testnet spend key, from the signer's own
    /// `sp_spend_vectors.h` (`SPV_LABEL_SPEND_PUB`). The same key appears as the
    /// 0x1f key data in its BIP-376 reference PSBT.
    const SPEND_PUB: [u8; 33] = [
        0x02, 0x83, 0x30, 0x85, 0xc9, 0xa7, 0x16, 0xd3, 0x6b, 0x46, 0x75, 0x52, 0xc0, 0x0d, 0x6a,
        0xa8, 0xbd, 0x42, 0xe3, 0x9a, 0xdb, 0xe9, 0x8b, 0x05, 0xbc, 0x20, 0x31, 0x10, 0x17, 0x71,
        0x92, 0xf7, 0x02,
    ];

    /// `SPV_SPEND_EVEN_TWEAK` / `SPV_SPEND_EVEN_OUTKEY`: a tweak whose sum with
    /// the spend key has even Y.
    const EVEN_TWEAK: [u8; 32] = [0x02; 32];
    const EVEN_OUTKEY: [u8; 32] = [
        0x83, 0x2e, 0xac, 0x66, 0xec, 0xbc, 0xfc, 0x00, 0x75, 0x8a, 0x69, 0xb1, 0x7f, 0x25, 0xd4,
        0x82, 0xe6, 0xc4, 0xff, 0x4a, 0x55, 0xb4, 0xac, 0xfc, 0x83, 0x1c, 0x15, 0x8f, 0x90, 0xe5,
        0x7a, 0x25,
    ];

    /// `SPV_SPEND_ODD_*`: the negation path, where the sum has odd Y.
    const ODD_TWEAK: [u8; 32] = [0x01; 32];
    const ODD_OUTKEY: [u8; 32] = [
        0xbd, 0x57, 0x9e, 0x15, 0x5b, 0x56, 0xad, 0xe0, 0xc4, 0x9b, 0xd6, 0xc6, 0x2a, 0xc7, 0xa1,
        0x20, 0x22, 0x4d, 0xba, 0xfc, 0x3e, 0xf9, 0x45, 0x05, 0x59, 0x63, 0xc4, 0xe2, 0x20, 0x16,
        0xd2, 0x8f,
    ];

    /// `SPV_SPEND_FOREIGN_TWEAK`: does not reproduce the even output key.
    const FOREIGN_TWEAK: [u8; 32] = [0x77; 32];

    /// The 0x1f value from the decoded reference PSBT: fingerprint 73c5da0a
    /// then m/352h/1h/0h/0h/0, one little-endian word each.
    const ORIGIN_VALUE: [u8; 24] = [
        0x73, 0xc5, 0xda, 0x0a, 0x60, 0x01, 0x00, 0x80, 0x01, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
        0x80, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00,
    ];

    fn spend() -> PublicKey {
        PublicKey::from_slice(&SPEND_PUB).unwrap()
    }

    fn stored(tweak: [u8; 32], outkey: [u8; 32], amount: u64) -> StoredOut {
        StoredOut {
            outpoint: OutPoint::new(Txid::from_byte_array([0xcd; 32]), 0),
            tweak: SecretKey::from_slice(&tweak).unwrap(),
            script_pubkey: p2tr_script(&XOnlyPublicKey::from_slice(&outkey).unwrap()),
            amount: Amount::from_sat(amount),
            label: None,
            height: 100,
        }
    }

    #[test]
    fn derives_the_output_key_the_signer_derives() {
        for (tweak, outkey) in [(EVEN_TWEAK, EVEN_OUTKEY), (ODD_TWEAK, ODD_OUTKEY)] {
            let derived = output_key(&spend(), &SecretKey::from_slice(&tweak).unwrap()).unwrap();
            assert_eq!(derived.serialize(), outkey);
        }
    }

    #[test]
    fn refuses_a_tweak_that_does_not_reproduce_the_script() {
        let coin = stored(FOREIGN_TWEAK, EVEN_OUTKEY, 100_000);
        let error = SpCoin::checked(&coin, &spend()).unwrap_err().to_string();
        assert!(error.contains("does not re-derive"), "{error}");
        assert!(error.contains("re-paired"), "{error}");
    }

    #[test]
    fn accepts_both_output_key_parities() {
        for (tweak, outkey) in [(EVEN_TWEAK, EVEN_OUTKEY), (ODD_TWEAK, ODD_OUTKEY)] {
            SpCoin::checked(&stored(tweak, outkey, 100_000), &spend()).unwrap();
        }
    }

    /// A labelled output is not a special case. `bdk_sp` folds the label into
    /// the tweak it stores, so `P = B_spend + tweak*G` still holds and the
    /// signer's own check needs no change. Refusing labels here would be a
    /// restriction the protocol does not have.
    #[test]
    fn a_labelled_output_spends_like_any_other() {
        let mut coin = stored(EVEN_TWEAK, EVEN_OUTKEY, 100_000);
        coin.label = Some(5);
        SpCoin::checked(&coin, &spend()).unwrap();
    }

    #[test]
    fn refuses_an_amount_over_the_money_supply() {
        let coin = stored(EVEN_TWEAK, EVEN_OUTKEY, MAX_MONEY_SATS + 1);
        let error = SpCoin::checked(&coin, &spend()).unwrap_err().to_string();
        assert!(error.contains("21M cap"), "{error}");
    }

    #[test]
    fn builds_the_key_origin_the_reference_psbt_carries() {
        let origin = spend_origin(Fingerprint::from_str("73c5da0a").unwrap());
        assert_eq!(origin_value(&origin), ORIGIN_VALUE);
    }

    /// The signer stops on any key-value pair it does not recognise, so the
    /// input it is handed is a whitelist. Absences are asserted because each of
    /// them fails silently rather than loudly: a BIP-32 derivation breaks
    /// signing outright, a sighash type changes the message signed, and a
    /// previous transaction only wastes the byte budget.
    #[test]
    fn writes_exactly_the_fields_the_signer_reads() {
        let coin = SpCoin::checked(&stored(EVEN_TWEAK, EVEN_OUTKEY, 100_000), &spend()).unwrap();
        let origin = spend_origin(Fingerprint::from_str("73c5da0a").unwrap());
        let input = psbt_input(&coin, &spend(), &origin);

        assert!(input.witness_utxo.is_some());
        assert!(input.non_witness_utxo.is_none());
        assert!(input.sighash_type.is_none());
        assert!(input.tap_internal_key.is_none());
        assert!(input.tap_merkle_root.is_none());
        assert!(input.bip32_derivation.is_empty());
        assert!(input.tap_key_origins.is_empty());
        assert!(input.partial_sigs.is_empty());
        assert!(input.proprietary.is_empty());

        let keys: Vec<(u8, usize, usize)> = input
            .unknown
            .iter()
            .map(|(key, value)| (key.type_value, key.key.len(), value.len()))
            .collect();
        // The signer measures the whole key including its type byte: 1 for the
        // tweak, 34 for the derivation.
        assert_eq!(
            keys,
            vec![
                (PSBT_IN_SP_SPEND_BIP32_DERIVATION, 33, 24),
                (PSBT_IN_SP_TWEAK, 0, 32),
            ]
        );
    }

    #[test]
    fn the_witness_utxo_is_the_taproot_script_the_signer_demands() {
        let coin = SpCoin::checked(&stored(EVEN_TWEAK, EVEN_OUTKEY, 100_000), &spend()).unwrap();
        let script = coin.txout().script_pubkey;
        assert_eq!(script.len(), 34);
        assert_eq!(script.as_bytes()[0], 0x51);
        assert_eq!(script.as_bytes()[1], 0x20);
    }

    fn coin(amount: u64) -> SpCoin {
        SpCoin::checked(&stored(EVEN_TWEAK, EVEN_OUTKEY, amount), &spend()).unwrap()
    }

    #[test]
    fn selects_only_as_many_coins_as_the_payment_needs() {
        let rate = FeeRate::from_sat_per_vb(2).unwrap();
        let chosen = select(
            vec![coin(60_000), coin(60_000), coin(60_000)],
            Amount::from_sat(50_000),
            rate,
            16,
        )
        .unwrap();
        assert_eq!(chosen.len(), 1);
    }

    #[test]
    fn accumulates_until_the_payment_and_its_fee_are_covered() {
        let rate = FeeRate::from_sat_per_vb(2).unwrap();
        let chosen = select(
            vec![coin(30_000), coin(30_000), coin(30_000)],
            Amount::from_sat(50_000),
            rate,
            16,
        )
        .unwrap();
        assert_eq!(chosen.len(), 2);
    }

    #[test]
    fn refuses_rather_than_reaching_for_ordinary_coins() {
        let rate = FeeRate::from_sat_per_vb(2).unwrap();
        let error = select(vec![coin(10_000)], Amount::from_sat(50_000), rate, 16)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("silent payment balance is 10000 sats"),
            "{error}"
        );
        assert!(error.contains("mixes silent payment inputs"), "{error}");
    }

    #[test]
    fn drops_coins_worth_less_than_they_cost_to_spend() {
        let rate = FeeRate::from_sat_per_vb(100).unwrap();
        let error = select(vec![coin(500)], Amount::from_sat(50_000), rate, 16)
            .unwrap_err()
            .to_string();
        assert!(error.contains("costs to spend"), "{error}");
    }

    #[test]
    fn stops_at_the_input_ceiling_rather_than_building_what_kiss_refuses() {
        let rate = FeeRate::from_sat_per_vb(2).unwrap();
        let coins: Vec<SpCoin> = (0..20).map(|_| coin(1_000)).collect();
        let error = select(coins, Amount::from_sat(50_000), rate, 16)
            .unwrap_err()
            .to_string();
        assert!(error.contains("16 spendable output(s)"), "{error}");
    }
}
