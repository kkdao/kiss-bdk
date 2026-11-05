//! A silent payment paid by two wallets together.
//!
//! Each wallet has its own airgapped signer, and neither signer holds every
//! input key, so the single "global" ECDH share the rest of this coordinator
//! uses cannot be made. BIP-375 already has the answer: one share and one
//! BIP-374 proof per input. The shares add up to the same point the global one
//! would have been, so the output script can be derived by anyone holding all
//! of them, without a private key.
//!
//! That turns the coordinator's job around. In a single signer payment it
//! checks a script the signer derived. Here it collects shares from two
//! signers that never meet, checks every one against the public key of the
//! coin it belongs to, and derives the script itself. A signer that used a
//! different key, or a share moved onto another input, fails its proof and is
//! named.
//!
//! Everything in this module is a plain function of its arguments: no files,
//! no network, no camera. `sharedflow` adds those.
//!
//! The steps, for wallet A (which starts) and wallet B (which joins):
//!
//! 1. A proposes: its coins, the recipient with the full amount, its change.
//! 2. B joins: adds its coins and its change. From here the transaction's
//!    inputs and outputs never change again.
//! 3. B's signer adds its shares. It cannot sign: A's shares are missing.
//! 4. A's signer adds its shares, which completes the set, and signs.
//! 5. B's signer checks the complete set and signs.
//! 6. Whoever holds every signature finalizes and broadcasts.
//!
//! The rule behind that order is general: it is a wallet's turn when the
//! newest state came from the other side and its own inputs are not signed.

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use bdk_wallet::bitcoin::absolute::LockTime;
use bdk_wallet::bitcoin::hashes::{Hash, sha256};
use bdk_wallet::bitcoin::secp256k1::{
    Message as SecpMessage, PublicKey as SecpPublicKey, Secp256k1,
};
use bdk_wallet::bitcoin::sighash::{EcdsaSighashType, Prevouts, SighashCache, TapSighashType};
use bdk_wallet::bitcoin::{
    Amount, CompressedPublicKey, OutPoint, Psbt, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Txid, Witness,
};
use psbt_v2::v2::{Input, Output, Psbt as PsbtV2};
use serde::{Deserialize, Serialize};

use crate::dleq;
use crate::sp::{self, SilentPaymentAddress, derive};
use crate::spsend::{self, SpOutput};

/// The message and session format this code speaks.
pub const VERSION: u32 = 1;

/// `PSBT_GLOBAL_TX_MODIFIABLE` with inputs and outputs both open, which is
/// what a proposal carries until the second wallet has joined.
const OPEN_TO_BOTH: u8 = 0x03;

/// The BIP-341 point nobody knows a private key for. A taproot output with
/// this internal key can only be spent through a script, so BIP-352 does not
/// count it, and no signer here could add a share for it.
const NUMS_KEY: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

/// The smallest amount a taproot output may carry and still be relayed.
const TAPROOT_DUST_SATS: u64 = 330;

/// What both halves of the transaction count when each is built on its own:
/// version, lock time, the two counts, the 43 byte silent payment output, and
/// the segwit marker and flag. Each wallet pays for half of it.
const SHARED_WEIGHT: u64 = (4 + 4 + 1 + 1 + 43) * 4 + 2;

/// A silent payment output script: `OP_1`, a push of 32, and the key.
const TAPROOT_SCRIPT_BYTES: u64 = 34;

/// Witness weight assumed when checking the fee: the item count, then a
/// signature of the usual 71 bytes and a 33 byte key for P2WPKH, or one
/// 64 byte signature for taproot. On the low side on purpose, so the check
/// never refuses a transaction whose halves were both built at the rate.
const P2WPKH_WITNESS_WEIGHT: u64 = 1 + 1 + 71 + 1 + 33;
const TAPROOT_WITNESS_WEIGHT: u64 = 1 + 1 + 64;

/// A fee this far above the agreed rate is a broken half, not generosity:
/// three times the expected fee plus room for two change outputs that were
/// too small to keep.
const FEE_CEILING_FACTOR: u64 = 3;
const FEE_CEILING_SLACK_SATS: u64 = 1_000;

// ---------------------------------------------------------------------------
// Messages

/// What a message is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// Wallet A's half, open for wallet B to join.
    Proposal,
    /// The sender's whole current state, signatures included.
    Update,
    /// The transaction was broadcast.
    Done,
}

/// One message between the two coordinators, as it travels in JSON.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Message {
    pub v: u32,
    /// 16 hex characters naming the shared send.
    pub session: String,
    pub kind: Kind,
    /// The sending wallet's master fingerprint, 8 hex characters.
    pub from: String,
    /// Base64 PSBTv2. Required on a proposal and an update.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub psbt: Option<String>,
    /// The recipient's silent payment address. Required on a proposal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    /// The full amount the recipient gets. Required on a proposal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sats: Option<u64>,
    /// Whole sat/vB. Required on a proposal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fee_rate: Option<u64>,
    /// Required on done.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub txid: Option<String>,
}

impl Message {
    /// Read one message, refusing anything that is not well formed.
    ///
    /// Nothing here says the message is honest. That is what the checks on
    /// its PSBT are for.
    pub fn parse(text: &str) -> Result<Self> {
        let mut message: Message =
            serde_json::from_str(text.trim()).context("this is not a shared send message")?;
        if message.v != VERSION {
            bail!(
                "this shared send message is version {}, and only version {VERSION} is understood",
                message.v
            );
        }
        message.session = hex_field("session", &message.session, 16)?;
        message.from = hex_field("from", &message.from, 8)?;
        let missing = |name: &str| anyhow!("a {:?} message needs {name}", message.kind);
        match message.kind {
            Kind::Proposal => {
                message.psbt.as_ref().ok_or_else(|| missing("psbt"))?;
                message.to.as_ref().ok_or_else(|| missing("to"))?;
                message.sats.ok_or_else(|| missing("sats"))?;
                message.fee_rate.ok_or_else(|| missing("fee_rate"))?;
            }
            Kind::Update => {
                message.psbt.as_ref().ok_or_else(|| missing("psbt"))?;
            }
            Kind::Done => {
                message.txid.as_ref().ok_or_else(|| missing("txid"))?;
            }
        }
        Ok(message)
    }

    /// The message as the one line of JSON that travels.
    pub fn encode(&self) -> String {
        serde_json::to_string(self).expect("a message is plain strings and numbers")
    }
}

fn hex_field(name: &str, value: &str, length: usize) -> Result<String> {
    if value.len() != length || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("the message's {name} must be {length} hex characters");
    }
    Ok(value.to_ascii_lowercase())
}

/// A session name: 16 hex characters derived from whatever the caller mixes
/// in. It only has to tell one shared send from another, not be secret.
pub fn session_id(seed: &[u8]) -> String {
    let digest = sha256::Hash::hash(seed).to_byte_array();
    digest[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

// ---------------------------------------------------------------------------
// PSBT plumbing

/// A PSBTv2 as the base64 a message or the session file carries.
pub fn encode(psbt: &PsbtV2) -> Result<String> {
    Ok(base64::engine::general_purpose::STANDARD.encode(spsend::serialize_v2(psbt)?))
}

/// The reverse of [`encode`].
pub fn decode(text: &str) -> Result<PsbtV2> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(text.trim())
        .context("the PSBT is not base64")?;
    parse(&bytes)
}

/// Read PSBTv2 bytes.
pub fn parse(bytes: &[u8]) -> Result<PsbtV2> {
    PsbtV2::deserialize(bytes).map_err(|error| anyhow!("this is not a valid PSBTv2: {error:?}"))
}

fn outpoint(input: &Input) -> OutPoint {
    OutPoint {
        txid: input.previous_txid,
        vout: input.spent_output_index,
    }
}

fn prevout(index: usize, input: &Input) -> Result<&TxOut> {
    input.witness_utxo.as_ref().with_context(|| {
        format!("input {index} has no witness UTXO; a shared send only takes P2WPKH and P2TR coins")
    })
}

/// The lock time a missing field stands for. BIP-370 reads it as zero.
fn fallback_lock_time(psbt: &PsbtV2) -> LockTime {
    psbt.global.fallback_lock_time.unwrap_or(LockTime::ZERO)
}

/// The sequence a missing field stands for. BIP-370 reads it as final.
fn sequence(input: &Input) -> Sequence {
    input.sequence.unwrap_or(Sequence::MAX)
}

// ---------------------------------------------------------------------------
// Section 2 of the contract: which key an input stands for

/// The public key BIP-352 counts for this input.
///
/// * P2WPKH: the compressed key whose HASH160 is the witness program. It is
///   read from `PSBT_IN_BIP32_DERIVATION`, and the hash is checked here,
///   because nothing else ties a key written in a PSBT to the coin.
/// * P2TR: the output key in the previous script, taken with even Y.
///
/// Anything else cannot take part in a shared send.
pub fn input_key(index: usize, input: &Input) -> Result<SecpPublicKey> {
    let script = &prevout(index, input)?.script_pubkey;
    if script.is_p2wpkh() {
        return input
            .bip32_derivations
            .keys()
            .filter(|key| key.compressed)
            .find(|key| {
                ScriptBuf::new_p2wpkh(&CompressedPublicKey(key.inner).wpubkey_hash()) == *script
            })
            .map(|key| key.inner)
            .with_context(|| {
                format!(
                    "input {index} has no BIP-32 derivation key whose hash is its witness program"
                )
            });
    }
    if script.is_p2tr() {
        if input
            .tap_internal_key
            .is_some_and(|key| key.serialize() == NUMS_KEY)
        {
            bail!(
                "input {index} is a taproot coin that can only be spent through a script; \
                 a shared send cannot use it"
            );
        }
        let mut even_y = [0x02_u8; 33];
        even_y[1..].copy_from_slice(&script.as_bytes()[2..]);
        return SecpPublicKey::from_slice(&even_y)
            .with_context(|| format!("input {index} pays a taproot key that is not on the curve"));
    }
    bail!("input {index} is neither P2WPKH nor P2TR; a shared send cannot use it")
}

/// Who signs for an input, for messages: the master fingerprint in its key
/// origin. It names the signer, it does not prove anything.
pub fn signer_of(input: &Input) -> String {
    let p2wpkh = input.witness_utxo.as_ref().and_then(|utxo| {
        input.bip32_derivations.iter().find(|(key, _)| {
            key.compressed
                && ScriptBuf::new_p2wpkh(&CompressedPublicKey(key.inner).wpubkey_hash())
                    == utxo.script_pubkey
        })
    });
    match p2wpkh {
        Some((_, (fingerprint, _))) => fingerprint.to_string(),
        None => input
            .tap_key_origins
            .values()
            .next()
            .map(|(_, (fingerprint, _))| fingerprint.to_string())
            .unwrap_or_else(|| "unknown".to_owned()),
    }
}

/// The previous transaction must hash to the outpoint, and the output it
/// created there must be the witness UTXO. Without this an amount is only a
/// claim: BIP-143 signs the amount of one input, not of all of them.
fn check_previous_transaction(index: usize, input: &Input) -> Result<()> {
    let utxo = prevout(index, input)?;
    let previous = input
        .non_witness_utxo
        .as_ref()
        .with_context(|| format!("input {index} does not carry its previous transaction"))?;
    if previous.compute_txid() != input.previous_txid {
        bail!("input {index}: the previous transaction does not hash to the coin being spent");
    }
    let spent = previous
        .output
        .get(input.spent_output_index as usize)
        .with_context(|| {
            format!(
                "input {index} spends output {} of a previous transaction that has {}",
                input.spent_output_index,
                previous.output.len()
            )
        })?;
    if spent != utxo {
        bail!("input {index}: the witness UTXO is not the output its previous transaction created");
    }
    Ok(())
}

/// Absent or SIGHASH_ALL. Every other type leaves part of the transaction
/// open, and the output script is only safe when all of it is signed.
fn check_sighash_type(index: usize, input: &Input) -> Result<()> {
    match input.sighash_type {
        None => Ok(()),
        Some(kind) if kind.to_u32() == EcdsaSighashType::All.to_u32() => Ok(()),
        Some(kind) => bail!(
            "input {index} asks for sighash type {}; a silent payment is only signed with ALL",
            kind.to_u32()
        ),
    }
}

/// Everything one input has to be before it is let into a shared send.
fn check_input(index: usize, input: &Input) -> Result<()> {
    input_key(index, input)?;
    check_previous_transaction(index, input)?;
    check_sighash_type(index, input)?;
    if input.sequence.is_none() {
        bail!(
            "input {index} has no sequence; a shared send needs it written out so that \
             every signer hashes the same transaction"
        );
    }
    Ok(())
}

/// A copy of somebody else's input holding only what this wallet checked.
///
/// Shares and signatures are left behind on purpose: they come in through
/// [`absorb`], which verifies each one first.
fn adopt_input(index: usize, input: &Input) -> Result<Input> {
    check_input(index, input)?;
    let mut clean = Input::new(&outpoint(input));
    clean.sequence = input.sequence;
    clean.min_time = input.min_time;
    clean.min_height = input.min_height;
    clean.witness_utxo = input.witness_utxo.clone();
    clean.non_witness_utxo = input.non_witness_utxo.clone();
    clean.bip32_derivations = input.bip32_derivations.clone();
    clean.tap_internal_key = input.tap_internal_key;
    clean.sighash_type = input.sighash_type;
    Ok(clean)
}

/// A copy of somebody else's ordinary output: the amount and the script.
fn adopt_output(index: usize, output: &Output) -> Result<Output> {
    if output.script_pubkey.is_empty() {
        bail!("output {index} has no script");
    }
    Ok(Output::new(TxOut {
        value: output.amount,
        script_pubkey: output.script_pubkey.clone(),
    }))
}

// ---------------------------------------------------------------------------
// Section 2 of the contract: shares, proofs and the script they give

/// A silent payment output and the two keys it names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Recipient {
    pub output: usize,
    pub scan: SecpPublicKey,
    pub spend: SecpPublicKey,
}

/// The outputs that carry `PSBT_OUT_SP_V0_INFO`, in output order.
pub fn recipients(psbt: &PsbtV2) -> Result<Vec<Recipient>> {
    let mut found = Vec::new();
    for (output, entry) in psbt.outputs.iter().enumerate() {
        let Some(info) = &entry.sp_v0_info else {
            continue;
        };
        if info.len() != 66 {
            bail!("output {output} names a silent payment recipient of the wrong length");
        }
        let scan = SecpPublicKey::from_slice(&info[..33])
            .with_context(|| format!("output {output} has an invalid silent payment scan key"))?;
        let spend = SecpPublicKey::from_slice(&info[33..])
            .with_context(|| format!("output {output} has an invalid silent payment spend key"))?;
        found.push(Recipient {
            output,
            scan,
            spend,
        });
    }
    Ok(found)
}

/// Which shares a PSBT holds, every one of them verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Shares {
    /// The distinct scan keys among the silent payment outputs.
    pub scan_keys: Vec<SecpPublicKey>,
    /// `(input, scan key)` for every share that passed its proof.
    pub verified: BTreeSet<(usize, SecpPublicKey)>,
    inputs: usize,
}

impl Shares {
    /// The `(input, scan key)` pairs that still have no share.
    pub fn missing(&self) -> Vec<(usize, SecpPublicKey)> {
        let mut missing = Vec::new();
        for scan in &self.scan_keys {
            for input in 0..self.inputs {
                if !self.verified.contains(&(input, *scan)) {
                    missing.push((input, *scan));
                }
            }
        }
        missing
    }

    /// Every input has a verified share for this scan key.
    pub fn complete_for(&self, scan: &SecpPublicKey) -> bool {
        (0..self.inputs).all(|input| self.verified.contains(&(input, *scan)))
    }

    /// Every input has a verified share for every scan key.
    pub fn complete(&self) -> bool {
        self.scan_keys.iter().all(|scan| self.complete_for(scan))
    }
}

/// Verify every per-input share in `psbt` against the key of its input.
///
/// A share is `a_i·B_scan` and its proof shows it was made with the private
/// key behind `A_i`, the key [`input_key`] returns. So a share made with any
/// other key fails here, and so does an honest share moved to another input.
/// A share and its proof come together or not at all.
pub fn check_shares(psbt: &PsbtV2) -> Result<Shares> {
    if !psbt.global.sp_ecdh_shares.is_empty() || !psbt.global.sp_dleq_proofs.is_empty() {
        bail!(
            "the PSBT carries a global ECDH share; a payment shared between signers \
             has one share per input and no global one"
        );
    }
    let mut scan_keys: Vec<SecpPublicKey> = Vec::new();
    for recipient in recipients(psbt)? {
        if !scan_keys.contains(&recipient.scan) {
            scan_keys.push(recipient.scan);
        }
    }

    let mut verified = BTreeSet::new();
    for (index, input) in psbt.inputs.iter().enumerate() {
        let key = input_key(index, input)?;
        let signer = signer_of(input);
        for (scan, share) in &input.sp_ecdh_shares {
            if !scan_keys.contains(&scan.0) {
                bail!("input {index} carries an ECDH share for a scan key no output pays");
            }
            let proof = input.sp_dleq_proofs.get(scan).with_context(|| {
                format!("input {index} (signer {signer}) has an ECDH share without its DLEQ proof")
            })?;
            dleq::verify(&key, &scan.0, &share.0, proof.as_bytes()).with_context(|| {
                format!(
                    "input {index} (signer {signer}): the ECDH share does not match its \
                     DLEQ proof for this input's key"
                )
            })?;
            verified.insert((index, scan.0));
        }
        if let Some(scan) = input
            .sp_dleq_proofs
            .keys()
            .find(|scan| !input.sp_ecdh_shares.contains_key(scan))
        {
            bail!(
                "input {index} (signer {signer}) has a DLEQ proof without its ECDH share \
                 for scan key {}",
                short_key(&scan.0)
            );
        }
    }
    Ok(Shares {
        scan_keys,
        verified,
        inputs: psbt.inputs.len(),
    })
}

/// Derive the script of every silent payment output whose shares are complete.
///
/// `C_sum`, the sum of the shares, stands where `a_sum·B_scan` stands in
/// BIP-352, so no private key is needed. Inside one scan key group BIP-375
/// fixes the order `k` counts in: by spend key, and for the same spend key by
/// output index. Two signers that disagreed on it would derive different
/// scripts from the same shares.
pub fn derive_scripts(psbt: &PsbtV2, shares: &Shares) -> Result<BTreeMap<usize, ScriptBuf>> {
    let mut scripts = BTreeMap::new();
    let recipients = recipients(psbt)?;
    let complete: Vec<SecpPublicKey> = shares
        .scan_keys
        .iter()
        .filter(|scan| shares.complete_for(scan))
        .copied()
        .collect();
    if complete.is_empty() {
        return Ok(scripts);
    }

    let keys: Vec<SecpPublicKey> = psbt
        .inputs
        .iter()
        .enumerate()
        .map(|(index, input)| input_key(index, input))
        .collect::<Result<_>>()?;
    let a_sum = sum(&keys).context("the input public keys add up to no point at all")?;
    let outpoints: Vec<OutPoint> = psbt.inputs.iter().map(outpoint).collect();
    let input_hash = derive::input_hash(&outpoints, &a_sum)?;

    for scan in complete {
        let parts: Vec<SecpPublicKey> = psbt
            .inputs
            .iter()
            .map(|input| input.sp_ecdh_shares[&CompressedPublicKey(scan)].0)
            .collect();
        let c_sum = sum(&parts).context("the ECDH shares add up to no point at all")?;

        let mut group: Vec<&Recipient> = recipients
            .iter()
            .filter(|recipient| recipient.scan == scan)
            .collect();
        // Stable, so recipients with one spend key stay in output order.
        group.sort_by_key(|recipient| recipient.spend.serialize());
        for (k, recipient) in group.iter().enumerate() {
            let script = derive::output_script(&c_sum, &recipient.spend, &input_hash, k as u32)?;
            scripts.insert(recipient.output, script);
        }
    }
    Ok(scripts)
}

/// Check a PSBT's silent payment fields against each other, using nothing
/// but the PSBT itself.
///
/// Every share must pass its proof for its own input's key. A silent payment
/// output may carry a script only when every input has a share for its scan
/// key, the script must be the one those shares derive, and by then the
/// transaction must be closed to changes. Shares that are still missing are
/// not an error here: the returned [`Shares`] says which.
pub fn audit(psbt: &PsbtV2) -> Result<Shares> {
    for (index, input) in psbt.inputs.iter().enumerate() {
        check_sighash_type(index, input)?;
    }
    let shares = check_shares(psbt)?;
    let derived = derive_scripts(psbt, &shares)?;
    for recipient in recipients(psbt)? {
        let output = recipient.output;
        let script = &psbt.outputs[output].script_pubkey;
        if script.is_empty() {
            continue;
        }
        match derived.get(&output) {
            Some(expected) if script == expected => {}
            Some(_) => bail!(
                "output {output} does not pay the silent payment address: its script is not \
                 the one the shares derive"
            ),
            None => {
                let (input, _) = shares
                    .missing()
                    .into_iter()
                    .find(|(_, scan)| *scan == recipient.scan)
                    .expect("an incomplete scan key has a missing share");
                bail!(
                    "output {output} has a script, but input {input} has no ECDH share for \
                     its scan key; a script cannot exist before every share does"
                );
            }
        }
        if psbt.global.tx_modifiable_flags != 0 {
            bail!(
                "output {output} has its silent payment script, but the transaction is still \
                 marked open to changes"
            );
        }
    }
    Ok(shares)
}

fn sum(points: &[SecpPublicKey]) -> Result<SecpPublicKey> {
    let borrowed: Vec<&SecpPublicKey> = points.iter().collect();
    SecpPublicKey::combine_keys(&borrowed).map_err(|error| anyhow!("{error}"))
}

fn short_key(key: &SecpPublicKey) -> String {
    let hex: String = key.serialize()[..5]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("{hex}...")
}

// ---------------------------------------------------------------------------
// Signatures

/// The transaction the signers sign, once every output script is known.
fn unsigned_transaction(psbt: &PsbtV2) -> Result<Transaction> {
    let lock_time = psbt
        .determine_lock_time()
        .map_err(|error| anyhow!("the inputs ask for lock times that cannot both hold: {error}"))?;
    let mut input = Vec::with_capacity(psbt.inputs.len());
    for (index, entry) in psbt.inputs.iter().enumerate() {
        input.push(TxIn {
            previous_output: outpoint(entry),
            script_sig: ScriptBuf::new(),
            sequence: entry
                .sequence
                .with_context(|| format!("input {index} has no sequence"))?,
            witness: Witness::new(),
        });
    }
    let mut output = Vec::with_capacity(psbt.outputs.len());
    for (index, entry) in psbt.outputs.iter().enumerate() {
        if entry.script_pubkey.is_empty() {
            bail!(
                "output {index} has no script yet: not every signer has added its share, \
                 so nothing can be signed or checked"
            );
        }
        output.push(TxOut {
            value: entry.amount,
            script_pubkey: entry.script_pubkey.clone(),
        });
    }
    Ok(Transaction {
        version: psbt.global.tx_version,
        lock_time,
        input,
        output,
    })
}

/// Check the signature an input carries against `tx`, the transaction this
/// coordinator rebuilt from its own state.
///
/// `Ok(false)` means the input is not signed. A signature that is present and
/// wrong is an error, never a quiet "not signed".
fn signature_verifies(psbt: &PsbtV2, tx: &Transaction, index: usize) -> Result<bool> {
    let input = &psbt.inputs[index];
    let utxo = prevout(index, input)?;
    let key = input_key(index, input)?;
    let secp = Secp256k1::verification_only();

    if utxo.script_pubkey.is_p2wpkh() {
        if input.tap_key_sig.is_some() {
            bail!("input {index} is P2WPKH but carries a taproot signature");
        }
        let mut signatures = input.partial_sigs.iter();
        let Some((public, signature)) = signatures.next() else {
            return Ok(false);
        };
        if signatures.next().is_some() {
            bail!("input {index} carries more than one signature; P2WPKH takes exactly one");
        }
        if !public.compressed || public.inner != key {
            bail!("input {index} is signed with a key that is not the one its coin pays");
        }
        if signature.sighash_type != EcdsaSighashType::All {
            bail!("input {index} is not signed with SIGHASH_ALL");
        }
        let hash = SighashCache::new(tx)
            .p2wpkh_signature_hash(
                index,
                &utxo.script_pubkey,
                utxo.value,
                EcdsaSighashType::All,
            )
            .with_context(|| format!("hashing the transaction for input {index}"))?;
        secp.verify_ecdsa(&SecpMessage::from(hash), &signature.signature, &key)
            .with_context(|| {
                format!("input {index}: the signature is not valid for this transaction")
            })?;
        return Ok(true);
    }

    if !input.partial_sigs.is_empty() {
        bail!("input {index} is taproot but carries an ECDSA signature");
    }
    let Some(signature) = input.tap_key_sig else {
        return Ok(false);
    };
    if !matches!(
        signature.sighash_type,
        TapSighashType::Default | TapSighashType::All
    ) {
        bail!("input {index} is not signed over the whole transaction");
    }
    let prevouts: Vec<TxOut> = psbt
        .inputs
        .iter()
        .enumerate()
        .map(|(other, entry)| prevout(other, entry).cloned())
        .collect::<Result<_>>()?;
    let hash = SighashCache::new(tx)
        .taproot_key_spend_signature_hash(index, &Prevouts::All(&prevouts), signature.sighash_type)
        .with_context(|| format!("hashing the transaction for input {index}"))?;
    let (x_only, _) = key.x_only_public_key();
    secp.verify_schnorr(&signature.signature, &SecpMessage::from(hash), &x_only)
        .with_context(|| {
            format!("input {index}: the signature is not valid for this transaction")
        })?;
    Ok(true)
}

fn carries_signature(input: &Input) -> bool {
    !input.partial_sigs.is_empty() || input.tap_key_sig.is_some()
}

/// Which inputs carry a signature. The state only ever holds verified ones.
pub fn signed_inputs(state: &PsbtV2) -> BTreeSet<usize> {
    state
        .inputs
        .iter()
        .enumerate()
        .filter(|(_, input)| carries_signature(input))
        .map(|(index, _)| index)
        .collect()
}

// ---------------------------------------------------------------------------
// Section 4 of the contract: what may change, and taking it in

/// Where a PSBT being taken in came from. It decides what it may add.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// This wallet's own signer: signatures on this wallet's inputs only.
    Signer,
    /// The other coordinator, relaying its signer's work.
    Peer,
}

impl Source {
    fn name(self) -> &'static str {
        match self {
            Source::Signer => "the signer",
            Source::Peer => "the other wallet",
        }
    }
}

/// Nothing that decides the transaction id or what is paid may differ.
///
/// The one exception is the script of a silent payment output, which appears
/// when the shares are complete. A different script where one is already
/// known is the redirect this whole check exists for.
fn same_skeleton(mine: &PsbtV2, theirs: &PsbtV2, who: &str) -> Result<()> {
    if mine.global.tx_version != theirs.global.tx_version {
        bail!("{who} returned a different transaction version");
    }
    if fallback_lock_time(mine) != fallback_lock_time(theirs) {
        bail!("{who} returned a different lock time");
    }
    if mine.inputs.len() != theirs.inputs.len() {
        bail!(
            "{who} returned {} inputs where there were {}",
            theirs.inputs.len(),
            mine.inputs.len()
        );
    }
    if mine.outputs.len() != theirs.outputs.len() {
        bail!(
            "{who} returned {} outputs where there were {}",
            theirs.outputs.len(),
            mine.outputs.len()
        );
    }
    for (index, (before, after)) in mine.inputs.iter().zip(&theirs.inputs).enumerate() {
        if outpoint(before) != outpoint(after) {
            bail!("{who} changed which coin input {index} spends");
        }
        if sequence(before) != sequence(after) {
            bail!("{who} changed the sequence of input {index}");
        }
        if before.min_time != after.min_time || before.min_height != after.min_height {
            bail!("{who} changed the lock time requirement of input {index}");
        }
    }
    for (index, (before, after)) in mine.outputs.iter().zip(&theirs.outputs).enumerate() {
        if before.amount != after.amount {
            bail!("{who} changed the amount of output {index}");
        }
        if before.sp_v0_info != after.sp_v0_info || before.sp_v0_label != after.sp_v0_label {
            bail!("{who} changed the silent payment recipient of output {index}");
        }
        if before.sp_v0_info.is_some() {
            if !before.script_pubkey.is_empty()
                && !after.script_pubkey.is_empty()
                && before.script_pubkey != after.script_pubkey
            {
                bail!(
                    "output {index} does not pay the silent payment address: {who} wrote a \
                     script that is not the one the shares derive"
                );
            }
        } else if before.script_pubkey != after.script_pubkey {
            bail!("{who} changed the script of output {index}");
        }
    }
    Ok(())
}

/// Take in what a signer or the other wallet sent, keeping only what passes.
///
/// `state` is this coordinator's own record. `incoming` may add shares with
/// their proofs, the script of a silent payment output, and signatures. Each
/// is checked against `state`, never against `incoming`'s own copy of the
/// facts, and nothing else in `incoming` is read at all. The returned lines
/// say what was checked, one per check.
pub fn absorb(
    state: &PsbtV2,
    incoming: &PsbtV2,
    source: Source,
    mine: &BTreeSet<usize>,
) -> Result<(PsbtV2, Vec<String>)> {
    let who = source.name();
    if !incoming.global.sp_ecdh_shares.is_empty() || !incoming.global.sp_dleq_proofs.is_empty() {
        bail!(
            "{who} returned a global ECDH share; a payment shared between signers has one \
             share per input and no global one"
        );
    }
    same_skeleton(state, incoming, who)?;
    if incoming.global.tx_modifiable_flags != 0 {
        bail!("{who} returned a transaction still marked open to changes");
    }
    let mut lines = vec![format!(
        "transaction unchanged: {} inputs, {} outputs",
        state.inputs.len(),
        state.outputs.len()
    )];
    let mut next = state.clone();

    // Shares first: whether a script may exist, and whether a signature can
    // be checked, both depend on them.
    let scan_keys: Vec<SecpPublicKey> = recipients(state)?.iter().map(|r| r.scan).collect();
    for (index, arrived) in incoming.inputs.iter().enumerate() {
        check_sighash_type(index, arrived)?;
        let key = input_key(index, &state.inputs[index])?;
        let signer = signer_of(&state.inputs[index]);
        for (scan, share) in &arrived.sp_ecdh_shares {
            if !scan_keys.contains(&scan.0) {
                bail!("{who} sent a share on input {index} for a scan key no output pays");
            }
            let proof = arrived.sp_dleq_proofs.get(scan).with_context(|| {
                format!("input {index} (signer {signer}): {who} sent an ECDH share without its DLEQ proof")
            })?;
            dleq::verify(&key, &scan.0, &share.0, proof.as_bytes()).with_context(|| {
                format!(
                    "input {index} (signer {signer}): the ECDH share {who} sent does not \
                     match its DLEQ proof for this input's key"
                )
            })?;
            lines.push(format!("input {index} share proof OK (signer {signer})"));
            // One key and one scan key give exactly one share, so a verified
            // share can only repeat what is already held. The first proof
            // kept is as good as any later one.
            if !next.inputs[index].sp_ecdh_shares.contains_key(scan) {
                next.inputs[index].sp_ecdh_shares.insert(*scan, *share);
                next.inputs[index].sp_dleq_proofs.insert(*scan, *proof);
            }
        }
        if arrived
            .sp_dleq_proofs
            .keys()
            .any(|scan| !arrived.sp_ecdh_shares.contains_key(scan))
        {
            bail!(
                "input {index} (signer {signer}): {who} sent a DLEQ proof without its ECDH share"
            );
        }
    }

    // The script, as soon as the shares allow it.
    let shares = check_shares(&next)?;
    let derived = derive_scripts(&next, &shares)?;
    for recipient in recipients(&next)? {
        let output = recipient.output;
        let sent = &incoming.outputs[output].script_pubkey;
        match derived.get(&output) {
            Some(script) => {
                if next.outputs[output].script_pubkey.is_empty() {
                    next.outputs[output].script_pubkey = script.clone();
                    lines.push(format!(
                        "output {output} script derived from {} shares",
                        next.inputs.len()
                    ));
                } else if next.outputs[output].script_pubkey != *script {
                    bail!("output {output} holds a script that is not the one the shares derive");
                }
                if !sent.is_empty() {
                    if sent != script {
                        bail!(
                            "output {output} does not pay the silent payment address: {who} \
                             wrote a script that is not the one the shares derive"
                        );
                    }
                    lines.push(format!("output {output} script from {who} matches"));
                }
            }
            None if !sent.is_empty() => {
                let (input, _) = shares
                    .missing()
                    .into_iter()
                    .find(|(_, scan)| *scan == recipient.scan)
                    .expect("an incomplete scan key has a missing share");
                bail!(
                    "{who} wrote a script for output {output}, but input {input} has no \
                     ECDH share yet; a script cannot exist before every share does"
                );
            }
            None => {}
        }
    }

    // Signatures last, against the transaction rebuilt from `next`.
    let signed: Vec<usize> = incoming
        .inputs
        .iter()
        .enumerate()
        .filter(|(_, arrived)| carries_signature(arrived))
        .map(|(index, _)| index)
        .collect();
    if !signed.is_empty() {
        let tx = unsigned_transaction(&next).with_context(|| {
            format!(
                "{who} sent a signature for input {}, which cannot be checked",
                signed[0]
            )
        })?;
        for index in signed {
            if source == Source::Signer && !mine.contains(&index) {
                bail!(
                    "the signer returned a signature for input {index}, which is not this \
                     wallet's coin"
                );
            }
            // Checked on a copy holding only what arrived, so a bad signature
            // can never ride in beside a good one already held.
            let mut probe = next.clone();
            probe.inputs[index].partial_sigs = incoming.inputs[index].partial_sigs.clone();
            probe.inputs[index].tap_key_sig = incoming.inputs[index].tap_key_sig;
            signature_verifies(&probe, &tx, index)?;
            lines.push(format!("input {index} signature OK"));
            if !carries_signature(&next.inputs[index]) {
                next.inputs[index].partial_sigs = probe.inputs[index].partial_sigs.clone();
                next.inputs[index].tap_key_sig = probe.inputs[index].tap_key_sig;
            }
        }
    }
    Ok((next, lines))
}

// ---------------------------------------------------------------------------
// Section 4 of the contract: building the transaction

/// What a wallet pays towards the recipient: half each, and the odd satoshi
/// from the wallet that started.
pub fn share_of(sats: u64, role: Role) -> u64 {
    match role {
        Role::Start => sats / 2 + sats % 2,
        Role::Join => sats / 2,
    }
}

/// Refuse an amount that cannot be split into two outputs BDK will build.
pub fn check_amount(sats: u64) -> Result<()> {
    if sats / 2 < TAPROOT_DUST_SATS {
        bail!(
            "{sats} sats is too little to pay from two wallets: each half must be at \
             least {TAPROOT_DUST_SATS} sats"
        );
    }
    Ok(())
}

/// Turn the half BDK built into PSBTv2 inputs and a change output.
///
/// `half` is an ordinary BDK transaction that pays this wallet's share to the
/// recipient's placeholder script at the agreed fee rate. Built on its own it
/// pays for all of the bytes both halves have in common, so half of that fee
/// goes back into the change. Returns the PSBT and the placeholder's index.
fn half_as_v2(
    half: &Psbt,
    recipient: &SilentPaymentAddress,
    share: u64,
    fee_rate: u64,
) -> Result<(PsbtV2, usize)> {
    if spsend::placeholder_count(half, recipient) != 1 {
        bail!("a wallet's half must pay the recipient exactly once");
    }
    let index = spsend::placeholder_index(half, recipient)?;
    let outputs = &half.unsigned_tx.output;
    if outputs[index].value != Amount::from_sat(share) {
        bail!(
            "this wallet's half pays the recipient {} sats, not its share of {share}",
            outputs[index].value.to_sat()
        );
    }
    if outputs.len() > 2 {
        bail!("a wallet's half has the payment and at most one change output");
    }
    let bytes = spsend::build_v2(
        half,
        &[SpOutput {
            index,
            recipient: *recipient,
        }],
    )?;
    let mut psbt = parse(&bytes)?;
    for (input_index, input) in psbt.inputs.iter().enumerate() {
        check_input(input_index, input)
            .context("this wallet's own coin cannot go into a shared send")?;
    }

    let spent: u64 = psbt
        .inputs
        .iter()
        .filter_map(|input| input.witness_utxo.as_ref())
        .map(|utxo| utxo.value.to_sat())
        .sum();
    let paid: u64 = outputs.iter().map(|output| output.value.to_sat()).sum();
    let fee = spent
        .checked_sub(paid)
        .context("this wallet's half pays out more than it spends")?;
    let refund = fee_rate * SHARED_WEIGHT / 8;
    if let Some(change) = (0..outputs.len()).find(|other| *other != index)
        && refund < fee
    {
        psbt.outputs[change].amount += Amount::from_sat(refund);
    }
    Ok((psbt, index))
}

/// Wallet A's half as a proposal: its coins, the recipient with the FULL
/// amount, its change, and both modifiable flags set so wallet B may join.
///
/// It does not balance, and is not meant to. It is never shown to a signer.
pub fn propose(
    half: &Psbt,
    recipient: &SilentPaymentAddress,
    sats: u64,
    fee_rate: u64,
) -> Result<PsbtV2> {
    check_terms(recipient, sats, fee_rate)?;
    let (mut psbt, index) = half_as_v2(half, recipient, share_of(sats, Role::Start), fee_rate)?;
    psbt.outputs[index].amount = Amount::from_sat(sats);
    psbt.global.tx_modifiable_flags = OPEN_TO_BOTH;
    Ok(psbt)
}

fn check_terms(recipient: &SilentPaymentAddress, sats: u64, fee_rate: u64) -> Result<()> {
    if recipient.mainnet {
        bail!("that is a mainnet silent payment address; this coordinator is for test networks");
    }
    if fee_rate == 0 {
        bail!("the fee rate must be at least 1 sat/vB");
    }
    check_amount(sats)
}

/// A proposal that passed every check wallet B makes before adding coins.
#[derive(Clone, Debug)]
pub struct Proposal {
    pub session: String,
    /// Wallet A's fingerprint.
    pub from: String,
    /// The recipient exactly as wallet A wrote it.
    pub to: String,
    pub recipient: SilentPaymentAddress,
    pub sats: u64,
    pub fee_rate: u64,
    /// Wallet A's half, reduced to what was checked.
    pub psbt: PsbtV2,
}

/// Check wallet A's proposal on behalf of wallet `me`.
///
/// The message says who is paid and how much; the PSBT has to say the same.
/// Every coin in it must prove its amount with its previous transaction.
pub fn read_proposal(message: &Message, me: &str) -> Result<Proposal> {
    if message.kind != Kind::Proposal {
        bail!("that message is not a proposal");
    }
    if message.from == me {
        bail!(
            "that proposal came from this same wallet; a shared send needs two wallets \
             with different seeds"
        );
    }
    let to = message.to.clone().context("a proposal needs to")?;
    let sats = message.sats.context("a proposal needs sats")?;
    let fee_rate = message.fee_rate.context("a proposal needs fee_rate")?;
    let recipient = sp::decode(&to).context("the proposal's recipient")?;
    check_terms(&recipient, sats, fee_rate)?;

    let theirs = decode(message.psbt.as_deref().context("a proposal needs psbt")?)?;
    if !theirs.global.sp_ecdh_shares.is_empty() || !theirs.global.sp_dleq_proofs.is_empty() {
        bail!("the proposal carries a global ECDH share, which a shared send never uses");
    }
    if theirs.global.tx_modifiable_flags & OPEN_TO_BOTH != OPEN_TO_BOTH {
        bail!("the proposal is not open for another wallet's coins and change");
    }
    if theirs.inputs.is_empty() {
        bail!("the proposal spends no coins");
    }

    let mut psbt = theirs.clone();
    psbt.global.xpubs.clear();
    psbt.global.proprietaries.clear();
    psbt.global.unknowns.clear();
    psbt.inputs.clear();
    psbt.outputs.clear();
    for (index, input) in theirs.inputs.iter().enumerate() {
        psbt.inputs
            .push(adopt_input(index, input).context("the proposal")?);
    }
    let mut paid = 0;
    for (index, output) in theirs.outputs.iter().enumerate() {
        if output.sp_v0_info.is_none() {
            psbt.outputs
                .push(adopt_output(index, output).context("the proposal")?);
            continue;
        }
        paid += 1;
        if output.sp_v0_info.as_deref() != Some(&recipient.sp_v0_info()[..])
            || output.sp_v0_label.is_some()
        {
            bail!("output {index} of the proposal does not pay the recipient it names");
        }
        if output.amount != Amount::from_sat(sats) {
            bail!(
                "output {index} of the proposal pays {} sats, not the {sats} it names",
                output.amount.to_sat()
            );
        }
        if !output.script_pubkey.is_empty() {
            bail!(
                "output {index} of the proposal already has a script, before any signer \
                 has added a share"
            );
        }
        let mut clean = Output::new(TxOut {
            value: output.amount,
            script_pubkey: ScriptBuf::new(),
        });
        clean.sp_v0_info = output.sp_v0_info.clone();
        psbt.outputs.push(clean);
    }
    if paid != 1 {
        bail!("the proposal must pay the recipient exactly once, not {paid} times");
    }
    no_coin_twice(&psbt)?;

    Ok(Proposal {
        session: message.session.clone(),
        from: message.from.clone(),
        to,
        recipient,
        sats,
        fee_rate,
        psbt,
    })
}

fn no_coin_twice(psbt: &PsbtV2) -> Result<()> {
    let mut seen = BTreeSet::new();
    for input in &psbt.inputs {
        if !seen.insert(outpoint(input)) {
            bail!("the coin {} is spent twice", outpoint(input));
        }
    }
    Ok(())
}

fn set_counts(psbt: &mut PsbtV2) {
    psbt.global.input_count = psbt.inputs.len();
    psbt.global.output_count = psbt.outputs.len();
}

/// Wallet B adds its half to a checked proposal.
///
/// `half` is B's own BDK transaction paying its share to the recipient's
/// placeholder. B's coins go after A's and B's change goes last, so A finds
/// its own half exactly where it left it. The result has both modifiable
/// flags cleared: from here on the transaction is fixed.
pub fn join(proposal: &Proposal, half: &Psbt) -> Result<PsbtV2> {
    let (mine, placeholder) = half_as_v2(
        half,
        &proposal.recipient,
        share_of(proposal.sats, Role::Join),
        proposal.fee_rate,
    )?;
    let mut joined = proposal.psbt.clone();
    for input in &mine.inputs {
        joined.inputs.push(input.clone());
    }
    for (index, output) in mine.outputs.iter().enumerate() {
        if index != placeholder {
            joined.outputs.push(output.clone());
        }
    }
    joined.global.tx_modifiable_flags = 0;
    set_counts(&mut joined);
    no_coin_twice(&joined).context(
        "the proposal spends a coin of this wallet; a shared send needs two different wallets",
    )?;
    check_fee(&joined, proposal.fee_rate)
        .context("the two halves together do not pay the agreed fee")?;
    Ok(joined)
}

/// Wallet A checks what wallet B made of its proposal.
///
/// A's own coins and change must be exactly as proposed, the recipient and
/// the amount as agreed, and every coin B added must prove its amount. The
/// result is A's new state: B's order, A's own copy of everything that is
/// A's, and of B's coins only what was checked. Shares and signatures in
/// `joined` are not taken here; [`absorb`] does that next.
pub fn adopt_join(proposal: &PsbtV2, joined: &PsbtV2, fee_rate: u64) -> Result<PsbtV2> {
    let who = Source::Peer.name();
    if !joined.global.sp_ecdh_shares.is_empty() || !joined.global.sp_dleq_proofs.is_empty() {
        bail!("{who} sent a global ECDH share, which a shared send never uses");
    }
    if joined.global.tx_version != proposal.global.tx_version {
        bail!("{who} changed the transaction version");
    }
    if fallback_lock_time(joined) != fallback_lock_time(proposal) {
        bail!("{who} changed the lock time");
    }
    if joined.global.tx_modifiable_flags != 0 {
        bail!("{who} left the transaction open to further changes");
    }
    no_coin_twice(joined)?;

    let mut state = proposal.clone();
    state.inputs.clear();
    state.outputs.clear();
    state.global.tx_modifiable_flags = 0;

    let mut found = 0;
    for (index, theirs) in joined.inputs.iter().enumerate() {
        match proposal
            .inputs
            .iter()
            .find(|own| outpoint(own) == outpoint(theirs))
        {
            Some(own) => {
                if sequence(own) != sequence(theirs)
                    || own.min_time != theirs.min_time
                    || own.min_height != theirs.min_height
                {
                    bail!("{who} changed how this wallet's coin in input {index} is spent");
                }
                found += 1;
                state.inputs.push(own.clone());
            }
            None => state
                .inputs
                .push(adopt_input(index, theirs).with_context(|| format!("a coin {who} added"))?),
        }
    }
    if found != proposal.inputs.len() {
        bail!("{who} dropped one of this wallet's coins from the transaction");
    }
    if joined.inputs.len() == found {
        bail!("{who} added no coins of its own");
    }

    let mut unclaimed: Vec<&Output> = proposal.outputs.iter().collect();
    for (index, theirs) in joined.outputs.iter().enumerate() {
        let own = unclaimed.iter().position(|own| {
            own.amount == theirs.amount
                && own.sp_v0_info == theirs.sp_v0_info
                && own.sp_v0_label == theirs.sp_v0_label
                && (own.sp_v0_info.is_some() || own.script_pubkey == theirs.script_pubkey)
        });
        match own {
            Some(position) => state.outputs.push(unclaimed.remove(position).clone()),
            None if theirs.sp_v0_info.is_some() => bail!(
                "output {index} pays a silent payment recipient or amount that was not agreed"
            ),
            None => state.outputs.push(adopt_output(index, theirs)?),
        }
    }
    if let Some(lost) = unclaimed.first() {
        if lost.sp_v0_info.is_some() {
            bail!("{who} changed the recipient or the amount of the payment");
        }
        bail!("{who} changed or removed this wallet's change output");
    }

    set_counts(&mut state);
    check_fee(&state, fee_rate).with_context(|| format!("the half {who} added"))?;
    Ok(state)
}

/// The weight the signed transaction will have, estimated on the low side.
pub fn estimated_weight(psbt: &PsbtV2) -> Result<u64> {
    let mut base = 4 + 4 + compact_size(psbt.inputs.len()) + compact_size(psbt.outputs.len());
    let mut witness = 2;
    for (index, input) in psbt.inputs.iter().enumerate() {
        base += 36 + 4 + 1;
        witness += if prevout(index, input)?.script_pubkey.is_p2tr() {
            TAPROOT_WITNESS_WEIGHT
        } else {
            P2WPKH_WITNESS_WEIGHT
        };
    }
    for output in &psbt.outputs {
        let script = if output.sp_v0_info.is_some() {
            TAPROOT_SCRIPT_BYTES
        } else {
            output.script_pubkey.len() as u64
        };
        base += 8 + compact_size(script as usize) + script;
    }
    Ok(base * 4 + witness)
}

fn compact_size(value: usize) -> u64 {
    match value {
        0..=0xfc => 1,
        0xfd..=0xffff => 3,
        _ => 5,
    }
}

/// What the transaction pays in fees: the inputs minus the outputs.
pub fn fee(psbt: &PsbtV2) -> Result<Amount> {
    let mut spent = Amount::ZERO;
    for (index, input) in psbt.inputs.iter().enumerate() {
        spent = spent
            .checked_add(prevout(index, input)?.value)
            .context("the input amounts overflow")?;
    }
    let mut paid = Amount::ZERO;
    for output in &psbt.outputs {
        paid = paid
            .checked_add(output.amount)
            .context("the output amounts overflow")?;
    }
    spent
        .checked_sub(paid)
        .context("the outputs add up to more than the inputs")
}

/// The whole transaction must pay at least the agreed rate, and not wildly
/// more. Each wallet fixes its own contribution, so a short fee means the
/// other half is short, and this is the only place that shows.
pub fn check_fee(psbt: &PsbtV2, fee_rate: u64) -> Result<Amount> {
    let fee = fee(psbt)?;
    let weight = estimated_weight(psbt)?;
    let wanted = (fee_rate * weight).div_ceil(4);
    if fee.to_sat() < wanted {
        bail!(
            "the transaction pays {} sats in fees, less than the {wanted} that {fee_rate} \
             sat/vB needs",
            fee.to_sat()
        );
    }
    if fee.to_sat() > wanted * FEE_CEILING_FACTOR + FEE_CEILING_SLACK_SATS {
        bail!(
            "the transaction pays {} sats in fees, far above the {wanted} that {fee_rate} \
             sat/vB needs",
            fee.to_sat()
        );
    }
    Ok(fee)
}

// ---------------------------------------------------------------------------
// Talking to the signer, and finishing

/// What the next visit to the signer will be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pass {
    /// The other wallet's shares are not all here, so the signer can only add
    /// its own share. Nothing is signed.
    ShareOnly,
    /// Every other share is here: the signer adds its own, derives the script,
    /// shows the payment for review and signs.
    Sign,
}

/// The PSBT for this wallet's signer: the whole current state, without any
/// signature of the other wallet's signer.
pub fn signer_request(state: &PsbtV2, mine: &BTreeSet<usize>) -> Result<Vec<u8>> {
    let mut request = state.clone();
    request.global.tx_modifiable_flags = 0;
    for (index, input) in request.inputs.iter_mut().enumerate() {
        if !mine.contains(&index) {
            input.partial_sigs.clear();
            input.tap_key_sig = None;
        }
    }
    spsend::serialize_v2(&request)
}

/// Check everything once more, from nothing, and build the transaction.
///
/// The state was checked piece by piece as it arrived. This does not rely on
/// that: the session lives in a file, and a file can be edited. Every coin
/// proves its amount, every share its key, the script is derived again, and
/// every signature is verified against the transaction about to be sent.
pub fn finalize(state: &PsbtV2) -> Result<Transaction> {
    if state.global.tx_modifiable_flags != 0 {
        bail!("the transaction is still marked open to changes");
    }
    for (index, input) in state.inputs.iter().enumerate() {
        check_input(index, input)?;
    }
    let shares = audit(state)?;
    if let Some((input, scan)) = shares.missing().first() {
        bail!(
            "input {input} (signer {}) has no ECDH share for scan key {}; the payment \
             cannot be finished without it",
            signer_of(&state.inputs[*input]),
            short_key(scan)
        );
    }
    fee(state)?;

    let mut tx = unsigned_transaction(state)?;
    let unsigned = tx.clone();
    for (index, input) in state.inputs.iter().enumerate() {
        if !signature_verifies(state, &unsigned, index)? {
            bail!(
                "input {index} (signer {}) is not signed yet",
                signer_of(input)
            );
        }
        tx.input[index].witness = match input.tap_key_sig {
            Some(signature) => Witness::p2tr_key_spend(&signature),
            None => {
                let (public, signature) = input
                    .partial_sigs
                    .iter()
                    .next()
                    .expect("a verified P2WPKH input has its signature");
                Witness::p2wpkh(signature, &public.inner)
            }
        };
    }
    Ok(tx)
}

// ---------------------------------------------------------------------------
// The session: one wallet's record of one shared send

/// Which side of the shared send this wallet is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Wallet A: proposed the payment.
    Start,
    /// Wallet B: joined it.
    Join,
}

/// How far the shared send has come.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Stage {
    /// Proposed, and waiting for the other wallet to join.
    Proposed,
    /// Joined: the transaction is fixed and the signers take turns.
    Active,
    /// Broadcast, by either side.
    Done,
}

/// Where the newest state came from, which decides whose turn it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Newest {
    /// This wallet made it: proposed, or absorbed its own signer's answer.
    Mine,
    /// The other wallet sent it.
    Theirs,
    /// This wallet just joined, so its signer goes first.
    Joined,
}

/// What became of a message from the other wallet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Received {
    /// Not applied, and harmless: another session, a duplicate, an older state.
    Ignored(String),
    /// Applied. One line per check that passed.
    Applied(Vec<String>),
    /// The other wallet broadcast the transaction with this id.
    Done(String),
}

/// One wallet's record of one shared send. It is what the session file holds,
/// so everything a stopped command needs to carry on is in here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    pub v: u32,
    pub session: String,
    pub role: Role,
    /// This wallet's master fingerprint.
    pub me: String,
    /// The other wallet's, once it is known.
    pub peer: Option<String>,
    /// The recipient's silent payment address.
    pub to: String,
    /// The full amount the recipient gets.
    pub sats: u64,
    pub fee_rate: u64,
    pub stage: Stage,
    pub newest: Newest,
    /// The current state: a base64 PSBTv2 holding every verified share, the
    /// script once derived, and every verified signature of both signers.
    pub psbt: String,
    /// This wallet's own coins, as `txid:vout`.
    pub mine: Vec<String>,
    /// How many answers this wallet's signer has given.
    pub visits: u32,
    /// Messages for the other wallet that are not known to have been sent.
    pub outbox: Vec<String>,
    /// Set once the transaction is broadcast.
    pub txid: Option<String>,
}

impl Session {
    /// Wallet A starts a shared send from the half BDK built for it.
    ///
    /// The proposal message is left in the outbox.
    pub fn propose(
        me: &str,
        session: &str,
        half: &Psbt,
        to: &str,
        sats: u64,
        fee_rate: u64,
    ) -> Result<Self> {
        let recipient = sp::decode(to)?;
        let psbt = propose(half, &recipient, sats, fee_rate)?;
        let mut created = Session {
            v: VERSION,
            session: hex_field("session", session, 16)?,
            role: Role::Start,
            me: hex_field("fingerprint", me, 8)?,
            peer: None,
            to: to.trim().to_owned(),
            sats,
            fee_rate,
            stage: Stage::Proposed,
            newest: Newest::Mine,
            psbt: encode(&psbt)?,
            mine: psbt
                .inputs
                .iter()
                .map(|input| outpoint(input).to_string())
                .collect(),
            visits: 0,
            outbox: Vec::new(),
            txid: None,
        };
        let proposal = created.proposal_message()?;
        created.outbox.push(proposal.encode());
        Ok(created)
    }

    /// Wallet B joins a checked proposal with the half BDK built for it.
    ///
    /// Nothing is sent yet: B's signer adds its share first, and the update
    /// after that visit is what tells wallet A that B joined.
    pub fn join(me: &str, proposal: &Proposal, half: &Psbt) -> Result<Self> {
        let joined = join(proposal, half)?;
        let theirs: BTreeSet<OutPoint> = proposal.psbt.inputs.iter().map(outpoint).collect();
        Ok(Session {
            v: VERSION,
            session: proposal.session.clone(),
            role: Role::Join,
            me: hex_field("fingerprint", me, 8)?,
            peer: Some(proposal.from.clone()),
            to: proposal.to.clone(),
            sats: proposal.sats,
            fee_rate: proposal.fee_rate,
            stage: Stage::Active,
            newest: Newest::Joined,
            psbt: encode(&joined)?,
            mine: joined
                .inputs
                .iter()
                .map(outpoint)
                .filter(|coin| !theirs.contains(coin))
                .map(|coin| coin.to_string())
                .collect(),
            visits: 0,
            outbox: Vec::new(),
            txid: None,
        })
    }

    /// The current state as a PSBT.
    pub fn state(&self) -> Result<PsbtV2> {
        decode(&self.psbt).context("the session's own PSBT")
    }

    /// The positions of this wallet's coins in `state`.
    fn my_inputs(&self, state: &PsbtV2) -> Result<BTreeSet<usize>> {
        let mut indices = BTreeSet::new();
        for coin in &self.mine {
            let coin = OutPoint::from_str(coin)
                .with_context(|| format!("the session lists {coin:?} as a coin"))?;
            let index = state
                .inputs
                .iter()
                .position(|input| outpoint(input) == coin)
                .with_context(|| format!("this wallet's coin {coin} is not in the transaction"))?;
            indices.insert(index);
        }
        Ok(indices)
    }

    /// Whether this wallet's signer is the one to visit now: the newest state
    /// came from the other side, or this wallet just joined, and this wallet's
    /// own coins are not all signed.
    pub fn my_turn(&self) -> Result<bool> {
        if self.stage != Stage::Active || self.newest == Newest::Mine {
            return Ok(false);
        }
        let state = self.state()?;
        let signed = signed_inputs(&state);
        Ok(!self.my_inputs(&state)?.is_subset(&signed))
    }

    /// Whether every input is signed and the transaction can be finished.
    pub fn ready(&self) -> Result<bool> {
        if self.stage != Stage::Active {
            return Ok(false);
        }
        let state = self.state()?;
        Ok(signed_inputs(&state).len() == state.inputs.len())
    }

    /// What this wallet's signer will be asked to do on its next visit.
    pub fn pass(&self) -> Result<Pass> {
        let state = self.state()?;
        let mine = self.my_inputs(&state)?;
        let waiting = check_shares(&state)?
            .missing()
            .into_iter()
            .any(|(input, _)| !mine.contains(&input));
        Ok(if waiting { Pass::ShareOnly } else { Pass::Sign })
    }

    /// The PSBT to show this wallet's signer.
    pub fn request(&self) -> Result<Vec<u8>> {
        match self.stage {
            Stage::Proposed => bail!(
                "the other wallet has not joined yet; a proposal is only half a \
                 transaction and is never shown to a signer"
            ),
            Stage::Done => bail!("this shared send is already broadcast"),
            Stage::Active => {}
        }
        if !self.my_turn()? {
            bail!("it is not this wallet's signer's turn; the other wallet goes next");
        }
        let state = self.state()?;
        signer_request(&state, &self.my_inputs(&state)?)
    }

    /// Take in this wallet's signer's answer. Returns one line per check, and
    /// leaves the update for the other wallet in the outbox.
    pub fn respond(&mut self, answer: &[u8]) -> Result<Vec<String>> {
        if !self.my_turn()? {
            bail!("no answer from this wallet's signer is expected right now");
        }
        let state = self.state()?;
        let mine = self.my_inputs(&state)?;
        let answer = parse(answer).context("the signer's answer")?;
        let (next, lines) = absorb(&state, &answer, Source::Signer, &mine)?;
        if next == state {
            bail!(
                "the signer's answer adds nothing: no new share and no signature. \
                 Show the signer the current request and scan its new answer"
            );
        }
        self.psbt = encode(&next)?;
        self.newest = Newest::Mine;
        self.visits += 1;
        let update = self.update_message()?;
        self.outbox.push(update.encode());
        Ok(lines)
    }

    /// Apply a message from the other wallet, if it passes every check.
    ///
    /// An error means the message was for this shared send and was refused;
    /// the session is left exactly as it was.
    pub fn receive(&mut self, message: &Message) -> Result<Received> {
        let mut trial = self.clone();
        let outcome = trial.apply(message)?;
        *self = trial;
        Ok(outcome)
    }

    fn apply(&mut self, message: &Message) -> Result<Received> {
        if message.session != self.session {
            return Ok(Received::Ignored("it is for another shared send".into()));
        }
        if message.from == self.me {
            return Ok(Received::Ignored("it is this wallet's own message".into()));
        }
        if self.peer.as_ref().is_some_and(|peer| *peer != message.from) {
            return Ok(Received::Ignored(format!(
                "it is from {}, which is not the wallet in this shared send",
                message.from
            )));
        }
        match message.kind {
            Kind::Proposal => Ok(Received::Ignored(
                "this wallet is already part of that shared send".into(),
            )),
            Kind::Update => self.receive_update(message),
            Kind::Done => self.receive_done(message),
        }
    }

    fn receive_update(&mut self, message: &Message) -> Result<Received> {
        if self.stage == Stage::Done {
            return Ok(Received::Ignored(
                "this shared send is already broadcast".into(),
            ));
        }
        let incoming = decode(message.psbt.as_deref().context("an update needs psbt")?)
            .context("the other wallet's update")?;
        let mut state = self.state()?;
        let mut lines = Vec::new();
        if self.stage == Stage::Proposed {
            state = adopt_join(&state, &incoming, self.fee_rate)?;
            lines.push(format!(
                "the other wallet ({}) joined: {} inputs, {} outputs, fee {} sats",
                message.from,
                state.inputs.len(),
                state.outputs.len(),
                fee(&state)?.to_sat()
            ));
        }
        let before = state.clone();
        let mine = self.my_inputs(&state)?;
        let (next, checks) = absorb(&state, &incoming, Source::Peer, &mine)?;
        if self.stage == Stage::Active && next == before {
            return Ok(Received::Ignored(
                "it holds nothing new: a duplicate or an older state".into(),
            ));
        }
        lines.extend(checks);
        self.psbt = encode(&next)?;
        self.stage = Stage::Active;
        self.newest = Newest::Theirs;
        self.peer = Some(message.from.clone());
        Ok(Received::Applied(lines))
    }

    fn receive_done(&mut self, message: &Message) -> Result<Received> {
        let reported = message.txid.as_deref().context("done needs txid")?;
        let reported = Txid::from_str(reported).context("done names an invalid txid")?;
        if self.stage == Stage::Done {
            if self.txid.as_deref() == Some(reported.to_string().as_str()) {
                return Ok(Received::Ignored("it is already recorded".into()));
            }
            bail!(
                "the other wallet reports transaction {reported}, but this shared send \
                 was broadcast as {}",
                self.txid.as_deref().unwrap_or("another one")
            );
        }
        if self.stage == Stage::Proposed {
            bail!("the other wallet reports a broadcast before it ever joined");
        }
        // The last state may travel with the news. Take it in the usual way
        // first, so the transaction it names can be checked against it.
        if message.psbt.is_some() {
            let mut update = message.clone();
            update.kind = Kind::Update;
            self.receive_update(&update)?;
        }
        let tx = unsigned_transaction(&self.state()?)
            .context("the reported transaction cannot be checked yet")?;
        if tx.compute_txid() != reported {
            bail!(
                "the other wallet reports transaction {reported}, but this shared send's \
                 transaction is {}",
                tx.compute_txid()
            );
        }
        self.stage = Stage::Done;
        self.txid = Some(reported.to_string());
        Ok(Received::Done(reported.to_string()))
    }

    /// The finished transaction, once every input is signed.
    pub fn finalize(&self) -> Result<Transaction> {
        match self.stage {
            Stage::Proposed => bail!("the other wallet has not joined yet"),
            Stage::Active | Stage::Done => finalize(&self.state()?),
        }
    }

    /// Record that the transaction was broadcast, and leave the news for the
    /// other wallet in the outbox.
    pub fn finish(&mut self, txid: &Txid) -> Result<()> {
        let tx = self.finalize()?;
        if tx.compute_txid() != *txid {
            bail!("{txid} is not this shared send's transaction");
        }
        self.stage = Stage::Done;
        self.txid = Some(txid.to_string());
        let done = Message {
            v: VERSION,
            session: self.session.clone(),
            kind: Kind::Done,
            from: self.me.clone(),
            psbt: Some(self.psbt.clone()),
            to: None,
            sats: None,
            fee_rate: None,
            txid: Some(txid.to_string()),
        };
        self.outbox.push(done.encode());
        Ok(())
    }

    /// The proposal as a message. Only wallet A has one, and only until the
    /// other wallet joins.
    pub fn proposal_message(&self) -> Result<Message> {
        if self.role != Role::Start || self.stage != Stage::Proposed {
            bail!("only a shared send that is still waiting to be joined has a proposal");
        }
        Ok(Message {
            v: VERSION,
            session: self.session.clone(),
            kind: Kind::Proposal,
            from: self.me.clone(),
            psbt: Some(self.psbt.clone()),
            to: Some(self.to.clone()),
            sats: Some(self.sats),
            fee_rate: Some(self.fee_rate),
            txid: None,
        })
    }

    /// This wallet's whole state as a message, signatures included, so that
    /// either side can finish.
    pub fn update_message(&self) -> Result<Message> {
        if self.stage == Stage::Proposed {
            bail!("there is nothing to update before the other wallet joins");
        }
        Ok(Message {
            v: VERSION,
            session: self.session.clone(),
            kind: Kind::Update,
            from: self.me.clone(),
            psbt: Some(self.psbt.clone()),
            to: None,
            sats: None,
            fee_rate: None,
            txid: None,
        })
    }

    /// Where the shared send stands, as lines for a person to read.
    pub fn describe(&self) -> Result<Vec<String>> {
        let state = self.state()?;
        let mut lines = vec![
            format!("shared send: {}", self.session),
            format!(
                "this wallet: {} ({})",
                self.me,
                match self.role {
                    Role::Start => "started it",
                    Role::Join => "joined it",
                }
            ),
            format!(
                "other wallet: {}",
                self.peer.as_deref().unwrap_or("not joined yet")
            ),
            format!("pays: {} sats to {}", self.sats, self.to),
            format!(
                "this wallet's half: {} sats plus its part of the fee",
                share_of(self.sats, self.role)
            ),
            format!("fee rate: {} sat/vB", self.fee_rate),
        ];
        if self.stage == Stage::Proposed {
            lines.push("state: proposed, waiting for the other wallet to join".into());
            return Ok(lines);
        }

        let mine = self.my_inputs(&state)?;
        let shares = check_shares(&state)?;
        let signed = signed_inputs(&state);
        lines.push(format!("fee: {} sats", fee(&state)?.to_sat()));
        for (index, input) in state.inputs.iter().enumerate() {
            let has_share = shares
                .scan_keys
                .iter()
                .all(|scan| shares.verified.contains(&(index, *scan)));
            lines.push(format!(
                "input {index}: {} sats, {} (signer {}), share {}, {}",
                prevout(index, input)?.value.to_sat(),
                if mine.contains(&index) {
                    "this wallet"
                } else {
                    "other wallet"
                },
                signer_of(input),
                if has_share { "verified" } else { "missing" },
                if signed.contains(&index) {
                    "signed"
                } else {
                    "not signed"
                }
            ));
        }
        for recipient in recipients(&state)? {
            lines.push(format!(
                "output {}: silent payment script {}",
                recipient.output,
                if state.outputs[recipient.output].script_pubkey.is_empty() {
                    "not derived yet"
                } else {
                    "derived"
                }
            ));
        }
        lines.push(match (self.stage, &self.txid) {
            (Stage::Done, Some(txid)) => format!("state: broadcast as {txid}"),
            _ if self.ready()? => "state: every input is signed, ready to broadcast".into(),
            _ if self.my_turn()? => match self.pass()? {
                Pass::ShareOnly => {
                    "state: this wallet's signer goes next, to add its share (nothing is \
                     signed in this step)"
                        .into()
                }
                Pass::Sign => "state: this wallet's signer goes next, to review and sign".into(),
            },
            _ => "state: waiting for the other wallet".into(),
        });
        Ok(lines)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(kind: &str, extra: &str) -> String {
        format!(
            r#"{{"v":1,"session":"00112233aabbccdd","kind":"{kind}","from":"73C5DA0A"{extra}}}"#
        )
    }

    #[test]
    fn reads_the_three_kinds_and_what_each_needs() {
        let proposal = Message::parse(&message(
            "proposal",
            r#","psbt":"cHNidA==","to":"tsp1q","sats":10000,"fee_rate":2"#,
        ))
        .unwrap();
        assert_eq!(proposal.kind, Kind::Proposal);
        assert_eq!(
            proposal.from, "73c5da0a",
            "fingerprints compare in lowercase"
        );
        assert_eq!(proposal.sats, Some(10_000));

        assert!(Message::parse(&message("update", r#","psbt":"cHNidA==""#)).is_ok());
        assert!(Message::parse(&message("done", r#","txid":"ab""#)).is_ok());

        for (kind, extra) in [
            ("proposal", r#","psbt":"cHNidA==","to":"tsp1q","sats":1"#),
            ("proposal", r#","to":"tsp1q","sats":1,"fee_rate":2"#),
            ("update", ""),
            ("done", r#","psbt":"cHNidA==""#),
            ("hello", ""),
        ] {
            assert!(
                Message::parse(&message(kind, extra)).is_err(),
                "{kind} {extra}"
            );
        }
    }

    #[test]
    fn refuses_other_versions_and_malformed_names() {
        let text = message("update", r#","psbt":"cHNidA==""#);
        assert!(Message::parse(&text.replace(r#""v":1"#, r#""v":2"#)).is_err());
        assert!(Message::parse(&text.replace("00112233aabbccdd", "0011")).is_err());
        assert!(Message::parse(&text.replace("73C5DA0A", "nothex!!")).is_err());
        assert!(Message::parse("not json").is_err());
    }

    #[test]
    fn writes_a_message_in_the_order_the_contract_shows() {
        let done = Message {
            v: VERSION,
            session: "00112233aabbccdd".into(),
            kind: Kind::Done,
            from: "73c5da0a".into(),
            psbt: None,
            to: None,
            sats: None,
            fee_rate: None,
            txid: Some("ab".into()),
        };
        assert_eq!(
            done.encode(),
            r#"{"v":1,"session":"00112233aabbccdd","kind":"done","from":"73c5da0a","txid":"ab"}"#
        );
        assert_eq!(Message::parse(&done.encode()).unwrap(), done);
    }

    #[test]
    fn splits_the_amount_with_the_odd_satoshi_on_the_starter() {
        assert_eq!(share_of(10_000, Role::Start), 5_000);
        assert_eq!(share_of(10_000, Role::Join), 5_000);
        assert_eq!(share_of(10_001, Role::Start), 5_001);
        assert_eq!(share_of(10_001, Role::Join), 5_000);
        assert!(check_amount(660).is_ok());
        assert!(check_amount(659).is_err());
    }

    #[test]
    fn names_a_session_with_sixteen_hex_characters() {
        let id = session_id(b"anything");
        assert_eq!(id.len(), 16);
        assert!(id.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_ne!(id, session_id(b"anything else"));
        assert_eq!(id, session_id(b"anything"));
    }
}
