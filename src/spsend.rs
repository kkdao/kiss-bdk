//! BIP-375 silent payment sending.
//!
//! A silent payment output script is derived from the *input private keys*, so
//! a watch-only wallet cannot compute it. BIP-375 carries the recipient's scan
//! and spend keys in the PSBT instead and lets the signer fill the script in,
//! which is why the transaction has to leave here as a PSBTv2: v0's fixed
//! unsigned transaction cannot express an output whose script is not yet known.
//!
//! BDK still does all the wallet work. This module only re-shapes the v0 PSBT
//! it produced into the v2 form KISS accepts.

use anyhow::{Context, Result, bail};
use bdk_wallet::bitcoin::bip32::KeySource;
use bdk_wallet::bitcoin::secp256k1::PublicKey as SecpPublicKey;
use bdk_wallet::bitcoin::{
    OutPoint, Psbt, PublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use psbt_v2::v2::{Creator, InputBuilder, OutputBuilder};

use crate::sp::SilentPaymentAddress;

/// Stand-in output BDK selects coins and computes the fee against.
///
/// A silent payment output is always a 34-byte P2TR script, so the placeholder
/// must be one too or the fee would be estimated against the wrong vsize. The
/// key is the recipient's spend key, which makes the script deterministic and
/// findable afterwards — BDK shuffles the outputs it builds.
pub fn placeholder_script(recipient: &SilentPaymentAddress) -> ScriptBuf {
    let (xonly, _) = recipient.spend.x_only_public_key();
    let mut script = Vec::with_capacity(34);
    script.push(0x51); // OP_1: taproot witness version
    script.push(0x20); // 32-byte program
    script.extend_from_slice(&xonly.serialize());
    ScriptBuf::from_bytes(script)
}

/// Locate the placeholder among the outputs BDK shuffled.
pub fn placeholder_index(psbt: &Psbt, recipient: &SilentPaymentAddress) -> Result<usize> {
    Ok(resolve_sp_outputs(psbt, std::slice::from_ref(recipient))?[0].index)
}

/// How many outputs carry this recipient's placeholder.
///
/// A caller building the recipient list needs this because change is not
/// guaranteed: an exact-amount spend has none, and a change below the dust
/// threshold is folded into the fee instead of becoming an output.
pub fn placeholder_count(psbt: &Psbt, recipient: &SilentPaymentAddress) -> usize {
    let placeholder = placeholder_script(recipient);
    psbt.unsigned_tx
        .output
        .iter()
        .filter(|out| out.script_pubkey == placeholder)
        .count()
}

/// Match every recipient to the output BDK put its placeholder in.
///
/// One entry per output expected, so a wallet paying its own code twice — the
/// payment and the silent payment change beside it — passes that code twice.
///
/// Two such outputs used to be refused as ambiguous. They are interchangeable
/// rather than ambiguous: both carry the same `PSBT_OUT_SP_V0_INFO`, and which
/// one ends up at derivation order 0 is the signer's to decide. What matters is
/// that each is claimed once, so a recipient never takes an output another has
/// already been promised.
pub fn resolve_sp_outputs(
    psbt: &Psbt,
    recipients: &[SilentPaymentAddress],
) -> Result<Vec<SpOutput>> {
    let outputs = &psbt.unsigned_tx.output;
    let mut claimed = vec![false; outputs.len()];
    let mut resolved = Vec::with_capacity(recipients.len());

    for recipient in recipients {
        let placeholder = placeholder_script(recipient);
        let index = outputs
            .iter()
            .enumerate()
            .find(|(index, out)| !claimed[*index] && out.script_pubkey == placeholder)
            .map(|(index, _)| index)
            .context("a silent payment placeholder output is missing")?;
        claimed[index] = true;
        resolved.push(SpOutput {
            index,
            recipient: *recipient,
        });
    }
    Ok(resolved)
}

/// PSBT_OUT_SCRIPT. BIP-375 omits it entirely on a silent payment output.
const PSBT_OUT_SCRIPT: u8 = 0x04;
const PSBT_MAGIC: [u8; 5] = [0x70, 0x73, 0x62, 0x74, 0xff];

/// An output whose script the signer derives, and the address it must reach.
pub struct SpOutput {
    pub index: usize,
    pub recipient: SilentPaymentAddress,
}

/// Convert BDK's v0 PSBT into the PSBTv2 KISS signs, replacing each placeholder
/// output with its silent payment recipient.
///
/// `sp_outputs` may be empty. A BIP-376 spend has silent payment *inputs* and
/// ordinary outputs, and it still has to leave here as a v2: the signer computes
/// its taproot sighash only from the transaction view it extracts from a v2's
/// own fields, so a v0 carrying tweaks loads green and then fails to sign.
pub fn build_v2(psbt: &Psbt, sp_outputs: &[SpOutput]) -> Result<Vec<u8>> {
    let tx = &psbt.unsigned_tx;
    for sp in sp_outputs {
        if sp.index >= tx.output.len() {
            bail!("silent payment output index {} is out of range", sp.index);
        }
    }

    let mut constructor = Creator::new()
        .transaction_version(tx.version)
        .fallback_lock_time(tx.lock_time)
        .constructor_modifiable();

    for (txin, input) in tx.input.iter().zip(psbt.inputs.iter()) {
        // KISS only co-signs silent payments from native segwit inputs, which
        // is also the only script type its descriptor produces.
        let utxo = input
            .witness_utxo
            .clone()
            .context("silent payments need a witness UTXO on every input")?;
        let mut built = InputBuilder::new(&txin.previous_output)
            .segwit_fund(utxo)
            .build();
        // The witness UTXO is what signing needs, but it states an amount
        // nothing commits to. Carry the full previous transaction across too,
        // so the signer can hash each amount back to its outpoint; dropping it
        // here is what made silent payments the one path the signer still
        // refused after `create` started attaching them.
        built.non_witness_utxo = input.non_witness_utxo.clone();
        built.sequence = Some(txin.sequence);
        built.bip32_derivations = compressed_derivations(&input.bip32_derivation);
        // A BIP-376 input carries its tweak and its spend-key origin as raw
        // pairs, because no typed field for either exists in psbt-v2 0.3.0.
        // They are built in `spspend` and only carried here.
        built.unknowns = input
            .unknown
            .iter()
            .map(|(key, value)| {
                (
                    psbt_v2::raw::Key {
                        type_value: key.type_value,
                        key: key.key.clone(),
                    },
                    value.clone(),
                )
            })
            .collect();
        // Sighash type is deliberately left unset: BIP-375 signing is
        // SIGHASH_ALL, which is what KISS uses when the field is absent.
        constructor = constructor.input(built);
    }

    for (index, txout) in tx.output.iter().enumerate() {
        let mut built = OutputBuilder::new(txout.clone()).build();
        built.bip32_derivations = compressed_derivations(&psbt.outputs[index].bip32_derivation);
        if let Some(sp) = sp_outputs.iter().find(|sp| sp.index == index) {
            // The signer derives this script; carrying the placeholder would
            // both be wrong and let a coordinator smuggle in its own output.
            built.script_pubkey = ScriptBuf::default();
            built.sp_v0_info = Some(sp.recipient.sp_v0_info());
        }
        constructor = constructor.output(built);
    }

    // updater() clears both modifiable flags. BIP-375 requires them zero once
    // silent payment outputs are present, and KISS rejects a PSBT that is
    // still marked modifiable.
    let v2 = constructor
        .updater()
        .map_err(|error| anyhow::anyhow!("building PSBTv2: {error}"))?
        .psbt();

    strip_empty_output_scripts(&v2.serialize(), tx.input.len())
}

/// rust-bitcoin keys BIP-32 derivations by the secp256k1 key; psbt-v2 keys them
/// by `bitcoin::PublicKey`. Every key BDK puts here is compressed.
fn compressed_derivations(
    source: &std::collections::BTreeMap<SecpPublicKey, KeySource>,
) -> std::collections::BTreeMap<PublicKey, KeySource> {
    source
        .iter()
        .map(|(key, origin)| (PublicKey::new(*key), origin.clone()))
        .collect()
}

/// Remove the zero-length `PSBT_OUT_SCRIPT` that psbt-v2 0.3.0 writes for every
/// output, including silent payment ones.
///
/// BIP-375 omits the field on an SP output because its script is not known
/// until signing, and the official test vectors have no such pair. Emitting an
/// empty one is a spec violation on the sending side, so it is stripped here
/// rather than relied upon to be tolerated.
fn strip_empty_output_scripts(bytes: &[u8], input_count: usize) -> Result<Vec<u8>> {
    let mut cursor = Cursor::new(bytes);
    let magic = cursor.take(PSBT_MAGIC.len())?;
    if magic != PSBT_MAGIC {
        bail!("serialized PSBT is missing its magic bytes");
    }
    let mut out = Vec::with_capacity(bytes.len());
    out.extend_from_slice(magic);

    // Map order is global, then one per input, then one per output.
    let first_output_map = 1 + input_count;
    let mut map_index = 0;
    while !cursor.is_empty() {
        let strip = map_index >= first_output_map;
        copy_map(&mut cursor, &mut out, strip)?;
        map_index += 1;
    }
    Ok(out)
}

/// Copy one key-value map, optionally dropping empty `PSBT_OUT_SCRIPT` pairs.
fn copy_map(cursor: &mut Cursor<'_>, out: &mut Vec<u8>, strip: bool) -> Result<()> {
    loop {
        let start = cursor.position;
        let key_len = cursor.compact_size()?;
        if key_len == 0 {
            out.push(0x00); // map terminator
            return Ok(());
        }
        let key = cursor.take(key_len)?.to_vec();
        let value_len = cursor.compact_size()?;
        cursor.take(value_len)?;
        let drop = strip && value_len == 0 && key == [PSBT_OUT_SCRIPT];
        if !drop {
            out.extend_from_slice(&cursor.bytes[start..cursor.position]);
        }
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Cursor { bytes, position: 0 }
    }

    fn is_empty(&self) -> bool {
        self.position >= self.bytes.len()
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(length)
            .filter(|end| *end <= self.bytes.len())
            .context("PSBT ended mid-field")?;
        let slice = &self.bytes[self.position..end];
        self.position = end;
        Ok(slice)
    }

    fn compact_size(&mut self) -> Result<usize> {
        let first = self.take(1)?[0];
        let width = match first {
            0xfd => 2,
            0xfe => 4,
            0xff => 8,
            _ => return Ok(usize::from(first)),
        };
        let raw = self.take(width)?;
        let mut value = 0_u64;
        for (index, byte) in raw.iter().enumerate() {
            value |= u64::from(*byte) << (8 * index);
        }
        usize::try_from(value).context("PSBT field length does not fit in memory")
    }
}

/// Read a PSBT that may be either version.
///
/// The two are told apart by structure rather than by a flag: a PSBTv0 carries
/// a global unsigned transaction and a v2 must not, so the v0 parser rejects a
/// v2 outright.
pub enum AnyPsbt {
    V0(Psbt),
    V2(psbt_v2::v2::Psbt),
}

impl AnyPsbt {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        match Psbt::deserialize(bytes) {
            Ok(psbt) => Ok(AnyPsbt::V0(psbt)),
            Err(v0_error) => match psbt_v2::v2::Psbt::deserialize(bytes) {
                Ok(psbt) => Ok(AnyPsbt::V2(psbt)),
                Err(v2_error) => bail!("not a PSBT: {v0_error}; and not a PSBTv2: {v2_error}"),
            },
        }
    }
}

/// Rebuild a v0 PSBT from a signed v2 one.
///
/// Once the signer has filled in the silent payment output scripts every output
/// is known, so the transaction can be expressed as a v0 PSBT again. That lets
/// the existing signature check, finalization and broadcast path stay as they
/// are instead of being duplicated for v2.
pub fn to_v0(v2: &psbt_v2::v2::Psbt) -> Result<Psbt> {
    let lock_time = v2
        .determine_lock_time()
        .map_err(|error| anyhow::anyhow!("PSBTv2 has no usable lock time: {error}"))?;

    let unsigned_tx = Transaction {
        version: v2.global.tx_version,
        lock_time,
        input: v2
            .inputs
            .iter()
            .map(|input| TxIn {
                previous_output: OutPoint {
                    txid: input.previous_txid,
                    vout: input.spent_output_index,
                },
                script_sig: ScriptBuf::default(),
                sequence: input.sequence.unwrap_or(Sequence::ENABLE_RBF_NO_LOCKTIME),
                witness: Witness::default(),
            })
            .collect(),
        output: v2
            .outputs
            .iter()
            .map(|output| TxOut {
                value: output.amount,
                script_pubkey: output.script_pubkey.clone(),
            })
            .collect(),
    };

    let mut psbt = Psbt::from_unsigned_tx(unsigned_tx)
        .map_err(|error| anyhow::anyhow!("rebuilding a v0 PSBT: {error}"))?;
    for (index, (target, source)) in psbt.inputs.iter_mut().zip(v2.inputs.iter()).enumerate() {
        // This is a hand-maintained whitelist, and it has already silently
        // dropped a signature once -- the taproot one below, which is the whole
        // point of a BIP-376 spend. So anything it does not know how to carry is
        // a refusal rather than an omission: losing a signature here surfaces
        // much later as an unexplainable "not fully signed/finalizable".
        unsupported(index, source)?;

        target.witness_utxo = source.witness_utxo.clone();
        target.partial_sigs = source.partial_sigs.clone();
        target.bip32_derivation = secp_derivations(&source.bip32_derivations);
        target.tap_key_sig = source.tap_key_sig;
        target.final_script_sig = source.final_script_sig.clone();
        target.final_script_witness = source.final_script_witness.clone();
    }
    for (target, source) in psbt.outputs.iter_mut().zip(v2.outputs.iter()) {
        target.bip32_derivation = secp_derivations(&source.bip32_derivations);
    }
    Ok(psbt)
}

/// Refuse a v2 input carrying something `to_v0` would drop on the floor.
///
/// The two BIP-376 raw pairs are expected: the signer reads the tweak and
/// leaves it in place, and neither it nor its spend-key origin has any meaning
/// once the transaction is finalized.
fn unsupported(index: usize, input: &psbt_v2::v2::Input) -> Result<()> {
    let mut carried = Vec::new();
    if !input.tap_script_sigs.is_empty() {
        carried.push("taproot script-path signatures");
    }
    if !input.tap_scripts.is_empty() {
        carried.push("taproot leaf scripts");
    }
    if !input.proprietaries.is_empty() {
        carried.push("proprietary fields");
    }
    let stray: Vec<u8> = input
        .unknowns
        .keys()
        .map(|key| key.type_value)
        .filter(|type_value| {
            *type_value != crate::spspend::PSBT_IN_SP_TWEAK
                && *type_value != crate::spspend::PSBT_IN_SP_SPEND_BIP32_DERIVATION
        })
        .collect();
    if !stray.is_empty() {
        bail!(
            "input {index} carries unrecognised PSBT fields {stray:02x?}; \
             flattening it would silently discard them"
        );
    }
    if !carried.is_empty() {
        bail!(
            "input {index} carries {}, which this coordinator cannot flatten to a \
             v0 PSBT without losing them",
            carried.join(" and ")
        );
    }
    Ok(())
}

fn secp_derivations(
    source: &std::collections::BTreeMap<PublicKey, KeySource>,
) -> std::collections::BTreeMap<SecpPublicKey, KeySource> {
    source
        .iter()
        .map(|(key, origin)| (key.inner, origin.clone()))
        .collect()
}
