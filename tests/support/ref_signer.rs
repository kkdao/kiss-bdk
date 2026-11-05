//! A signer for tests, written from section 3 of the shared send contract.
//!
//! It stands in for a signing device with P2WPKH coins: it sorts the inputs
//! into its own and foreign ones, adds one ECDH share and one BIP-374 proof
//! per own input, checks the foreign shares, and either stops there (a share
//! only pass) or derives the output script and signs (a complete pass).
//!
//! None of the coordinator's checking code is used here. The proofs, the
//! proof verification and the BIP-352 derivation are written out again from
//! the BIPs, so a mistake in the coordinator shows up as a disagreement
//! instead of being made twice.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::str::FromStr;

use bdk_wallet::bitcoin::bip32::{DerivationPath, Fingerprint, Xpriv, Xpub};
use bdk_wallet::bitcoin::hashes::{Hash, sha256};
use bdk_wallet::bitcoin::secp256k1::{Message, PublicKey, Scalar, Secp256k1, SecretKey};
use bdk_wallet::bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bdk_wallet::bitcoin::{
    CompressedPublicKey, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
    absolute, ecdsa,
};
use psbt_v2::v2::{Input, Psbt};

/// The order of the secp256k1 group.
const ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// The generator, compressed, as BIP-374 hashes it into the challenge.
const GENERATOR: [u8; 33] = [
    0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
    0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17,
    0x98,
];

/// What a visit produced, as the desktop bridges report it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Own shares added, nothing signed.
    Share(Vec<u8>),
    /// Complete: script derived and own inputs signed.
    Signed(Vec<u8>),
}

impl Outcome {
    pub fn bytes(&self) -> &[u8] {
        match self {
            Outcome::Share(bytes) | Outcome::Signed(bytes) => bytes,
        }
    }
}

/// A refusal, with the reason a device would put on its screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal(pub String);

fn refuse<T>(reason: impl Into<String>) -> Result<T, Refusal> {
    Err(Refusal(reason.into()))
}

pub struct RefSigner {
    master: Xpriv,
    /// Return only what section 3 lists, the way a signer trims its QR.
    pub trim: bool,
}

impl RefSigner {
    /// A signer for the BIP-32 seed `seed`, on testnet account `m/84'/1'/0'`.
    pub fn new(seed: &[u8]) -> Self {
        RefSigner {
            master: Xpriv::new_master(Network::Testnet, seed).unwrap(),
            trim: false,
        }
    }

    pub fn trimmed(mut self) -> Self {
        self.trim = true;
        self
    }

    pub fn fingerprint(&self) -> Fingerprint {
        self.master.fingerprint(&Secp256k1::new())
    }

    /// The descriptor a coordinator pairs with, in the form KISS shows it.
    pub fn descriptor(&self) -> String {
        let secp = Secp256k1::new();
        let path = DerivationPath::from_str("84'/1'/0'").unwrap();
        let account = Xpub::from_priv(&secp, &self.master.derive_priv(&secp, &path).unwrap());
        format!("wpkh([{}/84h/1h/0h]{account}/<0;1>/*)", self.fingerprint())
    }

    /// The private key behind an input, if this signer holds it: one of the
    /// input's key origins must lead from this seed to a key whose HASH160 is
    /// the witness program.
    pub fn own_key(&self, input: &Input) -> Option<SecretKey> {
        let script = &input.witness_utxo.as_ref()?.script_pubkey;
        if !script.is_p2wpkh() {
            return None;
        }
        let secp = Secp256k1::new();
        input
            .bip32_derivations
            .values()
            .filter(|(fingerprint, _)| *fingerprint == self.fingerprint())
            .filter_map(|(_, path)| self.master.derive_priv(&secp, path).ok())
            .map(|child| child.private_key)
            .find(|key| p2wpkh_script(&key.public_key(&secp)) == *script)
    }

    /// One scan of a request, following section 3 step by step.
    pub fn sign(&self, request: &[u8]) -> Result<Outcome, Refusal> {
        let secp = Secp256k1::new();
        let mut psbt = match Psbt::deserialize(request) {
            Ok(psbt) => psbt,
            Err(error) => return refuse(format!("not a PSBTv2: {error}")),
        };
        let recipients = recipients(&psbt)?;
        if recipients.is_empty() {
            return refuse("no silent payment output");
        }
        let mut scan_keys: Vec<PublicKey> = Vec::new();
        for (_, scan, _) in &recipients {
            if !scan_keys.contains(scan) {
                scan_keys.push(*scan);
            }
        }

        // 1. Own and foreign.
        let mut own: BTreeMap<usize, SecretKey> = BTreeMap::new();
        let mut keys: Vec<PublicKey> = Vec::new();
        for (index, input) in psbt.inputs.iter().enumerate() {
            let Some(utxo) = &input.witness_utxo else {
                return refuse(format!("input {index} has no witness UTXO"));
            };
            match self.own_key(input) {
                Some(key) => {
                    keys.push(key.public_key(&secp));
                    own.insert(index, key);
                }
                None => keys.push(foreign_key(index, input, &utxo.script_pubkey)?),
            }
        }

        // 2. All own: the single signer path, which this test signer leaves
        // to the real ones.
        if own.len() == psbt.inputs.len() {
            return refuse("every input is this signer's own, so this is not a shared send");
        }

        // 3.1 Refusals.
        if !psbt.global.sp_ecdh_shares.is_empty() || !psbt.global.sp_dleq_proofs.is_empty() {
            return refuse("a global share is present beside an input this signer does not own");
        }
        for (index, input) in psbt.inputs.iter().enumerate() {
            if input
                .sighash_type
                .is_some_and(|kind| kind.to_u32() != EcdsaSighashType::All.to_u32())
            {
                return refuse(format!("input {index} is not SIGHASH_ALL"));
            }
        }
        if own.is_empty() {
            return refuse("this signer owns no input");
        }

        // 3.2 Own inputs: compute, and overwrite whatever arrived.
        for (index, key) in &own {
            let input = &mut psbt.inputs[*index];
            input.sp_ecdh_shares.clear();
            input.sp_dleq_proofs.clear();
            for scan in &scan_keys {
                let share = scan.mul_tweak(&secp, &Scalar::from(*key)).unwrap();
                let aux = aux_bytes(key, scan);
                let proof = generate_proof(key, scan, &aux, None, None).unwrap();
                input
                    .sp_ecdh_shares
                    .insert(CompressedPublicKey(*scan), CompressedPublicKey(share));
                input
                    .sp_dleq_proofs
                    .insert(CompressedPublicKey(*scan), proof.into());
            }
        }

        // 3.3 Foreign inputs: a share and its proof together, or neither.
        let mut complete = true;
        for (index, input) in psbt.inputs.iter().enumerate() {
            if own.contains_key(&index) {
                continue;
            }
            for scan in &scan_keys {
                let slot = CompressedPublicKey(*scan);
                match (
                    input.sp_ecdh_shares.get(&slot),
                    input.sp_dleq_proofs.get(&slot),
                ) {
                    (Some(share), Some(proof)) => {
                        if !verify_proof(&keys[index], scan, &share.0, proof.as_bytes(), None, None)
                        {
                            return refuse(format!("input {index}: bad proof for its share"));
                        }
                    }
                    (None, None) => complete = false,
                    _ => {
                        return refuse(format!(
                            "input {index}: a share and a proof travel together"
                        ));
                    }
                }
            }
        }

        // 3.4 Incomplete: a share only pass.
        if !complete {
            if recipients
                .iter()
                .any(|(output, _, _)| !psbt.outputs[*output].script_pubkey.is_empty())
            {
                return refuse("an output script exists before every share does");
            }
            psbt.global.tx_modifiable_flags = 0;
            return Ok(Outcome::Share(self.answer(&psbt, &own)));
        }

        // 3.5 Complete: derive, compare or set, sign.
        let outpoints: Vec<OutPoint> = psbt.inputs.iter().map(outpoint).collect();
        for scan in &scan_keys {
            let shares: Vec<PublicKey> = psbt
                .inputs
                .iter()
                .map(|input| input.sp_ecdh_shares[&CompressedPublicKey(*scan)].0)
                .collect();
            let mut group: Vec<&(usize, PublicKey, PublicKey)> = recipients
                .iter()
                .filter(|(_, other, _)| other == scan)
                .collect();
            group.sort_by_key(|(_, _, spend)| spend.serialize());
            for (k, (output, _, spend)) in group.into_iter().enumerate() {
                let script = script_from_shares(&keys, &shares, &outpoints, spend, k as u32);
                let slot = &mut psbt.outputs[*output].script_pubkey;
                if slot.is_empty() {
                    *slot = script;
                } else if *slot != script {
                    return refuse(format!(
                        "output {output} is not the script the shares derive"
                    ));
                }
            }
        }
        psbt.global.tx_modifiable_flags = 0;

        let tx = unsigned_transaction(&psbt);
        for (index, key) in &own {
            let utxo = psbt.inputs[*index].witness_utxo.clone().unwrap();
            let hash = SighashCache::new(&tx)
                .p2wpkh_signature_hash(
                    *index,
                    &utxo.script_pubkey,
                    utxo.value,
                    EcdsaSighashType::All,
                )
                .unwrap();
            let signature = ecdsa::Signature {
                signature: secp.sign_ecdsa(&Message::from(hash), key),
                sighash_type: EcdsaSighashType::All,
            };
            let public = bdk_wallet::bitcoin::PublicKey::new(key.public_key(&secp));
            psbt.inputs[*index].partial_sigs.clear();
            psbt.inputs[*index].partial_sigs.insert(public, signature);
        }
        Ok(Outcome::Signed(self.answer(&psbt, &own)))
    }

    /// What comes back: everything, or only what section 3 step 4 lists.
    fn answer(&self, psbt: &Psbt, own: &BTreeMap<usize, SecretKey>) -> Vec<u8> {
        let mut answer = psbt.clone();
        if self.trim {
            for (index, input) in answer.inputs.iter_mut().enumerate() {
                input.witness_utxo = None;
                input.non_witness_utxo = None;
                input.bip32_derivations.clear();
                if !own.contains_key(&index) {
                    input.sp_ecdh_shares.clear();
                    input.sp_dleq_proofs.clear();
                    input.partial_sigs.clear();
                }
            }
            for output in &mut answer.outputs {
                output.bip32_derivations.clear();
            }
        }
        kiss_bdk::spsend::serialize_v2(&answer).unwrap()
    }
}

fn p2wpkh_script(key: &PublicKey) -> ScriptBuf {
    ScriptBuf::new_p2wpkh(&CompressedPublicKey(*key).wpubkey_hash())
}

fn outpoint(input: &Input) -> OutPoint {
    OutPoint {
        txid: input.previous_txid,
        vout: input.spent_output_index,
    }
}

/// The key a foreign input stands for, read the way section 2 says.
fn foreign_key(index: usize, input: &Input, script: &ScriptBuf) -> Result<PublicKey, Refusal> {
    if script.is_p2wpkh() {
        return match input
            .bip32_derivations
            .keys()
            .find(|key| p2wpkh_script(&key.inner) == *script)
        {
            Some(key) => Ok(key.inner),
            None => refuse(format!(
                "foreign input {index} has no derivation key matching its witness program"
            )),
        };
    }
    if script.is_p2tr() {
        let mut even_y = [0x02_u8; 33];
        even_y[1..].copy_from_slice(&script.as_bytes()[2..]);
        return match PublicKey::from_slice(&even_y) {
            Ok(key) => Ok(key),
            Err(_) => refuse(format!("input {index} pays an invalid taproot key")),
        };
    }
    refuse(format!("input {index} is not P2WPKH or P2TR"))
}

fn recipients(psbt: &Psbt) -> Result<Vec<(usize, PublicKey, PublicKey)>, Refusal> {
    let mut found = Vec::new();
    for (index, output) in psbt.outputs.iter().enumerate() {
        let Some(info) = &output.sp_v0_info else {
            continue;
        };
        match (
            PublicKey::from_slice(&info[..33]),
            PublicKey::from_slice(&info[33..]),
        ) {
            (Ok(scan), Ok(spend)) => found.push((index, scan, spend)),
            _ => return refuse(format!("output {index} names an invalid recipient")),
        }
    }
    Ok(found)
}

fn unsigned_transaction(psbt: &Psbt) -> Transaction {
    Transaction {
        version: psbt.global.tx_version,
        lock_time: psbt
            .global
            .fallback_lock_time
            .unwrap_or(absolute::LockTime::ZERO),
        input: psbt
            .inputs
            .iter()
            .map(|input| TxIn {
                previous_output: outpoint(input),
                script_sig: ScriptBuf::new(),
                sequence: input.sequence.unwrap_or(Sequence::MAX),
                witness: Witness::new(),
            })
            .collect(),
        output: psbt
            .outputs
            .iter()
            .map(|output| TxOut {
                value: output.amount,
                script_pubkey: output.script_pubkey.clone(),
            })
            .collect(),
    }
}

/// Deterministic stand-in for the 32 random bytes a device would draw.
fn aux_bytes(key: &SecretKey, scan: &PublicKey) -> [u8; 32] {
    let mut seed = b"reference signer aux".to_vec();
    seed.extend_from_slice(&key.secret_bytes());
    seed.extend_from_slice(&scan.serialize());
    sha256::Hash::hash(&seed).to_byte_array()
}

// ---------------------------------------------------------------------------
// BIP-340 style hashing, BIP-374 and BIP-352, written out again

pub fn tagged_hash(tag: &str, message: &[u8]) -> [u8; 32] {
    let tag_hash = sha256::Hash::hash(tag.as_bytes()).to_byte_array();
    let mut bytes = Vec::with_capacity(64 + message.len());
    bytes.extend_from_slice(&tag_hash);
    bytes.extend_from_slice(&tag_hash);
    bytes.extend_from_slice(message);
    sha256::Hash::hash(&bytes).to_byte_array()
}

/// `value mod n` for a 256 bit value, which is at most one subtraction.
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

fn multiply(point: &PublicKey, scalar: &SecretKey) -> PublicKey {
    point
        .mul_tweak(&Secp256k1::new(), &Scalar::from(*scalar))
        .unwrap()
}

fn challenge(
    a_pub: &PublicKey,
    b: &PublicKey,
    c: &PublicKey,
    g: &[u8; 33],
    r1: &PublicKey,
    r2: &PublicKey,
    m: Option<&[u8; 32]>,
) -> [u8; 32] {
    let mut message = Vec::with_capacity(33 * 6 + 32);
    message.extend_from_slice(&a_pub.serialize());
    message.extend_from_slice(&b.serialize());
    message.extend_from_slice(&c.serialize());
    message.extend_from_slice(g);
    message.extend_from_slice(&r1.serialize());
    message.extend_from_slice(&r2.serialize());
    if let Some(m) = m {
        message.extend_from_slice(m);
    }
    tagged_hash("BIP0374/challenge", &message)
}

/// BIP-374 GenerateProof(a, B, r, G, m). `None` where the BIP says fail.
pub fn generate_proof(
    a: &SecretKey,
    b: &PublicKey,
    r: &[u8; 32],
    g: Option<&PublicKey>,
    m: Option<&[u8; 32]>,
) -> Option<[u8; 64]> {
    let generator = PublicKey::from_slice(&GENERATOR).unwrap();
    let g_point = g.unwrap_or(&generator);
    let g_bytes = g_point.serialize();

    let a_pub = multiply(g_point, a);
    let c = multiply(b, a);

    // t = a xor hash_aux(r)
    let aux = tagged_hash("BIP0374/aux", r);
    let mut t = a.secret_bytes();
    for (byte, mask) in t.iter_mut().zip(aux) {
        *byte ^= mask;
    }
    // k = hash_nonce(t || A || C || m) mod n
    let mut nonce = t.to_vec();
    nonce.extend_from_slice(&a_pub.serialize());
    nonce.extend_from_slice(&c.serialize());
    if let Some(m) = m {
        nonce.extend_from_slice(m);
    }
    let k = SecretKey::from_slice(&reduce(tagged_hash("BIP0374/nonce", &nonce))).ok()?;

    let r1 = multiply(g_point, &k);
    let r2 = multiply(b, &k);
    let e = challenge(&a_pub, b, &c, &g_bytes, &r1, &r2, m);

    // s = (k + e·a) mod n
    let s = match SecretKey::from_slice(&reduce(e)) {
        Ok(e_scalar) => a
            .mul_tweak(&Scalar::from(e_scalar))
            .ok()?
            .add_tweak(&Scalar::from(k))
            .ok()?,
        // e is a multiple of n, so e·a vanishes.
        Err(_) => k,
    };

    let mut proof = [0_u8; 64];
    proof[..32].copy_from_slice(&e);
    proof[32..].copy_from_slice(&s.secret_bytes());
    verify_proof(&a_pub, b, &c, &proof, g, m).then_some(proof)
}

/// BIP-374 VerifyProof(A, B, C, proof, G, m).
pub fn verify_proof(
    a_pub: &PublicKey,
    b: &PublicKey,
    c: &PublicKey,
    proof: &[u8; 64],
    g: Option<&PublicKey>,
    m: Option<&[u8; 32]>,
) -> bool {
    let generator = PublicKey::from_slice(&GENERATOR).unwrap();
    let g_point = g.unwrap_or(&generator);

    let e: [u8; 32] = proof[..32].try_into().unwrap();
    let Ok(s) = SecretKey::from_slice(&proof[32..]) else {
        return false;
    };
    let Ok(e_scalar) = SecretKey::from_slice(&reduce(e)) else {
        return false;
    };
    let minus_e = e_scalar.negate();

    // R1 = s·G - e·A, R2 = s·B - e·C
    let Ok(r1) = multiply(g_point, &s).combine(&multiply(a_pub, &minus_e)) else {
        return false;
    };
    let Ok(r2) = multiply(b, &s).combine(&multiply(c, &minus_e)) else {
        return false;
    };
    challenge(a_pub, b, c, &g_point.serialize(), &r1, &r2, m) == e
}

/// The script BIP-352 gives recipient `k`, from public values only: the input
/// keys, one share per input, and the outpoints.
pub fn script_from_shares(
    keys: &[PublicKey],
    shares: &[PublicKey],
    outpoints: &[OutPoint],
    spend: &PublicKey,
    k: u32,
) -> ScriptBuf {
    let a_sum = sum(keys);
    let c_sum = sum(shares);
    let hash = SecretKey::from_slice(&input_hash(outpoints, &a_sum)).unwrap();
    output_script(&multiply(&c_sum, &hash), spend, k)
}

/// The same script from the PRIVATE keys of every input, which is how a lone
/// sender computes it in BIP-352. Nothing here touches a share or a proof.
pub fn script_from_private_keys(
    keys: &[SecretKey],
    outpoints: &[OutPoint],
    scan: &PublicKey,
    spend: &PublicKey,
    k: u32,
) -> ScriptBuf {
    let secp = Secp256k1::new();
    let mut a_sum = keys[0];
    for key in &keys[1..] {
        a_sum = a_sum.add_tweak(&Scalar::from(*key)).unwrap();
    }
    let hash = SecretKey::from_slice(&input_hash(outpoints, &a_sum.public_key(&secp))).unwrap();
    // ecdh = (input_hash · a_sum) · B_scan
    let secret = a_sum.mul_tweak(&Scalar::from(hash)).unwrap();
    output_script(&multiply(scan, &secret), spend, k)
}

fn sum(points: &[PublicKey]) -> PublicKey {
    let borrowed: Vec<&PublicKey> = points.iter().collect();
    PublicKey::combine_keys(&borrowed).unwrap()
}

fn input_hash(outpoints: &[OutPoint], a_sum: &PublicKey) -> [u8; 32] {
    let smallest = outpoints
        .iter()
        .map(|outpoint| {
            let mut bytes = outpoint.txid.to_byte_array().to_vec();
            bytes.extend_from_slice(&outpoint.vout.to_le_bytes());
            bytes
        })
        .min()
        .unwrap();
    let mut message = smallest;
    message.extend_from_slice(&a_sum.serialize());
    tagged_hash("BIP0352/Inputs", &message)
}

fn output_script(shared_secret: &PublicKey, spend: &PublicKey, k: u32) -> ScriptBuf {
    let secp = Secp256k1::new();
    let mut message = shared_secret.serialize().to_vec();
    message.extend_from_slice(&k.to_be_bytes());
    let tweak = SecretKey::from_slice(&tagged_hash("BIP0352/SharedSecret", &message)).unwrap();
    let output = spend.combine(&tweak.public_key(&secp)).unwrap();
    let (x_only, _) = output.x_only_public_key();
    let mut script = vec![0x51, 0x20];
    script.extend_from_slice(&x_only.serialize());
    ScriptBuf::from_bytes(script)
}
