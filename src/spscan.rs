//! Finding silent payments in a block.
//!
//! The coordinator cannot ask "is this output mine?" the way it can for a
//! descriptor address, because a silent payment output is derived from the
//! sender's input keys and exists nowhere until they spend. What it can do is
//! take the tweak the oracle publishes for a candidate transaction, combine it
//! with the scan key, and re-derive the output that transaction *would* have
//! paid this wallet. If that script is really in the block, the payment is ours.
//!
//! Matching happens in two passes for cost rather than correctness. Deriving
//! one candidate script per tweak and looking it up is cheap; running the full
//! scan is not. So the first pass narrows the block to transactions worth
//! looking at, and the second pass asks `bdk_sp` for the real answer — which
//! also catches a second payment to this wallet in the same transaction, at a
//! derivation order the narrowing pass never generates.

use std::collections::HashMap;

use anyhow::{Context, Result, bail};
use bdk_sp::compute_shared_secret;
use bdk_sp::receive::SpOut;
use bdk_sp::receive::scan::Scanner;
use bdk_wallet::bitcoin::key::TweakedPublicKey;
use bdk_wallet::bitcoin::secp256k1::{PublicKey, XOnlyPublicKey};
use bdk_wallet::bitcoin::{
    Amount, Block, ScriptBuf, Transaction, TxOut, Txid, absolute, transaction,
};

use crate::spreceive::ScanKeys;

/// A silent payment output found in a block, with the height that anchors it.
#[derive(Debug)]
pub struct Found {
    pub height: u32,
    pub out: SpOut,
}

/// One taproot output a candidate transaction created.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaprootOut {
    pub vout: u32,
    pub key: XOnlyPublicKey,
    pub amount: Amount,
}

/// A transaction a tweak stream flagged, with everything a match needs.
///
/// This is what [`electrum`](crate::electrum) publishes and BlindBit does not:
/// the tweak arrives already attached to the transaction it belongs to, along
/// with the taproot outputs that transaction created. That is the whole of what
/// [`scan_candidate`] looks at, which is why scanning this way needs no blocks.
///
/// It is a claim, not a fact. The tweak is checked by re-deriving from it, so a
/// wrong one simply fails to match — but `amount` is only ever the server's
/// word, and a caller that stores it must check it against the chain first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub txid: Txid,
    pub tweak: PublicKey,
    pub outputs: Vec<TaprootOut>,
}

/// Build the scanner for a wallet's keys.
///
/// The label map is empty: this wallet publishes one unlabelled code, so every
/// payment to it derives from the bare spend key. Labels only ever add
/// candidates, so an empty map cannot cause a miss on the address in use.
pub fn scanner(keys: &ScanKeys) -> Scanner {
    Scanner::new(keys.scan, keys.spend, Default::default())
}

/// The height stored for a payment seen before it was mined.
///
/// A real height would be a lie and `Option` would spread through the store for
/// one transient case, so unconfirmed is its own value and printed as such.
pub const UNCONFIRMED: u32 = 0;

/// Search a single transaction, deriving its tweak locally.
///
/// The oracle only publishes tweaks for blocks it has indexed, so a payment
/// cannot be seen this way until it is mined — no use when the transaction was
/// broadcast a moment ago and someone is watching. For one known transaction
/// the tweak can be computed here instead, from its inputs' previous scripts,
/// which is a handful of requests rather than a chain walk.
///
/// `prevouts` must hold one entry per input, in input order: `bdk_sp` zips the
/// two and a short slice would silently sum the wrong keys.
pub fn scan_transaction(
    scanner: &Scanner,
    tx: &Transaction,
    prevouts: &[TxOut],
    height: u32,
) -> Result<Vec<Found>> {
    if prevouts.len() != tx.input.len() {
        bail!(
            "{} prevouts for {} inputs; the tweak would be computed from the wrong keys",
            prevouts.len(),
            tx.input.len()
        );
    }
    let outs = scanner
        .scan_tx(tx, prevouts)
        .with_context(|| format!("scanning {}", tx.compute_txid()))?;
    Ok(outs.into_iter().map(|out| Found { height, out }).collect())
}

/// Search one block for payments to this wallet.
pub fn scan_block(
    keys: &ScanKeys,
    scanner: &Scanner,
    tweaks: &[PublicKey],
    block: &Block,
    height: u32,
) -> Result<Vec<Found>> {
    if tweaks.is_empty() {
        return Ok(Vec::new());
    }

    // First pass: one candidate script per tweak, at derivation order 0.
    let mut candidates: HashMap<ScriptBuf, PublicKey> = HashMap::new();
    for tweak in tweaks {
        for spk in scanner.get_spks_from_tweak(tweak, 0) {
            candidates.insert(spk, *tweak);
        }
    }

    let mut found = Vec::new();
    for tx in &block.txdata {
        // A tweak is published per transaction but arrives in an unlabelled
        // list, so the matching script is what identifies which one to use.
        let Some(tweak) = tx
            .output
            .iter()
            .find_map(|out| candidates.get(&out.script_pubkey))
        else {
            continue;
        };

        let shared = compute_shared_secret(&keys.scan, tweak);
        let outs = scanner
            .scan_txouts(tx, shared)
            .with_context(|| format!("scanning {} at height {height}", tx.compute_txid()))?;
        found.extend(outs.into_iter().map(|out| Found { height, out }));
    }
    Ok(found)
}

/// Search one flagged transaction without fetching it.
///
/// [`scan_block`] needs the block because a bare tweak does not say which
/// transaction it belongs to. A [`Candidate`] does, and carries that
/// transaction's taproot outputs with it, so the same test can be run against
/// nothing but the stream.
///
/// `bdk_sp` takes a whole transaction, and takes each outpoint from its own
/// walk of the outputs — so it gets one built from the candidate. Only taproot
/// outputs are published and only taproot outputs are looked at, which makes
/// that reconstruction exact rather than approximate: every output the real
/// transaction would have contributed is present, at the index it really has,
/// and the gaps between them are filled with something that cannot be mistaken
/// for one. The synthetic transaction's own txid is meaningless and is replaced
/// by the published one afterwards.
pub fn scan_candidate(
    keys: &ScanKeys,
    scanner: &Scanner,
    candidate: &Candidate,
    height: u32,
) -> Result<Vec<Found>> {
    let Some(width) = candidate.outputs.iter().map(|out| out.vout).max() else {
        return Ok(Vec::new());
    };
    let width = width as usize + 1;

    let mut output = vec![
        TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::new(),
        };
        width
    ];
    for out in &candidate.outputs {
        output[out.vout as usize] = TxOut {
            value: out.amount,
            // Already an output key: it is on the chain, so whatever tweak it
            // carries is baked in and must not be applied again.
            script_pubkey: ScriptBuf::new_p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(
                out.key,
            )),
        };
    }

    let shared = compute_shared_secret(&keys.scan, &candidate.tweak);
    let outs = scanner
        .scan_txouts(
            &Transaction {
                version: transaction::Version::TWO,
                lock_time: absolute::LockTime::ZERO,
                input: Vec::new(),
                output,
            },
            shared,
        )
        .with_context(|| format!("scanning {} at height {height}", candidate.txid))?;

    Ok(outs
        .into_iter()
        .map(|mut out| {
            out.outpoint.txid = candidate.txid;
            Found { height, out }
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bdk_wallet::bitcoin::block::{Header, Version};
    use bdk_wallet::bitcoin::hashes::Hash;
    use bdk_wallet::bitcoin::secp256k1::{Secp256k1, SecretKey};
    use bdk_wallet::bitcoin::{
        Amount, BlockHash, CompactTarget, Transaction, TxMerkleNode, TxOut, absolute, transaction,
    };

    fn keys() -> ScanKeys {
        let secp = Secp256k1::new();
        ScanKeys {
            scan: SecretKey::from_slice(&[0x11; 32]).unwrap(),
            spend: SecretKey::from_slice(&[0x22; 32])
                .unwrap()
                .public_key(&secp),
        }
    }

    fn block_with(outputs: Vec<TxOut>) -> Block {
        Block {
            header: Header {
                version: Version::TWO,
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: 0,
                bits: CompactTarget::from_consensus(0),
                nonce: 0,
            },
            txdata: vec![Transaction {
                version: transaction::Version::TWO,
                lock_time: absolute::LockTime::ZERO,
                input: Vec::new(),
                output: outputs,
            }],
        }
    }

    #[test]
    fn a_block_with_no_tweaks_is_skipped_without_touching_it() {
        let keys = keys();
        let block = block_with(vec![TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: ScriptBuf::new(),
        }]);
        assert!(
            scan_block(&keys, &scanner(&keys), &[], &block, 1)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn a_block_whose_outputs_match_no_candidate_finds_nothing() {
        let keys = keys();
        let secp = Secp256k1::new();
        let tweak = SecretKey::from_slice(&[0x33; 32])
            .unwrap()
            .public_key(&secp);
        // An output that is emphatically not the derived script.
        let block = block_with(vec![TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51, 0x20, 0xAB]),
        }]);
        assert!(
            scan_block(&keys, &scanner(&keys), &[tweak], &block, 1)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn the_derived_candidate_script_is_what_gets_matched() {
        let keys = keys();
        let secp = Secp256k1::new();
        let tweak = SecretKey::from_slice(&[0x33; 32])
            .unwrap()
            .public_key(&secp);
        let scanner = scanner(&keys);

        // Put exactly the script the scanner would look for into a block.
        let spk = scanner.get_spks_from_tweak(&tweak, 0).remove(0);
        let block = block_with(vec![TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: spk.clone(),
        }]);

        let found = scan_block(&keys, &scanner, &[tweak], &block, 7).unwrap();
        assert_eq!(found.len(), 1, "the planted output must be found");
        assert_eq!(found[0].height, 7);
        assert_eq!(found[0].out.script_pubkey, spk);
        assert_eq!(found[0].out.amount, Amount::from_sat(10_000));
    }

    /// A candidate built from a transaction the block scan also sees, so the
    /// two paths can be held against each other rather than each against a
    /// hand-written expectation.
    fn candidate_for(tx: &Transaction, tweak: PublicKey) -> Candidate {
        let txid = tx.compute_txid();
        Candidate {
            txid,
            tweak,
            outputs: tx
                .output
                .iter()
                .enumerate()
                .filter(|(_, out)| out.script_pubkey.is_p2tr())
                .map(|(vout, out)| TaprootOut {
                    vout: vout as u32,
                    key: XOnlyPublicKey::from_slice(&out.script_pubkey.as_bytes()[2..]).unwrap(),
                    amount: out.value,
                })
                .collect(),
        }
    }

    #[test]
    fn a_candidate_with_no_taproot_outputs_is_skipped() {
        let keys = keys();
        let secp = Secp256k1::new();
        let candidate = Candidate {
            txid: Txid::all_zeros(),
            tweak: SecretKey::from_slice(&[0x33; 32])
                .unwrap()
                .public_key(&secp),
            outputs: Vec::new(),
        };
        assert!(
            scan_candidate(&keys, &scanner(&keys), &candidate, 1)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn scanning_a_candidate_finds_what_scanning_the_block_finds() {
        let keys = keys();
        let secp = Secp256k1::new();
        let tweak = SecretKey::from_slice(&[0x33; 32])
            .unwrap()
            .public_key(&secp);
        let scanner = scanner(&keys);

        // The payment sits at index 2, behind two outputs that are not taproot
        // at all. If the reconstruction shifted it, the outpoint would be wrong
        // and the coin unspendable.
        let spk = scanner.get_spks_from_tweak(&tweak, 0).remove(0);
        let filler = TxOut {
            value: Amount::from_sat(546),
            script_pubkey: ScriptBuf::from_bytes(vec![0x00, 0x14, 0xAB]),
        };
        let block = block_with(vec![
            filler.clone(),
            filler,
            TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: spk.clone(),
            },
        ]);
        let tx = &block.txdata[0];

        let from_block = scan_block(&keys, &scanner, &[tweak], &block, 9).unwrap();
        let from_candidate = scan_candidate(&keys, &scanner, &candidate_for(tx, tweak), 9).unwrap();

        assert_eq!(from_block.len(), 1);
        assert_eq!(from_candidate.len(), 1, "the stream must find it too");
        assert_eq!(from_candidate[0].out.outpoint, from_block[0].out.outpoint);
        assert_eq!(from_candidate[0].out.outpoint.vout, 2);
        assert_eq!(from_candidate[0].out.script_pubkey, spk);
        assert_eq!(from_candidate[0].out.amount, Amount::from_sat(10_000));
        assert_eq!(
            from_candidate[0].out.tweak.secret_bytes(),
            from_block[0].out.tweak.secret_bytes(),
            "the spending tweak is the thing the coin cannot be moved without"
        );
    }

    #[test]
    fn two_payments_in_one_transaction_both_come_back() {
        let keys = keys();
        let secp = Secp256k1::new();
        let tweak = SecretKey::from_slice(&[0x33; 32])
            .unwrap()
            .public_key(&secp);
        let scanner = scanner(&keys);

        // Derivation order 1 only exists once order 0 has matched, which is the
        // case a narrowing pass on its own would miss.
        let first = scanner.get_spks_from_tweak(&tweak, 0).remove(0);
        let second = scanner.get_spks_from_tweak(&tweak, 1).remove(0);
        let block = block_with(vec![
            TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: first,
            },
            TxOut {
                value: Amount::from_sat(20_000),
                script_pubkey: second,
            },
        ]);

        let found =
            scan_candidate(&keys, &scanner, &candidate_for(&block.txdata[0], tweak), 9).unwrap();
        assert_eq!(found.len(), 2);
        assert_eq!(
            found.iter().map(|f| f.out.amount.to_sat()).sum::<u64>(),
            30_000
        );
    }

    #[test]
    fn a_candidate_whose_outputs_are_not_ours_finds_nothing() {
        let keys = keys();
        let secp = Secp256k1::new();
        let tweak = SecretKey::from_slice(&[0x33; 32])
            .unwrap()
            .public_key(&secp);
        // A real taproot key, just not one this wallet's tweak derives.
        let stranger = SecretKey::from_slice(&[0x44; 32])
            .unwrap()
            .x_only_public_key(&secp)
            .0;
        let candidate = Candidate {
            txid: Txid::all_zeros(),
            tweak,
            outputs: vec![TaprootOut {
                vout: 0,
                key: stranger,
                amount: Amount::from_sat(10_000),
            }],
        };
        assert!(
            scan_candidate(&keys, &scanner(&keys), &candidate, 1)
                .unwrap()
                .is_empty()
        );
    }
}
