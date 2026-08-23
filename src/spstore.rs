//! Where receive-side silent payment state lives.
//!
//! BDK's wallet cannot hold any of this. Its `KeychainKind` is a closed pair of
//! external and internal, so there is no keychain a silent payment output could
//! belong to, and an output inserted by hand only reaches the fee graph without
//! ever becoming spendable. So this keeps its own tables — in BDK's own SQLite
//! file, through BDK's own migration helper, so there is still one file per
//! wallet directory and one schema version table describing all of it.
//!
//! Three things are stored: the keys, the outputs found with them, and how far
//! the chain has been searched. The watermark matters as much as the outputs —
//! without it every scan would start from the genesis block, and with a wrong
//! one a payment is skipped silently rather than loudly.

use anyhow::{Context, Result};
use bdk_wallet::bitcoin::secp256k1::{PublicKey, SecretKey};
use bdk_wallet::bitcoin::{Amount, OutPoint, ScriptBuf, Txid};
use bdk_wallet::rusqlite::{Connection, OptionalExtension, params};
use bdk_wallet::rusqlite_impl::migrate_schema;
use std::str::FromStr;

use crate::spreceive::ScanKeys;
use crate::spscan::Found;

const SCHEMA_NAME: &str = "kiss_sp";

const SCHEMA_V0: &str = "\
CREATE TABLE kiss_sp_keys ( \
    id INTEGER PRIMARY KEY CHECK (id = 0), \
    scan_sk BLOB NOT NULL, \
    spend_pk BLOB NOT NULL \
) STRICT; \
CREATE TABLE kiss_sp_outputs ( \
    txid TEXT NOT NULL, \
    vout INTEGER NOT NULL, \
    tweak BLOB NOT NULL, \
    script_pubkey BLOB NOT NULL, \
    amount INTEGER NOT NULL, \
    label INTEGER, \
    height INTEGER NOT NULL, \
    PRIMARY KEY (txid, vout) \
) STRICT; \
CREATE TABLE kiss_sp_watermark ( \
    id INTEGER PRIMARY KEY CHECK (id = 0), \
    height INTEGER NOT NULL \
) STRICT;";

/// Create the tables if they are not there yet. Safe to call on every open.
pub fn migrate(connection: &mut Connection) -> Result<()> {
    let tx = connection.transaction()?;
    migrate_schema(&tx, SCHEMA_NAME, &[SCHEMA_V0]).context("creating silent payment tables")?;
    tx.commit()?;
    Ok(())
}

/// Store the keys imported from KISS, replacing any previous pairing.
pub fn put_keys(connection: &mut Connection, keys: &ScanKeys) -> Result<()> {
    connection
        .execute(
            "INSERT INTO kiss_sp_keys (id, scan_sk, spend_pk) VALUES (0, ?1, ?2) \
             ON CONFLICT(id) DO UPDATE SET scan_sk = ?1, spend_pk = ?2",
            params![
                keys.scan.secret_bytes().to_vec(),
                keys.spend.serialize().to_vec()
            ],
        )
        .context("storing the silent payment keys")?;
    Ok(())
}

pub fn keys(connection: &Connection) -> Result<Option<ScanKeys>> {
    let row = connection
        .query_row(
            "SELECT scan_sk, spend_pk FROM kiss_sp_keys WHERE id = 0",
            [],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()
        .context("reading the silent payment keys")?;

    let Some((scan, spend)) = row else {
        return Ok(None);
    };
    Ok(Some(ScanKeys {
        scan: SecretKey::from_slice(&scan).context("stored scan key is not a key")?,
        spend: PublicKey::from_slice(&spend).context("stored spend key is not a key")?,
    }))
}

/// Record found outputs. Re-scanning a block must not duplicate them, so the
/// outpoint is the primary key and a repeat is an update rather than a row.
pub fn put_found(connection: &mut Connection, found: &[Found]) -> Result<()> {
    let tx = connection.transaction()?;
    for item in found {
        tx.execute(
            "INSERT INTO kiss_sp_outputs \
                 (txid, vout, tweak, script_pubkey, amount, label, height) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) \
             ON CONFLICT(txid, vout) DO UPDATE SET height = ?7",
            params![
                item.out.outpoint.txid.to_string(),
                item.out.outpoint.vout,
                item.out.tweak.secret_bytes().to_vec(),
                item.out.script_pubkey.to_bytes(),
                item.out.amount.to_sat(),
                item.out.label,
                item.height,
            ],
        )
        .context("storing a silent payment output")?;
    }
    tx.commit()?;
    Ok(())
}

/// One found output, read back.
#[derive(Debug)]
pub struct StoredOut {
    pub outpoint: OutPoint,
    pub tweak: SecretKey,
    pub script_pubkey: ScriptBuf,
    pub amount: Amount,
    pub label: Option<u32>,
    pub height: u32,
}

pub fn outputs(connection: &Connection) -> Result<Vec<StoredOut>> {
    let mut statement = connection.prepare(
        "SELECT txid, vout, tweak, script_pubkey, amount, label, height \
         FROM kiss_sp_outputs ORDER BY height, txid, vout",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, u32>(1)?,
            row.get::<_, Vec<u8>>(2)?,
            row.get::<_, Vec<u8>>(3)?,
            row.get::<_, u64>(4)?,
            row.get::<_, Option<u32>>(5)?,
            row.get::<_, u32>(6)?,
        ))
    })?;

    let mut out = Vec::new();
    for row in rows {
        let (txid, vout, tweak, spk, amount, label, height) = row?;
        out.push(StoredOut {
            outpoint: OutPoint::new(
                Txid::from_str(&txid).context("stored txid is malformed")?,
                vout,
            ),
            tweak: SecretKey::from_slice(&tweak).context("stored tweak is not a key")?,
            script_pubkey: ScriptBuf::from_bytes(spk),
            amount: Amount::from_sat(amount),
            label,
            height,
        });
    }
    Ok(out)
}

/// The outputs worth offering to a spend, oldest first.
///
/// The store's own opinion, and only that: confirmed, and not the sentinel a
/// payment seen in the mempool is stored under. Whether a coin has already been
/// spent is Esplora's answer rather than this table's — a column here would go
/// stale the moment anything else moved the coin, and a wrong "unspent" is a
/// transaction that dies at broadcast after a walk to the device.
///
/// An unconfirmed output is excluded for a reason beyond depth: it was matched
/// against a mempool transaction rather than a block, and if that transaction is
/// replaced the tweak describes a coin that never existed.
pub fn candidates(connection: &Connection) -> Result<Vec<StoredOut>> {
    Ok(outputs(connection)?
        .into_iter()
        .filter(|out| out.height != crate::spscan::UNCONFIRMED)
        .collect())
}

/// Whether this outpoint is a silent payment this wallet found.
///
/// `broadcast` needs it: an SP input is not in BDK's UTXO set, so the check that
/// every input belongs to this wallet has to ask here too.
pub fn contains(connection: &Connection, outpoint: OutPoint) -> Result<bool> {
    let count: u32 = connection
        .query_row(
            "SELECT COUNT(*) FROM kiss_sp_outputs WHERE txid = ?1 AND vout = ?2",
            params![outpoint.txid.to_string(), outpoint.vout],
            |row| row.get(0),
        )
        .context("looking up a silent payment output")?;
    Ok(count > 0)
}

/// The last height searched, if any.
pub fn watermark(connection: &Connection) -> Result<Option<u32>> {
    connection
        .query_row(
            "SELECT height FROM kiss_sp_watermark WHERE id = 0",
            [],
            |row| row.get(0),
        )
        .optional()
        .context("reading the scan watermark")
}

pub fn set_watermark(connection: &mut Connection, height: u32) -> Result<()> {
    connection
        .execute(
            "INSERT INTO kiss_sp_watermark (id, height) VALUES (0, ?1) \
             ON CONFLICT(id) DO UPDATE SET height = ?1",
            params![height],
        )
        .context("recording the scan watermark")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bdk_sp::receive::SpOut;
    use bdk_wallet::bitcoin::hashes::Hash;
    use bdk_wallet::bitcoin::secp256k1::Secp256k1;

    fn connection() -> Connection {
        let mut connection = Connection::open_in_memory().unwrap();
        migrate(&mut connection).unwrap();
        connection
    }

    fn keys_fixture() -> ScanKeys {
        let secp = Secp256k1::new();
        ScanKeys {
            scan: SecretKey::from_slice(&[0x11; 32]).unwrap(),
            spend: SecretKey::from_slice(&[0x22; 32])
                .unwrap()
                .public_key(&secp),
        }
    }

    fn found_fixture(vout: u32, height: u32) -> Found {
        Found {
            height,
            out: SpOut {
                outpoint: OutPoint::new(Txid::all_zeros(), vout),
                tweak: SecretKey::from_slice(&[0x33; 32]).unwrap(),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51, 0x20]),
                amount: Amount::from_sat(10_000),
                label: None,
            },
        }
    }

    #[test]
    fn migrating_twice_is_harmless() {
        let mut connection = connection();
        migrate(&mut connection).expect("a second open must not fail");
    }

    #[test]
    fn an_unpaired_wallet_has_no_keys() {
        assert!(keys(&connection()).unwrap().is_none());
    }

    #[test]
    fn keys_survive_a_round_trip() {
        let mut connection = connection();
        put_keys(&mut connection, &keys_fixture()).unwrap();
        assert_eq!(keys(&connection).unwrap().unwrap(), keys_fixture());
    }

    #[test]
    fn re_pairing_replaces_rather_than_accumulates() {
        let mut connection = connection();
        put_keys(&mut connection, &keys_fixture()).unwrap();

        let secp = Secp256k1::new();
        let other = ScanKeys {
            scan: SecretKey::from_slice(&[0x44; 32]).unwrap(),
            spend: SecretKey::from_slice(&[0x55; 32])
                .unwrap()
                .public_key(&secp),
        };
        put_keys(&mut connection, &other).unwrap();
        assert_eq!(keys(&connection).unwrap().unwrap(), other);
    }

    #[test]
    fn rescanning_a_block_does_not_duplicate_its_outputs() {
        let mut connection = connection();
        put_found(&mut connection, &[found_fixture(0, 100)]).unwrap();
        put_found(&mut connection, &[found_fixture(0, 100)]).unwrap();
        assert_eq!(outputs(&connection).unwrap().len(), 1);
    }

    #[test]
    fn outputs_survive_a_round_trip() {
        let mut connection = connection();
        put_found(&mut connection, &[found_fixture(1, 318_745)]).unwrap();

        let stored = outputs(&connection).unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].outpoint.vout, 1);
        assert_eq!(stored[0].amount, Amount::from_sat(10_000));
        assert_eq!(stored[0].height, 318_745);
        assert_eq!(stored[0].tweak.secret_bytes(), [0x33; 32]);
        assert_eq!(stored[0].label, None);
    }

    #[test]
    fn the_watermark_starts_absent_and_then_advances() {
        let mut connection = connection();
        assert!(watermark(&connection).unwrap().is_none());
        set_watermark(&mut connection, 318_745).unwrap();
        assert_eq!(watermark(&connection).unwrap(), Some(318_745));
        set_watermark(&mut connection, 318_800).unwrap();
        assert_eq!(watermark(&connection).unwrap(), Some(318_800));
    }
}
