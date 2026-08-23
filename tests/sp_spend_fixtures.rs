//! Write BIP-376 spend PSBTs for the signer's own host harness to judge.
//!
//! Unit tests here can prove the bytes are what this coordinator meant. Only
//! the signer's parser can say whether they are what it accepts, and it does
//! not have to be a physical one: `sim/check_sd_psbts.sh` in the signer repo
//! compiles `kiss_psbt.c` and `kiss_sp.c` with clang and runs the real
//! `kiss_psbt_load` and `kiss_psbt_sign` over files on disk.
//!
//! That harness opens the `abandon abandon … about` development seed on
//! testnet, so a fixture has to be built for *that* wallet's keys or the device
//! correctly refuses it as someone else's coin. Those keys are published in the
//! signer's own `main/sp_spend_vectors.h`, which is why this needs no BIP-39
//! and no derivation: `SPV_LABEL_SPEND_PUB` is the spend key, and the tweak and
//! output key pairs come from the same header.
//!
//! Ignored by default and gated on an output directory, so `cargo test` stays
//! hermetic:
//!
//! ```sh
//! KISS_FIXTURE_DIR=/tmp/sp-fixtures \
//!   cargo test --test sp_spend_fixtures -- --ignored --nocapture
//! ```

use std::path::PathBuf;
use std::str::FromStr;

use bdk_wallet::bitcoin::bip32::Fingerprint;
use bdk_wallet::bitcoin::secp256k1::{PublicKey, SecretKey, XOnlyPublicKey};
use bdk_wallet::bitcoin::{Address, Amount, FeeRate, OutPoint, ScriptBuf, Sequence, Txid};
use bdk_wallet::test_utils::new_wallet_and_funding_update;
use kiss_bdk::spsend::build_v2;
use kiss_bdk::spspend::{self, SATISFACTION_WEIGHT, SpCoin};
use kiss_bdk::spstore::StoredOut;

/// The same descriptor `tests/cli.rs` uses. Its origin is `73c5da0a`, the
/// development seed's master fingerprint, so change re-derives on the device.
const KISS_DESC: &str = "wpkh([73c5da0a/84h/1h/0h]tpubDC8msFGeGuwnKG9Upg7DM2b4DaRqg3CUZa5g8v2SRQ6K4NSkxUgd7HsL2XVWbVm39yBA4LAxysQAm397zwQSQoQgewGiYZqrA9DsP4zbQ1M/<0;1>/*)";
const DESTINATION: &str = "tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl";

/// `SPV_LABEL_SPEND_PUB`: the development seed's `m/352h/1h/0h/0h/0`.
const SPEND_PUB: [u8; 33] = [
    0x02, 0x83, 0x30, 0x85, 0xc9, 0xa7, 0x16, 0xd3, 0x6b, 0x46, 0x75, 0x52, 0xc0, 0x0d, 0x6a, 0xa8,
    0xbd, 0x42, 0xe3, 0x9a, 0xdb, 0xe9, 0x8b, 0x05, 0xbc, 0x20, 0x31, 0x10, 0x17, 0x71, 0x92, 0xf7,
    0x02,
];

/// `SPV_SPEND_EVEN_TWEAK` and the output key it produces.
const EVEN_TWEAK: [u8; 32] = [0x02; 32];
const EVEN_OUTKEY: [u8; 32] = [
    0x83, 0x2e, 0xac, 0x66, 0xec, 0xbc, 0xfc, 0x00, 0x75, 0x8a, 0x69, 0xb1, 0x7f, 0x25, 0xd4, 0x82,
    0xe6, 0xc4, 0xff, 0x4a, 0x55, 0xb4, 0xac, 0xfc, 0x83, 0x1c, 0x15, 0x8f, 0x90, 0xe5, 0x7a, 0x25,
];

/// `SPV_SPEND_ODD_*`: the other Y parity.
const ODD_TWEAK: [u8; 32] = [0x01; 32];
const ODD_OUTKEY: [u8; 32] = [
    0xbd, 0x57, 0x9e, 0x15, 0x5b, 0x56, 0xad, 0xe0, 0xc4, 0x9b, 0xd6, 0xc6, 0x2a, 0xc7, 0xa1, 0x20,
    0x22, 0x4d, 0xba, 0xfc, 0x3e, 0xf9, 0x45, 0x05, 0x59, 0x63, 0xc4, 0xe2, 0x20, 0x16, 0xd2, 0x8f,
];

fn spend() -> PublicKey {
    PublicKey::from_slice(&SPEND_PUB).unwrap()
}

fn coin(vout: u32, tweak: [u8; 32], outkey: [u8; 32], sats: u64) -> SpCoin {
    let key = XOnlyPublicKey::from_slice(&outkey).unwrap();
    let mut script = vec![0x51, 0x20];
    script.extend_from_slice(&key.serialize());
    let stored = StoredOut {
        outpoint: OutPoint::new(Txid::from_str(&"cd".repeat(32)).unwrap(), vout),
        tweak: SecretKey::from_slice(&tweak).unwrap(),
        script_pubkey: ScriptBuf::from_bytes(script),
        amount: Amount::from_sat(sats),
        label: None,
        height: 200,
    };
    SpCoin::checked(&stored, &spend()).unwrap()
}

/// A coin whose tweak does *not* reproduce its script. `SpCoin::checked` would
/// refuse this, which is the point of the fixture — the device must refuse it
/// too, so it is assembled behind the check rather than through it.
fn foreign_coin() -> SpCoin {
    // The even output key with a tweak that never produced it. Built by
    // claiming ownership of the even coin and then substituting the tweak in
    // the PSBT, which is exactly the attack the device's guard exists for.
    coin(0, EVEN_TWEAK, EVEN_OUTKEY, 100_000)
}

fn build(coins: &[SpCoin], sats: u64) -> Vec<u8> {
    let origin = spspend::spend_origin(Fingerprint::from_str("73c5da0a").unwrap());
    let (external, internal) = kiss_bdk::split_kiss_descriptor(KISS_DESC).unwrap();
    let (mut wallet, _, funding) = new_wallet_and_funding_update(&external, Some(&internal));
    wallet.apply_update(funding).unwrap();

    let destination = Address::from_str(DESTINATION)
        .unwrap()
        .assume_checked()
        .script_pubkey();

    let mut builder = wallet.build_tx();
    for c in coins {
        builder
            .add_foreign_utxo_with_sequence(
                c.outpoint,
                spspend::psbt_input(c, &spend(), &origin),
                SATISFACTION_WEIGHT,
                Sequence::ENABLE_RBF_NO_LOCKTIME,
            )
            .unwrap();
    }
    builder.manually_selected_only();
    builder
        .add_recipient(destination, Amount::from_sat(sats))
        .fee_rate(FeeRate::from_sat_per_vb(2).unwrap());
    let v0 = builder.finish().unwrap();
    build_v2(&v0, &[]).unwrap()
}

/// Replace the 32-byte tweak value on the first input, leaving everything else
/// intact. The device must recompute the key and refuse.
fn substitute_tweak(mut bytes: Vec<u8>, replacement: [u8; 32]) -> Vec<u8> {
    let needle = [
        &[0x01_u8, spspend::PSBT_IN_SP_TWEAK, 0x20][..],
        &EVEN_TWEAK[..],
    ]
    .concat();
    let at = bytes
        .windows(needle.len())
        .position(|window| window == needle)
        .expect("the tweak pair must be present");
    bytes[at + 3..at + 3 + 32].copy_from_slice(&replacement);
    bytes
}

#[test]
#[ignore = "writes fixtures for the signer's host harness; needs KISS_FIXTURE_DIR"]
fn write_spend_fixtures() {
    let dir = PathBuf::from(
        std::env::var("KISS_FIXTURE_DIR").expect("set KISS_FIXTURE_DIR to an output directory"),
    );
    std::fs::create_dir_all(&dir).unwrap();

    let files: Vec<(&str, Vec<u8>)> = vec![
        // Must load READY and sign, leaving a 64-byte tap key signature.
        (
            "01-sp-spend-1in.psbt",
            build(&[coin(0, EVEN_TWEAK, EVEN_OUTKEY, 100_000)], 50_000),
        ),
        // Two inputs, both silent payments: the exemption from the
        // unproven-amounts refusal applies only when every input is one.
        (
            "02-sp-spend-2in.psbt",
            build(
                &[
                    coin(0, EVEN_TWEAK, EVEN_OUTKEY, 100_000),
                    coin(1, ODD_TWEAK, ODD_OUTKEY, 100_000),
                ],
                150_000,
            ),
        ),
        // Both output key parities in one transaction.
        (
            "03-sp-spend-odd.psbt",
            build(&[coin(1, ODD_TWEAK, ODD_OUTKEY, 100_000)], 50_000),
        ),
        // A tweak that does not reproduce the key being spent. The device must
        // STOP with "not this wallet's" rather than sign onto a foreign key.
        (
            "04-sp-spend-foreign-tweak.psbt",
            substitute_tweak(build(&[foreign_coin()], 50_000), [0x77; 32]),
        ),
    ];

    for (name, bytes) in &files {
        let path = dir.join(name);
        std::fs::write(&path, bytes).unwrap();
        println!("wrote {} ({} bytes)", path.display(), bytes.len());
    }
}

/// Verify the signatures the *device's own code* produced.
///
/// The other half of the loop: `write_spend_fixtures` emits what this
/// coordinator builds, the signer's host harness signs it, and this reads the
/// result back through the same verify → finalize → extract path `broadcast`
/// uses. Nothing about the signature is taken on trust — the key it is checked
/// against is re-derived here from the tweak and the spend key.
///
/// ```sh
/// KISS_FIXTURE_DIR=/tmp/sp-fixtures \
///   cargo test --test sp_spend_fixtures verify_device -- --ignored --nocapture
/// ```
#[test]
#[ignore = "reads PSBTs signed by the signer's host harness; needs KISS_FIXTURE_DIR"]
fn verify_device_signed_fixtures() {
    use kiss_bdk::spsend::to_v0;
    use psbt_v2::v2::Psbt as PsbtV2;

    let dir = PathBuf::from(
        std::env::var("KISS_FIXTURE_DIR").expect("set KISS_FIXTURE_DIR to the fixture directory"),
    );
    let cases: Vec<(&str, Vec<SpCoin>)> = vec![
        (
            "01-sp-spend-1in.psbt.signed",
            vec![coin(0, EVEN_TWEAK, EVEN_OUTKEY, 100_000)],
        ),
        (
            "02-sp-spend-2in.psbt.signed",
            vec![
                coin(0, EVEN_TWEAK, EVEN_OUTKEY, 100_000),
                coin(1, ODD_TWEAK, ODD_OUTKEY, 100_000),
            ],
        ),
        (
            "03-sp-spend-odd.psbt.signed",
            vec![coin(1, ODD_TWEAK, ODD_OUTKEY, 100_000)],
        ),
    ];

    for (name, coins) in cases {
        let bytes = std::fs::read(dir.join(name))
            .unwrap_or_else(|_| panic!("{name} is missing; run the signer's harness first"));
        let v2 = PsbtV2::deserialize(&bytes).expect("the signed PSBT must parse strictly");
        let mut psbt = to_v0(&v2).unwrap();

        let sp = spspend::sp_inputs(&psbt, &coins).unwrap();
        assert_eq!(sp.len(), coins.len());
        spspend::verify_signatures(&psbt, &sp).unwrap_or_else(|error| panic!("{name}: {error:#}"));
        spspend::finalize(&mut psbt, &sp).unwrap();

        for index in sp.keys() {
            let witness = psbt.inputs[*index].final_script_witness.as_ref().unwrap();
            assert_eq!(witness.len(), 1);
            assert_eq!(witness.iter().next().unwrap().len(), 64);
        }
        let tx = psbt.extract_tx().unwrap_or_else(|e| panic!("{name}: {e}"));
        println!("{name}: verified and extracted {}", tx.compute_txid());
    }
}
