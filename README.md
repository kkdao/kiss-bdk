<p align="center">
  <img src="assets/kiss-bdk-gallery.png" alt="KISS plus BDK" width="720">
</p>

# KISS-BDK

**Air-gapped Bitcoin transactions powered by BDK**

An experimental Rust coordinator for the Bitcoin test networks. BDK runs the
online watch-only wallet; KISS, an air-gapped C signer, holds the keys. They
only ever talk in QR codes.

`Pair` → `Sync` → `Build` → `Sign` → `Verify` → `Broadcast`

## Networks

Chosen at `init` and fixed for that wallet directory.

| `--network` | Default Esplora | Faucet |
| --- | --- | --- |
| `testnet4` (default) | `mempool.space/testnet4` | browser only |
| `signet` | `mempool.space/signet` | browser only |
| `mutinynet` | `mutinynet.com` | `kiss-bdk faucet --token …` |
| `regtest` | `127.0.0.1:3000` | mine to the address |

All four are coin type `1h`, so one descriptor derives the same addresses on all
of them — which also means a `tb1…` address is valid on three of them and
nothing tells them apart. Keep one `--wallet-dir` per network. Mainnet is not
selectable. Mutinynet's 30-second blocks make it the one to demo on.

## Quick start

On KISS: enable Testnet, unlock, then **PAIR COORDINATOR → DESKTOP**.

```sh
kiss-bdk init --network mutinynet --scan-qr
kiss-bdk sync
kiss-bdk address
```

Fund that address, `sync` again, then send:

```sh
kiss-bdk create --to tb1q… --sats 10000 --qr
```

On KISS choose **SIGN → SCAN QR**, review, sign. While it shows the animated
signed QR:

```sh
kiss-bdk scan
kiss-bdk broadcast signed.psbt --original unsigned.psbt --dry-run
kiss-bdk broadcast signed.psbt --original unsigned.psbt
```

`broadcast` re-checks that KISS returned the transaction it was given, verifies
every signature, and finalizes before anything reaches the network.

Fees default to 2 sat/vB. On a busy test network pass `--fee-rate`.

## Silent payments

### Sending to one

```sh
kiss-bdk create --to tsp1… --sats 10000 --qr
```

The output script comes from the *input private keys*, so a watch-only wallet
cannot compute it. BIP-375 puts the recipient's keys in the PSBT and lets the
signer fill the script in. Three things are checked before broadcast: the same
transaction came back, its BIP-374 DLEQ proof is valid, and re-deriving the
output reproduces the script the signer wrote.

### Receiving

```sh
kiss-bdk sp-pair --scan-qr     # import KISS's scan key
kiss-bdk sp-address            # the tsp1… code to hand out
kiss-bdk sp-scan               # search the chain
kiss-bdk sp-balance            # what was found
```

Nothing on chain names the recipient, so every block has to be tested against
the scan key — and that test needs each transaction's input key sum, which
Esplora will not serve. So tweaks come from a [BlindBit] server and are matched
locally. The server learns which blocks you scanned, never which outputs
matched.

`sp-pair` imports the scan private key and never the spend key: this wallet can
see payments and can never move them.

`sp-scan --tx <txid>` works before a payment is mined, deriving the tweak from
the transaction itself instead of asking a server.

### From a node of your own

```sh
git clone https://github.com/reardencode/rbitcoin && cd rbitcoin
cargo build --release -p rbitcoin-node
./target/release/rbitcoin-node --datadir ~/rbitcoin-signet --network signet \
  --shindex --sptweaks \
  --electrum-listen 127.0.0.1:50001 --esplora-listen 127.0.0.1:3000
```

```sh
kiss-bdk sp-scan --electrum 127.0.0.1:50001
```

[rbitcoin] serves the same tweaks over the Electrum protocol, so nobody has to
be asked at all. Each tweak arrives already attached to its transaction, so
**scanning fetches no blocks** — on signet that was 46 s against BlindBit's
5 m 23 s.

It serves nothing until fully synced: signet cost 19 GB, about 1½ hours to sync
and 18 minutes to index. `--network regtest` comes up in seconds.

Amounts are still checked against the chain before being stored. A value ends up
in the `witness_utxo` of the spend that moves the coin and BIP-341 signs over
it, so a wrong one is a valid signature over a lie.

### Which tweak source

| | who matches | what the server learns |
| --- | --- | --- |
| your own node | you | nothing |
| BlindBit | you | which blocks you scanned |
| Frigate (Sparrow) | **the server** | **every payment you receive** |

[Frigate] is not a faster oracle, it is a different trust model: the client
hands it the **scan private key** and the server does the matching. The other
two send you tweaks and your keys never leave. That is the whole comparison.

[Frigate]: https://github.com/sparrowwallet/frigate

### Spending what was received

```sh
kiss-bdk create --to tb1q… --sats 10000 --from-sp --qr
```

A received silent payment pays `B_spend + t*G` — the spend key plus that
output's tweak, which is a BIP-32 child of nothing and lives in no descriptor.
The tweak travels as BIP-376's `PSBT_IN_SP_TWEAK`, and the signature that comes
back is verified against a key worked out locally.

**Silent payment coins are spent on their own.** A transaction mixing them with
ordinary coins is refused: BIP-341 hashes every input amount, so an all-taproot
spend proves its own fee, and a P2WPKH input does not. If the silent payment
balance cannot cover a payment, the ordinary balance cannot make up the
difference.

Change goes to an ordinary address for now.

[BlindBit]: https://github.com/setavenger/blindbit-oracle
[rbitcoin]: https://github.com/reardencode/rbitcoin

## Topping up

```sh
kiss-bdk faucet --sats 100000
```

Mutinynet is the only network with a callable faucet API, and it needs a bearer
token — sign in at <https://faucet.mutinynet.com/>, then pass `--token` or export
`MUTINYNET_FAUCET_TOKEN`. The others are captcha-protected, so the command
prints the address and the links instead of pretending.

## Testing another signer

Nothing here is tied to KISS except the QR commands. `create` writes a PSBT file
and `broadcast` reads one back, so any signer that can load a file will do.

You need a signer that implements **BIP-375** (paying a `tsp1…` code) or
**BIP-376** (spending what one paid you). As of writing no other signing device
ships either — SeedSigner, Krux, Specter-DIY and Jade included — so this is
mostly a way to build one.

Use regtest and you need no faucet and no waiting for blocks.

**1.** Point a wallet at your signer's descriptor:

```sh
kiss-bdk init --network regtest --descriptor "<your signer's descriptor>"
```

**2.** Build the transaction:

```sh
kiss-bdk create --to tsp1… --sats 10000 --out unsigned.psbt
```

**3.** Sign `unsigned.psbt` on your device, however it does that, and save the
result as `signed.psbt`.

**4.** Check it:

```sh
kiss-bdk broadcast signed.psbt --original unsigned.psbt --dry-run
```

**5.** Fix whatever it names, and repeat.

Step 4 is the point of all this. It takes nothing on trust — same transaction
back, DLEQ proof, re-derived output script, every signature checked against a
key worked out here — and it says which part failed, before anything reaches
the network.

The exact bytes `create` emits are asserted in
[tests/sp_spend_psbt.rs](tests/sp_spend_psbt.rs), so it is a specification you
can diff against rather than a description.
[tests/sp_spend_fixtures.rs](tests/sp_spend_fixtures.rs) writes PSBTs for a
device's own test harness, including one whose tweak does not reproduce the
output key — which a correct signer must refuse.

## Build

```sh
cargo test --locked
cargo build --release --locked
```

Needs Rust, a C compiler, and a webcam. Tested on macOS.

## QR

- Computer → KISS: static Base64 PSBT QR. A PSBTv2 is larger than a v0, so
  `create --qr` stops past roughly three inputs rather than emit a frame the
  camera cannot read.
- KISS → computer: animated BC-UR `crypto-psbt`.
- Decoding uses the vendored `k_quirc`, the same decoder KISS runs.

## Proof

Every flow below ran over the physical hardware.

- Ordinary send, Testnet4 —
  [8b3473f8…3f8659](https://mempool.space/testnet4/tx/8b3473f888ff1f896f9112e2886bd63d3d2595456f57d3009038f5de173f8659)
- Silent payment **sent**, Signet —
  [3a6801e9…0cd12a](https://mempool.space/signet/tx/3a6801e9b5a7398406621299aefc8a2c915d20de612f21a26011972aa90cd12a).
  Its recipient uses throwaway keys, so it checks from the receiving side too.
- Silent payment **spent**, Mutinynet —
  [3e0fdd39…54ab80](https://mutinynet.com/tx/3e0fdd3965f541d25771c732d42b459759b6fd643d07bc1843a756f9de54ab80).
  One `v1_p2tr` key-path input, one 64-byte signature.
- **The whole loop**, Signet, on a node of this wallet's own: KISS signed a
  payment to this wallet's own code
  ([339b903e…df21d3fb](https://mempool.space/signet/tx/339b903ee339a864a6e54dfc87c459f86fc213ec319568edfbdfcb3adf21d3fb),
  block 319011), `sp-scan --electrum` found it through that node's BIP-352
  index, and KISS spent it back
  ([e6543ce2…2dd18560](https://mempool.space/signet/tx/e6543ce27be85b688e57dd57d75de92450ecbb138c5ea443e0d0de6a2dd18560),
  block 319014) as a `v1_p2tr` key-path input with one 64-byte witness item.

Scanning the same signet range through that node and through the public BlindBit
oracle finds the same output — same outpoint, same amount, same block. Two
independent sources agreeing is the check that matters; 46 s against 5 m 23 s is
the difference in cost.

[tests/rbitcoin_regtest.rs](tests/rbitcoin_regtest.rs) runs the whole thing
unattended against a local node: mines a coin, pays a real silent payment to
itself, and finds it again knowing only the recipient's keys.
