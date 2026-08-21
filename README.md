<p align="center">
  <img src="assets/kiss-bdk-gallery.png" alt="KISS plus BDK" width="720">
</p>

# KISS-BDK

**Air-gapped Bitcoin transactions powered by BDK**

KISS-BDK is an experimental Rust coordinator for the Bitcoin test networks —
Testnet4 and Signet. Bitcoin Dev Kit manages the online, watch-only wallet while
KISS, an air-gapped hardware signer written in C, keeps the private keys offline
and approves signatures.

## Live flow

`Pair` → `Sync` → `Build` → `Sign` → `Verify` → `Broadcast`

- **BDK** manages the descriptor, addresses, wallet state, coin selection,
  fees, change, PSBT creation, finalization, and broadcasting.
- **KISS** verifies the transaction offline, signs it, and returns the signed
  PSBT as animated BC-UR QR.

```text
Testnet4 or Signet / Esplora ↔ Rust + BDK ↔ PSBT over QR ↔ KISS C signer
```

## What BDK does

The coordinator uses:

- `bdk_wallet` for the watch-only descriptor wallet, receive/change derivation,
  SQLite persistence, balances, UTXOs, transaction building, and PSBT
  finalization.
- `bdk_esplora` for chain scanning and transaction broadcasting over HTTPS.

BDK is the wallet engine, not the network server and not the signer.

## Networks

Choose one at `init`; it is fixed for the life of that wallet directory.

```sh
kiss-bdk init --network signet --scan-qr
```

| `--network` | Chain | Default Esplora | Faucet |
| --- | --- | --- | --- |
| `testnet4` (default) | Testnet4 | `https://mempool.space/testnet4/api` | browser only |
| `signet` | Signet (BIP-325) | `https://mempool.space/signet/api` | browser only |
| `mutinynet` | Mutinynet, a custom signet | `https://mutinynet.com/api` | `kiss-bdk faucet` (needs a token) |

The signer needs no change for any of them. Its account is BIP-44 coin type
`1h`, the keyspace shared by the whole Bitcoin test family, so one KISS
descriptor derives the same addresses on all three. Mutinynet is a separate
chain from the default signet despite sharing its address format; its blocks
are about 30 seconds apart, so a demo confirmation arrives while you are still
on stage.

Mainnet and regtest are not selectable. Override the backend with
`--esplora URL` at `init` if you would rather use your own.

Because all three share one address format, a `tb1...` address is valid on every
one of them and neither this CLI nor KISS can tell them apart. Keep one
`--wallet-dir` per network; a wallet directory is pinned to the network it was
created on, and `init` refuses to overwrite an existing one.

## Silent payments

Send to a BIP-352 address by passing it to `create`:

```sh
kiss-bdk create --to tsp1… --sats 10000 --qr
```

A silent payment output script is derived from the *input private keys*, so a
watch-only wallet cannot compute it. BIP-375 carries the recipient's scan and
spend keys in the PSBT and lets KISS fill the script in, which is why these
transactions leave as a PSBTv2 — a v0 PSBT cannot express an output whose script
is not yet known.

BDK still does all the wallet work: it selects coins and computes change and the
fee against a taproot placeholder of exactly the size the real output will be.

Nothing about that output is taken on trust. Before broadcasting, `scan` and
`broadcast` check three things: that KISS returned the same transaction it was
given apart from the scripts it was asked to fill in, that its BIP-374 DLEQ
proof shows the ECDH share came from these inputs, and that re-deriving the
output from that share reproduces the script KISS wrote. Only all three together
show the payment reaches the address you typed.

`inspect` reads either PSBT version and names the silent payment outputs.

**Sending only.** Receiving requires scanning every block for tweak data, which
the Esplora backend cannot serve.

## Topping up

```sh
kiss-bdk faucet --sats 100000
```

This derives the wallet's next unused receive address, prints it, and asks that
network's faucet for coins. `--address` tops up some other address instead.

No public faucet on these networks will fund an anonymous script, so what the
command can do depends on the network:

- **Mutinynet** is the only one with a callable API, and it requires an
  `Authorization: Bearer` token. Sign in with GitHub once at
  <https://faucet.mutinynet.com/>, then pass `--token` or export
  `MUTINYNET_FAUCET_TOKEN` and the top-up is a single command. It sends at most
  1,000,000 sats per request. The token is never printed or persisted.
- **Testnet4 and Signet** faucets are all Cloudflare-Turnstile-protected, so the
  command prints the address and the faucet links for you to paste into a
  browser rather than pretending it can claim.

## Build

Requirements: Rust, a C compiler, and a webcam. The current hardware flow is tested on macOS.

```sh
cargo test --locked
cargo build --release --locked
```

The executable is `target/release/kiss-bdk`.

## QR-only demo

Create a fresh runtime directory:

```sh
mkdir -p hackathon-demo
cd hackathon-demo
```

On KISS, enable Testnet, unlock the wallet, then open **PAIR COORDINATOR → DESKTOP**.

```sh
../target/release/kiss-bdk init --scan-qr
../target/release/kiss-bdk sync
../target/release/kiss-bdk address
```

Compare the address on KISS, fund it with that network's coins, and sync again. A pending faucet payment is sufficient for the demo.

```sh
../target/release/kiss-bdk sync
../target/release/kiss-bdk address
```

Copy the new address as the self-send destination:

```sh
KISS_DEST='tb1q...'
../target/release/kiss-bdk create \
  --to "$KISS_DEST" --sats 10000 --fee-rate 2 --qr
```

On KISS choose **SIGN → SCAN QR**, review the transaction, and sign. While KISS displays the animated signed QR:

```sh
../target/release/kiss-bdk scan
../target/release/kiss-bdk broadcast signed.psbt \
  --original unsigned.psbt --dry-run
../target/release/kiss-bdk broadcast signed.psbt \
  --original unsigned.psbt
```

The CLI retains `unsigned.psbt`, confirms that KISS returned the same
transaction, verifies the ECDSA signatures, and asks BDK to finalize it before broadcasting.

## QR implementation

- Computer → KISS: static Base64 PSBT QR.
- KISS → computer: animated BC-UR `crypto-psbt` QR.
- Desktop recognition: the vendored `k_quirc` decoder also used by KISS.

## Proof

The full physical flow produced this accepted Testnet4 transaction:

[8b3473f888ff1f896f9112e2886bd63d3d2595456f57d3009038f5de173f8659](https://mempool.space/testnet4/tx/8b3473f888ff1f896f9112e2886bd63d3d2595456f57d3009038f5de173f8659)

