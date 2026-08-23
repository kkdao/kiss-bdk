<p align="center">
  <img src="assets/kiss-bdk-gallery.png" alt="KISS plus BDK" width="720">
</p>

# KISS-BDK

**Air-gapped Bitcoin transactions powered by BDK**

An experimental Rust coordinator for the Bitcoin test networks. BDK runs the
online watch-only wallet; KISS, an air-gapped C signer, holds the keys and
approves signatures. They only ever talk in QR codes.

```text
Testnet4 / Signet / Mutinynet ↔ Esplora ↔ Rust + BDK ↔ QR ↔ KISS
```

`Pair` → `Sync` → `Build` → `Sign` → `Verify` → `Broadcast`

BDK does the wallet work — descriptors, addresses, coin selection, fees,
change, PSBTs, finalization, broadcast — via `bdk_wallet`, `bdk_esplora` and
`bdk_sp`. It is not the server and not the signer.

## Networks

Chosen at `init` and fixed for the life of that wallet directory.

| `--network` | Default Esplora | Faucet |
| --- | --- | --- |
| `testnet4` (default) | `https://mempool.space/testnet4/api` | browser only |
| `signet` | `https://mempool.space/signet/api` | browser only |
| `mutinynet` | `https://mutinynet.com/api` | `kiss-bdk faucet --token …` |

All three are BIP-44 coin type `1h`, so one KISS descriptor derives the same
addresses on all of them — which also means a `tb1…` address is valid on every
one and nothing can tell them apart. Keep one `--wallet-dir` per network.

Mutinynet's blocks are ~30 seconds apart, so it is the one to demo on. Mainnet
and regtest are not selectable. Override the backend with `--esplora URL`.

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

On KISS choose **SIGN → SCAN QR**, review, sign. While it displays the animated
signed QR:

```sh
kiss-bdk scan
kiss-bdk broadcast signed.psbt --original unsigned.psbt --dry-run
kiss-bdk broadcast signed.psbt --original unsigned.psbt
```

`broadcast` re-checks that KISS returned the transaction it was given, verifies
every signature, and finalizes before anything reaches the network.

## Silent payments

### Sending to one

```sh
kiss-bdk create --to tsp1… --sats 10000 --qr
```

The output script is derived from the *input private keys*, so a watch-only
wallet cannot compute it. BIP-375 puts the recipient's keys in the PSBT and lets
KISS fill the script in — which is why these leave as a PSBTv2, since a v0
cannot express an output whose script is not yet known. BDK still sizes the fee
and change against a taproot placeholder of the exact final size.

Nothing is trusted. Before broadcast, three things are checked: KISS returned
the same transaction, its BIP-374 DLEQ proof shows the ECDH share came from
these inputs, and re-deriving the output reproduces the script KISS wrote.

### Receiving

```sh
kiss-bdk sp-pair --scan-qr     # import KISS's scan key
kiss-bdk sp-address            # the tsp1… code to hand out
kiss-bdk sp-scan               # search the chain
kiss-bdk sp-balance            # what was found
```

Nothing on chain names the recipient, so every block has to be tested against
the scan key. That test needs each transaction's input key sum, which Esplora
will not serve — so tweaks come from a [BlindBit] server and are matched
locally. The server learns which blocks you scanned, never which outputs
matched.

`sp-pair` reads KISS's **SCAN KEY** export: the scan private key, never the
spend key. This coordinator can see payments and can never move them. It is the
only secret the wallet directory holds, and mainnet is unreachable here, so it
can only ever be a testnet key.

A tweak server only publishes for blocks it has indexed, so `sp-scan` cannot see
a payment until it is mined. `sp-scan --tx <txid>` derives the tweak from that
transaction's own inputs instead and needs no server at all.

### Spending what was received

```sh
kiss-bdk create --to tb1q… --sats 10000 --from-sp --qr
```

A received silent payment pays `B_spend + t*G`, so its key is the spend key plus
the output's tweak — not a BIP-32 child of anything, and in no descriptor. The
tweak travels as BIP-376's `PSBT_IN_SP_TWEAK` and KISS adds it to the spend key
it kept. Every candidate is re-derived here first and dropped unless its tweak
reproduces the script the output pays; the returned Schnorr signature is
verified against a key worked out locally.

**Silent payment coins are spent on their own.** KISS refuses a transaction
mixing them with ordinary ones: BIP-143 commits only to the amount of the input
being signed, so a coordinator with two inputs can run two truthful signing
sessions and combine them into a transaction paying a fee neither screen showed.
BIP-341 hashes every input amount, so an all-taproot spend proves its own fee. A
P2WPKH input does not. If silent payments cannot cover a payment, the ordinary
balance cannot make up the difference.

Change goes to an ordinary address for now. Keeping it in the silent payment
keyspace needs BIP-376 inputs and BIP-375 outputs in one PSBT — the signer
supports that shape, this does not yet.

[BlindBit]: https://github.com/setavenger/blindbit-oracle

## Topping up

```sh
kiss-bdk faucet --sats 100000
```

Derives the next unused address and asks that network's faucet for coins.
Mutinynet is the only one with a callable API, and it needs a bearer token —
sign in once at <https://faucet.mutinynet.com/>, then pass `--token` or export
`MUTINYNET_FAUCET_TOKEN`. Testnet4 and Signet faucets are Turnstile-protected,
so the command prints the address and the links instead of pretending.

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
  Its `tsp1` recipient uses throwaway keys, so it can be checked from the
  receiving side too: deriving from that scan key reproduces the broadcast
  script `tb1p74frpnrdrq2mt09xdnrje0ewvctp4g2wzra0a8xpdmuc3lhuafast97k48`.
- Silent payment **spent**, Mutinynet —
  [3e0fdd39…54ab80](https://mutinynet.com/tx/3e0fdd3965f541d25771c732d42b459759b6fd643d07bc1843a756f9de54ab80).
  One `v1_p2tr` key-path input, one 64-byte signature — the shape a BIP-376
  spend must have, since the key is `spend + tweak` with no taproot tweak on
  top.
