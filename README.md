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
| `regtest` | `http://127.0.0.1:3000` | mine to the address |

All four are BIP-44 coin type `1h`, so one KISS descriptor derives the same
addresses on all of them. On the first three that also means a `tb1…` address is
valid on every one and nothing can tell them apart; regtest says `bcrt1…`, which
is the only one that cannot be mistaken. Keep one `--wallet-dir` per network.

Mutinynet's blocks are ~30 seconds apart, so it is the one to demo on. Mainnet
is not selectable. Override the backend with `--esplora URL`.

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

#### From a node of your own

```sh
kiss-bdk sp-scan --electrum 127.0.0.1:50001
```

[rbitcoin] indexes the same tweaks and serves them over the Electrum protocol,
so nobody has to be asked at all. Plain `cargo` builds it on macOS and Linux:

```sh
git clone https://github.com/reardencode/rbitcoin && cd rbitcoin
cargo build --release -p rbitcoin-node
./target/release/rbitcoin-node --datadir ~/rbitcoin-signet --network signet \
  --shindex --sptweaks \
  --electrum-listen 127.0.0.1:50001 --esplora-listen 127.0.0.1:3000
```

```sh
kiss-bdk init --network signet --scan-qr --esplora http://127.0.0.1:3000
kiss-bdk sp-scan --electrum 127.0.0.1:50001
```

It serves nothing until it has caught up — both listeners stay closed during
sync and the tweak index is built after it, so there is no partial-chain
shortcut. Signet cost 19 GB, ~1½ h to sync and ~18 min to index; pruning is a
stated non-goal. `--network regtest` comes up in seconds.

This is also faster, and not only because it is local. BlindBit publishes a bare
list of tweaks, so finding which transaction each belongs to means fetching the
whole block; the Electrum stream sends each tweak already attached to its txid
and to that transaction's taproot outputs, which is the whole of what the match
needs. **Scanning this way fetches no blocks.**

Amounts are still not taken on trust. A tweak needs none — it either re-derives
the output key or it does not — but a value is stored, and later becomes the
`witness_utxo` of the BIP-376 spend that moves the coin, which BIP-341 signs
over. A wrong one is a valid signature over a lie. Reading the block settles
that as a side effect; reading a stream does not, so every *found* output is
checked against the chain before it is stored: one pair of requests per payment,
rather than one block per height.

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
[rbitcoin]: https://github.com/reardencode/rbitcoin

## Topping up

```sh
kiss-bdk faucet --sats 100000
```

Derives the next unused address and asks that network's faucet for coins.
Mutinynet is the only one with a callable API, and it needs a bearer token —
sign in once at <https://faucet.mutinynet.com/>, then pass `--token` or export
`MUTINYNET_FAUCET_TOKEN`. Testnet4 and Signet faucets are Turnstile-protected,
so the command prints the address and the links instead of pretending.

## Testing another signer

KISS is the signer this was written for, not the only one it can talk to. The
QR path is the part that is specific to it; the file path is not, and everything
worth borrowing lives there.

```sh
kiss-bdk create --to tsp1… --sats 10000 --out unsigned.psbt   # BIP-375
kiss-bdk create --to tb1q… --sats 10000 --from-sp --out unsigned.psbt   # BIP-376
# sign unsigned.psbt however your device does it, into signed.psbt
kiss-bdk broadcast signed.psbt --original unsigned.psbt --dry-run
```

`create` emits the PSBTv2 shape both drafts call for, down to the key types —
`0x20` for the tweak, `0x1f` for the spend key's origin, and no
`PSBT_IN_BIP32_DERIVATION` on a silent payment input, which breaks signing on at
least one implementation. The exact per-input key set is asserted on the
serialized bytes in [tests/sp_spend_psbt.rs](tests/sp_spend_psbt.rs), so it is
a specification you can diff against rather than a description.

`broadcast --dry-run` is the half that makes it a test rig. It takes nothing on
trust: it checks the signer returned the same transaction it was given, verifies
the BIP-374 DLEQ proof, re-derives each silent payment output and compares it to
the script the signer wrote, and verifies every signature — schnorr or ECDSA —
against a key worked out locally. A signer that gets any of it wrong is told
which part, before anything reaches the network.

For a loop with no faucet and no waiting, `--network regtest` against a local
node works end to end;
[tests/rbitcoin_regtest.rs](tests/rbitcoin_regtest.rs) is a worked example that
mines its own coin, pays a silent payment to itself and finds it again.

Two fixture helpers exist for driving a device from files:
[tests/sp_spend_fixtures.rs](tests/sp_spend_fixtures.rs) writes BIP-376 PSBTs
for a signer's own host harness — including one whose tweak does not reproduce
the output key, which must be refused — and reads the signed results back
through the same verify → finalize → extract path `broadcast` uses.

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
  Both tweak sources find it, which is what the timings below are measured on.
- Silent payment **spent**, Mutinynet —
  [3e0fdd39…54ab80](https://mutinynet.com/tx/3e0fdd3965f541d25771c732d42b459759b6fd643d07bc1843a756f9de54ab80).
  One `v1_p2tr` key-path input, one 64-byte signature — the shape a BIP-376
  spend must have, since the key is `spend + tweak` with no taproot tweak on
  top.
- **The whole loop**, Signet, against a node of this wallet's own. Received and
  then spent again, with nothing asked of anyone else:
  1. KISS derived and signed a payment to this wallet's own `tsp1` code —
     [339b903e…df21d3fb](https://mempool.space/signet/tx/339b903ee339a864a6e54dfc87c459f86fc213ec319568edfbdfcb3adf21d3fb),
     block 319011.
  2. `sp-scan --electrum` found it through that node's BIP-352 index, fetching
     no blocks.
  3. KISS spent it back —
     [e6543ce2…2dd18560](https://mempool.space/signet/tx/e6543ce27be85b688e57dd57d75de92450ecbb138c5ea443e0d0de6a2dd18560),
     block 319014, reported as `1 silent payment, 0 ECDSA` and landing on chain
     as a `v1_p2tr` key-path input with one 64-byte witness item and an empty
     `scriptSig`.

  On the device's details screen that input reads `m/352'/1'/0'` with a silent
  payment marker rather than a BIP-32 path, which is the only part of this
  nothing off the device can check.

The tweak stream needs no signer and no hardware, so it is proven twice over
instead — against a full signet archive, and against a chain small enough to
keep in a test.

**Signet, on a self-hosted node.** [rbitcoin] `master` at
[`a5ce3b1`](https://github.com/reardencode/rbitcoin/commit/a5ce3b199d82329306726d1792058f3f6c950b83),
synced to 318958 with `--shindex --sptweaks` — 19 GB. Scanning for the payment
listed above, with `--esplora` pointed at the same node, so nothing left the
machine:

```text
scanning 318745 to 318959 via 127.0.0.1:50001...
found 10000 sats at 3a6801e9…a90cd12a:0 in block 318745
scanned to 318959; 1 silent payment output(s) in range
```

The public oracle finds exactly the same output over exactly the same range —
same outpoint, same 10000 sats, same block — which is the check that matters:
two independent sources of the same tweaks agreeing. What differs is the cost.

| | wall clock | CPU |
| --- | --- | --- |
| `--electrum` (own node) | **46 s** | 99% |
| `--blindbit` (public) | **5 m 23 s** | 10% |

That gap is structural rather than a matter of one being nearer. BlindBit was at
10% CPU because it spends the time *waiting on block fetches* — one per height
carrying any tweak. The stream sends the txid and the outputs with the tweak, so
there are none to wait for.

**Regtest, as a test that runs on its own.**
[tests/rbitcoin_regtest.rs](tests/rbitcoin_regtest.rs) mines a coinbase, spends
it to a real BIP-352 output derived from the sender's own input key, and then —
knowing only the recipient's keys — finds it again through the same stream. It
also holds the node's published tweak against `input_hash · A` computed locally,
repeats the whole thing through the `sp-scan` command itself, and checks that a
wallet on the wrong chain is refused. Signet cannot be a test: a node serves
Electrum only once it has caught up to its peers.
