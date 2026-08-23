<p align="center">
  <img src="assets/kiss-bdk-gallery.png" alt="KISS plus BDK" width="720">
</p>

# KISS-BDK

**Air-gapped Bitcoin transactions powered by BDK**

An experimental Rust coordinator for the Bitcoin test networks. BDK runs the
online watch-only wallet; KISS, an air-gapped C signing device, holds the
keys. They only ever talk in QR codes.

`Pair` → `Sync` → `Build` → `Sign` → `Verify` → `Broadcast`

[Roadmap](ROADMAP.md) · [How silent payments work here](docs/silent-payments.md) · [Security](SECURITY.md) · [Contributing](CONTRIBUTING.md)

## 🧩 Who does what

Two machines, and neither trusts the other.

**kiss-bdk is the coordinator**: online, watch-only, holds no spending keys. It
builds transactions and checks what comes back. **The signing device** is
offline, holds the keys, and is the only thing that can sign. QR codes are the
only thing that crosses between them.

Inside the coordinator, silent payments are not one library's job:

| | |
| --- | --- |
| **BDK** (`bdk_wallet`) | the wallet: descriptors, addresses, coin selection, fees, change, building and finalizing PSBTs |
| **`bdk_sp`** | the BIP-352 maths: deriving a silent payment output, and testing a block's tweaks against a scan key |
| **kiss-bdk** | what neither covers: the BIP-375 and BIP-376 PSBT fields, verifying what the device returns, the QR transport, and the tweak clients |
| **the signing device** | the keys. It derives each silent payment output script, because only the input private keys can |
| **a tweak source** | per-block data no block explorer serves. A [BlindBit] oracle, or your own [rbitcoin] node |

BDK is the wallet library, not the server and not the signing device.

## 📦 Install

Needs Rust, a C compiler and a webcam. macOS and Linux.

```sh
# macOS
xcode-select --install
# Linux (Debian or Ubuntu)
sudo apt install -y build-essential pkg-config libv4l-dev libclang-dev clang
```

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
git clone https://github.com/kkdao/kiss-bdk && cd kiss-bdk
cargo build --release
```

Commands below start `./target/release/kiss-bdk`, or run `cargo install --path .`
to type just `kiss-bdk`. No git? Download the
[zip](https://github.com/kkdao/kiss-bdk/archive/refs/heads/main.zip) instead.

macOS asks for camera permission on the first `--scan-qr`. No webcam is fine:
everything also works from files, see
[Testing another signing device](#-testing-another-signing-device).

## 🌐 Networks

Chosen at `init` and fixed for that wallet directory.

| `--network` | Default Esplora | Faucet |
| --- | --- | --- |
| `testnet4` (default) | `mempool.space/testnet4` | browser only |
| `signet` | `mempool.space/signet` | browser only |
| `mutinynet` | `mutinynet.com` | `kiss-bdk faucet --token …` |
| `regtest` | `127.0.0.1:3000` | mine to the address |

All four are coin type `1h`, so one descriptor derives the same addresses on all
of them, which also means a `tb1…` address is valid on three of them and
nothing tells them apart. Keep one `--wallet-dir` per network. Mainnet is not
selectable. Mutinynet's 30-second blocks make it the one to demo on.

## 🚀 Quick start

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

The fee rate comes from the backend's next-block estimate. `--fee-rate` overrides
it.

## 🤫 Silent payments

One reusable code, `tsp1…`, and no address reuse. The reasoning behind all of
this is in [docs/silent-payments.md](docs/silent-payments.md); these are the
commands.

### Sending to one

```sh
kiss-bdk create --to tsp1… --sats 10000 --qr
```

The signing device derives the output script, because only the input private
keys can. Before broadcast this checks the same transaction came back, that its
DLEQ proof is honest, and that re-deriving reproduces the script it wrote.

### Receiving

```sh
kiss-bdk sp-pair --scan-qr     # import the scan key
kiss-bdk sp-address            # the tsp1… code to hand out
kiss-bdk sp-scan               # search the chain
kiss-bdk sp-balance            # what was found
```

Finding a payment means testing every block against your scan key, using data
no block explorer serves. It comes from a [BlindBit] oracle by default and is
matched locally, so the server learns which blocks you scanned and never which
outputs matched.

`sp-pair` imports the scan key only: this wallet can see payments and can never
move them. `sp-scan --tx <txid>` works before a payment is mined.

### Spending what was received

```sh
kiss-bdk create --to tb1q… --sats 10000 --from-sp --qr
```

Change stays in the silent payment keyspace rather than landing on an ordinary
address.

**Silent payment coins are spent on their own.** A transaction mixing them with
ordinary coins is refused, because only an all-taproot spend proves its own fee.
If the silent payment balance cannot cover a payment, the ordinary balance
cannot make up the difference.

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

[rbitcoin] serves the same data over the Electrum protocol, so nobody is asked
at all. Each tweak arrives attached to its transaction, so **no blocks are
fetched**: 46 s against BlindBit's 5 m 23 s over the same signet range.

**Storage.** It does not prune, so this is a full archive: **signet is 19 GB**,
roughly 1½ hours to sync plus 18 minutes to index. It serves nothing until that
finishes. `--network regtest` comes up in seconds.

Silent payments work fully against your node today. Ordinary `sync` does not
yet, so leave `--esplora` on a public server for now
([rbitcoin#209](https://github.com/reardencode/rbitcoin/issues/209)).

[BlindBit]: https://github.com/setavenger/blindbit-oracle
[rbitcoin]: https://github.com/reardencode/rbitcoin

## 💧 Topping up

```sh
kiss-bdk faucet --sats 100000
```

Mutinynet is the only network with a callable faucet API, and it needs a bearer
token. Sign in at <https://faucet.mutinynet.com/>, then pass `--token` or export
`MUTINYNET_FAUCET_TOKEN`. The others are captcha-protected, so the command
prints the address and the links instead of pretending.

## 🔌 Testing another signing device

Nothing here is tied to KISS except the QR commands. `create` writes a PSBT file
and `broadcast` reads one back, so any device that can load a file will do,
whether it ships BIP-375 and BIP-376 today or you are adding them.

No node needed: the check runs offline, against files.

```sh
kiss-bdk init --network signet --descriptor "<your device's descriptor>"
kiss-bdk create --to tsp1… --sats 10000 --out unsigned.psbt
# sign unsigned.psbt on your device, save it as signed.psbt
kiss-bdk broadcast signed.psbt --original unsigned.psbt --dry-run
```

That last line is the point. It takes nothing on trust: same transaction back,
DLEQ proof, re-derived output script, every signature checked against a key
worked out here. And it names which part failed. Fix, repeat.

To receive as well, pair from the two keys directly, since BIP-352 does not say
how a device should hand its scan key over:

```sh
kiss-bdk sp-pair --keys SCAN_PRIVATE_HEX:SPEND_PUBLIC_HEX
```

64 hex digits then 66. From there `sp-address`, `sp-scan` and `--from-sp` all
work as they do for KISS.

The exact bytes `create` emits are asserted in
[tests/sp_spend_psbt.rs](tests/sp_spend_psbt.rs), so it is a specification you
can diff against rather than a description.
[tests/sp_spend_fixtures.rs](tests/sp_spend_fixtures.rs) writes PSBTs for a
device's own harness, including one whose tweak does not reproduce the output
key, which a correct device must refuse.

For a loop with no faucet and no ten-minute blocks, `--network regtest` against
a local node has neither, and
[tests/rbitcoin_regtest.rs](tests/rbitcoin_regtest.rs) is a worked example.

## 🔨 Build

```sh
cargo test --locked
cargo build --release --locked
```

Needs Rust, a C compiler, and a webcam. Tested on macOS.

## 📷 QR

- Computer → device: one static Base64 PSBT QR when it fits, and an animated
  BC-UR `crypto-psbt` GIF when it does not. `--qr` also picks the largest coins
  first, so a transaction uses the fewest inputs it can.
- Device → computer: animated BC-UR `crypto-psbt`.
- Decoding uses the vendored `k_quirc`, the same decoder the device runs.

## ✅ Proof

Every flow below ran over the physical hardware.

- Ordinary send, Testnet4:
  [8b3473f8…3f8659](https://mempool.space/testnet4/tx/8b3473f888ff1f896f9112e2886bd63d3d2595456f57d3009038f5de173f8659)
- Silent payment **sent**, Signet:
  [3a6801e9…0cd12a](https://mempool.space/signet/tx/3a6801e9b5a7398406621299aefc8a2c915d20de612f21a26011972aa90cd12a).
  Its recipient uses throwaway keys, so it checks from the receiving side too.
- Silent payment **spent**, Mutinynet:
  [3e0fdd39…54ab80](https://mutinynet.com/tx/3e0fdd3965f541d25771c732d42b459759b6fd643d07bc1843a756f9de54ab80).
  One `v1_p2tr` key-path input, one 64-byte signature.
- **The whole loop**, Signet, on a node of this wallet's own: KISS signed a
  payment to this wallet's own code
  ([339b903e…df21d3fb](https://mempool.space/signet/tx/339b903ee339a864a6e54dfc87c459f86fc213ec319568edfbdfcb3adf21d3fb),
  block 319011), `sp-scan --electrum` found it through that node's BIP-352
  index, and KISS spent it back
  ([e6543ce2…2dd18560](https://mempool.space/signet/tx/e6543ce27be85b688e57dd57d75de92450ecbb138c5ea443e0d0de6a2dd18560),
  block 319014) as a `v1_p2tr` key-path input with one 64-byte witness item.

- **Silent payment change**, Signet, with both halves in one transaction:
  [56458880…e7cad3f1](https://mempool.space/signet/tx/564588801141c52bd412a69ac6b08af843724f66cbe20f75cc443436e7cad3f1),
  block 319035. BIP-376 on the input, BIP-375 on **both** outputs, paying this
  wallet's own code so the two carry the same recipient and the device assigns
  them different derivation orders. On chain: a `v1_p2tr` key-path input with
  one 64-byte witness item, and two `v1_p2tr` outputs, no ordinary address
  anywhere. `sp-scan` then found both again, so the change stayed in the
  keyspace it came from.

Scanning the same signet range through that node and through the public BlindBit
oracle finds the same output: same outpoint, same amount, same block. Two
independent sources agreeing is the check that matters; 46 s against 5 m 23 s is
the difference in cost.

[tests/rbitcoin_regtest.rs](tests/rbitcoin_regtest.rs) runs the whole thing
unattended against a local node: mines a coin, pays a real silent payment to
itself, and finds it again knowing only the recipient's keys.

## 🙏 Built on

- [BDK](https://github.com/bitcoindevkit/bdk_wallet) and
  [bdk_sp](https://github.com/bitcoindevkit/bdk-sp), which do the wallet and the
  BIP-352 maths
- [rbitcoin](https://github.com/reardencode/rbitcoin) by
  [@reardencode](https://github.com/reardencode), the node serving the tweak
  stream. Signet scanning here runs against it today
- [BlindBit](https://github.com/setavenger/blindbit-oracle), the oracle used
  when you have no node of your own
- [k_quirc](vendor/k_quirc), the QR decoder shared with the signing device

## 💬 Community

Silent payments, air-gapped signing devices and DIY hardware get discussed here:

<p align="center">
  <a href="https://t.me/DIYbitcoin"><img alt="DIY Bitcoin on Telegram" src="https://img.shields.io/badge/Telegram-DIY%20Bitcoin-2CA5E0.svg?style=for-the-badge&logo=telegram&logoColor=white"></a>
</p>

Bringing BIP-375 or BIP-376 up on another device is exactly the sort of thing
worth asking about there. Bugs and results are welcome as issues here too.
