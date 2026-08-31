<p align="center">
  <img src="assets/kiss-bdk-gallery.png" alt="KISS plus BDK" width="720">
</p>

# KISS-BDK

**Offline Bitcoin signing, powered by BDK**

A command-line Bitcoin wallet that never touches your keys. They stay offline on
KISS, a signing device. This side watches the chain, builds the transaction, and
checks what comes back. QR codes are the only thing that crosses between them.

`Pair` → `Sync` → `Build` → `Sign` → `Verify` → `Broadcast`

⚠️ **Experimental, and test networks only.** Mainnet cannot be selected.

> ### 🔁 A silent payment, received and spent
>
> On Mutinynet this wallet paid its own `tsp1…` code, found the payment again,
> and spent it back out. An offline device signed both, over QR.
>
> **Nobody was asked.** The blocks, the fee estimate, the scan and the
> broadcast all came from a node on the same machine. No block explorer, no
> Electrum server.
>
> Received [7844c4b7…](https://mutinynet.com/tx/7844c4b74439fbc982fb716ffd55d1295ecff254e31fd151d40766f5e5fc8a77)
> · spent [dc87380d…](https://mutinynet.com/tx/dc87380d6921412d7ddd3026e6a9a28f6db9add57983f0f488d7d182cc7804cc)
> · [run it yourself](docs/node.md)

[Roadmap](ROADMAP.md) · [Silent payments](docs/silent-payments.md) ·
[Your own node](docs/node.md) · [Other signing devices](docs/other-devices.md) ·
[Proof](docs/proof.md) · [Security](SECURITY.md) ·
[Contributing](CONTRIBUTING.md)

## 🧩 Who does what

Two machines, and neither trusts the other.

- **kiss-bdk**, this program, is online and watch-only. It holds no spending
  keys, so the worst it can do is show you the wrong thing.
- **The signing device** is offline, holds the keys, and is the only thing that
  can sign.

Under the hood, the work is split up:

| | |
| --- | --- |
| **BDK** (`bdk_wallet`) | descriptors, addresses, coin selection, fees, change, building and finalizing PSBTs |
| **`bdk_sp`** | the BIP-352 maths |
| **kiss-bdk** | the BIP-375 and BIP-376 PSBT fields, verifying what the device returns, the QR transport, the tweak clients |
| **the signing device** | the keys, and deriving each silent payment output script, because only the input private keys can |
| **a tweak source** | per-block data no block explorer serves: a [BlindBit] oracle, or your own [rbitcoin] node |

## 📦 Install

You need Rust, a C compiler and a webcam. macOS and Linux.

**1. Compiler.**

```sh
xcode-select --install                                                       # macOS
sudo apt install -y build-essential pkg-config libv4l-dev libclang-dev clang  # Debian, Ubuntu
```

**2. Rust.**

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

**3. This.**

```sh
git clone https://github.com/kkdao/kiss-bdk && cd kiss-bdk
cargo install --path .
```

That puts `kiss-bdk` on your `PATH`. macOS asks for camera permission the first
time you scan. No webcam is fine, everything also works from files: see
[other signing devices](docs/other-devices.md).

## 🚀 Quick start

Mutinynet has 30-second blocks, so it is the least boring network to learn on.

**1. Pair.** On KISS: enable Testnet, unlock, then **PAIR COORDINATOR →
DESKTOP**. Then hold it up to the camera:

```sh
kiss-bdk init --network mutinynet --scan-qr
```

**2. Get an address**, and put coins on it.

```sh
kiss-bdk sync
kiss-bdk address
kiss-bdk faucet --sats 100000 --token …   # Mutinynet only, see below
```

**3. Check it arrived.** `sync` reads the chain, `balance` reads what sync
stored, so always sync first.

```sh
kiss-bdk sync
kiss-bdk balance
```

**4. Build a payment.** This prints a QR on your screen.

```sh
kiss-bdk create --to tb1q… --sats 10000 --qr
```

**5. Sign it.** On KISS choose **SIGN → SCAN QR**, check the amount and address
on its screen, and sign. It answers with an animated QR.

**6. Read the answer back**, while KISS is still showing it:

```sh
kiss-bdk scan
```

**7. Check and send.**

```sh
kiss-bdk broadcast signed.psbt --original unsigned.psbt
```

That last step re-checks that KISS returned the transaction it was given,
verifies every signature, and finalizes, all before anything reaches the
network. Add `--dry-run` to do everything except send.

The fee rate comes from the backend's next-block estimate; `--fee-rate`
overrides it.

**Faucets.** Mutinynet is the only network with a faucet you can call from the
command line, and it needs a token: sign in at
<https://faucet.mutinynet.com/>, then pass `--token` or export
`MUTINYNET_FAUCET_TOKEN`. On the others the command prints the address and the
faucet links for you to open in a browser.

## 🤫 Silent payments

One address, `tsp1…`, that you reuse forever. Each payment to it still lands on
a different address on chain, so nothing links them. The reasoning is in
[docs/silent-payments.md](docs/silent-payments.md); these are the commands.

```sh
kiss-bdk create --to tsp1… --sats 10000 --qr             # pay one

kiss-bdk sp-pair --scan-qr                               # import the scan key
kiss-bdk sp-address                                      # the tsp1… code to hand out
kiss-bdk sp-scan                                         # search the chain
kiss-bdk sp-balance                                      # what was found

kiss-bdk create --to tb1q… --sats 10000 --from-sp --qr   # spend what was found
```

`sp-pair` imports the scan key only: this wallet can see payments and can never
move them. `sp-scan --tx <txid>` works before a payment is mined.

Two things worth knowing:

- **Scanning needs a tweak source.** By default a public [BlindBit] oracle. The
  matching runs on your machine, so that server sees which blocks you asked for,
  never which coins are yours. [Your own node](docs/node.md) sees nothing, and
  is seven times faster.
- **Silent payment coins are spent on their own.** A transaction mixing them
  with ordinary coins is refused, because only an all-taproot spend proves its
  own fee. If the silent payment balance cannot cover a payment, the ordinary
  balance cannot make up the difference. Change stays in the silent payment
  keyspace.

Sending is checked as hard as anything else: before broadcast this confirms the
same transaction came back, that its DLEQ proof is honest, and that re-deriving
reproduces the script it wrote.

## 🌐 Networks

Picked at `init` and fixed for that wallet directory.

| `--network` | Blocks | Default Esplora |
| --- | --- | --- |
| `testnet4` (default) | ~10 min | `mempool.space/testnet4` |
| `signet` | ~10 min | `mempool.space/signet` |
| `mutinynet` | 30 s | `mutinynet.com` |
| `regtest` | you mine them | `127.0.0.1:3000` |

All four are coin type `1h`, so one descriptor derives the same addresses on all
of them, which also means a `tb1…` address is valid on three of them and nothing
tells them apart. **Keep one `--wallet-dir` per network.**

## 🩺 If something goes wrong

- **`broadcast` refuses.** Good. It names which check failed rather than sending
  something it cannot vouch for. Nothing reached the network.
- **Camera does not open on macOS.** Grant Terminal camera access in System
  Settings, then run the command again.
- **No webcam, or KISS is elsewhere.** Use `--out unsigned.psbt` and pass files
  around instead: [other signing devices](docs/other-devices.md).
- **Balance looks wrong.** Run `sync` first, and check you are pointing at the
  wallet directory for that network.

## 📷 QR

Computer to device: one static Base64 PSBT QR when it fits, an animated BC-UR
`crypto-psbt` GIF when it does not. `--qr` also picks the largest coins first, so
a transaction uses the fewest inputs it can. Device to computer: animated BC-UR.
Decoding uses the vendored [k_quirc](vendor/k_quirc), the same decoder the device
runs.

## ✅ Proof

Don't trust, verify. Every flow ran on real hardware and the transactions are on
chain: **[docs/proof.md](docs/proof.md)**.

The one that matters is the whole loop with no public server in it, node and
wallet on the same laptop. Scanning the same signet range through that node and
through the public oracle finds the same output, at 46 s against 5 m 23 s.

## 🙏 Built on

- [BDK](https://github.com/bitcoindevkit/bdk_wallet) and
  [bdk_sp](https://github.com/bitcoindevkit/bdk-sp), which do the wallet and the
  BIP-352 maths
- [rbitcoin] by [@reardencode](https://github.com/reardencode), the node serving
  the tweak stream
- [BlindBit], the oracle used when you have no node of your own
- [k_quirc](vendor/k_quirc), the QR decoder shared with the signing device

## 💬 Community

Silent payments, offline signing devices and DIY hardware get discussed here:

<p align="center">
  <a href="https://t.me/DIYbitcoin"><img alt="DIY Bitcoin on Telegram" src="https://img.shields.io/badge/Telegram-DIY%20Bitcoin-2CA5E0.svg?style=for-the-badge&logo=telegram&logoColor=white"></a>
</p>

Bringing BIP-375 or BIP-376 up on another device is exactly the sort of thing
worth asking about there. Bugs and results are welcome as issues here too.

[BlindBit]: https://github.com/setavenger/blindbit-oracle
[rbitcoin]: https://github.com/reardencode/rbitcoin
