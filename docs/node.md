# Running your own node

Scanning for silent payments needs per-block data no block explorer serves. By
default kiss-bdk asks a public [BlindBit] oracle. This is how to ask nobody.

[rbitcoin] is a Bitcoin node in Rust that builds a BIP-352 tweak index and
serves it over the Electrum protocol, alongside an Esplora API. One binary, so
it can answer every question this wallet has.

## Signet

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

Each tweak arrives attached to its transaction, so **no blocks are fetched**:
46 s against BlindBit's 5 m 23 s over the same signet range.

Build from `master` rather than a release. Ordinary sync needed a public server
until [rbitcoin#209](https://github.com/reardencode/rbitcoin/issues/209) was
fixed.

## Storage

It does not prune, so this is a full archive: **signet is 19 GB**, roughly
1½ hours to sync plus 18 minutes to index. It serves nothing until that
finishes. `--network regtest` comes up in seconds.

Serving address history means keeping an index over every block, which is the
same limit any Electrum server has. `--datadir-cold PATH` puts the bulk archive
on a second drive and leaves the indexes on the fast one.

## Everything from your own node

Point `--esplora` at the node too and no public server is left in the loop:

```sh
kiss-bdk init --network mutinynet --esplora http://127.0.0.1:3002 --scan-qr
```

Now `sync`, the fee estimate and `broadcast` all come from the same node that
serves the tweaks.

## Mutinynet

Mutinynet has 30-second blocks, which makes it the quickest network to test on.
It is a custom signet, so the node needs its challenge and block time, and it
publishes no DNS seeds, so it needs its one peer by hand:

```sh
./target/release/rbitcoin-node --datadir ~/rbitcoin-mutinynet --network signet \
  --signetchallenge 512102f7561d208dd9ae99bf497273e16f389bdbd6c4742ddb8e6b216e64fa2928ad8f51ae \
  --signetblocktime 30 --connect 45.79.52.207:38333 \
  --shindex --sptweaks \
  --electrum-listen 127.0.0.1:50002 --esplora-listen 127.0.0.1:3002
```

About 7 GB and a few hours. With one peer and no seeds, a dial that fails is not
retried, so if the tip stops moving, restart it.

## Regtest

Your own chain, so there is no faucet and no waiting: mine to the address.
[tests/rbitcoin_regtest.rs](../tests/rbitcoin_regtest.rs) is a worked example
that mines a coin, pays a real silent payment to itself, and finds it again.

[BlindBit]: https://github.com/setavenger/blindbit-oracle
[rbitcoin]: https://github.com/reardencode/rbitcoin
