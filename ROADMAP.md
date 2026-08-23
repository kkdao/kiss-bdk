# Roadmap

Short list, honestly ordered. Everything here came out of using the thing.

## Done

- Ordinary send, receive, verify, broadcast
- Silent payments: send (BIP-375), receive (BIP-352), spend (BIP-376)
- Silent payment change, so a spend keeps the coins in the keyspace
- Tweaks from a node of your own over the Electrum protocol, not just BlindBit
- Regtest, and pairing a signing device that has no KISS-style export

All of it proven on hardware. See the Proof section in the [README](README.md).

## Now: Mutinynet

Signet blocks are ten minutes apart, so one round trip is an evening. Mutinynet
is a custom signet with **30-second blocks**, which turns the same test into a
few minutes.

It also has **no public tweak oracle at all**, so a node of your own is the only
way to scan it. That makes it the first place `--electrum` is not merely nicer
than BlindBit but the only option.

Status: syncing. It is 3.4M blocks behind one public peer, so it is slow rather
than hard, and the peer wedges occasionally — `stallguard.sh` restarts it.

Then: the same receive-and-spend loop, at 30 seconds a block.

## Next

**Animated QR from computer to device.** `--qr` now selects largest-first, so a
transaction uses the fewest inputs it can and the frame stays readable. That is
a smaller budget than it needs to be: the device's decoder already handles
multi-part input, and only this side is still single-frame.

**Labels.** BIP-352 labelled addresses. The scanner passes an empty label map
today, which is correct for one published code and wrong the moment there are
two.

**Use your own node for ordinary sync too.** Blocked on
[rbitcoin#209](https://github.com/reardencode/rbitcoin/issues/209): it serves
`bits` as a hex string where the Esplora schema has an integer, so `bdk_esplora`
refuses the block. Silent payments already work fully against it.

**Upstream what belongs upstream.**
[bdk-sp#70](https://github.com/bitcoindevkit/bdk-sp/pull/70) and
[#71](https://github.com/bitcoindevkit/bdk-sp/pull/71) are open.

## Not planned

- **Mainnet.** This holds a scan private key and is not audited. See
  [SECURITY.md](SECURITY.md).
- **Being a wallet.** BDK does the wallet work and the signing device holds the
  keys. This is the thing in between.
