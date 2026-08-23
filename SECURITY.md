# Security

## What this is

An experimental coordinator for the Bitcoin **test networks**. It builds
transactions and verifies what a signing device hands back. It is not audited
and has not been reviewed by anyone outside this repository.

Do not point it at money you would miss.

## Mainnet is unreachable by design

`init` refuses `--network bitcoin`, and a wallet directory is pinned to the
network it was created on. The reason is not caution about bugs: this
coordinator holds a **scan private key**, imported by `sp-pair`, and a mainnet
scan key in a hot wallet directory is a different risk from a testnet one.

The scan key is the only secret a wallet directory ever contains. It finds
payments and cannot move them; the spend key stays on the signing device. See
[BIP-352](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki) for
why that split exists.

## In scope

Reports about this repository's own code are welcome, particularly:

- A verification that passes when it should not. `broadcast` checks that the
  signer returned the transaction it was given, that the BIP-374 DLEQ proof is
  honest, that each derived output re-derives to the script the signer wrote,
  and that every signature verifies against a key computed here. A way past any
  of those matters.
- A silent payment output stored with an amount, script or outpoint the chain
  does not agree with. Amounts reach the `witness_utxo` of the spend that moves
  a coin and BIP-341 signs over them.
- A PSBT this builds that a correct signer should refuse, or that misrepresents
  on screen what it will do on chain.
- Anything that writes a scan key somewhere other than the wallet directory.

## Out of scope

- The signing device itself. That is [kiss-signer](https://github.com/kkdao/kiss-signer).
- Third-party servers: Esplora backends, BlindBit oracles, tweak servers. Their
  answers are treated as untrusted here, which is the point; a server behaving
  badly is expected, and a report is only interesting if this code believes it.
- Anything requiring mainnet, which this cannot reach.

## Reporting

Open an issue. There are no real funds at stake on a test network, so there is
nothing to embargo and a public report gets fixed faster.
