# Silent payments, in more detail

The [README](../README.md) has the commands. This is the reasoning behind them:
why a silent payment leaves as a PSBTv2, why these coins are spent on their own,
and what is checked before anything reaches the network.

Throughout, **the coordinator** is kiss-bdk: online, watch-only, no spending
keys. **The signing device** is the offline one that holds them. The whole
design is the coordinator never having to trust what the device sends back.

## Why the signing device derives the output, not the coordinator

A silent payment output pays a script computed from the **sender's input private
keys** and the recipient's code. A watch-only wallet has neither, so it cannot
work out where the money is going.

[BIP-375](https://github.com/bitcoin/bips/blob/master/bip-0375.mediawiki) puts
the recipient's two public keys in the PSBT and leaves the output script empty
for the device to fill in. That is also why these leave as a **PSBTv2**: a v0
carries one fixed unsigned transaction, and it cannot express an output whose
script does not exist yet.

BDK still needs to size the fee, so `create` puts a taproot placeholder of the
exact final size where the real output will go, and strips it on the way out.

## What is checked before broadcast

Nothing the signing device returns is taken on trust. `broadcast` refuses unless:

- **It is the same transaction.** Inputs, outputs, amounts, sequences, locktime
  and the modifiable flags all match what was sent.
- **The BIP-374 DLEQ proof verifies.** This proves the ECDH share the device
  used really came from the inputs being spent, rather than from a key it
  chose.
- **Re-deriving reproduces the script.** The output is computed again here, from
  the proof and the recipient's code, and must equal the script the device
  wrote. Without this a device could pay anyone and call it your recipient.
- **Every signature verifies**, schnorr or ECDSA, against a key worked out here
  rather than one the PSBT supplied.

## Why silent payment coins are spent on their own

A transaction mixing a received silent payment with an ordinary coin is refused
by the signing device, and `create --from-sp` will not build one.

The reason is a sighash difference.
[BIP-143](https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki), which
covers P2WPKH, commits only to the amount of the input **being signed**. So a
coordinator holding two inputs can run two individually truthful signing
sessions, each showing a correct amount, and combine the results into a
transaction paying a fee neither screen ever displayed.

[BIP-341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki) hashes
**every** input amount into each signature, so an all-taproot spend proves its
own fee. A received silent payment is always taproot. Keeping the whole
transaction taproot is what closes the hole, and the cost is that the ordinary
balance cannot top up a silent payment spend.

## Spending one: BIP-376

A received silent payment pays `B_spend + t·G`: the spend key plus that output's
tweak. It is a BIP-32 child of nothing and appears in no descriptor, which is
why a wallet that only knows descriptors cannot spend it.

[BIP-376](https://github.com/bitcoin/bips/blob/master/bip-0376.mediawiki) puts
the tweak on the input as `PSBT_IN_SP_TWEAK`, and the device adds it to the
spend key it kept. Two things guard that:

- Every candidate is re-derived here first, and dropped unless its tweak
  reproduces the script the output actually pays.
- The device does the same check independently before signing, so a tampered
  tweak fails on the device as well.

Change goes back into the silent payment keyspace. That puts BIP-376 on the
inputs and BIP-375 on both outputs in one PSBT, which is the ordinary shape of
a silent payment wallet's spend rather than a corner case. Paying your own code
simply puts two derived outputs in one transaction, at derivation orders the
device assigns.

## Why finding them needs a tweak source

Nothing on chain names the recipient, so every block has to be tested against
your scan key. That test needs each transaction's summed input public keys,
which no ordinary block explorer serves.

Three ways to get it, and they are not equivalent:

| | who does the matching | what the server learns |
| --- | --- | --- |
| a node of your own | you | nothing |
| a [BlindBit] oracle | you | which blocks you scanned |
| [Frigate] (Sparrow) | **the server** | **every payment you receive** |

Frigate is not a faster oracle, it is a different trust model: the client hands
it the **scan private key** and the server does the matching. The other two send
data and your keys never leave.

Between the first two, the difference is cost. BlindBit publishes a bare list of
tweaks, so a client must fetch each block to find which transaction a tweak
belongs to. The Electrum stream sends the txid and the taproot outputs alongside
the tweak, so no blocks are fetched at all, 46 s against 5 m 23 s over the same
signet range.

## Why amounts are still checked against the chain

A tweak needs no trust: it either re-derives the output key or it does not.

An **amount** does. It is stored, and later becomes the `witness_utxo` of the
BIP-376 spend that moves the coin, which BIP-341 signs over. A wrong one is a
valid signature over a lie, discovered as a rejected broadcast after a walk to
the device and back. Reading a whole block settles that as a side effect;
reading a stream does not, so every *found* output is checked against the chain
before it is stored.

## The scan key

`sp-pair` imports the **scan private key** and never the spend key. This wallet
can see payments and can never move them; that split is
[BIP-352](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki)'s
whole design.

It is the only secret a wallet directory holds. See [SECURITY.md](../SECURITY.md).

[BlindBit]: https://github.com/setavenger/blindbit-oracle
[Frigate]: https://github.com/sparrowwallet/frigate
