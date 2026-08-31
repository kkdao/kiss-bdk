# Proof

Don't trust, verify. Every flow below ran on real hardware. The transactions are
on chain.

| What | Network | Transaction |
| --- | --- | --- |
| Ordinary send | Testnet4 | [8b3473f8…](https://mempool.space/testnet4/tx/8b3473f888ff1f896f9112e2886bd63d3d2595456f57d3009038f5de173f8659) |
| Silent payment **sent** | Signet | [3a6801e9…](https://mempool.space/signet/tx/3a6801e9b5a7398406621299aefc8a2c915d20de612f21a26011972aa90cd12a) |
| Silent payment **spent** | Mutinynet | [3e0fdd39…](https://mutinynet.com/tx/3e0fdd3965f541d25771c732d42b459759b6fd643d07bc1843a756f9de54ab80) |

The sent one pays a recipient using throwaway keys, so it checks from the
receiving side too. The spent one is a single `v1_p2tr` key-path input with one
64-byte signature.

## The whole loop, on a node of this wallet's own

Signet. KISS signed a payment to this wallet's own code
([339b903e…](https://mempool.space/signet/tx/339b903ee339a864a6e54dfc87c459f86fc213ec319568edfbdfcb3adf21d3fb),
block 319011), `sp-scan --electrum` found it through that node's BIP-352 index,
and KISS spent it back
([e6543ce2…](https://mempool.space/signet/tx/e6543ce27be85b688e57dd57d75de92450ecbb138c5ea443e0d0de6a2dd18560),
block 319014) as a `v1_p2tr` key-path input with one 64-byte witness item.

## Silent payment change, both halves in one transaction

Signet, block 319035:
[56458880…](https://mempool.space/signet/tx/564588801141c52bd412a69ac6b08af843724f66cbe20f75cc443436e7cad3f1).
BIP-376 on the input, BIP-375 on **both** outputs, paying this wallet's own code
so the two carry the same recipient and the device assigns them different
derivation orders. On chain: a `v1_p2tr` key-path input with one 64-byte witness
item, and two `v1_p2tr` outputs, no ordinary address anywhere. `sp-scan` then
found both again, so the change stayed in the keyspace it came from.

## The whole loop with no public server

Mutinynet, with `--esplora` pointed at that same node as well. KISS signed a
payment to this wallet's own code
([7844c4b7…](https://mutinynet.com/tx/7844c4b74439fbc982fb716ffd55d1295ecff254e31fd151d40766f5e5fc8a77),
block 3371651), `sp-scan --electrum` found it, and KISS spent it back
([dc87380d…](https://mutinynet.com/tx/dc87380d6921412d7ddd3026e6a9a28f6db9add57983f0f488d7d182cc7804cc),
block 3371657). The blocks, the fee estimate, the tweaks and the broadcast all
came from one node on the same laptop.

## Two sources agreeing

Scanning the same signet range through that node and through the public BlindBit
oracle finds the same output: same outpoint, same amount, same block. Two
independent sources agreeing is the check that matters; 46 s against 5 m 23 s is
the difference in cost.

[tests/rbitcoin_regtest.rs](../tests/rbitcoin_regtest.rs) runs the whole thing
unattended against a local node: mines a coin, pays a real silent payment to
itself, and finds it again knowing only the recipient's keys.
