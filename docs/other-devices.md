# Using another signing device

Nothing here is tied to KISS except the QR commands. `create` writes a PSBT file
and `broadcast` reads one back, so any device that can load a file will do,
whether it ships BIP-375 and BIP-376 today or you are adding them.

No node and no webcam needed: the check runs offline, against files.

```sh
kiss-bdk init --network signet --descriptor "<your device's descriptor>"
kiss-bdk create --to tsp1… --sats 10000 --out unsigned.psbt
# sign unsigned.psbt on your device, save it as signed.psbt
kiss-bdk broadcast signed.psbt --original unsigned.psbt --dry-run
```

That last line is the point. It trusts nothing the device sends back: same
transaction, DLEQ proof, re-derived output script, every signature checked
against a key worked out here. And it names which part failed. Fix, repeat.

## Receiving too

BIP-352 does not say how a device should hand its scan key over, so pair from
the two keys directly:

```sh
kiss-bdk sp-pair --keys SCAN_PRIVATE_HEX:SPEND_PUBLIC_HEX
```

64 hex digits then 66. From there `sp-address`, `sp-scan` and `--from-sp` all
work as they do for KISS.

## Fixtures to test against

The exact bytes `create` emits are asserted in
[tests/sp_spend_psbt.rs](../tests/sp_spend_psbt.rs), so it is a specification
you can diff against rather than a description.

[tests/sp_spend_fixtures.rs](../tests/sp_spend_fixtures.rs) writes PSBTs for a
device's own harness, including one whose tweak does not reproduce the output
key, which a correct device must refuse.

For a fast loop, `--network regtest` against a
[local node](node.md) has no faucet and no ten-minute blocks.
