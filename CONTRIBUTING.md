# Contributing

## Before you push

```sh
cargo fmt --all
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
```

CI runs exactly these. Tests that need a network or a device are `#[ignore]`d
and say what they need in their own module comment, so a green `cargo test` is
a real statement rather than a partial one.

## Say whether hardware was tested

Anything touching a hardware or IO path — QR encoding or decoding, the camera,
the PSBT bytes a device parses, what a review screen shows — needs a plain
verdict in the pull request:

- **DEVICE TEST: REQUIRED**, with the exact flows to run and why, or
- **DEVICE TEST: NOT REQUIRED**, with the concrete reason hardware cannot change
  the outcome.

Passing tests are not that verdict and do not substitute for it. A change can be
green here and still refuse to load on a device, which is the failure this rule
exists to catch.

## No tool or agent is named anywhere

Not in a commit trailer, a pull request body, an issue, a code comment or a doc.
CI enforces it on commits and tracked files, because it cannot be undone
afterwards: GitHub writes `refs/pull/*/head` itself and never lets it be
rewritten.

The record is for whoever reads it later working out why a line exists. Who
held the keyboard is not part of that.

## Comments carry the why

The code says what it does. A comment is worth keeping when it explains a
protocol rule, an invariant, or why an obvious approach is wrong — the kind of
thing someone would otherwise reintroduce as a bug. Restating the next
statement in English is not worth keeping.

## Test networks only

`init` refuses mainnet and a wallet directory is pinned to its network. Do not
add a path around that. See [SECURITY.md](SECURITY.md).
