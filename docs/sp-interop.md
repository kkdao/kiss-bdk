# Silent Payment regression checks

Run the coordinator against the actual C signer in a local checkout:

```sh
bash tools/run_sp_interop.sh ../kiss-signer
```

Requires clang and the usual coordinator build dependencies. The runner builds
the signer's production PSBT and Silent Payment code, then explicitly runs all
three required integration tests. A missing test is a failure, not a zero-test
success. Test keys are public development keys; no device, wallet database,
network service or broadcast is involved. Cargo can download dependencies.
Temporary binaries and signing directories are removed after the run.

The cases cover BIP-375 sending, BIP-376 spending and invalid-tweak refusal,
and BIP-376 spending to a Silent Payment recipient with Silent Payment change.
The combined case covers both input-key parities, multiple inputs, distinct
recipients and paying the same code twice. Rust verifies the returned intent,
proofs, scripts and signatures, finalizes the transaction, and scans it to
recover the change (and both outputs when paying ourselves). Redirecting either
output or changing the change amount must fail verification.

The `Silent Payment interoperability` workflow runs on PRs and main pushes.
It tests the coordinator under review against a pinned signer commit; manual
dispatch accepts another signer ref. The signer repository also runs this suite
against its own source and the coordinator's main branch. Both revisions are
printed so a CI result can be reproduced with exact checkouts.

Publish the coordinator runner/tests before enabling the companion signer
workflow: it deliberately fails if the required suite is missing. This is a
cross-repository rollout requirement, not a reason to skip the tests. Repository
branch protection must require the new check to prevent merging a failing PR;
adding a workflow does not change GitHub's branch protection settings.

This checks the two implementations together. Independent third-party
validation and physical device UI/QR/SD tests remain separate checks.
