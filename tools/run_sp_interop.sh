#!/usr/bin/env bash
# Run every required coordinator -> real C signer -> verifier case, offline.
set -euo pipefail
BDK=$(cd "$(dirname "$0")/.." && pwd)
SIGNER=$(cd "${1:?usage: run_sp_interop.sh <kiss-signer-checkout>}" && pwd)
SCRATCH=$(mktemp -d "${TMPDIR:-/tmp}/kiss-sp-interop.XXXXXX")
trap 'rm -rf "$SCRATCH"' EXIT

printf 'Coordinator revision: %s\n' "$(git -C "$BDK" rev-parse HEAD)"
printf 'Signer revision: %s\n' "$(git -C "$SIGNER" rev-parse HEAD)"
git -C "$BDK" status --short
git -C "$SIGNER" status --short
bash "$SIGNER/sim/build_sp_interop.sh" "$SCRATCH/signer"
export KISS_INTEROP_SIGNER="$SCRATCH/signer"
cd "$BDK"

# Cargo returns success when a filter matches zero tests. Require every named
# ignored test before running it, including the combined spend/send/change case.
CASES=(
  sp_psbt:c_signer_bip375_round_trip_and_tampering
  sp_spend_fixtures:c_signer_bip376_round_trip_and_foreign_tweak_refusal
  sp_spend_fixtures:c_signer_sp_payment_and_change_round_trip
)
for spec in "${CASES[@]}"; do
  target=${spec%%:*}
  case_name=${spec#*:}
  cargo test --locked --test "$target" "$case_name" -- --ignored --exact --list > "$SCRATCH/tests"
  if ! grep -Fxq "$case_name: test" "$SCRATCH/tests"; then
    printf 'FAIL: required interop test is missing: %s\n' "$spec" >&2
    exit 1
  fi
  cargo test --locked --test "$target" "$case_name" -- --ignored --exact --nocapture
done
