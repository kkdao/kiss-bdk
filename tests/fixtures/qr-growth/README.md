# Signed PSBT growth fixture

A synthetic Silent Payments request is exactly 4,096 bytes; the production C
signer returns 4,405 bytes after adding its signature, share, proof and output
script. This reproduces the coordinator's former 4,096-byte receive rejection.
The fixture uses the published `abandon … about` development seed and synthetic
chain data. It contains no user keys, wallet files or real funds.

- `request.b64` and `signed.b64` contain the binary PSBTv2 payloads as Base64.
- `signed-20.parts` contains 442 frames from the firmware's C UR encoder: 221
  source fragments followed by fountain frames, using narrow-board easy-scan's
  20-byte setting.
- `provenance.json` records the signer/coordinator revisions and source/payload
  hashes. The signer baseline is `2c03a85be4079d79e113b1236752d0a391c6396f`.
- `generate.rs` constructs the request and verifies the C signer's response.
  The request reaches the size boundary through a complete synthetic previous
  transaction in `non_witness_utxo`, with its txid and selected output matched
  to the spending input. It does not use unrecognized PSBT padding fields.
- `emit.c` calls the unmodified firmware QR encoder to generate the frame file.

The ordinary QR tests recover the response through rendered QR images and
`k_quirc`, then verify the exact bytes, transaction intent, DLEQ proof, output
script and ECDSA signature. Another test skips the first five source frames
and recovers from the remaining fountain stream. These are offline software
checks, not camera/display measurements on a physical device.

## Regenerate

Use a clean signer checkout at the recorded revision. From the coordinator root:

```sh
bdk_root="$PWD"
signer_root=/absolute/path/to/kiss-signer
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

bash "$signer_root/sim/build_sp_interop.sh" "$scratch/signer"
cargo run --offline --locked --example qr-growth-fixture -- "$scratch/signer" "$scratch"
(
  cd "$signer_root"
  clang -O1 -w -Imain -Icomponents/cUR/src \
    main/qr_transport.c components/cUR/src/*.c components/cUR/src/types/*.c \
    components/cUR/src/sha256/sha256.c \
    "$bdk_root/tests/fixtures/qr-growth/emit.c" -o "$scratch/emit"
)
"$scratch/emit" "$scratch/signed.psbt" > "$scratch/signed-20.parts"

python3 - "$scratch" <<'PY'
import base64
import pathlib
import sys

actual = pathlib.Path(sys.argv[1])
expected = pathlib.Path('tests/fixtures/qr-growth')
for stem in ('request', 'signed'):
    assert (actual / (stem + '.psbt')).read_bytes() == base64.b64decode(
        (expected / (stem + '.b64')).read_bytes())
assert (actual / 'signed-20.parts').read_bytes() == (expected / 'signed-20.parts').read_bytes()
print('Request, signed reply and C UR frames reproduced byte-for-byte.')
PY
```

The generator clears ambient test mnemonic/passphrase overrides, signs only in
its own temporary directory, verifies before writing, and refuses to overwrite
its output PSBT files. Cargo dependencies must already be cached for `--offline`.
