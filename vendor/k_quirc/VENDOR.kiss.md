# Vendored: odudex/k_quirc

- Upstream: https://github.com/odudex/k_quirc
- Pinned commit: `06549efae32a4378216b868b2fc2e93cbcdd9707` (the exact SHA Kern pins as its
  `components/k_quirc` submodule, checked 2026-07-04).
- License: MIT (quirc by Daniel Beer + OpenMV + Kern modifications; see LICENSE).
- Local changes: ONE patch in `src/k_quirc.c` `k_quirc_decode()` — corner coordinates are
  copied into the result BEFORE the decode-error check (upstream only copies them on
  success). Corners come from `quirc_extract_internal` and are valid for any located grid;
  the scan UI uses them to warn when the QR is clipped by the frame edge. `test/`
  (desktop validation harness + 292KB stb_image.h), `.git`, `.github/` stripped.
- Device-only component: the desktop sim/test builds never compile it (camera is a device path).
