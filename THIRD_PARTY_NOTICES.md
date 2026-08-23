# Third party notices

## k_quirc

`vendor/k_quirc` is a vendored copy of the QR decoder the KISS signing device runs, so
that a QR this coordinator fails to decode fails the same way on both sides.

Licensed MIT. Full text in [`vendor/k_quirc/LICENSE`](vendor/k_quirc/LICENSE).

```
Original Copyright (C) 2010-2012 Daniel Beer <dlbeer@gmail.com>
OpenMV modifications Copyright (c) 2013-2021 Ibrahim Abdelkader <iabdalkader@openmv.io>
OpenMV modifications Copyright (c) 2013-2021 Kwabena W. Agyeman <kwagyeman@openmv.io>
K-Quirc modifications Copyright (c) 2025 Kern contributors
```

## Rust dependencies

Everything else arrives through Cargo and keeps its own licence. To see them:

```sh
cargo install cargo-license
cargo license
```
