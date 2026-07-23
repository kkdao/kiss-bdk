# K-Quirc

A standalone QR code recognition and decoding library optimized for embedded systems. Adapted from [OpenMV](https://github.com/openmv/openmv)'s quirc implementation, itself based on Daniel Beer's [quirc](https://github.com/dlbeer/quirc).

## Features

- QR code versions 1-25 (up to ~2,500-byte payloads)
- All four ECC levels (L/M/Q/H)
- Numeric, Alphanumeric, Byte, and Kanji data types
- Inverted QR code detection (white-on-black)
- Multiple QR codes per image
- Extended Channel Interpretation (ECI) support

### Optimizations over upstream quirc

- **Bilinear thresholding** -- 4-quadrant Otsu with fixed-point 16.16 interpolation handles uneven lighting
- **Adaptive threshold** -- auto-adjusts offset from timing pattern analysis for improved reliability
- **Span-based flood fill** -- line-based fill with explicit stack avoids recursion
- **ESP32 memory layout** -- large buffers in SPIRAM (cache-aligned), temporary buffers in internal RAM
- **FreeRTOS integration** -- task yields during long loops to prevent watchdog timeout

On non-ESP platforms, memory allocation falls back to standard `malloc`/`free`.

## Usage

### ESP-IDF component

Add as a component in your ESP-IDF project and include the header:

```c
#include "k_quirc.h"
```

### One-shot API

For simple use cases, decode grayscale image data in a single call:

```c
k_quirc_result_t results[4];
int count = k_quirc_decode_grayscale(grayscale_buf, width, height,
                                     results, 4, false);
for (int i = 0; i < count; i++) {
    if (results[i].valid) {
        printf("QR: %.*s\n", results[i].data.payload_len,
               results[i].data.payload);
    }
}
```

### Step-by-step API

For repeated scanning (e.g. camera feed), reuse the decoder instance:

```c
// Create once
k_quirc_t *q = k_quirc_new();
k_quirc_resize(q, width, height);

// Per frame
int w, h;
uint8_t *buf = k_quirc_begin(q, &w, &h);
// Fill buf with grayscale image data (w * h bytes)
memcpy(buf, frame_data, w * h);
k_quirc_end(q, false);  // true to also detect inverted QR codes

int count = k_quirc_count(q);
for (int i = 0; i < count; i++) {
    k_quirc_result_t result;
    k_quirc_error_t err = k_quirc_decode(q, i, &result);
    if (err == K_QUIRC_SUCCESS && result.valid) {
        // result.data.payload, result.data.payload_len
        // result.corners[0..3] for position
    }
}

// Cleanup
k_quirc_destroy(q);
```

## Build options

Feature flags are set as compile definitions in `CMakeLists.txt`:

| Flag | Default | Description |
|------|---------|-------------|
| `K_QUIRC_BILINEAR_THRESHOLD` | Enabled | 4-quadrant Otsu thresholding for uneven lighting |
| `K_QUIRC_ADAPTIVE_THRESHOLD` | Enabled | Auto-adjust threshold offset from timing patterns |
| `K_QUIRC_DEBUG` | Disabled | Debug visualization (thresholded buffer with grid overlays) |

## Constraints

- Maximum image size: 1280x1280 pixels
- Maximum QR version: 25 (117x117 modules)
- Flood-fill stack: 8,192 entries

## License

MIT -- see source file headers for full copyright notices.

**Original:** Daniel Beer (2010-2012)
**OpenMV modifications:** Ibrahim Abdelkader, Kwabena W. Agyeman (2013-2021)
