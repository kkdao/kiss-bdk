/*
 * K-Quirc Internal Header
 * Internal types, macros, and shared structures
 */

#ifndef K_QUIRC_INTERNAL_H
#define K_QUIRC_INTERNAL_H

#include "k_quirc.h"
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef ESP_PLATFORM
#include <esp_heap_caps.h>
static inline void *k_malloc_large(size_t size) {
  void *ptr = heap_caps_malloc(size, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT |
                                         MALLOC_CAP_CACHE_ALIGNED);
  if (!ptr)
    ptr = heap_caps_malloc(size, MALLOC_CAP_8BIT);
  return ptr;
}

static inline void *k_malloc_fast(size_t size) {
  void *ptr = heap_caps_malloc(size, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
  if (!ptr)
    ptr = k_malloc_large(size);
  return ptr;
}

#define K_MALLOC(size) k_malloc_large(size)
#define K_MALLOC_FAST(size) k_malloc_fast(size)
#define K_MALLOC_CONTEXT(size) k_malloc_fast(size)
#define K_MALLOC_IMAGE(size) k_malloc_large(size)
#define K_MALLOC_SCRATCH(size) k_malloc_fast(size)
#define K_FREE(ptr) heap_caps_free(ptr)
#else
#define K_MALLOC(size) malloc(size)
#define K_MALLOC_FAST(size) malloc(size)
#define K_MALLOC_CONTEXT(size) malloc(size)
#define K_MALLOC_IMAGE(size) malloc(size)
#define K_MALLOC_SCRATCH(size) malloc(size)
#define K_FREE(ptr) free(ptr)
#endif

/* Compiler optimization hints */
#ifndef __GNUC__
#define __attribute__(x)
#endif

#define HOT_FUNC __attribute__((hot))
#define ALWAYS_INLINE __attribute__((always_inline)) static inline
#define LIKELY(x) __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)

/* Quirc internal definitions */
#define QUIRC_PIXEL_WHITE 0
#define QUIRC_PIXEL_BLACK 1
#define QUIRC_PIXEL_REGION 2

#ifndef QUIRC_MAX_REGIONS
#define QUIRC_MAX_REGIONS 254
#endif

#define QUIRC_MAX_CAPSTONES 32
#define QUIRC_MAX_GRIDS 8
#define QUIRC_PERSPECTIVE_PARAMS 8
#define QUIRC_MAX_VERSION 25
#define QUIRC_MAX_ALIGNMENT 7
#define QUIRC_FLOOD_FILL_STACK 8192
#define K_QUIRC_MAX_IMAGE_DIM 1280
#define K_QUIRC_THRESHOLD_OFFSET_DEFAULT 10
#define K_QUIRC_THRESHOLD_OFFSET_MAX 20

#if QUIRC_MAX_REGIONS < UINT8_MAX
typedef uint8_t quirc_pixel_t;
#elif QUIRC_MAX_REGIONS < UINT16_MAX
typedef uint16_t quirc_pixel_t;
#else
#error "QUIRC_MAX_REGIONS > 65534 is not supported"
#endif

/*
 * Internal structures
 */
struct quirc_point {
  int x;
  int y;
};

struct quirc_region {
  struct quirc_point seed;
  int count;
  int capstone;
};

struct quirc_capstone {
  int ring;
  int stone;
  struct quirc_point corners[4];
  struct quirc_point center;
  float c[QUIRC_PERSPECTIVE_PARAMS];
  int qr_grid;
};

struct quirc_grid {
  int caps[3];
  int align_region;
  struct quirc_point align;
  int grid_size;
  float c[QUIRC_PERSPECTIVE_PARAMS];
  int timing_bias;
};

struct quirc_code {
  struct quirc_point corners[4];
  int size;
  uint8_t cell_bitmap[K_QUIRC_MAX_BITMAP];
};

struct quirc_data {
  int version;
  int ecc_level;
  int mask;
  int data_type;
  uint8_t payload[K_QUIRC_MAX_PAYLOAD];
  int payload_len;
  uint32_t eci;
};

struct datastream {
  uint8_t raw[K_QUIRC_MAX_PAYLOAD];
  int data_bits;
  int ptr;
  uint8_t data[K_QUIRC_MAX_PAYLOAD];
};

struct k_quirc {
  uint8_t *image;
  quirc_pixel_t *pixels;
  uint8_t *flood_fill_stack;
  bool owns_pixels;
  bool flood_fill_overflow;
#ifdef K_QUIRC_ADAPTIVE_THRESHOLD
  int threshold_offset;
  bool processing_inverted;
#endif
  int w;
  int h;
  int num_regions;
  struct quirc_region regions[QUIRC_MAX_REGIONS];
  int num_capstones;
  struct quirc_capstone capstones[QUIRC_MAX_CAPSTONES];
  int num_grids;
  struct quirc_grid grids[QUIRC_MAX_GRIDS];
  struct quirc_code code_scratch;
  struct quirc_data data_scratch;
  struct datastream ds_scratch;
};

/*
 * Version info structure
 */
struct quirc_rs_params {
  uint8_t bs;
  uint8_t dw;
  uint8_t ns;
};

struct quirc_version_info {
  uint16_t data_bytes;
  uint8_t apat[QUIRC_MAX_ALIGNMENT];
  struct quirc_rs_params ecc[4];
};

/* Version database - defined in k_quirc_version.c */
extern const struct quirc_version_info quirc_version_db[QUIRC_MAX_VERSION + 1];

/*
 * Helper functions
 */
ALWAYS_INLINE int fast_roundf(float x) { return (int)(x + 0.5f); }

ALWAYS_INLINE void perspective_map(const float *c, float u, float v,
                                   struct quirc_point *ret) {
  float den = c[6] * u + c[7] * v + 1.0f;
  float inv_den = 1.0f / den;
  float x = (c[0] * u + c[1] * v + c[2]) * inv_den;
  float y = (c[3] * u + c[4] * v + c[5]) * inv_den;

  ret->x = fast_roundf(x);
  ret->y = fast_roundf(y);
}

/*
 * Identification module functions (k_quirc_identify.c)
 */
void k_quirc_identify(struct k_quirc *q, bool find_inverted);
int k_quirc_get_threshold_offset(void);
void k_quirc_set_threshold_offset(int offset);
int k_quirc_get_threshold_offset_for(const struct k_quirc *q);
void k_quirc_set_threshold_offset_for(struct k_quirc *q, int offset);

/*
 * Decode module functions (k_quirc_decode.c)
 */
void quirc_extract_internal(const struct k_quirc *q, int index,
                            struct quirc_code *code);
k_quirc_error_t quirc_decode_internal(const struct quirc_code *code,
                                      struct quirc_data *data,
                                      struct datastream *ds);

#endif /* K_QUIRC_INTERNAL_H */
