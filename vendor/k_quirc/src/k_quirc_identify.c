/*
 * K-Quirc Identification Module
 * QR code detection: flood-fill, thresholding, capstone and grid detection
 */

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "k_quirc_internal.h"

/*
 * LIFO (stack) for flood-fill — uses persistent buffer from struct k_quirc
 */
typedef struct {
  int16_t x, y, l, r;
} xylf_t;

typedef struct {
  xylf_t *data;
  size_t len;
  size_t capacity;
  bool *overflow;
} lifo_t;

ALWAYS_INLINE int lifo_push(lifo_t *s, const xylf_t *item) {
  if (s->len < s->capacity) {
    s->data[s->len++] = *item;
    return 1;
  }
  if (s->overflow)
    *s->overflow = true;
  return 0;
}

ALWAYS_INLINE void lifo_pop(lifo_t *s, xylf_t *item) {
  *item = s->data[--s->len];
}

/*
 * Linear algebra routines
 */
static int line_intersect(const struct quirc_point *p0,
                          const struct quirc_point *p1,
                          const struct quirc_point *q0,
                          const struct quirc_point *q1, struct quirc_point *r) {
  int a = -(p1->y - p0->y);
  int b = p1->x - p0->x;
  int c = -(q1->y - q0->y);
  int d = q1->x - q0->x;
  int e = a * p1->x + b * p1->y;
  int f = c * q1->x + d * q1->y;
  int det = (a * d) - (b * c);

  if (!det)
    return 0;

  r->x = (d * e - b * f) / det;
  r->y = (-c * e + a * f) / det;
  return 1;
}

static int perspective_setup(float *c, const struct quirc_point *rect, float w,
                             float h) {
  float x0 = rect[0].x;
  float y0 = rect[0].y;
  float x1 = rect[1].x;
  float y1 = rect[1].y;
  float x2 = rect[2].x;
  float y2 = rect[2].y;
  float x3 = rect[3].x;
  float y3 = rect[3].y;

  float wden = w * (x2 * y3 - x3 * y2 + (x3 - x2) * y1 + x1 * (y2 - y3));
  float hden = h * (x2 * y3 + x1 * (y2 - y3) - x3 * y2 + (x3 - x2) * y1);

  if (fabsf(wden) < 1e-6f || fabsf(hden) < 1e-6f) {
    memset(c, 0, sizeof(float) * QUIRC_PERSPECTIVE_PARAMS);
    return 0;
  }

  c[0] = (x1 * (x2 * y3 - x3 * y2) +
          x0 * (-x2 * y3 + x3 * y2 + (x2 - x3) * y1) + x1 * (x3 - x2) * y0) /
         wden;
  c[1] = -(x0 * (x2 * y3 + x1 * (y2 - y3) - x2 * y1) - x1 * x3 * y2 +
           x2 * x3 * y1 + (x1 * x3 - x2 * x3) * y0) /
         hden;
  c[2] = x0;
  c[3] = (y0 * (x1 * (y3 - y2) - x2 * y3 + x3 * y2) + y1 * (x2 * y3 - x3 * y2) +
          x0 * y1 * (y2 - y3)) /
         wden;
  c[4] = (x0 * (y1 * y3 - y2 * y3) + x1 * y2 * y3 - x2 * y1 * y3 +
          y0 * (x3 * y2 - x1 * y2 + (x2 - x3) * y1)) /
         hden;
  c[5] = y0;
  c[6] = (x1 * (y3 - y2) + x0 * (y2 - y3) + (x2 - x3) * y1 + (x3 - x2) * y0) /
         wden;
  c[7] = (-x2 * y3 + x1 * y3 + x3 * y2 + x0 * (y1 - y2) - x3 * y1 +
          (x2 - x1) * y0) /
         hden;
  return 1;
}

static int solve_8x8_system(float A[8][8], float b[8], float x[8]) {
  for (int k = 0; k < 8; k++) {
    int max_row = k;
    float max_val = fabsf(A[k][k]);
    for (int i = k + 1; i < 8; i++) {
      if (fabsf(A[i][k]) > max_val) {
        max_val = fabsf(A[i][k]);
        max_row = i;
      }
    }

    if (max_row != k) {
      for (int j = k; j < 8; j++) {
        float tmp = A[k][j];
        A[k][j] = A[max_row][j];
        A[max_row][j] = tmp;
      }
      float tmp = b[k];
      b[k] = b[max_row];
      b[max_row] = tmp;
    }

    float pivot = A[k][k];
    if (fabsf(pivot) < 1e-10f) {
      for (int i = 0; i < 8; i++)
        x[i] = 0.0f;
      return 0;
    }

    for (int i = k + 1; i < 8; i++) {
      float factor = A[i][k] / pivot;
      for (int j = k; j < 8; j++) {
        A[i][j] -= factor * A[k][j];
      }
      b[i] -= factor * b[k];
    }
  }

  for (int i = 7; i >= 0; i--) {
    x[i] = b[i];
    for (int j = i + 1; j < 8; j++) {
      x[i] -= A[i][j] * x[j];
    }
    x[i] /= A[i][i];
  }
  return 1;
}

static int perspective_setup_direct(float *c, const float img[4][2],
                                    const float mod[4][2]) {
  float A[8][8];
  float b[8];

  for (int i = 0; i < 4; i++) {
    float u = mod[i][0], v = mod[i][1];
    float x = img[i][0], y = img[i][1];
    int row1 = i * 2, row2 = i * 2 + 1;

    A[row1][0] = u;
    A[row1][1] = v;
    A[row1][2] = 1.0f;
    A[row1][3] = 0.0f;
    A[row1][4] = 0.0f;
    A[row1][5] = 0.0f;
    A[row1][6] = -u * x;
    A[row1][7] = -v * x;
    b[row1] = x;

    A[row2][0] = 0.0f;
    A[row2][1] = 0.0f;
    A[row2][2] = 0.0f;
    A[row2][3] = u;
    A[row2][4] = v;
    A[row2][5] = 1.0f;
    A[row2][6] = -u * y;
    A[row2][7] = -v * y;
    b[row2] = y;
  }

  return solve_8x8_system(A, b, c);
}

static int perspective_unmap(const float *c, const struct quirc_point *in,
                             float *u, float *v) {
  float x = in->x;
  float y = in->y;
  float den = -c[0] * c[7] * y + c[1] * c[6] * y +
              (c[3] * c[7] - c[4] * c[6]) * x + c[0] * c[4] - c[1] * c[3];

  if (fabsf(den) < 1e-6f)
    return 0;

  *u = -(c[1] * (y - c[5]) - c[2] * c[7] * y + (c[5] * c[7] - c[4]) * x +
         c[2] * c[4]) /
       den;
  *v = (c[0] * (y - c[5]) - c[2] * c[6] * y + (c[5] * c[6] - c[3]) * x +
        c[2] * c[3]) /
       den;
  return 1;
}

/*
 * Span-based floodfill routine
 */
typedef void (*span_func_t)(void *user_data, int y, int left, int right);

HOT_FUNC
static void flood_fill_seed(struct k_quirc *q, int x, int y,
                            quirc_pixel_t from_color, quirc_pixel_t to_color,
                            span_func_t func, void *user_data, int depth) {
  (void)depth;

  lifo_t lifo;
  lifo.data = (xylf_t *)q->flood_fill_stack;
  lifo.len = 0;
  lifo.capacity = QUIRC_FLOOD_FILL_STACK;
  lifo.overflow = &q->flood_fill_overflow;

  for (;;) {
    int left = x;
    int right = x;
    quirc_pixel_t *row = q->pixels + y * q->w;

    while (left > 0 && row[left - 1] == from_color)
      left--;

    while (right < q->w - 1 && row[right + 1] == from_color)
      right++;

    for (int i = left; i <= right; i++)
      row[i] = to_color;

    if (func)
      func(user_data, y, left, right);

    for (;;) {
      bool recurse = false;

      if (lifo.len < lifo.capacity) {
        if (y > 0) {
          row = q->pixels + (y - 1) * q->w;
          for (int i = left; i <= right; i++) {
            if (row[i] == from_color) {
              xylf_t context = {(int16_t)x, (int16_t)y, (int16_t)left,
                                (int16_t)right};
              if (!lifo_push(&lifo, &context))
                return;
              x = i;
              y = y - 1;
              recurse = true;
              break;
            }
          }
        }

        if (!recurse && y < q->h - 1) {
          row = q->pixels + (y + 1) * q->w;
          for (int i = left; i <= right; i++) {
            if (row[i] == from_color) {
              xylf_t context = {(int16_t)x, (int16_t)y, (int16_t)left,
                                (int16_t)right};
              if (!lifo_push(&lifo, &context))
                return;
              x = i;
              y = y + 1;
              recurse = true;
              break;
            }
          }
        }
      }

      if (!recurse) {
        if (!lifo.len)
          return;

        xylf_t context;
        lifo_pop(&lifo, &context);
        x = context.x;
        y = context.y;
        left = context.l;
        right = context.r;
      } else {
        break;
      }
    }
  }
}

/*
 * Thresholding with Otsu's method
 */
static uint8_t otsu_threshold(uint32_t *histogram, uint32_t total) {
  float sum = 0;
  for (int i = 0; i < 256; i++) {
    sum += (float)i * histogram[i];
  }

  float sumB = 0;
  uint32_t wB = 0;
  float varMax = 0;
  uint8_t threshold = 0;

  for (int i = 0; i < 256; i++) {
    wB += histogram[i];
    if (wB == 0)
      continue;

    uint32_t wF = total - wB;
    if (wF == 0)
      break;

    sumB += (float)i * histogram[i];
    float mB = sumB / wB;
    float mF = (sum - sumB) / wF;
    float mDiff = mB - mF;

    float varBetween = (float)wB * (float)wF * mDiff * mDiff;
    if (varBetween >= varMax) {
      varMax = varBetween;
      threshold = i;
    }
  }

  return threshold;
}

// Percentage of image border to ignore for threshold calculation (0.0 - 0.5)
// 0.2 = ignore 20% on each edge, leaving 60% central region
#define K_QUIRC_THRESHOLD_MARGIN 0.2f

#ifdef K_QUIRC_ADAPTIVE_THRESHOLD
static int default_threshold_offset = K_QUIRC_THRESHOLD_OFFSET_DEFAULT;
#endif

static inline int clamp_threshold(int t) {
  return (t < 0) ? 0 : (t > 255) ? 255 : t;
}

HOT_FUNC
static void threshold(struct k_quirc *q, bool inverted) {
  int w = q->w;
  int h = q->h;
  quirc_pixel_t *pixels = q->pixels;

  /* XOR mask unifies inverted/non-inverted into a single comparison.
   * Normal: pixel < threshold = black. Inverted: (pixel^0xFF) < threshold. */
  uint8_t xor_mask = inverted ? 0xFF : 0x00;

#ifdef K_QUIRC_BILINEAR_THRESHOLD
  int mid_x = w / 2;
  int mid_y = h / 2;

  int half_w = (int)(w * (0.5f - K_QUIRC_THRESHOLD_MARGIN));
  int half_h = (int)(h * (0.5f - K_QUIRC_THRESHOLD_MARGIN));
  int sample_start_x = mid_x - half_w;
  int sample_end_x = mid_x + half_w;
  int sample_start_y = mid_y - half_h;
  int sample_end_y = mid_y + half_h;

  uint32_t hist_tl[256] = {0}, hist_tr[256] = {0};
  uint32_t hist_bl[256] = {0}, hist_br[256] = {0};

  for (int y = sample_start_y; y < sample_end_y; y++) {
    quirc_pixel_t *row = pixels + y * w;
    if (y < mid_y) {
      for (int x = sample_start_x; x < mid_x; x++)
        hist_tl[row[x]]++;
      for (int x = mid_x; x < sample_end_x; x++)
        hist_tr[row[x]]++;
    } else {
      for (int x = sample_start_x; x < mid_x; x++)
        hist_bl[row[x]]++;
      for (int x = mid_x; x < sample_end_x; x++)
        hist_br[row[x]]++;
    }
  }

  uint32_t quad_pixels = (uint32_t)half_w * half_h;
#ifdef K_QUIRC_ADAPTIVE_THRESHOLD
  int t_tl = clamp_threshold(otsu_threshold(hist_tl, quad_pixels) +
                             q->threshold_offset);
  int t_tr = clamp_threshold(otsu_threshold(hist_tr, quad_pixels) +
                             q->threshold_offset);
  int t_bl = clamp_threshold(otsu_threshold(hist_bl, quad_pixels) +
                             q->threshold_offset);
  int t_br = clamp_threshold(otsu_threshold(hist_br, quad_pixels) +
                             q->threshold_offset);
#else
  int t_tl = otsu_threshold(hist_tl, quad_pixels);
  int t_tr = otsu_threshold(hist_tr, quad_pixels);
  int t_bl = otsu_threshold(hist_bl, quad_pixels);
  int t_br = otsu_threshold(hist_br, quad_pixels);
#endif

  /* Fixed-point 16.16 bilinear interpolation — all integer math */
  int inv_h_dim = (h > 1) ? h - 1 : 1;
  int tl_fp = t_tl << 16;
  int tr_fp = t_tr << 16;
  int dl_fp = ((t_bl - t_tl) << 16) / inv_h_dim;
  int dr_fp = ((t_br - t_tr) << 16) / inv_h_dim;

  int inv_w_dim = (w > 1) ? w - 1 : 1;

  for (int y = 0; y < h; y++) {
    int t_left_fp = tl_fp + y * dl_fp;
    int t_right_fp = tr_fp + y * dr_fp;
    int delta = t_right_fp - t_left_fp;
    int dt_fp = delta / inv_w_dim;
    int rem = delta - dt_fp * inv_w_dim;
    int abs_rem = (rem >= 0) ? rem : -rem;
    int step_corr = (rem >= 0) ? 1 : -1;
    int error = 0;
    int t_fp = t_left_fp;

    quirc_pixel_t *row = pixels + y * w;

    for (int x = 0; x < w; x++) {
      int t = t_fp >> 16;
      row[x] =
          ((row[x] ^ xor_mask) < t) ? QUIRC_PIXEL_BLACK : QUIRC_PIXEL_WHITE;
      t_fp += dt_fp;
      error += abs_rem;
      if (error >= inv_w_dim) {
        t_fp += step_corr;
        error -= inv_w_dim;
      }
    }
  }

#else /* !K_QUIRC_BILINEAR_THRESHOLD */
  int margin_x = (int)(w * K_QUIRC_THRESHOLD_MARGIN);
  int margin_y = (int)(h * K_QUIRC_THRESHOLD_MARGIN);
  int sample_start_x = margin_x;
  int sample_end_x = w - margin_x;
  int sample_start_y = margin_y;
  int sample_end_y = h - margin_y;

  uint32_t histogram[256] = {0};
  uint32_t sampled_pixels = 0;
  for (int y = sample_start_y; y < sample_end_y; y++) {
    quirc_pixel_t *row = pixels + y * w;
    for (int x = sample_start_x; x < sample_end_x; x++) {
      histogram[row[x]]++;
      sampled_pixels++;
    }
  }

#ifdef K_QUIRC_ADAPTIVE_THRESHOLD
  uint8_t t = clamp_threshold(otsu_threshold(histogram, sampled_pixels) +
                              q->threshold_offset);
#else
  uint8_t t = otsu_threshold(histogram, sampled_pixels);
#endif

  int total_pixels = w * h;
  for (int i = 0; i < total_pixels; i++)
    pixels[i] =
        ((pixels[i] ^ xor_mask) < t) ? QUIRC_PIXEL_BLACK : QUIRC_PIXEL_WHITE;
#endif /* K_QUIRC_BILINEAR_THRESHOLD */
}

ALWAYS_INLINE void area_count(void *user_data, int y, int left, int right) {
  (void)y;
  ((struct quirc_region *)user_data)->count += right - left + 1;
}

HOT_FUNC
static int region_code(struct k_quirc *q, int x, int y) {
  int pixel;
  struct quirc_region *box;
  int region;

  if (x < 0 || y < 0 || x >= q->w || y >= q->h)
    return -1;

  pixel = q->pixels[y * q->w + x];

  if (pixel >= QUIRC_PIXEL_REGION)
    return pixel;

  if (pixel == QUIRC_PIXEL_WHITE)
    return -1;

  if (q->num_regions >= QUIRC_MAX_REGIONS)
    return -1;

  region = q->num_regions;
  box = &q->regions[q->num_regions++];

  memset(box, 0, sizeof(*box));

  box->seed.x = x;
  box->seed.y = y;
  box->capstone = -1;

  q->flood_fill_overflow = false;
  flood_fill_seed(q, x, y, pixel, region, area_count, box, 0);
  if (q->flood_fill_overflow) {
    box->count = 0;
    box->capstone = -1;
    return -1;
  }

  return region;
}

struct polygon_score_data {
  struct quirc_point ref;
  int scores[4];
  struct quirc_point *corners;
};

static void find_one_corner(void *user_data, int y, int left, int right) {
  struct polygon_score_data *psd = (struct polygon_score_data *)user_data;
  int xs[2] = {left, right};
  int dy = y - psd->ref.y;

  for (int i = 0; i < 2; i++) {
    int dx = xs[i] - psd->ref.x;
    int d = dx * dx + dy * dy;

    if (d > psd->scores[0]) {
      psd->scores[0] = d;
      psd->corners[0].x = xs[i];
      psd->corners[0].y = y;
    }
  }
}

static void find_other_corners(void *user_data, int y, int left, int right) {
  struct polygon_score_data *psd = (struct polygon_score_data *)user_data;
  int xs[2] = {left, right};

  for (int i = 0; i < 2; i++) {
    int up = xs[i] * psd->ref.x + y * psd->ref.y;
    int rt = xs[i] * -psd->ref.y + y * psd->ref.x;
    int scores[4] = {up, rt, -up, -rt};

    for (int j = 0; j < 4; j++) {
      if (scores[j] > psd->scores[j]) {
        psd->scores[j] = scores[j];
        psd->corners[j].x = xs[i];
        psd->corners[j].y = y;
      }
    }
  }
}

static void find_region_corners(struct k_quirc *q, int rcode,
                                const struct quirc_point *ref,
                                struct quirc_point *corners) {
  struct quirc_region *region = &q->regions[rcode];
  struct polygon_score_data psd;

  memset(&psd, 0, sizeof(psd));
  psd.corners = corners;

  memcpy(&psd.ref, ref, sizeof(psd.ref));
  psd.scores[0] = -1;
  q->flood_fill_overflow = false;
  flood_fill_seed(q, region->seed.x, region->seed.y, rcode, QUIRC_PIXEL_BLACK,
                  find_one_corner, &psd, 0);
  if (q->flood_fill_overflow)
    return;

  psd.ref.x = psd.corners[0].x - psd.ref.x;
  psd.ref.y = psd.corners[0].y - psd.ref.y;

  for (int i = 0; i < 4; i++)
    memcpy(&psd.corners[i], &region->seed, sizeof(psd.corners[i]));

  int i = region->seed.x * psd.ref.x + region->seed.y * psd.ref.y;
  psd.scores[0] = i;
  psd.scores[2] = -i;
  i = region->seed.x * -psd.ref.y + region->seed.y * psd.ref.x;
  psd.scores[1] = i;
  psd.scores[3] = -i;

  flood_fill_seed(q, region->seed.x, region->seed.y, QUIRC_PIXEL_BLACK, rcode,
                  find_other_corners, &psd, 0);
}

static void record_capstone(struct k_quirc *q, int ring, int stone) {
  struct quirc_region *stone_reg = &q->regions[stone];
  struct quirc_region *ring_reg = &q->regions[ring];
  struct quirc_capstone *capstone;
  int cs_index;

  if (q->num_capstones >= QUIRC_MAX_CAPSTONES)
    return;

  cs_index = q->num_capstones;
  capstone = &q->capstones[q->num_capstones++];

  memset(capstone, 0, sizeof(*capstone));

  capstone->qr_grid = -1;
  capstone->ring = ring;
  capstone->stone = stone;
  stone_reg->capstone = cs_index;
  ring_reg->capstone = cs_index;

  find_region_corners(q, ring, &stone_reg->seed, capstone->corners);
  if (q->flood_fill_overflow ||
      !perspective_setup(capstone->c, capstone->corners, 7.0f, 7.0f)) {
    stone_reg->capstone = -1;
    ring_reg->capstone = -1;
    q->num_capstones = cs_index;
    return;
  }
  perspective_map(capstone->c, 3.5f, 3.5f, &capstone->center);
}

static void test_capstone(struct k_quirc *q, int x, int y, int *pb) {
  int ring_right_x = x - pb[4];
  int ring_left_x = x - pb[4] - pb[3] - pb[2] - pb[1] - pb[0];
  int stone_x = x - pb[4] - pb[3] - pb[2];
  int ring_right = region_code(q, ring_right_x, y);
  int ring_left = region_code(q, ring_left_x, y);

  if (ring_left < 0 || ring_right < 0)
    return;

  if (ring_left != ring_right)
    return;

  int stone = region_code(q, stone_x, y);
  if (stone < 0)
    return;

  if (ring_left == stone)
    return;

  struct quirc_region *stone_reg = &q->regions[stone];
  struct quirc_region *ring_reg = &q->regions[ring_left];

  if (stone_reg->capstone >= 0 || ring_reg->capstone >= 0)
    return;

  if (ring_reg->count <= 0)
    return;

  int ratio = stone_reg->count * 100 / ring_reg->count;
  if (ratio < 5 || ratio > 80)
    return;

  record_capstone(q, ring_left, stone);
}

static void finder_scan(struct k_quirc *q, int y) {
  quirc_pixel_t *row = q->pixels + y * q->w;
  uint8_t last_color;
  int run_length = 1;
  int run_count = 0;
  int pb[5];

  memset(pb, 0, sizeof(pb));
  last_color = row[0];
  for (int x = 1; x < q->w; x++) {
    uint8_t color = row[x];

    if (color != last_color) {
      pb[0] = pb[1];
      pb[1] = pb[2];
      pb[2] = pb[3];
      pb[3] = pb[4];
      pb[4] = run_length;
      run_length = 0;
      run_count++;

      if (!color && run_count >= 5) {
        int avg = (pb[0] + pb[1] + pb[3] + pb[4]) >> 2;
        if (avg == 0)
          avg = 1;
        int err = (avg * 3) >> 2;

        /* Check 1:1:3:1:1 finder pattern ratio */
        int lo = avg - err;
        int hi = avg + err;
        int lo3 = avg * 3 - err;
        int hi3 = avg * 3 + err;

        if (pb[0] >= lo && pb[0] <= hi && pb[1] >= lo && pb[1] <= hi &&
            pb[2] >= lo3 && pb[2] <= hi3 && pb[3] >= lo && pb[3] <= hi &&
            pb[4] >= lo && pb[4] <= hi) {
          test_capstone(q, x, y, pb);
        }
      }
    }

    run_length++;
    last_color = color;
  }
}

static void find_alignment_pattern(struct k_quirc *q, int index) {
  struct quirc_grid *qr = &q->grids[index];
  struct quirc_capstone *c0 = &q->capstones[qr->caps[0]];
  struct quirc_capstone *c2 = &q->capstones[qr->caps[2]];
  struct quirc_point a;
  struct quirc_point b;
  struct quirc_point c;
  int size_estimate;
  int step_size = 1;
  int dir = 0;
  float u, v;

  memcpy(&b, &qr->align, sizeof(b));

  if (!perspective_unmap(c0->c, &b, &u, &v))
    return;
  perspective_map(c0->c, u, v + 1.0f, &a);
  if (!perspective_unmap(c2->c, &b, &u, &v))
    return;
  perspective_map(c2->c, u + 1.0f, v, &c);

  size_estimate = abs((a.x - b.x) * -(c.y - b.y) + (a.y - b.y) * (c.x - b.x));

  while (step_size * step_size < size_estimate * 100) {
    static const int dx_map[] = {1, 0, -1, 0};
    static const int dy_map[] = {0, -1, 0, 1};

    for (int i = 0; i < step_size; i++) {
      int code = region_code(q, b.x, b.y);

      if (code >= 0) {
        struct quirc_region *reg = &q->regions[code];

        if (reg->count >= size_estimate / 2 &&
            reg->count <= size_estimate * 2) {
          qr->align_region = code;
          return;
        }
      }

      b.x += dx_map[dir];
      b.y += dy_map[dir];
    }

    dir = (dir + 1) % 4;
    if (!(dir & 1))
      step_size++;
  }
}

HOT_FUNC
static int fitness_cell(const struct k_quirc *q, int index, int x, int y) {
  const struct quirc_grid *qr = &q->grids[index];
  int score = 0;
  struct quirc_point p;
  static const float offsets[] = {0.3f, 0.5f, 0.7f};
  int w = q->w;
  int h = q->h;
  const quirc_pixel_t *pixels = q->pixels;

  for (int v = 0; v < 3; v++) {
    float yoff = y + offsets[v];
    for (int u = 0; u < 3; u++) {
      perspective_map(qr->c, x + offsets[u], yoff, &p);

      if (LIKELY(p.y >= 0 && p.y < h && p.x >= 0 && p.x < w)) {
        score += pixels[p.y * w + p.x] ? 1 : -1;
      }
    }
  }

  return score;
}

static int fitness_ring(const struct k_quirc *q, int index, int cx, int cy,
                        int radius) {
  int score = 0;

  for (int i = 0; i < radius * 2; i++) {
    score += fitness_cell(q, index, cx - radius + i, cy - radius);
    score += fitness_cell(q, index, cx - radius, cy + radius - i);
    score += fitness_cell(q, index, cx + radius, cy - radius + i);
    score += fitness_cell(q, index, cx + radius - i, cy + radius);
  }

  return score;
}

static int fitness_apat(const struct k_quirc *q, int index, int cx, int cy) {
  return fitness_cell(q, index, cx, cy) - fitness_ring(q, index, cx, cy, 1) +
         fitness_ring(q, index, cx, cy, 2);
}

static int fitness_capstone(const struct k_quirc *q, int index, int x, int y) {
  x += 3;
  y += 3;

  return fitness_cell(q, index, x, y) + fitness_ring(q, index, x, y, 1) -
         fitness_ring(q, index, x, y, 2) + fitness_ring(q, index, x, y, 3);
}

static int fitness_all(const struct k_quirc *q, int index) {
  const struct quirc_grid *qr = &q->grids[index];
  int version = (qr->grid_size - 17) / 4;
  int score = 0;
  int ap_count;

  for (int i = 0; i < qr->grid_size - 14; i++) {
    int expect = (i & 1) ? 1 : -1;
    score += fitness_cell(q, index, i + 7, 6) * expect;
    score += fitness_cell(q, index, 6, i + 7) * expect;
  }

  score += fitness_capstone(q, index, 0, 0);
  score += fitness_capstone(q, index, qr->grid_size - 7, 0);
  score += fitness_capstone(q, index, 0, qr->grid_size - 7);

  if (version < 0 || version > QUIRC_MAX_VERSION)
    return score;

  const struct quirc_version_info *info = &quirc_version_db[version];
  ap_count = 0;
  while ((ap_count < QUIRC_MAX_ALIGNMENT) && info->apat[ap_count])
    ap_count++;

  for (int i = 1; i + 1 < ap_count; i++) {
    score += fitness_apat(q, index, 6, info->apat[i]);
    score += fitness_apat(q, index, info->apat[i], 6);
  }

  for (int i = 1; i < ap_count; i++)
    for (int j = 1; j < ap_count; j++)
      score += fitness_apat(q, index, info->apat[i], info->apat[j]);

  return score;
}

#ifdef K_QUIRC_ADAPTIVE_THRESHOLD
static int timing_bias(const struct k_quirc *q, int index) {
  const struct quirc_grid *qr = &q->grids[index];
  int bias = 0;

  for (int i = 0; i < qr->grid_size - 14; i++) {
    int cell_h = fitness_cell(q, index, i + 7, 6);
    int cell_v = fitness_cell(q, index, 6, i + 7);

    if (i & 1) {
      if (cell_h < 0)
        bias++;
      if (cell_v < 0)
        bias++;
    } else {
      if (cell_h > 0)
        bias--;
      if (cell_v > 0)
        bias--;
    }
  }
  return bias;
}

static int clamp_threshold_offset(int offset) {
  if (offset > K_QUIRC_THRESHOLD_OFFSET_MAX)
    return K_QUIRC_THRESHOLD_OFFSET_MAX;
  if (offset < -K_QUIRC_THRESHOLD_OFFSET_MAX)
    return -K_QUIRC_THRESHOLD_OFFSET_MAX;
  return offset;
}

static void update_threshold_offset(struct k_quirc *q, int bias) {
  if (bias > 0)
    q->threshold_offset++;
  else if (bias < 0)
    q->threshold_offset--;

  q->threshold_offset = clamp_threshold_offset(q->threshold_offset);
}

int k_quirc_get_threshold_offset(void) { return default_threshold_offset; }
void k_quirc_set_threshold_offset(int offset) {
  default_threshold_offset = clamp_threshold_offset(offset);
}
int k_quirc_get_threshold_offset_for(const struct k_quirc *q) {
  return q ? q->threshold_offset : default_threshold_offset;
}
void k_quirc_set_threshold_offset_for(struct k_quirc *q, int offset) {
  if (q)
    q->threshold_offset = clamp_threshold_offset(offset);
}
#else
int k_quirc_get_threshold_offset(void) { return 0; }
void k_quirc_set_threshold_offset(int offset) { (void)offset; }
int k_quirc_get_threshold_offset_for(const struct k_quirc *q) {
  (void)q;
  return 0;
}
void k_quirc_set_threshold_offset_for(struct k_quirc *q, int offset) {
  (void)q;
  (void)offset;
}
#endif

#define JIGGLE_PASSES 2

static void jiggle_perspective(struct k_quirc *q, int index) {
  struct quirc_grid *qr = &q->grids[index];
  int best = fitness_all(q, index);
  float adjustments[8];

  float step_factor = 0.42f / (float)qr->grid_size;
  for (int i = 0; i < 8; i++)
    adjustments[i] = qr->c[i] * step_factor;

  for (int pass = 0; pass < JIGGLE_PASSES; pass++) {
    for (int i = 0; i < 16; i++) {
      int j = i >> 1;
      float old = qr->c[j];
      float step = adjustments[j];
      float new_val = (i & 1) ? old + step : old - step;

      qr->c[j] = new_val;
      int test = fitness_all(q, index);

      if (test > best)
        best = test;
      else
        qr->c[j] = old;
    }

    for (int i = 0; i < 8; i++)
      adjustments[i] *= 0.5f;
  }
}

static int setup_qr_perspective(struct k_quirc *q, int index) {
  struct quirc_grid *qr = &q->grids[index];
  float gs = (float)qr->grid_size;

  struct quirc_point *c0 = &q->capstones[qr->caps[0]].center;
  struct quirc_point *c1 = &q->capstones[qr->caps[1]].center;
  struct quirc_point *c2 = &q->capstones[qr->caps[2]].center;

  float img[4][2] = {{(float)c1->x, (float)c1->y},
                     {(float)c2->x, (float)c2->y},
                     {(float)qr->align.x, (float)qr->align.y},
                     {(float)c0->x, (float)c0->y}};

  float mod[4][2] = {{3.5f, 3.5f},
                     {gs - 3.5f, 3.5f},
                     {gs - 6.5f, gs - 6.5f},
                     {3.5f, gs - 3.5f}};

  if (qr->grid_size == 21) {
    mod[2][0] = gs - 7.0f;
    mod[2][1] = gs - 7.0f;
  }

  if (!perspective_setup_direct(qr->c, img, mod))
    return 0;

  jiggle_perspective(q, index);

#ifdef K_QUIRC_ADAPTIVE_THRESHOLD
  qr->timing_bias = timing_bias(q, index);
  if (!q->processing_inverted)
    update_threshold_offset(q, qr->timing_bias);
#endif
  return 1;
}

static float length(struct quirc_point a, struct quirc_point b) {
  float dx = (float)(abs(a.x - b.x) + 1);
  float dy = (float)(abs(a.y - b.y) + 1);
  return sqrtf(dx * dx + dy * dy);
}

static void measure_grid_size(struct k_quirc *q, int index) {
  struct quirc_grid *qr = &q->grids[index];

  struct quirc_capstone *a = &(q->capstones[qr->caps[0]]);
  struct quirc_capstone *b = &(q->capstones[qr->caps[1]]);
  struct quirc_capstone *c = &(q->capstones[qr->caps[2]]);

  float ab = length(b->corners[0], a->corners[3]);
  float capstone_ab_size = (length(b->corners[0], b->corners[3]) +
                            length(a->corners[0], a->corners[3])) *
                           0.5f;
  float ver_grid = 7.0f * ab / capstone_ab_size;

  float bc = length(b->corners[0], c->corners[1]);
  float capstone_bc_size = (length(b->corners[0], b->corners[1]) +
                            length(c->corners[0], c->corners[1])) *
                           0.5f;
  float hor_grid = 7.0f * bc / capstone_bc_size;

  float grid_size_estimate = (ver_grid + hor_grid) * 0.5f;

  int ver = (int)((grid_size_estimate - 15.0f) * 0.25f);
  if (ver > QUIRC_MAX_VERSION)
    ver = QUIRC_MAX_VERSION;

  qr->grid_size = 4 * ver + 17;
}

static int rotate_capstone(struct quirc_capstone *cap,
                           const struct quirc_point *h0,
                           const struct quirc_point *hd) {
  struct quirc_point copy[4];
  float c[QUIRC_PERSPECTIVE_PARAMS];
  int best = 0;
  int best_score = 0;

  for (int j = 0; j < 4; j++) {
    struct quirc_point *p = &cap->corners[j];
    int score = (p->x - h0->x) * -hd->y + (p->y - h0->y) * hd->x;

    if (!j || score < best_score) {
      best = j;
      best_score = score;
    }
  }

  for (int j = 0; j < 4; j++)
    memcpy(&copy[j], &cap->corners[(j + best) % 4], sizeof(copy[j]));
  if (!perspective_setup(c, copy, 7.0f, 7.0f))
    return 0;

  memcpy(cap->corners, copy, sizeof(cap->corners));
  memcpy(cap->c, c, sizeof(c));
  return 1;
}

static void record_qr_grid(struct k_quirc *q, int a, int b, int c) {
  struct quirc_point h0, hd;
  struct quirc_grid *qr;

  if (q->num_grids >= QUIRC_MAX_GRIDS)
    return;

  memcpy(&h0, &q->capstones[a].center, sizeof(h0));
  hd.x = q->capstones[c].center.x - q->capstones[a].center.x;
  hd.y = q->capstones[c].center.y - q->capstones[a].center.y;

  if ((q->capstones[b].center.x - h0.x) * -hd.y +
          (q->capstones[b].center.y - h0.y) * hd.x >
      0) {
    int swap = a;
    a = c;
    c = swap;
    hd.x = -hd.x;
    hd.y = -hd.y;
  }

  qr = &q->grids[q->num_grids];
  memset(qr, 0, sizeof(*qr));
  qr->caps[0] = a;
  qr->caps[1] = b;
  qr->caps[2] = c;
  qr->align_region = -1;

  for (int i = 0; i < 3; i++) {
    struct quirc_capstone *cap = &q->capstones[qr->caps[i]];
    if (!rotate_capstone(cap, &h0, &hd))
      return;
  }

  measure_grid_size(q, q->num_grids);

  if (qr->grid_size < 21)
    return;

  if (qr->grid_size > 177)
    return;

  if (!line_intersect(&q->capstones[a].corners[0], &q->capstones[a].corners[1],
                      &q->capstones[c].corners[0], &q->capstones[c].corners[3],
                      &qr->align))
    return;

  if (qr->grid_size > 21) {
    find_alignment_pattern(q, q->num_grids);
    if (qr->align_region >= 0) {
      /* Use the centroid of the alignment region, not the seed point.
       * The seed is just the first pixel the spiral search landed on,
       * which can be at the edge of the region rather than its center.
       * This offset skews the perspective transform and causes decode
       * failures, especially for low-version QR codes captured at
       * high resolution where each module consists of many pixels. */
      struct quirc_region *areg = &q->regions[qr->align_region];
      int code = qr->align_region;
      int est = (int)sqrtf((float)areg->count) + 2;
      int x0 = areg->seed.x - est, y0 = areg->seed.y - est;
      int x1 = areg->seed.x + est, y1 = areg->seed.y + est;
      if (x0 < 0)
        x0 = 0;
      if (y0 < 0)
        y0 = 0;
      if (x1 >= q->w)
        x1 = q->w - 1;
      if (y1 >= q->h)
        y1 = q->h - 1;
      long sum_x = 0, sum_y = 0;
      int n = 0;
      for (int sy = y0; sy <= y1; sy++) {
        for (int sx = x0; sx <= x1; sx++) {
          if (q->pixels[sy * q->w + sx] == code) {
            sum_x += sx;
            sum_y += sy;
            n++;
          }
        }
      }
      if (n > 0) {
        qr->align.x = (int)(sum_x / n);
        qr->align.y = (int)(sum_y / n);
      } else {
        memcpy(&qr->align, &areg->seed, sizeof(qr->align));
      }
    }
  }

  if (!setup_qr_perspective(q, q->num_grids))
    return;

  for (int i = 0; i < 3; i++)
    q->capstones[qr->caps[i]].qr_grid = q->num_grids;

  q->num_grids++;
}

/*
 * Geometric grouping: detect right-angle triangles formed by capstone centers.
 *
 * In a valid QR code the three finder patterns always form a right-angle
 * triangle.  The right-angle vertex is the "top-left" capstone in QR
 * terminology.  We detect this directly from image-space distances using the
 * Pythagorean theorem, which is far more robust than perspective_unmap when
 * the QR code is viewed at a steep angle or is very dense.
 */
ALWAYS_INLINE float dist2(const struct quirc_point *a,
                          const struct quirc_point *b) {
  float dx = (float)(a->x - b->x);
  float dy = (float)(a->y - b->y);
  return dx * dx + dy * dy;
}

/* Maximum candidate triplets to evaluate before selecting the best */
#define MAX_CANDIDATES 16

struct triplet_candidate {
  int leg1, vertex, leg2;
  float score; /* higher = better (leg_ratio * (1 - pyth_error)) */
};

static void geometric_grouping(struct k_quirc *q) {
  int n = q->num_capstones;
  struct triplet_candidate candidates[MAX_CANDIDATES];
  int ncand = 0;

  /* Collect all valid right-angle triplets */
  for (int i = 0; i < n - 2; i++) {
    for (int j = i + 1; j < n - 1; j++) {
      for (int k = j + 1; k < n; k++) {

        float d2_ij = dist2(&q->capstones[i].center, &q->capstones[j].center);
        float d2_ik = dist2(&q->capstones[i].center, &q->capstones[k].center);
        float d2_jk = dist2(&q->capstones[j].center, &q->capstones[k].center);

        /* Find hypotenuse (longest side).  The vertex opposite it has the
         * right angle and corresponds to the top-left finder pattern. */
        float d2_hyp, d2_a, d2_b;
        int vertex, leg1, leg2;

        if (d2_jk >= d2_ij && d2_jk >= d2_ik) {
          d2_hyp = d2_jk;
          d2_a = d2_ij;
          d2_b = d2_ik;
          vertex = i;
          leg1 = j;
          leg2 = k;
        } else if (d2_ik >= d2_ij && d2_ik >= d2_jk) {
          d2_hyp = d2_ik;
          d2_a = d2_ij;
          d2_b = d2_jk;
          vertex = j;
          leg1 = i;
          leg2 = k;
        } else {
          d2_hyp = d2_ij;
          d2_a = d2_ik;
          d2_b = d2_jk;
          vertex = k;
          leg1 = i;
          leg2 = j;
        }

        /* Pythagorean check: a² + b² ≈ c²  (right-angle test) */
        float expected = d2_a + d2_b;
        if (expected < 100.0f)
          continue;

        float pyth_error = fabsf(1.0f - d2_hyp / expected);
        if (pyth_error > 0.25f)
          continue;

        /* Leg ratio: reject if legs are wildly different (squared) */
        float leg_ratio = (d2_a < d2_b) ? d2_a / d2_b : d2_b / d2_a;
        if (leg_ratio < 0.1f)
          continue;

        if (ncand < MAX_CANDIDATES) {
          candidates[ncand].leg1 = leg1;
          candidates[ncand].vertex = vertex;
          candidates[ncand].leg2 = leg2;
          /* Score: prefer square triangles with perfect right angles */
          candidates[ncand].score = leg_ratio * (1.0f - pyth_error);
          ncand++;
        }
      }
    }
  }

  /* Sort candidates by score descending (simple insertion sort) */
  for (int i = 1; i < ncand; i++) {
    struct triplet_candidate tmp = candidates[i];
    int j = i - 1;
    while (j >= 0 && candidates[j].score < tmp.score) {
      candidates[j + 1] = candidates[j];
      j--;
    }
    candidates[j + 1] = tmp;
  }

  /* Record grids in score order, skipping capstones already used */
  for (int i = 0; i < ncand; i++) {
    if (q->num_grids >= QUIRC_MAX_GRIDS)
      return;
    int l1 = candidates[i].leg1;
    int v = candidates[i].vertex;
    int l2 = candidates[i].leg2;
    if (q->capstones[l1].qr_grid >= 0 || q->capstones[v].qr_grid >= 0 ||
        q->capstones[l2].qr_grid >= 0)
      continue;
    record_qr_grid(q, l1, v, l2);
  }
}

static void pixels_setup(struct k_quirc *q) {
  if (sizeof(*q->image) == sizeof(*q->pixels)) {
    q->pixels = (quirc_pixel_t *)q->image;
  } else {
    int total = q->w * q->h;
    for (int i = 0; i < total; i++)
      q->pixels[i] = q->image[i];
  }
}

/*
 * Public identification function
 */
void k_quirc_identify(struct k_quirc *q, bool find_inverted) {
  if (!q)
    return;

#ifdef K_QUIRC_ADAPTIVE_THRESHOLD
  q->processing_inverted = false;
#endif
  pixels_setup(q);
  threshold(q, false);

  for (int i = 0; i < q->h; i++)
    finder_scan(q, i);

  geometric_grouping(q);

#ifdef K_QUIRC_INVERTED_RETRY
  if (q->num_grids == 0 && find_inverted) {
    vTaskDelay(1);
#ifdef K_QUIRC_ADAPTIVE_THRESHOLD
    q->processing_inverted = true;
#endif
    q->num_regions = QUIRC_PIXEL_REGION;
    q->num_capstones = 0;
    q->num_grids = 0;

    pixels_setup(q);
    threshold(q, true);

    for (int i = 0; i < q->h; i++)
      finder_scan(q, i);

    geometric_grouping(q);
  }
#else
  (void)find_inverted;
#endif
}
