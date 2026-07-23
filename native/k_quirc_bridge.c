#include "k_quirc.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

// Keep k_quirc_result_t on the C side so Rust never has to duplicate its
// layout. The capacity check also makes future payload-size changes safe.
int kiss_k_quirc_decode_payload(k_quirc_t *quirc, int index, uint8_t *payload,
                                size_t capacity) {
  k_quirc_result_t result;
  if (!quirc || !payload ||
      k_quirc_decode(quirc, index, &result) != K_QUIRC_SUCCESS ||
      !result.valid || result.data.payload_len <= 0)
    return 0;

  size_t length = (size_t)result.data.payload_len;
  if (length > capacity)
    return -1;
  memcpy(payload, result.data.payload, length);
  return result.data.payload_len;
}
