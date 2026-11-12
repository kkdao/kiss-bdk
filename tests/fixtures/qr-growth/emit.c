/* Test-only driver for the unmodified firmware's C UR encoder. */
#include <stdio.h>
#include <stdlib.h>
#include "qr_transport.h"
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    unsigned char raw[QRT_MAX_SIGNED_PSBT + 1];
    FILE *f = fopen(argv[1], "rb");
    if (!f) return 2;
    size_t n = fread(raw, 1, sizeof raw, f);
    int bad = ferror(f) || n > QRT_MAX_SIGNED_PSBT;
    fclose(f);
    if (bad) return 2;
    qrt_encoder_t *enc = qrt_encoder_new_frag(QRT_FMT_UR, raw, n, 20);
    if (!enc) return 2;
    int count = qrt_encoder_parts(enc);
    fprintf(stderr, "%zu signed bytes; %d source fragments at 20 bytes; emitting %d frames\n", n, count, 2 * count);
    char part[600];
    for (int i = 0; i < 2 * count; ++i) {
        if (qrt_encoder_next(enc, part, sizeof part)) { qrt_encoder_free(enc); return 2; }
        puts(part);
    }
    qrt_encoder_free(enc);
    return 0;
}
