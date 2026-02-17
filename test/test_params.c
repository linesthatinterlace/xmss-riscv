/**
 * test_params.c - Tests for xmss_params OID table and derivation
 *
 * RFC 8391 §5.3: Verifies that all 12 OIDs produce correct derived parameters.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "test_utils.h"
#include "../include/xmss/params.h"
#include "../include/xmss/xmss.h"

typedef struct {
    uint32_t oid;
    const char *name;
    uint32_t n;
    uint32_t w;
    uint32_t h;
    uint32_t len;      /* len1 + len2 */
    uint32_t sig_bytes;
    uint32_t pk_bytes;
    uint32_t sk_bytes;
    uint32_t idx_bytes;
} expected_params_t;

/*
 * Expected values computed from RFC 8391 §5.3:
 *   n=32, w=16: len1=64, len2=3, len=67
 *   n=64, w=16: len1=128, ... wait, n=64 gives len1 = ceil(8*64/4) = 128;
 *               len2 = floor(log2(128*15)/4)+1 = floor(log2(1920)/4)+1
 *                    = floor(10.9/4)+1 = 2+1 = 3; len = 131.
 *               But XMSS_MAX_WOTS_LEN = 67 which is wrong for n=64!
 *
 * Wait: RFC 8391 Table 2 shows w=16 for all standard sets.
 * For n=64, w=16: len1 = ceil(8*64/log2(16)) = ceil(512/4) = 128.
 * len2 = floor(log2(128*(16-1))/log2(16)) + 1
 *       = floor(log2(1920)/4) + 1
 *       = floor(10.906.../4) + 1
 *       = floor(2.727) + 1 = 2 + 1 = 3.
 * len = 131.
 *
 * So XMSS_MAX_WOTS_LEN should be 131, not 67!
 * The plan says "len for n=64, w=4: len1=64, len2=3, len=67" but RFC
 * standard sets use w=16, not w=4.
 *
 * For n=64, w=16 (standard): len=131.
 * For n=32, w=16 (standard): len=67.
 * XMSS_MAX_WOTS_LEN must be at least 131.
 *
 * This is a bug in the plan. We need to fix XMSS_MAX_WOTS_LEN.
 */

static const expected_params_t expected[] = {
    /* OID, name, n, w, h, len, sig_bytes, pk_bytes, sk_bytes, idx_bytes
     *
     * All RFC 8391 standard sets use w=16.
     * For XMSS (d=1), idx_bytes is always 4 (matching xmss-reference).
     *
     * n=32, w=16: len1=ceil(256/4)=64, len2=3, len=67
     *   sig = 4 + 32*(1 + 67 + h)
     *   pk  = 4 + 2n = 68
     *   sk  = 4 + 4 + 4n = 136
     *
     * h=10: sig=4+32*78=2500
     * h=16: sig=4+32*84=2692
     * h=20: sig=4+32*88=2820
     *
     * n=64, w=16: len1=128, len2=3, len=131
     *   sig = 4 + 64*(1 + 131 + h)
     *   pk  = 4 + 2*64 = 132
     *   sk  = 4 + 4 + 4*64 = 264
     *
     * h=10: sig=4+64*142=9092
     * h=16: sig=4+64*148=9476
     * h=20: sig=4+64*152=9732
     */

    /* SHA-2 n=32 */
    { 0x00000001, "XMSS-SHA2_10_256",  32, 16, 10, 67, 2500, 68, 136, 4 },
    { 0x00000002, "XMSS-SHA2_16_256",  32, 16, 16, 67, 2692, 68, 136, 4 },
    { 0x00000003, "XMSS-SHA2_20_256",  32, 16, 20, 67, 2820, 68, 136, 4 },

    /* SHA-2 n=64 */
    { 0x00000004, "XMSS-SHA2_10_512",  64, 16, 10, 131, 9092,  132, 264, 4 },
    { 0x00000005, "XMSS-SHA2_16_512",  64, 16, 16, 131, 9476,  132, 264, 4 },
    { 0x00000006, "XMSS-SHA2_20_512",  64, 16, 20, 131, 9732,  132, 264, 4 },

    /* SHAKE n=32 */
    { 0x00000007, "XMSS-SHAKE_10_256", 32, 16, 10, 67, 2500, 68, 136, 4 },
    { 0x00000008, "XMSS-SHAKE_16_256", 32, 16, 16, 67, 2692, 68, 136, 4 },
    { 0x00000009, "XMSS-SHAKE_20_256", 32, 16, 20, 67, 2820, 68, 136, 4 },

    /* SHAKE n=64 */
    { 0x0000000A, "XMSS-SHAKE_10_512", 64, 16, 10, 131, 9092,  132, 264, 4 },
    { 0x0000000B, "XMSS-SHAKE_16_512", 64, 16, 16, 131, 9476,  132, 264, 4 },
    { 0x0000000C, "XMSS-SHAKE_20_512", 64, 16, 20, 131, 9732,  132, 264, 4 },
};

#define N_ENTRIES ((int)(sizeof(expected)/sizeof(expected[0])))

static void print_params(const xmss_params *p)
{
    printf("    n=%u w=%u h=%u len1=%u len2=%u len=%u\n",
           p->n, p->w, p->h, p->len1, p->len2, p->len);
    printf("    sig_bytes=%u pk_bytes=%u sk_bytes=%u idx_bytes=%u\n",
           p->sig_bytes, p->pk_bytes, p->sk_bytes, p->idx_bytes);
}

int main(void)
{
    int i;
    xmss_params p;
    char name_buf[64];

    printf("=== test_params ===\n");

    for (i = 0; i < N_ENTRIES; i++) {
        const expected_params_t *e = &expected[i];
        int ret;

        printf("Testing OID 0x%08x (%s):\n", e->oid, e->name);

        /* Test by OID */
        ret = xmss_params_from_oid(&p, e->oid);
        TEST_INT("xmss_params_from_oid returns 0", ret, 0);
        if (ret != 0) { continue; }

        print_params(&p);

        TEST_INT("n",         p.n,         e->n);
        TEST_INT("w",         p.w,         e->w);
        TEST_INT("h",         p.h,         e->h);
        TEST_INT("len",       p.len,       e->len);
        TEST_INT("sig_bytes", p.sig_bytes, e->sig_bytes);
        TEST_INT("pk_bytes",  p.pk_bytes,  e->pk_bytes);
        TEST_INT("sk_bytes",  p.sk_bytes,  e->sk_bytes);
        TEST_INT("idx_bytes", p.idx_bytes, e->idx_bytes);

        /* Test by name */
        ret = xmss_params_from_name(&p, e->name);
        snprintf(name_buf, sizeof(name_buf), "xmss_params_from_name(%s)", e->name);
        TEST_INT(name_buf, ret, 0);
    }

    /* Test invalid OID */
    {
        int ret = xmss_params_from_oid(&p, 0xDEADBEEFU);
        TEST_INT("invalid OID returns error", ret, XMSS_ERR_PARAMS);
    }

    /* Test invalid name */
    {
        int ret = xmss_params_from_name(&p, "XMSS-INVALID");
        TEST_INT("invalid name returns error", ret, XMSS_ERR_PARAMS);
    }

    return tests_done();
}
