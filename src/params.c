/**
 * params.c - XMSS parameter set derivation
 *
 * RFC 8391 §5.3: all 12 XMSS parameter sets.
 * Formulae from RFC 8391 §3.1 and §5.3.
 */
#include <string.h>
#include <stddef.h>

#include "../include/xmss/params.h"
#include "../include/xmss/xmss.h"

/* ceil(a/b) for positive integers */
static uint32_t ceil_div(uint32_t a, uint32_t b)
{
    return (a + b - 1) / b;
}

/* floor(log2(x)) for x > 0 */
static uint32_t floor_log2(uint32_t x)
{
    uint32_t r = 0;
    while (x > 1) { x >>= 1; r++; }
    return r;
}

/*
 * Derive all computed fields given the primitive parameters.
 * Returns 0 on success.
 */
static int derive_params(xmss_params *p)
{
    /* log2(w) */
    if (p->w == 4)        { p->log2_w = 2; }
    else if (p->w == 16)  { p->log2_w = 4; }
    else { return -1; }

    /* RFC 8391 §3.1.1 */
    p->len1 = ceil_div(8 * p->n, p->log2_w);
    p->len2 = floor_log2(p->len1 * (p->w - 1)) / p->log2_w + 1;
    p->len  = p->len1 + p->len2;

    if (p->len > XMSS_MAX_WOTS_LEN) { return -1; }

    /* d = 1 for XMSS */
    p->d = 1;

    /* pad_len: n bytes for all standard parameter sets */
    p->pad_len = p->n;

    /* idx_bytes: 4 for XMSS (d=1), ceil(h/8) for XMSS-MT */
    if (p->d == 1) {
        p->idx_bytes = 4;
    } else {
        p->idx_bytes = ceil_div(p->h, 8);
    }

    /* idx_max = 2^h - 1 */
    p->idx_max = ((uint64_t)1 << p->h) - 1;

    /*
     * sig_bytes = idx_bytes + n + len*n + h*n
     *           = idx_bytes + (1 + len + h) * n
     * (RFC 8391 §4.1.8)
     */
    p->sig_bytes = p->idx_bytes + (1 + p->len + p->h) * p->n;

    /*
     * pk_bytes = 4 (OID) + n (root) + n (SEED)
     * (RFC 8391 §4.1.7)
     */
    p->pk_bytes = 4 + 2 * p->n;

    /*
     * sk_bytes = 4 (OID) + idx_bytes + n (SK_SEED) + n (SK_PRF)
     *          + n (root) + n (SEED)
     * (RFC 8391 §4.1.3, Errata 7900)
     */
    p->sk_bytes = 4 + p->idx_bytes + 4 * p->n;

    return 0;
}

/*
 * Static OID table.  All 12 RFC 8391 XMSS parameter sets.
 * Fields: oid, func, n, w, h.  Remaining fields derived by derive_params().
 */
typedef struct {
    uint32_t oid;
    const char *name;
    uint8_t  func;
    uint32_t n;
    uint32_t w;
    uint32_t h;
} oid_entry_t;

static const oid_entry_t oid_table[] = {
    /* SHA-2 based */
    { OID_XMSS_SHA2_10_256,  "XMSS-SHA2_10_256",  XMSS_FUNC_SHA2,    32, 16, 10 },
    { OID_XMSS_SHA2_16_256,  "XMSS-SHA2_16_256",  XMSS_FUNC_SHA2,    32, 16, 16 },
    { OID_XMSS_SHA2_20_256,  "XMSS-SHA2_20_256",  XMSS_FUNC_SHA2,    32, 16, 20 },
    { OID_XMSS_SHA2_10_512,  "XMSS-SHA2_10_512",  XMSS_FUNC_SHA2,    64, 16, 10 },
    { OID_XMSS_SHA2_16_512,  "XMSS-SHA2_16_512",  XMSS_FUNC_SHA2,    64, 16, 16 },
    { OID_XMSS_SHA2_20_512,  "XMSS-SHA2_20_512",  XMSS_FUNC_SHA2,    64, 16, 20 },
    /* SHAKE based */
    { OID_XMSS_SHAKE_10_256, "XMSS-SHAKE_10_256", XMSS_FUNC_SHAKE128, 32, 16, 10 },
    { OID_XMSS_SHAKE_16_256, "XMSS-SHAKE_16_256", XMSS_FUNC_SHAKE128, 32, 16, 16 },
    { OID_XMSS_SHAKE_20_256, "XMSS-SHAKE_20_256", XMSS_FUNC_SHAKE128, 32, 16, 20 },
    { OID_XMSS_SHAKE_10_512, "XMSS-SHAKE_10_512", XMSS_FUNC_SHAKE256, 64, 16, 10 },
    { OID_XMSS_SHAKE_16_512, "XMSS-SHAKE_16_512", XMSS_FUNC_SHAKE256, 64, 16, 16 },
    { OID_XMSS_SHAKE_20_512, "XMSS-SHAKE_20_512", XMSS_FUNC_SHAKE256, 64, 16, 20 },
};

#define OID_TABLE_SIZE ((uint32_t)(sizeof(oid_table) / sizeof(oid_table[0])))

int xmss_params_from_oid(xmss_params *p, uint32_t oid)
{
    uint32_t i;
    for (i = 0; i < OID_TABLE_SIZE; i++) {
        if (oid_table[i].oid == oid) {
            p->oid  = oid_table[i].oid;
            p->func = oid_table[i].func;
            p->n    = oid_table[i].n;
            p->w    = oid_table[i].w;
            p->h    = oid_table[i].h;
            return derive_params(p);
        }
    }
    return XMSS_ERR_PARAMS;
}

int xmss_params_from_name(xmss_params *p, const char *name)
{
    uint32_t i;
    for (i = 0; i < OID_TABLE_SIZE; i++) {
        if (strcmp(oid_table[i].name, name) == 0) {
            p->oid  = oid_table[i].oid;
            p->func = oid_table[i].func;
            p->n    = oid_table[i].n;
            p->w    = oid_table[i].w;
            p->h    = oid_table[i].h;
            return derive_params(p);
        }
    }
    return XMSS_ERR_PARAMS;
}
