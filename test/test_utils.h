/**
 * test_utils.h - Test utilities
 */
#ifndef XMSS_TEST_UTILS_H
#define XMSS_TEST_UTILS_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Simple test framework */
static int test_pass = 0;
static int test_fail = 0;

#define TEST(name, cond) do { \
    if (cond) { \
        printf("  PASS: %s\n", name); \
        test_pass++; \
    } else { \
        printf("  FAIL: %s\n", name); \
        test_fail++; \
    } \
} while(0)

#define TEST_BYTES(name, a, b, n) do { \
    if (memcmp(a, b, n) == 0) { \
        printf("  PASS: %s\n", name); \
        test_pass++; \
    } else { \
        printf("  FAIL: %s\n", name); \
        hex_print("    got", (const uint8_t *)(a), n); \
        hex_print("    exp", (const uint8_t *)(b), n); \
        test_fail++; \
    } \
} while(0)

#define TEST_INT(name, a, b) do { \
    long long test__a = (long long)(a), test__b = (long long)(b); \
    if (test__a == test__b) { \
        printf("  PASS: %s\n", name); \
        test_pass++; \
    } else { \
        printf("  FAIL: %s (got %lld, expected %lld)\n", name, test__a, test__b); \
        test_fail++; \
    } \
} while(0)

static inline int tests_done(void)
{
    printf("Results: %d passed, %d failed\n", test_pass, test_fail);
    return test_fail > 0 ? 1 : 0;
}

/* Parse hex string into bytes; return 0 on success */
static inline int hex_decode(uint8_t *out, const char *hex, size_t nbytes)
{
    size_t i;
    for (i = 0; i < nbytes; i++) {
        unsigned int v = 0;
        if (sscanf(hex + 2*i, "%02x", &v) != 1) { return -1; }
        out[i] = (uint8_t)v;
    }
    return 0;
}

static inline void hex_print(const char *label, const uint8_t *data, size_t len)
{
    size_t i;
    printf("%s: ", label);
    for (i = 0; i < len; i++) { printf("%02x", data[i]); }
    printf("\n");
}

/* Deterministic "random" bytes from a counter for testing */
static uint64_t test_rng_counter = 0;

static inline void test_rng_reset(uint64_t seed)
{
    test_rng_counter = seed;
}

static inline int test_randombytes(uint8_t *buf, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++) {
        buf[i] = (uint8_t)(test_rng_counter >> (8 * (i & 7)));
        if ((i & 7) == 7) { test_rng_counter++; }
    }
    test_rng_counter++;
    return 0;
}

/* ====================================================================
 * Test buffer helpers — reduce malloc/free boilerplate in roundtrip tests
 * ==================================================================== */

#include "../include/xmss/xmss.h"

/** Common buffers for XMSS roundtrip tests. */
typedef struct {
    xmss_params p;
    uint8_t *pk;
    uint8_t *sk;
    uint8_t *sig;
    xmss_bds_state *state;
} xmss_test_ctx;

/** Initialise from an OID.  Returns 0 on success, -1 on failure. */
static inline int xmss_test_ctx_init(xmss_test_ctx *ctx, uint32_t oid)
{
    if (xmss_params_from_oid(&ctx->p, oid) != 0) { return -1; }
    ctx->pk    = (uint8_t *)malloc(ctx->p.pk_bytes);
    ctx->sk    = (uint8_t *)malloc(ctx->p.sk_bytes);
    ctx->sig   = (uint8_t *)malloc(ctx->p.sig_bytes);
    ctx->state = (xmss_bds_state *)malloc(sizeof(xmss_bds_state));
    if (!ctx->pk || !ctx->sk || !ctx->sig || !ctx->state) {
        free(ctx->pk); free(ctx->sk); free(ctx->sig); free(ctx->state);
        return -1;
    }
    return 0;
}

static inline void xmss_test_ctx_free(xmss_test_ctx *ctx)
{
    free(ctx->pk); free(ctx->sk); free(ctx->sig); free(ctx->state);
}

/** Common buffers for XMSS-MT roundtrip tests. */
typedef struct {
    xmss_params p;
    uint8_t *pk;
    uint8_t *sk;
    uint8_t *sig;
    xmss_mt_state *state;
} xmss_mt_test_ctx;

/** Initialise from an XMSS-MT OID.  Returns 0 on success, -1 on failure. */
static inline int xmss_mt_test_ctx_init(xmss_mt_test_ctx *ctx, uint32_t oid)
{
    if (xmss_mt_params_from_oid(&ctx->p, oid) != 0) { return -1; }
    ctx->pk    = (uint8_t *)malloc(ctx->p.pk_bytes);
    ctx->sk    = (uint8_t *)malloc(ctx->p.sk_bytes);
    ctx->sig   = (uint8_t *)malloc(ctx->p.sig_bytes);
    ctx->state = (xmss_mt_state *)malloc(sizeof(xmss_mt_state));
    if (!ctx->pk || !ctx->sk || !ctx->sig || !ctx->state) {
        free(ctx->pk); free(ctx->sk); free(ctx->sig); free(ctx->state);
        return -1;
    }
    return 0;
}

static inline void xmss_mt_test_ctx_free(xmss_mt_test_ctx *ctx)
{
    free(ctx->pk); free(ctx->sk); free(ctx->sig); free(ctx->state);
}

#endif /* XMSS_TEST_UTILS_H */
