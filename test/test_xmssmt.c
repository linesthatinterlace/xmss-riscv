/**
 * test_xmssmt.c - Integration tests for XMSS-MT keygen/sign/verify
 *
 * Uses BDS-accelerated hypertree operations.
 *
 * Tests:
 * - keygen -> sign -> verify roundtrip (XMSSMT-SHA2_20/2_256)
 * - Bit-flip and wrong-message rejection
 * - Sequential signing: 5 signatures all verify
 * - Tree boundary crossing: 1024 signatures (crosses layer-0 tree)
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "test_utils.h"
#include "../include/xmss/xmss.h"
#include "../include/xmss/params.h"

/* Smallest practical XMSS-MT: h=20, d=2, tree_height=10 */
#define TEST_OID OID_XMSSMT_SHA2_20_2_256

static void test_roundtrip(void)
{
    xmss_params p;
    xmssmt_state *state;
    uint8_t *pk, *sk, *sig;
    const char *msg = "Hello, XMSS-MT!";
    size_t msglen = strlen(msg);
    int ret;

    printf("\n--- roundtrip ---\n");

    ret = xmssmt_params_from_oid(&p, TEST_OID);
    TEST_INT("params_from_oid", ret, 0);
    if (ret != 0) { return; }

    printf("  sig_bytes=%u pk_bytes=%u sk_bytes=%u\n",
           p.sig_bytes, p.pk_bytes, p.sk_bytes);
    printf("  h=%u d=%u tree_height=%u idx_bytes=%u\n",
           p.h, p.d, p.tree_height, p.idx_bytes);

    pk    = (uint8_t *)malloc(p.pk_bytes);
    sk    = (uint8_t *)malloc(p.sk_bytes);
    sig   = (uint8_t *)malloc(p.sig_bytes);
    state = (xmssmt_state *)malloc(sizeof(xmssmt_state));
    if (!pk || !sk || !sig || !state) {
        printf("  FAIL: malloc\n");
        free(pk); free(sk); free(sig); free(state);
        return;
    }

    test_rng_reset(0xDEADBEEF42ULL);

    /* Keygen */
    ret = xmssmt_keygen(&p, pk, sk, state, 0, test_randombytes);
    TEST_INT("keygen", ret, XMSS_OK);
    if (ret != XMSS_OK) { goto done; }

    /* Sign */
    ret = xmssmt_sign(&p, sig, (const uint8_t *)msg, msglen, sk, state, 0);
    TEST_INT("sign", ret, XMSS_OK);
    if (ret != XMSS_OK) { goto done; }

    /* Verify valid signature */
    ret = xmssmt_verify(&p, (const uint8_t *)msg, msglen, sig, pk);
    TEST_INT("verify valid sig", ret, XMSS_OK);

    /* Bit-flip rejection */
    {
        uint8_t *bad_sig = (uint8_t *)malloc(p.sig_bytes);
        memcpy(bad_sig, sig, p.sig_bytes);
        bad_sig[p.sig_bytes / 2] ^= 0x01;
        ret = xmssmt_verify(&p, (const uint8_t *)msg, msglen, bad_sig, pk);
        TEST_INT("verify bit-flipped sig fails", ret, XMSS_ERR_VERIFY);
        free(bad_sig);
    }

    /* Wrong message rejection */
    {
        const char *bad_msg = "Hello, XMSS-MT?";
        ret = xmssmt_verify(&p, (const uint8_t *)bad_msg, msglen, sig, pk);
        TEST_INT("verify wrong message fails", ret, XMSS_ERR_VERIFY);
    }

    /* Index should be 1 after one signature */
    {
        uint64_t idx = 0;
        uint32_t i;
        for (i = 0; i < p.idx_bytes; i++) {
            idx = (idx << 8) | sk[4 + i];
        }
        TEST_INT("idx incremented to 1", (int)idx, 1);
    }

done:
    free(pk); free(sk); free(sig); free(state);
}

static void test_sequential(void)
{
    xmss_params p;
    xmssmt_state *state;
    uint8_t *pk, *sk, *sig;
    char label[128];
    int i, rc;
    int nsigs = 5;

    printf("\n--- sequential signing (%d sigs) ---\n", nsigs);

    xmssmt_params_from_oid(&p, TEST_OID);

    pk    = (uint8_t *)malloc(p.pk_bytes);
    sk    = (uint8_t *)malloc(p.sk_bytes);
    sig   = (uint8_t *)malloc(p.sig_bytes);
    state = (xmssmt_state *)malloc(sizeof(xmssmt_state));

    test_rng_reset(0x1111222233334444ULL);
    xmssmt_keygen(&p, pk, sk, state, 0, test_randombytes);

    for (i = 0; i < nsigs; i++) {
        uint8_t msg[4];
        msg[0] = (uint8_t)i;
        msg[1] = (uint8_t)(i + 1);
        msg[2] = (uint8_t)(i * 3);
        msg[3] = (uint8_t)(i ^ 0x55);

        rc = xmssmt_sign(&p, sig, msg, sizeof(msg), sk, state, 0);
        if (rc != XMSS_OK) {
            snprintf(label, sizeof(label), "sign idx=%d", i);
            TEST(label, 0);
            break;
        }

        rc = xmssmt_verify(&p, msg, sizeof(msg), sig, pk);
        snprintf(label, sizeof(label), "verify idx=%d", i);
        TEST(label, rc == XMSS_OK);
    }

    free(pk); free(sk); free(sig); free(state);
}

static void test_tree_boundary(void)
{
    xmss_params p;
    xmssmt_state *state;
    uint8_t *pk, *sk, *sig;
    int i, rc;
    char label[128];
    uint32_t boundary;

    printf("\n--- tree boundary crossing ---\n");

    xmssmt_params_from_oid(&p, TEST_OID);

    /* tree_height=10, so layer-0 tree boundary is at idx=1024 */
    boundary = (uint32_t)1 << p.tree_height;
    printf("  tree_height=%u, boundary at idx=%u\n", p.tree_height, boundary);

    pk    = (uint8_t *)malloc(p.pk_bytes);
    sk    = (uint8_t *)malloc(p.sk_bytes);
    sig   = (uint8_t *)malloc(p.sig_bytes);
    state = (xmssmt_state *)malloc(sizeof(xmssmt_state));

    test_rng_reset(0xAAAABBBBCCCCDDDDULL);
    xmssmt_keygen(&p, pk, sk, state, 0, test_randombytes);

    /* Sign up to the boundary and a few past it */
    for (i = 0; i < (int)(boundary + 3); i++) {
        uint8_t msg[4];
        msg[0] = (uint8_t)(i >> 0);
        msg[1] = (uint8_t)(i >> 8);
        msg[2] = (uint8_t)(i >> 16);
        msg[3] = (uint8_t)(i >> 24);

        rc = xmssmt_sign(&p, sig, msg, sizeof(msg), sk, state, 0);
        if (rc != XMSS_OK) {
            snprintf(label, sizeof(label), "sign idx=%d FAILED", i);
            TEST(label, 0);
            break;
        }

        /* Verify a few key signatures: first, last-before-boundary,
         * first-after-boundary, and a few more after */
        if (i == 0 || i == (int)(boundary - 1) || i == (int)boundary ||
            i == (int)(boundary + 1) || i == (int)(boundary + 2)) {
            rc = xmssmt_verify(&p, msg, sizeof(msg), sig, pk);
            snprintf(label, sizeof(label), "verify idx=%d", i);
            TEST(label, rc == XMSS_OK);
        }

        if (i % 200 == 0) {
            printf("  signed %d/%u...\n", i, boundary + 3);
        }
    }

    printf("  signed %u signatures total\n", boundary + 3);

    free(pk); free(sk); free(sig); free(state);
}

int main(void)
{
    printf("=== test_xmssmt ===\n");

    test_roundtrip();
    test_sequential();
    test_tree_boundary();

    return tests_done();
}
