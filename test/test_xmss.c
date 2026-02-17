/**
 * test_xmss.c - Integration tests for XMSS keygen/sign/verify
 *
 * Uses BDS-accelerated keygen/sign for practical performance.
 *
 * Tests:
 * - keygen → sign → verify roundtrip (3 parameter sets)
 * - Verify with bit-flipped signature fails
 * - Verify with wrong message fails
 * - Index increment in SK
 * - Sequential signing: 20 signatures all verify
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "test_utils.h"
#include "../include/xmss/xmss.h"
#include "../include/xmss/params.h"

static int test_one_set(uint32_t oid, const char *name)
{
    xmss_params p;
    xmss_bds_state *state;
    uint8_t *pk, *sk, *sig;
    const char *msg = "Hello, XMSS!";
    size_t msglen = strlen(msg);
    int ret;

    printf("\n  Testing %s (OID=0x%08x):\n", name, oid);

    if (xmss_params_from_oid(&p, oid) != 0) {
        printf("  FAIL: cannot get params\n");
        return 1;
    }

    pk    = (uint8_t *)malloc(p.pk_bytes);
    sk    = (uint8_t *)malloc(p.sk_bytes);
    sig   = (uint8_t *)malloc(p.sig_bytes);
    state = (xmss_bds_state *)malloc(sizeof(xmss_bds_state));
    if (!pk || !sk || !sig || !state) {
        printf("  FAIL: malloc failed\n");
        free(pk); free(sk); free(sig); free(state);
        return 1;
    }

    /* Use deterministic entropy */
    test_rng_reset(0x1234567890ABCDEFULL);

    /* Keygen */
    ret = xmss_keygen(&p, pk, sk, state, 0, test_randombytes);
    {
        char tname[64];
        snprintf(tname, sizeof(tname), "%s keygen returns XMSS_OK", name);
        TEST_INT(tname, ret, XMSS_OK);
    }
    if (ret != XMSS_OK) { goto done; }

    /* Sign */
    ret = xmss_sign(&p, sig, (const uint8_t *)msg, msglen, sk, state, 0);
    {
        char tname[64];
        snprintf(tname, sizeof(tname), "%s sign returns XMSS_OK", name);
        TEST_INT(tname, ret, XMSS_OK);
    }
    if (ret != XMSS_OK) { goto done; }

    /* Verify valid signature */
    ret = xmss_verify(&p, (const uint8_t *)msg, msglen, sig, pk);
    {
        char tname[64];
        snprintf(tname, sizeof(tname), "%s verify valid sig returns XMSS_OK", name);
        TEST_INT(tname, ret, XMSS_OK);
    }

    /* Verify with bit-flipped signature */
    {
        uint8_t *bad_sig = (uint8_t *)malloc(p.sig_bytes);
        char tname[64];
        memcpy(bad_sig, sig, p.sig_bytes);
        bad_sig[p.sig_bytes / 2] ^= 0x01;
        ret = xmss_verify(&p, (const uint8_t *)msg, msglen, bad_sig, pk);
        snprintf(tname, sizeof(tname), "%s verify bit-flipped sig fails", name);
        TEST_INT(tname, ret, XMSS_ERR_VERIFY);
        free(bad_sig);
    }

    /* Verify with different message */
    {
        const char *bad_msg = "Hello, XMSS?";
        char tname[64];
        ret = xmss_verify(&p, (const uint8_t *)bad_msg, msglen, sig, pk);
        snprintf(tname, sizeof(tname), "%s verify wrong message fails", name);
        TEST_INT(tname, ret, XMSS_ERR_VERIFY);
    }

    /* Index should now be 1 in SK (keygen set 0, sign incremented to 1) */
    {
        uint64_t idx = 0;
        uint32_t i;
        uint32_t idx_off = 4;
        for (i = 0; i < p.idx_bytes; i++) {
            idx = (idx << 8) | sk[idx_off + i];
        }
        char tname[64];
        snprintf(tname, sizeof(tname), "%s idx incremented to 1", name);
        TEST_INT(tname, (int)idx, 1);
    }

done:
    free(pk); free(sk); free(sig); free(state);
    return 0;
}

/* Sequential signing: exercises bds_round across multiple tau values */
static void test_sequential(uint32_t oid, const char *name)
{
    xmss_params p;
    xmss_bds_state *state;
    uint8_t *pk, *sk, *sig;
    char label[128];
    int i, rc;

    xmss_params_from_oid(&p, oid);

    pk    = (uint8_t *)malloc(p.pk_bytes);
    sk    = (uint8_t *)malloc(p.sk_bytes);
    sig   = (uint8_t *)malloc(p.sig_bytes);
    state = (xmss_bds_state *)malloc(sizeof(xmss_bds_state));

    test_rng_reset(99);
    xmss_keygen(&p, pk, sk, state, 0, test_randombytes);

    for (i = 0; i < 20; i++) {
        uint8_t msg[4];
        msg[0] = (uint8_t)i;
        msg[1] = (uint8_t)(i + 1);
        msg[2] = (uint8_t)(i * 3);
        msg[3] = (uint8_t)(i ^ 0x55);

        rc = xmss_sign(&p, sig, msg, sizeof(msg), sk, state, 0);
        if (rc != XMSS_OK) {
            snprintf(label, sizeof(label), "%s: seq sign idx=%d", name, i);
            TEST(label, 0);
            break;
        }

        rc = xmss_verify(&p, msg, sizeof(msg), sig, pk);
        snprintf(label, sizeof(label), "%s: seq verify idx=%d", name, i);
        TEST(label, rc == XMSS_OK);
    }

    free(pk); free(sk); free(sig); free(state);
}

int main(void)
{
    printf("=== test_xmss ===\n");

    test_one_set(OID_XMSS_SHA2_10_256,  "XMSS-SHA2_10_256");
    test_one_set(OID_XMSS_SHAKE_10_256, "XMSS-SHAKE_10_256");
    test_one_set(OID_XMSS_SHA2_10_512,  "XMSS-SHA2_10_512");

    printf("\n--- sequential signing ---\n");
    test_sequential(OID_XMSS_SHA2_10_256, "XMSS-SHA2_10_256");

    return tests_done();
}
