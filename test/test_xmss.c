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

/* Cross-key rejection: a valid sig must NOT verify under a different PK */
static void test_cross_key_rejection(uint32_t oid, const char *name)
{
    xmss_params p;
    xmss_bds_state *stateA, *stateB;
    uint8_t *pkA, *skA, *pkB, *skB, *sig;
    const char *msg = "cross-key test";
    size_t msglen = strlen(msg);
    int ret;
    char label[128];

    xmss_params_from_oid(&p, oid);

    pkA    = (uint8_t *)malloc(p.pk_bytes);
    skA    = (uint8_t *)malloc(p.sk_bytes);
    pkB    = (uint8_t *)malloc(p.pk_bytes);
    skB    = (uint8_t *)malloc(p.sk_bytes);
    sig    = (uint8_t *)malloc(p.sig_bytes);
    stateA = (xmss_bds_state *)malloc(sizeof(xmss_bds_state));
    stateB = (xmss_bds_state *)malloc(sizeof(xmss_bds_state));

    test_rng_reset(0xABCDEF01ULL);
    xmss_keygen(&p, pkA, skA, stateA, 0, test_randombytes);
    test_rng_reset(0x12345678ULL);
    xmss_keygen(&p, pkB, skB, stateB, 0, test_randombytes);

    xmss_sign(&p, sig, (const uint8_t *)msg, msglen, skA, stateA, 0);

    /* Sig made with key A must not verify under key B */
    ret = xmss_verify(&p, (const uint8_t *)msg, msglen, sig, pkB);
    snprintf(label, sizeof(label), "%s cross-key rejection", name);
    TEST_INT(label, ret, XMSS_ERR_VERIFY);

    free(pkA); free(skA); free(pkB); free(skB); free(sig);
    free(stateA); free(stateB);
}

/* Targeted bit-flips in idx, r, and auth regions of the signature */
static void test_targeted_bitflips(uint32_t oid, const char *name)
{
    xmss_params p;
    xmss_bds_state *state;
    uint8_t *pk, *sk, *sig, *bad_sig;
    const char *msg = "bitflip test";
    size_t msglen = strlen(msg);
    char label[128];

    xmss_params_from_oid(&p, oid);

    pk      = (uint8_t *)malloc(p.pk_bytes);
    sk      = (uint8_t *)malloc(p.sk_bytes);
    sig     = (uint8_t *)malloc(p.sig_bytes);
    bad_sig = (uint8_t *)malloc(p.sig_bytes);
    state   = (xmss_bds_state *)malloc(sizeof(xmss_bds_state));

    test_rng_reset(0xFEDCBA9876543210ULL);
    xmss_keygen(&p, pk, sk, state, 0, test_randombytes);
    xmss_sign(&p, sig, (const uint8_t *)msg, msglen, sk, state, 0);

    /* Flip a bit in the idx field (first byte of sig) */
    memcpy(bad_sig, sig, p.sig_bytes);
    bad_sig[0] ^= 0x01;
    snprintf(label, sizeof(label), "%s bit-flip in idx region fails", name);
    TEST_INT(label, xmss_verify(&p, (const uint8_t *)msg, msglen, bad_sig, pk),
             XMSS_ERR_VERIFY);

    /* Flip a bit in the r field (byte idx_bytes into sig) */
    memcpy(bad_sig, sig, p.sig_bytes);
    bad_sig[p.idx_bytes] ^= 0x80;
    snprintf(label, sizeof(label), "%s bit-flip in r region fails", name);
    TEST_INT(label, xmss_verify(&p, (const uint8_t *)msg, msglen, bad_sig, pk),
             XMSS_ERR_VERIFY);

    /* Flip a bit in the auth path (last n bytes of sig) */
    memcpy(bad_sig, sig, p.sig_bytes);
    bad_sig[p.sig_bytes - 1] ^= 0x01;
    snprintf(label, sizeof(label), "%s bit-flip in auth region fails", name);
    TEST_INT(label, xmss_verify(&p, (const uint8_t *)msg, msglen, bad_sig, pk),
             XMSS_ERR_VERIFY);

    free(pk); free(sk); free(sig); free(bad_sig); free(state);
}

/* Message boundary tests: empty message and block-boundary-length message */
static void test_message_boundaries(uint32_t oid, const char *name)
{
    xmss_params p;
    xmss_bds_state *state;
    uint8_t *pk, *sk, *sig;
    /* 64 bytes = one SHA-256 block, also a SHAKE rate multiple edge */
    uint8_t msg64[64];
    char label[128];
    int ret;
    size_t i;

    xmss_params_from_oid(&p, oid);

    pk    = (uint8_t *)malloc(p.pk_bytes);
    sk    = (uint8_t *)malloc(p.sk_bytes);
    sig   = (uint8_t *)malloc(p.sig_bytes);
    state = (xmss_bds_state *)malloc(sizeof(xmss_bds_state));

    test_rng_reset(0x0102030405060708ULL);
    xmss_keygen(&p, pk, sk, state, 0, test_randombytes);

    /* Empty message */
    ret = xmss_sign(&p, sig, (const uint8_t *)"", 0, sk, state, 0);
    snprintf(label, sizeof(label), "%s sign empty msg", name);
    TEST_INT(label, ret, XMSS_OK);
    ret = xmss_verify(&p, (const uint8_t *)"", 0, sig, pk);
    snprintf(label, sizeof(label), "%s verify empty msg", name);
    TEST_INT(label, ret, XMSS_OK);

    /* 64-byte message (SHA-256 block boundary) */
    for (i = 0; i < sizeof(msg64); i++) { msg64[i] = (uint8_t)(i + 1); }
    ret = xmss_sign(&p, sig, msg64, sizeof(msg64), sk, state, 0);
    snprintf(label, sizeof(label), "%s sign 64-byte msg", name);
    TEST_INT(label, ret, XMSS_OK);
    ret = xmss_verify(&p, msg64, sizeof(msg64), sig, pk);
    snprintf(label, sizeof(label), "%s verify 64-byte msg", name);
    TEST_INT(label, ret, XMSS_OK);

    free(pk); free(sk); free(sig); free(state);
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

    printf("\n--- cross-key rejection ---\n");
    test_cross_key_rejection(OID_XMSS_SHA2_10_256,  "XMSS-SHA2_10_256");
    test_cross_key_rejection(OID_XMSS_SHAKE_10_256, "XMSS-SHAKE_10_256");

    printf("\n--- targeted bit-flips ---\n");
    test_targeted_bitflips(OID_XMSS_SHA2_10_256,  "XMSS-SHA2_10_256");
    test_targeted_bitflips(OID_XMSS_SHAKE_10_256, "XMSS-SHAKE_10_256");

    printf("\n--- message boundary tests ---\n");
    test_message_boundaries(OID_XMSS_SHA2_10_256,  "XMSS-SHA2_10_256");
    test_message_boundaries(OID_XMSS_SHAKE_10_256, "XMSS-SHAKE_10_256");

    return tests_done();
}
