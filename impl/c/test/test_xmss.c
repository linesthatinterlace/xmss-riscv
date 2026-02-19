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
    xmss_test_ctx t;
    const char *msg = "Hello, XMSS!";
    size_t msglen = strlen(msg);
    int ret;

    printf("\n  Testing %s (OID=0x%08x):\n", name, oid);

    if (xmss_test_ctx_init(&t, oid) != 0) {
        printf("  FAIL: init failed\n");
        return 1;
    }

    /* Use deterministic entropy */
    test_rng_reset(0x1234567890ABCDEFULL);

    /* Keygen */
    ret = xmss_keygen(&t.p, t.pk, t.sk, t.state, 0, test_randombytes);
    {
        char tname[64];
        snprintf(tname, sizeof(tname), "%s keygen returns XMSS_OK", name);
        TEST_INT(tname, ret, XMSS_OK);
    }
    if (ret != XMSS_OK) { goto done; }

    /* Sign */
    ret = xmss_sign(&t.p, t.sig, (const uint8_t *)msg, msglen, t.sk, t.state, 0);
    {
        char tname[64];
        snprintf(tname, sizeof(tname), "%s sign returns XMSS_OK", name);
        TEST_INT(tname, ret, XMSS_OK);
    }
    if (ret != XMSS_OK) { goto done; }

    /* Verify valid signature */
    ret = xmss_verify(&t.p, (const uint8_t *)msg, msglen, t.sig, t.pk);
    {
        char tname[64];
        snprintf(tname, sizeof(tname), "%s verify valid sig returns XMSS_OK", name);
        TEST_INT(tname, ret, XMSS_OK);
    }

    /* Verify with bit-flipped signature */
    {
        uint8_t *bad_sig = (uint8_t *)malloc(t.p.sig_bytes);
        char tname[64];
        memcpy(bad_sig, t.sig, t.p.sig_bytes);
        bad_sig[t.p.sig_bytes / 2] ^= 0x01;
        ret = xmss_verify(&t.p, (const uint8_t *)msg, msglen, bad_sig, t.pk);
        snprintf(tname, sizeof(tname), "%s verify bit-flipped sig fails", name);
        TEST_INT(tname, ret, XMSS_ERR_VERIFY);
        free(bad_sig);
    }

    /* Verify with corrupted PK OID */
    {
        uint8_t *bad_pk = (uint8_t *)malloc(t.p.pk_bytes);
        char tname[64];
        memcpy(bad_pk, t.pk, t.p.pk_bytes);
        bad_pk[0] ^= 0x01;
        ret = xmss_verify(&t.p, (const uint8_t *)msg, msglen, t.sig, bad_pk);
        snprintf(tname, sizeof(tname), "%s verify corrupted PK OID fails", name);
        TEST_INT(tname, ret, XMSS_ERR_VERIFY);
        free(bad_pk);
    }

    /* Verify with different message */
    {
        const char *bad_msg = "Hello, XMSS?";
        char tname[64];
        ret = xmss_verify(&t.p, (const uint8_t *)bad_msg, msglen, t.sig, t.pk);
        snprintf(tname, sizeof(tname), "%s verify wrong message fails", name);
        TEST_INT(tname, ret, XMSS_ERR_VERIFY);
    }

    /* Index should now be 1 in SK (keygen set 0, sign incremented to 1) */
    {
        uint64_t idx = 0;
        uint32_t i;
        uint32_t idx_off = 4;
        for (i = 0; i < t.p.idx_bytes; i++) {
            idx = (idx << 8) | t.sk[idx_off + i];
        }
        char tname[64];
        snprintf(tname, sizeof(tname), "%s idx incremented to 1", name);
        TEST_INT(tname, (int)idx, 1);
    }

done:
    xmss_test_ctx_free(&t);
    return 0;
}

/* Cross-key rejection: a valid sig must NOT verify under a different PK */
static void test_cross_key_rejection(uint32_t oid, const char *name)
{
    xmss_test_ctx a, b;
    const char *msg = "cross-key test";
    size_t msglen = strlen(msg);
    int ret;
    char label[128];

    xmss_test_ctx_init(&a, oid);
    xmss_test_ctx_init(&b, oid);

    test_rng_reset(0xABCDEF01ULL);
    ret = xmss_keygen(&a.p, a.pk, a.sk, a.state, 0, test_randombytes);
    snprintf(label, sizeof(label), "%s cross-key keygen_a", name);
    TEST_INT(label, ret, XMSS_OK);
    if (ret != XMSS_OK) { goto done; }

    test_rng_reset(0x12345678ULL);
    ret = xmss_keygen(&b.p, b.pk, b.sk, b.state, 0, test_randombytes);
    snprintf(label, sizeof(label), "%s cross-key keygen_b", name);
    TEST_INT(label, ret, XMSS_OK);
    if (ret != XMSS_OK) { goto done; }

    ret = xmss_sign(&a.p, a.sig, (const uint8_t *)msg, msglen, a.sk, a.state, 0);
    snprintf(label, sizeof(label), "%s cross-key sign", name);
    TEST_INT(label, ret, XMSS_OK);
    if (ret != XMSS_OK) { goto done; }

    /* Sig made with key A must not verify under key B */
    ret = xmss_verify(&a.p, (const uint8_t *)msg, msglen, a.sig, b.pk);
    snprintf(label, sizeof(label), "%s cross-key rejection", name);
    TEST_INT(label, ret, XMSS_ERR_VERIFY);

done:
    xmss_test_ctx_free(&a);
    xmss_test_ctx_free(&b);
}

/* Targeted bit-flips in idx, r, and auth regions of the signature */
static void test_targeted_bitflips(uint32_t oid, const char *name)
{
    xmss_test_ctx t;
    uint8_t *bad_sig = NULL;
    const char *msg = "bitflip test";
    size_t msglen = strlen(msg);
    char label[128];
    int ret;

    xmss_test_ctx_init(&t, oid);

    test_rng_reset(0xFEDCBA9876543210ULL);
    ret = xmss_keygen(&t.p, t.pk, t.sk, t.state, 0, test_randombytes);
    snprintf(label, sizeof(label), "%s keygen", name);
    TEST_INT(label, ret, XMSS_OK);
    if (ret != XMSS_OK) { goto done; }

    ret = xmss_sign(&t.p, t.sig, (const uint8_t *)msg, msglen, t.sk, t.state, 0);
    snprintf(label, sizeof(label), "%s sign", name);
    TEST_INT(label, ret, XMSS_OK);
    if (ret != XMSS_OK) { goto done; }

    bad_sig = (uint8_t *)malloc(t.p.sig_bytes);
    if (!bad_sig) { TEST("malloc", 0); goto done; }

    /* Flip a bit in the idx field (first byte of sig) */
    memcpy(bad_sig, t.sig, t.p.sig_bytes);
    bad_sig[0] ^= 0x01;
    snprintf(label, sizeof(label), "%s bit-flip in idx region fails", name);
    TEST_INT(label, xmss_verify(&t.p, (const uint8_t *)msg, msglen, bad_sig, t.pk),
             XMSS_ERR_VERIFY);

    /* Flip a bit in the r field (byte idx_bytes into sig) */
    memcpy(bad_sig, t.sig, t.p.sig_bytes);
    bad_sig[t.p.idx_bytes] ^= 0x80;
    snprintf(label, sizeof(label), "%s bit-flip in r region fails", name);
    TEST_INT(label, xmss_verify(&t.p, (const uint8_t *)msg, msglen, bad_sig, t.pk),
             XMSS_ERR_VERIFY);

    /* Flip a bit in the auth path (last n bytes of sig) */
    memcpy(bad_sig, t.sig, t.p.sig_bytes);
    bad_sig[t.p.sig_bytes - 1] ^= 0x01;
    snprintf(label, sizeof(label), "%s bit-flip in auth region fails", name);
    TEST_INT(label, xmss_verify(&t.p, (const uint8_t *)msg, msglen, bad_sig, t.pk),
             XMSS_ERR_VERIFY);

done:
    free(bad_sig);
    xmss_test_ctx_free(&t);
}

/* Message boundary tests: empty message and block-boundary-length message */
static void test_message_boundaries(uint32_t oid, const char *name)
{
    xmss_test_ctx t;
    /* 64 bytes = one SHA-256 block, also a SHAKE rate multiple edge */
    uint8_t msg64[64];
    char label[128];
    int ret;
    size_t i;

    xmss_test_ctx_init(&t, oid);

    test_rng_reset(0x0102030405060708ULL);
    ret = xmss_keygen(&t.p, t.pk, t.sk, t.state, 0, test_randombytes);
    snprintf(label, sizeof(label), "%s keygen", name);
    TEST_INT(label, ret, XMSS_OK);
    if (ret != XMSS_OK) { xmss_test_ctx_free(&t); return; }

    /* Empty message */
    ret = xmss_sign(&t.p, t.sig, (const uint8_t *)"", 0, t.sk, t.state, 0);
    snprintf(label, sizeof(label), "%s sign empty msg", name);
    TEST_INT(label, ret, XMSS_OK);
    ret = xmss_verify(&t.p, (const uint8_t *)"", 0, t.sig, t.pk);
    snprintf(label, sizeof(label), "%s verify empty msg", name);
    TEST_INT(label, ret, XMSS_OK);

    /* 64-byte message (SHA-256 block boundary) */
    for (i = 0; i < sizeof(msg64); i++) { msg64[i] = (uint8_t)(i + 1); }
    ret = xmss_sign(&t.p, t.sig, msg64, sizeof(msg64), t.sk, t.state, 0);
    snprintf(label, sizeof(label), "%s sign 64-byte msg", name);
    TEST_INT(label, ret, XMSS_OK);
    ret = xmss_verify(&t.p, msg64, sizeof(msg64), t.sig, t.pk);
    snprintf(label, sizeof(label), "%s verify 64-byte msg", name);
    TEST_INT(label, ret, XMSS_OK);

    xmss_test_ctx_free(&t);
}

/* Sequential signing: exercises bds_round across multiple tau values */
static void test_sequential(uint32_t oid, const char *name)
{
    xmss_test_ctx t;
    char label[128];
    int i, rc;

    xmss_test_ctx_init(&t, oid);

    test_rng_reset(99);
    rc = xmss_keygen(&t.p, t.pk, t.sk, t.state, 0, test_randombytes);
    snprintf(label, sizeof(label), "%s keygen", name);
    TEST_INT(label, rc, XMSS_OK);
    if (rc != XMSS_OK) { xmss_test_ctx_free(&t); return; }

    for (i = 0; i < 20; i++) {
        uint8_t msg[4];
        msg[0] = (uint8_t)i;
        msg[1] = (uint8_t)(i + 1);
        msg[2] = (uint8_t)(i * 3);
        msg[3] = (uint8_t)(i ^ 0x55);

        rc = xmss_sign(&t.p, t.sig, msg, sizeof(msg), t.sk, t.state, 0);
        if (rc != XMSS_OK) {
            snprintf(label, sizeof(label), "%s: seq sign idx=%d", name, i);
            TEST(label, 0);
            break;
        }

        rc = xmss_verify(&t.p, msg, sizeof(msg), t.sig, t.pk);
        snprintf(label, sizeof(label), "%s: seq verify idx=%d", name, i);
        TEST(label, rc == XMSS_OK);
    }

    xmss_test_ctx_free(&t);
}

/* Remaining-signatures query */
static void test_remaining_sigs(uint32_t oid, const char *name)
{
    xmss_test_ctx t;
    uint64_t rem;
    char label[128];
    uint32_t i;
    int rc;

    xmss_test_ctx_init(&t, oid);
    test_rng_reset(0xCAFEBABEULL);
    rc = xmss_keygen(&t.p, t.pk, t.sk, t.state, 0, test_randombytes);
    snprintf(label, sizeof(label), "%s: keygen", name);
    TEST_INT(label, rc, XMSS_OK);
    if (rc != XMSS_OK) { xmss_test_ctx_free(&t); return; }

    /* After keygen: remaining == 2^h */
    rem = xmss_remaining_sigs(&t.p, t.sk);
    snprintf(label, sizeof(label), "%s: remaining after keygen == 2^h", name);
    TEST_INT(label, (long long)rem, (long long)(t.p.idx_max + 1));

    /* After one signature: remaining == 2^h - 1 */
    rc = xmss_sign(&t.p, t.sig, (const uint8_t *)"x", 1, t.sk, t.state, 0);
    snprintf(label, sizeof(label), "%s: sign idx=0", name);
    TEST_INT(label, rc, XMSS_OK);
    if (rc != XMSS_OK) { xmss_test_ctx_free(&t); return; }
    rem = xmss_remaining_sigs(&t.p, t.sk);
    snprintf(label, sizeof(label), "%s: remaining after 1 sign == 2^h-1", name);
    TEST_INT(label, (long long)rem, (long long)(t.p.idx_max));

    /* Set idx to idx_max directly: remaining == 1 */
    for (i = 0; i < t.p.idx_bytes; i++) {
        t.sk[4 + i] = (uint8_t)(t.p.idx_max >> (8 * (t.p.idx_bytes - 1 - i)));
    }
    rem = xmss_remaining_sigs(&t.p, t.sk);
    snprintf(label, sizeof(label), "%s: remaining at idx_max == 1", name);
    TEST_INT(label, (long long)rem, 1LL);

    /* Set idx to idx_max + 1: key exhausted, remaining == 0 */
    for (i = 0; i < t.p.idx_bytes; i++) {
        uint64_t exhausted = t.p.idx_max + 1;
        t.sk[4 + i] = (uint8_t)(exhausted >> (8 * (t.p.idx_bytes - 1 - i)));
    }
    rem = xmss_remaining_sigs(&t.p, t.sk);
    snprintf(label, sizeof(label), "%s: remaining when exhausted == 0", name);
    TEST_INT(label, (long long)rem, 0LL);

    xmss_test_ctx_free(&t);
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

    printf("\n--- remaining signatures query ---\n");
    test_remaining_sigs(OID_XMSS_SHA2_10_256,  "XMSS-SHA2_10_256");
    test_remaining_sigs(OID_XMSS_SHAKE_10_256, "XMSS-SHAKE_10_256");

    return tests_done();
}
