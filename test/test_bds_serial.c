/**
 * test_bds_serial.c - BDS state serialization round-trip tests
 *
 * Tests:
 *   1. Round-trip after keygen (serialize -> deserialize -> sign -> verify)
 *   2. Round-trip mid-signing (sign 5 -> serialize -> deserialize -> sign -> verify)
 *   3. Byte-exact round-trip (serialize -> deserialize -> re-serialize == original)
 *   4. Size consistency (serialized_size matches actual bytes written)
 *   5. Multiple parameter sets (SHA2_10_256, SHA2_10_512)
 *   6. Non-zero bds_k (bds_k=2)
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "test_utils.h"
#include "../include/xmss/params.h"
#include "../include/xmss/xmss.h"

/* ------------------------------------------------------------------ */
/* Round-trip after keygen                                             */
/* ------------------------------------------------------------------ */
static void test_roundtrip_after_keygen(uint32_t oid, const char *name,
                                        uint32_t bds_k)
{
    xmss_params p;
    xmss_bds_state *state, *state2;
    uint8_t *pk, *sk, *sig, *buf;
    uint8_t msg[] = { 0xDE, 0xAD, 0xBE, 0xEF };
    uint32_t sz;
    char label[128];
    int rc;

    xmss_params_from_oid(&p, oid);
    sz = xmss_bds_serialized_size(&p, bds_k);

    pk     = (uint8_t *)malloc(p.pk_bytes);
    sk     = (uint8_t *)malloc(p.sk_bytes);
    sig    = (uint8_t *)malloc(p.sig_bytes);
    state  = (xmss_bds_state *)malloc(sizeof(xmss_bds_state));
    state2 = (xmss_bds_state *)malloc(sizeof(xmss_bds_state));
    buf    = (uint8_t *)malloc(sz);

    test_rng_reset(100);
    rc = xmss_keygen(&p, pk, sk, state, bds_k, test_randombytes);
    snprintf(label, sizeof(label), "%s (k=%u): keygen", name, bds_k);
    TEST(label, rc == XMSS_OK);

    /* Serialize and deserialize */
    rc = xmss_bds_serialize(&p, buf, state, bds_k);
    snprintf(label, sizeof(label), "%s (k=%u): serialize", name, bds_k);
    TEST(label, rc == XMSS_OK);

    rc = xmss_bds_deserialize(&p, state2, buf, bds_k);
    snprintf(label, sizeof(label), "%s (k=%u): deserialize", name, bds_k);
    TEST(label, rc == XMSS_OK);

    /* Sign with deserialized state and verify */
    rc = xmss_sign(&p, sig, msg, sizeof(msg), sk, state2, bds_k);
    snprintf(label, sizeof(label), "%s (k=%u): sign after deser", name, bds_k);
    TEST(label, rc == XMSS_OK);

    rc = xmss_verify(&p, msg, sizeof(msg), sig, pk);
    snprintf(label, sizeof(label), "%s (k=%u): verify after deser", name, bds_k);
    TEST(label, rc == XMSS_OK);

    free(pk); free(sk); free(sig); free(state); free(state2); free(buf);
}

/* ------------------------------------------------------------------ */
/* Round-trip mid-signing                                              */
/* ------------------------------------------------------------------ */
static void test_roundtrip_mid_signing(uint32_t oid, const char *name,
                                       uint32_t bds_k)
{
    xmss_params p;
    xmss_bds_state *state, *state2;
    uint8_t *pk, *sk, *sig, *buf;
    uint32_t sz;
    char label[128];
    int i, rc;

    xmss_params_from_oid(&p, oid);
    sz = xmss_bds_serialized_size(&p, bds_k);

    pk     = (uint8_t *)malloc(p.pk_bytes);
    sk     = (uint8_t *)malloc(p.sk_bytes);
    sig    = (uint8_t *)malloc(p.sig_bytes);
    state  = (xmss_bds_state *)malloc(sizeof(xmss_bds_state));
    state2 = (xmss_bds_state *)malloc(sizeof(xmss_bds_state));
    buf    = (uint8_t *)malloc(sz);

    test_rng_reset(200);
    xmss_keygen(&p, pk, sk, state, bds_k, test_randombytes);

    /* Sign 5 messages */
    for (i = 0; i < 5; i++) {
        uint8_t msg[2] = { (uint8_t)i, (uint8_t)(i ^ 0xAA) };
        rc = xmss_sign(&p, sig, msg, sizeof(msg), sk, state, bds_k);
        snprintf(label, sizeof(label), "%s (k=%u): pre-sign idx=%d",
                 name, bds_k, i);
        TEST(label, rc == XMSS_OK);
    }

    /* Serialize and deserialize */
    xmss_bds_serialize(&p, buf, state, bds_k);
    xmss_bds_deserialize(&p, state2, buf, bds_k);

    /* Sign one more with deserialized state and verify */
    {
        uint8_t msg[] = { 0xCA, 0xFE };
        rc = xmss_sign(&p, sig, msg, sizeof(msg), sk, state2, bds_k);
        snprintf(label, sizeof(label), "%s (k=%u): sign after 5+deser",
                 name, bds_k);
        TEST(label, rc == XMSS_OK);

        rc = xmss_verify(&p, msg, sizeof(msg), sig, pk);
        snprintf(label, sizeof(label), "%s (k=%u): verify after 5+deser",
                 name, bds_k);
        TEST(label, rc == XMSS_OK);
    }

    free(pk); free(sk); free(sig); free(state); free(state2); free(buf);
}

/* ------------------------------------------------------------------ */
/* Byte-exact round-trip                                               */
/* ------------------------------------------------------------------ */
static void test_byte_exact(uint32_t oid, const char *name, uint32_t bds_k)
{
    xmss_params p;
    xmss_bds_state *state, *state2;
    uint8_t *pk, *sk, *buf1, *buf2;
    uint32_t sz;
    char label[128];

    xmss_params_from_oid(&p, oid);
    sz = xmss_bds_serialized_size(&p, bds_k);

    pk     = (uint8_t *)malloc(p.pk_bytes);
    sk     = (uint8_t *)malloc(p.sk_bytes);
    state  = (xmss_bds_state *)malloc(sizeof(xmss_bds_state));
    state2 = (xmss_bds_state *)malloc(sizeof(xmss_bds_state));
    buf1   = (uint8_t *)malloc(sz);
    buf2   = (uint8_t *)malloc(sz);

    test_rng_reset(300);
    xmss_keygen(&p, pk, sk, state, bds_k, test_randombytes);

    /* Sign a few to get non-trivial state */
    {
        uint8_t *sig_buf = (uint8_t *)malloc(p.sig_bytes);
        uint8_t msg[] = { 0x01 };
        int i;
        for (i = 0; i < 3; i++) {
            msg[0] = (uint8_t)i;
            xmss_sign(&p, sig_buf, msg, sizeof(msg), sk, state, bds_k);
        }
        free(sig_buf);
    }

    xmss_bds_serialize(&p, buf1, state, bds_k);
    xmss_bds_deserialize(&p, state2, buf1, bds_k);
    xmss_bds_serialize(&p, buf2, state2, bds_k);

    snprintf(label, sizeof(label), "%s (k=%u): byte-exact round-trip",
             name, bds_k);
    TEST(label, memcmp(buf1, buf2, sz) == 0);

    free(pk); free(sk); free(state); free(state2); free(buf1); free(buf2);
}

/* ------------------------------------------------------------------ */
/* Size consistency                                                    */
/* ------------------------------------------------------------------ */
static void test_size_consistency(void)
{
    xmss_params p;
    uint32_t sz;

    /* SHA2_10_256: n=32, h=10, bds_k=0 */
    xmss_params_from_oid(&p, OID_XMSS_SHA2_10_256);
    sz = xmss_bds_serialized_size(&p, 0);
    /* auth=10*32 + keep=5*32 + stack=11*32 + levels=11 + off=4
     * + treehash=10*(32+4+4+1+1) + retain=0 + next_leaf=4 = 1299 */
    TEST("size SHA2_10_256 k=0",
         sz == 10*32 + 5*32 + 11*32 + 11 + 4 + 10*(32+4+4+1+1) + 0 + 4);

    /* SHA2_10_256, bds_k=2: retain_count = 2^2 - 2 - 1 = 1 */
    sz = xmss_bds_serialized_size(&p, 2);
    TEST("size SHA2_10_256 k=2",
         sz == 10*32 + 5*32 + 11*32 + 11 + 4 + 8*(32+4+4+1+1) + 1*32 + 4);

    /* SHA2_10_512: n=64, h=10, bds_k=0 */
    xmss_params_from_oid(&p, OID_XMSS_SHA2_10_512);
    sz = xmss_bds_serialized_size(&p, 0);
    TEST("size SHA2_10_512 k=0",
         sz == 10*64 + 5*64 + 11*64 + 11 + 4 + 10*(64+4+4+1+1) + 0 + 4);
}

int main(void)
{
    printf("=== test_bds_serial (BDS serialization) ===\n");

    printf("--- size consistency ---\n");
    test_size_consistency();

    printf("--- round-trip after keygen (SHA2_10_256, k=0) ---\n");
    test_roundtrip_after_keygen(OID_XMSS_SHA2_10_256, "SHA2_10_256", 0);

    printf("--- round-trip after keygen (SHAKE_10_256, k=0) ---\n");
    test_roundtrip_after_keygen(OID_XMSS_SHAKE_10_256, "SHAKE_10_256", 0);

    printf("--- round-trip after keygen (SHA2_10_256, k=2) ---\n");
    test_roundtrip_after_keygen(OID_XMSS_SHA2_10_256, "SHA2_10_256", 2);

    printf("--- round-trip mid-signing (SHA2_10_256, k=0) ---\n");
    test_roundtrip_mid_signing(OID_XMSS_SHA2_10_256, "SHA2_10_256", 0);

    printf("--- round-trip mid-signing (SHA2_10_256, k=2) ---\n");
    test_roundtrip_mid_signing(OID_XMSS_SHA2_10_256, "SHA2_10_256", 2);

    printf("--- round-trip after keygen (SHA2_10_256, k=4) ---\n");
    test_roundtrip_after_keygen(OID_XMSS_SHA2_10_256, "SHA2_10_256", 4);

    printf("--- round-trip mid-signing (SHA2_10_256, k=4) ---\n");
    test_roundtrip_mid_signing(OID_XMSS_SHA2_10_256, "SHA2_10_256", 4);

    printf("--- byte-exact (SHA2_10_256, k=0) ---\n");
    test_byte_exact(OID_XMSS_SHA2_10_256, "SHA2_10_256", 0);

    printf("--- byte-exact (SHA2_10_256, k=2) ---\n");
    test_byte_exact(OID_XMSS_SHA2_10_256, "SHA2_10_256", 2);

    printf("--- byte-exact (SHA2_10_256, k=4) ---\n");
    test_byte_exact(OID_XMSS_SHA2_10_256, "SHA2_10_256", 4);

    return tests_done();
}
