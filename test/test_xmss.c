/**
 * test_xmss.c - Integration tests for XMSS keygen/sign/verify
 *
 * Tests:
 * - keygen → sign → verify roundtrip
 * - Verify with bit-flipped signature fails
 * - Verify with bit-flipped message fails
 * - Index increment in SK
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "test_utils.h"
#include "../include/xmss/xmss.h"
#include "../include/xmss/params.h"

/* Use a very small tree (h=10 is the smallest RFC set) */
static int test_one_set(uint32_t oid, const char *name)
{
    xmss_params p;
    uint8_t *pk, *sk, *sig;
    const char *msg = "Hello, XMSS!";
    size_t msglen = strlen(msg);
    int ret;

    printf("\n  Testing %s (OID=0x%08x):\n", name, oid);

    if (xmss_params_from_oid(&p, oid) != 0) {
        printf("  FAIL: cannot get params\n");
        return 1;
    }

    pk  = (uint8_t *)malloc(p.pk_bytes);
    sk  = (uint8_t *)malloc(p.sk_bytes);
    sig = (uint8_t *)malloc(p.sig_bytes);
    if (!pk || !sk || !sig) {
        printf("  FAIL: malloc failed\n");
        free(pk); free(sk); free(sig);
        return 1;
    }

    /* Use deterministic entropy */
    test_rng_reset(0x1234567890ABCDEFULL);

    /* Keygen */
    ret = xmss_keygen(&p, pk, sk, test_randombytes);
    {
        char tname[64];
        snprintf(tname, sizeof(tname), "%s keygen returns XMSS_OK", name);
        TEST_INT(tname, ret, XMSS_OK);
    }
    if (ret != XMSS_OK) { goto done; }

    /* Sign */
    ret = xmss_sign(&p, sig, (const uint8_t *)msg, msglen, sk);
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
        uint8_t bad_sig[9731 + 10]; /* max sig size */
        char tname[64];
        memcpy(bad_sig, sig, p.sig_bytes);
        bad_sig[p.sig_bytes / 2] ^= 0x01;  /* flip one bit in middle */
        ret = xmss_verify(&p, (const uint8_t *)msg, msglen, bad_sig, pk);
        snprintf(tname, sizeof(tname), "%s verify bit-flipped sig fails", name);
        TEST_INT(tname, ret, XMSS_ERR_VERIFY);
    }

    /* Verify with different message */
    {
        const char *bad_msg = "Hello, XMSS?";  /* differs in last char */
        char tname[64];
        ret = xmss_verify(&p, (const uint8_t *)bad_msg, msglen, sig, pk);
        snprintf(tname, sizeof(tname), "%s verify wrong message fails", name);
        TEST_INT(tname, ret, XMSS_ERR_VERIFY);
    }

    /* Index should now be 1 in SK */
    {
        uint64_t idx = 0;
        uint32_t i;
        uint32_t idx_off = 4;  /* after OID */
        for (i = 0; i < p.idx_bytes; i++) {
            idx = (idx << 8) | sk[idx_off + i];
        }
        char tname[64];
        snprintf(tname, sizeof(tname), "%s idx incremented to 1", name);
        TEST_INT(tname, (int)idx, 1);
    }

done:
    free(pk); free(sk); free(sig);
    return 0;
}

int main(void)
{
    printf("=== test_xmss ===\n");

    /* Test with SHA2_10_256 (smallest tree) */
    test_one_set(0x00000001, "XMSS-SHA2_10_256");

    /* Test with SHAKE_10_256 */
    test_one_set(0x00000007, "XMSS-SHAKE_10_256");

    /* Test with SHA2_10_512 */
    test_one_set(0x00000004, "XMSS-SHA2_10_512");

    return tests_done();
}
