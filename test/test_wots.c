/**
 * test_wots.c - Tests for WOTS+ (base_w, checksum, genPK, sign, pkFromSig)
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "test_utils.h"
#include "../include/xmss/params.h"
#include "../include/xmss/types.h"
#include "../src/wots.h"
#include "../src/address.h"

int main(void)
{
    xmss_params p;
    xmss_adrs_t adrs;

    printf("=== test_wots ===\n");

    /* Use XMSS-SHA2_10_256 for functional tests */
    if (xmss_params_from_oid(&p, 0x00000001U) != 0) {
        printf("FAIL: cannot get params\n");
        return 1;
    }

    /* ----------------------------------------------------------------
     * Test: wots_sign then wots_pk_from_sig should recover original pk
     * ---------------------------------------------------------------- */
    {
        uint8_t  sk_seed[32];
        uint8_t  seed[32];
        uint8_t  msg[32];
        uint8_t  pk_gen[131 * 64];    /* len*n, max size */
        uint8_t  pk_rec[131 * 64];
        uint8_t  sig[131 * 64];
        uint32_t i;

        /* Use deterministic test data */
        for (i = 0; i < 32; i++) {
            sk_seed[i] = (uint8_t)(0x11 + i);
            seed[i]    = (uint8_t)(0x22 + i);
            msg[i]     = (uint8_t)(0x33 + i);
        }

        memset(&adrs, 0, sizeof(adrs));
        xmss_adrs_set_type(&adrs, XMSS_ADRS_TYPE_OTS);
        xmss_adrs_set_ots(&adrs, 0);

        /* Generate public key */
        wots_gen_pk(&p, pk_gen, sk_seed, seed, &adrs);

        /* Sign message */
        memset(&adrs, 0, sizeof(adrs));
        xmss_adrs_set_type(&adrs, XMSS_ADRS_TYPE_OTS);
        xmss_adrs_set_ots(&adrs, 0);
        wots_sign(&p, sig, msg, sk_seed, seed, &adrs);

        /* Recover public key from signature */
        memset(&adrs, 0, sizeof(adrs));
        xmss_adrs_set_type(&adrs, XMSS_ADRS_TYPE_OTS);
        xmss_adrs_set_ots(&adrs, 0);
        wots_pk_from_sig(&p, pk_rec, sig, msg, seed, &adrs);

        TEST_BYTES("WOTS+ sign->pkFromSig roundtrip",
                   pk_gen, pk_rec, p.len * p.n);
    }

    /* ----------------------------------------------------------------
     * Test: Different messages produce different signatures
     * ---------------------------------------------------------------- */
    {
        uint8_t sk_seed[32];
        uint8_t seed[32];
        uint8_t msg1[32], msg2[32];
        uint8_t sig1[131 * 64], sig2[131 * 64];
        uint32_t i;

        for (i = 0; i < 32; i++) {
            sk_seed[i] = (uint8_t)(0xAA + i);
            seed[i]    = (uint8_t)(0xBB + i);
            msg1[i]    = (uint8_t)(0x01);
            msg2[i]    = (uint8_t)(0x02);
        }

        memset(&adrs, 0, sizeof(adrs));
        xmss_adrs_set_type(&adrs, XMSS_ADRS_TYPE_OTS);
        xmss_adrs_set_ots(&adrs, 5);

        wots_sign(&p, sig1, msg1, sk_seed, seed, &adrs);

        memset(&adrs, 0, sizeof(adrs));
        xmss_adrs_set_type(&adrs, XMSS_ADRS_TYPE_OTS);
        xmss_adrs_set_ots(&adrs, 5);

        wots_sign(&p, sig2, msg2, sk_seed, seed, &adrs);

        TEST("Different messages -> different signatures",
             memcmp(sig1, sig2, p.len * p.n) != 0);
    }

    /* ----------------------------------------------------------------
     * Test: pkFromSig with wrong message fails to recover pk
     * ---------------------------------------------------------------- */
    {
        uint8_t sk_seed[32];
        uint8_t seed[32];
        uint8_t msg[32];
        uint8_t wrong_msg[32];
        uint8_t pk_gen[131 * 64];
        uint8_t pk_rec[131 * 64];
        uint8_t sig[131 * 64];
        uint32_t i;

        for (i = 0; i < 32; i++) {
            sk_seed[i]    = (uint8_t)(0xCC);
            seed[i]       = (uint8_t)(0xDD);
            msg[i]        = (uint8_t)(0x55);
            wrong_msg[i]  = (uint8_t)(0x66);
        }

        memset(&adrs, 0, sizeof(adrs));
        xmss_adrs_set_type(&adrs, XMSS_ADRS_TYPE_OTS);
        xmss_adrs_set_ots(&adrs, 3);
        wots_gen_pk(&p, pk_gen, sk_seed, seed, &adrs);

        memset(&adrs, 0, sizeof(adrs));
        xmss_adrs_set_type(&adrs, XMSS_ADRS_TYPE_OTS);
        xmss_adrs_set_ots(&adrs, 3);
        wots_sign(&p, sig, msg, sk_seed, seed, &adrs);

        memset(&adrs, 0, sizeof(adrs));
        xmss_adrs_set_type(&adrs, XMSS_ADRS_TYPE_OTS);
        xmss_adrs_set_ots(&adrs, 3);
        wots_pk_from_sig(&p, pk_rec, sig, wrong_msg, seed, &adrs);

        TEST("Wrong message -> pk mismatch",
             memcmp(pk_gen, pk_rec, p.len * p.n) != 0);
    }

    /* ----------------------------------------------------------------
     * Test with SHA-2_10_512 (n=64)
     * ---------------------------------------------------------------- */
    {
        xmss_params p512;
        uint8_t sk_seed[64];
        uint8_t seed[64];
        uint8_t msg[64];
        uint8_t pk_gen[131 * 64];
        uint8_t pk_rec[131 * 64];
        uint8_t sig[131 * 64];
        uint32_t i;

        if (xmss_params_from_oid(&p512, 0x00000004U) != 0) {
            printf("FAIL: cannot get SHA2_10_512 params\n");
            return 1;
        }

        for (i = 0; i < 64; i++) {
            sk_seed[i] = (uint8_t)(0x11 + i);
            seed[i]    = (uint8_t)(0x22 + i);
            msg[i]     = (uint8_t)(0x33 + i);
        }

        memset(&adrs, 0, sizeof(adrs));
        xmss_adrs_set_type(&adrs, XMSS_ADRS_TYPE_OTS);
        xmss_adrs_set_ots(&adrs, 0);
        wots_gen_pk(&p512, pk_gen, sk_seed, seed, &adrs);

        memset(&adrs, 0, sizeof(adrs));
        xmss_adrs_set_type(&adrs, XMSS_ADRS_TYPE_OTS);
        xmss_adrs_set_ots(&adrs, 0);
        wots_sign(&p512, sig, msg, sk_seed, seed, &adrs);

        memset(&adrs, 0, sizeof(adrs));
        xmss_adrs_set_type(&adrs, XMSS_ADRS_TYPE_OTS);
        xmss_adrs_set_ots(&adrs, 0);
        wots_pk_from_sig(&p512, pk_rec, sig, msg, seed, &adrs);

        TEST_BYTES("WOTS+ n=64 sign->pkFromSig roundtrip",
                   pk_gen, pk_rec, p512.len * p512.n);
    }

    return tests_done();
}
