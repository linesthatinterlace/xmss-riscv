/**
 * test_address.c - Tests for ADRS byte serialisation and setters
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "test_utils.h"
#include "../include/xmss/types.h"
#include "../src/address.h"

int main(void)
{
    xmss_adrs_t a;
    uint8_t out[32];
    uint8_t expected[32];

    printf("=== test_address ===\n");

    /* Test: zero-initialised ADRS serialises to all zeros */
    memset(&a, 0, sizeof(a));
    memset(expected, 0, 32);
    xmss_adrs_to_bytes(&a, out);
    TEST_BYTES("zero ADRS", out, expected, 32);

    /* Test: set_layer */
    memset(&a, 0, sizeof(a));
    xmss_adrs_set_layer(&a, 0x01020304U);
    xmss_adrs_to_bytes(&a, out);
    TEST_INT("layer word[0] byte 0", out[0], 0x01);
    TEST_INT("layer word[0] byte 1", out[1], 0x02);
    TEST_INT("layer word[0] byte 2", out[2], 0x03);
    TEST_INT("layer word[0] byte 3", out[3], 0x04);

    /* Test: set_tree (64-bit, words 1 and 2) */
    memset(&a, 0, sizeof(a));
    xmss_adrs_set_tree(&a, 0x0102030405060708ULL);
    xmss_adrs_to_bytes(&a, out);
    /* word 1 = high 32 = 0x01020304 */
    TEST_INT("tree high byte 0", out[4], 0x01);
    TEST_INT("tree high byte 3", out[7], 0x04);
    /* word 2 = low 32 = 0x05060708 */
    TEST_INT("tree low byte 0", out[8], 0x05);
    TEST_INT("tree low byte 3", out[11], 0x08);

    /* Test: set_type zeros words 4-7 (RFC requirement) */
    memset(&a, 0, sizeof(a));
    a.w[4] = 0xDEADBEEFU;
    a.w[5] = 0xCAFEBABEU;
    a.w[6] = 0x12345678U;
    a.w[7] = 0xABCDEF01U;
    xmss_adrs_set_type(&a, XMSS_ADRS_TYPE_OTS);
    TEST_INT("set_type zeros w[4]", a.w[4], 0U);
    TEST_INT("set_type zeros w[5]", a.w[5], 0U);
    TEST_INT("set_type zeros w[6]", a.w[6], 0U);
    TEST_INT("set_type zeros w[7]", a.w[7], 0U);

    /* Test: OTS address set correctly (word 4) */
    memset(&a, 0, sizeof(a));
    xmss_adrs_set_type(&a, XMSS_ADRS_TYPE_OTS);
    xmss_adrs_set_ots(&a, 42);
    xmss_adrs_set_chain(&a, 3);
    xmss_adrs_set_hash(&a, 7);
    xmss_adrs_set_key_and_mask(&a, 1);
    xmss_adrs_to_bytes(&a, out);
    /* word 3 = type = 0 */
    TEST_INT("type=OTS word[3]=0", out[12], 0);
    TEST_INT("type=OTS word[3] low", out[15], 0);
    /* word 4 = OTS index = 42 */
    TEST_INT("ots index low byte", out[19], 42);
    /* word 5 = chain = 3 */
    TEST_INT("chain low byte", out[23], 3);
    /* word 6 = hash = 7 */
    TEST_INT("hash low byte", out[27], 7);
    /* word 7 = key_and_mask = 1 */
    TEST_INT("key_and_mask low byte", out[31], 1);

    /* Test: L-tree address */
    memset(&a, 0, sizeof(a));
    xmss_adrs_set_type(&a, XMSS_ADRS_TYPE_LTREE);
    xmss_adrs_set_ltree(&a, 100);
    xmss_adrs_set_tree_height(&a, 2);
    xmss_adrs_set_tree_index(&a, 5);
    xmss_adrs_to_bytes(&a, out);
    /* type = 1 */
    TEST_INT("ltree type byte", out[15], 1);
    TEST_INT("ltree index low byte", out[19], 100);
    TEST_INT("ltree height low byte", out[23], 2);
    TEST_INT("ltree tree_index low byte", out[27], 5);

    /* Test: hash tree address */
    memset(&a, 0, sizeof(a));
    xmss_adrs_set_type(&a, XMSS_ADRS_TYPE_HASH);
    xmss_adrs_set_tree_height(&a, 3);
    xmss_adrs_set_tree_index(&a, 12);
    xmss_adrs_to_bytes(&a, out);
    /* type = 2 */
    TEST_INT("hash type byte", out[15], 2);
    TEST_INT("hash tree_height low byte", out[23], 3);
    TEST_INT("hash tree_index low byte", out[27], 12);

    /* Test: max-value fields round-trip via serialisation.
     * XMSS_ADRS_TYPE_OTS = 0, so word 3 stays 0x00000000.
     * All other fields are set to 0xFFFFFFFF / 0xFFFFFFFFFFFFFFFF. */
    memset(&a, 0, sizeof(a));
    xmss_adrs_set_layer(&a, 0xFFFFFFFFU);
    xmss_adrs_set_tree(&a, 0xFFFFFFFFFFFFFFFFULL);
    xmss_adrs_set_type(&a, XMSS_ADRS_TYPE_OTS);
    xmss_adrs_set_ots(&a, 0xFFFFFFFFU);
    xmss_adrs_set_chain(&a, 0xFFFFFFFFU);
    xmss_adrs_set_hash(&a, 0xFFFFFFFFU);
    xmss_adrs_set_key_and_mask(&a, 0xFFFFFFFFU);
    xmss_adrs_to_bytes(&a, out);
    /* Bytes 0-3: layer = 0xFFFFFFFF */
    TEST_INT("max-value: layer all-0xFF", out[0] & out[1] & out[2] & out[3], 0xFF);
    /* Bytes 4-11: tree = 0xFFFFFFFFFFFFFFFF */
    {
        int tree_ff = 1;
        size_t i;
        for (i = 4; i < 12; i++) { if (out[i] != 0xFF) { tree_ff = 0; break; } }
        TEST("max-value: tree all-0xFF", tree_ff);
    }
    /* Bytes 12-15: type = OTS = 0x00000000 */
    TEST_INT("max-value: type word is OTS (0)", out[15], 0);
    /* Bytes 16-31: w[4..7] = 0xFFFFFFFF each */
    {
        int data_ff = 1;
        size_t i;
        for (i = 16; i < 32; i++) { if (out[i] != 0xFF) { data_ff = 0; break; } }
        TEST("max-value: OTS sub-fields all-0xFF", data_ff);
    }

    /* Test: repeated set_type() calls — each must zero words 4-7 */
    memset(&a, 0, sizeof(a));
    xmss_adrs_set_type(&a, XMSS_ADRS_TYPE_OTS);
    xmss_adrs_set_ots(&a, 99);
    xmss_adrs_set_chain(&a, 3);
    /* Call set_type again — must wipe the OTS fields set above */
    xmss_adrs_set_type(&a, XMSS_ADRS_TYPE_LTREE);
    TEST_INT("repeated set_type: w[4] zeroed", a.w[4], 0U);
    TEST_INT("repeated set_type: w[5] zeroed", a.w[5], 0U);
    TEST_INT("repeated set_type: w[6] zeroed", a.w[6], 0U);
    TEST_INT("repeated set_type: w[7] zeroed", a.w[7], 0U);
    /* Confirm new type is set correctly */
    xmss_adrs_to_bytes(&a, out);
    TEST_INT("repeated set_type: new type byte", out[15], 1); /* LTREE = 1 */

    return tests_done();
}
