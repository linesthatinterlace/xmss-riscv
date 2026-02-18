/**
 * test_hash.c - Tests for SHA-256, SHA-512, SHAKE, and XMSS hash functions
 *
 * Verifies correctness of our local SHA-2 and SHAKE implementations against
 * known test vectors (FIPS 180-4, NIST SHAKE test vectors).
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "test_utils.h"
#include "../src/hash/sha2_local.h"
#include "../src/hash/shake_local.h"

int main(void)
{
    uint8_t out[64];

    printf("=== test_hash ===\n");

    /* ----------------------------------------------------------------
     * SHA-256: FIPS 180-4 Test Vectors
     * ---------------------------------------------------------------- */

    /* SHA-256("") */
    {
        static const uint8_t expected[] = {
            0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14,
            0x9a,0xfb,0xf4,0xc8,0x99,0x6f,0xb9,0x24,
            0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c,
            0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55
        };
        sha256_local(out, (const uint8_t *)"", 0);
        TEST_BYTES("SHA-256 empty string", out, expected, 32);
    }

    /* SHA-256("abc") */
    {
        static const uint8_t expected[] = {
            0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,
            0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
            0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,
            0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad
        };
        sha256_local(out, (const uint8_t *)"abc", 3);
        TEST_BYTES("SHA-256 abc", out, expected, 32);
    }

    /* SHA-256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") */
    {
        static const uint8_t expected[] = {
            0x24,0x8d,0x6a,0x61,0xd2,0x06,0x38,0xb8,
            0xe5,0xc0,0x26,0x93,0x0c,0x3e,0x60,0x39,
            0xa3,0x3c,0xe4,0x59,0x64,0xff,0x21,0x67,
            0xf6,0xec,0xed,0xd4,0x19,0xdb,0x06,0xc1
        };
        const char *msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        sha256_local(out, (const uint8_t *)msg, strlen(msg));
        TEST_BYTES("SHA-256 448-bit msg", out, expected, 32);
    }

    /* ----------------------------------------------------------------
     * SHA-512: FIPS 180-4 Test Vectors
     * ---------------------------------------------------------------- */

    /* SHA-512("") */
    {
        static const uint8_t expected[] = {
            0xcf,0x83,0xe1,0x35,0x7e,0xef,0xb8,0xbd,
            0xf1,0x54,0x28,0x50,0xd6,0x6d,0x80,0x07,
            0xd6,0x20,0xe4,0x05,0x0b,0x57,0x15,0xdc,
            0x83,0xf4,0xa9,0x21,0xd3,0x6c,0xe9,0xce,
            0x47,0xd0,0xd1,0x3c,0x5d,0x85,0xf2,0xb0,
            0xff,0x83,0x18,0xd2,0x87,0x7e,0xec,0x2f,
            0x63,0xb9,0x31,0xbd,0x47,0x41,0x7a,0x81,
            0xa5,0x38,0x32,0x7a,0xf9,0x27,0xda,0x3e
        };
        sha512_local(out, (const uint8_t *)"", 0);
        TEST_BYTES("SHA-512 empty string", out, expected, 64);
    }

    /* SHA-512("abc") */
    {
        static const uint8_t expected[] = {
            0xdd,0xaf,0x35,0xa1,0x93,0x61,0x7a,0xba,
            0xcc,0x41,0x73,0x49,0xae,0x20,0x41,0x31,
            0x12,0xe6,0xfa,0x4e,0x89,0xa9,0x7e,0xa2,
            0x0a,0x9e,0xee,0xe6,0x4b,0x55,0xd3,0x9a,
            0x21,0x92,0x99,0x2a,0x27,0x4f,0xc1,0xa8,
            0x36,0xba,0x3c,0x23,0xa3,0xfe,0xeb,0xbd,
            0x45,0x4d,0x44,0x23,0x64,0x3c,0xe8,0x0e,
            0x2a,0x9a,0xc9,0x4f,0xa5,0x4c,0xa4,0x9f
        };
        sha512_local(out, (const uint8_t *)"abc", 3);
        TEST_BYTES("SHA-512 abc", out, expected, 64);
    }

    /* ----------------------------------------------------------------
     * SHAKE-128: NIST test vectors
     * ---------------------------------------------------------------- */

    /* SHAKE128("", 32 bytes output) - verified with Python hashlib */
    {
        static const uint8_t expected[] = {
            0x7f,0x9c,0x2b,0xa4,0xe8,0x8f,0x82,0x7d,
            0x61,0x60,0x45,0x50,0x76,0x05,0x85,0x3e,
            0xd7,0x3b,0x80,0x93,0xf6,0xef,0xbc,0x88,
            0xeb,0x1a,0x6e,0xac,0xfa,0x66,0xef,0x26
        };
        shake128_local(out, 32, (const uint8_t *)"", 0);
        TEST_BYTES("SHAKE128 empty 32 bytes", out, expected, 32);
    }

    /* SHAKE128("abc", 32 bytes) */
    {
        static const uint8_t expected[] = {
            0x58,0x81,0x09,0x2d,0xd8,0x18,0xbf,0x5c,
            0xf8,0xa3,0xdd,0xb7,0x93,0xfb,0xcb,0xa7,
            0x40,0x97,0xd5,0xc5,0x26,0xa6,0xd3,0x5f,
            0x97,0xb8,0x33,0x51,0x94,0x0f,0x2c,0xc8
        };
        shake128_local(out, 32, (const uint8_t *)"abc", 3);
        TEST_BYTES("SHAKE128 abc 32 bytes", out, expected, 32);
    }

    /* ----------------------------------------------------------------
     * SHAKE-256: NIST test vectors
     * ---------------------------------------------------------------- */

    /* SHAKE256("", 32 bytes) */
    {
        static const uint8_t expected[] = {
            0x46,0xb9,0xdd,0x2b,0x0b,0xa8,0x8d,0x13,
            0x23,0x3b,0x3f,0xeb,0x74,0x3e,0xeb,0x24,
            0x3f,0xcd,0x52,0xea,0x62,0xb8,0x1b,0x82,
            0xb5,0x0c,0x27,0x64,0x6e,0xd5,0x76,0x2f
        };
        shake256_local(out, 32, (const uint8_t *)"", 0);
        TEST_BYTES("SHAKE256 empty 32 bytes", out, expected, 32);
    }

    /* SHAKE256("abc", 32 bytes) — NIST CAVP */
    {
        static const uint8_t expected[] = {
            0x48,0x33,0x66,0x60,0x13,0x60,0xa8,0x77,
            0x1c,0x68,0x63,0x08,0x0c,0xc4,0x11,0x4d,
            0x8d,0xb4,0x45,0x30,0xf8,0xf1,0xe1,0xee,
            0x4f,0x94,0xea,0x37,0xe7,0x8b,0x57,0x39
        };
        shake256_local(out, 32, (const uint8_t *)"abc", 3);
        TEST_BYTES("SHAKE256 abc 32 bytes", out, expected, 32);
    }

    /* ----------------------------------------------------------------
     * SHAKE incremental API: same result as one-shot
     * ---------------------------------------------------------------- */
    {
        uint8_t oneshot[32];
        uint8_t incremental[32];
        const char *msg = "The quick brown fox";

        shake128_local(oneshot, 32, (const uint8_t *)msg, strlen(msg));

        shake128_ctx_t ctx;
        shake128_ctx_init(&ctx);
        shake128_ctx_absorb(&ctx, (const uint8_t *)msg, 10);
        shake128_ctx_absorb(&ctx, (const uint8_t *)msg + 10, strlen(msg) - 10);
        shake128_ctx_finalize(&ctx);
        shake128_ctx_squeeze(&ctx, incremental, 32);

        TEST_BYTES("SHAKE128 incremental == oneshot", oneshot, incremental, 32);
    }

    /* SHAKE256 incremental API: same result as one-shot */
    {
        uint8_t oneshot[32];
        uint8_t incremental[32];
        const char *msg = "The quick brown fox";

        shake256_local(oneshot, 32, (const uint8_t *)msg, strlen(msg));

        shake256_ctx_t ctx;
        shake256_ctx_init(&ctx);
        shake256_ctx_absorb(&ctx, (const uint8_t *)msg, 10);
        shake256_ctx_absorb(&ctx, (const uint8_t *)msg + 10, strlen(msg) - 10);
        shake256_ctx_finalize(&ctx);
        shake256_ctx_squeeze(&ctx, incremental, 32);

        TEST_BYTES("SHAKE256 incremental == oneshot", oneshot, incremental, 32);
    }

    /* ----------------------------------------------------------------
     * SHA-256 incremental API: same result as one-shot
     * ---------------------------------------------------------------- */
    {
        uint8_t oneshot[32];
        uint8_t incremental[32];
        const char *msg = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ01";

        sha256_local(oneshot, (const uint8_t *)msg, strlen(msg));

        sha256_ctx_t ctx;
        sha256_ctx_init(&ctx);
        sha256_ctx_update(&ctx, (const uint8_t *)msg, 32);
        sha256_ctx_update(&ctx, (const uint8_t *)msg + 32, strlen(msg) - 32);
        sha256_ctx_final(&ctx, incremental);

        TEST_BYTES("SHA-256 incremental == oneshot", oneshot, incremental, 32);
    }

    /* SHA-512 incremental API: same result as one-shot */
    {
        uint8_t oneshot[64];
        uint8_t incremental[64];
        const char *msg = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ01";

        sha512_local(oneshot, (const uint8_t *)msg, strlen(msg));

        sha512_ctx_t ctx;
        sha512_ctx_init(&ctx);
        sha512_ctx_update(&ctx, (const uint8_t *)msg, 32);
        sha512_ctx_update(&ctx, (const uint8_t *)msg + 32, strlen(msg) - 32);
        sha512_ctx_final(&ctx, incremental);

        TEST_BYTES("SHA-512 incremental == oneshot", oneshot, incremental, 64);
    }

    return tests_done();
}
