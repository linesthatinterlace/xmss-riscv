/**
 * sha2_local.c - Stack-based SHA-256 and SHA-512
 *
 * Implements SHA-256 (FIPS 180-4) and SHA-512 with no heap allocation.
 * Algorithm follows FIPS 180-4 exactly.
 *
 * References:
 *   FIPS 180-4, "Secure Hash Standard (SHS)", August 2015.
 *   Public domain implementation; no copyright claimed.
 */
#include <string.h>
#include <stdint.h>
#include "sha2_local.h"

/* ====================================================================
 * Common helpers
 * ==================================================================== */

#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define ROR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

static uint32_t be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] << 8)  |  (uint32_t)p[3];
}

static void store_be32(uint8_t *p, uint32_t x)
{
    p[0] = (uint8_t)(x >> 24); p[1] = (uint8_t)(x >> 16);
    p[2] = (uint8_t)(x >>  8); p[3] = (uint8_t)(x      );
}

static uint64_t be64(const uint8_t *p)
{
    return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48)
         | ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32)
         | ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16)
         | ((uint64_t)p[6] <<  8) |  (uint64_t)p[7];
}

static void store_be64(uint8_t *p, uint64_t x)
{
    p[0] = (uint8_t)(x >> 56); p[1] = (uint8_t)(x >> 48);
    p[2] = (uint8_t)(x >> 40); p[3] = (uint8_t)(x >> 32);
    p[4] = (uint8_t)(x >> 24); p[5] = (uint8_t)(x >> 16);
    p[6] = (uint8_t)(x >>  8); p[7] = (uint8_t)(x      );
}

/* ====================================================================
 * SHA-256
 * ==================================================================== */

static const uint32_t K256[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

static const uint32_t SHA256_IV[8] = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
};

static void sha256_transform(uint32_t state[8], const uint8_t block[64])
{
    uint32_t W[64];
    uint32_t a, b, c, d, e, f, g, h, T1, T2;
    uint32_t i;

    for (i = 0; i < 16; i++) {
        W[i] = be32(block + 4*i);
    }
    for (i = 16; i < 64; i++) {
        uint32_t s0 = ROR32(W[i-15], 7) ^ ROR32(W[i-15], 18) ^ (W[i-15] >> 3);
        uint32_t s1 = ROR32(W[i-2], 17) ^ ROR32(W[i-2], 19)  ^ (W[i-2]  >> 10);
        W[i] = W[i-16] + s0 + W[i-7] + s1;
    }

    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];

    for (i = 0; i < 64; i++) {
        uint32_t S1 = ROR32(e, 6) ^ ROR32(e, 11) ^ ROR32(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        T1 = h + S1 + ch + K256[i] + W[i];
        uint32_t S0 = ROR32(a, 2) ^ ROR32(a, 13) ^ ROR32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        T2 = S0 + maj;

        h = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

void sha256_ctx_init(sha256_ctx_t *ctx)
{
    ctx->state[0] = SHA256_IV[0]; ctx->state[1] = SHA256_IV[1];
    ctx->state[2] = SHA256_IV[2]; ctx->state[3] = SHA256_IV[3];
    ctx->state[4] = SHA256_IV[4]; ctx->state[5] = SHA256_IV[5];
    ctx->state[6] = SHA256_IV[6]; ctx->state[7] = SHA256_IV[7];
    ctx->count  = 0;
    ctx->buflen = 0;
}

void sha256_ctx_update(sha256_ctx_t *ctx, const uint8_t *in, size_t inlen)
{
    size_t rem;

    ctx->count += (uint64_t)inlen * 8;

    if (ctx->buflen > 0) {
        rem = 64 - ctx->buflen;
        if (inlen < rem) {
            memcpy(ctx->buf + ctx->buflen, in, inlen);
            ctx->buflen += (uint32_t)inlen;
            return;
        }
        memcpy(ctx->buf + ctx->buflen, in, rem);
        sha256_transform(ctx->state, ctx->buf);
        in    += rem;
        inlen -= rem;
        ctx->buflen = 0;
    }

    while (inlen >= 64) {
        sha256_transform(ctx->state, in);
        in    += 64;
        inlen -= 64;
    }

    if (inlen > 0) {
        memcpy(ctx->buf, in, inlen);
        ctx->buflen = (uint32_t)inlen;
    }
}

void sha256_ctx_final(sha256_ctx_t *ctx, uint8_t out[32])
{
    uint8_t pad[64];
    uint32_t i;
    uint64_t bit_count = ctx->count;

    /* Padding: 0x80 then zeros then 8-byte big-endian bit count */
    memset(pad, 0, sizeof(pad));
    pad[0] = 0x80;

    /* Total message length must be ≡ 448 (mod 512) bits.
     * buflen is the number of unprocessed bytes. */
    if (ctx->buflen < 56) {
        /* Fits in one more block */
        sha256_ctx_update(ctx, pad, 56 - ctx->buflen);
    } else {
        /* Need an extra block */
        sha256_ctx_update(ctx, pad, 64 - ctx->buflen);
        sha256_ctx_update(ctx, pad + 1, 56); /* 56 zeros */
    }

    /* Append bit count as 8 bytes big-endian */
    for (i = 0; i < 8; i++) {
        pad[i] = (uint8_t)(bit_count >> (56 - 8*i));
    }
    sha256_ctx_update(ctx, pad, 8);

    for (i = 0; i < 8; i++) {
        store_be32(out + 4*i, ctx->state[i]);
    }
}

void sha256_local(uint8_t out[32], const uint8_t *in, size_t inlen)
{
    sha256_ctx_t ctx;
    sha256_ctx_init(&ctx);
    sha256_ctx_update(&ctx, in, inlen);
    sha256_ctx_final(&ctx, out);
}

/* ====================================================================
 * SHA-512
 * ==================================================================== */

static const uint64_t K512[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL,
    0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
    0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL,
    0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL,
    0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
    0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL,
    0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL,
    0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
    0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL,
    0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL,
    0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
    0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL,
    0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL,
    0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
    0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL,
    0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL,
    0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
    0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL,
    0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL,
    0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
    0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

static const uint64_t SHA512_IV[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

static void sha512_transform(uint64_t state[8], const uint8_t block[128])
{
    uint64_t W[80];
    uint64_t a, b, c, d, e, f, g, h, T1, T2;
    uint32_t i;

    for (i = 0; i < 16; i++) {
        W[i] = be64(block + 8*i);
    }
    for (i = 16; i < 80; i++) {
        uint64_t s0 = ROR64(W[i-15], 1) ^ ROR64(W[i-15], 8) ^ (W[i-15] >> 7);
        uint64_t s1 = ROR64(W[i-2], 19) ^ ROR64(W[i-2], 61) ^ (W[i-2]  >> 6);
        W[i] = W[i-16] + s0 + W[i-7] + s1;
    }

    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];

    for (i = 0; i < 80; i++) {
        uint64_t S1 = ROR64(e, 14) ^ ROR64(e, 18) ^ ROR64(e, 41);
        uint64_t ch = (e & f) ^ (~e & g);
        T1 = h + S1 + ch + K512[i] + W[i];
        uint64_t S0 = ROR64(a, 28) ^ ROR64(a, 34) ^ ROR64(a, 39);
        uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
        T2 = S0 + maj;

        h = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

void sha512_ctx_init(sha512_ctx_t *ctx)
{
    ctx->state[0] = SHA512_IV[0]; ctx->state[1] = SHA512_IV[1];
    ctx->state[2] = SHA512_IV[2]; ctx->state[3] = SHA512_IV[3];
    ctx->state[4] = SHA512_IV[4]; ctx->state[5] = SHA512_IV[5];
    ctx->state[6] = SHA512_IV[6]; ctx->state[7] = SHA512_IV[7];
    ctx->count[0] = ctx->count[1] = 0;
    ctx->buflen = 0;
}

void sha512_ctx_update(sha512_ctx_t *ctx, const uint8_t *in, size_t inlen)
{
    size_t rem;
    uint64_t bit_add = (uint64_t)inlen * 8;

    /* 128-bit addition for bit count */
    ctx->count[1] += bit_add;
    if (ctx->count[1] < bit_add) { ctx->count[0]++; }

    if (ctx->buflen > 0) {
        rem = 128 - ctx->buflen;
        if (inlen < rem) {
            memcpy(ctx->buf + ctx->buflen, in, inlen);
            ctx->buflen += (uint32_t)inlen;
            return;
        }
        memcpy(ctx->buf + ctx->buflen, in, rem);
        sha512_transform(ctx->state, ctx->buf);
        in    += rem;
        inlen -= rem;
        ctx->buflen = 0;
    }

    while (inlen >= 128) {
        sha512_transform(ctx->state, in);
        in    += 128;
        inlen -= 128;
    }

    if (inlen > 0) {
        memcpy(ctx->buf, in, inlen);
        ctx->buflen = (uint32_t)inlen;
    }
}

void sha512_ctx_final(sha512_ctx_t *ctx, uint8_t out[64])
{
    uint8_t pad[128];
    uint32_t i;
    uint64_t bit_count_hi = ctx->count[0];
    uint64_t bit_count_lo = ctx->count[1];

    memset(pad, 0, sizeof(pad));
    pad[0] = 0x80;

    if (ctx->buflen < 112) {
        sha512_ctx_update(ctx, pad, 112 - ctx->buflen);
    } else {
        sha512_ctx_update(ctx, pad, 128 - ctx->buflen);
        sha512_ctx_update(ctx, pad + 1, 112);
    }

    /* Append 128-bit bit count (high then low), big-endian */
    for (i = 0; i < 8; i++) {
        pad[i]   = (uint8_t)(bit_count_hi >> (56 - 8*i));
        pad[8+i] = (uint8_t)(bit_count_lo >> (56 - 8*i));
    }
    sha512_ctx_update(ctx, pad, 16);

    for (i = 0; i < 8; i++) {
        store_be64(out + 8*i, ctx->state[i]);
    }
}

void sha512_local(uint8_t out[64], const uint8_t *in, size_t inlen)
{
    sha512_ctx_t ctx;
    sha512_ctx_init(&ctx);
    sha512_ctx_update(&ctx, in, inlen);
    sha512_ctx_final(&ctx, out);
}
