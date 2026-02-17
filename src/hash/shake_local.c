/**
 * shake_local.c - Stack-based SHAKE-128 and SHAKE-256
 *
 * Implements Keccak-f[1600] from scratch with no heap allocation.
 * All state is held in uint64_t[25] on the caller's stack.
 *
 * Based on the public-domain "Keccak reference implementation" by
 * the Keccak team (https://keccak.team/). Simplified for readability.
 *
 * SHAKE128: rate=168, capacity=32, domain=0x1F
 * SHAKE256: rate=136, capacity=64, domain=0x1F
 */
#include <string.h>
#include <stdint.h>
#include "shake_local.h"

/* ====================================================================
 * Keccak-f[1600] permutation
 * ==================================================================== */

#define ROL64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))

static const uint64_t KECCAK_RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL
};

static const uint32_t KECCAK_RHO[24] = {
     1,  3,  6, 10, 15, 21, 28, 36, 45, 55,  2, 14,
    27, 41, 56,  8, 25, 43, 62, 18, 39, 61, 20, 44
};

static const uint32_t KECCAK_PI[24] = {
    10,  7, 11, 17, 18,  3,  5, 16,  8, 21, 24,  4,
    15, 23, 19, 13, 12,  2, 20, 14, 22,  9,  6,  1
};

static void keccak_f1600(uint64_t st[25])
{
    int round;
    uint64_t tmp, C[5], D[5];

    for (round = 0; round < 24; round++) {
        uint32_t x, y;

        /* Theta */
        for (x = 0; x < 5; x++) {
            C[x] = st[x] ^ st[x+5] ^ st[x+10] ^ st[x+15] ^ st[x+20];
        }
        for (x = 0; x < 5; x++) {
            D[x] = C[(x+4)%5] ^ ROL64(C[(x+1)%5], 1);
        }
        for (x = 0; x < 5; x++) {
            for (y = 0; y < 5; y++) { st[y*5+x] ^= D[x]; }
        }

        /* Rho and Pi */
        {
            uint64_t cur = st[1];
            for (x = 0; x < 24; x++) {
                uint32_t j = KECCAK_PI[x];
                tmp = st[j];
                st[j] = ROL64(cur, KECCAK_RHO[x]);
                cur = tmp;
            }
        }

        /* Chi */
        for (y = 0; y < 5; y++) {
            uint64_t t[5];
            for (x = 0; x < 5; x++) { t[x] = st[y*5+x]; }
            for (x = 0; x < 5; x++) {
                st[y*5+x] = t[x] ^ (~t[(x+1)%5] & t[(x+2)%5]);
            }
        }

        /* Iota */
        st[0] ^= KECCAK_RC[round];
    }
}

/* XOR rate bytes of input into state (little-endian 64-bit lanes) */
static void keccak_absorb_block(uint64_t st[25], const uint8_t *block, uint32_t rate)
{
    uint32_t i;
    for (i = 0; i < rate / 8; i++) {
        uint64_t w = 0;
        uint32_t j;
        for (j = 0; j < 8; j++) {
            w |= ((uint64_t)block[8*i+j]) << (8*j);
        }
        st[i] ^= w;
    }
}

/* Squeeze rate bytes from state into output */
static void keccak_squeeze_block(const uint64_t st[25], uint8_t *block, uint32_t rate)
{
    uint32_t i;
    for (i = 0; i < rate / 8; i++) {
        uint64_t w = st[i];
        uint32_t j;
        for (j = 0; j < 8; j++) {
            block[8*i+j] = (uint8_t)(w >> (8*j));
        }
    }
}

/* ====================================================================
 * Generic Keccak-based XOF (SHAKE)
 * ==================================================================== */

static void shake_absorb(uint64_t st[25], uint8_t *buf, uint32_t *buflen,
                         uint32_t rate, const uint8_t *in, size_t inlen)
{
    size_t rem;

    if (*buflen > 0) {
        rem = rate - *buflen;
        if (inlen < rem) {
            memcpy(buf + *buflen, in, inlen);
            *buflen += (uint32_t)inlen;
            return;
        }
        memcpy(buf + *buflen, in, rem);
        keccak_absorb_block(st, buf, rate);
        keccak_f1600(st);
        in    += rem;
        inlen -= rem;
        *buflen = 0;
    }

    while (inlen >= (size_t)rate) {
        keccak_absorb_block(st, in, rate);
        keccak_f1600(st);
        in    += rate;
        inlen -= rate;
    }

    if (inlen > 0) {
        memcpy(buf, in, inlen);
        *buflen = (uint32_t)inlen;
    }
}

static void shake_finalize(uint64_t st[25], uint8_t *buf, uint32_t buflen,
                           uint32_t rate)
{
    /* SHAKE domain separation: 0x1F */
    buf[buflen] = 0x1F;
    memset(buf + buflen + 1, 0, rate - buflen - 1);
    buf[rate - 1] |= 0x80;
    keccak_absorb_block(st, buf, rate);
    keccak_f1600(st);
}

/* One-shot helper */
static void shake_oneshot(uint8_t *out, size_t outlen,
                          const uint8_t *in, size_t inlen,
                          uint32_t rate)
{
    uint64_t st[25];
    uint8_t  buf[168]; /* max rate (SHAKE128) */
    uint32_t buflen = 0;
    uint8_t  out_buf[168];

    memset(st, 0, sizeof(st));
    memset(buf, 0, sizeof(buf));
    memset(out_buf, 0, sizeof(out_buf));

    shake_absorb(st, buf, &buflen, rate, in, inlen);
    shake_finalize(st, buf, buflen, rate);

    /* After finalize, state is ready to squeeze directly */
    while (outlen > 0) {
        size_t blk = (outlen < rate) ? outlen : rate;
        keccak_squeeze_block(st, out_buf, rate);
        memcpy(out, out_buf, blk);
        out    += blk;
        outlen -= blk;
        if (outlen > 0) { keccak_f1600(st); }
    }
}

/* ====================================================================
 * Public API - SHAKE-128
 * ==================================================================== */

#define SHAKE128_RATE 168

void shake128_local(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen)
{
    shake_oneshot(out, outlen, in, inlen, SHAKE128_RATE);
}

void shake128_ctx_init(shake128_ctx_t *ctx)
{
    memset(ctx->state, 0, sizeof(ctx->state));
    memset(ctx->buf, 0, sizeof(ctx->buf));
    memset(ctx->out_buf, 0, sizeof(ctx->out_buf));
    ctx->buflen    = 0;
    ctx->finalized = 0;
    ctx->squeeze_off = 0;
}

void shake128_ctx_absorb(shake128_ctx_t *ctx, const uint8_t *in, size_t inlen)
{
    shake_absorb(ctx->state, ctx->buf, &ctx->buflen, SHAKE128_RATE, in, inlen);
}

void shake128_ctx_finalize(shake128_ctx_t *ctx)
{
    shake_finalize(ctx->state, ctx->buf, ctx->buflen, SHAKE128_RATE);
    ctx->finalized   = 1;
    ctx->squeeze_off = 0;
}

void shake128_ctx_squeeze(shake128_ctx_t *ctx, uint8_t *out, size_t outlen)
{
    /* On first squeeze call, populate out_buf */
    if (ctx->squeeze_off == 0) {
        keccak_squeeze_block(ctx->state, ctx->out_buf, SHAKE128_RATE);
    }

    while (outlen > 0) {
        size_t have = SHAKE128_RATE - ctx->squeeze_off;
        if (outlen <= have) {
            memcpy(out, ctx->out_buf + ctx->squeeze_off, outlen);
            ctx->squeeze_off += (uint32_t)outlen;
            if (ctx->squeeze_off == SHAKE128_RATE) {
                keccak_f1600(ctx->state);
                ctx->squeeze_off = 0;
            }
            return;
        }
        memcpy(out, ctx->out_buf + ctx->squeeze_off, have);
        out    += have;
        outlen -= have;
        keccak_f1600(ctx->state);
        keccak_squeeze_block(ctx->state, ctx->out_buf, SHAKE128_RATE);
        ctx->squeeze_off = 0;
    }
}

/* ====================================================================
 * Public API - SHAKE-256
 * ==================================================================== */

#define SHAKE256_RATE 136

void shake256_local(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen)
{
    shake_oneshot(out, outlen, in, inlen, SHAKE256_RATE);
}

void shake256_ctx_init(shake256_ctx_t *ctx)
{
    memset(ctx->state, 0, sizeof(ctx->state));
    memset(ctx->buf, 0, sizeof(ctx->buf));
    memset(ctx->out_buf, 0, sizeof(ctx->out_buf));
    ctx->buflen    = 0;
    ctx->finalized = 0;
    ctx->squeeze_off = 0;
}

void shake256_ctx_absorb(shake256_ctx_t *ctx, const uint8_t *in, size_t inlen)
{
    shake_absorb(ctx->state, ctx->buf, &ctx->buflen, SHAKE256_RATE, in, inlen);
}

void shake256_ctx_finalize(shake256_ctx_t *ctx)
{
    shake_finalize(ctx->state, ctx->buf, ctx->buflen, SHAKE256_RATE);
    ctx->finalized   = 1;
    ctx->squeeze_off = 0;
}

void shake256_ctx_squeeze(shake256_ctx_t *ctx, uint8_t *out, size_t outlen)
{
    if (ctx->squeeze_off == 0) {
        keccak_squeeze_block(ctx->state, ctx->out_buf, SHAKE256_RATE);
    }

    while (outlen > 0) {
        size_t have = SHAKE256_RATE - ctx->squeeze_off;
        if (outlen <= have) {
            memcpy(out, ctx->out_buf + ctx->squeeze_off, outlen);
            ctx->squeeze_off += (uint32_t)outlen;
            if (ctx->squeeze_off == SHAKE256_RATE) {
                keccak_f1600(ctx->state);
                ctx->squeeze_off = 0;
            }
            return;
        }
        memcpy(out, ctx->out_buf + ctx->squeeze_off, have);
        out    += have;
        outlen -= have;
        keccak_f1600(ctx->state);
        keccak_squeeze_block(ctx->state, ctx->out_buf, SHAKE256_RATE);
        ctx->squeeze_off = 0;
    }
}
