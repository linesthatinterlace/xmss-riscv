/**
 * shake_local.h - Stack-based SHAKE-128 and SHAKE-256 (no malloc)
 *
 * Wraps the PQClean fips202 functions but provides the Keccak state
 * on the caller's stack by using the non-incremental absorb/squeeze API
 * which may still internally malloc.  For guaranteed no-malloc, we
 * implement a thin Keccak-based SHAKE directly.
 *
 * Actually: PQClean's shake128_absorb / shake256_absorb use malloc too.
 * So we implement SHAKE from scratch using a stack-based Keccak state.
 */
#ifndef XMSS_SHAKE_LOCAL_H
#define XMSS_SHAKE_LOCAL_H

#include <stddef.h>
#include <stdint.h>

/* One-shot SHAKE-128: output outlen bytes */
void shake128_local(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);

/* One-shot SHAKE-256: output outlen bytes */
void shake256_local(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);

/*
 * Incremental SHAKE-128 for H_msg with n=32 SHAKE sets.
 * All state is stack-allocated.
 */
typedef struct {
    uint64_t state[25];
    uint8_t  buf[168];   /* SHAKE128_RATE = 168 */
    uint32_t buflen;
    int      finalized;
    uint32_t squeeze_off; /* byte offset within current squeezed block */
    uint8_t  out_buf[168];
} shake128_ctx_t;

void shake128_ctx_init   (shake128_ctx_t *ctx);
void shake128_ctx_absorb (shake128_ctx_t *ctx, const uint8_t *in, size_t inlen);
void shake128_ctx_finalize(shake128_ctx_t *ctx);
void shake128_ctx_squeeze(shake128_ctx_t *ctx, uint8_t *out, size_t outlen);

/*
 * Incremental SHAKE-256 for H_msg with n=64 SHAKE sets.
 */
typedef struct {
    uint64_t state[25];
    uint8_t  buf[136];   /* SHAKE256_RATE = 136 */
    uint32_t buflen;
    int      finalized;
    uint32_t squeeze_off;
    uint8_t  out_buf[136];
} shake256_ctx_t;

void shake256_ctx_init   (shake256_ctx_t *ctx);
void shake256_ctx_absorb (shake256_ctx_t *ctx, const uint8_t *in, size_t inlen);
void shake256_ctx_finalize(shake256_ctx_t *ctx);
void shake256_ctx_squeeze(shake256_ctx_t *ctx, uint8_t *out, size_t outlen);

#endif /* XMSS_SHAKE_LOCAL_H */
