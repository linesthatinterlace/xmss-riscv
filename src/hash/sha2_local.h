/**
 * sha2_local.h - Stack-based SHA-256 and SHA-512 (no malloc)
 *
 * These are minimal, self-contained implementations for use within XMSS.
 * They do not use malloc; all state is on the caller's stack.
 * API is a simple one-shot function for the bounded inputs used in XMSS.
 *
 * For variable-length H_msg, an incremental API is provided.
 */
#ifndef XMSS_SHA2_LOCAL_H
#define XMSS_SHA2_LOCAL_H

#include <stddef.h>
#include <stdint.h>

/* One-shot SHA-256: produces 32 bytes */
void sha256_local(uint8_t out[32], const uint8_t *in, size_t inlen);

/* One-shot SHA-512: produces 64 bytes */
void sha512_local(uint8_t out[64], const uint8_t *in, size_t inlen);

/*
 * Incremental SHA-256 for H_msg (arbitrary-length messages).
 * State is entirely on the stack; no malloc.
 */
typedef struct {
    uint32_t state[8];
    uint64_t count;          /* bits processed so far */
    uint8_t  buf[64];
    uint32_t buflen;
} sha256_ctx_t;

void sha256_ctx_init   (sha256_ctx_t *ctx);
void sha256_ctx_update (sha256_ctx_t *ctx, const uint8_t *in, size_t inlen);
void sha256_ctx_final  (sha256_ctx_t *ctx, uint8_t out[32]);

/*
 * Incremental SHA-512 for H_msg with n=64 parameter sets.
 */
typedef struct {
    uint64_t state[8];
    uint64_t count[2];       /* 128-bit bit counter (high, low) */
    uint8_t  buf[128];
    uint32_t buflen;
} sha512_ctx_t;

void sha512_ctx_init   (sha512_ctx_t *ctx);
void sha512_ctx_update (sha512_ctx_t *ctx, const uint8_t *in, size_t inlen);
void sha512_ctx_final  (sha512_ctx_t *ctx, uint8_t out[64]);

#endif /* XMSS_SHA2_LOCAL_H */
