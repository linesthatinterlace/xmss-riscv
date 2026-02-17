/**
 * xmss_hash.c - XMSS hash function dispatch
 *
 * This is the SOLE location of hash backend dispatch.
 * Implements F, H, H_msg, PRF, PRF_keygen for SHA-2 and SHAKE backends.
 *
 * RFC 8391 §5.2: SHA-2 based parameter sets use SHA-256 (n=32) or SHA-512
 * (n=64) with a bitmask XOR construction.
 *
 * SHA-2 domain separation (RFC 8391 §5.1):
 *   input = toByte(D, 32) || KEY || ADRS || M
 * where D is:
 *   F        = 0x00000000 (word, encodes as: all-zero pad then 0x00 in last byte)
 *   H        = 0x00000001
 *   H_msg    = 0x00000002
 *   PRF      = 0x00000003
 *   PRF_keygen = 0x00000004 (not in all RFC versions; some use PRF for both)
 *
 * Actually RFC 8391 §5.1 uses a specific padding scheme.  The SHA-2 based
 * functions hash:
 *   toByte(func_const, n) || KEY || ADRS_bytes(32) || M
 * where func_const distinguishes F/H/H_msg/PRF.
 *
 * For SHA-2 bitmask: F and H XOR their data input with a bitmask generated
 * by hashing with key_and_mask = 1 (for single-input) or 0,1 (for two inputs).
 *
 * SHAKE based parameter sets hash:
 *   SHAKE128(ADRS_bytes || KEY || M, n_bytes) (no bitmask)
 * for n=32, and SHAKE256 for n=64.
 *
 * JASMIN: replace this file with a .jazz file per parameter set.
 * Mark each dispatch point with: JASMIN-direct-call
 */
#include <stddef.h>
#include <string.h>
#include <stdint.h>

#include "hash_iface.h"
#include "sha2_local.h"
#include "shake_local.h"
#include "../utils.h"
#include "../address.h"
#include "../../include/xmss/params.h"
#include "../../include/xmss/types.h"

/* Domain constants for SHA-2 padding (RFC 8391 §5.1) */
#define DOM_F         0x00U
#define DOM_H         0x01U
#define DOM_H_MSG     0x02U
#define DOM_PRF       0x03U
#define DOM_PRF_KEYGEN 0x04U

/*
 * sha2_prf_bitmask() - Generate n-byte bitmask for SHA-2 F and H.
 *
 * bitmask = Hash(toByte(dom, n) || KEY || ADRS_with_key_and_mask_set)
 *
 * For F: one bitmask (key_and_mask = 1).
 * For H: two bitmasks (key_and_mask = 0 and 1), each n bytes.
 */
static void sha2_hash_prf(const xmss_params *p,
                          uint8_t *out,          /* n bytes output */
                          uint8_t dom,
                          const uint8_t *key,    /* n bytes */
                          const xmss_adrs_t *adrs)
{
    uint8_t  adrs_bytes[32];
    /* Max input: pad(n) + key(n) + adrs(32) = 64+64+32 = 160 bytes for n=64 */
    uint8_t  buf[64 + 64 + 32]; /* XMSS_MAX_N * 2 + 32 */
    uint32_t off = 0;
    uint32_t i;

    /* toByte(dom, n): n-1 zero bytes then dom in the last byte */
    for (i = 0; i < p->n - 1; i++) { buf[off++] = 0x00; }
    buf[off++] = dom;

    /* KEY */
    memcpy(buf + off, key, p->n);
    off += p->n;

    /* ADRS serialised */
    xmss_adrs_to_bytes(adrs, adrs_bytes);
    memcpy(buf + off, adrs_bytes, 32);
    off += 32;

    /* Hash */
    if (p->n == 32) {
        sha256_local(out, buf, off); /* JASMIN: replace with direct call */
    } else {
        sha512_local(out, buf, off); /* JASMIN: replace with direct call */
    }
}

/*
 * sha2_hash_full() - Hash with prepended domain and the full construction
 * for F and H (including bitmask XOR).
 *
 * For F (single input of n bytes):
 *   bm    = sha2_prf(dom=0, SEED, adrs[key_and_mask=1])
 *   input = m XOR bm
 *   out   = Hash(toByte(0,n) || SEED || ADRS[key_and_mask=0] || input)
 *
 * For H (two inputs of n bytes each):
 *   bm_l  = sha2_prf(dom=1, SEED, adrs[key_and_mask=0])
 *   bm_r  = sha2_prf(dom=1, SEED, adrs[key_and_mask=1])
 *   input = (l XOR bm_l) || (r XOR bm_r)
 *   out   = Hash(toByte(1,n) || SEED || ADRS[key_and_mask=0] || input)
 *
 * Wait — RFC 8391 §5.1 is precise. Let me re-read.
 *
 * RFC 8391 §5.1.1 SHA2-F:
 *   KEY = SEED
 *   M   = M[0] (n bytes)
 *   F(KEY, M) = Hash(toByte(0, 32) || KEY || ADRS || BM)
 *   where BM = M XOR PRF(KEY, ADRS[key_and_mask=1])
 *
 * RFC 8391 §5.1.2 SHA2-H:
 *   KEY = SEED
 *   H(KEY, M_l || M_r):
 *   BM_0 = PRF(KEY, ADRS[key_and_mask=0])
 *   BM_1 = PRF(KEY, ADRS[key_and_mask=1])
 *   H(KEY, M) = Hash(toByte(1, 32) || KEY || ADRS || (M_l XOR BM_0) || (M_r XOR BM_1))
 *
 * So the PRF used here for bitmask generation is a SEPARATE call
 * (conceptually PRF(KEY, ADRS)).  For SHA-2, ADRS differs by key_and_mask field.
 * The outer hash uses toByte(dom, 32) not toByte(dom, n).
 *
 * CORRECTION: RFC 8391 §5.1 Table 2 uses pad_len=32 for n=32, pad_len=64 for n=64.
 * So toByte(dom, n) where n is the same as hash output size.
 */

/*
 * bitmask_sha2(): PRF for SHA-2 bitmask generation.
 * PRF(KEY, ADRS) = Hash(toByte(3, n) || KEY || ADRS)
 * (same as xmss_PRF but used internally here)
 */
static void bitmask_sha2(const xmss_params *p,
                         uint8_t *out,
                         const uint8_t *key,
                         xmss_adrs_t *adrs_copy, /* modified (key_and_mask) */
                         uint32_t key_and_mask)
{
    xmss_adrs_set_key_and_mask(adrs_copy, key_and_mask);
    sha2_hash_prf(p, out, DOM_PRF, key, adrs_copy);
}

/* ====================================================================
 * F - WOTS+ chaining function
 * ==================================================================== */

int xmss_F(const xmss_params *p, uint8_t *out,
           const uint8_t *key, const xmss_adrs_t *adrs,
           const uint8_t *in)
{
    /* JASMIN: replace dispatch with direct call */
    if (p->func == XMSS_FUNC_SHA2) {
        uint8_t  bm[XMSS_MAX_N];
        uint8_t  masked[XMSS_MAX_N];
        uint8_t  buf[64 + XMSS_MAX_N + 32 + XMSS_MAX_N];
        uint32_t off = 0;
        uint32_t i;
        xmss_adrs_t a = *adrs;

        /* Generate bitmask: PRF(SEED, ADRS[key_and_mask=1]) */
        bitmask_sha2(p, bm, key, &a, 1);

        /* BM = in XOR bm */
        for (i = 0; i < p->n; i++) { masked[i] = in[i] ^ bm[i]; }

        /* Outer hash: toByte(0, n) || SEED || ADRS[key_and_mask=0] || BM */
        a = *adrs;
        xmss_adrs_set_key_and_mask(&a, 0);

        uint8_t adrs_bytes[32];
        xmss_adrs_to_bytes(&a, adrs_bytes);

        /* toByte(0, n): all zeros */
        for (i = 0; i < p->n; i++) { buf[off++] = 0x00; }
        memcpy(buf + off, key, p->n);   off += p->n;
        memcpy(buf + off, adrs_bytes, 32); off += 32;
        memcpy(buf + off, masked, p->n); off += p->n;

        if (p->n == 32) { sha256_local(out, buf, off); }
        else            { sha512_local(out, buf, off); }

    } else {
        /* SHAKE: F(KEY, M) = SHAKE(toByte(0,32) || KEY || ADRS || M, n*8) */
        uint8_t  buf[32 + XMSS_MAX_N + 32 + XMSS_MAX_N];
        uint8_t  adrs_bytes[32];
        uint32_t off = 0;
        uint32_t i;

        /* 32 bytes of zeros (function constant) */
        for (i = 0; i < 32; i++) { buf[off++] = 0x00; }
        memcpy(buf + off, key, p->n);  off += p->n;
        xmss_adrs_to_bytes(adrs, adrs_bytes);
        memcpy(buf + off, adrs_bytes, 32); off += 32;
        memcpy(buf + off, in, p->n);   off += p->n;

        if (p->func == XMSS_FUNC_SHAKE128) {
            shake128_local(out, p->n, buf, off); /* JASMIN: replace with direct call */
        } else {
            shake256_local(out, p->n, buf, off); /* JASMIN: replace with direct call */
        }
    }
    return 0;
}

/* ====================================================================
 * H - Tree hash function
 * ==================================================================== */

int xmss_H(const xmss_params *p, uint8_t *out,
           const uint8_t *key, const xmss_adrs_t *adrs,
           const uint8_t *in_l, const uint8_t *in_r)
{
    /* JASMIN: replace dispatch with direct call */
    if (p->func == XMSS_FUNC_SHA2) {
        uint8_t  bm_l[XMSS_MAX_N], bm_r[XMSS_MAX_N];
        uint8_t  buf[64 + XMSS_MAX_N + 32 + 2*XMSS_MAX_N];
        uint8_t  adrs_bytes[32];
        uint32_t off = 0;
        uint32_t i;
        xmss_adrs_t a = *adrs;

        bitmask_sha2(p, bm_l, key, &a, 0);
        a = *adrs;
        bitmask_sha2(p, bm_r, key, &a, 1);

        a = *adrs;
        xmss_adrs_set_key_and_mask(&a, 0);
        xmss_adrs_to_bytes(&a, adrs_bytes);

        for (i = 0; i < p->n; i++) { buf[off++] = 0x00; } /* toByte(1,n)? no: toByte(1,n) means val=1 */
        /* Wait: RFC says toByte(1, n) for H which means n-1 zeros then 0x01 */
        off = 0;
        for (i = 0; i < p->n - 1; i++) { buf[off++] = 0x00; }
        buf[off++] = 0x01;
        memcpy(buf + off, key, p->n);            off += p->n;
        memcpy(buf + off, adrs_bytes, 32);        off += 32;
        for (i = 0; i < p->n; i++) { buf[off++] = in_l[i] ^ bm_l[i]; }
        for (i = 0; i < p->n; i++) { buf[off++] = in_r[i] ^ bm_r[i]; }

        if (p->n == 32) { sha256_local(out, buf, off); }
        else            { sha512_local(out, buf, off); }

    } else {
        /* SHAKE: H = SHAKE(toByte(1,32) || KEY || ADRS || M_l || M_r, n*8) */
        uint8_t  buf[32 + XMSS_MAX_N + 32 + 2*XMSS_MAX_N];
        uint8_t  adrs_bytes[32];
        uint32_t off = 0;
        uint32_t i;

        for (i = 0; i < 31; i++) { buf[off++] = 0x00; }
        buf[off++] = 0x01;
        memcpy(buf + off, key, p->n);   off += p->n;
        xmss_adrs_to_bytes(adrs, adrs_bytes);
        memcpy(buf + off, adrs_bytes, 32); off += 32;
        memcpy(buf + off, in_l, p->n);  off += p->n;
        memcpy(buf + off, in_r, p->n);  off += p->n;

        if (p->func == XMSS_FUNC_SHAKE128) {
            shake128_local(out, p->n, buf, off);
        } else {
            shake256_local(out, p->n, buf, off);
        }
    }
    return 0;
}

/* ====================================================================
 * H_msg - Message hash function
 * ==================================================================== */

int xmss_H_msg(const xmss_params *p, uint8_t *out,
               const uint8_t *r, const uint8_t *root, uint64_t idx,
               const uint8_t *msg, size_t msglen)
{
    /*
     * H_msg(KEY, M) where KEY = r || root || toByte(idx, 32)
     * SHA-2: Hash(toByte(2, n) || KEY || M)
     * SHAKE: SHAKE(toByte(2, 32) || KEY || M, n*8)
     *
     * KEY length = n + n + 32 = 2n + 32
     * This has variable-length M, so we use incremental hashing.
     */
    uint8_t  idx_bytes[32];
    uint32_t i;

    ull_to_bytes(idx_bytes, 32, idx);

    if (p->func == XMSS_FUNC_SHA2) {
        sha256_ctx_t ctx256;
        sha512_ctx_t ctx512;
        uint8_t  dom[64]; /* toByte(2, n): n-1 zeros then 0x02 */

        for (i = 0; i < p->n - 1; i++) { dom[i] = 0x00; }
        dom[p->n - 1] = DOM_H_MSG;

        if (p->n == 32) {
            sha256_ctx_init(&ctx256);
            sha256_ctx_update(&ctx256, dom, p->n);
            sha256_ctx_update(&ctx256, r, p->n);
            sha256_ctx_update(&ctx256, root, p->n);
            sha256_ctx_update(&ctx256, idx_bytes, 32);
            sha256_ctx_update(&ctx256, msg, msglen);
            sha256_ctx_final(&ctx256, out);
        } else {
            sha512_ctx_init(&ctx512);
            sha512_ctx_update(&ctx512, dom, p->n);
            sha512_ctx_update(&ctx512, r, p->n);
            sha512_ctx_update(&ctx512, root, p->n);
            sha512_ctx_update(&ctx512, idx_bytes, 32);
            sha512_ctx_update(&ctx512, msg, msglen);
            sha512_ctx_final(&ctx512, out);
        }
    } else {
        /* SHAKE: toByte(2, 32) prefix */
        uint8_t dom[32];
        memset(dom, 0, 31);
        dom[31] = DOM_H_MSG;

        if (p->func == XMSS_FUNC_SHAKE128) {
            shake128_ctx_t ctx;
            shake128_ctx_init(&ctx);
            shake128_ctx_absorb(&ctx, dom, 32);
            shake128_ctx_absorb(&ctx, r, p->n);
            shake128_ctx_absorb(&ctx, root, p->n);
            shake128_ctx_absorb(&ctx, idx_bytes, 32);
            shake128_ctx_absorb(&ctx, msg, msglen);
            shake128_ctx_finalize(&ctx);
            shake128_ctx_squeeze(&ctx, out, p->n);
        } else {
            shake256_ctx_t ctx;
            shake256_ctx_init(&ctx);
            shake256_ctx_absorb(&ctx, dom, 32);
            shake256_ctx_absorb(&ctx, r, p->n);
            shake256_ctx_absorb(&ctx, root, p->n);
            shake256_ctx_absorb(&ctx, idx_bytes, 32);
            shake256_ctx_absorb(&ctx, msg, msglen);
            shake256_ctx_finalize(&ctx);
            shake256_ctx_squeeze(&ctx, out, p->n);
        }
    }
    return 0;
}

/* ====================================================================
 * PRF - Pseudorandom function
 * ==================================================================== */

int xmss_PRF(const xmss_params *p, uint8_t *out,
             const uint8_t *key, const xmss_adrs_t *adrs)
{
    /* JASMIN: replace dispatch with direct call */
    if (p->func == XMSS_FUNC_SHA2) {
        sha2_hash_prf(p, out, DOM_PRF, key, adrs);
    } else {
        uint8_t  buf[32 + XMSS_MAX_N + 32];
        uint8_t  adrs_bytes[32];
        uint32_t off = 0;
        uint32_t i;

        /* toByte(3, 32) */
        for (i = 0; i < 31; i++) { buf[off++] = 0x00; }
        buf[off++] = DOM_PRF;
        memcpy(buf + off, key, p->n);  off += p->n;
        xmss_adrs_to_bytes(adrs, adrs_bytes);
        memcpy(buf + off, adrs_bytes, 32); off += 32;

        if (p->func == XMSS_FUNC_SHAKE128) {
            shake128_local(out, p->n, buf, off);
        } else {
            shake256_local(out, p->n, buf, off);
        }
    }
    return 0;
}

/* ====================================================================
 * PRF_keygen - Key generation PRF
 * ==================================================================== */

int xmss_PRF_keygen(const xmss_params *p, uint8_t *out,
                    const uint8_t *sk_seed, const xmss_adrs_t *adrs)
{
    /* JASMIN: replace dispatch with direct call */
    if (p->func == XMSS_FUNC_SHA2) {
        sha2_hash_prf(p, out, DOM_PRF_KEYGEN, sk_seed, adrs);
    } else {
        uint8_t  buf[32 + XMSS_MAX_N + 32];
        uint8_t  adrs_bytes[32];
        uint32_t off = 0;
        uint32_t i;

        /* toByte(4, 32) */
        for (i = 0; i < 31; i++) { buf[off++] = 0x00; }
        buf[off++] = DOM_PRF_KEYGEN;
        memcpy(buf + off, sk_seed, p->n);  off += p->n;
        xmss_adrs_to_bytes(adrs, adrs_bytes);
        memcpy(buf + off, adrs_bytes, 32); off += 32;

        if (p->func == XMSS_FUNC_SHAKE128) {
            shake128_local(out, p->n, buf, off);
        } else {
            shake256_local(out, p->n, buf, off);
        }
    }
    return 0;
}

/* ====================================================================
 * xmss_PRF_idx() - PRF with index as raw 32-byte message
 * Used for computing r = PRF(SK_PRF, toByte(idx, 32)) in signing.
 * ==================================================================== */
int xmss_PRF_idx(const xmss_params *p, uint8_t *out,
                 const uint8_t *sk_prf, uint64_t idx)
{
    /* toByte(3, n) || SK_PRF || toByte(idx, 32) */
    uint8_t  buf[XMSS_MAX_N + XMSS_MAX_N + 32];
    uint8_t  idx_bytes[32];
    uint32_t off = 0;
    uint32_t i;

    /* toByte(3, n): domain for PRF */
    for (i = 0; i < p->n - 1; i++) { buf[off++] = 0x00; }
    buf[off++] = DOM_PRF;

    memcpy(buf + off, sk_prf, p->n); off += p->n;

    /* Encode idx as 32-byte big-endian */
    for (i = 0; i < 24; i++) { idx_bytes[i] = 0x00; }
    idx_bytes[24] = (uint8_t)(idx >> 56);
    idx_bytes[25] = (uint8_t)(idx >> 48);
    idx_bytes[26] = (uint8_t)(idx >> 40);
    idx_bytes[27] = (uint8_t)(idx >> 32);
    idx_bytes[28] = (uint8_t)(idx >> 24);
    idx_bytes[29] = (uint8_t)(idx >> 16);
    idx_bytes[30] = (uint8_t)(idx >>  8);
    idx_bytes[31] = (uint8_t)(idx      );

    memcpy(buf + off, idx_bytes, 32); off += 32;

    /* JASMIN: replace dispatch with direct call */
    if (p->func == XMSS_FUNC_SHA2) {
        if (p->n == 32) { sha256_local(out, buf, off); }
        else            { sha512_local(out, buf, off); }
    } else if (p->func == XMSS_FUNC_SHAKE128) {
        shake128_local(out, p->n, buf, off);
    } else {
        shake256_local(out, p->n, buf, off);
    }
    return 0;
}
