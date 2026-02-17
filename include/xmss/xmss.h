/**
 * xmss.h - Public XMSS API
 *
 * RFC 8391 XMSS: eXtended Merkle Signature Scheme.
 *
 * All functions return 0 on success and a negative value on failure.
 * No heap allocation is performed; callers must supply correctly-sized buffers.
 * Buffer sizes are determined by xmss_params fields sig_bytes, pk_bytes, sk_bytes.
 *
 * Jasmin portability rules (see implementation plan):
 *   J1: No VLAs
 *   J2: No function pointers in algorithm code (dispatch only in xmss_hash.c)
 *   J3: No malloc
 *   J4: No recursion
 *   J5: Bounded loop counts
 *   J6: Constant-time for secret-dependent operations
 *   J7: ADRS always by pointer, serialised to 32-byte stack buffer for hashing
 *   J8: One C file per algorithm
 */
#ifndef XMSS_H
#define XMSS_H

#include <stddef.h>
#include <stdint.h>

#include "params.h"

/** Error codes */
#define XMSS_OK            0
#define XMSS_ERR_PARAMS   (-1)
#define XMSS_ERR_ENTROPY  (-2)
#define XMSS_ERR_VERIFY   (-3)
#define XMSS_ERR_EXHAUSTED (-4)  /* key index exhausted */

/**
 * Entropy callback type.
 *
 * The caller supplies a function that fills buf[0..len-1] with len bytes of
 * cryptographically secure random data.  Returns 0 on success, non-zero on
 * failure.  This keeps the library bare-metal compatible.
 */
typedef int (*xmss_randombytes_fn)(uint8_t *buf, size_t len);

/**
 * xmss_keygen() - Generate an XMSS key pair.
 *
 * @p:           Pointer to populated xmss_params (from xmss_params_from_oid).
 * @pk:          Output public key  (p->pk_bytes bytes).
 * @sk:          Output secret key  (p->sk_bytes bytes).
 * @randombytes: Caller-supplied entropy function.
 *
 * Returns XMSS_OK on success.
 *
 * SK layout (RFC 8391 §4.1.3, Errata 7900):
 *   OID(4) | idx(idx_bytes) | SK_SEED(n) | SK_PRF(n) | root(n) | SEED(n)
 * PK layout:
 *   OID(4) | root(n) | SEED(n)
 */
int xmss_keygen(const xmss_params *p, uint8_t *pk, uint8_t *sk,
                xmss_randombytes_fn randombytes);

/**
 * xmss_sign() - Sign a message.
 *
 * @p:    Parameter set.
 * @sig:  Output signature (p->sig_bytes bytes).
 * @msg:  Message to sign.
 * @msglen: Message length in bytes.
 * @sk:   Secret key (p->sk_bytes bytes); leaf index is incremented in place.
 *
 * Returns XMSS_OK on success, XMSS_ERR_EXHAUSTED if key index is already at
 * maximum.
 *
 * The leaf index in sk is incremented BEFORE returning to the caller.
 * Callers must persist the updated sk immediately to prevent index reuse.
 *
 * Signature layout (RFC 8391 §4.1.8):
 *   idx(idx_bytes) | r(n) | sig_WOTS(len*n) | auth(h*n)
 */
int xmss_sign(const xmss_params *p, uint8_t *sig,
              const uint8_t *msg, size_t msglen,
              uint8_t *sk);

/**
 * xmss_verify() - Verify an XMSS signature.
 *
 * @p:      Parameter set.
 * @msg:    Message that was signed.
 * @msglen: Message length.
 * @sig:    Signature (p->sig_bytes bytes).
 * @pk:     Public key (p->pk_bytes bytes).
 *
 * Returns XMSS_OK if signature is valid, XMSS_ERR_VERIFY if invalid.
 * Comparison is constant-time (ct_memcmp).
 */
int xmss_verify(const xmss_params *p,
                const uint8_t *msg, size_t msglen,
                const uint8_t *sig, const uint8_t *pk);

/* ====================================================================
 * BDS-accelerated API
 *
 * BDS amortises auth path computation: signing is O(h) leaf computations
 * instead of O(h * 2^h).  The BDS state is a separate caller-managed
 * buffer (not stored in SK, which stays RFC-compatible).
 * ==================================================================== */

/** Per-level treehash instance (internal detail exposed for static sizing). */
typedef struct {
    uint8_t  node[XMSS_MAX_N];   /* partial/completed result */
    uint32_t h;                   /* target height */
    uint32_t next_idx;            /* next leaf to process */
    uint8_t  stack_usage;         /* entries this instance has on shared stack */
    uint8_t  completed;           /* 1 if treehash is done */
} xmss_bds_treehash_inst;

/**
 * xmss_bds_state - BDS traversal state.
 *
 * Fixed-size, no pointers, no malloc (J1/J3).  Allocated by the caller
 * on the stack or as a static/global.  Must be initialised by
 * xmss_keygen_bds() and updated by each xmss_sign_bds() call.
 */
typedef struct xmss_bds_state {
    /* Auth path for current leaf: h nodes of n bytes */
    uint8_t auth[XMSS_MAX_H][XMSS_MAX_N];

    /* Keep nodes: floor(h/2) nodes saved during bds_round */
    uint8_t keep[XMSS_MAX_H / 2][XMSS_MAX_N];

    /* Shared stack for treehash instances */
    uint8_t  stack[XMSS_MAX_H + 1][XMSS_MAX_N];
    uint8_t  stack_levels[XMSS_MAX_H + 1];
    uint32_t stack_offset;

    /* Treehash instances: one per level below (h - bds_k) */
    xmss_bds_treehash_inst treehash[XMSS_MAX_H];

    /* Retain stack for top bds_k levels.
     * Size: sum_{j=0}^{k-1} 2^(j) - 1 = 2^k - k - 1 nodes.
     * For k=0 this is unused.  For k=4: 11 nodes. */
    uint8_t retain[((1U << XMSS_MAX_BDS_K) - XMSS_MAX_BDS_K - 1) > 0 ?
                   ((1U << XMSS_MAX_BDS_K) - XMSS_MAX_BDS_K - 1) : 1][XMSS_MAX_N];

    uint32_t next_leaf;  /* next leaf to compute during state_update */
} xmss_bds_state;

/**
 * xmss_keygen_bds() - Generate an XMSS key pair with BDS state.
 *
 * Same as xmss_keygen() but also initialises the BDS state for
 * subsequent BDS-accelerated signing.
 *
 * @p:           Parameter set.
 * @pk:          Output public key (p->pk_bytes bytes).
 * @sk:          Output secret key (p->sk_bytes bytes).
 * @state:       Output BDS state (caller-allocated).
 * @bds_k:       Retain parameter (must be even, 0 <= bds_k <= h).
 * @randombytes: Caller-supplied entropy function.
 *
 * Returns XMSS_OK on success, XMSS_ERR_PARAMS if bds_k is invalid.
 */
int xmss_keygen_bds(const xmss_params *p, uint8_t *pk, uint8_t *sk,
                    xmss_bds_state *state, uint32_t bds_k,
                    xmss_randombytes_fn randombytes);

/**
 * xmss_sign_bds() - Sign a message using BDS-accelerated auth path.
 *
 * Same as xmss_sign() but uses and updates the BDS state instead of
 * recomputing the auth path from scratch.  O(h) leaf computations per
 * signature instead of O(h * 2^h).
 *
 * @p:      Parameter set.
 * @sig:    Output signature (p->sig_bytes bytes).
 * @msg:    Message to sign.
 * @msglen: Message length in bytes.
 * @sk:     Secret key (p->sk_bytes bytes); leaf index incremented in place.
 * @state:  BDS state (updated in place).
 * @bds_k:  Retain parameter (same value used in keygen_bds).
 *
 * Returns XMSS_OK on success, XMSS_ERR_EXHAUSTED if key index exhausted.
 */
int xmss_sign_bds(const xmss_params *p, uint8_t *sig,
                  const uint8_t *msg, size_t msglen,
                  uint8_t *sk, xmss_bds_state *state, uint32_t bds_k);

#endif /* XMSS_H */
