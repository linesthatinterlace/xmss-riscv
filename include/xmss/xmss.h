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
 * SK layout (RFC 8391 §4.1.6, Errata 7900):
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

#endif /* XMSS_H */
