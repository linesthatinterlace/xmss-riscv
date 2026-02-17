/**
 * xmss.c - XMSS key generation, signing, verification
 *
 * RFC 8391 §4.1, Algorithms 10, 11, 14.
 *
 * SK layout (RFC 8391 §4.1.6, Errata 7900):
 *   OID(4) | idx(idx_bytes) | SK_SEED(n) | SK_PRF(n) | root(n) | SEED(n)
 * PK layout (RFC 8391 §4.1.7):
 *   OID(4) | root(n) | SEED(n)
 * Signature layout (RFC 8391 §4.1.8):
 *   idx(idx_bytes) | r(n) | sig_WOTS(len*n) | auth(h*n)
 */
#include <string.h>
#include <stdint.h>

#include "../include/xmss/xmss.h"
#include "../include/xmss/params.h"
#include "../include/xmss/types.h"
#include "utils.h"
#include "address.h"
#include "hash/hash_iface.h"
#include "wots.h"
#include "ltree.h"
#include "treehash.h"

/* ====================================================================
 * SK / PK field accessors
 * ==================================================================== */

/* SK offsets */
static uint32_t sk_off_oid (const xmss_params *p) { (void)p; return 0; }
static uint32_t sk_off_idx (const xmss_params *p) { (void)p; return 4; }
static uint32_t sk_off_seed(const xmss_params *p) { return 4 + p->idx_bytes; }
static uint32_t sk_off_prf (const xmss_params *p) { return 4 + p->idx_bytes + p->n; }
static uint32_t sk_off_root(const xmss_params *p) { return 4 + p->idx_bytes + 2*p->n; }
static uint32_t sk_off_pub_seed(const xmss_params *p) { return 4 + p->idx_bytes + 3*p->n; }

/* PK offsets */
static uint32_t pk_off_root(const xmss_params *p) { (void)p; return 4; }
static uint32_t pk_off_seed(const xmss_params *p) { return 4 + p->n; }

/* ====================================================================
 * xmss_keygen() - Algorithm 10
 * ==================================================================== */

int xmss_keygen(const xmss_params *p, uint8_t *pk, uint8_t *sk,
                xmss_randombytes_fn randombytes)
{
    uint8_t  root[XMSS_MAX_N];
    uint8_t  seeds[3 * XMSS_MAX_N]; /* SK_SEED || SK_PRF || SEED */
    xmss_adrs_t adrs;
    int ret;

    /* Sample 3n random bytes: SK_SEED, SK_PRF, SEED */
    ret = randombytes(seeds, 3 * p->n);
    if (ret != 0) { return XMSS_ERR_ENTROPY; }

    /* Compute tree root */
    memset(&adrs, 0, sizeof(adrs));
    xmss_adrs_set_layer(&adrs, 0);
    xmss_adrs_set_tree(&adrs, 0);

    treehash(p, root,
             seeds,           /* SK_SEED */
             seeds + 2*p->n,  /* SEED */
             0, (uint32_t)1 << p->h,
             &adrs);

    /* Serialise PK: OID(4) | root(n) | SEED(n) */
    ull_to_bytes(pk, 4, p->oid);
    memcpy(pk + pk_off_root(p), root, p->n);
    memcpy(pk + pk_off_seed(p), seeds + 2*p->n, p->n);

    /* Serialise SK: OID(4) | idx(idx_bytes) | SK_SEED(n) | SK_PRF(n) | root(n) | SEED(n) */
    ull_to_bytes(sk + sk_off_oid(p),  4,            p->oid);
    ull_to_bytes(sk + sk_off_idx(p),  p->idx_bytes, 0);      /* index starts at 0 */
    memcpy(sk + sk_off_seed(p),     seeds,          p->n);   /* SK_SEED */
    memcpy(sk + sk_off_prf(p),      seeds + p->n,   p->n);   /* SK_PRF  */
    memcpy(sk + sk_off_root(p),     root,            p->n);   /* root    */
    memcpy(sk + sk_off_pub_seed(p), seeds + 2*p->n, p->n);   /* SEED    */

    xmss_memzero(seeds, sizeof(seeds));
    return XMSS_OK;
}

/* ====================================================================
 * xmss_sign() - Algorithm 11
 * ==================================================================== */

int xmss_sign(const xmss_params *p, uint8_t *sig,
              const uint8_t *msg, size_t msglen,
              uint8_t *sk)
{
    uint64_t idx;
    uint8_t  r[XMSS_MAX_N];
    uint8_t  m_hash[XMSS_MAX_N];
    xmss_adrs_t adrs;

    const uint8_t *sk_seed    = sk + sk_off_seed(p);
    const uint8_t *sk_prf     = sk + sk_off_prf(p);
    const uint8_t *root       = sk + sk_off_root(p);
    const uint8_t *pub_seed   = sk + sk_off_pub_seed(p);

    /* Read current index */
    idx = bytes_to_ull(sk + sk_off_idx(p), p->idx_bytes);

    /* Check for index exhaustion */
    if (idx > p->idx_max) {
        return XMSS_ERR_EXHAUSTED;
    }

    /* Increment index in SK immediately (RFC 8391 §4.1.9 note) */
    ull_to_bytes(sk + sk_off_idx(p), p->idx_bytes, idx + 1);

    /* r = PRF(SK_PRF, toByte(idx, 32))
     * RFC 8391 §4.1.8: r is computed using the PRF with the raw index
     * as the 32-byte message input (not via ADRS structure).
     */
    xmss_PRF_idx(p, r, sk_prf, idx);

    /* m_hash = H_msg(r, root, idx, msg) */
    xmss_H_msg(p, m_hash, r, root, idx, msg, msglen);

    /* sig = idx || r || WOTS_sign(m_hash) || auth_path */
    ull_to_bytes(sig, p->idx_bytes, idx);
    memcpy(sig + p->idx_bytes, r, p->n);

    /* WOTS+ signature */
    memset(&adrs, 0, sizeof(adrs));
    xmss_adrs_set_layer(&adrs, 0);
    xmss_adrs_set_tree(&adrs, 0);
    xmss_adrs_set_type(&adrs, XMSS_ADRS_TYPE_OTS);
    xmss_adrs_set_ots(&adrs, (uint32_t)idx);

    wots_sign(p,
              sig + p->idx_bytes + p->n,  /* sig_WOTS */
              m_hash,
              sk_seed, pub_seed, &adrs);

    /* Authentication path */
    memset(&adrs, 0, sizeof(adrs));
    xmss_adrs_set_layer(&adrs, 0);
    xmss_adrs_set_tree(&adrs, 0);

    treehash_auth_path(p,
                       sig + p->idx_bytes + p->n + p->len * p->n,  /* auth */
                       sk_seed, pub_seed,
                       (uint32_t)idx, &adrs);

    return XMSS_OK;
}

/* ====================================================================
 * xmss_verify() - Algorithm 14
 * ==================================================================== */

int xmss_verify(const xmss_params *p,
                const uint8_t *msg, size_t msglen,
                const uint8_t *sig, const uint8_t *pk)
{
    uint64_t idx;
    uint8_t  r[XMSS_MAX_N];
    uint8_t  m_hash[XMSS_MAX_N];
    uint8_t  wots_pk[XMSS_MAX_WOTS_LEN * XMSS_MAX_N];
    uint8_t  leaf[XMSS_MAX_N];
    uint8_t  computed_root[XMSS_MAX_N];
    xmss_adrs_t adrs;

    const uint8_t *pk_root = pk + pk_off_root(p);
    const uint8_t *pk_seed = pk + pk_off_seed(p);
    const uint8_t *sig_wots = sig + p->idx_bytes + p->n;
    const uint8_t *auth     = sig + p->idx_bytes + p->n + p->len * p->n;

    /* Extract index */
    idx = bytes_to_ull(sig, p->idx_bytes);

    /* Sanity check */
    if (idx > p->idx_max) { return XMSS_ERR_VERIFY; }

    /* Extract r */
    memcpy(r, sig + p->idx_bytes, p->n);

    /* m_hash = H_msg(r, root, idx, msg) */
    xmss_H_msg(p, m_hash, r, pk_root, idx, msg, msglen);

    /* Recover WOTS+ public key from signature */
    memset(&adrs, 0, sizeof(adrs));
    xmss_adrs_set_layer(&adrs, 0);
    xmss_adrs_set_tree(&adrs, 0);
    xmss_adrs_set_type(&adrs, XMSS_ADRS_TYPE_OTS);
    xmss_adrs_set_ots(&adrs, (uint32_t)idx);

    wots_pk_from_sig(p, wots_pk, sig_wots, m_hash, pk_seed, &adrs);

    /* Compute leaf from WOTS+ pk via l_tree */
    memset(&adrs, 0, sizeof(adrs));
    xmss_adrs_set_layer(&adrs, 0);
    xmss_adrs_set_tree(&adrs, 0);
    xmss_adrs_set_type(&adrs, XMSS_ADRS_TYPE_LTREE);
    xmss_adrs_set_ltree(&adrs, (uint32_t)idx);

    l_tree(p, leaf, wots_pk, pk_seed, &adrs);

    /* Walk auth path to compute candidate root */
    memset(&adrs, 0, sizeof(adrs));
    xmss_adrs_set_layer(&adrs, 0);
    xmss_adrs_set_tree(&adrs, 0);

    compute_root(p, computed_root, leaf, (uint32_t)idx, auth, pk_seed, &adrs);

    /* Constant-time compare (J6) */
    if (ct_memcmp(computed_root, pk_root, p->n) != 0) {
        return XMSS_ERR_VERIFY;
    }
    return XMSS_OK;
}
