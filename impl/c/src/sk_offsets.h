/**
 * sk_offsets.h - SK / PK field offset helpers (internal header)
 *
 * Shared between xmss.c and xmss_mt.c.  The SK/PK byte layout is identical
 * for both XMSS and XMSS-MT (only idx_bytes differs):
 *
 *   SK: OID(4) | idx(idx_bytes) | SK_SEED(n) | SK_PRF(n) | root(n) | SEED(n)
 *   PK: OID(4) | root(n) | SEED(n)
 */
#ifndef XMSS_SK_OFFSETS_H
#define XMSS_SK_OFFSETS_H

#include <stdint.h>
#include "../include/xmss/params.h"

/* SK offsets */
static inline uint32_t sk_off_oid (const xmss_params *p) { (void)p; return 0; }
static inline uint32_t sk_off_idx (const xmss_params *p) { (void)p; return 4; }
static inline uint32_t sk_off_seed(const xmss_params *p) { return 4 + p->idx_bytes; }
static inline uint32_t sk_off_prf (const xmss_params *p) { return 4 + p->idx_bytes + p->n; }
static inline uint32_t sk_off_root(const xmss_params *p) { return 4 + p->idx_bytes + 2*p->n; }
static inline uint32_t sk_off_pub_seed(const xmss_params *p) { return 4 + p->idx_bytes + 3*p->n; }

/* PK offsets */
static inline uint32_t pk_off_root(const xmss_params *p) { (void)p; return 4; }
static inline uint32_t pk_off_seed(const xmss_params *p) { return 4 + p->n; }

#endif /* XMSS_SK_OFFSETS_H */
