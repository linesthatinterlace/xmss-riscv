/**
 * wots.h - WOTS+ internal API
 *
 * RFC 8391 §4.1.2: WOTS+ one-time signature scheme.
 */
#ifndef XMSS_WOTS_H
#define XMSS_WOTS_H

#include <stdint.h>
#include "../include/xmss/params.h"
#include "../include/xmss/types.h"

/**
 * wots_gen_pk() - Generate a WOTS+ public key (RFC 8391 Alg 4).
 *
 * @p:       Parameter set.
 * @pk:      Output: len*n bytes (public key).
 * @sk_seed: n-byte secret seed.
 * @seed:    n-byte public seed (SEED).
 * @adrs:    Address (type=OTS, OTS address must be set by caller).
 */
void wots_gen_pk(const xmss_params *p, uint8_t *pk,
                 const uint8_t *sk_seed, const uint8_t *seed,
                 xmss_adrs_t *adrs);

/**
 * wots_sign() - Generate a WOTS+ signature (RFC 8391 Alg 5).
 *
 * @p:       Parameter set.
 * @sig:     Output: len*n bytes (signature).
 * @msg:     n-byte message hash.
 * @sk_seed: n-byte secret seed.
 * @seed:    n-byte public seed.
 * @adrs:    Address (type=OTS, OTS address must be set by caller).
 */
void wots_sign(const xmss_params *p, uint8_t *sig,
               const uint8_t *msg,
               const uint8_t *sk_seed, const uint8_t *seed,
               xmss_adrs_t *adrs);

/**
 * wots_pk_from_sig() - Recover WOTS+ public key from signature (RFC 8391 Alg 6).
 *
 * @p:    Parameter set.
 * @pk:   Output: len*n bytes (recovered public key).
 * @sig:  len*n byte signature.
 * @msg:  n-byte message hash.
 * @seed: n-byte public seed.
 * @adrs: Address (type=OTS, OTS address must be set by caller).
 */
void wots_pk_from_sig(const xmss_params *p, uint8_t *pk,
                      const uint8_t *sig, const uint8_t *msg,
                      const uint8_t *seed, xmss_adrs_t *adrs);

#endif /* XMSS_WOTS_H */
