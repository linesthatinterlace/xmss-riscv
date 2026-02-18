/**
 * hash_iface.h - XMSS hash function interface (internal)
 *
 * This is the SOLE location of hash backend dispatch.
 * All algorithm code calls only the five functions declared here.
 * No algorithm file includes sha2_local.h or shake_local.h directly.
 *
 * JASMIN: when porting, replace xmss_hash.c with a parameter-set-specific
 * .jazz file. No other files change.  Mark dispatch points with:
 *   "JASMIN: replace with direct call" in comments.
 */
#ifndef XMSS_HASH_IFACE_H
#define XMSS_HASH_IFACE_H

#include <stddef.h>
#include <stdint.h>
#include "../../include/xmss/params.h"
#include "../../include/xmss/types.h"

/**
 * xmss_F() - WOTS+ chaining function (RFC 8391 §4.1.2)
 *
 * F(KEY, M) = H(toByte(0, pad_len) || KEY || ADRS || M)
 * where KEY and M are each n bytes.
 *
 * @p:    Parameter set.
 * @out:  Output (n bytes).
 * @key:  n-byte key (SEED in WOTS+ context).
 * @adrs: Address (sets type=OTS, key_and_mask=0/1).
 * @in:   n-byte input.
 */
int xmss_F(const xmss_params *p, uint8_t *out,
           const uint8_t *key, const xmss_adrs_t *adrs,
           const uint8_t *in);

/**
 * xmss_H() - Tree hash function (RFC 8391 §4.1.2)
 *
 * H(KEY, M) where M = M_l || M_r (each n bytes).
 *
 * @p:     Parameter set.
 * @out:   Output (n bytes).
 * @key:   n-byte key (SEED).
 * @adrs:  Address.
 * @in_l:  Left n-byte input.
 * @in_r:  Right n-byte input.
 */
int xmss_H(const xmss_params *p, uint8_t *out,
           const uint8_t *key, const xmss_adrs_t *adrs,
           const uint8_t *in_l, const uint8_t *in_r);

/**
 * xmss_H_msg() - Message hash function (RFC 8391 §4.1.2)
 *
 * H_msg(KEY, M) where KEY = r || root || toByte(idx, 32).
 * Message M has arbitrary length.
 *
 * @p:      Parameter set.
 * @out:    Output (n bytes).
 * @r:      n-byte random value.
 * @root:   n-byte tree root.
 * @idx:    Leaf index.
 * @msg:    Message bytes.
 * @msglen: Message length.
 */
int xmss_H_msg(const xmss_params *p, uint8_t *out,
               const uint8_t *r, const uint8_t *root, uint64_t idx,
               const uint8_t *msg, size_t msglen);

/**
 * xmss_PRF() - Pseudorandom function (RFC 8391 §4.1.2)
 *
 * PRF(KEY, M) = H(toByte(3, pad_len) || KEY || ADRS)
 * where KEY is n bytes (SK_PRF) and ADRS determines the output.
 *
 * @p:    Parameter set.
 * @out:  Output (n bytes).
 * @key:  n-byte secret key SK_PRF.
 * @adrs: Address structure.
 */
int xmss_PRF(const xmss_params *p, uint8_t *out,
             const uint8_t *key, const xmss_adrs_t *adrs);

/**
 * xmss_PRF_keygen() - Key generation PRF (RFC 8391 §4.1.11)
 *
 * PRF_keygen(SK_SEED, PUB_SEED, ADRS) =
 *   H(toByte(4, n) || SK_SEED || PUB_SEED || ADRS)
 *
 * @p:        Parameter set.
 * @out:      Output (n bytes).
 * @sk_seed:  n-byte secret seed SK_SEED.
 * @pub_seed: n-byte public seed PUB_SEED.
 * @adrs:     Address structure.
 */
int xmss_PRF_keygen(const xmss_params *p, uint8_t *out,
                    const uint8_t *sk_seed, const uint8_t *pub_seed,
                    const xmss_adrs_t *adrs);

/**
 * xmss_PRF_idx() - PRF with index as 32-byte message (RFC 8391 §4.1.9)
 *
 * Used in signing to compute r = PRF(SK_PRF, toByte(idx, 32)).
 * This differs from xmss_PRF() in that the 32-byte M is an index encoding,
 * not an ADRS structure.
 *
 * @p:      Parameter set.
 * @out:    Output (n bytes).
 * @sk_prf: n-byte SK_PRF key.
 * @idx:    Leaf index.
 */
int xmss_PRF_idx(const xmss_params *p, uint8_t *out,
                 const uint8_t *sk_prf, uint64_t idx);

#endif /* XMSS_HASH_IFACE_H */
