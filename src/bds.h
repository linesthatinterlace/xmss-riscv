/**
 * bds.h - BDS tree traversal internal API
 *
 * BDS (Buchmann-Dahmen-Szydlo) amortises auth path computation.
 * During keygen it captures the initial auth path plus treehash instances
 * that incrementally compute future auth nodes.  Each subsequent sign
 * does O(h) leaf computations instead of O(h * 2^h).
 */
#ifndef XMSS_BDS_H
#define XMSS_BDS_H

#include <stdint.h>
#include "../include/xmss/params.h"
#include "../include/xmss/types.h"

/**
 * bds_treehash_init() - Build the full Merkle tree while capturing BDS state.
 *
 * This is the modified treehash (Algorithm 9) used during keygen.
 * It computes the root and populates state->auth, state->treehash[].node,
 * and state->retain for the initial auth path at leaf 0.
 *
 * @p:       Parameter set.
 * @root:    Output n-byte tree root.
 * @state:   BDS state to initialise (from xmss.h).
 * @bds_k:   Retain parameter (even, 0 <= bds_k <= h).
 * @sk_seed: n-byte secret seed.
 * @seed:    n-byte public seed.
 * @adrs:    Hash tree address (layer/tree set by caller).
 */
struct xmss_bds_state;  /* forward declaration */

void bds_treehash_init(const xmss_params *p, uint8_t *root,
                       struct xmss_bds_state *state, uint32_t bds_k,
                       const uint8_t *sk_seed, const uint8_t *seed,
                       xmss_adrs_t *adrs);

/**
 * bds_round() - Update auth path after signing leaf leaf_idx.
 *
 * Must be called after each signature with the leaf index that was just used.
 * Updates state->auth to contain the auth path for leaf (leaf_idx + 1).
 *
 * @p:        Parameter set.
 * @state:    BDS state.
 * @bds_k:    Retain parameter.
 * @leaf_idx: Leaf index that was just signed (the NEXT leaf's auth path is computed).
 * @sk_seed:  n-byte secret seed.
 * @seed:     n-byte public seed.
 * @adrs:     Hash tree address.
 */
void bds_round(const xmss_params *p, struct xmss_bds_state *state,
               uint32_t bds_k, uint32_t leaf_idx,
               const uint8_t *sk_seed, const uint8_t *seed,
               xmss_adrs_t *adrs);

/**
 * bds_treehash_update() - Run incremental treehash updates.
 *
 * Runs up to 'updates' leaf computations on the most-needed treehash
 * instance.  Call after bds_round() each signature.
 *
 * @p:       Parameter set.
 * @state:   BDS state.
 * @bds_k:   Retain parameter.
 * @updates: Number of treehash updates (leaf computations) to run.
 * @sk_seed: n-byte secret seed.
 * @seed:    n-byte public seed.
 * @adrs:    Hash tree address.
 */
void bds_treehash_update(const xmss_params *p, struct xmss_bds_state *state,
                         uint32_t bds_k, uint32_t updates,
                         const uint8_t *sk_seed, const uint8_t *seed,
                         xmss_adrs_t *adrs);

#endif /* XMSS_BDS_H */
