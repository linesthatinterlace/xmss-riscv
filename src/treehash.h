/**
 * treehash.h - Treehash internal API
 */
#ifndef XMSS_TREEHASH_H
#define XMSS_TREEHASH_H

#include <stdint.h>
#include "../include/xmss/params.h"
#include "../include/xmss/types.h"

/**
 * treehash() - Algorithm 9 (RFC 8391): Compute the root of a Merkle tree.
 *
 * Direct (naive) implementation: computes the full tree iteratively.
 * Uses a stack of height XMSS_MAX_H nodes to merge subtrees.
 *
 * @p:       Parameter set.
 * @root:    Output n-byte tree root.
 * @sk_seed: n-byte secret seed.
 * @seed:    n-byte public seed.
 * @s:       Starting leaf index (0 for full tree root).
 * @t:       Number of leaves (2^h for the full tree at height h).
 * @adrs:    Hash tree address (layer and tree fields must be set by caller).
 */
void treehash(const xmss_params *p, uint8_t *root,
              const uint8_t *sk_seed, const uint8_t *seed,
              uint32_t s, uint32_t t, xmss_adrs_t *adrs);

/**
 * compute_root() - Compute the tree root from a leaf and authentication path.
 *
 * Used by xmss_verify() to walk up the tree from a leaf.
 *
 * @p:         Parameter set.
 * @root:      Output n-byte root.
 * @leaf:      n-byte leaf value (l_tree output of recovered WOTS+ pk).
 * @leaf_idx:  Index of this leaf in the tree.
 * @auth:      Authentication path (h * n bytes).
 * @seed:      n-byte public seed.
 * @adrs:      Hash tree address.
 */
void compute_root(const xmss_params *p, uint8_t *root,
                  const uint8_t *leaf, uint32_t leaf_idx,
                  const uint8_t *auth,
                  const uint8_t *seed, xmss_adrs_t *adrs);

#ifdef XMSS_NAIVE_AUTH_PATH
/**
 * treehash_auth_path() - Compute auth path for leaf at index idx.
 *
 * Naive O(h * 2^h) implementation.
 * For each level i, computes the sibling node of the node on the
 * path from leaf idx to the root.
 *
 * @p:       Parameter set.
 * @auth:    Output authentication path (h * n bytes).
 * @sk_seed: n-byte secret seed.
 * @seed:    n-byte public seed.
 * @idx:     Leaf index.
 * @adrs:    Hash tree address.
 */
void treehash_auth_path(const xmss_params *p, uint8_t *auth,
                        const uint8_t *sk_seed, const uint8_t *seed,
                        uint32_t idx, xmss_adrs_t *adrs);
#endif /* XMSS_NAIVE_AUTH_PATH */

#endif /* XMSS_TREEHASH_H */
