/**
 * ltree.h - L-tree internal API
 */
#ifndef XMSS_LTREE_H
#define XMSS_LTREE_H

#include <stdint.h>
#include "../include/xmss/params.h"
#include "../include/xmss/types.h"

/**
 * l_tree() - Algorithm 7: Compute an L-tree root from a WOTS+ public key.
 *
 * Iteratively reduces len WOTS+ key elements to a single n-byte node
 * using the H function, handling odd-length layers.
 *
 * @p:    Parameter set.
 * @root: Output n-byte root.
 * @pk:   WOTS+ public key (len * n bytes); modified in place.
 * @seed: n-byte public seed.
 * @adrs: L-tree address (type must be set to XMSS_ADRS_TYPE_LTREE).
 */
void l_tree(const xmss_params *p, uint8_t *root, uint8_t *pk,
            const uint8_t *seed, xmss_adrs_t *adrs);

#endif /* XMSS_LTREE_H */
