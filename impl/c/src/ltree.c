/**
 * ltree.c - L-tree (Algorithm 7, RFC 8391)
 *
 * Reduces a WOTS+ public key (len elements of n bytes) to a single
 * n-byte value using the H hash function.  Handles odd-length layers
 * by passing the odd element up unchanged.
 *
 * J4: Iterative (no recursion).
 * J3: No malloc; pk buffer is used in place.
 */
#include <string.h>
#include <stdint.h>

#include "ltree.h"
#include "hash/hash_iface.h"
#include "address.h"
#include "../include/xmss/params.h"
#include "../include/xmss/types.h"

void l_tree(const xmss_params *p, uint8_t *root, uint8_t *pk,
            const uint8_t *seed, xmss_adrs_t *adrs)
{
    uint32_t len   = p->len;
    uint32_t height = 0;
    uint32_t i;
    uint8_t  tmp[XMSS_MAX_N];

    /*
     * RFC 8391 Alg 7:
     *   while len > 1:
     *     for i in 0..floor(len/2)-1:
     *       ADRS.setTreeHeight(height)
     *       ADRS.setTreeIndex(i)
     *       pk[i] = H(SEED, ADRS, pk[2i] || pk[2i+1])
     *     if len is odd:
     *       pk[floor(len/2)] = pk[len-1]
     *     len = ceil(len / 2)
     *     height++
     */
    while (len > 1) {
        uint32_t half = len / 2;

        xmss_adrs_set_tree_height(adrs, height);

        for (i = 0; i < half; i++) {
            xmss_adrs_set_tree_index(adrs, i);
            xmss_H(p, tmp,
                   seed, adrs,
                   pk + (2*i)     * p->n,
                   pk + (2*i + 1) * p->n);
            memcpy(pk + i * p->n, tmp, p->n);
        }

        /* If len is odd, copy the last element up */
        if (len & 1) {
            memcpy(pk + half * p->n, pk + (len - 1) * p->n, p->n);
        }

        len    = (len + 1) / 2;
        height++;
    }

    memcpy(root, pk, p->n);
}
