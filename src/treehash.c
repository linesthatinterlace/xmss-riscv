/**
 * treehash.c - Merkle treehash and auth path computation
 *
 * RFC 8391 Algorithm 9 (direct iterative treehash).
 * Uses a stack-based iterative algorithm; no recursion (J4).
 * No malloc; stack-only (J3).
 *
 * Phase 1: naive O(h * 2^h) auth path via repeated treehash calls.
 * Phase 7 (future): replace with BDS algorithm.
 */
#include <string.h>
#include <stdint.h>

#include "treehash.h"
#include "wots.h"
#include "ltree.h"
#include "hash/hash_iface.h"
#include "address.h"
#include "utils.h"
#include "../include/xmss/params.h"
#include "../include/xmss/types.h"

/* Internal stack for treehash (no malloc) */
typedef struct {
    uint8_t  node[XMSS_MAX_H + 1][XMSS_MAX_N];
    uint32_t height[XMSS_MAX_H + 1];
    uint32_t top;  /* number of elements currently on stack */
} treehash_stack_t;

static void stack_push(treehash_stack_t *st, const uint8_t *node, uint32_t n, uint32_t height)
{
    memcpy(st->node[st->top], node, n);
    st->height[st->top] = height;
    st->top++;
}

static void stack_pop_two(treehash_stack_t *st, uint8_t *lo, uint8_t *hi,
                          uint32_t *lo_h, uint32_t *hi_h, uint32_t n)
{
    /* pop top two: hi was pushed last, lo before it */
    st->top--;
    memcpy(hi, st->node[st->top], n);
    *hi_h = st->height[st->top];

    st->top--;
    memcpy(lo, st->node[st->top], n);
    *lo_h = st->height[st->top];
}

/* ====================================================================
 * treehash() - Algorithm 9: iterative treehash
 *
 * Iterates over all 2^t leaves from index s to s+2^t-1.
 * For each leaf:
 *   1. Compute leaf via WOTS+ keygen + l_tree.
 *   2. Push onto stack with height 0.
 *   3. While top two stack elements have equal height h:
 *      - Pop them, H-merge, push result with height h+1.
 * Root is the final stack element.
 *
 * t here is the number of leaves (power of 2); height h = log2(t).
 * ==================================================================== */
void treehash(const xmss_params *p, uint8_t *root,
              const uint8_t *sk_seed, const uint8_t *seed,
              uint32_t s, uint32_t t, xmss_adrs_t *adrs)
{
    treehash_stack_t stack;
    uint8_t  wots_pk[XMSS_MAX_WOTS_LEN * XMSS_MAX_N];
    uint8_t  leaf[XMSS_MAX_N];
    uint8_t  lo[XMSS_MAX_N], hi[XMSS_MAX_N];
    uint32_t lo_h, hi_h;
    uint32_t idx;
    xmss_adrs_t a;

    stack.top = 0;

    /* J5: loop over t leaves (t = 2^height, bounded by 2^XMSS_MAX_H) */
    for (idx = s; idx < s + t; idx++) {
        /* Compute leaf = l_tree(WOTS_genPK(SK_SEED, SEED, OTS_ADRS)) */
        a = *adrs;
        xmss_adrs_set_type(&a, XMSS_ADRS_TYPE_OTS);
        xmss_adrs_set_ots(&a, idx);
        wots_gen_pk(p, wots_pk, sk_seed, seed, &a);

        a = *adrs;
        xmss_adrs_set_type(&a, XMSS_ADRS_TYPE_LTREE);
        xmss_adrs_set_ltree(&a, idx);
        l_tree(p, leaf, wots_pk, seed, &a);

        /* Push leaf at height 0 */
        a = *adrs;
        xmss_adrs_set_type(&a, XMSS_ADRS_TYPE_HASH);
        xmss_adrs_set_tree_index(&a, idx);
        stack_push(&stack, leaf, p->n, 0);

        /* Merge while top two have equal height */
        while (stack.top >= 2 &&
               stack.height[stack.top - 2] == stack.height[stack.top - 1]) {
            uint32_t node_height = stack.height[stack.top - 2];

            stack_pop_two(&stack, lo, hi, &lo_h, &hi_h, p->n);
            (void)lo_h; (void)hi_h;

            /* Tree index for merged node at height node_height+1 */
            uint32_t node_idx = (idx - s) >> (node_height + 1);
            a = *adrs;
            xmss_adrs_set_type(&a, XMSS_ADRS_TYPE_HASH);
            xmss_adrs_set_tree_height(&a, node_height);
            xmss_adrs_set_tree_index(&a, (s >> (node_height + 1)) + node_idx);

            xmss_H(p, leaf, seed, &a, lo, hi);
            stack_push(&stack, leaf, p->n, node_height + 1);
        }
    }

    /* Root is the sole element on the stack */
    memcpy(root, stack.node[0], p->n);
}

/* ====================================================================
 * compute_root() - Walk authentication path to compute root
 * ==================================================================== */
void compute_root(const xmss_params *p, uint8_t *root,
                  const uint8_t *leaf, uint32_t leaf_idx,
                  const uint8_t *auth,
                  const uint8_t *seed, xmss_adrs_t *adrs)
{
    uint8_t  buf[XMSS_MAX_N];
    uint8_t  tmp[XMSS_MAX_N];
    uint32_t h;
    xmss_adrs_t a;

    memcpy(buf, leaf, p->n);

    for (h = 0; h < p->h; h++) {
        a = *adrs;
        xmss_adrs_set_type(&a, XMSS_ADRS_TYPE_HASH);
        xmss_adrs_set_tree_height(&a, h);
        xmss_adrs_set_tree_index(&a, leaf_idx >> 1);

        if ((leaf_idx & 1) == 0) {
            /* Current node is left child; auth[h] is right sibling */
            xmss_H(p, tmp, seed, &a, buf, auth + h * p->n);
        } else {
            /* Current node is right child; auth[h] is left sibling */
            xmss_H(p, tmp, seed, &a, auth + h * p->n, buf);
        }
        memcpy(buf, tmp, p->n);
        leaf_idx >>= 1;
    }

    memcpy(root, buf, p->n);
}

/* ====================================================================
 * treehash_auth_path() - Naive auth path computation
 *
 * For level i (0 to h-1):
 *   sibling_idx = floor(leaf_idx / 2^i) XOR 1
 *   Compute the subtree of 2^i leaves starting at sibling_idx * 2^i.
 *   auth[i] = root of that subtree.
 * ==================================================================== */
void treehash_auth_path(const xmss_params *p, uint8_t *auth,
                        const uint8_t *sk_seed, const uint8_t *seed,
                        uint32_t idx, xmss_adrs_t *adrs)
{
    uint32_t h;

    for (h = 0; h < p->h; h++) {
        /* Sibling node index at level h */
        uint32_t sibling = ((idx >> h) ^ 1) << h;
        uint32_t subtree_size = (uint32_t)1 << h; /* 2^h leaves */
        xmss_adrs_t a = *adrs;

        if (h == 0) {
            /* At leaf level: compute a single leaf directly */
            uint8_t  wots_pk[XMSS_MAX_WOTS_LEN * XMSS_MAX_N];
            xmss_adrs_set_type(&a, XMSS_ADRS_TYPE_OTS);
            xmss_adrs_set_ots(&a, sibling);
            wots_gen_pk(p, wots_pk, sk_seed, seed, &a);

            a = *adrs;
            xmss_adrs_set_type(&a, XMSS_ADRS_TYPE_LTREE);
            xmss_adrs_set_ltree(&a, sibling);
            l_tree(p, auth + h * p->n, wots_pk, seed, &a);
        } else {
            /* Compute a subtree of height h with 2^h leaves */
            treehash(p, auth + h * p->n,
                     sk_seed, seed,
                     sibling, subtree_size, &a);
        }
    }
}
