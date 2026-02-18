/**
 * address.h - ADRS typed setters (internal header)
 */
#ifndef XMSS_ADDRESS_H
#define XMSS_ADDRESS_H

#include <stdint.h>
#include "../include/xmss/types.h"

void xmss_adrs_set_layer      (xmss_adrs_t *, uint32_t);
void xmss_adrs_set_tree       (xmss_adrs_t *, uint64_t);
void xmss_adrs_set_type       (xmss_adrs_t *, uint32_t);
void xmss_adrs_set_ots        (xmss_adrs_t *, uint32_t);
void xmss_adrs_set_chain      (xmss_adrs_t *, uint32_t);
void xmss_adrs_set_hash       (xmss_adrs_t *, uint32_t);
void xmss_adrs_set_ltree      (xmss_adrs_t *, uint32_t);
void xmss_adrs_set_tree_height(xmss_adrs_t *, uint32_t);
void xmss_adrs_set_tree_index (xmss_adrs_t *, uint32_t);
void xmss_adrs_set_key_and_mask(xmss_adrs_t *, uint32_t);
void xmss_adrs_to_bytes       (const xmss_adrs_t *, uint8_t out[32]);

#endif /* XMSS_ADDRESS_H */
