/**
 * types.h - XMSS fundamental types
 *
 * RFC 8391 §2.5: ADRS is a 32-byte array of 8 big-endian 32-bit words.
 */
#ifndef XMSS_TYPES_H
#define XMSS_TYPES_H

#include <stdint.h>

/* ADRS: 32-byte address structure, stored as 8 big-endian 32-bit words.
 * Always manipulated via the typed setters in address.h; never accessed
 * directly by algorithm code.
 */
typedef struct {
    uint32_t w[8];
} xmss_adrs_t;

/* ADRS type constants (RFC 8391 §2.5) */
#define XMSS_ADRS_TYPE_OTS   0
#define XMSS_ADRS_TYPE_LTREE 1
#define XMSS_ADRS_TYPE_HASH  2

/* ADRS word indices */
#define XMSS_ADRS_W_LAYER  0
#define XMSS_ADRS_W_TREE_H 1  /* high 32 bits of 64-bit tree address */
#define XMSS_ADRS_W_TREE_L 2  /* low  32 bits of 64-bit tree address */
#define XMSS_ADRS_W_TYPE   3
/* Words 4-7 are type-specific; set_type() zeros them */

#endif /* XMSS_TYPES_H */
