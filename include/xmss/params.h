/**
 * params.h - XMSS parameter sets and OID table
 *
 * RFC 8391 §5.3 and Appendix B (all 12 XMSS parameter sets).
 */
#ifndef XMSS_PARAMS_H
#define XMSS_PARAMS_H

#include <stdint.h>

/* Maximums for static buffer sizing (Jasmin Rule J1: no VLAs) */
#define XMSS_MAX_N        64U
#define XMSS_MAX_H        20U
/* WOTS+ len for n=64, w=16 (RFC 8391 standard sets):
 *   len1 = ceil(8*64/log2(16)) = ceil(512/4) = 128
 *   len2 = floor(log2(128*15)/4) + 1 = floor(10.9/4) + 1 = 3
 *   len  = 131
 */
#define XMSS_MAX_WOTS_LEN 131U
#define XMSS_MAX_BDS_K    4U   /* max BDS retain parameter (must be even, ≤ XMSS_MAX_H) */

/* Hash function identifiers */
#define XMSS_FUNC_SHA2    0
#define XMSS_FUNC_SHAKE128 1
#define XMSS_FUNC_SHAKE256 2

/**
 * xmss_params - all derived parameters for one XMSS instance.
 *
 * Fields are derived from (n, w, h, func) by xmss_params_from_oid().
 * Never modify fields directly; treat as read-only after initialisation.
 *
 * The field d is always 1 for XMSS; present for XMSS-MT generalisation.
 */
typedef struct {
    uint32_t oid;
    uint8_t  func;        /* XMSS_FUNC_* */
    uint32_t n;           /* hash output / private key element size in bytes */
    uint32_t w;           /* Winternitz parameter (4 or 16) */
    uint32_t log2_w;      /* log2(w): 2 for w=4, 4 for w=16 */
    uint32_t len1;        /* ceil(8*n / log2(w)) */
    uint32_t len2;        /* floor(log2(len1*(w-1)) / log2(w)) + 1 */
    uint32_t len;         /* len1 + len2 */
    uint32_t h;           /* tree height */
    uint32_t d;           /* number of layers (always 1 for XMSS) */
    uint32_t pad_len;     /* PRF padding length (n for standard; 4 for n=24) */
    uint32_t idx_bytes;   /* ceil(h/8) - bytes to encode leaf index */
    uint64_t idx_max;     /* 2^h - 1 - maximum leaf index */
    uint32_t sig_bytes;   /* total signature bytes */
    uint32_t pk_bytes;    /* total public key bytes */
    uint32_t sk_bytes;    /* total secret key bytes */
} xmss_params;

/**
 * xmss_params_from_oid() - populate params from a numeric OID.
 *
 * Returns 0 on success, -1 if OID is not recognised.
 * All 12 RFC 8391 XMSS OIDs are supported.
 */
int xmss_params_from_oid(xmss_params *p, uint32_t oid);

/**
 * xmss_params_from_name() - populate params from a name string.
 *
 * Name format: "XMSS-SHA2_10_256", "XMSS-SHAKE_10_256", etc.
 * Returns 0 on success, -1 if name is not recognised.
 */
int xmss_params_from_name(xmss_params *p, const char *name);

/* RFC 8391 Appendix A OID values */
#define OID_XMSS_SHA2_10_256   0x00000001U
#define OID_XMSS_SHA2_16_256   0x00000002U
#define OID_XMSS_SHA2_20_256   0x00000003U
#define OID_XMSS_SHA2_10_512   0x00000004U
#define OID_XMSS_SHA2_16_512   0x00000005U
#define OID_XMSS_SHA2_20_512   0x00000006U
#define OID_XMSS_SHAKE_10_256  0x00000007U
#define OID_XMSS_SHAKE_16_256  0x00000008U
#define OID_XMSS_SHAKE_20_256  0x00000009U
#define OID_XMSS_SHAKE_10_512  0x0000000AU
#define OID_XMSS_SHAKE_16_512  0x0000000BU
#define OID_XMSS_SHAKE_20_512  0x0000000CU

#endif /* XMSS_PARAMS_H */
