/**
 * utils.h - XMSS utility functions (internal header)
 */
#ifndef XMSS_UTILS_H
#define XMSS_UTILS_H

#include <stddef.h>
#include <stdint.h>

void     ull_to_bytes(uint8_t *out, uint32_t len, uint64_t val);
uint64_t bytes_to_ull(const uint8_t *in, uint32_t len);
void     xmss_memzero(void *ptr, size_t len);
int      ct_memcmp(const uint8_t *a, const uint8_t *b, size_t len);

#endif /* XMSS_UTILS_H */
