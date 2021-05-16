#ifndef DHT_BSWAP_H
#define DHT_BSWAP_H

#include <stdint.h>

void hton_16(void *dst, uint16_t x);
void hton_32(void *dst, uint32_t x);
void hton_64(void *dst, uint64_t x);
uint16_t ntoh_16(const void *src);
uint32_t ntoh_32(const void *src);
uint64_t ntoh_64(const void *src);

size_t lcp(const uint8_t *x, const uint8_t *y, size_t len);

#endif /* DHT_BSWAP_H */
