#pragma once

#include <stdbool.h>
#include <stddef.h>

size_t min(size_t x, size_t y);

ssize_t read2(int fd, void *buf, size_t count);
ssize_t write2(int fd, const void *buf, size_t count);

int copy_n(int out, int in, size_t n);

void hton_16(void *dst, uint16_t x);
void hton_32(void *dst, uint32_t x);
void hton_64(void *dst, uint64_t x);
uint16_t ntoh_16(const void *src);
uint32_t ntoh_32(const void *src);
uint64_t ntoh_64(const void *src);

size_t leading_zeros(const uint8_t *b, size_t len);
void memxor(uint8_t *dst, const uint8_t *a, const uint8_t *b, size_t len);
bool is_zero(const void *src, size_t len);
