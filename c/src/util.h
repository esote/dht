#ifndef DHT_UTIL_H
#define DHT_UTIL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <syslog.h>

#define dht_log(priority, format, ...) syslog((priority), "%s:%s:%d [%d] " format, __FILE__, __func__, __LINE__, getpid(), ## __VA_ARGS__)

size_t min(size_t x, size_t y);
char *strdup(const char *str);
char *join_path_file(const char *path, const char *file);
void bin2hex(char *const hex, const size_t hex_maxlen, const void *bin,
	const size_t bin_len);
int hex2bin(void *const bin, const size_t bin_maxlen, const char *const hex,
	const size_t hex_len);
bool string_empty(const char *s);

#endif /* DHT_UTIL_H */
