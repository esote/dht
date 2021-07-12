#ifndef DHT_UTIL_H
#define DHT_UTIL_H

#include <stddef.h>
#include <stdint.h>
#include <syslog.h>

#define dht_log(priority, format, ...) syslog((priority), "%s:%s:%d [%d] " format, __FILE__, __func__, __LINE__, getpid(), ## __VA_ARGS__)

size_t min(size_t x, size_t y);
char *strdup(const char *str);
char *join_path_file(const char *path, const char *file);
size_t base64_url_nopad_len(size_t len);
void base64_url_nopad(void *d, const void *s, size_t len);

#endif /* DHT_UTIL_H */
