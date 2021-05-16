#ifndef UTIL_H
#define UTIL_H

#include <pthread.h>
#include <stddef.h>

char *strdup(const char *str);
char *join_path_file(const char *path, const char *file);
size_t base64_url_nopad_len(size_t len);
void base64_url_nopad(void *d, const void *s, size_t len);
ssize_t read_full(int fd, void *buf, size_t buflen);
ssize_t write_full(int fd, void *buf, size_t buflen);
int copy(int out, int in, size_t n);

#endif /* UTIL_H */
