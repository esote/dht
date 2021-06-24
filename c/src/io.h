#ifndef DHT_IO_H
#define DHT_IO_H

#include <sys/types.h>
#include <stddef.h>

ssize_t read2(int fd, void *buf, size_t count);
ssize_t write2(int fd, const void *buf, size_t count);

int copy_n(int in, int out, size_t n);

#endif /* DHT_IO_H */
