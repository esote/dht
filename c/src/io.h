#ifndef DHT_IO_H
#define DHT_IO_H

#include <sys/types.h>
#include <stddef.h>

struct io {
	ssize_t (*read)(void *buf, size_t count, void *ctx);
	ssize_t (*write)(const void *buf, size_t count, void *ctx);
	int (*close)(void *ctx);
	void *ctx;
};

ssize_t io_read(const struct io *io, void *buf, size_t count);
ssize_t io_write(const struct io *io, const void *buf, size_t count);
int io_close(const struct io *io);

ssize_t read2(int fd, void *buf, size_t count);
ssize_t write2(int fd, const void *buf, size_t count);

int copy_n(const struct io *in, const struct io *out, size_t n);

void wrap_fd(struct io *io, int fd);

#endif /* DHT_IO_H */
