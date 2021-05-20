#include <sys/types.h>
#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

#include "io.h"
#include "util.h"

#define BUFFER_SIZE 16384

static ssize_t wrap_read(void *buf, size_t count, void *ctx);
static ssize_t wrap_write(const void *buf, size_t count, void *ctx);
static int wrap_close(void *ctx);

ssize_t
io_read(const struct io *io, void *buf, size_t count)
{
	if (io->read == NULL) {
		return -1;
	}
	return io->read(buf, count, io->ctx);
}

ssize_t
io_write(const struct io *io, const void *buf, size_t count)
{
	if (io->write == NULL) {
		return -1;
	}
	return io->write(buf, count, io->ctx);
}

int
io_close(const struct io *io)
{
	if (io->close == NULL) {
		return -1;
	}
	return io->close(io->ctx);
}

ssize_t
read2(int fd, void *buf, size_t count)
{
	uint8_t *bbuf;
	ssize_t offset;
	ssize_t nn;
	struct pollfd pfd;

	bbuf = buf;
	offset = 0;
	pfd.fd = fd;
	pfd.events = POLLIN;
	if (count > SSIZE_MAX) { /* TODO: assign to ssize_t variable */
		count = SSIZE_MAX;
	}

	while (count > offset) {
		nn = read(fd, bbuf + offset, count - (size_t)offset);
		switch (nn) {
		case -1:
			if (errno == EINTR) {
				errno = 0;
				continue;
			} else if (errno == EAGAIN || errno == EWOULDBLOCK) {
				(void)poll(&pfd, 1, -1);
				errno = 0;
				continue;
			}
			/* data may have been read, but shouldn't be trusted */
			return -1;
		case 0:
			return offset;
		default:
			offset += nn;
		}
	}
	return offset;
}

ssize_t
write2(int fd, const void *buf, size_t count)
{
	const uint8_t *bbuf;
	ssize_t offset;
	ssize_t nn;
	struct pollfd pfd;

	bbuf = buf;
	offset = 0;
	pfd.fd = fd;
	pfd.events = POLLOUT;
	if (count > SSIZE_MAX) { /* TODO: assign to ssize_t variable */
		count = SSIZE_MAX;
	}

	while (count > offset) {
		nn = write(fd, bbuf + offset, count - (size_t)offset);
		switch (nn) {
		case -1:
			if (errno == EINTR) {
				errno = 0;
				continue;
			} else if (errno == EAGAIN || errno == EWOULDBLOCK) {
				(void)poll(&pfd, 1, -1);
				errno = 0;
				continue;
			}
			/* data may have been written, but shouldn't be trusted */
			return -1;
		case 0:
			return offset;
		default:
			offset += nn;
		}
	}
	return offset;
}

int
copy_n(const struct io *in, const struct io *out, size_t n)
{
	size_t off;
	ssize_t r, w;
	uint8_t buf[BUFFER_SIZE];
	w = 0;
	while (n != 0 && (r = io_read(in, buf, min(n, BUFFER_SIZE))) != -1 && r != 0) {
		for (off = 0; r != 0; r -= w, off += (size_t)w) {
			if ((w = io_write(out, buf+off, (size_t)r)) == 0 || w == -1) {
				return -1;
			}
		}
		n -= off;
	}
	if (r == -1) {
		return -1;
	}
	return 0;
}

void
wrap_fd(struct io *io, int fd)
{
	io->read = wrap_read;
	io->write = wrap_write;
	io->close = wrap_close;
	io->ctx = &fd;
}

static ssize_t
wrap_read(void *buf, size_t count, void *ctx)
{
	int *fd = ctx;
	return read2(*fd, buf, count);
}

static ssize_t
wrap_write(const void *buf, size_t count, void *ctx)
{
	int *fd = ctx;
	return write2(*fd, buf, count);
}

static int
wrap_close(void *ctx)
{
	int *fd = ctx;
	return close(*fd);
}
