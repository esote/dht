#include <sys/types.h>
#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

#include "dht_internal.h"
#include "io.h"
#include "util.h"

#define BUFFER_SIZE 16384

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
copy_n(int in, int out, size_t n)
{
	size_t off;
	ssize_t r, w;
	uint8_t buf[BUFFER_SIZE];
	w = 0;
	while ((r = read2(in, buf, min(n, BUFFER_SIZE))) != -1 && r != 0) {
		for (off = 0; r != 0; r -= w, off += (size_t)w) {
			if ((w = write2(out, buf+off, (size_t)r)) == 0 || w == -1) {
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
