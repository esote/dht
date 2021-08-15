#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>

#include "io.h"

ssize_t
read2(int fd, void *buf, size_t count)
{
	uint8_t *b = buf;
	size_t off = 0;

	if (count > SSIZE_MAX) {
		return -1;
	}

	while (count > off) {
		ssize_t r = read(fd, b + off, count - off);
		switch (r) {
		case -1:
			if (errno == EINTR) {
				errno = 0;
				continue;
			}
			return -1;
		case 0:
			return (ssize_t)off;
		default:
			off += (size_t)r;
		}
	}

	return (ssize_t)off;
}

ssize_t
write2(int fd, const void *buf, size_t count)
{
	const uint8_t *b = buf;
	size_t off = 0;

	if (count > SSIZE_MAX) {
		return -1;
	}

	while (count > off) {
		ssize_t r = write(fd, b + off, count - off);
		switch (r) {
		case -1:
			if (errno == EINTR) {
				errno = 0;
				continue;
			}
			return -1;
		case 0:
			return (ssize_t)off;
		default:
			off += (size_t)r;
		}
	}

	return (ssize_t)off;
}

ssize_t
sendmsg2(int fd, const struct msghdr *msg, int flags)
{
	size_t total = 0, iov = 0;
	struct msghdr tmp = *msg;

	while (tmp.msg_iovlen > iov) {
		ssize_t w = sendmsg(fd, &tmp, flags);
		switch (w) {
		case -1:
			if (errno == EINTR) {
				errno = 0;
				continue;
			}
			return -1;
		case 0:
			return (ssize_t)total;
		default:
			if (SSIZE_MAX - total < w) {
				/* overflow */
				return -1;
			}
			total += (size_t)w;

			for (; iov < tmp.msg_iovlen && w > tmp.msg_iov[iov].iov_len; iov++) {
				w -= (ssize_t)tmp.msg_iov[iov].iov_len;
			}
			if (iov == tmp.msg_iovlen) {
				/* no more iovecs to send */
				return (ssize_t)total;
			}

			/* ancillary data sent with the first octet */
			tmp.msg_control = NULL;
			tmp.msg_controllen = 0;

			tmp.msg_iov[iov].iov_base = (uint8_t *)tmp.msg_iov[iov].iov_base + w;
			tmp.msg_iov[iov].iov_len -= (size_t)w;
		}
	}

	return (ssize_t)total;
}
