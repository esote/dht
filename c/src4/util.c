#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "dhtd.h"
#include "util.h"

#ifdef CLOCK_MONOTONIC_COARSE
#define gettime_mono(tp) clock_gettime(CLOCK_MONOTONIC_COARSE, (tp))
#else
#define gettime_mono(tp) clock_gettime(CLOCK_MONOTONIC, (tp))
#endif

#define BUFFER_SIZE (4 * 4096)

#define	timespeccmp(tsp, usp, cmp)					\
	(((tsp)->tv_sec == (usp)->tv_sec) ?				\
		((tsp)->tv_nsec cmp (usp)->tv_nsec) :			\
		((tsp)->tv_sec cmp (usp)->tv_sec))

#define	timespecsub(tsp, usp, vsp)					\
	do {								\
		(vsp)->tv_sec = (tsp)->tv_sec - (usp)->tv_sec;		\
		(vsp)->tv_nsec = (tsp)->tv_nsec - (usp)->tv_nsec;	\
		if ((vsp)->tv_nsec < 0) {				\
			(vsp)->tv_sec--;				\
			(vsp)->tv_nsec += 1000000000L;			\
		}							\
	} while (0)

static uint16_t bswap_16(uint16_t x);
static uint32_t bswap_32(uint32_t x);
static uint64_t bswap_64(uint64_t x);
static uint16_t hton_16b(uint16_t x);
static uint16_t ntoh_16b(uint16_t x);
static uint32_t hton_32b(uint32_t x);
static uint32_t ntoh_32b(uint32_t x);
static uint64_t hton_64b(uint64_t x);
static uint64_t ntoh_64b(uint64_t x);

static size_t leading_zeros8(uint8_t b);

size_t
min(size_t x, size_t y)
{
	if (x < y) {
		return x;
	}
	return y;
}

ssize_t
read2(int fd, void *buf, size_t count)
{
	uint8_t *bbuf;
	ssize_t offset;
	ssize_t nn;
	struct pollfd pfd;
	struct timespec start, now;
	static const struct timespec read_full_timeout = {
		.tv_sec = READ_FULL_TIMEOUT_SEC,
		.tv_nsec = READ_FULL_TIMEOUT_NSEC,
	};

	bbuf = buf;
	offset = 0;
	pfd.fd = fd;
	pfd.events = POLLIN;

	if (count > SSIZE_MAX) {
		count = SSIZE_MAX;
	}

	if (gettime_mono(&start) == -1) {
		return -1;
	}

	while (count > offset) {
		if (gettime_mono(&now) == -1) {
			return -1;
		}
		timespecsub(&now, &start, &now);
		if (timespeccmp(&now, &read_full_timeout, >)) {
			return -1;
		}

		switch (poll(&pfd, 1, READ_POLL_TIMEOUT)) {
		case -1:
			if (errno == EAGAIN || errno == EINTR) {
				errno = 0;
				continue;
			}
			return -1;
		case 0:
			return -1;
		}

		nn = read(fd, bbuf + offset, count - (size_t)offset);
		switch (nn) {
		case -1:
			if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
				errno = 0;
				continue;
			}
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
	struct timespec start, now;
	static const struct timespec write_full_timeout = {
		.tv_sec = WRITE_FULL_TIMEOUT_SEC,
		.tv_nsec = WRITE_FULL_TIMEOUT_NSEC,
	};


	bbuf = buf;
	offset = 0;
	pfd.fd = fd;
	pfd.events = POLLOUT;

	if (count > SSIZE_MAX) {
		count = SSIZE_MAX;
	}

	if (gettime_mono(&start) == -1) {
		return -1;
	}

	while (count > offset) {
		if (gettime_mono(&now) == -1) {
			return -1;
		}
		timespecsub(&now, &start, &now);
		if (timespeccmp(&now, &write_full_timeout, >)) {
			return -1;
		}

		switch (poll(&pfd, 1, WRITE_POLL_TIMEOUT)) {
		case -1:
			if (errno == EAGAIN || errno == EINTR) {
				errno = 0;
				continue;
			}
			return -1;
		case 0:
			return -1;
		}


		nn = write(fd, bbuf + offset, count - (size_t)offset);
		switch (nn) {
		case -1:
			if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
				errno = 0;
				continue;
			}
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
copy_n(int out, int in, size_t n)
{
	size_t nn;
	uint8_t buf[BUFFER_SIZE];

	while (n > 0) {
		nn = min(n, BUFFER_SIZE);
		if (read2(in, buf, nn) != nn) {
			return -1;
		}
		if (write2(out, buf, nn) != nn) {
			return -1;
		}
		n -= nn;
	}

	return 0;
}

void
hton_16(void *dst, uint16_t x)
{
	union { uint16_t i; uint8_t b[2]; } u;
	u.i = hton_16b(x);
	(void)memcpy(dst, u.b, 2);
}

uint16_t
ntoh_16(const void *src)
{
	union { uint8_t b[2]; uint16_t i; } u;
	(void)memcpy(u.b, src, 2);
	return ntoh_16b(u.i);
}

void
hton_32(void *dst, uint32_t x)
{
	union { uint32_t i; uint8_t b[4]; } u;
	u.i = hton_32b(x);
	(void)memcpy(dst, u.b, 4);
}

uint32_t
ntoh_32(const void *src)
{
	union { uint8_t b[4]; uint32_t i; } u;
	(void)memcpy(u.b, src, 4);
	return ntoh_32b(u.i);
}

void
hton_64(void *dst, uint64_t x)
{
	union { uint64_t i; uint8_t b[8]; } u;
	u.i = hton_64b(x);
	(void)memcpy(dst, u.b, 8);
}

uint64_t
ntoh_64(const void *src)
{
	union { uint8_t b[8]; uint64_t i; } u;
	(void)memcpy(u.b, src, 8);
	return ntoh_64b(u.i);
}

static uint16_t
bswap_16(uint16_t x)
{
	return (uint16_t)(x<<8 | x>>8);
}

static uint32_t
bswap_32(uint32_t x)
{
	return x>>24 | ((x>>8)&0xff00) | ((x<<8)&0xff0000) | x<<24;
}

static uint64_t
bswap_64(uint64_t x)
{
	return ((uint64_t)bswap_32((uint32_t)x))<<32 | bswap_32((uint32_t)(x>>32));
}

static uint16_t
hton_16b(uint16_t x)
{
	static const union { int i; char c; } u = { 1 };
	if (u.c == 1) {
		return bswap_16(x);
	}
	return x;
}

static uint16_t
ntoh_16b(uint16_t x)
{
	static const union { int i; char c; } u = { 1 };
	if (u.c == 1) {
		return bswap_16(x);
	}
	return x;
}

static uint32_t
hton_32b(uint32_t x)
{
	static const union { int i; char c; } u = { 1 };
	if (u.c == 1) {
		return bswap_32(x);
	}
	return x;
}

static uint32_t
ntoh_32b(uint32_t x)
{
	static const union { int i; char c; } u = { 1 };
	if (u.c == 1) {
		return bswap_32(x);
	}
	return x;
}

static uint64_t
hton_64b(uint64_t x)
{
	static const union { int i; char c; } u = { 1 };
	if (u.c == 1) {
		return bswap_64(x);
	}
	return x;
}

static uint64_t
ntoh_64b(uint64_t x)
{
	static const union { int i; char c; } u = { 1 };
	if (u.c == 1) {
		return bswap_64(x);
	}
	return x;
}

static const uint8_t len8[256] = {
	0x00, 0x01, 0x02, 0x02, 0x03, 0x03, 0x03, 0x03, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
	0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
	0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
	0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
	0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
	0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
	0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
	0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
	0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
	0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
	0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
	0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
	0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
	0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
	0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
	0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
};

static size_t
leading_zeros8(uint8_t b)
{
	return 8 - len8[b];
}

size_t
leading_zeros(const uint8_t *b, size_t len)
{
	size_t i;
	for (i = 0; i < len; i++) {
		if (b[i] != 0) {
			return i*8 + leading_zeros8(b[i]);
		}
	}
	return len*8;
}
void
memxor(uint8_t *dst, const uint8_t *a, const uint8_t *b, size_t len)
{
	size_t i;
	for (i = 0; i < len; i++) {
		dst[i] = a[i] ^ b[i];
	}
}

bool
is_zero(const void *src, size_t len)
{
	const uint8_t *u8src = src;
	size_t i;
	for (i = 0; i < len; i++) {
		if (u8src[i] != 0) {
			return false;
		}
	}
	return true;
}

size_t
lcp(const uint8_t *x, const uint8_t *y, size_t len)
{
	size_t i;
	uint8_t b;
	for (i = 0; i < len; i++) {
		if ((b = x[i] ^ y[i]) != 0) {
			return i*8 + leading_zeros8(b);
		}
	}
	return len*8;
}
