#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "util.h"

#define BUFFER_SIZE	8192

static size_t min(size_t a, size_t b);

char *
strdup(const char *str)
{
	size_t size;
	char *copy;
	size = strlen(str) + 1;
	if ((copy = malloc(size)) == NULL) {
		return NULL;
	}
	(void)memcpy(copy, str, size);
	return copy;
}

char *
join_path_file(const char *path, const char *file)
{
	size_t path_length, file_length, full_length;
	char *full;
	path_length = strlen(path);
	file_length = strlen(file);
	full_length = path_length + 1 + file_length + 1;
	if ((full = malloc(full_length)) == NULL) {
		return NULL;
	}
	(void)memcpy(full, path, path_length);
	full[path_length] = '/';
	(void)memcpy(full + path_length + 1, file, file_length);
	full[full_length - 1] = '\0';
	return full;
}

size_t
base64_url_nopad_len(size_t len)
{
	return (len*8 + 5) / 6;
}

void
base64_url_nopad(void *d, const void *s, size_t len)
{
	const static uint8_t url_table[] = {
		'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
		'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
		'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
		'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
		'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
		'-', '_'
	};
	const uint8_t *src;
	uint8_t *dst;
	size_t di, si;
	size_t n;
	unsigned int val;
	size_t remain;

	dst = d;
	src = s;

	di = 0;
	si = 0;
	n = len/3 * 3;
	while (si < n) {
		val = (unsigned int)(src[si+0] << 16)
			| (unsigned int)(src[si+1] << 8)
			| (unsigned int)(src[si+2]);

		dst[di+0] = url_table[val>>18&0x3F];
		dst[di+1] = url_table[val>>12&0x3F];
		dst[di+2] = url_table[val>>6&0x3F];
		dst[di+3] = url_table[val&0x3F];

		si += 3;
		di += 4;
	}

	remain = len - si;
	if (remain == 0) {
		return;
	}
	val = src[si+0] << 16;
	if (remain == 2) {
		val |= src[si+1] << 8;
	}
	dst[di+0] = url_table[val>>18&0x3F];
	dst[di+1] = url_table[val>>12&0x3F];
	if (remain == 2) {
		dst[di+2] = url_table[val>>6&0x3F];
	}
}

ssize_t
read_full(int fd, void *buf, size_t buflen)
{
	ssize_t r;
	size_t rtotal;
	char *bbuf;
	bbuf = buf;
	if (buflen > SSIZE_MAX) {
		/* implementation-defined */
		return -1;
	}
	rtotal = 0;
	while ((r = read(fd, bbuf+rtotal, buflen-rtotal)) != -1 && r != 0) {
		rtotal += (size_t)r;
	}
	if (r == -1) {
		return -1;
	}
	return (ssize_t)rtotal;
}

ssize_t
write_full(int fd, void *buf, size_t buflen)
{
	ssize_t w;
	size_t wtotal;
	char *bbuf;
	bbuf = buf;
	if (buflen > SSIZE_MAX) {
		/* implementation-defined */
		return -1;
	}
	wtotal = 0;
	while ((w = write(fd, bbuf+wtotal, buflen-wtotal)) != -1 && w != 0) {
		wtotal += (size_t)w;
	}
	if (w == -1 || (size_t)wtotal != buflen) {
		return -1;
	}
	return (ssize_t)wtotal;
}

int
copy(int out, int in, size_t n)
{
	static uint8_t buffer[BUFFER_SIZE];
	ssize_t r, off, w;
	w = 0;
	/* TODO: need to support unlimited copy when n==0? */
	while ((r = read(in, buffer, min(BUFFER_SIZE, n))) > 0) {
		for (off = 0; r > 0; r -= w, off += w) {
			if ((w = write(out, buffer + off, (size_t)r)) <= 0) {
				return -1;
			}
		}
		n -= (size_t)off; /* off equals r once everything is writen */
	}
	if (r < 0) {
		return -1;
	}
	return 0;
}

static size_t
min(size_t a, size_t b)
{
	if (a < b) {
		return a;
	}
	return b;
}

/*
int
max(int a, int b)
{
	if (a > b) {
		return a;
	}
	return b;
}
*/
