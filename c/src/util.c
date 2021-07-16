#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "util.h"

size_t
min(size_t x, size_t y)
{
	if (x < y) {
		return x;
	}
	return y;
}

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
	static const uint8_t url_table[] = {
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
	val = (unsigned int)src[si+0] << 16;
	if (remain == 2) {
		val |= (unsigned int)src[si+1] << 8;
	}
	dst[di+0] = url_table[val>>18&0x3F];
	dst[di+1] = url_table[val>>12&0x3F];
	if (remain == 2) {
		dst[di+2] = url_table[val>>6&0x3F];
	}
}

bool
string_empty(const char *s)
{
	return s == NULL || *s == '\0';
}
