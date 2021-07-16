#include <sodium.h>
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

void
bin2hex(char *const hex, const size_t hex_maxlen, const void *bin,
	const size_t bin_len)
{
	(void)sodium_bin2hex(hex, hex_maxlen, bin, bin_len);
}

int
hex2bin(void *const bin, const size_t bin_maxlen, const char *const hex,
	const size_t hex_len)
{
	return sodium_hex2bin(bin, bin_maxlen, hex, hex_len, NULL, NULL, NULL);
}

bool
string_empty(const char *s)
{
	return s == NULL || *s == '\0';
}
