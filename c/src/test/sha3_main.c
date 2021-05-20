#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "sha3.h"

void
hex(void *x, size_t n)
{
	uint8_t *xx = x;
	for (size_t i = 0; i < n; i++) {
		printf("%02X", xx[i]);
	}
	printf("\n");
}

int
main(int argc, char *argv[])
{
	uint8_t b[64];
	char *msg = argv[1];
	struct keccak_ctx ctx;
	keccak_init(&ctx);
	keccak_update(&ctx, msg, strlen(msg));
	keccak_finish(&ctx, b);
	hex(b, 64);
}
