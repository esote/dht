#ifndef DHT_CRYPTO_SHA3_H
#define DHT_CRYPTO_SHA3_H

#include <stddef.h>
#include <stdint.h>

#define KECCAK_DIGESTSIZE 64

struct sha3_state {
	/* 1600-bit algorithm hashing state */
	uint64_t hash[25];

	/* buffer for leftovers, block size = 72 bytes for 512-bit keccak */
	uint64_t message[9];

	/* count of bytes in the message buffer */
	size_t rest;
};

void sha3_init(struct sha3_state *state);
int sha3_update(struct sha3_state *state, const uint8_t *m, size_t mlen);
void sha3_final(struct sha3_state *state, uint8_t out[KECCAK_DIGESTSIZE]);

#endif /* DHT_CRYPTO_SHA3_H */
