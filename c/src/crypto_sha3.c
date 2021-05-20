#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "crypto_sha3.h"

/* TODO: clean up endian stuff */

#if !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || !defined(__ORDER_BIG_ENDIAN__)
#error
#endif

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
static uint64_t
swap64le(uint64_t x)
{
	return x;
}

static void
memcpy_swap64le(void *dst, const void *src, size_t n)
{
	memcpy(dst, src, 8 * n);
}
#endif

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
static uint64_t
swap64le(uint64_t x)
{
	x = ((x & 0x00ff00ff00ff00ff) << 8) | ((x & 0xff00ff00ff00ff00) >> 8);
	x = ((x & 0x0000ffff0000ffff) << 16) | ((x & 0xffff0000ffff0000) >> 16);
	return (x << 32) | (x >> 32);
}

static void
memcpy_swap64le(void *dst, const void *src, size_t n)
{
	const uint64_t *bsrc;
	uint64_t *bdst;
	size_t i;
	bsrc = src;
	bdst = dst;
	for (i = 0; i < n; i++) {
		bdst[i] = swap64le(bsrc[i]);
	}
}
#endif

#define KECCAK_ROUNDS 24
#define ROTL64(x, y) (((x) << (y)) | ((x) >> (64 - (y))))
#define KECCAK_FINALIZED 0x80000000
#define KECCAK_BLOCKLEN 72
#define KECCAK_WORDS ((KECCAK_BLOCKLEN)/8)
#define KECCAK_PROCESS_BLOCK(st, block) { \
	for (size_t i_ = 0; i_ < KECCAK_WORDS; i_++) { \
		((st))[i_] ^= swap64le(((block))[i_]); \
	}; \
	keccakf(st); }

#if KECCAK_BLOCKLEN <= KECCAK_DIGESTSIZE
#error
#endif

#if KECCAK_DIGESTSIZE % 8 != 0
#error
#endif

const uint64_t keccakf_rndc[24] =
{
	0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
	0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
	0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
	0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
	0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
	0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
	0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
	0x8000000000008080, 0x0000000080000001, 0x8000000080008008
};

const int keccakf_rotc[24] =
{
	1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
	27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
};

const int keccakf_piln[24] =
{
	10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
	15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
};

/* update the state with given number of rounds */
static void keccakf(uint64_t st[25])
{
	int i, j, round;
	uint64_t t, bc[5];

	for (round = 0; round < KECCAK_ROUNDS; round++) {
		/* Theta */
		for (i = 0; i < 5; i++) {
			bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
		}

		for (i = 0; i < 5; i++) {
			t = bc[(i + 4) % 5] ^ ROTL64(bc[(i + 1) % 5], 1);
			for (j = 0; j < 25; j += 5) {
				st[j + i] ^= t;
			}
		}

		/* Rho Pi */
		t = st[1];
		for (i = 0; i < 24; i++) {
			j = keccakf_piln[i];
			bc[0] = st[j];
			st[j] = ROTL64(t, keccakf_rotc[i]);
			t = bc[0];
		}

		/* Chi */
		for (j = 0; j < 25; j += 5) {
			for (i = 0; i < 5; i++) {
				bc[i] = st[j + i];
			}
			for (i = 0; i < 5; i++) {
				st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
			}
		}

		/* Iota */
		st[0] ^= keccakf_rndc[round];
	}
}

void
sha3_init(struct sha3_state *state)
{
	(void)memset(state, 0, sizeof(*state));
}

int
sha3_update(struct sha3_state *state, const uint8_t *m, size_t mlen)
{
	const size_t idx = state->rest;

	if (state->rest == KECCAK_FINALIZED) {
		return -1;
	}

	state->rest = (state->rest + mlen) % KECCAK_BLOCKLEN;

	/* fill partial block */
	if (idx != 0) {
		size_t left = KECCAK_BLOCKLEN - idx;
		(void)memcpy((uint8_t *)state->message + idx, m,
			(mlen < left ? mlen : left));
		if (mlen < left) {
			return 0;
		}

		KECCAK_PROCESS_BLOCK(state->hash, state->message);

		m += left;
		mlen -= left;
	}

	while (mlen >= KECCAK_BLOCKLEN) {
		(void)memcpy(state->message, m, KECCAK_BLOCKLEN);

		KECCAK_PROCESS_BLOCK(state->hash, state->message);

		m += KECCAK_BLOCKLEN;
		mlen -= KECCAK_BLOCKLEN;
	}
	if (mlen != 0) {
		(void)memcpy(state->message, m, mlen);
	}
	return 0;
}

static void
set_padding(struct sha3_state *state)
{
	uint8_t *message = (uint8_t*)state->message;
	/* clear the rest of the data queue */
	(void)memset(message + state->rest, 0, KECCAK_BLOCKLEN - state->rest);
	message[state->rest] |= 0x06;
	message[KECCAK_BLOCKLEN - 1] |= 0x80;
}

void
sha3_final(struct sha3_state *state, uint8_t out[KECCAK_DIGESTSIZE])
{
	if (state->rest != KECCAK_FINALIZED) {
		set_padding(state);

		/* process final block */
		KECCAK_PROCESS_BLOCK(state->hash, state->message);
		state->rest = KECCAK_FINALIZED; /* mark context as finalized */
	}
	if (out != NULL) {
		memcpy_swap64le(out, state->hash, KECCAK_DIGESTSIZE / sizeof(uint64_t));
	}
}
