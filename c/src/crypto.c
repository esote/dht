#include <sodium.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "bytes.h"
#include "crypto.h"
#include "crypto_sha3.h"
#include "io.h"
#include "util.h"

#define C1 13 /* 23 */
#define C2 14 /* 24 */

static int new_keypair_static(unsigned char publ[PUBL_SIZE],
	unsigned char priv[PRIV_SIZE]);
static int new_keypair_dynamic(const unsigned char publ[PUBL_SIZE],
	unsigned char x[SHA3_512_SIZE]);

static bool verify_key_static(const unsigned char publ[PUBL_SIZE]);
static bool verify_key_dynamic(const unsigned char publ[PUBL_SIZE],
	const unsigned char x[SHA3_512_SIZE]);

int
sign(unsigned char sig[SIG_SIZE], const void *msg, size_t msg_len,
	const unsigned char priv[PRIV_SIZE])
{
	return crypto_sign_ed25519_detached(sig, NULL, msg, msg_len, priv);
}

bool
sign_verify(const unsigned char sig[SIG_SIZE], const void *msg, size_t msg_len,
	const unsigned char publ[PUBL_SIZE])
{
	return crypto_sign_ed25519_verify_detached(sig, msg, msg_len, publ) != -1;
}

int
sha2_init(struct sha2_state *state)
{
	return crypto_hash_sha512_init(&state->state);
}

int
sha2_update(struct sha2_state *state, const uint8_t *m, size_t mlen)
{
	return crypto_hash_sha512_update(&state->state, m, mlen);
}

int
sha2_final(struct sha2_state *state, uint8_t out[SHA2_512_SIZE])
{
	return crypto_hash_sha512_final(&state->state, out);
}

int
new_keypair(unsigned char publ[PUBL_SIZE], unsigned char priv[PRIV_SIZE],
	unsigned char x[SHA3_512_SIZE])
{
	unsigned char ed_publ[PUBL_SIZE], ed_priv[PRIV_SIZE];
	unsigned char tmp_x[SHA3_512_SIZE];
	if (new_keypair_static(ed_publ, ed_priv) == -1) {
		sodium_memzero(ed_priv, PRIV_SIZE);
		return -1;
	}
	if (new_keypair_dynamic(ed_publ, tmp_x) == -1) {
		sodium_memzero(ed_priv, PRIV_SIZE);
		return -1;
	}
	(void)memcpy(publ, ed_publ, PUBL_SIZE);
	(void)memcpy(priv, ed_priv, PRIV_SIZE);
	(void)memcpy(x, tmp_x, SHA3_512_SIZE);
	return 0;
}

static int
new_keypair_static(unsigned char publ[PUBL_SIZE], unsigned char priv[PRIV_SIZE])
{
	crypto_hash_sha512_state state;
	uint8_t h[SHA2_512_SIZE];
	for (;;) {
		if (crypto_sign_ed25519_keypair(publ, priv) == -1) {
			return -1;
		}

		/* first hash */
		if (crypto_hash_sha512_init(&state) == -1) {
			return -1;
		}
		if (crypto_hash_sha512_update(&state, publ, PUBL_SIZE) == -1) {
			return -1;
		}
		if (crypto_hash_sha512_final(&state, h) == -1) {
			return -1;
		}

		/* second hash */
		if (crypto_hash_sha512_init(&state) == -1) {
			return -1;
		}
		if (crypto_hash_sha512_update(&state, h, SHA2_512_SIZE) == -1) {
			return -1;
		}
		if (crypto_hash_sha512_final(&state, h) == -1) {
			return -1;
		}

		if (leading_zeros(h, SHA2_512_SIZE) >= C1) {
			/* Success */
			return 0;
		}
	}
}

static int
new_keypair_dynamic(const unsigned char publ[PUBL_SIZE],
	unsigned char x[SHA3_512_SIZE])
{
	struct sha3_state state;
	uint8_t h[SHA3_512_SIZE], h2[SHA3_512_SIZE], xh[SHA3_512_SIZE];

	sha3_init(&state);
	if (sha3_update(&state, publ, PUBL_SIZE) == -1) {
		return -1;
	}
	sha3_final(&state, h);

	for (;;) {
		randombytes_buf(x, SHA3_512_SIZE);
		memxor(xh, h, x, SHA3_512_SIZE);

		sha3_init(&state);
		if (sha3_update(&state, xh, SHA3_512_SIZE) == -1) {
			return -1;
		}
		sha3_final(&state, h2);
		if (leading_zeros(h2, SHA3_512_SIZE) >= C2) {
			/* Success */
			return 0;
		}
	}
}

bool
verify_key(const unsigned char publ[PUBL_SIZE],
	const unsigned char x[SHA3_512_SIZE])
{
	return verify_key_static(publ) && verify_key_dynamic(publ, x);
}

static bool
verify_key_static(const unsigned char publ[PUBL_SIZE])
{
	crypto_hash_sha512_state state;
	uint8_t h[SHA2_512_SIZE];
	/* first hash */
	if (crypto_hash_sha512_init(&state) == -1) {
		return false;
	}
	if (crypto_hash_sha512_update(&state, publ, PUBL_SIZE) == -1) {
		return false;
	}
	if (crypto_hash_sha512_final(&state, h) == -1) {
		return false;
	}
	/* second hash */
	if (crypto_hash_sha512_init(&state) == -1) {
		return false;
	}
	if (crypto_hash_sha512_update(&state, h, SHA2_512_SIZE) == -1) {
		return false;
	}
	if (crypto_hash_sha512_final(&state, h) == -1) {
		return false;
	}
	return leading_zeros(h, SHA2_512_SIZE) >= C1;
}

static bool
verify_key_dynamic(const unsigned char publ[PUBL_SIZE],
	const unsigned char x[SHA3_512_SIZE])
{
	struct sha3_state state;
	uint8_t h[SHA3_512_SIZE];

	sha3_init(&state);
	if (sha3_update(&state, publ, PUBL_SIZE) == -1) {
		return false;
	}
	sha3_final(&state, h);

	sha3_init(&state);
	memxor(h, h, x, SHA3_512_SIZE);
	if (sha3_update(&state, h, SHA3_512_SIZE) == -1) {
		return false;
	}
	sha3_final(&state, h);
	return leading_zeros(h, SHA3_512_SIZE) >= C2;
}

void
crypto_rand(void *buf, size_t len)
{
	randombytes_buf(buf, len);
}
