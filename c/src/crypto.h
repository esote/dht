#ifndef DHT_CRYPTO_H
#define DHT_CRYPTO_H

#include <sodium.h>
#include <stdbool.h>
#include <stddef.h>

#include "crypto_sha3.h"

#define PUBL_SIZE crypto_sign_ed25519_PUBLICKEYBYTES
#define PRIV_SIZE crypto_sign_ed25519_SECRETKEYBYTES

/* Sign */

#define SIG_SIZE crypto_sign_BYTES

int sign(unsigned char sig[SIG_SIZE], const void *msg, size_t msg_len,
	const unsigned char priv[PRIV_SIZE]);
bool sign_verify(const unsigned char sig[SIG_SIZE], const void *msg,
	size_t msg_len, const unsigned char publ[PUBL_SIZE]);

/* Hash (SHA2) */

#define SHA2_512_SIZE crypto_hash_sha512_BYTES

struct sha2_state {
	crypto_hash_sha512_state state;
};

int sha2_init(struct sha2_state *state);
int sha2_update(struct sha2_state *state, const uint8_t *m, size_t mlen);
int sha2_final(struct sha2_state *state, uint8_t out[SHA2_512_SIZE]);

/* Generate keypair */

#define SHA3_512_SIZE KECCAK_DIGESTSIZE

int new_keypair(unsigned char publ[PUBL_SIZE], unsigned char priv[PRIV_SIZE],
	unsigned char x[SHA3_512_SIZE]);
bool verify_key(const unsigned char publ[PUBL_SIZE],
	const unsigned char x[SHA3_512_SIZE]);

/* Random */
void crypto_rand(void *buf, size_t len);

#endif /* DHT_CRYPTO_H */
