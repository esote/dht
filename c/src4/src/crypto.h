#pragma once

#include <pthread.h>
#include <sodium.h>
#include <stdbool.h>
#include <stddef.h>

#include "crypto_sha3.h"

#define PUBL_SIZE crypto_sign_ed25519_PUBLICKEYBYTES
#define PRIV_SIZE crypto_sign_ed25519_SECRETKEYBYTES

#define EPHEM_PUBL_SIZE crypto_scalarmult_curve25519_BYTES
#define EPHEM_KEY_SIZE crypto_aead_chacha20poly1305_KEYBYTES

#define SIG_SIZE crypto_sign_BYTES

#define SHA2_512_SIZE crypto_hash_sha512_BYTES
#define SHA3_512_SIZE KECCAK_DIGESTSIZE

struct encrypt_arg {
	int monitor;
	int out;
	int in;
	uint64_t length;
	uint8_t ephem_publ[EPHEM_PUBL_SIZE];
	uint8_t ephem_key[EPHEM_KEY_SIZE];
};

struct decrypt_arg {
	int monitor;
	int in;
	int out;
};

int encrypt(struct encrypt_arg *arg, pthread_t *thread);
int decrypt(struct decrypt_arg *arg, pthread_t *thread);

bool valid_sig(const unsigned char sig[SIG_SIZE], const void *msg, size_t msg_len, const unsigned char publ[PUBL_SIZE]);

int new_keypair(unsigned char publ[PUBL_SIZE], unsigned char priv[PRIV_SIZE], unsigned char x[SHA3_512_SIZE]);
bool valid_key(const unsigned char id[PUBL_SIZE], const unsigned char x[SHA3_512_SIZE]);
