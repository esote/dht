#pragma once

#include <pthread.h>
#include <sodium.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* crypto_sha3.c */
#define KECCAK_DIGESTSIZE 64

struct sha3_state {
	/* 1600-bit algorithm hashing state */
	uint64_t hash[25];

	/* buffer for leftovers, block size = 72 bytes for 512-bit keccak */
	uint64_t message[9];

	/* count of bytes in the message buffer */
	size_t rest;
};

/* crypto.c */
#define PUBL_SIZE crypto_sign_ed25519_PUBLICKEYBYTES
#define PRIV_SIZE crypto_sign_ed25519_SECRETKEYBYTES

#define EPHEM_PUBL_SIZE crypto_scalarmult_curve25519_BYTES
#define EPHEM_KEY_SIZE crypto_aead_chacha20poly1305_KEYBYTES

#define SIG_SIZE crypto_sign_BYTES

#define SHA2_512_SIZE crypto_hash_sha512_BYTES
#define SHA3_512_SIZE KECCAK_DIGESTSIZE
