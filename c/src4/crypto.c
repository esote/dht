#include <errno.h>
#include <pthread.h>
#include <sodium.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

#include "crypto.h"
#include "crypto_sha3.h"
#include "monitor.h"
#include "util.h"

#ifndef C1
#define C1 23
#endif /* C1 */

#ifndef C2
#define C2 24
#endif /* C2 */

#define NONCE_SIZE crypto_aead_chacha20poly1305_NPUBBYTES
#define CRYPTO_VERSION 0
#define BLOCK_SIZE (16 * 4096)
#define CIPHER_OVERHEAD	crypto_aead_chacha20poly1305_ABYTES

static void *encrypt_work(void *v);
static int encrypt_loop(int in, int out, uint64_t length, uint8_t nonce[NONCE_SIZE], const uint8_t ephem_key[EPHEM_KEY_SIZE]);

static void *decrypt_work(void *v);
static int decrypt_monitor_req(int monitor, const uint8_t ephem_publ[EPHEM_PUBL_SIZE], uint8_t ephem_key[EPHEM_KEY_SIZE]);
static int decrypt_loop(int in, int out, uint64_t length, uint8_t nonce[NONCE_SIZE], const uint8_t ephem_key[EPHEM_KEY_SIZE]);

static int new_keypair_static(unsigned char publ[PUBL_SIZE], unsigned char priv[PRIV_SIZE]);
static int new_keypair_dynamic(const unsigned char publ[PUBL_SIZE], unsigned char x[SHA3_512_SIZE]);

static bool valid_key_static(const unsigned char publ[PUBL_SIZE]);
static bool valid_key_dynamic(const unsigned char publ[PUBL_SIZE], const unsigned char x[SHA3_512_SIZE]);

int
encrypt(struct encrypt_arg *arg, pthread_t *thread)
{
	errno = pthread_create(thread, NULL, encrypt_work, arg);
	if (errno != 0) {
		return -1;
	}
	return 0;
}

static void *
encrypt_work(void *v)
{
	struct encrypt_arg *arg = v;
	uint8_t version;
	uint64_t length;
	uint8_t nonce[NONCE_SIZE];

	/* VERSION */
	version = CRYPTO_VERSION;
	if (write2(arg->out, &version, sizeof(version)) != sizeof(version)) {
		return NULL;
	}

	/* LENGTH */
	if (arg->length == 0) {
		return NULL;
	}
	hton_64(&length, arg->length);
	if (write2(arg->out, &length, sizeof(length)) != sizeof(length)) {
		return NULL;
	}

	/* EPHEM PUBL */
	if (write2(arg->out, arg->ephem_publ, sizeof(arg->ephem_publ)) != sizeof(arg->ephem_publ)) {
		return NULL;
	}

	/* NONCE */
	randombytes_buf(nonce, sizeof(nonce));
	if (write2(arg->out, nonce, sizeof(nonce)) != sizeof(nonce)) {
		return NULL;
	}

	if (encrypt_loop(arg->in, arg->out, length, nonce, arg->ephem_key) == -1) {
		return NULL;
	}

	return NULL;
}

static int
encrypt_loop(int in, int out, uint64_t length, uint8_t nonce[NONCE_SIZE], const uint8_t ephem_key[EPHEM_KEY_SIZE])
{
	unsigned char cipher[BLOCK_SIZE + CIPHER_OVERHEAD];
	unsigned char *plain;
	ssize_t r;
	unsigned long long cipher_len;
	size_t n;

	plain = cipher;

	while (length > 0) {
		n = min(BLOCK_SIZE, length);

		if ((r = read2(in, plain, n)) != n) {
			sodium_memzero(plain, BLOCK_SIZE);
			return -1;
		}
		length -= n;

		sodium_increment(nonce, NONCE_SIZE);
		if (crypto_aead_chacha20poly1305_encrypt(cipher, &cipher_len, plain, (unsigned long long)r, NULL, 0, NULL, nonce, ephem_key) == -1) {
			sodium_memzero(plain, BLOCK_SIZE);
			return -1;
		}

		if (write2(out, cipher, cipher_len) != cipher_len) {
			sodium_memzero(plain, BLOCK_SIZE);
			return -1;
		}
	}

	sodium_memzero(plain, BLOCK_SIZE);
	return 0;
}

int
decrypt(struct decrypt_arg *arg, pthread_t *thread)
{
	errno = pthread_create(thread, NULL, decrypt_work, arg);
	if (errno != 0) {
		return -1;
	}
	return 0;
}

static void *
decrypt_work(void *v)
{
	struct decrypt_arg *arg = v;
	uint8_t version;
	uint64_t length;
	uint8_t ephem_publ[EPHEM_PUBL_SIZE];
	uint8_t ephem_key[EPHEM_KEY_SIZE];
	uint8_t nonce[NONCE_SIZE];

	/* VERSION */
	if (read2(arg->in, &version, sizeof(version)) != sizeof(version)) {
		return NULL;
	}
	if (version != CRYPTO_VERSION) {
		return NULL;
	}

	/* LENGTH */
	if (read2(arg->in, &length, sizeof(length)) != sizeof(length)) {
		return NULL;
	}
	length = ntoh_64(&length);
	if (length == 0) {
		return NULL;
	}

	/* EPHEM PUBL */
	if (read2(arg->in, ephem_publ, sizeof(ephem_publ)) != sizeof(ephem_publ)) {
		return NULL;
	}
	if (decrypt_monitor_req(arg->monitor, ephem_publ, ephem_key) == -1) {
		return NULL;
	}

	/* NONCE */
	if (read2(arg->in, nonce, sizeof(nonce)) != sizeof(nonce)) {
		sodium_memzero(ephem_key, sizeof(ephem_key));
		return NULL;
	}

	if (decrypt_loop(arg->in, arg->out, length, nonce, ephem_key) == -1) {
		sodium_memzero(ephem_key, sizeof(ephem_key));
		return NULL;
	}

	sodium_memzero(ephem_key, sizeof(ephem_key));
	return NULL;
}

static int
decrypt_monitor_req(int monitor, const uint8_t ephem_publ[EPHEM_PUBL_SIZE], uint8_t ephem_key[EPHEM_KEY_SIZE])
{
	struct monitor_message req;
	struct monitor_message resp;

	req.type = M_DECRYPT_REQ;
	memcpy(req.payload.decrypt_req.ephem_publ, ephem_publ, sizeof(req.payload.decrypt_req.ephem_publ));
	if (monitor_send(monitor, &req) == -1) {
		return -1;
	}

	if (monitor_recv(monitor, &resp) == -1) {
		return -1;
	}
	if (resp.type != M_DECRYPT_RESP) {
		return -1;
	}
	memcpy(ephem_key, resp.payload.decrypt_resp.ephem_key, sizeof(resp.payload.decrypt_resp.ephem_key));

	return 0;
}

static int
decrypt_loop(int in, int out, uint64_t length, uint8_t nonce[NONCE_SIZE], const uint8_t ephem_key[EPHEM_KEY_SIZE])
{
	unsigned char cipher[BLOCK_SIZE + CIPHER_OVERHEAD];
	unsigned char *plain;
	ssize_t r;
	unsigned long long plain_len;
	size_t n;

	plain = cipher;

	while (length > 0) {
		n = min(BLOCK_SIZE, length);

		if ((r = read2(in, cipher, n + CIPHER_OVERHEAD)) != n + CIPHER_OVERHEAD) {
			sodium_memzero(plain, BLOCK_SIZE);
			return -1;
		}
		length -= n;

		sodium_increment(nonce, NONCE_SIZE);
		if (crypto_aead_chacha20poly1305_decrypt(plain, &plain_len, NULL, cipher, (unsigned long long)r, NULL, 0, nonce, ephem_key) == -1) {
			sodium_memzero(plain, BLOCK_SIZE);
			return -1;
		}

		if (write2(out, plain, plain_len) != plain_len) {
			sodium_memzero(plain, BLOCK_SIZE);
			return -1;
		}
	}

	sodium_memzero(plain, BLOCK_SIZE);
	return 0;
}

bool
valid_sig(const unsigned char sig[SIG_SIZE], const void *msg, size_t msg_len,
	const unsigned char publ[PUBL_SIZE])
{
	return crypto_sign_ed25519_verify_detached(sig, msg, msg_len, publ) != -1;
}

int
new_keypair(unsigned char publ[PUBL_SIZE], unsigned char priv[PRIV_SIZE], unsigned char x[SHA3_512_SIZE])
{
	unsigned char tmp_publ[PUBL_SIZE], tmp_priv[PRIV_SIZE], tmp_x[SHA3_512_SIZE];

	if (new_keypair_static(tmp_publ, tmp_priv) == -1) {
		sodium_memzero(tmp_priv, PRIV_SIZE);
		return -1;
	}

	if (new_keypair_dynamic(tmp_publ, tmp_x) == -1) {
		sodium_memzero(tmp_priv, PRIV_SIZE);
		return -1;
	}

	memcpy(publ, tmp_publ, PUBL_SIZE);
	memcpy(priv, tmp_priv, PRIV_SIZE);
	memcpy(x, tmp_x, SHA3_512_SIZE);

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
new_keypair_dynamic(const unsigned char publ[PUBL_SIZE], unsigned char x[SHA3_512_SIZE])
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
valid_key(const unsigned char publ[PUBL_SIZE], const unsigned char x[SHA3_512_SIZE])
{
	return valid_key_static(publ) && valid_key_dynamic(publ, x);
}

static bool
valid_key_static(const unsigned char publ[PUBL_SIZE])
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
valid_key_dynamic(const unsigned char publ[PUBL_SIZE], const unsigned char x[SHA3_512_SIZE])
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
