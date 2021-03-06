#include <errno.h>
#include <sodium.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "bytes.h"
#include "crypto.h"
#include "crypto_stream.h"
#include "io.h"
#include "util.h"

#define XPUBL_SIZE	crypto_scalarmult_curve25519_BYTES
#define XPRIV_SIZE	crypto_scalarmult_curve25519_BYTES

#define SHARED_SIZE	crypto_scalarmult_BYTES

#if XPUBL_SIZE != SHARED_SIZE
#error xpubl and scalar mismatch
#endif
#if XPRIV_SIZE != crypto_scalarmult_SCALARBYTES
#error xpriv and scalar mismatch
#endif

#define NONCE_SIZE	crypto_aead_chacha20poly1305_NPUBBYTES
#define CIPHER_OVERHEAD	crypto_aead_chacha20poly1305_ABYTES
#define KEY_SIZE	crypto_aead_chacha20poly1305_KEYBYTES

#if KEY_SIZE != crypto_generichash_KEYBYTES
#error hash key size mismatch
#endif

#define BLOCK_SIZE	UINT16_MAX
#define BLOCK_SIZE_MAX	((SSIZE_MAX) - (CIPHER_OVERHEAD))
#if BLOCK_SIZE > BLOCK_SIZE_MAX
#error block size invalid
#endif

static const uint16_t cipher_version = 0;

static int encrypt_child(int in, size_t inlen, int out,
	const unsigned char publ[PUBL_SIZE]);
static int encrypt_ed25519(int in, size_t inlen, int out,
	const unsigned char publ[PUBL_SIZE]);
static int encrypt_x25519(int in, size_t inlen, int out,
	const unsigned char xpubl[XPUBL_SIZE]);
static int encrypt_loop(int in, size_t inlen, int out,
	unsigned char nonce[NONCE_SIZE], const unsigned char key[KEY_SIZE]);

static int decrypt_child(int in, int out, const unsigned char publ[PUBL_SIZE],
	const unsigned char priv[PRIV_SIZE]);
static int decrypt_ed25519(int in, int out, const unsigned char publ[PUBL_SIZE],
	const unsigned char priv[PRIV_SIZE]);
static int decrypt_x25519(int in, int out, const unsigned char xpubl[XPUBL_SIZE],
	const unsigned char xpriv[XPRIV_SIZE]);
static int decrypt_loop(int in, int out, size_t outlen,
	unsigned char nonce[NONCE_SIZE], const unsigned char key[KEY_SIZE]);

static int gen_x25519_pair(unsigned char xpubl[XPUBL_SIZE],
	unsigned char xpriv[XPRIV_SIZE]);
static int ephem_key(const unsigned char shared_secret[SHARED_SIZE],
	const unsigned char xpubl[XPUBL_SIZE],
	const unsigned char epubl[XPUBL_SIZE], unsigned char key[KEY_SIZE]);
static int ephem_publ(const unsigned char xpubl[XPUBL_SIZE],
	unsigned char epubl[XPUBL_SIZE], unsigned char key[KEY_SIZE]);
static int ephem_priv(const unsigned char xpubl[XPUBL_SIZE],
	const unsigned char xpriv[XPRIV_SIZE],
	const unsigned char epubl[XPUBL_SIZE], unsigned char key[KEY_SIZE]);

static int privsep_child(void);

pid_t
encrypt(int *in, size_t inlen, int out,
	const unsigned char publ[XPUBL_SIZE])
{
	pid_t pid;
	int pipefd[2];

	if (in == NULL) {
		return -1;
	}
	if (pipe(pipefd) == -1) {
		return -1;
	}

	pid = fork();
	switch (pid) {
	case -1:
		(void)close(pipefd[0]);
		(void)close(pipefd[1]);
		return -1;
	case 0:
		/* child */
		(void)close(pipefd[1]);
		if (encrypt_child(pipefd[0], inlen, out, publ) == -1) {
			(void)close(pipefd[0]);
			exit(1);
		}
		(void)close(pipefd[0]);
		exit(0);
	default:
		/* parent */
		(void)close(pipefd[0]);
		*in = pipefd[1];
		return pid;
	}
}

pid_t
decrypt(int in, int *out, const unsigned char publ[PUBL_SIZE],
	const unsigned char priv[PRIV_SIZE])
{
	pid_t pid;
	int pipefd[2];

	if (out == NULL) {
		return -1;
	}
	if (pipe(pipefd) == -1) {
		return -1;
	}

	pid = fork();
	switch (pid) {
	case -1:
		(void)close(pipefd[0]);
		(void)close(pipefd[1]);
		return -1;
	case 0:
		/* child */
		(void)close(pipefd[0]);
		if (decrypt_child(in, pipefd[1], publ, priv) == -1) {
			(void)close(pipefd[1]);
			exit(1);
		}
		(void)close(pipefd[1]);
		exit(0);
	default:
		/* parent */
		(void)close(pipefd[1]);
		*out = pipefd[0];
		return pid;
	}
}

static int
encrypt_child(int in, size_t inlen, int out, const unsigned char publ[PUBL_SIZE])
{
	if (privsep_child() == -1) {
		return -1;
	}
	return encrypt_ed25519(in, inlen, out, publ);
}

static int
encrypt_ed25519(int in, size_t inlen, int out, const unsigned char publ[PUBL_SIZE])
{
	unsigned char xpubl[XPUBL_SIZE];
	if (crypto_sign_ed25519_pk_to_curve25519(xpubl, publ) == -1) {
		return -1;
	}
	return encrypt_x25519(in, inlen, out, xpubl);
}

static int
encrypt_x25519(int in, size_t inlen, int out,
	const unsigned char xpubl[XPUBL_SIZE])
{
	uint16_t version;
	uint64_t inlen64;
	unsigned char epubl[XPUBL_SIZE];
	unsigned char key[KEY_SIZE];
	unsigned char nonce[NONCE_SIZE];

	/* VERSION */
	hton_16(&version, cipher_version);
	if (write2(out, &version, sizeof(version)) != sizeof(version)) {
		return -1;
	}

	/* LENGTH */
	if (inlen == 0 || inlen > UINT64_MAX) {
		return -1;
	}
	inlen64 = inlen;
	hton_64(&inlen64, inlen64);
	if (write2(out, &inlen64, sizeof(inlen64)) != sizeof(inlen64)) {
		return -1;
	}

	/* EPHEM_PUBL */
	if (ephem_publ(xpubl, epubl, key) == -1) {
		sodium_memzero(key, KEY_SIZE);
		return -1;
	}
	if (write2(out, epubl, XPUBL_SIZE) != XPUBL_SIZE) {
		sodium_memzero(key, KEY_SIZE);
		return -1;
	}

	/* NONCE */
	randombytes_buf(nonce, NONCE_SIZE);
	if (write2(out, nonce, NONCE_SIZE) != NONCE_SIZE) {
		sodium_memzero(key, KEY_SIZE);
		return -1;
	}

	if (encrypt_loop(in, inlen, out, nonce, key) == -1) {
		sodium_memzero(key, KEY_SIZE);
		return -1;
	}

	sodium_memzero(key, KEY_SIZE);
	return 0;
}

static int
encrypt_loop(int in, size_t inlen, int out, unsigned char nonce[NONCE_SIZE],
	const unsigned char key[KEY_SIZE])
{
	unsigned char cipher[BLOCK_SIZE + CIPHER_OVERHEAD];
	unsigned char *plain;
	ssize_t r;
	unsigned long long cipher_len;
	size_t n;

	plain = cipher;

	while (inlen > 0) {
		n = min(BLOCK_SIZE, inlen);

		if ((r = read2(in, plain, n)) != n) {
			sodium_memzero(plain, BLOCK_SIZE);
			return -1;
		}
		inlen -= n;

		sodium_increment(nonce, NONCE_SIZE);
		if (crypto_aead_chacha20poly1305_encrypt(cipher, &cipher_len,
			plain, (unsigned long long)r, NULL, 0, NULL, nonce,
			key) == -1) {
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

static int
decrypt_child(int in, int out, const unsigned char publ[PUBL_SIZE],
	const unsigned char priv[PRIV_SIZE])
{
	if (privsep_child() == -1) {
		return -1;
	}
	return decrypt_ed25519(in, out, publ, priv);
}

static int
decrypt_ed25519(int in, int out, const unsigned char publ[PUBL_SIZE],
	const unsigned char priv[PRIV_SIZE])
{
	unsigned char xpubl[XPUBL_SIZE], xpriv[XPRIV_SIZE];
	if (crypto_sign_ed25519_pk_to_curve25519(xpubl, publ) == -1) {
		return -1;
	}
	if (crypto_sign_ed25519_sk_to_curve25519(xpriv, priv) == -1) {
		sodium_memzero(xpriv, XPRIV_SIZE);
		return -1;
	}
	if (decrypt_x25519(in, out, xpubl, xpriv) == -1) {
		sodium_memzero(xpriv, XPRIV_SIZE);
		return -1;
	}
	sodium_memzero(xpriv, XPRIV_SIZE);
	return 0;
}

static int
decrypt_x25519(int in, int out, const unsigned char xpubl[XPUBL_SIZE],
	const unsigned char xpriv[XPRIV_SIZE])
{
	uint16_t version;
	size_t outlen;
	uint64_t outlen64;
	unsigned char epubl[XPUBL_SIZE];
	unsigned char key[KEY_SIZE];
	unsigned char nonce[NONCE_SIZE];

	/* VERSION */
	if (read2(in, &version, sizeof(version)) != sizeof(version)) {
		return -1;
	}
	version = ntoh_16(&version);
	if (version != cipher_version) {
		return -1;
	}

	/* LENGTH */
	if (read2(in, &outlen64, sizeof(outlen64)) != sizeof(outlen64)) {
		return -1;
	}
	outlen64 = ntoh_64(&outlen64);
	outlen = outlen64;
	if (outlen == 0) {
		return -1;
	}

	/* EPHEM_PUBL */
	if (read2(in, epubl, XPUBL_SIZE) != XPUBL_SIZE) {
		return -1;
	}
	if (ephem_priv(xpubl, xpriv, epubl, key) == -1) {
		sodium_memzero(key, KEY_SIZE);
		return -1;
	}

	/* NONCE */
	if (read2(in, nonce, NONCE_SIZE) != NONCE_SIZE) {
		sodium_memzero(key, KEY_SIZE);
		return -1;
	}

	if (decrypt_loop(in, out, outlen, nonce, key) == -1) {
		sodium_memzero(key, KEY_SIZE);
		return -1;
	}

	sodium_memzero(key, KEY_SIZE);
	return 0;
}

static int
decrypt_loop(int in, int out, size_t outlen, unsigned char nonce[NONCE_SIZE],
	const unsigned char key[KEY_SIZE])
{
	unsigned char cipher[BLOCK_SIZE + CIPHER_OVERHEAD];
	unsigned char *plain;
	ssize_t r;
	unsigned long long plain_len;
	size_t n;

	plain = cipher;

	while (outlen > 0) {
		n = min(BLOCK_SIZE, outlen);

		if ((r = read2(in, cipher, n + CIPHER_OVERHEAD)) != n + CIPHER_OVERHEAD) {
			sodium_memzero(plain, BLOCK_SIZE);
			return -1;
		}
		outlen -= n;

		sodium_increment(nonce, NONCE_SIZE);
		if (crypto_aead_chacha20poly1305_decrypt(plain, &plain_len,
			NULL, cipher, (unsigned long long)r, NULL, 0, nonce,
			key) == -1) {
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

/* generate a new x25519 keypair */
static int
gen_x25519_pair(unsigned char xpubl[XPUBL_SIZE], unsigned char xpriv[XPRIV_SIZE])
{
	randombytes_buf(xpriv, XPRIV_SIZE);
	return crypto_scalarmult_base(xpubl, xpriv);
}

/* create an ephemeral key = h(shared secret | xpubl | epubl) */
static int
ephem_key(const unsigned char shared_secret[SHARED_SIZE],
	const unsigned char xpubl[XPUBL_SIZE], const unsigned char epubl[XPUBL_SIZE],
	unsigned char key[KEY_SIZE])
{
	/* XXX: hash out crypto_generichash_BYTES then copy to key? */
	/* XXX: impact of different outlen for init and final? */
	crypto_generichash_state h;
	if (crypto_generichash_init(&h, NULL, 0, KEY_SIZE) == -1) {
		return -1;
	}
	if (crypto_generichash_update(&h, shared_secret, SHARED_SIZE) == -1) {
		return -1;
	}
	if (crypto_generichash_update(&h, xpubl, XPUBL_SIZE) == -1) {
		return -1;
	}
	if (crypto_generichash_update(&h, epubl, XPUBL_SIZE) == -1) {
		return -1;
	}
	if (crypto_generichash_final(&h, key, KEY_SIZE) == -1) {
		return -1;
	}
	return 0;
}

static int
ephem_publ(const unsigned char xpubl[XPUBL_SIZE], unsigned char epubl[XPUBL_SIZE],
	unsigned char key[KEY_SIZE])
{
	unsigned char epriv[XPRIV_SIZE];
	unsigned char shared_secret[SHARED_SIZE];
	if (gen_x25519_pair(epubl, epriv) == -1) {
		sodium_memzero(epriv, XPRIV_SIZE);
		return -1;
	}
	if (crypto_scalarmult(shared_secret, epriv, xpubl) == -1) {
		sodium_memzero(shared_secret, SHARED_SIZE);
		sodium_memzero(epriv, XPRIV_SIZE);
		return -1;
	}
	if (ephem_key(shared_secret, xpubl, epubl, key) == -1) {
		sodium_memzero(shared_secret, SHARED_SIZE);
		sodium_memzero(epriv, XPRIV_SIZE);
		return -1;
	}
	sodium_memzero(shared_secret, SHARED_SIZE);
	sodium_memzero(epriv, XPRIV_SIZE);
	return 0;
}

static int
ephem_priv(const unsigned char xpubl[XPUBL_SIZE], const unsigned char xpriv[XPRIV_SIZE],
	const unsigned char epubl[XPUBL_SIZE], unsigned char key[KEY_SIZE])
{
	unsigned char shared_secret[SHARED_SIZE];
	if (crypto_scalarmult(shared_secret, xpriv, epubl) == -1) {
		sodium_memzero(shared_secret, SHARED_SIZE);
		return -1;
	}
	if (ephem_key(shared_secret, xpubl, epubl, key) == -1) {
		sodium_memzero(shared_secret, SHARED_SIZE);
		return -1;
	}
	sodium_memzero(shared_secret, SHARED_SIZE);
	return 0;
}

static int
privsep_child(void)
{
	/* TODO */
	return 0;
}
