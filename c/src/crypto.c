#include <sodium.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <sys/types.h>

#include "bytes.h"
#include "crypto.h"
#include "crypto_sha3.h"
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

#define BLOCK_SIZE	262144
#define BLOCK_SIZE_MAX	((SSIZE_MAX) - (CIPHER_OVERHEAD))
#if BLOCK_SIZE > BLOCK_SIZE_MAX
#error block size invalid
#endif

#define C1 23
#define C2 24

struct encrypt_writer {
	int out;
	size_t n;
	unsigned char *plain;
	unsigned char cipher[BLOCK_SIZE + CIPHER_OVERHEAD];
	unsigned char nonce[NONCE_SIZE];
	unsigned char key[KEY_SIZE];
	bool err;
	struct io *io;
};

struct decrypt_reader {
	int in;
	unsigned char *plain;
	/* r = read index, w = write index, plain[r:w] is valid */
	size_t r, w;
	unsigned char cipher[BLOCK_SIZE + CIPHER_OVERHEAD];
	/* cn = cipher index, cipher[0:cn] is valid */
	size_t cn;
	unsigned char nonce[NONCE_SIZE];
	unsigned char key[KEY_SIZE];
	bool err;
	struct io *io;
};

static struct io *encrypt_x25519(int out,
	const unsigned char xpubl[XPUBL_SIZE]);
static ssize_t encrypt_write(const void *buf, size_t count, void *ctx);
static int encrypt_flush(struct encrypt_writer *w);
static int encrypt_close(void *ctx);

static struct io *decrypt_x25519(int in,
	const unsigned char xpubl[XPUBL_SIZE],
	const unsigned char xpriv[XPRIV_SIZE]);
static ssize_t decrypt_read(void *buf, size_t count, void *ctx);
static int decrypt_flush(struct decrypt_reader *r);
static int decrypt_close(void *ctx);

static int new_keypair_static(unsigned char publ[PUBL_SIZE],
	unsigned char priv[PRIV_SIZE]);
static int new_keypair_dynamic(const unsigned char publ[PUBL_SIZE],
	unsigned char x[SHA3_512_SIZE]);

static bool verify_key_static(const unsigned char publ[PUBL_SIZE]);
static bool verify_key_dynamic(const unsigned char publ[PUBL_SIZE],
	const unsigned char x[SHA3_512_SIZE]);

static int
gen_x25519_pair(unsigned char xpubl[XPUBL_SIZE], unsigned char xpriv[XPRIV_SIZE])
{
	randombytes_buf(xpriv, XPRIV_SIZE);
	return crypto_scalarmult_base(xpubl, xpriv);
}

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

static struct io *
encrypt_x25519(int out, const unsigned char xpubl[XPUBL_SIZE])
{
	unsigned char epubl[XPUBL_SIZE];
	struct io *io;
	struct encrypt_writer *w;
	if ((io = malloc(sizeof(*io))) == NULL) {
		return NULL;
	}
	if ((w = malloc(sizeof(*w))) == NULL) {
		free(io);
		return NULL;
	}
	/* ephemeral key */
	if (ephem_publ(xpubl, epubl, w->key) == -1) {
		sodium_memzero(w->key, KEY_SIZE);
		free(w);
		free(io);
		return NULL;
	}
	if (write2(out, epubl, XPUBL_SIZE) != XPUBL_SIZE) {
		sodium_memzero(w->key, KEY_SIZE);
		free(w);
		free(io);
		return NULL;
	}
	/* initial nonce */
	randombytes_buf(w->nonce, NONCE_SIZE);
	if (write2(out, w->nonce, NONCE_SIZE) != NONCE_SIZE) {
		sodium_memzero(w->key, KEY_SIZE);
		free(w);
		free(io);
		return NULL;
	}
	w->out = out;
	w->n = 0;
	w->plain = w->cipher;
	w->err = false;
	w->io = io;
	io->write = encrypt_write;
	io->close = encrypt_close;
	io->ctx = w;
	return io;
}

struct io *
encrypt(int out, const unsigned char publ[PUBL_SIZE])
{
	unsigned char xpubl[XPUBL_SIZE];
	if (crypto_sign_ed25519_pk_to_curve25519(xpubl, publ) == -1) {
		return NULL;
	}
	return encrypt_x25519(out, xpubl);
}

static ssize_t
encrypt_write(const void *buf, size_t count, void *ctx)
{
	const uint8_t *b;
	size_t n;
	size_t nn;
	struct encrypt_writer *w;

	w = ctx;
	if (w->err) {
		return -1;
	}
	b = buf;
	n = 0;
	if (count > SSIZE_MAX) {
		count = SSIZE_MAX;
	}

	while (count > BLOCK_SIZE - w->n) {
		nn = min(BLOCK_SIZE - w->n, count);
		(void)memcpy(w->plain + w->n, b, nn);
		w->n += nn;
		n += nn;
		b += nn;
		count -= nn;
		if (encrypt_flush(w) == -1) {
			w->err = true;
			return -1;
		}
	}
	nn = min(BLOCK_SIZE - w->n, count);
	(void)memcpy(w->plain + w->n, b, count);
	w->n += nn;
	n += nn;
	return (ssize_t)n;
}

static int
encrypt_flush(struct encrypt_writer *w)
{
	unsigned long long cipher_len;
	if (w->n == 0) {
		return 0;
	}
	sodium_increment(w->nonce, NONCE_SIZE);
	if (crypto_aead_chacha20poly1305_encrypt(w->cipher, &cipher_len,
		w->plain, w->n, NULL, 0, NULL, w->nonce, w->key) == -1) {
		return -1;
	}
	if (write2(w->out, w->cipher, cipher_len) != cipher_len) {
		return -1;
	}
	w->n = 0;
	return 0;
}

static int
encrypt_close(void *ctx)
{
	int ret;
	struct encrypt_writer *w;
	w = ctx;
	ret = encrypt_flush(w);
	sodium_memzero(w->plain, BLOCK_SIZE);
	sodium_memzero(w->key, KEY_SIZE);
	free(w->io);
	free(w);
	return ret;
}

static struct io *
decrypt_x25519(int in, const unsigned char xpubl[XPUBL_SIZE],
	const unsigned char xpriv[XPRIV_SIZE])
{
	unsigned char epubl[XPUBL_SIZE];
	struct io *io;
	struct decrypt_reader *r;
	if ((io = malloc(sizeof(*io))) == NULL) {
		return NULL;
	}
	if ((r = malloc(sizeof(*r))) == NULL) {
		free(io);
		return NULL;
	}
	/* read ephemeral key */
	if (read2(in, epubl, XPUBL_SIZE) != XPUBL_SIZE) {
		free(r);
		free(io);
		return NULL;
	}
	if (ephem_priv(xpubl, xpriv, epubl, r->key) == -1) {
		sodium_memzero(r->key, KEY_SIZE);
		free(r);
		free(io);
		return NULL;
	}
	/* read nonce */
	if (read2(in, r->nonce, NONCE_SIZE) != NONCE_SIZE) {
		sodium_memzero(r->key, KEY_SIZE);
		free(r);
		free(io);
		return NULL;
	}
	r->in = in;
	r->plain = r->cipher;
	r->r = 0;
	r->w = 0;
	r->cn = 0;
	r->err = false;
	r->io = io;
	io->read = decrypt_read;
	io->close = decrypt_close;
	io->ctx = r;
	return io;
}

struct io *
decrypt(int in, const unsigned char publ[PUBL_SIZE],
	const unsigned char priv[PRIV_SIZE])
{
	struct io *dec;
	unsigned char xpubl[XPUBL_SIZE], xpriv[XPRIV_SIZE];
	if (crypto_sign_ed25519_pk_to_curve25519(xpubl, publ) == -1) {
		return NULL;
	}
	if (crypto_sign_ed25519_sk_to_curve25519(xpriv, priv) == -1) {
		sodium_memzero(xpriv, XPRIV_SIZE);
		return NULL;
	}
	dec = decrypt_x25519(in, xpubl, xpriv);
	sodium_memzero(xpriv, XPRIV_SIZE);
	return dec;
}

static ssize_t
decrypt_read(void *buf, size_t count, void *ctx)
{
	uint8_t *b;
	size_t n;
	size_t nn;
	struct decrypt_reader *r;

	r = ctx;
	b = buf;
	n = 0;
	if (count > SSIZE_MAX) {
		count = SSIZE_MAX;
	}

	if (r->err) {
		return -1;
	}
	for (;;) {
		nn = min(r->w - r->r, count);
		(void)memcpy(b, r->plain + r->r, nn);
		r->r += nn;
		n += nn;
		b += nn;
		count -= nn;
		if (count == 0 || r->in == -1) {
			break;
		}
		if (decrypt_flush(r) == -1) {
			r->err = true;
			return -1;
		}
	}
	return (ssize_t)n;
}

static int
decrypt_flush(struct decrypt_reader *r)
{
	unsigned long long plain_len;
	ssize_t rr;
	rr = read2(r->in, r->cipher + r->cn,
		(BLOCK_SIZE + CIPHER_OVERHEAD) - r->cn);
	if (rr == -1) {
		return -1;
	}
	r->cn += (size_t)rr;
	if (r->cn != (BLOCK_SIZE + CIPHER_OVERHEAD)) {
		/* EOF, r->in is now invalid */
		r->in = -1;
	}
	sodium_increment(r->nonce, NONCE_SIZE);
	if (crypto_aead_chacha20poly1305_decrypt(r->plain, &plain_len, NULL,
		r->cipher, r->cn, NULL, 0, r->nonce, r->key) == -1) {
		return -1;
	}
	r->r = 0;
	r->w = plain_len;
	r->cn = 0;
	return 0;
}

static int
decrypt_close(void *ctx)
{
	struct decrypt_reader *r = ctx;
	sodium_memzero(r->plain, BLOCK_SIZE);
	sodium_memzero(r->key, KEY_SIZE);
	free(r->io);
	free(r);
	return 0;
}

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
	return crypto_sign_ed25519_verify_detached(sig, msg, msg_len, publ);
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
