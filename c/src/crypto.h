#ifndef DHT_CRYPTO_H
#define DHT_CRYPTO_H

#include <sodium.h>

#define PUBL_SIZE	crypto_sign_ed25519_PUBLICKEYBYTES
#define PRIV_SIZE	crypto_sign_ed25519_SECRETKEYBYTES

struct io *encrypt(int out, unsigned char const publ[PUBL_SIZE]);
struct io *decrypt(int in, unsigned char const publ[PUBL_SIZE],
	const unsigned char priv[PRIV_SIZE]);

#endif /* DHT_CRYPTO_H */
