#ifndef DHT_CRYPTO_STREAM_H
#define DHT_CRYPTO_STREAM_H

#include <sys/types.h>

#include "crypto.h"

/* Encrypt */

pid_t encrypt(int *in, int out, const unsigned char publ[PUBL_SIZE]);
pid_t decrypt(int in, int *out, const unsigned char publ[PUBL_SIZE],
	const unsigned char priv[PRIV_SIZE]);

#endif /* DHT_CRYPTO_STREAM_H */
