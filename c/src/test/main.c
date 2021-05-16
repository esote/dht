#include <unistd.h>
#include <sodium.h>
#include <assert.h>
#include <fcntl.h>
#include "crypto.h"
#include "proto.h"
#include <string.h>

//#define NEW

static void
ed25519_pair(unsigned char publ[PUBL_SIZE], unsigned char priv[PRIV_SIZE])
{
#ifdef NEW
	assert(crypto_sign_ed25519_keypair(publ, priv) != -1);
	int fpubl = open("t/publ", O_WRONLY|O_CREAT|O_EXCL|O_TRUNC, 0600);
	assert(fpubl != -1);
	int fpriv = open("t/priv", O_WRONLY|O_CREAT|O_EXCL|O_TRUNC, 0600);
	assert(fpriv != -1);
	assert(write(fpubl, publ, PUBL_SIZE) == PUBL_SIZE);
	assert(write(fpriv, priv, PRIV_SIZE) == PRIV_SIZE);
	assert(close(fpubl) != -1);
	assert(close(fpriv) != -1);
#else
	int fpubl = open("t/publ", O_RDONLY);
	assert(fpubl != -1);
	int fpriv = open("t/priv", O_RDONLY);
	assert(fpriv != -1);
	assert(read(fpubl, publ, PUBL_SIZE) == PUBL_SIZE);
	assert(read(fpriv, priv, PRIV_SIZE) == PRIV_SIZE);
	assert(close(fpubl) != -1);
	assert(close(fpriv) != -1);
#endif
}

int
main(void)
{
	uint8_t publ[PUBL_SIZE], priv[PRIV_SIZE];
	ed25519_pair(publ, priv);
	struct message m1 = {
		.version = VERSION,
		.hdr = {
			.network_id = {1, 2, 3, 4, 5, 6, 7, 8},
			.msg_type = TYPE_STORE,
			//.id = publ,
			.dyn_x = {1}, /* TODO */
			.ip = {2}, /* TODO */
			.port = 8080,
			.rpc_id = {3},
			.expiration = 69420,
		},
		.payload = {
			.store = {
				.key = {4},
				.length = 10,
			}
		}
	};
	(void)memcpy(m1.hdr.id, publ, PUBL_SIZE);

	int e = open("t/e", O_WRONLY|O_CREAT|O_TRUNC, 0600);
	assert(e != -1);
	int ret = message_encode(&m1, e, priv, publ); /* sending it to ourself */
	assert(ret != -1);
	assert(close(e) != -1);

	e = open("t/e", O_RDONLY);
	assert(e != -1);
	struct message *m2 = message_decode(e, publ, priv);
	assert(m2 != NULL);
	assert(close(e) != -1);
	message_free(m2);
}
