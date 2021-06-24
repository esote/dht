#include "../proto.h"
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>
#include <sys/types.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <assert.h>
int
main(void)
{
	unsigned char publ[PUBL_SIZE], priv[PRIV_SIZE], x[SHA3_512_SIZE];
	new_keypair(publ, priv, x);
	struct message m1 = {
		.version = VERSION,
		.hdr = {
			.network_id = {1, 2, 3, 4, 5, 6, 7, 8},
			.msg_type = TYPE_FVAL,
			.ip = {
				.s6_addr = {2},
			},
			.port = 8080,
			.rpc_id = {3},
			.expiration = time(NULL) + 694200,
		},
		.payload = {
			.fval = {
				.key = {4},
			}
		}
	};
	(void)memcpy(m1.hdr.id, publ, PUBL_SIZE);
	(void)memcpy(m1.hdr.dyn_x, x, SHA3_512_SIZE);

	int eout = open("/tmp/eoutput", O_WRONLY|O_CREAT, 0600);
	int ret = message_encode(&m1, eout, priv, publ);
	assert(ret != -1);
	close(eout);

	eout = open("/tmp/eoutput", O_RDONLY);
	struct message *m2 = message_decode(eout, publ, priv);
	assert(m2 != NULL);
	message_close(m2);
	close(eout);
}
