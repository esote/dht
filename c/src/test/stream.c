#include "../crypto.h"
#include "../crypto_stream.h"
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>
#include <sys/types.h>
#include <fcntl.h>
int
main(void)
{
	unsigned char publ[PUBL_SIZE], priv[PRIV_SIZE], x[SHA3_512_SIZE];
	new_keypair(publ, priv, x);

	int in = open("/tmp/input", O_RDONLY);
	int eout = open("/tmp/eoutput", O_WRONLY|O_CREAT, 0600);
	pid_t child = encrypt(in, eout, publ);
	int status;
	while (waitpid(child, &status, 0) == -1) {
		if (errno == EINTR) {
			errno = 0;
			continue;
		}
		exit(1);
	}
	close(in);
	close(eout);
	eout = open("/tmp/eoutput", O_RDONLY);
	int dout = open("/tmp/doutput", O_WRONLY|O_CREAT, 0600);
	child = decrypt(eout, dout, publ, priv);
	while (waitpid(child, &status, 0) == -1) {
		if (errno == EINTR) {
			errno = 0;
			continue;
		}
		exit(1);
	}
	close(eout);
	close(dout);
}
