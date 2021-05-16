#include <sys/types.h>
#include <sys/socket.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <netinet/in.h>

int
main(void)
{
	struct sigaction act;
	(void)memset(&act, 0, sizeof(act));
	if (sigemptyset(&act.sa_mask) == -1) {
		return 1;
	}
	act.sa_handler = SIG_IGN;
	if (sigaction(SIGPIPE, &act, NULL) == -1) {
		return 2;
	}

	int sfd;
	if ((sfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		return 3;
	}
	int opt;
	opt = 1;
	/* TODO: also reuse port ? */
	if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
		return 4;
	}
	uint16_t port = 8080;
	struct sockaddr_in addr;
	(void)memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	socklen_t addrlen;
}
