#include <signal.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "proto.h"
#include "dhtd.h"

struct listener {
	int conn;
	pid_t child;
};

static int spawn_listeners(struct listener listeners[LISTENER_COUNT]);
static void cull_listeners(struct listener *listeners, size_t i);

int
main(void)
{
	struct listener listeners[LISTENER_COUNT];
	uint8_t priv[PRIV_SIZE];
	uint8_t network_id[NETWORK_ID_SIZE] = {1};
	struct node node = {
		.addrlen = 9,
		.addr = "localhost",
		.port = 8080
	};

	if (spawn_listeners(listeners) == -1) {
		return EXIT_FAILURE;
	}

	if (new_keypair(node.id, priv, node.dyn_x) == -1) {
		cull_listeners(listeners, LISTENER_COUNT);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

static int
spawn_listeners(struct listener listeners[LISTENER_COUNT])
{
	size_t i;
	pid_t pid;
	int sv[2];

	for (i = 0; i < LISTENER_COUNT; i++) {
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1) {
			dhtd_log(LOG_CRIT, "%zu", i);
			cull_listeners(listeners, i);
			return -1;
		}
		switch (pid = fork()) {
		case -1:
			close(sv[0]);
			close(sv[1]);
			cull_listeners(listeners, i);
			return -1;
		case 0:
			/* child */
			dhtd_log(LOG_DEBUG, "child[%zu]", i);
			close(sv[0]);
			if (listener_start(sv[1]) == -1) {
				dhtd_log(LOG_CRIT, "%zu", i);
			}
			close(sv[1]);
			return -1;
		default:
			/* parent */
			close(sv[1]);
			listeners[i].conn = sv[0];
			listeners[i].child = pid;
		}
	}

	return 0;
}

static void
cull_listeners(struct listener *listeners, size_t i)
{
	while (i-- > 0) {
		dhtd_log(LOG_DEBUG, "kill[%zu] %d", i, listeners[i].child);
		kill(listeners[i].child, SIGKILL);
		close(listeners[i].conn);
	}
}
