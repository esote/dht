#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "dhtd.h"
#include "listen.h"
#include "monitor.h"
#include "proto.h"
#include "rtable.h"

struct child {
	int conn;
	pid_t pid;
};

struct handler {
	struct child listener, rtable, ping, storer;
};

static int create_handlers(struct handler handlers[HANDLER_COUNT]);
static int create_handler(struct handler *handler);
static int create_child(struct child *child, const char *name, int (*privsep)(void), int (*start)(int monitor, struct config *config));
static int load_config(int monitor, struct config *config);
static int handler_start(struct handler *handler);
static void join_handlers(struct handler *handlers, size_t i);
static void join_child(struct child *child);

int
main(void)
{
	struct handler handlers[HANDLER_COUNT];

	if (create_handlers(handlers) == -1) {
		return EXIT_FAILURE;
	}
}

static int
create_handlers(struct handler handlers[HANDLER_COUNT])
{
	size_t i;

	for (i = 0; i < HANDLER_COUNT; i++) {
		if (create_handler(&handlers[i]) == -1) {
			join_handlers(handlers, i);
			dhtd_log(LOG_CRIT, "handler[%zu]", i);
			return -1;
		}
	}

	return 0;
}

static int
create_handler(struct handler *handler)
{
	if (create_child(&handler->listener, "listener", NULL, listener_start) == -1) {
		return -1;
	}
	if (create_child(&handler->rtable, "rtable", NULL, rtable_start) == -1) {
		join_child(&handler->listener);
		return -1;
	}
	if (create_child(&handler->ping, "ping", NULL, NULL /* ping_start */) == -1) {
		join_child(&handler->rtable);
		join_child(&handler->listener);
		return -1;
	}
	if (create_child(&handler->storer, "storer", NULL, NULL /* storer_start */) == -1) {
		join_child(&handler->ping);
		join_child(&handler->rtable);
		join_child(&handler->listener);
		return -1;
	}
	if (handler_start(handler) == -1) {
		join_child(&handler->storer);
		join_child(&handler->ping);
		join_child(&handler->rtable);
		join_child(&handler->listener);
		return -1;
	}
	return 0;

}

static int
create_child(struct child *child, const char *name, int (*privsep)(void), int (*start)(int monitor, struct config *config))
{
	pid_t pid;
	int sv[2];
	struct config config;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1) {
		return -1;
	}

	switch (pid = fork()) {
	case -1:
		close(sv[0]);
		close(sv[1]);
		return -1;
	case 0:
		/* child */
		dhtd_log(LOG_DEBUG, "create %s child %d", name, pid);

		close(sv[0]);
		if (privsep() == -1) {
			dhtd_log(LOG_CRIT, "%d", pid);
			close(sv[1]);
			return -1;
		}

		if (load_config(sv[1], &config) == -1) {
			dhtd_log(LOG_CRIT, "%d", pid);
			close(sv[1]);
			return -1;
		}

		if (start(sv[1], &config) == -1) {
			dhtd_log(LOG_CRIT, "%d", pid);
			close(sv[1]);
			return -1;
		}

		close(sv[1]);
		return -1;
	default:
		/* parent */
		close(sv[1]);
		child->conn = sv[0];
		child->pid = pid;
		return 0;
	}
}

static int
load_config(int monitor, struct config *config)
{
	struct monitor_message msg;
	struct pollfd pfd;

	pfd.fd = monitor;
	pfd.events = POLLIN;

	for (;;) {
		switch (poll(&pfd, 1, -1)) {
		case -1:
			if (errno == EINTR || errno == EAGAIN) {
				errno = 0;
				continue;
			}
			return -1;
		case 0:
			continue;
		}
		if (!(pfd.revents & POLLIN)) {
			return -1;
		}
		break;
	}
	if (monitor_recv(monitor, &msg) == -1) {
		return -1;
	}
	if (msg.type != M_CONFIG) {
		monitor_close(&msg);
		return -1;
	}

	*config = msg.payload.config;

	monitor_close(&msg);
	return 0;
}

static int
handler_start(struct handler *handler)
{
	return 0;
}

static void
join_handlers(struct handler *handlers, size_t i)
{
	while (i-- > 0) {
		dhtd_log(LOG_DEBUG, "join handler %zu", i);
		join_child(&handlers[i].listener);
		join_child(&handlers[i].rtable);
		join_child(&handlers[i].ping);
		join_child(&handlers[i].storer);
	}
}

static void
join_child(struct child *child)
{
	dhtd_log(LOG_DEBUG, "join child %d", child->pid);
	if (child->pid > 0) {
		kill(child->pid, SIGKILL);
	}
	close(child->conn);
}
