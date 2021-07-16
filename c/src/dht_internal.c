#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "dht_internal.h"
#include "proto.h"
#include "session.h"
#include "util.h"

static int connect_timeout(int fd, const struct addrinfo *rp);
static bool ping_node(const struct node *n, void *arg);

int
socket_timeout(int fd)
{
	struct timeval tv;
	tv.tv_sec = SOCKET_TIMEOUT_SEC;
	tv.tv_usec = SOCKET_TIMEOUT_USEC;
	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == -1) {
		return -1;
	}
	return setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

int
connect_remote(const char *addr, uint16_t port)
{
	int fd;
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	char str_port[6];
	int n;

	(void)memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = 0;
	hints.ai_protocol = 0;

	/* TODO: cleaner way? */
	n = snprintf(str_port, sizeof(str_port), "%" PRIu16, port);
	assert(n >= 0 && n < sizeof(str_port));

	if (getaddrinfo(addr, str_port, &hints, &result) != 0) {
		/*  TODO: print return value, retry? */
		return -1;
	}

	for (rp = result; rp != NULL; rp = rp->ai_next) {
		fd = socket(rp->ai_family, rp->ai_socktype | SOCK_NONBLOCK,
			rp->ai_protocol);
		if (fd == -1) {
			dht_log(LOG_WARNING, "%s", strerror(errno));
			continue;
		}
		if (socket_timeout(fd) == -1) {
			dht_log(LOG_WARNING, "%s", strerror(errno));
			(void)close(fd);
			continue;
		}

		if (connect_timeout(fd, rp) == -1) {
			dht_log(LOG_WARNING, "%s", strerror(errno));
			(void)close(fd);
			continue;
		}

		break;
	}

	freeaddrinfo(result);

	if (rp == NULL) {
		/* no address succeeded */
		return -1;
	}

	return fd;
}

static int
connect_timeout(int fd, const struct addrinfo *rp)
{
	struct pollfd pfd;
	int err;
	socklen_t errsize;

	if (connect(fd, rp->ai_addr, rp->ai_addrlen) == -1) {
		if (errno == EINPROGRESS || errno == EALREADY) {
			/* connection is forming */
			errno = 0;
		} else {
			/* TODO: handle EINTR */
			return -1;
		}
	}

	pfd.fd = fd;
	pfd.events = POLLOUT;
	switch (poll(&pfd, 1, CONNECT_TIMEOUT)) {
	case -1:
		return -1;
	case 0:
		dht_log(LOG_DEBUG, "poll timed out");
		return -1;
	}

	errsize = sizeof(err);
	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errsize) == -1) {
		return -1;
	}
	if (err != 0) {
		/* socket connect failed */
		errno = err;
		return -1;
	}

	/* socket connect succeeded */
	return 0;
}

int
dht_update(struct dht *dht, const struct node *target)
{
	struct node *replaced;
	replaced = rtable_replace_oldest(dht->rtable, target, ping_node, dht);
	if (replaced != NULL) {
		free(replaced);
	}
	return 0;
}

/* TODO: differentiate between internal error and remote error? */
static bool
ping_node(const struct node *n, void *arg)
{
	struct dht *dht;
	struct session s;
	int afd;
	struct message *msg;
	bool alive;

	dht = arg;

	if ((afd = connect_remote(n->addr, n->port)) == -1) {
		return false;
	}

	session_init(&s, dht, n->id, afd);

	if (session_send(&s, TYPE_PING, NULL) == -1) {
		(void)close(afd);
		return false;
	}

	if ((msg = session_recv(&s)) == NULL) {
		(void)close(afd);
		return false;
	}

	alive = msg->hdr.msg_type == TYPE_PING;

	if (message_close(msg) == -1) {
		(void)close(afd);
		return false;
	}

	if (close(afd) == -1) {
		return false;
	}

	return alive;
}
