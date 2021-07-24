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
#include "rtable.h"
#include "session.h"
#include "util.h"

static int connect_timeout(int fd, const struct addrinfo *rp);

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
	int n;

	(void)memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = 0;
	hints.ai_protocol = 0;

	if ((n = getaddrinfo_port(addr, port, &hints, &result)) != 0) {
		dht_log(LOG_ERR, "%s", gai_strerror(n));
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

	while (connect(fd, rp->ai_addr, rp->ai_addrlen) == -1) {
		switch (errno) {
		case EINPROGRESS:
		case EALREADY:
			/* connection is forming */
			errno = 0;
			break;
		case EINTR:
			continue;
		default:
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

	return 0;
}

int
getaddrinfo_port(const char *node, uint16_t port, const struct addrinfo *hints,
	struct addrinfo **res)
{
#define SERVICE_LEN (5+1)
	char service[SERVICE_LEN];
	int n;

	n = snprintf(service, sizeof(service), "%"PRIu16, port);
	if (n < 0 || n >= sizeof(service)) {
		return EAI_NONAME;
	}

	return getaddrinfo(node, service, hints, res);
}

int
dht_update(struct dht *dht, const struct node *target)
{
	return rtable_store(&dht->rtable, target);
}

/* TODO: differentiate between internal error and remote error? */
bool
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
