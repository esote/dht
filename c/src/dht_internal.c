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
#include "util.h"

static int connect_timeout(int fd, const struct addrinfo *rp);
static bool ping_node(const struct node *n, void *arg);

int
send_message(const struct dht *dht, int afd, uint16_t msg_type,
	const uint8_t session_id[SESSION_ID_SIZE], const union payload *p,
	const uint8_t target_id[NODE_ID_SIZE])
{
	struct message m;
	time_t now;

	(void)memcpy(m.hdr.session_id, session_id, SESSION_ID_SIZE);
	if ((now = time(NULL)) == -1 || now > (INT64_MAX - MSG_EXPIRATION)) {
		return -1;
	}
	m.hdr.expiration = now + MSG_EXPIRATION;

	(void)memcpy(m.hdr.network_id, dht->network_id, NETWORK_ID_SIZE);
	m.hdr.msg_type = msg_type;
	(void)memcpy(m.hdr.self.id, dht->id, NODE_ID_SIZE);
	(void)memcpy(m.hdr.self.dyn_x, dht->dyn_x, DYN_X_SIZE);
	if ((m.hdr.self.addr = strdup(dht->addr)) == NULL) {
		/* TODO: if strlen(dht->addr) == 0 null might be right */
		return -1;
	}
	m.hdr.self.port = dht->port;

	if (p == NULL) {
		(void)memset(&m.payload, 0, sizeof(m.payload));
	} else {
		m.payload = *p;
	}
	if (message_encode(&m, afd, dht->priv, target_id) == -1) {
		free(m.hdr.self.addr);
		return -1;
	}
	free(m.hdr.self.addr);
	return 0;
}

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
	int ready, err;
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
	ready = poll(&pfd, 1, CONNECT_TIMEOUT);
	if (ready == -1) {
		return -1;
	} else if (ready == 0) {
		dht_log(LOG_DEBUG, "connect timed out");
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
dht_update(struct dht *dht, struct node *target)
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
	struct dht *dht = arg;
	uint8_t session_id[SESSION_ID_SIZE];
	int afd;
	struct message *msg;
	bool alive;

	if ((afd = connect_remote(n->addr, n->port)) == -1) {
		return false;
	}
	crypto_rand(session_id, SESSION_ID_SIZE);
	if (send_message(dht, afd, TYPE_PING, session_id, NULL, n->id) == -1) {
		(void)close(afd);
		return false;
	}
	if ((msg = message_decode(afd, dht->id, dht->priv)) == NULL) {
		(void)close(afd);
		return false;
	}

	alive = msg->hdr.msg_type == TYPE_PING
		&& memcmp(msg->hdr.session_id, session_id, SESSION_ID_SIZE) == 0;

	if (message_close(msg) == -1) {
		(void)close(afd);
		return false;
	}
	if (close(afd) == -1) {
		return false;
	}
	return alive;
}
