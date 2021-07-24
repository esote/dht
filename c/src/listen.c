#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <semaphore.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "dht.h"
#include "dht_internal.h"
#include "io.h"
#include "listen.h"
#include "proto.h"
#include "rtable.h"
#include "session.h"
#include "storer.h"
#include "util.h"

#define LISTEN_BACKLOG 64

static int listener_accept(struct dht *dht, int sfd);
static int listen_net(uint16_t port);
static int socket_reuse(int fd);
static int listener_work(struct dht *dht, int afd);
static bool listener_should_exit(struct dht *dht);
static int respond_msg(struct dht *dht, struct session *s,
	const struct message *msg);
static int respond_ping(struct session *s);
static int respond_data(struct dht *dht, struct session *s,
	const struct message *msg);
static int respond_fnode(struct dht *dht, struct session *s,
	const struct message *msg);
static int send_fnode_closest(struct dht *dht, struct session *s,
	const uint8_t id[NODE_ID_SIZE], uint8_t k);
static int respond_fval(struct dht *dht, struct session *s,
	const struct message *msg);

static int listen_success = 0;

void *
listener_start(void *arg)
{
	struct dht *dht;
	int sfd;

	dht = arg;

	if ((sfd = listen_net(dht->port)) == -1) {
		dht_log(LOG_ERR, "%s", strerror(errno));
		return NULL;
	}

	if (listener_accept(dht, sfd) == -1) {
		dht_log(LOG_ERR, "%s", strerror(errno));
		(void)close(sfd);
		return NULL;
	}

	if (close(sfd) == -1) {
		dht_log(LOG_ERR, "%s", strerror(errno));
		return NULL;
	}

	return &listen_success;
}

static int
listen_net(uint16_t port)
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

	if ((n = getaddrinfo_port(NULL, port, &hints, &result)) != 0) {
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

		if (socket_reuse(fd) == -1) {
			dht_log(LOG_WARNING, "%s", strerror(errno));
			(void)close(fd);
			continue;
		}

		if (bind(fd, rp->ai_addr, rp->ai_addrlen) == -1) {
			dht_log(LOG_WARNING, "%s", strerror(errno));
			(void)close(fd);
			continue;
		}

		if (listen(fd, LISTEN_BACKLOG) == -1) {
			dht_log(LOG_WARNING, "%s", strerror(errno));
			(void)close(fd);
			continue;
		}

		break;
	}

	freeaddrinfo(result);

	if (rp == NULL) {
		dht_log(LOG_ERR, "no address succeeded");
		return -1;
	}

	return fd;
}

static int
socket_reuse(int fd)
{
	int opt = 1;

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) == -1) {
		return -1;
	}

	return setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
}

static int
listener_accept(struct dht *dht, int sfd)
{
	struct pollfd pfd;
	int afd;

	pfd.fd = sfd;
	pfd.events = POLLIN;

	for (;;) {
		if (listener_should_exit(dht)) {
			return 0;
		}

		/* wait for new connection, with timeout */
		switch (poll(&pfd, 1, ACCEPT_TIMEOUT)) {
		case -1:
			if (errno == EAGAIN || errno == EINTR) {
				dht_log(LOG_DEBUG, "poll interrupted");
				errno = 0;
				continue;
			}
			dht_log(LOG_ERR, "%s", strerror(errno));
			return -1;
		case 0:
			continue;
		}

		if ((afd = accept(sfd, NULL, NULL)) == -1) {
			if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
				errno = 0;
				continue;
			}
			dht_log(LOG_ERR, "%s", strerror(errno));
			return -1;
		}

		if (socket_timeout(afd) == -1) {
			dht_log(LOG_ERR, "%s", strerror(errno));
			(void)close(afd);
			return -1;
		}

		if (listener_work(dht, afd) == -1) {
			dht_log(LOG_WARNING, "%s", strerror(errno));
		}

		if (close(afd) == -1) {
			dht_log(LOG_ERR, "%s", strerror(errno));
			return -1;
		}
	}
}

static bool
listener_should_exit(struct dht *dht)
{
	for (;;) {
		if (sem_trywait(&dht->listen_exit) == 0) {
			return true;
		}
		switch (errno) {
		case EINTR:
			/* trywait was interrupted */
			continue;
		case EAGAIN:
			/* exit not signalled */
			return false;
		default:
			/* unknown error, exit to be safe */
			return true;
		}
	}
}

static int
listener_work(struct dht *dht, int afd)
{
	struct session s;
	struct message msg;

	session_init(&s, dht, NULL, afd);

	if (session_recv(&s, &msg) == -1) {
		return -1;
	}

	if (respond_msg(dht, &s, &msg) == -1) {
		(void)message_close(&msg);
		return -1;
	}

	if (dht_update(dht, &msg.hdr.node) == -1) {
		(void)message_close(&msg);
		return -1;
	}

	return message_close(&msg);
}

static int
respond_msg(struct dht *dht, struct session *s, const struct message *msg)
{
	switch (msg->hdr.msg_type) {
	case TYPE_PING:
		return respond_ping(s);
	case TYPE_DATA:
		return respond_data(dht, s, msg);
	case TYPE_FNODE:
		return respond_fnode(dht, s, msg);
	case TYPE_FVAL:
		return respond_fval(dht, s, msg);
	default:
		return -1;
	}
}

static int
respond_ping(struct session *s)
{
	return session_send(s, TYPE_PING, NULL);
}

static int
respond_data(struct dht *dht, struct session *s, const struct message *msg)
{
	if (storer_store(dht->storer, msg->payload.data.key, KEY_SIZE,
		msg->payload.data.value, msg->payload.data.length) == -1) {
		return -1;
	}

	return session_send(s, TYPE_PING, NULL);
}

static int
respond_fnode(struct dht *dht, struct session *s, const struct message *msg)
{
	return send_fnode_closest(dht, s, msg->payload.fnode.target_id,
		msg->payload.fnode.count);
}

static int
send_fnode_closest(struct dht *dht, struct session *s,
	const uint8_t id[NODE_ID_SIZE], uint8_t k)
{
	size_t len;
	struct node *closest;
	union payload p;

	if (k > K) {
		k = K;
	} else if (k == 0) {
		return -1;
	}

	if (rtable_closest(&dht->rtable, id, k, &closest, &len) == -1) {
		return -1;
	}

	assert(len <= UINT8_MAX);
	p.fnode_resp.count = (uint8_t)len;
	p.fnode_resp.nodes = closest;

	if (session_send(s, TYPE_FNODE_RESP, &p) == -1) {
		free(closest);
		return -1;
	}

	free(closest);
	return 0;
}

static int
respond_fval(struct dht *dht, struct session *s, const struct message *msg)
{
	union payload p;

	p.data.value = storer_load(dht->storer, msg->payload.fval.key, KEY_SIZE,
		&p.data.length);
	if (p.data.value == -1) {
		return send_fnode_closest(dht, s, msg->payload.fval.key, K);
	}

	if (session_send(s, TYPE_DATA, &p) == -1) {
		(void)close(p.data.value);
		return -1;
	}

	return close(p.data.value);
}
