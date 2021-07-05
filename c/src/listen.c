#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/in.h>
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
#include "storer.h"

#define LISTEN_BACKLOG 64

static int listener_accept(struct dht *dht, int sfd);
static int listen_net(uint16_t port);
static int socket_reuse(int fd);
static int listener_work(struct dht *dht, int afd);
static bool listener_should_exit(struct dht *dht);
static int respond_msg(struct dht *dht, int afd, const struct message *msg);
static int respond_ping(const struct dht *dht, int afd, const struct message *msg);
static int respond_data(struct dht *dht, int afd, const struct message *msg);
static int respond_fnode(const struct dht *dht, int afd, const struct message *msg);
static int send_fnode_closest(const struct dht *dht, int afd,
	const uint8_t id[NODE_ID_SIZE], size_t k, const uint8_t session_id[SESSION_ID_SIZE],
	const uint8_t target[NODE_ID_SIZE]);
static int respond_fval(const struct dht *dht, int afd, const struct message *req);

static int listen_success = 0;

void *
listener_start(void *arg)
{
	struct dht *dht;
	int sfd;

	dht = arg;
	if ((sfd = listen_net(dht->port)) == -1) {
		return NULL;
	}
	if (listener_accept(dht, sfd) == -1) {
		(void)close(sfd);
		return NULL;
	}
	if (close(sfd) == -1) {
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
	char str_port[6];
	int n;

	(void)memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = 0;
	hints.ai_protocol = 0;

	n = snprintf(str_port, sizeof(str_port), "%" PRIu16, port);
	assert(n >= 0 && n < sizeof(str_port));

	if (getaddrinfo(NULL, str_port, &hints, &result) != 0) {
		/* TODO: print return value, retry? */
		return -1;
	}

	for (rp = result; rp != NULL; rp = rp->ai_next) {
		fd = socket(rp->ai_family, rp->ai_socktype | SOCK_NONBLOCK, rp->ai_protocol);
		if (fd == -1) {
			continue;
		}
		if (socket_reuse(fd) == -1) {
			(void)close(fd);
			continue;
		}
		if (bind(fd, rp->ai_addr, rp->ai_addrlen) == -1) {
			(void)close(fd);
			continue;
		}
		if (listen(fd, LISTEN_BACKLOG) == -1) {
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
socket_reuse(int fd)
{
	int opt = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) == -1) {
		return 1;
	}
	return setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
}

static int
listener_accept(struct dht *dht, int sfd)
{
	int afd;
	for (;;) {
		/* TODO: setsockopts timeouts */
		if (listener_should_exit(dht)) {
			return 0;
		}
		if ((afd = accept(sfd, NULL, NULL)) == -1) {
			if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
				errno = 0;
				continue;
			}
			return -1;
		}
		if (listener_work(dht, afd) == -1) {
			/* TODO: log */
		}
		if (close(afd) == -1) {
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
	struct message *msg;
	struct node target;

	if ((msg = message_decode(afd, dht->id, dht->priv)) == NULL) {
		return -1;
	}
	if (respond_msg(dht, afd, msg) == -1) {
		(void)message_close(msg);
		return -1;
	}
	(void)memcpy(target.id, msg->hdr.node.id, NODE_ID_SIZE);
	(void)memcpy(target.dyn_x, msg->hdr.node.dyn_x, DYN_X_SIZE);
	target.addr = msg->hdr.node.addr;
	target.port = msg->hdr.node.port;
	if (dht_update(dht, &target) == -1) {
		(void)message_close(msg);
		return -1;
	}
	return message_close(msg);
}

static int
respond_msg(struct dht *dht, int afd, const struct message *msg)
{
	switch (msg->hdr.msg_type) {
	case TYPE_PING:
		return respond_ping(dht, afd, msg);
	case TYPE_DATA:
		return respond_data(dht, afd, msg);
	case TYPE_FNODE:
		return respond_fnode(dht, afd, msg);
	case TYPE_FVAL:
		return respond_fval(dht, afd, msg);
	default:
		return -1;
	}
}

static int
respond_ping(const struct dht *dht, int afd, const struct message *msg)
{
	return send_message(dht, afd, TYPE_PING, msg->hdr.session_id, NULL,
		msg->hdr.node.id);
}

static int
respond_data(struct dht *dht, int afd, const struct message *msg)
{
	if (storer_store(dht->storer, msg->payload.data.key, KEY_SIZE,
		msg->payload.data.value, msg->payload.data.length) == -1) {
		return -1;
	}
	return send_message(dht, afd, TYPE_PING, msg->hdr.session_id, NULL,
		msg->hdr.node.id);
}

static int
respond_fnode(const struct dht *dht, int afd, const struct message *msg)
{
	return send_fnode_closest(dht, afd, msg->payload.fnode.target_id,
		msg->payload.fnode.count, msg->hdr.session_id, msg->hdr.node.id);
}

static int
send_fnode_closest(const struct dht *dht, int afd, const uint8_t id[NODE_ID_SIZE],
	size_t k, const uint8_t session_id[SESSION_ID_SIZE], const uint8_t target[NODE_ID_SIZE])
{
	size_t len;
	struct node *closest;
	union payload p;
	int ret;

	if (k > K) {
		k = K;
	} else if (k == 0) {
		return -1;
	}
	if (rtable_closest(dht->rtable, id, k, &closest, &len) == -1) {
		return -1;
	}
	assert(len <= UINT8_MAX);
	p.fnode_resp.count = (uint8_t)len;
	p.fnode_resp.nodes = closest;
	ret = send_message(dht, afd, TYPE_FNODE_RESP, session_id, &p, target);
	free(closest);
	return ret;
}

static int
respond_fval(const struct dht *dht, int afd, const struct message *req)
{
	union payload p;
	int value;
	size_t value_length;

	if ((value = storer_load(dht->storer, req->payload.fval.key, KEY_SIZE,
		&value_length)) == -1) {
		return send_fnode_closest(dht, afd, req->payload.fval.key, K,
			req->hdr.session_id, req->hdr.node.id);
	}
	p.data.length = value_length;
	p.data.value = value;
	if (send_message(dht, afd, TYPE_DATA, req->hdr.session_id, &p, req->hdr.node.id) == -1) {
		(void)close(value);
	}
	return close(value);
}
