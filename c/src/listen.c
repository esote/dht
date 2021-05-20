#include <assert.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "dht.h"
#include "dht_internal.h"
#include "io.h"
#include "listen.h"
#include "proto.h"
#include "rtable.h"
#include "storer.h"

static int socket_reuse(int sfd);
static int listener_accept(struct dht *dht, int sfd);
static int listener_work(struct dht *dht, int afd);
static int respond_msg(struct dht *dht, int afd, struct message *msg);
static int respond_ping(struct dht *dht, int afd, struct message *msg);
static int respond_data(struct dht *dht, int afd, struct message *msg);
static int respond_fnode(struct dht *dht, int afd, struct message *msg);
static int send_fnode_closest(struct dht *dht, int afd, uint8_t id[NODE_ID_SIZE],
	size_t k, uint8_t rpc_id[RPC_ID_SIZE], uint8_t target[NODE_ID_SIZE]);
static int respond_fval(struct dht *dht, int afd, struct message *req);
static int send_message(struct dht *dht, int afd, uint16_t msg_type,
	uint8_t rpc_id[RPC_ID_SIZE], union payload *p,
	uint8_t target_id[NODE_ID_SIZE]);

#define LISTEN_BACKLOG 64

/* shouldn't be modified */
static int listen_success = 0;

/* TODO return error value */
void *
listener_start(void *arg)
{
	struct dht *dht;
	int sfd;
	struct sockaddr_in addr = {0};

	dht = arg;
	if ((sfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		return NULL;
	}
	if (socket_reuse(sfd) == -1) {
		(void)close(sfd);
		return NULL;
	}
	addr.sin_family = AF_INET;
	addr.sin_port = htons(dht->port);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(sfd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		(void)close(sfd);
		return NULL;
	}
	if (listen(sfd, LISTEN_BACKLOG) == -1) {
		(void)close(sfd);
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
socket_reuse(int sfd)
{
	/* TODO: reuse port? */
	int opt = 1;
	return setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
}

static int
listener_accept(struct dht *dht, int sfd)
{
	int afd;
	for (;;) {
		/* TODO: setsockopts timeouts */
		if ((afd = accept(sfd, NULL, NULL)) == -1) {
			/* TODO: EAGAIN, etc. */
			return -1;
		}
		if (listener_work(dht, afd) == -1) {
			/* TODO: log */
		}
		if (close(afd) == -1) {
			/* TODO: EAGAIN? */
			return -1;
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
	(void)memcpy(target.id, msg->hdr.id, NODE_ID_SIZE);
	target.ip = msg->hdr.ip;
	target.port = msg->hdr.port;
	if (rtable_store(dht->rtable, &target) == -1) {
		(void)message_close(msg);
		return -1;
	}
	return message_close(msg);
}

static int
respond_msg(struct dht *dht, int afd, struct message *msg)
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
respond_ping(struct dht *dht, int afd, struct message *msg)
{
	return send_message(dht, afd, TYPE_PING, msg->hdr.rpc_id, NULL,
		msg->hdr.id);
}

static int
respond_data(struct dht *dht, int afd, struct message *msg)
{
	if (storer_store(dht->storer, msg->payload.data.key, KEY_SIZE,
		msg->payload.data.value, msg->payload.data.length) == -1) {
		return -1;
	}
	return send_message(dht, afd, TYPE_PING, msg->hdr.rpc_id, NULL,
		msg->hdr.id);
}

static int
respond_fnode(struct dht *dht, int afd, struct message *msg)
{
	return send_fnode_closest(dht, afd, msg->payload.fnode.target,
		msg->payload.fnode.count, msg->hdr.rpc_id, msg->hdr.id);
}

static int
send_fnode_closest(struct dht *dht, int afd, uint8_t id[NODE_ID_SIZE], size_t k,
	uint8_t rpc_id[RPC_ID_SIZE], uint8_t target[NODE_ID_SIZE])
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
	if ((closest = rtable_closest(dht->rtable, id, k, &len)) == NULL) {
		return -1;
	}
	assert(len <= UINT8_MAX);
	p.fnode_resp.count = (uint8_t)len;
	p.fnode_resp.nodes = closest;
	ret = send_message(dht, afd, TYPE_FNODE_RESP, rpc_id, &p, target);
	free(closest);
	return ret;
}

static int
respond_fval(struct dht *dht, int afd, struct message *req)
{
	union payload p;
	int value;
	struct io value_io;
	size_t value_length;

	if ((value = storer_load(dht->storer, req->payload.fval.key, KEY_SIZE,
		&value_length)) == -1) {
		return send_fnode_closest(dht, afd, req->payload.fval.key, K,
			req->hdr.rpc_id, req->hdr.id);
	}
	wrap_fd(&value_io, value);
	p.data.length = value_length;
	p.data.value = &value_io;
	if (send_message(dht, afd, TYPE_DATA, req->hdr.rpc_id, &p, req->hdr.id) == -1) {
		(void)close(value);
	}
	return close(value);
}

static int
send_message(struct dht *dht, int afd, uint16_t msg_type,
	uint8_t rpc_id[RPC_ID_SIZE], union payload *p,
	uint8_t target_id[NODE_ID_SIZE])
{
	struct message m;
	time_t now;

	m.version = VERSION;

	(void)memcpy(m.hdr.network_id, dht->network_id, NETWORK_ID_SIZE);
	m.hdr.msg_type = msg_type;
	(void)memcpy(m.hdr.id, dht->id, NODE_ID_SIZE);
	(void)memcpy(m.hdr.dyn_x, dht->dyn_x, DYN_X_SIZE);
	(void)memcpy(m.hdr.ip.s6_addr, dht->ip.s6_addr, sizeof(dht->ip.s6_addr));
	m.hdr.port = dht->port;
	(void)memcpy(m.hdr.rpc_id, rpc_id, RPC_ID_SIZE);
	if ((now = time(NULL)) == -1) {
		return -1;
	}
	m.hdr.expiration = now + dht->fixed_timeout; /* TODO: might overflow */

	if (p == NULL) {
		(void)memset(&m.payload, 0, sizeof(m.payload));
	} else {
		m.payload = *p;
	}
	return message_encode(&m, afd, dht->priv, target_id);
}
