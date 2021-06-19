#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <semaphore.h>
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

static int listener_accept(struct dht *dht, int sfd);
static int listener_work(struct dht *dht, int afd);
static bool listener_should_exit(struct dht *dht);
static int respond_msg(struct dht *dht, int afd, const struct message *msg);
static int respond_ping(const struct dht *dht, int afd, const struct message *msg);
static int respond_data(struct dht *dht, int afd, const struct message *msg);
static int respond_fnode(const struct dht *dht, int afd, const struct message *msg);
static int send_fnode_closest(const struct dht *dht, int afd,
	const uint8_t id[NODE_ID_SIZE], size_t k, const uint8_t rpc_id[RPC_ID_SIZE],
	const uint8_t target[NODE_ID_SIZE]);
static int respond_fval(const struct dht *dht, int afd, const struct message *req);

static int listen_success = 0;

void *
listener_start(void *arg)
{
	struct dht *dht;
	int sfd;

	dht = arg;
	if ((sfd = listen_local(dht->port)) == -1) {
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
	(void)memcpy(target.id, msg->hdr.id, NODE_ID_SIZE);
	target.ip = msg->hdr.ip;
	target.port = msg->hdr.port;
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
	return send_message(dht, afd, TYPE_PING, msg->hdr.rpc_id, NULL,
		msg->hdr.id);
}

static int
respond_data(struct dht *dht, int afd, const struct message *msg)
{
	if (storer_store(dht->storer, msg->payload.data.key, KEY_SIZE,
		msg->payload.data.value, msg->payload.data.length) == -1) {
		return -1;
	}
	return send_message(dht, afd, TYPE_PING, msg->hdr.rpc_id, NULL,
		msg->hdr.id);
}

static int
respond_fnode(const struct dht *dht, int afd, const struct message *msg)
{
	return send_fnode_closest(dht, afd, msg->payload.fnode.target,
		msg->payload.fnode.count, msg->hdr.rpc_id, msg->hdr.id);
}

static int
send_fnode_closest(const struct dht *dht, int afd, const uint8_t id[NODE_ID_SIZE],
	size_t k, const uint8_t rpc_id[RPC_ID_SIZE], const uint8_t target[NODE_ID_SIZE])
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
	ret = send_message(dht, afd, TYPE_FNODE_RESP, rpc_id, &p, target);
	free(closest);
	return ret;
}

static int
respond_fval(const struct dht *dht, int afd, const struct message *req)
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
