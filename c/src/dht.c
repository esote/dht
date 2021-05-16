#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <assert.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include "proto.h"
#include "rtable.h"

#define K		20
#define LISTEN_BACKLOG	64

struct dht {
	size_t worker_count;
	pthread_t *workers;

	struct rtable *rt;

	time_t fixed_timeout;

	uint8_t network_id[NETWORK_ID_SIZE];

	uint8_t id[NODE_ID_SIZE];
	uint8_t ip[IP_SIZE];
	uint16_t port;
	uint8_t dyn_x[DYN_X_SIZE];
	unsigned char priv[PRIV_SIZE];
};


static int worker_work(struct dht *dht, int afd);
static int respond_msg(struct dht *dht, struct message *req, int afd);
static int respond_ping(struct dht *dht, struct message *req, int afd);
static int respond_store(struct dht *dht, struct message *req, int afd);
static int respond_fnode(struct dht *dht, struct message *req, int afd);
static int respond_fval(struct dht *dht, struct message *req, int afd);
static int send_message(struct dht *dht, int afd, uint16_t msg_type,
	uint8_t rpc_id[RPC_ID_SIZE], union payload *p,
	uint8_t target_id[NODE_ID_SIZE]);
static int socket_reuse(int sfd);

static void *
worker_run(void *arg)
{
	struct dht *dht;
	int sfd, afd;
	struct sockaddr_in addr;
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
	for (;;) {
		if ((afd = accept(sfd, NULL, NULL)) == -1) {
			break;
		}
		/* TODO: setsockopt timeouts */
		if (worker_work(dht, afd) == -1) {
			/* log */
		}
		if (close(afd) == -1) {
			break;
		}
	}
	if (close(sfd) == -1) {
		return NULL;
	}
}

static int
worker_work(struct dht *dht, int afd)
{
	struct message *req;
	if ((req = message_decode(afd, dht->id, dht->priv)) == NULL) {
		return -1;
	}
	if (respond_msg(dht, req, afd) == -1) {
		message_free(req);
		return -1;
	}
	/* add to/update rtable */
	return 0;
}

static int
respond_msg(struct dht *dht, struct message *req, int afd)
{
	switch (req->hdr.msg_type) {
	case TYPE_PING:
		return respond_ping(dht, req, afd);
	case TYPE_STORE:
		return respond_store(dht, req, afd);
	case TYPE_FNODE:
		return respond_fnode(dht, req, afd);
	case TYPE_FVAL:
		return respond_fval(dht, req, afd);
	default:
		return -1;
	}
}

static int
respond_ping(struct dht *dht, struct message *req, int afd)
{
	return send_message(dht, afd, TYPE_PING, req->hdr.rpc_id, NULL, req->hdr.id);
}

static int
respond_store(struct dht *dht, struct message *req, int afd)
{
	return -1; /* TODO */
}

static int
respond_fnode(struct dht *dht, struct message *req, int afd)
{
	/* TODO: error payloads on error */
	struct node_triple *closest;
	size_t len;
	union payload p;
	int ret;
	if (req->payload.fnode.count > K) {
		req->payload.fnode.count = K;
	} else if (req->payload.fnode.count == 0) {
		return -1;
	}
	closest = rtable_closest(dht->rt, req->payload.fnode.target,
		req->payload.fnode.count, &len);
	if (closest == NULL) {
		return -1;
	}
	assert(len <= UINT8_MAX);
	p.fnode_resp.count = (uint8_t)len;
	p.fnode_resp.nodes = closest;

	ret = send_message(dht, afd, TYPE_FNODE_RESP, req->hdr.rpc_id, &p,
		req->hdr.id);
	free(closest);
	return ret;
}

static int
respond_fval(struct dht *dht, struct message *req, int afd)
{
	return -1; /* TODO */
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
	(void)memcpy(m.hdr.ip, dht->ip, IP_SIZE);
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

static int
socket_reuse(int sfd)
{
	/* TODO: reuse port? */
	int opt = 1;
	return setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
}
