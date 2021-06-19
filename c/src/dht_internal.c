#include <netinet/in.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "dht_internal.h"
#include "proto.h"

#define LISTEN_BACKLOG 64

static int socket_reuse(int fd);
static bool ping_node(const struct node *n, void *arg);

int
send_message(const struct dht *dht, int afd, uint16_t msg_type,
	const uint8_t rpc_id[RPC_ID_SIZE], const union payload *p,
	const uint8_t target_id[NODE_ID_SIZE])
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
	m.hdr.expiration = now + dht->timeout; /* TODO: might overflow */

	if (p == NULL) {
		(void)memset(&m.payload, 0, sizeof(m.payload));
	} else {
		m.payload = *p;
	}
	return message_encode(&m, afd, dht->priv, target_id);
}

int
connect_remote(const struct in6_addr *ip, uint16_t port)
{
	int fd;
	struct sockaddr_in6 addr = {0};

	if ((fd = socket(AF_INET6, SOCK_STREAM, 0)) == -1) {
		return -1;
	}
	addr.sin6_family = AF_INET6;
	addr.sin6_port = htons(port);
	(void)memcpy(addr.sin6_addr.s6_addr, ip->s6_addr, sizeof(ip->s6_addr));
	/* TODO: set socket reuse addr, timeouts, etc. ? */
	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		(void)close(fd);
		return -1;
	}
	return fd;
}

int
listen_local(uint16_t port)
{
	int fd;
	struct sockaddr_in6 addr = {0};

	if ((fd = socket(AF_INET6, SOCK_STREAM, 0)) == -1) {
		return -1;
	}
	if (socket_reuse(fd) == -1) {
		(void)close(fd);
		return -1;
	}
	addr.sin6_family = AF_INET6;
	addr.sin6_port = htons(port);
	addr.sin6_addr = in6addr_any;
	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		(void)close(fd);
		return -1;
	}
	if (listen(fd, LISTEN_BACKLOG) == -1) {
		(void)close(fd);
		return -1;
	}
	return fd;
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
	uint8_t rpc_id[RPC_ID_SIZE];
	int afd;
	struct message *msg;
	bool alive;

	if ((afd = connect_remote(&n->ip, n->port)) == -1) {
		return false;
	}
	crypto_rand(rpc_id, RPC_ID_SIZE);
	if (send_message(dht, afd, TYPE_PING, rpc_id, NULL, n->id) == -1) {
		(void)close(afd);
		return false;
	}
	if ((msg = message_decode(afd, dht->id, dht->priv)) == NULL) {
		(void)close(afd);
		return false;
	}

	alive = msg->hdr.msg_type == TYPE_PING
		&& memcmp(msg->hdr.rpc_id, rpc_id, RPC_ID_SIZE) == 0;

	if (message_close(msg) == -1) {
		(void)close(afd);
		return false;
	}
	if (close(afd) == -1) {
		return false;
	}
	return alive;
}

static int
socket_reuse(int fd)
{
	/* TODO: reuse port? */
	int opt = 1;
	return setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
}
