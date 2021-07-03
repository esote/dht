#include <assert.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "dht_internal.h"
#include "proto.h"

#define LISTEN_BACKLOG 64

static int socket_reuse(int fd);
static bool ping_node(const struct node *n, void *arg);

int
send_message(const struct dht *dht, int afd, uint16_t msg_type,
	const uint8_t session_id[SESSION_ID_SIZE], const union payload *p,
	const uint8_t target_id[NODE_ID_SIZE])
{
	struct message m;
	time_t now;

	m.version = VERSION;

	(void)memcpy(m.hdr.session_id, session_id, SESSION_ID_SIZE);
	if ((now = time(NULL)) == -1) {
		return -1;
	}
	m.hdr.expiration = now + dht->timeout; /* TODO: might overflow */
	(void)memcpy(m.hdr.network_id, dht->network_id, NETWORK_ID_SIZE);
	m.hdr.msg_type = msg_type;

	(void)memcpy(m.hdr.node.id, dht->id, NODE_ID_SIZE);
	(void)memcpy(m.hdr.node.dyn_x, dht->dyn_x, DYN_X_SIZE);
	if ((m.hdr.node.addr = strdup(dht->addr)) == NULL) {
		/* TODO: if strlen(dht->addr) == 0 null might be right */
		return -1;
	}
	m.hdr.node.port = dht->port;

	if (p == NULL) {
		(void)memset(&m.payload, 0, sizeof(m.payload));
	} else {
		m.payload = *p;
	}
	if (message_encode(&m, afd, dht->priv, target_id) == -1) {
		free(m.hdr.node.addr);
		return -1;
	}
	free(m.hdr.node.addr);
	return 0;
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

	if (getaddrinfo(addr, str_port, &hints, &result)) {
		/*  TODO: print return value, retry? */
		return -1;
	}

	for (rp = result; rp != NULL; rp = rp->ai_next) {
		fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (fd == -1) {
			continue;
		}
		if (connect(fd, rp->ai_addr, rp->ai_addrlen) != -1) {
			break;
		}
		if (close(fd) == -1) {
			freeaddrinfo(result);
			return -1;
		}
	}

	freeaddrinfo(result);

	if (rp == NULL) {
		/* no address succeeded */
		return -1;
	}

	return fd;
}

int
listen_local(uint16_t port)
{
	int fd;
	struct sockaddr_in6 addr = {0};

	if ((fd = socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK, 0)) == -1) {
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

static int
socket_reuse(int fd)
{
	int opt = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) == -1) {
		return 1;
	}
	return setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
}
