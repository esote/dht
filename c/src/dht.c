#include <netinet/in.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "dht.h"
#include "dht_internal.h"
#include "listen.h"
#include "proto.h"

struct dht *
dht_new(const struct dht_config *config)
{
	struct dht *dht;
	struct sigaction act;
	size_t i;

	if ((dht = malloc(sizeof(*dht))) == NULL) {
		return NULL;
	}

	/* Copy config */
	(void)memcpy(dht->network_id, config->network_id, NETWORK_ID_SIZE);
	(void)memcpy(dht->ip.s6_addr, config->ip->s6_addr, sizeof(dht->ip.s6_addr));
	dht->port = config->port;
	dht->timeout = config->timeout;
	dht->storer = config->storer;

	/* Create node identity */
	if (new_keypair(dht->id, dht->priv, dht->dyn_x) == -1) {
		free(dht);
		return NULL;
	}

	/* Ignore SIGPIPE */
	(void)memset(&act, 0, sizeof(act));
	if (sigemptyset(&act.sa_mask) == -1) {
		free(dht);
		return NULL;
	}
	act.sa_handler = SIG_IGN;
	if (sigaction(SIGPIPE, &act, NULL) == -1) {
		free(dht);
		return NULL;
	}

	/* Initialize routing table */
	if ((dht->rtable = rtable_new(dht->id, K)) == NULL) {
		free(dht);
		return NULL;
	}

	/* Begin listening for incoming requests */
	for (i = 0; i < LISTENER_COUNT; i++) {
		if (pthread_create(&dht->listeners[i], NULL, listener_start, dht) != 0) {
			while (i-- > 0) {
				(void)pthread_cancel(dht->listeners[i]);
			}
			rtable_free(dht->rtable);
			free(dht);
			return NULL;
		}
	}

	return dht;
}

int
dht_bootstrap(struct dht *dht, const uint8_t id[NODE_ID_SIZE],
	const struct in6_addr *ip, uint16_t port)
{
	uint8_t rpc_id[RPC_ID_SIZE];
	struct node target;
	union payload p;
	struct message *msg;
	size_t i;
	int afd;

	/* Target node */
	(void)memcpy(target.id, id, NODE_ID_SIZE);
	(void)memcpy(target.ip.s6_addr, ip->s6_addr, sizeof(ip->s6_addr));
	target.port = port;

	/* Find node request payload */
	p.fnode.count = K;
	(void)memcpy(p.fnode.target, dht->id, NODE_ID_SIZE);

	if ((afd = connect_remote(ip, port)) == -1) {
		return -1;
	}

	/* Send fnode request */
	crypto_rand(rpc_id, RPC_ID_SIZE);
	if (send_message(dht, afd, TYPE_FNODE, rpc_id, &p, id) == -1) {
		(void)close(afd);
		return -1;
	}

	/* Recv fnode_resp response */
	if ((msg = message_decode(afd, dht->id, dht->priv)) == NULL) {
		(void)close(afd);
		return -1;
	}
	if (msg->hdr.msg_type != TYPE_FNODE_RESP) {
		(void)message_close(msg);
		(void)close(afd);
		return -1;
	}
	if (memcmp(msg->hdr.rpc_id, rpc_id, RPC_ID_SIZE) != 0) {
		(void)message_close(msg);
		(void)close(afd);
		return -1;
	}

	/* Target node is alive, update rtable */
	if (dht_update(dht, &target) == -1) {
		(void)message_close(msg);
		(void)close(afd);
		return -1;
	}

	/* Update rtable with nodes returned by target */
	for (i = 0; i < msg->payload.fnode_resp.count && i < K; i++) {
		if (dht_update(dht, &msg->payload.fnode_resp.nodes[i]) == -1) {
			(void)message_close(msg);
			(void)close(afd);
			return -1;
		}
	}

	if (message_close(msg) == -1) {
		(void)close(afd);
		return -1;
	}
	return close(afd);
}
