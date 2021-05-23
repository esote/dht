#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "dht.h"
#include "dht_internal.h"
#include "proto.h"

struct dht *
dht_new(const struct dht_config *config)
{
	return NULL;
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

	(void)memcpy(target.id, id, NODE_ID_SIZE);
	(void)memcpy(target.ip.s6_addr, ip->s6_addr, sizeof(ip->s6_addr));
	target.port = port;

	p.fnode.count = K;
	(void)memcpy(p.fnode.target, dht->id, NODE_ID_SIZE);

	if ((afd = connect_remote(ip, port)) == -1) {
		return -1;
	}

	crypto_rand(rpc_id, RPC_ID_SIZE);
	if (send_message(dht, afd, TYPE_FNODE, NULL, &p, id) == -1) {
		(void)close(afd);
		return -1;
	}
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
	if (dht_update(dht, &target) == -1) {
		(void)message_close(msg);
		(void)close(afd);
		return -1;
	}
	for (i = 0; i < msg->payload.fnode_resp.count && i < K; i++) {
		if (dht_update(dht, &msg->payload.fnode_resp.nodes[i]) == -1) {
			(void)message_close(msg);
			(void)close(afd);
			return -1;
		}
	}
	if (message_close(msg) == -1) {
		return -1;
	}
	return close(afd);
}
