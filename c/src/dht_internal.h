#ifndef DHT_INTERNAL_H
#define DHT_INTERNAL_H

#include <netinet/in.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#include "proto.h"
#include "rtable.h"
#include "storer.h"

struct dht {
	size_t worker_count;
	pthread_t *workers;

	struct rtable *rtable;
	struct storer *storer;

	time_t fixed_timeout;

	uint8_t network_id[NETWORK_ID_SIZE];

	uint8_t id[NODE_ID_SIZE];
	struct in6_addr ip;
	uint16_t port;
	uint8_t dyn_x[DYN_X_SIZE];
	unsigned char priv[PRIV_SIZE];
};

int send_message(const struct dht *dht, int afd, uint16_t msg_type,
	const uint8_t rpc_id[RPC_ID_SIZE], const union payload *p,
	const uint8_t target_id[NODE_ID_SIZE]);

int connect_remote(const struct in6_addr *ip, uint16_t port);
int listen_local(uint16_t port);

int dht_update(struct dht *dht, struct node *target);

#endif /* DHT_INTERNAL_H */
