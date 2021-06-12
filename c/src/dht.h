#ifndef DHT_H
#define DHT_H

#include <netinet/in.h>
#include <stdint.h>

#include "proto.h"

#define K 20

struct dht;

struct dht_config {
	uint8_t network_id[NETWORK_ID_SIZE];
	struct in6_addr *ip;
	uint16_t port;
	time_t timeout;

	struct storer *storer;
};

struct dht *dht_new(const struct dht_config *config);
int dht_bootstrap(struct dht *dht, const uint8_t id[NODE_ID_SIZE],
	const struct in6_addr *ip, uint16_t port);

#endif /* DHT_H */
