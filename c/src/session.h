#ifndef DHT_SESSION_H
#define DHT_SESSION_H

#include <stdbool.h>
#include <stdint.h>

#include "dht.h"
#include "proto.h"

struct session {
	bool set;

	uint8_t target_id[NODE_ID_SIZE];
	uint8_t session_id[SESSION_ID_SIZE];

	struct dht *dht;
	int fd;
};


void session_init(struct session *s, struct dht *dht,
	const uint8_t target_id[NODE_ID_SIZE], int fd);
int session_send(struct session *s, uint16_t msg_type,
	const union payload *p);
int session_recv(struct session *s, struct message *m);

#endif /* DHT_SESSION_H */
