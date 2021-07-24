#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "dht_internal.h"
#include "proto.h"
#include "session.h"
#include "util.h"

void
session_init(struct session *s, struct dht *dht,
	const uint8_t target_id[NODE_ID_SIZE], int fd)
{
	s->set = target_id != NULL;
	if (s->set) {
		(void)memcpy(s->target_id, target_id, NODE_ID_SIZE);
		crypto_rand(s->session_id, SESSION_ID_SIZE);
	}
	s->dht = dht;
	s->fd = fd;
}

int
session_send(struct session *s, uint16_t msg_type, const union payload *p)
{
	struct message m;
	time_t now;

	if (!s->set) {
		return -1;
	}

	(void)memcpy(m.hdr.session_id, s->session_id, SESSION_ID_SIZE);
	if ((now = time(NULL)) == -1 || now > (INT64_MAX - MSG_EXPIRATION)) {
		return -1;
	}
	m.hdr.expiration = now + MSG_EXPIRATION;

	(void)memcpy(m.hdr.network_id, s->dht->network_id, NETWORK_ID_SIZE);
	m.hdr.msg_type = msg_type;
	(void)memcpy(m.hdr.node.id, s->dht->id, NODE_ID_SIZE);
	(void)memcpy(m.hdr.node.dyn_x, s->dht->dyn_x, DYN_X_SIZE);
	if (string_empty(s->dht->addr)) {
		m.hdr.node.addr = NULL;
	} else if ((m.hdr.node.addr = strdup(s->dht->addr)) == NULL) {
		return -1;
	}
	m.hdr.node.port = s->dht->port;

	if (p == NULL) {
		(void)memset(&m.payload, 0, sizeof(m.payload));
	} else {
		m.payload = *p;
	}

	if (message_encode(&m, s->fd, s->dht->priv, s->target_id) == -1) {
		free(m.hdr.node.addr);
		return -1;
	}

	free(m.hdr.node.addr);
	return 0;
}

int
session_recv(struct session *s, struct message *m)
{
	if (message_decode(m, s->fd, s->dht->id, s->dht->priv) == -1) {
		return -1;
	}

	if (!s->set) {
		(void)memcpy(s->target_id, m->hdr.node.id, NODE_ID_SIZE);
		(void)memcpy(s->session_id, m->hdr.session_id, SESSION_ID_SIZE);
		s->set = true;
	} else if (memcmp(m->hdr.session_id, s->session_id, SESSION_ID_SIZE) != 0) {
		(void)message_close(m);
		return -1;
	}

	return 0;
}
