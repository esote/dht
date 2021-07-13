#ifndef DHT_INTERNAL_H
#define DHT_INTERNAL_H

#include <netinet/in.h>
#include <pthread.h>
#include <semaphore.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#include "proto.h"
#include "rtable.h"
#include "storer.h"

#define LISTENER_COUNT 3
#if LISTENER_COUNT > SEM_VALUE_MAX
#error listener count invalid
#endif

/* Message expiration time (s) */
#define MSG_EXPIRATION 25

/* Remote connect timeout (s) */
#define CONNECT_TIMEOUT 3000

/* Remote accept timeout (ms) */
#define ACCEPT_TIMEOUT 1000

/* Socket timeout during read/write */
#define SOCKET_TIMEOUT_SEC 1
#define SOCKET_TIMEOUT_USEC 0

/* Socket timeout waiting for available read/write (ms) */
#define SOCKET_POLL_TIMEOUT 1000

struct dht {
	uint8_t network_id[NETWORK_ID_SIZE];

	char *addr;
	uint8_t dyn_x[DYN_X_SIZE];
	uint16_t port;

	uint8_t id[NODE_ID_SIZE];
	unsigned char priv[PRIV_SIZE];

	pthread_t listeners[LISTENER_COUNT];
	sem_t listen_exit;

	struct rtable *rtable;
	struct storer *storer;
};

int send_message(const struct dht *dht, int afd, uint16_t msg_type,
	const uint8_t session_id[SESSION_ID_SIZE], const union payload *p,
	const uint8_t target_id[NODE_ID_SIZE]);

int socket_timeout(int fd);
int connect_remote(const char *addr, uint16_t port);

int dht_update(struct dht *dht, struct node *target);

#endif /* DHT_INTERNAL_H */
