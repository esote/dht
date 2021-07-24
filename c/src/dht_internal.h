#ifndef DHT_INTERNAL_H
#define DHT_INTERNAL_H

#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <semaphore.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>
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
#define SOCKET_POLL_TIMEOUT 500

struct dht {
	uint8_t network_id[NETWORK_ID_SIZE];

	char *addr;
	uint8_t dyn_x[DYN_X_SIZE];
	uint16_t port;

	uint8_t id[NODE_ID_SIZE];
	unsigned char priv[PRIV_SIZE];

	pthread_t listeners[LISTENER_COUNT];
	sem_t listen_exit;

	struct rtable rtable;
	struct storer *storer;
};

int socket_timeout(int fd);
int connect_remote(const char *addr, uint16_t port);
int getaddrinfo_port(const char *node, uint16_t port,
	const struct addrinfo *hints, struct addrinfo **res);

int dht_update(struct dht *dht, const struct node *target);
bool ping_node(const struct node *n, void *arg);

#endif /* DHT_INTERNAL_H */
