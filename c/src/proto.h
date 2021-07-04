#ifndef DHT_PROTO_H
#define DHT_PROTO_H

#include <netinet/in.h>
#include <stdint.h>
#include <time.h>

#include "crypto.h"
#include "io.h"

#define VERSION 0
#define SESSION_ID_SIZE 20
#define NETWORK_ID_SIZE 8
#define NODE_ID_SIZE PUBL_SIZE
#define DYN_X_SIZE SHA3_512_SIZE

#define KEY_SIZE SHA2_512_SIZE
#if KEY_SIZE < NODE_ID_SIZE
#error key cannot be used with XOR metric
#endif

#define TYPE_PING 0
#define TYPE_DATA 1
#define TYPE_FNODE 2
#define TYPE_FNODE_RESP 3
#define TYPE_FVAL 4

struct data_payload {
	uint8_t key[KEY_SIZE];
	uint64_t length;
	int value;
};

struct fnode_payload {
	uint8_t count;
	uint8_t target_id[NODE_ID_SIZE];
	uint8_t target_dyn_x[DYN_X_SIZE];
};

struct node {
	uint8_t id[NODE_ID_SIZE];
	uint8_t dyn_x[DYN_X_SIZE];
	char *addr;
	uint16_t port;
};

struct fnode_resp_payload {
	uint8_t count;
	struct node *nodes;
};

struct fval_payload {
	uint8_t key[KEY_SIZE];
};

union payload {
	struct data_payload data;
	struct fnode_payload fnode;
	struct fnode_resp_payload fnode_resp;
	struct fval_payload fval;
};

struct header {
	uint8_t session_id[SESSION_ID_SIZE];
	time_t expiration;
	uint8_t network_id[NETWORK_ID_SIZE];
	uint16_t msg_type;
	struct node node;
};

struct message {
	uint16_t version;
	struct header hdr;
	union payload payload;

	int _child;
};

int message_encode(const struct message *m, int out,
	const unsigned char priv[PRIV_SIZE],
	const unsigned char target_publ[PUBL_SIZE]);
struct message *message_decode(int in,
	const unsigned char publ[PUBL_SIZE],
	const unsigned char priv[PRIV_SIZE]);
int message_close(struct message *m);

#endif /* DHT_PROTO_H */
