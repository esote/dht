#ifndef DHT_PROTO_H
#define DHT_PROTO_H

#include <sodium.h>
#include "crypto.h"
#include "io.h"

#define VERSION 0
#define NETWORK_ID_SIZE 8
#define NODE_ID_SIZE PUBL_SIZE
#define DYN_X_SIZE 64 /* TODO: define using libsodium sha3.512 size */
#define IP_SIZE 16 /* TODO: define IP as struct in6_addr, see ipv6(7) */
#define RPC_ID_SIZE 20
#define NONCE_SIZE 16
#define SIG_SIZE crypto_sign_BYTES /* TODO: check equals 64 */

#define KEY_SIZE 64 /* TODO: sha512.size */
#if KEY_SIZE < NODE_ID_SIZE
#error key cannot be used with XOR metric
#endif

#define TYPE_PING 0
#define TYPE_STORE 1
#define TYPE_DATA 2
#define TYPE_FNODE 3
#define TYPE_FNODE_RESP 4
#define TYPE_FVAL 5
#define TYPE_ERR 6

struct store_payload {
	uint8_t key[KEY_SIZE];
	uint64_t length;
};

struct data_payload {
	uint64_t length;
	struct io *value;
};

struct fnode_payload {
	uint8_t count;
	uint8_t target[NODE_ID_SIZE];
};

struct node_triple {
	uint8_t id[NODE_ID_SIZE];
	uint8_t ip[IP_SIZE];
	uint16_t port;
};

struct fnode_resp_payload {
	uint8_t count;
	struct node_triple *nodes;
};

struct fval_payload {
	uint8_t key[KEY_SIZE];
};

struct err_payload {
	uint8_t length;
	void *msg;
};

union payload {
	struct store_payload store;
	struct data_payload data;
	struct fnode_payload fnode;
	struct fnode_resp_payload fnode_resp;
	struct fval_payload fval;
	struct err_payload err;
};

struct header {
	uint8_t network_id[NETWORK_ID_SIZE];
	uint16_t msg_type;
	uint8_t id[NODE_ID_SIZE];
	uint8_t dyn_x[DYN_X_SIZE];
	uint8_t ip[IP_SIZE];
	uint16_t port;
	uint8_t rpc_id[RPC_ID_SIZE];
	time_t expiration;
	/* uint8_t nonce[NONCE_SIZE]; */ /* excluded from header */
	/* uint8_t sig[SIG_SIZE]; */ /* excluded from header */
};

struct message {
	uint16_t version;
	struct header hdr;
	union payload payload;
};

int message_encode(const struct message *m, int out,
	const unsigned char priv[PRIV_SIZE],
	const unsigned char target_publ[PUBL_SIZE]);
struct message *message_decode(int in,
	const unsigned char publ[PUBL_SIZE],
	const unsigned char priv[PRIV_SIZE]);
void message_free(struct message *m);

#endif /* DHT_PROTO_H */
