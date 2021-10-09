#pragma once

#include <pthread.h>

#include "crypto.h"

#define TYPE_PING 0
#define TYPE_FNODE 1
#define TYPE_FNODE_RESP 2
#define TYPE_DATA 3
#define TYPE_FVAL 4

#define NODE_ID_SIZE PUBL_SIZE
#define DYN_X_SIZE SHA3_512_SIZE
#define KEY_SIZE SHA2_512_SIZE
#define SESSION_ID_SIZE 20
#define NETWORK_ID_SIZE 32

struct node {
	uint8_t id[NODE_ID_SIZE];
	uint8_t dyn_x[DYN_X_SIZE];
	uint8_t addrlen;
	uint8_t addr[UINT8_MAX + 1];
	uint16_t port;
};

struct fnode {
	uint8_t count;
	uint8_t target_id[NODE_ID_SIZE];
};

struct fnode_resp {
	uint8_t count;
	struct node *nodes;
};

struct data {
	uint8_t key[KEY_SIZE];
	uint64_t length;
	int value;
};

struct fval {
	uint8_t key[KEY_SIZE];
};

union payload {
	struct fnode fnode;
	struct fnode_resp fnode_resp;
	struct data data;
	struct fval fval;
};

struct header {
	uint8_t session_id[SESSION_ID_SIZE];
	uint8_t network_id[NETWORK_ID_SIZE];
	uint8_t type;
	struct node node;
};

struct message {
	struct header header;
	union payload payload;

	pthread_t th;
	int pipefd[2];
};

int message_send(int monitor, int out, struct message *msg, const uint8_t target_id[NODE_ID_SIZE]);
int message_recv(int monitor, int in, struct message *msg);
int message_close(struct message *msg);

int encode_node(int out, const struct node *node);
int encode_fnode(int out, const struct fnode *fnode);
int encode_fnode_resp(int out, const struct fnode_resp *fnode_resp);
int encode_fval(int out, const struct fval *fval);

int decode_node(int in, struct node *node);
int decode_fnode(int in, struct fnode *fnode);
int decode_fnode_resp(int in, struct fnode_resp *fnode_resp);
int decode_fval(int in, struct fval *fval);
