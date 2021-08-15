#pragma once

struct node {
	uint8_t id[NODE_ID_SIZE];
	uint8_t dyn_x[DYN_X_SIZE];
	uint8_t addrlen;
	uint8_t *addr;
	uint16_t port;
};

struct data {
	uint8_t key[KEY_SIZE];
	uint64_t length;
	int value;
};

struct fnode {
	uint8_t count;
	uint8_t target_id[NODE_ID_SIZE];
};

struct fnode_resp {
	uint8_t count;
	struct node *nodes;
};

struct fval {
	uint8_t key[KEY_SIZE];
};

union payload {
	struct data data;
	struct fnode fnode;
	struct fnode_resp fnode_resp;
	struct fval fval;
};

struct header {
	uint8_t ver;
	uint8_t session_id[SESSION_ID_SIZE];
	uint64_t exp;
	uint8_t net_id[NET_ID_SIZE];
	uint8_t type;
	struct node node;
	uint8_t sig[SIG_SIZE];
};

struct message {
	uint16_t hdrlen;
	struct header hdr;
	uint64_t payloadlen;
	union payload payload;
};

#define NODE_SIZE(addrlen) (sizeof(((struct node *)0)->id)	\
	+ sizeof(((struct node *)0)->dyn_x)			\
	+ sizeof(((struct node *)0)->addrlen)			\
	+ (addrlen)						\
	+ sizeof(((struct node *)0)->port))

#define HEADER_SIZE(addrlen) (sizeof(((struct header *)0)->ver)	\
	+ sizeof(((struct header *)0)->session_id)		\
	+ sizeof(((struct header *)0)->exp)			\
	+ sizeof(((struct header *)0)->net_id)			\
	+ sizeof(((struct header *)0)->type)			\
	+ NODE_SIZE(addrlen)					\
	+ sizeof(((struct header *)0)->sig))

#define DATA_IOV_SIZE (sizeof(((struct data *)0)->key)	\
	+ sizeof(((struct data *)0)->length))

#define FNODE_SIZE (sizeof(((struct fnode *)0)->count)	\
	+ sizeof(((struct fnode *)0)->target_id))

#define FNODE_RESP_MAX_SIZE(count) (sizeof(((struct fnode_resp *)0)->count)	\
	+ ((count) * (NODE_SIZE(UINT8_MAX))))

#define FVAL_SIZE (sizeof(((struct fval *)0)->key))

ssize_t encode_node(void *buf, size_t len, const struct node *n);
