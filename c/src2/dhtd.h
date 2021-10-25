#pragma once

#include <err.h> /* TODO: temp */
#include "crypto.h"

#define nitems(x) (sizeof((x)) / sizeof((x)[0]))
#define _PATH_DEVNULL "/dev/null"

#define DHTD_USER "dhtd"
#define DHTD_NUMPROC 1

#define CONTROL_FILENO 3

#define PARENT_ROOT "/var/empty/"
#define LISTEN_ROOT "/var/empty/"
#define RTABLE_ROOT "/tmp/dhtd/"

enum procid {
	PROC_PARENT,
	PROC_LISTEN,
	PROC_RTABLE,
	PROC_MAX
};

struct pipe {
	int fd;
	struct imsgbuf ibuf;
	struct event *event;
};

struct proc {
	char *title;
	enum procid id;
	const char *root;
	int (*start)(void);

	struct event_base *evbase;

	struct event *evsigint;
	struct event *evsigterm;
	struct event *evsigchld;
	struct event *evsigpipe;

	/* only initialized in parent */
	struct pipe pipes[PROC_MAX][DHTD_NUMPROC];
};

/* protocol */
enum message_type {
	PING = 0,
	FNODE = 1,
	FNODE_RESP = 2,
	DATA = 3,
	FVAL = 4
};

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

struct header {
	uint8_t session_id[SESSION_ID_SIZE];
	uint8_t network_id[NETWORK_ID_SIZE];
	uint8_t type;
	struct node node;
};

struct message {
	struct header header;
	union {
		struct fnode fnode;
		struct fnode_resp fnode_resp;
		struct data data;
		struct fval fval;
	};
};


/* ipc */
enum imsg_type {
	IMSG_CONFIG
};

struct config {
	uint8_t network_id[NETWORK_ID_SIZE];
	struct node node;
};

/* parent.c */
int parent_start(void);

/* listen.c */
int listen_start(void);

/* rtable.c */
int rtable_start(void);
