#pragma once

#include "proto.h"

#define M_DISCOVER 1
#define M_SELF 2
#define M_DECRYPT_REQ 3
#define M_DECRYPT_RESP 4
#define M_ENCRYPT_REQ 5
#define M_ENCRYPT_RESP 6
#define M_PING 7
#define M_FNODE 8
#define M_FNODE_RESP 9
#define M_DATA 10
#define M_FVAL 11

struct decrypt_req {
	uint8_t ephem_publ[EPHEM_PUBL_SIZE];
};

struct decrypt_resp {
	uint8_t ephem_key[EPHEM_KEY_SIZE];
};

struct encrypt_req {
	uint8_t session_id[SESSION_ID_SIZE];
	uint64_t expiration;
	uint8_t target_id[NODE_ID_SIZE];
};

struct encrypt_resp {
	uint8_t sig[SIG_SIZE];
	uint8_t ephem_publ[EPHEM_PUBL_SIZE];
	uint8_t ephem_key[EPHEM_KEY_SIZE];
};

union monitor_payload {
	struct node self;

	struct decrypt_req decrypt_req;
	struct decrypt_resp decrypt_resp;
	struct encrypt_req encrypt_req;
	struct encrypt_resp encrypt_resp;

	struct fnode fnode;
	struct fnode_resp fnode_resp;
	struct data data;
	struct fval fval;
};

struct monitor_message {
	uint8_t type;
	union monitor_payload payload;
};

int monitor_send(int monitor, const struct monitor_message *msg);
int monitor_recv(int monitor, struct monitor_message *msg);
void monitor_message_close(struct monitor_message *msg);
