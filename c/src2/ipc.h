#pragma once

#include <stdint.h>

#define ADDR_MAX_SIZE UINT8_MAX
#define MSG_MAX_SIZE UINT8_MAX
#include "proto.h"

#define IPC_TYPE_BOOTSTRAP 0
#define IPC_TYPE_DATA 1
#define IPC_TYPE_LOAD 2
#define IPC_TYPE_ERROR 3

struct ipc_bootstrap {
	uint8_t id[NODE_ID_SIZE];
	uint8_t dyn_x[DYN_X_SIZE];
	uint8_t addrlen;
	char addr[ADDR_MAX_SIZE];
	uint16_t port;
};

struct ipc_data {
	uint8_t key[KEY_SIZE];
	uint64_t length;
	int value;
};

struct ipc_load {
	uint8_t key[KEY_SIZE];
};

struct ipc_error {
	uint8_t msglen;
	char msg[MSG_MAX_SIZE];
};

union ipc_payload {
	struct ipc_bootstrap bootstrap;
	struct ipc_data data;
	struct ipc_load load;
	struct ipc_error error;
};

struct ipc_message {
	uint8_t type;
	union ipc_payload payload;
};

int ipc_encode(int out, const struct ipc_message *m);
int ipc_decode(int in, struct ipc_message *m);
