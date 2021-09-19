#pragma once

#include <sqlite3.h>
#include <stdint.h>

#include "proto.h"

struct rtable {
	sqlite3 *db;
	uint8_t self[NODE_ID_SIZE];
	bool (*alive)(void *ctx, const struct node *n);
	void *alive_ctx;
};

int rtable_open(struct rtable *rt, const char *filename, const uint8_t self[NODE_ID_SIZE], bool (*alive)(void *ctx, const struct node *n), void *alive_ctx);
int rtable_close(struct rtable *rt);
int rtable_store(struct rtable *rt, const struct node *n);
