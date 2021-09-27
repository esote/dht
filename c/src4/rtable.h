#pragma once

#include <sqlite3.h>

#include "monitor.h"
#include "proto.h"

struct rtable {
	sqlite3 *db;

	sqlite3_stmt *select_old;
	sqlite3_stmt *delete_node;
	sqlite3_stmt *insert_node;
	sqlite3_stmt *select_closest;

	uint8_t self[NODE_ID_SIZE];
	bool (*alive)(void *ctx, const struct node *n);
	void *alive_ctx;
};

#ifndef K
#define K 20
#endif

int rtable_start(int monitor, struct config *config);

int rtable_open(struct rtable *rt, const char *filename, const uint8_t self[NODE_ID_SIZE], bool (*alive)(void *ctx, const struct node *n), void *alive_ctx);
int rtable_close(struct rtable *rt);
int rtable_store(struct rtable *rt, const struct node *n);
int rtable_closest(struct rtable *rt, const uint8_t node_id[NODE_ID_SIZE], struct node closest[K], size_t *len);
