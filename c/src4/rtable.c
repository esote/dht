#include <assert.h>
#include <sqlite3.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "proto.h"
#include "rtable.h"
#include "util.h"

#ifndef K
#define K 20
#endif

#define CREATE_TABLE ("CREATE TABLE IF NOT EXISTS \"rtable\" (" \
	"\"id\" BLOB PRIMARY KEY NOT NULL," \
	"\"dyn_x\" BLOB NOT NULL," \
	"\"addr\" BLOB NOT NULL," \
	"\"port\" INT NOT NULL," \
	"\"dist\" INT NOT NULL," \
	"\"last_ping\" INT NOT NULL);")

#define BEGIN_TRAN "BEGIN TRANSACTION;"
#define END_TRAN "END TRANSACTION;"
#define ROLLBACK_TRAN "ROLLBACK TRANSACTION;"

#define SELECT_OLD "SELECT \"id\", \"dyn_x\", \"addr\", \"port\" FROM \"rtable\" " \
	"WHERE \"dist\" = @dist " \
	"ORDER BY \"last_ping\" ASC " \
	"LIMIT -1 OFFSET (@k - 1);"

#define DELETE_NODE "DELETE FROM \"rtable\" WHERE \"id\" = @id;"

#define INSERT_NODE "INSERT INTO \"rtable\" (\"id\", \"dyn_x\", \"addr\", \"port\", \"dist\", \"last_ping\") " \
	"VALUES (@id, @dyn_x, @addr, @port, @dist, strftime('%s', 'now'))"

static int select_old(struct rtable *rt, int dist, bool *insert);
static int delete_node(struct rtable *rt, const uint8_t node_id[NODE_ID_SIZE]);
static int insert_node(struct rtable *rt, const struct node *n, int dist);

/* TODO: log sqlite3 errors if ret != SQLITE_OK, errmsg for sqlite3_exec */
int
rtable_open(struct rtable *rt, const char *filename, const uint8_t self[NODE_ID_SIZE], bool (*alive)(void *ctx, const struct node *n), void *alive_ctx)
{
	if (sqlite3_open(filename, &rt->db) != SQLITE_OK) {
		assert(sqlite3_close(rt->db) == SQLITE_OK);
		return -1;
	}

	if (sqlite3_exec(rt->db, CREATE_TABLE, NULL, NULL, NULL) != SQLITE_OK) {
		assert(sqlite3_close(rt->db) == SQLITE_OK);
		return -1;
	}

	rt->alive = alive;
	rt->alive_ctx = alive_ctx;
	memcpy(rt->self, self, sizeof(rt->self));

	return 0;
}

int
rtable_close(struct rtable *rt)
{
	if (sqlite3_close(rt->db) != SQLITE_OK) {
		return -1;
	}

	return 0;
}

int
rtable_store(struct rtable *rt, const struct node *n)
{
	bool insert = false;
	int dist = (int)lcp(rt->self, n->id, sizeof(rt->self));

	if (sqlite3_exec(rt->db, BEGIN_TRAN, NULL, NULL, NULL) != SQLITE_OK) {
		return -1;
	}

	if (select_old(rt, dist, &insert) == -1) {
		assert(sqlite3_exec(rt->db, ROLLBACK_TRAN, NULL, NULL, NULL) == SQLITE_OK);
		return -1;
	}

	if (!insert) {
		/* rtable bucket full */
		assert(sqlite3_exec(rt->db, ROLLBACK_TRAN, NULL, NULL, NULL) == SQLITE_OK);
		return -1;
	}

	if (insert_node(rt, n, dist) == -1) {
		assert(sqlite3_exec(rt->db, ROLLBACK_TRAN, NULL, NULL, NULL) == SQLITE_OK);
		return -1;
	}

	if (sqlite3_exec(rt->db, END_TRAN, NULL, NULL, NULL) != SQLITE_OK) {
		assert(sqlite3_exec(rt->db, ROLLBACK_TRAN, NULL, NULL, NULL) == SQLITE_OK);
		return -1;
	}

	return 0;
}

static int
select_old(struct rtable *rt, int dist, bool *insert)
{
	sqlite3_stmt *stmt;
	struct node row;
	const void *blob;
	int length, port;
	bool was_full = false;
	*insert = false;

	if (sqlite3_prepare_v2(rt->db, SELECT_OLD, -1, &stmt, NULL) != SQLITE_OK) {
		return -1;
	}

	/* @dist */
	if (sqlite3_bind_int(stmt, 1, dist) != SQLITE_OK) {
		assert(sqlite3_finalize(stmt) == SQLITE_OK);
		return -1;
	}

	/* @k */
	if (sqlite3_bind_int(stmt, 2, K) != SQLITE_OK) {
		assert(sqlite3_finalize(stmt) == SQLITE_OK);
		return -1;
	}

	while (sqlite3_step(stmt) == SQLITE_ROW) {
		was_full = true;

		assert(sqlite3_column_count(stmt) == 4);

		assert(sqlite3_column_type(stmt, 0) == SQLITE_BLOB);
		assert(sqlite3_column_bytes(stmt, 0) == sizeof(row.id));
		assert((blob = sqlite3_column_blob(stmt, 0)) != NULL);
		memcpy(row.id, blob, sizeof(row.id));

		assert(sqlite3_column_type(stmt, 1) == SQLITE_BLOB);
		assert(sqlite3_column_bytes(stmt, 1) == sizeof(row.dyn_x));
		assert((blob = sqlite3_column_blob(stmt, 0)) != NULL);
		memcpy(row.dyn_x, blob, sizeof(row.dyn_x));

		assert(sqlite3_column_type(stmt, 2) == SQLITE_BLOB);
		static_assert(sizeof(row.addr) - 1 == UINT8_MAX);
		assert((length = sqlite3_column_bytes(stmt, 2)) <= sizeof(row.addr) - 1);
		row.addrlen = (uint8_t)length;
		assert((blob = sqlite3_column_blob(stmt, 2)) != NULL);
		memcpy(row.addr, blob, row.addrlen);
		row.addr[row.addrlen] = '\0';

		assert(sqlite3_column_type(stmt, 3) == SQLITE_INTEGER);
		assert((port = sqlite3_column_int(stmt, 3)) > 0 && port <= UINT16_MAX);
		row.port = (uint16_t)port;

		if (!rt->alive(rt->alive_ctx, &row)) {
			if (delete_node(rt, row.id) == -1) {
				assert(sqlite3_finalize(stmt) == SQLITE_OK);
				return -1;
			}
			*insert = true;
		}
	}

	if (sqlite3_finalize(stmt) != SQLITE_OK) {
		return -1;
	}

	*insert = *insert || !was_full;
	return 0;
}

static int
delete_node(struct rtable *rt, const uint8_t node_id[NODE_ID_SIZE])
{
	sqlite3_stmt *stmt;

	if (sqlite3_prepare_v2(rt->db, DELETE_NODE, -1, &stmt, NULL) != SQLITE_OK) {
		return -1;
	}

	/* @id */
	if (sqlite3_bind_blob(stmt, 1, node_id, NODE_ID_SIZE, SQLITE_STATIC) != SQLITE_OK) {
		assert(sqlite3_finalize(stmt) == SQLITE_OK);
		return -1;
	}

	if (sqlite3_step(stmt) != SQLITE_DONE) {
		assert(sqlite3_finalize(stmt) == SQLITE_OK);
		return -1;
	}

	if (sqlite3_finalize(stmt) != SQLITE_OK) {
		return -1;
	}

	return 0;
}

static int
insert_node(struct rtable *rt, const struct node *n, int dist)
{
	sqlite3_stmt *stmt;

	if (sqlite3_prepare_v2(rt->db, INSERT_NODE, -1, &stmt, NULL) != SQLITE_OK) {
		return -1;
	}

	/* @id */
	if (sqlite3_bind_blob(stmt, 1, n->id, sizeof(n->id), SQLITE_STATIC) != SQLITE_OK) {
		assert(sqlite3_finalize(stmt) == SQLITE_OK);
		return -1;
	}

	/* @dyn_x */
	if (sqlite3_bind_blob(stmt, 2, n->dyn_x, sizeof(n->dyn_x), SQLITE_STATIC) != SQLITE_OK) {
		assert(sqlite3_finalize(stmt) == SQLITE_OK);
		return -1;
	}

	/* @addr */
	if (sqlite3_bind_blob(stmt, 3, n->addr, n->addrlen, SQLITE_STATIC) != SQLITE_OK) {
		assert(sqlite3_finalize(stmt) == SQLITE_OK);
		return -1;
	}

	/* @port */
	if (sqlite3_bind_int(stmt, 4, n->port) != SQLITE_OK) {
		assert(sqlite3_finalize(stmt) == SQLITE_OK);
		return -1;
	}

	/* @dist */
	if (sqlite3_bind_int(stmt, 5, dist) != SQLITE_OK) {
		assert(sqlite3_finalize(stmt) == SQLITE_OK);
		return -1;
	}

	if (sqlite3_step(stmt) != SQLITE_DONE) {
		assert(sqlite3_finalize(stmt) == SQLITE_OK);
		return -1;
	}

	if (sqlite3_finalize(stmt) != SQLITE_OK) {
		return -1;
	}

	return 0;
}
