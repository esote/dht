#include <assert.h>
#include <sqlite3.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "proto.h"
#include "rtable.h"
#include "util.h"

#define CREATE_TABLE "CREATE TABLE IF NOT EXISTS \"rtable\" (" \
	"\"id\" BLOB PRIMARY KEY NOT NULL," \
	"\"dyn_x\" BLOB NOT NULL," \
	"\"addr\" BLOB NOT NULL," \
	"\"port\" INT NOT NULL," \
	"\"dist\" INT NOT NULL," \
	"\"last_ping\" INT NOT NULL);"

#define BEGIN_TRAN "BEGIN TRANSACTION;"
#define END_TRAN "END TRANSACTION;"
#define ROLLBACK_TRAN "ROLLBACK TRANSACTION;"

static int db_restrict(sqlite3 *db);
static int db_prepare(struct rtable *rt);
static int select_old(struct rtable *rt, int dist, bool *insert);
static int delete_node(struct rtable *rt, const uint8_t node_id[NODE_ID_SIZE]);
static int insert_node(struct rtable *rt, const struct node *n, int dist);
static int decode_node_row(sqlite3_stmt *stmt, struct node *n);

/* TODO: log sqlite3 errors if ret != SQLITE_OK, errmsg for sqlite3_exec */
int
rtable_open(struct rtable *rt, const char *filename, const uint8_t self[NODE_ID_SIZE], bool (*alive)(void *ctx, const struct node *n), void *alive_ctx)
{
	if (sqlite3_open(filename, &rt->db) != SQLITE_OK) {
		assert(sqlite3_close(rt->db) == SQLITE_OK);
		return -1;
	}

	if (db_restrict(rt->db) == -1) {
		assert(sqlite3_close(rt->db) == SQLITE_OK);
		return -1;
	}

	if (sqlite3_exec(rt->db, CREATE_TABLE, NULL, NULL, NULL) != SQLITE_OK) {
		assert(sqlite3_close(rt->db) == SQLITE_OK);
		return -1;
	}

	if (db_prepare(rt) == -1) {
		assert(sqlite3_close(rt->db) == SQLITE_OK);
		return -1;
	}

	rt->alive = alive;
	rt->alive_ctx = alive_ctx;
	memcpy(rt->self, self, sizeof(rt->self));

	return 0;
}

static int
db_restrict(sqlite3 *db)
{
	sqlite3_stmt *stmt;

	if (sqlite3_db_config(db, SQLITE_DBCONFIG_DEFENSIVE, 1, 0) != SQLITE_OK) {
		return -1;
	}

	if (sqlite3_db_config(db, SQLITE_DBCONFIG_TRUSTED_SCHEMA, 0, 0) != SQLITE_OK) {
		return -1;
	}

	if (sqlite3_db_config(db, SQLITE_DBCONFIG_ENABLE_TRIGGER, 0, 0) != SQLITE_OK) {
		return -1;
	}

	if (sqlite3_db_config(db, SQLITE_DBCONFIG_ENABLE_VIEW, 0, 0) != SQLITE_OK) {
		return -1;
	}

	/* values from https://sqlite.org/security.html */
	sqlite3_limit(db, SQLITE_LIMIT_LENGTH, 1e6);
	sqlite3_limit(db, SQLITE_LIMIT_SQL_LENGTH, 1e5);
	sqlite3_limit(db, SQLITE_LIMIT_COLUMN, 100);
	sqlite3_limit(db, SQLITE_LIMIT_EXPR_DEPTH, 10);
	sqlite3_limit(db, SQLITE_LIMIT_COMPOUND_SELECT, 3);
	sqlite3_limit(db, SQLITE_LIMIT_VDBE_OP, 25000);
	sqlite3_limit(db, SQLITE_LIMIT_FUNCTION_ARG, 8);
	sqlite3_limit(db, SQLITE_LIMIT_ATTACHED, 0);
	sqlite3_limit(db, SQLITE_LIMIT_LIKE_PATTERN_LENGTH, 50);
	sqlite3_limit(db, SQLITE_LIMIT_VARIABLE_NUMBER, 10);
	sqlite3_limit(db, SQLITE_LIMIT_TRIGGER_DEPTH, 10);

	/* TODO: sqlite3_set_authorizer */

	/* TODO: sqlite3_progress_handler or sqlite3_interrupt */

	/* TODO: sqlite3_hard_heap_limit64 */

	if (sqlite3_prepare_v2(db, "PRAGMA integrity_check", -1, &stmt, NULL) != SQLITE_OK) {
		return -1;
	}
	if (sqlite3_step(stmt) != SQLITE_ROW) {
		sqlite3_finalize(stmt);
		return -1;
	}
	/* check returned 'ok' */
	assert(sqlite3_column_count(stmt) == 1);
	assert(sqlite3_column_type(stmt, 0) == SQLITE_TEXT);
	assert(sqlite3_column_bytes(stmt, 0) == 2);
	assert(strncmp((const char *)sqlite3_column_text(stmt, 0), "ok", 2) == 0);
	if (sqlite3_step(stmt) != SQLITE_DONE) {
		sqlite3_finalize(stmt);
		return -1;
	}
	if (sqlite3_finalize(stmt) != SQLITE_OK) {
		return -1;
	}

	if (sqlite3_prepare_v2(db, "PRAGMA cell_size_check=ON", -1, &stmt, NULL) != SQLITE_OK) {
		return -1;
	}
	if (sqlite3_step(stmt) != SQLITE_DONE) {
		sqlite3_finalize(stmt);
		return -1;
	}
	if (sqlite3_finalize(stmt) != SQLITE_OK) {
		return -1;
	}

	if (sqlite3_prepare_v2(db, "PRAGMA mmap_size=0", -1, &stmt, NULL) != SQLITE_OK) {
		return -1;
	}
	if (sqlite3_step(stmt) != SQLITE_ROW) {
		sqlite3_finalize(stmt);
		return -1;
	}
	/* check returned 0 */
	assert(sqlite3_column_count(stmt) == 1);
	assert(sqlite3_column_type(stmt, 0) == SQLITE_INTEGER);
	assert(sqlite3_column_int(stmt, 0) == 0);
	if (sqlite3_step(stmt) != SQLITE_DONE) {
		sqlite3_finalize(stmt);
		return -1;
	}
	if (sqlite3_finalize(stmt) != SQLITE_OK) {
		return -1;
	}

	if (sqlite3_prepare_v2(db, "PRAGMA secure_delete=ON", -1, &stmt, NULL) != SQLITE_OK) {
		return -1;
	}
	if (sqlite3_step(stmt) != SQLITE_ROW) {
		sqlite3_finalize(stmt);
		return -1;
	}
	/* check returned 1 */
	assert(sqlite3_column_count(stmt) == 1);
	assert(sqlite3_column_type(stmt, 0) == SQLITE_INTEGER);
	assert(sqlite3_column_int(stmt, 0) == 1);
	if (sqlite3_step(stmt) != SQLITE_DONE) {
		sqlite3_finalize(stmt);
		return -1;
	}
	if (sqlite3_finalize(stmt) != SQLITE_OK) {
		return -1;
	}

	if (sqlite3_prepare_v2(db, "PRAGMA auto_vacuum=FULL", -1, &stmt, NULL) != SQLITE_OK) {
		return -1;
	}
	if (sqlite3_step(stmt) != SQLITE_DONE) {
		sqlite3_finalize(stmt);
		return -1;
	}
	if (sqlite3_finalize(stmt) != SQLITE_OK) {
		return -1;
	}

	return 0;
}

static int
db_prepare(struct rtable *rt)
{
#define SELECT_OLD "SELECT \"id\", \"dyn_x\", \"addr\", \"port\" FROM \"rtable\" " \
	"WHERE \"dist\" = @dist " \
	"ORDER BY \"last_ping\" ASC " \
	"LIMIT -1 OFFSET (@k - 1);"

	if (sqlite3_prepare_v2(rt->db, SELECT_OLD, -1, &rt->select_old, NULL) != SQLITE_OK) {
		return -1;
	}

#define DELETE_NODE "DELETE FROM \"rtable\" WHERE \"id\" = @id;"

	if (sqlite3_prepare_v2(rt->db, DELETE_NODE, -1, &rt->delete_node, NULL) != SQLITE_OK) {
		assert(sqlite3_finalize(rt->select_old) == SQLITE_OK);
		return -1;
	}

#define INSERT_NODE "INSERT INTO \"rtable\" " \
	"(\"id\", \"dyn_x\", \"addr\", \"port\", \"dist\", \"last_ping\") " \
	"VALUES (@id, @dyn_x, @addr, @port, @dist, strftime('%s', 'now'))"

	if (sqlite3_prepare_v2(rt->db, INSERT_NODE, -1, &rt->insert_node, NULL) != SQLITE_OK) {
		assert(sqlite3_finalize(rt->delete_node) == SQLITE_OK);
		assert(sqlite3_finalize(rt->select_old) == SQLITE_OK);
		return -1;
	}

#define SELECT_CLOSEST "SELECT \"id\", \"dyn_x\", \"addr\", \"port\" "\
	"FROM \"rtable\" AS \"r1\" " \
	"WHERE \"r1\".\"id\" IN (" \
		"SELECT \"r2\".\"id\" " \
		"FROM \"rtable\" AS \"r2\" " \
		"WHERE \"r1\".\"dist\" = \"r2\".\"dist\" " \
		"ORDER BY \"last_ping\" DESC " \
		"LIMIT @k" \
	") " \
	"ORDER BY abs(@dist - \"dist\") ASC, \"last_ping\" DESC " \
	"LIMIT @n;"

	if (sqlite3_prepare_v2(rt->db, SELECT_CLOSEST, -1, &rt->select_closest, NULL) != SQLITE_OK) {
		assert(sqlite3_finalize(rt->insert_node) == SQLITE_OK);
		assert(sqlite3_finalize(rt->delete_node) == SQLITE_OK);
		assert(sqlite3_finalize(rt->select_old) == SQLITE_OK);
		return -1;
	}

	return 0;
}

int
rtable_close(struct rtable *rt)
{
	int ret = 0;

	if (sqlite3_finalize(rt->select_closest) != SQLITE_OK) {
		ret = -1;
	}
	if (sqlite3_finalize(rt->insert_node) != SQLITE_OK) {
		ret = -1;
	}
	if (sqlite3_finalize(rt->delete_node) != SQLITE_OK) {
		ret = -1;
	}
	if (sqlite3_finalize(rt->select_old) != SQLITE_OK) {
		ret = -1;
	}

	if (sqlite3_close(rt->db) != SQLITE_OK) {
		ret = -1;
	}

	return ret;
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
	bool was_full = false;
	*insert = false;

	stmt = rt->select_old;
	if (sqlite3_reset(stmt) != SQLITE_OK) {
		return -1;
	}
	if (sqlite3_clear_bindings(stmt) != SQLITE_OK) {
		return -1;
	}

	/* @dist */
	if (sqlite3_bind_int(stmt, 1, dist) != SQLITE_OK) {
		return -1;
	}

	/* @k */
	if (sqlite3_bind_int(stmt, 2, K) != SQLITE_OK) {
		return -1;
	}

	while (sqlite3_step(stmt) == SQLITE_ROW) {
		was_full = true;

		if (decode_node_row(stmt, &row) == -1) {
			return -1;
		}

		if (!rt->alive(rt->alive_ctx, &row)) {
			if (delete_node(rt, row.id) == -1) {
				return -1;
			}
			*insert = true;
		}
	}

	*insert = *insert || !was_full;
	return 0;
}

static int
delete_node(struct rtable *rt, const uint8_t node_id[NODE_ID_SIZE])
{
	sqlite3_stmt *stmt;

	stmt = rt->delete_node;
	if (sqlite3_reset(stmt) != SQLITE_OK) {
		return -1;
	}
	if (sqlite3_clear_bindings(stmt) != SQLITE_OK) {
		return -1;
	}

	/* @id */
	if (sqlite3_bind_blob(stmt, 1, node_id, NODE_ID_SIZE, SQLITE_STATIC) != SQLITE_OK) {
		return -1;
	}

	if (sqlite3_step(stmt) != SQLITE_DONE) {
		return -1;
	}

	return 0;
}

static int
insert_node(struct rtable *rt, const struct node *n, int dist)
{
	sqlite3_stmt *stmt;

	stmt = rt->insert_node;
	if (sqlite3_reset(stmt) != SQLITE_OK) {
		return -1;
	}
	if (sqlite3_clear_bindings(stmt) != SQLITE_OK) {
		return -1;
	}

	/* @id */
	if (sqlite3_bind_blob(stmt, 1, n->id, sizeof(n->id), SQLITE_STATIC) != SQLITE_OK) {
		return -1;
	}

	/* @dyn_x */
	if (sqlite3_bind_blob(stmt, 2, n->dyn_x, sizeof(n->dyn_x), SQLITE_STATIC) != SQLITE_OK) {
		return -1;
	}

	/* @addr */
	if (sqlite3_bind_blob(stmt, 3, n->addr, n->addrlen, SQLITE_STATIC) != SQLITE_OK) {
		return -1;
	}

	/* @port */
	if (sqlite3_bind_int(stmt, 4, n->port) != SQLITE_OK) {
		return -1;
	}

	/* @dist */
	if (sqlite3_bind_int(stmt, 5, dist) != SQLITE_OK) {
		return -1;
	}

	if (sqlite3_step(stmt) != SQLITE_DONE) {
		return -1;
	}

	return 0;
}

int
rtable_closest(struct rtable *rt, const uint8_t node_id[NODE_ID_SIZE], struct node closest[K], size_t *len)
{
	sqlite3_stmt *stmt;
	int dist;
	size_t i;

	*len = 0;

	stmt = rt->select_closest;
	if (sqlite3_reset(stmt) != SQLITE_OK) {
		return -1;
	}
	if (sqlite3_clear_bindings(stmt) != SQLITE_OK) {
		return -1;
	}

	/* @k */
	if (sqlite3_bind_int(stmt, 1, K) != SQLITE_OK) {
		return -1;
	}

	/* @dist */
	dist = (int)lcp(rt->self, node_id, sizeof(rt->self));
	if (sqlite3_bind_int(stmt, 2, dist) != SQLITE_OK) {
		return -1;
	}

	/* @n */
	if (sqlite3_bind_int(stmt, 3, K) != SQLITE_OK) {
		return -1;
	}

	for (i = 0; sqlite3_step(stmt) == SQLITE_ROW; i++) {
		if (decode_node_row(stmt, &closest[i]) == -1) {
			return -1;
		}
	}

	*len = i;
	return 0;
}

static int
decode_node_row(sqlite3_stmt *stmt, struct node *n)
{
	const void *blob;
	int length, port;

	if (sqlite3_column_count(stmt) != 4) {
		return -1;
	}

	/* id */
	if (sqlite3_column_type(stmt, 0) != SQLITE_BLOB) {
		return -1;
	}
	if ((blob = sqlite3_column_blob(stmt, 0)) == NULL) {
		return -1;
	}
	if (sqlite3_column_bytes(stmt, 0) != sizeof(n->id)) {
		return -1;
	}
	memcpy(n->id, blob, sizeof(n->id));

	/* dyn_x */
	if (sqlite3_column_type(stmt, 1) != SQLITE_BLOB) {
		return -1;
	}
	if ((blob = sqlite3_column_blob(stmt, 1)) == NULL) {
		return -1;
	}
	if (sqlite3_column_bytes(stmt, 1) != sizeof(n->dyn_x)) {
		return -1;
	}
	memcpy(n->dyn_x, blob, sizeof(n->dyn_x));

	/* addr */
	if (sqlite3_column_type(stmt, 2) != SQLITE_BLOB) {
		return -1;
	}
	if ((blob = sqlite3_column_blob(stmt, 2)) == NULL) {
		return -1;
	}
	static_assert(sizeof(n->addr) - 1 <= UINT8_MAX);
	if ((length = sqlite3_column_bytes(stmt, 2)) > sizeof(n->addr) - 1) {
		return -1;
	}
	n->addrlen = (uint8_t)length;
	memcpy(n->addr, blob, n->addrlen);
	n->addr[n->addrlen] = '\0';

	/* port */
	if (sqlite3_column_type(stmt, 3) != SQLITE_INTEGER) {
		return -1;
	}
	if ((port = sqlite3_column_int(stmt, 3)) == 0 || port > UINT16_MAX) {
		return -1;
	}
	n->port = (uint16_t)port;

	return 0;
}
