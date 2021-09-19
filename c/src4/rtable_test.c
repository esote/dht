#include <assert.h>
#include <check.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>

#include "proto.h"
#include "rtable.h"
#include "test.h"

static bool
alive_true(void *ctx, const struct node *n)
{
	return true;
}

static bool
alive_false(void *ctx, const struct node *n)
{
	return false;
}

#define SQLITE_TMP_TEMPLATE "/tmp/dhtd.test.rtable.XXXXXXXXXX"
static char sqlite_tmpname[sizeof(SQLITE_TMP_TEMPLATE)] = {0};

static void
sqlite_setup(void)
{
	int fd;
	strncpy(sqlite_tmpname, SQLITE_TMP_TEMPLATE, sizeof(sqlite_tmpname));
	assert((fd = mkstemp(sqlite_tmpname)) != -1);
	assert(close(fd) != -1);
}

static void
sqlite_teardown(void)
{
	assert(unlink(sqlite_tmpname) != -1);
}

START_TEST (test_open)
{
	struct rtable rt;
	unsigned char id[NODE_ID_SIZE], priv[PRIV_SIZE], dyn_x[DYN_X_SIZE];
	ck_assert(new_keypair(id, priv, dyn_x) != -1);
	ck_assert(rtable_open(&rt, sqlite_tmpname, id, alive_true, NULL) != -1);
	ck_assert(rtable_close(&rt) != -1);
}

START_TEST (test_open_create)
{
	struct rtable rt;
	unsigned char id[NODE_ID_SIZE], priv[PRIV_SIZE], dyn_x[DYN_X_SIZE];
	ck_assert(new_keypair(id, priv, dyn_x) != -1);
	ck_assert(unlink(sqlite_tmpname) != -1);
	ck_assert(rtable_open(&rt, sqlite_tmpname, id, alive_true, NULL) != -1);
	ck_assert(rtable_close(&rt) != -1);
}

START_TEST (test_store)
{
	struct rtable rt;

	unsigned char self_id[NODE_ID_SIZE], self_priv[PRIV_SIZE], self_dyn_x[DYN_X_SIZE];
	ck_assert(new_keypair(self_id, self_priv, self_dyn_x) != -1);

	struct node n = {
		.addrlen = 3,
		.addr = {1, 2, 3},
		.port = 8080
	};
	unsigned char n_priv[PRIV_SIZE];
	ck_assert(new_keypair(n.id, n_priv, n.dyn_x) != -1);

	ck_assert(rtable_open(&rt, sqlite_tmpname, self_id, alive_true, NULL) != -1);
	ck_assert(rtable_store(&rt, &n) != -1);
	ck_assert(rtable_close(&rt) != -1);
}

START_TEST (test_store_full)
{
	struct rtable rt;

	unsigned char self_id[NODE_ID_SIZE], self_priv[PRIV_SIZE], self_dyn_x[DYN_X_SIZE];
	ck_assert(new_keypair(self_id, self_priv, self_dyn_x) != -1);

	ck_assert(rtable_open(&rt, sqlite_tmpname, self_id, alive_false, NULL) != -1);

	struct node n[UINT8_MAX+2];
	for (size_t i = 0; i < UINT8_MAX+2; i++) {
		uint8_t n_priv[PRIV_SIZE];
		ck_assert(new_keypair(n[i].id, n_priv, n[i].dyn_x) != -1);
		n[i].addrlen = 3;
		memcpy(n[i].addr, "123", 3);
		n[i].port = 123;

		ck_assert(rtable_store(&rt, &n[i]) != -1);
	}

	ck_assert(rtable_close(&rt) != -1);
}

Suite *
suite_rtable(void)
{
	Suite *s = suite_create("rtable");

	TCase *open = tcase_create("open");
	tcase_add_checked_fixture(open, sqlite_setup, sqlite_teardown);
	tcase_add_test(open, test_open);
	tcase_add_test(open, test_open_create);
	suite_add_tcase(s, open);


	TCase *store = tcase_create("store");
	tcase_add_checked_fixture(store, sqlite_setup, sqlite_teardown);
	tcase_add_test(store, test_store);
	tcase_add_test(store, test_store_full);
	suite_add_tcase(s, store);

	return s;
}
