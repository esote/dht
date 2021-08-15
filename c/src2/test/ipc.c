#include <assert.h>
#include <check.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../ipc.h"
#include "test.h"

static void
test_ipc_bootstrap_type(int type)
{
	struct ipc_message m1 = {
		.type = IPC_TYPE_BOOTSTRAP,
		.payload.bootstrap = {
			.id = { 1 },
			.dyn_x = { 2 },
			.addrlen = 3,
			.addr = { 1, 2, 3 },
			.port = 4
		}
	};

	int sv[2];
	ck_assert(socketpair(AF_UNIX, type, 0, sv) != -1);
	ck_assert(ipc_encode(sv[0], &m1) != -1);
	ck_assert(close(sv[0]) != -1);

	struct ipc_message m2;
	ck_assert(ipc_decode(sv[1], &m2) != -1);
	ck_assert(close(sv[1]) != -1);

	ck_assert(m1.type == m2.type);
	ck_assert(memcmp(m1.payload.bootstrap.id, m2.payload.bootstrap.id, sizeof(m1.payload.bootstrap.id)) == 0);
	ck_assert(memcmp(m1.payload.bootstrap.dyn_x, m2.payload.bootstrap.dyn_x, sizeof(m1.payload.bootstrap.dyn_x)) == 0);
	ck_assert(m1.payload.bootstrap.addrlen == m2.payload.bootstrap.addrlen);
	ck_assert(memcmp(m1.payload.bootstrap.addr, m2.payload.bootstrap.addr, sizeof(m1.payload.bootstrap.addr)) == 0);
	ck_assert(m1.payload.bootstrap.port == m2.payload.bootstrap.port);
}

START_TEST (test_ipc_bootstrap_stream)
{
	test_ipc_bootstrap_type(SOCK_STREAM);
}

START_TEST (test_ipc_bootstrap_dgram)
{
	test_ipc_bootstrap_type(SOCK_DGRAM);
}

#define TMP_TEMPLATE "/tmp/dhtd.test.ipc.XXXXXXXXXX"
static char tmpname[sizeof(TMP_TEMPLATE)] = { 0 };
static int tempfd = -1;

static void
data_setup(void)
{
	(void)strncpy(tmpname, TMP_TEMPLATE, sizeof(tmpname));
	assert((tempfd = mkstemp(tmpname)) != -1);
}

static void
data_teardown(void)
{
	assert(unlink(tmpname) != -1);
}

static void
test_ipc_data_type(int type)
{
	const uint8_t data[3] = { 1, 2, 3 };
	ck_assert(write(tempfd, data, sizeof(data)) == sizeof(data));
	ck_assert(lseek(tempfd, 0, SEEK_SET) != -1);

	struct ipc_message m1 = {
		.type = IPC_TYPE_BOOTSTRAP,
		.payload.data = {
			.key = { 1 },
			.length = 3,
			.value = tempfd
		}
	};

	int sv[2];
	ck_assert(socketpair(AF_UNIX, type, 0, sv) != -1);
	ck_assert(ipc_encode(sv[0], &m1) != -1);
	ck_assert(close(sv[0]) != -1);

	struct ipc_message m2;
	ck_assert(ipc_decode(sv[1], &m2) != -1);
	ck_assert(close(sv[1]) != -1);

	ck_assert(m1.type == m2.type);
	ck_assert(memcmp(m1.payload.data.key, m2.payload.data.key, sizeof(m1.payload.data.key)) == 0);
	ck_assert(m1.payload.data.length == m2.payload.data.length);

	if (m2.payload.data.value != tempfd) {
		/* because we're sending to self the fd is probably the same */
		ck_assert(close(tempfd) != -1);
	}

	uint8_t buf[sizeof(data) + 1];
	ck_assert(read(m2.payload.data.value, buf, sizeof(buf)) == sizeof(data));
	ck_assert(memcmp(data, buf, sizeof(data)) == 0);
	ck_assert(close(m2.payload.data.value) != -1);
}

START_TEST (test_ipc_data_stream)
{
	test_ipc_data_type(SOCK_STREAM);
}

START_TEST (test_ipc_data_dgram)
{
	test_ipc_data_type(SOCK_DGRAM);
}

static void
test_ipc_load_type(int type)
{
	struct ipc_message m1 = {
		.type = IPC_TYPE_LOAD,
		.payload.load = {
			.key = { 1 }
		}
	};

	int sv[2];
	ck_assert(socketpair(AF_UNIX, type, 0, sv) != -1);
	ck_assert(ipc_encode(sv[0], &m1) != -1);
	ck_assert(close(sv[0]) != -1);

	struct ipc_message m2;
	ck_assert(ipc_decode(sv[1], &m2) != -1);
	ck_assert(close(sv[1]) != -1);

	ck_assert(m1.type == m2.type);
	ck_assert(memcmp(m1.payload.load.key, m2.payload.load.key, sizeof(m1.payload.load.key)) == 0);
}

START_TEST (test_ipc_load_stream)
{
	test_ipc_load_type(SOCK_STREAM);
}

START_TEST (test_ipc_load_dgram)
{
	test_ipc_load_type(SOCK_DGRAM);
}

static void
test_ipc_error_type(int type)
{
	struct ipc_message m1 = {
		.type = IPC_TYPE_ERROR,
		.payload.error = {
			.msglen = 3,
			.msg = { 1, 2, 3 }
		}
	};

	int sv[2];
	ck_assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != -1);
	ck_assert(ipc_encode(sv[0], &m1) != -1);
	ck_assert(close(sv[0]) != -1);

	struct ipc_message m2;
	ck_assert(ipc_decode(sv[1], &m2) != -1);
	ck_assert(close(sv[1]) != -1);

	ck_assert(m1.type == m2.type);
	ck_assert(m1.payload.error.msglen == m2.payload.error.msglen);
	ck_assert(memcmp(m1.payload.error.msg, m2.payload.error.msg, sizeof(m1.payload.error.msg)) == 0);
}

START_TEST (test_ipc_error_stream)
{
	test_ipc_error_type(SOCK_STREAM);
}

START_TEST (test_ipc_error_dgram)
{
	test_ipc_error_type(SOCK_DGRAM);
}

Suite *
suite_ipc(void)
{
	Suite *s = suite_create("ipc");

	TCase *bootstrap = tcase_create("bootstrap");
	tcase_add_test(bootstrap, test_ipc_bootstrap_stream);
	tcase_add_test(bootstrap, test_ipc_bootstrap_dgram);
	suite_add_tcase(s, bootstrap);

	TCase *data = tcase_create("data");
	tcase_add_checked_fixture(data, data_setup, data_teardown);
	tcase_add_test(data, test_ipc_data_stream);
	tcase_add_test(data, test_ipc_data_dgram);
	suite_add_tcase(s, data);

	TCase *load = tcase_create("load");
	tcase_add_test(load, test_ipc_load_stream);
	tcase_add_test(load, test_ipc_load_dgram);
	suite_add_tcase(s, load);

	TCase *error = tcase_create("error");
	tcase_add_test(error, test_ipc_error_stream);
	tcase_add_test(error, test_ipc_error_dgram);
	suite_add_tcase(s, error);

	return s;
}
