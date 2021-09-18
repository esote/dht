#include <assert.h>
#include <check.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "crypto.h"
#include "monitor.h"
#include "test.h"

static size_t
min(size_t x, size_t y)
{
	if (x < y) {
		return x;
	}
	return y;
}

static bool
node_equal(const struct node *n1, const struct node *n2)
{
	return memcmp(n1->id, n2->id, sizeof(n1->id)) == 0
		&& memcmp(n1->dyn_x, n2->dyn_x, sizeof(n1->dyn_x)) == 0
		&& n1->addrlen == n2->addrlen
		&& memcmp(n1->addr, n2->addr, n1->addrlen) == 0
		&& n1->port == n2->port;
}

static bool
fnode_equal(const struct fnode *p1, const struct fnode *p2)
{
	return p1->count == p2->count
		&& memcmp(p1->target_id, p2->target_id, sizeof(p1->target_id)) == 0;
}

static bool
fnode_resp_equal(const struct fnode_resp *p1, const struct fnode_resp *p2)
{
	size_t i;

	if (p1->count != p2->count) {
		return false;
	}
	for (i = 0; i < p1->count; i++) {
		if (!node_equal(&p1->nodes[i], &p2->nodes[i])) {
			return false;
		}
	}
	return true;
}

static bool
fd_equal(const uint8_t *expect, int fd, size_t count)
{
	uint8_t buf[1024];
	size_t n, off = 0;
	ssize_t r;

	while (count > 0) {
		n = min(count, sizeof(buf));
		if ((r = read(fd, buf, n)) != n || memcmp(expect + off, buf, n) != 0) {
			return false;
		}
		off += n;
		count -= n;
	}
	return true;
}

static bool
data_equal(const struct data *p1, const struct data *p2)
{
	return memcmp(p1->key, p2->key, sizeof(p1->key)) == 0
		&& p1->length == p2->length;
}

static bool
fval_equal(const struct fval *p1, const struct fval *p2)
{
	return memcmp(p1->key, p2->key, sizeof(p1->key)) == 0;
}

static bool
monitor_message_equal(const struct monitor_message *m1, const struct monitor_message *m2)
{
	if (m1->type != m2->type) {
		return false;
	}
	switch (m1->type) {
	case M_DISCOVER:
		return true;
	case M_SELF:
		return memcmp(m1->payload.self.network_id, m2->payload.self.network_id, sizeof(m1->payload.self.network_id)) == 0
			&& node_equal(&m1->payload.self.node, &m2->payload.self.node);
	case M_DECRYPT_REQ:
		return memcmp(m1->payload.decrypt_req.ephem_publ, m2->payload.decrypt_req.ephem_publ, sizeof(m1->payload.decrypt_req.ephem_publ)) == 0;
	case M_DECRYPT_RESP:
		return memcmp(m1->payload.decrypt_resp.ephem_key, m2->payload.decrypt_resp.ephem_key, sizeof(m1->payload.decrypt_resp.ephem_key)) == 0;
	case M_ENCRYPT_REQ:
		return memcmp(m1->payload.encrypt_req.session_id, m2->payload.encrypt_req.session_id, sizeof(m1->payload.encrypt_req.session_id)) == 0
			&& m1->payload.encrypt_req.expiration == m2->payload.encrypt_req.expiration
			&& memcmp(m1->payload.encrypt_req.target_id, m2->payload.encrypt_req.target_id, sizeof(m1->payload.encrypt_req.target_id)) == 0;
	case M_ENCRYPT_RESP:
		return memcmp(m1->payload.encrypt_resp.sig, m2->payload.encrypt_resp.sig, sizeof(m1->payload.encrypt_resp.sig)) == 0
			&& memcmp(m1->payload.encrypt_resp.ephem_publ, m2->payload.encrypt_resp.ephem_publ, sizeof(m1->payload.encrypt_resp.ephem_publ)) == 0
			&& memcmp(m1->payload.encrypt_resp.ephem_key, m2->payload.encrypt_resp.ephem_key, sizeof(m1->payload.encrypt_resp.ephem_key)) == 0;
	case M_PING:
		return true;
	case M_FNODE:
		return fnode_equal(&m1->payload.fnode, &m2->payload.fnode);
	case M_FNODE_RESP:
		return fnode_resp_equal(&m1->payload.fnode_resp, &m2->payload.fnode_resp);
	case M_DATA:
		return data_equal(&m1->payload.data, &m2->payload.data);
	case M_FVAL:
		return fval_equal(&m2->payload.fval, &m2->payload.fval);
	default:
		return -1;
	}
}

START_TEST (test_discover)
{
	int sv[2];
	struct monitor_message req = {
		.type = M_DISCOVER
	};
	struct monitor_message resp;

	ck_assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != -1);

	ck_assert(monitor_send(sv[0], &req) != -1);
	ck_assert(monitor_recv(sv[1], &resp) != -1);
	ck_assert(monitor_message_equal(&req, &resp));
	monitor_close(&resp);

	ck_assert(close(sv[0]) != -1);
	ck_assert(close(sv[1]) != -1);
}

START_TEST (test_self)
{
	int sv[2];
	struct monitor_message req = {
		.type = M_SELF,
		.payload.self = {
			.network_id = {1},
			.node = {
				.addrlen = 2,
				.addr = {3, 3},
				.port = 4
			}
		}
	};
	struct monitor_message resp;
	unsigned char priv[PRIV_SIZE];

	ck_assert(new_keypair(req.payload.self.node.id, priv, req.payload.self.node.dyn_x) != -1);

	ck_assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != -1);

	ck_assert(monitor_send(sv[0], &req) != -1);
	ck_assert(monitor_recv(sv[1], &resp) != -1);
	ck_assert(monitor_message_equal(&req, &resp));
	monitor_close(&resp);

	ck_assert(close(sv[0]) != -1);
	ck_assert(close(sv[1]) != -1);
}

START_TEST (test_decrypt_req)
{
	int sv[2];
	struct monitor_message req = {
		.type = M_DECRYPT_REQ,
		.payload.decrypt_req = {
			.ephem_publ = {1}
		}
	};
	struct monitor_message resp;

	ck_assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != -1);

	ck_assert(monitor_send(sv[0], &req) != -1);
	ck_assert(monitor_recv(sv[1], &resp) != -1);
	ck_assert(monitor_message_equal(&req, &resp));
	monitor_close(&resp);

	ck_assert(close(sv[0]) != -1);
	ck_assert(close(sv[1]) != -1);
}

START_TEST (test_decrypt_resp)
{
	int sv[2];
	struct monitor_message req = {
		.type = M_DECRYPT_RESP,
		.payload.decrypt_resp = {
			.ephem_key = {1}
		}
	};
	struct monitor_message resp;

	ck_assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != -1);

	ck_assert(monitor_send(sv[0], &req) != -1);
	ck_assert(monitor_recv(sv[1], &resp) != -1);
	ck_assert(monitor_message_equal(&req, &resp));
	monitor_close(&resp);

	ck_assert(close(sv[0]) != -1);
	ck_assert(close(sv[1]) != -1);
}

START_TEST (test_encrypt_req)
{
	int sv[2];
	struct monitor_message req = {
		.type = M_ENCRYPT_REQ,
		.payload.encrypt_req = {
			.session_id = {1},
			.expiration = 2,
			.target_id = {3}
		}
	};
	struct monitor_message resp;

	ck_assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != -1);

	ck_assert(monitor_send(sv[0], &req) != -1);
	ck_assert(monitor_recv(sv[1], &resp) != -1);
	ck_assert(monitor_message_equal(&req, &resp));
	monitor_close(&resp);

	ck_assert(close(sv[0]) != -1);
	ck_assert(close(sv[1]) != -1);
}

START_TEST (test_encrypt_resp)
{
	int sv[2];
	struct monitor_message req = {
		.type = M_ENCRYPT_RESP,
		.payload.encrypt_resp = {
			.sig = {1},
			.ephem_publ = {2},
			.ephem_key = {3}
		}
	};
	struct monitor_message resp;

	ck_assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != -1);

	ck_assert(monitor_send(sv[0], &req) != -1);
	ck_assert(monitor_recv(sv[1], &resp) != -1);
	ck_assert(monitor_message_equal(&req, &resp));
	monitor_close(&resp);

	ck_assert(close(sv[0]) != -1);
	ck_assert(close(sv[1]) != -1);
}

START_TEST (test_ping)
{
	int sv[2];
	struct monitor_message req = {
		.type = M_PING,
	};
	struct monitor_message resp;

	ck_assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != -1);

	ck_assert(monitor_send(sv[0], &req) != -1);
	ck_assert(monitor_recv(sv[1], &resp) != -1);
	ck_assert(monitor_message_equal(&req, &resp));
	monitor_close(&resp);

	ck_assert(close(sv[0]) != -1);
	ck_assert(close(sv[1]) != -1);
}

START_TEST (test_fnode)
{
	int sv[2];
	struct monitor_message req = {
		.type = M_FNODE,
		.payload.fnode = {
			.count = 1,
			.target_id = {2}
		}
	};
	struct monitor_message resp;

	ck_assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != -1);

	ck_assert(monitor_send(sv[0], &req) != -1);
	ck_assert(monitor_recv(sv[1], &resp) != -1);
	ck_assert(monitor_message_equal(&req, &resp));
	monitor_close(&resp);

	ck_assert(close(sv[0]) != -1);
	ck_assert(close(sv[1]) != -1);
}

START_TEST (test_fnode_resp)
{
	int sv[2];
	struct node nodes[3] = {
		{
			.addrlen = 1,
			.addr = {2},
			.port = 3
		},
		{
			.addrlen = 4,
			.addr = {5, 5, 5, 5},
			.port = 6
		},
		{
			.addrlen = 7,
			.addr = {8, 8, 8, 8, 8, 8, 8},
			.port = 9
		}
	};
	struct monitor_message req = {
		.type = M_FNODE_RESP,
		.payload.fnode_resp = {
			.count = 3,
			.nodes = nodes
		}
	};
	struct monitor_message resp;
	unsigned char priv[PRIV_SIZE];

	ck_assert(new_keypair(nodes[0].id, priv, nodes[0].dyn_x) != -1);
	ck_assert(new_keypair(nodes[1].id, priv, nodes[1].dyn_x) != -1);
	ck_assert(new_keypair(nodes[2].id, priv, nodes[2].dyn_x) != -1);

	ck_assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != -1);

	ck_assert(monitor_send(sv[0], &req) != -1);
	ck_assert(monitor_recv(sv[1], &resp) != -1);
	ck_assert(monitor_message_equal(&req, &resp));
	monitor_close(&resp);

	ck_assert(close(sv[0]) != -1);
	ck_assert(close(sv[1]) != -1);
}

#define DATA_TMP_TEMPLATE "/tmp/dhtd.test.monitor.data.XXXXXXXXXX"
static char data_tmpname[sizeof(DATA_TMP_TEMPLATE)] = {0};
static int data_tmpfd = -1;

static void
data_setup(void)
{
	strncpy(data_tmpname, DATA_TMP_TEMPLATE, sizeof(data_tmpname));
	assert((data_tmpfd = mkstemp(data_tmpname)) != -1);
}

static void
data_teardown(void)
{
	assert(unlink(data_tmpname) != -1);
}

START_TEST (test_data)
{
	static const uint8_t data[2] = {3, 3};
	ck_assert(write(data_tmpfd, data, sizeof(data)) == sizeof(data));
	ck_assert(lseek(data_tmpfd, 0, SEEK_SET) != -1);

	int sv[2];
	struct monitor_message req = {
		.type = M_DATA,
		.payload.data = {
			.key = {1},
			.length = 2,
			.value = data_tmpfd
		}
	};
	struct monitor_message resp;

	ck_assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != -1);

	ck_assert(monitor_send(sv[0], &req) != -1);
	ck_assert(monitor_recv(sv[1], &resp) != -1);
	ck_assert(monitor_message_equal(&req, &resp));
	ck_assert(fd_equal(data, resp.payload.data.value, req.payload.data.length));
	monitor_close(&resp);

	ck_assert(close(data_tmpfd) != -1);
	if (resp.payload.data.value != req.payload.data.value) {
		ck_assert(close(resp.payload.data.value) != -1);
	}
	ck_assert(close(sv[0]) != -1);
	ck_assert(close(sv[1]) != -1);
}

START_TEST (test_fval)
{
	int sv[2];
	struct monitor_message req = {
		.type = M_FVAL,
		.payload.fval = {
			.key = {1}
		}
	};
	struct monitor_message resp;

	ck_assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != -1);

	ck_assert(monitor_send(sv[0], &req) != -1);
	ck_assert(monitor_recv(sv[1], &resp) != -1);
	ck_assert(monitor_message_equal(&req, &resp));
	monitor_close(&resp);

	ck_assert(close(sv[0]) != -1);
	ck_assert(close(sv[1]) != -1);
}

Suite *
suite_monitor(void)
{
	Suite *s = suite_create("monitor");

	TCase *discover = tcase_create("discover");
	tcase_add_test(discover, test_discover);
	suite_add_tcase(s, discover);

	TCase *self = tcase_create("self");
	tcase_add_test(self, test_self);
	suite_add_tcase(s, self);

	TCase *decrypt_req = tcase_create("decrypt_req");
	tcase_add_test(decrypt_req, test_decrypt_req);
	suite_add_tcase(s, decrypt_req);

	TCase *decrypt_resp = tcase_create("decrypt_resp");
	tcase_add_test(decrypt_resp, test_decrypt_resp);
	suite_add_tcase(s, decrypt_resp);

	TCase *encrypt_req = tcase_create("encrypt_req");
	tcase_add_test(encrypt_req, test_encrypt_req);
	suite_add_tcase(s, encrypt_req);

	TCase *encrypt_resp = tcase_create("encrypt_resp");
	tcase_add_test(encrypt_resp, test_encrypt_resp);
	suite_add_tcase(s, encrypt_resp);

	TCase *ping = tcase_create("ping");
	tcase_add_test(ping, test_ping);
	suite_add_tcase(s, ping);

	TCase *fnode = tcase_create("fnode");
	tcase_add_test(fnode, test_fnode);
	suite_add_tcase(s, fnode);

	TCase *fnode_resp = tcase_create("fnode_resp");
	tcase_add_test(fnode_resp, test_fnode_resp);
	suite_add_tcase(s, fnode_resp);

	TCase *data = tcase_create("data");
	tcase_add_checked_fixture(data, data_setup, data_teardown);
	tcase_add_test(data, test_data);
	suite_add_tcase(s, data);

	TCase *fval = tcase_create("fval");
	tcase_add_test(fval, test_fval);
	suite_add_tcase(s, fval);

	return s;
}
