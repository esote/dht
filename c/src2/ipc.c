#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "bytes.h"
#include "io.h"
#include "ipc.h"

#define BASE_SIZE (sizeof(ipc_version)			\
	+ sizeof(((struct ipc_message *)0)->type))

#define BOOTSTRAP_SIZE ((BASE_SIZE)			\
	+ sizeof(((struct ipc_bootstrap *)0)->id)	\
	+ sizeof(((struct ipc_bootstrap *)0)->dyn_x)	\
	+ sizeof(((struct ipc_bootstrap *)0)->addrlen)	\
	+ sizeof(((struct ipc_bootstrap *)0)->addr)	\
	+ sizeof(((struct ipc_bootstrap *)0)->port))

#define DATA_IOV_SIZE ((BASE_SIZE)			\
	+ sizeof(((struct ipc_data *)0)->key)		\
	+ sizeof(((struct ipc_data *)0)->length))

#define LOAD_SIZE ((BASE_SIZE)			\
	+ sizeof(((struct ipc_load *)0)->key))

#define ERROR_SIZE ((BASE_SIZE)				\
	+ sizeof(((struct ipc_error *)0)->msglen)	\
	+ sizeof(((struct ipc_error *)0)->msg))

const uint8_t ipc_version = 0;

static uint8_t *encode_base(uint8_t buf[static BASE_SIZE], const struct ipc_message *m);
static int encode_bootstrap(int out, const struct ipc_message *m);
static int encode_data(int out, const struct ipc_message *m);
static int encode_load(int out, const struct ipc_message *m);
static int encode_error(int out, const struct ipc_message *m);
static uint8_t *decode_base(uint8_t buf[static BASE_SIZE], struct ipc_message *m);
static int decode_bootstrap(int in, struct ipc_message *m);
static int decode_data(int in, struct ipc_message *m);
static int decode_load(int in, struct ipc_message *m);
static int decode_error(int in, struct ipc_message *m);

int
ipc_encode(int out, const struct ipc_message *m)
{
	switch (m->type) {
	case IPC_TYPE_BOOTSTRAP:
		return encode_bootstrap(out, m);
	case IPC_TYPE_DATA:
		return encode_data(out, m);
	case IPC_TYPE_LOAD:
		return encode_load(out, m);
	case IPC_TYPE_ERROR:
		return encode_error(out, m);
	default:
		return -1;
	}
}

static uint8_t *
encode_base(uint8_t buf[static BASE_SIZE], const struct ipc_message *m)
{
	uint8_t *b;
	b = buf;

	/* VERSION */
	*b = ipc_version;
	b += sizeof(ipc_version);

	/* TYPE */
	*b = m->type;
	b += sizeof(m->type);

	assert(b == buf + BASE_SIZE);
	return b;
}

static int
encode_bootstrap(int out, const struct ipc_message *m)
{
	const struct ipc_bootstrap *bootstrap = &m->payload.bootstrap;
	uint8_t buf[BOOTSTRAP_SIZE];
	uint8_t *b = buf;

	if ((b = encode_base(b, m)) == NULL) {
		return -1;
	}

	/* ID */
	(void)memcpy(b, bootstrap->id, sizeof(bootstrap->id));
	b += sizeof(bootstrap->id);

	/* DYN_X */
	(void)memcpy(b, bootstrap->dyn_x, sizeof(bootstrap->dyn_x));
	b += sizeof(bootstrap->dyn_x);

	/* ADDRLEN */
	*b = bootstrap->addrlen;
	b += sizeof(bootstrap->addrlen);

	/* ADDR */
	if (!is_zero(bootstrap->addr + bootstrap->addrlen,
		sizeof(bootstrap->addr) - bootstrap->addrlen)) {
		return -1;
	}
	(void)memcpy(b, bootstrap->addr, sizeof(bootstrap->addr));
	b += sizeof(bootstrap->addr);

	/* PORT */
	hton_16(b, bootstrap->port);
	b += sizeof(bootstrap->port);

	assert(b == buf + sizeof(buf));
	if (write2(out, buf, sizeof(buf)) != sizeof(buf)) {
		return -1;
	}

	return 0;
}

static int
encode_data(int out, const struct ipc_message *m)
{
	const struct ipc_data *data = &m->payload.data;
	uint8_t buf[DATA_IOV_SIZE];
	uint8_t *b = buf;
	uint8_t auxbuf[CMSG_SPACE(sizeof(data->value))] = { 0 };
	struct iovec io = { 0 };
	struct msghdr msg = { 0 };
	struct cmsghdr *cmsg;
	uint64_t length;

	if ((b = encode_base(b, m)) == NULL) {
		return -1;
	}

	/* KEY */
	(void)memcpy(b, data->key, sizeof(data->key));
	b += sizeof(data->key);

	/* LENGTH */
	length = data->length;
	(void)memcpy(b, &length, sizeof(length));
	b += sizeof(length);

	assert(b == buf + sizeof(buf));

	io.iov_base = buf;
	io.iov_len = sizeof(buf);
	msg.msg_iov = &io;
	msg.msg_iovlen = 1;
	msg.msg_control = auxbuf;
	msg.msg_controllen = sizeof(auxbuf);

	if ((cmsg = CMSG_FIRSTHDR(&msg)) == NULL) {
		return -1;
	}
	cmsg->cmsg_len = CMSG_LEN(sizeof(data->value));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;

	/* VALUE */
	(void)memcpy(CMSG_DATA(cmsg), &data->value, sizeof(data->value));

	if (sendmsg(out, &msg, 0) != sizeof(buf)) {
		return -1;
	}

	return 0;
}

static int
encode_load(int out, const struct ipc_message *m)
{
	const struct ipc_load *load = &m->payload.load;
	uint8_t buf[LOAD_SIZE];
	uint8_t *b = buf;

	if ((b = encode_base(b, m)) == NULL) {
		return -1;
	}

	/* KEY */
	(void)memcpy(b, load->key, sizeof(load->key));
	b += sizeof(load->key);

	assert(b == buf + sizeof(buf));
	if (write2(out, buf, sizeof(buf)) != sizeof(buf)) {
		return -1;
	}

	return 0;
}

static int
encode_error(int out, const struct ipc_message *m)
{
	const struct ipc_error *error = &m->payload.error;
	uint8_t buf[ERROR_SIZE];
	uint8_t *b = buf;

	if ((b = encode_base(b, m)) == NULL) {
		return -1;
	}

	/* MSGLEN */
	*b = error->msglen;
	b += sizeof(error->msglen);

	/* MESSAGE */
	if (!is_zero(error->msg + error->msglen, sizeof(error->msg) - error->msglen)) {
		return -1;
	}
	(void)memcpy(b, error->msg, sizeof(error->msg));
	b += sizeof(error->msg);

	assert(b == buf + sizeof(buf));
	if (write2(out, buf, sizeof(buf)) != sizeof(buf)) {
		return -1;
	}

	return 0;
}

int
ipc_decode(int in, struct ipc_message *m)
{
	uint8_t buf[BASE_SIZE];
	struct iovec io = {
		.iov_base = buf,
		.iov_len = sizeof(buf)
	};
	struct msghdr msg = {
		.msg_iov = &io,
		.msg_iovlen = 1
	};

	if (recvmsg(in, &msg, MSG_PEEK) != sizeof(buf)) {
		return -1;
	}

	uint8_t version = buf[0];
	if (version != ipc_version) {
		return -1;
	}

	uint8_t type = buf[1];
	switch (type) {
	case IPC_TYPE_BOOTSTRAP:
		return decode_bootstrap(in, m);
	case IPC_TYPE_DATA:
		return decode_data(in, m);
	case IPC_TYPE_LOAD:
		return decode_load(in, m);
	case IPC_TYPE_ERROR:
		return decode_error(in, m);
	default:
		return -1;
	}
}

static uint8_t *
decode_base(uint8_t buf[static BASE_SIZE], struct ipc_message *m)
{
	uint8_t *b;
	uint8_t version;
	b = buf;

	/* VERSION */
	version = *b;
	if (version != ipc_version) {
		return NULL;
	}
	b += sizeof(version);

	m->type = *b;
	b += sizeof(m->type);

	assert(b == buf + BASE_SIZE);
	return b;
}

static int
decode_bootstrap(int in, struct ipc_message *m)
{
	struct ipc_bootstrap *bootstrap = &m->payload.bootstrap;
	uint8_t buf[BOOTSTRAP_SIZE];
	uint8_t *b = buf;

	if (read2(in, buf, sizeof(buf)) != sizeof(buf)) {
		return -1;
	}

	if ((b = decode_base(b, m)) == NULL) {
		return -1;
	}

	/* ID */
	(void)memcpy(bootstrap->id, b, sizeof(bootstrap->id));
	b += sizeof(bootstrap->id);

	/* DYN_X */
	(void)memcpy(bootstrap->dyn_x, b, sizeof(bootstrap->dyn_x));
	b += sizeof(bootstrap->dyn_x);

	/* ADDRLEN */
	bootstrap->addrlen = *b;
	b += sizeof(bootstrap->addrlen);

	/* ADDR */
	(void)memcpy(bootstrap->addr, b, sizeof(bootstrap->addr));
	b += sizeof(bootstrap->addr);
	if (!is_zero(bootstrap->addr + bootstrap->addrlen,
		sizeof(bootstrap->addr) - bootstrap->addrlen)) {
		return -1;
	}

	/* PORT */
	bootstrap->port = ntoh_16(b);
	b += sizeof(bootstrap->port);

	assert(b == buf + sizeof(buf));
	return 0;
}

static int
decode_data(int in, struct ipc_message *m)
{
	struct ipc_data *data = &m->payload.data;
	uint8_t buf[DATA_IOV_SIZE];
	uint8_t *b = buf;
	uint8_t auxbuf[CMSG_SPACE(sizeof(data->value))] = { 0 };
	struct iovec io = { 0 };
	struct msghdr msg = { 0 };
	struct cmsghdr *cmsg;
	ssize_t r;

	io.iov_base = buf;
	io.iov_len = sizeof(buf);
	msg.msg_iov = &io;
	msg.msg_iovlen = 1;
	msg.msg_control = auxbuf;
	msg.msg_controllen = sizeof(auxbuf);

	/* delay checking r == sizeof(buf) until after reading cmsg */
	if ((r = recvmsg(in, &msg, 0)) == -1) {
		return -1;
	}

	if ((cmsg = CMSG_FIRSTHDR(&msg)) == NULL) {
		return -1;
	}
	if (cmsg->cmsg_len != CMSG_LEN(sizeof(data->value))
		|| cmsg->cmsg_level != SOL_SOCKET
		|| cmsg->cmsg_type != SCM_RIGHTS) {
		return -1;
	}

	/* VALUE */
	(void)memcpy(&data->value, CMSG_DATA(cmsg), sizeof(data->value));

	if (r != sizeof(buf)) {
		(void)close(data->value);
		return -1;
	}

	if ((b = decode_base(b, m)) == NULL) {
		(void)close(data->value);
		return -1;
	}

	/* KEY */
	(void)memcpy(data->key, b, sizeof(data->key));
	b += sizeof(data->key);

	/* LENGTH */
	data->length = ntoh_64(b);
	b += sizeof(data->length);

	assert(b == buf + sizeof(buf));
	return 0;
}

static int
decode_load(int in, struct ipc_message *m)
{
	struct ipc_load *load = &m->payload.load;
	uint8_t buf[LOAD_SIZE];
	uint8_t *b = buf;

	if (read2(in, buf, sizeof(buf)) != sizeof(buf)) {
		return -1;
	}

	if ((b = decode_base(b, m)) == NULL) {
		return -1;
	}

	/* KEY */
	(void)memcpy(load->key, b, sizeof(load->key));
	b += sizeof(load->key);

	assert(b == buf + sizeof(buf));
	return 0;
}

static int
decode_error(int in, struct ipc_message *m)
{
	struct ipc_error *error = &m->payload.error;
	uint8_t buf[ERROR_SIZE];
	uint8_t *b = buf;

	if (read2(in, buf, sizeof(buf)) != sizeof(buf)) {
		return -1;
	}

	if ((b = decode_base(b, m)) == NULL) {
		return -1;
	}

	/* MSGLEN */
	error->msglen = *b;
	b += sizeof(error->msglen);

	/* MSG */
	(void)memcpy(error->msg, b, sizeof(error->msg));
	b += sizeof(error->msg);
	if (!is_zero(error->msg + error->msglen, sizeof(error->msg) - error->msglen)) {
		return -1;
	}

	assert(b == buf + sizeof(buf));
	return 0;
}
