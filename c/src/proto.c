#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "crypto.h"
#include "monitor.h"
#include "proto.h"
#include "util.h"

static const uint8_t PROTO_VERSION = 0;

#define MESSAGE_EXPIRATION 10 /* TODO: move to dhtd.h */

#define NODE_SIZE(arg_addrlen) (sizeof(((struct node *)0)->id)	\
	+ sizeof(((struct node *)0)->dyn_x)		\
	+ sizeof(((struct node *)0)->addrlen)		\
	+ (arg_addrlen)						\
	+ sizeof(((struct node *)0)->port))

#define HEADER_SIZE(arg_addrlen) (sizeof(uint16_t)	\
	+ sizeof(((struct header *)0)->session_id)	\
	+ sizeof(uint64_t)				\
	+ sizeof(((struct header *)0)->network_id)	\
	+ sizeof(((struct header *)0)->type)		\
	+ NODE_SIZE(arg_addrlen)			\
	+ (SIG_SIZE))

#define DATA_SIZE (sizeof(((struct data *)0)->key)	\
	+ sizeof(((struct data *)0)->length))

#define FNODE_SIZE (sizeof(((struct fnode *)0)->count)	\
	+ sizeof(((struct fnode *)0)->target_id))

#define FVAL_SIZE (sizeof(((struct fval *)0)->key))

static bool message_keep_alive(const struct message *msg);
static int decode_message(int in, struct message *msg);
static int decode_header(int in, struct header *header);
static int decode_payload(int in, uint8_t type, union payload *p);
static int decode_data(int in, struct data *data);

static int send_monitor_req(int monitor, const struct header *header, uint64_t expiration, const uint8_t target_id[NODE_ID_SIZE], uint8_t sig[SIG_SIZE], uint8_t ephem_publ[EPHEM_PUBL_SIZE], uint8_t ephem_key[EPHEM_KEY_SIZE]);
static uint64_t message_length(const struct message *msg);
static uint64_t payload_length(uint8_t type, const union payload *p);
static uint64_t fnode_resp_length(const struct fnode_resp *fnode_resp);

static int encode_message(int out, struct message *msg);
static int encode_header(int out, struct header *header);
static int encode_payload(int out, uint8_t type, const union payload *p);
static int encode_data(int out, const struct data *data);

int
message_recv(int monitor, int in, struct message *msg)
{
	int pipefd[2];
	struct decrypt_arg arg;
	pthread_t th;

	if (pipe(pipefd) == -1) {
		return -1;
	}
	arg.monitor = monitor;
	arg.in = in;
	arg.out = pipefd[1];

	if (decrypt(&arg, &th) == -1) {
		close(pipefd[0]);
		close(pipefd[1]);
		return -1;
	}

	if (decode_message(pipefd[0], msg) == -1) {
		assert(pthread_cancel(th) == 0);
		assert(pthread_join(th, NULL) == 0);
		close(pipefd[0]);
		close(pipefd[1]);
		return -1;
	}

	if (message_keep_alive(msg)) {
		msg->th = th;
		msg->pipefd[0] = pipefd[0];
		msg->pipefd[1] = pipefd[1];
	} else {
		if ((errno = pthread_join(th, NULL)) != 0) {
			close(pipefd[0]);
			close(pipefd[1]);
			return -1;
		}

		if (close(pipefd[0]) == -1) {
			close(pipefd[1]);
			return -1;
		}

		if (close(pipefd[1]) == -1) {
			return -1;
		}
	}

	return 0;
}

static bool
message_keep_alive(const struct message *msg)
{
	return msg->header.type == TYPE_DATA;
}

static int
decode_message(int in, struct message *msg)
{
	uint8_t ver;

	if (read2(in, &ver, sizeof(ver)) != sizeof(ver)) {
		return -1;
	}
	if (ver != PROTO_VERSION) {
		return -1;
	}

	if (decode_header(in, &msg->header) == -1) {
		return -1;
	}

	return decode_payload(in, msg->header.type, &msg->payload);
}

static int
decode_header(int in, struct header *header)
{
	uint8_t buf[HEADER_SIZE(UINT8_MAX)];
	uint8_t *b;
	uint16_t size;
	uint64_t expiration;
	time_t now;
	uint8_t sig[SIG_SIZE];

	b = buf;

	/* SIZE */
	if (read2(in, b, sizeof(size)) != sizeof(size)) {
		return -1;
	}
	size = ntoh_16(b);
	if (size < HEADER_SIZE(0) || size > sizeof(buf)) {
		return -1;
	}
	b += sizeof(size);

	if (read2(in, b, size - sizeof(size)) != size - sizeof(size)) {
		return -1;
	}

	/* SESSION ID */
	memcpy(header->session_id, b, sizeof(header->session_id));
	b += sizeof(header->session_id);

	/* EXPIRATION */
	expiration = ntoh_64(b);
	static_assert(sizeof(time_t) == sizeof(uint64_t));
	if (expiration > INT64_MAX) {
		return -1;
	}
	if ((now = time(NULL)) == -1 || expiration < now) {
		return -1;
	}
	b += sizeof(expiration);

	/* NETWORK ID */
	memcpy(header->network_id, b, sizeof(header->network_id));
	b += sizeof(header->network_id);

	/* TYPE */
	header->type = *b;
	b += sizeof(header->type);

	/* NODE ID */
	memcpy(header->node.id, b, sizeof(header->node.id));
	b += sizeof(header->node.id);

	/* NODE DYN X */
	memcpy(header->node.dyn_x, b, sizeof(header->node.dyn_x));
	if (!valid_key(header->node.id, header->node.dyn_x)) {
		return -1;
	}
	b += sizeof(header->node.dyn_x);

	/* NODE ADDRLEN */
	header->node.addrlen = *b;
	if (size != HEADER_SIZE(header->node.addrlen)) {
		return -1;
	}
	b += sizeof(header->node.addrlen);

	/* NODE ADDR */
	memcpy(header->node.addr, b, header->node.addrlen);
	header->node.addr[header->node.addrlen] = '\0';
	b += header->node.addrlen;

	/* NODE PORT */
	header->node.port = ntoh_16(b);
	if (header->node.port == 0) {
		return -1;
	}
	b += sizeof(header->node.port);

	/* SIG */
	memcpy(sig, b, sizeof(sig));
	if (!valid_sig(sig, buf, size - sizeof(sig), header->node.id)) {
		return -1;
	}
	b += sizeof(sig);

	assert(b == buf + size);
	return 0;
}

static int
decode_payload(int in, uint8_t type, union payload *p)
{
	switch (type) {
	case TYPE_PING:
		return 0;
	case TYPE_DATA:
		return decode_data(in, &p->data);
	case TYPE_FNODE:
		return decode_fnode(in, &p->fnode);
	case TYPE_FNODE_RESP:
		return decode_fnode_resp(in, &p->fnode_resp);
	case TYPE_FVAL:
		return decode_fval(in, &p->fval);
	default:
		return -1;
	}
}

int
decode_node(int in, struct node *node)
{
	/* ID */
	if (read2(in, node->id, sizeof(node->id)) != sizeof(node->id)) {
		return -1;
	}

	/* DYN X */
	if (read2(in, node->dyn_x, sizeof(node->dyn_x)) != sizeof(node->dyn_x)) {
		return -1;
	}
	if (!valid_key(node->id, node->dyn_x)) {
		return -1;
	}

	/* ADDRLEN */
	if (read2(in, &node->addrlen, sizeof(node->addrlen)) != sizeof(node->addrlen)) {
		return -1;
	}

	/* ADDR */
	if (read2(in, node->addr, node->addrlen) != node->addrlen) {
		return -1;
	}
	node->addr[node->addrlen] = '\0';

	/* PORT */
	if (read2(in, &node->port, sizeof(node->port)) != sizeof(node->port)) {
		return -1;
	}
	node->port = ntoh_16(&node->port);
	if (node->port == 0) {
		return -1;
	}

	return 0;
}

int
decode_fnode(int in, struct fnode *fnode)
{
	uint8_t buf[FNODE_SIZE];
	uint8_t *b;

	b = buf;

	if (read2(in, buf, sizeof(buf)) != sizeof(buf)) {
		return -1;
	}

	/* COUNT */
	fnode->count = *b;
	if (fnode->count == 0) {
		return -1;
	}
	b += sizeof(fnode->count);

	/* TARGET ID */
	memcpy(fnode->target_id, b, sizeof(fnode->target_id));
	b += sizeof(fnode->target_id);

	assert(b == buf + sizeof(buf));
	return 0;
}

int
decode_fnode_resp(int in, struct fnode_resp *fnode_resp)
{
	size_t i;

	/* COUNT */
	if (read2(in, &fnode_resp->count, sizeof(fnode_resp->count)) != sizeof(fnode_resp->count)) {
		return -1;
	}

	/* NODES */
	if ((fnode_resp->nodes = malloc(fnode_resp->count * sizeof(*fnode_resp->nodes))) == NULL) {
		return -1;
	}
	for (i = 0; i < fnode_resp->count; i++) {
		if (decode_node(in, &fnode_resp->nodes[i]) == -1) {
			free(fnode_resp->nodes);
			return -1;
		}
	}

	return 0;
}

static int
decode_data(int in, struct data *data)
{
	uint8_t buf[DATA_SIZE];
	uint8_t *b;

	b = buf;

	if (read2(in, buf, sizeof(buf)) != sizeof(buf)) {
		return -1;
	}

	/* KEY */
	memcpy(data->key, b, sizeof(data->key));
	b += sizeof(data->key);

	/* LENGTH */
	data->length = ntoh_64(b);
	if (data->length == 0) {
		return -1;
	}
	b += sizeof(data->length);

	data->value = in;

	assert(b == buf + sizeof(buf));
	return 0;
}

int
decode_fval(int in, struct fval *fval)
{
	/* KEY */
	if (read2(in, fval->key, sizeof(fval->key)) != sizeof(fval->key)) {
		return -1;
	}

	return 0;
}

int
message_close(struct message *msg)
{
	if (msg->header.type == TYPE_FNODE_RESP) {
		free(msg->payload.fnode_resp.nodes);
	}

	if (!message_keep_alive(msg)) {
		/* thread and pipe already closed */
		return 0;
	}

	if ((errno = pthread_join(msg->th, NULL)) != 0) {
		close(msg->pipefd[0]);
		close(msg->pipefd[1]);
		return -1;
	}

	if (close(msg->pipefd[0]) == -1) {
		close(msg->pipefd[1]);
		return -1;
	}

	return close(msg->pipefd[1]);
}

int
message_send(int monitor, int out, struct message *msg, const uint8_t target_id[NODE_ID_SIZE])
{
	int pipefd[2];
	struct encrypt_arg arg;
	pthread_t th;
	uint8_t sig[SIG_SIZE];
	uint64_t expiration;
	time_t now;

	if ((now = time(NULL)) == -1) {
		return -1;
	}
	static_assert(sizeof(now) == sizeof(expiration));
	if (now > INT64_MAX - MESSAGE_EXPIRATION) {
		return -1;
	}
	expiration = (uint64_t)now;

	if (pipe(pipefd) == -1) {
		return -1;
	}

	arg.monitor = monitor;
	arg.in = pipefd[0];
	arg.out = out;
	arg.length = message_length(msg);

	if (send_monitor_req(monitor, &msg->header, expiration, target_id, sig, arg.ephem_publ, arg.ephem_key) == -1) {
		close(pipefd[0]);
		close(pipefd[1]);
		return -1;
	}

	if (encrypt(&arg, &th) == -1) {
		close(pipefd[0]);
		close(pipefd[1]);
		sodium_memzero(arg.ephem_key, sizeof(arg.ephem_key));
		return -1;
	}

	if (encode_message(pipefd[1], msg) == -1) {
		assert(pthread_cancel(th) == 0);
		assert(pthread_join(th, NULL) == 0);
		close(pipefd[0]);
		close(pipefd[1]);
		sodium_memzero(arg.ephem_key, sizeof(arg.ephem_key));
		return -1;
	}

	if ((errno = pthread_join(th, NULL)) != 0) {
		close(pipefd[0]);
		close(pipefd[1]);
		sodium_memzero(arg.ephem_key, sizeof(arg.ephem_key));
		return -1;
	}

	sodium_memzero(arg.ephem_key, sizeof(arg.ephem_key));

	if (close(pipefd[0]) == -1) {
		close(pipefd[1]);
		return -1;
	}

	return close(pipefd[1]);
}

static int
send_monitor_req(int monitor, const struct header *header, uint64_t expiration, const uint8_t target_id[NODE_ID_SIZE], uint8_t sig[SIG_SIZE], uint8_t ephem_publ[EPHEM_PUBL_SIZE], uint8_t ephem_key[EPHEM_KEY_SIZE])
{
	struct monitor_message req;
	struct monitor_message resp;

	req.type = M_ENCRYPT_REQ;
	memcpy(req.payload.encrypt_req.session_id, header->session_id, sizeof(req.payload.encrypt_req.session_id));
	req.payload.encrypt_req.expiration = expiration;
	memcpy(req.payload.encrypt_req.target_id, target_id, sizeof(req.payload.encrypt_req.target_id));
	if (monitor_send(monitor, &req) == -1) {
		return -1;
	}

	if (monitor_recv(monitor, &resp) == -1) {
		return -1;
	}
	if (resp.type != M_ENCRYPT_RESP) {
		return -1;
	}
	memcpy(sig, resp.payload.encrypt_resp.sig, sizeof(resp.payload.encrypt_resp.sig));
	memcpy(ephem_publ, resp.payload.encrypt_resp.ephem_publ, sizeof(resp.payload.encrypt_resp.ephem_publ));
	memcpy(ephem_key, resp.payload.encrypt_resp.ephem_key, sizeof(resp.payload.encrypt_resp.ephem_key));

	return 0;
}

static uint64_t
message_length(const struct message *msg)
{
	return sizeof(uint8_t) + HEADER_SIZE(msg->header.node.addrlen)
		+ payload_length(msg->header.type, &msg->payload);
}

static uint64_t
payload_length(uint8_t type, const union payload *p)
{
	switch (type) {
	case TYPE_PING:
		return 0;
	case TYPE_DATA:
		return DATA_SIZE + p->data.length;
	case TYPE_FNODE:
		return FNODE_SIZE;
	case TYPE_FNODE_RESP:
		return fnode_resp_length(&p->fnode_resp);
	case TYPE_FVAL:
		return FVAL_SIZE;
	default:
		return 0;
	}
}

static uint64_t
fnode_resp_length(const struct fnode_resp *fnode_resp)
{
	size_t i;
	uint64_t length = 0;

	for (i = 0; i < fnode_resp->count; i++) {
		length += NODE_SIZE(fnode_resp->nodes[i].addrlen);
	}

	return length;
}

static int
encode_message(int out, struct message *msg)
{
	if (write2(out, &PROTO_VERSION, sizeof(PROTO_VERSION)) != sizeof(PROTO_VERSION)) {
		return -1;
	}

	if (encode_header(out, &msg->header) == -1) {
		return -1;
	}

	return encode_payload(out, msg->header.type, &msg->payload);
}

static int
encode_header(int out, struct header *header)
{
	uint8_t buf[HEADER_SIZE(UINT8_MAX)];
	uint8_t *b;
	uint16_t size;
	time_t now;
	uint8_t sig[SIG_SIZE];

	b = buf;

	/* SIZE */
	size = HEADER_SIZE(header->node.addrlen);
	hton_16(b, size);
	b += sizeof(size);

	/* SESSION ID */
	memcpy(b, header->session_id, sizeof(header->session_id));
	b += sizeof(header->session_id);

	/* EXPIRATION */
	static_assert(sizeof(time_t) == sizeof(uint64_t));
	if ((now = time(NULL)) == -1) {
		return -1;
	}
	hton_64(b, (uint64_t)now);
	b += sizeof(uint64_t);

	/* NETWORK ID */
	memcpy(b, header->network_id, sizeof(header->network_id));
	b += sizeof(header->network_id);

	/* TYPE */
	*b = header->type;
	b += sizeof(header->type);

	/* NODE ID */
	memcpy(b, header->node.id, sizeof(header->node.id));
	b += sizeof(header->node.id);

	/* NODE DYN X */
	if (!valid_key(header->node.id, header->node.dyn_x)) {
		return -1;
	}
	memcpy(b, header->node.dyn_x, sizeof(header->node.dyn_x));
	b += sizeof(header->node.dyn_x);

	/* NODE ADDRLEN */
	*b = header->node.addrlen;
	b += sizeof(header->node.addrlen);

	/* NODE ADDR */
	memcpy(b, header->node.addr, header->node.addrlen);
	b += header->node.addrlen;

	/* NODE PORT */
	if (header->node.port == 0) {
		return -1;
	}
	hton_16(b, header->node.port);
	b += sizeof(header->node.port);

	/* SIG */
	assert(valid_sig(sig, buf, size - sizeof(sig), header->node.id));
	memcpy(b, sig, sizeof(sig));
	b += sizeof(sig);

	assert(b == buf + size);
	if (write2(out, buf, size) != size) {
		return -1;
	}

	return 0;
}

static int
encode_payload(int out, uint8_t type, const union payload *p)
{
	switch (type) {
	case TYPE_PING:
		return 0;
	case TYPE_DATA:
		return encode_data(out, &p->data);
	case TYPE_FNODE:
		return encode_fnode(out, &p->fnode);
	case TYPE_FNODE_RESP:
		return encode_fnode_resp(out, &p->fnode_resp);
	case TYPE_FVAL:
		return encode_fval(out, &p->fval);
	default:
		return -1;
	}
}

int
encode_node(int out, const struct node *node)
{
	uint16_t port;

	/* ID */
	if (!valid_key(node->id, node->dyn_x)) {
		return -1;
	}
	if (write2(out, node->id, sizeof(node->id)) != sizeof(node->id)) {
		return -1;
	}

	/* DYN X */
	if (write2(out, node->dyn_x, sizeof(node->dyn_x)) != sizeof(node->dyn_x)) {
		return -1;
	}

	/* ADDRLEN */
	if (write2(out, &node->addrlen, sizeof(node->addrlen)) != sizeof(node->addrlen)) {
		return -1;
	}

	/* ADDR */
	if (write2(out, node->addr, node->addrlen) != node->addrlen) {
		return -1;
	}

	/* PORT */
	if (node->port == 0) {
		return -1;
	}
	hton_16(&port, node->port);
	if (write2(out, &port, sizeof(port)) != sizeof(port)) {
		return -1;
	}

	return 0;
}


int
encode_fnode(int out, const struct fnode *fnode)
{
	uint8_t buf[FNODE_SIZE];
	uint8_t *b;

	b = buf;

	/* COUNT */
	if (fnode->count == 0) {
		return -1;
	}
	*b = fnode->count;
	b += sizeof(fnode->count);

	/* TARGET ID */
	memcpy(b, fnode->target_id, sizeof(fnode->target_id));
	b += sizeof(fnode->target_id);

	assert(b == buf + sizeof(buf));
	if (write2(out, buf, sizeof(buf)) != sizeof(buf)) {
		return -1;
	}

	return 0;
}

int
encode_fnode_resp(int out, const struct fnode_resp *fnode_resp)
{
	size_t i;

	/* COUNT */
	if (write2(out, &fnode_resp->count, sizeof(fnode_resp->count)) != sizeof(fnode_resp->count)) {
		return -1;
	}

	/* NODES */
	for (i = 0; i < fnode_resp->count; i++) {
		if (encode_node(out, &fnode_resp->nodes[i]) == -1) {
			return -1;
		}
	}

	return 0;
}

static int
encode_data(int out, const struct data *data)
{
	uint8_t buf[DATA_SIZE];
	uint8_t *b;

	b = buf;

	/* KEY */
	memcpy(b, data->key, sizeof(data->key));
	b += sizeof(data->key);

	/* LENGTH */
	if (data->length == 0) {
		return -1;
	}
	hton_64(b, data->length);
	b += sizeof(data->length);

	assert(b == buf + sizeof(buf));
	if (write2(out, buf, sizeof(buf)) != sizeof(buf)) {
		return -1;
	}

	if (copy_n(out, data->value, data->length) == -1) {
		return -1;
	}

	return 0;
}

int
encode_fval(int out, const struct fval *fval)
{
	/* KEY */
	if (write2(out, fval->key, sizeof(fval->key)) != sizeof(fval->key)) {
		return -1;
	}

	return 0;
}
