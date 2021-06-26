#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "bytes.h"
#include "crypto.h"
#include "crypto_stream.h"
#include "io.h"
#include "proto.h"

#define PRE_BODY_SIZE sizeof(uint16_t)

#define IP_SIZE sizeof(((struct in6_addr *)0)->s6_addr)
#define HDR_SIZE ((NETWORK_ID_SIZE) + sizeof(uint16_t) + (NODE_ID_SIZE) \
	+ (DYN_X_SIZE) + (IP_SIZE) + sizeof(uint16_t) + (RPC_ID_SIZE) \
	+ sizeof(uint64_t) + (SIG_SIZE))

#define NODE_SIZE ((NODE_ID_SIZE) + (IP_SIZE) + sizeof(uint16_t))

#define DATA_PL_SIZE ((KEY_SIZE) + sizeof(uint64_t))
#define FNODE_PL_SIZE (sizeof(uint8_t) + (NODE_ID_SIZE))
#define FNODE_RESP_PL_SIZE sizeof(uint8_t)
#define FVAL_PL_SIZE KEY_SIZE

static int write_prebody(const struct message *m, int out);
static int write_header(const struct header *hdr, int out,
	const unsigned char priv[PRIV_SIZE]);
static int write_payload(uint16_t type, const union payload *p, int out);
static int write_payload_data(const struct data_payload *p, int out);
static int write_payload_fnode(const struct fnode_payload *p, int out);
static int write_payload_fnode_resp(const struct fnode_resp_payload *p, int out);
static int write_node(const struct node *n, int out);
static int write_payload_fval(const struct fval_payload *p, int out);

static int read_prebody(struct message *m, int in);
static int read_header(struct header *hdr, int in);
static int read_payload(uint16_t type, union payload *p, int in);
static int read_payload_data(struct data_payload *p, int in);
static int read_payload_fnode(struct fnode_payload *p, int in);
static int read_payload_fnode_resp(struct fnode_resp_payload *p, int in);
static int read_node(struct node *n, int in);
static int read_payload_fval(struct fval_payload *p, int in);
static bool decode_keep_open(const struct message *m);

int
message_encode(const struct message *m, int out,
	const unsigned char priv[PRIV_SIZE],
	const unsigned char target_publ[PUBL_SIZE])
{
	int in;
	pid_t child;
	int status;

	if (write_prebody(m, out) == -1) {
		return -1;
	}

	if ((child = encrypt(&in, out, target_publ)) == -1) {
		return -1;
	}

	if (write_header(&m->hdr, in, priv) == -1) {
		(void)close(in);
		return -1;
	}
	if (write_payload(m->hdr.msg_type, &m->payload, in) == -1) {
		(void)close(in);
		return -1;
	}

	if (close(in) == -1) {
		return -1;
	}
	while (waitpid(child, &status, 0) == -1) {
		if (errno == EINTR) {
			errno = 0;
			continue;
		}
		return -1;
	}
	return 0;
}

static bool
valid_version(uint16_t version)
{
	switch (version) {
	case VERSION:
		return true;
	default:
		return false;
	}
}

static int
write_prebody(const struct message *m, int out)
{
	uint8_t data[PRE_BODY_SIZE];
	uint8_t *b = data;

	if (!valid_version(m->version)) {
		return -1;
	}
	hton_16(b, m->version);
	b += sizeof(m->version);

	assert(b == data + PRE_BODY_SIZE);
	if (write2(out, data, PRE_BODY_SIZE) != PRE_BODY_SIZE) {
		return -1;
	}
	return 0;
}

static bool
valid_msg_type(uint16_t msg_type) {
	switch (msg_type) {
	case TYPE_PING:
	case TYPE_DATA:
	case TYPE_FNODE:
	case TYPE_FNODE_RESP:
	case TYPE_FVAL:
		return true;
	default:
		return false;
	}
}

static int
write_header(const struct header *hdr, int out,
	const unsigned char priv[PRIV_SIZE])
{
	uint8_t data[HDR_SIZE];
	uint8_t *b = data;
	uint64_t expiration;
	time_t now;

	if (is_zero(hdr->network_id, NETWORK_ID_SIZE)) {
		return -1;
	}
	(void)memcpy(b, hdr->network_id, NETWORK_ID_SIZE);
	b += NETWORK_ID_SIZE;

	if (!valid_msg_type(hdr->msg_type)) {
		return -1;
	}
	hton_16(b, hdr->msg_type);
	b += sizeof(hdr->msg_type);

	if (!valid_key(hdr->id, hdr->dyn_x)) {
		return -1;
	}
	(void)memcpy(b, hdr->id, NODE_ID_SIZE);
	b += NODE_ID_SIZE;

	(void)memcpy(b, hdr->dyn_x, DYN_X_SIZE);
	b += DYN_X_SIZE;

	(void)memcpy(b, hdr->ip.s6_addr, IP_SIZE);
	b += IP_SIZE;

	if (hdr->port == 0) {
		return -1;
	}
	hton_16(b, hdr->port);
	b += sizeof(hdr->port);

	(void)memcpy(b, hdr->rpc_id, RPC_ID_SIZE);
	b += RPC_ID_SIZE;

	if ((now = time(NULL)) == -1 || hdr->expiration < now) {
		return -1;
	}
	expiration = (uint64_t)hdr->expiration;
	hton_64(b, expiration);
	b += sizeof(expiration);

	if (sign(b, data, HDR_SIZE - SIG_SIZE, priv) == -1) {
		return -1;
	}
	b += SIG_SIZE;

	assert(b == data + HDR_SIZE);
	if (write2(out, data, HDR_SIZE) != HDR_SIZE) {
		return -1;
	}
	return 0;
}

static int
write_payload(uint16_t type, const union payload *p, int out)
{
	switch (type) {
	case TYPE_PING:
		return 0;
	case TYPE_DATA:
		return write_payload_data(&p->data, out);
	case TYPE_FNODE:
		return write_payload_fnode(&p->fnode, out);
	case TYPE_FNODE_RESP:
		return write_payload_fnode_resp(&p->fnode_resp, out);
	case TYPE_FVAL:
		return write_payload_fval(&p->fval, out);
	default:
		return -1;
	}
}

static int
write_payload_data(const struct data_payload *p, int out)
{
	uint8_t data[DATA_PL_SIZE];
	uint8_t *b;
	b = data;

	(void)memcpy(b, p->key, KEY_SIZE);
	b += KEY_SIZE;

	if (p->length == 0) {
		return -1;
	}
	hton_64(b, p->length);
	b += sizeof(p->length);

	assert(b == data + DATA_PL_SIZE);
	if (write2(out, data, DATA_PL_SIZE) != DATA_PL_SIZE) {
		return -1;
	}

	return copy_n(p->value, out, p->length);
}

static int
write_payload_fnode(const struct fnode_payload *p, int out)
{
	uint8_t data[FNODE_PL_SIZE];
	uint8_t *b;
	b = data;

	if (p->count == 0) {
		return -1;
	}
	b[0] = p->count;
	b += sizeof(p->count);

	(void)memcpy(b, p->target, NODE_ID_SIZE);
	b += NODE_ID_SIZE;

	assert(b == data + FNODE_PL_SIZE);
	if (write2(out, data, FNODE_PL_SIZE) != FNODE_PL_SIZE) {
		return -1;
	}
	return 0;
}

static int
write_payload_fnode_resp(const struct fnode_resp_payload *p, int out)
{
	uint8_t data[FNODE_RESP_PL_SIZE];
	uint8_t *b;
	size_t i;
	b = data;

	b[0] = p->count;
	b += sizeof(p->count);

	assert(b == data + FNODE_RESP_PL_SIZE);
	if (write2(out, data, FNODE_RESP_PL_SIZE) != FNODE_RESP_PL_SIZE) {
		return -1;
	}

	for (i = 0; i < p->count; i++) {
		if (write_node(&p->nodes[i], out) == -1) {
			return -1;
		}
	}
	return 0;
}

static int
write_node(const struct node *n, int out)
{
	uint8_t data[NODE_SIZE];
	uint8_t *b;
	b = data;

	(void)memcpy(b, n->id, NODE_ID_SIZE);
	b += NODE_ID_SIZE;

	(void)memcpy(b, n->ip.s6_addr, IP_SIZE);
	b += IP_SIZE;

	if (n->port == 0) {
		return -1;
	}
	hton_16(b, n->port);
	b += sizeof(n->port);

	assert(b == data + NODE_SIZE);
	if (write2(out, data, NODE_SIZE) != NODE_SIZE) {
		return -1;
	}
	return 0;
}

static int
write_payload_fval(const struct fval_payload *p, int out)
{
	uint8_t data[FVAL_PL_SIZE];
	uint8_t *b;
	b = data;

	(void)memcpy(b, p->key, KEY_SIZE);
	b += KEY_SIZE;

	assert(b == data + FVAL_PL_SIZE);
	if (write2(out, data, FVAL_PL_SIZE) != FVAL_PL_SIZE) {
		return -1;
	}
	return 0;
}

struct message *
message_decode(int in, const unsigned char publ[PUBL_SIZE],
	const unsigned char priv[PRIV_SIZE])
{
	struct message *m;
	int out;
	pid_t child;
	int status;

	if ((m = malloc(sizeof(*m))) == NULL) {
		return NULL;
	}
	if (read_prebody(m, in) == -1) {
		free(m);
		return NULL;
	}

	if ((child = decrypt(in, &out, publ, priv)) == -1) {
		free(m);
		return NULL;
	}

	if (read_header(&m->hdr, out) == -1) {
		(void)close(out);
		free(m);
		return NULL;
	}
	if (read_payload(m->hdr.msg_type, &m->payload, out) == -1) {
		(void)close(out);
		free(m);
		return NULL;
	}
	if (!decode_keep_open(m)) {
		if (close(out) == -1) {
			free(m);
			return NULL;
		}
		while (waitpid(child, &status, 0) == -1) {
			if (errno == EINTR) {
				errno = 0;
				continue;
			}
			free(m);
			return NULL;
		}
	}
	return m;
}

int
message_close(struct message *m)
{
	int ret = 0;
	switch (m->hdr.msg_type) {
	case TYPE_DATA:
		ret = close(m->payload.data.value);
	case TYPE_FNODE_RESP:
		free(m->payload.fnode_resp.nodes);
		break;
	}
	free(m);
	return ret;
}

static int
read_prebody(struct message *m, int in)
{
	uint8_t data[PRE_BODY_SIZE];
	uint8_t *b = data;

	if (read2(in, data, PRE_BODY_SIZE) != PRE_BODY_SIZE) {
		return -1;
	}

	m->version = ntoh_16(b);
	b += sizeof(m->version);
	if (m->version != VERSION) {
		return -1;
	}

	assert(b == data + PRE_BODY_SIZE);
	return 0;
}

static int
read_header(struct header *hdr, int in)
{
	uint8_t data[HDR_SIZE];
	uint8_t *b = data;
	uint64_t expiration;
	time_t now;

	if (read2(in, data, HDR_SIZE) != HDR_SIZE) {
		return -1;
	}

	(void)memcpy(hdr->network_id, b, NETWORK_ID_SIZE);
	b += NETWORK_ID_SIZE;
	if (is_zero(hdr->network_id, NETWORK_ID_SIZE)) {
		return -1;
	}

	hdr->msg_type = ntoh_16(b);
	b += sizeof(hdr->msg_type);
	if (!valid_msg_type(hdr->msg_type)) {
		return -1;
	}

	(void)memcpy(hdr->id, b, NODE_ID_SIZE);
	b += NODE_ID_SIZE;

	(void)memcpy(hdr->dyn_x, b, DYN_X_SIZE);
	b += DYN_X_SIZE;
	if (!valid_key(hdr->id, hdr->dyn_x)) {
		return -1;
	}

	(void)memcpy(hdr->ip.s6_addr, b, IP_SIZE);
	b += IP_SIZE;

	hdr->port = ntoh_16(b);
	b += sizeof(hdr->port);
	if (hdr->port == 0) {
		return -1;
	}

	(void)memcpy(hdr->rpc_id, b, RPC_ID_SIZE);
	b += RPC_ID_SIZE;

	expiration = ntoh_64(b);
	if (sizeof(time_t) == sizeof(uint64_t) && expiration > INT64_MAX) {
		/* uint64_t time overflows time_t */
		return -1;
	}
	hdr->expiration = (time_t)expiration;
	assert(hdr->expiration >= 0);
	b += sizeof(expiration);
	if ((now = time(NULL)) == -1 || hdr->expiration < now) {
		return -1;
	}

	if (!sign_verify(b, data, HDR_SIZE - SIG_SIZE, hdr->id)) {
		return -1;
	}
	b += SIG_SIZE;

	assert(b == data + HDR_SIZE);
	return 0;
}

static int
read_payload(uint16_t type, union payload *p, int in)
{
	switch (type) {
	case TYPE_PING:
		return 0;
	case TYPE_DATA:
		return read_payload_data(&p->data, in);
	case TYPE_FNODE:
		return read_payload_fnode(&p->fnode, in);
	case TYPE_FNODE_RESP:
		return read_payload_fnode_resp(&p->fnode_resp, in);
	case TYPE_FVAL:
		return read_payload_fval(&p->fval, in);
	default:
		return -1;
	}
}

static int
read_payload_data(struct data_payload *p, int in)
{
	uint8_t data[DATA_PL_SIZE];
	uint8_t *b;
	b = data;

	if (read2(in, data, DATA_PL_SIZE) != DATA_PL_SIZE) {
		return -1;
	}

	(void)memcpy(p->key, b, KEY_SIZE);
	b += KEY_SIZE;

	p->length = ntoh_64(b);
	b += sizeof(p->length);
	if (p->length == 0) {
		return -1;
	}

	assert(b == data + DATA_PL_SIZE);

	/* in kept open, referenced as data value */
	p->value = in;
	return 0;
}

static int
read_payload_fnode(struct fnode_payload *p, int in)
{
	uint8_t data[FNODE_PL_SIZE];
	uint8_t *b;
	b = data;

	if (read2(in, data, FNODE_PL_SIZE) != FNODE_PL_SIZE) {
		return -1;
	}

	p->count = b[0];
	b += sizeof(p->count);
	if (p->count == 0) {
		return -1;
	}

	(void)memcpy(p->target, b, NODE_ID_SIZE);
	b += NODE_ID_SIZE;

	assert(b == data + FNODE_PL_SIZE);
	return 0;
}

static int
read_payload_fnode_resp(struct fnode_resp_payload *p, int in)
{
	uint8_t data[FNODE_RESP_PL_SIZE];
	uint8_t *b;
	size_t i;
	b = data;

	if (read2(in, data, FNODE_RESP_PL_SIZE) != FNODE_RESP_PL_SIZE) {
		return -1;
	}

	p->count = b[0];
	b += sizeof(p->count);

	assert(b == data + FNODE_RESP_PL_SIZE);

	p->nodes = malloc(NODE_SIZE * (size_t)p->count);
	if (p->nodes == NULL && p->count != 0) {
		return -1;
	}
	for (i = 0; i < p->count; i++) {
		if (read_node(&p->nodes[i], in) == -1) {
			free(p->nodes);
			return -1;
		}
	}
	return 0;
}

static int
read_node(struct node *n, int in)
{
	uint8_t data[NODE_SIZE];
	uint8_t *b;
	b = data;

	if (read2(in, data, NODE_SIZE) != NODE_SIZE) {
		return -1;
	}

	(void)memcpy(n->id, b, NODE_ID_SIZE);
	b += NODE_ID_SIZE;

	(void)memcpy(n->ip.s6_addr, b, IP_SIZE);
	b += IP_SIZE;

	n->port = ntoh_16(b);
	b += sizeof(n->port);
	if (n->port == 0) {
		return -1;
	}

	assert(b == data + NODE_SIZE);
	return 0;
}

static int
read_payload_fval(struct fval_payload *p, int in)
{
	uint8_t data[FVAL_PL_SIZE];
	uint8_t *b;
	b = data;

	if (read2(in, data, FVAL_PL_SIZE) != FVAL_PL_SIZE) {
		return -1;
	}

	(void)memcpy(p->key, b, KEY_SIZE);
	b += KEY_SIZE;

	assert(b == data + FVAL_PL_SIZE);
	return 0;
}

static bool
decode_keep_open(const struct message *m)
{
	return m->hdr.msg_type == TYPE_DATA;
}
