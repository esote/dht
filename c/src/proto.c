#include <assert.h>
#include <stdbool.h>
#include <string.h>

#include "bytes.h"
#include "crypto.h"
#include "io.h"
#include "proto.h"

#define PRE_BODY_SIZE sizeof(uint16_t)

/* TODO: check HDR_SIZE == 232 */
#define HDR_SIZE ((NETWORK_ID_SIZE) + sizeof(uint16_t) + (NODE_ID_SIZE) \
	+ (DYN_X_SIZE) + (IP_SIZE) + sizeof(uint16_t) + (RPC_ID_SIZE) \
	+ sizeof(uint64_t) + (NONCE_SIZE) + (SIG_SIZE))

#define NODE_TRIPLE_SIZE ((NODE_ID_SIZE) + (IP_SIZE) + sizeof(uint16_t))

#define STORE_PL_SIZE ((KEY_SIZE) + sizeof(uint64_t))
#define DATA_PL_MIN_SIZE sizeof(uint64_t)
#define FNODE_PL_SIZE (sizeof(uint8_t) + (NODE_ID_SIZE))
#define FNODE_RESP_PL_MIN_SIZE sizeof(uint8_t)
#define FVAL_PL_SIZE KEY_SIZE
#define ERR_PL_MIN_SIZE (sizeof(uint8_t) + sizeof(char))

static int write_prebody(const struct message *m, int out);
static int write_header(const struct header *hdr, const struct io *io,
	const unsigned char priv[PRIV_SIZE]);
static int write_payload(uint16_t type, const union payload *p, const struct io *io);
static int write_payload_store(const struct store_payload *p, const struct io *io);
static int write_payload_data(const struct data_payload *p, const struct io *io);
static int write_payload_fnode(const struct fnode_payload *p, const struct io *io);
static int write_payload_fnode_resp(const struct fnode_resp_payload *p,
	const struct io *io);
static int write_node_triple(const struct node_triple *n, const struct io *io);
static int write_payload_fval(const struct fval_payload *p, const struct io *io);
static int write_payload_err(const struct err_payload *p, const struct io *io);

static int read_prebody(struct message *m, int in);
static int read_header(struct header *hdr, const struct io *io);
static int read_payload(uint16_t type, union payload *p, struct io *io);
static int read_payload_store(struct store_payload *p, const struct io *io);
static int read_payload_data(struct data_payload *p, struct io *io);
static int read_payload_fnode(struct fnode_payload *p, const struct io *io);
static int read_payload_fnode_resp(struct fnode_resp_payload *p,
	const struct io *io);
static int read_node_triple(struct node_triple *n, const struct io *io);
static int read_payload_fval(struct fval_payload *p, const struct io *io);
static int read_payload_err(struct err_payload *p, const struct io *io);

int
message_encode(const struct message *m, int out,
	const unsigned char priv[PRIV_SIZE],
	const unsigned char target_publ[PUBL_SIZE])
{
	struct io *enc;
	if (write_prebody(m, out) == -1) {
		return -1;
	}
	if ((enc = encrypt(out, target_publ)) == NULL) {
		return -1;
	}
	if (write_header(&m->hdr, enc, priv) == -1) {
		(void)io_close(enc);
		return -1;
	}
	if (write_payload(m->hdr.msg_type, &m->payload, enc) == -1) {
		(void)io_close(enc);
		return -1;
	}
	return io_close(enc);
}

static int
write_prebody(const struct message *m, int out)
{
	uint8_t data[PRE_BODY_SIZE];
	uint8_t *b = data;

	hton_16(b, m->version);
	b += sizeof(m->version);

	assert(b == data + PRE_BODY_SIZE);
	if (write2(out, data, PRE_BODY_SIZE) != PRE_BODY_SIZE) {
		return -1;
	}
	return 0;
}

static int
write_header(const struct header *hdr, const struct io *io,
	const unsigned char priv[PRIV_SIZE])
{
	uint8_t data[HDR_SIZE];
	uint8_t *b = data;
	uint64_t expiration;

	(void)memcpy(b, hdr->network_id, NETWORK_ID_SIZE);
	b += NETWORK_ID_SIZE;

	hton_16(b, hdr->msg_type);
	b += sizeof(hdr->msg_type);

	(void)memcpy(b, hdr->id, NODE_ID_SIZE);
	b += NODE_ID_SIZE;

	(void)memcpy(b, hdr->dyn_x, DYN_X_SIZE);
	b += DYN_X_SIZE;

	(void)memcpy(b, hdr->ip, IP_SIZE);
	b += IP_SIZE;

	hton_16(b, hdr->port);
	b += sizeof(hdr->port);

	(void)memcpy(b, hdr->rpc_id, RPC_ID_SIZE);
	b += RPC_ID_SIZE;

	if (hdr->expiration < 0) {
		return -1;
	}
	expiration = (uint64_t)hdr->expiration;
	hton_64(b, expiration);
	b += sizeof(expiration);

	randombytes_buf(b, NONCE_SIZE);
	b += NONCE_SIZE;

	if (crypto_sign_ed25519_detached(b, NULL, data, HDR_SIZE-SIG_SIZE,
		priv) == -1) {
		return -1;
	}
	b += SIG_SIZE;

	assert(b == data + HDR_SIZE);
	if (io_write(io, data, HDR_SIZE) != HDR_SIZE) {
		return -1;
	}
	return 0;
}

static int
write_payload(uint16_t type, const union payload *p, const struct io *io)
{
	switch (type) {
	case TYPE_PING:
		return 0;
	case TYPE_STORE:
		return write_payload_store(&p->store, io);
	case TYPE_DATA:
		return write_payload_data(&p->data, io);
	case TYPE_FNODE:
		return write_payload_fnode(&p->fnode, io);
	case TYPE_FNODE_RESP:
		return write_payload_fnode_resp(&p->fnode_resp, io);
	case TYPE_FVAL:
		return write_payload_fval(&p->fval, io);
	case TYPE_ERR:
		return write_payload_err(&p->err, io);
	default:
		return -1;
	}
}

static int
write_payload_store(const struct store_payload *p, const struct io *io)
{
	uint8_t data[STORE_PL_SIZE];
	uint8_t *b;
	b = data;

	(void)memcpy(b, p->key, KEY_SIZE);
	b += KEY_SIZE;

	hton_64(b, p->length);
	b += sizeof(p->length);

	assert(b == data + STORE_PL_SIZE);
	if (io_write(io, data, STORE_PL_SIZE) != STORE_PL_SIZE) {
		return -1;
	}
	return 0;
}

static int
write_payload_data(const struct data_payload *p, const struct io *io)
{
	uint8_t data[DATA_PL_MIN_SIZE];
	uint8_t *b;
	b = data;

	hton_64(b, p->length);
	b += sizeof(p->length);

	assert(b == data + DATA_PL_MIN_SIZE);
	if (io_write(io, data, DATA_PL_MIN_SIZE) != DATA_PL_MIN_SIZE) {
		return -1;
	}

	return copy_n(p->value, io, p->length);
}

static int
write_payload_fnode(const struct fnode_payload *p, const struct io *io)
{
	uint8_t data[FNODE_PL_SIZE];
	uint8_t *b;
	b = data;

	b[0] = p->count;
	b += sizeof(p->count);

	(void)memcpy(b, p->target, NODE_ID_SIZE);
	b += NODE_ID_SIZE;

	assert(b == data + FNODE_PL_SIZE);
	if (io_write(io, data, FNODE_PL_SIZE) != FNODE_PL_SIZE) {
		return -1;
	}
	return 0;
}

static int
write_payload_fnode_resp(const struct fnode_resp_payload *p, const struct io *io)
{
	uint8_t data[FNODE_RESP_PL_MIN_SIZE];
	uint8_t *b;
	size_t i;
	b = data;

	b[0] = p->count;
	b += sizeof(p->count);

	assert(b == data + FNODE_RESP_PL_MIN_SIZE);
	if (io_write(io, data, FNODE_RESP_PL_MIN_SIZE) != FNODE_RESP_PL_MIN_SIZE) {
		return -1;
	}

	for (i = 0; i < p->count; i++) {
		if (write_node_triple(&p->nodes[i], io) == -1) {
			return -1;
		}
	}
	return 0;
}

static int
write_node_triple(const struct node_triple *n, const struct io *io)
{
	uint8_t data[NODE_TRIPLE_SIZE];
	uint8_t *b;
	b = data;

	(void)memcpy(b, n->id, NODE_ID_SIZE);
	b += NODE_ID_SIZE;

	(void)memcpy(b, n->ip, IP_SIZE);
	b += IP_SIZE;

	hton_16(b, n->port);
	b += sizeof(n->port);

	assert(b == data + NODE_TRIPLE_SIZE);
	if (io_write(io, data, NODE_TRIPLE_SIZE) != NODE_TRIPLE_SIZE) {
		return -1;
	}
	return 0;
}

static int
write_payload_fval(const struct fval_payload *p, const struct io *io)
{
	uint8_t data[FVAL_PL_SIZE];
	uint8_t *b;
	b = data;

	(void)memcpy(b, p->key, KEY_SIZE);
	b += KEY_SIZE;

	assert(b == data + FVAL_PL_SIZE);
	if (io_write(io, data, FVAL_PL_SIZE) == FVAL_PL_SIZE) {
		return -1;
	}
	return 0;
}

static int
write_payload_err(const struct err_payload *p, const struct io *io)
{
	uint8_t data[ERR_PL_MIN_SIZE];
	uint8_t *b;
	b = data;

	b[0] = p->length;
	b += sizeof(p->length);

	assert(b == data + ERR_PL_MIN_SIZE);
	if (io_write(io, data, ERR_PL_MIN_SIZE) != ERR_PL_MIN_SIZE) {
		return -1;
	}

	if (io_write(io, p->msg, p->length) != p->length) {
		return -1;
	}
	return 0;
}

struct message *
message_decode(int in, const unsigned char publ[PUBL_SIZE],
	const unsigned char priv[PRIV_SIZE])
{
	struct message *m;
	struct io *dec;
	if ((m = malloc(sizeof(*m))) == NULL) {
		return NULL;
	}
	if (read_prebody(m, in) == -1) {
		free(m);
		return NULL;
	}
	if ((dec = decrypt(in, publ, priv)) == NULL) {
		free(m);
		return NULL;
	}
	if (read_header(&m->hdr, dec) == -1) {
		(void)io_close(dec);
		free(m);
		return NULL;
	}
	if (read_payload(m->hdr.msg_type, &m->payload, dec) == -1) {
		(void)io_close(dec);
		free(m);
		return NULL;
	}
	if (io_close(dec) == -1) {
		free(m);
		return NULL;
	}
	return m;
}

void
message_free(struct message *m)
{
	switch (m->hdr.msg_type) {
	case TYPE_FNODE_RESP:
		free(m->payload.fnode_resp.nodes);
		break;
	case TYPE_ERR:
		free(m->payload.err.msg);
		break;
	}
	free(m);
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

	assert(b == data + PRE_BODY_SIZE);
	return 0;
}

static int
read_header(struct header *hdr, const struct io *io)
{
	uint8_t data[HDR_SIZE];
	uint8_t *b = data;
	uint64_t expiration;

	if (io_read(io, data, HDR_SIZE) != HDR_SIZE) {
		return -1;
	}

	(void)memcpy(hdr->network_id, b, NETWORK_ID_SIZE);
	b += NETWORK_ID_SIZE;

	hdr->msg_type = ntoh_16(b);
	b += sizeof(hdr->msg_type);

	(void)memcpy(hdr->id, b, NODE_ID_SIZE);
	b += NODE_ID_SIZE;

	(void)memcpy(hdr->dyn_x, b, DYN_X_SIZE);
	b += DYN_X_SIZE;

	(void)memcpy(hdr->ip, b, IP_SIZE);
	b += IP_SIZE;

	hdr->port = ntoh_16(b);
	b += sizeof(hdr->port);

	(void)memcpy(hdr->rpc_id, b, RPC_ID_SIZE);
	b += RPC_ID_SIZE;

	expiration = ntoh_64(b);
	if (sizeof(time_t) == sizeof(uint64_t) && expiration > INT64_MAX) {
		/* unsigned 64-bit expiration overflows time_t */
		return -1;
	}
	hdr->expiration = (time_t)expiration;
	assert(hdr->expiration >= 0);
	b += sizeof(expiration);

	b += NONCE_SIZE;

	if (crypto_sign_ed25519_verify_detached(b, data, HDR_SIZE-SIG_SIZE,
		hdr->id) == -1) {
		return -1;
	}
	b += SIG_SIZE;

	assert(b == data + HDR_SIZE);
	return 0;
}

static int
read_payload(uint16_t type, union payload *p, struct io *io)
{
	switch (type) {
	case TYPE_PING:
		return 0;
	case TYPE_STORE:
		return read_payload_store(&p->store, io);
	case TYPE_DATA:
		return read_payload_data(&p->data, io);
	case TYPE_FNODE:
		return read_payload_fnode(&p->fnode, io);
	case TYPE_FNODE_RESP:
		return read_payload_fnode_resp(&p->fnode_resp, io);
	case TYPE_FVAL:
		return read_payload_fval(&p->fval, io);
	case TYPE_ERR:
		return read_payload_err(&p->err, io);
	default:
		return -1;
	}
}

static int
read_payload_store(struct store_payload *p, const struct io *io)
{
	uint8_t data[STORE_PL_SIZE];
	uint8_t *b = data;

	if (io_read(io, data, STORE_PL_SIZE) != STORE_PL_SIZE) {
		return -1;
	}

	(void)memcpy(p->key, b, KEY_SIZE);
	b += KEY_SIZE;

	p->length = ntoh_64(b);
	b += sizeof(p->length);

	assert(b == data + STORE_PL_SIZE);
	return 0;
}

static int
read_payload_data(struct data_payload *p, struct io *io)
{
	uint8_t data[DATA_PL_MIN_SIZE];
	uint8_t *b;
	b = data;

	if (io_read(io, data, DATA_PL_MIN_SIZE) != DATA_PL_MIN_SIZE) {
		return -1;
	}

	p->length = ntoh_64(b);
	b += sizeof(p->length);

	assert(b == data + DATA_PL_MIN_SIZE);
	p->value = io;
	return 0;
}

static int
read_payload_fnode(struct fnode_payload *p, const struct io *io)
{
	uint8_t data[FNODE_PL_SIZE];
	uint8_t *b;
	b = data;

	if (io_read(io, data, FNODE_PL_SIZE) != FNODE_PL_SIZE) {
		return -1;
	}
	p->count = b[0];
	b += sizeof(p->count);

	(void)memcpy(p->target, b, NODE_ID_SIZE);
	b += NODE_ID_SIZE;

	assert(b == data + FNODE_PL_SIZE);
	return 0;
}

static int
read_payload_fnode_resp(struct fnode_resp_payload *p, const struct io *io)
{
	uint8_t data[FNODE_RESP_PL_MIN_SIZE];
	uint8_t *b;
	size_t i;
	b = data;

	if (io_read(io, data, FNODE_RESP_PL_MIN_SIZE) != FNODE_RESP_PL_MIN_SIZE) {
		return -1;
	}
	p->count = b[0];
	b += sizeof(p->count);

	assert(b == data + FNODE_RESP_PL_MIN_SIZE);

	if ((p->nodes = malloc(NODE_TRIPLE_SIZE * (size_t)p->count)) == NULL) {
		return -1;
	}
	for (i = 0; i < p->count; i++) {
		if (read_node_triple(&p->nodes[i], io) == -1) {
			free(p->nodes);
			return -1;
		}
	}
	return 0;
}

static int
read_node_triple(struct node_triple *n, const struct io *io)
{
	uint8_t data[NODE_TRIPLE_SIZE];
	uint8_t *b;
	b = data;

	if (io_read(io, data, NODE_TRIPLE_SIZE) != NODE_TRIPLE_SIZE) {
		return -1;
	}

	(void)memcpy(n->id, b, NODE_ID_SIZE);
	b += NODE_ID_SIZE;

	(void)memcpy(n->ip, b, IP_SIZE);
	b += IP_SIZE;

	n->port = ntoh_16(b);
	b += sizeof(n->port);

	assert(b == data + NODE_TRIPLE_SIZE);
	return 0;
}

static int
read_payload_fval(struct fval_payload *p, const struct io *io)
{
	uint8_t data[FVAL_PL_SIZE];
	uint8_t *b;
	b = data;

	if (io_read(io, data, FVAL_PL_SIZE) == FVAL_PL_SIZE) {
		return -1;
	}

	(void)memcpy(p->key, b, KEY_SIZE);
	b += KEY_SIZE;

	assert(b == data + FVAL_PL_SIZE);
	return 0;
}

static int
read_payload_err(struct err_payload *p, const struct io *io)
{
	uint8_t data[ERR_PL_MIN_SIZE];
	uint8_t *b;
	b = data;

	if (io_read(io, data, ERR_PL_MIN_SIZE) != ERR_PL_MIN_SIZE) {
		return -1;
	}

	p->length = b[0];
	b += sizeof(p->length);

	assert(b == data + ERR_PL_MIN_SIZE);

	if ((p->msg = malloc(p->length)) == NULL) {
		return -1;
	}
	if (io_read(io, p->msg, p->length) != p->length) {
		free(p->msg);
		return -1;
	}
	return 0;
}

