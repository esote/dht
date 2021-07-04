#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "bytes.h"
#include "crypto.h"
#include "crypto_stream.h"
#include "io.h"
#include "proto.h"

static bool supported_version(uint16_t version);
static bool supported_msg_type(uint16_t msg_type);
static bool message_keep_open(const struct message *m);
static void free_node(struct node *n);
static int payload_close(uint16_t msg_type, union payload *p);

static int write_prebody(const struct message *m, int out);
static int write_node(const struct node *n, int out);
static int write_header(const struct header *hdr, int out,
	const unsigned char priv[PRIV_SIZE]);
static int write_payload(uint16_t type, const union payload *p, int out);
static int write_payload_data(const struct data_payload *p, int out);
static int write_payload_fnode(const struct fnode_payload *p, int out);
static int write_payload_fnode_resp(const struct fnode_resp_payload *p, int out);
static int write_payload_fval(const struct fval_payload *p, int out);

static int read_prebody(struct message *m, int in);
static int read_node(struct node *n, int in);
static int read_header(struct header *hdr, int in);
static int read_payload(uint16_t type, union payload *p, int in);
static int read_payload_data(struct data_payload *p, int in);
static int read_payload_fnode(struct fnode_payload *p, int in);
static int read_payload_fnode_resp(struct fnode_resp_payload *p, int in);
static int read_payload_fval(struct fval_payload *p, int in);

int
message_encode(const struct message *m, int out,
	const unsigned char priv[PRIV_SIZE],
	const unsigned char target_publ[PUBL_SIZE])
{
	int in;
	pid_t child;
	int status;

	/* prebody is unencrypted */
	if (write_prebody(m, out) == -1) {
		return -1;
	}

	/* get input fd to encrypt body */
	if ((child = encrypt(&in, out, target_publ)) == -1) {
		return -1;
	}

	if (write_header(&m->hdr, in, priv) == -1) {
		(void)close(in);
		(void)kill(child, SIGKILL);
		return -1;
	}
	if (write_payload(m->hdr.msg_type, &m->payload, in) == -1) {
		(void)close(in);
		(void)kill(child, SIGKILL);
		return -1;
	}

	if (close(in) == -1) {
		(void)kill(child, SIGKILL);
		return -1;
	}

	/* wait for encryption to stop, check return code */
	while (waitpid(child, &status, 0) == -1) {
		if (errno == EINTR) {
			errno = 0;
			continue;
		}
		(void)kill(child, SIGKILL);
		return -1;
	}
	if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
		/* child exited normally */
		return 0;
	}

	/* child failed */
	return -1;
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
	m->_child = -1;
	m->hdr.msg_type = TYPE_PING;
	m->hdr.node.addr = NULL;

	/* prebody is unencrypted */
	if (read_prebody(m, in) == -1) {
		(void)message_close(m);
		return NULL;
	}

	/* get output fd to decrypt body */
	if ((child = decrypt(in, &out, publ, priv)) == -1) {
		(void)message_close(m);
		return NULL;
	}
	m->_child = child;

	if (read_header(&m->hdr, out) == -1) {
		(void)message_close(m);
		return NULL;
	}
	if (read_payload(m->hdr.msg_type, &m->payload, out) == -1) {
		(void)message_close(m);
		return NULL;
	}

	if (message_keep_open(m)) {
		/* return early, keep the message fd open and child running */
		return m;
	}

	/* close output fd, wait for child to stop, check output status */
	if (close(out) == -1) {
		(void)message_close(m);
		return NULL;
	}
	while (waitpid(child, &status, 0) == -1) {
		if (errno == EINTR) {
			errno = 0;
			continue;
		}
		(void)message_close(m);
		return NULL;
	}
	m->_child = -1;
	if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
		/* child exited normally */
		return m;
	}

	/* child failed */
	(void)message_close(m);
	return NULL;
}

int
message_close(struct message *m)
{
	int ret;
	ret = payload_close(m->hdr.msg_type, &m->payload);
	if (m->_child != -1 && kill(m->_child, SIGKILL) == -1) {
		ret = -1;
	}
	free_node(&m->hdr.node);
	free(m);
	return ret;
}

static bool
supported_version(uint16_t version)
{
	return version == VERSION;
}

static bool
supported_msg_type(uint16_t msg_type)
{
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

static bool
message_keep_open(const struct message *m)
{
	return m->hdr.msg_type == TYPE_DATA;
}

static void
free_node(struct node *n)
{
	free(n->addr);
}

static int
payload_close(uint16_t msg_type, union payload *p)
{
	size_t i;
	switch (msg_type) {
	case TYPE_DATA:
		if (close(p->data.value) == -1) {
			return -1;
		}
		return 0;
	case TYPE_FNODE_RESP:
		for (i = 0; i < p->fnode_resp.count; i++) {
			free_node(&p->fnode_resp.nodes[i]);
		}
		free(p->fnode_resp.nodes);
		return 0;
	default:
		return 0;
	}
}

static int
write_prebody(const struct message *m, int out)
{
	uint8_t version[sizeof(m->version)];

	/* VERSION */
	if (!supported_version(m->version)) {
		return -1;
	}
	hton_16(version, m->version);
	if (write2(out, version, sizeof(version)) != sizeof(version)) {
		return -1;
	}

	return 0;
}

static int
write_node(const struct node *n, int out)
{
	size_t str_addrlen;
	uint8_t addrlen[sizeof(uint16_t)];
	uint8_t port[sizeof(n->port)];

	/* ID */
	if (write2(out, n->id, NODE_ID_SIZE) != NODE_ID_SIZE) {
		return -1;
	}

	/* DYN X */
	if (write2(out, n->dyn_x, DYN_X_SIZE) != DYN_X_SIZE) {
		return -1;
	}

	/* ADDRLEN */
	str_addrlen = strlen(n->addr); /* TODO: at most sizeof(uint16_t)+1 bytes */
	if (str_addrlen > UINT16_MAX) {
		return -1;
	}
	hton_16(addrlen, (uint16_t)str_addrlen);
	if (write2(out, addrlen, sizeof(addrlen)) != sizeof(addrlen)) {
		return -1;
	}

	/* ADDR */
	if (write2(out, n->addr, str_addrlen) != str_addrlen) {
		return -1;
	}

	/* PORT */
	hton_16(port, n->port);
	if (write2(out, port, sizeof(port)) != sizeof(port)) {
		return -1;
	}

	return 0;
}

#define SIG_BODY_SIZE ((SESSION_ID_SIZE) + sizeof(uint64_t))

static int
write_header(const struct header *hdr, int out,
	const unsigned char priv[PRIV_SIZE])
{
	uint8_t sig_body[SIG_BODY_SIZE];
	uint8_t sig[SIG_SIZE];
	uint8_t *p;
	uint64_t expiration;
	uint8_t msg_type[sizeof(hdr->msg_type)];

	p = sig_body;

	/* SESSION ID */
	(void)memcpy(p, hdr->session_id, SESSION_ID_SIZE);
	p += SESSION_ID_SIZE;

	/* EXPIRATION */
	if (hdr->expiration < 0) {
		return -1;
	}
	expiration = (uint64_t)hdr->expiration;
	hton_64(p, expiration);
	p += sizeof(expiration);

	if (write2(out, sig_body, SIG_BODY_SIZE) != SIG_BODY_SIZE) {
		return -1;
	}

	/* SIG */
	if (sign(sig, sig_body, SIG_BODY_SIZE, priv) == -1) {
		return -1;
	}
	if (write2(out, sig, SIG_SIZE) != SIG_SIZE) {
		return -1;
	}

	/* NETWORK ID */
	if (write2(out, hdr->network_id, NETWORK_ID_SIZE) != NETWORK_ID_SIZE) {
		return -1;
	}

	/* MSG TYPE */
	if (!supported_msg_type(hdr->msg_type)) {
		return -1;
	}
	hton_16(msg_type, hdr->msg_type);
	if (write2(out, msg_type, sizeof(msg_type)) != sizeof(msg_type)) {
		return -1;
	}

	if (write_node(&hdr->node, out) == -1) {
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
	uint8_t length[sizeof(p->length)];

	/* KEY */
	if (write2(out, p->key, KEY_SIZE) != KEY_SIZE) {
		return -1;
	}

	/* LENGTH */
	hton_64(length, p->length);
	if (write2(out, length, sizeof(length)) != sizeof(length)) {
		return -1;
	}

	/* VALUE */
	if (copy_n(p->value, out, p->length) == -1) {
		return -1;
	}

	return 0;
}

static int
write_payload_fnode(const struct fnode_payload *p, int out)
{
	/* COUNT */
	if (write2(out, &p->count, sizeof(p->count)) != sizeof(p->count)) {
		return -1;
	}

	/* TARGET ID */
	if (write2(out, p->target_id, NODE_ID_SIZE) != NODE_ID_SIZE) {
		return -1;
	}

	/* TARGET DYN X */
	if (write2(out, p->target_dyn_x, DYN_X_SIZE) != DYN_X_SIZE) {
		return -1;
	}

	return 0;
}

static int
write_payload_fnode_resp(const struct fnode_resp_payload *p, int out)
{
	size_t i;

	/* COUNT */
	if (write2(out, &p->count, sizeof(p->count)) != sizeof(p->count)) {
		return -1;
	}

	/* NODES */
	for (i = 0; i < p->count; i++) {
		if (write_node(&p->nodes[i], out) == -1) {
			return -1;
		}
	}

	return 0;
}

static int
write_payload_fval(const struct fval_payload *p, int out)
{
	/* KEY */
	if (write2(out, p->key, KEY_SIZE) != KEY_SIZE) {
		return -1;
	}

	return 0;
}

static int
read_prebody(struct message *m, int in)
{
	uint8_t version[sizeof(m->version)];

	/* VERSION */
	if (read2(in, version, sizeof(version)) != sizeof(version)) {
		return -1;
	}
	m->version = ntoh_16(version);
	if (!supported_version(m->version)) {
		return -1;
	}

	return 0;
}

static int
read_node(struct node *n, int in)
{
	size_t str_addrlen;
	uint8_t addrlen[sizeof(uint16_t)];
	uint8_t port[sizeof(n->port)];

	/* ID */
	if (read2(in, n->id, NODE_ID_SIZE) != NODE_ID_SIZE) {
		return -1;
	}

	/* DYN X */
	if (read2(in, n->dyn_x, DYN_X_SIZE) != DYN_X_SIZE) {
		return -1;
	}

	/* ADDRLEN */
	if (read2(in, addrlen, sizeof(addrlen)) != sizeof(addrlen)) {
		return -1;
	}
	str_addrlen = (size_t)ntoh_16(addrlen);

	/* ADDR */
	if ((n->addr = malloc(str_addrlen + 1)) == NULL) {
		return -1;
	}
	if (read2(in, n->addr, str_addrlen) != str_addrlen) {
		free(n->addr);
		return -1;
	}
	n->addr[str_addrlen] = '\0';

	/* PORT */
	if (read2(in, port, sizeof(port)) != sizeof(port)) {
		free(n->addr);
		return -1;
	}
	n->port = ntoh_16(port);

	return 0;
}

static int
read_header(struct header *hdr, int in)
{
	uint8_t sig_body[SIG_BODY_SIZE];
	uint8_t sig[SIG_SIZE];
	uint8_t *p;
	uint64_t expiration;
	uint8_t msg_type[sizeof(hdr->msg_type)];

	p = sig_body;

	if (read2(in, sig_body, SIG_BODY_SIZE) != SIG_BODY_SIZE) {
		return -1;
	}

	/* SESSION ID */
	(void)memcpy(hdr->session_id, p, SESSION_ID_SIZE);
	p += SESSION_ID_SIZE;

	/* EXPIRATION */
	expiration = ntoh_64(p);
	p += sizeof(expiration);
	if ((sizeof(time_t) == sizeof(uint64_t)) && expiration > INT64_MAX) {
		/* uint64_t time overflows time_t */
		return -1;
	}
	hdr->expiration = (time_t)expiration;
	assert(hdr->expiration >= 0);

	/* SIG */
	if (read2(in, sig, SIG_SIZE) != SIG_SIZE) {
		return -1;
	}

	/* NETWORK ID */
	if (read2(in, hdr->network_id, NETWORK_ID_SIZE) != NETWORK_ID_SIZE) {
		return -1;
	}

	/* MSG TYPE */
	if (read2(in, msg_type, sizeof(msg_type)) != sizeof(msg_type)) {
		return -1;
	}
	hdr->msg_type = ntoh_16(msg_type);

	if (read_node(&hdr->node, in) == -1) {
		return -1;
	}

	if (!sign_verify(sig, sig_body, SIG_BODY_SIZE, hdr->node.id)) {
		free_node(&hdr->node);
		return -1;
	}

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
	uint8_t length[sizeof(p->length)];

	/* KEY */
	if (read2(in, p->key, KEY_SIZE) != KEY_SIZE) {
		return -1;
	}

	/* LENGTH */
	if (read2(in, length, sizeof(length)) != sizeof(length)) {
		return -1;
	}
	p->length = ntoh_64(length);
	if (p->length == 0) {
		return -1;
	}

	/* VALUE */
	p->value = in; /* in is kept open, referenced as value */
	return 0;
}

static int
read_payload_fnode(struct fnode_payload *p, int in)
{
	/* COUNT */
	if (read2(in, &p->count, sizeof(p->count)) != sizeof(p->count)) {
		return -1;
	}

	/* TARGET ID */
	if (read2(in, p->target_id, NODE_ID_SIZE) != NODE_ID_SIZE) {
		return -1;
	}

	/* TARGET DYN X */
	if (read2(in, p->target_dyn_x, DYN_X_SIZE) != DYN_X_SIZE) {
		return -1;
	}

	return 0;
}

static int
read_payload_fnode_resp(struct fnode_resp_payload *p, int in)
{
	size_t i;

	/* COUNT */
	if (read2(in, &p->count, sizeof(p->count)) != sizeof(p->count)) {
		return -1;
	}

	/* NODES */
	if ((p->nodes = malloc(sizeof(p->nodes[0]) * p->count)) == NULL) {
		return -1;
	}
	for (i = 0; i < p->count; i++) {
		if (read_node(&p->nodes[i], in) == -1) {
			while (i-- > 0) {
				free_node(&p->nodes[i]);
			}
			free(p->nodes);
			return -1;
		}
	}

	return 0;
}

static int
read_payload_fval(struct fval_payload *p, int in)
{
	/* KEY */
	if (read2(in, p->key, KEY_SIZE) != KEY_SIZE) {
		return -1;
	}

	return 0;
}
