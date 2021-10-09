#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "monitor.h"
#include "proto.h"
#include "util.h"

static int monitor_encode_config(int monitor, const struct config *config);
static int monitor_encode_decrypt_req(int monitor, const struct decrypt_req *decrypt_req);
static int monitor_encode_decrypt_resp(int monitor, const struct decrypt_resp *decrypt_resp);
static int monitor_encode_encrypt_req(int monitor, const struct encrypt_req *encrypt_req);
static int monitor_encode_encrypt_resp(int monitor, const struct encrypt_resp *encrypt_resp);
static int monitor_encode_data(int monitor, const struct data *data);

static int monitor_decode_config(int monitor, struct config *config);
static int monitor_decode_decrypt_req(int monitor, struct decrypt_req *decrypt_req);
static int monitor_decode_decrypt_resp(int monitor, struct decrypt_resp *decrypt_resp);
static int monitor_decode_encrypt_req(int monitor, struct encrypt_req *encrypt_req);
static int monitor_decode_encrypt_resp(int monitor, struct encrypt_resp *encrypt_resp);
static int monitor_decode_data(int monitor, struct data *data);

int
monitor_send(int monitor, const struct monitor_message *msg)
{
	if (write2(monitor, &msg->type, sizeof(msg->type)) != sizeof(msg->type)) {
		return -1;
	}

	switch (msg->type) {
	case M_CONFIG:
		return monitor_encode_config(monitor, &msg->payload.config);
	case M_DECRYPT_REQ:
		return monitor_encode_decrypt_req(monitor, &msg->payload.decrypt_req);
	case M_DECRYPT_RESP:
		return monitor_encode_decrypt_resp(monitor, &msg->payload.decrypt_resp);
	case M_ENCRYPT_REQ:
		return monitor_encode_encrypt_req(monitor, &msg->payload.encrypt_req);
	case M_ENCRYPT_RESP:
		return monitor_encode_encrypt_resp(monitor, &msg->payload.encrypt_resp);
	case M_PING:
		return 0;
	case M_FNODE:
		return encode_fnode(monitor, &msg->payload.fnode);
	case M_FNODE_RESP:
		return encode_fnode_resp(monitor, &msg->payload.fnode_resp);
	case M_DATA:
		return monitor_encode_data(monitor, &msg->payload.data);
	case M_FVAL:
		return encode_fval(monitor, &msg->payload.fval);
	default:
		return -1;
	}
}

static int
monitor_encode_config(int monitor, const struct config *config)
{
	if (write2(monitor, config->network_id, sizeof(config->network_id)) != sizeof(config->network_id)) {
		return -1;
	}

	if (encode_node(monitor, &config->node) == -1) {
		return -1;
	}

	if (write2(monitor, &config->rtable_filename, sizeof(config->rtable_filename)) != sizeof(config->rtable_filename)) {
		return -1;
	}

	return 0;
}

static int
monitor_encode_decrypt_req(int monitor, const struct decrypt_req *decrypt_req)
{
	if (write2(monitor, decrypt_req->ephem_publ, sizeof(decrypt_req->ephem_publ)) != sizeof(decrypt_req->ephem_publ)) {
		return -1;
	}

	return 0;
}

static int
monitor_encode_decrypt_resp(int monitor, const struct decrypt_resp *decrypt_resp)
{
	if (write2(monitor, decrypt_resp->ephem_key, sizeof(decrypt_resp->ephem_key)) != sizeof(decrypt_resp->ephem_key)) {
		return -1;
	}

	return 0;
}

static int
monitor_encode_encrypt_req(int monitor, const struct encrypt_req *encrypt_req)
{
	if (write2(monitor, encrypt_req->session_id, sizeof(encrypt_req->session_id)) != sizeof(encrypt_req->session_id)) {
		return -1;
	}

	if (write2(monitor, &encrypt_req->expiration, sizeof(encrypt_req->expiration)) != sizeof(encrypt_req->expiration)) {
		return -1;
	}

	if (write2(monitor, encrypt_req->target_id, sizeof(encrypt_req->target_id)) != sizeof(encrypt_req->target_id)) {
		return -1;
	}

	return 0;
}

static int
monitor_encode_encrypt_resp(int monitor, const struct encrypt_resp *encrypt_resp)
{
	if (write2(monitor, encrypt_resp->sig, sizeof(encrypt_resp->sig)) != sizeof(encrypt_resp->sig)) {
		return -1;
	}

	if (write2(monitor, encrypt_resp->ephem_publ, sizeof(encrypt_resp->ephem_publ)) != sizeof(encrypt_resp->ephem_publ)) {
		return -1;
	}

	if (write2(monitor, encrypt_resp->ephem_key, sizeof(encrypt_resp->ephem_key)) != sizeof(encrypt_resp->ephem_key)) {
		return -1;
	}

	return 0;
}

static int
monitor_encode_data(int monitor, const struct data *data)
{
	uint8_t iobuf[1] = {0};
	uint8_t auxbuf[CMSG_SPACE(sizeof(data->value))] = {0};
	struct iovec io = {0};
	struct msghdr msg = {0};
	struct cmsghdr *cmsg;

	if (write2(monitor, data->key, sizeof(data->key)) != sizeof(data->key)) {
		return -1;
	}
	if (write2(monitor, &data->length, sizeof(data->length)) != sizeof(data->length)) {
		return -1;
	}

	io.iov_base = iobuf;
	io.iov_len = sizeof(iobuf);
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
	memcpy(CMSG_DATA(cmsg), &data->value, sizeof(data->value));

	if (sendmsg(monitor, &msg, 0) != sizeof(iobuf)) {
		return -1;
	}

	return 0;
}

int
monitor_recv(int monitor, struct monitor_message *msg)
{
	if (read2(monitor, &msg->type, sizeof(msg->type)) != sizeof(msg->type)) {
		return -1;
	}

	switch (msg->type) {
	case M_CONFIG:
		return monitor_decode_config(monitor, &msg->payload.config);
	case M_DECRYPT_REQ:
		return monitor_decode_decrypt_req(monitor, &msg->payload.decrypt_req);
	case M_DECRYPT_RESP:
		return monitor_decode_decrypt_resp(monitor, &msg->payload.decrypt_resp);
	case M_ENCRYPT_REQ:
		return monitor_decode_encrypt_req(monitor, &msg->payload.encrypt_req);
	case M_ENCRYPT_RESP:
		return monitor_decode_encrypt_resp(monitor, &msg->payload.encrypt_resp);
	case M_PING:
		return 0;
	case M_FNODE:
		return decode_fnode(monitor, &msg->payload.fnode);
	case M_FNODE_RESP:
		return decode_fnode_resp(monitor, &msg->payload.fnode_resp);
	case M_DATA:
		return monitor_decode_data(monitor, &msg->payload.data);
	case M_FVAL:
		return decode_fval(monitor, &msg->payload.fval);
	default:
		return -1;
	}
}

static int
monitor_decode_config(int monitor, struct config *config)
{
	if (read2(monitor, config->network_id, sizeof(config->network_id)) != sizeof(config->network_id)) {
		return -1;
	}

	if (decode_node(monitor, &config->node) == -1) {
		return -1;
	}

	if (read2(monitor, &config->rtable_filename, sizeof(config->rtable_filename)) != sizeof(config->rtable_filename)) {
		return -1;
	}

	return 0;
}
static int
monitor_decode_decrypt_req(int monitor, struct decrypt_req *decrypt_req)
{
	if (read2(monitor, decrypt_req->ephem_publ, sizeof(decrypt_req->ephem_publ)) != sizeof(decrypt_req->ephem_publ)) {
		return -1;
	}

	return 0;
}

static int
monitor_decode_decrypt_resp(int monitor, struct decrypt_resp *decrypt_resp)
{
	if (read2(monitor, decrypt_resp->ephem_key, sizeof(decrypt_resp->ephem_key)) != sizeof(decrypt_resp->ephem_key)) {
		return -1;
	}

	return 0;
}

static int
monitor_decode_encrypt_req(int monitor, struct encrypt_req *encrypt_req)
{
	if (read2(monitor, encrypt_req->session_id, sizeof(encrypt_req->session_id)) != sizeof(encrypt_req->session_id)) {
		return -1;
	}

	if (read2(monitor, &encrypt_req->expiration, sizeof(encrypt_req->expiration)) != sizeof(encrypt_req->expiration)) {
		return -1;
	}

	if (read2(monitor, encrypt_req->target_id, sizeof(encrypt_req->target_id)) != sizeof(encrypt_req->target_id)) {
		return -1;
	}

	return 0;
}

static int
monitor_decode_encrypt_resp(int monitor, struct encrypt_resp *encrypt_resp)
{
	if (read2(monitor, encrypt_resp->sig, sizeof(encrypt_resp->sig)) != sizeof(encrypt_resp->sig)) {
		return -1;
	}

	if (read2(monitor, encrypt_resp->ephem_publ, sizeof(encrypt_resp->ephem_publ)) != sizeof(encrypt_resp->ephem_publ)) {
		return -1;
	}

	if (read2(monitor, encrypt_resp->ephem_key, sizeof(encrypt_resp->ephem_key)) != sizeof(encrypt_resp->ephem_key)) {
		return -1;
	}

	return 0;
}

static int
monitor_decode_data(int monitor, struct data *data)
{
	uint8_t iobuf[1];
	uint8_t auxbuf[CMSG_SPACE(sizeof(data->value))] = {0};
	struct iovec io = {0};
	struct msghdr msg = {0};
	struct cmsghdr *cmsg;

	if (read2(monitor, data->key, sizeof(data->key)) != sizeof(data->key)) {
		return -1;
	}
	if (read2(monitor, &data->length, sizeof(data->length)) != sizeof(data->length)) {
		return -1;
	}

	io.iov_base = iobuf;
	io.iov_len = sizeof(iobuf);
	msg.msg_iov = &io;
	msg.msg_iovlen = 1;
	msg.msg_control = auxbuf;
	msg.msg_controllen = sizeof(auxbuf);

	if (recvmsg(monitor, &msg, 0) != sizeof(iobuf)) {
		return -1;
	}
	if (!is_zero(iobuf, sizeof(iobuf))) {
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

	memcpy(&data->value, CMSG_DATA(cmsg), sizeof(data->value));

	return 0;
}

void
monitor_close(struct monitor_message *msg)
{
	if (msg->type == M_FNODE_RESP) {
		free(msg->payload.fnode_resp.nodes);
	}
}
