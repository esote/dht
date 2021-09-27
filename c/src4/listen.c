#include <errno.h>
#include <inttypes.h>
#include <netdb.h>
#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "dhtd.h"
#include "listen.h"
#include "monitor.h"
#include "proto.h"

struct listen_ctx {
	int monitor;
	uint8_t network_id[NETWORK_ID_SIZE];
	struct node node;
};

static int listen_local(uint16_t port);
static int getaddrinfo_port(const char *node, uint16_t port, const struct addrinfo *hints, struct addrinfo **res);
static int socket_timeout(int fd);
static int socket_reuse(int fd);
static int listen_accept(const struct listen_ctx *ctx, int sfd);
static int listen_work(const struct listen_ctx *ctx, int afd);
static int listen_monitor_end(int monitor, struct node *node);
static int respond_msg(const struct listen_ctx *ctx, int afd, const struct message *req);
static int respond_ping(const struct listen_ctx *ctx, int afd, const struct message *req);
static int respond_fnode(const struct listen_ctx *ctx, int afd, const struct message *req);
static int respond_data(const struct listen_ctx *ctx, int afd, const struct message *req);
static int respond_fval(const struct listen_ctx *ctx, int afd, const struct message *req);

int
listener_start(int monitor, struct config *config)
{
	struct pollfd pfd;
	int sfd;
	struct listen_ctx ctx;

	memcpy(ctx.network_id, config->network_id, sizeof(config->network_id));
	ctx.node = config->node;
	ctx.monitor = monitor;

	if ((sfd = listen_local(LISTEN_PORT)) == -1) {
		return -1;
	}
	pfd.fd = sfd;
	pfd.events = POLLIN;

	for (;;) {
		switch (poll(&pfd, 1, LISTEN_POLL_TIMEOUT)) {
		case -1:
			if (errno == EINTR || errno == EAGAIN) {
				errno = 0;
				continue;
			}
			close(sfd);
			return -1;
		case 0:
			continue;
		}

		if (pfd.revents & POLLIN) {
			if (listen_accept(&ctx, sfd) == -1) {
				dhtd_log(LOG_WARNING, "accept");
			}
			continue;
		} else {
			close(sfd);
			return -1;
		}
	}
}

static int
listen_local(uint16_t port)
{
	int fd;
	struct addrinfo hints = { 0 };
	struct addrinfo *result, *rp;
	int n;

	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ((n = getaddrinfo_port(NULL, port, &hints, &result)) != 0) {
		return -1;
	}

	for (rp = result; rp != NULL; rp = rp->ai_next) {
		fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (fd == -1) {
			continue;
		}

		if (socket_timeout(fd) == -1) {
			close(fd);
			continue;
		}

		if (socket_reuse(fd) == -1) {
			close(fd);
			continue;
		}

		if (bind(fd, rp->ai_addr, rp->ai_addrlen) == -1) {
			close(fd);
			continue;
		}

		if (listen(fd, LISTEN_BACKLOG) == -1) {
			close(fd);
			continue;
		}

		break;
	}

	freeaddrinfo(result);

	if (rp == NULL) {
		return -1;
	}

	return fd;
}

static int
getaddrinfo_port(const char *node, uint16_t port, const struct addrinfo *hints,
	struct addrinfo **res)
{
#define SERVICE_LEN (5+1)
	char service[SERVICE_LEN];
	int n;

	n = snprintf(service, sizeof(service), "%"PRIu16, port);
	if (n < 0 || n >= sizeof(service)) {
		return EAI_NONAME;
	}

	return getaddrinfo(node, service, hints, res);
}

static int
socket_timeout(int fd)
{
	struct timeval tv;

	tv.tv_sec = SOCKET_TIMEOUT_SEC;
	tv.tv_usec = SOCKET_TIMEOUT_USEC;

	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == -1) {
		return -1;
	}

	return setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

static int
socket_reuse(int fd)
{
	int opt = 1;

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) == -1) {
		return -1;
	}

	return setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
}

static int
listen_accept(const struct listen_ctx *ctx, int sfd)
{
	int afd;

	if ((afd = accept(sfd, NULL, NULL)) == -1) {
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
			errno = 0;
			return 0;
		}
		return -1;
	}

	if (socket_timeout(afd) == -1) {
		close(afd);
		return -1;
	}

	if (listen_work(ctx, afd) == -1) {
		close(afd);
		return -1;
	}

	return close(afd);
}

static int
listen_work(const struct listen_ctx *ctx, int afd)
{
	struct message req;

	if (message_recv(ctx->monitor, afd, &req) == -1) {
		return -1;
	}

	if (respond_msg(ctx, afd, &req) == -1) {
		message_close(&req);
		return -1;
	}

	if (message_close(&req) == -1) {
		return -1;
	}

	return listen_monitor_end(ctx->monitor, &req.header.node);
}

static int
listen_monitor_end(int monitor, struct node *node)
{
	struct monitor_message req;

	req.type = M_FNODE_RESP;
	req.payload.fnode_resp.count = 1;
	req.payload.fnode_resp.nodes = node;

	return monitor_send(monitor, &req);
}

static int
respond_msg(const struct listen_ctx *ctx, int afd, const struct message *req)
{
	switch (req->header.type) {
	case TYPE_PING:
		return respond_ping(ctx, afd, req);
	case TYPE_FNODE:
		return respond_fnode(ctx, afd, req);
	case TYPE_DATA:
		return respond_data(ctx, afd, req);
	case TYPE_FVAL:
		return respond_fval(ctx, afd, req);
	default:
		return -1;
	}
}

static int
respond_ping(const struct listen_ctx *ctx, int afd, const struct message *req)
{
	struct message resp;

	memcpy(resp.header.session_id, req->header.session_id, sizeof(resp.header.session_id));
	memcpy(resp.header.network_id, ctx->network_id, sizeof(resp.header.network_id));
	resp.header.type = TYPE_PING;
	resp.header.node = ctx->node;
	return message_send(ctx->monitor, afd, &resp, req->header.node.id);
}

static int
respond_fnode(const struct listen_ctx *ctx, int afd, const struct message *req)
{
	struct monitor_message mreq, mresp;
	struct message resp;

	mreq.type = M_FNODE;
	mreq.payload.fnode.count = req->payload.fnode.count;
	memcpy(mreq.payload.fnode.target_id, req->payload.fnode.target_id, sizeof(mreq.payload.fnode.target_id));
	if (monitor_send(ctx->monitor, &mreq) == -1) {
		return -1;
	}

	if (monitor_recv(ctx->monitor, &mresp) == -1) {
		return -1;
	}
	if (mresp.type != M_FNODE_RESP) {
		monitor_close(&mresp);
		return -1;
	}

	memcpy(resp.header.session_id, req->header.session_id, sizeof(resp.header.session_id));
	memcpy(resp.header.network_id, ctx->network_id, sizeof(resp.header.network_id));
	resp.header.type = TYPE_FNODE_RESP;
	resp.header.node = ctx->node;
	resp.payload.fnode_resp = mresp.payload.fnode_resp;
	if (message_send(ctx->monitor, afd, &resp, req->header.node.id) == -1) {
		monitor_close(&mresp);
		return -1;
	}

	monitor_close(&mresp);
	return 0;
}

static int
respond_data(const struct listen_ctx *ctx, int afd, const struct message *req)
{
	struct monitor_message mreq, mresp;
	struct message resp;

	mreq.type = M_DATA;
	memcpy(mreq.payload.data.key, req->payload.data.key, sizeof(mreq.payload.data.key));
	mreq.payload.data.length = req->payload.data.length;
	mreq.payload.data.value = req->payload.data.value;
	if (monitor_send(ctx->monitor, &mreq) == -1) {
		return -1;
	}

	if (monitor_recv(ctx->monitor, &mresp) == -1) {
		return -1;
	}
	if (mresp.type != M_PING) {
		monitor_close(&mresp);
		return -1;
	}

	memcpy(resp.header.session_id, req->header.session_id, sizeof(resp.header.session_id));
	memcpy(resp.header.network_id, ctx->network_id, sizeof(resp.header.network_id));
	resp.header.type = TYPE_PING;
	resp.header.node = ctx->node;
	if (message_send(ctx->monitor, afd, &resp, req->header.node.id) == -1) {
		monitor_close(&mresp);
		return -1;
	}

	monitor_close(&mresp);
	return 0;
}

static int
respond_fval(const struct listen_ctx *ctx, int afd, const struct message *req)
{
	struct monitor_message mreq, mresp;
	struct message resp;

	mreq.type = M_FVAL;
	memcpy(mreq.payload.fval.key, req->payload.fval.key, sizeof(mreq.payload.fval.key));
	if (monitor_send(ctx->monitor, &mreq) == -1) {
		return -1;
	}

	if (monitor_recv(ctx->monitor, &mresp) == -1) {
		return -1;
	}
	switch (mresp.type) {
	case M_DATA:
		resp.header.type = TYPE_DATA;
		resp.payload.data = mresp.payload.data;
		break;
	case M_FNODE_RESP:
		resp.header.type = TYPE_FNODE_RESP;
		resp.payload.fnode_resp = mresp.payload.fnode_resp;
		break;
	default:
		monitor_close(&mresp);
		return -1;
	}

	memcpy(resp.header.session_id, req->header.session_id, sizeof(resp.header.session_id));
	memcpy(resp.header.network_id, ctx->network_id, sizeof(resp.header.network_id));
	resp.header.node = ctx->node;
	return message_send(ctx->monitor, afd, &resp, req->header.node.id);
}
