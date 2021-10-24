#include <errno.h>
#include <poll.h>
#include <string.h>
#include <sys/types.h>

#ifdef HAVE_IMSG
#include <imsg.h>
#else
#include "compat/imsg.h"
#endif

#include "dhtd.h"

int read_config(struct imsgbuf *ibuf, struct config *config);

int
listen_start(void)
{
	struct imsgbuf ibuf;
	struct config config;

	imsg_init(&ibuf, CONTROL_FILENO);

	if (read_config(&ibuf, &config) == -1) {
		imsg_clear(&ibuf);
		return -1;
	}

	imsg_clear(&ibuf);
	return 0;
}

int
read_config(struct imsgbuf *ibuf, struct config *config)
{
	struct imsg imsg;
	ssize_t n;
	struct pollfd pfd = {
		.fd = ibuf->fd,
		.events = POLLIN
	};

	for (;;) {
		switch (poll(&pfd, 1, -1)) {
		case -1:
			if (errno == EAGAIN || errno == EINTR) {
				errno = 0;
				continue;
			}
			return -1;
		case 0:
			return -1;
		}
		if (!(pfd.revents & POLLIN)) {
			return -1;
		}
		break;
	}

	if (((n = imsg_read(ibuf)) == -1) || n == 0) {
		return -1;
	}
	if ((n = imsg_get(ibuf, &imsg)) == -1 || n == 0) {
		return -1;
	}
	if (imsg.hdr.type != IMSG_CONFIG || imsg.hdr.len - IMSG_HEADER_SIZE < sizeof(*config)) {
		imsg_free(&imsg);
		return -1;
	}

	memcpy(config, imsg.data, sizeof(*config));
	imsg_free(&imsg);
	return 0;
}
