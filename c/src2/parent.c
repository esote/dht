#include <errno.h>
#include <poll.h>

#include <unistd.h> // TODO

#ifdef HAVE_IMSG
#include <imsg.h>
#else
#include "compat/imsg.h"
#endif

#include "dhtd.h"

int parent_start(int fds[DHTD_NUMPROC])
{
	size_t i;
	struct config config = {
		.network_id = {1},
		.node = {
			.id = {2},
			.dyn_x = {3},
			.addrlen = 4,
			.addr = "5555",
			.port = 6
		}
	};
	for (i = 0; i < DHTD_NUMPROC; i++) {
		struct imsgbuf ibuf;
		struct pollfd pfd = {
			.fd = fds[i],
			.events = POLLOUT
		};
		imsg_init(&ibuf, fds[i]);
		imsg_compose(&ibuf, IMSG_CONFIG, 0, 0, -1, &config, sizeof(config));
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
			if (!(pfd.revents & POLLOUT)) {
				return -1;
			}
			break;
		}
		imsg_flush(&ibuf);
		imsg_clear(&ibuf);
	}
	return 0;
}
