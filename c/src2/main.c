#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

#include "ipc.h"

int
main(void)
{
	int sv[2];
	assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != -1);

	struct ipc_message msg1 = {
		.type = IPC_TYPE_DATA,
		.payload = {
			.data = {
				.key = { 0 },
				.length = 1,
				.value = open("/tmp/wow", O_RDONLY),
			}
		}
	};

	assert(ipc_encode(sv[0], &msg1) != -1);
	close(sv[0]);
	close(msg1.payload.data.value);

	struct ipc_message msg2;
	assert(ipc_decode(sv[1], &msg2) != -1);
	close(sv[1]);

	uint8_t buf[1024];
	ssize_t r = read(msg2.payload.data.value, buf, sizeof(buf));
	assert(r != -1);
	buf[r] = '\0';
	printf("%s\n", buf);
	close(msg2.payload.data.value);
}
