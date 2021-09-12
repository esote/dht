#pragma once

#include <errno.h>
#include <stdint.h>
#include <sys/types.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "crypto.h"

#define dhtd_log(priority, format, ...) syslog((priority), "%s:%s:%d [pid %d] (errno %d) " format, __FILE__, __func__, __LINE__, getpid(), errno, ## __VA_ARGS__)

#define LISTENER_COUNT 1
#define LISTEN_PORT 8080
#define LISTEN_POLL_TIMEOUT (-1)
#define LISTEN_BACKLOG 64

#define READ_POLL_TIMEOUT 1000
#define READ_FULL_TIMEOUT_SEC 1
#define READ_FULL_TIMEOUT_NSEC 0

#define WRITE_POLL_TIMEOUT 1000
#define WRITE_FULL_TIMEOUT_SEC 1
#define WRITE_FULL_TIMEOUT_NSEC 0

#define SOCKET_TIMEOUT_SEC 0
#define SOCKET_TIMEOUT_USEC 100000 /* 0.1 seconds */

int listener_start(int monitor);

