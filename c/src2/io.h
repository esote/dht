#pragma once

#include <sys/socket.h>
#include <sys/types.h>
#include <stddef.h>

ssize_t read2(int fd, void *buf, size_t count);
ssize_t write2(int fd, const void *buf, size_t count);
ssize_t sendmsg2(int fd, const struct msghdr *msg, int flags);
