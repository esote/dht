#pragma once

#include <err.h> /* TODO: temp */

#define DHTD_USER "dhtd"
#define PARENT_ROOT "/var/empty/"
#define LISTEN_ROOT "/var/empty/"
#define RTABLE_ROOT "/tmp/dhtd/"
#define LISTEN_NPROC 1
#define RTABLE_NPROC 1
#define DHTD_NPROC ((LISTEN_NPROC) + (RTABLE_NPROC))
#define CONTROL_FILENO 3

#define nitems(x) (sizeof((x)) / sizeof((x)[0]))
#define _PATH_DEVNULL "/dev/null"

/* parent.c */
int parent_start(int fds[DHTD_NPROC]);

/* listen.c */
int listen_start(void);

/* rtable.c */
int rtable_start(void);
