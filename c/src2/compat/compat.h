#pragma once

#include <limits.h> /* for IOV_MAX in ismg-buffer.c, from _XOPEN_SOURCE=700 */
#include <sys/uio.h> /* for iovec in imsg.h */

#include "queue.h"

void explicit_bzero(void *, size_t);
void freezero(void *, size_t);
int getdtablecount(void);
int getdtablesize(void);
int getpagesize(void);
void *recallocarray(void *, size_t, size_t, size_t);
