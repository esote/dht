#pragma once

#include <limits.h> /* for IOV_MAX with _XOPEN_SOURCE=700 */

#ifndef HAVE_EXPLICIT_BZERO
void explicit_bzero(void *, size_t);
#endif

#ifndef HAVE_FREEZERO
void freezero(void *, size_t);
#endif

#ifndef HAVE_GETDTABLECOUNT
int getdtablecount(void);
#endif

#ifndef HAVE_GETDTABLESIZE
int getdtablesize(void);
#endif

#ifndef HAVE_GETPAGESIZE
int getpagesize(void);
#endif

#ifdef HAVE_QUEUE
#include <sys/queue.h>
#else
#include "queue.h"
#endif

#ifndef HAVE_RECALLOCARRAY
void *recallocarray(void *, size_t, size_t, size_t);
#endif
