#define _GNU_SOURCE /* need qsort_r */
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "bucket.h"
#include "bytes.h"
#include "proto.h"
#include "rtable.h"

static int rtable_close_buckets(struct rtable *rt, size_t i);
static size_t bucket_index(const struct rtable *rt, const uint8_t id[NODE_ID_SIZE]);
static void sort_closest(struct node *closest, size_t len,
	const uint8_t id[NODE_ID_SIZE]);
static int sort_compare(const void *x, const void *y, void *arg);

int
rtable_init(struct rtable *rt, const uint8_t self[NODE_ID_SIZE],
	bool (*alive)(const struct node *n, void *arg), void *arg)
{
	size_t i;

	(void)memcpy(rt->self, self, NODE_ID_SIZE);

	for (i = 0; i < BUCKET_COUNT; i++) {
		if (bucket_init(&rt->buckets[i], alive, arg, K) == -1) {
			/* free previous indicies */
			(void)rtable_close_buckets(rt, i);
			return -1;
		}
	}

	return 0;
}

static int
rtable_close_buckets(struct rtable *rt, size_t i)
{
	int ret = 0;

	while (i-- > 0) {
		if (bucket_close(&rt->buckets[i]) == -1) {
			ret = -1;
		}
	}

	return ret;
}

int rtable_close(struct rtable *rt)
{
	return rtable_close_buckets(rt, BUCKET_COUNT);
}

int
rtable_store(struct rtable *rt, const struct node *n)
{
	struct bucket *b;
	size_t index;

	index = bucket_index(rt, n->id);
	b = &rt->buckets[index];

	if (bucket_store(b, n) == -1) {
		return -1;
	}

	return 0;
}

int
rtable_closest(struct rtable *rt, const uint8_t id[NODE_ID_SIZE], size_t k,
	struct node **closest, size_t *len)
{
	size_t dist;
	size_t i;
	size_t llen;

	if (len == NULL || closest == NULL) {
		return -1;
	}
	dist = bucket_index(rt, id);
	*closest = NULL;
	llen = 0;
	*len = 0;

	if (bucket_append(&rt->buckets[dist], closest, &llen, k) == -1) {
		free(*closest);
		return -1;
	}
	for (i = 1; (dist >= i || dist+i < BUCKET_COUNT) && llen < k; i++) {
		if (dist >= i && bucket_append(&rt->buckets[dist-i], closest,
			&llen,  k - llen) == -1) {
			free(*closest);
			return -1;
		}
		if (dist+i < BUCKET_COUNT && bucket_append(&rt->buckets[dist+i],
			closest, &llen, k - llen) == -1) {
			free(*closest);
			return -1;
		}
	}

	sort_closest(*closest, llen, id);
	return 0;
}

static void
sort_closest(struct node *closest, size_t len, const uint8_t id[NODE_ID_SIZE])
{
	uint8_t id_copy[NODE_ID_SIZE];
	(void)memcpy(id_copy, id, NODE_ID_SIZE);
	qsort_r(closest, len, sizeof(*closest), sort_compare, id_copy);
}

static int
sort_compare(const void *x, const void *y, void *arg)
{
	const struct node *nx = x, *ny = y;
	const uint8_t *id = arg;
	size_t lx, ly;
	lx = lcp(id, nx->id, NODE_ID_SIZE);
	ly = lcp(id, ny->id, NODE_ID_SIZE);
	if (lx > ly) {
		return 1;
	}
	if (ly < lx) {
		return -1;
	}
	return 0;
}

static size_t
bucket_index(const struct rtable *rt, const uint8_t id[NODE_ID_SIZE])
{
	size_t index = lcp(rt->self, id, NODE_ID_SIZE);
	assert(index < BUCKET_COUNT);
	return index;
}
