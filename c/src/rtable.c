#define _GNU_SOURCE /* need qsort_r */
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "bytes.h"
#include "proto.h"
#include "kbucket.h"
#include "rtable.h"

#define BUCKET_COUNT ((NODE_ID_SIZE) * 8)

struct rtable {
	uint8_t self[NODE_ID_SIZE];
	struct kbucket *buckets[BUCKET_COUNT];
	/* TODO: mutex each bucket */
};

static size_t bucket_index(const struct rtable *rt, const uint8_t id[NODE_ID_SIZE]);
static void sort_closest(struct node *closest, size_t len, uint8_t id[NODE_ID_SIZE]);
static int sort_compare(const void *x, const void *y, void *arg);

struct rtable *
rtable_new(const uint8_t self[NODE_ID_SIZE], size_t k)
{
	size_t i;
	struct rtable *rt;
	if ((rt = malloc(sizeof(*rt))) == NULL) {
		return NULL;
	}
	(void)memcpy(rt->self, self, NODE_ID_SIZE);
	for (i = 0; i < BUCKET_COUNT; i++) {
		if ((rt->buckets[i] = kbucket_new(k)) == NULL) {
			/* free previous kbuckets */
			while (i-- > 0) {
				kbucket_free(rt->buckets[i]);
			}
			free(rt);
			return NULL;
		}
	}
	return rt;
}

void rtable_free(struct rtable *rt)
{
	size_t i;
	for (i = 0; i < BUCKET_COUNT; i++) {
		kbucket_free(rt->buckets[i]);
	}
	free(rt);
}

int
rtable_store(struct rtable *rt, const struct node *n)
{
	struct kbucket *kb;
	kb = rt->buckets[bucket_index(rt, n->id)];
	return kbucket_store(kb, n);
}

const struct node *
rtable_oldest(const struct rtable *rt, const uint8_t id[NODE_ID_SIZE])
{
	struct kbucket *kb;
	kb = rt->buckets[bucket_index(rt, id)];
	return kbucket_oldest(kb);
}

struct node *
rtable_replace_oldest(struct rtable *rt, const struct node *n,
	bool (*ping)(const struct node *n, void *arg), void *arg)
{
	const struct node *oldest;
	struct node *removed;
	struct kbucket *kb;
	kb = rt->buckets[bucket_index(rt, n->id)];
	if (kbucket_store(kb, n) != -1) {
		return NULL;
	}
	if ((oldest = kbucket_oldest(kb)) == NULL) {
		return NULL;
	}
	if (ping(oldest, arg)) {
		/* Oldest is still alive, refresh it */
		(void)kbucket_store(kb, oldest);
		return NULL;
	}
	assert((removed = kbucket_remove(kb, oldest->id)) != NULL);
	assert(memcmp(removed->id, oldest->id, NODE_ID_SIZE) == 0);
	assert(kbucket_store(kb, n) != -1);
	return removed;
}

int
rtable_closest(const struct rtable *rt, const uint8_t id[NODE_ID_SIZE], size_t k,
	struct node **closest, size_t *len)
{
	size_t dist;
	size_t i;
	size_t llen;
	uint8_t id_copy[NODE_ID_SIZE];
	if (len == NULL || closest == NULL) {
		return -1;
	}
	dist = bucket_index(rt, id);
	*closest = NULL;
	llen = 0;
	*len = 0;
	if (kbucket_append(rt->buckets[dist], closest, &llen, k) == -1) {
		free(*closest);
		return -1;
	}
	for (i = 1; (dist >= i || dist+i < BUCKET_COUNT) && llen < k; i++) {
		if (dist >= i && kbucket_append(rt->buckets[dist-i], closest,
			&llen,  k - llen) == -1) {
			free(*closest);
			return -1;
		}
		if (dist+i < BUCKET_COUNT && kbucket_append(rt->buckets[dist+i],
			closest, &llen, k - llen) == -1) {
			free(*closest);
			return -1;
		}
	}

	(void)memcpy(id_copy, id, NODE_ID_SIZE);
	sort_closest(*closest, llen, id_copy);
	return 0;
}

static void
sort_closest(struct node *closest, size_t len, uint8_t id[NODE_ID_SIZE])
{
	qsort_r(closest, len, sizeof(*closest), sort_compare, id);
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
