#define _GNU_SOURCE /* need qsort_r */
#include <assert.h>
#include <errno.h>
#include <pthread.h>
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
	pthread_rwlock_t mu[BUCKET_COUNT];
};

static int rtable_close_index(struct rtable *rt, size_t i);
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
			/* free previous indicies */
			(void)rtable_close_index(rt, i);
			return NULL;
		}
		if ((errno = pthread_rwlock_init(&rt->mu[i], NULL)) != 0) {
			/* free current index */
			(void)kbucket_free(rt->buckets[i]);
			/* free previous indicies */
			(void)rtable_close_index(rt, i);
			return NULL;
		}
	}
	return rt;
}

static int
rtable_close_index(struct rtable *rt, size_t i)
{
	int ret = 0;
	while (i-- > 0) {
		kbucket_free(rt->buckets[i]);
		if ((errno = pthread_rwlock_destroy(&rt->mu[i])) != 0) {
			ret = -1;
		}
	}
	free(rt);
	return ret;
}

int rtable_close(struct rtable *rt)
{
	return rtable_close_index(rt, BUCKET_COUNT);
}

int
rtable_store(struct rtable *rt, const struct node *n)
{
	struct kbucket *kb;
	size_t index;
	int ret;
	index = bucket_index(rt, n->id);
	kb = rt->buckets[index];

	assert(pthread_rwlock_wrlock(&rt->mu[index]) == 0);
	ret = kbucket_store(kb, n);
	assert(pthread_rwlock_unlock(&rt->mu[index]) == 0);

	return ret;
}

const struct node *
rtable_oldest(struct rtable *rt, const uint8_t id[NODE_ID_SIZE])
{
	struct kbucket *kb;
	size_t index;
	const struct node *ret;
	index = bucket_index(rt, id);
	kb = rt->buckets[index];

	assert(pthread_rwlock_rdlock(&rt->mu[index]) == 0);
	ret = kbucket_oldest(kb);
	assert(pthread_rwlock_unlock(&rt->mu[index]) == 0);
	return ret;
}

struct node *
rtable_replace_oldest(struct rtable *rt, const struct node *n,
	bool (*ping)(const struct node *n, void *arg), void *arg)
{
	const struct node *oldest;
	struct node *removed;
	struct kbucket *kb;
	size_t index;

	index = bucket_index(rt, n->id);
	kb = rt->buckets[index];

	assert(pthread_rwlock_wrlock(&rt->mu[index]) == 0);

	if (kbucket_store(kb, n) != -1) {
		assert(pthread_rwlock_unlock(&rt->mu[index]) == 0);
		return NULL;
	}
	if ((oldest = kbucket_oldest(kb)) == NULL) {
		assert(pthread_rwlock_unlock(&rt->mu[index]) == 0);
		return NULL;
	}
	if (ping(oldest, arg)) {
		/* Oldest is still alive, refresh it */
		(void)kbucket_store(kb, oldest);
		assert(pthread_rwlock_unlock(&rt->mu[index]) == 0);
		return NULL;
	}
	assert((removed = kbucket_remove(kb, oldest->id)) != NULL);
	assert(memcmp(removed->id, oldest->id, NODE_ID_SIZE) == 0);
	assert(kbucket_store(kb, n) != -1);

	assert(pthread_rwlock_unlock(&rt->mu[index]) == 0);
	return removed;
}

int
rtable_closest(struct rtable *rt, const uint8_t id[NODE_ID_SIZE], size_t k,
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

	for (i = 0; i < BUCKET_COUNT; i++) {
		assert(pthread_rwlock_rdlock(&rt->mu[i]) == 0);
	}

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

	for (i = 0; i < BUCKET_COUNT; i++) {
		assert(pthread_rwlock_unlock(&rt->mu[i]) == 0);
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
