#define _GNU_SOURCE /* need qsort_r */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
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
static void sort_closest(struct node_triple *closest, size_t len,
	uint8_t id[NODE_ID_SIZE]);
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
		if ((rt->buckets[i] = kb_new(k)) == NULL) {
			/* free previous kbuckets */
			while (i-- > 0) {
				kb_free(rt->buckets[i]);
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
		kb_free(rt->buckets[i]);
	}
	free(rt);
}

int
rtable_store(struct rtable *rt, const struct node_triple *n)
{
	struct kbucket *kb;
	kb = rt->buckets[bucket_index(rt, n->id)]; /* TODO: assert within array */
	return kb_store(kb, n);
}

const struct node_triple *
rtable_oldest(const struct rtable *rt, const uint8_t id[NODE_ID_SIZE])
{
	struct kbucket *kb;
	kb = rt->buckets[bucket_index(rt, id)];
	return kb_oldest(kb);
}

struct node_triple *
rtable_replace_oldest(struct rtable *rt, const struct node_triple *n)
{
	const struct node_triple *oldest;
	struct node_triple *removed;
	struct kbucket *kb;
	kb = rt->buckets[bucket_index(rt, n->id)];
	if ((oldest = kb_oldest(kb)) == NULL) {
		return NULL;
	}
	if ((removed = kb_remove(kb, oldest->id)) == NULL) {
		return NULL;
	}
	assert(removed->id == oldest->id);
	assert(kb_store(kb, n) != -1);
	return removed;
}

struct node_triple *
rtable_closest(const struct rtable *rt, const uint8_t id[NODE_ID_SIZE], size_t k, size_t *len)
{
	struct node_triple *closest;
	struct node_triple *tmp;
	size_t dist;
	size_t i;
	size_t llen;
	uint8_t id_copy[NODE_ID_SIZE];

	if (len == NULL) {
		return NULL;
	}

	dist = bucket_index(rt, id);
	closest = NULL;
	llen = 0;
	*len = 0;

	tmp = kb_append(rt->buckets[dist], closest, &llen, k);
	if (tmp == NULL) {
		free(closest);
		return NULL;
	}
	closest = tmp;

	for (i = 1; (dist - i >= 0 /* TODO: overflow? */ || dist+i < BUCKET_COUNT) && *len < k; i++) {
		if (dist-i >= 0) {
			tmp = kb_append(rt->buckets[dist-i], closest, len, k - *len);
		}
		if (dist+i < BUCKET_COUNT) {
			tmp = kb_append(rt->buckets[dist+i], closest, len, k - *len);
		}
		if (tmp == NULL) {
			free(closest);
			return NULL;
		}
	}
	(void)memcpy(id_copy, id, NODE_ID_SIZE);
	sort_closest(closest, *len, id_copy);
	return closest;
}

static void
sort_closest(struct node_triple *closest, size_t len, uint8_t id[NODE_ID_SIZE])
{
	qsort_r(closest, len, sizeof(*closest), sort_compare, id);
}

static int
sort_compare(const void *x, const void *y, void *arg)
{
	const struct node_triple *nx = x, *ny = y;
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
	return lcp(rt->self, id, NODE_ID_SIZE);
}
