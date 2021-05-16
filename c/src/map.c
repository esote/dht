#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "map.h"
#include "lset.h"

#define MIN_BUCKETS	4
/* XXX: get real value, function to check load factor? */
#define MAX_BUCKET_LOAD	8

struct map_item {
	uint8_t	*key;
	size_t	keylen;
	void	*value;
};

struct map {
	struct lset **buckets;
	size_t len;
};

static bool map_free_item(void *data, void *ctx);

static size_t map_hash(uint8_t *key, size_t keylen);

static struct lset *map_bucket(struct map *map, uint8_t *key, size_t keylen);

static bool map_item_equal(void *x, void *y);

static size_t nearest_power2(size_t x);

static bool map_iter_lset(void *data, void *ctx);

static bool map_grow_copy_item(void *data, void *ctx);

static int map_grow(struct map *map);

struct map *
map_new(size_t len)
{
	struct map *map;
	size_t i;

	if ((map = malloc(sizeof(struct map))) == NULL) {
		return NULL;
	}

	/* convert len to the optimal count of buckets */
	len /= MAX_BUCKET_LOAD;
	if (len < MIN_BUCKETS) {
		len = MIN_BUCKETS;
	}

	if ((map->buckets = malloc(len * sizeof(struct lset *))) == NULL) {
		goto err1;
	}

	for (i = 0; i < len; i++) {
		if ((map->buckets[i] = lset_new(map_item_equal)) == NULL) {
			/* free previous buckets */
			goto err2;
		}
	}

	map->len = len;
	return map;
err2:
	while (i-- > 0) {
		lset_free(map->buckets[i]);
	}
	free(map->buckets);
err1:
	free(map);
	return NULL;
}

void
map_free(struct map *map)
{
	size_t i;
	for (i = 0; i < map->len; i++) {
		lset_iter(map->buckets[i], map_free_item, NULL);
		lset_free(map->buckets[i]);
	}
	free(map->buckets);
	free(map);
}

int
map_store(struct map *map, uint8_t *key, size_t keylen, void *value)
{
	struct lset *bucket;
	struct map_item *item;
	void *replaced = NULL;

	if ((item = malloc(sizeof(struct map_item))) == NULL) {
		return -1;
	}
	item->key = key;
	item->keylen = keylen;
	item->value = value;

	bucket = map_bucket(map, key, keylen);

	if (lset_store(bucket, item, &replaced) == -1) {
		free(item);
		return -1;
	}
	if (replaced != NULL) {
		free(replaced);
	}

	if (lset_len(bucket) > MAX_BUCKET_LOAD) {
		return map_grow(map);
	}

	return 0;
}

void *
map_load(struct map *map, uint8_t *key, size_t keylen)
{
	struct lset *bucket;
	struct map_item search, *found;

	search.key = key;
	search.keylen = keylen;

	bucket = map_bucket(map, key, keylen);
	found = lset_load(bucket, &search);
	if (found == NULL) {
		return NULL;
	}
	return found->value;
}

void *
map_remove(struct map *map, uint8_t *key, size_t keylen)
{
	struct lset *bucket;
	struct map_item search, *removed;
	void *value;

	search.key = key;
	search.keylen = keylen;

	bucket = map_bucket(map, key, keylen);
	removed = lset_remove(bucket, &search);
	if (removed == NULL) {
		return NULL;
	}
	value = removed->value;
	free(removed);
	return value;
}

struct map_iter_ctx {
	bool (*it)(uint8_t *key, size_t keylen, void *value, void *ctx);
	void *ctx;
	bool ok;
};

static bool
map_iter_lset(void *data, void *ctx)
{
	struct map_item *item = data;
	struct map_iter_ctx *mctx = ctx;
	mctx->ok = mctx->it(item->key, item->keylen, item->value, mctx->ctx);
	return mctx->ok;
}

void
map_iter(struct map *map, bool (*it)(uint8_t *key, size_t keylen, void *value, void *ctx), void *ctx)
{
	struct map_iter_ctx mctx;
	size_t i;
	mctx.it = it;
	mctx.ctx = ctx;
	mctx.ok = true;
	for (i = 0; i < map->len && mctx.ok; i++) {
		lset_iter(map->buckets[i], map_iter_lset, &mctx);
	}
}

static bool
map_free_item(void *data, void *ctx)
{
	(void)ctx;
	free(data);
	return true;
}

static bool
map_item_equal(void *x, void *y)
{
	struct map_item *ix = x, *iy = y;
	return ix->keylen == iy->keylen && memcmp(ix->key, iy->key, ix->keylen) == 0;
}

static size_t
map_hash(uint8_t *key, size_t keylen)
{
	/* variant of djb2 */
	size_t i;
	size_t hash = 5381;
	for (i = 0; i < keylen; i++) {
		hash = hash * 33 ^ key[i];
	}
	return hash;
}

static struct lset *
map_bucket(struct map *map, uint8_t *key, size_t keylen)
{
	size_t index = map_hash(key, keylen) % map->len;
	return map->buckets[index];
}

static size_t
nearest_power2(size_t x)
{
	x--;
	x |= x >> 1;
	x |= x >> 2;
	x |= x >> 4;
	x |= x >> 8;
	x |= x >> 16;
	/* TODO: better way? */
	if (sizeof(size_t) == 8) {
		/* size_t is 64-bit */
		x |= x >> 32;
	}
	x++;
	return x;
}

struct map_grow_context {
	struct map *new;
	bool ok;
};

static bool
map_grow_copy_item(void *data, void *ctx)
{
	struct map_item *item = data;
	struct map_grow_context *gctx = ctx;
	struct lset *bucket;
	void *replaced = NULL;
	bucket = map_bucket(gctx->new, item->key, item->keylen);
	if (lset_store(bucket, item, &replaced) == -1) {
		gctx->ok = false;
		return false;
	}
	/* map shouldn't have duplicates */
	if (replaced != NULL) {
		gctx->ok = false;
		return false;
	}
	return true;
}

static int
map_grow(struct map *map)
{
	struct map new;
	struct map_grow_context ctx;
	size_t i;

	/* initialize new buckets */
	new.len = nearest_power2(map->len + 1);
	if ((new.buckets = malloc(new.len * sizeof(struct lset *))) == NULL) {
		return -1;
	}

	for (i = 0; i < new.len; i++) {
		if ((new.buckets[i] = lset_new(map_item_equal)) == NULL) {
			goto err1;
		}
	}

	/* copy existing bucket data */
	ctx.new = &new;
	ctx.ok = true;
	for (i = 0; i < map->len; i++) {
		lset_iter(map->buckets[i], map_grow_copy_item, &ctx);
		if (!ctx.ok) {
			goto err2;
		}
	}

	/* free old buckets */
	for (i = 0; i < map->len; i++) {
		lset_free(map->buckets[i]);
	}
	free(map->buckets);

	/* replace buckets reference */
	map->buckets = new.buckets;
	map->len = new.len;
	return 0;
err2:
	i = new.len;
err1:
	while (i-- > 0) {
		lset_free(new.buckets[i]);
	}
	free(new.buckets);
	return -1;
}
