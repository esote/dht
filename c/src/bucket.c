#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "bucket.h"
#include "proto.h"
#include "util.h"

static int bucket_store_node(struct bucket *b, const struct node *n);
static const struct node *bucket_oldest(const struct bucket *b);
static int bucket_remove(struct bucket *b, const uint8_t id[NODE_ID_SIZE]);
static int copy_node(struct node *dst, const struct node *src);

int
bucket_init(struct bucket *b, bool (*alive)(const struct node *n, void *arg),
	void *arg, size_t k)
{
	b->alive = alive;
	b->arg = arg;
	b->k = k;
	b->n = 0;

	if ((errno = pthread_rwlock_init(&b->mu, NULL)) != 0) {
		return -1;
	}

	/* TODO: overflow n*m */
	if ((b->nodes = malloc(sizeof(*b->nodes) * k)) == NULL) {
		(void)pthread_rwlock_destroy(&b->mu);
		return -1;
	}

	return 0;
}

int
bucket_close(struct bucket *b)
{
	size_t i;
	int ret;

	ret = 0;

	if ((errno = pthread_rwlock_destroy(&b->mu)) != 0) {
		ret = -1;
	}

	for (i = 0; i < b->n; i++) {
		free(b->nodes[i].addr);
	}

	free(b->nodes);
	return ret;
}

int
bucket_store(struct bucket *b, const struct node *n)
{
	const struct node *oldest;

	if (bucket_store_node(b, n) != -1) {
		/* n moved to back */
		return 0;
	}

	if ((oldest = bucket_oldest(b)) == NULL) {
		/* bucket should have >0 nodes if storing failed */
		return -1;
	}

	if (b->alive(oldest, b->arg)) {
		/* oldest node is alive, refresh it */
		(void)bucket_store_node(b, oldest);
		return 0;
	}

	if (bucket_remove(b, oldest->id) == -1) {
		return -1;
	}

	if (bucket_store_node(b, n) == -1) {
		return -1;
	}

	return 0;
}

int
bucket_append(struct bucket *b, struct node **s, size_t *len, size_t n)
{
	size_t i, j;
	struct node *tmp;

	i = min(b->n, n);
	if (i == 0) {
		return 0;
	}

	if ((tmp = realloc(*s, sizeof(**s) * (*len + i))) == NULL) {
		return -1;
	}
	*s = tmp;

	for (j = 0; j < i; i++) {
		(*s)[*len + j] = b->nodes[b->n - 1 - j];
	}
	*len += i;

	return 0;
}

static int
bucket_store_node(struct bucket *b, const struct node *n)
{
	struct node tmp;
	size_t i;

	for (i = 0; i < b->n; i++) {
		if (memcmp(b->nodes[i].id, n->id, NODE_ID_SIZE) == 0) {
			/* bucket contains n */
			if (i == b->n - 1) {
				/* n is already at the back */
				return 0;
			}

			/* move n to the back */
			tmp = b->nodes[i];
			(void)memmove(b->nodes + i, b->nodes + i + 1,
				(b->n - i - 1) * sizeof(*b->nodes));
			b->nodes[b->n - 1] = tmp;
			return 0;
		}
	}

	if (b->n == b->k) {
		/* bucket full */
		return -1;
	}

	if (copy_node(&b->nodes[b->n], n) == -1) {
		return -1;
	}
	b->n++;
	return 0;
}

static const struct node *
bucket_oldest(const struct bucket *b)
{
	if (b->n == 0) {
		return NULL;
	}
	return &b->nodes[0];
}

static int
bucket_remove(struct bucket *b, const uint8_t id[NODE_ID_SIZE])
{
	size_t i;

	for (i = 0; i < b->n; i++) {
		if (memcmp(b->nodes[i].id, id, NODE_ID_SIZE) == 0) {
			free(b->nodes[i].addr);
			(void)memmove(b->nodes + i, b->nodes + i + 1,
				(b->n - i - 1) * sizeof(*b->nodes));
			b->n--;
			return 0;
		}
	}

	return -1;
}

static int
copy_node(struct node *dst, const struct node *src)
{
	(void)memcpy(dst->id, src->id, NODE_ID_SIZE);
	(void)memcpy(dst->dyn_x, src->dyn_x, DYN_X_SIZE);
	if (string_empty(src->addr)) {
		dst->addr = NULL;
	} else if ((dst->addr = strdup(src->addr)) == NULL){
		return -1;
	}
	dst->port = src->port;
	return 0;
}
