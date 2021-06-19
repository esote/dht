#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "kbucket.h"
#include "proto.h"
#include "util.h"

struct kbucket {
	size_t k;
	size_t n;
	struct node *nodes;
};

struct kbucket *
kbucket_new(size_t k)
{
	struct kbucket *kb;
	if (k == 0) {
		return NULL;
	}
	if ((kb = malloc(sizeof(*kb))) == NULL) {
		return NULL;
	}
	if ((kb->nodes = malloc(sizeof(*kb->nodes) * k)) == NULL) {
		free(kb);
		return NULL;
	}
	kb->k = k;
	kb->n = 0;
	return kb;
}

void
kbucket_free(struct kbucket *kb)
{
	free(kb->nodes);
	free(kb);
}

const struct node *
kbucket_load(const struct kbucket *kb, const uint8_t id[NODE_ID_SIZE])
{
	size_t i;
	for (i = 0; i < kb->n; i++) {
		if (memcmp(kb->nodes[i].id, id, NODE_ID_SIZE) == 0) {
			return &kb->nodes[i];
		}
	}
	return NULL;
}

const struct node *
kbucket_oldest(const struct kbucket *kb)
{
	if (kb->n == 0) {
		return NULL;
	}
	return &kb->nodes[0];
}

int
kbucket_store(struct kbucket *kb, const struct node *n)
{
	struct node tmp;
	size_t i;
	for (i = 0; i < kb->n; i++) {
		if (memcmp(kb->nodes[i].id, n->id, NODE_ID_SIZE) == 0) {
			if (i == kb->n - 1) {
				return 0;
			}
			/* move n to back */
			(void)memcpy(&tmp, &kb->nodes[i], sizeof(tmp));
			(void)memmove(&kb->nodes[i], &kb->nodes[i+1],
				(kb->n-i-1)*sizeof(*kb->nodes));
			(void)memcpy(&kb->nodes[kb->n - 1], &tmp, sizeof(tmp));
			return 0;
		}
	}
	if (kb->n == kb->k) {
		/* bucket full */
		return -1;
	}
	(void)memcpy(&kb->nodes[kb->n], n, sizeof(*n));
	kb->n++;
	return 0;
}

struct node *
kbucket_remove(struct kbucket *kb, const uint8_t id[NODE_ID_SIZE])
{
	struct node *n;
	size_t i;
	for (i = 0; i < kb->n; i++) {
		if (memcmp(kb->nodes[i].id, id, NODE_ID_SIZE) == 0) {
			/* remove and return node */
			if ((n = malloc(sizeof(*n))) == NULL) {
				return NULL;
			}
			(void)memcpy(n, &kb->nodes[i], sizeof(*n));
			(void)memmove(&kb->nodes[i], &kb->nodes[i+1],
				(kb->n-i-1)*sizeof(*kb->nodes));
			kb->n--;
			return n;
		}
	}
	return NULL;
}

int
kbucket_append(const struct kbucket *kb, struct node **s, size_t *len, size_t n)
{
	size_t i, j;
	struct node *dst, *tmp;
	if (len == NULL || s == NULL) {
		return -1;
	}
	i = min(kb->n, n);
	if (i == 0) {
		return 0;
	}
	tmp = realloc(*s, sizeof(**s) * (*len + i));
	if (tmp == NULL && *len + i != 0) {
		return -1;
	}
	*s = tmp;
	dst = *s + *len;
	/* copy kb->nodes from back to front */
	for (j = 0; j < i; j++) {
		(void)memcpy(&dst[j], &kb->nodes[kb->n - j - 1], sizeof(*dst));
	}
	*len += i;
	return 0;
}
