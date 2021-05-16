#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "proto.h"
#include "kbucket.h"
#include "util.h"

struct kbucket {
	size_t k;
	size_t n;
	struct node_triple *nodes;
};

struct kbucket *
kb_new(size_t k)
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
kb_free(struct kbucket *kb)
{
	free(kb->nodes);
	free(kb);
}

const struct node_triple *
kb_load(const struct kbucket *kb, const uint8_t id[NODE_ID_SIZE])
{
	size_t i;
	for (i = 0; i < kb->n; i++) {
		if (memcmp(kb->nodes[i].id, id, NODE_ID_SIZE) == 0) {
			return &kb->nodes[i];
		}
	}
	return NULL;
}

const struct node_triple *
kb_oldest(const struct kbucket *kb)
{
	if (kb->n == 0) {
		return NULL;
	}
	return &kb->nodes[0];
}

int
kb_store(struct kbucket *kb, const struct node_triple *n)
{
	struct node_triple tmp;
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

struct node_triple *
kb_remove(struct kbucket *kb, const uint8_t id[NODE_ID_SIZE])
{
	struct node_triple *n;
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

struct node_triple *
kb_append(const struct kbucket *kb, struct node_triple *s, size_t *len, size_t n)
{
	size_t i, j;
	struct node_triple *dst;
	if (len == NULL) {
		return NULL;
	}
	i = min(kb->n, n);
	if (i == 0) {
		return s;
	}
	if ((s = realloc(s, sizeof(*s) * (*len + i))) == NULL) {
		return NULL;
	}
	dst = s + *len;
	/* copy kb->nodes from back to front */
	for (j = 0; j < i; j++) {
		(void)memcpy(&dst[j], &kb->nodes[kb->n - j - 1], sizeof(*dst));
	}
	*len += i;
	return s;
}
