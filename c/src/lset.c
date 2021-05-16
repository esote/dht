#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include "lset.h"

struct lset_node {
	void *data;
	struct lset_node *prev;
	struct lset_node *next;
};

struct lset {
	struct lset_node *head;
	struct lset_node *tail;
	size_t len;
	bool (*equal)(void *, void *);
};

struct lset *
lset_new(bool (*equal)(void *, void *))
{
	struct lset *set;
	if ((set = malloc(sizeof(struct lset))) == NULL) {
		return NULL;
	}
	set->head = NULL;
	set->tail = NULL;
	set->len = 0;
	set->equal = equal;
	return set;
}

void
lset_free(struct lset *set)
{
	struct lset_node *tmp;
	while (set->head != NULL) {
		tmp = set->head;
		set->head = set->head->next;
		free(tmp);
	}
	free(set);
}

int
lset_store(struct lset *set, void *data, void **replaced)
{
	struct lset_node *n, *new;

	for (n = set->head; n != NULL; n = n->next) {
		if (set->equal(data, n->data)) {
			if (replaced != NULL) {
				*replaced = n->data;
			}
			n->data = data;
			return 0;
		}
	}

	/* data is not in set */
	if ((new = malloc(sizeof(struct lset_node))) == NULL) {
		return -1;
	}
	new->data = data;
	new->next = NULL;
	new->prev = set->tail;

	if (set->head == NULL) {
		set->head = new;
		set->tail = new;
	} else {
		set->tail->next = new;
		set->tail = new;
	}
	set->len++;
	return 0;
}

void *
lset_load(struct lset *set, void *data)
{
	struct lset_node *n;
	for (n = set->head; n != NULL; n = n->next) {
		if (set->equal(data, n->data)) {
			return n->data;
		}
	}
	return NULL;
}

void *
lset_remove(struct lset *set, void *data)
{
	void *removed;
	struct lset_node *n;

	for (n = set->head; n != NULL && !set->equal(data, n->data); n = n->next) {}

	if (n == NULL) {
		return NULL;
	}

	set->len--;
	if (n->prev == NULL) {
		set->head = n->next;
	} else {
		n->prev->next = n->next;
	}
	if (n->next == NULL) {
		set->tail = n->prev;
	} else {
		n->next->prev = n->prev;
	}
	removed = n->data;
	free(n);
	return removed;
}

void
lset_iter(struct lset *set, bool (*it)(void *data, void *ctx), void *ctx)
{
	struct lset_node *n;
	for (n = set->head; n != NULL && it(n->data, ctx); n = n->next) {}
}

size_t
lset_len(struct lset *set)
{
	return set->len;
}
