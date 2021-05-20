#ifndef DHT_LSET_H
#define DHT_LSET_H

#include <stdbool.h>
#include <stddef.h>

struct lset;

struct lset *lset_new(bool (*equal)(void *, void*));
void lset_free(struct lset *set);
int lset_store(struct lset *set, void *data, void **replaced);
void *lset_load(struct lset *set, void *data);
void *lset_remove(struct lset *set, void *data);
void lset_iter(struct lset *set, bool (*it)(void *data, void *ctx), void *ctx);
size_t lset_len(struct lset *set);

#endif /* DHT_LSET_H */
