#ifndef DHT_KBUCKET_H
#define DHT_KBUCKET_H

#include <stddef.h>
#include <stdint.h>
#include "proto.h"

struct kbucket;

/* TODO: change to kbucket_* */
struct kbucket *kb_new(size_t k);
void kb_free(struct kbucket *kb);
const struct node_triple *kb_load(const struct kbucket *kb,
	const uint8_t id[NODE_ID_SIZE]);
const struct node_triple *kb_oldest(const struct kbucket *kb);
int kb_store(struct kbucket *kb, const struct node_triple *n);
struct node_triple *kb_remove(struct kbucket *kb, const uint8_t id[NODE_ID_SIZE]);
struct node_triple *kb_append(const struct kbucket *kb, struct node_triple *s,
	size_t *len, size_t n);

#endif /* DHT_KBUCKET_H */
