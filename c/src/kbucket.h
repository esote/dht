#ifndef DHT_KBUCKET_H
#define DHT_KBUCKET_H

#include <stddef.h>
#include <stdint.h>

#include "proto.h"

struct kbucket;

struct kbucket *kbucket_new(size_t k);
void kbucket_free(struct kbucket *kb);
const struct node *kbucket_load(const struct kbucket *kb, const uint8_t id[NODE_ID_SIZE]);
const struct node *kbucket_oldest(const struct kbucket *kb);
int kbucket_store(struct kbucket *kb, const struct node *n);
struct node *kbucket_remove(struct kbucket *kb, const uint8_t id[NODE_ID_SIZE]);
int kbucket_append(const struct kbucket *kb, struct node **s, size_t *len,
	size_t n);

#endif /* DHT_KBUCKET_H */
