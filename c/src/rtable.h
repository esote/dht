#ifndef DHT_RTABLE_H
#define DHT_RTABLE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "proto.h"
#include "bucket.h"

#define BUCKET_COUNT ((NODE_ID_SIZE) * 8)
#define K 20

struct rtable {
	uint8_t self[NODE_ID_SIZE];
	struct bucket buckets[BUCKET_COUNT];
};

int rtable_init(struct rtable *rt, const uint8_t self[NODE_ID_SIZE],
	bool (*alive)(const struct node *n, void *arg), void *arg);
int rtable_close(struct rtable *rt);
int rtable_store(struct rtable *rt, const struct node *n);
int rtable_closest(struct rtable *rt, const uint8_t id[NODE_ID_SIZE], size_t k,
	struct node **closest, size_t *len);

#endif /* DHT_RTABLE_H */
