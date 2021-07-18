#ifndef DHT_BUCKET_H
#define DHT_BUCKET_H

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#include "proto.h"

struct bucket {
	bool (*alive)(const struct node *n, void *arg);
	void *arg;
	size_t k;
	size_t n;
	pthread_rwlock_t mu;
	struct node *nodes;
};

int bucket_init(struct bucket *b, bool (*alive)(const struct node *n, void *arg),
	void *arg, size_t k);
int bucket_close(struct bucket *b);
int bucket_store(struct bucket *b, const struct node *n);
int bucket_append(struct bucket *b, struct node **s, size_t *len, size_t n);

#endif /* DHT_BUCKET_H */
