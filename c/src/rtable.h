#ifndef DHT_RTABLE_H
#define DHT_RTABLE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "proto.h"

struct rtable;

struct rtable *rtable_new(const uint8_t self[NODE_ID_SIZE], size_t k);
int rtable_close(struct rtable *rt);
int rtable_store(struct rtable *rt, const struct node *n);
const struct node *rtable_oldest(struct rtable *rt, const uint8_t id[NODE_ID_SIZE]);
struct node *rtable_replace_oldest(struct rtable *rt, const struct node *n,
	bool (*ping)(const struct node *n, void *arg), void *arg);
int rtable_closest(struct rtable *rt, const uint8_t id[NODE_ID_SIZE],
	size_t k, struct node **closest, size_t *len);

#endif /* DHT_RTABLE_H */
