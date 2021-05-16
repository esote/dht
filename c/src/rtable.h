#ifndef DHT_RTABLE_H
#define DHT_RTABLE_H

#include <stdint.h>
#include <stddef.h>
#include "proto.h"

struct rtable;

struct rtable *rtable_new(const uint8_t self[NODE_ID_SIZE], size_t k);
void rtable_free(struct rtable *rt);
int rtable_store(struct rtable *rt, const struct node_triple *n);
const struct node_triple *rtable_oldest(const struct rtable *rt,
	const uint8_t id[NODE_ID_SIZE]);
struct node_triple *rtable_replace_oldest(struct rtable *rt,
	const struct node_triple *n);
struct node_triple *rtable_closest(const struct rtable *rt,
	const uint8_t id[NODE_ID_SIZE], size_t k, size_t *len);

#endif /* DHT_RTABLE_H */
