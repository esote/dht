#pragma once

#include <stdint.h>
#include <stddef.h>

#include "monitor.h"
#include "proto.h"

#ifndef K
#define K 20
#endif

struct rtable {
	int (*close)(struct rtable *rt);
	int (*store)(struct rtable *rt, const struct node *n);
	int (*closest)(struct rtable *rt, const uint8_t node_id[NODE_ID_SIZE], struct node closest[K], size_t *len);
	void *priv;
};

int rtable_start(int monitor, struct config *config);
