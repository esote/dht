#pragma once

#include <stdint.h>
#include <stdbool.h>

#include "proto.h"
#include "rtable.h"

int rtable_sqlite(struct rtable *rt, const char *filename, const uint8_t self[NODE_ID_SIZE], bool (*alive)(void *ctx, const struct node *n), void *alive_ctx);
