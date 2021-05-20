#ifndef DHT_STORER_H
#define DHT_STORER_H

#include <stddef.h>
#include <stdint.h>
#include "io.h"

struct storer;

struct storer * storer_new(const char *dir, size_t max_length, size_t max_count);
int storer_free(struct storer *s);
int storer_load(struct storer *s, const uint8_t *key, size_t key_length, size_t *value_length);
int storer_store(struct storer *s, const uint8_t *key, size_t key_length, struct io *value, size_t value_length);
int storer_delete(struct storer *s, const uint8_t *key, size_t key_length);

#endif /* DHT_STORER_H */
