#ifndef DHT_MAP_H
#define DHT_MAP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct map;

struct map *map_new(size_t len);
void map_free(struct map *map);
int map_store(struct map *map, uint8_t *key, size_t keylen, void *value);
void *map_load(struct map *map, uint8_t *key, size_t keylen);
void *map_remove(struct map *map, uint8_t *key, size_t keylen);
void map_iter(struct map *map, bool (*it)(uint8_t *key, size_t keylen, void *value, void *ctx), void *ctx);

#endif /* DHT_MAP_H */
