#include <stdlib.h>

#include <check.h>

#include "map.h"
#include "lset.h"

START_TEST (test_map_init)
{
	struct map *map;
	if ((map = map_new(5)) == NULL) {
		ck_abort_msg("map_init");
	}
	map_free(map);
}

START_TEST (test_map_store_leak)
{
	struct map *map = map_new(0);
	uint8_t key[] = {1};

	int *value = malloc(sizeof(int));
	*value = 3;

	if (map_store(map, key, 1, value) == -1) {
		ck_abort_msg("map_store");
	}

	map_free(map);
	free(value);
}

START_TEST (test_map_store_grow)
{
	struct map *map = map_new(0);
	uint8_t keys[200];
	uint8_t i;

	for (i = 0; i < 200; i++) {
		keys[i] = i;
		if (map_store(map, &keys[i], 1, NULL) == -1) {
			ck_abort_msg("map_store");
		}
	}
	map_free(map);
}

static bool
map_unset_found(uint8_t *key, size_t keylen, void *value, void *ctx)
{
	bool *found;
	uint8_t *v;
	(void)keylen;
	found = ctx;
	v = value;
	if (*v != key[0]) {
		return false;
	}
	found[*v] = false;
	return true;
}

START_TEST (test_map_full)
{
	struct map *map = map_new(0);
	uint8_t keys[6][1] = {{0}, {1}, {2}, {3}, {4}, {5}};
	bool found[6] = {false};
	uint8_t *n = NULL;
	uint8_t i;
	for (i = 0; i < 6; i++) {
		map_store(map, keys[i], 1, &keys[i][0]);
	}
	for (i = 0; i < 6; i++) {
		if ((n = map_load(map, keys[i], 1)) == NULL) {
			ck_abort_msg("map_load");
		}
		if (*n != i) {
			ck_abort_msg("wrong loaded value");
		}
		found[*n] = true;
	}
	for (i = 0; i < 6; i++) {
		if (!found[i]) {
			ck_abort_msg("value missing");
		}
	}
	map_iter(map, map_unset_found, found);
	for (i = 0; i < 6; i++) {
		if (found[i]) {
			ck_abort_msg("value not unset");
		}
	}
	for (i = 0; i < 6; i++) {
		if ((n = map_remove(map, keys[i], 1)) == NULL) {
			ck_abort_msg("value missing");
		}
		if (*n != i) {
			ck_abort_msg("wrong deleted value");
		}
	}
	map_free(map);
}

Suite *
suite_map(void)
{
	Suite *s = suite_create("map");
	TCase *tc_core = tcase_create("core");

	tcase_add_test(tc_core, test_map_init);
	tcase_add_test(tc_core, test_map_store_leak);
	tcase_add_test(tc_core, test_map_store_grow);
	tcase_add_test(tc_core, test_map_full);

	suite_add_tcase(s, tc_core);
	return s;
}
