#include <stdbool.h>
#include <stddef.h>
#include <check.h>

#include "lset.h"

static bool
equal(void *x, void *y)
{
	return *(int*)(x) == *(int*)(y);
}

START_TEST (test_lset_store)
{
	struct lset *set;
	size_t i;
	int data[] = {0, 1, 2, 1, 3, 2};
	int *replaced = NULL;

	set = lset_new(equal);
	ck_assert(set != NULL);

	for (i = 0; i < 6; i++) {
		if (lset_store(set, &data[i], (void**)&replaced) == -1) {
			ck_abort_msg("lset_store");
		}
		if (replaced != NULL) {
			ck_assert(*replaced == data[i]);
			replaced = NULL;
		}
	}
	ck_assert(lset_len(set) == 4);
	lset_free(set);
}

START_TEST (test_lset_load)
{
	struct lset *set;
	size_t i;
	int data[] = {0, 1, 2, 1, 3, 2};
	int missing = 4;
	int *found;

	set = lset_new(equal);
	for (i = 0; i < 6; i++) {
		lset_store(set, &data[i], NULL);
	}

	for (i = 0; i < 6; i++) {
		found = lset_load(set, &data[i]);
		ck_assert(found != NULL);
		ck_assert(*found == data[i]);
	}

	found = lset_load(set, &missing);
	ck_assert(found == NULL);

	lset_free(set);
}

START_TEST (test_lset_remove)
{
	struct lset *set;
	size_t i;
	int data[] = {0, 1, 2, 3};
	int *removed;

	set = lset_new(equal);
	for (i = 0; i < 4; i++) {
		lset_store(set, &data[i], NULL);
	}

	/* remove from head */
	int forward[] = {0, 1, 2, 3};
	for (i = 0; i < 4; i++) {
		removed = lset_remove(set, &forward[i]);
		ck_assert(removed != NULL);
		ck_assert(*removed == forward[i]);
	}

	for (i = 0; i < 4; i++) {
		lset_store(set, &data[i], NULL);
	}

	/* remove from tail */
	int reverse[] = {3, 2, 1, 0};
	for (i = 0; i < 4; i++) {
		removed = lset_remove(set, &reverse[i]);
		ck_assert(removed != NULL);
		ck_assert(*removed == reverse[i]);
	}

	for (i = 0; i < 4; i++) {
		lset_store(set, &data[i], NULL);
	}

	/* remove from middle */
	int mid[] = {2, 1, 3, 0};
	for (i = 0; i < 4; i++) {
		removed = lset_remove(set, &mid[i]);
		ck_assert(removed != NULL);
		ck_assert(*removed == mid[i]);
	}

	/* remove missing element */
	ck_assert(lset_remove(set, &data[0]) == NULL);

	ck_assert(lset_len(set) == 0);

	lset_free(set);
}

Suite *
suite_lset(void)
{
	Suite *s = suite_create("lset");
	TCase *tc_core = tcase_create("core");

	tcase_add_test(tc_core, test_lset_store);
	tcase_add_test(tc_core, test_lset_load);
	tcase_add_test(tc_core, test_lset_remove);

	suite_add_tcase(s, tc_core);
	return s;
}
