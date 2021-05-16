#include <sys/stat.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <check.h>

#include "test.h"

#include "../storer.h"
#include "../util.h"

static int
recursive_delete(const char *dir)
{
	DIR *d;
	struct dirent *ent;
	char *full;

	if ((d = opendir(dir)) == NULL) {
		if (errno == ENOENT) {
			errno = 0;
			return 0;
		}
		return -1;
	}
	errno = 0;
	while ((ent = readdir(d)) != NULL) {
		if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) {
			continue;
		}
		if ((full = join_path_file(dir, ent->d_name)) == NULL) {
			(void)closedir(d);
			return -1;
		}
		if (unlink(full) == -1) {
			free(full);
			(void)closedir(d);
			return -1;
		}
		free(full);
	}
	if (errno != 0) {
		(void)closedir(d);
		return -1;
	}
	if (closedir(d) == -1) {
		return -1;
	}
	return rmdir(dir);
}

static const char *t_dir = "dir.test";
static const char *t_name = "val.test";
static const char *t_data = 

static void setup(void)
{
	ck_assert(recursive_delete(t_dir) != -1);
	ck_assert(mkdir(t_dir, 0700) != -1);
}

static void teardown(void)
{
	ck_assert(recursive_delete(t_dir) != -1);
}

/* 001 Test storing a file, loading it, then deleting it. */
START_TEST (test_storer_001)
{
	const uint8_t key[] = {'k', 'e', 'y'};
	const char *enc_key = "a2V5";
	const uint8_t value[] = {'v', 'a', 'l'};
	const char *value_name = "value.test";
	struct storer *s;

	ck_assert((s = storer_new(t_dir, 10, 2)) != NULL);
}

/* Test storing a key-value pair */
START_TEST (test_storer_store)
{
	struct storer *s;
	uint8_t key[] = {'k', 'e', 'y'};
	const char *enc_key = "a2V5";
	int value = open(t_value, O_RDONLY);
	uint8_t value_data[5];
	char *file;
	int fd;

	(void)memset(value_data, 0, 5);
	ck_assert((s = storer_new(t_dir, 10, 2)) != NULL);

	ck_assert(storer_store(s, key, 3, value, 4) != -1);
	ck_assert(close(value) != -1);

	ck_assert((file = join_path_file(t_dir, enc_key)) != NULL);
	ck_assert((fd = open(file, O_RDONLY)) != -1);
	/* should under-read, only stored 4 bytes from t_value_data */
	ck_assert(read(fd, value_data, 5) == 4);
	ck_assert(memcmp(value_data, t_value_data, 4) == 0);
	ck_assert(read(fd, value_data, 1) == 0); /* should get EOF */
	ck_assert(close(fd) != -1);
	free(file);

	ck_assert(storer_free(s) != -1);
}

Suite *
suite_storer(void)
{
	Suite *s = suite_create("storer");
	TCase *tc_core = tcase_create("core");

	tcase_add_checked_fixture(tc_core, setup, teardown);

	tcase_add_test(tc_core, test_storer_store);

	suite_add_tcase(s, tc_core);
	return s;
}
