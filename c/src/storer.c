#include <sys/stat.h>

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "io.h"
#include "storer.h"
#include "util.h"

static int store_file(struct storer *s, char *file, int value, size_t value_length);
static char *encode_key(const struct storer *s, const uint8_t *key, size_t key_length);
static int count_files(const char *dir, size_t *count);
static bool file_is_regular(const struct dirent *ent);

struct storer {
	char *dir;
	size_t dir_length;
	size_t max_length;
	size_t max_count;
	size_t count;
	pthread_mutex_t mu;
};

struct storer *
storer_new(const char *dir, size_t max_length, size_t max_count)
{
	struct storer *s;

	if ((s = malloc(sizeof(*s))) == NULL) {
		return NULL;
	}

	if ((s->dir = strdup(dir)) == NULL) {
		free(s);
		return NULL;
	}
	s->dir_length = strlen(s->dir);

	if (count_files(s->dir, &s->count) == -1) {
		free(s->dir);
		free(s);
		return NULL;
	}

	if ((errno = pthread_mutex_init(&s->mu, NULL)) != 0) {
		free(s->dir);
		free(s);
		return NULL;
	}

	s->max_length = max_length;
	s->max_count = max_count;
	return s;
}

int
storer_free(struct storer *s)
{
	errno = pthread_mutex_destroy(&s->mu);
	free(s->dir);
	free(s);
	if (errno != 0) {
		return -1;
	}
	return 0;
}

int
storer_load(struct storer *s, const uint8_t *key, size_t key_length, size_t *value_length)
{
	struct stat sb;
	char *file;
	int fd;
	if ((file = encode_key(s, key, key_length)) == NULL) {
		return -1;
	}

	fd = open(file, O_RDONLY);
	free(file);
	if (fd == -1) {
		return -1;
	}
	if (fstat(fd, &sb) == -1) {
		(void)close(fd);
		return -1;
	}
	*value_length = (size_t)sb.st_size;
	return fd;
}

int
storer_store(struct storer *s, const uint8_t *key, size_t key_length, int value, size_t value_length)
{
	char *file;
	bool can_store;

	if (value_length > s->max_length) {
		return -1;
	}
	if (s->count >= s->max_count) {
		return -1;
	}

	if ((file = encode_key(s, key, key_length)) == NULL) {
		return -1;
	}
	if (value == -1) {
		/* check if file could be stored */
		can_store = access(file, F_OK) == -1 && errno != ENOENT;
		errno = 0;
		free(file);
		if (can_store) {
			return 0;
		}
		return -1;
	}

	/* reserve spot for file */
	assert(pthread_mutex_lock(&s->mu) == 0);
	s->count++;
	assert(pthread_mutex_unlock(&s->mu) == 0);

	if (store_file(s, file, value, value_length) == -1) {
		/* clear reserved spot */
		assert(pthread_mutex_lock(&s->mu) == 0);
		s->count--;
		assert(pthread_mutex_unlock(&s->mu) == 0);
	}

	free(file);
	return 0;
}

int
storer_delete(struct storer *s, const uint8_t *key, size_t key_length)
{
	char *file;
	if ((file = encode_key(s, key, key_length)) == NULL) {
		return -1;
	}
	if (unlink(file) == -1) {
		free(file);
		return -1;
	}
	free(file);
	assert(pthread_mutex_lock(&s->mu) == 0);
	/* count might be incorrect if files were changed outside of storer */
	if (s->count > 0) {
		s->count--;
	}
	assert(pthread_mutex_unlock(&s->mu) == 0);
	return 0;
}

static int
store_file(struct storer *s, char *file, int value, size_t value_length)
{
	int fd;
	if ((fd = open(file, O_WRONLY|O_CREAT|O_EXCL, 0600)) == -1) {
		return -1;
	}
	if (copy_n(fd, value, value_length) == -1) {
		(void)close(fd);
		return -1;
	}
	return close(fd);
}

static char *
encode_key(const struct storer *s, const uint8_t *key, size_t key_length)
{
	/* dir + '/' + encoded key + '\0' */
	char *file;
	if ((file = malloc(s->dir_length + 1 + base64_url_nopad_len(key_length) + 1)) == NULL) {
		return NULL;
	}
	(void)memcpy(file, s->dir, s->dir_length);
	file[s->dir_length] = '/';
	base64_url_nopad(file + s->dir_length + 1, key, key_length);
	file[s->dir_length + 1 + base64_url_nopad_len(key_length)] = '\0';
	return file;
}

static int
count_files(const char *dir, size_t *count)
{
	DIR *d;
	struct dirent *ent;
	size_t working_count;
	working_count = 0;
	if ((d = opendir(dir)) == NULL) {
		return -1;
	}
	errno = 0;
	while ((ent = readdir(d)) != NULL) {
		if (file_is_regular(ent)) {
			working_count++;
		}
	}
	if (errno != 0) {
		/* reading failed */
		(void)closedir(d);
		return -1;
	}
	if (closedir(d) == -1) {
		return -1;
	}
	*count = working_count;
	return 0;
}

static bool
file_is_regular(const struct dirent *ent)
{
	/* TODO: try to use (ent->d_type==DT_REG) if available */
	struct stat sb;
	if (stat(ent->d_name, &sb) == -1) {
		errno = 0; /* ignore error */
		return false;
	}
	return S_ISREG(sb.st_mode);
}
