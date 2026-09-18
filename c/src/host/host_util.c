/*
 * host_util.c -- the shared operations of the host module.
 *
 * See `host_internal.h`. The one thing here that is a decision rather than
 * plumbing is the temporary file's name in `ncfg_host_write_atomically`, and
 * `state.h` has the measurement behind it.
 */
#include "host_internal.h"

#include "ncfg/base.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

char *ncfg_host_join(const char *dir, const char *leaf, char *err, size_t err_size)
{
	size_t length;
	char *out;

	if (!dir || !leaf) {
		ncfg_error_set(err, err_size, "a path was asked for with nothing to build it from");
		return NULL;
	}
	length = strlen(dir) + 1u + strlen(leaf) + 1u;
	out = malloc(length);
	if (!out) {
		ncfg_error_set(err, err_size, "out of memory building a path");
		return NULL;
	}
	(void)snprintf(out, length, "%s/%s", dir, leaf);
	return out;
}

int ncfg_host_make_directory(const char *path, mode_t mode, char *err, size_t err_size)
{
	char *work;
	char *at;
	int ok = 1;

	if (!path || !path[0]) {
		ncfg_error_set(err, err_size, "a directory was asked for with no name");
		return 0;
	}
	work = strdup(path);
	if (!work) {
		ncfg_error_set(err, err_size, "out of memory");
		return 0;
	}
	for (at = work + 1; *at; at++) {
		if (*at != '/') {
			continue;
		}
		*at = '\0';
		if (mkdir(work, mode) != 0 && errno != EEXIST) {
			ok = 0;
			break;
		}
		*at = '/';
	}
	if (ok && mkdir(work, mode) != 0 && errno != EEXIST) {
		ok = 0;
	}
	if (!ok) {
		ncfg_error_set(err, err_size, "could not create %s: %s", path, strerror(errno));
	}
	free(work);
	return ok;
}

static int write_all(int fd, const void *bytes, size_t length)
{
	const char *at = bytes;
	size_t written = 0;

	while (written < length) {
		ssize_t put = write(fd, at + written, length - written);

		if (put < 0) {
			if (errno == EINTR) {
				continue;
			}
			return 0;
		}
		written += (size_t)put;
	}
	return 1;
}

int ncfg_host_write_atomically(const char *path, const void *bytes, size_t length, mode_t mode,
    char *err, size_t err_size)
{
	/*
	 * **Distinguishes one call from the next within a process.** The process
	 * id alone is not enough: two threads of one process share it, and the
	 * defect this naming exists for is two writers landing on one temporary.
	 */
	static unsigned long sequence;
	const char *slash = strrchr(path, '/');
	char *directory;
	char *temporary;
	size_t temporary_size;
	int fd;

	if (!path || !path[0]) {
		ncfg_error_set(err, err_size, "a file was asked for with no name");
		return 0;
	}
	directory = slash ? strndup(path, (size_t)(slash - path)) : strdup(".");
	if (!directory || !directory[0]) {
		/* A path of `/x` has an empty parent, which is the root. */
		free(directory);
		directory = strdup("/");
	}
	if (!directory) {
		ncfg_error_set(err, err_size, "out of memory");
		return 0;
	}
	if (!ncfg_host_make_directory(directory, (mode_t)0755, err, err_size)) {
		free(directory);
		return 0;
	}
	temporary_size = strlen(directory) + strlen(slash ? slash + 1 : path) + 64u;
	temporary = malloc(temporary_size);
	if (!temporary) {
		free(directory);
		ncfg_error_set(err, err_size, "out of memory");
		return 0;
	}
	(void)snprintf(temporary, temporary_size, "%s/.%s.%ld.%lu", directory,
	    slash ? slash + 1 : path, (long)getpid(), sequence++);
	free(directory);

	fd = open(temporary, O_WRONLY | O_CREAT | O_TRUNC, mode);
	if (fd < 0) {
		ncfg_error_set(err, err_size, "could not write %s: %s", path, strerror(errno));
		free(temporary);
		return 0;
	}
	/* The mode is set on the descriptor as well as the open, because `open`
	 * applies its mode only when it creates the file -- and this one may be
	 * writing a credential back over a temporary an earlier run left. */
	if (fchmod(fd, mode) != 0 || !write_all(fd, bytes, length) ||
	    /* Durable before it is visible. A rename that beats the data to disk
	     * is a truncated file after a power cut, which on a router is the
	     * failure that needs a serial cable. */
	    fsync(fd) != 0 || close(fd) != 0) {
		ncfg_error_set(err, err_size, "could not write %s: %s", path, strerror(errno));
		(void)unlink(temporary);
		free(temporary);
		return 0;
	}
	if (rename(temporary, path) != 0) {
		ncfg_error_set(err, err_size, "could not write %s: %s", path, strerror(errno));
		(void)unlink(temporary);
		free(temporary);
		return 0;
	}
	free(temporary);
	return 1;
}

char *ncfg_host_read_file(const char *path, size_t *length_out, size_t ceiling)
{
	int fd;
	char *body = NULL;
	size_t length = 0;
	size_t capacity = 0;

	if (length_out) {
		*length_out = 0;
	}
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		return NULL;
	}
	for (;;) {
		ssize_t got;

		if (length + 1u >= capacity) {
			size_t want = capacity ? capacity * 2u : 8192u;
			char *grown;

			/* One byte past the ceiling, plus the terminator: a file of
			 * exactly `ceiling` bytes is content and must read, and the
			 * byte after it is what makes "too big" observable. */
			if (want > ceiling + 2u) {
				want = ceiling + 2u;
			}
			if (length + 1u >= want) {
				free(body);
				(void)close(fd);
				errno = EFBIG;
				return NULL;
			}
			grown = realloc(body, want);
			if (!grown) {
				free(body);
				(void)close(fd);
				errno = ENOMEM;
				return NULL;
			}
			body = grown;
			capacity = want;
		}
		got = read(fd, body + length, capacity - length - 1u);
		if (got < 0) {
			if (errno == EINTR) {
				continue;
			}
			free(body);
			(void)close(fd);
			return NULL;
		}
		if (got == 0) {
			break;
		}
		length += (size_t)got;
		/* The callers here read files netcfgd or a helper wrote. One that has
		 * grown without bound is a fault rather than content, and reading it
		 * whole in order to say so would be the fault happening twice. */
		if (length > ceiling) {
			free(body);
			(void)close(fd);
			errno = EFBIG;
			return NULL;
		}
	}
	(void)close(fd);
	if (!body) {
		body = malloc(1u);
		if (!body) {
			errno = ENOMEM;
			return NULL;
		}
	}
	body[length] = '\0';
	if (length_out) {
		*length_out = length;
	}
	return body;
}

int ncfg_host_strings_add_bytes(char ***items, size_t *count, size_t *capacity,
    const char *text, size_t length)
{
	char *copy;

	if (*count == *capacity) {
		size_t want = *capacity ? *capacity * 2u : 8u;
		char **grown = realloc(*items, want * sizeof(*grown));

		if (!grown) {
			return 0;
		}
		*items = grown;
		*capacity = want;
	}
	copy = malloc(length + 1u);
	if (!copy) {
		return 0;
	}
	if (length) {
		memcpy(copy, text, length);
	}
	copy[length] = '\0';
	(*items)[*count] = copy;
	(*count)++;
	return 1;
}

int ncfg_host_strings_add(char ***items, size_t *count, size_t *capacity, const char *text)
{
	return ncfg_host_strings_add_bytes(items, count, capacity, text, strlen(text));
}

static int by_name(const void *one, const void *other)
{
	const char *const *a = one;
	const char *const *b = other;

	return strcmp(*a, *b);
}

void ncfg_host_strings_sort_unique(char **items, size_t *count)
{
	size_t kept = 0;
	size_t i;

	if (!items || *count < 1u) {
		return;
	}
	qsort(items, *count, sizeof(*items), by_name);
	for (i = 0; i < *count; i++) {
		if (kept && strcmp(items[kept - 1u], items[i]) == 0) {
			free(items[i]);
			continue;
		}
		items[kept++] = items[i];
	}
	*count = kept;
}

void ncfg_host_strings_free(char **items, size_t count)
{
	size_t i;

	for (i = 0; i < count; i++) {
		free(items[i]);
	}
	free(items);
}

int ncfg_host_is_staging(const char *name)
{
	return name && name[0] == '.';
}
