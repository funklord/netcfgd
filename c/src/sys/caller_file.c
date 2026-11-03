/*
 * caller_file.c -- the rule described in caller_file.h.
 *
 * The directory is opened and checked, and the file is created relative to
 * that descriptor, so what is checked is what is written into: a path walked
 * twice is a path somebody can change between the walks.
 */
#include "ncfg/caller_file.h"

#include "ncfg/base.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* The directory part and the file name of `path`, into `dir` and `*name`. */
static int split(const char *path, char *dir, size_t dir_size, const char **name)
{
	const char *slash = strrchr(path, '/');
	size_t      length;

	if (!slash || !slash[1] || strcmp(slash + 1, ".") == 0 || strcmp(slash + 1, "..") == 0) {
		return 0;
	}
	length = (size_t)(slash - path);
	if (length == 0u) {
		length = 1u; /* the root directory itself */
	}
	if (length >= dir_size) {
		return 0;
	}
	memcpy(dir, path, length);
	dir[length] = '\0';
	*name = slash + 1;
	return 1;
}

int ncfg_caller_file_create(const char *path, uid_t uid, gid_t gid, const char *body,
    size_t length, char *err, size_t err_size)
{
	char        dir[4096];
	const char *name = NULL;
	struct stat held;
	size_t      written = 0;
	int         dir_fd;
	int         fd;

	if (!path || path[0] != '/') {
		ncfg_error_set(err, err_size, "a document's path must be absolute");
		return 0;
	}
	if (!split(path, dir, sizeof(dir), &name)) {
		ncfg_error_set(err, err_size, "%s does not name a file", path);
		return 0;
	}
	dir_fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (dir_fd < 0) {
		ncfg_error_set(err, err_size, "%s cannot be opened: %s", dir, strerror(errno));
		return 0;
	}
	if (fstat(dir_fd, &held) != 0) {
		ncfg_error_set(err, err_size, "%s cannot be read: %s", dir, strerror(errno));
		(void)close(dir_fd);
		return 0;
	}
	if (held.st_uid != uid) {
		ncfg_error_set(err, err_size,
		    "%s is not the caller's directory, so a document is not written there", dir);
		(void)close(dir_fd);
		return 0;
	}
	if (held.st_mode & (S_IWGRP | S_IWOTH)) {
		ncfg_error_set(err, err_size,
		    "%s is writable by others than the caller, so a document is not written there",
		    dir);
		(void)close(dir_fd);
		return 0;
	}
	fd = openat(dir_fd, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
	if (fd < 0) {
		ncfg_error_set(err, err_size, "%s cannot be created%s: %s", path,
		    errno == EEXIST ? " (it is already there, and is not replaced)" : "",
		    strerror(errno));
		(void)close(dir_fd);
		return 0;
	}
	if (fchown(fd, uid, gid) != 0 && geteuid() == 0) {
		ncfg_error_set(err, err_size, "%s could not be given to its caller: %s", path,
		    strerror(errno));
		(void)close(fd);
		(void)unlinkat(dir_fd, name, 0);
		(void)close(dir_fd);
		return 0;
	}
	while (written < length) {
		ssize_t n = write(fd, body + written, length - written);

		if (n < 0 && errno == EINTR) {
			continue;
		}
		if (n <= 0) {
			ncfg_error_set(err, err_size, "%s could not be written: %s", path,
			    n < 0 ? strerror(errno) : "no progress");
			(void)close(fd);
			(void)unlinkat(dir_fd, name, 0);
			(void)close(dir_fd);
			return 0;
		}
		written += (size_t)n;
	}
	if (close(fd) != 0) {
		ncfg_error_set(err, err_size, "%s could not be written: %s", path, strerror(errno));
		(void)unlinkat(dir_fd, name, 0);
		(void)close(dir_fd);
		return 0;
	}
	(void)close(dir_fd);
	return 1;
}
