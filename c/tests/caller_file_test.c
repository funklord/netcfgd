/*
 * caller_file_test.c -- the rule a root daemon holds a client-named path to
 * before writing a document there (caller_file.h, project.md 10.680).
 *
 * Run as whoever runs the suite, which is the caller here: its uid owns the
 * scratch directory, and a directory it does not own is /, which nobody but
 * root owns -- so the refusal is checked by asking for a different uid rather
 * than by needing a second account.
 */
#include "ncfg/caller_file.h"

#include "testdir.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int failures;

static void check(int condition, const char *what)
{
	printf("%-72s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

static int contents_are(const char *path, const char *want)
{
	char    got[256];
	ssize_t n;
	int     fd = open(path, O_RDONLY | O_CLOEXEC);

	if (fd < 0) {
		return 0;
	}
	n = read(fd, got, sizeof(got) - 1u);
	(void)close(fd);
	if (n < 0) {
		return 0;
	}
	got[n] = '\0';
	return strcmp(got, want) == 0;
}

int main(void)
{
	const char *base = testdir_make("caller_file");
	char        own[512];
	char        shared[512];
	char        path[600];
	char        target[600];
	char        link[600];
	char        err[256];
	struct stat held;
	uid_t       me = getuid();
	gid_t       group = getgid();

	(void)mkdir(testdir_in(base, "own", own, sizeof(own)), 0700);
	(void)mkdir(testdir_in(base, "shared", shared, sizeof(shared)), 0700);
	(void)chmod(shared, 0770);

	(void)snprintf(path, sizeof(path), "%s/status.json", own);
	check(ncfg_caller_file_create(path, me, group, "{}\n", 3u, err, sizeof(err)),
	    "a new file in the caller's own directory is written");
	check(contents_are(path, "{}\n"), "  with the document in it");
	check(stat(path, &held) == 0 && (held.st_mode & 0777) == 0600 && held.st_uid == me,
	    "  made 0600 and the caller's");

	check(!ncfg_caller_file_create(path, me, group, "x", 1u, err, sizeof(err)) &&
	        strstr(err, "already there") != NULL && contents_are(path, "{}\n"),
	    "a file already there is refused and left as it was");

	(void)snprintf(target, sizeof(target), "%s/elsewhere", own);
	(void)snprintf(link, sizeof(link), "%s/link.json", own);
	(void)symlink(target, link);
	check(!ncfg_caller_file_create(link, me, group, "x", 1u, err, sizeof(err)) &&
	        access(target, F_OK) != 0,
	    "a symlink in the file's place is refused, and nothing is written through it");

	(void)snprintf(path, sizeof(path), "%s/status.json", own);
	check(!ncfg_caller_file_create(path + 1, me, group, "x", 1u, err, sizeof(err)) &&
	        strstr(err, "absolute") != NULL,
	    "a relative path is refused");
	check(!ncfg_caller_file_create(own, me, group, "x", 1u, err, sizeof(err)) &&
	        stat(own, &held) == 0 && S_ISDIR(held.st_mode),
	    "a path naming an existing directory is refused, the directory untouched");
	(void)snprintf(path, sizeof(path), "%s/", own);
	check(!ncfg_caller_file_create(path, me, group, "x", 1u, err, sizeof(err)),
	    "a path ending in a slash names no file and is refused");

	(void)snprintf(path, sizeof(path), "%s/status.json", own);
	(void)unlink(path);
	check(!ncfg_caller_file_create(path, me + 1u, group, "x", 1u, err, sizeof(err)) &&
	        strstr(err, "not the caller's") != NULL && access(path, F_OK) != 0,
	    "a directory owned by somebody other than the caller is refused");

	(void)snprintf(path, sizeof(path), "%s/status.json", shared);
	check(!ncfg_caller_file_create(path, me, group, "x", 1u, err, sizeof(err)) &&
	        strstr(err, "writable by others") != NULL && access(path, F_OK) != 0,
	    "a directory others may write in is refused, though the caller owns it");

	check(!ncfg_caller_file_create("/netcfgd-caller-file-test", me, group, "x", 1u, err,
	          sizeof(err)) || me == 0,
	    "the root directory is not a non-root caller's to be written into");

	(void)snprintf(path, sizeof(path), "%s/missing/status.json", own);
	check(!ncfg_caller_file_create(path, me, group, "x", 1u, err, sizeof(err)),
	    "a directory that is not there is refused, not made");

	(void)unlink(link);
	testdir_remove(base);
	if (failures) {
		printf("\ncaller_file_test: %d check(s) FAILED\n", failures);
		return 1;
	}
	printf("\ncaller_file_test: all checks passed\n");
	return 0;
}
