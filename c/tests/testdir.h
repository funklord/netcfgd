/*
 * testdir.h -- a directory of a test's own, and nothing outside it.
 *
 * WHY THIS EXISTS AT ALL
 *   The daemon these tests are a port of runs on the machine they are built
 *   on, with that machine's real configuration in `/etc/netcfgd` and its real
 *   credentials in `/etc/netcfgd/secrets`. **A test that took a default path
 *   would be editing the developer's network.** So every test that touches a
 *   filesystem takes one of these and passes its path in explicitly; nothing
 *   here ever falls back to a default, and `ncfg_state_resolve_dir`'s default
 *   is asserted by reading the constant rather than by letting anything write
 *   there.
 *
 *   The Rust has `netcfgd_testdir::TestDir` for the same reason, and its
 *   comment carries the rule this copies: **the process id alone is not
 *   enough, tests in one binary share it.** `mkdtemp` answers that by asking
 *   the kernel for a name nobody else holds.
 *
 * WHAT IT REMOVES
 *   Everything under the directory it made, and it is allowed to do that by a
 *   pattern because the *directory* is one this process created: `mkdtemp`
 *   under `TMPDIR`, the path recorded, and the removal refuses to start unless
 *   the path it was handed is the one that was made. That is the test
 *   `~/.claude/guidelines` sets for a wildcard removal -- vouch for the
 *   directory when you cannot vouch for the names -- and the names here are
 *   genuinely not knowable: a projection is named after an interface and a
 *   staging file after a pid.
 */
#ifndef NCFG_TESTDIR_H
#define NCFG_TESTDIR_H

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* The one directory this binary made, so that the removal can refuse anything
 * else. Filled by `testdir_make` and never written again. */
static char testdir_path[256];

/*
 * Make it, or leave with a sentence.
 *
 * Failing to make one is not a test failure to be counted and carried past: a
 * suite that carried on would run every following case against whatever the
 * empty path happens to mean, which is the working directory.
 */
static inline const char *testdir_make(const char *what)
{
	const char *base = getenv("TMPDIR");

	if (!base || base[0] != '/') {
		base = "/tmp";
	}
	(void)snprintf(testdir_path, sizeof(testdir_path), "%s/netcfgd-c-%s-XXXXXX", base, what);
	if (!mkdtemp(testdir_path)) {
		printf("could not make a directory to work in under %s\n", base);
		exit(1);
	}
	return testdir_path;
}

/* `<testdir>/<leaf>` in the caller's buffer, which it may then join to again. */
static inline const char *testdir_in(const char *base, const char *leaf, char *out, size_t out_size)
{
	(void)snprintf(out, out_size, "%s/%s", base, leaf);
	return out;
}

static inline int testdir_exists(const char *path)
{
	struct stat about;

	return stat(path, &about) == 0;
}

/* The permission bits, or -1 where it is not there. */
static inline int testdir_mode(const char *path)
{
	struct stat about;

	if (stat(path, &about) != 0) {
		return -1;
	}
	return (int)(about.st_mode & (mode_t)0777);
}

/* The whole file, NUL-terminated, or NULL. The caller frees it. */
static inline char *testdir_read(const char *path, size_t *length_out)
{
	FILE *file = fopen(path, "rb");
	char *body;
	long length;
	size_t got;

	if (length_out) {
		*length_out = 0;
	}
	if (!file) {
		return NULL;
	}
	if (fseek(file, 0, SEEK_END) != 0 || (length = ftell(file)) < 0) {
		(void)fclose(file);
		return NULL;
	}
	rewind(file);
	body = malloc((size_t)length + 1u);
	if (!body) {
		(void)fclose(file);
		return NULL;
	}
	got = fread(body, 1u, (size_t)length, file);
	body[got] = '\0';
	if (length_out) {
		*length_out = got;
	}
	(void)fclose(file);
	return body;
}

/* Write one, for a fixture. Returns 1. */
static inline int testdir_write(const char *path, const char *bytes, size_t length)
{
	FILE *file = fopen(path, "wb");
	size_t put;

	if (!file) {
		return 0;
	}
	put = length ? fwrite(bytes, 1u, length, file) : 0u;
	return fclose(file) == 0 && put == length;
}

/*
 * One level, recursively, with a depth bound.
 *
 * **This was three levels of hand-unrolled loops and a fixture four deep
 * defeated it.** `cli_reset_test` builds `etc/profile/office/10-office.conf`;
 * the innermost loop unlinked files three levels down, so the file at the
 * fourth survived, so `office` could not be removed, so nothing above it
 * could either. Every run left its whole tree behind -- one hundred and
 * seventy of them accumulated in `/tmp` over a single day's work before
 * anybody counted.
 *
 * The depth bound is what makes recursion here defensible rather than a
 * second way to lose a filesystem: a directory tree arriving from a symlink
 * loop or a fixture nobody meant to nest has an end. `NCFG_TESTDIR_MAX_DEPTH`
 * is far deeper than any fixture and far shallower than anything that could
 * run away, and reaching it says so rather than passing over it, because a
 * remover that quietly gave up is exactly what produced the pile above.
 *
 * `lstat`, not `stat`: a symlink is unlinked as a symlink. Following one is
 * how a remover bounded to its own directory reaches outside it.
 */
#define NCFG_TESTDIR_MAX_DEPTH 16

static inline void testdir_remove_within(const char *path, int depth)
{
	DIR *open_dir;
	const struct dirent *found;

	if (depth > NCFG_TESTDIR_MAX_DEPTH) {
		printf("refusing to go deeper than %d levels under `%s`; something is "
		    "wrong with the fixture\n", NCFG_TESTDIR_MAX_DEPTH, testdir_path);
		return;
	}
	open_dir = opendir(path);
	if (!open_dir) {
		return;
	}
	while ((found = readdir(open_dir)) != NULL) {
		char child[1024];
		struct stat about;

		if (strcmp(found->d_name, ".") == 0 || strcmp(found->d_name, "..") == 0) {
			continue;
		}
		if ((size_t)snprintf(child, sizeof(child), "%s/%s", path, found->d_name) >=
		    sizeof(child)) {
			printf("refusing to remove a path longer than %zu bytes under `%s`\n",
			    sizeof(child), testdir_path);
			continue;
		}
		if (lstat(child, &about) == 0 && S_ISDIR(about.st_mode)) {
			testdir_remove_within(child, depth + 1);
			(void)rmdir(child);
			continue;
		}
		(void)unlink(child);
	}
	(void)closedir(open_dir);
}

/*
 * Refuses anything that is not the directory this binary made, which is the
 * guard that makes the recursion defensible: an unset or mistyped path here
 * would otherwise be the classic way a clean step eats something it should
 * not.
 */
static inline void testdir_remove(const char *path)
{
	if (!path || !path[0] || !testdir_path[0] || strcmp(path, testdir_path) != 0) {
		printf("refusing to remove `%s`, which is not the directory this test made\n",
		    path ? path : "");
		return;
	}
	testdir_remove_within(path, 0);
	(void)rmdir(path);
}

#endif /* NCFG_TESTDIR_H */
