/*
 * tempdir.h -- a directory a test makes for itself, wherever the system keeps
 * them.
 *
 * WHY THIS IS SHARED RATHER THAN COPIED
 *   Three checks below this line need a directory of their own -- the radio
 *   fixture, the watcher and the lock -- and each of them would otherwise
 *   hard-code `/tmp`. The Rust has `netcfgd_testdir` for the same reason and
 *   says it plainly: two copies of a rule is how two of them come to disagree
 *   about it. This is the same rule, one call, and it honours `TMPDIR` as the
 *   Rust's `std::env::temp_dir` does -- a machine that puts its temporary files
 *   somewhere else is a machine this suite should not be writing to `/tmp` on.
 *
 * WHY IT IS NOT A TEST BINARY OF ITS OWN
 *   The Makefile builds one binary per test source, so a helper has to be
 *   a header or it becomes a test binary with no `main`.
 *
 * WHAT IT DOES NOT DO
 *   It does not remove anything. A test that makes a directory removes what it
 *   made, by name, at the end -- which is what keeps a cleanup from turning
 *   into a pattern that could match something it did not create. The tag is for
 *   whoever finds one that survived a crash: it should say which test.
 *
 * AND WHAT `tempdir_gone` IS FOR
 *   That rule was stated here and obeyed nowhere it could be checked: every
 *   caller ended `(void)rmdir(dir)`, so a file the cleanup did not name made
 *   the `rmdir` fail and nothing said so. Measured 2026-10-10: 111 directories
 *   from `apply_test`, each holding one `bssid` marker, and 111 from
 *   `apply_kernel_test`, each holding a `run/wireguard` the fixture made the
 *   way a daemon would -- 222 in all, accumulated over two days of ordinary
 *   runs while the suite printed that everything passed.
 *
 *   So the removal returns its answer and a caller asserts on it. `rmdir` is
 *   the right instrument precisely because it refuses a directory with
 *   anything in it: the assertion then says "this test removed everything it
 *   made", which is the property the paragraph above claims, rather than "this
 *   test called rmdir".
 */
#ifndef NCFG_TESTS_TEMPDIR_H
#define NCFG_TESTS_TEMPDIR_H

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/*
 * Make one, and write its path into `out`. 1 on success.
 *
 * `mkdtemp` rather than a name built from the process id: two runs of one
 * binary can overlap on a build machine, and a directory a test found already
 * populated fails for a reason that has nothing to do with what it tests.
 */
static int tempdir_make(const char *tag, char *out, size_t out_size)
{
	const char *root = getenv("TMPDIR");
	int         written;

	if (!root || root[0] != '/') {
		root = "/tmp";
	}
	written = snprintf(out, out_size, "%s/ncfg-%s-XXXXXX", root, tag);
	if (written < 0 || (size_t)written >= out_size) {
		return 0;
	}
	return mkdtemp(out) != NULL;
}

/*
 * Remove one, and say whether it is gone. 1 when it is.
 *
 * A caller asserts on this, so a file it forgot to name fails the test that
 * left it rather than filling a filesystem nobody is watching.
 *
 * `static inline` rather than `static`, unlike `tempdir_make` above: this
 * header reaches every test binary and only three of them remove a directory,
 * so a plain `static` is an unused-function warning in all the rest.
 */
static inline int tempdir_gone(const char *dir)
{
	if (!dir || dir[0] == '\0') {
		return 0;
	}
	return rmdir(dir) == 0;
}

#endif /* NCFG_TESTS_TEMPDIR_H */
