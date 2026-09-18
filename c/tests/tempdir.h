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

#endif /* NCFG_TESTS_TEMPDIR_H */
