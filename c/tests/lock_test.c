/*
 * lock_test.c -- the lock is mutual, and it gives up when it said it would.
 *
 * WHY THE PROPERTY IS WORTH A TEST AT ALL
 *   The one this module rests on is not the one POSIX record locks have:
 *   `fcntl` locks are owned by the *process*, so a second attempt from the same
 *   one is handed the lock immediately and the guard guards nothing. `flock` is
 *   owned by the open file description, so two `open` calls conflict whether or
 *   not they are in the same process -- which is what makes a second descriptor
 *   here meaningful evidence about two daemons. Swapping the implementation for
 *   `fcntl` would pass every other check in this file and fail this one.
 *
 * WHAT IS LOCKED, AND WHAT IS NOT
 *   Everything below happens under a directory this test makes and removes.
 *   Nothing here touches netcfgd's own lock: this suite runs on the machine
 *   netcfgd is configuring, and taking the real lock would stall a real apply.
 *
 * WHY EVERY WAIT HAS A CEILING
 *   A test of a blocking lock that gets the wait wrong does not fail, it hangs
 *   -- and a hung test in a suite reports nothing at all. So the only blocking
 *   call made here is made when the lock is known to be free, and every wait
 *   that could block is a deadline measured in tens of milliseconds.
 */
#include "ncfg/base.h"
#include "ncfg/lock.h"

#include "tempdir.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static int failures;

static void check(int condition, const char *what)
{
	printf("%-58s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

static long now_ms(void)
{
	struct timespec at;

	if (clock_gettime(CLOCK_MONOTONIC, &at) != 0) {
		return 0;
	}
	return (long)at.tv_sec * 1000L + at.tv_nsec / 1000000L;
}

int main(void)
{
	char        root[256];
	char        path[400];
	char        nested[400];
	ncfg_lock_t lock;
	int         second;

	if (!tempdir_make("lock", root, sizeof(root))) {
		printf("lock_test: could not make a temporary directory\n");
		return 1;
	}
	(void)snprintf(path, sizeof(path), "%s/owned.lock", root);
	(void)snprintf(nested, sizeof(nested), "%s/run/netcfgd/made.lock", root);

	/* The lock is mutual between two descriptors of one file. */
	{
		ncfg_lock_init(&lock);
		check(ncfg_lock_take(&lock, path, NULL, 0), "the first lock is taken");
		check(lock.fd >= 0, "and it holds a descriptor, which is what the lock is");

		/* Non-blocking, because the point is that it is *not* available.
		 * The blocking call is what the daemon makes and is not what a
		 * test can assert on without a deadline. */
		second = open(path, O_WRONLY | O_CREAT | O_CLOEXEC, 0644);
		check(second >= 0, "a second descriptor on the same file is opened");
		errno = 0;
		check(flock(second, LOCK_EX | LOCK_NB) == -1,
		    "a second exclusive lock must not be granted");
		check(errno == EWOULDBLOCK, "and it is refused for being held, not for a mistake");

		ncfg_lock_release(&lock);
		check(lock.fd < 0, "releasing leaves nothing held");
		check(flock(second, LOCK_EX | LOCK_NB) == 0,
		    "and the lock is free once it has been released");
		check(flock(second, LOCK_UN) == 0, "the second descriptor gives it back");
		(void)close(second);

		/* Releasing twice is nothing, which is what makes a failure path
		 * cheap. */
		ncfg_lock_release(&lock);
		ncfg_lock_release(NULL);
	}

	/* The file's contents are never the point: nothing is written to it and
	 * an existing one is not truncated. */
	{
		struct stat found;
		int         wrote = open(path, O_WRONLY | O_CLOEXEC);

		if (wrote >= 0) {
			check(write(wrote, "held by nobody\n", 15u) == 15,
			    "something is written into the lock file");
			(void)close(wrote);
		}
		ncfg_lock_init(&lock);
		check(ncfg_lock_take(&lock, path, NULL, 0), "the lock is taken over it");
		check(stat(path, &found) == 0 && found.st_size == 15,
		    "and what was in the file is still there, because a lock is a name");
		ncfg_lock_release(&lock);
	}

	/* A deadline that runs out, which is the shape an apply needs: a hook is
	 * an operator's shell script, and waiting for ever on one turns a stuck
	 * apply into a daemon that never reconciles again. */
	{
		char err[NCFG_ERROR_MAX];
		int  held = 0;
		long started;
		long took;

		second = open(path, O_WRONLY | O_CREAT | O_CLOEXEC, 0644);
		check(second >= 0 && flock(second, LOCK_EX | LOCK_NB) == 0,
		    "somebody else takes the lock");

		ncfg_lock_init(&lock);
		err[0] = '\0';
		started = now_ms();
		check(!ncfg_lock_take_within(&lock, path, 120L, &held, err, sizeof(err)),
		    "a lock held throughout is not taken");
		took = now_ms() - started;
		check(held == 1, "and the failure says it was somebody else holding it");
		check(strstr(err, path) != NULL && strstr(err, "another apply") != NULL,
		    "with a sentence naming the path and what it was waiting for");
		check(took >= 100L, "it waited for about as long as it was told to");
		check(took < 3000L, "and gave up rather than blocking");
		check(lock.fd < 0, "a refused wait leaves nothing held");

		/* And when the holder lets go, the same call succeeds. */
		check(flock(second, LOCK_UN) == 0, "the holder lets go");
		(void)close(second);
		check(ncfg_lock_take_within(&lock, path, 120L, &held, NULL, 0),
		    "and the lock is then taken within its patience");
		check(held == 0, "with nothing reported as held");
		ncfg_lock_release(&lock);
	}

	/* The directory a lock path names is made, because the lock lives under
	 * `/run` and a machine that has just booted may not have it yet. */
	{
		struct stat found;

		ncfg_lock_init(&lock);
		check(ncfg_lock_take(&lock, nested, NULL, 0),
		    "a lock two directories down is taken");
		check(stat(nested, &found) == 0, "and the file is where it was asked for");
		ncfg_lock_release(&lock);
	}

	/* What cannot be opened is a refusal with a sentence, and it is told
	 * apart from the lock being held. */
	{
		char err[NCFG_ERROR_MAX];
		int  held = 1;
		char impossible[460];

		/* A path whose parent is a file rather than a directory: the
		 * `mkdir` fails with `ENOTDIR`, which is a machine that needs
		 * looking at rather than a lock to wait for. */
		(void)snprintf(impossible, sizeof(impossible), "%s/in/a/file.lock", path);
		ncfg_lock_init(&lock);
		err[0] = '\0';
		check(!ncfg_lock_take_within(&lock, impossible, 10L, &held, err, sizeof(err)),
		    "a lock whose directory cannot be made is refused");
		check(held == 0, "and it is not reported as somebody else holding it");
		check(err[0] != '\0', "with a sentence saying what failed");
		check(lock.fd < 0, "and nothing is held");

		check(!ncfg_lock_take(&lock, NULL, NULL, 0), "a lock with no path is refused");
		check(!ncfg_lock_take_within(NULL, path, 10L, NULL, NULL, 0),
		    "as is one with nowhere to keep the descriptor");
	}

	/* Removed by name: the two files this test made, then the directories it
	 * made, innermost first. */
	if (unlink(path) != 0) {
		printf("lock_test: could not remove %s\n", path);
		failures++;
	}
	if (unlink(nested) != 0) {
		printf("lock_test: could not remove %s\n", nested);
		failures++;
	}
	{
		char directory[400];

		(void)snprintf(directory, sizeof(directory), "%s/run/netcfgd", root);
		if (rmdir(directory) != 0) {
			printf("lock_test: could not remove %s\n", directory);
			failures++;
		}
		(void)snprintf(directory, sizeof(directory), "%s/run", root);
		if (rmdir(directory) != 0) {
			printf("lock_test: could not remove %s\n", directory);
			failures++;
		}
	}
	if (rmdir(root) != 0) {
		printf("lock_test: could not remove %s\n", root);
		failures++;
	}

	if (failures == 0) {
		printf("lock_test: all checks passed\n");
	} else {
		printf("lock_test: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
