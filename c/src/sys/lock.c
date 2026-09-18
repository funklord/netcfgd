/*
 * lock.c -- `flock`, a deadline, and the directory the lock file sits in.
 *
 * The whole of the argument for `flock` over the alternatives is in lock.h.
 * What is here is the three things it needs: the parent directory, the open,
 * and the wait.
 */
#include "ncfg/lock.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/* How long to wait between attempts while a deadline is running. Short enough
 * that a lock released early is taken promptly, long enough that waiting costs
 * nothing measurable. */
#define LOCK_RETRY_MS 20L

/* Room for the parent of a lock path. */
#define LOCK_PATH_MAX 4096u

static long now_ms(void)
{
	struct timespec at;

	/* Monotonic, because a deadline measured against the wall clock is a
	 * deadline that moves when something sets the time -- which on a machine
	 * netcfgd is configuring is precisely what happens when the network
	 * comes up and NTP steps the clock. */
	if (clock_gettime(CLOCK_MONOTONIC, &at) != 0) {
		return 0;
	}
	return (long)at.tv_sec * 1000L + at.tv_nsec / 1000000L;
}

static void wait_ms(long milliseconds)
{
	struct timespec wanted;

	wanted.tv_sec = milliseconds / 1000L;
	wanted.tv_nsec = (milliseconds % 1000L) * 1000000L;
	(void)nanosleep(&wanted, NULL);
}

/*
 * Make the directories a lock path needs, as `mkdir -p` would.
 *
 * Each component is created and an existing one is not an error. Nothing here
 * removes anything: a directory that is in the way and is not a directory is
 * reported by the open that follows, which names the path.
 */
static int make_parents(const char *path, char *err, size_t err_size)
{
	char   work[LOCK_PATH_MAX];
	size_t length = strlen(path);
	size_t at;

	if (length >= sizeof(work)) {
		ncfg_error_set(err, err_size, "%s is too long a path for a lock", path);
		return 0;
	}
	memcpy(work, path, length + 1u);
	/* From 1, so a leading `/` is never treated as a component to create. */
	for (at = 1; at < length; at++) {
		if (work[at] != '/') {
			continue;
		}
		work[at] = '\0';
		if (mkdir(work, 0755) != 0 && errno != EEXIST) {
			ncfg_error_set(err, err_size, "cannot make %s: %s", work,
			    strerror(errno));
			return 0;
		}
		work[at] = '/';
	}
	return 1;
}

void ncfg_lock_init(ncfg_lock_t *lock)
{
	if (!lock) {
		return;
	}
	lock->fd = -1;
}

/* Open the file the lock is taken on. */
static int lock_open(const char *path, char *err, size_t err_size)
{
	int opened;

	if (!make_parents(path, err, err_size)) {
		return -1;
	}
	/* Write, create, and **not** truncate: the contents are not the point
	 * and another holder's descriptor is watching this same file. Opened
	 * for writing because a lock is a claim to change something. */
	opened = open(path, O_WRONLY | O_CREAT | O_CLOEXEC, 0644);
	if (opened < 0) {
		ncfg_error_set(err, err_size, "cannot open %s: %s", path, strerror(errno));
		return -1;
	}
	return opened;
}

int ncfg_lock_take(ncfg_lock_t *lock, const char *path, char *err, size_t err_size)
{
	int opened;

	if (!lock || !path) {
		ncfg_error_set(err, err_size, "taking a lock needs a path");
		return 0;
	}
	ncfg_lock_init(lock);
	opened = lock_open(path, err, err_size);
	if (opened < 0) {
		return 0;
	}
	while (flock(opened, LOCK_EX) != 0) {
		/* A signal arriving while blocked is not a lock somebody else
		 * holds. Asking again is what the caller wanted; reporting it
		 * would turn a `SIGCHLD` -- which netcfgd generates itself,
		 * every time it spawns a hook -- into a failed apply. */
		if (errno == EINTR) {
			continue;
		}
		ncfg_error_set(err, err_size, "cannot lock %s: %s", path, strerror(errno));
		(void)close(opened);
		return 0;
	}
	lock->fd = opened;
	return 1;
}

int ncfg_lock_take_within(ncfg_lock_t *lock, const char *path, long patience_ms, int *held,
    char *err, size_t err_size)
{
	long deadline;
	int  opened;

	if (held) {
		*held = 0;
	}
	if (!lock || !path) {
		ncfg_error_set(err, err_size, "taking a lock needs a path");
		return 0;
	}
	ncfg_lock_init(lock);
	opened = lock_open(path, err, err_size);
	if (opened < 0) {
		return 0;
	}
	deadline = now_ms() + (patience_ms > 0 ? patience_ms : 0);
	for (;;) {
		if (flock(opened, LOCK_EX | LOCK_NB) == 0) {
			lock->fd = opened;
			return 1;
		}
		if (errno != EWOULDBLOCK && errno != EINTR) {
			ncfg_error_set(err, err_size, "cannot lock %s: %s", path,
			    strerror(errno));
			(void)close(opened);
			return 0;
		}
		if (now_ms() >= deadline) {
			if (held) {
				*held = 1;
			}
			if (patience_ms >= 1000L) {
				ncfg_error_set(err, err_size,
				    "%s is held by another apply, which has not finished in %ld seconds",
				    path, patience_ms / 1000L);
			} else {
				ncfg_error_set(err, err_size,
				    "%s is held by another apply, which has not finished in %ld milliseconds",
				    path, patience_ms);
			}
			(void)close(opened);
			return 0;
		}
		wait_ms(LOCK_RETRY_MS);
	}
}

void ncfg_lock_release(ncfg_lock_t *lock)
{
	if (!lock || lock->fd < 0) {
		return;
	}
	/* `LOCK_UN` rather than leaving it to the close on the next line. Both
	 * release it, and a failure here is not actionable and is not reported:
	 * the close releases the lock regardless. */
	(void)flock(lock->fd, LOCK_UN);
	(void)close(lock->fd);
	lock->fd = -1;
}
