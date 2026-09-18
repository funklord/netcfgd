/*
 * watch.c -- which mechanism answers "did the configuration change?", and the
 * fingerprint the slow one compares.
 *
 * No syscall that is not a `stat` or a `readdir` is made here: the descriptor
 * and the events are next door in inotify.c, and this file chooses between them
 * and the fallback. watch.h has the argument for there being a fallback at all.
 */
#include "ncfg/watch.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

const char *ncfg_watch_mechanism_name(ncfg_watch_mechanism_t mechanism)
{
	switch (mechanism) {
	case NCFG_WATCH_INOTIFY:
		return "inotify";
	case NCFG_WATCH_POLLING:
		return "mtime polling";
	}
	return "unknown";
}

ncfg_watch_mechanism_t ncfg_watch_mechanism(const ncfg_watch_t *watch)
{
	return watch ? watch->mechanism : NCFG_WATCH_POLLING;
}

static void marks_free(ncfg_watch_marks_t *marks)
{
	size_t at;

	if (!marks) {
		return;
	}
	for (at = 0; at < marks->count; at++) {
		free(marks->items[at].path);
	}
	free(marks->items);
	marks->items = NULL;
	marks->count = 0;
	marks->capacity = 0;
}

/* One path and its mtime, or that it is not there. Absence is a mark rather
 * than a missing entry: see watch.h. */
static int mark_add(ncfg_watch_marks_t *marks, const char *path)
{
	struct stat found;
	char       *copy;

	if (marks->count == marks->capacity) {
		size_t             wanted = marks->capacity ? marks->capacity * 2u : 16u;
		ncfg_watch_mark_t *grown = realloc(marks->items, wanted * sizeof(*grown));

		if (!grown) {
			return 0;
		}
		marks->items = grown;
		marks->capacity = wanted;
	}
	copy = strdup(path);
	if (!copy) {
		return 0;
	}
	memset(&marks->items[marks->count], 0, sizeof(marks->items[0]));
	marks->items[marks->count].path = copy;
	if (stat(path, &found) == 0) {
		marks->items[marks->count].has_mtime = 1;
		marks->items[marks->count].seconds = (int64_t)found.st_mtime;
		marks->items[marks->count].nanoseconds = found.st_mtim.tv_nsec;
	}
	marks->count++;
	return 1;
}

static int compare_marks(const void *left, const void *right)
{
	const ncfg_watch_mark_t *one = (const ncfg_watch_mark_t *)left;
	const ncfg_watch_mark_t *two = (const ncfg_watch_mark_t *)right;

	return strcmp(one->path, two->path);
}

/*
 * Every watched path and everything directly beneath it, with its mtime.
 *
 * **Into a fingerprint of its own**, never into the watcher's: the one being
 * compared against has to survive being compared, and a version of this that
 * cleared the watcher first reported a change on every tick -- which is how it
 * was found.
 *
 * The children are sorted, or the fingerprint would differ run to run on
 * directory order alone -- which is the filesystem's and is not stable -- and
 * every tick would look like a change for a second reason.
 *
 * Everything beneath, not only what looks like configuration: a drop-in renamed
 * from `netcfgd.conf.new` into place is a change, and a fingerprint that only
 * counted the final name would see the rename and nothing before it. The Rust's
 * doc comment says `.conf` and its code does the same as this; the code is what
 * the behaviour was measured against.
 */
static int fingerprint(const ncfg_watch_t *watch, ncfg_watch_marks_t *out)
{
	size_t at;

	memset(out, 0, sizeof(*out));
	for (at = 0; at < watch->path_count; at++) {
		DIR           *directory;
		struct dirent *entry;
		char           child[4096];
		size_t         first;

		if (!mark_add(out, watch->paths[at])) {
			marks_free(out);
			return 0;
		}
		directory = opendir(watch->paths[at]);
		if (!directory) {
			/* A directory that is not there yet is a mark of its
			 * own, above, and its appearance is a change. */
			continue;
		}
		first = out->count;
		while ((entry = readdir(directory)) != NULL) {
			int written;

			if (strcmp(entry->d_name, ".") == 0 ||
			    strcmp(entry->d_name, "..") == 0) {
				continue;
			}
			written = snprintf(child, sizeof(child), "%s/%s", watch->paths[at],
			    entry->d_name);
			if (written < 0 || (size_t)written >= sizeof(child)) {
				continue;
			}
			if (!mark_add(out, child)) {
				(void)closedir(directory);
				marks_free(out);
				return 0;
			}
		}
		(void)closedir(directory);
		if (out->count - first > 1u) {
			qsort(&out->items[first], out->count - first,
			    sizeof(out->items[0]), compare_marks);
		}
	}
	return 1;
}

static int same_fingerprint(const ncfg_watch_marks_t *one, const ncfg_watch_marks_t *two)
{
	size_t at;

	if (one->count != two->count) {
		return 0;
	}
	for (at = 0; at < one->count; at++) {
		if (strcmp(one->items[at].path, two->items[at].path) != 0) {
			return 0;
		}
		if (one->items[at].has_mtime != two->items[at].has_mtime) {
			return 0;
		}
		/* Nanoseconds as well as seconds: two writes in one second is
		 * an editor saving twice, and a watcher that could not tell them
		 * apart would miss the second. */
		if (one->items[at].has_mtime &&
		    (one->items[at].seconds != two->items[at].seconds ||
		    one->items[at].nanoseconds != two->items[at].nanoseconds)) {
			return 0;
		}
	}
	return 1;
}

static int paths_copy(ncfg_watch_t *watch, const char *const *paths, size_t count,
    char *err, size_t err_size)
{
	size_t at;

	if (count == 0) {
		return 1;
	}
	watch->paths = calloc(count, sizeof(*watch->paths));
	if (!watch->paths) {
		ncfg_error_set(err, err_size, "out of memory watching for changes");
		return 0;
	}
	for (at = 0; at < count; at++) {
		if (!paths[at]) {
			ncfg_error_set(err, err_size, "a directory to watch cannot be nothing");
			return 0;
		}
		watch->paths[at] = strdup(paths[at]);
		if (!watch->paths[at]) {
			ncfg_error_set(err, err_size, "out of memory watching for changes");
			return 0;
		}
		watch->path_count++;
	}
	return 1;
}

/*
 * Replace the fingerprint with a fresh one, and say nothing about whether it
 * differed.
 *
 * Used both for the first one -- which is what every later one is compared
 * against -- and for the inotify path, which keeps it current without ever
 * comparing it.
 */
static int refresh(ncfg_watch_t *watch, char *err, size_t err_size)
{
	ncfg_watch_marks_t taken;

	if (!fingerprint(watch, &taken)) {
		ncfg_error_set(err, err_size, "out of memory watching for changes");
		return 0;
	}
	marks_free(&watch->marks);
	watch->marks = taken;
	return 1;
}

int ncfg_watch_open_polling(ncfg_watch_t *watch, const char *const *paths, size_t count,
    char *err, size_t err_size)
{
	if (!watch || (count > 0 && !paths)) {
		ncfg_error_set(err, err_size, "watching needs somewhere to keep the watch");
		return 0;
	}
	memset(watch, 0, sizeof(*watch));
	ncfg_inotify_init(&watch->inotify);
	watch->mechanism = NCFG_WATCH_POLLING;
	if (!paths_copy(watch, paths, count, err, err_size)) {
		ncfg_watch_close(watch);
		return 0;
	}
	if (!refresh(watch, err, err_size)) {
		ncfg_watch_close(watch);
		return 0;
	}
	return 1;
}

int ncfg_watch_open(ncfg_watch_t *watch, const char *const *paths, size_t count,
    char *err, size_t err_size)
{
	size_t at;
	size_t watched = 0;

	if (!ncfg_watch_open_polling(watch, paths, count, err, err_size)) {
		return 0;
	}
	/* The descriptor is asked for after the paths are in place, so that a
	 * kernel that refuses one leaves a watcher that is already usable. */
	if (!ncfg_inotify_open(&watch->inotify, NULL, 0)) {
		return 1;
	}
	for (at = 0; at < watch->path_count; at++) {
		if (ncfg_inotify_watch(&watch->inotify, watch->paths[at],
		    NCFG_WATCH_CONFIG_MASK, NULL, NULL, 0)) {
			watched++;
		}
	}
	if (watched == 0) {
		/* A descriptor with no successful watch is worse than none: it
		 * would block for ever reporting nothing. */
		ncfg_inotify_close(&watch->inotify);
		return 1;
	}
	watch->mechanism = NCFG_WATCH_INOTIFY;
	return 1;
}

void ncfg_watch_close(ncfg_watch_t *watch)
{
	size_t at;

	if (!watch) {
		return;
	}
	ncfg_inotify_close(&watch->inotify);
	for (at = 0; at < watch->path_count; at++) {
		free(watch->paths[at]);
	}
	free(watch->paths);
	watch->paths = NULL;
	watch->path_count = 0;
	marks_free(&watch->marks);
	watch->mechanism = NCFG_WATCH_POLLING;
}

int ncfg_watch_wait(ncfg_watch_t *watch, int timeout_ms, int *changed, char *err,
    size_t err_size)
{
	ncfg_watch_marks_t taken;

	if (changed) {
		*changed = 0;
	}
	if (!watch || !changed) {
		ncfg_error_set(err, err_size, "waiting for a change needs somewhere to say so");
		return 0;
	}
	if (watch->mechanism == NCFG_WATCH_INOTIFY) {
		ncfg_inotify_batch_t batch;

		if (!ncfg_inotify_wait(&watch->inotify, timeout_ms, &batch, err, err_size)) {
			return 0;
		}
		if (batch.length == 0) {
			return 1;
		}
		/* The events are not read apart: like a netlink multicast
		 * message, one means "something moved, look again". The caller
		 * re-reads and recompiles, so a missed detail costs nothing and
		 * a missed event is what matters.
		 *
		 * The fingerprint is kept current here so that a later fall back
		 * to polling does not immediately report a change that was
		 * already handled. */
		if (!refresh(watch, err, err_size)) {
			return 0;
		}
		*changed = 1;
		return 1;
	}

	{
		struct timespec wanted;
		long            milliseconds = timeout_ms > 0 ? (long)timeout_ms : 0;

		wanted.tv_sec = milliseconds / 1000L;
		wanted.tv_nsec = (milliseconds % 1000L) * 1000000L;
		(void)nanosleep(&wanted, NULL);
	}
	if (!fingerprint(watch, &taken)) {
		ncfg_error_set(err, err_size, "out of memory watching for changes");
		return 0;
	}
	if (same_fingerprint(&watch->marks, &taken)) {
		marks_free(&taken);
		return 1;
	}
	marks_free(&watch->marks);
	watch->marks = taken;
	*changed = 1;
	return 1;
}
