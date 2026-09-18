/*
 * watch.h -- noticing that the configuration directory changed.
 *
 * ONE HEADER, TWO SOURCES, AND WHY THAT IS ONE RESPONSIBILITY
 *   `inotify.c` holds the syscalls and the walk over what they return;
 *   `watch.c` chooses a mechanism and answers the one question above it. They
 *   share a header for netlink.h's reason: a caller does not get one without
 *   the other, and the two halves must not be able to touch each other's
 *   problem -- the descriptor is in one file and the bytes-to-events walk is in
 *   neither's way. The responsibility is "did the configuration change?", and
 *   it is one question however it is answered.
 *
 * INOTIFY WHERE IT WORKS, MTIME POLLING WHERE IT DOES NOT
 *   The fallback is not defensive programming for its own sake:
 *   `inotify_init1` fails with `EMFILE` when `fs.inotify.max_user_instances` is
 *   exhausted, which happens on real machines running enough watchers, and some
 *   container runtimes and hardened kernels restrict it outright. A config
 *   daemon that stops noticing config changes because a limit somewhere else
 *   was reached is a worse outcome than one that polls.
 *
 *   Both paths answer the same question and both answer it the way netlink
 *   does: by saying that something moved, not by saying what. The caller
 *   re-reads and recompiles, so a missed detail costs nothing and a missed
 *   *event* is what matters.
 *
 * THE WALK HAS THE SAME TWO OBLIGATIONS AS THE NETLINK ONES
 *   These are bytes the kernel wrote into a buffer, read by length fields the
 *   walk has to trust just far enough: it must terminate, and it must not read
 *   past the end. A `len` large enough to run past the buffer ends the walk
 *   rather than indexing out of it. That is why `ncfg_wire_step_t` is reused
 *   here rather than a second three-outcome enum being declared -- one boolean
 *   cannot tell "nothing more" from "malformed", and two spellings of one
 *   answer is how a caller comes to treat a truncated buffer as a finished one.
 *
 * THE NUMBERS ARE THE SYSTEM'S
 *   `IN_MODIFY` and its neighbours come from <sys/inotify.h>. The Rust spells
 *   them out because `libc` is not where it wanted them; a C port that copied
 *   them across would be inventing a second place for them to be wrong.
 */
#ifndef NCFG_WATCH_H
#define NCFG_WATCH_H

#include <stddef.h>
#include <stdint.h>

#include <sys/inotify.h>

#include "ncfg/base.h"
#include "ncfg/wire.h"

/* Length of `struct inotify_event` before its trailing name. Checked against
 * the system's own `sizeof` in inotify.c. */
#define NCFG_INOTIFY_EVENT_HDR_LEN 16u

/* `NAME_MAX` and its terminator: the longest name one event can carry. */
#define NCFG_INOTIFY_NAME_MAX 256u

/*
 * Everything that means "the config directory changed".
 *
 * `IN_MODIFY` is included as well as `IN_CLOSE_WRITE` because a writer that
 * keeps the file open -- `>>` from a script, say -- never produces a close, and
 * a config that changed without netcfgd noticing is the whole failure this
 * watch exists to prevent. `IN_MOVED_TO` is the other usual editor signal,
 * since a careful writer renames into place rather than truncating.
 */
#define NCFG_WATCH_CONFIG_MASK                                                 \
	((uint32_t)(IN_MODIFY | IN_CLOSE_WRITE | IN_MOVED_FROM | IN_MOVED_TO | \
	    IN_CREATE | IN_DELETE | IN_DELETE_SELF | IN_MOVE_SELF))

/* One event, as read from the descriptor. */
typedef struct {
	/* Which watch produced it. */
	int      wd;
	/* What happened. */
	uint32_t mask;
	/* The name within the watched directory, where there is one. */
	int      has_name;
	char     name[NCFG_INOTIFY_NAME_MAX];
} ncfg_inotify_event_t;

/*
 * Whether the kernel dropped events before this one.
 *
 * Handled the same way as netlink's `ENOBUFS`: it means "you missed something",
 * which for a watcher that re-reads everything is indistinguishable from an
 * ordinary change.
 */
int ncfg_inotify_event_overflowed(const ncfg_inotify_event_t *event);

/* An inotify descriptor. Treat the field as private; `fd` is -1 when nothing is
 * open. */
typedef struct {
	int fd;
} ncfg_inotify_t;

/*
 * What one read returned.
 *
 * A fixed buffer rather than an allocation, because its size is the kernel's
 * and not a caller's: one read returns whole events and never part of one, so
 * anything that fits is complete and anything that does not is left queued for
 * the next read.
 */
#define NCFG_INOTIFY_BATCH 8192u
typedef struct {
	uint8_t bytes[NCFG_INOTIFY_BATCH];
	size_t  length;
} ncfg_inotify_batch_t;

/* A walk over the events in one batch. Start it with `ncfg_inotify_walk_start`
 * and treat the fields as private. */
typedef struct {
	const uint8_t *rest;
	size_t         remaining;
} ncfg_inotify_walk_t;

void ncfg_inotify_walk_start(ncfg_inotify_walk_t *walk, const void *bytes, size_t length);

/*
 * The next event, the end of the buffer, or a refusal.
 *
 * `NCFG_WIRE_BAD` for a length that would run past the end -- and the walk is
 * left exhausted, so a loop that ignores it still terminates.
 */
ncfg_wire_step_t ncfg_inotify_walk_next(ncfg_inotify_walk_t *walk, ncfg_inotify_event_t *out,
    char *err, size_t err_size);

/* Leave a descriptor closed and unopened. */
void ncfg_inotify_init(ncfg_inotify_t *inotify);

/*
 * Open a descriptor.
 *
 * `EMFILE` here means the system's `fs.inotify.max_user_instances` is
 * exhausted, which is a real and ordinary condition on a busy machine -- the
 * caller is expected to fall back rather than fail, which is what
 * `ncfg_watch_open` does.
 */
int ncfg_inotify_open(ncfg_inotify_t *inotify, char *err, size_t err_size);

/* Close it. Nothing where it was never opened. */
void ncfg_inotify_close(ncfg_inotify_t *inotify);

/*
 * Watch a directory, and hand back the watch descriptor.
 *
 * A path that does not exist is a refusal and not a fatal one: a config
 * directory may be created later, which is what the polling path covers.
 */
int ncfg_inotify_watch(const ncfg_inotify_t *inotify, const char *path, uint32_t mask,
    int *wd, char *err, size_t err_size);

/*
 * Wait up to `timeout_ms` for events, and read whatever arrived.
 *
 * An empty batch means the wait timed out, which a caller can use as its own
 * tick. A signal during the wait is a timeout too rather than a failure: it is
 * not a failure to watch, and netcfgd generates signals of its own every time
 * it spawns a hook.
 */
int ncfg_inotify_wait(const ncfg_inotify_t *inotify, int timeout_ms,
    ncfg_inotify_batch_t *out, char *err, size_t err_size);

/* ------------------------------------------------------------------------ */
/* The watcher.                                                             */
/* ------------------------------------------------------------------------ */

/* Which mechanism a watcher ended up with. */
typedef enum {
	/* The kernel tells us. */
	NCFG_WATCH_INOTIFY = 0,
	/* We ask, repeatedly. */
	NCFG_WATCH_POLLING = 1
} ncfg_watch_mechanism_t;

/* A name for logs and for `ncfg status`, because an operator debugging a reload
 * that did not happen needs to know which one is in play. */
const char *ncfg_watch_mechanism_name(ncfg_watch_mechanism_t mechanism);

/*
 * One path and when it last changed, or that it is not there.
 *
 * A file that does not exist contributes "absent" rather than being left out,
 * so that its appearance and its disappearance both change the fingerprint.
 * Omitting it would make a deleted drop-in invisible.
 */
typedef struct {
	char    *path;
	int      has_mtime;
	int64_t  seconds;
	long     nanoseconds;
} ncfg_watch_mark_t;

/* A whole fingerprint: one mark per watched path and per entry beneath it. */
typedef struct {
	ncfg_watch_mark_t *items;
	size_t             count;
	size_t             capacity;
} ncfg_watch_marks_t;

/* Watches a set of directories for any change. Treat the fields as private. */
typedef struct {
	ncfg_inotify_t         inotify;
	char                 **paths;
	size_t                 path_count;
	ncfg_watch_marks_t     marks;
	ncfg_watch_mechanism_t mechanism;
} ncfg_watch_t;

/*
 * Watch these directories, preferring inotify.
 *
 * A directory that does not exist yet is still watched, by the polling path,
 * and its appearance counts as a change -- which matters because `conf.d/` is
 * created the first time somebody writes a drop-in.
 *
 * **A descriptor with no successful watch is worse than none**: it would block
 * for ever reporting nothing. So inotify is kept only where at least one watch
 * was taken, and otherwise this falls back.
 */
int ncfg_watch_open(ncfg_watch_t *watch, const char *const *paths, size_t count,
    char *err, size_t err_size);

/*
 * Watch these directories without inotify.
 *
 * Public rather than test-only for two reasons: an operator debugging a reload
 * that is not happening wants to take inotify out of the picture, and a
 * fallback that only runs when something else has already gone wrong is a
 * fallback nobody has ever seen work. The checks use it to exercise both paths
 * against the same assertions.
 */
int ncfg_watch_open_polling(ncfg_watch_t *watch, const char *const *paths, size_t count,
    char *err, size_t err_size);

/* Release what it holds and close what it opened. Nothing where it was never
 * opened. */
void ncfg_watch_close(ncfg_watch_t *watch);

/* Which mechanism is in use. */
ncfg_watch_mechanism_t ncfg_watch_mechanism(const ncfg_watch_t *watch);

/*
 * Wait up to `timeout_ms` for a change.
 *
 * `*changed` is 0 on a timeout, so a caller can use this as its own tick. The
 * return value is the usual 1-or-0: a real failure.
 *
 * The fingerprint is kept current on the inotify path too, so that a later fall
 * back to polling does not immediately report a change that was already
 * handled.
 */
int ncfg_watch_wait(ncfg_watch_t *watch, int timeout_ms, int *changed,
    char *err, size_t err_size);

#endif /* NCFG_WATCH_H */
