/*
 * lock.h -- an exclusive advisory lock, held until it is released.
 *
 * WHY `flock` AND NOT A LOCK FILE CREATED WITH `O_EXCL`
 *   The lock has to survive whatever the holder does, including being killed:
 *   an `O_EXCL` file outlives the process that made it, so every user of one
 *   needs a staleness rule, and every staleness rule is a guess about how long
 *   the work takes. A `flock` is held by the open file description and the
 *   kernel drops it when the last descriptor closes, which a dying process does
 *   for free.
 *
 * WHY `flock` AND NOT `fcntl`
 *   POSIX record locks are owned by the *process*, so a second thread asking
 *   for one is handed it immediately and the guard guards nothing. `flock` is
 *   owned by the open file description, so two `open` calls conflict whether or
 *   not they are in the same process -- which is what makes a test in one
 *   process meaningful evidence about two daemons.
 *
 * WHAT IS LOCKED IS THE NAME
 *   The file's *contents* are not the point and are never read or written; what
 *   is being locked is the name, so that two processes agree on who is midway
 *   through a read-modify-write of something else. The file is opened for
 *   writing because a lock is a claim to change something -- a descriptor opened
 *   read-only can still take an exclusive lock, which would make the mode say
 *   the opposite of what the caller means.
 *
 * TWO WAITS, BECAUSE THEY GUARD DIFFERENT THINGS
 *   `ncfg_lock_take` blocks, which is the behaviour that makes it useful: the
 *   caller wants the update to happen, not to be told that somebody else is
 *   updating, and the critical sections it guards are a read, a serialisation
 *   and a rename -- microseconds.
 *
 *   **Blocking for ever is the wrong shape for an apply.** An apply can hold
 *   one for as long as a hook takes, and a hook is an operator's shell script.
 *   Waiting for ever on that turns one stuck apply into a daemon that never
 *   reconciles again. So `ncfg_lock_take_within` waits, and then says what it
 *   was waiting for.
 */
#ifndef NCFG_LOCK_H
#define NCFG_LOCK_H

#include <stddef.h>

#include "ncfg/base.h"

/*
 * A held lock. Treat the field as private; `fd` is -1 when nothing is held.
 *
 * The descriptor is the lock: closing it is what releases it, which is why this
 * is a value a caller keeps rather than a call that returns nothing.
 */
typedef struct {
	int fd;
} ncfg_lock_t;

/* Leave a lock unheld. `ncfg_lock_release` on one that has been through this is
 * nothing, which is what makes a failure path cheap. */
void ncfg_lock_init(ncfg_lock_t *lock);

/*
 * Take the exclusive lock, creating the file and its directory if they are not
 * there.
 *
 * **Blocks** until the lock is available. A caller that treats a failure as
 * "carry on without the lock" is choosing the old behaviour deliberately and
 * should say so where it does it.
 */
int ncfg_lock_take(ncfg_lock_t *lock, const char *path, char *err, size_t err_size);

/*
 * Take the exclusive lock, giving up after `patience_ms`.
 *
 * `*held` -- which may be NULL -- says which kind of failure it was: 1 where
 * somebody else had the lock throughout, and 0 where the file could not be
 * opened at all. That distinction is the Rust's `WouldBlock`, and it matters
 * because the two have different answers: one is worth trying again and the
 * other is a machine that needs looking at.
 */
int ncfg_lock_take_within(ncfg_lock_t *lock, const char *path, long patience_ms, int *held,
    char *err, size_t err_size);

/*
 * Release it.
 *
 * Unlocks explicitly before closing. Both release it, and the explicit call is
 * what makes the release visible at the point it happens -- a reader should not
 * have to know that the close is what unlocks this. Nothing where no lock is
 * held.
 */
void ncfg_lock_release(ncfg_lock_t *lock);

#endif /* NCFG_LOCK_H */
