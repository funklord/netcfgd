/*
 * daemon_internal.h -- what the daemon's own files share and nobody else does.
 *
 * Everything here is here for one reason: nothing outside this directory may
 * call it. What an apply did is folded by whoever ran the apply; a window is
 * opened by whoever applied the change it covers; an executor is opened
 * through the loop's own seam. The paths that do those things are the
 * reconcile pass and the three requests that change the machine, and both are
 * in this directory.
 */
#ifndef NCFG_DAEMON_INTERNAL_H
#define NCFG_DAEMON_INTERNAL_H

#include "ncfg/apply.h"
#include "ncfg/daemon.h"
#include "ncfg/plan.h"

/*
 * Fold what an apply just did into `owned.json`, and publish its journal.
 *
 * **Called under the apply lock and before the executor is closed.**
 * `ncfg_owned_update` takes `owned.lock` of its own, so the file cannot be
 * interleaved either way -- but the apply lock is what makes the read, the
 * change and the write describe one machine rather than two applies' worth of
 * it.
 *
 * The journal goes out after the fold rather than inside it: both take
 * `owned.lock` and `flock` is held by the open file description, so a call
 * nested in the other's critical section would be this process waiting on
 * itself.
 *
 * **The DNS scopes this state would deliver are taken here**, because
 * `dns.apply` is the one op that is not its own effect and the record has to be
 * given what was delivered rather than what was named -- `apply.h` has the
 * argument. `ncfg_dns_scopes_of` is a pure function of the document and the
 * observation, and it is the same call on the same pair that built the
 * executor's own list, so the record says what the delivery did.
 *
 * A failure is a note rather than a refusal, for `state.h`'s reason: the run
 * directory is derived and disposable. What it costs is said, because an object
 * netcfgd installed and did not record is one it will decline to remove later
 * -- the safe direction, and still a machine that drifts.
 *
 * `tag` is the log subsystem the notes are emitted under, which is the only
 * thing that differed between the two copies of this that used to exist.
 */
void ncfg_daemon_record_what_ran(const ncfg_daemon_state_t *state, const char *tag,
    const ncfg_plan_t *plan, const ncfg_journal_t *journal);

/* ------------------------------------------------------------------------ *
 * The loop's seams, reached by the request arms as well as by the pass
 * ------------------------------------------------------------------------ */

/* Tell every subscriber. A world with no `announce` tells nobody, which is an
 * ordinary daemon with no monitor attached. */
void ncfg_daemon_announce(const ncfg_reconcile_world_t *world, const ncfg_proto_event_t *event);

/*
 * Open the way to the machine, or 0 with a sentence.
 *
 * **A world with no `executor_open` is refused rather than defaulted.** That
 * is the seam a test installs a recorder in and the one `src/main/` installs
 * netlink in; inventing one here would be this library reaching a kernel
 * because a caller forgot to say it may.
 */
int ncfg_daemon_open_executor(const ncfg_reconcile_world_t *world, ncfg_executor_t *out,
    char *err, size_t err_size);
void ncfg_daemon_close_executor(const ncfg_reconcile_world_t *world, ncfg_executor_t *executor);

/*
 * The SIM cycles this plan actually carries, from the ones that are waiting.
 *
 * Taken before the plan runs and cleared only after it has, which is what lets
 * a pass that could not apply leave the note in place for the next one. A
 * device whose `link.down` the planner declined is not in the answer, because
 * nothing cycled it.
 */
size_t ncfg_daemon_cycles_in(const ncfg_plan_t *plan, const ncfg_sims_t *sims,
    const char **out, size_t out_max);

/*
 * Open the window over a change that has just been applied.
 *
 * Called after the apply and **even where the apply failed part-way**: a
 * half-applied change is exactly what a window is for, and withholding the
 * safety net from the case that needs it most is the wrong way round.
 *
 * `last_good` is what a revert goes back to, which is not the document that
 * was just applied -- `ncfg_confirm_may_arm` is what answers it, and the
 * caller asks *before* applying so that a refusal leaves the machine untouched
 * rather than changed-but-unprotected.
 *
 * `armed_out` is set to 1 where a window was opened and left alone otherwise,
 * so a caller reporting on a pass can say which happened. Everything that can
 * go wrong here is logged: by the time this is reached the machine has already
 * changed, and there is no answer to give back but the truth about the net.
 */
void ncfg_daemon_arm_window(ncfg_reconcile_t *loop, const ncfg_plan_t *applied,
    const ncfg_journal_t *journal, uint32_t seconds, const ncfg_document_t *last_good,
    int *armed_out);

#endif /* NCFG_DAEMON_INTERNAL_H */
