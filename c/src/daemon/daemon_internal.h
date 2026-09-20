/*
 * daemon_internal.h -- what the daemon's own files share and nobody else does.
 *
 * One declaration so far, and the reason it is here rather than in
 * `ncfg/daemon.h` is that nothing outside this directory may call it: what an
 * apply did is folded by whoever ran the apply, and both of the paths that do
 * are here.
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

#endif /* NCFG_DAEMON_INTERNAL_H */
