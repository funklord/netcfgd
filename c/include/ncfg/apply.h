/*
 * apply.h -- carrying out a plan, and writing down what happened.
 *
 * WHAT THIS MODULE IS FOR
 *   The planner answers "what will change?"; this answers "what changed?".
 *   Section 4's failure semantics, made concrete: execution stops at the first
 *   failed action, every action is recorded as done, failed or skipped, and
 *   the remainder is re-runnable. **There is deliberately no rollback on
 *   failure** -- that is what commit-confirm is for, and conflating the two
 *   produces behaviour nobody can predict from the outside.
 *
 * THE SEAM, AND WHY IT IS THE FIRST THING IN THE FILE
 *   `ncfg_executor_t` is a struct of function pointers. The real one talks to
 *   netlink; a test fills it with a recorder and can be told to fail at a
 *   chosen step. Everything about ordering, failure handling and journalling
 *   is exercised against the recorder, so **none of it needs a privilege, a
 *   socket or an interface** -- which is the property that makes this module
 *   testable on the machine it would otherwise reconfigure. The Rust has the
 *   same seam as a trait and for the same reason.
 *
 * THE ORDERING RULES ARE THE PLAN'S, AND THIS PRESERVES THEM
 *   A plan arrives already in a valid execution order (see `plan.h`), so this
 *   walks it front to back and does not reorder. That is not a simplification:
 *   three of the orderings cost this project a defect each, and an executor
 *   that sorted by op kind, or grouped by interface, would take all three back.
 *
 *     * **Addresses go in before the routes that need them.** A route whose
 *       next hop is not yet reachable is `ENETUNREACH`.
 *     * **The hook phases bracket a bring-up and a teardown.** `pre_up` runs
 *       before `link.up`, `post_up` after the last addressing action; both
 *       used to be emitted unconditionally, so a converged interface ran them
 *       on every apply and a disabled one went `pre_up`, `link.down`,
 *       `post_down`, `post_up` (0063).
 *     * **The withdrawal sits between `pre_down` and `down`.** `pre_down` runs
 *       while the interface still works, the addresses come off, and only then
 *       does `down` fire -- which is what makes the two phases different
 *       moments rather than the same one, and which is a fix in its own right:
 *       `link.down` flushes IPv6 and leaves IPv4 behind.
 *
 *   `apply_test.c` asserts the **sequence** the recorder saw, not the set,
 *   because a set cannot tell any of those three apart from its opposite.
 *
 * WHAT THIS BUILD EXECUTES, AND WHAT IT REFUSES
 *   `ncfg_apply_supported` is the single answer, and it is a value rather than
 *   a branch buried in the executor so that a test can ask it about all
 *   forty-eight ops without opening anything. An op this build cannot carry
 *   out is **refused with a sentence naming it**, never ignored: an executor
 *   that returned success for work it did not do would report a converged
 *   machine that had not been touched.
 *
 * ERRORS
 *   base.h's convention throughout: 1 or 0, and a sentence. The two deliberate
 *   exceptions are named where they are declared -- `ncfg_hook_run`, which
 *   answers an outcome because the phase decides what a failure means, and
 *   `ncfg_apply`, whose return says whether the *journal* could be written and
 *   never whether the plan succeeded.
 */
#ifndef NCFG_APPLY_H
#define NCFG_APPLY_H

#include <stddef.h>
#include <stdint.h>

#include "ncfg/buf.h"
#include "ncfg/dns.h"
#include "ncfg/document.h"
#include "ncfg/json_write.h"
#include "ncfg/plan.h"
#include "ncfg/secrets.h"
#include "ncfg/state.h"

/* ------------------------------------------------------------------------ *
 * The seam
 * ------------------------------------------------------------------------ */

/*
 * Something that can carry out one action.
 *
 * Filled by `ncfg_kernel_executor` against real netlink, and by a recorder in
 * the tests. A struct of function pointers rather than a single callback
 * because the two implementations differ in what they own as well as in what
 * they do, and `state` is the only thing either of them needs from the other
 * side.
 */
typedef struct {
	/* Whatever the implementation keeps. Never touched by this module. */
	void *state;
	/*
	 * Carry out one action. 1 for success, 0 with a sentence.
	 *
	 * The sentence goes into the journal and in front of an operator, so it
	 * names what failed rather than restating the action.
	 */
	int (*execute)(void *state, const ncfg_op_t *op, char *err, size_t err_size);
} ncfg_executor_t;

/* ------------------------------------------------------------------------ *
 * The journal
 * ------------------------------------------------------------------------ */

/* How one action ended. */
typedef enum {
	/* It ran and the kernel accepted it. */
	NCFG_OUTCOME_DONE,
	/* It ran and failed. Execution stopped here. */
	NCFG_OUTCOME_FAILED,
	/* It never ran, because something before it failed. */
	NCFG_OUTCOME_SKIPPED,
	/*
	 * It ran, and a revert has since put it back.
	 *
	 * **A divergence from the Rust**, which has three outcomes and records a
	 * revert as log lines. An operator reading `/run/netcfgd/plan.last.json`
	 * after a window closed unconfirmed could otherwise not tell which of the
	 * actions it lists are still in effect -- which is the one question that
	 * file exists to answer, and the one moment it is read.
	 */
	NCFG_OUTCOME_REVERTED
} ncfg_outcome_t;

/* The word this outcome is written as. NULL outside the set, value.h's
 * convention: a plausible word for an outcome that is not one is worse than
 * no word. */
const char *ncfg_outcome_name(int outcome);

/*
 * One line of the journal.
 *
 * Carries the reason as well as the outcome, because an operator reading this
 * after a failure needs to know *why* the action existed, not only that it
 * failed.
 *
 * **Every string here is the journal's own**, copied when the record was
 * pushed. The plan a record came from may be freed first -- and the error
 * message never belonged to anything that outlives the call that produced it.
 */
typedef struct {
	/* The action's id in the plan, and how a revert finds it again. */
	uint32_t      id;
	/* Its op name, for example `addr.add`. */
	const char   *op;
	/* Which interface it touched, or NULL where it named none. */
	const char   *interface;
	ncfg_reason_t reason;
	int           outcome; /* ncfg_outcome_t */
	/* What went wrong, for a failure. NULL otherwise. */
	const char   *error;
} ncfg_record_t;

/*
 * The record of one apply.
 *
 * The arena and the sticky failure are `ncfg_plan_t`'s, for its reasons: one
 * `free` loop rather than a walk over a union of thirty arms, and a caller
 * that may push a hundred records and check once.
 */
typedef struct {
	ncfg_record_t *records;
	size_t         record_count;
	size_t         record_capacity;

	void   **owned;
	size_t   owned_count;
	size_t   owned_capacity;
	/* Set by the first allocation failure and never cleared. */
	int      failed;
} ncfg_journal_t;

/* Start an empty journal. Safe on a journal that has been through
 * `ncfg_journal_free`. */
void ncfg_journal_init(ncfg_journal_t *journal);

/* Release what it holds and leave it usable and empty. Freeing one that was
 * never filled in is nothing. */
void ncfg_journal_free(ncfg_journal_t *journal);

/* Whether anything went wrong while the journal was being built. Not whether
 * the plan succeeded -- see `ncfg_journal_succeeded`. */
int ncfg_journal_failed(const ncfg_journal_t *journal);

/*
 * Append a record, copying every string it names.
 *
 * Public because the daemon assembles a journal from more than one apply, and
 * because a test that cannot build one by hand can only test the loop that
 * happens to produce them.
 */
void ncfg_journal_push(ncfg_journal_t *journal, const ncfg_record_t *record);

/* Whether every action ran and succeeded. An empty journal succeeded: an
 * already-correct system produces an empty plan, which is the normal case. */
int ncfg_journal_succeeded(const ncfg_journal_t *journal);

/* The action that failed, if one did. At most one: execution stops there. */
const ncfg_record_t *ncfg_journal_failure(const ncfg_journal_t *journal);

/* How many ran and succeeded, never ran, and have since been put back. */
size_t ncfg_journal_done(const ncfg_journal_t *journal);
size_t ncfg_journal_skipped(const ncfg_journal_t *journal);
size_t ncfg_journal_reverted(const ncfg_journal_t *journal);

/*
 * Write the journal as `/run/netcfgd/plan.last.json` carries it.
 *
 * Compact rather than indented, which is the port's convention and
 * `ncfg_plan_write`'s: the Rust renders this with `to_string_pretty` and the
 * two differ by whitespace and by nothing else.
 */
int ncfg_journal_write(const ncfg_journal_t *journal, ncfg_buf_t *buf, char *err,
    size_t err_size);

/*
 * The same members, into a message somebody else began.
 *
 * For the protocol's `journal` response, which carries them flattened into the
 * envelope: `{"response":"journal","records":[...]}`. Published for
 * `ncfg_plan_write_members`' reason -- the alternative is a second writer for
 * this shape in the daemon, and a journal that gains a member there and not
 * here is a client reading one fewer field than the file has.
 *
 * **A journal that ran out of memory while it was being built is not refused
 * here**, because this writes into a message already begun. `ncfg_journal_write`
 * and the response encoder each ask `failed` before they start.
 */
void ncfg_journal_write_members(ncfg_json_writer_t *writer, const ncfg_journal_t *journal);

/* ------------------------------------------------------------------------ *
 * Running a plan
 * ------------------------------------------------------------------------ */

/*
 * Run a plan, in plan order, stopping at the first failure.
 *
 * Every action after the failure is recorded as skipped rather than dropped,
 * because "what did not run" is the question an operator asks next and a
 * journal that omits it cannot answer.
 *
 * **The return value is not whether the plan succeeded.** It is 1 unless the
 * journal itself could not be built, which is an allocation failure and
 * nothing to do with the machine. Ask `ncfg_journal_succeeded` for the other
 * question. The two are separated because an executor that conflated them
 * would report a full success for a plan whose record was lost, which is the
 * one direction this must not be wrong in.
 *
 * `journal` is initialised here; the caller frees it either way.
 */
int ncfg_apply(const ncfg_plan_t *plan, const ncfg_executor_t *executor,
    ncfg_journal_t *journal, char *err, size_t err_size);

/*
 * Put back what this apply did, newest first.
 *
 * **An apply that cannot be confirmed puts the machine back**, and this is the
 * half of that which needs no daemon: the declared inverse of every action
 * that actually ran, replayed in the reverse of the order it ran in. A
 * re-plan against the last-good document is the other half and belongs to
 * whoever holds that document -- it is the safety net, and it cannot replace
 * this one, because a re-plan can only take back what the old document
 * *disagrees* with. Measured, on a window that moved an address, a route and
 * the MTU: the document restore alone left the MTU at the new value, because
 * the last-good document states no MTU and 1400 agrees with it as well as 1500
 * does. A declared inverse carries the value it replaced.
 *
 * Driven by the journal rather than by the plan alone. An action that failed
 * or never ran has nothing to undo, and replaying its inverse would be netcfgd
 * removing an address it never added -- on a machine that is already in the
 * state a revert exists to rescue. `NCFG_OUTCOME_DONE` is the only outcome
 * that means the machine changed, and an action with no declared inverse
 * contributes nothing: those are what the plan's "cannot be undone" warning is
 * about, and it was true before this and stays true.
 *
 * A failed inverse is stepped over rather than stopping the revert. The
 * remaining ones are for other actions and are still worth running; stopping
 * would leave a machine that is neither the new configuration nor the old one,
 * which is the one outcome a revert exists to prevent.
 *
 * Each record whose inverse ran is marked `NCFG_OUTCOME_REVERTED`. Answers how
 * many were put back.
 *
 * **Where this is in the Rust**: `netcfgd-daemon::confirm`, as `undo_from` and
 * the first half of `revert`. It is here because both halves are pure
 * functions of a plan, a journal and an executor -- no window file, no
 * last-good document, no socket -- so this is where they can be driven by the
 * same double as everything else. The sentence that used to end this one said
 * "and the daemon module is not ported", which was the reason at the time and
 * has not been true since `src/daemon/confirm.c` landed; the placement stayed
 * because the first reason is the one that decided it.
 */
size_t ncfg_apply_revert(const ncfg_plan_t *plan, ncfg_journal_t *journal,
    const ncfg_executor_t *executor);

/* ------------------------------------------------------------------------ *
 * What an apply did, folded into the ownership record
 * ------------------------------------------------------------------------ */

/*
 * Fold one action that reached the machine into `owned.json`'s record.
 *
 * WHY THIS IS AN OP AND NOT AN EFFECT LIST
 *   The Rust accumulates an `Effects` struct inside `KernelExecutor` as it
 *   goes, and the daemon calls `OwnedState::absorb` on it afterwards. Here the
 *   effect of an action **is** the action: every member of that struct which
 *   this record can carry is a pure function of the op that produced it -- a
 *   created link is the op's name, an added address is the op's interface and
 *   CIDR with `static` for its origin, a forwarding sysctl is the op's
 *   interface and its boolean. So there is no second aggregate to build, to
 *   free and to keep in step with the record it folds into.
 *
 *   What that buys is the property this module exists for: the fold is driven
 *   through `ncfg_executor_t` like everything else, so **it is checked against
 *   the recorder and needs no socket, no privilege and no interface.** An
 *   accumulator inside the real executor would put the one piece of bookkeeping
 *   that decides what netcfgd may later delete behind a live netlink socket.
 *
 * THE ONE ACTION THAT IS NOT ITS OWN EFFECT
 *   `dns.apply` names one scope and `ncfg_service_dns_apply` delivers *every*
 *   scope its context carries whatever the op says, so folding the op's own
 *   scope would record one delivery as the whole of one -- and a scope that has
 *   left the document would stand in the record for ever, with the planner
 *   asking for a re-delivery on every pass while it did.
 *
 *   So the delivered set is an argument: `ncfg_apply_record` takes the same
 *   scope list the executor was given, and a `dns.apply` that reached the
 *   machine **replaces** the record's with it. That keeps the fold a pure
 *   function of things the caller already holds -- the list is
 *   `ncfg_dns_scopes_of` of the document and the observation, which is what
 *   built the executor's -- rather than an accumulator inside it.
 *
 *   A caller with no list passes NULL, and the record is left alone. It costs
 *   one re-delivery on the next pass and never a wrong file, because the
 *   resolver is written from the document rather than from this record. The
 *   Rust's `absorb` says the same of an empty `applied_dns`.
 *
 *   **Without it every pass plans `dns.apply` for ever.** `observed.dns` is
 *   filled from this record and from nowhere else, so a record nothing writes
 *   is an empty list, and the planner compares every scope it wants against
 *   nothing. That is the plan-idempotence property failing with the machine
 *   already changed, which is what `dns.h`, `service.h` and `observed.h` each
 *   warn of from their own side.
 *
 * 0079'S THIRD CLEAR, AND WHY IT IS AN ARGUMENT
 *
 *   Two of the decision's three rules are things an apply did, so they come out
 *   of the journal: a `backend.start` counts, a `backend.stop` clears. The
 *   third is **a backend the observation found running**, which no action
 *   performed -- so the observation the plan was made from is an argument here,
 *   the way the delivered scopes are, and for the same reason: the fold stays a
 *   pure function of things the caller already holds.
 *
 *   **This was held back for two waves and the reason was real.** `running` in
 *   the record was netcfgd's memory of having started something, so clearing on
 *   it would have cleared every count on every pass and 0079's cap would never
 *   have bitten at all -- "a backend that failed five times is never started
 *   again" traded for "one that fails for ever is started for ever", which is
 *   the defect 0079 was written against and was measured at 181 starts in
 *   twelve seconds. `ncfg_observe_backend_liveness` is what made it a fact
 *   about a process, for the six kinds netcfgd has a handle on; where it has
 *   none the field is still memory, and there it is inert, because a record
 *   saying a backend is up is one the planner asks for no start against.
 *
 *   **A caller with no observation passes NULL and the counts are left alone**,
 *   which is what the port did for both waves before this one. The cost is the
 *   cap never lifting: five starts a month apart count the same as five in a
 *   second, and the sixth is refused on a machine where nothing is wrong.
 *
 *   The Rust reaches the same three rules in the same order from its effect
 *   list, `netcfgd_apply`'s executor having taken the running set at
 *   `with_context` time -- which is the same observation, held in a different
 *   place. The order matters where one pass both sees a backend up and starts
 *   another: the clear goes first so the start is still counted.
 *
 * 1, or 0 where the record could not grow -- which is an allocation failure and
 * nothing to do with the machine.
 */
int ncfg_owned_absorb(ncfg_owned_state_t *owned, const ncfg_op_t *op);

/*
 * Fold everything this journal says reached the machine into `owned.json`.
 *
 * **Driven by the journal rather than by the plan**, which is
 * `ncfg_apply_revert`'s rule and is here for a sharper reason: an action that
 * failed or never ran changed nothing, and recording it would have netcfgd
 * claim an address it never installed -- and ownership is what decides whether
 * it may later withdraw one.
 *
 * `NCFG_OUTCOME_REVERTED` folds the action's **inverse** instead, which is what
 * lets a revert be recorded at all here. The Rust reaches the same answer by a
 * different route -- its revert runs the inverses through the executor it will
 * absorb afterwards, so their removals are in the effect list -- but
 * `ncfg_apply_revert` is a library call taking a plan, a journal and an
 * executor, with no run directory and no effects, which is exactly why 0263
 * deferred the fold on that path. Reading the outcome is what closes it: what
 * is in effect now is the inverse, so that is what the record says, and a
 * record whose inverse failed stays `done` -- the honest answer, since that
 * change is still in effect.
 *
 * Folding the same journal twice is deliberate and safe: every rule in
 * `ncfg_owned_absorb` replaces or removes before it adds, so a second fold of a
 * record that has not moved writes the same file again.
 *
 * Read-modify-written under `owned.lock` through `ncfg_owned_update`, because
 * two processes write this file -- `ncfg apply` and the daemon -- and a lost
 * update here **puts back** a record the other one had just removed.
 *
 * A plan with nothing to record does not write, and a pass that changed nothing
 * does not rewrite a file another writer is in the middle of. **With an
 * observation the read still happens**, because whether a count is there to
 * clear is not knowable without it -- and the read is under the same lock, so
 * it is the one moment the record and the answer exist together. The write is
 * what is skipped, not the look.
 */
int ncfg_apply_record(const char *run_dir, const ncfg_plan_t *plan,
    const ncfg_journal_t *journal, const ncfg_dns_scope_t *delivered, size_t delivered_count,
    const ncfg_observed_t *observed, char *err, size_t err_size);

/*
 * Publish the journal as `<run_dir>/plan.last.json`.
 *
 * **This is the file that answers "where did it stop".** An apply halts at the
 * first failure and records everything after it as skipped; without this that
 * answer exists only in whatever ran the apply -- and for the daemon that is
 * nowhere, since a reconcile has no terminal. The Rust's daemon writes it after
 * every apply, after every wifi apply and after every revert, and `ncfg apply`
 * writes it too; this is the same call and the same moment.
 *
 * **Written under `owned.lock`, which the Rust does not do.** Its writer is an
 * atomic rename and nothing else, so `plan.last.json` and `owned.json` can be
 * replaced in either order by two writers -- and there are two: `ncfg apply`
 * and the daemon. The two files are the two halves of one statement about one
 * apply, so a reader that finds a journal claiming a link was created and a
 * record that does not claim it has been handed two applies' worth of machine.
 * The critical section is a render and a rename, which is the same cost
 * `ncfg_owned_update` already pays.
 *
 * **So it must not be called from inside `ncfg_owned_update`'s change
 * callback**, which would be the same process asking for a lock it holds --
 * `flock` is owned by the open file description, so a second `open` in this
 * process blocks against the first for ever. Every caller does the pair in
 * sequence instead.
 *
 * **The run directory is created where it is not there**, which is
 * `ncfg_owned_update`'s behaviour rather than a choice made here: both reach
 * `ncfg_lock_take`, which makes the directory it is asked to put the lock in.
 * So a wrong path is made rather than refused, and the refusals below are the
 * ones a path that cannot be made produces.
 *
 * An empty journal is written, unlike the fold beside it, and the difference is
 * not an inconsistency: the record is a claim that accumulates and must not be
 * rewritten by a pass that did nothing, while this file is an answer about the
 * *last* apply -- and "the last one did nothing" is that answer rather than the
 * absence of one. It is what the Rust writes there too.
 */
int ncfg_apply_write_journal(const char *run_dir, const ncfg_journal_t *journal, char *err,
    size_t err_size);

/*
 * Whether this build can carry this op out, and the sentence if it cannot.
 *
 * The refusal names the op and says what is missing, because "not implemented"
 * on its own sends the reader to the source. Asked by the kernel executor
 * before it touches anything, and separately by `apply_test.c` for every op in
 * the taxonomy -- which is how "nothing is silently ignored" is a checked
 * property rather than a claim.
 */
int ncfg_apply_supported(const ncfg_op_t *op, char *err, size_t err_size);

/* ------------------------------------------------------------------------ *
 * Hooks
 * ------------------------------------------------------------------------ */

/* What happened when a hook ran. */
typedef enum {
	/* It ran and succeeded. */
	NCFG_HOOK_OK,
	/* It failed, and the phase says that vetoes the transition. */
	NCFG_HOOK_VETOED,
	/* It failed, and the phase says to carry on. */
	NCFG_HOOK_NOTED
} ncfg_hook_outcome_t;

/*
 * Whether a failure in this phase stops what is going on.
 *
 * Section 5.2: a non-zero exit from a `pre_*` hook **aborts** the transition --
 * you can veto a bring-up -- while `post_*` and event hook failures are logged
 * and roll nothing back. That distinction is the whole reason this is a
 * function rather than an exit-status check at the call site: treating a
 * `post_up` failure as fatal would stop a plan after the interface is already
 * configured, leaving the rest of the machine unconfigured because a logging
 * script exited 1.
 */
int ncfg_hook_is_veto_phase(int phase);

/*
 * How long a hook may run when its own block does not say.
 *
 * Sixty seconds because the honest slow cases are real: a `pre_up` that waits
 * for a peer takes tens of seconds and is not misbehaving. The number is a
 * bound on damage rather than a service-level target -- and it is the only
 * limit any hook has, since the configuration language has no `timeout` key
 * and `ncfg_hook_ref_t::timeout` is therefore never anything but absent.
 */
#define NCFG_HOOK_DEFAULT_TIMEOUT_SECONDS 60

/*
 * What a hook is told.
 *
 * Section 5.2 fixes these names, so they are a contract rather than an
 * implementation detail: a hook written against them keeps working. Every
 * member may be NULL, which means the variable is not set at all rather than
 * set empty -- a script testing `[ -n "$NCFG_ADDR" ]` has to be able to tell.
 */
typedef struct {
	const char *iface;
	/* Why it ran, for the event phases. `NCFG_REASON`. */
	const char *reason;
	/* The address in play, where there is one. `NCFG_ADDR`. */
	const char *addr;
	/* The gateway, where there is one. `NCFG_GW`. */
	const char *gateway;
	/*
	 * The one variable a phase carries that the four above do not name:
	 * `NCFG_ACTION` for `drift`, `NCFG_BSSID` for `roam`, `NCFG_URL` for
	 * `portal`. Section 5.2 fixes those three names too, so a hook written
	 * against them is the same contract as one written against `NCFG_ADDR`.
	 *
	 * **A general pair rather than three more members**, which is what
	 * `daemon.h`'s hook seam said this struct would grow the day it grew
	 * anything: the phases that carry one each carry exactly one, and three
	 * fixed members would be two NULLs at every call site. Both NULL, or
	 * neither -- a name with no value sets nothing, because a hook testing
	 * `[ -n "$NCFG_BSSID" ]` must be able to tell an absent station from an
	 * empty one.
	 *
	 * `variable` is the whole name and carries no `NCFG_` prefix of its own:
	 * the caller names it in full, so a phase that grows a fourth does not
	 * need this file changed.
	 */
	const char *variable;
	const char *value;
} ncfg_hook_env_t;

/*
 * Run one hook.
 *
 * **Answers an outcome rather than base.h's 1 or 0**, and that is the one
 * place in this module the convention is set aside: a hook that exits non-zero
 * has not failed *this call*, it has said something, and what it means is the
 * phase's to decide. `err` carries the sentence for both failing outcomes and
 * is left alone for `NCFG_HOOK_OK`.
 *
 * The content hash is checked before execution, which makes section 2.2's
 * record a control rather than a report: a hook file swapped after the
 * configuration was compiled does not run as root on the strength of the old
 * approval.
 *
 * **This forks and execs. No test that drives the executor double reaches
 * it.**
 */
ncfg_hook_outcome_t ncfg_hook_run(const ncfg_hook_ref_t *hook, const ncfg_hook_env_t *env,
    char *err, size_t err_size);

/* ------------------------------------------------------------------------ *
 * The executor that talks to the kernel
 * ------------------------------------------------------------------------ */

/*
 * The real executor.
 *
 * **Opening one opens a netlink socket, and using one reconfigures the machine
 * this process is running on.** Nothing under `tests/` constructs one: every
 * check in this module drives a recorder through `ncfg_executor_t` instead,
 * which is what the seam is for.
 */
typedef struct ncfg_kernel ncfg_kernel_t;

/* Open the socket. NULL with a sentence. */
ncfg_kernel_t *ncfg_kernel_new(char *err, size_t err_size);

/* Close it and release everything. NULL is nothing. */
void ncfg_kernel_free(ncfg_kernel_t *kernel);

/*
 * The hooks the document declares, borrowed for the executor's life.
 *
 * Needed because `hook.run` carries a path and not a hash -- the op is what
 * goes into `/run` and over the socket, and a hash there would say what the
 * document already says. Without this the executor has nothing to check a
 * script against, and `ncfg_hook_run` refuses rather than running whatever is
 * on disk now.
 *
 * Borrowed rather than copied, which is `plan.h`'s rule for the four values a
 * plan borrows and is here for the same reason: **the executor must not
 * outlive the document.** Every caller in this project builds, applies and
 * drops inside one call.
 */
void ncfg_kernel_set_hooks(ncfg_kernel_t *kernel, const ncfg_hook_ref_t *hooks, size_t count);

/*
 * The document being applied, borrowed for the executor's life.
 *
 * Needed because six ops carry a device's *name* and nothing else --
 * `link.set_bridge`, `link.set_bond`, `link.set_macvlan`, `link.set_tunnel`,
 * `link.set_vxlan` and `wg.set_device`. What they change is the document's,
 * and a plan that carried it would put a WireGuard private key reference,
 * every peer's public key and every allowed prefix into
 * `/run/netcfgd/plan.last.json` for no gain -- constraint 5 applied to a plan,
 * which is the same reason `hook.run` carries a path and not a hash.
 *
 * **Without one those six refuse by name**, rather than configuring a device
 * with nothing: a bridge re-stated from an empty block is a bridge with every
 * setting at the kernel's default, reported as a successful apply.
 *
 * Borrowed rather than copied, which is `ncfg_kernel_set_hooks`' rule and
 * `plan.h`'s: **the executor must not outlive the document.**
 */
void ncfg_kernel_set_document(ncfg_kernel_t *kernel, const ncfg_document_t *document);

/*
 * Where `file` secrets live, for the two ops that load key material.
 *
 * `wg.set_device` resolves a private key and `wg.set_peers` resolves a
 * preshared key per peer; both arrive as `ncfg_secret_ref_t` in the document,
 * and resolving one reads a file, a keyring or a subprocess. NULL -- which is
 * the default -- means the machine's own directory, which is what `secrets.h`
 * reads a NULL `secrets_dir` as.
 *
 * A setter rather than an environment variable, for `contention.h`'s reason: a
 * test that forgot to set a variable would read the developer's real secrets
 * directory, and one that forgets an argument does not compile. Borrowed, and
 * the resolver must outlive the executor.
 */
void ncfg_kernel_set_secrets(ncfg_kernel_t *kernel, const ncfg_secret_resolver_t *resolver);

/* Fill in the seam. `out` borrows `kernel` and must not outlive it. */
void ncfg_kernel_executor(ncfg_kernel_t *kernel, ncfg_executor_t *out);

/* ------------------------------------------------------------------------ *
 * What else on the machine is touching the network
 * ------------------------------------------------------------------------ */

/*
 * TWO DAEMONS ON ONE INTERFACE IS THE FAILURE THIS PROJECT IS ARRANGED AGAINST
 *   netcfgd would otherwise simply join the fight: it applies its
 *   configuration, `NetworkManager` applies its own a second later, and the
 *   operator watches an address appear and disappear with neither tool saying
 *   why.
 *
 *   Detection is by the files these daemons leave in `/run`, not by D-Bus:
 *   D-Bus is the dependency 0014 declined to take, and the files are the only
 *   per-interface evidence available -- which is the part that matters, since
 *   netcfgd and `NetworkManager` can share a machine perfectly well as long as
 *   they do not share a device.
 *
 *   **A process name is consulted as well, and only for liveness.**
 *   `NetworkManager.service` has no `RuntimeDirectory=` and no `ExecStop=`, so
 *   its device files outlive it with `managed=true` still in them, and netcfgd
 *   declined a radio on behalf of a daemon systemd had already stopped --
 *   leaving a machine with no network manager at all (0145). So: **the file
 *   says which interfaces, and a live process says the claim is current.**
 *   Neither is sufficient alone.
 *
 *   netcfgd never acts on what it finds here. It reports, and the operator
 *   decides -- the same posture as a guard or a drift report. The one caller
 *   that does act stops **netcfgd's own** backend and nothing else.
 *
 * WHERE THIS DIVERGES FROM THE RUST
 *   * **Where to look is an argument, not an environment variable.** The Rust
 *     reads `NCFG_RUN_ROOT` and `NCFG_PROC` so that its tests can point it
 *     somewhere safe; here the paths are a struct the caller fills, and
 *     `ncfg_contention_machine` is the one place `/run` and `/proc` are
 *     written down. A test that forgot to set a variable would read the
 *     developer's real `/run`; a test that forgets an argument does not
 *     compile.
 *   * **`/proc` is walked once per call rather than once per daemon.** The
 *     Rust asks `daemon_is_running` separately for `NetworkManager` and for
 *     `systemd-networkd`, which is two full scans of `/proc` on every
 *     reconcile tick. One walk answers both questions.
 */

/* An interface netcfgd claims, and the kernel index it claims it by.
 *
 * By index because every daemon here keys its state that way -- an interface
 * can be renamed and the index cannot. */
typedef struct {
	const char *name;
	uint32_t    index;
} ncfg_interface_claim_t;

/* The longest a remedy command gets once the device name is in it. */
#define NCFG_REMEDY_MAX 160

/* Another daemon that claims interfaces netcfgd also claims. */
typedef struct {
	/* What to call it, as the operator would. Static; not freed. */
	const char *name;
	/* The interfaces of netcfgd's that it also manages, sorted. Owned. */
	char      **interfaces;
	size_t      interface_count;
	/* How to hand a device over, with `{}` where its name goes. Static. */
	const char *remedy;
} ncfg_contender_t;

/* Every daemon found claiming something. `ncfg_contenders_free` is the one
 * `free` for the whole aggregate, and freeing one never filled in is nothing. */
typedef struct {
	ncfg_contender_t *at;
	size_t            count;
} ncfg_contenders_t;

/*
 * Where the evidence is read from.
 *
 * `run_root_is_the_machines` is the question `/run` alone cannot answer:
 * every daemon here keys its state by kernel index, and **an index means
 * nothing outside the network namespace that issued it**. `/run` is a mount
 * rather than a namespace, so a netcfgd in a private network namespace that
 * can still see the host's `/run` reads the host's files and matches them
 * against its own indices -- which collide immediately, both numberings
 * starting at 1. Measured: `tests/live/hwsim.sh` puts two simulated radios in
 * a private namespace where the station is index 3, and on the host index 3
 * was the operator's real `wlp0s20f3` with `managed=true`, so netcfgd refused
 * to start a supplicant on a radio `NetworkManager` had never heard of.
 *
 * So where this is set, the namespace is checked and a `/run` written from
 * another one claims nothing. Where it is clear -- a fixture, or a container
 * with state of its own that somebody pointed netcfgd at on purpose -- the
 * question does not arise and no check is made.
 */
/* What a program reads to point these two somewhere else, which is what the
 * Rust's `contention.rs` reads and is therefore what the live scripts set.
 * The library never reads them: `service.h` says why a seam takes its roots as
 * arguments, and `daemon_world.c` is where a netcfgd resolves these. */
#define NCFG_CONTENTION_RUN_ROOT_ENV  "NCFG_RUN_ROOT"
#define NCFG_CONTENTION_PROC_ROOT_ENV "NCFG_PROC"

typedef struct {
	/* Where the other daemons' state lives. */
	const char *run_root;
	/* Where to look for running processes. */
	const char *proc_root;
	int         run_root_is_the_machines;
} ncfg_contention_where_t;

/*
 * The machine this process is running on: `/run`, `/proc`, and its own
 * namespace.
 *
 * The two paths are written down here and nowhere else, so that a test can
 * assert what the daemon reads by reading this rather than by letting anything
 * go near it.
 */
void ncfg_contention_machine(ncfg_contention_where_t *out);

/*
 * Which other daemons claim any of `claims`.
 *
 * `out` is filled in on success and is empty where nothing was found, which is
 * the ordinary answer on the ordinary machine. 0 with a sentence is an
 * allocation failure and nothing else: a `/run` that is not there, a file that
 * cannot be read and a `/proc` that will not answer are all ordinary states
 * with their own documented readings, not failures to report.
 */
int ncfg_contenders_find(const ncfg_contention_where_t *where,
    const ncfg_interface_claim_t *claims, size_t claim_count, ncfg_contenders_t *out, char *err,
    size_t err_size);

/* Release what it holds and leave it usable and empty. */
void ncfg_contenders_free(ncfg_contenders_t *found);

/*
 * The command that hands one device over, with the name filled in.
 *
 * Filled in rather than left as a placeholder: an operator who has to work out
 * what `DEV` stands for is an operator who might use the wrong name, and the
 * whole point of the message is that they act on it.
 *
 * `out` is `NCFG_REMEDY_MAX` bytes. 0 where it would not fit, which leaves
 * `out` empty rather than half a command.
 */
int ncfg_contender_remedy_for(const ncfg_contender_t *contender, const char *interface, char *out,
    size_t out_size);

/*
 * One message per contender, for a plan warning or a startup line.
 *
 * Appended to `buf`, which is `buf.h`'s arrangement and is here for its
 * reason: this text is composed from interface names and grows with them, and
 * a message a daemon builds has to be bounded somewhere the caller can see.
 * 0 with a sentence where the buffer would not take it.
 */
int ncfg_contender_describe(const ncfg_contender_t *contender, ncfg_buf_t *buf, char *err,
    size_t err_size);

/* ------------------------------------------------------------------------ *
 * Asking a running dhcpcd which configuration file it was started with
 * ------------------------------------------------------------------------ */

/*
 * **THE ONE BACKEND WHOSE MARK CANNOT BE READ FROM THE PROCESS**
 *   netcfgd recovers its supplicant, and its udhcpc, by finding a path it
 *   chose as a whole `argv` element (0140). dhcpcd calls `setproctitle` and
 *   destroys both: measured, `/proc/<pid>/cmdline` reads
 *   `dhcpcd: wlp0s20f3 [ip4]`, and the environment block comes back 4494 bytes
 *   of NUL. Nothing netcfgd passed survives in the process image.
 *
 *   What does survive is dhcpcd's own memory of its `-f` argument, which it
 *   recites verbatim -- symlink and all, with no `realpath` -- to anyone who
 *   asks `--getconfigfile` on its control socket. So netcfgd starts dhcpcd
 *   with a `-f` under its own run directory and asks for it back (0143).
 *
 * THREE THINGS MEASURED THAT THE OBVIOUS IMPLEMENTATION GETS WRONG
 *   * **The privileged socket, not the unprivileged one.** dhcpcd 10.5.0
 *     removed `<iface>-4.unpriv.sock` outright -- "a breaking ABI change" in
 *     its own commit message -- and Debian sid ships 10.5.2. netcfgd is root,
 *     so the privileged socket is available on every version that has a socket
 *     at all, and answers this command identically.
 *   * **The length prefix is a native `size_t`.** dhcpcd's `control.c` writes
 *     `iov[0].iov_len = sizeof(size_t)`: eight bytes on amd64, **four** on
 *     32-bit ARM, and big-endian on a big-endian MIPS. Parsing it as a
 *     little-endian `uint64_t` works on the developer's machine and on nothing
 *     else this targets, so the reply's *tail* is read instead.
 *   * **An unknown command does not fail, it hangs.** `--getinterfaces`,
 *     `--isprivileged` and a bare `-q` were each measured to produce no reply
 *     *and no close*, past a four-second wait, on both sockets. A probe
 *     without a deadline is a daemon that stops reconciling.
 */

/* The longest reply worth reading: a path, so `PATH_MAX` and a little. This is
 * the cap that stands in for the length prefix netcfgd deliberately does not
 * parse. */
#define NCFG_DHCPCD_REPLY_MAX 4200

/*
 * How long to wait for a reply.
 *
 * Generous rather than tuned. The command is answered by dhcpcd's separate
 * `[control proxy]` process, which replied in 0.00s even with the main dhcpcd
 * stopped with `SIGSTOP` -- only stopping *every* dhcpcd process silenced it.
 * So the deadline exists for the wedged case, not the ordinary one, and
 * waiting longer buys nothing but a slower refusal.
 */
#define NCFG_DHCPCD_DEADLINE_MILLISECONDS 250

/*
 * The path out of one control-socket reply, into `out`.
 *
 * The frame is a native-width length then a NUL-terminated string, and netcfgd
 * parses only the second half: the last run of printable bytes. A filesystem
 * path holds no NUL and no control character, dhcpcd sends exactly one string,
 * and the prefix is binary -- so the tail is the answer whatever width the
 * prefix had.
 *
 * **It must be an absolute path, and that is a divergence from the Rust.**
 * There, a read that arrived holding only the length prefix answers with the
 * prefix's low byte, which is printable for any ordinary path: 34 bytes gives
 * `22 00 00 00 00 00 00 00`, and the answer is `"`. That is the very defect
 * the tail rule replaced, coming back through a short read -- and a caller
 * comparing it against netcfgd's own `-f` reads it as somebody else's dhcpcd.
 * A reply that is not an absolute path terminated by a byte below `0x20` is
 * not an answer, and `ncfg_dhcpcd_config_file_of` reads again rather than
 * believing it.
 *
 * 1 with the path in `out`, 0 where there is no answer in these bytes.
 */
int ncfg_dhcpcd_control_payload(const void *bytes, size_t length, char *out, size_t out_size);

/*
 * The configuration file a running dhcpcd was started with. The caller frees
 * it.
 *
 * `NULL` covers every way of not knowing: no socket, nothing listening, a
 * version that does not answer, a reply that does not parse, or the deadline.
 * **`NULL` is not "somebody else's"** -- it is "netcfgd could not tell", and
 * the caller must treat the two differently, which is 0074's rule and 0141's
 * default.
 *
 * No error buffer, for `process.h`'s reason: none of the ways of not knowing
 * is a sentence an operator reads, and a lookup that reported them all as
 * failures is a lookup whose return value stops being checked.
 *
 * `family` is dhcpcd's, `4` or `6`, and is the second half of the socket's
 * name.
 */
char *ncfg_dhcpcd_config_file_of(const char *run_dir, const char *interface, const char *family);

#endif /* NCFG_APPLY_H */
