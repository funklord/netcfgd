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
#include "ncfg/document.h"
#include "ncfg/plan.h"

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
 * same double as everything else, and the daemon module is not ported.
 */
size_t ncfg_apply_revert(const ncfg_plan_t *plan, ncfg_journal_t *journal,
    const ncfg_executor_t *executor);

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

/* Fill in the seam. `out` borrows `kernel` and must not outlive it. */
void ncfg_kernel_executor(ncfg_kernel_t *kernel, ncfg_executor_t *out);

#endif /* NCFG_APPLY_H */
