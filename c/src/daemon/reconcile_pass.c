/*
 * reconcile_pass.c -- the order the decisions are carried out in.
 *
 * **Nothing in this file decides anything.** Every rule it applies is a call
 * into `reconcile.c`, and everything it reaches the world with is a seam in
 * `ncfg_reconcile_world_t`. What is left is a sequence, and the sequence is
 * the part of the Rust's loop that carries the most reasons per line:
 *
 *   * the `drift` hooks run **before** the reconcile, so a script sees the
 *     machine as it drifted rather than as netcfgd has just put it back --
 *     which is the only ordering that makes the hook worth having under
 *     `reconcile`, where the window between the two is milliseconds;
 *   * the portal checks run **after** the drift hooks and before the
 *     reconcile, for the same reason;
 *   * a contended radio is given back **before** the reconcile and not inside
 *     it, because once netcfgd holds a backend the plan says "nothing to do"
 *     for that interface and a claim appearing afterwards would never be
 *     looked at again;
 *   * the observation is **never** held by `--no-apply-on-start`; only the
 *     acting is, because a daemon planning against what it saw at startup
 *     answers `apply` with work for a machine that has since moved;
 *   * and the documents either side of a reload are compared, because "the
 *     file was written" is not "the configuration changed" and a confirm
 *     window turns on the difference.
 *
 * A comment can claim an order. `reconcile_test.c` reads it back: every seam
 * records the step it was called for, and the assertion is the list.
 *
 * WHAT IS DEFERRED HERE, RATHER THAN QUIETLY MISSING
 *   **Not `plan.last.json` any more**, and not the fold beside it. Both run in
 *   `record_what_ran`, under the apply lock and before the executor is closed,
 *   and both are the same pair on the revert path in `confirm.c`. The fold was
 *   never waiting on an effect list -- `ncfg_apply_record` takes the plan and
 *   the journal -- and the journal writer was waiting on nothing but being
 *   written.
 *
 *   The `cycle` option a plan is built with. `ncfg_plan_options_t` has none
 *   yet, so this build's planner emits no link cycle for a modem that has
 *   advanced -- and the note is therefore **not cleared**, because clearing a
 *   note whose cycle never happened is the exact defect `ncfg_sims_cycled`
 *   exists to refuse. The filter below expresses "a plan carrying that cycle"
 *   directly, so it is right now and stays right when the option lands.
 */
#include "ncfg/daemon.h"

#include "ncfg/log.h"
#include "ncfg/portal.h"
#include "ncfg/state.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * How many devices one pass may clear a SIM note for.
 *
 * A machine has one modem, or two. Overflowing this leaves the note in place,
 * which is the safe direction and the same one `NCFG_RESOLV_OURS_MAX` takes:
 * a note that survives costs one more cycle attempt, and a note dropped
 * without its cycle leaves the modem on a source nothing ever selected.
 */
#define CYCLES_MAX 16

/* ------------------------------------------------------------------------ *
 * The seams, with what a missing one costs
 * ------------------------------------------------------------------------ */

static uint64_t now_of(const ncfg_reconcile_world_t *world)
{
	if (world->now) {
		return world->now(world->context);
	}
	return ncfg_confirm_now();
}

static void announce(const ncfg_reconcile_world_t *world, const ncfg_proto_event_t *event)
{
	if (world->announce) {
		world->announce(world->context, event);
	}
}

/* An `observed` event, which is what a client redraws on. */
static void announce_summary(const ncfg_reconcile_world_t *world, const char *summary)
{
	ncfg_proto_event_t event;

	memset(&event, 0, sizeof(event));
	event.kind = NCFG_PROTO_EVENT_OBSERVED;
	event.summary = ncfg_proto_str(summary);
	announce(world, &event);
}

static int open_executor(const ncfg_reconcile_world_t *world, ncfg_executor_t *out, char *err,
    size_t err_size)
{
	memset(out, 0, sizeof(*out));
	if (!world->executor_open) {
		ncfg_error_set(err, err_size,
		    "this loop was given no way to change the machine, so it observes and "
		    "reports and does nothing else");
		return 0;
	}
	return world->executor_open(world->context, out, err, err_size);
}

static void close_executor(const ncfg_reconcile_world_t *world, ncfg_executor_t *executor)
{
	if (world->executor_close) {
		world->executor_close(world->context, executor);
	}
}

void ncfg_reconcile_hook_run(void *context, const ncfg_hook_ref_t *hook,
    const ncfg_hook_env_t *env, const char *variable, const char *value)
{
	char message[NCFG_ERROR_MAX];

	(void)context;
	/*
	 * `variable` and `value` are dropped, and that is the one thing this
	 * runner cannot carry: `ncfg_hook_env_t` is `apply.h`'s and has four
	 * fixed members, so `NCFG_ACTION`, `NCFG_BSSID` and `NCFG_URL` are not
	 * set. The pair reaches this seam so that the loop is not where the fact
	 * is lost, and the day that struct grows a general pair this is where the
	 * two lines go.
	 */
	(void)variable;
	(void)value;
	message[0] = '\0';
	/* Never a veto at any of the three phases this runs: the drift has
	 * happened, the station has moved, the portal has answered. There is
	 * nothing left to stop. */
	if (ncfg_hook_run(hook, env, message, sizeof(message)) != NCFG_HOOK_OK) {
		ncfg_log_emitf("hook", NCFG_LOG_NOTE, "%s", message);
	}
}

void ncfg_reconcile_portal_probe(void *context, const char *url, ncfg_portal_result_t *out)
{
	(void)context;
	/* This process' own image, run under the helper's name with the URL as
	 * its one argument, which is what `portal.h` says a caller in the daemon
	 * passes. There is no default in the struct and none invented here. */
	ncfg_portal_probe(NCFG_PORTAL_OWN_IMAGE, url, NCFG_PORTAL_EXPECT_DEFAULT, out);
}

/* Run every hook of one phase that this interface declares. */
static void run_hooks(const ncfg_reconcile_world_t *world, const ncfg_interface_t *interface,
    ncfg_hook_phase_t phase, const char *reason, const char *variable, const char *value)
{
	ncfg_hook_env_t env;
	size_t          at;

	if (!world->hook) {
		return;
	}
	for (at = 0; at < interface->hook_count; at++) {
		if (interface->hooks[at].phase != (int)phase) {
			continue;
		}
		memset(&env, 0, sizeof(env));
		env.iface = interface->name;
		env.reason = reason;
		world->hook(world->context, &interface->hooks[at], &env, variable, value);
	}
}

/* The interface block of this name, or NULL. */
static const ncfg_interface_t *interface_of(const ncfg_document_t *document, const char *name)
{
	size_t at;

	if (!document || !name) {
		return NULL;
	}
	for (at = 0; at < document->interface_count; at++) {
		if (document->interfaces[at].name &&
		    strcmp(document->interfaces[at].name, name) == 0) {
			return &document->interfaces[at];
		}
	}
	return NULL;
}

/* ------------------------------------------------------------------------ *
 * What a phase was told, written back to /run
 * ------------------------------------------------------------------------ */

/* One interface and the thing it was last told, on its way to the record. */
typedef struct {
	const char *interface;
	char        value[NCFG_DRIFT_SUMMARY_MAX];
} telling_t;

typedef struct {
	telling_t at[NCFG_DRIFT_MAX];
	size_t    count;
	int       phase;
} tellings_t;

static void tell(tellings_t *told, const char *interface, const char *value)
{
	telling_t *one;

	if (told->count >= NCFG_DRIFT_MAX) {
		return;
	}
	one = &told->at[told->count++];
	one->interface = interface;
	(void)snprintf(one->value, sizeof(one->value), "%s", value ? value : "");
}

static int note_them(ncfg_owned_state_t *owned, void *context)
{
	const tellings_t *told = context;
	size_t            at;

	for (at = 0; at < told->count; at++) {
		if (!ncfg_owned_note_hook_state(owned, told->at[at].interface, told->phase,
		    told->at[at].value)) {
			return 0;
		}
	}
	return 1;
}

/*
 * Record what a phase was last told, per interface, and nowhere else.
 *
 * Written to `/run` alone: every observation reads the record back, so an
 * in-memory copy beside it would be a second answer that can disagree (0084).
 * A failure is a note rather than a refusal -- the run directory is derived
 * and disposable, and the cost of losing this is a hook that fires twice.
 */
static void remember(const char *run_dir, tellings_t *told)
{
	char message[NCFG_ERROR_MAX];

	if (told->count == 0u) {
		return;
	}
	message[0] = '\0';
	if (!ncfg_owned_update(run_dir, note_them, told, message, sizeof(message))) {
		ncfg_log_emitf("apply", NCFG_LOG_NOTE,
		    "what the %s hooks were told could not be recorded (%s), so they may "
		    "fire again",
		    ncfg_hook_phase_name((ncfg_hook_phase_t)told->phase), message);
	}
}

/*
 * Fold what an apply just did into `owned.json`.
 *
 * **Under the apply lock, which is why it is here and not after the close.**
 * `ncfg_owned_update` takes `owned.lock` of its own, so the file cannot be
 * interleaved either way -- but the apply lock is what makes the read, the
 * change and the write describe one machine rather than two applies' worth of
 * it.
 *
 * A failure is a note rather than a refusal, which is `remember`'s bargain
 * above and is the same one: the run directory is derived and disposable. What
 * it costs is larger here and is said, because an object netcfgd installed and
 * did not record is one it will decline to remove later -- the safe direction,
 * and still a machine that drifts.
 */
static void record_what_ran(const char *run_dir, const ncfg_plan_t *plan,
    const ncfg_journal_t *journal)
{
	char message[NCFG_ERROR_MAX];

	message[0] = '\0';
	if (!ncfg_apply_record(run_dir, plan, journal, message, sizeof(message))) {
		ncfg_log_emitf("apply", NCFG_LOG_NOTE,
		    "what this apply did could not be recorded (%s), so netcfgd will not "
		    "claim those objects as its own", message);
	}
	/*
	 * And the journal beside it, which is the file that answers *where an
	 * apply stopped*. A reconcile has no terminal, so without this a pass that
	 * halted at its third action leaves that fact in the log alone -- and the
	 * Rust's own record of this says the log held two startup lines and
	 * nothing else while `plan.last.json` named the cause exactly.
	 *
	 * After the fold rather than inside it: both take `owned.lock` and `flock`
	 * is held by the open file description, so a call nested in the other's
	 * critical section would be this process waiting on itself.
	 */
	message[0] = '\0';
	if (!ncfg_apply_write_journal(run_dir, journal, message, sizeof(message))) {
		ncfg_log_emitf("apply", NCFG_LOG_NOTE,
		    "the journal of this apply could not be written (%s), so nothing under "
		    "the run directory says where it got to", message);
	}
}

/* ------------------------------------------------------------------------ *
 * The window, the reload, the probes
 * ------------------------------------------------------------------------ */

/*
 * Resolve a window whose timer fired -- or whose timer never started.
 *
 * **A timer resolves the window it was spawned for, and no other.** The
 * message carries no identity, so a timer outliving its own window used to
 * revert whatever window happened to be open when it fired: measured in the
 * Rust, a window confirmed at three seconds left its six-second timer
 * running, a second change armed a new window at five, and at six the first
 * timer reverted the second window two seconds into its life. Asking the
 * window whether it has really expired costs one clock read and cannot be
 * fooled by an extra timer.
 */
static void resolve_window(ncfg_reconcile_t *loop, ncfg_reconcile_report_t *report)
{
	ncfg_confirm_window_t window;
	ncfg_executor_t       executor;
	ncfg_proto_event_t    event;
	char                  message[NCFG_ERROR_MAX];

	if (!ncfg_confirm_read_window(loop->state->paths.run, &window)) {
		return;
	}
	if (!ncfg_confirm_expired_at(&window, now_of(&loop->world))) {
		return;
	}
	message[0] = '\0';
	if (!open_executor(&loop->world, &executor, message, sizeof(message))) {
		ncfg_log_emitf("confirm", NCFG_LOG_ERROR,
		    "a commit-confirm window closed unconfirmed and cannot be put back: %s",
		    message);
		return;
	}
	if (ncfg_confirm_revert(loop->state, loop->armed, &executor,
	    "the window closed unconfirmed", &event, message, sizeof(message))) {
		announce(&loop->world, &event);
		report->window_resolved = 1;
	} else {
		ncfg_log_emitf("confirm", NCFG_LOG_ERROR, "the window could not be resolved: %s",
		    message);
	}
	close_executor(&loop->world, &executor);
}

/*
 * Recompile, and say whether the desired document actually moved.
 *
 * Comparing the document either side is what makes the exclusion true rather
 * than intended: an editor writing the same bytes, or a reload that fails to
 * compile, is a write that leaves the desired document exactly as it was --
 * and either of those on a pass that is also correcting drift would otherwise
 * arm a window over the drift correction, which 0157 says never happens.
 */
static int reload(ncfg_reconcile_t *loop)
{
	char               before[NCFG_DAEMON_HASH_MAX];
	char               after[NCFG_DAEMON_HASH_MAX];
	char               message[NCFG_ERROR_MAX];
	ncfg_proto_event_t event;
	int                had_before;
	int                had_after;
	int                compiled;

	message[0] = '\0';
	had_before = loop->state->desired && ncfg_daemon_document_hash(loop->state->desired, before,
	    message, sizeof(message));
	message[0] = '\0';
	compiled = ncfg_daemon_state_reload(loop->state, message, sizeof(message));
	had_after = loop->state->desired &&
	    ncfg_daemon_document_hash(loop->state->desired, after, message, sizeof(message));

	memset(&event, 0, sizeof(event));
	event.kind = NCFG_PROTO_EVENT_RELOADED;
	event.ok = compiled ? 1u : 0u;
	event.diagnostics = ncfg_proto_str(loop->state->diagnostics);
	announce(&loop->world, &event);

	if (had_before != had_after) {
		return 1;
	}
	return had_before && strcmp(before, after) != 0 ? 1 : 0;
}

/*
 * Move a modem to its next SIM source when its probe says the link is dead.
 *
 * Only a *decided* failure counts (0119, 0152): switching a SIM on no
 * information is what that rule exists to prevent, so a modem with no `probe`
 * block never falls back. Called only when a verdict moved, so a link that has
 * been down for an hour costs nothing.
 */
static void advance_failed_sims(ncfg_reconcile_t *loop, int probes_changed)
{
	size_t at;
	size_t failing;

	if (!probes_changed || !loop->state->desired || !loop->sims) {
		return;
	}
	failing = ncfg_probes_failing_count(loop->probes);
	for (at = 0; at < failing; at++) {
		const char *interface = ncfg_probes_failing_at(loop->probes, at);
		const char *moved_to = NULL;
		char        message[NCFG_ERROR_MAX];

		message[0] = '\0';
		if (!ncfg_sims_advance(loop->sims, loop->state->desired, interface,
		    loop->state->paths.run, &moved_to, message, sizeof(message))) {
			/* Most failing links are not modems at all, which is what the
			 * Rust folds into `None`. Said at verbose so that the two cases
			 * that are real -- a selection that could not be published, and
			 * no memory -- can be found by somebody looking. */
			ncfg_log_emitf("modem", NCFG_LOG_VERBOSE, "%s: %s", interface, message);
			continue;
		}
		if (moved_to) {
			ncfg_log_emitf("modem", NCFG_LOG_NOTE,
			    "%s: probe says this link is dead; trying SIM `%s`", interface,
			    moved_to);
		}
	}
}

/* ------------------------------------------------------------------------ *
 * The hooks that fire on what an observation found
 * ------------------------------------------------------------------------ */

/*
 * Run the `roam` hooks for stations that have just moved.
 *
 * **No de-duplication, unlike `drift`.** That one fires on a condition which
 * persists; a roam is a thing that happened once, and the watcher already
 * reports only a *change* of access point. Suppressing a second would mean a
 * station that moved back and forth told the script once.
 */
static void roam_hooks(ncfg_reconcile_t *loop, const ncfg_reconcile_roam_t *roams,
    size_t roam_count)
{
	size_t at;

	if (!roams || !loop->state->desired) {
		return;
	}
	for (at = 0; at < roam_count; at++) {
		const ncfg_interface_t *interface =
		    interface_of(loop->state->desired, roams[at].interface);
		char reason[NCFG_DRIFT_SUMMARY_MAX];

		if (!interface) {
			continue;
		}
		(void)snprintf(reason, sizeof(reason), "moved to %s",
		    roams[at].bssid ? roams[at].bssid : "");
		run_hooks(&loop->world, interface, NCFG_HOOK_PHASE_ROAM, reason, "NCFG_BSSID",
		    roams[at].bssid);
	}
}

/*
 * Tell the `drift` hooks what has just moved.
 *
 * **Not through the plan**, which every other phase goes through, and the
 * reason is the phase's whole point: drift under `report` produces no apply at
 * all, so a planned hook action would never be executed and the one policy
 * whose purpose is "tell me, do not touch it" would be the one where nothing
 * told anybody. The hook *is* the telling.
 *
 * Recorded whether or not the script succeeded, and whether or not the
 * interface declared one: a hook that failed and was retried on every
 * observation is the storm this exists to avoid, and recording it for an
 * interface with no hook costs one line in `/run` and keeps "has this drift
 * been seen" independent of whether anybody was listening.
 */
static void drift_hooks(ncfg_reconcile_t *loop, const ncfg_drifts_t *drifts)
{
	tellings_t told;
	size_t     at;

	memset(&told, 0, sizeof(told));
	told.phase = (int)NCFG_HOOK_PHASE_DRIFT;
	for (at = 0; at < drifts->count; at++) {
		const ncfg_drift_t     *drift = &drifts->at[at];
		const ncfg_interface_t *interface =
		    interface_of(loop->state->desired, drift->interface);
		const char             *last;

		if (!interface) {
			continue;
		}
		last = ncfg_reconcile_told(loop->state->observed, drift->interface,
		    (int)NCFG_HOOK_PHASE_DRIFT);
		if (!ncfg_reconcile_tells(last, drift->summary)) {
			continue;
		}
		run_hooks(&loop->world, interface, NCFG_HOOK_PHASE_DRIFT, drift->summary,
		    "NCFG_ACTION", drift->action);
		tell(&told, drift->interface, drift->summary);
	}
	remember(loop->state->paths.run, &told);
}

/* Whether netcfgd can see an address on this device that could reach
 * anything. A portal hands out a perfectly ordinary lease, so "addressed" is
 * exactly the moment the machine looks configured and may not be. */
static int is_addressed(const ncfg_observed_t *observed, const char *device)
{
	size_t at;

	if (!observed) {
		return 0;
	}
	for (at = 0; at < observed->address_count; at++) {
		if (observed->addresses[at].interface &&
		    strcmp(observed->addresses[at].interface, device) == 0 &&
		    ncfg_portal_is_routable(observed->addresses[at].address)) {
			return 1;
		}
	}
	return 0;
}

/* Say what the check found, in the words the operator needs. */
static void say_about_portal(const char *device, int verdict,
    const ncfg_portal_answer_t *answer, const char *detail)
{
	if (answer->retrying) {
		ncfg_log_emitf("portal", NCFG_LOG_WARNING,
		    "%s could not be checked: %s (attempt %u of %u)", device, detail,
		    answer->attempt, (unsigned)NCFG_PORTAL_RECORD_ATTEMPTS);
		return;
	}
	if (verdict == (int)NCFG_PORTAL_VERDICT_UNREACHABLE) {
		ncfg_log_emitf("portal", NCFG_LOG_WARNING,
		    "%s could not be checked after %u attempts, giving up until it is "
		    "addressed again: %s",
		    device, (unsigned)NCFG_PORTAL_RECORD_ATTEMPTS, detail);
		return;
	}
	if (verdict == (int)NCFG_PORTAL_VERDICT_PORTAL) {
		ncfg_log_emitf("portal", NCFG_LOG_NOTE, "%s looks like a captive portal: %s",
		    device, detail);
	}
	/* `Clear` is said to nobody: a hook that ran on every successful join is a
	 * hook nobody keeps, and a log line on every one is the same thing said to
	 * the journal. */
}

/*
 * Ask, once per joining, whether something is intercepting traffic.
 *
 * **Not a plan action.** A probe is not a change, so an action would run on
 * every apply and no plan would ever converge. It is also not something an
 * observation can answer: netcfgd has to *ask*, which is I/O, and doing it on
 * every netlink event would be a request to somebody else's server every time
 * a cable moved. So it fires on a transition, and only where the operator gave
 * a URL (0061, 0095).
 */
static void portal_checks(ncfg_reconcile_t *loop)
{
	const ncfg_document_t *document = loop->state->desired;
	tellings_t             told;
	size_t                 at;

	if (!document || !loop->world.portal) {
		return;
	}
	memset(&told, 0, sizeof(told));
	told.phase = (int)NCFG_HOOK_PHASE_PORTAL;

	for (at = 0; at < document->device_count; at++) {
		const ncfg_device_t    *device = &document->devices[at];
		const ncfg_interface_t *interface;
		const char             *url;
		const char             *was;
		ncfg_portal_step_t      step;
		ncfg_portal_result_t    found;
		ncfg_portal_answer_t    answer;
		/* The prefix plus a whole detail: `NCFG_REASON` reaches a root
		 * shell and `portal.h` has already made it legible, so what must
		 * not happen here is losing the end of it to a shorter buffer. */
		char                    reason[NCFG_ERROR_MAX + 32];
		unsigned                attempts = 0;

		url = device->wifi ? device->wifi->portal_check : NULL;
		if (!url || !device->name) {
			continue;
		}
		was = ncfg_reconcile_told(loop->state->observed, device->name,
		    (int)NCFG_HOOK_PHASE_PORTAL);
		step = ncfg_portal_step(is_addressed(loop->state->observed, device->name), was,
		    &attempts);
		if (step == NCFG_PORTAL_STEP_NOTHING) {
			continue;
		}
		if (step == NCFG_PORTAL_STEP_BARE) {
			tell(&told, device->name, NCFG_PORTAL_RECORD_BARE);
			continue;
		}

		memset(&found, 0, sizeof(found));
		/* Always a verdict: everything that can go wrong on netcfgd's side
		 * is `unreachable` with a sentence, because a probe that could not
		 * be run has not found a portal. */
		found.verdict = (int)NCFG_PORTAL_VERDICT_UNREACHABLE;
		loop->world.portal(loop->world.context, url, &found);
		ncfg_portal_answered(found.verdict, attempts, &answer);
		say_about_portal(device->name, found.verdict, &answer, found.detail);
		tell(&told, device->name, answer.record);
		if (!answer.run_hooks) {
			continue;
		}
		interface = interface_of(document, device->name);
		if (!interface) {
			continue;
		}
		(void)snprintf(reason, sizeof(reason), "a captive portal answered: %s", found.detail);
		run_hooks(&loop->world, interface, NCFG_HOOK_PHASE_PORTAL, reason, "NCFG_URL", url);
	}
	remember(loop->state->paths.run, &told);
}

/* ------------------------------------------------------------------------ *
 * Putting back what drifted
 * ------------------------------------------------------------------------ */

/*
 * The pending devices whose cycle this plan actually carries.
 *
 * `ncfg_sims_cycled` reads "no records at all" as "no cycle was needed", so
 * asking the plan for the `link.down` is what tells a note that was acted on
 * from one that was not. **The option has landed**, and this is why it is
 * still asked rather than assumed: the planner declines a cycle for a device
 * it will not touch -- an unmanaged one, or a link that is already down -- so
 * a note whose cycle the planner refused must stay, and clearing it on the
 * strength of having asked would leave the modem on a source nothing selected.
 */
static size_t cycles_in(const ncfg_plan_t *plan, const ncfg_sims_t *sims, const char **out,
    size_t out_max)
{
	size_t kept = 0;
	size_t at;
	size_t pending = ncfg_sims_pending_count(sims);

	for (at = 0; at < pending; at++) {
		const char *device = ncfg_sims_pending_at(sims, at);
		size_t      action;

		if (!device) {
			continue;
		}
		for (action = 0; action < plan->action_count; action++) {
			const char *interface = ncfg_op_interface(&plan->actions[action].op);

			if (plan->actions[action].op.kind != (int)NCFG_OP_LINK_DOWN ||
			    !interface || strcmp(interface, device) != 0) {
				continue;
			}
			if (kept < out_max) {
				out[kept] = device;
			}
			kept++;
			break;
		}
	}
	return kept < out_max ? kept : out_max;
}

/* What a window over this change would be, and what it would fall back to. */
typedef struct {
	ncfg_arm_t       answer;
	uint32_t         seconds;
	ncfg_document_t *last_good;
} arming_t;

/*
 * Decide the window before anything is applied, and arm it afterwards.
 *
 * Asked of the planner rather than re-derived: the rule has three cases --
 * the caller's number, the caller's zero meaning "no window despite the
 * default", and the document's own -- and a second copy of it beside this one
 * is how the two would stop agreeing.
 */
static void decide_arming(ncfg_reconcile_t *loop, int config_is_new, arming_t *out)
{
	ncfg_optint_t window;
	char          message[NCFG_ERROR_MAX];

	memset(out, 0, sizeof(*out));
	window = ncfg_plan_confirm_window(loop->state->desired, NULL);
	if (config_is_new && window.has && window.value > 0) {
		message[0] = '\0';
		out->last_good = ncfg_confirm_may_arm(loop->state, message, sizeof(message));
		if (!out->last_good) {
			/* Said out loud rather than swallowed: nobody asked for this
			 * window, so an operator who set the key and watched the change
			 * apply would otherwise believe they had one. */
			ncfg_log_emitf("confirm", NCFG_LOG_WARNING,
			    "not arming a window for this change: %s", message);
		}
	}
	out->answer = ncfg_reconcile_arms(config_is_new, window, out->last_good);
	if (out->answer == NCFG_ARM_YES) {
		out->seconds = (uint32_t)window.value;
		return;
	}
	if (out->answer == NCFG_ARM_EMPTY_LAST_GOOD) {
		ncfg_log_emitf("confirm", NCFG_LOG_WARNING, "not arming a window for this change: %s",
		    ncfg_reconcile_arm_why(out->answer));
	}
}

/*
 * Open the window, after the apply and even where the apply failed part-way:
 * a half-applied change is exactly what a window is for, and refusing to arm
 * one there would withhold the safety net from the case that needs it most.
 */
static void arm_window(ncfg_reconcile_t *loop, const ncfg_plan_t *applied,
    const ncfg_journal_t *journal, arming_t *arming, ncfg_reconcile_report_t *report)
{
	ncfg_proto_event_t event;
	char               message[NCFG_ERROR_MAX];

	if (arming->answer != NCFG_ARM_YES) {
		return;
	}
	message[0] = '\0';
	/* What to undo if nobody confirms, set *before* the window is opened, so
	 * there is no instant in which a window is open with nothing recorded
	 * against it. */
	if (loop->armed && loop->state->desired) {
		ncfg_confirm_armed_free(loop->armed);
		if (!ncfg_confirm_armed_from(applied, journal, loop->state->desired, loop->armed,
		    message, sizeof(message))) {
			ncfg_log_emitf("confirm", NCFG_LOG_ERROR,
			    "what this change would undo could not be recorded (%s), so the "
			    "window falls back to re-planning against the last-good "
			    "configuration",
			    message);
		}
	}
	message[0] = '\0';
	if (!ncfg_confirm_arm(loop->state, arming->seconds, arming->last_good, &event, message,
	    sizeof(message))) {
		/* **Refused rather than announced.** The Rust logs this and hands
		 * back the event anyway, so a full or read-only `/run` told every
		 * client the change was covered while nothing on disk would ever
		 * resolve it. */
		ncfg_log_emitf("confirm", NCFG_LOG_ERROR, "the window could not be opened: %s",
		    message);
		if (loop->armed) {
			ncfg_confirm_armed_free(loop->armed);
		}
		return;
	}
	if (loop->world.expiry) {
		loop->world.expiry(loop->world.context, arming->seconds);
	}
	announce(&loop->world, &event);
	report->armed = 1;
}

/* Count the reclaim, and sweep where something will not stop taking
 * `/etc/resolv.conf` back. */
static void guard_resolv(ncfg_reconcile_t *loop, const ncfg_plan_t *applied,
    ncfg_reconcile_report_t *report)
{
	if (!ncfg_reconcile_sweeps(&loop->reclaims, ncfg_reconcile_reclaimed(applied))) {
		return;
	}
	report->swept = 1;
	if (!loop->world.resolv) {
		/* The seam has no default and this is not the place to invent one:
		 * whoever sweeps says what they are sweeping. */
		ncfg_log_emitf("dns", NCFG_LOG_WARNING,
		    "/etc/resolv.conf has been taken back %d times running and this daemon "
		    "was given no way to look at what is doing it",
		    NCFG_RESOLV_PATIENCE);
		return;
	}
	report->signalled = ncfg_resolv_sweep(loop->state->paths.run, loop->world.resolv);
}

/*
 * Put back what drifted, on the interfaces whose policy says to.
 *
 * **Not `nothing reconciles` alone.** A host whose only reconcilable state is
 * `resolv.conf` has no interface in that answer -- a `global { dns { .. } }`
 * block with no `interface` block at all is an ordinary configuration -- so
 * the host-wide half is asked separately and an empty restriction is what
 * decides there is nothing to do (0165).
 */
static void reconcile_drift(ncfg_reconcile_t *loop, const ncfg_plan_t *plan, int config_is_new,
    ncfg_reconcile_report_t *report)
{
	ncfg_plan_t    *restricted;
	ncfg_buf_t      dropped;
	ncfg_journal_t  journal;
	ncfg_executor_t executor;
	arming_t        arming;
	const char     *cycled[CYCLES_MAX];
	size_t          cycles;
	char            message[NCFG_ERROR_MAX];
	char            summary[NCFG_DRIFT_SUMMARY_MAX];
	int             moved = 0;

	ncfg_buf_init(&dropped, NCFG_LOG_MAX);
	message[0] = '\0';
	restricted = ncfg_reconcile_restrict(plan, loop->state->desired, loop->sims,
	    ncfg_reconcile_host_wide(loop->state->desired), &dropped, message, sizeof(message));
	if (!restricted) {
		ncfg_log_emitf("apply", NCFG_LOG_ERROR, "this pass could not be planned: %s",
		    message);
		ncfg_buf_free(&dropped);
		return;
	}
	if (restricted->action_count == 0u) {
		ncfg_plan_free(restricted);
		ncfg_buf_free(&dropped);
		return;
	}
	if (!ncfg_buf_failed(&dropped) && ncfg_buf_text(&dropped)[0] != '\0') {
		ncfg_log_emitf("apply", NCFG_LOG_NOTE, "not reconciled in isolation: %s",
		    ncfg_buf_text(&dropped));
	}
	ncfg_buf_free(&dropped);

	/* After the early returns, not before them: computing it earlier
	 * announced a refusal to arm on a pass that then applied nothing at all,
	 * which is a message about a change that never happened. */
	decide_arming(loop, config_is_new, &arming);

	/* The cycles waiting to happen, taken before the plan and cleared only
	 * after it ran: a plan that could not be applied leaves the note in place
	 * so the next pass tries again. */
	cycles = ncfg_sims_pending_count(loop->sims) == 0u
	    ? 0u
	    : cycles_in(restricted, loop->sims, cycled, CYCLES_MAX);

	message[0] = '\0';
	if (!open_executor(&loop->world, &executor, message, sizeof(message))) {
		ncfg_log_emitf("apply", NCFG_LOG_ERROR,
		    "cannot start an apply to reconcile drift: %s", message);
		ncfg_document_free(arming.last_good);
		ncfg_plan_free(restricted);
		return;
	}
	ncfg_journal_init(&journal);
	message[0] = '\0';
	(void)ncfg_apply(restricted, &executor, &journal, message, sizeof(message));
	record_what_ran(loop->state->paths.run, restricted, &journal);
	close_executor(&loop->world, &executor);

	guard_resolv(loop, restricted, report);
	ncfg_sims_cycled(loop->sims, cycled, cycles, &journal);
	(void)ncfg_daemon_state_reobserve(loop->state, &moved, message, sizeof(message));
	arm_window(loop, restricted, &journal, &arming, report);

	/*
	 * **A failed reconcile used to say nothing at all.** The startup apply
	 * prints the action that failed and this path did not, so the only trace
	 * of a broken pass was a count in an event nobody is subscribed to and a
	 * file under `/run` that has to be gone looking for.
	 */
	if (ncfg_journal_failure(&journal)) {
		const ncfg_record_t *failure = ncfg_journal_failure(&journal);

		ncfg_log_emitf("apply", NCFG_LOG_ERROR,
		    "reconcile stopped at %s: %s; %zu done, %zu not attempted", failure->op,
		    failure->error ? failure->error : "no detail", ncfg_journal_done(&journal),
		    ncfg_journal_skipped(&journal));
	}
	report->reconciled = 1;
	report->actions_done = ncfg_journal_done(&journal);
	(void)snprintf(summary, sizeof(summary), "reconciled %zu actions",
	    ncfg_journal_done(&journal));
	announce_summary(&loop->world, summary);

	ncfg_journal_free(&journal);
	ncfg_document_free(arming.last_good);
	ncfg_plan_free(restricted);
}

/* ------------------------------------------------------------------------ *
 * Looking at the machine
 * ------------------------------------------------------------------------ */

/* Re-read the kernel, and put on it the two things an observation cannot
 * carry by itself: the probe verdicts, which come from running the operator's
 * programs, and which card each SIM source turned out to hold. */
static void reobserve(ncfg_reconcile_t *loop, ncfg_reconcile_report_t *report)
{
	char message[NCFG_ERROR_MAX];
	int  moved = 0;

	message[0] = '\0';
	if (!ncfg_daemon_state_reobserve(loop->state, &moved, message, sizeof(message))) {
		ncfg_log_emitf("netlink", NCFG_LOG_WARNING,
		    "the machine could not be re-read (%s); the previous observation stands",
		    message);
		return;
	}
	message[0] = '\0';
	/* After the kernel and before anything reads it: the planner asks the
	 * observation whether a link is reaching anything, and one without the
	 * verdicts stamped on would answer "nobody asked" for a link a probe has
	 * just declared down. */
	if (!ncfg_probes_apply(loop->probes, loop->state->observed, message, sizeof(message))) {
		ncfg_log_emitf("probe", NCFG_LOG_NOTE, "a probe verdict was not recorded: %s",
		    message);
	}
	message[0] = '\0';
	if (loop->state->observed &&
	    !ncfg_sims_observe(loop->sims, loop->state->desired, loop->state->observed->reports,
	    loop->state->observed->report_count, message, sizeof(message))) {
		ncfg_log_emitf("modem", NCFG_LOG_NOTE, "a reported SIM card was not recorded: %s",
		    message);
	}
	if (moved) {
		report->links_moved = 1;
		/* **A link appearing or going away is an event even when netcfgd does
		 * nothing about it**, which is exactly the unmanaged device: deleting
		 * one produced no drift, no reconcile and no event, and a client with
		 * no other trigger went on serving a device whose link was gone. */
		announce_summary(&loop->world, "the links the kernel reports have changed");
	}
}

/*
 * Everything a pass does when something moved.
 *
 * The order is the subject of this file's header comment, and it is this
 * function.
 */
static void look(ncfg_reconcile_t *loop, int config_is_new, const ncfg_proto_request_t *requests,
    size_t request_count, ncfg_reconcile_report_t *report)
{
	ncfg_drifts_t         *drifts;
	ncfg_plan_t           *plan;
	ncfg_plan_options_t    options;
	ncfg_confirm_window_t  window;
	const char            *wanted[CYCLES_MAX];
	char                   message[NCFG_ERROR_MAX];
	size_t                 pending;
	size_t                 at;

	report->looked = 1;
	reobserve(loop, report);

	if (!loop->state->desired || !loop->state->observed) {
		/* Nothing to compare the machine against. The observation above is
		 * still worth having: it is what the daemon answers `status` from. */
		return;
	}
	/*
	 * **The cycles go into the plan rather than being done to it.** 0152's
	 * option half: a modem the daemon advanced needs its link taken down and
	 * brought back so the `pre_up` hook acts on the new selection, and doing
	 * that by handing an executor a `link.down` of this module's own making
	 * would go round the `managed` choke point 0035 exists to be. So the
	 * planner is told, and it decides -- including declining an unmanaged
	 * device, which is the whole point.
	 */
	memset(&options, 0, sizeof(options));
	for (pending = 0; pending < ncfg_sims_pending_count(loop->sims) &&
	    pending < (size_t)CYCLES_MAX; pending++) {
		wanted[pending] = ncfg_sims_pending_at(loop->sims, pending);
	}
	options.cycle = wanted;
	options.cycle_count = pending;
	message[0] = '\0';
	plan = ncfg_plan_build(loop->state->desired, loop->state->observed, &options, message,
	    sizeof(message));
	if (!plan) {
		ncfg_log_emitf("apply", NCFG_LOG_ERROR, "this machine could not be planned for: %s",
		    message);
		return;
	}
	/*
	 * **One plan where the Rust builds two.** `detect_drift` builds its own
	 * and `reconcile_drift` builds another a few lines later, from the same
	 * document and the same observation -- and nothing between them touches
	 * either, so the second can only ever be the first again. The hooks and
	 * the contention stop below change the *machine*; neither re-observes, so
	 * what a plan is computed from is unchanged.
	 */
	drifts = calloc(1u, sizeof(*drifts));
	if (!drifts) {
		ncfg_log_emitf("apply", NCFG_LOG_ERROR, "not enough memory to report drift");
		ncfg_plan_free(plan);
		return;
	}
	ncfg_reconcile_drift(plan, loop->state->desired, drifts);
	report->drift_count = drifts->count;
	for (at = 0; at < drifts->count; at++) {
		ncfg_proto_event_t event;

		ncfg_drift_event(&drifts->at[at], &event);
		announce(&loop->world, &event);
	}
	if (drifts->total > drifts->count) {
		ncfg_log_emitf("apply", NCFG_LOG_NOTE,
		    "%zu of %zu drifting things are reported; the rest are the same fight",
		    drifts->count, drifts->total);
	}

	/* Before the reconcile, so a script sees the machine as it drifted. */
	drift_hooks(loop, drifts);
	/* After the drift hooks and before the reconcile, for the same reason. */
	portal_checks(loop);
	free(drifts);

	/* Before the reconcile, and not inside it. */
	if (loop->world.release_contended) {
		message[0] = '\0';
		if (!loop->world.release_contended(loop->world.context, loop->state, message,
		    sizeof(message))) {
			ncfg_log_emitf("contention", NCFG_LOG_ERROR,
			    "a contended radio could not be given back: %s", message);
		}
	}

	if (loop->holding) {
		/* Observing is not holding. */
		ncfg_plan_free(plan);
		return;
	}
	if (ncfg_reconcile_defers(ncfg_confirm_read_window(loop->state->paths.run, &window),
	    requests, request_count)) {
		ncfg_plan_free(plan);
		return;
	}
	reconcile_drift(loop, plan, config_is_new, report);
	ncfg_plan_free(plan);
}

/* ------------------------------------------------------------------------ *
 * Starting, and one pass
 * ------------------------------------------------------------------------ */

int ncfg_reconcile_establish_last_good(const ncfg_daemon_state_t *state, char *err,
    size_t err_size)
{
	ncfg_document_t *found;
	ncfg_document_t *empty;
	char             message[NCFG_ERROR_MAX];
	int              wrote;

	if (!state) {
		ncfg_error_set(err, err_size, "there is no state to record a last-good for");
		return 0;
	}
	message[0] = '\0';
	found = ncfg_confirm_read_last_good(state->paths.run, message, sizeof(message));
	if (found) {
		ncfg_document_free(found);
		return 1;
	}
	empty = ncfg_document_new(err, err_size);
	if (!empty) {
		return 0;
	}
	wrote = ncfg_confirm_write_last_good(state->paths.run, empty, err, err_size);
	ncfg_document_free(empty);
	if (wrote) {
		ncfg_log_emitf("confirm", NCFG_LOG_NOTE,
		    "no previous configuration recorded, so a revert would undo everything "
		    "netcfgd does from here. `ncfg apply --confirm-within N` works from the "
		    "first apply.");
	}
	return wrote;
}

int ncfg_reconcile_converge(ncfg_reconcile_t *loop, ncfg_reconcile_report_t *report, char *err,
    size_t err_size)
{
	ncfg_reconcile_report_t ignored;
	ncfg_plan_t            *plan;
	ncfg_journal_t          journal;
	ncfg_executor_t         executor;
	char                    message[NCFG_ERROR_MAX];
	char                    summary[NCFG_DRIFT_SUMMARY_MAX];
	size_t                  at;
	int                     moved = 0;

	if (!loop || !loop->state) {
		ncfg_error_set(err, err_size, "there is no loop to converge");
		return 0;
	}
	if (!report) {
		memset(&ignored, 0, sizeof(ignored));
		report = &ignored;
	}
	if (!loop->state->desired) {
		ncfg_log_emitf("apply", NCFG_LOG_ERROR,
		    "there is no compiled configuration, so nothing was applied");
		return 1;
	}
	message[0] = '\0';
	if (!open_executor(&loop->world, &executor, message, sizeof(message))) {
		ncfg_log_emitf("apply", NCFG_LOG_ERROR, "cannot start an apply: %s", message);
		return 1;
	}
	message[0] = '\0';
	plan = ncfg_plan_build(loop->state->desired, loop->state->observed, NULL, message,
	    sizeof(message));
	if (!plan) {
		close_executor(&loop->world, &executor);
		ncfg_error_set(err, err_size, "the startup apply could not be planned: %s",
		    message);
		return 0;
	}
	ncfg_journal_init(&journal);
	message[0] = '\0';
	(void)ncfg_apply(plan, &executor, &journal, message, sizeof(message));
	record_what_ran(loop->state->paths.run, plan, &journal);
	close_executor(&loop->world, &executor);

	if (ncfg_journal_failure(&journal)) {
		const ncfg_record_t *failure = ncfg_journal_failure(&journal);

		ncfg_log_emitf("apply", NCFG_LOG_ERROR, "%s failed: %s", failure->op,
		    failure->error ? failure->error : "no detail");
	}
	for (at = 0; at < plan->refusal_count; at++) {
		ncfg_log_emitf("apply", NCFG_LOG_WARNING, "refused %s on %s -- %s depends on it",
		    plan->refusals[at].op, plan->refusals[at].interface,
		    plan->refusals[at].guard);
	}
	(void)ncfg_daemon_state_reobserve(loop->state, &moved, message, sizeof(message));

	/*
	 * This configuration is now the one in effect, so it is what a future
	 * window falls back to. Without recording it, the first
	 * `apply --confirm-within` after a boot is refused for having nothing to
	 * revert to -- which is safe, and useless.
	 */
	if (ncfg_journal_succeeded(&journal)) {
		message[0] = '\0';
		if (!ncfg_confirm_write_last_good(loop->state->paths.run, loop->state->desired,
		    message, sizeof(message))) {
			ncfg_log_emitf("confirm", NCFG_LOG_WARNING,
			    "this configuration could not be recorded as the one to fall back "
			    "to: %s",
			    message);
		}
	}
	report->reconciled = 1;
	report->actions_done = ncfg_journal_done(&journal);
	(void)snprintf(summary, sizeof(summary), "applied %zu actions",
	    ncfg_journal_done(&journal));
	announce_summary(&loop->world, summary);

	ncfg_journal_free(&journal);
	ncfg_plan_free(plan);
	return 1;
}

int ncfg_reconcile_start(ncfg_reconcile_t *loop, int apply_on_start, int reverted, char *err,
    size_t err_size)
{
	if (!loop) {
		ncfg_error_set(err, err_size, "there is no loop to start");
		return 0;
	}
	/* A latch, not a startup skip: once the loop reconciles on its own,
	 * `--no-apply-on-start` has to keep meaning something, or it delays
	 * acting by one tick and no more. */
	loop->holding = apply_on_start ? 0 : 1;
	if (!apply_on_start || reverted) {
		/* A machine that has just been put back is not one to apply over. */
		return 1;
	}
	return ncfg_reconcile_converge(loop, NULL, err, err_size);
}

int ncfg_reconcile_pass(ncfg_reconcile_t *loop, const ncfg_reconcile_wake_t *wake,
    const ncfg_reconcile_roam_t *roams, size_t roam_count,
    const ncfg_proto_request_t *requests, size_t request_count,
    ncfg_reconcile_report_t *report, char *err, size_t err_size)
{
	ncfg_reconcile_report_t ignored;
	ncfg_reconcile_wake_t   quiet;
	char                    message[NCFG_ERROR_MAX];
	int                     config_is_new = 0;
	int                     probes_changed = 0;

	if (!loop || !loop->state) {
		ncfg_error_set(err, err_size, "there is no loop to run a pass of");
		return 0;
	}
	if (!report) {
		memset(&ignored, 0, sizeof(ignored));
		report = &ignored;
	}
	memset(report, 0, sizeof(*report));
	if (!wake) {
		memset(&quiet, 0, sizeof(quiet));
		wake = &quiet;
	}

	if (ncfg_reconcile_should_resolve_window(wake->confirm_expired, wake->ticked)) {
		resolve_window(loop, report);
	}
	/* Before anything re-observes, so a `roam` script sees the machine as the
	 * move left it. Nothing here re-plans: a station moving within its own
	 * network changes no desired state, which is why it is a hook and not
	 * drift. */
	roam_hooks(loop, roams, roam_count);

	if (wake->config_changed) {
		report->reloaded = 1;
		config_is_new = reload(loop);
		report->config_is_new = config_is_new;
	}

	message[0] = '\0';
	if (loop->probes && !ncfg_probes_run_due(loop->probes, loop->state->desired,
	    loop->state->observed, &probes_changed, message, sizeof(message))) {
		ncfg_log_emitf("probe", NCFG_LOG_ERROR, "the due probes could not be run: %s",
		    message);
	}
	report->probes_changed = probes_changed;
	advance_failed_sims(loop, probes_changed);

	if (ncfg_reconcile_looks(wake, probes_changed)) {
		look(loop, config_is_new, requests, request_count, report);
	}

	if (loop->holding && ncfg_reconcile_releases_hold(requests, request_count)) {
		loop->holding = 0;
		report->released_hold = 1;
	}
	return 1;
}
