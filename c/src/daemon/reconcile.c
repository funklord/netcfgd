/*
 * reconcile.c -- what the loop decides, with nothing in it that acts.
 *
 * **Nothing in this file opens a descriptor, reads a clock, runs a program or
 * writes a byte.** Every call takes values and answers one, which is the
 * whole reason the file exists: the Rust's loop owns a channel, four watcher
 * threads, a timer and a socket, so the rules inside it can only be exercised
 * by standing a daemon up -- and its own comments say so, once, where
 * `a_window_is_requested` was split out of `defers_to_a_window` because "a
 * predicate that cannot be exercised without building one is a predicate
 * nothing exercises". Everything that decides something is split out here, and
 * `reconcile_pass.c` is the order those answers are acted on in.
 *
 * WHAT THAT BUYS, CONCRETELY
 *   `reconcile_test.c` walks these rather than sampling them: every arm of the
 *   portal record, every reason a window is not armed, the reclaim count
 *   across a run of passes, a plan restricted to nothing. None of that needs a
 *   kernel, a `/run`, a clock or a second of waiting.
 *
 * WHAT IS NOT A DECISION AND SO IS NOT HERE
 *   Reading the window file, taking the apply lock, running a hook, asking a
 *   URL, signalling a process. Each is a seam in `ncfg_reconcile_world_t` and
 *   the pass is what reaches through it.
 */
#include "ncfg/daemon.h"

#include "ncfg/log.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* What a plan says when a reason names nothing. The plan renders an absent
 * value as `<absent>` itself, so this is only ever a field the builder left
 * out entirely. */
static const char *or_unknown(const char *text)
{
	return text ? text : "?";
}

/* ------------------------------------------------------------------------ *
 * What woke it
 * ------------------------------------------------------------------------ */

void ncfg_reconcile_collapse(ncfg_reconcile_wake_t *wake, ncfg_woke_t woke)
{
	if (!wake) {
		return;
	}
	switch (woke) {
	case NCFG_WOKE_KERNEL:
		wake->kernel_changed = 1;
		break;
	case NCFG_WOKE_CONFIG:
		wake->config_changed = 1;
		break;
	case NCFG_WOKE_CONFIRM_EXPIRED:
		wake->confirm_expired = 1;
		break;
	case NCFG_WOKE_TICK:
		wake->ticked = 1;
		break;
	default:
		/* A command this build does not know is not a reason to look at the
		 * machine, and not a reason to stop either. */
		break;
	}
}

int ncfg_reconcile_looks(const ncfg_reconcile_wake_t *wake, int probe_changed)
{
	if (!wake) {
		return probe_changed ? 1 : 0;
	}
	if (wake->kernel_changed || wake->config_changed || wake->ticked) {
		return 1;
	}
	return probe_changed ? 1 : 0;
}

int ncfg_reconcile_should_resolve_window(int confirm_expired, int ticked)
{
	return (confirm_expired || ticked) ? 1 : 0;
}

/* ------------------------------------------------------------------------ *
 * What the waiting requests say
 * ------------------------------------------------------------------------ */

int ncfg_reconcile_window_requested(const ncfg_proto_request_t *requests, size_t count)
{
	size_t at;

	if (!requests) {
		return 0;
	}
	for (at = 0; at < count; at++) {
		if (requests[at].kind != NCFG_PROTO_REQ_APPLY) {
			continue;
		}
		/*
		 * A zero is `--confirm-within 0`, which is how an operator declines a
		 * window on a machine whose configuration sets one (0094). It is not
		 * a window, so it must not hold the reconcile off -- and a negative
		 * number is not one either: `ncfg_proto_int_t` carries whatever
		 * integer arrived, and the protocol's own type is unsigned.
		 */
		if (requests[at].u.apply.confirm.present && requests[at].u.apply.confirm.value > 0) {
			return 1;
		}
	}
	return 0;
}

int ncfg_reconcile_releases_hold(const ncfg_proto_request_t *requests, size_t count)
{
	size_t at;

	if (!requests) {
		return 0;
	}
	for (at = 0; at < count; at++) {
		/* Any apply, with a window or without one: what the hold was waiting
		 * for is the operator saying go. */
		if (requests[at].kind == NCFG_PROTO_REQ_APPLY) {
			return 1;
		}
	}
	return 0;
}

int ncfg_reconcile_defers(int window_open, const ncfg_proto_request_t *requests, size_t count)
{
	if (window_open) {
		return 1;
	}
	return ncfg_reconcile_window_requested(requests, count);
}

/* ------------------------------------------------------------------------ *
 * Drift
 * ------------------------------------------------------------------------ */

ncfg_drift_policy_t ncfg_reconcile_policy_for(const ncfg_document_t *document,
    const char *interface)
{
	size_t at;

	if (!document) {
		/* No configuration is not a licence to change anything. */
		return NCFG_DRIFT_POLICY_REPORT;
	}
	if (interface) {
		for (at = 0; at < document->interface_count; at++) {
			const ncfg_interface_t *one = &document->interfaces[at];

			if (!one->name || strcmp(one->name, interface) != 0) {
				continue;
			}
			if (one->on_drift.has) {
				return (ncfg_drift_policy_t)one->on_drift.value;
			}
			break;
		}
	}
	return (ncfg_drift_policy_t)document->globals.on_drift_default;
}

int ncfg_reconcile_host_wide(const ncfg_document_t *document)
{
	if (!document) {
		return 0;
	}
	return document->globals.on_drift_default == (int)NCFG_DRIFT_POLICY_RECONCILE ? 1 : 0;
}

int ncfg_reconcile_reconciles(const ncfg_document_t *document, const ncfg_sims_t *sims,
    const char *interface)
{
	size_t at;

	if (!document || !interface) {
		return 0;
	}
	for (at = 0; at < document->interface_count; at++) {
		const ncfg_interface_t *one = &document->interfaces[at];

		if (!one->name || strcmp(one->name, interface) != 0) {
			continue;
		}
		/* The two exceptions, neither of which is drift: see the header. */
		if (ncfg_sims_is_pending(sims, interface) || one->preference.has) {
			return 1;
		}
		if (ncfg_reconcile_policy_for(document, interface) ==
		    NCFG_DRIFT_POLICY_RECONCILE) {
			return 1;
		}
		return 0;
	}
	/* An interface the document does not name is not one netcfgd reconciles:
	 * a plan can only carry an action for it if something else in the
	 * document asked for it, and acting there would be netcfgd changing a
	 * device nobody configured. */
	return 0;
}

ncfg_plan_t *ncfg_reconcile_restrict(const ncfg_plan_t *plan, const ncfg_document_t *document,
    const ncfg_sims_t *sims, int host_wide, ncfg_buf_t *dropped, char *err, size_t err_size)
{
	ncfg_plan_t *kept;
	char        *in_set = NULL;
	size_t       at;

	if (!plan) {
		ncfg_error_set(err, err_size, "there is no plan to restrict");
		return NULL;
	}
	kept = ncfg_plan_new(err, err_size);
	if (!kept) {
		return NULL;
	}
	if (plan->action_count != 0u) {
		/* Indexed by action id, which `ncfg_plan_add` assigns as the
		 * position: one byte per action rather than a search per edge. */
		in_set = calloc(plan->action_count, 1u);
		if (!in_set) {
			ncfg_plan_free(kept);
			ncfg_error_set(err, err_size,
			    "not enough memory to restrict a plan of %zu actions",
			    plan->action_count);
			return NULL;
		}
	}

	for (at = 0; at < plan->action_count; at++) {
		const ncfg_action_t *action = &plan->actions[at];
		const char          *interface = ncfg_op_interface(&action->op);
		const uint32_t      *missing = NULL;
		size_t               edge;
		int                  wanted;

		/*
		 * A host-wide action belongs to no interface, so the per-interface
		 * filter could only ever drop it -- which is how a `resolv.conf`
		 * another resolver had overwritten could never be put back (0165).
		 * The three commit ops name no interface either and are deliberately
		 * not swept in by this.
		 */
		if (ncfg_op_is_host_wide_config(&action->op)) {
			wanted = host_wide;
		} else {
			wanted = ncfg_reconcile_reconciles(document, sims, interface);
		}
		if (!wanted) {
			continue;
		}
		for (edge = 0; edge < action->depends_count; edge++) {
			uint32_t id = action->depends_on[edge];

			if ((size_t)id >= plan->action_count || !in_set[id]) {
				missing = &action->depends_on[edge];
				break;
			}
		}
		if (missing) {
			/* Named rather than dropped quietly: applying it would run out
			 * of order, and silently applying a subset that happens to work
			 * is how a reconciler becomes unpredictable. */
			if (dropped) {
				ncfg_buf_addf(dropped,
				    "%s on %s needs action %u, which belongs to another "
				    "interface\n",
				    ncfg_op_name(&action->op), or_unknown(interface),
				    (unsigned)*missing);
			}
			continue;
		}
		(void)ncfg_plan_add(kept, &action->op, &action->reason, action->depends_on,
		    action->depends_count, action->has_inverse ? &action->inverse : NULL);
		if (action->id < plan->action_count) {
			in_set[action->id] = 1;
		}
	}

	/*
	 * The refusals and the stranded credentials come across whole, because
	 * restricting a plan changes what will be *done* and not what is true
	 * about the configuration: a key left on a device the operator did not
	 * ask about is still a key left. The warnings deliberately do not --
	 * `ncfg_plan_add` writes the "cannot be undone" one as each action is
	 * copied, so carrying the source's list over would say it twice.
	 */
	for (at = 0; at < plan->refusal_count; at++) {
		ncfg_plan_refuse(kept, &plan->refusals[at]);
	}
	for (at = 0; at < plan->stranded_count; at++) {
		ncfg_plan_strand(kept, &plan->stranded[at]);
	}
	free(in_set);

	if (ncfg_plan_failed(kept)) {
		ncfg_plan_free(kept);
		ncfg_error_set(err, err_size, "not enough memory to restrict the plan");
		return NULL;
	}
	return kept;
}

/* Whether an earlier action in this plan already named this interface. The
 * Rust keeps a `seen` list; asking the plan instead makes the answer
 * independent of how many drifts are kept, so `total` counts what is there
 * rather than what fitted. */
static int already_named(const ncfg_plan_t *plan, size_t before, const char *interface)
{
	size_t at;

	for (at = 0; at < before; at++) {
		const char *earlier = ncfg_op_interface(&plan->actions[at].op);

		if (earlier && interface && strcmp(earlier, interface) == 0) {
			return 1;
		}
	}
	return 0;
}

/* Keep one, or count it and move on. */
static ncfg_drift_t *drift_open(ncfg_drifts_t *out, const char *interface)
{
	ncfg_drift_t *one;

	out->total++;
	if (out->count >= NCFG_DRIFT_MAX) {
		return NULL;
	}
	one = &out->at[out->count++];
	memset(one, 0, sizeof(*one));
	one->interface = interface;
	return one;
}

void ncfg_reconcile_drift(const ncfg_plan_t *plan, const ncfg_document_t *document,
    ncfg_drifts_t *out)
{
	size_t at;

	if (!out) {
		return;
	}
	memset(out, 0, sizeof(*out));
	if (!plan) {
		return;
	}

	for (at = 0; at < plan->action_count; at++) {
		const ncfg_action_t *action = &plan->actions[at];
		const char          *interface = ncfg_op_interface(&action->op);
		ncfg_drift_policy_t  policy;
		ncfg_drift_t        *one;

		if (!interface || already_named(plan, at, interface)) {
			continue;
		}
		policy = ncfg_reconcile_policy_for(document, interface);
		if (policy == NCFG_DRIFT_POLICY_IGNORE) {
			continue;
		}
		one = drift_open(out, interface);
		if (!one) {
			continue;
		}
		(void)snprintf(one->summary, sizeof(one->summary), "%s: %s is %s but should be %s",
		    ncfg_op_name(&action->op), or_unknown(action->reason.field),
		    or_unknown(action->reason.observed), or_unknown(action->reason.desired));
		(void)snprintf(one->action, sizeof(one->action), "%s",
		    policy == NCFG_DRIFT_POLICY_RECONCILE ? "reconciling" : "reported only");
	}

	/* A guard refusing something is worth saying out loud: it is exactly the
	 * case where an operator is waiting for a change that is never going to
	 * happen. */
	for (at = 0; at < plan->refusal_count; at++) {
		const ncfg_refusal_t *refusal = &plan->refusals[at];
		ncfg_drift_t         *one = drift_open(out, refusal->interface);

		if (!one) {
			continue;
		}
		(void)snprintf(one->summary, sizeof(one->summary), "%s refused: %s depends on it",
		    or_unknown(refusal->op), or_unknown(refusal->guard));
		(void)snprintf(one->action, sizeof(one->action), "blocked; %s",
		    or_unknown(refusal->override_with));
	}

	/* And a credential nobody can revoke, for a stronger version of the same
	 * reason: nothing is waiting on this one, which is exactly why it would
	 * otherwise go unsaid until the hardware was gone. */
	for (at = 0; at < plan->stranded_count; at++) {
		const ncfg_stranded_t *stranded = &plan->stranded[at];
		ncfg_drift_t          *one = drift_open(out, stranded->interface);

		if (!one) {
			continue;
		}
		(void)snprintf(one->summary, sizeof(one->summary), "unmanaging it leaves %s",
		    or_unknown(stranded->credential));
		(void)snprintf(one->action, sizeof(one->action), "undecided; %s or %s",
		    or_unknown(stranded->remove_with), or_unknown(stranded->consent_with));
	}
}

void ncfg_drift_event(const ncfg_drift_t *drift, ncfg_proto_event_t *out)
{
	if (!out) {
		return;
	}
	memset(out, 0, sizeof(*out));
	out->kind = NCFG_PROTO_EVENT_DRIFT;
	if (!drift) {
		return;
	}
	out->interface = ncfg_proto_str(drift->interface);
	out->summary = ncfg_proto_str(drift->summary);
	out->action = ncfg_proto_str(drift->action);
}

const char *ncfg_reconcile_told(const ncfg_observed_t *observed, const char *interface, int phase)
{
	size_t at;

	if (!observed || !interface) {
		return NULL;
	}
	for (at = 0; at < observed->hook_state_count; at++) {
		const ncfg_observed_hook_state_t *record = &observed->hook_state[at];

		if (record->phase == phase && record->interface &&
		    strcmp(record->interface, interface) == 0) {
			return record->value;
		}
	}
	return NULL;
}

int ncfg_reconcile_tells(const char *last_told, const char *summary)
{
	if (!summary) {
		return 0;
	}
	return (last_told && strcmp(last_told, summary) == 0) ? 0 : 1;
}

/* ------------------------------------------------------------------------ *
 * The captive-portal record
 * ------------------------------------------------------------------------ */

ncfg_portal_step_t ncfg_portal_step(int addressed, const char *was, unsigned *attempts_out)
{
	const char *counted;

	if (attempts_out) {
		*attempts_out = 0;
	}
	if (!addressed) {
		/* The record holds the state rather than the verdict, because what
		 * this fires on is the transition and not what the transition turned
		 * out to mean. Written only where it moved. */
		if (was && strcmp(was, NCFG_PORTAL_RECORD_BARE) == 0) {
			return NCFG_PORTAL_STEP_NOTHING;
		}
		return NCFG_PORTAL_STEP_BARE;
	}
	if (was && strcmp(was, NCFG_PORTAL_RECORD_DONE) == 0) {
		/* Already answered. Nothing until the interface goes bare. */
		return NCFG_PORTAL_STEP_NOTHING;
	}
	if (was && strncmp(was, NCFG_PORTAL_RECORD_TRYING, strlen(NCFG_PORTAL_RECORD_TRYING)) == 0) {
		counted = was + strlen(NCFG_PORTAL_RECORD_TRYING);
		if (attempts_out && counted[0] != '\0') {
			unsigned long parsed = 0;
			size_t        at;

			for (at = 0; counted[at] != '\0'; at++) {
				if (counted[at] < '0' || counted[at] > '9' ||
				    parsed > NCFG_PORTAL_RECORD_ATTEMPTS) {
					/* A record this build does not recognise counts as
					 * no attempts, which is the Rust's `unwrap_or(0)`
					 * and starts the retry rather than ending it. */
					parsed = 0;
					break;
				}
				parsed = parsed * 10u + (unsigned long)(counted[at] - '0');
			}
			*attempts_out = (unsigned)parsed;
		}
	}
	return NCFG_PORTAL_STEP_ASK;
}

void ncfg_portal_answered(int verdict, unsigned attempts, ncfg_portal_answer_t *out)
{
	unsigned next;

	if (!out) {
		return;
	}
	memset(out, 0, sizeof(*out));
	next = attempts < UINT_MAX ? attempts + 1u : attempts;
	out->attempt = next;

	if (verdict == NCFG_PORTAL_VERDICT_UNREACHABLE) {
		/*
		 * **An answer that was not an answer must not consume the
		 * transition.** The probe runs before the reconcile that delivers
		 * DNS, so on a fresh join the name may not resolve for another pass
		 * -- and DNS is exactly what a portal hijacks. Recording that as
		 * "checked, and clear" meant the one network behind a portal and slow
		 * to come up was the one netcfgd never told anybody about.
		 */
		if (next < NCFG_PORTAL_RECORD_ATTEMPTS) {
			(void)snprintf(out->record, sizeof(out->record), "%s%u",
			    NCFG_PORTAL_RECORD_TRYING, next);
			out->retrying = 1;
			return;
		}
		/* Given up on, and said once rather than kept quiet: the operator
		 * asked for this network to be checked and it was not. */
		(void)snprintf(out->record, sizeof(out->record), "%s", NCFG_PORTAL_RECORD_DONE);
		return;
	}
	(void)snprintf(out->record, sizeof(out->record), "%s", NCFG_PORTAL_RECORD_DONE);
	/* Two verdicts, one record, and they are not the same finding. `Clear`
	 * means nothing is in the way, which is said to the log and to nobody
	 * else: a hook that ran on every successful join is a hook nobody keeps. */
	out->run_hooks = verdict == (int)NCFG_PORTAL_VERDICT_PORTAL ? 1 : 0;
}

/* ------------------------------------------------------------------------ *
 * The resolv counting
 * ------------------------------------------------------------------------ */

int ncfg_reconcile_reclaimed(const ncfg_plan_t *plan)
{
	size_t at;

	if (!plan) {
		return 0;
	}
	for (at = 0; at < plan->action_count; at++) {
		if (plan->actions[at].op.kind == (int)NCFG_OP_DNS_APPLY) {
			return 1;
		}
	}
	return 0;
}

int ncfg_reconcile_sweeps(unsigned *reclaims, int reclaimed)
{
	if (!reclaims) {
		return 0;
	}
	if (!reclaimed) {
		*reclaims = 0;
		return 0;
	}
	if (*reclaims < UINT_MAX) {
		*reclaims += 1u;
	}
	if (*reclaims >= (unsigned)NCFG_RESOLV_PATIENCE) {
		*reclaims = 0;
		return 1;
	}
	return 0;
}

/* ------------------------------------------------------------------------ *
 * Arming for a change
 * ------------------------------------------------------------------------ */

int ncfg_reconcile_document_is_empty(const ncfg_document_t *document)
{
	char             mine[NCFG_DAEMON_HASH_MAX];
	char             theirs[NCFG_DAEMON_HASH_MAX];
	char             message[NCFG_ERROR_MAX];
	ncfg_document_t *empty;
	int              same;

	if (!document) {
		return 1;
	}
	message[0] = '\0';
	empty = ncfg_document_new(message, sizeof(message));
	if (!empty) {
		/* Doubt answers yes, which refuses a window rather than arming one
		 * whose revert undoes everything netcfgd has done. */
		return 1;
	}
	if (!ncfg_daemon_document_hash(document, mine, message, sizeof(message)) ||
	    !ncfg_daemon_document_hash(empty, theirs, message, sizeof(message))) {
		ncfg_document_free(empty);
		return 1;
	}
	same = strcmp(mine, theirs) == 0 ? 1 : 0;
	ncfg_document_free(empty);
	return same;
}

ncfg_arm_t ncfg_reconcile_arms(int config_is_new, ncfg_optint_t window,
    const ncfg_document_t *last_good)
{
	if (!config_is_new) {
		return NCFG_ARM_NOT_A_CHANGE;
	}
	if (!window.has || window.value <= 0) {
		return NCFG_ARM_NO_WINDOW;
	}
	if (!last_good) {
		return NCFG_ARM_REFUSED;
	}
	if (ncfg_reconcile_document_is_empty(last_good)) {
		return NCFG_ARM_EMPTY_LAST_GOOD;
	}
	return NCFG_ARM_YES;
}

const char *ncfg_reconcile_arm_why(ncfg_arm_t answer)
{
	switch (answer) {
	case NCFG_ARM_YES:
		return NULL;
	case NCFG_ARM_NOT_A_CHANGE:
		return "this pass corrected drift rather than applying a change, and a "
		       "correction nobody asked for is not one anybody is waiting to confirm";
	case NCFG_ARM_NO_WINDOW:
		return "this configuration asks for no confirm window";
	case NCFG_ARM_REFUSED:
		return "a window could not be opened for this change";
	case NCFG_ARM_EMPTY_LAST_GOOD:
		return "the last-good configuration is empty, so reverting would undo "
		       "everything netcfgd has done rather than this change";
	default:
		return NULL;
	}
}
