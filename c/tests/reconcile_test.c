/*
 * reconcile_test.c -- the loop's decisions, and the order they are acted on in.
 *
 * NOTHING HERE TOUCHES THE MACHINE THIS IS BUILT ON
 *   netcfgd is running here. Every directory below is one this binary made
 *   with `mkdtemp` and removes at the end, no path has a default, and **not
 *   one of the seams is the real thing**: the executor is a recorder, the
 *   hooks are counted rather than run, the captive-portal probe answers from a
 *   fixture, the contended radio is given back to nobody, and the clock is a
 *   number this file moves. `ncfg_reconcile_hook_run` is never called, which
 *   is deliberate -- it forks and execs.
 *
 * WHY THE ORDER IS A CHECK RATHER THAN A COMMENT
 *   Five of the Rust's orderings are load-bearing and each is written down
 *   there with a reason: the drift hooks before the reconcile, the portal
 *   checks after them, a contended radio given back before the reconcile
 *   rather than inside it, the observation never held by
 *   `--no-apply-on-start`, and the documents compared either side of a reload.
 *   None of them could be checked, because reaching any of them meant standing
 *   a daemon up with four watcher threads and a socket. Here every seam
 *   appends the step it was called for to one list, and the assertion is that
 *   list -- so an ordering somebody rearranges goes red rather than staying
 *   true only in a comment.
 *
 * WHAT THE INTERESTING CASES ARE
 *   A byte-identical rewrite of the configuration, which must **not** arm a
 *   window over a drift correction; a pass held by `--no-apply-on-start`,
 *   which must still observe, report and run every hook; a plan restricted to
 *   an interface whose neighbour holds a dependency; and the portal record,
 *   which is a small state machine that used to be unreachable without a
 *   network behind a captive portal.
 */
#include "ncfg/apply.h"
#include "ncfg/base.h"
#include "ncfg/daemon.h"
#include "ncfg/document.h"
#include "ncfg/log.h"
#include "ncfg/observed.h"
#include "ncfg/plan.h"
#include "ncfg/portal.h"
#include "ncfg/proto.h"
#include "ncfg/state.h"
#include "ncfg/value.h"

#include "testdir.h"

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int failures;
static int checks;

static void check(int condition, const char *what)
{
	checks++;
	printf("%-72s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

static void detail(const char *label, const char *text)
{
	printf("       %s: %s\n", label, text ? text : "(none)");
}

/* ------------------------------------------------------------------------ *
 * Fixtures
 * ------------------------------------------------------------------------ */

/* Read through the model, so that nothing here builds a document by hand and
 * a fixture that is not a document is refused rather than quietly acted on. */
static ncfg_document_t *document_of(const char *body)
{
	char             text[4096];
	char             message[NCFG_ERROR_MAX];
	ncfg_document_t *document;

	(void)snprintf(text, sizeof(text),
	    "{\"schema_version\":{\"major\":1,\"minor\":1},\"globals\":{},\"networks\":[]%s%s}",
	    body && body[0] ? "," : "", body ? body : "");
	message[0] = '\0';
	document = ncfg_document_read(text, strlen(text), message, sizeof(message));
	if (!document) {
		detail("fixture document did not read", message);
	}
	return document;
}

static ncfg_observed_t *observed_of(const char *body)
{
	char             text[4096];
	char             message[NCFG_ERROR_MAX];
	ncfg_observed_t *observed;

	(void)snprintf(text, sizeof(text), "{%s}", body);
	message[0] = '\0';
	observed = ncfg_observed_read(text, strlen(text), message, sizeof(message));
	if (!observed) {
		detail("fixture observation did not read", message);
	}
	return observed;
}

#define ZEROS "0000000000000000000000000000000000000000000000000000000000000000"

/* One radio with a portal URL, one interface that reconciles and declares a
 * hook at each of the two phases the loop fires. */
#define DRIFTING_DOCUMENT                                                              \
	"\"devices\":[{\"name\":\"eth0\",\"kind\":{\"kind\":\"physical\"},\"mtu\":1400," \
	"\"wifi\":{\"portal_check\":\"http://portal.invalid/generate_204\"}}],"         \
	"\"interfaces\":[{\"name\":\"eth0\",\"on_drift\":\"reconcile\",\"hooks\":["     \
	"{\"phase\":\"drift\",\"path\":\"/nonexistent/drift.sh\",\"sha256\":\"" ZEROS   \
	"\"},{\"phase\":\"portal\",\"path\":\"/nonexistent/portal.sh\",\"sha256\":\""   \
	ZEROS "\"}]}]"

/* The same machine, at the wrong MTU and holding a routable address -- so the
 * plan has something to do and the portal check has a reason to fire. */
#define DRIFTING_OBSERVED                                                                     \
	"\"links\":[{\"name\":\"eth0\",\"index\":2,\"mtu\":1500,\"up\":true,"                 \
	"\"carrier\":true,\"ownership\":\"unknown\"}],"                                       \
	"\"addresses\":[{\"interface\":\"eth0\",\"address\":\"192.0.2.5/24\","                \
	"\"origin\":\"static\",\"ownership\":\"unknown\"}]"

/* ------------------------------------------------------------------------ *
 * Plans built by hand
 * ------------------------------------------------------------------------ */

static uint32_t add_mtu(ncfg_plan_t *plan, const char *interface, const uint32_t *depends,
    size_t depend_count)
{
	ncfg_op_t     op;
	ncfg_reason_t reason;

	memset(&op, 0, sizeof(op));
	op.kind = NCFG_OP_LINK_SET_MTU;
	op.u.set_mtu.name = interface;
	op.u.set_mtu.mtu = 1400;
	memset(&reason, 0, sizeof(reason));
	reason.interface = interface;
	reason.field = "mtu";
	reason.desired = "1400";
	reason.observed = "1500";
	return ncfg_plan_add(plan, &op, &reason, depends, depend_count, NULL);
}

static uint32_t add_dns(ncfg_plan_t *plan)
{
	ncfg_op_t     op;
	ncfg_reason_t reason;

	memset(&op, 0, sizeof(op));
	op.kind = NCFG_OP_DNS_APPLY;
	op.u.dns.scope = "globals";
	memset(&reason, 0, sizeof(reason));
	reason.field = "dns";
	reason.desired = "192.0.2.1";
	reason.observed = "<absent>";
	return ncfg_plan_add(plan, &op, &reason, NULL, 0u, NULL);
}

static uint32_t add_commit_arm(ncfg_plan_t *plan)
{
	ncfg_op_t     op;
	ncfg_reason_t reason;

	memset(&op, 0, sizeof(op));
	op.kind = NCFG_OP_COMMIT_ARM;
	op.u.commit_arm.window_seconds = 30;
	memset(&reason, 0, sizeof(reason));
	reason.field = "confirm";
	reason.desired = "30";
	reason.observed = "<absent>";
	return ncfg_plan_add(plan, &op, &reason, NULL, 0u, NULL);
}

/* ------------------------------------------------------------------------ *
 * What woke it, and what that makes the loop do
 * ------------------------------------------------------------------------ */

static void a_burst_collapses_to_what_it_means(void)
{
	ncfg_reconcile_wake_t wake;

	memset(&wake, 0, sizeof(wake));
	check(!ncfg_reconcile_looks(&wake, 0), "a pass told nothing looks at nothing");

	ncfg_reconcile_collapse(&wake, NCFG_WOKE_KERNEL);
	ncfg_reconcile_collapse(&wake, NCFG_WOKE_KERNEL);
	ncfg_reconcile_collapse(&wake, NCFG_WOKE_KERNEL);
	check(wake.kernel_changed && !wake.config_changed && !wake.ticked,
	    "a run of netlink messages is one pass, which is what collapsing is for");

	memset(&wake, 0, sizeof(wake));
	ncfg_reconcile_collapse(&wake, NCFG_WOKE_CONFIG);
	check(wake.config_changed && ncfg_reconcile_looks(&wake, 0), "a write in the directory");
	memset(&wake, 0, sizeof(wake));
	ncfg_reconcile_collapse(&wake, NCFG_WOKE_TICK);
	check(wake.ticked && ncfg_reconcile_looks(&wake, 0),
	    "and the backstop, which is what makes this a verification loop");

	/* A confirm timer is not a reason to look at the machine: it is a reason
	 * to ask the window whether it closed, which is a different question and
	 * is asked before this one. */
	memset(&wake, 0, sizeof(wake));
	ncfg_reconcile_collapse(&wake, NCFG_WOKE_CONFIRM_EXPIRED);
	check(wake.confirm_expired && !ncfg_reconcile_looks(&wake, 0),
	    "a fired confirm timer resolves a window rather than re-reading the kernel");

	/* A changed probe verdict is movement even where nothing else woke the
	 * loop, because a verdict is an observation of the link (0119). */
	memset(&wake, 0, sizeof(wake));
	check(ncfg_reconcile_looks(&wake, 1), "a probe verdict that moved is movement");

	/* And a command this build does not know changes nothing, rather than
	 * being read as whichever flag sits at that offset. */
	memset(&wake, 0, sizeof(wake));
	ncfg_reconcile_collapse(&wake, (ncfg_woke_t)99);
	check(!wake.kernel_changed && !wake.config_changed && !wake.confirm_expired &&
	        !wake.ticked,
	    "a command outside the enum sets nothing");
}

/*
 * A tick asks the confirm window whether it closed, not only the timer.
 *
 * **The timer was the only thing that asked, and its spawn result was
 * discarded (0234).** A timer that could not start left the window open for
 * ever, so a change the operator never confirmed stayed applied -- the failure
 * commit-confirm exists to prevent, arriving through the mechanism meant to
 * prevent it.
 */
static void a_tick_also_asks_whether_the_window_closed(void)
{
	check(ncfg_reconcile_should_resolve_window(1, 0), "the timer fired: ask, obviously");
	check(ncfg_reconcile_should_resolve_window(0, 1),
	    "a tick has to ask, or a timer that never started loses the window");
	check(ncfg_reconcile_should_resolve_window(1, 1), "both, which is the ordinary case");
	check(!ncfg_reconcile_should_resolve_window(0, 0),
	    "and a pass woken by something else has no reason to read the clock");
}

/* ------------------------------------------------------------------------ *
 * The waiting requests
 * ------------------------------------------------------------------------ */

static ncfg_proto_request_t an_apply(int has_window, int64_t seconds)
{
	ncfg_proto_request_t request;

	memset(&request, 0, sizeof(request));
	request.kind = NCFG_PROTO_REQ_APPLY;
	request.u.apply.confirm.present = has_window ? 1u : 0u;
	request.u.apply.confirm.value = seconds;
	return request;
}

static ncfg_proto_request_t a_plain(ncfg_proto_request_kind_t kind)
{
	ncfg_proto_request_t request;

	memset(&request, 0, sizeof(request));
	request.kind = kind;
	return request;
}

/*
 * A pending apply that asks for a window defers the loop, and one that asks
 * for nothing does not.
 *
 * The second half is the control. Without it this passes for a predicate that
 * answers yes unconditionally, which is what the first version of the live
 * check did before a no-window run was put beside it.
 */
static void only_a_requested_window_defers_the_loop(void)
{
	ncfg_proto_request_t several[3];

	{
		ncfg_proto_request_t one = an_apply(1, 60);

		check(ncfg_reconcile_window_requested(&one, 1u), "an apply asking for 60 seconds");
	}
	{
		ncfg_proto_request_t one = an_apply(0, 0);

		check(!ncfg_reconcile_window_requested(&one, 1u), "an apply asking for nothing");
	}
	{
		/* `--confirm-within 0` is "apply and arm nothing" (0094), so it is not
		 * a window and must not hold the loop off. */
		ncfg_proto_request_t one = an_apply(1, 0);

		check(!ncfg_reconcile_window_requested(&one, 1u),
		    "a window of no seconds is how an operator declines one");
	}
	{
		ncfg_proto_request_t one = an_apply(1, -5);

		check(!ncfg_reconcile_window_requested(&one, 1u),
		    "and a negative number is not a window either");
	}

	several[0] = a_plain(NCFG_PROTO_REQ_STATUS);
	several[1] = an_apply(1, 30);
	several[2] = an_apply(0, 0);
	check(ncfg_reconcile_window_requested(several, 3u),
	    "one among several is enough: the loop must not reconcile past it");
	several[1] = a_plain(NCFG_PROTO_REQ_RELOAD);
	check(!ncfg_reconcile_window_requested(several, 3u),
	    "and a batch with no window in it does not defer");

	/* An open window is the other half, and it is the stronger one: it says a
	 * change is already awaiting confirmation. */
	check(ncfg_reconcile_defers(1, NULL, 0u), "an open window defers on its own");
	check(!ncfg_reconcile_defers(0, NULL, 0u), "and nothing at all does not");
}

static void only_an_apply_releases_the_hold(void)
{
	ncfg_proto_request_t several[2];
	ncfg_proto_request_t one;

	one = an_apply(0, 0);
	check(ncfg_reconcile_releases_hold(&one, 1u), "an explicit apply is the operator saying go");
	one = an_apply(1, 0);
	check(ncfg_reconcile_releases_hold(&one, 1u),
	    "including one that declines a window, which is still an apply");
	one = a_plain(NCFG_PROTO_REQ_RELOAD);
	check(!ncfg_reconcile_releases_hold(&one, 1u),
	    "a reload is not, because nothing else is the operator saying go");
	one = a_plain(NCFG_PROTO_REQ_STATUS);
	check(!ncfg_reconcile_releases_hold(&one, 1u), "and neither is reading the status");

	several[0] = a_plain(NCFG_PROTO_REQ_STATUS);
	several[1] = an_apply(1, 60);
	check(ncfg_reconcile_releases_hold(several, 2u), "one among several releases it");
	check(!ncfg_reconcile_releases_hold(NULL, 0u), "and an empty batch releases nothing");
}

/* ------------------------------------------------------------------------ *
 * Whose drift netcfgd puts back
 * ------------------------------------------------------------------------ */

static void the_drift_policy_in_force(void)
{
	ncfg_document_t *document = document_of(
	    "\"devices\":[],\"interfaces\":[{\"name\":\"eth0\",\"on_drift\":\"report\"},"
	    "{\"name\":\"eth1\"}]");

	if (!document) {
		check(0, "the drift-policy fixture reads");
		return;
	}
	check(ncfg_reconcile_policy_for(document, "eth0") == NCFG_DRIFT_POLICY_REPORT,
	    "an interface that states a policy has it");
	check(ncfg_reconcile_policy_for(document, "eth1") == NCFG_DRIFT_POLICY_RECONCILE,
	    "one that states none takes the document's default, which is reconcile");
	check(ncfg_reconcile_policy_for(document, "eth9") == NCFG_DRIFT_POLICY_RECONCILE,
	    "and so does a name the document does not carry");
	check(ncfg_reconcile_policy_for(NULL, "eth0") == NCFG_DRIFT_POLICY_REPORT,
	    "no configuration at all is not a licence to change anything");
	check(ncfg_reconcile_host_wide(document),
	    "the host's own configuration follows the same default");
	check(!ncfg_reconcile_host_wide(NULL), "and follows nothing where there is no document");

	check(ncfg_reconcile_reconciles(document, NULL, "eth1"), "eth1 is netcfgd's to put back");
	check(!ncfg_reconcile_reconciles(document, NULL, "eth0"), "eth0 is reported and left");
	check(!ncfg_reconcile_reconciles(document, NULL, "eth9"),
	    "and an interface nobody configured is not touched");
	ncfg_document_free(document);

	document = document_of("\"devices\":[],\"interfaces\":[{\"name\":\"eth0\","
	    "\"on_drift\":\"ignore\"}]");
	if (document) {
		check(ncfg_reconcile_policy_for(document, "eth0") == NCFG_DRIFT_POLICY_IGNORE &&
		        !ncfg_reconcile_reconciles(document, NULL, "eth0"),
		    "an ignored interface is neither reported nor reconciled");
		ncfg_document_free(document);
	}

	/*
	 * **A preference is not drift**, and it outranks the policy: losing
	 * carrier is the configuration's own meaning changing rather than
	 * something else moving the machine, and a laptop that announces "your
	 * cable is out" while still routing down it is not the feature anybody
	 * asked for.
	 */
	document = document_of("\"devices\":[],\"interfaces\":[{\"name\":\"eth0\","
	    "\"on_drift\":\"report\",\"preference\":10}]");
	if (document) {
		check(ncfg_reconcile_reconciles(document, NULL, "eth0"),
		    "an interface with a preference is reconciled whatever the policy says");
		ncfg_document_free(document);
	}
}

/* A pending SIM cycle is the other exception, and the only way to get one is
 * to advance a modem, so this needs a run directory of its own. */
static void a_pending_sim_cycle_is_not_drift_either(const char *base)
{
	ncfg_document_t *document = document_of(
	    "\"devices\":[{\"name\":\"wwan0\",\"kind\":{\"kind\":\"physical\"},"
	    "\"modem\":{\"sim\":[\"soldered\",\"socket\"]}}],"
	    "\"interfaces\":[{\"name\":\"wwan0\",\"on_drift\":\"report\"}]");
	ncfg_sims_t *sims = ncfg_sims_new(NULL, 0u);
	char         run[512];
	char         err[NCFG_ERROR_MAX];
	const char  *moved_to = NULL;

	(void)testdir_in(base, "sims-run", run, sizeof(run));
	(void)mkdir(run, 0700);
	if (!document || !sims) {
		check(0, "the pending-cycle fixture is built");
		ncfg_document_free(document);
		ncfg_sims_free(sims);
		return;
	}
	err[0] = '\0';
	check(ncfg_sims_sync(sims, document, run, err, sizeof(err)),
	    "a modem starts on the first source its document names");
	check(!ncfg_reconcile_reconciles(document, sims, "wwan0"),
	    "and while it sits there the interface's own `report` policy stands");
	err[0] = '\0';
	check(ncfg_sims_advance(sims, document, "wwan0", run, &moved_to, err, sizeof(err)) &&
	        moved_to != NULL,
	    "advancing it to the next source leaves a note that the link must cycle");
	detail("moved to", moved_to);
	check(ncfg_reconcile_reconciles(document, sims, "wwan0"),
	    "which netcfgd must act on, or the modem sits on a source nothing selected");

	ncfg_sims_free(sims);
	ncfg_document_free(document);
}

/* ------------------------------------------------------------------------ *
 * Restricting a plan
 * ------------------------------------------------------------------------ */

static int plan_touches(const ncfg_plan_t *plan, const char *interface)
{
	size_t at;

	for (at = 0; at < plan->action_count; at++) {
		const char *named = ncfg_op_interface(&plan->actions[at].op);

		if (named && strcmp(named, interface) == 0) {
			return 1;
		}
	}
	return 0;
}

static void a_restricted_plan_keeps_only_what_it_may_act_on(void)
{
	ncfg_document_t *document = document_of(
	    "\"devices\":[],\"interfaces\":[{\"name\":\"eth0\"},"
	    "{\"name\":\"eth1\",\"on_drift\":\"report\"}]");
	ncfg_plan_t *plan;
	ncfg_plan_t *kept;
	ncfg_buf_t   dropped;
	char         err[NCFG_ERROR_MAX];
	uint32_t     first;
	uint32_t     depends[1];

	if (!document) {
		check(0, "the restriction fixture reads");
		return;
	}
	plan = ncfg_plan_new(err, sizeof(err));
	if (!plan) {
		check(0, "a plan to restrict");
		ncfg_document_free(document);
		return;
	}
	first = add_mtu(plan, "eth1", NULL, 0u);
	depends[0] = first;
	(void)add_mtu(plan, "eth0", NULL, 0u);
	(void)add_dns(plan);
	(void)add_commit_arm(plan);
	/* An action on a reconciling interface that waits on one belonging to an
	 * interface the operator set to `report`. */
	(void)add_mtu(plan, "eth0", depends, 1u);

	ncfg_buf_init(&dropped, NCFG_LOG_MAX);
	err[0] = '\0';
	kept = ncfg_reconcile_restrict(plan, document, NULL, 0, &dropped, err, sizeof(err));
	if (!kept) {
		check(0, "a plan restricts");
		detail("because", err);
		ncfg_buf_free(&dropped);
		ncfg_plan_free(plan);
		ncfg_document_free(document);
		return;
	}
	check(plan_touches(kept, "eth0"), "the reconciling interface's action is kept");
	check(!plan_touches(kept, "eth1"),
	    "and the reported one's is not, so putting one back cannot drag the other");
	check(kept->action_count == 1u, "which leaves exactly the one action");
	check(strstr(ncfg_buf_text(&dropped), "needs action") != NULL,
	    "an action orphaned by the filtering is dropped and named rather than reordered");
	detail("dropped", ncfg_buf_text(&dropped));
	ncfg_plan_free(kept);

	/*
	 * `resolv.conf` belongs to no interface, so the per-interface filter can
	 * only ever drop it -- which is how a foreign overwrite could never be put
	 * back (0165). The three commit ops name no interface either and must not
	 * be swept in by the same rule.
	 */
	err[0] = '\0';
	kept = ncfg_reconcile_restrict(plan, document, NULL, 1, NULL, err, sizeof(err));
	if (kept) {
		size_t at;
		int    has_dns = 0;
		int    has_commit = 0;

		for (at = 0; at < kept->action_count; at++) {
			if (kept->actions[at].op.kind == NCFG_OP_DNS_APPLY) {
				has_dns = 1;
			}
			if (kept->actions[at].op.kind == NCFG_OP_COMMIT_ARM) {
				has_commit = 1;
			}
		}
		check(has_dns, "a host-wide action is kept where the host's policy reconciles");
		check(!has_commit, "and a commit marker is not swept in beside it");
		ncfg_plan_free(kept);
	} else {
		check(0, "a host-wide restriction builds");
	}

	/* Restricting to nothing yields nothing, which is the ordinary converged
	 * machine and the case a loop must not treat as work. */
	{
		ncfg_document_t *nobody = document_of("\"devices\":[],\"interfaces\":[]");

		err[0] = '\0';
		kept = ncfg_reconcile_restrict(plan, nobody, NULL, 0, NULL, err, sizeof(err));
		check(kept && kept->action_count == 0u,
		    "a plan restricted to nothing is empty rather than refused");
		ncfg_plan_free(kept);
		ncfg_document_free(nobody);
	}

	/* And the refusals come across whole: restricting a plan changes what
	 * will be done, not what is true about the configuration. */
	{
		ncfg_refusal_t refusal;

		memset(&refusal, 0, sizeof(refusal));
		refusal.interface = "eth1";
		refusal.op = "link.down";
		refusal.guard = "the default route";
		refusal.override_with = "ncfg apply --allow-disruption eth1";
		ncfg_plan_refuse(plan, &refusal);
		err[0] = '\0';
		kept = ncfg_reconcile_restrict(plan, document, NULL, 0, NULL, err, sizeof(err));
		check(kept && kept->refusal_count == 1u,
		    "a refusal about an interface the restriction dropped is still carried");
		ncfg_plan_free(kept);
	}

	ncfg_buf_free(&dropped);
	ncfg_plan_free(plan);
	ncfg_document_free(document);
}

/* ------------------------------------------------------------------------ *
 * Reading drift out of a plan
 * ------------------------------------------------------------------------ */

static void drift_is_read_out_of_the_plan(void)
{
	ncfg_document_t *document = document_of(
	    "\"devices\":[],\"interfaces\":[{\"name\":\"eth0\"},"
	    "{\"name\":\"eth1\",\"on_drift\":\"report\"},"
	    "{\"name\":\"eth2\",\"on_drift\":\"ignore\"}]");
	ncfg_plan_t   *plan;
	ncfg_drifts_t  drifts;
	ncfg_refusal_t refusal;
	char           err[NCFG_ERROR_MAX];

	if (!document) {
		check(0, "the drift fixture reads");
		return;
	}
	plan = ncfg_plan_new(err, sizeof(err));
	if (!plan) {
		check(0, "a plan to read drift out of");
		ncfg_document_free(document);
		return;
	}
	(void)add_mtu(plan, "eth0", NULL, 0u);
	/* A second action on one interface is the same fight, not a second one. */
	(void)add_mtu(plan, "eth0", NULL, 0u);
	(void)add_mtu(plan, "eth1", NULL, 0u);
	(void)add_mtu(plan, "eth2", NULL, 0u);
	memset(&refusal, 0, sizeof(refusal));
	refusal.interface = "eth1";
	refusal.op = "link.down";
	refusal.guard = "the default route";
	refusal.override_with = "ncfg apply --allow-disruption eth1";
	ncfg_plan_refuse(plan, &refusal);

	ncfg_reconcile_drift(plan, document, &drifts);
	check(drifts.count == 3u, "one entry per drifting interface, plus the refusal");
	if (drifts.count >= 2u) {
		check(strcmp(drifts.at[0].interface, "eth0") == 0 &&
		        strcmp(drifts.at[0].action, "reconciling") == 0,
		    "an interface netcfgd puts back says so");
		check(strstr(drifts.at[0].summary, "mtu is 1500 but should be 1400") != NULL,
		    "and says which field moved and which way");
		detail("summary", drifts.at[0].summary);
		check(strcmp(drifts.at[1].interface, "eth1") == 0 &&
		        strcmp(drifts.at[1].action, "reported only") == 0,
		    "one under `report` is named and left alone");
	}
	if (drifts.count >= 3u) {
		check(strstr(drifts.at[2].summary, "refused") != NULL &&
		        strstr(drifts.at[2].action, "blocked; ncfg apply") != NULL,
		    "a guard's refusal is drift too: somebody is waiting for a change that "
		    "will never happen");
		detail("refusal", drifts.at[2].action);
	}
	{
		size_t at;
		int    mentioned = 0;

		for (at = 0; at < drifts.count; at++) {
			if (drifts.at[at].interface &&
			    strcmp(drifts.at[at].interface, "eth2") == 0) {
				mentioned = 1;
			}
		}
		check(!mentioned, "and an interface set to `ignore` produces nothing at all");
	}

	/* The event a client is sent carries the same three strings and nothing
	 * else, which is what a monitor filters by interface on. */
	if (drifts.count > 0u) {
		ncfg_proto_event_t event;

		ncfg_drift_event(&drifts.at[0], &event);
		check(event.kind == NCFG_PROTO_EVENT_DRIFT && event.interface.bytes &&
		        strncmp(event.interface.bytes, "eth0", 4u) == 0 &&
		        event.summary.bytes != NULL && event.action.bytes != NULL,
		    "and travels as a `drift` event naming the interface");
	}
	ncfg_plan_free(plan);
	ncfg_document_free(document);
}

/* The bound is `NCFG_DIAGS_MAX`'s bargain, and `total` is what keeps the fact
 * from being lost. */
static void more_drift_than_is_kept_is_counted(void)
{
	ncfg_document_t *document = document_of("\"devices\":[],\"interfaces\":[]");
	ncfg_plan_t     *plan;
	ncfg_drifts_t    drifts;
	char             err[NCFG_ERROR_MAX];
	char             name[NCFG_DRIFT_MAX + 8][8];
	size_t           at;

	if (!document) {
		check(0, "the bound fixture reads");
		return;
	}
	plan = ncfg_plan_new(err, sizeof(err));
	if (!plan) {
		check(0, "a plan of many interfaces");
		ncfg_document_free(document);
		return;
	}
	/* No document entry for any of them, so every one takes the default,
	 * which is `reconcile`. */
	for (at = 0; at < NCFG_DRIFT_MAX + 4u; at++) {
		(void)snprintf(name[at], sizeof(name[at]), "eth%zu", at);
		(void)add_mtu(plan, name[at], NULL, 0u);
	}
	ncfg_reconcile_drift(plan, document, &drifts);
	check(drifts.count == (size_t)NCFG_DRIFT_MAX, "the kept set stops at the bound");
	check(drifts.total == NCFG_DRIFT_MAX + 4u,
	    "and `total` says how many there were, so a client can show 32 of 36");
	ncfg_plan_free(plan);
	ncfg_document_free(document);
}

static void a_drift_hook_fires_on_the_change_not_on_the_condition(void)
{
	check(ncfg_reconcile_tells(NULL, "eth0: mtu is 1500 but should be 1400"),
	    "drift nobody has been told about fires the hook");
	check(!ncfg_reconcile_tells("eth0: mtu is 1500 but should be 1400",
	    "eth0: mtu is 1500 but should be 1400"),
	    "the same drift on the next pass does not, or `report` runs a script for ever");
	check(ncfg_reconcile_tells("eth0: mtu is 1500 but should be 1400",
	    "eth0: address is <absent> but should be 192.0.2.5/24"),
	    "and different drift is news again");
}

/* ------------------------------------------------------------------------ *
 * The captive-portal record
 * ------------------------------------------------------------------------ */

static void the_portal_record_decides_what_to_ask(void)
{
	unsigned attempts = 99u;

	check(ncfg_portal_step(0, NULL, &attempts) == NCFG_PORTAL_STEP_BARE,
	    "an interface with no routable address is recorded bare");
	check(ncfg_portal_step(0, NCFG_PORTAL_RECORD_BARE, &attempts) == NCFG_PORTAL_STEP_NOTHING,
	    "and one already recorded bare is not written again");
	check(ncfg_portal_step(1, NCFG_PORTAL_RECORD_DONE, &attempts) == NCFG_PORTAL_STEP_NOTHING,
	    "an interface already answered for is not asked again until it goes bare");

	attempts = 99u;
	check(ncfg_portal_step(1, NULL, &attempts) == NCFG_PORTAL_STEP_ASK && attempts == 0u,
	    "a fresh join is asked about, with no attempts behind it");
	attempts = 99u;
	check(ncfg_portal_step(1, "trying:3", &attempts) == NCFG_PORTAL_STEP_ASK && attempts == 3u,
	    "and one part-way through the retry carries its count");
	attempts = 99u;
	check(ncfg_portal_step(1, "trying:", &attempts) == NCFG_PORTAL_STEP_ASK && attempts == 0u,
	    "a record with no number counts as none, which starts the retry rather than "
	    "ending it");
	attempts = 99u;
	check(ncfg_portal_step(1, "trying:soon", &attempts) == NCFG_PORTAL_STEP_ASK && attempts == 0u,
	    "and so does one this build does not recognise");
	attempts = 99u;
	check(ncfg_portal_step(1, "trying:4000000000", &attempts) == NCFG_PORTAL_STEP_ASK &&
	        attempts == 0u,
	    "including a count too large to be one this ever wrote");
}

static void an_inconclusive_check_does_not_consume_the_transition(void)
{
	ncfg_portal_answer_t answer;
	unsigned             at;

	for (at = 0; at + 1u < NCFG_PORTAL_RECORD_ATTEMPTS; at++) {
		char wanted[NCFG_PORTAL_RECORD_MAX];

		(void)snprintf(wanted, sizeof(wanted), "trying:%u", at + 1u);
		ncfg_portal_answered(NCFG_PORTAL_VERDICT_UNREACHABLE, at, &answer);
		check(answer.retrying && strcmp(answer.record, wanted) == 0 && !answer.run_hooks,
		    "an answer that was not an answer leaves a count and is tried again");
	}
	ncfg_portal_answered(NCFG_PORTAL_VERDICT_UNREACHABLE, NCFG_PORTAL_RECORD_ATTEMPTS - 1u,
	    &answer);
	check(!answer.retrying && strcmp(answer.record, NCFG_PORTAL_RECORD_DONE) == 0,
	    "the last attempt gives up until the interface is addressed again");
	check(!answer.run_hooks,
	    "and does not call a network with no route a captive portal, which would send "
	    "an operator to a login page that is not there");

	ncfg_portal_answered(NCFG_PORTAL_VERDICT_PORTAL, 0u, &answer);
	check(answer.run_hooks && strcmp(answer.record, NCFG_PORTAL_RECORD_DONE) == 0 &&
	        !answer.retrying,
	    "something that answered with the wrong thing is a portal, and runs the hooks");
	ncfg_portal_answered(NCFG_PORTAL_VERDICT_CLEAR, 0u, &answer);
	check(!answer.run_hooks && strcmp(answer.record, NCFG_PORTAL_RECORD_DONE) == 0,
	    "and a clear check is recorded and told to nobody");
}

/* ------------------------------------------------------------------------ *
 * The resolv counting, and arming
 * ------------------------------------------------------------------------ */

static void the_reclaim_count_means_in_a_row(void)
{
	unsigned reclaims = 0;
	int      at;

	for (at = 1; at < NCFG_RESOLV_PATIENCE; at++) {
		check(!ncfg_reconcile_sweeps(&reclaims, 1),
		    "one write is ordinary, and so is the next");
	}
	check(ncfg_reconcile_sweeps(&reclaims, 1),
	    "something that has taken the file back three times running is not passing through");
	check(reclaims == 0u,
	    "and the count starts again, because whatever was signalled needs a moment to go");

	/* A machine where something rewrites the file once an hour never reaches
	 * the threshold, which is the intent: that is somebody's cron. */
	check(!ncfg_reconcile_sweeps(&reclaims, 1), "a reclaim");
	check(!ncfg_reconcile_sweeps(&reclaims, 0), "a quiet pass in between");
	check(!ncfg_reconcile_sweeps(&reclaims, 1), "and another reclaim");
	check(!ncfg_reconcile_sweeps(&reclaims, 1), "does not reach three in a row");
}

static void a_reclaim_is_asked_of_the_plan(void)
{
	ncfg_plan_t *plan;
	char         err[NCFG_ERROR_MAX];

	plan = ncfg_plan_new(err, sizeof(err));
	if (!plan) {
		check(0, "a plan to ask");
		return;
	}
	(void)add_mtu(plan, "eth0", NULL, 0u);
	check(!ncfg_reconcile_reclaimed(plan), "a pass that touched no resolver is not a reclaim");
	(void)add_dns(plan);
	check(ncfg_reconcile_reclaimed(plan),
	    "and one that had to deliver `resolv.conf` again is");
	ncfg_plan_free(plan);
}

static void a_window_is_armed_only_over_a_change(void)
{
	ncfg_document_t *empty = ncfg_document_new(NULL, 0u);
	ncfg_document_t *real = document_of("\"devices\":[],\"interfaces\":[{\"name\":\"eth0\"}]");
	ncfg_optint_t    thirty;
	ncfg_optint_t    none;
	ncfg_optint_t    zero;

	thirty.has = 1;
	thirty.value = 30;
	none.has = 0;
	none.value = 0;
	zero.has = 1;
	zero.value = 0;

	if (!empty || !real) {
		check(0, "the arming fixture is built");
		ncfg_document_free(empty);
		ncfg_document_free(real);
		return;
	}
	check(ncfg_reconcile_arms(1, thirty, real) == NCFG_ARM_YES,
	    "a configuration change with a window and something to fall back to arms one");
	check(ncfg_reconcile_arms(0, thirty, real) == NCFG_ARM_NOT_A_CHANGE,
	    "a drift correction never arms, or the machine oscillates (0157)");
	check(ncfg_reconcile_arms(1, none, real) == NCFG_ARM_NO_WINDOW,
	    "a configuration that asks for no window gets none");
	check(ncfg_reconcile_arms(1, zero, real) == NCFG_ARM_NO_WINDOW,
	    "and a window of no seconds is how a document says no, not a window of zero");
	check(ncfg_reconcile_arms(1, thirty, NULL) == NCFG_ARM_REFUSED,
	    "a window that could not be opened is refused rather than announced");
	check(ncfg_reconcile_arms(1, thirty, empty) == NCFG_ARM_EMPTY_LAST_GOOD,
	    "and one whose fall-back is the placeholder is a scheduled outage, not a net");

	check(ncfg_reconcile_arm_why(NCFG_ARM_YES) == NULL, "a yes has nothing to explain");
	check(ncfg_reconcile_arm_why(NCFG_ARM_EMPTY_LAST_GOOD) != NULL &&
	        strstr(ncfg_reconcile_arm_why(NCFG_ARM_EMPTY_LAST_GOOD), "undo everything") !=
	    NULL,
	    "and every refusal says what it would have cost");

	check(ncfg_reconcile_document_is_empty(empty),
	    "the placeholder is recognised by identity rather than by field");
	check(!ncfg_reconcile_document_is_empty(real), "and a real configuration is not it");
	check(ncfg_reconcile_document_is_empty(NULL),
	    "doubt answers yes, which refuses a window rather than arming a bad one");
	ncfg_document_free(empty);
	ncfg_document_free(real);
}

/* ------------------------------------------------------------------------ *
 * The world a pass runs against, all of it made up
 * ------------------------------------------------------------------------ */

#define STEPS_MAX 64
#define STEP_MAX 96

typedef struct {
	char                  steps[STEPS_MAX][STEP_MAX];
	size_t                count;
	int                   overflowed;
	/* What the portal probe answers. */
	int                   verdict;
	/* What the clock says, in seconds since the epoch. */
	uint64_t              now;
	/* Whether an executor can be opened at all. */
	int                   no_executor;
	/* An op name the executor refuses, or NULL. */
	const char           *refuse;
	ncfg_executor_t       executor;
} world_t;

static void step(world_t *world, const char *format, ...)
{
	va_list args;

	if (world->count >= STEPS_MAX) {
		world->overflowed = 1;
		return;
	}
	va_start(args, format);
	(void)vsnprintf(world->steps[world->count], STEP_MAX, format, args);
	va_end(args);
	world->count++;
}

/* Where a step is in the list, or -1. Prefix rather than equality, so that a
 * check can name `op:link.set_mtu` without spelling the value. */
static int step_at(const world_t *world, const char *prefix)
{
	size_t at;

	for (at = 0; at < world->count; at++) {
		if (strncmp(world->steps[at], prefix, strlen(prefix)) == 0) {
			return (int)at;
		}
	}
	return -1;
}

static void steps_said(const world_t *world)
{
	size_t at;

	for (at = 0; at < world->count; at++) {
		detail("step", world->steps[at]);
	}
}

/* `a` happens before `b`, and both happened. */
static void before(world_t *world, const char *a, const char *b, const char *what)
{
	int first = step_at(world, a);
	int second = step_at(world, b);

	if (first < 0 || second < 0 || first >= second) {
		detail("wanted before", a);
		detail("       and then", b);
		steps_said(world);
	}
	check(first >= 0 && second >= 0 && first < second, what);
}

static int world_execute(void *state, const ncfg_op_t *op, char *err, size_t err_size)
{
	world_t *world = state;

	step(world, "op:%s", ncfg_op_name(op));
	if (world->refuse && strcmp(ncfg_op_name(op), world->refuse) == 0) {
		ncfg_error_set(err, err_size, "the double was told to refuse %s", world->refuse);
		return 0;
	}
	return 1;
}

static int world_executor_open(void *context, ncfg_executor_t *out, char *err, size_t err_size)
{
	world_t *world = context;

	if (world->no_executor) {
		ncfg_error_set(err, err_size, "the double was told it cannot apply");
		return 0;
	}
	step(world, "executor.open");
	out->state = world;
	out->execute = world_execute;
	return 1;
}

static void world_executor_close(void *context, ncfg_executor_t *executor)
{
	(void)executor;
	step(context, "executor.close");
}

static void world_announce(void *context, const ncfg_proto_event_t *event)
{
	world_t    *world = context;
	const char *name = ncfg_proto_event_name(event->kind);

	if (event->kind == NCFG_PROTO_EVENT_DRIFT && event->interface.bytes) {
		step(world, "event:%s:%.*s", name, (int)event->interface.length,
		    event->interface.bytes);
		return;
	}
	step(world, "event:%s", name);
}

static void world_hook(void *context, const ncfg_hook_ref_t *hook, const ncfg_hook_env_t *env,
    const char *variable, const char *value)
{
	step(context, "hook:%s:%s:%s=%s", ncfg_hook_phase_name((ncfg_hook_phase_t)hook->phase),
	    env->iface ? env->iface : "?", variable ? variable : "?", value ? value : "?");
}

static void world_portal(void *context, const char *url, ncfg_portal_result_t *out)
{
	world_t *world = context;

	step(world, "portal:%s", url);
	out->verdict = world->verdict;
	(void)snprintf(out->detail, sizeof(out->detail), "the double answered");
}

static int world_release_contended(void *context, ncfg_daemon_state_t *state, char *err,
    size_t err_size)
{
	(void)state;
	(void)err;
	(void)err_size;
	step(context, "contention");
	return 1;
}

static void world_expiry(void *context, uint32_t seconds)
{
	step(context, "expiry:%u", (unsigned)seconds);
}

static uint64_t world_now(void *context)
{
	return ((world_t *)context)->now;
}

static void world_install(world_t *world, ncfg_reconcile_world_t *seams)
{
	memset(seams, 0, sizeof(*seams));
	seams->context = world;
	seams->executor_open = world_executor_open;
	seams->executor_close = world_executor_close;
	seams->announce = world_announce;
	seams->hook = world_hook;
	seams->portal = world_portal;
	seams->release_contended = world_release_contended;
	seams->expiry = world_expiry;
	seams->now = world_now;
}

/*
 * An observe seam that hands back a fresh copy of one fixture, with what the
 * hooks were last told read back onto it.
 *
 * **That second half is the real observer's, not this double's invention.**
 * `reobserve` reads the `/run` record into every observation, which is what
 * makes "fire on the change" possible for `drift` and `portal` without either
 * keeping state of its own -- and an in-memory copy beside it was removed for
 * exactly that reason (0084). A double that dropped it would make every
 * de-duplicating rule in this module unreachable, and they would pass by
 * never being asked.
 */
typedef struct {
	const char *body;
	const char *run;
} machine_t;

static int observe_fixture(void *context, const ncfg_document_t *desired, ncfg_observed_t **out,
    char *err, size_t err_size)
{
	const machine_t   *machine = context;
	ncfg_owned_state_t owned;
	ncfg_observed_t   *observed;
	size_t             at;

	(void)desired;
	(void)err;
	(void)err_size;
	observed = observed_of(machine->body);
	if (!observed) {
		return 0;
	}
	memset(&owned, 0, sizeof(owned));
	if (!ncfg_owned_read(machine->run, &owned, NULL, 0u) || owned.hook_state_count == 0u) {
		ncfg_owned_free(&owned);
		*out = observed;
		return 1;
	}
	observed->hook_state = calloc(owned.hook_state_count, sizeof(*observed->hook_state));
	if (observed->hook_state) {
		for (at = 0; at < owned.hook_state_count; at++) {
			observed->hook_state[at].interface = strdup(owned.hook_state[at].interface);
			observed->hook_state[at].phase = owned.hook_state[at].phase;
			observed->hook_state[at].value = strdup(owned.hook_state[at].value);
		}
		observed->hook_state_count = owned.hook_state_count;
	}
	ncfg_owned_free(&owned);
	*out = observed;
	return 1;
}

/* ------------------------------------------------------------------------ *
 * One pass, in order
 * ------------------------------------------------------------------------ */

/* Everything a pass needs, over directories of this test's own. */
typedef struct {
	ncfg_daemon_state_t state;
	ncfg_probes_t      *probes;
	ncfg_sims_t        *sims;
	ncfg_reconcile_t    loop;
	world_t             world;
	machine_t           machine;
	char                config[512];
	char                run[512];
} harness_t;

static int harness_start(harness_t *harness, const char *base, const char *leaf)
{
	char err[NCFG_ERROR_MAX];

	memset(harness, 0, sizeof(*harness));
	(void)snprintf(harness->config, sizeof(harness->config), "%s/%s-etc", base, leaf);
	(void)snprintf(harness->run, sizeof(harness->run), "%s/%s-run", base, leaf);
	(void)mkdir(harness->config, 0700);
	(void)mkdir(harness->run, 0700);
	err[0] = '\0';
	if (!ncfg_daemon_state_init(&harness->state, "", harness->config, harness->run, err,
	    sizeof(err))) {
		detail("the state would not start", err);
		return 0;
	}
	harness->probes = ncfg_probes_new(err, sizeof(err));
	harness->sims = ncfg_sims_new(err, sizeof(err));
	harness->loop.state = &harness->state;
	harness->loop.probes = harness->probes;
	harness->loop.sims = harness->sims;
	harness->machine.body = NULL;
	harness->machine.run = harness->run;
	harness->world.verdict = (int)NCFG_PORTAL_VERDICT_PORTAL;
	harness->world.now = 1000000u;
	world_install(&harness->world, &harness->loop.world);
	return harness->probes != NULL && harness->sims != NULL;
}

static void harness_stop(harness_t *harness)
{
	ncfg_probes_free(harness->probes);
	ncfg_sims_free(harness->sims);
	ncfg_daemon_state_free(&harness->state);
}

/*
 * The five orderings the Rust's comments call load-bearing, read back.
 *
 * Every one of them is a sentence there and none of them was a check: the
 * drift hooks before the reconcile so a script sees the machine as it drifted,
 * the portal checks after those and before the reconcile for the same reason,
 * and a contended radio given back before the reconcile rather than inside it.
 */
static void the_order_of_one_pass_is_the_contract(const char *base)
{
	harness_t               harness;
	ncfg_reconcile_wake_t   wake;
	ncfg_reconcile_report_t report;
	char                    err[NCFG_ERROR_MAX];

	if (!harness_start(&harness, base, "order")) {
		check(0, "a loop over directories of this test's own");
		harness_stop(&harness);
		return;
	}
	harness.state.desired = document_of(DRIFTING_DOCUMENT);
	harness.state.observed = observed_of(DRIFTING_OBSERVED);
	harness.state.observe = observe_fixture;
	harness.machine.body = DRIFTING_OBSERVED;
	harness.state.observe_context = &harness.machine;
	if (!harness.state.desired || !harness.state.observed) {
		check(0, "the drifting fixture reads");
		harness_stop(&harness);
		return;
	}

	memset(&wake, 0, sizeof(wake));
	ncfg_reconcile_collapse(&wake, NCFG_WOKE_TICK);
	err[0] = '\0';
	check(ncfg_reconcile_pass(&harness.loop, &wake, NULL, 0u, NULL, 0u, &report, err,
	    sizeof(err)),
	    "a pass on the loop's own backstop runs");
	detail("if not", err);

	check(report.looked && report.drift_count == 1u,
	    "it looked at the machine and found one thing that had moved");
	before(&harness.world, "event:drift:eth0", "hook:drift",
	    "the drift is announced before the script is run");
	before(&harness.world, "hook:drift", "op:",
	    "the `drift` hooks run before the reconcile, so a script sees the machine as "
	    "it drifted");
	before(&harness.world, "hook:drift", "portal:",
	    "the portal check runs after the drift hooks");
	before(&harness.world, "portal:", "op:",
	    "and before the reconcile, for the same reason");
	before(&harness.world, "portal:", "hook:portal",
	    "a captive portal that answered runs the `portal` hooks");
	before(&harness.world, "contention", "executor.open",
	    "a contended radio is given back before the reconcile, not inside it");
	check(step_at(&harness.world, "op:link.set_mtu") >= 0 && report.reconciled &&
	        report.actions_done == 1u,
	    "and then what drifted is put back");
	check(!harness.world.overflowed, "the step recorder had room for the whole pass");
	if (failures) {
		steps_said(&harness.world);
	}

	/*
	 * The hook is told once. The drift is still there on the next pass --
	 * nothing in this double actually changes the machine -- so firing on
	 * presence would run somebody else's script on every observation.
	 */
	harness.world.count = 0;
	err[0] = '\0';
	(void)ncfg_reconcile_pass(&harness.loop, &wake, NULL, 0u, NULL, 0u, &report, err,
	    sizeof(err));
	check(step_at(&harness.world, "hook:drift") < 0,
	    "the same drift on the next pass tells the hook nothing");
	check(step_at(&harness.world, "portal:") < 0,
	    "and the portal, already answered for, is not asked again");
	check(step_at(&harness.world, "op:link.set_mtu") >= 0,
	    "while the reconcile still runs, because the machine is still wrong");

	harness_stop(&harness);
}

/*
 * `--no-apply-on-start` holds the acting and nothing else.
 *
 * Gating the observation too left the daemon planning against what it saw at
 * startup, which is worse than not looking: it answers `apply` with a plan for
 * a machine that has since moved, and the operator gets an apply that does the
 * wrong work and reports success.
 */
static void a_held_loop_still_observes_and_still_reports(const char *base)
{
	harness_t               harness;
	ncfg_reconcile_wake_t   wake;
	ncfg_reconcile_report_t report;
	ncfg_proto_request_t    apply;
	char                    err[NCFG_ERROR_MAX];

	if (!harness_start(&harness, base, "held")) {
		check(0, "a held loop");
		harness_stop(&harness);
		return;
	}
	harness.state.desired = document_of(DRIFTING_DOCUMENT);
	harness.state.observed = observed_of(DRIFTING_OBSERVED);
	harness.state.observe = observe_fixture;
	harness.machine.body = DRIFTING_OBSERVED;
	harness.state.observe_context = &harness.machine;
	if (!harness.state.desired || !harness.state.observed) {
		check(0, "the held fixture reads");
		harness_stop(&harness);
		return;
	}
	err[0] = '\0';
	check(ncfg_reconcile_start(&harness.loop, 0, 0, err, sizeof(err)) && harness.loop.holding,
	    "`--no-apply-on-start` holds, and holds as a latch rather than a startup skip");
	check(step_at(&harness.world, "executor.open") < 0,
	    "so nothing was applied at start");

	memset(&wake, 0, sizeof(wake));
	ncfg_reconcile_collapse(&wake, NCFG_WOKE_KERNEL);
	err[0] = '\0';
	(void)ncfg_reconcile_pass(&harness.loop, &wake, NULL, 0u, NULL, 0u, &report, err,
	    sizeof(err));
	check(report.looked && report.drift_count == 1u,
	    "a held pass still looks at the machine and still finds the drift");
	check(step_at(&harness.world, "event:drift:eth0") >= 0, "still tells every subscriber");
	check(step_at(&harness.world, "hook:drift") >= 0, "still runs the `drift` hooks");
	check(step_at(&harness.world, "portal:") >= 0, "still asks about the captive portal");
	check(step_at(&harness.world, "contention") >= 0, "still gives a contended radio back");
	check(step_at(&harness.world, "op:") < 0 && !report.reconciled,
	    "and changes nothing at all, which is the only thing the flag holds");

	/* An explicit apply is what the hold was waiting for. Nothing else is. */
	harness.world.count = 0;
	{
		ncfg_proto_request_t reload = a_plain(NCFG_PROTO_REQ_RELOAD);

		err[0] = '\0';
		(void)ncfg_reconcile_pass(&harness.loop, &wake, NULL, 0u, &reload, 1u, &report,
		    err, sizeof(err));
		check(harness.loop.holding && !report.released_hold,
		    "a reload does not release the hold");
	}
	apply = an_apply(0, 0);
	err[0] = '\0';
	(void)ncfg_reconcile_pass(&harness.loop, &wake, NULL, 0u, &apply, 1u, &report, err,
	    sizeof(err));
	check(!harness.loop.holding && report.released_hold, "an apply does");

	harness_stop(&harness);
}

/*
 * A station that moved is told about before anything re-observes, so the
 * script sees the machine as the move left it -- and two roams are two events.
 */
static void a_roam_is_told_before_anything_looks(const char *base)
{
	harness_t               harness;
	ncfg_reconcile_wake_t   wake;
	ncfg_reconcile_roam_t   roams[2];
	ncfg_reconcile_report_t report;
	char                    err[NCFG_ERROR_MAX];

	if (!harness_start(&harness, base, "roam")) {
		check(0, "a loop for roaming");
		harness_stop(&harness);
		return;
	}
	harness.state.desired = document_of(
	    "\"devices\":[],\"interfaces\":[{\"name\":\"eth0\",\"hooks\":[{\"phase\":\"roam\","
	    "\"path\":\"/nonexistent/roam.sh\",\"sha256\":\"" ZEROS "\"}]}]");
	harness.state.observed = observed_of(DRIFTING_OBSERVED);
	harness.state.observe = observe_fixture;
	harness.machine.body = DRIFTING_OBSERVED;
	harness.state.observe_context = &harness.machine;
	if (!harness.state.desired) {
		check(0, "the roam fixture reads");
		harness_stop(&harness);
		return;
	}
	roams[0].interface = "eth0";
	roams[0].bssid = "aa:bb:cc:dd:ee:01";
	roams[1].interface = "eth0";
	roams[1].bssid = "aa:bb:cc:dd:ee:02";

	memset(&wake, 0, sizeof(wake));
	ncfg_reconcile_collapse(&wake, NCFG_WOKE_KERNEL);
	err[0] = '\0';
	(void)ncfg_reconcile_pass(&harness.loop, &wake, roams, 2u, NULL, 0u, &report, err,
	    sizeof(err));
	check(step_at(&harness.world, "hook:roam:eth0:NCFG_BSSID=aa:bb:cc:dd:ee:01") == 0,
	    "the `roam` hook runs first of everything, before the machine is re-read");
	check(step_at(&harness.world, "hook:roam:eth0:NCFG_BSSID=aa:bb:cc:dd:ee:02") == 1,
	    "and a station that moved twice moved twice: roams are never collapsed");
	if (failures) {
		steps_said(&harness.world);
	}

	/* A roam on an interface the document does not name runs nothing, rather
	 * than running every hook on the machine. */
	harness.world.count = 0;
	roams[0].interface = "wlan9";
	err[0] = '\0';
	(void)ncfg_reconcile_pass(&harness.loop, &wake, roams, 1u, NULL, 0u, &report, err,
	    sizeof(err));
	check(step_at(&harness.world, "hook:roam") < 0,
	    "a roam on an interface nobody configured runs nothing");

	harness_stop(&harness);
}

/* ------------------------------------------------------------------------ *
 * The reload, and the window over a change
 * ------------------------------------------------------------------------ */

static void write_config(const char *config_dir, const char *text)
{
	char path[640];

	(void)snprintf(path, sizeof(path), "%s/netcfgd.conf", config_dir);
	if (!testdir_write(path, text, strlen(text))) {
		check(0, "a configuration fixture is written");
	}
}

#define WITH_A_WINDOW                    \
	"global {\n\tconfirm = 30\n}\n" \
	"interface eth0 {\n\tconfig = \"192.0.2.10/24\"\n}\n"

/* The same link with nothing routable on it, which is every interface the
 * kernel has just brought up. */
#define LINK_LOCAL_ONLY                                                              \
	"\"links\":[{\"name\":\"eth0\",\"index\":2,\"mtu\":1500,\"up\":true,"        \
	"\"carrier\":true,\"ownership\":\"unknown\"}],"                                  \
	"\"addresses\":[{\"interface\":\"eth0\",\"address\":\"fe80::1/64\","           \
	"\"origin\":\"link_local\",\"ownership\":\"unknown\"}]"

/* A machine with the link up and no address on it, so the configuration above
 * has something to do. */
#define BARE_LINK                                                            \
	"\"links\":[{\"name\":\"eth0\",\"index\":2,\"mtu\":1500,\"up\":true," \
	"\"carrier\":true,\"ownership\":\"unknown\"}]"

/*
 * **"The file was written" is not "the configuration changed".**
 *
 * An editor writing the same bytes, or a configuration-management tool
 * rewriting the file on a timer, is a write -- and either of those on a pass
 * that is also correcting drift used to arm a window over the drift
 * correction, which 0157 says never happens. Measured in the Rust with a
 * sysctl, whose drift the kernel does not announce: on expiry the window
 * reverts netcfgd's own repair, the drift is found again on the next pass, and
 * the machine oscillates.
 *
 * Comparing the document either side of the reload is what makes the exclusion
 * true rather than intended, and this is the check that says so.
 */
static void a_byte_identical_rewrite_arms_nothing(const char *base)
{
	harness_t               harness;
	ncfg_reconcile_wake_t   wake;
	ncfg_reconcile_report_t report;
	ncfg_document_t        *last_good;
	char                    err[NCFG_ERROR_MAX];

	if (!harness_start(&harness, base, "rewrite")) {
		check(0, "a loop over a real configuration directory");
		harness_stop(&harness);
		return;
	}
	harness.state.observe = observe_fixture;
	harness.machine.body = BARE_LINK;
	harness.state.observe_context = &harness.machine;
	harness.state.observed = observed_of(BARE_LINK);
	write_config(harness.config, WITH_A_WINDOW);

	/* Something to fall back to, and not the placeholder: a window over the
	 * placeholder is a scheduled outage rather than a safety net. */
	last_good = document_of("\"devices\":[],\"interfaces\":[{\"name\":\"eth0\"}]");
	if (!last_good || !harness.state.observed) {
		check(0, "the rewrite fixture is built");
		ncfg_document_free(last_good);
		harness_stop(&harness);
		return;
	}
	err[0] = '\0';
	check(ncfg_confirm_write_last_good(harness.run, last_good, err, sizeof(err)),
	    "a last-good configuration is recorded");
	ncfg_document_free(last_good);

	memset(&wake, 0, sizeof(wake));
	ncfg_reconcile_collapse(&wake, NCFG_WOKE_CONFIG);
	err[0] = '\0';
	(void)ncfg_reconcile_pass(&harness.loop, &wake, NULL, 0u, NULL, 0u, &report, err,
	    sizeof(err));
	check(report.reloaded && report.config_is_new,
	    "a configuration that was not there before is a new one");
	check(step_at(&harness.world, "event:reloaded") >= 0, "and every client is told");
	check(report.reconciled && report.armed,
	    "so the change it applies is covered by the window the document asks for");
	check(step_at(&harness.world, "expiry:30") >= 0,
	    "with a timer, or the window never closes and the change stands unconfirmed");
	check(step_at(&harness.world, "event:confirm_armed") >= 0, "and the clients are told");
	if (failures) {
		steps_said(&harness.world);
	}

	/*
	 * Now the same bytes again, over a machine that is still drifting -- the
	 * double changes nothing, so the address is still missing. The reload
	 * happens, the document does not move, and no window may be armed over
	 * netcfgd putting its own configuration back.
	 */
	{
		char message[NCFG_ERROR_MAX];

		message[0] = '\0';
		(void)ncfg_confirm_clear_window(harness.run, message, sizeof(message));
	}
	harness.world.count = 0;
	write_config(harness.config, WITH_A_WINDOW);
	err[0] = '\0';
	(void)ncfg_reconcile_pass(&harness.loop, &wake, NULL, 0u, NULL, 0u, &report, err,
	    sizeof(err));
	check(report.reloaded, "the file was written again, so it is read again");
	check(!report.config_is_new,
	    "but the document did not move, which is what the comparison is for");
	check(report.reconciled && !report.armed,
	    "so the drift is still corrected and no window is armed over the correction");
	check(step_at(&harness.world, "expiry:") < 0, "and no timer is started for it");
	if (failures) {
		steps_said(&harness.world);
	}

	harness_stop(&harness);
}

/*
 * A window with time left is not one that closed.
 *
 * `confirm_expired` carries no identity, so a timer outliving its own window
 * used to revert whatever window happened to be open when it fired: a window
 * confirmed at three seconds left its six-second timer running, a second
 * change armed a new window at five, and at six the first timer reverted the
 * second window two seconds into its life.
 */
static void a_stale_timer_finds_nothing_to_do(const char *base)
{
	harness_t               harness;
	ncfg_reconcile_wake_t   wake;
	ncfg_reconcile_report_t report;
	ncfg_confirm_window_t   window;
	ncfg_document_t        *last_good;
	char                    err[NCFG_ERROR_MAX];

	if (!harness_start(&harness, base, "stale")) {
		check(0, "a loop with a window open");
		harness_stop(&harness);
		return;
	}
	harness.state.observe = observe_fixture;
	harness.machine.body = BARE_LINK;
	harness.state.observe_context = &harness.machine;
	harness.state.observed = observed_of(BARE_LINK);
	last_good = document_of("\"devices\":[],\"interfaces\":[{\"name\":\"eth0\"}]");
	if (!last_good || !harness.state.observed) {
		check(0, "the stale-timer fixture is built");
		ncfg_document_free(last_good);
		harness_stop(&harness);
		return;
	}
	(void)ncfg_confirm_write_last_good(harness.run, last_good, NULL, 0u);
	ncfg_document_free(last_good);

	memset(&window, 0, sizeof(window));
	window.window_seconds = 60u;
	window.deadline_epoch = harness.world.now + 30u;
	err[0] = '\0';
	check(ncfg_confirm_write_window(harness.run, &window, err, sizeof(err)),
	    "a window with thirty seconds left is open");

	memset(&wake, 0, sizeof(wake));
	ncfg_reconcile_collapse(&wake, NCFG_WOKE_CONFIRM_EXPIRED);
	err[0] = '\0';
	(void)ncfg_reconcile_pass(&harness.loop, &wake, NULL, 0u, NULL, 0u, &report, err,
	    sizeof(err));
	check(!report.window_resolved,
	    "a timer that fired for some other window finds nothing to do");
	check(ncfg_confirm_read_window(harness.run, &window),
	    "and the open window is still open, rather than reverted two seconds in");

	/* And when the clock really has passed the deadline, the tick alone is
	 * enough -- a timer that never started must not cost the window. */
	harness.world.now = window.deadline_epoch + 1u;
	harness.world.count = 0;
	memset(&wake, 0, sizeof(wake));
	ncfg_reconcile_collapse(&wake, NCFG_WOKE_TICK);
	err[0] = '\0';
	(void)ncfg_reconcile_pass(&harness.loop, &wake, NULL, 0u, NULL, 0u, &report, err,
	    sizeof(err));
	check(report.window_resolved, "a tick closes a window whose timer never started (0234)");
	check(!ncfg_confirm_read_window(harness.run, &window), "and the window is gone");
	check(step_at(&harness.world, "event:confirm_resolved") >= 0, "with every client told");
	if (failures) {
		steps_said(&harness.world);
	}

	harness_stop(&harness);
}

/*
 * An open window holds the reconcile off.
 *
 * Reconciling over it would apply something the operator has not accepted yet,
 * on top of something they may be about to reject, and the revert would then
 * undo a state nobody ever chose.
 */
static void an_open_window_holds_the_reconcile_off(const char *base)
{
	harness_t               harness;
	ncfg_reconcile_wake_t   wake;
	ncfg_reconcile_report_t report;
	ncfg_confirm_window_t   window;
	char                    err[NCFG_ERROR_MAX];

	if (!harness_start(&harness, base, "deferred")) {
		check(0, "a loop with a window in the way");
		harness_stop(&harness);
		return;
	}
	harness.state.desired = document_of(DRIFTING_DOCUMENT);
	harness.state.observed = observed_of(DRIFTING_OBSERVED);
	harness.state.observe = observe_fixture;
	harness.machine.body = DRIFTING_OBSERVED;
	harness.state.observe_context = &harness.machine;
	if (!harness.state.desired || !harness.state.observed) {
		check(0, "the deferral fixture reads");
		harness_stop(&harness);
		return;
	}
	memset(&window, 0, sizeof(window));
	window.window_seconds = 60u;
	window.deadline_epoch = harness.world.now + 60u;
	(void)ncfg_confirm_write_window(harness.run, &window, NULL, 0u);

	memset(&wake, 0, sizeof(wake));
	ncfg_reconcile_collapse(&wake, NCFG_WOKE_KERNEL);
	err[0] = '\0';
	(void)ncfg_reconcile_pass(&harness.loop, &wake, NULL, 0u, NULL, 0u, &report, err,
	    sizeof(err));
	check(report.looked && report.drift_count == 1u,
	    "the machine is still looked at, and the drift still reported");
	check(step_at(&harness.world, "op:") < 0 && !report.reconciled,
	    "and nothing is applied over a change the operator has not accepted yet");

	/* A pending apply carrying a window is the other half: the operator is
	 * saying they want this change to be revertible, and the apply is served
	 * a moment later with the window that goes with it. */
	(void)ncfg_confirm_clear_window(harness.run, NULL, 0u);
	harness.world.count = 0;
	{
		ncfg_proto_request_t wants = an_apply(1, 60);

		err[0] = '\0';
		(void)ncfg_reconcile_pass(&harness.loop, &wake, NULL, 0u, &wants, 1u, &report,
		    err, sizeof(err));
		check(step_at(&harness.world, "op:") < 0 && !report.reconciled,
		    "a waiting `--confirm-within` defers the pass, so the window covers "
		    "the change rather than nothing");
	}
	harness.world.count = 0;
	{
		ncfg_proto_request_t plain = an_apply(0, 0);

		err[0] = '\0';
		(void)ncfg_reconcile_pass(&harness.loop, &wake, NULL, 0u, &plain, 1u, &report,
		    err, sizeof(err));
		check(report.reconciled,
		    "while an apply with no window in it does not defer anything");
	}

	harness_stop(&harness);
}

/*
 * A portal check fires on a *joining*, and a link-local address is not one.
 *
 * Every interface that is up has an `fe80::` address the moment the kernel
 * brings it up, so a check for "has an address" would be true from the instant
 * the link existed and never change again -- which is what the first version
 * of this did, and 0095 records how it was found. The record goes to `bare`,
 * nothing is asked, and the transition is still there to fire on when a real
 * address arrives.
 */
static void a_link_local_address_is_not_a_joining(const char *base)
{
	harness_t               harness;
	ncfg_reconcile_wake_t   wake;
	ncfg_reconcile_report_t report;
	char                    err[NCFG_ERROR_MAX];

	if (!harness_start(&harness, base, "linklocal")) {
		check(0, "a loop over a link with nothing routable on it");
		harness_stop(&harness);
		return;
	}
	harness.state.desired = document_of(DRIFTING_DOCUMENT);
	harness.machine.body = LINK_LOCAL_ONLY;
	harness.state.observed = observed_of(LINK_LOCAL_ONLY);
	harness.state.observe = observe_fixture;
	harness.state.observe_context = &harness.machine;
	if (!harness.state.desired || !harness.state.observed) {
		check(0, "the link-local fixture reads");
		harness_stop(&harness);
		return;
	}
	memset(&wake, 0, sizeof(wake));
	ncfg_reconcile_collapse(&wake, NCFG_WOKE_TICK);
	err[0] = '\0';
	(void)ncfg_reconcile_pass(&harness.loop, &wake, NULL, 0u, NULL, 0u, &report, err,
	    sizeof(err));
	check(step_at(&harness.world, "portal:") < 0,
	    "an interface holding only a link-local address is not asked about");

	/* And when a routable address arrives, the transition is still there. */
	harness.machine.body = DRIFTING_OBSERVED;
	harness.world.count = 0;
	err[0] = '\0';
	(void)ncfg_reconcile_pass(&harness.loop, &wake, NULL, 0u, NULL, 0u, &report, err,
	    sizeof(err));
	check(step_at(&harness.world, "portal:") >= 0,
	    "and the joining that follows is, which is the transition this fires on");

	harness_stop(&harness);
}

/*
 * A loop with no way to change the machine goes on watching it.
 *
 * Every seam may be absent and the pass says what a missing one costs rather
 * than refusing: an apply that cannot start is a fact to report, not a reason
 * to stop observing.
 */
static void a_loop_with_no_seams_still_observes(const char *base)
{
	harness_t               harness;
	ncfg_reconcile_wake_t   wake;
	ncfg_reconcile_report_t report;
	char                    err[NCFG_ERROR_MAX];

	if (!harness_start(&harness, base, "seamless")) {
		check(0, "a loop with nothing installed");
		harness_stop(&harness);
		return;
	}
	harness.state.desired = document_of(DRIFTING_DOCUMENT);
	harness.state.observed = observed_of(DRIFTING_OBSERVED);
	harness.state.observe = observe_fixture;
	harness.machine.body = DRIFTING_OBSERVED;
	harness.state.observe_context = &harness.machine;
	if (!harness.state.desired || !harness.state.observed) {
		check(0, "the seamless fixture reads");
		harness_stop(&harness);
		return;
	}
	memset(&harness.loop.world, 0, sizeof(harness.loop.world));

	memset(&wake, 0, sizeof(wake));
	ncfg_reconcile_collapse(&wake, NCFG_WOKE_TICK);
	err[0] = '\0';
	check(ncfg_reconcile_pass(&harness.loop, &wake, NULL, 0u, NULL, 0u, &report, err,
	    sizeof(err)),
	    "a pass with no seam installed at all still runs");
	check(report.looked && report.drift_count == 1u, "and still finds what has moved");
	check(!report.reconciled, "while changing nothing, because it has no way to");

	harness_stop(&harness);
}

/*
 * The startup apply records what stood as the configuration to fall back to,
 * and never arms a window.
 *
 * `ncfg_reconcile_establish_last_good` writes an empty document before this
 * runs, so a window armed at boot and left unconfirmed on a machine that has
 * never applied would revert to *nothing* -- taking down everything netcfgd
 * had just brought up, N seconds after start, with no operator present.
 */
static void the_startup_apply_records_a_last_good_and_arms_nothing(const char *base)
{
	harness_t               harness;
	ncfg_reconcile_report_t report;
	ncfg_document_t        *found;
	ncfg_confirm_window_t   window;
	char                    err[NCFG_ERROR_MAX];

	if (!harness_start(&harness, base, "startup")) {
		check(0, "a loop to start");
		harness_stop(&harness);
		return;
	}
	harness.state.observe = observe_fixture;
	harness.machine.body = BARE_LINK;
	harness.state.observe_context = &harness.machine;
	harness.state.observed = observed_of(BARE_LINK);
	write_config(harness.config, WITH_A_WINDOW);
	err[0] = '\0';
	if (!ncfg_daemon_state_reload(&harness.state, err, sizeof(err))) {
		check(0, "the startup configuration compiles");
		detail("because", err);
		harness_stop(&harness);
		return;
	}

	err[0] = '\0';
	check(ncfg_reconcile_establish_last_good(&harness.state, err, sizeof(err)),
	    "an empty last-good is written before the first apply, so a window works "
	    "from the very beginning");
	memset(&report, 0, sizeof(report));
	err[0] = '\0';
	check(ncfg_reconcile_start(&harness.loop, 1, 0, err, sizeof(err)),
	    "and the daemon configures the machine at start");
	detail("if not", err);
	check(!harness.loop.holding, "without holding, since nothing asked it to");
	check(step_at(&harness.world, "op:") >= 0, "something was applied");
	check(!ncfg_confirm_read_window(harness.run, &window),
	    "and no window was armed at boot, which would revert to nothing");

	err[0] = '\0';
	found = ncfg_confirm_read_last_good(harness.run, err, sizeof(err));
	check(found != NULL && !ncfg_reconcile_document_is_empty(found),
	    "what was applied and stood is now the configuration a window falls back to");
	ncfg_document_free(found);

	/* And a machine that has just been put back is not one to apply over. */
	harness.world.count = 0;
	err[0] = '\0';
	check(ncfg_reconcile_start(&harness.loop, 1, 1, err, sizeof(err)) &&
	        step_at(&harness.world, "op:") < 0,
	    "a daemon that reverted a window at startup does not then apply over it");

	harness_stop(&harness);
}

/*
 * An apply that failed part-way is not the configuration a window falls back
 * to.
 *
 * The startup apply records a last-good so that the first
 * `apply --confirm-within` after a boot has somewhere to go -- but only where
 * it had no failure at all. Recording a half-applied machine would point the
 * next window's revert at a state nobody has ever been in, which is the shape
 * of the defect `ncfg_confirm_keep` records against the Rust and must not be
 * reintroduced from the other end.
 */
static void a_startup_apply_that_failed_records_no_last_good(const char *base)
{
	harness_t        harness;
	ncfg_document_t *found;
	char             err[NCFG_ERROR_MAX];

	if (!harness_start(&harness, base, "halfway")) {
		check(0, "a loop whose apply will fail");
		harness_stop(&harness);
		return;
	}
	harness.machine.body = BARE_LINK;
	harness.state.observe = observe_fixture;
	harness.state.observe_context = &harness.machine;
	harness.state.observed = observed_of(BARE_LINK);
	write_config(harness.config, WITH_A_WINDOW);
	err[0] = '\0';
	if (!harness.state.observed || !ncfg_daemon_state_reload(&harness.state, err, sizeof(err))) {
		check(0, "the half-applied fixture compiles");
		detail("because", err);
		harness_stop(&harness);
		return;
	}
	err[0] = '\0';
	check(ncfg_reconcile_establish_last_good(&harness.state, err, sizeof(err)),
	    "the placeholder is written before the first apply");

	/* The address is what this configuration is for, so refusing it is an
	 * apply that stopped part-way through. */
	harness.world.refuse = "addr.add";
	err[0] = '\0';
	check(ncfg_reconcile_start(&harness.loop, 1, 0, err, sizeof(err)),
	    "the daemon still starts, because a failed apply is not a failed start");
	check(step_at(&harness.world, "op:addr.add") >= 0, "and it did try");

	err[0] = '\0';
	found = ncfg_confirm_read_last_good(harness.run, err, sizeof(err));
	check(found != NULL && ncfg_reconcile_document_is_empty(found),
	    "but what did not stand is not recorded as the configuration to fall back to");
	ncfg_document_free(found);

	harness_stop(&harness);
}

int main(void)
{
	const char *base = testdir_make("reconcile");

	printf("== reconcile_test in %s\n", base);

	a_burst_collapses_to_what_it_means();
	a_tick_also_asks_whether_the_window_closed();
	only_a_requested_window_defers_the_loop();
	only_an_apply_releases_the_hold();
	the_drift_policy_in_force();
	a_pending_sim_cycle_is_not_drift_either(base);
	a_restricted_plan_keeps_only_what_it_may_act_on();
	drift_is_read_out_of_the_plan();
	more_drift_than_is_kept_is_counted();
	a_drift_hook_fires_on_the_change_not_on_the_condition();
	the_portal_record_decides_what_to_ask();
	an_inconclusive_check_does_not_consume_the_transition();
	the_reclaim_count_means_in_a_row();
	a_reclaim_is_asked_of_the_plan();
	a_window_is_armed_only_over_a_change();

	the_order_of_one_pass_is_the_contract(base);
	a_held_loop_still_observes_and_still_reports(base);
	a_roam_is_told_before_anything_looks(base);
	a_byte_identical_rewrite_arms_nothing(base);
	a_stale_timer_finds_nothing_to_do(base);
	an_open_window_holds_the_reconcile_off(base);
	a_link_local_address_is_not_a_joining(base);
	a_loop_with_no_seams_still_observes(base);
	the_startup_apply_records_a_last_good_and_arms_nothing(base);
	a_startup_apply_that_failed_records_no_last_good(base);

	testdir_remove(base);

	printf("reconcile_test: %d check(s)\n", checks);
	if (failures == 0) {
		printf("reconcile_test: all checks passed\n");
	} else {
		printf("reconcile_test: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
