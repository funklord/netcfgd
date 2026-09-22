/*
 * apply_test.c -- the executor, driven entirely through a recorder.
 *
 * WHAT NONE OF THIS TOUCHES
 *   No netlink socket is opened, no link is created, no address or route is
 *   moved, and `ip`, `nft` and `ethtool` are not run. `ncfg_kernel_new` -- the
 *   only thing in the module that does any of that -- is never called here.
 *   Every check drives a double through `ncfg_executor_t`, which is what the
 *   seam is for: the machine this runs on is somebody's workstation and the
 *   real netcfgd is configuring its network while this test runs.
 *
 *   Four checks at the end do fork a process, and they run a `#!/bin/sh`
 *   script the test wrote into a directory it made. Each is bounded by the
 *   runner's own timeout, and the one that times out on purpose uses a sleep
 *   of five seconds rather than the Rust's three hundred -- so a regression in
 *   the group kill leaves something that dies on its own while still
 *   reproducing the defect.
 *
 * WHY THE ASSERTIONS ARE ON SEQUENCES
 *   Ordering is the property nearly all of this is about, and a set cannot
 *   tell any of the three ordering rules apart from its opposite: "addr.add
 *   and route.add both happened" is equally true of the plan that works and
 *   the plan that gets `ENETUNREACH`. So the recorder keeps what it was asked
 *   for **in order**, and the checks compare a joined string -- which also
 *   prints readably when it is wrong.
 *
 * WHERE THE FIXTURES COME FROM
 *   The ordering checks build a real plan with `ncfg_plan_build` and apply it,
 *   rather than hand-assembling the action list. A hand-built list would prove
 *   that the loop preserves whatever order it was given, which is true and
 *   uninteresting; running the planner's own output proves the pair of them
 *   together produce the order the kernel needs. The revert checks do build by
 *   hand, because their subject is which records are eligible and that is
 *   easiest to state as four records with four different outcomes -- which is
 *   how the Rust states it too.
 */
#include "ncfg/apply.h"
#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/dns.h"
#include "ncfg/document.h"
#include "ncfg/hooks.h"
#include "ncfg/observed.h"
#include "ncfg/plan.h"
#include "ncfg/state.h"
#include "ncfg/value.h"

#include "tempdir.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* The model's own structs hold `char *`, and a test's values are literals.
 * `-Wwrite-strings` makes a literal `const char[]`, so the cast is what lets a
 * fixture be written as data. Nothing here is ever modified or freed. */
#define LIT(text) ((char *)(uintptr_t)(text))

static int failures;
static int checks;

static void check(int condition, const char *what)
{
	checks++;
	printf("%-70s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

/* ------------------------------------------------------------------------ *
 * The recording double
 *
 * The whole point of the seam. It answers every op, keeps what it was asked
 * for in order, and can be told to fail at a chosen step -- which is how the
 * stop-and-skip behaviour is checked without a kernel that can refuse
 * anything.
 * ------------------------------------------------------------------------ */

#define RECORDER_MAX 64
#define DESCRIPTION_MAX 160

typedef struct {
	char   seen[RECORDER_MAX][DESCRIPTION_MAX];
	size_t count;
	/* The step to fail at, counting from zero, or -1 for never. */
	long   fail_at;
	/* What that failure says. */
	const char *failure;
	/* Set if it was asked for more than `RECORDER_MAX` ops, so a silently
	 * truncated sequence cannot pass for a short one. */
	int    overflowed;
} recorder_t;

/*
 * One op as a line.
 *
 * The name alone is not enough for the checks that matter: five hook.run
 * actions in a teardown are five identical words unless the phase is in the
 * line, and an ordering check on identical words proves nothing.
 */
static void describe(const ncfg_op_t *op, char *out, size_t out_size)
{
	const char *name = ncfg_op_name(op);

	switch ((ncfg_op_kind_t)op->kind) {
	case NCFG_OP_HOOK_RUN:
		(void)snprintf(out, out_size, "hook.run(%s)",
		    ncfg_hook_phase_name((ncfg_hook_phase_t)op->u.hook.phase));
		return;
	case NCFG_OP_ADDR_ADD:
		(void)snprintf(out, out_size, "addr.add %s %s", op->u.addr_add.iface,
		    op->u.addr_add.addr);
		return;
	case NCFG_OP_ADDR_DEL:
		(void)snprintf(out, out_size, "addr.del %s %s", op->u.addr_del.iface,
		    op->u.addr_del.addr);
		return;
	case NCFG_OP_ROUTE_ADD:
	case NCFG_OP_ROUTE_DEL:
		(void)snprintf(out, out_size, "%s %s %s", name, op->u.route.iface,
		    op->u.route.route && op->u.route.route->destination ?
		    op->u.route.route->destination : "?");
		return;
	case NCFG_OP_LINK_SET_MTU:
		(void)snprintf(out, out_size, "link.set_mtu %s %lld", op->u.set_mtu.name,
		    (long long)op->u.set_mtu.mtu);
		return;
	default:
		break;
	}
	{
		const char *interface = ncfg_op_interface(op);

		(void)snprintf(out, out_size, "%s%s%s", name, interface ? " " : "",
		    interface ? interface : "");
	}
}

static int recorder_execute(void *state, const ncfg_op_t *op, char *err, size_t err_size)
{
	recorder_t *recorder = state;

	if (recorder->count >= RECORDER_MAX) {
		recorder->overflowed = 1;
		ncfg_error_set(err, err_size, "the recorder has no room left");
		return 0;
	}
	describe(op, recorder->seen[recorder->count], DESCRIPTION_MAX);
	if (recorder->fail_at >= 0 && (size_t)recorder->fail_at == recorder->count) {
		recorder->count++;
		ncfg_error_set(err, err_size, "%s",
		    recorder->failure ? recorder->failure : "the double was told to fail here");
		return 0;
	}
	recorder->count++;
	return 1;
}

static void recorder_init(recorder_t *recorder, ncfg_executor_t *executor)
{
	memset(recorder, 0, sizeof(*recorder));
	recorder->fail_at = -1;
	executor->state = recorder;
	executor->execute = recorder_execute;
}

/* What it saw, joined, so a mismatch prints as one line. */
static void joined(const recorder_t *recorder, char *out, size_t out_size)
{
	size_t at = 0;
	size_t i;

	out[0] = '\0';
	for (i = 0; i < recorder->count; i++) {
		int wrote = snprintf(out + at, out_size - at, "%s%s", at ? "," : "",
		    recorder->seen[i]);

		if (wrote < 0 || (size_t)wrote >= out_size - at) {
			return;
		}
		at += (size_t)wrote;
	}
}

/* Assert the whole sequence, printing both sides when they differ. */
static void sequence_is(const recorder_t *recorder, const char *wanted, const char *what)
{
	char got[2048];

	joined(recorder, got, sizeof(got));
	if (strcmp(got, wanted) != 0 || recorder->overflowed) {
		printf("  wanted: %s\n", wanted);
		printf("  got:    %s\n", got);
	}
	check(!recorder->overflowed && strcmp(got, wanted) == 0, what);
}

/* ------------------------------------------------------------------------ *
 * Fixtures: a document, an observation and the plan between them
 * ------------------------------------------------------------------------ */

static ncfg_document_t *document_of(const char *body)
{
	char             text[8192];
	char             message[NCFG_ERROR_MAX];
	ncfg_document_t *document;

	(void)snprintf(text, sizeof(text),
	    "{\"schema_version\":{\"major\":1,\"minor\":1},\"generated_by\":\"apply_test\","
	    "\"globals\":{},\"networks\":[],%s}", body);
	message[0] = '\0';
	document = ncfg_document_read(text, strlen(text), message, sizeof(message));
	if (!document) {
		printf("  fixture document did not read: %s\n", message);
	}
	return document;
}

static ncfg_observed_t *observed_of(const char *body)
{
	char             text[8192];
	char             message[NCFG_ERROR_MAX];
	ncfg_observed_t *observed;

	(void)snprintf(text, sizeof(text), "{%s}", body);
	message[0] = '\0';
	observed = ncfg_observed_read(text, strlen(text), message, sizeof(message));
	if (!observed) {
		printf("  fixture observation did not read: %s\n", message);
	}
	return observed;
}

#define LINK(name) \
	"{\"name\":\"" name "\",\"index\":2,\"mtu\":1500,\"up\":false,\"carrier\":true," \
	"\"ownership\":\"unknown\"}"
#define LINK_UP(name) \
	"{\"name\":\"" name "\",\"index\":2,\"mtu\":1500,\"up\":true,\"carrier\":true," \
	"\"ownership\":\"unknown\"}"

static ncfg_plan_t *plan_of(const char *body, const char *observation,
    const ncfg_plan_options_t *options, ncfg_document_t **document_out,
    ncfg_observed_t **observed_out)
{
	char             message[NCFG_ERROR_MAX];
	ncfg_document_t *document = document_of(body);
	ncfg_observed_t *observed = observed_of(observation);
	ncfg_plan_t     *plan;

	*document_out = document;
	*observed_out = observed;
	if (!document || !observed) {
		return NULL;
	}
	message[0] = '\0';
	plan = ncfg_plan_build(document, observed, options, message, sizeof(message));
	if (!plan) {
		printf("  could not build the plan: %s\n", message);
	}
	return plan;
}

static void release(ncfg_plan_t *plan, ncfg_document_t *document, ncfg_observed_t *observed)
{
	ncfg_plan_free(plan);
	ncfg_document_free(document);
	ncfg_observed_free(observed);
}

/* ------------------------------------------------------------------------ *
 * The ordering rules
 * ------------------------------------------------------------------------ */

/*
 * The executor carries a plan out in plan order, and that is the point.
 *
 * Rule 3 says an address may go on a link that is down, so `addr.add` does not
 * wait for `link.up`; the kernel rejects a route on a down link, so `route.add`
 * does. An executor that grouped by interface or sorted by op kind would take
 * both back, and neither would be visible in a check on the *set* of ops.
 */
static void a_plan_is_carried_out_in_the_order_it_was_planned(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_executor_t  executor;
	recorder_t       recorder;
	ncfg_journal_t   journal;
	char             message[NCFG_ERROR_MAX];
	ncfg_plan_t     *plan = plan_of(
	    "\"devices\":[{\"name\":\"eth0\",\"kind\":{\"kind\":\"physical\"},\"mtu\":9000}],"
	    "\"interfaces\":[{\"name\":\"eth0\","
	    "\"addressing\":[{\"source\":\"static\",\"address\":\"192.168.1.10/24\"}],"
	    "\"routes\":[{\"destination\":\"default\",\"via\":\"192.168.1.1\"}]}]",
	    "\"links\":[" LINK("eth0") "]", NULL, &document, &observed);

	recorder_init(&recorder, &executor);
	ncfg_journal_init(&journal);
	message[0] = '\0';
	check(plan && ncfg_apply(plan, &executor, &journal, message, sizeof(message)),
	    "a plan the planner built is applied");
	sequence_is(&recorder,
	    "link.set_mtu eth0 9000,link.up eth0,addr.add eth0 192.168.1.10/24,"
	    "route.add eth0 default",
	    "and every action reaches the executor in plan order");
	check(ncfg_journal_succeeded(&journal) && ncfg_journal_done(&journal) == 4u &&
	    ncfg_journal_skipped(&journal) == 0u,
	    "the journal says four done, none skipped");
	ncfg_journal_free(&journal);
	release(plan, document, observed);
}

/*
 * Addresses go in before the routes that need them.
 *
 * The rule this file exists to protect at execution time: a route installed
 * before the address that makes its next hop reachable is `ENETUNREACH`, and
 * the interface comes up with no default route and no error anybody reads. Two
 * of each, so that a check on positions cannot pass by accident on a plan of
 * length two.
 */
static void addresses_go_in_before_the_routes_that_need_them(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_executor_t  executor;
	recorder_t       recorder;
	ncfg_journal_t   journal;
	char             message[NCFG_ERROR_MAX];
	ncfg_plan_t     *plan = plan_of(
	    "\"devices\":[{\"name\":\"eth0\",\"kind\":{\"kind\":\"physical\"}}],"
	    "\"interfaces\":[{\"name\":\"eth0\","
	    "\"addressing\":[{\"source\":\"static\",\"address\":\"192.168.1.10/24\"},"
	    "{\"source\":\"static\",\"address\":\"10.9.0.2/24\"}],"
	    "\"routes\":[{\"destination\":\"default\",\"via\":\"192.168.1.1\"},"
	    "{\"destination\":\"172.16.0.0/16\",\"via\":\"10.9.0.1\"}]}]",
	    "\"links\":[" LINK_UP("eth0") "]", NULL, &document, &observed);

	recorder_init(&recorder, &executor);
	ncfg_journal_init(&journal);
	message[0] = '\0';
	if (plan && ncfg_apply(plan, &executor, &journal, message, sizeof(message))) {
		sequence_is(&recorder,
		    "addr.add eth0 192.168.1.10/24,addr.add eth0 10.9.0.2/24,"
		    "route.add eth0 default,route.add eth0 172.16.0.0/16",
		    "both addresses are added before either route is");
	} else {
		check(0, "both addresses are added before either route is");
	}
	ncfg_journal_free(&journal);
	release(plan, document, observed);
}

/*
 * Rule 6: the hook phases bracket a bring-up.
 *
 * `pre_up` before `link.up`, `up` while the link is live and carries nothing,
 * `post_up` after the last addressing action. Decision 0063 is what the shape
 * cost: both up hooks used to be emitted unconditionally, so a converged
 * interface ran them on every apply -- against the promise that an
 * already-correct state runs zero hooks -- and a *disabled* interface produced
 * a plan that went `pre_up`, `link.down`, `post_down`, `post_up`.
 */
static void the_hook_phases_bracket_a_bring_up(void)
{
	static const char *const body =
	    "\"devices\":[{\"name\":\"eth0\",\"kind\":{\"kind\":\"physical\"}}],"
	    "\"interfaces\":[{\"name\":\"eth0\","
	    "\"addressing\":[{\"source\":\"static\",\"address\":\"10.0.0.1/24\"}],"
	    "\"hooks\":[{\"phase\":\"pre_up\",\"path\":\"/run/pre\",\"sha256\":\"00\"},"
	    "{\"phase\":\"up\",\"path\":\"/run/mid\",\"sha256\":\"22\"},"
	    "{\"phase\":\"post_up\",\"path\":\"/run/post\",\"sha256\":\"11\"}]}]";
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_executor_t  executor;
	recorder_t       recorder;
	ncfg_journal_t   journal;
	char             message[NCFG_ERROR_MAX];
	ncfg_plan_t     *plan = plan_of(body, "\"links\":[" LINK("eth0") "]", NULL, &document,
	    &observed);

	recorder_init(&recorder, &executor);
	ncfg_journal_init(&journal);
	message[0] = '\0';
	if (plan && ncfg_apply(plan, &executor, &journal, message, sizeof(message))) {
		sequence_is(&recorder,
		    "hook.run(pre_up),link.up eth0,hook.run(up),addr.add eth0 10.0.0.1/24,"
		    "hook.run(post_up)",
		    "the hook phases bracket a bring-up (0063)");
	} else {
		check(0, "the hook phases bracket a bring-up (0063)");
	}
	ncfg_journal_free(&journal);
	release(plan, document, observed);

	/* And a converged interface runs none of them: the executor is asked to do
	 * nothing at all, which is the normal case rather than the edge case. */
	plan = plan_of(body,
	    "\"links\":[" LINK_UP("eth0") "],"
	    "\"addresses\":[{\"interface\":\"eth0\",\"address\":\"10.0.0.1/24\","
	    "\"proto\":110,\"ownership\":\"ours\",\"origin\":\"static\"}]",
	    NULL, &document, &observed);
	recorder_init(&recorder, &executor);
	ncfg_journal_init(&journal);
	message[0] = '\0';
	check(plan && ncfg_apply(plan, &executor, &journal, message, sizeof(message)) &&
	    recorder.count == 0u && ncfg_journal_succeeded(&journal),
	    "an already-correct interface runs zero hooks and zero ops (0063)");
	ncfg_journal_free(&journal);
	release(plan, document, observed);
}

/*
 * The withdrawal sits between `pre_down` and `down`.
 *
 * `pre_down` runs while the interface still works -- unmounting a share,
 * telling a peer -- then the addresses netcfgd installed come off, and only
 * then does `down` fire, with the link still up and nothing on it. That middle
 * step is what makes the two phases different moments rather than the same
 * one, and it is a fix in its own right: `link.down` flushes IPv6 and **leaves
 * IPv4 behind**, measured on a real kernel, so a disabled interface kept a
 * stale address that netcfgd still recorded as its own.
 */
static void the_withdrawal_sits_between_pre_down_and_down(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_executor_t  executor;
	recorder_t       recorder;
	ncfg_journal_t   journal;
	char             message[NCFG_ERROR_MAX];
	ncfg_plan_t     *plan = plan_of(
	    "\"devices\":[{\"name\":\"eth0\",\"kind\":{\"kind\":\"physical\"}}],"
	    "\"interfaces\":[{\"name\":\"eth0\",\"enabled\":false,"
	    "\"hooks\":[{\"phase\":\"pre_down\",\"path\":\"/run/pre\",\"sha256\":\"00\"},"
	    "{\"phase\":\"down\",\"path\":\"/run/mid\",\"sha256\":\"22\"},"
	    "{\"phase\":\"post_down\",\"path\":\"/run/post\",\"sha256\":\"11\"}]}]",
	    "\"links\":[" LINK_UP("eth0") "],"
	    "\"addresses\":[{\"interface\":\"eth0\",\"address\":\"10.0.0.1/24\","
	    "\"ownership\":\"ours\"}]",
	    NULL, &document, &observed);

	recorder_init(&recorder, &executor);
	ncfg_journal_init(&journal);
	message[0] = '\0';
	if (plan && ncfg_apply(plan, &executor, &journal, message, sizeof(message))) {
		sequence_is(&recorder,
		    "hook.run(pre_down),addr.del eth0 10.0.0.1/24,hook.run(down),"
		    "link.down eth0,hook.run(post_down)",
		    "the withdrawal sits between pre_down and down");
	} else {
		check(0, "the withdrawal sits between pre_down and down");
	}
	ncfg_journal_free(&journal);
	release(plan, document, observed);
}

/*
 * The confirm window is armed before anything it covers.
 *
 * Rule 8. An arm that ran after the change would cover nothing that had
 * already happened, which is the whole safety net gone in the case it exists
 * for -- a change that severs the session that made it.
 */
static void the_confirm_window_is_armed_before_anything_it_covers(void)
{
	ncfg_plan_options_t options;
	ncfg_document_t    *document;
	ncfg_observed_t    *observed;
	ncfg_executor_t     executor;
	recorder_t          recorder;
	ncfg_journal_t      journal;
	char                message[NCFG_ERROR_MAX];
	ncfg_plan_t        *plan;

	memset(&options, 0, sizeof(options));
	options.confirm_window.has = 1;
	options.confirm_window.value = 90;
	options.revert_to = "abc";
	plan = plan_of(
	    "\"devices\":[{\"name\":\"eth0\",\"kind\":{\"kind\":\"physical\"}}],"
	    "\"interfaces\":[{\"name\":\"eth0\","
	    "\"addressing\":[{\"source\":\"static\",\"address\":\"10.0.0.1/24\"}]}]",
	    "\"links\":[" LINK_UP("eth0") "]", &options, &document, &observed);

	recorder_init(&recorder, &executor);
	ncfg_journal_init(&journal);
	message[0] = '\0';
	if (plan && ncfg_apply(plan, &executor, &journal, message, sizeof(message))) {
		sequence_is(&recorder, "commit.arm,addr.add eth0 10.0.0.1/24",
		    "commit.arm reaches the executor before the change it covers");
	} else {
		check(0, "commit.arm reaches the executor before the change it covers");
	}
	/* And it is a marker rather than work: the executor is expected to accept
	 * it and do nothing, not to fail the very plan it is bracketing. */
	message[0] = '\0';
	check(plan && plan->action_count > 0u &&
	    ncfg_apply_supported(&plan->actions[0].op, message, sizeof(message)),
	    "and the commit family is accepted rather than refused");
	ncfg_journal_free(&journal);
	release(plan, document, observed);
}

/* ------------------------------------------------------------------------ *
 * Failure
 * ------------------------------------------------------------------------ */

/*
 * Execution stops at the first failure, and what did not run is written down.
 *
 * Section 4. "What did not run" is the question an operator asks next, and a
 * journal that dropped those actions instead of recording them as skipped
 * could not answer it -- so this asserts the count as well as the outcome.
 */
static void a_failure_stops_the_plan_and_the_rest_is_recorded_as_skipped(void)
{
	ncfg_document_t     *document;
	ncfg_observed_t     *observed;
	ncfg_executor_t      executor;
	recorder_t           recorder;
	ncfg_journal_t       journal;
	const ncfg_record_t *failure;
	char                 message[NCFG_ERROR_MAX];
	ncfg_plan_t         *plan = plan_of(
	    "\"devices\":[{\"name\":\"eth0\",\"kind\":{\"kind\":\"physical\"},\"mtu\":9000}],"
	    "\"interfaces\":[{\"name\":\"eth0\","
	    "\"addressing\":[{\"source\":\"static\",\"address\":\"192.168.1.10/24\"}],"
	    "\"routes\":[{\"destination\":\"default\",\"via\":\"192.168.1.1\"}]}]",
	    "\"links\":[" LINK("eth0") "]", NULL, &document, &observed);

	recorder_init(&recorder, &executor);
	/* The link comes up and then the address is refused, which is the shape a
	 * real failure has: the first half of the plan is already on the machine. */
	recorder.fail_at = 2;
	recorder.failure = "Cannot assign requested address";
	ncfg_journal_init(&journal);
	message[0] = '\0';
	check(plan && ncfg_apply(plan, &executor, &journal, message, sizeof(message)),
	    "a plan whose third action fails still produces a journal");
	sequence_is(&recorder,
	    "link.set_mtu eth0 9000,link.up eth0,addr.add eth0 192.168.1.10/24",
	    "and nothing after the failure is ever asked for");

	failure = ncfg_journal_failure(&journal);
	check(!ncfg_journal_succeeded(&journal), "the journal does not claim success");
	check(ncfg_journal_done(&journal) == 2u, "two actions are recorded as done");
	check(ncfg_journal_skipped(&journal) == 1u,
	    "and the action that never ran is skipped rather than dropped");
	check(failure && failure->op && strcmp(failure->op, "addr.add") == 0,
	    "the failure names the op that failed");
	check(failure && failure->error &&
	    strcmp(failure->error, "Cannot assign requested address") == 0,
	    "and carries the executor's own sentence");
	check(failure && failure->interface && strcmp(failure->interface, "eth0") == 0 &&
	    failure->reason.field && strcmp(failure->reason.field, "addressing[0]") == 0,
	    "and says which interface and which field the action was about");
	ncfg_journal_free(&journal);
	release(plan, document, observed);
}

/*
 * An executor that fails without saying why still produces a readable line.
 *
 * `"outcome":"failed"` beside `"error":null` is a journal entry that reads as a
 * failure nobody described, and the reader has no way to tell it from a bug in
 * the journal. So the absence is named instead.
 */
static void a_silent_failure_is_still_described(void)
{
	ncfg_document_t     *document;
	ncfg_observed_t     *observed;
	ncfg_executor_t      executor;
	recorder_t           recorder;
	ncfg_journal_t       journal;
	const ncfg_record_t *failure;
	char                 message[NCFG_ERROR_MAX];
	ncfg_plan_t         *plan = plan_of(
	    "\"devices\":[{\"name\":\"eth0\",\"kind\":{\"kind\":\"physical\"}}],"
	    "\"interfaces\":[{\"name\":\"eth0\","
	    "\"addressing\":[{\"source\":\"static\",\"address\":\"10.0.0.1/24\"}]}]",
	    "\"links\":[" LINK_UP("eth0") "]", NULL, &document, &observed);

	recorder_init(&recorder, &executor);
	recorder.fail_at = 0;
	recorder.failure = "";
	ncfg_journal_init(&journal);
	message[0] = '\0';
	(void)(plan && ncfg_apply(plan, &executor, &journal, message, sizeof(message)));
	failure = ncfg_journal_failure(&journal);
	check(failure && failure->error && failure->error[0] != '\0',
	    "a failure with no message is still given one");
	ncfg_journal_free(&journal);
	release(plan, document, observed);
}

/*
 * A plan that did not finish being built is not applied at all.
 *
 * Half a plan that looks whole is the one that gets applied: it describes less
 * than the machine needs and there is nothing on its face to say so.
 */
static void an_unfinished_plan_is_refused_rather_than_half_applied(void)
{
	ncfg_executor_t executor;
	recorder_t      recorder;
	ncfg_journal_t  journal;
	char            message[NCFG_ERROR_MAX];
	ncfg_plan_t    *plan = ncfg_plan_new(message, sizeof(message));

	recorder_init(&recorder, &executor);
	ncfg_journal_init(&journal);
	if (plan) {
		ncfg_op_t     op;
		ncfg_reason_t reason;

		memset(&op, 0, sizeof(op));
		op.kind = NCFG_OP_LINK_UP;
		op.u.named.name = "eth0";
		memset(&reason, 0, sizeof(reason));
		reason.field = "enabled";
		reason.desired = "true";
		reason.observed = "false";
		(void)ncfg_plan_add(plan, &op, &reason, NULL, 0, NULL);
		/* The sticky failure, reached the way a real one is: from inside. */
		plan->failed = 1;
		message[0] = '\0';
		check(!ncfg_apply(plan, &executor, &journal, message, sizeof(message)) &&
		    recorder.count == 0u,
		    "a plan that ran out of memory is refused, not partly applied");
	} else {
		check(0, "a plan that ran out of memory is refused, not partly applied");
	}
	ncfg_journal_free(&journal);
	ncfg_plan_free(plan);
}

/* ------------------------------------------------------------------------ *
 * Putting it back
 * ------------------------------------------------------------------------ */

/* An `link.set_mtu` on `e0` carrying `mtu`, which is the Rust's fixture. */
static void mtu_op(ncfg_op_t *op, int64_t mtu)
{
	memset(op, 0, sizeof(*op));
	op->kind = NCFG_OP_LINK_SET_MTU;
	op->u.set_mtu.name = "e0";
	op->u.set_mtu.mtu = mtu;
}

/* A plan of `count` MTU changes, each declaring the value it replaced as its
 * inverse. `inverses[i]` of 0 means the action declares none. */
static ncfg_plan_t *mtu_plan(const int64_t *inverses, size_t count)
{
	char          message[NCFG_ERROR_MAX];
	ncfg_plan_t  *plan = ncfg_plan_new(message, sizeof(message));
	ncfg_reason_t reason;
	size_t        i;

	if (!plan) {
		return NULL;
	}
	memset(&reason, 0, sizeof(reason));
	reason.interface = "e0";
	reason.field = "mtu";
	reason.desired = "1400";
	reason.observed = "1500";
	for (i = 0; i < count; i++) {
		ncfg_op_t op;
		ncfg_op_t inverse;

		mtu_op(&op, 1400);
		mtu_op(&inverse, inverses[i]);
		(void)ncfg_plan_add(plan, &op, &reason, NULL, 0, inverses[i] ? &inverse : NULL);
	}
	return plan;
}

/* Journal the plan with the outcome each action is to be given. */
static void journal_of(ncfg_journal_t *journal, const ncfg_plan_t *plan, const int *outcomes)
{
	size_t i;

	ncfg_journal_init(journal);
	for (i = 0; i < plan->action_count; i++) {
		ncfg_record_t record;

		memset(&record, 0, sizeof(record));
		record.id = plan->actions[i].id;
		record.op = ncfg_op_name(&plan->actions[i].op);
		record.interface = ncfg_op_interface(&plan->actions[i].op);
		record.reason = plan->actions[i].reason;
		record.outcome = outcomes[i];
		ncfg_journal_push(journal, &record);
	}
}

/*
 * Only what reached the kernel, and only what declared an inverse.
 *
 * The three rejections are the point rather than the acceptance. An action that
 * failed or never ran has nothing to undo, and replaying its inverse would be
 * netcfgd taking back a change it never made -- on a machine that is already in
 * the state a revert exists to rescue.
 */
static void only_done_actions_with_an_inverse_are_undone(void)
{
	static const int64_t inverses[] = { 1500, 1200, 1100, 0 };
	static const int     outcomes[] = { NCFG_OUTCOME_DONE, NCFG_OUTCOME_FAILED,
		NCFG_OUTCOME_SKIPPED, NCFG_OUTCOME_DONE };
	ncfg_plan_t    *plan = mtu_plan(inverses, 4u);
	ncfg_executor_t executor;
	recorder_t      recorder;
	ncfg_journal_t  journal;

	recorder_init(&recorder, &executor);
	if (plan) {
		journal_of(&journal, plan, outcomes);
		check(ncfg_apply_revert(plan, &journal, &executor) == 1u,
		    "exactly one action is undone: 1 failed, 2 never ran, 3 declares no inverse");
		sequence_is(&recorder, "link.set_mtu e0 1500", "and it is the one that ran");
		check(ncfg_journal_reverted(&journal) == 1u &&
		    journal.records[0].outcome == NCFG_OUTCOME_REVERTED,
		    "the journal records which action was put back");
		ncfg_journal_free(&journal);
	} else {
		check(0, "exactly one action is undone: 1 failed, 2 never ran, 3 declares no inverse");
		check(0, "and it is the one that ran");
		check(0, "the journal records which action was put back");
	}
	ncfg_plan_free(plan);
}

/*
 * The inverses run newest first.
 *
 * Asserted separately from the filtering above, because a revert that happened
 * to undo in plan order would pass every check on *which* records are eligible
 * and still be wrong: an address added after a link was brought up has to come
 * off before the link goes down, or the removal is aimed at something that is
 * no longer there.
 */
static void the_inverses_run_newest_first(void)
{
	static const int64_t inverses[] = { 1500, 1400, 1300 };
	static const int     outcomes[] = { NCFG_OUTCOME_DONE, NCFG_OUTCOME_DONE,
		NCFG_OUTCOME_DONE };
	ncfg_plan_t    *plan = mtu_plan(inverses, 3u);
	ncfg_executor_t executor;
	recorder_t      recorder;
	ncfg_journal_t  journal;

	recorder_init(&recorder, &executor);
	if (plan) {
		journal_of(&journal, plan, outcomes);
		check(ncfg_apply_revert(plan, &journal, &executor) == 3u, "all three are undone");
		sequence_is(&recorder,
		    "link.set_mtu e0 1300,link.set_mtu e0 1400,link.set_mtu e0 1500",
		    "and the inverses run in the reverse of the order they were applied");
		ncfg_journal_free(&journal);
	} else {
		check(0, "all three are undone");
		check(0, "and the inverses run in the reverse of the order they were applied");
	}
	ncfg_plan_free(plan);
}

/*
 * An inverse that fails does not stop the revert.
 *
 * The remaining ones are for other actions and are still worth running.
 * Stopping here would leave a machine that is neither the new configuration nor
 * the old one, which is the one outcome a revert exists to prevent -- and the
 * record of what did not come back is the journal entry that stays `done`.
 */
static void an_inverse_that_fails_does_not_stop_the_revert(void)
{
	static const int64_t inverses[] = { 1500, 1400, 1300 };
	static const int     outcomes[] = { NCFG_OUTCOME_DONE, NCFG_OUTCOME_DONE,
		NCFG_OUTCOME_DONE };
	ncfg_plan_t    *plan = mtu_plan(inverses, 3u);
	ncfg_executor_t executor;
	recorder_t      recorder;
	ncfg_journal_t  journal;

	recorder_init(&recorder, &executor);
	/* The first inverse asked for -- action 2's, since this runs backwards. */
	recorder.fail_at = 0;
	recorder.failure = "No such device";
	if (plan) {
		journal_of(&journal, plan, outcomes);
		check(ncfg_apply_revert(plan, &journal, &executor) == 2u,
		    "the two inverses after a failed one still run");
		sequence_is(&recorder,
		    "link.set_mtu e0 1300,link.set_mtu e0 1400,link.set_mtu e0 1500",
		    "and every inverse was attempted");
		check(ncfg_journal_done(&journal) == 1u &&
		    journal.records[2].outcome == NCFG_OUTCOME_DONE,
		    "the one that could not be put back still reads as done, which it is");
		ncfg_journal_free(&journal);
	} else {
		check(0, "the two inverses after a failed one still run");
		check(0, "and every inverse was attempted");
		check(0, "the one that could not be put back still reads as done, which it is");
	}
	ncfg_plan_free(plan);
}

/*
 * A hook is not undone, and a second revert undoes nothing twice.
 *
 * netcfgd cannot know what a script did, so `hook.run` declares no inverse and
 * the plan carries a warning saying commit-confirm will not revert it. That
 * warning was true before the revert existed and stays true.
 */
static void a_hook_is_not_undone_and_a_revert_is_not_repeated(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_executor_t  executor;
	recorder_t       recorder;
	ncfg_journal_t   journal;
	char             message[NCFG_ERROR_MAX];
	ncfg_plan_t     *plan = plan_of(
	    "\"devices\":[{\"name\":\"eth0\",\"kind\":{\"kind\":\"physical\"}}],"
	    "\"interfaces\":[{\"name\":\"eth0\","
	    "\"addressing\":[{\"source\":\"static\",\"address\":\"10.0.0.1/24\"}],"
	    "\"hooks\":[{\"phase\":\"pre_up\",\"path\":\"/run/pre\",\"sha256\":\"00\"}]}]",
	    "\"links\":[" LINK("eth0") "]", NULL, &document, &observed);

	recorder_init(&recorder, &executor);
	ncfg_journal_init(&journal);
	message[0] = '\0';
	if (plan && ncfg_apply(plan, &executor, &journal, message, sizeof(message))) {
		size_t undone;

		recorder_init(&recorder, &executor);
		undone = ncfg_apply_revert(plan, &journal, &executor);
		check(undone == 2u, "the link and the address are put back");
		sequence_is(&recorder, "addr.del eth0 10.0.0.1/24,link.down eth0",
		    "and the hook is not, because nothing knows what it did");
		recorder_init(&recorder, &executor);
		check(ncfg_apply_revert(plan, &journal, &executor) == 0u && recorder.count == 0u,
		    "a second revert finds nothing left to put back");
	} else {
		check(0, "the link and the address are put back");
		check(0, "and the hook is not, because nothing knows what it did");
		check(0, "a second revert finds nothing left to put back");
	}
	ncfg_journal_free(&journal);
	release(plan, document, observed);
}

/* ------------------------------------------------------------------------ *
 * What this build executes, and what it refuses
 * ------------------------------------------------------------------------ */

/*
 * Nothing is silently ignored.
 *
 * Every op in the taxonomy is either something this build carries out or
 * something it refuses **with a sentence naming it**. The direction that must
 * not happen is the third one: an op that reaches the executor, matches
 * nothing, and is reported as done. That is a converged machine nobody touched.
 */
static void every_op_is_either_executed_or_refused_by_name(void)
{
	/*
	 * **The list names what is refused, and it used to name what was carried
	 * out.** It was inverted when the two executor halves landed and the
	 * fifteen became forty-five: a list of what works grows with every wave
	 * and has to be edited by whoever adds an op, which is the edit most
	 * easily forgotten. A list of what does not works the other way -- it
	 * shrinks, and the day it empties this check becomes "everything is
	 * carried out", which is the end state the port is for.
	 *
	 * Only the reload is refused for a zero-initialised op now. Kind 0 is the
	 * DHCP client, which `src/backend/dhcp/` carries -- so its start and its
	 * stop have left this list, and what is left is the one a DHCP client
	 * genuinely does not have: a reload is the client's own business, and
	 * inventing one that stopped and started would hide that difference
	 * behind a word. `link.create` answers differently depending on what is
	 * being created and is checked on its own below.
	 */
	static const ncfg_op_kind_t refused[] = { NCFG_OP_BACKEND_RELOAD };
	int    every_refusal_names_its_op = 1;
	int    every_op_answered = 1;
	size_t kind;

	/* `NCFG_OP_COMMIT_REVERT` is the last of the forty-eight. */
	for (kind = 0; kind <= (size_t)NCFG_OP_COMMIT_REVERT; kind++) {
		ncfg_op_t   op;
		char        message[NCFG_ERROR_MAX];
		const char *name;
		int         wanted = 1;
		int         answered;
		size_t      i;

		memset(&op, 0, sizeof(op));
		op.kind = (int)kind;
		name = ncfg_op_name(&op);
		for (i = 0; i < sizeof(refused) / sizeof(refused[0]); i++) {
			if ((size_t)refused[i] == kind) {
				wanted = 0;
			}
		}
		/* `link.create` is the one whose answer depends on what is being
		 * created, so it is checked on its own below. */
		if (kind == (size_t)NCFG_OP_LINK_CREATE) {
			continue;
		}
		message[0] = '\0';
		answered = ncfg_apply_supported(&op, message, sizeof(message));
		if (answered != wanted) {
			printf("  %s: expected %s, got %s\n", name, wanted ? "executed" : "refused",
			    answered ? "executed" : "refused");
			every_op_answered = 0;
		}
		if (!answered && (message[0] == '\0' || !strstr(message, name))) {
			printf("  %s is refused with `%s`, which does not name it\n", name, message);
			every_refusal_names_its_op = 0;
		}
	}
	check(every_op_answered, "every op is answered, and the answers are the expected ones");
	check(every_refusal_names_its_op, "and every refusal names the op it is about");
}

/*
 * Which kinds this build can bring into being, one row per kind.
 *
 * **The four that used to be refused for wanting a number are made now.** A
 * VLAN's ethertype, a bond's mode, a macvlan's mode and a tunnel's kind word
 * are the model's numbering, and `ops.h`'s rule was never that they cannot be
 * sent -- it is that `src/apply/` may not keep a second copy. `document.h`
 * publishes all four, so `ncfg_kernel_newlink_of` reads them and the refusals
 * are gone with the rule intact.
 *
 * **What this table is for is that a kind cannot change sides unasked.** It
 * has caught that once already, on the row below that says so.
 */
static void a_link_whose_kind_needs_the_models_numbering_is_refused(void)
{
	static const struct {
		int         kind;
		int         creatable;
		const char *what;
	} kinds[] = {
		{ NCFG_KIND_BRIDGE, 1, "a bridge" },
		{ NCFG_KIND_DUMMY, 1, "a dummy" },
		{ NCFG_KIND_VETH, 1, "a veth" },
		{ NCFG_KIND_VRF, 1, "a vrf" },
		{ NCFG_KIND_VXLAN, 1, "a vxlan" },
		{ NCFG_KIND_IFB, 1, "an ifb" },
		{ NCFG_KIND_WIREGUARD, 1, "a wireguard link" },
		/*
		 * **The one kind that is not a netlink message, and the one row this
		 * table did not have.** A tun is made through `/dev/net/tun`, so for
		 * one wave this list answered no while `tun.h` carried the call that
		 * makes one and nothing invoked it. Nothing here noticed either way,
		 * which is the half worth fixing: the table's whole job is that a
		 * kind cannot change sides unasked.
		 */
		{ NCFG_KIND_TUN, 1, "a tun" },
		/*
		 * **The four the model's numbering used to hold back.** Each is a
		 * netlink message like any other now; what made them wait was that
		 * `document.h` published no conversion, and it publishes all four.
		 * A bond is the one whose two routes differ -- creation always
		 * carries its mode, a bond being made having no members yet, while
		 * `link.set_bond` carries one only when the planner says it may.
		 */
		{ NCFG_KIND_VLAN, 1, "a vlan" },
		{ NCFG_KIND_BOND, 1, "a bond" },
		{ NCFG_KIND_MACVLAN, 1, "a macvlan" },
		{ NCFG_KIND_TUNNEL, 1, "a tunnel" },
		{ NCFG_KIND_PHYSICAL, 0, "a physical device" },
		{ NCFG_KIND_PPPOE, 0, "a pppoe session" },
		{ NCFG_KIND_OPENVPN, 0, "an openvpn tunnel" }
	};
	int    every_kind_answered = 1;
	int    every_refusal_explains = 1;
	size_t i;

	for (i = 0; i < sizeof(kinds) / sizeof(kinds[0]); i++) {
		ncfg_interface_kind_t kind;
		ncfg_op_t             op;
		char                  message[NCFG_ERROR_MAX];
		int                   answered;

		memset(&kind, 0, sizeof(kind));
		kind.kind = kinds[i].kind;
		kind.veth.peer = LIT("peer0");
		memset(&op, 0, sizeof(op));
		op.kind = NCFG_OP_LINK_CREATE;
		op.u.link_create.name = "x0";
		op.u.link_create.kind = &kind;
		message[0] = '\0';
		answered = ncfg_apply_supported(&op, message, sizeof(message));
		if (answered != kinds[i].creatable) {
			printf("  %s: expected %s, got %s (%s)\n", kinds[i].what,
			    kinds[i].creatable ? "creatable" : "refused",
			    answered ? "creatable" : "refused", message);
			every_kind_answered = 0;
		}
		if (!answered && !strstr(message, "x0")) {
			printf("  %s is refused without naming the link: %s\n", kinds[i].what,
			    message);
			every_refusal_explains = 0;
		}
	}
	check(every_kind_answered, "the kinds that need no numbering are made, the rest refused");
	check(every_refusal_explains, "and a refused creation names the link it was for");

	{
		/* A creation carrying no kind at all is a refusal rather than a
		 * segmentation fault: this is reached from a plan, and a plan is data
		 * that arrives over a socket. */
		ncfg_op_t op;
		char      message[NCFG_ERROR_MAX];

		memset(&op, 0, sizeof(op));
		op.kind = NCFG_OP_LINK_CREATE;
		op.u.link_create.name = "x0";
		message[0] = '\0';
		check(!ncfg_apply_supported(&op, message, sizeof(message)) && message[0] != '\0',
		    "and a creation with no kind at all is refused with a sentence");
	}
}

/*
 * A refused op fails its action rather than being passed over.
 *
 * Driven through the double, which stands in for the kernel executor's own
 * first question -- the point being that a plan carrying something this build
 * cannot do stops, and the journal says which op and why.
 */
static void an_op_this_build_cannot_do_fails_its_action(void)
{
	ncfg_executor_t      executor;
	recorder_t           recorder;
	ncfg_journal_t       journal;
	const ncfg_record_t *failure;
	char                 message[NCFG_ERROR_MAX];
	ncfg_plan_t         *plan = ncfg_plan_new(message, sizeof(message));

	recorder_init(&recorder, &executor);
	ncfg_journal_init(&journal);
	if (plan) {
		ncfg_op_t     op;
		ncfg_reason_t reason;

		/*
		 * **`wg.set_peers` stood here, then the DHCP client, then the
		 * supplicant's launcher, then a PPPoE session -- and all four are
		 * carried out now.** The comment above this check said that when the
		 * last of them landed it would have nowhere left to move to, and that
		 * the port would then be finished; this is that, and the check stays
		 * rather than being deleted, with its subject changed to the refusal
		 * that is *not* a missing port.
		 *
		 * A plain `backend.start` for DHCPv6 is refused in both
		 * implementations and for the same reason: which v6 client can serve a
		 * document turns on whether it asked for a delegated prefix -- only
		 * odhcp6c reports one -- and the op carries neither the request nor
		 * the client (0050). So what this asserts is unchanged and its subject
		 * is permanent: a refusal says *what* is missing rather than only that
		 * something is.
		 */
		memset(&reason, 0, sizeof(reason));
		reason.interface = "eth0";
		reason.field = "backend.dhcp6";
		reason.desired = "running";
		reason.observed = "<absent>";
		memset(&op, 0, sizeof(op));
		op.kind = NCFG_OP_BACKEND_START;
		op.u.backend.kind = (int)NCFG_BACKEND_DHCP6;
		op.u.backend.iface = "eth0";
		(void)ncfg_plan_add(plan, &op, &reason, NULL, 0, NULL);

		/* The double refuses exactly what `ncfg_apply_supported` refuses,
		 * which is what the kernel executor asks before it does anything. */
		recorder.fail_at = 0;
		recorder.failure = NULL;
		message[0] = '\0';
		(void)ncfg_apply(plan, &executor, &journal, message, sizeof(message));
		failure = ncfg_journal_failure(&journal);
		check(failure && failure->op && strcmp(failure->op, "backend.start") == 0,
		    "an op this build cannot carry out fails its action rather than passing");
		message[0] = '\0';
		check(!ncfg_apply_supported(&op, message, sizeof(message)) &&
		    strstr(message, "backend.start") && strstr(message, "delegated prefix"),
		    "and the refusal says what is missing, not just that it is missing");
	} else {
		check(0, "an op this build cannot carry out fails its action rather than passing");
		check(0, "and the refusal says what is missing, not just that it is missing");
	}
	ncfg_journal_free(&journal);
	ncfg_plan_free(plan);
}

/* ------------------------------------------------------------------------ *
 * The journal as a file
 * ------------------------------------------------------------------------ */

/*
 * What `/run/netcfgd/plan.last.json` holds, byte for byte.
 *
 * Written out in full rather than parsed and inspected: this file is read by
 * `ncfg status`, by the TUI and by whatever an operator pipes into `jq`, so a
 * member renamed or an absent one written as `null` where the Rust omits it is
 * a change to an interface rather than to an implementation detail.
 */
static void the_journal_is_written_as_the_file_carries_it(void)
{
	static const char *const wanted =
	    "{\"records\":["
	    "{\"id\":0,\"op\":\"link.up\",\"interface\":\"eth0\","
	    "\"reason\":{\"interface\":\"eth0\",\"field\":\"enabled\",\"desired\":\"true\","
	    "\"observed\":\"false\"},\"outcome\":\"done\"},"
	    "{\"id\":1,\"op\":\"addr.add\",\"interface\":\"eth0\","
	    "\"reason\":{\"field\":\"addressing[0]\",\"desired\":\"10.0.0.1/24\","
	    "\"observed\":\"<absent>\"},\"outcome\":\"failed\","
	    "\"error\":\"Cannot assign requested address\"},"
	    "{\"id\":2,\"op\":\"commit.arm\","
	    "\"reason\":{\"field\":\"confirm\",\"desired\":\"90\",\"observed\":\"<absent>\"},"
	    "\"outcome\":\"skipped\"}"
	    "]}";
	ncfg_journal_t journal;
	ncfg_record_t  record;
	ncfg_buf_t     buf;
	char           message[NCFG_ERROR_MAX];
	char          *text;
	size_t         length = 0;

	ncfg_journal_init(&journal);
	memset(&record, 0, sizeof(record));
	record.id = 0;
	record.op = "link.up";
	record.interface = "eth0";
	record.reason.interface = "eth0";
	record.reason.field = "enabled";
	record.reason.desired = "true";
	record.reason.observed = "false";
	record.outcome = NCFG_OUTCOME_DONE;
	ncfg_journal_push(&journal, &record);

	memset(&record, 0, sizeof(record));
	record.id = 1;
	record.op = "addr.add";
	record.interface = "eth0";
	/* No `reason.interface`, which is the member the Rust omits when absent --
	 * checked here because the record's own `interface` is present, so a writer
	 * that confused the two would still produce plausible JSON. */
	record.reason.field = "addressing[0]";
	record.reason.desired = "10.0.0.1/24";
	record.reason.observed = "<absent>";
	record.outcome = NCFG_OUTCOME_FAILED;
	record.error = "Cannot assign requested address";
	ncfg_journal_push(&journal, &record);

	memset(&record, 0, sizeof(record));
	record.id = 2;
	record.op = "commit.arm";
	/* An op that names no interface omits the member rather than writing
	 * `null`, exactly as the Rust's `skip_serializing_if` does. */
	record.reason.field = "confirm";
	record.reason.desired = "90";
	record.reason.observed = "<absent>";
	record.outcome = NCFG_OUTCOME_SKIPPED;
	ncfg_journal_push(&journal, &record);

	ncfg_buf_init(&buf, 0);
	message[0] = '\0';
	if (ncfg_journal_write(&journal, &buf, message, sizeof(message))) {
		text = ncfg_buf_take(&buf, &length);
		if (text && strcmp(text, wanted) != 0) {
			printf("  wanted: %s\n", wanted);
			printf("  got:    %s\n", text);
		}
		check(text && strcmp(text, wanted) == 0, "the journal is written as the file holds it");
		free(text);
	} else {
		printf("  could not write the journal: %s\n", message);
		check(0, "the journal is written as the file holds it");
	}
	ncfg_buf_free(&buf);
	ncfg_journal_free(&journal);

	check(ncfg_outcome_name(NCFG_OUTCOME_REVERTED) &&
	    strcmp(ncfg_outcome_name(NCFG_OUTCOME_REVERTED), "reverted") == 0 &&
	    ncfg_outcome_name(99) == NULL,
	    "an outcome outside the set has no word, rather than a plausible one");
}

/* ------------------------------------------------------------------------ *
 * Hooks
 * ------------------------------------------------------------------------ */

/*
 * A failure means different things in different phases.
 *
 * Section 5.2: a non-zero exit from a `pre_*` hook aborts the transition, and
 * `post_*` and event hook failures are logged and roll nothing back. Treating a
 * `post_up` failure as fatal would stop a plan after the interface is already
 * configured, leaving the rest of the machine unconfigured because a logging
 * script exited 1.
 */
static void a_failure_vetoes_only_in_the_phases_that_can_veto(void)
{
	static const struct {
		ncfg_hook_phase_t phase;
		int               vetoes;
	} phases[] = {
		{ NCFG_HOOK_PHASE_PRE_UP, 1 },
		{ NCFG_HOOK_PHASE_UP, 1 },
		{ NCFG_HOOK_PHASE_POST_UP, 0 },
		{ NCFG_HOOK_PHASE_PRE_DOWN, 1 },
		{ NCFG_HOOK_PHASE_DOWN, 1 },
		{ NCFG_HOOK_PHASE_POST_DOWN, 0 },
		{ NCFG_HOOK_PHASE_CARRIER, 0 },
		{ NCFG_HOOK_PHASE_LEASE, 0 },
		{ NCFG_HOOK_PHASE_ROAM, 0 },
		{ NCFG_HOOK_PHASE_PORTAL, 0 },
		{ NCFG_HOOK_PHASE_DRIFT, 0 }
	};
	int    correct = 1;
	size_t i;

	for (i = 0; i < sizeof(phases) / sizeof(phases[0]); i++) {
		if (ncfg_hook_is_veto_phase((int)phases[i].phase) != phases[i].vetoes) {
			printf("  %s answers the wrong way\n",
			    ncfg_hook_phase_name(phases[i].phase));
			correct = 0;
		}
	}
	check(correct, "a failure vetoes in the four phases inside a transition and no others");
}

/* Write a hook script and fill in the reference that names it. */
static int write_hook(const char *dir, const char *body, ncfg_hook_ref_t *out, char *path,
    size_t path_size)
{
	char    script[1024];
	FILE   *file;
	size_t  length;

	(void)snprintf(path, path_size, "%s/hook.sh", dir);
	length = (size_t)snprintf(script, sizeof(script), "#!/bin/sh\n%s\n", body);
	file = fopen(path, "wb");
	if (!file) {
		return 0;
	}
	if (fwrite(script, 1u, length, file) != length) {
		fclose(file);
		return 0;
	}
	fclose(file);
	if (chmod(path, S_IRWXU) != 0) {
		return 0;
	}
	memset(out, 0, sizeof(*out));
	out->path = path;
	out->sha256 = malloc(NCFG_SHA256_HEX_SIZE);
	if (!out->sha256) {
		return 0;
	}
	ncfg_sha256_hex(script, length, out->sha256);
	return 1;
}

/*
 * A hook that has changed since the configuration was compiled does not run.
 *
 * Section 2.2's content hash, made a control rather than a report: a hook file
 * swapped after the configuration was compiled does not get to run as root on
 * the strength of the old approval. Nothing is forked on this path -- the
 * refusal happens before the spawn, which is the whole point.
 */
static void a_changed_hook_does_not_run(const char *dir)
{
	ncfg_hook_ref_t hook;
	ncfg_hook_env_t env;
	char            path[320];
	char            message[NCFG_ERROR_MAX];
	char            marker[320];

	(void)snprintf(marker, sizeof(marker), "%s/ran", dir);
	if (!write_hook(dir, "exit 0", &hook, path, sizeof(path))) {
		check(0, "a hook whose content has changed is not run");
		check(0, "and a hook this build has no hash for is not run either");
		return;
	}
	hook.phase = NCFG_HOOK_PHASE_PRE_UP;
	/* The file on disk is not what the document was compiled against. */
	hook.sha256[0] = hook.sha256[0] == 'a' ? 'b' : 'a';
	memset(&env, 0, sizeof(env));
	env.iface = "eth0";
	message[0] = '\0';
	check(ncfg_hook_run(&hook, &env, message, sizeof(message)) == NCFG_HOOK_VETOED &&
	    strstr(message, "has changed") && access(marker, F_OK) != 0,
	    "a hook whose content has changed is not run");

	hook.sha256[0] = '\0';
	message[0] = '\0';
	check(ncfg_hook_run(&hook, &env, message, sizeof(message)) == NCFG_HOOK_VETOED &&
	    strstr(message, "no content hash"),
	    "and a hook this build has no hash for is not run either");
	free(hook.sha256);
}

/*
 * A hook naming a user does not run at all.
 *
 * The direction matters more than the assertion, and it is the Rust's own
 * sentence: the wrong answer here is not "an error" but "runs anyway, as
 * root". A hook that asked to be unprivileged and was handed the daemon's
 * privileges instead is worse than one that did not run, because nothing
 * reports it. This port cannot resolve a user name at all -- `process.h` keeps
 * NSS out of the privileged process -- so it takes the closed direction for
 * every name rather than the privileged one for any.
 */
static void a_hook_asking_to_drop_privilege_does_not_run_as_root_instead(const char *dir)
{
	ncfg_hook_ref_t hook;
	ncfg_hook_env_t env;
	char            path[320];
	char            message[NCFG_ERROR_MAX];
	char            marker[320];
	char            body[512];

	(void)snprintf(marker, sizeof(marker), "%s/dropped", dir);
	(void)snprintf(body, sizeof(body), "touch %s", marker);
	if (!write_hook(dir, body, &hook, path, sizeof(path))) {
		check(0, "a hook that asked to be unprivileged does not run privileged instead");
		return;
	}
	hook.phase = NCFG_HOOK_PHASE_PRE_UP;
	hook.run_as = LIT("root");
	memset(&env, 0, sizeof(env));
	env.iface = "eth0";
	message[0] = '\0';
	check(ncfg_hook_run(&hook, &env, message, sizeof(message)) == NCFG_HOOK_VETOED &&
	    strstr(message, "run as") && access(marker, F_OK) != 0,
	    "a hook that asked to be unprivileged does not run privileged instead");
	free(hook.sha256);
	(void)remove(marker);
}

/*
 * A hook that finishes inside its bound succeeds, and is told what it needs.
 *
 * The control for the timeout below: without it, a bound that killed
 * everything would look exactly like a bound that worked. It also checks the
 * environment, because section 5.2 fixes those names as a contract -- a hook
 * written against them keeps working, and one that stopped being told its
 * interface would fail in a way no test of the outcome could see.
 */
static void a_prompt_hook_succeeds_and_is_told_its_phase(const char *dir)
{
	ncfg_hook_ref_t hook;
	ncfg_hook_env_t env;
	char            path[320];
	char            message[NCFG_ERROR_MAX];
	char            marker[320];
	char            body[512];
	FILE           *file;
	char            said[256];

	(void)snprintf(marker, sizeof(marker), "%s/said", dir);
	(void)snprintf(body, sizeof(body),
	    "printf '%%s %%s %%s' \"$NCFG_IFACE\" \"$NCFG_PHASE\" \"$NCFG_ADDR\" > %s", marker);
	if (!write_hook(dir, body, &hook, path, sizeof(path))) {
		check(0, "a hook that finishes inside its bound succeeds");
		check(0, "and is told its interface, its phase and the address in play");
		return;
	}
	hook.phase = NCFG_HOOK_PHASE_LEASE;
	hook.timeout.has = 1;
	hook.timeout.value = 30;
	memset(&env, 0, sizeof(env));
	env.iface = "eth0";
	env.addr = "10.0.0.5/24";
	message[0] = '\0';
	check(ncfg_hook_run(&hook, &env, message, sizeof(message)) == NCFG_HOOK_OK,
	    "a hook that finishes inside its bound succeeds");

	said[0] = '\0';
	file = fopen(marker, "rb");
	if (file) {
		size_t got = fread(said, 1u, sizeof(said) - 1u, file);

		said[got] = '\0';
		fclose(file);
	}
	if (strcmp(said, "eth0 lease 10.0.0.5/24") != 0) {
		printf("  the hook was told: `%s`\n", said);
	}
	check(strcmp(said, "eth0 lease 10.0.0.5/24") == 0,
	    "and is told its interface, its phase and the address in play");
	free(hook.sha256);
	(void)remove(marker);
}

/*
 * What the hook started dies with it.
 *
 * This is the defect the first version of the timeout had, found by looking for
 * orphans after a suite that reported success: a hook is a script, a background
 * `sleep` inside it is a *grandchild*, and killing the shell left the sleep
 * running and reparented to init. The daemon stopped waiting; the work it was
 * waiting for carried on.
 *
 * The child records its own child's pid and this asserts that pid is gone
 * afterwards -- read from `/proc`, because `kill -0` calls a zombie alive and a
 * reaped-by-init grandchild is exactly where that lies.
 *
 * **Five seconds rather than the Rust's three hundred.** The bound under test
 * is one second, so five is well outside it and reproduces the defect exactly;
 * what it also does is make a regression in the group kill leave something that
 * goes away on its own rather than a process this suite orphaned for five
 * minutes on somebody's workstation.
 */
static void a_hooks_own_children_are_killed_with_it(const char *dir)
{
	ncfg_hook_ref_t hook;
	ncfg_hook_env_t env;
	char            path[320];
	char            message[NCFG_ERROR_MAX];
	char            pidfile[320];
	char            body[512];
	char            proc[64];
	FILE           *file;
	long            pid = 0;
	int             alive = 1;
	int             look;

	(void)snprintf(pidfile, sizeof(pidfile), "%s/child.pid", dir);
	(void)snprintf(body, sizeof(body), "sleep 5 &\necho $! > %s\nwait", pidfile);
	if (!write_hook(dir, body, &hook, path, sizeof(path))) {
		check(0, "a hook that outstays its bound is killed, and the phase decides");
		check(0, "and what the hook started dies with it");
		return;
	}
	/* `post_up`, so the outcome is `Noted`: the same bound in a veto phase is
	 * the same mechanism, and the phase split is checked on its own above. */
	hook.phase = NCFG_HOOK_PHASE_POST_UP;
	hook.timeout.has = 1;
	hook.timeout.value = 1;
	memset(&env, 0, sizeof(env));
	env.iface = "eth0";
	message[0] = '\0';
	check(ncfg_hook_run(&hook, &env, message, sizeof(message)) == NCFG_HOOK_NOTED &&
	    strstr(message, "did not finish within 1s"),
	    "a hook that outstays its bound is killed, and the phase decides");

	file = fopen(pidfile, "rb");
	if (file) {
		if (fscanf(file, "%ld", &pid) != 1) {
			pid = 0;
		}
		fclose(file);
	}
	/* The group signal is delivered before `ncfg_hook_run` returns, but the
	 * kernel reaping is not instantaneous. Poll briefly rather than assert
	 * once, and bound the polling. */
	(void)snprintf(proc, sizeof(proc), "/proc/%ld/cmdline", pid);
	for (look = 0; pid > 0 && look < 200; look++) {
		struct timespec tick;
		FILE           *entry = fopen(proc, "rb");
		char            line[64];
		size_t          got = 0;

		if (entry) {
			got = fread(line, 1u, sizeof(line), entry);
			fclose(entry);
		}
		if (!entry || got == 0) {
			alive = 0;
			break;
		}
		tick.tv_sec = 0;
		tick.tv_nsec = 10L * 1000000L;
		(void)nanosleep(&tick, NULL);
	}
	if (alive) {
		printf("  the hook's child %ld outlived the hook\n", pid);
	}
	check(pid > 0 && !alive, "and what the hook started dies with it");
	free(hook.sha256);
	(void)remove(pidfile);
}

/* The four checks above share one directory, made and removed by name. */
static void the_hook_runner(void)
{
	char dir[256];
	char script[320];

	if (!tempdir_make("apply-hook", dir, sizeof(dir))) {
		check(0, "a directory for the hook checks");
		return;
	}
	a_changed_hook_does_not_run(dir);
	a_hook_asking_to_drop_privilege_does_not_run_as_root_instead(dir);
	a_prompt_hook_succeeds_and_is_told_its_phase(dir);
	a_hooks_own_children_are_killed_with_it(dir);
	/* By name, never by pattern: this directory holds one file this test wrote
	 * and nothing else it is entitled to remove. */
	(void)snprintf(script, sizeof(script), "%s/hook.sh", dir);
	(void)remove(script);
	(void)rmdir(dir);
}

/* ------------------------------------------------------------------------ *
 * The seam itself
 * ------------------------------------------------------------------------ */

/* Every entry point survives being handed nothing, because a library that
 * segmentation faults on a NULL is a daemon that dies holding CAP_NET_ADMIN. */
static void nothing_here_falls_over_on_an_empty_argument(void)
{
	ncfg_journal_t  journal;
	ncfg_executor_t executor;
	recorder_t      recorder;
	ncfg_buf_t      buf;
	char            message[NCFG_ERROR_MAX];

	recorder_init(&recorder, &executor);
	ncfg_journal_init(&journal);
	ncfg_journal_free(&journal);
	ncfg_journal_free(&journal);
	ncfg_journal_init(&journal);
	ncfg_journal_push(&journal, NULL);
	ncfg_buf_init(&buf, 0);
	message[0] = '\0';
	check(!ncfg_apply(NULL, &executor, &journal, message, sizeof(message)) &&
	    !ncfg_apply_supported(NULL, message, sizeof(message)) &&
	    ncfg_apply_revert(NULL, &journal, &executor) == 0u &&
	    !ncfg_journal_write(NULL, &buf, message, sizeof(message)) &&
	    ncfg_journal_succeeded(&journal) && ncfg_journal_done(&journal) == 0u,
	    "every entry point answers rather than falling over on nothing");
	ncfg_buf_free(&buf);
	ncfg_journal_free(&journal);
	ncfg_kernel_free(NULL);
}


/* ------------------------------------------------------------------------ *
 * What an apply did, folded into the ownership record
 * ------------------------------------------------------------------------ */

/*
 * WHY THIS IS THE SECTION THE DAEMON'S GUARD TURNED ON
 *   `owned.json` is not a log. Every entry in it is netcfgd's answer to "may I
 *   take this away?", and that answer is what `ncfg_ownership_may_remove`
 *   gates every teardown on. Until this landed the answer was no, for ever,
 *   about every object an apply installed -- and about a link the kernel mark
 *   could not rescue either.
 *
 *   None of it needs a kernel: the fold is a function of the plan and the
 *   journal, so the recorder produces the journal and a directory this test
 *   made holds the file.
 */

/* One op, built on the stack, with no inverse. */
static void put(ncfg_plan_t *plan, const ncfg_op_t *op)
{
	ncfg_reason_t reason;

	memset(&reason, 0, sizeof(reason));
	reason.field = "fixture";
	(void)ncfg_plan_add(plan, op, &reason, NULL, 0, NULL);
}

static void addr_op(ncfg_op_t *op, int kind, const char *iface, const char *addr)
{
	memset(op, 0, sizeof(*op));
	op->kind = kind;
	if (kind == NCFG_OP_ADDR_ADD) {
		op->u.addr_add.iface = iface;
		op->u.addr_add.addr = addr;
	} else {
		op->u.addr_del.iface = iface;
		op->u.addr_del.addr = addr;
	}
}

/* The record as it is on disk, read back through the module that writes it. */
static int read_back(const char *run_dir, ncfg_owned_state_t *out)
{
	char message[NCFG_ERROR_MAX];

	message[0] = '\0';
	memset(out, 0, sizeof(*out));
	return ncfg_owned_read(run_dir, out, message, sizeof(message));
}

static int has_string(char *const *list, size_t count, const char *wanted)
{
	size_t at;

	for (at = 0; at < count; at++) {
		if (list[at] && strcmp(list[at], wanted) == 0) {
			return 1;
		}
	}
	return 0;
}

static const ncfg_owned_object_t *object_named(const ncfg_owned_object_t *list, size_t count,
    const char *interface, const char *key)
{
	size_t at;

	for (at = 0; at < count; at++) {
		if (list[at].interface && list[at].key &&
		    strcmp(list[at].interface, interface) == 0 && strcmp(list[at].key, key) == 0) {
			return &list[at];
		}
	}
	return NULL;
}

/*
 * Only what reached the machine is claimed.
 *
 * The three outcomes are the subject rather than the one: an action that failed
 * or never ran changed nothing, and a record claiming it would have netcfgd
 * withdraw an address it never installed. So the recorder is told to fail in
 * the middle of a plan of four, and the file afterwards holds exactly the two
 * that ran.
 */
static void only_what_ran_is_claimed(char *run_dir)
{
	ncfg_plan_t       *plan;
	ncfg_executor_t    executor;
	recorder_t         recorder;
	ncfg_journal_t     journal;
	ncfg_owned_state_t owned;
	ncfg_op_t          op;
	ncfg_route_t       route;
	char               message[NCFG_ERROR_MAX];

	message[0] = '\0';
	plan = ncfg_plan_new(message, sizeof(message));
	if (!plan) {
		check(0, "only the actions that ran are claimed in owned.json");
		return;
	}
	memset(&op, 0, sizeof(op));
	op.kind = NCFG_OP_LINK_CREATE;
	op.u.link_create.name = "br0";
	put(plan, &op);
	addr_op(&op, NCFG_OP_ADDR_ADD, "br0", "10.0.0.1/24");
	put(plan, &op);
	/* The third fails, so this and the fourth change nothing. */
	addr_op(&op, NCFG_OP_ADDR_ADD, "br0", "10.0.0.2/24");
	put(plan, &op);
	memset(&route, 0, sizeof(route));
	route.destination = LIT("default");
	route.via = LIT("10.0.0.254");
	memset(&op, 0, sizeof(op));
	op.kind = NCFG_OP_ROUTE_ADD;
	op.u.route.iface = "br0";
	op.u.route.route = &route;
	put(plan, &op);

	recorder_init(&recorder, &executor);
	recorder.fail_at = 2;
	recorder.failure = "the double was told to fail here";
	ncfg_journal_init(&journal);
	message[0] = '\0';
	(void)ncfg_apply(plan, &executor, &journal, message, sizeof(message));

	message[0] = '\0';
	check(ncfg_apply_record(run_dir, plan, &journal, NULL, 0u, message, sizeof(message)),
	    "what an apply did is folded into owned.json");
	if (read_back(run_dir, &owned)) {
		check(has_string(owned.created_links, owned.created_link_count, "br0"),
		    "  the link it created is netcfgd's, so netcfgd may take it down again");
		check(object_named(owned.addresses, owned.address_count, "br0",
		    "10.0.0.1/24") != NULL,
		    "  and the address that went on before the failure is claimed");
		check(object_named(owned.addresses, owned.address_count, "br0",
		    "10.0.0.2/24") == NULL,
		    "  the one whose action failed is not claimed");
		check(owned.route_count == 0u,
		    "  and neither is the route that never ran at all");
		{
			const ncfg_owned_object_t *one = object_named(owned.addresses,
			    owned.address_count, "br0", "10.0.0.1/24");

			check(one && one->origin == (int)NCFG_ORIGIN_STATIC,
			    "  an address netcfgd installs is `static`, which every teardown "
			    "gates on");
		}
		ncfg_owned_free(&owned);
	} else {
		check(0, "  the link it created is netcfgd's, so netcfgd may take it down again");
		check(0, "  and the address that went on before the failure is claimed");
		check(0, "  the one whose action failed is not claimed");
		check(0, "  and neither is the route that never ran at all");
		check(0, "  an address netcfgd installs is `static`, which every teardown "
		    "gates on");
	}
	ncfg_journal_free(&journal);
	ncfg_plan_free(plan);
}

/*
 * A revert takes the claims back.
 *
 * `ncfg_apply_revert` marks every record whose inverse ran, and the same fold
 * run again folds the **inverse** for those -- so an address a window installed
 * stops being netcfgd's the moment it is withdrawn. Without it the file would
 * go on claiming every object a window that closed unconfirmed has given back,
 * and netcfgd would believe it owns an address that is not there.
 *
 * Driven on the record written by the check above, which is what makes it a
 * removal rather than an empty file that happens to look right. And the second
 * fold re-folds the first check's records, which is the idempotence the
 * arrangement depends on: it is asserted rather than assumed, by checking that
 * what the revert did not touch is still there afterwards.
 */
static void a_revert_takes_the_claims_back(char *run_dir)
{
	ncfg_plan_t       *plan;
	ncfg_executor_t    executor;
	recorder_t         recorder;
	ncfg_journal_t     journal;
	ncfg_owned_state_t owned;
	ncfg_op_t          op;
	ncfg_op_t          inverse;
	ncfg_reason_t      reason;
	char               message[NCFG_ERROR_MAX];

	message[0] = '\0';
	plan = ncfg_plan_new(message, sizeof(message));
	if (!plan) {
		check(0, "a revert takes back what the apply claimed");
		return;
	}
	memset(&reason, 0, sizeof(reason));
	reason.field = "fixture";
	addr_op(&op, NCFG_OP_ADDR_ADD, "br0", "10.0.0.9/24");
	addr_op(&inverse, NCFG_OP_ADDR_DEL, "br0", "10.0.0.9/24");
	(void)ncfg_plan_add(plan, &op, &reason, NULL, 0, &inverse);

	recorder_init(&recorder, &executor);
	ncfg_journal_init(&journal);
	message[0] = '\0';
	(void)ncfg_apply(plan, &executor, &journal, message, sizeof(message));
	message[0] = '\0';
	(void)ncfg_apply_record(run_dir, plan, &journal, NULL, 0u, message, sizeof(message));
	if (read_back(run_dir, &owned)) {
		check(object_named(owned.addresses, owned.address_count, "br0",
		    "10.0.0.9/24") != NULL,
		    "an address a window installed is claimed while the window is open");
		ncfg_owned_free(&owned);
	} else {
		check(0, "an address a window installed is claimed while the window is open");
	}

	check(ncfg_apply_revert(plan, &journal, &executor) == 1u, "  the window closes unconfirmed");
	message[0] = '\0';
	(void)ncfg_apply_record(run_dir, plan, &journal, NULL, 0u, message, sizeof(message));
	if (read_back(run_dir, &owned)) {
		check(object_named(owned.addresses, owned.address_count, "br0",
		    "10.0.0.9/24") == NULL,
		    "  and the claim leaves with the address the revert withdrew");
		/* And nothing else moved: the earlier check's records are untouched,
		 * which is what a fold that only ever adds could not promise. */
		check(has_string(owned.created_links, owned.created_link_count, "br0"),
		    "  while what the revert did not touch is still netcfgd's");
		ncfg_owned_free(&owned);
	} else {
		check(0, "  and the claim leaves with the address the revert withdrew");
		check(0, "  while what the revert did not touch is still netcfgd's");
	}
	ncfg_journal_free(&journal);
	ncfg_plan_free(plan);
}

/*
 * The rules that are not "add a name to a list".
 *
 * Each of these is a rule the Rust wrote down once and this port had to spell
 * again, and each is the kind that is wrong in a direction nobody notices:
 *
 *   * switching a sysctl **off** drops the record rather than storing false --
 *     the question is "is this ours to undo", and once undone the answer is no;
 *   * `accept_ra`'s off is the value `1`, the kernel's own default (0073), not
 *     false -- so a write of 1 must drop the record and a write of 2 must keep
 *     it;
 *   * a deleted link stops being netcfgd's, because a record outliving its
 *     device is a claim on whatever next takes that name;
 *   * an event hook remembers what it was told, once per interface and phase,
 *     and only for the two phases that carry a value.
 *
 * Driven against `ncfg_owned_absorb` directly, because what is being checked is
 * one rule per op and a plan would only add noise between the two.
 */
static void the_folding_rules(void)
{
	ncfg_owned_state_t owned;
	ncfg_op_t          op;

	memset(&owned, 0, sizeof(owned));

	memset(&op, 0, sizeof(op));
	op.kind = NCFG_OP_SYSCTL_SET_FORWARDING;
	op.u.forwarding.iface = "eth0";
	op.u.forwarding.enabled = 1;
	(void)ncfg_owned_absorb(&owned, &op);
	check(has_string(owned.forwarding, owned.forwarding_count, "eth0"),
	    "an interface netcfgd switched forwarding on for is recorded");
	op.u.forwarding.enabled = 0;
	(void)ncfg_owned_absorb(&owned, &op);
	check(owned.forwarding_count == 0u,
	    "  and switching it back off drops the record rather than storing false");

	memset(&op, 0, sizeof(op));
	op.kind = NCFG_OP_SYSCTL_SET_ACCEPT_RA;
	op.u.accept_ra.iface = "eth0";
	op.u.accept_ra.value = 2;
	(void)ncfg_owned_absorb(&owned, &op);
	check(has_string(owned.accept_ra, owned.accept_ra_count, "eth0"),
	    "accept_ra is recorded where netcfgd set it to 2");
	op.u.accept_ra.value = 1;
	(void)ncfg_owned_absorb(&owned, &op);
	check(owned.accept_ra_count == 0u,
	    "  and handing the interface back is the value 1, not false (0073)");

	memset(&op, 0, sizeof(op));
	op.kind = NCFG_OP_QDISC_SET;
	op.u.qdisc.iface = "eth0";
	(void)ncfg_owned_absorb(&owned, &op);
	memset(&op, 0, sizeof(op));
	op.kind = NCFG_OP_QDISC_RESET;
	op.u.iface.iface = "eth0";
	(void)ncfg_owned_absorb(&owned, &op);
	check(owned.qdisc_count == 0u, "a qdisc set and then reset leaves no claim behind");

	memset(&op, 0, sizeof(op));
	op.kind = NCFG_OP_LINK_CREATE;
	op.u.link_create.name = "br0";
	(void)ncfg_owned_absorb(&owned, &op);
	(void)ncfg_owned_absorb(&owned, &op);
	check(owned.created_link_count == 1u,
	    "a link created twice is recorded once, so folding a journal again is safe");
	memset(&op, 0, sizeof(op));
	op.kind = NCFG_OP_LINK_DELETE;
	op.u.named.name = "br0";
	(void)ncfg_owned_absorb(&owned, &op);
	check(owned.created_link_count == 0u,
	    "  and deleting it takes the record away, so the name is nobody's claim");

	memset(&op, 0, sizeof(op));
	op.kind = NCFG_OP_HOOK_RUN;
	op.u.hook.iface = "eth0";
	op.u.hook.phase = (int)NCFG_HOOK_PHASE_LEASE;
	op.u.hook.path = "/run/lease";
	op.u.hook.value = "10.0.0.5/24";
	(void)ncfg_owned_absorb(&owned, &op);
	op.u.hook.value = "10.0.0.6/24";
	(void)ncfg_owned_absorb(&owned, &op);
	check(owned.hook_state_count == 1u && owned.hook_state[0].value &&
	    strcmp(owned.hook_state[0].value, "10.0.0.6/24") == 0,
	    "a hook remembers what it was told last, one record per interface and phase");
	memset(&op, 0, sizeof(op));
	op.kind = NCFG_OP_HOOK_RUN;
	op.u.hook.iface = "eth0";
	op.u.hook.phase = (int)NCFG_HOOK_PHASE_PRE_UP;
	op.u.hook.path = "/run/pre";
	check(ncfg_owned_absorb(&owned, &op) && owned.hook_state_count == 1u,
	    "  and a lifecycle phase carries no value, so it remembers nothing");
	/*
	 * **With a value on it, which the planner never puts there.** Checked
	 * anyway, because the phase test and the value test are two rules and a
	 * fixture that only ever exercises the second cannot tell them apart: the
	 * record's own type says `lease` and `carrier` are the two phases that
	 * have a value, and the two things that read it compare nothing else. A
	 * row for a third phase would be one nobody ever looks at and one nothing
	 * ever takes out.
	 */
	op.u.hook.value = "up";
	check(ncfg_owned_absorb(&owned, &op) && owned.hook_state_count == 1u,
	    "  and a value on a phase that has none is not remembered either");

	memset(&op, 0, sizeof(op));
	op.kind = NCFG_OP_BACKEND_START;
	op.u.backend.kind = (int)NCFG_BACKEND_DHCP4;
	op.u.backend.iface = "eth0";
	(void)ncfg_owned_absorb(&owned, &op);
	(void)ncfg_owned_absorb(&owned, &op);
	check(owned.backend_restart_count == 1u && owned.backend_restarts[0].count == 2,
	    "a backend started twice without staying up is counted twice (0079)");
	/*
	 * **The tally and the list are two answers to two questions**, and the
	 * second is the one the whole observation hangs off: `observed.backends`
	 * is filled from this record and from nowhere else, so a start that
	 * counted a restart and recorded no backend left six observation passes
	 * with an empty list to walk (project.md 10.183).
	 */
	check(owned.backend_count == 1u && owned.backends[0].kind == (int)NCFG_BACKEND_DHCP4 &&
	    owned.backends[0].interface && strcmp(owned.backends[0].interface, "eth0") == 0,
	    "  and the backend itself is in the record, once for two starts");
	check(owned.backend_count == 1u && owned.backends[0].running,
	    "  as running, which is netcfgd's memory of having started it (0078)");
	check(owned.backend_count == 1u && !owned.backends[0].answering.has,
	    "  and answering absent, because nothing asked it anything");
	memset(&op, 0, sizeof(op));
	op.kind = NCFG_OP_BACKEND_START;
	op.u.backend.kind = (int)NCFG_BACKEND_DHCP6;
	op.u.backend.iface = "eth0";
	check(ncfg_owned_absorb(&owned, &op) && owned.backend_count == 2u,
	    "  a second kind on one interface is a second backend, not the same one");
	memset(&op, 0, sizeof(op));
	op.kind = NCFG_OP_BACKEND_STOP;
	op.u.backend.kind = (int)NCFG_BACKEND_DHCP4;
	op.u.backend.iface = "eth0";
	(void)ncfg_owned_absorb(&owned, &op);
	check(owned.backend_restart_count == 1u &&
	    owned.backend_restarts[0].kind == (int)NCFG_BACKEND_DHCP6,
	    "  and a deliberate stop clears that count, the document having stopped asking");
	check(owned.backend_count == 1u && owned.backends[0].kind == (int)NCFG_BACKEND_DHCP6,
	    "  and takes that backend out, leaving the other kind alone");
	/*
	 * **The absence is the claim.** A record that outlived the daemon it
	 * describes would have netcfgd believe it may stop whatever next answers
	 * on that interface -- `link.delete`'s rule, one layer up.
	 */
	(void)ncfg_owned_absorb(&owned, &op);
	check(owned.backend_count == 1u,
	    "  and stopping one that is already gone is nothing, so a journal folds twice");

	/*
	 * `dns.apply` records nothing, and that is decided rather than missed.
	 * The executor delivers every scope its context carries whatever this op
	 * names, so the op is not the effect -- `apply.h` has the argument, and
	 * this pins the behaviour so that a wave which closes it has to come here.
	 */
	memset(&op, 0, sizeof(op));
	op.kind = NCFG_OP_DNS_APPLY;
	op.u.dns.scope = "globals";
	check(ncfg_owned_absorb(&owned, &op) && owned.dns_count == 0u,
	    "a dns.apply folds nothing, being the one op that is not its own effect");

	ncfg_owned_free(&owned);
}

/* A plan that changed nothing does not rewrite the file. */
/* A document whose `globals` block has a DNS policy of its own, which
 * `planfix_document`'s does not -- half the point here is that the host scope
 * and an interface's are two entries rather than one. */
static ncfg_document_t *dns_document(void)
{
	char             text[4096];
	char             message[NCFG_ERROR_MAX];
	ncfg_document_t *document;

	(void)snprintf(text, sizeof(text),
	    "{\"schema_version\":{\"major\":1,\"minor\":1},\"generated_by\":\"apply_test\","
	    "\"globals\":{\"dns\":{\"mode\":\"resolved\","
	    "\"servers\":[{\"addr\":\"9.9.9.9\"}]}},"
	    "\"devices\":[{\"name\":\"eth0\",\"kind\":{\"kind\":\"physical\"}}],"
	    "\"interfaces\":[{\"name\":\"eth0\","
	    "\"addressing\":[{\"source\":\"static\",\"address\":\"10.0.0.2/24\"}],"
	    "\"dns\":{\"mode\":\"resolved\","
	    "\"servers\":[{\"addr\":\"10.0.0.53\",\"port\":5353,\"sni\":\"dns.lan\"}],"
	    "\"search\":[\"lan.example\"],"
	    "\"domains\":[{\"suffix\":\"lan.example\",\"exclusive\":true}],"
	    "\"dnssec\":\"yes\",\"transport\":\"tls\"}}],"
	    "\"networks\":[]}");
	message[0] = '\0';
	document = ncfg_document_read(text, strlen(text), message, sizeof(message));
	if (!document) {
		printf("  fixture document did not read: %s\n", message);
	}
	return document;
}

static const ncfg_applied_dns_t *applied_named(const ncfg_owned_state_t *owned, const char *scope)
{
	size_t at;

	for (at = 0; at < owned->dns_count; at++) {
		if (owned->dns[at].scope && strcmp(owned->dns[at].scope, scope) == 0) {
			return &owned->dns[at];
		}
	}
	return NULL;
}

static int plans_a_delivery(const ncfg_plan_t *plan)
{
	size_t at;

	for (at = 0; at < plan->action_count; at++) {
		if (plan->actions[at].op.kind == NCFG_OP_DNS_APPLY) {
			return 1;
		}
	}
	return 0;
}

/*
 * What a delivery is written down as, and what that is for.
 *
 * **The second plan is the subject, not the file.** `observed.dns` is filled
 * from this record and from nowhere else, so while nothing wrote it the
 * planner compared every scope it wanted against an empty list and emitted a
 * `dns.apply` on every pass for ever -- plan idempotence failing with the
 * machine already changed. So the last two checks plan twice against the same
 * document: once with the record this fold wrote and once with nothing, and
 * they have to disagree.
 *
 * The scope list is the executor's, not the op's: one `dns.apply` names
 * `globals` and both scopes are recorded, because a delivery writes the
 * resolver file whole.
 */
static void what_a_delivery_is_recorded_as(char *run_dir)
{
	static const int done[] = { NCFG_OUTCOME_DONE };
	static const int failed[] = { NCFG_OUTCOME_FAILED };
	ncfg_document_t        *document = dns_document();
	ncfg_dns_scopes_t      *scopes;
	const ncfg_dns_scope_t *items;
	size_t                  count = 0;
	ncfg_plan_t            *plan;
	ncfg_journal_t          journal;
	ncfg_owned_state_t      owned;
	ncfg_op_t               op;
	char                    message[NCFG_ERROR_MAX];

	if (!document) {
		check(0, "what a delivery is recorded as");
		return;
	}
	message[0] = '\0';
	scopes = ncfg_dns_scopes_of(document, NULL, message, sizeof(message));
	items = ncfg_dns_scopes_items(scopes, &count);
	check(count == 2u, "the fixture has a host scope and an interface's");
	message[0] = '\0';
	plan = ncfg_plan_new(message, sizeof(message));
	if (!plan || !scopes) {
		check(0, "a plan carrying one delivery");
		ncfg_dns_scopes_free(scopes);
		ncfg_document_free(document);
		ncfg_plan_free(plan);
		return;
	}
	memset(&op, 0, sizeof(op));
	op.kind = NCFG_OP_DNS_APPLY;
	op.u.dns.scope = "globals";
	op.u.dns.policy = items[0].policy;
	put(plan, &op);

	journal_of(&journal, plan, done);
	message[0] = '\0';
	check(ncfg_apply_record(run_dir, plan, &journal, items, count, message, sizeof(message)),
	    "what a delivery delivered is folded into owned.json");
	if (read_back(run_dir, &owned)) {
		const ncfg_applied_dns_t *eth0 = applied_named(&owned, "eth0");

		check(owned.dns_count == 2u && applied_named(&owned, "globals") != NULL &&
		        eth0 != NULL,
		    "  both scopes are recorded, not the one the op named");
		check(eth0 && eth0->policy.server_count == 1u && eth0->policy.servers[0].addr &&
		        strcmp(eth0->policy.servers[0].addr, "10.0.0.53") == 0,
		    "  with the servers that were delivered");
		/* The four a hand-written copy is likeliest to drop, and every one of
		 * them is a field the planner compares: a policy that read back
		 * without them would be called different on every pass. */
		check(eth0 && eth0->policy.server_count == 1u &&
		        eth0->policy.servers[0].port.has &&
		        eth0->policy.servers[0].port.value == 5353 &&
		        eth0->policy.servers[0].sni &&
		        strcmp(eth0->policy.servers[0].sni, "dns.lan") == 0,
		    "  a server's port and SNI survive the round trip");
		check(eth0 && eth0->policy.dnssec.has &&
		        eth0->policy.dnssec.value == (int64_t)NCFG_DNSSEC_YES &&
		        eth0->policy.transport.has &&
		        eth0->policy.transport.value == (int64_t)NCFG_DNS_TRANSPORT_TLS,
		    "  and so do dnssec and transport");
		check(eth0 && eth0->policy.search_count == 1u && eth0->policy.domain_count == 1u &&
		        eth0->policy.domains[0].exclusive,
		    "  and the search list and the routing domains");
		{
			ncfg_observed_t *blank = observed_of("\"links\":[]");
			ncfg_observed_t *knowing = observed_of("\"links\":[]");
			ncfg_plan_t     *again;
			ncfg_plan_t     *ignorant;

			/* Moved rather than copied, which is what `observe/current.c`
			 * does with this member for the same reason: the record owns the
			 * policies and the observation is about to. */
			if (knowing) {
				knowing->dns = owned.dns;
				knowing->dns_count = owned.dns_count;
				owned.dns = NULL;
				owned.dns_count = 0;
			}
			message[0] = '\0';
			again = knowing ? ncfg_plan_build(document, knowing, NULL, message,
			    sizeof(message)) : NULL;
			ignorant = blank ? ncfg_plan_build(document, blank, NULL, message,
			    sizeof(message)) : NULL;
			check(again && !plans_a_delivery(again),
			    "  and a second plan against it asks for no delivery at all");
			check(ignorant && plans_a_delivery(ignorant),
			    "  which the same plan against an empty record does ask for");
			ncfg_plan_free(again);
			ncfg_plan_free(ignorant);
			ncfg_observed_free(knowing);
			ncfg_observed_free(blank);
		}
		ncfg_owned_free(&owned);
	}
	ncfg_journal_free(&journal);

	/*
	 * A caller with no list leaves the record alone rather than emptying it.
	 * Emptying would be the failure this whole path exists to close, arrived
	 * at from the other side: the next plan would ask for a delivery again.
	 */
	journal_of(&journal, plan, done);
	message[0] = '\0';
	(void)ncfg_apply_record(run_dir, plan, &journal, NULL, 0u, message, sizeof(message));
	if (read_back(run_dir, &owned)) {
		check(owned.dns_count == 2u,
		    "a fold with no scope list leaves the delivered scopes alone");
		ncfg_owned_free(&owned);
	}
	ncfg_journal_free(&journal);

	/* And an action that did not reach the machine delivered nothing, so the
	 * record still says what the last delivery said. */
	journal_of(&journal, plan, failed);
	message[0] = '\0';
	(void)ncfg_apply_record(run_dir, plan, &journal, items, 1u, message, sizeof(message));
	if (read_back(run_dir, &owned)) {
		check(owned.dns_count == 2u,
		    "and a delivery that failed records nothing, not even a shorter list");
		ncfg_owned_free(&owned);
	}
	ncfg_journal_free(&journal);

	ncfg_plan_free(plan);
	ncfg_dns_scopes_free(scopes);
	ncfg_document_free(document);
}

static void an_empty_journal_writes_nothing(char *run_dir)
{
	ncfg_plan_t   *plan;
	ncfg_journal_t journal;
	char           message[NCFG_ERROR_MAX];
	char           path[600];
	struct stat    before;
	struct stat    after;

	message[0] = '\0';
	plan = ncfg_plan_new(message, sizeof(message));
	ncfg_journal_init(&journal);
	(void)snprintf(path, sizeof(path), "%s/owned.json", run_dir);
	if (!plan || stat(path, &before) != 0) {
		check(0, "a plan with nothing in it does not rewrite the record");
		ncfg_plan_free(plan);
		return;
	}
	message[0] = '\0';
	check(ncfg_apply_record(run_dir, plan, &journal, NULL, 0u, message, sizeof(message)) &&
	    stat(path, &after) == 0 && before.st_ino == after.st_ino,
	    "a plan with nothing in it does not rewrite the record");
	ncfg_journal_free(&journal);
	ncfg_plan_free(plan);
}

/*
 * The journal reaches `<run_dir>/plan.last.json`, and holds what the renderer
 * rendered.
 *
 * **This is the file that answers "where did it stop".** An apply halts at the
 * first failure and marks everything after it skipped; a reconcile has no
 * terminal to print that to, so without this the answer exists nowhere. The
 * bytes themselves are the neighbouring check's subject -- what is asserted
 * here is that they arrive, whole, at the path every reader is pointed at.
 */
static void the_journal_reaches_the_run_directory(const char *run_dir)
{
	char           path[600];
	char           message[NCFG_ERROR_MAX];
	ncfg_journal_t journal;
	ncfg_record_t  record;
	ncfg_buf_t     rendered;
	char          *rendered_text = NULL;
	char          *on_disk;
	size_t         length = 0;
	FILE          *file;
	struct stat    first;
	struct stat    second;

	(void)snprintf(path, sizeof(path), "%s/plan.last.json", run_dir);

	ncfg_journal_init(&journal);
	memset(&record, 0, sizeof(record));
	record.id = 0;
	record.op = "link.up";
	record.interface = "eth0";
	record.outcome = NCFG_OUTCOME_DONE;
	ncfg_journal_push(&journal, &record);
	memset(&record, 0, sizeof(record));
	record.id = 1;
	record.op = "addr.add";
	record.interface = "eth0";
	record.outcome = NCFG_OUTCOME_FAILED;
	record.error = "Cannot assign requested address";
	ncfg_journal_push(&journal, &record);
	memset(&record, 0, sizeof(record));
	record.id = 2;
	record.op = "route.add";
	record.interface = "eth0";
	record.outcome = NCFG_OUTCOME_SKIPPED;
	ncfg_journal_push(&journal, &record);

	ncfg_buf_init(&rendered, 0);
	message[0] = '\0';
	if (ncfg_journal_write(&journal, &rendered, message, sizeof(message))) {
		rendered_text = ncfg_buf_take(&rendered, &length);
	}
	ncfg_buf_free(&rendered);

	message[0] = '\0';
	check(ncfg_apply_write_journal(run_dir, &journal, message, sizeof(message)),
	    "the journal of an apply is written to the run directory");
	on_disk = NULL;
	file = fopen(path, "rb");
	if (file) {
		char   bytes[4096];
		size_t got = fread(bytes, 1u, sizeof(bytes) - 1u, file);

		bytes[got] = '\0';
		on_disk = strdup(bytes);
		(void)fclose(file);
	}
	check(on_disk != NULL, "  at plan.last.json, where every reader is pointed");
	check(on_disk && rendered_text && strcmp(on_disk, rendered_text) == 0,
	    "  holding exactly what the renderer rendered, and no more");
	/* The action that failed, by name, is the whole reason the file exists:
	 * an operator finding a half-configured machine reads this rather than
	 * guessing from the log. */
	check(on_disk && strstr(on_disk, "\"outcome\":\"failed\"") != NULL &&
	    strstr(on_disk, "addr.add") != NULL,
	    "  including which action stopped it, which is what the file is for");
	check(on_disk && strstr(on_disk, "\"outcome\":\"skipped\"") != NULL,
	    "  and what never ran behind it");

	/*
	 * An empty journal is written, where the *fold* beside it deliberately
	 * does not write at all. Not an inconsistency: the record is a claim that
	 * accumulates and must not be rewritten by a pass that did nothing, while
	 * this file answers a question about the last apply -- and "it did
	 * nothing" is that answer rather than the absence of one. A stale journal
	 * left behind would be read as the last apply's, which is the failure.
	 */
	ncfg_journal_free(&journal);
	ncfg_journal_init(&journal);
	check(stat(path, &first) == 0, "  the file is there to be replaced");
	message[0] = '\0';
	check(ncfg_apply_write_journal(run_dir, &journal, message, sizeof(message)) &&
	    stat(path, &second) == 0 && first.st_ino != second.st_ino,
	    "an apply that did nothing replaces it rather than leaving the last one behind");
	free(on_disk);
	on_disk = NULL;
	file = fopen(path, "rb");
	if (file) {
		char   bytes[256];
		size_t got = fread(bytes, 1u, sizeof(bytes) - 1u, file);

		bytes[got] = '\0';
		on_disk = strdup(bytes);
		(void)fclose(file);
	}
	check(on_disk && strcmp(on_disk, "{\"records\":[]}") == 0,
	    "  and what it then holds says so rather than being empty or half a file");
	free(on_disk);

	/*
	 * And it is written under `owned.lock`, which is the fold's lock and is
	 * the one thing here the file's own contents cannot show. Asserted in a
	 * directory nothing has locked yet, so the lock file's existence is this
	 * call's doing and not a leftover: `ncfg_lock_take` creates it, and
	 * nothing else in this test has been near it.
	 *
	 * What the lock buys is ordering between this file and `owned.json` --
	 * they are two halves of one statement about one apply, and two processes
	 * write both.
	 */
	(void)snprintf(path, sizeof(path), "%s/locked", run_dir);
	if (mkdir(path, 0700) == 0) {
		char lock[700];

		message[0] = '\0';
		check(ncfg_apply_write_journal(path, &journal, message, sizeof(message)),
		    "a journal is written into a directory nothing has locked");
		(void)snprintf(lock, sizeof(lock), "%s/owned.lock", path);
		check(stat(lock, &first) == 0,
		    "  and owned.lock is there, so the write went under the fold's own lock");
		(void)unlink(lock);
		(void)snprintf(lock, sizeof(lock), "%s/plan.last.json", path);
		(void)unlink(lock);
		(void)rmdir(path);
	} else {
		check(0, "a directory nothing has locked could be made");
		check(0, "  and owned.lock is there, so the write went under the fold's own lock");
	}
	(void)snprintf(path, sizeof(path), "%s/plan.last.json", run_dir);

	/* The refusals, which are the shape every call in this header has. */
	message[0] = '\0';
	check(!ncfg_apply_write_journal(NULL, &journal, message, sizeof(message)) &&
	    message[0] != '\0', "a write with no run directory is refused with a sentence");
	check(!ncfg_apply_write_journal("", &journal, NULL, 0),
	    "and so is one with an empty one, which would write into the working directory");
	check(!ncfg_apply_write_journal(run_dir, NULL, NULL, 0),
	    "and one with no journal at all");
	/*
	 * A run directory that cannot be made is a failure that is *reported*
	 * rather than a file quietly not written. `state.h` calls the run
	 * directory derived and disposable, which is why every caller logs this
	 * and carries on -- but a caller can only do that if it is told.
	 *
	 * The unwritable path is inside this test's own directory, under a file
	 * rather than a directory, so `mkdir` answers `ENOTDIR`. **A path outside
	 * it would be made rather than refused**: `ncfg_lock_take` creates the
	 * directory it is asked for, which is `ncfg_owned_update`'s behaviour too
	 * -- so a check that handed this an absent absolute path would prove
	 * nothing and would create that path on whoever ran the suite. Found by
	 * writing it the wrong way round first.
	 */
	(void)snprintf(path, sizeof(path), "%s/owned.json/run", run_dir);
	message[0] = '\0';
	check(!ncfg_apply_write_journal(path, &journal, message, sizeof(message)) &&
	    message[0] != '\0',
	    "and a run directory that cannot be made fails loudly rather than silently");

	/*
	 * And the other half of that, which is a different branch entirely: the
	 * lock is taken, the directory is fine, and the **publish** is what fails.
	 * A directory in the file's place is the cheapest way to produce it -- the
	 * rename lands on a directory and cannot -- and it is inside this test's
	 * own tree.
	 *
	 * Worth its own case because the two failures are far apart in the call:
	 * a sabotage that made the write's result be ignored left every other
	 * check here green, this one being the only thing between it and an apply
	 * reporting a journal it did not write.
	 */
	(void)snprintf(path, sizeof(path), "%s/blocked", run_dir);
	if (mkdir(path, 0700) == 0) {
		char occupied[700];

		(void)snprintf(occupied, sizeof(occupied), "%s/plan.last.json", path);
		if (mkdir(occupied, 0700) == 0) {
			message[0] = '\0';
			check(!ncfg_apply_write_journal(path, &journal, message,
			    sizeof(message)) && message[0] != '\0',
			    "a publish that could not happen is reported, not reported as done");
			(void)rmdir(occupied);
		} else {
			check(0, "a directory could be put in the journal's place");
		}
		(void)snprintf(occupied, sizeof(occupied), "%s/owned.lock", path);
		(void)unlink(occupied);
		(void)rmdir(path);
	} else {
		check(0, "a directory could be put in the journal's place");
	}
	(void)snprintf(path, sizeof(path), "%s/plan.last.json", run_dir);
	ncfg_journal_free(&journal);
	free(rendered_text);
}

static void what_an_apply_did_is_recorded(void)
{
	char run_dir[512];

	if (!tempdir_make("apply-owned", run_dir, sizeof(run_dir))) {
		check(0, "a directory for the ownership record");
		return;
	}
	only_what_ran_is_claimed(run_dir);
	a_revert_takes_the_claims_back(run_dir);
	an_empty_journal_writes_nothing(run_dir);
	the_journal_reaches_the_run_directory(run_dir);
	what_a_delivery_is_recorded_as(run_dir);
	the_folding_rules();

	/* Named, never swept: this directory is one this test made, and the two
	 * files in it are the two it wrote. */
	{
		char path[600];

		(void)snprintf(path, sizeof(path), "%s/owned.json", run_dir);
		(void)unlink(path);
		(void)snprintf(path, sizeof(path), "%s/owned.lock", run_dir);
		(void)unlink(path);
		(void)snprintf(path, sizeof(path), "%s/plan.last.json", run_dir);
		(void)unlink(path);
		(void)rmdir(run_dir);
	}
}

int main(void)
{
	a_plan_is_carried_out_in_the_order_it_was_planned();
	addresses_go_in_before_the_routes_that_need_them();
	the_hook_phases_bracket_a_bring_up();
	the_withdrawal_sits_between_pre_down_and_down();
	the_confirm_window_is_armed_before_anything_it_covers();

	a_failure_stops_the_plan_and_the_rest_is_recorded_as_skipped();
	a_silent_failure_is_still_described();
	an_unfinished_plan_is_refused_rather_than_half_applied();

	only_done_actions_with_an_inverse_are_undone();
	the_inverses_run_newest_first();
	an_inverse_that_fails_does_not_stop_the_revert();
	a_hook_is_not_undone_and_a_revert_is_not_repeated();

	every_op_is_either_executed_or_refused_by_name();
	a_link_whose_kind_needs_the_models_numbering_is_refused();
	an_op_this_build_cannot_do_fails_its_action();

	the_journal_is_written_as_the_file_carries_it();

	what_an_apply_did_is_recorded();

	a_failure_vetoes_only_in_the_phases_that_can_veto();
	the_hook_runner();

	nothing_here_falls_over_on_an_empty_argument();

	printf("\n%d checks, %d failed\n", checks, failures);
	return failures ? 1 : 0;
}
