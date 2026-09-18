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
#include "ncfg/document.h"
#include "ncfg/hooks.h"
#include "ncfg/observed.h"
#include "ncfg/plan.h"
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
	static const ncfg_op_kind_t executed[] = { NCFG_OP_LINK_DELETE, NCFG_OP_LINK_SET_MTU,
		NCFG_OP_LINK_SET_MAC, NCFG_OP_LINK_SET_MASTER, NCFG_OP_LINK_UNSET_MASTER,
		NCFG_OP_LINK_UP, NCFG_OP_LINK_DOWN, NCFG_OP_ADDR_ADD, NCFG_OP_ADDR_DEL,
		NCFG_OP_ROUTE_ADD, NCFG_OP_ROUTE_DEL, NCFG_OP_HOOK_RUN, NCFG_OP_COMMIT_ARM,
		NCFG_OP_COMMIT_CONFIRM, NCFG_OP_COMMIT_REVERT };
	int    every_refusal_names_its_op = 1;
	int    every_op_answered = 1;
	size_t kind;

	/* `NCFG_OP_COMMIT_REVERT` is the last of the forty-eight. */
	for (kind = 0; kind <= (size_t)NCFG_OP_COMMIT_REVERT; kind++) {
		ncfg_op_t   op;
		char        message[NCFG_ERROR_MAX];
		const char *name;
		int         wanted = 0;
		int         answered;
		size_t      i;

		memset(&op, 0, sizeof(op));
		op.kind = (int)kind;
		name = ncfg_op_name(&op);
		for (i = 0; i < sizeof(executed) / sizeof(executed[0]); i++) {
			if ((size_t)executed[i] == kind) {
				wanted = 1;
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
 * A link whose kind needs the model's numbering is refused rather than half
 * made.
 *
 * `ops.h` says why the numbering belongs with the model: two lists of four
 * numbers in two places is how a mode comes to mean one thing on the way out
 * and another on the way back in. `document.h` is final and carries no such
 * function, so the honest answer here is a refusal that says so -- not a table
 * written in the module least likely to be read when the first one changes.
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
		{ NCFG_KIND_VLAN, 0, "a vlan" },
		{ NCFG_KIND_BOND, 0, "a bond" },
		{ NCFG_KIND_MACVLAN, 0, "a macvlan" },
		{ NCFG_KIND_TUNNEL, 0, "a tunnel" },
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

		memset(&reason, 0, sizeof(reason));
		reason.interface = "wg0";
		reason.field = "wireguard.peers";
		reason.desired = "1 peer";
		reason.observed = "<absent>";
		memset(&op, 0, sizeof(op));
		op.kind = NCFG_OP_WG_SET_PEERS;
		op.u.wg_peers.iface = "wg0";
		(void)ncfg_plan_add(plan, &op, &reason, NULL, 0, NULL);

		/* The double refuses exactly what `ncfg_apply_supported` refuses,
		 * which is what the kernel executor asks before it does anything. */
		recorder.fail_at = 0;
		recorder.failure = NULL;
		message[0] = '\0';
		(void)ncfg_apply(plan, &executor, &journal, message, sizeof(message));
		failure = ncfg_journal_failure(&journal);
		check(failure && failure->op && strcmp(failure->op, "wg.set_peers") == 0,
		    "an op this build cannot carry out fails its action rather than passing");
		message[0] = '\0';
		check(!ncfg_apply_supported(&op, message, sizeof(message)) &&
		    strstr(message, "wg.set_peers") && strstr(message, "generic netlink"),
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

	a_failure_vetoes_only_in_the_phases_that_can_veto();
	the_hook_runner();

	nothing_here_falls_over_on_an_empty_argument();

	printf("\n%d checks, %d failed\n", checks, failures);
	return failures ? 1 : 0;
}
