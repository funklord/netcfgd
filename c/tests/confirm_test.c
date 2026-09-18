/*
 * confirm_test.c -- the commit-confirm window, and the sweep that defends
 * `/etc/resolv.conf`.
 *
 * NOTHING HERE TOUCHES THE MACHINE THIS IS BUILT ON
 *   netcfgd is running here, its run directory is `/run/netcfgd` and its
 *   confirm files are `/run/netcfgd-confirm`. Every path below is under a
 *   directory this binary made with `mkdtemp` and removes at the end, and the
 *   run directory is one *inside* it -- so the sibling the confirm files go in
 *   is inside it too and goes when it does. Passing the scratch directory
 *   itself would put the sibling next to it, where nothing removes it.
 *
 *   **And nothing here signals a process.** The sweep is driven through
 *   `ncfg_resolv_machine_t`, a double this file fills in, so the four
 *   exclusions and the count are checked without a single real pid being
 *   looked at -- which is why the C has unit tests for a sweep the Rust could
 *   only cover with a live script. `ncfg_resolv_machine_default` is never
 *   called here, and that is deliberate.
 *
 * WHAT THE INTERESTING CASES ARE
 *   The clock, because a window is a promise about time: a machine that slept
 *   through one, and a clock somebody moved. Both are unwritable where the
 *   comparison reads the clock itself, which is why this port takes it as an
 *   argument and the Rust grew a second form to get the same two cases.
 *
 *   The ownership of what a window covers, because it outlives the document it
 *   was armed from: a reload *inside* a window replaces the daemon's desired
 *   document, so the record must not point into it. That is asserted by freeing
 *   the document and the plan before the revert runs, which under
 *   `make SANITIZE=1` is a use-after-free detector rather than a hope.
 */
#include "ncfg/apply.h"
#include "ncfg/base.h"
#include "ncfg/daemon.h"
#include "ncfg/document.h"
#include "ncfg/observed.h"
#include "ncfg/plan.h"
#include "ncfg/process.h"
#include "ncfg/state.h"

#include "testdir.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

/* A document with whatever body the caller wants, read through the model so
 * that nothing here builds one by hand. */
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

/* An interface whose MTU the document asks for, which is the one field the
 * revert measurement in `daemon.h` is about. */
#define DEVICE_WITH_MTU(mtu) \
	"\"devices\":[{\"name\":\"eth0\",\"kind\":{\"kind\":\"physical\"},\"mtu\":" mtu "}]," \
	"\"interfaces\":[{\"name\":\"eth0\"}]"
/* The smallest document the model accepts: both lists present and empty. */
#define NOTHING_CONFIGURED "\"devices\":[],\"interfaces\":[]"
#define LINK_AT_MTU(mtu) \
	"\"links\":[{\"name\":\"eth0\",\"index\":2,\"mtu\":" mtu ",\"up\":true," \
	"\"carrier\":true,\"ownership\":\"unknown\"}]"

/* ------------------------------------------------------------------------ *
 * The doubles
 * ------------------------------------------------------------------------ */

#define RECORDER_MAX 32
#define DESCRIPTION_MAX 128

typedef struct {
	char   seen[RECORDER_MAX][DESCRIPTION_MAX];
	size_t count;
	/* An op name whose execution fails, or NULL. */
	const char *refuse;
	int    overflowed;
} recorder_t;

static void describe(const ncfg_op_t *op, char *out, size_t out_size)
{
	const char *name = ncfg_op_name(op);

	switch ((ncfg_op_kind_t)op->kind) {
	case NCFG_OP_LINK_SET_MTU:
		(void)snprintf(out, out_size, "link.set_mtu %s %lld", op->u.set_mtu.name,
		    (long long)op->u.set_mtu.mtu);
		return;
	case NCFG_OP_ADDR_ADD:
		(void)snprintf(out, out_size, "addr.add %s %s", op->u.addr_add.iface,
		    op->u.addr_add.addr);
		return;
	case NCFG_OP_ADDR_DEL:
		(void)snprintf(out, out_size, "addr.del %s %s", op->u.addr_del.iface,
		    op->u.addr_del.addr);
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
	recorder->count++;
	if (recorder->refuse && strcmp(ncfg_op_name(op), recorder->refuse) == 0) {
		ncfg_error_set(err, err_size, "the double was told to refuse %s", recorder->refuse);
		return 0;
	}
	return 1;
}

static void recorder_init(recorder_t *recorder, ncfg_executor_t *executor)
{
	memset(recorder, 0, sizeof(*recorder));
	executor->state = recorder;
	executor->execute = recorder_execute;
}

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

static void sequence_is(const recorder_t *recorder, const char *wanted, const char *what)
{
	char got[1024];

	joined(recorder, got, sizeof(got));
	if (strcmp(got, wanted) != 0 || recorder->overflowed) {
		detail("wanted", wanted);
		detail("got", got);
	}
	check(!recorder->overflowed && strcmp(got, wanted) == 0, what);
}

static int recorder_saw(const recorder_t *recorder, const char *line)
{
	size_t at;

	for (at = 0; at < recorder->count; at++) {
		if (strcmp(recorder->seen[at], line) == 0) {
			return 1;
		}
	}
	return 0;
}

/* An observe seam that hands back a fresh copy of one fixture and counts how
 * often it was asked. A revert has to re-read the machine twice -- once after
 * the inverses and once at the end -- and nothing else can see that. */
typedef struct {
	const char *body;
	unsigned    calls;
} observer_t;

static int observe_fixture(void *context, const ncfg_document_t *desired,
    ncfg_observed_t **out, char *err, size_t err_size)
{
	observer_t *observer = context;

	(void)desired;
	observer->calls++;
	*out = observed_of(observer->body);
	if (!*out) {
		ncfg_error_set(err, err_size, "the fixture observation did not read");
		return 0;
	}
	return 1;
}

/*
 * What a real stop does to a `RuntimeDirectory=`: everything in it, and then
 * it. One level and no recursion, because that is what these run directories
 * hold -- and it refuses any path that is not inside the directory this binary
 * made, which is the guard `testdir.h` sets for a removal it cannot name the
 * files of.
 */
static void a_stop_removes(const char *base, const char *run)
{
	DIR                 *open_dir;
	const struct dirent *found;

	if (strncmp(run, base, strlen(base)) != 0) {
		printf("refusing to empty `%s`, which is not inside this test's directory\n", run);
		return;
	}
	open_dir = opendir(run);
	if (open_dir) {
		while ((found = readdir(open_dir)) != NULL) {
			char child[1024];

			if (strcmp(found->d_name, ".") == 0 ||
			    strcmp(found->d_name, "..") == 0) {
				continue;
			}
			(void)snprintf(child, sizeof(child), "%s/%s", run, found->d_name);
			(void)unlink(child);
		}
		(void)closedir(open_dir);
	}
	(void)rmdir(run);
}

/* ------------------------------------------------------------------------ *
 * Where the promise is kept
 * ------------------------------------------------------------------------ */

static void a_degenerate_run_directory_does_not_escape(void)
{
	char out[NCFG_CONFIRM_PATH_MAX];

	check(ncfg_confirm_dir("/run/netcfgd", out, sizeof(out)) &&
	        strcmp(out, "/run/netcfgd-confirm") == 0,
	    "the confirm directory is a sibling of the run directory");
	detail("for /run/netcfgd", out);
	check(ncfg_confirm_dir("/run/netcfgd/", out, sizeof(out)) &&
	        strcmp(out, "/run/netcfgd-confirm") == 0,
	    "a trailing slash names the same directory and answers the same");
	check(ncfg_confirm_dir("/", out, sizeof(out)) && strcmp(out, "/confirm") == 0,
	    "a root run directory resolves inside itself rather than escaping upwards");
	check(ncfg_confirm_dir("", out, sizeof(out)) && strcmp(out, "confirm") == 0,
	    "and so does an empty one");
	check(ncfg_confirm_dir("/netcfgd", out, sizeof(out)) &&
	        strcmp(out, "/netcfgd-confirm") == 0,
	    "a run directory directly under the root keeps the root as its parent");
	check(!ncfg_confirm_dir("/run/netcfgd", out, 8u),
	    "a directory that would not fit is refused rather than truncated");
}

static void a_window_round_trips_through_the_file(const char *base)
{
	char                  run[512];
	char                  err[NCFG_ERROR_MAX];
	ncfg_confirm_window_t window;
	ncfg_confirm_window_t back;

	(void)testdir_in(base, "roundtrip", run, sizeof(run));
	memset(&window, 0, sizeof(window));
	window.deadline_epoch = ncfg_confirm_now() + 120u;
	window.window_seconds = 120u;
	(void)snprintf(window.last_good_hash, sizeof(window.last_good_hash), "abc123");

	err[0] = '\0';
	check(ncfg_confirm_write_window(run, &window, err, sizeof(err)),
	    "a window is written to a run directory that does not exist yet");
	detail("if not", err);
	check(ncfg_confirm_read_window(run, &back) &&
	        back.deadline_epoch == window.deadline_epoch &&
	        back.window_seconds == 120u && strcmp(back.last_good_hash, "abc123") == 0,
	    "and reads back as the same window");
}

static void the_window_is_written_outside_the_runtime_directory(const char *base)
{
	char                  run[512];
	char                  directory[NCFG_CONFIRM_PATH_MAX];
	char                  path[NCFG_CONFIRM_PATH_MAX + 64];
	char                  err[NCFG_ERROR_MAX];
	ncfg_confirm_window_t window;
	ncfg_document_t      *document = document_of(NOTHING_CONFIGURED);
	ncfg_document_t      *back;

	(void)testdir_in(base, "outside", run, sizeof(run));
	memset(&window, 0, sizeof(window));
	window.deadline_epoch = ncfg_confirm_now() + 60u;
	window.window_seconds = 60u;
	(void)snprintf(window.last_good_hash, sizeof(window.last_good_hash), "x");
	err[0] = '\0';
	(void)ncfg_confirm_write_window(run, &window, err, sizeof(err));
	(void)ncfg_confirm_write_last_good(run, document, err, sizeof(err));

	(void)ncfg_confirm_dir(run, directory, sizeof(directory));
	check(strcmp(directory, run) != 0 &&
	        (strncmp(directory, run, strlen(run)) != 0 || directory[strlen(run)] != '/'),
	    "the confirm directory is neither the runtime directory nor inside it");
	detail("run", run);
	detail("confirm", directory);
	(void)snprintf(path, sizeof(path), "%s/confirm.json", directory);
	check(testdir_exists(path), "and the window really is over there");
	(void)snprintf(path, sizeof(path), "%s/last-good.json", directory);
	check(testdir_exists(path), "and so is the document it reverts to");
	(void)snprintf(path, sizeof(path), "%s/confirm.json", run);
	check(!testdir_exists(path), "rather than in the runtime directory");

	/*
	 * What a real stop does: `RuntimeDirectory=` goes and nothing else. A
	 * round trip passes just as well with both files back inside the run
	 * directory, so this is the assertion the fix exists for.
	 */
	(void)mkdir(run, 0755);
	(void)snprintf(path, sizeof(path), "%s/desired.json", run);
	(void)testdir_write(path, "{}", 2u);
	check(testdir_exists(path), "the runtime directory has something to lose");
	a_stop_removes(base, run);
	check(!testdir_exists(run), "and a stop takes it away, contents and all");
	check(ncfg_confirm_read_window(run, &window),
	    "a window survives the runtime directory being removed");
	back = ncfg_confirm_read_last_good(run, NULL, 0u);
	check(back != NULL, "and so does the document it reverts to");
	ncfg_document_free(back);
	ncfg_document_free(document);
}

static void a_window_file_something_else_wrote_is_refused(const char *base)
{
	char                  run[512];
	char                  directory[NCFG_CONFIRM_PATH_MAX];
	char                  path[NCFG_CONFIRM_PATH_MAX + 64];
	ncfg_confirm_window_t window;
	static const char     unknown[] =
	    "{\"deadline_epoch\":10,\"window_seconds\":5,\"last_good_hash\":\"a\",\"why\":1}";
	static const char     short_of_one[] = "{\"deadline_epoch\":10,\"window_seconds\":5}";
	static const char     rubbish[] = "not json at all";

	(void)testdir_in(base, "refused", run, sizeof(run));
	(void)ncfg_confirm_dir(run, directory, sizeof(directory));
	(void)snprintf(path, sizeof(path), "%s/confirm.json", directory);
	/* The directory is made by writing a real window into it first. */
	memset(&window, 0, sizeof(window));
	window.window_seconds = 5u;
	(void)ncfg_confirm_write_window(run, &window, NULL, 0u);

	(void)testdir_write(path, unknown, strlen(unknown));
	check(!ncfg_confirm_read_window(run, &window),
	    "a window file carrying a member netcfgd never writes is refused");
	(void)testdir_write(path, short_of_one, strlen(short_of_one));
	check(!ncfg_confirm_read_window(run, &window),
	    "and so is one that is short of a member");
	(void)testdir_write(path, rubbish, strlen(rubbish));
	check(!ncfg_confirm_read_window(run, &window),
	    "and a file that is not JSON reads as no window rather than as a failure");
	check(window.window_seconds == 0u && window.deadline_epoch == 0u,
	    "and the window it was given is left empty rather than half filled in");
}

static void clearing_an_absent_window_is_not_an_error(const char *base)
{
	char                  run[512];
	char                  err[NCFG_ERROR_MAX];
	ncfg_confirm_window_t window;

	(void)testdir_in(base, "clear", run, sizeof(run));
	err[0] = '\0';
	check(ncfg_confirm_clear_window(run, err, sizeof(err)) &&
	        ncfg_confirm_clear_window(run, err, sizeof(err)),
	    "clearing a window that is not there is success, twice over");
	detail("if not", err);
	check(!ncfg_confirm_read_window(run, &window), "and there is still no window open");
}

static void a_last_good_document_round_trips(const char *base)
{
	char             run[512];
	char             err[NCFG_ERROR_MAX];
	ncfg_document_t *document = document_of(DEVICE_WITH_MTU("9000"));
	ncfg_document_t *back;
	char             one[NCFG_DAEMON_HASH_MAX];
	char             two[NCFG_DAEMON_HASH_MAX];

	(void)testdir_in(base, "lastgood", run, sizeof(run));
	err[0] = '\0';
	check(document && ncfg_confirm_write_last_good(run, document, err, sizeof(err)),
	    "a last-good document is written");
	detail("if not", err);
	back = ncfg_confirm_read_last_good(run, err, sizeof(err));
	check(back != NULL, "and reads back");
	if (document && back && ncfg_daemon_document_hash(document, one, NULL, 0u) &&
	    ncfg_daemon_document_hash(back, two, NULL, 0u)) {
		check(strcmp(one, two) == 0, "as the same configuration, by identity");
	} else {
		check(0, "as the same configuration, by identity");
	}
	check(ncfg_confirm_read_last_good("/nonexistent-netcfgd-test", NULL, 0u) == NULL,
	    "and a directory with no last-good document answers none");
	ncfg_document_free(back);
	ncfg_document_free(document);
}

static void the_hash_follows_the_document_not_the_compile(void)
{
	ncfg_document_t *one = document_of(DEVICE_WITH_MTU("1400"));
	ncfg_document_t *two = document_of(DEVICE_WITH_MTU("1400"));
	ncfg_document_t *other = document_of(DEVICE_WITH_MTU("1401"));
	char             first[NCFG_DAEMON_HASH_MAX];
	char             second[NCFG_DAEMON_HASH_MAX];
	char             third[NCFG_DAEMON_HASH_MAX];

	if (one && two && other && ncfg_daemon_document_hash(one, first, NULL, 0u) &&
	    ncfg_daemon_document_hash(two, second, NULL, 0u) &&
	    ncfg_daemon_document_hash(other, third, NULL, 0u)) {
		check(strcmp(first, second) == 0,
		    "a hash identifies a configuration rather than a compilation");
		check(strcmp(first, third) != 0, "and a different configuration is a different one");
	} else {
		check(0, "a hash identifies a configuration rather than a compilation");
		check(0, "and a different configuration is a different one");
	}
	ncfg_document_free(one);
	ncfg_document_free(two);
	ncfg_document_free(other);
}

/* ------------------------------------------------------------------------ *
 * The clock
 * ------------------------------------------------------------------------ */

static void a_window_that_has_passed_reports_expired(void)
{
	ncfg_confirm_window_t past;
	ncfg_confirm_window_t future;
	uint64_t              now = ncfg_confirm_now();

	memset(&past, 0, sizeof(past));
	past.deadline_epoch = now > 0u ? now - 1u : 0u;
	past.window_seconds = 60u;
	check(ncfg_confirm_expired_at(&past, now), "a window whose deadline has passed is closed");
	check(ncfg_confirm_remaining_at(&past, now) == 0u, "and has no time left rather than a "
	    "negative one that wrapped");

	memset(&future, 0, sizeof(future));
	future.deadline_epoch = now + 60u;
	future.window_seconds = 60u;
	check(!ncfg_confirm_expired_at(&future, now), "one whose deadline has not is open");
	check(ncfg_confirm_remaining_at(&future, now) == 60u, "with its whole duration left");
}

/*
 * A window is wall-clock, so a machine that sleeps through it wakes with it
 * already closed. That is the property suspend needs and the reason the
 * deadline is an epoch rather than a monotonic instant, which does not advance
 * across a suspend -- a window stored that way would come back with its whole
 * duration still to run, and the first observation after the lid opens would
 * revert a change the operator had been living with all night.
 */
static void a_window_does_not_survive_the_machine_sleeping_through_it(void)
{
	const uint64_t        armed_at = 1700000000u;
	ncfg_confirm_window_t window;

	memset(&window, 0, sizeof(window));
	window.deadline_epoch = armed_at + 60u;
	window.window_seconds = 60u;

	check(!ncfg_confirm_expired_at(&window, armed_at + 59u), "a second before the deadline "
	    "the window is open");
	check(ncfg_confirm_remaining_at(&window, armed_at + 59u) == 1u, "with a second left");
	check(ncfg_confirm_expired_at(&window, armed_at + 8u * 60u * 60u),
	    "eight hours of suspend later it is closed rather than untouched");
	check(ncfg_confirm_remaining_at(&window, armed_at + 8u * 60u * 60u) == 0u,
	    "and has nothing left");
}

/*
 * The cost of wall-clock, pinned where somebody deciding about it will look: a
 * laptop usually takes an NTP correction shortly after resuming, and a step
 * backwards lengthens an open window rather than leaving it alone. Neither
 * direction is asserted to be right; the check exists so that changing it is a
 * decision with a number attached rather than an accident.
 */
static void moving_the_clock_moves_an_open_window(void)
{
	const uint64_t        armed_at = 1700000000u;
	ncfg_confirm_window_t window;

	memset(&window, 0, sizeof(window));
	window.deadline_epoch = armed_at + 60u;
	window.window_seconds = 60u;

	check(!ncfg_confirm_expired_at(&window, armed_at - 60u * 60u),
	    "a clock stepped back an hour leaves the window open");
	check(ncfg_confirm_remaining_at(&window, armed_at - 60u * 60u) == 60u * 60u + 60u,
	    "with an hour and a minute on it, and nothing notices the jump");
	check(ncfg_confirm_expired_at(&window, armed_at + 61u),
	    "and one stepped past the deadline closes it early");
}

/* ------------------------------------------------------------------------ *
 * What an open window covers
 * ------------------------------------------------------------------------ */

/* An action whose op is `link.set_mtu <mtu>` and whose inverse puts `was`
 * back, which is the shape the revert measurement is about. */
static uint32_t add_mtu_action(ncfg_plan_t *plan, int64_t mtu, int64_t was, int reversible)
{
	ncfg_op_t     op;
	ncfg_op_t     inverse;
	ncfg_reason_t reason;

	memset(&op, 0, sizeof(op));
	op.kind = NCFG_OP_LINK_SET_MTU;
	op.u.set_mtu.name = "eth0";
	op.u.set_mtu.mtu = mtu;
	memset(&inverse, 0, sizeof(inverse));
	inverse.kind = NCFG_OP_LINK_SET_MTU;
	inverse.u.set_mtu.name = "eth0";
	inverse.u.set_mtu.mtu = was;
	memset(&reason, 0, sizeof(reason));
	reason.interface = "eth0";
	reason.field = "mtu";
	reason.desired = "1400";
	reason.observed = "1500";
	return ncfg_plan_add(plan, &op, &reason, NULL, 0u, reversible ? &inverse : NULL);
}

static void push_outcome(ncfg_journal_t *journal, uint32_t id, int outcome)
{
	ncfg_record_t record;

	memset(&record, 0, sizeof(record));
	record.id = id;
	record.op = "link.set_mtu";
	record.interface = "eth0";
	record.reason.interface = "eth0";
	record.reason.field = "mtu";
	record.reason.desired = "1400";
	record.reason.observed = "1500";
	record.outcome = outcome;
	ncfg_journal_push(journal, &record);
}

/*
 * Only what reached the kernel, and only what declared an inverse.
 *
 * The three rejections are the point rather than the acceptance. An action
 * that failed or never ran has nothing to undo, and replaying its inverse
 * would be netcfgd taking back a change it never made -- on a machine that is
 * already in the state a revert exists to rescue.
 */
static void only_done_actions_with_an_inverse_are_undone(void)
{
	ncfg_plan_t         *plan = ncfg_plan_new(NULL, 0u);
	ncfg_journal_t       journal;
	ncfg_confirm_armed_t armed;
	ncfg_executor_t      executor;
	recorder_t           recorder;
	char                 err[NCFG_ERROR_MAX];

	ncfg_journal_init(&journal);
	push_outcome(&journal, add_mtu_action(plan, 1400, 1500, 1), NCFG_OUTCOME_DONE);
	push_outcome(&journal, add_mtu_action(plan, 1400, 1200, 1), NCFG_OUTCOME_FAILED);
	push_outcome(&journal, add_mtu_action(plan, 1400, 1100, 1), NCFG_OUTCOME_SKIPPED);
	push_outcome(&journal, add_mtu_action(plan, 1400, 0, 0), NCFG_OUTCOME_DONE);

	err[0] = '\0';
	check(ncfg_confirm_armed_from(plan, &journal, NULL, &armed, err, sizeof(err)),
	    "what a window covers is taken from the plan and the journal together");
	detail("if not", err);
	recorder_init(&recorder, &executor);
	(void)ncfg_apply_revert(armed.undo, &armed.journal, &executor);
	sequence_is(&recorder, "link.set_mtu eth0 1500",
	    "and it is the one action that ran and declared an inverse");

	ncfg_confirm_armed_free(&armed);
	ncfg_journal_free(&journal);
	ncfg_plan_free(plan);
}

/*
 * Plan order is preserved, because the revert is what reverses it.
 *
 * Asserted separately from the filtering above: a record that happened to come
 * out reversed would leave the revert applying the inverses oldest-first,
 * which is the wrong order and which no test of the filtering could see. An
 * address added after a link was brought up has to go before the link goes
 * down, or the removal is aimed at something that is no longer there.
 */
static void the_inverses_are_replayed_newest_first(void)
{
	ncfg_plan_t         *plan = ncfg_plan_new(NULL, 0u);
	ncfg_journal_t       journal;
	ncfg_confirm_armed_t armed;
	ncfg_executor_t      executor;
	recorder_t           recorder;

	ncfg_journal_init(&journal);
	push_outcome(&journal, add_mtu_action(plan, 1400, 1500, 1), NCFG_OUTCOME_DONE);
	push_outcome(&journal, add_mtu_action(plan, 1400, 1400, 1), NCFG_OUTCOME_DONE);
	push_outcome(&journal, add_mtu_action(plan, 1400, 1300, 1), NCFG_OUTCOME_DONE);

	(void)ncfg_confirm_armed_from(plan, &journal, NULL, &armed, NULL, 0u);
	recorder_init(&recorder, &executor);
	check(ncfg_apply_revert(armed.undo, &armed.journal, &executor) == 3u,
	    "every inverse that ran is counted");
	sequence_is(&recorder, "link.set_mtu eth0 1300,link.set_mtu eth0 1400,"
	    "link.set_mtu eth0 1500",
	    "and they come off newest first, the way any stack of changes does");

	/* A second revert finds every record marked as put back and leaves them
	 * alone, which is what makes an expiry and an explicit revert racing each
	 * other harmless. */
	memset(&recorder, 0, sizeof(recorder));
	check(ncfg_apply_revert(armed.undo, &armed.journal, &executor) == 0u &&
	        recorder.count == 0u,
	    "and a second revert puts nothing back a second time");

	ncfg_confirm_armed_free(&armed);
	ncfg_journal_free(&journal);
	ncfg_plan_free(plan);
}

/*
 * The record outlives the document and the plan it was built from.
 *
 * **This is the assertion the design exists for.** A reload inside a window
 * replaces the daemon's desired document with an edit that was deferred and
 * never applied, so a record borrowing from that document would be reading
 * freed memory at the moment the revert runs. Under `make SANITIZE=1` this is
 * a use-after-free detector; without it, the op still has to carry the right
 * name and value.
 */
static void what_a_window_covers_outlives_the_document_it_came_from(void)
{
	ncfg_document_t     *document = document_of(DEVICE_WITH_MTU("9000"));
	ncfg_observed_t     *observed = observed_of(LINK_AT_MTU("1500"));
	ncfg_plan_t         *plan;
	ncfg_journal_t       journal;
	ncfg_confirm_armed_t armed;
	ncfg_executor_t      executor;
	recorder_t           recorder;
	char                 err[NCFG_ERROR_MAX];

	err[0] = '\0';
	plan = ncfg_plan_build(document, observed, NULL, err, sizeof(err));
	if (!plan) {
		detail("the planner refused the fixture", err);
		check(0, "what a window covers outlives the document it came from");
		ncfg_document_free(document);
		ncfg_observed_free(observed);
		return;
	}
	recorder_init(&recorder, &executor);
	ncfg_journal_init(&journal);
	(void)ncfg_apply(plan, &executor, &journal, err, sizeof(err));
	check(ncfg_confirm_armed_from(plan, &journal, document, &armed, err, sizeof(err)),
	    "a window is armed over a plan the planner built");

	/* Everything the plan and the record were built from goes away first. */
	ncfg_journal_free(&journal);
	ncfg_plan_free(plan);
	ncfg_document_free(document);
	ncfg_observed_free(observed);

	memset(&recorder, 0, sizeof(recorder));
	(void)ncfg_apply_revert(armed.undo, &armed.journal, &executor);
	check(recorder_saw(&recorder, "link.set_mtu eth0 1500"),
	    "and the revert still carries the value the action replaced");
	ncfg_confirm_armed_free(&armed);
}

/* ------------------------------------------------------------------------ *
 * The state machine
 * ------------------------------------------------------------------------ */

/* A state over a run directory of its own, with nothing read yet. */
static int state_over(ncfg_daemon_state_t *state, const char *base, const char *leaf,
    char *run, size_t run_size)
{
	char config[512];
	char err[NCFG_ERROR_MAX];

	(void)testdir_in(base, leaf, run, run_size);
	(void)snprintf(config, sizeof(config), "%s/%s-config", base, leaf);
	err[0] = '\0';
	if (!ncfg_daemon_state_init(state, NULL, config, run, err, sizeof(err))) {
		detail("the state would not start", err);
		return 0;
	}
	return 1;
}

static void a_window_is_refused_where_there_is_nothing_to_go_back_to(const char *base)
{
	ncfg_daemon_state_t   state;
	char                  run[512];
	char                  err[NCFG_ERROR_MAX];
	ncfg_confirm_window_t window;

	if (!state_over(&state, base, "mayarm", run, sizeof(run))) {
		return;
	}
	err[0] = '\0';
	check(ncfg_confirm_may_arm(&state, err, sizeof(err)) == NULL &&
	        strstr(err, "no last-good configuration") != NULL,
	    "arming with nothing to revert to is refused rather than armed over nothing");
	detail("said", err);

	/* Now there is one, and a window may be opened. */
	{
		ncfg_document_t *document = document_of(DEVICE_WITH_MTU("1400"));
		ncfg_document_t *answered;

		(void)ncfg_confirm_write_last_good(run, document, NULL, 0u);
		err[0] = '\0';
		answered = ncfg_confirm_may_arm(&state, err, sizeof(err));
		check(answered != NULL, "with a last-good configuration on disk it is allowed");
		detail("if not", err);
		ncfg_document_free(answered);
		ncfg_document_free(document);
	}

	/* And a second window over the first is refused, naming what is left. */
	memset(&window, 0, sizeof(window));
	window.deadline_epoch = ncfg_confirm_now() + 45u;
	window.window_seconds = 45u;
	(void)ncfg_confirm_write_window(run, &window, NULL, 0u);
	err[0] = '\0';
	check(ncfg_confirm_may_arm(&state, err, sizeof(err)) == NULL &&
	        strstr(err, "already open") != NULL && strstr(err, "45s") != NULL,
	    "a second window over an open one is refused, with the time left named");
	detail("said", err);
	ncfg_daemon_state_free(&state);
}

static void arming_writes_the_window_and_says_so(const char *base)
{
	ncfg_daemon_state_t   state;
	char                  run[512];
	char                  err[NCFG_ERROR_MAX];
	ncfg_document_t      *last_good = document_of(DEVICE_WITH_MTU("1400"));
	ncfg_proto_event_t    event;
	ncfg_confirm_window_t window;
	char                  hash[NCFG_DAEMON_HASH_MAX];

	if (!state_over(&state, base, "arm", run, sizeof(run))) {
		ncfg_document_free(last_good);
		return;
	}
	memset(&event, 0, sizeof(event));
	err[0] = '\0';
	check(ncfg_confirm_arm(&state, 90u, last_good, &event, err, sizeof(err)),
	    "arming a window writes it");
	detail("if not", err);
	check(event.kind == NCFG_PROTO_EVENT_CONFIRM_ARMED && event.seconds == 90,
	    "and answers the event a subscriber is told");
	check(ncfg_confirm_read_window(run, &window) && window.window_seconds == 90u &&
	        ncfg_confirm_remaining_at(&window, ncfg_confirm_now()) > 85u,
	    "and the window on disk carries the deadline and the duration");
	check(ncfg_daemon_document_hash(last_good, hash, NULL, 0u) &&
	        strcmp(window.last_good_hash, hash) == 0,
	    "and names the document it would go back to, by identity");

	ncfg_daemon_state_free(&state);
	ncfg_document_free(last_good);
}

/*
 * A window that could not be written is not a window, and this is the whole
 * reason the C returns a refusal where the Rust logs one: a `confirm_armed`
 * event with no file behind it tells every client the change is covered while
 * nothing on disk will ever resolve it.
 */
static void a_window_that_cannot_be_written_is_refused(const char *base)
{
	ncfg_daemon_state_t state;
	char                run[512];
	char                directory[NCFG_CONFIRM_PATH_MAX];
	char                err[NCFG_ERROR_MAX];
	ncfg_document_t    *last_good = document_of(NOTHING_CONFIGURED);
	ncfg_proto_event_t  event;

	if (!state_over(&state, base, "unwritable", run, sizeof(run))) {
		ncfg_document_free(last_good);
		return;
	}
	/*
	 * A *file* where the confirm directory should be, rather than a mode: the
	 * suite may be run as root, and root writes through a mode of 000. A
	 * regular name in the way refuses whoever is asking.
	 */
	(void)ncfg_confirm_dir(run, directory, sizeof(directory));
	(void)testdir_write(directory, "in the way", 10u);
	memset(&event, 0, sizeof(event));
	err[0] = '\0';
	check(!ncfg_confirm_arm(&state, 30u, last_good, &event, err, sizeof(err)),
	    "a window that could not be written is refused rather than announced");
	detail("said", err);
	check(event.kind == 0 && event.seconds == 0,
	    "and no `confirm_armed` event is handed out for a window that is not there");
	(void)unlink(directory);
	ncfg_daemon_state_free(&state);
	ncfg_document_free(last_good);
}

static void keeping_the_change_closes_the_window(const char *base)
{
	ncfg_daemon_state_t   state;
	char                  run[512];
	char                  err[NCFG_ERROR_MAX];
	ncfg_document_t      *applied = document_of(DEVICE_WITH_MTU("9000"));
	ncfg_document_t      *edited = document_of(DEVICE_WITH_MTU("1400"));
	ncfg_document_t      *back;
	ncfg_proto_event_t    event;
	ncfg_confirm_window_t window;
	ncfg_confirm_armed_t  armed;
	ncfg_plan_t          *plan = ncfg_plan_new(NULL, 0u);
	ncfg_journal_t        journal;
	char                  wanted[NCFG_DAEMON_HASH_MAX];
	char                  got[NCFG_DAEMON_HASH_MAX];

	if (!state_over(&state, base, "keep", run, sizeof(run))) {
		ncfg_document_free(applied);
		ncfg_document_free(edited);
		ncfg_plan_free(plan);
		return;
	}
	err[0] = '\0';
	check(!ncfg_confirm_keep(&state, NULL, applied, &event, err, sizeof(err)) &&
	        strcmp(err, "no confirm window is open") == 0,
	    "confirming with no window open is refused, in a sentence for the caller");

	ncfg_journal_init(&journal);
	push_outcome(&journal, add_mtu_action(plan, 9000, 1500, 1), NCFG_OUTCOME_DONE);
	(void)ncfg_confirm_armed_from(plan, &journal, applied, &armed, NULL, 0u);
	(void)ncfg_confirm_arm(&state, 60u, applied, NULL, NULL, 0u);

	/*
	 * **The daemon's desired document has moved on**, which is what a reload
	 * inside the window does: the operator edited again and that edit was
	 * deferred, never applied. What is confirmed is what was applied.
	 */
	state.desired = edited;
	memset(&event, 0, sizeof(event));
	err[0] = '\0';
	check(ncfg_confirm_keep(&state, &armed, applied, &event, err, sizeof(err)),
	    "confirming an open window succeeds");
	detail("if not", err);
	check(event.kind == NCFG_PROTO_EVENT_CONFIRM_RESOLVED && event.confirmed == 1u,
	    "and says the change was confirmed");
	check(!ncfg_confirm_read_window(run, &window), "the window is closed");
	check(armed.undo == NULL && armed.journal.record_count == 0u,
	    "and there is nothing left to take back");

	back = ncfg_confirm_read_last_good(run, NULL, 0u);
	check(back != NULL && ncfg_daemon_document_hash(applied, wanted, NULL, 0u) &&
	        ncfg_daemon_document_hash(back, got, NULL, 0u) && strcmp(wanted, got) == 0,
	    "and the last-good document is the one the window covered, not the deferred edit");
	if (back && ncfg_daemon_document_hash(edited, wanted, NULL, 0u) &&
	    ncfg_daemon_document_hash(back, got, NULL, 0u)) {
		check(strcmp(wanted, got) != 0,
		    "which is a configuration the machine has actually been in");
	} else {
		check(0, "which is a configuration the machine has actually been in");
	}

	ncfg_document_free(back);
	ncfg_journal_free(&journal);
	ncfg_plan_free(plan);
	ncfg_daemon_state_free(&state);
	ncfg_document_free(applied);
}

static void reverting_needs_a_window_and_a_document(const char *base)
{
	ncfg_daemon_state_t   state;
	char                  run[512];
	char                  err[NCFG_ERROR_MAX];
	ncfg_executor_t       executor;
	recorder_t            recorder;
	ncfg_proto_event_t    event;
	ncfg_confirm_window_t window;

	if (!state_over(&state, base, "norevert", run, sizeof(run))) {
		return;
	}
	recorder_init(&recorder, &executor);
	err[0] = '\0';
	check(!ncfg_confirm_revert(&state, NULL, &executor, "asked to", &event, err, sizeof(err)) &&
	        strcmp(err, "no confirm window is open") == 0,
	    "reverting with no window open is refused");

	/* A window with no last-good document beside it: the window is closed
	 * anyway, because one nothing can resolve is a timer that never stops. */
	memset(&window, 0, sizeof(window));
	window.deadline_epoch = ncfg_confirm_now() + 60u;
	window.window_seconds = 60u;
	(void)ncfg_confirm_write_window(run, &window, NULL, 0u);
	err[0] = '\0';
	check(!ncfg_confirm_revert(&state, NULL, &executor, "asked to", &event, err, sizeof(err)) &&
	        strstr(err, "unreadable") != NULL,
	    "a window whose last-good document is unreadable reverts nothing and says so");
	detail("said", err);
	check(!ncfg_confirm_read_window(run, &window),
	    "and the window is closed anyway, rather than left as a timer nothing can stop");
	check(recorder.count == 0u, "and nothing was carried out on the machine");
	ncfg_daemon_state_free(&state);
}

/*
 * The whole path: the inverses, the document, the blacklist and the re-plan.
 *
 * The MTU is the case the two halves are about. The last-good document states
 * an MTU of 1500 here, so the re-plan would put it back on its own -- what the
 * inverse adds is the case where it does not, which
 * `the_replan_is_the_safety_net_where_the_inverses_are_gone` drives from the
 * other side.
 */
static void a_revert_puts_the_machine_and_the_document_back(const char *base)
{
	ncfg_daemon_state_t   state;
	char                  run[512];
	char                  err[NCFG_ERROR_MAX];
	ncfg_document_t      *last_good = document_of(DEVICE_WITH_MTU("1500"));
	ncfg_document_t      *applied = document_of(DEVICE_WITH_MTU("9000"));
	ncfg_document_t      *edited = document_of(DEVICE_WITH_MTU("1400"));
	ncfg_plan_t          *plan = ncfg_plan_new(NULL, 0u);
	ncfg_journal_t        journal;
	ncfg_confirm_armed_t  armed;
	ncfg_executor_t       executor;
	recorder_t            recorder;
	observer_t            observer;
	ncfg_proto_event_t    event;
	ncfg_confirm_window_t window;
	char                  hash[NCFG_DAEMON_HASH_MAX];
	char                  wanted[NCFG_DAEMON_HASH_MAX];
	/*
	 * Taken before the revert, because the revert frees the document it
	 * replaces -- which is the deferred edit, and is exactly what makes
	 * holding the hash rather than the document the right shape.
	 */
	char                  edited_hash[NCFG_DAEMON_HASH_MAX];

	if (!state_over(&state, base, "revert", run, sizeof(run))) {
		return;
	}
	observer.body = LINK_AT_MTU("1500");
	observer.calls = 0u;
	state.observe = observe_fixture;
	state.observe_context = &observer;
	state.observed = observed_of(LINK_AT_MTU("9000"));
	/* The operator edited again inside the window; that edit was deferred and
	 * never applied. */
	state.desired = edited;
	edited_hash[0] = '\0';
	(void)ncfg_daemon_document_hash(edited, edited_hash, NULL, 0u);

	ncfg_journal_init(&journal);
	push_outcome(&journal, add_mtu_action(plan, 9000, 1500, 1), NCFG_OUTCOME_DONE);
	(void)ncfg_confirm_armed_from(plan, &journal, applied, &armed, NULL, 0u);
	(void)ncfg_confirm_write_last_good(run, last_good, NULL, 0u);
	(void)ncfg_confirm_arm(&state, 60u, last_good, NULL, NULL, 0u);

	recorder_init(&recorder, &executor);
	memset(&event, 0, sizeof(event));
	err[0] = '\0';
	check(ncfg_confirm_revert(&state, &armed, &executor, "the window closed unconfirmed",
	        &event, err, sizeof(err)),
	    "a revert with a window, a last-good document and an executor succeeds");
	detail("if not", err);
	check(event.kind == NCFG_PROTO_EVENT_CONFIRM_RESOLVED && event.confirmed == 0u,
	    "and says the change was not confirmed");
	check(recorder_saw(&recorder, "link.set_mtu eth0 1500"),
	    "the declared inverse ran, carrying the value the action replaced");
	check(!ncfg_confirm_read_window(run, &window), "the window is closed");
	check(armed.undo == NULL, "and what it covered is spent");
	check(state.desired != NULL &&
	        ncfg_daemon_document_hash(state.desired, hash, NULL, 0u) &&
	        ncfg_daemon_document_hash(last_good, wanted, NULL, 0u) &&
	        strcmp(hash, wanted) == 0,
	    "the desired state is the last-good document, so the next drift check "
	    "cannot put the breakage back");
	check(observer.calls >= 2u,
	    "and the machine was re-read after the inverses ran, so the re-plan did not "
	    "re-issue work already done");

	/*
	 * **What the window covered, not what is on disk now.** Blacklisting the
	 * deferred edit would refuse the operator's newest configuration for
	 * something it never did.
	 */
	check(state.rejected != NULL && ncfg_daemon_document_hash(applied, hash, NULL, 0u) &&
	        strcmp(state.rejected, hash) == 0,
	    "the configuration the revert rejects is the one the window covered");
	check(state.rejected && edited_hash[0] && strcmp(state.rejected, edited_hash) != 0,
	    "and not the edit that arrived while the window was open");

	ncfg_journal_free(&journal);
	ncfg_plan_free(plan);
	ncfg_daemon_state_free(&state);
	ncfg_document_free(last_good);
	ncfg_document_free(applied);
}

/*
 * A failed inverse is stepped over rather than stopping the revert.
 *
 * The remaining inverses are for other actions and are still worth running,
 * and the re-plan is what covers whatever this one failed to take back.
 * Stopping here would leave a machine that is neither the new configuration
 * nor the old one, which is the one outcome a revert exists to prevent.
 */
static void a_failed_inverse_does_not_stop_the_revert(const char *base)
{
	ncfg_daemon_state_t  state;
	char                 run[512];
	ncfg_document_t     *last_good = document_of(NOTHING_CONFIGURED);
	ncfg_plan_t         *plan = ncfg_plan_new(NULL, 0u);
	ncfg_journal_t       journal;
	ncfg_confirm_armed_t armed;
	ncfg_executor_t      executor;
	recorder_t           recorder;
	ncfg_proto_event_t   event;

	if (!state_over(&state, base, "stepover", run, sizeof(run))) {
		return;
	}
	ncfg_journal_init(&journal);
	push_outcome(&journal, add_mtu_action(plan, 9000, 1500, 1), NCFG_OUTCOME_DONE);
	push_outcome(&journal, add_mtu_action(plan, 9000, 1400, 1), NCFG_OUTCOME_DONE);
	push_outcome(&journal, add_mtu_action(plan, 9000, 1300, 1), NCFG_OUTCOME_DONE);
	(void)ncfg_confirm_armed_from(plan, &journal, last_good, &armed, NULL, 0u);
	(void)ncfg_confirm_write_last_good(run, last_good, NULL, 0u);
	(void)ncfg_confirm_arm(&state, 60u, last_good, NULL, NULL, 0u);

	recorder_init(&recorder, &executor);
	recorder.refuse = "link.set_mtu";
	check(ncfg_confirm_revert(&state, &armed, &executor, "asked to", &event, NULL, 0u),
	    "a revert whose every inverse fails still reports what it did");
	sequence_is(&recorder, "link.set_mtu eth0 1300,link.set_mtu eth0 1400,"
	    "link.set_mtu eth0 1500",
	    "and every one of them was attempted rather than stopping at the first");

	ncfg_journal_free(&journal);
	ncfg_plan_free(plan);
	ncfg_daemon_state_free(&state);
	ncfg_document_free(last_good);
}

/*
 * The re-plan is the safety net, and it is not a duplicate of the inverses.
 *
 * A restarted daemon has no record of what it applied -- the inverses are in
 * memory and the process is new -- so this is the path every restart takes. It
 * converges from wherever the machine actually is.
 */
static void the_replan_is_the_safety_net_where_the_inverses_are_gone(const char *base)
{
	ncfg_daemon_state_t state;
	char                run[512];
	ncfg_document_t    *last_good = document_of(DEVICE_WITH_MTU("1500"));
	ncfg_executor_t     executor;
	recorder_t          recorder;
	ncfg_proto_event_t  event;
	char                err[NCFG_ERROR_MAX];
	int                 resolved = -1;

	if (!state_over(&state, base, "replan", run, sizeof(run))) {
		ncfg_document_free(last_good);
		return;
	}
	err[0] = '\0';
	check(ncfg_confirm_resolve_on_startup(&state, NULL, &executor, &resolved, &event, err,
	        sizeof(err)) && resolved == 0,
	    "a daemon that starts with no window open resolves nothing");
	detail("if not", err);

	/* The machine is at 9000 and the last-good document says 1500; nothing is
	 * armed, which is what a restart leaves behind. */
	state.observed = observed_of(LINK_AT_MTU("9000"));
	(void)ncfg_confirm_write_last_good(run, last_good, NULL, 0u);
	(void)ncfg_confirm_arm(&state, 3600u, last_good, NULL, NULL, 0u);
	recorder_init(&recorder, &executor);
	resolved = -1;
	err[0] = '\0';
	check(ncfg_confirm_resolve_on_startup(&state, NULL, &executor, &resolved, &event, err,
	        sizeof(err)) && resolved == 1,
	    "a window found at startup is resolved whether or not its deadline has passed");
	detail("if not", err);
	check(recorder_saw(&recorder, "link.set_mtu eth0 1500"),
	    "and the re-plan puts the machine back with no inverses to replay");
	check(event.kind == NCFG_PROTO_EVENT_CONFIRM_RESOLVED && event.confirmed == 0u,
	    "reporting it as a window nobody confirmed");

	ncfg_daemon_state_free(&state);
	ncfg_document_free(last_good);
}

/* ------------------------------------------------------------------------ *
 * The resolv guard
 * ------------------------------------------------------------------------ */

#define MACHINE_MAX 8

typedef struct {
	ncfg_process_ref_t candidates[MACHINE_MAX];
	size_t             candidate_count;
	/* More candidates than were written, for the overflow report. */
	size_t             candidate_total;
	pid_t              in_service[MACHINE_MAX];
	size_t             in_service_count;
	pid_t              elsewhere[MACHINE_MAX];
	size_t             elsewhere_count;
	pid_t              supervised[MACHINE_MAX];
	size_t             supervised_count;
	/* A pid whose `terminate` refuses, for the path that counts nothing. */
	pid_t              refuses;
	pid_t              terminated[MACHINE_MAX];
	size_t             terminated_count;
} machine_double_t;

static int holds(const pid_t *list, size_t count, pid_t pid)
{
	size_t at;

	for (at = 0; at < count; at++) {
		if (list[at] == pid) {
			return 1;
		}
	}
	return 0;
}

static size_t double_candidates(void *state, ncfg_process_ref_t *out, size_t out_max)
{
	machine_double_t *machine = state;
	size_t            at;

	for (at = 0; at < machine->candidate_count && at < out_max; at++) {
		out[at] = machine->candidates[at];
	}
	return machine->candidate_total ? machine->candidate_total : machine->candidate_count;
}

static int double_in_our_service(void *state, pid_t pid)
{
	machine_double_t *machine = state;

	return holds(machine->in_service, machine->in_service_count, pid);
}

static int double_shares_network_namespace(void *state, pid_t pid)
{
	machine_double_t *machine = state;

	return !holds(machine->elsewhere, machine->elsewhere_count, pid);
}

static int double_is_service_supervised(void *state, pid_t pid)
{
	machine_double_t *machine = state;

	return holds(machine->supervised, machine->supervised_count, pid);
}

static int double_terminate(void *state, pid_t pid, char *err, size_t err_size)
{
	machine_double_t *machine = state;

	if (machine->refuses == pid) {
		ncfg_error_set(err, err_size, "Operation not permitted");
		return 0;
	}
	if (machine->terminated_count < MACHINE_MAX) {
		machine->terminated[machine->terminated_count++] = pid;
	}
	return 1;
}

static void machine_add(machine_double_t *machine, pid_t pid, const char *program)
{
	ncfg_process_ref_t *ref;

	if (machine->candidate_count >= MACHINE_MAX) {
		return;
	}
	ref = &machine->candidates[machine->candidate_count++];
	memset(ref, 0, sizeof(*ref));
	ref->pid = pid;
	(void)snprintf(ref->program, sizeof(ref->program), "%s", program);
}

static ncfg_resolv_machine_t double_machine(machine_double_t *state)
{
	ncfg_resolv_machine_t machine;

	machine.state = state;
	machine.candidates = double_candidates;
	machine.in_our_service = double_in_our_service;
	machine.shares_network_namespace = double_shares_network_namespace;
	machine.is_service_supervised = double_is_service_supervised;
	machine.terminate = double_terminate;
	return machine;
}

/*
 * `/proc/<pid>/comm` is truncated to fifteen characters, so a name one
 * character too long never matches and the sweep reports nothing while looking
 * like it had looked -- the vacuous pass in its most literal form. Measured
 * against the buffer rather than spelled out here, so that a seventh name
 * added later cannot be silently too long.
 */
static void every_writer_name_is_one_proc_can_report(void)
{
	size_t             count = 0u;
	const char *const *names = ncfg_resolv_writers(&count);
	size_t             at;
	int                all_fit = 1;
	int                resolved_is_truncated = 0;

	check(count == 6u, "the writer list is the six programs the Rust names");
	for (at = 0; at < count; at++) {
		if (strlen(names[at]) >= NCFG_PROGRAM_MAX) {
			detail("too long for /proc/<pid>/comm", names[at]);
			all_fit = 0;
		}
		if (strcmp(names[at], "systemd-resolve") == 0) {
			resolved_is_truncated = 1;
		}
	}
	check(all_fit, "and every name in it fits what /proc/<pid>/comm reports");
	check(resolved_is_truncated,
	    "with systemd-resolved spelled the way the kernel truncates it");
	check(NCFG_RESOLV_PATIENCE == 3,
	    "three reclaims in a row before netcfgd stops merely rewriting");
}

static void the_pids_netcfgd_started_are_read_from_the_run_directory(const char *base)
{
	char   run[512];
	char   directory[640];
	char   path[800];
	pid_t  ours[8];
	size_t total;

	(void)testdir_in(base, "ours", run, sizeof(run));
	(void)snprintf(directory, sizeof(directory), "%s/dhcp", run);
	(void)mkdir(run, 0755);
	(void)mkdir(directory, 0755);
	(void)snprintf(path, sizeof(path), "%s/eth0.pid", directory);
	(void)testdir_write(path, "4242\n", 5u);
	(void)snprintf(path, sizeof(path), "%s/eth1.pid", directory);
	(void)testdir_write(path, "  4243  ", 8u);
	/* Not a pid file, and a pid file that is not a number. */
	(void)snprintf(path, sizeof(path), "%s/eth0.lease", directory);
	(void)testdir_write(path, "4244", 4u);
	(void)snprintf(path, sizeof(path), "%s/eth2.pid", directory);
	(void)testdir_write(path, "not a number", 12u);

	total = ncfg_resolv_ours(run, ours, sizeof(ours) / sizeof(ours[0]));
	check(total == 3u, "netcfgd's own pid and the two it recorded starting");
	check(holds(ours, total, (pid_t)getpid()),
	    "its own pid is in the set, so a rename can never make it kill itself");
	check(holds(ours, total, 4242) && holds(ours, total, 4243),
	    "and both pid files were read, whitespace and all");
	check(!holds(ours, total, 4244),
	    "a file that is not a pid file is not read, whatever is in it");
	check(ncfg_resolv_ours(NULL, ours, sizeof(ours) / sizeof(ours[0])) == 1u,
	    "and a run directory that is not there still answers netcfgd's own pid");
}

static void the_sweep_leaves_alone_everything_it_should(const char *base)
{
	char                  run[512];
	char                  directory[640];
	char                  path[800];
	machine_double_t      state;
	ncfg_resolv_machine_t machine;
	size_t                signalled;

	(void)testdir_in(base, "sweep", run, sizeof(run));
	(void)snprintf(directory, sizeof(directory), "%s/dhcp", run);
	(void)mkdir(run, 0755);
	(void)mkdir(directory, 0755);
	(void)snprintf(path, sizeof(path), "%s/wan0.pid", directory);
	(void)testdir_write(path, "4242", 4u);

	memset(&state, 0, sizeof(state));
	machine_add(&state, 4242, "dhcpcd");           /* netcfgd recorded starting it */
	machine_add(&state, 4243, "dhcpcd");           /* netcfgd's own, by cgroup */
	machine_add(&state, 4244, "dhclient");         /* another namespace */
	machine_add(&state, 4245, "systemd-resolve");  /* another service manager's */
	machine_add(&state, 4246, "NetworkManager");   /* nothing exempts it */
	state.in_service[state.in_service_count++] = 4243;
	state.elsewhere[state.elsewhere_count++] = 4244;
	state.supervised[state.supervised_count++] = 4245;
	machine = double_machine(&state);

	signalled = ncfg_resolv_sweep(run, &machine);
	check(signalled == 1u, "one of five candidates is signalled and the count says so");
	check(state.terminated_count == 1u && state.terminated[0] == 4246,
	    "and it is the one nothing exempts");
	check(!holds(state.terminated, state.terminated_count, 4242),
	    "a process netcfgd recorded starting is left alone");
	check(!holds(state.terminated, state.terminated_count, 4243),
	    "so is one in netcfgd's own service, which is how its children with no pid file "
	    "are found");
	check(!holds(state.terminated, state.terminated_count, 4244),
	    "so is one in another network namespace, which configures nothing here");
	check(!holds(state.terminated, state.terminated_count, 4245),
	    "and a service another manager restarts is reported rather than signalled");
}

static void a_sweep_that_signals_nothing_says_so(const char *base)
{
	char                  run[512];
	machine_double_t      state;
	ncfg_resolv_machine_t machine;

	(void)testdir_in(base, "quiet", run, sizeof(run));
	memset(&state, 0, sizeof(state));
	machine = double_machine(&state);
	check(ncfg_resolv_sweep(run, &machine) == 0u,
	    "a sweep that finds nothing to signal answers none");

	machine_add(&state, 5000, "dhclient");
	state.refuses = 5000;
	check(ncfg_resolv_sweep(run, &machine) == 0u && state.terminated_count == 0u,
	    "and a process that could not be signalled is not counted as one that was");

	check(ncfg_resolv_sweep(run, NULL) == 0u,
	    "a sweep with no machine to ask signals nobody");
	{
		ncfg_resolv_machine_t half = double_machine(&state);

		half.terminate = NULL;
		check(ncfg_resolv_sweep(run, &half) == 0u,
		    "and neither does one whose machine is missing a call");
	}
}

/* ------------------------------------------------------------------------ *
 * main
 * ------------------------------------------------------------------------ */

int main(void)
{
	const char *base = testdir_make("confirm");

	a_degenerate_run_directory_does_not_escape();
	a_window_round_trips_through_the_file(base);
	the_window_is_written_outside_the_runtime_directory(base);
	a_window_file_something_else_wrote_is_refused(base);
	clearing_an_absent_window_is_not_an_error(base);
	a_last_good_document_round_trips(base);
	the_hash_follows_the_document_not_the_compile();

	a_window_that_has_passed_reports_expired();
	a_window_does_not_survive_the_machine_sleeping_through_it();
	moving_the_clock_moves_an_open_window();

	only_done_actions_with_an_inverse_are_undone();
	the_inverses_are_replayed_newest_first();
	what_a_window_covers_outlives_the_document_it_came_from();

	a_window_is_refused_where_there_is_nothing_to_go_back_to(base);
	arming_writes_the_window_and_says_so(base);
	a_window_that_cannot_be_written_is_refused(base);
	keeping_the_change_closes_the_window(base);
	reverting_needs_a_window_and_a_document(base);
	a_revert_puts_the_machine_and_the_document_back(base);
	a_failed_inverse_does_not_stop_the_revert(base);
	the_replan_is_the_safety_net_where_the_inverses_are_gone(base);

	every_writer_name_is_one_proc_can_report();
	the_pids_netcfgd_started_are_read_from_the_run_directory(base);
	the_sweep_leaves_alone_everything_it_should(base);
	a_sweep_that_signals_nothing_says_so(base);

	testdir_remove(base);
	printf("confirm_test: %d check(s)\n", checks);
	if (failures == 0) {
		printf("confirm_test: all checks passed\n");
	} else {
		printf("confirm_test: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
