/*
 * cli_apply_test.c -- `ncfg apply`, driven through a recorder.
 *
 * WHY THIS IS SAFE TO RUN ON THE MACHINE THAT BUILT IT
 *   `cli.h`'s machine seam is the whole of how this command reaches a kernel,
 *   a hostname or a resolver, and every case here installs a recorder in its
 *   place. That is a property of the arrangement rather than of the fixtures:
 *   `ncfg_cli_main` installs no machine at all, so a case that forgot to pass
 *   one would get the refusal `cli_test.c` asserts instead of an apply. The
 *   only way to reach a real executor from this binary is to write one, and
 *   nothing here does.
 *
 *   The suite is built and run on a workstation whose network is managed by
 *   the daemon this is a port of. That is the machine an `ncfg apply` with the
 *   seam `src/main/` installs would reconfigure, which is why the seam exists.
 *
 * WHAT IS DRIVEN, AND WHY FROM `argv`
 *   The path being checked is the operator's -- compile, observe, plan, act,
 *   record, report, exit -- and half of what it is worth checking is the
 *   wiring between those steps: that the plan is what gets carried out, that
 *   the seam is handed the directories this invocation was pointed at, that
 *   the record is written before the exit status is decided. A test that
 *   called `ncfg_apply` directly would check the part that `apply_test.c`
 *   already checks and none of that.
 *
 * WHERE THE DETERMINISM COMES FROM
 *   The observation is this machine's: `ncfg apply` observes through netlink
 *   and there is no seam for it, so every fixture here is written so that its
 *   plan does not depend on what this machine has.
 *
 *   `hostname.set` is planned because the document names a hostname no machine
 *   is called, and `dns.apply` because the observed DNS delivery is read from
 *   `owned.json` under the run directory -- which is this test's own, and
 *   empty. An interface fixture would not have that property, so there is not
 *   one: `interface ncfgt0` is here precisely *because* no such device exists,
 *   and what it checks is that a plan with nothing in it opens nothing.
 */
#include "ncfg/cli.h"

#include "ncfg/apply.h"
#include "ncfg/base.h"
#include "ncfg/plan.h"

#include "testdir.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int failures;

static void check(int condition, const char *what)
{
	printf("%-72s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

static void detail(const char *label, const char *text)
{
	printf("       %s: %s\n", label, text ? text : "(none)");
}

/* Whole-line, for `cli_test.c`'s reason: a substring match passes on a line
 * that has grown a column or lost one. */
static int has_line(const char *text, const char *wanted)
{
	size_t      length = strlen(wanted);
	const char *at = text;

	while (at && *at) {
		const char *end = strchr(at, '\n');
		size_t      run = end ? (size_t)(end - at) : strlen(at);

		if (run == length && memcmp(at, wanted, length) == 0) {
			return 1;
		}
		if (!end) {
			return 0;
		}
		at = end + 1;
	}
	return 0;
}

static void line(const char *text, const char *wanted, const char *what)
{
	int found = has_line(text, wanted);

	check(found, what);
	if (!found) {
		detail("wanted", wanted);
		detail("got", text);
	}
}

/*
 * The same, for a line whose tail is this machine's and not this test's.
 *
 * `hostname.set` reads `(was <whatever this host is called>)`, and an
 * assertion carrying the hostname of the workstation it was written on is one
 * that fails everywhere else. The prefix is the whole of what the port decides;
 * the tail is the observation's.
 */
static int has_line_starting(const char *text, const char *wanted)
{
	size_t      length = strlen(wanted);
	const char *at = text;

	while (at && *at) {
		const char *end = strchr(at, '\n');
		size_t      run = end ? (size_t)(end - at) : strlen(at);

		if (run >= length && memcmp(at, wanted, length) == 0) {
			return 1;
		}
		if (!end) {
			return 0;
		}
		at = end + 1;
	}
	return 0;
}

static void line_starting(const char *text, const char *wanted, const char *what)
{
	int found = has_line_starting(text, wanted);

	check(found, what);
	if (!found) {
		detail("wanted a line starting", wanted);
		detail("got", text);
	}
}

static void no_line(const char *text, const char *unwanted, const char *what)
{
	int found = has_line(text, unwanted);

	check(!found, what);
	if (found) {
		detail("unwanted", unwanted);
	}
}

static void no_line_starting(const char *text, const char *unwanted, const char *what)
{
	int found = has_line_starting(text, unwanted);

	check(!found, what);
	if (found) {
		detail("unwanted a line starting", unwanted);
		detail("got", text);
	}
}

/* ------------------------------------------------------------------------ *
 * The recorder, in the machine's place
 * ------------------------------------------------------------------------ *
 *
 * `apply_test.c`'s recorder keeps a rendering of every operation because the
 * subject there is what the executor does with one. The subject here is the
 * command, so this one keeps the names in order and the two counts that say
 * whether the seam was opened and given back.
 */

#define RECORDED_MAX 16u

static struct {
	char   ops[RECORDED_MAX][64];
	size_t count;
	int    overflowed;
	int    opened;
	int    closed;
	/* What the double was told to do before it was asked anything. */
	int         refuse_open;
	const char *fail_at;
	/* What the command handed over, kept so a case can compare it with what
	 * the command line said. */
	char config_dir[512];
	char run_dir[512];
} recorder;

static int recorded_execute(void *state, const ncfg_op_t *op, char *err, size_t err_size)
{
	const char *name = ncfg_op_name(op);

	(void)state;
	if (recorder.count >= RECORDED_MAX) {
		recorder.overflowed = 1;
		ncfg_error_set(err, err_size, "the recorder has no room left");
		return 0;
	}
	(void)snprintf(recorder.ops[recorder.count], sizeof(recorder.ops[0]), "%s",
	    name ? name : "(unnamed)");
	recorder.count++;
	if (recorder.fail_at && name && strcmp(name, recorder.fail_at) == 0) {
		ncfg_error_set(err, err_size, "the double was told to fail here");
		return 0;
	}
	return 1;
}

static int recorded_open(void *context, const char *config_dir, const char *run_dir,
    const ncfg_document_t *desired, const ncfg_observed_t *observed, ncfg_executor_t *out,
    char *err, size_t err_size)
{
	(void)context;
	if (recorder.refuse_open) {
		ncfg_error_set(err, err_size, "the double was told not to open");
		return 0;
	}
	/* The pair the real seam builds an executor from. Asserted present rather
	 * than inspected: a seam handed a null document would resolve credentials
	 * against nothing, and the failure would be a blank secret rather than a
	 * crash. */
	if (!desired || !observed) {
		ncfg_error_set(err, err_size, "the command opened the seam with no subject");
		return 0;
	}
	(void)snprintf(recorder.config_dir, sizeof(recorder.config_dir), "%s",
	    config_dir ? config_dir : "");
	(void)snprintf(recorder.run_dir, sizeof(recorder.run_dir), "%s", run_dir ? run_dir : "");
	recorder.opened++;
	out->state = NULL;
	out->execute = recorded_execute;
	return 1;
}

static void recorded_close(void *context, ncfg_executor_t *executor)
{
	(void)context;
	(void)executor;
	recorder.closed++;
}

static const ncfg_cli_machine_t recording_machine = { NULL, recorded_open, recorded_close };

/* The names it saw, joined, so a whole sequence is one assertion. */
static void sequence_is(const char *wanted, const char *what)
{
	char   got[512];
	size_t at;
	size_t used = 0;

	got[0] = '\0';
	for (at = 0; at < recorder.count; at++) {
		int written = snprintf(got + used, sizeof(got) - used, "%s%s", used ? ", " : "",
		    recorder.ops[at]);

		if (written < 0 || (size_t)written >= sizeof(got) - used) {
			break;
		}
		used += (size_t)written;
	}
	check(!recorder.overflowed && strcmp(got, wanted) == 0, what);
	if (recorder.overflowed || strcmp(got, wanted) != 0) {
		detail("wanted", wanted);
		detail("got", got);
	}
}

/* ------------------------------------------------------------------------ *
 * A run of the command
 * ------------------------------------------------------------------------ */

static const char *base;

static int   saved_stdout = -1;
static int   saved_stderr = -1;
static char  capture_file[320];
static char  complaint_file[320];
static char *captured;
static char *complained;

/* The whole of a file this test wrote, or the empty string. */
static char *slurp(const char *path)
{
	char *body = testdir_read(path, NULL);

	return body ? body : NULL;
}

static int redirect(int stream, const char *path)
{
	int saved = dup(stream);
	int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);

	if (saved < 0 || fd < 0) {
		printf("could not redirect a stream to %s\n", path);
		exit(1);
	}
	(void)dup2(fd, stream);
	(void)close(fd);
	return saved;
}

static void restore(int stream, int saved)
{
	(void)dup2(saved, stream);
	(void)close(saved);
}

/*
 * One `ncfg apply`, with the recorder wound back and both streams read.
 *
 * Both streams, because the command divides its answer between them: the
 * journal and the plan's notes go to stdout through `out.c`, and every
 * diagnostic goes straight to stderr (0261). A case that read one of them
 * would be asserting half the output and would not see the other half go
 * missing.
 */
static int ran(char **argv, int argc, const ncfg_cli_machine_t *machine, const char **said,
    const char **complaint)
{
	int code;

	recorder.count = 0;
	recorder.overflowed = 0;
	recorder.opened = 0;
	recorder.closed = 0;
	recorder.config_dir[0] = '\0';
	recorder.run_dir[0] = '\0';

	(void)fflush(stdout);
	(void)fflush(stderr);
	saved_stdout = redirect(STDOUT_FILENO, capture_file);
	saved_stderr = redirect(STDERR_FILENO, complaint_file);
	code = ncfg_cli_main_on(argc, argv, machine);
	(void)fflush(stdout);
	(void)fflush(stderr);
	restore(STDOUT_FILENO, saved_stdout);
	restore(STDERR_FILENO, saved_stderr);
	saved_stdout = -1;
	saved_stderr = -1;

	free(captured);
	free(complained);
	captured = slurp(capture_file);
	complained = slurp(complaint_file);
	*said = captured ? captured : "";
	*complaint = complained ? complained : "";
	return code;
}

/* ------------------------------------------------------------------------ *
 * Fixtures
 * ------------------------------------------------------------------------ */

/*
 * Two directories of this case's own and a configuration in one of them.
 *
 * Per case rather than shared, and that is load-bearing: an apply folds what
 * it did into `owned.json` under the run directory, and the next observation
 * reads it. Two cases sharing one run directory would have the second planning
 * against what the first recorded, which is a real behaviour worth a check of
 * its own and a trap underneath every other check here.
 */
static void fixture(const char *name, const char *text, char *config_out, size_t config_size,
    char *run_out, size_t run_size)
{
	char path[1024];

	(void)snprintf(config_out, config_size, "%s/%s/config", base, name);
	(void)snprintf(run_out, run_size, "%s/%s/run", base, name);
	testdir_mkdirp(config_out);
	testdir_mkdirp(run_out);
	(void)snprintf(path, sizeof(path), "%s/netcfgd.conf", config_out);
	if (!testdir_write(path, text, strlen(text))) {
		printf("could not write the configuration for %s\n", name);
		exit(1);
	}
}

/* A document whose plan is two actions, neither of which needs a device: a
 * hostname nothing is called, and a delivery no empty run directory has a
 * record of. */
static const char *const TWO_ACTIONS =
    "global {\n"
    "\thostname = \"netcfgd-c-port-fixture\"\n"
    "\tdns {\n"
    "\t\tmode    = \"write_resolv_conf\"\n"
    "\t\tservers = [\"10.77.0.53\"]\n"
    "\t}\n"
    "}\n";

/* A document whose plan is empty on every machine, because the interface it
 * configures is one no machine has. */
static const char *const NO_ACTIONS =
    "interface ncfgt0 {\n"
    "\tconfig = \"10.77.0.2/24\"\n"
    "}\n";

static int left_behind(const char *run_dir, const char *leaf)
{
	char path[1024];

	(void)snprintf(path, sizeof(path), "%s/%s", run_dir, leaf);
	return testdir_exists(path);
}

/* One of the files an apply leaves under the run directory, or NULL. The
 * caller frees it. */
static char *run_file(const char *run_dir, const char *leaf)
{
	char path[1024];

	(void)snprintf(path, sizeof(path), "%s/%s", run_dir, leaf);
	return slurp(path);
}

/* ------------------------------------------------------------------------ *
 * The cases
 * ------------------------------------------------------------------------ */

/*
 * Nothing to do reaches nothing.
 *
 * The check that matters is `opened`: an apply on a converged machine is the
 * ordinary case, and taking the apply lock and opening three netlink sockets
 * to discover there is no work is both slower and a chance to fail where there
 * was none.
 */
static void an_empty_plan_opens_nothing(void)
{
	char        config_dir[600];
	char        run_dir[600];
	char       *argv[6];
	const char *said;
	const char *complaint;
	int         code;

	fixture("empty", NO_ACTIONS, config_dir, sizeof(config_dir), run_dir, sizeof(run_dir));
	argv[0] = (char *)"ncfg";
	argv[1] = (char *)"apply";
	argv[2] = (char *)"--config-dir";
	argv[3] = config_dir;
	argv[4] = (char *)"--run-dir";
	argv[5] = run_dir;
	code = ran(argv, 6, &recording_machine, &said, &complaint);

	check(code == NCFG_CLI_EXIT_OK, "an empty plan leaves with 0");
	line(said, "nothing to do", "an empty plan says so");
	check(recorder.opened == 0, "an empty plan never opens the machine");
	check(recorder.count == 0, "an empty plan carries nothing out");
	check(!left_behind(run_dir, "plan.last.json"),
	    "an empty plan writes no journal of the last apply");
	/* The observation and the document are written anyway, because `ncfg
	 * status` reads them and an apply that found nothing to do still saw. */
	check(left_behind(run_dir, "observed"), "an empty plan still writes what it observed");
}

/*
 * A plan is carried out, in order, through the seam.
 */
static void a_plan_is_carried_out(void)
{
	char        config_dir[600];
	char        run_dir[600];
	char       *argv[6];
	const char *said;
	const char *complaint;
	char       *owned;
	int         code;

	fixture("carried", TWO_ACTIONS, config_dir, sizeof(config_dir), run_dir, sizeof(run_dir));
	argv[0] = (char *)"ncfg";
	argv[1] = (char *)"apply";
	argv[2] = (char *)"--config-dir";
	argv[3] = config_dir;
	argv[4] = (char *)"--run-dir";
	argv[5] = run_dir;
	code = ran(argv, 6, &recording_machine, &said, &complaint);

	check(code == NCFG_CLI_EXIT_OK, "an apply that worked leaves with 0");
	sequence_is("dns.apply, hostname.set", "every action reached the machine, in the plan's order");
	check(recorder.opened == 1, "the machine was opened once");
	check(recorder.closed == 1, "and given back once");
	line(said, "ok   dns.apply  dns: write_resolv_conf (was <absent>)",
	    "the journal names the delivery it made");
	line_starting(said, "ok   hostname.set  globals.hostname: netcfgd-c-port-fixture (was ",
	    "the journal names the hostname it set");

	/* Where the seam was pointed. `--config-dir` is the whole of how somebody
	 * points an apply at a tree that is not the machine's, and the executor
	 * resolves credentials under it; a seam left to answer for itself would
	 * read `/etc/netcfgd/secrets` on a run that named neither. */
	check(strcmp(recorder.config_dir, config_dir) == 0,
	    "the seam was given the configuration directory this run named");
	check(strcmp(recorder.run_dir, run_dir) == 0,
	    "the seam was given the run directory this run named");

	check(left_behind(run_dir, "plan.last.json"), "the last apply left a journal behind");
	owned = run_file(run_dir, "owned.json");
	check(owned != NULL, "and folded what it did into owned.json");
	if (owned) {
		check(strstr(owned, "10.77.0.53") != NULL,
		    "the fold records the servers the delivery carried");
		free(owned);
	}
}

/*
 * An action that failed stops the apply, and is still recorded.
 *
 * The three things that have to happen together: the rest of the plan is not
 * attempted, the seam is given back anyway, and what did happen is on disk
 * before the exit status is decided. The last one is the one that matters when
 * it goes wrong for real -- an apply that changed two things and then crashed
 * without folding them into `owned.json` leaves netcfgd owning state it has no
 * record of, which is the class of bug `owned.json` exists to prevent.
 */
static void a_failing_action_stops_the_apply(void)
{
	char        config_dir[600];
	char        run_dir[600];
	char       *argv[6];
	const char *said;
	const char *complaint;
	char       *journal;
	int         code;

	fixture("failed", TWO_ACTIONS, config_dir, sizeof(config_dir), run_dir, sizeof(run_dir));
	argv[0] = (char *)"ncfg";
	argv[1] = (char *)"apply";
	argv[2] = (char *)"--config-dir";
	argv[3] = config_dir;
	argv[4] = (char *)"--run-dir";
	argv[5] = run_dir;

	recorder.fail_at = "dns.apply";
	code = ran(argv, 6, &recording_machine, &said, &complaint);
	recorder.fail_at = NULL;

	check(code == NCFG_CLI_EXIT_FAILED, "an apply that failed leaves with 1");
	sequence_is("dns.apply", "the action after the failure was not attempted");
	check(recorder.closed == 1, "the machine is given back even when an action failed");
	line(said, "FAIL dns.apply  dns: write_resolv_conf (was <absent>)",
	    "the journal marks the action that failed");
	line(said, "     the double was told to fail here",
	    "and prints the sentence the executor gave for it");
	line_starting(said, "skip hostname.set  globals.hostname: netcfgd-c-port-fixture (was ",
	    "and marks what it did not attempt");
	line(complaint, "ncfg: stopped at action 0 (dns.apply); 0 done, 1 not attempted",
	    "the diagnostic counts what happened");
	line(complaint, "ncfg: re-run `ncfg apply` to resume from current state",
	    "and says what to do about it");

	journal = run_file(run_dir, "plan.last.json");
	check(journal != NULL, "the failure is written to plan.last.json");
	if (journal) {
		check(strstr(journal, "the double was told to fail here") != NULL,
		    "and the journal on disk carries the reason");
		free(journal);
	}
}

/*
 * `--json` answers with the journal and nothing else.
 *
 * Both halves are the check. The journal has to be there, and the two
 * sentences the plain form prints -- the per-action lines and the diagnostic
 * about resuming -- have to be absent: a `--json` run is something a script
 * parses, and a line of prose on either stream is what breaks it. `command_plan`
 * makes the same decision about the notes under a plan, for the same reason.
 *
 * **The stderr half is what this command prints, not everything on the
 * stream.** It read `complaint[0] == '\0'` until the suite was first run by
 * somebody who was not root, and an ordinary user's observation pass warns:
 * the nftables dump and every WireGuard device come back EPERM without
 * CAP_NET_ADMIN, and the library says so. Those warnings carry `netcfgd: `,
 * this command's own prose carries `ncfg: `, and it is the second that `--json`
 * owes a script silence on. Asserting the whole stream empty asserted a
 * property of whoever ran the suite.
 */
/*
 * An apply puts the hook bodies on disk; a read-only verb does not.
 *
 * **`hooks.h` states the rule and nothing obeyed it.** "A caller that compiles
 * to read the configuration has a document that names them and no reason to
 * put them on disk; the one that runs them does." Every verb took the writing
 * sink and no verb ever called `ncfg_pending_hooks_write`, so `ncfg apply`
 * planned `hook.run` against a path in `<run>/hooks/` that nothing had
 * created. What the operator saw was `cannot read ...: No such file or
 * directory` and a `pre_up` that never ran -- and `plan` said nothing, because
 * a plan is right about what it intends.
 *
 * Both halves are asserted, because writing them from every verb would also
 * make this pass: `ncfg plan` must leave no `hooks/` behind at all, which is
 * what "the directory is created only when there is something to put in it"
 * means for a machine that is only being asked questions.
 */
static void an_apply_materialises_the_hook_bodies(void)
{
	static const char *const WITH_HOOK =
	    "interface eth0 {\n\tconfig = \"null\"\n\tpre_up {\n\techo ran\n\t}\n}\n";
	char  config_dir[600];
	char  run_dir[600];
	char  path[1024];
	char *argv[6];
	const char *said;
	const char *complaint;
	char *body;

	fixture("hookbody", WITH_HOOK, config_dir, sizeof(config_dir), run_dir, sizeof(run_dir));
	argv[0] = (char *)"ncfg";
	argv[1] = (char *)"plan";
	argv[2] = (char *)"--config-dir";
	argv[3] = config_dir;
	argv[4] = (char *)"--run-dir";
	argv[5] = run_dir;
	(void)ran(argv, 6, &recording_machine, &said, &complaint);
	(void)snprintf(path, sizeof(path), "%s/hooks/eth0.pre_up.0", run_dir);
	body = testdir_read(path, NULL);
	check(body == NULL, "`ncfg plan` writes no hook body, having nothing to run");
	free(body);

	argv[1] = (char *)"apply";
	(void)ran(argv, 6, &recording_machine, &said, &complaint);
	body = testdir_read(path, NULL);
	check(body != NULL, "`ncfg apply` writes the body the plan points `hook.run` at");
	check(body && strstr(body, "echo ran") != NULL,
	    "  holding the script the operator wrote");
	free(body);
}

static void json_answers_with_the_journal_alone(void)
{
	char        config_dir[600];
	char        run_dir[600];
	char       *argv[7];
	const char *said;
	const char *complaint;
	int         code;

	fixture("json", TWO_ACTIONS, config_dir, sizeof(config_dir), run_dir, sizeof(run_dir));
	argv[0] = (char *)"ncfg";
	argv[1] = (char *)"apply";
	argv[2] = (char *)"--config-dir";
	argv[3] = config_dir;
	argv[4] = (char *)"--run-dir";
	argv[5] = run_dir;
	argv[6] = (char *)"--json";

	recorder.fail_at = "hostname.set";
	code = ran(argv, 7, &recording_machine, &said, &complaint);
	recorder.fail_at = NULL;

	check(code == NCFG_CLI_EXIT_FAILED, "a `--json` apply that failed still leaves with 1");
	check(said[0] == '{', "the answer is a JSON object and starts as one");
	check(strstr(said, "\"dns.apply\"") != NULL, "which carries the action that ran");
	check(strstr(said, "the double was told to fail here") != NULL,
	    "and the sentence the failure came with");
	no_line(said, "ok   dns.apply  dns: write_resolv_conf (was <absent>)",
	    "a `--json` apply prints no journal lines beside it");
	no_line_starting(complaint, "ncfg: ",
	    "and says nothing of its own on stderr, about resuming or anything else");
}

/*
 * A machine that will not open changes nothing and says why.
 *
 * The apply lock is the thing behind this in a real build: a second `ncfg
 * apply` finds it held and is refused, and what an operator gets has to be the
 * reason rather than a plan half carried out.
 */
static void a_machine_that_will_not_open_changes_nothing(void)
{
	char        config_dir[600];
	char        run_dir[600];
	char       *argv[6];
	const char *said;
	const char *complaint;
	int         code;

	fixture("refused", TWO_ACTIONS, config_dir, sizeof(config_dir), run_dir, sizeof(run_dir));
	argv[0] = (char *)"ncfg";
	argv[1] = (char *)"apply";
	argv[2] = (char *)"--config-dir";
	argv[3] = config_dir;
	argv[4] = (char *)"--run-dir";
	argv[5] = run_dir;

	recorder.refuse_open = 1;
	code = ran(argv, 6, &recording_machine, &said, &complaint);
	recorder.refuse_open = 0;

	check(code == NCFG_CLI_EXIT_FAILED, "an apply that could not start leaves with 1");
	check(recorder.count == 0, "and carries nothing out");
	line(complaint, "ncfg: cannot start an apply: the double was told not to open",
	    "the refusal is passed through with what it said");
	check(!left_behind(run_dir, "plan.last.json"),
	    "an apply that never started writes no journal");
	check(!left_behind(run_dir, "owned.json"), "and folds nothing into the record");
}

/*
 * `--confirm-within` is the daemon's apply, not this one's.
 *
 * A confirm window is a timer that has to outlive the command, so the work
 * belongs to the process that stays. What is checked here is the handover: the
 * seam is not opened at all, whatever happens to the conversation afterwards.
 * There is no daemon under this test's run directory, so the conversation
 * fails -- which is the point of running it here rather than on a machine with
 * one.
 */
static void a_confirm_window_never_opens_the_machine(void)
{
	char        config_dir[600];
	char        run_dir[600];
	char       *argv[8];
	const char *said;
	const char *complaint;
	int         code;

	fixture("confirm", TWO_ACTIONS, config_dir, sizeof(config_dir), run_dir, sizeof(run_dir));
	argv[0] = (char *)"ncfg";
	argv[1] = (char *)"apply";
	argv[2] = (char *)"--config-dir";
	argv[3] = config_dir;
	argv[4] = (char *)"--run-dir";
	argv[5] = run_dir;
	argv[6] = (char *)"--confirm-within";
	argv[7] = (char *)"90";
	code = ran(argv, 8, &recording_machine, &said, &complaint);

	check(code == NCFG_CLI_EXIT_FAILED, "with no daemon to ask, it leaves with 1");
	check(recorder.opened == 0, "a confirm window never opens the machine here");
	check(recorder.count == 0, "and carries nothing out here");
	check(complaint[0] != '\0', "and says what went wrong with the conversation");
	check(!left_behind(run_dir, "plan.last.json"),
	    "the local apply path was not taken at all");
}

/*
 * The seam is the only way in, and this binary's default has none.
 *
 * `cli_test.c` asserts the sentence; what is asserted here is the consequence,
 * against the same fixture every other case in this file applies successfully.
 * Together they are the safety property this file rests on: the plan is real,
 * the machine would have been reached, and `ncfg_cli_main` does not reach it.
 */
static void the_default_program_applies_nothing(void)
{
	char        config_dir[600];
	char        run_dir[600];
	char       *argv[6];
	const char *said;
	const char *complaint;
	int         code;

	fixture("unwired", TWO_ACTIONS, config_dir, sizeof(config_dir), run_dir, sizeof(run_dir));
	argv[0] = (char *)"ncfg";
	argv[1] = (char *)"apply";
	argv[2] = (char *)"--config-dir";
	argv[3] = config_dir;
	argv[4] = (char *)"--run-dir";
	argv[5] = run_dir;
	code = ran(argv, 6, NULL, &said, &complaint);

	check(code == NCFG_CLI_EXIT_FAILED, "an apply with no machine leaves with 1");
	check(recorder.opened == 0, "and does not reach the recorder either");
	check(strstr(complaint, "no way to reach the ") != NULL,
	    "and says that this build was started without one");
	check(!left_behind(run_dir, "observed"),
	    "it refuses before it observes, so it writes nothing at all");
}

int main(void)
{
	base = testdir_make("cli-apply");
	(void)snprintf(capture_file, sizeof(capture_file), "%s/stdout", base);
	(void)snprintf(complaint_file, sizeof(complaint_file), "%s/stderr", base);

	an_empty_plan_opens_nothing();
	a_plan_is_carried_out();
	a_failing_action_stops_the_apply();
	an_apply_materialises_the_hook_bodies();
	json_answers_with_the_journal_alone();
	a_machine_that_will_not_open_changes_nothing();
	a_confirm_window_never_opens_the_machine();
	the_default_program_applies_nothing();

	free(captured);
	free(complained);
	testdir_remove(base);
	if (failures == 0) {
		printf("cli_apply_test: all checks passed\n");
	} else {
		printf("cli_apply_test: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
