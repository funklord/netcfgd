/*
 * probe_test.c -- the verdicts, the hysteresis, and the programs they run.
 *
 * EVERY PROGRAM THIS FILE RUNS IS ONE IT WROTE
 *   `testdir.h` makes a directory with `mkdtemp`, every script below is
 *   written into it by the case that runs it, and the directory goes at the
 *   end. Nothing here names a program on the machine, nothing reads
 *   `/etc/netcfgd` and nothing writes under `/run`: the real netcfgd is the
 *   network daemon of the machine these tests are built on.
 *
 *   Each script is a handful of lines with a bounded loop or none at all, and
 *   every one of them is spawned through `ncfg_probes_run_due`, which gives it
 *   a deadline from the configuration, kills its whole process group when the
 *   deadline passes and reaps it before returning. The one case that runs a
 *   program which would outlive its probe asserts, afterwards, that it did not:
 *   see `a_probe_that_hangs_is_killed_along_with_what_it_started`.
 *
 * WHY THE CLOCK IS DRIVEN RATHER THAN WAITED FOR
 *   `interval` is in seconds and the compiler refuses zero, so the Rust's
 *   dwell tests sleep 1050ms six times, twice -- twelve seconds of a suite, and
 *   its own comments record one of them flaking. `ncfg_probes_clock` is a seam
 *   for exactly this: the cases below move a counter and the hysteresis is
 *   measured rather than waited for, which is why they can assert an exact
 *   number of verdict changes where the Rust asserts `>= 4` and `<= 1`.
 *
 *   The seam is the *scheduling* clock only. The two cases that are about a
 *   running program -- the timeout and the chatty one -- use the real clock,
 *   because a frozen clock against a live child is a wait that never ends.
 *
 * WHICH HOOK SINK, AND WHY IT IS THE SAME ONE EVERYWHERE HERE
 *   **Every compile in this file is a compile to read.** Each one turns
 *   configuration text into a document so that this module can be driven by it;
 *   none of them is going to act on the hooks, and none has anywhere to put a
 *   script. So every one passes `ncfg_hook_sink_unwritten()`.
 *
 *   The Rust's own `probe.rs` tests reach for `NoHooks` --
 *   `ncfg_hook_sink_refusing()` here -- at three sites, and 0258 leaves them
 *   alone on the grounds that their fixtures carry no hooks. That is true of
 *   the fixtures and not of the question: a fixture that gains a hook later
 *   would start failing in a test about probes, with a message about hooks. So
 *   these sites answer the question they are actually asking, and
 *   `a_fixture_that_carries_a_hook_still_compiles_to_be_read` is the case that
 *   makes the difference visible rather than theoretical.
 */
#include "ncfg/base.h"
#include "ncfg/daemon.h"
#include "ncfg/hooks.h"
#include "ncfg/lower.h"
#include "ncfg/observed.h"
#include "ncfg/parse.h"

#include "testdir.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
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

/* ------------------------------------------------------------- the clock */

/*
 * The scheduling clock the cases drive, in milliseconds.
 *
 * A file-static counter rather than something passed through the context,
 * because every case here runs one probe set at a time and a context pointer
 * would be a parameter nobody varies.
 */
static int64_t fake_now;

static int64_t fake_clock(void *context)
{
	(void)context;
	return fake_now;
}

/* ---------------------------------------------------------- the fixtures */

/* Write a script and make it executable. Returns its path in `out`. */
static const char *script(const char *base, const char *leaf, const char *body, char *out,
    size_t out_size)
{
	(void)testdir_in(base, leaf, out, out_size);
	if (!testdir_write(out, body, strlen(body)) || chmod(out, 0755) != 0) {
		printf("could not write the script %s\n", out);
		exit(1);
	}
	return out;
}

/*
 * The document this text compiles to, read rather than acted on.
 *
 * `ncfg_hook_sink_unwritten()`: see the header comment. The question every
 * caller here asks is "what does this configuration say", never "put the
 * scripts somewhere and give me a document to apply".
 */
static ncfg_document_t *compiled(const char *text)
{
	ncfg_ast_file_t *file = NULL;
	ncfg_source_t    source;
	ncfg_document_t *document;
	char             err[NCFG_ERROR_MAX];

	if (!ncfg_parse(text, strlen(text), &file, NULL, err, sizeof(err))) {
		printf("the fixture did not parse: %s\n%s", err, text);
		exit(1);
	}
	source.name = "netcfgd.conf";
	source.file = file;
	document = ncfg_compile(&source, 1u, ncfg_hook_sink_unwritten(), NULL, err, sizeof(err));
	ncfg_ast_file_free(file);
	if (!document) {
		printf("the fixture did not compile: %s\n%s", err, text);
		exit(1);
	}
	return document;
}

/* One interface with a probe, spelled out so every case can vary the parts it
 * is about. `extra` is dropped in beside the fixed keys. */
static ncfg_document_t *with_probe(const char *command, int64_t timeout, int64_t hold_down,
    const char *extra)
{
	char text[2048];

	(void)snprintf(text, sizeof(text),
	    "interface eth0 {\n"
	    "\tpreference = 10\n"
	    "\tprobe {\n"
	    "\t\tcommand = \"%s\"\n"
	    "\t\tinterval = 1\n"
	    "\t\ttimeout = %lld\n"
	    "\t\tdown_after = 1\n"
	    "\t\tup_after = 1\n"
	    "\t\thold_down = %lld\n"
	    "%s"
	    "\t}\n"
	    "}\n",
	    command, (long long)timeout, (long long)hold_down, extra ? extra : "");
	return compiled(text);
}

/* An interface that asks for DHCP, which is what the lease precondition is
 * about. */
static ncfg_document_t *dhcp_with_probe(const char *command, int require_lease)
{
	char text[2048];

	(void)snprintf(text, sizeof(text),
	    "interface eth0 {\n"
	    "\tconfig = \"dhcp\"\n"
	    "\tprobe {\n"
	    "\t\tcommand = \"%s\"\n"
	    "\t\tinterval = 1\n"
	    "\t\ttimeout = 5\n"
	    "\t\tdown_after = 1\n"
	    "\t\tup_after = 1\n"
	    "%s"
	    "\t}\n"
	    "}\n",
	    command, require_lease ? "" : "\t\trequire_lease = false\n");
	return compiled(text);
}

/* An observation carrying one route, as a DHCP client would have left it. A
 * `proto` of 3 is boot/static, which is what netcfgd's own routes carry. */
static ncfg_observed_t *leased(const char *interface, int64_t proto)
{
	char             err[NCFG_ERROR_MAX];
	ncfg_observed_t *observed = ncfg_observed_new(err, sizeof(err));

	if (!observed) {
		printf("no observation: %s\n", err);
		exit(1);
	}
	observed->routes = calloc(1u, sizeof(*observed->routes));
	if (!observed->routes) {
		printf("no memory for a route\n");
		exit(1);
	}
	observed->route_count = 1u;
	observed->routes[0].interface = strdup(interface);
	observed->routes[0].destination = strdup("default");
	observed->routes[0].proto.has = 1;
	observed->routes[0].proto.value = proto;
	return observed;
}

/*
 * An observation carrying one link of this name.
 *
 * Only the fields this file looks at are filled in; the rest is the zero an
 * observation's fields already default to, which is why `observed.h` says this
 * type is a `calloc` with a name.
 */
static ncfg_observed_t *with_link(const char *name)
{
	char             err[NCFG_ERROR_MAX];
	ncfg_observed_t *observed = ncfg_observed_new(err, sizeof(err));

	if (!observed) {
		printf("no observation: %s\n", err);
		exit(1);
	}
	observed->links = calloc(1u, sizeof(*observed->links));
	if (!observed->links) {
		printf("no memory for a link\n");
		exit(1);
	}
	observed->link_count = 1u;
	observed->links[0].name = strdup(name);
	observed->links[0].index = 2;
	observed->links[0].kind = strdup("");
	observed->links[0].up = 1;
	observed->links[0].carrier = 1;
	observed->links[0].mtu = 1500;
	return observed;
}

/* A probe set with the driven clock already fitted. */
static ncfg_probes_t *probes_new(void)
{
	char           err[NCFG_ERROR_MAX];
	ncfg_probes_t *probes = ncfg_probes_new(err, sizeof(err));

	if (!probes) {
		printf("no probe set: %s\n", err);
		exit(1);
	}
	fake_now = 0;
	ncfg_probes_clock(probes, fake_clock, NULL);
	return probes;
}

/* One tick. `*changed` is filled in; the call itself must not fail. */
static int tick(ncfg_probes_t *probes, const ncfg_document_t *document,
    const ncfg_observed_t *observed)
{
	char err[NCFG_ERROR_MAX];
	int  changed = 0;

	if (!ncfg_probes_run_due(probes, document, observed, &changed, err, sizeof(err))) {
		printf("a tick failed, which only happens when memory runs out: %s\n", err);
		failures++;
	}
	return changed;
}

/* Whether the verdict is exactly this. `-1` for absent. */
static int verdict_is(const ncfg_probes_t *probes, const char *interface, int want)
{
	ncfg_optbool_t verdict = ncfg_probes_verdict(probes, interface);

	if (want < 0) {
		return !verdict.has;
	}
	return verdict.has && verdict.value == want;
}

/* ------------------------------------------------------- the precondition */

/*
 * **No lease, no spawn**, and the verdict is still down.
 *
 * An interface that asked for DHCP and has no lease has nothing a reachability
 * probe could succeed over: it can only fail, and finding that out costs a
 * process every interval. The command here is one that would *succeed* if it
 * ran -- so a verdict of down proves the precondition decided it, not the
 * program (0191).
 */
static void an_interface_with_no_lease_is_down_without_running_the_probe(const char *base)
{
	char             path[512];
	char             marker[512];
	char             body[1024];
	ncfg_document_t *document;
	ncfg_probes_t   *probes = probes_new();

	(void)testdir_in(base, "lease-ran", marker, sizeof(marker));
	(void)snprintf(body, sizeof(body), "#!/bin/sh\ntouch %s\nexit 0\n", marker);
	document = dhcp_with_probe(script(base, "lease.sh", body, path, sizeof(path)), 1);

	(void)tick(probes, document, NULL);
	check(!testdir_exists(marker), "an interface with no lease does not spawn its probe");
	check(verdict_is(probes, "eth0", 0),
	    "  and no lease is an answer about the link, not an absence of one");
	detail("said", ncfg_probes_detail(probes, "eth0"));

	ncfg_probes_free(probes);
	ncfg_document_free(document);
	(void)unlink(marker);
}

/* **With a lease the program runs**, which is what stops the check above
 * passing because nothing ever runs. */
static void an_interface_with_a_lease_runs_the_probe(const char *base)
{
	char             path[512];
	char             marker[512];
	char             body[1024];
	ncfg_document_t *document;
	ncfg_observed_t *observed = leased("eth0", NCFG_DHCP_ROUTE_PROTO);
	ncfg_probes_t   *probes = probes_new();

	(void)testdir_in(base, "lease-ran", marker, sizeof(marker));
	(void)snprintf(body, sizeof(body), "#!/bin/sh\ntouch %s\nexit 0\n", marker);
	document = dhcp_with_probe(script(base, "lease.sh", body, path, sizeof(path)), 1);

	(void)tick(probes, document, observed);
	check(testdir_exists(marker), "with a lease the probe runs");
	check(verdict_is(probes, "eth0", 1), "  and the link is judged reachable");

	ncfg_probes_free(probes);
	ncfg_observed_free(observed);
	ncfg_document_free(document);
	(void)unlink(marker);
}

/*
 * A route from something that is not a DHCP client is not a lease.
 *
 * netcfgd installs default routes of its own from the document, and counting
 * one of those would make the precondition pass on a static interface that
 * never had a lease at all.
 */
static void a_route_from_another_source_is_not_a_lease(const char *base)
{
	char             path[512];
	char             marker[512];
	char             body[1024];
	ncfg_document_t *document;
	/* `proto 3` is boot/static, which is what netcfgd's own routes carry. */
	ncfg_observed_t *observed = leased("eth0", 3);
	ncfg_probes_t   *probes = probes_new();

	(void)testdir_in(base, "lease-ran", marker, sizeof(marker));
	(void)snprintf(body, sizeof(body), "#!/bin/sh\ntouch %s\nexit 0\n", marker);
	document = dhcp_with_probe(script(base, "lease.sh", body, path, sizeof(path)), 1);

	(void)tick(probes, document, observed);
	check(!testdir_exists(marker), "a static route is not taken for a lease");

	ncfg_probes_free(probes);
	ncfg_observed_free(observed);
	ncfg_document_free(document);
	(void)unlink(marker);
}

/* **And it is optional**, because an operator whose client netcfgd cannot see
 * would otherwise have a working link held down for ever. */
static void require_lease_false_runs_the_probe_with_no_lease_at_all(const char *base)
{
	char             path[512];
	char             marker[512];
	char             body[1024];
	ncfg_document_t *document;
	ncfg_probes_t   *probes = probes_new();

	(void)testdir_in(base, "lease-ran", marker, sizeof(marker));
	(void)snprintf(body, sizeof(body), "#!/bin/sh\ntouch %s\nexit 0\n", marker);
	document = dhcp_with_probe(script(base, "lease.sh", body, path, sizeof(path)), 0);

	check(document->interfaces[0].probe && !document->interfaces[0].probe->require_lease,
	    "`require_lease = false` survives the compiler");
	(void)tick(probes, document, NULL);
	check(testdir_exists(marker), "  and the probe runs with no lease at all");
	detail("said", ncfg_probes_detail(probes, "eth0"));

	ncfg_probes_free(probes);
	ncfg_document_free(document);
	(void)unlink(marker);
}

/* ------------------------------------------------------------ the detail */

/*
 * **A failing probe says why, in the program's own words.**
 *
 * The exit status says the link does not work and nothing about why not, and
 * standard error used to go to `/dev/null` -- so the one thing the program had
 * to say about it was discarded. A probe nobody can debug is one that gets
 * deleted rather than fixed.
 */
static void a_failing_probe_reports_what_it_printed(const char *base)
{
	char             path[512];
	ncfg_document_t *document = with_probe(
	    script(base, "noisy.sh",
	        "#!/bin/sh\necho 'ping: connect: Network is unreachable' >&2\nexit 1\n", path,
	        sizeof(path)),
	    5, 0, NULL);
	ncfg_observed_t *observed = with_link("eth0");
	ncfg_probes_t   *probes = probes_new();
	char             err[NCFG_ERROR_MAX];

	(void)tick(probes, document, NULL);
	check(ncfg_probes_apply(probes, observed, err, sizeof(err)), "the verdicts are stamped on");
	check(observed->links[0].reachable.has && !observed->links[0].reachable.value,
	    "  it ran and said no");
	check(observed->links[0].probe_detail &&
	        strcmp(observed->links[0].probe_detail,
	            "ping: connect: Network is unreachable") == 0,
	    "  and what it printed reaches the observation");
	detail("probe_detail", observed->links[0].probe_detail);

	ncfg_probes_free(probes);
	ncfg_observed_free(observed);
	ncfg_document_free(document);
}

/*
 * The last non-empty line, and its tail.
 *
 * A program that printed a banner and then an error should report the error,
 * and a line longer than a client is shown is cut from the front with `...`
 * rather than from the back -- a shell script's last words are the ones about
 * the thing that just failed.
 */
static void the_detail_is_the_last_non_empty_line_and_its_tail(const char *base)
{
	char             path[512];
	ncfg_document_t *document;
	ncfg_probes_t   *probes;
	const char      *said;

	/* A banner, then a line of 500 `x` with a recognisable tail, then two
	 * blank lines -- so both halves of the rule are exercised at once. The
	 * loop is bounded by `seq 50`; every line it writes is ten bytes. */
	document = with_probe(script(base, "wordy.sh",
	    "#!/bin/sh\n"
	    "echo 'a banner nobody wants' >&2\n"
	    "for i in $(seq 50); do printf 'xxxxxxxxxx' >&2; done\n"
	    "printf 'END-OF-THE-LINE\\n\\n\\n' >&2\n"
	    "exit 1\n", path, sizeof(path)), 5, 0, NULL);
	probes = probes_new();

	(void)tick(probes, document, NULL);
	said = ncfg_probes_detail(probes, "eth0");
	check(said && strncmp(said, "...", 3u) == 0,
	    "a line past the ceiling is cut from the front and says so");
	check(said && strlen(said) == (size_t)NCFG_PROBE_DETAIL_MAX + 3u,
	    "  and what is kept is exactly the ceiling");
	check(said && strstr(said, "END-OF-THE-LINE") != NULL,
	    "  the tail is the end of the line rather than its beginning");
	check(said && strstr(said, "a banner nobody wants") == NULL,
	    "  and the banner two lines earlier is not what is reported");
	detail("said", said);

	ncfg_probes_free(probes);
	ncfg_document_free(document);
}

/*
 * **A probe that says more than a pipe holds still finishes.**
 *
 * The Rust reads standard error only once the child has exited, so a program
 * writing past the pipe buffer blocks in `write`, never exits, and is killed at
 * its deadline -- a working link reported as "no answer within 5s" and stripped
 * of its routes. 64 KiB is a Linux pipe; this writes more than twice that and
 * then exits zero, so the verdict is the program's rather than the clock's.
 *
 * The timeout is two seconds, so a build that reintroduced the deadlock fails
 * here in two seconds rather than hanging.
 */
static void a_probe_that_says_a_great_deal_is_still_heard_out(const char *base)
{
	char             path[512];
	ncfg_document_t *document;
	ncfg_probes_t   *probes;
	const char      *said;

	/* A bounded loop: 3000 lines of 50 bytes is about 150 KiB, well past one
	 * pipe. `i` is the only thing that ends it and it counts up by one. */
	document = with_probe(script(base, "chatty.sh",
	    "#!/bin/sh\n"
	    "i=0\n"
	    "while [ $i -lt 3000 ]; do\n"
	    "\techo \"chatter $i ...................................\" >&2\n"
	    "\ti=$((i + 1))\n"
	    "done\n"
	    "echo 'the last word' >&2\n"
	    "exit 0\n", path, sizeof(path)), 2, 0, NULL);
	probes = probes_new();

	(void)tick(probes, document, NULL);
	said = ncfg_probes_detail(probes, "eth0");
	check(verdict_is(probes, "eth0", 1),
	    "a probe that writes past a pipe buffer is heard out rather than killed");
	check(said && strcmp(said, "the last word") == 0,
	    "  and the last thing it said is what is kept");
	detail("said", said);

	ncfg_probes_free(probes);
	ncfg_document_free(document);
}

/*
 * **A probe that hangs is killed, and so is what it started.**
 *
 * A probe is a script and what it forks is a grandchild: signalling only the
 * shell leaves that grandchild running and reparented to init, with the daemon
 * no longer waiting for work that is still happening.
 *
 * **The marker is touched by the grandchild and not by the script**, which is
 * the whole shape of the case. A script that slept and then touched would prove
 * nothing: killing the shell alone already stops the `touch`, because it is the
 * shell that would run it. So the background subshell is what sleeps and
 * touches, the script only waits for it, and the marker appears if and only if
 * something outlived the kill.
 *
 * Bounded three ways: the probe's own one-second timeout ends the call, the
 * subshell's `sleep 2` ends the subshell, and nothing here loops.
 */
static void a_probe_that_hangs_is_killed_along_with_what_it_started(const char *base)
{
	char             path[512];
	char             marker[512];
	char             body[1024];
	ncfg_document_t *document;
	ncfg_probes_t   *probes = probes_new();
	struct timespec  wait;
	time_t           began;
	const char      *said;

	(void)testdir_in(base, "survived", marker, sizeof(marker));
	(void)snprintf(body, sizeof(body),
	    "#!/bin/sh\n( sleep 2; touch %s ) &\nwait\n", marker);
	document = with_probe(script(base, "hangs.sh", body, path, sizeof(path)), 1, 0, NULL);

	began = time(NULL);
	(void)tick(probes, document, NULL);
	check(time(NULL) - began <= 2, "a probe that never answers is killed at its timeout");
	said = ncfg_probes_detail(probes, "eth0");
	check(said && strstr(said, "no answer within 1s") != NULL, "  and says so");
	check(verdict_is(probes, "eth0", 0),
	    "  a hanging probe is a failing link rather than a broken script");
	detail("said", said);

	/* Past the subshell's own sleep, so a grandchild that outlived the kill
	 * would have left the marker by now. */
	wait.tv_sec = 2;
	wait.tv_nsec = 500L * 1000L * 1000L;
	(void)nanosleep(&wait, NULL);
	check(!testdir_exists(marker),
	    "  and the `sleep` it started went with it rather than outliving the daemon");

	ncfg_probes_free(probes);
	ncfg_document_free(document);
	(void)unlink(marker);
}

/* ----------------------------------------------------------- setting aside */

/*
 * **A program that cannot be started is set aside, not left withholding routes
 * for ever.**
 *
 * It says nothing about the link, so a verdict of down would be an answer to a
 * question nobody managed to ask -- and a typo in `command` would take an
 * interface off the network and keep it there. Loudly: the detail names the
 * count and the reason, which is the half the original "a typo quietly meaning
 * always up" concern was about.
 */
static void a_probe_that_cannot_run_is_set_aside_with_a_reason(const char *base)
{
	ncfg_document_t *document = with_probe("/nonexistent/probe", 5, 0, NULL);
	ncfg_observed_t *observed = with_link("eth0");
	ncfg_probes_t   *probes = probes_new();
	char             err[NCFG_ERROR_MAX];
	unsigned         attempt;

	(void)base;
	/* One short of the limit: still trying, and no verdict has been reached
	 * because nothing ever ran. */
	for (attempt = 0; attempt < NCFG_PROBE_START_FAILURES_BEFORE_SET_ASIDE - 1u; attempt++) {
		(void)tick(probes, document, NULL);
		fake_now += 1100;
	}
	check(ncfg_probes_detail(probes, "eth0") &&
	        strstr(ncfg_probes_detail(probes, "eth0"), "cannot run") != NULL,
	    "it says what went wrong before giving up");
	check(!strstr(ncfg_probes_detail(probes, "eth0"), "set aside"),
	    "  and has not given up yet");
	check(verdict_is(probes, "eth0", -1), "  with no verdict, because nothing ever ran");

	(void)tick(probes, document, NULL);
	check(ncfg_probes_apply(probes, observed, err, sizeof(err)), "the verdicts are stamped on");
	check(!observed->links[0].reachable.has,
	    "a probe that never ran leaves the link unjudged rather than down");
	check(observed->links[0].probe_detail &&
	        strstr(observed->links[0].probe_detail, "set aside") != NULL,
	    "  and says so, with the count and the reason");
	detail("probe_detail", observed->links[0].probe_detail);

	/* And it stays set aside: asking again every interval for ever is noise
	 * rather than resilience. The detail does not go back to `cannot run`. */
	fake_now += 1100;
	(void)tick(probes, document, NULL);
	check(ncfg_probes_detail(probes, "eth0") &&
	        strstr(ncfg_probes_detail(probes, "eth0"), "set aside") != NULL,
	    "  and set aside stays set aside until the configuration changes");

	ncfg_probes_free(probes);
	ncfg_observed_free(observed);
	ncfg_document_free(document);
}

/* ------------------------------------------------------------- the dwell */

/*
 * How many times the verdict changes over six runs of a link that alternates
 * on every single run.
 *
 * A fixed `/bin/true` or `/bin/false` cannot exercise a dwell at all -- the
 * dwell only ever suppresses a *second* change, so a probe that never changes
 * its mind would let a broken implementation pass. This is the flapping link
 * the hold-down exists for, at the fastest period it can have.
 */
static int changes(const char *base, int64_t hold_down)
{
	char             path[512];
	char             counter[512];
	/* Two copies of a path that may be long: enough for both, so the gate's
	 * truncation warning is answered rather than silenced. */
	char             body[2048];
	ncfg_document_t *document;
	ncfg_probes_t   *probes;
	int              changed = 0;
	unsigned         run;

	(void)testdir_in(base, "flap.n", counter, sizeof(counter));
	(void)unlink(counter);
	/* Succeed, fail, succeed, fail: the counter is read, written back one
	 * higher, and its parity is the exit status. Nothing loops. */
	(void)snprintf(body, sizeof(body),
	    "#!/bin/sh\n"
	    "n=$(cat %s 2>/dev/null || echo 0)\n"
	    "echo $((n + 1)) > %s\n"
	    "exit $((n %% 2))\n", counter, counter);
	document = with_probe(script(base, "flap.sh", body, path, sizeof(path)), 5, hold_down,
	    NULL);
	probes = probes_new();

	for (run = 0; run < 6u; run++) {
		if (run > 0u) {
			/* Past `interval = 1`, so every run is due. */
			fake_now += 1050;
		}
		if (tick(probes, document, NULL)) {
			changed++;
		}
	}
	ncfg_probes_free(probes);
	ncfg_document_free(document);
	(void)unlink(counter);
	return changed;
}

/*
 * The counter-case, and the one that makes the other mean something: with no
 * dwell this link moves the default route on every tick, which is precisely
 * what 0119 left open.
 *
 * Six, exactly. The Rust asserts `>= 4` because it is racing a real clock; a
 * driven one can say what should happen.
 */
static void without_a_dwell_a_flapping_link_oscillates(const char *base)
{
	int seen = changes(base, 0);

	check(seen == 6, "with no dwell a link that alternates changes verdict on every run");
	if (seen != 6) {
		printf("       changed %d times, wanted 6\n", seen);
	}
}

/* And with one, it settles: the first verdict stands and the rest of the
 * flapping is absorbed. */
static void a_dwell_absorbs_the_flapping(const char *base)
{
	int seen = changes(base, 60);

	check(seen == 1, "a dwell longer than the run lets the verdict change once, then holds");
	if (seen != 1) {
		printf("       changed %d times, wanted 1\n", seen);
	}
}

/*
 * A dwell suppresses the change and not the running.
 *
 * **The counts keep running while the verdict is held.** That is the half a
 * dwell is easy to get wrong -- suppressing the *run* would mean the moment it
 * expired the verdict reflected one stale result rather than what has been
 * happening -- and this is built so that only the right implementation passes:
 * `down_after` is three, the three failing runs happen across a dwell, and the
 * verdict flips on the third. An implementation that reset the counts when it
 * held the change would be at one there and would not flip.
 *
 * Driven past the dwell, which is the half a test against the real clock cannot
 * reach without waiting ten seconds.
 */
static void a_dwell_that_expires_lets_the_verdict_move_again(const char *base)
{
	char             path[512];
	char             counter[512];
	/* Two copies of a path that may be long: enough for both, so the gate's
	 * truncation warning is answered rather than silenced. */
	char             body[2048];
	char             text[2048];
	ncfg_document_t *document;
	ncfg_probes_t   *probes;

	(void)testdir_in(base, "expire.n", counter, sizeof(counter));
	(void)unlink(counter);
	/* Succeeds once and fails for ever after. Nothing loops: the counter is
	 * read, written back one higher, and only its first value is a success. */
	(void)snprintf(body, sizeof(body),
	    "#!/bin/sh\n"
	    "n=$(cat %s 2>/dev/null || echo 0)\n"
	    "echo $((n + 1)) > %s\n"
	    "if [ \"$n\" -eq 0 ]; then exit 0; fi\n"
	    "exit 1\n", counter, counter);
	(void)snprintf(text, sizeof(text),
	    "interface eth0 {\n\tpreference = 10\n\tprobe {\n\t\tcommand = \"%s\"\n"
	    "\t\tinterval = 1\n\t\ttimeout = 5\n\t\tdown_after = 3\n\t\tup_after = 1\n"
	    "\t\thold_down = 10\n\t}\n}\n",
	    script(base, "expire.sh", body, path, sizeof(path)));
	document = compiled(text);
	probes = probes_new();

	check(tick(probes, document, NULL) && verdict_is(probes, "eth0", 1),
	    "the first run decides, and the dwell starts");
	fake_now += 1050;
	check(!tick(probes, document, NULL) && verdict_is(probes, "eth0", 1),
	    "  a failing run inside the dwell is absorbed");
	fake_now += 1050;
	check(!tick(probes, document, NULL) && verdict_is(probes, "eth0", 1),
	    "  and so is the second");
	/* Past the ten-second dwell. This is the third consecutive failure and
	 * `down_after` is three, so it flips only if the two held runs counted. */
	fake_now += 11000;
	check(tick(probes, document, NULL) && verdict_is(probes, "eth0", 0),
	    "  and the counts kept running, so the third failure is the one that decides");

	ncfg_probes_free(probes);
	ncfg_document_free(document);
	(void)unlink(counter);
}

/* ------------------------------------------------------- what is reported */

/*
 * `failing` is decided falses, in name order, and nothing else.
 *
 * A machine with two failing modems has to advance them in the same order every
 * time, and an interface whose probe has not yet agreed with itself must not be
 * in here at all -- that is what stops a SIM being switched on no information
 * (0152).
 */
static void failing_is_the_decided_falses_in_name_order(const char *base)
{
	char             good[512];
	char             bad[512];
	char             text[2048];
	ncfg_document_t *document;
	ncfg_probes_t   *probes = probes_new();

	(void)script(base, "yes.sh", "#!/bin/sh\nexit 0\n", good, sizeof(good));
	(void)script(base, "no.sh", "#!/bin/sh\nexit 1\n", bad, sizeof(bad));
	/* `wwan1` fails at once, `wwan0` needs two runs and gets one, and `eth0`
	 * succeeds. So exactly one name is failing after the first tick, and the
	 * order is proved by the second. */
	(void)snprintf(text, sizeof(text),
	    "interface eth0 {\n\tpreference = 10\n\tprobe {\n\t\tcommand = \"%s\"\n"
	    "\t\tinterval = 1\n\t\tdown_after = 1\n\t\tup_after = 1\n\t}\n}\n"
	    "interface wwan0 {\n\tpreference = 20\n\tprobe {\n\t\tcommand = \"%s\"\n"
	    "\t\tinterval = 1\n\t\tdown_after = 2\n\t\tup_after = 1\n\t}\n}\n"
	    "interface wwan1 {\n\tpreference = 30\n\tprobe {\n\t\tcommand = \"%s\"\n"
	    "\t\tinterval = 1\n\t\tdown_after = 1\n\t\tup_after = 1\n\t}\n}\n",
	    good, bad, bad);
	document = compiled(text);

	(void)tick(probes, document, NULL);
	check(ncfg_probes_failing_count(probes) == 1u,
	    "a probe that has not yet agreed with itself is not failing yet");
	check(ncfg_probes_failing_at(probes, 0) &&
	        strcmp(ncfg_probes_failing_at(probes, 0), "wwan1") == 0,
	    "  and the one that has is named");

	fake_now += 1050;
	(void)tick(probes, document, NULL);
	check(ncfg_probes_failing_count(probes) == 2u, "the second run brings the other one down");
	check(ncfg_probes_failing_at(probes, 0) &&
	        strcmp(ncfg_probes_failing_at(probes, 0), "wwan0") == 0 &&
	        ncfg_probes_failing_at(probes, 1) &&
	        strcmp(ncfg_probes_failing_at(probes, 1), "wwan1") == 0,
	    "  in name order, so two failing modems advance in the same order every time");
	check(ncfg_probes_failing_at(probes, 2) == NULL, "  and there is no third");

	ncfg_probes_free(probes);
	ncfg_document_free(document);
}

/*
 * An interface whose probe was removed stops having a verdict, rather than
 * keeping the last one for ever -- and that counts as a change, because it is
 * one the planner has to act on.
 */
static void a_probe_removed_from_the_document_loses_its_verdict(const char *base)
{
	char             path[512];
	ncfg_document_t *before = with_probe(script(base, "no.sh", "#!/bin/sh\nexit 1\n", path,
	    sizeof(path)), 5, 0, NULL);
	ncfg_document_t *after = compiled("interface eth0 {\n\tpreference = 10\n}\n");
	ncfg_probes_t   *probes = probes_new();

	check(tick(probes, before, NULL) && verdict_is(probes, "eth0", 0),
	    "the probe decides the link is down");
	fake_now += 1050;
	check(tick(probes, after, NULL), "removing the probe is a change the planner is told about");
	check(verdict_is(probes, "eth0", -1), "  and the verdict goes with it");
	check(ncfg_probes_failing_count(probes) == 0u, "  so nothing is failing any more");

	ncfg_probes_free(probes);
	ncfg_document_free(before);
	ncfg_document_free(after);
}

/* A daemon holding no desired state knows nothing about any link. */
static void no_document_clears_every_tally(const char *base)
{
	char             path[512];
	ncfg_document_t *document = with_probe(script(base, "no.sh", "#!/bin/sh\nexit 1\n", path,
	    sizeof(path)), 5, 0, NULL);
	ncfg_probes_t   *probes = probes_new();

	(void)tick(probes, document, NULL);
	check(ncfg_probes_failing_count(probes) == 1u, "a verdict has been reached");
	(void)tick(probes, NULL, NULL);
	check(ncfg_probes_failing_count(probes) == 0u && verdict_is(probes, "eth0", -1),
	    "and a daemon with no document holds no verdicts");

	ncfg_probes_free(probes);
	ncfg_document_free(document);
}

/*
 * A link nobody asked about keeps its routes.
 *
 * Absent is **not** false: `ncfg_probes_apply` writes only what it has, so a
 * machine that configured no probes comes out of it exactly as it went in.
 */
static void a_link_with_no_probe_is_left_unjudged(void)
{
	ncfg_observed_t *observed = with_link("eth9");
	ncfg_probes_t   *probes = probes_new();
	char             err[NCFG_ERROR_MAX];

	check(ncfg_probes_apply(probes, observed, err, sizeof(err)), "applying no verdicts works");
	check(!observed->links[0].reachable.has && !observed->links[0].probe_detail,
	    "  and a link no probe named is left exactly as it was");

	ncfg_probes_free(probes);
	ncfg_observed_free(observed);
}

/* ------------------------------------------------------------- the sink */

/*
 * **A fixture that carries a hook still compiles to be read.**
 *
 * The three Rust sites this file replaces pass `NoHooks`, on the grounds that
 * their fixtures have no hooks -- true of the fixtures and not of the question
 * (0258). This drives both sinks over one text so the difference is a fact
 * rather than an argument: the refusing one answers a *probe* test with a
 * sentence about hooks, and the unwritten one hands over the document this
 * module is here to be driven by.
 */
static void a_fixture_that_carries_a_hook_still_compiles_to_be_read(const char *base)
{
	char             path[512];
	char             text[2048];
	ncfg_ast_file_t *file = NULL;
	ncfg_source_t    source;
	ncfg_document_t *refused;
	ncfg_document_t *document;
	ncfg_probes_t   *probes;
	char             err[NCFG_ERROR_MAX];

	(void)script(base, "no.sh", "#!/bin/sh\nexit 1\n", path, sizeof(path));
	(void)snprintf(text, sizeof(text),
	    "interface eth0 {\n"
	    "\tpreference = 10\n"
	    "\tpost_up {\n#!/bin/sh\nlogger up\n\t}\n"
	    "\tprobe {\n\t\tcommand = \"%s\"\n\t\tinterval = 1\n"
	    "\t\tdown_after = 1\n\t\tup_after = 1\n\t}\n"
	    "}\n", path);

	check(ncfg_parse(text, strlen(text), &file, NULL, err, sizeof(err)),
	    "a configuration with a hook and a probe parses");
	source.name = "netcfgd.conf";
	source.file = file;
	refused = ncfg_compile(&source, 1u, ncfg_hook_sink_refusing(), NULL, err, sizeof(err));
	check(refused == NULL && strstr(err, "hook") != NULL,
	    "  the refusing sink answers a probe question with a sentence about hooks");
	detail("refusing sink", err);
	ncfg_document_free(refused);

	document = ncfg_compile(&source, 1u, ncfg_hook_sink_unwritten(), NULL, err, sizeof(err));
	ncfg_ast_file_free(file);
	check(document != NULL, "  and the unwritten sink gives the document a reader asked for");
	if (!document) {
		return;
	}

	probes = probes_new();
	(void)tick(probes, document, NULL);
	check(verdict_is(probes, "eth0", 0),
	    "  which is the one this module is driven by, hook and all");
	ncfg_probes_free(probes);
	ncfg_document_free(document);
}

int main(void)
{
	const char *base = testdir_make("probe");

	an_interface_with_no_lease_is_down_without_running_the_probe(base);
	an_interface_with_a_lease_runs_the_probe(base);
	a_route_from_another_source_is_not_a_lease(base);
	require_lease_false_runs_the_probe_with_no_lease_at_all(base);

	a_failing_probe_reports_what_it_printed(base);
	the_detail_is_the_last_non_empty_line_and_its_tail(base);
	a_probe_that_says_a_great_deal_is_still_heard_out(base);
	a_probe_that_hangs_is_killed_along_with_what_it_started(base);

	a_probe_that_cannot_run_is_set_aside_with_a_reason(base);

	without_a_dwell_a_flapping_link_oscillates(base);
	a_dwell_absorbs_the_flapping(base);
	a_dwell_that_expires_lets_the_verdict_move_again(base);

	failing_is_the_decided_falses_in_name_order(base);
	a_probe_removed_from_the_document_loses_its_verdict(base);
	no_document_clears_every_tally(base);
	a_link_with_no_probe_is_left_unjudged();

	a_fixture_that_carries_a_hook_still_compiles_to_be_read(base);

	testdir_remove(base);
	if (failures == 0) {
		printf("probe_test: all checks passed\n");
	} else {
		printf("probe_test: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
