/*
 * autoip_test.c -- what netcfgd's IPv4LL client is started with, and what it
 * will not do to somebody else's.
 *
 * WHAT THESE CASES ARE FOR
 *   `autoip.h` argues that the ownership claim here is weaker than every other
 *   backend's, because `avahi-autoipd` writes no pid file and its `--kill`
 *   acts on whichever client is on the interface. These are the cases that
 *   hold what is left of the claim to its word:
 *
 *   * **`--force-bind` is passed, and it is not cosmetic.** `document.h` says
 *     link-local coexists with routable addresses rather than being a
 *     fallback; without that argument the client declines when a routable
 *     address is present, which is the behaviour the document forbids. The
 *     argument list is read back from a stand-in rather than asserted about.
 *   * **A client netcfgd cannot claim is not signalled.** A pid whose
 *     `cmdline` no longer carries the marker is somebody else's by now, and
 *     the stop leaves it alone. That is the case `--kill` could not express.
 *   * **A start that leaves nothing running is a failure.** The client
 *     detaches, so "it exited 0" is not evidence that link-local addressing is
 *     happening -- and reporting success there would leave netcfgd with
 *     nothing it could ever stop.
 *
 *   Never the real `avahi-autoipd`: every case runs a stand-in, which is
 *   `backend_internal.h`'s rule and the reason the program is a parameter.
 */
#include "ncfg/autoip.h"
#include "ncfg/base.h"

#include "testdir.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int failures;

static void check(int condition, const char *what)
{
	printf("%-70s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

static void write_fake(const char *path, const char *body)
{
	check(testdir_write(path, body, strlen(body)), "the stand-in client is written");
	check(chmod(path, 0755) == 0, "and is executable");
}

/* ------------------------------------------------------------ the paths */

static void the_paths_are_the_shape_every_other_backend_has(const char *run)
{
	char path[NCFG_AUTOIP_PATH_MAX];
	char message[NCFG_ERROR_MAX];

	check(ncfg_autoip_run_dir(run, path, sizeof(path), message, sizeof(message)) &&
	    strstr(path, "/autoip") != NULL,
	    "the run directory is `<run>/autoip`");
	check(ncfg_autoip_pid_path(run, "lan0", path, sizeof(path), message, sizeof(message)) &&
	    strstr(path, "/autoip/lan0.pid") != NULL,
	    "and the pid file is netcfgd's own, named for the interface");
	check(ncfg_autoip_log_path(run, "lan0", path, sizeof(path), message, sizeof(message)) &&
	    strstr(path, "/autoip/lan0.log") != NULL,
	    "and the log a refusal is quoted from sits beside it");
}

/* ------------------------------------------------------- nothing running */

static void with_nothing_running_the_answers_are_the_quiet_ones(const char *run)
{
	char message[NCFG_ERROR_MAX];

	check(ncfg_autoip_running_pid(run, "lan0") == 0,
	    "with no record there is no client of netcfgd's");
	message[0] = '\0';
	check(ncfg_autoip_stop(run, "lan0", message, sizeof(message)),
	    "and stopping nothing is success, because it is the state asked for");
}

/*
 * **The path is deliberately not named `avahi-autoipd`**, and the first
 * version of this check was `/nonexistent/avahi-autoipd` -- which contains the
 * conventional name, so `strstr(message, "avahi-autoipd")` matched whether the
 * refusal named the path asked for or the name nobody asked for. It passed
 * against both, which is to say it was asking nothing. A basename that shares
 * no text with the constant is what makes the two answers separable.
 */
static void an_absent_client_is_refused_by_name(const char *run)
{
	char message[NCFG_ERROR_MAX];

	message[0] = '\0';
	check(!ncfg_autoip_start(run, "lan0", "/nonexistent/ipv4ll-stand-in", message,
	      sizeof(message)) &&
	    strstr(message, "/nonexistent/ipv4ll-stand-in") != NULL &&
	    strstr(message, "install") != NULL,
	    "an explicit client that is not there is refused by the path asked for");
	/*
	 * **The other branch -- no path given, so the conventional name is looked
	 * for -- is deliberately not checked here, and could not be checked
	 * safely.** `ncfg_backend_find_program` searches `/usr/sbin` before
	 * `PATH`, which `backend_run.c` argues at length after inverting it broke
	 * finding the real hostapd; so a stand-in on `PATH` is found on a machine
	 * with no client installed and ignored on one that has it. A check
	 * written that way would spawn a real IPv4LL client from the unit suite on
	 * exactly the machines where it mattered, and pass on this one because
	 * nothing is installed -- a verdict about the machine rather than the
	 * source. The program parameter is the seam, which is what every other
	 * case here uses.
	 */
}

/* --------------------------------------------------------- the arguments */

/*
 * The one case that reads the argument list rather than asserting about it.
 *
 * The stand-in records what it was given and exits 0 having started nothing,
 * which is also the "nothing left running" refusal below -- so this case gets
 * both halves out of one run: the arguments are right, and a start that
 * detaches into nothing is not reported as success.
 */
static void the_client_is_given_force_bind_and_the_interface(const char *run)
{
	char  fake[512];
	char  seen[512];
	char  body[1024];
	char  message[NCFG_ERROR_MAX];
	char *arguments;

	(void)testdir_in(run, "fake-autoipd", fake, sizeof(fake));
	(void)testdir_in(run, "arguments", seen, sizeof(seen));
	(void)snprintf(body, sizeof(body), "#!/bin/sh\nprintf '%%s\\n' \"$@\" > '%s'\nexit 0\n",
	    seen);
	write_fake(fake, body);

	message[0] = '\0';
	check(!ncfg_autoip_start(run, "lan0", fake, message, sizeof(message)) &&
	    strstr(message, "nothing it could stop") != NULL,
	    "a client that exits 0 and leaves nothing running is not a success");

	arguments = testdir_read(seen, NULL);
	check(arguments != NULL && strstr(arguments, "--force-bind") != NULL,
	    "  and `--force-bind` was passed, which is what makes it coexist");
	check(arguments != NULL && strstr(arguments, "lan0") != NULL,
	    "  with the interface, which is the client's one positional argument");
	check(arguments != NULL && strstr(arguments, "-w") != NULL,
	    "  and `-w`, so the exit status means an address was acquired");
	free(arguments);
}

static void a_client_that_refuses_is_quoted(const char *run)
{
	char fake[512];
	char body[1024];
	char message[NCFG_ERROR_MAX];

	(void)testdir_in(run, "fake-refusing", fake, sizeof(fake));
	(void)snprintf(body, sizeof(body),
	    "#!/bin/sh\necho 'avahi-autoipd: Failed to bind: cannot do that here' >&2\nexit 3\n");
	write_fake(fake, body);

	message[0] = '\0';
	check(!ncfg_autoip_start(run, "lan0", fake, message, sizeof(message)) &&
	    strstr(message, "would not claim") != NULL &&
	    strstr(message, "Failed to bind") != NULL,
	    "a client that refuses is quoted rather than summarised by its status");
}

/* ----------------------------------------------- the ownership claim */

/*
 * A start that really leaves something behind, and the stop that recognises it.
 *
 * The stand-in backgrounds a shell whose own command line carries the marker,
 * which is the only thing this client's invocation can be made to carry. That
 * is deliberately the same weak claim the module documents rather than a
 * stronger one invented for the test.
 */
static void a_recorded_client_is_recognised_and_stopped(const char *run)
{
	char  fake[512];
	char  body[1024];
	char  message[NCFG_ERROR_MAX];
	pid_t pid;

	(void)testdir_in(run, "fake-detaching", fake, sizeof(fake));
	(void)snprintf(body, sizeof(body),
	    "#!/bin/sh\n"
	    "# Leave a process whose cmdline carries what netcfgd passed, the way a\n"
	    "# detached client would, and exit 0 as `-w` says a successful one does.\n"
	    "setsid sh -c 'sleep 60' holder --force-bind lan0 >/dev/null 2>&1 &\n"
	    "sleep 0.3\n"
	    "exit 0\n");
	write_fake(fake, body);

	message[0] = '\0';
	check(ncfg_autoip_start(run, "lan0", fake, message, sizeof(message)),
	    "a client that detaches and keeps running is a successful start");
	if (message[0] != '\0') {
		printf("  said: %s\n", message);
	}
	pid = ncfg_autoip_running_pid(run, "lan0");
	check(pid > 0, "  and netcfgd can say which process is its own");

	message[0] = '\0';
	check(ncfg_autoip_stop(run, "lan0", message, sizeof(message)),
	    "  and the stop signals that one");
	check(ncfg_autoip_running_pid(run, "lan0") == 0,
	    "  after which netcfgd has no client on that interface");
}

/*
 * A pid that is no longer what the record says is left alone.
 *
 * Written by hand rather than produced by a start, because the condition is a
 * pid file that outlived its process -- which is what happens across a reboot,
 * and what makes a blind `kill` reach a stranger.
 */
static void a_pid_that_is_not_ours_any_more_is_not_signalled(const char *run)
{
	char pid_path[NCFG_AUTOIP_PATH_MAX];
	char message[NCFG_ERROR_MAX];
	char mine[32];

	check(ncfg_autoip_pid_path(run, "wan0", pid_path, sizeof(pid_path), message,
	      sizeof(message)),
	    "a pid file for an interface nothing was started on");
	/* This test's own pid: alive, certainly not an IPv4LL client, and the one
	 * process a mistake here would be guaranteed to kill. */
	(void)snprintf(mine, sizeof(mine), "%ld\n", (long)getpid());
	check(testdir_write(pid_path, mine, strlen(mine)), "  naming a live process that is not one");

	check(ncfg_autoip_running_pid(run, "wan0") == 0,
	    "  is not netcfgd's client, because the cmdline does not carry the marker");
	message[0] = '\0';
	check(ncfg_autoip_stop(run, "wan0", message, sizeof(message)),
	    "  and the stop reports the state it was asked for");
	check(getpid() > 0, "  having signalled nothing -- this process is still here");
}

int main(void)
{
	const char *run = testdir_make("autoip");

	the_paths_are_the_shape_every_other_backend_has(run);
	with_nothing_running_the_answers_are_the_quiet_ones(run);
	an_absent_client_is_refused_by_name(run);
	the_client_is_given_force_bind_and_the_interface(run);
	a_client_that_refuses_is_quoted(run);
	a_recorded_client_is_recognised_and_stopped(run);
	a_pid_that_is_not_ours_any_more_is_not_signalled(run);

	testdir_remove(run);
	if (failures > 0) {
		printf("autoip: %d check(s) failed\n", failures);
		return 1;
	}
	printf("autoip: every check passed\n");
	return 0;
}
