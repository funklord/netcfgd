/*
 * supplicant_launch_test.c -- starting a `wpa_supplicant`, finding the one
 * already running, filling it, and stopping it.
 *
 * WHAT THIS MAY NOT TOUCH, AND HOW THAT IS ENFORCED
 *   This is the developer's own workstation and its wifi is real and in use.
 *   **No radio, no real interface and no real supplicant is reached by
 *   anything below.** Every interface named here is one the kernel has never
 *   heard of, every path is under one `mkdtemp` directory, and the program
 *   every start runs is a shell script this file wrote in that directory.
 *
 *   The protection is the module's rather than this file's discipline, which
 *   is the point: `ncfg_supplicant_start` has no default for the run
 *   directory, the control directory or the program, and
 *   `ncfg_service_t::supplicant_program` is the seam the Rust spells
 *   `NCFG_WPA_SUPPLICANT`. Checks below hand each of them NULL and read the
 *   sentence back.
 *
 * THE SUPPLICANT THIS STARTS IS THE REPOSITORY'S OWN FAKE
 *   `tests/live/fake_supplicant.py`, unchanged, driven through a wrapper this
 *   file writes. Two reasons rather than one: the wire format is the real one
 *   -- which is `fake_supplicant.py`'s whole bargain -- and a second fake
 *   supplicant in this tree would be a second place the protocol could be got
 *   wrong.
 *
 *   **The wrapper is where `-B` is honoured, and that is a deliberate
 *   difference from what netcfgd's own caller does.** A real
 *   `wpa_supplicant -B` forks, calls `setsid` and is then outside every bound
 *   a parent could put on it; so is the fake. A fixture that can be left
 *   running is the fault `hwsim.sh` shipped with, where a passing run held
 *   netcfgd and two supplicants ten minutes later. So the wrapper checks the
 *   flags netcfgd passed -- refusing by name anything it does not know, which
 *   is the property `fake_supplicant.py`'s own parser exists for -- records
 *   them verbatim for the checks below, and then runs the fake in its
 *   *positional* form under `timeout`, backgrounded, returning only once the
 *   control socket is there. That is exactly the promise `-B` makes and the
 *   one `backend.stop` relies on, and it leaves every process this file
 *   starts with something outside it that ends it.
 *
 * THE CHILD, AND HOW IT CANNOT OUTLIVE THIS
 *   Three things, none of which is a name or a pattern: every spawn is under
 *   `timeout`; every fake is put in **its own process group** and taken down
 *   by the pid this file recorded; and the supplicants netcfgd started are
 *   stopped through their own control sockets by the pid in the file netcfgd
 *   wrote. A worker in this tree once matched on a binary path and killed 76
 *   netcfgd processes, 74 of them other people's.
 *
 *   **The group is signalled before the pid, and a `SIGKILL` is why.** A
 *   `SIGTERM` is forwarded by anything standing in front of the real process
 *   and a `SIGKILL` is not, so killing a `timeout` on its own leaves what it
 *   was bounding reparented to init -- which is `process.h`'s sentence about a
 *   hook, and was measured here: a run left `sh -c 'sleep 60'` carrying this
 *   file's own marker with a ppid of 1. It went at its own bound, which is the
 *   difference between a residue and a leak, and the fixture should not have
 *   been relying on that.
 *
 *   **What is left for up to one second is the backstop, on purpose.** The
 *   reaper the wrapper starts is not torn down by pid: it wakes once a second,
 *   sees that the record it was guarding has gone with the run, and exits.
 *   Tearing it down by pid would mean signalling a process this file did not
 *   fork and whose `sleep` would outlive the signal anyway. Nothing it holds
 *   is a lock, a socket or a file, and nothing it can do after the run is
 *   anything: the one pid it will ever signal is the one it read before the
 *   directory was removed.
 *
 * THE CANARY
 *   `secrets_test.c`'s proof, carried through a launch. One value is the
 *   passphrase of the radio's network **and** the 802.1X password of the
 *   wired port -- `configure_wired` has the identical shape and is the second
 *   half of what 10.163 records -- and every failure this module has is driven
 *   with it in place. Five channels are read back: every `err` buffer this
 *   file filled, this process' whole standard error, the launch log netcfgd
 *   writes, the fake's own output, and the argv netcfgd built.
 *
 *   **And the proof is checked for being vacuous from both ends.** A sweep
 *   that passes because the credential never existed proves nothing, so the
 *   exact function the population sends through is asked to render the line
 *   and the canary is asserted to be *in* it; and a sweep that passes because
 *   it is reading an empty buffer proves nothing either, so the same `strstr`
 *   over the same buffers is asked for a string that is known to be there.
 */
#include "ncfg/apply.h"
#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/document.h"
#include "ncfg/process.h"
#include "ncfg/secrets.h"
#include "ncfg/service.h"
#include "ncfg/supplicant.h"

/* The one question the driver and the population both have to answer the same
 * way. Private to `src/apply/`, and reached the way `apply_kernel_test.c`
 * reaches `kernel_internal.h`: a rule that must not be written twice has one
 * declaration, and the check that it is one rule has to be able to call it. */
#include "../src/apply/service_internal.h"

#include "testdir.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* The value nothing may repeat. Distinctive enough that finding it in a buffer
 * is never a coincidence, and long enough to be a legal WPA2 passphrase so
 * that the length check is not what refuses it. */
#define CANARY "zq7-CANARY-passphrase-must-never-be-printed-4f1e"

static int failures;

static void check(int condition, const char *what)
{
	printf("%-76s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

/* Every `err` buffer this file has filled, end to end, swept at the end. */
static char   every_message[64u * 1024u];
static size_t every_message_length;

static void record(const char *message)
{
	size_t length = message ? strlen(message) : 0u;

	if (length > 0u && every_message_length + length + 2u < sizeof(every_message)) {
		memcpy(every_message + every_message_length, message, length);
		every_message_length += length;
		every_message[every_message_length++] = '\n';
		every_message[every_message_length] = '\0';
	}
}

/*
 * An outcome, with whatever the call wrote into `message` kept for the sweep.
 *
 * Wrapped around the call rather than around the buffer, because the buffer is
 * an argument the call is about to fill: reading it in the argument list would
 * sweep what was there before.
 */
static int recorded(int outcome, const char *message)
{
	record(message);
	return outcome;
}

/* A refusal has to name the thing it is about, or an operator cannot act on
 * it. Every failing check below goes through this rather than asserting only
 * that something returned 0. */
static void refused(int outcome, const char *message, const char *naming, const char *what)
{
	record(message);
	if (outcome != 0) {
		printf("%-76s %s\n", what, "FAILED (it succeeded)");
		failures++;
		return;
	}
	if (!message || !naming || strstr(message, naming) == NULL) {
		printf("%-76s FAILED (said `%s`)\n", what, message ? message : "");
		failures++;
		return;
	}
	printf("%-76s %s\n", what, "ok");
}

/* A writable copy of a literal, from a fixed arena: the document's fields are
 * `char *`, and these run under ASan where a fixture nobody frees is a
 * failure. */
static char   arena[4u * 1024u];
static size_t arena_used;

static char *text(const char *value)
{
	size_t length = strlen(value) + 1u;
	char  *out;

	if (arena_used + length > sizeof(arena)) {
		printf("the fixture arena is full\n");
		exit(1);
	}
	out = arena + arena_used;
	memcpy(out, value, length);
	arena_used += length;
	return out;
}

/* ====================================================== where everything is */

static char base[256];
static char run_dir[320];
static char ctrl_dir[320];
static char secrets_dir[320];
static char wrapper[384];
static char refuser[384];
static char reaper[384];
static char recorded_argv[384];
static char fake_output[384];
static char stderr_path[384];
static char script[512];

static long long now_ms(void)
{
	struct timespec when;

	(void)clock_gettime(CLOCK_MONOTONIC, &when);
	return (long long)when.tv_sec * 1000 + when.tv_nsec / 1000000;
}

static void pause_briefly(void)
{
	struct timespec slice;

	slice.tv_sec = 0;
	slice.tv_nsec = 5000000;
	(void)nanosleep(&slice, NULL);
}

static void make_dir(const char *path)
{
	if (mkdir(path, 0700) != 0 && errno != EEXIST) {
		printf("could not make %s: %s\n", path, strerror(errno));
		exit(1);
	}
}

static void write_program(const char *path, const char *body)
{
	if (!testdir_write(path, body, strlen(body)) || chmod(path, (mode_t)0755) != 0) {
		printf("could not write the fixture program %s\n", path);
		exit(1);
	}
}

static void write_secret(const char *name, const char *body)
{
	char path[512];

	(void)snprintf(path, sizeof(path), "%s/%s", secrets_dir, name);
	if (!testdir_write(path, body, strlen(body)) || chmod(path, (mode_t)0600) != 0) {
		printf("could not write the fixture secret %s\n", path);
		exit(1);
	}
}

/* ================================================ what this file may kill */

/*
 * Every pid this file is responsible for, and nothing else.
 *
 * A supplicant netcfgd started is not this process' child -- the wrapper
 * backgrounded it and exited -- so there is no `waitpid` to do and no group to
 * signal. What there is, is the number, recorded when it was seen, which is
 * the only thing that makes a kill here defensible.
 */
#define OURS_MAX 8

static pid_t ours[OURS_MAX];
static size_t ours_count;

/* The last fake this file started itself, for the one check that needs to
 * point a record at a process that is not netcfgd's. */
static pid_t last_fake;

static void remember(pid_t pid)
{
	size_t at;

	if (pid <= 0) {
		return;
	}
	for (at = 0; at < ours_count; at++) {
		if (ours[at] == pid) {
			return;
		}
	}
	if (ours_count < OURS_MAX) {
		ours[ours_count++] = pid;
	}
}

static void stop_ours(void)
{
	size_t at;

	for (at = 0; at < ours_count; at++) {
		if (ours[at] <= 0) {
			continue;
		}
		(void)kill(ours[at], SIGTERM);
	}
	pause_briefly();
	for (at = 0; at < ours_count; at++) {
		if (ours[at] <= 0) {
			continue;
		}
		/*
		 * **The group before the pid**, which a `SIGKILL` makes necessary: a
		 * `SIGTERM` is forwarded by anything in front of the real process and
		 * a `SIGKILL` is not, so killing a `timeout` on its own leaves what it
		 * was bounding reparented to init. Every pid here leads a group of its
		 * own -- the ones this file forked put themselves in one before the
		 * exec, and the ones read out of netcfgd's pid files called `setsid`
		 * -- so this reaches that group and nothing else.
		 */
		(void)kill(-ours[at], SIGKILL);
		(void)kill(ours[at], SIGKILL);
		/* Reaped where it happens to be a child of this process, and
		 * harmlessly refused where it is not. */
		(void)waitpid(ours[at], NULL, WNOHANG);
		ours[at] = 0;
	}
	ours_count = 0;
}

/* The pid netcfgd's own record names, remembered so it can be taken down. */
static pid_t recorded_pid(const char *iface)
{
	char  path[512];
	char *body;
	pid_t pid = 0;

	if (!ncfg_supplicant_pid_path(run_dir, iface, path, sizeof(path), NULL, 0)) {
		return 0;
	}
	body = testdir_read(path, NULL);
	if (body) {
		pid = (pid_t)atoi(body);
		free(body);
	}
	remember(pid);
	return pid;
}

/*
 * A supplicant netcfgd did **not** start, for the one check that needs one.
 *
 * Defined below, beside the rest of the process handling; declared here
 * because the check that uses it reads better where it belongs in the order.
 */
static int start_fake(const char *const *argument, size_t argument_count,
    const char *socket_path);

/* ===================================================== the fixture programs */

/*
 * The wrapper netcfgd is pointed at.
 *
 * It is the *shape* of a `wpa_supplicant` command line that is under test
 * here, so the wrapper refuses a flag it does not know rather than ignoring
 * it: a flag netcfgd starts passing that a fake silently swallows is a flag no
 * check covers, which is `fake_supplicant.py`'s own reason for not using
 * getopt.
 */
static void write_wrapper(void)
{
	char body[4096];

	(void)snprintf(body, sizeof(body),
	    "#!/bin/sh\n"
	    "# netcfgd's own argv, verbatim, before anything else.\n"
	    ": > '%s'\n"
	    "for one in \"$@\"; do printf '%%s\\n' \"$one\" >> '%s'; done\n"
	    "# The three paths this script needs, read out of that same argv rather\n"
	    "# than passed in: the layout is what is under test, so knowing it twice\n"
	    "# would be a fixture that agrees with itself.\n"
	    "iface= ctrl= pidfile= prev=\n"
	    "for one in \"$@\"; do\n"
	    "  case \"$prev\" in\n"
	    "    -i) iface=$one ;;\n"
	    "    -C) ctrl=$one ;;\n"
	    "    -P) pidfile=$one ;;\n"
	    "  esac\n"
	    "  prev=$one\n"
	    "done\n"
	    "# The repository's fake, given netcfgd's command line unaltered -- so the\n"
	    "# flag parser that refuses anything it does not know is the fake's own.\n"
	    "python3 '%s' \"$@\" >> '%s' 2>&1 || exit $?\n"
	    "# **`-B` returns only once the control interface is up**, which is what a\n"
	    "# stop relies on and what a real supplicant promises. The fake forks\n"
	    "# before it binds, so the promise is kept here. Waited for rather than\n"
	    "# slept on, and bounded.\n"
	    "waited=0\n"
	    "while [ \"$waited\" -lt 600 ]; do\n"
	    "  if [ -S \"$ctrl/$iface\" ]; then break; fi\n"
	    "  waited=$((waited + 1))\n"
	    "  sleep 0.01\n"
	    "done\n"
	    "if [ ! -S \"$ctrl/$iface\" ]; then\n"
	    "  echo 'fake-wpa-supplicant: the control socket never appeared' >&2\n"
	    "  exit 1\n"
	    "fi\n"
	    "# And the backstop, which is the only thing outside this run that can\n"
	    "# end a fake that has called setsid(). The pid reaches it in the\n"
	    "# environment rather than in its argv, because an argv carrying that\n"
	    "# path is exactly what netcfgd reads as `this process is mine`.\n"
	    "if [ -n \"$pidfile\" ]; then\n"
	    "  NCFG_TEST_PIDFILE=$pidfile '%s' >/dev/null 2>&1 &\n"
	    "fi\n"
	    "exit 0\n",
	    recorded_argv, recorded_argv, script, fake_output, reaper);
	write_program(wrapper, body);
}

/*
 * What ends a fake this run started, whatever becomes of this process.
 *
 * `wpa_supplicant -B` forks and calls `setsid`, and so does the fake: it is
 * then outside every bound a parent could put on it, and `timeout` in front of
 * it would bound the wrong process. So the bound is this, and it is the one
 * shape allowed here -- **it waits on one pid it read out of a file netcfgd
 * wrote, and signals that pid and nothing else.** Never a name, never a
 * pattern.
 *
 * Both loops are counted, so it ends whatever happens: it gives up waiting for
 * a pid to appear, and it gives up waiting for that pid to go.
 */
static void write_reaper(void)
{
	write_program(reaper,
	    "#!/bin/sh\n"
	    "# The pid, read once and not waited for. The wrapper does not start\n"
	    "# this until the control socket is up and the supplicant writes its\n"
	    "# pid before it binds, so a file that is not there now is one that\n"
	    "# never will be -- or one a stop has already taken away, which is the\n"
	    "# same answer. A grace period here would be a process sitting on a\n"
	    "# directory the run has already removed, which is measured: it was\n"
	    "# twenty seconds of one doing nothing.\n"
	    "pid=$(cat \"$NCFG_TEST_PIDFILE\" 2>/dev/null)\n"
	    "if [ -z \"$pid\" ]; then exit 0; fi\n"
	    "# **The record going is the run being over**, and it is the condition\n"
	    "# to watch rather than the pid alone: a stop takes the file away and a\n"
	    "# finished run takes the whole directory, while `kill -0` against a\n"
	    "# number that has been recycled goes on answering yes. Measured -- two\n"
	    "# of these sat in this loop across three consecutive runs with the\n"
	    "# supplicants they guarded long gone. Where the run really did die\n"
	    "# without cleaning up, the file is still there and this still guards.\n"
	    "waited=0\n"
	    "while [ \"$waited\" -lt 300 ]; do\n"
	    "  if [ ! -e \"$NCFG_TEST_PIDFILE\" ]; then exit 0; fi\n"
	    "  if ! kill -0 \"$pid\" 2>/dev/null; then exit 0; fi\n"
	    "  sleep 1\n"
	    "  waited=$((waited + 1))\n"
	    "done\n"
	    "kill \"$pid\" 2>/dev/null\n"
	    "exit 0\n");
}

/* A supplicant that will not start, in the words a real one uses: an interface
 * that is not there is `Could not read interface <name> flags: No such
 * device`, and `Failed to initialize interface` follows it. */
static void write_refuser(void)
{
	write_program(refuser,
	    "#!/bin/sh\n"
	    "echo \"Could not read interface $5 flags: No such device\" >&2\n"
	    "echo 'Failed to initialize interface' >&2\n"
	    "exit 255\n");
}

/* What netcfgd's command line was, one argument per line. */
static char *argv_seen(void)
{
	char *body = testdir_read(recorded_argv, NULL);

	return body ? body : strdup("");
}

static int argv_carries(const char *one)
{
	char *body = argv_seen();
	char *at = body;
	int   found = 0;

	while ((at = strstr(at, one)) != NULL) {
		int starts = at == body || at[-1] == '\n';
		int ends = at[strlen(one)] == '\n' || at[strlen(one)] == '\0';

		if (starts && ends) {
			found = 1;
			break;
		}
		at += strlen(one);
	}
	free(body);
	return found;
}

/* ============================================================ the fixtures */

static ncfg_document_t           fixture;
static ncfg_device_t             fixture_device;
static ncfg_wifi_device_policy_t fixture_wifi;
static ncfg_wifi_network_t       fixture_network;
static ncfg_interface_t          fixture_interfaces[2];
static ncfg_eap_config_t         fixture_eap;
static ncfg_secret_ref_t         fixture_password;

/*
 * One radio with one WPA2 network, and one wired port with 802.1X.
 *
 * Both credentials are the canary, because both reach a control socket through
 * different code -- `add_network` and `configure_wired` -- and 10.163 records
 * the Rust leaking through each of them in the same sentence.
 */
static void a_document(void)
{
	memset(&fixture, 0, sizeof(fixture));
	memset(&fixture_device, 0, sizeof(fixture_device));
	memset(&fixture_wifi, 0, sizeof(fixture_wifi));
	memset(&fixture_network, 0, sizeof(fixture_network));
	memset(fixture_interfaces, 0, sizeof(fixture_interfaces));
	memset(&fixture_eap, 0, sizeof(fixture_eap));
	memset(&fixture_password, 0, sizeof(fixture_password));

	fixture_wifi.mac_policy = NCFG_MAC_POLICY_PERMANENT;
	fixture_wifi.scan_randomization = 1;
	fixture_wifi.autoconnect = 1;
	fixture_device.name = text("wlan-test0");
	fixture_device.managed = 1;
	fixture_device.wifi = &fixture_wifi;
	fixture.devices = &fixture_device;
	fixture.device_count = 1u;

	fixture_network.id = text("home");
	fixture_network.ssid.has = 1;
	fixture_network.ssid.length = 4u;
	memcpy(fixture_network.ssid.bytes, "Cafe", 4u);
	fixture_network.autoconnect = 1;
	fixture_network.security.kind = NCFG_SECURITY_PSK;
	fixture_network.security.psk.proto = NCFG_PSK_PROTO_WPA2;
	fixture_network.security.psk.passphrase.provider = NCFG_SECRET_PROVIDER_FILE;
	fixture_network.security.psk.passphrase.name = text("canary");
	fixture.networks = &fixture_network;
	fixture.network_count = 1u;

	fixture_password.provider = NCFG_SECRET_PROVIDER_FILE;
	fixture_password.name = text("canary");
	fixture_eap.method = NCFG_EAP_METHOD_PEAP;
	fixture_eap.identity = text("port@example.test");
	fixture_eap.password = &fixture_password;

	fixture_interfaces[0].name = text("wlan-test0");
	fixture_interfaces[1].name = text("eth-test0");
	fixture_interfaces[1].dot1x = &fixture_eap;
	fixture.interfaces = fixture_interfaces;
	fixture.interface_count = 2u;
}

static ncfg_secret_resolver_t resolver;

static ncfg_service_t a_context(void)
{
	ncfg_service_t service;

	memset(&service, 0, sizeof(service));
	service.run_dir = run_dir;
	service.supplicant_dir = ctrl_dir;
	service.document = &fixture;
	service.secrets = &resolver;
	service.supplicant_program = wrapper;
	/* Short, because two checks below deliberately drive something that will
	 * not answer and the thing waiting behind a real one is the reconcile
	 * loop. */
	service.patience_ms = 400;
	return service;
}

/* ================================================================= checks */

static void the_paths_are_the_mark(void)
{
	char path[NCFG_SUPPLICANT_PATH_MAX];
	char want[NCFG_SUPPLICANT_PATH_MAX];
	char message[NCFG_ERROR_MAX];
	char small[8];

	printf("\n-- the paths, which are the mark\n");
	(void)snprintf(want, sizeof(want), "%s/supplicant/wlan-test0.pid", run_dir);
	message[0] = '\0';
	check(ncfg_supplicant_pid_path(run_dir, "wlan-test0", path, sizeof(path), message,
	    sizeof(message)) && strcmp(path, want) == 0,
	    "the pid file is `<run>/supplicant/<iface>.pid`, which `-P` names");
	(void)snprintf(want, sizeof(want), "%s/supplicant/wlan-test0.log", run_dir);
	check(ncfg_supplicant_log_path(run_dir, "wlan-test0", path, sizeof(path), message,
	    sizeof(message)) && strcmp(path, want) == 0,
	    "  and the launch log sits beside it");
	/* Truncation is a failure and not a shorter path: every caller is about to
	 * write to it or compare against it, and a path that lost its last
	 * component names a different file. */
	message[0] = '\0';
	refused(ncfg_supplicant_pid_path(run_dir, "wlan-test0", small, sizeof(small), message,
	    sizeof(message)), message, "longer",
	    "a path that would not fit is a failure rather than a shorter one");
}

static void the_command_line_is_what_a_supplicant_is_started_with(void)
{
	ncfg_supplicant_args_t args;
	char                   message[NCFG_ERROR_MAX];
	char                   joined[512];
	size_t                 at;

	printf("\n-- the command line\n");
	message[0] = '\0';
	check(recorded(ncfg_supplicant_arguments("/usr/sbin/wpa_supplicant",
	    NCFG_SUPPLICANT_DRIVER_RADIO, "wlan-test0", "/run/wpa_supplicant",
	    "/run/netcfgd/supplicant/wlan-test0.pid", &args, message, sizeof(message)), message),
	    "a radio's command line is built");
	joined[0] = '\0';
	for (at = 0; at < args.count; at++) {
		(void)strncat(joined, args.argv[at], sizeof(joined) - strlen(joined) - 1u);
		(void)strncat(joined, " ", sizeof(joined) - strlen(joined) - 1u);
	}
	check(strcmp(joined, "/usr/sbin/wpa_supplicant -B -Dnl80211,wext -s -i wlan-test0 -C "
	    "/run/wpa_supplicant -P /run/netcfgd/supplicant/wlan-test0.pid ") == 0,
	    "  exactly, and in this order");
	if (strcmp(joined, "/usr/sbin/wpa_supplicant -B -Dnl80211,wext -s -i wlan-test0 -C "
	    "/run/wpa_supplicant -P /run/netcfgd/supplicant/wlan-test0.pid ") != 0) {
		printf("    (it said: %s)\n", joined);
	}
	check(args.argv[args.count] == NULL, "  NULL-terminated, which is what `execv` reads");
	/* **No `-c`, and not an empty one.** 0015: `-C` supplies the control
	 * interface, so a configuration file has nothing to be needed for, and one
	 * that does not exist cannot be edited by anything else. */
	check(strstr(joined, " -c ") == NULL,
	    "  and carries no configuration file at all, which is 0015 as a flag");
	check(strstr(joined, " -s ") != NULL,
	    "  and `-s`, without which a daemonised supplicant logs nowhere at all");

	message[0] = '\0';
	refused(ncfg_supplicant_arguments("/usr/sbin/wpa_supplicant", NULL, "wlan-test0",
	    "/run/wpa_supplicant", "/run/netcfgd/supplicant/wlan-test0.pid", &args, message,
	    sizeof(message)), message, "wired",
	    "a command line with no driver is refused, naming both of them");
	message[0] = '\0';
	refused(ncfg_supplicant_arguments(NULL, NCFG_SUPPLICANT_DRIVER_WIRED, "eth-test0",
	    "/run/wpa_supplicant", "/run/netcfgd/supplicant/eth-test0.pid", &args, message,
	    sizeof(message)), message, "program",
	    "and one with no program says which piece is missing");
}

/*
 * The whole of a start: the program runs with the argv netcfgd built, the
 * supplicant that comes up is netcfgd's by the mark it carries, and it is
 * already holding the document's networks when the action returns.
 */
static void a_start_runs_the_program_and_fills_what_it_started(void)
{
	ncfg_service_t service = a_context();
	char           message[NCFG_ERROR_MAX];
	char           digest[512];
	char          *held;
	pid_t          started;

	printf("\n-- a radio's supplicant, started and filled\n");
	message[0] = '\0';
	check(recorded(ncfg_service_backend_start(&service, NCFG_BACKEND_SUPPLICANT, "wlan-test0",
	    message, sizeof(message)), message),
	    "backend.start on a radio starts a supplicant");
	if (message[0] != '\0') {
		printf("    (it said: %s)\n", message);
	}
	check(argv_carries("-B") && argv_carries("-s") && argv_carries("wlan-test0"),
	    "  with the flags a real one needs");
	check(argv_carries("-D" NCFG_SUPPLICANT_DRIVER_RADIO),
	    "  and `nl80211`, because the document calls this device a radio");
	check(argv_carries(ctrl_dir), "  pointed at the control directory it was given");

	started = recorded_pid("wlan-test0");
	check(started > 0, "the supplicant wrote the pid netcfgd named on its command line");
	check(ncfg_supplicant_running_pid(run_dir, "wlan-test0") == started,
	    "  and netcfgd recognises it by the `-P` path in its own argv");

	/*
	 * **Filling it is part of starting it**, which is the property this whole
	 * arm exists for: a start that returned with an empty supplicant would be
	 * reporting a radio configured that holds no credentials. The digest is
	 * what the next observation compares, and it is only written after the
	 * last network was handed over.
	 */
	message[0] = '\0';
	check(recorded(ncfg_service_networks_record_path(run_dir, "wlan-test0", digest, sizeof(digest),
	    message, sizeof(message)), message), "the digest of what it was handed has a path");
	held = testdir_read(digest, NULL);
	check(held != NULL && strlen(held) == 64u,
	    "  and a start leaves one written, so the supplicant was populated by it");
	free(held);
}

/* 0140, against a supplicant this really started: the run directory goes and
 * the process does not. */
static void a_handle_survives_the_run_directory(void)
{
	char  path[512];
	pid_t started;
	pid_t adopted = 0;
	char  message[NCFG_ERROR_MAX];
	char *body;

	printf("\n-- the handle, after `RuntimeDirectory=` has emptied /run/netcfgd\n");
	started = recorded_pid("wlan-test0");
	if (started <= 0 || !ncfg_supplicant_pid_path(run_dir, "wlan-test0", path, sizeof(path),
	    NULL, 0)) {
		check(0, "there is a started supplicant to lose the record of");
		return;
	}
	check(unlink(path) == 0, "the pid file goes with the run directory");
	check(ncfg_supplicant_running_pid(run_dir, "wlan-test0") == 0,
	    "  so netcfgd no longer recognises its own child");
	message[0] = '\0';
	check(ncfg_supplicant_adopt(run_dir, ctrl_dir, "wlan-test0", &adopted, message,
	    sizeof(message)) && adopted == started,
	    "  and adoption finds it again by the mark it still carries");
	body = testdir_read(path, NULL);
	check(body != NULL && atoi(body) == (int)started,
	    "  writing the pid back down, which is all `adopted` means");
	free(body);
	check(ncfg_supplicant_running_pid(run_dir, "wlan-test0") == started,
	    "  so the record and the process agree again");

	adopted = -1;
	message[0] = '\0';
	check(ncfg_supplicant_adopt(run_dir, ctrl_dir, "wlan-test0", &adopted, message,
	    sizeof(message)) && adopted == 0,
	    "one already recorded is not adopted again, and is not a failure");
}

/* A process that carries the mark and answers nothing is netcfgd's and no use
 * to it, so adopting it would claim a radio netcfgd cannot drive. */
static void a_marked_process_that_answers_nothing_is_not_adopted(void)
{
	char  path[512];
	pid_t child;
	pid_t adopted = -1;
	char  message[NCFG_ERROR_MAX];

	printf("\n-- a mark is not enough on its own\n");
	if (!ncfg_supplicant_pid_path(run_dir, "wlan-silent", path, sizeof(path), NULL, 0)) {
		check(0, "the mark for a silent interface could be named");
		return;
	}
	child = fork();
	if (child < 0) {
		check(0, "a process carrying the mark could be started");
		return;
	}
	if (child == 0) {
		const char *argv[9];

		(void)setpgid(0, 0);
		argv[0] = "timeout";
		argv[1] = "-k";
		argv[2] = "2";
		argv[3] = "60";
		argv[4] = "sh";
		argv[5] = "-c";
		argv[6] = "sleep 60";
		argv[7] = path;
		argv[8] = NULL;
		execvp("timeout", (char *const *)(const void *)argv);
		_exit(127);
	}
	(void)setpgid(child, child);
	remember(child);
	/* Wait for the marker to really be in its command line rather than
	 * sleeping a fixed time. */
	{
		long long deadline = now_ms() + 3000;

		while (now_ms() < deadline &&
		    ncfg_process_pid_by_marker(path) <= 0) {
			pause_briefly();
		}
	}
	check(ncfg_process_pid_by_marker(path) > 0,
	    "a process carries netcfgd's `-P` path as a whole argument");
	message[0] = '\0';
	check(ncfg_supplicant_adopt(run_dir, ctrl_dir, "wlan-silent", &adopted, message,
	    sizeof(message)) && adopted == 0,
	    "  and is still not adopted, because nothing answers on that interface");
	check(!testdir_exists(path), "  so no record claiming it was written");
	/*
	 * **The group, and then the pid.** `timeout` runs the shell as its own
	 * child, so a `SIGKILL` to `timeout` alone leaves that shell running and
	 * reparented to init -- which is `process.h`'s sentence about a hook
	 * exactly, and was measured here: a run left `sh -c 'sleep 60'` holding
	 * this very marker with a ppid of 1. The bound held and it went at its
	 * own `sleep`, but a fixture that relies on that is one that can be left
	 * running. The child put itself in a group of its own before the exec, so
	 * this is still the pid this file recorded rather than a name or a
	 * pattern.
	 */
	(void)kill(-child, SIGKILL);
	(void)kill(child, SIGKILL);
	(void)waitpid(child, NULL, 0);
}

/* Applying a plan twice on a converged machine must not start a second
 * supplicant beside the first. */
static void a_second_start_starts_nothing(void)
{
	ncfg_service_t service = a_context();
	char           message[NCFG_ERROR_MAX];
	char           never[384];

	printf("\n-- the second apply of a converged machine\n");
	(void)snprintf(never, sizeof(never), "%s/must-not-be-run", base);
	service.supplicant_program = never;
	message[0] = '\0';
	check(recorded(ncfg_service_backend_start(&service, NCFG_BACKEND_SUPPLICANT, "wlan-test0",
	    message, sizeof(message)), message),
	    "a start against a supplicant netcfgd's record names succeeds");
	check(!testdir_exists(never),
	    "  and runs nothing: the program it was pointed at is not even there");
}

/* 0125 and 0140: netcfgd does not take a radio from a manager that is still
 * running. */
static void a_supplicant_somebody_else_is_answering_is_declined(void)
{
	ncfg_service_t service = a_context();
	char           message[NCFG_ERROR_MAX];
	char           socket_path[512];
	const char    *argument[2];

	printf("\n-- a radio another manager is holding\n");
	fixture_device.name = text("wlan-other");
	argument[0] = ctrl_dir;
	argument[1] = "wlan-other";
	(void)snprintf(socket_path, sizeof(socket_path), "%s/wlan-other", ctrl_dir);
	if (!start_fake(argument, 2u, socket_path)) {
		check(0, "a supplicant netcfgd did not start could be put on the radio");
		return;
	}
	/*
	 * **The mark is the `-P` path and not the interface name.** A stranger's
	 * command line carries the interface too -- this one is
	 * `fake_supplicant.py <dir> wlan-other`, where `wlan-other` is a whole
	 * argv element -- so a record pointed at it still must not read as a
	 * supplicant of netcfgd's. Loosening the marker to the interface name is
	 * the one change that would make it one, and `process.h` says why that
	 * matters: netcfgd would adopt another manager's supplicant.
	 */
	{
		char path[512];
		char number[32];

		(void)snprintf(number, sizeof(number), "%d\n", (int)last_fake);
		if (ncfg_supplicant_pid_path(run_dir, "wlan-other", path, sizeof(path), NULL,
		    0)) {
			check(testdir_write(path, number, strlen(number)),
			    "a record pointed at the other manager's process");
			check(ncfg_supplicant_running_pid(run_dir, "wlan-other") == 0,
			    "  is still not a supplicant of netcfgd's: its argv names the "
			    "interface and not the `-P` path");
			(void)unlink(path);
		}
	}
	message[0] = '\0';
	refused(ncfg_service_backend_start(&service, NCFG_BACKEND_SUPPLICANT, "wlan-other",
	    message, sizeof(message)), message, "did not start",
	    "a start declines a radio somebody else's supplicant is answering on");
	refused(0, message, "-P", "  naming the mark it looked for and did not find");
	refused(0, message, "systemctl stop wpa_supplicant",
	    "  and both units an operator has to stop on Debian");
	check(testdir_exists(socket_path),
	    "  leaving the other manager's socket exactly where it was");
	/* Nothing should have been started here -- that is the check above -- but a
	 * fixture is also the thing sabotage is run against, and a run that *does*
	 * start one has to be able to take it down by the pid it recorded. */
	(void)recorded_pid("wlan-other");
	check(strlen(message) < NCFG_ERROR_MAX - 1u,
	    "  and saying all of it: a refusal `err` truncated loses the advice at the end");
	fixture_device.name = text("wlan-test0");
}

/* 0080: a supplicant that *died* leaves its socket behind, and that one is
 * cleared rather than declined -- which is the case the refusal above must not
 * swallow. */
static void a_socket_nothing_answers_is_cleared(void)
{
	ncfg_service_t service = a_context();
	char           message[NCFG_ERROR_MAX];
	char           socket_path[512];
	struct stat    about;

	printf("\n-- a socket a dead supplicant left behind\n");
	(void)snprintf(socket_path, sizeof(socket_path), "%s/wlan-stale", ctrl_dir);
	check(testdir_write(socket_path, "not a socket\n", 13u),
	    "a control socket path with nothing behind it");
	message[0] = '\0';
	check(recorded(ncfg_service_backend_start(&service, NCFG_BACKEND_SUPPLICANT, "wlan-stale",
	    message, sizeof(message)) == 0, message),
	    "starting there fails, because the document names no such radio");
	refused(0, message, "neither a wired 802.1X port nor a radio",
	    "  and says so rather than picking a driver by elimination");
	/* And with a document that does describe it, the stale file goes and the
	 * supplicant comes up in its place. */
	fixture_device.name = text("wlan-stale");
	message[0] = '\0';
	check(recorded(ncfg_service_backend_start(&service, NCFG_BACKEND_SUPPLICANT, "wlan-stale",
	    message, sizeof(message)), message),
	    "a radio the document does describe gets one started there");
	if (message[0] != '\0') {
		printf("    (it said: %s)\n", message);
	}
	check(lstat(socket_path, &about) == 0 && S_ISSOCK(about.st_mode),
	    "  the stale file having been removed and a real socket bound in its place");
	(void)recorded_pid("wlan-stale");
	fixture_device.name = text("wlan-test0");
}

/* A supplicant that will not start says why, and where the rest of it is. */
static void a_program_that_refuses_says_why_and_where(void)
{
	ncfg_service_t service = a_context();
	char           message[NCFG_ERROR_MAX];
	char           log[512];
	char          *body;

	printf("\n-- a supplicant that would not start\n");
	service.supplicant_program = refuser;
	fixture_device.name = text("wlan-refuse");
	message[0] = '\0';
	refused(ncfg_service_backend_start(&service, NCFG_BACKEND_SUPPLICANT, "wlan-refuse",
	    message, sizeof(message)), message, "No such device",
	    "a start quotes what the supplicant said rather than only its status");
	refused(0, message, "Its output is in", "  and says where the rest of it is");
	check(ncfg_supplicant_log_path(run_dir, "wlan-refuse", log, sizeof(log), NULL, 0),
	    "the log has a path under the run directory");
	body = testdir_read(log, NULL);
	check(body != NULL && strstr(body, "Failed to initialize interface") != NULL,
	    "  and holds what it said before it would have forked");
	free(body);
	fixture_device.name = text("wlan-test0");

	/* And a program that is not there at all is a different sentence. */
	{
		char absent[384];

		(void)snprintf(absent, sizeof(absent), "%s/no-such-supplicant", base);
		service.supplicant_program = absent;
		fixture_device.name = text("wlan-absent");
		message[0] = '\0';
		refused(ncfg_service_backend_start(&service, NCFG_BACKEND_SUPPLICANT,
		    "wlan-absent", message, sizeof(message)), message, "could not run",
		    "and a program that is not there says that instead");
		fixture_device.name = text("wlan-test0");
	}
}

/* The wired half: the same process under another name, and the one thing that
 * must not be shared with the radio. */
static void a_wired_port_is_started_with_the_other_driver(void)
{
	ncfg_service_t service = a_context();
	char           message[NCFG_ERROR_MAX];

	printf("\n-- a wired 802.1X port\n");
	message[0] = '\0';
	check(recorded(ncfg_service_backend_start(&service, NCFG_BACKEND_SUPPLICANT, "eth-test0",
	    message, sizeof(message)), message),
	    "backend.start on a `dot1x` interface starts a supplicant");
	if (message[0] != '\0') {
		printf("    (it said: %s)\n", message);
	}
	check(argv_carries("-D" NCFG_SUPPLICANT_DRIVER_WIRED),
	    "  with `wired`, because `WPA-EAP` on a wired port authenticates nothing");
	check(argv_carries("eth-test0"), "  and the interface it was asked about");
	check(recorded_pid("eth-test0") > 0, "  and it recorded its pid where `-P` said");
}

/* The stop, which is the inverse `backend.start` declares. */
static void a_stop_goes_through_the_socket(void)
{
	ncfg_service_t service = a_context();
	char           message[NCFG_ERROR_MAX];
	char           path[512];
	char           socket_path[512];
	long long      deadline;
	pid_t          running = recorded_pid("wlan-test0");

	printf("\n-- stopping one\n");
	(void)snprintf(socket_path, sizeof(socket_path), "%s/wlan-test0", ctrl_dir);
	message[0] = '\0';
	check(recorded(ncfg_service_backend_stop(&service, NCFG_BACKEND_SUPPLICANT, "wlan-test0",
	    message, sizeof(message)), message),
	    "backend.stop sends TERMINATE over the control socket");
	if (message[0] != '\0') {
		printf("    (it said: %s)\n", message);
	}
	check(ncfg_supplicant_pid_path(run_dir, "wlan-test0", path, sizeof(path), NULL, 0) &&
	    !testdir_exists(path),
	    "  and the pid file goes with it, so 0080 cannot recur");
	deadline = now_ms() + 3000;
	while (running > 0 && now_ms() < deadline && kill(running, 0) == 0) {
		pause_briefly();
	}
	check(running > 0 && kill(running, 0) != 0 && errno == ESRCH,
	    "  and the supplicant it was told to stop has gone");

	/* Nothing running is the state the op was asked to produce. */
	message[0] = '\0';
	check(recorded(ncfg_service_backend_stop(&service, NCFG_BACKEND_SUPPLICANT, "wlan-nothing",
	    message, sizeof(message)), message),
	    "stopping one that was never there is success and not an error");

	/* **But only nothing running.** A socket that is there and silent is a
	 * different state and gets a different answer, which is 0109 and is kept in
	 * step with the access point's stop deliberately. */
	(void)snprintf(socket_path, sizeof(socket_path), "%s/wlan-wedged", ctrl_dir);
	check(testdir_write(socket_path, "silent\n", 7u), "a control socket that says nothing");
	message[0] = '\0';
	refused(ncfg_service_backend_stop(&service, NCFG_BACKEND_SUPPLICANT, "wlan-wedged",
	    message, sizeof(message)), message, "did not answer",
	    "  and a stop over it fails rather than reporting a radio released");
}

static void nothing_here_has_a_default(void)
{
	ncfg_service_t service;
	char           message[NCFG_ERROR_MAX];
	const char    *driver = NULL;

	printf("\n-- nothing here has a default\n");
	message[0] = '\0';
	refused(ncfg_supplicant_start(NULL, ctrl_dir, "wlan-test0",
	    NCFG_SUPPLICANT_DRIVER_RADIO, wrapper, message, sizeof(message)), message,
	    "run directory", "a start with no run directory is refused by name");
	message[0] = '\0';
	refused(ncfg_supplicant_start(run_dir, NULL, "wlan-test0",
	    NCFG_SUPPLICANT_DRIVER_RADIO, wrapper, message, sizeof(message)), message,
	    "control directory", "and one with nowhere to put the control socket");

	service = a_context();
	service.supplicant_dir = NULL;
	message[0] = '\0';
	refused(ncfg_service_backend_start(&service, NCFG_BACKEND_SUPPLICANT, "wlan-test0",
	    message, sizeof(message)), message, "no default",
	    "an executor with no control directory refuses rather than reaching for one");
	message[0] = '\0';
	refused(ncfg_service_backend_stop(&service, NCFG_BACKEND_SUPPLICANT, "wlan-test0",
	    message, sizeof(message)), message, "no default",
	    "  and so does the stop, which would otherwise signal the machine's own");

	service = a_context();
	service.document = NULL;
	message[0] = '\0';
	refused(ncfg_service_backend_start(&service, NCFG_BACKEND_SUPPLICANT, "wlan-test0",
	    message, sizeof(message)), message, "which driver",
	    "and an executor with no document will not guess a driver");

	message[0] = '\0';
	refused(ncfg_service_supplicant_driver(&fixture, "br-lan", &driver, message,
	    sizeof(message)), message, "neither a wired 802.1X port nor a radio",
	    "an interface the document describes as neither is refused, naming both blocks");
	message[0] = '\0';
	check(ncfg_service_supplicant_driver(&fixture, "eth-test0", &driver, message,
	    sizeof(message)) && strcmp(driver, NCFG_SUPPLICANT_DRIVER_WIRED) == 0,
	    "a `dot1x` interface answers `wired`, before the radio question is asked");
	check(ncfg_service_supplicant_driver(&fixture, "wlan-test0", &driver, message,
	    sizeof(message)) && strcmp(driver, NCFG_SUPPLICANT_DRIVER_RADIO) == 0,
	    "  and a device with a `wifi` section answers `nl80211`");
	/*
	 * **And the order between them, which is the planner's.** An interface
	 * carrying `dot1x` has said what its supplicant is for, and
	 * `ncfg_plan_radio_supplicant` returns without planning anything for it --
	 * so an interface that is both has to answer `wired` here as well, or the
	 * process the planner asked for and the process this starts are two
	 * different things.
	 *
	 * Found by sabotage: swapping the two lookups over turned nothing red
	 * until this case existed, because no fixture had an interface in both
	 * states.
	 */
	fixture_interfaces[0].dot1x = &fixture_eap;
	message[0] = '\0';
	check(ncfg_service_supplicant_driver(&fixture, "wlan-test0", &driver, message,
	    sizeof(message)) && strcmp(driver, NCFG_SUPPLICANT_DRIVER_WIRED) == 0,
	    "  and one that is both answers `wired`, which is the order the planner takes");
	fixture_interfaces[0].dot1x = NULL;
}

static void this_build_says_it_can_do_it(void)
{
	ncfg_op_t op;
	char      message[NCFG_ERROR_MAX];

	printf("\n-- what this build says it carries out\n");
	memset(&op, 0, sizeof(op));
	op.kind = NCFG_OP_BACKEND_START;
	op.u.backend.kind = (int)NCFG_BACKEND_SUPPLICANT;
	op.u.backend.iface = "wlan-test0";
	message[0] = '\0';
	check(recorded(ncfg_apply_supported(&op, message, sizeof(message)), message),
	    "`backend.start` on a supplicant is carried out rather than refused");
	op.kind = NCFG_OP_BACKEND_STOP;
	message[0] = '\0';
	check(recorded(ncfg_apply_supported(&op, message, sizeof(message)), message),
	    "  and so is `backend.stop`, which is the inverse the start declares");
	op.kind = NCFG_OP_BACKEND_RELOAD;
	message[0] = '\0';
	refused(ncfg_apply_supported(&op, message, sizeof(message)), message, "reload",
	    "  and a reload is still refused: a supplicant has none");
}

/* =========================================================== the canary */

/*
 * **Non-vacuity, from the credential's end.**
 *
 * The exact function `add_network` renders each command with is asked for the
 * line that carries the passphrase, and the canary is asserted to be *in* it.
 * Without this the silences below would pass just as loudly on a fixture whose
 * network had stopped carrying a credential at all -- which is the shape
 * 10.163 records: a redaction with a test, and a composed sentence without
 * one.
 */
static size_t the_credential_really_is_in_what_is_sent(void)
{
	ncfg_supplicant_settings_t settings;
	char                       message[NCFG_ERROR_MAX];
	size_t                     carried = 0;
	size_t                     at;

	printf("\n-- the canary, and the proof that the sweep is not vacuous\n");
	memset(&settings, 0, sizeof(settings));
	message[0] = '\0';
	if (!recorded(ncfg_supplicant_settings(&fixture_network, NULL,
	    NCFG_MAC_POLICY_PERMANENT, &resolver, &settings, message, sizeof(message)),
	    message)) {
		check(0, "the fixture network can be expressed at all");
		return 0;
	}
	for (at = 0; at < settings.count; at++) {
		ncfg_buf_t line;
		ncfg_buf_t shown;

		ncfg_buf_init(&line, 1024u);
		message[0] = '\0';
		if (recorded(ncfg_supplicant_setting_command(&settings.items[at], 0u, &resolver,
		    &line, message, sizeof(message)), message)) {
			if (strstr(ncfg_buf_text(&line), CANARY) != NULL) {
				carried++;
			}
		}
		ncfg_supplicant_buf_wipe(&line);

		/* And the form a message may quote resolves nothing. */
		ncfg_buf_init(&shown, 1024u);
		ncfg_supplicant_setting_redacted(&settings.items[at], 0u, &shown);
		check(strstr(ncfg_buf_text(&shown), CANARY) == NULL,
		    at == 0u ? "the redacted form of a setting carries no material" : "  nor any "
		    "of the others");
		ncfg_buf_free(&shown);
	}
	ncfg_supplicant_settings_free(&settings);
	check(carried > 0,
	    "the line this population really sends does carry the credential");
	printf("    (%zu of the network's settings rendered it)\n", carried);
	return carried;
}

/* ================================================================== main */

/* Started here rather than by netcfgd: a supplicant netcfgd did not start, for
 * the one check that needs one. `timeout` is the outer bound and is not a
 * courtesy -- a test binary killed part way through must not leave a python
 * process holding a socket, and the only thing that can promise that is
 * something outside this process. */
static int start_fake(const char *const *argument, size_t argument_count,
    const char *socket_path)
{
	const char *argv[12];
	size_t      at = 0;
	size_t      which;
	long long   deadline;
	pid_t       child;

	if (argument_count + 7u > sizeof(argv) / sizeof(argv[0])) {
		return 0;
	}
	argv[at++] = "timeout";
	argv[at++] = "-k";
	argv[at++] = "2";
	argv[at++] = "120";
	argv[at++] = "python3";
	argv[at++] = script;
	for (which = 0; which < argument_count; which++) {
		argv[at++] = argument[which];
	}
	argv[at] = NULL;
	child = fork();
	if (child < 0) {
		return 0;
	}
	if (child == 0) {
		int log = open(fake_output, O_WRONLY | O_CREAT | O_APPEND, 0600);

		(void)setpgid(0, 0);
		if (log >= 0) {
			(void)dup2(log, STDOUT_FILENO);
			(void)dup2(log, STDERR_FILENO);
			(void)close(log);
		}
		execvp("timeout", (char *const *)(const void *)argv);
		_exit(127);
	}
	(void)setpgid(child, child);
	remember(child);
	last_fake = child;
	deadline = now_ms() + 5000;
	while (now_ms() < deadline) {
		if (testdir_exists(socket_path)) {
			return 1;
		}
		pause_briefly();
	}
	return 0;
}

int main(int argc, char **argv)
{
	const char *fakes = (argc > 1) ? argv[1] : "../tests/live";
	int         stderr_copy;
	char       *sweep;
	size_t      carried;

	(void)testdir_make("suplaunch");
	(void)snprintf(base, sizeof(base), "%s", testdir_path);
	(void)snprintf(run_dir, sizeof(run_dir), "%s/run", base);
	(void)snprintf(ctrl_dir, sizeof(ctrl_dir), "%s/ctrl", base);
	(void)snprintf(secrets_dir, sizeof(secrets_dir), "%s/secrets", base);
	(void)snprintf(wrapper, sizeof(wrapper), "%s/fake-wpa-supplicant", base);
	(void)snprintf(refuser, sizeof(refuser), "%s/refusing-supplicant", base);
	(void)snprintf(reaper, sizeof(reaper), "%s/reaper", base);
	(void)snprintf(recorded_argv, sizeof(recorded_argv), "%s/argv", base);
	(void)snprintf(fake_output, sizeof(fake_output), "%s/fake.out", base);
	(void)snprintf(stderr_path, sizeof(stderr_path), "%s/stderr", base);
	(void)snprintf(script, sizeof(script), "%s/fake_supplicant.py", fakes);
	make_dir(run_dir);
	make_dir(ctrl_dir);
	make_dir(secrets_dir);

	if (!testdir_exists(script)) {
		/* Not skipped. A suite that carried on here would report success for a
		 * run that checked a launch against nothing at all. */
		printf("the repository's fake supplicant is not at `%s`; pass its directory "
		    "as the first argument\n", script);
		testdir_remove(testdir_path);
		return 1;
	}
	write_reaper();
	write_wrapper();
	write_refuser();
	write_secret("canary", CANARY);
	resolver.secrets_dir = secrets_dir;
	resolver.materialise_dir = base;
	a_document();

	/* Everything this process writes to standard error, kept so the sweep can
	 * read it back. Restored before anything is printed about it. */
	stderr_copy = dup(STDERR_FILENO);
	{
		int redirected = open(stderr_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);

		if (redirected >= 0) {
			(void)dup2(redirected, STDERR_FILENO);
			(void)close(redirected);
		}
	}

	the_paths_are_the_mark();
	the_command_line_is_what_a_supplicant_is_started_with();
	a_start_runs_the_program_and_fills_what_it_started();
	a_handle_survives_the_run_directory();
	a_marked_process_that_answers_nothing_is_not_adopted();
	a_second_start_starts_nothing();
	a_supplicant_somebody_else_is_answering_is_declined();
	a_socket_nothing_answers_is_cleared();
	a_program_that_refuses_says_why_and_where();
	a_wired_port_is_started_with_the_other_driver();
	a_stop_goes_through_the_socket();
	nothing_here_has_a_default();
	this_build_says_it_can_do_it();
	carried = the_credential_really_is_in_what_is_sent();

	/* Everything this file started, by the pid it recorded, before the sweep
	 * so that their output is complete. */
	stop_ours();

	(void)fflush(stderr);
	if (stderr_copy >= 0) {
		(void)dup2(stderr_copy, STDERR_FILENO);
		(void)close(stderr_copy);
	}

	/* ------------------------------------------------------------- the sweep */

	check(carried > 0,
	    "the credential was rendered into what a population sends, so the rest is a proof");
	{
		size_t length = 0;
		char  *said = testdir_read(stderr_path, &length);

		check(said != NULL && strstr(said, CANARY) == NULL,
		    "nothing this module said on standard error carries the material");
		free(said);
	}
	{
		char *seen = argv_seen();

		/* **And the instrument is checked too.** The same `strstr` over the
		 * same buffer finds a string that is known to be there, so a silence
		 * below is a silence rather than an empty file. */
		check(strstr(seen, "-P") != NULL,
		    "the recorded command line is really there, which is what makes its "
		    "silence mean something");
		check(strstr(seen, CANARY) == NULL,
		    "  and no command line netcfgd built carries the material");
		free(seen);
	}
	{
		char *heard = testdir_read(fake_output, NULL);

		check(heard == NULL || strstr(heard, CANARY) == NULL,
		    "nor does anything the fake supplicant wrote");
		free(heard);
	}
	{
		char  path[512];
		char *body;

		body = ncfg_supplicant_log_path(run_dir, "wlan-test0", path, sizeof(path), NULL,
		    0) ? testdir_read(path, NULL) : NULL;
		check(body == NULL || strstr(body, CANARY) == NULL,
		    "nor the launch log netcfgd writes beside the pid file");
		free(body);
	}
	check(every_message_length > 0u && strstr(every_message, "wired") != NULL,
	    "the diagnostics this file collected are really there");
	check(strstr(every_message, CANARY) == NULL,
	    "  and none of them carries the material either");
	printf("    (%zu bytes of diagnostics were swept)\n", every_message_length);

	sweep = testdir_read(recorded_argv, NULL);
	free(sweep);
	testdir_remove(testdir_path);
	if (failures == 0) {
		printf("\nsupplicant_launch_test: all checks passed\n");
		return 0;
	}
	printf("\nsupplicant_launch_test: %d check(s) failed\n", failures);
	return 1;
}
