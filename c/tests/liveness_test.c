/*
 * liveness_test.c -- whether netcfgd can tell that a daemon it started has
 * died.
 *
 * WHAT THESE CASES DRIVE
 *   `ncfg_observe_backend_liveness` against real processes, because the
 *   question it answers is about `/proc` and the module that reads `/proc` does
 *   so at a fixed path on purpose -- `process.h` spends its header on why
 *   finding a process is a security property and not a lookup. So there is no
 *   tree to point this at, and a fake would prove the fake. Each case starts a
 *   child carrying the marker netcfgd would have given it, writes the pid file
 *   netcfgd would have written, and asks.
 *
 * WHAT MAKES THAT SAFE TO RUN ON A WORKSTATION WITH A LIVE NETWORK
 *   Every child is `timeout 20 sh -c 'sleep 20'` in a process group of its own,
 *   carrying a path under this test's own temporary directory. It configures
 *   nothing, it is bounded twice -- by `timeout` and by the `sleep` -- and the
 *   reaper below kills **the group before the pid**, because a `SIGKILL` to
 *   `timeout` alone leaves the shell it was bounding reparented to init. That
 *   is this suite's own measured lesson rather than a precaution
 *   (`supplicant_launch_test.c`, project.md).
 *
 *   The markers are absolute paths under the temporary directory, so nothing
 *   the machine is really running can match one and nothing here can match
 *   something the machine is really running. The user's own `wpa_supplicant`
 *   carries `/run/netcfgd/supplicant/wlp0s20f3.pid`; these carry
 *   `/tmp/netcfgd-liveness-XXXX/...`.
 */
#include "ncfg/observe.h"

#include "ncfg/base.h"
#include "ncfg/dhcp.h"
#include "ncfg/hostapd.h"
#include "ncfg/process.h"
#include "ncfg/supplicant.h"

#include "testdir.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int checks;
static int failures;

static void check(int condition, const char *what)
{
	checks++;
	printf("%-72s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

static const char *base;
static char        run_dir[512];

/* Every child this file started, by pid, so the reaper names them rather than
 * matching a pattern. */
#define LIVENESS_CHILDREN_MAX 8
static pid_t children[LIVENESS_CHILDREN_MAX];
static size_t child_count;

static long long now_ms(void)
{
	struct timespec when;

	(void)clock_gettime(CLOCK_MONOTONIC, &when);
	return (long long)when.tv_sec * 1000 + when.tv_nsec / 1000000;
}

static void pause_briefly(void)
{
	struct timespec nap = { 0, 5 * 1000 * 1000 };

	(void)nanosleep(&nap, NULL);
}

/*
 * A bounded child carrying `marker` as a whole `argv` element.
 *
 * `timeout` and the `sleep` are both twenty seconds, so the process goes away
 * on its own if this file's reaper never runs at all. Waits for the marker to
 * really be in the command line rather than sleeping a fixed time -- an exec
 * is not instant and a fixed sleep is either flaky or slow.
 */
static pid_t marked_child(const char *marker)
{
	pid_t     child = fork();
	long long deadline;

	if (child < 0) {
		return 0;
	}
	if (child == 0) {
		const char *argv[9];

		(void)setpgid(0, 0);
		argv[0] = "timeout";
		argv[1] = "-k";
		argv[2] = "2";
		argv[3] = "20";
		argv[4] = "sh";
		argv[5] = "-c";
		argv[6] = "sleep 20";
		argv[7] = marker;
		argv[8] = NULL;
		execvp("timeout", (char *const *)(const void *)argv);
		_exit(127);
	}
	(void)setpgid(child, child);
	if (child_count < (size_t)LIVENESS_CHILDREN_MAX) {
		children[child_count++] = child;
	}
	deadline = now_ms() + 3000;
	while (now_ms() < deadline && ncfg_process_pid_by_marker(marker) <= 0) {
		pause_briefly();
	}
	return child;
}

/* The group before the pid: `timeout` runs the shell as its own child, so a
 * `SIGKILL` to `timeout` alone leaves that shell reparented to init. */
static void reap(void)
{
	size_t at;

	for (at = 0; at < child_count; at++) {
		if (children[at] <= 0) {
			continue;
		}
		(void)kill(-children[at], SIGKILL);
		(void)kill(children[at], SIGKILL);
		(void)waitpid(children[at], NULL, 0);
		children[at] = 0;
	}
	child_count = 0;
}

/* ------------------------------------------------------------------------ *
 * Fixtures
 * ------------------------------------------------------------------------ */

/* One observation holding one backend record, as the prior state would. */
static ncfg_observed_t *observed_with(int kind, const char *iface, int running)
{
	char             text[1024];
	char             message[NCFG_ERROR_MAX];
	ncfg_observed_t *observed;

	(void)snprintf(text, sizeof(text),
	    "{\"links\":[],\"backends\":[{\"kind\":\"%s\",\"interface\":\"%s\","
	    "\"running\":%s,\"answering\":true}]}",
	    ncfg_backend_kind_name(kind), iface, running ? "true" : "false");
	message[0] = '\0';
	observed = ncfg_observed_read(text, strlen(text), message, sizeof(message));
	if (!observed) {
		printf("  fixture observation did not read: %s\n", message);
	}
	return observed;
}

/* Write the pid file netcfgd would have written for a supplicant. */
static int record_supplicant(const char *iface, pid_t pid, char *path, size_t path_size)
{
	char dir[640];
	char text[32];

	(void)snprintf(dir, sizeof(dir), "%s/supplicant", run_dir);
	testdir_mkdirp(dir);
	if (!ncfg_supplicant_pid_path(run_dir, iface, path, path_size, NULL, 0)) {
		return 0;
	}
	(void)snprintf(text, sizeof(text), "%d\n", (int)pid);
	return testdir_write(path, text, strlen(text));
}

/* Write the metric record netcfgd writes when it starts a dhcpcd client. */
static int record_metric(const char *iface, const char *text)
{
	char dir[640];
	char path[700];

	(void)snprintf(dir, sizeof(dir), "%s/dhcpcd", run_dir);
	testdir_mkdirp(dir);
	if (!ncfg_dhcp_metric_path(run_dir, iface, path, sizeof(path), NULL, 0)) {
		return 0;
	}
	return testdir_write(path, text, strlen(text));
}

/* ------------------------------------------------------------------------ *
 * The cases
 * ------------------------------------------------------------------------ */

static void a_daemon_that_is_still_there_stays_running(void)
{
	char             marker[512];
	ncfg_observed_t *observed = observed_with(NCFG_BACKEND_SUPPLICANT, "wlan-alive", 1);
	pid_t            child;
	char             message[NCFG_ERROR_MAX];

	if (!observed) {
		check(0, "the fixture for a live daemon reads");
		return;
	}
	/*
	 * The pid file has to exist before the child, because the marker *is* the
	 * pid file's path -- that is `ncfg_supplicant_running_pid`'s rule and the
	 * strongest kind of mark: netcfgd chose the path and it names the
	 * interface.
	 */
	if (!ncfg_supplicant_pid_path(run_dir, "wlan-alive", marker, sizeof(marker), NULL, 0)) {
		check(0, "the supplicant's mark could be named");
		ncfg_observed_free(observed);
		return;
	}
	child = marked_child(marker);
	check(child > 0 && record_supplicant("wlan-alive", child, marker, sizeof(marker)),
	    "a child carrying netcfgd's mark is running and recorded");
	message[0] = '\0';
	check(ncfg_observe_backend_liveness(observed, run_dir, message, sizeof(message)),
	    "the liveness round runs");
	check(observed->backend_count == 1u && observed->backends[0].running,
	    "  and a daemon that is still there is left running");
	check(observed->backend_count == 1u && observed->backends[0].answering.has &&
	    observed->backends[0].answering.value,
	    "  with what it last answered untouched, which is a different question");
	ncfg_observed_free(observed);
	reap();
}

static void a_daemon_that_has_died_stops_being_running(void)
{
	char             marker[512];
	ncfg_observed_t *observed = observed_with(NCFG_BACKEND_SUPPLICANT, "wlan-dead", 1);
	char             text[32];
	char             message[NCFG_ERROR_MAX];

	if (!observed) {
		check(0, "the fixture for a dead daemon reads");
		return;
	}
	if (!ncfg_supplicant_pid_path(run_dir, "wlan-dead", marker, sizeof(marker), NULL, 0)) {
		check(0, "the mark for a dead daemon could be named");
		ncfg_observed_free(observed);
		return;
	}
	/*
	 * **A pid file outliving the process it names is the whole case.** This is
	 * exactly what a crash leaves behind, and it is why the record alone could
	 * never answer: the file is there, the number in it is a real number, and
	 * nothing is running under it. A pid nothing owns rather than a live one
	 * belonging to somebody else -- 1 would be `init` and would test the
	 * ownership rule instead of this one.
	 */
	{
		char dir[640];

		(void)snprintf(dir, sizeof(dir), "%s/supplicant", run_dir);
		testdir_mkdirp(dir);
		(void)snprintf(text, sizeof(text), "%d\n", 0x7ffffff0);
		(void)testdir_write(marker, text, strlen(text));
	}
	message[0] = '\0';
	check(ncfg_observe_backend_liveness(observed, run_dir, message, sizeof(message)),
	    "the liveness round runs over a pid file that outlived its process");
	check(observed->backend_count == 1u && !observed->backends[0].running,
	    "  and `running` stops being netcfgd's memory of having started it");
	/*
	 * 0078 keeps `running` and `answering` apart because a wedged daemon holds
	 * its pid and serves nobody. The converse is not a question anybody can
	 * ask: a process that is gone is not answering, and a stale `true` here
	 * would let a later pass conclude that a dead hostapd is serving its LAN.
	 */
	check(observed->backend_count == 1u && observed->backends[0].answering.has &&
	    !observed->backends[0].answering.value,
	    "  and what it last answered goes with it, because nothing gone is answering");
	ncfg_observed_free(observed);
}

static void it_only_ever_clears(void)
{
	char             marker[512];
	ncfg_observed_t *observed = observed_with(NCFG_BACKEND_SUPPLICANT, "wlan-notmine", 0);
	pid_t            child;
	char             message[NCFG_ERROR_MAX];

	if (!observed) {
		check(0, "the fixture for a record saying `not running` reads");
		return;
	}
	if (!ncfg_supplicant_pid_path(run_dir, "wlan-notmine", marker, sizeof(marker), NULL, 0)) {
		check(0, "the mark for an unrecorded daemon could be named");
		ncfg_observed_free(observed);
		return;
	}
	child = marked_child(marker);
	(void)record_supplicant("wlan-notmine", child, marker, sizeof(marker));
	message[0] = '\0';
	(void)ncfg_observe_backend_liveness(observed, run_dir, message, sizeof(message));
	/*
	 * **A live process carrying the mark, and the record still says no.** The
	 * record is netcfgd's account of what *it* started; a process netcfgd did
	 * not start is not netcfgd's, whatever its command line says. Setting
	 * `running` here would make the observation a scan of the machine, and the
	 * planner would then stop a daemon netcfgd never started.
	 */
	check(observed->backend_count == 1u && !observed->backends[0].running,
	    "a live process carrying the mark does not make a record say `running`");
	ncfg_observed_free(observed);
	reap();
}

static void a_client_netcfgd_gave_no_pid_file_is_left_alone(void)
{
	ncfg_observed_t *observed = observed_with(NCFG_BACKEND_DHCP4, "eth-dhcpcd", 1);
	char             message[NCFG_ERROR_MAX];

	if (!observed) {
		check(0, "the fixture for a dhcpcd client reads");
		return;
	}
	message[0] = '\0';
	(void)ncfg_observe_backend_liveness(observed, run_dir, message, sizeof(message));
	/*
	 * **The case that would have taken a working machine's network down.**
	 * dhcpcd is the default client on a Debian machine and netcfgd gives it no
	 * pid file at all, so "no pid file" means *netcfgd cannot ask* rather than
	 * *the client is gone*. Clearing here would report every dhcpcd lease on
	 * the machine as dead, and the planner would restart a client that is
	 * running -- taking the lease down to do it. `dhcp.h` says the question for
	 * one of those is `ncfg_dhcpcd_whose`, which needs paths a pass is not
	 * given.
	 */
	check(observed->backend_count == 1u && observed->backends[0].running,
	    "a DHCP client with no pid file of netcfgd's is unanswerable, not dead");
	ncfg_observed_free(observed);
}

/*
 * What the client was started with, which is the other half of a rule.
 *
 * `ncfg_plan_metric_restart` asks two questions and neither subsumes the
 * other: the installed route says what the client *did*, and this says what it
 * was *told* -- which is there before the first exchange has installed
 * anything. The second had no producer at all until this pass read it, so a
 * client started with the wrong metric was left alone until it managed to
 * install a route with the wrong metric (project.md 10.206).
 *
 * The client here is a dhcpcd one, which is deliberate twice over: it is the
 * only client netcfgd gives a metric to, and it is the one this pass cannot
 * ask about -- so a metric read only behind a pid would never be read at all.
 */
static void a_running_client_says_what_it_was_started_with(void)
{
	ncfg_observed_t *observed = observed_with(NCFG_BACKEND_DHCP4, "eth-metric", 1);
	ncfg_observed_t *quiet = observed_with(NCFG_BACKEND_DHCP4, "eth-nometric", 1);
	ncfg_observed_t *other = observed_with(NCFG_BACKEND_DHCP6, "eth-metric", 1);
	char             message[NCFG_ERROR_MAX];

	if (!observed || !quiet || !other || !record_metric("eth-metric", "600\n")) {
		check(0, "the fixture for a client started with a metric");
		ncfg_observed_free(observed);
		ncfg_observed_free(quiet);
		ncfg_observed_free(other);
		return;
	}
	message[0] = '\0';
	(void)ncfg_observe_backend_liveness(observed, run_dir, message, sizeof(message));
	(void)ncfg_observe_backend_liveness(quiet, run_dir, message, sizeof(message));
	(void)ncfg_observe_backend_liveness(other, run_dir, message, sizeof(message));
	check(observed->backend_count == 1u && observed->backends[0].started_metric.has &&
	        observed->backends[0].started_metric.value == 600,
	    "a running DHCP client reports the metric it was started with");
	/* "netcfgd cannot tell" and "started with metric 0" are different answers
	 * and only one of them may be compared against: 0 is a legitimate metric
	 * and the strongest one. */
	check(quiet->backend_count == 1u && !quiet->backends[0].started_metric.has,
	    "  and a client with no record of one says nothing, rather than zero");
	/*
	 * The record is named for the interface and nothing else, so a v6 client
	 * on the same interface would read the v4 client's number as its own --
	 * and `-m` is only ever given to a v4 one. The v6 kind rather than some
	 * distant daemon on purpose: it shares this pass's whole DHCP arm, so it
	 * reaches the same place by the same route and only the kind separates
	 * them.
	 */
	check(other->backend_count == 1u && !other->backends[0].started_metric.has,
	    "  and a v6 client on that interface is never given the v4 one's");
	ncfg_observed_free(observed);
	ncfg_observed_free(quiet);
	ncfg_observed_free(other);
}

/*
 * And a client this pass has just buried is not asked what it was started
 * with. A record outlives the process where a client was killed rather than
 * stopped -- netcfgd removes it on a stop -- and a metric read off one would
 * be an observation of a process that is gone.
 */
static void a_client_that_has_died_reports_no_metric(void)
{
	ncfg_observed_t *observed = observed_with(NCFG_BACKEND_DHCP4, "eth-gone", 1);
	char             path[700];
	char             dir[640];
	char             text[32];
	char             message[NCFG_ERROR_MAX];
	pid_t            child;

	if (!observed) {
		check(0, "the fixture for a client that has died");
		return;
	}
	(void)snprintf(dir, sizeof(dir), "%s/udhcpc", run_dir);
	testdir_mkdirp(dir);
	if (!ncfg_dhcp_pid_path(run_dir, "udhcpc", "eth-gone", path, sizeof(path), NULL, 0)) {
		check(0, "the pid file for a udhcpc client could be named");
		ncfg_observed_free(observed);
		return;
	}
	/* Started carrying the pid file's path, as netcfgd's own `-p` would have
	 * it, and then killed -- so this pass can answer, and answers `gone`. */
	child = marked_child(path);
	(void)snprintf(text, sizeof(text), "%d\n", (int)child);
	if (!testdir_write(path, text, strlen(text)) || !record_metric("eth-gone", "700\n")) {
		check(0, "the fixture for a client that has died could be written");
		ncfg_observed_free(observed);
		reap();
		return;
	}
	reap();
	message[0] = '\0';
	(void)ncfg_observe_backend_liveness(observed, run_dir, message, sizeof(message));
	check(observed->backend_count == 1u && !observed->backends[0].running,
	    "a client whose process is gone stops being running");
	check(observed->backend_count == 1u && !observed->backends[0].started_metric.has,
	    "  and is not asked what it was started with, its record having outlived it");
	ncfg_observed_free(observed);
}

static void a_kind_that_is_not_a_process_is_left_alone(void)
{
	ncfg_observed_t *wireguard = observed_with(NCFG_BACKEND_WIREGUARD, "wg0", 1);
	ncfg_observed_t *dns = observed_with(NCFG_BACKEND_DNS, "globals", 1);
	char             message[NCFG_ERROR_MAX];

	if (!wireguard || !dns) {
		check(0, "the fixtures for the two kinds that are not processes read");
		ncfg_observed_free(wireguard);
		ncfg_observed_free(dns);
		return;
	}
	message[0] = '\0';
	(void)ncfg_observe_backend_liveness(wireguard, run_dir, message, sizeof(message));
	(void)ncfg_observe_backend_liveness(dns, run_dir, message, sizeof(message));
	/* WireGuard is a kernel device and DNS is a file delivered to somebody
	 * else's daemon. Neither has a pid, so "no process found" is not a fact
	 * about either of them. */
	check(wireguard->backend_count == 1u && wireguard->backends[0].running,
	    "a WireGuard record is not cleared by looking for a process it never had");
	check(dns->backend_count == 1u && dns->backends[0].running,
	    "and neither is a DNS one, which is a file rather than a daemon");
	ncfg_observed_free(wireguard);
	ncfg_observed_free(dns);
}

static void an_access_point_can_be_asked_at_last(void)
{
	char             marker[512];
	char             dir[640];
	char             text[32];
	ncfg_observed_t *observed = observed_with(NCFG_BACKEND_ACCESS_POINT, "wlan-ap", 1);
	pid_t            child;
	char             message[NCFG_ERROR_MAX];

	if (!observed) {
		check(0, "the fixture for an access point reads");
		return;
	}
	/*
	 * **The sixth answer, and the one that did not exist.** `hostapd.h` said an
	 * access point was the one backend netcfgd could never tell had died, so
	 * `running: true` was the only account of a daemon that crashed an hour
	 * ago and 0079's restart could not fire for it. `-P` puts the pid file's
	 * path in hostapd's own `argv`, which is what makes this answerable at all.
	 */
	if (!ncfg_hostapd_pid_path(run_dir, "wlan-ap", marker, sizeof(marker), NULL, 0)) {
		check(0, "the access point's mark could be named");
		ncfg_observed_free(observed);
		return;
	}
	child = marked_child(marker);
	(void)snprintf(dir, sizeof(dir), "%s/hostapd", run_dir);
	testdir_mkdirp(dir);
	(void)snprintf(text, sizeof(text), "%d\n", (int)child);
	(void)testdir_write(marker, text, strlen(text));
	message[0] = '\0';
	(void)ncfg_observe_backend_liveness(observed, run_dir, message, sizeof(message));
	check(child > 0 && observed->backend_count == 1u && observed->backends[0].running,
	    "an access point that is still there is left running");
	reap();

	/* And the same record once it is gone, which is the half that never had an
	 * answer before. */
	(void)snprintf(text, sizeof(text), "%d\n", 0x7ffffff0);
	(void)testdir_write(marker, text, strlen(text));
	(void)ncfg_observe_backend_liveness(observed, run_dir, message, sizeof(message));
	check(observed->backend_count == 1u && !observed->backends[0].running,
	    "  and one that has died is finally noticed, which is 0079's precondition");
	ncfg_observed_free(observed);
}

/*
 * A daemon with no pid file of netcfgd's is unanswerable, for all five kinds.
 *
 * **The rule was applied to one of them.** `a_client_netcfgd_gave_no_pid_file_
 * is_left_alone` covers the DHCP arm, which got it in 10.206 because a udhcpc
 * client that died stayed `running` for ever. The other four asked
 * `*_running_pid` directly, and that answers 0 for a missing file exactly as
 * it does for a dead process -- so a record naming a running supplicant with
 * no pid file beside it was read as "not running".
 *
 * What that cost is not the field. `ncfg_observe_supplicants` asks only about
 * backends the record still calls up, so clearing `running` took the whole
 * `answering` round off the supplicant: netcfgd never opened the control
 * socket, and a wedged supplicant went unreported along with a working one.
 * `tests/live/wedged.sh` is what noticed, by asserting that its fake logged a
 * PING at all -- a negative that would otherwise have passed against an
 * observation which never asked.
 *
 * A pid file that IS there and names something else is the other half and
 * still clears, which `an_access_point_can_be_asked_at_last` proves for
 * hostapd. This is the absence.
 */
static void a_daemon_with_no_pid_file_of_netcfgds_is_left_alone(void)
{
	static const struct {
		int         kind;
		const char *interface;
		const char *what;
	} kinds[] = {
		{ NCFG_BACKEND_SUPPLICANT, "wlan-nofile", "a supplicant" },
		{ NCFG_BACKEND_ACCESS_POINT, "ap-nofile", "an access point" },
		{ NCFG_BACKEND_ROUTER_ADVERT, "ra-nofile", "a router advertisement daemon" },
		{ NCFG_BACKEND_OPENVPN, "vpn-nofile", "an openvpn tunnel" }
	};
	size_t at;

	for (at = 0; at < sizeof(kinds) / sizeof(kinds[0]); at++) {
		ncfg_observed_t *observed = observed_with(kinds[at].kind, kinds[at].interface, 1);
		char             message[NCFG_ERROR_MAX];
		char             said[256];

		if (!observed) {
			check(0, "the fixture reads");
			continue;
		}
		message[0] = '\0';
		(void)ncfg_observe_backend_liveness(observed, run_dir, message, sizeof(message));
		(void)snprintf(said, sizeof(said),
		    "%s with no pid file of netcfgd's is unanswerable, not dead",
		    kinds[at].what);
		check(observed->backend_count == 1u && observed->backends[0].running, said);
		ncfg_observed_free(observed);
	}
}

static void the_round_refuses_what_it_cannot_be_asked(void)
{
	ncfg_observed_t *observed = observed_with(NCFG_BACKEND_SUPPLICANT, "wlan0", 1);
	char             message[NCFG_ERROR_MAX];

	message[0] = '\0';
	check(!ncfg_observe_backend_liveness(NULL, run_dir, message, sizeof(message)) &&
	    message[0] != '\0',
	    "no observation at all is refused with a sentence");
	message[0] = '\0';
	check(observed && !ncfg_observe_backend_liveness(observed, NULL, message,
	    sizeof(message)) && strstr(message, "run directory") != NULL,
	    "and so is a round with no run directory, naming what was missing");
	ncfg_observed_free(observed);
}

int main(void)
{
	const char *made = testdir_make("liveness");

	base = made;
	(void)snprintf(run_dir, sizeof(run_dir), "%s/run", base);
	testdir_mkdirp(run_dir);
	printf("== liveness_test in %s\n", base);

	a_daemon_that_is_still_there_stays_running();
	a_daemon_that_has_died_stops_being_running();
	it_only_ever_clears();
	a_client_netcfgd_gave_no_pid_file_is_left_alone();
	a_kind_that_is_not_a_process_is_left_alone();
	a_running_client_says_what_it_was_started_with();
	a_client_that_has_died_reports_no_metric();
	an_access_point_can_be_asked_at_last();
	a_daemon_with_no_pid_file_of_netcfgds_is_left_alone();
	the_round_refuses_what_it_cannot_be_asked();

	/* Named pids, never a pattern: another session's `sleep` is not this
	 * file's to kill. */
	reap();
	testdir_remove(made);

	printf("liveness_test: %d check(s)\n", checks);
	if (failures == 0) {
		printf("liveness_test: all checks passed\n");
	} else {
		printf("liveness_test: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
