/*
 * openvpn_test.c -- the tunnel netcfgd starts without reading its
 * configuration, and the script that tells it what the server pushed.
 *
 * WHAT THESE CASES ARE FOR
 *   The Rust's, each keeping the sentence that says which defect it is about:
 *
 *   * **A config record that cannot be written names the file and the reason**
 *     (0180). This was an ignored write inside `start`, which is two silences
 *     at once: unreachable from a test without a real openvpn, and unreported
 *     when it failed. The hash is the only thing that makes an *edited* `.ovpn`
 *     something a reconcile can notice (0053), so without it netcfgd leaves a
 *     stale tunnel up and says nothing. The refusal here is a file where the
 *     directory has to be, which needs no privilege -- a mode would not do,
 *     because root walks through one.
 *   * **A config that cannot be read leaves no record and no complaint.** "The
 *     operator's file is not there" is a different statement from "it changed",
 *     and only one of them is a reason to restart a working tunnel.
 *   * **The script stages under a dot.** `is_staging` is "the name begins with
 *     a dot", which is the contract's own wording -- and this script staged at
 *     `<report>.tmp`, which does not begin with one. So a half-written report
 *     was read as an interface in its own right: `ncfg status` listed
 *     `vpn0.tmp` carrying the address and nameservers of the file being written
 *     (0113).
 *   * **The script parses.** It is written into the run directory and run by
 *     openvpn rather than by anything in this repository, so `make shell`
 *     cannot see it: a syntax error here would first be noticed as a tunnel
 *     that reports nothing.
 *   * **It writes what openvpn put in its environment.** The environment below
 *     is copied from a real openvpn 2.6.14 run under `--route-noexec`: a dotted
 *     netmask, a gateway openvpn filled in for a route that named none, an
 *     explicit gateway on the second, a mask with a hole in it, and an IPv6
 *     route already in CIDR. Running the script is the only way to check the
 *     mask conversion without a tunnel.
 *   * **The down call empties the report rather than removing it**, which is
 *     the difference the contract draws between "nothing, deliberately" and
 *     "nobody is watching".
 *
 *   And the C port's, which cover what the Rust got from its standard library
 *   or from a live script: the argument list, the credentials file, the
 *   management client's greeting, and a stop against a daemon that is not
 *   listening.
 *
 * THE `.ovpn` IS NEVER OPENED FOR MEANING
 *   `openvpn.config` is `netcfgd-compile`'s `ForeignConfig` production:
 *   privileged because netcfgd hands the file to openvpn as root and it may
 *   itself name scripts. So the fixtures here are `.ovpn` files with content
 *   netcfgd must not care about, and the only things asserted of them are that
 *   a missing one is named and that a present one is hashed.
 *
 * NOTHING OUTSIDE ITS OWN DIRECTORY, AND NO openvpn
 *   Every path is under one `mkdtemp` directory and is passed explicitly. The
 *   program started is a shell script this test wrote -- `ncfg_openvpn_start`
 *   takes the program precisely so that a check never reaches `/usr/sbin/
 *   openvpn`, which is the defect 0101 records on the Rust side. No tunnel is
 *   negotiated and no `tun` is created.
 */
#include "ncfg/base.h"
#include "ncfg/hooks.h"
#include "ncfg/openvpn.h"

#include "testdir.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* The password nothing may repeat. */
#define CANARY "zq7-CANARY-openvpn-password-never-printed-4f1e"

static int    failures;
static char   every_message[64u * 1024u];
static size_t every_message_length;

static void check(int condition, const char *what)
{
	printf("%-72s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

static const char *kept(const char *message)
{
	size_t length = strlen(message);

	if (every_message_length + length + 2u < sizeof(every_message)) {
		memcpy(every_message + every_message_length, message, length);
		every_message_length += length;
		every_message[every_message_length++] = '\n';
		every_message[every_message_length] = '\0';
	}
	return message;
}

static void check_text(const char *got, const char *want, const char *what)
{
	int same = got != NULL && strcmp(got, want) == 0;

	check(same, what);
	if (!same) {
		printf("  wanted:\n%s\n  got:\n%s\n", want, got ? got : "(null)");
	}
}

static int write_program(const char *path, const char *body)
{
	return testdir_write(path, body, strlen(body)) && chmod(path, 0755) == 0;
}

/* Wait for one child, with a ceiling: nothing here takes more than a moment
 * when it works, and a blocking wait on a child that wedged would hold the
 * whole suite. */
static int wait_for(pid_t child)
{
	int rounds;

	for (rounds = 0; rounds < 500; rounds++) {
		int   status = 0;
		pid_t got = waitpid(child, &status, WNOHANG);
		struct timespec pause;

		if (got == child) {
			return WIFEXITED(status) && WEXITSTATUS(status) == 0;
		}
		if (got < 0) {
			return 0;
		}
		pause.tv_sec = 0;
		pause.tv_nsec = 10L * 1000000L;
		(void)nanosleep(&pause, NULL);
	}
	/* Its own process group, so nothing it started outlives it either. */
	(void)kill(child, SIGKILL);
	(void)waitpid(child, NULL, 0);
	return 0;
}

/* ------------------------------------------------------------- the record */

/*
 * A config record that cannot be written names the file and the reason (0180).
 *
 * The refusal is a file where the run subdirectory has to be, which needs no
 * privilege: a mode would not do, because root walks through one.
 */
static void a_config_record_that_cannot_be_written_names_the_file_and_the_reason(const char *base)
{
	char run[512];
	char blocker[1024];
	char config[512];
	char message[NCFG_ERROR_MAX];

	(void)testdir_in(base, "record-blocked", run, sizeof(run));
	check(mkdir(run, 0755) == 0, "a run directory of its own");
	(void)testdir_in(run, "openvpn", blocker, sizeof(blocker));
	check(testdir_write(blocker, "in the way", 10u), "a file where the subdirectory has to be");
	(void)testdir_in(base, "office.ovpn", config, sizeof(config));
	check(testdir_write(config, "remote vpn.example.com 1194\n", 28u), "an operator's .ovpn");

	message[0] = '\0';
	check(!ncfg_openvpn_record_started_from(run, "vpn0", config, message, sizeof(message)),
	    "a record under a file is not a record");
	(void)kept(message);
	check(strstr(message, "vpn0") != NULL, "the refusal names the interface");
	check(strstr(message, "openvpn") != NULL, "and the path it could not make");
	check(strstr(message, "edited config") != NULL,
	    "and says what is lost rather than only that something failed");
}

/* And it succeeds where it can, so the case above is about the failure. */
static void a_config_record_is_the_hash_of_the_file(const char *base)
{
	char run[512];
	char config[512];
	char path[NCFG_OPENVPN_PATH_MAX];
	char hash[NCFG_SHA256_HEX_SIZE];
	char message[NCFG_ERROR_MAX];
	char *written;

	(void)testdir_in(base, "record", run, sizeof(run));
	check(mkdir(run, 0755) == 0, "a run directory for the record");
	(void)testdir_in(base, "office.ovpn", config, sizeof(config));

	message[0] = '\0';
	check(ncfg_openvpn_record_started_from(run, "vpn0", config, message, sizeof(message)),
	    "the record is written");
	check(ncfg_openvpn_hash_of(config, hash, sizeof(hash)), "and the file hashes");
	check(ncfg_openvpn_config_hash_path(run, "vpn0", path, sizeof(path), NULL, 0), "its path");
	written = testdir_read(path, NULL);
	check_text(written, hash, "and what was recorded is the hash of the file it started from");
	free(written);

	/* A `.ovpn` that is not there is not a write that failed: this returns
	 * success, leaves no record, and lets the caller's own check on the missing
	 * file speak. */
	(void)testdir_in(base, "absent.ovpn", config, sizeof(config));
	message[0] = '\0';
	check(ncfg_openvpn_record_started_from(run, "vpn1", config, message, sizeof(message)),
	    "a config that cannot be read is not a failure");
	check(ncfg_openvpn_config_hash_path(run, "vpn1", path, sizeof(path), NULL, 0) &&
	    !testdir_exists(path),
	    "and leaves no record and no complaint");
}

/* ------------------------------------------------------------- the script */

static void the_script_stages_under_a_dot(void)
{
	char message[NCFG_ERROR_MAX];
	char *script = ncfg_openvpn_report_script("vpn0", "/run/netcfgd/reported/vpn0", message,
	    sizeof(message));

	check(script != NULL && strstr(script, "$target.tmp") == NULL,
	    "the script does not stage at a name netcfgd would read as an interface");
	check(script != NULL && strstr(script, ".$(basename \"$target\")") != NULL,
	    "it stages under a dotted name, which is the contract's own rule for a staging file");
	free(script);
}

static void the_script_parses_and_reports(const char *base)
{
	char  run[512];
	char  path[1024];
	char  report[1024];
	char  runner[1024];
	char  body[2048];
	char  message[NCFG_ERROR_MAX];
	char *script;
	char *written;
	pid_t child;

	(void)testdir_in(base, "script", run, sizeof(run));
	check(mkdir(run, 0755) == 0, "a directory for the script");
	(void)testdir_in(run, "report.sh", path, sizeof(path));
	(void)testdir_in(run, "vpn0", report, sizeof(report));

	message[0] = '\0';
	script = ncfg_openvpn_report_script("vpn0", report, message, sizeof(message));
	check(script != NULL, "the script renders");
	if (!script) {
		return;
	}
	check(write_program(path, script), "and is written executable");
	free(script);

	/* `sh -n` costs a fork and is the only thing in this repository that can
	 * see this file at all. */
	child = fork();
	if (child == 0) {
		(void)setpgid(0, 0);
		execlp("sh", "sh", "-n", path, (char *)NULL);
		_exit(127);
	}
	check(child > 0 && wait_for(child), "the generated script parses");

	/*
	 * It converts what openvpn actually hands it.
	 *
	 * Driven through a wrapper rather than by setting this process' environment:
	 * the variables are openvpn's and belong to the one run, and a test that
	 * exported them would leave them for every check after it.
	 */
	(void)testdir_in(run, "run.sh", runner, sizeof(runner));
	(void)snprintf(body, sizeof(body),
	    "#!/bin/sh\n"
	    "script_type=route-up \\\n"
	    /* Both spellings of a nameserver, and the two the server does not get to
	     * decide -- copied from a real openvpn's environment. */
	    "foreign_option_1='dhcp-option DNS 10.0.0.53' \\\n"
	    "foreign_option_2='dhcp-option DNS6 fd00::53' \\\n"
	    "foreign_option_3='dhcp-option DOMAIN corp.example' \\\n"
	    "foreign_option_4='dhcp-option DOMAIN-SEARCH sub.corp.example' \\\n"
	    /* Something the contract has no key for at all, so the comment path
	     * still has a subject: without one, deleting it would leave every
	     * assertion here passing. */
	    "foreign_option_5='dhcp-option WINS 10.0.0.7' \\\n"
	    "route_network_1=10.9.0.0 route_netmask_1=255.255.255.0 route_gateway_1=10.8.0.2 \\\n"
	    "route_network_2=10.10.0.0 route_netmask_2=255.255.0.0 route_gateway_2=192.168.99.1 \\\n"
	    /* A mask with a hole in it, which the kernel would refuse and which is
	     * better dropped here where the rest of the report survives. */
	    "route_network_3=10.11.0.0 route_netmask_3=255.0.255.0 route_gateway_3=10.8.0.2 \\\n"
	    "route_ipv6_network_1=fd77::/32 route_ipv6_gateway_1=fd00::2 \\\n"
	    "%s\n",
	    path);
	check(write_program(runner, body), "a wrapper carrying openvpn's own environment");

	child = fork();
	if (child == 0) {
		(void)setpgid(0, 0);
		execl(runner, runner, (char *)NULL);
		_exit(127);
	}
	check(child > 0 && wait_for(child), "the script runs");

	written = testdir_read(report, NULL);
	check(written != NULL, "and leaves a report");
	if (!written) {
		return;
	}
	check(strstr(written, "route=10.9.0.0/24 via 10.8.0.2\n") != NULL,
	    "a dotted netmask becomes a prefix length");
	check(strstr(written, "route=10.10.0.0/16 via 192.168.99.1\n") != NULL,
	    "and so does the second, with the gateway the config named");
	check(strstr(written, "10.11.0.0") == NULL,
	    "a mask with a hole in it is dropped rather than summed into a different number");
	check(strstr(written, "route=fd77::/32 via fd00::2\n") != NULL,
	    "an IPv6 route arrives already in CIDR, which is openvpn's asymmetry not netcfgd's");
	check(strstr(written, "dns=10.0.0.53\n") != NULL && strstr(written, "dns=fd00::53\n") != NULL,
	    "both families of nameserver are reported");
	/* `DOMAIN` and `DOMAIN-SEARCH` are search suffixes (0067). A *routing*
	 * domain is the operator's to say in the document and has no report key at
	 * all (0049), so the assertion below is half the point. */
	check(strstr(written, "search=corp.example\n") != NULL &&
	    strstr(written, "search=sub.corp.example\n") != NULL,
	    "and both spellings of a pushed domain become search suffixes");
	check(strstr(written, "domain=") == NULL,
	    "a pushed domain is not a routing domain, and this contract has no key for one");
	check(strstr(written, "# the server also said: dhcp-option WINS 10.0.0.7") != NULL,
	    "what was declined is still visible as a comment rather than silently dropped");
	free(written);

	/* The tunnel going down empties the report rather than removing it, which is
	 * the difference the contract draws between "nothing, deliberately" and
	 * "nobody is watching". */
	(void)snprintf(body, sizeof(body), "#!/bin/sh\nscript_type=down %s\n", path);
	check(write_program(runner, body), "a wrapper for the down call");
	child = fork();
	if (child == 0) {
		(void)setpgid(0, 0);
		execl(runner, runner, (char *)NULL);
		_exit(127);
	}
	check(child > 0 && wait_for(child), "the down call runs");
	written = testdir_read(report, NULL);
	check_text(written, "", "and leaves an empty report, not a gone one");
	free(written);
}

/* ------------------------------------------------------------ the daemon */

/*
 * The argument list, asserted whole.
 *
 * Every flag here is load-bearing in a way no compiler notices:
 * `--route-noexec` keeps the routes netcfgd's (0047), `--script-security 2` is
 * the difference between a tunnel that reports and one that silently does not,
 * `--writepid` is the handle for the window between the fork and the bind
 * (0074), and `--dev` is netcfgd choosing the interface name rather than the
 * `.ovpn`.
 */
static void the_tunnel_is_started_with_the_flags_that_carry_the_design(const char *base)
{
	char  run[512];
	char  config[512];
	char  report[1024];
	char  fake[1024];
	char  seen[1024];
	char  body[4096];
	char  message[NCFG_ERROR_MAX];
	char  want[8192];
	char *arguments;

	(void)testdir_in(base, "start", run, sizeof(run));
	check(mkdir(run, 0755) == 0, "a run directory for the start");
	(void)testdir_in(base, "office.ovpn", config, sizeof(config));
	(void)testdir_in(run, "reported-vpn0", report, sizeof(report));
	(void)testdir_in(run, "fake-openvpn", fake, sizeof(fake));
	(void)testdir_in(run, "arguments", seen, sizeof(seen));
	(void)snprintf(body, sizeof(body), "#!/bin/sh\nprintf '%%s\\n' \"$@\" > '%s'\nexit 0\n",
	    seen);
	check(write_program(fake, body), "the stand-in daemon is written");

	message[0] = '\0';
	check(ncfg_openvpn_start(run, "vpn0", config, NULL, NULL, report, fake, message,
	      sizeof(message)),
	    "a tunnel with a config that is there starts");
	if (message[0] != '\0') {
		printf("  said: %s\n", kept(message));
	}

	arguments = testdir_read(seen, NULL);
	(void)snprintf(want, sizeof(want),
	    "--config\n%s\n"
	    "--dev\nvpn0\n"
	    "--management\n%s/openvpn/vpn0.sock\nunix\n"
	    "--daemon\nnetcfgd-vpn0\n"
	    "--writepid\n%s/openvpn/vpn0.pid\n"
	    "--log\n%s/openvpn/vpn0.log\n"
	    "--route-noexec\n"
	    "--script-security\n2\n"
	    "--route-up\n%s/openvpn/vpn0.report\n"
	    "--down\n%s/openvpn/vpn0.report\n",
	    config, run, run, run, run, run);
	check_text(arguments, want, "the whole argument list, in openvpn's order");
	free(arguments);

	/* Checked by netcfgd rather than left to openvpn, only because the error is
	 * so much better: openvpn says "Options error" against a file the operator
	 * may not realise netcfgd chose. */
	message[0] = '\0';
	check(!ncfg_openvpn_start(run, "vpn0", "/nonexistent/office.ovpn", NULL, NULL, report, fake,
	      message, sizeof(message)) &&
	    strstr(message, "/nonexistent/office.ovpn") != NULL &&
	    strstr(message, "there is no file there") != NULL,
	    "a config that is not there is named, with the path the document gave");
}

/*
 * The credentials go in a file, and the file's path goes on the command line.
 *
 * A password on a command line is readable by every process on the machine
 * through `/proc`, so the argument list is swept for the value as well as the
 * diagnostics.
 */
static void the_credentials_go_in_a_file_and_never_on_the_command_line(const char *base)
{
	char  run[512];
	char  config[512];
	char  report[1024];
	char  fake[1024];
	char  seen[1024];
	char  auth[NCFG_OPENVPN_PATH_MAX];
	char  body[4096];
	char  message[NCFG_ERROR_MAX];
	char *arguments;
	char *credentials;

	(void)testdir_in(base, "credentials", run, sizeof(run));
	check(mkdir(run, 0755) == 0, "a run directory for the credentials");
	(void)testdir_in(base, "office.ovpn", config, sizeof(config));
	(void)testdir_in(run, "reported-vpn1", report, sizeof(report));
	(void)testdir_in(run, "fake-openvpn", fake, sizeof(fake));
	(void)testdir_in(run, "arguments", seen, sizeof(seen));
	(void)snprintf(body, sizeof(body), "#!/bin/sh\nprintf '%%s\\n' \"$@\" > '%s'\nexit 0\n",
	    seen);
	check(write_program(fake, body), "the stand-in daemon is written");

	message[0] = '\0';
	check(ncfg_openvpn_start(run, "vpn1", config, "someone", CANARY, report, fake, message,
	      sizeof(message)),
	    "a tunnel with credentials starts");
	if (message[0] != '\0') {
		printf("  said: %s\n", kept(message));
	}
	check(ncfg_openvpn_auth_path(run, "vpn1", auth, sizeof(auth), NULL, 0), "the auth path");
	check(testdir_mode(auth) == 0600, "the credentials file is readable only by root");
	credentials = testdir_read(auth, NULL);
	check_text(credentials, "someone\n" CANARY "\n",
	    "and is exactly the two lines --auth-user-pass reads");
	free(credentials);

	arguments = testdir_read(seen, NULL);
	check(arguments != NULL && strstr(arguments, "--auth-user-pass") != NULL &&
	    strstr(arguments, auth) != NULL,
	    "openvpn is given the path");
	check(arguments != NULL && strstr(arguments, CANARY) == NULL,
	    "and never the value, which /proc would show to every process on the machine");
	free(arguments);

	/* A username with a newline would become a password line; nothing in the
	 * model stops one, so it is stopped here. */
	message[0] = '\0';
	check(!ncfg_openvpn_start(run, "vpn1", config, "someone\nelse", CANARY, report, fake,
	      message, sizeof(message)) &&
	    strstr(message, "read as a different field") != NULL,
	    "a credential carrying a newline is refused rather than written");
	(void)kept(message);

	/* No credentials in the document any more: the file goes, so a password does
	 * not outlive the document that asked for it. */
	message[0] = '\0';
	check(ncfg_openvpn_start(run, "vpn1", config, NULL, NULL, report, fake, message,
	      sizeof(message)) &&
	    !testdir_exists(auth),
	    "a tunnel started without credentials removes the ones an earlier document left");
}

/*
 * A daemon that will not start is quoted, not summarised.
 *
 * openvpn announces the reason and then narrates its shutdown, so the tail is
 * the wrong lines.
 */
static void a_daemon_that_will_not_start_is_quoted(const char *base)
{
	char run[512];
	char config[512];
	char report[1024];
	char fake[1024];
	char body[4096];
	char message[NCFG_ERROR_MAX];

	(void)testdir_in(base, "angry", run, sizeof(run));
	check(mkdir(run, 0755) == 0, "a run directory for the refusing daemon");
	(void)testdir_in(base, "office.ovpn", config, sizeof(config));
	(void)testdir_in(run, "reported-vpn2", report, sizeof(report));
	(void)testdir_in(run, "fake-openvpn", fake, sizeof(fake));
	(void)snprintf(body, sizeof(body),
	    "#!/bin/sh\n"
	    "echo 'OpenVPN 2.6.14 x86_64-pc-linux-gnu'\n"
	    "echo 'Options error: --ca fails with cert.pem: No such file.'\n"
	    "echo 'Use --help for more information.'\n"
	    "echo 'Exiting due to fatal error'\n"
	    "exit 1\n");
	check(write_program(fake, body), "the refusing stand-in is written");

	message[0] = '\0';
	check(!ncfg_openvpn_start(run, "vpn2", config, NULL, NULL, report, fake, message,
	      sizeof(message)),
	    "a daemon that refuses its options fails the start");
	(void)kept(message);
	check(strstr(message, "Options error: --ca fails with cert.pem") != NULL,
	    "and the refusal quotes the line that said why");
	check(strstr(message, "Use --help") == NULL,
	    "rather than the tail, which is openvpn narrating its own exit");
	check(strstr(message, ".log") != NULL, "and says where the rest of the output is");
}

/* --------------------------------------------------- the management socket */

/*
 * The greeting is skipped, and an answer is found.
 *
 * OpenVPN greets a new client with `>INFO:` before it is asked anything and
 * emits further `>`-prefixed notifications whenever it likes, interleaved with
 * replies. **Reading the first line as the answer is the classic bug in a
 * management client** and produces a stop that silently did nothing, so the
 * stand-in below sends the greeting first and a notification in the middle.
 */
static void the_greeting_is_not_mistaken_for_an_answer(const char *base)
{
	char               run[512];
	char               path[1024];
	struct sockaddr_un address;
	int                listener;
	pid_t              child;
	ncfg_openvpn_management_t *management;
	char                       reply[256];
	char                       message[NCFG_ERROR_MAX];

	(void)testdir_in(base, "management", run, sizeof(run));
	check(mkdir(run, 0755) == 0, "a directory for the socket");
	(void)testdir_in(run, "vpn0.sock", path, sizeof(path));

	listener = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	/* Bounded rather than truncated: a unix address is about a hundred bytes and
	 * a silently shortened one would bind somewhere else entirely. The module
	 * refuses the same way, so this is the same rule on both sides. */
	if (strlen(path) + 1u > sizeof(address.sun_path)) {
		check(0, "the temporary directory leaves room for a unix socket path");
		(void)close(listener);
		return;
	}
	memcpy(address.sun_path, path, strlen(path) + 1u);
	check(listener >= 0 && bind(listener, (const struct sockaddr *)&address, sizeof(address)) == 0 &&
	    listen(listener, 1) == 0,
	    "a stand-in daemon is listening");

	child = fork();
	if (child == 0) {
		int served = accept(listener, NULL, NULL);
		char asked[256];
		ssize_t got;

		(void)setpgid(0, 0);
		if (served < 0) {
			_exit(1);
		}
		/* Exactly openvpn's own opening, then a notification, then the answer. */
		(void)write(served, ">INFO:OpenVPN Management Interface Version 5\n", 45u);
		got = read(served, asked, sizeof(asked));
		if (got <= 0) {
			_exit(1);
		}
		(void)write(served, ">STATE:1700000000,CONNECTED,SUCCESS,10.8.0.2\n", 45u);
		(void)write(served, "SUCCESS: signal SIGTERM thrown\n", 31u);
		(void)close(served);
		_exit(0);
	}

	management = ncfg_openvpn_connect(path, message, sizeof(message));
	check(management != NULL, "the client connects");
	if (management) {
		message[0] = '\0';
		check(ncfg_openvpn_command(management, "signal SIGTERM", reply, sizeof(reply), message,
		      sizeof(message)),
		    "and reads past the greeting and the notification to the answer");
		check_text(reply, "signal SIGTERM thrown", "which is what followed SUCCESS:");
		ncfg_openvpn_disconnect(management);
	}
	check(child > 0 && wait_for(child), "the stand-in finishes");
	(void)close(listener);
	(void)unlink(path);

	/* And nothing listening is not an answer either. */
	(void)testdir_in(run, "gone.sock", path, sizeof(path));
	message[0] = '\0';
	check(ncfg_openvpn_connect(path, message, sizeof(message)) == NULL,
	    "and a socket nothing is listening on does not connect");
	(void)kept(message);
}

/*
 * A stop with nothing listening and nothing running is the state asked for.
 *
 * And the report goes first, outside that question: a daemon that already died
 * is exactly the case where nobody comes back to tidy up.
 */
/*
 * A DAEMON SLOW TO EXIT IS WAITED FOR, ON BOTH STOP PATHS.
 *
 * `ncfg_openvpn_stop` used to signal and then remove the pid file immediately,
 * on both the management path and the pid one. `ncfg_openvpn_running_pid` reads
 * that file, so a daemon still tearing its tunnel down read as *absent* -- and
 * a restart is a stop followed by a start, so the start met the daemon it was
 * replacing. The same defect `autoip` and the RA daemon carried.
 *
 * **The management path is the worse of the two and is why this test covers
 * both.** That path also unlinked the management socket, which openvpn removes
 * itself on the way out. Unlink it early, let a restart bind a new socket at
 * the same path, and the daemon that was leaving deletes the live tunnel's
 * socket -- after which netcfgd cannot reach a tunnel that is running
 * perfectly well.
 *
 * **The assertion is the relationship, not a duration.** A timing check would
 * pass or fail with the machine; "after the stop returns, the daemon is gone"
 * is false exactly when the wait is missing. Read through
 * `/proc/<pid>/cmdline` rather than `kill(pid, 0)`, because a process nothing
 * has reaped is a zombie and `kill -0` calls it alive.
 */
static int still_alive(pid_t pid)
{
	char  path[64];
	char  buffer[64];
	int   fd;
	ssize_t got;

	(void)snprintf(path, sizeof(path), "/proc/%ld/cmdline", (long)pid);
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		return 0;
	}
	got = read(fd, buffer, sizeof(buffer));
	(void)close(fd);
	/* Empty is a zombie: the entry is there and the process is not. */
	return got > 0;
}

static void a_daemon_slow_to_exit_is_waited_for(const char *base)
{
	char  run[512];
	char  dir[640];
	char  holder[1024];
	char  pid_file[1024];
	char  socket_path[1024];
	char  body[4096];
	char  message[NCFG_ERROR_MAX];
	char *written;
	pid_t held;
	pid_t               parent;

	(void)testdir_in(base, "slowstop", run, sizeof(run));
	check(mkdir(run, 0755) == 0, "a run directory for the slow stop");
	(void)snprintf(dir, sizeof(dir), "%s/openvpn", run);
	check(mkdir(dir, 0755) == 0, "and the openvpn directory inside it");
	(void)snprintf(pid_file, sizeof(pid_file), "%s/vpn0.pid", dir);
	(void)snprintf(socket_path, sizeof(socket_path), "%s/vpn0.sock", dir);
	(void)testdir_in(run, "holder", holder, sizeof(holder));

	/*
	 * **The stand-in has to be matchable, which is what shapes it.**
	 * `ncfg_openvpn_running_pid` reads the pid file and then checks that
	 * process's command line for this tunnel's socket path, so the holder has
	 * to recite the path -- the interface name alone is what that function
	 * deliberately refuses to match on. It traps TERM and takes half a second
	 * over it, which is the window the old code returned inside.
	 */
	(void)snprintf(body, sizeof(body),
	    "#!/bin/sh\n"
	    "trap 'sleep 0.5; exit 0' TERM\n"
	    "echo $$ > '%s'\n"
	    "while :; do sleep 0.05; done\n",
	    pid_file);
	check(write_program(holder, body), "a stand-in daemon that is slow to exit is written");

	parent = getpid();
	held = fork();
	if (held == 0) {
		(void)setpgid(0, 0);
		/* Dies with the test, whatever kills it: this stand-in ignores
		 * `TERM` on purpose and loops for ever, so a test binary that died
		 * before stopping it would leave it running -- dhcp_test's twin was
		 * found reparented to init three days after its run. */
		(void)prctl(PR_SET_PDEATHSIG, SIGKILL);
		if (getppid() != parent) {
			_exit(127);
		}
		(void)execl("/bin/sh", "sh", holder, socket_path, (char *)NULL);
		_exit(127);
	}
	check(held > 0, "the stand-in is running");

	/* Wait for it to have written its pid, so the stop has something to find.
	 * Without this the test could pass by the stop finding nothing at all,
	 * which is the vacuous version of the thing being checked. */
	{
		int waited = 0;

		while (waited < 100) {
			struct timespec step = { 0, 50L * 1000000L };

			written = testdir_read(pid_file, NULL);
			if (written && written[0] != '\0') {
				free(written);
				break;
			}
			free(written);
			(void)nanosleep(&step, NULL);
			waited++;
		}
	}
	check(ncfg_openvpn_running_pid(run, "vpn0") > 0,
	    "and netcfgd finds it by its pid file and this tunnel's socket path");

	/*
	 * Nothing is listening on the management socket, so this takes the pid
	 * path -- the one that signals directly. The management path shares the
	 * same waiter, and `the_greeting_is_not_mistaken_for_an_answer` covers the
	 * command it sends.
	 */
	message[0] = '\0';
	check(ncfg_openvpn_stop(run, "vpn0", NULL, message, sizeof(message)),
	    "a stop of a daemon that is slow to exit succeeds");
	if (message[0] != '\0') {
		printf("  said: %s\n", kept(message));
	}
	check(!still_alive(held),
	    "and it has gone by the time the stop returns, so a start that follows "
	    "cannot meet the daemon it replaced");
	written = testdir_read(pid_file, NULL);
	check(written == NULL, "the pid file is removed only after that");
	free(written);

	(void)wait_for(held);
}

/*
 * A MANAGEMENT STOP AGAINST A DAEMON SLOW TO EXIT, AND THE SOCKET IT MUST NOT
 * PULL AWAY.
 *
 * 10.571 named this gap rather than leaving it as an assumption that the
 * shared waiter was enough: the test above drives the pid path, and **the
 * management path is the one with the hazard**. It sends `signal SIGTERM` over
 * the management socket -- which returns when openvpn has read the line, not
 * when it has gone -- and then unlinks that socket, which openvpn removes
 * itself on the way out.
 *
 * **So this reproduces the hazard rather than asserting a duration.** The
 * stand-in does what openvpn does: it lives on after the command, then unlinks
 * the socket path as it exits. After the stop returns, the test puts a file
 * where the next start's socket would be. If the stop waited, the stand-in is
 * already gone and that file survives; if it did not, the stand-in is still
 * alive and deletes it -- which is precisely a restart losing the live
 * tunnel's management socket to the daemon it replaced.
 */
static void a_management_stop_does_not_pull_the_socket_from_the_next_start(const char *base)
{
	char               run[512];
	char               dir[640];
	char               socket_path[1024];
	char               pid_file[1024];
	char               holder[1024];
	char               body[4096];
	char               message[NCFG_ERROR_MAX];
	struct sockaddr_un address;
	int                listener;
	pid_t              server;
	pid_t              held;
	pid_t              parent;
	char              *written;

	(void)testdir_in(base, "mgmtslow", run, sizeof(run));
	check(mkdir(run, 0755) == 0, "a run directory for the management stop");
	(void)snprintf(dir, sizeof(dir), "%s/openvpn", run);
	check(mkdir(dir, 0755) == 0, "and the openvpn directory inside it");
	(void)snprintf(socket_path, sizeof(socket_path), "%s/vpn0.sock", dir);
	(void)snprintf(pid_file, sizeof(pid_file), "%s/vpn0.pid", dir);
	(void)testdir_in(run, "holder", holder, sizeof(holder));

	listener = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	if (strlen(socket_path) + 1u > sizeof(address.sun_path)) {
		check(0, "the temporary directory leaves room for a unix socket path");
		(void)close(listener);
		return;
	}
	memcpy(address.sun_path, socket_path, strlen(socket_path) + 1u);
	check(listener >= 0 &&
	    bind(listener, (const struct sockaddr *)&address, sizeof(address)) == 0 &&
	    listen(listener, 1) == 0,
	    "a stand-in daemon is listening on the management socket");

	/* The management half: greet, take the command, answer as openvpn does. */
	server = fork();
	if (server == 0) {
		int     served = accept(listener, NULL, NULL);
		char    asked[256];
		ssize_t got;

		(void)setpgid(0, 0);
		if (served < 0) {
			_exit(1);
		}
		(void)write(served, ">INFO:OpenVPN Management Interface Version 5\n", 45u);
		/*
		 * **Read to the newline, not just once.** netcfgd sends the command
		 * and its newline as two writes, so a single `read` can return the
		 * command without its terminator -- and a stand-in that answers and
		 * closes at that point leaves the newline landing on a closed peer.
		 * That is how this fixture killed the suite under load before
		 * `MSG_NOSIGNAL` (10.573), and a fixture whose timing decides whether
		 * the run survives is not a fixture.
		 */
		{
			size_t taken = 0u;

			for (;;) {
				got = read(served, asked + taken, sizeof(asked) - taken);
				if (got <= 0) {
					_exit(1);
				}
				taken += (size_t)got;
				if (memchr(asked, '\n', taken) || taken == sizeof(asked)) {
					break;
				}
			}
		}
		(void)write(served, "SUCCESS: signal SIGTERM thrown\n", 31u);
		(void)close(served);
		_exit(0);
	}
	check(server > 0, "the management stand-in is running");

	/*
	 * The process half, which is what `ncfg_openvpn_running_pid` sees: it
	 * recites the socket path, writes its pid where openvpn writes its own,
	 * and **removes the socket as it goes**, which is the behaviour that makes
	 * the race dangerous rather than merely untidy.
	 */
	(void)snprintf(body, sizeof(body),
	    "#!/bin/sh\n"
	    "echo $$ > '%s'\n"
	    "sleep 0.6\n"
	    "rm -f '%s'\n"
	    "exit 0\n",
	    pid_file, socket_path);
	check(write_program(holder, body), "a stand-in that outlives the command is written");
	parent = getpid();
	held = fork();
	if (held == 0) {
		(void)setpgid(0, 0);
		/* Dies with the test, as the slow-stop stand-in above does. */
		(void)prctl(PR_SET_PDEATHSIG, SIGKILL);
		if (getppid() != parent) {
			_exit(127);
		}
		(void)execl("/bin/sh", "sh", holder, socket_path, (char *)NULL);
		_exit(127);
	}
	check(held > 0, "and is running");
	{
		int waited = 0;

		while (waited < 100) {
			struct timespec step = { 0, 20L * 1000000L };

			if (ncfg_openvpn_running_pid(run, "vpn0") > 0) {
				break;
			}
			(void)nanosleep(&step, NULL);
			waited++;
		}
	}
	check(ncfg_openvpn_running_pid(run, "vpn0") > 0,
	    "  and netcfgd finds it, so this stop is not measuring an empty run directory");

	message[0] = '\0';
	check(ncfg_openvpn_stop(run, "vpn0", NULL, message, sizeof(message)),
	    "a management stop against a daemon slow to exit succeeds");
	if (message[0] != '\0') {
		printf("  said: %s\n", kept(message));
	}
	check(!still_alive(held),
	    "and the daemon has gone by the time it returns, which is what the socket "
	    "below depends on");
	written = testdir_read(pid_file, NULL);
	check(written == NULL, "the pid file is removed only after that");
	free(written);

	/*
	 * **The next start's socket, and the assertion the whole test exists
	 * for.** Nothing may delete this but the daemon that has already gone.
	 */
	check(testdir_write(socket_path, "next\n", 5u), "the next start binds its own socket");
	{
		struct timespec settle = { 1, 0 };

		(void)nanosleep(&settle, NULL);
	}
	check(testdir_exists(socket_path),
	    "and it survives, so the stop did not leave the old daemon to delete the new "
	    "tunnel's socket");
	(void)unlink(socket_path);

	(void)wait_for(server);
	(void)wait_for(held);
	(void)close(listener);
}

/*
 * A PEER THAT CLOSES MID-COMMAND IS AN ERROR, NOT A DEAD DAEMON.
 *
 * netcfgd sends a management command as two writes -- the command, then its
 * newline -- and the peer is openvpn, which the command usually tells to
 * terminate. So netcfgd writes to a process it is in the act of killing, and a
 * plain `write` to a closed peer raises `SIGPIPE`, whose default action ends
 * the process holding `CAP_NET_ADMIN`.
 *
 * `answer.c` already records this rule for the control socket -- "a daemon
 * holding CAP_NET_ADMIN must not be killable by a client disconnecting" -- and
 * the management client was written with `write` anyway. **This is that rule's
 * control, on the socket where the peer's death is intended rather than
 * merely possible.**
 *
 * The stand-in reads one byte and closes, which puts the newline on a dead
 * socket every time rather than when the scheduler happens to allow it. With
 * `MSG_NOSIGNAL` the call returns an error naming the command; without it this
 * process dies here and the suite reports nothing at all, which is exactly how
 * the bug was found.
 */
static void a_peer_that_closes_mid_command_is_an_error(const char *base)
{
	char                       run[512];
	char                       path[1024];
	struct sockaddr_un         address;
	int                        listener;
	pid_t                      child;
	ncfg_openvpn_management_t *management;
	char                       message[NCFG_ERROR_MAX];
	char                       closed[1024];

	(void)testdir_in(base, "halfclose", run, sizeof(run));
	check(mkdir(run, 0755) == 0, "a directory for the half-closing stand-in");
	(void)testdir_in(run, "vpn0.sock", path, sizeof(path));
	(void)testdir_in(run, "closed", closed, sizeof(closed));

	listener = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	if (strlen(path) + 1u > sizeof(address.sun_path)) {
		check(0, "the temporary directory leaves room for a unix socket path");
		(void)close(listener);
		return;
	}
	memcpy(address.sun_path, path, strlen(path) + 1u);
	check(listener >= 0 &&
	    bind(listener, (const struct sockaddr *)&address, sizeof(address)) == 0 &&
	    listen(listener, 1) == 0,
	    "a stand-in that will hang up mid-command is listening");

	child = fork();
	if (child == 0) {
		int  served = accept(listener, NULL, NULL);
		char one[1];

		(void)setpgid(0, 0);
		if (served < 0) {
			_exit(1);
		}
		/*
		 * **Greet, then close at once, and do not read.** The first draft read
		 * a byte first and the run reported `no answer to \`signal SIGTERM\``
		 * -- the writes had both succeeded and the READ had failed, so the test
		 * was exercising the reply path and not the write path at all. A peer
		 * that is already closed when netcfgd writes is the only version of
		 * this that tests what it claims to.
		 *
		 * The greeting still goes, so `ncfg_openvpn_connect` has its
		 * connection; closing the write side afterwards is what makes
		 * netcfgd's `send` meet a dead peer.
		 */
		(void)write(served, ">INFO:OpenVPN Management Interface Version 5\n", 45u);
		(void)close(served);
		/*
		 * **The marker is the synchronisation, and the first version of this
		 * test did not have it.** Two drafts reported `no answer to \`signal
		 * SIGTERM\``: netcfgd had written before the peer managed to close, so
		 * both writes landed in the socket buffer and the READ was what
		 * failed -- the test was exercising the reply path while claiming the
		 * write path. A third draft waited on a marker the child never wrote,
		 * so a two-second timeout did the synchronising and the check for the
		 * marker failed while the test passed. The write path is reached only
		 * if the close has definitely happened, and only a handshake makes
		 * that true rather than likely.
		 */
		(void)testdir_write(closed, "gone\n", 5u);
		(void)one;
		_exit(0);
	}
	check(child > 0, "the stand-in is running");

	message[0] = '\0';
	management = ncfg_openvpn_connect(path, message, sizeof(message));
	check(management != NULL, "the client connects");
	if (management) {
		int waited = 0;

		/* Wait for the stand-in to have closed, so the command below is written
		 * to a peer that is certainly gone. */
		while (!testdir_exists(closed) && waited < 200) {
			struct timespec step = { 0, 10L * 1000000L };

			(void)nanosleep(&step, NULL);
			waited++;
		}
		check(testdir_exists(closed),
		    "  and has closed its end before netcfgd writes, which is the point");
		message[0] = '\0';
		/*
		 * **Reaching the next line at all is the assertion.** A process killed
		 * by SIGPIPE prints nothing and fails no check; it simply stops, and
		 * the suite exits non-zero with its output ending mid-file.
		 */
		int sent = ncfg_openvpn_command(management, "signal SIGTERM", NULL, 0u, message,
		    sizeof(message));

		check(1, "and netcfgd is still alive after writing to a peer that hung up");
		/*
		 * **Not `|| 1`, which the first draft of this line had.** A check that
		 * cannot fail is worse than no check: it reads as coverage. The command
		 * must fail here -- either the write meets the closed peer or the reply
		 * never comes -- and a failure has to carry a sentence, which is this
		 * tree's rule for every refusal an operator may meet.
		 */
		check(!sent && message[0] != '\0',
		    "  reporting the failure with a sentence rather than being signalled");
		if (message[0] != '\0') {
			printf("  said: %s\n", kept(message));
		}
		ncfg_openvpn_disconnect(management);
	}
	(void)wait_for(child);
	(void)close(listener);
	(void)unlink(path);
}

/*
 * A DAEMON THAT LEFT UNDER THE COMMAND IS A STOP THAT TOOK.
 *
 * `Broken pipe` from `signal SIGTERM` is the ordinary way openvpn says it is
 * going: the socket closes under netcfgd's write. Reporting that as a failed
 * stop asks an operator to fix a tunnel that is gone, and this file already
 * holds the rule in its own words -- stopping one that is already stopped is
 * not an error.
 *
 * So the stop asks by waiting rather than by reading the errno, which covers
 * every way a command can fail against a departing daemon rather than only the
 * one that was measured. Here nothing is running at all, which is the state a
 * daemon that has finished leaving is in.
 *
 * **The refusal arm is unchanged and is what the sentence was written for**: a
 * daemon that is genuinely alive and refusing still costs the patience and
 * still gets the named refusal (10.571). That arm is not exercised here --
 * driving it would hold a stand-in alive for the full 3000 ms -- and 10.574
 * says so rather than implying the pair is covered.
 */
static void a_daemon_that_left_under_the_command_is_a_stop_that_took(const char *base)
{
	char               run[512];
	char               dir[640];
	char               socket_path[1024];
	struct sockaddr_un address;
	int                listener;
	pid_t              child;
	char               message[NCFG_ERROR_MAX];

	(void)testdir_in(base, "leftunder", run, sizeof(run));
	check(mkdir(run, 0755) == 0, "a run directory for the departing daemon");
	(void)snprintf(dir, sizeof(dir), "%s/openvpn", run);
	check(mkdir(dir, 0755) == 0, "and the openvpn directory inside it");
	(void)snprintf(socket_path, sizeof(socket_path), "%s/vpn0.sock", dir);

	listener = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	if (strlen(socket_path) + 1u > sizeof(address.sun_path)) {
		check(0, "the temporary directory leaves room for a unix socket path");
		(void)close(listener);
		return;
	}
	memcpy(address.sun_path, socket_path, strlen(socket_path) + 1u);
	check(listener >= 0 &&
	    bind(listener, (const struct sockaddr *)&address, sizeof(address)) == 0 &&
	    listen(listener, 1) == 0,
	    "a socket is listening, as a daemon on its way out still has one");

	/*
	 * **No pid file, which is the whole setup.** A daemon that has gone leaves
	 * none, so `ncfg_openvpn_running_pid` answers 0 -- and the management
	 * socket is still bound because nothing has unlinked it yet, which is why
	 * netcfgd takes the management path rather than the pid one.
	 */
	child = fork();
	if (child == 0) {
		int served = accept(listener, NULL, NULL);

		(void)setpgid(0, 0);
		if (served < 0) {
			_exit(1);
		}
		(void)write(served, ">INFO:OpenVPN Management Interface Version 5\n", 45u);
		(void)close(served);
		_exit(0);
	}
	check(child > 0, "a stand-in that hangs up is running");

	message[0] = '\0';
	check(ncfg_openvpn_stop(run, "vpn0", NULL, message, sizeof(message)),
	    "a stop whose command failed against a daemon that has gone is success");
	if (message[0] != '\0') {
		printf("  said: %s\n", kept(message));
	}
	/* And it tidied: the socket a departing daemon may not have removed is the
	 * one that would take the bind on the next start. */
	check(!testdir_exists(socket_path),
	    "  and the management socket is gone, so the next start can bind its own");

	(void)wait_for(child);
	(void)close(listener);
}

/*
 * A TUNNEL THAT WILL NOT GO IS A REFUSAL, AND IT KEEPS WHAT THE NEXT START
 * WOULD COLLIDE WITH.
 *
 * The other arm of this file's wait, and the last gap 10.571 named. A daemon
 * that goes is covered above; this is the one that does not.
 *
 * **What it asserts is the keeping, not the sentence.** The pid file and the
 * management socket are what the refusal holds on to, and holding them is the
 * whole reason the arm exists: removing them while the daemon is alive is
 * exactly the collision proved earlier in this file, where the departing
 * daemon deletes the next start's socket. A refusal that tidied up anyway
 * would reintroduce it by the one path that reports failure.
 *
 * **It costs the full patience, 3000 ms, and that is why it is one test and
 * not two.** openvpn's figure is a `#define` rather than a field, unlike
 * `dhcp`'s `machine->patience_ms`, and adding a parameter to a public stop
 * for a test's benefit is a production seam this tree declined (10.578). So
 * the arm is bought once, here, at three seconds.
 */
static void a_tunnel_that_will_not_go_is_a_refusal(const char *base)
{
	char  run[512];
	char  dir[640];
	char  socket_path[1024];
	char  pid_file[1024];
	char  holder[1024];
	char  body[4096];
	char  message[NCFG_ERROR_MAX];
	pid_t held;
	pid_t parent;
	int   waited = 0;

	(void)testdir_in(base, "stubborn", run, sizeof(run));
	check(mkdir(run, 0755) == 0, "a run directory for the stubborn tunnel");
	(void)snprintf(dir, sizeof(dir), "%s/openvpn", run);
	check(mkdir(dir, 0755) == 0, "and the openvpn directory inside it");
	(void)snprintf(pid_file, sizeof(pid_file), "%s/vpn0.pid", dir);
	(void)snprintf(socket_path, sizeof(socket_path), "%s/vpn0.sock", dir);
	(void)testdir_in(run, "holder", holder, sizeof(holder));

	/* **Ignoring `TERM` outright rather than being slow**, so the wait reaches
	 * its patience instead of racing a process that was going to exit. */
	(void)snprintf(body, sizeof(body),
	    "#!/bin/sh\n"
	    "trap '' TERM\n"
	    "echo $$ > '%s'\n"
	    "while :; do sleep 0.05; done\n",
	    pid_file);
	check(write_program(holder, body), "a stand-in that ignores SIGTERM is written");
	parent = getpid();
	held = fork();
	if (held == 0) {
		(void)setpgid(0, 0);
		/* Dies with the test, as the slow-stop stand-in above does. */
		(void)prctl(PR_SET_PDEATHSIG, SIGKILL);
		if (getppid() != parent) {
			_exit(127);
		}
		(void)execl("/bin/sh", "sh", holder, socket_path, (char *)NULL);
		_exit(127);
	}
	check(held > 0, "and is running");
	while (waited < 100) {
		struct timespec step = { 0, 20L * 1000000L };

		if (ncfg_openvpn_running_pid(run, "vpn0") > 0) {
			break;
		}
		(void)nanosleep(&step, NULL);
		waited++;
	}
	check(ncfg_openvpn_running_pid(run, "vpn0") > 0,
	    "  which netcfgd finds, so the refusal is about a real daemon");

	/* No listener, so this takes the pid path; the management path shares the
	 * same waiter and the same arm. */
	message[0] = '\0';
	check(!ncfg_openvpn_stop(run, "vpn0", NULL, message, sizeof(message)),
	    "a stop of a tunnel that will not go is a failure rather than a silent success");
	check(strstr(message, "vpn0") != NULL,
	    "  naming the interface, since an operator may have several tunnels");
	check(strstr(message, "pid file is kept") != NULL,
	    "  and saying the record was kept");
	if (message[0] != '\0') {
		printf("  said: %s\n", kept(message));
	}
	check(testdir_exists(pid_file),
	    "and the pid file survives, so the next start meets a tunnel rather than a gap");

	(void)kill(held, SIGKILL);
	(void)wait_for(held);
}

static void stopping_a_tunnel_that_is_not_there_is_success(const char *base)
{
	char run[512];
	char report[1024];
	char hash[NCFG_OPENVPN_PATH_MAX];
	char pid_file[NCFG_OPENVPN_PATH_MAX];
	char mine[32];
	char message[NCFG_ERROR_MAX];

	(void)testdir_in(base, "stop", run, sizeof(run));
	check(mkdir(run, 0755) == 0, "a run directory for the stop");
	check(ncfg_openvpn_run_dir(run, hash, sizeof(hash), NULL, 0) && mkdir(hash, 0755) == 0,
	    "and its openvpn subdirectory");
	(void)testdir_in(run, "reported-vpn0", report, sizeof(report));
	check(testdir_write(report, "route=10.0.0.0/8 via 10.8.0.1\n", 30u), "a stale report");
	check(ncfg_openvpn_config_hash_path(run, "vpn0", hash, sizeof(hash), NULL, 0) &&
	    testdir_write(hash, "deadbeef", 8u),
	    "and a stale record of what it was started from");

	/* A pid file naming this very process, whose command line does not carry
	 * this tunnel's socket path. It must not be signalled. */
	check(ncfg_openvpn_pid_path(run, "vpn0", pid_file, sizeof(pid_file), NULL, 0), "the pid "
	                                          "path");
	(void)snprintf(mine, sizeof(mine), "%d\n", (int)getpid());
	check(testdir_write(pid_file, mine, strlen(mine)), "a pid file naming this process");
	check(ncfg_openvpn_running_pid(run, "vpn0") == 0,
	    "a pid whose command line does not name this tunnel's socket is not this tunnel");

	message[0] = '\0';
	check(ncfg_openvpn_stop(run, "vpn0", report, message, sizeof(message)),
	    "stopping a tunnel that is neither reachable nor running is the state asked for");
	check(!testdir_exists(report), "the report is gone, because the routes it claims are");
	check(!testdir_exists(hash), "and so is the record of a tunnel that is not running");
	check(!testdir_exists(pid_file), "and the pid file naming nothing this tunnel owns");
	check(getpid() > 0, "and this process was not signalled");
}

/* --------------------------------------------------------------- the sweep */

static void the_credential_reaches_no_diagnostic(const char *stderr_path)
{
	char *errors;

	check(strstr(every_message, CANARY) == NULL,
	    "no `err` buffer this file has filled carries the password");
	(void)fflush(stderr);
	errors = testdir_read(stderr_path, NULL);
	check(errors != NULL && strstr(errors, CANARY) == NULL,
	    "nor does this process' whole standard error");
	free(errors);
}

int main(void)
{
	const char *base = testdir_make("openvpn");
	char        config[512];
	char        stderr_path[512];
	int         saved;
	int         redirected;

	(void)testdir_in(base, "stderr", stderr_path, sizeof(stderr_path));
	saved = dup(STDERR_FILENO);
	redirected = open(stderr_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (redirected >= 0) {
		(void)dup2(redirected, STDERR_FILENO);
		(void)close(redirected);
	}

	/* The operator's file. Its content is deliberately something netcfgd must
	 * not care about: 0046 keeps it theirs, and nothing here reads it. */
	(void)testdir_in(base, "office.ovpn", config, sizeof(config));
	if (!testdir_write(config, "remote vpn.example.com 1194\nup /usr/local/bin/theirs\n", 53u)) {
		printf("could not write the fixture .ovpn\n");
		return 1;
	}

	a_config_record_that_cannot_be_written_names_the_file_and_the_reason(base);
	a_config_record_is_the_hash_of_the_file(base);
	the_script_stages_under_a_dot();
	the_script_parses_and_reports(base);
	the_tunnel_is_started_with_the_flags_that_carry_the_design(base);
	the_credentials_go_in_a_file_and_never_on_the_command_line(base);
	a_daemon_that_will_not_start_is_quoted(base);
	the_greeting_is_not_mistaken_for_an_answer(base);
	a_daemon_slow_to_exit_is_waited_for(base);
	a_management_stop_does_not_pull_the_socket_from_the_next_start(base);
	a_peer_that_closes_mid_command_is_an_error(base);
	a_daemon_that_left_under_the_command_is_a_stop_that_took(base);
	a_tunnel_that_will_not_go_is_a_refusal(base);
	stopping_a_tunnel_that_is_not_there_is_success(base);
	the_credential_reaches_no_diagnostic(stderr_path);

	if (saved >= 0) {
		(void)fflush(stderr);
		(void)dup2(saved, STDERR_FILENO);
		(void)close(saved);
	}
	testdir_remove(base);
	if (failures > 0) {
		printf("openvpn: %d check(s) failed\n", failures);
		return 1;
	}
	printf("openvpn: every check passed\n");
	return 0;
}
