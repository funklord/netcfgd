/*
 * dhcp_test.c -- which client is started, with what, and whose the one already
 * running is.
 *
 * WHAT THESE CASES ARE FOR
 *   The arguments and the marks, because every one of them carries a measured
 *   reason that nothing else would notice if it were dropped:
 *
 *   * **`-O search`.** udhcpc does not request option 119 by default, so a
 *     server that honours the request list never sends a search list. 0067's
 *     suffixes reached netcfgd only because the live test's server was
 *     `busybox udhcpd`, which pushes every configured option whether it was
 *     asked for or not -- found by porting that test to a second server, not
 *     by reading the code.
 *   * **`-R`.** Without it a stopped udhcpc leaves its address on the
 *     interface, where `dhcpcd -k` takes it away: two behaviours for one
 *     `backend.stop`.
 *   * **The family flag.** `dhcpcd -k <iface>` without one looks for
 *     `<iface>.pid`, finds nothing, and says "dhcpcd is not running" -- which
 *     is also what a machine with no dhcpcd says, so a client that was still
 *     renewing was reported stopped (0070).
 *   * **`-c`.** Every dhcpcd netcfgd starts gets the hook, because "leave
 *     dhcpcd's own hooks alone" meant a lease rewriting `/etc/resolv.conf` on
 *     a machine where netcfgd's DNS mode owns that file (0072).
 *   * **`-f`, and that it is a symlink.** It is the one mark dhcpcd keeps:
 *     `setproctitle` destroys its argv, so ownership is read off its control
 *     socket or not at all (0143). Pointing at the operator's file rather than
 *     replacing it keeps their `duid` and `persistent`, which `-f` would
 *     otherwise drop silently.
 *   * **`-p`, and that it is the marker.** udhcpc carries netcfgd's pid-file
 *     path in its own `argv` for as long as it lives, which is what lets a
 *     client be adopted after the run directory has been deleted underneath
 *     it -- and what makes a signal defensible without finding a process by
 *     name.
 *
 *   And the two verbs around them: a start that adopts rather than doubling,
 *   and a stop that asks whose the client is before it signals anything.
 *
 * NOTHING OUTSIDE ITS OWN DIRECTORY, AND NO REAL CLIENT
 *   This machine's real netcfgd is managing its real network. Every path here
 *   is under one `mkdtemp` directory; the run directory, dhcpcd's run
 *   directory, the hook and all three programs are parameters of every call,
 *   and **every program started is a shell script this test wrote**. Nothing
 *   here obtains a lease, signals a client it did not start, or touches
 *   `/run`, `/etc` or a real interface.
 *
 *   The one process this starts that is not a script is `/bin/sh -c 'sleep
 *   20'`, which stands in for a client carrying netcfgd's mark in its own
 *   `argv`. It is put in its own process group, its pid is recorded, and it is
 *   killed by that pid -- and it would exit on its own inside half a minute if
 *   this binary died first.
 */
#include "ncfg/apply.h"
#include "ncfg/base.h"
#include "ncfg/dhcp.h"
#include "ncfg/document.h"

#include "testdir.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int failures;

static void check(int condition, const char *what)
{
	printf("%-74s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

static void check_text(const char *got, const char *want, const char *what)
{
	int same = got != NULL && strcmp(got, want) == 0;

	check(same, what);
	if (!same) {
		printf("  wanted:\n%s\n  got:\n%s\n", want, got ? got : "(null)");
	}
}

/* Where everything in this binary lives. */
static char run_dir[256];
static char dhcpcd_dir[256];
static char hook_path[256];

/* ------------------------------------------------------------------------ *
 * Fixtures
 * ------------------------------------------------------------------------ */

static void write_fake(const char *path, const char *body)
{
	check(testdir_write(path, body, strlen(body)) && chmod(path, 0755) == 0,
	    "a stand-in program is written and made executable");
}

/* A program that writes its argument list, one per line, and exits `status`. */
static void write_recorder(const char *path, const char *record, int status)
{
	char body[1024];

	(void)snprintf(body, sizeof(body), "#!/bin/sh\nprintf '%%s\\n' \"$@\" > '%s'\nexit %d\n",
	    record, status);
	write_fake(path, body);
}

/*
 * A process carrying `marker` as a whole `argv` element.
 *
 * `sh -c 'sleep 20' <marker>` puts the marker in `$0` of the shell, which is
 * argv[3] of the process -- exactly the shape `process.h` describes and
 * exactly what `udhcpc -p <path>` produces. **Its own process group**, so that
 * what this test kills is what this test started and nothing above it, and a
 * lifetime of twenty seconds so that a binary that died before its teardown
 * leaves nothing behind either.
 */
static pid_t spawn_marked(const char *marker)
{
	pid_t child = fork();

	if (child < 0) {
		return -1;
	}
	if (child == 0) {
		const char *argv[5];

		(void)setpgid(0, 0);
		argv[0] = "/bin/sh";
		argv[1] = "-c";
		argv[2] = "sleep 20";
		argv[3] = marker;
		argv[4] = NULL;
		execv("/bin/sh", (char *const *)(const void *)argv);
		_exit(127);
	}
	/* The child may not have reached `setpgid` yet; doing it in both is the
	 * documented way to make the race harmless. */
	(void)setpgid(child, child);
	/* And it may not have reached `execv` either, so wait until the marker is
	 * actually in its command line rather than sleeping a fixed time. */
	{
		int looks;

		for (looks = 0; looks < 200; looks++) {
			struct timespec step;
			char            path[64];
			char           *bytes;
			size_t          length = 0;
			int             found = 0;

			(void)snprintf(path, sizeof(path), "/proc/%d/cmdline", (int)child);
			bytes = testdir_read(path, &length);
			if (bytes) {
				size_t at;

				for (at = 0; at + strlen(marker) < length + 1u; at++) {
					if ((at == 0u || bytes[at - 1u] == '\0') &&
					    strcmp(bytes + at, marker) == 0) {
						found = 1;
						break;
					}
				}
				free(bytes);
			}
			if (found) {
				return child;
			}
			step.tv_sec = 0;
			step.tv_nsec = 5L * 1000000L;
			(void)nanosleep(&step, NULL);
		}
	}
	return child;
}

/* Kill exactly what `spawn_marked` started, by the pid it answered. */
static void stop_marked(pid_t child)
{
	if (child <= 0) {
		return;
	}
	(void)kill(-child, SIGKILL);
	(void)kill(child, SIGKILL);
	while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {
		continue;
	}
}

/*
 * Whether a process this test started has gone, within `milliseconds`.
 *
 * **Reaped rather than signalled with 0, and asked once.** These are this
 * binary's own children, so `kill(pid, 0)` succeeds against a zombie and would
 * report a terminated client as still running -- which is the one thing this
 * exists to tell apart. `waitpid` answers correctly and *consumes* the answer,
 * so a predicate called in a loop would say "gone" once and "still there" for
 * ever after: the loop is inside.
 */
static int gone_within(pid_t child, int milliseconds)
{
	int waited = 0;

	if (child <= 0) {
		return 1;
	}
	for (;;) {
		struct timespec step;

		if (waitpid(child, NULL, WNOHANG) == child) {
			return 1;
		}
		if (waited >= milliseconds) {
			return 0;
		}
		step.tv_sec = 0;
		step.tv_nsec = 5L * 1000000L;
		(void)nanosleep(&step, NULL);
		waited += 5;
	}
}

/* ------------------------------------------------------------------------ *
 * A dhcpcd control socket, answering what a real one answered
 * ------------------------------------------------------------------------ */

/*
 * Every `--getconfigfile`, answered in a child of this test.
 *
 * The framing is dhcpcd 10.1.0's, measured in `contention_test.c`: a native
 * `size_t` length prefix and then the NUL-terminated path. dhcpcd does not
 * close the connection, so the linger below is what the caller's own deadline
 * ends -- long enough to outlive the answer, short enough not to be a sleep in
 * a test suite.
 *
 * **It answers for as long as it is left alive**, which is what a stop needs:
 * that path asks once before it signals and again afterwards, and a socket
 * that answered only once would report every stop a success by falling silent.
 * The `alarm` is a ceiling on a child of this test that nothing else bounds.
 */
static void serve_forever(int listener, const char *recites)
{
	unsigned char reply[NCFG_DHCPCD_REPLY_MAX];
	size_t        length = strlen(recites) + 1u;
	size_t        at;

	alarm(60);
	memset(reply, 0, sizeof(reply));
	for (at = 0; at < sizeof(size_t); at++) {
		reply[at] = (unsigned char)((length >> (8u * at)) & 0xffu);
	}
	memcpy(reply + sizeof(size_t), recites, length);
	for (;;) {
		struct timespec linger;
		char            asked[64];
		int             talking = accept(listener, NULL, NULL);

		if (talking < 0) {
			_exit(1);
		}
		if (read(talking, asked, sizeof(asked)) > 0) {
			(void)write(talking, reply, sizeof(size_t) + length);
		}
		linger.tv_sec = 0;
		linger.tv_nsec = 120L * 1000000L;
		(void)nanosleep(&linger, NULL);
		(void)close(talking);
	}
}

/* Stand up a socket where dhcpcd would, answering one question. 0 on failure. */
static pid_t a_dhcpcd_reciting(const char *iface, const char *family, const char *recites,
    char *path, size_t path_size)
{
	struct sockaddr_un where;
	int                listener;
	pid_t              server;

	(void)snprintf(path, path_size, "%s/%s-%s.sock", dhcpcd_dir, iface, family);
	(void)unlink(path);
	listener = socket(AF_UNIX, SOCK_STREAM, 0);
	if (listener < 0 || strlen(path) >= sizeof(where.sun_path)) {
		return 0;
	}
	memset(&where, 0, sizeof(where));
	where.sun_family = AF_UNIX;
	memcpy(where.sun_path, path, strlen(path) + 1u);
	if (bind(listener, (const struct sockaddr *)&where, (socklen_t)sizeof(where)) != 0 ||
	    listen(listener, 1) != 0) {
		(void)close(listener);
		return 0;
	}
	server = fork();
	if (server < 0) {
		(void)close(listener);
		return 0;
	}
	if (server == 0) {
		serve_forever(listener, recites);
	}
	(void)close(listener);
	return server;
}

/* Kill exactly the server this test forked, by the pid it answered, and take
 * the socket file with it. */
static void reap(pid_t server, const char *path)
{
	if (server > 0) {
		(void)kill(server, SIGKILL);
		while (waitpid(server, NULL, 0) < 0 && errno == EINTR) {
			continue;
		}
	}
	if (path) {
		(void)unlink(path);
	}
}

/* ------------------------------------------------------------------------ *
 * The argument vectors
 * ------------------------------------------------------------------------ */

/* The whole vector, joined, so a missing argument is visible rather than
 * summarised. */
static void joined(const ncfg_dhcp_args_t *args, char *out, size_t out_size)
{
	size_t at;
	size_t filled = 0;

	out[0] = '\0';
	for (at = 0; at < args->count; at++) {
		int put = snprintf(out + filled, out_size - filled, "%s%s", at ? " " : "",
		    args->argv[at]);

		if (put < 0 || (size_t)put >= out_size - filled) {
			return;
		}
		filled += (size_t)put;
	}
}

static void what_udhcpc_is_started_with(void)
{
	ncfg_dhcp_args_t args;
	char             message[NCFG_ERROR_MAX];
	char             line[1024];

	message[0] = '\0';
	check(ncfg_dhcp_udhcpc_args("/sbin/udhcpc", NULL, "eth0", "/run/netcfgd/udhcpc/eth0.script",
	      "/run/netcfgd/udhcpc/eth0.pid", &args, message, sizeof(message)),
	    "udhcpc's command line is built");
	joined(&args, line, sizeof(line));
	check_text(line,
	    "/sbin/udhcpc -b -i eth0 -s /run/netcfgd/udhcpc/eth0.script -p "
	    "/run/netcfgd/udhcpc/eth0.pid -R -O search",
	    "  the whole list, in order, with -R and -O search");
	check(args.argv[args.count] == NULL, "  and it is NULL-terminated for execv");

	/* Debian packages busybox as one binary with no `udhcpc` symlink beside
	 * it, so the applet has to be named -- which is what made the fallback
	 * unreachable on exactly the machines most likely to want it. */
	message[0] = '\0';
	check(ncfg_dhcp_udhcpc_args("/bin/busybox", "udhcpc", "eth0", "/s", "/p", &args, message,
	      sizeof(message)),
	    "busybox is the same client behind an applet name");
	joined(&args, line, sizeof(line));
	check_text(line, "/bin/busybox udhcpc -b -i eth0 -s /s -p /p -R -O search",
	    "  with the applet first and everything else unchanged");

	message[0] = '\0';
	check(!ncfg_dhcp_udhcpc_args(NULL, NULL, "eth0", "/s", "/p", &args, message,
	      sizeof(message)) && message[0] != '\0',
	    "a vector asked for with no program is refused with a sentence");
}

/*
 * The DHCPv6 half: which client can serve a document, and what it is given.
 *
 * **All four combinations, which is why the choice is a pure function.** The
 * refusing one needs a machine with only dhcpcd installed, and a branch no
 * test can make fire is untested code however defensive it looks -- so the
 * Rust keeps its `dhcp6_client` pure and separate for exactly this, and so
 * does this port.
 */
static void which_v6_client_can_serve_the_document(void)
{
	char message[NCFG_ERROR_MAX];

	message[0] = '\0';
	check_text(ncfg_dhcp6_client(0, 1, "eth0", message, sizeof(message)), "odhcp6c",
	    "odhcp6c serves a plain dhcp6 interface");
	check_text(ncfg_dhcp6_client(1, 1, "eth0", message, sizeof(message)), "odhcp6c",
	    "  and one that asks for a delegated prefix");
	check_text(ncfg_dhcp6_client(0, 0, "eth0", message, sizeof(message)), "dhcpcd",
	    "dhcpcd serves one that asks for no prefix, where there is no odhcp6c");

	/* The one that matters, and the one no machine here can reach: dhcpcd
	 * reports the addresses it derived from a prefix rather than the prefix,
	 * and netcfgd does the deriving -- so the lease would arrive and nothing
	 * would come of it (0050). */
	message[0] = '\0';
	check(ncfg_dhcp6_client(1, 0, "eth0", message, sizeof(message)) == NULL,
	    "and a delegation with only dhcpcd installed is refused rather than served");
	check(strstr(message, "eth0") != NULL && strstr(message, "0050") != NULL &&
	    strstr(message, "Install odhcp6c") != NULL,
	    "  naming the interface, the decision, and what to install");
}

static void what_a_prefix_is_asked_for_with(void)
{
	ncfg_pd_request_t request;
	char              out[64];

	memset(&request, 0, sizeof(request));
	check(ncfg_dhcp_prefix_request(&request, out, sizeof(out)) && strcmp(out, "0") == 0,
	    "a request that states no length asks for whatever the server offers");
	request.length.has = 1;
	request.length.value = 56;
	check(ncfg_dhcp_prefix_request(&request, out, sizeof(out)) && strcmp(out, "56") == 0,
	    "  a stated length is the whole argument");
	request.hint = (char *)(void *)"2001:db8::";
	check(ncfg_dhcp_prefix_request(&request, out, sizeof(out)) &&
	    strcmp(out, "2001:db8::/56") == 0,
	    "  and a hint is the pair odhcp6c takes");
	request.length.has = 0;
	check(ncfg_dhcp_prefix_request(&request, out, sizeof(out)) &&
	    strcmp(out, "2001:db8::/0") == 0,
	    "  a hint with no length still asks for any length");

	out[0] = 'x';
	check(!ncfg_dhcp_prefix_request(NULL, out, sizeof(out)) && out[0] == '\0',
	    "no request is no argument, and the buffer is emptied rather than left");
	check(!ncfg_dhcp_prefix_request(&request, out, 4u) && out[0] == '\0',
	    "  and one that would not fit is refused rather than truncated");
}

static void what_odhcp6c_is_started_with(void)
{
	ncfg_dhcp_args_t args;
	char             message[NCFG_ERROR_MAX];
	char             line[1024];

	message[0] = '\0';
	check(ncfg_dhcp_odhcp6c_args("/usr/sbin/odhcp6c", "eth0",
	      "/run/netcfgd/hooks/pd-eth0", "/run/netcfgd/odhcp6c/eth0.pid", NULL, &args,
	      message, sizeof(message)),
	    "odhcp6c's command line is built");
	joined(&args, line, sizeof(line));
	check_text(line,
	    "/usr/sbin/odhcp6c -d -p /run/netcfgd/odhcp6c/eth0.pid -s "
	    "/run/netcfgd/hooks/pd-eth0 eth0",
	    "  and carries no -P at all where the document asked for no prefix");
	check(args.argv[args.count] == NULL, "  and it is NULL-terminated for execv");

	/*
	 * **The half an unconditional `-P` cost.** The Rust records it: every
	 * `config = "dhcp6"` solicited a delegation nobody had written down, and
	 * an ISP handed one out that nothing would ever use. Both directions are
	 * asserted, because "the flag is there when asked for" passes just as
	 * loudly on a build that always passes it.
	 */
	message[0] = '\0';
	check(ncfg_dhcp_odhcp6c_args("/usr/sbin/odhcp6c", "eth0", "/h", "/p", "2001:db8::/56",
	      &args, message, sizeof(message)),
	    "a document that asked for a prefix gets one asked for");
	joined(&args, line, sizeof(line));
	check_text(line, "/usr/sbin/odhcp6c -d -p /p -P 2001:db8::/56 -s /h eth0",
	    "  with -P before the script, and the request as written");

	message[0] = '\0';
	check(ncfg_dhcp_odhcp6c_args("/usr/sbin/odhcp6c", "eth0", "/h", "/p", "", &args, message,
	      sizeof(message)),
	    "an empty request is no request");
	joined(&args, line, sizeof(line));
	check_text(line, "/usr/sbin/odhcp6c -d -p /p -s /h eth0", "  and carries no -P either");

	message[0] = '\0';
	check(!ncfg_dhcp_odhcp6c_args(NULL, "eth0", "/h", "/p", NULL, &args, message,
	      sizeof(message)) && message[0] != '\0',
	    "a vector asked for with no program is refused with a sentence");
}

/*
 * The hook odhcp6c runs, and the file the observer already reads.
 *
 * `ncfg_state_read_reports` has walked `<run>/prefixes/` since the host module
 * landed and nothing ever wrote into it. This is the writer end; what is
 * asserted is the contract between them -- one prefix per line, written to a
 * staged name beside the target and renamed.
 */
static void the_prefix_hook_writes_what_the_observer_reads(void)
{
	char  message[NCFG_ERROR_MAX];
	char *text;

	message[0] = '\0';
	text = ncfg_dhcp_pd_script("eth0", "/run/netcfgd/prefixes/eth0", message,
	    sizeof(message));
	check(text != NULL, "the prefix hook renders");
	if (!text) {
		return;
	}
	check(strncmp(text, "#!/bin/sh\n", 10u) == 0, "  it is a shell script");
	check(strstr(text, "${PREFIXES:-}") != NULL,
	    "  it reads odhcp6c's PREFIXES and nothing else");
	check(strstr(text, "new_delegated_dhcp6_prefix") == NULL &&
	    strstr(text, "new_dhcp6_prefix") == NULL,
	    "  and no dhcpcd variable beside it, which would never be set (0050)");
	check(strstr(text, "${p%%,*}") != NULL,
	    "  odhcp6c's trailing lifetimes are stripped, the prefix being up to the comma");
	check(strstr(text, "'/run/netcfgd/prefixes/.eth0.tmp'") != NULL,
	    "  it writes to the staged name beside the target, which the reader skips");
	check(strstr(text, "mv '/run/netcfgd/prefixes/.eth0.tmp' \"$out\"") != NULL,
	    "  and renames it, so a half-written file is never read as a shorter list");
	check(strstr(text, ": > '/run/netcfgd/prefixes/.eth0.tmp'") != NULL,
	    "  truncating first, so a renewal that dropped a prefix does not leave both");
	free(text);

	message[0] = '\0';
	check(ncfg_dhcp_pd_script(NULL, "/t", message, sizeof(message)) == NULL &&
	    message[0] != '\0',
	    "a hook asked for with no interface is refused with a sentence");
}

static void what_dhcpcd_is_started_with(void)
{
	ncfg_dhcp_args_t args;
	ncfg_optint_t    metric;
	char             message[NCFG_ERROR_MAX];
	char             line[1024];

	metric.has = 0;
	metric.value = 0;
	message[0] = '\0';
	check(ncfg_dhcp_dhcpcd_args("/sbin/dhcpcd", "4", "eth0", &metric, "/usr/libexec/hook",
	      "/run/netcfgd/dhcpcd/eth0-4.conf", &args, message, sizeof(message)),
	    "dhcpcd's command line is built");
	joined(&args, line, sizeof(line));
	check_text(line,
	    "/sbin/dhcpcd -c /usr/libexec/hook -f /run/netcfgd/dhcpcd/eth0-4.conf -b -4 eth0",
	    "  the hook and the mark before the family, and the interface last");

	/* **Zero is a metric and the strongest one**, so an optional integer is
	 * read through its `has` rather than through its value -- a port that read
	 * the value alone would pass `-m 0` on every interface. */
	metric.has = 1;
	metric.value = 0;
	message[0] = '\0';
	check(ncfg_dhcp_dhcpcd_args("/sbin/dhcpcd", "4", "eth0", &metric, "/h", "/c", &args,
	      message, sizeof(message)),
	    "a metric of zero is a metric");
	joined(&args, line, sizeof(line));
	check_text(line, "/sbin/dhcpcd -c /h -f /c -b -4 -m 0 eth0",
	    "  and reaches the client as -m 0 rather than being read as absent");

	metric.has = 1;
	metric.value = 1024;
	message[0] = '\0';
	check(ncfg_dhcp_dhcpcd_args("/sbin/dhcpcd", "6", "wlan0", &metric, "/h", "/c", &args,
	      message, sizeof(message)),
	    "and the v6 client takes the same shape");
	joined(&args, line, sizeof(line));
	check_text(line, "/sbin/dhcpcd -c /h -f /c -b -6 -m 1024 wlan0",
	    "  one family at a time, never both, because netcfgd decides per source");

	metric.has = 0;
	message[0] = '\0';
	check(!ncfg_dhcp_dhcpcd_args("/sbin/dhcpcd", "5", "eth0", &metric, "/h", "/c", &args,
	      message, sizeof(message)) && strstr(message, "`5`") != NULL,
	    "a family dhcpcd does not have is refused by name rather than passed through");
}

static void what_stops_it_names_the_same_family(void)
{
	ncfg_dhcp_args_t args;
	char             message[NCFG_ERROR_MAX];
	char             line[256];

	message[0] = '\0';
	check(ncfg_dhcp_dhcpcd_stop_args("/sbin/dhcpcd", "4", "eth0", &args, message,
	      sizeof(message)),
	    "the stop command line is built");
	joined(&args, line, sizeof(line));
	/* **0070.** A client started with `-4` writes `<iface>-4.pid`, and a `-k`
	 * with no family looks for `<iface>.pid`, finds nothing, and says "dhcpcd
	 * is not running" -- which is also what a machine with no dhcpcd says. */
	check_text(line, "/sbin/dhcpcd -4 -k eth0",
	    "  and names the family, because dhcpcd's pid file carries it");

	message[0] = '\0';
	check(ncfg_dhcp_dhcpcd_stop_args("/sbin/dhcpcd", "6", "eth0", &args, message,
	      sizeof(message)),
	    "and the v6 stop names its own");
	joined(&args, line, sizeof(line));
	check_text(line, "/sbin/dhcpcd -6 -k eth0", "  which is a different pid file again");

	message[0] = '\0';
	check(!ncfg_dhcp_dhcpcd_stop_args("/sbin/dhcpcd", NULL, "eth0", &args, message,
	      sizeof(message)) && strstr(message, "0070") != NULL,
	    "a stop with no family is refused, naming the decision that made it required");
}

/* ------------------------------------------------------------------------ *
 * The paths, which are the marks
 * ------------------------------------------------------------------------ */

static void the_paths_are_the_marks(void)
{
	char path[NCFG_DHCP_PATH_MAX];
	char message[NCFG_ERROR_MAX];
	char want[NCFG_DHCP_PATH_MAX];

	check(ncfg_dhcp_pid_path(run_dir, "udhcpc", "eth0", path, sizeof(path), NULL, 0),
	    "the pid path is built");
	(void)snprintf(want, sizeof(want), "%s/udhcpc/eth0.pid", run_dir);
	check_text(path, want, "  <run>/<program>/<iface>.pid, which is also the -p argument");

	check(ncfg_dhcp_pid_path(run_dir, "odhcp6c", "eth0", path, sizeof(path), NULL, 0),
	    "and the v6 client's is the same shape under its own name");
	(void)snprintf(want, sizeof(want), "%s/odhcp6c/eth0.pid", run_dir);
	check_text(path, want, "  so a third client cannot invent a third convention");

	check(ncfg_dhcp_config_path(run_dir, "eth0", "4", path, sizeof(path), NULL, 0),
	    "the mark dhcpcd recites is built");
	(void)snprintf(want, sizeof(want), "%s/dhcpcd/eth0-4.conf", run_dir);
	check_text(path, want, "  <run>/dhcpcd/<iface>-<family>.conf");

	message[0] = '\0';
	check(!ncfg_dhcp_config_path(run_dir, "eth0", "9", path, sizeof(path), message,
	      sizeof(message)) && path[0] == '\0' && message[0] != '\0',
	    "a mark in a family dhcpcd does not have is refused and leaves nothing behind");

	check(ncfg_dhcp_report_path(run_dir, "eth0", path, sizeof(path), NULL, 0),
	    "the report path is built");
	(void)snprintf(want, sizeof(want), "%s/reported/eth0", run_dir);
	/* The single file rather than a fragment: both DHCPv4 clients write it,
	 * and the second writer on a dual-stack interface is the v6 one (0086).
	 * `packaging/hooks/dhcpcd-hook` composes the same two paths in shell. */
	check_text(path, want, "  the single report, which is what the shipped hook writes too");

	/* Truncation is a failure and not a shorter path: every caller is about to
	 * write to what comes back, and a path that lost its last component names
	 * a different file. */
	message[0] = '\0';
	check(!ncfg_dhcp_pid_path(run_dir, "udhcpc", "eth0", path, 8u, message, sizeof(message)) &&
	    path[0] == '\0' && message[0] != '\0',
	    "a path that would not fit is a failure rather than a shorter one");
}

/* ------------------------------------------------------------------------ *
 * The udhcpc script
 * ------------------------------------------------------------------------ */

static void the_script_touches_nothing_it_does_not_own(void)
{
	char  message[NCFG_ERROR_MAX];
	char *text = ncfg_dhcp_udhcpc_script("eth0", "/run/netcfgd/udhcpc/eth0.address",
	    "/run/netcfgd/reported/eth0", message, sizeof(message));

	check(text != NULL, "the script udhcpc runs is rendered");
	if (!text) {
		return;
	}
	/* A stock script flushes on `deconfig`, which would delete a static
	 * address netcfgd installed beside the lease. This one records what it
	 * added and removes exactly that. */
	check(strstr(text, "ip -4 addr del \"$held\" dev \"$iface\"") != NULL,
	    "it removes exactly the address it added");
	check(strstr(text, "flush") == NULL,
	    "  and never flushes the interface, which would take netcfgd's own addresses");
	check(strstr(text, "resolv.conf") != NULL && strstr(text, "> /etc/resolv.conf") == NULL &&
	    strstr(text, "resolvconf") == NULL,
	    "it writes no resolver: that file is netcfgd's DNS backend's");
	check(strstr(text, "link set") == NULL && strstr(text, " mtu ") == NULL,
	    "and touches the link itself not at all: the MTU is the document's");
	/* 0113: the reader takes every entry in the report directory as an
	 * interface name, so a staging file has to begin with a dot -- and a dot
	 * is ordinary *inside* a name, `eth0.100` being a VLAN, so a rule about
	 * the suffix would skip a real interface. */
	check(strstr(text, "'/run/netcfgd/reported/.eth0.tmp'") != NULL,
	    "the report is staged under a leading dot and renamed into place");
	check(strstr(text, "${mask:?") != NULL,
	    "a client that sets only $subnet is refused by name rather than guessed at");
	check(strstr(text, "${search:-${domain:-}}") != NULL,
	    "option 119 where the server sent one and option 15 otherwise");
	free(text);

	message[0] = '\0';
	check(ncfg_dhcp_udhcpc_script("eth0'; rm -rf /tmp; echo '", "/a", "/b", message,
	      sizeof(message)) == NULL && strstr(message, "single quote") != NULL,
	    "an interface name carrying a quote is refused, not quoted into a command");
}

/*
 * The script, run the way udhcpc runs it.
 *
 * A rendering checked by `strstr` says nothing about whether the shell agrees.
 * This writes the script, puts a stand-in `ip` first on `PATH`, and calls it
 * with the environment busybox sets -- so what is asserted is the report that
 * comes out and the commands that would have been sent to the kernel, neither
 * of which a reading of the text could have told apart from a script that
 * exits 1 before doing anything.
 */
static void the_script_does_what_it_says(const char *base)
{
	char   dir[512];
	char   bin[768];
	char   fake_ip[1024];
	char   ip_log[1024];
	char   script[1024];
	char   state[1024];
	char   report[1024];
	char   message[NCFG_ERROR_MAX];
	char   body[2048];
	char   env_path[2048];
	char   env_iface[128];
	char  *text;
	char  *seen;
	pid_t  child;
	int    status = 0;

	(void)testdir_in(base, "scriptrun", dir, sizeof(dir));
	check(mkdir(dir, 0755) == 0 || errno == EEXIST, "a directory for the script to run in");
	(void)testdir_in(dir, "bin", bin, sizeof(bin));
	check(mkdir(bin, 0755) == 0 || errno == EEXIST, "and one for the stand-in ip");
	(void)testdir_in(bin, "ip", fake_ip, sizeof(fake_ip));
	(void)testdir_in(dir, "ip.log", ip_log, sizeof(ip_log));
	(void)snprintf(body, sizeof(body), "#!/bin/sh\nprintf '%%s\\n' \"$*\" >> '%s'\nexit 0\n",
	    ip_log);
	write_fake(fake_ip, body);

	(void)testdir_in(dir, "eth9.script", script, sizeof(script));
	(void)testdir_in(dir, "eth9.address", state, sizeof(state));
	(void)testdir_in(dir, "eth9.report", report, sizeof(report));
	message[0] = '\0';
	text = ncfg_dhcp_udhcpc_script("eth9", state, report, message, sizeof(message));
	check(text != NULL && testdir_write(script, text, strlen(text)) && chmod(script, 0755) == 0,
	    "the script is written where udhcpc would run it");
	free(text);

	/* The stand-in `ip` first and the ordinary utilities behind it, which is
	 * what udhcpc's own environment looks like: the script runs `cat` and `mv`
	 * as well, and a `PATH` holding only the stand-in would have this case
	 * pass or fail for a reason that has nothing to do with the script. */
	(void)snprintf(env_path, sizeof(env_path), "PATH=%s:/usr/bin:/bin", bin);
	(void)snprintf(env_iface, sizeof(env_iface), "interface=eth9");

	child = fork();
	if (child == 0) {
		const char *argv[3];
		const char *envp[10];

		argv[0] = script;
		argv[1] = "bound";
		argv[2] = NULL;
		envp[0] = env_path;
		envp[1] = env_iface;
		envp[2] = "ip=192.0.2.10";
		envp[3] = "mask=24";
		envp[4] = "router=192.0.2.1";
		envp[5] = "dns=192.0.2.53 192.0.2.54";
		envp[6] = "search=example.com corp.example.com";
		envp[7] = NULL;
		execve(script, (char *const *)(const void *)argv,
		    (char *const *)(const void *)envp);
		_exit(127);
	}
	check(child > 0, "the script is run with the environment busybox sets");
	while (child > 0 && waitpid(child, &status, 0) < 0 && errno == EINTR) {
		continue;
	}
	check(WIFEXITED(status) && WEXITSTATUS(status) == 0, "  and it exits zero on a lease");

	seen = testdir_read(report, NULL);
	check_text(seen,
	    "# eth9, from a DHCPv4 lease. Written by netcfgd.\n"
	    "dns=192.0.2.53\n"
	    "dns=192.0.2.54\n"
	    "search=example.com\n"
	    "search=corp.example.com\n",
	    "  the report is the interface-report format, whole");
	free(seen);

	seen = testdir_read(state, NULL);
	check_text(seen, "192.0.2.10/24",
	    "  and the one address it installed is recorded beside it, as a prefix length");
	free(seen);

	seen = testdir_read(ip_log, NULL);
	check_text(seen,
	    "-4 addr replace 192.0.2.10/24 dev eth9\n"
	    "-4 route replace default via 192.0.2.1 dev eth9\n",
	    "  the address and the default route are all it asked the kernel for");
	free(seen);

	/* `deconfig` arrives on a `SIGTERM` with `-R`, and once before the first
	 * lease when there is nothing recorded -- which must be a no-op rather
	 * than a flush. */
	(void)unlink(ip_log);
	child = fork();
	if (child == 0) {
		const char *argv[3];
		const char *envp[3];

		argv[0] = script;
		argv[1] = "deconfig";
		argv[2] = NULL;
		envp[0] = env_path;
		envp[1] = env_iface;
		envp[2] = NULL;
		execve(script, (char *const *)(const void *)argv,
		    (char *const *)(const void *)envp);
		_exit(127);
	}
	while (child > 0 && waitpid(child, &status, 0) < 0 && errno == EINTR) {
		continue;
	}
	check(WIFEXITED(status) && WEXITSTATUS(status) == 0, "deconfig exits zero too");
	seen = testdir_read(ip_log, NULL);
	check_text(seen,
	    "-4 route del default dev eth9\n"
	    "-4 addr del 192.0.2.10/24 dev eth9\n",
	    "  and withdraws exactly the address it recorded, not whatever is on the link");
	free(seen);
	check(!testdir_exists(state) && !testdir_exists(report),
	    "  taking the record and the report with it");

	(void)unlink(ip_log);
	child = fork();
	if (child == 0) {
		const char *argv[3];
		const char *envp[3];

		argv[0] = script;
		argv[1] = "deconfig";
		argv[2] = NULL;
		envp[0] = env_path;
		envp[1] = env_iface;
		envp[2] = NULL;
		execve(script, (char *const *)(const void *)argv,
		    (char *const *)(const void *)envp);
		_exit(127);
	}
	while (child > 0 && waitpid(child, &status, 0) < 0 && errno == EINTR) {
		continue;
	}
	check(WIFEXITED(status) && WEXITSTATUS(status) == 0 && !testdir_exists(ip_log),
	    "a deconfig with nothing recorded touches the interface at all");
}

/* ------------------------------------------------------------------------ *
 * Whose client is this
 * ------------------------------------------------------------------------ */

static void a_running_dhcpcd_is_asked_whose_it_is(void)
{
	ncfg_dhcp_machine_t machine;
	char                mark[NCFG_DHCP_PATH_MAX];
	char                socket_path[512];
	char                recited[NCFG_DHCP_PATH_MAX];
	pid_t               server;

	memset(&machine, 0, sizeof(machine));
	machine.dhcpcd_run_dir = dhcpcd_dir;
	check(ncfg_dhcp_config_path(run_dir, "eth5", "4", mark, sizeof(mark), NULL, 0),
	    "the mark netcfgd would have started a client with");

	/* Nothing there at all is "netcfgd could not tell", which is the ordinary
	 * state of every machine whose client is udhcpc. */
	recited[0] = 'x';
	check(ncfg_dhcpcd_whose(run_dir, "eth5", "4", &machine, recited, sizeof(recited)) ==
	    NCFG_DHCPCD_SILENT && recited[0] == '\0',
	    "no socket is `could not tell` and recites nothing");

	server = a_dhcpcd_reciting("eth5", "4", mark, socket_path, sizeof(socket_path));
	check(server > 0, "a dhcpcd reciting netcfgd's own -f");
	check(ncfg_dhcpcd_whose(run_dir, "eth5", "4", &machine, recited, sizeof(recited)) ==
	    NCFG_DHCPCD_OURS && strcmp(recited, mark) == 0,
	    "  is netcfgd's, which is the whole of how netcfgd knows its own dhcpcd");
	reap(server, socket_path);

	server = a_dhcpcd_reciting("eth5", "4", "/etc/dhcpcd.conf", socket_path,
	    sizeof(socket_path));
	check(server > 0, "a dhcpcd reciting the operator's own file");
	check(ncfg_dhcpcd_whose(run_dir, "eth5", "4", &machine, recited, sizeof(recited)) ==
	    NCFG_DHCPCD_THEIRS && strcmp(recited, "/etc/dhcpcd.conf") == 0,
	    "  is somebody else's, which is a different answer from `could not tell`");
	reap(server, socket_path);

	/* A machine with no answer for where dhcpcd keeps its sockets cannot ask,
	 * and saying so is not the same as saying nothing is running. */
	machine.dhcpcd_run_dir = NULL;
	check(ncfg_dhcpcd_whose(run_dir, "eth5", "4", &machine, NULL, 0) == NCFG_DHCPCD_SILENT,
	    "and an executor told nowhere to ask answers `could not tell` too");
}

/* ------------------------------------------------------------------------ *
 * Marking and adoption
 * ------------------------------------------------------------------------ */

static void a_client_is_recognised_by_the_path_it_carries(void)
{
	char  pid_path[NCFG_DHCP_PATH_MAX];
	char  dir[NCFG_DHCP_PATH_MAX];
	char  mine[32];
	pid_t child;
	pid_t adopted = 0;
	char  message[NCFG_ERROR_MAX];
	char *seen;

	check(ncfg_dhcp_pid_path(run_dir, "udhcpc", "eth6", pid_path, sizeof(pid_path), NULL, 0) &&
	    ncfg_dhcp_client_dir(run_dir, "udhcpc", dir, sizeof(dir), NULL, 0),
	    "the mark and the directory it lives in");
	check(mkdir(dir, 0755) == 0 || errno == EEXIST, "  which netcfgd makes");

	/* **A pid file outlives the process it names and pids are recycled**, so
	 * the pid is only half an answer. This process is alive and its command
	 * line does not carry the mark. */
	(void)snprintf(mine, sizeof(mine), "%d\n", (int)getpid());
	check(testdir_write(pid_path, mine, strlen(mine)), "a pid file naming this very process");
	check(ncfg_dhcp_running_pid(run_dir, "udhcpc", "eth6") == 0,
	    "  is not a client, because its command line does not carry the mark");

	child = spawn_marked(pid_path);
	check(child > 0, "a process carrying netcfgd's -p path as a whole argument");
	(void)snprintf(mine, sizeof(mine), "%d\n", (int)child);
	check(testdir_write(pid_path, mine, strlen(mine)), "  recorded in the pid file");
	check(ncfg_dhcp_running_pid(run_dir, "udhcpc", "eth6") == child,
	    "  is netcfgd's client, by the mark and by the privilege it runs with");

	/* 0140's case: `RuntimeDirectory=netcfgd` takes the pid file and
	 * `KillMode=process` leaves the client. The mark is in the client's own
	 * argv, so the record is rebuilt from it. */
	check(unlink(pid_path) == 0, "the run directory is deleted underneath it");
	check(ncfg_dhcp_running_pid(run_dir, "udhcpc", "eth6") == 0,
	    "  so netcfgd no longer recognises its own client");
	message[0] = '\0';
	check(ncfg_dhcp_adopt(run_dir, "udhcpc", "eth6", &adopted, message, sizeof(message)) &&
	    adopted == child,
	    "  and adoption finds it again by the mark it still carries");
	seen = testdir_read(pid_path, NULL);
	check(seen != NULL && atoi(seen) == (int)child,
	    "  writing the pid back down, which is all `adopted` means");
	free(seen);
	check(ncfg_dhcp_running_pid(run_dir, "udhcpc", "eth6") == child,
	    "  so the record and the process agree again");

	/* Adopting one that is already recorded is not an adoption, and is not a
	 * failure: the caller's own "is one running" has already answered it. */
	adopted = -1;
	message[0] = '\0';
	check(ncfg_dhcp_adopt(run_dir, "udhcpc", "eth6", &adopted, message, sizeof(message)) &&
	    adopted == 0,
	    "a client already recorded is not adopted again");

	stop_marked(child);
	check(ncfg_dhcp_running_pid(run_dir, "udhcpc", "eth6") == 0,
	    "and a client that has gone is not running, whatever the pid file says");

	adopted = -1;
	message[0] = '\0';
	check(ncfg_dhcp_adopt(run_dir, "udhcpc", "eth7", &adopted, message, sizeof(message)) &&
	    adopted == 0 && message[0] == '\0',
	    "nothing to adopt is the ordinary answer and not a failure");
	(void)unlink(pid_path);
}

/* ------------------------------------------------------------------------ *
 * The metric netcfgd started a client with
 * ------------------------------------------------------------------------ */

static void the_writer_and_the_reader_agree_on_where_the_record_lives(void)
{
	ncfg_optint_t metric;
	ncfg_optint_t read_back;
	char          message[NCFG_ERROR_MAX];
	char          path[NCFG_DHCP_PATH_MAX];

	/*
	 * **A disagreement between the two would be invisible**: every client
	 * would read "cannot tell", the planner would fall back to the route
	 * comparison, and nothing would look wrong. The first version of 0241 read
	 * the metric out of `/proc/<pid>/cmdline`, where dhcpcd has rewritten its
	 * argv, and so read nothing on every machine.
	 */
	metric.has = 1;
	metric.value = 100;
	message[0] = '\0';
	check(ncfg_dhcp_record_metric(run_dir, "eth8", &metric, message, sizeof(message)),
	    "the metric a client was started with is written down");
	read_back = ncfg_dhcp_started_metric(run_dir, "eth8");
	check(read_back.has && read_back.value == 100,
	    "  and read back through the same path the writer used");
	check(ncfg_dhcp_metric_path(run_dir, "eth8", path, sizeof(path), NULL, 0) &&
	    testdir_exists(path),
	    "  which is the one both of them build");

	metric.value = 0;
	message[0] = '\0';
	check(ncfg_dhcp_record_metric(run_dir, "eth8", &metric, message, sizeof(message)),
	    "a metric of zero is recorded");
	read_back = ncfg_dhcp_started_metric(run_dir, "eth8");
	check(read_back.has && read_back.value == 0,
	    "  and reads back as a value rather than as `cannot tell`");

	/* **Removed rather than left**, which is not tidiness: a record from the
	 * previous network would say the running client carries a metric it was
	 * never given, and that is a restart on every pass until the limit gives
	 * up. */
	message[0] = '\0';
	check(ncfg_dhcp_record_metric(run_dir, "eth8", NULL, message, sizeof(message)),
	    "an absent metric clears the record");
	check(!testdir_exists(path), "  removing it rather than writing something in it");
	read_back = ncfg_dhcp_started_metric(run_dir, "eth8");
	check(!read_back.has, "  so the planner reads `cannot tell` and compares the route");

	check(testdir_write(path, "not a number\n", 13u), "a record nothing netcfgd wrote");
	read_back = ncfg_dhcp_started_metric(run_dir, "eth8");
	check(!read_back.has, "  is `cannot tell` rather than a confident wrong answer");

	/* **And one that begins with a number and goes on**, which is the case a
	 * `strtoll` that stops where it likes reads as the number and throws the
	 * rest away. Trailing space is what a shell's `echo` leaves and is
	 * forgiven; anything else is not a record netcfgd wrote. */
	check(testdir_write(path, "100 apples\n", 11u), "a record that begins with a number");
	read_back = ncfg_dhcp_started_metric(run_dir, "eth8");
	check(!read_back.has, "  is `cannot tell` too, rather than the part that parsed");
	check(testdir_write(path, "100 \n", 5u), "and one with nothing after it but space");
	read_back = ncfg_dhcp_started_metric(run_dir, "eth8");
	check(read_back.has && read_back.value == 100,
	    "  is the number, since that is what an `echo` into the file leaves");
	(void)unlink(path);
}

/* ------------------------------------------------------------------------ *
 * Starting
 * ------------------------------------------------------------------------ */

/* A machine with all three programs pointed somewhere this test wrote. */
static void a_machine(ncfg_dhcp_machine_t *machine, const char *dhcpcd, const char *udhcpc,
    const char *busybox)
{
	memset(machine, 0, sizeof(*machine));
	machine->dhcpcd_program = dhcpcd;
	machine->udhcpc_program = udhcpc;
	machine->busybox_program = busybox;
	machine->hook = hook_path;
	machine->dhcpcd_run_dir = dhcpcd_dir;
	machine->dhcpcd_config = "/etc/dhcpcd.conf";
	/* Short, because two cases here deliberately drive a client that will not
	 * stop and the thing waiting behind a real one is the reconcile loop. */
	machine->patience_ms = 200;
}

/*
 * A whole argument in the recorder's output, rather than a substring of it.
 *
 * `strstr(said, "-P")` reads a file of newline-separated argv as one string,
 * and several of those arguments are **paths**: the run directory, the hook.
 * This binary's scratch directory is `netcfgd-c-dhcp-XXXXXX`, so a `mkdtemp`
 * that picks `P` for the first of its six characters puts a literal `-P` into
 * every path the client is given, and "no delegation is solicited" fails for a
 * directory name. One run in sixty-two -- which is the rate at which a failure
 * is read as somebody else's flake rather than as a defect in the check.
 *
 * The positive assertion had the same fault pointing the other way, and it is
 * the worse half: it would have passed on the directory name alone with the
 * `-P` deleted from the argv builder entirely.
 */
static int argv_has(const char *recorded, const char *argument)
{
	size_t length = strlen(argument);
	const char *at = recorded;

	while (at && *at) {
		const char *end = strchr(at, '\n');
		size_t      span = end ? (size_t)(end - at) : strlen(at);

		if (span == length && memcmp(at, argument, length) == 0) {
			return 1;
		}
		at = end ? end + 1 : NULL;
	}
	return 0;
}

/*
 * A DHCPv6 start: which client, what it is given, and the file it leaves.
 *
 * **The recorder is the whole instrument.** `write_recorder` puts a shell
 * script where the client should be, which prints its own argv into a file and
 * exits 0 -- so the start runs to completion without a real odhcp6c, and what
 * it was given is on disk to be read back. That is how the v4 half is driven
 * and it is what makes the v6 half's `-P` assertable end to end rather than
 * only at the argv builder.
 */
static void a_dhcp6_start_carries_the_document_s_request(const char *base)
{
	ncfg_dhcp_machine_t machine;
	char                fake[256];
	char                record[256];
	char                where[256];
	char                hook[512];
	char                message[NCFG_ERROR_MAX];
	char               *said;

	(void)testdir_in(base, "v6run", where, sizeof(where));
	testdir_mkdirp(where);
	(void)testdir_in(base, "fake-odhcp6c", fake, sizeof(fake));
	(void)testdir_in(base, "v6-argv", record, sizeof(record));
	write_recorder(fake, record, 0);
	a_machine(&machine, "/nonexistent/dhcpcd", "/nonexistent/udhcpc",
	    "/nonexistent/busybox");
	machine.odhcp6c_program = fake;

	message[0] = '\0';
	check(ncfg_dhcp6_start(where, "eth6", NULL, &machine, message, sizeof(message)),
	    "a dhcp6 start with no prefix asked for runs the client");
	said = testdir_read(record, NULL);
	check(said && !argv_has(said, "-P"),
	    "  and gives it no -P, so no delegation is solicited");
	check(said && strstr(said, "eth6") != NULL,
	    "  with the interface it was started for");
	free(said);

	/* The hook, which is the writer end of a file whose reader has existed
	 * since the host module landed. */
	(void)snprintf(hook, sizeof(hook), "%s/hooks/pd-eth6", where);
	check(testdir_exists(hook), "  and leaves the prefix hook where it told odhcp6c to look");
	said = testdir_read(hook, NULL);
	check(said && strstr(said, "${PREFIXES:-}") != NULL,
	    "  which reads odhcp6c's PREFIXES");
	free(said);

	message[0] = '\0';
	check(ncfg_dhcp6_start(where, "eth7", "2001:db8::/56", &machine, message,
	      sizeof(message)),
	    "and one that asked for a prefix runs it too");
	said = testdir_read(record, NULL);
	check(said && argv_has(said, "-P") && argv_has(said, "2001:db8::/56"),
	    "  with the request the document asked for, and only then");
	free(said);
}

/*
 * A machine that cannot serve the document, which is a refusal rather than a
 * fallback.
 *
 * The only place the two answers differ, and the reason `ncfg_dhcp6_client` is
 * pure: with no odhcp6c a plain dhcp6 interface is dhcpcd's and one that asked
 * for a prefix is nobody's (0050).
 */
static void a_dhcp6_start_without_odhcp6c(const char *base)
{
	ncfg_dhcp_machine_t machine;
	char                where[256];
	char                message[NCFG_ERROR_MAX];

	(void)testdir_in(base, "v6bare", where, sizeof(where));
	testdir_mkdirp(where);
	a_machine(&machine, "/nonexistent/dhcpcd", "/nonexistent/udhcpc",
	    "/nonexistent/busybox");
	machine.odhcp6c_program = "/nonexistent/odhcp6c";

	message[0] = '\0';
	check(!ncfg_dhcp6_start(where, "eth6", "2001:db8::/56", &machine, message,
	      sizeof(message)) &&
	    strstr(message, "0050") != NULL && strstr(message, "Install odhcp6c") != NULL,
	    "a delegation with no odhcp6c is refused, naming the decision and the repair");
	check(!testdir_exists("/nonexistent"),
	    "  and nothing was written for a client that was never going to run");

	message[0] = '\0';
	check(!ncfg_dhcp6_start(where, "eth6", NULL, &machine, message, sizeof(message)) &&
	    strstr(message, "install odhcp6c or dhcpcd") != NULL,
	    "and with neither client installed the refusal names both");

	message[0] = '\0';
	check(!ncfg_dhcp6_start(where, "eth6", NULL, NULL, message, sizeof(message)) &&
	    message[0] != '\0',
	    "a v6 start with no machine refuses rather than reaching for this machine's own");
}

static void a_start_prefers_dhcpcd_and_writes_both_marks(const char *base)
{
	ncfg_dhcp_machine_t machine;
	ncfg_optint_t       metric;
	char                fake[256];
	char                record[256];
	char                message[NCFG_ERROR_MAX];
	char                want[2048];
	char                path[NCFG_DHCP_PATH_MAX];
	char                target[NCFG_DHCP_PATH_MAX];
	char               *seen;
	ssize_t             length;

	(void)testdir_in(base, "fake-dhcpcd", fake, sizeof(fake));
	(void)testdir_in(base, "dhcpcd.args", record, sizeof(record));
	write_recorder(fake, record, 0);
	a_machine(&machine, fake, "/nonexistent/udhcpc", "/nonexistent/busybox");

	metric.has = 1;
	metric.value = 300;
	message[0] = '\0';
	check(ncfg_dhcp_start(run_dir, "eth0", &metric, &machine, message, sizeof(message)),
	    "a start with a dhcpcd installed runs it");
	if (message[0] != '\0') {
		printf("  said: %s\n", message);
	}

	seen = testdir_read(record, NULL);
	check(ncfg_dhcp_config_path(run_dir, "eth0", "4", path, sizeof(path), NULL, 0),
	    "the mark it was pointed at");
	(void)snprintf(want, sizeof(want), "-c\n%s\n-f\n%s\n-b\n-4\n-m\n300\neth0\n", hook_path,
	    path);
	check_text(seen, want, "  with the hook, the mark, the family, the metric and no more");
	free(seen);

	/* **A symlink, not a file of netcfgd's own.** `-f` replaces
	 * `/etc/dhcpcd.conf` outright and dhcpcd has no `include`, so a file here
	 * would silently drop the operator's `duid` and `persistent`. */
	length = readlink(path, target, sizeof(target) - 1u);
	check(length > 0, "the mark is a symlink");
	if (length > 0) {
		target[length] = '\0';
		check_text(target, "/etc/dhcpcd.conf",
		    "  pointing at the operator's own configuration rather than replacing it");
	}

	/* The udhcpc script is written whichever client ran, because which client
	 * this machine has is not netcfgd's to assume and the next apply may find
	 * a different one. */
	check(ncfg_dhcp_script_path(run_dir, "eth0", path, sizeof(path), NULL, 0) &&
	    testdir_exists(path) && (testdir_mode(path) & 0100) != 0,
	    "the script the other client would need is written and executable");

	metric = ncfg_dhcp_started_metric(run_dir, "eth0");
	check(metric.has && metric.value == 300,
	    "and the metric the client was given is written down beside it");
}

static void a_machine_with_only_busybox_still_gets_a_lease(const char *base)
{
	ncfg_dhcp_machine_t machine;
	ncfg_optint_t       metric;
	char                fake[256];
	char                record[256];
	char                message[NCFG_ERROR_MAX];
	char                want[2048];
	char                script[NCFG_DHCP_PATH_MAX];
	char                pid_path[NCFG_DHCP_PATH_MAX];
	char               *seen;

	(void)testdir_in(base, "fake-busybox", fake, sizeof(fake));
	(void)testdir_in(base, "busybox.args", record, sizeof(record));
	write_recorder(fake, record, 0);
	a_machine(&machine, "/nonexistent/dhcpcd", "/nonexistent/udhcpc", fake);
	/*
	 * **And no hook, which is the divergence.** The hook is dhcpcd's and
	 * udhcpc never runs it, so a machine whose only client is busybox must not
	 * be refused its lease over a file that would not have been used. The Rust
	 * asks for the hook before it chooses a client, so this start fails there
	 * with a message naming `/usr/libexec/netcfgd/dhcpcd-hook`.
	 */
	machine.hook = "/nonexistent/hook";

	metric.has = 1;
	metric.value = 400;
	message[0] = '\0';
	check(ncfg_dhcp_start(run_dir, "eth1", &metric, &machine, message, sizeof(message)),
	    "a machine with only busybox and no dhcpcd hook still starts a client");
	if (message[0] != '\0') {
		printf("  said: %s\n", message);
	}
	seen = testdir_read(record, NULL);
	check(ncfg_dhcp_script_path(run_dir, "eth1", script, sizeof(script), NULL, 0) &&
	    ncfg_dhcp_pid_path(run_dir, "udhcpc", "eth1", pid_path, sizeof(pid_path), NULL, 0),
	    "the script and the pid file it is told about");
	(void)snprintf(want, sizeof(want), "udhcpc\n-b\n-i\neth1\n-s\n%s\n-p\n%s\n-R\n-O\nsearch\n",
	    script, pid_path);
	check_text(seen, want, "  the applet first, and -R and -O search behind it");
	free(seen);

	/*
	 * **And no metric record, which is the second divergence.** busybox udhcpc
	 * has no metric option -- its script does the routing -- so a record
	 * saying 400 would have the planner believe a metric had been applied that
	 * the client never heard, and that record is read *instead of* the route
	 * comparison that would have caught it. The Rust writes it for whichever
	 * of the three ran.
	 */
	metric = ncfg_dhcp_started_metric(run_dir, "eth1");
	check(!metric.has,
	    "and nothing is recorded about a metric, because udhcpc was never given one");
}

static void a_stale_metric_record_goes_with_the_client_that_had_one(const char *base)
{
	ncfg_dhcp_machine_t machine;
	ncfg_optint_t       metric;
	char                fake[256];
	char                record[256];
	char                message[NCFG_ERROR_MAX];

	(void)testdir_in(base, "fake-udhcpc", fake, sizeof(fake));
	(void)testdir_in(base, "udhcpc.args", record, sizeof(record));
	write_recorder(fake, record, 0);

	metric.has = 1;
	metric.value = 100;
	message[0] = '\0';
	check(ncfg_dhcp_record_metric(run_dir, "eth2", &metric, message, sizeof(message)),
	    "a record left by a dhcpcd that used to serve this interface");

	a_machine(&machine, "/nonexistent/dhcpcd", fake, "/nonexistent/busybox");
	message[0] = '\0';
	check(ncfg_dhcp_start(run_dir, "eth2", &metric, &machine, message, sizeof(message)),
	    "the machine now has udhcpc instead, and a start uses it");
	metric = ncfg_dhcp_started_metric(run_dir, "eth2");
	check(!metric.has,
	    "  and the old record is cleared rather than left claiming a metric is in force");
}

static void a_dhcpcd_with_no_hook_is_refused_naming_the_file(const char *base)
{
	ncfg_dhcp_machine_t machine;
	char                fake[256];
	char                record[256];
	char                message[NCFG_ERROR_MAX];

	(void)testdir_in(base, "fake-dhcpcd", fake, sizeof(fake));
	(void)testdir_in(base, "hookless.args", record, sizeof(record));
	write_recorder(fake, record, 0);
	a_machine(&machine, fake, "/nonexistent/udhcpc", "/nonexistent/busybox");
	machine.hook = "/nonexistent/dhcpcd-hook";

	message[0] = '\0';
	check(!ncfg_dhcp_start(run_dir, "eth3", NULL, &machine, message, sizeof(message)) &&
	    strstr(message, "/nonexistent/dhcpcd-hook") != NULL,
	    "a dhcpcd whose hook is not installed is refused, naming the file");
	/* 0178: without the hook a lease's nameservers never reach netcfgd and the
	 * resolver is written empty -- 1,350 `script_runreason: Permission denied`
	 * messages in a journal while netcfgd reported success. */
	check(strstr(message, "resolver") != NULL,
	    "  and says what it would have cost, which is a resolver that resolves nothing");
	check(!testdir_exists(record), "  having run nothing on the way to refusing");
}

static void a_client_that_refuses_its_configuration_is_quoted(const char *base)
{
	ncfg_dhcp_machine_t machine;
	char                fake[256];
	char                message[NCFG_ERROR_MAX];
	char                body[512];

	(void)testdir_in(base, "fake-angry", fake, sizeof(fake));
	(void)snprintf(body, sizeof(body),
	    "#!/bin/sh\n"
	    "echo 'dhcpcd-10.1.0 starting'\n"
	    "echo 'dhcpcd: eth4: unknown option -- q'\n"
	    "echo 'dhcpcd: exited'\n"
	    "exit 1\n");
	write_fake(fake, body);
	a_machine(&machine, fake, "/nonexistent/udhcpc", "/nonexistent/busybox");

	message[0] = '\0';
	check(!ncfg_dhcp_start(run_dir, "eth4", NULL, &machine, message, sizeof(message)),
	    "a client that refuses its configuration fails the start");
	check(strstr(message, "unknown option") != NULL,
	    "  quoting the line that said why, rather than the tail");
	check(strstr(message, ".log") != NULL, "  and saying where the rest of the output is");
}

static void a_machine_with_no_client_says_so(void)
{
	ncfg_dhcp_machine_t machine;
	char                message[NCFG_ERROR_MAX];

	a_machine(&machine, "/nonexistent/dhcpcd", "/nonexistent/udhcpc", "/nonexistent/busybox");
	message[0] = '\0';
	check(!ncfg_dhcp_start(run_dir, "ethA", NULL, &machine, message, sizeof(message)) &&
	    strstr(message, "no DHCPv4 client found") != NULL &&
	    strstr(message, "busybox") != NULL,
	    "a machine with none of the three is told which packages would serve it");
}

static void a_client_already_running_is_not_started_again(const char *base)
{
	ncfg_dhcp_machine_t machine;
	char                fake[256];
	char                record[256];
	char                pid_path[NCFG_DHCP_PATH_MAX];
	char                dir[NCFG_DHCP_PATH_MAX];
	char                mine[32];
	char                message[NCFG_ERROR_MAX];
	pid_t               child;

	(void)testdir_in(base, "fake-never", fake, sizeof(fake));
	(void)testdir_in(base, "never.args", record, sizeof(record));
	write_recorder(fake, record, 0);
	a_machine(&machine, fake, fake, fake);

	check(ncfg_dhcp_pid_path(run_dir, "udhcpc", "ethB", pid_path, sizeof(pid_path), NULL, 0) &&
	    ncfg_dhcp_client_dir(run_dir, "udhcpc", dir, sizeof(dir), NULL, 0) &&
	    (mkdir(dir, 0755) == 0 || errno == EEXIST),
	    "a run directory with a client recorded in it");
	child = spawn_marked(pid_path);
	(void)snprintf(mine, sizeof(mine), "%d\n", (int)child);
	check(child > 0 && testdir_write(pid_path, mine, strlen(mine)),
	    "  and the client itself, carrying the mark");

	message[0] = '\0';
	check(ncfg_dhcp_start(run_dir, "ethB", NULL, &machine, message, sizeof(message)),
	    "a start against a client already running is success");
	check(!testdir_exists(record),
	    "  and starts nothing: two clients take the same lease and the second wins the file");
	stop_marked(child);
	(void)unlink(pid_path);
}

static void a_client_of_netcfgds_own_is_adopted_rather_than_doubled(const char *base)
{
	ncfg_dhcp_machine_t machine;
	char                fake[256];
	char                record[256];
	char                pid_path[NCFG_DHCP_PATH_MAX];
	char                message[NCFG_ERROR_MAX];
	char               *seen;
	pid_t               child;

	(void)testdir_in(base, "fake-double", fake, sizeof(fake));
	(void)testdir_in(base, "double.args", record, sizeof(record));
	write_recorder(fake, record, 0);
	a_machine(&machine, "/nonexistent/dhcpcd", fake, "/nonexistent/busybox");

	check(ncfg_dhcp_pid_path(run_dir, "udhcpc", "ethC", pid_path, sizeof(pid_path), NULL, 0),
	    "the mark a udhcpc on this interface would carry");
	child = spawn_marked(pid_path);
	check(child > 0 && !testdir_exists(pid_path),
	    "a client running with no pid file, which is what a netcfgd restart leaves");

	message[0] = '\0';
	check(ncfg_dhcp_start(run_dir, "ethC", NULL, &machine, message, sizeof(message)),
	    "a start adopts it");
	check(!testdir_exists(record),
	    "  rather than starting a second, which would take the same lease and win the file");
	seen = testdir_read(pid_path, NULL);
	check(seen != NULL && atoi(seen) == (int)child,
	    "  and the pid file is written back from the mark the client still carries");
	free(seen);
	stop_marked(child);
	(void)unlink(pid_path);
}

static void a_dhcpcd_of_netcfgds_own_is_adopted_through_its_socket(const char *base)
{
	ncfg_dhcp_machine_t machine;
	char                fake[256];
	char                record[256];
	char                mark[NCFG_DHCP_PATH_MAX];
	char                socket_path[512];
	char                message[NCFG_ERROR_MAX];
	pid_t               server;

	(void)testdir_in(base, "fake-adopt", fake, sizeof(fake));
	(void)testdir_in(base, "adopt.args", record, sizeof(record));
	write_recorder(fake, record, 0);
	a_machine(&machine, fake, "/nonexistent/udhcpc", "/nonexistent/busybox");

	check(ncfg_dhcp_config_path(run_dir, "ethD", "4", mark, sizeof(mark), NULL, 0),
	    "the -f netcfgd would start a dhcpcd with");
	server = a_dhcpcd_reciting("ethD", "4", mark, socket_path, sizeof(socket_path));
	check(server > 0, "and a dhcpcd already reciting it");

	message[0] = '\0';
	check(ncfg_dhcp_start(run_dir, "ethD", NULL, &machine, message, sizeof(message)),
	    "a start adopts it through its control socket");
	/* **A second `dhcpcd -b` against a running one is a SILENT no-op** -- it
	 * prints "sending commands to dhcpcd process" and exits 0 having started
	 * nothing -- so without this netcfgd would report success on every
	 * reconcile while the orphan kept the lease and netcfgd kept no handle. */
	check(!testdir_exists(record), "  and runs nothing, which is what adoption means");
	reap(server, socket_path);
}

static void a_strangers_dhcpcd_is_refused_rather_than_spawned_beside(const char *base)
{
	ncfg_dhcp_machine_t machine;
	char                fake[256];
	char                record[256];
	char                socket_path[512];
	char                message[NCFG_ERROR_MAX];
	pid_t               server;

	(void)testdir_in(base, "fake-beside", fake, sizeof(fake));
	(void)testdir_in(base, "beside.args", record, sizeof(record));
	write_recorder(fake, record, 0);
	a_machine(&machine, fake, "/nonexistent/udhcpc", "/nonexistent/busybox");

	server = a_dhcpcd_reciting("ethE", "4", "/etc/dhcpcd.conf", socket_path,
	    sizeof(socket_path));
	check(server > 0, "a dhcpcd on this interface that is not netcfgd's");

	message[0] = '\0';
	/*
	 * **The divergence.** The Rust's comment says "neither is a reason to
	 * spawn beside it" and the code then spawns: dhcpcd's instance lock
	 * refuses the second, it exits 0 having started nothing, and netcfgd
	 * records a start it did not make on a client it can never stop.
	 */
	check(!ncfg_dhcp_start(run_dir, "ethE", NULL, &machine, message, sizeof(message)),
	    "a start beside a stranger's dhcpcd is refused rather than attempted");
	check(strstr(message, "/etc/dhcpcd.conf") != NULL,
	    "  naming what the client it found recites");
	check(strstr(message, "silent no-op") != NULL,
	    "  and why attempting it would have looked like success");
	check(!testdir_exists(record), "  having run nothing");
	reap(server, socket_path);
}

/* ------------------------------------------------------------------------ *
 * Stopping
 * ------------------------------------------------------------------------ */

static void stopping_nothing_is_the_state_that_was_asked_for(const char *base)
{
	ncfg_dhcp_machine_t machine;
	char                fake[256];
	char                record[256];
	char                message[NCFG_ERROR_MAX];

	(void)testdir_in(base, "fake-stop", fake, sizeof(fake));
	(void)testdir_in(base, "stop.args", record, sizeof(record));
	write_recorder(fake, record, 0);
	a_machine(&machine, fake, "/nonexistent/udhcpc", "/nonexistent/busybox");

	message[0] = '\0';
	check(ncfg_dhcp_stop(run_dir, "ethF", "4", &machine, message, sizeof(message)),
	    "stopping an interface with no client is the state that was asked for");
	/* The `-k` still goes out: on a machine where dhcpcd's socket mode has
	 * been tightened netcfgd cannot read the mark, and silence is not proof
	 * there is nothing there. What it must not do is read the exit status. */
	check(testdir_exists(record), "  and the -k is still sent, because silence is not proof");

	message[0] = '\0';
	check(!ncfg_dhcp_stop(run_dir, "ethF", NULL, &machine, message, sizeof(message)) &&
	    strstr(message, "0070") != NULL,
	    "a stop with no family is refused, naming what it would have cost");
}

static void a_stop_signals_only_what_it_can_prove_is_netcfgds(const char *base)
{
	ncfg_dhcp_machine_t machine;
	char                fake[256];
	char                record[256];
	char                pid_path[NCFG_DHCP_PATH_MAX];
	char                mine[32];
	char                message[NCFG_ERROR_MAX];
	pid_t               child;

	(void)testdir_in(base, "fake-stop2", fake, sizeof(fake));
	(void)testdir_in(base, "stop2.args", record, sizeof(record));
	write_recorder(fake, record, 0);
	a_machine(&machine, fake, "/nonexistent/udhcpc", "/nonexistent/busybox");

	check(ncfg_dhcp_pid_path(run_dir, "udhcpc", "ethG", pid_path, sizeof(pid_path), NULL, 0),
	    "the pid file a udhcpc on this interface would have");

	/* **A pid file naming a process that is not netcfgd's client must not be
	 * signalled.** This process is alive and carries no mark. */
	(void)snprintf(mine, sizeof(mine), "%d\n", (int)getpid());
	check(testdir_write(pid_path, mine, strlen(mine)), "a pid file naming this very test");
	message[0] = '\0';
	check(ncfg_dhcp_stop(run_dir, "ethG", "4", &machine, message, sizeof(message)),
	    "a stop against it reports the state that was asked for");
	check(getpid() > 0, "  and this process is still here to say so");
	check(!testdir_exists(pid_path), "  with the stale record removed rather than believed");

	child = spawn_marked(pid_path);
	(void)snprintf(mine, sizeof(mine), "%d\n", (int)child);
	check(child > 0 && testdir_write(pid_path, mine, strlen(mine)),
	    "a client of netcfgd's own, recorded");
	message[0] = '\0';
	check(ncfg_dhcp_stop(run_dir, "ethG", "4", &machine, message, sizeof(message)),
	    "a stop signals it");
	check(gone_within(child, 2000), "  and the client is gone");
	check(!testdir_exists(pid_path), "  with its record removed, so nothing asks about a "
	    "recycled pid");
	stop_marked(child);
}

/*
 * The marker is the path netcfgd composed, never the interface name.
 *
 * **The interface name is the weakest marker netcfgd has and this is what it
 * would cost.** `eth0` is a short string an unrelated command line carries all
 * the time -- `wpa_supplicant -i eth0`, `dhclient eth0` -- so a stale pid file
 * whose number has been recycled onto one of those would have netcfgd signal
 * another manager's daemon, which is 0014's rule broken by the one function
 * that sends a signal. The pid file's own path is in the client's `argv`
 * because netcfgd put it there with `-p`, and it is what this checks.
 *
 * The Rust's `stop_recorded_client` uses the interface name here, while the
 * start path in the same file uses the pid-file path: two markers for one
 * process, and the weaker one is where the signal goes.
 */
static void the_interface_name_is_not_a_marker(const char *base)
{
	ncfg_dhcp_machine_t machine;
	char                fake[256];
	char                record[256];
	char                pid_path[NCFG_DHCP_PATH_MAX];
	char                mine[32];
	char                message[NCFG_ERROR_MAX];
	pid_t               stranger;

	(void)testdir_in(base, "fake-stop5", fake, sizeof(fake));
	(void)testdir_in(base, "stop5.args", record, sizeof(record));
	write_recorder(fake, record, 0);
	a_machine(&machine, fake, "/nonexistent/udhcpc", "/nonexistent/busybox");

	check(ncfg_dhcp_pid_path(run_dir, "udhcpc", "ethJ", pid_path, sizeof(pid_path), NULL, 0),
	    "the pid file a udhcpc on ethJ would have");
	/* Somebody else's process, carrying the interface name as a whole argument
	 * the way every manager's command line does -- and not netcfgd's path. */
	stranger = spawn_marked("ethJ");
	(void)snprintf(mine, sizeof(mine), "%d\n", (int)stranger);
	check(stranger > 0 && testdir_write(pid_path, mine, strlen(mine)),
	    "and a recycled pid in it, naming a process that carries `ethJ` and nothing else");

	message[0] = '\0';
	check(ncfg_dhcp_stop(run_dir, "ethJ", "4", &machine, message, sizeof(message)),
	    "a stop reports the state it was asked for");
	check(!gone_within(stranger, 300),
	    "  and signals nothing, because `ethJ` is not a mark netcfgd put anywhere");
	stop_marked(stranger);
}

static void a_stop_asks_whose_the_client_is_before_it_signals(const char *base)
{
	ncfg_dhcp_machine_t machine;
	char                fake[256];
	char                record[256];
	char                socket_path[512];
	char                message[NCFG_ERROR_MAX];
	pid_t               server;

	(void)testdir_in(base, "fake-stop3", fake, sizeof(fake));
	(void)testdir_in(base, "stop3.args", record, sizeof(record));
	write_recorder(fake, record, 0);
	a_machine(&machine, fake, "/nonexistent/udhcpc", "/nonexistent/busybox");

	server = a_dhcpcd_reciting("ethH", "4", "/etc/dhcpcd.conf", socket_path,
	    sizeof(socket_path));
	check(server > 0, "a dhcpcd on this interface that is not netcfgd's");

	message[0] = '\0';
	/*
	 * **The divergence, and 0014's rule where the Rust does not apply it.**
	 * `dhcpcd -k <iface>` finds a client by convention, so sending it first
	 * and asking afterwards signals a stranger's client -- and then reports
	 * that the stop "neither reached nor disturbed" it, which is its own
	 * comment's claim.
	 */
	check(ncfg_dhcp_stop(run_dir, "ethH", "4", &machine, message, sizeof(message)),
	    "a stop where the running client is somebody else's succeeds");
	check(!testdir_exists(record),
	    "  and sends no -k at all, because that command finds a client by convention");
	reap(server, socket_path);
}

static void a_stop_that_did_not_take_says_so(const char *base)
{
	ncfg_dhcp_machine_t machine;
	char                fake[256];
	char                record[256];
	char                mark[NCFG_DHCP_PATH_MAX];
	char                socket_path[512];
	char                message[NCFG_ERROR_MAX];
	pid_t               running;

	(void)testdir_in(base, "fake-stop4", fake, sizeof(fake));
	(void)testdir_in(base, "stop4.args", record, sizeof(record));
	write_recorder(fake, record, 0);
	a_machine(&machine, fake, "/nonexistent/udhcpc", "/nonexistent/busybox");

	check(ncfg_dhcp_config_path(run_dir, "ethI", "4", mark, sizeof(mark), NULL, 0),
	    "the mark netcfgd's own dhcpcd recites");
	/*
	 * Two answers, because the stop asks once before signalling and once
	 * after: a client that is still reciting netcfgd's `-f` after the `-k` is
	 * one the signal did not reach. That was the reporting machine's state for
	 * a month -- dhcpcd runs as its own user under privsep, signalling across
	 * uids needs `CAP_KILL`, and the unit did not grant it.
	 */
	running = a_dhcpcd_reciting("ethI", "4", mark, socket_path, sizeof(socket_path));
	check(running > 0, "a dhcpcd of netcfgd's that will not die");
	message[0] = '\0';
	check(!ncfg_dhcp_stop(run_dir, "ethI", "4", &machine, message, sizeof(message)),
	    "a stop that did not take is a failure rather than a silent success");
	check(strstr(message, "CAP_KILL") != NULL,
	    "  naming the privilege that is missing, because being root is not enough");
	check(testdir_exists(record), "  and the -k was sent, since the client was netcfgd's");
	reap(running, socket_path);
}

/* ------------------------------------------------------------------------ *
 * The whole of it
 * ------------------------------------------------------------------------ */

int main(void)
{
	const char *base = testdir_make("dhcp");
	char        message[NCFG_ERROR_MAX];

	/* A ceiling on the whole binary. Several cases fork, two wait out a
	 * deadline, and nothing else in this suite has a timeout. */
	alarm(180);

	(void)testdir_in(base, "run", run_dir, sizeof(run_dir));
	(void)testdir_in(base, "dhcpcd-run", dhcpcd_dir, sizeof(dhcpcd_dir));
	(void)testdir_in(base, "dhcpcd-hook", hook_path, sizeof(hook_path));
	check(mkdir(run_dir, 0755) == 0 && mkdir(dhcpcd_dir, 0755) == 0,
	    "a run directory of this test's own, and one standing in for dhcpcd's");
	write_fake(hook_path, "#!/bin/sh\nexit 0\n");

	what_udhcpc_is_started_with();
	what_dhcpcd_is_started_with();
	which_v6_client_can_serve_the_document();
	what_a_prefix_is_asked_for_with();
	what_odhcp6c_is_started_with();
	the_prefix_hook_writes_what_the_observer_reads();
	what_stops_it_names_the_same_family();
	the_paths_are_the_marks();

	the_script_touches_nothing_it_does_not_own();
	the_script_does_what_it_says(base);

	a_running_dhcpcd_is_asked_whose_it_is();
	a_client_is_recognised_by_the_path_it_carries();
	the_writer_and_the_reader_agree_on_where_the_record_lives();

	a_start_prefers_dhcpcd_and_writes_both_marks(base);
	a_dhcp6_start_carries_the_document_s_request(base);
	a_dhcp6_start_without_odhcp6c(base);
	a_machine_with_only_busybox_still_gets_a_lease(base);
	a_stale_metric_record_goes_with_the_client_that_had_one(base);
	a_dhcpcd_with_no_hook_is_refused_naming_the_file(base);
	a_client_that_refuses_its_configuration_is_quoted(base);
	a_machine_with_no_client_says_so();
	a_client_already_running_is_not_started_again(base);
	a_client_of_netcfgds_own_is_adopted_rather_than_doubled(base);
	a_dhcpcd_of_netcfgds_own_is_adopted_through_its_socket(base);
	a_strangers_dhcpcd_is_refused_rather_than_spawned_beside(base);

	stopping_nothing_is_the_state_that_was_asked_for(base);
	a_stop_signals_only_what_it_can_prove_is_netcfgds(base);
	the_interface_name_is_not_a_marker(base);
	a_stop_asks_whose_the_client_is_before_it_signals(base);
	a_stop_that_did_not_take_says_so(base);

	/* Nothing here has a default, so an executor told nothing refuses rather
	 * than reaching for `/run/dhcpcd` and `/usr/libexec` on the machine this
	 * is built on. */
	message[0] = '\0';
	check(!ncfg_dhcp_start(run_dir, "ethZ", NULL, NULL, message, sizeof(message)) &&
	    strstr(message, "default") != NULL,
	    "a start with no machine refuses rather than reaching for this machine's own");
	message[0] = '\0';
	check(!ncfg_dhcp_stop(run_dir, "ethZ", "4", NULL, message, sizeof(message)) &&
	    message[0] != '\0',
	    "and so does a stop, which would otherwise signal without knowing whose");

	testdir_remove(base);
	if (failures > 0) {
		printf("dhcp: %d check(s) failed\n", failures);
		return 1;
	}
	printf("dhcp: every check passed\n");
	return 0;
}
