/*
 * portal_test.c -- the captive-portal check, driven without leaving this
 * machine.
 *
 * NOTHING HERE REACHES THE NETWORK, AND HERE IS HOW
 *   A portal check exists to fetch somebody's URL, so a test of it has to be
 *   arranged not to. Three arrangements, and every case uses one of them:
 *
 *     * **The deciding parts are pure.** `is_routable`, `split`, `legible` and
 *       `verdict` take text and answer; they open nothing. Most of what a
 *       portal check gets wrong is in those four, which is why the Rust's own
 *       cases are all there too.
 *     * **The one call that opens a socket is pointed at a server this file
 *       started**, on `127.0.0.1` and on a port the kernel chose -- bound
 *       before the fork, so the test knows the number and nothing else can
 *       have it. The name in the URL is the loopback literal, so not even the
 *       resolver is asked anything a network could answer.
 *     * **The child that does the hostile half is a seam with no default.**
 *       `ncfg_portal_probe` is told which image to exec, and these cases hand
 *       it four-line shell scripts under this test's own directory: one per
 *       exit status the parent has to tell apart. That is the whole reason the
 *       image is an argument rather than `/proc/self/exe` (0263).
 *
 *   **`NCFG_PORTAL_OWN_IMAGE` is asserted by reading it and never by running
 *   it.** This binary is not netcfgd: exec it under `netcfgd-probe` and it
 *   runs this suite again, and again, and so on. The constant is checked as a
 *   string, which is `testdir.h`'s rule about a default applied to an image
 *   rather than to a path.
 *
 * WHAT COSTS TIME
 *   One case, and deliberately. `a_helper_that_will_not_finish_is_stopped`
 *   waits out the parent's own deadline -- a second past the alarm the real
 *   helper sets -- because the thing being checked is that the wait ends at
 *   all, and a bound that is never reached in a test is a bound nobody has
 *   seen work. It also leaves a grandchild holding the pipe, which is the case
 *   that tells "killed the child" from "killed the group": the shell exits
 *   immediately and only the group signal reaches what it started.
 *
 * NOTHING OUTSIDE ITS OWN DIRECTORY
 *   Every file here is under one `mkdtemp` directory, removed at the end. The
 *   daemon this is a port of is running on this machine.
 */
#include "ncfg/base.h"
#include "ncfg/portal.h"

#include "testdir.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int failures;

static void check(int condition, const char *what)
{
	printf("%-70s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

static int holds(const char *text, const char *wanted)
{
	return text && strstr(text, wanted) != NULL;
}

/* Wait a bounded time for something to become true, so that a check does not
 * turn into a sleep. Answers what it last saw. */
static int settles(int (*asked)(long), long about, int milliseconds)
{
	int waited = 0;

	while (waited < milliseconds) {
		struct timespec rest;

		if (asked(about)) {
			return 1;
		}
		rest.tv_sec = 0;
		rest.tv_nsec = 20L * 1000000L;
		(void)nanosleep(&rest, NULL);
		waited += 20;
	}
	return asked(about);
}

static int is_gone(long pid)
{
	return kill((pid_t)pid, 0) != 0 && errno == ESRCH;
}

/* ------------------------------------------------------------------------ *
 * What an address says about connectivity
 * ------------------------------------------------------------------------ */

/*
 * **A link-local address is not a network to check.**
 *
 * Every up interface has an `fe80::` one, so treating it as connectivity makes
 * "became addressed" true from the moment the link exists -- and a probe that
 * fires on that transition fires once, at startup, and never again. Found by
 * watching a real daemon miss the second join (0095), and carried across with
 * the same addresses.
 */
static void a_link_local_address_is_not_connectivity(void)
{
	static const char *const local[] = { "fe80::ccdf:86ff:fe9c:f9c7/64", "FE80::1",
		"169.254.10.4/16", "127.0.0.1/8", "::1" };
	static const char *const real[] = { "10.3.3.1/24", "192.0.2.7", "2001:db8::5/64",
		"203.0.113.9/32" };
	size_t at;
	int    all_refused = 1;
	int    all_counted = 1;

	for (at = 0u; at < sizeof(local) / sizeof(*local); at++) {
		if (ncfg_portal_is_routable(local[at])) {
			printf("    %s should not count\n", local[at]);
			all_refused = 0;
		}
	}
	for (at = 0u; at < sizeof(real) / sizeof(*real); at++) {
		if (!ncfg_portal_is_routable(real[at])) {
			printf("    %s should count\n", real[at]);
			all_counted = 0;
		}
	}
	check(all_refused, "a link-local, an IPv4 link-local and loopback are not connectivity");
	check(all_counted, "and an address that could reach something is");
}

/* ------------------------------------------------------------------------ *
 * The URL
 * ------------------------------------------------------------------------ */

static void a_url_splits_into_what_a_request_needs(void)
{
	ncfg_portal_url_t parts;
	char              err[NCFG_ERROR_MAX];
	char              too_long[NCFG_PORTAL_URL_MAX + 16];

	check(ncfg_portal_split("http://example.com/generate_204", &parts, err, sizeof(err)) &&
	    strcmp(parts.host, "example.com") == 0 && strcmp(parts.port, "80") == 0 &&
	    strcmp(parts.path, "/generate_204") == 0,
	    "a URL splits into a host, a port and a path");

	/*
	 * **The authority is what the `Host:` header carries, and it is not the
	 * connect target.** The Rust's `split` says exactly this in its comment
	 * and then hands `exchange` the target, so a URL with no port is asked for
	 * under `Host: example.com:80` -- which is not what a browser sends, and a
	 * portal check is a comparison against what a browser would have got.
	 */
	check(strcmp(parts.authority, "example.com") == 0,
	    "and the authority keeps no port the operator did not write");

	/* No path is a request for the root, which is what a browser does. */
	check(ncfg_portal_split("http://example.com", &parts, err, sizeof(err)) &&
	    strcmp(parts.path, "/") == 0 && strcmp(parts.port, "80") == 0,
	    "a URL with no path asks for the root");

	/* An explicit port is kept, and stays in the Host header too. */
	check(ncfg_portal_split("http://example.com:8080/x", &parts, err, sizeof(err)) &&
	    strcmp(parts.host, "example.com") == 0 && strcmp(parts.port, "8080") == 0 &&
	    strcmp(parts.authority, "example.com:8080") == 0 && strcmp(parts.path, "/x") == 0,
	    "an explicit port is kept, in the target and in the authority");

	/*
	 * An IPv6 literal arrives in brackets, and the brackets are URL syntax
	 * rather than part of the address. The Rust keeps them and hands
	 * `[2001:db8::1]` to its resolver, which answers `invalid port value` --
	 * so a `portal_check` naming an address instead of a name compiles and can
	 * never be fetched.
	 */
	check(ncfg_portal_split("http://[2001:db8::1]/generate_204", &parts, err, sizeof(err)) &&
	    strcmp(parts.host, "2001:db8::1") == 0 && strcmp(parts.port, "80") == 0 &&
	    strcmp(parts.authority, "[2001:db8::1]") == 0,
	    "an IPv6 literal loses its brackets before the resolver sees it");
	check(ncfg_portal_split("http://[2001:db8::1]:8080/x", &parts, err, sizeof(err)) &&
	    strcmp(parts.host, "2001:db8::1") == 0 && strcmp(parts.port, "8080") == 0,
	    "and keeps a port written after them");

	err[0] = '\0';
	check(!ncfg_portal_split("https://example.com/x", &parts, err, sizeof(err)) && err[0],
	    "`https` is not a URL this can fetch, and the refusal says so");
	check(!ncfg_portal_split("http:///x", &parts, err, sizeof(err)),
	    "and neither is one that names no host");

	memset(too_long, 'a', sizeof(too_long));
	memcpy(too_long, "http://", 7u);
	too_long[sizeof(too_long) - 1u] = '\0';
	err[0] = '\0';
	check(!ncfg_portal_split(too_long, &parts, err, sizeof(err)) &&
	    holds(err, "at most"),
	    "a URL longer than the ceiling is refused by naming the ceiling");
}

/* ------------------------------------------------------------------------ *
 * The verdict
 * ------------------------------------------------------------------------ */

static void a_status_line_decides(void)
{
	ncfg_portal_result_t result;

	ncfg_portal_verdict("HTTP/1.1 204 No Content", NCFG_PORTAL_EXPECT_DEFAULT, &result);
	check(result.verdict == NCFG_PORTAL_VERDICT_CLEAR,
	    "the expected status is clear and nothing is in the way");

	/* The two a portal actually produces: a redirect to its login page, or
	 * the page itself with a 200. */
	ncfg_portal_verdict("HTTP/1.1 302 Found", NCFG_PORTAL_EXPECT_DEFAULT, &result);
	check(result.verdict == NCFG_PORTAL_VERDICT_PORTAL, "a redirect is a portal");
	ncfg_portal_verdict("HTTP/1.1 200 OK", NCFG_PORTAL_EXPECT_DEFAULT, &result);
	check(result.verdict == NCFG_PORTAL_VERDICT_PORTAL, "and so is a page with a 200");

	check(strcmp(ncfg_portal_verdict_name(NCFG_PORTAL_VERDICT_CLEAR), "clear") == 0 &&
	    strcmp(ncfg_portal_verdict_name(NCFG_PORTAL_VERDICT_UNREACHABLE), "unreachable") == 0 &&
	    ncfg_portal_verdict_name(97) == NULL,
	    "a verdict has one word, and a number that is not one has none");
}

/*
 * **Something answering with something that is not HTTP is not "clear".**
 *
 * A transparent proxy that speaks nothing recognisable is still something in
 * the way, and the safe reading of an unparseable answer is that the network
 * is not what it claims -- not that everything is fine.
 */
static void an_answer_that_is_not_http_is_not_clear(void)
{
	static const char *const lines[] = { "", "hello", "220 smtp ready" };
	size_t                   at;
	int                      all_portals = 1;

	for (at = 0u; at < sizeof(lines) / sizeof(*lines); at++) {
		ncfg_portal_result_t result;

		ncfg_portal_verdict(lines[at], NCFG_PORTAL_EXPECT_DEFAULT, &result);
		if (result.verdict != NCFG_PORTAL_VERDICT_PORTAL) {
			printf("    `%s` should not read as clear\n", lines[at]);
			all_portals = 0;
		}
	}
	check(all_portals, "an answer that is not an HTTP status line is not clear");
}

/*
 * **The verdict is what reaches the hook, so the verdict is what is asserted.**
 *
 * The case below this one covers `legible` and would stay green with the call
 * site bypassed -- the Rust says it measured that by bypassing it. This drives
 * `ncfg_portal_verdict`, which is the function whose output becomes
 * `NCFG_REASON`, and it is the one that fails when the sanitising is skipped
 * rather than merely removed.
 */
static void the_detail_a_hook_receives_is_sanitised(void)
{
	static const char        nasty[] = "\x16\x03\x01 $(id) `id` ; rm -rf / | tee & glob*";
	static const char *const bad = "$`;|&*";
	ncfg_portal_result_t     result;
	size_t                   at;
	int                      clean = 1;

	ncfg_portal_verdict(nasty, NCFG_PORTAL_EXPECT_DEFAULT, &result);
	check(result.verdict == NCFG_PORTAL_VERDICT_PORTAL,
	    "something answered and it was not HTTP, so this is a portal");
	for (at = 0u; bad[at] != '\0'; at++) {
		if (strchr(result.detail, bad[at])) {
			printf("    `%c` reached the hook environment in `%s`\n", bad[at],
			    result.detail);
			clean = 0;
		}
	}
	check(clean, "and no shell metacharacter reaches the hook through the verdict");
	/* Still says what happened, or it is not a diagnostic. */
	check(holds(result.detail, "not an HTTP status line"),
	    "while still saying what happened");

	/* And the ordinary case is untouched: a real portal's code is a number
	 * and says which one. */
	ncfg_portal_verdict("HTTP/1.1 302 Found", NCFG_PORTAL_EXPECT_DEFAULT, &result);
	check(strcmp(result.detail, "expected 204, got 302") == 0,
	    "a portal's own code is reported as a number and nothing else");
}

/*
 * **What a hostile answer may put in a root script's environment.**
 *
 * A portal verdict's detail becomes `NCFG_REASON` for the `portal` hooks,
 * which run as root, and on that branch it is whatever answered on port 80.
 * The characters a careless hook could be hurt by are the ones to remove --
 * and the ones an operator reads it for are the ones to keep.
 */
static void a_hostile_answer_reaches_the_hook_declawed(void)
{
	char                     out[NCFG_PORTAL_LEGIBLE_MAX];
	char                     long_one[512];
	static const char        nasty[] = "$(id);`id`;rm -rf /|tee&x*?<>'\"\\";
	static const char *const bad = "$`;|&*?<>'\"\\";
	size_t                   at;
	int                      clean = 1;

	/* The case this exists for: it stays readable. */
	ncfg_portal_legible("HTTP/1.0 302 Found", out, sizeof(out));
	check(strcmp(out, "HTTP/1.0 302 Found") == 0, "a real status line survives intact");

	/* And the case it exists against. */
	ncfg_portal_legible(nasty, out, sizeof(out));
	for (at = 0u; bad[at] != '\0'; at++) {
		if (strchr(out, bad[at])) {
			printf("    `%c` survived into `%s`\n", bad[at], out);
			clean = 0;
		}
	}
	check(clean, "and every shell metacharacter becomes a dot");

	/* Bounded, because 1024 bytes of somebody else's choosing is not a
	 * diagnostic. */
	memset(long_one, 'A', sizeof(long_one));
	long_one[sizeof(long_one) - 1u] = '\0';
	ncfg_portal_legible(long_one, out, sizeof(out));
	check(strlen(out) == (size_t)NCFG_PORTAL_LEGIBLE_KEEP + 3u &&
	    holds(out, "..."),
	    "and a long answer is 64 characters and an ellipsis");
}

/* ------------------------------------------------------------------------ *
 * The one call that opens a socket
 * ------------------------------------------------------------------------ */

/*
 * Serve exactly one request on `listener` and record what was asked.
 *
 * Runs in a child of this test. It sets an alarm before it does anything, so
 * there is no arrangement of a failed accept or a half-open connection that
 * leaves it behind: the alarm's default action ends it.
 */
static void serve_one(int listener, const char *saw_path)
{
	static const char answer[] = "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n";
	char              request[2048];
	ssize_t           got;
	int               talking;
	FILE             *saw;

	alarm(10);
	talking = accept(listener, NULL, NULL);
	if (talking < 0) {
		_exit(1);
	}
	got = read(talking, request, sizeof(request) - 1u);
	if (got < 0) {
		got = 0;
	}
	request[got] = '\0';
	saw = fopen(saw_path, "wb");
	if (saw) {
		(void)fwrite(request, 1u, (size_t)got, saw);
		(void)fclose(saw);
	}
	(void)write(talking, answer, sizeof(answer) - 1u);
	(void)close(talking);
	(void)close(listener);
	_exit(0);
}

/*
 * **A real socket, and the far side is this file.**
 *
 * `127.0.0.1` on a port the kernel chose, so nothing is resolved that a
 * network could answer and nothing leaves the machine. What it proves is the
 * half the pure cases cannot: that the request is well formed, that
 * `Connection: close` is in it -- without it the read waits out the deadline
 * on every well-behaved server -- and that the status line comes back off the
 * wire rather than out of a string.
 */
static void the_status_line_comes_back_off_a_socket(const char *dir)
{
	struct sockaddr_in where;
	socklen_t          where_size = sizeof(where);
	char               url[128];
	char               status[NCFG_PORTAL_STATUS_MAX];
	char               err[NCFG_ERROR_MAX];
	char               saw_path[512];
	char              *saw;
	int                listener;
	pid_t              server;
	int                fetched;

	(void)testdir_in(dir, "request", saw_path, sizeof(saw_path));
	listener = socket(AF_INET, SOCK_STREAM, 0);
	if (listener < 0) {
		check(0, "a loopback listener could be opened");
		return;
	}
	memset(&where, 0, sizeof(where));
	where.sin_family = AF_INET;
	where.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	where.sin_port = 0;
	if (bind(listener, (const struct sockaddr *)&where, (socklen_t)sizeof(where)) != 0 ||
	    listen(listener, 1) != 0 ||
	    getsockname(listener, (struct sockaddr *)&where, &where_size) != 0) {
		check(0, "a loopback listener could be bound");
		(void)close(listener);
		return;
	}
	(void)snprintf(url, sizeof(url), "http://127.0.0.1:%u/generate_204",
	    (unsigned)ntohs(where.sin_port));

	server = fork();
	if (server < 0) {
		check(0, "a server for the loopback listener could be started");
		(void)close(listener);
		return;
	}
	if (server == 0) {
		serve_one(listener, saw_path);
	}
	/* The child owns the listener now; a copy left open here would hold it
	 * after the child has gone. */
	(void)close(listener);

	status[0] = '\0';
	err[0] = '\0';
	fetched = ncfg_portal_fetch(url, status, sizeof(status), err, sizeof(err));
	while (waitpid(server, NULL, 0) < 0 && errno == EINTR) {
		continue;
	}

	check(fetched && strcmp(status, "HTTP/1.1 204 No Content") == 0,
	    "the status line comes back off a real socket");
	if (!fetched) {
		printf("    %s\n", err);
	}

	saw = testdir_read(saw_path, NULL);
	check(holds(saw, "GET /generate_204 HTTP/1.1\r\n"), "and the request asked for the path");
	{
		char wanted[128];

		(void)snprintf(wanted, sizeof(wanted), "Host: 127.0.0.1:%u\r\n",
		    (unsigned)ntohs(where.sin_port));
		check(holds(saw, wanted), "with the authority the URL wrote in its `Host:` header");
	}
	check(holds(saw, "Connection: close\r\n"),
	    "and `Connection: close`, without which every read waits out the deadline");
	free(saw);
}

/* Nothing listening on a loopback port is not a portal: a portal is a thing
 * that replies. */
static void nothing_answering_is_not_a_portal(void)
{
	struct sockaddr_in where;
	socklen_t          where_size = sizeof(where);
	char               url[128];
	char               status[NCFG_PORTAL_STATUS_MAX];
	char               err[NCFG_ERROR_MAX];
	int                listener = socket(AF_INET, SOCK_STREAM, 0);
	unsigned           port;

	if (listener < 0) {
		check(0, "a loopback port could be reserved");
		return;
	}
	memset(&where, 0, sizeof(where));
	where.sin_family = AF_INET;
	where.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(listener, (const struct sockaddr *)&where, (socklen_t)sizeof(where)) != 0 ||
	    getsockname(listener, (struct sockaddr *)&where, &where_size) != 0) {
		check(0, "a loopback port could be reserved");
		(void)close(listener);
		return;
	}
	port = (unsigned)ntohs(where.sin_port);
	/* Closed before the fetch, so the port is one the kernel gave this test
	 * and is now listening on nothing. */
	(void)close(listener);
	(void)snprintf(url, sizeof(url), "http://127.0.0.1:%u/generate_204", port);

	err[0] = '\0';
	check(!ncfg_portal_fetch(url, status, sizeof(status), err, sizeof(err)) &&
	    holds(err, "cannot reach 127.0.0.1"),
	    "a port with nothing behind it is reported as unreachable, by name");
}

/* ------------------------------------------------------------------------ *
 * The child, and what the parent makes of it
 * ------------------------------------------------------------------------ */

/* Write one, make it runnable, and answer its path in the caller's buffer. */
static const char *helper(const char *dir, const char *leaf, const char *body, char *out,
    size_t out_size)
{
	(void)testdir_in(dir, leaf, out, out_size);
	if (!testdir_write(out, body, strlen(body)) || chmod(out, 0700) != 0) {
		check(0, "a helper script could be written");
		out[0] = '\0';
	}
	return out;
}

/*
 * **Every exit status the parent has to tell apart, told apart.**
 *
 * The Rust has no test of `probe` at all -- it can only be reached with the
 * real binary and a real network -- so these five arms are the ones nothing
 * was checking. Each is a shell script under this test's own directory, exec'd
 * exactly as the daemon execs its own image.
 */
static void the_helper_s_exit_status_decides_the_verdict(const char *dir)
{
	char                 path[512];
	ncfg_portal_result_t result;
	const char          *url = "http://127.0.0.1:1/generate_204";

	ncfg_portal_probe(helper(dir, "clear.sh",
	    "#!/bin/sh\necho 'HTTP/1.1 204 No Content'\nexit 0\n", path, sizeof(path)), url,
	    NCFG_PORTAL_EXPECT_DEFAULT, &result);
	check(result.verdict == NCFG_PORTAL_VERDICT_CLEAR,
	    "a helper that exits 0 with the expected status is clear");

	ncfg_portal_probe(helper(dir, "portal.sh",
	    "#!/bin/sh\necho 'HTTP/1.1 302 Found'\nexit 0\n", path, sizeof(path)), url,
	    NCFG_PORTAL_EXPECT_DEFAULT, &result);
	check(result.verdict == NCFG_PORTAL_VERDICT_PORTAL &&
	    strcmp(result.detail, "expected 204, got 302") == 0,
	    "one that exits 0 with a redirect is a portal, and says which code");

	ncfg_portal_probe(helper(dir, "quiet.sh",
	    "#!/bin/sh\necho 'cannot reach example.com: Connection refused'\nexit 1\n", path,
	    sizeof(path)), url, NCFG_PORTAL_EXPECT_DEFAULT, &result);
	check(result.verdict == NCFG_PORTAL_VERDICT_UNREACHABLE &&
	    strcmp(result.detail, "cannot reach example.com: Connection refused") == 0,
	    "exit 1 is unreachable, in the child's own words");

	/*
	 * **A probe that ran anyway would be the thing this exists to prevent,
	 * quietly**, so the refusal to shed is its own sentence rather than
	 * another unreachable.
	 */
	ncfg_portal_probe(helper(dir, "armed.sh",
	    "#!/bin/sh\necho 'still holds CAP_NET_ADMIN'\nexit 2\n", path, sizeof(path)), url,
	    NCFG_PORTAL_EXPECT_DEFAULT, &result);
	check(result.verdict == NCFG_PORTAL_VERDICT_UNREACHABLE &&
	    holds(result.detail, "would not drop its privileges") &&
	    holds(result.detail, "still holds CAP_NET_ADMIN"),
	    "a helper that could not shed says so, rather than being merely unreachable");

	ncfg_portal_probe(helper(dir, "confused.sh", "#!/bin/sh\nexit 3\n", path, sizeof(path)),
	    url, NCFG_PORTAL_EXPECT_DEFAULT, &result);
	check(result.verdict == NCFG_PORTAL_VERDICT_UNREACHABLE &&
	    holds(result.detail, "exited with 3"),
	    "and any other status is reported with the number");

	(void)testdir_in(dir, "not-installed", path, sizeof(path));
	ncfg_portal_probe(path, url, NCFG_PORTAL_EXPECT_DEFAULT, &result);
	check(result.verdict == NCFG_PORTAL_VERDICT_UNREACHABLE &&
	    holds(result.detail, "could not start the probe helper"),
	    "a helper that is not there is a probe that did not run, not a portal");
}

/*
 * **The bound on the wait, and the group it signals.**
 *
 * This one costs the parent's whole deadline, which is the point: a bound
 * nobody has watched expire is a bound nobody has checked. The helper exits
 * immediately and leaves a `sleep` of its own holding the pipe, so end of file
 * never arrives -- which is exactly the shape that tells a kill of the child
 * from a kill of the group. Signalling only the shell would leave the sleep
 * running, reparented to init, with the daemon no longer waiting for work it
 * can no longer stop.
 */
static void a_helper_that_will_not_finish_is_stopped(const char *dir)
{
	char                 path[512];
	char                 pid_path[512];
	char                 body[1024];
	char                *recorded;
	ncfg_portal_result_t result;
	long                 grandchild = 0;

	(void)testdir_in(dir, "grandchild.pid", pid_path, sizeof(pid_path));
	(void)snprintf(body, sizeof(body),
	    "#!/bin/sh\nsleep 30 &\necho $! > %s\nexit 0\n", pid_path);
	ncfg_portal_probe(helper(dir, "forks.sh", body, path, sizeof(path)),
	    "http://127.0.0.1:1/generate_204", NCFG_PORTAL_EXPECT_DEFAULT, &result);

	check(result.verdict == NCFG_PORTAL_VERDICT_UNREACHABLE &&
	    holds(result.detail, "did not finish"),
	    "a helper whose output never ends is unreachable rather than a wait with no end");

	recorded = testdir_read(pid_path, NULL);
	if (recorded) {
		grandchild = strtol(recorded, NULL, 10);
		free(recorded);
	}
	if (grandchild > 1) {
		int gone = settles(is_gone, grandchild, 2000);

		check(gone, "and what it started is gone too, which only a group signal does");
		if (!gone) {
			/* Started by this test's own helper and recorded by pid, so
			 * this is a process this file may end -- and leaving a
			 * `sleep 30` behind because a check failed is not something
			 * to hand the next run. */
			(void)kill((pid_t)grandchild, SIGKILL);
		}
	} else {
		check(0, "the helper recorded the pid of what it started");
	}
}

/* ------------------------------------------------------------------------ *
 * The image the daemon names
 * ------------------------------------------------------------------------ */

/*
 * **Read, never run.** Exec this binary under `netcfgd-probe` and it runs this
 * suite again: the multi-call dispatch belongs to netcfgd's `main` and there is
 * none here. So the constant is checked as text, which is the whole reason it
 * is a constant.
 */
static void the_image_the_daemon_names_is_its_own(void)
{
	check(strcmp(NCFG_PORTAL_OWN_IMAGE, "/proc/self/exe") == 0,
	    "the image a daemon hands the probe is how a process finds its own");
	check(strcmp(NCFG_PORTAL_HELPER_NAME, "netcfgd-probe") == 0,
	    "and the name it runs under is the one netcfgd's own `main` dispatches on");
	check(NCFG_PORTAL_CHILD_SECONDS > NCFG_PORTAL_DEADLINE_SECONDS,
	    "the child outlives the socket deadline, so a stuck read is reported as one");
}

int main(void)
{
	const char *dir = testdir_make("portal");

	/*
	 * A ceiling on the whole binary. One case here waits out a seven-second
	 * deadline on purpose and several fork; nothing else in this suite has a
	 * timeout, so a hang would be a hang of `make test`.
	 */
	alarm(120);

	printf("== portal_test in %s\n", dir);
	a_link_local_address_is_not_connectivity();
	a_url_splits_into_what_a_request_needs();
	a_status_line_decides();
	an_answer_that_is_not_http_is_not_clear();
	the_detail_a_hook_receives_is_sanitised();
	a_hostile_answer_reaches_the_hook_declawed();
	the_status_line_comes_back_off_a_socket(dir);
	nothing_answering_is_not_a_portal();
	the_helper_s_exit_status_decides_the_verdict(dir);
	a_helper_that_will_not_finish_is_stopped(dir);
	the_image_the_daemon_names_is_its_own();
	testdir_remove(dir);

	if (failures == 0) {
		printf("portal_test: all checks passed\n");
	} else {
		printf("portal_test: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
