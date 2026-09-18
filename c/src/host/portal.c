/*
 * portal.c -- the captive-portal check, and the child that does the hostile
 * half of it.
 *
 * WHAT THIS FILE SPAWNS, AND WHAT STOPS IT
 *   One child per probe, in its own process group, execing an image the caller
 *   named. There is no loop that spawns, no recursion and no path that leaves
 *   a process behind: the real helper bounds itself with an alarm, and this
 *   side bounds it again -- at the deadline the whole *group* gets `SIGTERM`
 *   and then `SIGKILL`, and the child is reaped before the call returns.
 *
 *   **The second bound is not redundancy, it is the seam.** The Rust's child
 *   is always netcfgd's own image, so its alarm is netcfgd's own code and the
 *   parent can lean on it. Here the image is an argument, and a parent that
 *   leaned on a promise the caller makes would be a reconcile loop that stops
 *   because somebody pointed it at the wrong file.
 *
 * WHY THE REQUEST IS WRITTEN BY HAND
 *   The request is one line and the answer that matters is the status on the
 *   first line of the response. Reading further would mean parsing a body this
 *   does not care about, from a host it has already decided not to trust --
 *   and an HTTP library would be a dependency bought for one `GET`.
 */
#include "ncfg/portal.h"

#include "ncfg/process.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* The characters a hostile answer may keep, beyond letters and digits. Chosen
 * so that `HTTP/1.0 302 Found` and a `Location:` line survive and a shell's
 * metacharacters do not. */
static const char legible_keep[] = " .,:/-_=";

/* How often the wait for the child wakes to look at the clock. `probe.c`'s
 * number, for the same wait. */
#define POLL_MILLISECONDS 20

/* How long the group gets between `SIGTERM` and `SIGKILL`. */
#define GRACE_MILLISECONDS 200

/* ------------------------------------------------------------------------ *
 * Small things
 * ------------------------------------------------------------------------ */

/* Milliseconds on a clock nothing can move. `CLOCK_MONOTONIC` rather than the
 * wall clock, because a deadline that a time step can extend is not one. */
static long long monotonic_milliseconds(void)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
		return 0;
	}
	return (long long)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

/* Take the trailing whitespace off in place. */
static void trim_end(char *text)
{
	size_t length = strlen(text);

	while (length > 0u && (text[length - 1u] == '\n' || text[length - 1u] == '\r' ||
	    text[length - 1u] == '\t' || text[length - 1u] == ' ')) {
		text[--length] = '\0';
	}
}

/* Whether `text` starts with `prefix`, ignoring case in the ASCII range --
 * which is the only range an address is written in. */
static int starts_with_folded(const char *text, const char *prefix)
{
	size_t at;

	for (at = 0u; prefix[at] != '\0'; at++) {
		char one = text[at];

		if (one >= 'A' && one <= 'Z') {
			one = (char)(one - 'A' + 'a');
		}
		if (one != prefix[at]) {
			return 0;
		}
	}
	return 1;
}

/* ------------------------------------------------------------------------ *
 * What an address says about connectivity
 * ------------------------------------------------------------------------ */

int ncfg_portal_is_routable(const char *address)
{
	char        host[NCFG_PORTAL_AUTHORITY_MAX];
	const char *slash;
	size_t      length;

	if (!address || address[0] == '\0') {
		return 0;
	}
	/* The address may carry a prefix length; the family is decided by what is
	 * in front of it. */
	slash = strchr(address, '/');
	length = slash ? (size_t)(slash - address) : strlen(address);
	if (length >= sizeof(host)) {
		/* Nothing this long is an address, so it is nothing this can call
		 * routable either. */
		return 0;
	}
	memcpy(host, address, length);
	host[length] = '\0';

	if (starts_with_folded(host, "fe80:") || starts_with_folded(host, "169.254.") ||
	    starts_with_folded(host, "127.")) {
		return 0;
	}
	return strcmp(host, "::1") != 0;
}

/* ------------------------------------------------------------------------ *
 * The URL
 * ------------------------------------------------------------------------ */

/*
 * Split `http://host[:port]/path` into what a request needs.
 *
 * **The authority and the connect target are answered separately**, which is
 * the divergence 0263 records: the `Host:` header carries the authority as the
 * operator wrote it, and only the connection needs a port whether or not the
 * URL gave one.
 *
 * An IPv6 literal arrives in brackets -- `http://[2001:db8::1]/x` -- and the
 * brackets are URL syntax rather than part of the address, so they come off
 * before `getaddrinfo` sees it. Without that, every colon in the literal reads
 * as a port separator.
 */
int ncfg_portal_split(const char *url, ncfg_portal_url_t *out, char *err, size_t err_size)
{
	const char *rest;
	const char *slash;
	const char *colon;
	size_t      authority_length;
	size_t      path_length;
	size_t      host_length;

	if (!out) {
		ncfg_error_set(err, err_size, "a URL has to be split into something");
		return 0;
	}
	memset(out, 0, sizeof(*out));
	if (!url || strlen(url) >= (size_t)NCFG_PORTAL_URL_MAX) {
		ncfg_error_set(err, err_size,
		    "a captive portal check is at most %d characters, and this one is longer",
		    NCFG_PORTAL_URL_MAX - 1);
		return 0;
	}
	if (strncmp(url, "http://", 7u) != 0) {
		ncfg_error_set(err, err_size, "`%s` is not a URL this can fetch", url);
		return 0;
	}
	rest = url + 7;
	slash = strchr(rest, '/');
	authority_length = slash ? (size_t)(slash - rest) : strlen(rest);
	if (authority_length == 0u) {
		ncfg_error_set(err, err_size, "`%s` is not a URL this can fetch", url);
		return 0;
	}
	if (authority_length >= sizeof(out->authority)) {
		ncfg_error_set(err, err_size, "`%s` names a host too long to connect to", url);
		return 0;
	}
	memcpy(out->authority, rest, authority_length);
	out->authority[authority_length] = '\0';

	/* No path is a request for the root, which is what a browser does. */
	path_length = slash ? strlen(slash) : 1u;
	if (path_length >= sizeof(out->path)) {
		ncfg_error_set(err, err_size, "`%s` asks for a path too long to send", url);
		return 0;
	}
	memcpy(out->path, slash ? slash : "/", path_length);
	out->path[path_length] = '\0';

	if (out->authority[0] == '[') {
		const char *close_bracket = strchr(out->authority, ']');

		if (!close_bracket || close_bracket == out->authority + 1) {
			ncfg_error_set(err, err_size, "`%s` is not a URL this can fetch", url);
			return 0;
		}
		host_length = (size_t)(close_bracket - out->authority) - 1u;
		colon = close_bracket[1] == ':' ? close_bracket + 1 : NULL;
		memcpy(out->host, out->authority + 1, host_length);
		out->host[host_length] = '\0';
	} else {
		colon = strchr(out->authority, ':');
		host_length = colon ? (size_t)(colon - out->authority) : authority_length;
		if (host_length == 0u) {
			ncfg_error_set(err, err_size, "`%s` is not a URL this can fetch", url);
			return 0;
		}
		memcpy(out->host, out->authority, host_length);
		out->host[host_length] = '\0';
	}

	if (colon) {
		if (colon[1] == '\0' || strlen(colon + 1) >= sizeof(out->port)) {
			ncfg_error_set(err, err_size, "`%s` does not name a port this can connect to",
			    url);
			return 0;
		}
		(void)snprintf(out->port, sizeof(out->port), "%s", colon + 1);
	} else {
		(void)snprintf(out->port, sizeof(out->port), "80");
	}
	return 1;
}

/* ------------------------------------------------------------------------ *
 * What is safe to repeat
 * ------------------------------------------------------------------------ */

void ncfg_portal_legible(const char *text, char *out, size_t out_size)
{
	size_t kept = 0u;
	size_t at;

	if (!out || out_size == 0u) {
		return;
	}
	out[0] = '\0';
	if (!text) {
		return;
	}
	for (at = 0u; text[at] != '\0' && kept + 1u < out_size &&
	    kept < (size_t)NCFG_PORTAL_LEGIBLE_KEEP; at++) {
		char one = text[at];
		int  alphanumeric = (one >= '0' && one <= '9') || (one >= 'a' && one <= 'z') ||
		    (one >= 'A' && one <= 'Z');

		out[kept++] = alphanumeric || strchr(legible_keep, one) != NULL ? one : '.';
	}
	out[kept] = '\0';
	/* An ellipsis where there was more, so that a reader can tell a short
	 * answer from a trimmed one. */
	if (text[at] != '\0' && kept + 4u <= out_size) {
		(void)memcpy(out + kept, "...", 4u);
	}
}

/* ------------------------------------------------------------------------ *
 * The verdict
 * ------------------------------------------------------------------------ */

const char *ncfg_portal_verdict_name(int verdict)
{
	switch (verdict) {
	case NCFG_PORTAL_VERDICT_CLEAR:
		return "clear";
	case NCFG_PORTAL_VERDICT_PORTAL:
		return "portal";
	case NCFG_PORTAL_VERDICT_UNREACHABLE:
		return "unreachable";
	default:
		return NULL;
	}
}

/* Fill in a verdict and its sentence. */
static void say(ncfg_portal_result_t *out, int verdict, const char *format, ...)
{
	va_list args;

	out->verdict = verdict;
	out->detail[0] = '\0';
	va_start(args, format);
	ncfg_error_setv(out->detail, sizeof(out->detail), format, args);
	va_end(args);
}

/*
 * The status code out of a status line, or -1 where there is not one.
 *
 * `HTTP/1.1 204 No Content` -- the code is the second word, and it is digits
 * only: a second word of `smtp` is an answer that is not HTTP, which is a
 * different verdict rather than a number to guess at.
 */
static int status_code(const char *status_line)
{
	const char *at = status_line;
	const char *word;
	int         code = 0;
	int         digits = 0;

	while (*at == ' ' || *at == '\t') {
		at++;
	}
	while (*at != '\0' && *at != ' ' && *at != '\t') {
		at++;
	}
	while (*at == ' ' || *at == '\t') {
		at++;
	}
	word = at;
	while (*at >= '0' && *at <= '9') {
		if (digits < 5) {
			code = code * 10 + (*at - '0');
		}
		digits++;
		at++;
	}
	if (digits == 0 || digits > 5 || (*at != '\0' && *at != ' ' && *at != '\t')) {
		return -1;
	}
	(void)word;
	return code;
}

void ncfg_portal_verdict(const char *status_line, int expect, ncfg_portal_result_t *out)
{
	char legible[NCFG_PORTAL_LEGIBLE_MAX];
	int  code;

	if (!out) {
		return;
	}
	code = status_line ? status_code(status_line) : -1;
	if (code == expect) {
		say(out, NCFG_PORTAL_VERDICT_CLEAR, "%s", "");
		return;
	}
	if (code >= 0) {
		say(out, NCFG_PORTAL_VERDICT_PORTAL, "expected %d, got %d", expect, code);
		return;
	}
	/*
	 * Something answered on port 80 and it was not HTTP. That is not
	 * "unreachable" -- something is there -- and calling it clear would be
	 * worse than calling it a portal.
	 */
	ncfg_portal_legible(status_line ? status_line : "", legible, sizeof(legible));
	say(out, NCFG_PORTAL_VERDICT_PORTAL, "the answer was not an HTTP status line: %s",
	    legible);
}

/* ------------------------------------------------------------------------ *
 * The fetch, which is the only thing here that touches the network
 * ------------------------------------------------------------------------ */

/* Connect with a deadline, which `connect(2)` has no option for: the socket is
 * made non-blocking for the attempt and put back afterwards. */
static int connect_by(int fd, const struct sockaddr *address, socklen_t length, int seconds)
{
	int           flags = fcntl(fd, F_GETFL, 0);
	struct pollfd watch;
	int           error_number = 0;
	socklen_t     error_size = sizeof(error_number);
	int           ready;

	if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
		return 0;
	}
	if (connect(fd, address, length) == 0) {
		return fcntl(fd, F_SETFL, flags) == 0;
	}
	if (errno != EINPROGRESS) {
		return 0;
	}
	memset(&watch, 0, sizeof(watch));
	watch.fd = fd;
	watch.events = POLLOUT;
	ready = poll(&watch, 1u, seconds * 1000);
	if (ready == 0) {
		/* `poll` says nothing about `errno` when it simply ran out of time, so
		 * the caller's sentence is given the one that means it. */
		errno = ETIMEDOUT;
		return 0;
	}
	if (ready != 1) {
		return 0;
	}
	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error_number, &error_size) != 0) {
		return 0;
	}
	if (error_number != 0) {
		errno = error_number;
		return 0;
	}
	return fcntl(fd, F_SETFL, flags) == 0;
}

/*
 * Send the request and read back the status line.
 *
 * `Connection: close` so the server hangs up rather than waiting for a second
 * request this will never send -- without it the read below waits out the
 * deadline on every well-behaved server.
 */
static int exchange(int fd, const ncfg_portal_url_t *url, char *status_line, size_t status_size,
    char *err, size_t err_size)
{
	char        request[NCFG_PORTAL_PATH_MAX + NCFG_PORTAL_AUTHORITY_MAX + 128];
	char        answer[NCFG_PORTAL_STATUS_MAX];
	size_t      filled = 0u;
	const char *at;
	size_t      length;
	size_t      sent = 0u;
	int         written;

	written = snprintf(request, sizeof(request),
	    "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: netcfgd\r\nAccept: */*\r\n"
	    "Connection: close\r\n\r\n", url->path, url->authority);
	if (written < 0 || (size_t)written >= sizeof(request)) {
		ncfg_error_set(err, err_size, "%s did not answer: the request would not fit",
		    url->authority);
		return 0;
	}
	length = (size_t)written;
	while (sent < length) {
		ssize_t put = write(fd, request + sent, length - sent);

		if (put < 0) {
			if (errno == EINTR) {
				continue;
			}
			ncfg_error_set(err, err_size, "%s did not answer: %s", url->authority,
			    strerror(errno));
			return 0;
		}
		sent += (size_t)put;
	}

	/*
	 * The status line and nothing more. Bounded because the far side is a host
	 * this has already decided not to trust: a portal that answered forever
	 * would otherwise be a portal that hung netcfgd.
	 */
	while (filled + 1u < sizeof(answer)) {
		ssize_t got = read(fd, answer + filled, sizeof(answer) - 1u - filled);

		if (got < 0) {
			if (errno == EINTR) {
				continue;
			}
			ncfg_error_set(err, err_size, "%s did not answer: %s", url->authority,
			    strerror(errno));
			return 0;
		}
		if (got == 0) {
			break;
		}
		filled += (size_t)got;
		answer[filled] = '\0';
		if (memchr(answer, '\n', filled) || memchr(answer, '\r', filled)) {
			break;
		}
	}
	answer[filled] = '\0';
	/* The first line, and never past what arrived: a NUL in the answer ends it
	 * here exactly as it would end any other string, which is the safe
	 * reading of bytes chosen by the far side. */
	at = answer;
	length = strcspn(at, "\r\n");
	if (length >= status_size) {
		length = status_size - 1u;
	}
	memcpy(status_line, at, length);
	status_line[length] = '\0';
	return 1;
}

int ncfg_portal_fetch(const char *url, char *status_line, size_t status_size, char *err,
    size_t err_size)
{
	ncfg_portal_url_t parts;
	struct addrinfo   wanted;
	struct addrinfo  *found = NULL;
	struct timeval    deadline;
	int               resolved;
	int               fd;
	int               ok;

	if (!status_line || status_size == 0u) {
		ncfg_error_set(err, err_size, "there is nowhere to put the answer");
		return 0;
	}
	status_line[0] = '\0';
	if (!ncfg_portal_split(url, &parts, err, err_size)) {
		return 0;
	}

	memset(&wanted, 0, sizeof(wanted));
	wanted.ai_family = AF_UNSPEC;
	wanted.ai_socktype = SOCK_STREAM;
	wanted.ai_protocol = IPPROTO_TCP;
	/*
	 * Resolution is the first thing a portal interferes with and the first
	 * thing that fails on a network with none, so its failure is reported as
	 * its own sentence rather than folded into "could not connect".
	 */
	resolved = getaddrinfo(parts.host, parts.port, &wanted, &found);
	if (resolved != 0) {
		ncfg_error_set(err, err_size, "cannot resolve %s: %s", parts.authority,
		    gai_strerror(resolved));
		if (found) {
			freeaddrinfo(found);
		}
		return 0;
	}
	if (!found) {
		ncfg_error_set(err, err_size, "%s resolved to nothing", parts.authority);
		return 0;
	}

	fd = socket(found->ai_family, found->ai_socktype, found->ai_protocol);
	if (fd < 0) {
		ncfg_error_set(err, err_size, "cannot reach %s: %s", parts.authority,
		    strerror(errno));
		freeaddrinfo(found);
		return 0;
	}
	if (!connect_by(fd, found->ai_addr, found->ai_addrlen, NCFG_PORTAL_DEADLINE_SECONDS)) {
		ncfg_error_set(err, err_size, "cannot reach %s: %s", parts.authority,
		    strerror(errno));
		(void)close(fd);
		freeaddrinfo(found);
		return 0;
	}
	freeaddrinfo(found);

	memset(&deadline, 0, sizeof(deadline));
	deadline.tv_sec = NCFG_PORTAL_DEADLINE_SECONDS;
	(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &deadline, (socklen_t)sizeof(deadline));
	(void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &deadline, (socklen_t)sizeof(deadline));

	ok = exchange(fd, &parts, status_line, status_size, err, err_size);
	(void)close(fd);
	return ok;
}

/* ------------------------------------------------------------------------ *
 * The child
 * ------------------------------------------------------------------------ */

int ncfg_portal_helper(const char *url, char *said, size_t said_size)
{
	char        status[NCFG_PORTAL_STATUS_MAX];
	char        why[NCFG_ERROR_MAX];
	ncfg_shed_t reached = NCFG_SHED_CAPABILITIES_ONLY;

	if (!said || said_size == 0u) {
		return 2;
	}
	said[0] = '\0';
	/* Before the alarm and before anything is resolved or opened. A failure
	 * here is the whole reason to stop. */
	if (!ncfg_privilege_shed(&reached, why, sizeof(why))) {
		(void)snprintf(said, said_size, "%s", why);
		return 2;
	}
	ncfg_privilege_die_after(NCFG_PORTAL_CHILD_SECONDS);

	if (!ncfg_portal_fetch(url, status, sizeof(status), why, sizeof(why))) {
		(void)snprintf(said, said_size, "%s", why);
		return 1;
	}
	(void)snprintf(said, said_size, "%s", status);
	return 0;
}

/* ------------------------------------------------------------------------ *
 * The parent
 * ------------------------------------------------------------------------ */

/*
 * Start the helper, or say why not.
 *
 * The `execv` failure comes back through a close-on-exec pipe, which is the
 * only way the parent can tell "started and exited 127" from "never started":
 * the first is a helper saying something and the second is a machine with no
 * helper on it.
 */
static pid_t spawn(const char *helper_program, const char *url, int say_write, int *exec_errno)
{
	int   report[2];
	pid_t child;
	int   got = 0;

	*exec_errno = 0;
	if (pipe(report) != 0) {
		*exec_errno = errno;
		return -1;
	}
	if (fcntl(report[1], F_SETFD, FD_CLOEXEC) != 0) {
		*exec_errno = errno;
		(void)close(report[0]);
		(void)close(report[1]);
		return -1;
	}
	child = fork();
	if (child < 0) {
		*exec_errno = errno;
		(void)close(report[0]);
		(void)close(report[1]);
		return -1;
	}
	if (child == 0) {
		char *argv[3];
		int   null = open("/dev/null", O_RDWR);

		/* Its own process group, so that killing it kills what it started. */
		(void)setpgid(0, 0);
		(void)close(report[0]);
		if (null >= 0) {
			/* Standard input is `/dev/null` so a helper waiting to be typed at
			 * fails rather than holding the daemon, and standard error goes
			 * there because the parent has no use for it -- the real helper
			 * says which shed it reached and that is for whoever is watching
			 * the child, not for the verdict. */
			(void)dup2(null, STDIN_FILENO);
			(void)dup2(null, STDERR_FILENO);
			if (null > STDERR_FILENO) {
				(void)close(null);
			}
		}
		if (dup2(say_write, STDOUT_FILENO) < 0) {
			_exit(127);
		}
		if (say_write > STDERR_FILENO) {
			(void)close(say_write);
		}
		argv[0] = (char *)(uintptr_t)(const void *)NCFG_PORTAL_HELPER_NAME;
		argv[1] = (char *)(uintptr_t)(const void *)url;
		argv[2] = NULL;
		(void)execv(helper_program, argv);
		got = errno;
		/* A short write is as good as none: the parent treats anything but a
		 * whole int as "it started". */
		(void)write(report[1], &got, sizeof(got));
		_exit(127);
	}
	(void)close(report[1]);
	/*
	 * The parent sets the group too. Whichever of the two runs first wins and
	 * the other is a no-op -- doing it in one place only is the classic race,
	 * where the parent signals a group the child has not joined yet.
	 */
	(void)setpgid(child, child);
	if (read(report[0], &got, sizeof(got)) == (ssize_t)sizeof(got)) {
		*exec_errno = got;
	}
	(void)close(report[0]);
	if (*exec_errno != 0) {
		/* It never ran, so it is a zombie already. Reaped here rather than
		 * left for a timeout path this branch does not reach. */
		(void)waitpid(child, NULL, 0);
		return -1;
	}
	return child;
}

/*
 * Kill the whole group, give it a moment, then kill it outright, and reap.
 *
 * **The `SIGKILL` goes out even where the leader has already gone**, which is
 * the part it is tempting to skip: the helper may have started something of
 * its own, and that grandchild is reparented to init the moment its parent
 * exits. `probe.c` says the same thing at more length; the two are deliberately
 * the same shape.
 */
static void end_it(pid_t child)
{
	char ignored[NCFG_ERROR_MAX];
	int  waited = 0;

	(void)ncfg_process_terminate_group(child, ignored, sizeof(ignored));
	while (waited < GRACE_MILLISECONDS) {
		siginfo_t about;

		memset(&about, 0, sizeof(about));
		/*
		 * `WNOWAIT`, so the child stays a zombie until the very end: it is the
		 * group leader, so its pid *is* the group id about to be signalled,
		 * and reaping it first would let the kernel recycle that number onto
		 * somebody else's group.
		 */
		if (waitid(P_PID, (id_t)child, &about, WEXITED | WNOWAIT | WNOHANG) == 0 &&
		    about.si_pid == child) {
			break;
		}
		{
			struct timespec rest;

			rest.tv_sec = 0;
			rest.tv_nsec = (long)POLL_MILLISECONDS * 1000000L;
			(void)nanosleep(&rest, NULL);
		}
		waited += POLL_MILLISECONDS;
	}
	(void)ncfg_process_kill_group(child, ignored, sizeof(ignored));
	while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {
		continue;
	}
}

void ncfg_portal_probe(const char *helper_program, const char *url, int expect,
    ncfg_portal_result_t *out)
{
	char      said[NCFG_ERROR_MAX];
	int       channel[2];
	pid_t     child;
	int       exec_errno = 0;
	int       status = 0;
	size_t    filled = 0u;
	long long deadline;
	int       finished = 0;

	if (!out) {
		return;
	}
	if (!helper_program || helper_program[0] == '\0' || !url || url[0] == '\0') {
		say(out, NCFG_PORTAL_VERDICT_UNREACHABLE,
		    "a portal check needs a URL and a helper to fetch it with, and this one "
		    "was given neither");
		return;
	}
	if (pipe(channel) != 0) {
		say(out, NCFG_PORTAL_VERDICT_UNREACHABLE, "could not start the probe helper: %s",
		    strerror(errno));
		return;
	}
	if (fcntl(channel[0], F_SETFD, FD_CLOEXEC) != 0) {
		say(out, NCFG_PORTAL_VERDICT_UNREACHABLE, "could not start the probe helper: %s",
		    strerror(errno));
		(void)close(channel[0]);
		(void)close(channel[1]);
		return;
	}

	child = spawn(helper_program, url, channel[1], &exec_errno);
	(void)close(channel[1]);
	if (child < 0) {
		(void)close(channel[0]);
		say(out, NCFG_PORTAL_VERDICT_UNREACHABLE, "could not start the probe helper: %s",
		    strerror(exec_errno ? exec_errno : ENOENT));
		return;
	}

	/*
	 * Read what it says, to end of file or to the deadline, whichever comes
	 * first. Bounded both ways: `said` is one sentence and anything past it is
	 * read and dropped, so a helper that will not stop talking cannot make
	 * this allocate, and the clock is watched in the same loop so it cannot
	 * make this wait either.
	 */
	said[0] = '\0';
	deadline = monotonic_milliseconds() + (NCFG_PORTAL_CHILD_SECONDS + 1) * 1000;
	for (;;) {
		struct pollfd watch;
		long long     left = deadline - monotonic_milliseconds();
		int           ready;

		if (left <= 0) {
			break;
		}
		memset(&watch, 0, sizeof(watch));
		watch.fd = channel[0];
		watch.events = POLLIN;
		ready = poll(&watch, 1u, left > 1000 ? 1000 : (int)left);
		if (ready < 0) {
			if (errno == EINTR) {
				continue;
			}
			break;
		}
		if (ready == 1) {
			char    chunk[256];
			ssize_t got = read(channel[0], chunk, sizeof(chunk));

			if (got < 0 && errno == EINTR) {
				continue;
			}
			if (got <= 0) {
				finished = 1;
				break;
			}
			if (filled + 1u < sizeof(said)) {
				size_t room = sizeof(said) - 1u - filled;
				size_t take = (size_t)got < room ? (size_t)got : room;

				memcpy(said + filled, chunk, take);
				filled += take;
				said[filled] = '\0';
			}
		}
	}
	(void)close(channel[0]);
	trim_end(said);

	if (!finished) {
		end_it(child);
		say(out, NCFG_PORTAL_VERDICT_UNREACHABLE, "the probe of %s did not finish", url);
		return;
	}
	while (waitpid(child, &status, 0) < 0 && errno == EINTR) {
		continue;
	}
	if (!WIFEXITED(status)) {
		/* Killed, which on this path means its own alarm. */
		say(out, NCFG_PORTAL_VERDICT_UNREACHABLE, "the probe of %s did not finish", url);
		return;
	}
	switch (WEXITSTATUS(status)) {
	case 0:
		ncfg_portal_verdict(said, expect, out);
		return;
	case 1:
		say(out, NCFG_PORTAL_VERDICT_UNREACHABLE, "%s", said);
		return;
	case 2:
		/* The child refused to do the work because it could not give up what
		 * it holds. Reported as its own sentence: a probe that ran anyway
		 * would be the thing this exists to prevent, quietly. */
		say(out, NCFG_PORTAL_VERDICT_UNREACHABLE,
		    "the probe helper would not drop its privileges, so it did not run: %s", said);
		return;
	default:
		say(out, NCFG_PORTAL_VERDICT_UNREACHABLE, "the probe helper exited with %d",
		    WEXITSTATUS(status));
		return;
	}
}
