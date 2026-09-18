/*
 * daemon_test.c -- the control socket and the state behind it.
 *
 * NOTHING HERE GOES NEAR THE REAL DAEMON
 *   netcfgd is running on the machine this is built on and its socket is
 *   `/run/netcfgd/netcfgd.sock`. Every socket below is bound inside a
 *   directory this binary made with `mkdtemp` and removed at the end, every
 *   config and run directory is the same, and `ncfg_daemon_serve` has no
 *   default path at all -- which is the point of it having none.
 *
 * WHY THE REFUSALS ARE DRIVEN OVER THE REMOTE ARRIVAL
 *   Root satisfies every principal, deliberately: a policy that could lock
 *   root out would be unrecoverable. So a suite that may be run as root cannot
 *   produce a *local* tier refusal over a real socket at all, and one that
 *   tried would pass or fail depending on who ran it. A remote arrival
 *   consults no peer credentials by design (0128), so the refusal is the same
 *   sentence whoever runs this -- and driving it here doubles as the
 *   end-to-end half of "a wide-open local policy opens nothing remotely",
 *   which `authorize_test.c` proves about the function.
 *
 * WHERE THE SOCKETS GO, AND THE ONE WAY THAT FAILS
 *   `testdir.h` makes the directory under `$TMPDIR`, and a `sockaddr_un` holds
 *   107 bytes of path. A machine whose `TMPDIR` is very long -- a per-session
 *   scratch directory named after a job id is the way this shows up -- leaves
 *   no room for one, and every bind here is refused. That is the check doing
 *   its job rather than a defect, and the refusal says the length and the
 *   bound so the reader is not left guessing; running with `TMPDIR` unset, as
 *   `make test` does, puts them under `/tmp` and there is room.
 *
 *   `authorize_test.c` is where the tiers themselves are proved, against a
 *   fixture passwd and group file. This file is about the wiring: that the
 *   gate is on the path a request actually takes, that a refusal comes back as
 *   an answer rather than a dropped connection, and that the framing, the cap
 *   and the socket's mode behave.
 */
#include "ncfg/base.h"
#include "ncfg/daemon.h"

#include "testdir.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
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

/* A tenth of a second, for the two places below that must wait for something
 * another thread does. Never a busy loop: a spin on a machine with one core
 * would starve the very thread it is waiting for. */
static void pause_briefly(void)
{
	struct timespec moment;

	moment.tv_sec = 0;
	moment.tv_nsec = 10L * 1000L * 1000L;
	(void)nanosleep(&moment, NULL);
}

/* ------------------------------------------------------------- the server */

/* What the answering seam was asked, so a test can assert the request reached
 * it rather than only that something came back. */
typedef struct {
	unsigned                  calls;
	ncfg_proto_request_kind_t last;
	uid_t                     last_uid;
} ncfg_test_answers_t;

static int answer_ok(void *context, const ncfg_proto_request_t *request,
    const ncfg_peer_t *peer, ncfg_arrival_t arrival, ncfg_buf_t *out, char *err, size_t err_size)
{
	ncfg_test_answers_t *seen = context;

	(void)arrival;
	if (seen) {
		seen->calls++;
		seen->last = request->kind;
		seen->last_uid = peer->uid;
	}
	return ncfg_daemon_ok_encode(out, err, err_size);
}

/* A seam that refuses, for the path where the daemon has no answer. */
static int answer_refusing(void *context, const ncfg_proto_request_t *request,
    const ncfg_peer_t *peer, ncfg_arrival_t arrival, ncfg_buf_t *out, char *err, size_t err_size)
{
	(void)context;
	(void)request;
	(void)peer;
	(void)arrival;
	(void)out;
	ncfg_error_set(err, err_size, "the machine is busy thinking");
	return 0;
}

static ncfg_control_t control_of(int observe, int wifi, int admin)
{
	ncfg_control_t control;

	memset(&control, 0, sizeof(control));
	control.observe.kind = observe;
	control.wifi.kind = wifi;
	control.admin.kind = admin;
	return control;
}

static int connect_to(const char *path)
{
	struct sockaddr_un address;
	int                at;

	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	(void)snprintf(address.sun_path, sizeof(address.sun_path), "%s", path);
	/* The listener is bound before `ncfg_daemon_serve` returns, so a
	 * connection cannot race the bind. Retried anyway on the accept backlog
	 * rather than assumed, since a refusal here would read as a cap failure. */
	for (at = 0; at < 200; at++) {
		int fd = socket(AF_UNIX, SOCK_STREAM, 0);

		if (fd < 0) {
			return -1;
		}
		if (connect(fd, (const struct sockaddr *)&address, (socklen_t)sizeof(address)) == 0) {
			return fd;
		}
		(void)close(fd);
		pause_briefly();
	}
	return -1;
}

static int send_text(int fd, const char *text)
{
	size_t length = strlen(text);
	size_t sent = 0;

	while (sent < length) {
		ssize_t put = send(fd, text + sent, length - sent, MSG_NOSIGNAL);

		if (put <= 0) {
			return 0;
		}
		sent += (size_t)put;
	}
	return 1;
}

/* One line, without its newline, or 0 where the peer closed first. */
static int read_line(int fd, char *out, size_t out_size)
{
	size_t at = 0;

	while (at + 1u < out_size) {
		char    one;
		ssize_t got = recv(fd, &one, 1u, 0);

		if (got <= 0) {
			break;
		}
		if (one == '\n') {
			out[at] = '\0';
			return 1;
		}
		out[at] = one;
		at++;
	}
	out[at] = '\0';
	return 0;
}

/*
 * One request over a real socket gets one answer.
 *
 * The point is not the answer -- it is that the bind, the accept, the
 * credentials, the framing, the gate and the seam are all on the path, which
 * nothing else asserts.
 */
static void a_connection_carries_a_request_and_its_answer(const char *base)
{
	ncfg_daemon_serve_t   how;
	ncfg_control_t        control = control_of(NCFG_PRINCIPAL_ANY, NCFG_PRINCIPAL_ANY,
	    NCFG_PRINCIPAL_ANY);
	ncfg_remote_policy_t  remote;
	ncfg_test_answers_t   seen = { 0 };
	ncfg_daemon_server_t *server;
	char                  path[512];
	char                  err[NCFG_ERROR_MAX];
	char                  line[1024];
	int                   fd;

	memset(&remote, 0, sizeof(remote));
	memset(&how, 0, sizeof(how));
	how.path = testdir_in(base, "round-trip.sock", path, sizeof(path));
	how.arrival = NCFG_ARRIVED_LOCAL;
	how.control = &control;
	how.remote = &remote;
	how.answer = answer_ok;
	how.context = &seen;
	server = ncfg_daemon_serve(&how, err, sizeof(err));
	check(server != NULL, "a socket in a directory of this test's own binds");
	if (!server) {
		detail("because", err);
		return;
	}
	fd = connect_to(path);
	check(fd >= 0, "and a client connects to it");
	if (fd < 0) {
		ncfg_daemon_server_stop(server);
		return;
	}
	check(send_text(fd, "{\"request\":\"status\"}\n"), "a request goes out");
	check(read_line(fd, line, sizeof(line)), "and an answer comes back");
	check(strcmp(line, "{\"response\":\"ok\"}") == 0, "which is the one the seam built");
	detail("answer", line);
	check(seen.calls == 1 && seen.last == NCFG_PROTO_REQ_STATUS,
	    "and the seam saw the request the client sent");
	check(seen.last_uid == getuid(), "with the peer credentials the kernel reported");

	/* Two requests in one write: a daemon that answered the first and dropped
	 * the tail would lose an answer somebody is waiting for, which is what the
	 * framer keeping its tail is for. */
	check(send_text(fd, "{\"request\":\"status\"}\n{\"request\":\"plan\"}\n"),
	    "two requests arrive in one write");
	check(read_line(fd, line, sizeof(line)) && read_line(fd, line, sizeof(line)),
	    "and both are answered");

	/* And one request split across two writes, which is the other half of the
	 * same property. */
	check(send_text(fd, "{\"request\":\"st"), "half a request arrives");
	check(send_text(fd, "atus\"}\n"), "and then the rest of it");
	check(read_line(fd, line, sizeof(line)) && strcmp(line, "{\"response\":\"ok\"}") == 0,
	    "and it is answered once, when it is whole");

	/*
	 * `hello` is answered by the server itself and never reaches the seam,
	 * because everything in it -- the two versions and the tiers this
	 * connection satisfies -- is the authorization module's. A seam computing
	 * the tier list would be a second implementation of "may I", which is
	 * what 0092 exists to prevent.
	 */
	seen.calls = 0;
	check(send_text(fd, "{\"request\":\"hello\"}\n"), "a hello goes out");
	check(read_line(fd, line, sizeof(line)), "and is answered");
	check(strstr(line, "\"response\":\"hello\"") != NULL &&
	        strstr(line, "\"tiers\":[\"observe\",\"wifi\",\"admin\"]") != NULL,
	    "with the tiers this connection satisfies");
	detail("hello", line);
	check(seen.calls == 0, "and the seam was never asked for it");

	(void)close(fd);
	ncfg_daemon_server_stop(server);
	check(!testdir_exists(path), "and stopping takes the socket file with it");
}

/*
 * A refusal is an answer, and it names the tier.
 *
 * Section 7: `{"response":"error"}` means the daemon replied, which is a
 * different thing from not reaching it, and only the caller knows whether that
 * is fatal. A daemon that dropped the connection instead would leave a client
 * unable to tell a refusal from a crash.
 */
static void a_refusal_arrives_as_an_answer_and_names_the_tier(const char *base)
{
	ncfg_daemon_serve_t   how;
	/* Wide open locally, which is the shape that makes the remote half worth
	 * asserting: nothing here got through on the local policy. */
	ncfg_control_t        control = control_of(NCFG_PRINCIPAL_ANY, NCFG_PRINCIPAL_ANY,
	    NCFG_PRINCIPAL_ANY);
	ncfg_remote_policy_t  remote;
	ncfg_test_answers_t   seen = { 0 };
	ncfg_daemon_server_t *server;
	char                  path[512];
	char                  err[NCFG_ERROR_MAX];
	char                  line[2048];
	int                   fd;

	memset(&remote, 0, sizeof(remote));
	/*
	 * `observe` and `admin` open, `wifi` shut. Two tiers rather than one
	 * because the two refusals below are different gates and each needs its
	 * own request: `wifi_scan` is stopped by the tier, and `config_put` gets
	 * through the tier and is stopped by what its text says. A policy that
	 * shut everything would refuse both at the first gate and the second
	 * would never be reached -- which is exactly the way this test could pass
	 * while proving nothing about the gate it is named for.
	 */
	remote.observe = 1;
	remote.admin = 1;
	memset(&how, 0, sizeof(how));
	how.path = testdir_in(base, "remote.sock", path, sizeof(path));
	how.arrival = NCFG_ARRIVED_REMOTE;
	how.control = &control;
	how.remote = &remote;
	how.answer = answer_ok;
	how.context = &seen;
	server = ncfg_daemon_serve(&how, err, sizeof(err));
	check(server != NULL, "a socket judged by the remote policy binds");
	if (!server) {
		detail("because", err);
		return;
	}
	fd = connect_to(path);
	if (fd < 0) {
		check(0, "a client connects to the remote socket");
		ncfg_daemon_server_stop(server);
		return;
	}
	check(send_text(fd, "{\"request\":\"wifi_scan\",\"interface\":\"wlan0\"}\n"),
	    "a request in a tier the remote policy does not open goes out");
	check(read_line(fd, line, sizeof(line)), "and something comes back");
	check(strstr(line, "\"response\":\"error\"") != NULL, "which is an error response");
	check(strstr(line, "`wifi` tier") != NULL, "naming the tier it would have needed");
	check(strstr(line, "off this machine") != NULL, "and saying it came from off the machine");
	detail("refusal", line);
	check(seen.calls == 0, "and the seam was never asked, so the gate is before it");

	/* The connection survives a refusal: a client refused one thing is
	 * entitled to ask for another. */
	check(send_text(fd, "{\"request\":\"status\"}\n"), "a permitted request follows it");
	check(read_line(fd, line, sizeof(line)) && strcmp(line, "{\"response\":\"ok\"}") == 0,
	    "and is answered on the same connection");
	check(seen.calls == 1, "and reached the seam");

	/*
	 * And the content gate is on the same path, which is the half that is
	 * invisible when it is missing: the request is inside a tier the policy
	 * opened, and what stops it is what the text says.
	 */
	check(send_text(fd, "{\"request\":\"config_put\",\"name\":\"from-a-client\",\"text\":"
	    "\"interface eth0 {\\n\\tpost_up {\\n\\t\\tid\\n\\t}\\n}\\n\",\"replace\":false}\n"),
	    "a config_put carrying a hook goes out");
	check(read_line(fd, line, sizeof(line)), "and is answered");
	check(strstr(line, "\"response\":\"error\"") != NULL &&
	        strstr(line, "root on this machine") != NULL,
	    "with the content gate's refusal, not the tier gate's");
	detail("refusal", line);

	(void)close(fd);
	ncfg_daemon_server_stop(server);
}

/* ---------------------------------------------------------------- monitor */

/*
 * One context for both seams, because `ncfg_daemon_serve_t` has one -- and
 * because what these checks are about is which of the two a request reached.
 */
typedef struct {
	unsigned answers;
	unsigned streams;
	/* What the stream seam was handed and now owns, or -1. */
	int      fd;
	int      refuse;
} ncfg_test_monitor_t;

static int monitor_answer(void *context, const ncfg_proto_request_t *request,
    const ncfg_peer_t *peer, ncfg_arrival_t arrival, ncfg_buf_t *out, char *err, size_t err_size)
{
	ncfg_test_monitor_t *seen = context;

	(void)request;
	(void)peer;
	(void)arrival;
	if (seen) {
		seen->answers++;
	}
	return ncfg_daemon_ok_encode(out, err, err_size);
}

static int monitor_stream(void *context, int fd, char *err, size_t err_size)
{
	ncfg_test_monitor_t *seen = context;

	if (!seen) {
		ncfg_error_set(err, err_size, "this fixture has nowhere to record it");
		return 0;
	}
	seen->streams++;
	if (seen->refuse) {
		ncfg_error_set(err, err_size, "this daemon is not taking subscriptions just now");
		return 0;
	}
	seen->fd = fd;
	return 1;
}

/*
 * A deadline on a client's reads, so that an answer which never comes is a
 * failed check rather than a suite that hangs.
 *
 * It is not decoration. A `monitor` handed over before the authorization gate
 * was asked leaves the seam holding the socket open, so the refusal the client
 * is waiting for never arrives and never will -- and without this the test
 * that is precisely about that ordering waits for ever instead of going red.
 * Generous, because everything here answers in microseconds.
 */
static void client_deadline(int fd)
{
	struct timeval deadline;

	deadline.tv_sec = 5;
	deadline.tv_usec = 0;
	(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &deadline, (socklen_t)sizeof(deadline));
}

/* How many descriptors this process holds. A hand-over that leaked one on the
 * refusal path is invisible to every other check here -- the client gets its
 * error, the connection goes on serving, and the daemon quietly runs out of
 * descriptors on the machine with a client that retries. */
static int descriptors_held(void)
{
	DIR           *open_dir = opendir("/proc/self/fd");
	struct dirent *entry;
	int            held = 0;

	if (!open_dir) {
		return -1;
	}
	while ((entry = readdir(open_dir)) != NULL) {
		if (entry->d_name[0] != '.') {
			held++;
		}
	}
	(void)closedir(open_dir);
	return held;
}

/* Bounded, because a hand-over that never happens must fail this rather than
 * hang the suite. */
static int wait_for_streams(const ncfg_test_monitor_t *seen, unsigned want)
{
	int at;

	for (at = 0; at < 500; at++) {
		if (seen->streams >= want) {
			return 1;
		}
		pause_briefly();
	}
	return 0;
}

static int wait_for_open(const ncfg_daemon_server_t *server, size_t want)
{
	int at;

	for (at = 0; at < 500; at++) {
		if (ncfg_daemon_server_open(server) == want) {
			return 1;
		}
		pause_briefly();
	}
	return 0;
}

/*
 * `monitor` hands the connection over, and the socket outlives the thread.
 *
 * **This is the wire, end to end on this side of it.** What makes it worth a
 * test of its own rather than a line in the round-trip check is the ownership:
 * the seam is given a `dup`, the connection thread then ends and closes its
 * own number, and the thing that must still work afterwards is the *socket* --
 * a client watching events for hours after the thread that accepted it
 * returned. An implementation that handed over the connection's own descriptor
 * would pass every check up to the last three here and then write one client's
 * events into whatever the number was reused for.
 */
static void a_monitor_hands_its_connection_over_and_the_socket_survives(const char *base)
{
	ncfg_daemon_serve_t   how;
	ncfg_control_t        control = control_of(NCFG_PRINCIPAL_ANY, NCFG_PRINCIPAL_ANY,
	    NCFG_PRINCIPAL_ANY);
	ncfg_remote_policy_t  remote;
	ncfg_test_monitor_t   seen;
	ncfg_daemon_server_t *server;
	char                  path[512];
	char                  err[NCFG_ERROR_MAX];
	char                  line[1024];
	int                   fd;

	memset(&remote, 0, sizeof(remote));
	memset(&seen, 0, sizeof(seen));
	seen.fd = -1;
	memset(&how, 0, sizeof(how));
	how.path = testdir_in(base, "monitor.sock", path, sizeof(path));
	how.arrival = NCFG_ARRIVED_LOCAL;
	how.control = &control;
	how.remote = &remote;
	how.answer = monitor_answer;
	how.stream = monitor_stream;
	how.context = &seen;
	server = ncfg_daemon_serve(&how, err, sizeof(err));
	check(server != NULL, "a socket that streams events binds");
	if (!server) {
		detail("because", err);
		return;
	}
	fd = connect_to(path);
	if (fd < 0) {
		check(0, "a client connects to it");
		ncfg_daemon_server_stop(server);
		return;
	}
	client_deadline(fd);
	check(send_text(fd, "{\"request\":\"monitor\"}\n"), "a monitor request goes out");
	check(wait_for_streams(&seen, 1u), "and the connection reaches the stream seam");
	check(seen.answers == 0,
	    "which is not the answer seam -- `monitor` is answered by the connection itself");
	check(seen.fd >= 0, "the seam is given a descriptor to keep");

	/*
	 * The slot goes back. A parked thread would hold one of
	 * `NCFG_DAEMON_MAX_CONNECTIONS` for as long as somebody is watching, and
	 * sixteen streams -- which is what the subscriber list carries -- would be
	 * sixteen slots held by threads with nothing left to read.
	 */
	check(wait_for_open(server, 0u),
	    "and the connection's slot is released rather than parked on for the life of "
	    "the stream");

	/*
	 * **And what the seam holds is still open, now that the connection thread
	 * has closed its own.** That is the whole of "a copy, not the connection's
	 * own number": handing over the descriptor itself would leave this one
	 * closed, and the number free for the next `accept` to hand to somebody
	 * else's client.
	 */
	check(seen.fd >= 0 && fcntl(seen.fd, F_GETFD) != -1,
	    "and it is a copy -- still open after the connection thread closed its own");

	/* The socket is still there, which is the whole point of the copy. */
	check(send_text(seen.fd, "{\"response\":\"event\",\"event\":\"observed\","
	    "\"summary\":\"two links moved\"}\n"),
	    "an event written to the handed-over descriptor goes out");
	check(read_line(fd, line, sizeof(line)) &&
	        strstr(line, "\"event\":\"observed\"") != NULL,
	    "and the client reads it, so the connection outlived the thread that took it");
	detail("event", line);

	/*
	 * And a client that hangs up is found by the write that fails -- which is
	 * the only reliable signal there is. End of stream on the *read* half says
	 * nothing: a client may `shutdown(SHUT_WR)` once it has asked and go on
	 * reading for hours.
	 */
	(void)close(fd);
	check(!send_text(seen.fd, "{\"response\":\"event\",\"event\":\"observed\","
	    "\"summary\":\"nobody is there\"}\n"),
	    "a subscriber that hung up refuses the next write, which is how it is dropped");
	(void)close(seen.fd);
	ncfg_daemon_server_stop(server);
}

/*
 * A refused hand-over keeps the connection and gives the descriptor back.
 *
 * Two things at once, and the second is the one nothing else would notice: the
 * copy the server made must be closed where the seam did not take it. A daemon
 * leaking one per refused `monitor` runs out of descriptors on exactly the
 * machine whose client retries.
 */
static void a_refused_monitor_keeps_the_connection_and_leaks_nothing(const char *base)
{
	ncfg_daemon_serve_t   how;
	ncfg_control_t        control = control_of(NCFG_PRINCIPAL_ANY, NCFG_PRINCIPAL_ANY,
	    NCFG_PRINCIPAL_ANY);
	ncfg_remote_policy_t  remote;
	ncfg_test_monitor_t   seen;
	ncfg_daemon_server_t *server;
	char                  path[512];
	char                  err[NCFG_ERROR_MAX];
	char                  line[1024];
	int                   before;
	int                   after;
	int                   fd;

	memset(&remote, 0, sizeof(remote));
	memset(&seen, 0, sizeof(seen));
	seen.fd = -1;
	seen.refuse = 1;
	memset(&how, 0, sizeof(how));
	how.path = testdir_in(base, "monitor-refused.sock", path, sizeof(path));
	how.arrival = NCFG_ARRIVED_LOCAL;
	how.control = &control;
	how.remote = &remote;
	how.answer = monitor_answer;
	how.stream = monitor_stream;
	how.context = &seen;
	server = ncfg_daemon_serve(&how, err, sizeof(err));
	if (!server) {
		check(0, "a socket whose stream seam refuses binds");
		detail("because", err);
		return;
	}
	fd = connect_to(path);
	if (fd < 0) {
		check(0, "a client connects to it");
		ncfg_daemon_server_stop(server);
		return;
	}
	client_deadline(fd);
	/* Taken with the connection already open, so what this measures is the
	 * hand-over and not the accept. */
	check(send_text(fd, "{\"request\":\"status\"}\n") &&
	        read_line(fd, line, sizeof(line)),
	    "a connection is open and answering before anything is counted");
	before = descriptors_held();
	check(send_text(fd, "{\"request\":\"monitor\"}\n"), "a monitor request goes out");
	check(read_line(fd, line, sizeof(line)), "and is answered rather than dropped");
	check(strstr(line, "\"response\":\"error\"") != NULL &&
	        strstr(line, "not taking subscriptions") != NULL,
	    "with the seam's own sentence");
	detail("refusal", line);
	after = descriptors_held();
	check(before > 0 && after == before,
	    "and the copy the server made is closed, so a refused monitor leaks nothing");
	if (after != before) {
		detail("descriptors before and after", "they differ");
	}

	check(send_text(fd, "{\"request\":\"status\"}\n"), "a request follows the refusal");
	check(read_line(fd, line, sizeof(line)) && strcmp(line, "{\"response\":\"ok\"}") == 0,
	    "and is answered on the same connection, a refusal being an answer");

	(void)close(fd);
	ncfg_daemon_server_stop(server);
}

/*
 * A daemon with no stream seam refuses `monitor` by name.
 *
 * The shape 0263 keeps refusing: accepting the request and streaming nothing
 * would leave a client watching a socket that can never say anything, which it
 * cannot tell from a machine where nothing is happening.
 */
static void a_daemon_that_streams_nothing_refuses_monitor_by_name(const char *base)
{
	ncfg_daemon_serve_t   how;
	ncfg_control_t        control = control_of(NCFG_PRINCIPAL_ANY, NCFG_PRINCIPAL_ANY,
	    NCFG_PRINCIPAL_ANY);
	ncfg_remote_policy_t  remote;
	ncfg_test_monitor_t   seen;
	ncfg_daemon_server_t *server;
	char                  path[512];
	char                  err[NCFG_ERROR_MAX];
	char                  line[1024];
	int                   fd;

	memset(&remote, 0, sizeof(remote));
	memset(&seen, 0, sizeof(seen));
	seen.fd = -1;
	memset(&how, 0, sizeof(how));
	how.path = testdir_in(base, "monitor-none.sock", path, sizeof(path));
	how.arrival = NCFG_ARRIVED_LOCAL;
	how.control = &control;
	how.remote = &remote;
	how.answer = monitor_answer;
	how.context = &seen;
	server = ncfg_daemon_serve(&how, err, sizeof(err));
	if (!server) {
		check(0, "a socket with no stream seam binds");
		detail("because", err);
		return;
	}
	fd = connect_to(path);
	if (fd < 0) {
		check(0, "a client connects to it");
		ncfg_daemon_server_stop(server);
		return;
	}
	client_deadline(fd);
	check(send_text(fd, "{\"request\":\"monitor\"}\n"), "a monitor request goes out");
	check(read_line(fd, line, sizeof(line)), "and is answered");
	check(strstr(line, "\"response\":\"error\"") != NULL &&
	        strstr(line, "does not stream events") != NULL,
	    "naming what is missing rather than leaving it to read as an unknown request");
	detail("refusal", line);
	check(seen.answers == 0 && seen.streams == 0,
	    "and neither seam was asked, there being nothing to ask");
	check(send_text(fd, "{\"request\":\"status\"}\n") &&
	        read_line(fd, line, sizeof(line)) &&
	        strcmp(line, "{\"response\":\"ok\"}") == 0,
	    "the connection goes on serving afterwards");

	(void)close(fd);
	ncfg_daemon_server_stop(server);
}

/*
 * A `monitor` beyond the tier never reaches the stream seam.
 *
 * The gate is before the hand-over, which is the ordering the whole thing
 * turns on: a connection given to the event stream before authorization was
 * asked is a subscription nobody checked, and `monitor` needs only `observe`
 * -- the tier `control { observe = "any" }` opens to every local user.
 *
 * Driven over the remote arrival for this file's stated reason: root satisfies
 * every local principal, so a suite that may be run as root cannot produce a
 * local tier refusal at all.
 */
static void a_monitor_beyond_the_tier_never_reaches_the_stream(const char *base)
{
	ncfg_daemon_serve_t   how;
	ncfg_control_t        control = control_of(NCFG_PRINCIPAL_ANY, NCFG_PRINCIPAL_ANY,
	    NCFG_PRINCIPAL_ANY);
	ncfg_remote_policy_t  remote;
	ncfg_test_monitor_t   seen;
	ncfg_daemon_server_t *server;
	char                  path[512];
	char                  err[NCFG_ERROR_MAX];
	char                  line[1024];
	int                   fd;

	/* Every tier shut remotely, and wide open locally -- which is what makes
	 * the refusal below about the remote policy rather than about nothing. */
	memset(&remote, 0, sizeof(remote));
	memset(&seen, 0, sizeof(seen));
	seen.fd = -1;
	memset(&how, 0, sizeof(how));
	how.path = testdir_in(base, "monitor-remote.sock", path, sizeof(path));
	how.arrival = NCFG_ARRIVED_REMOTE;
	how.control = &control;
	how.remote = &remote;
	how.answer = monitor_answer;
	how.stream = monitor_stream;
	how.context = &seen;
	server = ncfg_daemon_serve(&how, err, sizeof(err));
	if (!server) {
		check(0, "a socket judged by a shut remote policy binds");
		detail("because", err);
		return;
	}
	fd = connect_to(path);
	if (fd < 0) {
		check(0, "a client connects to it");
		ncfg_daemon_server_stop(server);
		return;
	}
	client_deadline(fd);
	check(send_text(fd, "{\"request\":\"monitor\"}\n"),
	    "a monitor request arrives from off the machine");
	check(read_line(fd, line, sizeof(line)) &&
	        strstr(line, "\"response\":\"error\"") != NULL,
	    "and is refused");
	detail("refusal", line);
	check(seen.streams == 0,
	    "the stream seam was never reached, so the gate is before the hand-over");
	check(seen.answers == 0, "and neither was the answer seam");

	(void)close(fd);
	ncfg_daemon_server_stop(server);
}

/*
 * A request the protocol does not define is refused and named.
 *
 * The strict direction, on the surface that reads untrusted bytes. The client
 * half stays lenient so an older client is not broken by a newer daemon's
 * response, and the asymmetry is between the two directions rather than
 * between an envelope and its payload.
 */
static void an_unknown_member_is_refused_and_named(const char *base)
{
	ncfg_daemon_serve_t   how;
	ncfg_control_t        control = control_of(NCFG_PRINCIPAL_ANY, NCFG_PRINCIPAL_ANY,
	    NCFG_PRINCIPAL_ANY);
	ncfg_remote_policy_t  remote;
	ncfg_daemon_server_t *server;
	char                  path[512];
	char                  err[NCFG_ERROR_MAX];
	char                  line[2048];
	int                   fd;

	memset(&remote, 0, sizeof(remote));
	memset(&how, 0, sizeof(how));
	how.path = testdir_in(base, "strict.sock", path, sizeof(path));
	how.arrival = NCFG_ARRIVED_LOCAL;
	how.control = &control;
	how.remote = &remote;
	how.answer = answer_ok;
	server = ncfg_daemon_serve(&how, err, sizeof(err));
	if (!server) {
		check(0, "a socket for the strict reader binds");
		return;
	}
	fd = connect_to(path);
	if (fd < 0) {
		check(0, "a client connects");
		ncfg_daemon_server_stop(server);
		return;
	}
	check(send_text(fd, "{\"request\":\"status\",\"bogus\":1}\n"), "a request with a member "
	    "the protocol does not define");
	check(read_line(fd, line, sizeof(line)), "is answered rather than ignored");
	check(strstr(line, "\"response\":\"error\"") != NULL && strstr(line, "bogus") != NULL,
	    "and the refusal names the member");
	detail("refusal", line);
	(void)close(fd);
	ncfg_daemon_server_stop(server);
}

/* A seam that cannot answer produces an error response rather than silence. */
static void a_seam_that_refuses_produces_an_answer(const char *base)
{
	ncfg_daemon_serve_t   how;
	ncfg_control_t        control = control_of(NCFG_PRINCIPAL_ANY, NCFG_PRINCIPAL_ANY,
	    NCFG_PRINCIPAL_ANY);
	ncfg_remote_policy_t  remote;
	ncfg_daemon_server_t *server;
	char                  path[512];
	char                  err[NCFG_ERROR_MAX];
	char                  line[1024];
	int                   fd;

	memset(&remote, 0, sizeof(remote));
	memset(&how, 0, sizeof(how));
	how.path = testdir_in(base, "refusing.sock", path, sizeof(path));
	how.arrival = NCFG_ARRIVED_LOCAL;
	how.control = &control;
	how.remote = &remote;
	how.answer = answer_refusing;
	server = ncfg_daemon_serve(&how, err, sizeof(err));
	if (!server) {
		check(0, "a socket for the refusing seam binds");
		return;
	}
	fd = connect_to(path);
	if (fd < 0) {
		check(0, "a client connects");
		ncfg_daemon_server_stop(server);
		return;
	}
	(void)send_text(fd, "{\"request\":\"status\"}\n");
	check(read_line(fd, line, sizeof(line)) &&
	        strstr(line, "the machine is busy thinking") != NULL,
	    "a seam that refuses answers with its own sentence");
	(void)close(fd);
	ncfg_daemon_server_stop(server);
}

/*
 * The connection past the cap is refused with an answer, and a released slot
 * comes back.
 *
 * The second half is the one worth having. A counter that only ever rose would
 * pass the first assertion and then refuse every connection once the daemon
 * had served `NCFG_DAEMON_MAX_CONNECTIONS` in total -- a worse failure than
 * the unbounded accept it replaced, and one no burst test would show.
 */
static void the_socket_refuses_past_the_cap_and_recovers(const char *base)
{
	ncfg_daemon_serve_t   how;
	ncfg_control_t        control = control_of(NCFG_PRINCIPAL_ANY, NCFG_PRINCIPAL_ANY,
	    NCFG_PRINCIPAL_ANY);
	ncfg_remote_policy_t  remote;
	ncfg_daemon_server_t *server;
	char                  path[512];
	char                  err[NCFG_ERROR_MAX];
	char                  line[1024];
	int                   held[NCFG_DAEMON_MAX_CONNECTIONS];
	int                   refused;
	int                   recovered = 0;
	int                   at;

	memset(&remote, 0, sizeof(remote));
	memset(&how, 0, sizeof(how));
	how.path = testdir_in(base, "cap.sock", path, sizeof(path));
	how.arrival = NCFG_ARRIVED_LOCAL;
	how.control = &control;
	how.remote = &remote;
	how.answer = answer_ok;
	server = ncfg_daemon_serve(&how, err, sizeof(err));
	if (!server) {
		check(0, "a socket for the cap binds");
		detail("because", err);
		return;
	}
	for (at = 0; at < NCFG_DAEMON_MAX_CONNECTIONS; at++) {
		held[at] = connect_to(path);
		/* Each connection must be *accepted*, not merely queued in the
		 * backlog, before the next is opened: the cap is counted at accept
		 * time, so a burst that sat in the backlog would measure the backlog
		 * rather than the cap. One round trip is what proves it was taken. */
		if (held[at] >= 0) {
			(void)send_text(held[at], "{\"request\":\"status\"}\n");
			(void)read_line(held[at], line, sizeof(line));
		}
	}
	check(ncfg_daemon_server_open(server) == (size_t)NCFG_DAEMON_MAX_CONNECTIONS,
	    "the cap's worth of connections are open at once");

	refused = connect_to(path);
	check(refused >= 0, "and the one past it still connects");
	check(read_line(refused, line, sizeof(line)), "and is told something");
	check(strstr(line, "too many connections") != NULL,
	    "which says why, rather than being a dropped connection");
	detail("refusal", line);
	(void)close(refused);

	for (at = 0; at < NCFG_DAEMON_MAX_CONNECTIONS; at++) {
		if (held[at] >= 0) {
			(void)close(held[at]);
		}
	}
	/*
	 * Retried rather than asserted once: closing a connection here does not
	 * release its slot, the handler thread waking on the end of stream does.
	 * That is genuinely asynchronous, and a single attempt would be a test
	 * that passes on a quiet machine and fails on a busy one.
	 */
	for (at = 0; at < 200 && !recovered; at++) {
		int fd = connect_to(path);

		if (fd >= 0 && send_text(fd, "{\"request\":\"status\"}\n") &&
		    read_line(fd, line, sizeof(line)) &&
		    strcmp(line, "{\"response\":\"ok\"}") == 0) {
			recovered = 1;
		}
		if (fd >= 0) {
			(void)close(fd);
		}
		if (!recovered) {
			pause_briefly();
		}
	}
	check(recovered, "and the daemon accepts again once connections close");
	ncfg_daemon_server_stop(server);
}

/*
 * **The remote socket's mode does not follow the local policy.**
 *
 * The defect this pins: passing the local `control` for both sockets made a
 * `control` block opening `observe` to `any` produce a world-writable
 * `remote.sock` -- and a remote connection consults no principal and no peer,
 * so the socket's mode was the only thing standing in front of the remote
 * tiers.
 *
 * The two sockets are checked in one test rather than two, because the
 * property is that they *differ*: a test asserting the remote mode alone would
 * still pass if the local one had been narrowed to match it, which is the
 * other way to make them agree and is a worse answer.
 */
static void a_wide_local_policy_leaves_the_remote_socket_shut(const char *base)
{
	ncfg_control_t        wide = control_of(NCFG_PRINCIPAL_ANY, NCFG_PRINCIPAL_ROOT,
	    NCFG_PRINCIPAL_ROOT);
	ncfg_remote_policy_t  closed;
	const ncfg_principal_t *local_reach[3];
	const ncfg_principal_t *remote_reach[1];
	ncfg_daemon_serve_t   how;
	ncfg_daemon_server_t *local_server;
	ncfg_daemon_server_t *remote_server;
	char                  local_path[512];
	char                  remote_path[512];
	char                  err[NCFG_ERROR_MAX];

	memset(&closed, 0, sizeof(closed));
	closed.agent.kind = NCFG_PRINCIPAL_ROOT;
	local_reach[0] = &wide.observe;
	local_reach[1] = &wide.wifi;
	local_reach[2] = &wide.admin;
	remote_reach[0] = &closed.agent;

	memset(&how, 0, sizeof(how));
	how.path = testdir_in(base, "mode-local.sock", local_path, sizeof(local_path));
	how.arrival = NCFG_ARRIVED_LOCAL;
	how.reach = local_reach;
	how.reach_count = 3;
	how.control = &wide;
	how.remote = &closed;
	how.answer = answer_ok;
	local_server = ncfg_daemon_serve(&how, err, sizeof(err));

	how.path = testdir_in(base, "mode-remote.sock", remote_path, sizeof(remote_path));
	how.arrival = NCFG_ARRIVED_REMOTE;
	how.reach = remote_reach;
	how.reach_count = 1;
	remote_server = ncfg_daemon_serve(&how, err, sizeof(err));

	check(local_server && remote_server, "both sockets bind");
	if (local_server && remote_server) {
		check(testdir_mode(local_path) == 0666, "the local policy said any, and means it");
		check(testdir_mode(remote_path) == 0600,
		    "and an unnamed agent leaves the remote socket to root, whatever local says");
		if (testdir_mode(remote_path) != 0600) {
			detail("remote mode", "not 0600");
		}
	}
	ncfg_daemon_server_stop(local_server);
	ncfg_daemon_server_stop(remote_server);
}

/*
 * A named agent opens the remote socket, which is what `agent` is for.
 *
 * Without this the test above is satisfied by a socket that is 0600
 * unconditionally, which would be safe and would have removed 0128's stated
 * mechanism rather than pointing it at the right policy.
 */
static void a_named_agent_opens_the_remote_socket(const char *base)
{
	ncfg_principal_t        agent;
	const ncfg_principal_t *reach[1];
	ncfg_control_t          control = control_of(NCFG_PRINCIPAL_ROOT, NCFG_PRINCIPAL_ROOT,
	    NCFG_PRINCIPAL_ROOT);
	ncfg_remote_policy_t    remote;
	ncfg_daemon_serve_t     how;
	ncfg_daemon_server_t   *server;
	char                    path[512];
	char                    err[NCFG_ERROR_MAX];
	static char             netcfgd[] = "netcfgd";

	agent.kind = NCFG_PRINCIPAL_GROUP;
	agent.name = netcfgd;
	reach[0] = &agent;
	memset(&remote, 0, sizeof(remote));
	remote.agent = agent;
	memset(&how, 0, sizeof(how));
	how.path = testdir_in(base, "agent.sock", path, sizeof(path));
	how.arrival = NCFG_ARRIVED_REMOTE;
	how.reach = reach;
	how.reach_count = 1;
	how.control = &control;
	how.remote = &remote;
	how.answer = answer_ok;
	/* A group file of this test's own, so nothing here asks the machine
	 * whether it happens to have a `netcfgd` group. */
	how.roots.group_file = "/nonexistent-group-file";
	how.roots.passwd_file = "/nonexistent-passwd-file";
	how.roots.proc_root = "/proc";
	server = ncfg_daemon_serve(&how, err, sizeof(err));
	check(server != NULL, "a socket for a named agent binds");
	if (server) {
		check(testdir_mode(path) == 0660, "a group-named agent reaches the socket");
	}
	ncfg_daemon_server_stop(server);
}

/* A path with no default, and one too long for a unix socket, are both
 * refused with a sentence rather than truncated into something else. */
static void a_socket_path_is_checked_rather_than_truncated(void)
{
	ncfg_control_t       control = control_of(NCFG_PRINCIPAL_ROOT, NCFG_PRINCIPAL_ROOT,
	    NCFG_PRINCIPAL_ROOT);
	ncfg_remote_policy_t remote;
	ncfg_daemon_serve_t  how;
	char                 err[NCFG_ERROR_MAX];
	char                 far_too_long[512];

	memset(&remote, 0, sizeof(remote));
	memset(&how, 0, sizeof(how));
	how.control = &control;
	how.remote = &remote;
	how.answer = answer_ok;
	how.path = NULL;
	check(ncfg_daemon_serve(&how, err, sizeof(err)) == NULL,
	    "a server with no path is refused");
	check(strstr(err, "no default") != NULL, "and says there is deliberately no default");
	memset(far_too_long, 'x', sizeof(far_too_long) - 1u);
	far_too_long[0] = '/';
	far_too_long[sizeof(far_too_long) - 1u] = '\0';
	how.path = far_too_long;
	check(ncfg_daemon_serve(&how, err, sizeof(err)) == NULL,
	    "and a path longer than a unix socket takes is refused");
	check(strstr(err, "silently shortened") != NULL,
	    "rather than truncated into a different path");
	detail("refusal", err);
}

/* --------------------------------------------------------------- the state */

static const char *const ORDINARY_CONFIG = "interface eth0 {\n\tconfig = \"dhcp\"\n}\n";

static void write_config(const char *config_dir, const char *text)
{
	char path[640];

	(void)snprintf(path, sizeof(path), "%s/netcfgd.conf", config_dir);
	if (!testdir_write(path, text, strlen(text))) {
		check(0, "a configuration fixture is written");
	}
}

/* An observation built from JSON rather than by hand, so the fixture is
 * checked by the same strict reader the daemon uses. */
static int observe_links(void *context, const ncfg_document_t *desired, ncfg_observed_t **out,
    char *err, size_t err_size)
{
	const char *const *text = context;

	(void)desired;
	if (!*text) {
		ncfg_error_set(err, err_size, "the kernel could not be read");
		return 0;
	}
	*out = ncfg_observed_read(*text, strlen(*text), err, err_size);
	return *out != NULL;
}

static void the_state_reloads_and_holds_what_compiled(const char *base)
{
	ncfg_daemon_state_t state;
	char                config_dir[512];
	char                run_dir[512];
	char                factory_dir[512];
	char                err[NCFG_ERROR_MAX];

	(void)testdir_in(base, "etc", config_dir, sizeof(config_dir));
	(void)testdir_in(base, "run", run_dir, sizeof(run_dir));
	(void)testdir_in(base, "factory-that-is-not-there", factory_dir, sizeof(factory_dir));
	(void)mkdir(config_dir, 0700);
	(void)mkdir(run_dir, 0700);
	write_config(config_dir, ORDINARY_CONFIG);

	check(ncfg_daemon_state_init(&state, factory_dir, config_dir, run_dir, err, sizeof(err)),
	    "a state over three directories of this test's own");
	check(ncfg_daemon_state_reload(&state, err, sizeof(err)), "reloads a configuration");
	if (!state.desired) {
		detail("because", err);
	}
	check(state.desired != NULL, "and holds what compiled");
	check(state.diagnostics == NULL, "with nothing to complain about");

	/*
	 * A configuration that does not compile keeps the previous document.
	 * Dropping it would mean a bad edit silently disarms drift detection,
	 * which is the moment it is most wanted.
	 */
	write_config(config_dir, "interface eth0 {\n\tconfig = \n");
	check(!ncfg_daemon_state_reload(&state, err, sizeof(err)),
	    "a configuration that does not compile is not adopted");
	check(state.desired != NULL, "and the previous one is kept");
	check(state.diagnostics != NULL, "with diagnostics saying why");
	detail("diagnostics", state.diagnostics);

	ncfg_daemon_state_free(&state);
	/* Freeing one twice, and one never filled in, is nothing. */
	ncfg_daemon_state_free(&state);
}

/*
 * A configuration a revert rejected is refused -- and the refusal lives in the
 * reload's own answer rather than in `diagnostics`.
 *
 * Reading `diagnostics` to answer a reload is wrong twice over: a rejected
 * configuration is refused without recording any, and where an earlier reload
 * failed to compile the field still holds *that* failure's text. One reload,
 * one answer.
 */
static void a_rejected_configuration_refuses_without_setting_diagnostics(const char *base)
{
	ncfg_daemon_state_t state;
	char                config_dir[512];
	char                run_dir[512];
	char                hash[NCFG_DAEMON_HASH_MAX];
	char                other[NCFG_DAEMON_HASH_MAX];
	char                err[NCFG_ERROR_MAX];

	(void)testdir_in(base, "rejected-etc", config_dir, sizeof(config_dir));
	(void)testdir_in(base, "rejected-run", run_dir, sizeof(run_dir));
	(void)mkdir(config_dir, 0700);
	(void)mkdir(run_dir, 0700);
	write_config(config_dir, ORDINARY_CONFIG);

	if (!ncfg_daemon_state_init(&state, "", config_dir, run_dir, err, sizeof(err)) ||
	    !ncfg_daemon_state_reload(&state, err, sizeof(err))) {
		check(0, "the rejected-configuration fixture compiles once");
		detail("because", err);
		ncfg_daemon_state_free(&state);
		return;
	}
	check(ncfg_daemon_document_hash(state.desired, hash, err, sizeof(err)),
	    "a document has a hash");
	check(strlen(hash) == 64u, "of sixty-four hex digits");
	state.rejected = strdup(hash);
	check(!ncfg_daemon_state_reload(&state, err, sizeof(err)),
	    "the same document a revert rejected is not adopted");
	check(strstr(err, "reverted away from") != NULL, "and the refusal says why");
	check(state.diagnostics == NULL,
	    "without recording diagnostics, which would be read as a compile failure");
	detail("refusal", err);

	/*
	 * And *fixing* the configuration clears it by itself, which is why this is
	 * a hash and not a flag: a different document is a different answer.
	 */
	write_config(config_dir, "interface eth0 {\n\tconfig = \"192.0.2.10/24\"\n}\n");
	check(ncfg_daemon_state_reload(&state, err, sizeof(err)),
	    "an edited configuration is adopted");
	check(state.rejected == NULL, "and the rejection clears itself");
	check(ncfg_daemon_document_hash(state.desired, other, err, sizeof(err)) &&
	        strcmp(other, hash) != 0,
	    "because a different document hashes differently");
	ncfg_daemon_state_free(&state);
}

/*
 * The observation arrives through a seam, and a kernel that cannot be read
 * keeps the last one.
 *
 * The seam is not a convenience: taking a snapshot is netlink, sysfs and
 * `/proc`, and a test that did it for real would be reading the developer's
 * own machine -- which is the one thing this suite must not do.
 */
static void the_observation_comes_through_a_seam(const char *base)
{
	static const char *const one_link =
	    "{\"links\":[{\"name\":\"eth0\",\"index\":1,\"kind\":\"\",\"up\":true,"
	    "\"carrier\":true,\"mtu\":1500}]}";
	static const char *const one_link_down =
	    "{\"links\":[{\"name\":\"eth0\",\"index\":1,\"kind\":\"\",\"up\":false,"
	    "\"carrier\":true,\"mtu\":1500}]}";
	static const char *const two_links =
	    "{\"links\":[{\"name\":\"eth0\",\"index\":1,\"kind\":\"\",\"up\":true,"
	    "\"carrier\":true,\"mtu\":1500},{\"name\":\"eth1\",\"index\":2,\"kind\":\"\","
	    "\"up\":true,\"carrier\":true,\"mtu\":1500}]}";
	ncfg_daemon_state_t state;
	const char         *text = one_link;
	char                config_dir[512];
	char                run_dir[512];
	char                err[NCFG_ERROR_MAX];
	int                 moved = 0;

	(void)testdir_in(base, "observe-etc", config_dir, sizeof(config_dir));
	(void)testdir_in(base, "observe-run", run_dir, sizeof(run_dir));
	(void)mkdir(config_dir, 0700);
	(void)mkdir(run_dir, 0700);
	write_config(config_dir, ORDINARY_CONFIG);
	check(ncfg_daemon_state_init(&state, "", config_dir, run_dir, err, sizeof(err)),
	    "a state to observe into");
	check(!ncfg_daemon_state_reobserve(&state, &moved, err, sizeof(err)),
	    "a daemon given no way to observe says so");
	check(strstr(err, "no way to observe") != NULL, "rather than reporting an empty machine");

	state.observe = observe_links;
	state.observe_context = &text;
	check(ncfg_daemon_state_reobserve(&state, &moved, err, sizeof(err)),
	    "the first observation arrives");
	check(moved == 1, "and the link set moved, because there was none before");
	check(state.observed && state.observed->link_count == 1, "with the link the seam gave");

	check(ncfg_daemon_state_reobserve(&state, &moved, err, sizeof(err)) && moved == 0,
	    "the same observation again is not movement");

	text = one_link_down;
	check(ncfg_daemon_state_reobserve(&state, &moved, err, sizeof(err)) && moved == 1,
	    "a link going down without leaving is movement");

	text = two_links;
	check(ncfg_daemon_state_reobserve(&state, &moved, err, sizeof(err)) && moved == 1,
	    "and so is a link appearing");
	check(state.observed->link_count == 2, "which is the observation now held");

	text = NULL;
	check(!ncfg_daemon_state_reobserve(&state, &moved, err, sizeof(err)),
	    "a kernel that cannot be read is reported");
	check(moved == 0, "as no movement");
	check(state.observed && state.observed->link_count == 2,
	    "and the last observation is kept rather than dropped");
	ncfg_daemon_state_free(&state);
}

/* --------------------------------------------------------- the three answers */

static void the_answers_this_module_writes_are_the_shapes_the_witness_pins(void)
{
	ncfg_buf_t  out;
	char        err[NCFG_ERROR_MAX];
	ncfg_tier_t tiers[2];

	ncfg_buf_init(&out, 0);
	check(ncfg_daemon_ok_encode(&out, err, sizeof(err)) &&
	        strcmp(ncfg_buf_text(&out), "{\"response\":\"ok\"}") == 0,
	    "`ok` is the shape the witness pins");
	ncfg_buf_free(&out);

	ncfg_buf_init(&out, 0);
	check(ncfg_daemon_error_encode("not permitted", &out, err, sizeof(err)) &&
	        strcmp(ncfg_buf_text(&out),
	            "{\"response\":\"error\",\"message\":\"not permitted\"}") == 0,
	    "and so is `error`");
	detail("error", ncfg_buf_text(&out));
	ncfg_buf_free(&out);

	tiers[0] = NCFG_TIER_OBSERVE;
	tiers[1] = NCFG_TIER_ADMIN;
	ncfg_buf_init(&out, 0);
	check(ncfg_daemon_hello_encode(tiers, 2u, &out, err, sizeof(err)) &&
	        strcmp(ncfg_buf_text(&out),
	            "{\"response\":\"hello\",\"protocol\":{\"major\":1,\"minor\":3},"
	            "\"schema\":{\"major\":1,\"minor\":1},\"tiers\":[\"observe\",\"admin\"]}") == 0,
	    "and so is `hello`, tiers and all");
	detail("hello", ncfg_buf_text(&out));
	ncfg_buf_free(&out);

	/* A connection that satisfies nothing is told an empty list rather than
	 * no list: section 10 item 10 says a client treats "could not tell" as
	 * permitted, so an omitted member would say the opposite of the truth. */
	ncfg_buf_init(&out, 0);
	check(ncfg_daemon_hello_encode(NULL, 0u, &out, err, sizeof(err)) &&
	        strstr(ncfg_buf_text(&out), "\"tiers\":[]") != NULL,
	    "and a connection that satisfies nothing is told an empty list, not no list");
	ncfg_buf_free(&out);
}

/* A message may not carry a raw newline: one that did would frame as two and
 * the peer would mis-parse both halves. */
static void a_message_may_not_carry_a_newline(void)
{
	ncfg_buf_t out;
	char       err[NCFG_ERROR_MAX];

	ncfg_buf_init(&out, 0);
	ncfg_buf_add_text(&out, "{\"response\":\"error\",\"message\":\"one\nnope\"}");
	check(!ncfg_daemon_line_write(-1, &out, err, sizeof(err)),
	    "a line carrying a raw newline is refused before it is sent");
	ncfg_buf_free(&out);
}

int main(void)
{
	const char *base = testdir_make("daemon");

	the_answers_this_module_writes_are_the_shapes_the_witness_pins();
	a_message_may_not_carry_a_newline();
	a_socket_path_is_checked_rather_than_truncated();

	a_connection_carries_a_request_and_its_answer(base);
	a_refusal_arrives_as_an_answer_and_names_the_tier(base);
	a_monitor_hands_its_connection_over_and_the_socket_survives(base);
	a_refused_monitor_keeps_the_connection_and_leaks_nothing(base);
	a_daemon_that_streams_nothing_refuses_monitor_by_name(base);
	a_monitor_beyond_the_tier_never_reaches_the_stream(base);
	an_unknown_member_is_refused_and_named(base);
	a_seam_that_refuses_produces_an_answer(base);
	the_socket_refuses_past_the_cap_and_recovers(base);
	a_wide_local_policy_leaves_the_remote_socket_shut(base);
	a_named_agent_opens_the_remote_socket(base);

	the_state_reloads_and_holds_what_compiled(base);
	a_rejected_configuration_refuses_without_setting_diagnostics(base);
	the_observation_comes_through_a_seam(base);

	testdir_remove(base);
	if (failures == 0) {
		printf("daemon_test: all checks passed\n");
	} else {
		printf("daemon_test: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
