/*
 * world_test.c -- the four seams a reconcile pass reaches the machine through.
 *
 * NOTHING HERE TOUCHES THE MACHINE THIS IS BUILT ON
 *   netcfgd runs on it, its wifi is real and its `/run/netcfgd/apply.lock` is
 *   the lock an operator's `ncfg apply` waits on. So: no netlink socket is
 *   opened, no executor is ever constructed, `/run` and `/proc` are directories
 *   this binary made, and the apply lock taken below is a file under them.
 *
 *   **`ncfg_main_world_executor_open` is deliberately never allowed to
 *   succeed.** Opening one opens a netlink socket and reconfigures the machine
 *   this process is running on, which `apply.h` says nothing under `tests/`
 *   may do. What is checked instead is everything up to that point: the lock
 *   it takes first, the refusal when somebody else holds it, and the fact that
 *   the two paths which have a choice about opening one do not.
 *
 * WHAT IS WORTH CHECKING HERE, WHICH IS NOT "IT WORKS"
 *     * that giving a contended radio back **asks who is contending before it
 *       opens an executor** -- the Rust does it the other way round, so every
 *       laptop with wifi takes the global apply lock every five seconds to
 *       find out there is nothing to do (project.md 10.169). The proof is a
 *       measurement rather than a reading: this test holds the apply lock, and
 *       a pass that tried to open an executor could not get it;
 *     * that an event is written the way `proto.h` reads one, decoded back by
 *       the client's own decoder rather than compared against a string;
 *     * that a subscriber which stopped reading is dropped rather than waited
 *       for, because the loop writes from the thread that reconciles;
 *     * and that a short write is a dropped subscriber and not a retry, since
 *       half a line on the wire makes the next event read as its tail.
 *
 *   The last of them is the wire rather than a piece of it: a real control
 *   socket in this test's own directory, a `monitor` from a real client, the
 *   mailbox carrying the descriptor across to the loop's thread, and an
 *   announcement coming back out on the client's socket. Every piece above can
 *   be correct while nothing is connected -- which is what this port had until
 *   the hand-over landed, a subscriber list that was always empty.
 */
#include "../src/main/loop_internal.h"

#include "ncfg/apply.h"
#include "ncfg/base.h"
#include "ncfg/daemon.h"
#include "ncfg/document.h"
#include "ncfg/lock.h"
#include "ncfg/log.h"
#include "ncfg/observed.h"
#include "ncfg/proto.h"

#include "testdir.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

static int failures;
static int checks;

static void check(int condition, const char *what)
{
	checks++;
	printf("%-72s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

static void detail(const char *label, const char *text)
{
	printf("       %s: %s\n", label, text ? text : "(none)");
}

static const char *base;

/* ------------------------------------------------------------------------ *
 * Fixtures
 * ------------------------------------------------------------------------ */

/*
 * A run directory and **nothing else**, which is what a test must point a
 * world at.
 *
 * Every other member of `ncfg_main_world_where_t` is somewhere the daemon
 * *writes*: `/proc`, the supplicant's control sockets, the machine's secrets.
 * Filling them in from `ncfg_service_machine` would let a case here change the
 * network of the workstation this suite is built on -- which is the reason
 * `service.h` gives for nothing in it having a default, and the reason the
 * cases below assert refusals by name rather than writes that worked.
 *
 * A static, so a caller may pass it straight into the call.
 */
static const ncfg_main_world_where_t *where_of(const char *run_dir)
{
	static ncfg_main_world_where_t where;

	memset(&where, 0, sizeof(where));
	where.run_dir = run_dir;
	return &where;
}

static ncfg_document_t *document_of(const char *body)
{
	char             text[4096];
	char             message[NCFG_ERROR_MAX];
	ncfg_document_t *document;

	(void)snprintf(text, sizeof(text),
	    "{\"schema_version\":{\"major\":1,\"minor\":1},\"globals\":{},\"networks\":[]%s%s}",
	    body && body[0] ? "," : "", body ? body : "");
	message[0] = '\0';
	document = ncfg_document_read(text, strlen(text), message, sizeof(message));
	if (!document) {
		detail("fixture document did not read", message);
	}
	return document;
}

static ncfg_observed_t *observed_of(const char *body)
{
	char             text[4096];
	char             message[NCFG_ERROR_MAX];
	ncfg_observed_t *observed;

	(void)snprintf(text, sizeof(text), "{%s}", body);
	message[0] = '\0';
	observed = ncfg_observed_read(text, strlen(text), message, sizeof(message));
	if (!observed) {
		detail("fixture observation did not read", message);
	}
	return observed;
}

/*
 * Everything this file made, so that it can take it back.
 *
 * `testdir_remove` unwinds three levels and the contention fixture is four --
 * `<base>/contend-run/NetworkManager/devices/3` -- so what this makes it
 * removes by the paths it recorded, deepest last in, first out. That is
 * `contention_test.c`'s arrangement and is here for the reason its comment
 * gives: vouch for the directory where you cannot vouch for the names, and the
 * names here are ones this file wrote down.
 */
#define MADE_MAX 64
static char   made_paths[MADE_MAX][512];
static size_t made_count;

static void record(const char *path)
{
	if (made_count >= (size_t)MADE_MAX) {
		check(0, "the fixture fits in what this file records");
		return;
	}
	(void)snprintf(made_paths[made_count], sizeof(made_paths[0]), "%s", path);
	made_count++;
}

/* A directory under the test's own, made as deep as it needs to be. */
static void make_dir(const char *path)
{
	char  work[512];
	char *at;

	(void)snprintf(work, sizeof(work), "%s", path);
	for (at = work + 1; *at; at++) {
		if (*at != '/') {
			continue;
		}
		*at = '\0';
		(void)mkdir(work, 0700);
		record(work);
		*at = '/';
	}
	(void)mkdir(work, 0700);
	record(work);
}

static void put_file(const char *path, const char *body)
{
	char  work[512];
	char *slash;

	(void)snprintf(work, sizeof(work), "%s", path);
	slash = strrchr(work, '/');
	if (slash) {
		*slash = '\0';
		make_dir(work);
	}
	if (!testdir_write(path, body, strlen(body))) {
		check(0, "a fixture file could be written");
		return;
	}
	record(path);
}

/* Back out, deepest first, each by the path that was recorded and nothing by a
 * pattern. Anything already gone is nothing. */
static void unmake_everything(void)
{
	size_t at;

	for (at = made_count; at > 0u; at--) {
		(void)unlink(made_paths[at - 1u]);
		(void)rmdir(made_paths[at - 1u]);
	}
	made_count = 0u;
}

/* ------------------------------------------------------------------------ *
 * An event, read back by the decoder a client uses
 * ------------------------------------------------------------------------ */

/*
 * The five kinds, encoded here and decoded by `proto.h`.
 *
 * Round-tripped rather than compared against a string on purpose: a literal
 * here would agree with this encoder for ever, including about a member name
 * the decoder refuses. The decoder is the client's half, so a member spelled
 * differently at either end is a monitor stream nothing can read.
 */
static int decodes(const ncfg_proto_event_t *event, ncfg_proto_event_t *out, char *why,
    size_t why_size)
{
	ncfg_buf_t           line;
	ncfg_proto_message_t message;
	char                 err[NCFG_ERROR_MAX];
	int                  read;

	why[0] = '\0';
	ncfg_buf_init(&line, NCFG_PROTO_MAX_LINE);
	err[0] = '\0';
	if (!ncfg_main_event_encode(event, &line, err, sizeof(err))) {
		(void)snprintf(why, why_size, "%s", err);
		ncfg_buf_free(&line);
		return 0;
	}
	memset(&message, 0, sizeof(message));
	err[0] = '\0';
	read = ncfg_proto_response_read(ncfg_buf_text(&line), line.length, &message, err,
	    sizeof(err));
	if (!read) {
		(void)snprintf(why, why_size, "%s", err);
		ncfg_buf_free(&line);
		return 0;
	}
	*out = message.u.response.u.event;
	/* Copied out before the message is freed would dangle, so the caller is
	 * handed the tag and the numbers and asks about the text here. */
	if (message.u.response.kind != NCFG_PROTO_RESP_EVENT) {
		(void)snprintf(why, why_size, "the response was not an event");
		ncfg_proto_message_free(&message);
		ncfg_buf_free(&line);
		return 0;
	}
	*out = message.u.response.u.event;
	out->summary = ncfg_proto_str_present(out->summary) ? out->summary : ncfg_proto_str_none();
	(void)snprintf(why, why_size, "%.*s", (int)line.length, ncfg_buf_text(&line));
	ncfg_proto_message_free(&message);
	ncfg_buf_free(&line);
	return 1;
}

/* Whether the encoded line holds this text. The decoded strings point into a
 * message that has been freed, so what is asserted about text is asserted
 * against the line. */
static int line_holds(const char *line, const char *wanted)
{
	return strstr(line, wanted) != NULL;
}

static void an_event_is_written_the_way_a_client_reads_it(void)
{
	ncfg_proto_event_t event;
	ncfg_proto_event_t back;
	char               line[NCFG_LOG_MAX];
	ncfg_buf_t         buffer;
	char               err[NCFG_ERROR_MAX];

	memset(&event, 0, sizeof(event));
	event.kind = NCFG_PROTO_EVENT_OBSERVED;
	event.summary = ncfg_proto_str("eth0 up");
	check(decodes(&event, &back, line, sizeof(line)) &&
	    back.kind == NCFG_PROTO_EVENT_OBSERVED,
	    "an `observed` event decodes as one");
	check(line_holds(line, "\"response\":\"event\"") && line_holds(line, "\"event\":\"observed\"") &&
	    line_holds(line, "eth0 up"), "and carries the response tag, the kind and the summary");

	memset(&event, 0, sizeof(event));
	event.kind = NCFG_PROTO_EVENT_RELOADED;
	event.ok = 0;
	event.diagnostics = ncfg_proto_str("line 3: no such key");
	check(decodes(&event, &back, line, sizeof(line)) && back.ok == 0,
	    "a `reloaded` event that did not compile decodes as one");
	check(line_holds(line, "no such key"), "and carries the diagnostics");

	memset(&event, 0, sizeof(event));
	event.kind = NCFG_PROTO_EVENT_RELOADED;
	event.ok = 1;
	check(decodes(&event, &back, line, sizeof(line)) && back.ok == 1,
	    "and one that compiled decodes as one too");
	/* Omitted rather than empty: the decoder reads an absent `diagnostics` as
	 * absent, and an empty string would say the compiler had something to
	 * report and nothing to say. */
	check(!line_holds(line, "diagnostics"),
	    "with no diagnostics member at all, which is not the same as an empty one");

	memset(&event, 0, sizeof(event));
	event.kind = NCFG_PROTO_EVENT_DRIFT;
	event.interface = ncfg_proto_str("wlan0");
	event.summary = ncfg_proto_str("the address is not there");
	event.action = ncfg_proto_str("addr.add");
	check(decodes(&event, &back, line, sizeof(line)) && back.kind == NCFG_PROTO_EVENT_DRIFT,
	    "a `drift` event decodes as one");
	check(line_holds(line, "wlan0") && line_holds(line, "addr.add"),
	    "and carries the interface and the action, which is what a script acts on");

	memset(&event, 0, sizeof(event));
	event.kind = NCFG_PROTO_EVENT_CONFIRM_ARMED;
	event.seconds = 90;
	check(decodes(&event, &back, line, sizeof(line)) && back.seconds == 90,
	    "a `confirm_armed` event carries its window");

	memset(&event, 0, sizeof(event));
	event.kind = NCFG_PROTO_EVENT_CONFIRM_RESOLVED;
	event.confirmed = 1;
	check(decodes(&event, &back, line, sizeof(line)) && back.confirmed == 1,
	    "and a `confirm_resolved` event says which way it went");

	/*
	 * A kind outside the enum is refused rather than written with a null tag.
	 * `daemon.h`'s `NCFG_PROTO_EVENT_COUNT` is the bound every walk uses in
	 * place of the `match` the Rust is checked for, and an event written past
	 * it would put a line on every monitor stream that no client can decode.
	 */
	memset(&event, 0, sizeof(event));
	event.kind = (ncfg_proto_event_kind_t)NCFG_PROTO_EVENT_COUNT;
	ncfg_buf_init(&buffer, NCFG_PROTO_MAX_LINE);
	err[0] = '\0';
	check(!ncfg_main_event_encode(&event, &buffer, err, sizeof(err)),
	    "an event kind outside the enum is refused rather than written");
	check(strstr(err, "no event spelled") != NULL, "and says so rather than failing quietly");
	ncfg_buf_free(&buffer);
}

/* ------------------------------------------------------------------------ *
 * The subscribers
 * ------------------------------------------------------------------------ */

/* One end of a socket pair for a subscriber, with the other for this test. */
static int pair_for(ncfg_main_subscribers_t *subscribers, int *mine)
{
	int  ends[2];
	char err[NCFG_ERROR_MAX];

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, ends) != 0) {
		check(0, "a socket pair could be made");
		return 0;
	}
	*mine = ends[0];
	err[0] = '\0';
	if (!ncfg_main_subscribers_add(subscribers, ends[1], err, sizeof(err))) {
		detail("the subscriber was not taken", err);
		(void)close(ends[0]);
		(void)close(ends[1]);
		return 0;
	}
	return 1;
}

static void told(ncfg_main_subscribers_t *subscribers, const char *summary)
{
	ncfg_proto_event_t event;

	memset(&event, 0, sizeof(event));
	event.kind = NCFG_PROTO_EVENT_OBSERVED;
	event.summary = ncfg_proto_str(summary);
	ncfg_main_subscribers_tell(subscribers, &event);
}

static void everyone_listening_is_told_and_nobody_else_waits_for_them(void)
{
	ncfg_main_subscribers_t subscribers;
	char                    buffer[512];
	ssize_t                 got;
	int                     first = -1;
	int                     second = -1;

	ncfg_main_subscribers_init(&subscribers);
	if (!pair_for(&subscribers, &first) || !pair_for(&subscribers, &second)) {
		return;
	}
	check(subscribers.count == 2u, "two subscribers are two subscribers");

	told(&subscribers, "eth0 up");
	got = recv(first, buffer, sizeof(buffer) - 1u, MSG_DONTWAIT);
	buffer[got > 0 ? (size_t)got : 0u] = '\0';
	check(got > 0 && strstr(buffer, "eth0 up") != NULL, "each of them gets the event");
	check(buffer[(size_t)(got > 0 ? got - 1 : 0)] == '\n',
	    "framed with the newline the protocol reads a message by");
	got = recv(second, buffer, sizeof(buffer) - 1u, MSG_DONTWAIT);
	check(got > 0, "and so does the other, from one encoding");

	/*
	 * A client that hung up. It is dropped as the event is written, which is
	 * the only pruning there is -- and is why the list is bounded rather than
	 * a vector that grows: a converged machine broadcasts nothing, so a
	 * subscriber that left is carried until something happens.
	 */
	(void)close(first);
	told(&subscribers, "eth0 down");
	check(subscribers.count == 1u, "a subscriber that hung up is dropped as an event is sent");
	check(subscribers.dropped == 1u, "and the drop is counted rather than silent");
	got = recv(second, buffer, sizeof(buffer) - 1u, MSG_DONTWAIT);
	check(got > 0, "and the one still there is told anyway");

	ncfg_main_subscribers_close(&subscribers);
	(void)close(second);
	check(subscribers.count == 0u, "closing the list leaves it empty and usable");
}

/*
 * A client that stopped reading must not stall the daemon.
 *
 * This is the property the non-blocking descriptor is for, and it is the one
 * that cannot be argued from the code: the write happens on the thread that
 * reconciles, so one blocking `send` to a full socket is a daemon that stops
 * correcting drift for as long as somebody feels like not reading. The test
 * fills the pipe by never reading and writing events until the buffer is gone.
 */
static void a_subscriber_that_stopped_reading_is_dropped_not_waited_for(void)
{
	ncfg_main_subscribers_t subscribers;
	unsigned                sent = 0;
	int                     mine = -1;

	ncfg_main_subscribers_init(&subscribers);
	if (!pair_for(&subscribers, &mine)) {
		return;
	}
	/* Bounded rather than `while`: if the drop never happened this would
	 * otherwise be the suite hanging, which is the slowest possible way for a
	 * test to be wrong. A socket buffer is a few hundred kilobytes and each
	 * event is tens of bytes, so ten thousand is comfortably past it. */
	while (subscribers.count > 0u && sent < 10000u) {
		told(&subscribers, "the operator is not reading this");
		sent++;
	}
	check(subscribers.count == 0u,
	    "a subscriber that stopped reading is dropped rather than waited for");
	check(subscribers.dropped == 1u, "and counted");
	ncfg_main_subscribers_close(&subscribers);
	(void)close(mine);
}

/*
 * A line that only half fitted is a dropped subscriber, not a retry.
 *
 * The other way for a write to come up short, and a different branch from the
 * one above: a full socket refuses the whole line, while a socket with a
 * little room left takes part of it. There is no recovering from the second --
 * what is on the wire is half a message, so the next event is read as its tail
 * and every one after that is one message out. A reader cannot tell that from
 * a daemon speaking a protocol it does not know.
 *
 * Driven with a send buffer squeezed down and an event far larger than it.
 */
static void a_line_that_only_half_fitted_drops_the_subscriber(void)
{
	ncfg_main_subscribers_t subscribers;
	ncfg_proto_event_t      event;
	char                   *big;
	int                     ends[2];
	int                     small = 2048;

	big = malloc(200000u);
	if (!big) {
		check(0, "the oversize event can be allocated");
		return;
	}
	memset(big, 'x', 199999u);
	big[199999] = '\0';

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, ends) != 0) {
		check(0, "a socket pair could be made");
		free(big);
		return;
	}
	/* Squeezed at both ends, so that the reader's window cannot swallow the
	 * line the sender could not finish. */
	(void)setsockopt(ends[1], SOL_SOCKET, SO_SNDBUF, &small, (socklen_t)sizeof(small));
	(void)setsockopt(ends[0], SOL_SOCKET, SO_RCVBUF, &small, (socklen_t)sizeof(small));
	ncfg_main_subscribers_init(&subscribers);
	{
		char err[NCFG_ERROR_MAX];

		err[0] = '\0';
		if (!ncfg_main_subscribers_add(&subscribers, ends[1], err, sizeof(err))) {
			check(0, "a subscriber could be taken");
			free(big);
			return;
		}
	}
	memset(&event, 0, sizeof(event));
	event.kind = NCFG_PROTO_EVENT_OBSERVED;
	event.summary = ncfg_proto_str(big);
	ncfg_main_subscribers_tell(&subscribers, &event);
	check(subscribers.count == 0u,
	    "an event too big for the room left is a dropped subscriber, not half a line");
	check(subscribers.dropped == 1u, "and that drop is counted like any other");
	ncfg_main_subscribers_close(&subscribers);
	(void)close(ends[0]);
	free(big);
}

static void the_list_is_bounded_and_says_so(void)
{
	ncfg_main_subscribers_t subscribers;
	int                     mine[NCFG_MAIN_SUBSCRIBERS_MAX + 1];
	int                     ends[2];
	char                    err[NCFG_ERROR_MAX];
	size_t                  at;

	ncfg_main_subscribers_init(&subscribers);
	for (at = 0; at < (size_t)NCFG_MAIN_SUBSCRIBERS_MAX; at++) {
		mine[at] = -1;
		if (!pair_for(&subscribers, &mine[at])) {
			return;
		}
	}
	check(subscribers.count == (size_t)NCFG_MAIN_SUBSCRIBERS_MAX,
	    "the list fills to its bound");
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, ends) != 0) {
		check(0, "a socket pair could be made");
		return;
	}
	err[0] = '\0';
	check(!ncfg_main_subscribers_add(&subscribers, ends[1], err, sizeof(err)),
	    "and one more is refused rather than dropping somebody");
	check(strstr(err, "which is all it carries") != NULL,
	    "with a sentence a client can be sent, since a refusal is an answer");
	/*
	 * **The refused descriptor is still the caller's.** A failed add that had
	 * closed it would leave the connection thread writing its refusal to a
	 * number it no longer holds -- and by then the kernel may have handed that
	 * number to something else.
	 */
	check(fcntl(ends[1], F_GETFD) != -1,
	    "and the descriptor it refused was not closed underneath the caller");
	(void)close(ends[0]);
	(void)close(ends[1]);

	ncfg_main_subscribers_close(&subscribers);
	for (at = 0; at < (size_t)NCFG_MAIN_SUBSCRIBERS_MAX; at++) {
		(void)close(mine[at]);
	}
}

/*
 * A stream whose client has gone is swept, on a machine that announces nothing.
 *
 * **This is the gap 0263 named and left open.** The only pruning there was
 * happened inside a broadcast, and a converged machine broadcasts nothing --
 * so a client that subscribed and hung up held one of sixteen places until
 * something happened, which on the machine that most needs those places is
 * never. Sixteen of them and the seventeenth `monitor` was refused over
 * streams nobody was reading.
 *
 * Driven without an event of any kind, which is the whole point: nothing below
 * writes a line, and the list still empties.
 */
static void a_stream_whose_client_has_gone_is_swept_without_an_event(void)
{
	ncfg_main_subscribers_t subscribers;
	char                    buffer[512];
	ssize_t                 got;
	int                     first = -1;
	int                     second = -1;
	int                     third = -1;

	ncfg_main_subscribers_init(&subscribers);
	if (!pair_for(&subscribers, &first) || !pair_for(&subscribers, &second) ||
	    !pair_for(&subscribers, &third)) {
		return;
	}
	check(ncfg_main_subscribers_prune(&subscribers) == 0u && subscribers.count == 3u,
	    "a sweep over three live streams drops none of them");

	(void)close(first);
	(void)close(third);
	check(ncfg_main_subscribers_prune(&subscribers) == 2u,
	    "the two whose client has gone are swept, with no event written anywhere");
	check(subscribers.count == 1u, "and the one still there keeps its place");
	check(subscribers.dropped == 2u,
	    "counted exactly as a failed write is, being the same thing to this list");

	/*
	 * The one kept is the one that was kept, not merely "one of them". A sweep
	 * that compacted wrongly would leave the right count over the wrong
	 * descriptor -- and the way that shows is a client being told somebody
	 * else's events, which is the failure the whole hand-over is shaped to
	 * avoid.
	 */
	told(&subscribers, "eth0 up");
	got = recv(second, buffer, sizeof(buffer) - 1u, MSG_DONTWAIT);
	buffer[got > 0 ? (size_t)got : 0u] = '\0';
	check(got > 0 && strstr(buffer, "eth0 up") != NULL,
	    "and it is the survivor that is still being written to");

	/*
	 * **A client that sent bytes down its stream is not a client that has
	 * gone**, and this is where the sweep's rule parts company with the source
	 * set's. `ncfg_main_readiness` reads `POLLIN` as "there is something to
	 * read" because somebody drains a source; nothing drains a subscriber, so
	 * a sweep that borrowed that reading would keep every hung-up descriptor
	 * (a close sets `POLLIN|POLLHUP`) and this one would be the only thing
	 * telling the two apart.
	 */
	(void)send(second, "hello?\n", 7u, 0);
	check(ncfg_main_subscribers_prune(&subscribers) == 0u && subscribers.count == 1u,
	    "a client that sends something rude down the stream is not one that has gone");

	ncfg_main_subscribers_close(&subscribers);
	(void)close(second);

	/* The empty list and the absent one, which is the seam's bargain: a run
	 * with no subscriber list sweeps nothing rather than refusing. */
	check(ncfg_main_subscribers_prune(&subscribers) == 0u, "sweeping an empty list is nothing");
	check(ncfg_main_subscribers_prune(NULL) == 0u, "and so is sweeping no list at all");
}

/*
 * What a `revents` means for a stream, as a value.
 *
 * Asserted here rather than only through a socket, because the case that
 * matters cannot be produced reliably on one: `POLLIN|POLLHUP` together is
 * what a client that wrote and then closed leaves behind, and getting a kernel
 * to hold both at the moment a test looks is a race. The decision is a
 * function taking a number, so it is checked as one.
 */
static void what_a_revents_means_for_a_stream(void)
{
	check(ncfg_main_subscriber_ended(POLLHUP), "a hang-up is a client that has gone");
	check(ncfg_main_subscriber_ended(POLLERR), "so is an error queued on the stream");
	check(ncfg_main_subscriber_ended(POLLNVAL), "and so is a descriptor this process lacks");
	check(ncfg_main_subscriber_ended((short)(POLLIN | POLLHUP)),
	    "and readable-and-hung-up is gone, which is where this differs from a source");
	check(ncfg_main_readiness((short)(POLLIN | POLLHUP)) == NCFG_MAIN_READY_DATA,
	    "  a source reads the same bits as data, because somebody drains a source");
	check(!ncfg_main_subscriber_ended(POLLIN),
	    "readable alone is a client talking, not a client leaving");
	check(!ncfg_main_subscriber_ended(0), "and nothing at all is nothing at all");
}

/* ------------------------------------------------------------------------ *
 * A `monitor`, all the way through
 * ------------------------------------------------------------------------ */

/* A client on a socket this test bound. Retried on the accept backlog rather
 * than assumed, the way `daemon_test.c` does it and for its reason: the
 * listener is up before `ncfg_daemon_serve` returns, so a refusal here would
 * read as something else entirely. */
static int connect_to(const char *path)
{
	struct sockaddr_un address;
	int                at;

	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	(void)snprintf(address.sun_path, sizeof(address.sun_path), "%s", path);
	for (at = 0; at < 200; at++) {
		int fd = socket(AF_UNIX, SOCK_STREAM, 0);

		if (fd < 0) {
			return -1;
		}
		if (connect(fd, (const struct sockaddr *)&address, (socklen_t)sizeof(address)) == 0) {
			return fd;
		}
		(void)close(fd);
		(void)poll(NULL, 0, 5);
	}
	return -1;
}

/* One line from a descriptor, without its newline, or 0. Bounded by the
 * buffer; nothing here sends a long line. */
static int line_from(int fd, char *out, size_t out_size)
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
 * A `monitor` becomes a subscriber, and an announcement reaches the client.
 *
 * **Every other check in this file drives one piece.** This one drives the
 * wire: a real unix socket, a real connection thread, the mailbox that carries
 * the descriptor across to the loop's thread, the desk that puts it in the
 * list, and an announcement that comes back out on the client's own socket.
 * Each piece can be correct while the wire is not connected -- which is what
 * this port had until now, a subscriber list that was always empty and a
 * `monitor` that refused by saying so.
 *
 * The test's own thread is the loop: it calls `ncfg_main_mailbox_settle`,
 * which is what a round does after its pass.
 */
static void a_monitor_becomes_a_subscriber_and_is_told(void)
{
	ncfg_main_subscribers_t subscribers;
	ncfg_main_desk_t        desk;
	ncfg_main_mailbox_t     mailbox;
	ncfg_daemon_serve_t     how;
	ncfg_control_t          control;
	ncfg_remote_policy_t    remote;
	ncfg_daemon_server_t   *server;
	/* Exactly what a unix socket path may be, which is also what keeps this
	 * from being a buffer the compiler cannot prove the copy below fits in. */
	char                    path[sizeof(((struct sockaddr_un *)0)->sun_path)];
	char                    err[NCFG_ERROR_MAX];
	char                    line[1024];
	struct timeval          deadline;
	int                     fd = -1;
	int                     at;

	ncfg_main_subscribers_init(&subscribers);
	memset(&desk, 0, sizeof(desk));
	desk.subscribers = &subscribers;
	err[0] = '\0';
	if (!ncfg_main_mailbox_open(&mailbox, ncfg_main_answer, ncfg_main_stream, &desk, -1, err,
	    sizeof(err))) {
		check(0, "a mailbox wired to the desk that holds the subscriber list");
		return;
	}

	memset(&control, 0, sizeof(control));
	control.observe.kind = NCFG_PRINCIPAL_ANY;
	control.wifi.kind = NCFG_PRINCIPAL_ANY;
	control.admin.kind = NCFG_PRINCIPAL_ANY;
	memset(&remote, 0, sizeof(remote));
	memset(&how, 0, sizeof(how));
	(void)snprintf(path, sizeof(path), "%s/monitor.sock", base);
	how.path = path;
	how.arrival = NCFG_ARRIVED_LOCAL;
	how.control = &control;
	how.remote = &remote;
	how.answer = ncfg_main_mailbox_answer;
	how.stream = ncfg_main_mailbox_stream;
	how.context = &mailbox;
	err[0] = '\0';
	server = ncfg_daemon_serve(&how, err, sizeof(err));
	if (!server) {
		check(0, "a control socket in this test's own directory");
		detail("because", err);
		ncfg_main_mailbox_close(&mailbox);
		return;
	}
	fd = connect_to(path);
	if (fd < 0) {
		check(0, "a client connects to it");
		ncfg_daemon_server_stop(server);
		ncfg_main_mailbox_close(&mailbox);
		return;
	}
	/* A deadline, so that an announcement which never arrives is a failed
	 * check rather than a suite that hangs on a socket nobody will write to. */
	deadline.tv_sec = 5;
	deadline.tv_usec = 0;
	(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &deadline, (socklen_t)sizeof(deadline));
	check(send(fd, "{\"request\":\"monitor\"}\n", 22u, MSG_NOSIGNAL) == 22,
	    "a client asks to watch");

	/* The loop's half, driven by hand. Bounded, so a hand-over that never
	 * happens fails this rather than hanging the suite. */
	for (at = 0; at < 2000 && subscribers.count == 0u; at++) {
		ncfg_main_mailbox_settle(&mailbox);
		if (subscribers.count == 0u) {
			(void)poll(NULL, 0, 1);
		}
	}
	check(subscribers.count == 1u,
	    "and the connection arrives in the subscriber list, which is the wire this "
	    "whole arrangement is");

	told(&subscribers, "two links moved");
	check(line_from(fd, line, sizeof(line)) &&
	        strstr(line, "\"event\":\"observed\"") != NULL &&
	        strstr(line, "two links moved") != NULL,
	    "an announcement reaches the client that asked for it");
	detail("event", line);

	/*
	 * And a client that goes away is dropped on the next announcement rather
	 * than written to for ever. This is the C half of the Rust's 10.169: there
	 * the list is a `Vec` with no bound, pruned only inside a broadcast, so a
	 * quiet machine accumulates them without limit. Here the pruning is the
	 * same and the list cannot grow past `NCFG_MAIN_SUBSCRIBERS_MAX`.
	 */
	(void)close(fd);
	told(&subscribers, "and now nobody is listening");
	check(subscribers.count == 0u && subscribers.dropped == 1u,
	    "a client that hung up is dropped as the next event is written, and counted");

	ncfg_main_mailbox_shut(&mailbox);
	ncfg_daemon_server_stop(server);
	ncfg_main_mailbox_close(&mailbox);
	ncfg_main_subscribers_close(&subscribers);
}

/* ------------------------------------------------------------------------ *
 * The world
 * ------------------------------------------------------------------------ */

static void the_seams_a_world_fills_in(void)
{
	ncfg_main_world_t      world;
	ncfg_reconcile_world_t seams;
	ncfg_daemon_state_t    state;
	char                   err[NCFG_ERROR_MAX];

	memset(&state, 0, sizeof(state));
	err[0] = '\0';
	check(ncfg_main_world_open(&world, where_of(base), &state, NULL, NULL, err, sizeof(err)),
	    "a world opens over a run directory");
	check(!ncfg_main_world_open(&world, NULL, &state, NULL, NULL, err, sizeof(err)),
	    "and one with nowhere to take the apply lock is refused");

	memset(&seams, 0, sizeof(seams));
	err[0] = '\0';
	(void)ncfg_main_world_open(&world, where_of(base), &state, NULL, NULL, err, sizeof(err));
	ncfg_main_world_seams(&world, &seams);
	check(seams.context == &world, "the context every seam shares is the world");
	check(seams.executor_open && seams.executor_close && seams.announce &&
	    seams.release_contended && seams.expiry,
	    "and the five this program implements are all installed");
	/*
	 * The three it does not fill are the library's own and the caller's to
	 * install. A world that filled them would be deciding what a daemon runs
	 * its hooks with, which is not its business -- and `daemon.h` says a
	 * missing seam costs exactly what it costs.
	 */
	check(seams.hook == NULL && seams.portal == NULL && seams.now == NULL,
	    "the three that belong to somebody else are left alone");

	/* Announcing with no list is nothing rather than a crash, which is the
	 * ordinary daemon with no monitor attached. */
	ncfg_main_world_announce(&world, NULL);
	ncfg_main_world_announce(NULL, NULL);
	ncfg_main_world_expiry(&world, 5u);
	check(1, "announcing to nobody and arming no timer are both nothing");

	ncfg_main_world_executor_close(&world, NULL);
	ncfg_main_world_close(&world);
	ncfg_main_world_close(NULL);
	check(1, "and closing one that never opened anything is nothing");
}

/*
 * The apply lock is taken before the socket, and a lock somebody else holds is
 * a refusal rather than a wait.
 *
 * This is as far into `executor_open` as a test may go: the next line opens a
 * netlink socket against the machine this is built on. What it proves is the
 * ordering -- the lock first -- because a socket opened before the lock would
 * mean this returned something other than a refusal naming the file.
 */
static void an_executor_takes_the_apply_lock_before_anything_else(void)
{
	ncfg_main_world_t   world;
	ncfg_daemon_state_t state;
	ncfg_lock_t         held;
	ncfg_executor_t     executor;
	char                run[256];
	char                path[512];
	char                err[NCFG_ERROR_MAX];

	(void)snprintf(run, sizeof(run), "%s/run-lock", base);
	make_dir(run);
	(void)snprintf(path, sizeof(path), "%s/apply.lock", run);
	record(path);
	ncfg_lock_init(&held);
	err[0] = '\0';
	if (!ncfg_lock_take(&held, path, err, sizeof(err))) {
		detail("the fixture lock was not taken", err);
		check(0, "this test can hold the apply lock itself");
		return;
	}

	memset(&state, 0, sizeof(state));
	err[0] = '\0';
	(void)ncfg_main_world_open(&world, where_of(run), &state, NULL, NULL, err, sizeof(err));
	/* Short, so that the refusal is a check rather than thirty seconds of the
	 * suite. The field exists for exactly this. */
	world.patience_ms = 50;
	memset(&executor, 0, sizeof(executor));
	err[0] = '\0';
	check(!ncfg_main_world_executor_open(&world, &executor, err, sizeof(err)),
	    "an executor cannot be opened while somebody else holds the apply lock");
	check(strstr(err, "apply.lock") != NULL, "and the refusal names the file to look at");
	check(executor.execute == NULL,
	    "and hands back nothing that could carry an action out");

	ncfg_main_world_close(&world);
	ncfg_lock_release(&held);
}

static void the_hooks_an_executor_is_given(void)
{
	ncfg_document_t *document = document_of(
	    "\"devices\":[],\"interfaces\":[{\"name\":\"eth0\",\"hooks\":["
	    "{\"phase\":\"post_up\",\"path\":\"/run/netcfgd/hooks/a\",\"sha256\":\"aa\"},"
	    "{\"phase\":\"pre_down\",\"path\":\"/run/netcfgd/hooks/b\",\"sha256\":\"bb\"}]},"
	    "{\"name\":\"eth1\"}]");
	ncfg_hook_ref_t  room[4];
	ncfg_hook_ref_t  one[1];
	size_t           missed = 99;
	size_t           taken;

	if (!document) {
		check(0, "the hook fixture reads");
		return;
	}
	taken = ncfg_main_hooks_of(document, room, sizeof(room) / sizeof(room[0]), &missed);
	check(taken == 2u && missed == 0u, "the hooks of every interface are collected");
	check(room[0].path && strcmp(room[0].path, "/run/netcfgd/hooks/a") == 0,
	    "in the order the document holds them");

	/*
	 * Past the bound they are counted rather than dropped in silence. A hook
	 * that did not fit is refused by `ncfg_hook_run` rather than run against
	 * whatever is on disk now, which is the safe direction -- and is also a
	 * hook that stops firing with nothing anywhere saying why.
	 */
	missed = 99;
	taken = ncfg_main_hooks_of(document, one, 1u, &missed);
	check(taken == 1u && missed == 1u, "one that does not fit is counted, not dropped quietly");

	check(ncfg_main_hooks_of(NULL, room, 4u, &missed) == 0u && missed == 0u,
	    "and a document that does not compile has no hooks rather than no answer");
	ncfg_document_free(document);
}

/* ------------------------------------------------------------------------ *
 * The half of an executor that is not netlink
 * ------------------------------------------------------------------------ */

/*
 * `ncfg_kernel_set_service` had no caller outside the tests, so fourteen of the
 * forty-eight ops refused on every apply -- `dns.apply`, the four sysctls, the
 * hostname, the six wifi ops and the three backend verbs. These cases are that
 * seam being wired, and the shape of every one of them is the same: the
 * refusal must stop naming *the missing context* and start naming the one
 * thing that is really missing.
 *
 * **Every path is the test's own, and none is filled in from a constant.**
 * `ncfg_main_world_where_t` says why at length; the short version is that this
 * suite is built on a workstation whose network is live, and `where_of` above
 * hands a world a run directory and nothing else precisely so that a case that
 * forgot to point somewhere safe refuses rather than writes.
 */

/* One op through an open executor, answering its refusal. `message` is the
 * caller's and is filled either way. */
static int execute_through(ncfg_main_world_t *world, const ncfg_op_t *op, char *message,
    size_t message_size)
{
	ncfg_executor_t executor;
	char            err[NCFG_ERROR_MAX];
	int             ran;

	memset(&executor, 0, sizeof(executor));
	err[0] = '\0';
	message[0] = '\0';
	if (!ncfg_main_world_executor_open(world, &executor, err, sizeof(err))) {
		/* The open's own sentence, unprefixed. `message_size` is the size an
		 * executor's refusal is written into, so anything added in front of
		 * one truncates the tail -- which is exactly where these sentences
		 * name the file or the root that was missing. */
		(void)snprintf(message, message_size, "%s", err);
		return 0;
	}
	ran = executor.execute && executor.execute(executor.state, op, message, message_size);
	ncfg_main_world_executor_close(world, &executor);
	return ran;
}

static void an_executor_now_carries_a_service_context(void)
{
	ncfg_main_world_t   world;
	ncfg_daemon_state_t state;
	ncfg_op_t           op;
	char                message[NCFG_ERROR_MAX];
	char                err[NCFG_ERROR_MAX];
	char                run[512];

	(void)snprintf(run, sizeof(run), "%s/service-context", base);
	testdir_mkdirp(run);
	memset(&state, 0, sizeof(state));
	state.desired = document_of("\"devices\":[],\"interfaces\":[{\"name\":\"eth0\"}]");
	err[0] = '\0';
	(void)ncfg_main_world_open(&world, where_of(run), &state, NULL, NULL, err, sizeof(err));

	memset(&op, 0, sizeof(op));
	op.kind = NCFG_OP_SYSCTL_SET_FORWARDING;
	op.u.forwarding.iface = "eth0";
	op.u.forwarding.enabled = 1;
	check(!execute_through(&world, &op, message, sizeof(message)),
	    "a sysctl still fails where this world was pointed at no proc root");
	/*
	 * The whole point of the wiring, and the reason this is checked by the
	 * words rather than by the return: before it, every one of these fourteen
	 * ops came back with "this executor was given no service context to do it
	 * with", which reads as *netcfgd cannot do this* when the truth is *this
	 * daemon was not told where*. One is a port that has not got there and the
	 * other is a path somebody has to fill in.
	 */
	check(strstr(message, "no service context") == NULL,
	    "and the refusal no longer says the executor was given no service context");
	check(strstr(message, "proc") != NULL || strstr(message, "root") != NULL,
	    "it names the root it was not given instead");
	ncfg_main_world_close(&world);
	ncfg_document_free(state.desired);
}

static void a_sysctl_is_written_where_the_world_was_pointed(void)
{
	ncfg_main_world_t       world;
	ncfg_main_world_where_t where;
	ncfg_daemon_state_t     state;
	ncfg_op_t               op;
	char                    message[NCFG_ERROR_MAX];
	char                    err[NCFG_ERROR_MAX];
	char                    run[512];
	char                    proc[512];
	char                    path[1024];
	char                   *held;

	(void)snprintf(run, sizeof(run), "%s/sysctl-run", base);
	testdir_mkdirp(run);
	(void)snprintf(proc, sizeof(proc), "%s/sysctl-proc", base);
	(void)snprintf(path, sizeof(path), "%s/sys/net/ipv4/conf/eth0", proc);
	testdir_mkdirp(path);
	(void)snprintf(path, sizeof(path), "%s/sys/net/ipv4/conf/eth0/forwarding", proc);
	(void)testdir_write(path, "0\n", 2u);
	(void)snprintf(path, sizeof(path), "%s/sys/net/ipv6/conf/eth0", proc);
	testdir_mkdirp(path);
	(void)snprintf(path, sizeof(path), "%s/sys/net/ipv6/conf/eth0/forwarding", proc);
	(void)testdir_write(path, "0\n", 2u);

	memset(&where, 0, sizeof(where));
	where.run_dir = run;
	where.proc_root = proc;
	memset(&state, 0, sizeof(state));
	state.desired = document_of("\"devices\":[],\"interfaces\":[{\"name\":\"eth0\"}]");
	err[0] = '\0';
	(void)ncfg_main_world_open(&world, &where, &state, NULL, NULL, err, sizeof(err));

	memset(&op, 0, sizeof(op));
	op.kind = NCFG_OP_SYSCTL_SET_FORWARDING;
	op.u.forwarding.iface = "eth0";
	op.u.forwarding.enabled = 1;
	if (!execute_through(&world, &op, message, sizeof(message))) {
		detail("the sysctl was refused", message);
		check(0, "a world given a proc root carries the sysctl out");
	} else {
		check(1, "a world given a proc root carries the sysctl out");
	}
	(void)snprintf(path, sizeof(path), "%s/sys/net/ipv4/conf/eth0/forwarding", proc);
	held = testdir_read(path, NULL);
	/*
	 * Read back off the tree rather than trusted from the return, and read at
	 * the path the *observer* uses -- `service.h` says that pairing is the
	 * only way "the write landed where the observation looks" is a checked
	 * property rather than two paths spelled twice.
	 */
	check(held && strcmp(held, "1") == 0, "  and the value is in the tree, where the observer reads");
	free(held);
	ncfg_main_world_close(&world);
	ncfg_document_free(state.desired);
}

static void the_service_carries_every_scope_and_not_the_one_the_op_names(void)
{
	ncfg_main_world_t   world;
	ncfg_daemon_state_t state;
	ncfg_executor_t     executor;
	char                err[NCFG_ERROR_MAX];
	char                run[512];

	(void)snprintf(run, sizeof(run), "%s/scopes-run", base);
	testdir_mkdirp(run);
	memset(&state, 0, sizeof(state));
	state.desired = document_of("\"devices\":[],\"interfaces\":["
	    "{\"name\":\"eth0\",\"dns\":{\"mode\":\"write_resolv_conf\","
	    "\"servers\":[{\"addr\":\"10.0.0.53\"}]}},"
	    "{\"name\":\"eth1\",\"dns\":{\"mode\":\"write_resolv_conf\","
	    "\"servers\":[{\"addr\":\"10.0.1.53\"}]}}]");
	err[0] = '\0';
	(void)ncfg_main_world_open(&world, where_of(run), &state, NULL, NULL, err, sizeof(err));
	memset(&executor, 0, sizeof(executor));
	check(ncfg_main_world_executor_open(&world, &executor, err, sizeof(err)),
	    "an executor opens over a document with two DNS scopes");
	/*
	 * A `dns.apply` names one scope and a delivery writes the resolver file
	 * whole, so a service holding only what the op carries would write a file
	 * with one interface's servers in it. That is the Rust's recorded defect;
	 * this is the daemon end of the same check `dns_scopes_test.c` makes at
	 * the rule.
	 */
	check(world.service.dns_scope_count == 2u,
	    "and it was given both of them, not the one a dns.apply would name");
	check(world.service.document == state.desired,
	    "and the document itself, for what an op names rather than carries");
	ncfg_main_world_executor_close(&world, &executor);
	check(world.service.dns_scope_count == 0u,
	    "closing it gives the scopes back, because the next document may not be this one");
	ncfg_main_world_close(&world);
	ncfg_document_free(state.desired);
}

static void the_route_metric_a_dhcp_client_is_started_with(void)
{
	ncfg_document_t             *document = document_of(
	    "\"devices\":[],\"interfaces\":["
	    "{\"name\":\"eth0\",\"preference\":100},"
	    "{\"name\":\"eth1\"},"
	    "{\"name\":\"wlan0\",\"preference\":600}]");
	ncfg_observed_t             *observed;
	ncfg_service_client_metric_t room[4];
	ncfg_service_client_metric_t one[1];
	size_t                       missed = 99;
	size_t                       taken;

	if (!document) {
		check(0, "the metric fixture reads");
		return;
	}
	/* `networks` is `document_of`'s empty list, so the association below finds
	 * no metric and the rule falls through to the preference. The case that
	 * needs a network carrying one is the second half. */
	observed = observed_of("\"links\":[]");
	taken = ncfg_main_metrics_of(document, observed, room,
	    sizeof(room) / sizeof(room[0]), &missed);
	check(taken == 2u && missed == 0u,
	    "an interface with a preference has a metric and one without has none");
	check(taken == 2u && strcmp(room[0].iface, "eth0") == 0 && room[0].metric.value == 100 &&
	    strcmp(room[1].iface, "wlan0") == 0 && room[1].metric.value == 600,
	    "  and each is the interface's own, in the document's order");
	/*
	 * Past the bound they are counted rather than dropped in silence -- the
	 * hooks' arrangement, and here it matters for the same reason: a client
	 * that did not fit starts with no `-m` and takes dhcpcd's default of 1003
	 * on a configuration that said 100, which is a route metric that quietly
	 * stopped being honoured.
	 */
	missed = 99;
	taken = ncfg_main_metrics_of(document, observed, one, 1u, &missed);
	check(taken == 1u && missed == 1u, "one that does not fit is counted, not dropped quietly");
	check(ncfg_main_metrics_of(NULL, observed, room, 4u, &missed) == 0u && missed == 0u,
	    "and a document that does not compile has no metrics rather than no answer");
	ncfg_observed_free(observed);
	ncfg_document_free(document);
}

static void an_associated_radio_takes_its_networks_metric(void)
{
	char             text[2048];
	char             message[NCFG_ERROR_MAX];
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_service_client_metric_t room[4];
	size_t                       taken;

	/*
	 * The half of `effective_metric` an executor cannot answer for itself: the
	 * radio's association is in the observation and the number is on the
	 * *network*, not on the interface. Measured on a veth with a real server,
	 * a client started from the document alone took dhcpcd's 1003 on a
	 * configuration whose network said 100.
	 */
	(void)snprintf(text, sizeof(text),
	    "{\"schema_version\":{\"major\":1,\"minor\":1},\"globals\":{},"
	    "\"networks\":[{\"id\":\"cafe\",\"security\":{\"type\":\"open\"},"
	    "\"metric\":100},"
	    "{\"id\":\"plain\",\"security\":{\"type\":\"open\"}}],"
	    "\"devices\":[],\"interfaces\":[{\"name\":\"wlan0\",\"preference\":600}]}");
	message[0] = '\0';
	document = ncfg_document_read(text, strlen(text), message, sizeof(message));
	if (!document) {
		detail("the association fixture did not read", message);
		check(0, "the association fixture reads");
		return;
	}
	observed = observed_of("\"links\":[{\"name\":\"wlan0\",\"index\":2,\"mtu\":1500,"
	    "\"up\":true,\"carrier\":true,\"ownership\":\"unknown\","
	    "\"network\":\"cafe\"}]");
	taken = ncfg_main_metrics_of(document, observed, room, 4u, NULL);
	check(taken == 1u && room[0].metric.value == 100,
	    "a radio associated to a network carrying a metric takes the network's");
	ncfg_observed_free(observed);

	/*
	 * **And a network with no metric of its own falls through to the
	 * preference rather than erasing it.** That is what `or` means in the
	 * rule, and getting it wrong drops an operator's number because they also
	 * named an SSID.
	 */
	observed = observed_of("\"links\":[{\"name\":\"wlan0\",\"index\":2,\"mtu\":1500,"
	    "\"up\":true,\"carrier\":true,\"ownership\":\"unknown\","
	    "\"network\":\"plain\"}]");
	taken = ncfg_main_metrics_of(document, observed, room, 4u, NULL);
	check(taken == 1u && room[0].metric.value == 600,
	    "and one associated to a network with no metric keeps the interface's preference");
	ncfg_observed_free(observed);
	ncfg_document_free(document);
}

/* ------------------------------------------------------------------------ *
 * What an interface advertises
 * ------------------------------------------------------------------------ */

/*
 * A delegation on `wan0`, which is where `lan0`'s `advertise` block points.
 * The reference's arithmetic is checked at the rule in `plan_addressing_test`;
 * what these cases are about is whether the daemon resolves the *same* thing
 * the planner does, and what it does when nothing resolves.
 */
#define WORLD_DELEGATION \
	"\"delegations\":[{\"interface\":\"wan0\",\"prefixes\":[\"2001:db8:0:100::/56\"]}]"

#define WORLD_ADVERTISING \
	"\"devices\":[{\"name\":\"lan0\",\"kind\":{\"kind\":\"physical\"}}]," \
	"\"interfaces\":[{\"name\":\"lan0\",\"addressing\":[]," \
	"\"dns\":{\"mode\":\"write_resolv_conf\",\"servers\":[" \
	"{\"addr\":\"2001:db8:0:101::1\"},{\"addr\":\"10.0.0.53\"}]}," \
	"\"advertise\":{\"backend\":\"radvd\"," \
	"\"prefixes\":[{\"source\":\"wan0\",\"index\":0,\"subnet\":1}]}}]"

static void what_an_interface_advertises_is_resolved_for_the_executor(void)
{
	ncfg_main_world_t   world;
	ncfg_daemon_state_t state;
	char                err[NCFG_ERROR_MAX];
	char                run[512];

	(void)snprintf(run, sizeof(run), "%s/advertise-run", base);
	testdir_mkdirp(run);
	memset(&state, 0, sizeof(state));
	state.desired = document_of(WORLD_ADVERTISING);
	state.observed = observed_of("\"links\":[]," WORLD_DELEGATION);
	err[0] = '\0';
	(void)ncfg_main_world_open(&world, where_of(run), &state, NULL, NULL, err, sizeof(err));
	world.advertise_count = ncfg_main_advertising_of(&world, state.desired, state.observed,
	    NULL);

	check(world.advertise_count == 1u, "an interface with an `advertise` block gets an entry");
	check(world.advertise_count == 1u && world.advertising[0].iface &&
	    strcmp(world.advertising[0].iface, "lan0") == 0 &&
	    world.advertising[0].policy == state.desired->interfaces[0].advertise,
	    "  naming the interface, with the document's own policy borrowed");
	/*
	 * Subnet 1 of `2001:db8:0:100::/56`, as the block rather than an address
	 * in it -- the same arithmetic the LAN's own address used with a host part
	 * instead. Checked by value here and not only by "something resolved",
	 * because the thing that goes wrong quietly is announcing the *wrong*
	 * prefix to every host on the wire, not announcing none.
	 */
	check(world.advertise_count == 1u && world.advertising[0].prefix_count == 1u &&
	    world.advertising[0].prefixes[0] &&
	    strcmp(world.advertising[0].prefixes[0], "2001:db8:0:101::/64") == 0,
	    "  and the prefix its reference resolves to, as a block and not a host");
	/*
	 * `RDNSS` carries IPv6, so the v4 server in the same block has nowhere to
	 * go here. It is not an error -- the resolver delivery uses it -- and the
	 * check is that it is dropped rather than rendered into a message that
	 * cannot hold it.
	 */
	check(world.advertise_count == 1u && world.advertising[0].server_count == 1u &&
	    world.advertising[0].servers[0] &&
	    strcmp(world.advertising[0].servers[0], "2001:db8:0:101::1") == 0,
	    "  and the IPv6 nameservers of its own dns block, for RDNSS, without the v4 one");
	ncfg_main_world_close(&world);
	ncfg_observed_free(state.observed);
	ncfg_document_free(state.desired);
}

static void a_delegation_that_has_not_arrived_advertises_nothing(void)
{
	ncfg_main_world_t   world;
	ncfg_daemon_state_t state;
	char                err[NCFG_ERROR_MAX];
	char                run[512];
	size_t              missed = 99;

	(void)snprintf(run, sizeof(run), "%s/advertise-waiting", base);
	testdir_mkdirp(run);
	memset(&state, 0, sizeof(state));
	state.desired = document_of(WORLD_ADVERTISING);
	/* The lease has not landed. On any machine with a DHCPv6 client this is
	 * the state between starting it and the prefix arriving. */
	state.observed = observed_of("\"links\":[]");
	err[0] = '\0';
	(void)ncfg_main_world_open(&world, where_of(run), &state, NULL, NULL, err, sizeof(err));
	world.advertise_count = ncfg_main_advertising_of(&world, state.desired, state.observed,
	    &missed);
	/*
	 * **No entry, rather than an entry with an empty list.** `ncfg_ra_start`
	 * refuses a router with no prefix, and a router advertising itself with no
	 * network on it is worse than one that has not started -- every host on
	 * the wire takes a default route to a machine that cannot forward for
	 * them. `backend.start` refuses by name instead.
	 */
	check(world.advertise_count == 0u,
	    "an interface whose delegation has not arrived gets no entry at all");
	/* And it is not counted as something that did not fit: nothing was
	 * dropped for want of room, so an error about capacity would send an
	 * operator looking at the wrong thing. */
	check(missed == 0u, "  and that is not reported as an overflow, which it is not");
	ncfg_main_world_close(&world);
	ncfg_observed_free(state.observed);
	ncfg_document_free(state.desired);
}

static void an_unmanaged_device_is_not_advertised_on(void)
{
	ncfg_main_world_t   world;
	ncfg_daemon_state_t state;
	char                err[NCFG_ERROR_MAX];
	char                run[512];

	(void)snprintf(run, sizeof(run), "%s/advertise-unmanaged", base);
	testdir_mkdirp(run);
	memset(&state, 0, sizeof(state));
	state.desired = document_of(
	    "\"devices\":[{\"name\":\"lan0\",\"kind\":{\"kind\":\"physical\"},"
	    "\"managed\":false}],"
	    "\"interfaces\":[{\"name\":\"lan0\",\"addressing\":[],"
	    "\"advertise\":{\"backend\":\"radvd\","
	    "\"prefixes\":[{\"source\":\"wan0\",\"index\":0,\"subnet\":1}]}}]");
	state.observed = observed_of("\"links\":[]," WORLD_DELEGATION);
	err[0] = '\0';
	(void)ncfg_main_world_open(&world, where_of(run), &state, NULL, NULL, err, sizeof(err));
	world.advertise_count = ncfg_main_advertising_of(&world, state.desired, state.observed,
	    NULL);
	/* The same question `ncfg_dns_scopes_of` asks, and for its reason: nothing
	 * between here and the executor asks whether netcfgd manages the
	 * interface a `backend.start` names. */
	check(world.advertise_count == 0u,
	    "an unmanaged device is not one netcfgd starts a router advertisement daemon on");
	ncfg_main_world_close(&world);
	ncfg_observed_free(state.observed);
	ncfg_document_free(state.desired);
}

static void the_planner_and_the_daemon_resolve_one_reference_the_same_way(void)
{
	ncfg_prefix_ref_t reference;
	ncfg_observed_t  *observed = observed_of("\"links\":[]," WORLD_DELEGATION);
	char              mine[NCFG_ADDRESS_MAX];
	char              theirs[NCFG_ADDRESS_MAX];

	memset(&reference, 0, sizeof(reference));
	reference.source = (char *)(uintptr_t)"wan0";
	reference.index = 0;
	reference.subnet = 1;
	/*
	 * **One function, asked twice** -- which is the whole of what lifting it
	 * into `observed.h` bought. Before, `plan/advertise.c` had a private
	 * `resolve` and this would have been a second copy; the one place two
	 * copies could disagree is what a router puts on the wire, and nothing
	 * downstream of that can notice.
	 */
	check(ncfg_observed_prefix_of(observed, &reference, mine, sizeof(mine)) &&
	    strcmp(mine, "2001:db8:0:101::/64") == 0,
	    "a reference resolves to the block its subnet selector names");
	reference.index = 7;
	check(!ncfg_observed_prefix_of(observed, &reference, theirs, sizeof(theirs)),
	    "and an index the lease does not carry resolves to nothing, not to something wrong");
	reference.index = 0;
	reference.source = (char *)(uintptr_t)"nosuch";
	check(!ncfg_observed_prefix_of(observed, &reference, theirs, sizeof(theirs)),
	    "and so does a source no delegation is held for");
	check(!ncfg_observed_prefix_of(NULL, &reference, theirs, sizeof(theirs)),
	    "and a machine nothing has observed resolves nothing rather than walking a NULL");
	ncfg_observed_free(observed);
}

/* ------------------------------------------------------------------------ *
 * What a tunnel is started with
 * ------------------------------------------------------------------------ */

#define WORLD_TUNNEL_SECRET "s3cret-canary"

/*
 * An openvpn device whose password is a `file` secret.
 *
 * `%s` is the secret's name, so a case can point at one that is there and one
 * that is not without a second fixture.
 */
#define WORLD_TUNNEL_FORMAT \
	"\"devices\":[{\"name\":\"vpn0\",\"kind\":{\"kind\":\"open_vpn\"," \
	"\"config\":\"/etc/netcfgd/work.ovpn\",\"username\":\"nabbe\"," \
	"\"password\":{\"provider\":\"file\",\"name\":\"%s\"}}}]," \
	"\"interfaces\":[{\"name\":\"vpn0\",\"addressing\":[]}]"

/* A world pointed at a secrets directory of this test's own making. */
static const ncfg_main_world_where_t *where_with_secrets(const char *run, const char *secrets)
{
	static ncfg_main_world_where_t where;

	memset(&where, 0, sizeof(where));
	where.run_dir = run;
	where.secrets_dir = secrets;
	return &where;
}

static ncfg_document_t *tunnel_document(const char *secret_name)
{
	char body[1024];

	(void)snprintf(body, sizeof(body), WORLD_TUNNEL_FORMAT, secret_name);
	return document_of(body);
}

static void a_tunnels_password_is_resolved_and_owned_by_the_world(void)
{
	ncfg_main_world_t   world;
	ncfg_daemon_state_t state;
	char                err[NCFG_ERROR_MAX];
	char                run[512];
	char                secrets[512];
	char                path[640];

	(void)snprintf(run, sizeof(run), "%s/tunnel-run", base);
	testdir_mkdirp(run);
	(void)snprintf(secrets, sizeof(secrets), "%s/tunnel-secrets", base);
	testdir_mkdirp(secrets);
	(void)snprintf(path, sizeof(path), "%s/work-vpn", secrets);
	(void)testdir_write(path, WORLD_TUNNEL_SECRET, strlen(WORLD_TUNNEL_SECRET));
	/* The `file` provider refuses anything anybody else can read, which is its
	 * whole point -- so the fixture has to be 0600 or this proves the refusal
	 * instead of the resolution. */
	(void)chmod(path, (mode_t)0600);

	memset(&state, 0, sizeof(state));
	state.desired = tunnel_document("work-vpn");
	err[0] = '\0';
	(void)ncfg_main_world_open(&world, where_with_secrets(run, secrets), &state, NULL, NULL,
	    err, sizeof(err));
	world.tunnel_count = ncfg_main_tunnels_of(&world, state.desired, NULL);

	check(world.tunnel_count == 1u, "an openvpn device gets a tunnel entry");
	check(world.tunnel_count == 1u && world.tunnels[0].iface &&
	    strcmp(world.tunnels[0].iface, "vpn0") == 0 && world.tunnels[0].config &&
	    strcmp(world.tunnels[0].config, "/etc/netcfgd/work.ovpn") == 0,
	    "  naming the interface and the `.ovpn` the document points at, unread");
	/*
	 * **The check that stops the rest of this being vacuous.** If the material
	 * never reached the struct, every assertion around it would pass while
	 * proving nothing -- which is `secrets_test.c`'s own sentence about its
	 * canary, and is the shape of empty gate `evidence.md` is about.
	 */
	check(world.tunnel_count == 1u && world.tunnels[0].password &&
	    strcmp(world.tunnels[0].password, WORLD_TUNNEL_SECRET) == 0,
	    "  and the password resolved out of the store, which is what makes this real");
	check(world.tunnel_count == 1u && world.tunnels[0].username &&
	    strcmp(world.tunnels[0].username, "nabbe") == 0,
	    "  with the username borrowed from the document beside it");
	/*
	 * The report file is `<run>/reported/<iface>` -- `state.h`'s path, which
	 * `ncfg_state_read_reports` is the other half of. A tunnel composing one
	 * for itself is a report written where nothing looks for it.
	 */
	(void)snprintf(path, sizeof(path), "%s/reported/vpn0", run);
	check(world.tunnel_count == 1u && world.tunnels[0].report &&
	    strcmp(world.tunnels[0].report, path) == 0,
	    "  and the file its `--route-up` reports into, where the reader looks");

	/*
	 * **Released with the service, and wiped.** `ncfg_secret_free` clears the
	 * bytes first, so an executor's close takes a credential out of this
	 * process' memory once per apply rather than leaving it resident for the
	 * life of the daemon. Checked by the count going to zero, because reading
	 * the buffer afterwards is reading freed memory -- which is what the
	 * sanitised build is for.
	 */
	ncfg_main_service_release(&world);
	check(world.tunnel_count == 0u, "and closing an executor gives the credentials back");
	ncfg_main_world_close(&world);
	ncfg_document_free(state.desired);
}

static void a_password_that_cannot_be_read_starts_no_tunnel(void)
{
	ncfg_main_world_t   world;
	ncfg_daemon_state_t state;
	char                err[NCFG_ERROR_MAX];
	char                run[512];
	char                secrets[512];

	(void)snprintf(run, sizeof(run), "%s/tunnel-missing", base);
	testdir_mkdirp(run);
	(void)snprintf(secrets, sizeof(secrets), "%s/tunnel-secrets", base);

	memset(&state, 0, sizeof(state));
	state.desired = tunnel_document("no-such-credential");
	err[0] = '\0';
	(void)ncfg_main_world_open(&world, where_with_secrets(run, secrets), &state, NULL, NULL,
	    err, sizeof(err));
	world.tunnel_count = ncfg_main_tunnels_of(&world, state.desired, NULL);
	/*
	 * **No entry, so `backend.start` refuses by name.** Starting openvpn
	 * without the credential its document names produces a daemon that
	 * authenticates, fails and retries -- which reads to an operator as a
	 * network problem rather than as a secret netcfgd could not read.
	 */
	check(world.tunnel_count == 0u,
	    "a tunnel whose password cannot be resolved gets no entry, so the start refuses");
	ncfg_main_world_close(&world);
	ncfg_document_free(state.desired);
}

static void a_tunnel_that_needs_no_password_still_starts(void)
{
	ncfg_main_world_t   world;
	ncfg_daemon_state_t state;
	char                err[NCFG_ERROR_MAX];
	char                run[512];

	(void)snprintf(run, sizeof(run), "%s/tunnel-open", base);
	testdir_mkdirp(run);
	memset(&state, 0, sizeof(state));
	/* Certificate-only authentication, which is the ordinary corporate
	 * arrangement: the `.ovpn` carries the material and there is no password
	 * to resolve. "Names none" and "names one that failed" must not be the
	 * same answer. */
	state.desired = document_of(
	    "\"devices\":[{\"name\":\"vpn0\",\"kind\":{\"kind\":\"open_vpn\","
	    "\"config\":\"/etc/netcfgd/certs.ovpn\"}}],"
	    "\"interfaces\":[{\"name\":\"vpn0\",\"addressing\":[]}]");
	err[0] = '\0';
	(void)ncfg_main_world_open(&world, where_of(run), &state, NULL, NULL, err, sizeof(err));
	world.tunnel_count = ncfg_main_tunnels_of(&world, state.desired, NULL);
	check(world.tunnel_count == 1u && world.tunnels[0].password == NULL,
	    "a tunnel that authenticates without a password gets an entry carrying none");
	ncfg_main_service_release(&world);
	ncfg_main_world_close(&world);
	ncfg_document_free(state.desired);
}

static void an_unmanaged_tunnel_is_not_netcfgds_to_start(void)
{
	ncfg_main_world_t   world;
	ncfg_daemon_state_t state;
	char                err[NCFG_ERROR_MAX];
	char                run[512];

	(void)snprintf(run, sizeof(run), "%s/tunnel-unmanaged", base);
	testdir_mkdirp(run);
	memset(&state, 0, sizeof(state));
	state.desired = document_of(
	    "\"devices\":[{\"name\":\"vpn0\",\"kind\":{\"kind\":\"open_vpn\","
	    "\"config\":\"/etc/netcfgd/work.ovpn\"},\"managed\":false}],"
	    "\"interfaces\":[{\"name\":\"vpn0\",\"addressing\":[]}]");
	err[0] = '\0';
	(void)ncfg_main_world_open(&world, where_of(run), &state, NULL, NULL, err, sizeof(err));
	world.tunnel_count = ncfg_main_tunnels_of(&world, state.desired, NULL);
	/* The third pass to ask this question, after the DNS scopes and the
	 * advertisements: `backend.start` names the interface and nothing between
	 * here and the executor asks whether netcfgd manages it. */
	check(world.tunnel_count == 0u,
	    "an unmanaged device is not one netcfgd starts a tunnel on");
	ncfg_main_world_close(&world);
	ncfg_document_free(state.desired);
}

/* ------------------------------------------------------------------------ *
 * Giving a contended radio back
 * ------------------------------------------------------------------------ */

/*
 * The whole of this is an ordering, and the ordering is measured.
 *
 * `release_contended` runs on every pass, on every machine netcfgd manages.
 * The Rust opens an executor -- which takes the apply lock and a netlink
 * socket -- as soon as netcfgd is running any backend at all, and only then
 * asks who is contending; on a laptop with wifi the answer is "nobody", five
 * seconds later it is "nobody" again, and in between an operator's `ncfg
 * apply` is waiting on that lock (0184, project.md 10.169).
 *
 * So the check is not that the code reads a certain way. This test **holds the
 * apply lock itself** and gives the world a patience of 50ms: a pass that
 * tried to open an executor could not, and would answer 0. Answering 1 with
 * the lock held is a measurement that nothing was opened.
 */
static void a_radio_is_not_given_back_by_taking_the_apply_lock_to_find_out(void)
{
	ncfg_main_world_t   world;
	ncfg_daemon_state_t state;
	ncfg_lock_t         held;
	char                run[256];
	char                run_root[256];
	char                proc_root[256];
	char                path[512];
	char                err[NCFG_ERROR_MAX];
	char                why[NCFG_ERROR_MAX];
	int                 stoppable;
	int                 answered;

	(void)snprintf(run, sizeof(run), "%s/run-contend", base);
	(void)snprintf(run_root, sizeof(run_root), "%s/contend-run", base);
	(void)snprintf(proc_root, sizeof(proc_root), "%s/contend-proc", base);
	make_dir(run);
	make_dir(run_root);
	make_dir(proc_root);
	(void)snprintf(path, sizeof(path), "%s/apply.lock", run);
	record(path);
	ncfg_lock_init(&held);
	err[0] = '\0';
	if (!ncfg_lock_take(&held, path, err, sizeof(err))) {
		check(0, "this test can hold the apply lock itself");
		return;
	}

	memset(&state, 0, sizeof(state));
	/* A machine netcfgd is running a supplicant on, which is the case the
	 * Rust opens an executor for. */
	state.desired = document_of("\"devices\":[],\"interfaces\":[{\"name\":\"wlan0\"}]");
	state.observed = observed_of(
	    "\"links\":[{\"name\":\"wlan0\",\"index\":3,\"mtu\":1500,\"up\":true,\"carrier\":true,\"ownership\":\"ours\"}],"
	    "\"backends\":[{\"kind\":\"supplicant\",\"interface\":\"wlan0\",\"running\":true}]");
	if (!state.desired || !state.observed) {
		check(0, "the contention fixture reads");
		ncfg_lock_release(&held);
		return;
	}
	err[0] = '\0';
	(void)ncfg_main_world_open(&world, where_of(run), &state, NULL, NULL, err, sizeof(err));
	world.patience_ms = 50;
	/* `/run` and `/proc` of this test's own, never the machine's. The struct
	 * is the argument for exactly this reason: a test that forgot an
	 * environment variable would read the developer's real `/run`, and one
	 * that forgets an argument does not compile. */
	world.contention.run_root = run_root;
	world.contention.proc_root = proc_root;
	world.contention.run_root_is_the_machines = 0;

	err[0] = '\0';
	answered = ncfg_main_world_release_contended(&world, &state, err, sizeof(err));
	check(answered, "a machine with nothing contending it is answered");
	check(!world.open,
	    "without taking the apply lock, which this test is holding and still holds");

	/*
	 * And now somebody does claim it. What happens next depends on whether
	 * this build's executor can carry out a `backend.stop` at all -- it
	 * refuses thirty-five of the forty-eight ops -- so the check moves with
	 * the build rather than pinning today's answer: where it cannot, nothing
	 * is opened and the operator is told; where it can, an executor is wanted
	 * and this test is holding the lock it needs.
	 */
	(void)snprintf(path, sizeof(path), "%s/NetworkManager/devices/3", run_root);
	put_file(path, "[device]\nmanaged=true\nconnection-uuid=abc\n");
	(void)snprintf(path, sizeof(path), "%s/900/comm", proc_root);
	put_file(path, "NetworkManager\n");

	why[0] = '\0';
	{
		ncfg_op_t op;

		memset(&op, 0, sizeof(op));
		op.kind = NCFG_OP_BACKEND_STOP;
		op.u.backend.iface = "";
		stoppable = ncfg_apply_supported(&op, why, sizeof(why));
	}
	err[0] = '\0';
	answered = ncfg_main_world_release_contended(&world, &state, err, sizeof(err));
	if (stoppable) {
		check(!answered,
		    "a contended radio wants an executor, and this test holds the lock");
		check(strstr(err, "apply.lock") != NULL, "and the refusal names the lock file");
	} else {
		check(answered,
		    "a contender netcfgd cannot hand a radio back to is reported, not locked "
		    "over");
		detail("this build's executor says", why);
	}
	check(!world.open, "and either way nothing was left holding an executor");

	ncfg_main_world_close(&world);
	ncfg_document_free(state.desired);
	ncfg_observed_free(state.observed);
	ncfg_lock_release(&held);
}

/*
 * Which interfaces a contention check is made about, and which are left out.
 *
 * Three rules in one answer, and each is a way of being wrong that costs
 * something different: an interface netcfgd runs nothing on is not netcfgd's
 * to fight over, an interface the kernel has no link for cannot be keyed by
 * index at all, and an index that does not fit **must not be truncated** --
 * 0263's narrowing rule pointed at a claim, because what netcfgd does about a
 * match is stop its own backend, and a truncated index matches an interface
 * nobody named.
 */
static void what_a_contention_check_is_made_about(void)
{
	ncfg_daemon_state_t    state;
	ncfg_interface_claim_t claims[4];
	size_t                 taken;

	memset(&state, 0, sizeof(state));
	state.desired = document_of("\"devices\":[],\"interfaces\":["
	    "{\"name\":\"wlan0\"},{\"name\":\"eth0\"},{\"name\":\"eth9\"}]");
	state.observed = observed_of(
	    "\"links\":[{\"name\":\"wlan0\",\"index\":3,\"mtu\":1500,\"up\":true,"
	    "\"carrier\":true,\"ownership\":\"ours\"},"
	    "{\"name\":\"eth0\",\"index\":2,\"mtu\":1500,\"up\":true,\"carrier\":true,"
	    "\"ownership\":\"ours\"}],"
	    "\"backends\":[{\"kind\":\"supplicant\",\"interface\":\"wlan0\","
	    "\"running\":true},"
	    "{\"kind\":\"dhcp4\",\"interface\":\"eth9\",\"running\":true}]");
	if (!state.desired || !state.observed) {
		check(0, "the claims fixture reads");
		return;
	}
	taken = ncfg_main_claims_of(&state, claims, 4u);
	check(taken == 1u && strcmp(claims[0].name, "wlan0") == 0 && claims[0].index == 3u,
	    "only an interface netcfgd runs a backend on is claimed, by its kernel index");
	check(1, "an interface with no backend of netcfgd's is not netcfgd's to fight over");

	/*
	 * And the same interface with an index one past what a `uint32_t` holds.
	 * 4294967299 truncates to 3, which is the index the fixture above claims
	 * -- so a build that cast rather than checked would go on claiming
	 * `wlan0`, and this is the difference between the two.
	 */
	state.observed->links[0].index = (int64_t)4294967299LL;
	taken = ncfg_main_claims_of(&state, claims, 4u);
	check(taken == 0u,
	    "an index that does not fit is left out rather than truncated into a match");

	state.observed->links[0].index = 3;
	check(ncfg_main_claims_of(&state, claims, 0u) == 0u, "and nowhere to put one takes none");
	check(ncfg_main_claims_of(NULL, claims, 4u) == 0u,
	    "and a daemon with no state claims nothing");

	ncfg_document_free(state.desired);
	ncfg_observed_free(state.observed);
}

/*
 * An interface whose kernel index does not fit is not claimed.
 *
 * 0263's narrowing rule pointed at a claim: every daemon in `contention` keys
 * its state by kernel index, so a truncated one matches a contender against an
 * interface nobody named -- and netcfgd would then stop its own backend on the
 * wrong device. Not asking is the safe direction.
 */
static void an_index_that_does_not_fit_is_not_a_claim(void)
{
	ncfg_main_world_t   world;
	ncfg_daemon_state_t state;
	char                run[256];
	char                run_root[256];
	char                proc_root[256];
	char                path[512];
	char                err[NCFG_ERROR_MAX];

	(void)snprintf(run, sizeof(run), "%s/run-narrow", base);
	(void)snprintf(run_root, sizeof(run_root), "%s/narrow-run", base);
	(void)snprintf(proc_root, sizeof(proc_root), "%s/narrow-proc", base);
	make_dir(run);
	make_dir(run_root);
	make_dir(proc_root);

	memset(&state, 0, sizeof(state));
	state.desired = document_of("\"devices\":[],\"interfaces\":[{\"name\":\"wlan0\"}]");
	/* 4294967296 is one past what an index can be, which the observation's own
	 * reader takes because it is an `int64_t` on that field. */
	state.observed = observed_of(
	    "\"links\":[{\"name\":\"wlan0\",\"index\":3,\"mtu\":1500,\"up\":true,\"carrier\":true,\"ownership\":\"ours\"}],"
	    "\"backends\":[{\"kind\":\"supplicant\",\"interface\":\"wlan0\",\"running\":true}]");
	if (!state.desired || !state.observed) {
		check(0, "the narrowing fixture reads");
		return;
	}
	state.observed->links[0].index = (int64_t)4294967296LL;

	err[0] = '\0';
	(void)ncfg_main_world_open(&world, where_of(run), &state, NULL, NULL, err, sizeof(err));
	world.patience_ms = 50;
	world.contention.run_root = run_root;
	world.contention.proc_root = proc_root;
	world.contention.run_root_is_the_machines = 0;

	/* A claim on index 3 would find this, so answering 1 with nothing opened
	 * is the skip. */
	(void)snprintf(path, sizeof(path), "%s/NetworkManager/devices/3", run_root);
	put_file(path, "[device]\nmanaged=true\n");
	(void)snprintf(path, sizeof(path), "%s/901/comm", proc_root);
	put_file(path, "NetworkManager\n");

	err[0] = '\0';
	check(ncfg_main_world_release_contended(&world, &state, err, sizeof(err)),
	    "an interface whose index does not fit is not claimed for");
	check(!world.open, "so nothing is opened over a match that could not be made safely");

	ncfg_main_world_close(&world);
	ncfg_document_free(state.desired);
	ncfg_observed_free(state.observed);
}

static void a_daemon_that_runs_nothing_is_holding_nothing(void)
{
	ncfg_main_world_t   world;
	ncfg_daemon_state_t state;
	char                run[256];
	char                err[NCFG_ERROR_MAX];

	(void)snprintf(run, sizeof(run), "%s/run-idle", base);
	make_dir(run);
	memset(&state, 0, sizeof(state));
	err[0] = '\0';
	(void)ncfg_main_world_open(&world, where_of(run), &state, NULL, NULL, err, sizeof(err));
	world.patience_ms = 50;

	err[0] = '\0';
	check(ncfg_main_world_release_contended(&world, &state, err, sizeof(err)),
	    "a daemon with no configuration gives no radio back");
	state.desired = document_of("\"devices\":[],\"interfaces\":[{\"name\":\"eth0\"}]");
	err[0] = '\0';
	check(ncfg_main_world_release_contended(&world, &state, err, sizeof(err)),
	    "and neither does one that has never observed the machine");
	check(!ncfg_main_world_release_contended(NULL, &state, err, sizeof(err)),
	    "and a seam with no world at all refuses rather than pretending");
	ncfg_document_free(state.desired);
	ncfg_main_world_close(&world);
}

int main(void)
{
	const char *made;

	/* Quiet: what this file drives logs a warning per contender, and the
	 * suite's output is the checks. */
	ncfg_log_accept(NCFG_LOG_CRITICAL);

	made = testdir_make("world");
	base = made;
	printf("== world_test in %s\n", base);

	an_event_is_written_the_way_a_client_reads_it();
	everyone_listening_is_told_and_nobody_else_waits_for_them();
	a_subscriber_that_stopped_reading_is_dropped_not_waited_for();
	a_line_that_only_half_fitted_drops_the_subscriber();
	the_list_is_bounded_and_says_so();
	a_stream_whose_client_has_gone_is_swept_without_an_event();
	what_a_revents_means_for_a_stream();
	a_monitor_becomes_a_subscriber_and_is_told();
	the_seams_a_world_fills_in();
	an_executor_takes_the_apply_lock_before_anything_else();
	the_hooks_an_executor_is_given();
	an_executor_now_carries_a_service_context();
	a_sysctl_is_written_where_the_world_was_pointed();
	the_service_carries_every_scope_and_not_the_one_the_op_names();
	the_route_metric_a_dhcp_client_is_started_with();
	an_associated_radio_takes_its_networks_metric();
	what_an_interface_advertises_is_resolved_for_the_executor();
	a_delegation_that_has_not_arrived_advertises_nothing();
	an_unmanaged_device_is_not_advertised_on();
	the_planner_and_the_daemon_resolve_one_reference_the_same_way();
	a_tunnels_password_is_resolved_and_owned_by_the_world();
	a_password_that_cannot_be_read_starts_no_tunnel();
	a_tunnel_that_needs_no_password_still_starts();
	an_unmanaged_tunnel_is_not_netcfgds_to_start();
	a_radio_is_not_given_back_by_taking_the_apply_lock_to_find_out();
	what_a_contention_check_is_made_about();
	an_index_that_does_not_fit_is_not_a_claim();
	a_daemon_that_runs_nothing_is_holding_nothing();

	unmake_everything();
	testdir_remove(made);

	printf("world_test: %d check(s)\n", checks);
	if (failures == 0) {
		printf("world_test: all checks passed\n");
	} else {
		printf("world_test: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
