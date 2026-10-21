/*
 * netcfgd's event stream, as the window's event pane reads it.
 *
 * WHY THIS IS A SECOND TARGET AND NOT PART OF `replies`
 *   That one drives twenty-one readers that make ONE request and read ONE
 *   reply. A monitor is the other shape: `monitor` turns a connection into a
 *   stream and it never goes back, so the reader is called again and again on
 *   the same connection, keeping a partial line between calls. None of that
 *   code runs in the other target.
 *
 *   It is also the GUI's reader rather than an abstract one. `gui/src/
 *   monitor_stream.cpp` puts the descriptor in a `QSocketNotifier` and calls
 *   `ncfg_monitor_next` whenever it is readable, which is the loop below with
 *   Qt's event loop in place of the `for`. What the GUI does with an event
 *   afterwards is Qt string handling of values this library already parsed, in
 *   widget classes that need a `QApplication` -- not a parser, and not
 *   something a fuzz target can reach without becoming a window.
 *
 * THE THREE ANSWERS, AND WHY THE LOOP IS BOUNDED
 *   `ncfg_monitor_next` returns 1 for an event, 0 for "no complete line yet"
 *   -- the ordinary answer on a quiet network -- and -1 when the stream is
 *   gone. A reader with three answers and a buffer it keeps between calls can
 *   fail to make progress without failing, which is the hazard
 *   `kernel_bytes` asserts against for the kernel's walks: the loop here is
 *   counted, and running out of count aborts rather than spinning.
 *
 *   **A zero is not a reason to stop**, because the GUI does not stop on one:
 *   the notifier fires again. So the loop goes on until the reader says the
 *   stream is gone or the bound is reached -- with the write half shut down,
 *   an honest reader reaches the end and says so.
 */
#include "fuzz.h"

#include "ncfg_client.h"

#include <sys/socket.h>
#include <sys/un.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Well past any number of events a reply-sized input can carry, and small
 * enough that a stuck reader is a failed run rather than a wedged machine. */
#define EVENT_MAX 100000u
#define STREAM_MAX 32768u

static int listener = -1;
static char socket_path[sizeof(((struct sockaddr_un *)0)->sun_path)];

static void stop_listening(void)
{
	if (listener >= 0) {
		(void)close(listener);
		listener = -1;
	}
	if (socket_path[0] != '\0') {
		(void)unlink(socket_path);
		socket_path[0] = '\0';
	}
}

static int start_listening(void)
{
	struct sockaddr_un address;
	const char        *dir = getenv("TMPDIR");

	if (listener >= 0) {
		return 1;
	}
	if (snprintf(socket_path, sizeof(socket_path), "%s/ncfg-monitor-fuzz-%ld.sock",
	        dir ? dir : "/tmp", (long)getpid()) >= (int)sizeof(socket_path)) {
		fprintf(stderr, "monitor: $TMPDIR makes a path longer than sun_path\n");
		socket_path[0] = '\0';
		return 0;
	}
	listener = socket(AF_UNIX, SOCK_STREAM, 0);
	if (listener < 0) {
		fprintf(stderr, "monitor: no socket: %s\n", strerror(errno));
		return 0;
	}
	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	memcpy(address.sun_path, socket_path, strlen(socket_path));
	(void)unlink(socket_path);
	if (bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0 ||
	    listen(listener, 16) != 0) {
		fprintf(stderr, "monitor: cannot listen on %s: %s\n", socket_path,
		    strerror(errno));
		stop_listening();
		return 0;
	}
	(void)atexit(stop_listening);
	return 1;
}

int ncfg_fuzz_one(const unsigned char *data, size_t length)
{
	ncfg_monitor_t *monitor;
	char            err[NCFG_ERROR_MAX];
	int             served;
	size_t          stream_length;
	size_t          seen = 0u;

	if (!start_listening()) {
		return 0;
	}
	monitor = ncfg_monitor_open(socket_path, err, sizeof(err));
	if (!monitor) {
		return 0;
	}
	served = accept(listener, NULL, NULL);
	if (served < 0) {
		ncfg_monitor_close(monitor);
		return 0;
	}
	(void)fcntl(served, F_SETFL, O_NONBLOCK);
	stream_length = length > STREAM_MAX ? STREAM_MAX : length;
	if (stream_length) {
		(void)write(served, data, stream_length);
	}
	/* Shut down rather than closing, so the reader meets an end of stream
	 * with whatever it has buffered -- which is the case a half-written event
	 * arrives in, and the one that must be refused rather than half-read. */
	(void)shutdown(served, SHUT_WR);

	for (;;) {
		ncfg_event_t event;
		int          answer;

		memset(&event, 0, sizeof(event));
		answer = ncfg_monitor_next(monitor, &event, err, sizeof(err));
		if (answer == 1) {
			/* Freed whatever came back, including the partial fills: the
			 * header says an event's strings are the caller's. */
			ncfg_event_free(&event);
		} else {
			/* 0 is "nothing complete yet" and -1 is "the stream is gone".
			 * Freeing on both is the contract being exercised rather than
			 * assumed -- a reader that allocated two of four strings and then
			 * refused must not leak them. */
			ncfg_event_free(&event);
			if (answer < 0) {
				break;
			}
			/* A zero with the write half shut down means the reader has
			 * nothing more it can ever get. One more call would be the
			 * notifier firing again; a thousand would be a spin. */
			if (++seen >= 2u) {
				break;
			}
			continue;
		}
		if (++seen >= EVENT_MAX) {
			abort(); /* a stream reader that never finishes */
		}
	}
	ncfg_monitor_close(monitor);
	(void)close(served);
	return 0;
}
