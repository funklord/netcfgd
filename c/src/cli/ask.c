/*
 * ask.c -- one request, one answer, and the monitor stream.
 *
 * ONLY WHERE THE DAEMON IS GENUINELY REQUIRED
 *   Design section 4.4 makes daemon-optional a property rather than a
 *   fallback: `ncfg plan` and `ncfg status` are meant to work without one. What
 *   is here is the set that cannot -- the wireless verbs, which reach the
 *   supplicant through netcfgd so that the `wifi` tier gets them without being
 *   able to change configuration (0013); the modem report; and a confirm window,
 *   which has to outlive the process that opened it.
 *
 * WHY THE TRANSPORT IS HERE AND NOT `ncfg_client_request`
 *   `client/` already talks to this daemon, is not duplicated and is not
 *   modified. What it hands back is the *GUI's* model of an answer, and
 *   `ncfg`'s output needs the protocol's: a radio's `blocked` sentence, the
 *   networks a supplicant has stopped trying, a station list and the policy it
 *   is read under. None of those are in the GUI's shapes -- so rendering the
 *   CLI from them would mean a second reader of this format inventing the
 *   missing halves, which is precisely how one access point's name came to be
 *   spelled three ways (0263). `proto.h` is the one reader, and this file is
 *   the socket under it.
 *
 * WHY THIS DOES NOT TOUCH SIGPIPE
 *   `send` with `MSG_NOSIGNAL`, per call, the same answer `client/` reached
 *   from the other side: a dead reader on **stdout** is this program's own
 *   business and ends it at 141 (0261), but a dead peer on a **socket** is a
 *   diagnostic somebody needs -- `ncfg` prints "cannot send to netcfgd" rather
 *   than dying. Changing a process-wide disposition on behalf of a program
 *   that did not ask is what neither half does.
 */
#include "cli_internal.h"

#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/log.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

const char *ncfg_cli_socket_path(const char *run_dir, char *out, size_t out_size)
{
	int wrote = snprintf(out, out_size, "%s/netcfgd.sock", run_dir ? run_dir : "");

	if (wrote < 0 || (size_t)wrote >= out_size) {
		return NULL;
	}
	return out;
}

/*
 * Connect, and say what went wrong in a way that points at the right file.
 *
 * One place, because there were four: three said only "cannot reach the
 * daemon" and the fourth added a sentence about it having to be running. A
 * diagnostic written four times is a diagnostic that is right in one of them,
 * and this one was wrong in all four for the case that matters.
 *
 * **`EACCES` is not "it is not running".** The socket's mode follows
 * `global { control { ... } }` and every tier defaults to root, so a client run
 * by a desktop user meets exactly this on a default install -- and being told
 * to check whether the daemon is running sends them to the journal for
 * something that is in a config file (0118).
 */
static int connect_to(const char *path, char *err, size_t err_size)
{
	struct sockaddr_un address;
	int                fd;

	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	if (!path || strlen(path) >= sizeof(address.sun_path)) {
		/* A truncated unix socket address is not an error the kernel
		 * reports -- it would connect to a shorter path that may well
		 * exist -- so the length is checked here or it is not checked. */
		ncfg_error_set(err, err_size, "the socket path is too long to connect to: %s",
		    path ? path : "");
		return -1;
	}
	memcpy(address.sun_path, path, strlen(path));

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		ncfg_error_set(err, err_size, "cannot open a socket: %s", strerror(errno));
		return -1;
	}
	if (connect(fd, (const struct sockaddr *)&address, sizeof(address)) < 0) {
		int why = errno;

		close(fd);
		if (why == EACCES || why == EPERM) {
			ncfg_error_set(err, err_size,
			    "not allowed to talk to netcfgd at %s: %s\n"
			    "the socket's mode follows `global { control { ... } }`, and every "
			    "tier defaults to root -- so this is a permission policy rather "
			    "than a daemon that is not running",
			    path, strerror(why));
		} else {
			ncfg_error_set(err, err_size,
			    "cannot reach the daemon at %s: %s\n"
			    "this command is answered by netcfgd, so the daemon has to be "
			    "running",
			    path, strerror(why));
		}
		return -1;
	}
	return fd;
}

/* Every byte, or a failure. `MSG_NOSIGNAL` for the reason in the header. */
static int send_all(int fd, const char *bytes, size_t length)
{
	size_t sent = 0;

	while (sent < length) {
		ssize_t wrote = send(fd, bytes + sent, length - sent, MSG_NOSIGNAL);

		if (wrote < 0) {
			if (errno == EINTR) {
				continue;
			}
			return 0;
		}
		if (wrote == 0) {
			return 0;
		}
		sent += (size_t)wrote;
	}
	return 1;
}

/*
 * One whole line off the socket, into the framer.
 *
 * Returns 1 with the line, 0 with a sentence. An end of stream with nothing
 * pending is not a failure of the transport but it *is* a failure of this
 * conversation -- the daemon closed without answering -- so it is reported as
 * one, with the words that say which happened.
 */
static int read_line(int fd, ncfg_proto_framer_t *framer, const char **line_out,
    size_t *length_out, char *err, size_t err_size)
{
	for (;;) {
		char    bytes[4096];
		ssize_t got;

		switch (ncfg_proto_framer_next(framer, line_out, length_out, err, err_size)) {
		case NCFG_PROTO_LINE:
			return 1;
		case NCFG_PROTO_LINE_FAILED:
			return 0;
		case NCFG_PROTO_LINE_INCOMPLETE:
		default:
			break;
		}
		got = recv(fd, bytes, sizeof(bytes), 0);
		if (got < 0) {
			if (errno == EINTR) {
				continue;
			}
			ncfg_error_set(err, err_size, "cannot read the answer: %s",
			    strerror(errno));
			return 0;
		}
		if (got == 0) {
			if (!ncfg_proto_framer_finish(framer, err, err_size)) {
				return 0;
			}
			ncfg_error_set(err, err_size,
			    "the daemon closed the connection without answering");
			return 0;
		}
		if (!ncfg_proto_framer_add(framer, bytes, (size_t)got, err, err_size)) {
			return 0;
		}
	}
}

/*
 * Say what the daemon said, where a failed send means it had already spoken.
 *
 * **A refusal arrives before the request goes out**, and a client that reported
 * the write error would lose it. The daemon's connection cap answers on accept
 * -- "too many connections, 64 are open" -- and then closes, so the write lands
 * on a closed socket and fails with `EPIPE` while the sentence explaining why
 * is already sitting in this process's own receive buffer, unread. Measured:
 * with the cap reached, `ncfg reload` said `cannot send: Broken pipe`, which
 * sends the reader looking for a crashed daemon. Decision 0183.
 *
 * The write error is kept where nothing was said, because then it is the whole
 * story.
 */
static void what_it_said_instead(int fd, int why, char *err, size_t err_size)
{
	ncfg_proto_framer_t  framer;
	const char          *line = NULL;
	size_t               length = 0;
	char                 ignored[NCFG_ERROR_MAX];
	ncfg_proto_message_t message;

	ncfg_error_set(err, err_size, "cannot send: %s", strerror(why));
	ncfg_proto_framer_init(&framer);
	if (read_line(fd, &framer, &line, &length, ignored, sizeof(ignored)) &&
	    ncfg_proto_response_read(line, length, &message, ignored, sizeof(ignored))) {
		if (message.kind == NCFG_PROTO_MESSAGE_RESPONSE &&
		    message.u.response.kind == NCFG_PROTO_RESP_ERROR) {
			char said[NCFG_ERROR_MAX];

			ncfg_error_set(err, err_size, "%s",
			    ncfg_cli_text(message.u.response.u.error.message, said, sizeof(said)));
		}
		ncfg_proto_message_free(&message);
	}
	ncfg_proto_framer_free(&framer);
}

int ncfg_cli_ask(const char *socket_path, const ncfg_proto_request_t *request,
    ncfg_proto_message_t *out, char *err, size_t err_size)
{
	ncfg_proto_framer_t framer;
	ncfg_buf_t          line;
	const char         *answer = NULL;
	size_t              length = 0;
	int                 fd;
	int                 read_it;

	ncfg_buf_init(&line, NCFG_PROTO_MAX_LINE);
	if (!ncfg_proto_request_write(request, &line, err, err_size)) {
		ncfg_buf_free(&line);
		return 0;
	}
	fd = connect_to(socket_path, err, err_size);
	if (fd < 0) {
		ncfg_buf_free(&line);
		return 0;
	}
	if (!send_all(fd, ncfg_buf_text(&line), line.length)) {
		what_it_said_instead(fd, errno, err, err_size);
		ncfg_buf_free(&line);
		close(fd);
		return 0;
	}
	ncfg_buf_free(&line);

	ncfg_proto_framer_init(&framer);
	read_it = read_line(fd, &framer, &answer, &length, err, err_size) &&
	    ncfg_proto_response_read(answer, length, out, err, err_size);
	ncfg_proto_framer_free(&framer);
	close(fd);
	return read_it;
}

/*
 * One line per event on a monitor stream.
 *
 * The five sentences themselves are `ncfg_cli_event_text`'s, not a second copy
 * of them -- the TUI needs the same text in a buffer and two lists of one
 * thing have drifted in this tree before.
 *
 * **What is not shared is the passthrough, and that is deliberate.** An event
 * this build does not recognise is printed whole rather than refused, so that
 * a newer daemon does not make an older `ncfg monitor` useless for the events
 * it does understand -- and "whole" means up to `NCFG_PROTO_MAX_LINE`, which
 * is a megabyte. `ncfg_cli_event_text` composes into a caller's buffer, so
 * routing that case through it would have quietly cut the line to whatever the
 * buffer was: the one arm whose entire purpose is not to lose anything would
 * have been the one that lost the most. So the recognised kinds go through the
 * shared renderer and the raw line is still streamed.
 *
 * The buffer holds the longest bounded sentence: `drift` is three
 * `NCFG_CLI_TEXT_MAX` fields and a dozen characters of frame.
 */
void ncfg_cli_print_event(const ncfg_proto_event_t *event, const char *raw, size_t raw_length)
{
	char text[4u * NCFG_CLI_TEXT_MAX];

	if (!event || event->kind >= NCFG_PROTO_EVENT_COUNT) {
		ncfg_out_writef("%.*s\n", (int)raw_length, raw ? raw : "");
		return;
	}
	ncfg_out_writef("%s\n", ncfg_cli_event_text(event, raw, raw_length, text, sizeof(text)));
}

int ncfg_cli_stream(const char *socket_path, char *err, size_t err_size)
{
	ncfg_proto_request_t request;
	ncfg_proto_framer_t  framer;
	ncfg_buf_t           line;
	int                  fd;

	memset(&request, 0, sizeof(request));
	request.kind = NCFG_PROTO_REQ_MONITOR;

	ncfg_buf_init(&line, NCFG_PROTO_MAX_LINE);
	if (!ncfg_proto_request_write(&request, &line, err, err_size)) {
		ncfg_buf_free(&line);
		return 0;
	}
	fd = connect_to(socket_path, err, err_size);
	if (fd < 0) {
		ncfg_buf_free(&line);
		return 0;
	}
	if (!send_all(fd, ncfg_buf_text(&line), line.length)) {
		what_it_said_instead(fd, errno, err, err_size);
		ncfg_buf_free(&line);
		close(fd);
		return 0;
	}
	ncfg_buf_free(&line);

	ncfg_proto_framer_init(&framer);
	for (;;) {
		const char          *answer = NULL;
		size_t               length = 0;
		ncfg_proto_message_t message;

		if (!read_line(fd, &framer, &answer, &length, err, err_size)) {
			/*
			 * The daemon stopping is how a monitor ends, and the reader
			 * distinguishes that from a broken stream by its sentence. Both
			 * arrive here as a failure, so the ordinary end is recognised and
			 * reported as success -- a client that called a closed connection
			 * an error would tell an operator the daemon had failed when it
			 * had merely gone away (section 10, item 4).
			 */
			int ended = strstr(err, "without answering") != NULL;

			ncfg_proto_framer_free(&framer);
			close(fd);
			if (ended) {
				err[0] = '\0';
				return 1;
			}
			return 0;
		}
		if (ncfg_proto_response_read(answer, length, &message, err, err_size)) {
			if (message.kind == NCFG_PROTO_MESSAGE_EVENT) {
				ncfg_cli_print_event(&message.u.event, answer, length);
			} else if (message.kind == NCFG_PROTO_MESSAGE_RESPONSE &&
			    message.u.response.kind == NCFG_PROTO_RESP_EVENT) {
				ncfg_cli_print_event(&message.u.response.u.event, answer, length);
			} else {
				ncfg_cli_print_event(NULL, answer, length);
			}
			ncfg_proto_message_free(&message);
		} else {
			/* A line this build cannot decode is still shown. A monitor that
			 * refused to parse an event a newer daemon sent would be useless
			 * for the ones it does understand. */
			ncfg_cli_print_event(NULL, answer, length);
		}
	}
}
