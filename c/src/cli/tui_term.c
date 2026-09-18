/*
 * tui_term.c -- the only part of `ncfg tui` that owns a terminal.
 *
 * WHY THE ESCAPE SEQUENCES ARE HERE RATHER THAN ncurses
 *   The Rust binds ncurses and `netcfgd-sys::curses` argues the case well: key
 *   decoding out of terminfo, dirty-region rendering, and wide characters are
 *   three things ncurses has had right for thirty years, and the first
 *   hand-rolled `ncfg tui` got all three wrong. **What does not carry is the
 *   dependency.** There it is a default-on cargo feature and
 *   `--no-default-features` leaves the binary linking libc alone; here
 *   `c/Makefile` builds every source into one archive, so a link would make
 *   ncurses mandatory for `libncfg.a` -- for the daemon, for the client library,
 *   for every test -- and "no mandatory dependencies" is one of the claims this
 *   project exists to prove. 0263's divergence list says what this subset does
 *   not do, in so many words, rather than leaving somebody to find out.
 *
 * WHAT IS IN HERE AND WHAT IS NOT
 *   Descriptors, termios, signals and `poll`. **No rendering**: the frame is
 *   composed by `tui.c` into a buffer and this writes it, so that everything a
 *   test would want to assert is reachable without a terminal. The rule is
 *   worth stating because it is easy to break: one `snprintf` of a row in here
 *   would be a row no test can see.
 *
 * WHY poll RATHER THAN A THREAD
 *   The Rust reads the event stream on a detached thread, and says the
 *   alternative is "`poll` on two descriptors and this client has no other
 *   reason to reach for one". This one does: without ncurses the keyboard needs
 *   a timeout of its own, so `poll` is already here -- and a second descriptor
 *   in the same call is cheaper than a thread, a mutex and the libc that comes
 *   with one.
 */
#include "cli_internal.h"

#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/state.h"

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <termios.h>
#include <unistd.h>

/*
 * How long to wait for the rest of an escape sequence before deciding a bare
 * `0x1b` was the Escape key.
 *
 * ncurses defaults to 1000ms, which is what makes Escape feel broken; 25 is the
 * conventional replacement and is long enough for a sequence that has already
 * begun arriving to finish, even over ssh. The same number the Rust sets
 * `set_escdelay` to, for the same reason.
 */
#define ESCAPE_WAIT_MS 25

/* How often a pane that watches the machine re-asks. The Rust's 1000. */
#define TICK_MS 1000

/* Enough for a burst of keystrokes and for the longest sequence in it. */
#define KEYS_MAX 64

/* What is read off the event socket in one go. */
#define STREAM_CHUNK 4096

/*
 * The alternate screen and the cursor, in and out.
 *
 * Named because they are written from two places and the leave sequence has to
 * be exactly the entry one backwards -- a terminal left on the alternate screen
 * is one whose scrollback the operator cannot get back to.
 */
static const char ENTER_SCREEN[] = "\033[?1049h\033[?25l\033[2J";
static const char LEAVE_SCREEN[] = "\033[?25h\033[?1049l";

/* The size assumed where the kernel will not say. */
#define ROWS_DEFAULT    24
#define COLUMNS_DEFAULT 80

/* ------------------------------------------------------------------------ *
 * The terminal
 * ------------------------------------------------------------------------ */

/*
 * What the terminal was, so it can be put back.
 *
 * File-static because the signal handler needs it and a signal arrives where
 * no argument can. `saved_valid` is what keeps a second restore from writing the
 * leave sequences into a terminal somebody else already owns.
 */
static struct termios saved_terminal;
static int            saved_valid;
static volatile sig_atomic_t stop_asked;
static volatile sig_atomic_t size_changed;

/* Every byte, or as far as it got. A failed write here has nowhere to go. */
static void write_all(int fd, const char *bytes, size_t length)
{
	size_t sent = 0;

	while (sent < length) {
		ssize_t wrote = write(fd, bytes + sent, length - sent);

		if (wrote < 0) {
			if (errno == EINTR) {
				continue;
			}
			return;
		}
		if (wrote == 0) {
			return;
		}
		sent += (size_t)wrote;
	}
}

/*
 * Raw enough, which is `cbreak` plus no echo.
 *
 * `ISIG` is off deliberately, which is ncurses' own choice under `cbreak`: `^C`
 * arrives as a key and the keymap treats it as `q`, so somebody whose reflex it
 * is leaves by the path that puts the terminal back rather than by the one that
 * does not.
 */
static int terminal_open(char *err, size_t err_size)
{
	struct termios raw;

	if (tcgetattr(STDIN_FILENO, &saved_terminal) != 0) {
		ncfg_error_set(err, err_size, "cannot read the terminal's settings: %s",
		    strerror(errno));
		return 0;
	}
	saved_valid = 1;
	raw = saved_terminal;
	raw.c_lflag &= (tcflag_t)~(ECHO | ICANON | ISIG | IEXTEN);
	raw.c_iflag &= (tcflag_t)~(IXON | ICRNL | INLCR | BRKINT | ISTRIP);
	raw.c_oflag &= (tcflag_t)~OPOST;
	raw.c_cc[VMIN] = 1;
	raw.c_cc[VTIME] = 0;
	if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) != 0) {
		ncfg_error_set(err, err_size, "cannot put the terminal in raw mode: %s",
		    strerror(errno));
		saved_valid = 0;
		return 0;
	}
	/* The alternate screen, so what the operator had in the scrollback is
	 * still there afterwards, and no cursor to chase around the panes. */
	write_all(STDOUT_FILENO, ENTER_SCREEN, strlen(ENTER_SCREEN));
	return 1;
}

/*
 * Put it back, whether or not it was ever taken.
 *
 * Safe to call twice and safe to call from a handler: `tcsetattr` and `write`
 * are both on POSIX's async-signal-safe list, which is what lets the
 * termination signals leave by the same path as `q`.
 */
static void terminal_close(void)
{
	if (!saved_valid) {
		return;
	}
	saved_valid = 0;
	write_all(STDOUT_FILENO, LEAVE_SCREEN, strlen(LEAVE_SCREEN));
	(void)tcsetattr(STDIN_FILENO, TCSAFLUSH, &saved_terminal);
}

static void on_stop(int signal_number)
{
	(void)signal_number;
	stop_asked = 1;
}

static void on_resize(int signal_number)
{
	(void)signal_number;
	size_changed = 1;
}

/*
 * Ask to be told, rather than killed.
 *
 * Without this the default disposition ends the process before anything can
 * put the terminal back, and the operator's shell is handed back with echo off
 * and no cursor. `SA_RESTART` is deliberately absent: the point is for `poll`
 * to return `EINTR` so the loop notices.
 */
static void watch_signals(void)
{
	struct sigaction stop;
	struct sigaction resize;

	memset(&stop, 0, sizeof(stop));
	stop.sa_handler = on_stop;
	(void)sigemptyset(&stop.sa_mask);
	(void)sigaction(SIGINT, &stop, NULL);
	(void)sigaction(SIGTERM, &stop, NULL);
	(void)sigaction(SIGHUP, &stop, NULL);

	memset(&resize, 0, sizeof(resize));
	resize.sa_handler = on_resize;
	(void)sigemptyset(&resize.sa_mask);
	(void)sigaction(SIGWINCH, &resize, NULL);
}

/* How big the window is now, or the terminal everybody has. */
static void terminal_size(size_t *rows_out, size_t *columns_out)
{
	struct winsize window;

	*rows_out = ROWS_DEFAULT;
	*columns_out = COLUMNS_DEFAULT;
	if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &window) != 0) {
		return;
	}
	if (window.ws_row > 0) {
		*rows_out = window.ws_row;
	}
	if (window.ws_col > 0) {
		*columns_out = window.ws_col;
	}
}

/* ------------------------------------------------------------------------ *
 * The socket
 * ------------------------------------------------------------------------ */

/*
 * A connected socket, subscribed to the event stream.
 *
 * `ncfg_cli_ask` is one request and one answer and cannot hold a stream open;
 * `ncfg_cli_stream` holds one open and prints, which a pane may not do. So the
 * monitor connection is opened here. Its failure is not fatal -- four of the
 * five panes work without it -- so the sentence goes on the status line and the
 * events pane says the stream never started.
 */
static int subscribe(const char *socket_path, char *err, size_t err_size)
{
	struct sockaddr_un address;
	ncfg_proto_request_t request;
	ncfg_buf_t           line;
	int                  fd;
	int                  sent;

	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	if (!socket_path || strlen(socket_path) >= sizeof(address.sun_path)) {
		ncfg_error_set(err, err_size, "the socket path is too long to connect to");
		return -1;
	}
	memcpy(address.sun_path, socket_path, strlen(socket_path));

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		ncfg_error_set(err, err_size, "cannot open a socket: %s", strerror(errno));
		return -1;
	}
	if (connect(fd, (const struct sockaddr *)&address, sizeof(address)) < 0) {
		ncfg_error_set(err, err_size, "cannot subscribe to events: %s", strerror(errno));
		(void)close(fd);
		return -1;
	}
	memset(&request, 0, sizeof(request));
	request.kind = NCFG_PROTO_REQ_MONITOR;
	ncfg_buf_init(&line, NCFG_PROTO_MAX_LINE);
	if (!ncfg_proto_request_write(&request, &line, err, err_size)) {
		ncfg_buf_free(&line);
		(void)close(fd);
		return -1;
	}
	sent = send(fd, ncfg_buf_text(&line), line.length, MSG_NOSIGNAL) ==
	    (ssize_t)line.length;
	ncfg_buf_free(&line);
	if (!sent) {
		ncfg_error_set(err, err_size, "cannot subscribe to events: %s", strerror(errno));
		(void)close(fd);
		return -1;
	}
	return fd;
}

/* One request, and what came back, with the daemon's own sentence on a
 * refusal. Returns 1 where the pane has a new answer. */
static int fetch(ncfg_tui_t *tui, const char *socket_path, ncfg_tui_answer_t *answer,
    const ncfg_proto_request_t *request)
{
	ncfg_proto_message_t message;
	char                 err[NCFG_ERROR_MAX];

	if (!ncfg_cli_ask(socket_path, request, &message, err, sizeof(err))) {
		(void)snprintf(tui->message, sizeof(tui->message), "%s", err);
		return 0;
	}
	return ncfg_tui_answer_take(tui, answer, &message);
}

/* One request whose answer is only interesting for having arrived. */
static void settle(ncfg_tui_t *tui, const char *socket_path,
    const ncfg_proto_request_t *request, const char *done)
{
	ncfg_proto_message_t message;
	char                 err[NCFG_ERROR_MAX];

	if (!ncfg_cli_ask(socket_path, request, &message, err, sizeof(err))) {
		(void)snprintf(tui->message, sizeof(tui->message), "%s", err);
		return;
	}
	if (message.kind == NCFG_PROTO_MESSAGE_RESPONSE &&
	    message.u.response.kind == NCFG_PROTO_RESP_ERROR) {
		(void)ncfg_cli_text(message.u.response.u.error.message, tui->message,
		    sizeof(tui->message));
	} else {
		(void)snprintf(tui->message, sizeof(tui->message), "%s", done);
	}
	ncfg_proto_message_free(&message);
}

/*
 * Re-ask the daemon for whatever the current pane draws.
 *
 * The Rust's `App::refresh`, arm for arm, including the ordering: status first
 * on the two wireless panes, because the scan needs an interface name and the
 * operator should not have to supply one they can see.
 */
static void refresh(ncfg_tui_t *tui, const char *socket_path)
{
	ncfg_proto_request_t request;
	char                 interface[NCFG_TUI_NAME_MAX];

	memset(&request, 0, sizeof(request));
	switch (tui->pane) {
	case NCFG_TUI_PANE_DEVICES:
		request.kind = NCFG_PROTO_REQ_STATUS;
		(void)fetch(tui, socket_path, &tui->status, &request);
		return;
	case NCFG_TUI_PANE_PLAN:
		request.kind = NCFG_PROTO_REQ_PLAN;
		(void)fetch(tui, socket_path, &tui->plan, &request);
		return;
	case NCFG_TUI_PANE_WIFI:
		request.kind = NCFG_PROTO_REQ_STATUS;
		(void)fetch(tui, socket_path, &tui->status, &request);
		memset(&request, 0, sizeof(request));
		request.kind = NCFG_PROTO_REQ_RADIOS;
		(void)fetch(tui, socket_path, &tui->radios, &request);
		if (ncfg_tui_radio(tui, interface, sizeof(interface))) {
			memset(&request, 0, sizeof(request));
			request.kind = NCFG_PROTO_REQ_WIFI_SCAN;
			request.u.interface = ncfg_proto_str(interface);
			(void)fetch(tui, socket_path, &tui->scan, &request);
		} else {
			/*
			 * **Not an error any more, and that is the point.** A machine with
			 * a radio nobody has activated is the ordinary starting state, not
			 * a misconfiguration -- and the pane can now do something about
			 * it, so saying "no wireless device" and stopping would be
			 * describing the problem to somebody standing in front of the fix.
			 */
			ncfg_tui_answer_free(&tui->scan);
		}
		return;
	case NCFG_TUI_PANE_CLIENTS:
		request.kind = NCFG_PROTO_REQ_STATUS;
		(void)fetch(tui, socket_path, &tui->status, &request);
		if (ncfg_tui_radio(tui, interface, sizeof(interface))) {
			memset(&request, 0, sizeof(request));
			request.kind = NCFG_PROTO_REQ_AP_STATIONS;
			request.u.interface = ncfg_proto_str(interface);
			(void)fetch(tui, socket_path, &tui->stations, &request);
		} else {
			/*
			 * **The machine rather than the configuration**, which is the
			 * sentence `run.c` already diverges on for the same reason: this
			 * wave has no loader, the radio came from the kernel's own link
			 * table, and sending somebody to edit a file about a fact that
			 * came from somewhere else is the wrong instruction. The Rust says
			 * "no wireless device in the configuration" here and says the
			 * opposite two arms above -- see 0263.
			 */
			(void)snprintf(tui->message, sizeof(tui->message),
			    "no wireless device on this machine");
		}
		return;
	case NCFG_TUI_PANE_EVENTS:
	case NCFG_TUI_PANE_COUNT:
	default:
		return;
	}
}

/*
 * Apply, always inside a confirm window.
 *
 * Section 7.2 is explicit that this is the context where you are one bad route
 * away from losing the session, so there is no unprotected apply here at all --
 * not a default that can be turned off, an absence. Neither consent is offered
 * either: a keystroke is the wrong place to agree to leave a key on hardware
 * that is walking away, or to kill a daemon that may only be busy (0141).
 */
static void apply(ncfg_tui_t *tui, const char *socket_path)
{
	ncfg_proto_request_t request;

	memset(&request, 0, sizeof(request));
	request.kind = NCFG_PROTO_REQ_APPLY;
	request.u.apply.confirm.present = 1u;
	request.u.apply.confirm.value = 60;
	settle(tui, socket_path, &request,
	    "applied with a 60s window -- press y to keep it, n to undo now");
	refresh(tui, socket_path);
}

/* `c`: hand netcfgd a radio, or join the selected network. */
static void use(ncfg_tui_t *tui, const char *socket_path)
{
	ncfg_tui_use_t       chosen;
	ncfg_proto_request_t request;
	char                 err[NCFG_ERROR_MAX];
	char                 said[NCFG_TUI_MESSAGE_MAX];

	if (!ncfg_tui_use(tui, &chosen, err, sizeof(err))) {
		(void)snprintf(tui->message, sizeof(tui->message), "%s", err);
		return;
	}
	memset(&request, 0, sizeof(request));
	if (chosen.kind == NCFG_TUI_USE_RADIO) {
		request.kind = NCFG_PROTO_REQ_RADIO_SET;
		request.u.radio_set.interface = ncfg_proto_str(chosen.interface);
		request.u.radio_set.activate = 1u;
		(void)snprintf(said, sizeof(said), "%s is netcfgd's now; scanning",
		    chosen.interface);
		settle(tui, socket_path, &request, said);
		/* Straight into a scan rather than waiting for `r`: activating is only
		 * ever a step towards looking at what is in range, and the supplicant
		 * needs a moment either way. */
		refresh(tui, socket_path);
		return;
	}
	if (chosen.kind != NCFG_TUI_USE_NETWORK) {
		return;
	}
	request.kind = NCFG_PROTO_REQ_WIFI_CONNECT;
	request.u.wifi_connect.interface = ncfg_proto_str(chosen.interface);
	request.u.wifi_connect.network = ncfg_proto_str(chosen.network);
	(void)snprintf(said, sizeof(said), "joining %s", chosen.network);
	settle(tui, socket_path, &request, said);
}

/* ------------------------------------------------------------------------ *
 * The loop
 * ------------------------------------------------------------------------ */

/* Compose the frame and put it on the terminal. Nothing is rendered here. */
static void paint(const ncfg_tui_t *tui)
{
	ncfg_buf_t frame;
	size_t     rows;
	size_t     columns;

	terminal_size(&rows, &columns);
	ncfg_buf_init(&frame, 0);
	ncfg_tui_frame(tui, rows, columns, &frame);
	/* A buffer that failed hands out the empty string rather than half a
	 * frame, so a painted screen is a whole one or is not painted. */
	write_all(STDOUT_FILENO, ncfg_buf_text(&frame), strlen(ncfg_buf_text(&frame)));
	ncfg_buf_free(&frame);
}

/*
 * What arrived on the event socket, as lines for the pane.
 *
 * Returns 0 once the stream has ended, which the pane says rather than hiding:
 * a daemon restart ends it, and an events pane that went quiet without a word
 * would look like a network where nothing was happening.
 */
static int drain_events(ncfg_tui_t *tui, int fd, ncfg_proto_framer_t *framer)
{
	char    bytes[STREAM_CHUNK];
	ssize_t got = recv(fd, bytes, sizeof(bytes), 0);
	char    err[NCFG_ERROR_MAX];

	if (got < 0) {
		if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
			return 1;
		}
		ncfg_tui_event_push(tui, "-- the stream ended --");
		return 0;
	}
	if (got == 0) {
		ncfg_tui_event_push(tui, "-- the daemon closed the stream --");
		return 0;
	}
	if (!ncfg_proto_framer_add(framer, bytes, (size_t)got, err, sizeof(err))) {
		ncfg_tui_event_push(tui, err);
		return 0;
	}
	for (;;) {
		const char          *line = NULL;
		size_t               length = 0;
		ncfg_proto_message_t message;
		char                 text[NCFG_TUI_EVENT_MAX];

		if (ncfg_proto_framer_next(framer, &line, &length, err, sizeof(err)) !=
		    NCFG_PROTO_LINE) {
			return 1;
		}
		if (!ncfg_proto_response_read(line, length, &message, err, sizeof(err))) {
			/* A line this build cannot decode is still shown. A monitor that
			 * refused to parse an event a newer daemon sent would be useless
			 * for the ones it does understand. */
			ncfg_tui_event_push(tui,
			    ncfg_cli_event_text(NULL, line, length, text, sizeof(text)));
			continue;
		}
		if (message.kind == NCFG_PROTO_MESSAGE_EVENT) {
			ncfg_tui_event_push(tui, ncfg_cli_event_text(&message.u.event, line,
			    length, text, sizeof(text)));
		} else if (message.kind == NCFG_PROTO_MESSAGE_RESPONSE &&
		    message.u.response.kind == NCFG_PROTO_RESP_EVENT) {
			ncfg_tui_event_push(tui, ncfg_cli_event_text(&message.u.response.u.event,
			    line, length, text, sizeof(text)));
		} else {
			ncfg_tui_event_push(tui,
			    ncfg_cli_event_text(NULL, line, length, text, sizeof(text)));
		}
		ncfg_proto_message_free(&message);
	}
}

/* Act on one decoded key. Returns 0 to leave. */
static int act(ncfg_tui_t *tui, const char *socket_path, int key)
{
	ncfg_proto_request_t request;

	switch (ncfg_tui_key(tui, key)) {
	case NCFG_TUI_ACT_QUIT:
		return 0;
	case NCFG_TUI_ACT_REFRESH:
		refresh(tui, socket_path);
		return 1;
	case NCFG_TUI_ACT_APPLY:
		apply(tui, socket_path);
		return 1;
	case NCFG_TUI_ACT_CONFIRM:
		memset(&request, 0, sizeof(request));
		request.kind = NCFG_PROTO_REQ_CONFIRM;
		settle(tui, socket_path, &request, "confirmed; the change stands");
		refresh(tui, socket_path);
		return 1;
	case NCFG_TUI_ACT_REVERT:
		memset(&request, 0, sizeof(request));
		request.kind = NCFG_PROTO_REQ_REVERT;
		settle(tui, socket_path, &request,
		    "reverted to the last-good configuration");
		refresh(tui, socket_path);
		return 1;
	case NCFG_TUI_ACT_USE:
		use(tui, socket_path);
		return 1;
	case NCFG_TUI_ACT_NONE:
	default:
		return 1;
	}
}

/*
 * Read keys and redraw until asked to stop.
 *
 * The pending buffer is what an escape sequence needs and a `getch` hides: a
 * burst may end mid-sequence, and the bytes have to wait somewhere for the rest
 * rather than be read as three keystrokes. `PARTIAL` shortens the next wait to
 * `ESCAPE_WAIT_MS`, and a wait that expires with a lone `ESC` still pending is
 * the Escape key.
 */
static void loop(ncfg_tui_t *tui, const char *socket_path, int events_fd,
    ncfg_proto_framer_t *framer)
{
	char   pending[KEYS_MAX];
	size_t pending_length = 0;
	int    streaming = events_fd >= 0;

	for (;;) {
		struct pollfd watch[2];
		nfds_t        count = 1;
		int           wait = pending_length > 0 ? ESCAPE_WAIT_MS : TICK_MS;
		int           ready;

		paint(tui);
		if (stop_asked) {
			return;
		}
		watch[0].fd = STDIN_FILENO;
		watch[0].events = POLLIN;
		watch[0].revents = 0;
		if (streaming) {
			watch[1].fd = events_fd;
			watch[1].events = POLLIN;
			watch[1].revents = 0;
			count = 2;
		}
		ready = poll(watch, count, wait);
		if (stop_asked) {
			return;
		}
		if (ready < 0) {
			if (errno == EINTR) {
				/* A resize is a repaint and nothing else: the frame is
				 * composed for whatever the window is now, so there is no
				 * layout to rebuild. */
				size_changed = 0;
				continue;
			}
			return;
		}
		if (ready == 0) {
			if (pending_length > 0) {
				/* The rest never came, so it was Escape. */
				(void)act(tui, socket_path, 0x1b);
				pending_length = 0;
				continue;
			}
			if (tui->pane == NCFG_TUI_PANE_DEVICES ||
			    tui->pane == NCFG_TUI_PANE_PLAN) {
				refresh(tui, socket_path);
			}
			continue;
		}
		if (streaming && (watch[1].revents & (POLLIN | POLLHUP | POLLERR)) != 0) {
			if (!drain_events(tui, events_fd, framer)) {
				(void)close(events_fd);
				events_fd = -1;
				streaming = 0;
			}
		}
		if ((watch[0].revents & POLLIN) != 0) {
			ssize_t got = read(STDIN_FILENO, pending + pending_length,
			    sizeof(pending) - pending_length);
			size_t  at = 0;

			if (got <= 0) {
				if (got < 0 && errno == EINTR) {
					continue;
				}
				return;
			}
			pending_length += (size_t)got;
			while (at < pending_length) {
				int    key = 0;
				size_t used = 0;

				if (ncfg_tui_key_decode(pending + at, pending_length - at, &key,
				    &used) != NCFG_TUI_INPUT_READY) {
					break;
				}
				at += used;
				if (!act(tui, socket_path, key)) {
					return;
				}
			}
			memmove(pending, pending + at, pending_length - at);
			pending_length -= at;
			/* A sequence longer than this buffer is not one any terminal
			 * sends; dropping it is better than never decoding again. */
			if (pending_length == sizeof(pending)) {
				pending_length = 0;
			}
		}
	}
}

/* ------------------------------------------------------------------------ *
 * The verb
 * ------------------------------------------------------------------------ */

static int say(const char *message)
{
	(void)fprintf(stderr, "ncfg: %s\n", message);
	return NCFG_CLI_EXIT_FAILED;
}

int ncfg_tui_run(const ncfg_cli_options_t *options)
{
	ncfg_tui_t           tui;
	ncfg_proto_framer_t  framer;
	ncfg_proto_request_t request;
	ncfg_proto_message_t message;
	char                 run_dir[NCFG_CLI_TEXT_MAX];
	char                 socket_path[NCFG_CLI_TEXT_MAX];
	char                 err[NCFG_ERROR_MAX];
	int                  events_fd;

	(void)ncfg_state_resolve_dir(options ? options->run_dir : NULL, run_dir,
	    sizeof(run_dir));
	if (!ncfg_cli_socket_path(run_dir, socket_path, sizeof(socket_path))) {
		return say("the run directory makes a socket path too long to connect to");
	}
	/*
	 * Checked before the terminal is touched, so a machine with no daemon gets
	 * a sentence rather than a cleared screen and a sentence.
	 */
	memset(&request, 0, sizeof(request));
	request.kind = NCFG_PROTO_REQ_HELLO;
	if (!ncfg_cli_ask(socket_path, &request, &message, err, sizeof(err))) {
		return say(err);
	}
	ncfg_proto_message_free(&message);

	/*
	 * Refused before anything is written, rather than discovered by a pipe
	 * filling up with escape sequences.
	 */
	if (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO)) {
		return say("`ncfg tui` needs a terminal; for a pipe use `ncfg status --json`");
	}

	ncfg_tui_init(&tui);
	/* `$NO_COLOR` turns off even reverse video, read once here so that no
	 * renderer has to reach for an environment. */
	tui.no_color = getenv("NO_COLOR") != NULL;

	events_fd = subscribe(socket_path, err, sizeof(err));
	if (events_fd < 0) {
		ncfg_tui_event_push(&tui, err);
	}
	ncfg_proto_framer_init(&framer);

	watch_signals();
	if (!terminal_open(err, sizeof(err))) {
		if (events_fd >= 0) {
			(void)close(events_fd);
		}
		ncfg_proto_framer_free(&framer);
		ncfg_tui_free(&tui);
		return say(err);
	}
	refresh(&tui, socket_path);
	loop(&tui, socket_path, events_fd, &framer);

	/* Explicit, and before anything else can print. */
	terminal_close();
	if (events_fd >= 0) {
		(void)close(events_fd);
	}
	ncfg_proto_framer_free(&framer);
	ncfg_tui_free(&tui);
	return NCFG_CLI_EXIT_OK;
}
