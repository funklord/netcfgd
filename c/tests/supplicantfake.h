/*
 * supplicantfake.h -- a stand-in for wpa_supplicant's control socket.
 *
 * WHY THIS IS A HEADER AND NOT A COPY PER FILE
 *   `hostapdfake.h`'s reason, and it was paid for here before it was taken:
 *   `supplicant_client_test.c` grew this fake, and when the daemon's watcher
 *   needed one -- to check that a supplicant event reaches the log -- there
 *   was nowhere to take it from. The answer for a whole wave was a `grep` of
 *   the watcher's source asserting the call was still written, which is a
 *   check of the text rather than of the behaviour (project.md 10.238).
 *
 *   Two stand-ins for one daemon is two beliefs about its protocol -- the
 *   reply shape, what `ATTACH` answers, how an event is framed -- and what
 *   would drift is the thing both sides of netcfgd are written against.
 *
 *   Everything is `static` so a file that uses this and another fake does not
 *   have to explain the rest to `-Wunused-function`, which is `planfix.h`'s
 *   and `hostapdfake.h`'s arrangement.
 *
 * WHAT IT IS
 *   A forked process bound to a `SOCK_DGRAM` unix socket at
 *   `<dir>/<interface>`, answering the commands netcfgd sends, broadcasting
 *   events to whoever has sent `ATTACH`, and appending every command it heard
 *   to a file the test reads back. **The wire format is the real one**:
 *   `tests/live/fake_supplicant.py` is the shape this copies, answer for
 *   answer, so that a parser changing its mind about the format is something
 *   both fakes notice.
 *
 * THE CHILD, AND HOW IT CANNOT OUTLIVE THE TEST
 *   Three separate things stop it: it puts itself in **its own process group**
 *   so the parent can take the whole of it down; it sets an `alarm` so an
 *   abandoned one dies on its own; and it wakes from `recvfrom` once a second
 *   to ask whether its parent is still there. A fixture that can be left
 *   running is the fault `hwsim.sh` shipped with, where a passing run held
 *   netcfgd and two supplicants ten minutes later.
 *
 * WHAT A CALLER HAS TO PROVIDE
 *   Nothing but the directory, the interface and a path for the log. The
 *   canary count beside it is written as it changes rather than at the end,
 *   because the end may be a signal.
 */
#ifndef NCFG_TESTS_SUPPLICANTFAKE_H
#define NCFG_TESTS_SUPPLICANTFAKE_H

#include "testdir.h"

#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/*
 * The passphrase a caller checks for, if it has one.
 *
 * `hostapdfake.h`'s arrangement -- the includer sets what this needs before
 * including it -- and the default matters: a file that does not drive
 * credentials still compiles, and the string it gets can never be one a test
 * would accidentally send, so the count it keeps stays honestly zero.
 */
#ifndef CANARY
#define CANARY "no-canary-was-defined-by-this-includer"
#endif

/* ------------------------------------------------------- the small helpers */

/*
 * Path and field copies that do their own bounding.
 *
 * `snprintf` is right in the library and wrong here: this fixture copies a
 * 16 KB datagram into a 64-byte field on purpose, and a compiler reasoning
 * about that is a warning per call site rather than a fault. These say what
 * they do -- a path that does not fit is a fixture that would check nothing,
 * so it stops; a field that does not fit is cut, because the fixture is
 * reading its own test's commands.
 */
static inline void join(char *out, size_t out_size, const char *dir, const char *leaf)
{
	size_t used = strlen(dir);
	size_t tail = strlen(leaf);

	if (used + 1u + tail >= out_size) {
		printf("a fixture path did not fit, which is a test that would check nothing\n");
		exit(1);
	}
	memcpy(out, dir, used);
	out[used] = '/';
	memcpy(out + used + 1u, leaf, tail + 1u);
}

static inline void put(char *out, size_t out_size, const char *value)
{
	size_t length = strlen(value);

	if (length >= out_size) {
		length = out_size - 1u;
	}
	memcpy(out, value, length);
	out[length] = '\0';
}

/* A unix address for a path, refusing one longer than an address holds rather
 * than binding a shorter name than was asked for. */
static inline void address_for(struct sockaddr_un *out, const char *path)
{
	size_t length = strlen(path);

	if (length >= sizeof(out->sun_path)) {
		printf("a fixture socket path is longer than a unix address\n");
		exit(1);
	}
	memset(out, 0, sizeof(*out));
	out->sun_family = AF_UNIX;
	memcpy(out->sun_path, path, length + 1u);
}

static inline long long now_ms(void)
{
	struct timespec when;

	(void)clock_gettime(CLOCK_MONOTONIC, &when);
	return (long long)when.tv_sec * 1000 + when.tv_nsec / 1000000;
}

/* ========================================================== the fake radio */

#define FAKE_BUFFER 16384u
#define FAKE_LISTENERS 4u

static const char SCAN_TABLE[] =
    "bssid / frequency / signal level / flags / ssid\n"
    "00:11:22:33:44:55\t2412\t-53\t[WPA2-PSK-CCMP][ESS]\tHomeFiber\n"
    "66:77:88:99:aa:bb\t5180\t-40\t[ESS]\tCafe\n"
    "cc:dd:ee:ff:00:11\t2437\t-100\t[WPA2-PSK-CCMP][WPS][ESS]\tDistant\n";

static const char STATUS_TABLE[] =
    "bssid=00:11:22:33:44:55\n"
    "freq=2412\n"
    "ssid=HomeFiber\n"
    "wpa_state=COMPLETED\n"
    "key_mgmt=WPA2-PSK\n";

struct fake {
	int                fd;
	int                log;
	struct sockaddr_un listener[FAKE_LISTENERS];
	socklen_t          listener_length[FAKE_LISTENERS];
	size_t             listeners;
	int                silent_next;
	int                huge_next;
	int                refuse_psk;
	int                disconnect_first;
	char               fail_scan[64];
	char               fail_join[64];
	unsigned long      canary_seen;
	/* Written out as it changes rather than at the end, because the end may
	 * be a signal: a count this process never got to record is a proof the
	 * parent cannot check, and it would read as "nothing was ever sent". */
	char               count_path[384];
};

static inline void fake_say(struct fake *state, const char *line)
{
	(void)write(state->log, line, strlen(line));
	(void)write(state->log, "\n", 1u);
}

/*
 * Record what was sent, with every keyword that carries key material cut off.
 *
 * The python fake's list, not a shorter one: its comment said secrets were
 * redacted while the list below it covered only WPA-Personal, so an enterprise
 * network's `password` and `private_key` went into a fixture's log in full.
 */
static inline void fake_log_command(struct fake *state, const char *command)
{
	static const char *const carries[] = { " psk ", " sae_password ", " password ",
		" private_key ", " private_key_passwd " };
	char                     shown[512];
	size_t                   cut = strlen(command);
	size_t                   which;

	if (strstr(command, CANARY)) {
		int note;

		state->canary_seen++;
		note = open(state->count_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
		if (note >= 0) {
			char summary[64];

			(void)snprintf(summary, sizeof(summary), "CANARY_SEEN %lu\n",
			    state->canary_seen);
			(void)write(note, summary, strlen(summary));
			(void)close(note);
		}
	}
	for (which = 0; which < sizeof(carries) / sizeof(carries[0]); which++) {
		const char *at = strstr(command, carries[which]);

		if (at && (size_t)(at - command) + strlen(carries[which]) < cut) {
			cut = (size_t)(at - command) + strlen(carries[which]);
		}
	}
	if (cut >= sizeof(shown)) {
		cut = sizeof(shown) - 1u;
	}
	memcpy(shown, command, cut);
	shown[cut] = '\0';
	fake_say(state, shown);
}

static inline void fake_reply(struct fake *state, const struct sockaddr_un *to, socklen_t to_length,
    const char *body, size_t length)
{
	/* A reply nobody is waiting for is not a reason to stop serving: a sender
	 * that has gone away gives ECONNREFUSED, which the python fake learned to
	 * swallow after it shut the whole thing down mid-suite. */
	(void)sendto(state->fd, body, length, 0, (const struct sockaddr *)to, to_length);
}

static inline void fake_broadcast(struct fake *state, const char *event)
{
	size_t which;

	for (which = 0; which < state->listeners; which++) {
		(void)sendto(state->fd, event, strlen(event), 0,
		    (const struct sockaddr *)&state->listener[which],
		    state->listener_length[which]);
	}
}

static inline void fake_attach(struct fake *state, const struct sockaddr_un *who, socklen_t length)
{
	/* A real wpa_supplicant sends unsolicited events only to connections that
	 * asked, which is the whole reason the roam watcher has to send `ATTACH`
	 * -- so a fake that broadcast to everybody would let a client that forgot
	 * it pass (0091). */
	if (state->listeners < FAKE_LISTENERS) {
		state->listener[state->listeners] = *who;
		state->listener_length[state->listeners] = length;
		state->listeners++;
	}
}

static inline int starts_with(const char *text_in, const char *prefix)
{
	return strncmp(text_in, prefix, strlen(prefix)) == 0;
}

static inline void fake_handle(struct fake *state, char *command, const struct sockaddr_un *from,
    socklen_t from_length)
{
	char event[256];

	fake_log_command(state, command);

	if (strcmp(command, "SILENT_NEXT") == 0) {
		state->silent_next = 1;
		fake_reply(state, from, from_length, "OK\n", 3u);
		return;
	}
	if (strcmp(command, "HUGE_NEXT") == 0) {
		state->huge_next = 1;
		fake_reply(state, from, from_length, "OK\n", 3u);
		return;
	}
	if (strcmp(command, "REFUSE_PSK") == 0) {
		/* One refusal, not a mode: every test after this one sends a
		 * credential for real, and a fake left refusing them would make the
		 * canary sweep pass by never carrying anything. */
		state->refuse_psk = 1;
		fake_reply(state, from, from_length, "OK\n", 3u);
		return;
	}
	if (starts_with(command, "FAIL_NEXT_SCAN ")) {
		put(state->fail_scan, sizeof(state->fail_scan),
		    command + strlen("FAIL_NEXT_SCAN "));
		fake_reply(state, from, from_length, "OK\n", 3u);
		return;
	}
	if (strcmp(command, "DISCONNECT_FIRST") == 0) {
		/* What a real supplicant does: `SELECT_NETWORK` leaves whatever the
		 * radio was on before it, so a disconnect is the ordinary first step
		 * of a join. A fake that never sent one would let a client that
		 * treated it as the outcome pass. */
		state->disconnect_first = 1;
		fake_reply(state, from, from_length, "OK\n", 3u);
		return;
	}
	if (starts_with(command, "FAIL_NEXT_JOIN ")) {
		put(state->fail_join, sizeof(state->fail_join),
		    command + strlen("FAIL_NEXT_JOIN "));
		fake_reply(state, from, from_length, "OK\n", 3u);
		return;
	}
	/* `TROUBLE <event text>` is not a wpa_supplicant command. It is how a
	 * test says an event happened that needs an access point refusing this
	 * station, which is not a thing a test can arrange. Verbatim on purpose:
	 * the texts are copied out of a real supplicant's journal, so what is
	 * checked is netcfgd's reading of the real format. */
	if (starts_with(command, "TROUBLE ")) {
		memcpy(event, "<3>", 3u);
		put(event + 3u, sizeof(event) - 3u, command + strlen("TROUBLE "));
		fake_reply(state, from, from_length, "OK\n", 3u);
		fake_broadcast(state, event);
		return;
	}
	if (state->silent_next) {
		/* A radio that took the request and never came back. */
		state->silent_next = 0;
		return;
	}
	if (state->huge_next) {
		static char huge[FAKE_BUFFER];

		state->huge_next = 0;
		memset(huge, 'x', sizeof(huge));
		fake_reply(state, from, from_length, huge, sizeof(huge));
		return;
	}
	if (strcmp(command, "PING") == 0) {
		fake_reply(state, from, from_length, "PONG\n", 5u);
		return;
	}
	if (strcmp(command, "ATTACH") == 0) {
		fake_attach(state, from, from_length);
		fake_reply(state, from, from_length, "OK\n", 3u);
		return;
	}
	if (strcmp(command, "DETACH") == 0) {
		fake_reply(state, from, from_length, "OK\n", 3u);
		return;
	}
	if (strcmp(command, "SCAN") == 0) {
		/* **A scan is two things: an answer and, later, an event.** A fake
		 * that only answered OK made every netcfgd scan wait out its full
		 * patience and then report the results as stale. */
		if (state->fail_scan[0] != '\0') {
			(void)snprintf(event, sizeof(event), "<3>CTRL-EVENT-SCAN-FAILED ret=%s",
			    state->fail_scan);
			state->fail_scan[0] = '\0';
		} else {
			(void)snprintf(event, sizeof(event), "<3>CTRL-EVENT-SCAN-RESULTS ");
		}
		fake_reply(state, from, from_length, "OK\n", 3u);
		fake_broadcast(state, event);
		return;
	}
	if (starts_with(command, "SELECT_NETWORK ")) {
		/* **A join is two things as well**: OK to the command, and later an
		 * event saying what became of it. 0197. */
		if (state->fail_join[0] != '\0') {
			(void)snprintf(event, sizeof(event),
			    "<3>CTRL-EVENT-SSID-TEMP-DISABLED id=0 ssid=\"HomeFiber\" "
			    "auth_failures=1 duration=10 reason=%s", state->fail_join);
			state->fail_join[0] = '\0';
		} else {
			(void)snprintf(event, sizeof(event),
			    "<3>CTRL-EVENT-CONNECTED - Connection to 00:11:22:33:44:55 "
			    "completed [id=0 id_str=]");
		}
		fake_reply(state, from, from_length, "OK\n", 3u);
		if (state->disconnect_first) {
			state->disconnect_first = 0;
			fake_broadcast(state, "<3>CTRL-EVENT-DISCONNECTED "
			    "bssid=00:11:22:33:44:55 reason=3 locally_generated=1");
		}
		fake_broadcast(state, event);
		return;
	}
	if (strcmp(command, "SCAN_RESULTS") == 0) {
		fake_reply(state, from, from_length, SCAN_TABLE, sizeof(SCAN_TABLE) - 1u);
		return;
	}
	if (strcmp(command, "STATUS") == 0) {
		fake_reply(state, from, from_length, STATUS_TABLE, sizeof(STATUS_TABLE) - 1u);
		return;
	}
	if (strcmp(command, "LIST_NETWORKS") == 0) {
		static const char empty[] = "network id / ssid / bssid / flags\n";

		fake_reply(state, from, from_length, empty, sizeof(empty) - 1u);
		return;
	}
	if (strcmp(command, "ADD_NETWORK") == 0) {
		fake_reply(state, from, from_length, "0\n", 2u);
		return;
	}
	if (starts_with(command, "SET_NETWORK ")) {
		if (state->refuse_psk && (strstr(command, " psk ") ||
		    strstr(command, " sae_password "))) {
			state->refuse_psk = 0;
			fake_reply(state, from, from_length, "FAIL\n", 5u);
			return;
		}
		fake_reply(state, from, from_length, "OK\n", 3u);
		return;
	}
	if (starts_with(command, "ENABLE_NETWORK ") || starts_with(command, "DISABLE_NETWORK ") ||
	    starts_with(command, "REMOVE_NETWORK ") || starts_with(command, "SET ")) {
		fake_reply(state, from, from_length, "OK\n", 3u);
		return;
	}
	/* Everything netcfgd might send that this does not model. FAIL is a real
	 * supplicant answer and netcfgd handles it; inventing a success would make
	 * a test pass for a command that did nothing. */
	fake_reply(state, from, from_length, "FAIL\n", 5u);
}

/* The child's whole life. Never returns. */
static inline void fake_serve(const char *path, const char *log_path, const char *count_path)
{
	struct fake        state;
	struct sockaddr_un address;
	struct timeval     slice;

	memset(&state, 0, sizeof(state));
	put(state.count_path, sizeof(state.count_path), count_path);
	state.log = open(log_path, O_WRONLY | O_CREAT | O_APPEND, 0600);
	state.fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (state.fd < 0 || state.log < 0) {
		_exit(1);
	}
	address_for(&address, path);
	(void)unlink(path);
	if (bind(state.fd, (const struct sockaddr *)&address, sizeof(address)) != 0) {
		_exit(1);
	}
	/* **Nothing here may outlive the run.** The alarm is the backstop for an
	 * abandoned child; the one-second receive slice is so that a child whose
	 * parent has gone notices within a second rather than at the alarm. */
	alarm(60);
	slice.tv_sec = 1;
	slice.tv_usec = 0;
	(void)setsockopt(state.fd, SOL_SOCKET, SO_RCVTIMEO, &slice, sizeof(slice));
	for (;;) {
		char               buffer[FAKE_BUFFER + 1u];
		struct sockaddr_un from;
		socklen_t          from_length = sizeof(from);
		ssize_t            got;

		memset(&from, 0, sizeof(from));
		got = recvfrom(state.fd, buffer, FAKE_BUFFER, 0, (struct sockaddr *)&from,
		    &from_length);
		if (got < 0) {
			if (getppid() == 1) {
				break;
			}
			continue;
		}
		buffer[got] = '\0';
		if (from_length == 0u || from.sun_path[0] == '\0') {
			continue;
		}
		fake_handle(&state, buffer, &from, from_length);
	}
	(void)close(state.fd);
	(void)unlink(path);
	_exit(0);
}

static pid_t fake_pid = -1;
static char  fake_socket[512];
static char  fake_log_path[512];
static char  fake_count_path[512];

static inline int fake_start(const char *dir, const char *interface, const char *log_path)
{
	long long deadline;

	join(fake_socket, sizeof(fake_socket), dir, interface);
	put(fake_log_path, sizeof(fake_log_path), log_path);
	put(fake_count_path, sizeof(fake_count_path), log_path);
	put(fake_count_path + strlen(fake_count_path),
	    sizeof(fake_count_path) - strlen(fake_count_path), ".count");
	fake_pid = fork();
	if (fake_pid < 0) {
		return 0;
	}
	if (fake_pid == 0) {
		/* **Its own process group**, so the parent can take down everything
		 * the fake started rather than one pid of it. */
		(void)setpgid(0, 0);
		fake_serve(fake_socket, log_path, fake_count_path);
		_exit(0);
	}
	(void)setpgid(fake_pid, fake_pid);
	/* Waited for rather than slept on: the socket appearing is the readiness
	 * signal, which is what netcfgd itself waits for when it starts one. */
	deadline = now_ms() + 3000;
	while (now_ms() < deadline) {
		if (testdir_exists(fake_socket)) {
			return 1;
		}
		{
			struct timespec pause;

			pause.tv_sec = 0;
			pause.tv_nsec = 1000000;
			(void)nanosleep(&pause, NULL);
		}
	}
	return 0;
}

static inline void fake_stop(void)
{
	int status = 0;

	if (fake_pid <= 0) {
		return;
	}
	/* The group, not the pid: anything the fake started goes with it. */
	(void)kill(-fake_pid, SIGTERM);
	(void)kill(fake_pid, SIGTERM);
	(void)waitpid(fake_pid, &status, 0);
	fake_pid = -1;
	(void)unlink(fake_socket);
}

/* What the fake was sent, since the log was last emptied. */
static inline char *fake_heard(void)
{
	size_t length = 0;
	char  *body = testdir_read(fake_log_path, &length);

	return body ? body : strdup("");
}

static inline void fake_forget(void)
{
	int log = open(fake_log_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);

	if (log >= 0) {
		(void)close(log);
	}
}

/* The fake's own count of how often the canary really crossed the socket, read
 * by asking it to write the number down on its way out. */
static inline unsigned long fake_canary_count(void)
{
	char         *heard;
	const char   *at;
	unsigned long count = 0;

	{
		size_t length = 0;

		heard = testdir_read(fake_count_path, &length);
	}
	if (!heard) {
		return 0;
	}
	at = strstr(heard, "CANARY_SEEN ");
	if (at) {
		count = strtoul(at + strlen("CANARY_SEEN "), NULL, 10);
	}
	free(heard);
	return count;
}

#endif /* NCFG_TESTS_SUPPLICANTFAKE_H */
