/*
 * supplicant_client_test.c -- the control socket, and the credential's whole
 * journey across it.
 *
 * THE FAKE IS A RADIO, NOT A PROTOCOL
 *   `tests/live/fake_supplicant.py` is the shape this copies and its first
 *   paragraph is the rule: the one thing this repository cannot produce on
 *   demand is a radio, so the hardware is faked and **the wire format is the
 *   real one**. The answers below are that file's, command for command, so
 *   that a parser changing its mind about the format is something both fakes
 *   notice.
 *
 * WHAT IT MAY NOT TOUCH
 *   This is the developer's own workstation and its wifi is live, managed by
 *   the real netcfgd. Nothing here goes near `/run/wpa_supplicant`,
 *   `/etc/netcfgd`, or the running supplicant: every socket is under one
 *   `mkdtemp` directory, the interface is called `wlan0` and exists only
 *   there, and `NCFG_SUPPLICANT_CTRL_DIR` is read in one check and never used
 *   to connect.
 *
 * THE CHILD, AND HOW IT CANNOT OUTLIVE THIS
 *   The fake is a forked process and three separate things stop it: it puts
 *   itself in **its own process group** so the parent can take the whole of it
 *   down; it sets an `alarm` so an abandoned one dies on its own; and it wakes
 *   from `recvfrom` once a second to ask whether its parent is still there.
 *   A test fixture that can be left running is the fault `hwsim.sh` shipped
 *   with, where a passing run held netcfgd and two supplicants ten minutes
 *   later.
 *
 * THE CANARY
 *   `secrets_test.c`'s proof, carried across a socket. One value is the
 *   passphrase for every credential here, every failure this module has is
 *   driven with it, and four channels are read back for it: every `err`
 *   buffer, this process' whole standard error, every redacted form, and the
 *   **fake supplicant's own log**, which redacts what it was sent exactly as
 *   the python one does.
 *
 *   And the proof is checked for being vacuous. The fake counts, separately
 *   and without writing it down, how many times the canary really arrived on
 *   the wire -- so a sweep that passes because nothing was ever sent fails
 *   instead.
 */
#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/document.h"
#include "ncfg/secrets.h"
#include "ncfg/supplicant.h"

#include "testdir.h"

#include <errno.h>
#include <fcntl.h>
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

/* The value nothing may repeat. Distinctive enough that finding it in a buffer
 * is never a coincidence, and long enough to be a legal WPA2 passphrase so
 * that the length check is not what refuses it. */
#define CANARY "zq7-CANARY-passphrase-must-never-be-printed-4f1e"

static int failures;

static void check(int condition, const char *what)
{
	printf("%-72s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

/* Every `err` buffer this file has filled, end to end, swept at the end. */
static char   every_message[64u * 1024u];
static size_t every_message_length;

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

/* A writable copy of a literal, from a fixed arena: the document's fields are
 * `char *`, and these run under ASan where a fixture nobody frees is a
 * failure. */
static char   arena[8u * 1024u];
static size_t arena_used;

static char *text(const char *value)
{
	size_t length = strlen(value) + 1u;
	char  *out;

	if (arena_used + length > sizeof(arena)) {
		printf("the fixture arena is full\n");
		exit(1);
	}
	out = arena + arena_used;
	memcpy(out, value, length);
	arena_used += length;
	return out;
}

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
static void join(char *out, size_t out_size, const char *dir, const char *leaf)
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

static void put(char *out, size_t out_size, const char *value)
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
static void address_for(struct sockaddr_un *out, const char *path)
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

static long long now_ms(void)
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

static void fake_say(struct fake *state, const char *line)
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
static void fake_log_command(struct fake *state, const char *command)
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

static void fake_reply(struct fake *state, const struct sockaddr_un *to, socklen_t to_length,
    const char *body, size_t length)
{
	/* A reply nobody is waiting for is not a reason to stop serving: a sender
	 * that has gone away gives ECONNREFUSED, which the python fake learned to
	 * swallow after it shut the whole thing down mid-suite. */
	(void)sendto(state->fd, body, length, 0, (const struct sockaddr *)to, to_length);
}

static void fake_broadcast(struct fake *state, const char *event)
{
	size_t which;

	for (which = 0; which < state->listeners; which++) {
		(void)sendto(state->fd, event, strlen(event), 0,
		    (const struct sockaddr *)&state->listener[which],
		    state->listener_length[which]);
	}
}

static void fake_attach(struct fake *state, const struct sockaddr_un *who, socklen_t length)
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

static int starts_with(const char *text_in, const char *prefix)
{
	return strncmp(text_in, prefix, strlen(prefix)) == 0;
}

static void fake_handle(struct fake *state, char *command, const struct sockaddr_un *from,
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
static void fake_serve(const char *path, const char *log_path, const char *count_path)
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

static int fake_start(const char *dir, const char *interface, const char *log_path)
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

static void fake_stop(void)
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
static char *fake_heard(void)
{
	size_t length = 0;
	char  *body = testdir_read(fake_log_path, &length);

	return body ? body : strdup("");
}

static void fake_forget(void)
{
	int log = open(fake_log_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);

	if (log >= 0) {
		(void)close(log);
	}
}

/* The fake's own count of how often the canary really crossed the socket, read
 * by asking it to write the number down on its way out. */
static unsigned long fake_canary_count(void)
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

/* ============================================================ the fixtures */

static void write_secret(const char *dir, const char *name, const char *body)
{
	char path[512];

	join(path, sizeof(path), dir, name);
	if (!testdir_write(path, body, strlen(body)) || chmod(path, (mode_t)0600) != 0) {
		printf("could not write the fixture secret %s\n", path);
		exit(1);
	}
}

static void a_network(ncfg_wifi_network_t *out, const char *id, const char *ssid,
    const char *secret_name)
{
	memset(out, 0, sizeof(*out));
	out->id = text(id);
	if (ssid) {
		out->ssid.has = 1;
		out->ssid.length = strlen(ssid);
		memcpy(out->ssid.bytes, ssid, out->ssid.length);
	}
	out->autoconnect = 1;
	if (secret_name) {
		out->security.kind = NCFG_SECURITY_PSK;
		out->security.psk.proto = NCFG_PSK_PROTO_WPA2;
		out->security.psk.passphrase.provider = NCFG_SECRET_PROVIDER_FILE;
		out->security.psk.passphrase.name = text(secret_name);
	} else {
		out->security.kind = NCFG_SECURITY_OPEN;
	}
}

/* ================================================================== checks */

/*
 * **A name that is a path is refused before the filesystem is touched.**
 *
 * The defect: joining a directory to an absolute name replaces the base, and
 * the two failure messages below the join distinguish "not there" from "there
 * and not connectable" -- so the pair answered, at the `observe` tier, whether
 * an arbitrary path exists. Measured against the daemon: `/etc/shadow` gave
 * "Permission denied", `/etc/nonexistent` gave "no control socket at ...".
 *
 * The assertion is on *which* refusal rather than only on there being one.
 * Every one of these would have failed anyway with the guard removed -- there
 * is no supplicant at any of them -- so a test that only asked "does this
 * error" would pass against the oracle it was written to close. What changes
 * is that the answer no longer depends on what is on disk. 0160.
 */
static void a_name_that_is_a_path_is_refused_without_looking(const char *dir)
{
	const char *names[] = { "/etc/shadow", "/etc/definitely-not-here", "../../etc/passwd",
		"..", "", "a name with spaces", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" };
	size_t      which;
	int         all = 1;

	for (which = 0; which < sizeof(names) / sizeof(names[0]); which++) {
		char message[NCFG_ERROR_MAX] = "";

		all = all && ncfg_supplicant_connect(dir, names[which], message,
		    sizeof(message)) == NULL &&
		    strstr(kept(message), "is not an interface name") != NULL &&
		    /* And it says nothing about a path, which is the oracle. */
		    strstr(message, "no control socket") == NULL;
	}
	check(all, "a name that is a path is refused as a name, never reported on as a path");
}

/*
 * And an ordinary name still reaches the filesystem to say what is wrong.
 *
 * The other half: a guard that refused everything would pass the check above
 * and take the diagnostic with it.
 */
static void an_ordinary_name_still_gets_the_ordinary_answer(const char *work_dir)
{
	char message[NCFG_ERROR_MAX] = "";
	char empty[512];

	join(empty, sizeof(empty), work_dir, "nothing-here");
	(void)mkdir(empty, (mode_t)0700);
	check(ncfg_supplicant_connect(empty, "wlan0", message, sizeof(message)) == NULL &&
	    strstr(kept(message), "no control socket at") != NULL &&
	    strstr(message, "wpa_supplicant running on wlan0") != NULL,
	    "a real name gets the real diagnosis, which names the interface");
}

/*
 * A shortened deadline governs the commands, not just the opening `PING`.
 *
 * This is the half an apply depends on and the half that is easy to lose: a
 * daemon can answer the `PING` and wedge before the first real command, so a
 * deadline that covered only the connect would leave every command after it on
 * the ten-second default. Measured against a fake that answered `PING` and then
 * nothing: ten seconds flat, per command, on the reconcile loop. 0114.
 *
 * **Timed rather than merely checked for an error**, because the wrong
 * behaviour here also returns an error -- just far too late to matter.
 */
static void the_deadline_outlives_the_connect(const char *dir)
{
	char                      message[NCFG_ERROR_MAX] = "";
	ncfg_supplicant_client_t *client = ncfg_supplicant_connect_within(dir, "wlan0", 250,
	    message, sizeof(message));
	long long                 started;
	long long                 waited;
	int                       refused;

	if (!client) {
		check(0, kept(message));
		return;
	}
	/* Answers this, and then nothing at all to what comes after it. */
	check(ncfg_supplicant_command(client, "SILENT_NEXT", message, sizeof(message)),
	    "a fake that will answer one command and then go quiet");
	started = now_ms();
	refused = !ncfg_supplicant_command(client, "SET update_config 0", message,
	    sizeof(message));
	waited = now_ms() - started;
	(void)kept(message);
	check(refused, "a command nothing answered cannot succeed");
	check(waited < 2000,
	    "and it waited the connect's deadline rather than the ten-second default");
	ncfg_supplicant_client_free(client);
}

/*
 * A reply that fills the buffer is an error, not an answer.
 *
 * **A unix datagram is truncated silently.** `recv` into a buffer smaller than
 * the datagram keeps the buffer's worth and drops the rest, with no error and
 * no flag -- so an oversized `SCAN_RESULTS` would come back as a shorter list of
 * access points, with the last row cut mid-field, and nothing anywhere saying
 * the list was incomplete. A network missing from a scan because it was
 * truncated off the end looks exactly like a network that is not there. 0224.
 */
static void a_reply_that_fills_the_buffer_is_refused_rather_than_used(const char *dir)
{
	char                      message[NCFG_ERROR_MAX] = "";
	char                      body[NCFG_SUPPLICANT_REPLY_MAX];
	ncfg_supplicant_client_t *client = ncfg_supplicant_connect_within(dir, "wlan0", 2000,
	    message, sizeof(message));
	int                       kind = 0;

	if (!client) {
		check(0, kept(message));
		return;
	}
	check(ncfg_supplicant_command(client, "HUGE_NEXT", message, sizeof(message)),
	    "a fake that will answer the next command with more than fits");
	check(!ncfg_supplicant_request(client, "SCAN_RESULTS", body, sizeof(body), &kind, message,
	    sizeof(message)), "a truncated reply is not an answer");
	check(strstr(kept(message), "cut short") != NULL, "and the failure says what happened");
	check(strstr(message, "SCAN_RESULTS") != NULL, "and which command it was about");
	ncfg_supplicant_client_free(client);
}

/*
 * The reply socket a client binds is recognised as netcfgd's own.
 *
 * The coupling this pins spans two places: what the client *names* its socket
 * and what a directory reader *skips*. A check asserting the prefix alone would
 * keep passing if the naming moved -- so the directory is read while a
 * connection is open, and every entry that is not the interface has to be
 * recognised. 0112.
 */
static void a_clients_own_reply_socket_is_not_an_interface(const char *dir)
{
	char                      message[NCFG_ERROR_MAX] = "";
	ncfg_supplicant_client_t *client = ncfg_supplicant_connect(dir, "wlan0", message,
	    sizeof(message));
	DIR                      *open_dir;
	const struct dirent      *found;
	size_t                    seen = 0;
	int                       all = 1;

	if (!client) {
		check(0, kept(message));
		return;
	}
	open_dir = opendir(dir);
	while (open_dir && (found = readdir(open_dir)) != NULL) {
		if (strcmp(found->d_name, ".") == 0 || strcmp(found->d_name, "..") == 0 ||
		    strcmp(found->d_name, "wlan0") == 0) {
			continue;
		}
		seen++;
		all = all && ncfg_supplicant_is_reply_socket(found->d_name);
	}
	if (open_dir) {
		(void)closedir(open_dir);
	}
	check(seen > 0u, "an open connection really did bind something in the control directory");
	check(all, "and every such entry is recognised rather than taken for an interface");
	check(!ncfg_supplicant_is_reply_socket("wlan0") &&
	    !ncfg_supplicant_is_reply_socket("p2p-dev-wlan0"),
	    "while a real interface socket is not one of ours");
	ncfg_supplicant_client_free(client);
}

/*
 * The two that mean nothing is there, and the ones that do not.
 *
 * A timeout is the shape of a daemon that is running and silent, and reading
 * it as absence tells the operator an access point was stopped while it is
 * still on the air with its passphrase in memory. Listed one by one so that a
 * rewrite widening the test has to delete an assertion rather than merely relax
 * a condition.
 */
static void a_silent_daemon_is_not_an_absent_one(void)
{
	check(ncfg_supplicant_nothing_is_listening(ENOENT), "no socket means nothing is there");
	check(ncfg_supplicant_nothing_is_listening(ECONNREFUSED),
	    "and so does a socket file nobody has open");
	check(!ncfg_supplicant_nothing_is_listening(EAGAIN), "a silent daemon is not an absent one");
	check(!ncfg_supplicant_nothing_is_listening(ETIMEDOUT), "nor is one that timed out");
	check(!ncfg_supplicant_nothing_is_listening(EACCES), "nor one that refused a permission");
}

/*
 * The reaper takes the dead and leaves everything else.
 *
 * Written as one directory holding every case at once, because what this has to
 * get right is not "does it delete" but "does it delete *only* that" -- and a
 * check with one candidate per run cannot fail in the way that matters.
 *
 * **The liveness question is asked of the kernel, not of `/proc`.** A pid is a
 * name that gets reused, and the numbers most likely to be taken are the low
 * ones, which on Linux belong to kernel threads that live as long as the boot:
 * `netcfgd-8-0` sat in `/run/wpa_supplicant` for three days because pid 8 is
 * `kworker/R-netns`. 0224.
 */
static void only_sockets_of_dead_processes_are_reaped(const char *work_dir)
{
	char               dir[512];
	char               leaf[64];
	char               path[512];
	int                mine;
	int                live;
	int                peer;
	int                connected;
	int                interface;
	int                malformed;
	int                truncated;
	struct sockaddr_un address;
	size_t             removed;
	int                left = 1;

	join(dir, sizeof(dir), work_dir, "reap");
	if (mkdir(dir, (mode_t)0700) != 0) {
		check(0, "a directory to sweep");
		return;
	}

	/* **What a socket left behind by a dead process actually is: a file with
	 * nothing bound to it.** Binding and closing gives exactly that -- closing
	 * a datagram socket does not unlink its path -- so this is the real
	 * article rather than a stand-in. The pid in the name is one that *is*
	 * alive, which is what the `/proc` check called a reason to keep it. */
	join(path, sizeof(path), dir, "netcfgd-1-9");
	address_for(&address, path);
	mine = socket(AF_UNIX, SOCK_DGRAM, 0);
	(void)bind(mine, (const struct sockaddr *)&address, sizeof(address));
	(void)close(mine);

	/* Ours, and the process holding it is this one. */
	(void)snprintf(leaf, sizeof(leaf), "netcfgd-%ld-0", (long)getpid());
	join(path, sizeof(path), dir, leaf);
	address_for(&address, path);
	mine = socket(AF_UNIX, SOCK_DGRAM, 0);
	(void)bind(mine, (const struct sockaddr *)&address, sizeof(address));

	/* **Another process' socket, and it is open.** Every other entry here is
	 * excluded by its name, its type, or by being ours, so without this one a
	 * reaper with no liveness check at all would pass. */
	join(path, sizeof(path), dir, "netcfgd-1-3");
	address_for(&address, path);
	live = socket(AF_UNIX, SOCK_DGRAM, 0);
	(void)bind(live, (const struct sockaddr *)&address, sizeof(address));

	/* **And the shape a real reply socket is in: bound, and connected to the
	 * supplicant.** The kernel refuses a second connect to it with `EPERM`
	 * rather than letting it through, so this is a different answer from the
	 * one above and has to be treated the same way. A reaper that removed
	 * anything it could not connect to would take every live client. */
	join(path, sizeof(path), dir, "netcfgd-1-4");
	address_for(&address, path);
	peer = socket(AF_UNIX, SOCK_DGRAM, 0);
	(void)bind(peer, (const struct sockaddr *)&address, sizeof(address));
	{
		struct sockaddr_un to_peer = address;

		join(path, sizeof(path), dir, "netcfgd-1-5");
		address_for(&address, path);
		connected = socket(AF_UNIX, SOCK_DGRAM, 0);
		(void)bind(connected, (const struct sockaddr *)&address, sizeof(address));
		(void)connect(connected, (const struct sockaddr *)&to_peer, sizeof(to_peer));
	}

	/* A real interface socket, which is what the directory is *for*. */
	join(path, sizeof(path), dir, "wlan0");
	address_for(&address, path);
	interface = socket(AF_UNIX, SOCK_DGRAM, 0);
	(void)bind(interface, (const struct sockaddr *)&address, sizeof(address));

	/* Shaped like ours and not a socket. A regular file with this name is not
	 * something netcfgd made, and a reaper that removes it is removing
	 * somebody else's file on the strength of its name alone. */
	join(path, sizeof(path), dir, "netcfgd-0-8");
	(void)testdir_write(path, "not a socket", 12u);

	/* Nearly ours: the serial is not a number, so the name did not come from
	 * the connect and the pid in it means nothing. */
	join(path, sizeof(path), dir, "netcfgd-0-x");
	address_for(&address, path);
	malformed = socket(AF_UNIX, SOCK_DGRAM, 0);
	(void)bind(malformed, (const struct sockaddr *)&address, sizeof(address));

	/* Ours in prefix only, with no serial at all. */
	join(path, sizeof(path), dir, "netcfgd-0");
	address_for(&address, path);
	truncated = socket(AF_UNIX, SOCK_DGRAM, 0);
	(void)bind(truncated, (const struct sockaddr *)&address, sizeof(address));

	removed = ncfg_supplicant_reap_reply_sockets(dir);
	check(removed == 1u, "exactly the one dead socket is taken");

	join(path, sizeof(path), dir, "netcfgd-1-9");
	check(!testdir_exists(path),
	    "and a dead socket under a pid something else now holds goes with it");
	{
		const char *survivors[] = { "netcfgd-1-3", "netcfgd-1-4", "netcfgd-1-5", "wlan0",
			"netcfgd-0-8", "netcfgd-0-x", "netcfgd-0" };
		size_t      which;

		(void)snprintf(leaf, sizeof(leaf), "netcfgd-%ld-0", (long)getpid());
		join(path, sizeof(path), dir, leaf);
		left = left && testdir_exists(path);
		for (which = 0; which < sizeof(survivors) / sizeof(survivors[0]); which++) {
			join(path, sizeof(path), dir, survivors[which]);
			left = left && testdir_exists(path);
		}
	}
	check(left, "and everything else -- live, connected, ours, a file, a name -- is left");

	(void)close(mine);
	(void)close(live);
	(void)close(peer);
	(void)close(connected);
	(void)close(interface);
	(void)close(malformed);
	(void)close(truncated);
}

/*
 * A reply is never handed back as an event, and an event never as a reply.
 *
 * Reading one as the other is the classic bug in a `wpa_supplicant` client: it
 * produces a status display that occasionally reports the previous command's
 * outcome. With the connection attached, both are on this socket at once, so
 * this is where the separation is actually exercised.
 */
static void events_and_replies_do_not_get_mixed_up(const char *dir)
{
	char                      message[NCFG_ERROR_MAX] = "";
	ncfg_supplicant_client_t *client = ncfg_supplicant_connect_within(dir, "wlan0", 2000,
	    message, sizeof(message));
	ncfg_supplicant_event_t   event;
	char                      body[NCFG_SUPPLICANT_REPLY_MAX];
	char                      name[64];
	int                       got = 0;

	if (!client) {
		check(0, kept(message));
		return;
	}
	check(ncfg_supplicant_attach(client, message, sizeof(message)),
	    "a connection that asked to be sent events");
	check(ncfg_supplicant_command(client,
	    "TROUBLE CTRL-EVENT-DISCONNECTED bssid=00:11:22:33:44:55 reason=3", message,
	    sizeof(message)), "and an event arriving while a command is in flight");
	/* The event was emitted before this reply, so a client that did not
	 * separate them would answer `STATUS` with the disconnect. */
	check(ncfg_supplicant_ask(client, "STATUS", body, sizeof(body), message,
	    sizeof(message)) && strstr(body, "wpa_state=COMPLETED") != NULL,
	    "the answer to a command is the command's, not the event that overtook it");
	check(ncfg_supplicant_next_event(client, 500, &event, &got, message, sizeof(message)) &&
	    !got, "and the event was consumed rather than left to be read as one later");

	check(ncfg_supplicant_command(client, "TROUBLE CTRL-EVENT-SCAN-RESULTS ", message,
	    sizeof(message)) &&
	    ncfg_supplicant_next_event(client, 1000, &event, &got, message, sizeof(message)) &&
	    got && strcmp(ncfg_supplicant_event_name(&event, name, sizeof(name)),
	    "CTRL-EVENT-SCAN-RESULTS") == 0,
	    "while an event with nothing outstanding is delivered as an event");
	ncfg_supplicant_client_free(client);
}

/*
 * A scan is waited for, because `SCAN` does not answer with results.
 *
 * `SCAN` queues one and returns at once; `SCAN_RESULTS` reads the cache the
 * last completed scan filled. Sending one and immediately reading the other
 * returns *the previous scan's* results, always -- measured at `ncfg wifi scan`
 * returning in 7 milliseconds and three consecutive calls giving 15, then 20,
 * then 20 access points. 0194.
 */
static void a_scan_waits_for_the_event_that_says_it_finished(const char *dir)
{
	char                      message[NCFG_ERROR_MAX] = "";
	ncfg_supplicant_client_t *client = ncfg_supplicant_connect_within(dir, "wlan0", 2000,
	    message, sizeof(message));

	if (!client) {
		check(0, kept(message));
		return;
	}
	/* The attach has to happen before `SCAN` is sent, which is why waiting is
	 * a separate call rather than part of one. */
	check(ncfg_supplicant_attach(client, message, sizeof(message)) &&
	    ncfg_supplicant_command(client, "SCAN", message, sizeof(message)) &&
	    ncfg_supplicant_wait_for_scan(client, 3000, message, sizeof(message)),
	    "a scan is finished when the supplicant says it is");

	/* `ret=` is the driver's own errno, negated: -16 is EBUSY, a radio doing
	 * something else. Passed through rather than translated, because the set
	 * is the kernel's and any translation here would be a partial one. */
	check(ncfg_supplicant_command(client, "FAIL_NEXT_SCAN -16", message, sizeof(message)) &&
	    ncfg_supplicant_command(client, "SCAN", message, sizeof(message)) &&
	    !ncfg_supplicant_wait_for_scan(client, 3000, message, sizeof(message)) &&
	    strstr(kept(message), "ret=-16") != NULL,
	    "and one that failed says so with the driver's own number");

	/* A radio that took the request and never came back waits out its
	 * patience and then says the results are stale rather than fresh. */
	check(ncfg_supplicant_command(client, "SILENT_NEXT", message, sizeof(message)) &&
	    ncfg_supplicant_command(client, "SCAN", message, sizeof(message)) == 0,
	    "a scan the radio swallowed is a command with no answer");
	check(!ncfg_supplicant_wait_for_scan(client, 300, message, sizeof(message)) &&
	    strstr(kept(message), "did not finish") != NULL,
	    "and the wait ends at its deadline rather than never");
	ncfg_supplicant_client_free(client);
}

/*
 * A join is waited for too, and `SELECT_NETWORK` answering OK is not one.
 *
 * Association, the key exchange and -- on an enterprise network -- a whole TLS
 * handshake all happen afterwards, and every way they fail is an event rather
 * than a reply. netcfgd used to return success the moment the command was
 * acknowledged, and `ncfg wifi connect` printed "joining; `ncfg wifi status`
 * says whether it worked" -- the program admitting it did not know the answer
 * to the question it had just been asked. On the network that started this
 * work that answer was forty-five consecutive authentication failures. 0197.
 */
static void a_join_is_waited_for_and_says_why_it_failed(const char *dir)
{
	char                      message[NCFG_ERROR_MAX] = "";
	ncfg_supplicant_client_t *client = ncfg_supplicant_connect_within(dir, "wlan0", 2000,
	    message, sizeof(message));

	if (!client) {
		check(0, kept(message));
		return;
	}
	check(ncfg_supplicant_attach(client, message, sizeof(message)) &&
	    ncfg_supplicant_command(client, "SELECT_NETWORK 0", message, sizeof(message)) &&
	    ncfg_supplicant_wait_for_connect(client, 3000, message, sizeof(message)),
	    "a join is done when the supplicant says the station connected");

	/* `WRONG_KEY` and `CONN_FAILED` send a person to different places, so the
	 * supplicant's own reason is worth more than any sentence here. */
	check(ncfg_supplicant_command(client, "FAIL_NEXT_JOIN WRONG_KEY", message,
	    sizeof(message)) &&
	    ncfg_supplicant_command(client, "SELECT_NETWORK 0", message, sizeof(message)) &&
	    !ncfg_supplicant_wait_for_connect(client, 3000, message, sizeof(message)) &&
	    strstr(kept(message), "WRONG_KEY") != NULL &&
	    strstr(message, "1 failed attempt") != NULL,
	    "and one that failed carries the supplicant's own reason and count");

	/* **A disconnect is not a failure.** `SELECT_NETWORK` leaves whatever the
	 * radio was on before it, so a disconnect is the ordinary first step of a
	 * join, and treating it as the outcome would fail every successful switch
	 * between networks. */
	check(ncfg_supplicant_command(client, "DISCONNECT_FIRST", message, sizeof(message)) &&
	    ncfg_supplicant_command(client, "SELECT_NETWORK 0", message, sizeof(message)) &&
	    ncfg_supplicant_wait_for_connect(client, 3000, message, sizeof(message)),
	    "while a disconnect on the way is the ordinary first step of a join");

	/* An access point that refuses the station answers in its own vocabulary
	 * too, and the status code is the part worth carrying. */
	check(ncfg_supplicant_command(client,
	    "TROUBLE CTRL-EVENT-ASSOC-REJECT bssid=00:11:22:33:44:55 status_code=17", message,
	    sizeof(message)) &&
	    !ncfg_supplicant_wait_for_connect(client, 1000, message, sizeof(message)) &&
	    strstr(kept(message), "status 17") != NULL,
	    "and a refusal by the access point is reported with its status code");
	ncfg_supplicant_client_free(client);
}

/* What a supplicant says it is on, and what state it is in. */
static void what_the_supplicant_says_it_is_on(const char *dir)
{
	char                      message[NCFG_ERROR_MAX] = "";
	ncfg_supplicant_client_t *client = ncfg_supplicant_connect_within(dir, "wlan0", 2000,
	    message, sizeof(message));
	ncfg_ssid_t               ssid;
	char                      bssid[32];
	char                      state[64];

	if (!client) {
		check(0, kept(message));
		return;
	}
	memset(&ssid, 0, sizeof(ssid));
	check(ncfg_supplicant_associated(client, &ssid, bssid, sizeof(bssid)) &&
	    ssid.length == 9u && memcmp(ssid.bytes, "HomeFiber", 9u) == 0 &&
	    strcmp(bssid, "00:11:22:33:44:55") == 0,
	    "both halves of an association come back, because resolving it needs both");
	check(ncfg_supplicant_state(client, state, sizeof(state), message, sizeof(message)) &&
	    strcmp(state, "COMPLETED") == 0, "and the supplicant's own state name with them");
	ncfg_supplicant_client_free(client);

	check(ncfg_supplicant_answers(dir, "wlan0"),
	    "a supplicant that completes a PING is one netcfgd may configure");
	check(!ncfg_supplicant_answers(dir, "wlan9"),
	    "and one whose socket is not there is not, without that being a crash");
}

/*
 * A whole network reaches the supplicant, in the order it has to.
 *
 * `ADD_NETWORK` first for the slot, every `SET_NETWORK` against it, and then
 * the enable -- or, where the document says the network is not joined by
 * itself, the disable. **Present but not joined** is what `autoconnect = false`
 * asks for: a network left enabled would be joined the moment it came in range.
 */
static void a_network_reaches_the_supplicant_in_order(const char *dir,
    const ncfg_secret_resolver_t *resolver)
{
	char                      message[NCFG_ERROR_MAX] = "";
	ncfg_supplicant_client_t *client;
	ncfg_wifi_network_t       network;
	uint32_t                  id = 999;
	char                     *heard;

	fake_forget();
	client = ncfg_supplicant_connect_within(dir, "wlan0", 2000, message, sizeof(message));
	if (!client) {
		check(0, kept(message));
		return;
	}
	a_network(&network, "Home", "HomeFiber", "pass");
	check(ncfg_supplicant_add_network(client, &network, NCFG_MAC_POLICY_PER_NETWORK, resolver,
	    &id, message, sizeof(message)) && id == 0u,
	    "a network is handed over and comes back with the slot it took");
	heard = fake_heard();
	check(strstr(heard, "\nADD_NETWORK\n") != NULL, "the supplicant was asked for a slot");
	/* Hex, so a name that reads like a command is a name. `HomeFiber` is
	 * 486f6d6546696265 72 without the space. */
	check(strstr(heard, "SET_NETWORK 0 ssid 486f6d654669626572") != NULL,
	    "the name went out as hex rather than as a quoted string");
	check(strstr(heard, "SET_NETWORK 0 mac_addr 1") != NULL,
	    "and the radio's address policy went with it, as it must for every policy");
	check(strstr(heard, "SET_NETWORK 0 psk \n") != NULL,
	    "and the passphrase was sent -- the fake's own log cuts it off there");
	check(strstr(heard, "\nENABLE_NETWORK 0\n") != NULL,
	    "and a network that joins by itself was enabled");
	free(heard);

	/* The other half: present but not joined. */
	fake_forget();
	network.autoconnect = 0;
	check(ncfg_supplicant_add_network(client, &network, NCFG_MAC_POLICY_PERMANENT, resolver,
	    &id, message, sizeof(message)), "a network the operator joins by hand is handed over");
	heard = fake_heard();
	check(strstr(heard, "\nDISABLE_NETWORK 0\n") != NULL &&
	    strstr(heard, "\nENABLE_NETWORK 0\n") == NULL,
	    "and left disabled, because `autoconnect = false` is not `join when in range`");
	free(heard);
	ncfg_supplicant_client_free(client);
}

/*
 * A network named by address reads its name off the last scan.
 *
 * WPA derives its key from the passphrase *and* the SSID, so there is nothing
 * to send without a name -- and no `SCAN` is issued to get one, because a scan
 * takes seconds, interrupts traffic on the radio, and this runs inside an
 * apply. 0090.
 */
static void a_network_named_by_address_learns_its_name_over_the_socket(const char *dir,
    const ncfg_secret_resolver_t *resolver)
{
	char                      message[NCFG_ERROR_MAX] = "";
	ncfg_supplicant_client_t *client;
	ncfg_wifi_network_t       network;
	char                     *addresses[1];
	uint32_t                  id = 999;
	char                     *heard;

	fake_forget();
	client = ncfg_supplicant_connect_within(dir, "wlan0", 2000, message, sizeof(message));
	if (!client) {
		check(0, kept(message));
		return;
	}
	a_network(&network, "Lobby", NULL, "pass");
	addresses[0] = text("00:11:22:33:44:55");
	network.bssid = addresses;
	network.bssid_count = 1u;
	check(ncfg_supplicant_add_network(client, &network, NCFG_MAC_POLICY_PERMANENT, resolver,
	    &id, message, sizeof(message)), "a network named by address is still configurable");
	heard = fake_heard();
	check(strstr(heard, "\nSCAN_RESULTS\n") != NULL && strstr(heard, "\nSCAN\n") == NULL,
	    "the name came off the last scan, and no new scan was asked for");
	check(strstr(heard, "SET_NETWORK 0 ssid 486f6d654669626572") != NULL,
	    "and it is the name that access point advertises");
	free(heard);

	/* And one whose access points are not in range leaves nothing behind. */
	fake_forget();
	addresses[0] = text("de:ad:be:ef:00:00");
	message[0] = '\0';
	check(!ncfg_supplicant_add_network(client, &network, NCFG_MAC_POLICY_PERMANENT, resolver,
	    &id, message, sizeof(message)) &&
	    strstr(kept(message), "de:ad:be:ef:00:00") != NULL,
	    "an access point out of range is refused with its address, not with `not found`");
	heard = fake_heard();
	check(strstr(heard, "ADD_NETWORK") == NULL,
	    "and nothing was added, so there is no half-configured network to explain");
	free(heard);
	ncfg_supplicant_client_free(client);
}

/*
 * A setting the supplicant refuses takes the network away again.
 *
 * **The half-configured network is worse than none**: it would sit in the
 * supplicant's list looking like something netcfgd put there on purpose. The
 * removal happens before the failure is reported, and the failure quotes the
 * **redacted** form -- because the command most likely to be refused is the one
 * carrying the passphrase.
 */
static void a_refused_setting_takes_the_network_away_again(const char *dir,
    const ncfg_secret_resolver_t *resolver)
{
	char                      message[NCFG_ERROR_MAX] = "";
	ncfg_supplicant_client_t *client;
	ncfg_wifi_network_t       network;
	uint32_t                  id = 999;
	char                     *heard;

	fake_forget();
	client = ncfg_supplicant_connect_within(dir, "wlan0", 2000, message, sizeof(message));
	if (!client) {
		check(0, kept(message));
		return;
	}
	check(ncfg_supplicant_command(client, "REFUSE_PSK", message, sizeof(message)),
	    "a supplicant that will refuse the one setting carrying the credential");
	a_network(&network, "Home", "HomeFiber", "canary");
	message[0] = '\0';
	check(!ncfg_supplicant_add_network(client, &network, NCFG_MAC_POLICY_PERMANENT, resolver,
	    &id, message, sizeof(message)), "the network cannot be configured");
	check(strstr(kept(message), "SET_NETWORK 0 psk") != NULL &&
	    strstr(message, "<redacted>") != NULL,
	    "and the failure names the setting that was refused, redacted");
	/* **This is where the Rust leaks.** There, `add_network` formats
	 * `setting.redacted(id)` and then interpolates the error from
	 * `Client::command`, whose own message is "`{command}` answered ... rather
	 * than OK" with the command being the line carrying the passphrase -- so
	 * the redaction is undone one format string later. */
	check(strstr(message, CANARY) == NULL,
	    "and the sentence it is wrapped in does not undo the redaction");
	heard = fake_heard();
	check(strstr(heard, "\nREMOVE_NETWORK 0\n") != NULL,
	    "and the half-configured network was taken away before anything was reported");
	free(heard);
	ncfg_supplicant_client_free(client);
}

/*
 * The whole conversation, driven with a credential nothing may repeat.
 *
 * Every shape a credential reaches the supplicant in -- a WPA2 passphrase, a
 * WPA3 password, an EAP password -- and every failure each of them has, so that
 * the sweep at the end covers the paths a leak would actually appear in. The
 * leak, when it comes, will be in the *next* failure path somebody adds, which
 * is why this drives them all rather than one.
 */
static void the_canary_goes_everywhere_a_credential_goes(const char *dir,
    const ncfg_secret_resolver_t *resolver)
{
	char                      message[NCFG_ERROR_MAX] = "";
	ncfg_supplicant_client_t *client;
	ncfg_wifi_network_t       network;
	ncfg_secret_ref_t         password;
	uint32_t                  id = 999;
	char                      digest[NCFG_SUPPLICANT_SSID_HEX_SIZE];
	int                       protos[3] = { NCFG_PSK_PROTO_WPA2, NCFG_PSK_PROTO_WPA3,
		NCFG_PSK_PROTO_WPA2_WPA3 };
	size_t                    which;
	int                       all = 1;

	client = ncfg_supplicant_connect_within(dir, "wlan0", 2000, message, sizeof(message));
	if (!client) {
		check(0, kept(message));
		return;
	}
	/* The three personal generations, each sent for real. */
	for (which = 0; which < 3u; which++) {
		a_network(&network, "Canary", "HomeFiber", "canary");
		network.security.psk.proto = protos[which];
		message[0] = '\0';
		all = all && ncfg_supplicant_add_network(client, &network,
		    NCFG_MAC_POLICY_PER_CONNECTION, resolver, &id, message, sizeof(message));
		(void)kept(message);
	}
	check(all, "every WPA generation carries the credential to the supplicant");

	/* And the enterprise shape, whose password is a different field. */
	memset(&password, 0, sizeof(password));
	password.provider = NCFG_SECRET_PROVIDER_FILE;
	password.name = text("canary");
	a_network(&network, "Corp", "HomeFiber", NULL);
	memset(&network.security, 0, sizeof(network.security));
	network.security.kind = NCFG_SECURITY_EAP;
	network.security.eap.method = NCFG_EAP_METHOD_PEAP;
	network.security.eap.identity = text("user@corp.example");
	network.security.eap.password = &password;
	message[0] = '\0';
	check(ncfg_supplicant_add_network(client, &network, NCFG_MAC_POLICY_PERMANENT, resolver,
	    &id, message, sizeof(message)),
	    "and an enterprise network carries its password the same way");
	(void)kept(message);

	/* The digest, which covers the passphrase and must carry none of it. */
	a_network(&network, "Canary", "HomeFiber", "canary");
	message[0] = '\0';
	check(ncfg_supplicant_fingerprint(&network, 1u, NCFG_MAC_POLICY_PERMANENT, 1, 1, resolver,
	    digest, message, sizeof(message)) && strstr(digest, CANARY) == NULL,
	    "the digest covers the credential and carries none of it");
	(void)kept(message);

	/* Every failure the settings can have, driven with the canary in place. */
	{
		ncfg_supplicant_settings_t settings;
		char                      *bad[1];

		a_network(&network, "Canary", "HomeFiber", "canary");
		bad[0] = text("not-a-mac");
		network.bssid = bad;
		network.bssid_count = 1u;
		message[0] = '\0';
		(void)ncfg_supplicant_settings(&network, NULL, NCFG_MAC_POLICY_PERMANENT, resolver,
		    &settings, message, sizeof(message));
		(void)kept(message);

		a_network(&network, "Canary", NULL, "canary");
		message[0] = '\0';
		(void)ncfg_supplicant_settings(&network, NULL, NCFG_MAC_POLICY_PERMANENT, resolver,
		    &settings, message, sizeof(message));
		(void)kept(message);

		/* A credential that will not resolve at all, which is the path whose
		 * message names the reference rather than the value. */
		a_network(&network, "Canary", "HomeFiber", "nothing-of-that-name");
		message[0] = '\0';
		(void)ncfg_supplicant_settings(&network, NULL, NCFG_MAC_POLICY_PERMANENT, resolver,
		    &settings, message, sizeof(message));
		(void)kept(message);
	}

	/* And the redacted forms of everything a rendered network holds. */
	{
		ncfg_supplicant_settings_t settings;
		size_t                     index;
		int                        quiet = 1;

		a_network(&network, "Canary", "HomeFiber", "canary");
		if (ncfg_supplicant_settings(&network, NULL, NCFG_MAC_POLICY_PERMANENT, resolver,
		    &settings, message, sizeof(message))) {
			for (index = 0; index < settings.count; index++) {
				ncfg_buf_t shown;

				ncfg_buf_init(&shown, 0);
				ncfg_supplicant_setting_redacted(&settings.items[index], 0, &shown);
				quiet = quiet && strstr(ncfg_buf_text(&shown), CANARY) == NULL;
				(void)kept(ncfg_buf_text(&shown));
				ncfg_buf_free(&shown);
			}
			ncfg_supplicant_settings_free(&settings);
		}
		check(quiet, "and no setting's printable form carries the material");
	}
	ncfg_supplicant_client_free(client);
}

/* ==================================================================== main */

int main(void)
{
	const char            *work_dir = testdir_make("supplicant-client");
	char                   ctrl_dir[320];
	char                   secrets_dir[320];
	char                   log_path[384];
	char                   stderr_path[384];
	ncfg_secret_resolver_t resolver;
	int                    saved_stderr = dup(STDERR_FILENO);
	int                    log;

	printf("== supplicant_client_test in %s\n", work_dir);
	join(ctrl_dir, sizeof(ctrl_dir), work_dir, "ctrl");
	join(secrets_dir, sizeof(secrets_dir), work_dir, "secrets");
	join(log_path, sizeof(log_path), work_dir, "heard");
	join(stderr_path, sizeof(stderr_path), work_dir, "stderr.log");
	if (mkdir(ctrl_dir, (mode_t)0700) != 0 || mkdir(secrets_dir, (mode_t)0700) != 0) {
		printf("could not make the directories to work in\n");
		return 1;
	}
	write_secret(secrets_dir, "pass", "hunter2hunter2");
	write_secret(secrets_dir, "canary", CANARY);
	resolver.secrets_dir = secrets_dir;
	resolver.materialise_dir = NULL;

	/* **The real control directory is read and never used.** A test that
	 * connected to it would be talking to the supplicant managing this
	 * machine's wifi. */
	{
		char where[256];

		where[0] = '\0';
		char message[NCFG_ERROR_MAX];

		check(ncfg_supplicant_ctrl_dir(where, sizeof(where), message, sizeof(message)) &&
		    strcmp(where, NCFG_SUPPLICANT_CTRL_DIR) == 0,
		    "the default control directory is the supplicant's own, unless overridden");
	}

	/* Everything netcfgd would log goes here for the length of the run, and is
	 * swept at the end. A leak into a log line is a leak into every log
	 * aggregator downstream. */
	log = open(stderr_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (log >= 0) {
		(void)dup2(log, STDERR_FILENO);
		(void)close(log);
	}

	a_name_that_is_a_path_is_refused_without_looking(ctrl_dir);
	an_ordinary_name_still_gets_the_ordinary_answer(work_dir);
	a_silent_daemon_is_not_an_absent_one();
	only_sockets_of_dead_processes_are_reaped(work_dir);

	if (!fake_start(ctrl_dir, "wlan0", log_path)) {
		fake_stop();
		printf("the fake supplicant did not bind its socket\n");
		return 1;
	}
	the_deadline_outlives_the_connect(ctrl_dir);
	a_reply_that_fills_the_buffer_is_refused_rather_than_used(ctrl_dir);
	a_clients_own_reply_socket_is_not_an_interface(ctrl_dir);
	events_and_replies_do_not_get_mixed_up(ctrl_dir);
	a_scan_waits_for_the_event_that_says_it_finished(ctrl_dir);
	a_join_is_waited_for_and_says_why_it_failed(ctrl_dir);
	what_the_supplicant_says_it_is_on(ctrl_dir);
	a_network_reaches_the_supplicant_in_order(ctrl_dir, &resolver);
	a_network_named_by_address_learns_its_name_over_the_socket(ctrl_dir, &resolver);
	a_refused_setting_takes_the_network_away_again(ctrl_dir, &resolver);
	the_canary_goes_everywhere_a_credential_goes(ctrl_dir, &resolver);
	/* Stopped before the sweep, so its own log is complete and its count of
	 * what really crossed the socket has been written down. */
	fake_stop();

	if (saved_stderr >= 0) {
		(void)dup2(saved_stderr, STDERR_FILENO);
		(void)close(saved_stderr);
	}

	/* ------------------------------------------------------------- the sweep */

	/* **Checked for being vacuous first.** A sweep that passes because the
	 * credential never left this process proves nothing at all, so the fake's
	 * own count of how many times it really arrived is what makes the three
	 * silences below evidence. */
	{
		unsigned long arrived = fake_canary_count();

		check(arrived >= 4u,
		    "the credential really did cross the socket, which is what makes the rest a proof");
		printf("    (the fake supplicant was sent it %lu times)\n", arrived);
	}
	{
		size_t length = 0;
		char  *said = testdir_read(stderr_path, &length);

		check(said && !strstr(said, CANARY),
		    "nothing this module said on stderr carries the material");
		free(said);
	}
	{
		char *heard = fake_heard();

		check(strstr(heard, "SET_NETWORK 0 psk") != NULL && !strstr(heard, CANARY),
		    "and the fake's own log has the commands with the material cut out of them");
		free(heard);
	}
	check(every_message_length > 0u && !strstr(every_message, CANARY),
	    "and neither does any of the diagnostics it handed back");
	printf("    (%zu bytes of diagnostics were swept)\n", every_message_length);

	testdir_remove(work_dir);
	if (failures == 0) {
		printf("supplicant_client_test: all checks passed\n");
	} else {
		printf("supplicant_client_test: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
