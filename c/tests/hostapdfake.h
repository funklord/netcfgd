/*
 * hostapdfake.h -- a stand-in for hostapd's control socket.
 *
 * WHY THIS IS A HEADER AND NOT A COPY PER FILE
 *   `service_test.c` grew it first, for the executor's access-control ops, and
 *   the observer needs the same thing for the round trip that reads those lists
 *   back. Two stand-ins for one daemon is two beliefs about its protocol: the
 *   reply shape, the `FAIL` on a duplicate, what a wedged one does. They can
 *   drift the way any pair can, and what would drift is the thing both sides of
 *   netcfgd are written against.
 *
 *   Everything is `static` so a file that uses two of these does not have to
 *   explain the rest to `-Wunused-function`, which is `planfix.h`'s
 *   arrangement.
 *
 * WHAT IT IS
 *   A forked process bound to a `SOCK_DGRAM` unix socket, answering the
 *   commands netcfgd sends and appending every one it heard to a file the test
 *   can read back. It is stopped **by the recorded pid and its group**, never
 *   by name or pattern -- so a fixture cannot take down a daemon somebody else
 *   started.
 */
#ifndef NCFG_TESTS_HOSTAPDFAKE_H
#define NCFG_TESTS_HOSTAPDFAKE_H

#include "testdir.h"

#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Where the log of heard commands is written. The includer sets it before
 * starting one; a NULL leaves the log beside the socket. */
static const char *hostapdfake_log_dir;

static inline long long hostapdfake_now_ms(void)
{
	struct timespec when;

	(void)clock_gettime(CLOCK_MONOTONIC, &when);
	return (long long)when.tv_sec * 1000 + when.tv_nsec / 1000000;
}

#define FAKE_BUFFER 4096u
#define FAKE_ACL_MAX 8u

struct fake {
	int    fd;
	int    log;
	/* Answers nothing, ever: a daemon that bound its socket and went silent,
	 * which is the state 0109 is about and which nothing else here produces. */
	int    wedged;
	/*
	 * Answers `PING` and nothing else.
	 *
	 * **A different state from `wedged`, and the difference is where it fails.**
	 * A caller that pings on connect gets a client back from this one and then
	 * finds the command it actually wanted unanswered -- so it exercises the
	 * "connected and then would not answer" path, which `wedged` never reaches
	 * because it fails at the connect. That path had no case at all until this
	 * flag: two sabotages of it turned nothing red.
	 */
	int    deaf;
	char   accept_list[FAKE_ACL_MAX][18];
	size_t accept_count;
	char   deny_list[FAKE_ACL_MAX][18];
	size_t deny_count;
	/* What `STATUS` reports, empty for a radio that has joined nothing. */
	char   associated[64];
	/* What `LIST_NETWORKS` holds, as one ssid per slot. */
	char   networks[4][64];
	size_t network_count;
};

static struct fake fake_config;

static inline void fake_note(struct fake *state, const char *command)
{
	if (state->log >= 0) {
		(void)write(state->log, command, strlen(command));
		(void)write(state->log, "\n", 1u);
	}
}

static inline void fake_reply(struct fake *state, const struct sockaddr_un *to, socklen_t to_length,
    const char *body)
{
	if (state->wedged) {
		return;
	}
	(void)sendto(state->fd, body, strlen(body), 0, (const struct sockaddr *)to, to_length);
}

static inline int starts_with(const char *text_in, const char *prefix)
{
	return strncmp(text_in, prefix, strlen(prefix)) == 0;
}

/* One of the two lists, by the command that names it. */
static inline char (*acl_of(struct fake *state, const char *command, size_t **count_out))[18]
{
	if (starts_with(command, "ACCEPT_ACL")) {
		*count_out = &state->accept_count;
		return state->accept_list;
	}
	*count_out = &state->deny_count;
	return state->deny_list;
}

static inline void fake_acl(struct fake *state, const char *command, const struct sockaddr_un *from,
    socklen_t from_length)
{
	size_t *count;
	char  (*list)[18] = acl_of(state, command, &count);
	const char *verb = strchr(command, ' ');
	char        joined[FAKE_BUFFER];
	size_t      i;

	verb = verb ? verb + 1 : "";
	if (starts_with(verb, "SHOW")) {
		/* `hostapd_ctrl_iface_acl_show_mac` prints `MACSTR " VLAN_ID=%d\n"` per
		 * entry and *nothing at all* for an empty list. */
		joined[0] = '\0';
		for (i = 0; i < *count; i++) {
			char line[64];

			(void)snprintf(line, sizeof(line), "%s VLAN_ID=0\n", list[i]);
			(void)strncat(joined, line, sizeof(joined) - strlen(joined) - 1u);
		}
		fake_reply(state, from, from_length, joined);
		return;
	}
	if (starts_with(verb, "ADD_MAC ")) {
		const char *address = verb + strlen("ADD_MAC ");

		for (i = 0; i < *count; i++) {
			if (strcmp(list[i], address) == 0) {
				/* `hostapd_add_acl_maclist` refuses a duplicate. This is the
				 * answer the executor must never provoke, and provoking it is
				 * what an executor that did not read first would do. */
				fake_reply(state, from, from_length, "FAIL\n");
				return;
			}
		}
		if (*count < FAKE_ACL_MAX) {
			(void)snprintf(list[*count], sizeof(list[*count]), "%s", address);
			(*count)++;
		}
		fake_reply(state, from, from_length, "OK\n");
		return;
	}
	if (starts_with(verb, "DEL_MAC ")) {
		const char *address = verb + strlen("DEL_MAC ");

		for (i = 0; i < *count; i++) {
			if (strcmp(list[i], address) == 0) {
				/* `memmove` rather than a copy per entry: the source and
				 * the destination are the same array, which is exactly
				 * what `-Wrestrict` is about. */
				if (i + 1u < *count) {
					memmove(list[i], list[i + 1u],
					    (*count - i - 1u) * sizeof(list[0]));
				}
				(*count)--;
				break;
			}
		}
		fake_reply(state, from, from_length, "OK\n");
		return;
	}
	fake_reply(state, from, from_length, "FAIL\n");
}

static inline void fake_handle(struct fake *state, const char *command, const struct sockaddr_un *from,
    socklen_t from_length)
{
	char body[FAKE_BUFFER];

	fake_note(state, command);
	if (state->wedged) {
		return;
	}
	if (strcmp(command, "PING") == 0) {
		fake_reply(state, from, from_length, "PONG\n");
		return;
	}
	if (starts_with(command, "ACCEPT_ACL") || starts_with(command, "DENY_ACL")) {
		if (state->deaf) {
			return;
		}
		fake_acl(state, command, from, from_length);
		return;
	}
	if (strcmp(command, "STATUS") == 0) {
		(void)snprintf(body, sizeof(body), "bssid=00:11:22:33:44:55\n%s%s%swpa_state=%s\n",
		    state->associated[0] ? "ssid=" : "", state->associated,
		    state->associated[0] ? "\n" : "",
		    state->associated[0] ? "COMPLETED" : "SCANNING");
		fake_reply(state, from, from_length, body);
		return;
	}
	if (strcmp(command, "LIST_NETWORKS") == 0) {
		size_t i;

		(void)snprintf(body, sizeof(body), "network id / ssid / bssid / flags\n");
		for (i = 0; i < state->network_count; i++) {
			char line[128];

			(void)snprintf(line, sizeof(line), "%zu\t%s\tany\t\n", i,
			    state->networks[i]);
			(void)strncat(body, line, sizeof(body) - strlen(body) - 1u);
		}
		fake_reply(state, from, from_length, body);
		return;
	}
	if (strcmp(command, "ADD_NETWORK") == 0) {
		fake_reply(state, from, from_length, "0\n");
		return;
	}
	if (starts_with(command, "SELECT_NETWORK ")) {
		/* A join is two things: OK to the command, and later an event saying
		 * what became of it. 0197. */
		fake_reply(state, from, from_length, "OK\n");
		(void)sendto(state->fd,
		    "<3>CTRL-EVENT-CONNECTED - Connection to 00:11:22:33:44:55 completed "
		    "[id=0 id_str=]", 88u, 0, (const struct sockaddr *)from, from_length);
		return;
	}
	if (strcmp(command, "TERMINATE") == 0 || strcmp(command, "DISCONNECT") == 0 ||
	    strcmp(command, "ATTACH") == 0 || strcmp(command, "DETACH") == 0 ||
	    starts_with(command, "SET ") || starts_with(command, "SET_NETWORK ") ||
	    starts_with(command, "ENABLE_NETWORK ") || starts_with(command, "DISABLE_NETWORK ") ||
	    starts_with(command, "REMOVE_NETWORK ")) {
		fake_reply(state, from, from_length, "OK\n");
		return;
	}
	/* Everything netcfgd might send that this does not model. FAIL is a real
	 * answer from both daemons and netcfgd handles it; inventing a success
	 * would make a check pass for a command that did nothing. */
	fake_reply(state, from, from_length, "FAIL\n");
}

static inline void fake_serve(const char *path, const char *log_path)
{
	struct fake        state = fake_config;
	struct sockaddr_un address;
	struct timeval     slice;

	state.log = open(log_path, O_WRONLY | O_CREAT | O_APPEND, 0600);
	state.fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (state.fd < 0 || state.log < 0) {
		_exit(1);
	}
	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	/* `sun_path` is 108 bytes and a fixture path is not, so this is a copy
	 * that refuses rather than one the compiler has to reason about: a socket
	 * bound at a truncated path is a fixture checking nothing. */
	if (strlen(path) >= sizeof(address.sun_path)) {
		_exit(1);
	}
	memcpy(address.sun_path, path, strlen(path));
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
/* Generous, and checked: the path is a directory this test made plus an
 * interface name, and a truncated socket path binds somewhere nobody looks. */
static char  fake_socket[1024];
static char  fake_log[1024];

/* Start one, and wait for its socket rather than sleeping: the socket
 * appearing is the readiness signal, which is what netcfgd itself waits for. */
static inline int fake_start(const char *dir, const char *interface)
{
	long long deadline;

	(void)snprintf(fake_socket, sizeof(fake_socket), "%s/%s", dir, interface);
	(void)snprintf(fake_log, sizeof(fake_log), "%s/%s.heard",
	    hostapdfake_log_dir ? hostapdfake_log_dir : dir, interface);
	(void)unlink(fake_log);
	fake_pid = fork();
	if (fake_pid < 0) {
		return 0;
	}
	if (fake_pid == 0) {
		/* **Its own process group**, so the parent can take down everything
		 * the fake started rather than one pid of it. */
		(void)setpgid(0, 0);
		fake_serve(fake_socket, fake_log);
		_exit(0);
	}
	(void)setpgid(fake_pid, fake_pid);
	deadline = hostapdfake_now_ms() + 3000;
	while (hostapdfake_now_ms() < deadline) {
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

/* Stopped by **the recorded pid** and its group, never by name or pattern. */
static inline void fake_stop(void)
{
	int status = 0;

	if (fake_pid <= 0) {
		return;
	}
	(void)kill(-fake_pid, SIGTERM);
	(void)kill(fake_pid, SIGTERM);
	(void)waitpid(fake_pid, &status, 0);
	fake_pid = -1;
	(void)unlink(fake_socket);
}

/* What the fake was sent since it started. The caller frees it. */
static char *fake_heard(void)
{
	size_t length = 0;
	char  *body = testdir_read(fake_log, &length);

	return body ? body : strdup("");
}

/* How many times a command was sent. The count, not the presence: an op that
 * is idempotent sends a command once and not twice, and only a count can tell
 * those apart. */
static inline int heard_times(const char *needle)
{
	char *body = fake_heard();
	char *at = body;
	int   seen = 0;

	while ((at = strstr(at, needle)) != NULL) {
		seen++;
		at += strlen(needle);
	}
	free(body);
	return seen;
}


#endif /* NCFG_TESTS_HOSTAPDFAKE_H */
