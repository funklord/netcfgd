/*
 * management.c -- OpenVPN's text control protocol, on a unix stream socket.
 *
 * The third daemon of this shape after `wpa_supplicant` and `hostapd`, and the
 * first that is a **stream** socket where `wpa_ctrl` is a datagram one -- so
 * this is a separate client rather than a reuse. See `openvpn.h` for why a
 * reply is read until it *is* an answer rather than by testing for `>`.
 */
#include "ncfg/openvpn.h"

#include "ncfg/base.h"

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <unistd.h>

/*
 * How long to wait for the daemon to answer.
 *
 * Short, and for the reason hostapd's ACL read is: this runs where an apply is
 * waiting, and the daemon is answering from memory. A tunnel that has wedged
 * should not hold the executor.
 */
#define MANAGEMENT_TIMEOUT_SECONDS 2

/*
 * A line is bounded, because this is a daemon reading another process's output.
 * OpenVPN's own are far shorter; a stream that never sent a newline would
 * otherwise be a caller that never returns.
 */
#define MANAGEMENT_LINE_MAX 4096

struct ncfg_openvpn_management {
	int fd;
	/* What has been read and not yet consumed as a line. */
	char   held[MANAGEMENT_LINE_MAX];
	size_t held_length;
};

ncfg_openvpn_management_t *ncfg_openvpn_connect(const char *socket_path, char *err,
    size_t err_size)
{
	ncfg_openvpn_management_t *management;
	struct sockaddr_un         address;
	struct timeval             deadline;
	size_t                     length;

	if (!socket_path) {
		ncfg_error_set(err, err_size, "a management socket was opened with no path");
		return NULL;
	}
	length = strlen(socket_path);
	if (length + 1u > sizeof(address.sun_path)) {
		ncfg_error_set(err, err_size, "%s is longer than a unix socket path may be",
		    socket_path);
		return NULL;
	}
	management = calloc(1u, sizeof(*management));
	if (!management) {
		ncfg_error_set(err, err_size, "out of memory opening a management socket");
		return NULL;
	}
	management->fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (management->fd < 0) {
		ncfg_error_set(err, err_size, "cannot open a management socket: %s", strerror(errno));
		free(management);
		return NULL;
	}
	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	memcpy(address.sun_path, socket_path, length + 1u);
	if (connect(management->fd, (const struct sockaddr *)&address, sizeof(address)) != 0) {
		/* Nothing listening is the ordinary case for a tunnel that is not
		 * running, so this is not shouted about here -- the caller decides what
		 * it means, and for a stop it means "ask the pid file next". */
		ncfg_error_set(err, err_size, "nothing is listening on %s: %s", socket_path,
		    strerror(errno));
		(void)close(management->fd);
		free(management);
		return NULL;
	}
	deadline.tv_sec = MANAGEMENT_TIMEOUT_SECONDS;
	deadline.tv_usec = 0;
	(void)setsockopt(management->fd, SOL_SOCKET, SO_RCVTIMEO, &deadline, sizeof(deadline));
	(void)setsockopt(management->fd, SOL_SOCKET, SO_SNDTIMEO, &deadline, sizeof(deadline));
	return management;
}

void ncfg_openvpn_disconnect(ncfg_openvpn_management_t *management)
{
	if (!management) {
		return;
	}
	if (management->fd >= 0) {
		(void)close(management->fd);
	}
	free(management);
}

/*
 * The next whole line, without its terminator, into `line`.
 *
 * 0 at the end of the stream, on a timeout, or where a line would be longer
 * than the buffer -- all of which end the read rather than being distinguished,
 * because the caller's answer is "no answer to this command" in every case.
 */
static int next_line(ncfg_openvpn_management_t *management, char *line, size_t line_size)
{
	for (;;) {
		char  *newline = memchr(management->held, '\n', management->held_length);
		ssize_t got;

		if (newline) {
			size_t length = (size_t)(newline - management->held);
			size_t consumed = length + 1u;

			if (length + 1u > line_size) {
				return 0;
			}
			memcpy(line, management->held, length);
			line[length] = '\0';
			/* Trailing carriage returns trimmed with the rest: openvpn writes
			 * `\r\n` on some builds and the answer is the same either way. */
			while (length > 0u && (line[length - 1u] == '\r' ||
			    line[length - 1u] == ' ')) {
				line[--length] = '\0';
			}
			memmove(management->held, management->held + consumed,
			    management->held_length - consumed);
			management->held_length -= consumed;
			return 1;
		}
		if (management->held_length == sizeof(management->held)) {
			/* A line longer than this buffer. Refused rather than grown: a
			 * daemon that never sends a newline must not become a caller that
			 * never returns. */
			return 0;
		}
		got = read(management->fd, management->held + management->held_length,
		    sizeof(management->held) - management->held_length);
		if (got < 0 && errno == EINTR) {
			continue;
		}
		if (got <= 0) {
			return 0;
		}
		management->held_length += (size_t)got;
	}
}

int ncfg_openvpn_command(ncfg_openvpn_management_t *management, const char *command, char *reply,
    size_t reply_size, char *err, size_t err_size)
{
	char        line[MANAGEMENT_LINE_MAX];
	const char *at;
	size_t      left;

	if (reply && reply_size > 0u) {
		reply[0] = '\0';
	}
	if (!management || !command) {
		ncfg_error_set(err, err_size, "a management command was sent with nothing to send");
		return 0;
	}
	at = command;
	left = strlen(command);
	while (left > 0u) {
		ssize_t put = write(management->fd, at, left);

		if (put < 0) {
			if (errno == EINTR) {
				continue;
			}
			ncfg_error_set(err, err_size, "could not send `%s`: %s", command,
			    strerror(errno));
			return 0;
		}
		at += put;
		left -= (size_t)put;
	}
	if (write(management->fd, "\n", 1u) != 1) {
		ncfg_error_set(err, err_size, "could not send `%s`: %s", command, strerror(errno));
		return 0;
	}

	/* **Read until a line is an answer.** OpenVPN greets a new client with
	 * `>INFO:` before it is asked anything and emits further `>`-prefixed
	 * notifications whenever it likes, interleaved with replies. This passes
	 * over anything that is not an answer without testing for `>`, which would
	 * be a guard clause no input could make fire. */
	while (next_line(management, line, sizeof(line))) {
		if (strncmp(line, "SUCCESS: ", 9u) == 0) {
			if (reply && reply_size > 0u) {
				(void)snprintf(reply, reply_size, "%s", line + 9);
			}
			return 1;
		}
		if (strncmp(line, "ERROR: ", 7u) == 0) {
			ncfg_error_set(err, err_size, "openvpn refused `%s`: %s", command, line + 7);
			return 0;
		}
	}
	ncfg_error_set(err, err_size, "no answer to `%s`", command);
	return 0;
}
