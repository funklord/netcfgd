/*
 * dhcpcd_control.c -- asking a running dhcpcd which configuration file it was
 * started with.
 *
 * The reasoning is in `apply.h`, where a caller will read it: dhcpcd calls
 * `setproctitle` and destroys both the command line and the environment
 * netcfgd started it with, so the only surviving mark is dhcpcd's own memory
 * of its `-f` argument, which it recites on its control socket.
 *
 * WHAT THIS OPENS, AND WHAT STOPS IT
 *   One `AF_UNIX` stream socket at a time, under a run directory the caller
 *   names, with a send and a receive deadline set before a byte is written.
 *   It spawns nothing, signals nothing and loops only while a read is still
 *   making progress into a buffer with a ceiling -- an unknown command on this
 *   socket produces no reply *and no close*, which is what the deadline is
 *   for.
 */
#include "ncfg/apply.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

/* Arguments are NUL-separated with a newline before the final NUL, which is
 * the framing dhcpcd's `control.c` reads. */
static const char get_config_file[] = "--getconfigfile\n\0";

/* The bytes of it that go on the wire: everything but the terminator C adds
 * after the one dhcpcd's framing asks for. */
#define GET_CONFIG_FILE_BYTES (sizeof(get_config_file) - 1u)

/* ------------------------------------------------------------------------ *
 * The reply
 * ------------------------------------------------------------------------ */

int ncfg_dhcpcd_control_payload(const void *bytes, size_t length, char *out, size_t out_size)
{
	const unsigned char *at = bytes;
	size_t               end;
	size_t               start;
	size_t               run;

	if (!out || out_size == 0u) {
		return 0;
	}
	out[0] = '\0';
	if (!at || length == 0u) {
		return 0;
	}
	/* The last run of printable bytes. A filesystem path holds no NUL and no
	 * control character, dhcpcd sends exactly one string, and the length
	 * prefix in front of it is binary -- so the tail is the answer whatever
	 * width that prefix had. */
	end = length;
	while (end > 0u && at[end - 1u] < 0x20u) {
		end--;
	}
	if (end == 0u) {
		return 0;
	}
	/*
	 * **A run that reaches the end of what was read is not an answer.** dhcpcd
	 * terminates the string, so a reply with no terminator in it is a reply
	 * that has not all arrived -- and believing it is how the length prefix's
	 * own low byte came to be reported as a path.
	 */
	if (end == length) {
		return 0;
	}
	start = end;
	while (start > 0u && at[start - 1u] >= 0x20u) {
		start--;
	}
	run = end - start;
	while (run > 0u && at[start] == ' ') {
		start++;
		run--;
	}
	while (run > 0u && at[start + run - 1u] == ' ') {
		run--;
	}
	if (run == 0u || run + 1u > out_size) {
		return 0;
	}
	/*
	 * **Absolute, or it is not an answer.** The one thing every caller does
	 * with this is compare it against a path netcfgd composed, and a reply
	 * that is not a path at all compares unequal -- which reads as "somebody
	 * else's dhcpcd" rather than as "netcfgd could not tell". Those two have
	 * different consequences (0141), so the difference is decided here.
	 */
	if (at[start] != (unsigned char)'/') {
		return 0;
	}
	memcpy(out, at + start, run);
	out[run] = '\0';
	return 1;
}

/* ------------------------------------------------------------------------ *
 * The socket
 * ------------------------------------------------------------------------ */

/* A copy of `text`, or NULL. */
static char *duplicate(const char *text)
{
	size_t length = strlen(text) + 1u;
	char  *copy = malloc(length);

	if (copy) {
		memcpy(copy, text, length);
	}
	return copy;
}

/* Ask one socket, and answer what it recited. NULL for every way of not
 * knowing. */
static char *ask(const char *path)
{
	struct sockaddr_un  where;
	struct timeval      deadline;
	unsigned char       reply[NCFG_DHCPCD_REPLY_MAX];
	char                answer[NCFG_DHCPCD_REPLY_MAX];
	size_t              filled = 0u;
	size_t              sent = 0u;
	int                 fd;

	if (strlen(path) >= sizeof(where.sun_path)) {
		return NULL;
	}
	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		return NULL;
	}
	memset(&where, 0, sizeof(where));
	where.sun_family = AF_UNIX;
	(void)snprintf(where.sun_path, sizeof(where.sun_path), "%s", path);

	memset(&deadline, 0, sizeof(deadline));
	deadline.tv_usec = NCFG_DHCPCD_DEADLINE_MILLISECONDS * 1000;
	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &deadline, (socklen_t)sizeof(deadline)) != 0 ||
	    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &deadline, (socklen_t)sizeof(deadline)) != 0) {
		(void)close(fd);
		return NULL;
	}
	if (connect(fd, (const struct sockaddr *)&where, (socklen_t)sizeof(where)) != 0) {
		(void)close(fd);
		return NULL;
	}
	while (sent < GET_CONFIG_FILE_BYTES) {
		ssize_t put = write(fd, get_config_file + sent, GET_CONFIG_FILE_BYTES - sent);

		if (put < 0 && errno == EINTR) {
			continue;
		}
		if (put <= 0) {
			(void)close(fd);
			return NULL;
		}
		sent += (size_t)put;
	}

	/*
	 * Read until the reply holds a whole answer, or until the deadline.
	 *
	 * **Not "read once", which is what the Rust does.** A reply split between
	 * its length prefix and its string leaves the prefix's printable low byte
	 * as the last run of printable bytes, and that is an answer the parser
	 * above refuses -- so this asks for the rest rather than returning
	 * something that is not a path. dhcpcd does not close the connection
	 * either, so an answer that never completes ends at the receive timeout
	 * rather than at end of file.
	 */
	while (filled < sizeof(reply)) {
		ssize_t got;

		if (ncfg_dhcpcd_control_payload(reply, filled, answer, sizeof(answer))) {
			(void)close(fd);
			return duplicate(answer);
		}
		got = read(fd, reply + filled, sizeof(reply) - filled);
		if (got < 0 && errno == EINTR) {
			continue;
		}
		if (got <= 0) {
			break;
		}
		filled += (size_t)got;
	}
	if (ncfg_dhcpcd_control_payload(reply, filled, answer, sizeof(answer))) {
		(void)close(fd);
		return duplicate(answer);
	}
	(void)close(fd);
	return NULL;
}

char *ncfg_dhcpcd_config_file_of(const char *run_dir, const char *interface, const char *family)
{
	/*
	 * Privileged first. The unprivileged one is a fallback for nothing in
	 * particular -- netcfgd is root -- and is tried only because a machine may
	 * have tightened the privileged socket's mode. dhcpcd 10.5.0 removed it
	 * outright, so on a current Debian the second path is never there.
	 */
	static const char *const suffixes[] = { "sock", "unpriv.sock" };
	size_t                   at;

	if (!run_dir || !interface || !family) {
		return NULL;
	}
	for (at = 0u; at < sizeof(suffixes) / sizeof(*suffixes); at++) {
		char path[512];
		char *found;
		int   written;

		written = snprintf(path, sizeof(path), "%s/%s-%s.%s", run_dir, interface, family,
		    suffixes[at]);
		if (written < 0 || (size_t)written >= sizeof(path)) {
			continue;
		}
		found = ask(path);
		if (found) {
			return found;
		}
	}
	return NULL;
}
