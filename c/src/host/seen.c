/*
 * seen.c -- the recorder described in seen.h.
 *
 * THE CONVERSATION
 *   One connection per record: `add record KEY VALUE` and a newline, and one
 *   line back that starts `ok` or says why not. fuzznetd's grammar escapes a
 *   byte up to a space, a `%`, a comma or DEL as `%` and two hex digits, and
 *   that is applied to VALUE, which carries spaces and may carry a host's
 *   own name; KEY is checked rather than escaped, since fuzznet refuses a key
 *   outside its grammar outright.
 *
 *   **Bounded at both ends.** The connect and the reply each wait at most a
 *   second, because a pass of the reconcile loop must not stall on a daemon
 *   that is wedged, and a line longer than the buffer is no answer.
 */
#include "ncfg/seen.h"

#include "ncfg/base.h"
#include "ncfg/log.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define SEEN_WAIT_MS 1000

typedef struct {
	char     key[NCFG_SEEN_KEY_MAX + 1u];
	char     value[NCFG_SEEN_VALUE_MAX + 1u];
	uint64_t written;
} held_t;

struct ncfg_seen {
	char     socket_path[sizeof(((struct sockaddr_un *)0)->sun_path)];
	held_t  *held;
	size_t   held_count;
	uint64_t silent_until; /* fuzznetd did not answer; not asked before then */
	int      said_silent;  /* the line saying so has been written */
};

ncfg_seen_t *ncfg_seen_new(const char *socket_path)
{
	ncfg_seen_t *seen = calloc(1u, sizeof(*seen));
	const char  *run;
	int          wrote;

	if (!seen) {
		return NULL;
	}
	if (socket_path) {
		wrote = snprintf(seen->socket_path, sizeof(seen->socket_path), "%s", socket_path);
	} else {
		/* fuzznetd's own default, `fzn_socket_default_path`, written again
		 * here because linking fuzznet to ask it is what 0269 refuses. */
		run = getenv("XDG_RUNTIME_DIR");
		wrote = run && run[0] == '/'
		    ? snprintf(seen->socket_path, sizeof(seen->socket_path),
		          "%s/fuzznet/fuzznetd.sock", run)
		    : snprintf(seen->socket_path, sizeof(seen->socket_path),
		          "/tmp/fuzznet-%lu/fuzznetd.sock", (unsigned long)geteuid());
	}
	if (wrote < 0 || (size_t)wrote >= sizeof(seen->socket_path)) {
		/* A path that does not fit is a socket nobody can be at: kept
		 * empty, and every pass writes nothing. */
		seen->socket_path[0] = '\0';
	}
	return seen;
}

void ncfg_seen_free(ncfg_seen_t *seen)
{
	if (!seen) {
		return;
	}
	free(seen->held);
	free(seen);
}

static int key_char(char c)
{
	return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_' ||
	    c == '/' || c == '-';
}

int ncfg_seen_key(const char *interface, const char *mac, char *out, size_t out_size)
{
	size_t at;
	int    wrote;

	if (!interface || !mac || !interface[0] || !mac[0]) {
		return 0;
	}
	wrote = snprintf(out, out_size, "seen/%s/%s", interface, mac);
	if (wrote < 0 || (size_t)wrote >= out_size || (size_t)wrote > NCFG_SEEN_KEY_MAX) {
		return 0;
	}
	for (at = 0; out[at]; at++) {
		if (out[at] == ':') {
			out[at] = '-';
		} else if (out[at] >= 'A' && out[at] <= 'F') {
			out[at] = (char)(out[at] - 'A' + 'a');
		}
		if (!key_char(out[at])) {
			return 0;
		}
	}
	return 1;
}

/* fuzznet's escape: a byte up to a space, `%`, a comma or DEL as %XX. */
static int escape_value(const char *value, char *out, size_t out_size)
{
	static const char hex[] = "0123456789abcdef";
	size_t            at = 0;

	for (; *value; value++) {
		const unsigned char c = (unsigned char)*value;

		if (c <= ' ' || c == '%' || c == ',' || c == 0x7f) {
			if (at + 3u >= out_size) {
				return 0;
			}
			out[at++] = '%';
			out[at++] = hex[c >> 4];
			out[at++] = hex[c & 0x0f];
		} else {
			if (at + 1u >= out_size) {
				return 0;
			}
			out[at++] = (char)c;
		}
	}
	out[at] = '\0';
	return 1;
}

/* One record, one connection. 1 where fuzznetd said `ok`; 0 with `*silent`
 * set where nobody answered, which is the absence the header describes. */
static int add_record(const char *socket_path, const char *key, const char *value,
    int *silent, char *why, size_t why_size)
{
	struct sockaddr_un address;
	struct pollfd      wait;
	char               escaped[NCFG_SEEN_VALUE_MAX * 3u + 1u];
	char               line[NCFG_SEEN_KEY_MAX + sizeof(escaped) + 32u];
	char               reply[256];
	size_t             length;
	size_t             sent = 0;
	size_t             got = 0;
	int                fd;
	int                wrote;

	*silent = 1;
	why[0] = '\0';
	if (!socket_path[0] || strlen(socket_path) >= sizeof(address.sun_path)) {
		(void)snprintf(why, why_size, "no fuzznetd socket path fits");
		return 0;
	}
	if (!escape_value(value, escaped, sizeof(escaped))) {
		*silent = 0;
		(void)snprintf(why, why_size, "the value for %s is too long to write", key);
		return 0;
	}
	wrote = snprintf(line, sizeof(line), "add record %s %s\n", key, escaped);
	if (wrote < 0 || (size_t)wrote >= sizeof(line)) {
		*silent = 0;
		(void)snprintf(why, why_size, "the record for %s is too long to send", key);
		return 0;
	}
	length = (size_t)wrote;
	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	if (fd < 0) {
		(void)snprintf(why, why_size, "no socket: %s", strerror(errno));
		return 0;
	}
	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	memcpy(address.sun_path, socket_path, strlen(socket_path) + 1u);
	if (connect(fd, (const struct sockaddr *)&address, sizeof(address)) != 0 &&
	    errno != EINPROGRESS) {
		(void)snprintf(why, why_size, "fuzznetd is not at %s: %s", socket_path,
		    strerror(errno));
		(void)close(fd);
		return 0;
	}
	while (sent < length) {
		ssize_t n;

		wait.fd = fd;
		wait.events = POLLOUT;
		if (poll(&wait, 1, SEEN_WAIT_MS) <= 0) {
			(void)snprintf(why, why_size, "fuzznetd at %s did not take the request",
			    socket_path);
			(void)close(fd);
			return 0;
		}
		n = send(fd, line + sent, length - sent, MSG_NOSIGNAL);
		if (n < 0 && errno != EAGAIN && errno != EINTR) {
			(void)snprintf(why, why_size, "fuzznetd at %s: %s", socket_path,
			    strerror(errno));
			(void)close(fd);
			return 0;
		}
		if (n > 0) {
			sent += (size_t)n;
		}
	}
	while (got + 1u < sizeof(reply) && !memchr(reply, '\n', got)) {
		ssize_t n;

		wait.fd = fd;
		wait.events = POLLIN;
		if (poll(&wait, 1, SEEN_WAIT_MS) <= 0) {
			break;
		}
		n = recv(fd, reply + got, sizeof(reply) - 1u - got, 0);
		if (n <= 0) {
			if (n < 0 && (errno == EAGAIN || errno == EINTR)) {
				continue;
			}
			break;
		}
		got += (size_t)n;
	}
	(void)close(fd);
	reply[got] = '\0';
	if (!memchr(reply, '\n', got)) {
		(void)snprintf(why, why_size, "fuzznetd at %s gave no answer", socket_path);
		return 0;
	}
	*silent = 0;
	if (strncmp(reply, "ok", 2u) == 0 && (reply[2] == '\n' || reply[2] == ' ')) {
		return 1;
	}
	reply[strcspn(reply, "\n")] = '\0';
	(void)snprintf(why, why_size, "fuzznetd refused %s: %s", key, reply);
	return 0;
}

static held_t *held_find(ncfg_seen_t *seen, const char *key)
{
	size_t at;

	for (at = 0; at < seen->held_count; at++) {
		if (strcmp(seen->held[at].key, key) == 0) {
			return &seen->held[at];
		}
	}
	return NULL;
}

/* Remember a record written. Full, the one written longest ago makes room. */
static void held_keep(ncfg_seen_t *seen, const char *key, const char *value, uint64_t now)
{
	held_t *one = held_find(seen, key);

	if (!one) {
		if (seen->held_count < NCFG_SEEN_HELD_MAX) {
			held_t *grown = realloc(seen->held, (seen->held_count + 1u) * sizeof(*grown));

			if (!grown) {
				return;
			}
			seen->held = grown;
			one = &seen->held[seen->held_count++];
		} else {
			size_t at;

			one = &seen->held[0];
			for (at = 1; at < seen->held_count; at++) {
				if (seen->held[at].written < one->written) {
					one = &seen->held[at];
				}
			}
		}
		(void)snprintf(one->key, sizeof(one->key), "%s", key);
	}
	(void)snprintf(one->value, sizeof(one->value), "%s", value);
	one->written = now;
}

/* Write one host if it is new, changed or due. Returns 1 where written; sets
 * `*stop` where fuzznetd is not there, so the pass asks no further. */
static int consider(ncfg_seen_t *seen, const char *interface, const char *mac,
    const char *value, uint64_t now, int *stop)
{
	char    key[NCFG_SEEN_KEY_MAX + 1u];
	char    why[NCFG_ERROR_MAX];
	held_t *one;
	int     silent = 0;

	if (!ncfg_seen_key(interface, mac, key, sizeof(key))) {
		return 0;
	}
	one = held_find(seen, key);
	if (one && strcmp(one->value, value) == 0 && now < one->written + NCFG_SEEN_REFRESH_SECONDS) {
		return 0;
	}
	if (!add_record(seen->socket_path, key, value, &silent, why, sizeof(why))) {
		if (silent) {
			*stop = 1;
			seen->silent_until = now + NCFG_SEEN_RETRY_SECONDS;
			if (!seen->said_silent) {
				ncfg_log_emitf("seen", NCFG_LOG_NOTE,
				    "the hosts this machine sees are not being written down: %s", why);
				seen->said_silent = 1;
			}
		} else {
			ncfg_log_emitf("seen", NCFG_LOG_WARNING, "%s", why);
		}
		return 0;
	}
	if (seen->said_silent) {
		ncfg_log_emitf("seen", NCFG_LOG_NOTE,
		    "fuzznetd answers at %s, and the hosts this machine sees are written there",
		    seen->socket_path);
		seen->said_silent = 0;
	}
	held_keep(seen, key, value, now);
	return 1;
}

size_t ncfg_seen_record(ncfg_seen_t *seen, const ncfg_observed_t *observed, uint64_t now)
{
	size_t written = 0;
	size_t at;
	size_t one;
	int    stop = 0;

	if (!seen || !observed || now < seen->silent_until) {
		return 0;
	}
	for (at = 0; at < observed->backend_count && !stop; at++) {
		const ncfg_observed_backend_t *backend = &observed->backends[at];

		if (backend->access_control) {
			for (one = 0; one < backend->access_control->associated_count && !stop; one++) {
				written += (size_t)consider(seen, backend->interface,
				    backend->access_control->associated[one], "station", now, &stop);
			}
		}
		for (one = 0; one < backend->lease_count && !stop; one++) {
			const ncfg_observed_lease_t *lease = &backend->leases[one];
			char                         value[NCFG_SEEN_VALUE_MAX + 1u];

			if (!lease->mac || !lease->mac[0] || !lease->address) {
				continue;
			}
			(void)snprintf(value, sizeof(value), "lease %s%s%s", lease->address,
			    lease->hostname && lease->hostname[0] ? " " : "",
			    lease->hostname ? lease->hostname : "");
			written += (size_t)consider(seen, backend->interface, lease->mac, value, now,
			    &stop);
		}
	}
	return written;
}
