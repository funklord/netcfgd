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
#include <limits.h>
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
	/* The store whose face is asked for the socket, or "" for `socket_path`. */
	char     store[1024];
	held_t  *held;
	size_t   held_count;
	uint64_t silent_until; /* fuzznetd did not answer; not asked before then */
	int      said_silent;  /* the line saying so has been written */
	/* Reading back: the last whole listing, and the one under way. */
	char   **known;
	size_t   known_count;
	char   **reading;
	size_t   reading_count;
	size_t   cursor;       /* the FROM the next page is asked from */
	int      listing;      /* a listing is under way */
	uint64_t next_listing; /* when the next may begin */
	int      said_unread;  /* the line saying a listing stopped is out */
	/* This process is the face, so the face's socket is its own and a line
	 * is asked in-process instead (10.676). NULL for the socket. */
	ncfg_seen_local_fn local;
};

static void free_list(char **list, size_t count)
{
	size_t at;

	for (at = 0; at < count; at++) {
		free(list[at]);
	}
	free(list);
}

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

void ncfg_seen_use_store(ncfg_seen_t *seen, const char *dir)
{
	if (!seen || !dir || strlen(dir) >= sizeof(seen->store)) {
		return;
	}
	(void)snprintf(seen->store, sizeof(seen->store), "%s", dir);
}

/*
 * The face's socket, as the store's `face` file names it, into `out`: one
 * line, an absolute path, which is how fuzznetd writes it and reads it
 * (`face_socket` in its `node/daemon.c`). 0 where there is no face.
 */
static int face_socket(const char *store, char *out, size_t out_size)
{
	char   path[1100];
	FILE  *file;
	size_t length;

	(void)snprintf(path, sizeof(path), "%s/face", store);
	file = fopen(path, "r");
	if (!file) {
		return 0;
	}
	length = fread(out, 1u, out_size - 1u, file);
	(void)fclose(file);
	while (length && (out[length - 1u] == '\n' || out[length - 1u] == '\r')) {
		length--;
	}
	out[length] = '\0';
	return length > 0u && out[0] == '/';
}

void ncfg_seen_in_process(ncfg_seen_t *seen, ncfg_seen_local_fn local)
{
	if (seen) {
		seen->local = local;
	}
}

void ncfg_seen_free(ncfg_seen_t *seen)
{
	if (!seen) {
		return;
	}
	free(seen->held);
	free_list(seen->known, seen->known_count);
	free_list(seen->reading, seen->reading_count);
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

/*
 * One line of the socket into `out`, from `buffer` (which holds `*have`
 * bytes read already, kept for the next line). 1 with the line, its newline
 * taken off; 0 where none came within the wait, or it did not fit.
 */
static int read_line(int fd, char *buffer, size_t buffer_size, size_t *have, char *out,
    size_t out_size)
{
	struct pollfd wait;
	char         *end;

	while (!(end = memchr(buffer, '\n', *have))) {
		ssize_t n;

		if (*have + 1u >= buffer_size) {
			return 0;
		}
		wait.fd = fd;
		wait.events = POLLIN;
		if (poll(&wait, 1, SEEN_WAIT_MS) <= 0) {
			return 0;
		}
		n = recv(fd, buffer + *have, buffer_size - 1u - *have, 0);
		if (n <= 0) {
			if (n < 0 && (errno == EAGAIN || errno == EINTR)) {
				continue;
			}
			return 0;
		}
		*have += (size_t)n;
	}
	{
		const size_t length = (size_t)(end - buffer);

		if (length >= out_size) {
			return 0;
		}
		memcpy(out, buffer, length);
		out[length] = '\0';
		*have -= length + 1u;
		memmove(buffer, end + 1, *have);
	}
	return 1;
}

/*
 * One line asked, one line back, one connection. 1 with the reply in `reply`
 * (its newline taken off); 0 with `*silent` set where nobody answered, which
 * is the absence the header describes, and a sentence in `why` either way.
 */
static int ask_socket(const char *socket_path, const char *line, char *reply,
    size_t reply_size, int *silent, char *why, size_t why_size)
{
	struct sockaddr_un address;
	struct pollfd      wait;
	char               buffer[4096];
	size_t             length = strlen(line);
	size_t             sent = 0;
	size_t             have = 0;
	int                fd;

	*silent = 1;
	why[0] = '\0';
	reply[0] = '\0';
	if (!socket_path[0] || strlen(socket_path) >= sizeof(address.sun_path)) {
		(void)snprintf(why, why_size, "no fuzznetd socket path fits");
		return 0;
	}
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
	if (!read_line(fd, buffer, sizeof(buffer), &have, reply, reply_size)) {
		(void)snprintf(why, why_size, "fuzznetd at %s gave no answer", socket_path);
		reply[0] = '\0';
		(void)close(fd);
		return 0;
	}
	(void)close(fd);
	*silent = 0;
	return 1;
}

/*
 * One line asked of whichever serves the store: in-process where this process
 * is its face (`ncfg_seen_in_process`), else over the socket. In-process, a
 * line comes back with its newline and an empty one is fuzznet saying the
 * node is not serving yet, which is the same absence as nobody at a socket.
 */
static int ask(const ncfg_seen_t *seen, const char *line, char *reply, size_t reply_size,
    int *silent, char *why, size_t why_size)
{
	char   bare[2048];
	size_t length;

	if (!seen->local) {
		return ask_socket(seen->socket_path, line, reply, reply_size, silent, why, why_size);
	}
	length = strlen(line);
	if (length >= sizeof(bare)) {
		*silent = 0;
		(void)snprintf(why, why_size, "the request is too long to ask");
		return 0;
	}
	memcpy(bare, line, length + 1u);
	while (length && bare[length - 1u] == '\n') {
		bare[--length] = '\0';
	}
	reply[0] = '\0';
	length = seen->local(bare, reply, reply_size);
	if (length == 0u || length >= reply_size) {
		*silent = 1;
		reply[0] = '\0';
		(void)snprintf(why, why_size, "this node is not serving its store yet");
		return 0;
	}
	reply[length] = '\0';
	while (length && (reply[length - 1u] == '\n' || reply[length - 1u] == '\r')) {
		reply[--length] = '\0';
	}
	*silent = 0;
	return 1;
}

/* One record, one connection. 1 where fuzznetd said `ok`; 0 with `*silent`
 * set where nobody answered, which is the absence the header describes. */
static int add_record(const ncfg_seen_t *seen, const char *key, const char *value,
    int *silent, char *why, size_t why_size)
{
	char escaped[NCFG_SEEN_VALUE_MAX * 3u + 1u];
	char line[NCFG_SEEN_KEY_MAX + sizeof(escaped) + 32u];
	char reply[256];
	int  wrote;

	*silent = 1;
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
	if (!ask(seen, line, reply, sizeof(reply), silent, why, why_size)) {
		return 0;
	}
	/*
	 * **`ok` alone, and nothing after it.** A record kept is answered `ok`
	 * and nothing more. A request no handler serves -- a fuzznetd started
	 * without a record store -- is answered with the node's status line,
	 * `ok served granted ...`, which is fuzznet saying it is there and
	 * nothing about the record. Read as success it reported records kept
	 * that went nowhere; found by the first run against a real fuzznetd
	 * (10.674).
	 */
	if (strcmp(reply, "ok") == 0) {
		return 1;
	}
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
	/* Asked of the store each time where there is one: the face is whichever
	 * process holds the claim now. */
	if (!seen->local && seen->store[0] && !face_socket(seen->store, seen->socket_path,
	        sizeof(seen->socket_path))) {
		*stop = 1;
		seen->silent_until = now + NCFG_SEEN_RETRY_SECONDS;
		if (!seen->said_silent) {
			ncfg_log_emitf("seen", NCFG_LOG_NOTE,
			    "the hosts this machine sees are not being written down: no process "
			    "serves the fuzznet store %s", seen->store);
			seen->said_silent = 1;
		}
		return 0;
	}
	if (!add_record(seen, key, value, &silent, why, sizeof(why))) {
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

/* ------------------------------------------------------------------------ *
 * Reading it back
 * ------------------------------------------------------------------------ */

/* `aa-bb-cc-dd-ee-ff` as the key spells it, into `out` as `aa:bb:...`.
 * 0 for anything not six pairs of lowercase hex. */
static int mac_of_key_part(const char *part, size_t length, char out[18])
{
	size_t at;

	if (length != 17u) {
		return 0;
	}
	for (at = 0; at < 17u; at++) {
		const char c = part[at];

		if (at % 3u == 2u) {
			if (c != '-') {
				return 0;
			}
			out[at] = ':';
		} else if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			out[at] = c;
		} else {
			return 0;
		}
	}
	out[17] = '\0';
	return 1;
}

/* Into the sorted, unique list. 0 on out of memory; a full list or a MAC
 * already held is not a failure. */
static int add_station(char **list, size_t *count, size_t room, const char *mac)
{
	size_t low = 0;
	size_t high = *count;
	char  *copy;

	while (low < high) {
		const size_t middle = low + (high - low) / 2u;
		const int    order = strcmp(list[middle], mac);

		if (order == 0) {
			return 1;
		}
		if (order < 0) {
			low = middle + 1u;
		} else {
			high = middle;
		}
	}
	if (*count >= room) {
		return 1;
	}
	copy = strdup(mac);
	if (!copy) {
		return 0;
	}
	memmove(&list[low + 1u], &list[low], (*count - low) * sizeof(*list));
	list[low] = copy;
	(*count)++;
	return 1;
}

long ncfg_seen_parse_listing(const char *reply, char **out, size_t *count, size_t room,
    int *more)
{
	unsigned long from = 0;
	unsigned long shown = 0;
	int           flag = 0;
	int           used = 0;
	const char   *at;
	long          listed = 0;

	*more = 0;
	if (!reply || strncmp(reply, "ok ", 3u) != 0 ||
	    sscanf(reply + 3, "%lu %lu %d%n", &from, &shown, &flag, &used) != 3) {
		return -1;
	}
	/*
	 * **Digits only, and a count a `long` can carry.** `%lu` takes a leading
	 * minus and wraps it, so `ok 8 -3 1` read SHOWN as a huge count that came
	 * back as -3 -- outside "the count, or -1" (project.md 10.681, found by
	 * `fuzz/seen_listing.c`).
	 */
	if (memchr(reply + 3, '-', (size_t)used) != NULL || shown > (unsigned long)LONG_MAX) {
		return -1;
	}
	(void)from;
	*more = flag != 0;
	at = reply + 3 + used;
	/* Each record: ` HOST,KEY,MS,VALUE`, the value escaped so it holds no
	 * space or comma. */
	while (*at == ' ') {
		const char *item = ++at;
		const char *end = item + strcspn(item, " ");
		const char *key = memchr(item, ',', (size_t)(end - item));
		const char *key_end;
		char        mac[18];

		at = end;
		listed++;
		if (!key) {
			continue;
		}
		key++;
		key_end = memchr(key, ',', (size_t)(end - key));
		if (!key_end || (size_t)(key_end - key) < 5u || strncmp(key, "seen/", 5u) != 0) {
			continue;
		}
		/* `seen/<interface>/<mac>`: the MAC is after the last slash. */
		{
			const char *slash = key_end;

			while (slash > key + 5 && slash[-1] != '/') {
				slash--;
			}
			if (slash == key + 5 ||
			    !mac_of_key_part(slash, (size_t)(key_end - slash), mac)) {
				continue;
			}
		}
		if (!add_station(out, count, room, mac)) {
			return -1;
		}
	}
	/* The count is the reply's own, which is what FROM counts in; the
	 * records walked are only what this side could split. */
	(void)listed;
	return (long)shown;
}

/* A listing stopped partway: said once until one finishes, and the last
 * whole set stands. */
static void listing_stopped(ncfg_seen_t *seen, uint64_t now, const char *why)
{
	free_list(seen->reading, seen->reading_count);
	seen->reading = NULL;
	seen->reading_count = 0;
	seen->listing = 0;
	seen->next_listing = now + NCFG_SEEN_RETRY_SECONDS;
	if (!seen->said_unread) {
		ncfg_log_emitf("seen", NCFG_LOG_NOTE,
		    "the hosts seen before are not being read back (%s); %zu from the last "
		    "whole reading stand", why, seen->known_count);
		seen->said_unread = 1;
	}
}

void ncfg_seen_read(ncfg_seen_t *seen, uint64_t now)
{
	char     line[64];
	char     reply[2048];
	char     why[NCFG_ERROR_MAX];
	unsigned page;

	if (!seen) {
		return;
	}
	if (!seen->listing) {
		if (now < seen->next_listing) {
			return;
		}
		seen->reading = calloc(NCFG_SEEN_STATIONS_MAX, sizeof(*seen->reading));
		if (!seen->reading) {
			return;
		}
		seen->reading_count = 0;
		seen->cursor = 0;
		seen->listing = 1;
	}
	for (page = 0; page < NCFG_SEEN_READ_PAGES; page++) {
		long listed;
		int  silent = 0;
		int  more = 0;

		if (!seen->local && seen->store[0] && !face_socket(seen->store, seen->socket_path,
		        sizeof(seen->socket_path))) {
			listing_stopped(seen, now, "no process serves the fuzznet store");
			return;
		}
		(void)snprintf(line, sizeof(line), "list record %zu\n", seen->cursor);
		if (!ask(seen, line, reply, sizeof(reply), &silent, why,
		        sizeof(why))) {
			listing_stopped(seen, now, why);
			return;
		}
		listed = ncfg_seen_parse_listing(reply, seen->reading, &seen->reading_count,
		    NCFG_SEEN_STATIONS_MAX, &more);
		if (listed < 0) {
			(void)snprintf(why, sizeof(why), "fuzznetd answered `%.80s`", reply);
			listing_stopped(seen, now, why);
			return;
		}
		seen->cursor += (size_t)listed;
		/* A page that lists nothing and says there is more would be asked
		 * again for ever; it is taken as the end. */
		if (!more || listed == 0) {
			free_list(seen->known, seen->known_count);
			seen->known = seen->reading;
			seen->known_count = seen->reading_count;
			seen->reading = NULL;
			seen->reading_count = 0;
			seen->listing = 0;
			seen->next_listing = now + NCFG_SEEN_READ_SECONDS;
			if (seen->said_unread) {
				ncfg_log_emitf("seen", NCFG_LOG_NOTE,
				    "the hosts seen before are read back again: %zu", seen->known_count);
				seen->said_unread = 0;
			}
			return;
		}
	}
}

char *const *ncfg_seen_stations(const ncfg_seen_t *seen, size_t *count)
{
	*count = seen ? seen->known_count : 0u;
	return seen && seen->known_count ? seen->known : NULL;
}
