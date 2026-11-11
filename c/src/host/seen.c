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
 *   that is wedged, and a line longer than the buffer is no answer. The
 *   conversation and the escape are `client/ncfg_fuzznet.c`'s, shared with
 *   `ncfg` and the GUI.
 */
#include "ncfg/seen.h"

#include "ncfg/base.h"
#include "ncfg_fuzznet.h"
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
	/* Refused, not written (10.696): `written` is when it was last asked, and
	 * it is asked again a minute on rather than every pass, its warning said
	 * once for this value. */
	int      refused;
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
		/* fuzznetd's own default, `fzn_socket_default_path`, for a node that
		 * is not this process: in-process the face is asked directly
		 * (`ncfg_seen_in_process`, 10.676). */
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
		return ncfg_fuzznet_ask(seen->socket_path, line, reply, reply_size, SEEN_WAIT_MS, silent,
		    why, why_size);
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
	if (!ncfg_fuzznet_escape(value, escaped, sizeof(escaped))) {
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
	(void)snprintf(why, why_size, "the fuzznet node refused %s: %s", key, reply);
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
	one->refused = 0;
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
	if (one && strcmp(one->value, value) == 0 &&
	    now < one->written + (one->refused ? NCFG_SEEN_RETRY_SECONDS : NCFG_SEEN_REFRESH_SECONDS)) {
		return 0;
	}
	/* Asked of the store each time where there is one: the face is whichever
	 * process holds the claim now. */
	if (!seen->local && seen->store[0] && !ncfg_fuzznet_face(seen->store, seen->socket_path,
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
			/*
			 * **Refused: asked again a minute on, and said once** (10.696). A
			 * refusal may lift -- a permit given, a record trimmed -- so it is
			 * asked again; but every pass, warning each time, was a log a
			 * joining client could fill, since a lease's value carries the
			 * hostname the client chose, and one long enough escapes past
			 * fuzznet's 512-byte line.
			 */
			int said = one && one->refused && strcmp(one->value, value) == 0;

			held_keep(seen, key, value, now);
			one = held_find(seen, key);
			if (one) {
				one->refused = 1;
			}
			if (!said) {
				ncfg_log_emitf("seen", NCFG_LOG_WARNING, "%s", why);
			}
		}
		return 0;
	}
	if (seen->said_silent) {
		ncfg_log_emitf("seen", NCFG_LOG_NOTE,
		    "the fuzznet node answers at %s, and the hosts this machine sees are written "
		    "there",
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

		if (!seen->local && seen->store[0] && !ncfg_fuzznet_face(seen->store, seen->socket_path,
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
			(void)snprintf(why, sizeof(why), "the fuzznet node answered `%.80s`", reply);
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
