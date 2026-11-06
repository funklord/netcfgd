/*
 * ncfg_fuzznet.c -- what ncfg_fuzznet.h describes.
 *
 * A page is somebody else's bytes -- another host's, through fuzznet -- so
 * it is read as hostile: digits only where numbers are, no number a `size_t`
 * cannot carry, COUNT exactly the bytes that follow, and a gathering that
 * makes no progress or outgrows its bound stops rather than looping.
 */
#include "ncfg_fuzznet.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* A page unescaped: one local reply line (1024) or a remote answer (4096). */
#define PAGE_CAP 8192u

static void say(char *err, size_t err_size, const char *format, ...)
{
	va_list args;

	if (!err || err_size == 0u) {
		return;
	}
	va_start(args, format);
	(void)vsnprintf(err, err_size, format, args);
	va_end(args);
}

int ncfg_fuzznet_escape(const char *text, char *out, size_t out_size)
{
	static const char hex[] = "0123456789abcdef";
	size_t            at = 0;

	if (!out || out_size == 0u) {
		return 0;
	}
	for (; text && *text; text++) {
		const unsigned char c = (unsigned char)*text;

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

static int hex_value(char c)
{
	if (c >= '0' && c <= '9') {
		return c - '0';
	}
	if (c >= 'a' && c <= 'f') {
		return c - 'a' + 10;
	}
	if (c >= 'A' && c <= 'F') {
		return c - 'A' + 10;
	}
	return -1;
}

long ncfg_fuzznet_unescape(const char *text, size_t length, char *out, size_t out_size)
{
	size_t at = 0;
	size_t wrote = 0;

	if (!text || !out) {
		return -1;
	}
	while (at < length) {
		char c = text[at];

		if (c == '%') {
			int high;
			int low;

			if (length - at < 3u || (high = hex_value(text[at + 1u])) < 0 ||
			    (low = hex_value(text[at + 2u])) < 0) {
				return -1;
			}
			c = (char)((high << 4) | low);
			at += 3u;
		} else {
			at++;
		}
		if (wrote >= out_size) {
			return -1;
		}
		out[wrote++] = c;
	}
	return (long)wrote;
}

/*
 * One line of the socket into `out`, from `buffer` (which holds `*have`
 * bytes read already). 1 with the line, its newline taken off; 0 where none
 * came within the wait, or it did not fit.
 */
static int read_line(int fd, int wait_ms, char *buffer, size_t buffer_size, size_t *have,
    char *out, size_t out_size)
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
		if (poll(&wait, 1, wait_ms) <= 0) {
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
		if (length && out[length - 1u] == '\r') {
			out[length - 1u] = '\0';
		}
		*have -= length + 1u;
		memmove(buffer, end + 1, *have);
	}
	return 1;
}

/* Every byte of `bytes` within the wait: 1, or 0 with a sentence. */
static int send_within(int fd, const char *path, const char *bytes, size_t length, int wait_ms,
    char *why, size_t why_size)
{
	struct pollfd wait;
	size_t        sent = 0;

	while (sent < length) {
		ssize_t n;

		wait.fd = fd;
		wait.events = POLLOUT;
		if (poll(&wait, 1, wait_ms) <= 0) {
			say(why, why_size, "fuzznet at %s did not take the request", path);
			return 0;
		}
		n = send(fd, bytes + sent, length - sent, MSG_NOSIGNAL);
		if (n < 0 && errno != EAGAIN && errno != EINTR) {
			say(why, why_size, "fuzznet at %s: %s", path, strerror(errno));
			return 0;
		}
		if (n > 0) {
			sent += (size_t)n;
		}
	}
	return 1;
}

/* `ncfg_fuzznet_ask`, and `*sent` set once any of the line may have gone. */
static int ask_noting_sent(const char *path, const char *line, char *reply, size_t reply_size,
    int wait_ms, int *silent, int *sent, char *why, size_t why_size)
{
	struct sockaddr_un address;
	char               buffer[4096];
	size_t             length;
	size_t             have = 0;
	int                fd;

	*silent = 1;
	why[0] = '\0';
	if (reply_size) {
		reply[0] = '\0';
	}
	if (!path || !path[0] || strlen(path) >= sizeof(address.sun_path) || !line ||
	    reply_size == 0u) {
		say(why, why_size, "no fuzznet socket path fits");
		return 0;
	}
	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	if (fd < 0) {
		say(why, why_size, "no socket: %s", strerror(errno));
		return 0;
	}
	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	memcpy(address.sun_path, path, strlen(path) + 1u);
	if (connect(fd, (const struct sockaddr *)&address, sizeof(address)) != 0 &&
	    errno != EINPROGRESS) {
		say(why, why_size, "fuzznet is not at %s: %s", path, strerror(errno));
		(void)close(fd);
		return 0;
	}
	length = strlen(line);
	if (length + (length && line[length - 1u] == '\n' ? 0u : 1u) > NCFG_FUZZNET_REQUEST_MAX) {
		say(why, why_size, "a line to fuzznet is at most %u bytes, and this is %zu",
		    NCFG_FUZZNET_REQUEST_MAX, length);
		(void)close(fd);
		*silent = 0;
		return 0;
	}
	if (sent) {
		*sent = 1;
	}
	if (!send_within(fd, path, line, length, wait_ms, why, why_size) ||
	    ((length == 0u || line[length - 1u] != '\n') &&
	        !send_within(fd, path, "\n", 1u, wait_ms, why, why_size))) {
		(void)close(fd);
		return 0;
	}
	if (!read_line(fd, wait_ms, buffer, sizeof(buffer), &have, reply, reply_size)) {
		say(why, why_size, "fuzznet at %s gave no answer that fits", path);
		reply[0] = '\0';
		(void)close(fd);
		return 0;
	}
	(void)close(fd);
	*silent = 0;
	return 1;
}

/*
 * `ask_noting_sent`, through a daemon busy with a peer: fuzznet refuses a call to
 * another host while one of its steps waits, up to 3 s, and says to ask again. That
 * is the usual state of a daemon just started, which a client that started it would
 * otherwise hand on as a failure (0314). Nothing has run, so asking again is safe.
 */
static int ask_again(const char *path, const char *line, char *reply, size_t reply_size,
    int wait_ms, int *silent, int *sent, char *why, size_t why_size)
{
	static const char     busy[] = "error the node is waiting on a peer";
	const struct timespec look = { 0, 50000000L };
	int                   looks;

	for (looks = 0;; looks++) {
		int asked = ask_noting_sent(path, line, reply, reply_size, wait_ms, silent, sent, why,
		    why_size);

		if (!asked || looks >= 80 || strncmp(reply, busy, sizeof(busy) - 1u) != 0) {
			return asked;
		}
		(void)nanosleep(&look, NULL);
	}
}

int ncfg_fuzznet_ask(const char *path, const char *line, char *reply, size_t reply_size,
    int wait_ms, int *silent, char *why, size_t why_size)
{
	return ask_again(path, line, reply, reply_size, wait_ms, silent, NULL, why, why_size);
}

/*
 * The face's socket, as the store's `face` file names it, into `out`: one
 * line, an absolute path, which is how fuzznetd writes it and reads it
 * (`face_socket` in its `node/daemon.c`). 0 where there is no face.
 */
int ncfg_fuzznet_face(const char *store, char *out, size_t out_size)
{
	char   path[1100];
	FILE  *file;
	size_t length;

	if (!store || !store[0] || !out || out_size < 2u) {
		return 0;
	}
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

uint64_t ncfg_status_page_digest(const char *bytes, size_t length)
{
	uint64_t hash = 0xcbf29ce484222325ull;
	size_t   at;

	for (at = 0; at < length; at++) {
		hash ^= (unsigned char)bytes[at];
		hash *= 0x100000001b3ull;
	}
	return hash;
}

/* Decimal digits at `*at` into `*out`, then the byte `end`: 1, or 0. */
static int number(const char *page, size_t length, size_t *at, char end, size_t *out)
{
	size_t value = 0;
	size_t start = *at;

	while (*at < length && page[*at] >= '0' && page[*at] <= '9') {
		size_t digit = (size_t)(page[*at] - '0');

		if (value > (NCFG_STATUS_PAGE_TOTAL_MAX - digit) / 10u) {
			return 0; /* past any status this side would gather */
		}
		value = value * 10u + digit;
		(*at)++;
	}
	if (*at == start || *at - start > 1u + 9u || *at >= length || page[*at] != end) {
		return 0;
	}
	(*at)++;
	*out = value;
	return 1;
}

int ncfg_status_page_read(const char *page, size_t length, ncfg_status_page_t *out)
{
	size_t   at = 3;
	size_t   digits;
	uint64_t digest = 0;

	if (!page || !out || length < 3u || memcmp(page, "ok ", 3u) != 0) {
		return 0;
	}
	memset(out, 0, sizeof(*out));
	if (!number(page, length, &at, ' ', &out->total) ||
	    !number(page, length, &at, ' ', &out->from) ||
	    !number(page, length, &at, ' ', &out->count)) {
		return 0;
	}
	for (digits = 0; digits < 16u; digits++, at++) {
		char c = at < length ? page[at] : '\0';
		int  value = c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;

		if (value < 0) {
			return 0;
		}
		digest = (digest << 4) | (uint64_t)value;
	}
	if (at >= length || page[at] != '\n') {
		return 0;
	}
	at++;
	if (out->from > out->total || out->count > out->total - out->from ||
	    length - at != out->count) {
		return 0;
	}
	out->digest = digest;
	out->bytes = page + at;
	return 1;
}

int ncfg_status_pages_join(ncfg_status_page_ask_fn ask, void *context, char **out,
    size_t *length, char *err, size_t err_size)
{
	char *page;
	int   attempt;

	if (!ask || !out || !length) {
		say(err, err_size, "nothing to ask the status of");
		return 0;
	}
	*out = NULL;
	*length = 0;
	page = malloc(PAGE_CAP);
	if (!page) {
		say(err, err_size, "no memory for a page of the status");
		return 0;
	}
	for (attempt = 0; attempt < 4; attempt++) {
		ncfg_status_page_t first = { 0, 0, 0, 0, NULL };
		ncfg_status_page_t one;
		char              *whole = NULL;
		size_t             from = 0;
		size_t             got = 0;
		int                moved = 0;

		do {
			if (!ask(context, from, page, PAGE_CAP, &got, err, err_size)) {
				free(whole);
				free(page);
				return 0;
			}
			if (!ncfg_status_page_read(page, got, &one)) {
				say(err, err_size, "the answer is not a page of the status: %.80s",
				    got ? page : "(empty)");
				free(whole);
				free(page);
				return 0;
			}
			if (from == 0) {
				first = one;
				whole = malloc(first.total + 1u);
				if (!whole) {
					say(err, err_size, "the status did not fit in memory");
					free(page);
					return 0;
				}
			}
			if (one.digest != first.digest || one.total != first.total) {
				moved = 1; /* another status: these pages are not one */
				break;
			}
			if (one.from != from || (one.count == 0u && from < one.total)) {
				say(err, err_size,
				    "the status came back from %zu when %zu was asked, or without progress",
				    one.from, from);
				free(whole);
				free(page);
				return 0;
			}
			memcpy(whole + from, one.bytes, one.count);
			from += one.count;
		} while (from < first.total);
		if (moved) {
			free(whole);
			continue;
		}
		whole[first.total] = '\0';
		if (ncfg_status_page_digest(whole, first.total) != first.digest) {
			say(err, err_size, "the pages joined are not the status their digest names");
			free(whole);
			free(page);
			return 0;
		}
		free(page);
		*out = whole;
		*length = first.total;
		return 1;
	}
	free(page);
	say(err, err_size, "the status moved faster than it could be read whole");
	return 0;
}

/* The value of `name=` in `<run_dir>/node`, one `name=value` a line. */
static int node_value(const char *run_dir, const char *name, char *out, size_t out_size)
{
	char        path[1100];
	char        text[2400];
	const char *at = text;
	size_t      name_length = strlen(name);
	size_t      got;
	FILE       *file;

	(void)snprintf(path, sizeof(path), "%s/node", run_dir);
	file = fopen(path, "r");
	if (!file) {
		return 0;
	}
	got = fread(text, 1u, sizeof(text) - 1u, file);
	(void)fclose(file);
	text[got] = '\0';
	while (*at) {
		const char *end = strchr(at, '\n');
		size_t      length = end ? (size_t)(end - at) : strlen(at);

		if (length > name_length && strncmp(at, name, name_length) == 0 &&
		    at[name_length] == '=') {
			length -= name_length + 1u;
			if (length == 0u || length >= out_size) {
				return 0;
			}
			memcpy(out, at + name_length + 1u, length);
			out[length] = '\0';
			return 1;
		}
		at += length + (end ? 1u : 0u);
	}
	return 0;
}

int ncfg_fuzznet_daemon_socket(const char *run_dir, char *out, size_t out_size)
{
	char store[1024];
	int  wrote;

	if (!run_dir || !out || out_size == 0u) {
		return 0;
	}
	if (node_value(run_dir, "store", store, sizeof(store)) &&
	    ncfg_fuzznet_face(store, out, out_size)) {
		return 1;
	}
	wrote = snprintf(out, out_size, "%s/fuzznet.sock", run_dir);
	return wrote > 0 && (size_t)wrote < out_size;
}

/* Where a page is asked: a socket, and the host for a call across the estate
 * (NULL for the daemon on this machine). */
typedef struct {
	const char *path;
	const char *host;
	const char *request; /* for `ask`; NULL asks `status` */
	const char *eventlog; /* for `eventlog`, its SINCE or `-`; wins over the others */
	char        staged[18]; /* `@DIGEST` once it went in pieces, else "" */
	int         wait_ms;    /* for `ask` on this machine; else fuzznet's round */
	int         ran_maybe;  /* the request may have reached the daemon */
} asked_t;

/* One page over fuzznet: `call status [at HOST] FROM` on the socket in
 * `context`, the answer unescaped. A call across the estate waits for
 * fuzznet's round, three seconds (its sec 853), so it is given more. */
static int fuzznet_page(void *context, size_t from, char *page, size_t cap, size_t *length,
    char *err, size_t err_size)
{
	const asked_t *asked = context;
	char           line[NCFG_FUZZNET_REQUEST_MAX];
	char           reply[2048];
	int            silent = 0;
	long           n;

	if (asked->eventlog) {
		(void)snprintf(line, sizeof(line), "call eventlog %s", asked->eventlog);
		if (asked->eventlog[0] != '-') {
			size_t used = strlen(line);

			(void)snprintf(line + used, sizeof(line) - used, " %zu", from);
		}
	} else if (asked->request) {
		const char *request = asked->staged[0] ? asked->staged : asked->request;
		int wrote = asked->host
		    ? snprintf(line, sizeof(line), "call ask at %s %zu %s", asked->host, from, request)
		    : snprintf(line, sizeof(line), "call ask %zu %s", from, request);

		if (wrote <= 0 || (size_t)wrote >= sizeof(line)) {
			say(err, err_size, "the request is too long for one fuzznet line: %zu bytes",
			    strlen(asked->request));
			return 0;
		}
	} else if (asked->host) {
		(void)snprintf(line, sizeof(line), "call status at %s %zu", asked->host, from);
	} else {
		(void)snprintf(line, sizeof(line), "call status %zu", from);
	}
	if (asked->wait_ms) {
		int sent = 0;

		if (!ask_again(asked->path, line, reply, sizeof(reply), asked->wait_ms, &silent,
		        &sent, err, err_size)) {
			((asked_t *)context)->ran_maybe |= sent;
			return 0;
		}
		/* fuzznet's own `ok` or its refusal of the call: the first means the
		 * daemon has it, the second that nothing behind fuzznet saw it. */
		((asked_t *)context)->ran_maybe |= strncmp(reply, "ok ", 3) == 0;
	} else if (!ncfg_fuzznet_ask(asked->path, line, reply, sizeof(reply),
	               asked->host ? 8000 : 2000, &silent, err, err_size)) {
		return 0;
	}
	if (strncmp(reply, "ok ", 3) != 0) {
		say(err, err_size, "fuzznet answered %.160s", reply);
		return 0;
	}
	n = ncfg_fuzznet_unescape(reply + 3, strlen(reply + 3), page, cap);
	if (n < 0) {
		say(err, err_size, "fuzznet's answer is not escaped as fuzznet escapes");
		return 0;
	}
	*length = (size_t)n;
	return 1;
}

/*
 * The pages of `asked`, asking again while the daemon says it is still at it: a
 * procedure answers at once, so a slow request runs beside fuzznet's loop and is
 * collected. Bounded by the longest wait such a request has, with room over.
 */
static int pages_of_work(asked_t *asked, char **out, size_t *length, char *err, size_t err_size)
{
	const struct timespec look = { 0, 100000000L };
	int                   looks;

	for (looks = 0;; looks++) {
		int joined = ncfg_status_pages_join(fuzznet_page, asked, out, length, err, err_size);

		if (!joined || !strstr(*out, "working on that; ask again")) {
			return joined;
		}
		if (looks >= 150) {
			return joined; /* said to the caller as it stands */
		}
		free(*out);
		*out = NULL;
		(void)nanosleep(&look, NULL);
	}
}

int ncfg_fuzznet_status(const char *run_dir, char **out, size_t *length, char *err,
    size_t err_size)
{
	char path[1100];

	asked_t asked;

	if (!ncfg_fuzznet_daemon_socket(run_dir, path, sizeof(path))) {
		say(err, err_size, "no fuzznet socket path fits");
		return 0;
	}
	memset(&asked, 0, sizeof(asked));
	asked.path = path;
	return ncfg_status_pages_join(fuzznet_page, &asked, out, length, err, err_size);
}

int ncfg_fuzznet_user_socket(char *out, size_t out_size)
{
	const char *run = getenv("XDG_RUNTIME_DIR");
	int         wrote;

	if (!out || out_size == 0u) {
		return 0;
	}
	if (run && run[0] == '/') {
		wrote = snprintf(out, out_size, "%s/fuzznet/fuzznetd.sock", run);
	} else {
		wrote = snprintf(out, out_size, "/tmp/fuzznet-%lu/fuzznetd.sock",
		    (unsigned long)getuid());
	}
	return wrote > 0 && (size_t)wrote < out_size;
}

/* Connected and let go, with nothing asked: a socket left behind by a node that
 * died refuses, and this is asked before every use. */
static int user_host_answers(const char *socket_path)
{
	struct sockaddr_un address;
	int                fd;
	int                up;

	if (strlen(socket_path) >= sizeof(address.sun_path)) {
		return 0;
	}
	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		return 0;
	}
	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	memcpy(address.sun_path, socket_path, strlen(socket_path) + 1u);
	up = connect(fd, (const struct sockaddr *)&address, sizeof(address)) == 0;
	(void)close(fd);
	return up;
}

int ncfg_fuzznet_user_lock(char *out, size_t out_size)
{
	char *slash;

	if (!out || !ncfg_fuzznet_user_socket(out, out_size)) {
		return 0;
	}
	slash = strrchr(out, '/');
	if (!slash || (size_t)(slash - out) + sizeof("/ncfg-clients.lock") > out_size) {
		return 0;
	}
	memcpy(slash, "/ncfg-clients.lock", sizeof("/ncfg-clients.lock"));
	return 1;
}

/* Where a person's store is, as fuzznet's default puts it: only joining makes one,
 * so this is whether they are a host (0314). A look, and nothing read. */
int ncfg_fuzznet_user_joined(void)
{
	const char *data = getenv("XDG_DATA_HOME");
	const char *home = getenv("HOME");
	char        path[1100];
	struct stat seen;
	int         wrote;

	if (data && data[0] == '/') {
		wrote = snprintf(path, sizeof(path), "%s/fuzznet", data);
	} else if (home && home[0] == '/') {
		wrote = snprintf(path, sizeof(path), "%s/.local/share/fuzznet", home);
	} else {
		return 0;
	}
	return wrote > 0 && (size_t)wrote < sizeof(path) && stat(path, &seen) == 0 &&
	       S_ISDIR(seen.st_mode);
}

#ifndef __ANDROID__
/*
 * This process's hold on the host daemon, for as long as it runs (0314): a shared
 * lock, which the kernel lets go of however the process ends. Taken before the
 * daemon is looked for or started. One going away holds the lock exclusively until
 * it has gone, so a look that waits here finds nothing and starts another rather
 * than leaning on one that is stopping.
 */
static int user_host_hold(char *why, size_t why_size)
{
	static _Atomic int    held = -1;
	const struct timespec look = { 0, 10000000L };
	char                  path[1100];
	char                 *slash;
	int                   fd;
	int                   looks;
	int                   none = -1;

	if (held >= 0) {
		return 1;
	}
	if (!ncfg_fuzznet_user_lock(path, sizeof(path))) {
		say(why, why_size, "this user's host lock path does not fit");
		return 0;
	}
	/* The daemon makes these too, private, but this comes first. */
	slash = strrchr(path, '/');
	*slash = '\0';
	(void)mkdir(path, 0700);
	*slash = '/';
	fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
	if (fd < 0) {
		say(why, why_size, "could not open %s: %s", path, strerror(errno));
		return 0;
	}
	for (looks = 0; flock(fd, LOCK_SH | LOCK_NB) != 0; looks++) {
		if (looks >= 500) {
			say(why, why_size, "this user's host is taking too long to stop");
			(void)close(fd);
			return 0;
		}
		(void)nanosleep(&look, NULL);
	}
	if (!atomic_compare_exchange_strong(&held, &none, fd)) {
		(void)close(fd); /* another thread of this process holds it */
	}
	return 1;
}

/*
 * Twice forked, so a window that never reaps does not keep a zombie, and in a
 * session of its own, so the node outlives the terminal. Only what is safe
 * after a fork in a process with threads, which a window is: the path is read
 * before it. `ncfg` is the program itself where this is `ncfg`, and the one on
 * the PATH where this is a window.
 */
/* 1 where `ncfg` is on the PATH: without one there is nothing to wait for, and
 * a window asks this from its own thread. */
static int user_host_program(void)
{
	const char *path = getenv("PATH");
	char        candidate[4096];

	while (path && *path) {
		const char  *end = strchr(path, ':');
		const size_t length = end ? (size_t)(end - path) : strlen(path);
		const int    wrote = snprintf(candidate, sizeof(candidate), "%.*s/ncfg", (int)length, path);

		if (wrote > 0 && (size_t)wrote < sizeof(candidate) && access(candidate, X_OK) == 0) {
			return 1;
		}
		path = end ? end + 1 : NULL;
	}
	return 0;
}

static int user_host_spawn(void)
{
	char *const argv[] = { (char *)"ncfg", (char *)"host", (char *)"--while-held", NULL };
	char        self[4096];
	ssize_t     length = readlink("/proc/self/exe", self, sizeof(self) - 1u);
	int         own = 0;
	pid_t       child;

	if (length > 8) {
		self[length] = '\0';
		own = strcmp(self + length - 8, "/netcfgd") == 0;
	}
	if (!own && !user_host_program()) {
		return 0;
	}
	child = fork();
	if (child == 0) {
		int fd;

		(void)setsid();
		if (fork() != 0) {
			_exit(0);
		}
		fd = open("/dev/null", O_RDWR);
		if (fd >= 0) {
			(void)dup2(fd, 0);
			(void)dup2(fd, 1);
			(void)dup2(fd, 2);
		}
		for (fd = 3; fd < 1024; fd++) {
			(void)close(fd);
		}
		if (own) {
			(void)execv(self, argv);
		}
		(void)execvp("ncfg", argv);
		_exit(127);
	}
	if (child > 0) {
		(void)waitpid(child, NULL, 0);
	}
	return child > 0;
}
#endif

int ncfg_fuzznet_user_host(int start, char *why, size_t why_size)
{
	char socket[1100];

	if (!ncfg_fuzznet_user_socket(socket, sizeof(socket))) {
		say(why, why_size, "this user's host socket path does not fit");
		return 0;
	}
#ifndef __ANDROID__
	if (start != NCFG_FUZZNET_HOST_LOOK) {
		const struct timespec look = { 0, 10000000L };
		int                   looks;

		if (start == NCFG_FUZZNET_HOST_USE && !ncfg_fuzznet_user_joined() &&
		    !user_host_answers(socket)) {
			say(why, why_size, "this user is no host yet: `ncfg join` with a host's code");
			return 0;
		}
		if (!user_host_hold(why, why_size)) {
			return 0;
		}
		if (user_host_answers(socket)) {
			return 1;
		}
		if (!user_host_spawn()) {
			say(why, why_size, "this user's host did not start: `ncfg` is not installed");
			return 0;
		}
		for (looks = 0; looks < 500; looks++) {
			if (user_host_answers(socket)) {
				return 1;
			}
			(void)nanosleep(&look, NULL);
		}
		say(why, why_size, "this user's host did not start");
		return 0;
	}
#else
	(void)start;
#endif
	if (user_host_answers(socket)) {
		return 1;
	}
	say(why, why_size, "this user's host is not running");
	return 0;
}

int ncfg_fuzznet_status_at(const char *socket, const char *host, char **out, size_t *length,
    char *err, size_t err_size)
{
	asked_t asked;
	size_t  at;

	/* The key as fuzznet writes it, 64 hex digits: anything else would put
	 * a word of the caller's into the line fuzznet reads. */
	for (at = 0; host && host[at]; at++) {
		char c = host[at];

		if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
			break;
		}
	}
	if (!socket || !host || at != 64u || host[at] != '\0') {
		say(err, err_size, "a host is its key, 64 lower-case hex digits");
		return 0;
	}
	memset(&asked, 0, sizeof(asked));
	asked.path = socket;
	asked.host = host;
	return ncfg_status_pages_join(fuzznet_page, &asked, out, length, err, err_size);
}

/* A piece of a long request: what fits fuzznet's 512-byte line beside `call
 * askpart at HOST TOTAL OFFSET DIGEST ` (about 110 bytes), with room to
 * spare; and the longest request sent whole beside `call ask at HOST FROM `. */
#define ASK_PIECE 360u

/* `request` to `host` in pieces, in order, each answered `ok HAVE TOTAL`. */
static int send_in_pieces(const char *socket, const char *host, const char *request,
    char *err, size_t err_size)
{
	size_t   total = strlen(request);
	uint64_t digest = ncfg_status_page_digest(request, total);
	size_t   offset = 0;

	while (offset < total) {
		char   line[NCFG_FUZZNET_REQUEST_MAX];
		char   reply[256];
		size_t piece = total - offset < ASK_PIECE ? total - offset : ASK_PIECE;
		int    silent = 0;
		int    wrote = host
		    ? snprintf(line, sizeof(line), "call askpart at %s %zu %zu %016llx %.*s", host,
		          total, offset, (unsigned long long)digest, (int)piece, request + offset)
		    : snprintf(line, sizeof(line), "call askpart %zu %zu %016llx %.*s", total, offset,
		          (unsigned long long)digest, (int)piece, request + offset);

		if (wrote <= 0 || (size_t)wrote >= sizeof(line)) {
			say(err, err_size, "a piece of the request does not fit a line");
			return 0;
		}
		if (!ncfg_fuzznet_ask(socket, line, reply, sizeof(reply), 8000, &silent, err,
		        err_size)) {
			return 0;
		}
		/* fuzznet's `ok`, then the node's escaped `ok%20HAVE%20TOTAL` -- or,
		 * staged at many hosts, propagation's own `ok TOTAL ANSWERED`. */
		if (host && ncfg_fuzznet_target_is_many(host) ? strncmp(reply, "ok ", 3) != 0
		                                              : strncmp(reply, "ok ok%20", 8) != 0) {
			say(err, err_size, "sending the request in pieces: %.160s", reply);
			return 0;
		}
		offset += piece;
	}
	return 1;
}

int ncfg_fuzznet_ask_at(const char *socket, const char *host, const char *request, char **out,
    size_t *length, char *err, size_t err_size)
{
	asked_t asked;
	size_t  at;

	for (at = 0; host && host[at]; at++) {
		char c = host[at];

		if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
			break;
		}
	}
	if (!socket || !host || at != 64u || host[at] != '\0') {
		say(err, err_size, "a host is its key, 64 lower-case hex digits");
		return 0;
	}
	/* One line: a newline in it would be a second request to fuzznet. */
	if (!request || strchr(request, '\n')) {
		say(err, err_size, "a request is one line");
		return 0;
	}
	memset(&asked, 0, sizeof(asked));
	asked.path = socket;
	asked.host = host;
	asked.request = request;
	if (strlen(request) > ASK_PIECE) {
		if (!send_in_pieces(socket, host, request, err, err_size)) {
			return 0;
		}
		(void)snprintf(asked.staged, sizeof(asked.staged), "@%016llx",
		    (unsigned long long)ncfg_status_page_digest(request, strlen(request)));
	}
	return pages_of_work(&asked, out, length, err, err_size);
}

int ncfg_fuzznet_run_dir_of(const char *socket_path, char *out, size_t out_size)
{
	const char *slash = socket_path ? strrchr(socket_path, '/') : NULL;

	if (!slash || slash == socket_path || strcmp(slash, "/netcfgd.sock") != 0 ||
	    (size_t)(slash - socket_path) >= out_size) {
		return 0;
	}
	memcpy(out, socket_path, (size_t)(slash - socket_path));
	out[slash - socket_path] = '\0';
	return 1;
}

/* A request can take as long as an apply does; the control socket waits as
 * long, for the same daemon. */
#define ASK_HERE_WAIT_MS 300000

int ncfg_fuzznet_ask_here(const char *run_dir, const char *request, char **out, size_t *length,
    int *nothing_ran, char *err, size_t err_size)
{
	char    socket[1100];
	asked_t asked;
	int     joined;

	*nothing_ran = 1;
	if (!ncfg_fuzznet_daemon_socket(run_dir, socket, sizeof(socket))) {
		say(err, err_size, "this daemon serves no fuzznet node");
		return 0;
	}
	if (!request || strchr(request, '\n')) {
		*nothing_ran = 0;
		say(err, err_size, "a request is one line");
		return 0;
	}
	memset(&asked, 0, sizeof(asked));
	asked.path = socket;
	asked.request = request;
	asked.wait_ms = ASK_HERE_WAIT_MS;
	if (strlen(request) > ASK_PIECE) {
		/* A piece is not the request: until the whole of it is asked for
		 * below, nothing has run, so a failure here is still a fallback. */
		if (!send_in_pieces(socket, NULL, request, err, err_size)) {
			return 0;
		}
		(void)snprintf(asked.staged, sizeof(asked.staged), "@%016llx",
		    (unsigned long long)ncfg_status_page_digest(request, strlen(request)));
	}
	joined = pages_of_work(&asked, out, length, err, err_size);
	*nothing_ran = !joined && !asked.ran_maybe;
	return joined;
}

/* A key of 64 lower-case hex digits at `text`, ending at `end`. */
static int key_at(const char *text, const char *end)
{
	const char *at;

	if (end - text != 64) {
		return 0;
	}
	for (at = text; at < end; at++) {
		if (!((*at >= '0' && *at <= '9') || (*at >= 'a' && *at <= 'f'))) {
			return 0;
		}
	}
	return 1;
}

/* `through_root`: asked of a root netcfgd's `hosts`, which hands on the same list
 * as a procedure's answer, escaped. */
static int members_of(const char *socket, int through_root,
    char (*keys)[NCFG_FUZZNET_KEY_TEXT], size_t cap, size_t *count, char *err, size_t err_size)
{
	char   reply[2048];
	size_t from = 0;
	size_t pages = 0;
	size_t total = 0;

	if (!socket || !keys || !count) {
		say(err, err_size, "nowhere to list the estate's members into");
		return 0;
	}
	*count = 0;
	do {
		char          line[48];
		char         *at;
		char         *end;
		unsigned long t;
		unsigned long f;
		size_t        taken = 0;
		int           silent = 0;

		(void)snprintf(line, sizeof(line), through_root ? "call hosts %zu" : "list peer %zu", from);
		if (!ncfg_fuzznet_ask(socket, line, reply, sizeof(reply), 2000, &silent, err,
		        err_size)) {
			return 0;
		}
		if (through_root && strncmp(reply, "ok ", 3) == 0) {
			char plain[sizeof(reply)];
			long n = ncfg_fuzznet_unescape(reply + 3, strcspn(reply + 3, "\r\n"), plain,
			    sizeof(plain) - 1u);

			if (n < 0) {
				say(err, err_size, "netcfgd's host list is not one");
				return 0;
			}
			plain[n] = '\0';
			memcpy(reply, plain, (size_t)n + 1u);
		}
		if (strncmp(reply, "ok ", 3) != 0) {
			say(err, err_size, "fuzznet answered %.160s", reply);
			return 0;
		}
		t = strtoul(reply + 3, &end, 10);
		if (end == reply + 3 || *end != ' ') {
			say(err, err_size, "fuzznet's peer list is not one: %.80s", reply);
			return 0;
		}
		at = end + 1;
		f = strtoul(at, &end, 10);
		if (end == at || (*end != ' ' && *end != '\0') || f != from || t > 1000000ul) {
			say(err, err_size, "fuzznet's peer list is not one: %.80s", reply);
			return 0;
		}
		total = (size_t)t;
		at = end;
		while (*at == ' ') {
			char *word = ++at;
			char *stop = strchr(word, ' ');
			char *key_end;

			if (!stop) {
				stop = word + strlen(word);
			}
			key_end = memchr(word, ',', (size_t)(stop - word));
			if (!key_end) {
				key_end = stop;
			}
			if (!key_at(word, key_end)) {
				say(err, err_size, "fuzznet listed a peer that is not a key: %.80s", word);
				return 0;
			}
			taken++;
			if (key_end == stop) { /* no `,contact`: a member */
				if (*count >= cap) {
					say(err, err_size, "the estate has more than %zu members", cap);
					return 0;
				}
				memcpy(keys[*count], word, 64u);
				keys[*count][64] = '\0';
				(*count)++;
			}
			at = stop;
		}
		if (taken == 0 && from < total) {
			say(err, err_size, "fuzznet's peer list made no progress from %zu", from);
			return 0;
		}
		from += taken;
	} while (from < total && ++pages < 100000u);
	return from >= total;
}

int ncfg_fuzznet_members(const char *socket, char (*keys)[NCFG_FUZZNET_KEY_TEXT], size_t cap,
    size_t *count, char *err, size_t err_size)
{
	return members_of(socket, 0, keys, cap, count, err, err_size);
}

int ncfg_fuzznet_root_members(const char *run_dir, char (*keys)[NCFG_FUZZNET_KEY_TEXT],
    size_t cap, size_t *count, char *err, size_t err_size)
{
	char path[1100];

	if (!ncfg_fuzznet_daemon_socket(run_dir, path, sizeof(path))) {
		say(err, err_size, "no fuzznet socket path fits");
		return 0;
	}
	return members_of(path, 1, keys, cap, count, err, err_size);
}

int ncfg_fuzznet_events_at(const char *socket, const char *host, size_t from, size_t *next,
    size_t *first, char (*subjects)[NCFG_FUZZNET_SUBJECT_TEXT], size_t cap, size_t *count,
    char *err, size_t err_size)
{
	char   line[160];
	char   reply[2048];
	char   text[2048];
	long   n;
	int    silent = 0;
	size_t digit;

	for (digit = 0; host && host[digit]; digit++) {
		if (!((host[digit] >= '0' && host[digit] <= '9') ||
		        (host[digit] >= 'a' && host[digit] <= 'f'))) {
			break;
		}
	}
	if (!socket || !host || digit != 64u || host[digit] != '\0' || !next || !first ||
	    !count) {
		say(err, err_size, "a host is its key, 64 lower-case hex digits");
		return 0;
	}
	*count = 0;
	(void)snprintf(line, sizeof(line), "call events at %s %zu", host, from);
	if (!ncfg_fuzznet_ask(socket, line, reply, sizeof(reply), 8000, &silent, err, err_size)) {
		return 0;
	}
	if (strncmp(reply, "ok ", 3) != 0) {
		say(err, err_size, "fuzznet answered %.160s", reply);
		return 0;
	}
	n = ncfg_fuzznet_unescape(reply + 3, strlen(reply + 3), text, sizeof(text) - 1u);
	if (n < 0) {
		say(err, err_size, "fuzznet's answer is not escaped as fuzznet escapes");
		return 0;
	}
	text[n] = '\0';
	return ncfg_fuzznet_events_read(text, (size_t)n, next, first, subjects, cap, count, err,
	    err_size);
}

/* Decimal digits only at `*at`, as the page reader reads them (no sign, no
 * space, which `strtoul` alone would take): 1 with the value, or 0. */
static int events_number(char **at, size_t *out)
{
	size_t value = 0;
	char  *start = *at;

	while (**at >= '0' && **at <= '9' && *at - start < 20) {
		size_t digit = (size_t)(**at - '0');

		if (value > ((size_t)-1 - digit) / 10u) {
			return 0;
		}
		value = value * 10u + digit;
		(*at)++;
	}
	if (*at == start) {
		return 0;
	}
	*out = value;
	return 1;
}

int ncfg_fuzznet_events_read(const char *text, size_t length, size_t *next, size_t *first,
    char (*subjects)[NCFG_FUZZNET_SUBJECT_TEXT], size_t cap, size_t *count, char *err,
    size_t err_size)
{
	char   copy[2048];
	char  *at = copy;
	size_t digit;

	if (!text || !next || !first || !count || length >= sizeof(copy) ||
	    memchr(text, '\0', length) != NULL) {
		say(err, err_size, "that node's events are not a list");
		return 0;
	}
	*count = 0;
	memcpy(copy, text, length);
	copy[length] = '\0';
	/* `NEXT FIRST`, then a SUBJECT and a NAME for each event: fuzznet's
	 * `fzn_node_events_since`, with no `ok` of its own inside the call's. */
	if (!events_number(&at, next) || *at++ != ' ' || !events_number(&at, first) ||
	    (*at != ' ' && *at != '\0')) {
		say(err, err_size, "that node's events are not a list: %.80s", copy);
		return 0;
	}
	while (*at == ' ') {
		char  *subject = ++at;
		size_t size;

		while (*at && *at != ' ') {
			at++;
		}
		size = (size_t)(at - subject);
		if (size == 0u || size >= NCFG_FUZZNET_SUBJECT_TEXT || *at != ' ') {
			say(err, err_size, "that node listed an event that is not one: %.80s", subject);
			return 0;
		}
		/* Lower-case letters and hyphens, as fuzznet publishes them -- held
		 * here too, not trusted to the other host's fuzznet, since a subject
		 * is printed and a quote in one would forge a line of `--json`. */
		for (digit = 0; digit < size; digit++) {
			if (!((subject[digit] >= 'a' && subject[digit] <= 'z') || subject[digit] == '-')) {
				say(err, err_size, "that node listed an event that is not one: %.80s",
				    subject);
				return 0;
			}
		}
		at++;
		while (*at && *at != ' ') {
			at++; /* the NAME, which netcfgd's events do not carry */
		}
		if (*count < cap) {
			memcpy(subjects[*count], subject, size);
			subjects[*count][size] = '\0';
		}
		(*count)++;
	}
	if (*at != '\0') {
		say(err, err_size, "that node's events are not a list: %.80s", copy);
		return 0;
	}
	/* More than room: NEXT is already past them all, so the ones not kept are
	 * gone from this caller's view -- said the way a gap is said, FIRST past
	 * the cursor, so the caller re-reads the status rather than missing them. */
	if (*count > cap) {
		*count = cap;
		*first = *next;
	}
	return 1;
}

int ncfg_fuzznet_target_is_many(const char *target)
{
	size_t at;

	if (!target) {
		return 0;
	}
	if (strcmp(target, "estate") == 0) {
		return 1;
	}
	if (strncmp(target, "group=", 6) != 0 || target[6] == '\0' || strlen(target + 6) > 32u) {
		return 0;
	}
	for (at = 6; target[at]; at++) {
		char c = target[at];

		if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_' ||
		        c == '-')) {
			return 0;
		}
	}
	return 1;
}

int ncfg_fuzznet_do_many(const char *socket, const char *target, const char *request,
    char *rows, size_t rows_size, char *err, size_t err_size)
{
	char line[NCFG_FUZZNET_REQUEST_MAX];
	char named[18];
	int  silent = 0;
	int  wrote;

	if (!socket || !rows || rows_size == 0u || !request || strchr(request, '\n') ||
	    !ncfg_fuzznet_target_is_many(target)) {
		say(err, err_size, "propagation takes `estate` or `group=NAME`, and one request line");
		return 0;
	}
	named[0] = '\0';
	/* Long, so staged at every host first, as `--at HOST` stages at one. */
	if (strlen(request) > ASK_PIECE) {
		if (!send_in_pieces(socket, target, request, err, err_size)) {
			return 0;
		}
		(void)snprintf(named, sizeof(named), "@%016llx",
		    (unsigned long long)ncfg_status_page_digest(request, strlen(request)));
	}
	wrote = snprintf(line, sizeof(line), "call do at %s %s", target, named[0] ? named : request);
	if (wrote <= 0 || (size_t)wrote >= sizeof(line)) {
		say(err, err_size, "the request does not fit one fuzznet line");
		return 0;
	}
	if (!ncfg_fuzznet_ask(socket, line, rows, rows_size, 60000, &silent, err, err_size)) {
		return 0;
	}
	if (strncmp(rows, "ok ", 3) != 0) {
		say(err, err_size, "fuzznet answered %.160s", rows);
		return 0;
	}
	return 1;
}

int ncfg_fuzznet_events_hold(const char *run_dir, char *why, size_t why_size)
{
	static const char  request[] = "get events\n";
	struct sockaddr_un address;
	char               path[1100];
	char               buffer[256];
	char               reply[256];
	size_t             have = 0;
	int                fd;

	if (!ncfg_fuzznet_daemon_socket(run_dir, path, sizeof(path)) ||
	    strlen(path) >= sizeof(address.sun_path)) {
		say(why, why_size, "no fuzznet socket path fits");
		return -1;
	}
	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		say(why, why_size, "no socket: %s", strerror(errno));
		return -1;
	}
	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	memcpy(address.sun_path, path, strlen(path) + 1u);
	if (connect(fd, (const struct sockaddr *)&address, sizeof(address)) != 0 ||
	    write(fd, request, sizeof(request) - 1u) != (ssize_t)(sizeof(request) - 1u)) {
		say(why, why_size, "fuzznet is not at %s: %s", path, strerror(errno));
		(void)close(fd);
		return -1;
	}
	/* Byte by byte, so nothing of the stream is read past its first line. */
	while (have + 1u < sizeof(buffer)) {
		struct pollfd wait = { fd, POLLIN, 0 };
		char          byte;

		if (poll(&wait, 1, 3000) <= 0 || read(fd, &byte, 1) != 1) {
			say(why, why_size, "fuzznet at %s gave no answer", path);
			(void)close(fd);
			return -1;
		}
		if (byte == '\n') {
			break;
		}
		buffer[have++] = byte;
	}
	memcpy(reply, buffer, have);
	reply[have] = '\0';
	if (strcmp(reply, "ok events") != 0) {
		say(why, why_size, "fuzznet would not hold netcfgd's events: %.160s", reply);
		(void)close(fd);
		return -1;
	}
	return fd;
}

static int event_json(const char *line, char *out, size_t out_size)
{
	static const struct {
		const char *subject;
		const char *event;
		const char *summary;
	} kinds[] = {
		{ "net-observed", "observed", "the machine changed: its status has what" },
		{ "net-reloaded", "reloaded", "the configuration was read again: its status has how" },
		{ "net-drift", "drift", "the machine drifted from its configuration" },
		{ "net-armed", "confirm_armed", "a confirm window opened" },
		{ "net-resolved", "confirm_resolved", "a confirm window closed" },
	};
	static const char word[] = "event ";

	if (!line || strncmp(line, word, sizeof(word) - 1u) != 0) {
		return 0;
	}
	line += sizeof(word) - 1u;
	for (size_t at = 0; at < sizeof(kinds) / sizeof(kinds[0]); at++) {
		size_t length = strlen(kinds[at].subject);
		int    wrote;

		if (strncmp(line, kinds[at].subject, length) != 0 ||
		    (line[length] != ' ' && line[length] != '\0')) {
			continue;
		}
		wrote = snprintf(out, out_size, "{\"event\":\"%s\",\"summary\":\"%s\"}",
		    kinds[at].event, kinds[at].summary);
		return wrote > 0 && (size_t)wrote < out_size;
	}
	return 0;
}

/* The events since `events->cursor` into `pending`, the cursor moved on. */
static int events_read(ncfg_fuzznet_events_t *events)
{
	char    path[1100];
	char    since[32];
	char    why[256];
	char   *text = NULL;
	char   *end = NULL;
	size_t  length = 0;
	asked_t asked;
	long    next;

	if (!ncfg_fuzznet_daemon_socket(events->run_dir, path, sizeof(path))) {
		return 0;
	}
	memset(&asked, 0, sizeof(asked));
	asked.path = path;
	(void)snprintf(since, sizeof(since), "%ld", events->cursor);
	asked.eventlog = events->cursor < 0 ? "-" : since;
	if (!ncfg_status_pages_join(fuzznet_page, &asked, &text, &length, why, sizeof(why))) {
		return 0;
	}
	next = strtol(text, &end, 10);
	if (end == text || *end != '\n' || next < 0) {
		free(text);
		return 0;
	}
	free(events->pending);
	events->pending = text;
	events->length = length;
	events->at = (size_t)(end + 1 - text);
	events->cursor = next;
	return 1;
}

int ncfg_fuzznet_events_tick(const char *run_dir, char *why, size_t why_size)
{
	static const char line[] = "event net-tick -\n";
	char              path[1100];
	char              reply[256];
	int               silent = 0;
	int               ends[2];
	pid_t             child;

	if (!ncfg_fuzznet_daemon_socket(run_dir, path, sizeof(path))) {
		say(why, why_size, "no fuzznet socket path fits");
		return -1;
	}
	if (!ncfg_fuzznet_ask(path, "call eventlog -", reply, sizeof(reply), 2000, &silent, why,
	        why_size)) {
		return -1;
	}
	if (strncmp(reply, "ok ", 3) != 0) {
		say(why, why_size, "fuzznet would not hold netcfgd's events: %.120s", reply);
		return -1;
	}
	/* A socket, as every reader of a stream here reads with `recv`. */
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, ends) != 0) {
		say(why, why_size, "no socket pair: %s", strerror(errno));
		return -1;
	}
	/* Twice forked, as `user_host_spawn` is, for a window that never reaps, and only
	 * what is safe after a fork in a process with threads. The reader going takes
	 * this with it by the write failing, and the daemon going ends the stream as a
	 * held one ends. */
	child = fork();
	if (child == 0) {
		const struct timespec look = { 2, 0 };
		int                   fd;

		if (fork() != 0) {
			_exit(0);
		}
		for (fd = 3; fd < 1024; fd++) {
			if (fd != ends[1]) {
				(void)close(fd);
			}
		}
		while (user_host_answers(path) && write(ends[1], line, sizeof(line) - 1u) > 0) {
			(void)nanosleep(&look, NULL);
		}
		_exit(0);
	}
	(void)close(ends[1]);
	if (child < 0) {
		say(why, why_size, "no process to watch with: %s", strerror(errno));
		(void)close(ends[0]);
		return -1;
	}
	(void)waitpid(child, NULL, 0);
	return ends[0];
}

void ncfg_fuzznet_events_begin(ncfg_fuzznet_events_t *events, const char *run_dir)
{
	memset(events, 0, sizeof(*events));
	events->cursor = -1;
	(void)snprintf(events->run_dir, sizeof(events->run_dir), "%s", run_dir);
	(void)events_read(events);
}

void ncfg_fuzznet_events_heard(ncfg_fuzznet_events_t *events, const char *line)
{
	char json[256];

	/* Everything waiting is what this one was told of; only what has been given
	 * out already goes, or a burst heard together would lose its earlier half. */
	if (events->at < events->length) {
		return;
	}
	if (events->cursor >= 0 && events_read(events)) {
		return;
	}
	if (event_json(line, json, sizeof(json))) {
		size_t length = strlen(json);
		char  *copy = malloc(length + 2u);

		if (copy) {
			memcpy(copy, json, length);
			copy[length] = '\n';
			copy[length + 1u] = '\0';
			free(events->pending);
			events->pending = copy;
			events->length = length + 1u;
			events->at = 0;
		}
	}
}

int ncfg_fuzznet_events_take(ncfg_fuzznet_events_t *events, const char **line, size_t *length)
{
	char *newline;

	if (!events->pending || events->at >= events->length) {
		return 0;
	}
	*line = events->pending + events->at;
	newline = memchr(events->pending + events->at, '\n', events->length - events->at);
	*length = newline ? (size_t)(newline - *line) : events->length - events->at;
	events->at += *length + 1u;
	return 1;
}

void ncfg_fuzznet_events_end(ncfg_fuzznet_events_t *events)
{
	free(events->pending);
	events->pending = NULL;
}
