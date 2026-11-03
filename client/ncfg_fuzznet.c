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
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
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

int ncfg_fuzznet_ask(const char *path, const char *line, char *reply, size_t reply_size,
    int wait_ms, int *silent, char *why, size_t why_size)
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
	char        staged[18]; /* `@DIGEST` once it went in pieces, else "" */
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

	if (asked->request) {
		int wrote = snprintf(line, sizeof(line), "call ask at %s %zu %s", asked->host, from,
		    asked->staged[0] ? asked->staged : asked->request);

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
	if (!ncfg_fuzznet_ask(asked->path, line, reply, sizeof(reply), asked->host ? 8000 : 2000,
	        &silent, err, err_size)) {
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

int ncfg_fuzznet_status(const char *run_dir, char **out, size_t *length, char *err,
    size_t err_size)
{
	char path[1100];

	asked_t asked;

	if (!ncfg_fuzznet_daemon_socket(run_dir, path, sizeof(path))) {
		say(err, err_size, "no fuzznet socket path fits");
		return 0;
	}
	asked.path = path;
	asked.host = NULL;
	asked.request = NULL;
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
	asked.path = socket;
	asked.host = host;
	asked.request = NULL;
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
		int    wrote = snprintf(line, sizeof(line), "call askpart at %s %zu %zu %016llx %.*s",
		    host, total, offset, (unsigned long long)digest, (int)piece, request + offset);

		if (wrote <= 0 || (size_t)wrote >= sizeof(line)) {
			say(err, err_size, "a piece of the request does not fit a line");
			return 0;
		}
		if (!ncfg_fuzznet_ask(socket, line, reply, sizeof(reply), 8000, &silent, err,
		        err_size)) {
			return 0;
		}
		/* fuzznet's `ok`, then the node's escaped `ok%20HAVE%20TOTAL`. */
		if (strncmp(reply, "ok ok%20", 8) != 0) {
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
	asked.path = socket;
	asked.host = host;
	asked.request = request;
	asked.staged[0] = '\0';
	if (strlen(request) > ASK_PIECE) {
		if (!send_in_pieces(socket, host, request, err, err_size)) {
			return 0;
		}
		(void)snprintf(asked.staged, sizeof(asked.staged), "@%016llx",
		    (unsigned long long)ncfg_status_page_digest(request, strlen(request)));
	}
	return ncfg_status_pages_join(fuzznet_page, &asked, out, length, err, err_size);
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

int ncfg_fuzznet_members(const char *socket, char (*keys)[NCFG_FUZZNET_KEY_TEXT], size_t cap,
    size_t *count, char *err, size_t err_size)
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

		(void)snprintf(line, sizeof(line), "list peer %zu", from);
		if (!ncfg_fuzznet_ask(socket, line, reply, sizeof(reply), 2000, &silent, err,
		        err_size)) {
			return 0;
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

int ncfg_fuzznet_events_at(const char *socket, const char *host, size_t from, size_t *next,
    size_t *first, char (*subjects)[NCFG_FUZZNET_SUBJECT_TEXT], size_t cap, size_t *count,
    char *err, size_t err_size)
{
	char          line[160];
	char          reply[2048];
	char          text[2048];
	char         *at;
	char         *end;
	unsigned long value;
	long          n;
	int           silent = 0;
	size_t        digit;

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
	/* `NEXT FIRST`, then a SUBJECT and a NAME for each event: fuzznet's
	 * `fzn_node_events_since`, with no `ok` of its own inside the call's. */
	value = strtoul(text, &end, 10);
	if (end == text || *end != ' ' || text[0] < '0' || text[0] > '9') {
		say(err, err_size, "that node's events are not a list: %.80s", text);
		return 0;
	}
	*next = (size_t)value;
	at = end + 1;
	value = strtoul(at, &end, 10);
	if (end == at || (*end != ' ' && *end != '\0')) {
		say(err, err_size, "that node's events are not a list: %.80s", text);
		return 0;
	}
	*first = (size_t)value;
	at = end;
	while (*at == ' ') {
		char  *subject = ++at;
		size_t length;

		while (*at && *at != ' ') {
			at++;
		}
		length = (size_t)(at - subject);
		if (length == 0u || length >= NCFG_FUZZNET_SUBJECT_TEXT || *at != ' ') {
			say(err, err_size, "that node listed an event that is not one: %.80s", subject);
			return 0;
		}
		/* Lower-case letters and hyphens, as fuzznet publishes them -- held
		 * here too, not trusted to the other host's fuzznet, since a subject
		 * is printed and a quote in one would forge a line of `--json`. */
		for (digit = 0; digit < length; digit++) {
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
			memcpy(subjects[*count], subject, length);
			subjects[*count][length] = '\0';
		}
		(*count)++;
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
