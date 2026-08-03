/*
 * ncfg_client.c -- the connection described in ncfg_client.h.
 */
#include "ncfg_client.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

/* The daemon's compiled-in default, and the one `ncfg` resolves to. Kept as a
 * literal rather than read from anywhere: it is part of the installed layout,
 * and a client that guessed differently would silently talk to nothing. */
#define NCFG_DEFAULT_RUN_DIR "/run/netcfgd"
#define NCFG_SOCKET_NAME     "netcfgd.sock"

/* A response is a line, and a status on a busy router is the largest of them:
 * every link, address, route and backend. A megabyte is far past that and is
 * still a bound -- without one, a peer that never sends a newline is a client
 * that grows until it is killed. */
#define NCFG_LINE_MAX (1024u * 1024u)

struct ncfg_client {
	int    fd;
	char   path[108]; /* sun_path is 108 on Linux, so a longer one cannot be
			   * connected to anyway and is refused when it is set */
	char  *buffer;    /* what has been read and not yet consumed */
	size_t length;
	size_t capacity;
};

static void set_error(char *err, size_t err_size, const char *format, ...)
{
	va_list args;

	if (!err || !err_size) {
		return;
	}
	va_start(args, format);
	vsnprintf(err, err_size, format, args);
	va_end(args);
}

const char *ncfg_client_default_socket(void)
{
	static char path[sizeof(((struct ncfg_client *)0)->path)];
	const char *run_dir = getenv("NCFG_RUN_DIR");

	if (!run_dir || !*run_dir) {
		run_dir = NCFG_DEFAULT_RUN_DIR;
	}
	int written = snprintf(path, sizeof(path), "%s/%s", run_dir, NCFG_SOCKET_NAME);
	if (written < 0 || (size_t)written >= sizeof(path)) {
		/* A run directory long enough to overflow sun_path cannot be
		 * connected to by anybody, so returning the default is more
		 * useful than returning a truncation that would fail obscurely. */
		snprintf(path, sizeof(path), "%s/%s", NCFG_DEFAULT_RUN_DIR, NCFG_SOCKET_NAME);
	}
	return path;
}

ncfg_client_t *ncfg_client_open(const char *socket_path, char *err, size_t err_size)
{
	if (err && err_size) {
		err[0] = '\0';
	}
	if (!socket_path || !*socket_path) {
		socket_path = ncfg_client_default_socket();
	}

	struct sockaddr_un address;
	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	if (strlen(socket_path) >= sizeof(address.sun_path)) {
		set_error(err, err_size, "the socket path is longer than a unix socket allows: %s",
			  socket_path);
		return NULL;
	}
	strcpy(address.sun_path, socket_path);

	int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		set_error(err, err_size, "cannot make a socket: %s", strerror(errno));
		return NULL;
	}
	if (connect(fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
		/* The path is in the message on purpose. "Connection refused"
		 * alone sends the reader looking for a network problem, when the
		 * answer is nearly always that netcfgd is not running or that
		 * this client is looking in the wrong run directory. */
		set_error(err, err_size, "cannot reach netcfgd at %s: %s. Is the daemon running?",
			  socket_path, strerror(errno));
		close(fd);
		return NULL;
	}

	ncfg_client_t *client = calloc(1, sizeof(*client));
	if (!client) {
		set_error(err, err_size, "out of memory");
		close(fd);
		return NULL;
	}
	client->fd = fd;
	snprintf(client->path, sizeof(client->path), "%s", socket_path);
	return client;
}

void ncfg_client_close(ncfg_client_t *client)
{
	if (!client) {
		return;
	}
	if (client->fd >= 0) {
		close(client->fd);
	}
	free(client->buffer);
	free(client);
}

const char *ncfg_client_socket_path(const ncfg_client_t *client)
{
	return client ? client->path : "";
}

/* Everything, or a failure. `write` on a socket may write part of a buffer. */
static int write_all(int fd, const char *data, size_t length)
{
	while (length) {
		ssize_t wrote = write(fd, data, length);
		if (wrote < 0) {
			if (errno == EINTR) {
				continue;
			}
			return 0;
		}
		data += (size_t)wrote;
		length -= (size_t)wrote;
	}
	return 1;
}

/*
 * One line from the connection, without its newline.
 *
 * The buffer holds whatever arrived past the end of the line, because a daemon
 * that answered two requests quickly may have put both in one read -- and
 * throwing the second away would lose an answer somebody is waiting for.
 */
static char *read_line(ncfg_client_t *client, size_t *length_out, char *err, size_t err_size)
{
	for (;;) {
		/* Guarded on the length rather than trusting memchr with a null
		 * buffer and zero bytes: that is undefined behaviour even though
		 * every implementation returns NULL, and UBSan says so on the
		 * first read of every fresh connection -- which is how this was
		 * found, in the first headless run of the GUI against a real
		 * daemon. */
		char *newline = client->length ? memchr(client->buffer, '\n', client->length)
					       : NULL;
		if (newline) {
			size_t line_length = (size_t)(newline - client->buffer);
			char *line = malloc(line_length + 1u);
			if (!line) {
				set_error(err, err_size, "out of memory");
				return NULL;
			}
			memcpy(line, client->buffer, line_length);
			line[line_length] = '\0';

			size_t consumed = line_length + 1u;
			memmove(client->buffer, client->buffer + consumed,
				client->length - consumed);
			client->length -= consumed;
			*length_out = line_length;
			return line;
		}

		if (client->length >= NCFG_LINE_MAX) {
			set_error(err, err_size,
				  "netcfgd sent more than %u bytes with no end of line",
				  NCFG_LINE_MAX);
			return NULL;
		}
		if (client->length == client->capacity) {
			size_t next = client->capacity ? client->capacity * 2u : 8192u;
			char *grown = realloc(client->buffer, next);
			if (!grown) {
				set_error(err, err_size, "out of memory");
				return NULL;
			}
			client->buffer = grown;
			client->capacity = next;
		}
		ssize_t got = read(client->fd, client->buffer + client->length,
				   client->capacity - client->length);
		if (got < 0) {
			if (errno == EINTR) {
				continue;
			}
			set_error(err, err_size, "cannot read from netcfgd: %s", strerror(errno));
			return NULL;
		}
		if (got == 0) {
			set_error(err, err_size,
				  "netcfgd closed the connection without answering");
			return NULL;
		}
		client->length += (size_t)got;
	}
}

ncfg_json_doc_t *ncfg_client_request(ncfg_client_t *client, const char *request,
				     char *err, size_t err_size)
{
	if (err && err_size) {
		err[0] = '\0';
	}
	if (!client || !request) {
		set_error(err, err_size, "no client");
		return NULL;
	}
	if (strchr(request, '\n')) {
		/* The same refusal netcfgd-proto's codec.rs makes on its side: a
		 * message containing a newline would frame as two. Refusing here
		 * means a bug in a caller is a message rather than a daemon
		 * reading half a request as a whole one. */
		set_error(err, err_size, "a request may not contain a newline");
		return NULL;
	}

	size_t length = strlen(request);
	if (!write_all(client->fd, request, length) || !write_all(client->fd, "\n", 1)) {
		set_error(err, err_size, "cannot send to netcfgd: %s", strerror(errno));
		return NULL;
	}

	size_t line_length = 0;
	char *line = read_line(client, &line_length, err, err_size);
	if (!line) {
		return NULL;
	}

	char parse_error[NCFG_ERROR_MAX];
	ncfg_json_doc_t *doc = ncfg_json_parse(line, line_length, parse_error,
					       sizeof(parse_error));
	free(line);
	if (!doc) {
		set_error(err, err_size, "netcfgd sent something this cannot read: %s",
			  parse_error);
		return NULL;
	}
	return doc;
}

ncfg_json_doc_t *ncfg_client_hello(ncfg_client_t *client, char *err, size_t err_size)
{
	return ncfg_client_request(client, "{\"request\":\"hello\"}", err, err_size);
}

ncfg_json_doc_t *ncfg_client_status(ncfg_client_t *client, char *err, size_t err_size)
{
	return ncfg_client_request(client, "{\"request\":\"status\"}", err, err_size);
}

ncfg_json_doc_t *ncfg_client_plan(ncfg_client_t *client, char *err, size_t err_size)
{
	return ncfg_client_request(client, "{\"request\":\"plan\"}", err, err_size);
}

const char *ncfg_client_error_message(const ncfg_json_doc_t *doc, size_t *length_out)
{
	uint32_t root = ncfg_json_root(doc);

	if (length_out) {
		*length_out = 0;
	}
	if (!ncfg_json_string_equals(doc, ncfg_json_member(doc, root, "response"), "error")) {
		return NULL;
	}
	return ncfg_json_string(doc, ncfg_json_member(doc, root, "message"), length_out);
}

size_t ncfg_client_quote(const char *text, char *out, size_t out_size)
{
	if (!text || !out || out_size < 3u) {
		return 0;
	}
	size_t at = 0;
	out[at++] = '"';

	for (const unsigned char *p = (const unsigned char *)text; *p; p++) {
		char escape[7];
		size_t span;

		switch (*p) {
		case '"':  memcpy(escape, "\\\"", 2); span = 2; break;
		case '\\': memcpy(escape, "\\\\", 2); span = 2; break;
		case '\b': memcpy(escape, "\\b", 2);  span = 2; break;
		case '\f': memcpy(escape, "\\f", 2);  span = 2; break;
		case '\n': memcpy(escape, "\\n", 2);  span = 2; break;
		case '\r': memcpy(escape, "\\r", 2);  span = 2; break;
		case '\t': memcpy(escape, "\\t", 2);  span = 2; break;
		default:
			if (*p < 0x20u) {
				/* The remaining control characters, which JSON
				 * has no short escape for. */
				span = (size_t)snprintf(escape, sizeof(escape), "\\u%04x", *p);
			} else {
				escape[0] = (char)*p;
				span = 1;
			}
			break;
		}
		if (at + span + 2u > out_size) {
			return 0;
		}
		memcpy(out + at, escape, span);
		at += span;
	}
	out[at++] = '"';
	out[at] = '\0';
	return at;
}
