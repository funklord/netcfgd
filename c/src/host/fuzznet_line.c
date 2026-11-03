/*
 * fuzznet_line.c -- the conversation and the escape described in
 * fuzznet_line.h, moved out of the seen recorder (10.688) so `ncfg` asks the
 * same way.
 */
#include "ncfg/fuzznet_line.h"

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

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
			(void)snprintf(why, why_size, "fuzznet at %s did not take the request", path);
			return 0;
		}
		n = send(fd, bytes + sent, length - sent, MSG_NOSIGNAL);
		if (n < 0 && errno != EAGAIN && errno != EINTR) {
			(void)snprintf(why, why_size, "fuzznet at %s: %s", path, strerror(errno));
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
		(void)snprintf(why, why_size, "no fuzznet socket path fits");
		return 0;
	}
	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	if (fd < 0) {
		(void)snprintf(why, why_size, "no socket: %s", strerror(errno));
		return 0;
	}
	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	memcpy(address.sun_path, path, strlen(path) + 1u);
	if (connect(fd, (const struct sockaddr *)&address, sizeof(address)) != 0 &&
	    errno != EINPROGRESS) {
		(void)snprintf(why, why_size, "fuzznet is not at %s: %s", path, strerror(errno));
		(void)close(fd);
		return 0;
	}
	length = strlen(line);
	if (!send_within(fd, path, line, length, wait_ms, why, why_size) ||
	    ((length == 0u || line[length - 1u] != '\n') &&
	        !send_within(fd, path, "\n", 1u, wait_ms, why, why_size))) {
		(void)close(fd);
		return 0;
	}
	if (!read_line(fd, wait_ms, buffer, sizeof(buffer), &have, reply, reply_size)) {
		(void)snprintf(why, why_size, "fuzznet at %s gave no answer that fits", path);
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
