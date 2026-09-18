/*
 * answer.c -- the three responses the authorization path writes for itself.
 *
 * `proto.h` decodes every response and encodes none: the encoder is the
 * daemon's half, and most of it belongs beside the requests that produce it --
 * a `status` encoder without a status to encode would be a shape nobody had
 * checked against anything. These three are different. `error` and `hello` are
 * answers this module itself decides, and `ok` is what a permitted request
 * that says nothing else comes back as, so they live with the code that
 * decides them.
 *
 * **A refusal is an answer.** `{"response":"error","message":"..."}` means the
 * daemon replied, which is a different thing from not reaching it, and the
 * sentence names the tier that would have been needed. A client replacing it
 * with wording of its own throws away the part that says what to do about it.
 */
#include "ncfg/daemon.h"

#include "ncfg/json_write.h"

#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/* Finish a writer into `out`, turning its own complaint into this module's
 * sentence. The buffer is failed rather than merely reported on, for
 * `request.c`'s reason: half a message is the one that gets sent by accident. */
static int finish(ncfg_json_writer_t *writer, ncfg_buf_t *out, const char *what, char *err,
    size_t err_size)
{
	if (!ncfg_json_write_done(writer)) {
		const char *why = ncfg_json_write_failure(writer);

		out->failed = 1;
		ncfg_error_set(err, err_size, "the %s response could not be written: %s", what,
		    why ? why : "it was left unfinished");
		return 0;
	}
	return 1;
}

int ncfg_daemon_error_encode(const char *message, ncfg_buf_t *out, char *err, size_t err_size)
{
	ncfg_json_writer_t writer;

	if (!out) {
		ncfg_error_set(err, err_size, "nowhere to put the refusal");
		return 0;
	}
	ncfg_json_write_init(&writer, out);
	ncfg_json_write_object_begin(&writer);
	ncfg_json_write_member_string(&writer, "response", "error");
	/* Never omitted, even for an empty sentence: a client reading `message`
	 * as absent would have no way to tell a refusal with nothing said from a
	 * response of another kind. */
	ncfg_json_write_member_string(&writer, "message", message ? message : "");
	ncfg_json_write_object_end(&writer);
	return finish(&writer, out, "error", err, err_size);
}

int ncfg_daemon_ok_encode(ncfg_buf_t *out, char *err, size_t err_size)
{
	ncfg_json_writer_t writer;

	if (!out) {
		ncfg_error_set(err, err_size, "nowhere to put the answer");
		return 0;
	}
	ncfg_json_write_init(&writer, out);
	ncfg_json_write_object_begin(&writer);
	ncfg_json_write_member_string(&writer, "response", "ok");
	ncfg_json_write_object_end(&writer);
	return finish(&writer, out, "ok", err, err_size);
}

static void write_version(ncfg_json_writer_t *writer, const char *name, int64_t major,
    int64_t minor)
{
	ncfg_json_write_key(writer, name);
	ncfg_json_write_object_begin(writer);
	ncfg_json_write_member_int(writer, "major", major);
	ncfg_json_write_member_int(writer, "minor", minor);
	ncfg_json_write_object_end(writer);
}

int ncfg_daemon_hello_encode(const ncfg_tier_t *tiers, size_t tier_count, ncfg_buf_t *out,
    char *err, size_t err_size)
{
	ncfg_json_writer_t writer;
	size_t             at;

	if (!out) {
		ncfg_error_set(err, err_size, "nowhere to put the greeting");
		return 0;
	}
	ncfg_json_write_init(&writer, out);
	ncfg_json_write_object_begin(&writer);
	ncfg_json_write_member_string(&writer, "response", "hello");
	write_version(&writer, "protocol", NCFG_DAEMON_PROTOCOL_MAJOR, NCFG_DAEMON_PROTOCOL_MINOR);
	write_version(&writer, "schema", NCFG_SCHEMA_MAJOR, NCFG_SCHEMA_MINOR);
	/*
	 * **Which tiers this connection satisfies** -- peer-specific, not
	 * machine-specific, and always written even when it is empty. A client is
	 * told what it may do rather than finding out by being refused (0092), and
	 * an omitted list would read as "could not tell", which section 10 item 10
	 * says to treat as permitted.
	 */
	ncfg_json_write_key(&writer, "tiers");
	ncfg_json_write_array_begin(&writer);
	for (at = 0; at < tier_count; at++) {
		const char *name = ncfg_tier_name(tiers[at]);

		if (name) {
			ncfg_json_write_string(&writer, name);
		}
	}
	ncfg_json_write_array_end(&writer);
	ncfg_json_write_object_end(&writer);
	return finish(&writer, out, "hello", err, err_size);
}

int ncfg_daemon_line_write(int socket, ncfg_buf_t *object, char *err, size_t err_size)
{
	const char *bytes;
	size_t      length;
	size_t      sent = 0;

	if (!object) {
		ncfg_error_set(err, err_size, "there is no line to write");
		return 0;
	}
	if (!ncfg_proto_line_finish(object, err, err_size)) {
		return 0;
	}
	if (ncfg_buf_failed(object)) {
		/* `ncfg_buf_text` hands out the empty string for a failed buffer, so
		 * a writer that trusted it would report success having sent nothing.
		 * That is the sticky failure being checked once, at the end, which is
		 * the whole point of it. */
		ncfg_error_set(err, err_size, "the answer was never fully built");
		return 0;
	}
	bytes = ncfg_buf_text(object);
	length = object->length;
	while (sent < length) {
		/*
		 * `send` with `MSG_NOSIGNAL` rather than `write`, because a client
		 * that hung up between the accept and the answer would otherwise
		 * raise `SIGPIPE` and **end the daemon**. That is not hypothetical
		 * for a control socket: `ncfg status | head` closes the pipe and then
		 * the socket the moment it has what it wants. A daemon holding
		 * `CAP_NET_ADMIN` must not be killable by a client disconnecting.
		 */
		ssize_t put = send(socket, bytes + sent, length - sent, MSG_NOSIGNAL);

		if (put < 0) {
			if (errno == EINTR) {
				continue;
			}
			/*
			 * A client that hung up mid-answer is ordinary. It is reported
			 * rather than swallowed because only the caller knows whether it
			 * matters, and the daemon's own loop treats it as "this
			 * connection is over" without logging.
			 */
			ncfg_error_set(err, err_size, "the answer could not be sent: %s",
			    strerror(errno));
			return 0;
		}
		sent += (size_t)put;
	}
	return 1;
}
