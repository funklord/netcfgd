/*
 * message.c -- one line in, one decoded message out, and what it owns.
 */
#include "internal.h"

#include <stdlib.h>
#include <string.h>

/*
 * Which of the three tags a line carries.
 *
 * Three rather than two, and the third surprised the C client on its first
 * run: an event payload appears both on its own and wrapped in
 * `{"response":"event",...}`, because a monitor stream carries it inside the
 * wrapper and the payload is its own pinned shape. A client that knew only
 * requests and responses would read a stream and recognise nothing.
 */
static int tag_of(const ncfg_json_doc_t *doc, uint32_t root, ncfg_proto_message_kind_t *out)
{
	if (ncfg_json_member(doc, root, "request") != NCFG_JSON_NONE) {
		*out = NCFG_PROTO_MESSAGE_REQUEST;
		return 1;
	}
	if (ncfg_json_member(doc, root, "response") != NCFG_JSON_NONE) {
		*out = NCFG_PROTO_MESSAGE_RESPONSE;
		return 1;
	}
	if (ncfg_json_member(doc, root, "event") != NCFG_JSON_NONE) {
		*out = NCFG_PROTO_MESSAGE_EVENT;
		return 1;
	}
	return 0;
}

/*
 * `accept` is a bitmask of the kinds this caller will take, which is the
 * direction expressed once rather than a flag checked in three places.
 */
#define ACCEPT_REQUEST  1u
#define ACCEPT_RESPONSE 2u
#define ACCEPT_EVENT    4u

static int read_line(const char *line, size_t length, unsigned accept, ncfg_proto_message_t *out,
    char *err, size_t err_size)
{
	ncfg_proto_dec_t dec;
	uint32_t root;
	ncfg_proto_message_kind_t kind;
	int ok;

	if (!out) {
		ncfg_error_set(err, err_size, "nowhere to put the decoded message");
		return 0;
	}
	memset(out, 0, sizeof(*out));
	if (!line) {
		ncfg_error_set(err, err_size, "no line to decode");
		return 0;
	}
	out->doc = ncfg_json_parse(line, length, err, err_size);
	if (!out->doc) {
		/* The reader's own sentence, with the byte offset: a line that will
		 * not parse is a bug in one of two programs, and the offset is what
		 * says which. */
		return 0;
	}
	root = ncfg_json_root(out->doc);
	if (ncfg_json_type(out->doc, root) != NCFG_JSON_OBJECT) {
		ncfg_error_set(err, err_size, "a message is a JSON object and this is not one");
		ncfg_proto_message_free(out);
		return 0;
	}
	if (!tag_of(out->doc, root, &kind)) {
		ncfg_error_set(err, err_size,
		    "a message carries a `request`, a `response` or an `event` and this carries none");
		ncfg_proto_message_free(out);
		return 0;
	}
	if (!((1u << (unsigned)kind) & accept)) {
		static const char *const what[] = { "request", "response", "event" };

		ncfg_error_set(err, err_size, "a %s arrived where one was not expected",
		    what[kind]);
		ncfg_proto_message_free(out);
		return 0;
	}
	out->kind = kind;

	dec.message = out;
	dec.doc = out->doc;
	dec.err = err;
	dec.err_size = err_size;
	/* The asymmetry, set once: strict on what a daemon accepts, tolerant on
	 * what a client accepts. See proto.h for why it is between the two
	 * directions rather than between an envelope and a payload. */
	dec.strict = (kind == NCFG_PROTO_MESSAGE_REQUEST);

	switch (kind) {
	case NCFG_PROTO_MESSAGE_REQUEST:
		ok = ncfg_proto_decode_request(&dec, root, &out->u.request);
		break;
	case NCFG_PROTO_MESSAGE_RESPONSE:
		ok = ncfg_proto_decode_response(&dec, root, &out->u.response);
		break;
	case NCFG_PROTO_MESSAGE_EVENT:
	default:
		ok = ncfg_proto_decode_event(&dec, root, &out->u.event);
		break;
	}
	if (!ok) {
		/* Half a decoded message is the one that gets acted on by
		 * accident, so a refusal hands back nothing rather than the part
		 * that was understood -- `ncfg_buf_t`'s rule, one layer up. */
		ncfg_proto_message_free(out);
		return 0;
	}
	return 1;
}

int ncfg_proto_request_read(const char *line, size_t length, ncfg_proto_message_t *out,
    char *err, size_t err_size)
{
	return read_line(line, length, ACCEPT_REQUEST, out, err, err_size);
}

int ncfg_proto_response_read(const char *line, size_t length, ncfg_proto_message_t *out,
    char *err, size_t err_size)
{
	return read_line(line, length, ACCEPT_RESPONSE | ACCEPT_EVENT, out, err, err_size);
}

int ncfg_proto_message_read(const char *line, size_t length, ncfg_proto_message_t *out,
    char *err, size_t err_size)
{
	return read_line(line, length, ACCEPT_REQUEST | ACCEPT_RESPONSE | ACCEPT_EVENT, out,
	    err, err_size);
}

const ncfg_json_doc_t *ncfg_proto_message_doc(const ncfg_proto_message_t *message)
{
	return message ? message->doc : NULL;
}

void ncfg_proto_message_free(ncfg_proto_message_t *message)
{
	size_t at;

	if (!message) {
		return;
	}
	/* Freeing something that was never filled in is nothing: a message a
	 * caller declared and never decoded into is all zeroes, and every line
	 * below is a no-op on it (0263's third convention). */
	for (at = 0; at < message->block_count; at++) {
		free(message->blocks[at]);
	}
	free(message->blocks);
	ncfg_json_free(message->doc);
	memset(message, 0, sizeof(*message));
}
