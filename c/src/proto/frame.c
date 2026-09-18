/*
 * frame.c -- one JSON object per line, in both directions.
 *
 * The interesting part is not the encoding, it is the bound. A control socket
 * is reachable by anything that can open it, so a client that sends a
 * gigabyte without a newline must be refused rather than absorbed -- the
 * daemon holds `CAP_NET_ADMIN` and being killed by the OOM killer is a denial
 * of service with extra steps.
 */
#include "ncfg/proto.h"

#include <string.h>

/*
 * Room for a pipelining peer, which is why the framer's own ceiling is not
 * `NCFG_PROTO_MAX_LINE`.
 *
 * A daemon that answered two requests quickly may put both in one read, and a
 * `read` that lands one whole line plus the head of the next is ordinary. The
 * *line* bound is enforced separately and exactly, below; this is only the
 * point past which the framer stops holding bytes at all, and it is where it
 * is so that the exact bound is the one that produces the refusal a caller
 * sees.
 */
#define PENDING_LIMIT (NCFG_PROTO_MAX_LINE * 2u)

void ncfg_proto_framer_init(ncfg_proto_framer_t *framer)
{
	if (!framer) {
		return;
	}
	ncfg_buf_init(&framer->pending, PENDING_LIMIT);
	framer->handed = 0;
	framer->broken = 0;
}

void ncfg_proto_framer_free(ncfg_proto_framer_t *framer)
{
	if (!framer) {
		return;
	}
	ncfg_buf_free(&framer->pending);
	framer->handed = 0;
	framer->broken = 0;
}

/*
 * Drop the line handed out last time, now that the caller has had its turn.
 *
 * Deferred rather than done when the line was returned, because the line
 * *is* the front of this buffer: consuming it there would memmove the tail
 * over the bytes just handed back, and the decoder points straight into them.
 * So the contract is the narrow one -- a line is valid until the next call on
 * this framer -- and this is where it is collected.
 */
static void drop_handed(ncfg_proto_framer_t *framer)
{
	if (!framer->handed) {
		return;
	}
	framer->pending.length -= framer->handed;
	memmove(framer->pending.data, framer->pending.data + framer->handed,
	    framer->pending.length);
	framer->pending.data[framer->pending.length] = '\0';
	framer->handed = 0;
}

/* The bytes not yet framed, after whatever was handed out has been dropped. */
static const char *pending_bytes(const ncfg_proto_framer_t *framer, size_t *length_out)
{
	*length_out = framer->pending.length;
	return framer->pending.data;
}

int ncfg_proto_framer_add(ncfg_proto_framer_t *framer, const void *bytes, size_t length,
    char *err, size_t err_size)
{
	const char *held;
	size_t held_length;

	if (!framer) {
		ncfg_error_set(err, err_size, "no framer to read into");
		return 0;
	}
	if (framer->broken) {
		ncfg_error_set(err, err_size,
		    "this connection stopped being the protocol and cannot be read on");
		return 0;
	}
	if (length && !bytes) {
		ncfg_error_set(err, err_size, "bytes to frame that are not there");
		framer->broken = 1;
		return 0;
	}
	drop_handed(framer);
	ncfg_buf_add(&framer->pending, bytes, length);
	if (ncfg_buf_failed(&framer->pending)) {
		framer->broken = 1;
		ncfg_error_set(err, err_size, "more than %u bytes are waiting to be framed",
		    (unsigned)PENDING_LIMIT);
		return 0;
	}

	/*
	 * The bound, checked as the bytes arrive rather than when a line is
	 * taken. A peer that never sends a newline is the case this exists for,
	 * and a caller that reads until it has a line would never reach the
	 * check if it lived there.
	 */
	held = pending_bytes(framer, &held_length);
	if (held_length >= NCFG_PROTO_MAX_LINE &&
	    !(held_length ? memchr(held, '\n', held_length) : NULL)) {
		framer->broken = 1;
		ncfg_error_set(err, err_size, "a message exceeded %u bytes without a newline",
		    (unsigned)NCFG_PROTO_MAX_LINE);
		return 0;
	}
	return 1;
}

ncfg_proto_line_result_t ncfg_proto_framer_next(ncfg_proto_framer_t *framer,
    const char **line_out, size_t *length_out, char *err, size_t err_size)
{
	const char *held;
	size_t held_length;
	const char *newline;
	size_t line_length;

	if (line_out) {
		*line_out = NULL;
	}
	if (length_out) {
		*length_out = 0;
	}
	if (!framer) {
		ncfg_error_set(err, err_size, "no framer to read from");
		return NCFG_PROTO_LINE_FAILED;
	}
	if (framer->broken) {
		ncfg_error_set(err, err_size,
		    "this connection stopped being the protocol and cannot be read on");
		return NCFG_PROTO_LINE_FAILED;
	}
	drop_handed(framer);
	held = pending_bytes(framer, &held_length);
	/* Guarded on the length rather than trusting memchr with a null pointer
	 * and zero bytes: that is undefined behaviour even though every
	 * implementation returns NULL, and UBSan says so on the first read of
	 * every fresh connection -- which is how the client found it, in the
	 * first headless run of the GUI against a real daemon. */
	newline = held_length ? memchr(held, '\n', held_length) : NULL;
	if (!newline) {
		return NCFG_PROTO_LINE_INCOMPLETE;
	}
	line_length = (size_t)(newline - held);
	/*
	 * `MAX_LINE` counts the newline, which is the Rust's arithmetic to the
	 * byte: it reads at most that many bytes and refuses what does not end
	 * in one. A line of exactly the bound including its terminator is
	 * accepted and a content byte more is not. The boundary is the part a
	 * copied number gets wrong, so it is tested rather than described.
	 */
	if (line_length + 1u > NCFG_PROTO_MAX_LINE) {
		framer->broken = 1;
		ncfg_error_set(err, err_size, "a message of %u bytes is past the %u byte line",
		    (unsigned)(line_length + 1u), (unsigned)NCFG_PROTO_MAX_LINE);
		return NCFG_PROTO_LINE_FAILED;
	}
	if (line_out) {
		*line_out = held;
	}
	if (length_out) {
		*length_out = line_length;
	}
	/*
	 * The line stays where it is until the next call, so the caller can
	 * decode out of it without a copy. Consuming it here instead would move
	 * the tail over the bytes being returned -- and the whole decoder points
	 * into them.
	 */
	framer->handed = line_length + 1u;
	return NCFG_PROTO_LINE;
}

int ncfg_proto_framer_finish(ncfg_proto_framer_t *framer, char *err, size_t err_size)
{
	if (!framer) {
		ncfg_error_set(err, err_size, "no framer to finish");
		return 0;
	}
	if (framer->broken) {
		ncfg_error_set(err, err_size,
		    "this connection stopped being the protocol and cannot be read on");
		return 0;
	}
	drop_handed(framer);
	if (framer->pending.length) {
		/*
		 * A message that was cut in half. Refusing rather than parsing
		 * what arrived is the point: half a request read as a whole one
		 * is a request nobody sent, and this surface reaches a process
		 * holding `CAP_NET_ADMIN`.
		 */
		framer->broken = 1;
		ncfg_error_set(err, err_size,
		    "the connection ended in the middle of a message, %u bytes in",
		    (unsigned)framer->pending.length);
		return 0;
	}
	/* Nothing pending is an ordinary disconnect, and is not an error
	 * (section 10, item 4). */
	return 1;
}

int ncfg_proto_line_finish(ncfg_buf_t *line, char *err, size_t err_size)
{
	size_t at;

	if (!line) {
		ncfg_error_set(err, err_size, "no line to terminate");
		return 0;
	}
	if (ncfg_buf_failed(line)) {
		ncfg_error_set(err, err_size, "the message did not fit the buffer it was built in");
		return 0;
	}
	/*
	 * A message containing a newline would frame as two, and the peer would
	 * mis-parse both halves. The JSON writer escapes newlines inside strings,
	 * so on an encoded request this can only fire on a bug here -- which is
	 * exactly why it is checked: the client library checks it, the daemon's
	 * codec checks it, and the one that does not is the one that ships the
	 * split message.
	 */
	for (at = 0; at < line->length; at++) {
		if (line->data[at] == '\n') {
			ncfg_error_set(err, err_size,
			    "a message may not contain a newline, and this one does at byte %u",
			    (unsigned)at);
			return 0;
		}
	}
	if (line->length + 1u > NCFG_PROTO_MAX_LINE) {
		ncfg_error_set(err, err_size, "a message of %u bytes is past the %u byte line",
		    (unsigned)(line->length + 1u), (unsigned)NCFG_PROTO_MAX_LINE);
		return 0;
	}
	ncfg_buf_add_char(line, '\n');
	if (ncfg_buf_failed(line)) {
		ncfg_error_set(err, err_size, "the message did not fit the buffer it was built in");
		return 0;
	}
	return 1;
}
