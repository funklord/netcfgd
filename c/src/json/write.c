/*
 * write.c -- the writer described in json_write.h.
 */
#include "ncfg/json_write.h"

#include <string.h>

static const char hex_digits[] = "0123456789abcdef";

/*
 * Record the first misuse, and fail the buffer with it.
 *
 * Reaching into `buf->failed` rather than appending something illegal is
 * deliberate: `ncfg_buf_t` has no call that says "you are ruined", and the
 * alternative is a caller reading a truncated document out of a buffer that
 * reports success. buf.h already refuses to hand out half a rendered block;
 * half a JSON message is the same hazard with a socket at the end of it.
 */
static void writer_fail(ncfg_json_writer_t *writer, const char *why)
{
	if (!writer->failure) {
		writer->failure = why;
	}
	if (writer->buf) {
		writer->buf->failed = 1;
	}
}

/*
 * Whether this writer can still be written to.
 *
 * The buffer's own failure is adopted here rather than only reported by
 * `ncfg_json_write_failed`, so that a document stopped by the ceiling names
 * the same thing however it is asked.
 */
static int usable(ncfg_json_writer_t *writer)
{
	if (!writer || writer->failure) {
		return 0;
	}
	if (ncfg_buf_failed(writer->buf)) {
		writer_fail(writer, "the buffer this document is written into failed");
		return 0;
	}
	return 1;
}

/*
 * Take the place a value is about to occupy, and write the separator it owes.
 *
 * Every value goes through here, which is what makes "a value where a member
 * name belongs" impossible to write rather than merely wrong when written.
 */
static int begin_value(ncfg_json_writer_t *writer)
{
	ncfg_json_write_frame_t *frame;

	if (!usable(writer)) {
		return 0;
	}
	frame = &writer->frames[writer->depth];
	if (writer->depth == 0) {
		if (frame->has_child) {
			writer_fail(writer, "a second value after the document's only one");
			return 0;
		}
	} else if (frame->is_object) {
		if (!frame->wants_value) {
			writer_fail(writer, "a value where a member name belongs");
			return 0;
		}
		/* The comma and the colon went in with the name. */
		frame->wants_value = 0;
	} else if (frame->has_child) {
		ncfg_buf_add_char(writer->buf, ',');
	}
	frame->has_child = 1;
	return 1;
}

/*
 * One UTF-8 sequence, or 0 for anything that is not one.
 *
 * Strict on purpose, and the strictness is the whole value of the function:
 * an overlong `\xc0\xaf` and a surrogate half `\xed\xa0\x80` both decode to
 * something a lenient decoder will accept, which is how one program's idea of
 * a name stops matching another's. The lead-byte ranges exclude the overlongs
 * by construction -- 0xc0 and 0xc1 cannot start anything -- and the two
 * explicit tests cover the three-byte and four-byte cases that ranges cannot.
 */
static size_t utf8_step(const unsigned char *at, size_t available)
{
	uint32_t code_point;
	size_t needed;
	size_t i;

	if (at[0] < 0x80u) {
		return 1u;
	}
	if (at[0] >= 0xc2u && at[0] <= 0xdfu) {
		needed = 2u;
		code_point = at[0] & 0x1fu;
	} else if (at[0] >= 0xe0u && at[0] <= 0xefu) {
		needed = 3u;
		code_point = at[0] & 0x0fu;
	} else if (at[0] >= 0xf0u && at[0] <= 0xf4u) {
		needed = 4u;
		code_point = at[0] & 0x07u;
	} else {
		return 0u;
	}
	if (available < needed) {
		return 0u;
	}
	for (i = 1u; i < needed; i++) {
		if ((at[i] & 0xc0u) != 0x80u) {
			return 0u;
		}
		code_point = (code_point << 6) | (at[i] & 0x3fu);
	}
	if (needed == 3u && (code_point < 0x800u ||
	    (code_point >= 0xd800u && code_point <= 0xdfffu))) {
		return 0u;
	}
	if (needed == 4u && (code_point < 0x10000u || code_point > 0x10ffffu)) {
		return 0u;
	}
	return needed;
}

/*
 * A quoted, escaped string.
 *
 * The short forms are used where RFC 8259 has one, because what this writes
 * is read by people as often as by programs -- a `config_put` body with every
 * newline spelled as a six-character escape is a diagnostic nobody can check
 * against the file it came from. Everything else below 0x20 becomes \u00XX,
 * which is the only way to carry it at all: the reader refuses a raw control
 * character, and the one that matters would have split the line in two before
 * it ever got there.
 */
static void write_quoted(ncfg_json_writer_t *writer, const char *bytes, size_t length)
{
	const unsigned char *at = (const unsigned char *)bytes;
	size_t i = 0;

	ncfg_buf_add_char(writer->buf, '"');
	while (i < length) {
		const char *shortform = NULL;
		unsigned char c = at[i];
		size_t step;

		switch (c) {
		case '"':  shortform = "\\\""; break;
		case '\\': shortform = "\\\\"; break;
		case '\b': shortform = "\\b";  break;
		case '\f': shortform = "\\f";  break;
		case '\n': shortform = "\\n";  break;
		case '\r': shortform = "\\r";  break;
		case '\t': shortform = "\\t";  break;
		default:   break;
		}
		if (shortform) {
			ncfg_buf_add_text(writer->buf, shortform);
			i++;
			continue;
		}
		if (c < 0x20u) {
			char escape[6];

			escape[0] = '\\';
			escape[1] = 'u';
			escape[2] = '0';
			escape[3] = '0';
			escape[4] = hex_digits[c >> 4];
			escape[5] = hex_digits[c & 0x0fu];
			ncfg_buf_add(writer->buf, escape, sizeof(escape));
			i++;
			continue;
		}
		step = utf8_step(at + i, length - i);
		if (!step) {
			/* See json_write.h: the three ways to carry this anyway all
			 * put a value in front of a user that nobody wrote. */
			writer_fail(writer, "a string that is not UTF-8");
			return;
		}
		ncfg_buf_add(writer->buf, at + i, step);
		i += step;
	}
	ncfg_buf_add_char(writer->buf, '"');
}

static void container_begin(ncfg_json_writer_t *writer, char open, int is_object)
{
	ncfg_json_write_frame_t *frame;

	if (!begin_value(writer)) {
		return;
	}
	if (writer->depth >= NCFG_JSON_MAX_DEPTH) {
		writer_fail(writer, "nesting deeper than the reader accepts");
		return;
	}
	ncfg_buf_add_char(writer->buf, open);
	writer->depth++;
	frame = &writer->frames[writer->depth];
	frame->is_object = (unsigned char)(is_object ? 1 : 0);
	frame->has_child = 0;
	frame->wants_value = 0;
}

static void container_end(ncfg_json_writer_t *writer, char close, int is_object)
{
	if (!usable(writer)) {
		return;
	}
	if (writer->depth == 0) {
		writer_fail(writer, is_object ? "an object closed with none open"
		                              : "an array closed with none open");
		return;
	}
	if ((writer->frames[writer->depth].is_object != 0) != (is_object != 0)) {
		writer_fail(writer, is_object ? "an object end closing an array"
		                              : "an array end closing an object");
		return;
	}
	if (writer->frames[writer->depth].wants_value) {
		writer_fail(writer, "an object closed after a member name with no value");
		return;
	}
	ncfg_buf_add_char(writer->buf, close);
	writer->depth--;
}

void ncfg_json_write_init(ncfg_json_writer_t *writer, ncfg_buf_t *buf)
{
	if (!writer) {
		return;
	}
	memset(writer, 0, sizeof(*writer));
	writer->buf = buf;
	if (!buf) {
		writer_fail(writer, "a writer with no buffer to write into");
	}
}

void ncfg_json_write_object_begin(ncfg_json_writer_t *writer)
{
	container_begin(writer, '{', 1);
}

void ncfg_json_write_object_end(ncfg_json_writer_t *writer)
{
	container_end(writer, '}', 1);
}

void ncfg_json_write_array_begin(ncfg_json_writer_t *writer)
{
	container_begin(writer, '[', 0);
}

void ncfg_json_write_array_end(ncfg_json_writer_t *writer)
{
	container_end(writer, ']', 0);
}

void ncfg_json_write_key(ncfg_json_writer_t *writer, const char *name)
{
	ncfg_json_write_frame_t *frame;

	if (!usable(writer)) {
		return;
	}
	if (writer->depth == 0 || !writer->frames[writer->depth].is_object) {
		writer_fail(writer, "a member name outside an object");
		return;
	}
	frame = &writer->frames[writer->depth];
	if (frame->wants_value) {
		writer_fail(writer, "a member name where its value belongs");
		return;
	}
	if (!name) {
		writer_fail(writer, "a member with no name");
		return;
	}
	if (frame->has_child) {
		ncfg_buf_add_char(writer->buf, ',');
	}
	write_quoted(writer, name, strlen(name));
	ncfg_buf_add_char(writer->buf, ':');
	frame->has_child = 1;
	frame->wants_value = 1;
}

void ncfg_json_write_string(ncfg_json_writer_t *writer, const char *text)
{
	if (!text) {
		if (usable(writer)) {
			writer_fail(writer, "a string that is a null pointer");
		}
		return;
	}
	ncfg_json_write_string_bytes(writer, text, strlen(text));
}

void ncfg_json_write_string_bytes(ncfg_json_writer_t *writer, const char *bytes, size_t length)
{
	if (!bytes) {
		/* Refused even for a length of 0, because the NULL a caller
		 * actually has in hand came from `ncfg_json_string` saying "that
		 * member is not a string" -- and re-emitting it as "" would turn
		 * a missing field into an empty one. */
		if (usable(writer)) {
			writer_fail(writer, "a string that is a null pointer");
		}
		return;
	}
	if (!begin_value(writer)) {
		return;
	}
	write_quoted(writer, bytes, length);
}

void ncfg_json_write_int(ncfg_json_writer_t *writer, int64_t value)
{
	if (!begin_value(writer)) {
		return;
	}
	ncfg_buf_addf(writer->buf, "%lld", (long long)value);
}

void ncfg_json_write_uint(ncfg_json_writer_t *writer, uint64_t value)
{
	if (!begin_value(writer)) {
		return;
	}
	ncfg_buf_addf(writer->buf, "%llu", (unsigned long long)value);
}

void ncfg_json_write_bool(ncfg_json_writer_t *writer, int value)
{
	if (!begin_value(writer)) {
		return;
	}
	ncfg_buf_add_text(writer->buf, value ? "true" : "false");
}

void ncfg_json_write_null(ncfg_json_writer_t *writer)
{
	if (!begin_value(writer)) {
		return;
	}
	ncfg_buf_add_text(writer->buf, "null");
}

void ncfg_json_write_member_string(ncfg_json_writer_t *writer, const char *name, const char *text)
{
	ncfg_json_write_key(writer, name);
	ncfg_json_write_string(writer, text);
}

void ncfg_json_write_member_int(ncfg_json_writer_t *writer, const char *name, int64_t value)
{
	ncfg_json_write_key(writer, name);
	ncfg_json_write_int(writer, value);
}

void ncfg_json_write_member_bool(ncfg_json_writer_t *writer, const char *name, int value)
{
	ncfg_json_write_key(writer, name);
	ncfg_json_write_bool(writer, value);
}

int ncfg_json_write_failed(const ncfg_json_writer_t *writer)
{
	return !writer || writer->failure != NULL || ncfg_buf_failed(writer->buf);
}

const char *ncfg_json_write_failure(const ncfg_json_writer_t *writer)
{
	return writer ? writer->failure : NULL;
}

int ncfg_json_write_done(const ncfg_json_writer_t *writer)
{
	if (ncfg_json_write_failed(writer)) {
		return 0;
	}
	return writer->depth == 0 && writer->frames[0].has_child;
}
