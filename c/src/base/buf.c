/*
 * buf.c -- the buffer described in buf.h.
 */
#include "ncfg/buf.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * The ceiling a buffer gets when the caller states none.
 *
 * Sixteen megabytes: larger than any configuration this compiles -- the
 * example file with every block uncommented is under a hundred kilobytes --
 * and small enough that a loop appending for ever is an error rather than a
 * machine that stops answering. A caller with a real bound passes it.
 */
#define DEFAULT_LIMIT (16u * 1024u * 1024u)

/* The first allocation. Small enough that a buffer holding one line does not
 * cost a page, large enough that the ordinary case never grows twice. */
#define FIRST_CAPACITY 256u

void ncfg_buf_init(ncfg_buf_t *buf, size_t limit)
{
	if (!buf) {
		return;
	}
	buf->data = NULL;
	buf->length = 0;
	buf->capacity = 0;
	buf->limit = limit ? limit : DEFAULT_LIMIT;
	buf->failed = 0;
}

void ncfg_buf_free(ncfg_buf_t *buf)
{
	if (!buf) {
		return;
	}
	free(buf->data);
	buf->data = NULL;
	buf->length = 0;
	buf->capacity = 0;
	buf->failed = 0;
}

/*
 * Make room for `wanted` more bytes plus the terminator.
 *
 * Doubling, because appending a byte at a time is what a renderer does and
 * growing by a constant would make that quadratic. The limit is tested
 * against the *result*, so a single huge append is refused as loudly as a
 * thousand small ones.
 */
static int reserve(ncfg_buf_t *buf, size_t wanted)
{
	size_t needed;
	size_t capacity;
	char *grown;

	if (buf->failed) {
		return 0;
	}
	/* The terminator is not part of `length` and is always there, which is
	 * what lets `ncfg_buf_text` hand out a C string without a copy. */
	if (wanted > buf->limit - buf->length) {
		buf->failed = 1;
		return 0;
	}
	needed = buf->length + wanted + 1u;
	if (needed <= buf->capacity) {
		return 1;
	}
	capacity = buf->capacity ? buf->capacity : FIRST_CAPACITY;
	while (capacity < needed) {
		/* Cannot overflow: `needed` is bounded by the limit plus one, and
		 * the limit is a `size_t` the caller chose. */
		capacity *= 2u;
	}
	grown = realloc(buf->data, capacity);
	if (!grown) {
		buf->failed = 1;
		return 0;
	}
	buf->data = grown;
	buf->capacity = capacity;
	return 1;
}

void ncfg_buf_add(ncfg_buf_t *buf, const void *bytes, size_t length)
{
	if (!buf || !bytes || !length) {
		return;
	}
	if (!reserve(buf, length)) {
		return;
	}
	memcpy(buf->data + buf->length, bytes, length);
	buf->length += length;
	buf->data[buf->length] = '\0';
}

void ncfg_buf_add_text(ncfg_buf_t *buf, const char *text)
{
	if (!text) {
		return;
	}
	ncfg_buf_add(buf, text, strlen(text));
}

void ncfg_buf_add_char(ncfg_buf_t *buf, char one)
{
	ncfg_buf_add(buf, &one, 1u);
}

void ncfg_buf_addf(ncfg_buf_t *buf, const char *format, ...)
{
	va_list args;
	va_list again;
	int wanted;

	if (!buf || !format || buf->failed) {
		return;
	}
	va_start(args, format);
	va_copy(again, args);
	/* Asked how much room it needs before writing anything, which is the
	 * only way to append a formatted string without either a fixed scratch
	 * buffer or a silent truncation. Both were considered and both are how
	 * a rendered block loses its tail. */
	wanted = vsnprintf(NULL, 0, format, args);
	va_end(args);
	if (wanted < 0) {
		buf->failed = 1;
		va_end(again);
		return;
	}
	if (reserve(buf, (size_t)wanted)) {
		(void)vsnprintf(buf->data + buf->length, (size_t)wanted + 1u, format, again);
		buf->length += (size_t)wanted;
	}
	va_end(again);
}

int ncfg_buf_failed(const ncfg_buf_t *buf)
{
	return !buf || buf->failed;
}

const char *ncfg_buf_text(const ncfg_buf_t *buf)
{
	if (!buf || buf->failed || !buf->data) {
		return "";
	}
	return buf->data;
}

char *ncfg_buf_take(ncfg_buf_t *buf, size_t *length_out)
{
	char *taken;

	if (length_out) {
		*length_out = 0;
	}
	if (!buf || buf->failed || !buf->data) {
		return NULL;
	}
	taken = buf->data;
	if (length_out) {
		*length_out = buf->length;
	}
	buf->data = NULL;
	buf->length = 0;
	buf->capacity = 0;
	return taken;
}
