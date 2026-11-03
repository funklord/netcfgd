/*
 * status_page.c -- the page described in status_page.h, read and joined.
 *
 * A page is somebody else's bytes -- another host's, through fuzznet -- so
 * it is read as hostile: digits only where numbers are, no number a `size_t`
 * cannot carry, COUNT exactly the bytes that follow, and a gathering that
 * makes no progress or outgrows its bound stops rather than looping.
 */
#include "ncfg/status_page.h"

#include "ncfg/base.h"

#include <string.h>

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

int ncfg_status_pages_join(ncfg_status_page_ask_fn ask, void *context, ncfg_buf_t *out,
    char *err, size_t err_size)
{
	static char page[8192];
	int         attempt;

	if (!ask || !out) {
		ncfg_error_set(err, err_size, "nothing to ask the status of");
		return 0;
	}
	for (attempt = 0; attempt < 4; attempt++) {
		ncfg_status_page_t first = { 0, 0, 0, 0, NULL };
		ncfg_status_page_t one;
		size_t             from = 0;
		size_t             length = 0;
		int                moved = 0;

		ncfg_buf_free(out);
		do {
			if (!ask(context, from, page, sizeof(page), &length, err, err_size)) {
				return 0;
			}
			if (!ncfg_status_page_read(page, length, &one)) {
				ncfg_error_set(err, err_size, "the answer is not a page of the status: %.80s",
				    length ? page : "(empty)");
				return 0;
			}
			if (from == 0) {
				first = one;
			}
			if (one.digest != first.digest || one.total != first.total) {
				moved = 1; /* another status: these pages are not one */
				break;
			}
			if (one.from != from || (one.count == 0u && from < one.total)) {
				ncfg_error_set(err, err_size,
				    "the status came back from %zu when %zu was asked, or without progress",
				    one.from, from);
				return 0;
			}
			ncfg_buf_add(out, one.bytes, one.count);
			from += one.count;
		} while (from < first.total);
		if (moved) {
			continue;
		}
		if (ncfg_buf_failed(out) || out->length != first.total) {
			ncfg_error_set(err, err_size, "the status did not fit in memory");
			return 0;
		}
		if (ncfg_status_page_digest(out->data, out->length) != first.digest) {
			ncfg_error_set(err, err_size,
			    "the pages joined are not the status their digest names");
			return 0;
		}
		return 1;
	}
	ncfg_error_set(err, err_size, "the status moved faster than it could be read whole");
	return 0;
}
