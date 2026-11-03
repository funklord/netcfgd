/*
 * status_page.h -- the daemon's status a page at a time, and the pages put
 * back together (project.md 10.685, 10.688, 10.689).
 *
 * THE PAGE
 *   `ok TOTAL FROM COUNT DIGEST`, a newline, and COUNT bytes of the status's
 *   JSON from offset FROM. Paged because fuzznet's replies have caps this side
 *   does not choose -- a remote answer's, and one local reply line once
 *   escaped -- and a busy router's status is tens of kilobytes.
 *
 * WHY A DIGEST
 *   Each page is cut from the status as it is when that page is asked, and a
 *   router's status moves between two asks. Joined blindly, pages of two
 *   statuses make JSON that fails to parse at best and, at the same length,
 *   one that parses as a status that never existed. DIGEST is FNV-1a over
 *   the whole status the page came from -- which status, not a protection:
 *   the transport is fuzznet's, authenticated already -- so pages that
 *   disagree are not joined, and the joined bytes are checked against it.
 */
#ifndef NCFG_STATUS_PAGE_H
#define NCFG_STATUS_PAGE_H

#include "ncfg/buf.h"

#include <stddef.h>
#include <stdint.h>

/* A whole status this large is refused rather than gathered. */
#define NCFG_STATUS_PAGE_TOTAL_MAX (64u * 1024u * 1024u)

typedef struct {
	size_t      total;
	size_t      from;
	size_t      count;
	uint64_t    digest;
	const char *bytes; /* the COUNT bytes, inside the page read */
} ncfg_status_page_t;

/* FNV-1a, 64 bits, of `length` bytes. */
uint64_t ncfg_status_page_digest(const char *bytes, size_t length);

/* `page`, `length` bytes, read as a page: 1 with its fields, 0 where it is
 * not one -- a refusal (`denied ...`), a header out of shape, or COUNT that
 * is not the bytes after it. */
int ncfg_status_page_read(const char *page, size_t length, ncfg_status_page_t *out);

/*
 * One page from `from`, its bytes into `page` (at most `cap`) and their
 * count into `*length`: 1, or 0 with a sentence where none came.
 */
typedef int (*ncfg_status_page_ask_fn)(void *context, size_t from, char *page, size_t cap,
    size_t *length, char *err, size_t err_size);

/*
 * Every page, asked through `ask`, joined into `out` (emptied first): 1 with
 * the whole status, whose digest matched every page's. A page of another
 * status starts the gathering again, at most four times, since a status that
 * moves faster than it can be read is not going to be read whole. 0 with a
 * sentence otherwise.
 */
int ncfg_status_pages_join(ncfg_status_page_ask_fn ask, void *context, ncfg_buf_t *out,
    char *err, size_t err_size);

#endif /* NCFG_STATUS_PAGE_H */
