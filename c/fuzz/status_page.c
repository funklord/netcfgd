/*
 * A status page, as another host's bytes (project.md 10.689, 10.701).
 *
 * WHY THIS DESERVES A TARGET OF ITS OWN
 *   `ncfg_status_page_read` reads what a node of the estate answered -- or
 *   whatever answered in its place -- and `ncfg_status_pages_join` gathers
 *   pages into the JSON `ncfg` and the GUI parse. A count it trusted would be
 *   a copy past a buffer, and a gathering that never ended would be a client
 *   that hangs on one hostile host.
 *
 * THE INVARIANTS WORTH ASSERTING
 *   A page read is inside its bytes: FROM at most TOTAL, COUNT at most what
 *   is left, and the bytes exactly the COUNT after the header. And joining
 *   pages cut from the input ends, by its own bounds, with a whole that its
 *   digest names or with a refusal.
 */
#include "fuzz.h"

#include "ncfg_fuzznet.h"

#include <stdlib.h>
#include <string.h>

typedef struct {
	const unsigned char *data;
	size_t               length;
	size_t               asks;
} source_t;

/* Each page is the input again: a host that answers the same bytes to every
 * offset, which is the shape of most hostile answers. */
static int ask(void *context, size_t from, char *page, size_t cap, size_t *length, char *err,
    size_t err_size)
{
	source_t *source = context;

	(void)from;
	(void)err;
	(void)err_size;
	if (++source->asks > 100000u) {
		abort(); /* a join that does not end */
	}
	*length = source->length < cap ? source->length : cap;
	memcpy(page, source->data, *length);
	return 1;
}

int ncfg_fuzz_one(const unsigned char *data, size_t length)
{
	ncfg_status_page_t page;
	source_t           source = { data, length, 0 };
	char              *whole = NULL;
	size_t             whole_length = 0;
	char               err[256];

	if (ncfg_status_page_read((const char *)data, length, &page)) {
		const char *end = (const char *)data + length;

		if (page.from > page.total || page.count > page.total - page.from ||
		    page.bytes < (const char *)data || page.bytes + page.count != end) {
			abort(); /* a page read outside its own bytes */
		}
	}
	if (ncfg_status_pages_join(ask, &source, &whole, &whole_length, err, sizeof(err))) {
		/* Joined only where the digest matched, so check that it did. */
		if (!whole || whole[whole_length] != '\0' ||
		    !ncfg_status_page_read((const char *)data, length, &page) ||
		    ncfg_status_page_digest(whole, whole_length) != page.digest) {
			abort(); /* a whole that its pages' digest does not name */
		}
	}
	free(whole);
	return 0;
}
