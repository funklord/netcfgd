/*
 * status_page_test.c -- a status page read, and pages joined
 * (`src/daemon/status_page.c`, project.md 10.689), against a fake source.
 *
 * WHAT HAS TO HOLD
 *   A page is read only in its exact shape; a steady status joins byte for
 *   byte; one that moves mid-gathering is gathered again and comes back as
 *   the newer whole, never a mixture -- **including a newer status of the
 *   same length**, which is the case a parse would not catch; one that never
 *   holds still is given up on; and a page whose digest does not name its
 *   bytes, or that makes no progress, is refused.
 */
#include "ncfg/status_page.h"

#include "ncfg/base.h"
#include "ncfg/buf.h"

#include <stdio.h>
#include <string.h>

static int failures;

static void check(int condition, const char *what)
{
	printf("%-72s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

typedef struct {
	char   a[1000];
	char   b[1000];
	size_t page;       /* bytes per page */
	size_t asks;
	size_t switch_at;  /* the source becomes `b` after this many asks; 0 never */
	int    every;      /* it alternates on every ask */
	int    lie;        /* every page names a digest of other bytes */
	int    stall;      /* every page carries nothing */
} source_t;

static int ask(void *context, size_t from, char *page, size_t cap, size_t *length, char *err,
    size_t err_size)
{
	source_t   *source = context;
	const char *status;
	size_t      count;
	int         wrote;

	(void)err;
	(void)err_size;
	source->asks++;
	status = source->every ? (source->asks % 2u ? source->a : source->b)
	         : source->switch_at && source->asks > source->switch_at ? source->b
	                                                                   : source->a;
	count = from >= sizeof(source->a) ? 0u : sizeof(source->a) - from;
	if (count > source->page) {
		count = source->page;
	}
	if (source->stall) {
		count = 0;
	}
	wrote = snprintf(page, cap, "ok %zu %zu %zu %016llx\n", sizeof(source->a), from, count,
	    (unsigned long long)(ncfg_status_page_digest(status, sizeof(source->a)) ^
	        (source->lie ? 1u : 0u)));
	memcpy(page + wrote, status + from, count);
	*length = (size_t)wrote + count;
	return 1;
}

static void reading(void)
{
	static const char *const bad[] = {
		"denied not permitted\n",
		"ok 10 0 3\nabc",                                   /* no digest */
		"ok 10 0 3 00000000000000AA\nabc",                  /* upper case */
		"ok 10 0 3 000000000000000a\nab",                   /* COUNT not the bytes */
		"ok 10 11 0 000000000000000a\n",                    /* FROM past TOTAL */
		"ok 10 8 3 000000000000000a\nabc",                  /* past TOTAL's end */
		"ok 99999999999999999999 0 0 000000000000000a\n",   /* a number nothing holds */
		"ok -1 0 0 000000000000000a\n",
		"ok 10  0 3 000000000000000a\nabc",
	};
	ncfg_status_page_t page;
	size_t             at;
	int                refused = 1;

	check(ncfg_status_page_read("ok 10 7 3 00000000000000ff\nabc", 30u, &page) &&
	        page.total == 10u && page.from == 7u && page.count == 3u && page.digest == 0xffu &&
	        memcmp(page.bytes, "abc", 3u) == 0,
	    "a page is read with its fields and its bytes");
	for (at = 0; at < sizeof(bad) / sizeof(bad[0]); at++) {
		if (ncfg_status_page_read(bad[at], strlen(bad[at]), &page)) {
			printf("  read, and should not have been: %s\n", bad[at]);
			refused = 0;
		}
	}
	check(refused, "  and nothing out of that shape is read as one");
}

int main(void)
{
	source_t   source;
	ncfg_buf_t out;
	char       err[NCFG_ERROR_MAX];
	size_t     at;
	int        ok;

	reading();
	memset(&source, 0, sizeof(source));
	for (at = 0; at < sizeof(source.a); at++) {
		source.a[at] = (char)('a' + at % 26u);
		source.b[at] = (char)('A' + at % 26u); /* the same length, other bytes */
	}
	source.page = 100;
	ncfg_buf_init(&out, 0);

	ok = ncfg_status_pages_join(ask, &source, &out, err, sizeof(err));
	check(ok && out.length == sizeof(source.a) && memcmp(out.data, source.a, out.length) == 0 &&
	        source.asks == 10u,
	    "a steady status joins byte for byte, in its ten pages");

	source.asks = 0;
	source.switch_at = 4;
	ok = ncfg_status_pages_join(ask, &source, &out, err, sizeof(err));
	check(ok && out.length == sizeof(source.b) && memcmp(out.data, source.b, out.length) == 0,
	    "one that moves mid-way, at the same length, comes back the newer whole");

	source.asks = 0;
	source.switch_at = 0;
	source.every = 1;
	ok = ncfg_status_pages_join(ask, &source, &out, err, sizeof(err));
	check(!ok && strstr(err, "moved") != NULL && source.asks <= 8u,
	    "one that never holds still is given up on, within four tries");

	source.asks = 0;
	source.every = 0;
	source.lie = 1;
	ok = ncfg_status_pages_join(ask, &source, &out, err, sizeof(err));
	check(!ok && strstr(err, "digest") != NULL,
	    "pages whose digest does not name their bytes are refused");

	source.lie = 0;
	source.stall = 1;
	ok = ncfg_status_pages_join(ask, &source, &out, err, sizeof(err));
	check(!ok && strstr(err, "progress") != NULL, "and so is a page that carries nothing");

	ncfg_buf_free(&out);
	if (failures) {
		printf("\nstatus_page_test: %d check(s) FAILED\n", failures);
		return 1;
	}
	printf("\nstatus_page_test: all checks passed\n");
	return 0;
}
