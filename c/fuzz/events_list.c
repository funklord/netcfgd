/*
 * Another node's events as `events` answers them, unescaped (project.md
 * 10.703, 10.705).
 *
 * WHY THIS DESERVES A TARGET OF ITS OWN
 *   `ncfg_fuzznet_events_read` reads text another host's node wrote, and what
 *   it keeps is printed -- by `ncfg monitor --at`, into `--json` as well --
 *   and listed in the GUI's and TUI's events. A subject it let through with a
 *   quote in it forges a line; a count it trusted is a copy past a slot.
 *
 * THE INVARIANTS WORTH ASSERTING
 *   Every subject kept is lower-case letters and hyphens, NUL-ended inside
 *   its slot, and there are no more of them than room; and a reply with more
 *   events than room says so the way a gap is said, FIRST at NEXT.
 */
#include "fuzz.h"

#include "ncfg_fuzznet.h"

#include <stdlib.h>
#include <string.h>

int ncfg_fuzz_one(const unsigned char *data, size_t length)
{
	char   subjects[3][NCFG_FUZZNET_SUBJECT_TEXT];
	char   err[256];
	size_t next = 0;
	size_t first = 0;
	size_t count = 0;
	size_t at;

	memset(subjects, 'x', sizeof(subjects));
	if (!ncfg_fuzznet_events_read((const char *)data, length, &next, &first, subjects, 3u,
	        &count, err, sizeof(err))) {
		return 0;
	}
	if (count > 3u) {
		abort(); /* more subjects than room */
	}
	for (at = 0; at < count; at++) {
		const char *end = memchr(subjects[at], '\0', NCFG_FUZZNET_SUBJECT_TEXT);
		const char *c;

		if (!end || end == subjects[at]) {
			abort(); /* a subject not ended inside its slot, or empty */
		}
		for (c = subjects[at]; c < end; c++) {
			if (!((*c >= 'a' && *c <= 'z') || *c == '-')) {
				abort(); /* a character that could forge a printed line */
			}
		}
	}
	return 0;
}
