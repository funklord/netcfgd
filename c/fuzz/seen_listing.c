/*
 * A page of fuzznet's `list record` reply, which is what any host of the
 * estate can put into this machine's store (project.md 10.674, 10.681).
 *
 * WHY THIS DESERVES A TARGET OF ITS OWN
 *   A record is a setting its own host signs about itself, and a station
 *   one host recorded reaches every other through the estate's rounds. So the
 *   listing `ncfg_seen_parse_listing` reads is text another machine chose,
 *   escaped by fuzznet and put back into one line, and what it returns ends
 *   up in an access point's allow list as a MAC hostapd is handed. No other
 *   target reaches it: it reads a socket reply, not a document or a file.
 *
 * THE INVARIANTS WORTH ASSERTING
 *   What the header promises: -1 or a count it read; never more stations than
 *   `room`; the list sorted and unique; and every station a MAC in the shape
 *   the kernel spells one, `xx:xx:xx:xx:xx:xx`, lowercase hex -- anything
 *   else would be text from another host written into hostapd's file.
 */
#include "fuzz.h"

#include "ncfg/seen.h"

#include <stdlib.h>
#include <string.h>

#define ROOM 8u

static int is_mac(const char *mac)
{
	size_t at;

	if (strlen(mac) != 17u) {
		return 0;
	}
	for (at = 0; at < 17u; at++) {
		const char c = mac[at];

		if (at % 3u == 2u) {
			if (c != ':') {
				return 0;
			}
		} else if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
			return 0;
		}
	}
	return 1;
}

int ncfg_fuzz_one(const unsigned char *data, size_t length)
{
	char  *list[ROOM];
	size_t count = 0;
	size_t at;
	int    more = 0;
	long   shown;
	char  *text = ncfg_fuzz_text(data, length);

	if (!text) {
		return 0;
	}
	shown = ncfg_seen_parse_listing(text, list, &count, ROOM, &more);
	if (shown < -1) {
		abort(); /* an answer the header does not have */
	}
	if (count > ROOM) {
		abort(); /* more stations than there was room for */
	}
	for (at = 0; at < count; at++) {
		if (!list[at] || !is_mac(list[at])) {
			abort(); /* a station that is not a MAC as the kernel spells one */
		}
		if (at > 0u && strcmp(list[at - 1u], list[at]) >= 0) {
			abort(); /* not sorted, or not unique */
		}
	}
	for (at = 0; at < count; at++) {
		free(list[at]);
	}
	free(text);
	return 0;
}
