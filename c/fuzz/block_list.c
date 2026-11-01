/*
 * A line of a published block list, which is a file downloaded from somebody
 * this machine does not trust (0305, 10.640).
 *
 * WHY THIS DESERVES A TARGET OF ITS OWN
 *   `ncfg block fetch` puts whatever a list's server sends into the file, and
 *   `ncfg_block_list_name_of_line` is the one thing standing between those
 *   bytes and dnsmasq's configuration: every name it returns becomes an
 *   `address=/name/` line. A name carrying a `/` ends the domain and starts a
 *   target; a newline starts a directive of the author's choosing. No other
 *   target reaches it, because it reads a list's lines and not the document.
 *
 * THE INVARIANTS WORTH ASSERTING
 *   A name it returns is what the header promises: inside the buffer, and one
 *   `ncfg_block_list_name` accepts -- lowercase, and free of anything dnsmasq
 *   would read as more than a name. And it is a fixed point: the name, given
 *   back as a bare line, comes back unchanged, so a list rewritten from its
 *   own output says the same thing.
 */
#include "fuzz.h"

#include "ncfg/document.h"

#include <stdlib.h>
#include <string.h>

int ncfg_fuzz_one(const unsigned char *data, size_t length)
{
	char  name[256];
	char  again[256];
	char *text = ncfg_fuzz_text(data, length);

	if (!text) {
		return 0;
	}
	memset(name, 'x', sizeof(name));
	if (ncfg_block_list_name_of_line(text, length, name, sizeof(name))) {
		size_t at;

		if (memchr(name, '\0', sizeof(name)) == NULL) {
			abort(); /* a name was returned without its end */
		}
		if (!ncfg_block_list_name(name)) {
			abort(); /* a name the header says it would refuse */
		}
		for (at = 0; name[at] != '\0'; at++) {
			if (name[at] >= 'A' && name[at] <= 'Z') {
				abort(); /* not lowercased */
			}
		}
		if (!ncfg_block_list_name_of_line(name, strlen(name), again, sizeof(again)) ||
		    strcmp(name, again) != 0) {
			abort(); /* not a fixed point */
		}
	}
	free(text);
	return 0;
}
