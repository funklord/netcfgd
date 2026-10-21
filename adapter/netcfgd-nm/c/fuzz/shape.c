/*
 * Is this text a block the renderer could have written?
 *
 * WHY THIS EXISTS
 *   The renderer turns a client's dictionary into netcfgd configuration, and
 *   the daemon compiles whatever comes out. So the question that matters is
 *   not "did it crash" but **"is the file still one network block"** -- and a
 *   fuzzer checking only for crashes answers the first and misses the second
 *   entirely.
 *
 *   It missed it here. A client could name a setting key with a newline, the
 *   dropped-settings note wrote the name into a comment, the newline ended the
 *   comment, and everything after it was configuration the client chose: a
 *   whole `network` block of its own, in a file a privileged daemon reads.
 *   Nothing crashed, every assertion about labels and credentials held, and
 *   the fuzzer ran happily past it for millions of executions
 *   (project.md 10.509).
 *
 * WHY A LINE RULE RATHER THAN A PARSE
 *   The honest check would be to compile the text with the daemon's own
 *   compiler, which is in this tree -- and linking it here would put two
 *   archives that both define the JSON reader on one command line, which is
 *   the landmine `build-and-commit.md` names. The grammar this renderer may
 *   emit is also tiny, so a line rule is exact for it:
 *
 *     * a blank line;
 *     * a comment, which must START the line: `#` anywhere else is text that
 *       something put there;
 *     * a tab-indented line, which is a key inside the block;
 *     * the closing brace, alone;
 *     * exactly one header, `network "<label>" {`.
 *
 *   Anything else is structure the renderer did not choose, which is the
 *   definition of the defect.
 */
#include "shape.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void refuse(const char *why, const char *line, size_t length)
{
	fprintf(stderr, "shape: %s: [%.*s]\n", why, (int)length, line);
	abort();
}

void nmc_fuzz_check_shape(const char *text)
{
	const char *cursor = text;
	size_t      headers = 0u;

	while (*cursor != '\0') {
		const char *end = strchr(cursor, '\n');
		size_t      length = end ? (size_t)(end - cursor) : strlen(cursor);

		if (length == 0u || cursor[0] == '#' || cursor[0] == '\t') {
			/* blank, a comment, or a key inside the block */
		} else if (length == 1u && cursor[0] == '}') {
			/* the end of the block */
		} else if (strncmp(cursor, "network \"", 9u) == 0 &&
		    length >= 11u && cursor[length - 1u] == '{') {
			headers++;
		} else {
			refuse("a line the renderer could not have written", cursor, length);
		}
		if (!end) {
			break;
		}
		cursor = end + 1;
	}
	if (headers != 1u) {
		char count[64];

		(void)snprintf(count, sizeof(count), "%zu network blocks, not one", headers);
		refuse(count, text, strlen(text) > 60u ? 60u : strlen(text));
	}
}
