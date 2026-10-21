/* `ncfg_fuzz_text`, in its own file so every target and both drivers share
 * one copy. See `fuzz.h`. */
#include "fuzz.h"

#include <stdlib.h>
#include <string.h>

char *ncfg_fuzz_text(const unsigned char *data, size_t length)
{
	char *text = malloc(length + 1u);

	if (!text) {
		return NULL;
	}
	if (length) {
		memcpy(text, data, length);
	}
	text[length] = '\0';
	return text;
}
