/*
 * pair_draw_test.c -- the code `ncfg pair` draws is the code it was given.
 *
 * A code read off a terminal is the whole of a phone's pairing, and two rows to a
 * character is where a row goes missing. So the drawing is read back to modules,
 * for an odd side, where the last line holds one row, and the quiet zone and the
 * colours are held: a code with neither does not scan on a dark terminal.
 */
#include "ncfg/cli.h"
#include "ncfg/node.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failed;

static void check(int ok, const char *what)
{
	printf("%-64s %s\n", what, ok ? "ok" : "FAILED");
	failed |= !ok;
}

int main(void)
{
	static uint8_t modules[32768];
	static char    drawn[1 << 20];
	size_t         size = 0;
	char           card[704];
	FILE          *out;
	size_t         length;
	size_t         row = 0;
	size_t         mismatched = 0;
	size_t         side;
	size_t         lines = 0;

	memset(card, 'A', sizeof(card) - 1u);
	card[sizeof(card) - 1u] = '\0';
	memcpy(card, "FZN4:", 5);
	check(ncfg_node_qr(card, modules, sizeof(modules), &size) && size % 2u == 1u,
	    "a card's length makes a code of an odd side");
	out = fmemopen(drawn, sizeof(drawn), "w");
	ncfg_cli_pair_draw(out, modules, size);
	fclose(out);
	length = strlen(drawn);
	side = size + 8u;
	check(strncmp(drawn, "\033[30;47m", 8) == 0, "it says its colours, black on white");
	for (const char *line = drawn; line < drawn + length; row += 2u) {
		const char *at = line + 8;
		size_t      x = 0;

		while (*at != '\033' && *at) {
			int top = 0;
			int bottom = 0;

			if (*at == ' ') {
				at++;
			} else {
				top = at[2] == '\x88' || at[2] == '\x80';
				bottom = at[2] == '\x88' || at[2] == '\x84';
				at += 3;
			}
			for (int half = 0; half < 2; half++) {
				size_t y = row + (size_t)half;
				int    want = 0;

				if (x >= 4u && y >= 4u && x < size + 4u && y < size + 4u) {
					want = modules[(y - 4u) * size + (x - 4u)];
				}
				mismatched += (half ? bottom : top) != want && y < side;
			}
			x++;
		}
		mismatched += x != side;
		line = strchr(at, '\n');
		if (!line) {
			break;
		}
		line++;
	}
	for (const char *at = drawn; (at = strchr(at, '\n')) != NULL; at++) {
		lines++;
	}
	check(lines == (side + 1u) / 2u, "every row of modules is drawn");
	check(mismatched == 0u, "and read back, every module is the one given");
	return failed;
}
