/*
 * upnp_test.c -- the ports miniupnpd has mapped, read from its lease file
 * (project.md 10.675): what `ncfg status` and the GUI show of the openings
 * no document wrote.
 *
 * The lines are miniupnpd's own shape, `PROTO:EXTPORT:INTADDR:INTPORT:
 * EXPIRY:DESCRIPTION`, as `tests/hull/upnp/` reads them from a real one.
 */
#include "ncfg/upnp.h"

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

static void read_from_the_file(void)
{
	ncfg_observed_mapping_t *mappings = NULL;
	size_t                   count = 7;

	check(ncfg_upnp_mappings_in_text("", &mappings, &count) && !mappings && count == 0,
	    "an empty lease file is a miniupnpd that has mapped nothing");

	check(ncfg_upnp_mappings_in_text(
	          "TCP:18080:192.168.1.20:8080:1793668448:game server\n"
	          "UDP:3074:192.168.1.21:3074:0:\n"
	          "not a mapping at all\n"
	          "TCP:0:192.168.1.22:80:0:no port\n"
	          "TCP:80:192.168.1.23:70000:0:too far\n"
	          "UDP:5353:192.168.1.24:5353",
	          &mappings, &count) &&
	        count == 3,
	    "three mappings of six lines: the rest are not that shape or not ports");
	if (count == 3) {
		check(strcmp(mappings[0].protocol, "TCP") == 0 && mappings[0].external_port == 18080 &&
		        strcmp(mappings[0].address, "192.168.1.20") == 0 &&
		        mappings[0].internal_port == 8080 && mappings[0].expires == 1793668448 &&
		        strcmp(mappings[0].description, "game server") == 0,
		    "  each with its ports, its host, its expiry and what the client called it");
		check(mappings[1].expires == 0 && mappings[1].description[0] == '\0',
		    "  one that never expires, with no description, is still a mapping");
		check(mappings[2].external_port == 5353 && mappings[2].expires == 0,
		    "  and so is a last line with no newline and no expiry");
	}
	ncfg_upnp_mappings_free(mappings, count);
}

int main(void)
{
	read_from_the_file();
	if (failures) {
		printf("\nupnp_test: %d check(s) FAILED\n", failures);
		return 1;
	}
	printf("\nupnp_test: all checks passed\n");
	return 0;
}
