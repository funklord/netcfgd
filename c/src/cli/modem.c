/*
 * modem.c -- `ncfg modem`: which SIM source each modem is on.
 *
 * READ-ONLY, AND DELIBERATELY
 *   Choosing a source is not a verb. 0152 makes the order the operator's and
 *   the choice netcfgd's, and a command that overrode the choice would be
 *   netcfgd's fallback being fought by hand. So this reports what the document
 *   lists and what netcfgd has selected from it, and offers nothing to change
 *   either.
 *
 * WHY `cycle_pending` IS THE COLUMN THIS WAS WRITTEN FOR
 *   It is the difference between a modem that has switched and one that is
 *   still waiting for its link to come back. Until this verb existed the flag
 *   was reachable only through the gui, so a fault that left it set had nothing
 *   that could see it from a script.
 */
#include "cli_internal.h"

#include "ncfg/log.h"

#include <string.h>

void ncfg_cli_print_modems(const ncfg_proto_modem_t *modems, size_t count)
{
	size_t at;

	if (count == 0) {
		ncfg_out_line("no device in the configuration has a `modem` block");
		return;
	}
	for (at = 0; at < count; at++) {
		const ncfg_proto_modem_t *modem = &modems[at];
		char        device[NCFG_CLI_TEXT_MAX];
		char        selected_text[NCFG_CLI_TEXT_MAX];
		const char *selected;
		const char *state;
		int         on_first_choice;
		size_t      one;

		/* "none listed" rather than an empty column: a device whose document
		 * names no source is a different machine from one netcfgd has not
		 * chosen for yet, and a blank would read as the second. */
		selected = ncfg_proto_str_present(modem->selected)
		    ? ncfg_cli_text(modem->selected, selected_text, sizeof(selected_text))
		    : "none listed";

		on_first_choice = modem->sim.count > 0 &&
		    ncfg_proto_str_present(modem->selected) &&
		    modem->sim.items[0].bytes != NULL &&
		    modem->sim.items[0].length == modem->selected.length &&
		    memcmp(modem->sim.items[0].bytes, modem->selected.bytes,
		    modem->selected.length) == 0;

		if (modem->cycle_pending) {
			state = "switching";
		} else if (modem->sim.count > 1 && !on_first_choice) {
			state = "fallen back";
		} else {
			state = "on its first choice";
		}
		ncfg_out_writef("%s  %s  %s\n",
		    ncfg_cli_text(modem->device, device, sizeof(device)), selected, state);

		if (modem->sim.count > 0) {
			ncfg_out_write("    sources: ");
			for (one = 0; one < modem->sim.count; one++) {
				char source[NCFG_CLI_TEXT_MAX];

				if (one > 0) {
					ncfg_out_write(", ");
				}
				ncfg_out_write(ncfg_cli_text(modem->sim.items[one], source,
				    sizeof(source)));
			}
			ncfg_out_line("");
		}
		if (ncfg_proto_str_present(modem->apn)) {
			char apn[NCFG_CLI_TEXT_MAX];

			ncfg_out_writef("    apn: %s\n",
			    ncfg_cli_text(modem->apn, apn, sizeof(apn)));
		}
		/*
		 * **Only the sources a card has actually been read on.** The mux shows
		 * the module one SIM at a time, so a source netcfgd has never been on
		 * has nothing to show and saying so by omission beats inventing a
		 * placeholder. `in use` marks the one the module is reading now, which
		 * is the question this answers: a muxed board cannot be asked which
		 * source is selected, and the card's own identifier is the only fact
		 * that says.
		 */
		for (one = 0; one < modem->card_count; one++) {
			const ncfg_proto_sim_card_t *card = &modem->cards[one];
			char        source[NCFG_CLI_TEXT_MAX];
			char        iccid[NCFG_CLI_TEXT_MAX];
			const char *here = "";

			if (ncfg_proto_str_present(modem->selected) && card->source.bytes &&
			    card->source.length == modem->selected.length &&
			    memcmp(card->source.bytes, modem->selected.bytes,
			    modem->selected.length) == 0) {
				here = "  (in use)";
			}
			ncfg_out_writef("    %s card: %s%s\n",
			    ncfg_cli_text(card->source, source, sizeof(source)),
			    ncfg_cli_text(card->iccid, iccid, sizeof(iccid)), here);
		}
	}
}
