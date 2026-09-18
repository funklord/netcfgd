/*
 * wifi.c -- what the wireless half of netcfgd answers, as an operator reads
 * it.
 *
 * NONE OF THESE COMPILE OR APPLY ANYTHING
 *   They reach the supplicant and hostapd through netcfgd, which is what makes
 *   them available to the `wifi` tier without giving that tier the ability to
 *   change configuration (0013). So every function here renders an answer that
 *   arrived over the socket, and nothing here reads a file.
 *
 * THE CAVEATS COME FIRST
 *   A scan that is stale says so above the list, not under it: a person reads
 *   the first line and then the networks, and a caveat printed underneath is
 *   one they have already acted on. A radio that is switched off says so above
 *   the association, because "the kill switch is on" is the answer to "why is
 *   there no network" and printing it beneath the details of what the
 *   supplicant is not doing buries the one line that explains all of them.
 */
#include "cli_internal.h"

#include "ncfg/log.h"

#include <stdio.h>
#include <string.h>

/*
 * The name a wireless answer carries, through the one namer.
 *
 * `name` is absent rather than empty where the SSID is not valid UTF-8 -- the
 * daemon omits it rather than mangling it -- and that distinction is the whole
 * reason `ncfg_proto_str_t` carries a presence flag. Collapsing it here would
 * throw away the difference between a hidden network and an unprintable one,
 * which is exactly what two of the three clients used to do.
 */
static const char *named(ncfg_proto_str_t name, ncfg_proto_str_t ssid, char *out,
    size_t out_size)
{
	char name_text[NCFG_CLI_TEXT_MAX];
	char ssid_text[NCFG_CLI_TEXT_MAX];

	return ncfg_cli_access_point_name(
	    ncfg_proto_str_present(name) ? ncfg_cli_text(name, name_text, sizeof(name_text)) : NULL,
	    ncfg_cli_text(ssid, ssid_text, sizeof(ssid_text)), out, out_size);
}

void ncfg_cli_print_scan(const ncfg_proto_scan_t *scan)
{
	char   interface[NCFG_CLI_TEXT_MAX];
	size_t at;
	int    any_unconfigured = 0;

	if (!scan) {
		return;
	}
	(void)ncfg_cli_text(scan->interface, interface, sizeof(interface));
	/*
	 * Before the list, and before the empty case: "nothing is in range" and
	 * "netcfgd could not scan" are different answers, and the second one
	 * printed as the first is the whole complaint this ordering fixes.
	 */
	if (ncfg_proto_str_present(scan->stale)) {
		char why[NCFG_CLI_TEXT_MAX];

		ncfg_out_writef("these are the previous scan's results: %s\n",
		    ncfg_cli_text(scan->stale, why, sizeof(why)));
	}
	if (scan->access_point_count == 0) {
		ncfg_out_writef("no access points in range of %s\n", interface);
		return;
	}
	for (at = 0; at < scan->access_point_count; at++) {
		const ncfg_proto_scan_entry_t *entry = &scan->access_points[at];
		char name[NCFG_CLI_TEXT_MAX];
		char configured[NCFG_CLI_TEXT_MAX];
		const char *security = ncfg_cli_access_point_security(entry->secured,
		    entry->enterprise, entry->owe);

		configured[0] = '\0';
		if (ncfg_proto_str_present(entry->configured)) {
			char id[NCFG_CLI_TEXT_MAX];

			(void)snprintf(configured, sizeof(configured), "  [%s]",
			    ncfg_cli_text(entry->configured, id, sizeof(id)));
		} else {
			any_unconfigured = 1;
		}
		ncfg_out_writef("%4lld dBm  %5lld MHz  %-7s  %s%s\n", (long long)entry->signal,
		    (long long)entry->frequency, security,
		    named(entry->name, entry->ssid, name, sizeof(name)), configured);
	}
	if (any_unconfigured) {
		ncfg_out_line("");
		ncfg_out_line("a name in brackets is a `network` block: `ncfg wifi connect ID` "
		    "joins it. The rest need config written first, which needs the admin "
		    "tier.");
	}
}

void ncfg_cli_print_wifi_status(const ncfg_proto_wifi_status_t *state)
{
	char   interface[NCFG_CLI_TEXT_MAX];
	char   value[NCFG_CLI_TEXT_MAX];
	size_t at;
	int    temporarily_disabled = 0;

	if (!state) {
		return;
	}
	ncfg_out_writef("%s %s\n", ncfg_cli_text(state->interface, interface, sizeof(interface)),
	    ncfg_cli_text(state->state, value, sizeof(value)));
	/*
	 * **First, above the association.** A switched-off radio is the answer to
	 * "why is there no network".
	 */
	if (ncfg_proto_str_present(state->blocked)) {
		ncfg_out_writef("    %s\n", ncfg_cli_text(state->blocked, value, sizeof(value)));
	}
	/*
	 * Keyed on the ssid, which is the field that says "associated at all", and
	 * rendered by the shared namer. Taking the name and falling back to the
	 * ssid printed the raw hex with nothing marking it as hex whenever the
	 * SSID was not text -- the exact misreading the `hex:` prefix exists to
	 * stop, in the one place a scan's rendering had not reached.
	 */
	if (ncfg_proto_str_present(state->ssid)) {
		char name[NCFG_CLI_TEXT_MAX];
		char bssid[NCFG_CLI_TEXT_MAX + 4];

		bssid[0] = '\0';
		if (ncfg_proto_str_present(state->bssid)) {
			(void)snprintf(bssid, sizeof(bssid), " (%s)",
			    ncfg_cli_text(state->bssid, value, sizeof(value)));
		}
		ncfg_out_writef("    %s%s\n", named(state->name, state->ssid, name, sizeof(name)),
		    bssid);
	}
	if (ncfg_proto_str_present(state->network)) {
		ncfg_out_writef("    from the `%s` network block\n",
		    ncfg_cli_text(state->network, value, sizeof(value)));
	} else if (ncfg_proto_str_present(state->ssid)) {
		ncfg_out_line("    not from any `network` block, which should not happen: "
		    "netcfgd supplies every network the supplicant knows. Worth reporting.");
	}
	/*
	 * The half `wpa_state` cannot say. An interface with nothing to show above
	 * reads `SCANNING` whether it is looking hopefully or has given up on
	 * everything it was given, and this is the difference. Decision 0192.
	 */
	if (state->not_trying_count > 0) {
		ncfg_out_line("    not being tried:");
		for (at = 0; at < state->not_trying_count; at++) {
			const ncfg_proto_disabled_t *one = &state->not_trying[at];
			char name[NCFG_CLI_TEXT_MAX];
			char flags[NCFG_CLI_TEXT_MAX];

			(void)ncfg_cli_text(one->flags, flags, sizeof(flags));
			if (strstr(flags, "TEMP-DISABLED")) {
				temporarily_disabled = 1;
			}
			ncfg_out_writef("        %s %s\n",
			    named(one->name, one->ssid, name, sizeof(name)), flags);
		}
	}
	/*
	 * Said once, here, rather than on each of the log lines that got the
	 * operator to this command: a temporary disable is the supplicant giving
	 * up after repeated failures, and what it means is that the credentials or
	 * the settings are wrong rather than that the network is far away. A
	 * network merely out of range is never disabled -- it is simply not found.
	 */
	if (temporarily_disabled) {
		ncfg_out_line("    a temporary disable is the supplicant giving up after "
		    "repeated failures and waiting before it tries again. It is not a network "
		    "out of range -- that one is absent from a scan, not disabled. "
		    "`journalctl -u netcfgd | grep supplicant` has the count and the reason.");
	}
}

/*
 * The note under a station, which says what is *surprising*.
 *
 * That is the opposite thing under the two policies: a listed station is
 * expected under `allow` and should be impossible under `deny`. `anomalies` is
 * bumped only for the two that are surprising, because the paragraph at the
 * bottom is about arrows and not about an unauthorized association.
 */
static const char *station_note(ncfg_proto_str_t policy, const ncfg_proto_station_t *station,
    unsigned *anomalies)
{
	if (ncfg_proto_str_equals(policy, "deny") && station->listed) {
		(*anomalies)++;
		return "  <- on the deny list and still connected";
	}
	if (ncfg_proto_str_equals(policy, "allow") && !station->listed) {
		(*anomalies)++;
		return "  <- not on the allow list and still connected";
	}
	if (!station->authorized) {
		return "  (associated, not authorized)";
	}
	return "";
}

void ncfg_cli_print_stations(const ncfg_proto_stations_t *report)
{
	char     interface[NCFG_CLI_TEXT_MAX];
	char     access_point[NCFG_CLI_TEXT_MAX];
	size_t   at;
	unsigned anomalies = 0;

	if (!report) {
		return;
	}
	(void)ncfg_cli_text(report->interface, interface, sizeof(interface));
	(void)ncfg_cli_text(report->access_point, access_point, sizeof(access_point));
	if (report->station_count == 0) {
		ncfg_out_writef("nothing is associated with `%s` on %s\n", access_point, interface);
		return;
	}
	ncfg_out_writef("%zu station%s on `%s` (%s)\n", report->station_count,
	    report->station_count == 1 ? "" : "s", access_point, interface);
	ncfg_out_line("");
	ncfg_out_writef("%-17s  %7s  %9s  %7s  %8s  %8s\n", "ADDRESS", "SIGNAL", "CONNECTED",
	    "IDLE", "RX", "TX");

	for (at = 0; at < report->station_count; at++) {
		const ncfg_proto_station_t *station = &report->stations[at];
		char address[NCFG_CLI_TEXT_MAX];
		char signal[32];
		char connected[32];
		char idle[32];
		char rx[32];
		char tx[32];

		/*
		 * A station hostapd could not read a statistic for keeps its row, with
		 * a dash where the number would be. Hiding it would be the worst way
		 * for this to be wrong: a client that is there matters more than the
		 * signal strength that is not.
		 */
		if (station->signal.present) {
			(void)snprintf(signal, sizeof(signal), "%lld dBm",
			    (long long)station->signal.value);
		} else {
			(void)snprintf(signal, sizeof(signal), "--");
		}
		if (station->connected_seconds.present) {
			(void)ncfg_cli_duration(station->connected_seconds.value, connected,
			    sizeof(connected));
		} else {
			(void)snprintf(connected, sizeof(connected), "--");
		}
		if (station->inactive_msec.present) {
			(void)ncfg_cli_duration(station->inactive_msec.value / 1000, idle,
			    sizeof(idle));
		} else {
			(void)snprintf(idle, sizeof(idle), "--");
		}
		if (station->rx_bytes.present) {
			(void)ncfg_cli_bytes(station->rx_bytes.value, rx, sizeof(rx));
		} else {
			(void)snprintf(rx, sizeof(rx), "--");
		}
		if (station->tx_bytes.present) {
			(void)ncfg_cli_bytes(station->tx_bytes.value, tx, sizeof(tx));
		} else {
			(void)snprintf(tx, sizeof(tx), "--");
		}
		ncfg_out_writef("%-17s  %7s  %9s  %7s  %8s  %8s%s\n",
		    ncfg_cli_text(station->address, address, sizeof(address)), signal, connected,
		    idle, rx, tx, station_note(report->access_control, station, &anomalies));
	}

	if (anomalies > 0) {
		ncfg_out_line("");
		/*
		 * What this means changed with decision 0041, and saying the old thing
		 * would send an operator to restart an access point that was about to
		 * fix itself. hostapd still reads its file once at startup, but
		 * netcfgd now converges the live list over the control socket, so an
		 * arrow is a state that lasts until the next reconcile rather than
		 * until somebody intervenes.
		 */
		ncfg_out_line("An arrow means hostapd's live list does not match the document "
		    "yet: it reads \nthe file once at startup and netcfgd converges the "
		    "difference over the control \nsocket. `ncfg apply` does it now; if an "
		    "arrow survives that, `ncfg plan` says \nwhy (doc/decision/0041).");
	}
}

void ncfg_cli_print_radios(const ncfg_proto_radio_t *radios, size_t count)
{
	size_t at;
	int    any_inactive = 0;

	if (count == 0) {
		ncfg_out_line("no radios on this machine");
		return;
	}
	for (at = 0; at < count; at++) {
		char interface[NCFG_CLI_TEXT_MAX];
		const char *state;

		/*
		 * **Three states rather than two, because the third is the one
		 * somebody is stuck in**: a radio nothing has activated but where a
		 * supplicant is answering belongs to another manager, and netcfgd
		 * declines those rather than taking them. Saying "not activated" there
		 * and nothing else would invite an `activate` that changes nothing.
		 */
		if (radios[at].activated && radios[at].supplicant) {
			state = "netcfgd's";
		} else if (radios[at].activated) {
			state = "netcfgd's, but no supplicant is answering";
		} else if (radios[at].supplicant) {
			state = "another manager's -- a supplicant is answering that netcfgd "
			    "did not start";
		} else {
			state = "not activated";
		}
		if (!radios[at].activated) {
			any_inactive = 1;
		}
		ncfg_out_writef("%-16s %s\n",
		    ncfg_cli_text(radios[at].interface, interface, sizeof(interface)), state);
	}
	if (any_inactive) {
		ncfg_out_line("");
		ncfg_out_line("`ncfg wifi activate <radio>` hands one to netcfgd.");
	}
}
