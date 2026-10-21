/*
 * What netcfgd reads back from the daemons it drives.
 *
 * **A lower-trust boundary than it looks, and lower than the kernel's.** These
 * replies arrive over a unix socket from a separate process netcfgd starts but
 * does not contain: a `wpa_supplicant` upgraded underneath it, one that
 * crashes mid-reply, or simply a different implementation will send bytes
 * these parsers have never seen. The kernel is the more trustworthy of the
 * two ends, and `netlink_wire.c` fuzzes that one.
 *
 * Driven whole and line by line, because a control socket delivers one reply
 * at a time: feeding only the whole blob would leave the per-line parsers
 * reachable solely through whatever the blob happened to contain. The Rust's
 * `backend_ipc` target splits for the same reason.
 *
 * `ncfg_supplicant_reply_parse` edits in place, so it gets a copy of its own
 * rather than the one the other parsers read.
 */
#include "fuzz.h"

#include "ncfg/base.h"
#include "ncfg/apply.h"
#include "ncfg/hostapd.h"
#include "ncfg/supplicant.h"

#include <stdlib.h>
#include <string.h>

static void one_line(const char *line)
{
	ncfg_supplicant_event_t event;

	if (ncfg_supplicant_is_event(line) && ncfg_supplicant_event_parse(line, &event)) {
		char     value[128];
		char     bssid[32];
		uint32_t id;

		(void)ncfg_supplicant_event_is(&event, "CTRL-EVENT-CONNECTED");
		(void)ncfg_supplicant_event_connected_bssid(&event, bssid, sizeof(bssid));
		(void)ncfg_supplicant_event_network_id(&event, &id);
		/* A key that is there and one that is not: the miss is the arm that
		 * walks the whole text looking for it. */
		(void)ncfg_supplicant_event_field(&event, "ssid", value, sizeof(value));
		(void)ncfg_supplicant_event_field(&event, "", value, sizeof(value));
	}
}

int ncfg_fuzz_one(const unsigned char *data, size_t length)
{
	ncfg_supplicant_scan_t  *scans = NULL;
	ncfg_supplicant_entry_t *entries = NULL;
	size_t                   count = 0u;
	char                     err[NCFG_ERROR_MAX];
	char                    *text = ncfg_fuzz_text(data, length);
	char                    *mutable_copy;
	char                    *cursor;
	int                      policy;

	if (!text) {
		return 0;
	}
	mutable_copy = ncfg_fuzz_text(data, length);
	if (mutable_copy) {
		(void)ncfg_supplicant_reply_parse(mutable_copy);
		free(mutable_copy);
	}

	if (ncfg_supplicant_parse_scan_results(text, &scans, &count, err, sizeof(err))) {
		size_t at;

		for (at = 0u; at < count; at++) {
			(void)ncfg_supplicant_scan_is_secured(&scans[at]);
			(void)ncfg_supplicant_scan_is_enterprise(&scans[at]);
		}
		ncfg_supplicant_scans_free(scans, count);
	}
	count = 0u;
	if (ncfg_supplicant_parse_network_list(text, &entries, &count, err, sizeof(err))) {
		size_t at;

		for (at = 0u; at < count; at++) {
			(void)ncfg_supplicant_entry_is_current(&entries[at]);
		}
		ncfg_supplicant_entries_free(entries, count);
	}

	/*
	 * hostapd's three. The policy file is read from disk rather than a socket
	 * and is a parser all the same; the other two are replies off its control
	 * socket, which `hostapd.h` names together with the supplicant's for the
	 * same reason this target drives them together -- it is one boundary, a
	 * process netcfgd starts and does not contain.
	 */
	(void)ncfg_hostapd_policy_in(text, &policy);
	{
		char                 **allowed = NULL;
		size_t                 allowed_count = 0u;
		ncfg_hostapd_station_t station;

		if (ncfg_hostapd_parse_acl_show(text, &allowed, &allowed_count, err,
		        sizeof(err))) {
			ncfg_hostapd_stations_free(allowed, allowed_count);
		}
		memset(&station, 0, sizeof(station));
		(void)ncfg_hostapd_parse_station(text, &station);
	}

	/*
	 * And dhcpcd's control socket, which is the third process of this kind:
	 * its payload is length-prefixed bytes rather than lines, so it is driven
	 * from the raw input rather than from the text copy.
	 */
	{
		char payload[512];

		(void)ncfg_dhcpcd_control_payload(data, length, payload, sizeof(payload));
	}

	/* Line by line. The text is NUL-terminated by `ncfg_fuzz_text`, and an
	 * embedded NUL left in place ends this walk early -- which is itself the
	 * input worth having, since that is what a truncated datagram looks like. */
	cursor = text;
	for (;;) {
		char *newline = strchr(cursor, '\n');

		if (newline) {
			*newline = '\0';
		}
		one_line(cursor);
		if (!newline) {
			break;
		}
		cursor = newline + 1;
	}
	free(text);
	return 0;
}
