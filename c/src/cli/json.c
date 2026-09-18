/*
 * json.c -- what `--json` prints, for the answers `ncfg` renders as tables.
 *
 * WHY THIS IS HERE AND NOT IN `proto.h`
 *   The daemon already writes four of these shapes, out of its own data, in
 *   `src/daemon/wifi.c`. This writes the same shapes out of the *decoded*
 *   answer, which is a different input and not a second reader -- but it is a
 *   second writer, and two writers of one format is exactly the drift this
 *   port spends its length refusing. So the two are held together by the
 *   frozen witness rather than by good intentions: `cli_test.c` takes each
 *   `{"response":...}` line out of `doc/schema/socket.json`, decodes it with
 *   `ncfg_proto_response_read` and writes it back through the calls below,
 *   and the result must be that line again, byte for byte, with its
 *   `"response"` member removed. A member renamed at either end is red.
 *
 *   It is not in `proto.h` because nothing but `ncfg` wants it: the daemon
 *   composes its answers as it discovers them and never holds a decoded one,
 *   and the GUI reads through `client/`. A third spelling would arrive the
 *   moment this became a general call with no caller.
 *
 * WHAT IS AND IS NOT WRITTEN
 *   The payload, never the envelope; an absent optional member is absent
 *   rather than null; a list that the protocol skips when empty is skipped.
 *   `cli.h` argues each of those and says where the rules come from.
 *
 * ERRORS
 *   base.h's convention: 1, or 0 with a sentence. A string that is not valid
 *   UTF-8 is what these actually fail on, and the buffer is left empty rather
 *   than holding the part that fitted -- `ncfg_buf_t`'s bargain, and the
 *   reason a caller may write forty calls and check once.
 */
#include "cli_internal.h"

#include "ncfg/base.h"
#include "ncfg/json_write.h"

#include <stddef.h>

/*
 * The one check at the end, and the sentence that says what could not be
 * written.
 *
 * `ncfg_json_write_done` rather than `ncfg_json_write_failed`, because an
 * object left open is not detectable when it happens -- only a caller that
 * says it has finished can be told that it has not.
 */
static int finish(ncfg_json_writer_t *writer, const char *what, char *err, size_t err_size)
{
	if (!ncfg_json_write_done(writer)) {
		const char *why = ncfg_json_write_failure(writer);

		ncfg_error_set(err, err_size, "%s could not be written as JSON: %s", what,
		    why ? why : "it did not fit");
		return 0;
	}
	return 1;
}

/*
 * A member the protocol always carries.
 *
 * An absent one reads as empty, which is this call's whole difference from
 * `member_maybe` below: the decoder has already required these, so absence
 * here means a caller built the structure by hand and left a field out --
 * and `ncfg_json_write_string_bytes` refuses a NULL pointer outright, which
 * would fail the whole document over a missing `bssid` rather than write the
 * rest of the scan.
 */
static void member_text(ncfg_json_writer_t *writer, const char *name, ncfg_proto_str_t text)
{
	ncfg_json_write_key(writer, name);
	ncfg_json_write_string_bytes(writer, text.bytes ? text.bytes : "", text.length);
}

/* A member the protocol skips where it has nothing. Absent, not null. */
static void member_maybe(ncfg_json_writer_t *writer, const char *name, ncfg_proto_str_t text)
{
	if (ncfg_proto_str_present(text)) {
		member_text(writer, name, text);
	}
}

/* The same for an integer hostapd may not have been able to read. */
static void member_int_maybe(ncfg_json_writer_t *writer, const char *name,
    ncfg_proto_int_t value)
{
	if (value.present) {
		ncfg_json_write_member_int(writer, name, value.value);
	}
}

int ncfg_cli_json_scan(const ncfg_proto_scan_t *scan, ncfg_buf_t *out, char *err,
    size_t err_size)
{
	ncfg_json_writer_t writer;
	size_t             at;

	if (!scan || !out) {
		ncfg_error_set(err, err_size, "no scan to write");
		return 0;
	}
	ncfg_json_write_init(&writer, out);
	ncfg_json_write_object_begin(&writer);
	member_text(&writer, "interface", scan->interface);
	ncfg_json_write_key(&writer, "access_points");
	ncfg_json_write_array_begin(&writer);
	for (at = 0; at < scan->access_point_count; at++) {
		const ncfg_proto_scan_entry_t *point = &scan->access_points[at];

		ncfg_json_write_object_begin(&writer);
		member_text(&writer, "bssid", point->bssid);
		ncfg_json_write_member_int(&writer, "frequency", point->frequency);
		ncfg_json_write_member_int(&writer, "signal", point->signal);
		ncfg_json_write_member_bool(&writer, "secured", point->secured);
		ncfg_json_write_member_bool(&writer, "owe", point->owe);
		ncfg_json_write_member_bool(&writer, "enterprise", point->enterprise);
		/*
		 * The hex form is the canonical identity and is always there; the
		 * text form is absent rather than mangled where the octets are not
		 * UTF-8, which is what lets a reader tell "not text" from "empty"
		 * without this writer having to guess.
		 */
		member_text(&writer, "ssid", point->ssid);
		member_maybe(&writer, "name", point->name);
		member_maybe(&writer, "mobility_domain", point->mobility_domain);
		member_maybe(&writer, "configured", point->configured);
		ncfg_json_write_object_end(&writer);
	}
	ncfg_json_write_array_end(&writer);
	member_maybe(&writer, "stale", scan->stale);
	ncfg_json_write_object_end(&writer);
	return finish(&writer, "the scan", err, err_size);
}

int ncfg_cli_json_wifi_status(const ncfg_proto_wifi_status_t *state, ncfg_buf_t *out, char *err,
    size_t err_size)
{
	ncfg_json_writer_t writer;
	size_t             at;

	if (!state || !out) {
		ncfg_error_set(err, err_size, "no radio status to write");
		return 0;
	}
	ncfg_json_write_init(&writer, out);
	ncfg_json_write_object_begin(&writer);
	member_text(&writer, "interface", state->interface);
	member_text(&writer, "state", state->state);
	member_maybe(&writer, "ssid", state->ssid);
	member_maybe(&writer, "name", state->name);
	member_maybe(&writer, "bssid", state->bssid);
	member_maybe(&writer, "network", state->network);
	member_maybe(&writer, "blocked", state->blocked);
	/* Empty on a healthy radio, which is why the protocol skips it rather
	 * than sending an empty list -- and why this does too. */
	if (state->not_trying_count > 0) {
		ncfg_json_write_key(&writer, "not_trying");
		ncfg_json_write_array_begin(&writer);
		for (at = 0; at < state->not_trying_count; at++) {
			const ncfg_proto_disabled_t *one = &state->not_trying[at];

			ncfg_json_write_object_begin(&writer);
			member_text(&writer, "ssid", one->ssid);
			member_maybe(&writer, "name", one->name);
			member_text(&writer, "flags", one->flags);
			ncfg_json_write_object_end(&writer);
		}
		ncfg_json_write_array_end(&writer);
	}
	ncfg_json_write_object_end(&writer);
	return finish(&writer, "the radio status", err, err_size);
}

int ncfg_cli_json_stations(const ncfg_proto_stations_t *report, ncfg_buf_t *out, char *err,
    size_t err_size)
{
	ncfg_json_writer_t writer;
	size_t             at;

	if (!report || !out) {
		ncfg_error_set(err, err_size, "no station list to write");
		return 0;
	}
	ncfg_json_write_init(&writer, out);
	ncfg_json_write_object_begin(&writer);
	member_text(&writer, "interface", report->interface);
	member_text(&writer, "access_point", report->access_point);
	/* Which way the list reads: `listed` means opposite things under the two
	 * policies, so a reader without this would have to guess. */
	member_maybe(&writer, "access_control", report->access_control);
	ncfg_json_write_key(&writer, "stations");
	ncfg_json_write_array_begin(&writer);
	for (at = 0; at < report->station_count; at++) {
		const ncfg_proto_station_t *one = &report->stations[at];

		ncfg_json_write_object_begin(&writer);
		member_text(&writer, "address", one->address);
		ncfg_json_write_member_bool(&writer, "authorized", one->authorized);
		ncfg_json_write_member_bool(&writer, "listed", one->listed);
		/*
		 * Everything past `listed` is optional because hostapd omits the
		 * whole statistics block when the driver will not give it one. A
		 * station that is really there with no numbers beside it is the
		 * honest answer; a zero would be a measurement nobody made.
		 */
		member_int_maybe(&writer, "signal", one->signal);
		member_int_maybe(&writer, "connected_seconds", one->connected_seconds);
		member_int_maybe(&writer, "inactive_msec", one->inactive_msec);
		member_int_maybe(&writer, "rx_bytes", one->rx_bytes);
		member_int_maybe(&writer, "tx_bytes", one->tx_bytes);
		ncfg_json_write_object_end(&writer);
	}
	ncfg_json_write_array_end(&writer);
	ncfg_json_write_object_end(&writer);
	return finish(&writer, "the station list", err, err_size);
}

int ncfg_cli_json_radios(const ncfg_proto_radio_t *radios, size_t count, ncfg_buf_t *out,
    char *err, size_t err_size)
{
	ncfg_json_writer_t writer;
	size_t             at;

	if (!out || (count > 0 && !radios)) {
		ncfg_error_set(err, err_size, "no radio list to write");
		return 0;
	}
	ncfg_json_write_init(&writer, out);
	ncfg_json_write_object_begin(&writer);
	ncfg_json_write_key(&writer, "radios");
	ncfg_json_write_array_begin(&writer);
	for (at = 0; at < count; at++) {
		ncfg_json_write_object_begin(&writer);
		member_text(&writer, "interface", radios[at].interface);
		ncfg_json_write_member_bool(&writer, "activated", radios[at].activated);
		ncfg_json_write_member_bool(&writer, "supplicant", radios[at].supplicant);
		ncfg_json_write_object_end(&writer);
	}
	ncfg_json_write_array_end(&writer);
	ncfg_json_write_object_end(&writer);
	return finish(&writer, "the radio list", err, err_size);
}

int ncfg_cli_json_modems(const ncfg_proto_modem_t *modems, size_t count, ncfg_buf_t *out,
    char *err, size_t err_size)
{
	ncfg_json_writer_t writer;
	size_t             at;

	if (!out || (count > 0 && !modems)) {
		ncfg_error_set(err, err_size, "no modem list to write");
		return 0;
	}
	ncfg_json_write_init(&writer, out);
	ncfg_json_write_object_begin(&writer);
	ncfg_json_write_key(&writer, "modems");
	ncfg_json_write_array_begin(&writer);
	for (at = 0; at < count; at++) {
		const ncfg_proto_modem_t *modem = &modems[at];
		size_t                    item;

		ncfg_json_write_object_begin(&writer);
		member_text(&writer, "device", modem->device);
		if (modem->sim.count > 0) {
			ncfg_json_write_key(&writer, "sim");
			ncfg_json_write_array_begin(&writer);
			for (item = 0; item < modem->sim.count; item++) {
				ncfg_proto_str_t source = modem->sim.items[item];

				ncfg_json_write_string_bytes(&writer,
				    source.bytes ? source.bytes : "", source.length);
			}
			ncfg_json_write_array_end(&writer);
		}
		member_maybe(&writer, "selected", modem->selected);
		member_maybe(&writer, "apn", modem->apn);
		/* False is the ordinary state and the protocol does not send it:
		 * "this modem is not switching" is what every other modem's silence
		 * already says. */
		if (modem->cycle_pending) {
			ncfg_json_write_member_bool(&writer, "cycle_pending", 1);
		}
		/* One per source a helper has actually reported a card for, which is
		 * why an empty list is absent rather than sent: a source netcfgd has
		 * never been on has no card, and saying `[]` would read as a modem
		 * with no SIM anywhere. */
		if (modem->card_count > 0) {
			ncfg_json_write_key(&writer, "cards");
			ncfg_json_write_array_begin(&writer);
			for (item = 0; item < modem->card_count; item++) {
				ncfg_json_write_object_begin(&writer);
				member_text(&writer, "source", modem->cards[item].source);
				member_text(&writer, "iccid", modem->cards[item].iccid);
				ncfg_json_write_object_end(&writer);
			}
			ncfg_json_write_array_end(&writer);
		}
		ncfg_json_write_object_end(&writer);
	}
	ncfg_json_write_array_end(&writer);
	ncfg_json_write_object_end(&writer);
	return finish(&writer, "the modem list", err, err_size);
}

int ncfg_cli_json_explanation(const ncfg_explanation_t *explanation, ncfg_buf_t *out, char *err,
    size_t err_size)
{
	ncfg_json_writer_t writer;
	size_t             at;

	if (!explanation || !out) {
		ncfg_error_set(err, err_size, "no explanation to write");
		return 0;
	}
	ncfg_json_write_init(&writer, out);
	ncfg_json_write_object_begin(&writer);
	ncfg_json_write_member_string(&writer, "subject",
	    explanation->subject ? explanation->subject : "");
	ncfg_json_write_key(&writer, "facts");
	ncfg_json_write_array_begin(&writer);
	for (at = 0; at < explanation->count; at++) {
		const ncfg_explain_fact_t *fact = &explanation->facts[at];

		ncfg_json_write_object_begin(&writer);
		ncfg_json_write_member_string(&writer, "topic", fact->topic ? fact->topic : "");
		ncfg_json_write_member_string(&writer, "detail",
		    fact->detail ? fact->detail : "");
		/* Absent where the fact came from nowhere nameable -- a derived
		 * answer, or a policy read off the document with no position. Null
		 * would be a third thing the protocol does not have. */
		if (fact->source) {
			ncfg_json_write_member_string(&writer, "source", fact->source);
		}
		ncfg_json_write_object_end(&writer);
	}
	ncfg_json_write_array_end(&writer);
	/* See cli.h: how many there were, so that a bounded explanation says so
	 * to a program as well as to a person. */
	ncfg_json_write_member_int(&writer, "total", (int64_t)explanation->total);
	ncfg_json_write_object_end(&writer);
	return finish(&writer, "the explanation", err, err_size);
}

int ncfg_cli_json_ok(ncfg_buf_t *out, char *err, size_t err_size)
{
	ncfg_json_writer_t writer;

	if (!out) {
		ncfg_error_set(err, err_size, "nowhere to write the answer");
		return 0;
	}
	ncfg_json_write_init(&writer, out);
	ncfg_json_write_object_begin(&writer);
	ncfg_json_write_member_bool(&writer, "ok", 1);
	ncfg_json_write_object_end(&writer);
	return finish(&writer, "the answer", err, err_size);
}
