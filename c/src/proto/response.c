/*
 * response.c -- what the daemon answers, and what a monitor stream carries.
 *
 * Read leniently: a member this build does not know is passed over rather
 * than refused, because a client may be older than the daemon it is talking
 * to and refusing an unfamiliar member is how an upgrade breaks a working
 * client. The leniency is about members and not about the tag -- a `response`
 * nobody here can act on is refused, exactly as the Rust refuses it.
 */
#include "internal.h"

#include <string.h>

static const char *const response_names[NCFG_PROTO_RESP_COUNT] = {
	"hello",
	"status",
	"plan",
	"document",
	"journal",
	"explanation",
	"event",
	"wifi_scan",
	"secrets",
	"modems",
	"profiles",
	"configs",
	"hooks",
	"probes",
	"radios",
	"wifi_status",
	"ap_stations",
	"ok",
	"error",
};

static const char *const event_names[NCFG_PROTO_EVENT_COUNT] = {
	"observed",
	"reloaded",
	"drift",
	"confirm_armed",
	"confirm_resolved",
};

const char *ncfg_proto_response_name(ncfg_proto_response_kind_t kind)
{
	int at = (int)kind;

	if (at < 0 || at >= NCFG_PROTO_RESP_COUNT) {
		return NULL;
	}
	return response_names[at];
}

const char *ncfg_proto_event_name(ncfg_proto_event_kind_t kind)
{
	int at = (int)kind;

	if (at < 0 || at >= NCFG_PROTO_EVENT_COUNT) {
		return NULL;
	}
	return event_names[at];
}

/* One element of a list of objects, refused where it is not one. */
static int element(ncfg_proto_dec_t *dec, uint32_t array, size_t at, const char *what,
    uint32_t *out)
{
	*out = ncfg_json_at(dec->doc, array, (uint32_t)at);
	if (ncfg_json_type(dec->doc, *out) != NCFG_JSON_OBJECT) {
		return ncfg_proto_fail(dec, "%s holds something that is not an object", what);
	}
	return 1;
}

/*
 * The list preamble every one of these repeats: find the array, take a block
 * for it, and hand back both. 0 with the refusal already written.
 */
static int list_of(ncfg_proto_dec_t *dec, uint32_t object, const char *name, int required,
    const char *what, size_t size, uint32_t *array_out, size_t *count_out, void **items_out)
{
	*items_out = NULL;
	if (!ncfg_proto_get_array(dec, object, name, required, what, array_out, count_out)) {
		return 0;
	}
	if (!*count_out) {
		return 1;
	}
	*items_out = ncfg_proto_block(dec, *count_out, size);
	return *items_out != NULL;
}

/* --------------------------------------------------------------- events */

int ncfg_proto_decode_event(ncfg_proto_dec_t *dec, uint32_t object, ncfg_proto_event_t *out)
{
	const char *what = "this event";
	ncfg_proto_str_t tag;
	ncfg_proto_int_t seconds;
	int at;

	memset(out, 0, sizeof(*out));
	if (!ncfg_proto_get_str(dec, object, "event", 1, what, &tag)) {
		return 0;
	}
	for (at = 0; at < NCFG_PROTO_EVENT_COUNT; at++) {
		if (ncfg_proto_str_equals(tag, event_names[at])) {
			break;
		}
	}
	if (at == NCFG_PROTO_EVENT_COUNT) {
		return ncfg_proto_fail(dec, "`%.*s` is not an event this speaks",
		    (int)tag.length, tag.bytes);
	}
	out->kind = (ncfg_proto_event_kind_t)at;
	switch (out->kind) {
	case NCFG_PROTO_EVENT_OBSERVED:
		return ncfg_proto_get_str(dec, object, "summary", 1, what, &out->summary);
	case NCFG_PROTO_EVENT_RELOADED:
		return ncfg_proto_get_bool(dec, object, "ok", 1, 0, what, &out->ok) &&
		    ncfg_proto_get_str(dec, object, "diagnostics", 0, what, &out->diagnostics);
	case NCFG_PROTO_EVENT_DRIFT:
		return ncfg_proto_get_str(dec, object, "interface", 1, what, &out->interface) &&
		    ncfg_proto_get_str(dec, object, "summary", 1, what, &out->summary) &&
		    ncfg_proto_get_str(dec, object, "action", 1, what, &out->action);
	case NCFG_PROTO_EVENT_CONFIRM_ARMED:
		if (!ncfg_proto_get_int(dec, object, "seconds", 1, what, &seconds)) {
			return 0;
		}
		out->seconds = seconds.value;
		return 1;
	case NCFG_PROTO_EVENT_CONFIRM_RESOLVED:
	default:
		return ncfg_proto_get_bool(dec, object, "confirmed", 1, 0, what, &out->confirmed);
	}
}

/* ------------------------------------------------------------ the arms */

static int decode_hello(ncfg_proto_dec_t *dec, uint32_t object, ncfg_proto_response_t *out)
{
	const char *what = "a `hello` response";

	return ncfg_proto_get_version(dec, object, "protocol", what, &out->u.hello.protocol) &&
	    ncfg_proto_get_version(dec, object, "schema", what, &out->u.hello.schema) &&
	    /* Not required: a daemon that answered a connection it could work out
	     * nothing about would still be answering, and `tiers` defaults to the
	     * empty list. Item 10 of section 10 says to treat "could not tell" as
	     * permitted rather than greying a button out. */
	    ncfg_proto_get_strs(dec, object, "tiers", 0, what, &out->u.hello.tiers);
}

static int decode_explanation(ncfg_proto_dec_t *dec, uint32_t object, ncfg_proto_response_t *out)
{
	const char *what = "an `explanation` response";
	uint32_t array;
	size_t count;
	size_t at;
	void *block;
	ncfg_proto_fact_t *items;

	if (!ncfg_proto_get_str(dec, object, "subject", 1, what, &out->u.explanation.subject)) {
		return 0;
	}
	if (!list_of(dec, object, "facts", 1, what, sizeof(*items), &array, &count, &block)) {
		return 0;
	}
	items = block;
	for (at = 0; at < count; at++) {
		uint32_t fact;

		if (!element(dec, array, at, "`facts`", &fact) ||
		    !ncfg_proto_get_str(dec, fact, "topic", 1, "a fact", &items[at].topic) ||
		    !ncfg_proto_get_str(dec, fact, "detail", 1, "a fact", &items[at].detail) ||
		    !ncfg_proto_get_str(dec, fact, "source", 0, "a fact", &items[at].source)) {
			return 0;
		}
	}
	out->u.explanation.facts = items;
	out->u.explanation.fact_count = count;
	return 1;
}

static int decode_scan(ncfg_proto_dec_t *dec, uint32_t object, ncfg_proto_response_t *out)
{
	const char *what = "a `wifi_scan` response";
	uint32_t array;
	size_t count;
	size_t at;
	void *block;
	ncfg_proto_scan_entry_t *items;

	if (!ncfg_proto_get_str(dec, object, "interface", 1, what, &out->u.wifi_scan.interface) ||
	    !ncfg_proto_get_str(dec, object, "stale", 0, what, &out->u.wifi_scan.stale)) {
		return 0;
	}
	if (!list_of(dec, object, "access_points", 1, what, sizeof(*items), &array, &count,
	        &block)) {
		return 0;
	}
	items = block;
	for (at = 0; at < count; at++) {
		uint32_t entry;
		ncfg_proto_int_t frequency;
		ncfg_proto_int_t signal;
		const char *point = "an access point";

		if (!element(dec, array, at, "`access_points`", &entry) ||
		    !ncfg_proto_get_str(dec, entry, "bssid", 1, point, &items[at].bssid) ||
		    !ncfg_proto_get_int(dec, entry, "frequency", 1, point, &frequency) ||
		    !ncfg_proto_get_int(dec, entry, "signal", 1, point, &signal) ||
		    !ncfg_proto_get_bool(dec, entry, "secured", 1, 0, point, &items[at].secured) ||
		    !ncfg_proto_get_bool(dec, entry, "owe", 1, 0, point, &items[at].owe) ||
		    /* Defaulted rather than required, as the Rust has it: a daemon
		     * older than this client does not send it, and an access point
		     * missing from a list is worse than one whose dialog asks for
		     * a passphrase. */
		    !ncfg_proto_get_bool(dec, entry, "enterprise", 0, 0, point,
		        &items[at].enterprise) ||
		    /* Hex, always present, and the canonical identity: two networks
		     * cannot collide in it after rendering. */
		    !ncfg_proto_get_str(dec, entry, "ssid", 1, point, &items[at].ssid) ||
		    /* The same value as text, absent rather than mangled where the
		     * octets are not UTF-8 -- which is what lets a client tell "not
		     * text" from "empty" (section 8). */
		    !ncfg_proto_get_str(dec, entry, "name", 0, point, &items[at].name) ||
		    !ncfg_proto_get_str(dec, entry, "mobility_domain", 0, point,
		        &items[at].mobility_domain) ||
		    !ncfg_proto_get_str(dec, entry, "configured", 0, point,
		        &items[at].configured)) {
			return 0;
		}
		items[at].frequency = frequency.value;
		items[at].signal = signal.value;
	}
	out->u.wifi_scan.access_points = items;
	out->u.wifi_scan.access_point_count = count;
	return 1;
}

static int decode_wifi_status(ncfg_proto_dec_t *dec, uint32_t object, ncfg_proto_response_t *out)
{
	const char *what = "a `wifi_status` response";
	uint32_t array;
	size_t count;
	size_t at;
	void *block;
	ncfg_proto_disabled_t *items;
	ncfg_proto_wifi_status_t *status = &out->u.wifi_status;

	if (!ncfg_proto_get_str(dec, object, "interface", 1, what, &status->interface) ||
	    !ncfg_proto_get_str(dec, object, "state", 1, what, &status->state) ||
	    !ncfg_proto_get_str(dec, object, "ssid", 0, what, &status->ssid) ||
	    !ncfg_proto_get_str(dec, object, "name", 0, what, &status->name) ||
	    !ncfg_proto_get_str(dec, object, "bssid", 0, what, &status->bssid) ||
	    /* Absent means the supplicant is on something the document did not
	     * put there, which after 0015 should not happen -- so a client
	     * showing it is showing a discrepancy, not a gap. */
	    !ncfg_proto_get_str(dec, object, "network", 0, what, &status->network) ||
	    !ncfg_proto_get_str(dec, object, "blocked", 0, what, &status->blocked)) {
		return 0;
	}
	/* Empty on a healthy radio, which is why it is skipped when empty rather
	 * than always present. */
	if (!list_of(dec, object, "not_trying", 0, what, sizeof(*items), &array, &count,
	        &block)) {
		return 0;
	}
	items = block;
	for (at = 0; at < count; at++) {
		uint32_t entry;
		const char *one = "a network the supplicant is not trying";

		if (!element(dec, array, at, "`not_trying`", &entry) ||
		    !ncfg_proto_get_str(dec, entry, "ssid", 1, one, &items[at].ssid) ||
		    !ncfg_proto_get_str(dec, entry, "name", 0, one, &items[at].name) ||
		    !ncfg_proto_get_str(dec, entry, "flags", 1, one, &items[at].flags)) {
			return 0;
		}
	}
	status->not_trying = items;
	status->not_trying_count = count;
	return 1;
}

static int decode_stations(ncfg_proto_dec_t *dec, uint32_t object, ncfg_proto_response_t *out)
{
	const char *what = "an `ap_stations` response";
	uint32_t array;
	size_t count;
	size_t at;
	void *block;
	ncfg_proto_station_t *items;
	ncfg_proto_stations_t *report = &out->u.ap_stations;

	if (!ncfg_proto_get_str(dec, object, "interface", 1, what, &report->interface) ||
	    !ncfg_proto_get_str(dec, object, "access_point", 1, what, &report->access_point) ||
	    !ncfg_proto_get_str(dec, object, "access_control", 0, what,
	        &report->access_control)) {
		return 0;
	}
	if (!list_of(dec, object, "stations", 1, what, sizeof(*items), &array, &count, &block)) {
		return 0;
	}
	items = block;
	for (at = 0; at < count; at++) {
		uint32_t entry;
		const char *one = "a station";

		/*
		 * Every field but the address, `authorized` and `listed` is
		 * optional because hostapd omits the whole statistics block when
		 * it cannot read it from the driver. A client that required them
		 * would hide a station that is really there, which is the worst
		 * way for this to be wrong.
		 */
		if (!element(dec, array, at, "`stations`", &entry) ||
		    !ncfg_proto_get_str(dec, entry, "address", 1, one, &items[at].address) ||
		    !ncfg_proto_get_bool(dec, entry, "authorized", 1, 0, one,
		        &items[at].authorized) ||
		    !ncfg_proto_get_bool(dec, entry, "listed", 1, 0, one, &items[at].listed) ||
		    !ncfg_proto_get_int(dec, entry, "signal", 0, one, &items[at].signal) ||
		    !ncfg_proto_get_int(dec, entry, "connected_seconds", 0, one,
		        &items[at].connected_seconds) ||
		    !ncfg_proto_get_int(dec, entry, "inactive_msec", 0, one,
		        &items[at].inactive_msec) ||
		    !ncfg_proto_get_int(dec, entry, "rx_bytes", 0, one, &items[at].rx_bytes) ||
		    !ncfg_proto_get_int(dec, entry, "tx_bytes", 0, one, &items[at].tx_bytes)) {
			return 0;
		}
	}
	report->stations = items;
	report->station_count = count;
	return 1;
}

static int decode_secrets(ncfg_proto_dec_t *dec, uint32_t object, ncfg_proto_response_t *out)
{
	const char *what = "a `secrets` response";
	uint32_t array;
	size_t count;
	size_t at;
	void *block;
	ncfg_proto_secret_t *items;

	if (!list_of(dec, object, "secrets", 1, what, sizeof(*items), &array, &count, &block)) {
		return 0;
	}
	items = block;
	for (at = 0; at < count; at++) {
		uint32_t entry;
		const char *one = "a credential";

		/* Names only: there is no field here that could carry a value,
		 * which is a stronger guarantee than a rule saying not to fill
		 * one in. */
		if (!element(dec, array, at, "`secrets`", &entry) ||
		    !ncfg_proto_get_str(dec, entry, "name", 1, one, &items[at].name) ||
		    !ncfg_proto_get_bool(dec, entry, "stored", 1, 0, one, &items[at].stored) ||
		    !ncfg_proto_get_strs(dec, entry, "used_by", 0, one, &items[at].used_by)) {
			return 0;
		}
	}
	out->u.secrets.items = items;
	out->u.secrets.count = count;
	return 1;
}

static int decode_modems(ncfg_proto_dec_t *dec, uint32_t object, ncfg_proto_response_t *out)
{
	const char *what = "a `modems` response";
	uint32_t array;
	size_t count;
	size_t at;
	void *block;
	ncfg_proto_modem_t *items;

	if (!list_of(dec, object, "modems", 1, what, sizeof(*items), &array, &count, &block)) {
		return 0;
	}
	items = block;
	for (at = 0; at < count; at++) {
		uint32_t entry;
		uint32_t cards;
		size_t card_count;
		size_t card;
		void *card_block;
		ncfg_proto_sim_card_t *card_items;
		const char *one = "a modem";

		if (!element(dec, array, at, "`modems`", &entry) ||
		    !ncfg_proto_get_str(dec, entry, "device", 1, one, &items[at].device) ||
		    !ncfg_proto_get_strs(dec, entry, "sim", 0, one, &items[at].sim) ||
		    !ncfg_proto_get_str(dec, entry, "selected", 0, one, &items[at].selected) ||
		    !ncfg_proto_get_str(dec, entry, "apn", 0, one, &items[at].apn) ||
		    !ncfg_proto_get_bool(dec, entry, "cycle_pending", 0, 0, one,
		        &items[at].cycle_pending)) {
			return 0;
		}
		/* Not one per listed source: a source netcfgd has never been on
		 * has no card here, and that absence is the honest answer rather
		 * than a gap to fill. */
		if (!list_of(dec, entry, "cards", 0, one, sizeof(*card_items), &cards, &card_count,
		        &card_block)) {
			return 0;
		}
		card_items = card_block;
		for (card = 0; card < card_count; card++) {
			uint32_t node;

			if (!element(dec, cards, card, "`cards`", &node) ||
			    !ncfg_proto_get_str(dec, node, "source", 1, "a SIM card",
			        &card_items[card].source) ||
			    !ncfg_proto_get_str(dec, node, "iccid", 1, "a SIM card",
			        &card_items[card].iccid)) {
				return 0;
			}
		}
		items[at].cards = card_items;
		items[at].card_count = card_count;
	}
	out->u.modems.items = items;
	out->u.modems.count = count;
	return 1;
}

static int decode_profiles(ncfg_proto_dec_t *dec, uint32_t object, ncfg_proto_response_t *out)
{
	const char *what = "a `profiles` response";
	uint32_t array;
	size_t count;
	size_t at;
	void *block;
	ncfg_proto_profile_t *items;

	/* Absent stops using one, which is the default state and is not a
	 * profile called "none" -- so null and absent are the same answer here,
	 * and the daemon writes null. */
	if (!ncfg_proto_get_str(dec, object, "chosen", 0, what, &out->u.profiles.chosen)) {
		return 0;
	}
	if (!list_of(dec, object, "profiles", 1, what, sizeof(*items), &array, &count, &block)) {
		return 0;
	}
	items = block;
	for (at = 0; at < count; at++) {
		uint32_t entry;
		const char *one = "a profile";

		if (!element(dec, array, at, "`profiles`", &entry) ||
		    !ncfg_proto_get_str(dec, entry, "name", 1, one, &items[at].name) ||
		    !ncfg_proto_get_bool(dec, entry, "shipped", 1, 0, one, &items[at].shipped)) {
			return 0;
		}
	}
	out->u.profiles.items = items;
	out->u.profiles.count = count;
	return 1;
}

static int decode_configs(ncfg_proto_dec_t *dec, uint32_t object, ncfg_proto_response_t *out)
{
	const char *what = "a `configs` response";
	uint32_t array;
	size_t count;
	size_t at;
	void *block;
	ncfg_proto_config_file_t *items;

	if (!list_of(dec, object, "configs", 1, what, sizeof(*items), &array, &count, &block)) {
		return 0;
	}
	items = block;
	for (at = 0; at < count; at++) {
		uint32_t entry;
		const char *one = "a configuration file";

		/* `name` is absent for `netcfgd.conf` itself, which no request can
		 * write or remove -- so a client showing a name for it would be
		 * offering a verb that does not exist. */
		if (!element(dec, array, at, "`configs`", &entry) ||
		    !ncfg_proto_get_str(dec, entry, "name", 0, one, &items[at].name) ||
		    !ncfg_proto_get_str(dec, entry, "file", 1, one, &items[at].file) ||
		    !ncfg_proto_get_bool(dec, entry, "removable", 1, 0, one,
		        &items[at].removable) ||
		    !ncfg_proto_get_str(dec, entry, "text", 1, one, &items[at].text)) {
			return 0;
		}
	}
	out->u.configs.items = items;
	out->u.configs.count = count;
	return 1;
}

static int decode_hooks(ncfg_proto_dec_t *dec, uint32_t object, ncfg_proto_response_t *out)
{
	const char *what = "a `hooks` response";
	uint32_t array;
	size_t count;
	size_t at;
	void *block;
	ncfg_proto_hook_t *items;

	if (!list_of(dec, object, "hooks", 1, what, sizeof(*items), &array, &count, &block)) {
		return 0;
	}
	items = block;
	for (at = 0; at < count; at++) {
		uint32_t entry;
		const char *one = "a hook";

		/* `text` is defaulted rather than required, because it is empty
		 * where `readable` is false -- which is not the same as a hook
		 * with nothing in it, and is a fact a client must not round-trip.
		 */
		if (!element(dec, array, at, "`hooks`", &entry) ||
		    !ncfg_proto_get_str(dec, entry, "interface", 1, one, &items[at].interface) ||
		    !ncfg_proto_get_str(dec, entry, "phase", 1, one, &items[at].phase) ||
		    !ncfg_proto_get_str(dec, entry, "path", 1, one, &items[at].path) ||
		    !ncfg_proto_get_str(dec, entry, "text", 0, one, &items[at].text) ||
		    !ncfg_proto_get_bool(dec, entry, "readable", 1, 0, one, &items[at].readable)) {
			return 0;
		}
	}
	out->u.hooks.items = items;
	out->u.hooks.count = count;
	return 1;
}

static int decode_probes(ncfg_proto_dec_t *dec, uint32_t object, ncfg_proto_response_t *out)
{
	const char *what = "a `probes` response";
	uint32_t array;
	size_t count;
	size_t at;
	void *block;
	ncfg_proto_probe_t *items;

	if (!list_of(dec, object, "probes", 1, what, sizeof(*items), &array, &count, &block)) {
		return 0;
	}
	items = block;
	for (at = 0; at < count; at++) {
		uint32_t entry;
		const char *one = "a probe script";

		if (!element(dec, array, at, "`probes`", &entry) ||
		    !ncfg_proto_get_str(dec, entry, "name", 1, one, &items[at].name) ||
		    !ncfg_proto_get_str(dec, entry, "directory", 1, one, &items[at].directory) ||
		    !ncfg_proto_get_str(dec, entry, "text", 1, one, &items[at].text) ||
		    !ncfg_proto_get_bool(dec, entry, "editable", 1, 0, one, &items[at].editable)) {
			return 0;
		}
	}
	out->u.probes.items = items;
	out->u.probes.count = count;
	return 1;
}

static int decode_radios(ncfg_proto_dec_t *dec, uint32_t object, ncfg_proto_response_t *out)
{
	const char *what = "a `radios` response";
	uint32_t array;
	size_t count;
	size_t at;
	void *block;
	ncfg_proto_radio_t *items;

	if (!list_of(dec, object, "radios", 1, what, sizeof(*items), &array, &count, &block)) {
		return 0;
	}
	items = block;
	for (at = 0; at < count; at++) {
		uint32_t entry;
		const char *one = "a radio";

		/* Every wireless interface the kernel reports, managed or not:
		 * the list exists so that somebody can turn one on, and a list of
		 * only the ones already on could not offer that. */
		if (!element(dec, array, at, "`radios`", &entry) ||
		    !ncfg_proto_get_str(dec, entry, "interface", 1, one, &items[at].interface) ||
		    !ncfg_proto_get_bool(dec, entry, "activated", 1, 0, one,
		        &items[at].activated) ||
		    !ncfg_proto_get_bool(dec, entry, "supplicant", 1, 0, one,
		        &items[at].supplicant)) {
			return 0;
		}
	}
	out->u.radios.items = items;
	out->u.radios.count = count;
	return 1;
}

int ncfg_proto_decode_response(ncfg_proto_dec_t *dec, uint32_t object, ncfg_proto_response_t *out)
{
	ncfg_proto_str_t tag;
	int at;

	memset(out, 0, sizeof(*out));
	if (!ncfg_proto_get_str(dec, object, "response", 1, "this response", &tag)) {
		return 0;
	}
	for (at = 0; at < NCFG_PROTO_RESP_COUNT; at++) {
		if (ncfg_proto_str_equals(tag, response_names[at])) {
			break;
		}
	}
	if (at == NCFG_PROTO_RESP_COUNT) {
		/*
		 * The leniency in this direction is about members, not about the
		 * tag, and the Rust draws the line in the same place. A message
		 * whose kind is unknown is one a client cannot act on; guessing
		 * which arm it belongs to is how a client renders the wrong
		 * thing, which is worse than saying it does not know.
		 */
		return ncfg_proto_fail(dec, "`%.*s` is not a response this speaks",
		    (int)tag.length, tag.bytes);
	}
	out->kind = (ncfg_proto_response_kind_t)at;
	switch (out->kind) {
	case NCFG_PROTO_RESP_HELLO:
		return decode_hello(dec, object, out);
	case NCFG_PROTO_RESP_STATUS:
	case NCFG_PROTO_RESP_PLAN:
	case NCFG_PROTO_RESP_DOCUMENT:
	case NCFG_PROTO_RESP_JOURNAL:
		/*
		 * Named here, owned elsewhere. These carry `netcfgd_model`'s,
		 * `netcfgd_plan`'s and `netcfgd_apply`'s own types -- the Rust
		 * writes them `Response::Status(Box<Observed>)`, where proto names
		 * the arm and another crate owns the contents. Those modules are
		 * not in the port yet, so the parsed object is handed over whole:
		 * nothing is lost and nothing is guessed, and when they land the
		 * payload becomes their argument rather than something this module
		 * has to be taught.
		 */
		out->u.payload.doc = dec->doc;
		out->u.payload.object = object;
		return 1;
	case NCFG_PROTO_RESP_EXPLANATION:
		return decode_explanation(dec, object, out);
	case NCFG_PROTO_RESP_EVENT:
		/* The payload is flattened beside the wrapper's tag, so the same
		 * decoder reads it here and on a bare event line. */
		return ncfg_proto_decode_event(dec, object, &out->u.event);
	case NCFG_PROTO_RESP_WIFI_SCAN:
		return decode_scan(dec, object, out);
	case NCFG_PROTO_RESP_SECRETS:
		return decode_secrets(dec, object, out);
	case NCFG_PROTO_RESP_MODEMS:
		return decode_modems(dec, object, out);
	case NCFG_PROTO_RESP_PROFILES:
		return decode_profiles(dec, object, out);
	case NCFG_PROTO_RESP_CONFIGS:
		return decode_configs(dec, object, out);
	case NCFG_PROTO_RESP_HOOKS:
		return decode_hooks(dec, object, out);
	case NCFG_PROTO_RESP_PROBES:
		return decode_probes(dec, object, out);
	case NCFG_PROTO_RESP_RADIOS:
		return decode_radios(dec, object, out);
	case NCFG_PROTO_RESP_WIFI_STATUS:
		return decode_wifi_status(dec, object, out);
	case NCFG_PROTO_RESP_AP_STATIONS:
		return decode_stations(dec, object, out);
	case NCFG_PROTO_RESP_OK:
		/* Succeeded and had nothing to return. */
		return 1;
	case NCFG_PROTO_RESP_ERROR:
	default:
		/* **A refusal is an answer**: the daemon replied, which is a
		 * different thing from not reaching it, and only the caller knows
		 * whether it is fatal. The sentence is the daemon's and names the
		 * tier that would have been needed. */
		return ncfg_proto_get_str(dec, object, "message", 1, "an `error` response",
		    &out->u.error.message);
	}
}
