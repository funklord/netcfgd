/*
 * session.c -- what netcfgd asks a running supplicant to do.
 *
 * The three verbs above the socket: read what it is on, empty it, and fill it
 * from the document. Everything that carries a credential is here, which is
 * why this file and not `client.c` is where the redaction rule lives.
 *
 * NOTHING IS SENT UNTIL EVERYTHING RESOLVES
 *   A network whose access points are out of range, or whose passphrase will
 *   not resolve, leaves nothing half-configured behind: the name is read off
 *   the last scan and every setting is rendered before `ADD_NETWORK` is sent.
 *   Where a setting is refused anyway the network is removed before the
 *   failure is reported -- a half-configured network is worse than none,
 *   because it sits in the supplicant's list looking like something netcfgd
 *   put there on purpose.
 */
#include "ncfg/supplicant.h"

#include "supplicant_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int ncfg_supplicant_answers(const char *dir, const char *interface)
{
	char                      message[NCFG_ERROR_MAX];
	ncfg_supplicant_client_t *client = ncfg_supplicant_connect_within(dir, interface,
	    NCFG_SUPPLICANT_IMPATIENT_MS, message, sizeof(message));

	/* **A question about the process, not about wifi.** A supplicant that has
	 * bound its socket and stopped answering looks, from every other angle
	 * netcfgd has, exactly like one that is working and has not associated
	 * yet -- so the answer is whether it completed a `PING`, which is what the
	 * connect does. */
	if (!client) {
		return 0;
	}
	ncfg_supplicant_client_free(client);
	return 1;
}

/* `STATUS`, parsed, for the three readers below. */
static int read_status(ncfg_supplicant_client_t *client, ncfg_supplicant_status_pair_t **out,
    size_t *count_out, char *err, size_t err_size)
{
	char body[NCFG_SUPPLICANT_REPLY_MAX];

	if (!ncfg_supplicant_ask(client, "STATUS", body, sizeof(body), err, err_size)) {
		return 0;
	}
	return ncfg_supplicant_parse_status(body, out, count_out, err, err_size);
}

/*
 * `key_mgmt=` as a security kind. See `supplicant.h` for what it is for.
 *
 * **Matched by what the string contains**, because a station negotiating more
 * than one reports them joined by `+` -- `WPA2-PSK+WPA-PSK` -- and because the
 * suffixes multiply: `WPA2-PSK-SHA256`, `FT-PSK`, `FT-EAP`. Asking for
 * equality would answer "unstated" for the ordinary case.
 *
 * The order is the one that cannot be fooled by a substring of another: `OWE`
 * and `SAE` are their own words, `EAP` and `IEEE8021X` name the enterprise
 * kinds, `PSK` the personal one, and `NONE` is what an open network reports.
 */
int ncfg_supplicant_key_mgmt_security(const char *key_mgmt)
{
	if (!key_mgmt || key_mgmt[0] == '\0') {
		return NCFG_WIFI_SECURITY_UNSTATED;
	}
	if (strstr(key_mgmt, "OWE")) {
		return NCFG_SECURITY_OWE;
	}
	if (strstr(key_mgmt, "EAP") || strstr(key_mgmt, "IEEE8021X")) {
		return NCFG_SECURITY_EAP;
	}
	if (strstr(key_mgmt, "PSK") || strstr(key_mgmt, "SAE")) {
		return NCFG_SECURITY_PSK;
	}
	if (strcmp(key_mgmt, "NONE") == 0) {
		return NCFG_SECURITY_OPEN;
	}
	/* Something this build does not know. Not a guess: `network_for` asked
	 * without an answer behaves exactly as it did before this existed. */
	return NCFG_WIFI_SECURITY_UNSTATED;
}

int ncfg_supplicant_associated(ncfg_supplicant_client_t *client, ncfg_ssid_t *ssid_out,
    char *bssid, size_t bssid_size, char *key_mgmt, size_t key_mgmt_size)
{
	char                           message[NCFG_ERROR_MAX];
	ncfg_supplicant_status_pair_t *status = NULL;
	size_t                         count = 0;
	const char                    *name;
	const char                    *address;
	size_t                         length;
	int                            answered = 0;

	if (bssid && bssid_size) {
		bssid[0] = '\0';
	}
	if (key_mgmt && key_mgmt_size) {
		key_mgmt[0] = '\0';
	}
	if (!client || !ssid_out) {
		return 0;
	}
	if (!read_status(client, &status, &count, message, sizeof(message))) {
		return 0;
	}
	name = ncfg_supplicant_status_field(status, count, "ssid");
	if (name) {
		/* The supplicant reports the name here already decoded from its own
		 * hex, but escaped the same way as everywhere else -- so a network
		 * called `caf<e-acute>` arrives as `caf\xc3\xa9` and a reader that
		 * took the field literally would show that to the operator. */
		length = ncfg_supplicant_printf_decode(name, ssid_out->bytes,
		    sizeof(ssid_out->bytes));
		if (length <= sizeof(ssid_out->bytes)) {
			ssid_out->has = 1;
			ssid_out->length = length;
			answered = 1;
		}
	}
	address = ncfg_supplicant_status_field(status, count, "bssid");
	if (answered && bssid && bssid_size) {
		/* Empty rather than absent where `STATUS` carried none: both halves
		 * come back because resolving an association to a configured network
		 * needs both -- a network that lists BSSIDs instead of an SSID is
		 * identified by the second. */
		(void)snprintf(bssid, bssid_size, "%s", address ? address : "");
	}
	if (answered && key_mgmt && key_mgmt_size) {
		/* The third half, and it comes from this round trip rather than a
		 * second: two `network` blocks may share an SSID and pin no address,
		 * and what separates them is what the radio is actually using. */
		const char *how = ncfg_supplicant_status_field(status, count, "key_mgmt");

		(void)snprintf(key_mgmt, key_mgmt_size, "%s", how ? how : "");
	}
	ncfg_supplicant_status_free(status, count);
	return answered;
}

int ncfg_supplicant_state(ncfg_supplicant_client_t *client, char *out, size_t out_size,
    char *err, size_t err_size)
{
	ncfg_supplicant_status_pair_t *status = NULL;
	size_t                         count = 0;
	const char                    *state;

	if (!out || out_size == 0u) {
		ncfg_error_set(err, err_size, "a state needs somewhere to be put");
		return 0;
	}
	out[0] = '\0';
	if (!read_status(client, &status, &count, err, err_size)) {
		return 0;
	}
	state = ncfg_supplicant_status_field(status, count, "wpa_state");
	/* `UNKNOWN` rather than an absence: every client renders this, and a
	 * caller handed nothing would have to decide what that means. */
	(void)snprintf(out, out_size, "%s", state ? state : "UNKNOWN");
	ncfg_supplicant_status_free(status, count);
	return 1;
}

int ncfg_supplicant_clear_networks(ncfg_supplicant_client_t *client, char *err, size_t err_size)
{
	/* Decision 0015: called before adding anything, so a supplicant started
	 * by something else -- or one that survived a netcfgd crash -- does not
	 * contribute networks the document cannot account for. */
	return ncfg_supplicant_command(client, "REMOVE_NETWORK all", err, err_size);
}

/* `ADD_NETWORK`'s answer, which is a slot number and nothing else. */
static int new_network_id(ncfg_supplicant_client_t *client, uint32_t *out, char *err,
    size_t err_size)
{
	char     body[NCFG_SUPPLICANT_REPLY_MAX];
	size_t   index = 0;
	size_t   length;
	uint64_t value = 0;
	int      digits = 0;

	if (!ncfg_supplicant_ask(client, "ADD_NETWORK", body, sizeof(body), err, err_size)) {
		return 0;
	}
	length = strlen(body);
	while (index < length && (body[index] == ' ' || body[index] == '\t')) {
		index++;
	}
	for (; index < length; index++) {
		if (body[index] < '0' || body[index] > '9') {
			break;
		}
		value = value * 10u + (uint64_t)(body[index] - '0');
		digits++;
		if (value > UINT32_MAX) {
			digits = 0;
			break;
		}
	}
	while (index < length && (body[index] == ' ' || body[index] == '\t')) {
		index++;
	}
	if (!digits || index != length) {
		ncfg_error_set(err, err_size, "ADD_NETWORK did not answer with a network id");
		return 0;
	}
	*out = (uint32_t)value;
	return 1;
}

/*
 * Send one setting, and never quote what it carried.
 *
 * The line exists for as long as the `send` takes and is wiped after it. What
 * any message says is the redacted form, which is built first precisely so
 * that the failure path has something safe to hand out without reaching for
 * the line it is reporting on.
 */
static int send_setting(ncfg_supplicant_client_t *client, const ncfg_supplicant_setting_t *setting,
    uint32_t id, const ncfg_secret_resolver_t *resolver, char *err, size_t err_size)
{
	ncfg_buf_t line;
	ncfg_buf_t shown;
	char       body[NCFG_SUPPLICANT_REPLY_MAX];
	char       refusal[NCFG_ERROR_MAX];
	int        kind = NCFG_SUPPLICANT_REPLY_FAIL;
	int        sent;

	ncfg_buf_init(&shown, 0);
	ncfg_supplicant_setting_redacted(setting, id, &shown);
	if (ncfg_buf_failed(&shown)) {
		ncfg_buf_free(&shown);
		ncfg_error_set(err, err_size, "the `%s` setting is longer than one command may be",
		    setting->variable);
		return 0;
	}
	ncfg_buf_init(&line, 0);
	if (!ncfg_supplicant_setting_command(setting, id, resolver, &line, refusal,
	    sizeof(refusal))) {
		ncfg_supplicant_buf_wipe(&line);
		ncfg_error_set(err, err_size, "%s could not be built: %s", ncfg_buf_text(&shown),
		    refusal);
		ncfg_buf_free(&shown);
		return 0;
	}
	sent = ncfg_supplicant_request_labelled(client, ncfg_buf_text(&line),
	    ncfg_buf_text(&shown), body, sizeof(body), &kind, refusal, sizeof(refusal));
	/* **Before anything else happens with the outcome.** The line held the
	 * credential and its job is done; holding it across the error formatting
	 * below is exactly the window this design exists to close. */
	ncfg_supplicant_buf_wipe(&line);
	if (!sent) {
		ncfg_error_set(err, err_size, "%s was refused: %s", ncfg_buf_text(&shown), refusal);
		ncfg_buf_free(&shown);
		return 0;
	}
	if (kind != NCFG_SUPPLICANT_REPLY_OK) {
		ncfg_error_set(err, err_size, "%s was refused: the supplicant answered %s",
		    ncfg_buf_text(&shown),
		    kind == NCFG_SUPPLICANT_REPLY_FAIL ? "FAIL" : body);
		ncfg_buf_free(&shown);
		return 0;
	}
	ncfg_buf_free(&shown);
	return 1;
}

/* Hand a whole rendered network over, removing it again if anything is
 * refused. */
static int populate(ncfg_supplicant_client_t *client, const ncfg_supplicant_settings_t *settings,
    const ncfg_secret_resolver_t *resolver, uint32_t *id_out, char *err, size_t err_size)
{
	uint32_t id = 0;
	size_t   index;

	if (!new_network_id(client, &id, err, err_size)) {
		return 0;
	}
	for (index = 0; index < settings->count; index++) {
		if (!send_setting(client, &settings->items[index], id, resolver, err, err_size)) {
			char away[64];
			char ignored[NCFG_ERROR_MAX];

			/* **The half-configured network is worse than none**: it would
			 * sit in the supplicant's list looking like something netcfgd put
			 * there on purpose. Removed before the failure is reported, and
			 * the removal's own outcome is not allowed to replace the message
			 * that says what actually went wrong. */
			(void)snprintf(away, sizeof(away), "REMOVE_NETWORK %lu", (unsigned long)id);
			(void)ncfg_supplicant_command(client, away, ignored, sizeof(ignored));
			return 0;
		}
	}
	*id_out = id;
	return 1;
}

int ncfg_supplicant_add_network(ncfg_supplicant_client_t *client,
    const ncfg_wifi_network_t *network, int mac_policy, const ncfg_secret_resolver_t *resolver,
    uint32_t *id_out, char *err, size_t err_size)
{
	ncfg_supplicant_settings_t settings;
	ncfg_ssid_t                learned;
	const ncfg_ssid_t         *resolved = NULL;
	uint32_t                   id = 0;
	char                       enable[64];

	if (!client || !network || !id_out) {
		ncfg_error_set(err, err_size, "a network needs a supplicant to be given to");
		return 0;
	}
	memset(&learned, 0, sizeof(learned));
	if (!network->ssid.has) {
		/*
		 * **Read from the last scan, and no `SCAN` is issued.** A scan takes
		 * seconds, interrupts traffic on the radio, and this runs inside an
		 * apply. If the access point is not in the last results the honest
		 * answer is that netcfgd cannot see it -- with its address in the
		 * message, because "network not found" about a network named by
		 * address is not a sentence anybody can act on.
		 */
		char                    body[NCFG_SUPPLICANT_REPLY_MAX];
		ncfg_supplicant_scan_t *seen = NULL;
		size_t                  seen_count = 0;
		int                     picked;

		if (!ncfg_supplicant_ask(client, "SCAN_RESULTS", body, sizeof(body), err,
		    err_size)) {
			return 0;
		}
		if (!ncfg_supplicant_parse_scan_results(body, &seen, &seen_count, err, err_size)) {
			return 0;
		}
		picked = ncfg_supplicant_pick_ssid(network, seen, seen_count, &learned, err,
		    err_size);
		ncfg_supplicant_scans_free(seen, seen_count);
		if (!picked) {
			return 0;
		}
		resolved = &learned;
	}
	/* Rendered before anything is sent, so a network that cannot be expressed
	 * leaves nothing behind in the supplicant. */
	if (!ncfg_supplicant_settings(network, resolved, mac_policy, resolver, &settings, err,
	    err_size)) {
		return 0;
	}
	if (!populate(client, &settings, resolver, &id, err, err_size)) {
		ncfg_supplicant_settings_free(&settings);
		return 0;
	}
	ncfg_supplicant_settings_free(&settings);

	/* **Present but not joined** where the document says so: `ncfg wifi up`
	 * selects it later, and a network left enabled would be joined the moment
	 * it came in range, which is not what `autoconnect = false` asks for. */
	(void)snprintf(enable, sizeof(enable), "%s %lu",
	    network->autoconnect ? "ENABLE_NETWORK" : "DISABLE_NETWORK", (unsigned long)id);
	if (!ncfg_supplicant_command(client, enable, err, err_size)) {
		return 0;
	}
	*id_out = id;
	return 1;
}

int ncfg_supplicant_configure_wired(ncfg_supplicant_client_t *client,
    const ncfg_eap_config_t *eap, const ncfg_secret_resolver_t *resolver, uint32_t *id_out,
    char *err, size_t err_size)
{
	ncfg_supplicant_settings_t settings;
	uint32_t                   id = 0;
	char                       enable[64];

	if (!client || !eap || !id_out) {
		ncfg_error_set(err, err_size, "a wired 802.1X port needs a supplicant and a config");
		return 0;
	}
	/* **Cleared first.** A wired supplicant has exactly one thing to
	 * authenticate with: the port cannot be "on" two profiles, and leaving a
	 * stale one would let the supplicant fall back to it. */
	if (!ncfg_supplicant_clear_networks(client, err, err_size)) {
		return 0;
	}
	if (!ncfg_supplicant_wired_settings(eap, resolver, &settings, err, err_size)) {
		return 0;
	}
	if (!populate(client, &settings, resolver, &id, err, err_size)) {
		ncfg_supplicant_settings_free(&settings);
		return 0;
	}
	ncfg_supplicant_settings_free(&settings);
	(void)snprintf(enable, sizeof(enable), "ENABLE_NETWORK %lu", (unsigned long)id);
	if (!ncfg_supplicant_command(client, enable, err, err_size)) {
		return 0;
	}
	*id_out = id;
	return 1;
}
