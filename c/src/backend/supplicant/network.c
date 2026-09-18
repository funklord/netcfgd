/*
 * network.c -- a network from the document, as control-socket commands.
 *
 * Decision 0015: `wpa_supplicant` holds no state, so every network it knows
 * about arrives this way. This file is the translation, and it is pure -- it
 * produces the command list without a socket in sight, which is what makes
 * "does netcfgd configure WPA3 correctly?" a question a test can answer on a
 * machine with no radio.
 *
 * THE CREDENTIAL IS NOT IN THE LIST
 *   A sensitive setting carries the `ncfg_secret_ref_t` the document gave and
 *   nothing else. It is resolved twice and held neither time: once here, to
 *   answer "can this network be expressed at all" before anything is sent, and
 *   once by `ncfg_supplicant_setting_command` at the instant the line is
 *   built. See `supplicant.h` for why that is worth an extra read of the
 *   store.
 */
#include "ncfg/supplicant.h"

#include "ncfg/hooks.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * A random address that is never reused: a fresh one on every association.
 */
#define RAND_ADDR_LIFETIME_FRESH "0"

/* The supplicant's own default, stated rather than inherited. */
#define RAND_ADDR_LIFETIME_KEEP "60"

/*
 * The highest rank a derived join order takes, for a metric of 0.
 *
 * `netcfgd_model::wifi::RANK_CEILING`, which is above any metric worth writing
 * and small enough to scale into a narrower range without the arithmetic
 * needing care.
 */
#define RANK_CEILING 4096

/*
 * The SSID a network named by its access points is fingerprinted against.
 *
 * Never sent to anything: `add_network` resolves the real name from a scan on
 * its own. This exists so that the rest of such a network still reaches the
 * digest, and it is a constant rather than anything derived so that two passes
 * agree.
 */
static const unsigned char UNRESOLVED[] = "netcfgd:ssid-from-scan";

/* The `psk` field's range, which is the field's and **not WPA's**: a network
 * sent as `sae_password` has no such limit (0205). Octets, because that is what
 * the supplicant counts (0229). */
#define PASSPHRASE_MIN 8u
#define PASSPHRASE_MAX 63u

/* ---------------------------------------------------------- the list itself */

void ncfg_supplicant_settings_free(ncfg_supplicant_settings_t *settings)
{
	size_t index;

	if (!settings || !settings->items) {
		if (settings) {
			settings->items = NULL;
			settings->count = 0;
		}
		return;
	}
	for (index = 0; index < settings->count; index++) {
		free(settings->items[index].variable);
		free(settings->items[index].value);
	}
	free(settings->items);
	settings->items = NULL;
	settings->count = 0;
}

static ncfg_supplicant_setting_t *reserve(ncfg_supplicant_settings_t *out)
{
	ncfg_supplicant_setting_t *bigger;

	/* One at a time: a network renders a dozen settings and a doubling
	 * strategy for twelve items is arithmetic nobody needs to check. */
	bigger = realloc(out->items, (out->count + 1u) * sizeof(*out->items));
	if (!bigger) {
		return NULL;
	}
	out->items = bigger;
	memset(&out->items[out->count], 0, sizeof(*out->items));
	return &out->items[out->count++];
}

static int add_setting(ncfg_supplicant_settings_t *out, const char *variable, char *value,
    const ncfg_secret_ref_t *secret, int sensitive, char *err, size_t err_size)
{
	ncfg_supplicant_setting_t *one = reserve(out);

	if (!one) {
		free(value);
		ncfg_error_set(err, err_size, "no memory for the `%s` setting", variable);
		return 0;
	}
	one->variable = strdup(variable);
	one->value = value;
	one->secret = secret;
	one->sensitive = sensitive;
	if (!one->variable) {
		ncfg_error_set(err, err_size, "no memory for the `%s` setting", variable);
		return 0;
	}
	return 1;
}

static int add_plain(ncfg_supplicant_settings_t *out, const char *variable, const char *value,
    char *err, size_t err_size)
{
	char *held = strdup(value);

	if (!held) {
		ncfg_error_set(err, err_size, "no memory for the `%s` setting", variable);
		return 0;
	}
	return add_setting(out, variable, held, NULL, 0, err, err_size);
}

/* A value that reaches the command line quoted: an identity, a path, a
 * `phase2` string. `sensitive` separates an EAP identity -- a username, and
 * half of a credential -- from a certificate path, which is not one. */
static int add_quoted(ncfg_supplicant_settings_t *out, const char *variable, const char *value,
    int sensitive, char *err, size_t err_size)
{
	ncfg_buf_t rendered;
	char      *held;

	ncfg_buf_init(&rendered, 0);
	ncfg_supplicant_quote(&rendered, value);
	if (ncfg_buf_failed(&rendered)) {
		ncfg_buf_free(&rendered);
		ncfg_error_set(err, err_size, "the `%s` value is longer than one command may be",
		    variable);
		return 0;
	}
	held = ncfg_buf_take(&rendered, NULL);
	ncfg_buf_free(&rendered);
	if (!held) {
		ncfg_error_set(err, err_size, "no memory for the `%s` setting", variable);
		return 0;
	}
	return add_setting(out, variable, held, NULL, sensitive, err, err_size);
}

/* The credential, by reference. `value` stays NULL, which is the invariant
 * `supplicant.h` states and the whole of what keeps a passphrase out of this
 * list. */
static int add_secret(ncfg_supplicant_settings_t *out, const char *variable,
    const ncfg_secret_ref_t *secret, char *err, size_t err_size)
{
	return add_setting(out, variable, NULL, secret, 1, err, err_size);
}

/* ------------------------------------------------------------- the policies */

const char *ncfg_supplicant_mac_addr_value(int mac_policy)
{
	switch (mac_policy) {
	case NCFG_MAC_POLICY_PERMANENT:
		return "0";
	case NCFG_MAC_POLICY_PER_NETWORK:
	case NCFG_MAC_POLICY_PER_CONNECTION:
	default:
		/* **Not 2 for `per_connection`, which is what this sent until
		 * 0230.** `wpa_supplicant.conf` documents 2 as "like 1, but maintain
		 * OUI (with local admin bit set)" -- so for the policy netcfgd
		 * documents as the strongest it was sending the one value that keeps
		 * the part of the address saying who made the radio. */
		return "1";
	}
}

const char *ncfg_supplicant_rand_addr_lifetime_value(int mac_policy)
{
	/* The half the per-network key cannot express: both randomising policies
	 * are `mac_addr 1`, and what separates "a fresh address per network" from
	 * "a fresh address every time" is whether the previous one is still in
	 * date when the radio rejoins. */
	if (mac_policy == NCFG_MAC_POLICY_PER_CONNECTION) {
		return RAND_ADDR_LIFETIME_FRESH;
	}
	return RAND_ADDR_LIFETIME_KEEP;
}

/*
 * Whether a string is six colon-separated hex octets.
 *
 * A BSSID reaches the command line unquoted, so this is the same injection
 * surface as an SSID with a narrower answer available: the set of valid values
 * is small enough to check exactly.
 */
static int is_bssid(const char *text)
{
	size_t index;

	if (!text || strlen(text) != 17u) {
		return 0;
	}
	for (index = 0; index < 17u; index++) {
		char one = text[index];

		if (index % 3u == 2u) {
			if (one != ':') {
				return 0;
			}
			continue;
		}
		if (!((one >= '0' && one <= '9') || (one >= 'a' && one <= 'f') ||
		    (one >= 'A' && one <= 'F'))) {
			return 0;
		}
	}
	return 1;
}

/*
 * The join priority a metric becomes.
 *
 * **The inversion, and it is the whole risk in 0154.** A metric counts up and
 * a join rank counts down, so the better route metric has to come out the
 * larger priority -- and getting it backwards is silent, because the machine
 * still joins a network and still comes up. It just prefers the wrong one.
 *
 * Subtracting from a ceiling rather than negating is what makes an absurd
 * metric rank last instead of first.
 */
static int64_t join_rank(int64_t metric)
{
	if (metric <= 0) {
		return RANK_CEILING;
	}
	if (metric >= RANK_CEILING) {
		return 0;
	}
	return RANK_CEILING - metric;
}

/* -------------------------------------------------------------- the security */

static const char *eap_name(int method)
{
	switch (method) {
	case NCFG_EAP_METHOD_PEAP:
		return "PEAP";
	case NCFG_EAP_METHOD_TTLS:
		return "TTLS";
	case NCFG_EAP_METHOD_TLS:
		return "TLS";
	case NCFG_EAP_METHOD_PWD:
	default:
		return "PWD";
	}
}

/*
 * Resolve a credential, check it can be sent at all, and drop it again.
 *
 * The value never leaves this function. What the caller gets is the answer to
 * "is this network expressible", which is the question that has to be settled
 * before anything reaches the socket.
 */
static int credential_is_usable(const ncfg_secret_resolver_t *resolver,
    const ncfg_secret_ref_t *reference, int check_length, char *err, size_t err_size)
{
	ncfg_secret_t *secret = ncfg_secret_resolve(resolver, reference, NULL, err, err_size);
	const char    *text;
	size_t         length;
	int            usable = 1;

	if (!secret) {
		return 0;
	}
	text = ncfg_secret_expose(secret);
	length = ncfg_secret_length(secret);
	/* A NUL inside would end the command where the store did not. `strlen`
	 * disagreeing with the stored length is the only way to see one from
	 * here, and it is the same refusal a newline gets. */
	if (length != strlen(text) || !ncfg_supplicant_passphrase_is_sendable(text)) {
		ncfg_error_set(err, err_size,
		    "the passphrase contains a newline or NUL, which the control protocol "
		    "cannot carry");
		usable = 0;
	} else if (check_length && (length < PASSPHRASE_MIN || length > PASSPHRASE_MAX)) {
		/* Checked here rather than left to the supplicant because `FAIL` with
		 * no detail is what it answers otherwise, and a passphrase with a
		 * stray space is a common enough mistake to deserve a real message.
		 * **The length is safe to report; the value is not.** */
		ncfg_error_set(err, err_size,
		    "a WPA2 passphrase is 8 to 63 octets and this one is %zu -- a character "
		    "outside ASCII counts as more than one, which is how the supplicant counts "
		    "it. That is what the `psk` field accepts; WPA3 on its own has no such "
		    "limit, so `proto = \"wpa3\"` would take it",
		    length);
		usable = 0;
	}
	ncfg_secret_free(secret);
	return usable;
}

/*
 * The settings for a pre-shared-key network.
 *
 * WHY THE `FT-` VARIANTS ARE NAMED ALONGSIDE THE BASE ONES
 *   `key_mgmt` is a list of key management modes netcfgd is **willing** to
 *   use, not one it demands. The supplicant intersects the list with what the
 *   access point advertises and picks from what is left, so naming `FT-PSK`
 *   beside `WPA-PSK` costs nothing against a BSS that does no fast transition.
 *   Omitting it costs something real against a BSS that does: 802.11r is
 *   negotiated at association, so a supplicant that never offered it cannot
 *   fast-transition later, and every roam within one mobility domain is a full
 *   reauthentication -- on an enterprise network, a fresh EAP conversation
 *   with the authentication server per roam.
 *
 *   **Fast transition over SAE requires protected management frames**, which
 *   is the one place this could have gone wrong. It does not: the arm naming
 *   `FT-SAE` alone already sets `ieee80211w=2`, and the transitional arm names
 *   it beside plain `SAE` under `ieee80211w=1`, where an access point offering
 *   SAE at all requires the protection.
 */
static int psk_settings(const ncfg_psk_config_t *psk, const ncfg_secret_resolver_t *resolver,
    ncfg_supplicant_settings_t *out, char *err, size_t err_size)
{
	int wpa3 = psk->proto == NCFG_PSK_PROTO_WPA3;

	if (!credential_is_usable(resolver, &psk->passphrase, !wpa3, err, err_size)) {
		return 0;
	}
	/* **The field differs with the generation.** SAE alone takes
	 * `sae_password`; anything that can still negotiate WPA2 needs `psk`,
	 * because that is the field the WPA2 half reads -- and in transitional
	 * mode the access point chooses, so both halves work from one value. This
	 * sent every passphrase in `psk`, so a WPA3 network with a longer password
	 * could not be joined and was told a rule SAE does not have (0205). */
	if (!add_secret(out, wpa3 ? "sae_password" : "psk", &psk->passphrase, err, err_size)) {
		return 0;
	}
	switch (psk->proto) {
	case NCFG_PSK_PROTO_WPA2:
		return add_plain(out, "key_mgmt", "WPA-PSK FT-PSK", err, err_size) &&
		    add_plain(out, "proto", "RSN", err, err_size) &&
		    add_plain(out, "ieee80211w", "1", err, err_size);
	case NCFG_PSK_PROTO_WPA3:
		/* SAE only, with management frame protection required -- WPA3
		 * personal is not WPA3 without it. */
		return add_plain(out, "key_mgmt", "SAE FT-SAE", err, err_size) &&
		    add_plain(out, "proto", "RSN", err, err_size) &&
		    add_plain(out, "ieee80211w", "2", err, err_size);
	case NCFG_PSK_PROTO_WPA2_WPA3:
	default:
		/* Transitional: offer both and let the access point choose.
		 * `ieee80211w=1` is the only value that works against both, since 2
		 * excludes WPA2 access points and 0 excludes SAE. */
		return add_plain(out, "key_mgmt", "WPA-PSK SAE FT-PSK FT-SAE", err, err_size) &&
		    add_plain(out, "proto", "RSN", err, err_size) &&
		    add_plain(out, "ieee80211w", "1", err, err_size);
	}
}

/* A certificate or key as the path `wpa_supplicant` will open. */
static int add_certificate(ncfg_supplicant_settings_t *out, const char *variable,
    const ncfg_cert_source_t *source, const char *role, const ncfg_secret_resolver_t *resolver,
    char *err, size_t err_size)
{
	char *path = ncfg_secret_path_for(resolver, source, role, NULL, err, err_size);
	int   added;

	if (!path) {
		return 0;
	}
	added = add_quoted(out, variable, path, 0, err, err_size);
	free(path);
	return added;
}

static int eap_settings(const ncfg_eap_config_t *eap, const ncfg_secret_resolver_t *resolver,
    ncfg_supplicant_settings_t *out, char *err, size_t err_size)
{
	if (!add_plain(out, "key_mgmt", "WPA-EAP FT-EAP", err, err_size) ||
	    !add_plain(out, "eap", eap_name(eap->method), err, err_size) ||
	    !add_quoted(out, "identity", eap->identity ? eap->identity : "", 1, err, err_size)) {
		return 0;
	}
	if (eap->anonymous_identity &&
	    !add_quoted(out, "anonymous_identity", eap->anonymous_identity, 0, err, err_size)) {
		return 0;
	}
	/*
	 * **No `ca_cert` line at all where nothing is pinned, and this was the
	 * wifi fault the whole project was opened for.**
	 *
	 * This used to send `ca_cert=""`. wpa_supplicant reads that as a
	 * *filename* -- every one of these is a path it opens -- so it tried to
	 * open a file whose name is the empty string, OpenSSL refused, and PEAP
	 * never got as far as an inner method. Measured on the reporting
	 * machine's corporate network, which pins nothing:
	 *
	 *     OpenSSL: tls_connection_ca_cert - Failed to load root certificates
	 *              error:80000002:system library::No such file or directory
	 *     EAP-PEAP: Failed to initialize SSL.
	 *     CTRL-EVENT-SSID-TEMP-DISABLED ... auth_failures=45 reason=CONN_FAILED
	 *
	 * NetworkManager joined the same network on the same laptop minutes
	 * later, writing no `ca_cert` at all. An omitted setting is how "verify
	 * nothing" is spelled. Decision 0189.
	 */
	if (eap->ca_cert.has &&
	    !add_certificate(out, "ca_cert", &eap->ca_cert, "ca.pem", resolver, err, err_size)) {
		return 0;
	}
	/*
	 * **The second half of checking a server, and the one that was missing.**
	 * `ca_cert` answers who signed the certificate; this answers who the
	 * certificate is for. Pinning an issuer and nothing else accepts every
	 * certificate that issuer signed, which is right for an organisation's
	 * own CA and nearly worthless for a public one -- and a commercial
	 * certificate on a RADIUS server is ordinary. Decision 0206.
	 *
	 * Sent only when the document asks for it: an absent line leaves the
	 * supplicant's own default, and sending an empty one would be 0189's
	 * fault again in a different field.
	 */
	if (eap->domain_suffix_match &&
	    !add_quoted(out, "domain_suffix_match", eap->domain_suffix_match, 0, err, err_size)) {
		return 0;
	}
	if (eap->client_cert.has && !add_certificate(out, "client_cert", &eap->client_cert,
	    "client.pem", resolver, err, err_size)) {
		return 0;
	}
	if (eap->phase2 && !add_quoted(out, "phase2", eap->phase2, 0, err, err_size)) {
		return 0;
	}

	if (eap->method == NCFG_EAP_METHOD_TLS) {
		/*
		 * **A path, always, because wpa_supplicant opens it as a file.** Its
		 * own README says `private_key="/etc/cert/user.prv"`.
		 *
		 * This used to resolve the secret and send its *value*, which could
		 * not work: key material there is a filename that does not exist, and
		 * a PEM is multi-line, so it terminated the line-based `SET_NETWORK`
		 * command in the middle and corrupted the rest of the conversation.
		 * Nothing caught it because the only EAP-TLS test asserted a
		 * missing-field error and never looked at what a complete network
		 * renders to.
		 */
		if (!eap->private_key.has) {
			ncfg_error_set(err, err_size, "this EAP method needs `private_key`");
			return 0;
		}
		return add_certificate(out, "private_key", &eap->private_key, "client.key",
		    resolver, err, err_size);
	}
	if (!eap->password) {
		ncfg_error_set(err, err_size, "this EAP method needs `password`");
		return 0;
	}
	if (!credential_is_usable(resolver, eap->password, 0, err, err_size)) {
		return 0;
	}
	return add_secret(out, "password", eap->password, err, err_size);
}

int ncfg_supplicant_wired_settings(const ncfg_eap_config_t *eap,
    const ncfg_secret_resolver_t *resolver, ncfg_supplicant_settings_t *out, char *err,
    size_t err_size)
{
	size_t index;

	if (!eap || !out) {
		ncfg_error_set(err, err_size, "a wired 802.1X port needs an EAP configuration");
		return 0;
	}
	out->items = NULL;
	out->count = 0;
	if (!eap_settings(eap, resolver, out, err, err_size)) {
		ncfg_supplicant_settings_free(out);
		return 0;
	}
	/* `eap_settings` speaks wifi. Replace the two things that differ rather
	 * than duplicating the method, identity and certificate handling. */
	for (index = 0; index < out->count; index++) {
		if (strcmp(out->items[index].variable, "key_mgmt") == 0) {
			char *wired = strdup("IEEE8021X");

			if (!wired) {
				ncfg_supplicant_settings_free(out);
				ncfg_error_set(err, err_size, "no memory for the `key_mgmt` setting");
				return 0;
			}
			free(out->items[index].value);
			out->items[index].value = wired;
		}
	}
	/* Without this the supplicant tries to install WEP keys the switch never
	 * sends, and the port authenticates and then goes quiet. */
	if (!add_plain(out, "eapol_flags", "0", err, err_size)) {
		ncfg_supplicant_settings_free(out);
		return 0;
	}
	return 1;
}

/* ------------------------------------------------------- one whole network */

int ncfg_supplicant_settings(const ncfg_wifi_network_t *network,
    const ncfg_ssid_t *resolved_ssid, int mac_policy, const ncfg_secret_resolver_t *resolver,
    ncfg_supplicant_settings_t *out, char *err, size_t err_size)
{
	const ncfg_ssid_t *ssid;
	char               hex[NCFG_SUPPLICANT_SSID_HEX_SIZE];
	size_t             index;
	int                built;

	if (!network || !out) {
		ncfg_error_set(err, err_size, "a network needs somewhere to be rendered to");
		return 0;
	}
	out->items = NULL;
	out->count = 0;

	/* The SSID has to be known by now. A document may leave it out and name
	 * access points instead, and the caller resolves it from a scan before
	 * getting here -- because WPA derives its key from the passphrase *and*
	 * the SSID, so there is nothing to send without one. */
	ssid = network->ssid.has ? &network->ssid : resolved_ssid;
	if (!ssid || !ssid->has) {
		ncfg_error_set(err, err_size,
		    "this network names access points instead of an SSID, and the name was "
		    "never read off a scan");
		return 0;
	}
	if (!ncfg_supplicant_ssid_argument(ssid, hex, sizeof(hex))) {
		ncfg_error_set(err, err_size, "an SSID is 0 to 32 octets and this one is %zu",
		    ssid->length);
		return 0;
	}
	built = add_plain(out, "ssid", hex, err, err_size);
	/* **Sent always, including for `permanent`.** Leaving it unset would
	 * inherit whatever the supplicant's global happens to be, which on a
	 * distribution that sets one would make netcfgd's `permanent` mean
	 * something else -- and a privacy property that depends on somebody
	 * else's default is not a property. */
	built = built && add_plain(out, "mac_addr", ncfg_supplicant_mac_addr_value(mac_policy),
	    err, err_size);
	if (built && network->hidden) {
		/* Without this a hidden network is never probed for, so it simply
		 * never appears -- with no error anywhere to say why. */
		built = add_plain(out, "scan_ssid", "1", err, err_size);
	}
	for (index = 0; built && index < network->bssid_count; index++) {
		if (!is_bssid(network->bssid[index])) {
			ncfg_error_set(err, err_size, "`%s` is not a MAC address",
			    network->bssid[index]);
			built = 0;
		}
	}
	if (built && network->bssid_count == 1u) {
		/* One is a pin: `bssid` refuses every other access point outright. */
		built = add_plain(out, "bssid", network->bssid[0], err, err_size);
	} else if (built && network->bssid_count > 1u) {
		/* **Several is a choice.** `bssid_accept` limits selection to the set
		 * and lets the supplicant pick among them by signal, which is what
		 * "any of these, whichever is best" means -- and it composes with a
		 * roam policy, where a pin does not (0090). Space separated, each
		 * with an exact mask: the masked form is what `wpa_supplicant`
		 * parses, and every-bit-set is one specific address. */
		ncfg_buf_t list;
		char      *held;

		ncfg_buf_init(&list, 0);
		for (index = 0; index < network->bssid_count; index++) {
			if (index) {
				ncfg_buf_add_char(&list, ' ');
			}
			ncfg_buf_addf(&list, "%s/ff:ff:ff:ff:ff:ff", network->bssid[index]);
		}
		held = ncfg_buf_failed(&list) ? NULL : ncfg_buf_take(&list, NULL);
		ncfg_buf_free(&list);
		if (!held) {
			ncfg_error_set(err, err_size, "no memory for %zu access points",
			    network->bssid_count);
			built = 0;
		} else {
			built = add_setting(out, "bssid_accept", held, NULL, 0, err, err_size);
		}
	}
	if (built && network->roam) {
		/* `simple`, not `learn`. The learn module keeps a database file of
		 * which channels this network uses, which is a second piece of state
		 * on disk that netcfgd would then own the lifetime of -- and its
		 * benefit is fewer scans, not better roaming. The module name is
		 * chosen here and not in the document because a
		 * `bgscan="simple:30:-70:300"` in netcfgd.conf would be netcfgd
		 * asking the operator which supplicant is underneath.
		 *
		 * Quoted, because wpa_supplicant parses this one as a string and
		 * takes the whole quoted value as the module specification. The order
		 * is the module's own: short interval, threshold, long interval. */
		char module[128];

		(void)snprintf(module, sizeof(module), "\"simple:%lld:%lld:%lld\"",
		    (long long)network->roam->interval, (long long)network->roam->signal,
		    (long long)network->roam->slow_interval);
		built = add_plain(out, "bgscan", module, err, err_size);
	}
	if (built && network->metric.has) {
		/* The supplicant still orders networks and still needs telling; what
		 * it is told is derived rather than asked for (0154). */
		char rank[32];

		(void)snprintf(rank, sizeof(rank), "%lld", (long long)join_rank(network->metric.value));
		built = add_plain(out, "priority", rank, err, err_size);
	}
	if (built) {
		switch (network->security.kind) {
		case NCFG_SECURITY_OPEN:
			built = add_plain(out, "key_mgmt", "NONE", err, err_size);
			break;
		case NCFG_SECURITY_PSK:
			built = psk_settings(&network->security.psk, resolver, out, err, err_size);
			break;
		case NCFG_SECURITY_EAP:
			built = eap_settings(&network->security.eap, resolver, out, err, err_size);
			break;
		case NCFG_SECURITY_OWE:
		default:
			/* Opportunistic Wireless Encryption: unauthenticated but
			 * encrypted. `ieee80211w` is required rather than optional here
			 * -- OWE without management frame protection is not OWE. */
			built = add_plain(out, "key_mgmt", "OWE", err, err_size) &&
			    add_plain(out, "ieee80211w", "2", err, err_size);
			break;
		}
	}
	if (!built) {
		ncfg_supplicant_settings_free(out);
		return 0;
	}
	return 1;
}

/* ------------------------------------------------------------ the rendering */

void ncfg_supplicant_buf_wipe(ncfg_buf_t *buf)
{
	if (!buf) {
		return;
	}
	if (buf->data && buf->capacity) {
		memset(buf->data, 0, buf->capacity);
	}
	ncfg_buf_free(buf);
}

/*
 * Append one setting's value, resolving a credential where that is what it is.
 *
 * The only place a passphrase becomes text, and it is one statement long: the
 * secret is resolved, quoted into the caller's buffer, and freed -- and
 * `ncfg_secret_free` wipes what it held.
 */
static int append_value(const ncfg_supplicant_setting_t *setting,
    const ncfg_secret_resolver_t *resolver, ncfg_buf_t *out, char *err, size_t err_size)
{
	ncfg_secret_t *secret;

	if (!setting->secret) {
		ncfg_buf_add_text(out, setting->value ? setting->value : "");
		return 1;
	}
	secret = ncfg_secret_resolve(resolver, setting->secret, NULL, err, err_size);
	if (!secret) {
		return 0;
	}
	ncfg_supplicant_quote(out, ncfg_secret_expose(secret));
	ncfg_secret_free(secret);
	return 1;
}

int ncfg_supplicant_setting_command(const ncfg_supplicant_setting_t *setting, uint32_t id,
    const ncfg_secret_resolver_t *resolver, ncfg_buf_t *out, char *err, size_t err_size)
{
	if (!setting || !out) {
		ncfg_error_set(err, err_size, "a setting needs somewhere to be written");
		return 0;
	}
	ncfg_buf_addf(out, "SET_NETWORK %lu %s ", (unsigned long)id, setting->variable);
	if (!append_value(setting, resolver, out, err, err_size)) {
		return 0;
	}
	if (ncfg_buf_failed(out)) {
		ncfg_error_set(err, err_size, "the `%s` command is longer than one may be",
		    setting->variable);
		return 0;
	}
	return 1;
}

void ncfg_supplicant_setting_redacted(const ncfg_supplicant_setting_t *setting, uint32_t id,
    ncfg_buf_t *out)
{
	if (!setting || !out) {
		return;
	}
	ncfg_buf_addf(out, "SET_NETWORK %lu %s %s", (unsigned long)id, setting->variable,
	    setting->sensitive ? ncfg_secret_redacted() : (setting->value ? setting->value : ""));
}

/* ------------------------------------------------------------ the digest */

int ncfg_supplicant_fingerprint(const ncfg_wifi_network_t *networks, size_t count,
    int mac_policy, int scan_randomization, int device_autoconnect,
    const ncfg_secret_resolver_t *resolver, char *out, char *err, size_t err_size)
{
	ncfg_buf_t  text;
	ncfg_ssid_t stand_in;
	size_t      index;

	if (!out) {
		ncfg_error_set(err, err_size, "a digest needs somewhere to be written");
		return 0;
	}
	out[0] = '\0';
	memset(&stand_in, 0, sizeof(stand_in));
	stand_in.has = 1;
	stand_in.length = sizeof(UNRESOLVED) - 1u;
	memcpy(stand_in.bytes, UNRESOLVED, stand_in.length);

	ncfg_buf_init(&text, 0);
	/* **A line only when it is on, and that asymmetry is deliberate.** This
	 * digest decides whether a *running* supplicant still matches the
	 * document, and a mismatch replaces its whole network set -- which drops
	 * the association. Encoding the off state as a line would change the
	 * digest of every machine that has never used this, so the first apply
	 * after an upgrade would disconnect all of them to record a setting none
	 * of them asked for. 0220. */
	if (scan_randomization) {
		ncfg_buf_add_text(&text, "preassoc_mac_addr 1\n");
	}
	/* **Whether this radio joins anything by itself (0236)**, a line only
	 * when it does not, for the reason the one above is conditional. */
	if (!device_autoconnect) {
		ncfg_buf_add_text(&text, "device manual\n");
	}
	for (index = 0; index < count; index++) {
		const ncfg_wifi_network_t *network = &networks[index];
		ncfg_supplicant_settings_t rendered;
		size_t                     which;
		int                        ok;

		/* The id as well as the settings: two networks that render
		 * identically are still two networks, and one being renamed is a
		 * change. */
		ncfg_buf_add_text(&text, network->id ? network->id : "");
		ncfg_buf_add_char(&text, '\n');
		/* **A network whose SSID comes from a scan is rendered against a
		 * fixed stand-in, and used not to be rendered at all.** One such
		 * network turned change detection off for the whole radio, silently
		 * and permanently, because the digest was absent and an absent digest
		 * removes the record. */
		if (!network->ssid.has) {
			ncfg_buf_add_text(&text, "ssid-from-scan\n");
		}
		/* **`autoconnect` drives `ENABLE_NETWORK`, not a `SET_NETWORK`, so it
		 * never reached this digest (0236).** Changing it in a document left
		 * the digest identical, so the planner saw no drift, so the
		 * supplicant was never repopulated and the edit did nothing. */
		if (!network->autoconnect) {
			ncfg_buf_add_text(&text, "manual\n");
		}
		if (!ncfg_supplicant_settings(network, &stand_in, mac_policy, resolver, &rendered,
		    err, err_size)) {
			/* A network that cannot be rendered at all: netcfgd could not
			 * have handed it over, so it genuinely cannot say what the
			 * supplicant holds. */
			ncfg_supplicant_buf_wipe(&text);
			return 0;
		}
		ok = 1;
		for (which = 0; ok && which < rendered.count; which++) {
			ncfg_buf_add_text(&text, rendered.items[which].variable);
			ncfg_buf_add_char(&text, ' ');
			ok = append_value(&rendered.items[which], resolver, &text, err, err_size);
			ncfg_buf_add_char(&text, '\n');
		}
		ncfg_supplicant_settings_free(&rendered);
		if (!ok) {
			ncfg_supplicant_buf_wipe(&text);
			return 0;
		}
	}
	if (ncfg_buf_failed(&text)) {
		ncfg_supplicant_buf_wipe(&text);
		ncfg_error_set(err, err_size, "%zu networks are more than one digest may cover",
		    count);
		return 0;
	}
	ncfg_sha256_hex(ncfg_buf_text(&text), strlen(ncfg_buf_text(&text)), out);
	/* **The text held every passphrase on the radio.** It is hashed and then
	 * gone; leaving it for the allocator would put the whole set of
	 * credentials in whatever is allocated next. */
	ncfg_supplicant_buf_wipe(&text);
	return 1;
}

/* ------------------------------------------------------- reading a name off */

/* Lowercase hex of an SSID, for a message. Not `ssid_argument`'s job: that one
 * renders for the wire and refuses what it cannot render, and a diagnostic
 * must say something either way. */
static void ssid_hex(const ncfg_ssid_t *ssid, char *out, size_t out_size)
{
	if (!ncfg_supplicant_ssid_argument(ssid, out, out_size) && out_size) {
		out[0] = '\0';
	}
}

static int same_address(const char *one, const char *other)
{
	size_t index;

	/* Case-insensitively: an address an operator typed and one a driver
	 * reported differ in case often enough that comparing them exactly is a
	 * bug waiting for a capital letter. */
	for (index = 0; one[index] != '\0' && other[index] != '\0'; index++) {
		char left = one[index];
		char right = other[index];

		if (left >= 'A' && left <= 'Z') {
			left = (char)(left - 'A' + 'a');
		}
		if (right >= 'A' && right <= 'Z') {
			right = (char)(right - 'A' + 'a');
		}
		if (left != right) {
			return 0;
		}
	}
	return one[index] == other[index];
}

int ncfg_supplicant_pick_ssid(const ncfg_wifi_network_t *network,
    const ncfg_supplicant_scan_t *seen, size_t seen_count, ncfg_ssid_t *out, char *err,
    size_t err_size)
{
	const ncfg_supplicant_scan_t *advertised = NULL;
	const char                   *at_address = NULL;
	ncfg_buf_t                    missing;
	ncfg_buf_t                    silent;
	size_t                        wanted;
	size_t                        found = 0;
	size_t                        silent_count = 0;
	int                           answered = 0;
	const char                   *id;

	if (!network || !out) {
		ncfg_error_set(err, err_size, "a name needs somewhere to be put");
		return 0;
	}
	id = network->id ? network->id : "";
	ncfg_buf_init(&missing, 0);
	ncfg_buf_init(&silent, 0);
	for (wanted = 0; wanted < network->bssid_count; wanted++) {
		const ncfg_supplicant_scan_t *row = NULL;
		size_t                        which;

		for (which = 0; which < seen_count; which++) {
			if (seen[which].bssid && same_address(seen[which].bssid,
			    network->bssid[wanted])) {
				row = &seen[which];
				break;
			}
		}
		if (!row) {
			continue;
		}
		found++;
		if (row->ssid.length == 0u) {
			/* **A hidden access point is in range and still says nothing.**
			 * Dropped rather than compared: it does not disagree with a named
			 * one about what the network is called, it declines to say, and
			 * comparing them produced "they are on different networks", which
			 * is both wrong and unactionable. 0223. */
			if (silent_count++) {
				ncfg_buf_add_text(&silent, ", ");
			}
			ncfg_buf_add_text(&silent, network->bssid[wanted]);
			continue;
		}
		if (!advertised) {
			advertised = row;
			at_address = network->bssid[wanted];
			continue;
		}
		/* **Every one that is in range and advertising has to agree.** Two
		 * addresses advertising different names are two networks, and one
		 * passphrase cannot be right for both -- WPA's key is derived per
		 * SSID. */
		if (!answered && (row->ssid.length != advertised->ssid.length ||
		    memcmp(row->ssid.bytes, advertised->ssid.bytes, row->ssid.length) != 0)) {
			char one[NCFG_SUPPLICANT_SSID_HEX_SIZE];
			char other[NCFG_SUPPLICANT_SSID_HEX_SIZE];

			ssid_hex(&advertised->ssid, one, sizeof(one));
			ssid_hex(&row->ssid, other, sizeof(other));
			ncfg_error_set(err, err_size,
			    "`%s` lists access points that are on different networks: %s "
			    "advertises %s and %s advertises %s",
			    id, at_address, one, network->bssid[wanted], other);
			answered = -1;
		}
	}
	for (wanted = 0; found == 0u && wanted < network->bssid_count; wanted++) {
		if (wanted) {
			ncfg_buf_add_text(&missing, ", ");
		}
		ncfg_buf_add_text(&missing, network->bssid[wanted]);
	}
	if (answered == 0) {
		if (found == 0u) {
			/* Named rather than counted: "network not found", about a network
			 * identified by address, is not a sentence anybody can act on. */
			ncfg_error_set(err, err_size,
			    "none of the access points `%s` names is in range, so its network "
			    "name could not be read: %s",
			    id, ncfg_buf_text(&missing));
		} else if (!advertised) {
			ncfg_error_set(err, err_size,
			    "the access points `%s` names are in range and hidden, so a scan "
			    "cannot say what the network is called: %s. Write the name in the "
			    "block -- `ssid = \"...\"` -- and keep `bssid` to pin which radios "
			    "it may use",
			    id, ncfg_buf_text(&silent));
		} else {
			*out = advertised->ssid;
			answered = 1;
		}
	}
	ncfg_buf_free(&missing);
	ncfg_buf_free(&silent);
	return answered == 1;
}
