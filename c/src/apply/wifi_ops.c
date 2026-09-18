/*
 * wifi_ops.c -- the six ops carried out over a `wpa_ctrl` control socket.
 *
 * ONE CLIENT, TWO DAEMONS
 *   `hostapd` and `wpa_supplicant` speak the same control protocol over the
 *   same kind of socket, and `supplicant.h` is the port's only client for it.
 *   So the access-control ops here connect with `ncfg_supplicant_connect_
 *   within` pointed at `ncfg_hostapd_ctrl_dir`, which is exactly what the Rust
 *   does -- `netcfgd_hostapd::acl` calls `netcfgd_supplicant::Client` -- and is
 *   what `hostapd.h` means when it says the round trip its parsers need "is the
 *   supplicant module's". **Nothing in this file writes a second client.**
 *
 * WHAT IS ASKED BEFORE IT IS ANSWERED, AND WHY
 *   `service.h` carries the argument; the short version is that a plan is
 *   applied twice on a converged machine and an op that failed or disrupted
 *   the second time would break the property `plan.h` calls load-bearing.
 *   Two of these read before they write, and each reads through a parser that
 *   already exists.
 *
 * WHAT NEVER REACHES A COMMAND UNEXAMINED
 *   A station address, an SSID and a country code all come out of a
 *   configuration file and all end up in a control command. The SSID goes as
 *   hex, which is `ncfg_supplicant_ssid_argument`'s whole point; the station
 *   is normalised; the country is checked for being two letters. That is the
 *   same rule in three places rather than three rules.
 */
#include "ncfg/service.h"

#include "ncfg/base.h"
#include "ncfg/hostapd.h"
#include "ncfg/log.h"
#include "ncfg/supplicant.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* The longest path this module builds: a control directory and an interface. */
#define WIFI_PATH_MAX 4352u

/* How long a control socket gets, with 0 meaning the impatient default. */
static int patience_of(const ncfg_service_t *service)
{
	if (service && service->patience_ms > 0) {
		return service->patience_ms;
	}
	return NCFG_SUPPLICANT_IMPATIENT_MS;
}

/* ------------------------------------------------------------------------ *
 * hostapd's access control lists
 * ------------------------------------------------------------------------ */

const char *ncfg_service_acl_command(int policy)
{
	switch ((ncfg_acl_policy_t)policy) {
	case NCFG_ACL_POLICY_DENY:
		return "DENY_ACL";
	case NCFG_ACL_POLICY_ALLOW:
		return "ACCEPT_ACL";
	}
	/* value.h's convention: a plausible word for something outside the set is
	 * worse than no word, and the caller refuses by name. */
	return NULL;
}

/* Whether `address` is one of `count` sorted, normalised entries. */
static int list_holds(char *const *addresses, size_t count, const char *address)
{
	size_t i;

	for (i = 0; i < count; i++) {
		if (addresses[i] && strcmp(addresses[i], address) == 0) {
			return 1;
		}
	}
	return 0;
}

int ncfg_service_access_control(const char *run_dir, const char *iface, int policy,
    const char *station, int adding, int patience_ms, char *err, size_t err_size)
{
	char                      directory[WIFI_PATH_MAX];
	char                      address[18];
	char                      command[64];
	char                      body[NCFG_SUPPLICANT_REPLY_MAX];
	const char               *list = ncfg_service_acl_command(policy);
	char                    **present = NULL;
	size_t                    present_count = 0;
	ncfg_supplicant_client_t *client;
	int                       held;
	int                       ok;

	if (!run_dir || run_dir[0] == '\0') {
		ncfg_error_set(err, err_size,
		    "an access_control action needs to be told where netcfgd's run "
		    "directory is, and this build has no default for it");
		return 0;
	}
	if (!iface || iface[0] == '\0') {
		ncfg_error_set(err, err_size, "an access_control action names no access point");
		return 0;
	}
	if (!list) {
		ncfg_error_set(err, err_size,
		    "an access_control action on %s names neither of hostapd's two lists",
		    iface);
		return 0;
	}
	/* Normalised before it is compared *or* sent. Everything here has been
	 * through the compiler, so this is the backstop -- and it is the one that
	 * keeps `hwaddr_aton` from failing inside hostapd against a station
	 * netcfgd would not name. */
	if (!ncfg_hostapd_normalize_station(station, address, sizeof(address), err, err_size)) {
		return 0;
	}
	if (!ncfg_hostapd_ctrl_dir(run_dir, directory, sizeof(directory), err, err_size)) {
		return 0;
	}
	client = ncfg_supplicant_connect_within(directory, iface,
	    patience_ms > 0 ? patience_ms : NCFG_SUPPLICANT_IMPATIENT_MS, err, err_size);
	if (!client) {
		char detail[NCFG_ERROR_MAX];

		/*
		 * Not softened into success the way a stop is. A list this build was
		 * told to converge belongs to an access point the observation reported
		 * as running, so nothing listening here is a hostapd that has gone --
		 * and reporting that as done would have the planner satisfied about a
		 * station that is still admitted.
		 *
		 * The sentence is copied out before the buffer is written, which is
		 * not fussiness: `ncfg_error_set(err, ..., err)` reads the buffer it is
		 * filling, and `vsnprintf` says that is undefined.
		 */
		(void)snprintf(detail, sizeof(detail), "%s", err);
		ncfg_error_set(err, err_size,
		    "cannot reach the access point on %s to change its %s list: %s", iface, list,
		    detail);
		return 0;
	}

	(void)snprintf(command, sizeof(command), "%s SHOW", list);
	body[0] = '\0';
	if (!ncfg_supplicant_ask(client, command, body, sizeof(body), err, err_size)) {
		ncfg_supplicant_client_free(client);
		return 0;
	}
	if (!ncfg_hostapd_parse_acl_show(body, &present, &present_count, err, err_size)) {
		ncfg_supplicant_client_free(client);
		return 0;
	}
	held = list_holds(present, present_count, address);
	ncfg_hostapd_stations_free(present, present_count);

	/*
	 * **The whole reason this reads first.** hostapd's `ADD_MAC` answers FAIL
	 * for an address already on the list -- `hostapd_add_acl_maclist` refuses a
	 * duplicate -- so an executor that sent it blind would fail the second
	 * apply of a converged machine, which is the plan-idempotence property
	 * failing inside the executor rather than in the planner.
	 */
	if (held == (adding ? 1 : 0)) {
		ncfg_supplicant_client_free(client);
		return 1;
	}
	(void)snprintf(command, sizeof(command), "%s %s %s", list, adding ? "ADD_MAC" : "DEL_MAC",
	    address);
	ok = ncfg_supplicant_command(client, command, err, err_size);
	if (!ok) {
		char detail[NCFG_ERROR_MAX];

		(void)snprintf(detail, sizeof(detail), "%s", err);
		ncfg_error_set(err, err_size,
		    "hostapd would not %s %s %s %s's %s list: %s", adding ? "add" : "remove",
		    address, adding ? "to" : "from", iface, list, detail);
	}
	ncfg_supplicant_client_free(client);
	return ok;
}

/* ------------------------------------------------------------------------ *
 * What the document says about one radio
 * ------------------------------------------------------------------------ */

/* The device block for a name, or NULL. */
static const ncfg_device_t *device_named(const ncfg_document_t *document, const char *name)
{
	size_t i;

	if (!document || !name) {
		return NULL;
	}
	for (i = 0; i < document->device_count; i++) {
		if (document->devices[i].name && strcmp(document->devices[i].name, name) == 0) {
			return &document->devices[i];
		}
	}
	return NULL;
}

/* The interface block for a name, or NULL. */
static const ncfg_interface_t *interface_named(const ncfg_document_t *document, const char *name)
{
	size_t i;

	if (!document || !name) {
		return NULL;
	}
	for (i = 0; i < document->interface_count; i++) {
		if (document->interfaces[i].name &&
		    strcmp(document->interfaces[i].name, name) == 0) {
			return &document->interfaces[i];
		}
	}
	return NULL;
}

/*
 * The three radio policies, defaulted where the document says nothing.
 *
 * A device with no `wifi` block is asking for nothing, and the defaults are the
 * document's own: the permanent address, no scan randomisation, and joining by
 * itself. `autoconnect` defaulting to true is 0236's answer and is why the
 * `DISABLE_NETWORK all` below is not sent on almost every machine.
 */
static void radio_policy(const ncfg_document_t *document, const char *device, int *mac_policy,
    int *randomise, int *joins)
{
	const ncfg_device_t *found = device_named(document, device);

	*mac_policy = NCFG_MAC_POLICY_PERMANENT;
	*randomise = 0;
	*joins = 1;
	if (found && found->wifi) {
		*mac_policy = found->wifi->mac_policy;
		*randomise = found->wifi->scan_randomization;
		*joins = found->wifi->autoconnect;
	}
}

/* ------------------------------------------------------------------------ *
 * The networks a supplicant holds
 * ------------------------------------------------------------------------ */

int ncfg_service_networks_record_path(const char *run_dir, const char *iface, char *out,
    size_t out_size, char *err, size_t err_size)
{
	int written;

	if (!run_dir || run_dir[0] == '\0' || !iface || iface[0] == '\0') {
		ncfg_error_set(err, err_size,
		    "the supplicant's network record is named after a run directory and an "
		    "interface, and one of them is missing");
		return 0;
	}
	written = snprintf(out, out_size, "%s/supplicant/%s.networks.sha256", run_dir, iface);
	if (written < 0 || (size_t)written >= out_size) {
		ncfg_error_set(err, err_size,
		    "the supplicant's network record for %s does not fit in %zu bytes", iface,
		    out_size);
		return 0;
	}
	return 1;
}

/*
 * Keep the digest of what was just handed over.
 *
 * **Best effort, and deliberately so** (0180): failing to write it means the
 * next observation cannot say whether the supplicant matches, which the planner
 * reads as "no reason to act" -- and a supplicant that was populated correctly
 * is not made wrong by a record that could not be kept. What it costs is said
 * out loud, because "the planner sees no reason to act" is indistinguishable
 * from a correct machine unless somebody says so.
 *
 * No digest at all removes the record rather than leaving a stale one: a claim
 * about a set the supplicant does not hold is worse than no claim.
 */
static void record_networks(const ncfg_service_t *service, const char *device, int mac_policy,
    int randomise, int joins)
{
	char  path[WIFI_PATH_MAX];
	char  digest[NCFG_SUPPLICANT_SSID_HEX_SIZE];
	char  detail[NCFG_ERROR_MAX];
	FILE *file;

	/* The directory the record goes in, since `<run>` may hold nothing of this
	 * backend's yet -- a supplicant netcfgd adopted rather than started leaves
	 * no `<run>/supplicant` behind it. 0700 because the neighbouring files a
	 * supplicant backend keeps are not for everybody; an existing directory is
	 * success, which is what this means. */
	if (snprintf(path, sizeof(path), "%s/supplicant", service->run_dir) > 0) {
		(void)mkdir(path, 0700);
	}
	if (!ncfg_service_networks_record_path(service->run_dir, device, path, sizeof(path),
	    detail, sizeof(detail))) {
		ncfg_log_emitf("supplicant", NCFG_LOG_WARNING,
		    "cannot name the supplicant's network record for %s: %s; a changed "
		    "passphrase, bssid or network list will not be noticed", device, detail);
		return;
	}
	detail[0] = '\0';
	if (!ncfg_supplicant_fingerprint(service->document->networks,
	    service->document->network_count, mac_policy, randomise, joins, service->secrets,
	    digest, detail, sizeof(detail))) {
		(void)unlink(path);
		return;
	}
	file = fopen(path, "wb");
	if (!file || fprintf(file, "%s", digest) < 0) {
		if (file) {
			(void)fclose(file);
		}
		ncfg_log_emitf("supplicant", NCFG_LOG_WARNING,
		    "cannot keep the supplicant's network record for %s at %s; a changed "
		    "passphrase, bssid or network list will not be noticed", device, path);
		return;
	}
	if (fclose(file) != 0) {
		ncfg_log_emitf("supplicant", NCFG_LOG_WARNING,
		    "cannot finish the supplicant's network record for %s at %s; a changed "
		    "passphrase, bssid or network list will not be noticed", device, path);
	}
}

/* What this module needs before it may talk to a supplicant at all. */
static int supplicant_context(const ncfg_service_t *service, const char *device, const char *doing,
    char *err, size_t err_size)
{
	if (!service) {
		ncfg_error_set(err, err_size,
		    "%s needs an executor that was given a service context, and this one has "
		    "none", doing);
		return 0;
	}
	if (!device || device[0] == '\0') {
		ncfg_error_set(err, err_size, "%s names no device", doing);
		return 0;
	}
	if (!service->supplicant_dir || service->supplicant_dir[0] == '\0') {
		ncfg_error_set(err, err_size,
		    "%s on %s needs to be told where the supplicant control sockets are; "
		    "this build has no default for it, because a default is how a test "
		    "comes to reach the machine's own supplicant", doing, device);
		return 0;
	}
	return 1;
}

int ncfg_service_set_profiles(const ncfg_service_t *service, const char *device, char *err,
    size_t err_size)
{
	ncfg_supplicant_client_t *client;
	const ncfg_interface_t   *interface;
	char                      command[96];
	char                      detail[NCFG_ERROR_MAX];
	int                       mac_policy;
	int                       randomise;
	int                       joins;
	size_t                    i;

	if (!supplicant_context(service, device, "wifi.set_profiles", err, err_size)) {
		return 0;
	}
	if (!service->document) {
		ncfg_error_set(err, err_size,
		    "wifi.set_profiles on %s needs the document the plan was built from, and "
		    "the op carries only the device", device);
		return 0;
	}
	if (!service->secrets) {
		/* A network's passphrase is resolved rather than carried, so an
		 * executor with no resolver would hand the supplicant every network
		 * with its credential missing -- a radio that is configured and cannot
		 * authenticate, reported as done. */
		ncfg_error_set(err, err_size,
		    "wifi.set_profiles on %s needs a secret resolver; without one every "
		    "network would be sent without its credential", device);
		return 0;
	}
	client = ncfg_supplicant_connect_within(service->supplicant_dir, device,
	    patience_of(service), err, err_size);
	if (!client) {
		(void)snprintf(detail, sizeof(detail), "%s", err);
		ncfg_error_set(err, err_size, "cannot reach the supplicant on %s: %s", device,
		    detail);
		return 0;
	}
	/* Explicit, not assumed. 0015: a silent default is not a control, and this
	 * is what keeps the document the only authority over what a supplicant
	 * holds. */
	if (!ncfg_supplicant_command(client, "SET update_config 0", detail, sizeof(detail))) {
		ncfg_error_set(err, err_size, "could not pin update_config on %s: %s", device,
		    detail);
		ncfg_supplicant_client_free(client);
		return 0;
	}

	/*
	 * A wired 802.1X port is a different population rather than a smaller one:
	 * it has exactly one thing to authenticate with and uses `IEEE8021X`, while
	 * a radio gets every network in the document and chooses among them.
	 */
	interface = interface_named(service->document, device);
	if (interface && interface->dot1x) {
		uint32_t slot = 0;
		int      ok = ncfg_supplicant_configure_wired(client, interface->dot1x,
		    service->secrets, &slot, detail, sizeof(detail));

		if (!ok) {
			ncfg_error_set(err, err_size, "could not configure 802.1X on %s: %s",
			    device, detail);
		}
		ncfg_supplicant_client_free(client);
		return ok;
	}

	radio_policy(service->document, device, &mac_policy, &randomise, &joins);
	/* Cleared first, so a supplicant that survived a netcfgd crash -- or one
	 * started by something else -- does not contribute networks the document
	 * cannot account for. 0015. */
	if (!ncfg_supplicant_clear_networks(client, detail, sizeof(detail))) {
		ncfg_error_set(err, err_size, "could not clear %s: %s", device, detail);
		ncfg_supplicant_client_free(client);
		return 0;
	}
	(void)snprintf(command, sizeof(command), "SET rand_addr_lifetime %s",
	    ncfg_supplicant_rand_addr_lifetime_value(mac_policy));
	if (!ncfg_supplicant_command(client, command, detail, sizeof(detail))) {
		ncfg_error_set(err, err_size,
		    "could not set the random address lifetime on %s: %s", device, detail);
		ncfg_supplicant_client_free(client);
		return 0;
	}
	/* The address in probe requests, which is the bigger exposure: it is
	 * broadcast to everyone in range whether or not anything is ever joined.
	 * Sent in both directions for 0015's reason. */
	if (!ncfg_supplicant_command(client,
	    randomise ? "SET preassoc_mac_addr 1" : "SET preassoc_mac_addr 0", detail,
	    sizeof(detail))) {
		ncfg_error_set(err, err_size, "could not set the scanning address policy on %s: %s",
		    device, detail);
		ncfg_supplicant_client_free(client);
		return 0;
	}
	/*
	 * Two globals whose refusal is **not** fatal, each because a `FAIL` means
	 * the supplicant predates the setting rather than that anything is wrong.
	 * `okc` is opportunistic key caching, without which every roam on an
	 * enterprise network costs a full authentication (0228); `sae_pwe 2` adds
	 * hash-to-element, without which SAE against an access point configured for
	 * it alone simply never completes (0226). Refusing to populate over either
	 * would lose every other network on the radio to make a point about one
	 * that cannot work anyway.
	 */
	if (!ncfg_supplicant_command(client, "SET okc 1", detail, sizeof(detail))) {
		ncfg_log_emitf("supplicant", NCFG_LOG_NOTE,
		    "%s: this supplicant does not take `okc` (%s), so each roam on an "
		    "enterprise network costs a full authentication", device, detail);
	}
	if (!ncfg_supplicant_command(client, "SET sae_pwe 2", detail, sizeof(detail))) {
		ncfg_log_emitf("supplicant", NCFG_LOG_NOTE,
		    "%s: this supplicant does not take `sae_pwe` (%s), so SAE will derive "
		    "its password element by hunting and pecking only -- an access point "
		    "set to hash-to-element only cannot be joined", device, detail);
	}

	for (i = 0; i < service->document->network_count; i++) {
		const ncfg_wifi_network_t *network = &service->document->networks[i];
		uint32_t                   slot = 0;

		if (!ncfg_supplicant_add_network(client, network, mac_policy, service->secrets,
		    &slot, detail, sizeof(detail))) {
			ncfg_error_set(err, err_size, "could not give `%s` to %s: %s",
			    network->id ? network->id : "?", device, detail);
			ncfg_supplicant_client_free(client);
			return 0;
		}
	}
	/*
	 * After the networks rather than before: `add_network` enables each one it
	 * adds, so a disable sent first would be undone by the next addition.
	 * `all` is the supplicant's own word. The networks stay configured, so
	 * `ncfg wifi connect` joins one without resolving a credential again.
	 */
	if (!joins && !ncfg_supplicant_command(client, "DISABLE_NETWORK all", detail,
	    sizeof(detail))) {
		ncfg_error_set(err, err_size, "could not leave %s's networks unselected: %s",
		    device, detail);
		ncfg_supplicant_client_free(client);
		return 0;
	}
	/* Written after the last `add_network`, so a population that failed
	 * part-way leaves the previous record -- or none -- rather than claiming a
	 * set the supplicant does not hold. */
	if (service->run_dir && service->run_dir[0] != '\0') {
		record_networks(service, device, mac_policy, randomise, joins);
	}
	ncfg_supplicant_client_free(client);
	return 1;
}

/* ------------------------------------------------------------------------ *
 * Joining and leaving
 * ------------------------------------------------------------------------ */

/* The network block an id names, or NULL. */
static const ncfg_wifi_network_t *network_with_id(const ncfg_document_t *document,
    const char *id)
{
	size_t i;

	if (!document || !id) {
		return NULL;
	}
	for (i = 0; i < document->network_count; i++) {
		if (document->networks[i].id && strcmp(document->networks[i].id, id) == 0) {
			return &document->networks[i];
		}
	}
	return NULL;
}

/*
 * The name to join, which for a network listing access points comes from a
 * scan rather than from the document.
 *
 * No `SCAN` is issued -- `ncfg_supplicant_add_network` gives the reason and it
 * is the same one here: a scan takes seconds, interrupts traffic on the radio,
 * and this runs inside an apply. The last results are what there is, and where
 * the access point is not among them the honest answer is that netcfgd cannot
 * see it.
 */
static int name_to_join(ncfg_supplicant_client_t *client, const ncfg_wifi_network_t *network,
    ncfg_ssid_t *out, char *err, size_t err_size)
{
	char                     body[NCFG_SUPPLICANT_REPLY_MAX];
	ncfg_supplicant_scan_t  *seen = NULL;
	size_t                   seen_count = 0;
	int                      ok;

	if (network->ssid.has) {
		*out = network->ssid;
		return 1;
	}
	body[0] = '\0';
	if (!ncfg_supplicant_ask(client, "SCAN_RESULTS", body, sizeof(body), err, err_size)) {
		return 0;
	}
	if (!ncfg_supplicant_parse_scan_results(body, &seen, &seen_count, err, err_size)) {
		return 0;
	}
	ok = ncfg_supplicant_pick_ssid(network, seen, seen_count, out, err, err_size);
	ncfg_supplicant_scans_free(seen, seen_count);
	return ok;
}

static int same_ssid(const ncfg_ssid_t *one, const ncfg_ssid_t *two)
{
	return one->has && two->has && one->length == two->length &&
	    memcmp(one->bytes, two->bytes, one->length) == 0;
}

int ncfg_service_associate(const ncfg_service_t *service, const char *device,
    const char *network_id, char *err, size_t err_size)
{
	ncfg_supplicant_client_t  *client;
	const ncfg_wifi_network_t *network;
	ncfg_supplicant_entry_t   *entries = NULL;
	size_t                     entry_count = 0;
	ncfg_ssid_t                wanted;
	ncfg_ssid_t                current;
	char                       body[NCFG_SUPPLICANT_REPLY_MAX];
	char                       command[64];
	char                       detail[NCFG_ERROR_MAX];
	size_t                     i;
	int                        found = 0;
	uint32_t                   slot = 0;

	if (!supplicant_context(service, device, "wifi.associate", err, err_size)) {
		return 0;
	}
	network = network_with_id(service->document, network_id);
	if (!network) {
		/*
		 * The op carries a profile id and not a supplicant slot, because a
		 * plan is written before anything is added to a supplicant and cannot
		 * name a slot. So an id the document does not carry is a plan and a
		 * document that have parted company, and there is nothing to guess.
		 */
		ncfg_error_set(err, err_size,
		    "wifi.associate asks %s to join `%s`, which is not a network in the "
		    "document this plan was built from", device,
		    network_id ? network_id : "<nothing>");
		return 0;
	}
	client = ncfg_supplicant_connect_within(service->supplicant_dir, device,
	    patience_of(service), err, err_size);
	if (!client) {
		(void)snprintf(detail, sizeof(detail), "%s", err);
		ncfg_error_set(err, err_size, "cannot reach the supplicant on %s: %s", device,
		    detail);
		return 0;
	}
	if (!name_to_join(client, network, &wanted, err, err_size)) {
		ncfg_supplicant_client_free(client);
		return 0;
	}
	/*
	 * **Asked before it is answered.** Re-selecting a network the radio is
	 * already on is a disassociation and a rejoin -- a visible outage produced
	 * by a plan that had nothing to do, on exactly the machine `plan.h` says
	 * must produce an empty second plan.
	 */
	memset(&current, 0, sizeof(current));
	if (ncfg_supplicant_associated(client, &current, NULL, 0u) &&
	    same_ssid(&current, &wanted)) {
		ncfg_supplicant_client_free(client);
		return 1;
	}

	body[0] = '\0';
	if (!ncfg_supplicant_ask(client, "LIST_NETWORKS", body, sizeof(body), err, err_size)) {
		ncfg_supplicant_client_free(client);
		return 0;
	}
	if (!ncfg_supplicant_parse_network_list(body, &entries, &entry_count, err, err_size)) {
		ncfg_supplicant_client_free(client);
		return 0;
	}
	for (i = 0; i < entry_count; i++) {
		if (same_ssid(&entries[i].ssid, &wanted)) {
			slot = entries[i].id;
			found = 1;
			break;
		}
	}
	ncfg_supplicant_entries_free(entries, entry_count);
	if (!found) {
		/*
		 * A `wifi.associate` with no `wifi.set_profiles` before it, or one
		 * whose population failed. Refused by name rather than adding the
		 * network here: that is `set_profiles`' work and doing it in two
		 * places is how a radio comes to hold a network nothing recorded.
		 */
		ncfg_error_set(err, err_size,
		    "the supplicant on %s holds no network matching `%s`; a "
		    "`wifi.set_profiles` has to have put it there first", device, network_id);
		ncfg_supplicant_client_free(client);
		return 0;
	}
	(void)snprintf(command, sizeof(command), "SELECT_NETWORK %lu", (unsigned long)slot);
	if (!ncfg_supplicant_command(client, command, detail, sizeof(detail))) {
		ncfg_error_set(err, err_size, "%s would not join `%s`: %s", device, network_id,
		    detail);
		ncfg_supplicant_client_free(client);
		return 0;
	}
	/*
	 * **`SELECT_NETWORK` answering OK means the supplicant accepted the
	 * command**, not that the machine joined anything: association, the key
	 * exchange and -- on an enterprise network -- a whole TLS handshake all
	 * happen afterwards, and every way they fail is an event rather than a
	 * reply. Returning here would be the defect 0197 records, where `ncfg wifi
	 * connect` reported success over forty-five consecutive authentication
	 * failures.
	 */
	if (!ncfg_supplicant_wait_for_connect(client, NCFG_SUPPLICANT_CONNECT_PATIENCE_MS, detail,
	    sizeof(detail))) {
		ncfg_error_set(err, err_size, "%s did not join `%s`: %s", device, network_id,
		    detail);
		ncfg_supplicant_client_free(client);
		return 0;
	}
	ncfg_supplicant_client_free(client);
	return 1;
}

int ncfg_service_disassociate(const ncfg_service_t *service, const char *device, char *err,
    size_t err_size)
{
	ncfg_supplicant_client_t *client;
	char                      detail[NCFG_ERROR_MAX];
	int                       ok;

	if (!supplicant_context(service, device, "wifi.disassociate", err, err_size)) {
		return 0;
	}
	client = ncfg_supplicant_connect_within(service->supplicant_dir, device,
	    patience_of(service), err, err_size);
	if (!client) {
		(void)snprintf(detail, sizeof(detail), "%s", err);
		ncfg_error_set(err, err_size, "cannot reach the supplicant on %s: %s", device,
		    detail);
		return 0;
	}
	/* A state rather than a transition, so sending it twice is sending it
	 * once: a radio that is already disconnected answers OK. */
	ok = ncfg_supplicant_command(client, "DISCONNECT", detail, sizeof(detail));
	if (!ok) {
		ncfg_error_set(err, err_size, "%s would not leave the network it is on: %s",
		    device, detail);
	}
	ncfg_supplicant_client_free(client);
	return ok;
}

int ncfg_service_set_regdom(const ncfg_service_t *service, const char *device,
    const char *country, char *err, size_t err_size)
{
	ncfg_supplicant_client_t *client;
	char                      command[32];
	char                      detail[NCFG_ERROR_MAX];
	char                      code[3];
	int                       ok;

	if (!supplicant_context(service, device, "wifi.set_regdom", err, err_size)) {
		return 0;
	}
	/*
	 * ISO 3166-1 alpha-2 and nothing else, upper cased. A value from a
	 * configuration file reaching a control command unexamined is what this
	 * module refuses everywhere else, and `SET country` takes the rest of the
	 * line -- so a value carrying a space would set a country nobody wrote.
	 */
	if (!country || country[0] < 'A' || country[1] == '\0' || country[2] != '\0') {
		ncfg_error_set(err, err_size,
		    "wifi.set_regdom on %s asks for `%s`, and a regulatory domain is two "
		    "letters", device, country ? country : "<nothing>");
		return 0;
	}
	{
		size_t i;

		for (i = 0; i < 2u; i++) {
			char letter = country[i];

			if (letter >= 'a' && letter <= 'z') {
				letter = (char)(letter - 'a' + 'A');
			}
			if (letter < 'A' || letter > 'Z') {
				ncfg_error_set(err, err_size,
				    "wifi.set_regdom on %s asks for `%s`, and a regulatory "
				    "domain is two letters", device, country);
				return 0;
			}
			code[i] = letter;
		}
		code[2] = '\0';
	}
	client = ncfg_supplicant_connect_within(service->supplicant_dir, device,
	    patience_of(service), err, err_size);
	if (!client) {
		(void)snprintf(detail, sizeof(detail), "%s", err);
		ncfg_error_set(err, err_size, "cannot reach the supplicant on %s: %s", device,
		    detail);
		return 0;
	}
	(void)snprintf(command, sizeof(command), "SET country %s", code);
	/* Idempotent: the supplicant takes the same country twice and answers OK
	 * both times, and `cfg80211` treats a request for the domain already in
	 * force as satisfied. */
	ok = ncfg_supplicant_command(client, command, detail, sizeof(detail));
	if (!ok) {
		ncfg_error_set(err, err_size,
		    "%s would not take the regulatory domain `%s`: %s", device, code, detail);
	}
	ncfg_supplicant_client_free(client);
	return ok;
}
