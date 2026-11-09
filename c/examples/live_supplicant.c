/*
 * live_supplicant.c -- every setting netcfgd sends a supplicant, sent to a real one.
 *
 *     live_supplicant CONFIG_DIR CTRL_DIR INTERFACE WORK_DIR
 *
 * Compiles CONFIG_DIR the way the daemon does, connects to the `wpa_supplicant`
 * whose control socket is CTRL_DIR/INTERFACE, and for every network in the
 * document and every MAC policy sends exactly what a reconcile would: the
 * globals `wifi_ops.c` sets on a radio, then `ADD_NETWORK` and one
 * `SET_NETWORK` per setting from `ncfg_supplicant_settings`. Each line it prints
 * is `ok` or `FAIL`, and it exits 1 if anything was refused. WORK_DIR is where a
 * stored certificate may be written for the supplicant to read.
 *
 * WHY THIS EXISTS
 *   The unit tests render those commands and compare them with what they
 *   should say; nothing there knows what a real supplicant's parser accepts,
 *   and every value in this file has been refused by one at some point --
 *   `okc 7` answers OK, `ieee80211w` does not take `required`, an EAP method
 *   list is space-separated. `backend/netcfgd-supplicant/tests/live.rs` drove
 *   the Rust's settings at a real supplicant and went with the Rust (0317);
 *   this is the C's, driven by `tests/live/c_supplicant_settings.sh`.
 *
 * WHAT IT DOES NOT PROVE
 *   That a network authenticates. `wpa_supplicant -Dwired` on a dummy link
 *   parses and stores what it is given and associates with nothing, so an OK
 *   here says the setting exists and its value parses -- which is what kept
 *   going wrong -- and not that the value means what netcfgd intends.
 */
#include "ncfg/config.h"
#include "ncfg/document.h"
#include "ncfg/hooks.h"
#include "ncfg/secrets.h"
#include "ncfg/supplicant.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;

static void report(int ok, const char *what, const char *detail)
{
	if (ok) {
		printf("ok   %s\n", what);
	} else {
		printf("FAIL %s: %s\n", what, detail ? detail : "");
		failures++;
	}
}

/*
 * The globals a radio is given before its networks, in `wifi_ops.c`'s order.
 * `okc` and `sae_pwe` are not fatal there -- an old supplicant may lack them
 * -- and are held to OK here, because this one is the supplicant the suite
 * runs and a refusal is worth seeing.
 */
static void globals(ncfg_supplicant_client_t *client, int policy)
{
	char        command[128];
	char        detail[NCFG_ERROR_MAX];
	const char *fixed[] = { "SET update_config 0", "SET okc 1", "SET sae_pwe 2" };
	size_t      at;

	for (at = 0; at < sizeof(fixed) / sizeof(fixed[0]); at++) {
		report(ncfg_supplicant_command(client, fixed[at], detail, sizeof(detail)), fixed[at],
		    detail);
	}
	(void)snprintf(command, sizeof(command), "SET rand_addr_lifetime %s",
	    ncfg_supplicant_rand_addr_lifetime_value(policy));
	report(ncfg_supplicant_command(client, command, detail, sizeof(detail)), command, detail);
	(void)snprintf(command, sizeof(command), "SET preassoc_mac_addr %d",
	    policy == NCFG_MAC_POLICY_PERMANENT ? 0 : 1);
	report(ncfg_supplicant_command(client, command, detail, sizeof(detail)), command, detail);
}

static const char *policy_name(int policy)
{
	switch (policy) {
	case NCFG_MAC_POLICY_PERMANENT:
		return "permanent";
	case NCFG_MAC_POLICY_PER_NETWORK:
		return "per_network";
	case NCFG_MAC_POLICY_PER_CONNECTION:
		return "per_connection";
	default:
		return "?";
	}
}

/* One network, sent whole, then removed so the next starts from nothing. */
static void one_network(ncfg_supplicant_client_t *client, const ncfg_wifi_network_t *network,
    int policy, const ncfg_secret_resolver_t *resolver)
{
	ncfg_supplicant_settings_t settings;
	char                       body[64];
	char                       detail[NCFG_ERROR_MAX];
	char                       what[512];
	char                       command[64];
	unsigned long              id;
	size_t                     at;
	size_t                     refused = 0;
	ncfg_ssid_t                fallback;
	const ncfg_ssid_t         *resolved = NULL;

	/* A network that names access points rather than an SSID takes its name
	 * from a scan, and this has none to read -- so it is given one, which is
	 * what a scan would have supplied. */
	memset(&fallback, 0, sizeof(fallback));
	if (!network->ssid.has) {
		fallback.has = 1;
		memcpy(fallback.bytes, "probe", 5u);
		fallback.length = 5u;
		resolved = &fallback;
	}
	(void)snprintf(what, sizeof(what), "network `%s` under %s", network->id,
	    policy_name(policy));
	if (!ncfg_supplicant_settings(network, resolved, policy, resolver, &settings, detail,
	        sizeof(detail))) {
		report(0, what, detail);
		return;
	}
	if (!ncfg_supplicant_ask(client, "ADD_NETWORK", body, sizeof(body), detail,
	        sizeof(detail))) {
		report(0, what, detail);
		ncfg_supplicant_settings_free(&settings);
		return;
	}
	id = strtoul(body, NULL, 10);
	for (at = 0; at < settings.count; at++) {
		ncfg_buf_t line;
		ncfg_buf_t shown;

		ncfg_buf_init(&line, 0);
		if (!ncfg_supplicant_setting_command(&settings.items[at], (uint32_t)id, resolver,
		        &line, detail, sizeof(detail)) ||
		    !ncfg_supplicant_command(client, ncfg_buf_text(&line), detail, sizeof(detail))) {
			/* The redacted form, because the refused line is the one most
			 * likely to carry the passphrase. */
			ncfg_buf_init(&shown, 0);
			ncfg_supplicant_setting_redacted(&settings.items[at], (uint32_t)id, &shown);
			printf("FAIL %s: `%s` was refused: %s\n", what, ncfg_buf_text(&shown), detail);
			ncfg_buf_free(&shown);
			refused++;
			failures++;
		}
		ncfg_supplicant_buf_wipe(&line);
	}
	if (refused == 0u) {
		printf("ok   %s: %lu setting(s) accepted\n", what, (unsigned long)settings.count);
	}
	(void)snprintf(command, sizeof(command), "REMOVE_NETWORK %lu", id);
	report(ncfg_supplicant_command(client, command, detail, sizeof(detail)),
	    "and it is removed again", detail);
	ncfg_supplicant_settings_free(&settings);
}

int main(int argc, char **argv)
{
	static const int        policies[] = { NCFG_MAC_POLICY_PERMANENT,
		       NCFG_MAC_POLICY_PER_NETWORK, NCFG_MAC_POLICY_PER_CONNECTION };
	ncfg_config_sources_t    sources;
	ncfg_document_t         *document;
	ncfg_supplicant_client_t *client;
	ncfg_secret_resolver_t   resolver;
	char                     secrets[4096];
	char                     err[NCFG_ERROR_MAX];
	size_t                   p;
	size_t                   n;

	if (argc != 5) {
		fprintf(stderr, "usage: %s CONFIG_DIR CTRL_DIR INTERFACE WORK_DIR\n", argv[0]);
		return 2;
	}
	memset(&sources, 0, sizeof(sources));
	if (!ncfg_config_load(argv[1], &sources, err, sizeof(err))) {
		fprintf(stderr, "live_supplicant: %s\n", err);
		return 2;
	}
	/* The read-only verbs' sink: hook bodies are not this probe's to write. */
	document = ncfg_config_compile(&sources, ncfg_hook_sink_unwritten(), NULL, err,
	    sizeof(err));
	ncfg_config_sources_free(&sources);
	if (!document) {
		fprintf(stderr, "live_supplicant: %s\n", err);
		return 2;
	}
	if (document->network_count == 0u) {
		fprintf(stderr, "live_supplicant: the configuration has no networks, so nothing "
		    "would be sent\n");
		ncfg_document_free(document);
		return 2;
	}
	(void)snprintf(secrets, sizeof(secrets), "%s/secrets", argv[1]);
	resolver.secrets_dir = secrets;
	resolver.materialise_dir = argv[4];
	client = ncfg_supplicant_connect(argv[2], argv[3], err, sizeof(err));
	if (!client) {
		fprintf(stderr, "live_supplicant: %s\n", err);
		ncfg_document_free(document);
		return 2;
	}
	for (p = 0; p < sizeof(policies) / sizeof(policies[0]); p++) {
		globals(client, policies[p]);
		for (n = 0; n < document->network_count; n++) {
			one_network(client, &document->networks[n], policies[p], &resolver);
		}
	}
	printf("live_supplicant: %lu network(s) under %lu MAC policies, %d refused\n",
	    (unsigned long)document->network_count,
	    (unsigned long)(sizeof(policies) / sizeof(policies[0])), failures);
	ncfg_supplicant_client_free(client);
	ncfg_document_free(document);
	return failures ? 1 : 0;
}
