/*
 * supplicants.c -- what a running supplicant is holding, and whether it
 * answers.
 *
 * THREE ANSWERS, AND THE THIRD IS THE ONE OTHER PASSES WAIT ON
 *   One connection per running supplicant, answering:
 *
 *     * **`answering`**, 0078's question again -- and matched to the backend
 *       **by kind as well as by interface**. One interface carries several
 *       backends, a supplicant and a DHCP client at least, and matching on the
 *       name alone writes the supplicant's answer onto whichever happened to
 *       sort first. The Rust records having had exactly that defect.
 *     * **`networks_match`**, whether the running supplicant still holds what
 *       the document asks for.
 *     * **`link.network`**, which network the radio is associated to. Nothing
 *       in this port wrote that field, and three readers want it --
 *       `ncfg_observed_effective_metric`, which is why a route took the
 *       interface's `preference` where its network named a metric;
 *       `inventory.c`; and `derive.c`. The rule was written and the input was
 *       not.
 *
 * WHY `networks_match` COMES FROM A RECORD AND NOT FROM THE SUPPLICANT
 *   The supplicant cannot say. `LIST_NETWORKS` returns ids and SSIDs, and a
 *   passphrase is write-only -- so "does it hold what the document asks for"
 *   is answered by digesting what the document asks for and comparing it
 *   against the digest netcfgd wrote when it handed the set over. The answer
 *   travels and the values do not, which is `secret_matches`' trade and is
 *   here for its reason: this is serialised into `/run`.
 *
 *   **The record is what netcfgd did, not what is** (0237). It cannot see a
 *   supplicant that lost its networks afterwards while staying reachable, and
 *   that is not hypothetical: `RECONFIGURE` re-reads a configuration file
 *   which, for the one netcfgd writes, names no networks. Measured against
 *   wpa_supplicant 2.10 on the `none` driver:
 *
 *       LIST_NETWORKS  ->  0  probe  any
 *       RECONFIGURE    ->  OK
 *       LIST_NETWORKS  ->  (empty)
 *       PING           ->  PONG
 *
 *   So the coarse question is asked of the supplicant on the connection
 *   already open, and it **overrides** the record: `LIST_NETWORKS` cannot
 *   confirm a set but it can refute one.
 *
 * WHY THE FINGERPRINT IS COMPUTED THE SAME WAY ON BOTH SIDES
 *   `ncfg_supplicant_fingerprint` takes the networks *and* the three
 *   device-wide settings, and the executor digests all four when it records
 *   what it handed over. `ncfg_service_radio_policy` is published so this asks
 *   for those three the same way rather than spelling the defaults again -- two
 *   spellings is a digest that never matches, which is `networks_match` false
 *   for ever and the whole set re-handed on every reconcile.
 */
#include "ncfg/observe.h"

#include "observe_internal.h"

#include "ncfg/base.h"
#include "ncfg/daemon.h"
#include "ncfg/service.h"
#include "ncfg/supplicant.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The supplicant backend on this interface, by kind as well as by name. */
static ncfg_observed_backend_t *supplicant_on(ncfg_observed_t *observed, const char *interface)
{
	size_t at;

	for (at = 0; at < observed->backend_count; at++) {
		ncfg_observed_backend_t *backend = &observed->backends[at];

		if (backend->kind == NCFG_BACKEND_SUPPLICANT && backend->interface && interface &&
		    strcmp(backend->interface, interface) == 0) {
			return backend;
		}
	}
	return NULL;
}

/*
 * Whether the record says the supplicant holds what the document asks for.
 *
 * Absent where there is no record -- a supplicant netcfgd adopted rather than
 * started, a `/run` cleared under a running one, or a write that failed, which
 * `record_networks` says is deliberately best effort. None of those is
 * "differs".
 */
static ncfg_optbool_t record_says(const char *run_dir, const char *interface,
    const ncfg_document_t *desired, const ncfg_secret_resolver_t *secrets)
{
	ncfg_optbool_t answer = { 0, 0 };
	char           path[NCFG_SUPPLICANT_PATH_MAX];
	char           digest[NCFG_SUPPLICANT_SSID_HEX_SIZE];
	char           why[NCFG_ERROR_MAX];
	char          *recorded;
	int            mac_policy = 0;
	int            randomise = 0;
	int            joins = 0;
	size_t         length;

	if (!ncfg_service_networks_record_path(run_dir, interface, path, sizeof(path), NULL, 0)) {
		return answer;
	}
	recorded = observe_read_generated(path);
	if (!recorded) {
		return answer;
	}
	/* The same three the executor digested, asked the same way. */
	ncfg_service_radio_policy(desired, interface, &mac_policy, &randomise, &joins);
	why[0] = '\0';
	if (!ncfg_supplicant_fingerprint(desired->networks, desired->network_count, mac_policy,
	    randomise, joins, secrets, digest, why, sizeof(why))) {
		/* A credential the store cannot answer for. Nothing may be concluded:
		 * the set netcfgd would hand over is not knowable, so neither is
		 * whether the supplicant is holding it. */
		free(recorded);
		return answer;
	}
	length = strlen(recorded);
	while (length > 0u && (unsigned char)recorded[length - 1u] <= ' ') {
		recorded[--length] = '\0';
	}
	answer.has = 1;
	answer.value = strcmp(digest, recorded) == 0;
	free(recorded);
	return answer;
}

/*
 * Whether `LIST_NETWORKS` refutes the record.
 *
 * Only in one direction, and only from empty: a supplicant holding nothing
 * while the document names networks cannot be holding them, whatever the
 * record says. The reverse proves nothing -- a supplicant holding *some*
 * networks may still hold the wrong ones, and `LIST_NETWORKS` carries no
 * passphrase to tell.
 */
static int emptied(ncfg_supplicant_client_t *client, const ncfg_document_t *desired)
{
	char                     body[NCFG_SUPPLICANT_REPLY_MAX];
	ncfg_supplicant_entry_t *entries = NULL;
	size_t                   count = 0;
	char                     why[NCFG_ERROR_MAX];
	int                      refuted;

	if (desired->network_count == 0u) {
		return 0;
	}
	body[0] = '\0';
	why[0] = '\0';
	if (!ncfg_supplicant_ask(client, "LIST_NETWORKS", body, sizeof(body), why, sizeof(why))) {
		return 0;
	}
	if (!ncfg_supplicant_parse_network_list(body, &entries, &count, why, sizeof(why))) {
		return 0;
	}
	refuted = count == 0u;
	ncfg_supplicant_entries_free(entries, count);
	return refuted;
}

/* Which network this radio is associated to, written onto the link. */
static void note_association(ncfg_observed_t *observed, ncfg_supplicant_client_t *client,
    const char *interface, const ncfg_document_t *desired)
{
	ncfg_ssid_t                ssid;
	char                       bssid[18];
	const ncfg_wifi_network_t *network;
	ncfg_observed_link_t      *link;

	memset(&ssid, 0, sizeof(ssid));
	bssid[0] = '\0';
	if (!ncfg_supplicant_associated(client, &ssid, bssid, sizeof(bssid))) {
		return;
	}
	network = ncfg_wifi_network_for(desired->networks, desired->network_count, &ssid,
	    bssid[0] ? bssid : NULL);
	if (!network || !network->id) {
		/* Associated to something the document does not describe. Left absent
		 * rather than named, because every reader of this field asks it about
		 * a network the document has. */
		return;
	}
	link = (ncfg_observed_link_t *)(uintptr_t)ncfg_observed_link(observed, interface);
	if (!link) {
		return;
	}
	free(link->network);
	link->network = observe_dup(network->id);
}

int ncfg_observe_supplicants(ncfg_observed_t *observed, const char *run_dir,
    const ncfg_secret_resolver_t *secrets, const ncfg_document_t *desired, int patience_ms,
    char *err, size_t err_size)
{
	char   directory[NCFG_SUPPLICANT_PATH_MAX];
	size_t at;

	if (!observed || !run_dir || !run_dir[0]) {
		ncfg_error_set(err, err_size,
		    "a supplicant round needs an observation and the run directory the "
		    "daemons were started under");
		return 0;
	}
	if (!ncfg_supplicant_ctrl_dir(directory, sizeof(directory), NULL, 0)) {
		return 1;
	}
	for (at = 0; at < observed->backend_count; at++) {
		ncfg_observed_backend_t  *backend = &observed->backends[at];
		ncfg_supplicant_client_t *client;
		const char               *interface;

		if (backend->kind != NCFG_BACKEND_SUPPLICANT || !backend->running ||
		    !backend->interface) {
			continue;
		}
		interface = backend->interface;
		client = ncfg_supplicant_connect_within(directory, interface,
		    patience_ms > 0 ? patience_ms : NCFG_SUPPLICANT_IMPATIENT_MS, NULL, 0);
		/*
		 * By kind as well as by interface -- `supplicant_on` rather than this
		 * loop's own `backend`, so that the answer lands on the supplicant
		 * even if a later pass reorders the list. The two are the same record
		 * today and the lookup says which one is meant.
		 */
		backend = supplicant_on(observed, interface);
		if (!backend) {
			ncfg_supplicant_client_free(client);
			continue;
		}
		backend->answering.has = 1;
		backend->answering.value = client != NULL;
		if (!client) {
			continue;
		}
		/* The document is what turns an SSID into a network id and what a
		 * fingerprint is taken of, so without one there is nothing to resolve
		 * against and both answers stay absent. */
		if (desired) {
			ncfg_optbool_t matches = record_says(run_dir, interface, desired, secrets);

			if (emptied(client, desired)) {
				/* The supplicant is holding nothing and the document names
				 * networks, which refutes whatever the record says. */
				matches.has = 1;
				matches.value = 0;
			}
			backend->networks_match = matches;
			note_association(observed, client, interface, desired);
		}
		ncfg_supplicant_client_free(client);
	}
	return 1;
}
