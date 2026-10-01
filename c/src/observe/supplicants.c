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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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
 * TWO REFUTATIONS, AND BOTH ARE ONE-DIRECTIONAL
 *   **Empty.** A supplicant holding nothing while the document names networks
 *   cannot be holding them, whatever the record says. The reverse proves
 *   nothing -- a supplicant holding *some* networks may still hold the wrong
 *   ones, and `LIST_NETWORKS` carries no passphrase to tell.
 *
 *   **Disabled.** A network the document says to join automatically, which the
 *   supplicant has been told to leave alone, is a machine that has stopped
 *   matching its configuration -- project.md 10.337. The record says netcfgd
 *   handed the set over and it did; what the record cannot say is that
 *   something disabled one afterwards.
 *
 * WHAT MAKES THIS A RECONCILE RATHER THAN A REPORT
 *   Refuting the record is what `plan/wifi.c` acts on: `networks_match` false
 *   becomes `NCFG_OP_WIFI_SET_PROFILES`, which re-adds every network and
 *   enables each one. So this is an ordinary plan action -- `on_drift` governs
 *   it, a `report` interface says so and changes nothing, the drift hook and
 *   10.330's log line cover it, and a confirm window can revert it. Nothing
 *   new was needed but the question.
 *
 * THE ANSWER THIS TAKES, OF THE FOUR 10.337 NAMES
 *   *Re-enable what `autoconnect` names, and leave the current association
 *   alone.* `set_profiles` sends no `SELECT_NETWORK`, and `ENABLE_NETWORK`
 *   does not deselect, so the station stays where it is.
 *
 *   **The edge, stated rather than discovered: `ncfg wifi connect` stops
 *   pinning future autoconnect.** `SELECT_NETWORK` disables the others, this
 *   pass re-enables them, and the supplicant is then free to move to a network
 *   that ranks better. Joining the WORSE network deliberately therefore holds
 *   only until the next pass.
 *
 *   That is not a regression hiding in a fix; it is the document winning, which
 *   is this project's first constraint. A document whose networks all say
 *   `autoconnect` means "either of these, by metric", and a machine where one
 *   is disabled does not match it. What is genuinely missing is a way to SAY
 *   "only this one, for now" -- `autoconnect = false` on the others says it
 *   permanently and nothing says it temporarily. That is a language gap and is
 *   recorded as one, not closed here.
 */
static int refuted(ncfg_supplicant_client_t *client, const ncfg_document_t *desired)
{
	char                     body[NCFG_SUPPLICANT_REPLY_MAX];
	ncfg_supplicant_entry_t *entries = NULL;
	size_t                   count = 0;
	size_t                   at;
	char                     why[NCFG_ERROR_MAX];

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
	if (count == 0u) {
		ncfg_supplicant_entries_free(entries, count);
		return 1;
	}
	for (at = 0u; at < count; at++) {
		const ncfg_wifi_network_t *network;

		if (!ncfg_supplicant_entry_is_disabled(&entries[at])) {
			continue;
		}
		/* The tree's own matcher, so this agrees with what a join credits a
		 * network by. A `LIST_NETWORKS` row carries neither bssid nor
		 * security to narrow by. */
		network = ncfg_wifi_network_for(desired->networks, desired->network_count,
		    &entries[at].ssid, NULL, -1);
		/* A network the document does not name is not netcfgd's to enable, and
		 * one it names with `autoconnect = false` is disabled because it asked
		 * to be. */
		if (network && network->autoconnect) {
			ncfg_supplicant_entries_free(entries, count);
			return 1;
		}
	}
	ncfg_supplicant_entries_free(entries, count);
	return 0;
}

/* Which network this radio is associated to, written onto the link. */
static void note_association(ncfg_observed_t *observed, ncfg_supplicant_client_t *client,
    const char *interface, const ncfg_document_t *desired)
{
	ncfg_ssid_t                ssid;
	char                       bssid[18];
	char                       key_mgmt[64];
	const ncfg_wifi_network_t *network;
	ncfg_observed_link_t      *link;

	memset(&ssid, 0, sizeof(ssid));
	bssid[0] = '\0';
	key_mgmt[0] = '\0';
	if (!ncfg_supplicant_associated(client, &ssid, bssid, sizeof(bssid), key_mgmt,
	        sizeof(key_mgmt))) {
		return;
	}
	/*
	 * **The security as well as the name and the address**, because this is
	 * the answer the *planner* reads: an interface's routes take the metric of
	 * the network the radio is on, so crediting a join to the wrong one of two
	 * same-named blocks puts the wrong number on every route.
	 */
	network = ncfg_wifi_network_for(desired->networks, desired->network_count, &ssid,
	    bssid[0] ? bssid : NULL, ncfg_supplicant_key_mgmt_security(key_mgmt));
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

/*
 * Whether this process may talk to that socket at all.
 *
 * **`answering: false` is a statement about the SUPPLICANT, and a caller who
 * may not open the socket is not entitled to make it.** wpa_supplicant binds
 * its control socket 0770 root:root, so an ordinary user running `ncfg status`
 * gets EACCES on connect -- and the observation then said the supplicant was
 * not answering, of a supplicant answering the daemon perfectly.
 *
 * Measured on this machine: `/run/netcfgd/observed.json`, which the daemon
 * writes as root, says `answering: true` and names the network, while
 * `ncfg status` run as an ordinary user said false five times out of five.
 * Both readings were correct about what their own process could reach, and one
 * of them was reported as a fact about the machine. project.md 10.333.
 *
 * `observed.h` already has the vocabulary: absent means "nothing asked", which
 * is exactly what a refused connection is.
 */
static int may_ask(const char *directory, const char *interface)
{
	char remote[NCFG_SUPPLICANT_PATH_MAX];
	int  written;

	written = snprintf(remote, sizeof(remote), "%s/%s", directory, interface);
	if (written < 0 || (size_t)written >= sizeof(remote)) {
		return 1; /* Not a path this can judge; let the connect answer. */
	}
	/* Write permission is what `connect` needs on a unix socket. A socket
	 * that is not there at all is a different answer and stays `false`: the
	 * supplicant is gone, which IS a statement about it. */
	if (access(remote, W_OK) == 0) {
		return 1;
	}
	return errno != EACCES && errno != EPERM;
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
		if (!client && !may_ask(directory, interface)) {
			/*
			 * Absent rather than false: this process is not allowed to
			 * ask, so it has nothing to say about whether the supplicant
			 * answers. The daemon, which runs as root, does.
			 */
			backend->answering.has = 0;
			backend->answering.value = 0;
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

			if (refuted(client, desired)) {
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
