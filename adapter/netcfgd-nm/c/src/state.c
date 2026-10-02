/* state.c -- the client handle, opened late and reopened after a break. */
#include "nmc/state.h"

#include <stdio.h>
#include <string.h>

void nmc_state_init(nmc_state_t *state, const char *socket_path)
{
	memset(state, 0, sizeof(*state));
	state->socket_path = socket_path;
}

void nmc_state_free(nmc_state_t *state)
{
	if (state->client) {
		ncfg_client_close(state->client);
		state->client = NULL;
	}
}

void nmc_state_broke(nmc_state_t *state)
{
	if (state->client) {
		ncfg_client_close(state->client);
		state->client = NULL;
	}
}

ncfg_client_t *nmc_state_client(nmc_state_t *state)
{
	char err[256];

	if (!state) {
		return NULL;
	}
	/*
	 * **A broken client is dropped here rather than at the call that broke
	 * it.** `ncfg_client_broken` is the library's own answer and every
	 * caller would otherwise have to remember to ask; asking once, on the
	 * way in, means a daemon restart costs one failed property and not a
	 * shim that never reconnects.
	 */
	if (state->client && ncfg_client_broken(state->client)) {
		nmc_state_broke(state);
	}
	if (!state->client) {
		err[0] = '\0';
		state->client = ncfg_client_open(state->socket_path, err, sizeof(err));
	}
	return state->client;
}

/* ------------------------------------------------- one dispatch's facts */

/*
 * The window lives in the state because every getter reaches the state and
 * nothing else is common to all of them. One per process, which is right: this
 * shim dispatches one message at a time.
 */
static nmc_facts_t the_facts;
/* Which interface `the_facts.scan` is for, so a second radio is not handed the
 * first one's results. */
static char scanned_for[64];
/* The interface the window's wifi status describes, for the same reason
 * `scanned_for` exists: a second radio asking must get its own answer. */
static char asked_about[64];

void nmc_window_begin(void)
{
	the_facts.depth++;
}

void nmc_window_end(void)
{
	if (the_facts.depth == 0) {
		return;
	}
	the_facts.depth--;
	if (the_facts.depth > 0) {
		return;
	}
	/*
	 * **Freed at the outermost close and not kept for the next message.** A
	 * list that outlived its window would be the stale cache this design
	 * exists to avoid, and the saving is already taken: the expensive thing
	 * was sixty-two fetches inside one message, not one fetch per message.
	 */
	if (the_facts.have_devices) {
		ncfg_devices_free(&the_facts.devices);
		the_facts.have_devices = 0;
	}
	if (the_facts.have_links) {
		ncfg_links_free(&the_facts.links);
		the_facts.have_links = 0;
	}
	if (the_facts.have_radios) {
		ncfg_radios_free(&the_facts.radios);
		the_facts.have_radios = 0;
	}
	if (the_facts.have_inventory) {
		ncfg_inventory_free(&the_facts.inventory);
		the_facts.have_inventory = 0;
	}
	if (the_facts.have_scan) {
		ncfg_scan_free(&the_facts.scan);
		the_facts.have_scan = 0;
	}
	if (the_facts.have_status) {
		ncfg_wifi_status_free(&the_facts.status);
		the_facts.have_status = 0;
	}
	if (the_facts.have_saved) {
		ncfg_saved_networks_free(&the_facts.saved);
		the_facts.have_saved = 0;
	}
	memset(&the_facts.devices, 0, sizeof(the_facts.devices));
	memset(&the_facts.links, 0, sizeof(the_facts.links));
	memset(&the_facts.radios, 0, sizeof(the_facts.radios));
	memset(&the_facts.inventory, 0, sizeof(the_facts.inventory));
	memset(&the_facts.scan, 0, sizeof(the_facts.scan));
	memset(&the_facts.status, 0, sizeof(the_facts.status));
	memset(&the_facts.saved, 0, sizeof(the_facts.saved));
	scanned_for[0] = '\0';
	asked_about[0] = '\0';
}

#define NMC_LIST_IN_WINDOW(name, type, have, field, fetch)                                    \
	const type *name(nmc_state_t *state)                                                  \
	{                                                                                     \
		ncfg_client_t *client;                                                        \
		char           err[256] = "";                                                 \
                                                                                              \
		if (!state || the_facts.depth == 0) {                                          \
			return NULL;                                                          \
		}                                                                             \
		if (the_facts.have) {                                                         \
			return &the_facts.field;                                              \
		}                                                                             \
		client = nmc_state_client(state);                                              \
		if (!client) {                                                                \
			return NULL;                                                          \
		}                                                                             \
		memset(&the_facts.field, 0, sizeof(the_facts.field));                          \
		if (!fetch(client, &the_facts.field, err, sizeof(err))) {                      \
			return NULL;                                                          \
		}                                                                             \
		the_facts.have = 1;                                                           \
		return &the_facts.field;                                                      \
	}

NMC_LIST_IN_WINDOW(nmc_state_devices, ncfg_devices_t, have_devices, devices,
    ncfg_client_devices)
NMC_LIST_IN_WINDOW(nmc_state_links, ncfg_links_t, have_links, links, ncfg_client_links)
NMC_LIST_IN_WINDOW(nmc_state_radios, ncfg_radios_t, have_radios, radios, ncfg_client_radios)
NMC_LIST_IN_WINDOW(nmc_state_inventory, ncfg_inventory_t, have_inventory, inventory,
    ncfg_client_inventory)
NMC_LIST_IN_WINDOW(nmc_state_saved, ncfg_saved_networks_t, have_saved, saved,
    ncfg_client_saved_networks)

const ncfg_scan_t *nmc_state_scan(nmc_state_t *state, const char *interface)
{
	ncfg_client_t *client;
	char           err[256] = "";

	if (!state || the_facts.depth == 0 || !interface || interface[0] == '\0') {
		return NULL;
	}
	if (the_facts.have_scan && strcmp(scanned_for, interface) == 0) {
		return &the_facts.scan;
	}
	client = nmc_state_client(state);
	if (!client) {
		return NULL;
	}
	if (the_facts.have_scan) {
		/* A different radio in one window: the first one's results are
		 * replaced rather than both being kept, because nothing asks for
		 * two at once and a second slot would be a second thing to free. */
		ncfg_scan_free(&the_facts.scan);
		the_facts.have_scan = 0;
	}
	memset(&the_facts.scan, 0, sizeof(the_facts.scan));
	if (!ncfg_client_wifi_scan(client, interface, &the_facts.scan, err, sizeof(err))) {
		return NULL;
	}
	(void)snprintf(scanned_for, sizeof(scanned_for), "%s", interface);
	the_facts.have_scan = 1;
	return &the_facts.scan;
}

const ncfg_wifi_status_t *nmc_state_wifi_status(nmc_state_t *state, const char *interface)
{
	ncfg_client_t *client;
	char           err[256] = "";

	if (!state || the_facts.depth == 0 || !interface || interface[0] == '\0') {
		return NULL;
	}
	if (the_facts.have_status && strcmp(asked_about, interface) == 0) {
		return &the_facts.status;
	}
	client = nmc_state_client(state);
	if (!client) {
		return NULL;
	}
	if (the_facts.have_status) {
		ncfg_wifi_status_free(&the_facts.status);
		the_facts.have_status = 0;
	}
	memset(&the_facts.status, 0, sizeof(the_facts.status));
	if (!ncfg_client_wifi_status(client, interface, &the_facts.status, err, sizeof(err))) {
		return NULL;
	}
	(void)snprintf(asked_about, sizeof(asked_about), "%s", interface);
	the_facts.have_status = 1;
	return &the_facts.status;
}
