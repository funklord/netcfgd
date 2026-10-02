/*
 * nmc/state.h -- what the shim knows, and the one place it asks netcfgd.
 *
 * `state.rs` is 1,295 lines because it also caches, diffs and drives signal
 * emission. This is the half that answers a property: a client handle and the
 * answers fetched through it.
 *
 * **The client is already C.** `client/libncfg_client.a` and
 * `client/ncfg_client.h` are the daemon's own local-hop library, so `client.rs`
 * has no counterpart here to write -- the adapter links what `ncfg` links.
 * That is the one place this port starts ahead of the daemon's.
 *
 * WHY A PROPERTY FETCHES RATHER THAN READS A CACHE
 *   For now, and said rather than left to be discovered: every getter asks
 *   netcfgd. A D-Bus `GetAll` on the manager is then one socket round trip per
 *   property that needs one, which is wrong for a tray polling it and right
 *   for being correct first. The cache belongs with the signal emission it
 *   exists to drive -- `emit.rs`'s job -- and inventing one before then would
 *   be a cache nothing invalidates.
 */
#ifndef NMC_STATE_H
#define NMC_STATE_H

#include "ncfg_client.h"

#include <stddef.h>

/* Forward-declared rather than included: `store.h` includes this, so including
 * it here would be a cycle. The store is reached through this pointer by the
 * one interface that needs it -- the manager, listing device paths. */
struct nmc_store;
struct nmc_connections;

typedef struct {
	/* NULL until the first successful open, and again after netcfgd goes
	 * away: the shim outlives the daemon and must answer while it is gone. */
	ncfg_client_t     *client;
	const char        *socket_path;
	struct nmc_store       *store;
	struct nmc_connections *connections;
} nmc_state_t;

void nmc_state_init(nmc_state_t *state, const char *socket_path);
void nmc_state_free(nmc_state_t *state);

/*
 * A client, opening one if there is none.
 *
 * NULL where netcfgd cannot be reached, which is not an error for most
 * callers: a property whose answer needs the daemon answers with NM's own
 * word for "unknown" rather than failing the call. A D-Bus error for a
 * daemon that is restarting would put an error dialog on a desktop.
 */
ncfg_client_t *nmc_state_client(nmc_state_t *state);

/* Drop a client that has broken, so the next call reopens. */
void nmc_state_broke(nmc_state_t *state);

#endif /* NMC_STATE_H */
