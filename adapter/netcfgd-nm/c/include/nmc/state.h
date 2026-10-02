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
	/* `void *` rather than a third forward declaration: `accesspoint.h`
	 * includes this, so naming its type here would be the cycle the other two
	 * avoid, and a third `struct` tag for one pointer is noise. */
	void                   *access_points;
} nmc_state_t;

void nmc_state_init(nmc_state_t *state, const char *socket_path);
void nmc_state_free(nmc_state_t *state);

/*
 * ONE DISPATCH'S WORTH OF FACTS, AND WHY THAT IS THE ONLY HONEST CACHE HERE
 *
 * Every getter asked netcfgd directly, which made a `GetAll` on one device
 * sixty-two socket round trips -- thirty-one properties times a device list and
 * a link list each. That is what starved the loop (project.md 10.364): a sweep
 * took longer than the tick, so `read_write_dispatch` never ran and the shim
 * answered nothing while looking alive.
 *
 * **The fix is a cache whose lifetime is one message.** It is opened when a
 * dispatch begins and closed when it ends, so it cannot go stale -- there is no
 * window in which the world could move and this still be consulted. That is the
 * objection `state.h` used to raise against caching at all, answered by scoping
 * rather than by invalidation: a cache nothing invalidates is a bug, and a cache
 * that cannot outlive its question needs no invalidation.
 *
 * Reads inside one window see one world, which is also correct rather than
 * merely fast: `GetAll` returning a device's state from one fetch and its
 * address from another could describe a device that never existed in either.
 *
 * `begin` nests, because a getter may be reached through another. Only the
 * outermost close frees.
 *
 * **It takes no state, and that is deliberate.** An object's data is a state at
 * one path, a device slot at another and an agent registry at a third, so a
 * window keyed on the caller's data would need every call site to know which it
 * had. The window is a property of the dispatch rather than of any object, and
 * the one process dispatches one message at a time.
 */
typedef struct {
	int            depth;
	int            have_devices;
	int            have_links;
	int            have_radios;
	int            have_scan;
	int            have_status;
	int            have_saved;
	ncfg_devices_t devices;
	ncfg_links_t   links;
	ncfg_radios_t  radios;
	ncfg_scan_t    scan;
	ncfg_wifi_status_t status;
	ncfg_saved_networks_t saved;
} nmc_facts_t;

/* Open and close one window. Unbalanced calls leak a list until the next close,
 * which is why `bus.c` opens exactly once per dispatch and closes on every
 * path out. */
void nmc_window_begin(void);
void nmc_window_end(void);

/*
 * The three lists, fetched once per window.
 *
 * NULL where netcfgd could not be asked. Outside a window they fetch and the
 * caller must not hold the pointer -- which is why nothing calls them outside
 * one, and why they are named `in_window`.
 */
const ncfg_devices_t *nmc_state_devices(nmc_state_t *state);
const ncfg_links_t   *nmc_state_links(nmc_state_t *state);
const ncfg_radios_t  *nmc_state_radios(nmc_state_t *state);

/*
 * The last scan results for `interface`, once per window.
 *
 * **In the window because reading one is the most expensive thing here.** The
 * change detector reads every property twice -- once to compare and once to
 * send -- so an unwindowed scan was two reads per tick, and a tick that landed
 * on the radio took seconds while clients waited. One per window is one per
 * tick.
 *
 * The interface is remembered with the results: a second radio asking in the
 * same window gets its own fetch rather than the first one's answer.
 */
const ncfg_scan_t *nmc_state_scan(nmc_state_t *state, const char *interface);

/*
 * What this radio is doing, once per window.
 *
 * In the window for the reason the scan is, and the reason is measured rather
 * than guessed: the change detector reads every property twice -- once to compare
 * and once to send -- so an unwindowed call is two requests per tick on the one
 * device that can least afford them. 10.365 is this adapter's tick taking a
 * second because of a wifi fetch, and starving the dispatch loop.
 *
 * Like the scan, a second radio in one window replaces the first one's answer
 * rather than being kept beside it.
 */
const ncfg_wifi_status_t *nmc_state_wifi_status(nmc_state_t *state, const char *interface);

/*
 * The saved networks, once per window.
 *
 * In the window because the device-to-connection join reads it per property: a
 * device's `AvailableConnections` and an active connection's `Connection` both
 * need the list, and so does every `Settings.Connection` getter.
 */
const ncfg_saved_networks_t *nmc_state_saved(nmc_state_t *state);

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
