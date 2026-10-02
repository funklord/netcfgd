/*
 * nmc/store.h -- which object path belongs to which device, for good.
 *
 * **A number, once assigned, is never reused for a different device**, and
 * that is a contract with clients rather than tidiness. `state.rs` says it
 * plainly: a client caches object paths, so a client holding `/Devices/1`
 * must keep holding it, and handing `/Devices/3` to a second device because
 * the first went away makes every cached path a lie.
 *
 * So the slots only grow. A device that disappears keeps its number and its
 * slot, and the subtree answers `UnknownObject` for it -- which is what a
 * client with a stale path must be told, and is a different answer from
 * silently resolving to somebody else.
 *
 * The cost is a slot per device ever seen by one process. A shim restarts
 * with the daemon, so that is bounded by a session rather than by uptime.
 */
#ifndef NMC_STORE_H
#define NMC_STORE_H

#include "nmc/state.h"

#include <stddef.h>

typedef struct {
	char        *name;    /* the interface name netcfgd uses */
	unsigned     number;  /* the `/Devices/<n>` number, stable for the process */
	int          present; /* 0 once netcfgd stopped reporting it */
	/* The number as text, so `enumerate` can hand out names that outlive
	 * the call without allocating per listing. */
	char         label[12];
	nmc_state_t *state;   /* so a property getter can reach the client */
} nmc_device_slot_t;

typedef struct {
	nmc_device_slot_t *slots;
	size_t             count;
	size_t             capacity;
	unsigned           next;
	nmc_state_t       *state;
} nmc_store_t;

void nmc_store_init(nmc_store_t *store, nmc_state_t *state);
void nmc_store_free(nmc_store_t *store);

/*
 * Bring the store up to date with what netcfgd reports.
 *
 * New names gain a slot and a number; names that have gone are marked absent
 * and keep theirs. Answers 0 only where netcfgd could not be asked, which
 * leaves the previous answer standing rather than emptying the device list --
 * a daemon restarting must not look to a client like every device unplugged.
 */
int nmc_store_refresh(nmc_store_t *store);

/* The slot for a `/Devices/<tail>` path, or NULL. */
nmc_device_slot_t *nmc_store_resolve(nmc_store_t *store, const char *tail);

/* The object path for a device name, or NULL where it has no slot. */
const char *nmc_store_path_for(nmc_store_t *store, const char *name);

/* `nmc_subtree_t`'s two callbacks, with a `nmc_store_t *` as the context. */
void  *nmc_store_resolve_for_bus(const char *tail, void *context);
size_t nmc_store_enumerate_for_bus(const char **names, size_t max, void *context);

#endif /* NMC_STORE_H */
