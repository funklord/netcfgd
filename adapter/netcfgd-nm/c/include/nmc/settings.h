/*
 * nmc/settings.h -- the connection store, as NM shapes it.
 *
 * Two interfaces. `...Settings` lists connections at the settings path;
 * `...Settings.Connection` is one per saved network, under a subtree, numbered
 * the way devices are and for the same reason -- a client caches these paths.
 */
#ifndef NMC_SETTINGS_H
#define NMC_SETTINGS_H

#include "nmc/bus.h"
#include "nmc/state.h"

#include <stddef.h>

/* One saved network with a path of its own. Numbers never reused, as devices. */
typedef struct {
	char        *id;     /* the network's id in netcfgd's document */
	unsigned     number;
	char         label[12];
	int          present;
	nmc_state_t *state;
} nmc_connection_slot_t;

typedef struct {
	nmc_connection_slot_t *slots;
	size_t                 count;
	size_t                 capacity;
	unsigned               next;
	nmc_state_t           *state;
} nmc_connections_t;

void nmc_connections_init(nmc_connections_t *store, nmc_state_t *state);
void nmc_connections_free(nmc_connections_t *store);
int  nmc_connections_refresh(nmc_connections_t *store);

/* `nmc_subtree_t`'s callbacks, with an `nmc_connections_t *` as the context. */
void  *nmc_connections_resolve_for_bus(const char *tail, void *context);
size_t nmc_connections_enumerate_for_bus(const char **names, size_t max, void *context);

/*
 * Whether this pointer is the settings object's data rather than a connection's.
 *
 * The two interfaces share one write handler and are handed different object
 * data -- the settings path gets the state, a connection gets its slot -- so
 * the handler has to tell them apart before reaching for a member. Asked by
 * identity rather than by a tag: the state is one object and its address is
 * what distinguishes it.
 */
int nmc_connections_is_state(const void *data);

/* Its object data is an `nmc_state_t *`; the connection's is a slot. */
extern const nmc_interface_t nmc_settings_interface;
extern const nmc_interface_t nmc_connection_interface;

#endif /* NMC_SETTINGS_H */
