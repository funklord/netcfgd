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

/*
 * Which of netcfgd's two link-shaped blocks a profile came from.
 *
 * **They differ in more than their settings dictionary.** A wifi profile can be
 * activated on any radio -- an SSID is in range of whatever radio can hear it --
 * and an interface profile IS the interface. NM's types say so: `802-11-wireless`
 * carries no device, and `802-3-ethernet` is bound to one.
 */
typedef enum {
	NMC_PROFILE_NETWORK = 0,
	NMC_PROFILE_INTERFACE
} nmc_profile_kind_t;

/* One profile with a path of its own. Numbers never reused, as devices. */
typedef struct {
	char              *id; /* a `network` block's id, or an `interface`'s name */
	nmc_profile_kind_t kind;
	unsigned           number;
	char               label[12];
	int                present;
	/*
	 * Derived once, when the slot is made, and not recomputed per call.
	 *
	 * It cannot change while the slot lives: it is a function of the kind and
	 * the id, and those are what the slot is keyed on. A getter deriving it
	 * again would be a second answer to a settled question, and it has to
	 * outlive the call that returns it.
	 */
	char               uuid[40];
	nmc_state_t       *state;
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
/*
 * The device-to-connection join: a network's id as its object path, or NULL.
 *
 * A lookup and never arithmetic -- the two stores number independently, so
 * `/Devices/3` and `/Settings/3` are unrelated (project.md 10.393, 10.397).
 */
const char *nmc_connections_path_of(nmc_connections_t *store, nmc_profile_kind_t kind,
    const char *id);

/*
 * The slot a uuid names, or NULL.
 *
 * For `GetConnectionByUuid`, which is how a client that stored a reference finds
 * the profile again -- and the reason the uuid is derived rather than generated:
 * the reference survives a restart because nothing made it up in the first place.
 */
nmc_connection_slot_t *nmc_connections_by_uuid(nmc_connections_t *store, const char *uuid);

/*
 * The slot for a profile, where the caller wants what is in it rather than its
 * path -- the derived uuid, which an activation has to report so that a client
 * can match the two.
 */
const nmc_connection_slot_t *nmc_connections_slot_of(nmc_connections_t *store,
    nmc_profile_kind_t kind, const char *id);

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
