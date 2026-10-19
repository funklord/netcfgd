/* nmc/active.h -- `Connection.Active`, numbered by its device. */
#ifndef NMC_ACTIVE_H
#define NMC_ACTIVE_H

#include "nmc/device.h"
/* `nmc_profile_kind_t`, which `nmc_active_profile_of` answers with. */
#include "nmc/settings.h"

/* Its object data is an `nmc_device_slot_t *`. */
/*
 * Whether this device has an activation: it is carrying a routable address AND
 * the document gives it a profile. Asked by the device's own property, by the
 * manager's list and by this subtree's resolve, so that the three cannot
 * disagree about whether an object exists.
 */
int nmc_active_exists(const nmc_device_slot_t *slot);

/*
 * Which PROFILE an activation is of, and its id.
 *
 * A device carrying a `network` block is a network activation named by the
 * block; one without is its `interface` block's -- and only where that block
 * is actually served as a profile, because a radio that has joined nothing and
 * a tunnel have no profile at all and naming one hands a client a path that
 * resolves to nothing.
 *
 * **Published for `DeactivateConnection`**, which has to tell the two apart:
 * a network activation is taken down through netcfgd's own disconnect, while
 * an interface is up because the configuration says so and taking it down
 * means changing that. Promoted from `static` rather than copied, for
 * `nmc_admin_principal`'s reason -- the nuance about a block only counting
 * when it is served is the part a second copy would lose.
 */
int nmc_active_profile_of(const nmc_device_slot_t *slot, nmc_profile_kind_t *kind, char *id,
    size_t id_size);

/* The subtree's resolve, which is the device store's filtered by the above. */
void *nmc_active_resolve_for_bus(const char *tail, void *context);

extern const nmc_interface_t nmc_active_interface;

#endif /* NMC_ACTIVE_H */
