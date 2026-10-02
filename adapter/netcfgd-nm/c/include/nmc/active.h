/* nmc/active.h -- `Connection.Active`, numbered by its device. */
#ifndef NMC_ACTIVE_H
#define NMC_ACTIVE_H

#include "nmc/device.h"

/* Its object data is an `nmc_device_slot_t *`. */
/*
 * Whether this device has an activation: it is carrying a routable address AND
 * the document gives it a profile. Asked by the device's own property, by the
 * manager's list and by this subtree's resolve, so that the three cannot
 * disagree about whether an object exists.
 */
int nmc_active_exists(const nmc_device_slot_t *slot);

/* The subtree's resolve, which is the device store's filtered by the above. */
void *nmc_active_resolve_for_bus(const char *tail, void *context);

extern const nmc_interface_t nmc_active_interface;

#endif /* NMC_ACTIVE_H */
