/*
 * nmc/subtypes.h -- the per-type device interfaces, and which one applies.
 */
#ifndef NMC_SUBTYPES_H
#define NMC_SUBTYPES_H

#include "nmc/device.h"

/* `nmc_subtree_t.interfaces_for`: `.Device` and the one subtype that fits. */
const nmc_interface_t *const *nmc_device_interfaces_for(void *object);

#endif /* NMC_SUBTYPES_H */
