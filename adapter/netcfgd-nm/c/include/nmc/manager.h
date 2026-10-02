/* nmc/manager.h -- `org.freedesktop.NetworkManager`, at the manager path. */
#ifndef NMC_MANAGER_H
#define NMC_MANAGER_H

#include "nmc/bus.h"
#include "nmc/state.h"

/* Its object data is an `nmc_state_t *`. */
extern const nmc_interface_t nmc_manager_interface;

#endif /* NMC_MANAGER_H */
