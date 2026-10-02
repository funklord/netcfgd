/* nmc/device.h -- `org.freedesktop.NetworkManager.Device`, per device. */
#ifndef NMC_DEVICE_H
#define NMC_DEVICE_H

#include "nmc/bus.h"
#include "nmc/store.h"

/* Its object data is an `nmc_device_slot_t *`. */
extern const nmc_interface_t nmc_device_interface;

/*
 * A kernel link kind, a radio flag and an interface name as NM's `DeviceType`.
 *
 * Exposed for its test rather than for a second caller: it is pure, it is a
 * table, and it got a wifi card wrong once by reading netcfgd's device kind
 * instead of the kernel's link kind.
 */
dbus_uint32_t nmc_device_type_of(const char *kind, int wireless, const char *name);

#endif /* NMC_DEVICE_H */
