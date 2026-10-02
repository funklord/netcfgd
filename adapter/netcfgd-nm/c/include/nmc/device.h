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

/*
 * The facts a subtype interface needs, answered exactly as `.Device` answers
 * them -- a client told two different `HwAddress`es has caught the shim
 * disagreeing with itself.
 */
void          nmc_device_address_of(const nmc_device_slot_t *slot, char *out, size_t out_size);
void          nmc_device_kind_of(const nmc_device_slot_t *slot, char *out, size_t out_size);
int           nmc_device_carrier_of(const nmc_device_slot_t *slot);
void          nmc_device_addresses_of(const nmc_device_slot_t *slot, char *out, size_t out_size);
void          nmc_device_network_of(const nmc_device_slot_t *slot, char *out, size_t out_size);
void          nmc_device_name_of(const nmc_device_slot_t *slot, char *out, size_t out_size);
int           nmc_device_default_route_of(const nmc_device_slot_t *slot);
dbus_uint32_t nmc_device_type_now(const nmc_device_slot_t *slot);

#endif /* NMC_DEVICE_H */
