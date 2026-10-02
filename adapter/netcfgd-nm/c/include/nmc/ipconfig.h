/*
 * nmc/ipconfig.h -- `IP4Config` and `IP6Config`, one of each per device.
 *
 * WHY THE NUMBER IS THE DEVICE'S
 *   NM numbers these objects independently. Here `/IP4Config/3` is device 3's,
 *   because netcfgd has **one addressing per interface** -- so a second store
 *   with a second numbering would be two things able to disagree about which
 *   config belongs to which device.
 *
 *   It also inherits the device store's rule for free: numbers are never
 *   reused, so a client holding `/IP4Config/3` can never be handed the config
 *   of a different device that took the number later. That is the property
 *   `state.rs` insisted on for devices, and it matters here for the same
 *   reason.
 *
 * WHAT IS ANSWERED AND FROM WHERE
 *   The addresses are the link's, split on `,` and sorted into families by
 *   whether they contain a `:`. Everything netcfgd does not publish per
 *   interface answers empty, and the resolver is the exception that is
 *   explained at its getter.
 */
#ifndef NMC_IPCONFIG_H
#define NMC_IPCONFIG_H

#include "nmc/device.h"

/* Both take an `nmc_device_slot_t *` as their object data. */
extern const nmc_interface_t nmc_ip4config_interface;
extern const nmc_interface_t nmc_ip6config_interface;

#endif /* NMC_IPCONFIG_H */
