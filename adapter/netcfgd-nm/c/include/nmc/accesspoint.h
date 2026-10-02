/*
 * nmc/accesspoint.h -- scan results as NM's access point objects.
 *
 * WHY THIS STORE KEYS ON THE BSSID
 *   A scan result list is the most volatile thing this shim serves: it is
 *   reordered by signal on every scan and entries come and go as a person walks
 *   about. The device and connection stores key on a name that does not move;
 *   here the only stable identity is the **BSSID**, which is one radio's MAC and
 *   is what a client is really pointing at when it holds `/AccessPoint/7`.
 *
 *   Keyed on anything else and the paths would be a lie within a second: on the
 *   SSID, and two radios of one network share an object; on the list position,
 *   and every path changes when somebody walks across a room.
 *
 * WHAT A STALE SCAN MEANS HERE
 *   `ncfg_scan_t.stale` says why results are the previous scan's. The list is
 *   still served -- last-known is what a client shows while scanning -- and
 *   `LastSeen` is what tells it how old. Hiding a stale list would blank a
 *   network chooser every time a scan was busy.
 */
#ifndef NMC_ACCESSPOINT_H
#define NMC_ACCESSPOINT_H

#include "nmc/state.h"
#include "nmc/bus.h"

#include <stddef.h>

typedef struct {
	char         bssid[32];
	unsigned     number;
	char         label[12];
	int          present;
	/* Copied out of the scan, because the scan is freed before a property is
	 * ever read: a getter holding a pointer into it would be reading freed
	 * memory a second later. */
	char         ssid_hex[72];
	char         name[128];
	int          frequency;
	int          signal;
	int          secured;
	int          enterprise;
	int          owe;
	nmc_state_t *state;
} nmc_ap_slot_t;

typedef struct {
	nmc_ap_slot_t *slots;
	size_t         count;
	size_t         capacity;
	unsigned       next;
	nmc_state_t   *state;
	/* Which radio to scan. The first one netcfgd reports, found once. */
	char           interface[64];
} nmc_aps_t;

void nmc_aps_init(nmc_aps_t *store, nmc_state_t *state);
void nmc_aps_free(nmc_aps_t *store);
int  nmc_aps_refresh(nmc_aps_t *store);

void  *nmc_aps_resolve_for_bus(const char *tail, void *context);
size_t nmc_aps_enumerate_for_bus(const char **names, size_t max, void *context);

extern const nmc_interface_t nmc_accesspoint_interface;

/* dBm as NM's percentage, exposed for its test. */
unsigned char nmc_ap_strength(int dbm);

#endif /* NMC_ACCESSPOINT_H */
