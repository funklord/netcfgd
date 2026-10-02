/* store.c -- stable device numbering, which clients depend on. */
#include "nmc/store.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NMC_PATH_MAX 96u

void nmc_store_init(nmc_store_t *store, nmc_state_t *state)
{
	memset(store, 0, sizeof(*store));
	store->state = state;
	/*
	 * **Numbering starts at 1 because NM's does.** A client that special-
	 * cases `/Devices/0` is a client nobody has to think about if the number
	 * is never 0.
	 */
	store->next = 1u;
}

void nmc_store_free(nmc_store_t *store)
{
	size_t at;

	for (at = 0u; at < store->count; at++) {
		free(store->slots[at].name);
	}
	free(store->slots);
	memset(store, 0, sizeof(*store));
}

static nmc_device_slot_t *slot_named(nmc_store_t *store, const char *name)
{
	size_t at;

	for (at = 0u; at < store->count; at++) {
		if (strcmp(store->slots[at].name, name) == 0) {
			return &store->slots[at];
		}
	}
	return NULL;
}

static nmc_device_slot_t *add(nmc_store_t *store, const char *name)
{
	nmc_device_slot_t *slot;

	if (store->count == store->capacity) {
		size_t             bigger = store->capacity ? store->capacity * 2u : 8u;
		nmc_device_slot_t *grown = realloc(store->slots, bigger * sizeof(*grown));

		if (!grown) {
			return NULL;
		}
		store->slots = grown;
		store->capacity = bigger;
	}
	slot = &store->slots[store->count];
	memset(slot, 0, sizeof(*slot));
	slot->name = strdup(name);
	if (!slot->name) {
		return NULL;
	}
	slot->number = store->next++;
	(void)snprintf(slot->label, sizeof(slot->label), "%u", slot->number);
	slot->state = store->state;
	store->count++;
	return slot;
}

int nmc_store_refresh(nmc_store_t *store)
{
	const ncfg_devices_t *devices = nmc_state_devices(store->state);
	size_t                at;

	/* The dispatch's own list, so a refresh inside a message that already
	 * fetched one costs nothing. NULL where netcfgd could not be asked, which
	 * leaves the previous answer standing rather than emptying the list. */
	if (!devices) {
		return 0;
	}
	/*
	 * Absent first, then present: a device still reported keeps its slot and
	 * is marked present again, and one that has gone is left absent. Doing
	 * it in this order means a name that is still there is never briefly
	 * absent to a message arriving in between -- which cannot happen in one
	 * thread today and is free to be right about.
	 */
	for (at = 0u; at < store->count; at++) {
		store->slots[at].present = 0;
	}
	for (at = 0u; at < devices->count; at++) {
		const char        *name = devices->items[at].name;
		nmc_device_slot_t *slot;

		if (!name || name[0] == '\0') {
			continue;
		}
		slot = slot_named(store, name);
		if (!slot) {
			slot = add(store, name);
		}
		if (slot) {
			slot->present = 1;
		}
	}
	return 1;
}

nmc_device_slot_t *nmc_store_resolve(nmc_store_t *store, const char *tail)
{
	unsigned number = 0u;
	char     extra = '\0';
	size_t   at;

	/*
	 * **`%u%c` and not `%u`**: `sscanf("3x", "%u", ...)` succeeds and leaves
	 * the `x`, so a path of `/Devices/3x` would resolve to device 3. The
	 * second conversion failing is what proves the tail was only a number.
	 */
	if (sscanf(tail, "%u%c", &number, &extra) != 1) {
		return NULL;
	}
	for (at = 0u; at < store->count; at++) {
		if (store->slots[at].number == number) {
			/* A slot that is no longer present resolves to nothing, so
			 * a client with a stale path is told so rather than being
			 * handed a device that has gone. */
			return store->slots[at].present ? &store->slots[at] : NULL;
		}
	}
	return NULL;
}

const char *nmc_store_path_for(nmc_store_t *store, const char *name)
{
	nmc_device_slot_t *slot = slot_named(store, name);
	static char        path[NMC_PATH_MAX];

	if (!slot) {
		return NULL;
	}
	/*
	 * One buffer, overwritten per call, which is safe for the one caller
	 * shape there is: a property appends the path immediately. A second
	 * caller holding the result across another call would be a bug this
	 * comment is here to prevent.
	 */
	(void)snprintf(path, sizeof(path), "/org/freedesktop/NetworkManager/Devices/%u",
	    slot->number);
	return path;
}

void *nmc_store_resolve_for_bus(const char *tail, void *context)
{
	nmc_store_t *store = context;

	/*
	 * **Refreshed on the way in**, because the subtree stores nothing: a
	 * path for a device that appeared since the last message must resolve,
	 * and one for a device that has gone must not. A failed refresh leaves
	 * the previous answer standing rather than resolving nothing, so a
	 * daemon restart does not make every held path raise.
	 */
	(void)nmc_store_refresh(store);
	return nmc_store_resolve(store, tail);
}

size_t nmc_store_enumerate_for_bus(const char **names, size_t max, void *context)
{
	nmc_store_t *store = context;
	size_t       kept = 0u;
	size_t       at;

	(void)nmc_store_refresh(store);
	for (at = 0u; at < store->count && kept < max; at++) {
		if (store->slots[at].present) {
			names[kept++] = store->slots[at].label;
		}
	}
	return kept;
}
