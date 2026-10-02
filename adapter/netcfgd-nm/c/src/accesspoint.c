/* accesspoint.c -- one object per BSSID netcfgd has seen. */
#include "nmc/accesspoint.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* NM's access point flags and security bits. */
#define NM_802_11_AP_FLAGS_NONE     0x0u
#define NM_802_11_AP_FLAGS_PRIVACY  0x1u
#define NM_802_11_AP_SEC_NONE       0x0u
#define NM_802_11_AP_SEC_PAIR_CCMP  0x10u
#define NM_802_11_AP_SEC_GROUP_CCMP 0x100u
#define NM_802_11_AP_SEC_KEY_MGMT_PSK   0x100u
#define NM_802_11_AP_SEC_KEY_MGMT_802_1X 0x200u
#define NM_802_11_AP_SEC_KEY_MGMT_OWE    0x1000u
#define NM_802_11_MODE_INFRA        2u

/*
 * dBm as NM's 0..100.
 *
 * **wpa_supplicant's own mapping, because NM shows what the supplicant
 * reported.** `2 * (dBm + 100)` clamped: -100 dBm and worse is 0, -50 and better
 * is 100. It is not a physical percentage of anything -- no such number exists
 * -- and the point is that a client's bars match what `wpa_cli` would have
 * shown for the same radio. A different curve here would put netcfgd's shim and
 * every other NM client at different bar counts for one access point.
 */
unsigned char nmc_ap_strength(int dbm)
{
	long scaled = 2L * ((long)dbm + 100L);

	if (scaled < 0L) {
		return 0u;
	}
	if (scaled > 100L) {
		return 100u;
	}
	return (unsigned char)scaled;
}

/* ------------------------------------------------------------- the store */

void nmc_aps_init(nmc_aps_t *store, nmc_state_t *state)
{
	memset(store, 0, sizeof(*store));
	store->state = state;
	store->next = 1u;
}

void nmc_aps_free(nmc_aps_t *store)
{
	free(store->slots);
	memset(store, 0, sizeof(*store));
}

static nmc_ap_slot_t *slot_for(nmc_aps_t *store, const char *bssid)
{
	size_t at;

	for (at = 0u; at < store->count; at++) {
		if (strcmp(store->slots[at].bssid, bssid) == 0) {
			return &store->slots[at];
		}
	}
	return NULL;
}

static nmc_ap_slot_t *add(nmc_aps_t *store, const char *bssid)
{
	nmc_ap_slot_t *slot;

	if (store->count == store->capacity) {
		size_t         bigger = store->capacity ? store->capacity * 2u : 32u;
		nmc_ap_slot_t *grown = realloc(store->slots, bigger * sizeof(*grown));

		if (!grown) {
			return NULL;
		}
		store->slots = grown;
		store->capacity = bigger;
	}
	slot = &store->slots[store->count];
	memset(slot, 0, sizeof(*slot));
	(void)snprintf(slot->bssid, sizeof(slot->bssid), "%s", bssid);
	slot->number = store->next++;
	(void)snprintf(slot->label, sizeof(slot->label), "%u", slot->number);
	slot->state = store->state;
	store->count++;
	return slot;
}

/* The radio to scan: the first netcfgd reports, remembered. */
static const char *radio_of(nmc_aps_t *store, ncfg_client_t *client)
{
	ncfg_radios_t radios;
	char          err[256] = "";

	if (store->interface[0] != '\0') {
		return store->interface;
	}
	memset(&radios, 0, sizeof(radios));
	if (ncfg_client_radios(client, &radios, err, sizeof(err))) {
		if (radios.count > 0u && radios.items[0].interface) {
			(void)snprintf(store->interface, sizeof(store->interface), "%s",
			    radios.items[0].interface);
		}
		ncfg_radios_free(&radios);
	}
	return store->interface[0] != '\0' ? store->interface : NULL;
}

int nmc_aps_refresh(nmc_aps_t *store)
{
	ncfg_client_t *client = nmc_state_client(store->state);
	const char        *interface;
	const ncfg_scan_t *scan;
	size_t             at;

	if (!client) {
		return 0;
	}
	interface = radio_of(store, client);
	if (!interface) {
		return 0;
	}
	/*
	 * **Asks netcfgd for results and does not ask it to scan.** A scan takes
	 * seconds and takes the radio, and a property read must not do either: a
	 * client polling `AccessPoints` would otherwise hold the radio
	 * permanently. `ncfg wifi scan` is how a scan is asked for.
	 *
	 * Through the window, so one tick reads one scan rather than two -- the
	 * change detector reads every property twice.
	 */
	scan = nmc_state_scan(store->state, interface);
	if (!scan) {
		return 0;
	}
	for (at = 0u; at < store->count; at++) {
		store->slots[at].present = 0;
	}
	for (at = 0u; at < scan->count; at++) {
		const ncfg_access_point_t *entry = &scan->items[at];
		nmc_ap_slot_t             *slot;

		if (!entry->bssid || entry->bssid[0] == '\0') {
			continue;
		}
		slot = slot_for(store, entry->bssid);
		if (!slot) {
			slot = add(store, entry->bssid);
		}
		if (!slot) {
			continue;
		}
		slot->present = 1;
		(void)snprintf(slot->ssid_hex, sizeof(slot->ssid_hex), "%s",
		    entry->ssid ? entry->ssid : "");
		(void)snprintf(slot->name, sizeof(slot->name), "%s", entry->name ? entry->name : "");
		slot->frequency = entry->frequency;
		slot->signal = entry->signal;
		slot->secured = entry->secured;
		slot->enterprise = entry->enterprise;
		slot->owe = entry->owe;
	}
	return 1;
}

void *nmc_aps_resolve_for_bus(const char *tail, void *context)
{
	nmc_aps_t *store = context;
	unsigned   number = 0u;
	char       extra = '\0';
	size_t     at;

	(void)nmc_aps_refresh(store);
	if (sscanf(tail, "%u%c", &number, &extra) != 1) {
		return NULL;
	}
	for (at = 0u; at < store->count; at++) {
		if (store->slots[at].number == number) {
			return store->slots[at].present ? &store->slots[at] : NULL;
		}
	}
	return NULL;
}

size_t nmc_aps_enumerate_for_bus(const char **names, size_t max, void *context)
{
	nmc_aps_t *store = context;
	size_t     kept = 0u;
	size_t     at;

	(void)nmc_aps_refresh(store);
	for (at = 0u; at < store->count && kept < max; at++) {
		if (store->slots[at].present) {
			names[kept++] = store->slots[at].label;
		}
	}
	return kept;
}

/* ------------------------------------------------------- the properties */

/*
 * The SSID as bytes, decoded from netcfgd's hex.
 *
 * **`ay` and not a string, which is the whole reason netcfgd carries hex.** An
 * SSID is up to 32 arbitrary octets and is not guaranteed to be text, so NM
 * types this as bytes and a client renders it however it likes. Sending the
 * display name here would make a network named in Shift-JIS and one named
 * `(hidden)` indistinguishable -- which is exactly the collapse
 * `ncfg_client.h` says the daemon refuses to make.
 */
static int say_ssid(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	const nmc_ap_slot_t *slot = object;
	DBusMessageIter      bytes;
	size_t               at;
	size_t               length;

	(void)err;
	(void)err_size;
	if (!dbus_message_iter_open_container(into, DBUS_TYPE_ARRAY, "y", &bytes)) {
		return 0;
	}
	length = strlen(slot->ssid_hex);
	for (at = 0u; at + 1u < length; at += 2u) {
		char          pair[3] = { slot->ssid_hex[at], slot->ssid_hex[at + 1u], '\0' };
		unsigned char byte = (unsigned char)strtoul(pair, NULL, 16);

		(void)dbus_message_iter_append_basic(&bytes, DBUS_TYPE_BYTE, &byte);
	}
	return dbus_message_iter_close_container(into, &bytes) ? 1 : 0;
}

static int say_hw_address(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	const nmc_ap_slot_t *slot = object;
	const char          *text = slot->bssid;

	(void)err;
	(void)err_size;
	return dbus_message_iter_append_basic(into, DBUS_TYPE_STRING, &text) ? 1 : 0;
}

static int say_frequency(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	dbus_uint32_t mhz = (dbus_uint32_t)((const nmc_ap_slot_t *)object)->frequency;

	(void)err;
	(void)err_size;
	return dbus_message_iter_append_basic(into, DBUS_TYPE_UINT32, &mhz) ? 1 : 0;
}

static int say_strength(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	unsigned char percent = nmc_ap_strength(((const nmc_ap_slot_t *)object)->signal);

	(void)err;
	(void)err_size;
	return dbus_message_iter_append_basic(into, DBUS_TYPE_BYTE, &percent) ? 1 : 0;
}

/*
 * `Flags` carries one bit that matters: whether joining needs a credential.
 *
 * **OWE counts as privacy.** It encrypts with no credential, so `secured` is
 * false for it and the link is still not open -- a client that read this bit as
 * "needs a password" would be wrong either way, and one that read it as
 * "encrypted" would be wrong only for OWE if this said no.
 */
static int say_flags(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	const nmc_ap_slot_t *slot = object;
	dbus_uint32_t        flags = (slot->secured || slot->owe) ? NM_802_11_AP_FLAGS_PRIVACY
	                                                         : NM_802_11_AP_FLAGS_NONE;

	(void)err;
	(void)err_size;
	return dbus_message_iter_append_basic(into, DBUS_TYPE_UINT32, &flags) ? 1 : 0;
}

/*
 * `RsnFlags` says which key management the access point offers.
 *
 * netcfgd reports three facts -- secured, enterprise, owe -- and not the cipher
 * suites, so the key management bit is set and the pairwise and group ciphers
 * are claimed as CCMP. **That is a narrowing and not a guess**: CCMP is
 * mandatory for WPA2 and everything netcfgd will join, and a client reading
 * these bits is deciding which credential to ask for rather than which cipher to
 * negotiate.
 *
 * `WpaFlags` stays none: the WPA1 era is not what netcfgd joins, and claiming
 * it would have a client offer TKIP.
 */
static int say_rsn_flags(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	const nmc_ap_slot_t *slot = object;
	dbus_uint32_t        flags = NM_802_11_AP_SEC_NONE;

	(void)err;
	(void)err_size;
	if (slot->owe) {
		flags = NM_802_11_AP_SEC_KEY_MGMT_OWE;
	} else if (slot->enterprise) {
		flags = NM_802_11_AP_SEC_KEY_MGMT_802_1X | NM_802_11_AP_SEC_PAIR_CCMP;
	} else if (slot->secured) {
		flags = NM_802_11_AP_SEC_KEY_MGMT_PSK | NM_802_11_AP_SEC_PAIR_CCMP;
	}
	return dbus_message_iter_append_basic(into, DBUS_TYPE_UINT32, &flags) ? 1 : 0;
}

static int say_zero_u32(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	dbus_uint32_t zero = 0u;

	(void)object;
	(void)err;
	(void)err_size;
	return dbus_message_iter_append_basic(into, DBUS_TYPE_UINT32, &zero) ? 1 : 0;
}

static int say_mode(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	dbus_uint32_t infra = NM_802_11_MODE_INFRA;

	(void)object;
	(void)err;
	(void)err_size;
	return dbus_message_iter_append_basic(into, DBUS_TYPE_UINT32, &infra) ? 1 : 0;
}

/*
 * `LastSeen` is NM's `CLOCK_BOOTTIME` seconds, and **-1 means never**.
 *
 * netcfgd publishes no per-entry timestamp, so -1 is said rather than "now":
 * claiming now would have a client treat a list from a stale scan as fresh,
 * which is the distinction `ncfg_scan_t.stale` exists to preserve.
 */
static int say_last_seen(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	dbus_int32_t never = -1;

	(void)object;
	(void)err;
	(void)err_size;
	return dbus_message_iter_append_basic(into, DBUS_TYPE_INT32, &never) ? 1 : 0;
}

static const nmc_property_t PROPERTIES[] = {
	{ "Ssid", "ay", NMC_READ, say_ssid, NULL },
	{ "HwAddress", "s", NMC_READ, say_hw_address, NULL },
	{ "Frequency", "u", NMC_READ, say_frequency, NULL },
	{ "Strength", "y", NMC_READ, say_strength, NULL },
	{ "Flags", "u", NMC_READ, say_flags, NULL },
	{ "WpaFlags", "u", NMC_READ, say_zero_u32, NULL },
	{ "RsnFlags", "u", NMC_READ, say_rsn_flags, NULL },
	{ "Mode", "u", NMC_READ, say_mode, NULL },
	/* The advertised rate and channel width, which netcfgd does not report.
	 * 0 is NM's own "not known" for both. */
	{ "MaxBitrate", "u", NMC_READ, say_zero_u32, NULL },
	{ "Bandwidth", "u", NMC_READ, say_zero_u32, NULL },
	{ "LastSeen", "i", NMC_READ, say_last_seen, NULL }
};

const nmc_interface_t nmc_accesspoint_interface = {
	.name = "org.freedesktop.NetworkManager.AccessPoint",
	.properties = PROPERTIES,
	.property_count = sizeof(PROPERTIES) / sizeof(PROPERTIES[0])
};
