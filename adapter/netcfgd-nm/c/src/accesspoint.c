/* accesspoint.c -- one object per BSSID netcfgd has seen. */
#include "nmc/accesspoint.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* `strcasecmp`: glibc reaches it through <string.h> and musl does not. */
#include <strings.h>

/* NM's access point flags and security bits. */
#define NM_802_11_AP_FLAGS_NONE     0x0u
#define NM_802_11_AP_FLAGS_PRIVACY  0x1u
/*
 * `NM80211ApSecurityFlags`, and **three of these were wrong in a way that
 * cannot be seen by reading one of them.** `GROUP_CCMP` was 0x100, which is
 * `KEY_MGMT_PSK` -- so every cipher claim silently also claimed a pre-shared
 * key, and a WPA3-only network was rendered "WPA2 WPA3" by nmcli. `PAIR_CCMP`
 * was 0x10, which is `GROUP_WEP40`, and `OWE` was 0x1000, which is OWE in
 * transition mode.
 *
 * The whole ladder is written out rather than the four in use, because that is
 * what makes a collision visible: four values with gaps between them look
 * fine, and a reader can only check them against each other.
 *
 * One number pins them. A WPA2/WPA3 transition access point on the network
 * `enums.rs` was written against reported `RsnFlags` 1416, which is
 * `PAIR_CCMP | GROUP_CCMP | KEY_MGMT_PSK | KEY_MGMT_SAE` and nothing else --
 * so four of these are confirmed by a real daemon's answer, and `bus_test`
 * asserts the sum.
 */
#define NM_802_11_AP_SEC_NONE            0x0u
#define NM_802_11_AP_SEC_PAIR_WEP40      0x1u
#define NM_802_11_AP_SEC_PAIR_WEP104     0x2u
#define NM_802_11_AP_SEC_PAIR_TKIP       0x4u
#define NM_802_11_AP_SEC_PAIR_CCMP       0x8u
#define NM_802_11_AP_SEC_GROUP_WEP40     0x10u
#define NM_802_11_AP_SEC_GROUP_WEP104    0x20u
#define NM_802_11_AP_SEC_GROUP_TKIP      0x40u
#define NM_802_11_AP_SEC_GROUP_CCMP      0x80u
#define NM_802_11_AP_SEC_KEY_MGMT_PSK    0x100u
#define NM_802_11_AP_SEC_KEY_MGMT_802_1X 0x200u
#define NM_802_11_AP_SEC_KEY_MGMT_SAE    0x400u
#define NM_802_11_AP_SEC_KEY_MGMT_OWE    0x800u
#define NM_802_11_AP_SEC_KEY_MGMT_OWE_TM 0x1000u
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
	long clamped = (long)dbm;
	long below;
	long quality;

	/*
	 * **`nm_wifi_utils_level_to_quality`, and not the linear percentage this
	 * used to compute.** `2 * (dBm + 100)` is the formula everybody writes and
	 * it is not NM's: NM treats -40 dBm as perfect and -100 as hopeless and
	 * interpolates across those sixty, which is not a linear map of anything
	 * physical. It matters because every applet's signal-bars widget is
	 * calibrated against NM's numbers rather than against dBm.
	 *
	 * It cannot be checked by reading a dBm and a `Strength` for one access
	 * point, since NM exposes only the percentage. What it can be checked
	 * against is a real daemon's answer: NetworkManager on the machine
	 * `accesspoint.rs` was written on reported 79, and 79 is what this gives
	 * for -53 dBm, an ordinary level for a router in the same room. The old
	 * formula gave 94 for it.
	 */
	if (clamped < -100L) {
		clamped = -100L;
	}
	if (clamped > -40L) {
		clamped = -40L;
	}
	below = -(clamped + 40L); /* 0 at -40 dBm, 60 at -100 */
	quality = 100L - (100L * below) / 60L;
	if (quality < 0L) {
		return 0u;
	}
	if (quality > 100L) {
		return 100u;
	}
	return (unsigned char)quality;
}

dbus_uint32_t nmc_ap_flags_of(int secured, int enterprise, int owe, const char *written,
    const char *proto)
{
	/*
	 * **CCMP claimed rather than observed, which is a narrowing and not a
	 * guess.** netcfgd reports three collapsed facts and not the cipher suites;
	 * CCMP is mandatory for WPA2 and is everything netcfgd will join, and a
	 * client reading these bits is deciding which credential to ask for rather
	 * than which cipher to negotiate. `WpaFlags` stays none for the same
	 * reason, inverted: claiming the WPA1 era would have a client offer TKIP.
	 */
	const dbus_uint32_t ciphers = NM_802_11_AP_SEC_PAIR_CCMP | NM_802_11_AP_SEC_GROUP_CCMP;

	if (written && written[0] != '\0') {
		if (strcmp(written, "psk") == 0) {
			/*
			 * The generation the document pins, and BOTH where it pins
			 * neither: a network accepting WPA2 and WPA3 alike has two key
			 * managements on offer rather than a third kind.
			 */
			dbus_uint32_t key = NM_802_11_AP_SEC_KEY_MGMT_PSK |
			    NM_802_11_AP_SEC_KEY_MGMT_SAE;

			if (proto && strcmp(proto, "wpa2") == 0) {
				key = NM_802_11_AP_SEC_KEY_MGMT_PSK;
			} else if (proto && strcmp(proto, "wpa3") == 0) {
				key = NM_802_11_AP_SEC_KEY_MGMT_SAE;
			}
			return ciphers | key;
		}
		if (strcmp(written, "eap") == 0) {
			return ciphers | NM_802_11_AP_SEC_KEY_MGMT_802_1X;
		}
		if (strcmp(written, "owe") == 0) {
			return ciphers | NM_802_11_AP_SEC_KEY_MGMT_OWE;
		}
		/* "open" is a network with no security, which is what none means. */
		return NM_802_11_AP_SEC_NONE;
	}
	/*
	 * Not written down: the scan's three facts, which is all there is. OWE
	 * first, because `secured` is false for it -- a network that encrypts
	 * without a credential was reported as open until that was ordered this way.
	 */
	if (owe) {
		return ciphers | NM_802_11_AP_SEC_KEY_MGMT_OWE;
	}
	if (enterprise) {
		return ciphers | NM_802_11_AP_SEC_KEY_MGMT_802_1X;
	}
	if (secured) {
		return ciphers | NM_802_11_AP_SEC_KEY_MGMT_PSK;
	}
	return NM_802_11_AP_SEC_NONE;
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
	/*
	 * **The radios list is the kernel's and misses one the document declares.**
	 * netcfgd builds it from `ncfg_link_t.wireless` on purpose, so that a radio
	 * nobody has configured can still be taken on -- which means a managed
	 * device with a `wifi` block over a link the kernel calls something else is
	 * not in it, and `tests/live/nm.sh` is exactly that case. So the document is
	 * asked second, through the same `policy` word `device.c` reads.
	 *
	 * Second and not first: where both answer, the kernel's radio is a real one
	 * and is the better default for a machine with hardware.
	 */
	if (store->interface[0] == '\0') {
		ncfg_devices_t devices;

		memset(&devices, 0, sizeof(devices));
		if (ncfg_client_devices(client, &devices, err, sizeof(err))) {
			size_t at;

			for (at = 0u; at < devices.count; at++) {
				const ncfg_device_t *one = &devices.items[at];

				if (one->managed && one->name && one->policy &&
				    strcmp(one->policy, "wifi") == 0) {
					(void)snprintf(store->interface,
					    sizeof(store->interface), "%s", one->name);
					break;
				}
			}
			ncfg_devices_free(&devices);
		}
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
 * What the DOCUMENT says this network's security is, or NULL for one it does not
 * name.
 *
 * **Exact where a scan is a guess, and this is the network that matters.** A
 * scan reports three collapsed facts -- secured, enterprise, owe -- while the
 * document says `psk` with which generation, `eap`, or `owe`. The network an
 * applet is about to be asked to join is almost always one the document
 * describes, so answering `WPA2-PSK` for a network written down as WPA3 is the
 * wrong answer in the commonest case: a client offers SAE or does not.
 *
 * Keyed on the hex SSID rather than on the name, because an SSID is up to 32
 * arbitrary octets and need not be text -- the hex is what both sides always
 * have.
 */
static const ncfg_saved_network_t *written_down(const nmc_ap_slot_t *slot)
{
	const ncfg_saved_networks_t *saved;
	size_t                       at;

	if (!slot || slot->ssid_hex[0] == '\0') {
		return NULL;
	}
	saved = nmc_state_saved(slot->state);
	if (!saved) {
		return NULL;
	}
	for (at = 0u; at < saved->count; at++) {
		const ncfg_saved_network_t *one = &saved->items[at];

		if (one->ssid && strcasecmp(one->ssid, slot->ssid_hex) == 0) {
			return one;
		}
	}
	return NULL;
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
	const nmc_ap_slot_t        *slot = object;
	const ncfg_saved_network_t *written = written_down(slot);
	/* The document's answer where it has one, so `Flags` and `RsnFlags` cannot
	 * disagree about whether a network is open. */
	int                         private_network = slot->secured || slot->owe;
	dbus_uint32_t               flags;

	if (written && written->security) {
		private_network = strcmp(written->security, "open") != 0 &&
		    written->security[0] != '\0';
	}
	flags = private_network ? NM_802_11_AP_FLAGS_PRIVACY : NM_802_11_AP_FLAGS_NONE;

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
	const nmc_ap_slot_t        *slot = object;
	const ncfg_saved_network_t *written = written_down(slot);
	dbus_uint32_t               flags;

	(void)err;
	(void)err_size;
	flags = nmc_ap_flags_of(slot->secured, slot->enterprise, slot->owe,
	    written ? written->security : NULL, written ? written->proto : NULL);
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
