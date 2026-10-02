/*
 * subtypes.c -- the one interface per device that says what it is.
 *
 * NM puts `org.freedesktop.NetworkManager.Device` on every device and exactly
 * one subtype interface beside it, and **libnm reads the introspection
 * document to decide what a device is.** So serving `.Wireless` on an ethernet
 * port is not a harmless unused interface, it is a lie a client acts on -- it
 * would offer scanning on a device with no radio.
 *
 * WHAT IS HERE AND WHAT IS NOT
 *   Every interface is served with its properties declared. Six of them used to
 *   answer placeholders and now answer from the observation: a bridge's ports, a
 *   vlan's parent and tag, a tunnel's key and port, and which access point a
 *   radio is on. What remains empty is what netcfgd does not observe -- a link's
 *   negotiated speed, a permanent hardware address -- and an empty answer there
 *   is the truth about this build rather than a gap.
 *
 *   **Which interface a device gets is decided inside a window or not at all.**
 *   `nmc_device_type_now` reads netcfgd's lists, which answer NULL outside one,
 *   and an empty kind is a real network card -- so a decision made without a
 *   window makes every device an ethernet port. `bus.c`'s `fallback` opens it
 *   before resolving anything; see the comment there, which is the defect's.
 */
#include "nmc/subtypes.h"
#include "nmc/accesspoint.h"

#include <stdio.h>
#include <string.h>

/* NM's device types, repeated from `device.c` only as the switch's labels. */
#define NM_DEVICE_TYPE_ETHERNET   1u
#define NM_DEVICE_TYPE_WIFI       2u
#define NM_DEVICE_TYPE_BOND      10u
#define NM_DEVICE_TYPE_VLAN      11u
#define NM_DEVICE_TYPE_BRIDGE    13u
#define NM_DEVICE_TYPE_GENERIC   14u
#define NM_DEVICE_TYPE_WIREGUARD 29u
#define NM_DEVICE_TYPE_LOOPBACK  32u

/* NM's wifi mode: this shim only ever reports a station. */
#define NM_802_11_MODE_INFRA 2u

/* ------------------------------------------------------------- appenders */

static int put_string(DBusMessageIter *into, const char *text)
{
	const char *value = text ? text : "";

	return dbus_message_iter_append_basic(into, DBUS_TYPE_STRING, &value) ? 1 : 0;
}

static int put_u32(DBusMessageIter *into, dbus_uint32_t value)
{
	return dbus_message_iter_append_basic(into, DBUS_TYPE_UINT32, &value) ? 1 : 0;
}

static int put_bool(DBusMessageIter *into, int yes)
{
	dbus_bool_t value = yes ? TRUE : FALSE;

	return dbus_message_iter_append_basic(into, DBUS_TYPE_BOOLEAN, &value) ? 1 : 0;
}

static int put_empty(DBusMessageIter *into, const char *signature)
{
	DBusMessageIter array;

	if (!dbus_message_iter_open_container(into, DBUS_TYPE_ARRAY, signature, &array)) {
		return 0;
	}
	return dbus_message_iter_close_container(into, &array) ? 1 : 0;
}

/* ------------------------------------------------------- shared answers */

/*
 * `HwAddress`, which six of these eight declare.
 *
 * It is `device.c`'s answer, reached the same way, because a client reading it
 * from `.Device` and from `.Wired` and being told two things has caught the
 * shim disagreeing with itself.
 */
static int say_hw_address(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	char address[64] = "";

	(void)err;
	(void)err_size;
	nmc_device_address_of(object, address, sizeof(address));
	return put_string(into, address);
}

static int say_carrier(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	(void)err;
	(void)err_size;
	return put_bool(into, nmc_device_carrier_of(object));
}

/*
 * `PermHwAddress` is the permanent address, which netcfgd does not read.
 *
 * **Empty and not the current address.** NM's own is `""` when it cannot read
 * the permanent one, and a client comparing the two to detect MAC randomisation
 * would conclude there is none if this echoed `HwAddress`.
 */
static int say_no_string(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	(void)object;
	(void)err;
	(void)err_size;
	return put_string(into, "");
}

static int say_zero(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	(void)object;
	(void)err;
	(void)err_size;
	return put_u32(into, 0u);
}

static int say_no_strings(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	(void)object;
	(void)err;
	(void)err_size;
	return put_empty(into, "s");
}

/* ------------------------------------------- what netcfgd actually observes */

/*
 * Which access point this radio is on, as a path, or `/`.
 *
 * `/` is NM's "no object" and is the answer for a radio that is scanning, down,
 * or associated to something no scan result covers. A path to an access point
 * the radio is NOT on would have a client show the wrong network as connected,
 * which is worse than showing none.
 */
static int say_active_ap(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	const nmc_device_slot_t *slot = object;
	char                     name[64] = "";
	const char              *path = NULL;
	const char              *answer;

	(void)err;
	(void)err_size;
	nmc_device_name_of(object, name, sizeof(name));
	if (slot && slot->state && slot->state->access_points) {
		path = nmc_aps_active_path(slot->state->access_points, name);
	}
	answer = path ? path : "/";
	return dbus_message_iter_append_basic(into, DBUS_TYPE_OBJECT_PATH, &answer) ? 1 : 0;
}

static int say_ports(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	DBusMessageIter array;
	char            paths[32][64];
	size_t          count;
	size_t          at;

	(void)err;
	(void)err_size;
	count = nmc_device_ports_of(object, paths, sizeof(paths) / sizeof(paths[0]));
	if (!dbus_message_iter_open_container(into, DBUS_TYPE_ARRAY, "o", &array)) {
		return 0;
	}
	for (at = 0u; at < count; at++) {
		const char *path = paths[at];

		if (!dbus_message_iter_append_basic(&array, DBUS_TYPE_OBJECT_PATH, &path)) {
			break;
		}
	}
	return dbus_message_iter_close_container(into, &array) ? 1 : 0;
}

/* The parent's path, or `/` -- NM's "no object", which is what a device with no
 * parent and a device whose parent has no slot both honestly answer. */
static int say_parent(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	const char *path = nmc_device_parent_of(object);
	const char *answer = path ? path : "/";

	(void)err;
	(void)err_size;
	return dbus_message_iter_append_basic(into, DBUS_TYPE_OBJECT_PATH, &answer) ? 1 : 0;
}

static int say_vlan_id(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	(void)err;
	(void)err_size;
	/* 0 is not a valid tag, so it is unambiguous as "the kernel reported
	 * none" -- better than a number this would have to invent. */
	return put_u32(into, (dbus_uint32_t)nmc_device_vlan_id_of(object));
}

static int say_listen_port(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	int           port = nmc_device_listen_port_of(object);
	dbus_uint16_t value;

	(void)err;
	(void)err_size;
	/* A `q` and the daemon reports an int: a port outside the range is a
	 * daemon this build does not understand, and 0 says so rather than
	 * truncating into a plausible wrong port. */
	value = (port > 0 && port <= 65535) ? (dbus_uint16_t)port : 0u;
	return dbus_message_iter_append_basic(into, DBUS_TYPE_UINT16, &value) ? 1 : 0;
}

/*
 * The interface's own public key, as bytes.
 *
 * **`ay` and base64 in, so it is decoded here.** NM types this as the raw
 * 32-byte key and the kernel renders base64, which is what netcfgd carries. A
 * client comparing it against a peer's configured key compares bytes, so sending
 * the text would be a string in a field documented as a key.
 *
 * The PUBLIC key, which is published by design -- it is what a peer needs. The
 * private one never crosses netcfgd's socket.
 */
static int say_public_key(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	static const char ALPHABET[] =
	    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	char            text[64] = "";
	unsigned char   key[48];
	size_t          held = 0u;
	unsigned long   accumulator = 0u;
	int             bits = 0;
	size_t          at;
	DBusMessageIter array;

	(void)err;
	(void)err_size;
	nmc_device_public_key_of(object, text, sizeof(text));
	for (at = 0u; text[at] != '\0' && held < sizeof(key); at++) {
		const char *found;

		if (text[at] == '=') {
			break;
		}
		found = strchr(ALPHABET, text[at]);
		if (!found || text[at] == '\0') {
			/* Not base64. An empty key is the honest answer: a partial
			 * decode would be bytes nobody's key matches. */
			held = 0u;
			break;
		}
		accumulator = (accumulator << 6) | (unsigned long)(found - ALPHABET);
		bits += 6;
		if (bits >= 8) {
			bits -= 8;
			key[held++] = (unsigned char)((accumulator >> bits) & 0xffu);
		}
	}
	if (!dbus_message_iter_open_container(into, DBUS_TYPE_ARRAY, "y", &array)) {
		return 0;
	}
	for (at = 0u; at < held; at++) {
		if (!dbus_message_iter_append_basic(&array, DBUS_TYPE_BYTE, &key[at])) {
			break;
		}
	}
	return dbus_message_iter_close_container(into, &array) ? 1 : 0;
}

/* ----------------------------------------------------------------- Wired */

static const nmc_property_t WIRED_PROPERTIES[] = {
	{ "HwAddress", "s", NMC_READ, say_hw_address, NULL },
	{ "PermHwAddress", "s", NMC_READ, say_no_string, NULL },
	{ "Carrier", "b", NMC_READ, say_carrier, NULL },
	/* The link speed is the driver's and netcfgd does not read it. 0 is NM's
	 * own answer for "not known", not a claim of no throughput. */
	{ "Speed", "u", NMC_READ, say_zero, NULL },
	/* s390 channel devices, which this will never see. */
	{ "S390Subchannels", "as", NMC_READ, say_no_strings, NULL }
};

static const nmc_interface_t WIRED = {
	.name = "org.freedesktop.NetworkManager.Device.Wired",
	.properties = WIRED_PROPERTIES,
	.property_count = sizeof(WIRED_PROPERTIES) / sizeof(WIRED_PROPERTIES[0])
};

/* -------------------------------------------------------------- Wireless */

/*
 * `LastScan` is milliseconds on NM's clock, and **-1 means never**.
 *
 * Not 0, which is a real instant and would tell a client the radio scanned at
 * boot. netcfgd does not publish a scan timestamp, so never is the honest
 * answer until the access point slice lands.
 */
static int say_last_scan(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	dbus_int64_t never = -1;

	(void)object;
	(void)err;
	(void)err_size;
	return dbus_message_iter_append_basic(into, DBUS_TYPE_INT64, &never) ? 1 : 0;
}

static int say_mode(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	(void)object;
	(void)err;
	(void)err_size;
	/* netcfgd joins networks; it does not run this radio as an AP through
	 * this interface, and an access point is `hostapd`'s own device. */
	return put_u32(into, NM_802_11_MODE_INFRA);
}

/*
 * Every access point netcfgd's last scan reported.
 *
 * **Reached through the state rather than through the device**, because a scan
 * belongs to a radio and this shim scans one -- so the list is the same whichever
 * radio asks, and keeping a per-device copy would be a second list able to
 * disagree. A machine with two radios wants a store per radio, which is a change
 * to `nmc_aps_t` and not to this.
 */
static int say_access_points(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	const nmc_device_slot_t *slot = object;
	DBusMessageIter          array;
	const char              *names[256];
	size_t                   count = 0u;
	size_t                   at;

	(void)err;
	(void)err_size;
	if (!dbus_message_iter_open_container(into, DBUS_TYPE_ARRAY, "o", &array)) {
		return 0;
	}
	if (slot && slot->state && slot->state->access_points) {
		count = nmc_aps_enumerate_for_bus(names, sizeof(names) / sizeof(names[0]),
		    slot->state->access_points);
	}
	for (at = 0u; at < count; at++) {
		char        path[96];
		const char *as_path = path;

		(void)snprintf(path, sizeof(path),
		    "/org/freedesktop/NetworkManager/AccessPoint/%s", names[at]);
		(void)dbus_message_iter_append_basic(&array, DBUS_TYPE_OBJECT_PATH, &as_path);
	}
	return dbus_message_iter_close_container(into, &array) ? 1 : 0;
}

static const nmc_property_t WIRELESS_PROPERTIES[] = {
	{ "HwAddress", "s", NMC_READ, say_hw_address, NULL },
	{ "PermHwAddress", "s", NMC_READ, say_no_string, NULL },
	{ "Mode", "u", NMC_READ, say_mode, NULL },
	/* The negotiated rate in kb/s, which netcfgd does not report. */
	{ "Bitrate", "u", NMC_READ, say_zero, NULL },
	{ "WirelessCapabilities", "u", NMC_READ, say_zero, NULL },
	{ "LastScan", "x", NMC_READ, say_last_scan, NULL },
	{ "AccessPoints", "ao", NMC_READ, say_access_points, NULL },
	{ "ActiveAccessPoint", "o", NMC_READ, say_active_ap, NULL }
};

/* The two a client watches to keep a network list up to date. */
static const nmc_signal_t WIRELESS_SIGNALS[] = {
	{ "AccessPointAdded", "o" },
	{ "AccessPointRemoved", "o" }
};

static const nmc_interface_t WIRELESS = {
	.name = "org.freedesktop.NetworkManager.Device.Wireless",
	.properties = WIRELESS_PROPERTIES,
	.property_count = sizeof(WIRELESS_PROPERTIES) / sizeof(WIRELESS_PROPERTIES[0]),
	.signals = WIRELESS_SIGNALS,
	.signal_count = sizeof(WIRELESS_SIGNALS) / sizeof(WIRELESS_SIGNALS[0])
};

/* ------------------------------------------------- Bridge, Bond and Vlan */

static const nmc_property_t BRIDGE_PROPERTIES[] = {
	{ "HwAddress", "s", NMC_READ, say_hw_address, NULL },
	{ "Carrier", "b", NMC_READ, say_carrier, NULL },
	/* NM's spelling, kept because libnm reads this name. A bridge does not
	 * record its ports: each port names its bridge, so this is `master` read
	 * backwards across every link netcfgd reports. */
	{ "Slaves", "ao", NMC_READ, say_ports, NULL }
};

static const nmc_interface_t BRIDGE = {
	.name = "org.freedesktop.NetworkManager.Device.Bridge",
	.properties = BRIDGE_PROPERTIES,
	.property_count = sizeof(BRIDGE_PROPERTIES) / sizeof(BRIDGE_PROPERTIES[0])
};

static const nmc_interface_t BOND = {
	.name = "org.freedesktop.NetworkManager.Device.Bond",
	.properties = BRIDGE_PROPERTIES,
	.property_count = sizeof(BRIDGE_PROPERTIES) / sizeof(BRIDGE_PROPERTIES[0])
};

static const nmc_property_t VLAN_PROPERTIES[] = {
	{ "HwAddress", "s", NMC_READ, say_hw_address, NULL },
	{ "Carrier", "b", NMC_READ, say_carrier, NULL },
	{ "Parent", "o", NMC_READ, say_parent, NULL },
	{ "VlanId", "u", NMC_READ, say_vlan_id, NULL }
};

static const nmc_interface_t VLAN = {
	.name = "org.freedesktop.NetworkManager.Device.Vlan",
	.properties = VLAN_PROPERTIES,
	.property_count = sizeof(VLAN_PROPERTIES) / sizeof(VLAN_PROPERTIES[0])
};

/* ------------------------------------------------------------- WireGuard */

static const nmc_property_t WIREGUARD_PROPERTIES[] = {
	{ "PublicKey", "ay", NMC_READ, say_public_key, NULL },
	{ "ListenPort", "q", NMC_READ, say_listen_port, NULL },
	{ "FwMark", "u", NMC_READ, say_zero, NULL }
};

static const nmc_interface_t WIREGUARD = {
	.name = "org.freedesktop.NetworkManager.Device.WireGuard",
	.properties = WIREGUARD_PROPERTIES,
	.property_count = sizeof(WIREGUARD_PROPERTIES) / sizeof(WIREGUARD_PROPERTIES[0])
};

/* ------------------------------------------------- Generic and Loopback */

static int say_type_description(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	char kind[32] = "";

	(void)err;
	(void)err_size;
	nmc_device_kind_of(object, kind, sizeof(kind));
	/* The kernel's link kind, which is exactly what this field is for: NM
	 * shows it where it has no better word for the device. */
	return put_string(into, kind);
}

static const nmc_property_t GENERIC_PROPERTIES[] = {
	{ "HwAddress", "s", NMC_READ, say_hw_address, NULL },
	{ "TypeDescription", "s", NMC_READ, say_type_description, NULL }
};

static const nmc_interface_t GENERIC = {
	.name = "org.freedesktop.NetworkManager.Device.Generic",
	.properties = GENERIC_PROPERTIES,
	.property_count = sizeof(GENERIC_PROPERTIES) / sizeof(GENERIC_PROPERTIES[0])
};

/*
 * Loopback has no properties, and is served anyway.
 *
 * **A marker interface is not an empty one.** Its presence is how libnm knows
 * the device is the loopback, and leaving it off would make `lo` a device of
 * type 32 serving nothing that corroborates it.
 */
static const nmc_interface_t LOOPBACK = {
	.name = "org.freedesktop.NetworkManager.Device.Loopback",
	.properties = NULL,
	.property_count = 0u
};

/* ------------------------------------------------------- which one, then */

#define NMC_LIST(name, extra)                                                                 \
	static const nmc_interface_t *const name[] = { &nmc_device_interface, (extra), NULL }

NMC_LIST(AS_WIRED, &WIRED);
NMC_LIST(AS_WIRELESS, &WIRELESS);
NMC_LIST(AS_BRIDGE, &BRIDGE);
NMC_LIST(AS_BOND, &BOND);
NMC_LIST(AS_VLAN, &VLAN);
NMC_LIST(AS_WIREGUARD, &WIREGUARD);
NMC_LIST(AS_GENERIC, &GENERIC);
NMC_LIST(AS_LOOPBACK, &LOOPBACK);

const nmc_interface_t *const *nmc_device_interfaces_for(void *object)
{
	switch (nmc_device_type_now(object)) {
	case NM_DEVICE_TYPE_ETHERNET:
		return AS_WIRED;
	case NM_DEVICE_TYPE_WIFI:
		return AS_WIRELESS;
	case NM_DEVICE_TYPE_BRIDGE:
		return AS_BRIDGE;
	case NM_DEVICE_TYPE_BOND:
		return AS_BOND;
	case NM_DEVICE_TYPE_VLAN:
		return AS_VLAN;
	case NM_DEVICE_TYPE_WIREGUARD:
		return AS_WIREGUARD;
	case NM_DEVICE_TYPE_LOOPBACK:
		return AS_LOOPBACK;
	case NM_DEVICE_TYPE_GENERIC:
	default:
		/*
		 * **Generic for everything else, including NM's tunnel type.**
		 * NM serves `.IPTunnel` for a gre; this build does not, and
		 * `.Generic` beside a `DeviceType` of 17 is a device a client
		 * can see and read rather than one it finds with no subtype at
		 * all. The alternative -- serving nothing -- makes libnm treat
		 * it as a device whose class it cannot determine.
		 */
		return AS_GENERIC;
	}
}
