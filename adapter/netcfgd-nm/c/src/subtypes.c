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
 *   Every interface is served with its properties declared, and the ones whose
 *   answer needs a subsystem this port has not reached answer empty. That is
 *   the same position `manager.c` takes and for the same reason: the interface
 *   being PRESENT is what classifies the device, and a client that then reads
 *   an empty access point list has been told the truth about this build.
 *
 *   `.Wireless` has two signals in the Rust and none here. Signals need a
 *   mechanism `bus.h` has no member for, which is `emit.rs`'s slice.
 */
#include "nmc/subtypes.h"

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

static int say_no_paths(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	(void)object;
	(void)err;
	(void)err_size;
	return put_empty(into, "o");
}

static int say_no_strings(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	(void)object;
	(void)err;
	(void)err_size;
	return put_empty(into, "s");
}

static int say_root_path(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	const char *root = "/";

	(void)object;
	(void)err;
	(void)err_size;
	return dbus_message_iter_append_basic(into, DBUS_TYPE_OBJECT_PATH, &root) ? 1 : 0;
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

static const nmc_property_t WIRELESS_PROPERTIES[] = {
	{ "HwAddress", "s", NMC_READ, say_hw_address, NULL },
	{ "PermHwAddress", "s", NMC_READ, say_no_string, NULL },
	{ "Mode", "u", NMC_READ, say_mode, NULL },
	/* The negotiated rate in kb/s, which netcfgd does not report. */
	{ "Bitrate", "u", NMC_READ, say_zero, NULL },
	{ "WirelessCapabilities", "u", NMC_READ, say_zero, NULL },
	{ "LastScan", "x", NMC_READ, say_last_scan, NULL },
	/* Scan results are their own object family and their own slice. An empty
	 * list is "none known", which is true before a scan is published. */
	{ "AccessPoints", "ao", NMC_READ, say_no_paths, NULL },
	{ "ActiveAccessPoint", "o", NMC_READ, say_root_path, NULL }
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
	/* NM's spelling, kept because libnm reads this name. The device's own
	 * `Ports` says the same thing in NM's newer vocabulary and both are
	 * empty until the membership slice lands. */
	{ "Slaves", "ao", NMC_READ, say_no_paths, NULL }
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
	/* The parent device's path, which needs the store to answer and the
	 * kernel's link relationship, which the client does not carry. */
	{ "Parent", "o", NMC_READ, say_root_path, NULL },
	{ "VlanId", "u", NMC_READ, say_zero, NULL }
};

static const nmc_interface_t VLAN = {
	.name = "org.freedesktop.NetworkManager.Device.Vlan",
	.properties = VLAN_PROPERTIES,
	.property_count = sizeof(VLAN_PROPERTIES) / sizeof(VLAN_PROPERTIES[0])
};

/* ------------------------------------------------------------- WireGuard */

/*
 * The public key as bytes, which NM types `ay` and not `s`.
 *
 * Empty until the WireGuard slice: netcfgd has the key and this build does not
 * fetch it, and an empty array is "not published" where a wrong-length one
 * would be a key a client might try to use.
 */
static int say_no_bytes(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	(void)object;
	(void)err;
	(void)err_size;
	return put_empty(into, "y");
}

static int say_u16_zero(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	dbus_uint16_t zero = 0u;

	(void)object;
	(void)err;
	(void)err_size;
	return dbus_message_iter_append_basic(into, DBUS_TYPE_UINT16, &zero) ? 1 : 0;
}

static const nmc_property_t WIREGUARD_PROPERTIES[] = {
	{ "PublicKey", "ay", NMC_READ, say_no_bytes, NULL },
	{ "ListenPort", "q", NMC_READ, say_u16_zero, NULL },
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
