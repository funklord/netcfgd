/*
 * device.c -- `org.freedesktop.NetworkManager.Device`, one per netcfgd device.
 *
 * Thirty-one properties, which is what libnm reads for each device in its list.
 * Declared whole for the reason `manager.c` gives: a property answering
 * "nothing" is honest, and one absent from the introspection document is a
 * device libnm does not believe in.
 *
 * WHERE THE FACTS COME FROM, AND WHAT IT COSTS
 *   `ncfg_client_devices` answers for every device, and this picks its own out
 *   of that list per property. So a `GetAll` on one device is thirty-one socket
 *   round trips, each fetching the whole list. **That is the no-cache position
 *   `state.h` states, and it is the wrong shape for a tray** -- it is here
 *   because being correct without a cache is a step, and a cache without the
 *   change tracking that invalidates it is a bug. `emit.rs` is where both land
 *   together.
 */
#include "nmc/device.h"

#include <stdio.h>
#include <string.h>

/* NM's device types, by the numbers libnm reads. */
#define NM_DEVICE_TYPE_UNKNOWN    0u
#define NM_DEVICE_TYPE_ETHERNET   1u
#define NM_DEVICE_TYPE_WIFI       2u
#define NM_DEVICE_TYPE_BT         5u
#define NM_DEVICE_TYPE_MODEM      8u
#define NM_DEVICE_TYPE_BOND      10u
#define NM_DEVICE_TYPE_VLAN      11u
#define NM_DEVICE_TYPE_BRIDGE    13u
#define NM_DEVICE_TYPE_GENERIC   14u
#define NM_DEVICE_TYPE_TUN       16u
#define NM_DEVICE_TYPE_IP_TUNNEL 17u
#define NM_DEVICE_TYPE_WIREGUARD 29u
#define NM_DEVICE_TYPE_LOOPBACK  32u

/* NM's device states. */
#define NM_DEVICE_STATE_UNKNOWN       0u
#define NM_DEVICE_STATE_UNMANAGED    10u
#define NM_DEVICE_STATE_UNAVAILABLE  20u
#define NM_DEVICE_STATE_DISCONNECTED 30u
#define NM_DEVICE_STATE_ACTIVATED   100u

#define NM_DEVICE_STATE_REASON_NONE 0u
#define NM_METERED_GUESS_NO         4u

/* One device's current facts, copied out so nothing is owned here. */
typedef struct {
	char name[64];
	char kind[32];
	char mac[48];
	int  present;
	int  configured;
	int  managed;
	int  mtu;
	int  wireless;
	int  carrier;
	int  known;
} facts_t;

/*
 * This device, as netcfgd reports it now.
 *
 * `known` is 0 where netcfgd could not be asked or no longer lists it, and
 * every getter below answers NM's "unknown" for that rather than failing: a
 * device whose daemon is restarting must not make a client's property call
 * raise.
 */
static void facts_for(const nmc_device_slot_t *slot, facts_t *out)
{
	ncfg_client_t *client;
	ncfg_devices_t devices;
	char           err[256] = "";
	size_t         at;

	memset(out, 0, sizeof(*out));
	if (!slot || !slot->name) {
		return;
	}
	(void)snprintf(out->name, sizeof(out->name), "%s", slot->name);
	client = nmc_state_client(slot->state);
	if (!client) {
		return;
	}
	memset(&devices, 0, sizeof(devices));
	if (!ncfg_client_devices(client, &devices, err, sizeof(err))) {
		return;
	}
	for (at = 0u; at < devices.count; at++) {
		const ncfg_device_t *device = &devices.items[at];

		if (!device->name || strcmp(device->name, slot->name) != 0) {
			continue;
		}
		(void)snprintf(out->kind, sizeof(out->kind), "%s", device->kind ? device->kind : "");
		(void)snprintf(out->mac, sizeof(out->mac), "%s", device->mac ? device->mac : "");
		out->present = device->present;
		out->configured = device->configured;
		out->managed = device->managed;
		out->mtu = device->mtu;
		out->known = 1;
		break;
	}
	ncfg_devices_free(&devices);
	/*
	 * **The links, because the device list cannot answer the type.** netcfgd
	 * reports every device in this document with `kind = "physical"` -- its
	 * device kinds describe how a device is CONFIGURED -- so a table mapping
	 * that to NM's type called a wifi card an ethernet port. It showed up the
	 * first time a real device was read over the bus, and would have put the
	 * radio in libnm's wired list with no wifi operations on it.
	 *
	 * `ncfg_link_t.kind` is the KERNEL's link kind, which is the fact NM's
	 * `DeviceType` is about: `wireguard`, `bridge`, `gre`, and `""` for a
	 * real NIC. `wireless` beside it separates a radio from an ethernet port,
	 * both of which are `""`. A failure here leaves the kind empty, which
	 * reads as a real NIC -- the same answer as before and not a worse one.
	 */
	{
		ncfg_links_t links;
		size_t       link;

		memset(&links, 0, sizeof(links));
		if (ncfg_client_links(client, &links, err, sizeof(err))) {
			for (link = 0u; link < links.count; link++) {
				const ncfg_link_t *one = &links.items[link];

				if (!one->name || strcmp(one->name, slot->name) != 0) {
					continue;
				}
				(void)snprintf(out->kind, sizeof(out->kind), "%s",
				    one->kind ? one->kind : "");
				out->wireless = one->wireless;
				out->carrier = one->carrier;
				if (one->mtu > 0) {
					out->mtu = one->mtu;
				}
				if (one->mac && one->mac[0] != '\0') {
					(void)snprintf(out->mac, sizeof(out->mac), "%s",
					    one->mac);
				}
				break;
			}
			ncfg_links_free(&links);
		}
	}
}

/*
 * netcfgd's `kind` as NM's `DeviceType`.
 *
 * **`GENERIC` and not `UNKNOWN` for a kind this table does not know.** libnm
 * treats UNKNOWN as "I have no idea what this is" and hides it from some views;
 * GENERIC is "a device whose type has no special handling", which is exactly
 * true of a netcfgd device this build has not mapped. The difference is whether
 * a user can see their own interface in a list.
 */
dbus_uint32_t nmc_device_type_of(const char *kind, int wireless, const char *name)
{
	/*
	 * Kernel link kinds, which is what `ncfg_link_t.kind` carries. `""` is a
	 * real NIC and needs the two tests below it.
	 */
	static const struct {
		const char   *kind;
		dbus_uint32_t type;
	} KNOWN[] = {
		{ "bridge", NM_DEVICE_TYPE_BRIDGE },
		{ "bond", NM_DEVICE_TYPE_BOND },
		{ "vlan", NM_DEVICE_TYPE_VLAN },
		{ "wireguard", NM_DEVICE_TYPE_WIREGUARD },
		{ "tun", NM_DEVICE_TYPE_TUN },
		{ "tap", NM_DEVICE_TYPE_TUN },
		/* NM's one type for gre, gretap, sit, ipip and erspan alike. */
		{ "gre", NM_DEVICE_TYPE_IP_TUNNEL },
		{ "gretap", NM_DEVICE_TYPE_IP_TUNNEL },
		{ "sit", NM_DEVICE_TYPE_IP_TUNNEL },
		{ "ipip", NM_DEVICE_TYPE_IP_TUNNEL },
		{ "erspan", NM_DEVICE_TYPE_IP_TUNNEL }
	};
	size_t at;

	for (at = 0u; at < sizeof(KNOWN) / sizeof(KNOWN[0]); at++) {
		if (kind && kind[0] != '\0' && strcmp(kind, KNOWN[at].kind) == 0) {
			return KNOWN[at].type;
		}
	}
	/* A real NIC with a radio. The kernel kind is empty for both a wifi card
	 * and an ethernet port, so this is the only thing that separates them. */
	if (wireless) {
		return NM_DEVICE_TYPE_WIFI;
	}
	/*
	 * **Loopback by name, which is a proxy and is written down as one.** NM
	 * reads `IFF_LOOPBACK`; `ncfg_link_t` does not carry interface flags, so
	 * the name is what is available. It is right on every Linux system and
	 * would be wrong on one that renamed `lo`, which nothing does.
	 */
	if (name && strcmp(name, "lo") == 0) {
		return NM_DEVICE_TYPE_LOOPBACK;
	}
	if (kind && kind[0] == '\0') {
		return NM_DEVICE_TYPE_ETHERNET;
	}
	/*
	 * A kernel kind this build has not mapped. **`GENERIC` and not
	 * `UNKNOWN`**: libnm treats UNKNOWN as "no idea what this is" and hides
	 * it from some views, while GENERIC is "a device with no special
	 * handling", which is exactly true. The difference is whether a user can
	 * see their own interface in a list.
	 */
	return NM_DEVICE_TYPE_GENERIC;
}

/* ------------------------------------------------------------- appenders */

static int put_string(DBusMessageIter *into, const char *text)
{
	const char *value = text ? text : "";

	return dbus_message_iter_append_basic(into, DBUS_TYPE_STRING, &value) ? 1 : 0;
}

static int put_path(DBusMessageIter *into, const char *path)
{
	return dbus_message_iter_append_basic(into, DBUS_TYPE_OBJECT_PATH, &path) ? 1 : 0;
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

/* ------------------------------------------------------- the live answers */

#define NMC_FACT(name, body)                                                                  \
	static int name(DBusMessageIter *into, void *object, char *err, size_t err_size)       \
	{                                                                                     \
		facts_t facts;                                                                \
		(void)err;                                                                    \
		(void)err_size;                                                               \
		facts_for(object, &facts);                                                    \
		body                                                                          \
	}

NMC_FACT(say_interface, return put_string(into, facts.name);)
NMC_FACT(say_ip_interface, return put_string(into, facts.name);)
NMC_FACT(say_hw_address, return put_string(into, facts.mac);)
NMC_FACT(say_device_type, return put_u32(into, nmc_device_type_of(facts.kind, facts.wireless, facts.name));)
NMC_FACT(say_managed, return put_bool(into, facts.known && facts.managed);)
NMC_FACT(say_real, return put_bool(into, facts.known && facts.present);)
NMC_FACT(say_mtu, return put_u32(into, facts.mtu > 0 ? (dbus_uint32_t)facts.mtu : 0u);)
/*
 * **`Autoconnect` is whether the document would bring it up, which is what
 * netcfgd's `configured` says.** NM's own meaning is a per-device toggle a
 * client may write; this one is read-only because the answer lives in the
 * document and writing it here would be a second writer for `ncfg`'s job.
 */
NMC_FACT(say_autoconnect, return put_bool(into, facts.known && facts.configured);)

/*
 * The device state, from what netcfgd reports rather than from a state machine.
 *
 * Four rungs and no more: netcfgd does not model NM's twelve, and inventing
 * intermediate ones would put a client through transitions that never happened.
 * `ACTIVATED` for a managed, configured, present device is the claim a client
 * acts on; everything short of that is said exactly.
 */
static int say_state(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	facts_t facts;

	(void)err;
	(void)err_size;
	facts_for(object, &facts);
	if (!facts.known) {
		return put_u32(into, NM_DEVICE_STATE_UNKNOWN);
	}
	if (!facts.present) {
		return put_u32(into, NM_DEVICE_STATE_UNAVAILABLE);
	}
	if (!facts.managed) {
		return put_u32(into, NM_DEVICE_STATE_UNMANAGED);
	}
	return put_u32(into,
	    facts.configured ? NM_DEVICE_STATE_ACTIVATED : NM_DEVICE_STATE_DISCONNECTED);
}

/* `(uu)`: the state, and why. netcfgd gives no reason, and NONE is the honest
 * one rather than a guess at which of NM's forty applies. */
static int say_state_reason(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	DBusMessageIter pair;
	facts_t         facts;
	dbus_uint32_t   state;
	dbus_uint32_t   reason = NM_DEVICE_STATE_REASON_NONE;

	(void)err;
	(void)err_size;
	facts_for(object, &facts);
	if (!facts.known) {
		state = NM_DEVICE_STATE_UNKNOWN;
	} else if (!facts.present) {
		state = NM_DEVICE_STATE_UNAVAILABLE;
	} else if (!facts.managed) {
		state = NM_DEVICE_STATE_UNMANAGED;
	} else {
		state = facts.configured ? NM_DEVICE_STATE_ACTIVATED
		                         : NM_DEVICE_STATE_DISCONNECTED;
	}
	if (!dbus_message_iter_open_container(into, DBUS_TYPE_STRUCT, NULL, &pair)) {
		return 0;
	}
	(void)dbus_message_iter_append_basic(&pair, DBUS_TYPE_UINT32, &state);
	(void)dbus_message_iter_append_basic(&pair, DBUS_TYPE_UINT32, &reason);
	return dbus_message_iter_close_container(into, &pair) ? 1 : 0;
}

/* --------------------------------------------------------- the constants */

#define NMC_CONST(name, body)                                                                 \
	static int name(DBusMessageIter *into, void *object, char *err, size_t err_size)       \
	{                                                                                     \
		(void)object;                                                                 \
		(void)err;                                                                    \
		(void)err_size;                                                               \
		body                                                                          \
	}

/* netcfgd has no udev database and no sysfs identity to offer. NM allows both
 * to be empty and libnm tolerates it; inventing one would be a path a client
 * could try to open. */
NMC_CONST(say_udi, return put_string(into, "");)
NMC_CONST(say_path, return put_string(into, "");)
/* The driver is the kernel's and netcfgd does not read it. */
NMC_CONST(say_driver, return put_string(into, "");)
NMC_CONST(say_driver_version, return put_string(into, "");)
NMC_CONST(say_firmware_version, return put_string(into, "");)
NMC_CONST(say_physical_port_id, return put_string(into, "");)
/* Nothing is missing, because netcfgd does not load firmware or plugins. False
 * here is a fact rather than a default: a true would put a warning on a device
 * that has nothing wrong with it. */
NMC_CONST(say_firmware_missing, return put_bool(into, 0);)
NMC_CONST(say_plugin_missing, return put_bool(into, 0);)
NMC_CONST(say_capabilities, return put_u32(into, 0u);)
NMC_CONST(say_interface_flags, return put_u32(into, 0u);)
NMC_CONST(say_metered, return put_u32(into, NM_METERED_GUESS_NO);)
/* Per-address-family connectivity is not measured per device. */
NMC_CONST(say_ip4_connectivity, return put_u32(into, 0u);)
NMC_CONST(say_ip6_connectivity, return put_u32(into, 0u);)
/* The IP and DHCP config objects are their own interfaces and their own slice;
 * `/` is NM's "no object" and is not an empty string, which is not a valid
 * object path and would make libnm reject the reply. */
NMC_CONST(say_no_object, return put_path(into, "/");)
NMC_CONST(say_no_paths, return put_empty(into, "o");)
/* LLDP is a protocol netcfgd does not speak. */
NMC_CONST(say_no_lldp, return put_empty(into, "a{sv}");)

/* ------------------------------------------------------------ the table */

static const nmc_property_t PROPERTIES[] = {
	{ "Interface", "s", NMC_READ, say_interface, NULL },
	{ "IpInterface", "s", NMC_READ, say_ip_interface, NULL },
	{ "Udi", "s", NMC_READ, say_udi, NULL },
	{ "Path", "s", NMC_READ, say_path, NULL },
	{ "Driver", "s", NMC_READ, say_driver, NULL },
	{ "DriverVersion", "s", NMC_READ, say_driver_version, NULL },
	{ "FirmwareVersion", "s", NMC_READ, say_firmware_version, NULL },
	{ "DeviceType", "u", NMC_READ, say_device_type, NULL },
	{ "State", "u", NMC_READ, say_state, NULL },
	{ "StateReason", "(uu)", NMC_READ, say_state_reason, NULL },
	{ "Managed", "b", NMC_READ, say_managed, NULL },
	{ "Autoconnect", "b", NMC_READ, say_autoconnect, NULL },
	{ "FirmwareMissing", "b", NMC_READ, say_firmware_missing, NULL },
	{ "NmPluginMissing", "b", NMC_READ, say_plugin_missing, NULL },
	{ "Real", "b", NMC_READ, say_real, NULL },
	{ "Mtu", "u", NMC_READ, say_mtu, NULL },
	{ "HwAddress", "s", NMC_READ, say_hw_address, NULL },
	{ "Capabilities", "u", NMC_READ, say_capabilities, NULL },
	{ "InterfaceFlags", "u", NMC_READ, say_interface_flags, NULL },
	{ "Metered", "u", NMC_READ, say_metered, NULL },
	{ "PhysicalPortId", "s", NMC_READ, say_physical_port_id, NULL },
	{ "Ip4Connectivity", "u", NMC_READ, say_ip4_connectivity, NULL },
	{ "Ip6Connectivity", "u", NMC_READ, say_ip6_connectivity, NULL },
	{ "Ip4Config", "o", NMC_READ, say_no_object, NULL },
	{ "Ip6Config", "o", NMC_READ, say_no_object, NULL },
	{ "Dhcp4Config", "o", NMC_READ, say_no_object, NULL },
	{ "Dhcp6Config", "o", NMC_READ, say_no_object, NULL },
	{ "ActiveConnection", "o", NMC_READ, say_no_object, NULL },
	{ "AvailableConnections", "ao", NMC_READ, say_no_paths, NULL },
	{ "Ports", "ao", NMC_READ, say_no_paths, NULL },
	{ "LldpNeighbors", "aa{sv}", NMC_READ, say_no_lldp, NULL }
};

const nmc_interface_t nmc_device_interface = {
	.name = "org.freedesktop.NetworkManager.Device",
	.properties = PROPERTIES,
	.property_count = sizeof(PROPERTIES) / sizeof(PROPERTIES[0]),
	.methods = NULL,
	.method_count = 0u
};
