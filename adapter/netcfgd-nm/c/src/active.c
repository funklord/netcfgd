/*
 * active.c -- `Connection.Active`, one per device that is carrying something.
 *
 * NM's active connection is the join between a profile and a device: a client
 * reads it to show "this network, on this interface, in this state". netcfgd has
 * the same relation and spells it differently -- a `network` block and the radio
 * that joined it -- so this is a projection rather than a new fact.
 *
 * **Numbered by the device, as the IP configs are**, because netcfgd has one
 * active thing per interface and a second numbering would be a second thing
 * able to disagree.
 */
#include "nmc/active.h"
#include "nmc/settings.h"

#include <stdio.h>
#include <string.h>

/* NM's active connection states. */
#define NM_ACTIVE_CONNECTION_STATE_UNKNOWN      0u
#define NM_ACTIVE_CONNECTION_STATE_ACTIVATED    2u
#define NM_ACTIVE_CONNECTION_STATE_DEACTIVATED  4u

static int put_string(DBusMessageIter *into, const char *text)
{
	const char *value = text ? text : "";

	return dbus_message_iter_append_basic(into, DBUS_TYPE_STRING, &value) ? 1 : 0;
}

static int put_path(DBusMessageIter *into, const char *path)
{
	const char *value = path && path[0] != '\0' ? path : "/";

	return dbus_message_iter_append_basic(into, DBUS_TYPE_OBJECT_PATH, &value) ? 1 : 0;
}

static int put_bool(DBusMessageIter *into, int yes)
{
	dbus_bool_t value = yes ? TRUE : FALSE;

	return dbus_message_iter_append_basic(into, DBUS_TYPE_BOOLEAN, &value) ? 1 : 0;
}

static int put_u32(DBusMessageIter *into, dbus_uint32_t value)
{
	return dbus_message_iter_append_basic(into, DBUS_TYPE_UINT32, &value) ? 1 : 0;
}

/* The network this device is carrying, or "" where it carries none. */
static void network_of(const nmc_device_slot_t *slot, char *out, size_t out_size)
{
	nmc_device_network_of(slot, out, out_size);
}

static int say_id(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	char name[256] = "";

	(void)err;
	(void)err_size;
	network_of(object, name, sizeof(name));
	/*
	 * The network's id, or the interface name where there is none.
	 *
	 * **A wired link has no `network` block and is still active**, and NM's
	 * `Id` is what a client puts in a list -- so the interface name is the
	 * honest label rather than an empty row.
	 */
	if (name[0] == '\0') {
		nmc_device_name_of(object, name, sizeof(name));
	}
	return put_string(into, name);
}

/*
 * `Type` is NM's connection type, from the device's.
 *
 * A radio is `802-11-wireless` and everything else `802-3-ethernet`, which is
 * what NM calls a wired connection even over a bridge: the type describes the
 * PROFILE's medium and NM has no type for "whatever this device is".
 */
static int say_type(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	(void)err;
	(void)err_size;
	return put_string(into,
	    nmc_device_type_now(object) == 2u ? "802-11-wireless" : "802-3-ethernet");
}

static int say_state(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	char addresses[1024] = "";

	(void)err;
	(void)err_size;
	nmc_device_addresses_of(object, addresses, sizeof(addresses));
	/*
	 * **Activated means it holds an address.** NM's own activation is a state
	 * machine this shim does not have, and the question a client is really
	 * asking is whether traffic can leave -- which an address answers and a
	 * carrier does not. A link that is up with no address is `DEACTIVATED`
	 * here rather than a stage of activating, because netcfgd does not
	 * publish stages and inventing them would put a client through
	 * transitions that never happened.
	 */
	return put_u32(into, addresses[0] != '\0' ? NM_ACTIVE_CONNECTION_STATE_ACTIVATED
	                                          : NM_ACTIVE_CONNECTION_STATE_DEACTIVATED);
}

static int say_default(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	(void)err;
	(void)err_size;
	/* Whether this link carries the default route, which is the fact
	 * `ncfg_link_t.default_route` answers and NM calls `Default`. */
	return put_bool(into, nmc_device_default_route_of(object));
}

/* This device's own path, as a one-element array. */
static int say_devices(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	DBusMessageIter array;
	char            path[96];

	(void)err;
	(void)err_size;
	if (!dbus_message_iter_open_container(into, DBUS_TYPE_ARRAY, "o", &array)) {
		return 0;
	}
	(void)snprintf(path, sizeof(path), "/org/freedesktop/NetworkManager/Devices/%u",
	    ((const nmc_device_slot_t *)object)->number);
	(void)put_path(&array, path);
	return dbus_message_iter_close_container(into, &array) ? 1 : 0;
}

#define NMC_OWN_PATH(name, family)                                                            \
	static int name(DBusMessageIter *into, void *object, char *err, size_t err_size)       \
	{                                                                                     \
		char path[96];                                                                \
		(void)err;                                                                    \
		(void)err_size;                                                               \
		(void)snprintf(path, sizeof(path), "/org/freedesktop/NetworkManager/%s/%u",     \
		    (family), ((const nmc_device_slot_t *)object)->number);                    \
		return put_path(into, path);                                                  \
	}

NMC_OWN_PATH(say_ip4, "IP4Config")
NMC_OWN_PATH(say_ip6, "IP6Config")

static int say_no_path(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	(void)object;
	(void)err;
	(void)err_size;
	return put_path(into, "/");
}

static int say_false(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	(void)object;
	(void)err;
	(void)err_size;
	return put_bool(into, 0);
}

static int say_zero(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	(void)object;
	(void)err;
	(void)err_size;
	return put_u32(into, 0u);
}

/*
 * `Connection` points at the settings object for the network this device joined.
 *
 * **A lookup and never arithmetic.** The settings objects are numbered by the
 * CONNECTION store and this one by the DEVICE store, so `/Devices/3` and
 * `/Settings/3` are unrelated -- computing one from the other would hand a
 * client the settings of whatever connection happened to share a number. 10.362
 * answered `/` rather than guess; this asks the connection store for the id the
 * device's link reports.
 *
 * Still `/` for a device carrying no `network` block, which is every wired link
 * here: NM's "no object", and true.
 */
static int say_connection(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	const nmc_device_slot_t *slot = object;
	char                     network[128] = "";
	const char              *path = NULL;

	(void)err;
	(void)err_size;
	nmc_device_network_of(slot, network, sizeof(network));
	if (network[0] != '\0' && slot && slot->state) {
		path = nmc_connections_path_of((nmc_connections_t *)slot->state->connections,
		    NMC_PROFILE_NETWORK, network);
	}
	return put_path(into, path ? path : "/");
}

static const nmc_property_t PROPERTIES[] = {
	{ "Connection", "o", NMC_READ, say_connection, NULL },
	/* NM's `SpecificObject` is the access point for a wifi activation, which
	 * is the access point slice. */
	{ "SpecificObject", "o", NMC_READ, say_no_path, NULL },
	{ "Id", "s", NMC_READ, say_id, NULL },
	/* netcfgd names a network once, so the id is also the uuid -- a second
	 * identifier would be a second thing able to disagree. */
	{ "Uuid", "s", NMC_READ, say_id, NULL },
	{ "Type", "s", NMC_READ, say_type, NULL },
	{ "Devices", "ao", NMC_READ, say_devices, NULL },
	{ "State", "u", NMC_READ, say_state, NULL },
	{ "StateFlags", "u", NMC_READ, say_zero, NULL },
	{ "Default", "b", NMC_READ, say_default, NULL },
	/* IPv6's default route is a separate fact netcfgd does not publish
	 * separately, and false is the safer wrong answer: a client believing
	 * this is the v6 default would route through it. */
	{ "Default6", "b", NMC_READ, say_false, NULL },
	{ "Vpn", "b", NMC_READ, say_false, NULL },
	/* `Controller` is NM's newer name and `Master` the older one. Both are
	 * served because clients of both ages exist, and both answer the same
	 * thing rather than one being left out. */
	{ "Controller", "o", NMC_READ, say_no_path, NULL },
	{ "Master", "o", NMC_READ, say_no_path, NULL },
	{ "Ip4Config", "o", NMC_READ, say_ip4, NULL },
	{ "Ip6Config", "o", NMC_READ, say_ip6, NULL },
	{ "Dhcp4Config", "o", NMC_READ, say_no_path, NULL },
	{ "Dhcp6Config", "o", NMC_READ, say_no_path, NULL }
};

static const nmc_signal_t SIGNALS[] = {
	{ "StateChanged", "uu" }
};

const nmc_interface_t nmc_active_interface = {
	.name = "org.freedesktop.NetworkManager.Connection.Active",
	.properties = PROPERTIES,
	.property_count = sizeof(PROPERTIES) / sizeof(PROPERTIES[0]),
	.signals = SIGNALS,
	.signal_count = sizeof(SIGNALS) / sizeof(SIGNALS[0])
};
