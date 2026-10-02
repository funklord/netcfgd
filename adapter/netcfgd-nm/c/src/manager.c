/*
 * manager.c -- `org.freedesktop.NetworkManager` at the manager path.
 *
 * Twenty-four properties, every one declared even where this build's answer is
 * an empty list. **That is the point rather than a shortcut.** A client reads
 * the introspection document to decide what to ask, and libnm asks for most of
 * these at startup: a property declared and answering "nothing" is a shim
 * being honest, while one absent from the document is a shim libnm treats as
 * not being NetworkManager at all.
 *
 * WHERE THE ANSWERS COME FROM
 *   Three kinds. A constant, because NM's value is one and the shim's is the
 *   same -- `Capabilities` is empty for a thing with no NM plugins.
 *   A deliberate lie, which is `Version`: clients gate on it, design section
 *   9.3 says so, and `org.netcfgd.Compat` is where the truth is told.
 *   And netcfgd's own answer, through the client.
 *
 *   A property of the third kind whose answer needs a daemon that is not there
 *   returns NM's word for "unknown" rather than a D-Bus error. An error would
 *   put a dialog on a desktop for a daemon that is restarting.
 */
#include "nmc/manager.h"
#include "nmc/store.h"
#include "nmc/device.h"

#include <stdio.h>
#include <string.h>

/* The version of NetworkManager being impersonated. `manager.rs`'s constant. */
#define NMC_CLAIMED_VERSION "1.44.0"

/* NM's own enumerations, by the numbers libnm reads. `enums.rs`. */
#define NM_STATE_UNKNOWN           0u
#define NM_STATE_DISCONNECTED      20u
#define NM_STATE_CONNECTED_GLOBAL  70u
#define NM_CONNECTIVITY_UNKNOWN    0u
#define NM_CONNECTIVITY_FULL       4u
#define NM_METERED_GUESS_NO        4u

/* ------------------------------------------------------------- appenders */

static int say_string(DBusMessageIter *into, const char *text)
{
	return dbus_message_iter_append_basic(into, DBUS_TYPE_STRING, &text) ? 1 : 0;
}

static int say_path(DBusMessageIter *into, const char *path)
{
	return dbus_message_iter_append_basic(into, DBUS_TYPE_OBJECT_PATH, &path) ? 1 : 0;
}

static int put_device_path(DBusMessageIter *into, const char *path)
{
	return dbus_message_iter_append_basic(into, DBUS_TYPE_OBJECT_PATH, &path) ? 1 : 0;
}

static int say_u32(DBusMessageIter *into, dbus_uint32_t value)
{
	return dbus_message_iter_append_basic(into, DBUS_TYPE_UINT32, &value) ? 1 : 0;
}

static int say_bool(DBusMessageIter *into, int yes)
{
	dbus_bool_t value = yes ? TRUE : FALSE;

	return dbus_message_iter_append_basic(into, DBUS_TYPE_BOOLEAN, &value) ? 1 : 0;
}

/* An array of `signature` with nothing in it, which several of these are. */
static int say_empty(DBusMessageIter *into, const char *signature)
{
	DBusMessageIter array;

	if (!dbus_message_iter_open_container(into, DBUS_TYPE_ARRAY, signature, &array)) {
		return 0;
	}
	return dbus_message_iter_close_container(into, &array) ? 1 : 0;
}

/* ------------------------------------------------- what netcfgd answers */

/*
 * The connectivity rung, or no answer.
 *
 * Returns 1 having filled `rung`, or 0 where netcfgd could not be asked --
 * which the two callers turn into NM's `UNKNOWN` rather than into an error.
 */
static int rung_now(nmc_state_t *state, ncfg_rung_t *rung)
{
	ncfg_client_t      *client = nmc_state_client(state);
	ncfg_connectivity_t answer;
	char                err[256] = "";

	if (!client) {
		return 0;
	}
	memset(&answer, 0, sizeof(answer));
	if (!ncfg_client_connectivity(client, &answer, err, sizeof(err))) {
		return 0;
	}
	*rung = answer.rung;
	/* The strings in it are the library's to free and this wants none of
	 * them, so it is freed immediately rather than at the end of a scope
	 * that might grow a return in the middle. */
	ncfg_connectivity_free(&answer);
	return 1;
}

dbus_uint32_t nmc_manager_state_now(nmc_state_t *state)
{
	ncfg_rung_t rung = ncfg_rung_offline;

	if (!rung_now(state, &rung)) {
		/* A netcfgd that cannot be reached is NM's UNKNOWN. A confident
		 * DISCONNECTED would put a permanent warning on a desktop whose
		 * network is fine and whose daemon is restarting. */
		return NM_STATE_UNKNOWN;
	}
	/*
	 * `CONNECTED_GLOBAL` rather than `_SITE` once routed: netcfgd tells the
	 * two apart only where a probe is configured, and claiming the lesser
	 * one would put a warning triangle on every working desktop --
	 * `manager.rs` argues this at length and the argument is unchanged.
	 */
	return rung >= ncfg_rung_routed ? NM_STATE_CONNECTED_GLOBAL : NM_STATE_DISCONNECTED;
}

static int say_state(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	(void)err;
	(void)err_size;
	return say_u32(into, nmc_manager_state_now(object));
}

static int say_connectivity(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	ncfg_rung_t rung = ncfg_rung_offline;

	(void)err;
	(void)err_size;
	if (!rung_now(object, &rung)) {
		return say_u32(into, NM_CONNECTIVITY_UNKNOWN);
	}
	/* `FULL` only for a rung a probe confirmed. Everything below it is
	 * UNKNOWN and not `LIMITED`: netcfgd has not measured limited. */
	return say_u32(into, rung == ncfg_rung_online ? NM_CONNECTIVITY_FULL
	                                              : NM_CONNECTIVITY_UNKNOWN);
}

/* ------------------------------------------------------- the constants */

static int say_version(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	(void)object;
	(void)err;
	(void)err_size;
	/* The lie, said once, where clients gate on it. The truth is
	 * `org.netcfgd.Compat.ClaimedNetworkManagerVersion`. */
	return say_string(into, NMC_CLAIMED_VERSION);
}

/*
 * The same version packed as libnm reads it.
 *
 * `(major << 16) | (minor << 8) | micro`, then a 1 -- `manager.rs`'s
 * `version_info`, whose own test asserts the packing matches the string. Two
 * places saying one version is how they disagree, so this derives from the
 * same macro rather than carrying 0x012c00 as a literal.
 */
static int say_version_info(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	DBusMessageIter array;
	dbus_uint32_t   packed[2];
	unsigned        major = 0;
	unsigned        minor = 0;
	unsigned        micro = 0;

	(void)object;
	(void)err;
	(void)err_size;
	if (sscanf(NMC_CLAIMED_VERSION, "%u.%u.%u", &major, &minor, &micro) != 3) {
		return 0;
	}
	packed[0] = (dbus_uint32_t)((major << 16) | (minor << 8) | micro);
	packed[1] = 1u;
	if (!dbus_message_iter_open_container(into, DBUS_TYPE_ARRAY, "u", &array)) {
		return 0;
	}
	(void)dbus_message_iter_append_basic(&array, DBUS_TYPE_UINT32, &packed[0]);
	(void)dbus_message_iter_append_basic(&array, DBUS_TYPE_UINT32, &packed[1]);
	return dbus_message_iter_close_container(into, &array) ? 1 : 0;
}

#define NMC_CONST_U32(name, value)                                                            \
	static int name(DBusMessageIter *into, void *object, char *err, size_t err_size)      \
	{                                                                                     \
		(void)object;                                                                 \
		(void)err;                                                                    \
		(void)err_size;                                                               \
		return say_u32(into, (value));                                                \
	}

#define NMC_CONST_BOOL(name, value)                                                           \
	static int name(DBusMessageIter *into, void *object, char *err, size_t err_size)      \
	{                                                                                     \
		(void)object;                                                                 \
		(void)err;                                                                    \
		(void)err_size;                                                               \
		return say_bool(into, (value));                                               \
	}

#define NMC_CONST_EMPTY(name, signature)                                                      \
	static int name(DBusMessageIter *into, void *object, char *err, size_t err_size)      \
	{                                                                                     \
		(void)object;                                                                 \
		(void)err;                                                                    \
		(void)err_size;                                                               \
		return say_empty(into, (signature));                                          \
	}

/*
 * `Metered` is `GUESS_NO` and not `UNKNOWN`: netcfgd has a `metered` key per
 * network and the manager-wide answer is about the primary connection, which
 * this build does not track yet -- and NM's own default for an untracked one
 * is the guess rather than the absence.
 */
NMC_CONST_U32(say_metered, NM_METERED_GUESS_NO)
/* No NM plugins, so no capabilities. An empty list is exact. */
NMC_CONST_EMPTY(say_capabilities, "u")
NMC_CONST_U32(say_radio_flags, 0u)
/* netcfgd's commit-confirm is not reachable through this interface. Empty is
 * the truthful answer to "which checkpoints exist here"; an error is not. */
NMC_CONST_EMPTY(say_checkpoints, "o")
/*
 * The active connections: one per device that holds an address.
 *
 * The same list as `Devices` filtered, rather than a store of its own -- a
 * device carrying traffic IS an active connection here, and keeping a second
 * list would be a second thing able to disagree with the first.
 */
static int say_active_connections(DBusMessageIter *into, void *object, char *err,
    size_t err_size)
{
	nmc_state_t    *state = object;
	nmc_store_t    *store = state ? (nmc_store_t *)state->store : NULL;
	DBusMessageIter array;
	const char     *names[256];
	size_t          count = 0u;
	size_t          at;

	(void)err;
	(void)err_size;
	if (!dbus_message_iter_open_container(into, DBUS_TYPE_ARRAY, "o", &array)) {
		return 0;
	}
	if (store) {
		count = nmc_store_enumerate_for_bus(names, sizeof(names) / sizeof(names[0]),
		    store);
	}
	for (at = 0u; at < count; at++) {
		char               path[96];
		nmc_device_slot_t *slot = nmc_store_resolve(store, names[at]);
		char               addresses[1024] = "";

		if (!slot) {
			continue;
		}
		nmc_device_addresses_of(slot, addresses, sizeof(addresses));
		if (addresses[0] == '\0') {
			continue;
		}
		(void)snprintf(path, sizeof(path),
		    "/org/freedesktop/NetworkManager/ActiveConnection/%s", names[at]);
		if (!put_device_path(&array, path)) {
			break;
		}
	}
	return dbus_message_iter_close_container(into, &array) ? 1 : 0;
}

/*
 * Every device netcfgd reports, as object paths.
 *
 * `Devices` and `AllDevices` answer the same list, and `GetDevices` and
 * `GetAllDevices` answer it through the same function -- because a client that
 * asks two ways and is told different things has caught the shim lying. NM
 * distinguishes the two by realness, and every device netcfgd reports is real
 * enough to configure, which is the distinction that matters here.
 */
static int say_device_paths(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	nmc_state_t    *state = object;
	nmc_store_t    *store = state ? (nmc_store_t *)state->store : NULL;
	DBusMessageIter array;
	const char     *names[256];
	size_t          count = 0u;
	size_t          at;

	(void)err;
	(void)err_size;
	if (!dbus_message_iter_open_container(into, DBUS_TYPE_ARRAY, "o", &array)) {
		return 0;
	}
	if (store) {
		count = nmc_store_enumerate_for_bus(names, sizeof(names) / sizeof(names[0]),
		    store);
	}
	for (at = 0u; at < count; at++) {
		char path[96];

		(void)snprintf(path, sizeof(path),
		    "/org/freedesktop/NetworkManager/Devices/%s", names[at]);
		if (!put_device_path(&array, path)) {
			break;
		}
	}
	return dbus_message_iter_close_container(into, &array) ? 1 : 0;
}
/*
 * netcfgd has DNS policy and it is nothing like NM's global configuration
 * blob. Empty says "nothing set here", which is true of THIS INTERFACE;
 * writing netcfgd's policy into NM's shape is the foreign model leaking
 * inward that design section 9.2 forbids.
 */
NMC_CONST_EMPTY(say_global_dns, "{sv}")
NMC_CONST_BOOL(say_startup, 0)
NMC_CONST_BOOL(say_networking_enabled, 1)
NMC_CONST_BOOL(say_wireless_enabled, 1)
NMC_CONST_BOOL(say_wireless_hw_enabled, 1)
NMC_CONST_BOOL(say_wwan_enabled, 0)
NMC_CONST_BOOL(say_wwan_hw_enabled, 0)
/* netcfgd probes when a document asks it to; it has no NM-style global check
 * to offer or to toggle, so both are false and the URI is empty. */
NMC_CONST_BOOL(say_check_available, 0)
NMC_CONST_BOOL(say_check_enabled, 0)

static int say_check_uri(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	(void)object;
	(void)err;
	(void)err_size;
	return say_string(into, "");
}

static int say_no_path(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	(void)object;
	(void)err;
	(void)err_size;
	/* NM's "no object" is the root path and not an empty string, which is
	 * not a valid object path and would make libnm reject the reply. */
	return say_path(into, "/");
}

static int say_no_type(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	(void)object;
	(void)err;
	(void)err_size;
	return say_string(into, "");
}

/* ----------------------------------------------------------- the methods */

static int get_devices(DBusConnection *connection, DBusMessage *call, DBusMessage *reply,
    void *object, char *err, size_t err_size)
{
	DBusMessageIter out;

	(void)connection;
	(void)call;
	dbus_message_iter_init_append(reply, &out);
	/* The method and the property answer from one function, because a client
	 * that asks both and is told different things has caught the shim
	 * lying. */
	return say_device_paths(&out, object, err, err_size);
}

/*
 * `GetDeviceByIpIface`: the name a person types, to the path a client holds.
 *
 * **Through the store, which is the only thing that knows the numbers.** A path
 * computed from a position in the device list would be a second numbering, and
 * the store's whole contract is that a number is never reused -- so a client
 * holding `/Devices/1` keeps holding it. `nmc_store_path_for` is the lookup
 * `say_device_paths` already builds its answer from.
 *
 * It was missing, and it is not a small omission: `tests/live/nm.sh` resolves
 * every device it then reads properties off this way, so fourteen checks about
 * bridges, vlans and tunnels were failing on an empty path rather than on
 * anything those devices said.
 */
static int get_device_by_name(DBusConnection *connection, DBusMessage *call, DBusMessage *reply,
    void *object, char *err, size_t err_size)
{
	nmc_state_t *state = object;
	nmc_store_t *store = state ? (nmc_store_t *)state->store : NULL;
	const char  *name = NULL;
	const char  *path;

	(void)connection;
	if (!dbus_message_get_args(call, NULL, DBUS_TYPE_STRING, &name, DBUS_TYPE_INVALID)) {
		snprintf(err, err_size, "this takes one interface name");
		return 0;
	}
	/* The store is refreshed by the enumeration the device list already does,
	 * and a name netcfgd has stopped reporting has a slot that is not present
	 * -- which `nmc_store_path_for` answers NULL for, as it should: a client
	 * asking for a device that has gone wants to be told so. */
	(void)nmc_store_enumerate_for_bus(NULL, 0u, store);
	path = nmc_store_path_for(store, name);
	if (!path) {
		snprintf(err, err_size, "netcfgd reports no interface called %s",
		    name ? name : "");
		return 0;
	}
	return dbus_message_append_args(reply, DBUS_TYPE_OBJECT_PATH, &path,
	           DBUS_TYPE_INVALID)
	    ? 1
	    : 0;
}

/*
 * `state`, the method, beside `State`, the property.
 *
 * NM serves both and older clients call the lowercase method, so a shim with
 * only the property is one those clients read as a daemon that does not work.
 * One function behind both, for `get_devices`' reason.
 */
static int state_method(DBusConnection *connection, DBusMessage *call, DBusMessage *reply,
    void *object, char *err, size_t err_size)
{
	DBusMessageIter out;

	(void)connection;
	(void)call;
	(void)err;
	(void)err_size;
	dbus_message_iter_init_append(reply, &out);
	return say_state(&out, object, err, err_size);
}

/* ------------------------------------------------------------ the tables */

static const nmc_property_t PROPERTIES[] = {
	{ "Version", "s", NMC_READ, say_version, NULL },
	{ "VersionInfo", "au", NMC_READ, say_version_info, NULL },
	{ "State", "u", NMC_READ, say_state, NULL },
	{ "Connectivity", "u", NMC_READ, say_connectivity, NULL },
	{ "Devices", "ao", NMC_READ, say_device_paths, NULL },
	{ "AllDevices", "ao", NMC_READ, say_device_paths, NULL },
	{ "Checkpoints", "ao", NMC_READ, say_checkpoints, NULL },
	{ "ActiveConnections", "ao", NMC_READ, say_active_connections, NULL },
	{ "PrimaryConnection", "o", NMC_READ, say_no_path, NULL },
	{ "PrimaryConnectionType", "s", NMC_READ, say_no_type, NULL },
	{ "ActivatingConnection", "o", NMC_READ, say_no_path, NULL },
	{ "Startup", "b", NMC_READ, say_startup, NULL },
	{ "NetworkingEnabled", "b", NMC_READ, say_networking_enabled, NULL },
	{ "WirelessEnabled", "b", NMC_READ, say_wireless_enabled, NULL },
	{ "WirelessHardwareEnabled", "b", NMC_READ, say_wireless_hw_enabled, NULL },
	{ "WwanEnabled", "b", NMC_READ, say_wwan_enabled, NULL },
	{ "WwanHardwareEnabled", "b", NMC_READ, say_wwan_hw_enabled, NULL },
	{ "ConnectivityCheckAvailable", "b", NMC_READ, say_check_available, NULL },
	{ "ConnectivityCheckEnabled", "b", NMC_READ, say_check_enabled, NULL },
	{ "ConnectivityCheckUri", "s", NMC_READ, say_check_uri, NULL },
	{ "Metered", "u", NMC_READ, say_metered, NULL },
	{ "Capabilities", "au", NMC_READ, say_capabilities, NULL },
	{ "RadioFlags", "u", NMC_READ, say_radio_flags, NULL },
	{ "GlobalDnsConfiguration", "a{sv}", NMC_READ, say_global_dns, NULL }
};

static const nmc_method_t METHODS[] = {
	{ "GetDevices", "", "ao", get_devices },
	{ "GetAllDevices", "", "ao", get_devices },
	{ "GetDeviceByIpIface", "s", "o", get_device_by_name },
	/* Lowercase, which is NM's spelling for this one and not a slip. */
	{ "state", "", "u", state_method }
};

/*
 * NM's own signals on this interface.
 *
 * Declared and not yet emitted, which is the honest half: a client reads the
 * introspection document to decide whether to subscribe, so a signal nobody
 * declared is a signal nobody waits for. `PropertiesChanged` IS emitted and is
 * not declared here -- it belongs to `org.freedesktop.DBus.Properties`, which
 * `bus.c` publishes for every object.
 */
static const nmc_signal_t SIGNALS[] = {
	/* A device appearing or going. Emitting these needs the device set
	 * diffed, which `nmc_watch_poll` does for properties and not yet for the
	 * list -- so `Devices` changing is what a client currently sees. */
	{ "DeviceAdded", "o" },
	{ "DeviceRemoved", "o" },
	/* NM's manager state, the same value `State` carries. */
	{ "StateChanged", "u" },
	/* NM emits this when its permission set changes. netcfgd's authorization
	 * is a document, so this will fire when `control` changes. */
	{ "CheckPermissions", "" }
};

const nmc_interface_t nmc_manager_interface = {
	.name = "org.freedesktop.NetworkManager",
	.properties = PROPERTIES,
	.property_count = sizeof(PROPERTIES) / sizeof(PROPERTIES[0]),
	.methods = METHODS,
	.method_count = sizeof(METHODS) / sizeof(METHODS[0]),
	.signals = SIGNALS,
	.signal_count = sizeof(SIGNALS) / sizeof(SIGNALS[0])
};
