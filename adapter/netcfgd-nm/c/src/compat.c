/*
 * compat.c -- `org.netcfgd.Compat`, where the shim stops pretending.
 *
 * Design section 9.3: the shim lies about `Version` because clients gate on
 * it, so it offers a second interface where the lie is not required. Anything
 * that wants to know it is talking to netcfgd asks here; nothing has to.
 *
 * It is also the first interface this port carried, and deliberately: three
 * properties, two of them plain strings and one an `a{sb}`, which is enough to
 * exercise the whole dispatcher -- a variant, a container inside a variant,
 * and introspection rendered from a table -- against something whose correct
 * answer is a constant.
 */
#include "nmc/compat.h"

#include <string.h>

/* The version of NetworkManager being impersonated. `manager.rs`'s constant. */
#define NMC_CLAIMED_VERSION "1.44.0"

static int say_implementation(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	const char *text = "netcfgd-nm";

	(void)object;
	(void)err;
	(void)err_size;
	return dbus_message_iter_append_basic(into, DBUS_TYPE_STRING, &text) ? 1 : 0;
}

static int say_claimed_version(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	const char *text = NMC_CLAIMED_VERSION;

	(void)object;
	(void)err;
	(void)err_size;
	return dbus_message_iter_append_basic(into, DBUS_TYPE_STRING, &text) ? 1 : 0;
}

/*
 * Which of design section 9.5's tiers this build serves.
 *
 * A map rather than a number, because the tiers are not a ladder: the device
 * view landed before connection activation, and a client that wants one should
 * not have to infer it from the other.
 *
 * **Every entry is `true` and the list is still worth carrying**, because what
 * a client reads is the set of KEYS: a build that cannot activate a connection
 * omits `activation` rather than saying false, and `manager.rs` has said so
 * since the interface existed.
 */
static const char *const SUPPORTED[] = {
	"devices", "device_state", "wifi_scan", "connections", "activation",
	"profile_writes", "profile_writes_wifi_only", "secret_agents", "ip_config",
	"static_addressing", "connection_options"
};

static int say_supported(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	DBusMessageIter array;
	size_t          at;

	(void)object;
	if (!dbus_message_iter_open_container(into, DBUS_TYPE_ARRAY, "{sb}", &array)) {
		snprintf(err, err_size, "no memory for the supported map");
		return 0;
	}
	for (at = 0u; at < sizeof(SUPPORTED) / sizeof(SUPPORTED[0]); at++) {
		DBusMessageIter entry;
		dbus_bool_t     yes = TRUE;

		if (!dbus_message_iter_open_container(&array, DBUS_TYPE_DICT_ENTRY, NULL, &entry)) {
			(void)dbus_message_iter_abandon_container_if_open(into, &array);
			snprintf(err, err_size, "no memory for %s", SUPPORTED[at]);
			return 0;
		}
		(void)dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &SUPPORTED[at]);
		(void)dbus_message_iter_append_basic(&entry, DBUS_TYPE_BOOLEAN, &yes);
		(void)dbus_message_iter_close_container(&array, &entry);
	}
	return dbus_message_iter_close_container(into, &array) ? 1 : 0;
}

static const nmc_property_t PROPERTIES[] = {
	{ "Implementation", "s", NMC_READ, say_implementation, NULL },
	{ "ClaimedNetworkManagerVersion", "s", NMC_READ, say_claimed_version, NULL },
	{ "Supported", "a{sb}", NMC_READ, say_supported, NULL }
};

const nmc_interface_t nmc_compat_interface = {
	.name = "org.netcfgd.Compat",
	.properties = PROPERTIES,
	.property_count = sizeof(PROPERTIES) / sizeof(PROPERTIES[0]),
	.methods = NULL,
	.method_count = 0u
};
