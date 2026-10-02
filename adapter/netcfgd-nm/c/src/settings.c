/*
 * settings.c -- `...Settings` and `...Settings.Connection`, read-only for now.
 *
 * WHAT IS SERVED AND WHAT IS REFUSED, AND WHY THAT IS THE SHAPE
 *   Reads are answered: the connection list, each connection's settings, the
 *   hostname. **Every write is declared and refused**, by name, saying so.
 *
 *   That is deliberate and is not laziness. A write here means `AddConnection`,
 *   `Update` or `Delete` reaching `ncfg_client_config_put`, and doing it
 *   correctly means establishing WHO is asking -- the caller's uid off the
 *   message, against netcfgd's own `control` policy -- before touching a file.
 *   0264 found the Rust shim exporting a method with no authorization at all,
 *   which any local process could call. **A half-built write path is how that
 *   defect gets rewritten**, so the writes refuse until the authorization is
 *   its own slice with its own tests.
 *
 *   A refusal is also what NM itself answers a caller without permission, so a
 *   client meets a shape it already handles rather than a missing method.
 *
 * THE METHOD THIS DELIBERATELY DOES NOT SERVE
 *   `Writable`. 0264 found it exported from the Rust's `Settings.Connection`
 *   by accident -- it sits inside the `#[zbus::interface]` block where
 *   `authorize` and `republish` correctly sit outside it -- with no
 *   authorization, so any local process could call `Writable("anything")` and
 *   learn from the reply whether `/etc/netcfgd/conf.d/nm-<name>.conf` exists.
 *   NetworkManager has no such method, so it is also a difference a client
 *   introspecting the shim can see. It is not ported.
 */
#include "nmc/settings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NMC_SETTINGS_PATH "/org/freedesktop/NetworkManager/Settings"

/* ------------------------------------------------------- the connection store */

void nmc_connections_init(nmc_connections_t *store, nmc_state_t *state)
{
	memset(store, 0, sizeof(*store));
	store->state = state;
	store->next = 1u;
}

void nmc_connections_free(nmc_connections_t *store)
{
	size_t at;

	for (at = 0u; at < store->count; at++) {
		free(store->slots[at].id);
	}
	free(store->slots);
	memset(store, 0, sizeof(*store));
}

static nmc_connection_slot_t *slot_for(nmc_connections_t *store, const char *id)
{
	size_t at;

	for (at = 0u; at < store->count; at++) {
		if (strcmp(store->slots[at].id, id) == 0) {
			return &store->slots[at];
		}
	}
	return NULL;
}

static nmc_connection_slot_t *add(nmc_connections_t *store, const char *id)
{
	nmc_connection_slot_t *slot;

	if (store->count == store->capacity) {
		size_t                 bigger = store->capacity ? store->capacity * 2u : 8u;
		nmc_connection_slot_t *grown = realloc(store->slots, bigger * sizeof(*grown));

		if (!grown) {
			return NULL;
		}
		store->slots = grown;
		store->capacity = bigger;
	}
	slot = &store->slots[store->count];
	memset(slot, 0, sizeof(*slot));
	slot->id = strdup(id);
	if (!slot->id) {
		return NULL;
	}
	slot->number = store->next++;
	(void)snprintf(slot->label, sizeof(slot->label), "%u", slot->number);
	slot->state = store->state;
	store->count++;
	return slot;
}

int nmc_connections_refresh(nmc_connections_t *store)
{
	ncfg_client_t         *client = nmc_state_client(store->state);
	ncfg_saved_networks_t  saved;
	char                   err[256] = "";
	size_t                 at;

	if (!client) {
		return 0;
	}
	memset(&saved, 0, sizeof(saved));
	if (!ncfg_client_saved_networks(client, &saved, err, sizeof(err))) {
		return 0;
	}
	for (at = 0u; at < store->count; at++) {
		store->slots[at].present = 0;
	}
	for (at = 0u; at < saved.count; at++) {
		const char            *id = saved.items[at].id;
		nmc_connection_slot_t *slot;

		if (!id || id[0] == '\0') {
			continue;
		}
		slot = slot_for(store, id);
		if (!slot) {
			slot = add(store, id);
		}
		if (slot) {
			slot->present = 1;
		}
	}
	ncfg_saved_networks_free(&saved);
	return 1;
}

void *nmc_connections_resolve_for_bus(const char *tail, void *context)
{
	nmc_connections_t *store = context;
	unsigned           number = 0u;
	char               extra = '\0';
	size_t             at;

	(void)nmc_connections_refresh(store);
	/* One `%u` and nothing after it, or `/Settings/3x` would resolve to 3. */
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

size_t nmc_connections_enumerate_for_bus(const char **names, size_t max, void *context)
{
	nmc_connections_t *store = context;
	size_t             kept = 0u;
	size_t             at;

	(void)nmc_connections_refresh(store);
	for (at = 0u; at < store->count && kept < max; at++) {
		if (store->slots[at].present) {
			names[kept++] = store->slots[at].label;
		}
	}
	return kept;
}

/* ------------------------------------------------------------- appenders */

static int put_string(DBusMessageIter *into, const char *text)
{
	const char *value = text ? text : "";

	return dbus_message_iter_append_basic(into, DBUS_TYPE_STRING, &value) ? 1 : 0;
}

static int put_bool(DBusMessageIter *into, int yes)
{
	dbus_bool_t value = yes ? TRUE : FALSE;

	return dbus_message_iter_append_basic(into, DBUS_TYPE_BOOLEAN, &value) ? 1 : 0;
}

/*
 * One `name -> variant` pair, for a string value.
 *
 * Only strings, because every field this answers is one. A field of another
 * type gains an appender of its own rather than this growing a type argument:
 * NM's settings dictionary carries `ay`, `u` and `b` too, and a helper that
 * took a `void *` and a signature would be a marshaller with no type checking.
 */
static void put_pair(DBusMessageIter *into, const char *name, const char *text)
{
	DBusMessageIter entry;
	DBusMessageIter variant;
	const char     *value = text ? text : "";

	if (!dbus_message_iter_open_container(into, DBUS_TYPE_DICT_ENTRY, NULL, &entry)) {
		return;
	}
	(void)dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &name);
	if (!dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT, "s", &variant)) {
		(void)dbus_message_iter_abandon_container_if_open(into, &entry);
		return;
	}
	(void)dbus_message_iter_append_basic(&variant, DBUS_TYPE_STRING, &value);
	(void)dbus_message_iter_close_container(&entry, &variant);
	(void)dbus_message_iter_close_container(into, &entry);
}

/* --------------------------------------------------------- `...Settings` */

static int connection_paths(DBusMessageIter *into, nmc_connections_t *store)
{
	DBusMessageIter array;
	const char     *names[256];
	size_t          count = 0u;
	size_t          at;

	if (!dbus_message_iter_open_container(into, DBUS_TYPE_ARRAY, "o", &array)) {
		return 0;
	}
	if (store) {
		count = nmc_connections_enumerate_for_bus(names,
		    sizeof(names) / sizeof(names[0]), store);
	}
	for (at = 0u; at < count; at++) {
		char        path[96];
		const char *as_path = path;

		(void)snprintf(path, sizeof(path), "%s/%s", NMC_SETTINGS_PATH, names[at]);
		(void)dbus_message_iter_append_basic(&array, DBUS_TYPE_OBJECT_PATH, &as_path);
	}
	return dbus_message_iter_close_container(into, &array) ? 1 : 0;
}

static int say_connections(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	nmc_state_t *state = object;

	(void)err;
	(void)err_size;
	return connection_paths(into, state ? (nmc_connections_t *)state->connections : NULL);
}

/*
 * The hostname netcfgd is applying.
 *
 * `"none"` and `"from_dhcp"` are netcfgd's words for "not a static name", and
 * NM's field is the name itself -- so both become empty. Passing `"from_dhcp"`
 * through would be a machine whose hostname a client believes is the literal
 * string `from_dhcp`.
 */
static int say_hostname(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	nmc_state_t    *state = object;
	ncfg_client_t  *client = nmc_state_client(state);
	ncfg_globals_t  globals;
	char            name[256] = "";
	char            problem[256] = "";

	(void)err;
	(void)err_size;
	if (client) {
		memset(&globals, 0, sizeof(globals));
		if (ncfg_client_globals(client, &globals, problem, sizeof(problem))) {
			if (globals.hostname && strcmp(globals.hostname, "none") != 0 &&
			    strcmp(globals.hostname, "from_dhcp") != 0) {
				(void)snprintf(name, sizeof(name), "%s", globals.hostname);
			}
			ncfg_globals_free(&globals);
		}
	}
	return put_string(into, name);
}

/*
 * **`CanModify` is false, and that is the truth about this build.**
 *
 * NM means "may this caller add and change connections", and every write below
 * refuses. A `true` here would have clients offer an "Add network" button that
 * fails when pressed, which is worse than one that is not offered.
 */
static int say_can_modify(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	(void)object;
	(void)err;
	(void)err_size;
	return put_bool(into, 0);
}

static int list_connections(DBusMessage *call, DBusMessage *reply, void *object, char *err,
    size_t err_size)
{
	DBusMessageIter out;
	nmc_state_t    *state = object;

	(void)call;
	(void)err;
	(void)err_size;
	dbus_message_iter_init_append(reply, &out);
	/* The method and the property answer from one function, as on the
	 * manager: a client told two different lists has caught the shim out. */
	return connection_paths(&out, state ? (nmc_connections_t *)state->connections : NULL);
}

/*
 * **Every write, refused by name.**
 *
 * `NotSupported` and not `AccessDenied`: the second says "not you", which would
 * have a client retry as root, and nobody can do this yet. The sentence names
 * `ncfg` because that is where the operation lives today.
 */
static int refuse_write(DBusMessage *call, DBusMessage *reply, void *object, char *err,
    size_t err_size)
{
	(void)call;
	(void)reply;
	(void)object;
	(void)snprintf(err, err_size,
	    "this build of the shim does not write connections: the authorization that "
	    "decides who may is not built yet, and writing without it is the defect 0264 "
	    "found. Use `ncfg wifi add` or edit /etc/netcfgd/conf.d");
	return 0;
}

static const nmc_property_t SETTINGS_PROPERTIES[] = {
	{ "Connections", "ao", NMC_READ, say_connections, NULL },
	{ "Hostname", "s", NMC_READ, say_hostname, NULL },
	{ "CanModify", "b", NMC_READ, say_can_modify, NULL }
};

static const nmc_method_t SETTINGS_METHODS[] = {
	{ "ListConnections", "", "ao", list_connections },
	{ "AddConnection", "a{sa{sv}}", "o", refuse_write },
	{ "AddConnectionUnsaved", "a{sa{sv}}", "o", refuse_write },
	{ "LoadConnections", "as", "bas", refuse_write },
	{ "ReloadConnections", "", "b", refuse_write },
	{ "SaveHostname", "s", "", refuse_write }
};

static const nmc_signal_t SETTINGS_SIGNALS[] = {
	{ "NewConnection", "o" },
	{ "ConnectionRemoved", "o" }
};

const nmc_interface_t nmc_settings_interface = {
	.name = "org.freedesktop.NetworkManager.Settings",
	.properties = SETTINGS_PROPERTIES,
	.property_count = sizeof(SETTINGS_PROPERTIES) / sizeof(SETTINGS_PROPERTIES[0]),
	.methods = SETTINGS_METHODS,
	.method_count = sizeof(SETTINGS_METHODS) / sizeof(SETTINGS_METHODS[0]),
	.signals = SETTINGS_SIGNALS,
	.signal_count = sizeof(SETTINGS_SIGNALS) / sizeof(SETTINGS_SIGNALS[0])
};

/* ---------------------------------------------- `...Settings.Connection` */

/* This connection as netcfgd has it, or 0 where it could not be read. */
static int saved_for(const nmc_connection_slot_t *slot, ncfg_saved_network_t *out, char *keep,
    size_t keep_size)
{
	ncfg_client_t        *client;
	ncfg_saved_networks_t saved;
	char                  err[256] = "";
	size_t                at;
	int                   found = 0;

	memset(out, 0, sizeof(*out));
	keep[0] = '\0';
	if (!slot || !slot->id) {
		return 0;
	}
	client = nmc_state_client(slot->state);
	if (!client) {
		return 0;
	}
	memset(&saved, 0, sizeof(saved));
	if (!ncfg_client_saved_networks(client, &saved, err, sizeof(err))) {
		return 0;
	}
	for (at = 0u; at < saved.count; at++) {
		if (!saved.items[at].id || strcmp(saved.items[at].id, slot->id) != 0) {
			continue;
		}
		/* Only the scalars and one copied string: the list is freed below
		 * and a borrowed pointer would dangle. */
		*out = saved.items[at];
		out->id = NULL;
		out->name = NULL;
		out->ssid = NULL;
		out->security = NULL;
		out->proto = NULL;
		out->credential = NULL;
		(void)snprintf(keep, keep_size, "%s",
		    saved.items[at].name && saved.items[at].name[0] != '\0'
		        ? saved.items[at].name
		        : slot->id);
		found = 1;
		break;
	}
	ncfg_saved_networks_free(&saved);
	return found;
}

/*
 * `Filename` is the file netcfgd would have written for this network.
 *
 * NM's clients show it, and `store.rs`'s `path_for` is the same construction:
 * `conf.d/nm-<id>.conf`. **It is reported and not probed** -- whether the file
 * exists is exactly what 0264's `Writable` leaked, and a client has no business
 * learning it from this interface.
 */
static int say_filename(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	const nmc_connection_slot_t *slot = object;
	char                         path[320];

	(void)err;
	(void)err_size;
	(void)snprintf(path, sizeof(path), "/etc/netcfgd/conf.d/nm-%s.conf",
	    slot && slot->id ? slot->id : "");
	return put_string(into, path);
}

/* Nothing here is ever unsaved: netcfgd's document IS the store, so a
 * connection a client can see is one already written. */
static int say_unsaved(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	(void)object;
	(void)err;
	(void)err_size;
	return put_bool(into, 0);
}

static int say_flags(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	dbus_uint32_t none = 0u;

	(void)object;
	(void)err;
	(void)err_size;
	return dbus_message_iter_append_basic(into, DBUS_TYPE_UINT32, &none) ? 1 : 0;
}

/*
 * `VersionId` changes when the connection does, and NM's clients use it to
 * notice. netcfgd publishes no revision, so **0 is said rather than a number
 * that would look like a version and never move** -- a client comparing two
 * zeroes learns nothing, where a client comparing two 1s would conclude the
 * connection had not changed when it might have.
 */
static int say_version_id(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	dbus_uint64_t none = 0u;

	(void)object;
	(void)err;
	(void)err_size;
	return dbus_message_iter_append_basic(into, DBUS_TYPE_UINT64, &none) ? 1 : 0;
}

/*
 * `GetSettings` -- the connection as NM's nested dictionary.
 *
 * `a{sa{sv}}`: groups of settings, each a name to a variant. This answers the
 * two groups a client needs to show a wifi network in a list -- `connection`
 * and `802-11-wireless` -- and no `802-11-wireless-security`, because **secrets
 * are not in `GetSettings` even in NM**: they come from `GetSecrets`, which
 * refuses here.
 */
static int get_settings(DBusMessage *call, DBusMessage *reply, void *object, char *err,
    size_t err_size)
{
	const nmc_connection_slot_t *slot = object;
	ncfg_saved_network_t         saved;
	char                         shown[256] = "";
	DBusMessageIter              out;
	DBusMessageIter              groups;

	(void)call;
	if (!saved_for(slot, &saved, shown, sizeof(shown))) {
		(void)snprintf(err, err_size,
		    "netcfgd does not report this network; it may have been forgotten");
		return 0;
	}
	dbus_message_iter_init_append(reply, &out);
	if (!dbus_message_iter_open_container(&out, DBUS_TYPE_ARRAY, "{sa{sv}}", &groups)) {
		return 0;
	}
	{
		static const char *const GROUPS[] = { "connection", "802-11-wireless" };
		size_t                   which;

		for (which = 0u; which < sizeof(GROUPS) / sizeof(GROUPS[0]); which++) {
			DBusMessageIter group;
			DBusMessageIter pairs;

			if (!dbus_message_iter_open_container(&groups, DBUS_TYPE_DICT_ENTRY, NULL,
			        &group)) {
				break;
			}
			(void)dbus_message_iter_append_basic(&group, DBUS_TYPE_STRING,
			    &GROUPS[which]);
			if (!dbus_message_iter_open_container(&group, DBUS_TYPE_ARRAY, "{sv}",
			        &pairs)) {
				(void)dbus_message_iter_abandon_container_if_open(&groups, &group);
				break;
			}
			if (which == 0u) {
				/* `id`, `type` and `uuid` are what every NM client
				 * reads first. The id is netcfgd's own, which is
				 * also its uuid here: netcfgd names a network once
				 * and a second identifier would be a second thing
				 * able to disagree. */
				put_pair(&pairs, "id", shown);
				put_pair(&pairs, "type", "802-11-wireless");
				put_pair(&pairs, "uuid", slot->id);
			} else {
				put_pair(&pairs, "mode", "infrastructure");
				put_pair(&pairs, "ssid-text", shown);
			}
			(void)dbus_message_iter_close_container(&group, &pairs);
			(void)dbus_message_iter_close_container(&groups, &group);
		}
	}
	return dbus_message_iter_close_container(&out, &groups) ? 1 : 0;
}

static const nmc_property_t CONNECTION_PROPERTIES[] = {
	{ "Unsaved", "b", NMC_READ, say_unsaved, NULL },
	{ "Flags", "u", NMC_READ, say_flags, NULL },
	{ "Filename", "s", NMC_READ, say_filename, NULL },
	{ "VersionId", "t", NMC_READ, say_version_id, NULL }
};

static const nmc_method_t CONNECTION_METHODS[] = {
	{ "GetSettings", "", "a{sa{sv}}", get_settings },
	/*
	 * `GetSecrets` refuses, and that is not a placeholder. A secret in
	 * netcfgd is a reference -- `@secret:name` -- and the value lives at
	 * 0600 outside the document on purpose. Answering it over this bus would
	 * undo the whole arrangement, and it is a decision for the holder rather
	 * than a slice of a port.
	 */
	{ "GetSecrets", "s", "a{sa{sv}}", refuse_write },
	{ "Update", "a{sa{sv}}", "", refuse_write },
	{ "UpdateUnsaved", "a{sa{sv}}", "", refuse_write },
	{ "Delete", "", "", refuse_write },
	{ "Save", "", "", refuse_write },
	{ "ClearSecrets", "", "", refuse_write }
};

static const nmc_signal_t CONNECTION_SIGNALS[] = {
	{ "Updated", "" },
	{ "Removed", "" }
};

const nmc_interface_t nmc_connection_interface = {
	.name = "org.freedesktop.NetworkManager.Settings.Connection",
	.properties = CONNECTION_PROPERTIES,
	.property_count = sizeof(CONNECTION_PROPERTIES) / sizeof(CONNECTION_PROPERTIES[0]),
	.methods = CONNECTION_METHODS,
	.method_count = sizeof(CONNECTION_METHODS) / sizeof(CONNECTION_METHODS[0]),
	.signals = CONNECTION_SIGNALS,
	.signal_count = sizeof(CONNECTION_SIGNALS) / sizeof(CONNECTION_SIGNALS[0])
};
