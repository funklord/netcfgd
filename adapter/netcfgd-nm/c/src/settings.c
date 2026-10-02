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
#include "nmc/uuid.h"
#include "nmc/authorize.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NMC_SETTINGS_PATH "/org/freedesktop/NetworkManager/Settings"

/* ------------------------------------------------------- the connection store */

/* The one state this process has, remembered so the shared write handler can
 * tell the settings object's data from a connection's slot. */
static const nmc_state_t *the_state;

void nmc_connections_init(nmc_connections_t *store, nmc_state_t *state)
{
	memset(store, 0, sizeof(*store));
	store->state = state;
	store->next = 1u;
	the_state = state;
}

int nmc_connections_is_state(const void *data)
{
	return data != NULL && data == (const void *)the_state;
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

/*
 * **Keyed on the kind as well as the name, because the two can collide.** A
 * `network "wlan0"` and an `interface wlan0` are two profiles, and a lookup on
 * the name alone would hand the second one the first one's slot -- so the
 * interface block would be served as a wireless network. Unlikely and baffling,
 * which is also why the uuid identity carries the prefix.
 */
static nmc_connection_slot_t *slot_for(nmc_connections_t *store, nmc_profile_kind_t kind,
    const char *id)
{
	size_t at;

	for (at = 0u; at < store->count; at++) {
		if (store->slots[at].kind == kind && strcmp(store->slots[at].id, id) == 0) {
			return &store->slots[at];
		}
	}
	return NULL;
}

static nmc_connection_slot_t *add(nmc_connections_t *store, nmc_profile_kind_t kind,
    const char *id)
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
	slot->kind = kind;
	slot->number = store->next++;
	(void)snprintf(slot->label, sizeof(slot->label), "%u", slot->number);
	{
		/* The identity the uuid is derived from, prefixed by kind. */
		char identity[160];

		(void)snprintf(identity, sizeof(identity), "%s:%s",
		    kind == NMC_PROFILE_NETWORK ? "network" : "interface", id);
		nmc_uuid_of(identity, slot->uuid, sizeof(slot->uuid));
	}
	slot->state = store->state;
	store->count++;
	return slot;
}

/*
 * Whether this interface block gets a profile of its own.
 *
 * Two exclusions, and they are one sentence read twice.
 *
 * **A radio's `interface` block is not a profile.** What you activate on a radio
 * is a network; an `802-3-ethernet` profile named `wlan0` beside them would be a
 * thing in every client's list that cannot be activated and is not an ethernet.
 *
 * **Nor is a tunnel's.** NM's own profile for a WireGuard device carries the
 * peers and the private key, which is a shape this shim will not project -- 0029
 * keeps secrets from travelling and 0036 keeps VPN out of NM's interfaces. The
 * *device* is projected in full and says what it is; what is missing is a profile
 * pretending to configure it.
 *
 * Both are asked of the device list rather than worked out here: the radio
 * question is `policy`, which the daemon decided, and the kind is on the device
 * since netcfgd moved it there.
 */
static int gets_a_profile(const ncfg_devices_t *devices, const char *name)
{
	size_t at;

	if (!devices || !name) {
		return 1;
	}
	for (at = 0u; at < devices->count; at++) {
		const ncfg_device_t *one = &devices->items[at];

		if (!one->name || strcmp(one->name, name) != 0) {
			continue;
		}
		if (one->managed && one->policy && strcmp(one->policy, "wifi") == 0) {
			return 0;
		}
		if (one->kind && strcmp(one->kind, "wireguard") == 0) {
			return 0;
		}
		return 1;
	}
	return 1;
}

int nmc_connections_refresh(nmc_connections_t *store)
{
	const ncfg_saved_networks_t *saved = nmc_state_saved(store->state);
	const ncfg_inventory_t      *inventory = nmc_state_inventory(store->state);
	const ncfg_devices_t        *devices = nmc_state_devices(store->state);
	size_t                       at;

	/*
	 * **Both lists or neither.** A refresh that took the networks and failed to
	 * read the inventory would mark every interface profile absent and emit a
	 * `ConnectionRemoved` for each -- a client would watch its whole profile
	 * list disappear because one request failed. Leaving the previous answer
	 * standing is what the device store does, for this reason.
	 */
	if (!saved || !inventory) {
		return 0;
	}
	for (at = 0u; at < store->count; at++) {
		store->slots[at].present = 0;
	}
	for (at = 0u; at < saved->count; at++) {
		const char            *id = saved->items[at].id;
		nmc_connection_slot_t *slot;

		if (!id || id[0] == '\0') {
			continue;
		}
		slot = slot_for(store, NMC_PROFILE_NETWORK, id);
		if (!slot) {
			slot = add(store, NMC_PROFILE_NETWORK, id);
		}
		if (slot) {
			slot->present = 1;
		}
	}
	/*
	 * The interface blocks, from the inventory's `subject`. That field exists so
	 * a caller can tell the document's two link-shaped blocks apart, which is
	 * exactly this question -- and it is the daemon's answer rather than a second
	 * reading of the configuration.
	 */
	for (at = 0u; at < inventory->count; at++) {
		const ncfg_inventory_item_t *item = &inventory->items[at];
		nmc_connection_slot_t       *slot;

		if (!item->configured || !item->name || item->name[0] == '\0') {
			continue;
		}
		if (!item->subject || strcmp(item->subject, "interface") != 0) {
			continue;
		}
		if (!gets_a_profile(devices, item->name)) {
			continue;
		}
		slot = slot_for(store, NMC_PROFILE_INTERFACE, item->name);
		if (!slot) {
			slot = add(store, NMC_PROFILE_INTERFACE, item->name);
		}
		if (slot) {
			slot->present = 1;
		}
	}
	return 1;
}

const nmc_connection_slot_t *nmc_connections_slot_of(nmc_connections_t *store,
    nmc_profile_kind_t kind, const char *id)
{
	nmc_connection_slot_t *slot;

	if (!store || !id || id[0] == '\0') {
		return NULL;
	}
	(void)nmc_connections_refresh(store);
	slot = slot_for(store, kind, id);
	return slot && slot->present ? slot : NULL;
}

nmc_connection_slot_t *nmc_connections_by_uuid(nmc_connections_t *store, const char *uuid)
{
	size_t at;

	if (!store || !uuid || uuid[0] == '\0') {
		return NULL;
	}
	(void)nmc_connections_refresh(store);
	for (at = 0u; at < store->count; at++) {
		if (store->slots[at].present && strcmp(store->slots[at].uuid, uuid) == 0) {
			return &store->slots[at];
		}
	}
	return NULL;
}

/*
 * The object path for a network's id, or NULL where it has no slot.
 *
 * **This is the device-to-connection join**, and it is a lookup rather than
 * arithmetic for a reason worth keeping: the connection store numbers by the
 * order networks were first seen and the device store by the order devices
 * were, so `/Devices/3` and `/Settings/3` are unrelated. Computing one path
 * from the other's number would hand a client the settings of whatever
 * connection happened to share a number -- which is what 10.362 refused to do
 * and left as `/`.
 */
const char *nmc_connections_path_of(nmc_connections_t *store, nmc_profile_kind_t kind,
    const char *id)
{
	nmc_connection_slot_t *slot;
	static char            path[96];

	if (!store || !id || id[0] == '\0') {
		return NULL;
	}
	(void)nmc_connections_refresh(store);
	slot = slot_for(store, kind, id);
	if (!slot || !slot->present) {
		return NULL;
	}
	/* One buffer, overwritten per call, which is safe for the callers there
	 * are: each appends the path immediately. */
	(void)snprintf(path, sizeof(path), "%s/%u", NMC_SETTINGS_PATH, slot->number);
	return path;
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

static int list_connections(DBusConnection *connection, DBusMessage *call, DBusMessage *reply,
    void *object, char *err, size_t err_size)
{
	DBusMessageIter out;
	nmc_state_t    *state = object;

	(void)connection;
	(void)call;
	(void)err;
	(void)err_size;
	dbus_message_iter_init_append(reply, &out);
	/* The method and the property answer from one function, as on the
	 * manager: a client told two different lists has caught the shim out. */
	return connection_paths(&out, state ? (nmc_connections_t *)state->connections : NULL);
}

/*
 * The `admin` principal this machine's document names, or UNKNOWN.
 *
 * Read per call rather than cached: `control` is ordinary configuration a person
 * edits, and a policy cached at startup is a policy that goes on granting after
 * it was narrowed. **The expensive direction is the safe one here** -- a round
 * trip per write attempt, against a stale grant.
 */
static void admin_principal(nmc_state_t *state, nmc_principal_t *out)
{
	ncfg_client_t *client = nmc_state_client(state);
	ncfg_globals_t globals;
	char           problem[256] = "";

	/* Unknown until something says otherwise, which `nmc_may_write` refuses:
	 * a daemon that cannot be asked must not read as `any`. */
	nmc_principal_parse(NULL, out);
	if (!client) {
		return;
	}
	memset(&globals, 0, sizeof(globals));
	if (!ncfg_client_globals(client, &globals, problem, sizeof(problem))) {
		return;
	}
	nmc_principal_parse(globals.control_admin, out);
	ncfg_globals_free(&globals);
}

/*
 * **Every write: authorized first, then refused for not being built.**
 *
 * The order is the point. An unauthorized caller is told so -- which is the
 * answer that will still be right once writing works -- and an authorized one
 * is told the operation does not exist yet. Doing it the other way round would
 * mean the authorization arrived untested on the day the write did, which is
 * exactly how 0264's unauthorized method came to exist.
 *
 * So the gate is live, tested and already deciding, with nothing behind it.
 * `AccessDenied` for the first and `Failed` for the second, because a client
 * retrying as root should succeed in the first case and never in the second.
 */
static int refuse_write(DBusConnection *connection, DBusMessage *call, DBusMessage *reply,
    void *object, char *err, size_t err_size)
{
	nmc_state_t    *state = object;
	nmc_principal_t admin;
	unsigned long   uid = 0u;
	char            why[NMC_ERROR_MAX] = "";

	(void)reply;
	/*
	 * A connection object's data is its slot rather than the state, so the
	 * state is reached through it. Both shapes pass through here, which is
	 * why this is not simply `object`.
	 */
	if (state && !nmc_connections_is_state(state)) {
		const nmc_connection_slot_t *slot = object;

		state = slot ? slot->state : NULL;
	}
	if (!nmc_caller_uid(connection, call, &uid, why, sizeof(why))) {
		(void)snprintf(err, err_size, "%s", why);
		return 0;
	}
	admin_principal(state, &admin);
	if (!nmc_may_write(uid, &admin, why, sizeof(why))) {
		(void)snprintf(err, err_size, "%s", why);
		return 0;
	}
	(void)snprintf(err, err_size,
	    "you may change this machine's configuration and this build of the shim cannot: "
	    "writing connections over the bus is not implemented. Use `ncfg wifi add` or edit "
	    "/etc/netcfgd/conf.d");
	return 0;
}

/*
 * **Why these three say different things, and why the words are a contract.**
 *
 * One refusal for every write was the position while nothing was authorized --
 * `refuse_write` above, which still answers the ones that have no better
 * sentence. These three have one, and a client renders it: a settings panel puts
 * the error in front of a person, so "not implemented" where the real answer is
 * "edit the file" sends them looking for a missing feature.
 *
 * `tests/live/nm.sh` greps each of them, which makes the wording a contract
 * between this implementation and the Rust one rather than decoration -- the
 * same arrangement as "refusing to claim" at startup.
 */

/*
 * `GetSecrets`: the one refusal that is a security property rather than a gap.
 *
 * A secret in netcfgd is a reference -- `@secret:name` -- and the value lives at
 * 0600 outside the document on purpose. Answering this would put a passphrase on
 * a bus any local process can name, to no benefit: `psk-flags` already tells a
 * client the daemon owns the credential, so it does not prompt. NM gates this
 * behind polkit; netcfgd's answer is that there is nothing to gate.
 *
 * **Not authorized first, unlike every other refusal here.** An authorized caller
 * gets the same no, so asking who is calling would only tell an unauthorized one
 * that the answer depends on who they are.
 */
static int refuse_secrets(DBusConnection *connection, DBusMessage *call, DBusMessage *reply,
    void *object, char *err, size_t err_size)
{
	(void)connection;
	(void)call;
	(void)reply;
	(void)object;
	(void)snprintf(err, err_size,
	    "netcfgd does not hand out secrets. The configuration holds a reference and the "
	    "daemon resolves it when it connects; nothing needs the value on the bus, and "
	    "putting it there would be a leak with no beneficiary");
	return 0;
}

/*
 * `Update` and `Delete` on a block a person wrote.
 *
 * Design section 9.4 exposes hand-written blocks read-only for exactly this
 * reason: a stray click in a settings panel must not rewrite a tuned
 * `interface eth0`. Everything this shim serves today is hand-written -- it has
 * written nothing -- so this is every profile for now, and the sentence says
 * which profiles would be editable so that a client's user knows the rule rather
 * than concluding the shim is broken.
 */
static int refuse_read_only(DBusConnection *connection, DBusMessage *call, DBusMessage *reply,
    void *object, char *err, size_t err_size)
{
	const nmc_connection_slot_t *slot = object;
	nmc_principal_t              admin;
	unsigned long                uid = 0u;
	char                         why[NMC_ERROR_MAX] = "";

	(void)reply;
	if (!nmc_caller_uid(connection, call, &uid, why, sizeof(why))) {
		(void)snprintf(err, err_size, "%s", why);
		return 0;
	}
	admin_principal(slot ? slot->state : NULL, &admin);
	if (!nmc_may_write(uid, &admin, why, sizeof(why))) {
		(void)snprintf(err, err_size, "%s", why);
		return 0;
	}
	(void)snprintf(err, err_size,
	    "`%s` is a hand-written netcfgd block and is read-only here (design section 9.4). "
	    "Edit it in /etc/netcfgd and run `ncfg apply` -- a GUI that could rewrite a tuned "
	    "interface with a stray click is the thing that rule exists to prevent. Networks "
	    "this shim created are editable, because it knows it wrote them",
	    slot && slot->id ? slot->id : "this profile");
	return 0;
}

/*
 * `connection.type` out of the settings dictionary a client sent.
 *
 * `a{sa{sv}}`: groups of named variants. The type is a string under `type` in the
 * `connection` group, and nothing else in the message says what kind of profile
 * is being asked for -- an `802-11-wireless` group being present is a hint and
 * not the answer, since a client may send groups for a type it did not name.
 *
 * Fills `out` with an empty string where the dictionary has no type, which is a
 * different complaint from an unsupported one and is reported as such.
 *
 * **It walks rather than trusting the signature.** `dbus_message_get_args`
 * cannot express a nested dictionary, so the iterator is stepped by hand; a
 * group whose shape is not what was declared is skipped rather than refused,
 * because the dispatcher has already checked the signature of the whole argument
 * and a surprise here would be libdbus disagreeing with itself.
 */
static void settings_type_of(DBusMessage *call, char *out, size_t out_size)
{
	DBusMessageIter args;
	DBusMessageIter groups;

	if (out_size > 0u) {
		out[0] = '\0';
	}
	if (!dbus_message_iter_init(call, &args) ||
	    dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_ARRAY) {
		return;
	}
	dbus_message_iter_recurse(&args, &groups);
	while (dbus_message_iter_get_arg_type(&groups) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter group;
		DBusMessageIter pairs;
		const char     *name = NULL;

		dbus_message_iter_recurse(&groups, &group);
		if (dbus_message_iter_get_arg_type(&group) == DBUS_TYPE_STRING) {
			dbus_message_iter_get_basic(&group, &name);
		}
		if (!name || strcmp(name, "connection") != 0) {
			dbus_message_iter_next(&groups);
			continue;
		}
		(void)dbus_message_iter_next(&group);
		if (dbus_message_iter_get_arg_type(&group) != DBUS_TYPE_ARRAY) {
			return;
		}
		dbus_message_iter_recurse(&group, &pairs);
		while (dbus_message_iter_get_arg_type(&pairs) == DBUS_TYPE_DICT_ENTRY) {
			DBusMessageIter pair;
			DBusMessageIter value;
			const char     *key = NULL;
			const char     *text = NULL;

			dbus_message_iter_recurse(&pairs, &pair);
			if (dbus_message_iter_get_arg_type(&pair) == DBUS_TYPE_STRING) {
				dbus_message_iter_get_basic(&pair, &key);
			}
			(void)dbus_message_iter_next(&pair);
			if (key && strcmp(key, "type") == 0 &&
			    dbus_message_iter_get_arg_type(&pair) == DBUS_TYPE_VARIANT) {
				dbus_message_iter_recurse(&pair, &value);
				if (dbus_message_iter_get_arg_type(&value) == DBUS_TYPE_STRING) {
					dbus_message_iter_get_basic(&value, &text);
					if (text) {
						(void)snprintf(out, out_size, "%s", text);
						return;
					}
				}
			}
			dbus_message_iter_next(&pairs);
		}
		return;
	}
}

/*
 * `GetConnectionByUuid`: the lookup that makes a derived uuid worth deriving.
 *
 * A client stores the uuid and comes back for the profile later. Because the
 * value is a function of the configuration rather than something generated, the
 * reference survives a restart, a reinstall and another machine with the same
 * files -- which is the whole argument in design section 9.3, and it is only
 * cashable if this method exists.
 *
 * A uuid nothing matches is `UnknownObject` rather than an empty path: a client
 * holding a reference to a profile that has been deleted must be told so, not
 * handed `/` to cache.
 */
static int connection_by_uuid(DBusConnection *connection, DBusMessage *call,
    DBusMessage *reply, void *object, char *err, size_t err_size)
{
	nmc_state_t                 *state = object;
	nmc_connections_t           *store = state ? (nmc_connections_t *)state->connections : NULL;
	const char                  *uuid = NULL;
	const nmc_connection_slot_t *slot;
	char                         path[96];
	const char                  *as_path = path;

	(void)connection;
	if (!dbus_message_get_args(call, NULL, DBUS_TYPE_STRING, &uuid, DBUS_TYPE_INVALID)) {
		(void)snprintf(err, err_size, "this takes one uuid");
		return 0;
	}
	slot = nmc_connections_by_uuid(store, uuid);
	if (!slot) {
		(void)snprintf(err, err_size,
		    "no connection with uuid %s; netcfgd's configuration does not describe one",
		    uuid ? uuid : "");
		return 0;
	}
	(void)snprintf(path, sizeof(path), "%s/%u", NMC_SETTINGS_PATH, slot->number);
	return dbus_message_append_args(reply, DBUS_TYPE_OBJECT_PATH, &as_path, DBUS_TYPE_INVALID)
	    ? 1
	    : 0;
}

/*
 * `AddConnection`, which says what it can create rather than that it cannot.
 *
 * **It can create a wifi network and nothing else**, and that is not a gap to be
 * filled: an interface is configured by an `interface` block, which is a file to
 * edit rather than a profile to create. A client told "not implemented" goes
 * looking for a version where it is; one told this knows where to go.
 *
 * The creating half is a later slice. What is already right is the refusal's
 * shape -- authorized first, then the reason -- and the type check, which reads
 * the dictionary a client sent rather than refusing everything by default: that
 * is what makes the message name the type that was asked for.
 */
static int refuse_add(DBusConnection *connection, DBusMessage *call, DBusMessage *reply,
    void *object, char *err, size_t err_size)
{
	nmc_state_t    *state = object;
	nmc_principal_t admin;
	unsigned long   uid = 0u;
	char            why[NMC_ERROR_MAX] = "";
	char            kind[64] = "";

	(void)reply;
	if (!nmc_caller_uid(connection, call, &uid, why, sizeof(why))) {
		(void)snprintf(err, err_size, "%s", why);
		return 0;
	}
	admin_principal(state, &admin);
	if (!nmc_may_write(uid, &admin, why, sizeof(why))) {
		(void)snprintf(err, err_size, "%s", why);
		return 0;
	}
	settings_type_of(call, kind, sizeof(kind));
	if (strcmp(kind, "802-11-wireless") != 0) {
		(void)snprintf(err, err_size,
		    "netcfgd-nm can create wifi networks and nothing else; this asked for `%s`. "
		    "An interface is configured by an `interface` block in /etc/netcfgd, which "
		    "is a file to edit rather than a profile to create",
		    kind[0] != '\0' ? kind : "no type at all");
		return 0;
	}
	(void)snprintf(err, err_size,
	    "you may change this machine's configuration and this build of the shim cannot "
	    "yet write a network over the bus. Use `ncfg wifi add`");
	return 0;
}

static const nmc_property_t SETTINGS_PROPERTIES[] = {
	{ "Connections", "ao", NMC_READ, say_connections, NULL },
	{ "Hostname", "s", NMC_READ, say_hostname, NULL },
	{ "CanModify", "b", NMC_READ, say_can_modify, NULL }
};

static const nmc_method_t SETTINGS_METHODS[] = {
	{ "ListConnections", "", "ao", list_connections },
	{ "GetConnectionByUuid", "s", "o", connection_by_uuid },
	{ "AddConnection", "a{sa{sv}}", "o", refuse_add },
	{ "AddConnectionUnsaved", "a{sa{sv}}", "o", refuse_add },
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
	const ncfg_saved_networks_t *saved;
	size_t                       at;
	int                          found = 0;

	memset(out, 0, sizeof(*out));
	keep[0] = '\0';
	if (!slot || !slot->id) {
		return 0;
	}
	saved = nmc_state_saved(slot->state);
	if (!saved) {
		return 0;
	}
	for (at = 0u; at < saved->count; at++) {
		if (!saved->items[at].id || strcmp(saved->items[at].id, slot->id) != 0) {
			continue;
		}
		/* Only the scalars and one copied string: the list is freed below
		 * and a borrowed pointer would dangle. */
		*out = saved->items[at];
		out->id = NULL;
		out->name = NULL;
		out->ssid = NULL;
		out->security = NULL;
		out->proto = NULL;
		out->credential = NULL;
		(void)snprintf(keep, keep_size, "%s",
		    saved->items[at].name && saved->items[at].name[0] != '\0'
		        ? saved->items[at].name
		        : slot->id);
		found = 1;
		break;
	}
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
static int get_settings(DBusConnection *connection, DBusMessage *call, DBusMessage *reply,
    void *object, char *err, size_t err_size)
{
	const nmc_connection_slot_t *slot = object;
	ncfg_saved_network_t         saved;
	char                         shown[256] = "";
	DBusMessageIter              out;
	DBusMessageIter              groups;
	int                          wireless = slot && slot->kind == NMC_PROFILE_NETWORK;

	(void)connection;
	(void)call;
	/*
	 * A network is looked up to get the name a client displays; an interface
	 * profile's name IS its id, and there is no saved-network row for it.
	 */
	if (wireless) {
		if (!saved_for(slot, &saved, shown, sizeof(shown))) {
			(void)snprintf(err, err_size,
			    "netcfgd does not report this network; it may have been forgotten");
			return 0;
		}
	} else {
		(void)snprintf(shown, sizeof(shown), "%s", slot && slot->id ? slot->id : "");
	}
	dbus_message_iter_init_append(reply, &out);
	if (!dbus_message_iter_open_container(&out, DBUS_TYPE_ARRAY, "{sa{sv}}", &groups)) {
		return 0;
	}
	{
		/*
		 * The second group is what says what kind of connection this is, and
		 * a client switches on the `type` in the first: `802-11-wireless`
		 * carries a mode and an SSID, `802-3-ethernet` carries the interface
		 * it is bound to. A wifi profile names no interface on purpose -- an
		 * SSID is in range of whatever radio can hear it.
		 */
		const char *const GROUPS[] = { "connection",
			wireless ? "802-11-wireless" : "802-3-ethernet" };
		size_t            which;

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
				/*
				 * `id`, `type` and `uuid` are what every NM client
				 * reads first. **The uuid is derived and not the id**,
				 * which this used to answer: a client stores the uuid
				 * and looks the profile up by it later, and an id is
				 * not a uuid -- `nmcli` prints it in the UUID column
				 * and `GetConnectionByUuid` would never match what a
				 * client had kept.
				 */
				put_pair(&pairs, "id", shown);
				put_pair(&pairs, "type", GROUPS[1]);
				put_pair(&pairs, "uuid", slot->uuid);
				/*
				 * An interface profile is bound to its interface; a
				 * network is not, and saying so is what lets a client
				 * offer it on any radio.
				 */
				if (!wireless) {
					put_pair(&pairs, "interface-name", shown);
				}
			} else if (wireless) {
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
	{ "GetSecrets", "s", "a{sa{sv}}", refuse_secrets },
	{ "Update", "a{sa{sv}}", "", refuse_read_only },
	/* NM's newer spelling, and **the one `nmcli` actually calls**: with only
	 * `Update` declared, a modify got "this interface has no such method in
	 * this build" from the dispatcher instead of netcfgd's explanation. A
	 * refusal that never runs is not a refusal. */
	{ "Update2", "a{sa{sv}}ua{sv}", "a{sv}", refuse_read_only },
	{ "UpdateUnsaved", "a{sa{sv}}", "", refuse_read_only },
	{ "Delete", "", "", refuse_read_only },
	{ "Save", "", "", refuse_read_only },
	{ "ClearSecrets", "", "", refuse_read_only }
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
