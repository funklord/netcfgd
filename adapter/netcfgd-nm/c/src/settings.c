/*
 * settings.c -- `...Settings` and `...Settings.Connection`, and the one write.
 *
 * WHAT IS SERVED AND WHAT IS REFUSED, AND WHY THAT IS THE SHAPE
 *   Reads are answered: the connection list, each connection's settings, the
 *   hostname. **One write is served** -- `AddConnection` and the newer
 *   `AddConnection2` create a wifi network, which `block.c` renders and
 *   `config_put` installs. Every other write is declared and refused by name,
 *   saying so: an `Update`, a `Delete` or a `Save` reaches a hand-written
 *   netcfgd block, which design section 9.4 keeps out of a GUI's reach, and
 *   editing one this shim wrote is a later slice.
 *
 *   The order is what made the first write safe to add, and it is 0264's: the
 *   caller's uid off the message, against netcfgd's own `control` policy,
 *   BEFORE the settings dictionary is so much as read. 0264 found the Rust shim
 *   exporting a method with no authorization at all, which any local process
 *   could call, and a half-built write path is how that defect gets rewritten
 *   -- so the gate was built, tested and left refusing for two slices before
 *   anything was written through it.
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
#include "nmc/block.h"
#include "nmc/emit.h"
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
 * connection happened to share a number -- which is what 10.393 refused to do
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

/*
 * The SSID, as NetworkManager requires it: `ay`, not a string.
 *
 * **`802-11-wireless` is invalid without this**, and the comment above the
 * group already said it carries an SSID while the code wrote `ssid-text`,
 * which is not a property NM has. libnm validates a profile in the CLIENT
 * before calling `ActivateConnection`, so every activation of a wifi profile
 * was refused with `802-11-wireless.ssid: property is missing` -- 51 checks of
 * `nm.sh`, the activation itself and then everything about the connection it
 * never made. `settings.rs` carries the same requirement in a comment and
 * emits the bytes, which is what this is a port of.
 *
 * The bytes, not the characters: an SSID is 32 octets of anything and NM's
 * clients render it themselves. A separate helper rather than a signature
 * argument to `put_pair`, for `put_pair`'s own stated reason.
 */
static void put_ssid(DBusMessageIter *into, const char *text)
{
	DBusMessageIter entry;
	DBusMessageIter variant;
	DBusMessageIter bytes;
	const char     *name = "ssid";
	const char     *from = text ? text : "";
	size_t          at;
	size_t          length = strlen(from);

	if (!dbus_message_iter_open_container(into, DBUS_TYPE_DICT_ENTRY, NULL, &entry)) {
		return;
	}
	(void)dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &name);
	if (!dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT, "ay", &variant)) {
		(void)dbus_message_iter_abandon_container_if_open(into, &entry);
		return;
	}
	if (!dbus_message_iter_open_container(&variant, DBUS_TYPE_ARRAY, "y", &bytes)) {
		(void)dbus_message_iter_abandon_container_if_open(&entry, &variant);
		(void)dbus_message_iter_abandon_container_if_open(into, &entry);
		return;
	}
	for (at = 0u; at < length; at++) {
		unsigned char byte = (unsigned char)from[at];

		(void)dbus_message_iter_append_basic(&bytes, DBUS_TYPE_BYTE, &byte);
	}
	(void)dbus_message_iter_close_container(&variant, &bytes);
	(void)dbus_message_iter_close_container(&entry, &variant);
	(void)dbus_message_iter_close_container(into, &entry);
}

/*
 * `address-data` and `route-data`: NM's dictionary shapes for an address and a
 * route, each `{ "address"|"dest": s, "prefix": u }`.
 *
 * A separate pair of helpers rather than one taking the key, for `put_pair`'s
 * stated reason: the two differ in the key AND in what a reader expects to
 * find beside it, and a shared one would be a marshaller with the type
 * checking argued away.
 */
static void put_cidr_entry(DBusMessageIter *array, const char *key, const char *cidr)
{
	DBusMessageIter entry;
	DBusMessageIter pairs;
	DBusMessageIter pair;
	DBusMessageIter variant;
	const char     *name;
	char            address[64] = "";
	const char     *slash;
	dbus_uint32_t   prefix = 0u;

	if (!cidr || cidr[0] == '\0') {
		return;
	}
	slash = strchr(cidr, '/');
	if (!slash) {
		return;
	}
	if ((size_t)(slash - cidr) >= sizeof(address)) {
		return;
	}
	memcpy(address, cidr, (size_t)(slash - cidr));
	address[slash - cidr] = '\0';
	prefix = (dbus_uint32_t)strtoul(slash + 1, NULL, 10);

	if (!dbus_message_iter_open_container(array, DBUS_TYPE_ARRAY, "{sv}", &pairs)) {
		return;
	}
	name = key;
	if (dbus_message_iter_open_container(&pairs, DBUS_TYPE_DICT_ENTRY, NULL, &pair)) {
		const char *value = address;

		(void)dbus_message_iter_append_basic(&pair, DBUS_TYPE_STRING, &name);
		if (dbus_message_iter_open_container(&pair, DBUS_TYPE_VARIANT, "s", &variant)) {
			(void)dbus_message_iter_append_basic(&variant, DBUS_TYPE_STRING, &value);
			(void)dbus_message_iter_close_container(&pair, &variant);
		}
		(void)dbus_message_iter_close_container(&pairs, &pair);
	}
	name = "prefix";
	if (dbus_message_iter_open_container(&pairs, DBUS_TYPE_DICT_ENTRY, NULL, &pair)) {
		(void)dbus_message_iter_append_basic(&pair, DBUS_TYPE_STRING, &name);
		if (dbus_message_iter_open_container(&pair, DBUS_TYPE_VARIANT, "u", &variant)) {
			(void)dbus_message_iter_append_basic(&variant, DBUS_TYPE_UINT32, &prefix);
			(void)dbus_message_iter_close_container(&pair, &variant);
		}
		(void)dbus_message_iter_close_container(&pairs, &pair);
	}
	(void)dbus_message_iter_close_container(array, &pairs);
	(void)entry;
}

/* An `aa{sv}` member: the key, then one dictionary per CIDR the caller feeds. */
static void put_cidr_list(DBusMessageIter *into, const char *member, const char *entry_key,
    const char *const *cidrs, size_t count)
{
	DBusMessageIter pair;
	DBusMessageIter variant;
	DBusMessageIter array;
	size_t          at;

	if (!dbus_message_iter_open_container(into, DBUS_TYPE_DICT_ENTRY, NULL, &pair)) {
		return;
	}
	(void)dbus_message_iter_append_basic(&pair, DBUS_TYPE_STRING, &member);
	if (!dbus_message_iter_open_container(&pair, DBUS_TYPE_VARIANT, "aa{sv}", &variant)) {
		(void)dbus_message_iter_abandon_container_if_open(into, &pair);
		return;
	}
	if (dbus_message_iter_open_container(&variant, DBUS_TYPE_ARRAY, "a{sv}", &array)) {
		for (at = 0u; at < count; at++) {
			put_cidr_entry(&array, entry_key, cidrs[at]);
		}
		(void)dbus_message_iter_close_container(&variant, &array);
	}
	(void)dbus_message_iter_close_container(&pair, &variant);
	(void)dbus_message_iter_close_container(into, &pair);
}

/*
 * The `ipv4` group of a profile, from the document's own view of it.
 *
 * `method` is what the sources say: a static address is `manual`, a lease is
 * `auto`, nothing at all is `disabled`. NM has no word for netcfgd's mixture
 * of several sources on one interface, so the strongest one wins and a
 * `manual` profile with a lease beside it reads as manual -- which is what a
 * panel can edit, where `auto` would hide the address the document states.
 */
/*
 * Whether this is an IPv6 address, route or next hop.
 *
 * A colon, which no IPv4 text contains and every IPv6 text does. The document
 * does not label a source's family -- `config = ["10.7.7.1/24",
 * "2001:db8:7::1/64"]` is two `static` sources and nothing else -- so the
 * group has to tell them apart itself, and the first version did not: it put
 * both into `ipv4`, and a panel was told its IPv4 addresses included
 * `2001:db8:7::1/64`.
 */
static int is_ipv6_text(const char *text)
{
	return text && strchr(text, ':') != NULL;
}

static void put_ipv4_group(DBusMessageIter *groups, const ncfg_interface_config_t *config)
{
	DBusMessageIter group;
	DBusMessageIter pairs;
	const char     *name = "ipv4";
	const char     *method = "disabled";
	const char     *addresses[8];
	const char     *routes[8];
	const char     *gateway = "";
	size_t          address_count = 0u;
	size_t          route_count = 0u;
	size_t          at;

	for (at = 0u; at < config->source_count; at++) {
		const char *source = config->sources[at].source;

		if (!source) {
			continue;
		}
		if (strcmp(source, "static") == 0) {
			if (is_ipv6_text(config->sources[at].address)) {
				/* An `ipv6` group's business. A v6 address here is not a
				 * missing answer but a wrong one, which is the
				 * distinction `ipconfig.c` makes about the v6 gateway. */
				continue;
			}
			method = "manual";
			if (address_count < sizeof(addresses) / sizeof(addresses[0]) &&
			    config->sources[at].address) {
				addresses[address_count++] = config->sources[at].address;
			}
		} else if (strcmp(source, "dhcp4") == 0 && strcmp(method, "manual") != 0) {
			method = "auto";
		}
	}
	for (at = 0u; at < config->route_count; at++) {
		const char *destination = config->routes[at].destination;

		if (!destination) {
			continue;
		}
		if (strcmp(destination, "default") == 0) {
			/* The next hop becomes `gateway`, and the route itself is left
			 * out of the table below: 0033's split. A v6 next hop belongs
			 * to the group this is not. */
			if (!is_ipv6_text(config->routes[at].via)) {
				gateway = config->routes[at].via ? config->routes[at].via : "";
			}
			continue;
		}
		if (is_ipv6_text(destination)) {
			continue;
		}
		if (route_count < sizeof(routes) / sizeof(routes[0])) {
			routes[route_count++] = destination;
		}
	}

	if (!dbus_message_iter_open_container(groups, DBUS_TYPE_DICT_ENTRY, NULL, &group)) {
		return;
	}
	(void)dbus_message_iter_append_basic(&group, DBUS_TYPE_STRING, &name);
	if (!dbus_message_iter_open_container(&group, DBUS_TYPE_ARRAY, "{sv}", &pairs)) {
		(void)dbus_message_iter_abandon_container_if_open(groups, &group);
		return;
	}
	put_pair(&pairs, "method", method);
	put_pair(&pairs, "gateway", gateway);
	put_cidr_list(&pairs, "address-data", "address", addresses, address_count);
	put_cidr_list(&pairs, "route-data", "dest", routes, route_count);
	(void)dbus_message_iter_close_container(&group, &pairs);
	(void)dbus_message_iter_close_container(groups, &group);
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
 * The `admin` principal is `nmc_admin_principal` in `authorize.c` now.
 *
 * It was `static` here and `manager.c` needs the same answer for
 * `ActivateConnection`, so it moved rather than being copied: two definitions
 * of who may write is the duplication `authorize.h` exists to prevent, and
 * the reason it reads per call rather than caching went with it.
 */

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
	nmc_admin_principal(state, &admin);
	if (!nmc_may_write(uid, &admin, why, sizeof(why))) {
		(void)snprintf(err, err_size, "%s", why);
		return 0;
	}
	/* **Not "writing connections is not implemented" any more**, which is what
	 * this said while every write refused. Creating one is `AddConnection`, so
	 * that sentence would now send a client's user looking for a feature that
	 * is there -- and these three are not refused for being unbuilt but for
	 * being questions netcfgd answers elsewhere or not at all. */
	(void)snprintf(err, err_size,
	    "you may change this machine's configuration and this build of the shim does not "
	    "answer this call: netcfgd re-reads its own files when they change, so there is "
	    "nothing here to load or reload, and its hostname is a policy in the document "
	    "rather than a value a client sets. A network is created with AddConnection and "
	    "edited in /etc/netcfgd/conf.d");
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
 * `tests/live/nm.sh` greps `read-only here` three times, which makes THAT
 * one's wording a contract between this implementation and the Rust one rather
 * than decoration -- the same arrangement as "refusing to claim" at startup.
 *
 * **The other two are asserted nowhere**, measured 2026-10-19 across every
 * script in `tests/live/`, and this said "each of them" until then. Worth
 * knowing in both directions: rewording `refuse_write` costs nothing and
 * breaks nothing, and nothing would have caught it having gone stale -- which
 * it had, for as long as it claimed writing a connection was unimplemented
 * after `AddConnection` started working.
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
	nmc_admin_principal(slot ? slot->state : NULL, &admin);
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
 * `AddConnection`: the write direction of design section 9.4.
 *
 * A GUI is another editor of configuration files, so what comes out of this has
 * to be a netcfgd `network` block an operator could have typed. `block.c`
 * renders it and refuses by name anything netcfgd's language cannot say, which
 * is why this reads as authorize, render, write.
 *
 * **It can create a wifi network and nothing else**, and that is not a gap to be
 * filled: an interface is configured by an `interface` block, which is a file to
 * edit rather than a profile to create. A client told "not implemented" goes
 * looking for a version where it is; one told that knows where to go.
 *
 * WHY THE WRITE GOES THROUGH NETCFGD RATHER THAN TO THE FILE
 *   0127: netcfgd is the only writer of `/etc/netcfgd`, and `config_put` is the
 *   call that says so. It also gives for free the half the Rust shim writes by
 *   hand -- the daemon compiles the configuration back with the new file in it
 *   and restores what was there when the result will not compile. So a block
 *   that redefines a network another file already defines is refused here, as a
 *   failed `AddConnection`, rather than leaving a machine whose next reload
 *   changes nothing and says why in a log nobody is reading.
 *
 * WHY THE PATH IS LOOKED UP RATHER THAN PREDICTED
 *   A client that reads the returned path straight away has to find an object
 *   there, and the number is the connection store's to assign. Asking it also
 *   makes the answer netcfgd's: a write that succeeded and then does not appear
 *   in the saved list is reported, rather than papered over with a path that
 *   resolves to nothing.
 */
/*
 * Hand a rendered block to netcfgd: the credential first, then the file.
 *
 * **The order is `store.rs`'s and it matters for its reason.** A block naming a
 * credential that is not there yet is a configuration netcfgd will try to apply
 * and fail; a credential nothing refers to is inert. Of the two halves that can
 * be left behind, the inert one is the one to risk.
 *
 * **Neither write replaces anything, and that is what makes the rollback
 * safe.** `AddConnection` creates. A secret already on disk under that name is
 * an operator's or another profile's, and overwriting a credential is the one
 * thing 0042 says nobody can undo -- so a refusal is the right answer, and it
 * also settles ownership: a secret this call stored is one that was not there a
 * moment before, so removing it when the file is then refused cannot remove
 * anybody else's. `ncfg_client_wifi_add` draws the same line for the same
 * reason, refusing outright if either the network file or the secret exists.
 *
 * The Rust shim replaces instead, and correctly: `store.rs`'s one write serves
 * `AddConnection` and an agent answering a request for a credential, and 0031's
 * bridge needs the second to be able to say "no, this one". That is the update
 * path rather than this one.
 */
static int installed(nmc_state_t *state, DBusConnection *connection, const nmc_block_t *block,
    char *path, size_t path_size, char *err, size_t err_size)
{
	nmc_connections_t           *store = state ? (nmc_connections_t *)state->connections : NULL;
	const nmc_connection_slot_t *slot;
	ncfg_client_t               *client = nmc_state_client(state);
	char                         why[NMC_ERROR_MAX] = "";

	if (!client) {
		(void)snprintf(err, err_size,
		    "netcfgd is not answering, so there is nowhere to put `%s`: its files are "
		    "the authority and this shim keeps no copy of them",
		    block->label);
		return 0;
	}
	if (block->has_secret &&
	    !ncfg_client_secret_put(client, block->label, block->secret, 0, why, sizeof(why))) {
		(void)snprintf(err, err_size,
		    "netcfgd would not store the credential for `%s`: %s. Nothing has been "
		    "written",
		    block->label, why);
		return 0;
	}
	/*
	 * Never `replace`. `AddConnection` creates, and a client that has forgotten
	 * a network of this name exists must not be able to overwrite it by sending
	 * the name again -- the file it would clobber may be one an operator wrote.
	 */
	if (!ncfg_client_config_put(client, block->stem, block->text, 0, why, sizeof(why))) {
		char undo[NMC_ERROR_MAX] = "";

		(void)snprintf(err, err_size, "netcfgd would not take `%s`: %s", block->label,
		    why);
		/*
		 * The credential this call stored a moment ago goes with the file
		 * that was refused: a stored secret no block refers to is inert, but
		 * it would also refuse the client's next attempt at the same network,
		 * because the store above does not replace. Its failure is appended
		 * rather than replacing the real cause -- the reason the write was
		 * refused is what the operator needs, and the orphan is what they
		 * need to know about second.
		 */
		if (block->has_secret &&
		    !ncfg_client_secret_delete(client, block->label, undo, sizeof(undo))) {
			size_t said = strlen(err);

			if (said < err_size) {
				(void)snprintf(err + said, err_size - said,
				    ". The credential stored for it could not be removed again "
				    "(%s); `ncfg secret delete %s` does it by hand",
				    undo, block->label);
			}
		}
		return 0;
	}
	/*
	 * **The dispatch's fact window is reopened, because this dispatch moved the
	 * world.** `state.h` argues that a window scoped to one message cannot go
	 * stale, and that holds for every read-only dispatch -- which is all of
	 * them until this one. A getter that happened to have fetched the saved
	 * list before the write would leave the lookup below asking the list from
	 * before it, so the network would not be found and a client would be told
	 * its write failed after the file was on disk. Nothing fetches it that
	 * early today; the call order is the only thing keeping that true, and this
	 * does not depend on the call order.
	 */
	nmc_window_end();
	nmc_window_begin();
	slot = nmc_connections_slot_of(store, NMC_PROFILE_NETWORK, block->label);
	if (!slot) {
		(void)snprintf(err, err_size,
		    "wrote `%s` and netcfgd does not report it; another block of the same name "
		    "may be overriding it",
		    block->label);
		return 0;
	}
	(void)snprintf(path, path_size, "%s/%u", NMC_SETTINGS_PATH, slot->number);
	/*
	 * **Announced before answering, or the client is told the object is not
	 * there.** libnm learns what exists from `ObjectManager` alone, and
	 * `nmcli` reads the path this returns the moment it has it:
	 * `operation succeeded but object /Settings/8 does not exist` is what it
	 * says when the announcement waits for the loop's next tick. The Rust shim
	 * carries the same sentence in a comment, for the same race.
	 *
	 * The tick will announce it again when its membership pass notices the new
	 * name, and that is harmless rather than merely tolerated: both audiences
	 * key on the object path, so a second `InterfacesAdded` updates an object a
	 * client has instead of adding one it does not. Suppressing it would mean
	 * reaching into the loop's remembered set from a method handler.
	 */
	{
		static const nmc_interface_t *const AS_CONNECTION[] = { &nmc_connection_interface,
			NULL };
		nmc_object_t object_added;

		object_added.path = path;
		object_added.interfaces = AS_CONNECTION;
		/* The dispatcher's own resolver, so the announcement reads the object a
		 * client would: the slot is the tail of the path it was just given. */
		object_added.data = nmc_connections_resolve_for_bus(slot->label, store);
		nmc_bus_announce(connection, &object_added, 1);
		nmc_emit_path(connection, NMC_SETTINGS_PATH,
		    "org.freedesktop.NetworkManager.Settings", "NewConnection", path);
	}
	return 1;
}

/*
 * Authorize the caller, render what they asked for, write it, and forget it.
 *
 * **The wipe is here and not in `installed`, which is why the two are
 * separate.** A rendered block may hold a passphrase, and every path out of the
 * write has to clear it -- the client being away, a refused credential, a
 * refused file, a network netcfgd then does not report, and success. One call
 * after one call covers all five; a wipe at each `return` is the error path
 * somebody forgets.
 */
static int created(DBusConnection *connection, DBusMessage *call, void *object, char *path,
    size_t path_size, char *err, size_t err_size)
{
	nmc_state_t    *state = object;
	nmc_principal_t admin;
	unsigned long   uid = 0u;
	char            why[NMC_ERROR_MAX] = "";
	nmc_block_t     block;
	int             wrote;

	if (!nmc_caller_uid(connection, call, &uid, why, sizeof(why))) {
		(void)snprintf(err, err_size, "%s", why);
		return 0;
	}
	nmc_admin_principal(state, &admin);
	if (!nmc_may_write(uid, &admin, why, sizeof(why))) {
		(void)snprintf(err, err_size, "%s", why);
		return 0;
	}
	/*
	 * **Authorized before the dictionary is read**, which is the order 0264 is
	 * about: this shim authorizes the bus caller rather than its own socket
	 * peer, and a method that worked out what to write first would be doing
	 * work on behalf of somebody it had not asked about yet. It matters more
	 * now than it did when nothing was written: what the dictionary may carry
	 * is a credential.
	 */
	if (!nmc_block_render(call, &block, err, err_size)) {
		return 0;
	}
	wrote = installed(state, connection, &block, path, path_size, err, err_size);
	nmc_block_forget(&block);
	return wrote;
}

static int add_connection(DBusConnection *connection, DBusMessage *call, DBusMessage *reply,
    void *object, char *err, size_t err_size)
{
	char        path[96];
	const char *as_path = path;

	if (!created(connection, call, object, path, sizeof(path), err, err_size)) {
		return 0;
	}
	return dbus_message_append_args(reply, DBUS_TYPE_OBJECT_PATH, &as_path, DBUS_TYPE_INVALID)
	    ? 1
	    : 0;
}

/* The flags `AddConnection2` carries, which say where the profile is to live. */
#define NMC_ADD_IN_MEMORY 0x1eu

static dbus_uint32_t add_flags(DBusMessage *call)
{
	DBusMessageIter args;
	dbus_uint32_t   flags = 0u;

	if (!dbus_message_iter_init(call, &args) || !dbus_message_iter_next(&args) ||
	    dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_UINT32) {
		return 0u;
	}
	dbus_message_iter_get_basic(&args, &flags);
	return flags;
}

/*
 * Why an unsaved profile is refused, wherever it is asked for.
 *
 * There is nowhere for one to live: netcfgd's authority is its files, and a
 * profile held only in this process would be exactly the hidden state
 * constraint 1 exists to prevent.
 */
static const char UNSAVED_WHY[] =
    "netcfgd has nowhere to put an unsaved profile. Its authority is its files, and a "
    "profile held only in this process would be exactly the hidden state constraint 1 "
    "exists to prevent";

/*
 * NM's newer spelling, and **the one `nmcli` actually calls** -- the same lesson
 * `Update2` carries on the connection interface. With only `AddConnection`
 * declared, libnm's `add_connection2` gets `this interface has no such method in
 * this build` from the dispatcher and never reaches the method that would have
 * done the work.
 *
 * The flags are read rather than dropped, because one of them changes the
 * answer: a client asking for a profile that is not to touch the disk is asking
 * for the thing `AddConnectionUnsaved` is refused for, and writing the file
 * anyway would be obeying the method and ignoring the request.
 *
 * The result dictionary is empty. It is where NM reports what it did with the
 * profile beyond creating it -- nothing here does anything beyond that, and an
 * invented key is worse than an absent one.
 */
static int add_connection2(DBusConnection *connection, DBusMessage *call, DBusMessage *reply,
    void *object, char *err, size_t err_size)
{
	DBusMessageIter into;
	DBusMessageIter empty;
	char            path[96];
	const char     *as_path = path;

	if ((add_flags(call) & NMC_ADD_IN_MEMORY) != 0u) {
		(void)snprintf(err, err_size, "%s", UNSAVED_WHY);
		return 0;
	}
	if (!created(connection, call, object, path, sizeof(path), err, err_size)) {
		return 0;
	}
	if (!dbus_message_append_args(reply, DBUS_TYPE_OBJECT_PATH, &as_path, DBUS_TYPE_INVALID)) {
		(void)snprintf(err, err_size, "no memory for the reply");
		return 0;
	}
	dbus_message_iter_init_append(reply, &into);
	if (!dbus_message_iter_open_container(&into, DBUS_TYPE_ARRAY, "{sv}", &empty)) {
		(void)snprintf(err, err_size, "no memory for the reply");
		return 0;
	}
	return dbus_message_iter_close_container(&into, &empty) ? 1 : 0;
}

/*
 * `AddConnectionUnsaved`, authorized and then refused.
 *
 * The order is `refuse_write`'s and for its reason: an unauthorized caller is
 * told so, which is the answer that will still be right whatever this method
 * learns to do, and an authorized one is told why netcfgd cannot hold what it
 * asked for.
 */
static int refuse_unsaved(DBusConnection *connection, DBusMessage *call, DBusMessage *reply,
    void *object, char *err, size_t err_size)
{
	nmc_state_t    *state = object;
	nmc_principal_t admin;
	unsigned long   uid = 0u;
	char            why[NMC_ERROR_MAX] = "";

	(void)reply;
	if (!nmc_caller_uid(connection, call, &uid, why, sizeof(why))) {
		(void)snprintf(err, err_size, "%s", why);
		return 0;
	}
	nmc_admin_principal(state, &admin);
	if (!nmc_may_write(uid, &admin, why, sizeof(why))) {
		(void)snprintf(err, err_size, "%s", why);
		return 0;
	}
	(void)snprintf(err, err_size, "%s", UNSAVED_WHY);
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
	{ "AddConnection", "a{sa{sv}}", "o", add_connection },
	{ "AddConnection2", "a{sa{sv}}ua{sv}", "oa{sv}", add_connection2 },
	{ "AddConnectionUnsaved", "a{sa{sv}}", "o", refuse_unsaved },
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
				put_ssid(&pairs, shown);
			}
			(void)dbus_message_iter_close_container(&group, &pairs);
			(void)dbus_message_iter_close_container(&groups, &group);
		}
	}
	/*
	 * **And the `ipv4` group, which was absent rather than incomplete.**
	 *
	 * A panel opened on a profile reads this to draw the addressing tab, and
	 * with no group at all every field came back empty -- so it showed a
	 * static interface as having no method, no address, no gateway and no
	 * routes. The document has all four.
	 *
	 * **From the DOCUMENT and not the observation, which is the opposite of
	 * `IP4Config`.** 0032 puts the details panel on the observation because it
	 * answers what the machine is doing; a profile answers what was asked
	 * for, and a client editing one must see its own request rather than the
	 * result. `ncfg_client_interface_config` is that view and already types
	 * the routes with destination, via and metric.
	 *
	 * **0033's split, which is NM's and not netcfgd's.** netcfgd keeps one
	 * `routes` list with the default as an entry; NM keeps the default's next
	 * hop in `gateway` and everything else in `route-data`, so the default is
	 * deliberately absent from the list -- reporting it in both draws a
	 * duplicate row in every panel.
	 */
	if (slot && slot->kind == NMC_PROFILE_INTERFACE && slot->id) {
		ncfg_interface_config_t config;
		char                    problem[NMC_ERROR_MAX] = "";
		ncfg_client_t          *client = nmc_state_client(slot->state);

		memset(&config, 0, sizeof(config));
		if (client && ncfg_client_interface_config(client, slot->id, &config, problem,
		        sizeof(problem)) && config.present) {
			put_ipv4_group(&groups, &config);
		}
		ncfg_interface_config_free(&config);
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
