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
#include "nmc/store.h"
#include "nmc/settings.h"

#include <stdio.h>
#include <string.h>
/* For `strncasecmp`: glibc reaches it through <string.h> and musl does not, and
 * netcfgd packages for Alpine. */
#include <strings.h>

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

#define NM_DEVICE_STATE_REASON_NONE    0u
/* Nothing has happened yet, which is what a link nobody brought up is. */
#define NM_DEVICE_STATE_REASON_UNKNOWN 1u
/* No cable. NM's 40, and the one reason a client renders as a sentence. */
#define NM_DEVICE_STATE_REASON_CARRIER 40u
#define NM_METERED_GUESS_NO         4u

/* One device's current facts, copied out so nothing is owned here. */
typedef struct {
	char name[64];
	char kind[32];
	char mac[48];
	char policy[16];
	char addresses[1024];
	char network[128];
	char master[64];
	char parent[64];
	char public_key[64];
	int  vlan_id;
	int  listen_port;
	int  default_route;
	int  present;
	int  configured;
	int  managed;
	int  mtu;
	int  wireless;
	int  carrier;
	int  up;
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
	const ncfg_devices_t *devices;
	const ncfg_links_t   *links;
	size_t                at;

	memset(out, 0, sizeof(*out));
	if (!slot || !slot->name) {
		return;
	}
	(void)snprintf(out->name, sizeof(out->name), "%s", slot->name);
	/*
	 * **Both lists come from the dispatch's window**, so a `GetAll` over
	 * thirty-one properties costs two fetches rather than sixty-two. It is
	 * also the correctness half: every property in one reply then describes
	 * one world, where separate fetches could describe a device that existed
	 * in neither.
	 */
	devices = nmc_state_devices(slot->state);
	links = nmc_state_links(slot->state);
	if (devices) {
		for (at = 0u; at < devices->count; at++) {
			const ncfg_device_t *device = &devices->items[at];

			if (!device->name || strcmp(device->name, slot->name) != 0) {
				continue;
			}
			(void)snprintf(out->kind, sizeof(out->kind), "%s",
			    device->kind ? device->kind : "");
			(void)snprintf(out->mac, sizeof(out->mac), "%s",
			    device->mac ? device->mac : "");
			(void)snprintf(out->policy, sizeof(out->policy), "%s",
			    device->policy ? device->policy : "");
			out->present = device->present;
			out->configured = device->configured;
			out->managed = device->managed;
			out->mtu = device->mtu;
			out->known = 1;
			break;
		}
	}
	/*
	 * The kernel's link kind, which is what NM's `DeviceType` is about --
	 * netcfgd's device kind is `"physical"` for a wifi card and an ethernet
	 * port alike (project.md 10.357). A failure here leaves the kind empty,
	 * which reads as a real NIC and is the same answer as before.
	 */
	if (links) {
		for (at = 0u; at < links->count; at++) {
			const ncfg_link_t *one = &links->items[at];

			if (!one->name || strcmp(one->name, slot->name) != 0) {
				continue;
			}
			(void)snprintf(out->kind, sizeof(out->kind), "%s",
			    one->kind ? one->kind : "");
			out->wireless = one->wireless;
			out->carrier = one->carrier;
			out->up = one->up;
			out->default_route = one->default_route;
			if (one->mtu > 0) {
				out->mtu = one->mtu;
			}
			if (one->mac && one->mac[0] != '\0') {
				(void)snprintf(out->mac, sizeof(out->mac), "%s", one->mac);
			}
			(void)snprintf(out->addresses, sizeof(out->addresses), "%s",
			    one->addresses ? one->addresses : "");
			(void)snprintf(out->network, sizeof(out->network), "%s",
			    one->network ? one->network : "");
			(void)snprintf(out->master, sizeof(out->master), "%s",
			    one->master ? one->master : "");
			(void)snprintf(out->parent, sizeof(out->parent), "%s",
			    one->parent ? one->parent : "");
			(void)snprintf(out->public_key, sizeof(out->public_key), "%s",
			    one->public_key ? one->public_key : "");
			out->vlan_id = one->vlan_id;
			out->listen_port = one->listen_port;
			break;
		}
	}
	/*
	 * **A radio is either the kernel's answer or the document's, and the two
	 * disagree in both directions.** `ncfg_link_t.wireless` is what the kernel
	 * says, which is 0 for a device the document declares a radio over a link
	 * the kernel calls something else -- a dummy under test, or hardware whose
	 * driver says nothing. netcfgd's planner starts a supplicant on a managed
	 * device with a `wifi` block whatever the kernel calls the link, so a client
	 * that asked only the kernel would be told the device is not wireless while
	 * a supplicant ran on it.
	 *
	 * `ncfg_device_t.policy` is that answer, already decided by the daemon and
	 * carried for exactly this reason -- the header says the rule belongs in one
	 * place rather than in each front end. The radios list is the WRONG source
	 * and was tried first: it is built from the kernel's flag on purpose, so
	 * that somebody can take on a radio nobody has configured, and a device
	 * declared over a dummy never appears in it.
	 *
	 * Managed as well as declared, because an unmanaged device is one netcfgd
	 * does not touch: its `wifi` block says what would happen, not what is.
	 */
	if (out->managed && strcmp(out->policy, "wifi") == 0) {
		out->wireless = 1;
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
/*
 * Whether any of these addresses is one a client would call being connected.
 *
 * **Link-local does not count, and that is the whole function.** Every link with
 * IPv6 enabled gets an `fe80::` address the moment it comes up, so a test for
 * "has an address" reports every configured-but-addressless interface as
 * ACTIVATED -- which is what this did, and what `tests/live/nm.sh` caught on a
 * dummy with an empty `interface` block. `169.254.` is the same thing for IPv4,
 * and means the opposite of connected: it is what a host assigns itself when
 * DHCP found nobody.
 *
 * Prefix matching rather than parsing, which is `state.rs`'s rule and is enough:
 * `fe80:` is the whole of the IPv6 range in practice -- the block is `fe80::/10`
 * and nothing assigns out of the rest of it -- and the comparison is
 * case-insensitive because netcfgd's rendering is not this function's to assume.
 */
static int routable(const char *addresses)
{
	const char *at = addresses;

	while (at && *at != '\0') {
		size_t span = strcspn(at, ",");

		while (span > 0u && (*at == ' ' || *at == '\t')) {
			at++;
			span--;
		}
		if (span > 0u && strncasecmp(at, "fe80:", 5u) != 0 &&
		    strncmp(at, "169.254.", 8u) != 0) {
			return 1;
		}
		at += span;
		if (*at == ',') {
			at++;
		}
	}
	return 0;
}

/*
 * The state and why, which is one decision and so is written once.
 *
 * `nmc_device_state_now` is the state half of it. Splitting them was how the
 * device state came to be computed twice in this file.
 */
static dbus_uint32_t state_and_reason(const nmc_device_slot_t *slot, dbus_uint32_t *reason)
{
	facts_t facts;

	*reason = NM_DEVICE_STATE_REASON_NONE;
	facts_for(slot, &facts);
	if (!facts.known) {
		return NM_DEVICE_STATE_UNKNOWN;
	}
	if (!facts.present) {
		return NM_DEVICE_STATE_UNAVAILABLE;
	}
	if (!facts.managed) {
		return NM_DEVICE_STATE_UNMANAGED;
	}
	/*
	 * **What is, not what should be, and `device.rs`'s mapping exactly.** This
	 * asked `configured` -- netcfgd's word for "the document describes this
	 * device" -- and so reported a down link with no carrier and no address as
	 * `DISCONNECTED` and an interface block with no `config` in it as
	 * `ACTIVATED`. Both are the document's answer to a question a client asks
	 * about the machine: NM's `State` is what the device is doing.
	 *
	 * `up` before `carrier` because they are separate answers and the reasons
	 * differ -- a link that is down was not brought up, one with no carrier has
	 * no cable -- and `StateReason` says which.
	 */
	if (!facts.up) {
		*reason = NM_DEVICE_STATE_REASON_UNKNOWN;
		return NM_DEVICE_STATE_UNAVAILABLE;
	}
	if (!facts.carrier) {
		*reason = NM_DEVICE_STATE_REASON_CARRIER;
		return NM_DEVICE_STATE_UNAVAILABLE;
	}
	return routable(facts.addresses) ? NM_DEVICE_STATE_ACTIVATED
	                                : NM_DEVICE_STATE_DISCONNECTED;
}

dbus_uint32_t nmc_device_state_now(const nmc_device_slot_t *slot)
{
	dbus_uint32_t reason;

	return state_and_reason(slot, &reason);
}

static int say_state(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	(void)err;
	(void)err_size;
	return put_u32(into, nmc_device_state_now(object));
}

/*
 * `(uu)`: the state, and why.
 *
 * Two of NM's forty reasons are answerable from what netcfgd observes, and they
 * are the two a client renders: a link nobody brought up, and a cable that is
 * not in. Everything else is NONE rather than a guess.
 */
static int say_state_reason(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	DBusMessageIter pair;
	dbus_uint32_t   reason;
	dbus_uint32_t   state = state_and_reason(object, &reason);

	(void)err;
	(void)err_size;
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
/* `/` is NM's "no object", and is not an empty string -- that is not a valid
 * object path and libnm would reject the reply. */
NMC_CONST(say_no_object, return put_path(into, "/");)

/*
 * This device's own IP config and active connection, by its own number.
 *
 * **An object is named only where it exists.** A device with no addresses has
 * no active connection, and pointing at one would have a client follow the path
 * and read a `State` of deactivated -- which is a round trip to learn what the
 * absent path already said.
 */
#define NMC_OWN(name, family, only_when_addressed)                                            \
	static int name(DBusMessageIter *into, void *object, char *err, size_t err_size)       \
	{                                                                                     \
		facts_t facts;                                                                \
		char    path[96];                                                             \
		(void)err;                                                                    \
		(void)err_size;                                                               \
		facts_for(object, &facts);                                                    \
		if (!facts.known ||                                                           \
		    ((only_when_addressed) && facts.addresses[0] == '\0')) {                   \
			return put_path(into, "/");                                            \
		}                                                                             \
		(void)snprintf(path, sizeof(path), "/org/freedesktop/NetworkManager/%s/%u",     \
		    (family), ((const nmc_device_slot_t *)object)->number);                     \
		return put_path(into, path);                                                  \
	}

NMC_OWN(say_ip4_config, "IP4Config", 1)
NMC_OWN(say_ip6_config, "IP6Config", 1)
NMC_OWN(say_active, "ActiveConnection", 1)
NMC_CONST(say_no_paths, return put_empty(into, "o");)
/* LLDP is a protocol netcfgd does not speak. */
NMC_CONST(say_no_lldp, return put_empty(into, "a{sv}");)

/*
 * The connections that could be activated on this device.
 *
 * **Every saved network for a radio, and none for anything else**, which is what
 * netcfgd's document supports: a `network` block describes a wifi network, and
 * nothing in it can be activated on an ethernet port. A client reads this to
 * decide what to offer, so listing wifi profiles under a wired device would
 * offer a join that cannot happen.
 *
 * Not filtered by what is in range. NM's own list is "configured and applicable
 * to this device", and in-range-ness belongs to the access points -- a network
 * saved for home is still available on the radio while you are at work, in the
 * sense this property means.
 */
static int say_available(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	const nmc_device_slot_t     *slot = object;
	DBusMessageIter              array;
	const ncfg_saved_networks_t *saved;
	size_t                       at;

	(void)err;
	(void)err_size;
	if (!dbus_message_iter_open_container(into, DBUS_TYPE_ARRAY, "o", &array)) {
		return 0;
	}
	if (nmc_device_type_now(slot) != NM_DEVICE_TYPE_WIFI || !slot->state) {
		return dbus_message_iter_close_container(into, &array) ? 1 : 0;
	}
	saved = nmc_state_saved(slot->state);
	for (at = 0u; saved && at < saved->count; at++) {
		const char *path = nmc_connections_path_of(
		    (nmc_connections_t *)slot->state->connections, NMC_PROFILE_NETWORK,
		    saved->items[at].id);

		if (path) {
			(void)dbus_message_iter_append_basic(&array, DBUS_TYPE_OBJECT_PATH, &path);
		}
	}
	return dbus_message_iter_close_container(into, &array) ? 1 : 0;
}

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
	{ "Ip4Config", "o", NMC_READ, say_ip4_config, NULL },
	{ "Ip6Config", "o", NMC_READ, say_ip6_config, NULL },
	{ "Dhcp4Config", "o", NMC_READ, say_no_object, NULL },
	{ "Dhcp6Config", "o", NMC_READ, say_no_object, NULL },
	{ "ActiveConnection", "o", NMC_READ, say_active, NULL },
	{ "AvailableConnections", "ao", NMC_READ, say_available, NULL },
	{ "Ports", "ao", NMC_READ, say_no_paths, NULL },
	{ "LldpNeighbors", "aa{sv}", NMC_READ, say_no_lldp, NULL }
};

/*
 * `StateChanged(uuu)` -- new state, old state, reason.
 *
 * Three arguments and not one, which is NM's shape and is the one a client
 * cannot reconstruct: it needs the OLD state to know what transition happened,
 * and a `PropertiesChanged` on `State` carries only the new one.
 */
static const nmc_signal_t SIGNALS[] = {
	{ "StateChanged", "uuu" }
};

const nmc_interface_t nmc_device_interface = {
	.name = "org.freedesktop.NetworkManager.Device",
	.properties = PROPERTIES,
	.property_count = sizeof(PROPERTIES) / sizeof(PROPERTIES[0]),
	.methods = NULL,
	.method_count = 0u,
	.signals = SIGNALS,
	.signal_count = sizeof(SIGNALS) / sizeof(SIGNALS[0])
};

/* ------------------------------------------- what the subtypes ask of us */

/*
 * The four facts `subtypes.c` needs, each fetched the same way a property is.
 *
 * **Shared rather than re-derived**, because a client reading `HwAddress` from
 * `.Device` and from `.Wired` and being told two things has caught the shim
 * disagreeing with itself. The cost is another round trip per call, which is
 * the position `state.h` records.
 */
void nmc_device_address_of(const nmc_device_slot_t *slot, char *out, size_t out_size)
{
	facts_t facts;

	facts_for(slot, &facts);
	(void)snprintf(out, out_size, "%s", facts.mac);
}

void nmc_device_kind_of(const nmc_device_slot_t *slot, char *out, size_t out_size)
{
	facts_t facts;

	facts_for(slot, &facts);
	(void)snprintf(out, out_size, "%s", facts.kind);
}

int nmc_device_carrier_of(const nmc_device_slot_t *slot)
{
	facts_t facts;

	facts_for(slot, &facts);
	return facts.known && facts.carrier;
}

/*
 * The links enslaved to this one, as object paths.
 *
 * **Read backwards across every link, because `master` points the other way.** A
 * bridge does not list its ports; each port names its bridge, which is what
 * netcfgd observes and what the planner acts on. So this is the only one of the
 * subtype accessors that has to walk the whole list rather than find one row.
 *
 * Through the store, so a port's path is the number it already has. Answers how
 * many were written, and writes none past `room`.
 */
size_t nmc_device_ports_of(const nmc_device_slot_t *slot, char paths[][64], size_t room)
{
	const ncfg_links_t *links;
	size_t              kept = 0u;
	size_t              at;

	if (!slot || !slot->name || !slot->state) {
		return 0u;
	}
	links = nmc_state_links(slot->state);
	if (!links) {
		return 0u;
	}
	for (at = 0u; at < links->count && kept < room; at++) {
		const ncfg_link_t *one = &links->items[at];
		const char        *path;

		if (!one->master || strcmp(one->master, slot->name) != 0) {
			continue;
		}
		path = nmc_store_path_for((nmc_store_t *)slot->state->store, one->name);
		if (!path) {
			/* A port netcfgd reports and the store has no slot for cannot
			 * be named; silence is better than a path pointing elsewhere. */
			continue;
		}
		(void)snprintf(paths[kept], 64u, "%s", path);
		kept++;
	}
	return kept;
}

/*
 * The device this one rides on, as a path, or NULL.
 *
 * A vlan's parent and a tunnel's are the same relationship and netcfgd reports
 * both as `parent`. NULL where there is none or where the parent has no slot,
 * which the caller turns into `/` -- NM's "no object" path, and the answer a
 * client must be given rather than a path to somebody else.
 */
const char *nmc_device_parent_of(const nmc_device_slot_t *slot)
{
	facts_t facts;

	if (!slot || !slot->state) {
		return NULL;
	}
	facts_for(slot, &facts);
	if (facts.parent[0] == '\0') {
		return NULL;
	}
	return nmc_store_path_for((nmc_store_t *)slot->state->store, facts.parent);
}

int nmc_device_vlan_id_of(const nmc_device_slot_t *slot)
{
	facts_t facts;

	facts_for(slot, &facts);
	return facts.vlan_id;
}

int nmc_device_listen_port_of(const nmc_device_slot_t *slot)
{
	facts_t facts;

	facts_for(slot, &facts);
	return facts.listen_port;
}

void nmc_device_public_key_of(const nmc_device_slot_t *slot, char *out, size_t out_size)
{
	facts_t facts;

	facts_for(slot, &facts);
	(void)snprintf(out, out_size, "%s", facts.public_key);
}

dbus_uint32_t nmc_device_type_now(const nmc_device_slot_t *slot)
{
	facts_t facts;

	facts_for(slot, &facts);
	return nmc_device_type_of(facts.kind, facts.wireless, facts.name);
}

/*
 * The link's addresses, comma-separated and in netcfgd's order.
 *
 * Handed over as the daemon gave them rather than parsed here, because the
 * order is the daemon's answer -- `ncfg_link_t` says "already ordered" -- and a
 * client shows the first one.
 */
void nmc_device_addresses_of(const nmc_device_slot_t *slot, char *out, size_t out_size)
{
	facts_t facts;

	facts_for(slot, &facts);
	(void)snprintf(out, out_size, "%s", facts.addresses);
}
void nmc_device_network_of(const nmc_device_slot_t *slot, char *out, size_t out_size)
{
	facts_t facts;

	facts_for(slot, &facts);
	(void)snprintf(out, out_size, "%s", facts.network);
}

void nmc_device_name_of(const nmc_device_slot_t *slot, char *out, size_t out_size)
{
	(void)snprintf(out, out_size, "%s", slot && slot->name ? slot->name : "");
}

int nmc_device_default_route_of(const nmc_device_slot_t *slot)
{
	facts_t facts;

	facts_for(slot, &facts);
	return facts.known && facts.default_route;
}
