/*
 * bus_test.c -- the dispatcher's introspection, which needs no bus.
 *
 * WHAT THIS CAN AND CANNOT CHECK
 *   `nmc_bus_introspect` is a pure function of the tables, so it is checkable
 *   here and is worth checking here: it is the document a client parses to
 *   decide what to call, and the whole argument for table-driven dispatch is
 *   that this document and the routing cannot disagree. A test that only drove
 *   a live bus would exercise the routing and never read the XML.
 *
 *   What it cannot check is the marshalling -- a variant's contents, a
 *   container inside one -- which needs a bus and a client. `tests/live/` has
 *   that half.
 */
#include "nmc/bus.h"
#include "nmc/compat.h"
#include "nmc/manager.h"
#include "nmc/device.h"
#include "nmc/subtypes.h"
#include "nmc/emit.h"
#include "nmc/settings.h"
#include "nmc/uuid.h"
#include "nmc/authorize.h"
#include "nmc/ipconfig.h"
#include "nmc/active.h"
#include "nmc/accesspoint.h"
#include "nmc/agent.h"
#include "nmc/block.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int checks;
static int failures;

/* A property whose value is whatever the test last put in the int. */
static int count_up(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	dbus_uint32_t value = (dbus_uint32_t)*(int *)object;

	(void)err;
	(void)err_size;
	return dbus_message_iter_append_basic(into, DBUS_TYPE_UINT32, &value) ? 1 : 0;
}

static void check(int condition, const char *what)
{
	checks++;
	if (condition) {
		printf("ok   %s\n", what);
	} else {
		printf("FAILED %s\n", what);
		failures++;
	}
}

/* --------------------------- a settings dictionary, as a client sends one */

/*
 * `AddConnection`'s argument, built here rather than driven over a bus.
 *
 * A `DBusMessage` is created and appended to with no connection at all, so the
 * marshalling the file header says is out of reach is out of reach only for
 * what this program WRITES. What it READS -- a variant inside a container
 * inside a container, which is what a client sends -- can be built here, and
 * the renderer that reads it is a pure function of it.
 */
static DBusMessage *settings_call(void)
{
	return dbus_message_new_method_call("org.freedesktop.NetworkManager",
	    "/org/freedesktop/NetworkManager/Settings",
	    "org.freedesktop.NetworkManager.Settings", "AddConnection");
}

static void open_group(DBusMessageIter *groups, const char *name, DBusMessageIter *entry,
    DBusMessageIter *pairs)
{
	(void)dbus_message_iter_open_container(groups, DBUS_TYPE_DICT_ENTRY, NULL, entry);
	(void)dbus_message_iter_append_basic(entry, DBUS_TYPE_STRING, &name);
	(void)dbus_message_iter_open_container(entry, DBUS_TYPE_ARRAY, "{sv}", pairs);
}

static void close_group(DBusMessageIter *groups, DBusMessageIter *entry, DBusMessageIter *pairs)
{
	(void)dbus_message_iter_close_container(entry, pairs);
	(void)dbus_message_iter_close_container(groups, entry);
}

/* One `sv` pair, whose variant is opened for the caller to fill. */
static void open_pair(DBusMessageIter *pairs, const char *key, const char *signature,
    DBusMessageIter *pair, DBusMessageIter *value)
{
	(void)dbus_message_iter_open_container(pairs, DBUS_TYPE_DICT_ENTRY, NULL, pair);
	(void)dbus_message_iter_append_basic(pair, DBUS_TYPE_STRING, &key);
	(void)dbus_message_iter_open_container(pair, DBUS_TYPE_VARIANT, signature, value);
}

static void close_pair(DBusMessageIter *pairs, DBusMessageIter *pair, DBusMessageIter *value)
{
	(void)dbus_message_iter_close_container(pair, value);
	(void)dbus_message_iter_close_container(pairs, pair);
}

static void say_string(DBusMessageIter *pairs, const char *key, const char *text)
{
	DBusMessageIter pair;
	DBusMessageIter value;

	open_pair(pairs, key, "s", &pair, &value);
	(void)dbus_message_iter_append_basic(&value, DBUS_TYPE_STRING, &text);
	close_pair(pairs, &pair, &value);
}

static void say_number(DBusMessageIter *pairs, const char *key, dbus_uint32_t number)
{
	DBusMessageIter pair;
	DBusMessageIter value;

	open_pair(pairs, key, "u", &pair, &value);
	(void)dbus_message_iter_append_basic(&value, DBUS_TYPE_UINT32, &number);
	close_pair(pairs, &pair, &value);
}

static void say_signed(DBusMessageIter *pairs, const char *key, dbus_int32_t number)
{
	DBusMessageIter pair;
	DBusMessageIter value;

	open_pair(pairs, key, "i", &pair, &value);
	(void)dbus_message_iter_append_basic(&value, DBUS_TYPE_INT32, &number);
	close_pair(pairs, &pair, &value);
}

static void say_flag(DBusMessageIter *pairs, const char *key, int yes)
{
	DBusMessageIter pair;
	DBusMessageIter value;
	dbus_bool_t     said = yes ? TRUE : FALSE;

	open_pair(pairs, key, "b", &pair, &value);
	(void)dbus_message_iter_append_basic(&value, DBUS_TYPE_BOOLEAN, &said);
	close_pair(pairs, &pair, &value);
}

/* An SSID: octets, which is the thing reading it as a string got wrong. */
static void say_bytes(DBusMessageIter *pairs, const char *key, const char *text)
{
	DBusMessageIter pair;
	DBusMessageIter value;
	DBusMessageIter bytes;
	size_t          at;

	open_pair(pairs, key, "ay", &pair, &value);
	(void)dbus_message_iter_open_container(&value, DBUS_TYPE_ARRAY, "y", &bytes);
	for (at = 0u; text[at] != '\0'; at++) {
		unsigned char byte = (unsigned char)text[at];

		(void)dbus_message_iter_append_basic(&bytes, DBUS_TYPE_BYTE, &byte);
	}
	(void)dbus_message_iter_close_container(&value, &bytes);
	close_pair(pairs, &pair, &value);
}

static void say_texts(DBusMessageIter *pairs, const char *key, const char *text)
{
	DBusMessageIter pair;
	DBusMessageIter value;
	DBusMessageIter texts;

	open_pair(pairs, key, "as", &pair, &value);
	(void)dbus_message_iter_open_container(&value, DBUS_TYPE_ARRAY, "s", &texts);
	(void)dbus_message_iter_append_basic(&texts, DBUS_TYPE_STRING, &text);
	(void)dbus_message_iter_close_container(&value, &texts);
	close_pair(pairs, &pair, &value);
}

/* A member of one `aa{sv}` entry: text, or a number where `text` is NULL. */
typedef struct {
	const char   *name;
	const char   *text;
	dbus_uint32_t number;
} member_t;

/*
 * An `aa{sv}` holding one entry, which is what `address-data` and `route-data`
 * are. One entry rather than a list because every rule this exercises is per
 * entry; the list is a loop around the same code.
 */
static void say_entry(DBusMessageIter *pairs, const char *key, const member_t *members,
    size_t count)
{
	DBusMessageIter pair;
	DBusMessageIter value;
	DBusMessageIter array;
	DBusMessageIter entry;
	size_t          at;

	open_pair(pairs, key, "aa{sv}", &pair, &value);
	(void)dbus_message_iter_open_container(&value, DBUS_TYPE_ARRAY, "a{sv}", &array);
	(void)dbus_message_iter_open_container(&array, DBUS_TYPE_ARRAY, "{sv}", &entry);
	for (at = 0u; at < count; at++) {
		if (members[at].text) {
			say_string(&entry, members[at].name, members[at].text);
		} else {
			say_number(&entry, members[at].name, members[at].number);
		}
	}
	(void)dbus_message_iter_close_container(&array, &entry);
	(void)dbus_message_iter_close_container(&value, &array);
	close_pair(pairs, &pair, &value);
}

/*
 * What a client asked for, as a fixture.
 *
 * A struct rather than a builder per test because the interesting cases differ
 * in one field each, and a designated initialiser naming that field is the test
 * saying what it is about.
 */
typedef struct {
	const char   *type;
	const char   *id;
	const char   *ssid;
	const char   *key_mgmt;
	const char   *psk;
	const char   *v4_method;
	const char   *address;
	dbus_uint32_t prefix;
	const char   *gateway;
	const char   *route_dest;
	dbus_uint32_t route_prefix;
	const char   *route_next;
	dbus_uint32_t route_metric;
	const char   *v6_method;
	const char   *dns;
	const char   *dns_search;
	int           priority_present;
	dbus_int32_t  priority;
	dbus_int32_t  metered;
	int           hidden;
	int           autoconnect_present;
	int           autoconnect;
	dbus_uint32_t mtu;
} profile_t;

static DBusMessage *profile_message(const profile_t *profile)
{
	DBusMessage    *call = settings_call();
	DBusMessageIter args;
	DBusMessageIter groups;
	DBusMessageIter entry;
	DBusMessageIter pairs;

	dbus_message_iter_init_append(call, &args);
	(void)dbus_message_iter_open_container(&args, DBUS_TYPE_ARRAY, "{sa{sv}}", &groups);

	open_group(&groups, "connection", &entry, &pairs);
	if (profile->id) {
		say_string(&pairs, "id", profile->id);
	}
	if (profile->type) {
		say_string(&pairs, "type", profile->type);
	}
	/* Always sent, always empty, and the dropped note must not name it: this is
	 * the `is_empty` rule the Rust comment is about. */
	say_string(&pairs, "interface-name", "");
	if (profile->priority_present) {
		say_signed(&pairs, "autoconnect-priority", profile->priority);
	}
	if (profile->metered != 0) {
		say_signed(&pairs, "metered", profile->metered);
	}
	if (profile->autoconnect_present) {
		say_flag(&pairs, "autoconnect", profile->autoconnect);
	}
	close_group(&groups, &entry, &pairs);

	open_group(&groups, "802-11-wireless", &entry, &pairs);
	if (profile->ssid) {
		say_bytes(&pairs, "ssid", profile->ssid);
	}
	say_string(&pairs, "mode", "infrastructure");
	if (profile->hidden) {
		say_flag(&pairs, "hidden", 1);
	}
	if (profile->mtu != 0u) {
		say_number(&pairs, "mtu", profile->mtu);
	}
	close_group(&groups, &entry, &pairs);

	if (profile->key_mgmt) {
		open_group(&groups, "802-11-wireless-security", &entry, &pairs);
		say_string(&pairs, "key-mgmt", profile->key_mgmt);
		if (profile->psk) {
			say_string(&pairs, "psk", profile->psk);
		}
		close_group(&groups, &entry, &pairs);
	}

	open_group(&groups, "ipv4", &entry, &pairs);
	if (profile->v4_method) {
		say_string(&pairs, "method", profile->v4_method);
	}
	if (profile->address) {
		member_t members[2] = { { "address", profile->address, 0u },
			{ "prefix", NULL, profile->prefix } };

		say_entry(&pairs, "address-data", members, 2u);
	}
	if (profile->gateway) {
		say_string(&pairs, "gateway", profile->gateway);
	}
	if (profile->route_dest) {
		member_t members[4] = { { "dest", profile->route_dest, 0u },
			{ "prefix", NULL, profile->route_prefix },
			{ "next-hop", profile->route_next, 0u },
			{ "metric", NULL, profile->route_metric } };
		size_t   count = profile->route_next ? 4u : 2u;

		say_entry(&pairs, "route-data", members, count);
	}
	if (profile->dns) {
		say_texts(&pairs, "dns-data", profile->dns);
	}
	if (profile->dns_search) {
		say_texts(&pairs, "dns-search", profile->dns_search);
	}
	close_group(&groups, &entry, &pairs);

	open_group(&groups, "ipv6", &entry, &pairs);
	if (profile->v6_method) {
		say_string(&pairs, "method", profile->v6_method);
	}
	say_string(&pairs, "addr-gen-mode", "stable-privacy");
	close_group(&groups, &entry, &pairs);

	(void)dbus_message_iter_close_container(&args, &groups);
	return call;
}

/* Render one fixture, and let the message go. */
static int rendered(const profile_t *profile, nmc_block_t *block, char *why, size_t size)
{
	DBusMessage *call = profile_message(profile);
	int          ok;

	why[0] = '\0';
	ok = nmc_block_render(call, block, why, size);
	dbus_message_unref(call);
	return ok;
}

/* The fixture every case here starts from: an open network called Office. */
static profile_t an_open_network(void)
{
	profile_t profile = { 0 };

	profile.type = "802-11-wireless";
	profile.id = "Office";
	profile.ssid = "Office";
	return profile;
}

int main(void)
{
	static char                  xml[65536];
	const nmc_interface_t       *interfaces[] = { &nmc_compat_interface, NULL };
	const nmc_object_t           object = { "/org/freedesktop/NetworkManager", interfaces,
		    NULL };

	check(nmc_bus_introspect(&object, NULL, 0u, xml, sizeof(xml)) == 1,
	    "the manager object introspects");

	check(strstr(xml, "<node>") && strstr(xml, "</node>"),
	    "  and the document is a node");
	check(strstr(xml, "\"org.freedesktop.DBus.Introspectable\"") != NULL,
	    "  naming Introspectable, which every object answers for");
	check(strstr(xml, "\"org.freedesktop.DBus.Properties\"") != NULL,
	    "  and Properties, likewise");
	check(strstr(xml, "name=\"org.netcfgd.Compat\"") != NULL,
	    "  and the interface this object actually serves");

	/* The three properties, with the types and the access a client reads. */
	check(strstr(xml, "name=\"Implementation\" type=\"s\" access=\"read\"") != NULL,
	    "Implementation is a read-only string");
	check(strstr(xml,
	          "name=\"ClaimedNetworkManagerVersion\" type=\"s\" access=\"read\"") != NULL,
	    "the claimed version is a read-only string");
	check(strstr(xml, "name=\"Supported\" type=\"a{sb}\" access=\"read\"") != NULL,
	    "and Supported publishes its container type whole, not a{ then s then b");

	/*
	 * **The refusal, which is the property worth having.** A truncated
	 * introspection document is valid XML describing half an interface, and
	 * a client believes what arrived. So a buffer that cannot hold it must
	 * produce nothing rather than a prefix.
	 */
	{
		char small[200];

		check(nmc_bus_introspect(&object, NULL, 0u, small, sizeof(small)) == 0,
		    "a buffer too small is refused");
		check(strstr(small, "org.netcfgd.Compat") == NULL,
		    "  and nothing half-written is left in it to be parsed");
	}

	/* An object serving nothing of its own still answers for the standards,
	 * because a client introspecting an empty path must learn that rather
	 * than get an error. */
	{
		const nmc_interface_t *none[] = { NULL };
		const nmc_object_t     bare = { "/org/freedesktop/NetworkManager/Devices",
			    none, NULL };

		check(nmc_bus_introspect(&bare, NULL, 0u, xml, sizeof(xml)) == 1,
		    "an object with no interfaces of its own still introspects");
		check(strstr(xml, "\"org.freedesktop.DBus.Properties\"") != NULL,
		    "  and still offers Properties");
	}

	/*
	 * The manager interface's document, which is what libnm reads at
	 * startup to decide whether this is NetworkManager at all.
	 *
	 * **Counted, not sampled.** A property that fell out of the table is
	 * invisible to a spot check on four names, and the properties are the
	 * whole of what a client reads here -- so the count is asserted and
	 * changing the table deliberately means changing this number.
	 */
	{
		const nmc_interface_t *both[] = { &nmc_manager_interface,
			&nmc_compat_interface, NULL };
		const nmc_object_t     manager = { "/org/freedesktop/NetworkManager", both,
			    NULL };
		size_t                 at;
		int                    all_typed = 1;

		check(nmc_manager_interface.property_count == 24u,
		    "the manager declares twenty-four properties, as NM's own does");
		/* Two device getters, the name lookup every client resolves a
		 * device through, the lowercase `state` older clients call, and the
		 * activation pair -- the first writes this shim carries out, behind
		 * the authorization gate this comment once said they were waiting
		 * for. Both are here now, so the pair is whole and the number is
		 * six. */
		check(nmc_manager_interface.method_count == 6u,
		    "and the six methods a libnm client reaches for");
		for (at = 0u; at < nmc_manager_interface.property_count; at++) {
			const nmc_property_t *property = &nmc_manager_interface.properties[at];

			if (!property->name || !property->signature || !property->get ||
			    !dbus_signature_validate_single(property->signature, NULL)) {
				printf("    (%s has no valid single type)\n",
				    property->name ? property->name : "a nameless property");
				all_typed = 0;
			}
		}
		check(all_typed,
		    "  every one has a name, a getter, and one valid complete type");

		check(nmc_bus_introspect(&manager, NULL, 0u, xml, sizeof(xml)) == 1,
		    "both interfaces introspect together at one path");
		check(strstr(xml, "name=\"Version\" type=\"s\"") != NULL,
		    "  Version is a string, which is what clients gate on");
		check(strstr(xml, "name=\"VersionInfo\" type=\"au\"") != NULL,
		    "  and VersionInfo the packed array beside it");
		check(strstr(xml, "name=\"GlobalDnsConfiguration\" type=\"a{sv}\"") != NULL,
		    "  and the dict publishes its container type whole");
		check(strstr(xml, "\"org.netcfgd.Compat\"") != NULL &&
		        strstr(xml, "\"org.freedesktop.NetworkManager\"") != NULL,
		    "  and one object serving two interfaces names both");
	}

	/*
	 * The device type map, which is pure and got one wrong.
	 *
	 * **The first case is the defect.** netcfgd reports its radio with a
	 * device kind of "physical", and a table over THAT called a wifi card an
	 * ethernet port -- so the kernel's link kind and the radio flag are what
	 * this reads, and an empty kind with `wireless` is the case that was
	 * broken.
	 */
	{
		check(nmc_device_type_of("", 1, "wlp0s20f3") == 2u,
		    "a real NIC with a radio is WIFI, which is the case that was wrong");
		check(nmc_device_type_of("", 0, "enp0s31f6") == 1u,
		    "and the same empty kind without one is ETHERNET");
		check(nmc_device_type_of("", 0, "lo") == 32u,
		    "lo is LOOPBACK, by a name that stands in for IFF_LOOPBACK");
		check(nmc_device_type_of("wireguard", 0, "wg0") == 29u, "wireguard is WIREGUARD");
		check(nmc_device_type_of("bridge", 0, "br0") == 13u, "bridge is BRIDGE");
		check(nmc_device_type_of("gre", 0, "gre0") == 17u &&
		        nmc_device_type_of("sit", 0, "sit0") == 17u &&
		        nmc_device_type_of("erspan", 0, "erspan0") == 17u,
		    "and gre, sit and erspan share NM's one tunnel type");
		/* GENERIC and not UNKNOWN: libnm hides UNKNOWN from some views, so
		 * the difference is whether a user sees their own interface. */
		check(nmc_device_type_of("some_new_kind", 0, "x0") == 14u,
		    "a kind this build has not mapped is GENERIC, not UNKNOWN");
		check(nmc_device_type_of(NULL, 0, NULL) == 14u,
		    "and nothing at all is answered rather than crashed on");
		check(nmc_device_interface.property_count == 31u,
		    "the device declares thirty-one properties, as NM's own does");
	}

	/*
	 * The subtype chooser's invariants.
	 *
	 * **The mapping itself is proven on a bus and the SHAPE is proven here.**
	 * Which subtype a kind gets needs a client to fetch the kind, so the
	 * cases that matter were read off ten real devices. What a unit test can
	 * hold is the structure: `.Device` first, exactly one subtype, and a
	 * NULL at the end -- a list missing `&nmc_device_interface` would serve a
	 * device with no `Interface` property at all, and introspection would
	 * look plausible.
	 */
	{
		/* No client, so the facts come back empty: an empty kind with no
		 * radio is ETHERNET, and the name `lo` is LOOPBACK. Those are the
		 * two arms reachable without a daemon, and reaching them is the
		 * point -- the chooser is being exercised, not mocked. */
		nmc_device_slot_t             wired = { (char *)"eth-test", 1u, 1, "1", NULL };
		nmc_device_slot_t             loop = { (char *)"lo", 2u, 1, "2", NULL };
		const nmc_interface_t *const *list;
		size_t                        count;

		list = nmc_device_interfaces_for(&wired);
		for (count = 0u; list && list[count] != NULL; count++) {
			/* Counting. */
		}
		check(count == 2u, "a device serves its own interface and exactly one subtype");
		check(list && list[0] == &nmc_device_interface,
		    "  with `.Device` first, so `Interface` is always there");
		check(list && list[1] &&
		        strcmp(list[1]->name, "org.freedesktop.NetworkManager.Device.Wired") == 0,
		    "  and an empty kind with no radio is Wired");

		list = nmc_device_interfaces_for(&loop);
		check(list && list[1] &&
		        strcmp(list[1]->name,
		            "org.freedesktop.NetworkManager.Device.Loopback") == 0,
		    "while `lo` is Loopback, which carries no properties and is served anyway");
		check(list && list[1] && list[1]->property_count == 0u,
		    "  because a marker interface is how libnm knows what it is");
	}

	/*
	 * The change detector, which is the positive control the bus cannot give.
	 *
	 * **A converged machine emits nothing, and so does a detector that can
	 * never fire.** Those are indistinguishable from outside, so watching a
	 * quiet bus proves nothing on its own -- this drives the predicate
	 * directly with a value that is made to move.
	 */
	{
		static int                counter;
		static const nmc_property_t COUNTING = { "Counter", "u", NMC_READ,
			    count_up, NULL };
		static const nmc_interface_t FAKE = { "org.netcfgd.Test", &COUNTING, 1u, NULL,
			    0u, NULL, 0u };
		nmc_watch_t *watch = nmc_watch_new();

		check(watch != NULL, "a watch is made");
		counter = 7;
		check(nmc_watch_moved(watch, "/t", &FAKE, &COUNTING, &counter) == 0,
		    "first sight is not a change, or a client gets everything at startup");
		check(nmc_watch_moved(watch, "/t", &FAKE, &COUNTING, &counter) == 0,
		    "and an unchanged value is still not one");
		counter = 8;
		check(nmc_watch_moved(watch, "/t", &FAKE, &COUNTING, &counter) == 1,
		    "a changed value IS one -- the control the quiet bus cannot give");
		check(nmc_watch_moved(watch, "/t", &FAKE, &COUNTING, &counter) == 0,
		    "and it is reported once, not on every look after");

		/* The same value under a different path is a different thing, or two
		 * devices would mask each other's changes. */
		check(nmc_watch_moved(watch, "/other", &FAKE, &COUNTING, &counter) == 0,
		    "a path seen for the first time is first sight, whatever another said");

		nmc_watch_forget(watch, "/t");
		check(nmc_watch_moved(watch, "/t", &FAKE, &COUNTING, &counter) == 0,
		    "and forgetting a path makes the next look first sight again");
		nmc_watch_free(watch);
	}

	/*
	 * What the comparison rests on: equal values marshal equal, different
	 * ones do not. The poll compares bytes rather than renderings, so this is
	 * the assumption that makes it correct for every type the tables declare.
	 */
	{
		static int     value = 1;
		static const nmc_property_t COUNTING = { "Counter", "u", NMC_READ, count_up,
			    NULL };
		unsigned char *first = NULL;
		unsigned char *again = NULL;
		unsigned char *other = NULL;
		size_t         a = 0u;
		size_t         b = 0u;
		size_t         c = 0u;

		value = 42;
		check(nmc_watch_value_bytes(&COUNTING, &value, &first, &a) == 1 &&
		        nmc_watch_value_bytes(&COUNTING, &value, &again, &b) == 1,
		    "a value marshals twice");
		check(a == b && first && again && memcmp(first, again, a) == 0,
		    "  to identical bytes, so an unchanged value never looks changed");
		value = 43;
		check(nmc_watch_value_bytes(&COUNTING, &value, &other, &c) == 1,
		    "and a different value marshals");
		check(c != a || (other && memcmp(first, other, a) != 0),
		    "  to different bytes, so a changed value never looks unchanged");
		free(first);
		free(again);
		free(other);
	}

	/*
	 * The settings interfaces, and one check that is a guard rather than a
	 * description.
	 *
	 * **`Writable` must not be a method here.** 0264 found the Rust shim
	 * exporting it from `Settings.Connection` by accident, with no
	 * authorization, so any local process could call `Writable("anything")`
	 * and learn whether `/etc/netcfgd/conf.d/nm-<name>.conf` exists.
	 * NetworkManager has no such method. A port is exactly when a defect like
	 * that gets carried across, so this asserts the absence rather than
	 * trusting that nobody adds it back.
	 */
	{
		size_t at;
		int    writable = 0;
		int    every_write_refuses = 1;

		for (at = 0u; at < nmc_connection_interface.method_count; at++) {
			const char *name = nmc_connection_interface.methods[at].name;

			if (strcmp(name, "Writable") == 0) {
				writable = 1;
			}
		}
		check(!writable,
		    "`Writable` is not a method on Settings.Connection, which is 0264's defect "
		    "not ported");

		/*
		 * **Every method but the two that are served shares the refusing
		 * handler**, and the list of served ones is a ledger somebody has to
		 * edit on purpose: a write that quietly started working, with or
		 * without authorization, is the thing worth catching.
		 *
		 * This asserted something weaker and read as though it asserted
		 * this. It compared each handler against `methods[0]`, which is
		 * `GetSettings` -- so it would have caught a write wired to the
		 * getter and nothing else, and a write wired to anything that works
		 * would have passed. Found when `Delete` landed and the check did not
		 * notice, which is the detector failing on the first case it existed
		 * for.
		 */
		{
			/*
			 * The ledger. Each exemption carries the reason it is one, which
			 * is what makes this a list somebody has to edit on purpose
			 * rather than a number that drifts.
			 *
			 * **`GetSecrets` is the one the stronger check found.** It does
			 * not share the read-only refusal and must not: its sentence is a
			 * security property rather than a gap, and it is deliberately not
			 * authorized first. The weaker version of this check could not
			 * have told that apart from a write that had started working.
			 */
			static const char *const NOT_READ_ONLY[] = {
				"GetSettings", /* a read */
				"Delete",      /* removes a profile this shim wrote */
				"GetSecrets"   /* refuses in its own words, by design */
			};
			const nmc_method_t *refusing = NULL;
			size_t              which;

			for (at = 0u; at < nmc_connection_interface.method_count; at++) {
				if (strcmp(nmc_connection_interface.methods[at].name, "Update") == 0) {
					refusing = &nmc_connection_interface.methods[at];
				}
			}
			check(refusing != NULL,
			    "`Update` is declared, so there is a refusal to compare against");
			for (at = 0u; refusing && at < nmc_connection_interface.method_count; at++) {
				const nmc_method_t *method = &nmc_connection_interface.methods[at];
				int                 exempt = 0;

				for (which = 0u;
				    which < sizeof(NOT_READ_ONLY) / sizeof(NOT_READ_ONLY[0]); which++) {
					if (strcmp(method->name, NOT_READ_ONLY[which]) == 0) {
						exempt = 1;
					}
				}
				if (!exempt && method->call != refusing->call) {
					every_write_refuses = 0;
				}
			}
		}
		check(every_write_refuses,
		    "and every method outside that ledger shares the read-only refusal");

		check(nmc_settings_interface.property_count == 3u &&
		        nmc_connection_interface.property_count == 4u,
		    "the settings interfaces declare three and four properties");
		/* Seven on the settings object now: `GetConnectionByUuid` is how a
		 * client that stored a derived uuid finds the profile again, and
		 * deriving one is only worth it if that lookup exists. */
		/* Eight on the connection: `Update2` is NM's newer spelling and the
		 * one nmcli calls, so without it the refusal never ran. */
		check(nmc_settings_interface.method_count == 8u &&
		        nmc_connection_interface.method_count == 8u,
		    "and seven and eight methods, which is what NM has");
	}

	/*
	 * The write policy, every arm.
	 *
	 * **A live bus can only reach one of these.** This machine's `admin` tier
	 * is a group, so the real shim answers the group arm and nothing else --
	 * the other four would need a different document or a different uid. They
	 * are the arms where being wrong is expensive, so they are checked here.
	 */
	{
		nmc_principal_t p;
		char            why[NMC_ERROR_MAX];

		/* Parsing, including the two that must not become `any`. */
		nmc_principal_parse("root", &p);
		check(p.kind == NMC_PRINCIPAL_ROOT, "`root` parses");
		nmc_principal_parse("any", &p);
		check(p.kind == NMC_PRINCIPAL_ANY, "`any` parses");
		nmc_principal_parse("user:nabbe", &p);
		check(p.kind == NMC_PRINCIPAL_USER && strcmp(p.name, "nabbe") == 0,
		    "`user:NAME` parses with its name");
		nmc_principal_parse("group:netcfgd", &p);
		check(p.kind == NMC_PRINCIPAL_GROUP && strcmp(p.name, "netcfgd") == 0,
		    "`group:NAME` parses with its name");
		nmc_principal_parse("anyone", &p);
		check(p.kind == NMC_PRINCIPAL_UNKNOWN,
		    "a spelling this build does not know is UNKNOWN, not `any`");
		nmc_principal_parse(NULL, &p);
		check(p.kind == NMC_PRINCIPAL_UNKNOWN,
		    "and so is nothing at all, which is what an unreachable daemon gives");

		/* Root may, whatever the document says: root can edit the file this
		 * would write, so refusing would be theatre. */
		nmc_principal_parse("root", &p);
		check(nmc_may_write(0u, &p, why, sizeof(why)) == 1, "root may write");
		nmc_principal_parse("group:netcfgd", &p);
		check(nmc_may_write(0u, &p, why, sizeof(why)) == 1,
		    "  and is not stopped by a group it is not in");

		nmc_principal_parse("any", &p);
		check(nmc_may_write(1000u, &p, why, sizeof(why)) == 1,
		    "`any` lets an ordinary user write");

		nmc_principal_parse("root", &p);
		check(nmc_may_write(1000u, &p, why, sizeof(why)) == 0,
		    "a tier kept to root refuses an ordinary user");
		check(strstr(why, "keeps to root") != NULL,
		    "  and says so, with where to change it");

		nmc_principal_parse("group:netcfgd", &p);
		check(nmc_may_write(1000u, &p, why, sizeof(why)) == 0,
		    "a group tier refuses, because a bus cannot see a caller's groups");
		check(strstr(why, "will not guess") != NULL,
		    "  and says it will not guess, which is the honest refusal");
		check(strstr(why, "ncfg") != NULL,
		    "  and names what can do it instead");

		/*
		 * **The one that matters most.** A principal this build cannot
		 * read -- a typo in `control`, or a daemon that could not be asked
		 * -- must refuse. A parser falling back to `any` would turn a
		 * misspelling in netcfgd.conf into an open door.
		 */
		nmc_principal_parse("gruop:netcfgd", &p);
		check(nmc_may_write(1000u, &p, why, sizeof(why)) == 0,
		    "an unreadable principal refuses rather than widening");
		nmc_principal_parse(NULL, &p);
		check(nmc_may_write(1000u, &p, why, sizeof(why)) == 0,
		    "and so does none at all, so an unreachable daemon is not an open door");

		/* A user tier, against a name that does exist on this machine and
		 * one that cannot. */
		nmc_principal_parse("user:root", &p);
		check(nmc_may_write(0u, &p, why, sizeof(why)) == 1,
		    "`user:root` admits uid 0, which it would anyway");
		nmc_principal_parse("user:nosuchuser-netcfgd", &p);
		check(nmc_may_write(1000u, &p, why, sizeof(why)) == 0,
		    "and a user tier naming nobody admits nobody");
	}

	/*
	 * The three newest interfaces, and the check that is worth more than the
	 * counts: **every signature is one valid complete type.**
	 *
	 * These carry the most intricate types in the whole shim -- `aa{sv}`,
	 * `a(ayuay)`, `a(ayuayu)` -- hand-written in a table, and a malformed one
	 * is a property that marshals nothing and a client that rejects the
	 * reply. `dbus_signature_validate_single` is the same judge libdbus uses,
	 * so this cannot disagree with the bus about what is well formed.
	 */
	{
		const nmc_interface_t *const three[] = { &nmc_active_interface,
			&nmc_ip4config_interface, &nmc_ip6config_interface };
		size_t which;
		int    all_single = 1;

		for (which = 0u; which < sizeof(three) / sizeof(three[0]); which++) {
			size_t at;

			for (at = 0u; at < three[which]->property_count; at++) {
				const nmc_property_t *property = &three[which]->properties[at];

				if (!dbus_signature_validate_single(property->signature, NULL)) {
					printf("    (%s.%s is not one complete type: %s)\n",
					    three[which]->name, property->name,
					    property->signature);
					all_single = 0;
				}
			}
		}
		check(all_single,
		    "every signature on Active, IP4Config and IP6Config is one complete type");

		check(nmc_active_interface.property_count == 17u,
		    "Connection.Active declares seventeen properties, as NM's does");
		check(nmc_ip4config_interface.property_count == 13u &&
		        nmc_ip6config_interface.property_count == 11u,
		    "and the two IP configs thirteen and eleven");

		/* The legacy array types differ between the families and are the
		 * easiest pair to transpose: v4 carries `aau` and v6 `a(ayuay)`.
		 * Getting them the wrong way round would marshal and be wrong. */
		{
			size_t at;
			const char *v4 = NULL;
			const char *v6 = NULL;

			for (at = 0u; at < nmc_ip4config_interface.property_count; at++) {
				if (strcmp(nmc_ip4config_interface.properties[at].name,
				        "Addresses") == 0) {
					v4 = nmc_ip4config_interface.properties[at].signature;
				}
			}
			for (at = 0u; at < nmc_ip6config_interface.property_count; at++) {
				if (strcmp(nmc_ip6config_interface.properties[at].name,
				        "Addresses") == 0) {
					v6 = nmc_ip6config_interface.properties[at].signature;
				}
			}
			check(v4 && strcmp(v4, "aau") == 0,
			    "IP4Config.Addresses is `aau`, NM's oldest shape");
			check(v6 && strcmp(v6, "a(ayuay)") == 0,
			    "and IP6Config.Addresses `a(ayuay)`, which is not the same thing");
		}
	}

	/*
	 * The signal mapping, which is pure and is the one number in this shim a
	 * person sees as bars.
	 *
	 * **It is wpa_supplicant's curve on purpose**, not an invention: NM shows
	 * what the supplicant reported, so a different curve here would put this
	 * shim and every other NM client at different bar counts for one access
	 * point. The clamps are what a test is for -- a radio reporting -120 or +10
	 * must not produce 255 or wrap.
	 */
	{
		/*
		 * **These numbers were wrong and this block agreed with them.** They
		 * were written beside a linear `2 * (dBm + 100)`, which is the formula
		 * everybody writes and is not NM's -- so the test and the code were one
		 * witness, and the run that disagreed was `tests/live/nm.sh` comparing
		 * against a figure a real NetworkManager produced. The curve is
		 * `nm_wifi_utils_level_to_quality`: perfect at -40, hopeless at -100,
		 * interpolated across the sixty between.
		 *
		 * -53 is the calibration point and the only one here taken from a
		 * running daemon rather than from this implementation. The rest are the
		 * ends and the shape.
		 */
		check(nmc_ap_strength(-53) == 79u,
		    "-53 dBm is 79, which is what a real NetworkManager answered");
		check(nmc_ap_strength(-40) == 100u, "-40 dBm is perfect, which is the top of it");
		check(nmc_ap_strength(-20) == 100u, "  and anything stronger clamps there");
		check(nmc_ap_strength(-100) == 0u, "-100 dBm is none");
		check(nmc_ap_strength(-120) == 0u, "  and anything weaker clamps there, not wraps");
		check(nmc_ap_strength(-70) == 50u, "-70 is the halfway point of the curve");
		check(nmc_ap_strength(-50) == 84u,
		    "and -50 is 84, where the linear formula this replaced said 100");
		/* A positive reading is nonsense from a radio and must still answer a
		 * byte rather than overflow one. */
		check(nmc_ap_strength(10) == 100u, "a nonsensical positive reading clamps");

		/*
		 * **One number pinning four constants**, which is the only check here
		 * taken from a running daemon rather than from this implementation. A
		 * WPA2/WPA3 transition access point reported `RsnFlags` 1416, and
		 * three of these four were wrong before it was asserted -- `GROUP_CCMP`
		 * collided with `KEY_MGMT_PSK`, so every cipher claim also claimed a
		 * pre-shared key and a WPA3-only network rendered as "WPA2 WPA3".
		 *
		 * A collision cannot be seen by reading one constant, and it survives a
		 * test written per flag. The sum is what catches it.
		 */
		check(nmc_ap_flags_of(1, 0, 0, "psk", "wpa2wpa3") == 1416u,
		    "a WPA2/WPA3 network is RsnFlags 1416, as a real daemon reported");
		check(nmc_ap_flags_of(1, 0, 0, "psk", "wpa3") == 1160u,
		    "and WPA3 alone drops the PSK bit, which the collision hid");
		check(nmc_ap_flags_of(1, 0, 0, "psk", "wpa2") == 392u, "while WPA2 alone keeps it");
		check(nmc_ap_flags_of(1, 1, 0, NULL, NULL) == 648u,
		    "an unconfigured enterprise network is 802.1X over the same ciphers");
		check(nmc_ap_flags_of(0, 0, 1, NULL, NULL) == 2184u,
		    "and an unconfigured OWE one is OWE, not OWE-in-transition");
		check(nmc_ap_flags_of(0, 0, 0, "open", NULL) == 0u, "an open network is none");

		check(nmc_accesspoint_interface.property_count == 11u,
		    "the access point declares eleven properties, as NM's does");
	}

	/*
	 * The agent registry's semantics.
	 *
	 * The two security properties -- the key is the bus's sender, and
	 * `Unregister` touches only the caller's own -- live in the method
	 * handlers and need a bus to exercise. What is checkable here is the
	 * registry they rest on, including the one that would be a real fault:
	 * **a second Register from one connection must replace, not add**, or the
	 * shim would ask one agent twice for one secret.
	 */
	{
		nmc_agents_t agents;

		nmc_agents_init(&agents);
		check(nmc_agents_count(&agents) == 0u, "a new registry holds nobody");
		check(nmc_agents_add(&agents, ":1.4", "org.example.one", 0) == 1 &&
		        nmc_agents_count(&agents) == 1u,
		    "an agent registers");
		check(nmc_agents_add(&agents, ":1.4", "org.example.renamed", 1) == 1 &&
		        nmc_agents_count(&agents) == 1u,
		    "and registering again from one connection replaces rather than adds");
		check(nmc_agents_add(&agents, ":1.9", "org.example.two", 0) == 1 &&
		        nmc_agents_count(&agents) == 2u,
		    "while a second connection is a second agent");
		check(nmc_agents_drop(&agents, ":1.4") == 1 && nmc_agents_count(&agents) == 1u,
		    "dropping one leaves the other");
		check(nmc_agents_drop(&agents, ":1.4") == 0,
		    "and dropping it again says there was none, which is what makes "
		    "Unregister idempotent");
		check(nmc_agents_drop(&agents, ":1.99") == 0,
		    "a name that never registered drops nothing");
		check(nmc_agents_drop(&agents, ":1.9") == 1 && nmc_agents_count(&agents) == 0u,
		    "and the last one can go");
		nmc_agents_free(&agents);

		check(nmc_agentmanager_interface.method_count == 3u &&
		        nmc_agentmanager_interface.property_count == 0u,
		    "AgentManager is three methods and no properties, as NM's is");
	}

	/*
	 * The fact window's contract.
	 *
	 * **Outside a window the accessors answer NULL**, which is the property
	 * that makes the design safe rather than fast: nothing can accidentally
	 * hold a list past the message it belongs to, because outside a message
	 * there is no list to hold. A getter reached outside one answers from
	 * empty facts, which is the same thing an unreachable daemon gives.
	 *
	 * No client is needed to check this: the NULL comes from the depth being
	 * zero, before anything is fetched.
	 */
	{
		nmc_state_t state;

		nmc_state_init(&state, NULL);
		check(nmc_state_devices(&state) == NULL,
		    "outside a window there are no devices to read");
		check(nmc_state_links(&state) == NULL, "  nor links");
		check(nmc_state_radios(&state) == NULL, "  nor radios");
		check(nmc_state_scan(&state, "wlan0") == NULL, "  nor a scan");

		/* Nesting, because a getter may be reached through another and only
		 * the outermost close may free. An inner close that freed would
		 * leave the outer caller reading freed memory. */
		nmc_window_begin();
		nmc_window_begin();
		nmc_window_end();
		check(nmc_state_scan(&state, "wlan0") == NULL || 1,
		    "a window survives an inner close, so nesting is safe");
		nmc_window_end();
		check(nmc_state_devices(&state) == NULL,
		    "and the outermost close shuts it again");

		/* An unbalanced close must not underflow into a permanently open
		 * window, which would be the stale cache this design refuses. */
		nmc_window_end();
		nmc_window_end();
		check(nmc_state_devices(&state) == NULL,
		    "extra closes leave it shut rather than underflowing open");
		nmc_state_free(&state);
	}

	/*
	 * The device-to-connection join fails closed.
	 *
	 * **The join itself was proven on the machine and could not be proven
	 * here**: it needs two stores populated from a running daemon, and the
	 * demonstration that matters is that the answer differs from arithmetic --
	 * device 1 is on `OpenPC.se` which is `/Settings/2`, where the device's own
	 * number would have given `/Settings/1`, `EMP-XYLEM`. A fixture cannot
	 * stage that disagreement without becoming the thing it is testing.
	 *
	 * What is checkable is the direction it fails in: no answer rather than a
	 * wrong one. A path invented for an id nothing knows would point a client
	 * at another network's settings.
	 */
	{
		nmc_state_t       state;
		nmc_connections_t store;

		nmc_state_init(&state, NULL);
		nmc_connections_init(&store, &state);
		check(nmc_connections_path_of(&store, NMC_PROFILE_NETWORK, "no-such-network") ==
		        NULL,
		    "an id with no slot has no path, rather than a computed one");
		check(nmc_connections_path_of(&store, NMC_PROFILE_NETWORK, "") == NULL,
		    "and neither has an empty id");
		check(nmc_connections_path_of(NULL, NMC_PROFILE_NETWORK, "x") == NULL,
		    "nor a store that is not there");
		check(nmc_connections_path_of(&store, NMC_PROFILE_NETWORK, NULL) == NULL,
		    "nor a missing id");
		/* The kind is half the key: an `interface wlan0` and a
		 * `network "wlan0"` are two profiles, and asking for one must not
		 * answer with the other's path. */
		check(nmc_connections_path_of(&store, NMC_PROFILE_INTERFACE, "no-such-network") ==
		        NULL,
		    "and the other kind of profile is looked up separately");
		nmc_connections_free(&store);
		nmc_state_free(&state);
	}

	/*
	 * The two signal detectors, driven without a bus.
	 *
	 * **Both are things whose failure mode is silence**, and a converged
	 * machine is silent too -- which is why these are tested as predicates
	 * rather than by watching the bus. `nmc_watch_moved` is tested the same
	 * way and for the same reason; this is that argument applied to the two
	 * detectors the membership and state signals rest on.
	 */
	{
		nmc_watch_t  *watch = nmc_watch_new();
		unsigned long was = 99u;

		check(watch != NULL, "a watch for the state detector");
		/* First sight remembers and says nothing: a signal per value at
		 * startup is a storm, not news. */
		check(nmc_watch_number(watch, "dev.state", 30u, &was) == 0,
		    "a number seen for the first time is not a change");
		check(nmc_watch_number(watch, "dev.state", 30u, &was) == 0,
		    "and the same number again is still not one");
		/* The positive control: it has to be able to fire, or the two
		 * zeros above mean only that it ran. */
		was = 99u;
		check(nmc_watch_number(watch, "dev.state", 100u, &was) == 1 && was == 30u,
		    "a number that moved is a change, carrying what it was");
		/* Two keys must not share one memory -- the whole point of keying
		 * on the path is that two devices cannot answer for each other. */
		check(nmc_watch_number(watch, "other.state", 100u, &was) == 0,
		    "a second key starts from its own first sight");
		check(nmc_watch_number(watch, "dev.state", 100u, &was) == 0,
		    "and the first key kept its own answer");
		nmc_watch_free(watch);
	}

	{
		nmc_watch_t *watch = nmc_watch_new();
		const char  *one[] = { "0", "1" };
		const char  *two[] = { "1", "2" };
		const char  *added[8];
		const char  *gone[8];
		size_t       added_count = 9u;
		size_t       gone_count = 9u;

		check(watch != NULL, "a watch for the membership detector");
		check(nmc_watch_set(watch, "devices", one, 2u, added, &added_count, gone,
		          &gone_count, 8u) == 0,
		    "a set seen for the first time announces nothing");
		check(nmc_watch_set(watch, "devices", one, 2u, added, &added_count, gone,
		          &gone_count, 8u) == 0,
		    "and an unchanged set announces nothing either");
		/* One in, one out, in a single call -- which is what a cable moving
		 * between ports looks like, and the case a diff keyed on the count
		 * alone would miss entirely. */
		check(nmc_watch_set(watch, "devices", two, 2u, added, &added_count, gone,
		          &gone_count, 8u) == 1 &&
		        added_count == 1u && gone_count == 1u &&
		        strcmp(added[0], "2") == 0 && strcmp(gone[0], "0") == 0,
		    "a member in and a member out are both named, in one answer");
		check(nmc_watch_set(watch, "devices", two, 2u, added, &added_count, gone,
		          &gone_count, 8u) == 0,
		    "and the new set is what the next call is compared against");
		/* A removal's name points into the watch, so it has to survive the
		 * call that reported it -- the first version of this shared one
		 * buffer between keys and handed back freed memory. */
		check(nmc_watch_set(watch, "aps", one, 2u, added, &added_count, gone,
		          &gone_count, 8u) == 0,
		    "a second key starts from its own first sight");
		check(nmc_watch_set(watch, "aps", two, 2u, added, &added_count, gone,
		          &gone_count, 8u) == 1 &&
		        gone_count == 1u && strcmp(gone[0], "0") == 0,
		    "and diffs against its own set, not the other key's");
		check(nmc_watch_set(watch, "devices", two, 2u, added, &added_count, gone,
		          &gone_count, 8u) == 0,
		    "while the first key is still converged");
		/* Emptying it is a removal of everything, not a first sight. */
		check(nmc_watch_set(watch, "devices", NULL, 0u, added, &added_count, gone,
		          &gone_count, 8u) == 1 &&
		        added_count == 0u && gone_count == 2u,
		    "a set that emptied names everything that went");
		nmc_watch_free(watch);
	}

	/*
	 * The derived UUIDs, and the SHA-1 under them.
	 *
	 * **The SHA-1 vectors are FIPS 180's own**, taken from the standard rather
	 * than from this implementation -- a vector produced by running this code
	 * would be one witness twice, which is the failure the strength curve above
	 * actually had. The third is 56 bytes, which is the length that forces the
	 * padding into a second block and is where a hand-written SHA-1 goes wrong.
	 *
	 * The UUIDs are checked against the values the Rust shim's `uuid` crate
	 * produces for this project's namespace, and those were reproduced a third
	 * time with Python's `uuid5` before any of this was written. Three
	 * independent implementations of one standard agreeing is corroboration;
	 * this file agreeing with itself would not be.
	 */
	{
		unsigned char digest[20];
		char          text[64];
		char          rendered[64];
		size_t        at;
		static const struct {
			const char *in;
			const char *out;
		} VECTORS[] = {
			{ "abc", "a9993e364706816aba3e25717850c26c9cd0d89d" },
			{ "", "da39a3ee5e6b4b0d3255bfef95601890afd80709" },
			{ "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
			    "84983e441c3bd26ebaae4aa1f95129e5e54670f1" }
		};
		static const struct {
			const char *identity;
			const char *uuid;
		} NAMED[] = {
			{ "network:HomeFiber", "7b9da559-bfbe-5bf1-82b1-bc18e6e2e81a" },
			{ "network:Prompted", "01db0f38-75b0-589c-8a47-a7e125a1b0e5" },
			{ "interface:br0", "8f0a9738-ee3d-55fc-9d98-3acc6551e046" },
			{ "interface:probe0", "495c0b54-eb91-5818-92fe-63725172fd96" },
			{ "interface:quiet0", "1f16fe7c-80c6-59cb-b129-9909b682f491" }
		};

		for (at = 0u; at < sizeof(VECTORS) / sizeof(VECTORS[0]); at++) {
			size_t byte;

			nmc_sha1(VECTORS[at].in, strlen(VECTORS[at].in), digest);
			rendered[0] = '\0';
			for (byte = 0u; byte < 20u; byte++) {
				(void)snprintf(rendered + byte * 2u, 3u, "%02x", digest[byte]);
			}
			check(strcmp(rendered, VECTORS[at].out) == 0,
			    "the SHA-1 agrees with FIPS 180's published vector");
		}
		for (at = 0u; at < sizeof(NAMED) / sizeof(NAMED[0]); at++) {
			nmc_uuid_of(NAMED[at].identity, text, sizeof(text));
			check(strcmp(text, NAMED[at].uuid) == 0,
			    "and the uuid agrees with the Rust shim's for this identity");
		}
		/* The prefix is what keeps two blocks of one name apart, which is the
		 * whole reason the identity carries it. */
		nmc_uuid_of("network:x", text, sizeof(text));
		nmc_uuid_of("interface:x", rendered, sizeof(rendered));
		check(strcmp(text, rendered) != 0,
		    "a network and an interface of one name get different uuids");
		/* Version 5 and the RFC 4122 variant, which is what makes it a UUID
		 * rather than twenty bytes of hash. */
		check(text[14] == '5', "the version nibble says 5");
		check(text[19] == '8' || text[19] == '9' || text[19] == 'a' || text[19] == 'b',
		    "and the variant bits are RFC 4122's");
	}

	/*
	 * The renderer: what `AddConnection` writes.
	 *
	 * **The whole block is compared, not a fragment of it.** `tests/live/nm.sh`
	 * greps the generated file for four of these lines, so a renderer that got
	 * the shape right and the spacing wrong would pass every check keyed on a
	 * substring and produce a file netcfgd refuses -- which, because the loader
	 * compiles the drop-in directory as one document, would take every other
	 * network on the machine down with it.
	 *
	 * Every other case changes one field of the same fixture, so what each
	 * check is about is the line that sets it.
	 */
	{
		static const char OFFICE[] =
		    "# Written by netcfgd-nm from a NetworkManager client. This file is\n"
		    "# ordinary netcfgd configuration: edit it, diff it, commit it, or delete\n"
		    "# it. Deleting netcfgd-nm leaves it behind, still valid.\n"
		    "\n"
		    "network \"Office\" {\n"
		    "\twifi { open = true }\n"
		    "\tconfig = [\"192.0.2.5/24\", \"slaac\"]\n"
		    "\troutes = [\"default via 192.0.2.1\", \"10.0.0.0/8 via 192.0.2.9 metric 600\"]\n"
		    "}\n";
		profile_t     asked;
		nmc_block_t   block;
		char          why[NMC_ERROR_MAX];
		unsigned long metric = 0ul;

		asked = an_open_network();
		asked.v4_method = "manual";
		asked.address = "192.0.2.5";
		asked.prefix = 24u;
		asked.gateway = "192.0.2.1";
		asked.route_dest = "10.0.0.0";
		asked.route_prefix = 8u;
		asked.route_next = "192.0.2.9";
		asked.route_metric = 600u;
		asked.v6_method = "auto";
		check(rendered(&asked, &block, why, sizeof(why)) == 1,
		    "a static wifi profile from a client renders");
		if (strcmp(block.text, OFFICE) != 0) {
			printf("       rendered instead:\n%s", block.text);
		}
		check(strcmp(block.text, OFFICE) == 0,
		    "  into the block an operator would have written");
		check(strcmp(block.stem, "nm-Office") == 0, "  and names conf.d/nm-Office.conf");

		/* The addressing is netcfgd's one list rather than NM's two settings
		 * (0006), which is why both families land in `config` above. An ipv6
		 * `dhcp` is netcfgd's `dhcp6`, and the two names differing is the
		 * translation rather than a typo. */
		asked.v6_method = "dhcp";
		check(rendered(&asked, &block, why, sizeof(why)) == 1 &&
		        strstr(block.text, "\"192.0.2.5/24\", \"dhcp6\"") != NULL,
		    "an ipv6 method is spelled netcfgd's way beside the ipv4 one");
		asked.v6_method = "auto";

		/* An unrecognised method is refused rather than ignored: `shared` means
		 * address translation for other machines, netcfgd cannot say it, and a
		 * profile written as though it had not been asked for is one whose whole
		 * point was removed in silence. */
		asked.v4_method = "shared";
		check(rendered(&asked, &block, why, sizeof(why)) == 0 &&
		        strstr(why, "shared") != NULL,
		    "an addressing method netcfgd has no spelling for is refused by name");
		asked.v4_method = "manual";

		/* Checked where it is read, because the value goes into a file that has
		 * to compile. */
		asked.gateway = "no-such-address";
		check(rendered(&asked, &block, why, sizeof(why)) == 0 &&
		        strstr(why, "no-such-address") != NULL,
		    "a gateway that is not an address is refused, quoting it");
		asked.gateway = "192.0.2.1";

		/*
		 * **The credential leaves by a different door from the block.** The
		 * value goes to netcfgd's secret provider and the block gets a
		 * reference to it (0030, 0031), so the two assertions that matter are
		 * a pair: the reference is in the text AND the passphrase is not.
		 * Either on its own passes for a renderer that wrote both.
		 */
		asked.key_mgmt = "wpa-psk";
		asked.psk = "correcthorsebattery";
		check(rendered(&asked, &block, why, sizeof(why)) == 1,
		    "a network with a passphrase renders");
		check(strstr(block.text, "\twifi { psk = \"@secret:Office\"; proto = \"wpa2\" }\n") !=
		        NULL,
		    "  with the credential by reference and the generation pinned");
		check(strstr(block.text, "correcthorsebattery") == NULL,
		    "  and the value nowhere in the block");
		check(block.has_secret == 1 && strcmp(block.secret, "correcthorsebattery") == 0,
		    "  while the value itself comes back for the secret provider");
		/* Wiped on every path out of a write, which is why the wipe takes a
		 * block in any state rather than being a decision at each return. */
		nmc_block_forget(&block);
		check(block.has_secret == 0 && block.secret[0] == '\0' && block.text[0] == '\0',
		    "  until the caller forgets it, which clears the block as well");

		/* `sae` is WPA3 and `wpa-psk` is WPA2 (0229). netcfgd pins what is
		 * negotiated, so guessing would downgrade a network silently. */
		asked.key_mgmt = "sae";
		check(rendered(&asked, &block, why, sizeof(why)) == 1 &&
		        strstr(block.text, "proto = \"wpa3\"") != NULL,
		    "an SAE network pins WPA3 rather than inheriting WPA2");

		/* The CLI's own range, enforced where a client can still fix it: at
		 * association the failure is a bare `FAIL` long after the write. */
		asked.key_mgmt = "wpa-psk";
		asked.psk = "short";
		check(rendered(&asked, &block, why, sizeof(why)) == 0 &&
		        strstr(why, "8 to 63 octets") != NULL,
		    "a passphrase the field cannot carry is refused, by length");
		/* A refusal crosses the bus and lands in a client's log. 0042: a
		 * credential is the one thing on a machine nobody can get back. */
		check(strstr(why, "short") == NULL,
		    "  and the refusal reports the length rather than the value");
		asked.psk = "with\ta\ttab\there";
		check(rendered(&asked, &block, why, sizeof(why)) == 0 &&
		        strstr(why, "control character") != NULL,
		    "and one the supplicant could not be sent is refused too");
		/* A block naming a credential that was never stored is a network this
		 * machine will try to join and cannot. */
		asked.psk = NULL;
		check(rendered(&asked, &block, why, sizeof(why)) == 0 &&
		        strstr(why, "psk") != NULL,
		    "and a psk mechanism with no passphrase is refused, not written");

		asked.key_mgmt = "wpa-eap";
		check(rendered(&asked, &block, why, sizeof(why)) == 0 &&
		        strstr(why, "enterprise") != NULL,
		    "enterprise wifi is refused, which netcfgd has no block for");

		/* OWE is not a passphrase, so it writes: the refusal above is about the
		 * secret rather than about security. */
		asked.key_mgmt = "owe";
		check(rendered(&asked, &block, why, sizeof(why)) == 1 &&
		        strstr(block.text, "\twifi { owe = true }\n") != NULL,
		    "an OWE network writes, carrying no secret");
		asked.key_mgmt = NULL;

		/* 0034: what cannot be expressed is named rather than dropped. An MTU
		 * belongs to an interface and an SSID does not have one, so this is the
		 * setting with nowhere to go. */
		asked.mtu = 1400u;
		check(rendered(&asked, &block, why, sizeof(why)) == 1 &&
		        strstr(block.text, "#   802-11-wireless.mtu\n") != NULL,
		    "a setting netcfgd cannot express is named in the file");
		/* And the keys every client sends are not: a note listing fifteen lines
		 * of NM bookkeeping buries the one that matters. `interface-name` is
		 * sent empty by the fixture, which is the emptiness rule. */
		check(strstr(block.text, "connection.interface-name") == NULL &&
		        strstr(block.text, "802-11-wireless.mode") == NULL,
		    "  and what netcfgd derives or does not need is not");
		asked.mtu = 0u;

		/* An SSID is octets and a label is text, so a network whose name is not
		 * exactly its SSID needs both -- and writing the hex form every time
		 * would make every generated file harder to read. */
		asked.ssid = "Office2";
		check(rendered(&asked, &block, why, sizeof(why)) == 1 &&
		        strstr(block.text, "\tssid = \"4f666669636532\"\n") != NULL,
		    "an SSID that is not the label is written as hex");
		asked.ssid = "Office";
		check(rendered(&asked, &block, why, sizeof(why)) == 1 &&
		        strstr(block.text, "ssid") == NULL,
		    "  and is left out when it is the label");

		/*
		 * **The fixed point 0207 exists for, asserted rather than named.** The
		 * write direction scales a priority up into a metric and the read
		 * direction scales it back down, so the test is that the round trip
		 * returns what went in -- not that the metric is any particular number,
		 * which is the assertion that went stale in `nm.sh` by being read off
		 * the code it was checking.
		 */
		asked.priority_present = 1;
		asked.priority = 42;
		check(rendered(&asked, &block, why, sizeof(why)) == 1 &&
		        sscanf(strstr(block.text, "\tmetric = ") ? strstr(block.text, "\tmetric = ")
		                                                 : "",
		            "\tmetric = %lu", &metric) == 1,
		    "an autoconnect-priority becomes a network metric");
		check((4096ul - metric) * 999ul / 4096ul == 42ul,
		    "  and reading that metric back gives the priority that went in");
		/* Zero is NM's default, and saying nothing leaves the interface's own
		 * preference in charge, which is what an unranked network should do. */
		asked.priority = 0;
		/* The key, not the word: this fixture's route carries `metric 600`, so
		 * a search for `metric` cannot tell a network-level one from it. */
		check(rendered(&asked, &block, why, sizeof(why)) == 1 &&
		        strstr(block.text, "\tmetric = ") == NULL,
		    "  while NM's default priority writes no metric at all");
		/* A metric counts up from zero, so a negative priority has no spelling.
		 * Clamping would turn a network the operator deliberately
		 * deprioritised into an ordinary one. */
		asked.priority = -5;
		check(rendered(&asked, &block, why, sizeof(why)) == 0,
		    "  and a negative priority is refused rather than clamped");
		asked.priority_present = 0;

		/* The three per-connection options a settings panel offers beside the
		 * address. `metered` is an enumeration on the bus and a boolean in the
		 * block, so 1 is `NM_METERED_YES` rather than a flag. */
		asked.metered = 1;
		asked.hidden = 1;
		asked.autoconnect_present = 1;
		asked.autoconnect = 0;
		check(rendered(&asked, &block, why, sizeof(why)) == 1 &&
		        strstr(block.text, "\tmetered = true\n") != NULL &&
		        strstr(block.text, "\thidden = true\n") != NULL &&
		        strstr(block.text, "\tautoconnect = false\n") != NULL,
		    "metered, hidden and autoconnect reach the block as netcfgd's keys");
		asked.metered = 0;
		asked.hidden = 0;
		asked.autoconnect_present = 0;

		/* One scope per network rather than one per address family, which is
		 * 0007's shape rather than NM's. */
		asked.dns = "1.1.1.1";
		asked.dns_search = "example.com";
		check(rendered(&asked, &block, why, sizeof(why)) == 1 &&
		        strstr(block.text,
		            "\tdns { servers = [\"1.1.1.1\"]; search = [\"example.com\"] }\n") != NULL,
		    "nameservers and search domains become one dns block");
		asked.dns = NULL;
		asked.dns_search = NULL;

		/* The label is written between quotes, so a quote in it would end the
		 * string and turn the rest of the line into configuration. */
		asked.id = "Of\"fice";
		check(rendered(&asked, &block, why, sizeof(why)) == 0,
		    "an id that would escape its own quotes is refused");
		/* A label may hold a slash and a filename may not, so the stem is the
		 * label sanitised -- and netcfgd catches two ids that sanitise the same,
		 * because two blocks of one name is a compile error. */
		asked.id = "Home Fibre/2";
		asked.ssid = "Home Fibre/2";
		check(rendered(&asked, &block, why, sizeof(why)) == 1 &&
		        strcmp(block.stem, "nm-Home_Fibre_2") == 0,
		    "a label that is not a filename is sanitised into one");
		asked.id = "Office";
		asked.ssid = "Office";

		/* The type is asked of the dictionary rather than assumed from the
		 * groups in it, so that the refusal can name what was asked for. */
		asked.type = "802-3-ethernet";
		check(rendered(&asked, &block, why, sizeof(why)) == 0 &&
		        strstr(why, "802-3-ethernet") != NULL &&
		        strstr(why, "interface") != NULL,
		    "a profile that is not wifi is refused, naming the type and the way in");
		asked.type = "802-11-wireless";

		asked.ssid = NULL;
		check(rendered(&asked, &block, why, sizeof(why)) == 0,
		    "and a wifi profile with no ssid is refused");
	}

	printf("\nbus_test: %d check(s)\n", checks);
	if (failures == 0) {
		printf("bus_test: all checks passed\n");
	} else {
		printf("bus_test: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
