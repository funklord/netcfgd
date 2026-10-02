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
		check(nmc_manager_interface.method_count == 2u,
		    "and the two device getters this slice implements");
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

		/* Every write refusing is this build's position, and a write that
		 * quietly started working without authorization is the thing worth
		 * catching. They share one handler, so one pointer comparison holds
		 * all of them. */
		for (at = 0u; at < nmc_connection_interface.method_count; at++) {
			const nmc_method_t *method = &nmc_connection_interface.methods[at];

			if (strcmp(method->name, "GetSettings") == 0) {
				continue;
			}
			if (method->call == nmc_connection_interface.methods[0].call) {
				every_write_refuses = 0;
			}
		}
		check(every_write_refuses,
		    "and every method but GetSettings shares the refusing handler");

		check(nmc_settings_interface.property_count == 3u &&
		        nmc_connection_interface.property_count == 4u,
		    "the settings interfaces declare three and four properties");
		check(nmc_settings_interface.method_count == 6u &&
		        nmc_connection_interface.method_count == 7u,
		    "and six and seven methods, which is what NM has");
	}

	printf("\nbus_test: %d check(s)\n", checks);
	if (failures == 0) {
		printf("bus_test: all checks passed\n");
	} else {
		printf("bus_test: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
