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

#include <stdio.h>
#include <string.h>

static int checks;
static int failures;

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

	check(nmc_bus_introspect(&object, xml, sizeof(xml)) == 1,
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

		check(nmc_bus_introspect(&object, small, sizeof(small)) == 0,
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

		check(nmc_bus_introspect(&bare, xml, sizeof(xml)) == 1,
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

		check(nmc_bus_introspect(&manager, xml, sizeof(xml)) == 1,
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

	printf("\nbus_test: %d check(s)\n", checks);
	if (failures == 0) {
		printf("bus_test: all checks passed\n");
	} else {
		printf("bus_test: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
