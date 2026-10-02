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
#include "nmc/authorize.h"
#include "nmc/ipconfig.h"
#include "nmc/active.h"
#include "nmc/accesspoint.h"
#include "nmc/agent.h"

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
		/* Two device getters, the name lookup every client resolves a
		 * device through, and the lowercase `state` older clients call. The
		 * activation pair is a write and waits for the authorization gate. */
		check(nmc_manager_interface.method_count == 4u,
		    "and the four methods a libnm client reaches for");
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
		check(nmc_connections_path_of(&store, "no-such-network") == NULL,
		    "an id with no slot has no path, rather than a computed one");
		check(nmc_connections_path_of(&store, "") == NULL, "and neither has an empty id");
		check(nmc_connections_path_of(NULL, "x") == NULL, "nor a store that is not there");
		check(nmc_connections_path_of(&store, NULL) == NULL, "nor a missing id");
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

	printf("\nbus_test: %d check(s)\n", checks);
	if (failures == 0) {
		printf("bus_test: all checks passed\n");
	} else {
		printf("bus_test: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
