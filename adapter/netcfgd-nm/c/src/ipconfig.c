/* ipconfig.c -- the addresses a device holds, in NM's two shapes. */
#include "nmc/ipconfig.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------- appenders */

static int put_string(DBusMessageIter *into, const char *text)
{
	const char *value = text ? text : "";

	return dbus_message_iter_append_basic(into, DBUS_TYPE_STRING, &value) ? 1 : 0;
}

static int put_empty(DBusMessageIter *into, const char *signature)
{
	DBusMessageIter array;

	if (!dbus_message_iter_open_container(into, DBUS_TYPE_ARRAY, signature, &array)) {
		return 0;
	}
	return dbus_message_iter_close_container(into, &array) ? 1 : 0;
}

/* One `name -> variant` pair carrying a string. */
static void pair_string(DBusMessageIter *into, const char *name, const char *text)
{
	DBusMessageIter entry;
	DBusMessageIter variant;
	const char     *value = text ? text : "";

	if (!dbus_message_iter_open_container(into, DBUS_TYPE_DICT_ENTRY, NULL, &entry)) {
		return;
	}
	(void)dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &name);
	if (dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT, "s", &variant)) {
		(void)dbus_message_iter_append_basic(&variant, DBUS_TYPE_STRING, &value);
		(void)dbus_message_iter_close_container(&entry, &variant);
	}
	(void)dbus_message_iter_close_container(into, &entry);
}

/* The same, carrying a `u` -- which is what NM's `prefix` is. */
static void pair_u32(DBusMessageIter *into, const char *name, dbus_uint32_t value)
{
	DBusMessageIter entry;
	DBusMessageIter variant;

	if (!dbus_message_iter_open_container(into, DBUS_TYPE_DICT_ENTRY, NULL, &entry)) {
		return;
	}
	(void)dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &name);
	if (dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT, "u", &variant)) {
		(void)dbus_message_iter_append_basic(&variant, DBUS_TYPE_UINT32, &value);
		(void)dbus_message_iter_close_container(&entry, &variant);
	}
	(void)dbus_message_iter_close_container(into, &entry);
}

/* ------------------------------------------------- the link's own addresses */

/*
 * Walk the link's comma-separated addresses, handing each to `visit`.
 *
 * `ncfg_link_t.addresses` is "already ordered by the daemon", so the order NM
 * sees is netcfgd's order rather than this function's -- which matters because
 * a client shows the first one.
 */
static void for_each_address(const nmc_device_slot_t *slot, int want_six,
    void (*visit)(const char *address, unsigned prefix, void *into), void *into)
{
	char  addresses[1024] = "";
	char *cursor;
	char *rest;

	nmc_device_addresses_of(slot, addresses, sizeof(addresses));
	rest = addresses;
	while ((cursor = rest) != NULL && *cursor != '\0') {
		char    *comma = strchr(cursor, ',');
		char    *slash;
		unsigned prefix = 0u;
		int      is_six;

		if (comma) {
			*comma = '\0';
			rest = comma + 1;
		} else {
			rest = NULL;
		}
		/*
		 * **Leading whitespace, because netcfgd joins the list with `, `.**
		 * The first address is clean and every one after it arrived with a
		 * space on the front, which `AddressData` then reported as
		 * ` 2001:db8:7::1` -- an address libnm parses and drops, so a client
		 * showed the v4 address and nothing else. Only ever visible on a
		 * second address of the other family, which is why it survived
		 * `Addresses` and its packed form agreeing with each other.
		 */
		while (*cursor == ' ' || *cursor == '\t') {
			cursor++;
		}
		/* A `:` anywhere is the whole of the family test: an IPv4 literal
		 * cannot contain one, and a prefix length never does. */
		is_six = strchr(cursor, ':') != NULL;
		slash = strchr(cursor, '/');
		if (slash) {
			*slash = '\0';
			prefix = (unsigned)strtoul(slash + 1, NULL, 10);
		}
		if (cursor[0] != '\0' && is_six == (want_six ? 1 : 0)) {
			visit(cursor, prefix, into);
		}
		if (!rest) {
			break;
		}
	}
}

/* ---------------------------------------------------- IP4Config's answers */

static void one_address_data(const char *address, unsigned prefix, void *into)
{
	DBusMessageIter *array = into;
	DBusMessageIter  entry;

	if (!dbus_message_iter_open_container(array, DBUS_TYPE_ARRAY, "{sv}", &entry)) {
		return;
	}
	/* NM's two keys, and only those two: `address` and `prefix`. A client
	 * reads these by name, so an extra key is noise and a missing one is a
	 * row the client skips. */
	pair_string(&entry, "address", address);
	pair_u32(&entry, "prefix", prefix);
	(void)dbus_message_iter_close_container(array, &entry);
}

#define NMC_ADDRESS_DATA(name, six)                                                           \
	static int name(DBusMessageIter *into, void *object, char *err, size_t err_size)       \
	{                                                                                     \
		DBusMessageIter array;                                                        \
		(void)err;                                                                    \
		(void)err_size;                                                               \
		if (!dbus_message_iter_open_container(into, DBUS_TYPE_ARRAY, "aa{sv}",         \
		        &array)) {                                                            \
			return 0;                                                             \
		}                                                                             \
		for_each_address(object, (six), one_address_data, &array);                     \
		return dbus_message_iter_close_container(into, &array) ? 1 : 0;                \
	}

NMC_ADDRESS_DATA(say_v4_address_data, 0)
NMC_ADDRESS_DATA(say_v6_address_data, 1)

static void one_legacy_v4(const char *address, unsigned prefix, void *into)
{
	DBusMessageIter *array = into;
	DBusMessageIter  triple;
	struct in_addr   parsed;
	dbus_uint32_t    numbers[3];

	if (inet_pton(AF_INET, address, &parsed) != 1) {
		return;
	}
	/*
	 * **Network byte order, which is NM's oldest wart and is not negotiable.**
	 * `Addresses` predates `AddressData` and carries the address as a `u` in
	 * network order -- so on a little-endian machine the number looks
	 * byte-reversed, and a client that reads it expects exactly that. Writing
	 * host order here would give every such client a different address.
	 */
	numbers[0] = (dbus_uint32_t)parsed.s_addr;
	numbers[1] = (dbus_uint32_t)prefix;
	/* The gateway slot. netcfgd does not publish one per address, and 0 is
	 * NM's "none" here rather than a route to 0.0.0.0. */
	numbers[2] = 0u;
	if (!dbus_message_iter_open_container(array, DBUS_TYPE_ARRAY, "u", &triple)) {
		return;
	}
	(void)dbus_message_iter_append_basic(&triple, DBUS_TYPE_UINT32, &numbers[0]);
	(void)dbus_message_iter_append_basic(&triple, DBUS_TYPE_UINT32, &numbers[1]);
	(void)dbus_message_iter_append_basic(&triple, DBUS_TYPE_UINT32, &numbers[2]);
	(void)dbus_message_iter_close_container(array, &triple);
}

static int say_v4_addresses(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	DBusMessageIter array;

	(void)err;
	(void)err_size;
	if (!dbus_message_iter_open_container(into, DBUS_TYPE_ARRAY, "au", &array)) {
		return 0;
	}
	for_each_address(object, 0, one_legacy_v4, &array);
	return dbus_message_iter_close_container(into, &array) ? 1 : 0;
}

/*
 * Every route on this link, as `RouteData`.
 *
 * **The observation's, which is what this object is for** (0032): `IP4Config`
 * answers what the machine is doing, where a profile's `route-data` answers
 * what was asked for. The two can differ, and a panel showing the second under
 * the first would be telling an operator their configuration had taken effect
 * when it had not.
 *
 * It answered an empty list until the client library kept the routes it was
 * already walking -- so a device whose kernel had three routes reported none,
 * and the only thing a client could see was the gateway.
 *
 * **The default route is left out, which is 0033's split.** NM keeps its next
 * hop in `Gateway`, where `say_gateway` reports it; a row for it here as well
 * would draw a duplicate in every panel.
 */
static void for_each_route(const nmc_device_slot_t *slot, int want_six,
    void (*visit)(const ncfg_route_t *route, const char *destination, unsigned prefix,
        void *into),
    void *into)
{
	const ncfg_links_t *links = slot ? nmc_state_links(slot->state) : NULL;
	size_t              at;

	if (!links || !slot->name) {
		return;
	}
	for (at = 0u; at < links->count; at++) {
		const ncfg_link_t *link = &links->items[at];
		size_t             which;

		if (!link->name || strcmp(link->name, slot->name) != 0) {
			continue;
		}
		for (which = 0u; which < link->route_count; which++) {
			const ncfg_route_t *route = &link->routes[which];
			char                destination[64] = "";
			const char         *slash;
			unsigned            prefix = 0u;

			if (!route->destination || route->destination[0] == '\0') {
				continue;
			}
			if (strcmp(route->destination, "default") == 0) {
				continue;
			}
			/* The family is the destination's, as everywhere else here. */
			if ((strchr(route->destination, ':') != NULL) != (want_six ? 1 : 0)) {
				continue;
			}
			slash = strchr(route->destination, '/');
			if (!slash || (size_t)(slash - route->destination) >= sizeof(destination)) {
				continue;
			}
			memcpy(destination, route->destination,
			    (size_t)(slash - route->destination));
			prefix = (unsigned)strtoul(slash + 1, NULL, 10);
			visit(route, destination, prefix, into);
		}
		return;
	}
}

static void one_route_data(const ncfg_route_t *route, const char *destination, unsigned prefix,
    void *into)
{
	DBusMessageIter *array = into;
	DBusMessageIter  entry;

	if (!dbus_message_iter_open_container(array, DBUS_TYPE_ARRAY, "{sv}", &entry)) {
		return;
	}
	pair_string(&entry, "dest", destination);
	pair_u32(&entry, "prefix", (dbus_uint32_t)prefix);
	if (route->via && route->via[0] != '\0') {
		pair_string(&entry, "next-hop", route->via);
	}
	/* -1 is the kernel stating none, and NM's absence is the key being
	 * missing rather than a number meaning unranked. */
	if (route->metric >= 0) {
		pair_u32(&entry, "metric", (dbus_uint32_t)route->metric);
	}
	(void)dbus_message_iter_close_container(array, &entry);
}

#define NMC_ROUTE_DATA(name, six)                                                             \
	static int name(DBusMessageIter *into, void *object, char *err, size_t err_size)       \
	{                                                                                     \
		DBusMessageIter array;                                                        \
		(void)err;                                                                    \
		(void)err_size;                                                               \
		if (!dbus_message_iter_open_container(into, DBUS_TYPE_ARRAY, "aa{sv}",         \
		        &array)) {                                                            \
			return 0;                                                             \
		}                                                                             \
		for_each_route(object, (six), one_route_data, &array);                         \
		return dbus_message_iter_close_container(into, &array) ? 1 : 0;                \
	}

NMC_ROUTE_DATA(say_v4_route_data, 0)
NMC_ROUTE_DATA(say_v6_route_data, 1)

/*
 * The same routes in NM's oldest form: `aau` of destination, prefix, next hop
 * and metric, every address a word in network byte order.
 *
 * IPv4 only. The v6 form is `a(ayuayu)` and has to put two addresses back into
 * sixteen bytes each; `Addresses` declines that for the same reason and says so
 * -- getting the byte form subtly wrong is worse than not offering it, and
 * `RouteData` above carries the same routes in the form every current client
 * reads.
 */
static void one_legacy_v4_route(const ncfg_route_t *route, const char *destination,
    unsigned prefix, void *into)
{
	DBusMessageIter *array = into;
	DBusMessageIter  quad;
	struct in_addr   parsed;
	struct in_addr   next;
	dbus_uint32_t    numbers[4];

	if (inet_pton(AF_INET, destination, &parsed) != 1) {
		return;
	}
	numbers[0] = (dbus_uint32_t)parsed.s_addr;
	numbers[1] = (dbus_uint32_t)prefix;
	numbers[2] = 0u;
	if (route->via && route->via[0] != '\0' && inet_pton(AF_INET, route->via, &next) == 1) {
		numbers[2] = (dbus_uint32_t)next.s_addr;
	}
	numbers[3] = route->metric >= 0 ? (dbus_uint32_t)route->metric : 0u;
	if (!dbus_message_iter_open_container(array, DBUS_TYPE_ARRAY, "u", &quad)) {
		return;
	}
	(void)dbus_message_iter_append_basic(&quad, DBUS_TYPE_UINT32, &numbers[0]);
	(void)dbus_message_iter_append_basic(&quad, DBUS_TYPE_UINT32, &numbers[1]);
	(void)dbus_message_iter_append_basic(&quad, DBUS_TYPE_UINT32, &numbers[2]);
	(void)dbus_message_iter_append_basic(&quad, DBUS_TYPE_UINT32, &numbers[3]);
	(void)dbus_message_iter_close_container(array, &quad);
}

static int say_v4_routes(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	DBusMessageIter array;

	(void)err;
	(void)err_size;
	if (!dbus_message_iter_open_container(into, DBUS_TYPE_ARRAY, "au", &array)) {
		return 0;
	}
	for_each_route(object, 0, one_legacy_v4_route, &array);
	return dbus_message_iter_close_container(into, &array) ? 1 : 0;
}

/*
 * The resolver, and the two forms NM carries it in.
 *
 * **These are the machine's and not this link's, said here because the
 * difference is real.** NM's field is per-connection; netcfgd writes one
 * resolver state for the machine, so what a client is shown is what the
 * machine resolves with. The alternative -- an empty list -- would have a
 * client display "no DNS" for a connection that resolves names perfectly,
 * which is wrong in a way a person sees. A per-interface answer needs netcfgd
 * to publish a scope per link, which it has and this does not yet read.
 *
 * **The APPLIED servers, not the configured ones** (0032, and the check that
 * asks for this says so in its own name). It read `dns.servers`, which is what
 * the document names -- so a machine whose resolver came from an interface's
 * own scope reported nothing while `resolv.conf` named two servers. The
 * observation carries what resolution is using, and the client library kept
 * only the count of it until now.
 *
 * **And split by family**, which it was not: every server went into both
 * objects, so `IP4Config` offered an IPv6 nameserver to a client that would
 * use it as one. The same wrong-family fault the address list had, one
 * property along.
 */
static void for_each_nameserver(const nmc_device_slot_t *slot, int want_six,
    void (*visit)(const char *address, void *into), void *into)
{
	ncfg_client_t *client = slot ? nmc_state_client(slot->state) : NULL;
	ncfg_dns_t     dns;
	char           problem[256] = "";
	size_t         at;

	if (!client) {
		return;
	}
	memset(&dns, 0, sizeof(dns));
	if (!ncfg_client_dns(client, &dns, problem, sizeof(problem))) {
		return;
	}
	for (at = 0u; at < dns.applied_server_count; at++) {
		const char *address = dns.applied_servers[at];

		if (!address || address[0] == '\0') {
			continue;
		}
		if ((strchr(address, ':') != NULL) == (want_six ? 1 : 0)) {
			visit(address, into);
		}
	}
	ncfg_dns_free(&dns);
}

static void one_nameserver_data(const char *address, void *into)
{
	DBusMessageIter *array = into;
	DBusMessageIter  entry;

	if (!dbus_message_iter_open_container(array, DBUS_TYPE_ARRAY, "{sv}", &entry)) {
		return;
	}
	pair_string(&entry, "address", address);
	(void)dbus_message_iter_close_container(array, &entry);
}

#define NMC_NAMESERVER_DATA(name, six)                                                        \
	static int name(DBusMessageIter *into, void *object, char *err, size_t err_size)       \
	{                                                                                     \
		DBusMessageIter array;                                                        \
		(void)err;                                                                    \
		(void)err_size;                                                               \
		if (!dbus_message_iter_open_container(into, DBUS_TYPE_ARRAY, "a{sv}",          \
		        &array)) {                                                            \
			return 0;                                                             \
		}                                                                             \
		for_each_nameserver(object, (six), one_nameserver_data, &array);               \
		return dbus_message_iter_close_container(into, &array) ? 1 : 0;                \
	}

NMC_NAMESERVER_DATA(say_v4_nameserver_data, 0)
NMC_NAMESERVER_DATA(say_v6_nameserver_data, 1)

/* The packed IPv4 form, in network byte order like every other `u` here. */
static void one_legacy_v4_nameserver(const char *address, void *into)
{
	DBusMessageIter *array = into;
	struct in_addr   parsed;
	dbus_uint32_t    word;

	if (inet_pton(AF_INET, address, &parsed) != 1) {
		return;
	}
	word = (dbus_uint32_t)parsed.s_addr;
	(void)dbus_message_iter_append_basic(array, DBUS_TYPE_UINT32, &word);
}

static int say_v4_nameservers(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	DBusMessageIter array;

	(void)err;
	(void)err_size;
	if (!dbus_message_iter_open_container(into, DBUS_TYPE_ARRAY, "u", &array)) {
		return 0;
	}
	for_each_nameserver(object, 0, one_legacy_v4_nameserver, &array);
	return dbus_message_iter_close_container(into, &array) ? 1 : 0;
}

/* And the IPv6 one, `aay`: sixteen bytes per server. */
static void one_legacy_v6_nameserver(const char *address, void *into)
{
	DBusMessageIter *array = into;
	DBusMessageIter  octets;
	struct in6_addr  parsed;
	size_t           byte;

	if (inet_pton(AF_INET6, address, &parsed) != 1) {
		return;
	}
	if (!dbus_message_iter_open_container(array, DBUS_TYPE_ARRAY, "y", &octets)) {
		return;
	}
	for (byte = 0u; byte < sizeof(parsed.s6_addr); byte++) {
		(void)dbus_message_iter_append_basic(&octets, DBUS_TYPE_BYTE,
		    &parsed.s6_addr[byte]);
	}
	(void)dbus_message_iter_close_container(array, &octets);
}

static int say_v6_nameservers(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	DBusMessageIter array;

	(void)err;
	(void)err_size;
	if (!dbus_message_iter_open_container(into, DBUS_TYPE_ARRAY, "ay", &array)) {
		return 0;
	}
	for_each_nameserver(object, 1, one_legacy_v6_nameserver, &array);
	return dbus_message_iter_close_container(into, &array) ? 1 : 0;
}
#define NMC_EMPTY(name, signature)                                                            \
	static int name(DBusMessageIter *into, void *object, char *err, size_t err_size)       \
	{                                                                                     \
		(void)object;                                                                 \
		(void)err;                                                                    \
		(void)err_size;                                                               \
		return put_empty(into, (signature));                                          \
	}

/* Routes: netcfgd has them and does not publish them per interface to this
 * client, so both shapes are empty rather than guessed from the addresses. */
NMC_EMPTY(say_no_v6_routes, "(ayuayu)")
NMC_EMPTY(say_no_v6_addresses, "(ayuay)")
NMC_EMPTY(say_no_u32s, "u")
NMC_EMPTY(say_no_strings, "s")

/*
 * `Gateway`: the next hop of this link's default route, or empty.
 *
 * **This was served empty because the answer was not available**, and the
 * reasoning is kept because it is still the rule for the v6 case below:
 * `ncfg_link_t` carried WHETHER a link holds the default route and not what
 * the next hop is, and empty is NM's "unknown" while `0.0.0.0` would be a
 * claim -- a client shown `0.0.0.0` has been told something false, where one
 * shown nothing has been told nothing.
 *
 * `ncfg_link_t` carries the next hop now. It was already on the wire, since
 * the observation sends the routes the flag is derived from, so this exposes
 * what the client receives rather than asking the daemon for anything new --
 * the local justification 0271 wanted is in `ncfg_client.h` beside the field.
 *
 * Still empty where there is no default route, and where there is one with no
 * `via`: an on-link default has no next hop to name, and that is the absence
 * of an answer rather than a gateway of nothing.
 */
static int say_gateway(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	char gateway[64] = "";

	(void)err;
	(void)err_size;
	nmc_device_gateway_of(object, gateway, sizeof(gateway));
	return put_string(into, gateway);
}

/* The v6 half has no equivalent yet: the observation's `default_via` is the
 * IPv4 default's next hop, and a v6 gateway read from it would be the wrong
 * family rather than a missing one. Empty remains the honest answer there. */
static int say_no_gateway(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	(void)object;
	(void)err;
	(void)err_size;
	return put_string(into, "");
}

static int say_dns_priority(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	dbus_int32_t zero = 0;

	(void)object;
	(void)err;
	(void)err_size;
	return dbus_message_iter_append_basic(into, DBUS_TYPE_INT32, &zero) ? 1 : 0;
}

/*
 * `Searches` and `Domains` are netcfgd's search list.
 *
 * NM separates them -- `Domains` is for routing a name to a resolver and
 * `Searches` is what gets appended to a bare hostname -- and netcfgd's `search`
 * is the second. So `Searches` carries it and `Domains` is empty, rather than
 * both carrying it and a client routing on a search domain.
 */
static int say_searches(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	const nmc_device_slot_t *slot = object;
	DBusMessageIter          array;
	ncfg_client_t           *client;
	ncfg_dns_t               dns;
	char                     problem[256] = "";

	(void)err;
	(void)err_size;
	if (!dbus_message_iter_open_container(into, DBUS_TYPE_ARRAY, "s", &array)) {
		return 0;
	}
	client = slot ? nmc_state_client(slot->state) : NULL;
	if (client) {
		memset(&dns, 0, sizeof(dns));
		if (ncfg_client_dns(client, &dns, problem, sizeof(problem))) {
			size_t at;

			for (at = 0u; at < dns.search_count; at++) {
				if (dns.search[at] && dns.search[at][0] != '\0') {
					(void)dbus_message_iter_append_basic(&array,
					    DBUS_TYPE_STRING, &dns.search[at]);
				}
			}
			ncfg_dns_free(&dns);
		}
	}
	return dbus_message_iter_close_container(into, &array) ? 1 : 0;
}

static const nmc_property_t V4_PROPERTIES[] = {
	{ "AddressData", "aa{sv}", NMC_READ, say_v4_address_data, NULL },
	{ "Addresses", "aau", NMC_READ, say_v4_addresses, NULL },
	{ "Gateway", "s", NMC_READ, say_gateway, NULL },
	{ "RouteData", "aa{sv}", NMC_READ, say_v4_route_data, NULL },
	{ "Routes", "aau", NMC_READ, say_v4_routes, NULL },
	{ "NameserverData", "aa{sv}", NMC_READ, say_v4_nameserver_data, NULL },
	{ "Nameservers", "au", NMC_READ, say_v4_nameservers, NULL },
	{ "Domains", "as", NMC_READ, say_no_strings, NULL },
	{ "Searches", "as", NMC_READ, say_searches, NULL },
	{ "DnsOptions", "as", NMC_READ, say_no_strings, NULL },
	{ "DnsPriority", "i", NMC_READ, say_dns_priority, NULL },
	{ "WinsServerData", "as", NMC_READ, say_no_strings, NULL },
	{ "WinsServers", "au", NMC_READ, say_no_u32s, NULL }
};

const nmc_interface_t nmc_ip4config_interface = {
	.name = "org.freedesktop.NetworkManager.IP4Config",
	.properties = V4_PROPERTIES,
	.property_count = sizeof(V4_PROPERTIES) / sizeof(V4_PROPERTIES[0])
};

static const nmc_property_t V6_PROPERTIES[] = {
	{ "AddressData", "aa{sv}", NMC_READ, say_v6_address_data, NULL },
	/*
	 * `a(ayuay)` -- the address as bytes, the prefix, the gateway as bytes.
	 * Empty rather than built: an IPv6 address has to be put back into
	 * sixteen bytes to go in here, and `AddressData` above carries the same
	 * addresses in the form every current client reads. Getting the byte
	 * form subtly wrong is worse than not offering it.
	 */
	{ "Addresses", "a(ayuay)", NMC_READ, say_no_v6_addresses, NULL },
	{ "Gateway", "s", NMC_READ, say_no_gateway, NULL },
	{ "RouteData", "aa{sv}", NMC_READ, say_v6_route_data, NULL },
	{ "Routes", "a(ayuayu)", NMC_READ, say_no_v6_routes, NULL },
	{ "NameserverData", "aa{sv}", NMC_READ, say_v6_nameserver_data, NULL },
	{ "Nameservers", "aay", NMC_READ, say_v6_nameservers, NULL },
	{ "Domains", "as", NMC_READ, say_no_strings, NULL },
	{ "Searches", "as", NMC_READ, say_searches, NULL },
	{ "DnsOptions", "as", NMC_READ, say_no_strings, NULL },
	{ "DnsPriority", "i", NMC_READ, say_dns_priority, NULL }
};

const nmc_interface_t nmc_ip6config_interface = {
	.name = "org.freedesktop.NetworkManager.IP6Config",
	.properties = V6_PROPERTIES,
	.property_count = sizeof(V6_PROPERTIES) / sizeof(V6_PROPERTIES[0])
};
