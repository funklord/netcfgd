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
 * The resolver, as `NameserverData`.
 *
 * **These are the machine's and not this link's, said here because the
 * difference is real.** NM's field is per-connection; netcfgd writes one
 * `resolv.conf` for the machine, so what a client is shown is what the machine
 * resolves with. The alternative -- an empty list -- would have a client
 * display "no DNS" for a connection that resolves names perfectly, which is
 * wrong in a way a person sees. A per-interface answer needs netcfgd to publish
 * a scope per link, which it has and this does not yet read.
 */
static int say_nameserver_data(DBusMessageIter *into, void *object, char *err, size_t err_size)
{
	const nmc_device_slot_t *slot = object;
	DBusMessageIter          array;
	ncfg_client_t           *client;
	ncfg_dns_t               dns;
	char                     problem[256] = "";

	(void)err;
	(void)err_size;
	if (!dbus_message_iter_open_container(into, DBUS_TYPE_ARRAY, "a{sv}", &array)) {
		return 0;
	}
	client = slot ? nmc_state_client(slot->state) : NULL;
	if (client) {
		memset(&dns, 0, sizeof(dns));
		if (ncfg_client_dns(client, &dns, problem, sizeof(problem))) {
			size_t at;

			for (at = 0u; at < dns.server_count; at++) {
				DBusMessageIter entry;

				if (!dns.servers[at] || dns.servers[at][0] == '\0') {
					continue;
				}
				if (!dbus_message_iter_open_container(&array, DBUS_TYPE_ARRAY,
				        "{sv}", &entry)) {
					break;
				}
				pair_string(&entry, "address", dns.servers[at]);
				(void)dbus_message_iter_close_container(&array, &entry);
			}
			ncfg_dns_free(&dns);
		}
	}
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
NMC_EMPTY(say_no_route_data, "a{sv}")
NMC_EMPTY(say_no_v4_routes, "au")
NMC_EMPTY(say_no_v6_routes, "(ayuayu)")
NMC_EMPTY(say_no_v6_addresses, "(ayuay)")
NMC_EMPTY(say_no_u32s, "u")
NMC_EMPTY(say_no_strings, "s")
NMC_EMPTY(say_no_byte_arrays, "ay")

/*
 * `Gateway` is empty, and that is not the same as "no gateway".
 *
 * `ncfg_link_t` says WHETHER a link carries the default route and not what the
 * next hop is, so the address is not available here. **Empty is NM's "unknown"
 * and `0.0.0.0` would be a claim** -- a client showing a gateway of 0.0.0.0 has
 * been told something false, where one showing none has been told nothing.
 */
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
	{ "Gateway", "s", NMC_READ, say_no_gateway, NULL },
	{ "RouteData", "aa{sv}", NMC_READ, say_no_route_data, NULL },
	{ "Routes", "aau", NMC_READ, say_no_v4_routes, NULL },
	{ "NameserverData", "aa{sv}", NMC_READ, say_nameserver_data, NULL },
	{ "Nameservers", "au", NMC_READ, say_no_u32s, NULL },
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
	{ "RouteData", "aa{sv}", NMC_READ, say_no_route_data, NULL },
	{ "Routes", "a(ayuayu)", NMC_READ, say_no_v6_routes, NULL },
	{ "NameserverData", "aa{sv}", NMC_READ, say_nameserver_data, NULL },
	{ "Nameservers", "aay", NMC_READ, say_no_byte_arrays, NULL },
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
