/*
 * dhcp_server.c -- the range a DHCP server on an interface hands out
 * (decision 0297), one answer for the compiler, the renderer and the planner.
 *
 * Arithmetic on the interface's own static IPv4 address, which is the network
 * served and the router offered. Nothing here looks at the machine.
 */
#include "ncfg/document.h"

#include "ncfg/value.h"

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

static uint32_t to_host(const unsigned char *bytes)
{
	return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) |
	    ((uint32_t)bytes[2] << 8) | (uint32_t)bytes[3];
}

static void dotted(uint32_t value, char *out)
{
	(void)snprintf(out, NCFG_ADDRESS_MAX, "%u.%u.%u.%u", (unsigned)(value >> 24) & 255u,
	    (unsigned)(value >> 16) & 255u, (unsigned)(value >> 8) & 255u, (unsigned)value & 255u);
}

int ncfg_dhcp_server_plain_name(const char *name)
{
	size_t at;

	if (!name || !isalnum((unsigned char)name[0])) {
		return 0;
	}
	for (at = 0; name[at]; at++) {
		if (at >= 63u ||
		    !(isalnum((unsigned char)name[at]) || name[at] == '-' || name[at] == '.')) {
			return 0;
		}
	}
	return 1;
}

/* A bare IPv4 address, as a number; 0 for anything else. */
static int bare_ipv4(const char *text, uint32_t *out)
{
	ncfg_address_t address;

	if (!text || !ncfg_address_parse(text, &address, NULL, 0) || address.is_ipv6 ||
	    address.has_prefix) {
		return 0;
	}
	*out = to_host(address.bytes);
	return 1;
}

/*
 * The reservations, against the network served. The same four callers as the
 * range, so a reservation the compiler took is one dnsmasq is given and the
 * planner compares, and one it refused never reaches either.
 */
static int hosts_fit(const ncfg_dhcp_server_t *server, uint32_t own, uint32_t network,
    uint32_t broadcast, uint32_t mask, const char **why)
{
	size_t at;
	size_t other;

	for (at = 0; at < server->host_count; at++) {
		const ncfg_dhcp_host_t *host = &server->hosts[at];
		char                    canonical[18];
		uint32_t                address;

		if (!ncfg_dhcp_server_plain_name(host->name)) {
			if (why) {
				*why = "a reservation's name is a plain host name: letters, digits, "
				       "hyphens and dots, starting with a letter or digit";
			}
			return 0;
		}
		if (!ncfg_hardware_address_strict(host->mac, canonical, sizeof(canonical), NULL, 0)) {
			if (why) {
				*why = "a reservation's `mac` is six colon-separated hex octets, as in "
				       "AA:BB:CC:DD:EE:FF";
			}
			return 0;
		}
		if (!bare_ipv4(host->address, &address)) {
			if (why) {
				*why = "a reservation's `address` is one IPv4 address, with no prefix";
			}
			return 0;
		}
		if ((address & mask) != network || address == network || address == broadcast) {
			if (why) {
				*why = "a reservation's `address` is not inside the interface's network";
			}
			return 0;
		}
		if (address == own) {
			if (why) {
				*why = "a reservation's `address` is the interface's own, which it would "
				       "hand to a host";
			}
			return 0;
		}
		for (other = 0; other < at; other++) {
			const ncfg_dhcp_host_t *earlier = &server->hosts[other];

			if (strcmp(earlier->name, host->name) == 0 ||
			    strcasecmp(earlier->mac, host->mac) == 0 ||
			    strcmp(earlier->address, host->address) == 0) {
				if (why) {
					*why = "two reservations share a name, a MAC or an address, and "
					       "dnsmasq would give one of them what the other asked for";
				}
				return 0;
			}
		}
	}
	return 1;
}

int ncfg_dhcp_server_range(const ncfg_interface_t *interface, char *start, char *end,
    char *router, const char **why)
{
	const ncfg_dhcp_server_t *server = interface ? interface->dhcp_server : NULL;
	ncfg_address_t            address;
	uint32_t                  own = 0;
	uint32_t                  mask;
	uint32_t                  network;
	uint32_t                  broadcast;
	uint32_t                  first;
	uint32_t                  last;
	size_t                    at;
	int                       found = 0;

	if (why) {
		*why = NULL;
	}
	if (!server) {
		return 0;
	}
	for (at = 0; !found && at < interface->addressing_count; at++) {
		const ncfg_address_source_t *source = &interface->addressing[at];

		found = source->kind == NCFG_ADDRESS_SOURCE_STATIC && source->static_address.address &&
		    ncfg_address_parse(source->static_address.address, &address, NULL, 0) &&
		    !address.is_ipv6 && address.has_prefix;
	}
	if (!found) {
		if (why) {
			*why = "a DHCP server serves the network of its interface's static IPv4 address, "
			       "and this interface has none: add one to `config`, such as "
			       "\"192.168.1.1/24\"";
		}
		return 0;
	}
	if (address.prefix > 30u) {
		if (why) {
			*why = "the interface's network is too small to hand out addresses from";
		}
		return 0;
	}
	own = to_host(address.bytes);
	mask = address.prefix ? 0xffffffffu << (32u - address.prefix) : 0u;
	network = own & mask;
	broadcast = network | ~mask;
	if (server->range_start || server->range_end) {
		if (!bare_ipv4(server->range_start, &first) || !bare_ipv4(server->range_end, &last)) {
			if (why) {
				*why = "a `range` is two IPv4 addresses, \"192.168.1.100-192.168.1.249\"";
			}
			return 0;
		}
		if (first > last) {
			if (why) {
				*why = "the `range` runs backwards";
			}
			return 0;
		}
		if ((first & mask) != network || (last & mask) != network || first == network ||
		    last == broadcast) {
			if (why) {
				*why = "the `range` is not inside the interface's network";
			}
			return 0;
		}
		if (own >= first && own <= last) {
			if (why) {
				*why = "the `range` takes in the interface's own address, which it would hand "
				       "to a host";
			}
			return 0;
		}
	} else {
		/* OpenWrt's default: the 100th host, 150 of them, cut at the last
		 * host before the broadcast. */
		first = network + 100u;
		last = network + 249u;
		if (last >= broadcast) {
			last = broadcast - 1u;
		}
		if (first >= broadcast || first > last) {
			if (why) {
				*why = "the interface's network is too small for the default range, from its "
				       "100th host: state a `range`";
			}
			return 0;
		}
		if (own >= first && own <= last) {
			if (why) {
				*why = "the interface's own address is inside the default range, from the "
				       "100th host to the 249th: state a `range` that leaves it out";
			}
			return 0;
		}
	}
	if (!hosts_fit(server, own, network, broadcast, mask, why)) {
		return 0;
	}
	if (start) {
		dotted(first, start);
	}
	if (end) {
		dotted(last, end);
	}
	if (router) {
		dotted(own, router);
		(void)snprintf(router + strlen(router), NCFG_ADDRESS_MAX - strlen(router), "/%u",
		    address.prefix);
	}
	return 1;
}
