/*
 * dhcp_server.c -- the range a DHCP server on an interface hands out
 * (decision 0297), one answer for the compiler, the renderer and the planner.
 *
 * Arithmetic on the interface's own static IPv4 address, which is the network
 * served and the router offered. Nothing here looks at the machine.
 */
#include "ncfg/document.h"

#include "ncfg/value.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

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
