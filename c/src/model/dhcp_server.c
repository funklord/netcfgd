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

int ncfg_dhcp_server_dns_name(const char *name)
{
	size_t at;
	size_t label = 0;

	if (!name || !name[0] || strlen(name) > 253u) {
		return 0;
	}
	for (at = 0; name[at]; at++) {
		const unsigned char c = (unsigned char)name[at];

		if (c == '.') {
			/* An empty label, or one ending in a hyphen. */
			if (label == 0u || name[at - 1u] == '-') {
				return 0;
			}
			label = 0;
			continue;
		}
		if (!(isalnum(c) || c == '-') || (label == 0u && c == '-') || ++label > 63u) {
			return 0;
		}
	}
	return label != 0u && name[at - 1u] != '-';
}

/* Text dnsmasq is given inside a quoted option or a comma-separated field:
 * printable, and none of the characters that would end either. */
static int option_text(const char *text, size_t most, const char *refused)
{
	size_t at;

	if (!text || !text[0] || strlen(text) > most) {
		return 0;
	}
	for (at = 0; text[at]; at++) {
		if (!isprint((unsigned char)text[at]) || strchr(refused, text[at])) {
			return 0;
		}
	}
	return 1;
}

int ncfg_dhcp_option_code_taken(int64_t code)
{
	/* What a key of `dhcp_server` sets, and what the protocol itself
	 * carries -- the client's request, the server's identity, the message
	 * type, the lease's timers -- which no policy should be able to forge. */
	static const int taken[] = { 0, 1, 3, 6, 15, 42, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59,
		60, 61, 66, 67, 82, 252, 255 };
	size_t at;

	for (at = 0; at < sizeof(taken) / sizeof(taken[0]); at++) {
		if (code == taken[at]) {
			return 1;
		}
	}
	return 0;
}

int ncfg_dhcp_option_hex(const char *text)
{
	size_t at;
	size_t octets = 0;

	if (!text || !text[0]) {
		return 0;
	}
	for (at = 0; text[at]; at += 3u) {
		if (!isxdigit((unsigned char)text[at]) || !isxdigit((unsigned char)text[at + 1u]) ||
		    isupper((unsigned char)text[at]) || isupper((unsigned char)text[at + 1u]) ||
		    (text[at + 2u] != ':' && text[at + 2u] != '\0') ||
		    (text[at + 2u] == ':' && text[at + 3u] == '\0')) {
			return 0;
		}
		if (++octets > 255u || text[at + 2u] == '\0') {
			return octets <= 255u;
		}
	}
	return 0;
}

/* One custom option's value against its type (0303). */
static int option_value_fits(const ncfg_dhcp_option_t *option)
{
	static const int64_t most[] = { 0, 0, 255, 65535, 4294967295LL, 1, 0 };
	uint32_t             address;
	size_t               at;

	switch (option->kind) {
	case NCFG_DHCP_OPTION_IP:
		if (!option->ip_count || option->ip_count > 63u) {
			return 0;
		}
		for (at = 0; at < option->ip_count; at++) {
			if (!bare_ipv4(option->ip[at], &address)) {
				return 0;
			}
		}
		return !option->text && !option->number.has;
	case NCFG_DHCP_OPTION_TEXT:
		return option_text(option->text, 255u, "\"\\") && !option->ip_count &&
		    !option->number.has;
	case NCFG_DHCP_OPTION_HEX:
		return ncfg_dhcp_option_hex(option->text) && !option->ip_count && !option->number.has;
	case NCFG_DHCP_OPTION_U8:
	case NCFG_DHCP_OPTION_U16:
	case NCFG_DHCP_OPTION_U32:
	case NCFG_DHCP_OPTION_BOOL:
		return option->number.has && option->number.value >= 0 &&
		    option->number.value <= most[option->kind] && !option->text && !option->ip_count;
	default:
		return 0;
	}
}

static int custom_options_fit(const ncfg_dhcp_server_t *server, const char **why)
{
	size_t at;
	size_t other;

	for (at = 0; at < server->option_count; at++) {
		const ncfg_dhcp_option_t *option = &server->options[at];

		if (!ncfg_dhcp_server_plain_name(option->name)) {
			if (why) {
				*why = "an option's name is a plain name: letters, digits, hyphens and dots";
			}
			return 0;
		}
		if (option->code < 1 || option->code > 254 ||
		    ncfg_dhcp_option_code_taken(option->code)) {
			if (why) {
				*why = "an option's `code` is 1 to 254, and not one a `dhcp_server` key "
				       "already sets or the protocol itself carries: 1, 3, 6, 15, 42, 50 "
				       "to 61, 66, 67, 82 and 252";
			}
			return 0;
		}
		if (!option_value_fits(option)) {
			if (why) {
				*why = "an option's value does not fit its type: `ip` IPv4 addresses, `text` "
				       "printable with no quote or backslash, `u8`, `u16` and `u32` "
				       "numbers in range, `bool` true or false, `hex` octets as \"01:02\"";
			}
			return 0;
		}
		for (other = 0; other < at; other++) {
			if (strcmp(server->options[other].name, option->name) == 0 ||
			    server->options[other].code == option->code) {
				if (why) {
					*why = "two options share a name or a code, and a client would be "
					       "sent only one of them";
				}
				return 0;
			}
		}
	}
	return 1;
}

/*
 * The standard options (0303), with the same four callers as the range and
 * the reservations. The gateway has to be on the network served, since a
 * host reaches its gateway without one.
 */
static int options_fit(const ncfg_dhcp_server_t *server, uint32_t network, uint32_t broadcast,
    uint32_t mask, const char **why)
{
	uint32_t address;
	size_t   at;

	if (server->gateway) {
		if (!bare_ipv4(server->gateway, &address) || (address & mask) != network ||
		    address == network || address == broadcast) {
			if (why) {
				*why = "a `gateway` is one IPv4 address inside the interface's network, "
				       "since a host reaches its gateway directly";
			}
			return 0;
		}
	}
	if (server->domain && !ncfg_dhcp_server_dns_name(server->domain)) {
		if (why) {
			*why = "a `domain` is a DNS name: labels of letters, digits and hyphens, "
			       "joined by dots";
		}
		return 0;
	}
	for (at = 0; at < server->ntp_count; at++) {
		if (!bare_ipv4(server->ntp[at], &address)) {
			if (why) {
				*why = "an `ntp` server is an IPv4 address, which is what option 42 carries";
			}
			return 0;
		}
	}
	if (server->boot_file && !option_text(server->boot_file, 127u, ",\\\" ")) {
		if (why) {
			*why = "a `boot_file` is a file name of at most 127 printable characters, with "
			       "no comma, quote, backslash or space";
		}
		return 0;
	}
	if (server->boot_server) {
		if (!server->boot_file) {
			if (why) {
				*why = "a `boot_server` is where a `boot_file` is fetched from, and there is "
				       "no `boot_file`";
			}
			return 0;
		}
		if (!bare_ipv4(server->boot_server, &address)) {
			if (why) {
				*why = "a `boot_server` is one IPv4 address";
			}
			return 0;
		}
	}
	if (server->tftp_server && !ncfg_dhcp_server_dns_name(server->tftp_server)) {
		if (why) {
			*why = "a `tftp_server` is a DNS name or an IPv4 address";
		}
		return 0;
	}
	if (server->wpad && (!option_text(server->wpad, 255u, "\"\\ ") ||
	        (strncmp(server->wpad, "http://", 7u) != 0 &&
	            strncmp(server->wpad, "https://", 8u) != 0))) {
		if (why) {
			*why = "a `wpad` is an http:// or https:// URL, with no quote, backslash or space";
		}
		return 0;
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
	if (!hosts_fit(server, own, network, broadcast, mask, why) ||
	    !options_fit(server, network, broadcast, mask, why) || !custom_options_fit(server, why)) {
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

/* A bare address of either family, as a record answers it or a forward asks. */
static int bare_address(const char *text)
{
	ncfg_address_t address;

	return text && ncfg_address_parse(text, &address, NULL, 0) && !address.has_prefix;
}

/* A service name, `_sip._udp.home.lan`: a DNS name whose leading labels may
 * start with an underscore, as RFC 2782 spells them. */
static int service_name(const char *name)
{
	char   copy[254];
	size_t at;

	if (!name || name[0] != '_' || strlen(name) >= sizeof(copy)) {
		return 0;
	}
	strcpy(copy, name);
	for (at = 0; copy[at]; at++) {
		if (copy[at] == '_' && (at == 0u || copy[at - 1u] == '.')) {
			copy[at] = 'x';
		}
	}
	return ncfg_dhcp_server_dns_name(copy);
}

int ncfg_dns_record_check(const ncfg_dns_record_t *record, const char **why)
{
	const char *reason = NULL;
	size_t      at;
	int         kinds;

	if (!record) {
		return 0;
	}
	kinds = (record->address_count != 0u) + (record->mx != NULL) + (record->txt != NULL) +
	    (record->srv != NULL);
	if (!(record->srv ? service_name(record->name) : ncfg_dhcp_server_dns_name(record->name))) {
		reason = record->srv
		    ? "a record with `srv` is named for the service, as \"_sip._udp.home.lan\""
		    : "a record's name is a DNS name, as \"nas.home.lan\"";
	} else if (record->cname && (kinds || record->forward_count)) {
		reason = "a `cname` stands alone: DNS gives an alias no other record";
	} else if (record->forward_count && kinds) {
		reason = "a `forward` stands alone: the name's queries go to those servers, so "
		         "nothing here would be asked for its records";
	} else if (!kinds && !record->cname && !record->forward_count) {
		reason = "a record says what the name answers: `address`, `cname`, `mx`, `txt`, "
		         "`srv` or `forward`";
	} else if (record->cname && !ncfg_dhcp_server_dns_name(record->cname)) {
		reason = "a `cname` is the DNS name the alias stands for";
	} else if (record->mx && !ncfg_dhcp_server_dns_name(record->mx)) {
		reason = "an `mx` is the DNS name of the mail server";
	} else if (record->preference.has && !record->mx) {
		reason = "a `preference` belongs to an `mx`";
	} else if (record->txt && !option_text(record->txt, 255u, "\"\\")) {
		reason = "a `txt` is printable text, at most 255 characters, with no quote or "
		         "backslash";
	} else if (record->srv && !ncfg_dhcp_server_dns_name(record->srv)) {
		reason = "an `srv` is the DNS name of the host offering the service";
	} else if (record->srv && (!record->port.has || record->port.value < 1)) {
		reason = "an `srv` needs the `port` the service is on";
	} else if (!record->srv && (record->port.has || record->priority.has || record->weight.has)) {
		reason = "a `port`, `priority` or `weight` belongs to an `srv`";
	}
	for (at = 0; !reason && at < record->address_count; at++) {
		if (!bare_address(record->address[at])) {
			reason = "an `address` is an IPv4 or IPv6 address, with no prefix";
		}
	}
	for (at = 0; !reason && at < record->forward_count; at++) {
		if (!bare_address(record->forward[at])) {
			reason = "a `forward` server is an IPv4 or IPv6 address";
		}
	}
	if (why) {
		*why = reason;
	}
	return reason == NULL;
}
