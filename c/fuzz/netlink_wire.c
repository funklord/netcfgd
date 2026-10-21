/*
 * Netlink and generic netlink, as they arrive from the kernel.
 *
 * This is the target that matters most. A privileged process reads these
 * bytes off a socket it does not control the other end of, every decoder here
 * reads a length out of the message and trusts it to bound a read, and 0263
 * made this module's walks three-valued precisely because one boolean cannot
 * tell "nothing more" from "malformed".
 *
 * **Both properties the module's own header demands are asserted here**, and
 * the second is not a memory-safety property at all:
 *
 *   * nothing reads past the buffer -- which is the sanitizer's to catch, so
 *     this target exists mostly to hand it inputs;
 *   * a walk terminates -- which no sanitizer catches. A length field of zero,
 *     or one that points backwards, makes a walk that never advances, and from
 *     the outside that is a slow input rather than the infinite loop it is. So
 *     every walk is bounded by a count here and the bound is an assertion. The
 *     Rust target takes 10,000 for the same reason.
 */
#include "fuzz.h"

#include "ncfg/base.h"
#include "ncfg/genl.h"
#include "ncfg/wire.h"

#include <stdlib.h>

#define WALK_MAX 10000u

/*
 * Walk an attribute area to its end, asserting that it reaches one.
 *
 * Takes a started walk rather than bytes, because `ncfg_genl_payload_attrs`
 * hands back one of these and `wire.h` says to treat its fields as private --
 * so there is no reading the area back out of it to start a second walk.
 */
static void attrs_walk(ncfg_wire_attrs_t *walk)
{
	ncfg_wire_attr_t attr;
	size_t           seen = 0u;
	char             err[NCFG_ERROR_MAX];

	while (ncfg_wire_attrs_next(walk, &attr, err, sizeof(err)) == NCFG_WIRE_OK) {
		uint8_t          byte;
		uint16_t         half;
		uint32_t         word;
		char             string[64];
		char             mac[32];
		ncfg_wire_ip_t   address;

		/* Every typed reader, on every attribute: each one is a length check
		 * of its own and a nest's value is attacker-shaped too. */
		(void)ncfg_wire_attr_u8(&attr, &byte, err, sizeof(err));
		(void)ncfg_wire_attr_u16(&attr, &half, err, sizeof(err));
		(void)ncfg_wire_attr_u32(&attr, &word, err, sizeof(err));
		(void)ncfg_wire_attr_string(&attr, string, sizeof(string), err, sizeof(err));
		(void)ncfg_wire_attr_mac(&attr, mac, sizeof(mac), err, sizeof(err));
		(void)ncfg_wire_attr_ip(&attr, &address, err, sizeof(err));
		if (++seen >= WALK_MAX) {
			abort(); /* a walk that does not terminate */
		}
	}
}

static void attrs(const void *bytes, size_t length)
{
	ncfg_wire_attrs_t walk;

	ncfg_wire_attrs_start(&walk, bytes, length);
	attrs_walk(&walk);
}

int ncfg_fuzz_one(const unsigned char *data, size_t length)
{
	ncfg_wire_header_t   header;
	ncfg_wire_ifinfo_t   ifinfo;
	ncfg_wire_ifaddr_t   ifaddr;
	ncfg_wire_rtmsg_t    route;
	ncfg_genl_header_t   generic;
	ncfg_wire_messages_t walk;
	ncfg_wire_message_t  message;
	ncfg_wire_attrs_t    area;
	int32_t              code;
	size_t               seen = 0u;
	char                 err[NCFG_ERROR_MAX];

	/* The fixed headers, each against the same bytes: a decoder that reads its
	 * own length rather than the buffer's is the defect being hunted. */
	(void)ncfg_wire_header_decode(data, length, &header, err, sizeof(err));
	(void)ncfg_wire_ifinfo_decode(data, length, &ifinfo, err, sizeof(err));
	(void)ncfg_wire_ifaddr_decode(data, length, &ifaddr, err, sizeof(err));
	(void)ncfg_wire_rtmsg_decode(data, length, &route, err, sizeof(err));
	(void)ncfg_genl_header_decode(data, length, &generic, err, sizeof(err));
	(void)ncfg_wire_error_code(data, length, &code, err, sizeof(err));

	/* The whole buffer as an attribute area, which is what a caller that
	 * mistook a payload for a message would hand it. */
	attrs(data, length);

	ncfg_wire_messages_start(&walk, data, length);
	while (ncfg_wire_messages_next(&walk, &message, err, sizeof(err)) == NCFG_WIRE_OK) {
		(void)ncfg_wire_ifinfo_decode(message.payload, message.payload_length, &ifinfo,
		    err, sizeof(err));
		(void)ncfg_wire_ifaddr_decode(message.payload, message.payload_length, &ifaddr,
		    err, sizeof(err));
		(void)ncfg_wire_rtmsg_decode(message.payload, message.payload_length, &route,
		    err, sizeof(err));
		(void)ncfg_wire_error_code(message.payload, message.payload_length, &code, err,
		    sizeof(err));
		attrs(message.payload, message.payload_length);
		/* The generic-netlink path to an attribute area, which is the entry
		 * point every family added after nl80211 will share. */
		if (ncfg_genl_payload_attrs(message.payload, message.payload_length, &area, err,
		        sizeof(err))) {
			attrs_walk(&area);
		}
		if (++seen >= WALK_MAX) {
			abort(); /* a walk that does not terminate */
		}
	}
	return 0;
}
