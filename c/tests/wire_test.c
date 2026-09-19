/*
 * wire_test.c -- the netlink codec, against bytes rather than against a kernel.
 *
 * WHY THIS EXISTS
 *   Everything here runs with no socket, no privileges and no hardware, which
 *   is the property that makes the netlink layer reviewable at all. The round
 *   trips are the cheap half; the adversarial cases at the bottom are the
 *   point, and they are the deterministic stand-in for the fuzz target that
 *   found the `INT32_MIN` defect. Run them under `make SANITIZE=1`: in C the
 *   difference between "refused" and "read four bytes past the end and then
 *   refused" is invisible without ASan, and it is the whole difference.
 *
 *   Two properties are pinned everywhere below: a malformed length terminates
 *   the walk rather than looping on it, and a truncation is a refusal rather
 *   than a partial answer.
 *
 * WHY THE HOSTILE BUFFERS ARE MALLOCED TO SIZE
 *   A short read tested as a prefix of a longer buffer is not tested at all:
 *   an overread lands in the rest of the allocation, every byte of it is
 *   readable, and ASan has nothing to say. `exact_copy` puts the end of the
 *   input at the end of an allocation, so one byte past it is a report.
 */
#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/wire.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;

static void check(int condition, const char *what)
{
	printf("%-58s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

/*
 * A walk that will not run for ever even if the code under test would.
 *
 * The bug this file is mostly about does not look like a crash, it looks like
 * a hang in a privileged daemon, and a test that hangs reports nothing at all.
 * So every walk here is bounded and the bound is checked.
 */
#define WALK_CAP 10000u

/* `IFNAMSIZ`: the size of a buffer an interface name has to fit. Written out
 * rather than included, for the reason wire.h gives about `ALTIFNAMSIZ` --
 * `linux/if.h` and `net/if.h` redefine each other's structures. */
#define NAME_TEXT 16u

/* See the header comment. NULL for an empty input, which every walk here
 * takes as an empty buffer rather than as a failure. */
static uint8_t *exact_copy(const void *bytes, size_t length)
{
	uint8_t *copy;

	if (!bytes || length == 0) {
		return NULL;
	}
	copy = malloc(length);
	if (!copy) {
		return NULL;
	}
	memcpy(copy, bytes, length);
	return copy;
}

static size_t count_messages(const void *bytes, size_t length, int *refused)
{
	ncfg_wire_messages_t walk;
	ncfg_wire_message_t message;
	size_t seen = 0;

	if (refused) {
		*refused = 0;
	}
	ncfg_wire_messages_start(&walk, bytes, length);
	while (seen < WALK_CAP) {
		ncfg_wire_step_t step = ncfg_wire_messages_next(&walk, &message, NULL, 0);

		if (step == NCFG_WIRE_OK) {
			seen++;
			continue;
		}
		if (step == NCFG_WIRE_BAD && refused) {
			*refused = 1;
		}
		break;
	}
	return seen;
}

static size_t count_attrs(const ncfg_wire_attrs_t *area, int *refused)
{
	ncfg_wire_attrs_t walk = *area;
	ncfg_wire_attr_t attr;
	size_t seen = 0;

	if (refused) {
		*refused = 0;
	}
	while (seen < WALK_CAP) {
		ncfg_wire_step_t step = ncfg_wire_attrs_next(&walk, &attr, NULL, 0);

		if (step == NCFG_WIRE_OK) {
			seen++;
			continue;
		}
		if (step == NCFG_WIRE_BAD && refused) {
			*refused = 1;
		}
		break;
	}
	return seen;
}

/* The same, over raw bytes rather than a started area. */
static size_t count_attr_bytes(const void *bytes, size_t length, int *refused)
{
	ncfg_wire_attrs_t area;

	ncfg_wire_attrs_start(&area, bytes, length);
	return count_attrs(&area, refused);
}

/* The first message of a buffer, or zero where there is none. */
static int first_message(const void *bytes, size_t length, ncfg_wire_message_t *out)
{
	ncfg_wire_messages_t walk;

	ncfg_wire_messages_start(&walk, bytes, length);
	return ncfg_wire_messages_next(&walk, out, NULL, 0) == NCFG_WIRE_OK;
}

/* A link message: header, `ifinfomsg`, attributes. */
static int link_message(ncfg_buf_t *out, uint32_t seq, const ncfg_wire_ifinfo_t *info,
    const ncfg_buf_t *attrs)
{
	ncfg_buf_t body;
	int built;

	ncfg_buf_init(&body, 0);
	ncfg_wire_ifinfo_encode(info, &body);
	built = ncfg_wire_build_request(out, RTM_NEWLINK, 0, seq, &body, attrs, NULL, 0);
	ncfg_buf_free(&body);
	return built;
}

/* The name attribute of a link message, as text. */
static int link_name(const ncfg_wire_message_t *message, char *out, size_t out_size)
{
	ncfg_wire_attrs_t area;
	ncfg_wire_attr_t attr;

	if (!ncfg_wire_message_attrs(message, NCFG_WIRE_IFINFO_LEN, &area, NULL, 0)) {
		return 0;
	}
	if (ncfg_wire_attrs_find(&area, IFLA_IFNAME, &attr, NULL, 0) != NCFG_WIRE_OK) {
		return 0;
	}
	return ncfg_wire_attr_string(&attr, out, out_size, NULL, 0);
}

/* An attribute of this type in a buffer that is all attributes. */
static ncfg_wire_step_t find_in(const ncfg_buf_t *buf, uint16_t kind, ncfg_wire_attr_t *out)
{
	ncfg_wire_attrs_t area;

	ncfg_wire_attrs_start(&area, buf->data, buf->length);
	return ncfg_wire_attrs_find(&area, kind, out, NULL, 0);
}

int main(void)
{
	/* A request this port built is taken apart into what an exchange takes. */
	{
		ncfg_wire_header_t header;
		ncfg_buf_t         message;
		ncfg_buf_t         body;
		uint16_t           kind = 0;
		uint16_t           flags = 0;
		char               err[NCFG_ERROR_MAX];
		static const unsigned char payload[] = { 0x11, 0x22, 0x33, 0x44 };

		header.len = (uint32_t)(NCFG_WIRE_NLMSG_HDR_LEN + sizeof(payload));
		header.kind = 0x2au;
		header.flags = NLM_F_REQUEST | NLM_F_DUMP;
		header.seq = 7u;
		header.pid = 0;
		ncfg_buf_init(&message, 0);
		ncfg_wire_header_encode(&header, &message);
		ncfg_buf_add(&message, payload, sizeof(payload));

		ncfg_buf_init(&body, 0);
		err[0] = '\0';
		check(ncfg_wire_request_parts(&message, "generic netlink", &kind, &flags, &body,
		    err, sizeof(err)), "a built request comes apart");
		check(kind == 0x2au && flags == (NLM_F_REQUEST | NLM_F_DUMP),
		    "  with the kind and the flags the builder put in its header");
		/*
		 * The body and **not** the header, which is the whole point: an
		 * exchange writes a header of its own, so handing it the message
		 * entire would put two headers on the wire and the kernel would read
		 * the first sixteen bytes of netcfgd's request as its payload.
		 */
		check(body.length == sizeof(payload) &&
		    memcmp(body.data, payload, sizeof(payload)) == 0,
		    "  and the body alone, since the exchange writes a header itself");
		ncfg_buf_free(&body);
		ncfg_buf_free(&message);

		/*
		 * **The refusal names the kind of request, which is all that varied
		 * between the five copies this replaced.** A reader needs to know that
		 * netcfgd built something it cannot itself parse -- a fault here
		 * rather than in the kernel -- and which of the exchanges did it.
		 */
		ncfg_buf_init(&message, 0);
		ncfg_buf_add(&message, payload, 3u);
		ncfg_buf_init(&body, 0);
		err[0] = '\0';
		check(!ncfg_wire_request_parts(&message, "nftables", &kind, &flags, &body, err,
		    sizeof(err)) && strstr(err, "nftables") != NULL &&
		    strstr(err, "this port built") != NULL,
		    "something too short to be a message is refused, naming which request");
		ncfg_buf_free(&body);
		ncfg_buf_free(&message);

		/* A body with no room left is the other refusal, and it says which
		 * request as well: a caller building into a bounded buffer gets a
		 * sentence rather than a short body it would send. */
		ncfg_buf_init(&message, 0);
		ncfg_wire_header_encode(&header, &message);
		ncfg_buf_add(&message, payload, sizeof(payload));
		ncfg_buf_init(&body, 2u);
		err[0] = '\0';
		check(!ncfg_wire_request_parts(&message, "traffic control", &kind, &flags, &body,
		    err, sizeof(err)) && strstr(err, "traffic control") != NULL,
		    "and a body with no room for it is refused, naming the request too");
		ncfg_buf_free(&body);
		ncfg_buf_free(&message);

		check(!ncfg_wire_request_parts(NULL, "generic netlink", &kind, &flags, &body, err,
		    sizeof(err)), "and there being no request at all is a refusal, not a walk");
	}

	/* A header round trips. */
	{
		ncfg_wire_header_t header;
		ncfg_wire_header_t back;
		ncfg_buf_t buf;

		header.len = 64;
		header.kind = RTM_NEWLINK;
		header.flags = NLM_F_MULTI;
		header.seq = 0xdeadbeefu;
		header.pid = 4242;

		ncfg_buf_init(&buf, 0);
		ncfg_wire_header_encode(&header, &buf);
		check(buf.length == NCFG_WIRE_NLMSG_HDR_LEN,
		    "a header encodes to exactly 16 bytes");
		check(ncfg_wire_header_decode(buf.data, buf.length, &back, NULL, 0),
		    "and decodes again");
		/* This is the check that caught `seq` being decoded from a two-byte
		 * slice, which made every decode fail and would have made the whole
		 * layer silently see a kernel with nothing on it. */
		check(back.len == header.len && back.kind == header.kind &&
		    back.flags == header.flags && back.seq == header.seq && back.pid == header.pid,
		    "with every field back where it started, `seq` included");
		ncfg_buf_free(&buf);
	}

	/* The payload structs round trip. */
	{
		ncfg_wire_ifinfo_t info = { 0, 1, 7, 0x10043u, 0 };
		ncfg_wire_ifinfo_t info_back;
		ncfg_wire_ifaddr_t addr = { 2, 24, 0, 0, 7 };
		ncfg_wire_ifaddr_t addr_back;
		ncfg_wire_rtmsg_t route = { 2, 0, 0, 0, 254, NCFG_WIRE_RTPROT_NETCFGD, 0, 1, 0 };
		ncfg_wire_rtmsg_t route_back;
		ncfg_buf_t buf;

		ncfg_buf_init(&buf, 0);
		ncfg_wire_ifinfo_encode(&info, &buf);
		check(buf.length == NCFG_WIRE_IFINFO_LEN, "an ifinfomsg encodes to 16 bytes");
		check(ncfg_wire_ifinfo_decode(buf.data, buf.length, &info_back, NULL, 0) &&
		    info_back.family == info.family && info_back.kind == info.kind &&
		    info_back.index == info.index && info_back.flags == info.flags &&
		    info_back.change == info.change,
		    "and comes back with its type past the pad byte");
		ncfg_buf_free(&buf);

		ncfg_buf_init(&buf, 0);
		ncfg_wire_ifaddr_encode(&addr, &buf);
		check(buf.length == NCFG_WIRE_IFADDR_LEN, "an ifaddrmsg encodes to 8 bytes");
		check(ncfg_wire_ifaddr_decode(buf.data, buf.length, &addr_back, NULL, 0) &&
		    addr_back.family == addr.family && addr_back.prefix_len == addr.prefix_len &&
		    addr_back.flags == addr.flags && addr_back.scope == addr.scope &&
		    addr_back.index == addr.index,
		    "and comes back unchanged");
		ncfg_buf_free(&buf);

		ncfg_buf_init(&buf, 0);
		ncfg_wire_rtmsg_encode(&route, &buf);
		check(buf.length == NCFG_WIRE_RTMSG_LEN, "an rtmsg encodes to 12 bytes");
		check(ncfg_wire_rtmsg_decode(buf.data, buf.length, &route_back, NULL, 0) &&
		    route_back.table == 254 && route_back.protocol == NCFG_WIRE_RTPROT_NETCFGD &&
		    route_back.kind == 1 && route_back.flags == 0,
		    "and keeps the protocol netcfgd stamps on its routes");
		ncfg_buf_free(&buf);
	}

	/*
	 * **The two byte orders in one message.** Netlink's own fields are the
	 * host's; the addresses inside a payload are network order, which is to
	 * say byte strings rather than integers. The first half is untestable by
	 * comparison -- the host is the only authority on its own order -- so it
	 * is checked against the compiler's own representation, which is exactly
	 * what a hand-rolled low-byte-first encoder would pass on x86 and fail
	 * on anything else.
	 */
	{
		ncfg_wire_header_t header = { 0x01020304u, 0, 0, 0, 0 };
		ncfg_buf_t buf;
		ncfg_wire_ip_t ip;
		ncfg_wire_attr_t attr;
		uint32_t native = 0x01020304u;
		char text[NCFG_WIRE_IP_TEXT_MAX];

		ncfg_buf_init(&buf, 0);
		ncfg_wire_header_encode(&header, &buf);
		check(buf.length >= 4u && memcmp(buf.data, &native, sizeof(native)) == 0,
		    "a length field is written in the host's own byte order");
		ncfg_buf_free(&buf);

		ncfg_buf_init(&buf, 0);
		check(ncfg_wire_ip_parse("192.168.1.10", &ip, NULL, 0), "an address parses");
		ncfg_wire_attr_put_ip(&buf, IFA_LOCAL, &ip);
		check(find_in(&buf, IFA_LOCAL, &attr) == NCFG_WIRE_OK && attr.length == 4u &&
		    attr.value[0] == 192 && attr.value[1] == 168 && attr.value[2] == 1 &&
		    attr.value[3] == 10,
		    "while an address goes on the wire big-endian on every machine");
		check(ncfg_wire_attr_ip(&attr, &ip, NULL, 0) &&
		    ncfg_wire_ip_text(&ip, text, sizeof(text), NULL, 0) &&
		    strcmp(text, "192.168.1.10") == 0, "and reads back as the address it was");
		ncfg_buf_free(&buf);

		ncfg_buf_init(&buf, 0);
		check(ncfg_wire_ip_parse("fe80::1", &ip, NULL, 0) && ip.family == AF_INET6,
		    "an IPv6 address parses as sixteen bytes");
		ncfg_wire_attr_put_ip(&buf, IFA_ADDRESS, &ip);
		check(find_in(&buf, IFA_ADDRESS, &attr) == NCFG_WIRE_OK && attr.length == 16u &&
		    attr.value[0] == 0xfeu && attr.value[1] == 0x80u && attr.value[15] == 1,
		    "and goes on the wire in that order too");
		ncfg_buf_free(&buf);
		check(!ncfg_wire_ip_parse("010.0.0.1", &ip, NULL, 0),
		    "while an octal-looking octet is refused rather than reinterpreted");
	}

	/* Attributes round trip, including the padding between them. */
	{
		ncfg_buf_t attrs;
		ncfg_wire_attr_t attr;
		char text[NAME_TEXT];
		char mac[NCFG_WIRE_MAC_TEXT_MAX];
		uint32_t mtu = 0;
		uint8_t proto = 0;
		static const uint8_t hardware[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };

		ncfg_buf_init(&attrs, 0);
		ncfg_wire_attr_put_str(&attrs, IFLA_IFNAME, "eth0");
		ncfg_wire_attr_put_u32(&attrs, IFLA_MTU, 9000);
		ncfg_wire_attr_put(&attrs, IFLA_ADDRESS, hardware, sizeof(hardware));
		ncfg_wire_attr_put_u8(&attrs, IFA_PROTO, NCFG_WIRE_RTPROT_NETCFGD);
		check(!ncfg_buf_failed(&attrs), "four attributes build without complaint");

		/* Every attribute starts on a 4-byte boundary, so a 5-byte name and
		 * a 6-byte MAC both pad. If the padding were wrong the later
		 * attributes would decode as garbage rather than failing outright,
		 * which is the failure that is hard to see. */
		check(attrs.length == ncfg_wire_align4(attrs.length),
		    "and the area they make is 4-byte aligned");
		check(count_attr_bytes(attrs.data, attrs.length, NULL) == 4u,
		    "all four walk back out, padding and all");

		check(find_in(&attrs, IFLA_IFNAME, &attr) == NCFG_WIRE_OK &&
		    ncfg_wire_attr_string(&attr, text, sizeof(text), NULL, 0) &&
		    strcmp(text, "eth0") == 0, "a string attribute reads back as its name");
		check(find_in(&attrs, IFLA_MTU, &attr) == NCFG_WIRE_OK &&
		    ncfg_wire_attr_u32(&attr, &mtu, NULL, 0) && mtu == 9000u,
		    "a 32-bit attribute reads back as its number");
		check(find_in(&attrs, IFLA_ADDRESS, &attr) == NCFG_WIRE_OK &&
		    ncfg_wire_attr_mac(&attr, mac, sizeof(mac), NULL, 0) &&
		    strcmp(mac, "02:00:00:00:00:01") == 0, "a MAC reads back in colon notation");
		check(find_in(&attrs, IFA_PROTO, &attr) == NCFG_WIRE_OK &&
		    ncfg_wire_attr_u8(&attr, &proto, NULL, 0) && proto == 110,
		    "and a one-byte attribute as its byte");
		check(find_in(&attrs, IFLA_MASTER, &attr) == NCFG_WIRE_END,
		    "an attribute that is absent is an end, not a refusal");
		ncfg_buf_free(&attrs);
	}

	/* A whole link message: header, struct, attributes. */
	{
		ncfg_buf_t attrs;
		ncfg_buf_t raw;
		ncfg_wire_message_t message;
		ncfg_wire_ifinfo_t info = { 0, 1, 3, 0x41u, 0 };
		ncfg_wire_ifinfo_t back;
		ncfg_wire_attrs_t area;
		ncfg_wire_attr_t attr;
		char name[NAME_TEXT];
		char mac[NCFG_WIRE_MAC_TEXT_MAX];
		uint32_t mtu = 0;
		uint8_t carrier = 1;
		static const uint8_t hardware[6] = { 0xde, 0xad, 0xbe, 0xef, 0x00, 0x01 };

		ncfg_buf_init(&attrs, 0);
		ncfg_wire_attr_put_str(&attrs, IFLA_IFNAME, "eth0");
		ncfg_wire_attr_put_u32(&attrs, IFLA_MTU, 1500);
		ncfg_wire_attr_put(&attrs, IFLA_ADDRESS, hardware, sizeof(hardware));
		ncfg_wire_attr_put_u8(&attrs, IFLA_CARRIER, 0);
		ncfg_buf_init(&raw, 0);
		check(link_message(&raw, 1, &info, &attrs), "a link message assembles");
		check(raw.length == ncfg_wire_align4(raw.length) &&
		    count_messages(raw.data, raw.length, NULL) == 1u,
		    "and is exactly one message long");

		check(first_message(raw.data, raw.length, &message) &&
		    message.header.kind == RTM_NEWLINK &&
		    message.header.len == (uint32_t)raw.length,
		    "whose header says what it is and how long");
		check(ncfg_wire_ifinfo_decode(message.payload, message.payload_length, &back,
		    NULL, 0) && back.index == 3 && (back.flags & 0x1u) != 0,
		    "the ifinfomsg gives the index and the admin state");
		check(ncfg_wire_message_attrs(&message, NCFG_WIRE_IFINFO_LEN, &area, NULL, 0),
		    "the attributes begin after the family struct");
		check(count_attrs(&area, NULL) == 4u, "and there are four of them");
		check(link_name(&message, name, sizeof(name)) && strcmp(name, "eth0") == 0,
		    "the name comes back through the whole stack");
		check(ncfg_wire_attrs_find(&area, IFLA_MTU, &attr, NULL, 0) == NCFG_WIRE_OK &&
		    ncfg_wire_attr_u32(&attr, &mtu, NULL, 0) && mtu == 1500u,
		    "and so does the MTU");
		check(ncfg_wire_attrs_find(&area, IFLA_ADDRESS, &attr, NULL, 0) == NCFG_WIRE_OK &&
		    ncfg_wire_attr_mac(&attr, mac, sizeof(mac), NULL, 0) &&
		    strcmp(mac, "de:ad:be:ef:00:01") == 0, "and the hardware address");
		/* Administrative up and carrier are different things. Conflating
		 * them is how a plan decides to reconfigure a perfectly good
		 * interface whose cable is out, or ignores one that is
		 * administratively down. This link is up with no carrier. */
		check(ncfg_wire_attrs_find(&area, IFLA_CARRIER, &attr, NULL, 0) == NCFG_WIRE_OK &&
		    ncfg_wire_attr_u8(&attr, &carrier, NULL, 0) && carrier == 0,
		    "with carrier carried separately from the admin flags");
		ncfg_buf_free(&attrs);
		ncfg_buf_free(&raw);
	}

	/* A link kind lives one level down, inside the `IFLA_LINKINFO` nest. */
	{
		ncfg_buf_t nest;
		ncfg_buf_t attrs;
		ncfg_buf_t raw;
		ncfg_wire_message_t message;
		ncfg_wire_ifinfo_t info = { 0, 0, 0, 0, 0 };
		ncfg_wire_attrs_t area;
		ncfg_wire_attrs_t inside;
		ncfg_wire_attr_t outer;
		ncfg_wire_attr_t inner;
		char kind[16];
		uint16_t on_wire = 0;

		ncfg_buf_init(&nest, 0);
		ncfg_wire_attr_put_str(&nest, IFLA_INFO_KIND, "bridge");
		ncfg_buf_init(&attrs, 0);
		ncfg_wire_attr_put_str(&attrs, IFLA_IFNAME, "br0");
		ncfg_wire_attr_put_nested(&attrs, IFLA_LINKINFO, &nest);
		ncfg_buf_init(&raw, 0);
		check(link_message(&raw, 1, &info, &attrs), "a message with a nest assembles");

		check(first_message(raw.data, raw.length, &message) &&
		    ncfg_wire_message_attrs(&message, NCFG_WIRE_IFINFO_LEN, &area, NULL, 0) &&
		    ncfg_wire_attrs_find(&area, IFLA_LINKINFO, &outer, NULL, 0) == NCFG_WIRE_OK,
		    "the nest is found by its type with the nested bit masked off");
		ncfg_wire_attrs_start(&inside, outer.value, outer.length);
		check(ncfg_wire_attrs_find(&inside, IFLA_INFO_KIND, &inner, NULL, 0)
		    == NCFG_WIRE_OK &&
		    ncfg_wire_attr_string(&inner, kind, sizeof(kind), NULL, 0) &&
		    strcmp(kind, "bridge") == 0, "and the kind inside it reads as `bridge`");

		/* `NLA_F_NESTED` really is on the wire. The strict parsers -- which
		 * is what `RTM_NEWLINKPROP` goes through -- reject a nest without
		 * it with an `EINVAL` that says nothing about nesting, so the flag
		 * is checked in the bytes rather than trusted to the round trip
		 * that masks it off again. */
		memcpy(&on_wire, outer.value - 2, sizeof(on_wire));
		check((on_wire & NLA_F_NESTED) != 0,
		    "and the nested bit is set on it, as strict parsers demand");
		check((on_wire & 0x3fffu) == IFLA_LINKINFO,
		    "with the type still underneath the flag");
		ncfg_buf_free(&nest);
		ncfg_buf_free(&attrs);
		ncfg_buf_free(&raw);
	}

	/* Several messages in one read are all seen. */
	{
		ncfg_buf_t first_attrs;
		ncfg_buf_t second_attrs;
		ncfg_buf_t first;
		ncfg_buf_t second;
		ncfg_buf_t both;
		ncfg_wire_ifinfo_t info = { 0, 0, 0, 0, 0 };
		ncfg_wire_messages_t walk;
		ncfg_wire_message_t message;
		char name[NAME_TEXT];
		int seen = 0;
		int ordered = 1;
		static const char *const expected[2] = { "eth0", "eth1" };

		ncfg_buf_init(&first_attrs, 0);
		ncfg_wire_attr_put_str(&first_attrs, IFLA_IFNAME, "eth0");
		ncfg_buf_init(&second_attrs, 0);
		ncfg_wire_attr_put_str(&second_attrs, IFLA_IFNAME, "eth1");
		ncfg_buf_init(&first, 0);
		ncfg_buf_init(&second, 0);
		(void)link_message(&first, 1, &info, &first_attrs);
		(void)link_message(&second, 2, &info, &second_attrs);
		ncfg_buf_init(&both, 0);
		ncfg_buf_add(&both, first.data, first.length);
		ncfg_buf_add(&both, second.data, second.length);

		ncfg_wire_messages_start(&walk, both.data, both.length);
		while (ncfg_wire_messages_next(&walk, &message, NULL, 0) == NCFG_WIRE_OK) {
			if (seen >= 2 || !link_name(&message, name, sizeof(name)) ||
			    strcmp(name, expected[seen]) != 0) {
				ordered = 0;
				break;
			}
			seen++;
		}
		check(seen == 2 && ordered, "two messages in one read come out in order");
		ncfg_buf_free(&first_attrs);
		ncfg_buf_free(&second_attrs);
		ncfg_buf_free(&first);
		ncfg_buf_free(&second);
		ncfg_buf_free(&both);
	}

	/* An error payload reports its errno. */
	{
		int32_t negated = -EPERM;
		int32_t zero = 0;
		int32_t hostile = INT32_MIN;
		int32_t code = 0;
		char message[NCFG_ERROR_MAX];

		check(ncfg_wire_error_code(&negated, sizeof(negated), &code, NULL, 0) &&
		    code == EPERM, "netlink sends errno negated and it comes back positive");
		check(ncfg_wire_error_code(&zero, sizeof(zero), &code, NULL, 0) && code == 0,
		    "and zero is an acknowledgement rather than a failure");
		/*
		 * `INT32_MIN` is the one value with no positive counterpart, and
		 * negating it is undefined behaviour in C and a panic-or-wrap in
		 * Rust depending on the build profile -- so the same message either
		 * killed the daemon or gave it a nonsense errno. Found by
		 * `cargo fuzz` on the netlink_wire target, from a nine-byte input,
		 * and reduced to this. A refusal, because both callers turn a
		 * refusal into EPROTO and that is exactly what an impossible errno
		 * is.
		 */
		message[0] = '\0';
		check(!ncfg_wire_error_code(&hostile, sizeof(hostile), &code, message,
		    sizeof(message)) && message[0] != '\0',
		    "an errno with no positive counterpart is refused, with a sentence");
		check(!ncfg_wire_error_code(&zero, 3u, &code, NULL, 0),
		    "and a payload too short to hold a code is refused too");
	}

	/*
	 * **The classic netlink parser bug.** A length field below the header
	 * size makes no progress, and the loop runs for ever. This check exists
	 * because that failure mode does not look like a crash, it looks like a
	 * hang in a privileged daemon.
	 */
	{
		uint8_t buffer[64];
		uint8_t attrs[32];
		uint32_t zero = 0;
		uint16_t attr_zero = 0;
		uint8_t *hostile;
		int refused = 0;

		memset(buffer, 0, sizeof(buffer));
		memcpy(buffer, &zero, sizeof(zero));
		hostile = exact_copy(buffer, sizeof(buffer));
		check(count_messages(hostile, sizeof(buffer), &refused) == 0u && refused,
		    "a zero-length message terminates the walk rather than looping");
		free(hostile);

		memset(attrs, 0, sizeof(attrs));
		memcpy(attrs, &attr_zero, sizeof(attr_zero));
		hostile = exact_copy(attrs, sizeof(attrs));
		check(count_attr_bytes(hostile, sizeof(attrs), &refused) == 0u && refused,
		    "and a zero-length attribute does the same one level down");
		free(hostile);
	}

	/* A length that runs past the buffer must not read past the end of it.
	 * Under ASan this is the check that means something. */
	{
		uint8_t buffer[32];
		uint8_t attrs[16];
		uint32_t overlong = 9999;
		uint16_t attr_overlong = 9999;
		uint8_t *hostile;
		int refused = 0;

		memset(buffer, 0, sizeof(buffer));
		memcpy(buffer, &overlong, sizeof(overlong));
		hostile = exact_copy(buffer, sizeof(buffer));
		check(count_messages(hostile, sizeof(buffer), &refused) == 0u && refused,
		    "a message longer than its buffer is refused, not read");
		free(hostile);

		memset(attrs, 0, sizeof(attrs));
		memcpy(attrs, &attr_overlong, sizeof(attr_overlong));
		hostile = exact_copy(attrs, sizeof(attrs));
		check(count_attr_bytes(hostile, sizeof(attrs), &refused) == 0u && refused,
		    "and so is an attribute longer than its area");
		free(hostile);
	}

	/* An attribute that claims more than the message holds. The message is
	 * well-formed; only the attribute inside it lies, which is the shape a
	 * hostile sender actually produces. */
	{
		ncfg_buf_t attrs;
		ncfg_buf_t raw;
		ncfg_wire_ifinfo_t info = { 0, 0, 0, 0, 0 };
		ncfg_wire_message_t message;
		ncfg_wire_attrs_t area;
		ncfg_wire_attr_t attr;
		uint8_t *hostile;
		uint16_t liar;
		size_t at;
		int refused = 0;
		char sentence[NCFG_ERROR_MAX];

		ncfg_buf_init(&attrs, 0);
		ncfg_wire_attr_put_str(&attrs, IFLA_IFNAME, "eth0");
		ncfg_buf_init(&raw, 0);
		(void)link_message(&raw, 1, &info, &attrs);
		at = NCFG_WIRE_NLMSG_HDR_LEN + NCFG_WIRE_IFINFO_LEN;
		liar = (uint16_t)(raw.length - at + 8u);
		memcpy(raw.data + at, &liar, sizeof(liar));
		hostile = exact_copy(raw.data, raw.length);

		check(count_messages(hostile, raw.length, NULL) == 1u,
		    "the message around a lying attribute is still one message");
		check(first_message(hostile, raw.length, &message) &&
		    ncfg_wire_message_attrs(&message, NCFG_WIRE_IFINFO_LEN, &area, NULL, 0),
		    "and its attribute area still begins where it should");
		check(count_attrs(&area, &refused) == 0u && refused,
		    "but an attribute claiming more than the message holds is refused");
		sentence[0] = '\0';
		check(ncfg_wire_attrs_next(&area, &attr, sentence, sizeof(sentence))
		    == NCFG_WIRE_BAD && sentence[0] != '\0', "with a sentence saying so");
		free(hostile);
		ncfg_buf_free(&attrs);
		ncfg_buf_free(&raw);
	}

	/* A truncated header is a refusal; an empty buffer is an end. The
	 * difference is whether the caller has seen everything that was sent. */
	{
		uint8_t buffer[NCFG_WIRE_NLMSG_HDR_LEN - 1u];
		uint8_t *hostile;
		ncfg_wire_messages_t walk;
		ncfg_wire_message_t message;
		char sentence[NCFG_ERROR_MAX];

		memset(buffer, 0xff, sizeof(buffer));
		hostile = exact_copy(buffer, sizeof(buffer));
		sentence[0] = '\0';
		ncfg_wire_messages_start(&walk, hostile, sizeof(buffer));
		check(ncfg_wire_messages_next(&walk, &message, sentence, sizeof(sentence))
		    == NCFG_WIRE_BAD && sentence[0] != '\0',
		    "a buffer that stops mid-header is a refusal with a sentence");
		check(ncfg_wire_messages_next(&walk, &message, NULL, 0) == NCFG_WIRE_END,
		    "and the walk is finished afterwards rather than stuck on it");
		free(hostile);

		ncfg_wire_messages_start(&walk, buffer, 0);
		check(ncfg_wire_messages_next(&walk, &message, NULL, 0) == NCFG_WIRE_END,
		    "while an empty buffer is an end and not a failure");
		ncfg_wire_messages_start(&walk, NULL, 64u);
		check(ncfg_wire_messages_next(&walk, &message, NULL, 0) == NCFG_WIRE_END,
		    "and so is no buffer at all");
	}

	/* Alignment, which is where a padding mistake turns into a wrong value
	 * rather than a refusal. */
	{
		ncfg_buf_t attrs;
		ncfg_wire_attr_t attr;
		uint8_t byte = 1;
		uint32_t mtu = 0;

		check(ncfg_wire_align4(0) == 0 && ncfg_wire_align4(1u) == 4u &&
		    ncfg_wire_align4(4u) == 4u && ncfg_wire_align4(5u) == 8u &&
		    ncfg_wire_align4(17u) == 20u, "align4 rounds up to the next boundary");
		check(ncfg_wire_align4(SIZE_MAX) == SIZE_MAX,
		    "and a length with no room to round is left rather than wrapped to 0");

		ncfg_buf_init(&attrs, 0);
		/* A one-byte value, then a three-byte one, then a four: every
		 * padding case in one area, and the last attribute is the one that
		 * would be misread if any of them were wrong. */
		ncfg_wire_attr_put(&attrs, IFLA_CARRIER, &byte, 1u);
		ncfg_wire_attr_put(&attrs, IFLA_OPERSTATE, "abc", 3u);
		ncfg_wire_attr_put_u32(&attrs, IFLA_MTU, 1492);
		check(attrs.length == 8u + 8u + 8u,
		    "an odd-length attribute is padded and the next one starts aligned");
		check(count_attr_bytes(attrs.data, attrs.length, NULL) == 3u,
		    "all three walk back out");
		check(find_in(&attrs, IFLA_MTU, &attr) == NCFG_WIRE_OK &&
		    ncfg_wire_attr_u32(&attr, &mtu, NULL, 0) && mtu == 1492u,
		    "and the one after the padding is the one that was put there");
		ncfg_buf_free(&attrs);
	}

	/* A message whose own length is not aligned is still a message: the read
	 * ended there and the padding was never sent. */
	{
		ncfg_buf_t raw;
		ncfg_buf_t attrs;
		ncfg_wire_ifinfo_t info = { 0, 0, 0, 0, 0 };
		uint8_t *hostile;
		uint32_t shortened;
		int refused = 0;

		ncfg_buf_init(&attrs, 0);
		ncfg_wire_attr_put_str(&attrs, IFLA_IFNAME, "eth0");
		ncfg_buf_init(&raw, 0);
		(void)link_message(&raw, 1, &info, &attrs);
		/* Claim two bytes fewer than were sent, so `align4` of the length
		 * runs past the end of the buffer. Clamping keeps this message;
		 * wrapping or refusing would lose a well-formed one. */
		shortened = (uint32_t)(raw.length - 2u);
		memcpy(raw.data, &shortened, sizeof(shortened));
		hostile = exact_copy(raw.data, raw.length - 2u);
		check(count_messages(hostile, raw.length - 2u, &refused) == 1u && !refused,
		    "a final message whose padding was never sent is still read");
		free(hostile);
		ncfg_buf_free(&attrs);
		ncfg_buf_free(&raw);
	}

	/* The accessors refuse a value of the wrong size rather than inventing
	 * one out of whatever is next to it. */
	{
		ncfg_buf_t attrs;
		ncfg_wire_attr_t attr;
		uint32_t number = 0;
		uint16_t half = 0;
		ncfg_wire_ip_t ip;
		char text[4];
		char mac[NCFG_WIRE_MAC_TEXT_MAX];
		static const uint8_t two[2] = { 1, 0 };
		static const uint8_t five[5] = { 1, 2, 3, 4, 5 };
		static const uint8_t not_utf8[4] = { 'e', 't', 0xffu, 0 };

		ncfg_buf_init(&attrs, 0);
		ncfg_wire_attr_put(&attrs, IFLA_MTU, two, sizeof(two));
		check(find_in(&attrs, IFLA_MTU, &attr) == NCFG_WIRE_OK &&
		    !ncfg_wire_attr_u32(&attr, &number, NULL, 0) &&
		    ncfg_wire_attr_u16(&attr, &half, NULL, 0) && half == 1u,
		    "a two-byte value is refused as a u32 and read as a u16");
		ncfg_buf_free(&attrs);

		ncfg_buf_init(&attrs, 0);
		ncfg_wire_attr_put(&attrs, IFLA_ADDRESS, five, sizeof(five));
		check(find_in(&attrs, IFLA_ADDRESS, &attr) == NCFG_WIRE_OK &&
		    !ncfg_wire_attr_mac(&attr, mac, sizeof(mac), NULL, 0) &&
		    !ncfg_wire_attr_ip(&attr, &ip, NULL, 0),
		    "five bytes are neither a MAC nor an address, and say so");
		ncfg_buf_free(&attrs);

		ncfg_buf_init(&attrs, 0);
		ncfg_wire_attr_put_str(&attrs, IFLA_IFNAME, "enp0s31f6");
		check(find_in(&attrs, IFLA_IFNAME, &attr) == NCFG_WIRE_OK &&
		    !ncfg_wire_attr_string(&attr, text, sizeof(text), NULL, 0) && text[0] == '\0',
		    "a name that does not fit is refused, never a shorter name");
		ncfg_buf_free(&attrs);

		ncfg_buf_init(&attrs, 0);
		ncfg_wire_attr_put(&attrs, IFLA_IFNAME, not_utf8, sizeof(not_utf8));
		check(find_in(&attrs, IFLA_IFNAME, &attr) == NCFG_WIRE_OK &&
		    !ncfg_wire_attr_string(&attr, mac, sizeof(mac), NULL, 0),
		    "and a name that is not UTF-8 never reaches a document");
		ncfg_buf_free(&attrs);
	}

	/* A zero-length attribute is legal -- an empty nest arrives that way --
	 * and must walk like any other rather than ending the area or reading
	 * the four bytes that follow it. */
	{
		ncfg_buf_t attrs;
		ncfg_wire_attrs_t inside;
		ncfg_wire_attr_t attr;
		uint32_t mtu = 0;

		ncfg_buf_init(&attrs, 0);
		ncfg_wire_attr_put(&attrs, IFLA_LINKINFO, NULL, 0);
		ncfg_wire_attr_put_u32(&attrs, IFLA_MTU, 1280);
		check(attrs.length == 4u + 8u, "an empty attribute is four bytes and no value");
		check(count_attr_bytes(attrs.data, attrs.length, NULL) == 2u,
		    "it walks like any other and the one after it is still found");
		check(find_in(&attrs, IFLA_LINKINFO, &attr) == NCFG_WIRE_OK && attr.length == 0u,
		    "an empty nest comes back empty");
		ncfg_wire_attrs_start(&inside, attr.value, attr.length);
		check(ncfg_wire_attrs_find(&inside, IFLA_INFO_KIND, NULL, NULL, 0)
		    == NCFG_WIRE_END, "and walking the nothing inside it is an end, not a read");
		check(find_in(&attrs, IFLA_MTU, &attr) == NCFG_WIRE_OK &&
		    ncfg_wire_attr_u32(&attr, &mtu, NULL, 0) && mtu == 1280u,
		    "with the value after it intact");
		ncfg_buf_free(&attrs);
	}

	/*
	 * A value too long for the 16-bit length field has no wire form, so it
	 * fails the buffer rather than being appended short. The Rust casts the
	 * sum to `u16` here and appends whatever is left, which makes an
	 * attribute claiming a handful of bytes with the rest of the value
	 * trailing behind it where the next attribute's header should be.
	 */
	{
		ncfg_buf_t attrs;
		static uint8_t huge[70000];

		memset(huge, 'x', sizeof(huge));
		ncfg_buf_init(&attrs, 0);
		ncfg_wire_attr_put_str(&attrs, IFLA_IFNAME, "eth0");
		ncfg_wire_attr_put(&attrs, IFLA_ADDRESS, huge, sizeof(huge));
		check(ncfg_buf_failed(&attrs),
		    "a value too long for the length field fails the buffer");
		check(ncfg_buf_text(&attrs)[0] == '\0', "and hands out nothing to send");
		ncfg_buf_free(&attrs);
	}

	/* A request whose attributes never built must not go out with them
	 * quietly missing: an `RTM_NEWLINK` with no `IFLA_IFNAME` is not a
	 * refusal, it is a link the kernel names itself. */
	{
		ncfg_buf_t attrs;
		ncfg_buf_t body;
		ncfg_buf_t raw;
		ncfg_wire_ifinfo_t info = { 0, 0, 0, 0, 0 };
		char sentence[NCFG_ERROR_MAX];

		ncfg_buf_init(&attrs, 4u);
		ncfg_wire_attr_put_str(&attrs, IFLA_IFNAME, "eth0");
		check(ncfg_buf_failed(&attrs), "an attribute area past its limit says so");
		ncfg_buf_init(&body, 0);
		ncfg_wire_ifinfo_encode(&info, &body);
		ncfg_buf_init(&raw, 0);
		sentence[0] = '\0';
		check(!ncfg_wire_build_request(&raw, RTM_NEWLINK, NLM_F_REQUEST, 1, &body, &attrs,
		    sentence, sizeof(sentence)) && sentence[0] != '\0',
		    "and a request refuses to be built around it");
		ncfg_buf_free(&attrs);
		ncfg_buf_free(&body);
		ncfg_buf_free(&raw);
	}

	/* A payload shorter than the family struct it claims to carry. Clamping
	 * here would read whatever follows the message in the read buffer as
	 * this message's attributes. */
	{
		ncfg_buf_t raw;
		uint8_t *hostile;
		ncfg_wire_message_t message;
		ncfg_wire_attrs_t area;
		ncfg_wire_header_t header;
		ncfg_wire_ifinfo_t info;
		static const uint8_t stub[4] = { 1, 2, 3, 4 };
		char sentence[NCFG_ERROR_MAX];

		header.len = NCFG_WIRE_NLMSG_HDR_LEN + 4u;
		header.kind = RTM_NEWLINK;
		header.flags = 0;
		header.seq = 1;
		header.pid = 0;
		ncfg_buf_init(&raw, 0);
		ncfg_wire_header_encode(&header, &raw);
		ncfg_buf_add(&raw, stub, sizeof(stub));
		hostile = exact_copy(raw.data, raw.length);
		sentence[0] = '\0';
		check(first_message(hostile, raw.length, &message) &&
		    !ncfg_wire_message_attrs(&message, NCFG_WIRE_IFINFO_LEN, &area, sentence,
		    sizeof(sentence)) && sentence[0] != '\0',
		    "a payload too short for its family struct has no attribute area");
		check(!ncfg_wire_ifinfo_decode(message.payload, message.payload_length, &info,
		    NULL, 0), "and the struct itself refuses to be decoded from it");
		free(hostile);
		ncfg_buf_free(&raw);
	}

	/*
	 * **Adversarial bytes, at every entry point.** These decoders take bytes
	 * from a socket, which is input this process does not control. Nothing
	 * here may read past its buffer, whatever arrives, and the ASan build is
	 * what turns that from an assertion into a check.
	 */
	{
		static uint8_t ascending[256];
		static uint8_t descending[256];
		static uint8_t all_ff[64];
		static const uint8_t fifteen_zero[15] = { 0 };
		static const uint8_t one_le[4] = { 0x01, 0x00, 0x00, 0x00 };
		static const uint8_t two_headers[8] = {
			0x10, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00
		};
		static const uint8_t one_zero[1] = { 0 };
		struct {
			const uint8_t *bytes;
			size_t         length;
		} seeds[10];
		size_t seed;
		int bounded = 1;
		int i;

		for (i = 0; i < 256; i++) {
			ascending[i] = (uint8_t)i;
			descending[i] = (uint8_t)(255 - i);
		}
		memset(all_ff, 0xff, sizeof(all_ff));
		seeds[0].bytes = NULL;
		seeds[0].length = 0;
		seeds[1].bytes = one_zero;
		seeds[1].length = sizeof(one_zero);
		seeds[2].bytes = all_ff;
		seeds[2].length = 3u;
		seeds[3].bytes = all_ff;
		seeds[3].length = 16u;
		seeds[4].bytes = all_ff;
		seeds[4].length = sizeof(all_ff);
		seeds[5].bytes = fifteen_zero;
		seeds[5].length = sizeof(fifteen_zero);
		seeds[6].bytes = one_le;
		seeds[6].length = sizeof(one_le);
		seeds[7].bytes = ascending;
		seeds[7].length = sizeof(ascending);
		seeds[8].bytes = descending;
		seeds[8].length = sizeof(descending);
		seeds[9].bytes = two_headers;
		seeds[9].length = sizeof(two_headers);

		for (seed = 0; seed < sizeof(seeds) / sizeof(seeds[0]); seed++) {
			/* Copied to an allocation of exactly its length, so that a
			 * read one byte past the input is a read past the end of a
			 * heap block rather than a read of the next seed. */
			uint8_t *bytes = exact_copy(seeds[seed].bytes, seeds[seed].length);
			size_t length = bytes ? seeds[seed].length : 0;
			ncfg_wire_header_t header;
			ncfg_wire_ifinfo_t info;
			ncfg_wire_ifaddr_t addr;
			ncfg_wire_rtmsg_t route;
			ncfg_wire_messages_t walk;
			ncfg_wire_message_t message;
			int32_t code;

			/* Every entry point, on every seed. Any answer is fine;
			 * reading past the end is not, and that is ASan's to say. */
			(void)ncfg_wire_header_decode(bytes, length, &header, NULL, 0);
			(void)ncfg_wire_ifinfo_decode(bytes, length, &info, NULL, 0);
			(void)ncfg_wire_ifaddr_decode(bytes, length, &addr, NULL, 0);
			(void)ncfg_wire_rtmsg_decode(bytes, length, &route, NULL, 0);
			(void)ncfg_wire_error_code(bytes, length, &code, NULL, 0);
			if (count_messages(bytes, length, NULL) >= WALK_CAP ||
			    count_attr_bytes(bytes, length, NULL) >= WALK_CAP) {
				bounded = 0;
			}
			ncfg_wire_messages_start(&walk, bytes, length);
			while (ncfg_wire_messages_next(&walk, &message, NULL, 0) == NCFG_WIRE_OK) {
				ncfg_wire_attrs_t inside;
				char name[NAME_TEXT];

				(void)ncfg_wire_ifinfo_decode(message.payload,
				    message.payload_length, &info, NULL, 0);
				(void)ncfg_wire_ifaddr_decode(message.payload,
				    message.payload_length, &addr, NULL, 0);
				(void)ncfg_wire_rtmsg_decode(message.payload,
				    message.payload_length, &route, NULL, 0);
				(void)link_name(&message, name, sizeof(name));
				if (ncfg_wire_message_attrs(&message, NCFG_WIRE_IFADDR_LEN,
				    &inside, NULL, 0)) {
					(void)count_attrs(&inside, NULL);
				}
			}
			free(bytes);
		}
		check(bounded, "no seed makes a walk run away with itself");
	}

	/*
	 * Every truncation of a well-formed message, which is the shape a short
	 * read actually produces -- and the shape that finds an off-by-one,
	 * because exactly one cut sits on each boundary.
	 *
	 * Twice over: once with the length field left alone, where every cut has
	 * to be refused because the message says it is longer than what arrived,
	 * and once with the length field cut down to match, where the message is
	 * accepted and the truncation lands inside the attribute area instead.
	 * The second is the one that exercises the bounds checks that matter,
	 * and the first is the one a socket actually hands you.
	 */
	{
		ncfg_buf_t attrs;
		ncfg_buf_t whole;
		ncfg_wire_ifinfo_t info = { 0, 0, 0, 0, 0 };
		size_t cut;
		int bounded = 1;
		int accepted = 0;
		int named = 0;

		ncfg_buf_init(&attrs, 0);
		ncfg_wire_attr_put_str(&attrs, IFLA_IFNAME, "eth0");
		ncfg_wire_attr_put_u32(&attrs, IFLA_MTU, 1500);
		ncfg_buf_init(&whole, 0);
		(void)link_message(&whole, 1, &info, &attrs);

		for (cut = 0; cut < whole.length; cut++) {
			uint8_t *partial = exact_copy(whole.data, cut);

			if (count_messages(partial, cut, NULL) >= WALK_CAP) {
				bounded = 0;
			}
			if (count_messages(partial, cut, NULL) > 0) {
				accepted++;
			}
			free(partial);
		}
		check(bounded, "every truncation of a message terminates its walk");
		check(accepted == 0,
		    "and a message longer than what arrived is refused at every cut");

		for (cut = NCFG_WIRE_NLMSG_HDR_LEN; cut < whole.length; cut++) {
			uint8_t *partial = exact_copy(whole.data, cut);
			uint32_t honest = (uint32_t)cut;
			ncfg_wire_messages_t walk;
			ncfg_wire_message_t message;

			memcpy(partial, &honest, sizeof(honest));
			if (count_messages(partial, cut, NULL) >= WALK_CAP) {
				bounded = 0;
			}
			ncfg_wire_messages_start(&walk, partial, cut);
			while (ncfg_wire_messages_next(&walk, &message, NULL, 0) == NCFG_WIRE_OK) {
				ncfg_wire_attrs_t inside;
				char name[NAME_TEXT];

				(void)ncfg_wire_ifinfo_decode(message.payload,
				    message.payload_length, &info, NULL, 0);
				if (link_name(&message, name, sizeof(name))) {
					/* A name only comes back whole, never as a
					 * prefix of itself: a truncated interface
					 * name is a name, just somebody else's. */
					if (strcmp(name, "eth0") != 0) {
						named = 1;
					}
				}
				if (ncfg_wire_message_attrs(&message, NCFG_WIRE_IFINFO_LEN,
				    &inside, NULL, 0)) {
					(void)count_attrs(&inside, NULL);
				}
			}
			free(partial);
		}
		check(bounded, "a truncated attribute area terminates its walk too");
		check(named == 0, "and no cut ever yields a name that is a piece of one");
		check(count_messages(whole.data, whole.length, NULL) == 1u,
		    "while the untruncated message still reads as one");
		ncfg_buf_free(&attrs);
		ncfg_buf_free(&whole);
	}

	if (failures == 0) {
		printf("wire_test: all checks passed\n");
	} else {
		printf("wire_test: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
