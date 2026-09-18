/*
 * ops_test.c -- the rtnetlink operations, against the bytes they produce.
 *
 * WHY THIS EXISTS
 *   The Rust these builders come from can only be checked against a kernel,
 *   because it builds each request inside the method that sends it. Half the
 *   comments in ops.c name a defect that cost a measurement on a live machine
 *   to find -- a VXLAN's underlay in the outer `IFLA_LINK` where nothing reads
 *   it, a geneve tunnel's TTL written into the outer DSCP, an ip tunnel's
 *   attribute numbering sent to GRE. Every one of them is a wrong byte in a
 *   message, and a wrong byte is a thing a test can see without privileges,
 *   without a socket and without touching this machine's network.
 *
 *   So nothing here sends anything. Each case builds a request and walks it
 *   back out with the wire layer: header, family struct, attribute by
 *   attribute, into the nests. Walking it back rather than comparing against a
 *   hand-written blob is the point -- a blob says "these 96 bytes", and what
 *   wants saying is "the VLAN id is inside `INFO_DATA` and the protocol beside
 *   it is big-endian".
 *
 * WHERE A NUMBER IS WRITTEN OUT RATHER THAN NAMED
 *   Mostly the kernel's own constants are used, because the code uses them and
 *   a case naming a different one catches a wrong choice. Two groups are
 *   written out as numbers instead, and each says why: they are the ones where
 *   the defect *was* the number, and where the reader that agreed with the
 *   writer is what made it invisible.
 */
#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/ops.h"
#include "ncfg/wire.h"

#include <linux/if_bridge.h>
#include <linux/veth.h>
#include <stdio.h>
#include <string.h>

static int failures;

static void check(int condition, const char *what)
{
	printf("%-70s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

/* `IFF_UP`, written out rather than included: `linux/if.h` and `net/if.h`
 * redefine each other's structures, which is wire.h's reason for writing
 * `ALTIFNAMSIZ` out too. A test that included the first would be asserting
 * against the same header the code read; this one asserts against the bit. */
#define TEST_IFF_UP 0x1u

/* The one sequence number every case uses, so that "the header echoes it" is a
 * check rather than a coincidence with zero. */
#define SEQ 0x11223344u

static char err[NCFG_ERROR_MAX];

static const ncfg_wire_ip_t no_ip = NCFG_OPS_IP_ABSENT;
static const ncfg_optint_t absent = { 0, 0 };

static ncfg_optint_t some(int64_t value)
{
	ncfg_optint_t out;

	out.has = 1;
	out.value = value;
	return out;
}

/* An address, or an absent one where the text is not an address -- which is a
 * failure the case using it will report as a missing attribute. */
static ncfg_wire_ip_t parse_ip(const char *text)
{
	ncfg_wire_ip_t out;

	if (!ncfg_wire_ip_parse(text, &out, NULL, 0)) {
		return no_ip;
	}
	return out;
}

static ncfg_ops_newlink_t link_of(int kind)
{
	ncfg_ops_newlink_t link;

	memset(&link, 0, sizeof(link));
	link.kind = kind;
	link.vxlan.local = no_ip;
	link.vxlan.remote = no_ip;
	link.tunnel.local = no_ip;
	link.tunnel.remote = no_ip;
	return link;
}

/* The first message of a built request. */
static int message_of(const ncfg_buf_t *buf, ncfg_wire_message_t *out)
{
	ncfg_wire_messages_t walk;

	ncfg_wire_messages_start(&walk, buf->data, buf->length);
	return ncfg_wire_messages_next(&walk, out, NULL, 0) == NCFG_WIRE_OK;
}

/* The attribute area of a request whose family struct is `body` bytes long. */
static int area_of(const ncfg_buf_t *buf, size_t body, ncfg_wire_attrs_t *out)
{
	ncfg_wire_message_t message;

	if (!message_of(buf, &message)) {
		return 0;
	}
	return ncfg_wire_message_attrs(&message, body, out, NULL, 0);
}

static int find(const ncfg_wire_attrs_t *area, uint16_t kind, ncfg_wire_attr_t *out)
{
	return ncfg_wire_attrs_find(area, kind, out, NULL, 0) == NCFG_WIRE_OK;
}

/*
 * Well-formed, and no attribute of this type in it.
 *
 * `END` and not `BAD`, which is the distinction wire.h exists to keep: "this
 * attribute is not here" and "these bytes are rubbish" are different answers,
 * and a case asserting absence has to be sure it got the first.
 */
static int absent_attr(const ncfg_wire_attrs_t *area, uint16_t kind)
{
	ncfg_wire_attr_t attr;

	return ncfg_wire_attrs_find(area, kind, &attr, NULL, 0) == NCFG_WIRE_END;
}

static int nest_of(const ncfg_wire_attrs_t *area, uint16_t kind, ncfg_wire_attrs_t *out)
{
	ncfg_wire_attr_t attr;

	if (!find(area, kind, &attr)) {
		return 0;
	}
	ncfg_wire_attrs_start(out, attr.value, attr.length);
	return 1;
}

/* An attribute's value as a native integer, or a number no case expects where
 * it is missing or the wrong width. */
static uint32_t u32_of(const ncfg_wire_attrs_t *area, uint16_t kind)
{
	ncfg_wire_attr_t attr;
	uint32_t value = 0;

	if (!find(area, kind, &attr) || !ncfg_wire_attr_u32(&attr, &value, NULL, 0)) {
		return 0xdeadbeefu;
	}
	return value;
}

static uint16_t u16_of(const ncfg_wire_attrs_t *area, uint16_t kind)
{
	ncfg_wire_attr_t attr;
	uint16_t value = 0;

	if (!find(area, kind, &attr) || !ncfg_wire_attr_u16(&attr, &value, NULL, 0)) {
		return 0xbeefu;
	}
	return value;
}

static uint8_t u8_of(const ncfg_wire_attrs_t *area, uint16_t kind)
{
	ncfg_wire_attr_t attr;
	uint8_t value = 0;

	if (!find(area, kind, &attr) || !ncfg_wire_attr_u8(&attr, &value, NULL, 0)) {
		return 0xefu;
	}
	return value;
}

/*
 * An attribute whose value is big-endian, checked as bytes.
 *
 * The whole point of these fields is that they are *not* the host's order, so
 * reading one back through a native accessor and comparing would pass on a
 * little-endian machine with the encoder broken. wire.h says the same thing
 * about its own tests.
 */
static int be16_is(const ncfg_wire_attrs_t *area, uint16_t kind, uint16_t value)
{
	ncfg_wire_attr_t attr;

	return find(area, kind, &attr) && attr.length == 2u &&
	    attr.value[0] == (uint8_t)(value >> 8) && attr.value[1] == (uint8_t)(value & 0xffu);
}

static int be32_is(const ncfg_wire_attrs_t *area, uint16_t kind, uint32_t value)
{
	ncfg_wire_attr_t attr;

	return find(area, kind, &attr) && attr.length == 4u &&
	    attr.value[0] == (uint8_t)(value >> 24) &&
	    attr.value[1] == (uint8_t)((value >> 16) & 0xffu) &&
	    attr.value[2] == (uint8_t)((value >> 8) & 0xffu) &&
	    attr.value[3] == (uint8_t)(value & 0xffu);
}

static int ip_is(const ncfg_wire_attrs_t *area, uint16_t kind, const char *text)
{
	ncfg_wire_attr_t attr;
	ncfg_wire_ip_t want = parse_ip(text);
	size_t width = want.family == AF_INET6 ? 16u : 4u;

	return find(area, kind, &attr) && attr.length == width &&
	    memcmp(attr.value, want.bytes, width) == 0;
}

static int str_is(const ncfg_wire_attrs_t *area, uint16_t kind, const char *text)
{
	ncfg_wire_attr_t attr;
	char out[NCFG_WIRE_ALT_IFNAME_MAX];

	if (!find(area, kind, &attr) || !ncfg_wire_attr_string(&attr, out, sizeof(out), NULL, 0)) {
		return 0;
	}
	/* The NUL is part of the value: the kernel's `nla_strcmp` reads to the
	 * terminator, and a name sent without one matches the name beside it. */
	return strcmp(out, text) == 0 && attr.length == strlen(text) + 1u;
}

/*
 * Whether the attribute of this type carries `NLA_F_NESTED`.
 *
 * 1 for set, 0 for clear, -1 for not there. The walk masks the flag off --
 * it is not part of the type -- so this reads the raw four-byte headers, which
 * is the only way to see the bit that a strict rtnetlink parser rejects a nest
 * for missing.
 */
static int nested_bit(const void *bytes, size_t length, uint16_t kind)
{
	const uint8_t *at = bytes;
	size_t off = 0;

	while (off + NCFG_WIRE_RTATTR_HDR_LEN <= length) {
		uint16_t len;
		uint16_t type;

		memcpy(&len, at + off, sizeof(len));
		memcpy(&type, at + off + sizeof(len), sizeof(type));
		if (len < NCFG_WIRE_RTATTR_HDR_LEN || off + len > length) {
			return -1;
		}
		if ((type & 0x3fffu) == kind) {
			return (type & 0x8000u) != 0 ? 1 : 0;
		}
		off += ncfg_wire_align4(len);
	}
	return -1;
}

/*
 * The raw attribute bytes of a request, past the header and the family struct.
 *
 * Taken from the buffer rather than from a started walk, because the walk's
 * fields are its own business and the next helper needs the bytes exactly as
 * they were written.
 */
static const uint8_t *tail_of(const ncfg_buf_t *buf, size_t body, size_t *length)
{
	size_t start = NCFG_WIRE_NLMSG_HDR_LEN + ncfg_wire_align4(body);

	if (buf->length < start) {
		*length = 0;
		return NULL;
	}
	*length = buf->length - start;
	return (const uint8_t *)buf->data + start;
}

/* Header checks every case shares: the type, the flags, an echoed sequence
 * number, a port id of zero, and a length that agrees with the bytes. */
static int header_is(const ncfg_buf_t *buf, uint16_t kind, uint16_t flags)
{
	ncfg_wire_message_t message;

	if (!message_of(buf, &message)) {
		return 0;
	}
	return message.header.kind == kind && message.header.flags == flags &&
	    message.header.seq == SEQ && message.header.pid == 0 &&
	    message.header.len == (uint32_t)buf->length;
}

/* Every request this module builds asks to be acknowledged. */
static int acknowledged(const ncfg_buf_t *buf)
{
	ncfg_wire_message_t message;

	if (!message_of(buf, &message)) {
		return 0;
	}
	return (message.header.flags & (NLM_F_REQUEST | NLM_F_ACK)) ==
	    (NLM_F_REQUEST | NLM_F_ACK);
}

/* The `ifinfomsg` at the head of a link message. */
static int ifinfo_of(const ncfg_buf_t *buf, ncfg_wire_ifinfo_t *out)
{
	ncfg_wire_message_t message;

	if (!message_of(buf, &message)) {
		return 0;
	}
	return ncfg_wire_ifinfo_decode(message.payload, message.payload_length, out, NULL, 0);
}

static int ifaddr_of(const ncfg_buf_t *buf, ncfg_wire_ifaddr_t *out)
{
	ncfg_wire_message_t message;

	if (!message_of(buf, &message)) {
		return 0;
	}
	return ncfg_wire_ifaddr_decode(message.payload, message.payload_length, out, NULL, 0);
}

static int rtmsg_of(const ncfg_buf_t *buf, ncfg_wire_rtmsg_t *out)
{
	ncfg_wire_message_t message;

	if (!message_of(buf, &message)) {
		return 0;
	}
	return ncfg_wire_rtmsg_decode(message.payload, message.payload_length, out, NULL, 0);
}

/* The `LINKINFO` nest of a link message, and the `INFO_DATA` inside it. */
static int linkinfo_of(const ncfg_buf_t *buf, ncfg_wire_attrs_t *out)
{
	ncfg_wire_attrs_t area;

	if (!area_of(buf, NCFG_WIRE_IFINFO_LEN, &area)) {
		return 0;
	}
	return nest_of(&area, IFLA_LINKINFO, out);
}

static int info_data_of(const ncfg_buf_t *buf, ncfg_wire_attrs_t *out)
{
	ncfg_wire_attrs_t info;

	if (!linkinfo_of(buf, &info)) {
		return 0;
	}
	return nest_of(&info, IFLA_INFO_DATA, out);
}

/* The kind word a link message carries, or "" where it has none. */
static const char *kind_word_of(const ncfg_buf_t *buf, char *out, size_t out_size)
{
	ncfg_wire_attrs_t info;
	ncfg_wire_attr_t attr;

	out[0] = '\0';
	if (linkinfo_of(buf, &info) && find(&info, IFLA_INFO_KIND, &attr)) {
		(void)ncfg_wire_attr_string(&attr, out, out_size, NULL, 0);
	}
	return out;
}

int main(void)
{
	/* ---------------------------------------------------------------- *
	 * The frame: type, flags, sequence, and a length that agrees
	 * ---------------------------------------------------------------- */
	{
		ncfg_ops_newlink_t dummy = link_of(NCFG_OPS_LINK_DUMMY);
		ncfg_ops_route_t route;
		ncfg_ops_rule_t rule;
		ncfg_wire_ip_t address = parse_ip("192.0.2.7");
		ncfg_buf_t buf;
		uint16_t ack = (uint16_t)(NLM_F_REQUEST | NLM_F_ACK);

		memset(&route, 0, sizeof(route));
		route.index = 3;
		route.destination = no_ip;
		route.gateway = parse_ip("192.0.2.1");
		route.source = no_ip;
		memset(&rule, 0, sizeof(rule));
		rule.family = AF_INET;
		rule.from = no_ip;
		rule.to = no_ip;

		ncfg_buf_init(&buf, 0);
		check(ncfg_ops_create_link(&buf, SEQ, "dummy0", &dummy, err, sizeof(err)),
		    "a dummy link builds");
		check(header_is(&buf, RTM_NEWLINK,
		    (uint16_t)(ack | NLM_F_CREATE | NLM_F_EXCL)),
		    "creating a link is NEWLINK with CREATE and EXCL, and echoes the sequence");
		ncfg_buf_free(&buf);

		ncfg_buf_init(&buf, 0);
		check(ncfg_ops_delete_link(&buf, SEQ, 9, err, sizeof(err)) &&
		    header_is(&buf, RTM_DELLINK, ack), "deleting a link is DELLINK");
		ncfg_buf_free(&buf);

		ncfg_buf_init(&buf, 0);
		check(ncfg_ops_add_address(&buf, SEQ, 3, &address, 24,
		    NCFG_WIRE_RTPROT_NETCFGD, err, sizeof(err)) &&
		    header_is(&buf, RTM_NEWADDR,
		    (uint16_t)(ack | NLM_F_CREATE | NLM_F_REPLACE)),
		    "adding an address is NEWADDR with CREATE and REPLACE");
		ncfg_buf_free(&buf);

		ncfg_buf_init(&buf, 0);
		check(ncfg_ops_del_address(&buf, SEQ, 3, &address, 24, err, sizeof(err)) &&
		    header_is(&buf, RTM_DELADDR, ack), "removing one is DELADDR, and no more");
		ncfg_buf_free(&buf);

		ncfg_buf_init(&buf, 0);
		check(ncfg_ops_add_route(&buf, SEQ, &route, err, sizeof(err)) &&
		    header_is(&buf, RTM_NEWROUTE, (uint16_t)(ack | NLM_F_CREATE)),
		    "adding a route is NEWROUTE with CREATE");
		ncfg_buf_free(&buf);

		ncfg_buf_init(&buf, 0);
		check(ncfg_ops_del_route(&buf, SEQ, &route, err, sizeof(err)) &&
		    header_is(&buf, RTM_DELROUTE, ack), "removing one is DELROUTE");
		ncfg_buf_free(&buf);

		ncfg_buf_init(&buf, 0);
		check(ncfg_ops_add_rule(&buf, SEQ, &rule, err, sizeof(err)) &&
		    header_is(&buf, RTM_NEWRULE, (uint16_t)(ack | NLM_F_CREATE | NLM_F_EXCL)),
		    "adding a rule is NEWRULE with CREATE and EXCL");
		check(acknowledged(&buf), "and it asks to be acknowledged");
		ncfg_buf_free(&buf);

		ncfg_buf_init(&buf, 0);
		check(ncfg_ops_del_rule(&buf, SEQ, &rule, err, sizeof(err)) &&
		    header_is(&buf, RTM_DELRULE, ack), "removing one is DELRULE");
		ncfg_buf_free(&buf);

		ncfg_buf_init(&buf, 0);
		check(ncfg_ops_add_altname(&buf, SEQ, 3, "ncfg:eth0", err, sizeof(err)) &&
		    header_is(&buf, RTM_NEWLINKPROP, ack),
		    "an alternative name is NEWLINKPROP, not an attribute on NEWLINK");
		ncfg_buf_free(&buf);
	}

	/* ---------------------------------------------------------------- *
	 * A link with no kind data
	 * ---------------------------------------------------------------- */
	{
		static const int plain[] = { NCFG_OPS_LINK_BRIDGE, NCFG_OPS_LINK_DUMMY,
			NCFG_OPS_LINK_IFB, NCFG_OPS_LINK_WIREGUARD };
		static const char *const words[] = { "bridge", "dummy", "ifb", "wireguard" };
		int right = 1;
		size_t at;

		for (at = 0; at < sizeof(plain) / sizeof(plain[0]); at++) {
			ncfg_ops_newlink_t link = link_of(plain[at]);
			ncfg_wire_attrs_t info;
			ncfg_wire_ifinfo_t body;
			ncfg_buf_t buf;
			char word[32];

			ncfg_buf_init(&buf, 0);
			if (!ncfg_ops_create_link(&buf, SEQ, "x0", &link, err, sizeof(err))) {
				right = 0;
			} else {
				if (strcmp(kind_word_of(&buf, word, sizeof(word)),
				    words[at]) != 0) {
					right = 0;
				}
				/* No `INFO_DATA` at all, rather than an empty one:
				 * these four take no parameters and an empty nest
				 * would be a claim that they might. */
				if (!linkinfo_of(&buf, &info) ||
				    !absent_attr(&info, IFLA_INFO_DATA)) {
					right = 0;
				}
				if (!ifinfo_of(&buf, &body) || body.index != 0 ||
				    body.flags != 0 || body.change != 0) {
					right = 0;
				}
			}
			ncfg_buf_free(&buf);
		}
		check(right, "bridge, dummy, ifb and wireguard: the word, and no INFO_DATA");

		/* The spelling this project has shipped wrong twice. The document
		 * says `wire_guard` and the language says `wireguard`; the kernel
		 * takes the second, and a link created with the first is a link the
		 * kernel has never heard of. */
		{
			ncfg_ops_newlink_t wg = link_of(NCFG_OPS_LINK_WIREGUARD);

			check(strcmp(ncfg_ops_link_kind_word(&wg), "wireguard") == 0,
			    "and the kind word is `wireguard`, never the document's spelling");
		}
	}

	/* ---------------------------------------------------------------- *
	 * A VLAN: the id inside INFO_DATA, the protocol big-endian beside it,
	 * and the parent in the OUTER attribute
	 * ---------------------------------------------------------------- */
	{
		ncfg_ops_newlink_t link = link_of(NCFG_OPS_LINK_VLAN);
		ncfg_wire_attrs_t outer;
		ncfg_wire_attrs_t data;
		ncfg_buf_t buf;
		char word[32];

		link.vlan.parent = 7;
		link.vlan.id = 42;
		link.vlan.protocol = 0x8100u;

		ncfg_buf_init(&buf, 0);
		check(ncfg_ops_create_link(&buf, SEQ, "eth0.42", &link, err, sizeof(err)),
		    "a VLAN builds");
		check(area_of(&buf, NCFG_WIRE_IFINFO_LEN, &outer) &&
		    str_is(&outer, IFLA_IFNAME, "eth0.42"),
		    "with its name NUL-terminated in IFLA_IFNAME");
		check(u32_of(&outer, IFLA_LINK) == 7u,
		    "and its parent in the OUTER IFLA_LINK, which is where a VLAN's is read");
		check(strcmp(kind_word_of(&buf, word, sizeof(word)), "vlan") == 0,
		    "the kind word is `vlan`");
		check(info_data_of(&buf, &data), "and there is an INFO_DATA nest");
		/* The case that a port gets wrong: the id is *inside* the nest, not
		 * beside `IFLA_LINKINFO`, and it is a native `u16`. */
		check(u16_of(&data, IFLA_VLAN_ID) == 42u,
		    "the VLAN id lives inside INFO_DATA and is a native u16");
		check(absent_attr(&outer, IFLA_VLAN_ID),
		    "and nowhere else -- an id beside LINKINFO is silently ignored");
		/*
		 * Big-endian: it is an ethertype and the kernel reads it as one. It
		 * knows 0x8100 and 0x88a8 and rejects the byte-swapped values, so
		 * sending this natively is a link that refuses to be created -- or,
		 * on a big-endian machine, one that works by luck.
		 */
		check(be16_is(&data, IFLA_VLAN_PROTOCOL, 0x8100u),
		    "while the protocol beside it is an ethertype, big-endian");
		ncfg_buf_free(&buf);

		link.vlan.protocol = 0x88a8u;
		ncfg_buf_init(&buf, 0);
		check(ncfg_ops_create_link(&buf, SEQ, "eth0.42", &link, err, sizeof(err)) &&
		    info_data_of(&buf, &data) &&
		    be16_is(&data, IFLA_VLAN_PROTOCOL, 0x88a8u),
		    "and 802.1ad goes out as 0x88 0xa8 too");
		ncfg_buf_free(&buf);
	}

	/* ---------------------------------------------------------------- *
	 * A VXLAN: the underlay INSIDE the nest, which is the whole defect
	 * ---------------------------------------------------------------- */
	{
		ncfg_ops_newlink_t link = link_of(NCFG_OPS_LINK_VXLAN);
		ncfg_wire_attrs_t outer;
		ncfg_wire_attrs_t data;
		ncfg_buf_t buf;

		link.vxlan.id = 100;
		link.vxlan.parent = some(7);
		link.vxlan.local = parse_ip("192.0.2.9");
		link.vxlan.remote = parse_ip("239.1.1.1");
		link.vxlan.port = some(4789);

		ncfg_buf_init(&buf, 0);
		check(ncfg_ops_create_link(&buf, SEQ, "vx0", &link, err, sizeof(err)) &&
		    info_data_of(&buf, &data), "a VXLAN builds with an INFO_DATA nest");
		check(u32_of(&data, IFLA_VXLAN_ID) == 100u, "carrying its VNI");
		/*
		 * Measured, after the outer `IFLA_LINK` was sent for as long as
		 * VXLANs have existed and did nothing at all: `vxlan_nl2conf` reads
		 * `data[IFLA_VXLAN_LINK]` and nothing reads `tb[IFLA_LINK]`. A
		 * document naming a parent got a VXLAN whose outer packets the
		 * kernel routed itself, and nothing said so.
		 */
		check(u32_of(&data, IFLA_VXLAN_LINK) == 7u,
		    "its underlay INSIDE the nest, where the kernel reads it");
		check(area_of(&buf, NCFG_WIRE_IFINFO_LEN, &outer) &&
		    absent_attr(&outer, IFLA_LINK),
		    "and NOT in the outer IFLA_LINK, which a VXLAN ignores");
		check(ip_is(&data, IFLA_VXLAN_LOCAL, "192.0.2.9") &&
		    ip_is(&data, IFLA_VXLAN_GROUP, "239.1.1.1"),
		    "a v4 local and group take the v4 attribute numbers");
		check(be16_is(&data, IFLA_VXLAN_PORT, 4789u),
		    "and the destination port is big-endian, like every port on the wire");
		ncfg_buf_free(&buf);

		/* The v4 and v6 attributes are different numbers, so the family
		 * decides which is sent rather than the value being coerced. */
		link.vxlan.local = parse_ip("2001:db8::9");
		link.vxlan.remote = parse_ip("ff05::100");
		ncfg_buf_init(&buf, 0);
		check(ncfg_ops_create_link(&buf, SEQ, "vx0", &link, err, sizeof(err)) &&
		    info_data_of(&buf, &data) &&
		    ip_is(&data, IFLA_VXLAN_LOCAL6, "2001:db8::9") &&
		    ip_is(&data, IFLA_VXLAN_GROUP6, "ff05::100") &&
		    absent_attr(&data, IFLA_VXLAN_LOCAL) &&
		    absent_attr(&data, IFLA_VXLAN_GROUP),
		    "a v6 local and group take the v6 numbers and not the v4 ones");
		ncfg_buf_free(&buf);
	}

	/* ---------------------------------------------------------------- *
	 * Re-stating a kind to a device that exists: three attributes drop out
	 * ---------------------------------------------------------------- */
	{
		ncfg_ops_newlink_t link = link_of(NCFG_OPS_LINK_VXLAN);
		ncfg_wire_attrs_t data;
		ncfg_wire_ifinfo_t body;
		ncfg_buf_t buf;

		link.vxlan.id = 100;
		link.vxlan.parent = some(7);
		link.vxlan.local = no_ip;
		link.vxlan.remote = parse_ip("198.51.100.4");
		link.vxlan.port = some(4789);

		ncfg_buf_init(&buf, 0);
		check(ncfg_ops_set_link_kind(&buf, SEQ, 12, &link, err, sizeof(err)) &&
		    info_data_of(&buf, &data), "a VXLAN's settings re-state to an existing one");
		check(ifinfo_of(&buf, &body) && body.index == 12,
		    "at the index given, rather than at none");
		/* `vxlan_nl2conf` answers `EOPNOTSUPP` on the port attribute's
		 * presence, whether or not the value differs -- so a nest carrying
		 * it could never correct the remote beside it. Decision 0058. */
		check(absent_attr(&data, IFLA_VXLAN_PORT),
		    "the port is left out: the kernel refuses its presence, at any value");
		/* The VNI is refused only when it differs, so restating it would
		 * work -- and it is omitted anyway, because a VXLAN keeps what a
		 * change leaves out and a value whose only legal form is "the same
		 * as now" says nothing. */
		check(absent_attr(&data, IFLA_VXLAN_ID), "and so is the VNI");
		check(u32_of(&data, IFLA_VXLAN_LINK) == 7u,
		    "while the underlay stays, because the kernel takes that one");
		check(ip_is(&data, IFLA_VXLAN_GROUP, "198.51.100.4"),
		    "and the remote it was sent to correct");
		ncfg_buf_free(&buf);
	}

	/* ---------------------------------------------------------------- *
	 * A veth: the peer's whole definition, nested
	 * ---------------------------------------------------------------- */
	{
		ncfg_ops_newlink_t link = link_of(NCFG_OPS_LINK_VETH);
		ncfg_wire_attrs_t data;
		ncfg_wire_attr_t peer;
		ncfg_wire_attrs_t inside;
		ncfg_wire_ifinfo_t peer_info;
		ncfg_buf_t buf;

		link.veth.peer = "veth1";
		ncfg_buf_init(&buf, 0);
		check(ncfg_ops_create_link(&buf, SEQ, "veth0", &link, err, sizeof(err)) &&
		    info_data_of(&buf, &data), "a veth builds");
		memset(&peer, 0, sizeof(peer));
		check(find(&data, VETH_INFO_PEER, &peer) &&
		    peer.length > NCFG_WIRE_IFINFO_LEN,
		    "with the peer's whole definition rather than just its name");
		/* An `ifinfomsg` and then the peer's own attributes: veth is the one
		 * link type created two at a time, and this is why its encoding
		 * looks unlike every other kind's. */
		check(ncfg_wire_ifinfo_decode(peer.value, peer.length, &peer_info, NULL, 0) &&
		    peer_info.index == 0 && peer_info.family == 0,
		    "an ifinfomsg first, zeroed -- the kernel is making this end too");
		if (peer.length > NCFG_WIRE_IFINFO_LEN) {
			ncfg_wire_attrs_start(&inside, peer.value + NCFG_WIRE_IFINFO_LEN,
			    peer.length - NCFG_WIRE_IFINFO_LEN);
		} else {
			ncfg_wire_attrs_start(&inside, NULL, 0);
		}
		check(str_is(&inside, IFLA_IFNAME, "veth1"),
		    "and the other end's name in an IFNAME after it");
		/*
		 * Plain, not flagged. `NLA_F_NESTED` says "this value is a list of
		 * attributes" and this value is a struct with a list after it --
		 * `veth_policy` gives it a minimum length rather than `NLA_NESTED`
		 * for the same reason.
		 */
		{
			ncfg_wire_attrs_t info;
			ncfg_wire_attr_t attr;

			check(linkinfo_of(&buf, &info) && find(&info, IFLA_INFO_DATA, &attr) &&
			    nested_bit(attr.value, attr.length, VETH_INFO_PEER) == 0,
			    "the peer is not flagged as a nest, because it is not one");
		}
		ncfg_buf_free(&buf);
	}

	/* ---------------------------------------------------------------- *
	 * Bond, VRF and macvlan
	 * ---------------------------------------------------------------- */
	{
		ncfg_ops_newlink_t link = link_of(NCFG_OPS_LINK_BOND);
		ncfg_wire_attrs_t data;
		ncfg_wire_attrs_t outer;
		ncfg_buf_t buf;

		link.bond.mode = 4;
		link.bond.miimon = some(100);
		ncfg_buf_init(&buf, 0);
		check(ncfg_ops_create_link(&buf, SEQ, "bond0", &link, err, sizeof(err)) &&
		    info_data_of(&buf, &data) && u8_of(&data, IFLA_BOND_MODE) == 4u &&
		    u32_of(&data, IFLA_BOND_MIIMON) == 100u,
		    "a bond carries its mode as a byte and its miimon as a word");
		ncfg_buf_free(&buf);

		link.bond.miimon = absent;
		ncfg_buf_init(&buf, 0);
		check(ncfg_ops_create_link(&buf, SEQ, "bond0", &link, err, sizeof(err)) &&
		    info_data_of(&buf, &data) && absent_attr(&data, IFLA_BOND_MIIMON),
		    "and an absent miimon is an attribute that is not sent, not a zero");
		ncfg_buf_free(&buf);

		link = link_of(NCFG_OPS_LINK_VRF);
		link.vrf.table = 100;
		ncfg_buf_init(&buf, 0);
		check(ncfg_ops_create_link(&buf, SEQ, "vrf-blue", &link, err, sizeof(err)) &&
		    info_data_of(&buf, &data) && u32_of(&data, IFLA_VRF_TABLE) == 100u,
		    "a VRF carries the table its members' routes go into");
		ncfg_buf_free(&buf);

		link = link_of(NCFG_OPS_LINK_MACVLAN);
		link.macvlan.parent = 7;
		link.macvlan.mode = 4;
		ncfg_buf_init(&buf, 0);
		check(ncfg_ops_create_link(&buf, SEQ, "mv0", &link, err, sizeof(err)) &&
		    info_data_of(&buf, &data) && u32_of(&data, IFLA_MACVLAN_MODE) == 4u &&
		    area_of(&buf, NCFG_WIRE_IFINFO_LEN, &outer) &&
		    u32_of(&outer, IFLA_LINK) == 7u,
		    "a macvlan takes its mode in the nest and its parent outside, like a VLAN");
		ncfg_buf_free(&buf);
	}

	/* ---------------------------------------------------------------- *
	 * Tunnels: three families that do not share numbering
	 *
	 * The numbers below are written out rather than named, and this is the
	 * first of the two places that is deliberate. GRE puts its flags and
	 * keys at 2..5 and its endpoints at 6 and 7, where an ip tunnel has the
	 * endpoints at 2 and 3. Assuming they agreed is how the first version of
	 * this failed -- the local address landed in `IFLA_GRE_IFLAGS` and the
	 * kernel answered `EINVAL` -- and a case that named the constants would
	 * pass with the two swapped in the code and in the case.
	 * ---------------------------------------------------------------- */
	{
		ncfg_ops_newlink_t link = link_of(NCFG_OPS_LINK_TUNNEL);
		ncfg_wire_attrs_t data;
		ncfg_buf_t buf;
		char word[32];

		link.tunnel.kind = "gre";
		link.tunnel.parent = some(7);
		link.tunnel.local = parse_ip("192.0.2.1");
		link.tunnel.remote = parse_ip("198.51.100.1");
		link.tunnel.ttl = some(64);
		link.tunnel.key = some(0x2a);

		ncfg_buf_init(&buf, 0);
		check(ncfg_ops_create_link(&buf, SEQ, "gre0", &link, err, sizeof(err)) &&
		    info_data_of(&buf, &data) &&
		    strcmp(kind_word_of(&buf, word, sizeof(word)), "gre") == 0,
		    "a GRE tunnel builds under its own kind word");
		check(u32_of(&data, 1) == 7u, "GRE's underlay is attribute 1, in the nest");
		check(ip_is(&data, 6, "192.0.2.1") && ip_is(&data, 7, "198.51.100.1"),
		    "its endpoints are 6 and 7, not the 2 and 3 an ip tunnel uses");
		/* A key with no flag bit is ignored, and two ends with different
		 * keys would then pass traffic as though neither had one -- which is
		 * worse than an error. The flag is `GRE_KEY`, big-endian. */
		check(be16_is(&data, 2, 0x2000u) && be16_is(&data, 3, 0x2000u),
		    "a key comes with the flag that says it is there, in both directions");
		check(be32_is(&data, 4, 0x2au) && be32_is(&data, 5, 0x2au),
		    "and the key itself is big-endian in IKEY and OKEY");
		check(u8_of(&data, 8) == 64u, "the TTL is attribute 8");
		ncfg_buf_free(&buf);

		link.tunnel.key = absent;
		ncfg_buf_init(&buf, 0);
		check(ncfg_ops_create_link(&buf, SEQ, "gre0", &link, err, sizeof(err)) &&
		    info_data_of(&buf, &data) && absent_attr(&data, 2) &&
		    absent_attr(&data, 4),
		    "with no key, neither the flags nor the key are sent");
		ncfg_buf_free(&buf);

		/* `kind.contains("gre")` in the Rust, so `gretap` and `ip6gre` take
		 * the GRE numbering too. */
		link.tunnel.kind = "ip6gre";
		link.tunnel.local = parse_ip("2001:db8::1");
		link.tunnel.remote = parse_ip("2001:db8::2");
		ncfg_buf_init(&buf, 0);
		check(ncfg_ops_create_link(&buf, SEQ, "gt0", &link, err, sizeof(err)) &&
		    info_data_of(&buf, &data) && ip_is(&data, 6, "2001:db8::1") &&
		    ip_is(&data, 7, "2001:db8::2"),
		    "ip6gre is a GRE for numbering, which is what `contains` means");
		ncfg_buf_free(&buf);

		link.tunnel.kind = "ipip";
		link.tunnel.local = parse_ip("192.0.2.1");
		link.tunnel.remote = parse_ip("198.51.100.1");
		ncfg_buf_init(&buf, 0);
		check(ncfg_ops_create_link(&buf, SEQ, "ipip0", &link, err, sizeof(err)) &&
		    info_data_of(&buf, &data), "an ip tunnel builds");
		check(u32_of(&data, 1) == 7u && ip_is(&data, 2, "192.0.2.1") &&
		    ip_is(&data, 3, "198.51.100.1") && u8_of(&data, 4) == 64u,
		    "and its underlay, endpoints and TTL are 1, 2, 3 and 4");
		ncfg_buf_free(&buf);

		/*
		 * geneve, and the second place a number is written out.
		 *
		 * The enum runs UNSPEC, ID, REMOTE, TTL, TOS, so the TTL is 3 and
		 * the TOS is 4. netcfgd sent 4 and the reader read 4, so a geneve
		 * tunnel's `ttl` was written into the outer DSCP, the read-back
		 * agreed with it, and the plan converged silently -- `ip -d link
		 * show` reporting `tos 0x40` with no ttl at all. Two wrong halves
		 * round-tripping is a state no comparison in this codebase can see,
		 * so the case pins the number and the absence of the one beside it.
		 */
		link = link_of(NCFG_OPS_LINK_TUNNEL);
		link.tunnel.kind = "geneve";
		link.tunnel.remote = parse_ip("198.51.100.5");
		link.tunnel.ttl = some(64);
		link.tunnel.key = some(4711);
		ncfg_buf_init(&buf, 0);
		check(ncfg_ops_create_link(&buf, SEQ, "gnv0", &link, err, sizeof(err)) &&
		    info_data_of(&buf, &data), "a geneve tunnel builds");
		check(u32_of(&data, 1) == 4711u,
		    "its VNI is the tunnel key, because the model has no separate field");
		check(ip_is(&data, 2, "198.51.100.5"), "a v4 remote is attribute 2");
		check(u8_of(&data, 3) == 64u, "the TTL is attribute 3");
		check(absent_attr(&data, 4),
		    "and attribute 4 -- the outer DSCP -- is not written at all");
		ncfg_buf_free(&buf);

		link.tunnel.remote = parse_ip("2001:db8::5");
		ncfg_buf_init(&buf, 0);
		check(ncfg_ops_create_link(&buf, SEQ, "gnv0", &link, err, sizeof(err)) &&
		    info_data_of(&buf, &data) && ip_is(&data, 7, "2001:db8::5") &&
		    absent_attr(&data, 2),
		    "a v6 remote is attribute 7, which is what pins the numbering");
		ncfg_buf_free(&buf);

		/* Left out on a change: the kernel refuses a VNI that differs and
		 * refuses it as the whole message, which would take the remote
		 * beside it down too. */
		ncfg_buf_init(&buf, 0);
		check(ncfg_ops_set_link_kind(&buf, SEQ, 4, &link, err, sizeof(err)) &&
		    info_data_of(&buf, &data) && absent_attr(&data, 1) &&
		    ip_is(&data, 7, "2001:db8::5"),
		    "and a change leaves the VNI out while still correcting the remote");
		ncfg_buf_free(&buf);
	}

	/* ---------------------------------------------------------------- *
	 * Link attributes that are not a kind
	 * ---------------------------------------------------------------- */
	{
		ncfg_wire_ifinfo_t body;
		ncfg_wire_attrs_t area;
		ncfg_wire_attr_t attr;
		ncfg_buf_t buf;
		static const uint8_t mac[6] = { 0xde, 0xad, 0xbe, 0xef, 0x00, 0x01 };

		ncfg_buf_init(&buf, 0);
		check(ncfg_ops_set_link_up(&buf, SEQ, 3, 1, err, sizeof(err)) &&
		    ifinfo_of(&buf, &body) && body.index == 3 &&
		    (body.flags & TEST_IFF_UP) == TEST_IFF_UP,
		    "bringing a link up sets IFF_UP in the flags");
		/* `change` is the mask of which flag bits this message sets.
		 * Omitting it is how a request to bring one interface up silently
		 * clears every other flag on it. */
		check(body.change == TEST_IFF_UP,
		    "and sets `change` to that bit alone, never to zero");
		ncfg_buf_free(&buf);

		ncfg_buf_init(&buf, 0);
		check(ncfg_ops_set_link_up(&buf, SEQ, 3, 0, err, sizeof(err)) &&
		    ifinfo_of(&buf, &body) && (body.flags & TEST_IFF_UP) == 0 &&
		    body.change == TEST_IFF_UP,
		    "bringing one down clears the flag and keeps the same mask");
		ncfg_buf_free(&buf);

		ncfg_buf_init(&buf, 0);
		check(ncfg_ops_set_link_mtu(&buf, SEQ, 3, 9000, err, sizeof(err)) &&
		    area_of(&buf, NCFG_WIRE_IFINFO_LEN, &area) &&
		    u32_of(&area, IFLA_MTU) == 9000u && ifinfo_of(&buf, &body) &&
		    body.change == 0,
		    "an MTU goes in IFLA_MTU, with a change mask of nothing");
		ncfg_buf_free(&buf);

		ncfg_buf_init(&buf, 0);
		check(ncfg_ops_set_link_mac(&buf, SEQ, 3, mac, err, sizeof(err)) &&
		    area_of(&buf, NCFG_WIRE_IFINFO_LEN, &area) &&
		    find(&area, IFLA_ADDRESS, &attr) && attr.length == 6u &&
		    memcmp(attr.value, mac, 6) == 0,
		    "a hardware address goes out as six raw octets");
		ncfg_buf_free(&buf);

		ncfg_buf_init(&buf, 0);
		check(ncfg_ops_set_link_master(&buf, SEQ, 3, 9, err, sizeof(err)) &&
		    area_of(&buf, NCFG_WIRE_IFINFO_LEN, &area) &&
		    u32_of(&area, IFLA_MASTER) == 9u, "enslaving names the master's index");
		ncfg_buf_free(&buf);

		ncfg_buf_init(&buf, 0);
		check(ncfg_ops_set_link_master(&buf, SEQ, 3, 0, err, sizeof(err)) &&
		    area_of(&buf, NCFG_WIRE_IFINFO_LEN, &area) &&
		    u32_of(&area, IFLA_MASTER) == 0u,
		    "and releasing is the same message with zero, which is how netlink spells it");
		ncfg_buf_free(&buf);
	}

	/* ---------------------------------------------------------------- *
	 * The alternative name, which is the ownership mark for a link
	 * ---------------------------------------------------------------- */
	{
		ncfg_wire_attrs_t area;
		ncfg_wire_attrs_t props;
		ncfg_buf_t buf;
		char long_name[NCFG_WIRE_ALT_IFNAME_MAX + 1];

		ncfg_buf_init(&buf, 0);
		check(ncfg_ops_add_altname(&buf, SEQ, 3, "ncfg:eth0", err, sizeof(err)) &&
		    area_of(&buf, NCFG_WIRE_IFINFO_LEN, &area) &&
		    nest_of(&area, IFLA_PROP_LIST, &props) &&
		    str_is(&props, IFLA_ALT_IFNAME, "ncfg:eth0"),
		    "an alternative name goes in an ALT_IFNAME inside a PROP_LIST");
		/*
		 * `RTM_NEWLINKPROP` is a newer message type and is parsed strictly:
		 * it rejects a nest without `NLA_F_NESTED` with `EINVAL`, and the
		 * error says nothing about nesting. This is the message netcfgd met
		 * that on, after years of sending unflagged nests that worked.
		 */
		{
			size_t length = 0;
			const uint8_t *tail = tail_of(&buf, NCFG_WIRE_IFINFO_LEN, &length);

			check(tail && nested_bit(tail, length, IFLA_PROP_LIST) == 1,
			    "and the nest carries NLA_F_NESTED, which this type requires");
		}
		ncfg_buf_free(&buf);

		ncfg_buf_init(&buf, 0);
		check(!ncfg_ops_add_altname(&buf, SEQ, 3, "", err, sizeof(err)),
		    "an empty alternative name is refused");
		ncfg_buf_free(&buf);

		memset(long_name, 'a', sizeof(long_name) - 1u);
		long_name[sizeof(long_name) - 1u] = '\0';
		ncfg_buf_init(&buf, 0);
		check(!ncfg_ops_add_altname(&buf, SEQ, 3, long_name, err, sizeof(err)),
		    "and one at ALTIFNAMSIZ is refused rather than truncated");
		ncfg_buf_free(&buf);

		long_name[NCFG_WIRE_ALT_IFNAME_MAX - 1u] = '\0';
		ncfg_buf_init(&buf, 0);
		check(ncfg_ops_add_altname(&buf, SEQ, 3, long_name, err, sizeof(err)),
		    "while one byte shorter is accepted: the NUL is the difference");
		ncfg_buf_free(&buf);
	}

	/* ---------------------------------------------------------------- *
	 * Bridge attributes, a bond's, and a bridge VLAN
	 * ---------------------------------------------------------------- */
	{
		ncfg_ops_bridge_attrs_t attrs;
		ncfg_ops_vlan_change_t vlan;
		ncfg_wire_attrs_t data;
		ncfg_wire_attrs_t area;
		ncfg_wire_attrs_t spec;
		ncfg_wire_attr_t attr;
		ncfg_wire_ifinfo_t body;
		ncfg_buf_t buf;
		char word[32];

		memset(&attrs, 0, sizeof(attrs));
		attrs.stp = 1;
		attrs.forward_delay = some(4);
		attrs.hello_time = some(2);
		attrs.ageing_time = some(300);
		attrs.priority = some(4096);
		attrs.vlan_filtering = 1;

		ncfg_buf_init(&buf, 0);
		check(ncfg_ops_set_bridge_attrs(&buf, SEQ, 5, &attrs, err, sizeof(err)) &&
		    info_data_of(&buf, &data) &&
		    strcmp(kind_word_of(&buf, word, sizeof(word)), "bridge") == 0,
		    "a bridge's attributes go inside a bridge INFO_DATA");
		/* The kernel counts these in hundredths of a second and the config
		 * counts them in seconds, because that is what every other tool
		 * uses. Ageing time is the same unit, which is easy to miss since it
		 * is the one measured in minutes by habit. */
		check(u32_of(&data, IFLA_BR_FORWARD_DELAY) == 400u &&
		    u32_of(&data, IFLA_BR_HELLO_TIME) == 200u &&
		    u32_of(&data, IFLA_BR_AGEING_TIME) == 30000u,
		    "with the three timers converted from seconds to hundredths");
		check(u32_of(&data, IFLA_BR_STP_STATE) == 1u &&
		    u8_of(&data, IFLA_BR_VLAN_FILTERING) == 1u,
		    "spanning tree as a word and VLAN filtering as a byte");
		check(u16_of(&data, IFLA_BR_PRIORITY) == 4096u,
		    "and the priority as a native u16, which is a number rather than a field");
		ncfg_buf_free(&buf);

		memset(&attrs, 0, sizeof(attrs));
		ncfg_buf_init(&buf, 0);
		check(ncfg_ops_set_bridge_attrs(&buf, SEQ, 5, &attrs, err, sizeof(err)) &&
		    info_data_of(&buf, &data) && absent_attr(&data, IFLA_BR_FORWARD_DELAY) &&
		    u32_of(&data, IFLA_BR_STP_STATE) == 0u,
		    "an absent timer is not sent, while the two flags always are");
		ncfg_buf_free(&buf);

		ncfg_buf_init(&buf, 0);
		check(ncfg_ops_set_bond_attrs(&buf, SEQ, 6, some(1), some(100), err,
		    sizeof(err)) && info_data_of(&buf, &data) &&
		    u8_of(&data, IFLA_BOND_MODE) == 1u &&
		    u32_of(&data, IFLA_BOND_MIIMON) == 100u &&
		    strcmp(kind_word_of(&buf, word, sizeof(word)), "bond") == 0,
		    "a bond takes both on a device that exists");
		ncfg_buf_free(&buf);

		/* The kernel takes a mode only on a bond with no members and rejects
		 * the whole message otherwise -- monitoring interval included -- so
		 * the caller can leave the mode out and still move the interval. */
		ncfg_buf_init(&buf, 0);
		check(ncfg_ops_set_bond_attrs(&buf, SEQ, 6, absent, some(100), err,
		    sizeof(err)) && info_data_of(&buf, &data) &&
		    absent_attr(&data, IFLA_BOND_MODE) &&
		    u32_of(&data, IFLA_BOND_MIIMON) == 100u,
		    "and an absent mode leaves the interval sendable on its own");
		ncfg_buf_free(&buf);

		memset(&vlan, 0, sizeof(vlan));
		vlan.vid = 10;
		vlan.pvid = 1;
		vlan.untagged = 1;
		vlan.on_self = 0;
		vlan.add = 1;
		ncfg_buf_init(&buf, 0);
		check(ncfg_ops_set_bridge_vlan(&buf, SEQ, 7, &vlan, err, sizeof(err)) &&
		    header_is(&buf, RTM_SETLINK, (uint16_t)(NLM_F_REQUEST | NLM_F_ACK)),
		    "adding a VLAN to a bridge port is a SETLINK");
		check(ifinfo_of(&buf, &body) && body.family == AF_BRIDGE,
		    "in the bridge address family");
		check(area_of(&buf, NCFG_WIRE_IFINFO_LEN, &area) &&
		    nest_of(&area, IFLA_AF_SPEC, &spec) &&
		    u16_of(&spec, IFLA_BRIDGE_FLAGS) == BRIDGE_FLAGS_MASTER,
		    "a VLAN on a PORT is a MASTER operation: the bridge is being told");
		/* `struct bridge_vlan_info { __u16 flags; __u16 vid; }`, in that
		 * order. Two little integers, and swapping them produces a request
		 * for VLAN 0 with nonsense flags that the kernel may well accept. */
		check(find(&spec, IFLA_BRIDGE_VLAN_INFO, &attr) && attr.length == 4u,
		    "and the VLAN info is four bytes: flags, then the id");
		{
			uint16_t flags = 0;
			uint16_t vid = 0;

			memcpy(&flags, attr.value, sizeof(flags));
			memcpy(&vid, attr.value + sizeof(flags), sizeof(vid));
			check(vid == 10u, "the id is the SECOND of the two, not the first");
			check((flags & BRIDGE_VLAN_INFO_PVID) != 0 &&
			    (flags & BRIDGE_VLAN_INFO_UNTAGGED) != 0,
			    "and the flags are the first, with pvid and untagged set");
		}
		ncfg_buf_free(&buf);

		vlan.on_self = 1;
		vlan.add = 0;
		vlan.pvid = 0;
		vlan.untagged = 0;
		ncfg_buf_init(&buf, 0);
		check(ncfg_ops_set_bridge_vlan(&buf, SEQ, 7, &vlan, err, sizeof(err)) &&
		    header_is(&buf, RTM_DELLINK, (uint16_t)(NLM_F_REQUEST | NLM_F_ACK)) &&
		    area_of(&buf, NCFG_WIRE_IFINFO_LEN, &area) &&
		    nest_of(&area, IFLA_AF_SPEC, &spec) &&
		    u16_of(&spec, IFLA_BRIDGE_FLAGS) == BRIDGE_FLAGS_SELF,
		    "removing one from the bridge DEVICE is a DELLINK, and SELF");
		{
			uint16_t flags = 0xffffu;

			check(find(&spec, IFLA_BRIDGE_VLAN_INFO, &attr) &&
			    (memcpy(&flags, attr.value, sizeof(flags)), flags == 0),
			    "with neither pvid nor untagged asked for");
		}
		ncfg_buf_free(&buf);
	}

	/* ---------------------------------------------------------------- *
	 * The IPv6 token, whose nest is keyed by a family number
	 * ---------------------------------------------------------------- */
	{
		ncfg_wire_ip_t token = parse_ip("::5");
		ncfg_wire_ip_t four = parse_ip("192.0.2.5");
		ncfg_wire_attrs_t area;
		ncfg_wire_attrs_t spec;
		ncfg_wire_attrs_t inet6;
		ncfg_buf_t buf;

		ncfg_buf_init(&buf, 0);
		check(ncfg_ops_set_ipv6_token(&buf, SEQ, 3, &token, err, sizeof(err)) &&
		    header_is(&buf, RTM_SETLINK, (uint16_t)(NLM_F_REQUEST | NLM_F_ACK)),
		    "a token is a SETLINK");
		/* The family is the attribute *type* here, not a field: `IFLA_AF_SPEC`
		 * holds one nest per address family, keyed by the family number. */
		check(area_of(&buf, NCFG_WIRE_IFINFO_LEN, &area) &&
		    nest_of(&area, IFLA_AF_SPEC, &spec) &&
		    nest_of(&spec, AF_INET6, &inet6) &&
		    ip_is(&inet6, IFLA_INET6_TOKEN, "::5"),
		    "inside a nest whose TYPE is the address family");
		ncfg_buf_free(&buf);

		/*
		 * The Rust takes any `IpAddr` here and would send four bytes, which
		 * `inet6_af_policy` refuses with the same bare `EINVAL` as the five
		 * other reasons a token is refused -- so the operator is told their
		 * device is not ready when what happened is that somebody wrote an
		 * IPv4 address.
		 */
		ncfg_buf_init(&buf, 0);
		check(!ncfg_ops_set_ipv6_token(&buf, SEQ, 3, &four, err, sizeof(err)),
		    "and an IPv4 token is refused here, where the sentence can say which");
		ncfg_buf_free(&buf);
	}

	/* ---------------------------------------------------------------- *
	 * Addresses
	 * ---------------------------------------------------------------- */
	{
		ncfg_wire_ip_t address = parse_ip("192.0.2.10");
		ncfg_wire_ip_t six = parse_ip("2001:db8::1");
		ncfg_wire_ifaddr_t body;
		ncfg_wire_attrs_t area;
		ncfg_buf_t buf;

		ncfg_buf_init(&buf, 0);
		check(ncfg_ops_add_address(&buf, SEQ, 3, &address, 24,
		    NCFG_WIRE_RTPROT_NETCFGD, err, sizeof(err)) &&
		    ifaddr_of(&buf, &body) && body.family == AF_INET &&
		    body.prefix_len == 24u && body.index == 3u && body.flags == 0 &&
		    body.scope == 0, "an address carries its family, prefix and index");
		/* `IFA_LOCAL` is this host's address. `IFA_ADDRESS` must be sent too,
		 * and for anything but a point-to-point link it is the same value --
		 * sending only one produces an address the kernel will not accept. */
		check(area_of(&buf, NCFG_WIRE_IFADDR_LEN, &area) &&
		    ip_is(&area, IFA_LOCAL, "192.0.2.10") &&
		    ip_is(&area, IFA_ADDRESS, "192.0.2.10"),
		    "and goes out as both IFA_LOCAL and IFA_ADDRESS");
		check(u8_of(&area, IFA_PROTO) == NCFG_WIRE_RTPROT_NETCFGD,
		    "stamped with netcfgd's protocol, which is what makes it ours");
		ncfg_buf_free(&buf);

		ncfg_buf_init(&buf, 0);
		check(ncfg_ops_del_address(&buf, SEQ, 3, &six, 64, err, sizeof(err)) &&
		    ifaddr_of(&buf, &body) && body.family == AF_INET6 &&
		    body.prefix_len == 64u &&
		    area_of(&buf, NCFG_WIRE_IFADDR_LEN, &area) &&
		    ip_is(&area, IFA_LOCAL, "2001:db8::1") &&
		    absent_attr(&area, IFA_PROTO),
		    "a removal names the address and sends no protocol, which is not matched on");
		ncfg_buf_free(&buf);

		ncfg_buf_init(&buf, 0);
		check(!ncfg_ops_add_address(&buf, SEQ, 3, &no_ip, 24, 0, err, sizeof(err)),
		    "an absent address is refused rather than encoded as four zero bytes");
		ncfg_buf_free(&buf);
	}

	/* ---------------------------------------------------------------- *
	 * Routes
	 * ---------------------------------------------------------------- */
	{
		ncfg_ops_route_t route;
		ncfg_wire_rtmsg_t body;
		ncfg_wire_attrs_t area;
		ncfg_buf_t buf;

		memset(&route, 0, sizeof(route));
		route.index = 3;
		route.destination = no_ip;
		route.gateway = parse_ip("192.0.2.1");
		route.source = no_ip;

		ncfg_buf_init(&buf, 0);
		check(ncfg_ops_add_route(&buf, SEQ, &route, err, sizeof(err)) &&
		    rtmsg_of(&buf, &body), "a default route builds");
		check(body.family == AF_INET && body.dst_len == 0 &&
		    body.kind == RTN_UNICAST,
		    "with the family of its gateway, no destination length, and unicast");
		/* A route with a gateway reaches beyond the link; one without is on
		 * the link itself, and the kernel rejects that at universe scope. */
		check(body.scope == RT_SCOPE_UNIVERSE,
		    "a route with a gateway is at universe scope");
		check(body.table == NCFG_ROUTE_MAIN_TABLE,
		    "an unqualified route goes in the main table");
		check(area_of(&buf, NCFG_WIRE_RTMSG_LEN, &area) &&
		    absent_attr(&area, RTA_DST) && ip_is(&area, RTA_GATEWAY, "192.0.2.1") &&
		    u32_of(&area, RTA_OIF) == 3u && absent_attr(&area, RTA_TABLE),
		    "no RTA_DST, a gateway, an output interface and no table attribute");
		ncfg_buf_free(&buf);

		/* A length with no prefix beside it is not a default route, it is
		 * `0.0.0.0/24` -- so the one goes with the other or not at all. */
		route.dst_len = 24;
		ncfg_buf_init(&buf, 0);
		check(ncfg_ops_add_route(&buf, SEQ, &route, err, sizeof(err)) &&
		    rtmsg_of(&buf, &body) && body.dst_len == 0,
		    "a prefix length with no destination beside it is not sent");
		ncfg_buf_free(&buf);

		route.gateway = no_ip;
		route.destination = parse_ip("198.51.100.0");
		route.dst_len = 24;
		ncfg_buf_init(&buf, 0);
		check(ncfg_ops_add_route(&buf, SEQ, &route, err, sizeof(err)) &&
		    rtmsg_of(&buf, &body) && body.scope == RT_SCOPE_LINK &&
		    body.dst_len == 24u && area_of(&buf, NCFG_WIRE_RTMSG_LEN, &area) &&
		    ip_is(&area, RTA_DST, "198.51.100.0"),
		    "a route with no gateway is on the link, and the kernel needs it said");
		ncfg_buf_free(&buf);

		route.onlink = 1;
		route.gateway = parse_ip("192.0.2.1");
		route.metric = some(500);
		route.source = parse_ip("192.0.2.10");
		ncfg_buf_init(&buf, 0);
		check(ncfg_ops_add_route(&buf, SEQ, &route, err, sizeof(err)) &&
		    rtmsg_of(&buf, &body) && (body.flags & RTNH_F_ONLINK) != 0,
		    "an on-link next hop sets RTNH_F_ONLINK in the header");
		check(area_of(&buf, NCFG_WIRE_RTMSG_LEN, &area) &&
		    u32_of(&area, RTA_PRIORITY) == 500u &&
		    ip_is(&area, RTA_PREFSRC, "192.0.2.10"),
		    "with the metric in RTA_PRIORITY and the source in RTA_PREFSRC");
		ncfg_buf_free(&buf);

		/* A table id above 255 does not fit `rtm_table` and goes in
		 * `RTA_TABLE` instead, with the byte set to unspec so the kernel
		 * knows to look. Truncating would send table 1000 as table 232 --
		 * which is a real table, belonging to somebody else. */
		route.table = some(1000);
		ncfg_buf_init(&buf, 0);
		check(ncfg_ops_add_route(&buf, SEQ, &route, err, sizeof(err)) &&
		    rtmsg_of(&buf, &body) && body.table == 0 &&
		    area_of(&buf, NCFG_WIRE_RTMSG_LEN, &area) &&
		    u32_of(&area, RTA_TABLE) == 1000u,
		    "a table above 255 travels in RTA_TABLE with the byte unspecified");
		ncfg_buf_free(&buf);

		route.table = some(100);
		ncfg_buf_init(&buf, 0);
		check(ncfg_ops_add_route(&buf, SEQ, &route, err, sizeof(err)) &&
		    rtmsg_of(&buf, &body) && body.table == 100u &&
		    area_of(&buf, NCFG_WIRE_RTMSG_LEN, &area) &&
		    absent_attr(&area, RTA_TABLE),
		    "and one that fits stays in the byte, with no attribute beside it");
		ncfg_buf_free(&buf);

		memset(&route, 0, sizeof(route));
		route.index = 3;
		route.destination = parse_ip("2001:db8::");
		route.dst_len = 32;
		route.gateway = no_ip;
		route.source = no_ip;
		ncfg_buf_init(&buf, 0);
		check(ncfg_ops_add_route(&buf, SEQ, &route, err, sizeof(err)) &&
		    rtmsg_of(&buf, &body) && body.family == AF_INET6,
		    "an IPv6 destination gives the message its family");
		ncfg_buf_free(&buf);

		memset(&route, 0, sizeof(route));
		route.index = 3;
		route.destination = no_ip;
		route.gateway = no_ip;
		route.source = no_ip;
		ncfg_buf_init(&buf, 0);
		check(ncfg_ops_add_route(&buf, SEQ, &route, err, sizeof(err)) &&
		    rtmsg_of(&buf, &body) && body.family == AF_INET,
		    "and a route with neither falls back to AF_INET, as the Rust's bare 2 does");
		ncfg_buf_free(&buf);
	}

	/* ---------------------------------------------------------------- *
	 * THE OWNERSHIP MARK
	 *
	 * Decision 0002. Every route netcfgd installs carries `rtm_protocol`
	 * 110, and that one byte is the only thing that distinguishes a route
	 * netcfgd put there from one an operator did. Without it reconciliation
	 * has two options and both are wrong: remove theirs, or never remove its
	 * own. The same argument gives an address `IFA_PROTO` and a rule
	 * `FRA_PROTOCOL`, and a link -- which has no protocol field at all -- an
	 * alternative name instead.
	 * ---------------------------------------------------------------- */
	{
		ncfg_ops_route_t route;
		ncfg_ops_rule_t rule;
		ncfg_wire_rtmsg_t body;
		ncfg_wire_attrs_t area;
		ncfg_wire_ip_t address = parse_ip("192.0.2.10");
		ncfg_buf_t buf;

		memset(&route, 0, sizeof(route));
		route.index = 3;
		route.destination = no_ip;
		route.gateway = parse_ip("192.0.2.1");
		route.source = no_ip;

		ncfg_buf_init(&buf, 0);
		check(ncfg_ops_add_route(&buf, SEQ, &route, err, sizeof(err)) &&
		    rtmsg_of(&buf, &body) && body.protocol == NCFG_WIRE_RTPROT_NETCFGD &&
		    body.protocol == 110u,
		    "a route netcfgd builds carries protocol 110 without being asked");
		ncfg_buf_free(&buf);

		ncfg_buf_init(&buf, 0);
		check(ncfg_ops_del_route(&buf, SEQ, &route, err, sizeof(err)) &&
		    rtmsg_of(&buf, &body) && body.protocol == NCFG_WIRE_RTPROT_NETCFGD,
		    "and so does the request that removes one");
		ncfg_buf_free(&buf);

		/* RTPROT_BOOT: a route somebody else's tooling installed. The
		 * document may name a protocol, and a route named with another one
		 * is distinguishable from netcfgd's in the one byte that decides
		 * ownership. */
		route.proto = some(3);
		ncfg_buf_init(&buf, 0);
		check(ncfg_ops_add_route(&buf, SEQ, &route, err, sizeof(err)) &&
		    rtmsg_of(&buf, &body) && body.protocol == 3u &&
		    body.protocol != NCFG_WIRE_RTPROT_NETCFGD,
		    "a route asked for under another protocol is not stamped as netcfgd's");
		ncfg_buf_free(&buf);

		memset(&rule, 0, sizeof(rule));
		rule.family = AF_INET;
		rule.priority = 100;
		rule.table = 100;
		rule.action = FR_ACT_TO_TBL;
		rule.from = no_ip;
		rule.to = no_ip;

		ncfg_buf_init(&buf, 0);
		check(ncfg_ops_add_rule(&buf, SEQ, &rule, err, sizeof(err)) &&
		    area_of(&buf, 12u, &area) &&
		    u8_of(&area, FRA_PROTOCOL) == NCFG_WIRE_RTPROT_NETCFGD,
		    "a rule carries the same mark in FRA_PROTOCOL");
		ncfg_buf_free(&buf);

		/*
		 * The kernel matches a delete against every attribute the request
		 * carries, so a delete asking for 110 cannot match a rule that does
		 * not carry it. Verified on a live kernel rather than assumed: a
		 * rule installed with protocol 0 survives a delete sent with 110,
		 * and goes away when sent with 0.
		 */
		ncfg_buf_init(&buf, 0);
		check(ncfg_ops_del_rule(&buf, SEQ, &rule, err, sizeof(err)) &&
		    area_of(&buf, 12u, &area) &&
		    u8_of(&area, FRA_PROTOCOL) == NCFG_WIRE_RTPROT_NETCFGD,
		    "and the delete carries it too, which is what makes the kernel refuse");

		rule.protocol = some(0);
		ncfg_buf_free(&buf);
		ncfg_buf_init(&buf, 0);
		check(ncfg_ops_del_rule(&buf, SEQ, &rule, err, sizeof(err)) &&
		    area_of(&buf, 12u, &area) && u8_of(&area, FRA_PROTOCOL) == 0u,
		    "a rule netcfgd did not create is asked for by its own protocol, not 110");
		ncfg_buf_free(&buf);

		ncfg_buf_init(&buf, 0);
		check(ncfg_ops_add_address(&buf, SEQ, 3, &address, 24,
		    NCFG_WIRE_RTPROT_NETCFGD, err, sizeof(err)) &&
		    area_of(&buf, NCFG_WIRE_IFADDR_LEN, &area) &&
		    u8_of(&area, IFA_PROTO) == 110u,
		    "and an address carries it in IFA_PROTO, which an old kernel ignores");
		ncfg_buf_free(&buf);
	}

	/* ---------------------------------------------------------------- *
	 * Rules
	 * ---------------------------------------------------------------- */
	{
		ncfg_ops_rule_t rule;
		ncfg_wire_message_t message;
		ncfg_wire_attrs_t area;
		ncfg_buf_t buf;

		memset(&rule, 0, sizeof(rule));
		rule.family = AF_INET6;
		rule.priority = 1000;
		rule.table = 42;
		rule.action = FR_ACT_TO_TBL;
		rule.from = parse_ip("2001:db8::");
		rule.from_len = 32;
		rule.to = no_ip;
		rule.iif = "eth0";
		rule.oif = "eth1";
		rule.fwmark = some(1);
		rule.fwmask = some(0xff);
		rule.l3mdev = 1;
		rule.invert = 1;

		ncfg_buf_init(&buf, 0);
		check(ncfg_ops_add_rule(&buf, SEQ, &rule, err, sizeof(err)) &&
		    message_of(&buf, &message) && message.payload_length >= 12u,
		    "a rule builds with a twelve-byte header");
		/*
		 * `struct fib_rule_hdr` is byte-for-byte the same shape as `rtmsg`
		 * and is deliberately not that type: bytes five, six and seven are
		 * `res1`, `res2` and `action` here against `protocol`, `scope` and
		 * `type` there. Reusing the route header would compile and would put
		 * the action where the kernel reads a route type, which is why the
		 * two reserved bytes are checked to be zero rather than ignored.
		 */
		check(message.payload[0] == AF_INET6, "family in byte 0");
		check(message.payload[1] == 0 && message.payload[2] == 32u,
		    "the `to` prefix in byte 1 and the `from` prefix in byte 2");
		check(message.payload[4] == 42u, "the table in byte 4");
		check(message.payload[5] == 0 && message.payload[6] == 0,
		    "bytes 5 and 6 reserved -- an rtmsg has the protocol and scope there");
		check(message.payload[7] == FR_ACT_TO_TBL,
		    "and the action in byte 7, where an rtmsg has the route type");
		{
			uint32_t flags = 0;

			memcpy(&flags, message.payload + 8, sizeof(flags));
			check((flags & FIB_RULE_INVERT) != 0,
			    "an inverted rule sets FIB_RULE_INVERT in the header flags");
		}
		check(area_of(&buf, 12u, &area) && u32_of(&area, FRA_PRIORITY) == 1000u &&
		    u32_of(&area, FRA_TABLE) == 42u,
		    "the priority and the table are attributes as well as bytes");
		check(ip_is(&area, FRA_SRC, "2001:db8::") && absent_attr(&area, FRA_DST),
		    "a `from` selector is FRA_SRC, and an absent `to` sends no FRA_DST");
		check(str_is(&area, FRA_IIFNAME, "eth0") && str_is(&area, FRA_OIFNAME, "eth1"),
		    "the interface selectors are NUL-terminated names");
		check(u32_of(&area, FRA_FWMARK) == 1u && u32_of(&area, FRA_FWMASK) == 0xffu &&
		    u8_of(&area, FRA_L3MDEV) == 1u,
		    "the mark, its mask and l3mdev are there when asked for");
		check(absent_attr(&area, FRA_SUPPRESS_PREFIXLEN),
		    "and an absent suppressor is absent, not zero");
		ncfg_buf_free(&buf);

		/*
		 * Absent and zero are different answers, and this is the field the
		 * distinction was invented for: `suppress_prefixlength 0` says
		 * "consult this table but skip its default route", so a more
		 * specific rule below can catch it.
		 */
		rule.suppress_prefixlength = some(0);
		ncfg_buf_init(&buf, 0);
		check(ncfg_ops_add_rule(&buf, SEQ, &rule, err, sizeof(err)) &&
		    area_of(&buf, 12u, &area) &&
		    u32_of(&area, FRA_SUPPRESS_PREFIXLEN) == 0u,
		    "while a suppressor of zero is sent, which is the whole `ip rule` trick");
		ncfg_buf_free(&buf);

		memset(&rule, 0, sizeof(rule));
		rule.family = AF_INET;
		rule.priority = 100;
		rule.action = FR_ACT_BLACKHOLE;
		rule.from = no_ip;
		rule.to = no_ip;
		ncfg_buf_init(&buf, 0);
		check(ncfg_ops_add_rule(&buf, SEQ, &rule, err, sizeof(err)) &&
		    message_of(&buf, &message) && message.payload[7] == FR_ACT_BLACKHOLE &&
		    message.payload[4] == 0 && area_of(&buf, 12u, &area) &&
		    absent_attr(&area, FRA_TABLE) && absent_attr(&area, FRA_L3MDEV),
		    "a blackhole rule names no table, so neither byte nor attribute is sent");
		ncfg_buf_free(&buf);

		/* Only a table that fits in a byte goes in the header; anything
		 * larger travels in `FRA_TABLE` and the byte stays unspecified. */
		rule.table = 5000;
		rule.action = FR_ACT_TO_TBL;
		ncfg_buf_init(&buf, 0);
		check(ncfg_ops_add_rule(&buf, SEQ, &rule, err, sizeof(err)) &&
		    message_of(&buf, &message) && message.payload[4] == 0 &&
		    area_of(&buf, 12u, &area) && u32_of(&area, FRA_TABLE) == 5000u,
		    "a rule's table above 255 is unspecified in the byte and whole in FRA_TABLE");
		ncfg_buf_free(&buf);
	}

	/* ---------------------------------------------------------------- *
	 * What is refused
	 *
	 * Everything the Rust refuses, and the narrowings C has to do that Rust
	 * did in its type system. A refusal is a sentence, and the sentence is
	 * checked to be non-empty: a failure with nothing said is the one that
	 * costs an operator an afternoon.
	 * ---------------------------------------------------------------- */
	{
		ncfg_ops_newlink_t link;
		ncfg_ops_route_t route;
		ncfg_ops_bridge_attrs_t attrs;
		ncfg_buf_t buf;
		int said = 1;

		memset(&route, 0, sizeof(route));
		route.destination = no_ip;
		route.gateway = no_ip;
		route.source = no_ip;

#define REFUSED(call, what)                                                      \
	do {                                                                     \
		err[0] = '\0';                                                   \
		ncfg_buf_init(&buf, 0);                                          \
		check(!(call), what);                                            \
		if (err[0] == '\0') {                                            \
			said = 0;                                                \
		}                                                                \
		ncfg_buf_free(&buf);                                             \
	} while (0)

		link = link_of(NCFG_OPS_LINK_VXLAN);
		link.vxlan.port = some(70000);
		REFUSED(ncfg_ops_create_link(&buf, SEQ, "vx0", &link, err, sizeof(err)),
		    "a VXLAN port that does not fit sixteen bits is refused, not truncated");

		link = link_of(NCFG_OPS_LINK_TUNNEL);
		link.tunnel.kind = "geneve";
		link.tunnel.parent = some(7);
		REFUSED(ncfg_ops_create_link(&buf, SEQ, "gnv0", &link, err, sizeof(err)),
		    "a geneve tunnel with a parent is refused: its family has no such field");

		link = link_of(NCFG_OPS_LINK_TUNNEL);
		link.tunnel.kind = "ipip";
		link.tunnel.ttl = some(256);
		REFUSED(ncfg_ops_create_link(&buf, SEQ, "t0", &link, err, sizeof(err)),
		    "a TTL of 256 is refused rather than sent as zero");

		link = link_of(NCFG_OPS_LINK_TUNNEL);
		link.tunnel.kind = NULL;
		REFUSED(ncfg_ops_create_link(&buf, SEQ, "t0", &link, err, sizeof(err)),
		    "a tunnel with no encapsulation named is refused");

		link = link_of(NCFG_OPS_LINK_VETH);
		link.veth.peer = NULL;
		REFUSED(ncfg_ops_create_link(&buf, SEQ, "veth0", &link, err, sizeof(err)),
		    "a veth with no peer named is refused");

		link = link_of(999);
		REFUSED(ncfg_ops_create_link(&buf, SEQ, "x0", &link, err, sizeof(err)),
		    "a kind this build does not know is refused by number, not half made");

		link = link_of(NCFG_OPS_LINK_DUMMY);
		REFUSED(ncfg_ops_create_link(&buf, SEQ, NULL, &link, err, sizeof(err)),
		    "a link with no name is refused, not left for the kernel to name");

		/* `i32::try_from(index).unwrap_or(0)` in the Rust, and zero is not a
		 * refusal on the way in: on a DELLINK it is "unspecified". */
		REFUSED(ncfg_ops_delete_link(&buf, SEQ, 0x80000000u, err, sizeof(err)),
		    "an index that does not fit a signed word is refused, never zeroed");

		memset(&attrs, 0, sizeof(attrs));
		attrs.priority = some(70000);
		REFUSED(ncfg_ops_set_bridge_attrs(&buf, SEQ, 5, &attrs, err, sizeof(err)),
		    "a bridge priority past sixteen bits is refused");

		REFUSED(ncfg_ops_set_bond_attrs(&buf, SEQ, 6, some(300), absent, err,
		    sizeof(err)), "a bond mode past a byte is refused");

		route.table = some(1);
		route.proto = some(256);
		REFUSED(ncfg_ops_add_route(&buf, SEQ, &route, err, sizeof(err)),
		    "a route protocol past a byte is refused, not wrapped to 0");

		route.proto = absent;
		route.table = some((int64_t)1 << 33);
		REFUSED(ncfg_ops_add_route(&buf, SEQ, &route, err, sizeof(err)),
		    "and a table past thirty-two bits with it");

		REFUSED(ncfg_ops_set_ipv6_token(&buf, SEQ, 3, &no_ip, err, sizeof(err)),
		    "a token that is no address at all is refused");
#undef REFUSED

		check(said, "and every one of those refusals came with a sentence");
	}

	/* ---------------------------------------------------------------- *
	 * Hardware addresses
	 * ---------------------------------------------------------------- */
	{
		uint8_t mac[6];
		static const uint8_t want[6] = { 0xde, 0xad, 0xbe, 0xef, 0x00, 0x01 };

		check(ncfg_ops_parse_mac("de:ad:be:ef:00:01", mac, err, sizeof(err)) &&
		    memcmp(mac, want, sizeof(want)) == 0, "a hardware address parses");
		check(ncfg_ops_parse_mac("DE:AD:BE:EF:00:01", mac, err, sizeof(err)) &&
		    memcmp(mac, want, sizeof(want)) == 0, "in either case");
		check(!ncfg_ops_parse_mac("de:ad:be:ef:00", mac, err, sizeof(err)),
		    "five octets are refused");
		check(!ncfg_ops_parse_mac("de:ad:be:ef:00:01:02", mac, err, sizeof(err)),
		    "seven are refused");
		check(!ncfg_ops_parse_mac("de:ad:be:ef:00:zz", mac, err, sizeof(err)),
		    "and a non-hex octet is refused");
		/*
		 * Two the Rust takes and this does not. `u8::from_str_radix` accepts
		 * one digit and accepts a leading `+`, so `+1:2:3:4:5:6` is a
		 * hardware address to it. The configuration language has never
		 * allowed either -- `normalise_address` requires exactly two hex
		 * digits per octet -- so nothing that reaches here legitimately is
		 * lost, and what is gained is that the spelling going to
		 * `IFLA_ADDRESS` is the spelling everything else compares against.
		 */
		check(!ncfg_ops_parse_mac("d:ad:be:ef:00:01", mac, err, sizeof(err)),
		    "a single-digit octet is refused, which the Rust's parser accepts");
		check(!ncfg_ops_parse_mac("+1:ad:be:ef:00:01", mac, err, sizeof(err)),
		    "and so is a signed one, which it also accepts");
		check(!ncfg_ops_parse_mac("de-ad-be-ef-00-01", mac, err, sizeof(err)),
		    "dashes are the editor's leniency and not the kernel's");
	}

	/* ---------------------------------------------------------------- *
	 * The model's address type, converted once
	 * ---------------------------------------------------------------- */
	{
		ncfg_address_t from_model;
		ncfg_wire_ip_t converted;
		ncfg_wire_ip_t direct;

		check(ncfg_address_parse("2001:db8::1/64", &from_model, err, sizeof(err)) &&
		    ncfg_ops_ip_from_address(&from_model, &converted, err, sizeof(err)),
		    "a model address converts to a wire one");
		direct = parse_ip("2001:db8::1");
		check(converted.family == direct.family &&
		    memcmp(converted.bytes, direct.bytes, sizeof(direct.bytes)) == 0,
		    "to exactly the bytes the wire layer would have parsed itself");
		check(ncfg_ops_ip_present(&converted) && !ncfg_ops_ip_present(&no_ip),
		    "and an absent address is one the encoder will not take");
	}

	if (failures == 0) {
		printf("ops_test: all checks passed\n");
	} else {
		printf("ops_test: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
