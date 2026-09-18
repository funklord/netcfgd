/*
 * wg_test.c -- generic netlink and WireGuard, against bytes rather than
 * against a kernel.
 *
 * WHY THIS EXISTS
 *   Everything here runs with no socket, no privileges, no `wireguard` module
 *   and no hardware. That is the property that makes this layer reviewable at
 *   all: the half that can be silently wrong is the encoding -- a nest without
 *   its flag, an attribute numbered one too low, a port written in the host's
 *   byte order -- and none of it needs a kernel to check. The live half of the
 *   Rust's suite (`tests/wg.rs`, `a_tunnel_round_trips_through_the_kernel`)
 *   needs `CAP_NET_ADMIN` and a module, and skips without either; the cases
 *   below are the ones that were never allowed to skip.
 *
 *   Both modules are exercised here rather than in a `genl_test.c` beside it,
 *   because nothing in `genl.h` has a caller of its own yet: what it is for is
 *   resolving `wireguard`, and a test that resolved nothing would be checking
 *   the encoder against itself.
 *
 * WHAT IS ASSERTED, AND HOW
 *   The bytes are walked back with the wire layer rather than compared against
 *   a hand-written blob. A blob pins the encoder to whatever it did on the day
 *   it was written, including its mistakes, and says nothing about what the
 *   kernel would make of it; walking it back says the message is readable and
 *   names which attribute is wrong when it is not.
 *
 *   The one exception is `NLA_F_NESTED`, which the ordinary reader masks off
 *   -- rightly, since it says how to read a value rather than what it is. So
 *   `raw_attrs` below walks the same bytes keeping the type bits intact, and
 *   the nesting is asserted through that.
 *
 * WHY THE HOSTILE BUFFERS ARE MALLOCED TO SIZE
 *   `exact_copy` puts the end of an input at the end of an allocation, so a
 *   read one byte past it is an ASan report rather than a byte of the rest of
 *   the buffer. A short read tested as a prefix of a longer one is not tested.
 *   wire_test.c has the long version of this note.
 */
#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/document.h"
#include "ncfg/genl.h"
#include "ncfg/wg.h"
#include "ncfg/value.h"
#include "ncfg/wire.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;

static void check(int condition, const char *what)
{
	printf("%-66s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

/* A walk that will not run for ever even if the code under test would. The
 * defect this file is partly about does not look like a crash, it looks like a
 * hang in a privileged daemon -- and a test that hangs reports nothing. */
#define WALK_CAP 100000u

/* Enough for any attribute area this file builds by hand. */
#define RAW_MAX 64u

/* `IFNAMSIZ`: the size of a buffer an interface name has to fit. Written out
 * rather than included, for the reason wire.h gives about `ALTIFNAMSIZ` --
 * `linux/if.h` and `net/if.h` redefine each other's structures. */
#define NAME_TEXT 16u

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

/* One attribute with its type bits left alone. See the header comment. */
typedef struct {
	uint16_t       kind;
	const uint8_t *value;
	size_t         length;
} raw_attr_t;

static size_t raw_attrs(const void *bytes, size_t length, raw_attr_t *out, size_t max)
{
	const uint8_t *rest = bytes;
	size_t remaining = bytes ? length : 0;
	size_t seen = 0;

	while (remaining >= 4u && seen < max) {
		uint16_t claimed;
		uint16_t kind;
		size_t advance;

		memcpy(&claimed, rest, sizeof(claimed));
		memcpy(&kind, rest + 2, sizeof(kind));
		if (claimed < 4u || (size_t)claimed > remaining) {
			break;
		}
		out[seen].kind = kind;
		out[seen].value = rest + 4;
		out[seen].length = (size_t)claimed - 4u;
		seen++;
		advance = ncfg_wire_align4(claimed);
		if (advance == 0 || advance > remaining) {
			break;
		}
		rest += advance;
		remaining -= advance;
	}
	return seen;
}

/* The first attribute of a kind, with the nested and byte-order bits masked
 * off for the comparison but present in what comes back. */
static const raw_attr_t *raw_find(const raw_attr_t *attrs, size_t count, uint16_t kind)
{
	size_t index;

	for (index = 0; index < count; index++) {
		if ((attrs[index].kind & 0x3fffu) == kind) {
			return &attrs[index];
		}
	}
	return NULL;
}

/* The one message a buffer holds, or a failure. */
static int one_message(const void *bytes, size_t length, ncfg_wire_message_t *out)
{
	ncfg_wire_messages_t walk;

	ncfg_wire_messages_start(&walk, bytes, length);
	if (ncfg_wire_messages_next(&walk, out, NULL, 0) != NCFG_WIRE_OK) {
		return 0;
	}
	return ncfg_wire_messages_next(&walk, out, NULL, 0) == NCFG_WIRE_END ? 1 : 0;
}

/* ------------------------------------------------------------------------ *
 * The fixture, peer for peer the Rust's `sample()` plus the second peer its
 * removal test adds -- two peers, because one is not enough to see an array.
 * ------------------------------------------------------------------------ */

static char device_name[] = "wg-test";
static char alpha_name[] = "alpha";
static char beta_name[] = "beta";
static char alpha_ip4[] = "10.9.0.0/24";
static char alpha_ip6[] = "fd00::/64";
static char beta_ip4[] = "192.0.2.0/24";
static char *alpha_ips[] = { alpha_ip4, alpha_ip6 };
static char *beta_ips[] = { beta_ip4 };

static void fill_key(unsigned char *out, unsigned seed)
{
	size_t index;

	for (index = 0; index < NCFG_WG_KEY_LEN; index++) {
		out[index] = (unsigned char)((seed + (unsigned)index) & 0xffu);
	}
}

typedef struct {
	ncfg_wireguard_config_t config;
	ncfg_wg_peer_t          peers[2];
	ncfg_wg_peer_material_t material[2];
	ncfg_wg_request_t       request;
	unsigned char           private_key[NCFG_WG_KEY_LEN];
	unsigned char           preshared_key[NCFG_WG_KEY_LEN];
} sample_t;

static int sample(sample_t *out, char *err, size_t err_size)
{
	memset(out, 0, sizeof(*out));
	fill_key(out->private_key, 1);
	fill_key(out->preshared_key, 200);

	out->peers[0].name = alpha_name;
	fill_key(out->peers[0].public_key, 100);
	out->peers[0].allowed_ips = alpha_ips;
	out->peers[0].allowed_ip_count = 2;
	out->peers[0].keepalive.has = 1;
	out->peers[0].keepalive.value = 25;
	out->material[0].preshared_key = out->preshared_key;
	out->material[0].has_endpoint = 1;
	if (!ncfg_wg_endpoint_parse("127.0.0.1:51821", &out->material[0].endpoint,
	    &out->material[0].endpoint_port, err, err_size)) {
		return 0;
	}

	out->peers[1].name = beta_name;
	fill_key(out->peers[1].public_key, 7);
	out->peers[1].allowed_ips = beta_ips;
	out->peers[1].allowed_ip_count = 1;

	out->config.listen_port.has = 1;
	out->config.listen_port.value = 51820;
	out->config.fwmark.has = 1;
	out->config.fwmark.value = 42;
	out->config.peers = out->peers;
	out->config.peer_count = 2;

	out->request.name = device_name;
	out->request.config = &out->config;
	out->request.private_key = out->private_key;
	out->request.material = out->material;
	out->request.replace_peers = 1;
	return 1;
}

/* The family a resolved lookup would have produced, so that the encoders can
 * be exercised without one. */
static void sample_family(ncfg_genl_family_t *family)
{
	memset(family, 0, sizeof(*family));
	memcpy(family->name, "wireguard", sizeof("wireguard"));
	family->id = 27;
}

/* ------------------------------------------------------------------------ *
 * Generic netlink
 * ------------------------------------------------------------------------ */

static void genl_header_cases(void)
{
	ncfg_genl_header_t header;
	ncfg_genl_header_t read;
	ncfg_buf_t out;
	uint8_t *exact;

	header.cmd = CTRL_CMD_GETFAMILY;
	header.version = 1;
	ncfg_buf_init(&out, 0);
	ncfg_genl_header_encode(&header, &out);
	check(!ncfg_buf_failed(&out) && out.length == NCFG_GENL_HDR_LEN,
	    "a generic netlink header is four bytes");
	check(out.length == 4u && (uint8_t)out.data[0] == CTRL_CMD_GETFAMILY
	    && (uint8_t)out.data[1] == 1u && out.data[2] == 0 && out.data[3] == 0,
	    "the command, then the version, then two the kernel ignores");
	check(ncfg_genl_header_decode(out.data, out.length, &read, NULL, 0)
	    && read.cmd == header.cmd && read.version == header.version,
	    "and it reads back as what went in");

	/* A truncated payload is not a header and must not be read as one. The
	 * copy is exact so that a read past the end is a report. */
	exact = exact_copy(out.data, 3);
	check(!ncfg_genl_header_decode(exact, 3, &read, NULL, 0),
	    "three bytes are not a generic netlink header");
	free(exact);
	check(!ncfg_genl_header_decode(NULL, 0, &read, NULL, 0), "and neither is nothing");
	ncfg_buf_free(&out);
}

static void getfamily_cases(void)
{
	ncfg_buf_t request;
	ncfg_wire_message_t message;
	ncfg_genl_header_t header;
	ncfg_wire_attrs_t attrs;
	ncfg_wire_attr_t attr;
	char err[NCFG_ERROR_MAX];

	ncfg_buf_init(&request, 0);
	check(ncfg_genl_getfamily_request(&request, "nl80211", 42, err, sizeof(err)),
	    "a GETFAMILY request builds");
	check(one_message(request.data, request.length, &message),
	    "and it is exactly one netlink message");
	check(message.header.kind == GENL_ID_CTRL,
	    "addressed to the controller's fixed family id");
	check(message.header.seq == 42u && message.header.len == request.length,
	    "with the sequence asked for and a length counting the whole message");
	check((message.header.flags & NLM_F_REQUEST) != 0,
	    "and NLM_F_REQUEST, without which the kernel answers nothing at all");
	check(ncfg_genl_header_decode(message.payload, message.payload_length, &header, NULL, 0)
	    && header.cmd == CTRL_CMD_GETFAMILY && header.version == 1u,
	    "the payload begins with GETFAMILY version 1");
	check(ncfg_genl_payload_attrs(message.payload, message.payload_length, &attrs,
	    NULL, 0), "the attributes sit past that header");
	check(ncfg_wire_attrs_find(&attrs, CTRL_ATTR_FAMILY_NAME, &attr, NULL, 0)
	    == NCFG_WIRE_OK && attr.length == sizeof("nl80211")
	    && memcmp(attr.value, "nl80211\0", sizeof("nl80211")) == 0,
	    "and the name carries its NUL, which nla_strcmp reads to");
	ncfg_buf_free(&request);

	/* The kernel answers `EINVAL` for a name too long -- for the *length*,
	 * before it looks anything up -- which reads as "netcfgd sent a broken
	 * request" rather than "you typed the name wrong". */
	ncfg_buf_init(&request, 0);
	err[0] = '\0';
	check(!ncfg_genl_getfamily_request(&request, "a-name-far-too-long-to-be-a-family", 1,
	    err, sizeof(err)), "an over-long family name is refused before it is sent");
	check(strstr(err, "at most 15") != NULL, "and the refusal says what the limit is");
	ncfg_buf_free(&request);

	ncfg_buf_init(&request, 0);
	check(!ncfg_genl_getfamily_request(&request, "", 1, NULL, 0),
	    "and the empty string names no family");
	ncfg_buf_free(&request);
}

/* A controller reply: a genl header, an id, a name, and a groups nest holding
 * one group as the array entry the real controller sends. */
static void controller_reply(ncfg_buf_t *out, const char *name, int with_id,
    const char *group_name, uint32_t group_id)
{
	ncfg_genl_header_t header;
	ncfg_buf_t group;
	ncfg_buf_t array;

	header.cmd = CTRL_CMD_NEWFAMILY;
	header.version = 2;
	ncfg_buf_init(out, 0);
	ncfg_genl_header_encode(&header, out);
	if (with_id) {
		/* Two bytes, which is the whole reason the reader has a `u16`
		 * accessor: the group id below is four. */
		uint16_t id = 27;

		ncfg_wire_attr_put(out, CTRL_ATTR_FAMILY_ID, &id, sizeof(id));
	}
	ncfg_wire_attr_put_str(out, CTRL_ATTR_FAMILY_NAME, name);
	if (!group_name) {
		return;
	}
	ncfg_buf_init(&group, 0);
	ncfg_wire_attr_put_str(&group, CTRL_ATTR_MCAST_GRP_NAME, group_name);
	ncfg_wire_attr_put_u32(&group, CTRL_ATTR_MCAST_GRP_ID, group_id);
	ncfg_buf_init(&array, 0);
	/* The array entry's type is an index rather than a meaning, which is the
	 * case a reader gets wrong by treating it as a kind and finding nothing. */
	ncfg_wire_attr_put_nested(&array, 1, &group);
	ncfg_wire_attr_put_nested(out, CTRL_ATTR_MCAST_GROUPS, &array);
	ncfg_buf_free(&group);
	ncfg_buf_free(&array);
}

static void family_parse_cases(void)
{
	ncfg_buf_t reply;
	ncfg_genl_family_t family;
	uint32_t id = 0;
	char err[NCFG_ERROR_MAX];
	size_t cut;
	size_t refused = 0;

	controller_reply(&reply, "nlctrl", 1, "notify", 3);
	check(ncfg_genl_family_parse("nlctrl", reply.data, reply.length, &family, err,
	    sizeof(err)), "a controller reply parses");
	check(family.id == 27u && strcmp(family.name, "nlctrl") == 0,
	    "with the family id read as two bytes and the name kept");
	check(family.group_count == 1
	    && ncfg_genl_family_group(&family, "notify", &id, NULL, 0) && id == 3u,
	    "and the multicast group out of the nested array");
	check(!ncfg_genl_family_group(&family, "absent", &id, err, sizeof(err))
	    && strstr(err, "nlctrl") != NULL,
	    "a group the family does not publish is refused, naming the family");
	ncfg_genl_family_free(&family);
	check(family.groups == NULL && family.group_count == 0,
	    "freeing a family leaves it empty and usable");
	ncfg_genl_family_free(&family);

	/* Every truncation, which is the shape a short read produces -- and the
	 * shape that finds an off-by-one, because exactly one cut sits on each
	 * boundary. Each is copied to its exact length so an overread is a
	 * report rather than a byte of the rest of the buffer. */
	for (cut = 0; cut < reply.length; cut++) {
		uint8_t *partial = exact_copy(reply.data, cut);

		if (ncfg_genl_family_parse("nlctrl", partial, cut, &family, NULL, 0)) {
			/* A prefix that happens to hold the id is a legitimate
			 * parse; what must never happen is a read past the end,
			 * which is ASan's half of this and not a boolean's. */
			ncfg_genl_family_free(&family);
		} else {
			refused++;
		}
		free(partial);
	}
	check(refused > 0, "truncated controller replies are refused rather than read");
	check(ncfg_genl_family_parse("nlctrl", reply.data, reply.length, &family, NULL, 0),
	    "while the untruncated one still parses after every cut");
	ncfg_genl_family_free(&family);
	ncfg_buf_free(&reply);

	/* The reply that names somebody else. A socket subscribed to the
	 * controller's notifications receives NEWFAMILY announcements about
	 * every family that loads, and taking the id out of whichever reply
	 * arrived would resolve `wireguard` to whatever module came last. */
	controller_reply(&reply, "nl80211", 1, NULL, 0);
	err[0] = '\0';
	check(!ncfg_genl_family_parse("wireguard", reply.data, reply.length, &family, err,
	    sizeof(err)), "a reply about another family is not this family's id");
	check(strstr(err, "nl80211") != NULL && strstr(err, "wireguard") != NULL,
	    "and the refusal names both");
	ncfg_buf_free(&reply);

	controller_reply(&reply, "wireguard", 0, NULL, 0);
	err[0] = '\0';
	check(!ncfg_genl_family_parse("wireguard", reply.data, reply.length, &family, err,
	    sizeof(err)) && strstr(err, "without a family id") != NULL,
	    "a reply with no family id is refused, and says so");
	ncfg_buf_free(&reply);

	err[0] = '\0';
	check(!ncfg_genl_family_parse("wireguard", "\3\1", 2, &family, err, sizeof(err)),
	    "a payload too short for a genl header is not an empty attribute area");
}

static void malformed_reply_cases(void)
{
	/* The Rust's `a_malformed_reply_does_not_panic`, which is the entry
	 * point a fuzzer reaches: whatever the controller sends, reading it must
	 * terminate and must not read past the end. */
	static const uint8_t noise[][12] = {
		{ 0 },
		{ 3, 1, 0, 0 },
		{ 3, 1, 0, 0, 0xff, 0xff, 0xff, 0xff },
		{ 3, 1, 0, 0, 8, 0, 1, 0, 1, 0, 0, 0 },
		/* A groups nest that claims more length than it has. */
		{ 3, 1, 0, 0, 0xff, 0x7f, 7, 0, 1, 2, 3 }
	};
	static const size_t lengths[] = { 1, 4, 8, 12, 11 };
	size_t index;
	int bounded = 1;

	for (index = 0; index < sizeof(lengths) / sizeof(lengths[0]); index++) {
		uint8_t *exact = exact_copy(noise[index], lengths[index]);
		ncfg_genl_family_t family;
		ncfg_wg_state_t state;
		size_t seen = 0;
		ncfg_wire_attrs_t attrs;

		if (ncfg_genl_family_parse("nlctrl", exact, lengths[index], &family, NULL, 0)) {
			ncfg_genl_family_free(&family);
		}
		memset(&state, 0, sizeof(state));
		(void)ncfg_wg_state_merge(&state, exact, lengths[index], NULL, 0);
		ncfg_wg_state_free(&state);
		if (ncfg_genl_payload_attrs(exact, lengths[index], &attrs, NULL, 0)) {
			ncfg_wire_attr_t attr;

			while (seen < WALK_CAP
			    && ncfg_wire_attrs_next(&attrs, &attr, NULL, 0) == NCFG_WIRE_OK) {
				seen++;
			}
			if (seen >= WALK_CAP) {
				bounded = 0;
			}
		}
		free(exact);
	}
	check(bounded, "noise from the controller terminates every walk it starts");
}

static void lookup_failure_cases(void)
{
	char err[NCFG_ERROR_MAX];

	err[0] = '\0';
	check(!ncfg_genl_lookup_failed("wireguard", ENOENT, err, sizeof(err)),
	    "a lookup failure is always a failure");
	check(strstr(err, "wireguard") != NULL && strstr(err, "not loaded") != NULL,
	    "and ENOENT points at the module that is not loaded");
	err[0] = '\0';
	(void)ncfg_genl_lookup_failed("wireguard", EPERM, err, sizeof(err));
	check(strstr(err, "not loaded") == NULL && strstr(err, "wireguard") != NULL,
	    "while another errno is not reported as an absent module");
}

static void build_request_cases(void)
{
	ncfg_genl_header_t header;
	ncfg_buf_t attrs;
	ncfg_buf_t out;
	char err[NCFG_ERROR_MAX];

	header.cmd = WG_CMD_SET_DEVICE;
	header.version = WG_GENL_VERSION;
	ncfg_buf_init(&attrs, 0);
	ncfg_buf_init(&out, 0);
	err[0] = '\0';
	/* Zero is what an unresolved family's id is, and sent as it is the kernel
	 * reads it as NLMSG_NOOP and answers nothing: the failure arrives as a
	 * timeout with no sentence in it. */
	check(!ncfg_genl_build_request(&out, 0, &header, 0, 1, &attrs, err, sizeof(err))
	    && strstr(err, "never resolved") != NULL,
	    "a request to family zero is refused rather than sent");
	ncfg_buf_free(&attrs);
	ncfg_buf_free(&out);
}

/* ------------------------------------------------------------------------ *
 * WireGuard: the nesting, the numbering, and the endianness
 * ------------------------------------------------------------------------ */

/* The attribute area of a built message, past both headers. */
static int message_attrs(const ncfg_wg_message_t *message, ncfg_wire_message_t *out,
    const uint8_t **bytes, size_t *length)
{
	if (!one_message(message->bytes, message->length, out)) {
		return 0;
	}
	if (out->payload_length < NCFG_GENL_HDR_LEN) {
		return 0;
	}
	*bytes = out->payload + NCFG_GENL_HDR_LEN;
	*length = out->payload_length - NCFG_GENL_HDR_LEN;
	return 1;
}

static void nesting_cases(void)
{
	sample_t fixture;
	ncfg_genl_family_t family;
	ncfg_wg_messages_t messages;
	ncfg_wire_message_t message;
	const uint8_t *bytes;
	size_t length;
	raw_attr_t attrs[RAW_MAX];
	raw_attr_t peers[RAW_MAX];
	raw_attr_t inside[RAW_MAX];
	raw_attr_t allowed[RAW_MAX];
	const raw_attr_t *found;
	size_t count;
	size_t peer_count;
	size_t index;
	int all_nested = 1;
	char err[NCFG_ERROR_MAX];

	sample_family(&family);
	if (!sample(&fixture, err, sizeof(err))) {
		check(0, "the fixture builds");
		return;
	}
	if (!ncfg_wg_set_device_build(&messages, &family, 7, &fixture.request, err,
	    sizeof(err))) {
		printf("%s\n", err);
		check(0, "a SET_DEVICE builds");
		return;
	}
	check(messages.count == 1u, "two peers fit one message");
	check(message_attrs(&messages.message[0], &message, &bytes, &length),
	    "and it reads back as one netlink message with a genl header");
	check(message.header.kind == family.id
	    && (message.header.flags & (NLM_F_REQUEST | NLM_F_ACK))
	    == (NLM_F_REQUEST | NLM_F_ACK),
	    "addressed to the resolved family, asking for an acknowledgement");
	check(message.header.seq == 7u, "carrying the sequence number it was given");

	count = raw_attrs(bytes, length, attrs, RAW_MAX);
	found = raw_find(attrs, count, WGDEVICE_A_PEERS);
	check(found != NULL, "the peers attribute is there");
	if (!found) {
		ncfg_wg_messages_free(&messages);
		return;
	}
	/*
	 * Generic netlink validates strictly: an attribute the family declares
	 * as nested must carry `NLA_F_NESTED` or the whole message is rejected
	 * with `EINVAL`, naming nothing. rtnetlink does not enforce it, which is
	 * why netcfgd sent unflagged nests for years and only met this here.
	 */
	check((found->kind & NLA_F_NESTED) != 0, "WGDEVICE_A_PEERS is marked nested");
	peer_count = raw_attrs(found->value, found->length, peers, RAW_MAX);
	check(peer_count == 2u, "and it holds the two peers as an array");
	for (index = 0; index < peer_count; index++) {
		if ((peers[index].kind & NLA_F_NESTED) == 0) {
			all_nested = 0;
		}
		/* The array entry's type is its index, not a meaning. Numbering
		 * them all the same is a list read as one entry repeated. */
		if ((peers[index].kind & 0x3fffu) != (uint16_t)index) {
			all_nested = 0;
		}
	}
	check(all_nested, "every array element is nested, and numbered by position");

	count = raw_attrs(peers[0].value, peers[0].length, inside, RAW_MAX);
	found = raw_find(inside, count, WGPEER_A_ALLOWEDIPS);
	check(found != NULL && (found->kind & NLA_F_NESTED) != 0,
	    "a peer's allowed IPs are nested too");
	if (found) {
		count = raw_attrs(found->value, found->length, allowed, RAW_MAX);
		all_nested = count == 2u;
		for (index = 0; index < count; index++) {
			if ((allowed[index].kind & NLA_F_NESTED) == 0) {
				all_nested = 0;
			}
		}
		check(all_nested, "and so is every allowed IP inside them");
	}
	ncfg_wg_messages_free(&messages);
	check(messages.count == 0u && messages.message == NULL,
	    "freeing the messages leaves nothing behind");
}

static void numbering_cases(void)
{
	sample_t fixture;
	ncfg_genl_family_t family;
	ncfg_wg_messages_t messages;
	ncfg_wire_message_t message;
	const uint8_t *bytes;
	size_t length;
	ncfg_wire_attrs_t attrs;
	ncfg_wire_attr_t attr;
	uint32_t flags = 0;
	uint16_t port = 0;
	char err[NCFG_ERROR_MAX];

	sample_family(&family);
	if (!sample(&fixture, err, sizeof(err))
	    || !ncfg_wg_set_device_build(&messages, &family, 1, &fixture.request, err,
	    sizeof(err))) {
		check(0, "a SET_DEVICE builds");
		return;
	}
	if (!message_attrs(&messages.message[0], &message, &bytes, &length)) {
		check(0, "the message reads back");
		ncfg_wg_messages_free(&messages);
		return;
	}
	ncfg_wire_attrs_start(&attrs, bytes, length);
	/*
	 * The device numbering has a gap: `WGDEVICE_A_PUBLIC_KEY` sits at 4
	 * between the private key and the flags, because a `GET` reports the
	 * derived key even though nothing sets it. Numbering `FLAGS` as 4 sends
	 * four bytes where 32 octets are expected, and the kernel answers
	 * `ERANGE` -- naming neither the attribute nor the length. That is how
	 * the Rust found it.
	 */
	check(ncfg_wire_attrs_find(&attrs, WGDEVICE_A_FLAGS, &attr, NULL, 0) == NCFG_WIRE_OK
	    && ncfg_wire_attr_u32(&attr, &flags, NULL, 0)
	    && flags == WGDEVICE_F_REPLACE_PEERS,
	    "the flags attribute is five and replaces the peer list");
	check(ncfg_wire_attrs_find(&attrs, WGDEVICE_A_PUBLIC_KEY, &attr, NULL, 0)
	    == NCFG_WIRE_END, "and nothing at all occupies the public key on a set");
	check(ncfg_wire_attrs_find(&attrs, WGDEVICE_A_PRIVATE_KEY, &attr, NULL, 0)
	    == NCFG_WIRE_OK && attr.length == NCFG_WG_KEY_LEN,
	    "the private key is the kernel's 32 octets");
	check(ncfg_wire_attrs_find(&attrs, WGDEVICE_A_LISTEN_PORT, &attr, NULL, 0)
	    == NCFG_WIRE_OK && attr.length == 2u
	    && ncfg_wire_attr_u16(&attr, &port, NULL, 0) && port == 51820u,
	    "the listen port is two bytes in the host's order, like every netlink integer");
	ncfg_wg_messages_free(&messages);
}

static void endpoint_cases(void)
{
	sample_t fixture;
	ncfg_genl_family_t family;
	ncfg_wg_messages_t messages;
	ncfg_wire_message_t message;
	const uint8_t *bytes;
	size_t length;
	ncfg_wire_attrs_t attrs;
	ncfg_wire_attr_t attr;
	ncfg_wire_attrs_t peers;
	ncfg_wire_attr_t peer;
	ncfg_wire_attrs_t inside;
	uint16_t native = AF_INET;
	ncfg_wire_ip_t address;
	uint16_t port = 0;
	char text[NCFG_WG_ENDPOINT_TEXT_MAX];
	char err[NCFG_ERROR_MAX];

	sample_family(&family);
	if (!sample(&fixture, err, sizeof(err))
	    || !ncfg_wg_set_device_build(&messages, &family, 1, &fixture.request, err,
	    sizeof(err))
	    || !message_attrs(&messages.message[0], &message, &bytes, &length)) {
		check(0, "a SET_DEVICE builds and reads back");
		return;
	}
	ncfg_wire_attrs_start(&attrs, bytes, length);
	if (ncfg_wire_attrs_find(&attrs, WGDEVICE_A_PEERS, &attr, NULL, 0) != NCFG_WIRE_OK) {
		check(0, "the peers are there");
		ncfg_wg_messages_free(&messages);
		return;
	}
	ncfg_wire_attrs_start(&peers, attr.value, attr.length);
	if (ncfg_wire_attrs_next(&peers, &peer, NULL, 0) != NCFG_WIRE_OK) {
		check(0, "the first peer is there");
		ncfg_wg_messages_free(&messages);
		return;
	}
	ncfg_wire_attrs_start(&inside, peer.value, peer.length);
	if (ncfg_wire_attrs_find(&inside, WGPEER_A_ENDPOINT, &attr, NULL, 0) != NCFG_WIRE_OK) {
		check(0, "the peer has an endpoint");
		ncfg_wg_messages_free(&messages);
		return;
	}
	/*
	 * A `sockaddr_in` is sixteen bytes with a big-endian port and a
	 * native-endian family. Getting either wrong produces an endpoint the
	 * kernel accepts and sends nothing to -- a tunnel that comes up and
	 * carries no traffic, which is worse than one that refuses to.
	 */
	check(attr.length == 16u, "an endpoint is sizeof(struct sockaddr_in)");
	check(memcmp(attr.value, &native, sizeof(native)) == 0,
	    "with AF_INET in the host's byte order");
	check(attr.value[2] == (51821u >> 8) && attr.value[3] == (51821u & 0xffu),
	    "and the port big-endian, which is the opposite answer in the same struct");
	check(memcmp(attr.value + 4, "\x7f\x00\x00\x01", 4) == 0, "then the address");
	ncfg_wg_messages_free(&messages);

	/* The text forms, which is how the document spells one. */
	check(ncfg_wg_endpoint_parse("[2001:db8::1]:51820", &address, &port, NULL, 0)
	    && address.family == AF_INET6 && port == 51820u,
	    "a bracketed IPv6 endpoint parses");
	check(ncfg_wg_endpoint_text(&address, port, text, sizeof(text), NULL, 0)
	    && strcmp(text, "[2001:db8::1]:51820") == 0, "and renders back the same way");
	/*
	 * `fd00::1:51820` is a perfectly good address and also reads as an
	 * address and a port, and the two readings name different machines. The
	 * brackets settle it, so an unbracketed one is refused rather than
	 * guessed at.
	 */
	check(!ncfg_wg_endpoint_parse("fd00::1:51820", &address, &port, err, sizeof(err))
	    && strstr(err, "ambiguous") != NULL,
	    "an unbracketed IPv6 endpoint is refused rather than read as a port");
	check(!ncfg_wg_endpoint_parse("127.0.0.1:0", &address, &port, NULL, 0),
	    "port zero is nowhere to send to");
	check(!ncfg_wg_endpoint_parse("127.0.0.1:70000", &address, &port, NULL, 0),
	    "and a port past 65535 is not one");
	check(!ncfg_wg_endpoint_parse("vpn.example.com:51820", &address, &port, NULL, 0),
	    "a host name is the caller's to resolve, because a lookup is I/O");
}

/* ------------------------------------------------------------------------ *
 * The round trip
 * ------------------------------------------------------------------------ */

static int same_allowed(const ncfg_wg_allowed_ip_t *allowed, const char *text)
{
	char rendered[NCFG_ADDRESS_MAX];
	char address[NCFG_WIRE_IP_TEXT_MAX];
	int written;

	if (!ncfg_wire_ip_text(&allowed->address, address, sizeof(address), NULL, 0)) {
		return 0;
	}
	written = snprintf(rendered, sizeof(rendered), "%s/%u", address,
	    (unsigned)allowed->prefix);
	if (written < 0 || (size_t)written >= sizeof(rendered)) {
		return 0;
	}
	return strcmp(rendered, text) == 0;
}

static void round_trip_cases(void)
{
	sample_t fixture;
	ncfg_genl_family_t family;
	ncfg_wg_messages_t messages;
	ncfg_wire_message_t message;
	ncfg_wg_state_t state;
	unsigned char expected[NCFG_WG_KEY_LEN];
	char err[NCFG_ERROR_MAX];

	sample_family(&family);
	memset(&state, 0, sizeof(state));
	if (!sample(&fixture, err, sizeof(err))
	    || !ncfg_wg_set_device_build(&messages, &family, 1, &fixture.request, err,
	    sizeof(err))
	    || !one_message(messages.message[0].bytes, messages.message[0].length, &message)) {
		check(0, "a SET_DEVICE builds and reads back");
		return;
	}
	/*
	 * The message built for the kernel, read back with the reader written
	 * for the kernel's replies. The two shapes are the same tree -- the
	 * device, its peers, their allowed IPs -- which is what makes this a
	 * round trip rather than two encoders agreeing with themselves. What a
	 * `GET` adds is the derived public key, and what it drops is the private
	 * one; neither is asserted here for that reason.
	 */
	check(ncfg_wg_state_merge(&state, message.payload, message.payload_length, err,
	    sizeof(err)), "a device reads back out of the message built for it");
	check(state.has_listen_port && state.listen_port == 51820u, "the listen port survives");
	check(state.has_fwmark && state.fwmark == 42u, "and the firewall mark");
	check(state.peer_count == 2u, "two peers in, two peers out, in order");
	if (state.peer_count == 2u) {
		fill_key(expected, 100);
		check(memcmp(state.peers[0].public_key, expected, NCFG_WG_KEY_LEN) == 0,
		    "the first peer is the one that went in");
		check(state.peers[0].has_preshared_key,
		    "its preshared key is reported as set, and never as a value");
		check(state.peers[0].has_endpoint
		    && state.peers[0].endpoint.family == AF_INET
		    && state.peers[0].endpoint_port == 51821u,
		    "its endpoint comes back as the address and port that went in");
		check(state.peers[0].keepalive == 25u, "and its keepalive");
		check(state.peers[0].allowed_ip_count == 2u
		    && same_allowed(&state.peers[0].allowed_ips[0], alpha_ip4)
		    && same_allowed(&state.peers[0].allowed_ips[1], alpha_ip6),
		    "both allowed IPs, both families, in order");

		fill_key(expected, 7);
		check(memcmp(state.peers[1].public_key, expected, NCFG_WG_KEY_LEN) == 0,
		    "the second peer is the second one that went in");
		check(!state.peers[1].has_preshared_key && !state.peers[1].has_endpoint
		    && state.peers[1].keepalive == 0,
		    "and what it did not carry is absent rather than invented");
		check(state.peers[1].allowed_ip_count == 1u
		    && same_allowed(&state.peers[1].allowed_ips[0], beta_ip4),
		    "with its own allowed IP");
	}
	ncfg_wg_state_free(&state);
	check(state.peers == NULL && state.peer_count == 0,
	    "freeing a state leaves it empty and usable");
	ncfg_wg_state_free(&state);
	ncfg_wg_messages_free(&messages);
}

static void partial_set_cases(void)
{
	sample_t fixture;
	ncfg_genl_family_t family;
	ncfg_wg_messages_t messages;
	ncfg_wire_message_t message;
	const uint8_t *bytes;
	size_t length;
	ncfg_wire_attrs_t attrs;
	ncfg_wire_attr_t attr;
	char err[NCFG_ERROR_MAX];

	sample_family(&family);
	if (!sample(&fixture, err, sizeof(err))) {
		check(0, "the fixture builds");
		return;
	}
	/*
	 * `wg set wg0 listen-port 51821` changes a port without touching a peer,
	 * and decision 0054 needs the same thing: `wg.set_device` and
	 * `wg.set_peers` are two ops that are supposed to mean different things.
	 * An empty peers nest here would be a message saying "and here are the
	 * peers: none", which is a sentence worth not sending.
	 */
	fixture.request.replace_peers = 0;
	if (!ncfg_wg_set_device_build(&messages, &family, 1, &fixture.request, err, sizeof(err))
	    || !message_attrs(&messages.message[0], &message, &bytes, &length)) {
		check(0, "a partial SET_DEVICE builds");
		return;
	}
	ncfg_wire_attrs_start(&attrs, bytes, length);
	check(ncfg_wire_attrs_find(&attrs, WGDEVICE_A_PEERS, &attr, NULL, 0) == NCFG_WIRE_END,
	    "without replace_peers the peers are not mentioned at all");
	check(ncfg_wire_attrs_find(&attrs, WGDEVICE_A_FLAGS, &attr, NULL, 0) == NCFG_WIRE_END,
	    "and neither is the flag that would clear them");
	check(ncfg_wire_attrs_find(&attrs, WGDEVICE_A_LISTEN_PORT, &attr, NULL, 0)
	    == NCFG_WIRE_OK, "while the port it was sent for is there");
	ncfg_wg_messages_free(&messages);

	/* The other half of the same instruction: replace with nothing, which is
	 * how the last peer is removed. */
	fixture.request.replace_peers = 1;
	fixture.config.peer_count = 0;
	if (!ncfg_wg_set_device_build(&messages, &family, 1, &fixture.request, err, sizeof(err))
	    || !message_attrs(&messages.message[0], &message, &bytes, &length)) {
		check(0, "an empty replacement builds");
		return;
	}
	ncfg_wire_attrs_start(&attrs, bytes, length);
	check(ncfg_wire_attrs_find(&attrs, WGDEVICE_A_PEERS, &attr, NULL, 0) == NCFG_WIRE_OK
	    && attr.length == 0,
	    "replace_peers with no peers is an empty nest, which removes the last one");
	ncfg_wg_messages_free(&messages);
}

/* ------------------------------------------------------------------------ *
 * The bound the Rust does not check
 * ------------------------------------------------------------------------ */

/*
 * A peer set past what one attribute can carry.
 *
 * The Rust builds the whole peer set as a single attribute and casts its length
 * to `u16` with the lint suppressed, so somewhere between five hundred and a
 * thousand peers the length wraps, the attribute claims nearly nothing, and the
 * kernel reads the next attribute out of the middle of the peer list. Nothing
 * refuses it and nothing says so.
 *
 * This port splits instead, which is what <linux/wireguard.h> says to do and
 * what `wg(8)` does. So the assertions are about the split: every fragment is a
 * message the wire layer reads, only the first carries the replace flag, every
 * peers nest is inside the bound, and the peers that come back out of all of
 * them together are the peers that went in.
 */
static void oversized_peer_set_cases(void)
{
	enum { MANY = 2000 };
	ncfg_wireguard_config_t config;
	ncfg_wg_peer_t *peers;
	ncfg_wg_request_t request;
	ncfg_genl_family_t family;
	ncfg_wg_messages_t messages;
	ncfg_wg_state_t state;
	static char bulk_name[] = "bulk";
	size_t index;
	int flagged = 0;
	int named = 1;
	int bounded = 1;
	int readable = 1;
	int sequenced = 1;
	char err[NCFG_ERROR_MAX];

	peers = calloc((size_t)MANY, sizeof(*peers));
	if (!peers) {
		check(0, "room for the peers");
		return;
	}
	for (index = 0; index < (size_t)MANY; index++) {
		peers[index].name = bulk_name;
		/* Distinct keys, because a peer repeated is a continuation to be
		 * coalesced rather than a second peer -- which is the case below. */
		fill_key(peers[index].public_key, (unsigned)index);
		peers[index].public_key[0] = (unsigned char)(index & 0xffu);
		peers[index].public_key[1] = (unsigned char)((index >> 8) & 0xffu);
	}
	memset(&config, 0, sizeof(config));
	config.peers = peers;
	config.peer_count = (size_t)MANY;
	memset(&request, 0, sizeof(request));
	request.name = device_name;
	request.config = &config;
	request.replace_peers = 1;
	sample_family(&family);

	if (!ncfg_wg_set_device_build(&messages, &family, 100, &request, err, sizeof(err))) {
		printf("%s\n", err);
		check(0, "a peer set past the bound builds");
		free(peers);
		return;
	}
	check(messages.count > 1u,
	    "a peer set past 65531 bytes becomes several messages rather than one bad one");

	memset(&state, 0, sizeof(state));
	for (index = 0; index < messages.count; index++) {
		ncfg_wire_message_t message;
		const uint8_t *bytes;
		size_t length;
		ncfg_wire_attrs_t attrs;
		ncfg_wire_attr_t attr;
		char name[NAME_TEXT];

		if (!message_attrs(&messages.message[index], &message, &bytes, &length)) {
			readable = 0;
			break;
		}
		if (message.header.seq != 100u + (uint32_t)index) {
			sequenced = 0;
		}
		ncfg_wire_attrs_start(&attrs, bytes, length);
		/* Every fragment names the device, or the kernel has no idea which
		 * one the peers belong to. */
		if (ncfg_wire_attrs_find(&attrs, WGDEVICE_A_IFNAME, &attr, NULL, 0)
		    != NCFG_WIRE_OK
		    || !ncfg_wire_attr_string(&attr, name, sizeof(name), NULL, 0)
		    || strcmp(name, device_name) != 0) {
			named = 0;
		}
		if (ncfg_wire_attrs_find(&attrs, WGDEVICE_A_FLAGS, &attr, NULL, 0)
		    == NCFG_WIRE_OK) {
			flagged++;
		}
		if (ncfg_wire_attrs_find(&attrs, WGDEVICE_A_PEERS, &attr, NULL, 0)
		    != NCFG_WIRE_OK || attr.length > NCFG_WG_ATTR_VALUE_MAX) {
			bounded = 0;
		}
		if (!ncfg_wg_state_merge(&state, message.payload, message.payload_length,
		    err, sizeof(err))) {
			readable = 0;
			break;
		}
	}
	check(readable, "every fragment is a netlink message the reader accepts");
	check(named, "and every one of them names the device");
	/*
	 * The one that matters. A fragment repeating `WGDEVICE_F_REPLACE_PEERS`
	 * would clear the peers the fragment before it installed, and the device
	 * would end up holding only the last few hundred -- which looks like
	 * "most of my peers vanished" rather than like an error.
	 */
	check(flagged == 1, "only the first message carries the replace flag");
	check(bounded, "no peers nest is past what one attribute can carry");
	check(sequenced, "and the nth message carries the nth sequence number");
	check(state.peer_count == (size_t)MANY,
	    "every peer that went in comes back out of the fragments together");
	ncfg_wg_state_free(&state);
	ncfg_wg_messages_free(&messages);
	free(peers);
}

/*
 * And the case splitting cannot rescue: one peer too large for one attribute.
 *
 * Splitting a single peer's allowed IPs across messages is a second mechanism
 * the kernel allows and this port does not implement, so the refusal has to
 * name the peer and the size rather than produce a message the kernel reads
 * wrong.
 */
static void oversized_peer_cases(void)
{
	/* 28 bytes per allowed IP in the nest; 2340 of them is 65,520, which
	 * fits, and the peer around them does not. One more than that and the
	 * nest itself is what does not fit. */
	enum { FITS = 2340, SPILLS = 2341 };
	ncfg_wireguard_config_t config;
	ncfg_wg_peer_t peer;
	ncfg_wg_request_t request;
	ncfg_genl_family_t family;
	ncfg_wg_messages_t messages;
	static char many_name[] = "hub";
	char **allowed;
	size_t index;
	char err[NCFG_ERROR_MAX];

	allowed = calloc((size_t)SPILLS, sizeof(*allowed));
	if (!allowed) {
		check(0, "room for the allowed IPs");
		return;
	}
	for (index = 0; index < (size_t)SPILLS; index++) {
		allowed[index] = alpha_ip4;
	}
	memset(&peer, 0, sizeof(peer));
	peer.name = many_name;
	fill_key(peer.public_key, 3);
	peer.allowed_ips = allowed;
	peer.allowed_ip_count = (size_t)FITS;
	memset(&config, 0, sizeof(config));
	config.peers = &peer;
	config.peer_count = 1;
	memset(&request, 0, sizeof(request));
	request.name = device_name;
	request.config = &config;
	request.replace_peers = 1;
	sample_family(&family);

	err[0] = '\0';
	check(!ncfg_wg_set_device_build(&messages, &family, 1, &request, err, sizeof(err)),
	    "a peer too large for one attribute is refused rather than truncated");
	check(strstr(err, "hub") != NULL && strstr(err, "attribute") != NULL,
	    "and the refusal names the peer and what it is too large for");
	check(messages.count == 0 && messages.message == NULL,
	    "a refused build leaves no half a configuration behind");

	peer.allowed_ip_count = (size_t)SPILLS;
	err[0] = '\0';
	check(!ncfg_wg_set_device_build(&messages, &family, 1, &request, err, sizeof(err))
	    && strstr(err, "hub") != NULL,
	    "and so is an allowed-IP list too large for one, naming the peer");
	free(allowed);
}

/* ------------------------------------------------------------------------ *
 * Reading replies
 * ------------------------------------------------------------------------ */

/* A `GET_DEVICE` reply fragment: the device, then peers. */
static void get_reply(ncfg_buf_t *out, const unsigned char *public_key, int with_device,
    const ncfg_wg_allowed_ip_t *allowed, size_t allowed_count)
{
	ncfg_genl_header_t header;
	ncfg_buf_t peer;
	ncfg_buf_t nest;
	ncfg_buf_t array;
	size_t index;

	header.cmd = WG_CMD_GET_DEVICE;
	header.version = WG_GENL_VERSION;
	ncfg_buf_init(out, 0);
	ncfg_genl_header_encode(&header, out);
	if (with_device) {
		uint16_t port = 51820;

		ncfg_wire_attr_put(out, WGDEVICE_A_LISTEN_PORT, &port, sizeof(port));
	}
	ncfg_buf_init(&nest, 0);
	for (index = 0; index < allowed_count; index++) {
		ncfg_buf_t entry;
		uint16_t family = (uint16_t)allowed[index].address.family;

		ncfg_buf_init(&entry, 0);
		ncfg_wire_attr_put(&entry, WGALLOWEDIP_A_FAMILY, &family, sizeof(family));
		ncfg_wire_attr_put_ip(&entry, WGALLOWEDIP_A_IPADDR, &allowed[index].address);
		ncfg_wire_attr_put_u8(&entry, WGALLOWEDIP_A_CIDR_MASK, allowed[index].prefix);
		ncfg_wire_attr_put_nested(&nest, (uint16_t)index, &entry);
		ncfg_buf_free(&entry);
	}
	ncfg_buf_init(&peer, 0);
	ncfg_wire_attr_put(&peer, WGPEER_A_PUBLIC_KEY, public_key, NCFG_WG_KEY_LEN);
	ncfg_wire_attr_put_nested(&peer, WGPEER_A_ALLOWEDIPS, &nest);
	ncfg_buf_init(&array, 0);
	ncfg_wire_attr_put_nested(&array, 0, &peer);
	ncfg_wire_attr_put_nested(out, WGDEVICE_A_PEERS, &array);
	ncfg_buf_free(&peer);
	ncfg_buf_free(&nest);
	ncfg_buf_free(&array);
}

static void coalescing_cases(void)
{
	unsigned char key[NCFG_WG_KEY_LEN];
	unsigned char other[NCFG_WG_KEY_LEN];
	ncfg_wg_allowed_ip_t allowed[2];
	ncfg_wg_state_t state;
	ncfg_buf_t first;
	ncfg_buf_t second;
	char err[NCFG_ERROR_MAX];

	fill_key(key, 100);
	fill_key(other, 9);
	memset(allowed, 0, sizeof(allowed));
	if (!ncfg_wire_ip_parse("10.9.0.0", &allowed[0].address, NULL, 0)
	    || !ncfg_wire_ip_parse("fd00::", &allowed[1].address, NULL, 0)) {
		check(0, "the fixture addresses parse");
		return;
	}
	allowed[0].prefix = 24;
	allowed[1].prefix = 64;

	memset(&state, 0, sizeof(state));
	get_reply(&first, key, 1, &allowed[0], 1);
	get_reply(&second, key, 0, &allowed[1], 1);
	check(ncfg_wg_state_merge(&state, first.data, first.length, err, sizeof(err))
	    && ncfg_wg_state_merge(&state, second.data, second.length, err, sizeof(err)),
	    "a device arriving as two replies merges");
	/*
	 * The kernel may write one peer across two messages, the second carrying
	 * only its public key and the rest of its allowed IPs -- which is what
	 * <linux/wireguard.h> means by "it is then up to the receiver to
	 * coalesce adjacent peers". The Rust appends instead, which reports one
	 * peer twice, each with half its routing table.
	 */
	check(state.peer_count == 1u, "a peer continued in a second reply is not a second peer");
	check(state.peer_count == 1u && state.peers[0].allowed_ip_count == 2u,
	    "and its allowed IPs are the two replies' together");
	check(state.has_listen_port && state.listen_port == 51820u,
	    "while the device attributes came from the reply that carried them");
	ncfg_buf_free(&second);

	/* A different peer in the same position is a different peer. */
	get_reply(&second, other, 0, &allowed[1], 1);
	check(ncfg_wg_state_merge(&state, second.data, second.length, err, sizeof(err))
	    && state.peer_count == 2u, "a different key in the next reply is a second peer");
	ncfg_wg_state_free(&state);
	ncfg_buf_free(&first);
	ncfg_buf_free(&second);
}

static void reply_truncation_cases(void)
{
	unsigned char key[NCFG_WG_KEY_LEN];
	ncfg_wg_allowed_ip_t allowed;
	ncfg_buf_t reply;
	size_t cut;
	size_t refused = 0;
	char err[NCFG_ERROR_MAX];
	ncfg_wg_state_t state;
	ncfg_buf_t short_key;
	ncfg_genl_header_t header;

	fill_key(key, 100);
	memset(&allowed, 0, sizeof(allowed));
	if (!ncfg_wire_ip_parse("10.9.0.0", &allowed.address, NULL, 0)) {
		check(0, "the fixture address parses");
		return;
	}
	allowed.prefix = 24;
	get_reply(&reply, key, 1, &allowed, 1);

	/* Every truncation, each copied to its exact length so that a read one
	 * byte past the end is a report rather than a byte of the allocation. */
	for (cut = 0; cut < reply.length; cut++) {
		uint8_t *partial = exact_copy(reply.data, cut);

		memset(&state, 0, sizeof(state));
		if (!ncfg_wg_state_merge(&state, partial, cut, NULL, 0)) {
			refused++;
		}
		ncfg_wg_state_free(&state);
		free(partial);
	}
	header.cmd = WG_CMD_GET_DEVICE;
	header.version = WG_GENL_VERSION;
	check(refused > 0, "truncated replies are refused rather than half-read");
	memset(&state, 0, sizeof(state));
	check(ncfg_wg_state_merge(&state, reply.data, reply.length, NULL, 0)
	    && state.peer_count == 1u,
	    "while the untruncated reply still reads as one peer after every cut");
	ncfg_wg_state_free(&state);
	ncfg_buf_free(&reply);

	/*
	 * A peer whose allowed IPs are half-readable: the array is allocated as
	 * the entries are read, so a refusal partway through has already taken
	 * memory. Run under ASan, this is the case that says whether it comes
	 * back -- the assertion below is the refusal; the leak check is the rest.
	 */
	{
		ncfg_buf_t nest;
		ncfg_buf_t peer;
		ncfg_buf_t array;
		ncfg_buf_t entry;
		ncfg_buf_t reply_two;

		ncfg_buf_init(&entry, 0);
		ncfg_wire_attr_put_ip(&entry, WGALLOWEDIP_A_IPADDR, &allowed.address);
		ncfg_wire_attr_put_u8(&entry, WGALLOWEDIP_A_CIDR_MASK, 24);
		ncfg_buf_init(&nest, 0);
		ncfg_wire_attr_put_nested(&nest, 0, &entry);
		ncfg_buf_free(&entry);
		/* The second entry carries an address and no prefix length, which
		 * is not a route. */
		ncfg_buf_init(&entry, 0);
		ncfg_wire_attr_put_ip(&entry, WGALLOWEDIP_A_IPADDR, &allowed.address);
		ncfg_wire_attr_put_nested(&nest, 1, &entry);
		ncfg_buf_free(&entry);

		ncfg_buf_init(&peer, 0);
		ncfg_wire_attr_put(&peer, WGPEER_A_PUBLIC_KEY, key, NCFG_WG_KEY_LEN);
		ncfg_wire_attr_put_nested(&peer, WGPEER_A_ALLOWEDIPS, &nest);
		ncfg_buf_init(&array, 0);
		ncfg_wire_attr_put_nested(&array, 0, &peer);
		ncfg_buf_init(&reply_two, 0);
		ncfg_genl_header_encode(&header, &reply_two);
		ncfg_wire_attr_put_nested(&reply_two, WGDEVICE_A_PEERS, &array);

		memset(&state, 0, sizeof(state));
		err[0] = '\0';
		check(!ncfg_wg_state_merge(&state, reply_two.data, reply_two.length, err,
		    sizeof(err)) && strstr(err, "prefix") != NULL,
		    "an allowed IP with no prefix length refuses the peer, not half of it");
		ncfg_wg_state_free(&state);
		ncfg_buf_free(&nest);
		ncfg_buf_free(&peer);
		ncfg_buf_free(&array);
		ncfg_buf_free(&reply_two);
	}

	/*
	 * A key of the wrong length is a reply to throw away rather than a key
	 * to read the front of -- the kernel declares these `NLA_EXACT_LEN`. And
	 * the refusal says the length and never the bytes: a key that failed to
	 * parse is still a key.
	 */
	ncfg_buf_init(&short_key, 0);
	ncfg_genl_header_encode(&header, &short_key);
	ncfg_wire_attr_put(&short_key, WGDEVICE_A_PUBLIC_KEY, "SECRETSECRETSECRETSECRETSECRET", 30);
	memset(&state, 0, sizeof(state));
	err[0] = '\0';
	check(!ncfg_wg_state_merge(&state, short_key.data, short_key.length, err, sizeof(err)),
	    "a 30-octet public key is not a public key");
	check(strstr(err, "SECRET") == NULL && strstr(err, "30") != NULL,
	    "and the refusal carries the length rather than the key");
	ncfg_wg_state_free(&state);
	ncfg_buf_free(&short_key);
}

static void get_request_cases(void)
{
	ncfg_genl_family_t family;
	ncfg_buf_t request;
	ncfg_wire_message_t message;
	ncfg_genl_header_t header;
	ncfg_wire_attrs_t attrs;
	ncfg_wire_attr_t attr;
	char err[NCFG_ERROR_MAX];

	sample_family(&family);
	ncfg_buf_init(&request, 0);
	check(ncfg_wg_get_device_request(&request, &family, 3, device_name, err, sizeof(err)),
	    "a GET_DEVICE request builds");
	check(one_message(request.data, request.length, &message)
	    && message.header.kind == family.id
	    && (message.header.flags & NLM_F_DUMP) != 0,
	    "as a dump, because one device's peers may need more than one reply");
	check(ncfg_genl_header_decode(message.payload, message.payload_length, &header, NULL, 0)
	    && header.cmd == WG_CMD_GET_DEVICE && header.version == WG_GENL_VERSION,
	    "carrying the family's own command and version");
	check(ncfg_genl_payload_attrs(message.payload, message.payload_length, &attrs, NULL, 0)
	    && ncfg_wire_attrs_find(&attrs, WGDEVICE_A_IFNAME, &attr, NULL, 0) == NCFG_WIRE_OK
	    && attr.length == sizeof("wg-test"),
	    "and the interface name, NUL and all");
	ncfg_buf_free(&request);

	ncfg_buf_init(&request, 0);
	err[0] = '\0';
	check(!ncfg_wg_get_device_request(&request, &family, 3, "a-name-far-too-long", err,
	    sizeof(err)), "a name no link could have is refused before it is sent");
	ncfg_buf_free(&request);
}

int main(void)
{
	genl_header_cases();
	getfamily_cases();
	family_parse_cases();
	malformed_reply_cases();
	lookup_failure_cases();
	build_request_cases();
	nesting_cases();
	numbering_cases();
	endpoint_cases();
	round_trip_cases();
	partial_set_cases();
	oversized_peer_set_cases();
	oversized_peer_cases();
	coalescing_cases();
	reply_truncation_cases();
	get_request_cases();

	if (failures == 0) {
		printf("wg_test: all checks passed\n");
	} else {
		printf("wg_test: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
