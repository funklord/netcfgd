/*
 * nft.c -- the nftables described in nft.h.
 *
 * Nothing in this file opens, reads or writes a descriptor. Every function
 * either appends a transaction to a buffer the caller owns or reads bytes the
 * caller already has, and the ones that read treat those bytes as hostile: a
 * ruleset dump arrives through a socket anything on this machine with
 * `CAP_NET_ADMIN` can also write to.
 *
 * **The single-table rule of 0022 is enforced in three places in this file**,
 * and each one is named where it stands: `valid_uplink` and the absence of any
 * table argument at all on the way in, `audit_message` on the assembled bytes
 * on the way out, and the table check at the top of `ncfg_nft_rule_uplink` on
 * the way back.
 */
#include "ncfg/nft.h"
#include "ncfg/schedule.h"

#include "ncfg/sha256.h"
#include "ncfg/wire.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <linux/if_arp.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_conntrack_common.h>
#include <linux/netfilter/nf_nat.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter_ipv4.h>

/*
 * The numbers nft.h publishes are the kernel's, and here is the proof.
 *
 * The Rust writes all four out because `libc` exports none of them. A C port
 * that copied them across would be inventing a second place for them to be
 * wrong, so the header states them for its callers and this file holds them to
 * the machine it is built on.
 */
_Static_assert(NCFG_NFT_NETLINK_PROTOCOL == NETLINK_NETFILTER,
    "the netfilter netlink protocol is 12");
_Static_assert(NCFG_NFT_NAME_MAX == NFT_NAME_MAXLEN, "a table or chain name is 256 bytes");
_Static_assert(NCFG_NFT_NFGENMSG_LEN == sizeof(struct nfgenmsg), "nfgenmsg is 4 bytes");
/*
 * An interface name in a masquerade rule is compared against one register's
 * worth of bytes, so `NFT_REG_SIZE` is the real limit and it happens to equal
 * `IFNAMSIZ`. Asserted against the register rather than against `IFNAMSIZ`
 * because `linux/if.h` and `net/if.h` redefine each other's `struct ifreq`,
 * and this file has no business deciding that for anybody who includes it.
 */
_Static_assert(NCFG_NFT_IFNAME_MAX == NFT_REG_SIZE, "one register holds 16 bytes");

/* The nftables subsystem in the top byte of a message type. The batch markers
 * are the exception: they carry no subsystem there and put it in `res_id`
 * instead, which is how the kernel knows whose transaction this is. */
#define NFT_MESSAGE(kind) ((uint16_t)(((unsigned)NFNL_SUBSYS_NFTABLES << 8) | (unsigned)(kind)))

/*
 * Big-endian, which is the first way this protocol differs from the rtnetlink
 * everything else in the port speaks, and the first way it is silently got
 * wrong.
 *
 * wire.h says there is no `ntohl` anywhere in that file and one would be a
 * bug. Here the opposite holds and these two are why: an nftables integer
 * attribute is `__be32`, and a chain priority sent in the host's order is
 * accepted and puts the chain at 1677721600 instead of 100. Anybody
 * "simplifying" these into `ncfg_wire_attr_put_u32` is removing the
 * conversion that makes them right.
 */
static void put_be32(ncfg_buf_t *out, uint16_t kind, uint32_t value)
{
	uint32_t wire = htonl(value);

	ncfg_wire_attr_put(out, kind, &wire, sizeof(wire));
}

static void put_be64(ncfg_buf_t *out, uint16_t kind, uint64_t value)
{
	uint8_t wire[8];
	int     at;

	for (at = 7; at >= 0; at--) {
		wire[at] = (uint8_t)(value & 0xffu);
		value >>= 8;
	}
	ncfg_wire_attr_put(out, kind, wire, sizeof(wire));
}

static int attr_be32(const ncfg_wire_attr_t *attr, uint32_t *out, char *err, size_t err_size)
{
	uint32_t wire;

	if (!attr || !out || !attr->value || attr->length < sizeof(wire)) {
		ncfg_error_set(err, err_size,
		    "a 32-bit nftables attribute needs 4 bytes and this one has %zu",
		    attr && attr->value ? attr->length : (size_t)0);
		return 0;
	}
	memcpy(&wire, attr->value, sizeof(wire));
	*out = ntohl(wire);
	return 1;
}

/* `struct nfgenmsg`, in front of every nftables message's attributes. */
static void put_nfgenmsg(ncfg_buf_t *out, uint8_t family, uint16_t res_id)
{
	struct nfgenmsg header;

	memset(&header, 0, sizeof(header));
	header.nfgen_family = family;
	header.version = NFNETLINK_V0;
	/* Big-endian, like every other integer in this protocol and unlike every
	 * other integer in the port. */
	header.res_id = htons(res_id);
	ncfg_buf_add(out, &header, sizeof(header));
}

/* One nftables message: header, `nfgenmsg`, attributes. */
static int build(ncfg_buf_t *out, uint16_t kind, uint16_t flags, uint32_t seq, uint8_t family,
    const ncfg_buf_t *attrs, char *err, size_t err_size)
{
	ncfg_buf_t body;
	int built;

	ncfg_buf_init(&body, 0);
	put_nfgenmsg(&body, family, 0);
	built = ncfg_wire_build_request(out, NFT_MESSAGE(kind), (uint16_t)(NLM_F_REQUEST | flags),
	    seq, &body, attrs, err, err_size);
	ncfg_buf_free(&body);
	return built;
}

/* A batch begin or end marker. */
static int batch_marker(ncfg_buf_t *out, uint16_t kind, uint32_t seq, char *err, size_t err_size)
{
	ncfg_buf_t body;
	int built;

	ncfg_buf_init(&body, 0);
	/* `NFNL_SUBSYS_NFTABLES` in `res_id` rather than in the message type: a
	 * marker belongs to no subsystem, and this is how the kernel is told
	 * which one the transaction between the markers is for. */
	put_nfgenmsg(&body, NFPROTO_UNSPEC, NFNL_SUBSYS_NFTABLES);
	built = ncfg_wire_build_request(out, kind, NLM_F_REQUEST, seq, &body, NULL, err, err_size);
	ncfg_buf_free(&body);
	return built;
}

/* The attribute area of a dump payload, past the `nfgenmsg` at its front. */
static int payload_attrs(const void *payload, size_t length, ncfg_wire_attrs_t *out,
    char *err, size_t err_size)
{
	const uint8_t *raw = payload;

	if (!raw || length < NCFG_NFT_NFGENMSG_LEN) {
		ncfg_error_set(err, err_size,
		    "an nftables message carries a %u-byte header and this payload has %zu",
		    (unsigned)NCFG_NFT_NFGENMSG_LEN, raw ? length : (size_t)0);
		return 0;
	}
	ncfg_wire_attrs_start(out, raw + NCFG_NFT_NFGENMSG_LEN, length - NCFG_NFT_NFGENMSG_LEN);
	return 1;
}

/* One string attribute of an area, refused where it is absent, malformed or
 * too long. */
static int read_name(const ncfg_wire_attrs_t *area, uint16_t kind, char *out, size_t out_size,
    char *err, size_t err_size)
{
	ncfg_wire_attr_t attr;

	if (ncfg_wire_attrs_find(area, kind, &attr, NULL, 0) != NCFG_WIRE_OK) {
		ncfg_error_set(err, err_size, "an nftables message with no attribute %u",
		    (unsigned)kind);
		return 0;
	}
	return ncfg_wire_attr_string(&attr, out, out_size, err, err_size);
}

/* ------------------------------------------------------------------------ *
 * Decision 0022, as a check on the bytes
 * ------------------------------------------------------------------------ */

/* One name in a message that would change something, held to the one name this
 * module is allowed to write. */
static int name_must_be(const ncfg_wire_attrs_t *area, uint16_t kind, const char *expected,
    const char *what, char *err, size_t err_size)
{
	char name[NCFG_NFT_NAME_MAX];

	if (!read_name(area, kind, name, sizeof(name), NULL, 0)) {
		ncfg_error_set(err, err_size,
		    "a message that would change something and names no %s", what);
		return 0;
	}
	if (strcmp(name, expected) != 0) {
		ncfg_error_set(err, err_size,
		    "a message would write to %s `%s`; netcfgd owns `%s` and touches "
		    "nothing else (0022)", what, name, expected);
		return 0;
	}
	return 1;
}

/* The chains netcfgd's table holds: the NAT chain of 0022 and the three filter
 * chains of 0294. A fifth name in a message is refused by the audit. */
static const char *const OUR_CHAINS[] = { NCFG_NFT_CHAIN, NCFG_NFT_CHAIN_INPUT,
	NCFG_NFT_CHAIN_FORWARD, NCFG_NFT_CHAIN_OUTPUT, NCFG_NFT_CHAIN_PREROUTING,
	NCFG_NFT_CHAIN_OFFLOAD, NCFG_NFT_CHAIN_MSS };

static int chain_must_be_ours(const ncfg_wire_attrs_t *area, uint16_t kind, char *err,
    size_t err_size)
{
	char   name[NCFG_NFT_NAME_MAX];
	size_t at;

	if (!read_name(area, kind, name, sizeof(name), NULL, 0)) {
		ncfg_error_set(err, err_size, "a message that would change something and names no chain");
		return 0;
	}
	for (at = 0; at < sizeof(OUR_CHAINS) / sizeof(OUR_CHAINS[0]); at++) {
		if (strcmp(name, OUR_CHAINS[at]) == 0) {
			return 1;
		}
	}
	ncfg_error_set(err, err_size,
	    "a message would write to chain `%s`; netcfgd's table holds `postrouting`, "
	    "`prerouting`, `input`, `forward`, `output`, `offload` and `mss` and nothing else "
	    "(0022, 0294, 0298, 0319, 0334)", name);
	return 0;
}

/* A batch marker names its subsystem in `res_id`, and a marker for another one
 * would open a transaction this module has no business opening. */
static int marker_is_nftables(const ncfg_wire_message_t *message, char *err, size_t err_size)
{
	uint16_t res_id;

	if (message->payload_length < NCFG_NFT_NFGENMSG_LEN) {
		ncfg_error_set(err, err_size, "a transaction marker with no header");
		return 0;
	}
	memcpy(&res_id, message->payload + 2, sizeof(res_id));
	res_id = ntohs(res_id);
	if (res_id != NFNL_SUBSYS_NFTABLES) {
		ncfg_error_set(err, err_size,
		    "a transaction marker for netlink subsystem %u rather than nftables",
		    (unsigned)res_id);
		return 0;
	}
	return 1;
}

static int audit_message(const ncfg_wire_message_t *message, char *err, size_t err_size)
{
	ncfg_wire_attrs_t area;
	uint16_t subsystem = (uint16_t)(message->header.kind >> 8);
	uint16_t kind = (uint16_t)(message->header.kind & 0xffu);

	if (subsystem == 0) {
		if (kind != NFNL_MSG_BATCH_BEGIN && kind != NFNL_MSG_BATCH_END) {
			ncfg_error_set(err, err_size,
			    "a netlink message of type %u with no subsystem", (unsigned)kind);
			return 0;
		}
		return marker_is_nftables(message, err, err_size);
	}
	if (subsystem != NFNL_SUBSYS_NFTABLES) {
		ncfg_error_set(err, err_size,
		    "a message for netlink subsystem %u, which is not nftables",
		    (unsigned)subsystem);
		return 0;
	}
	if (!ncfg_wire_message_attrs(message, NCFG_NFT_NFGENMSG_LEN, &area, err, err_size)) {
		return 0;
	}
	switch (kind) {
	case NFT_MSG_GETTABLE:
	case NFT_MSG_GETCHAIN:
	case NFT_MSG_GETRULE:
	case NFT_MSG_GETSETELEM:
		/*
		 * Reading outside netcfgd's table is deliberate and is not a hole
		 * in this check. 0022 requires netcfgd to detect a *second* table
		 * doing source NAT at the same hook -- which double-translates --
		 * and detecting it means dumping every table and every chain.
		 * Reporting is all that ever follows: deleting somebody's table to
		 * resolve a NAT conflict would trade a working firewall for
		 * working NAT, silently.
		 */
		return 1;
	case NFT_MSG_NEWTABLE:
	case NFT_MSG_DELTABLE:
		return name_must_be(&area, NFTA_TABLE_NAME, NCFG_NFT_TABLE, "table", err,
		    err_size);
	case NFT_MSG_NEWCHAIN:
		return name_must_be(&area, NFTA_CHAIN_TABLE, NCFG_NFT_TABLE, "table", err,
		    err_size) &&
		    chain_must_be_ours(&area, NFTA_CHAIN_NAME, err, err_size);
	case NFT_MSG_NEWRULE:
		return name_must_be(&area, NFTA_RULE_TABLE, NCFG_NFT_TABLE, "table", err,
		    err_size) &&
		    chain_must_be_ours(&area, NFTA_RULE_CHAIN, err, err_size);
	case NFT_MSG_NEWSET:
		/* An `over` rule's meter (10.885) or a slot's set (0340): a set in
		 * netcfgd's table, named as `over_set_name` or
		 * `ncfg_nft_slot_set_name` names one, and nothing else. */
		{
			char set_name[NCFG_NFT_NAME_MAX];

			if (!name_must_be(&area, NFTA_SET_TABLE, NCFG_NFT_TABLE, "table", err, err_size) ||
			    !read_name(&area, NFTA_SET_NAME, set_name, sizeof(set_name), err, err_size)) {
				return 0;
			}
			if (strncmp(set_name, "over-", 5) != 0 && strncmp(set_name, "slot-", 5) != 0) {
				ncfg_error_set(err, err_size,
				    "a set `%s`, which is neither an `over` meter nor a slot", set_name);
				return 0;
			}
			return 1;
		}
	case NFT_MSG_NEWSETELEM:
	case NFT_MSG_DELSETELEM:
		/* A slot's members (0340), written live or carried across a
		 * replacement: a slot's set in netcfgd's table, and no other. */
		{
			char set_name[NCFG_NFT_NAME_MAX];

			if (!name_must_be(&area, NFTA_SET_ELEM_LIST_TABLE, NCFG_NFT_TABLE, "table", err,
			        err_size) ||
			    !read_name(&area, NFTA_SET_ELEM_LIST_SET, set_name, sizeof(set_name), err,
			        err_size)) {
				return 0;
			}
			if (strncmp(set_name, "slot-", 5) != 0) {
				ncfg_error_set(err, err_size, "members of a set `%s`, which is not a slot",
				    set_name);
				return 0;
			}
			return 1;
		}
	case NFT_MSG_NEWFLOWTABLE:
		/* One flowtable, by name, in netcfgd's table (0319). */
		return name_must_be(&area, NFTA_FLOWTABLE_TABLE, NCFG_NFT_TABLE, "table", err,
		    err_size) &&
		    name_must_be(&area, NFTA_FLOWTABLE_NAME, NCFG_NFT_FLOWTABLE, "flowtable", err,
		    err_size);
	default:
		break;
	}
	/* The set of messages netcfgd sends is closed: a table, its chains and
	 * rules, the one flowtable 0319 adds, and the dumps that read them back. A
	 * set-element or an object message arriving here means something upstream
	 * has started writing what no record lets it. */
	ncfg_error_set(err, err_size,
	    "an nftables message of type %u, which netcfgd does not write", (unsigned)kind);
	return 0;
}

int ncfg_nft_writes_only_our_table(const void *bytes, size_t length, char *err, size_t err_size)
{
	ncfg_wire_messages_t walk;
	ncfg_wire_message_t message;

	if (!bytes && length) {
		ncfg_error_set(err, err_size, "a transaction with no bytes behind it");
		return 0;
	}
	ncfg_wire_messages_start(&walk, bytes, length);
	for (;;) {
		ncfg_wire_step_t step = ncfg_wire_messages_next(&walk, &message, err, err_size);

		if (step == NCFG_WIRE_END) {
			return 1;
		}
		if (step != NCFG_WIRE_OK) {
			/* A malformed buffer is refused rather than read as far as it
			 * parses: half a transaction audited is not a transaction
			 * audited. The walk leaves itself exhausted on `BAD`, so this
			 * terminates either way. */
			return 0;
		}
		if (!audit_message(&message, err, err_size)) {
			return 0;
		}
	}
}

/* The UPnP table's audit: its own name, its three chains, and no rule -- so
 * netcfgd can make and delete the structure and cannot write a mapping. */
static int audit_upnp_message(const ncfg_wire_message_t *message, char *err, size_t err_size)
{
	ncfg_wire_attrs_t area;
	uint16_t          subsystem = (uint16_t)(message->header.kind >> 8);
	uint16_t          kind = (uint16_t)(message->header.kind & 0xffu);

	if (subsystem == 0) {
		if (kind != NFNL_MSG_BATCH_BEGIN && kind != NFNL_MSG_BATCH_END) {
			ncfg_error_set(err, err_size,
			    "a netlink message of type %u with no subsystem", (unsigned)kind);
			return 0;
		}
		return marker_is_nftables(message, err, err_size);
	}
	if (subsystem != NFNL_SUBSYS_NFTABLES) {
		ncfg_error_set(err, err_size,
		    "a message for netlink subsystem %u, which is not nftables",
		    (unsigned)subsystem);
		return 0;
	}
	if (!ncfg_wire_message_attrs(message, NCFG_NFT_NFGENMSG_LEN, &area, err, err_size)) {
		return 0;
	}
	switch (kind) {
	case NFT_MSG_NEWTABLE:
	case NFT_MSG_DELTABLE:
		return name_must_be(&area, NFTA_TABLE_NAME, NCFG_NFT_UPNP_TABLE, "table", err,
		    err_size);
	case NFT_MSG_NEWCHAIN:
		return name_must_be(&area, NFTA_CHAIN_TABLE, NCFG_NFT_UPNP_TABLE, "table", err,
		    err_size) &&
		    (name_must_be(&area, NFTA_CHAIN_NAME, NCFG_NFT_UPNP_CHAIN_FORWARD, "chain",
		        NULL, 0) ||
		     name_must_be(&area, NFTA_CHAIN_NAME, NCFG_NFT_UPNP_CHAIN_PREROUTING, "chain",
		        NULL, 0) ||
		     name_must_be(&area, NFTA_CHAIN_NAME, NCFG_NFT_UPNP_CHAIN_POSTROUTING, "chain",
		        err, err_size));
	default:
		break;
	}
	ncfg_error_set(err, err_size,
	    "an nftables message of type %u in the UPnP table, whose rules are miniupnpd's",
	    (unsigned)kind);
	return 0;
}

int ncfg_nft_writes_only_upnp_table(const void *bytes, size_t length, char *err,
    size_t err_size)
{
	ncfg_wire_messages_t walk;
	ncfg_wire_message_t  message;

	if (!bytes && length) {
		ncfg_error_set(err, err_size, "a transaction with no bytes behind it");
		return 0;
	}
	ncfg_wire_messages_start(&walk, bytes, length);
	for (;;) {
		ncfg_wire_step_t step = ncfg_wire_messages_next(&walk, &message, err, err_size);

		if (step == NCFG_WIRE_END) {
			return 1;
		}
		if (step != NCFG_WIRE_OK || !audit_upnp_message(&message, err, err_size)) {
			return 0;
		}
	}
}

/* ------------------------------------------------------------------------ *
 * Building requests
 * ------------------------------------------------------------------------ */

int ncfg_nft_build_table_dump(ncfg_buf_t *out, uint32_t seq, char *err, size_t err_size)
{
	return build(out, NFT_MSG_GETTABLE, NLM_F_DUMP, seq, NFPROTO_UNSPEC, NULL, err, err_size);
}

int ncfg_nft_build_chain_dump(ncfg_buf_t *out, uint32_t seq, char *err, size_t err_size)
{
	return build(out, NFT_MSG_GETCHAIN, NLM_F_DUMP, seq, NFPROTO_UNSPEC, NULL, err, err_size);
}

int ncfg_nft_build_rule_dump(ncfg_buf_t *out, uint32_t seq, char *err, size_t err_size)
{
	ncfg_buf_t filter;
	int built;

	ncfg_buf_init(&filter, 0);
	/* The kernel filters a rule dump by these two, and `ncfg_nft_rule_uplink`
	 * checks them again on every reply rather than trusting that it did. A
	 * kernel that ignored the filter would hand back every table's rules, and
	 * a reader that believed the request would report somebody else's
	 * masquerade as netcfgd's uplink. */
	ncfg_wire_attr_put_str(&filter, NFTA_RULE_TABLE, NCFG_NFT_TABLE);
	ncfg_wire_attr_put_str(&filter, NFTA_RULE_CHAIN, NCFG_NFT_CHAIN);
	built = build(out, NFT_MSG_GETRULE, NLM_F_DUMP, seq, NFPROTO_INET, &filter, err, err_size);
	ncfg_buf_free(&filter);
	return built;
}

int ncfg_nft_build_flowtable_dump(ncfg_buf_t *out, uint32_t seq, char *err, size_t err_size)
{
	ncfg_buf_t filter;
	int        built;

	ncfg_buf_init(&filter, 0);
	ncfg_wire_attr_put_str(&filter, NFTA_FLOWTABLE_TABLE, NCFG_NFT_TABLE);
	built = build(out, NFT_MSG_GETFLOWTABLE, NLM_F_DUMP, seq, NFPROTO_INET, &filter, err,
	    err_size);
	ncfg_buf_free(&filter);
	return built;
}

int ncfg_nft_flowtable_read(const void *payload, size_t length, ncfg_nft_flowtable_t *out,
    char *err, size_t err_size)
{
	ncfg_wire_attrs_t area;
	ncfg_wire_attrs_t hook;
	ncfg_wire_attrs_t devices;
	ncfg_wire_attr_t  attr;
	uint32_t          flags = 0;

	if (!out) {
		ncfg_error_set(err, err_size, "a flowtable needs somewhere to go");
		return 0;
	}
	memset(out, 0, sizeof(*out));
	if (!payload_attrs(payload, length, &area, err, err_size) ||
	    !read_name(&area, NFTA_FLOWTABLE_TABLE, out->table, sizeof(out->table), err, err_size) ||
	    !read_name(&area, NFTA_FLOWTABLE_NAME, out->name, sizeof(out->name), err, err_size)) {
		return 0;
	}
	if (ncfg_wire_attrs_find(&area, NFTA_FLOWTABLE_FLAGS, &attr, NULL, 0) == NCFG_WIRE_OK) {
		if (!attr_be32(&attr, &flags, err, err_size)) {
			return 0;
		}
		out->hardware = (flags & NFT_FLOWTABLE_HW_OFFLOAD) != 0u;
	}
	if (ncfg_wire_attrs_find(&area, NFTA_FLOWTABLE_HOOK, &attr, NULL, 0) != NCFG_WIRE_OK) {
		return 1; /* a flowtable bound to nothing names no device */
	}
	ncfg_wire_attrs_start(&hook, attr.value, attr.length);
	if (ncfg_wire_attrs_find(&hook, NFTA_FLOWTABLE_HOOK_DEVS, &attr, NULL, 0) != NCFG_WIRE_OK) {
		return 1;
	}
	ncfg_wire_attrs_start(&devices, attr.value, attr.length);
	for (;;) {
		ncfg_wire_step_t step = ncfg_wire_attrs_next(&devices, &attr, err, err_size);

		if (step == NCFG_WIRE_END) {
			return 1;
		}
		if (step != NCFG_WIRE_OK) {
			return 0;
		}
		if (out->device_count >= NCFG_NFT_FLOWTABLE_DEVICES_MAX) {
			ncfg_error_set(err, err_size, "a flowtable naming more than %u devices",
			    (unsigned)NCFG_NFT_FLOWTABLE_DEVICES_MAX);
			return 0;
		}
		if (!ncfg_wire_attr_string(&attr, out->devices[out->device_count],
		        sizeof(out->devices[0]), err, err_size)) {
			return 0;
		}
		out->device_count++;
	}
}

int ncfg_nft_rule_is_offload(const void *payload, size_t length)
{
	ncfg_wire_attrs_t area;
	ncfg_wire_attrs_t list;
	ncfg_wire_attr_t  attr;
	char              name[NCFG_NFT_NAME_MAX];

	if (!payload_attrs(payload, length, &area, NULL, 0) ||
	    !read_name(&area, NFTA_RULE_TABLE, name, sizeof(name), NULL, 0) ||
	    strcmp(name, NCFG_NFT_TABLE) != 0 ||
	    !read_name(&area, NFTA_RULE_CHAIN, name, sizeof(name), NULL, 0) ||
	    strcmp(name, NCFG_NFT_CHAIN_OFFLOAD) != 0 ||
	    ncfg_wire_attrs_find(&area, NFTA_RULE_EXPRESSIONS, &attr, NULL, 0) != NCFG_WIRE_OK) {
		return 0;
	}
	ncfg_wire_attrs_start(&list, attr.value, attr.length);
	while (ncfg_wire_attrs_next(&list, &attr, NULL, 0) == NCFG_WIRE_OK) {
		ncfg_wire_attrs_t expression;

		ncfg_wire_attrs_start(&expression, attr.value, attr.length);
		if (read_name(&expression, NFTA_EXPR_NAME, name, sizeof(name), NULL, 0) &&
		    strcmp(name, "flow_offload") == 0) {
			return 1;
		}
	}
	return 0;
}

int ncfg_nft_build_table_rule_dump(ncfg_buf_t *out, uint32_t seq, char *err, size_t err_size)
{
	ncfg_buf_t filter;
	int        built;

	/* The table only, every chain; the reader checks each reply's table and
	 * chain again rather than trusting the filter. */
	ncfg_buf_init(&filter, 0);
	ncfg_wire_attr_put_str(&filter, NFTA_RULE_TABLE, NCFG_NFT_TABLE);
	built = build(out, NFT_MSG_GETRULE, NLM_F_DUMP, seq, NFPROTO_INET, &filter, err, err_size);
	ncfg_buf_free(&filter);
	return built;
}

/*
 * The kernel's own name for one of these messages, or NULL.
 *
 * WHY THIS EXISTS AT ALL
 *   A refused transaction gives one errno, and the three ways NAT fails all
 *   give the same one. Measured 2026-10-24 in a hull vm whose module autoload
 *   was blocked (`tests/hull/natcap/`): a kernel with no `nft_chain_nat`
 *   refuses `NFT_MSG_NEWCHAIN` with `ENOENT`, one with no `nft_masq` refuses
 *   `NFT_MSG_NEWRULE` with `ENOENT`, and `kernel_nat.c`'s own header notes
 *   that deleting a table which is not there is `ENOENT` as well. So the
 *   number cannot say which, and the operator's next action differs in each
 *   case -- install a module, build a kernel, or ignore a race.
 *
 *   What does say which is the message the kernel named in its error: netlink
 *   echoes the offending header back, and `socket.c` already decodes it to
 *   spell `RTM_NEWLINK`. It had no name for anything here, so every nftables
 *   refusal read "a netlink request was refused" -- the discriminator arrived
 *   with the error and was thrown away for want of a table.
 *
 * NO PROTOCOL IS PASSED IN, AND THAT IS A MEASUREMENT RATHER THAN A HOPE
 *   `socket.c` consults this after `ncfg_netlink_kind_text`, with no idea
 *   which protocol the socket speaks, which is only safe because the numbers
 *   cannot collide: an nftables message is `(NFNL_SUBSYS_NFTABLES << 8) |
 *   kind`, so 2560 and up, while the largest `RTM_*` this kernel's headers
 *   define is 108.
 *
 *   **The one collision is the batch markers and it is left alone.**
 *   `NFNL_MSG_BATCH_BEGIN` is subsystem 0, type 16, which is `RTM_NEWLINK`
 *   exactly -- so a refused marker would be named as a link message. Nothing
 *   here can tell them apart without the protocol, and a marker asks for no
 *   acknowledgement: in all four states measured the kernel refused an inner
 *   message and never a marker. Said rather than guarded, because a reader
 *   who meets it needs to know it is known.
 */
const char *ncfg_nft_message_text(uint16_t kind)
{
	switch (kind) {
	case NFT_MESSAGE(NFT_MSG_NEWTABLE):
		return "NFT_MSG_NEWTABLE";
	case NFT_MESSAGE(NFT_MSG_GETTABLE):
		return "NFT_MSG_GETTABLE";
	case NFT_MESSAGE(NFT_MSG_DELTABLE):
		return "NFT_MSG_DELTABLE";
	case NFT_MESSAGE(NFT_MSG_NEWCHAIN):
		return "NFT_MSG_NEWCHAIN";
	case NFT_MESSAGE(NFT_MSG_GETCHAIN):
		return "NFT_MSG_GETCHAIN";
	case NFT_MESSAGE(NFT_MSG_DELCHAIN):
		return "NFT_MSG_DELCHAIN";
	case NFT_MESSAGE(NFT_MSG_NEWRULE):
		return "NFT_MSG_NEWRULE";
	case NFT_MESSAGE(NFT_MSG_GETRULE):
		return "NFT_MSG_GETRULE";
	case NFT_MESSAGE(NFT_MSG_DELRULE):
		return "NFT_MSG_DELRULE";
	case NFT_MESSAGE(NFT_MSG_GETGEN):
		return "NFT_MSG_GETGEN";
	case NFT_MESSAGE(NFT_MSG_NEWGEN):
		return "NFT_MSG_NEWGEN";
	default:
		/*
		 * Deliberately not every message nftables defines. These are the
		 * ones netcfgd sends and the two the kernel answers with, which is
		 * the closed set `writes_only_our_table` above holds it to; a name
		 * for a set-element or a flowtable message would be a name for
		 * something that cannot appear unless 0022's line has moved.
		 */
		return NULL;
	}
}

/*
 * `NFT_MSG_GETGEN`, which answers with the ruleset's generation counter.
 *
 * `NLM_F_DUMP` is deliberately absent: the kernel answers this one with a
 * single `NFT_MSG_NEWGEN` message, and asking for a dump of a thing there is
 * one of gets `EINVAL` on some kernels and a one-element dump on others. The
 * family is `NFPROTO_UNSPEC` because a generation is the ruleset's rather than
 * a family's.
 */
int ncfg_nft_build_gen_request(ncfg_buf_t *out, uint32_t seq, char *err, size_t err_size)
{
	return build(out, NFT_MSG_GETGEN, 0, seq, NFPROTO_UNSPEC, NULL, err, err_size);
}

int ncfg_nft_gen_read(const void *payload, size_t length, uint32_t *out, char *err,
    size_t err_size)
{
	ncfg_wire_attrs_t area;
	ncfg_wire_attr_t  attr;

	if (!out) {
		ncfg_error_set(err, err_size, "a generation needs somewhere to go");
		return 0;
	}
	*out = 0;
	if (!payload_attrs(payload, length, &area, err, err_size)) {
		return 0;
	}
	if (ncfg_wire_attrs_find(&area, NFTA_GEN_ID, &attr, NULL, 0) != NCFG_WIRE_OK) {
		/* **Absent is not zero.** A counter can hold zero, so a reply with no
		 * `NFTA_GEN_ID` is an answer to a question netcfgd did not ask --
		 * reported rather than read as a generation, which is what would make
		 * two unrelated replies compare equal. */
		ncfg_error_set(err, err_size,
		    "an nftables generation reply with no NFTA_GEN_ID, so this is not one");
		return 0;
	}
	return attr_be32(&attr, out, err, err_size);
}

/*
 * Whether this is a name a device could have.
 *
 * The kernel's own `dev_valid_name`: not empty, no slash, no whitespace or
 * control characters, and not `.` or `..`. A name no device can have compiles
 * into a comparison that matches nothing, which is NAT that silently does not
 * happen -- and silence is the failure mode this whole module is arranged
 * against.
 */
static int valid_uplink(const char *name, char *err, size_t err_size)
{
	size_t at;

	if (!name || name[0] == '\0') {
		ncfg_error_set(err, err_size, "a masquerade rule needs an interface to masquerade");
		return 0;
	}
	for (at = 0; name[at] != '\0'; at++) {
		unsigned char one = (unsigned char)name[at];

		if (one <= 0x20u || one >= 0x7fu || one == '/') {
			ncfg_error_set(err, err_size,
			    "`%s` is not a name the kernel would take for an interface", name);
			return 0;
		}
	}
	if (at + 1u > NCFG_NFT_IFNAME_MAX) {
		ncfg_error_set(err, err_size,
		    "`%s` is longer than the %u bytes one register holds, so no comparison "
		    "could be written for it", name, (unsigned)NCFG_NFT_IFNAME_MAX);
		return 0;
	}
	if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
		ncfg_error_set(err, err_size, "`%s` is not an interface name", name);
		return 0;
	}
	return 1;
}

/* `type nat hook postrouting priority srcnat`, which is the only chain netcfgd
 * creates and the only kind of chain 0022 allows it to. */
static void nat_chain(ncfg_buf_t *attrs)
{
	ncfg_buf_t hook;

	ncfg_buf_init(&hook, 0);
	put_be32(&hook, NFTA_HOOK_HOOKNUM, NF_INET_POST_ROUTING);
	/* Signed on the wire, and negative priorities are ordinary in nftables,
	 * so this is a reinterpretation rather than a conversion. */
	put_be32(&hook, NFTA_HOOK_PRIORITY, (uint32_t)NF_IP_PRI_NAT_SRC);

	ncfg_wire_attr_put_str(attrs, NFTA_CHAIN_TABLE, NCFG_NFT_TABLE);
	ncfg_wire_attr_put_str(attrs, NFTA_CHAIN_NAME, NCFG_NFT_CHAIN);
	ncfg_wire_attr_put_nested(attrs, NFTA_CHAIN_HOOK, &hook);
	/* `nat`, and nftables itself is what makes the line 0022 draws
	 * mechanical: a table whose only chain is a `nat` chain cannot hold a
	 * filtering rule, so "NAT and nothing else" is enforced by the mechanism
	 * rather than by a convention. */
	ncfg_wire_attr_put_str(attrs, NFTA_CHAIN_TYPE, "nat");
	ncfg_buf_free(&hook);
}

/* One expression -- a name and its parameters -- as an element of a rule's
 * expression list. */
static void put_expression(ncfg_buf_t *list, const char *name, const ncfg_buf_t *data)
{
	ncfg_buf_t expression;

	ncfg_buf_init(&expression, 0);
	ncfg_wire_attr_put_str(&expression, NFTA_EXPR_NAME, name);
	ncfg_wire_attr_put_nested(&expression, NFTA_EXPR_DATA, data);
	ncfg_wire_attr_put_nested(list, NFTA_LIST_ELEM, &expression);
	ncfg_buf_free(&expression);
}

/*
 * `oifname "NAME" masquerade`, as three expressions.
 *
 * nftables has no single "masquerade this interface" primitive. It is: load
 * the outgoing interface name into a register, compare it, and if the
 * comparison passes, masquerade.
 */
static void masquerade_rule(ncfg_buf_t *rule, const char *uplink)
{
	ncfg_buf_t meta;
	ncfg_buf_t cmp;
	ncfg_buf_t value;
	ncfg_buf_t empty;
	ncfg_buf_t expressions;

	ncfg_buf_init(&meta, 0);
	/* `NFT_META_OIFNAME` comes from the kernel's own enum. The Rust counts
	 * it out as 7 and says why that is delicate: counting `enum
	 * nft_meta_keys` wrong lands on `NFT_META_NFTRACE`, which can be set and
	 * not read, so the kernel answers `EOPNOTSUPP` -- an error that reads
	 * like "this kernel has no NAT" rather than "that is the wrong number".
	 * Using the header removes the counting rather than doing it carefully. */
	put_be32(&meta, NFTA_META_KEY, NFT_META_OIFNAME);
	put_be32(&meta, NFTA_META_DREG, NFT_REG_1);

	/*
	 * The NUL is part of the comparison and is what makes it exact.
	 * Comparing `strlen` bytes would match any interface whose name has this
	 * one as a prefix, so masquerading `eth0` would also masquerade
	 * `eth0.42` -- a VLAN on the uplink, translated twice.
	 */
	ncfg_buf_init(&value, 0);
	ncfg_wire_attr_put(&value, NFTA_DATA_VALUE, uplink, strlen(uplink) + 1u);

	ncfg_buf_init(&cmp, 0);
	put_be32(&cmp, NFTA_CMP_SREG, NFT_REG_1);
	put_be32(&cmp, NFTA_CMP_OP, NFT_CMP_EQ);
	ncfg_wire_attr_put_nested(&cmp, NFTA_CMP_DATA, &value);

	/* `masq` takes no parameters, and the empty nest is what the kernel
	 * expects rather than an absent one. */
	ncfg_buf_init(&empty, 0);

	ncfg_buf_init(&expressions, 0);
	put_expression(&expressions, "meta", &meta);
	put_expression(&expressions, "cmp", &cmp);
	put_expression(&expressions, "masq", &empty);

	ncfg_wire_attr_put_str(rule, NFTA_RULE_TABLE, NCFG_NFT_TABLE);
	ncfg_wire_attr_put_str(rule, NFTA_RULE_CHAIN, NCFG_NFT_CHAIN);
	ncfg_wire_attr_put_nested(rule, NFTA_RULE_EXPRESSIONS, &expressions);

	ncfg_buf_free(&expressions);
	ncfg_buf_free(&empty);
	ncfg_buf_free(&cmp);
	ncfg_buf_free(&value);
	ncfg_buf_free(&meta);
}

/* ------------------------------------------------------------------------ *
 * Layer one's firewall (0294, 10.592)
 * ------------------------------------------------------------------------ */

/* A filter base chain: `type filter hook HOOK priority 0; policy POLICY;`. */
static void filter_chain(ncfg_buf_t *attrs, const char *name, uint32_t hook, int policy)
{
	ncfg_buf_t nest;

	ncfg_buf_init(&nest, 0);
	put_be32(&nest, NFTA_HOOK_HOOKNUM, hook);
	put_be32(&nest, NFTA_HOOK_PRIORITY, 0u);
	ncfg_wire_attr_put_str(attrs, NFTA_CHAIN_TABLE, NCFG_NFT_TABLE);
	ncfg_wire_attr_put_str(attrs, NFTA_CHAIN_NAME, name);
	ncfg_wire_attr_put_nested(attrs, NFTA_CHAIN_HOOK, &nest);
	ncfg_wire_attr_put_str(attrs, NFTA_CHAIN_TYPE, "filter");
	put_be32(attrs, NFTA_CHAIN_POLICY,
	    policy == NCFG_FIREWALL_POLICY_DROP ? (uint32_t)NF_DROP : (uint32_t)NF_ACCEPT);
	ncfg_buf_free(&nest);
}

/* `meta KEY` into register 1. */
static void put_meta(ncfg_buf_t *list, uint32_t key)
{
	ncfg_buf_t data;

	ncfg_buf_init(&data, 0);
	put_be32(&data, NFTA_META_KEY, key);
	put_be32(&data, NFTA_META_DREG, NFT_REG_1);
	put_expression(list, "meta", &data);
	ncfg_buf_free(&data);
}

/* `payload` from BASE at OFFSET for LENGTH bytes, into register 1. */
static void put_payload(ncfg_buf_t *list, uint32_t base, uint32_t offset, uint32_t length)
{
	ncfg_buf_t data;

	ncfg_buf_init(&data, 0);
	put_be32(&data, NFTA_PAYLOAD_DREG, NFT_REG_1);
	put_be32(&data, NFTA_PAYLOAD_BASE, base);
	put_be32(&data, NFTA_PAYLOAD_OFFSET, offset);
	put_be32(&data, NFTA_PAYLOAD_LEN, length);
	put_expression(list, "payload", &data);
	ncfg_buf_free(&data);
}

/* A value nested as `NFTA_DATA_VALUE`, which is how cmp and bitwise carry one. */
static void put_data(ncfg_buf_t *attrs, uint16_t kind, const void *bytes, size_t length)
{
	ncfg_buf_t value;

	ncfg_buf_init(&value, 0);
	ncfg_wire_attr_put(&value, NFTA_DATA_VALUE, bytes, length);
	ncfg_wire_attr_put_nested(attrs, kind, &value);
	ncfg_buf_free(&value);
}

/* `register 1 OP BYTES`. */
static void put_cmp(ncfg_buf_t *list, uint32_t op, const void *bytes, size_t length)
{
	ncfg_buf_t data;

	ncfg_buf_init(&data, 0);
	put_be32(&data, NFTA_CMP_SREG, NFT_REG_1);
	put_be32(&data, NFTA_CMP_OP, op);
	put_data(&data, NFTA_CMP_DATA, bytes, length);
	put_expression(list, "cmp", &data);
	ncfg_buf_free(&data);
}

/* `register 1 = (register 1 & MASK) ^ XOR`. */
static void put_bitwise(ncfg_buf_t *list, const void *mask, const void *xor_bytes, size_t length)
{
	ncfg_buf_t data;

	ncfg_buf_init(&data, 0);
	put_be32(&data, NFTA_BITWISE_SREG, NFT_REG_1);
	put_be32(&data, NFTA_BITWISE_DREG, NFT_REG_1);
	put_be32(&data, NFTA_BITWISE_LEN, (uint32_t)length);
	put_data(&data, NFTA_BITWISE_MASK, mask, length);
	put_data(&data, NFTA_BITWISE_XOR, xor_bytes, length);
	put_expression(list, "bitwise", &data);
	ncfg_buf_free(&data);
}

/* `register 1 = register 1 & MASK`, which is how a prefix -- of an address or
 * a station -- is matched: mask, then compare. */
static void put_mask(ncfg_buf_t *list, const uint8_t *mask, size_t length)
{
	uint8_t zero[16];

	memset(zero, 0, sizeof(zero));
	put_bitwise(list, mask, zero, length);
}

/*
 * The packet mark, as nft 1.1.3 writes `meta mark set meta mark & 0x7fffffff`
 * (AND 0x7fffffff, XOR 0) and `meta mark set meta mark | 0x80000000` (AND
 * 0x7fffffff, XOR the bit): load, mask, store. The mark is host order in the
 * register, as `meta` hands it over.
 */
static void put_mark_set(ncfg_buf_t *list, uint32_t xor_value)
{
	const uint32_t mask = ~NCFG_NFT_MARK_BIT;
	ncfg_buf_t     data;

	put_meta(list, NFT_META_MARK);
	put_bitwise(list, &mask, &xor_value, sizeof(mask));
	ncfg_buf_init(&data, 0);
	put_be32(&data, NFTA_META_KEY, NFT_META_MARK);
	put_be32(&data, NFTA_META_SREG, NFT_REG_1);
	put_expression(list, "meta", &data);
	ncfg_buf_free(&data);
}

/* `meta mark & 0x80000000 == 0x80000000`. */
static void put_mark_test(ncfg_buf_t *list)
{
	const uint32_t bit = NCFG_NFT_MARK_BIT;
	const uint32_t zero = 0u;

	put_meta(list, NFT_META_MARK);
	put_bitwise(list, &bit, &zero, sizeof(bit));
	put_cmp(list, NFT_CMP_EQ, &bit, sizeof(bit));
}

/* Free `count` strings and the array holding them. */
static void ncfg_strings_free_list(char **list, size_t count)
{
	size_t at;

	for (at = 0; list && at < count; at++) {
		free(list[at]);
	}
	free(list);
}

/* An address or CIDR, as the family nftables names it, its bytes and its
 * prefix length. */
typedef struct {
	uint8_t  nfproto;
	uint8_t  bytes[16];
	uint32_t length;
	uint32_t prefix;
	/* A slot's set rather than an address (10.932): `@slot:NAME`, expanded to
	 * one family by the caller as `@slot:NAME/4` or `/6`. Empty otherwise. */
	char     slot[NCFG_FIREWALL_SLOT_NAME_MAX + 1u];
} nft_address_t;

/*
 * One schedule piece, as nft writes `meta hour "08:00"-"09:30" meta day 1`:
 * the hour loaded, swapped to network order -- `meta hour` is a host-order
 * register and `range` compares bytes -- and ranged; then the day compared.
 * Measured against nft 1.1.3's own encoding (doc/journal.md 10.663).
 */
static void put_schedule(ncfg_buf_t *list, const ncfg_schedule_piece_t *piece)
{
	ncfg_buf_t     data;
	const uint32_t from = htonl((uint32_t)piece->from);
	const uint32_t to = htonl((uint32_t)piece->to);

	put_meta(list, NFT_META_TIME_HOUR);
	ncfg_buf_init(&data, 0);
	put_be32(&data, NFTA_BYTEORDER_SREG, NFT_REG_1);
	put_be32(&data, NFTA_BYTEORDER_DREG, NFT_REG_1);
	put_be32(&data, NFTA_BYTEORDER_OP, NFT_BYTEORDER_HTON);
	put_be32(&data, NFTA_BYTEORDER_LEN, 4u);
	put_be32(&data, NFTA_BYTEORDER_SIZE, 4u);
	put_expression(list, "byteorder", &data);
	ncfg_buf_free(&data);

	ncfg_buf_init(&data, 0);
	put_be32(&data, NFTA_RANGE_SREG, NFT_REG_1);
	put_be32(&data, NFTA_RANGE_OP, NFT_RANGE_EQ);
	put_data(&data, NFTA_RANGE_FROM_DATA, &from, sizeof(from));
	put_data(&data, NFTA_RANGE_TO_DATA, &to, sizeof(to));
	put_expression(list, "range", &data);
	ncfg_buf_free(&data);

	if (piece->day >= 0) {
		const uint8_t day = (uint8_t)piece->day;

		put_meta(list, NFT_META_TIME_DAY);
		put_cmp(list, NFT_CMP_EQ, &day, sizeof(day));
	}
}

static int parse_address(const char *text, nft_address_t *out, char *err, size_t err_size)
{
	char        host[64];
	const char *slash = strchr(text, '/');
	size_t      span = slash ? (size_t)(slash - text) : strlen(text);
	long        prefix = -1;

	memset(out, 0, sizeof(*out));
	/* A slot's set, one family of it (10.932): only the expanded form, so an
	 * unexpanded `@slot:NAME` is not taken for either family by mistake. */
	if (strncmp(text, "@slot:", 6u) == 0) {
		const size_t name = slash ? (size_t)(slash - text) - 6u : 0u;

		if (!slash || name == 0u || name > NCFG_FIREWALL_SLOT_NAME_MAX ||
		    (strcmp(slash, "/4") != 0 && strcmp(slash, "/6") != 0)) {
			ncfg_error_set(err, err_size, "`%s` is not one family of a slot", text);
			return 0;
		}
		memcpy(out->slot, text + 6, name);
		out->slot[name] = '\0';
		out->nfproto = slash[1] == '6' ? NFPROTO_IPV6 : NFPROTO_IPV4;
		out->length = slash[1] == '6' ? 16u : 4u;
		return 1;
	}
	if (span == 0u || span >= sizeof(host)) {
		ncfg_error_set(err, err_size, "`%s` is not an address", text);
		return 0;
	}
	memcpy(host, text, span);
	host[span] = '\0';
	if (inet_pton(AF_INET, host, out->bytes) == 1) {
		out->nfproto = NFPROTO_IPV4;
		out->length = 4u;
	} else if (inet_pton(AF_INET6, host, out->bytes) == 1) {
		out->nfproto = NFPROTO_IPV6;
		out->length = 16u;
	} else {
		ncfg_error_set(err, err_size, "`%s` is not an IPv4 or IPv6 address", text);
		return 0;
	}
	out->prefix = out->length * 8u;
	if (slash) {
		char *stop = NULL;

		prefix = strtol(slash + 1, &stop, 10);
		if (!stop || stop == slash + 1 || *stop != '\0' || prefix < 0 ||
		    prefix > (long)(out->length * 8u)) {
			ncfg_error_set(err, err_size, "`%s` has a prefix length its family cannot have",
			    text);
			return 0;
		}
		out->prefix = (uint32_t)prefix;
	}
	return 1;
}

/* Load an address field, mask it where the prefix is short, compare. */
static void put_address_match(ncfg_buf_t *list, const nft_address_t *address, int source)
{
	uint8_t  mask[16];
	uint8_t  network[16];
	uint32_t offset;
	uint32_t at;

	if (address->nfproto == NFPROTO_IPV4) {
		offset = source ? 12u : 16u;
	} else {
		offset = source ? 8u : 24u;
	}
	put_payload(list, NFT_PAYLOAD_NETWORK_HEADER, offset, address->length);
	/* A slot's members (10.932): the address looked up in the slot's set,
	 * by name -- a set the same transaction makes is found by it. */
	if (address->slot[0]) {
		ncfg_buf_t data;
		char       set_name[NCFG_NFT_NAME_MAX];

		ncfg_nft_slot_set_name(address->slot, address->nfproto == NFPROTO_IPV6, set_name,
		    sizeof(set_name));
		ncfg_buf_init(&data, 0);
		ncfg_wire_attr_put_str(&data, NFTA_LOOKUP_SET, set_name);
		put_be32(&data, NFTA_LOOKUP_SREG, NFT_REG_1);
		put_expression(list, "lookup", &data);
		ncfg_buf_free(&data);
		return;
	}
	memset(mask, 0, sizeof(mask));
	for (at = 0; at < address->prefix; at++) {
		mask[at / 8u] = (uint8_t)(mask[at / 8u] | (0x80u >> (at % 8u)));
	}
	for (at = 0; at < address->length; at++) {
		network[at] = (uint8_t)(address->bytes[at] & mask[at]);
	}
	if (address->prefix < address->length * 8u) {
		put_mask(list, mask, address->length);
	}
	put_cmp(list, NFT_CMP_EQ, network, address->length);
}

/* An address's bytes and prefix, as the text the digest and the decoder share:
 * the network, and `/N` only where N is short of the family's length. */
static void format_address(uint8_t nfproto, const uint8_t *bytes, uint32_t prefix, char *out,
    size_t out_size)
{
	char     text[INET6_ADDRSTRLEN];
	uint32_t full = nfproto == NFPROTO_IPV4 ? 32u : 128u;

	if (!inet_ntop(nfproto == NFPROTO_IPV4 ? AF_INET : AF_INET6, bytes, text, sizeof(text))) {
		text[0] = '\0';
	}
	if (prefix < full) {
		(void)snprintf(out, out_size, "%s/%u", text, (unsigned)prefix);
	} else {
		(void)snprintf(out, out_size, "%s", text);
	}
}

/* A document address in that form. One the parser refuses is shown as
 * written: the builder refuses it before anything is digested. */
static void normal_address(const char *text, char *out, size_t out_size)
{
	nft_address_t address;
	uint32_t      at;

	/* A slot's set is its name, never an address (10.932). */
	if (!parse_address(text, &address, NULL, 0) || address.slot[0]) {
		(void)snprintf(out, out_size, "%s", text);
		return;
	}
	for (at = address.prefix; at < address.length * 8u; at++) {
		address.bytes[at / 8u] = (uint8_t)(address.bytes[at / 8u] & ~(0x80u >> (at % 8u)));
	}
	format_address(address.nfproto, address.bytes, address.prefix, out, out_size);
}

/* The conntrack state bit for one of the document's words, or 0. */
static uint32_t state_bit(const char *word)
{
	if (strcmp(word, "new") == 0) {
		return NF_CT_STATE_BIT(IP_CT_NEW);
	}
	if (strcmp(word, "established") == 0) {
		return NF_CT_STATE_BIT(IP_CT_ESTABLISHED);
	}
	if (strcmp(word, "related") == 0) {
		return NF_CT_STATE_BIT(IP_CT_RELATED);
	}
	if (strcmp(word, "invalid") == 0) {
		return NF_CT_STATE_INVALID_BIT;
	}
	return 0;
}

static uint8_t protocol_number(int protocol)
{
	switch (protocol) {
	case NCFG_FIREWALL_PROTO_TCP:
		return IPPROTO_TCP;
	case NCFG_FIREWALL_PROTO_UDP:
		return IPPROTO_UDP;
	case NCFG_FIREWALL_PROTO_ICMP:
		return IPPROTO_ICMP;
	case NCFG_FIREWALL_PROTO_ICMPV6:
		return IPPROTO_ICMPV6;
	case NCFG_FIREWALL_PROTO_GRE:
		return IPPROTO_GRE;
	case NCFG_FIREWALL_PROTO_ESP:
		return IPPROTO_ESP;
	case NCFG_FIREWALL_PROTO_AH:
		return IPPROTO_AH;
	case NCFG_FIREWALL_PROTO_SCTP:
		return IPPROTO_SCTP;
	case NCFG_FIREWALL_PROTO_IPIP:
		return IPPROTO_IPIP;
	case NCFG_FIREWALL_PROTO_SIT:
		return IPPROTO_IPV6;
	default:
		return 0;
	}
}

/*
 * A rule's schedule as UTC pieces (10.663): those it carries, where it is an
 * undo copy rebuilt from the kernel, and otherwise its written schedule
 * expanded at this machine's offset now. 0 for a rule with no schedule, and
 * -1 for one whose schedule cannot be read -- which the compiler refuses, so
 * only a hand-edited undo copy reaches it.
 */
static long rule_pieces(const ncfg_firewall_rule_t *rule, ncfg_schedule_piece_t *pieces)
{
	size_t count;
	size_t at;

	if (rule->utc_piece_count) {
		if (rule->utc_piece_count > NCFG_SCHEDULE_PIECES_MAX) {
			return -1;
		}
		for (at = 0; at < rule->utc_piece_count; at++) {
			if (!ncfg_schedule_piece_read(rule->utc_pieces[at], &pieces[at])) {
				return -1;
			}
		}
		return (long)rule->utc_piece_count;
	}
	if (!rule->hours && rule->day_count == 0u) {
		return 0;
	}
	count = ncfg_schedule_expand(rule->hours, rule->days, rule->day_count,
	    ncfg_schedule_offset(), pieces, NCFG_SCHEDULE_PIECES_MAX);
	return count ? (long)count : -1;
}

int ncfg_nft_firewall_rule_text(const char *chain, const ncfg_firewall_rule_t *rule,
    ncfg_buf_t *out)
{
	ncfg_schedule_piece_t pieces[NCFG_SCHEDULE_PIECES_MAX];
	long                  piece_count;
	static const char *const states[] = { "new", "established", "related", "invalid" };
	size_t                   at;

	if (!chain || !rule || !out) {
		return 0;
	}
	/* One field per line, in a fixed order, so the text -- and the digest --
	 * changes exactly when what the rule does changes. States in the
	 * language's order rather than as written: a set, as nftables holds it. */
	ncfg_buf_addf(out, "chain %s\naction %d\nprotocol %d\n", chain, rule->action,
	    rule->protocol);
	for (at = 0; at < rule->port_count; at++) {
		ncfg_buf_addf(out, "port %lld\n", (long long)rule->ports[at]);
	}
	/* Only where set, so no digest written before 0333 changes. */
	for (at = 0; at < rule->icmp_type_count; at++) {
		ncfg_buf_addf(out, "icmp_type %lld\n", (long long)rule->icmp_types[at]);
	}
	/* Only where set, so no digest written before 0331 changes. */
	for (at = 0; at < rule->port_range_count; at++) {
		ncfg_buf_addf(out, "port_range %s\n", rule->port_ranges[at]);
	}
	/* Addresses as the decoder prints them -- network masked, prefix shown
	 * only where it is short -- so that what is read back digests the same
	 * as what was written. */
	for (at = 0; at < rule->from_count; at++) {
		char shown[64];

		normal_address(rule->from[at], shown, sizeof(shown));
		ncfg_buf_addf(out, "from %s\n", shown);
	}
	for (at = 0; at < rule->to_count; at++) {
		char shown[64];

		normal_address(rule->to[at], shown, sizeof(shown));
		ncfg_buf_addf(out, "to %s\n", shown);
	}
	if (rule->interface) {
		ncfg_buf_addf(out, "interface %s\n", rule->interface);
	}
	/* Only where set, so no digest written before 0302 changes. */
	if (rule->out_interface) {
		ncfg_buf_addf(out, "out_interface %s\n", rule->out_interface);
	}
	for (at = 0; at < sizeof(states) / sizeof(states[0]); at++) {
		size_t one;

		for (one = 0; one < rule->state_count; one++) {
			if (strcmp(rule->states[one], states[at]) == 0) {
				ncfg_buf_addf(out, "state %s\n", states[at]);
				break;
			}
		}
	}
	/* Only where set, so no digest written before 0310 changes. */
	if (rule->translated) {
		ncfg_buf_add_text(out, "translated\n");
	}
	/* Only where set, so no digest written before 10.885 changes. */
	if (rule->over) {
		ncfg_buf_addf(out, "over %s\n", rule->over);
	}
	/* Only where set, so no digest written before 0330 changes. */
	if (rule->log) {
		ncfg_buf_add_text(out, "log\n");
	}
	/* Only where set, so no digest written before 0332 changes. */
	if (rule->reset) {
		ncfg_buf_add_text(out, "reset\n");
	}
	for (at = 0; at < rule->mac_count; at++) {
		ncfg_buf_addf(out, "mac %s\n", rule->mac[at]);
	}
	/* The schedule as the kernel will hold it, so the digest moves when the
	 * offset does -- a summer-time change is a firewall the planner sees as
	 * not the document's. Only where one is set, so no digest written before
	 * 10.663 changes. */
	piece_count = rule_pieces(rule, pieces);
	if (piece_count < 0) {
		return 0;
	}
	for (at = 0; at < (size_t)piece_count; at++) {
		char text[NCFG_SCHEDULE_PIECE_TEXT];

		ncfg_schedule_piece_text(&pieces[at], text, sizeof(text));
		ncfg_buf_addf(out, "time %s\n", text);
	}
	return !ncfg_buf_failed(out);
}

/* `name=NAME sha256=DIGEST`, as the comment nft writes and lists. */
static int rule_comment(const char *chain, const ncfg_firewall_rule_t *rule, char *out,
    size_t out_size, char *err, size_t err_size)
{
	ncfg_buf_t text;
	char       digest[NCFG_SHA256_HEX_SIZE];
	int        wrote;

	ncfg_buf_init(&text, 0);
	if (!ncfg_nft_firewall_rule_text(chain, rule, &text)) {
		ncfg_buf_free(&text);
		ncfg_error_set(err, err_size, "out of memory describing rule `%s`", rule->name);
		return 0;
	}
	ncfg_sha256_hex(text.data, text.length, digest);
	ncfg_buf_free(&text);
	wrote = snprintf(out, out_size, "name=%s sha256=%.*s", rule->name,
	    (int)NCFG_NFT_DIGEST_HEX, digest);
	if (wrote < 0 || (size_t)wrote > NCFG_NFT_COMMENT_MAX || (size_t)wrote >= out_size) {
		ncfg_error_set(err, err_size,
		    "rule `%s/%s` has a name too long for the %u characters an nftables comment "
		    "holds beside its digest", chain, rule->name, (unsigned)NCFG_NFT_COMMENT_MAX);
		return 0;
	}
	return 1;
}

/*
 * One kernel rule, every match single-valued, as the expressions nftables
 * would write for it.
 *
 * The order is nftables' own -- the family, the protocol, the port, the
 * addresses, the interface, the state, the station, and the verdict -- so
 * that `nft list ruleset` prints what the document says in the words an
 * operator would have typed. `comment` is the written rule's identity, the
 * same on every kernel rule it became.
 */
/* "COUNT/SECONDSs" into its two numbers; 0 where it is not that shape. */
/*
 * An `over` in its two forms: `COUNT/SECONDSs`, packets per window keyed on the
 * source (10.885), and `BBYTES/SECONDSs`, bytes per window -- a zone's
 * per-client cap (10.928), which a written rule cannot spell and the renderer
 * never writes -- keyed on the source, or on the destination with `@dst`.
 */
static int over_spec(const char *over, uint64_t *count, uint64_t *seconds, int *bytes,
    int *destination)
{
	unsigned long a = 0, b = 0;
	char          unit = 0, tail = 0;
	const char   *text = over;

	*bytes = 0;
	*destination = 0;
	if (!text) {
		return 0;
	}
	if (text[0] == 'B') {
		const char *at = strchr(text, '@');

		*bytes = 1;
		text++;
		if (at) {
			if (strcmp(at, "@dst") != 0) {
				return 0;
			}
			*destination = 1;
		}
	}
	if (sscanf(text, "%lu/%lu%c%c", &a, &b, &unit, &tail) < 3 || unit != 's' || a == 0 ||
	    b == 0 || (!*destination && sscanf(text, "%lu/%lu%c%c", &a, &b, &unit, &tail) != 3)) {
		return 0;
	}
	*count = a;
	*seconds = b;
	return 1;
}

/*
 * A cap's burst: an eighth of its window's bytes, and never less than two
 * full frames (10.928). A whole window's worth let a three-second transfer
 * average 8 Mbit/s under a 5 Mbit/s cap -- the bucket's first second spent on
 * top of the rate.
 */
static uint64_t cap_burst(uint64_t bytes)
{
	return bytes / 8u > 3000u ? bytes / 8u : 3000u;
}

static int over_parts(const char *over, uint64_t *count, uint64_t *seconds)
{
	int bytes, destination;

	return over_spec(over, count, seconds, &bytes, &destination);
}

/*
 * The rate an `over` meter's limit is written with: COUNT per WINDOW as the
 * same token bucket in the smallest unit nft has a word for -- a second, a
 * minute, an hour, a day or a week (10.898). The kernel takes any unit, but nft
 * prints one it has no word for as `8/error`, and a ruleset saved with `nft
 * list ruleset` then fails to load back. The bucket is the same: the burst
 * stays COUNT, and the time one packet costs, unit / rate, stays WINDOW /
 * COUNT, so 8 in 15 minutes is written `32/hour burst 8`. A window no unit
 * divides evenly keeps itself as the unit, as before.
 */
static void over_rate(uint64_t count, uint64_t seconds, uint64_t *rate, uint64_t *unit)
{
	static const uint64_t units[] = { 1u, 60u, 3600u, 86400u, 604800u };
	size_t                at;

	for (at = 0; seconds && at < sizeof(units) / sizeof(units[0]); at++) {
		if ((count * units[at]) % seconds == 0u) {
			*rate = count * units[at] / seconds;
			*unit = units[at];
			return;
		}
	}
	*rate = count;
	*unit = seconds;
}

/*
 * The meter an `over` rule counts in, one per family: `over-` and the first
 * twelve of the rule's digest, then `-4` or `-6`. From the digest so that a
 * changed rule is a new set, and per family because a set's key has one
 * length -- four bytes or sixteen.
 */
static void over_set_name(const char *comment, uint8_t family, char *out, size_t out_size)
{
	const char *digest = comment ? strstr(comment, "sha256=") : NULL;

	(void)snprintf(out, out_size, "over-%.12s-%c", digest ? digest + 7 : "unknown",
	    family == NFPROTO_IPV6 ? '6' : '4');
}

/*
 * `ip saddr` (or `ip6 saddr`) into register 1, and a `dynset` updating the
 * meter with it, the update carrying a `limit` that matches only past the
 * rate -- nftables' `meter NAME { ip saddr timeout Ns limit rate over R/UNIT
 * burst C packets }`, R/UNIT being C per window (`over_rate`). The token
 * bucket holds COUNT packets and refills COUNT per window, so the COUNT+1st
 * in a burst is the first that matches: an iptables `recent --hitcount
 * COUNT+1 --seconds WINDOW`, near enough to guard the same door. An entry
 * left untouched for a window expires, so a quiet source starts again from a
 * full bucket.
 */
static void put_over(ncfg_buf_t *expressions, const char *over, uint8_t family,
    const char *set_name, uint32_t set_id)
{
	ncfg_buf_t data;
	ncfg_buf_t limit;
	ncfg_buf_t expr;
	uint64_t   count = 0, seconds = 0, rate = 0, unit = 0;
	int        bytes = 0, destination = 0;

	(void)over_spec(over, &count, &seconds, &bytes, &destination);
	if (bytes) {
		/* A rate in bytes keeps its own window as the unit: nft has a word
		 * for a second, and a cap is per second. */
		rate = count;
		unit = seconds;
	} else {
		over_rate(count, seconds, &rate, &unit);
	}
	/* The source address, or the destination for a cap's way in. */
	if (family == NFPROTO_IPV6) {
		put_payload(expressions, NFT_PAYLOAD_NETWORK_HEADER, destination ? 24u : 8u, 16u);
	} else {
		put_payload(expressions, NFT_PAYLOAD_NETWORK_HEADER, destination ? 16u : 12u, 4u);
	}
	ncfg_buf_init(&limit, 0);
	put_be64(&limit, NFTA_LIMIT_RATE, rate);
	put_be64(&limit, NFTA_LIMIT_UNIT, unit);
	put_be32(&limit, NFTA_LIMIT_BURST, (uint32_t)(bytes ? cap_burst(count) : count));
	put_be32(&limit, NFTA_LIMIT_TYPE, bytes ? NFT_LIMIT_PKT_BYTES : NFT_LIMIT_PKTS);
	put_be32(&limit, NFTA_LIMIT_FLAGS, NFT_LIMIT_F_INV);
	ncfg_buf_init(&expr, 0);
	ncfg_wire_attr_put_str(&expr, NFTA_EXPR_NAME, "limit");
	ncfg_wire_attr_put_nested(&expr, NFTA_EXPR_DATA, &limit);
	ncfg_buf_init(&data, 0);
	ncfg_wire_attr_put_str(&data, NFTA_DYNSET_SET_NAME, set_name);
	put_be32(&data, NFTA_DYNSET_SET_ID, set_id);
	put_be32(&data, NFTA_DYNSET_OP, NFT_DYNSET_OP_UPDATE);
	put_be32(&data, NFTA_DYNSET_SREG_KEY, NFT_REG_1);
	put_be64(&data, NFTA_DYNSET_TIMEOUT, seconds * 1000u);
	ncfg_wire_attr_put_nested(&data, NFTA_DYNSET_EXPR, &expr);
	put_expression(expressions, "dynset", &data);
	ncfg_buf_free(&data);
	ncfg_buf_free(&expr);
	ncfg_buf_free(&limit);
}

/* The meter itself, in the transaction before the first rule using it. */
static int over_set_message(ncfg_buf_t *transaction, uint32_t *seq, uint32_t *last_acked,
    const char *set_name, uint32_t set_id, uint8_t family, const char *over, char *err,
    size_t err_size)
{
	ncfg_buf_t attrs;
	ncfg_buf_t desc;
	uint64_t   count = 0, seconds = 0;
	int        ok;

	(void)over_parts(over, &count, &seconds);
	ncfg_buf_init(&attrs, 0);
	ncfg_wire_attr_put_str(&attrs, NFTA_SET_TABLE, NCFG_NFT_TABLE);
	ncfg_wire_attr_put_str(&attrs, NFTA_SET_NAME, set_name);
	put_be32(&attrs, NFTA_SET_FLAGS, NFT_SET_TIMEOUT | NFT_SET_EVAL);
	/* nftables' own datatype numbers: 7 is `ipv4_addr`, 8 `ipv6_addr`. */
	put_be32(&attrs, NFTA_SET_KEY_TYPE, family == NFPROTO_IPV6 ? 8u : 7u);
	put_be32(&attrs, NFTA_SET_KEY_LEN, family == NFPROTO_IPV6 ? 16u : 4u);
	put_be32(&attrs, NFTA_SET_ID, set_id);
	put_be64(&attrs, NFTA_SET_TIMEOUT, seconds * 1000u);
	/* A bound on the sources remembered at once, nftables' default for a
	 * meter. */
	ncfg_buf_init(&desc, 0);
	put_be32(&desc, NFTA_SET_DESC_SIZE, 65535u);
	ncfg_wire_attr_put_nested(&attrs, NFTA_SET_DESC, &desc);
	ncfg_buf_free(&desc);
	*last_acked = *seq;
	ok = build(transaction, NFT_MSG_NEWSET, (uint16_t)(NLM_F_ACK | NLM_F_CREATE), (*seq)++,
	    NFPROTO_INET, &attrs, err, err_size);
	ncfg_buf_free(&attrs);
	return ok;
}

/*
 * A rule's log, rated: at most LOG_RATE a minute, a burst of LOG_BURST (0330).
 * Fixed rather than a key, because a rate somebody must choose before they may
 * log anything is a reason not to; ten a minute says a rule is being hit and
 * which address hit it, and no flood can take the disk with it.
 */
#define LOG_RATE  10u
#define LOG_BURST 5u
#define LOG_UNIT  60u

/*
 * `netcfgd CHAIN/NAME: `, what the kernel log line starts with. **Cut to the
 * kernel's 127 characters** (NF_LOG_PREFIXLEN less its NUL) rather than
 * refused: a long name still logs, and the reader cuts the one it expects the
 * same way, so the two agree.
 */
#define LOG_PREFIX_MAX 128u

static void log_prefix(const char *chain, const char *name, char *out, size_t out_size)
{
	char   whole[NCFG_NFT_NAME_MAX + NCFG_NFT_COMMENT_MAX + 16u];
	size_t keep;

	(void)snprintf(whole, sizeof(whole), "netcfgd %s/%s: ", chain, name);
	keep = strlen(whole);
	if (keep > LOG_PREFIX_MAX - 1u) {
		keep = LOG_PREFIX_MAX - 1u;
	}
	if (keep > out_size - 1u) {
		keep = out_size - 1u;
	}
	memcpy(out, whole, keep);
	out[keep] = '\0';
}

/*
 * The log's own kernel rule, ahead of the verdict's (0330): the same matches,
 * then `limit rate 10/minute burst 5 packets log prefix "..."`, and no
 * verdict. **Its own rule, because a `limit` in the verdict's rule would end
 * that rule past the rate**, and every packet past ten a minute would go on
 * to the next rule rather than be dropped.
 */
static void put_log(ncfg_buf_t *expressions, const char *chain, const char *name)
{
	ncfg_buf_t data;
	char       prefix[LOG_PREFIX_MAX];

	ncfg_buf_init(&data, 0);
	put_be64(&data, NFTA_LIMIT_RATE, LOG_RATE);
	put_be64(&data, NFTA_LIMIT_UNIT, LOG_UNIT);
	put_be32(&data, NFTA_LIMIT_BURST, LOG_BURST);
	put_be32(&data, NFTA_LIMIT_TYPE, NFT_LIMIT_PKTS);
	put_be32(&data, NFTA_LIMIT_FLAGS, 0u);
	put_expression(expressions, "limit", &data);
	ncfg_buf_free(&data);
	log_prefix(chain, name, prefix, sizeof(prefix));
	ncfg_buf_init(&data, 0);
	ncfg_wire_attr_put_str(&data, NFTA_LOG_PREFIX, prefix);
	put_expression(expressions, "log", &data);
	ncfg_buf_free(&data);
}

static int firewall_rule(ncfg_buf_t *attrs, const char *chain, const ncfg_firewall_rule_t *rule,
    const ncfg_schedule_piece_t *piece, const char *comment, uint8_t over_family,
    uint32_t over_set_id, int as_log, char *err, size_t err_size)
{
	ncfg_buf_t    expressions;
	ncfg_buf_t    data;
	ncfg_buf_t    verdict;
	ncfg_buf_t    userdata;
	nft_address_t from;
	nft_address_t to;
	uint8_t       family = 0;
	size_t        at;

	if (rule->from_count && !parse_address(rule->from[0], &from, err, err_size)) {
		return 0;
	}
	if (rule->to_count && !parse_address(rule->to[0], &to, err, err_size)) {
		return 0;
	}
	if (rule->from_count) {
		family = from.nfproto;
	}
	if (rule->to_count) {
		family = to.nfproto;
	}
	/* An `over` rule with no address names its family itself: the meter's
	 * key is one family's source address. */
	if (!family && rule->over) {
		family = over_family;
	}

	ncfg_buf_init(&expressions, 0);
	if (family) {
		put_meta(&expressions, NFT_META_NFPROTO);
		put_cmp(&expressions, NFT_CMP_EQ, &family, 1u);
	}
	if (rule->protocol != NCFG_FIREWALL_PROTO_ANY) {
		const uint8_t number = protocol_number(rule->protocol);

		put_meta(&expressions, NFT_META_L4PROTO);
		put_cmp(&expressions, NFT_CMP_EQ, &number, 1u);
	}
	if (rule->port_count) {
		const uint16_t port = htons((uint16_t)rule->ports[0]);

		put_payload(&expressions, NFT_PAYLOAD_TRANSPORT_HEADER, 2u, 2u);
		put_cmp(&expressions, NFT_CMP_EQ, &port, sizeof(port));
	} else if (rule->icmp_type_count) {
		/* `icmp type T` / `icmpv6 type T`: the transport header's first
		 * byte (0333). */
		const uint8_t type = (uint8_t)rule->icmp_types[0];

		put_payload(&expressions, NFT_PAYLOAD_TRANSPORT_HEADER, 0u, 1u);
		put_cmp(&expressions, NFT_CMP_EQ, &type, 1u);
	} else if (rule->port_range_count) {
		/* `th dport LOW-HIGH`, as nft 1.1.3 writes it: one `range`
		 * expression over the loaded port, network order both ends (0331). */
		unsigned long low = 0, high = 0;
		uint16_t      from_port;
		uint16_t      to_port;
		ncfg_buf_t    range;

		(void)sscanf(rule->port_ranges[0], "%lu-%lu", &low, &high);
		from_port = htons((uint16_t)low);
		to_port = htons((uint16_t)high);
		put_payload(&expressions, NFT_PAYLOAD_TRANSPORT_HEADER, 2u, 2u);
		ncfg_buf_init(&range, 0);
		put_be32(&range, NFTA_RANGE_SREG, NFT_REG_1);
		put_be32(&range, NFTA_RANGE_OP, NFT_RANGE_EQ);
		put_data(&range, NFTA_RANGE_FROM_DATA, &from_port, sizeof(from_port));
		put_data(&range, NFTA_RANGE_TO_DATA, &to_port, sizeof(to_port));
		put_expression(&expressions, "range", &range);
		ncfg_buf_free(&range);
	}
	if (rule->from_count) {
		put_address_match(&expressions, &from, 1);
	}
	if (rule->to_count) {
		put_address_match(&expressions, &to, 0);
	}
	if (rule->interface) {
		put_meta(&expressions, strcmp(chain, NCFG_NFT_CHAIN_OUTPUT) == 0 ? NFT_META_OIFNAME
		                                                              : NFT_META_IIFNAME);
		put_cmp(&expressions, NFT_CMP_EQ, rule->interface, strlen(rule->interface) + 1u);
	}
	/* `oifname`, in the forward chain where `interface` was `iifname` (0302).
	 * The compiler refuses it in the other two chains. */
	if (rule->out_interface) {
		put_meta(&expressions, NFT_META_OIFNAME);
		put_cmp(&expressions, NFT_CMP_EQ, rule->out_interface,
		    strlen(rule->out_interface) + 1u);
	}
	if (rule->state_count) {
		uint32_t bits = 0;
		uint32_t none = 0;

		for (at = 0; at < rule->state_count; at++) {
			bits |= state_bit(rule->states[at]);
		}
		/* Host order: conntrack's state is a host-endian register, unlike
		 * every other integer this module writes. */
		ncfg_buf_init(&data, 0);
		put_be32(&data, NFTA_CT_KEY, NFT_CT_STATE);
		put_be32(&data, NFTA_CT_DREG, NFT_REG_1);
		put_expression(&expressions, "ct", &data);
		ncfg_buf_free(&data);
		put_mask(&expressions, (const uint8_t *)&bits, sizeof(bits));
		put_cmp(&expressions, NFT_CMP_NEQ, &none, sizeof(none));
	}
	/* `ct status dnat`, as nft 1.1.3 writes it: the status register masked
	 * with IPS_DST_NAT and compared against zero -- host order, as the state
	 * is. */
	if (rule->translated) {
		uint32_t bits = IPS_DST_NAT;
		uint32_t none = 0;

		ncfg_buf_init(&data, 0);
		put_be32(&data, NFTA_CT_KEY, NFT_CT_STATUS);
		put_be32(&data, NFTA_CT_DREG, NFT_REG_1);
		put_expression(&expressions, "ct", &data);
		ncfg_buf_free(&data);
		put_mask(&expressions, (const uint8_t *)&bits, sizeof(bits));
		put_cmp(&expressions, NFT_CMP_NEQ, &none, sizeof(none));
	}
	if (rule->mac_count) {
		uint8_t        mac[6];
		uint8_t        mask[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
		const uint16_t ether = ARPHRD_ETHER;
		const int      prefix = ncfg_station_is_prefix(rule->mac[0]);
		unsigned       octet[6] = { 0, 0, 0, 0, 0, 0 };

		if (sscanf(rule->mac[0], "%2x:%2x:%2x:%2x:%2x:%2x", &octet[0], &octet[1], &octet[2],
		        &octet[3], &octet[4], &octet[5]) < (prefix ? 3 : 6)) {
			ncfg_buf_free(&expressions);
			ncfg_error_set(err, err_size, "rule `%s/%s` has a station `%s` it cannot read",
			    chain, rule->name, rule->mac[0]);
			return 0;
		}
		for (at = 0; at < 6u; at++) {
			mac[at] = (uint8_t)octet[at];
		}
		if (prefix) {
			mask[3] = mask[4] = mask[5] = 0;
			mac[3] = mac[4] = mac[5] = 0;
		}
		/* nftables' own dependency for `ether saddr` in an inet table: the
		 * header is only Ethernet's where the device is. Host order, as
		 * `meta iiftype` is. */
		put_meta(&expressions, NFT_META_IIFTYPE);
		put_cmp(&expressions, NFT_CMP_EQ, &ether, sizeof(ether));
		put_payload(&expressions, NFT_PAYLOAD_LL_HEADER, 6u, 6u);
		if (prefix) {
			put_mask(&expressions, mask, sizeof(mask));
		}
		put_cmp(&expressions, NFT_CMP_EQ, mac, sizeof(mac));
	}
	if (piece) {
		put_schedule(&expressions, piece);
	}
	/*
	 * **A logged `over` rule evaluates its meter once, in the log's rule**
	 * (0338), and tells the verdict's rule the answer in the packet mark's
	 * top bit, which netcfgd reserves: cleared ahead of the meter, so a packet
	 * arriving with it set says nothing, set past it, and ahead of the log's
	 * own rate, so a log line skipped is not a verdict skipped. The verdict's
	 * rule matches the bit in place of the meter and clears it again, so
	 * nothing after netcfgd's chain sees it.
	 */
	if (rule->over && rule->log && !as_log) {
		put_mark_test(&expressions);
		put_mark_set(&expressions, 0u);
	} else if (rule->over) {
		char set_name[NCFG_NFT_NAME_MAX];

		if (as_log) {
			put_mark_set(&expressions, 0u);
		}
		over_set_name(comment, family, set_name, sizeof(set_name));
		put_over(&expressions, rule->over, family, set_name, over_set_id);
		if (as_log) {
			put_mark_set(&expressions, NCFG_NFT_MARK_BIT);
		}
	}

	/*
	 * **A counter ahead of every verdict** (10.901), as nft 1.1.3 writes
	 * `counter`: both members, zero. A firewall that cannot say whether a
	 * rule is matching cannot be debugged, and `ncfg status` shows the
	 * count. Ahead of the verdict and after every match, `over`'s meter
	 * included, so it counts what the rule decided rather than what it
	 * looked at. Not on a log rule: its verdict's rule counts the same
	 * packets.
	 */
	if (!as_log) {
		ncfg_buf_init(&data, 0);
		put_be64(&data, NFTA_COUNTER_BYTES, 0u);
		put_be64(&data, NFTA_COUNTER_PACKETS, 0u);
		put_expression(&expressions, "counter", &data);
		ncfg_buf_free(&data);
	}

	ncfg_buf_init(&data, 0);
	if (as_log) {
		put_log(&expressions, chain, rule->name);
	} else if (rule->action == NCFG_FIREWALL_REJECT && rule->reset) {
		/* `reject with tcp reset` (0332): the type alone, as nft writes it. */
		put_be32(&data, NFTA_REJECT_TYPE, NFT_REJECT_TCP_RST);
		put_expression(&expressions, "reject", &data);
	} else if (rule->action == NCFG_FIREWALL_REJECT) {
		const uint8_t code = NFT_REJECT_ICMPX_PORT_UNREACH;

		put_be32(&data, NFTA_REJECT_TYPE, NFT_REJECT_ICMPX_UNREACH);
		ncfg_wire_attr_put(&data, NFTA_REJECT_ICMP_CODE, &code, 1u);
		put_expression(&expressions, "reject", &data);
	} else {
		ncfg_buf_t code;

		ncfg_buf_init(&code, 0);
		put_be32(&code, NFTA_VERDICT_CODE,
		    rule->action == NCFG_FIREWALL_DROP ? (uint32_t)NF_DROP : (uint32_t)NF_ACCEPT);
		ncfg_buf_init(&verdict, 0);
		ncfg_wire_attr_put_nested(&verdict, NFTA_DATA_VERDICT, &code);
		put_be32(&data, NFTA_IMMEDIATE_DREG, NFT_REG_VERDICT);
		ncfg_wire_attr_put_nested(&data, NFTA_IMMEDIATE_DATA, &verdict);
		put_expression(&expressions, "immediate", &data);
		ncfg_buf_free(&verdict);
		ncfg_buf_free(&code);
	}
	ncfg_buf_free(&data);

	/* nft's comment TLV, measured (0295): type 0, a length counting the NUL,
	 * the text and its NUL. */
	ncfg_buf_init(&userdata, 0);
	{
		const uint8_t head[2] = { 0u, (uint8_t)(strlen(comment) + 1u) };

		ncfg_buf_add(&userdata, head, sizeof(head));
		ncfg_buf_add(&userdata, comment, strlen(comment) + 1u);
	}
	ncfg_wire_attr_put_str(attrs, NFTA_RULE_TABLE, NCFG_NFT_TABLE);
	ncfg_wire_attr_put_str(attrs, NFTA_RULE_CHAIN, chain);
	ncfg_wire_attr_put_nested(attrs, NFTA_RULE_EXPRESSIONS, &expressions);
	ncfg_wire_attr_put(attrs, NFTA_RULE_USERDATA, userdata.data, userdata.length);
	ncfg_buf_free(&userdata);
	ncfg_buf_free(&expressions);
	return 1;
}

/*
 * How many kernel rules one written rule may become.
 *
 * **One per combination of values** (10.592 slice 2b): a rule with three
 * stations and two ports is six kernel rules, each carrying the written rule's
 * name and digest. The alternative is nftables' anonymous sets, which are
 * compact and native and need interval sets -- its most intricate encoding --
 * for every CIDR and OUI mask, with a decoder to match; the language and the
 * identity scheme would not change if sets replaced this. The bound keeps a
 * large host list from becoming thousands of rules silently: past it the rule
 * is refused and says why.
 */
#define FIREWALL_EXPANSION_MAX 256u

/*
 * A rule's addresses with each `@slot:NAME` (10.932) made two, `@slot:NAME/4`
 * and `/6` -- one kernel rule per family, as a set has one key length. NULL
 * and 0 where the list names no slot; *made says whether `out` was
 * allocated.
 */
static int expand_slots(char *const *in, size_t count, char ***out, size_t *out_count,
    int *made)
{
	size_t at;
	size_t slots = 0;
	size_t to = 0;
	char **list;

	*made = 0;
	*out = (char **)(uintptr_t)in;
	*out_count = count;
	for (at = 0; at < count; at++) {
		slots += strncmp(in[at], "@slot:", 6u) == 0 && !strchr(in[at], '/');
	}
	if (!slots) {
		return 1;
	}
	list = calloc(count + slots, sizeof(*list));
	if (!list) {
		return 0;
	}
	for (at = 0; at < count; at++) {
		if (strncmp(in[at], "@slot:", 6u) == 0 && !strchr(in[at], '/')) {
			size_t length = strlen(in[at]) + 3u;

			list[to] = malloc(length);
			list[to + 1u] = malloc(length);
			if (!list[to] || !list[to + 1u]) {
				free(list[to]);
				free(list[to + 1u]);
				ncfg_strings_free_list(list, to);
				return 0;
			}
			(void)snprintf(list[to], length, "%s/4", in[at]);
			(void)snprintf(list[to + 1u], length, "%s/6", in[at]);
			to += 2u;
		} else {
			list[to] = strdup(in[at]);
			if (!list[to]) {
				ncfg_strings_free_list(list, to);
				return 0;
			}
			to++;
		}
	}
	*out = list;
	*out_count = to;
	*made = 1;
	return 1;
}

static int firewall_rule_messages_one(ncfg_buf_t *transaction, uint32_t *seq,
    uint32_t *last_acked, const char *chain, const ncfg_firewall_rule_t *rule,
    const ncfg_firewall_rule_t *written, char *err, size_t err_size);

static int firewall_rule_messages(ncfg_buf_t *transaction, uint32_t *seq, uint32_t *last_acked,
    const char *chain, const ncfg_firewall_rule_t *rule, char *err, size_t err_size)
{
	ncfg_firewall_rule_t expanded = *rule;
	int                  made_from = 0;
	int                  made_to = 0;
	int                  ok;

	if (!expand_slots(rule->from, rule->from_count, &expanded.from, &expanded.from_count,
	        &made_from) ||
	    !expand_slots(rule->to, rule->to_count, &expanded.to, &expanded.to_count, &made_to)) {
		if (made_from) {
			ncfg_strings_free_list(expanded.from, expanded.from_count);
		}
		ncfg_error_set(err, err_size, "out of memory expanding rule `%s`'s slots", rule->name);
		return 0;
	}
	ok = firewall_rule_messages_one(transaction, seq, last_acked, chain,
	    made_from || made_to ? &expanded : rule, rule, err, err_size);
	if (made_from) {
		ncfg_strings_free_list(expanded.from, expanded.from_count);
	}
	if (made_to) {
		ncfg_strings_free_list(expanded.to, expanded.to_count);
	}
	return ok;
}

static int firewall_rule_messages_one(ncfg_buf_t *transaction, uint32_t *seq,
    uint32_t *last_acked, const char *chain, const ncfg_firewall_rule_t *rule,
    const ncfg_firewall_rule_t *written, char *err, size_t err_size)
{
	const size_t ports = rule->port_count + rule->port_range_count + rule->icmp_type_count
	    ? rule->port_count + rule->port_range_count + rule->icmp_type_count : 1u;
	const size_t froms = rule->from_count ? rule->from_count : 1u;
	const size_t tos = rule->to_count ? rule->to_count : 1u;
	const size_t macs = rule->mac_count ? rule->mac_count : 1u;
	char         comment[NCFG_NFT_COMMENT_MAX + 1u];
	ncfg_schedule_piece_t pieces[NCFG_SCHEDULE_PIECES_MAX];
	const long   piece_count = rule_pieces(rule, pieces);
	const size_t times = piece_count > 0 ? (size_t)piece_count : 1u;
	size_t       p, f, t, m, fam;
	size_t       families = 1u;
	int          has[2] = { 1, 1 };
	size_t       wrote = 0;

	if (piece_count < 0) {
		ncfg_error_set(err, err_size, "rule `%s/%s` has a schedule that cannot be read",
		    chain, rule->name);
		return 0;
	}
	if (ports * froms * tos * macs * times > FIREWALL_EXPANSION_MAX) {
		ncfg_error_set(err, err_size,
		    "rule `%s/%s` would be %zu kernel rules, one per combination of its ports, "
		    "addresses, stations and the pieces its schedule is in UTC, and %u is the most "
		    "one rule may become; split it",
		    chain, rule->name, ports * froms * tos * macs * times,
		    (unsigned)FIREWALL_EXPANSION_MAX);
		return 0;
	}
	/* The digest is the written rule's, slots unexpanded (10.932). */
	if (!rule_comment(chain, written, comment, sizeof(comment), err, err_size)) {
		return 0;
	}
	/* Which families an `over` rule counts in: those its addresses name, or
	 * both where it names none. */
	if (rule->over) {
		char *const *named = rule->from_count ? rule->from : rule->to;
		const size_t named_count = rule->from_count ? rule->from_count : rule->to_count;
		nft_address_t one_address;

		families = 2u;
		if (named_count) {
			has[0] = has[1] = 0;
			for (f = 0; f < named_count; f++) {
				if (parse_address(named[f], &one_address, NULL, 0)) {
					has[one_address.nfproto == NFPROTO_IPV6 ? 1 : 0] = 1;
				}
			}
		}
		/* **ICMP is one family's protocol** (10.905): `icmp` is IPv4's and
		 * `icmpv6` IPv6's, so the other family's meter and rule would match
		 * no packet -- and nft, printing `icmp type` with an `ip6 saddr`
		 * meter, writes a ruleset it cannot load back. */
		if (rule->protocol == NCFG_FIREWALL_PROTO_ICMP) {
			has[1] = 0;
		} else if (rule->protocol == NCFG_FIREWALL_PROTO_ICMPV6) {
			has[0] = 0;
		}
		if (!has[0] && !has[1]) {
			ncfg_error_set(err, err_size, "rule `%s/%s` counts `over` for %s from addresses "
			    "of the other family only, which no packet carries", chain, rule->name,
			    rule->protocol == NCFG_FIREWALL_PROTO_ICMP ? "icmp" : "icmpv6");
			return 0;
		}
	}
	/*
	 * **An `over` rule is one kernel rule per family as well**, where no
	 * address has chosen one: the meter's key is a source address, four bytes
	 * or sixteen, so each family counts in its own set -- made here, once,
	 * before the first rule that updates it.
	 */
	for (fam = 0; fam < families; fam++) {
		const uint8_t family = fam == 0u ? NFPROTO_IPV4 : NFPROTO_IPV6;
		const uint32_t set_id = *seq + 1000000u;

		if (rule->over && !has[fam]) {
			continue;
		}
		if (rule->over) {
			char set_name[NCFG_NFT_NAME_MAX];

			over_set_name(comment, family, set_name, sizeof(set_name));
			if (!over_set_message(transaction, seq, last_acked, set_name, set_id, family,
			        rule->over, err, err_size)) {
				return 0;
			}
		}
		for (p = 0; p < ports; p++) {
			for (f = 0; f < froms; f++) {
				for (t = 0; t < tos; t++) {
					for (m = 0; m < macs * times; m++) {
						ncfg_firewall_rule_t one = *rule;
						const size_t         mac_at = m / times;
						const ncfg_schedule_piece_t *piece =
						    piece_count > 0 ? &pieces[m % times] : NULL;
						nft_address_t        a;
						nft_address_t        b;
						ncfg_buf_t           attrs;
						int                  ok;

						/* The singles first, then the ranges (0331): one of
						 * either per kernel rule. */
						one.port_count = p < rule->port_count ? 1u : 0u;
						one.ports = p < rule->port_count ? &rule->ports[p] : NULL;
						one.port_range_count =
						    rule->port_range_count && p >= rule->port_count ? 1u : 0u;
						one.port_ranges = one.port_range_count
						    ? &rule->port_ranges[p - rule->port_count] : NULL;
						/* ICMP types share the dimension: a rule has them or
						 * ports, never both, which the compiler sees to. */
						one.icmp_type_count = rule->icmp_type_count ? 1u : 0u;
						one.icmp_types = rule->icmp_type_count ? &rule->icmp_types[p] : NULL;
						one.from_count = rule->from_count ? 1u : 0u;
						one.from = rule->from_count ? &rule->from[f] : NULL;
						one.to_count = rule->to_count ? 1u : 0u;
						one.to = rule->to_count ? &rule->to[t] : NULL;
						one.mac_count = rule->mac_count ? 1u : 0u;
						one.mac = rule->mac_count ? &rule->mac[mac_at] : NULL;
						/* A source of one family and a destination of the other
						 * is a combination no packet carries: skipped, not
						 * written as a rule that can never match. */
						if (one.from_count && one.to_count) {
							if (!parse_address(one.from[0], &a, err, err_size) ||
							    !parse_address(one.to[0], &b, err, err_size)) {
								return 0;
							}
							if (a.nfproto != b.nfproto) {
								continue;
							}
						}
						/* A family the meter is not for: an address of the
						 * other family is a rule the other set counts. */
						if (rule->over &&
						    ((one.from_count && parse_address(one.from[0], &a, NULL, 0) &&
						    a.nfproto != family) ||
						    (one.to_count && parse_address(one.to[0], &b, NULL, 0) &&
						    b.nfproto != family))) {
							continue;
						}
						/* The log's rule first, where there is one (0330): it
						 * has no verdict, so the packet goes on to the next. */
						int pass;

						for (pass = rule->log ? 0 : 1; pass < 2; pass++) {
							ncfg_buf_init(&attrs, 0);
							ok = firewall_rule(&attrs, chain, &one, piece, comment, family,
							    set_id, pass == 0, err, err_size);
							if (ok) {
								*last_acked = *seq;
								ok = build(transaction, NFT_MSG_NEWRULE,
								    (uint16_t)(NLM_F_ACK | NLM_F_CREATE | NLM_F_APPEND),
								    (*seq)++, NFPROTO_INET, &attrs, err, err_size);
							}
							ncfg_buf_free(&attrs);
							if (!ok) {
								return 0;
							}
						}
						wrote++;
					}
				}
			}
		}
	}
	if (wrote == 0u) {
		ncfg_error_set(err, err_size,
		    "rule `%s/%s` matches only IPv4 sources with IPv6 destinations or the reverse, "
		    "which no packet carries", chain, rule->name);
		return 0;
	}
	return 1;
}

/* ------------------------------------------------------------------------ *
 * Port forwards (0298)
 * ------------------------------------------------------------------------ */

/* `type nat hook prerouting priority dstnat`, for the forwards. */
static void prerouting_chain(ncfg_buf_t *attrs)
{
	ncfg_buf_t hook;

	ncfg_buf_init(&hook, 0);
	put_be32(&hook, NFTA_HOOK_HOOKNUM, NF_INET_PRE_ROUTING);
	put_be32(&hook, NFTA_HOOK_PRIORITY, (uint32_t)NF_IP_PRI_NAT_DST);
	ncfg_wire_attr_put_str(attrs, NFTA_CHAIN_TABLE, NCFG_NFT_TABLE);
	ncfg_wire_attr_put_str(attrs, NFTA_CHAIN_NAME, NCFG_NFT_CHAIN_PREROUTING);
	ncfg_wire_attr_put_nested(attrs, NFTA_CHAIN_HOOK, &hook);
	ncfg_wire_attr_put_str(attrs, NFTA_CHAIN_TYPE, "nat");
	ncfg_buf_free(&hook);
}

/* The role a kind of forward rule carries in its identity, after `@`; ""
 * for the forward itself (0299). */
static const char *forward_role(int kind)
{
	return kind == NCFG_FORWARD_RULE_REFLECT ? "reflect"
	    : kind == NCFG_FORWARD_RULE_HAIRPIN  ? "hairpin" : "";
}

/* The chain a kind of forward rule sits in: the return path is source NAT. */
static const char *forward_chain(int kind)
{
	return kind == NCFG_FORWARD_RULE_HAIRPIN ? NCFG_NFT_CHAIN : NCFG_NFT_CHAIN_PREROUTING;
}

int ncfg_nft_forward_text(const ncfg_forward_rule_t *forward, ncfg_buf_t *out)
{
	if (!forward || !out || !forward->interface || !forward->name || !forward->to) {
		return 0;
	}
	ncfg_buf_addf(out, "chain %s\ninterface %s\nprotocol %s\nport %u\nto %s\nto_port %u\n",
	    forward_chain(forward->kind), forward->interface,
	    forward->protocol == NCFG_PORT_FORWARD_UDP ? "udp" : "tcp", (unsigned)forward->port,
	    forward->to, (unsigned)forward->to_port);
	/* The forward itself has no role line, so its digest is the one 0298
	 * wrote and an installed forward from before 0299 still reads as itself. */
	if (forward->kind != NCFG_FORWARD_RULE_FORWARD) {
		ncfg_buf_addf(out, "role %s\n", forward_role(forward->kind));
	}
	if (forward->kind == NCFG_FORWARD_RULE_REFLECT) {
		ncfg_buf_addf(out, "address %s\n", forward->address ? forward->address : "");
	}
	if (forward->kind == NCFG_FORWARD_RULE_HAIRPIN) {
		ncfg_buf_addf(out, "network %s\nvia %s\n", forward->network ? forward->network : "",
		    forward->via ? forward->via : "");
	}
	/* Only where set (0336), so a forward from before has its digest. */
	if (forward->from && forward->kind != NCFG_FORWARD_RULE_HAIRPIN) {
		ncfg_buf_addf(out, "from %s\n", forward->from);
	}
	return !ncfg_buf_failed(out);
}

/* What one forward rule needs to be written: its host's bytes, and for the
 * kinds that have them the uplink address and the host's network. */
typedef struct {
	uint8_t       to[16];
	size_t        to_length; /* 4, or 16 for an IPv6 forward (0305) */
	uint8_t       address[4];
	nft_address_t network;
	nft_address_t from; /* the source allowed (0336), where `has_from` */
	int           has_from;
	char          comment[NCFG_NFT_COMMENT_MAX + 1u];
} forward_parts_t;

/* Everything a forward rule must be before a byte of it is written, and its
 * comment: `name=IF/NAME[@ROLE] sha256=DIGEST`. */
static int forward_checked(const ncfg_forward_rule_t *forward, forward_parts_t *parts, char *err,
    size_t err_size)
{
	ncfg_buf_t  text;
	char        digest[NCFG_SHA256_HEX_SIZE];
	const char *role = forward_role(forward->kind);
	int         wrote;

	memset(parts, 0, sizeof(*parts));
	if (!forward->name || !forward->to) {
		ncfg_error_set(err, err_size, "a port forward with no name or no address");
		return 0;
	}
	if (!valid_uplink(forward->interface, err, err_size)) {
		return 0;
	}
	/* **IPv6 for a plain forward only** (0305): DNS interception sends to
	 * the router's own IPv6 address. A reflection and a return path are the
	 * IPv4 port forward's, written for an uplink's one address and a
	 * masqueraded network. */
	if (inet_pton(AF_INET, forward->to, parts->to) == 1) {
		parts->to_length = 4u;
	} else if (forward->kind == NCFG_FORWARD_RULE_FORWARD &&
	    inet_pton(AF_INET6, forward->to, parts->to) == 1) {
		parts->to_length = 16u;
	} else {
		ncfg_error_set(err, err_size, "port forward `%s/%s` sends to `%s`, which is not an "
		    "IPv4 address", forward->interface, forward->name, forward->to);
		return 0;
	}
	if (forward->port == 0u || forward->to_port == 0u) {
		ncfg_error_set(err, err_size, "port forward `%s/%s` has a port of 0",
		    forward->interface, forward->name);
		return 0;
	}
	if (forward->kind == NCFG_FORWARD_RULE_REFLECT &&
	    (!forward->address || inet_pton(AF_INET, forward->address, parts->address) != 1)) {
		ncfg_error_set(err, err_size, "port forward `%s/%s` is reflected at `%s`, which is not "
		    "an IPv4 address", forward->interface, forward->name,
		    forward->address ? forward->address : "");
		return 0;
	}
	if (forward->kind == NCFG_FORWARD_RULE_HAIRPIN) {
		if (!forward->network || !parse_address(forward->network, &parts->network, err,
		        err_size) || parts->network.nfproto != NFPROTO_IPV4) {
			ncfg_error_set(err, err_size, "port forward `%s/%s` has a return path from `%s`, "
			    "which is not an IPv4 network", forward->interface, forward->name,
			    forward->network ? forward->network : "");
			return 0;
		}
		if (!valid_uplink(forward->via, err, err_size)) {
			return 0;
		}
	}
	/* A source (0336) limits who arrives, so it is the forward's and its
	 * reflections', never the return path's; and an IPv4 forward's. */
	if (forward->from) {
		if (forward->kind == NCFG_FORWARD_RULE_HAIRPIN || parts->to_length != 4u ||
		    !parse_address(forward->from, &parts->from, err, err_size) ||
		    parts->from.nfproto != NFPROTO_IPV4) {
			ncfg_error_set(err, err_size, "port forward `%s/%s` is limited to `%s`, which is "
			    "not an IPv4 source it can be limited to", forward->interface, forward->name,
			    forward->from);
			return 0;
		}
		parts->has_from = 1;
	}
	if (forward->kind != NCFG_FORWARD_RULE_FORWARD && forward->kind != NCFG_FORWARD_RULE_REFLECT &&
	    forward->kind != NCFG_FORWARD_RULE_HAIRPIN) {
		ncfg_error_set(err, err_size, "port forward `%s/%s` is of a kind netcfgd does not write",
		    forward->interface, forward->name);
		return 0;
	}
	ncfg_buf_init(&text, 0);
	if (!ncfg_nft_forward_text(forward, &text)) {
		ncfg_buf_free(&text);
		ncfg_error_set(err, err_size, "out of memory describing port forward `%s`",
		    forward->name);
		return 0;
	}
	ncfg_sha256_hex(text.data, text.length, digest);
	ncfg_buf_free(&text);
	wrote = snprintf(parts->comment, sizeof(parts->comment), "name=%s/%s%s%s sha256=%.*s",
	    forward->interface, forward->name, role[0] ? "@" : "", role, (int)NCFG_NFT_DIGEST_HEX,
	    digest);
	if (wrote < 0 || (size_t)wrote > NCFG_NFT_COMMENT_MAX || (size_t)wrote >= sizeof(parts->comment)) {
		ncfg_error_set(err, err_size,
		    "port forward `%s/%s` has a name too long for the %u characters an nftables "
		    "comment holds beside its digest", forward->interface, forward->name,
		    (unsigned)NCFG_NFT_COMMENT_MAX);
		return 0;
	}
	return 1;
}

/* An `immediate` loading BYTES into REGISTER. */
static void put_immediate(ncfg_buf_t *list, uint32_t reg, const void *bytes, size_t length)
{
	ncfg_buf_t data;

	ncfg_buf_init(&data, 0);
	put_be32(&data, NFTA_IMMEDIATE_DREG, reg);
	put_data(&data, NFTA_IMMEDIATE_DATA, bytes, length);
	put_expression(list, "immediate", &data);
	ncfg_buf_free(&data);
}

/*
 * One forward rule, as nft 1.1.3 writes it (0298, 0299, measured with
 * `--debug=netlink`):
 *
 *   forward  iifname "IF" tcp dport P dnat ip to A:Q
 *   reflect  iifname != "IF" ip daddr U tcp dport P dnat ip to A:Q
 *   hairpin  oifname "VIA" ip saddr NET ip daddr A tcp dport Q masquerade
 *
 * and a forward limited to a source (0336) matches `ip saddr S` in the forward
 * and each reflection, after the family:
 *
 *   forward  iifname "IF" ip saddr S tcp dport P dnat ip to A:Q
 *   reflect  iifname != "IF" ip daddr U ip saddr S tcp dport P dnat ip to A:Q
 *
 * The translated port is always loaded, so the decoder has one shape per kind.
 * An address is matched as the firewall matches one: the whole address, masked
 * where the prefix is short.
 */
static void forward_rule(ncfg_buf_t *attrs, const ncfg_forward_rule_t *forward,
    const forward_parts_t *parts)
{
	ncfg_buf_t     expressions;
	ncfg_buf_t     data;
	ncfg_buf_t     userdata;
	const uint8_t  number = forward->protocol == NCFG_PORT_FORWARD_UDP ? IPPROTO_UDP
	                                                                   : IPPROTO_TCP;
	const uint8_t  ipv4 = NFPROTO_IPV4;
	const uint8_t  ipv6 = NFPROTO_IPV6;
	const uint16_t port = htons(forward->kind == NCFG_FORWARD_RULE_HAIRPIN ? forward->to_port
	                                                                       : forward->port);
	const uint16_t to_port = htons(forward->to_port);
	nft_address_t  host;

	ncfg_buf_init(&expressions, 0);
	if (forward->kind == NCFG_FORWARD_RULE_HAIRPIN) {
		put_meta(&expressions, NFT_META_OIFNAME);
		put_cmp(&expressions, NFT_CMP_EQ, forward->via, strlen(forward->via) + 1u);
		put_meta(&expressions, NFT_META_NFPROTO);
		put_cmp(&expressions, NFT_CMP_EQ, &ipv4, 1u);
		put_address_match(&expressions, &parts->network, 1);
		memset(&host, 0, sizeof(host));
		host.nfproto = NFPROTO_IPV4;
		host.length = 4u;
		host.prefix = 32u;
		memcpy(host.bytes, parts->to, 4u);
		put_address_match(&expressions, &host, 0);
	} else {
		put_meta(&expressions, NFT_META_IIFNAME);
		put_cmp(&expressions,
		    forward->kind == NCFG_FORWARD_RULE_REFLECT ? NFT_CMP_NEQ : NFT_CMP_EQ,
		    forward->interface, strlen(forward->interface) + 1u);
		if (forward->kind == NCFG_FORWARD_RULE_REFLECT) {
			memset(&host, 0, sizeof(host));
			host.nfproto = NFPROTO_IPV4;
			host.length = 4u;
			host.prefix = 32u;
			memcpy(host.bytes, parts->address, 4u);
			put_meta(&expressions, NFT_META_NFPROTO);
			put_cmp(&expressions, NFT_CMP_EQ, &ipv4, 1u);
			put_address_match(&expressions, &host, 0);
		} else if (parts->has_from) {
			put_meta(&expressions, NFT_META_NFPROTO);
			put_cmp(&expressions, NFT_CMP_EQ, &ipv4, 1u);
		}
		if (parts->has_from) {
			put_address_match(&expressions, &parts->from, 1);
		}
		/* An IPv6 forward says its family, as `dnat ip6 to` makes nft do:
		 * the translation alone would pass IPv4 by, but the rule should not
		 * read as though it might apply to it. */
		if (parts->to_length == 16u) {
			put_meta(&expressions, NFT_META_NFPROTO);
			put_cmp(&expressions, NFT_CMP_EQ, &ipv6, 1u);
		}
	}
	put_meta(&expressions, NFT_META_L4PROTO);
	put_cmp(&expressions, NFT_CMP_EQ, &number, 1u);
	put_payload(&expressions, NFT_PAYLOAD_TRANSPORT_HEADER, 2u, 2u);
	put_cmp(&expressions, NFT_CMP_EQ, &port, sizeof(port));
	if (forward->kind == NCFG_FORWARD_RULE_HAIRPIN) {
		ncfg_buf_init(&data, 0);
		put_expression(&expressions, "masq", &data);
		ncfg_buf_free(&data);
	} else {
		put_immediate(&expressions, NFT_REG_1, parts->to, parts->to_length);
		put_immediate(&expressions, NFT_REG_2, &to_port, sizeof(to_port));
		ncfg_buf_init(&data, 0);
		put_be32(&data, NFTA_NAT_TYPE, NFT_NAT_DNAT);
		put_be32(&data, NFTA_NAT_FAMILY, parts->to_length == 16u ? NFPROTO_IPV6 : NFPROTO_IPV4);
		put_be32(&data, NFTA_NAT_REG_ADDR_MIN, NFT_REG_1);
		put_be32(&data, NFTA_NAT_REG_PROTO_MIN, NFT_REG_2);
		put_be32(&data, NFTA_NAT_FLAGS, NF_NAT_RANGE_PROTO_SPECIFIED);
		put_expression(&expressions, "nat", &data);
		ncfg_buf_free(&data);
	}

	ncfg_buf_init(&userdata, 0);
	{
		const uint8_t head[2] = { 0u, (uint8_t)(strlen(parts->comment) + 1u) };

		ncfg_buf_add(&userdata, head, sizeof(head));
		ncfg_buf_add(&userdata, parts->comment, strlen(parts->comment) + 1u);
	}
	ncfg_wire_attr_put_str(attrs, NFTA_RULE_TABLE, NCFG_NFT_TABLE);
	ncfg_wire_attr_put_str(attrs, NFTA_RULE_CHAIN, forward_chain(forward->kind));
	ncfg_wire_attr_put_nested(attrs, NFTA_RULE_EXPRESSIONS, &expressions);
	ncfg_wire_attr_put(attrs, NFTA_RULE_USERDATA, userdata.data, userdata.length);
	ncfg_buf_free(&userdata);
	ncfg_buf_free(&expressions);
}

/* Write every forward rule of one chain, in the order given. */
static int forward_messages(ncfg_buf_t *transaction, uint32_t *seq, uint32_t *last_acked,
    const ncfg_forward_rule_t *forwards, size_t forward_count, int postrouting, char *err,
    size_t err_size)
{
	size_t at;

	for (at = 0; at < forward_count; at++) {
		forward_parts_t parts;
		ncfg_buf_t      attrs;
		int             ok;

		if ((forwards[at].kind == NCFG_FORWARD_RULE_HAIRPIN) != postrouting) {
			continue;
		}
		if (!forward_checked(&forwards[at], &parts, err, err_size)) {
			return 0;
		}
		ncfg_buf_init(&attrs, 0);
		forward_rule(&attrs, &forwards[at], &parts);
		*last_acked = *seq;
		ok = build(transaction, NFT_MSG_NEWRULE,
		    (uint16_t)(NLM_F_ACK | NLM_F_CREATE | NLM_F_APPEND), (*seq)++, NFPROTO_INET,
		    &attrs, err, err_size);
		ncfg_buf_free(&attrs);
		if (!ok) {
			return 0;
		}
	}
	return 1;
}

/* ------------------------------------------------------------------------ *
 * Flow offload (0319)
 * ------------------------------------------------------------------------ */

/* `meta l4proto PROTO flow add @fastpath`. */
static void offload_rule(ncfg_buf_t *rule, uint8_t protocol)
{
	ncfg_buf_t expressions;
	ncfg_buf_t flow;

	ncfg_buf_init(&expressions, 0);
	put_meta(&expressions, NFT_META_L4PROTO);
	put_cmp(&expressions, NFT_CMP_EQ, &protocol, 1u);
	ncfg_buf_init(&flow, 0);
	ncfg_wire_attr_put_str(&flow, NFTA_FLOW_TABLE_NAME, NCFG_NFT_FLOWTABLE);
	put_expression(&expressions, "flow_offload", &flow);
	ncfg_wire_attr_put_str(rule, NFTA_RULE_TABLE, NCFG_NFT_TABLE);
	ncfg_wire_attr_put_str(rule, NFTA_RULE_CHAIN, NCFG_NFT_CHAIN_OFFLOAD);
	ncfg_wire_attr_put_nested(rule, NFTA_RULE_EXPRESSIONS, &expressions);
	ncfg_buf_free(&flow);
	ncfg_buf_free(&expressions);
}

int ncfg_nft_put_offload(ncfg_buf_t *transaction, uint32_t *seq, uint32_t *last_acked,
    int hardware, const char *const *devices, size_t device_count, char *err,
    size_t err_size)
{
	static const uint8_t protocols[2] = { IPPROTO_TCP, IPPROTO_UDP };
	ncfg_buf_t           attrs;
	ncfg_buf_t           hook;
	ncfg_buf_t           names;
	size_t               at;
	int                  ok;

	if (!transaction || !seq || !last_acked) {
		ncfg_error_set(err, err_size, "a flowtable needs a transaction to be written into");
		return 0;
	}
	/* A flowtable over no device is refused by the kernel, and one naming an
	 * absent device too, so the caller passes the links that exist. */
	if (device_count == 0u || !devices) {
		ncfg_error_set(err, err_size,
		    "flow offload has no device to offload between: no interface that forwards "
		    "or translates has a link yet");
		return 0;
	}
	for (at = 0; at < device_count; at++) {
		if (!valid_uplink(devices[at], err, err_size)) {
			return 0;
		}
	}

	ncfg_buf_init(&names, 0);
	for (at = 0; at < device_count; at++) {
		ncfg_wire_attr_put_str(&names, NFTA_DEVICE_NAME, devices[at]);
	}
	ncfg_buf_init(&hook, 0);
	put_be32(&hook, NFTA_FLOWTABLE_HOOK_NUM, NF_NETDEV_INGRESS);
	put_be32(&hook, NFTA_FLOWTABLE_HOOK_PRIORITY, 0u); /* `filter` */
	ncfg_wire_attr_put_nested(&hook, NFTA_FLOWTABLE_HOOK_DEVS, &names);
	ncfg_buf_init(&attrs, 0);
	ncfg_wire_attr_put_str(&attrs, NFTA_FLOWTABLE_TABLE, NCFG_NFT_TABLE);
	ncfg_wire_attr_put_str(&attrs, NFTA_FLOWTABLE_NAME, NCFG_NFT_FLOWTABLE);
	ncfg_wire_attr_put_nested(&attrs, NFTA_FLOWTABLE_HOOK, &hook);
	if (hardware) {
		put_be32(&attrs, NFTA_FLOWTABLE_FLAGS, NFT_FLOWTABLE_HW_OFFLOAD);
	}
	*last_acked = *seq;
	ok = build(transaction, NFT_MSG_NEWFLOWTABLE, (uint16_t)(NLM_F_ACK | NLM_F_CREATE),
	    (*seq)++, NFPROTO_INET, &attrs, err, err_size);
	ncfg_buf_free(&attrs);
	ncfg_buf_free(&hook);
	ncfg_buf_free(&names);

	/* Policy accept and nothing else to decide: this chain filters nothing,
	 * and an accept here overrides no other chain's drop. */
	if (ok) {
		ncfg_buf_init(&attrs, 0);
		filter_chain(&attrs, NCFG_NFT_CHAIN_OFFLOAD, NF_INET_FORWARD,
		    NCFG_FIREWALL_POLICY_ACCEPT);
		*last_acked = *seq;
		ok = build(transaction, NFT_MSG_NEWCHAIN, (uint16_t)(NLM_F_ACK | NLM_F_CREATE),
		    (*seq)++, NFPROTO_INET, &attrs, err, err_size);
		ncfg_buf_free(&attrs);
	}
	for (at = 0; ok && at < 2u; at++) {
		ncfg_buf_init(&attrs, 0);
		offload_rule(&attrs, protocols[at]);
		*last_acked = *seq;
		ok = build(transaction, NFT_MSG_NEWRULE, (uint16_t)(NLM_F_ACK | NLM_F_CREATE),
		    (*seq)++, NFPROTO_INET, &attrs, err, err_size);
		ncfg_buf_free(&attrs);
	}
	return ok;
}

/*
 * MSS clamping (0334)
 *
 * `oifname "X" tcp flags & (syn | rst) == syn tcp option maxseg size set rt
 * mtu`, and the same with `iifname`, as nft 1.1.3 encodes them (measured,
 * project.md 10.895): a forwarded connection's SYN, either way across the
 * interface, has its MSS lowered to what the route's MTU carries. That is
 * what keeps a site whose path drops ICMP from hanging behind a PPPoE
 * uplink's 1492 bytes.
 */
static void mss_rule(ncfg_buf_t *rule, const char *interface, int leaving)
{
	ncfg_buf_t     expressions;
	ncfg_buf_t     data;
	const uint8_t  tcp = IPPROTO_TCP;
	const uint8_t  flags = 0x06; /* syn | rst */
	const uint8_t  syn = 0x02;

	ncfg_buf_init(&expressions, 0);
	put_meta(&expressions, leaving ? NFT_META_OIFNAME : NFT_META_IIFNAME);
	put_cmp(&expressions, NFT_CMP_EQ, interface, strlen(interface) + 1u);
	put_meta(&expressions, NFT_META_L4PROTO);
	put_cmp(&expressions, NFT_CMP_EQ, &tcp, 1u);
	put_payload(&expressions, NFT_PAYLOAD_TRANSPORT_HEADER, 13u, 1u);
	put_mask(&expressions, &flags, 1u);
	put_cmp(&expressions, NFT_CMP_EQ, &syn, 1u);
	ncfg_buf_init(&data, 0);
	put_be32(&data, NFTA_RT_KEY, NFT_RT_TCPMSS);
	put_be32(&data, NFTA_RT_DREG, NFT_REG_1);
	put_expression(&expressions, "rt", &data);
	ncfg_buf_free(&data);
	ncfg_buf_init(&data, 0);
	put_be32(&data, NFTA_BYTEORDER_SREG, NFT_REG_1);
	put_be32(&data, NFTA_BYTEORDER_DREG, NFT_REG_1);
	put_be32(&data, NFTA_BYTEORDER_OP, NFT_BYTEORDER_HTON);
	put_be32(&data, NFTA_BYTEORDER_LEN, 2u);
	put_be32(&data, NFTA_BYTEORDER_SIZE, 2u);
	put_expression(&expressions, "byteorder", &data);
	ncfg_buf_free(&data);
	ncfg_buf_init(&data, 0);
	{
		const uint8_t maxseg = 2u; /* TCPOPT_MAXSEG */

		ncfg_wire_attr_put(&data, NFTA_EXTHDR_TYPE, &maxseg, 1u);
	}
	put_be32(&data, NFTA_EXTHDR_OFFSET, 2u);
	put_be32(&data, NFTA_EXTHDR_LEN, 2u);
	put_be32(&data, NFTA_EXTHDR_SREG, NFT_REG_1);
	put_be32(&data, NFTA_EXTHDR_OP, NFT_EXTHDR_OP_TCPOPT);
	put_expression(&expressions, "exthdr", &data);
	ncfg_buf_free(&data);
	ncfg_wire_attr_put_str(rule, NFTA_RULE_TABLE, NCFG_NFT_TABLE);
	ncfg_wire_attr_put_str(rule, NFTA_RULE_CHAIN, NCFG_NFT_CHAIN_MSS);
	ncfg_wire_attr_put_nested(rule, NFTA_RULE_EXPRESSIONS, &expressions);
	ncfg_buf_free(&expressions);
}

static int put_mss(ncfg_buf_t *transaction, uint32_t *seq, uint32_t *last_acked,
    const char *const *clamp, size_t clamp_count, char *err, size_t err_size)
{
	ncfg_buf_t attrs;
	ncfg_buf_t hook;
	size_t     at;
	int        ok;

	for (at = 0; at < clamp_count; at++) {
		if (!clamp[at] || !clamp[at][0] || strlen(clamp[at]) >= NCFG_NFT_IFNAME_MAX) {
			ncfg_error_set(err, err_size, "`%s` cannot be an interface to clamp the MSS on",
			    clamp[at] ? clamp[at] : "");
			return 0;
		}
	}
	/* Priority mangle, so the clamp is written before a filter at the same
	 * hook sees the packet; policy accept, since it decides nothing. */
	ncfg_buf_init(&hook, 0);
	put_be32(&hook, NFTA_HOOK_HOOKNUM, NF_INET_FORWARD);
	put_be32(&hook, NFTA_HOOK_PRIORITY, (uint32_t)NF_IP_PRI_MANGLE);
	ncfg_buf_init(&attrs, 0);
	ncfg_wire_attr_put_str(&attrs, NFTA_CHAIN_TABLE, NCFG_NFT_TABLE);
	ncfg_wire_attr_put_str(&attrs, NFTA_CHAIN_NAME, NCFG_NFT_CHAIN_MSS);
	ncfg_wire_attr_put_nested(&attrs, NFTA_CHAIN_HOOK, &hook);
	ncfg_wire_attr_put_str(&attrs, NFTA_CHAIN_TYPE, "filter");
	put_be32(&attrs, NFTA_CHAIN_POLICY, (uint32_t)NF_ACCEPT);
	*last_acked = *seq;
	ok = build(transaction, NFT_MSG_NEWCHAIN, (uint16_t)(NLM_F_ACK | NLM_F_CREATE), (*seq)++,
	    NFPROTO_INET, &attrs, err, err_size);
	ncfg_buf_free(&attrs);
	ncfg_buf_free(&hook);
	for (at = 0; ok && at < clamp_count * 2u; at++) {
		ncfg_buf_init(&attrs, 0);
		mss_rule(&attrs, clamp[at / 2u], at % 2u == 0u);
		*last_acked = *seq;
		ok = build(transaction, NFT_MSG_NEWRULE,
		    (uint16_t)(NLM_F_ACK | NLM_F_CREATE | NLM_F_APPEND), (*seq)++, NFPROTO_INET, &attrs,
		    err, err_size);
		ncfg_buf_free(&attrs);
	}
	return ok;
}

/* ------------------------------------------------------------------------ *
 * Slots (0340)
 * ------------------------------------------------------------------------ */

/* The readers' helpers, defined with the readers below. */
static int be64_member(const ncfg_wire_attrs_t *area, uint16_t kind, uint64_t *out);
static int data_value(const ncfg_wire_attrs_t *area, uint16_t kind, const uint8_t **bytes,
    size_t *length);

void ncfg_nft_slot_set_name(const char *slot, int ipv6, char *out, size_t out_size)
{
	(void)snprintf(out, out_size, "slot-%s-%c", slot ? slot : "", ipv6 ? '6' : '4');
}

/* What a slot's rule carries, which is the whole slot: the reader takes the
 * slot back from it, and the verdict and the lookup are checked against it. */
static int slot_comment(const ncfg_firewall_slot_t *slot, char *out, size_t out_size)
{
	int wrote = snprintf(out, out_size, "slot=%s match=%s timeout=%lld", slot->name,
	    slot->match == NCFG_FIREWALL_SLOT_TO ? "to" : "from", (long long)slot->timeout);

	return wrote > 0 && (size_t)wrote < out_size && (size_t)wrote <= NCFG_NFT_COMMENT_MAX;
}

/* The set: one family's addresses, each member with a lifetime of its own
 * where its writer gave one, the slot's `timeout` where not. No `eval` flag:
 * nothing in the ruleset writes into it, only a live write does. */
static int slot_set_message(ncfg_buf_t *transaction, uint32_t *seq, uint32_t *last_acked,
    const ncfg_firewall_slot_t *slot, uint8_t family, uint32_t set_id, char *err,
    size_t err_size)
{
	ncfg_buf_t attrs;
	char       set_name[NCFG_NFT_NAME_MAX];
	int        ok;

	ncfg_nft_slot_set_name(slot->name, family == NFPROTO_IPV6, set_name, sizeof(set_name));
	ncfg_buf_init(&attrs, 0);
	ncfg_wire_attr_put_str(&attrs, NFTA_SET_TABLE, NCFG_NFT_TABLE);
	ncfg_wire_attr_put_str(&attrs, NFTA_SET_NAME, set_name);
	put_be32(&attrs, NFTA_SET_FLAGS, NFT_SET_TIMEOUT);
	put_be32(&attrs, NFTA_SET_KEY_TYPE, family == NFPROTO_IPV6 ? 8u : 7u);
	put_be32(&attrs, NFTA_SET_KEY_LEN, family == NFPROTO_IPV6 ? 16u : 4u);
	put_be32(&attrs, NFTA_SET_ID, set_id);
	if (slot->timeout > 0) {
		put_be64(&attrs, NFTA_SET_TIMEOUT, (uint64_t)slot->timeout * 1000u);
	}
	*last_acked = *seq;
	ok = build(transaction, NFT_MSG_NEWSET, (uint16_t)(NLM_F_ACK | NLM_F_CREATE), (*seq)++,
	    NFPROTO_INET, &attrs, err, err_size);
	ncfg_buf_free(&attrs);
	return ok;
}

/*
 * One family's rule for a slot, as nft writes `ip saddr @slot-NAME-4 counter
 * drop`: the family, the address into register 1, the lookup, a counter, the
 * verdict -- `reject` as a rule's is, ICMPX port-unreachable.
 */
static void slot_rule(ncfg_buf_t *attrs, const char *chain, const ncfg_firewall_slot_t *slot,
    uint8_t family, uint32_t set_id, const char *comment)
{
	ncfg_buf_t expressions;
	ncfg_buf_t data;
	ncfg_buf_t userdata;
	char       set_name[NCFG_NFT_NAME_MAX];
	const int  source = slot->match != NCFG_FIREWALL_SLOT_TO;

	ncfg_nft_slot_set_name(slot->name, family == NFPROTO_IPV6, set_name, sizeof(set_name));
	ncfg_buf_init(&expressions, 0);
	put_meta(&expressions, NFT_META_NFPROTO);
	put_cmp(&expressions, NFT_CMP_EQ, &family, 1u);
	if (family == NFPROTO_IPV6) {
		put_payload(&expressions, NFT_PAYLOAD_NETWORK_HEADER, source ? 8u : 24u, 16u);
	} else {
		put_payload(&expressions, NFT_PAYLOAD_NETWORK_HEADER, source ? 12u : 16u, 4u);
	}
	ncfg_buf_init(&data, 0);
	ncfg_wire_attr_put_str(&data, NFTA_LOOKUP_SET, set_name);
	put_be32(&data, NFTA_LOOKUP_SREG, NFT_REG_1);
	put_be32(&data, NFTA_LOOKUP_SET_ID, set_id);
	put_expression(&expressions, "lookup", &data);
	ncfg_buf_free(&data);

	ncfg_buf_init(&data, 0);
	put_be64(&data, NFTA_COUNTER_BYTES, 0u);
	put_be64(&data, NFTA_COUNTER_PACKETS, 0u);
	put_expression(&expressions, "counter", &data);
	ncfg_buf_free(&data);

	ncfg_buf_init(&data, 0);
	if (slot->action == NCFG_FIREWALL_NONE) {
		/* Counted, and on to the next rule (10.933). */
	} else if (slot->action == NCFG_FIREWALL_REJECT) {
		const uint8_t code = NFT_REJECT_ICMPX_PORT_UNREACH;

		put_be32(&data, NFTA_REJECT_TYPE, NFT_REJECT_ICMPX_UNREACH);
		ncfg_wire_attr_put(&data, NFTA_REJECT_ICMP_CODE, &code, 1u);
		put_expression(&expressions, "reject", &data);
	} else {
		ncfg_buf_t code;
		ncfg_buf_t verdict;

		ncfg_buf_init(&code, 0);
		put_be32(&code, NFTA_VERDICT_CODE,
		    slot->action == NCFG_FIREWALL_DROP ? (uint32_t)NF_DROP : (uint32_t)NF_ACCEPT);
		ncfg_buf_init(&verdict, 0);
		ncfg_wire_attr_put_nested(&verdict, NFTA_DATA_VERDICT, &code);
		put_be32(&data, NFTA_IMMEDIATE_DREG, NFT_REG_VERDICT);
		ncfg_wire_attr_put_nested(&data, NFTA_IMMEDIATE_DATA, &verdict);
		put_expression(&expressions, "immediate", &data);
		ncfg_buf_free(&verdict);
		ncfg_buf_free(&code);
	}
	ncfg_buf_free(&data);

	ncfg_buf_init(&userdata, 0);
	{
		const uint8_t head[2] = { 0u, (uint8_t)(strlen(comment) + 1u) };

		ncfg_buf_add(&userdata, head, sizeof(head));
		ncfg_buf_add(&userdata, comment, strlen(comment) + 1u);
	}
	ncfg_wire_attr_put_str(attrs, NFTA_RULE_TABLE, NCFG_NFT_TABLE);
	ncfg_wire_attr_put_str(attrs, NFTA_RULE_CHAIN, chain);
	ncfg_wire_attr_put_nested(attrs, NFTA_RULE_EXPRESSIONS, &expressions);
	ncfg_wire_attr_put(attrs, NFTA_RULE_USERDATA, userdata.data, userdata.length);
	ncfg_buf_free(&userdata);
	ncfg_buf_free(&expressions);
}

/* One member as a set element: its key, and its lifetime where it has one. */
static void put_member(ncfg_buf_t *list, const uint8_t *address, int ipv6, uint64_t lifetime_ms)
{
	ncfg_buf_t element;
	ncfg_buf_t key;

	ncfg_buf_init(&element, 0);
	ncfg_buf_init(&key, 0);
	ncfg_wire_attr_put(&key, NFTA_DATA_VALUE, address, ipv6 ? 16u : 4u);
	ncfg_wire_attr_put_nested(&element, NFTA_SET_ELEM_KEY, &key);
	if (lifetime_ms > 0u) {
		put_be64(&element, NFTA_SET_ELEM_TIMEOUT, lifetime_ms);
	}
	ncfg_wire_attr_put_nested(list, NFTA_LIST_ELEM, &element);
	ncfg_buf_free(&key);
	ncfg_buf_free(&element);
}

/* The members of one slot's set of one family carried into it, one message,
 * after the set and before the rule that looks in it. Nothing where none. */
static int member_messages(ncfg_buf_t *transaction, uint32_t *seq, uint32_t *last_acked,
    const char *slot, int ipv6, uint32_t set_id, const ncfg_nft_slot_member_t *members,
    size_t member_count, char *err, size_t err_size)
{
	ncfg_buf_t attrs;
	ncfg_buf_t list;
	char       set_name[NCFG_NFT_NAME_MAX];
	size_t     at;
	size_t     carried = 0;
	int        ok;

	ncfg_buf_init(&list, 0);
	for (at = 0; at < member_count; at++) {
		if (members[at].ipv6 == ipv6 && strcmp(members[at].slot, slot) == 0) {
			put_member(&list, members[at].address, ipv6, members[at].remaining_ms);
			carried++;
		}
	}
	if (carried == 0u) {
		ncfg_buf_free(&list);
		return 1;
	}
	ncfg_nft_slot_set_name(slot, ipv6, set_name, sizeof(set_name));
	ncfg_buf_init(&attrs, 0);
	ncfg_wire_attr_put_str(&attrs, NFTA_SET_ELEM_LIST_TABLE, NCFG_NFT_TABLE);
	ncfg_wire_attr_put_str(&attrs, NFTA_SET_ELEM_LIST_SET, set_name);
	put_be32(&attrs, NFTA_SET_ELEM_LIST_SET_ID, set_id);
	ncfg_wire_attr_put_nested(&attrs, NFTA_SET_ELEM_LIST_ELEMENTS, &list);
	*last_acked = *seq;
	ok = build(transaction, NFT_MSG_NEWSETELEM, (uint16_t)(NLM_F_ACK | NLM_F_CREATE), (*seq)++,
	    NFPROTO_INET, &attrs, err, err_size);
	ncfg_buf_free(&attrs);
	ncfg_buf_free(&list);
	return ok;
}

/* A chain's slots: each one's two sets and the members carried into them,
 * then its two rules, ahead of the chain's first written rule -- 0339's
 * precedence. */
static int slot_messages(ncfg_buf_t *transaction, uint32_t *seq, uint32_t *last_acked,
    const char *chain, const ncfg_firewall_chain_t *written,
    const ncfg_nft_slot_member_t *members, size_t member_count, char *err, size_t err_size)
{
	size_t at;

	for (at = 0; at < written->slot_count; at++) {
		const ncfg_firewall_slot_t *slot = &written->slots[at];
		char                        comment[NCFG_NFT_COMMENT_MAX + 1u];
		uint32_t                    ids[2];
		size_t                      fam;

		if (!ncfg_firewall_slot_name_valid(slot->name) ||
		    !slot_comment(slot, comment, sizeof(comment))) {
			ncfg_error_set(err, err_size, "`%s` cannot name a slot",
			    slot->name ? slot->name : "");
			return 0;
		}
		for (fam = 0; fam < 2u; fam++) {
			ids[fam] = *seq + 2000000u;
			if (!slot_set_message(transaction, seq, last_acked, slot,
			        fam ? NFPROTO_IPV6 : NFPROTO_IPV4, ids[fam], err, err_size) ||
			    !member_messages(transaction, seq, last_acked, slot->name, (int)fam, ids[fam],
			        members, member_count, err, err_size)) {
				return 0;
			}
		}
		for (fam = 0; fam < 2u; fam++) {
			ncfg_buf_t attrs;
			int        ok;

			ncfg_buf_init(&attrs, 0);
			slot_rule(&attrs, chain, slot, fam ? NFPROTO_IPV6 : NFPROTO_IPV4, ids[fam],
			    comment);
			*last_acked = *seq;
			ok = build(transaction, NFT_MSG_NEWRULE,
			    (uint16_t)(NLM_F_ACK | NLM_F_CREATE | NLM_F_APPEND), (*seq)++, NFPROTO_INET,
			    &attrs, err, err_size);
			ncfg_buf_free(&attrs);
			if (!ok) {
				return 0;
			}
		}
	}
	return 1;
}

void ncfg_nft_slot_member_text(const ncfg_nft_slot_member_t *member, char *out,
    size_t out_size)
{
	format_address(member->ipv6 ? NFPROTO_IPV6 : NFPROTO_IPV4, member->address,
	    member->ipv6 ? 128u : 32u, out, out_size);
}

int ncfg_nft_slot_member_parse(const char *slot, const char *address,
    ncfg_nft_slot_member_t *out)
{
	nft_address_t parsed;

	if (!out || !ncfg_firewall_slot_name_valid(slot) || !address ||
	    !parse_address(address, &parsed, NULL, 0) || parsed.prefix != parsed.length * 8u) {
		return 0;
	}
	memset(out, 0, sizeof(*out));
	memcpy(out->slot, slot, strlen(slot) + 1u);
	out->ipv6 = parsed.nfproto == NFPROTO_IPV6;
	memcpy(out->address, parsed.bytes, parsed.length);
	return 1;
}

int ncfg_nft_build_slot_dump(ncfg_buf_t *out, uint32_t seq, const char *slot, int ipv6,
    char *err, size_t err_size)
{
	ncfg_buf_t attrs;
	char       set_name[NCFG_NFT_NAME_MAX];
	int        built;

	if (!ncfg_firewall_slot_name_valid(slot)) {
		ncfg_error_set(err, err_size, "`%s` cannot name a slot", slot ? slot : "");
		return 0;
	}
	ncfg_nft_slot_set_name(slot, ipv6, set_name, sizeof(set_name));
	ncfg_buf_init(&attrs, 0);
	ncfg_wire_attr_put_str(&attrs, NFTA_SET_ELEM_LIST_TABLE, NCFG_NFT_TABLE);
	ncfg_wire_attr_put_str(&attrs, NFTA_SET_ELEM_LIST_SET, set_name);
	built = build(out, NFT_MSG_GETSETELEM, NLM_F_DUMP, seq, NFPROTO_INET, &attrs, err,
	    err_size);
	ncfg_buf_free(&attrs);
	return built;
}

int ncfg_nft_slot_members_read(const void *payload, size_t length,
    ncfg_nft_slot_member_t **members, size_t *count, char *err, size_t err_size)
{
	ncfg_wire_attrs_t area;
	ncfg_wire_attrs_t list;
	ncfg_wire_attr_t  attr;
	char              name[NCFG_NFT_NAME_MAX];
	char              slot[NCFG_FIREWALL_SLOT_NAME_MAX + 1u];
	size_t            span;
	int               ipv6;

	if (!members || !count || !payload_attrs(payload, length, &area, err, err_size)) {
		return 0;
	}
	if (((const uint8_t *)payload)[0] != NFPROTO_INET ||
	    !read_name(&area, NFTA_SET_ELEM_LIST_TABLE, name, sizeof(name), err, err_size) ||
	    strcmp(name, NCFG_NFT_TABLE) != 0 ||
	    !read_name(&area, NFTA_SET_ELEM_LIST_SET, name, sizeof(name), err, err_size)) {
		ncfg_error_set(err, err_size, "set members outside netcfgd's table, which are not read");
		return 0;
	}
	span = strlen(name);
	if (span < 8u || strncmp(name, "slot-", 5) != 0 || name[span - 2u] != '-' ||
	    (name[span - 1u] != '4' && name[span - 1u] != '6') ||
	    span - 7u > NCFG_FIREWALL_SLOT_NAME_MAX) {
		ncfg_error_set(err, err_size, "members of `%s`, which is not a slot's set", name);
		return 0;
	}
	memcpy(slot, name + 5, span - 7u);
	slot[span - 7u] = '\0';
	ipv6 = name[span - 1u] == '6';
	if (!ncfg_firewall_slot_name_valid(slot)) {
		ncfg_error_set(err, err_size, "members of `%s`, which is not a slot's set", name);
		return 0;
	}
	if (ncfg_wire_attrs_find(&area, NFTA_SET_ELEM_LIST_ELEMENTS, &attr, NULL, 0) !=
	        NCFG_WIRE_OK) {
		return 1; /* a set with no members */
	}
	ncfg_wire_attrs_start(&list, attr.value, attr.length);
	while (ncfg_wire_attrs_next(&list, &attr, NULL, 0) == NCFG_WIRE_OK) {
		ncfg_wire_attrs_t       element;
		const uint8_t          *bytes = NULL;
		size_t                  bytes_length = 0;
		uint64_t                timeout = 0, expiration = 0;
		ncfg_nft_slot_member_t *grown;
		ncfg_nft_slot_member_t *one;

		if (attr.kind != NFTA_LIST_ELEM) {
			continue;
		}
		ncfg_wire_attrs_start(&element, attr.value, attr.length);
		if (!data_value(&element, NFTA_SET_ELEM_KEY, &bytes, &bytes_length) ||
		    bytes_length != (ipv6 ? 16u : 4u)) {
			ncfg_error_set(err, err_size, "a member of `%s` whose key is %zu bytes", name,
			    bytes_length);
			return 0;
		}
		(void)be64_member(&element, NFTA_SET_ELEM_TIMEOUT, &timeout);
		(void)be64_member(&element, NFTA_SET_ELEM_EXPIRATION, &expiration);
		grown = realloc(*members, (*count + 1u) * sizeof(*grown));
		if (!grown) {
			ncfg_error_set(err, err_size, "out of memory reading a slot's members");
			return 0;
		}
		*members = grown;
		one = &grown[(*count)++];
		memset(one, 0, sizeof(*one));
		memcpy(one->slot, slot, strlen(slot) + 1u);
		one->ipv6 = ipv6;
		memcpy(one->address, bytes, bytes_length);
		/* What is left, where the member has a lifetime at all. A member
		 * about to expire is carried with a millisecond rather than none,
		 * which would make it permanent. */
		one->remaining_ms = timeout ? (expiration ? expiration : 1u) : 0u;
	}
	return 1;
}

int ncfg_nft_build_slot_write(ncfg_buf_t *out, uint32_t first_seq, const char *slot, int add,
    const char *address, uint64_t seconds, ncfg_nft_batch_t *batch, char *err,
    size_t err_size)
{
	ncfg_buf_t    transaction;
	ncfg_buf_t    attrs;
	ncfg_buf_t    list;
	nft_address_t parsed;
	char          set_name[NCFG_NFT_NAME_MAX];
	uint32_t      seq = first_seq;
	uint32_t      last_acked = first_seq;
	int           ok;

	if (!out || !batch || !address) {
		ncfg_error_set(err, err_size, "a slot write needs a member and somewhere to go");
		return 0;
	}
	memset(batch, 0, sizeof(*batch));
	if (!ncfg_firewall_slot_name_valid(slot)) {
		ncfg_error_set(err, err_size, "`%s` cannot name a slot", slot ? slot : "");
		return 0;
	}
	if (!parse_address(address, &parsed, err, err_size)) {
		return 0;
	}
	if (parsed.prefix != parsed.length * 8u) {
		ncfg_error_set(err, err_size,
		    "`%s` is a network, and a slot's members are single addresses (0340)", address);
		return 0;
	}
	if (seconds > 604800u) {
		ncfg_error_set(err, err_size, "a member lives a week at most");
		return 0;
	}
	ncfg_nft_slot_set_name(slot, parsed.nfproto == NFPROTO_IPV6, set_name, sizeof(set_name));
	ncfg_buf_init(&transaction, 0);
	ncfg_buf_init(&attrs, 0);
	ncfg_buf_init(&list, 0);
	put_member(&list, parsed.bytes, parsed.nfproto == NFPROTO_IPV6, add ? seconds * 1000u : 0u);
	ncfg_wire_attr_put_str(&attrs, NFTA_SET_ELEM_LIST_TABLE, NCFG_NFT_TABLE);
	ncfg_wire_attr_put_str(&attrs, NFTA_SET_ELEM_LIST_SET, set_name);
	ncfg_wire_attr_put_nested(&attrs, NFTA_SET_ELEM_LIST_ELEMENTS, &list);
	ok = batch_marker(&transaction, NFNL_MSG_BATCH_BEGIN, seq++, err, err_size);
	if (ok) {
		last_acked = seq;
		/* Adding a member already there renews it rather than failing: no
		 * NLM_F_EXCL, so a writer that repeats itself is not an error. */
		ok = build(&transaction, add ? NFT_MSG_NEWSETELEM : NFT_MSG_DELSETELEM,
		    (uint16_t)(NLM_F_ACK | (add ? NLM_F_CREATE : 0)), seq++, NFPROTO_INET, &attrs, err,
		    err_size);
	}
	if (ok) {
		ok = batch_marker(&transaction, NFNL_MSG_BATCH_END, seq++, err, err_size);
	}
	if (ok) {
		ok = ncfg_nft_writes_only_our_table(transaction.data, transaction.length, err,
		    err_size);
	}
	if (ok) {
		ncfg_buf_add(out, transaction.data, transaction.length);
		ok = !ncfg_buf_failed(out);
	}
	if (ok) {
		batch->last_acked = last_acked;
		batch->next_seq = seq;
	}
	ncfg_buf_free(&list);
	ncfg_buf_free(&attrs);
	ncfg_buf_free(&transaction);
	return ok;
}

int ncfg_nft_build_replace_nat(ncfg_buf_t *out, uint32_t first_seq, int table_exists,
    const char *const *uplinks, size_t uplink_count, ncfg_nft_batch_t *batch,
    char *err, size_t err_size)
{
	return ncfg_nft_build_replace(out, first_seq, table_exists, uplinks, uplink_count, NULL,
	    batch, err, err_size);
}

int ncfg_nft_build_replace(ncfg_buf_t *out, uint32_t first_seq, int table_exists,
    const char *const *uplinks, size_t uplink_count, const ncfg_firewall_t *firewall,
    ncfg_nft_batch_t *batch, char *err, size_t err_size)
{
	return ncfg_nft_build_replace_all(out, first_seq, table_exists, uplinks, uplink_count,
	    firewall, NULL, 0, NULL, NULL, 0, batch, err, err_size);
}

int ncfg_nft_build_replace_all(ncfg_buf_t *out, uint32_t first_seq, int table_exists,
    const char *const *uplinks, size_t uplink_count, const ncfg_firewall_t *firewall,
    const ncfg_forward_rule_t *forwards, size_t forward_count,
    const ncfg_nft_offload_t *offload, const char *const *clamp, size_t clamp_count,
    ncfg_nft_batch_t *batch, char *err, size_t err_size)
{
	return ncfg_nft_build_replace_carrying(out, first_seq, table_exists, uplinks, uplink_count,
	    firewall, forwards, forward_count, offload, clamp, clamp_count, NULL, 0, batch, err,
	    err_size);
}

int ncfg_nft_build_replace_carrying(ncfg_buf_t *out, uint32_t first_seq, int table_exists,
    const char *const *uplinks, size_t uplink_count, const ncfg_firewall_t *firewall,
    const ncfg_forward_rule_t *forwards, size_t forward_count,
    const ncfg_nft_offload_t *offload, const char *const *clamp, size_t clamp_count,
    const ncfg_nft_slot_member_t *members, size_t member_count, ncfg_nft_batch_t *batch,
    char *err, size_t err_size)
{
	ncfg_buf_t transaction;
	ncfg_buf_t attrs;
	size_t     hairpins = 0;
	size_t     translations = 0;
	uint32_t seq = first_seq;
	uint32_t last_acked = first_seq;
	size_t at;
	int ok;

	if (!out || !batch) {
		ncfg_error_set(err, err_size, "a transaction needs somewhere to be built");
		return 0;
	}
	memset(batch, 0, sizeof(*batch));
	batch->last_acked = first_seq;
	batch->next_seq = first_seq;
	if (uplink_count > 0 && !uplinks) {
		ncfg_error_set(err, err_size, "%zu uplinks with no names behind them",
		    uplink_count);
		return 0;
	}
	/* Every name is checked before a byte is written, so a bad one is a
	 * refusal rather than a half-built transaction the caller has to know not
	 * to send. */
	for (at = 0; at < uplink_count; at++) {
		if (!valid_uplink(uplinks[at], err, err_size)) {
			return 0;
		}
	}
	if (forward_count > 0 && !forwards) {
		ncfg_error_set(err, err_size, "%zu port forwards with nothing behind them",
		    forward_count);
		return 0;
	}
	/* The forwards too, before anything is written; and which chains they
	 * need -- the return paths are source NAT and sit in `postrouting`. */
	for (at = 0; at < forward_count; at++) {
		forward_parts_t parts;

		if (!forward_checked(&forwards[at], &parts, err, err_size)) {
			return 0;
		}
		if (forwards[at].kind == NCFG_FORWARD_RULE_HAIRPIN) {
			hairpins++;
		} else {
			translations++;
		}
	}
	if (!table_exists && uplink_count == 0 && !firewall && forward_count == 0 && !offload &&
	    clamp_count == 0) {
		/* Nothing to remove and nothing to create. See `empty` in nft.h:
		 * the begin-and-end transaction this would otherwise produce asks
		 * for no acknowledgement and receives no reply, so a caller that
		 * sent it would wait out its own timeout and call that a failure to
		 * configure NAT. */
		batch->empty = 1;
		return 1;
	}

	ncfg_buf_init(&transaction, 0);
	ok = batch_marker(&transaction, NFNL_MSG_BATCH_BEGIN, seq++, err, err_size);

	/*
	 * Deleting first is what makes this a replacement rather than an
	 * accumulation, and it is what "netcfgd owns this table" means in
	 * practice: rules an operator added inside it go, exactly as an address
	 * netcfgd owns goes when the document stops asking for it.
	 */
	if (ok && table_exists) {
		ncfg_buf_init(&attrs, 0);
		ncfg_wire_attr_put_str(&attrs, NFTA_TABLE_NAME, NCFG_NFT_TABLE);
		last_acked = seq;
		ok = build(&transaction, NFT_MSG_DELTABLE, NLM_F_ACK, seq++, NFPROTO_INET,
		    &attrs, err, err_size);
		ncfg_buf_free(&attrs);
	}

	if (ok && (uplink_count > 0 || firewall || forward_count > 0 || offload || clamp_count > 0)) {
		ncfg_buf_init(&attrs, 0);
		ncfg_wire_attr_put_str(&attrs, NFTA_TABLE_NAME, NCFG_NFT_TABLE);
		last_acked = seq;
		/* `inet`, the family that sees both IPv4 and IPv6, so one table
		 * masquerades both rather than two tables each doing half. */
		ok = build(&transaction, NFT_MSG_NEWTABLE, (uint16_t)(NLM_F_ACK | NLM_F_CREATE),
		    seq++, NFPROTO_INET, &attrs, err, err_size);
		ncfg_buf_free(&attrs);

		if (ok && (uplink_count > 0 || hairpins > 0)) {
			ncfg_buf_init(&attrs, 0);
			nat_chain(&attrs);
			last_acked = seq;
			ok = build(&transaction, NFT_MSG_NEWCHAIN,
			    (uint16_t)(NLM_F_ACK | NLM_F_CREATE), seq++, NFPROTO_INET, &attrs,
			    err, err_size);
			ncfg_buf_free(&attrs);
		}
		for (at = 0; ok && at < uplink_count; at++) {
			ncfg_buf_init(&attrs, 0);
			masquerade_rule(&attrs, uplinks[at]);
			last_acked = seq;
			ok = build(&transaction, NFT_MSG_NEWRULE,
			    (uint16_t)(NLM_F_ACK | NLM_F_CREATE), seq++, NFPROTO_INET, &attrs,
			    err, err_size);
			ncfg_buf_free(&attrs);
		}
		/* The return paths after the masquerade: the two never match one
		 * packet, since one leaves on the uplink and the other towards a host
		 * behind it. */
		if (ok) {
			ok = forward_messages(&transaction, &seq, &last_acked, forwards, forward_count, 1,
			    err, err_size);
		}
		/* The forwards' chain before the filter chains: translation happens at
		 * prerouting, and `nft list ruleset` then reads in packet order. */
		if (ok && translations > 0) {
			ncfg_buf_init(&attrs, 0);
			prerouting_chain(&attrs);
			last_acked = seq;
			ok = build(&transaction, NFT_MSG_NEWCHAIN,
			    (uint16_t)(NLM_F_ACK | NLM_F_CREATE), seq++, NFPROTO_INET, &attrs,
			    err, err_size);
			ncfg_buf_free(&attrs);
		}
		if (ok) {
			ok = forward_messages(&transaction, &seq, &last_acked, forwards, forward_count, 0,
			    err, err_size);
		}
		if (ok && firewall) {
			const ncfg_firewall_chain_t *chains[3] = { &firewall->input, &firewall->forward,
				&firewall->output };
			static const char *const names[3] = { NCFG_NFT_CHAIN_INPUT,
				NCFG_NFT_CHAIN_FORWARD, NCFG_NFT_CHAIN_OUTPUT };
			static const uint32_t hooks[3] = { NF_INET_LOCAL_IN, NF_INET_FORWARD,
				NF_INET_LOCAL_OUT };
			size_t c;

			for (c = 0; ok && c < 3u; c++) {
				size_t r;

				ncfg_buf_init(&attrs, 0);
				filter_chain(&attrs, names[c], hooks[c], chains[c]->policy);
				last_acked = seq;
				ok = build(&transaction, NFT_MSG_NEWCHAIN,
				    (uint16_t)(NLM_F_ACK | NLM_F_CREATE), seq++, NFPROTO_INET, &attrs,
				    err, err_size);
				ncfg_buf_free(&attrs);
				if (ok) {
					ok = slot_messages(&transaction, &seq, &last_acked, names[c],
					    chains[c], members, member_count, err, err_size);
				}
				for (r = 0; ok && r < chains[c]->rule_count; r++) {
					ok = firewall_rule_messages(&transaction, &seq, &last_acked, names[c],
					    &chains[c]->rules[r], err, err_size);
				}
			}
		}
		/* Flow offload last (0319): its chain sits at the forward hook beside
		 * the firewall's, and filters nothing. */
		if (ok && offload) {
			ok = ncfg_nft_put_offload(&transaction, &seq, &last_acked, offload->hardware,
			    offload->devices, offload->device_count, err, err_size);
		}
		/* MSS clamping (0334), at the forward hook before the filter. */
		if (ok && clamp_count > 0) {
			ok = put_mss(&transaction, &seq, &last_acked, clamp, clamp_count, err, err_size);
		}
	}

	if (ok) {
		ok = batch_marker(&transaction, NFNL_MSG_BATCH_END, seq++, err, err_size);
	}
	/*
	 * **The audit, on the bytes rather than on the intention.**
	 *
	 * Everything above writes `NCFG_NFT_TABLE` from the constant and there is
	 * no argument that could make it write anything else -- and that is an
	 * argument about the code as it stands today, which is the kind of
	 * argument decision 0022 is too expensive to rest on. So the finished
	 * transaction is walked back and every message in it that would change
	 * something is held to the one table and the one chain. A refusal here
	 * appends nothing: there is nothing safe to send.
	 */
	if (ok) {
		ok = ncfg_nft_writes_only_our_table(transaction.data, transaction.length, err,
		    err_size);
	}
	if (ok) {
		ncfg_buf_add(out, transaction.data, transaction.length);
		if (ncfg_buf_failed(out)) {
			ncfg_error_set(err, err_size,
			    "a %zu-byte transaction did not fit its buffer", transaction.length);
			ok = 0;
		}
	}
	if (ok) {
		batch->last_acked = last_acked;
		batch->next_seq = seq;
	}
	ncfg_buf_free(&transaction);
	return ok;
}

/* One of the UPnP table's chains: hooked, accepting by policy, empty. */
static void upnp_chain(ncfg_buf_t *attrs, const char *name, const char *type, uint32_t hook,
    int32_t priority)
{
	ncfg_buf_t nest;

	ncfg_buf_init(&nest, 0);
	put_be32(&nest, NFTA_HOOK_HOOKNUM, hook);
	/* Signed on the wire, as `nat_chain` says. */
	put_be32(&nest, NFTA_HOOK_PRIORITY, (uint32_t)priority);
	ncfg_wire_attr_put_str(attrs, NFTA_CHAIN_TABLE, NCFG_NFT_UPNP_TABLE);
	ncfg_wire_attr_put_str(attrs, NFTA_CHAIN_NAME, name);
	ncfg_wire_attr_put_nested(attrs, NFTA_CHAIN_HOOK, &nest);
	ncfg_wire_attr_put_str(attrs, NFTA_CHAIN_TYPE, type);
	put_be32(attrs, NFTA_CHAIN_POLICY, (uint32_t)NF_ACCEPT);
	ncfg_buf_free(&nest);
}

int ncfg_nft_build_upnp_table(ncfg_buf_t *out, uint32_t first_seq, int table_exists, int wanted,
    ncfg_nft_batch_t *batch, char *err, size_t err_size)
{
	static const struct {
		const char *name;
		const char *type;
		uint32_t    hook;
		int32_t     priority;
	} chains[3] = {
		{ NCFG_NFT_UPNP_CHAIN_FORWARD, "filter", NF_INET_FORWARD, 0 },
		{ NCFG_NFT_UPNP_CHAIN_PREROUTING, "nat", NF_INET_PRE_ROUTING, NF_IP_PRI_NAT_DST },
		{ NCFG_NFT_UPNP_CHAIN_POSTROUTING, "nat", NF_INET_POST_ROUTING, NF_IP_PRI_NAT_SRC },
	};
	ncfg_buf_t transaction;
	ncfg_buf_t attrs;
	uint32_t   seq = first_seq;
	uint32_t   last_acked = first_seq;
	size_t     at;
	int        ok;

	if (!out || !batch) {
		ncfg_error_set(err, err_size, "a transaction needs somewhere to be built");
		return 0;
	}
	memset(batch, 0, sizeof(*batch));
	batch->last_acked = first_seq;
	batch->next_seq = first_seq;
	if (!table_exists && !wanted) {
		batch->empty = 1;
		return 1;
	}
	ncfg_buf_init(&transaction, 0);
	ok = batch_marker(&transaction, NFNL_MSG_BATCH_BEGIN, seq++, err, err_size);
	/* Deleted first, so a start always begins from the empty structure and a
	 * mapping a stopped miniupnpd left behind -- 0310's third measurement --
	 * cannot outlive it. */
	if (ok && table_exists) {
		ncfg_buf_init(&attrs, 0);
		ncfg_wire_attr_put_str(&attrs, NFTA_TABLE_NAME, NCFG_NFT_UPNP_TABLE);
		last_acked = seq;
		ok = build(&transaction, NFT_MSG_DELTABLE, NLM_F_ACK, seq++, NFPROTO_INET, &attrs,
		    err, err_size);
		ncfg_buf_free(&attrs);
	}
	if (ok && wanted) {
		ncfg_buf_init(&attrs, 0);
		ncfg_wire_attr_put_str(&attrs, NFTA_TABLE_NAME, NCFG_NFT_UPNP_TABLE);
		last_acked = seq;
		ok = build(&transaction, NFT_MSG_NEWTABLE, (uint16_t)(NLM_F_ACK | NLM_F_CREATE),
		    seq++, NFPROTO_INET, &attrs, err, err_size);
		ncfg_buf_free(&attrs);
		for (at = 0; ok && at < 3u; at++) {
			ncfg_buf_init(&attrs, 0);
			upnp_chain(&attrs, chains[at].name, chains[at].type, chains[at].hook,
			    chains[at].priority);
			last_acked = seq;
			ok = build(&transaction, NFT_MSG_NEWCHAIN, (uint16_t)(NLM_F_ACK | NLM_F_CREATE),
			    seq++, NFPROTO_INET, &attrs, err, err_size);
			ncfg_buf_free(&attrs);
		}
	}
	if (ok) {
		ok = batch_marker(&transaction, NFNL_MSG_BATCH_END, seq++, err, err_size);
	}
	if (ok) {
		ok = ncfg_nft_writes_only_upnp_table(transaction.data, transaction.length, err,
		    err_size);
	}
	if (ok) {
		ncfg_buf_add(out, transaction.data, transaction.length);
		if (ncfg_buf_failed(out)) {
			ncfg_error_set(err, err_size,
			    "a %zu-byte transaction did not fit its buffer", transaction.length);
			ok = 0;
		}
	}
	if (ok) {
		batch->last_acked = last_acked;
		batch->next_seq = seq;
	}
	ncfg_buf_free(&transaction);
	return ok;
}

/* ------------------------------------------------------------------------ *
 * Reading replies
 * ------------------------------------------------------------------------ */

int ncfg_nft_table_read(const void *payload, size_t length, ncfg_nft_table_t *out,
    char *err, size_t err_size)
{
	ncfg_wire_attrs_t area;

	if (!out) {
		ncfg_error_set(err, err_size, "a table needs somewhere to go");
		return 0;
	}
	memset(out, 0, sizeof(*out));
	if (!payload_attrs(payload, length, &area, err, err_size)) {
		return 0;
	}
	out->family = ((const uint8_t *)payload)[0];
	return read_name(&area, NFTA_TABLE_NAME, out->name, sizeof(out->name), err, err_size);
}

int ncfg_nft_chain_read(const void *payload, size_t length, ncfg_nft_chain_t *out,
    char *err, size_t err_size)
{
	ncfg_wire_attrs_t area;
	ncfg_wire_attrs_t hook;
	ncfg_wire_attr_t attr;

	if (!out) {
		ncfg_error_set(err, err_size, "a chain needs somewhere to go");
		return 0;
	}
	memset(out, 0, sizeof(*out));
	if (!payload_attrs(payload, length, &area, err, err_size)) {
		return 0;
	}
	if (!read_name(&area, NFTA_CHAIN_TABLE, out->table, sizeof(out->table), err, err_size) ||
	    !read_name(&area, NFTA_CHAIN_NAME, out->name, sizeof(out->name), err, err_size)) {
		return 0;
	}
	out->family = ((const uint8_t *)payload)[0];
	/* The type and the hook are absent on a regular chain, which is not a
	 * malformed record: a chain with neither is one that only runs when
	 * another chain jumps to it, and it hooks nothing. */
	if (ncfg_wire_attrs_find(&area, NFTA_CHAIN_TYPE, &attr, NULL, 0) == NCFG_WIRE_OK &&
	    !ncfg_wire_attr_string(&attr, out->kind, sizeof(out->kind), err, err_size)) {
		return 0;
	}
	if (ncfg_wire_attrs_find(&area, NFTA_CHAIN_POLICY, &attr, NULL, 0) == NCFG_WIRE_OK) {
		if (!attr_be32(&attr, &out->policy, err, err_size)) {
			return 0;
		}
		out->has_policy = 1;
	}
	if (ncfg_wire_attrs_find(&area, NFTA_CHAIN_HOOK, &attr, NULL, 0) == NCFG_WIRE_OK) {
		ncfg_wire_attrs_start(&hook, attr.value, attr.length);
		if (ncfg_wire_attrs_find(&hook, NFTA_HOOK_HOOKNUM, &attr, NULL, 0) ==
		    NCFG_WIRE_OK) {
			if (!attr_be32(&attr, &out->hook, err, err_size)) {
				return 0;
			}
			out->has_hook = 1;
		}
	}
	return 1;
}

int ncfg_nft_table_is_ours(const ncfg_nft_table_t *table)
{
	/* Family and name together: `ip netcfgd` would be a table with netcfgd's
	 * name that netcfgd did not create, and creating ours is what makes the
	 * name ours. */
	return table && table->family == NFPROTO_INET &&
	    strcmp(table->name, NCFG_NFT_TABLE) == 0;
}

int ncfg_nft_chain_is_source_nat(const ncfg_nft_chain_t *chain)
{
	return chain && strcmp(chain->kind, "nat") == 0 && chain->has_hook &&
	    chain->hook == NF_INET_POST_ROUTING;
}

/* One expression of a rule, folded into what has been seen so far. */
typedef struct {
	int      reads_oifname;
	int      compares_equal;
	int      masquerades;
	uint32_t loaded_into;
	uint32_t compared_from;
	char     name[NCFG_NFT_IFNAME_MAX];
} masquerade_t;

static int read_meta(const ncfg_wire_attrs_t *data, masquerade_t *seen)
{
	ncfg_wire_attr_t attr;
	uint32_t key = 0;

	if (ncfg_wire_attrs_find(data, NFTA_META_KEY, &attr, NULL, 0) != NCFG_WIRE_OK ||
	    !attr_be32(&attr, &key, NULL, 0) || key != NFT_META_OIFNAME) {
		return 1;
	}
	seen->reads_oifname = 1;
	if (ncfg_wire_attrs_find(data, NFTA_META_DREG, &attr, NULL, 0) == NCFG_WIRE_OK) {
		return attr_be32(&attr, &seen->loaded_into, NULL, 0);
	}
	return 1;
}

static int read_cmp(const ncfg_wire_attrs_t *data, masquerade_t *seen)
{
	ncfg_wire_attrs_t value;
	ncfg_wire_attr_t attr;
	uint32_t op = 0;

	/*
	 * **The operator is checked, and the Rust does not check it.** A rule
	 * comparing the interface name for *inequality* masquerades everything
	 * except that interface, and reading it as "this interface is an uplink"
	 * is not a near miss -- it is exactly backwards, and the plan built from
	 * it would leave the real uplinks untranslated.
	 */
	if (ncfg_wire_attrs_find(data, NFTA_CMP_OP, &attr, NULL, 0) != NCFG_WIRE_OK ||
	    !attr_be32(&attr, &op, NULL, 0) || op != NFT_CMP_EQ) {
		return 1;
	}
	seen->compares_equal = 1;
	if (ncfg_wire_attrs_find(data, NFTA_CMP_SREG, &attr, NULL, 0) == NCFG_WIRE_OK &&
	    !attr_be32(&attr, &seen->compared_from, NULL, 0)) {
		return 0;
	}
	if (ncfg_wire_attrs_find(data, NFTA_CMP_DATA, &attr, NULL, 0) != NCFG_WIRE_OK) {
		return 1;
	}
	ncfg_wire_attrs_start(&value, attr.value, attr.length);
	if (ncfg_wire_attrs_find(&value, NFTA_DATA_VALUE, &attr, NULL, 0) != NCFG_WIRE_OK) {
		return 1;
	}
	/* The trailing NUL is part of the comparison and not part of the name,
	 * and `ncfg_wire_attr_string` stops at it. A value too long for an
	 * interface name is not one. */
	return ncfg_wire_attr_string(&attr, seen->name, sizeof(seen->name), NULL, 0);
}

int ncfg_nft_rule_uplink(const void *payload, size_t length, char *out, size_t out_size,
    char *err, size_t err_size)
{
	ncfg_wire_attrs_t area;
	ncfg_wire_attrs_t expressions;
	ncfg_wire_attrs_t expression;
	ncfg_wire_attrs_t data;
	ncfg_wire_attr_t attr;
	ncfg_wire_attr_t element;
	masquerade_t seen;
	char name[NCFG_NFT_NAME_MAX];

	if (!out || out_size == 0) {
		ncfg_error_set(err, err_size, "an uplink name needs somewhere to go");
		return 0;
	}
	out[0] = '\0';
	memset(&seen, 0, sizeof(seen));
	if (!payload_attrs(payload, length, &area, err, err_size)) {
		return 0;
	}
	/*
	 * **The table is checked here, and the Rust trusts the kernel's dump
	 * filter instead.** The request asks for netcfgd's table and chain, and a
	 * kernel that ignored the filter -- or a caller that passed this a reply
	 * to some other dump -- would hand back somebody else's masquerade rules.
	 * Reporting one as netcfgd's uplink is the single worst thing this module
	 * could do: it is the "reads another table" that 0022 forbids, arriving
	 * through the reader rather than through the writer.
	 */
	if (((const uint8_t *)payload)[0] != NFPROTO_INET) {
		ncfg_error_set(err, err_size,
		    "a rule in family %u; netcfgd's table is `inet` and nothing else",
		    (unsigned)((const uint8_t *)payload)[0]);
		return 0;
	}
	if (!read_name(&area, NFTA_RULE_TABLE, name, sizeof(name), err, err_size)) {
		return 0;
	}
	if (strcmp(name, NCFG_NFT_TABLE) != 0) {
		ncfg_error_set(err, err_size,
		    "a rule in table `%s`; netcfgd reads its own table and no other (0022)",
		    name);
		return 0;
	}
	if (!read_name(&area, NFTA_RULE_CHAIN, name, sizeof(name), err, err_size)) {
		return 0;
	}
	if (strcmp(name, NCFG_NFT_CHAIN) != 0) {
		ncfg_error_set(err, err_size, "a rule in chain `%s` rather than `%s`", name,
		    NCFG_NFT_CHAIN);
		return 0;
	}

	if (ncfg_wire_attrs_find(&area, NFTA_RULE_EXPRESSIONS, &attr, NULL, 0) != NCFG_WIRE_OK) {
		ncfg_error_set(err, err_size, "a rule with no expressions");
		return 0;
	}
	ncfg_wire_attrs_start(&expressions, attr.value, attr.length);
	while (ncfg_wire_attrs_next(&expressions, &element, err, err_size) == NCFG_WIRE_OK) {
		if (element.kind != NFTA_LIST_ELEM) {
			continue;
		}
		ncfg_wire_attrs_start(&expression, element.value, element.length);
		if (!read_name(&expression, NFTA_EXPR_NAME, name, sizeof(name), NULL, 0)) {
			continue;
		}
		if (strcmp(name, "masq") == 0) {
			seen.masquerades = 1;
			continue;
		}
		if (ncfg_wire_attrs_find(&expression, NFTA_EXPR_DATA, &attr, NULL, 0) !=
		    NCFG_WIRE_OK) {
			continue;
		}
		ncfg_wire_attrs_start(&data, attr.value, attr.length);
		/* Each refusal says so: the observer logs the first, and one that
		 * said nothing logged whatever its buffer held (10.899). */
		if (strcmp(name, "meta") == 0 && !read_meta(&data, &seen)) {
			ncfg_error_set(err, err_size, "a rule loading a `meta` key netcfgd's "
			    "masquerade does not");
			return 0;
		}
		if (strcmp(name, "cmp") == 0 && !read_cmp(&data, &seen)) {
			ncfg_error_set(err, err_size, "a rule with a comparison netcfgd's masquerade "
			    "does not make");
			return 0;
		}
	}

	/*
	 * All of it, or this is not a rule netcfgd wrote. A rule with the
	 * comparison and no `masq` matches traffic and does nothing to it, and
	 * calling that an uplink would report NAT that is not happening.
	 */
	if (!seen.reads_oifname || !seen.compares_equal || !seen.masquerades ||
	    seen.name[0] == '\0') {
		ncfg_error_set(err, err_size,
		    "a rule that is not the `oifname \"X\" masquerade` netcfgd writes");
		return 0;
	}
	/*
	 * The comparison has to test the register the name was loaded into.
	 * Comparing a different one is a rule about something else that happens
	 * to mention an interface name.
	 *
	 * Register zero is `NFT_REG_VERDICT` and cannot hold a name, so it also
	 * stands for "neither expression named a register at all" -- which is
	 * what these two fields hold when the attributes are missing, and which
	 * would otherwise compare equal to itself and pass.
	 */
	if (seen.loaded_into == NFT_REG_VERDICT || seen.compared_from != seen.loaded_into) {
		ncfg_error_set(err, err_size,
		    "a rule comparing register %u where `oifname` went into register %u",
		    (unsigned)seen.compared_from, (unsigned)seen.loaded_into);
		return 0;
	}
	if (strlen(seen.name) >= out_size) {
		ncfg_error_set(err, err_size,
		    "a %zu-byte interface name does not fit a %zu-byte buffer",
		    strlen(seen.name), out_size - 1u);
		return 0;
	}
	memcpy(out, seen.name, strlen(seen.name) + 1u);
	return 1;
}

/* ------------------------------------------------------------------------ *
 * Reading the firewall back (0295 A, 10.592 slice 2c)
 * ------------------------------------------------------------------------ */

/* What register 1 holds as the expressions are walked. */
enum { LOADED_NONE, LOADED_META, LOADED_PAYLOAD, LOADED_CT };

typedef struct {
	int      what;
	uint32_t key;    /* meta or ct key */
	uint32_t base;   /* payload */
	uint32_t offset;
	uint32_t length;
	uint8_t  mask[16];
	uint8_t  xor_bytes[16];
	size_t   mask_length; /* 0 where nothing was masked */
	uint8_t  family; /* from `meta nfproto`, for the addresses after it */
	int      swapped; /* `meta hour` turned to network order, ready to range */
} reading_t;

static int be32_member(const ncfg_wire_attrs_t *area, uint16_t kind, uint32_t *out)
{
	ncfg_wire_attr_t attr;

	if (ncfg_wire_attrs_find(area, kind, &attr, NULL, 0) != NCFG_WIRE_OK) {
		return 0;
	}
	return attr_be32(&attr, out, NULL, 0);
}

static int be64_member(const ncfg_wire_attrs_t *area, uint16_t kind, uint64_t *out)
{
	ncfg_wire_attr_t attr;
	const uint8_t   *bytes;
	size_t           at;

	if (ncfg_wire_attrs_find(area, kind, &attr, NULL, 0) != NCFG_WIRE_OK || attr.length != 8u) {
		return 0;
	}
	bytes = attr.value;
	*out = 0;
	for (at = 0; at < 8u; at++) {
		*out = (*out << 8) | bytes[at];
	}
	return 1;
}

/*
 * An `over` meter's `dynset`, back into "COUNT/SECONDSs": the source address
 * loaded just before it, an update with one `limit` that counts packets and
 * matches over its rate -- exactly `put_over`'s shape, and nothing else.
 */
static int read_over(const reading_t *reading, const ncfg_wire_attrs_t *data,
    ncfg_nft_kernel_rule_t *out)
{
	ncfg_wire_attr_t  nest;
	ncfg_wire_attrs_t one;
	ncfg_wire_attrs_t limit;
	ncfg_wire_attr_t  limit_data;
	char              name[16];
	uint32_t          op = 0, type = 0, flags = 0, burst = 0;
	uint64_t          rate = 0, unit = 0;

	int               destination;

	if (reading->what != LOADED_PAYLOAD || reading->base != NFT_PAYLOAD_NETWORK_HEADER ||
	    !(((reading->offset == 12u || reading->offset == 16u) && reading->length == 4u) ||
	    ((reading->offset == 8u || reading->offset == 24u) && reading->length == 16u)) ||
	    !be32_member(data, NFTA_DYNSET_OP, &op) || op != NFT_DYNSET_OP_UPDATE) {
		return 0;
	}
	destination = reading->offset == 16u || reading->offset == 24u;
	if (ncfg_wire_attrs_find(data, NFTA_DYNSET_EXPR, &nest, NULL, 0) == NCFG_WIRE_OK) {
		ncfg_wire_attrs_start(&one, nest.value, nest.length);
	} else if (ncfg_wire_attrs_find(data, NFTA_DYNSET_EXPRESSIONS, &nest, NULL, 0) ==
	    NCFG_WIRE_OK) {
		ncfg_wire_attrs_t list;
		ncfg_wire_attr_t  element;

		ncfg_wire_attrs_start(&list, nest.value, nest.length);
		if (ncfg_wire_attrs_next(&list, &element, NULL, 0) != NCFG_WIRE_OK ||
		    element.kind != NFTA_LIST_ELEM) {
			return 0;
		}
		ncfg_wire_attrs_start(&one, element.value, element.length);
	} else {
		return 0;
	}
	if (!read_name(&one, NFTA_EXPR_NAME, name, sizeof(name), NULL, 0) ||
	    strcmp(name, "limit") != 0 ||
	    ncfg_wire_attrs_find(&one, NFTA_EXPR_DATA, &limit_data, NULL, 0) != NCFG_WIRE_OK) {
		return 0;
	}
	ncfg_wire_attrs_start(&limit, limit_data.value, limit_data.length);
	if (!be64_member(&limit, NFTA_LIMIT_RATE, &rate) ||
	    !be64_member(&limit, NFTA_LIMIT_UNIT, &unit) || rate == 0u || unit == 0u ||
	    !be32_member(&limit, NFTA_LIMIT_BURST, &burst) || burst == 0u ||
	    !be32_member(&limit, NFTA_LIMIT_FLAGS, &flags) || !(flags & NFT_LIMIT_F_INV)) {
		return 0;
	}
	(void)be32_member(&limit, NFTA_LIMIT_TYPE, &type);
	/* A zone's cap (10.928): bytes, one window's worth as the burst, keyed
	 * either way -- exactly what `put_over` writes for `B...`. */
	if (type == NFT_LIMIT_PKT_BYTES) {
		if (burst != cap_burst(rate)) {
			return 0;
		}
		(void)snprintf(out->over, sizeof(out->over), "B%llu/%llus%s",
		    (unsigned long long)rate, (unsigned long long)unit, destination ? "@dst" : "");
		return 1;
	}
	if (type != NFT_LIMIT_PKTS || destination || unit > UINT64_MAX / burst ||
	    (unit * burst) % rate != 0u) {
		return 0;
	}
	/* The burst is the count and the window what it refills in (10.898).
	 * Only the unit this build writes is netcfgd's: a meter written by an
	 * earlier one in its window's own unit -- `8/error` to nft -- reads as
	 * not netcfgd's, so the first plan after an upgrade writes it again. */
	{
		const uint64_t window = unit * burst / rate;
		uint64_t       want_rate = 0, want_unit = 0;

		over_rate(burst, window, &want_rate, &want_unit);
		if (want_rate != rate || want_unit != unit) {
			return 0;
		}
		(void)snprintf(out->over, sizeof(out->over), "%lu/%llus", (unsigned long)burst,
		    (unsigned long long)window);
	}
	return 1;
}

/* The bytes of a nested `NFTA_DATA_VALUE`. */
static int data_value(const ncfg_wire_attrs_t *area, uint16_t kind, const uint8_t **bytes,
    size_t *length)
{
	ncfg_wire_attr_t  outer;
	ncfg_wire_attr_t  inner;
	ncfg_wire_attrs_t nest;

	if (ncfg_wire_attrs_find(area, kind, &outer, NULL, 0) != NCFG_WIRE_OK) {
		return 0;
	}
	ncfg_wire_attrs_start(&nest, outer.value, outer.length);
	if (ncfg_wire_attrs_find(&nest, NFTA_DATA_VALUE, &inner, NULL, 0) != NCFG_WIRE_OK) {
		return 0;
	}
	*bytes = inner.value;
	*length = inner.length;
	return 1;
}

/* A mask's prefix length, or -1 where its ones are not all leading. */
static int prefix_of(const uint8_t *mask, size_t length)
{
	size_t bit;
	int    ones = 0;
	int    ended = 0;

	for (bit = 0; bit < length * 8u; bit++) {
		const int set = (mask[bit / 8u] >> (7u - bit % 8u)) & 1;

		if (set && ended) {
			return -1;
		}
		if (set) {
			ones++;
		} else {
			ended = 1;
		}
	}
	return ones;
}

static int read_cmp_into(reading_t *reading, const ncfg_wire_attrs_t *data,
    ncfg_nft_kernel_rule_t *out, char *err, size_t err_size)
{
	const uint8_t *value = NULL;
	size_t         length = 0;
	uint32_t       op = 0;

	if (!be32_member(data, NFTA_CMP_OP, &op) ||
	    !data_value(data, NFTA_CMP_DATA, &value, &length)) {
		ncfg_error_set(err, err_size, "a comparison with no operator or no value");
		return 0;
	}
	if (reading->what == LOADED_CT && reading->key == NFT_CT_STATE) {
		uint32_t bits = 0;

		if (op != NFT_CMP_NEQ || length != 4u || reading->mask_length != 4u) {
			ncfg_error_set(err, err_size, "a conntrack state test netcfgd does not write");
			return 0;
		}
		memcpy(&bits, reading->mask, sizeof(bits));
		out->states = 0;
		if (bits & NF_CT_STATE_BIT(IP_CT_NEW)) {
			out->states |= 1u;
		}
		if (bits & NF_CT_STATE_BIT(IP_CT_ESTABLISHED)) {
			out->states |= 2u;
		}
		if (bits & NF_CT_STATE_BIT(IP_CT_RELATED)) {
			out->states |= 4u;
		}
		if (bits & NF_CT_STATE_INVALID_BIT) {
			out->states |= 8u;
		}
		return 1;
	}
	if (reading->what == LOADED_CT && reading->key == NFT_CT_STATUS) {
		uint32_t bits = 0;
		uint32_t zero = 0;

		memcpy(&bits, reading->mask, reading->mask_length == 4u ? 4u : 0u);
		if (op != NFT_CMP_NEQ || length != 4u || reading->mask_length != 4u ||
		    bits != IPS_DST_NAT || memcmp(value, &zero, 4u) != 0) {
			ncfg_error_set(err, err_size, "a conntrack status test netcfgd does not write");
			return 0;
		}
		out->translated = 1;
		return 1;
	}
	if (op != NFT_CMP_EQ) {
		ncfg_error_set(err, err_size, "a comparison other than equality, which netcfgd "
		    "writes only for a conntrack state");
		return 0;
	}
	if (reading->what == LOADED_META) {
		switch (reading->key) {
		case NFT_META_NFPROTO:
			if (length != 1u) {
				break;
			}
			reading->family = value[0];
			return 1;
		case NFT_META_L4PROTO:
			if (length != 1u) {
				break;
			}
			switch (value[0]) {
			case IPPROTO_TCP:
				out->protocol = NCFG_FIREWALL_PROTO_TCP;
				return 1;
			case IPPROTO_UDP:
				out->protocol = NCFG_FIREWALL_PROTO_UDP;
				return 1;
			case IPPROTO_ICMP:
				out->protocol = NCFG_FIREWALL_PROTO_ICMP;
				return 1;
			case IPPROTO_ICMPV6:
				out->protocol = NCFG_FIREWALL_PROTO_ICMPV6;
				return 1;
			case IPPROTO_GRE:
				out->protocol = NCFG_FIREWALL_PROTO_GRE;
				return 1;
			case IPPROTO_ESP:
				out->protocol = NCFG_FIREWALL_PROTO_ESP;
				return 1;
			case IPPROTO_AH:
				out->protocol = NCFG_FIREWALL_PROTO_AH;
				return 1;
			case IPPROTO_SCTP:
				out->protocol = NCFG_FIREWALL_PROTO_SCTP;
				return 1;
			case IPPROTO_IPIP:
				out->protocol = NCFG_FIREWALL_PROTO_IPIP;
				return 1;
			case IPPROTO_IPV6:
				out->protocol = NCFG_FIREWALL_PROTO_SIT;
				return 1;
			default:
				break;
			}
			break;
		case NFT_META_IIFNAME:
		case NFT_META_OIFNAME: {
			/* `oifname` in the forward chain is where the packet leaves
			 * (0302); in `output` it is the rule's `interface`, as
			 * `iifname` is in `input` and `forward`. The chain was read
			 * before the expressions. A second match into one field is not
			 * a rule netcfgd writes. */
			char *into = reading->key == NFT_META_OIFNAME &&
			        strcmp(out->chain, NCFG_NFT_CHAIN_FORWARD) == 0
			    ? out->out_interface
			    : out->interface;

			if (length == 0u || length > NCFG_NFT_IFNAME_MAX ||
			    memchr(value, '\0', length) == NULL || into[0]) {
				break;
			}
			memcpy(into, value, length);
			return 1;
		}
		case NFT_META_TIME_DAY:
			/* A schedule piece's day (10.663). A second is not a rule
			 * netcfgd writes. */
			if (length != 1u || value[0] > 6u || out->has_day) {
				break;
			}
			out->has_day = 1;
			out->day = value[0];
			return 1;
		case NFT_META_IIFTYPE: {
			uint16_t type = 0;

			if (length != sizeof(type)) {
				break;
			}
			memcpy(&type, value, sizeof(type));
			if (type == ARPHRD_ETHER) {
				return 1;
			}
			break;
		}
		default:
			break;
		}
	} else if (reading->what == LOADED_PAYLOAD) {
		if (reading->base == NFT_PAYLOAD_TRANSPORT_HEADER && reading->offset == 2u &&
		    reading->length == 2u && length == 2u && reading->mask_length == 0u) {
			uint16_t port;

			memcpy(&port, value, sizeof(port));
			out->has_port = 1;
			out->port = ntohs(port);
			return 1;
		}
		/* An ICMP type, the transport header's first byte (0333). */
		if (reading->base == NFT_PAYLOAD_TRANSPORT_HEADER && reading->offset == 0u &&
		    reading->length == 1u && length == 1u && reading->mask_length == 0u &&
		    !out->has_icmp_type) {
			out->has_icmp_type = 1;
			out->icmp_type = value[0];
			return 1;
		}
		/* The whole address, masked where the prefix is short, as netcfgd
		 * writes it; or its leading bytes only, as nft compiles a prefix from
		 * text -- which is what a ruleset saved and loaded back with `nft -f`
		 * holds (10.899). The two are one match and read as one. */
		if (reading->base == NFT_PAYLOAD_NETWORK_HEADER && length == reading->length &&
		    length >= 1u &&
		    ((reading->length <= 4u && reading->family == NFPROTO_IPV4 &&
		    (reading->offset == 12u || reading->offset == 16u)) ||
		    (reading->length <= 16u && reading->family == NFPROTO_IPV6 &&
		    (reading->offset == 8u || reading->offset == 24u)))) {
			const int source = reading->offset == 12u || reading->offset == 8u;
			int       prefix = (int)(length * 8u);
			uint8_t   whole[16];

			if (reading->mask_length) {
				prefix = prefix_of(reading->mask, reading->mask_length);
				if (prefix < 0 || reading->mask_length != length) {
					ncfg_error_set(err, err_size, "an address mask that is not a prefix");
					return 0;
				}
			}
			memset(whole, 0, sizeof(whole));
			memcpy(whole, value, length);
			format_address(reading->family, whole, (uint32_t)prefix,
			    source ? out->from : out->to, sizeof(out->from));
			return 1;
		}
		if (reading->base == NFT_PAYLOAD_LL_HEADER && reading->offset == 6u &&
		    reading->length == 6u && length == 6u) {
			static const uint8_t oui[6] = { 0xff, 0xff, 0xff, 0, 0, 0 };

			if (reading->mask_length == 0u) {
				(void)snprintf(out->mac, sizeof(out->mac), "%02x:%02x:%02x:%02x:%02x:%02x",
				    value[0], value[1], value[2], value[3], value[4], value[5]);
				return 1;
			}
			if (reading->mask_length == 6u && memcmp(reading->mask, oui, 6u) == 0) {
				(void)snprintf(out->mac, sizeof(out->mac), "%02x:%02x:%02x:*", value[0],
				    value[1], value[2]);
				return 1;
			}
		}
	}
	ncfg_error_set(err, err_size, "a comparison netcfgd does not write");
	return 0;
}

static int read_comment(const ncfg_wire_attrs_t *area, ncfg_nft_kernel_rule_t *out)
{
	ncfg_wire_attr_t attr;
	const uint8_t   *at;
	size_t           left;
	const char      *digest;
	char             text[NCFG_NFT_COMMENT_MAX + 1u];

	if (ncfg_wire_attrs_find(area, NFTA_RULE_USERDATA, &attr, NULL, 0) != NCFG_WIRE_OK) {
		return 0;
	}
	at = attr.value;
	left = attr.length;
	while (left >= 2u) {
		const uint8_t type = at[0];
		const uint8_t length = at[1];

		if ((size_t)length + 2u > left) {
			return 0;
		}
		if (type == 0u && length > 0u && length <= sizeof(text) && at[2 + length - 1] == '\0') {
			memcpy(text, at + 2, length);
			if (strncmp(text, "name=", 5) != 0) {
				return 0;
			}
			digest = strstr(text, " sha256=");
			if (!digest || (size_t)(digest - (text + 5)) >= sizeof(out->name) ||
			    strlen(digest + 8) != NCFG_NFT_DIGEST_HEX) {
				return 0;
			}
			memcpy(out->name, text + 5, (size_t)(digest - (text + 5)));
			out->name[digest - (text + 5)] = '\0';
			memcpy(out->digest, digest + 8, NCFG_NFT_DIGEST_HEX + 1u);
			return 1;
		}
		at += 2u + length;
		left -= 2u + (size_t)length;
	}
	return 0;
}

/*
 * One of 0334's rules, read back exactly as `mss_rule` writes it: eight
 * expressions in one order, every value the one written. Anything else in
 * the `mss` chain is not netcfgd's clamp, and is answered 0.
 */
int ncfg_nft_rule_mss(const void *payload, size_t length, char *interface,
    size_t interface_size, int *leaving)
{
	static const char *const order[] = { "meta", "cmp", "meta", "cmp", "payload", "bitwise",
		"cmp", "rt", "byteorder", "exthdr" };
	ncfg_wire_attrs_t area;
	ncfg_wire_attrs_t list;
	ncfg_wire_attr_t  attr;
	char              name[NCFG_NFT_NAME_MAX];
	size_t            at = 0;
	int               way = -1;

	if (!interface || !interface_size || !leaving ||
	    !payload_attrs(payload, length, &area, NULL, 0) ||
	    ((const uint8_t *)payload)[0] != NFPROTO_INET ||
	    !read_name(&area, NFTA_RULE_TABLE, name, sizeof(name), NULL, 0) ||
	    strcmp(name, NCFG_NFT_TABLE) != 0 ||
	    !read_name(&area, NFTA_RULE_CHAIN, name, sizeof(name), NULL, 0) ||
	    strcmp(name, NCFG_NFT_CHAIN_MSS) != 0 ||
	    ncfg_wire_attrs_find(&area, NFTA_RULE_EXPRESSIONS, &attr, NULL, 0) != NCFG_WIRE_OK) {
		return 0;
	}
	interface[0] = '\0';
	ncfg_wire_attrs_start(&list, attr.value, attr.length);
	while (ncfg_wire_attrs_next(&list, &attr, NULL, 0) == NCFG_WIRE_OK) {
		ncfg_wire_attrs_t expression;
		ncfg_wire_attrs_t data;
		ncfg_wire_attr_t  data_attr;
		const uint8_t    *bytes = NULL;
		size_t            count = 0;
		uint32_t          value = 0;
		uint32_t          other = 0;

		if (attr.kind != NFTA_LIST_ELEM) {
			continue;
		}
		ncfg_wire_attrs_start(&expression, attr.value, attr.length);
		if (at >= sizeof(order) / sizeof(order[0]) ||
		    !read_name(&expression, NFTA_EXPR_NAME, name, sizeof(name), NULL, 0) ||
		    strcmp(name, order[at]) != 0 ||
		    ncfg_wire_attrs_find(&expression, NFTA_EXPR_DATA, &data_attr, NULL, 0) !=
		        NCFG_WIRE_OK) {
			return 0;
		}
		ncfg_wire_attrs_start(&data, data_attr.value, data_attr.length);
		switch (at) {
		case 0: /* meta oifname or iifname */
			if (!be32_member(&data, NFTA_META_KEY, &value) ||
			    (value != NFT_META_OIFNAME && value != NFT_META_IIFNAME)) {
				return 0;
			}
			way = value == NFT_META_OIFNAME;
			break;
		case 1: /* the interface's name */
			if (!data_value(&data, NFTA_CMP_DATA, &bytes, &count) || count == 0u ||
			    count > interface_size || count > NCFG_NFT_IFNAME_MAX ||
			    memchr(bytes, '\0', count) == NULL) {
				return 0;
			}
			memcpy(interface, bytes, count);
			interface[interface_size - 1u] = '\0';
			break;
		case 2: /* meta l4proto */
			if (!be32_member(&data, NFTA_META_KEY, &value) || value != NFT_META_L4PROTO) {
				return 0;
			}
			break;
		case 3: /* tcp */
			if (!data_value(&data, NFTA_CMP_DATA, &bytes, &count) || count != 1u ||
			    bytes[0] != IPPROTO_TCP) {
				return 0;
			}
			break;
		case 4: /* the flags byte */
			if (!be32_member(&data, NFTA_PAYLOAD_BASE, &value) ||
			    value != NFT_PAYLOAD_TRANSPORT_HEADER ||
			    !be32_member(&data, NFTA_PAYLOAD_OFFSET, &value) || value != 13u ||
			    !be32_member(&data, NFTA_PAYLOAD_LEN, &value) || value != 1u) {
				return 0;
			}
			break;
		case 5: /* & (syn | rst) */
			if (!data_value(&data, NFTA_BITWISE_MASK, &bytes, &count) || count != 1u ||
			    bytes[0] != 0x06u) {
				return 0;
			}
			break;
		case 6: /* == syn */
			if (!data_value(&data, NFTA_CMP_DATA, &bytes, &count) || count != 1u ||
			    bytes[0] != 0x02u) {
				return 0;
			}
			break;
		case 7: /* rt tcpmss */
			if (!be32_member(&data, NFTA_RT_KEY, &value) || value != NFT_RT_TCPMSS) {
				return 0;
			}
			break;
		case 8: /* hton, 2 of 2 */
			if (!be32_member(&data, NFTA_BYTEORDER_OP, &value) || value != NFT_BYTEORDER_HTON ||
			    !be32_member(&data, NFTA_BYTEORDER_LEN, &value) || value != 2u ||
			    !be32_member(&data, NFTA_BYTEORDER_SIZE, &other) || other != 2u) {
				return 0;
			}
			break;
		default: { /* write the maxseg option's size; the type is a bare u8 */
			ncfg_wire_attr_t type;

			if (ncfg_wire_attrs_find(&data, NFTA_EXTHDR_TYPE, &type, NULL, 0) != NCFG_WIRE_OK ||
			    type.length < 1u || ((const uint8_t *)type.value)[0] != 2u ||
			    !be32_member(&data, NFTA_EXTHDR_OP, &value) || value != NFT_EXTHDR_OP_TCPOPT ||
			    !be32_member(&data, NFTA_EXTHDR_OFFSET, &value) || value != 2u ||
			    !be32_member(&data, NFTA_EXTHDR_LEN, &other) || other != 2u) {
				return 0;
			}
		}
			break;
		}
		at++;
	}
	if (at != sizeof(order) / sizeof(order[0]) || way < 0 || !interface[0]) {
		return 0;
	}
	*leaving = way;
	return 1;
}

/* A slot rule's comment, "slot=NAME match=WORD timeout=N", into `out`. */
static int read_slot_comment(const ncfg_wire_attrs_t *area, ncfg_nft_kernel_slot_t *out)
{
	ncfg_wire_attr_t attr;
	const uint8_t   *at;
	size_t           left;

	if (ncfg_wire_attrs_find(area, NFTA_RULE_USERDATA, &attr, NULL, 0) != NCFG_WIRE_OK) {
		return 0;
	}
	at = attr.value;
	left = attr.length;
	while (left >= 2u) {
		const uint8_t type = at[0];
		const uint8_t length = at[1];

		if ((size_t)length + 2u > left) {
			return 0;
		}
		if (type == 0u && length > 0u && at[2 + length - 1] == '\0') {
			char      text[NCFG_NFT_COMMENT_MAX + 1u];
			char      name[NCFG_FIREWALL_SLOT_NAME_MAX + 2u];
			char      match[8];
			long long timeout = -1;
			char      tail = 0;

			if (length > sizeof(text)) {
				return 0;
			}
			memcpy(text, at + 2, length);
			if (sscanf(text, "slot=%49s match=%7s timeout=%lld%c", name, match, &timeout,
			        &tail) != 3 ||
			    !ncfg_firewall_slot_name_valid(name) || timeout < 0 || timeout > 604800) {
				return 0;
			}
			if (strcmp(match, "from") == 0) {
				out->slot.match = NCFG_FIREWALL_SLOT_FROM;
			} else if (strcmp(match, "to") == 0) {
				out->slot.match = NCFG_FIREWALL_SLOT_TO;
			} else {
				return 0;
			}
			memcpy(out->name, name, strlen(name) + 1u);
			out->slot.timeout = timeout;
			return 1;
		}
		at += 2u + length;
		left -= 2u + (size_t)length;
	}
	return 0;
}

int ncfg_nft_rule_slot(const void *payload, size_t length, ncfg_nft_kernel_slot_t *out)
{
	static const char *const order[] = { "meta", "cmp", "payload", "lookup", "counter" };
	ncfg_wire_attrs_t area;
	ncfg_wire_attrs_t list;
	ncfg_wire_attr_t  attr;
	char              name[NCFG_NFT_NAME_MAX];
	char              expected[NCFG_NFT_NAME_MAX];
	size_t            at = 0;
	int               verdict = 0;
	uint8_t           family = 0;

	if (!out) {
		return 0;
	}
	memset(out, 0, sizeof(*out));
	if (!payload_attrs(payload, length, &area, NULL, 0) ||
	    ((const uint8_t *)payload)[0] != NFPROTO_INET ||
	    !read_name(&area, NFTA_RULE_TABLE, name, sizeof(name), NULL, 0) ||
	    strcmp(name, NCFG_NFT_TABLE) != 0 ||
	    !read_name(&area, NFTA_RULE_CHAIN, out->chain, sizeof(out->chain), NULL, 0) ||
	    (strcmp(out->chain, NCFG_NFT_CHAIN_INPUT) != 0 &&
	    strcmp(out->chain, NCFG_NFT_CHAIN_FORWARD) != 0 &&
	    strcmp(out->chain, NCFG_NFT_CHAIN_OUTPUT) != 0) ||
	    !read_slot_comment(&area, out) ||
	    ncfg_wire_attrs_find(&area, NFTA_RULE_EXPRESSIONS, &attr, NULL, 0) != NCFG_WIRE_OK) {
		return 0;
	}
	out->slot.name = out->name;
	ncfg_wire_attrs_start(&list, attr.value, attr.length);
	while (ncfg_wire_attrs_next(&list, &attr, NULL, 0) == NCFG_WIRE_OK) {
		ncfg_wire_attrs_t expression;
		ncfg_wire_attrs_t data;
		ncfg_wire_attr_t  data_attr;
		const uint8_t    *bytes = NULL;
		size_t            count = 0;
		uint32_t          value = 0;

		if (attr.kind != NFTA_LIST_ELEM) {
			continue;
		}
		ncfg_wire_attrs_start(&expression, attr.value, attr.length);
		if (verdict || !read_name(&expression, NFTA_EXPR_NAME, name, sizeof(name), NULL, 0) ||
		    ncfg_wire_attrs_find(&expression, NFTA_EXPR_DATA, &data_attr, NULL, 0) !=
		        NCFG_WIRE_OK) {
			return 0;
		}
		ncfg_wire_attrs_start(&data, data_attr.value, data_attr.length);
		if (at < sizeof(order) / sizeof(order[0]) && strcmp(name, order[at]) != 0) {
			return 0;
		}
		switch (at) {
		case 0: /* meta nfproto */
			if (!be32_member(&data, NFTA_META_KEY, &value) || value != NFT_META_NFPROTO) {
				return 0;
			}
			break;
		case 1: /* ipv4 or ipv6 */
			if (!data_value(&data, NFTA_CMP_DATA, &bytes, &count) || count != 1u ||
			    (bytes[0] != NFPROTO_IPV4 && bytes[0] != NFPROTO_IPV6)) {
				return 0;
			}
			family = bytes[0];
			out->ipv6 = family == NFPROTO_IPV6;
			break;
		case 2: { /* the address the slot matches */
			const int source = out->slot.match == NCFG_FIREWALL_SLOT_FROM;
			uint32_t  offset = 0, size = 0;

			if (!be32_member(&data, NFTA_PAYLOAD_BASE, &value) ||
			    value != NFT_PAYLOAD_NETWORK_HEADER ||
			    !be32_member(&data, NFTA_PAYLOAD_OFFSET, &offset) ||
			    !be32_member(&data, NFTA_PAYLOAD_LEN, &size)) {
				return 0;
			}
			if (family == NFPROTO_IPV6 ? (size != 16u || offset != (source ? 8u : 24u))
			                           : (size != 4u || offset != (source ? 12u : 16u))) {
				return 0;
			}
			break;
		}
		case 3: /* the slot's own set */
			ncfg_nft_slot_set_name(out->name, out->ipv6, expected, sizeof(expected));
			if (!read_name(&data, NFTA_LOOKUP_SET, name, sizeof(name), NULL, 0) ||
			    strcmp(name, expected) != 0) {
				return 0;
			}
			break;
		case 4: { /* counter */
			uint64_t number = 0;

			if (be64_member(&data, NFTA_COUNTER_PACKETS, &number)) {
				out->packets = number;
			}
			if (be64_member(&data, NFTA_COUNTER_BYTES, &number)) {
				out->bytes = number;
			}
			break;
		}
		default:
			if (strcmp(name, "reject") == 0) {
				uint32_t type = 0;

				if (!be32_member(&data, NFTA_REJECT_TYPE, &type) ||
				    type != NFT_REJECT_ICMPX_UNREACH) {
					return 0;
				}
				out->slot.action = NCFG_FIREWALL_REJECT;
			} else if (strcmp(name, "immediate") == 0) {
				ncfg_wire_attr_t  nested;
				ncfg_wire_attrs_t verdict_area;
				ncfg_wire_attrs_t code_area;

				if (ncfg_wire_attrs_find(&data, NFTA_IMMEDIATE_DATA, &nested, NULL, 0) !=
				        NCFG_WIRE_OK) {
					return 0;
				}
				ncfg_wire_attrs_start(&verdict_area, nested.value, nested.length);
				if (ncfg_wire_attrs_find(&verdict_area, NFTA_DATA_VERDICT, &nested, NULL, 0) !=
				        NCFG_WIRE_OK) {
					return 0;
				}
				ncfg_wire_attrs_start(&code_area, nested.value, nested.length);
				if (!be32_member(&code_area, NFTA_VERDICT_CODE, &value) ||
				    (value != NF_DROP && value != NF_ACCEPT)) {
					return 0;
				}
				out->slot.action = value == NF_DROP ? NCFG_FIREWALL_DROP : NCFG_FIREWALL_ACCEPT;
			} else {
				return 0;
			}
			verdict = 1;
			break;
		}
		at++;
	}
	/* No verdict is a slot that only counts (10.933). */
	if (!verdict && at == sizeof(order) / sizeof(order[0])) {
		out->slot.action = NCFG_FIREWALL_NONE;
		return 1;
	}
	return verdict && at == sizeof(order) / sizeof(order[0]) + 1u;
}

int ncfg_nft_firewall_rule_read(const void *payload, size_t length,
    ncfg_nft_kernel_rule_t *out, char *err, size_t err_size)
{
	ncfg_wire_attrs_t area;
	ncfg_wire_attrs_t expressions;
	ncfg_wire_attr_t  attr;
	ncfg_wire_attr_t  element;
	reading_t         reading;
	char              name[NCFG_NFT_NAME_MAX];
	int               verdict = 0;
	/* 1 once the log's `limit` is read, 2 once its `log` is (0330). */
	int               logging = 0;
	/* The reserved mark bit (0338), in the order it is met: cleared ahead of
	 * a log's meter and set past it, or matched and cleared in its verdict's
	 * rule. */
	int               mark_cleared = 0;
	int               mark_set = 0;
	int               mark_tested = 0;
	int               mark_released = 0;

	if (!out) {
		ncfg_error_set(err, err_size, "a rule read needs somewhere to go");
		return 0;
	}
	memset(out, 0, sizeof(*out));
	memset(&reading, 0, sizeof(reading));
	out->protocol = NCFG_FIREWALL_PROTO_ANY;
	if (!payload_attrs(payload, length, &area, err, err_size)) {
		return 0;
	}
	if (((const uint8_t *)payload)[0] != NFPROTO_INET ||
	    !read_name(&area, NFTA_RULE_TABLE, name, sizeof(name), err, err_size) ||
	    strcmp(name, NCFG_NFT_TABLE) != 0) {
		ncfg_error_set(err, err_size, "a rule outside netcfgd's table, which is not read");
		return 0;
	}
	if (!read_name(&area, NFTA_RULE_CHAIN, out->chain, sizeof(out->chain), err, err_size) ||
	    (strcmp(out->chain, NCFG_NFT_CHAIN_INPUT) != 0 &&
	    strcmp(out->chain, NCFG_NFT_CHAIN_FORWARD) != 0 &&
	    strcmp(out->chain, NCFG_NFT_CHAIN_OUTPUT) != 0)) {
		ncfg_error_set(err, err_size, "a rule outside the three filter chains");
		return 0;
	}
	if (!read_comment(&area, out)) {
		ncfg_error_set(err, err_size,
		    "a rule in chain `%s` with no `name=... sha256=...` comment, so not one netcfgd "
		    "wrote", out->chain);
		return 0;
	}
	if (ncfg_wire_attrs_find(&area, NFTA_RULE_EXPRESSIONS, &attr, NULL, 0) != NCFG_WIRE_OK) {
		ncfg_error_set(err, err_size, "rule `%s` has no expressions", out->name);
		return 0;
	}
	ncfg_wire_attrs_start(&expressions, attr.value, attr.length);
	while (ncfg_wire_attrs_next(&expressions, &element, err, err_size) == NCFG_WIRE_OK) {
		ncfg_wire_attrs_t expression;
		ncfg_wire_attrs_t data;
		ncfg_wire_attr_t  data_attr;
		ncfg_wire_attr_t  stored;
		char              why[NCFG_ERROR_MAX];

		if (element.kind != NFTA_LIST_ELEM) {
			continue;
		}
		ncfg_wire_attrs_start(&expression, element.value, element.length);
		if (!read_name(&expression, NFTA_EXPR_NAME, name, sizeof(name), NULL, 0)) {
			ncfg_error_set(err, err_size, "rule `%s` has an expression with no name",
			    out->name);
			return 0;
		}
		memset(&data, 0, sizeof(data));
		if (ncfg_wire_attrs_find(&expression, NFTA_EXPR_DATA, &data_attr, NULL, 0) ==
		    NCFG_WIRE_OK) {
			ncfg_wire_attrs_start(&data, data_attr.value, data_attr.length);
		}
		if (verdict) {
			ncfg_error_set(err, err_size, "rule `%s` has an expression after its verdict",
			    out->name);
			return 0;
		}
		/* A counter is followed by the verdict and by nothing else (10.901). */
		if (out->counted && strcmp(name, "immediate") != 0 && strcmp(name, "reject") != 0) {
			ncfg_error_set(err, err_size, "rule `%s` has a `counter` netcfgd does not write",
			    out->name);
			return 0;
		}
		/* A log's `limit` is followed by its `log` and by nothing else. */
		if (logging == 1 && strcmp(name, "log") != 0) {
			ncfg_error_set(err, err_size, "rule `%s` has a `limit` netcfgd does not write",
			    out->name);
			return 0;
		}
		if (strcmp(name, "meta") == 0 && ncfg_wire_attrs_find(&data, NFTA_META_SREG, &stored,
		        NULL, 0) == NCFG_WIRE_OK) {
			/* A store: only the mark, only as `put_mark_set` writes it. */
			uint32_t key = 0;
			uint32_t mask = 0;
			uint32_t xor_value = 0;

			(void)be32_member(&data, NFTA_META_KEY, &key);
			if (reading.what == LOADED_META && reading.key == NFT_META_MARK &&
			    reading.mask_length == 4u) {
				memcpy(&mask, reading.mask, sizeof(mask));
				memcpy(&xor_value, reading.xor_bytes, sizeof(xor_value));
			}
			if (key != NFT_META_MARK || reading.what != LOADED_META ||
			    reading.key != NFT_META_MARK || reading.mask_length != 4u ||
			    mask != ~NCFG_NFT_MARK_BIT || (xor_value != 0u && xor_value != NCFG_NFT_MARK_BIT) ||
			    logging) {
				ncfg_error_set(err, err_size, "rule `%s` sets a packet mark netcfgd does not "
				    "write", out->name);
				return 0;
			}
			if (xor_value) {
				/* Set past the meter, once, after it was cleared. */
				if (!mark_cleared || mark_set || !out->over[0]) {
					ncfg_error_set(err, err_size, "rule `%s` sets the mark where netcfgd "
					    "does not", out->name);
					return 0;
				}
				mark_set = 1;
			} else if (mark_tested && !mark_released) {
				mark_released = 1;
			} else if (!mark_tested && !mark_cleared && !out->over[0]) {
				mark_cleared = 1;
			} else {
				ncfg_error_set(err, err_size, "rule `%s` clears the mark where netcfgd does "
				    "not", out->name);
				return 0;
			}
			reading.what = LOADED_NONE;
			reading.mask_length = 0;
		} else if (strcmp(name, "meta") == 0) {
			reading.what = LOADED_META;
			reading.mask_length = 0;
			reading.swapped = 0;
			(void)be32_member(&data, NFTA_META_KEY, &reading.key);
		} else if (strcmp(name, "byteorder") == 0) {
			uint32_t op = 0;
			uint32_t len = 0;
			uint32_t size = 0;

			/* Only as `put_schedule` writes it: the hour, to network order,
			 * four bytes of four. */
			if (reading.what != LOADED_META || reading.key != NFT_META_TIME_HOUR ||
			    !be32_member(&data, NFTA_BYTEORDER_OP, &op) || op != NFT_BYTEORDER_HTON ||
			    !be32_member(&data, NFTA_BYTEORDER_LEN, &len) || len != 4u ||
			    !be32_member(&data, NFTA_BYTEORDER_SIZE, &size) || size != 4u) {
				ncfg_error_set(err, err_size,
				    "rule `%s` has a byte-order swap netcfgd does not write", out->name);
				return 0;
			}
			reading.swapped = 1;
		} else if (strcmp(name, "range") == 0 && reading.what == LOADED_PAYLOAD) {
			/* A destination port range, as the builder writes it (0331):
			 * over the loaded port, network order, the lower end below the
			 * upper. */
			const uint8_t *from = NULL;
			const uint8_t *to = NULL;
			size_t         from_length = 0;
			size_t         to_length = 0;
			uint32_t       op = 0;
			uint16_t       low;
			uint16_t       high;

			if (reading.base != NFT_PAYLOAD_TRANSPORT_HEADER || reading.offset != 2u ||
			    reading.length != 2u || reading.mask_length != 0u || out->has_port ||
			    out->port_range[0] || !be32_member(&data, NFTA_RANGE_OP, &op) ||
			    op != NFT_RANGE_EQ ||
			    !data_value(&data, NFTA_RANGE_FROM_DATA, &from, &from_length) ||
			    !data_value(&data, NFTA_RANGE_TO_DATA, &to, &to_length) ||
			    from_length != 2u || to_length != 2u) {
				ncfg_error_set(err, err_size, "rule `%s` has a range netcfgd does not write",
				    out->name);
				return 0;
			}
			memcpy(&low, from, sizeof(low));
			memcpy(&high, to, sizeof(high));
			low = ntohs(low);
			high = ntohs(high);
			if (low < 1u || low >= high) {
				ncfg_error_set(err, err_size, "rule `%s` has a port range netcfgd does not "
				    "write", out->name);
				return 0;
			}
			(void)snprintf(out->port_range, sizeof(out->port_range), "%u-%u", (unsigned)low,
			    (unsigned)high);
			reading.what = LOADED_NONE;
		} else if (strcmp(name, "range") == 0) {
			const uint8_t *from = NULL;
			const uint8_t *to = NULL;
			size_t         from_length = 0;
			size_t         to_length = 0;
			uint32_t       op = 0;
			uint32_t       first;
			uint32_t       last;

			if (reading.what != LOADED_META || reading.key != NFT_META_TIME_HOUR ||
			    !reading.swapped || out->has_hours ||
			    !be32_member(&data, NFTA_RANGE_OP, &op) || op != NFT_RANGE_EQ ||
			    !data_value(&data, NFTA_RANGE_FROM_DATA, &from, &from_length) ||
			    !data_value(&data, NFTA_RANGE_TO_DATA, &to, &to_length) ||
			    from_length != 4u || to_length != 4u) {
				ncfg_error_set(err, err_size, "rule `%s` has a range netcfgd does not write",
				    out->name);
				return 0;
			}
			memcpy(&first, from, sizeof(first));
			memcpy(&last, to, sizeof(last));
			first = ntohl(first);
			last = ntohl(last);
			if (first > last || last >= (uint32_t)NCFG_SCHEDULE_DAY_SECONDS) {
				ncfg_error_set(err, err_size, "rule `%s` has an hour range netcfgd does not "
				    "write", out->name);
				return 0;
			}
			out->has_hours = 1;
			out->hour_from = first;
			out->hour_to = last;
			reading.what = LOADED_NONE;
			reading.swapped = 0;
		} else if (strcmp(name, "ct") == 0) {
			reading.what = LOADED_CT;
			reading.mask_length = 0;
			(void)be32_member(&data, NFTA_CT_KEY, &reading.key);
		} else if (strcmp(name, "payload") == 0) {
			reading.what = LOADED_PAYLOAD;
			reading.mask_length = 0;
			(void)be32_member(&data, NFTA_PAYLOAD_BASE, &reading.base);
			(void)be32_member(&data, NFTA_PAYLOAD_OFFSET, &reading.offset);
			(void)be32_member(&data, NFTA_PAYLOAD_LEN, &reading.length);
		} else if (strcmp(name, "bitwise") == 0) {
			const uint8_t *mask = NULL;
			const uint8_t *xor_bytes = NULL;
			size_t         mask_length = 0;
			size_t         xor_length = 0;
			size_t         at;
			int            flips = 0;

			if (!data_value(&data, NFTA_BITWISE_MASK, &mask, &mask_length) ||
			    mask_length > sizeof(reading.mask) ||
			    (data_value(&data, NFTA_BITWISE_XOR, &xor_bytes, &xor_length) &&
			    xor_length != mask_length)) {
				ncfg_error_set(err, err_size, "rule `%s` has a mask netcfgd does not write",
				    out->name);
				return 0;
			}
			memset(reading.xor_bytes, 0, sizeof(reading.xor_bytes));
			if (xor_bytes) {
				memcpy(reading.xor_bytes, xor_bytes, xor_length);
			}
			for (at = 0; at < mask_length; at++) {
				flips = flips || reading.xor_bytes[at];
			}
			/* Only the mark is ever flipped as well as masked (0338). */
			if (flips && !(reading.what == LOADED_META && reading.key == NFT_META_MARK)) {
				ncfg_error_set(err, err_size, "rule `%s` has a mask netcfgd does not write",
				    out->name);
				return 0;
			}
			memcpy(reading.mask, mask, mask_length);
			reading.mask_length = mask_length;
		} else if (strcmp(name, "cmp") == 0 && reading.what == LOADED_META &&
		    reading.key == NFT_META_MARK) {
			/* `meta mark & BIT == BIT`, once, in a verdict's rule with no meter
			 * of its own (0338). */
			const uint8_t *value = NULL;
			size_t         value_length = 0;
			uint32_t       op = 0;
			uint32_t       mask = 0;
			uint32_t       xor_value = 0;
			uint32_t       want = 0;

			if (reading.mask_length == 4u) {
				memcpy(&mask, reading.mask, sizeof(mask));
				memcpy(&xor_value, reading.xor_bytes, sizeof(xor_value));
			}
			if (data_value(&data, NFTA_CMP_DATA, &value, &value_length) && value_length == 4u) {
				memcpy(&want, value, sizeof(want));
			}
			if (!be32_member(&data, NFTA_CMP_OP, &op) || op != NFT_CMP_EQ ||
			    mask != NCFG_NFT_MARK_BIT || xor_value != 0u || want != NCFG_NFT_MARK_BIT ||
			    mark_tested || mark_cleared || out->over[0] || logging) {
				ncfg_error_set(err, err_size, "rule `%s` matches a packet mark netcfgd does "
				    "not write", out->name);
				return 0;
			}
			mark_tested = 1;
			reading.what = LOADED_NONE;
			reading.mask_length = 0;
		} else if (strcmp(name, "lookup") == 0 && reading.what == LOADED_PAYLOAD &&
		    reading.base == NFT_PAYLOAD_NETWORK_HEADER &&
		    ((reading.length == 4u && (reading.offset == 12u || reading.offset == 16u)) ||
		    (reading.length == 16u && (reading.offset == 8u || reading.offset == 24u)))) {
			/* A slot's members (10.932): `ip saddr @slot-NAME-4`, read back as
			 * the `@slot:NAME` the rule was written with. Only a slot's set. */
			char         set[NCFG_NFT_NAME_MAX];
			const int    source = reading.offset == 12u || reading.offset == 8u;
			size_t       named;

			if (!read_name(&data, NFTA_LOOKUP_SET, set, sizeof(set), NULL, 0) ||
			    strncmp(set, "slot-", 5u) != 0 || (named = strlen(set)) < 8u ||
			    named > 5u + NCFG_FIREWALL_SLOT_NAME_MAX + 2u ||
			    set[named - 2u] != '-' ||
			    set[named - 1u] != (reading.length == 16u ? '6' : '4')) {
				ncfg_error_set(err, err_size, "rule `%s` looks up a set netcfgd does not write",
				    out->name);
				return 0;
			}
			set[named - 2u] = '\0';
			(void)snprintf(source ? out->from : out->to, sizeof(out->from), "@slot:%.48s",
			    set + 5);
			reading.what = LOADED_NONE;
			reading.mask_length = 0;
		} else if (strcmp(name, "cmp") == 0) {
			if (!read_cmp_into(&reading, &data, out, why, sizeof(why))) {
				ncfg_error_set(err, err_size, "rule `%s`: %s", out->name, why);
				return 0;
			}
			reading.what = LOADED_NONE;
			reading.mask_length = 0;
		} else if (strcmp(name, "immediate") == 0) {
			ncfg_wire_attr_t  outer;
			ncfg_wire_attrs_t nest;
			ncfg_wire_attr_t  inner;
			ncfg_wire_attrs_t verdict_area;
			uint32_t          code = 0;

			if (ncfg_wire_attrs_find(&data, NFTA_IMMEDIATE_DATA, &outer, NULL, 0) !=
			    NCFG_WIRE_OK) {
				ncfg_error_set(err, err_size, "rule `%s` has no verdict", out->name);
				return 0;
			}
			ncfg_wire_attrs_start(&nest, outer.value, outer.length);
			if (ncfg_wire_attrs_find(&nest, NFTA_DATA_VERDICT, &inner, NULL, 0) !=
			    NCFG_WIRE_OK) {
				ncfg_error_set(err, err_size, "rule `%s` has no verdict", out->name);
				return 0;
			}
			ncfg_wire_attrs_start(&verdict_area, inner.value, inner.length);
			if (!be32_member(&verdict_area, NFTA_VERDICT_CODE, &code) ||
			    (code != NF_ACCEPT && code != NF_DROP)) {
				ncfg_error_set(err, err_size, "rule `%s` has a verdict netcfgd does not write",
				    out->name);
				return 0;
			}
			out->action = code == NF_DROP ? NCFG_FIREWALL_DROP : NCFG_FIREWALL_ACCEPT;
			verdict = 1;
		} else if (strcmp(name, "reject") == 0) {
			uint32_t type = NFT_REJECT_ICMPX_UNREACH;

			/* The two answers netcfgd writes, and no other (0332). */
			(void)be32_member(&data, NFTA_REJECT_TYPE, &type);
			if (type != NFT_REJECT_TCP_RST && type != NFT_REJECT_ICMPX_UNREACH) {
				ncfg_error_set(err, err_size, "rule `%s` rejects in a way netcfgd does not "
				    "write", out->name);
				return 0;
			}
			out->reset = type == NFT_REJECT_TCP_RST;
			out->action = NCFG_FIREWALL_REJECT;
			verdict = 1;
		} else if (strcmp(name, "limit") == 0) {
			/* Only as `put_log` writes it, and only once (0330). */
			uint64_t rate = 0, unit = 0;
			uint32_t burst = 0, type = 0, flags = 1;

			if (logging || !be64_member(&data, NFTA_LIMIT_RATE, &rate) || rate != LOG_RATE ||
			    !be64_member(&data, NFTA_LIMIT_UNIT, &unit) || unit != LOG_UNIT ||
			    !be32_member(&data, NFTA_LIMIT_BURST, &burst) || burst != LOG_BURST ||
			    !be32_member(&data, NFTA_LIMIT_TYPE, &type) || type != NFT_LIMIT_PKTS ||
			    (be32_member(&data, NFTA_LIMIT_FLAGS, &flags) && flags != 0u)) {
				ncfg_error_set(err, err_size, "rule `%s` has a `limit` netcfgd does not write",
				    out->name);
				return 0;
			}
			logging = 1;
		} else if (strcmp(name, "log") == 0) {
			char want[LOG_PREFIX_MAX];
			char said[LOG_PREFIX_MAX + 1u];

			/* The prefix names the rule, so one that does not is not this
			 * rule's log: something wrote it, and it is not netcfgd. */
			log_prefix(out->chain, out->name, want, sizeof(want));
			if (logging != 1 ||
			    !read_name(&data, NFTA_LOG_PREFIX, said, sizeof(said), NULL, 0) ||
			    strcmp(said, want) != 0) {
				ncfg_error_set(err, err_size, "rule `%s` has a `log` netcfgd does not write",
				    out->name);
				return 0;
			}
			logging = 2;
			out->log = 1;
			verdict = 1;
		} else if (strcmp(name, "counter") == 0) {
			/* Only once, and not in a log rule (10.901). What it holds is
			 * the count, which nothing compares. */
			if (logging || (mark_tested && !mark_released)) {
				ncfg_error_set(err, err_size, "rule `%s` has a `counter` netcfgd does not "
				    "write", out->name);
				return 0;
			}
			out->counted = 1;
			(void)be64_member(&data, NFTA_COUNTER_PACKETS, &out->packets);
			(void)be64_member(&data, NFTA_COUNTER_BYTES, &out->bytes);
		} else if (strcmp(name, "dynset") == 0) {
			if (out->over[0] || mark_tested || !read_over(&reading, &data, out)) {
				ncfg_error_set(err, err_size, "rule `%s` has a `dynset` netcfgd does not "
				    "write", out->name);
				return 0;
			}
			reading.what = LOADED_NONE;
		} else {
			ncfg_error_set(err, err_size, "rule `%s` has a `%s` expression, which netcfgd "
			    "does not write", out->name, name);
			return 0;
		}
	}
	if (!verdict) {
		ncfg_error_set(err, err_size, "rule `%s` has no verdict", out->name);
		return 0;
	}
	/* The mark in one of its two shapes or not at all (0338): a log's rule
	 * with a meter clears it ahead and sets it past, and a verdict's rule
	 * matches it and clears it before the counter. */
	if (out->log ? (out->over[0] != '\0') != (mark_cleared && mark_set) || mark_tested
	             : mark_cleared || mark_set || mark_tested != mark_released) {
		ncfg_error_set(err, err_size, "rule `%s` uses the packet mark where netcfgd does not",
		    out->name);
		return 0;
	}
	out->marked = mark_set || mark_tested;
	return 1;
}

/* ------------------------------------------------------------------------ *
 * Reading port forwards back (0298)
 * ------------------------------------------------------------------------ */

/* The register a `be32` member names, or 0 where it is missing. */
static uint32_t register_of(const ncfg_wire_attrs_t *area, uint16_t kind)
{
	uint32_t reg = 0;

	(void)be32_member(area, kind, &reg);
	return reg;
}

/* What a forward rule's expressions matched, as the decoder walks them. */
typedef struct {
	char     iif[NCFG_NFT_IFNAME_MAX];
	int      iif_op; /* 0 none, 1 equal, 2 not equal */
	char     oif[NCFG_NFT_IFNAME_MAX];
	int      ipv4;
	int      ipv6;
	int      has_saddr;
	uint8_t  saddr[4];
	int      saddr_prefix;
	int      has_daddr;
	uint8_t  daddr[4];
	int      has_proto;
	uint8_t  proto;
	int      has_dport;
	uint16_t dport;
	int      has_to;
	uint8_t  to[16];
	size_t   to_length;
	int      has_to_port;
	uint16_t to_port;
	int      nat;
	uint32_t nat_family;
	int      masq;
} forward_seen_t;

/* One comparison, into what the register held. 0 for one netcfgd does not
 * write. */
static int forward_cmp(const reading_t *reading, uint32_t op, const uint8_t *bytes,
    size_t length, forward_seen_t *seen)
{
	if (reading->what == LOADED_META && (reading->key == NFT_META_IIFNAME ||
	        reading->key == NFT_META_OIFNAME)) {
		char *into = reading->key == NFT_META_IIFNAME ? seen->iif : seen->oif;

		if (length == 0u || length > NCFG_NFT_IFNAME_MAX || bytes[length - 1u] != '\0' ||
		    (op != NFT_CMP_EQ && !(op == NFT_CMP_NEQ && reading->key == NFT_META_IIFNAME))) {
			return 0;
		}
		memcpy(into, bytes, length);
		if (reading->key == NFT_META_IIFNAME) {
			seen->iif_op = op == NFT_CMP_EQ ? 1 : 2;
		}
		return 1;
	}
	if (op != NFT_CMP_EQ) {
		return 0;
	}
	if (reading->what == LOADED_META && reading->key == NFT_META_NFPROTO) {
		seen->ipv4 = length == 1u && bytes[0] == NFPROTO_IPV4;
		seen->ipv6 = length == 1u && bytes[0] == NFPROTO_IPV6;
		return seen->ipv4 || seen->ipv6;
	}
	if (reading->what == LOADED_META && reading->key == NFT_META_L4PROTO) {
		if (length != 1u || (bytes[0] != IPPROTO_TCP && bytes[0] != IPPROTO_UDP)) {
			return 0;
		}
		seen->has_proto = 1;
		seen->proto = bytes[0];
		return 1;
	}
	if (reading->what == LOADED_PAYLOAD && reading->base == NFT_PAYLOAD_TRANSPORT_HEADER &&
	    reading->offset == 2u && reading->length == 2u && length == 2u &&
	    reading->mask_length == 0u) {
		uint16_t port;

		memcpy(&port, bytes, 2u);
		seen->has_dport = 1;
		seen->dport = ntohs(port);
		return 1;
	}
	/* A source as netcfgd writes it, the whole address masked, or as nft
	 * compiles a prefix from text, its leading bytes (10.899). */
	if (reading->what == LOADED_PAYLOAD && reading->base == NFT_PAYLOAD_NETWORK_HEADER &&
	    reading->offset == 12u && reading->length >= 1u && reading->length <= 4u &&
	    length == reading->length && seen->ipv4 &&
	    (reading->mask_length == 0u || reading->mask_length == length)) {
		seen->has_saddr = 1;
		memset(seen->saddr, 0, sizeof(seen->saddr));
		memcpy(seen->saddr, bytes, length);
		seen->saddr_prefix = reading->mask_length ? prefix_of(reading->mask, length)
		                                          : (int)(length * 8u);
		return seen->saddr_prefix >= 0;
	}
	if (reading->what == LOADED_PAYLOAD && reading->base == NFT_PAYLOAD_NETWORK_HEADER &&
	    reading->length == 4u && length == 4u && seen->ipv4) {
		if (reading->offset == 16u && reading->mask_length == 0u) {
			seen->has_daddr = 1;
			memcpy(seen->daddr, bytes, 4u);
			return 1;
		}
	}
	return 0;
}

int ncfg_nft_forward_read(const void *payload, size_t length, ncfg_nft_kernel_forward_t *out,
    char *err, size_t err_size)
{
	ncfg_wire_attrs_t      area;
	ncfg_wire_attrs_t      expressions;
	ncfg_wire_attr_t       attr;
	ncfg_wire_attr_t       element;
	ncfg_nft_kernel_rule_t identity;
	reading_t              reading;
	forward_seen_t         seen;
	char                   name[NCFG_NFT_NAME_MAX];
	char                   chain[NCFG_NFT_NAME_MAX];
	const char            *slash;
	char                  *at_sign;
	const char            *role;
	int                    shape;

	if (!out) {
		ncfg_error_set(err, err_size, "a forward read needs somewhere to go");
		return 0;
	}
	memset(out, 0, sizeof(*out));
	memset(&identity, 0, sizeof(identity));
	memset(&reading, 0, sizeof(reading));
	memset(&seen, 0, sizeof(seen));
	if (!payload_attrs(payload, length, &area, err, err_size)) {
		return 0;
	}
	if (((const uint8_t *)payload)[0] != NFPROTO_INET ||
	    !read_name(&area, NFTA_RULE_TABLE, name, sizeof(name), err, err_size) ||
	    strcmp(name, NCFG_NFT_TABLE) != 0) {
		ncfg_error_set(err, err_size, "a rule outside netcfgd's table, which is not read");
		return 0;
	}
	if (!read_name(&area, NFTA_RULE_CHAIN, chain, sizeof(chain), err, err_size) ||
	    (strcmp(chain, NCFG_NFT_CHAIN_PREROUTING) != 0 && strcmp(chain, NCFG_NFT_CHAIN) != 0)) {
		ncfg_error_set(err, err_size, "a rule outside the prerouting chain");
		return 0;
	}
	/* `postrouting` holds the masquerade too, and a rule there with no
	 * forward's identity is the uplink reader's, not a refusal here. */
	if (!read_comment(&area, &identity) || !(slash = strchr(identity.name, '/')) ||
	    slash == identity.name || slash[1] == '\0' ||
	    (size_t)(slash - identity.name) >= sizeof(out->interface)) {
		ncfg_error_set(err, err_size, strcmp(chain, NCFG_NFT_CHAIN) == 0
		    ? "a rule outside the prerouting chain"
		    : "a prerouting rule with no `name=IF/NAME sha256=...` comment, so not one netcfgd "
		      "wrote");
		return 0;
	}
	memcpy(out->interface, identity.name, (size_t)(slash - identity.name));
	out->interface[slash - identity.name] = '\0';
	(void)snprintf(out->name, sizeof(out->name), "%s", slash + 1);
	memcpy(out->digest, identity.digest, sizeof(out->digest));
	at_sign = strchr(out->name, '@');
	role = "";
	if (at_sign) {
		*at_sign = '\0';
		role = at_sign + 1;
	}
	if (strcmp(role, "") == 0) {
		out->kind = NCFG_FORWARD_RULE_FORWARD;
	} else if (strcmp(role, "reflect") == 0) {
		out->kind = NCFG_FORWARD_RULE_REFLECT;
	} else if (strcmp(role, "hairpin") == 0) {
		out->kind = NCFG_FORWARD_RULE_HAIRPIN;
	} else {
		ncfg_error_set(err, err_size, "forward `%s` names a role `%s` netcfgd does not write",
		    identity.name, role);
		return 0;
	}
	if ((out->kind == NCFG_FORWARD_RULE_HAIRPIN) != (strcmp(chain, NCFG_NFT_CHAIN) == 0)) {
		ncfg_error_set(err, err_size, "forward `%s` is in the wrong chain for its role",
		    identity.name);
		return 0;
	}

	if (ncfg_wire_attrs_find(&area, NFTA_RULE_EXPRESSIONS, &attr, NULL, 0) != NCFG_WIRE_OK) {
		ncfg_error_set(err, err_size, "forward `%s` has no expressions", identity.name);
		return 0;
	}
	ncfg_wire_attrs_start(&expressions, attr.value, attr.length);
	while (ncfg_wire_attrs_next(&expressions, &element, err, err_size) == NCFG_WIRE_OK) {
		ncfg_wire_attrs_t expression;
		ncfg_wire_attrs_t data;
		ncfg_wire_attr_t  data_attr;
		const uint8_t    *bytes = NULL;
		size_t            bytes_length = 0;
		uint32_t          value = 0;

		if (element.kind != NFTA_LIST_ELEM) {
			continue;
		}
		ncfg_wire_attrs_start(&expression, element.value, element.length);
		if (!read_name(&expression, NFTA_EXPR_NAME, name, sizeof(name), NULL, 0)) {
			ncfg_error_set(err, err_size, "forward `%s` has an expression with no name",
			    identity.name);
			return 0;
		}
		memset(&data, 0, sizeof(data));
		if (ncfg_wire_attrs_find(&expression, NFTA_EXPR_DATA, &data_attr, NULL, 0) ==
		    NCFG_WIRE_OK) {
			ncfg_wire_attrs_start(&data, data_attr.value, data_attr.length);
		}
		if (seen.nat || seen.masq) {
			ncfg_error_set(err, err_size, "forward `%s` has an expression after its translation",
			    identity.name);
			return 0;
		}
		if (strcmp(name, "meta") == 0) {
			reading.what = LOADED_META;
			reading.mask_length = 0;
			(void)be32_member(&data, NFTA_META_KEY, &reading.key);
		} else if (strcmp(name, "payload") == 0) {
			reading.what = LOADED_PAYLOAD;
			reading.mask_length = 0;
			(void)be32_member(&data, NFTA_PAYLOAD_BASE, &reading.base);
			(void)be32_member(&data, NFTA_PAYLOAD_OFFSET, &reading.offset);
			(void)be32_member(&data, NFTA_PAYLOAD_LEN, &reading.length);
		} else if (strcmp(name, "bitwise") == 0) {
			const uint8_t *mask = NULL;
			size_t         mask_length = 0;

			if (!data_value(&data, NFTA_BITWISE_MASK, &mask, &mask_length) ||
			    mask_length > sizeof(reading.mask)) {
				ncfg_error_set(err, err_size, "forward `%s` has a mask netcfgd does not write",
				    identity.name);
				return 0;
			}
			memcpy(reading.mask, mask, mask_length);
			reading.mask_length = mask_length;
		} else if (strcmp(name, "cmp") == 0) {
			if (!be32_member(&data, NFTA_CMP_OP, &value) ||
			    !data_value(&data, NFTA_CMP_DATA, &bytes, &bytes_length) ||
			    !forward_cmp(&reading, value, bytes, bytes_length, &seen)) {
				ncfg_error_set(err, err_size, "forward `%s` has a comparison netcfgd does not "
				    "write", identity.name);
				return 0;
			}
			reading.what = LOADED_NONE;
			reading.mask_length = 0;
		} else if (strcmp(name, "immediate") == 0) {
			const uint32_t reg = register_of(&data, NFTA_IMMEDIATE_DREG);

			if (!data_value(&data, NFTA_IMMEDIATE_DATA, &bytes, &bytes_length) ||
			    !((reg == NFT_REG_1 && (bytes_length == 4u || bytes_length == 16u) &&
			          !seen.has_to) ||
			    (reg == NFT_REG_2 && bytes_length == 2u && seen.has_to && !seen.has_to_port))) {
				ncfg_error_set(err, err_size, "forward `%s` loads something netcfgd does not "
				    "write", identity.name);
				return 0;
			}
			if (reg == NFT_REG_1) {
				memcpy(seen.to, bytes, bytes_length);
				seen.to_length = bytes_length;
				seen.has_to = 1;
			} else {
				uint16_t port;

				memcpy(&port, bytes, 2u);
				seen.to_port = ntohs(port);
				seen.has_to_port = 1;
			}
		} else if (strcmp(name, "nat") == 0) {
			/* The kernel echoes a range's maximum as its minimum where none
			 * was given, so both are allowed and must agree. */
			if (register_of(&data, NFTA_NAT_TYPE) != NFT_NAT_DNAT ||
			    (register_of(&data, NFTA_NAT_FAMILY) != NFPROTO_IPV4 &&
			    register_of(&data, NFTA_NAT_FAMILY) != NFPROTO_IPV6) ||
			    register_of(&data, NFTA_NAT_REG_ADDR_MIN) != NFT_REG_1 ||
			    register_of(&data, NFTA_NAT_REG_PROTO_MIN) != NFT_REG_2 ||
			    (register_of(&data, NFTA_NAT_REG_ADDR_MAX) != 0u &&
			    register_of(&data, NFTA_NAT_REG_ADDR_MAX) != NFT_REG_1) ||
			    (register_of(&data, NFTA_NAT_REG_PROTO_MAX) != 0u &&
			    register_of(&data, NFTA_NAT_REG_PROTO_MAX) != NFT_REG_2)) {
				ncfg_error_set(err, err_size, "forward `%s` translates in a way netcfgd does "
				    "not write", identity.name);
				return 0;
			}
			seen.nat = 1;
			seen.nat_family = register_of(&data, NFTA_NAT_FAMILY);
		} else if (strcmp(name, "masq") == 0) {
			seen.masq = 1;
		} else {
			ncfg_error_set(err, err_size, "forward `%s` has a `%s` expression, which netcfgd "
			    "does not write", identity.name, name);
			return 0;
		}
	}

	/* Exactly the matches the role is written with, and no others. */
	switch (out->kind) {
	case NCFG_FORWARD_RULE_FORWARD:
		/* IPv4 with no family match, as 0298 wrote it, IPv4 with one and a
		 * source (0336), or IPv6 with one (0305) -- the family, the address
		 * and the translation agreeing. */
		shape = seen.iif_op == 1 && !seen.oif[0] && seen.ipv4 == seen.has_saddr &&
		    !seen.has_daddr && seen.has_to && seen.has_to_port && seen.nat &&
		    (seen.ipv6 ? seen.to_length == 16u && seen.nat_family == NFPROTO_IPV6
		               : seen.to_length == 4u && seen.nat_family == NFPROTO_IPV4);
		break;
	case NCFG_FORWARD_RULE_REFLECT:
		shape = seen.iif_op == 2 && !seen.oif[0] && seen.ipv4 &&
		    seen.has_daddr && seen.has_to && seen.to_length == 4u && seen.has_to_port &&
		    seen.nat && seen.nat_family == NFPROTO_IPV4;
		break;
	default:
		shape = seen.iif_op == 0 && seen.oif[0] && seen.ipv4 && !seen.ipv6 && seen.has_saddr &&
		    seen.has_daddr && !seen.has_to && seen.masq;
		break;
	}
	if (!shape || !seen.has_proto || !seen.has_dport) {
		ncfg_error_set(err, err_size, "forward `%s` is not the shape netcfgd writes for it",
		    identity.name);
		return 0;
	}
	out->protocol = seen.proto == IPPROTO_UDP ? NCFG_PORT_FORWARD_UDP : NCFG_PORT_FORWARD_TCP;
	out->port = seen.dport;
	if (out->kind == NCFG_FORWARD_RULE_HAIRPIN) {
		char net[16];

		memcpy(seen.to, seen.daddr, 4u);
		seen.to_length = 4u;
		seen.to_port = seen.dport;
		(void)snprintf(out->via, sizeof(out->via), "%s", seen.oif);
		if (!inet_ntop(AF_INET, seen.saddr, net, sizeof(net))) {
			ncfg_error_set(err, err_size, "forward `%s` masquerades a network it cannot print",
			    identity.name);
			return 0;
		}
		(void)snprintf(out->network, sizeof(out->network), "%s/%d", net, seen.saddr_prefix);
	} else {
		if (strcmp(seen.iif, out->interface) != 0) {
			ncfg_error_set(err, err_size, "forward `%s` matches interface `%s`, not the one its "
			    "comment names", identity.name, seen.iif);
			return 0;
		}
		if (out->kind == NCFG_FORWARD_RULE_REFLECT &&
		    !inet_ntop(AF_INET, seen.daddr, out->address, sizeof(out->address))) {
			ncfg_error_set(err, err_size, "forward `%s` is reflected at an address it cannot "
			    "print", identity.name);
			return 0;
		}
		if (seen.has_saddr) {
			format_address(NFPROTO_IPV4, seen.saddr, (uint32_t)seen.saddr_prefix, out->from,
			    sizeof(out->from));
		}
	}
	out->to_port = seen.to_port;
	if (!inet_ntop(seen.to_length == 16u ? AF_INET6 : AF_INET, seen.to, out->to,
	        sizeof(out->to))) {
		ncfg_error_set(err, err_size, "forward `%s` sends to an address it cannot print",
		    identity.name);
		return 0;
	}
	return 1;
}

const char *ncfg_nft_kernel_rule_action_word(const ncfg_nft_kernel_rule_t *rule)
{
	return rule->log ? "log" : ncfg_nft_action_word(rule->action);
}

const char *ncfg_nft_action_word(int action)
{
	switch (action) {
	case NCFG_FIREWALL_ACCEPT:
		return "accept";
	case NCFG_FIREWALL_DROP:
		return "drop";
	case NCFG_FIREWALL_REJECT:
		return "reject";
	case NCFG_FIREWALL_NONE:
		return "none";
	default:
		return NULL;
	}
}

const char *ncfg_nft_protocol_word(int protocol)
{
	switch (protocol) {
	case NCFG_FIREWALL_PROTO_ANY:
		return "any";
	case NCFG_FIREWALL_PROTO_TCP:
		return "tcp";
	case NCFG_FIREWALL_PROTO_UDP:
		return "udp";
	case NCFG_FIREWALL_PROTO_ICMP:
		return "icmp";
	case NCFG_FIREWALL_PROTO_ICMPV6:
		return "icmpv6";
	case NCFG_FIREWALL_PROTO_GRE:
		return "gre";
	case NCFG_FIREWALL_PROTO_ESP:
		return "esp";
	case NCFG_FIREWALL_PROTO_AH:
		return "ah";
	case NCFG_FIREWALL_PROTO_SCTP:
		return "sctp";
	case NCFG_FIREWALL_PROTO_IPIP:
		return "ipip";
	case NCFG_FIREWALL_PROTO_SIT:
		return "sit";
	default:
		return NULL;
	}
}

const char *ncfg_nft_state_word(unsigned bit)
{
	static const char *const words[] = { "new", "established", "related", "invalid" };

	return bit < sizeof(words) / sizeof(words[0]) ? words[bit] : NULL;
}

/* Two optional strings: absent and empty are one answer, which is how the
 * decoder leaves a match it did not see. */
void ncfg_nft_kernel_rule_time(const ncfg_nft_kernel_rule_t *rule, char *out, size_t out_size)
{
	ncfg_schedule_piece_t piece;

	if (!rule->has_hours) {
		if (out_size) {
			out[0] = '\0';
		}
		return;
	}
	piece.day = rule->has_day ? (int)rule->day : -1;
	piece.from = (long)rule->hour_from;
	piece.to = (long)rule->hour_to;
	ncfg_schedule_piece_text(&piece, out, out_size);
}

static int same_text(const char *one, const char *other)
{
	return strcmp(one ? one : "", other ? other : "") == 0;
}

int ncfg_nft_kernel_rule_matches(const ncfg_nft_kernel_rule_t *expected,
    const ncfg_observed_firewall_rule_t *observed)
{
	size_t   at;
	unsigned states = 0;

	if (!expected || !observed) {
		return 0;
	}
	if (!same_text(expected->chain, observed->chain) ||
	    !same_text(expected->name, observed->name) ||
	    !same_text(expected->digest, observed->digest) ||
	    !same_text(ncfg_nft_kernel_rule_action_word(expected), observed->action) ||
	    !same_text(ncfg_nft_protocol_word(expected->protocol), observed->protocol) ||
	    expected->has_port != observed->port.has ||
	    (expected->has_port && (int64_t)expected->port != observed->port.value) ||
	    !same_text(expected->from, observed->from) || !same_text(expected->to, observed->to) ||
	    !same_text(expected->interface, observed->interface) ||
	    !same_text(expected->out_interface, observed->out_interface) ||
	    !same_text(expected->mac, observed->mac) ||
	    (expected->translated != 0) != (observed->translated != 0) ||
	    !same_text(expected->over, observed->over) ||
	    !same_text(expected->port_range, observed->port_range) ||
	    (expected->reset != 0) != (observed->reset != 0) ||
	    (expected->marked != 0) != (observed->marked != 0) ||
	    (expected->counted != 0) != (observed->packets.has != 0) ||
	    expected->has_icmp_type != observed->icmp_type.has ||
	    (expected->has_icmp_type && (int64_t)expected->icmp_type != observed->icmp_type.value)) {
		return 0;
	}
	{
		char time[NCFG_NFT_TIME_TEXT];

		ncfg_nft_kernel_rule_time(expected, time, sizeof(time));
		if (!same_text(time, observed->time)) {
			return 0;
		}
	}
	for (at = 0; at < observed->state_count; at++) {
		unsigned bit;

		for (bit = 0; bit < 4u; bit++) {
			if (same_text(ncfg_nft_state_word(bit), observed->states[at])) {
				states |= 1u << bit;
			}
		}
	}
	return states == expected->states;
}

static const char *policy_text(int policy)
{
	return policy == NCFG_FIREWALL_POLICY_DROP ? "drop" : "accept";
}

/*
 * Whether the installed firewall is the document's, exactly.
 *
 * **The document's own transaction, decoded, is what is compared**: the
 * builder writes it, the decoder reads it back into the kernel rules a
 * converged machine holds, and those are matched against the observation in
 * order, field by field and identity by identity -- the same reader on both
 * sides, so a difference is in the kernel and not in two renderings of one
 * rule. A rule the decoder refused (`unread`) is somebody's hand edit, and a
 * table holding one is not converged.
 *
 * `refusal` is set where the document's firewall cannot be built at all, and
 * the answer is then "not converged": the op is planned and fails at apply
 * naming the rule, which is 0294's all-or-nothing.
 */
int ncfg_nft_firewall_matches(const ncfg_firewall_t *desired,
    const ncfg_observed_firewall_t *observed, char *refusal, size_t refusal_size)
{
	ncfg_buf_t           built;
	ncfg_nft_batch_t     batch;
	ncfg_wire_messages_t walk;
	ncfg_wire_message_t  message;
	size_t               at = 0;
	size_t               slots = 0;
	int                  same = 1;

	refusal[0] = '\0';
	if (!desired || !observed) {
		return !desired && !observed;
	}
	if (observed->unread_count != 0u ||
	    strcmp(policy_text(desired->input.policy), observed->input ? observed->input : "") ||
	    strcmp(policy_text(desired->forward.policy),
	        observed->forward ? observed->forward : "") ||
	    strcmp(policy_text(desired->output.policy), observed->output ? observed->output : "")) {
		return 0;
	}
	ncfg_buf_init(&built, 0);
	if (!ncfg_nft_build_replace(&built, 1u, 0, NULL, 0, desired, &batch, refusal,
	        refusal_size)) {
		ncfg_buf_free(&built);
		return 0;
	}
	ncfg_wire_messages_start(&walk, built.data, built.length);
	while (same && ncfg_wire_messages_next(&walk, &message, NULL, 0) == NCFG_WIRE_OK) {
		ncfg_nft_kernel_rule_t expected;
		ncfg_nft_kernel_slot_t opened;

		if ((message.header.kind & 0xffu) != NFT_MSG_NEWRULE) {
			continue;
		}
		/* A slot's rule (0340), against the observed slots in their order:
		 * the slot as its rule carries it, never its members. */
		if (ncfg_nft_rule_slot(message.payload, message.payload_length, &opened)) {
			const ncfg_observed_firewall_slot_t *seen =
			    slots < observed->slot_count ? &observed->slots[slots] : NULL;

			same = seen && seen->chain && seen->name && seen->action && seen->match &&
			    strcmp(seen->chain, opened.chain) == 0 &&
			    strcmp(seen->name, opened.name) == 0 &&
			    strcmp(seen->action, ncfg_nft_action_word(opened.slot.action)) == 0 &&
			    strcmp(seen->match,
			        opened.slot.match == NCFG_FIREWALL_SLOT_TO ? "to" : "from") == 0 &&
			    seen->timeout == opened.slot.timeout && seen->ipv6 == opened.ipv6;
			slots++;
			continue;
		}
		if (!ncfg_nft_firewall_rule_read(message.payload, message.payload_length, &expected,
		        NULL, 0)) {
			continue; /* the NAT chain's masquerade, which is not this half */
		}
		same = at < observed->rule_count &&
		    ncfg_nft_kernel_rule_matches(&expected, &observed->rules[at]);
		at++;
	}
	ncfg_buf_free(&built);
	return same && at == observed->rule_count && slots == observed->slot_count;
}


/* The kernel's pieces for one written rule, in the order they appear. */
static int observed_pieces(const ncfg_observed_firewall_t *observed, const char *chain,
    const char *name, char ***out, size_t *count)
{
	size_t at;

	*out = NULL;
	*count = 0;
	for (at = 0; at < observed->rule_count; at++) {
		const ncfg_observed_firewall_rule_t *one = &observed->rules[at];
		char                               **grown;
		size_t                               seen;
		int                                  repeat = 0;

		if (!one->time || !same_text(one->chain, chain) || !same_text(one->name, name)) {
			continue;
		}
		for (seen = 0; seen < *count; seen++) {
			repeat = repeat || strcmp((*out)[seen], one->time) == 0;
		}
		if (repeat) {
			continue;
		}
		grown = realloc(*out, (*count + 1u) * sizeof(**out));
		if (!grown) {
			return 0;
		}
		*out = grown;
		(*out)[*count] = strdup(one->time);
		if (!(*out)[*count]) {
			return 0;
		}
		(*count)++;
	}
	return *count != 0u;
}

int ncfg_nft_firewall_only_schedule_moved(const ncfg_firewall_t *desired,
    const ncfg_observed_firewall_t *observed)
{
	static const char *const names[3] = { NCFG_NFT_CHAIN_INPUT, NCFG_NFT_CHAIN_FORWARD,
		                              NCFG_NFT_CHAIN_OUTPUT };
	ncfg_firewall_t         *pinned;
	ncfg_firewall_chain_t   *chains[3];
	char                     refusal[NCFG_ERROR_MAX];
	size_t                   c;
	size_t                   r;
	int                      scheduled = 0;
	int                      moved;

	if (!desired || !observed || ncfg_nft_firewall_matches(desired, observed, refusal,
	        sizeof(refusal))) {
		return 0;
	}
	pinned = ncfg_firewall_copy(desired);
	if (!pinned) {
		return 0;
	}
	chains[0] = &pinned->input;
	chains[1] = &pinned->forward;
	chains[2] = &pinned->output;
	for (c = 0; c < 3u; c++) {
		for (r = 0; r < chains[c]->rule_count; r++) {
			ncfg_firewall_rule_t *rule = &chains[c]->rules[r];

			if (!rule->hours && rule->day_count == 0u) {
				continue;
			}
			scheduled = 1;
			/* A scheduled rule the kernel holds no pieces for is a rule
			 * missing, which is not the clock. */
			if (!observed_pieces(observed, names[c], rule->name, &rule->utc_pieces,
			        &rule->utc_piece_count)) {
				ncfg_firewall_free(pinned);
				return 0;
			}
		}
	}
	moved = scheduled && ncfg_nft_firewall_matches(pinned, observed, refusal, sizeof(refusal));
	ncfg_firewall_free(pinned);
	return moved;
}
