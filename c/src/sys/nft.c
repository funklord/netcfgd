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
	NCFG_NFT_CHAIN_FORWARD, NCFG_NFT_CHAIN_OUTPUT, NCFG_NFT_CHAIN_PREROUTING };

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
	    "`prerouting`, `input`, `forward` and `output` and nothing else (0022, 0294, "
	    "0298)", name);
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
	default:
		break;
	}
	/* The set of messages netcfgd sends is closed: a table, a chain, three
	 * expressions and the dumps that read them back. A set-element, a
	 * flowtable or an object message arriving here means something upstream
	 * has started doing more than NAT, which is the line 0022 draws. */
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

/* `register 1 = register 1 & MASK`, which is how a prefix -- of an address or
 * a station -- is matched: mask, then compare. */
static void put_mask(ncfg_buf_t *list, const uint8_t *mask, size_t length)
{
	ncfg_buf_t data;
	uint8_t    zero[16];

	memset(zero, 0, sizeof(zero));
	ncfg_buf_init(&data, 0);
	put_be32(&data, NFTA_BITWISE_SREG, NFT_REG_1);
	put_be32(&data, NFTA_BITWISE_DREG, NFT_REG_1);
	put_be32(&data, NFTA_BITWISE_LEN, (uint32_t)length);
	put_data(&data, NFTA_BITWISE_MASK, mask, length);
	put_data(&data, NFTA_BITWISE_XOR, zero, length);
	put_expression(list, "bitwise", &data);
	ncfg_buf_free(&data);
}

/* An address or CIDR, as the family nftables names it, its bytes and its
 * prefix length. */
typedef struct {
	uint8_t  nfproto;
	uint8_t  bytes[16];
	uint32_t length;
	uint32_t prefix;
} nft_address_t;

static int parse_address(const char *text, nft_address_t *out, char *err, size_t err_size)
{
	char        host[64];
	const char *slash = strchr(text, '/');
	size_t      span = slash ? (size_t)(slash - text) : strlen(text);
	long        prefix = -1;

	memset(out, 0, sizeof(*out));
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

	if (!parse_address(text, &address, NULL, 0)) {
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
	default:
		return 0;
	}
}

int ncfg_nft_firewall_rule_text(const char *chain, const ncfg_firewall_rule_t *rule,
    ncfg_buf_t *out)
{
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
	for (at = 0; at < rule->mac_count; at++) {
		ncfg_buf_addf(out, "mac %s\n", rule->mac[at]);
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
static int firewall_rule(ncfg_buf_t *attrs, const char *chain, const ncfg_firewall_rule_t *rule,
    const char *comment, char *err, size_t err_size)
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

	ncfg_buf_init(&data, 0);
	if (rule->action == NCFG_FIREWALL_REJECT) {
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

static int firewall_rule_messages(ncfg_buf_t *transaction, uint32_t *seq, uint32_t *last_acked,
    const char *chain, const ncfg_firewall_rule_t *rule, char *err, size_t err_size)
{
	const size_t ports = rule->port_count ? rule->port_count : 1u;
	const size_t froms = rule->from_count ? rule->from_count : 1u;
	const size_t tos = rule->to_count ? rule->to_count : 1u;
	const size_t macs = rule->mac_count ? rule->mac_count : 1u;
	char         comment[NCFG_NFT_COMMENT_MAX + 1u];
	size_t       p, f, t, m;
	size_t       wrote = 0;

	if (ports * froms * tos * macs > FIREWALL_EXPANSION_MAX) {
		ncfg_error_set(err, err_size,
		    "rule `%s/%s` would be %zu kernel rules, one per combination of its ports, "
		    "addresses and stations, and %u is the most one rule may become; split it",
		    chain, rule->name, ports * froms * tos * macs, (unsigned)FIREWALL_EXPANSION_MAX);
		return 0;
	}
	if (!rule_comment(chain, rule, comment, sizeof(comment), err, err_size)) {
		return 0;
	}
	for (p = 0; p < ports; p++) {
		for (f = 0; f < froms; f++) {
			for (t = 0; t < tos; t++) {
				for (m = 0; m < macs; m++) {
					ncfg_firewall_rule_t one = *rule;
					nft_address_t        a;
					nft_address_t        b;
					ncfg_buf_t           attrs;
					int                  ok;

					one.port_count = rule->port_count ? 1u : 0u;
					one.ports = rule->port_count ? &rule->ports[p] : NULL;
					one.from_count = rule->from_count ? 1u : 0u;
					one.from = rule->from_count ? &rule->from[f] : NULL;
					one.to_count = rule->to_count ? 1u : 0u;
					one.to = rule->to_count ? &rule->to[t] : NULL;
					one.mac_count = rule->mac_count ? 1u : 0u;
					one.mac = rule->mac_count ? &rule->mac[m] : NULL;
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
					ncfg_buf_init(&attrs, 0);
					ok = firewall_rule(&attrs, chain, &one, comment, err, err_size);
					if (ok) {
						*last_acked = *seq;
						ok = build(transaction, NFT_MSG_NEWRULE,
						    (uint16_t)(NLM_F_ACK | NLM_F_CREATE | NLM_F_APPEND), (*seq)++,
						    NFPROTO_INET, &attrs, err, err_size);
					}
					ncfg_buf_free(&attrs);
					if (!ok) {
						return 0;
					}
					wrote++;
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
	return !ncfg_buf_failed(out);
}

/* What one forward rule needs to be written: its host's bytes, and for the
 * kinds that have them the uplink address and the host's network. */
typedef struct {
	uint8_t       to[4];
	uint8_t       address[4];
	nft_address_t network;
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
	if (inet_pton(AF_INET, forward->to, parts->to) != 1) {
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
		put_immediate(&expressions, NFT_REG_1, parts->to, 4u);
		put_immediate(&expressions, NFT_REG_2, &to_port, sizeof(to_port));
		ncfg_buf_init(&data, 0);
		put_be32(&data, NFTA_NAT_TYPE, NFT_NAT_DNAT);
		put_be32(&data, NFTA_NAT_FAMILY, NFPROTO_IPV4);
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
	    firewall, NULL, 0, batch, err, err_size);
}

int ncfg_nft_build_replace_all(ncfg_buf_t *out, uint32_t first_seq, int table_exists,
    const char *const *uplinks, size_t uplink_count, const ncfg_firewall_t *firewall,
    const ncfg_forward_rule_t *forwards, size_t forward_count, ncfg_nft_batch_t *batch,
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
	if (!table_exists && uplink_count == 0 && !firewall && forward_count == 0) {
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

	if (ok && (uplink_count > 0 || firewall || forward_count > 0)) {
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
				for (r = 0; ok && r < chains[c]->rule_count; r++) {
					ok = firewall_rule_messages(&transaction, &seq, &last_acked, names[c],
					    &chains[c]->rules[r], err, err_size);
				}
			}
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
		if (strcmp(name, "meta") == 0 && !read_meta(&data, &seen)) {
			return 0;
		}
		if (strcmp(name, "cmp") == 0 && !read_cmp(&data, &seen)) {
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
	size_t   mask_length; /* 0 where nothing was masked */
	uint8_t  family; /* from `meta nfproto`, for the addresses after it */
} reading_t;

static int be32_member(const ncfg_wire_attrs_t *area, uint16_t kind, uint32_t *out)
{
	ncfg_wire_attr_t attr;

	if (ncfg_wire_attrs_find(area, kind, &attr, NULL, 0) != NCFG_WIRE_OK) {
		return 0;
	}
	return attr_be32(&attr, out, NULL, 0);
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
		if (reading->base == NFT_PAYLOAD_NETWORK_HEADER &&
		    ((reading->length == 4u && reading->family == NFPROTO_IPV4 &&
		    (reading->offset == 12u || reading->offset == 16u)) ||
		    (reading->length == 16u && reading->family == NFPROTO_IPV6 &&
		    (reading->offset == 8u || reading->offset == 24u))) && length == reading->length) {
			const int source = reading->offset == 12u || reading->offset == 8u;
			int       prefix = (int)(length * 8u);

			if (reading->mask_length) {
				prefix = prefix_of(reading->mask, reading->mask_length);
				if (prefix < 0 || reading->mask_length != length) {
					ncfg_error_set(err, err_size, "an address mask that is not a prefix");
					return 0;
				}
			}
			format_address(reading->family, value, (uint32_t)prefix,
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
		if (strcmp(name, "meta") == 0) {
			reading.what = LOADED_META;
			reading.mask_length = 0;
			(void)be32_member(&data, NFTA_META_KEY, &reading.key);
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
			size_t         mask_length = 0;

			if (!data_value(&data, NFTA_BITWISE_MASK, &mask, &mask_length) ||
			    mask_length > sizeof(reading.mask)) {
				ncfg_error_set(err, err_size, "rule `%s` has a mask netcfgd does not write",
				    out->name);
				return 0;
			}
			memcpy(reading.mask, mask, mask_length);
			reading.mask_length = mask_length;
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
			out->action = NCFG_FIREWALL_REJECT;
			verdict = 1;
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
	uint8_t  to[4];
	int      has_to_port;
	uint16_t to_port;
	int      nat;
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
		return seen->ipv4;
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
	if (reading->what == LOADED_PAYLOAD && reading->base == NFT_PAYLOAD_NETWORK_HEADER &&
	    reading->length == 4u && length == 4u && seen->ipv4) {
		if (reading->offset == 12u) {
			seen->has_saddr = 1;
			memcpy(seen->saddr, bytes, 4u);
			seen->saddr_prefix = reading->mask_length == 4u
			    ? prefix_of(reading->mask, 4u) : 32;
			return seen->saddr_prefix >= 0;
		}
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
			    !((reg == NFT_REG_1 && bytes_length == 4u && !seen.has_to) ||
			    (reg == NFT_REG_2 && bytes_length == 2u && seen.has_to && !seen.has_to_port))) {
				ncfg_error_set(err, err_size, "forward `%s` loads something netcfgd does not "
				    "write", identity.name);
				return 0;
			}
			if (reg == NFT_REG_1) {
				memcpy(seen.to, bytes, 4u);
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
			    register_of(&data, NFTA_NAT_FAMILY) != NFPROTO_IPV4 ||
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
		shape = seen.iif_op == 1 && !seen.oif[0] && !seen.ipv4 && !seen.has_saddr &&
		    !seen.has_daddr && seen.has_to && seen.has_to_port && seen.nat;
		break;
	case NCFG_FORWARD_RULE_REFLECT:
		shape = seen.iif_op == 2 && !seen.oif[0] && seen.ipv4 && !seen.has_saddr &&
		    seen.has_daddr && seen.has_to && seen.has_to_port && seen.nat;
		break;
	default:
		shape = seen.iif_op == 0 && seen.oif[0] && seen.ipv4 && seen.has_saddr &&
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
	}
	out->to_port = seen.to_port;
	if (!inet_ntop(AF_INET, seen.to, out->to, sizeof(out->to))) {
		ncfg_error_set(err, err_size, "forward `%s` sends to an address it cannot print",
		    identity.name);
		return 0;
	}
	return 1;
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
	    !same_text(ncfg_nft_action_word(expected->action), observed->action) ||
	    !same_text(ncfg_nft_protocol_word(expected->protocol), observed->protocol) ||
	    expected->has_port != observed->port.has ||
	    (expected->has_port && (int64_t)expected->port != observed->port.value) ||
	    !same_text(expected->from, observed->from) || !same_text(expected->to, observed->to) ||
	    !same_text(expected->interface, observed->interface) ||
	    !same_text(expected->out_interface, observed->out_interface) ||
	    !same_text(expected->mac, observed->mac)) {
		return 0;
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

		if ((message.header.kind & 0xffu) != NFT_MSG_NEWRULE) {
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
	return same && at == observed->rule_count;
}

