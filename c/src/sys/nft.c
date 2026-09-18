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

#include "ncfg/wire.h"

#include <arpa/inet.h>
#include <string.h>

#include <linux/netfilter.h>
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
		    name_must_be(&area, NFTA_CHAIN_NAME, NCFG_NFT_CHAIN, "chain", err, err_size);
	case NFT_MSG_NEWRULE:
		return name_must_be(&area, NFTA_RULE_TABLE, NCFG_NFT_TABLE, "table", err,
		    err_size) &&
		    name_must_be(&area, NFTA_RULE_CHAIN, NCFG_NFT_CHAIN, "chain", err, err_size);
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

int ncfg_nft_build_replace_nat(ncfg_buf_t *out, uint32_t first_seq, int table_exists,
    const char *const *uplinks, size_t uplink_count, ncfg_nft_batch_t *batch,
    char *err, size_t err_size)
{
	ncfg_buf_t transaction;
	ncfg_buf_t attrs;
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
	if (!table_exists && uplink_count == 0) {
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

	if (ok && uplink_count > 0) {
		ncfg_buf_init(&attrs, 0);
		ncfg_wire_attr_put_str(&attrs, NFTA_TABLE_NAME, NCFG_NFT_TABLE);
		last_acked = seq;
		/* `inet`, the family that sees both IPv4 and IPv6, so one table
		 * masquerades both rather than two tables each doing half. */
		ok = build(&transaction, NFT_MSG_NEWTABLE, (uint16_t)(NLM_F_ACK | NLM_F_CREATE),
		    seq++, NFPROTO_INET, &attrs, err, err_size);
		ncfg_buf_free(&attrs);

		if (ok) {
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
