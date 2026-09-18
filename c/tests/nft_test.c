/*
 * nft_test.c -- nftables, against bytes rather than against a ruleset.
 *
 * WHY THIS EXISTS
 *   Nothing below opens a socket, and that matters more here than anywhere
 *   else in the port: the machine this is developed on has a real nftables
 *   ruleset with real firewalling in it, and a test that sent what it built
 *   would be a test that could delete somebody's firewall to prove it does not
 *   delete somebody's firewall.
 *
 *   Every assertion about a built transaction is made by **walking the bytes
 *   back with the wire layer**. A hand-written blob would be a second encoder
 *   with no tests of its own, and the first time the two disagreed it is the
 *   test that would be believed.
 *
 * WHAT IS ACTUALLY AT STAKE
 *   Decision 0022 gives this module exactly one table and no more, because the
 *   alternative is a daemon that can break every container host on the machine
 *   -- Docker, podman and libvirt all insert rules into their own tables as
 *   containers come and go. So the centre of this file is not the round trip.
 *   It is the pair of checks that the only names written are netcfgd's own, and
 *   that a message naming anything else is refused -- and the *count* of names
 *   inspected is asserted with them, because a check that walked nothing would
 *   report success exactly as loudly as one that walked six.
 */
#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/nft.h"
#include "ncfg/wire.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter_ipv4.h>

static int failures;

static void check(int condition, const char *what)
{
	printf("%-70s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

/* See wire_test.c: a truncation tested as a prefix of a longer buffer is not
 * tested at all, because the overread stays inside the same allocation. */
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

/* nftables integers are big-endian, which is the opposite of every other
 * integer in this port. A test that wrote them natively would agree with a
 * broken encoder, so this is deliberately not `ncfg_wire_attr_put_u32`. */
static void put_be32(ncfg_buf_t *out, uint16_t kind, uint32_t value)
{
	uint32_t wire = htonl(value);

	ncfg_wire_attr_put(out, kind, &wire, sizeof(wire));
}

static void put_nfgenmsg(ncfg_buf_t *out, uint8_t family, uint16_t res_id)
{
	uint16_t wire = htons(res_id);

	ncfg_buf_add(out, &family, sizeof(family));
	ncfg_buf_add_char(out, 0);
	ncfg_buf_add(out, &wire, sizeof(wire));
}

/* A dump payload: an `nfgenmsg` and its attributes, with no netlink header,
 * which is what the socket layer hands a reader. */
static void nft_payload(ncfg_buf_t *out, uint8_t family, const ncfg_buf_t *attrs)
{
	put_nfgenmsg(out, family, 0);
	if (attrs && attrs->length) {
		ncfg_buf_add(out, attrs->data, attrs->length);
	}
}

/* A whole message, for the cases that have to be fed to the audit. */
static void nft_message(ncfg_buf_t *out, uint16_t type, uint8_t family, uint16_t res_id,
    const ncfg_buf_t *attrs)
{
	ncfg_buf_t body;

	ncfg_buf_init(&body, 0);
	put_nfgenmsg(&body, family, res_id);
	(void)ncfg_wire_build_request(out, type, NLM_F_REQUEST, 1, &body, attrs, NULL, 0);
	ncfg_buf_free(&body);
}

static uint16_t nft_type(uint16_t kind)
{
	return (uint16_t)(((unsigned)NFNL_SUBSYS_NFTABLES << 8) | (unsigned)kind);
}

static int find(const ncfg_wire_attrs_t *area, uint16_t kind, ncfg_wire_attr_t *out)
{
	return ncfg_wire_attrs_find(area, kind, out, NULL, 0) == NCFG_WIRE_OK;
}

static void nested(const ncfg_wire_attr_t *attr, ncfg_wire_attrs_t *out)
{
	ncfg_wire_attrs_start(out, attr->value, attr->length);
}

/* The shape of a masquerade rule, so that each way of getting one wrong can be
 * built by changing one field of a rule that is otherwise right. */
typedef struct {
	const char *table;
	const char *chain;
	uint8_t     family;
	uint32_t    meta_key;
	uint32_t    dreg;
	uint32_t    sreg;
	uint32_t    op;
	const char *name;
	int         with_masq;
} rule_shape_t;

static rule_shape_t good_rule(void)
{
	rule_shape_t shape;

	shape.table = NCFG_NFT_TABLE;
	shape.chain = NCFG_NFT_CHAIN;
	shape.family = NFPROTO_INET;
	shape.meta_key = NFT_META_OIFNAME;
	shape.dreg = NFT_REG_1;
	shape.sreg = NFT_REG_1;
	shape.op = NFT_CMP_EQ;
	shape.name = "wan0";
	shape.with_masq = 1;
	return shape;
}

static void put_expression(ncfg_buf_t *list, const char *name, const ncfg_buf_t *data)
{
	ncfg_buf_t expression;

	ncfg_buf_init(&expression, 0);
	ncfg_wire_attr_put_str(&expression, NFTA_EXPR_NAME, name);
	ncfg_wire_attr_put_nested(&expression, NFTA_EXPR_DATA, data);
	ncfg_wire_attr_put_nested(list, NFTA_LIST_ELEM, &expression);
	ncfg_buf_free(&expression);
}

static void rule_payload(ncfg_buf_t *out, const rule_shape_t *shape)
{
	ncfg_buf_t attrs;
	ncfg_buf_t expressions;
	ncfg_buf_t meta;
	ncfg_buf_t cmp;
	ncfg_buf_t value;
	ncfg_buf_t empty;

	ncfg_buf_init(&meta, 0);
	put_be32(&meta, NFTA_META_KEY, shape->meta_key);
	put_be32(&meta, NFTA_META_DREG, shape->dreg);

	ncfg_buf_init(&value, 0);
	ncfg_wire_attr_put(&value, NFTA_DATA_VALUE, shape->name, strlen(shape->name) + 1u);

	ncfg_buf_init(&cmp, 0);
	put_be32(&cmp, NFTA_CMP_SREG, shape->sreg);
	put_be32(&cmp, NFTA_CMP_OP, shape->op);
	ncfg_wire_attr_put_nested(&cmp, NFTA_CMP_DATA, &value);

	ncfg_buf_init(&empty, 0);
	ncfg_buf_init(&expressions, 0);
	put_expression(&expressions, "meta", &meta);
	put_expression(&expressions, "cmp", &cmp);
	if (shape->with_masq) {
		put_expression(&expressions, "masq", &empty);
	}

	ncfg_buf_init(&attrs, 0);
	ncfg_wire_attr_put_str(&attrs, NFTA_RULE_TABLE, shape->table);
	ncfg_wire_attr_put_str(&attrs, NFTA_RULE_CHAIN, shape->chain);
	ncfg_wire_attr_put_nested(&attrs, NFTA_RULE_EXPRESSIONS, &expressions);
	nft_payload(out, shape->family, &attrs);

	ncfg_buf_free(&attrs);
	ncfg_buf_free(&expressions);
	ncfg_buf_free(&empty);
	ncfg_buf_free(&cmp);
	ncfg_buf_free(&value);
	ncfg_buf_free(&meta);
}

/*
 * Every table and chain name a transaction writes, counted into three buckets.
 *
 * The count is the point. `ncfg_nft_writes_only_our_table` answering yes over a
 * buffer it found nothing in is the shape of a gate that passes because its
 * input was empty, so the test asserts how many names were actually read as
 * well as what they were.
 */
static void count_names(const ncfg_buf_t *transaction, int *ours_table, int *ours_chain,
    int *foreign)
{
	/*
	 * Three numbers, and they are every name-valued attribute across the four
	 * message types this module writes. It is three rather than five because
	 * **nftables numbers its attributes per message type**:
	 * `NFTA_TABLE_NAME`, `NFTA_CHAIN_TABLE` and `NFTA_RULE_TABLE` are all 1,
	 * and searching for each of them separately would count the same name
	 * three times.
	 */
	static const uint16_t kinds[] = { NFTA_TABLE_NAME, NFTA_RULE_CHAIN, NFTA_CHAIN_NAME };
	ncfg_wire_messages_t walk;
	ncfg_wire_message_t message;

	*ours_table = 0;
	*ours_chain = 0;
	*foreign = 0;
	ncfg_wire_messages_start(&walk, transaction->data, transaction->length);
	while (ncfg_wire_messages_next(&walk, &message, NULL, 0) == NCFG_WIRE_OK) {
		ncfg_wire_attrs_t area;
		size_t at;

		if ((message.header.kind >> 8) != NFNL_SUBSYS_NFTABLES) {
			continue;
		}
		if (!ncfg_wire_message_attrs(&message, NCFG_NFT_NFGENMSG_LEN, &area, NULL, 0)) {
			continue;
		}
		for (at = 0; at < sizeof(kinds) / sizeof(kinds[0]); at++) {
			ncfg_wire_attr_t attr;
			char name[NCFG_NFT_NAME_MAX];

			if (!find(&area, kinds[at], &attr) ||
			    !ncfg_wire_attr_string(&attr, name, sizeof(name), NULL, 0)) {
				continue;
			}
			if (strcmp(name, NCFG_NFT_TABLE) == 0) {
				(*ours_table)++;
			} else if (strcmp(name, NCFG_NFT_CHAIN) == 0) {
				(*ours_chain)++;
			} else {
				(*foreign)++;
			}
		}
	}
}

/* The nth message of a buffer. */
static int message_at(const ncfg_buf_t *buf, size_t want, ncfg_wire_message_t *out)
{
	ncfg_wire_messages_t walk;
	size_t at = 0;

	ncfg_wire_messages_start(&walk, buf->data, buf->length);
	while (ncfg_wire_messages_next(&walk, out, NULL, 0) == NCFG_WIRE_OK) {
		if (at == want) {
			return 1;
		}
		at++;
	}
	return 0;
}

static size_t message_count(const ncfg_buf_t *buf)
{
	ncfg_wire_messages_t walk;
	ncfg_wire_message_t message;
	size_t seen = 0;

	ncfg_wire_messages_start(&walk, buf->data, buf->length);
	while (seen < 1000u && ncfg_wire_messages_next(&walk, &message, NULL, 0) == NCFG_WIRE_OK) {
		seen++;
	}
	return seen;
}

int main(void)
{
	char err[NCFG_ERROR_MAX];
	char uplink[NCFG_NFT_IFNAME_MAX];
	static const char *const one[] = { "wan0" };
	static const char *const two[] = { "wan0", "wwan0" };

	/*
	 * **The transaction, and the only two names in it.**
	 *
	 * Six messages: a begin marker, the delete that makes this a replacement
	 * rather than an accumulation, the table, its one chain, one rule per
	 * uplink, and an end marker. Every table and chain name inside is
	 * counted, and the count of names that are neither `netcfgd` nor
	 * `postrouting` is the whole of decision 0022 in one number.
	 */
	{
		ncfg_buf_t transaction;
		ncfg_nft_batch_t batch;
		ncfg_wire_message_t message;
		int ours_table = 0;
		int ours_chain = 0;
		int foreign = 0;

		ncfg_buf_init(&transaction, 0);
		check(ncfg_nft_build_replace_nat(&transaction, 7, 1, one, 1, &batch, err,
		    sizeof(err)) && !batch.empty,
		    "a table with one uplink builds, replacing what was there");
		check(message_count(&transaction) == 6,
		    "as six messages: begin, delete, table, chain, one rule, end");

		count_names(&transaction, &ours_table, &ours_chain, &foreign);
		check(foreign == 0,
		    "and not one name in it is a table or chain netcfgd does not own (0022)");
		check(ours_table == 4,
		    "`netcfgd` is named four times: the delete, the table, the chain, the rule");
		check(ours_chain == 2, "and `postrouting` twice: the chain and the rule");
		check(ncfg_nft_writes_only_our_table(transaction.data, transaction.length, err,
		    sizeof(err)),
		    "the audit agrees, on the bytes rather than on the intention");

		check(message_at(&transaction, 0, &message) &&
		    message.header.kind == NFNL_MSG_BATCH_BEGIN && message.header.seq == 7,
		    "the first message is the batch begin marker");
		check(message_at(&transaction, 5, &message) &&
		    message.header.kind == NFNL_MSG_BATCH_END,
		    "and the last is the batch end");
		/*
		 * The acknowledgement to wait for is the last message *inside* the
		 * transaction and deliberately not the end marker: the kernel
		 * acknowledges a transaction's contents and says nothing about its
		 * end, so a reply loop waiting for the end waits out its timeout
		 * and reports a failure that did not happen.
		 */
		check(batch.last_acked == 11u && batch.next_seq == 13u,
		    "and the sequence to wait for is the rule, not the end marker");
		ncfg_buf_free(&transaction);
	}

	/* The three other shapes a replacement takes. */
	{
		ncfg_buf_t transaction;
		ncfg_nft_batch_t batch;
		ncfg_wire_message_t message;

		ncfg_buf_init(&transaction, 0);
		check(ncfg_nft_build_replace_nat(&transaction, 1, 1, NULL, 0, &batch, err,
		    sizeof(err)) && message_count(&transaction) == 3,
		    "a document that stops asking for NAT removes the table and adds none");
		check(batch.last_acked == 2u,
		    "waiting on the delete, which is the only thing that will be acknowledged");
		ncfg_buf_free(&transaction);

		ncfg_buf_init(&transaction, 0);
		check(ncfg_nft_build_replace_nat(&transaction, 1, 0, two, 2, &batch, err,
		    sizeof(err)) && message_count(&transaction) == 6,
		    "a first apply creates the table without deleting one that is not there");
		check(message_at(&transaction, 1, &message) &&
		    message.header.kind == nft_type(NFT_MSG_NEWTABLE),
		    "so the message after the marker is the table, not a delete");
		/*
		 * The delete is conditional for a reason worth keeping: deleting a
		 * table that is not there is `ENOENT`, one failure aborts the whole
		 * transaction, and the error the operator would see would not be
		 * "no table" -- it would be "no NAT".
		 */
		ncfg_buf_free(&transaction);

		ncfg_buf_init(&transaction, 0);
		check(ncfg_nft_build_replace_nat(&transaction, 1, 0, NULL, 0, &batch, err,
		    sizeof(err)) && batch.empty && transaction.length == 0,
		    "no table and no uplinks builds nothing, because there is nothing to send");
		/* An empty transaction is a begin and an end, which ask for no
		 * acknowledgement and receive no reply -- so a caller that sent one
		 * would wait out its own timeout and call it a failure. */
		ncfg_buf_free(&transaction);
	}

	/*
	 * **The audit refuses what this module would never build.**
	 *
	 * This is the half that cannot be shown by building things correctly: a
	 * check that only ever sees good input has not been shown to refuse
	 * anything. Each of these is a message an nftables client could sensibly
	 * send and netcfgd may not.
	 */
	{
		ncfg_buf_t message;
		ncfg_buf_t attrs;

		ncfg_buf_init(&message, 0);
		ncfg_buf_init(&attrs, 0);
		ncfg_wire_attr_put_str(&attrs, NFTA_TABLE_NAME, "fw4");
		nft_message(&message, nft_type(NFT_MSG_DELTABLE), NFPROTO_INET, 0, &attrs);
		check(!ncfg_nft_writes_only_our_table(message.data, message.length, err,
		    sizeof(err)) && strstr(err, "fw4") != NULL && strstr(err, "0022") != NULL,
		    "deleting `fw4` is refused, by name and with the record that forbids it");
		ncfg_buf_free(&attrs);
		ncfg_buf_free(&message);

		ncfg_buf_init(&message, 0);
		ncfg_buf_init(&attrs, 0);
		ncfg_wire_attr_put_str(&attrs, NFTA_CHAIN_TABLE, NCFG_NFT_TABLE);
		ncfg_wire_attr_put_str(&attrs, NFTA_CHAIN_NAME, "input");
		nft_message(&message, nft_type(NFT_MSG_NEWCHAIN), NFPROTO_INET, 0, &attrs);
		check(!ncfg_nft_writes_only_our_table(message.data, message.length, err,
		    sizeof(err)),
		    "and so is a second chain inside netcfgd's own table");
		ncfg_buf_free(&attrs);
		ncfg_buf_free(&message);

		ncfg_buf_init(&message, 0);
		ncfg_buf_init(&attrs, 0);
		ncfg_wire_attr_put_str(&attrs, NFTA_RULE_TABLE, NCFG_NFT_TABLE);
		ncfg_wire_attr_put_str(&attrs, NFTA_RULE_CHAIN, NCFG_NFT_CHAIN);
		nft_message(&message, nft_type(NFT_MSG_NEWSET), NFPROTO_INET, 0, &attrs);
		check(!ncfg_nft_writes_only_our_table(message.data, message.length, err,
		    sizeof(err)),
		    "a set in netcfgd's table is refused too: the set of messages is closed");
		ncfg_buf_free(&attrs);
		ncfg_buf_free(&message);

		ncfg_buf_init(&message, 0);
		nft_message(&message, NFNL_MSG_BATCH_BEGIN, NFPROTO_UNSPEC, NFNL_SUBSYS_CTNETLINK,
		    NULL);
		check(!ncfg_nft_writes_only_our_table(message.data, message.length, err,
		    sizeof(err)),
		    "and a transaction opened for another netlink subsystem is not ours");
		ncfg_buf_free(&message);
	}

	/* Reading outside the table is allowed, and that is not a hole: 0022
	 * requires netcfgd to notice a second table doing source NAT at the same
	 * hook, and noticing means dumping every table there is. Reporting is all
	 * that ever follows. */
	{
		ncfg_buf_t request;

		ncfg_buf_init(&request, 0);
		check(ncfg_nft_build_table_dump(&request, 1, err, sizeof(err)) &&
		    ncfg_nft_writes_only_our_table(request.data, request.length, err,
		    sizeof(err)),
		    "a dump of every table on the machine passes the audit, because it reads");
		ncfg_buf_free(&request);

		ncfg_buf_init(&request, 0);
		check(ncfg_nft_build_chain_dump(&request, 1, err, sizeof(err)) &&
		    ncfg_nft_writes_only_our_table(request.data, request.length, err,
		    sizeof(err)),
		    "and so does a dump of every chain, which is the conflict check");
		ncfg_buf_free(&request);
	}

	/*
	 * **Big-endian, checked as raw bytes.**
	 *
	 * This is the one assertion in the file that cannot be made by comparing
	 * two numbers, because a native-endian encoder and a native-endian reader
	 * agree with each other perfectly. A priority sent in the host's order
	 * puts the chain at 1677721600 instead of 100, which nftables accepts and
	 * `nft list ruleset` prints without complaint.
	 */
	{
		ncfg_buf_t transaction;
		ncfg_nft_batch_t batch;
		ncfg_wire_message_t message;
		ncfg_wire_attrs_t area;
		ncfg_wire_attrs_t hook;
		ncfg_wire_attr_t attr;
		char kind[NCFG_NFT_NAME_MAX];
		static const uint8_t srcnat[4] = { 0x00, 0x00, 0x00, 0x64 };
		static const uint8_t postrouting[4] = { 0x00, 0x00, 0x00, 0x04 };

		ncfg_buf_init(&transaction, 0);
		check(ncfg_nft_build_replace_nat(&transaction, 1, 0, one, 1, &batch, err,
		    sizeof(err)) && message_at(&transaction, 2, &message) &&
		    message.header.kind == nft_type(NFT_MSG_NEWCHAIN) &&
		    ncfg_wire_message_attrs(&message, NCFG_NFT_NFGENMSG_LEN, &area, NULL, 0),
		    "the chain message is the third in the transaction");
		check(find(&area, NFTA_CHAIN_TYPE, &attr) &&
		    ncfg_wire_attr_string(&attr, kind, sizeof(kind), NULL, 0) &&
		    strcmp(kind, "nat") == 0,
		    "it is a `nat` chain, which is what makes 0022's line mechanical");
		check(find(&area, NFTA_CHAIN_HOOK, &attr), "and it registers at a hook");
		nested(&attr, &hook);
		check(find(&hook, NFTA_HOOK_PRIORITY, &attr) && attr.length == 4u &&
		    memcmp(attr.value, srcnat, sizeof(srcnat)) == 0,
		    "whose priority is the four bytes 00 00 00 64 -- 100, big-endian");
		check(find(&hook, NFTA_HOOK_HOOKNUM, &attr) && attr.length == 4u &&
		    memcmp(attr.value, postrouting, sizeof(postrouting)) == 0,
		    "and whose hook number is postrouting, in network order as well");
		ncfg_buf_free(&transaction);
	}

	/*
	 * **The trailing NUL is part of the comparison, and it is what makes it
	 * exact.**
	 *
	 * Comparing `strlen` bytes would match every interface whose name has
	 * this one as a prefix, so masquerading `eth0` would also masquerade
	 * `eth0.42` -- a VLAN on the uplink, translated twice on its way out.
	 */
	{
		ncfg_buf_t transaction;
		ncfg_nft_batch_t batch;
		ncfg_wire_message_t message;
		ncfg_wire_attrs_t area;
		ncfg_wire_attrs_t expressions;
		ncfg_wire_attrs_t expression;
		ncfg_wire_attrs_t data;
		ncfg_wire_attrs_t value;
		ncfg_wire_attr_t attr;
		ncfg_wire_attr_t element;
		char name[NCFG_NFT_NAME_MAX];
		int found = 0;

		ncfg_buf_init(&transaction, 0);
		check(ncfg_nft_build_replace_nat(&transaction, 1, 0, one, 1, &batch, err,
		    sizeof(err)) && message_at(&transaction, 3, &message) &&
		    message.header.kind == nft_type(NFT_MSG_NEWRULE) &&
		    ncfg_wire_message_attrs(&message, NCFG_NFT_NFGENMSG_LEN, &area, NULL, 0),
		    "the rule is the fourth message");
		check(find(&area, NFTA_RULE_EXPRESSIONS, &attr), "and carries expressions");
		nested(&attr, &expressions);
		while (ncfg_wire_attrs_next(&expressions, &element, NULL, 0) == NCFG_WIRE_OK) {
			nested(&element, &expression);
			if (!find(&expression, NFTA_EXPR_NAME, &attr) ||
			    !ncfg_wire_attr_string(&attr, name, sizeof(name), NULL, 0) ||
			    strcmp(name, "cmp") != 0) {
				continue;
			}
			if (!find(&expression, NFTA_EXPR_DATA, &attr)) {
				continue;
			}
			nested(&attr, &data);
			if (!find(&data, NFTA_CMP_DATA, &attr)) {
				continue;
			}
			nested(&attr, &value);
			if (!find(&value, NFTA_DATA_VALUE, &attr)) {
				continue;
			}
			found = attr.length == strlen("wan0") + 1u &&
			    attr.value[attr.length - 1u] == 0;
		}
		check(found,
		    "the compared value is `wan0` and a NUL, so `wan0.42` does not match it");
		ncfg_buf_free(&transaction);
	}

	/* The round trip: a rule netcfgd wrote reads back as the uplink it names,
	 * which is the observation half of the reconciliation -- what the kernel
	 * holds, in the same shape the document asks for. */
	{
		ncfg_buf_t transaction;
		ncfg_nft_batch_t batch;
		ncfg_wire_message_t message;

		ncfg_buf_init(&transaction, 0);
		check(ncfg_nft_build_replace_nat(&transaction, 1, 0, one, 1, &batch, err,
		    sizeof(err)) && message_at(&transaction, 3, &message) &&
		    ncfg_nft_rule_uplink(message.payload, message.payload_length, uplink,
		    sizeof(uplink), err, sizeof(err)) && strcmp(uplink, "wan0") == 0,
		    "a rule netcfgd wrote reads back as the interface it masquerades");
		ncfg_buf_free(&transaction);
	}

	/*
	 * **A rule from another table is refused, and the Rust does not refuse
	 * it.**
	 *
	 * The dump request asks the kernel for netcfgd's table and chain, and the
	 * Rust trusts that it was honoured. A kernel that ignored the filter --
	 * or a caller handing this the wrong dump -- would have somebody else's
	 * masquerade rules read as netcfgd's uplinks, which is the "reads another
	 * table" 0022 forbids, arriving through the reader instead of the writer.
	 */
	{
		ncfg_buf_t payload;
		rule_shape_t shape = good_rule();

		shape.table = "fw4";
		ncfg_buf_init(&payload, 0);
		rule_payload(&payload, &shape);
		check(!ncfg_nft_rule_uplink(payload.data, payload.length, uplink,
		    sizeof(uplink), err, sizeof(err)) && strstr(err, "0022") != NULL,
		    "a masquerade rule in `fw4` is not netcfgd's to describe");
		ncfg_buf_free(&payload);

		shape = good_rule();
		shape.chain = "srcnat";
		ncfg_buf_init(&payload, 0);
		rule_payload(&payload, &shape);
		check(!ncfg_nft_rule_uplink(payload.data, payload.length, uplink,
		    sizeof(uplink), err, sizeof(err)),
		    "nor is one in another chain of a table with the same name");
		ncfg_buf_free(&payload);

		shape = good_rule();
		shape.family = NFPROTO_IPV4;
		ncfg_buf_init(&payload, 0);
		rule_payload(&payload, &shape);
		check(!ncfg_nft_rule_uplink(payload.data, payload.length, uplink,
		    sizeof(uplink), err, sizeof(err)),
		    "and `ip netcfgd` is a different table from `inet netcfgd`");
		ncfg_buf_free(&payload);
	}

	/*
	 * The four ways a rule can look like netcfgd's and not be it. Each is
	 * refused rather than guessed at, because the next apply replaces the
	 * table wholesale -- so reporting one as an uplink would produce a plan
	 * claiming to remove something it never installed.
	 */
	{
		ncfg_buf_t payload;
		rule_shape_t shape = good_rule();

		shape.with_masq = 0;
		ncfg_buf_init(&payload, 0);
		rule_payload(&payload, &shape);
		check(!ncfg_nft_rule_uplink(payload.data, payload.length, uplink,
		    sizeof(uplink), err, sizeof(err)),
		    "a rule matching the uplink and not masquerading is not NAT happening");
		ncfg_buf_free(&payload);

		shape = good_rule();
		shape.meta_key = NFT_META_IIFNAME;
		ncfg_buf_init(&payload, 0);
		rule_payload(&payload, &shape);
		check(!ncfg_nft_rule_uplink(payload.data, payload.length, uplink,
		    sizeof(uplink), err, sizeof(err)),
		    "a rule reading the *incoming* interface is a different rule entirely");
		ncfg_buf_free(&payload);

		/*
		 * The one that is not a near miss but the exact opposite: `oifname
		 * != "wan0" masquerade` translates everything *except* the uplink,
		 * and reading it as "wan0 is an uplink" would leave the real ones
		 * untranslated. The Rust reads the comparison's data without ever
		 * looking at its operator.
		 */
		shape = good_rule();
		shape.op = NFT_CMP_NEQ;
		ncfg_buf_init(&payload, 0);
		rule_payload(&payload, &shape);
		check(!ncfg_nft_rule_uplink(payload.data, payload.length, uplink,
		    sizeof(uplink), err, sizeof(err)),
		    "`oifname != wan0 masquerade` is not `wan0 is an uplink` -- it is its opposite");
		ncfg_buf_free(&payload);

		shape = good_rule();
		shape.sreg = NFT_REG_2;
		ncfg_buf_init(&payload, 0);
		rule_payload(&payload, &shape);
		check(!ncfg_nft_rule_uplink(payload.data, payload.length, uplink,
		    sizeof(uplink), err, sizeof(err)),
		    "and a comparison against another register tests something else");
		ncfg_buf_free(&payload);
	}

	/* A name no interface could have never reaches the kernel: the comparison
	 * it would compile into matches nothing, which is NAT that silently does
	 * not happen. */
	{
		ncfg_buf_t transaction;
		ncfg_nft_batch_t batch;
		static const char *const empty_name[] = { "" };
		static const char *const slashed[] = { "wan/0" };
		static const char *const spaced[] = { "wan 0" };
		static const char *const too_long[] = { "abcdefghijklmnop" };

		ncfg_buf_init(&transaction, 0);
		check(!ncfg_nft_build_replace_nat(&transaction, 1, 0, empty_name, 1, &batch, err,
		    sizeof(err)), "an empty interface name is refused");
		check(!ncfg_nft_build_replace_nat(&transaction, 1, 0, slashed, 1, &batch, err,
		    sizeof(err)), "and one with a slash in it");
		check(!ncfg_nft_build_replace_nat(&transaction, 1, 0, spaced, 1, &batch, err,
		    sizeof(err)), "and one with a space");
		check(!ncfg_nft_build_replace_nat(&transaction, 1, 0, too_long, 1, &batch, err,
		    sizeof(err)) && strstr(err, "register") != NULL,
		    "and one too long for the register the comparison reads");
		check(transaction.length == 0,
		    "and none of them left half a transaction behind to be sent");
		ncfg_buf_free(&transaction);
	}

	/* The table and chain readers, and the double-NAT conflict 0022 says to
	 * detect and report. */
	{
		ncfg_buf_t payload;
		ncfg_buf_t attrs;
		ncfg_buf_t hook;
		ncfg_nft_table_t table;
		ncfg_nft_chain_t chain;

		ncfg_buf_init(&payload, 0);
		ncfg_buf_init(&attrs, 0);
		ncfg_wire_attr_put_str(&attrs, NFTA_TABLE_NAME, NCFG_NFT_TABLE);
		nft_payload(&payload, NFPROTO_INET, &attrs);
		check(ncfg_nft_table_read(payload.data, payload.length, &table, err,
		    sizeof(err)) && ncfg_nft_table_is_ours(&table),
		    "`inet netcfgd` is read back as the table netcfgd owns");
		table.family = NFPROTO_IPV4;
		check(!ncfg_nft_table_is_ours(&table),
		    "and `ip netcfgd` is not, because a table is a family and a name");
		ncfg_buf_free(&attrs);
		ncfg_buf_free(&payload);

		ncfg_buf_init(&payload, 0);
		ncfg_buf_init(&attrs, 0);
		ncfg_buf_init(&hook, 0);
		put_be32(&hook, NFTA_HOOK_HOOKNUM, NF_INET_POST_ROUTING);
		ncfg_wire_attr_put_str(&attrs, NFTA_CHAIN_TABLE, "fw4");
		ncfg_wire_attr_put_str(&attrs, NFTA_CHAIN_NAME, "srcnat");
		ncfg_wire_attr_put_str(&attrs, NFTA_CHAIN_TYPE, "nat");
		ncfg_wire_attr_put_nested(&attrs, NFTA_CHAIN_HOOK, &hook);
		nft_payload(&payload, NFPROTO_INET, &attrs);
		check(ncfg_nft_chain_read(payload.data, payload.length, &chain, err,
		    sizeof(err)) && strcmp(chain.table, "fw4") == 0,
		    "somebody else's chain is read, because the conflict check has to see it");
		check(ncfg_nft_chain_is_source_nat(&chain),
		    "and is recognised as source NAT, which double-translates with netcfgd's");
		chain.hook = NF_INET_PRE_ROUTING;
		check(!ncfg_nft_chain_is_source_nat(&chain),
		    "a `nat` chain at prerouting is destination NAT and does not conflict");
		ncfg_buf_free(&hook);
		ncfg_buf_free(&attrs);
		ncfg_buf_free(&payload);

		/* A regular chain has neither a type nor a hook, which is not a
		 * malformed record -- it is a chain another chain jumps to. */
		ncfg_buf_init(&payload, 0);
		ncfg_buf_init(&attrs, 0);
		ncfg_wire_attr_put_str(&attrs, NFTA_CHAIN_TABLE, "fw4");
		ncfg_wire_attr_put_str(&attrs, NFTA_CHAIN_NAME, "helper");
		nft_payload(&payload, NFPROTO_INET, &attrs);
		check(ncfg_nft_chain_read(payload.data, payload.length, &chain, err,
		    sizeof(err)) && !chain.has_hook && chain.kind[0] == '\0' &&
		    !ncfg_nft_chain_is_source_nat(&chain),
		    "and a regular chain reads with no hook rather than being refused");
		ncfg_buf_free(&attrs);
		ncfg_buf_free(&payload);
	}

	/* Truncation is a refusal with a sentence, never a partial answer.
	 * Copied to size so that a read past the end is a report under ASan
	 * rather than another byte of the same allocation. */
	{
		ncfg_buf_t payload;
		rule_shape_t shape = good_rule();
		uint8_t *cut;
		ncfg_nft_table_t table;

		ncfg_buf_init(&payload, 0);
		rule_payload(&payload, &shape);
		cut = exact_copy(payload.data, NCFG_NFT_NFGENMSG_LEN - 1u);
		check(cut && !ncfg_nft_rule_uplink(cut, NCFG_NFT_NFGENMSG_LEN - 1u, uplink,
		    sizeof(uplink), err, sizeof(err)),
		    "a payload too short for an nfgenmsg is refused");
		free(cut);

		cut = exact_copy(payload.data, payload.length / 2u);
		check(cut && !ncfg_nft_rule_uplink(cut, payload.length / 2u, uplink,
		    sizeof(uplink), err, sizeof(err)),
		    "and so is a rule cut in half");
		free(cut);

		cut = exact_copy(payload.data, NCFG_NFT_NFGENMSG_LEN);
		check(cut && !ncfg_nft_table_read(cut, NCFG_NFT_NFGENMSG_LEN, &table, err,
		    sizeof(err)),
		    "a table entry with no name is refused rather than left blank");
		free(cut);
		ncfg_buf_free(&payload);
	}

	if (failures) {
		printf("nft: %d check(s) failed\n", failures);
		return 1;
	}
	printf("nft: every check passed\n");
	return 0;
}
