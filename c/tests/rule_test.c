/*
 * rule_test.c -- the policy rules the kernel reports, against bytes this port
 * encoded rather than against a machine's routing policy.
 *
 * WHY THE BYTES COME FROM THE ENCODER NEXT DOOR
 *   A rule netcfgd installs and a rule it reads have to be comparable field by
 *   field; that is the whole reason `rule.rs` uses one type in both directions.
 *   So the case that matters is not "does this decoder read a blob somebody
 *   typed" but "does it read back what this port would have sent" -- and
 *   `ncfg_ops_add_rule` is what this port sends. Every round trip below builds
 *   a real `RTM_NEWRULE`, hands the decoder its payload, and compares the two.
 *   A hand-written blob would pin the decoder to whatever it did on the day it
 *   was written, including its mistakes.
 *
 *   The cases the encoder cannot produce -- a truncated message, a malformed
 *   attribute area, a suppressor the kernel dumps as all-ones -- are built by
 *   hand, and the hostile ones are allocated to their exact size so that a read
 *   one byte past the end is an ASan report rather than a byte of the rest of
 *   the buffer. wire_test.c has the long version of that note.
 *
 * NO SOCKET, NO PRIVILEGE, NO RULES TOUCHED
 *   Nothing here opens a netlink socket or asks the machine what its rules are.
 *   `RTM_GETRULE` is a read, but it is a read of the workstation this suite runs
 *   on, and the request it would send is checked as bytes instead.
 */
#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/ops.h"
#include "ncfg/rule.h"
#include "ncfg/wire.h"

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

/* Build an `RTM_NEWRULE` and decode its payload back, which is the same shape
 * a dump reply arrives in: everything after the netlink header. */
static int round_trip(const ncfg_ops_rule_t *rule, ncfg_rule_record_t *out)
{
	ncfg_buf_t message;
	int        read = 0;

	ncfg_buf_init(&message, 0);
	if (ncfg_ops_add_rule(&message, 1, rule, NULL, 0) &&
	    message.length > NCFG_WIRE_NLMSG_HDR_LEN) {
		read = ncfg_dump_rule(message.data + NCFG_WIRE_NLMSG_HDR_LEN,
		    message.length - NCFG_WIRE_NLMSG_HDR_LEN, out, NULL, 0);
	}
	ncfg_buf_free(&message);
	return read;
}

int main(void)
{
	/* The request a dump sends: an all-zero header, which asks for both
	 * families at once. */
	{
		ncfg_buf_t body;
		ncfg_buf_t attrs;
		int        zeroed = 1;
		size_t     at;

		ncfg_buf_init(&body, 0);
		ncfg_buf_init(&attrs, 0);
		ncfg_dump_rule_request(&body, &attrs);
		check(!ncfg_buf_failed(&body) && !ncfg_buf_failed(&attrs),
		    "a rule dump request is built");
		check(body.length == NCFG_RULE_HDR_LEN, "its body is one rule header");
		for (at = 0; at < body.length; at++) {
			zeroed = zeroed && body.data[at] == 0;
		}
		check(zeroed, "and every byte of it is zero, which asks for both families");
		check(attrs.length == 0u, "a rule dump carries no attributes");
		check(NCFG_DUMP_RULE == RTM_GETRULE, "and it is an RTM_GETRULE");
		ncfg_buf_free(&body);
		ncfg_buf_free(&attrs);
	}

	/* A rule with every field set, round tripped. */
	{
		ncfg_ops_rule_t    rule;
		ncfg_ops_rule_t    back;
		ncfg_rule_record_t record;
		char               source[] = "10.0.0.0";

		memset(&rule, 0, sizeof(rule));
		rule.family = AF_INET;
		rule.priority = 1200;
		/* Above 255 deliberately: this is the field that does not fit
		 * the header's byte. */
		rule.table = 1000;
		rule.action = FR_ACT_TO_TBL;
		check(ncfg_wire_ip_parse(source, &rule.from, NULL, 0), "a source selector parses");
		rule.from_len = 8;
		rule.iif = "eth0";
		rule.oif = "eth1";
		rule.fwmark.has = 1;
		rule.fwmark.value = 0x2a;
		rule.fwmask.has = 1;
		rule.fwmask.value = 0xff;
		/* Zero, and present: `suppress_prefixlength 0` is the whole
		 * `ip rule` trick and is not the same as no suppression. */
		rule.suppress_prefixlength.has = 1;
		rule.suppress_prefixlength.value = 0;
		rule.l3mdev = 1;
		rule.invert = 1;

		check(round_trip(&rule, &record), "a rule netcfgd would install reads back");
		check(record.family == AF_INET, "with its family");
		check(record.priority == 1200u, "its priority");
		check(record.table == 1000u,
		    "and its table, which does not fit the header's byte");
		check(record.action == FR_ACT_TO_TBL, "its action, where a route keeps its type");
		check(record.from.family == AF_INET && record.from_len == 8,
		    "its source selector and prefix length");
		check(record.has_iif && strcmp(record.iif, "eth0") == 0, "its incoming interface");
		check(record.has_oif && strcmp(record.oif, "eth1") == 0, "its outgoing one");
		check(record.has_fwmark && record.fwmark == 0x2au, "its firewall mark");
		check(record.has_fwmask && record.fwmask == 0xffu, "and the mask over it");
		check(record.has_suppress_prefixlength && record.suppress_prefixlength == 0u,
		    "a suppressor of zero comes back present and zero");
		check(record.l3mdev, "its l3mdev match");
		check(record.invert, "and the inversion, which lives in the header's flags");
		check(record.protocol == NCFG_WIRE_RTPROT_NETCFGD,
		    "a rule sent with no protocol carries netcfgd's 110");

		/* And the record as the type a plan compares against. */
		ncfg_rule_record_spec(&record, &back);
		check(back.family == rule.family && back.priority == rule.priority &&
		    back.table == rule.table && back.action == rule.action,
		    "the record becomes the type that installs one");
		check(back.iif && strcmp(back.iif, "eth0") == 0 &&
		    back.oif && strcmp(back.oif, "eth1") == 0,
		    "with its names borrowed from the record");
		check(back.from_len == rule.from_len && back.to_len == 0,
		    "the prefix length of a selector that is there, and none for one that is not");
		check(back.fwmark.has && back.fwmark.value == 0x2a &&
		    back.suppress_prefixlength.has && back.suppress_prefixlength.value == 0,
		    "and every optional field with absence told from zero");
		check(back.protocol.has && back.protocol.value == NCFG_WIRE_RTPROT_NETCFGD,
		    "a record's protocol is always present, because it is a fact");
		check(memcmp(back.from.bytes, rule.from.bytes, sizeof(rule.from.bytes)) == 0,
		    "and the selector is the address that went out");
	}

	/* The plainest rule there is: a priority, a table and nothing else. */
	{
		ncfg_ops_rule_t    rule;
		ncfg_rule_record_t record;

		memset(&rule, 0, sizeof(rule));
		rule.family = AF_INET6;
		rule.priority = 100;
		rule.table = 254;
		rule.action = FR_ACT_TO_TBL;

		check(round_trip(&rule, &record), "a rule with no selectors reads back");
		check(record.family == AF_INET6 && record.table == 254u,
		    "a table that fits the header's byte survives either way");
		check(!record.has_iif && !record.has_oif, "with no interface names");
		check(record.from.family == AF_UNSPEC && record.to.family == AF_UNSPEC,
		    "and no selectors, which is an absent family rather than 0.0.0.0");
		check(record.from_len == 0 && record.to_len == 0,
		    "a prefix length without a selector is not carried");
		check(!record.has_fwmark && !record.has_fwmask &&
		    !record.has_suppress_prefixlength,
		    "and every optional field reads as absent");
		check(!record.l3mdev && !record.invert, "and neither flag is set");
	}

	/* A rule somebody else installed, which is what protocol 0 means. */
	{
		ncfg_ops_rule_t    rule;
		ncfg_ops_rule_t    back;
		ncfg_rule_record_t record;

		memset(&rule, 0, sizeof(rule));
		rule.family = AF_INET;
		rule.priority = 32766;
		rule.table = 254;
		rule.action = FR_ACT_TO_TBL;
		rule.protocol.has = 1;
		rule.protocol.value = 0;

		check(round_trip(&rule, &record), "a rule with protocol 0 reads back");
		check(record.protocol == 0u, "and it does not become netcfgd's");
		ncfg_rule_record_spec(&record, &back);
		check(back.protocol.has && back.protocol.value == 0,
		    "which is what stops a plan from deleting somebody else's rule");
	}

	/*
	 * The suppressor the kernel dumps for a rule that has none.
	 *
	 * All-ones, which is not a prefix length. Read literally, every ordinary
	 * rule on the machine would look as though it suppressed prefixes
	 * shorter than four billion -- and a plan comparing that against a
	 * document that asked for nothing would rewrite every rule, for ever.
	 */
	{
		ncfg_ops_rule_t    rule;
		ncfg_rule_record_t record;

		memset(&rule, 0, sizeof(rule));
		rule.family = AF_INET;
		rule.priority = 100;
		rule.table = 254;
		rule.action = FR_ACT_TO_TBL;
		rule.suppress_prefixlength.has = 1;
		rule.suppress_prefixlength.value = 0xffffffff;

		check(round_trip(&rule, &record), "an all-ones suppressor reads back");
		check(!record.has_suppress_prefixlength,
		    "as absence rather than as a prefix length of four billion");
		check(record.suppress_prefixlength == 0u, "and the field is left at zero");
	}

	/* The three drop actions travel in the byte a route keeps its type in,
	 * which is the mistake reusing `rtmsg` would make. */
	{
		ncfg_ops_rule_t    rule;
		ncfg_rule_record_t record;
		int                every = 1;
		const uint8_t      actions[] = {
			FR_ACT_BLACKHOLE, FR_ACT_UNREACHABLE, FR_ACT_PROHIBIT
		};
		size_t             at;

		memset(&rule, 0, sizeof(rule));
		rule.family = AF_INET;
		rule.priority = 400;
		for (at = 0; at < sizeof(actions); at++) {
			rule.action = actions[at];
			every = every && round_trip(&rule, &record) &&
			    record.action == actions[at];
		}
		check(every, "each drop action comes back as itself");
	}

	/* Truncation is a refusal with a sentence, never a partial record. */
	{
		uint8_t            header[NCFG_RULE_HDR_LEN];
		uint8_t           *exact;
		ncfg_rule_record_t record;
		char               err[NCFG_ERROR_MAX];

		memset(header, 0, sizeof(header));
		exact = exact_copy(header, sizeof(header) - 1u);
		err[0] = '\0';
		memset(&record, 0xff, sizeof(record));
		if (exact) {
			check(!ncfg_dump_rule(exact, sizeof(header) - 1u, &record, err,
			    sizeof(err)), "a payload short of a rule header is refused");
			free(exact);
		}
		check(err[0] != '\0', "and the refusal says how short it was");
		check(record.family == 0 && record.priority == 0u && !record.has_iif,
		    "a refused payload leaves the record zeroed");
		check(!ncfg_dump_rule(NULL, NCFG_RULE_HDR_LEN, &record, NULL, 0),
		    "as are no bytes at all");
		check(!ncfg_dump_rule(header, sizeof(header), NULL, NULL, 0),
		    "and a decode with nowhere to put the answer");
	}

	/* A header with nothing after it is a rule with no attributes, which is
	 * a record rather than a refusal: the kernel sends the header first. */
	{
		uint8_t            header[NCFG_RULE_HDR_LEN];
		uint8_t           *exact;
		ncfg_rule_record_t record;

		memset(header, 0, sizeof(header));
		header[0] = AF_INET;
		header[7] = FR_ACT_TO_TBL;
		exact = exact_copy(header, sizeof(header));
		if (exact) {
			check(ncfg_dump_rule(exact, sizeof(header), &record, NULL, 0),
			    "a header with no attributes is still a rule");
			free(exact);
		}
		check(record.priority == 0u && record.table == 0u,
		    "with nothing where the attributes would have said otherwise");
	}

	/*
	 * An attribute area that does not make sense refuses the whole record.
	 *
	 * A length of zero is the classic netlink parser bug: the walk that
	 * reads it either loops for ever or reads past the end, and the wire
	 * layer exists to refuse both. A record decoded out of it would be a
	 * truncated message read as a finished one.
	 */
	{
		uint8_t            message[NCFG_RULE_HDR_LEN + 4u];
		uint8_t           *exact;
		ncfg_rule_record_t record;
		char               err[NCFG_ERROR_MAX];

		memset(message, 0, sizeof(message));
		message[0] = AF_INET;
		/* An attribute claiming a length of zero. */
		message[NCFG_RULE_HDR_LEN] = 0;
		message[NCFG_RULE_HDR_LEN + 1u] = 0;
		message[NCFG_RULE_HDR_LEN + 2u] = FRA_PRIORITY;
		exact = exact_copy(message, sizeof(message));
		err[0] = '\0';
		if (exact) {
			check(!ncfg_dump_rule(exact, sizeof(message), &record, err, sizeof(err)),
			    "an attribute of length zero refuses the record");
			free(exact);
		}
		check(err[0] != '\0', "and says so rather than returning what it had");
	}

	/* A spec built from nothing is empty rather than undefined, which is what
	 * lets a caller declare one and fill it in on either answer. */
	{
		ncfg_ops_rule_t back;

		memset(&back, 0xff, sizeof(back));
		ncfg_rule_record_spec(NULL, &back);
		check(back.family == 0 && back.iif == NULL && !back.fwmark.has,
		    "a spec built from no record is zeroed");
		ncfg_rule_record_spec(NULL, NULL);
	}

	if (failures == 0) {
		printf("rule_test: all checks passed\n");
	} else {
		printf("rule_test: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
