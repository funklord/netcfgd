/*
 * lower_firewall.c -- layer one's `firewall` block, from text into the model.
 *
 * THE GRAMMAR IS 0294'S AND THIS FILE IS WHERE IT IS ENFORCED
 *
 *     firewall {
 *         input {
 *             policy = "drop"
 *             accept "ssh"         { protocol = "tcp"; port = [22] }
 *             accept "established" { state = ["established", "related"] }
 *             drop   "netbios"     { protocol = "udp"; port = [137, 138] }
 *         }
 *         forward { policy = "drop" }
 *         output  { policy = "accept" }
 *     }
 *
 * **The action is the block's head and the name is its label.** Both halves
 * are 0294's: `rule` is already policy routing's word in this language, and
 * 0287 needs a rule to carry its own standing, which a position in a list
 * cannot be -- inserting a rule above it renames everything below.
 *
 * WHAT IS REFUSED RATHER THAN INTERPRETED
 *   Everything the kernel could not be asked for, and everything two readers
 *   could read differently. A `policy` of `reject`, because nftables has no
 *   such policy and rendering it as `drop` would be this file deciding
 *   somebody's security posture. A rule with no name, because the name is its
 *   identity. Two rules with one name in a chain, because the second would
 *   silently become the first's standing. A `port` with `icmp`, because the
 *   protocol has none and the transaction would be refused by the kernel for
 *   a reason that reads as netcfgd's fault. A state word outside the four,
 *   because `ct state` takes exactly those.
 *
 *   The rule the refusals follow is the tree's: a document that compiles and
 *   cannot be rendered is worse than one that is refused, and a refusal that
 *   names the key is worth more than one that names the block.
 */
#include "lower_internal.h"

#include "ncfg/schedule.h"
#include "ncfg/base.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The four words `ct state` takes, which is the whole set and not a subset of
 * a larger vocabulary: anything else is a typo or a feature this build does
 * not have, and both want saying rather than passing through. */
static const char *const state_words[] = { "new", "established", "related", "invalid" };

static void rule_free(ncfg_firewall_rule_t *rule)
{
	free(rule->name);
	free(rule->ports);
	free(rule->icmp_types);
	ncfg_strings_free(rule->port_ranges, rule->port_range_count);
	ncfg_strings_free(rule->from, rule->from_count);
	ncfg_strings_free(rule->to, rule->to_count);
	free(rule->interface);
	free(rule->out_interface);
	ncfg_strings_free(rule->states, rule->state_count);
	ncfg_strings_free(rule->mac, rule->mac_count);
	ncfg_strings_free(rule->mac_lists, rule->mac_list_count);
	ncfg_strings_free(rule->mac_written, rule->mac_written_count);
	free(rule->hours);
	free(rule->over);
	ncfg_strings_free(rule->days, rule->day_count);
	ncfg_strings_free(rule->utc_pieces, rule->utc_piece_count);
	memset(rule, 0, sizeof(*rule));
}

static void chain_free(ncfg_firewall_chain_t *chain)
{
	size_t i;

	for (i = 0; i < chain->rule_count; i++) {
		rule_free(&chain->rules[i]);
	}
	free(chain->rules);
	for (i = 0; i < chain->slot_count; i++) {
		free(chain->slots[i].name);
	}
	free(chain->slots);
	memset(chain, 0, sizeof(*chain));
}

/*
 * `accept`, `drop` or `reject` -- the block's head rather than a key.
 *
 * Returns 0 for a head that is none of them, which the caller reports as what
 * it is: an unknown block inside a chain, with the three that are allowed
 * named. A chain's own keys and a rule's are different vocabularies and the
 * diagnostic has to say which one the reader is in.
 */
static int rule_action(const char *head, int *out)
{
	if (strcmp(head, "accept") == 0) {
		*out = NCFG_FIREWALL_ACCEPT;
		return 1;
	}
	if (strcmp(head, "drop") == 0) {
		*out = NCFG_FIREWALL_DROP;
		return 1;
	}
	if (strcmp(head, "reject") == 0) {
		*out = NCFG_FIREWALL_REJECT;
		return 1;
	}
	return 0;
}

/* **Two words and not three.** nftables has no `policy reject`: a chain's
 * policy is what happens to a packet no rule matched, and the kernel offers
 * accept and drop. A document asking for a third is refused here rather than
 * rendered as one of these, which would be this file choosing. */
static void chain_policy(ncfg_lower_ctx_t *ctx, const ncfg_ast_assignment_t *assignment,
    int *out)
{
	char *word = ncfg_as_string(ctx, assignment->value);

	if (!word) {
		return;
	}
	if (strcmp(word, "accept") == 0) {
		*out = NCFG_FIREWALL_POLICY_ACCEPT;
	} else if (strcmp(word, "drop") == 0) {
		*out = NCFG_FIREWALL_POLICY_DROP;
	} else {
		ncfg_diag(ctx, assignment->span,
		    "`%s` is not a chain policy: one of accept, drop. A chain's policy is what "
		    "happens to a packet no rule matched, and the kernel has no `policy reject` "
		    "-- write a `reject` rule at the end of the chain instead", word);
	}
	free(word);
}

static void rule_protocol(ncfg_lower_ctx_t *ctx, const ncfg_ast_assignment_t *assignment,
    int *out)
{
	char *word = ncfg_as_string(ctx, assignment->value);

	if (!word) {
		return;
	}
	if (strcmp(word, "any") == 0) {
		*out = NCFG_FIREWALL_PROTO_ANY;
	} else if (strcmp(word, "tcp") == 0) {
		*out = NCFG_FIREWALL_PROTO_TCP;
	} else if (strcmp(word, "udp") == 0) {
		*out = NCFG_FIREWALL_PROTO_UDP;
	} else if (strcmp(word, "icmp") == 0) {
		*out = NCFG_FIREWALL_PROTO_ICMP;
	} else if (strcmp(word, "icmpv6") == 0) {
		*out = NCFG_FIREWALL_PROTO_ICMPV6;
	} else if (strcmp(word, "gre") == 0) {
		*out = NCFG_FIREWALL_PROTO_GRE;
	} else if (strcmp(word, "esp") == 0) {
		*out = NCFG_FIREWALL_PROTO_ESP;
	} else if (strcmp(word, "ah") == 0) {
		*out = NCFG_FIREWALL_PROTO_AH;
	} else if (strcmp(word, "sctp") == 0) {
		*out = NCFG_FIREWALL_PROTO_SCTP;
	} else if (strcmp(word, "ipip") == 0) {
		*out = NCFG_FIREWALL_PROTO_IPIP;
	} else if (strcmp(word, "sit") == 0) {
		*out = NCFG_FIREWALL_PROTO_SIT;
	} else {
		ncfg_diag(ctx, assignment->span,
		    "`%s` is not a protocol netcfgd matches: one of any, tcp, udp, sctp, icmp, "
		    "icmpv6, gre, esp, ah, ipip, sit (0294, 0335)", word);
	}
	free(word);
}

/*
 * One port, or a list of them, each a number or a range written as a string,
 * `"1000-2000"` (0331).
 *
 * A single number is accepted as well as a list, for the reason `addressing`
 * accepts a string or a list: a rule for one port is the common case and
 * `port = 22` is what somebody writes. A range is a string because the
 * language has no range literal, and `"60000-61000"` is what nft and iptables
 * both print.
 */
static void rule_ports(ncfg_lower_ctx_t *ctx, const ncfg_ast_assignment_t *assignment,
    ncfg_firewall_rule_t *rule)
{
	const ncfg_ast_value_t *value = assignment->value;
	ncfg_ast_value_t *const *entries;
	ncfg_ast_value_t        *one[1];
	size_t                   count;
	size_t                   i;

	if (value->kind == NCFG_AST_LIST) {
		entries = value->entries.at;
		count = value->entries.count;
	} else {
		/* Cast away the const for the one-element case only: the AST is the
		 * caller's and nothing here writes through it. */
		one[0] = (ncfg_ast_value_t *)value;
		entries = one;
		count = 1u;
	}
	free(rule->ports);
	rule->ports = NULL;
	rule->port_count = 0;
	ncfg_strings_free(rule->port_ranges, rule->port_range_count);
	rule->port_ranges = NULL;
	rule->port_range_count = 0;
	if (count == 0) {
		return;
	}
	rule->ports = calloc(count, sizeof(*rule->ports));
	if (!rule->ports) {
		ncfg_lower_oom(ctx);
		return;
	}
	for (i = 0; i < count; i++) {
		int64_t port = 0;

		if (entries[i]->kind == NCFG_AST_STRING) {
			unsigned long low = 0, high = 0;
			char          tail = 0;
			char          normal[16];
			char         *text = ncfg_as_string(ctx, entries[i]);

			if (!text) {
				continue;
			}
			if (sscanf(text, "%lu-%lu%c", &low, &high, &tail) != 2 || low < 1 ||
			    high > 65535 || low >= high) {
				ncfg_diag(ctx, entries[i]->span,
				    "`%s` is not a port range: two ports from 1 to 65535 with a dash, "
				    "the lower first, as \"1000-2000\"", text);
				free(text);
				continue;
			}
			free(text);
			/* Written back without leading zeros or spaces, so the digest
			 * and the reader agree on one spelling. */
			(void)snprintf(normal, sizeof(normal), "%lu-%lu", low, high);
			(void)ncfg_push_string(ctx, &rule->port_ranges, &rule->port_range_count, normal);
			continue;
		}
		if (entries[i]->kind != NCFG_AST_NUMBER) {
			ncfg_diag(ctx, entries[i]->span,
			    "a port is a number or a range as \"1000-2000\", found %s",
			    ncfg_ast_value_describe(entries[i]));
			continue;
		}
		if (!ncfg_as_i64(ctx, entries[i], &port)) {
			continue;
		}
		/* The kernel's range, said here rather than left to the transaction:
		 * `port = 0` and `port = 70000` are both things somebody types, and
		 * a refusal at compile time names the line. */
		if (port < 1 || port > 65535) {
			ncfg_diag(ctx, entries[i]->span,
			    "%lld is not a port: 1 to 65535", (long long)port);
			continue;
		}
		rule->ports[rule->port_count++] = port;
	}
}

/*
 * The ICMP and ICMPv6 types a rule may name in words (0333): the ones an
 * operator writes, as nft spells them. Anything else is written as its number.
 */
static const struct {
	int         icmpv6;
	int         type;
	const char *name;
} icmp_names[] = {
	{ 0, 0, "echo-reply" },
	{ 0, 3, "destination-unreachable" },
	{ 0, 5, "redirect" },
	{ 0, 8, "echo-request" },
	{ 0, 11, "time-exceeded" },
	{ 0, 12, "parameter-problem" },
	{ 1, 1, "destination-unreachable" },
	{ 1, 2, "packet-too-big" },
	{ 1, 3, "time-exceeded" },
	{ 1, 4, "parameter-problem" },
	{ 1, 128, "echo-request" },
	{ 1, 129, "echo-reply" },
	{ 1, 133, "nd-router-solicit" },
	{ 1, 134, "nd-router-advert" },
	{ 1, 135, "nd-neighbor-solicit" },
	{ 1, 136, "nd-neighbor-advert" },
};

const char *ncfg_icmp_type_name(int icmpv6, int64_t type)
{
	size_t at;

	for (at = 0; at < sizeof(icmp_names) / sizeof(icmp_names[0]); at++) {
		if ((icmp_names[at].icmpv6 != 0) == (icmpv6 != 0) && icmp_names[at].type == type) {
			return icmp_names[at].name;
		}
	}
	return NULL;
}

int64_t ncfg_icmp_type_number(int icmpv6, const char *name)
{
	size_t at;

	for (at = 0; name && at < sizeof(icmp_names) / sizeof(icmp_names[0]); at++) {
		if ((icmp_names[at].icmpv6 != 0) == (icmpv6 != 0) &&
		    strcmp(icmp_names[at].name, name) == 0) {
			return icmp_names[at].type;
		}
	}
	return -1;
}

/*
 * `icmp_type`: a name, a number, or a list of either (0333). Names are read
 * once the protocol is known, at the end of the rule, so the order the two
 * keys are written in does not matter; this keeps the words as written.
 */
static void rule_icmp_types(ncfg_lower_ctx_t *ctx, const ncfg_ast_assignment_t *assignment,
    const ncfg_ast_value_t **out)
{
	(void)ctx;
	*out = assignment->value;
}

/* The words kept by `rule_icmp_types`, as numbers, for the protocol the rule
 * names. 0 where any is refused, with the diagnostic said. */
static int resolve_icmp_types(ncfg_lower_ctx_t *ctx, const ncfg_ast_value_t *value,
    ncfg_firewall_rule_t *rule)
{
	ncfg_ast_value_t *const *entries;
	ncfg_ast_value_t        *one[1];
	size_t                   count;
	size_t                   i;
	const int                icmpv6 = rule->protocol == NCFG_FIREWALL_PROTO_ICMPV6;

	if (value->kind == NCFG_AST_LIST) {
		entries = value->entries.at;
		count = value->entries.count;
	} else {
		one[0] = (ncfg_ast_value_t *)value;
		entries = one;
		count = 1u;
	}
	free(rule->icmp_types);
	rule->icmp_types = count ? calloc(count, sizeof(*rule->icmp_types)) : NULL;
	rule->icmp_type_count = 0;
	if (count && !rule->icmp_types) {
		ncfg_lower_oom(ctx);
		return 0;
	}
	for (i = 0; i < count; i++) {
		int64_t type = -1;

		if (entries[i]->kind == NCFG_AST_STRING) {
			char *text = ncfg_as_string(ctx, entries[i]);

			type = ncfg_icmp_type_number(icmpv6, text);
			if (type < 0) {
				ncfg_diag(ctx, entries[i]->span,
				    "`%s` is not an %s type netcfgd knows by name: write its number, "
				    "0 to 255", text ? text : "", icmpv6 ? "ICMPv6" : "ICMP");
				free(text);
				return 0;
			}
			free(text);
		} else if (entries[i]->kind == NCFG_AST_NUMBER) {
			if (!ncfg_as_i64(ctx, entries[i], &type)) {
				return 0;
			}
			if (type < 0 || type > 255) {
				ncfg_diag(ctx, entries[i]->span,
				    "%lld is not an ICMP type: 0 to 255", (long long)type);
				return 0;
			}
		} else {
			ncfg_diag(ctx, entries[i]->span,
			    "an ICMP type is a name or a number, found %s",
			    ncfg_ast_value_describe(entries[i]));
			return 0;
		}
		rule->icmp_types[rule->icmp_type_count++] = type;
	}
	return 1;
}

static void rule_states(ncfg_lower_ctx_t *ctx, const ncfg_ast_assignment_t *assignment,
    ncfg_firewall_rule_t *rule)
{
	ncfg_words_t words;
	size_t       i;
	size_t       j;

	memset(&words, 0, sizeof(words));
	if (!ncfg_as_words(ctx, assignment->value, &words)) {
		ncfg_words_free(&words);
		return;
	}
	/* **Every word checked before any is kept**, so a list with one typo in
	 * it leaves the rule's states as they were rather than half written: a
	 * rule matching `established` where the document said `established,
	 * releated` is a rule nobody asked for. */
	for (i = 0; i < words.count; i++) {
		int known = 0;

		for (j = 0; j < sizeof(state_words) / sizeof(state_words[0]); j++) {
			if (strcmp(words.at[i].text, state_words[j]) == 0) {
				known = 1;
				break;
			}
		}
		if (!known) {
			ncfg_diag(ctx, words.at[i].span,
			    "`%s` is not a connection state: one of new, established, related, "
			    "invalid", words.at[i].text);
			ncfg_words_free(&words);
			return;
		}
	}
	ncfg_strings_free(rule->states, rule->state_count);
	rule->states = NULL;
	rule->state_count = 0;
	for (i = 0; i < words.count; i++) {
		(void)ncfg_push_string(ctx, &rule->states, &rule->state_count, words.at[i].text);
	}
	ncfg_words_free(&words);
}

/* An address list, held as written: the renderer has to put back what the
 * operator typed, which is why these are not canonicalised the way a routing
 * rule's selectors are. */
static void rule_addresses(ncfg_lower_ctx_t *ctx, const ncfg_ast_assignment_t *assignment,
    char ***out, size_t *count)
{
	ncfg_words_t words;
	size_t       i;

	memset(&words, 0, sizeof(words));
	if (!ncfg_as_words(ctx, assignment->value, &words)) {
		ncfg_words_free(&words);
		return;
	}
	ncfg_strings_free(*out, *count);
	*out = NULL;
	*count = 0;
	for (i = 0; i < words.count; i++) {
		(void)ncfg_push_string(ctx, out, count, words.at[i].text);
	}
	ncfg_words_free(&words);
}

/*
 * `mac`: the sending station, by address, by OUI prefix, or by host list
 * (10.592). Lists are resolved once every block is read -- `lower.c` -- and
 * the addresses written beside one are kept for the renderer only where one
 * is named, as an access point's are.
 */
static void rule_macs(ncfg_lower_ctx_t *ctx, const ncfg_ast_assignment_t *assignment,
    ncfg_firewall_rule_t *rule)
{
	ncfg_words_t words;
	size_t       i;

	memset(&words, 0, sizeof(words));
	if (!ncfg_as_words(ctx, assignment->value, &words)) {
		ncfg_words_free(&words);
		return;
	}
	for (i = 0; i < words.count; i++) {
		const char *text = words.at[i].text;
		char        why[NCFG_ERROR_MAX];
		char        normal[NCFG_STATION_ADDRESS_SIZE];

		if (strncmp(text, NCFG_HOST_LIST_PREFIX, strlen(NCFG_HOST_LIST_PREFIX)) == 0) {
			const char *name = text + strlen(NCFG_HOST_LIST_PREFIX);

			if (!ncfg_is_host_list_name(name)) {
				ncfg_diag(ctx, words.at[i].span,
				    "`%s` does not name a host list: after `%s` comes the list's name",
				    text, NCFG_HOST_LIST_PREFIX);
				continue;
			}
			if (!ncfg_has_string(rule->mac_lists, rule->mac_list_count, name)) {
				(void)ncfg_push_string(ctx, &rule->mac_lists, &rule->mac_list_count, name);
			}
			continue;
		}
		if (ncfg_station_is_prefix(text)
		    ? !ncfg_station_prefix_normalize(text, normal, sizeof(normal), why, sizeof(why))
		    : !ncfg_station_address_normalize(text, normal, sizeof(normal), why,
		          sizeof(why))) {
			ncfg_diag(ctx, words.at[i].span, "%s", why);
			continue;
		}
		if (!ncfg_has_string(rule->mac, rule->mac_count, normal)) {
			(void)ncfg_push_string(ctx, &rule->mac, &rule->mac_count, normal);
			(void)ncfg_push_string(ctx, &rule->mac_written, &rule->mac_written_count,
			    normal);
		}
	}
	ncfg_words_free(&words);
}

/* `hours`, refused by `schedule.h`'s own sentence and kept normalised. */
static void rule_hours(ncfg_lower_ctx_t *ctx, const ncfg_ast_assignment_t *assignment,
    ncfg_firewall_rule_t *rule)
{
	char *text = ncfg_as_string(ctx, assignment->value);
	char  normal[16];
	char  why[256];

	if (!text) {
		return;
	}
	if (!ncfg_schedule_hours_parse(text, NULL, NULL, normal, sizeof(normal), why,
	        sizeof(why))) {
		ncfg_diag(ctx, assignment->span, "`%s` %s", text, why);
		free(text);
		return;
	}
	free(text);
	free(rule->hours);
	rule->hours = strdup(normal);
	if (!rule->hours) {
		ncfg_diag(ctx, assignment->span, "out of memory");
	}
}

/*
 * `over`: "COUNT/DURATION", a duration being a number and `s`, `m`, `h` or
 * `d` -- `"8/15m"` -- kept as "COUNT/SECONDSs". Bounded so the kernel's limit
 * arithmetic stays sane: at least one packet, at most a million, over a
 * second to a week.
 */
static void rule_over(ncfg_lower_ctx_t *ctx, const ncfg_ast_assignment_t *assignment,
    ncfg_firewall_rule_t *rule)
{
	char         *text = ncfg_as_string(ctx, assignment->value);
	char          normal[48];
	char          unit = 0;
	char          tail = 0;
	unsigned long count = 0, amount = 0, seconds;

	if (!text) {
		return;
	}
	if (sscanf(text, "%lu/%lu%c%c", &count, &amount, &unit, &tail) != 3 ||
	    (unit != 's' && unit != 'm' && unit != 'h' && unit != 'd') || count == 0 ||
	    count > 1000000UL || amount == 0 || amount > 604800UL) {
		ncfg_diag(ctx, assignment->span,
		    "`%s` is not a rate `over` takes: a count, a slash and a duration in s, m, h "
		    "or d, such as \"8/15m\"", text);
		free(text);
		return;
	}
	free(text);
	seconds = amount * (unit == 's' ? 1UL : unit == 'm' ? 60UL : unit == 'h' ? 3600UL : 86400UL);
	if (seconds > 604800UL) {
		ncfg_diag(ctx, assignment->span, "`over` counts over a week at most");
		return;
	}
	(void)snprintf(normal, sizeof(normal), "%lu/%lus", count, seconds);
	free(rule->over);
	rule->over = strdup(normal);
	if (!rule->over) {
		ncfg_diag(ctx, assignment->span, "out of memory");
	}
}

/*
 * `days`, every word checked before any is kept, as `state`'s are; kept in
 * week order from Monday and once each, since a day is in a set or not.
 */
static void rule_days(ncfg_lower_ctx_t *ctx, const ncfg_ast_assignment_t *assignment,
    ncfg_firewall_rule_t *rule)
{
	static const int week[7] = { 1, 2, 3, 4, 5, 6, 0 };
	ncfg_words_t     words;
	unsigned         mask = 0;
	size_t           i;

	memset(&words, 0, sizeof(words));
	if (!ncfg_as_words(ctx, assignment->value, &words)) {
		ncfg_words_free(&words);
		return;
	}
	for (i = 0; i < words.count; i++) {
		const int day = ncfg_schedule_day(words.at[i].text, NULL);

		if (day < 0) {
			ncfg_diag(ctx, words.at[i].span,
			    "`%s` is not a day: one of mon, tue, wed, thu, fri, sat, sun, or the "
			    "whole name", words.at[i].text);
			ncfg_words_free(&words);
			return;
		}
		mask |= 1u << day;
	}
	ncfg_words_free(&words);
	ncfg_strings_free(rule->days, rule->day_count);
	rule->days = NULL;
	rule->day_count = 0;
	for (i = 0; i < 7u; i++) {
		if (mask & (1u << week[i])) {
			(void)ncfg_push_string(ctx, &rule->days, &rule->day_count,
			    ncfg_schedule_day_word(week[i]));
		}
	}
}

/*
 * One rule: the action from the head, the name from the label, the matches
 * from the keys.
 *
 * Returns 0 where the rule cannot be kept, which is a missing name or a
 * refused combination -- and the caller carries on with the next rule, so one
 * bad rule does not cost the chain its others. The document is refused anyway
 * once a diagnostic exists; carrying on is what makes a compile report every
 * fault rather than the first.
 */
static int lower_rule(ncfg_lower_ctx_t *ctx, const ncfg_ast_block_t *block, int action,
    ncfg_firewall_rule_t *out)
{
	ncfg_firewall_rule_t    rule;
	size_t                  i;
	/* `icmp_type` as written, read once the protocol is known (0333). */
	const ncfg_ast_value_t *icmp_written = NULL;

	memset(&rule, 0, sizeof(rule));
	rule.action = action;
	rule.protocol = NCFG_FIREWALL_PROTO_ANY;
	rule.name = ncfg_require_label(ctx, block);
	if (!rule.name) {
		return 0;
	}

	/*
	 * **The block's own items rather than a merged list.** The merge pass
	 * joins blocks of the same head and label across files and carries a
	 * source per item for diagnostics; a chain and a rule are nested inside
	 * one merged `firewall`, so their items come from one file and the
	 * enclosing walk has already set `ctx->source` to it.
	 */
	for (i = 0; i < block->items.count; i++) {
		const ncfg_ast_item_t       *item = block->items.at[i];
		const ncfg_ast_assignment_t *assignment;
		const char                  *key;

		if (item->kind == NCFG_AST_ITEM_BLOCK) {
			ncfg_diag(ctx, item->as.block.span,
			    "`%s` is not valid inside a firewall rule: a rule is keys only",
			    item->as.block.head);
			continue;
		}
		if (item->kind != NCFG_AST_ITEM_ASSIGNMENT) {
			continue;
		}
		assignment = &item->as.assignment;
		key = assignment->key;
		if (strcmp(key, "protocol") == 0) {
			rule_protocol(ctx, assignment, &rule.protocol);
		} else if (strcmp(key, "port") == 0) {
			rule_ports(ctx, assignment, &rule);
		} else if (strcmp(key, "from") == 0) {
			rule_addresses(ctx, assignment, &rule.from, &rule.from_count);
		} else if (strcmp(key, "to") == 0) {
			rule_addresses(ctx, assignment, &rule.to, &rule.to_count);
		} else if (strcmp(key, "interface") == 0) {
			free(rule.interface);
			rule.interface = ncfg_as_interface_name(ctx, assignment->value);
		} else if (strcmp(key, "out_interface") == 0) {
			free(rule.out_interface);
			rule.out_interface = ncfg_as_interface_name(ctx, assignment->value);
		} else if (strcmp(key, "state") == 0) {
			rule_states(ctx, assignment, &rule);
		} else if (strcmp(key, "translated") == 0) {
			int flag;

			if (ncfg_as_bool(ctx, assignment->value, &flag)) {
				rule.translated = flag;
			}
		} else if (strcmp(key, "mac") == 0) {
			rule_macs(ctx, assignment, &rule);
		} else if (strcmp(key, "hours") == 0) {
			rule_hours(ctx, assignment, &rule);
		} else if (strcmp(key, "days") == 0) {
			rule_days(ctx, assignment, &rule);
		} else if (strcmp(key, "over") == 0) {
			rule_over(ctx, assignment, &rule);
		} else if (strcmp(key, "log") == 0) {
			int flag;

			if (ncfg_as_bool(ctx, assignment->value, &flag)) {
				rule.log = flag;
			}
		} else if (strcmp(key, "icmp_type") == 0) {
			rule_icmp_types(ctx, assignment, &icmp_written);
		} else if (strcmp(key, "reset") == 0) {
			int flag;

			if (ncfg_as_bool(ctx, assignment->value, &flag)) {
				rule.reset = flag;
			}
		} else {
			ncfg_diag(ctx, assignment->span,
			    "`%s` is not a firewall rule key: one of protocol, port, from, to, "
			    "interface, out_interface, state, translated, mac, hours, days, over, log, "
			    "reset, icmp_type",
			    key);
		}
	}
	/* `log` beside `over` counts the meter once, in the log's rule, and hands
	 * the answer to the verdict's in the mark bit netcfgd reserves (0338). */
	/* **An ICMP type belongs to an ICMP rule** (0333), and its names are the
	 * protocol's: `echo-request` is 8 for one and 128 for the other. */
	if (icmp_written) {
		if (rule.protocol != NCFG_FIREWALL_PROTO_ICMP &&
		    rule.protocol != NCFG_FIREWALL_PROTO_ICMPV6) {
			ncfg_diag(ctx, block->span,
			    "rule `%s` matches an ICMP type with no ICMP protocol: add `protocol = "
			    "\"icmp\"` or `\"icmpv6\"`", rule.name);
			rule_free(&rule);
			return 0;
		}
		if (!resolve_icmp_types(ctx, icmp_written, &rule)) {
			rule_free(&rule);
			return 0;
		}
	}
	/* **A reset answers a TCP connection and nothing else** (0332): the kernel
	 * refuses `reject with tcp reset` on a rule that is not tcp's, and a
	 * reset for an accept or a drop says nothing anybody can act on. */
	if (rule.reset && (rule.action != NCFG_FIREWALL_REJECT ||
	        rule.protocol != NCFG_FIREWALL_PROTO_TCP)) {
		ncfg_diag(ctx, block->span,
		    "rule `%s` answers with a `reset`, which only a `reject` of `protocol = "
		    "\"tcp\"` can: a reset is TCP's way of refusing a connection", rule.name);
		rule_free(&rule);
		return 0;
	}
	/* What was written is the resolved set again where no list is named. */
	if (rule.mac_list_count == 0) {
		ncfg_strings_free(rule.mac_written, rule.mac_written_count);
		rule.mac_written = NULL;
		rule.mac_written_count = 0;
	}

	/*
	 * **A port with a protocol that has none.** The kernel would refuse the
	 * transaction, and the sentence an operator would read names a netlink
	 * message rather than the line they wrote -- which is the whole argument
	 * for refusing here. `any` is included: a port means tcp, udp or sctp,
	 * and a rule that does not say which is a rule whose author has not
	 * decided. sctp's destination port sits where tcp's does (0335).
	 */
	if ((rule.port_count > 0 || rule.port_range_count > 0) &&
	    rule.protocol != NCFG_FIREWALL_PROTO_TCP &&
	    rule.protocol != NCFG_FIREWALL_PROTO_UDP &&
	    rule.protocol != NCFG_FIREWALL_PROTO_SCTP) {
		ncfg_diag(ctx, block->span,
		    "rule `%s` matches ports with no protocol that has them: add "
		    "`protocol = \"tcp\"`, `\"udp\"` or `\"sctp\"`", rule.name);
		rule_free(&rule);
		return 0;
	}
	*out = rule;
	return 1;
}

/*
 * `slot "NAME" { action = ...; match = ...; timeout = ... }` (0340): a set the
 * chain opens for live updates. `action` and `match` are required, since a
 * slot that does not say what its members get is not one a writer can use.
 */
static int lower_slot(ncfg_lower_ctx_t *ctx, const ncfg_ast_block_t *block,
    ncfg_firewall_slot_t *out)
{
	ncfg_firewall_slot_t slot;
	int                  have_action = 0;
	int                  have_match = 0;
	int                  ok = 1;
	size_t               i;

	memset(&slot, 0, sizeof(slot));
	slot.name = ncfg_require_label(ctx, block);
	if (!slot.name) {
		return 0;
	}
	if (!ncfg_firewall_slot_name_valid(slot.name)) {
		ncfg_diag(ctx, block->span,
		    "`%s` cannot name a slot: a letter, then letters, digits, `-` or `_`, "
		    "%u at most, since it becomes a set's name and is what a live write names",
		    slot.name, NCFG_FIREWALL_SLOT_NAME_MAX);
		free(slot.name);
		return 0;
	}
	for (i = 0; i < block->items.count; i++) {
		const ncfg_ast_item_t       *item = block->items.at[i];
		const ncfg_ast_assignment_t *assignment;
		char                        *text;

		if (item->kind == NCFG_AST_ITEM_BLOCK) {
			ncfg_diag(ctx, item->as.block.span,
			    "`%s` is not valid inside a slot: a slot is keys only",
			    item->as.block.head);
			ok = 0;
			continue;
		}
		if (item->kind != NCFG_AST_ITEM_ASSIGNMENT) {
			continue;
		}
		assignment = &item->as.assignment;
		if (strcmp(assignment->key, "action") == 0) {
			text = ncfg_as_string(ctx, assignment->value);
			if (!text) {
				ok = 0;
				continue;
			}
			if (!rule_action(text, &slot.action)) {
				ncfg_diag(ctx, assignment->span,
				    "`%s` is not a slot's action: one of accept, drop, reject", text);
				ok = 0;
			} else {
				have_action = 1;
			}
			free(text);
		} else if (strcmp(assignment->key, "match") == 0) {
			text = ncfg_as_string(ctx, assignment->value);
			if (!text) {
				ok = 0;
				continue;
			}
			if (strcmp(text, "from") == 0) {
				slot.match = NCFG_FIREWALL_SLOT_FROM;
				have_match = 1;
			} else if (strcmp(text, "to") == 0) {
				slot.match = NCFG_FIREWALL_SLOT_TO;
				have_match = 1;
			} else {
				ncfg_diag(ctx, assignment->span,
				    "`%s` is not what a slot matches: `from`, a packet's source "
				    "address, or `to`, its destination", text);
				ok = 0;
			}
			free(text);
		} else if (strcmp(assignment->key, "timeout") == 0) {
			text = ncfg_as_string(ctx, assignment->value);
			if (!text) {
				ok = 0;
				continue;
			}
			if (!ncfg_firewall_duration(text, &slot.timeout)) {
				ncfg_diag(ctx, assignment->span,
				    "`%s` is not a slot's timeout: a count and s, m, h or d, such as "
				    "\"30m\", a week at most", text);
				ok = 0;
			}
			free(text);
		} else {
			ncfg_diag(ctx, assignment->span,
			    "`%s` is not a slot key: `action`, `match` and `timeout`",
			    assignment->key);
			ok = 0;
		}
	}
	if (ok && (!have_action || !have_match)) {
		ncfg_diag(ctx, block->span,
		    "slot `%s` does not say %s: a writer has to know what being in it does",
		    slot.name, !have_action ? "its `action`" : "what it `match`es");
		ok = 0;
	}
	if (!ok) {
		free(slot.name);
		return 0;
	}
	*out = slot;
	return 1;
}

/*
 * One chain: a policy and the rules under it, in the order they were written.
 * Never sorted -- nftables evaluates a chain in order, so the order is the
 * policy, and `ssh` before `netbios` accepts what the later rule drops.
 *
 * `preset` names the preset the chain is in (0341), or is NULL for the
 * firewall's own. A preset's chain has rules and nothing else -- no policy,
 * which is the host's answer, and no slot, which the host opens -- and each
 * rule is named `PRESET/RULE`.
 */
static int lower_chain(ncfg_lower_ctx_t *ctx, const ncfg_ast_block_t *block,
    const char *chain_name, ncfg_firewall_chain_t *out, const char *preset)
{
	ncfg_firewall_chain_t chain;
	int                   policy_named = 0;
	size_t                i;

	memset(&chain, 0, sizeof(chain));
	chain.policy = NCFG_FIREWALL_POLICY_ACCEPT;

	for (i = 0; i < block->items.count; i++) {
		const ncfg_ast_item_t *item = block->items.at[i];

		if (item->kind == NCFG_AST_ITEM_ASSIGNMENT) {
			if (preset && strcmp(item->as.assignment.key, "policy") == 0) {
				ncfg_diag(ctx, item->as.assignment.span,
				    "preset `%s` sets the %s chain's policy: a policy is what the host "
				    "does with what nothing matched, and is the host's own firewall's "
				    "to say", preset, chain_name);
			} else if (strcmp(item->as.assignment.key, "policy") == 0) {
				chain_policy(ctx, &item->as.assignment, &chain.policy);
				policy_named = 1;
			} else {
				ncfg_diag(ctx, item->as.assignment.span,
				    "`%s` is not a firewall chain key: `policy`, and then the "
				    "rules as `accept`, `drop` or `reject` blocks",
				    item->as.assignment.key);
			}
			continue;
		}
		if (item->kind != NCFG_AST_ITEM_BLOCK) {
			continue;
		}
		if (preset && strcmp(item->as.block.head, "slot") == 0) {
			ncfg_diag(ctx, item->as.block.span,
			    "preset `%s` opens a slot: a slot is opened by the host that is "
			    "written into, in its own firewall", preset);
			continue;
		}
		if (strcmp(item->as.block.head, "slot") == 0) {
			ncfg_firewall_slot_t  slot;
			ncfg_firewall_slot_t *grown;

			if (!lower_slot(ctx, &item->as.block, &slot)) {
				continue;
			}
			grown = realloc(chain.slots, (chain.slot_count + 1u) * sizeof(*grown));
			if (!grown) {
				ncfg_lower_oom(ctx);
				free(slot.name);
				chain_free(&chain);
				return 0;
			}
			chain.slots = grown;
			chain.slots[chain.slot_count++] = slot;
			continue;
		}
		{
			ncfg_firewall_rule_t rule;
			int                  action = 0;
			size_t               at;

			if (!rule_action(item->as.block.head, &action)) {
				ncfg_diag(ctx, item->as.block.span,
				    "`%s` is not a firewall action: a rule is `accept`, `drop` or "
				    "`reject`, each with a name, and a `slot` opens a set for live "
				    "updates", item->as.block.head);
				continue;
			}
			if (!lower_rule(ctx, &item->as.block, action, &rule)) {
				continue;
			}
			/* **A `/` is the preset's mark** (0341): `web/http` is the
			 * rule `http` from preset `web`, so a written rule may not
			 * wear one, and a preset's rule is given it here. */
			if (strchr(rule.name, '/') != NULL || strchr(rule.name, '>') != NULL) {
				ncfg_diag(ctx, item->as.block.span,
				    "rule `%s` has a `%c` in its name, which marks a %s",
				    rule.name, strchr(rule.name, '/') ? '/' : '>',
				    strchr(rule.name, '/') ? "preset's rule (`PRESET/RULE`)"
				                           : "zone's compiled rule (`ZONE>REACH:...`)");
				rule_free(&rule);
				continue;
			}
			if (preset) {
				size_t length = strlen(preset) + 1u + strlen(rule.name) + 1u;
				char  *named = malloc(length);

				if (!named) {
					ncfg_lower_oom(ctx);
					rule_free(&rule);
					continue;
				}
				(void)snprintf(named, length, "%s/%s", preset, rule.name);
				free(rule.name);
				rule.name = named;
			}
			/* A packet this host sends has no sending station yet: its link
			 * header is built after the output hook, so `ether saddr` there
			 * would compile into a rule that never matches. */
			/* **Where a packet leaves, in the one chain that has both ends**
			 * (0302). In `input` nothing leaves, and in `output` the
			 * interface a packet leaves by is already `interface`. */
			if (rule.out_interface && strcmp(chain_name, "forward") != 0) {
				ncfg_diag(ctx, item->as.block.span,
				    "rule `%s` matches `out_interface` in the %s chain: only a forwarded "
				    "packet has an interface it arrives on and one it leaves by%s",
				    rule.name, chain_name,
				    strcmp(chain_name, "output") == 0
				        ? "; in `output`, `interface` is the one it leaves by" : "");
				rule_free(&rule);
				continue;
			}
			/* **`over` counts per source**, so it means something only where
			 * the source is somebody else -- and only as a reason to stop
			 * them: an `accept` past a rate would let in exactly what the
			 * rate is there to keep out. */
			if (rule.over && (strcmp(chain_name, "output") == 0 ||
			    rule.action == NCFG_FIREWALL_ACCEPT)) {
				ncfg_diag(ctx, item->as.block.span,
				    "rule `%s` counts `over` %s: it is a per-source limit, for a `drop` "
				    "or `reject` in `input` or `forward`", rule.name,
				    rule.action == NCFG_FIREWALL_ACCEPT ? "on an accept"
				                                        : "in the output chain");
				rule_free(&rule);
				continue;
			}
			if (strcmp(chain_name, "output") == 0 &&
			    (rule.mac_count || rule.mac_list_count)) {
				ncfg_diag(ctx, item->as.block.span,
				    "rule `%s` matches `mac` in the output chain, where a packet "
				    "this host sends has no sending station to match; match it in "
				    "`input` or `forward`", rule.name);
				rule_free(&rule);
				continue;
			}
			/* **One name per chain**, because the name is the rule's
			 * identity: a second rule wearing it would take the first's
			 * standing, and a red row would name a rule the operator
			 * cannot find. */
			for (at = 0; at < chain.rule_count; at++) {
				if (strcmp(chain.rules[at].name, rule.name) == 0) {
					ncfg_diag(ctx, item->as.block.span,
					    "two rules in `%s` are named `%s`: a name is a "
					    "rule's identity and has to be its own",
					    chain_name, rule.name);
					rule_free(&rule);
					break;
				}
			}
			if (at < chain.rule_count) {
				continue;
			}
			{
				ncfg_firewall_rule_t *grown = realloc(chain.rules,
				    (chain.rule_count + 1u) * sizeof(*grown));

				if (!grown) {
					ncfg_lower_oom(ctx);
					rule_free(&rule);
					chain_free(&chain);
					return 0;
				}
				chain.rules = grown;
				chain.rules[chain.rule_count++] = rule;
			}
		}
	}

	/* **A chain with no policy is refused rather than defaulted.** The two
	 * answers are "everything else is allowed" and "everything else is
	 * blocked", and a firewall whose author did not say which is not a
	 * firewall. */
	if (!policy_named && !preset) {
		ncfg_diag(ctx, block->span,
		    "chain `%s` has no `policy`: say `policy = \"accept\"` or `\"drop\"`, since "
		    "the two are opposite answers for every packet no rule matched", chain_name);
		chain_free(&chain);
		return 0;
	}
	*out = chain;
	return 1;
}

/* Whether `name` can name a preset: a slot's alphabet, since it prefixes a
 * rule's name in the kernel's comment and in a red row. */
static int preset_name_ok(const char *name)
{
	return ncfg_firewall_slot_name_valid(name);
}

/* `presets = ["web", "dns"]` (0341): each name once, each one a preset can
 * have. Whether each is defined is answered once every block is read. */
static void firewall_presets(ncfg_lower_ctx_t *ctx, const ncfg_ast_assignment_t *assignment,
    ncfg_firewall_t *firewall)
{
	ncfg_words_t words;
	size_t       i, j;

	memset(&words, 0, sizeof(words));
	if (!ncfg_as_words(ctx, assignment->value, &words)) {
		ncfg_words_free(&words);
		return;
	}
	ncfg_strings_free(firewall->presets, firewall->preset_count);
	firewall->presets = NULL;
	firewall->preset_count = 0;
	ctx->presets_span = assignment->span;
	ctx->presets_source = ctx->source;
	for (i = 0; i < words.count; i++) {
		const char *name = words.at[i].text;
		int         twice = 0;

		if (!preset_name_ok(name)) {
			ncfg_diag(ctx, assignment->span,
			    "`%s` cannot name a preset: a letter, then letters, digits, `-` or `_`", name);
			continue;
		}
		for (j = 0; j < firewall->preset_count; j++) {
			twice = twice || strcmp(firewall->presets[j], name) == 0;
		}
		if (twice) {
			ncfg_diag(ctx, assignment->span, "preset `%s` is named twice in `presets`", name);
			continue;
		}
		(void)ncfg_push_string(ctx, &firewall->presets, &firewall->preset_count, name);
	}
	ncfg_words_free(&words);
}

/* `from`'s rules appended to `into`, which takes them over. */
static int chain_append(ncfg_lower_ctx_t *ctx, ncfg_firewall_chain_t *into,
    ncfg_firewall_chain_t *from)
{
	ncfg_firewall_rule_t *grown;

	if (from->rule_count == 0u) {
		return 1;
	}
	grown = realloc(into->rules, (into->rule_count + from->rule_count) * sizeof(*grown));
	if (!grown) {
		ncfg_lower_oom(ctx);
		return 0;
	}
	into->rules = grown;
	memcpy(&into->rules[into->rule_count], from->rules, from->rule_count * sizeof(*grown));
	into->rule_count += from->rule_count;
	free(from->rules);
	from->rules = NULL;
	from->rule_count = 0;
	return 1;
}

/* One preset block lowered into three chains of rules. 0 where it is not one
 * the language allows, which has been said. */
static int lower_preset(ncfg_lower_ctx_t *ctx, const ncfg_merged_block_t *merged,
    ncfg_firewall_chain_t chains[3])
{
	static const char *const names[3] = { "input", "forward", "output" };
	const char              *preset = merged->block->label;
	int                      seen[3] = { 0, 0, 0 };
	size_t                   i, c;

	memset(chains, 0, 3u * sizeof(*chains));
	if (!preset || !preset_name_ok(preset)) {
		ncfg_diag(ctx, merged->block->span,
		    "`preset` needs a name: a letter, then letters, digits, `-` or `_`, as "
		    "`preset \"web\" { ... }`");
		return 0;
	}
	for (i = 0; i < merged->item_count; i++) {
		const ncfg_ast_item_t *item = merged->items[i].item;

		ctx->source = merged->items[i].source;
		if (item->kind == NCFG_AST_ITEM_ASSIGNMENT) {
			ncfg_diag(ctx, item->as.assignment.span,
			    "`%s` is not valid directly inside a preset: it holds the chains "
			    "`input`, `forward` and `output`, and their rules", item->as.assignment.key);
			continue;
		}
		if (item->kind != NCFG_AST_ITEM_BLOCK) {
			continue;
		}
		for (c = 0; c < 3u; c++) {
			if (strcmp(item->as.block.head, names[c]) == 0) {
				break;
			}
		}
		if (c == 3u) {
			ncfg_diag(ctx, item->as.block.span,
			    "`%s` is not a firewall chain: a preset's are input, forward and output",
			    item->as.block.head);
			continue;
		}
		if (seen[c]) {
			ncfg_diag(ctx, item->as.block.span, "preset `%s` has a second `%s` chain",
			    preset, names[c]);
			continue;
		}
		seen[c] = 1;
		(void)lower_chain(ctx, &item->as.block, names[c], &chains[c], preset);
	}
	return 1;
}

void ncfg_lower_presets(ncfg_lower_ctx_t *ctx, const struct ncfg_merged *merged)
{
	ncfg_firewall_t *firewall = ctx && ctx->document ? ctx->document->firewall : NULL;
	size_t           used, b, c;

	if (!ctx || !merged) {
		return;
	}
	/* Every preset is checked, used or not: a library with a broken entry
	 * is found when it is written rather than when a host first uses it. */
	for (b = 0; b < merged->block_count; b++) {
		ncfg_firewall_chain_t chains[3];
		const char           *label = merged->blocks[b].block->label;
		size_t                at;
		int                   is_used = 0;

		if (strcmp(merged->blocks[b].block->head, "preset") != 0) {
			continue;
		}
		/* A used one is lowered below, and said once. */
		for (at = 0; firewall && label && at < firewall->preset_count; at++) {
			is_used = is_used || strcmp(firewall->presets[at], label) == 0;
		}
		if (is_used) {
			continue;
		}
		if (lower_preset(ctx, &merged->blocks[b], chains)) {
			for (c = 0; c < 3u; c++) {
				chain_free(&chains[c]);
			}
		}
	}
	if (!firewall) {
		return;
	}
	/* Then the used ones, in the order `presets` names them, each after the
	 * written rules and every preset named before it (0339). */
	for (used = 0; used < firewall->preset_count; used++) {
		const ncfg_merged_block_t *found = NULL;
		ncfg_firewall_chain_t      chains[3];

		for (b = 0; b < merged->block_count; b++) {
			const ncfg_ast_block_t *block = merged->blocks[b].block;

			if (strcmp(block->head, "preset") == 0 && block->label &&
			    strcmp(block->label, firewall->presets[used]) == 0) {
				found = &merged->blocks[b];
			}
		}
		if (!found) {
			ctx->source = ctx->presets_source;
			ncfg_diag(ctx, ctx->presets_span,
			    "the firewall uses preset `%s`, and no `preset \"%s\"` block defines it",
			    firewall->presets[used], firewall->presets[used]);
			continue;
		}
		if (!lower_preset(ctx, found, chains)) {
			continue;
		}
		(void)chain_append(ctx, &firewall->input, &chains[0]);
		(void)chain_append(ctx, &firewall->forward, &chains[1]);
		(void)chain_append(ctx, &firewall->output, &chains[2]);
		for (c = 0; c < 3u; c++) {
			chain_free(&chains[c]);
		}
	}
}

void ncfg_lower_firewall(ncfg_lower_ctx_t *ctx, const ncfg_merged_block_t *merged)
{
	ncfg_firewall_t *firewall;
	/*
	 * **Which chains have been said, and not whether they hold rules.** This
	 * keyed on `rule_count` first, and a second `input { policy = "accept" }`
	 * with no rules in it walked straight past and replaced the first chain's
	 * policy -- which `lower_test` caught. A chain that was written is a
	 * chain that was written, rules or not.
	 */
	int              seen_input = 0;
	int              seen_forward = 0;
	int              seen_output = 0;
	size_t           i;

	if (!ctx || !ctx->document || !merged) {
		return;
	}
	/*
	 * **One `firewall` block per configuration, and the merge pass is what
	 * says so.** A check here was written first and measured dead: two
	 * top-level `firewall` blocks are refused before lowering with the
	 * language's own sentence -- "`firewall` is already defined: first
	 * defined at netcfgd.conf:1; write `override firewall` to replace it" --
	 * which is better than anything this file would have said, because it
	 * names the other block's line and offers the mechanism.
	 *
	 * So this is an assertion rather than a check: reaching it twice would
	 * mean the merge pass had changed under us, and overwriting the first
	 * firewall silently is the one outcome worth refusing outright.
	 */
	if (ctx->document->firewall) {
		ncfg_diag(ctx, merged->block->span,
		    "a second `firewall` reached lowering, which the merge pass should have "
		    "refused: this is a defect in netcfgd rather than in the configuration");
		return;
	}
	firewall = calloc(1, sizeof(*firewall));
	if (!firewall) {
		ncfg_lower_oom(ctx);
		return;
	}
	firewall->input.policy = NCFG_FIREWALL_POLICY_ACCEPT;
	firewall->forward.policy = NCFG_FIREWALL_POLICY_ACCEPT;
	firewall->output.policy = NCFG_FIREWALL_POLICY_ACCEPT;

	for (i = 0; i < merged->item_count; i++) {
		const ncfg_ast_item_t *item = merged->items[i].item;

		ctx->source = merged->items[i].source;
		if (item->kind == NCFG_AST_ITEM_ASSIGNMENT &&
		    strcmp(item->as.assignment.key, "presets") == 0) {
			firewall_presets(ctx, &item->as.assignment, firewall);
			continue;
		}
		if (item->kind == NCFG_AST_ITEM_ASSIGNMENT) {
			ncfg_diag(ctx, item->as.assignment.span,
			    "`%s` is not valid directly inside `firewall`: the chains are "
			    "`input`, `forward` and `output`, and the keys go in them, beside "
			    "`presets`", item->as.assignment.key);
			continue;
		}
		if (item->kind != NCFG_AST_ITEM_BLOCK) {
			continue;
		}
		{
			const char            *head = item->as.block.head;
			ncfg_firewall_chain_t *target = NULL;

			int *seen = NULL;

			if (strcmp(head, "input") == 0) {
				target = &firewall->input;
				seen = &seen_input;
			} else if (strcmp(head, "forward") == 0) {
				target = &firewall->forward;
				seen = &seen_forward;
			} else if (strcmp(head, "output") == 0) {
				target = &firewall->output;
				seen = &seen_output;
			} else {
				ncfg_diag(ctx, item->as.block.span,
				    "`%s` is not a firewall chain: the three are input, forward "
				    "and output, which are the hooks netcfgd owns (0294)", head);
				continue;
			}
			if (*seen) {
				ncfg_diag(ctx, item->as.block.span,
				    "a second `%s` chain: say it once, since the order of the "
				    "rules in it is the order they are evaluated in", head);
				continue;
			}
			*seen = 1;
			(void)lower_chain(ctx, &item->as.block, head, target, NULL);
		}
	}
	/* **A slot's name is the firewall's, not the chain's** (0340): a live
	 * write names a slot and nothing else, so two of one name could not be
	 * told apart. */
	{
		const ncfg_firewall_chain_t *chains[3] = { &firewall->input, &firewall->forward,
			&firewall->output };
		size_t c, s, total = 0;

		for (c = 0; c < 3u; c++) {
			total += chains[c]->slot_count;
			for (s = 0; s < chains[c]->slot_count; s++) {
				const char *name = chains[c]->slots[s].name;
				size_t      d, t;
				int         twice = 0;

				for (d = 0; d <= c && !twice; d++) {
					size_t end = d == c ? s : chains[d]->slot_count;

					for (t = 0; t < end; t++) {
						if (strcmp(chains[d]->slots[t].name, name) == 0) {
							twice = 1;
							break;
						}
					}
				}
				if (twice) {
					ncfg_diag(ctx, merged->block->span,
					    "two slots are named `%s`: a live write names a slot and "
					    "nothing else, so the name has to be the firewall's own", name);
				}
			}
		}
		if (total > NCFG_FIREWALL_SLOT_MAX) {
			ncfg_diag(ctx, merged->block->span,
			    "%zu slots, and a firewall opens %u at most", total,
			    NCFG_FIREWALL_SLOT_MAX);
		}
	}
	ctx->document->firewall = firewall;
}

/* ------------------------------------------------------------------------ *
 * Zones (0284's layer three, project.md 10.927)
 * ------------------------------------------------------------------------ */

/* A zone's name: a slot's alphabet, as a preset's is, since it names compiled
 * rules and travels to every host. */
static int zone_name_ok(const char *name)
{
	return ncfg_firewall_slot_name_valid(name);
}

/*
 *     zone "guest" { reach = ["internet"] }
 *
 * The estate's: one name, one meaning, on every host. What it may reach is
 * other zones by name, itself included -- a zone that reaches itself lets its
 * interfaces forward between them.
 */
int ncfg_lower_zone(ncfg_lower_ctx_t *ctx, const ncfg_merged_block_t *merged, ncfg_zone_t *out)
{
	const ncfg_ast_block_t *block = merged->block;
	size_t                  i;

	memset(out, 0, sizeof(*out));
	out->name = ncfg_require_label(ctx, block);
	if (!out->name) {
		return 0;
	}
	if (!zone_name_ok(out->name)) {
		ncfg_diag(ctx, block->span,
		    "`%s` cannot name a zone: a letter, then letters, digits, `-` or `_`, up to %u",
		    out->name, NCFG_FIREWALL_SLOT_NAME_MAX);
		free(out->name);
		out->name = NULL;
		return 0;
	}
	for (i = 0; i < merged->item_count; i++) {
		const ncfg_ast_item_t       *item = merged->items[i].item;
		const ncfg_ast_assignment_t *assignment;
		ncfg_words_t                 words;
		size_t                       at;

		ctx->source = merged->items[i].source;
		if (item->kind == NCFG_AST_ITEM_BLOCK) {
			ncfg_diag(ctx, item->as.block.span, "`%s` is not valid inside `zone`",
			    item->as.block.head);
			continue;
		}
		if (item->kind != NCFG_AST_ITEM_ASSIGNMENT) {
			continue;
		}
		assignment = &item->as.assignment;
		/* Each client's cap (10.928): a rate as a queue's is written. */
		if (strcmp(assignment->key, "client_limit") == 0) {
			char   *text = ncfg_as_string(ctx, assignment->value);
			int64_t bits = 0;

			if (!text) {
				continue;
			}
			if (!ncfg_lower_rate_bits(ctx, text, assignment->span, &bits)) {
				free(text);
				continue;
			}
			if (bits < 8) {
				ncfg_diag(ctx, assignment->span,
				    "`client_limit = \"%s\"` is less than a byte a second", text);
				free(text);
				continue;
			}
			free(out->client_limit);
			out->client_limit = text;
			continue;
		}
		if (strcmp(assignment->key, "reach") != 0) {
			ncfg_diag(ctx, assignment->span,
			    "unknown zone key `%s`: a zone says which zones it may `reach`, and "
			    "may set a `client_limit`", assignment->key);
			continue;
		}
		if (!ncfg_as_words(ctx, assignment->value, &words)) {
			ncfg_words_free(&words);
			continue;
		}
		for (at = 0; at < words.count; at++) {
			size_t seen;
			int    twice = 0;

			if (!zone_name_ok(words.at[at].text)) {
				ncfg_diag(ctx, words.at[at].span, "`%s` cannot name a zone",
				    words.at[at].text);
				continue;
			}
			for (seen = 0; seen < out->reach_count; seen++) {
				twice = twice || strcmp(out->reach[seen], words.at[at].text) == 0;
			}
			if (twice) {
				ncfg_diag(ctx, words.at[at].span, "zone `%s` reaches `%s` twice", out->name,
				    words.at[at].text);
				continue;
			}
			(void)ncfg_push_string(ctx, &out->reach, &out->reach_count, words.at[at].text);
		}
		ncfg_words_free(&words);
	}
	return 1;
}

static int zone_order(const void *left, const void *right)
{
	return strcmp(((const ncfg_zone_t *)left)->name, ((const ncfg_zone_t *)right)->name);
}

static int text_order(const void *left, const void *right)
{
	return strcmp(*(char *const *)left, *(char *const *)right);
}

static const ncfg_zone_t *zone_named(const ncfg_document_t *document, const char *name)
{
	size_t at;

	for (at = 0; at < document->zone_count; at++) {
		if (strcmp(document->zones[at].name, name) == 0) {
			return &document->zones[at];
		}
	}
	return NULL;
}

/*
 * One link's cap (10.928): two drop rules, one for what its clients send --
 * the meter keyed on the source -- and one for what they receive, keyed on
 * the destination, each over `bytes` a second. Put first in the chain by the
 * caller.
 */
static int zone_cap(ncfg_lower_ctx_t *ctx, ncfg_firewall_chain_t *caps, const char *zone,
    const char *link, int64_t bytes)
{
	static const char *const ways[2] = { "up", "down" };
	int                      way;

	for (way = 0; way < 2; way++) {
		ncfg_firewall_rule_t  rule;
		ncfg_firewall_rule_t *grown;
		char                  name[160];
		char                  over[48];

		(void)snprintf(name, sizeof(name), "%s>limit:%s:%s", zone, ways[way], link);
		(void)snprintf(over, sizeof(over), "B%lld/1s%s", (long long)bytes, way ? "@dst" : "");
		memset(&rule, 0, sizeof(rule));
		rule.name = strdup(name);
		rule.action = NCFG_FIREWALL_DROP;
		rule.over = strdup(over);
		if (way == 0) {
			rule.interface = strdup(link);
		} else {
			rule.out_interface = strdup(link);
		}
		if (!rule.name || !rule.over || (way == 0 ? !rule.interface : !rule.out_interface)) {
			ncfg_lower_oom(ctx);
			rule_free(&rule);
			return 0;
		}
		grown = realloc(caps->rules, (caps->rule_count + 1u) * sizeof(*grown));
		if (!grown) {
			ncfg_lower_oom(ctx);
			rule_free(&rule);
			return 0;
		}
		caps->rules = grown;
		caps->rules[caps->rule_count++] = rule;
	}
	return 1;
}

/* One compiled rule: accept from `in` out of `out`, named `NAME`, and only a
 * reply where `replies`. */
static int zone_rule(ncfg_lower_ctx_t *ctx, ncfg_firewall_chain_t *forward, const char *name,
    const char *in, const char *out, int replies)
{
	ncfg_firewall_rule_t rule;
	ncfg_firewall_rule_t *grown;

	memset(&rule, 0, sizeof(rule));
	rule.name = strdup(name);
	rule.action = NCFG_FIREWALL_ACCEPT;
	rule.interface = strdup(in);
	rule.out_interface = strdup(out);
	if (!rule.name || !rule.interface || !rule.out_interface ||
	    (replies && (!ncfg_push_string(ctx, &rule.states, &rule.state_count, "established") ||
	        !ncfg_push_string(ctx, &rule.states, &rule.state_count, "related")))) {
		ncfg_lower_oom(ctx);
		rule_free(&rule);
		return 0;
	}
	grown = realloc(forward->rules, (forward->rule_count + 1u) * sizeof(*grown));
	if (!grown) {
		ncfg_lower_oom(ctx);
		rule_free(&rule);
		return 0;
	}
	forward->rules = grown;
	forward->rules[forward->rule_count++] = rule;
	return 1;
}

/*
 * The zones this host's interfaces are in, compiled into its forward chain:
 * for each zone Z, each zone R it reaches, each of this host's interfaces a in
 * Z and b in R, an accept from a out of b named `Z>R:a>b`, and the reply's
 * way back named `Z>R:b<a`, established and related only. After the written
 * rules and before the presets (0339); a `>` is the zone's mark, as `/` is a
 * preset's, and a written rule may not wear one.
 *
 * A zone or a reach naming no declared zone is refused, and an interface in a
 * zone on a host with no `firewall` block too: the rules have nowhere to go,
 * and a zone that silently compiled into nothing would be a guest network
 * that reaches everything.
 */
void ncfg_lower_zones(ncfg_lower_ctx_t *ctx)
{
	ncfg_document_t *document = ctx ? ctx->document : NULL;
	size_t           z, r, a, b;
	int              any = 0;

	if (!document) {
		return;
	}
	ctx->source = ctx->zones_source;
	/* **In name order, not the order written**: the document keeps zones as a
	 * set by name, so a profile written back lists them sorted, and rules
	 * compiled in file order would come back in another order -- a round
	 * trip that changes the kernel's rule order. */
	if (document->zone_count > 1u) {
		qsort(document->zones, document->zone_count, sizeof(*document->zones), zone_order);
	}
	for (z = 0; z < document->zone_count; z++) {
		if (document->zones[z].reach_count > 1u) {
			qsort(document->zones[z].reach, document->zones[z].reach_count,
			    sizeof(*document->zones[z].reach), text_order);
		}
	}
	for (z = 0; z < document->zone_count; z++) {
		for (r = 0; r < document->zones[z].reach_count; r++) {
			if (!zone_named(document, document->zones[z].reach[r])) {
				ncfg_diag(ctx, ctx->zones_span,
				    "zone `%s` reaches `%s`, and no `zone \"%s\"` block declares it",
				    document->zones[z].name, document->zones[z].reach[r],
				    document->zones[z].reach[r]);
			}
		}
	}
	for (a = 0; a < document->interface_count; a++) {
		const char *zone = document->interfaces[a].zone;

		if (!zone) {
			continue;
		}
		any = 1;
		if (!zone_named(document, zone)) {
			ncfg_diag(ctx, ctx->zones_span,
			    "interface `%s` is in zone `%s`, and no `zone \"%s\"` block declares it",
			    document->interfaces[a].name, zone, zone);
		}
	}
	if (!any) {
		return;
	}
	if (!document->firewall) {
		ncfg_diag(ctx, ctx->zones_span,
		    "this host puts interfaces in zones and has no `firewall` block: a zone "
		    "compiles into the firewall's forward chain, so it needs one to compile into");
		return;
	}
	/*
	 * **The caps first, ahead of the written rules** (10.928): a forward
	 * chain almost always opens with `accept established`, which would let
	 * every download past a cap placed among the zone's rules -- and a cap
	 * grants nothing; it holds the zone's traffic whatever accepts it later,
	 * as a qdisc does. 0339's order is about which layer's permission
	 * decides, and a limit is not a permission.
	 */
	{
		ncfg_firewall_chain_t caps;

		memset(&caps, 0, sizeof(caps));
		for (z = 0; z < document->zone_count; z++) {
			const ncfg_zone_t *zone = &document->zones[z];
			int64_t            bits = 0;

			if (!zone->client_limit ||
			    !ncfg_lower_rate_bits(ctx, zone->client_limit, ctx->zones_span, &bits)) {
				continue;
			}
			for (a = 0; a < document->interface_count; a++) {
				const ncfg_interface_t *in = &document->interfaces[a];

				if (in->zone && strcmp(in->zone, zone->name) == 0) {
					(void)zone_cap(ctx, &caps, zone->name, in->name, bits / 8);
				}
			}
		}
		if (caps.rule_count) {
			ncfg_firewall_chain_t *forward = &document->firewall->forward;
			ncfg_firewall_rule_t  *joined = realloc(caps.rules,
			    (caps.rule_count + forward->rule_count) * sizeof(*joined));

			if (!joined) {
				ncfg_lower_oom(ctx);
				chain_free(&caps);
				return;
			}
			memcpy(joined + caps.rule_count, forward->rules,
			    forward->rule_count * sizeof(*joined));
			free(forward->rules);
			forward->rules = joined;
			forward->rule_count += caps.rule_count;
		} else {
			free(caps.rules);
		}
	}
	for (z = 0; z < document->zone_count; z++) {
		const ncfg_zone_t *zone = &document->zones[z];

		for (r = 0; r < zone->reach_count; r++) {
			for (a = 0; a < document->interface_count; a++) {
				const ncfg_interface_t *in = &document->interfaces[a];

				if (!in->zone || strcmp(in->zone, zone->name) != 0) {
					continue;
				}
				for (b = 0; b < document->interface_count; b++) {
					const ncfg_interface_t *out = &document->interfaces[b];
					char                    name[256];

					if (b == a || !out->zone || strcmp(out->zone, zone->reach[r]) != 0) {
						continue;
					}
					(void)snprintf(name, sizeof(name), "%s>%s:%s>%s", zone->name,
					    zone->reach[r], in->name, out->name);
					(void)zone_rule(ctx, &document->firewall->forward, name, in->name,
					    out->name, 0);
					(void)snprintf(name, sizeof(name), "%s>%s:%s<%s", zone->name,
					    zone->reach[r], out->name, in->name);
					(void)zone_rule(ctx, &document->firewall->forward, name, out->name,
					    in->name, 1);
				}
			}
		}
	}
}
