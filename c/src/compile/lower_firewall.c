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

#include "ncfg/base.h"

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
	ncfg_strings_free(rule->from, rule->from_count);
	ncfg_strings_free(rule->to, rule->to_count);
	free(rule->interface);
	ncfg_strings_free(rule->states, rule->state_count);
	ncfg_strings_free(rule->mac, rule->mac_count);
	ncfg_strings_free(rule->mac_lists, rule->mac_list_count);
	ncfg_strings_free(rule->mac_written, rule->mac_written_count);
	memset(rule, 0, sizeof(*rule));
}

static void chain_free(ncfg_firewall_chain_t *chain)
{
	size_t i;

	for (i = 0; i < chain->rule_count; i++) {
		rule_free(&chain->rules[i]);
	}
	free(chain->rules);
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
	} else {
		ncfg_diag(ctx, assignment->span,
		    "`%s` is not a protocol netcfgd matches: one of any, tcp, udp, icmp, icmpv6 "
		    "(0294 names the whole set, and widening it is a decision)", word);
	}
	free(word);
}

/*
 * One port, or a list of them.
 *
 * A single number is accepted as well as a list, for the reason `addressing`
 * accepts a string or a list: a rule for one port is the common case and
 * `port = 22` is what somebody writes.
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

		if (entries[i]->kind != NCFG_AST_NUMBER) {
			ncfg_diag(ctx, entries[i]->span,
			    "a port is a number, found %s", ncfg_ast_value_describe(entries[i]));
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
	ncfg_firewall_rule_t rule;
	size_t               i;

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
		} else if (strcmp(key, "state") == 0) {
			rule_states(ctx, assignment, &rule);
		} else if (strcmp(key, "mac") == 0) {
			rule_macs(ctx, assignment, &rule);
		} else {
			ncfg_diag(ctx, assignment->span,
			    "`%s` is not a firewall rule key: one of protocol, port, from, to, "
			    "interface, state, mac", key);
		}
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
	 * for refusing here. `any` is included: a port means tcp or udp, and a
	 * rule that does not say which is a rule whose author has not decided.
	 */
	if (rule.port_count > 0 && rule.protocol != NCFG_FIREWALL_PROTO_TCP &&
	    rule.protocol != NCFG_FIREWALL_PROTO_UDP) {
		ncfg_diag(ctx, block->span,
		    "rule `%s` matches ports with no protocol that has them: add "
		    "`protocol = \"tcp\"` or `\"udp\"`", rule.name);
		rule_free(&rule);
		return 0;
	}
	*out = rule;
	return 1;
}

/* One chain: a policy and the rules under it, in the order they were written.
 * Never sorted -- nftables evaluates a chain in order, so the order is the
 * policy, and `ssh` before `netbios` accepts what the later rule drops. */
static int lower_chain(ncfg_lower_ctx_t *ctx, const ncfg_ast_block_t *block,
    const char *chain_name, ncfg_firewall_chain_t *out)
{
	ncfg_firewall_chain_t chain;
	int                   policy_named = 0;
	size_t                i;

	memset(&chain, 0, sizeof(chain));
	chain.policy = NCFG_FIREWALL_POLICY_ACCEPT;

	for (i = 0; i < block->items.count; i++) {
		const ncfg_ast_item_t *item = block->items.at[i];

		if (item->kind == NCFG_AST_ITEM_ASSIGNMENT) {
			if (strcmp(item->as.assignment.key, "policy") == 0) {
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
		{
			ncfg_firewall_rule_t rule;
			int                  action = 0;
			size_t               at;

			if (!rule_action(item->as.block.head, &action)) {
				ncfg_diag(ctx, item->as.block.span,
				    "`%s` is not a firewall action: a rule is `accept`, `drop` or "
				    "`reject`, each with a name", item->as.block.head);
				continue;
			}
			if (!lower_rule(ctx, &item->as.block, action, &rule)) {
				continue;
			}
			/* A packet this host sends has no sending station yet: its link
			 * header is built after the output hook, so `ether saddr` there
			 * would compile into a rule that never matches. */
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
	if (!policy_named) {
		ncfg_diag(ctx, block->span,
		    "chain `%s` has no `policy`: say `policy = \"accept\"` or `\"drop\"`, since "
		    "the two are opposite answers for every packet no rule matched", chain_name);
		chain_free(&chain);
		return 0;
	}
	*out = chain;
	return 1;
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
		if (item->kind == NCFG_AST_ITEM_ASSIGNMENT) {
			ncfg_diag(ctx, item->as.assignment.span,
			    "`%s` is not valid directly inside `firewall`: the chains are "
			    "`input`, `forward` and `output`, and the keys go in them",
			    item->as.assignment.key);
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
			(void)lower_chain(ctx, &item->as.block, head, target);
		}
	}
	ctx->document->firewall = firewall;
}
