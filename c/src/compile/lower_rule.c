/*
 * lower_rule.c -- `rule`, `linkset` and `bluetooth`.
 *
 * Three small blocks that belong to no interface. A rule is host-wide because
 * rules are selected by priority across the whole system and two interfaces'
 * rules interleave by number; a linkset is a group of links that can stand in
 * for each other; a Bluetooth device is a block like a network, labelled by a
 * handle the operator chose and carrying the address as a fact.
 */
#include <stdlib.h>
#include <string.h>

#include "lower_internal.h"

#include "ncfg/base.h"
#include "ncfg/value.h"

/* ------------------------------------------------------------------------ *
 * rule
 * ------------------------------------------------------------------------ */

static void rule_free(ncfg_routing_rule_t *rule)
{
	free(rule->id);
	free(rule->from);
	free(rule->to);
	free(rule->iif);
	free(rule->oif);
	memset(rule, 0, sizeof(*rule));
}

/*
 * A selector that the kernel prints back as an address.
 *
 * Canonicalised for the same reason an interface address is: the plan compares
 * these against the kernel's own rendering, so `2001:0DB8::/32` was a rule torn
 * down and reinstalled on every apply, with a window in between where it did
 * not exist. Text that is not an address at all passes through untouched,
 * which is the Rust's `unwrap_or(text)` and is how a selector this build does
 * not understand still reaches the place that can say so.
 */
static char *rule_selector(ncfg_lower_ctx_t *ctx, const ncfg_ast_value_t *value)
{
	char *text = ncfg_as_string(ctx, value);
	char *canonical;

	if (!text) {
		return NULL;
	}
	canonical = ncfg_canonical_address(ctx, text);
	if (!canonical) {
		return text;
	}
	free(text);
	return canonical;
}

/*
 * The checks a rule has to pass to mean anything.
 *
 * Separate from the key parsing because they are a different question: the
 * loop asks "is this a key I know?", and this asks "does the result describe
 * something the kernel can be asked for?".
 */
static int rule_is_complete(ncfg_lower_ctx_t *ctx, const ncfg_routing_rule_t *rule,
    const char *label, int has_priority, int action_named, const ncfg_ast_block_t *block)
{
	/* Mandatory. The kernel will assign a priority, but an unnumbered rule
	 * lands wherever it puts one, two applies can produce different orders,
	 * and the document has stopped describing the system. */
	if (!has_priority) {
		ncfg_diag(ctx, block->span,
		    "rule `%s` has no `priority`: add `priority = N`; lower is consulted first, and "
		    "leaving it to the kernel means two applies can order the rules differently",
		    label);
		return 0;
	}
	/* A rule that looks nothing up and does nothing else is a rule that has no
	 * effect, and the most likely cause is a `lookup` somebody meant to
	 * write. */
	if (rule->action == NCFG_RULE_ACTION_LOOKUP && !rule->table.has) {
		ncfg_diag(ctx, block->span, "rule `%s` looks up no table and names no action: %s",
		    label, action_named
		        ? "`action = \"lookup\"` needs a `lookup = N`"
		        : "add `lookup = N`, or an `action` of blackhole, unreachable or prohibit");
		return 0;
	}
	/* A mask without a mark matches nothing in particular, and reads as though
	 * it does. */
	if (rule->fwmask.has && !rule->fwmark.has) {
		ncfg_diag(ctx, block->span, "rule `%s` has an `fwmask` but no `fwmark`", label);
		return 0;
	}
	return 1;
}

int ncfg_lower_rule(ncfg_lower_ctx_t *ctx, const ncfg_merged_block_t *merged,
    ncfg_routing_rule_t *out)
{
	const ncfg_ast_block_t *block = merged->block;
	ncfg_routing_rule_t     rule;
	ncfg_optint_t           priority;
	int                     action_named = 0;
	size_t                  i;

	memset(&rule, 0, sizeof(rule));
	memset(&priority, 0, sizeof(priority));
	/* The label is the handle. Rules are the one thing here the kernel
	 * identifies purely by number, and "rule 100 conflicts with rule 200"
	 * tells an operator nothing they did not already see. */
	rule.id = ncfg_require_label(ctx, block);
	if (!rule.id) {
		return 0;
	}
	rule.family = NCFG_RULE_FAMILY_INET;
	rule.action = NCFG_RULE_ACTION_LOOKUP;

	for (i = 0; i < merged->item_count; i++) {
		const ncfg_ast_item_t       *item = merged->items[i].item;
		const ncfg_ast_assignment_t *assignment;
		const char                  *key;
		int                          flag;

		ctx->source = merged->items[i].source;
		if (item->kind == NCFG_AST_ITEM_BLOCK) {
			ncfg_diag(ctx, item->as.block.span, "`%s` is not valid inside `rule`",
			    item->as.block.head);
			continue;
		}
		if (item->kind != NCFG_AST_ITEM_ASSIGNMENT) {
			continue;
		}
		assignment = &item->as.assignment;
		key = assignment->key;
		if (strcmp(key, "family") == 0) {
			char *name = ncfg_as_string(ctx, assignment->value);

			if (!name) {
				continue;
			}
			if (strcmp(name, "inet") == 0 || strcmp(name, "ipv4") == 0) {
				rule.family = NCFG_RULE_FAMILY_INET;
			} else if (strcmp(name, "inet6") == 0 || strcmp(name, "ipv6") == 0) {
				rule.family = NCFG_RULE_FAMILY_INET6;
			} else {
				ncfg_diag(ctx, assignment->span,
				    "`%s` is not an address family: one of inet, inet6", name);
			}
			free(name);
		} else if (strcmp(key, "priority") == 0) {
			ncfg_as_u32_opt(ctx, assignment->value, &priority);
		} else if (strcmp(key, "from") == 0) {
			free(rule.from);
			rule.from = rule_selector(ctx, assignment->value);
		} else if (strcmp(key, "to") == 0) {
			free(rule.to);
			rule.to = rule_selector(ctx, assignment->value);
		} else if (strcmp(key, "iif") == 0) {
			free(rule.iif);
			rule.iif = ncfg_as_interface_name(ctx, assignment->value);
		} else if (strcmp(key, "oif") == 0) {
			free(rule.oif);
			rule.oif = ncfg_as_interface_name(ctx, assignment->value);
		} else if (strcmp(key, "fwmark") == 0) {
			ncfg_as_u32_opt(ctx, assignment->value, &rule.fwmark);
		} else if (strcmp(key, "fwmask") == 0) {
			ncfg_as_u32_opt(ctx, assignment->value, &rule.fwmask);
		} else if (strcmp(key, "lookup") == 0 || strcmp(key, "table") == 0) {
			ncfg_as_u32_opt(ctx, assignment->value, &rule.table);
		} else if (strcmp(key, "suppress_prefixlength") == 0) {
			ncfg_as_u32_opt(ctx, assignment->value, &rule.suppress_prefixlength);
		} else if (strcmp(key, "l3mdev") == 0) {
			if (ncfg_as_bool(ctx, assignment->value, &flag)) {
				rule.l3mdev = flag;
			}
		} else if (strcmp(key, "action") == 0) {
			char              *name = ncfg_as_string(ctx, assignment->value);
			ncfg_rule_action_t action;

			if (!name) {
				continue;
			}
			action_named = 1;
			if (ncfg_rule_action_from_name(name, &action, NULL, 0)) {
				rule.action = (int)action;
			} else {
				ncfg_diag(ctx, assignment->span,
				    "`%s` is not a rule action: one of lookup, blackhole, unreachable, "
				    "prohibit", name);
			}
			free(name);
		} else {
			ncfg_diag(ctx, assignment->span, "unknown rule key `%s`", key);
		}
	}

	if (!rule_is_complete(ctx, &rule, rule.id, priority.has, action_named, block)) {
		rule_free(&rule);
		return 0;
	}
	rule.priority = priority.value;
	*out = rule;
	return 1;
}

/* ------------------------------------------------------------------------ *
 * linkset
 * ------------------------------------------------------------------------ */

/*
 * A `linkset` block.
 *
 * The whole block is a name and a list, which is the point: a set says which
 * links can stand in for each other and nothing else. What each member *is* --
 * an interface, a wifi network, another set -- is read off the rest of the
 * document rather than declared here, so moving a member from one kind to
 * another does not mean editing two places.
 */
int ncfg_lower_linkset(ncfg_lower_ctx_t *ctx, const ncfg_merged_block_t *merged,
    ncfg_linkset_t *out)
{
	const ncfg_ast_block_t *block = merged->block;
	ncfg_linkset_t          set;
	size_t                  i;

	memset(&set, 0, sizeof(set));
	set.name = ncfg_require_label(ctx, block);
	if (!set.name) {
		return 0;
	}

	for (i = 0; i < merged->item_count; i++) {
		const ncfg_ast_item_t       *item = merged->items[i].item;
		const ncfg_ast_assignment_t *assignment;

		ctx->source = merged->items[i].source;
		if (item->kind == NCFG_AST_ITEM_BLOCK) {
			ncfg_diag(ctx, item->as.block.span, "`%s` is not valid inside `linkset`",
			    item->as.block.head);
			continue;
		}
		if (item->kind != NCFG_AST_ITEM_ASSIGNMENT) {
			continue;
		}
		assignment = &item->as.assignment;
		/* `members`, the same word a bridge and a bond use for the same idea.
		 * A second spelling was written first and removed: one key with two
		 * names is two things to document and nothing an operator gains. */
		if (strcmp(assignment->key, "members") == 0) {
			ncfg_words_t words;
			size_t       at;

			if (!ncfg_as_words(ctx, assignment->value, &words)) {
				ncfg_words_free(&words);
				continue;
			}
			for (at = 0; at < words.count; at++) {
				/* **Said twice in one set is refused rather than
				 * deduplicated.** The order is the ranking, so a name in two
				 * places has two different meanings and neither is obviously
				 * the intended one. */
				if (ncfg_has_string(set.members, set.member_count, words.at[at].text)) {
					ncfg_diag(ctx, words.at[at].span,
					    "`%s` is listed twice in `%s`: the order of the list is the "
					    "ranking, so a member can only be in one place in it",
					    words.at[at].text, set.name);
					continue;
				}
				(void)ncfg_push_string(ctx, &set.members, &set.member_count,
				    words.at[at].text);
			}
			ncfg_words_free(&words);
		} else {
			ncfg_diag(ctx, assignment->span,
			    "`%s` is not a `linkset` setting: a linkset has `members` and nothing else",
			    assignment->key);
		}
	}

	*out = set;
	return 1;
}

/* ------------------------------------------------------------------------ *
 * bluetooth
 * ------------------------------------------------------------------------ */

/*
 * A `bluetooth "handle" { ... }` block (0149).
 *
 * Labelled by a handle the operator chose, carrying the address as a fact. The
 * label is what `ncfg` prints and what the drop-in is named after; replacing
 * the hardware means changing one line rather than everything that refers to
 * it.
 */
int ncfg_lower_bluetooth(ncfg_lower_ctx_t *ctx, const ncfg_merged_block_t *merged,
    ncfg_bluetooth_device_t *out)
{
	const ncfg_ast_block_t *block = merged->block;
	ncfg_bluetooth_device_t device;
	int                     profile_seen = 0;
	size_t                  i;

	memset(&device, 0, sizeof(device));
	device.id = ncfg_require_label(ctx, block);
	if (!device.id) {
		return 0;
	}
	/* True unless said otherwise, which is `network`'s rule: a device somebody
	 * wrote down is one they want used. */
	device.autoconnect = 1;

	for (i = 0; i < merged->item_count; i++) {
		const ncfg_ast_item_t       *item = merged->items[i].item;
		const ncfg_ast_assignment_t *assignment;
		const char                  *key;
		int                          flag;

		ctx->source = merged->items[i].source;
		if (item->kind == NCFG_AST_ITEM_BLOCK) {
			ncfg_diag(ctx, item->as.block.span,
			    "unknown bluetooth key `%s`: a bluetooth block holds address, profile and "
			    "autoconnect", item->as.block.head);
			continue;
		}
		if (item->kind != NCFG_AST_ITEM_ASSIGNMENT) {
			continue;
		}
		assignment = &item->as.assignment;
		key = assignment->key;
		if (strcmp(key, "address") == 0) {
			char *text = ncfg_as_string(ctx, assignment->value);
			char  normal[NCFG_HARDWARE_ADDRESS_MAX];

			if (!text) {
				continue;
			}
			/* `value.h`'s strict reader, which is the language's: six
			 * colon-separated hex octets, uppercased because BlueZ prints
			 * uppercase and the same address in two cases is two strings to
			 * every diff and duplicate check downstream. */
			if (!ncfg_hardware_address_strict(text, normal, sizeof(normal), NULL, 0)) {
				ncfg_diag(ctx, assignment->span,
				    "`%s` is not a Bluetooth address: six colon-separated hex octets, "
				    "`AA:BB:CC:DD:EE:FF`", text);
			} else {
				free(device.address);
				device.address = ncfg_dup(ctx, normal);
			}
			free(text);
		} else if (strcmp(key, "profile") == 0) {
			char                    *text = ncfg_as_string(ctx, assignment->value);
			ncfg_bluetooth_profile_t profile;

			if (!text) {
				continue;
			}
			if (ncfg_bluetooth_profile_from_name(text, &profile, NULL, 0)) {
				device.profile = (int)profile;
				profile_seen = 1;
			} else {
				ncfg_diag(ctx, assignment->span,
				    "`%s` is not a Bluetooth profile: one of a2dp-sink, a2dp-source, hfp, "
				    "pan, nap", text);
			}
			free(text);
		} else if (strcmp(key, "autoconnect") == 0) {
			if (ncfg_as_bool(ctx, assignment->value, &flag)) {
				device.autoconnect = flag;
			}
		} else {
			ncfg_diag(ctx, assignment->span,
			    "unknown bluetooth key `%s`: address, profile or autoconnect", key);
		}
	}

	/* Both are required and neither has a defensible default: an address
	 * netcfgd invented would name somebody else's hardware, and a profile it
	 * guessed would decide whether the device carries audio or packets. */
	if (!device.address) {
		ncfg_diag(ctx, block->span,
		    "`bluetooth %s` names no address: `address = \"AA:BB:CC:DD:EE:FF\"`", device.id);
		goto refused;
	}
	if (!profile_seen) {
		ncfg_diag(ctx, block->span,
		    "`bluetooth %s` names no profile: one of a2dp-sink, a2dp-source, hfp, pan, nap",
		    device.id);
		goto refused;
	}
	*out = device;
	return 1;

refused:
	free(device.id);
	free(device.address);
	return 0;
}
