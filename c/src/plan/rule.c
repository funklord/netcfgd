/*
 * rule.c -- policy routing rules, which are the host's and not an interface's.
 *
 * WHY A RULE NAMES NO INTERFACE
 *   `iif` and `oif` are selectors rather than ownership, and rules are
 *   ordered by priority across the whole system -- two interfaces' rules
 *   interleave by number. So these are pushed as root actions: nothing gates
 *   them on a link's creation, and `ncfg_op_interface` deliberately answers
 *   NULL for them, which is what stops a guard on one uplink refusing a change
 *   to the table every uplink consults.
 *
 * THE KEY IS THE PRIORITY, AND THAT IS WHY A DELETE COMES FIRST
 *   The kernel keys a rule on `(family, priority)`, so adding a second rule at
 *   a priority already taken answers `EEXIST`. A rule at the wanted priority
 *   that is not the wanted rule therefore has to go before the new one
 *   arrives -- and only where it is netcfgd's to remove. Otherwise the plan
 *   says so and changes nothing, which is what `ncfg_ownership_may_remove` is
 *   for: nothing foreign is ever removed, and that property outranks
 *   converging on the document.
 *
 * EVERY SELECTOR, NOT JUST THE KEY
 *   Two rules at one priority that differ in `from` are different rules.
 *   Treating them as equal is how a changed selector silently never takes
 *   effect -- the plan reports nothing to do and the kernel goes on consulting
 *   the old table for the old set of packets.
 */
#include "plan_internal.h"

#include "ncfg/base.h"

#include <string.h>

/* ------------------------------------------------------------------------ *
 * Comparing
 * ------------------------------------------------------------------------ */

/*
 * Whether two optional selectors are the same selector.
 *
 * The addresses go through `ncfg_plan_address_equal` rather than `strcmp`,
 * which the Rust does not do: the compiler canonicalises what the document
 * says, so the two spellings agree for a document that came through it -- and
 * a rule reaching the planner some other way is exactly the case 10.169
 * records, where one value written twice reads as two and the rule is torn
 * down and reinstalled on every apply.
 */
static int same_address(const char *left, const char *right)
{
	if (!left || !right) {
		return left == right;
	}
	return ncfg_plan_address_equal(left, right);
}

static int same_text(const char *left, const char *right)
{
	if (!left || !right) {
		return left == right;
	}
	return strcmp(left, right) == 0;
}

static int same_number(ncfg_optint_t left, ncfg_optint_t right)
{
	return left.has == right.has && (!left.has || left.value == right.value);
}

/* Whether a desired rule and an observed one are the same rule. */
static int same_rule(const ncfg_routing_rule_t *desired, const ncfg_observed_rule_t *observed)
{
	return same_address(desired->from, observed->from) &&
	    same_address(desired->to, observed->to) &&
	    same_text(desired->iif, observed->iif) && same_text(desired->oif, observed->oif) &&
	    same_number(desired->fwmark, observed->fwmark) &&
	    same_number(desired->fwmask, observed->fwmask) &&
	    desired->action == observed->action &&
	    same_number(desired->suppress_prefixlength, observed->suppress_prefixlength) &&
	    desired->l3mdev == observed->l3mdev && desired->invert == observed->invert &&
	    /* A lookup names a table; the other actions do not, and the kernel
	     * reports nothing for them whatever the document says. */
	    (desired->action != NCFG_RULE_ACTION_LOOKUP ||
	    same_number(desired->table, observed->table));
}

/*
 * An observed rule as a desired one, owned by the plan.
 *
 * The `id` is netcfgd's handle and has no kernel counterpart, so a rule that
 * came back from a dump gets one describing where it came from rather than a
 * fabricated name that might collide with a real one.
 */
static const ncfg_routing_rule_t *to_desired(ncfg_plan_t *plan,
    const ncfg_observed_rule_t *observed)
{
	ncfg_routing_rule_t rule;

	memset(&rule, 0, sizeof(rule));
	rule.id = (char *)(uintptr_t)ncfg_plan_internf(plan, "observed-%s-%lld",
	    ncfg_rule_family_name((ncfg_rule_family_t)observed->family),
	    (long long)observed->priority);
	rule.priority = observed->priority;
	rule.family = observed->family;
	rule.from = observed->from;
	rule.to = observed->to;
	rule.iif = observed->iif;
	rule.oif = observed->oif;
	rule.fwmark = observed->fwmark;
	rule.fwmask = observed->fwmask;
	rule.table = observed->table;
	rule.action = observed->action;
	rule.suppress_prefixlength = observed->suppress_prefixlength;
	rule.l3mdev = observed->l3mdev;
	rule.invert = observed->invert;
	return ncfg_plan_intern_rule(plan, &rule);
}

/* One rule, for a plan line: `100 from 192.0.2.0/24 iif eth0 lookup 200`. */
static const char *describe(ncfg_plan_t *plan, const ncfg_routing_rule_t *rule)
{
	ncfg_buf_t  buf;
	const char *text;
	size_t      i;
	struct {
		const char *label;
		const char *value;
	} selectors[4];

	selectors[0].label = "from";
	selectors[0].value = rule->from;
	selectors[1].label = "to";
	selectors[1].value = rule->to;
	selectors[2].label = "iif";
	selectors[2].value = rule->iif;
	selectors[3].label = "oif";
	selectors[3].value = rule->oif;

	ncfg_buf_init(&buf, 0);
	ncfg_buf_addf(&buf, "%lld ", (long long)rule->priority);
	for (i = 0; i < sizeof(selectors) / sizeof(selectors[0]); i++) {
		if (selectors[i].value) {
			ncfg_buf_addf(&buf, "%s %s ", selectors[i].label, selectors[i].value);
		}
	}
	if (rule->fwmark.has) {
		ncfg_buf_addf(&buf, "fwmark %#llx ", (unsigned long long)rule->fwmark.value);
	}
	ncfg_buf_add_text(&buf, ncfg_rule_action_name((ncfg_rule_action_t)rule->action));
	if (rule->table.has) {
		ncfg_buf_addf(&buf, " %lld", (long long)rule->table.value);
	}
	text = ncfg_plan_intern(plan, ncfg_buf_text(&buf));
	ncfg_buf_free(&buf);
	return text ? text : "<absent>";
}

/* ------------------------------------------------------------------------ *
 * The pass
 * ------------------------------------------------------------------------ */

static void push_rule(ncfg_builder_t *builder, int kind, const ncfg_routing_rule_t *rule,
    const ncfg_reason_t *reason, int inverse_kind, const ncfg_routing_rule_t *inverse_rule)
{
	ncfg_op_t op;
	ncfg_op_t inverse;

	memset(&op, 0, sizeof(op));
	op.kind = kind;
	op.u.rule.rule = rule;
	if (!inverse_rule) {
		(void)ncfg_builder_push(builder, &op, reason, NULL, 0, NULL);
		return;
	}
	memset(&inverse, 0, sizeof(inverse));
	inverse.kind = inverse_kind;
	inverse.u.rule.rule = inverse_rule;
	(void)ncfg_builder_push(builder, &op, reason, NULL, 0, &inverse);
}

void ncfg_plan_rules(ncfg_builder_t *builder)
{
	const ncfg_document_t *desired = builder->desired;
	const ncfg_observed_t *observed = builder->observed;
	ncfg_reason_t          reason;
	size_t                 i;
	size_t                 j;

	for (i = 0; i < desired->rule_count; i++) {
		const ncfg_routing_rule_t  *rule = &desired->rules[i];
		const ncfg_observed_rule_t *current = NULL;

		for (j = 0; j < observed->rule_count; j++) {
			if (observed->rules[j].family == rule->family &&
			    observed->rules[j].priority == rule->priority) {
				current = &observed->rules[j];
				break;
			}
		}
		if (current && same_rule(rule, current)) {
			continue;
		}
		if (current && !ncfg_ownership_may_remove(current->ownership)) {
			ncfg_plan_warnf(builder->plan, NULL,
			    "rule `%s` wants priority %lld in %s, and a rule netcfgd does not own "
			    "is already there. Renumber it, or remove the other by hand.",
			    rule->id, (long long)rule->priority,
			    ncfg_rule_family_name((ncfg_rule_family_t)rule->family));
			continue;
		}
		if (current) {
			memset(&reason, 0, sizeof(reason));
			reason.field = ncfg_plan_internf(builder->plan, "rules.%s", rule->id);
			reason.desired = describe(builder->plan, rule);
			reason.observed = "a different rule at this priority";
			push_rule(builder, NCFG_OP_RULE_DEL,
			    to_desired(builder->plan, current), &reason, 0, NULL);
		}
		memset(&reason, 0, sizeof(reason));
		reason.field = ncfg_plan_internf(builder->plan, "rules.%s", rule->id);
		reason.desired = describe(builder->plan, rule);
		reason.observed = current ? "a different rule at this priority" : "<absent>";
		/* The document's own rule, borrowed rather than copied, which is what
		 * `plan.h` names as one of the four. */
		push_rule(builder, NCFG_OP_RULE_ADD, rule, &reason, NCFG_OP_RULE_DEL, rule);
	}

	/* And anything of netcfgd's the document no longer asks for. */
	for (j = 0; j < observed->rule_count; j++) {
		const ncfg_observed_rule_t *held = &observed->rules[j];
		const ncfg_routing_rule_t  *rule;
		int                         asked = 0;

		if (!ncfg_ownership_may_remove(held->ownership)) {
			continue;
		}
		for (i = 0; i < desired->rule_count; i++) {
			if (desired->rules[i].family == held->family &&
			    desired->rules[i].priority == held->priority) {
				asked = 1;
				break;
			}
		}
		if (asked) {
			continue;
		}
		rule = to_desired(builder->plan, held);
		if (!rule) {
			return;
		}
		memset(&reason, 0, sizeof(reason));
		reason.field = "rules";
		reason.desired = "<absent>";
		reason.observed = describe(builder->plan, rule);
		push_rule(builder, NCFG_OP_RULE_DEL, rule, &reason, NCFG_OP_RULE_ADD, rule);
	}
}
