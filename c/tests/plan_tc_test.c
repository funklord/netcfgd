/*
 * plan_tc_test.c -- the driver offloads, the policy routing rules, the root
 * qdisc and the ingress redirect.
 *
 * WHAT THESE ARE FOR
 *   Three passes that share one property and one hazard. The property is that
 *   each is always a comparison against something rather than an install where
 *   absent -- every interface always has a qdisc, and a rule at a taken
 *   priority answers `EEXIST` rather than arriving beside the old one. The
 *   hazard is ownership: a qdisc and a redirect carry no owner, so `qdisc_
 *   applied` and `ingress_applied` are the only thing standing between "the
 *   document stopped asking" and netcfgd undoing somebody else's `tc`.
 *
 *   Every one of them has an idempotence case, for `plan.h`'s reason: a
 *   comparison that is wrong in that direction plans the same action on every
 *   reconcile for ever, and the qdisc one is the shape `qdisc.sh` has been
 *   chasing in a container for four sessions.
 */
#include "planfix.h"

#include <stdio.h>

static int failures;
static int checks;

static void check(int condition, const char *what)
{
	checks++;
	printf("%-72s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

static ncfg_plan_t *one(const char *device, const char *observation,
    ncfg_document_t **document, ncfg_observed_t **observed)
{
	return planfix_plan(device, "", "", "", observation, document, observed);
}

static int quiet(const ncfg_plan_t *plan)
{
	char names[512];

	if (ncfg_plan_is_empty(plan)) {
		return 1;
	}
	planfix_names(plan, names, sizeof(names));
	printf("  expected nothing to do; the plan is [%s]\n", names);
	return 0;
}

/* Whether a `link.set_offloads` sets this feature to this state. */
static int sets(const ncfg_action_t *action, const char *name, int on)
{
	size_t i;

	if (!action) {
		return 0;
	}
	for (i = 0; i < action->op.u.set_offloads.feature_count; i++) {
		if (strcmp(action->op.u.set_offloads.features[i].name, name) == 0) {
			return action->op.u.set_offloads.features[i].wanted == on;
		}
	}
	return 0;
}

/* ------------------------------------------------------------------------ *
 * The offloads
 * ------------------------------------------------------------------------ */

#define ETHTOOL_DEVICE(body) \
	"{\"name\":\"eth0\",\"kind\":{\"kind\":\"physical\"},\"link_settings\":{" body "}}"

static void an_offload_the_driver_has_off_is_turned_on(void)
{
	ncfg_document_t     *document;
	ncfg_observed_t     *observed;
	ncfg_plan_t         *plan = one(ETHTOOL_DEVICE("\"gro\":\"on\""),
	    "\"links\":[" PLANFIX_LINK("eth0", ",\"offloads\":[]") "]", &document, &observed);
	const ncfg_action_t *action = plan ? planfix_action(plan, "link.set_offloads") : NULL;

	check(sets(action, "rx-gro", 1), "an offload the driver has off is turned on");
	check(action && action->has_inverse &&
	    action->inverse.u.set_offloads.feature_count == 1u &&
	    !action->inverse.u.set_offloads.features[0].wanted,
	    "and the inverse puts it back to what the kernel reported");
	planfix_release(plan, document, observed);
}

/*
 * One model field is several kernel features, because a driver offers
 * whichever its hardware has. "On" means any of them and "off" means all of
 * them, which is what `ethtool -K dev tx on|off` does.
 */
static void one_model_field_covers_every_spelling_a_driver_may_have(void)
{
	ncfg_document_t     *document;
	ncfg_observed_t     *observed;
	ncfg_plan_t         *plan = one(ETHTOOL_DEVICE("\"tx_checksum\":\"off\""),
	    "\"links\":[" PLANFIX_LINK("eth0", ",\"offloads\":[\"tx-checksum-ipv4\"]") "]",
	    &document, &observed);
	const ncfg_action_t *action = plan ? planfix_action(plan, "link.set_offloads") : NULL;

	check(action && action->op.u.set_offloads.feature_count == 3u,
	    "turning transmit checksumming off turns off all three of its spellings");
	check(sets(action, "tx-checksum-ip-generic", 0) && sets(action, "tx-checksum-ipv4", 0) &&
	    sets(action, "tx-checksum-ipv6", 0), "and each of them by name");
	planfix_release(plan, document, observed);

	plan = one(ETHTOOL_DEVICE("\"tx_checksum\":\"on\""),
	    "\"links\":[" PLANFIX_LINK("eth0", ",\"offloads\":[\"tx-checksum-ipv4\"]") "]",
	    &document, &observed);
	check(plan && quiet(plan), "and one of the three being on is enough for `on`");
	planfix_release(plan, document, observed);
}

/*
 * The link may not exist yet: this is the first apply and the device is about
 * to be created. Skipping instead is what made a fresh apply leave the
 * offloads at the driver default and need a second run.
 */
static void a_link_that_does_not_exist_yet_still_gets_its_offloads(void)
{
	ncfg_document_t     *document;
	ncfg_observed_t     *observed;
	ncfg_plan_t         *plan = one(
	    "{\"name\":\"br0\",\"kind\":{\"kind\":\"bridge\",\"members\":[],\"stp\":false},"
	    "\"link_settings\":{\"gro\":\"on\"}}", "\"links\":[]", &document, &observed);
	const ncfg_action_t *create = plan ? planfix_action(plan, "link.create") : NULL;
	const ncfg_action_t *action = plan ? planfix_action(plan, "link.set_offloads") : NULL;

	check(sets(action, "rx-gro", 1), "a link this plan is about to create gets its offloads");
	check(create && action && planfix_depends_on(action, create->id),
	    "and the action waits for the creation");
	planfix_release(plan, document, observed);
}

/*
 * The half of an `ethtool` block that needs a physical NIC is named field by
 * field rather than as one blanket sentence -- an operator who set only `gro`
 * should not be told their configuration is ignored.
 *
 * **One field, so the sentence has to agree with itself about number.** It
 * used to say "are recognised" of a single one, which read as a list where
 * there was none; whose gap that half is, and that the whole of the longest
 * form fits, is `plan_gaps_test.c`'s.
 */
static void only_the_unapplied_ethtool_fields_are_named(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = one(ETHTOOL_DEVICE("\"gro\":\"on\",\"wol\":\"g\""),
	    "\"links\":[" PLANFIX_LINK("eth0", ",\"offloads\":[]") "]", &document, &observed);

	check(plan && planfix_warned(plan,
	    "`wol` in the `ethtool` block is recognised and applied by nothing: it can"),
	    "a field that needs a physical NIC is named, in the singular it was written in");
	check(plan && !planfix_warned(plan, "`gro`"),
	    "and the offload beside it, which is applied, is not");
	planfix_release(plan, document, observed);

	plan = one(ETHTOOL_DEVICE("\"gro\":\"on\""),
	    "\"links\":[" PLANFIX_LINK("eth0", ",\"offloads\":[]") "]", &document, &observed);
	check(plan && !planfix_warned(plan, "`ethtool` block"),
	    "and a block naming only offloads says nothing at all");
	planfix_release(plan, document, observed);
}

static void offloads_that_already_agree_plan_nothing(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = one(ETHTOOL_DEVICE("\"gro\":\"on\",\"tso\":\"off\""),
	    "\"links\":[" PLANFIX_LINK("eth0", ",\"offloads\":[\"rx-gro\"]") "]",
	    &document, &observed);

	check(plan && quiet(plan), "offloads that already agree with the driver plan nothing");
	planfix_release(plan, document, observed);
}

/* ------------------------------------------------------------------------ *
 * Policy routing rules
 * ------------------------------------------------------------------------ */

#define RULE(id, body) "{\"id\":\"" id "\",\"priority\":100,\"family\":\"inet\"," body "}"
#define SEEN_RULE(body) "{\"priority\":100,\"family\":\"inet\"," body "}"

static ncfg_plan_t *rules(const char *document_rules, const char *observed_rules,
    ncfg_document_t **document, ncfg_observed_t **observed)
{
	char extra[1024];
	char observation[1024];

	(void)snprintf(extra, sizeof(extra), ",\"rules\":[%s]", document_rules);
	(void)snprintf(observation, sizeof(observation), "\"rules\":[%s]", observed_rules);
	return planfix_plan("", "", "", extra, observation, document, observed);
}

static void a_rule_the_kernel_does_not_have_is_added(void)
{
	ncfg_document_t     *document;
	ncfg_observed_t     *observed;
	ncfg_plan_t         *plan = rules(
	    RULE("vpn", "\"from\":\"192.0.2.0/24\",\"table\":42,\"action\":\"lookup\""), "",
	    &document, &observed);
	const ncfg_action_t *action = plan ? planfix_action(plan, "rule.add") : NULL;

	check(action != NULL, "a rule the kernel does not have is added");
	check(action && action->reason.desired && strstr(action->reason.desired, "lookup 42"),
	    "and the reason describes it the way `ip rule` reads");
	check(action && action->has_inverse, "and it can be taken back again");
	planfix_release(plan, document, observed);
}

/*
 * The kernel keys on the priority, so a different rule at the wanted priority
 * has to go before the new one arrives -- adding would answer `EEXIST`.
 */
static void a_different_rule_at_the_same_priority_goes_first(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = rules(
	    RULE("vpn", "\"from\":\"192.0.2.0/24\",\"table\":42,\"action\":\"lookup\""),
	    SEEN_RULE("\"from\":\"198.51.100.0/24\",\"table\":42,\"action\":\"lookup\","
	    "\"ownership\":\"ours\""), &document, &observed);
	char             names[256];

	if (plan) {
		planfix_names(plan, names, sizeof(names));
	}
	check(plan && strcmp(names, "rule.del,rule.add") == 0,
	    "a different rule at the same priority is removed before the new one arrives");
	planfix_release(plan, document, observed);
}

/* Nothing foreign is ever removed, and that property outranks converging on
 * the document: the plan says so and changes nothing. */
static void a_rule_netcfgd_does_not_own_is_reported_and_left(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = rules(
	    RULE("vpn", "\"from\":\"192.0.2.0/24\",\"table\":42,\"action\":\"lookup\""),
	    SEEN_RULE("\"from\":\"198.51.100.0/24\",\"table\":42,\"action\":\"lookup\","
	    "\"ownership\":\"foreign\""), &document, &observed);

	check(plan && planfix_warned(plan, "a rule netcfgd does not own is already there"),
	    "a foreign rule at the wanted priority is reported");
	check(plan && ncfg_plan_is_empty(plan), "and nothing at all is planned against it");
	planfix_release(plan, document, observed);
}

static void a_rule_of_netcfgds_the_document_dropped_is_removed(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = rules("",
	    SEEN_RULE("\"from\":\"192.0.2.0/24\",\"table\":42,\"action\":\"lookup\","
	    "\"ownership\":\"ours\""), &document, &observed);

	check(plan && planfix_action(plan, "rule.del"),
	    "a rule of netcfgd's the document no longer asks for is removed");
	planfix_release(plan, document, observed);

	plan = rules("", SEEN_RULE("\"table\":42,\"action\":\"lookup\","
	    "\"ownership\":\"unknown\""), &document, &observed);
	check(plan && !planfix_action(plan, "rule.del"),
	    "and one whose ownership is unknown is left where it is");
	planfix_release(plan, document, observed);
}

/*
 * Every selector, not just the key. Two rules at one priority that differ in
 * `from` are different rules, and treating them as equal is how a changed
 * selector silently never takes effect.
 */
static void a_rule_that_agrees_is_left_alone_and_a_changed_selector_is_not(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = rules(
	    RULE("vpn", "\"from\":\"192.0.2.0/24\",\"iif\":\"eth0\",\"table\":42,"
	    "\"action\":\"lookup\""),
	    SEEN_RULE("\"from\":\"192.0.2.0/24\",\"iif\":\"eth0\",\"table\":42,"
	    "\"action\":\"lookup\",\"ownership\":\"ours\""), &document, &observed);

	check(plan && quiet(plan), "a rule that is already the one asked for plans nothing");
	planfix_release(plan, document, observed);

	plan = rules(
	    RULE("vpn", "\"from\":\"192.0.2.0/24\",\"iif\":\"eth1\",\"table\":42,"
	    "\"action\":\"lookup\""),
	    SEEN_RULE("\"from\":\"192.0.2.0/24\",\"iif\":\"eth0\",\"table\":42,"
	    "\"action\":\"lookup\",\"ownership\":\"ours\""), &document, &observed);
	check(plan && planfix_action(plan, "rule.add"),
	    "and a rule whose selector moved is noticed rather than counted the same");
	planfix_release(plan, document, observed);
}

/*
 * A selector written in another spelling of the same prefix.
 *
 * The compiler canonicalises what a document says, so this is the case of a
 * rule reaching the planner some other way -- and 10.169 is what comparing the
 * two as text costs: the rule is torn down and reinstalled on every apply.
 */
static void a_selector_is_compared_as_an_address_and_not_as_text(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = rules(
	    "{\"id\":\"v6\",\"priority\":100,\"family\":\"inet6\","
	    "\"from\":\"2001:0DB8:0000::/32\",\"table\":42,\"action\":\"lookup\"}",
	    "{\"priority\":100,\"family\":\"inet6\",\"from\":\"2001:db8::/32\","
	    "\"table\":42,\"action\":\"lookup\",\"ownership\":\"ours\"}",
	    &document, &observed);

	check(plan && quiet(plan),
	    "two spellings of one prefix are one selector, so a second plan is empty");
	planfix_release(plan, document, observed);
}

/* ------------------------------------------------------------------------ *
 * The root qdisc
 * ------------------------------------------------------------------------ */

#define QDISC_DEVICE(body) \
	"{\"name\":\"eth0\",\"kind\":{\"kind\":\"physical\"},\"qdisc\":{" body "}}"

static void the_kind_and_the_rate_are_both_part_of_the_comparison(void)
{
	ncfg_document_t     *document;
	ncfg_observed_t     *observed;
	ncfg_plan_t         *plan = one(QDISC_DEVICE("\"kind\":\"cake\",\"ingress\":false"),
	    "\"links\":[" PLANFIX_LINK("eth0", ",\"qdisc\":\"fq_codel\"") "]",
	    &document, &observed);

	check(plan && planfix_action(plan, "qdisc.set"), "a qdisc of the wrong kind is replaced");
	planfix_release(plan, document, observed);

	plan = one(QDISC_DEVICE("\"kind\":\"cake\",\"bandwidth_bits\":20000000,"
	    "\"ingress\":false"),
	    "\"links\":[" PLANFIX_LINK("eth0",
	    ",\"qdisc\":\"cake\",\"qdisc_bandwidth_bits\":50000000") "]", &document, &observed);
	check(plan && planfix_action(plan, "qdisc.set"),
	    "and one of the right kind at somebody else's rate is too");
	planfix_release(plan, document, observed);

	plan = one(QDISC_DEVICE("\"kind\":\"cake\",\"bandwidth_bits\":20000000,"
	    "\"ingress\":false"),
	    "\"links\":[" PLANFIX_LINK("eth0",
	    ",\"qdisc\":\"cake\",\"qdisc_bandwidth_bits\":20000000") "]", &document, &observed);
	check(plan && quiet(plan), "while a qdisc that already agrees plans nothing");
	planfix_release(plan, document, observed);
}

/*
 * Stopped asking. The kernel default goes back, but only where netcfgd is what
 * moved it: an interface already running `cake` when netcfgd first started is
 * not netcfgd's to reset.
 */
static void a_qdisc_is_only_reset_where_netcfgd_is_what_moved_it(void)
{
	ncfg_document_t     *document;
	ncfg_observed_t     *observed;
	ncfg_plan_t         *plan = one("{\"name\":\"eth0\",\"kind\":{\"kind\":\"physical\"}}",
	    "\"links\":[" PLANFIX_LINK("eth0", ",\"qdisc\":\"cake\"") "],"
	    "\"qdisc_applied\":[\"eth0\"]", &document, &observed);
	const ncfg_action_t *action = plan ? planfix_action(plan, "qdisc.reset") : NULL;

	check(action != NULL, "a qdisc netcfgd installed is put back when the document stops");
	check(action && action->has_inverse &&
	    action->inverse.u.qdisc.kind && strcmp(action->inverse.u.qdisc.kind, "cake") == 0,
	    "and the inverse restores exactly what was observed");
	planfix_release(plan, document, observed);

	plan = one("{\"name\":\"eth0\",\"kind\":{\"kind\":\"physical\"}}",
	    "\"links\":[" PLANFIX_LINK("eth0", ",\"qdisc\":\"cake\"") "]",
	    &document, &observed);
	check(plan && !planfix_action(plan, "qdisc.reset"),
	    "and a qdisc somebody else installed is left exactly where it is");
	planfix_release(plan, document, observed);
}

/*
 * An observation carrying no qdisc produced a reset that could change nothing,
 * and an action that cannot change anything is not an action. Nothing but this
 * enforces the "every interface always has a qdisc" sentence.
 */
static void a_reset_that_could_change_nothing_is_not_planned(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = one("{\"name\":\"eth0\",\"kind\":{\"kind\":\"physical\"}}",
	    "\"links\":[" PLANFIX_LINK("eth0", "") "],\"qdisc_applied\":[\"eth0\"]",
	    &document, &observed);

	check(plan && !planfix_action(plan, "qdisc.reset"),
	    "an observation with no qdisc at all plans no reset");
	planfix_release(plan, document, observed);
}

/* ------------------------------------------------------------------------ *
 * The ingress redirect
 * ------------------------------------------------------------------------ */

static void a_redirect_waits_for_the_device_it_points_at(void)
{
	ncfg_document_t     *document;
	ncfg_observed_t     *observed;
	ncfg_plan_t         *plan = planfix_plan(
	    "{\"name\":\"eth0\",\"kind\":{\"kind\":\"physical\"},"
	    "\"ingress_redirect\":\"ifb-eth0\"},"
	    "{\"name\":\"ifb-eth0\",\"kind\":{\"kind\":\"ifb\"}}", "", "", "",
	    "\"links\":[" PLANFIX_LINK("eth0", "") "]", &document, &observed);
	const ncfg_action_t *create = plan ? planfix_action(plan, "link.create") : NULL;
	const ncfg_action_t *action = plan ? planfix_action(plan, "ingress.redirect") : NULL;

	check(action != NULL, "a device asking for an ingress redirect gets one");
	check(create && action && planfix_depends_on(action, create->id),
	    "and it waits for the `ifb` it points at, not for itself");
	planfix_release(plan, document, observed);
}

static void a_redirect_is_only_cleared_where_netcfgd_installed_it(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = one("{\"name\":\"eth0\",\"kind\":{\"kind\":\"physical\"}}",
	    "\"links\":[" PLANFIX_LINK("eth0", ",\"ingress_redirect\":\"ifb-eth0\"") "],"
	    "\"ingress_applied\":[\"eth0\"]", &document, &observed);

	check(plan && planfix_action(plan, "ingress.redirect.clear"),
	    "a redirect netcfgd installed is cleared when the document stops asking");
	planfix_release(plan, document, observed);

	plan = one("{\"name\":\"eth0\",\"kind\":{\"kind\":\"physical\"}}",
	    "\"links\":[" PLANFIX_LINK("eth0", ",\"ingress_redirect\":\"ifb-eth0\"") "]",
	    &document, &observed);
	check(plan && !planfix_action(plan, "ingress.redirect.clear"),
	    "and one somebody else put there is not netcfgd's to take away");
	planfix_release(plan, document, observed);
}

static void a_redirect_that_is_already_right_plans_nothing(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = planfix_plan(
	    "{\"name\":\"eth0\",\"kind\":{\"kind\":\"physical\"},"
	    "\"ingress_redirect\":\"ifb-eth0\"},"
	    "{\"name\":\"ifb-eth0\",\"kind\":{\"kind\":\"ifb\"}}", "", "", "",
	    "\"links\":[" PLANFIX_LINK("eth0", ",\"ingress_redirect\":\"ifb-eth0\"") ","
	    PLANFIX_LINK("ifb-eth0", "") "],\"ingress_applied\":[\"eth0\"]",
	    &document, &observed);

	check(plan && quiet(plan), "a redirect that already points where it should plans nothing");
	planfix_release(plan, document, observed);
}

int main(void)
{
	an_offload_the_driver_has_off_is_turned_on();
	one_model_field_covers_every_spelling_a_driver_may_have();
	a_link_that_does_not_exist_yet_still_gets_its_offloads();
	only_the_unapplied_ethtool_fields_are_named();
	offloads_that_already_agree_plan_nothing();

	a_rule_the_kernel_does_not_have_is_added();
	a_different_rule_at_the_same_priority_goes_first();
	a_rule_netcfgd_does_not_own_is_reported_and_left();
	a_rule_of_netcfgds_the_document_dropped_is_removed();
	a_rule_that_agrees_is_left_alone_and_a_changed_selector_is_not();
	a_selector_is_compared_as_an_address_and_not_as_text();

	the_kind_and_the_rate_are_both_part_of_the_comparison();
	a_qdisc_is_only_reset_where_netcfgd_is_what_moved_it();
	a_reset_that_could_change_nothing_is_not_planned();

	a_redirect_waits_for_the_device_it_points_at();
	a_redirect_is_only_cleared_where_netcfgd_installed_it();
	a_redirect_that_is_already_right_plans_nothing();

	printf("plan_tc_test: %d checks, %d failed\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
