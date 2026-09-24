/*
 * plan_kind_test.c -- the passes that correct what a device's `kind` says
 * about itself, and the per-port VLAN list.
 *
 * WHAT THESE ARE FOR
 *   Every setting under test is sent inside `link.create`, so the first apply
 *   gets it right and none of this is exercised by a fresh machine. The
 *   failure is the *second* apply: a bridge's `stp` and `forward_delay` were
 *   applied at creation and never compared again, so editing either planned
 *   nothing and said nothing (0054, 0057). Each case here moves one field and
 *   asserts the action and the field it names.
 *
 *   **And each of them has an idempotence half**, which is the property
 *   `plan.h` calls load-bearing: a converged device plans nothing. A
 *   comparison that is wrong in that direction is not a missing feature, it is
 *   a plan that does the same work for ever on every reconcile -- and it is
 *   exactly what 10.169 records a text comparison of addresses costing. The
 *   tunnel and VXLAN cases put the kernel's spelling of an address against the
 *   operator's on purpose.
 */
#include "planfix.h"

#include <stdio.h>
#include <stdlib.h>

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

/* A plan built from one device and one link, which is every case below. */
static ncfg_plan_t *one(const char *device, const char *link, ncfg_document_t **document,
    ncfg_observed_t **observed)
{
	return planfix_plan(device, "", "", "", link, document, observed);
}

/* Whether the plan holds exactly this op, naming this field. */
static int corrects(const ncfg_plan_t *plan, const char *op, const char *field)
{
	const ncfg_action_t *action = planfix_for_field(plan, op, field);

	if (!action) {
		char names[512];

		planfix_names(plan, names, sizeof(names));
		printf("  wanted %s naming %s; the plan is [%s]\n", op, field, names);
	}
	return action != NULL;
}

/* Whether the plan is empty, printing it where it is not. */
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

/* ------------------------------------------------------------------------ *
 * Remaking a link the kernel will not change (0059)
 * ------------------------------------------------------------------------ */

/*
 * The three shapes the kernel takes and ignores, and the one it does not.
 *
 * **`ip link set X type vlan id N` succeeds and changes nothing**, so a
 * planner that emits a set reports a change that never happened and goes on
 * reporting it. The only way to apply an edited id is to delete the interface
 * and make it again -- with everything on it, which is what the filtered
 * observation below the delete arranges.
 *
 * This is what `tests/live/links.sh` asserts against a real kernel and what
 * that script found missing from this port: an edited vlan id planned
 * **nothing to do**, on a configuration an operator had just changed.
 */
static void a_link_the_kernel_will_not_change_is_remade(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan;

	/* A vlan whose id differs. `ours` is what makes it netcfgd's to remove. */
	plan = one("{\"name\":\"v7\",\"kind\":{\"kind\":\"vlan\",\"parent\":\"br0\","
	    "\"id\":78,\"protocol\":\"dot1q\"}}",
	    "\"links\":[{\"name\":\"v7\",\"index\":9,\"mtu\":1500,\"up\":true,\"carrier\":true,"
	    "\"ownership\":\"ours\",\"kind\":\"vlan\",\"parent\":\"br0\","
	    "\"vlan\":{\"id\":77,\"protocol\":\"dot1q\"}}]",
	    &document, &observed);
	check(plan && corrects(plan, "link.delete", "vlan.id"),
	    "an edited vlan id plans a delete naming the field");
	check(plan && planfix_action(plan, "link.create"),
	    "  and a create after it, from the document rather than the observation");
	planfix_release(plan, document, observed);

	/* A device that exists as an entirely different kind. Before 0059 this
	 * planned a `link.up` and nothing else, on somebody else's device. */
	plan = one("{\"name\":\"flip0\",\"kind\":{\"kind\":\"macvlan\","
	    "\"parent\":\"base0\",\"mode\":\"bridge\"}}",
	    "\"links\":[{\"name\":\"flip0\",\"index\":9,\"mtu\":1500,\"up\":true,\"carrier\":true,"
	    "\"ownership\":\"ours\",\"kind\":\"dummy\"}]",
	    &document, &observed);
	check(plan && corrects(plan, "link.delete", "kind"),
	    "a device that is the wrong kind entirely plans a delete naming the kind");
	planfix_release(plan, document, observed);

	/* A vlan's parent is the outer `IFLA_LINK`, which the kernel accepts on a
	 * live device and ignores -- the same answer as the id and therefore the
	 * same remedy (0060). */
	plan = one("{\"name\":\"v7\",\"kind\":{\"kind\":\"vlan\",\"parent\":\"base0\","
	    "\"id\":77,\"protocol\":\"dot1q\"}}",
	    "\"links\":[{\"name\":\"v7\",\"index\":9,\"mtu\":1500,\"up\":true,\"carrier\":true,"
	    "\"ownership\":\"ours\",\"kind\":\"vlan\",\"parent\":\"br0\","
	    "\"vlan\":{\"id\":77,\"protocol\":\"dot1q\"}}]",
	    &document, &observed);
	check(plan && corrects(plan, "link.delete", "parent"),
	    "a moved vlan parent plans a delete naming the parent");
	planfix_release(plan, document, observed);

	/*
	 * **And a VXLAN's underlay is not one of them.** It lives in the VXLAN's
	 * own nest, the kernel moves it on a live device, and `link.set_vxlan`
	 * corrects it in place. Asserted here rather than only in the pass that
	 * does it, because the failure this guards is the remake rule reaching one
	 * field too far -- and throwing an interface away is the most destructive
	 * thing the planner does.
	 */
	plan = one("{\"name\":\"vx1\",\"kind\":{\"kind\":\"vxlan\",\"parent\":\"base0\","
	    "\"id\":100}}",
	    "\"links\":[{\"name\":\"vx1\",\"index\":9,\"mtu\":1500,\"up\":true,\"carrier\":true,"
	    "\"ownership\":\"ours\",\"kind\":\"vxlan\",\"parent\":\"br0\","
	    "\"vxlan\":{\"id\":100}}]",
	    &document, &observed);
	check(plan && !planfix_action(plan, "link.delete"),
	    "a moved vxlan underlay is not thrown away, being one the kernel moves");
	planfix_release(plan, document, observed);
}

/*
 * The one place the planner throws an interface away, and the ownership rule
 * that governs it.
 *
 * A link netcfgd has no record of creating gets a sentence naming what
 * differs and what correcting it would cost, and is left alone. That leaves a
 * real gap and it is the right gap: the alternative is a config file that
 * deletes interfaces netcfgd never made.
 */
static void a_link_netcfgd_did_not_make_is_explained_rather_than_remade(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = one(
	    "{\"name\":\"hand\",\"kind\":{\"kind\":\"vlan\",\"parent\":\"br0\","
	    "\"id\":91,\"protocol\":\"dot1q\"}}",
	    "\"links\":[{\"name\":\"hand\",\"index\":9,\"mtu\":1500,\"up\":true,\"carrier\":true,"
	    "\"ownership\":\"foreign\",\"kind\":\"vlan\",\"parent\":\"br0\","
	    "\"vlan\":{\"id\":90,\"protocol\":\"dot1q\"}}]",
	    &document, &observed);

	check(plan && !planfix_action(plan, "link.delete"),
	    "a link netcfgd did not create is not deleted");
	check(plan && !planfix_action(plan, "link.create"),
	    "  and not recreated either");
	check(plan && planfix_warned(plan, "will not do to a link it did not create"),
	    "  and the plan says so, naming what correcting it would cost");
	planfix_release(plan, document, observed);
}

/* ------------------------------------------------------------------------ *
 * A bridge
 * ------------------------------------------------------------------------ */

#define BRIDGE_DEVICE(body) \
	"{\"name\":\"br0\",\"kind\":{\"kind\":\"bridge\",\"members\":[]," body "}}"
#define BRIDGE_LINK(body) \
	PLANFIX_LINK("br0", ",\"kind\":\"bridge\",\"bridge\":{" body "}")

/*
 * All six of a bridge's own settings are compared.
 *
 * Three of them -- `ageing_time`, `priority` and `vlan_filtering` -- arrived
 * after the Rust's pass was written and nothing said they had to be added to
 * it, so they were parsed, sent at creation, read back by the observer, and
 * never compared. C has no destructuring to make that a compile error, so this
 * is the check that stands in for it: the count is here, and a seventh setting
 * that nobody compares fails the first line of this function.
 */
static void every_bridge_setting_is_compared(void)
{
	static const struct {
		const char *field;
		const char *document;
		const char *kernel;
	} cases[] = {
		{ "bridge.stp", "\"stp\":true", "\"stp\":false,\"vlan_filtering\":false" },
		{ "bridge.forward_delay", "\"stp\":false,\"forward_delay\":4",
		    "\"stp\":false,\"forward_delay\":15,\"vlan_filtering\":false" },
		{ "bridge.hello_time", "\"stp\":false,\"hello_time\":2",
		    "\"stp\":false,\"hello_time\":3,\"vlan_filtering\":false" },
		{ "bridge.ageing_time", "\"stp\":false,\"ageing_time\":300",
		    "\"stp\":false,\"ageing_time\":30,\"vlan_filtering\":false" },
		{ "bridge.priority", "\"stp\":false,\"priority\":4096",
		    "\"stp\":false,\"priority\":32768,\"vlan_filtering\":false" },
		{ "bridge.vlan_filtering", "\"stp\":false,\"vlan_filtering\":true",
		    "\"stp\":false,\"vlan_filtering\":false" }
	};
	size_t i;

	check(sizeof(cases) / sizeof(cases[0]) == 6u,
	    "a bridge has six settings of its own, and each is a case below");
	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		ncfg_document_t *document;
		ncfg_observed_t *observed;
		char             device[512];
		char             observation[700];
		ncfg_plan_t     *plan;

		(void)snprintf(device, sizeof(device), BRIDGE_DEVICE("%s"), cases[i].document);
		(void)snprintf(observation, sizeof(observation), "\"links\":[" BRIDGE_LINK("%s") "]",
		    cases[i].kernel);
		plan = one(device, observation, &document, &observed);
		check(plan && corrects(plan, "link.set_bridge", cases[i].field),
		    cases[i].field);
		planfix_release(plan, document, observed);
	}
}

/* An absent field means "whatever the kernel picked", and comparing it against
 * what the kernel picked rebuilds the bridge on every reconcile (0052). */
static void a_bridge_setting_the_document_omits_is_not_compared(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = one(BRIDGE_DEVICE("\"stp\":false"),
	    "\"links\":[" BRIDGE_LINK("\"stp\":false,\"forward_delay\":15,\"hello_time\":2,"
	    "\"ageing_time\":300,\"priority\":32768,\"vlan_filtering\":false") "]",
	    &document, &observed);

	check(plan && quiet(plan),
	    "a bridge setting the document omits is not compared against the kernel's");
	planfix_release(plan, document, observed);
}

/* ------------------------------------------------------------------------ *
 * A bond
 * ------------------------------------------------------------------------ */

#define BOND_DEVICE(body) "{\"name\":\"bond0\",\"kind\":{\"kind\":\"bond\",\"members\":[]," body "}}"

static void a_bond_mode_moves_on_a_bond_with_no_members(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = one(BOND_DEVICE("\"mode\":\"balance-rr\""),
	    "\"links\":[" PLANFIX_LINK("bond0",
	    ",\"kind\":\"bond\",\"bond\":{\"mode\":\"active-backup\"}") "]",
	    &document, &observed);
	const ncfg_action_t *action;

	check(plan && corrects(plan, "link.set_bond", "bond.mode"),
	    "a bond's mode is corrected on a bond with no members");
	action = plan ? planfix_for_field(plan, "link.set_bond", "bond.mode") : NULL;
	check(action && action->op.u.set_bond.mode,
	    "and the op says the mode is part of the message");
	planfix_release(plan, document, observed);
}

/*
 * A bond with members gets a sentence rather than an action that cannot work.
 *
 * The kernel answers `ENOTEMPTY`, which the Rust's first version of this found
 * by failing an apply and then planning the same action again on the next
 * reconcile, for ever. `miimon` has no such rule, so it is corrected in the
 * same plan -- the sentence stands beside the rest of the plan rather than
 * instead of it.
 */
static void a_bond_with_members_is_told_rather_than_tried(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = planfix_plan(
	    BOND_DEVICE("\"mode\":\"balance-rr\",\"miimon\":100") ","
	    "{\"name\":\"eth0\",\"kind\":{\"kind\":\"physical\"},\"master\":\"bond0\"}",
	    "", "", "",
	    "\"links\":[" PLANFIX_LINK("bond0",
	    ",\"kind\":\"bond\",\"bond\":{\"mode\":\"active-backup\",\"miimon\":50}") ","
	    PLANFIX_LINK("eth0", ",\"master\":\"bond0\"") "]",
	    &document, &observed);
	const ncfg_action_t *action;

	check(plan && planfix_warned(plan, "will not change it while the bond has members"),
	    "a bond with members is told its mode cannot move");
	action = plan ? planfix_for_field(plan, "link.set_bond", "bond.mode") : NULL;
	check(plan && !action, "and no action that must fail is planned");
	action = plan ? planfix_for_field(plan, "link.set_bond", "bond.miimon") : NULL;
	check(action && !action->op.u.set_bond.mode,
	    "while `miimon` beside it is corrected, with the mode left out of the message");
	planfix_release(plan, document, observed);
}

/* A mode netcfgd has no word for is somebody else's choice, expressed in
 * something this build cannot describe. Nothing is corrected on one. */
static void a_mode_netcfgd_cannot_name_is_not_corrected(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = one(BOND_DEVICE("\"mode\":\"balance-rr\""),
	    "\"links\":[" PLANFIX_LINK("bond0", ",\"kind\":\"bond\",\"bond\":{}") "]",
	    &document, &observed);

	check(plan && quiet(plan), "a bond mode netcfgd has no word for is not corrected");
	planfix_release(plan, document, observed);
}

/* ------------------------------------------------------------------------ *
 * A macvlan
 * ------------------------------------------------------------------------ */

#define MACVLAN_DEVICE(mode) \
	"{\"name\":\"mv0\",\"kind\":{\"kind\":\"macvlan\",\"parent\":\"eth0\",\"mode\":\"" \
	mode "\"}}"
#define MACVLAN_LINK(mode) \
	PLANFIX_LINK("mv0", ",\"kind\":\"macvlan\",\"parent\":\"eth0\"," \
	"\"macvlan\":{\"mode\":\"" mode "\"}")

static void a_macvlan_moves_among_the_three_modes_the_kernel_takes(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = one(MACVLAN_DEVICE("bridge"),
	    "\"links\":[" MACVLAN_LINK("vepa") "]", &document, &observed);

	check(plan && corrects(plan, "link.set_macvlan", "macvlan.mode"),
	    "a macvlan moves freely among private, vepa and bridge");
	planfix_release(plan, document, observed);
}

/* `macvlan_changelink` refuses this transition in either direction by name, so
 * it is said rather than tried (0058). */
static void a_macvlan_passthru_transition_is_told_rather_than_tried(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = one(MACVLAN_DEVICE("bridge"),
	    "\"links\":[" MACVLAN_LINK("passthru") "]", &document, &observed);

	check(plan && planfix_warned(plan, "into or out of passthru mode"),
	    "moving a macvlan out of passthru is told rather than tried");
	check(plan && !planfix_action(plan, "link.set_macvlan"),
	    "and nothing that must fail is planned");
	planfix_release(plan, document, observed);

	plan = one(MACVLAN_DEVICE("passthru"), "\"links\":[" MACVLAN_LINK("bridge") "]",
	    &document, &observed);
	check(plan && planfix_warned(plan, "into or out of passthru mode"),
	    "and moving one into passthru is refused the same way");
	planfix_release(plan, document, observed);
}

/* ------------------------------------------------------------------------ *
 * A tunnel
 * ------------------------------------------------------------------------ */

#define TUNNEL_DEVICE(name, body) \
	"{\"name\":\"" name "\",\"kind\":{\"kind\":\"tunnel\"," body "}}"
#define TUNNEL_LINK(name, body) \
	PLANFIX_LINK(name, ",\"kind\":\"gre\",\"tunnel\":{" body "}")

static void a_tunnel_endpoint_is_corrected(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = one(
	    TUNNEL_DEVICE("gre1", "\"mode\":\"gre\",\"local\":\"192.0.2.1\","
	    "\"remote\":\"192.0.2.9\""),
	    "\"links\":[" TUNNEL_LINK("gre1",
	    "\"local\":\"192.0.2.1\",\"remote\":\"192.0.2.2\"") "]", &document, &observed);

	check(plan && corrects(plan, "link.set_tunnel", "tunnel.remote"),
	    "a tunnel whose remote the document moved is corrected");
	planfix_release(plan, document, observed);
}

/*
 * **The idempotence case, and the one this module is most at risk from.**
 *
 * The document writes an IPv6 endpoint one way and the kernel reports its own
 * spelling of the same address. Compared as text they never agree, so the same
 * `link.set_tunnel` is planned on every reconcile for ever -- 10.169's defect,
 * in a second place. `ncfg_plan_address_equal` is what makes this quiet.
 */
static void an_endpoint_is_compared_as_an_address_and_not_as_text(void)
{
	char             message[NCFG_ERROR_MAX];
	ncfg_document_t *document = planfix_document(
	    TUNNEL_DEVICE("gre1", "\"mode\":\"ip6gre\",\"local\":\"2001:db8::1\","
	    "\"remote\":\"2001:db8::2\""), "", "", "");
	ncfg_observed_t *observed = planfix_observed(
	    "\"links\":[" TUNNEL_LINK("gre1",
	    "\"local\":\"2001:db8::1\",\"remote\":\"2001:db8::2\"") "]");
	ncfg_plan_t     *plan;

	if (!document || !observed) {
		check(0, "two spellings of one endpoint are one endpoint");
		planfix_release(NULL, document, observed);
		return;
	}
	/*
	 * **The observation is edited after it is read, and that is the point.**
	 * `ncfg_observed_read` canonicalises every address it parses, so a fixture
	 * written as JSON cannot express an observation that spells one endpoint
	 * the long way -- which would make a check built out of two JSON documents
	 * pass whatever this planner compared, and prove nothing. The producers
	 * that can are real: an observation assembled in memory by
	 * `src/observe/`, and a *report*, which keeps the text somebody's shell
	 * script wrote. So the struct is put into the state one of those can hand
	 * over, and the comparison is asked about it.
	 */
	free(observed->links[0].tunnel->local);
	free(observed->links[0].tunnel->remote);
	observed->links[0].tunnel->local = strdup("2001:0DB8:0000::1");
	observed->links[0].tunnel->remote = strdup("2001:0DB8:0000::2");
	message[0] = '\0';
	plan = ncfg_plan_build(document, observed, NULL, message, sizeof(message));
	check(plan && quiet(plan),
	    "two spellings of one endpoint are one endpoint, so a second plan is empty");
	planfix_release(plan, document, observed);
}

/*
 * A geneve VNI cannot change at all, and the sentence must not take the
 * endpoint beside it with it: the nest the executor sends leaves the VNI out
 * for exactly that reason (0057's lesson).
 */
static void a_geneve_id_is_told_and_the_remote_beside_it_is_still_corrected(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = one(
	    TUNNEL_DEVICE("gnv0", "\"mode\":\"geneve\",\"remote\":\"192.0.2.9\",\"key\":7"),
	    "\"links\":[" TUNNEL_LINK("gnv0", "\"remote\":\"192.0.2.2\",\"key\":3") "]",
	    &document, &observed);

	check(plan && planfix_warned(plan, "will not change the VNI of a geneve tunnel"),
	    "a geneve tunnel's id is told rather than tried");
	check(plan && corrects(plan, "link.set_tunnel", "tunnel.remote"),
	    "and the remote beside it is still corrected");
	planfix_release(plan, document, observed);
}

/* A geneve remote may not change family, and that one *does* take the message
 * with it: the remote is the thing that would be sent. */
static void a_geneve_remote_changing_family_stops_the_pass(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = one(
	    TUNNEL_DEVICE("gnv0", "\"mode\":\"geneve\",\"remote\":\"2001:db8::9\""),
	    "\"links\":[" TUNNEL_LINK("gnv0", "\"remote\":\"192.0.2.2\"") "]",
	    &document, &observed);

	check(plan && planfix_warned(plan, "which address family its remote is in"),
	    "a geneve remote moving family is told");
	check(plan && !planfix_action(plan, "link.set_tunnel"),
	    "and no set is planned beside it");
	planfix_release(plan, document, observed);
}

/* `gre0` is the name an operator reaches for first, and it is the one device
 * of its kind the kernel refuses everything on. */
static void the_kernels_own_fallback_tunnel_is_refused_by_name(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = one(
	    TUNNEL_DEVICE("gre0", "\"mode\":\"gre\",\"remote\":\"192.0.2.9\""),
	    "\"links\":[" TUNNEL_LINK("gre0", "\"remote\":\"192.0.2.2\"") "]",
	    &document, &observed);

	check(plan && planfix_warned(plan, "fallback tunnel device"),
	    "the kernel's own fallback tunnel is named rather than configured");
	check(plan && !planfix_action(plan, "link.set_tunnel"),
	    "and nothing that must fail with EINVAL is planned");
	planfix_release(plan, document, observed);
}

/* ------------------------------------------------------------------------ *
 * A VXLAN
 * ------------------------------------------------------------------------ */

#define VXLAN_DEVICE(body) "{\"name\":\"vx0\",\"kind\":{\"kind\":\"vxlan\"," body "}}"
#define VXLAN_LINK(body) PLANFIX_LINK("vx0", ",\"kind\":\"vxlan\",\"vxlan\":{" body "}")

static void a_vxlan_id_and_port_are_told_and_the_endpoints_are_corrected(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = one(
	    VXLAN_DEVICE("\"id\":100,\"port\":4789,\"remote\":\"192.0.2.9\""),
	    "\"links\":[" VXLAN_LINK("\"id\":200,\"port\":8472,\"remote\":\"192.0.2.2\"") "]",
	    &document, &observed);

	check(plan && planfix_warned(plan, "will not change the VNI of a VXLAN"),
	    "a VXLAN's id is told rather than tried");
	check(plan && planfix_warned(plan, "destination port of a VXLAN"),
	    "and so is its port, which the kernel refuses at any value");
	check(plan && corrects(plan, "link.set_vxlan", "vxlan.remote"),
	    "and the endpoints beside them are still corrected");
	planfix_release(plan, document, observed);
}

static void a_converged_vxlan_plans_nothing(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = one(
	    VXLAN_DEVICE("\"id\":100,\"port\":4789,\"local\":\"192.0.2.1\","
	    "\"remote\":\"192.0.2.2\",\"parent\":\"eth0\""),
	    "\"links\":[" PLANFIX_LINK("vx0", ",\"kind\":\"vxlan\",\"parent\":\"eth0\","
	    "\"vxlan\":{\"id\":100,\"port\":4789,\"local\":\"192.0.2.1\","
	    "\"remote\":\"192.0.2.2\"}") "]", &document, &observed);

	check(plan && quiet(plan), "a VXLAN that agrees with the kernel plans nothing");
	planfix_release(plan, document, observed);
}

/* ------------------------------------------------------------------------ *
 * Per-port VLANs
 * ------------------------------------------------------------------------ */

#define PORT_DEVICE(name, master, vlans) \
	"{\"name\":\"" name "\",\"kind\":{\"kind\":\"physical\"},\"master\":\"" master "\"," \
	"\"bridge_vlans\":[" vlans "]}"
#define PORT_LINK(name, master) PLANFIX_LINK(name, ",\"master\":\"" master "\"")

/*
 * A port whose config lists VLANs has exactly those.
 *
 * That includes removing the VLAN 1 the kernel adds by itself when a port
 * joins a filtering bridge: every real trunk setup begins by deleting it, and
 * leaving it because the kernel put it there would mean the document does not
 * describe the port.
 */
static void a_configured_port_owns_its_vlan_list(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = planfix_plan(
	    PORT_DEVICE("lan1", "br0", "{\"vid\":10,\"pvid\":true,\"untagged\":true}"),
	    "", "", "",
	    "\"links\":[" PORT_LINK("lan1", "br0") "],"
	    "\"bridge_vlans\":[{\"index\":2,\"vid\":1,\"pvid\":true,\"untagged\":true},"
	    "{\"index\":2,\"vid\":99,\"pvid\":false,\"untagged\":false}]",
	    &document, &observed);

	check(plan && planfix_count(plan, "bridge.vlan.del") == 2u,
	    "both VLANs go, including the kernel's own");
	check(plan && planfix_count(plan, "bridge.vlan.add") == 1u,
	    "and the one the document names arrives");
	planfix_release(plan, document, observed);
}

/* A VLAN present but tagged where the document says untagged is wrong in a way
 * that shows up as traffic arriving with a tag nobody expected. */
static void wrong_vlan_flags_are_corrected(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = planfix_plan(
	    PORT_DEVICE("lan1", "br0", "{\"vid\":10,\"pvid\":true,\"untagged\":true}"),
	    "", "", "",
	    "\"links\":[" PORT_LINK("lan1", "br0") "],"
	    "\"bridge_vlans\":[{\"index\":2,\"vid\":10,\"pvid\":false,\"untagged\":false}]",
	    &document, &observed);
	const ncfg_action_t *action = plan ? planfix_action(plan, "bridge.vlan.add") : NULL;

	check(action && action->op.u.bridge_vlan.vid == 10 && action->op.u.bridge_vlan.pvid,
	    "a VLAN present with the wrong flags is corrected rather than counted present");
	planfix_release(plan, document, observed);
}

/* The authority is over ports that are configured, not over the bridge. */
static void an_unmentioned_port_keeps_its_vlans(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = planfix_plan(
	    "{\"name\":\"other\",\"kind\":{\"kind\":\"physical\"},\"master\":\"br0\"}",
	    "", "", "",
	    "\"links\":[" PORT_LINK("other", "br0") "],"
	    "\"bridge_vlans\":[{\"index\":2,\"vid\":7,\"pvid\":false,\"untagged\":false}]",
	    &document, &observed);

	check(plan && !planfix_action(plan, "bridge.vlan.del"),
	    "a port the document says nothing about keeps whatever VLANs it has");
	planfix_release(plan, document, observed);
}

/*
 * **The port with no `interface` block, which is the ordinary shape of one.**
 *
 * A trunk port carries no address and never will, so it has a `device` block
 * and nothing else. The Rust reaches its VLAN pass from `plan_interface_
 * contents`, so exactly this port has never had its VLANs planned at all --
 * see 0263's divergence list. Driving the pass from the device list is what
 * fixes it, and this is the case that says so.
 */
static void a_port_with_no_interface_block_still_gets_its_vlans(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = planfix_plan(
	    PORT_DEVICE("lan1", "br0", "{\"vid\":10,\"pvid\":false,\"untagged\":false}"),
	    "", "", "",
	    "\"links\":[" PORT_LINK("lan1", "br0") "]", &document, &observed);

	check(plan && planfix_action(plan, "bridge.vlan.add"),
	    "a port with `vlans` and no `interface` block still gets them");
	planfix_release(plan, document, observed);
}

/*
 * The kernel puts VLAN 1 on a port the moment it joins a filtering bridge,
 * which happens during *this* apply -- so it is not in the observation the
 * plan was computed from. Without this the removal lands on the next
 * reconcile, which is fine for a daemon and never happens under `--oneshot`.
 */
static void a_port_about_to_be_created_still_drops_the_kernels_own_vlan(void)
{
	ncfg_document_t     *document;
	ncfg_observed_t     *observed;
	ncfg_plan_t         *plan = planfix_plan(
	    "{\"name\":\"lan1\",\"kind\":{\"kind\":\"dummy\"},\"master\":\"br0\","
	    "\"bridge_vlans\":[{\"vid\":10,\"pvid\":false,\"untagged\":false}]}",
	    "", "", "", "\"links\":[]", &document, &observed);
	const ncfg_action_t *action = plan ? planfix_action(plan, "bridge.vlan.del") : NULL;

	check(action && action->op.u.bridge_vlan.vid == 1,
	    "a port this plan creates still drops the VLAN 1 the kernel is about to add");
	planfix_release(plan, document, observed);

	plan = planfix_plan(
	    "{\"name\":\"lan1\",\"kind\":{\"kind\":\"dummy\"},\"master\":\"br0\","
	    "\"bridge_vlans\":[{\"vid\":1,\"pvid\":true,\"untagged\":true}]}",
	    "", "", "", "\"links\":[]", &document, &observed);
	check(plan && !planfix_action(plan, "bridge.vlan.del"),
	    "and a document that asks for VLAN 1 keeps it");
	planfix_release(plan, document, observed);
}

/*
 * A `vlans` on a device in no bridge is a configuration that cannot converge:
 * the kernel answers `EOPNOTSUPP`, the apply fails, and the same action is
 * planned again on the next reconcile and every one after. Said once (0061).
 */
static void vlans_on_a_device_in_no_bridge_are_said_once(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = one(
	    "{\"name\":\"eth0\",\"kind\":{\"kind\":\"physical\"},"
	    "\"bridge_vlans\":[{\"vid\":10,\"pvid\":false,\"untagged\":false}]}",
	    "\"links\":[" PLANFIX_LINK("eth0", "") "]", &document, &observed);

	check(plan && planfix_warned(plan, "neither a bridge nor a member of one"),
	    "`vlans` on a device in no bridge is said once rather than attempted for ever");
	check(plan && !planfix_action(plan, "bridge.vlan.add"),
	    "and nothing that must fail is planned");
	planfix_release(plan, document, observed);
}

/* A VLAN on the bridge device itself is a SELF operation; one on a port is
 * MASTER. Getting it backwards is accepted by the kernel and configures the
 * wrong device. */
static void a_vlan_on_the_bridge_itself_is_a_self_operation(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = one(
	    "{\"name\":\"br0\",\"kind\":{\"kind\":\"bridge\",\"members\":[],\"stp\":false,"
	    "\"vlan_filtering\":true},"
	    "\"bridge_vlans\":[{\"vid\":10,\"pvid\":false,\"untagged\":false}]}",
	    "\"links\":[" BRIDGE_LINK("\"stp\":false,\"vlan_filtering\":true") "]",
	    &document, &observed);
	const ncfg_action_t *action = plan ? planfix_action(plan, "bridge.vlan.add") : NULL;

	check(action && action->op.u.bridge_vlan.on_self,
	    "a VLAN on the bridge device itself is a SELF operation");
	planfix_release(plan, document, observed);

	plan = planfix_plan(
	    PORT_DEVICE("lan1", "br0", "{\"vid\":10,\"pvid\":false,\"untagged\":false}"),
	    "", "", "", "\"links\":[" PORT_LINK("lan1", "br0") "]", &document, &observed);
	action = plan ? planfix_action(plan, "bridge.vlan.add") : NULL;
	check(action && !action->op.u.bridge_vlan.on_self,
	    "and one on a port is a MASTER operation");
	planfix_release(plan, document, observed);
}

/* A converged port plans nothing, which is what stops a trunk being
 * reconfigured on every reconcile. */
static void a_converged_port_plans_nothing(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = planfix_plan(
	    PORT_DEVICE("lan1", "br0", "{\"vid\":10,\"pvid\":true,\"untagged\":true}"),
	    "", "", "",
	    "\"links\":[" PORT_LINK("lan1", "br0") "],"
	    "\"bridge_vlans\":[{\"index\":2,\"vid\":10,\"pvid\":true,\"untagged\":true}]",
	    &document, &observed);

	check(plan && quiet(plan), "a port whose VLANs are already right plans nothing");
	planfix_release(plan, document, observed);
}

/*
 * A kind this build cannot create is warned about, not planned.
 *
 * **The two halves of this port met here and disagreed.** The planner learned
 * to configure a bond, a macvlan and a tunnel in the same wave the executor
 * learned the `link.set_*` family -- and `link.create` for those kinds was
 * still refused, because `ncfg_kernel_newlink_of` built no nest for them.
 * Nothing connected the two, so a document naming a bond that did not exist
 * yet planned a `link.create` that fails on every apply, for ever, while
 * `ncfg plan` went on listing it as work to do.
 *
 * That is the non-convergence the neighbouring arms in `plan/link.c` each
 * exist to prevent, and that file's own comment states the rule: planning an
 * action that must fail is worse than saying why it cannot be done.
 *
 * **The bond and the macvlan have left this list, and so has the sentence they
 * were caught by.** The nests are written, so the check went green by itself
 * and the two kinds moved to the other half below -- and with them went the
 * last kind a *document* could express that `ncfg_apply_supported` refuses.
 * What it still refuses is a physical device, a pppoe session and an openvpn
 * tunnel, and `plan/link.c` reaches an arm of its own for each of those first:
 * a device that is not plugged in, and a link the daemon that dials it brings
 * into existence. Those arms are earlier deliberately, each saying something
 * the generic refusal cannot.
 *
 * So the executor probe is a backstop with nothing left to fire on, which is
 * the right state for it rather than a reason to delete it: it is what covers
 * the *next* kind to be held back, and the check that it is still consulted at
 * all is the sibling below -- five kinds that went from declined to planned
 * without `src/plan/` being touched.
 *
 * What this case asserts now is the property, not the sentence: a kind nothing
 * here can bring into being is not planned as a creation, and the plan says so
 * in somebody's words rather than staying silent.
 *
 * **Whose words they are has moved, which is the point of asserting the
 * property.** `link.c` used to say that nothing here creates the device and
 * that this build starts no backend for it; the second half stopped being true
 * when `session.c` landed, so that arm is silent now and the sentence an
 * operator gets is the session pass's -- the addressing is waiting rather than
 * missing. The creation is still not planned, which is what the first check
 * below is about, and the dial is: `plan_session_test.c` is where *that* is
 * asserted, one action per device.
 */
static void a_kind_this_build_cannot_create_is_warned_about(void)
{
	static const char *const bodies[] = {
		"{\"name\":\"new0\",\"kind\":{\"kind\":\"pppoe\",\"parent\":\"eth0\","
		"\"username\":\"alice\",\"password\":{\"provider\":\"file\",\"name\":\"dsl\"}}}",
		/* `open_vpn` is the document's spelling and `openvpn` the configuration
		 * language's -- `document.c` says so, and this is the model's side. */
		"{\"name\":\"new0\",\"kind\":{\"kind\":\"open_vpn\","
		"\"config\":\"/etc/openvpn/client.conf\"}}"
	};
	size_t i;

	for (i = 0; i < sizeof(bodies) / sizeof(bodies[0]); i++) {
		ncfg_document_t *document = NULL;
		ncfg_observed_t *observed = NULL;
		ncfg_plan_t     *plan;

		plan = planfix_plan(bodies[i], "", "", "", "\"links\":[]", &document, &observed);
		if (!plan) {
			check(0, "the fixture compiles");
			continue;
		}
		check(planfix_count(plan, "link.create") == 0u,
		    "a kind this build cannot create is not planned as a creation");
		check(planfix_warned(plan, "is not up yet"),
		    "  and the plan says so rather than staying silent");
		planfix_release(plan, document, observed);
	}
}

/*
 * And the other direction, which is the half that proves the question is being
 * asked rather than the answer being memorised.
 *
 * A `tun` was in the list above for one wave: `ncfg_apply_supported` refused
 * one because the executor had no path for it, so the planner declined the
 * device and warned. The executor has a path now -- `create_link` hands a tun
 * to `ncfg_tun_create` rather than building a netlink message -- and **nothing
 * in `src/plan/` changed**, because that file asks the executor instead of
 * keeping a list of its own. This is the check that says so; if it goes red,
 * either the executor has stopped being able to make one or the planner has
 * grown the second list `plan/link.c`'s comment refuses.
 *
 * **Four more joined it the wave `link.create` learned the model's
 * numbering**, and they are the four that were in the list above until then.
 * Each is here for the same reason and proves the same thing twice over: the
 * vlan, whose ethertype `document.h` had deliberately not published; the bond
 * and the macvlan, whose modes it had; and the tunnel, whose kind word it had.
 * Not one line of `src/plan/` moved for any of them.
 */
static void a_kind_this_build_can_create_again_is_planned(void)
{
	static const struct {
		const char *body;
		const char *what;
	} bodies[] = {
		{ "{\"name\":\"tap0\",\"kind\":{\"kind\":\"tun\",\"mode\":\"tap\"}}", "a tun" },
		{ "{\"name\":\"new0\",\"kind\":{\"kind\":\"bond\",\"members\":[],"
		  "\"mode\":\"802.3ad\",\"miimon\":100}}", "a bond" },
		{ "{\"name\":\"new0\",\"kind\":{\"kind\":\"macvlan\","
		  "\"parent\":\"eth0\",\"mode\":\"bridge\"}}", "a macvlan" },
		{ "{\"name\":\"new0\",\"kind\":{\"kind\":\"vlan\",\"parent\":\"eth0\","
		  "\"id\":42,\"protocol\":\"dot1ad\"}}", "a vlan" },
		{ "{\"name\":\"new0\",\"kind\":{\"kind\":\"tunnel\",\"mode\":\"gre\","
		  "\"local\":\"192.0.2.1\",\"remote\":\"192.0.2.2\"}}", "a tunnel" }
	};
	int    every_kind_planned = 1;
	int    nothing_declined = 1;
	size_t i;

	for (i = 0; i < sizeof(bodies) / sizeof(bodies[0]); i++) {
		ncfg_document_t *document = NULL;
		ncfg_observed_t *observed = NULL;
		ncfg_plan_t     *plan;

		plan = planfix_plan(bodies[i].body, "", "", "", "\"links\":[]", &document,
		    &observed);
		if (!plan) {
			check(0, "the fixture compiles");
			planfix_release(plan, document, observed);
			continue;
		}
		if (planfix_count(plan, "link.create") != 1u) {
			printf("  %s is not planned as a creation\n", bodies[i].what);
			every_kind_planned = 0;
		}
		if (planfix_warned(plan, "cannot create it")) {
			printf("  %s is still being declined\n", bodies[i].what);
			nothing_declined = 0;
		}
		planfix_release(plan, document, observed);
	}
	check(every_kind_planned,
	    "a kind the executor can make again is planned as a creation");
	check(nothing_declined,
	    "  and the planner has stopped declining it, without being told twice");
}

int main(void)
{
	every_bridge_setting_is_compared();
	a_kind_this_build_cannot_create_is_warned_about();
	a_kind_this_build_can_create_again_is_planned();
	a_bridge_setting_the_document_omits_is_not_compared();
	a_bond_mode_moves_on_a_bond_with_no_members();
	a_bond_with_members_is_told_rather_than_tried();
	a_mode_netcfgd_cannot_name_is_not_corrected();
	a_macvlan_moves_among_the_three_modes_the_kernel_takes();
	a_macvlan_passthru_transition_is_told_rather_than_tried();
	a_tunnel_endpoint_is_corrected();
	an_endpoint_is_compared_as_an_address_and_not_as_text();
	a_geneve_id_is_told_and_the_remote_beside_it_is_still_corrected();
	a_geneve_remote_changing_family_stops_the_pass();
	the_kernels_own_fallback_tunnel_is_refused_by_name();
	a_vxlan_id_and_port_are_told_and_the_endpoints_are_corrected();
	a_converged_vxlan_plans_nothing();
	a_configured_port_owns_its_vlan_list();
	wrong_vlan_flags_are_corrected();
	an_unmentioned_port_keeps_its_vlans();
	a_port_with_no_interface_block_still_gets_its_vlans();
	a_link_the_kernel_will_not_change_is_remade();
	a_link_netcfgd_did_not_make_is_explained_rather_than_remade();
	a_port_about_to_be_created_still_drops_the_kernels_own_vlan();
	vlans_on_a_device_in_no_bridge_are_said_once();
	a_vlan_on_the_bridge_itself_is_a_self_operation();
	a_converged_port_plans_nothing();

	printf("plan_kind_test: %d checks, %d failed\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
