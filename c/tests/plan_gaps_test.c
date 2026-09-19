/*
 * plan_gaps_test.c -- the four blocks the planner used to warn about instead
 * of acting on, and the ones it still warns about for a different reason.
 *
 * WHAT THIS FILE IS REALLY CHECKING
 *   `build.c`'s `warn_unported` held seven arms, each one a sentence telling
 *   an operator that this build of the planner reads their block and does
 *   nothing with it. Four of them were port gaps -- the Rust plans an
 *   `advertise` block, a `dot1x` block, a `linkset`'s choice and
 *   `on_unmanage = "clear"`, and this build did not -- and those four are
 *   ported here, so their arms are gone and this file is what stands in their
 *   place. Three were not port gaps at all: a `probe` block and a `modem`
 *   block are read by the daemon rather than by the planner, and nothing in
 *   either language acts on a `bluetooth` block. Those three keep a warning
 *   and the warning had to stop claiming otherwise.
 *
 *   **A `network` block was the same question asked of five fields at once**,
 *   and the answer was four one way and one the other: its addressing, its
 *   routes, its `dns` policy and its hooks are read by nothing in either
 *   language, and its `metric` is a real port gap. One sentence covering both
 *   kinds could only be wrong about one of them, so there are two now.
 *
 *   **The wording is under test as much as the actions are, and that is the
 *   point rather than a flourish.** "This build of the planner does not act on
 *   it" is a promise that a later release will. Said about a feature nobody has
 *   written, it tells somebody to wait for something that is not coming; said
 *   about a block the daemon *does* act on, it is simply false. Both read as
 *   an operator's own configuration being ignored, and neither can be found by
 *   a check that only looks at what a plan does.
 *
 * THE PROPERTY UNDERNEATH ALL OF IT
 *   `plan.h` calls it load-bearing: **applying a plan twice produces an empty
 *   second plan.** Every pass added here compares something it computed
 *   against something the machine reported, and each comparison is a place a
 *   plan can start adding and removing the same object for ever. So each of
 *   the four has a case that plans the action and a case that plans *nothing*
 *   against an observation carrying the result.
 *
 * NOTHING HERE TOUCHES A MACHINE
 *   Planning is a pure function of a document and an observation, both written
 *   as JSON and read by the readers a daemon uses. No socket, no radio, no
 *   file, nothing under `/tmp` -- which is what lets this run on a workstation
 *   whose network must not be disturbed.
 */
#include "planfix.h"

#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

static void check(int condition, const char *what)
{
	checks++;
	printf("%-74s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

static int has_name(const ncfg_plan_t *plan, const char *name)
{
	return plan && planfix_action(plan, name) != NULL;
}

/* Where the first action of this name sits, or a number past every action so
 * that "before" comparisons fail rather than pass by accident. */
static size_t position(const ncfg_plan_t *plan, const char *name)
{
	size_t i;

	for (i = 0; i < plan->action_count; i++) {
		if (strcmp(ncfg_op_name(&plan->actions[i].op), name) == 0) {
			return i;
		}
	}
	return plan->action_count + 1u;
}

/* Print what a plan holds, so a failure says what happened rather than only
 * that something did. */
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
 * `advertise`
 * ------------------------------------------------------------------------ */

#define LAN_DEVICE "{\"name\":\"lan0\",\"kind\":{\"kind\":\"physical\"}}"

#define ADVERTISING_LAN \
	"{\"name\":\"lan0\",\"addressing\":[],\"advertise\":{\"backend\":\"radvd\"," \
	"\"prefixes\":[{\"source\":\"wan0\",\"index\":0,\"subnet\":1}]}}"

#define PLAIN_LAN "{\"name\":\"lan0\",\"addressing\":[]}"

/* A delegation on the *other* interface, which is where an `advertise` block's
 * prefix comes from. `subnet` 1 of `2001:db8:0:100::/56` is `2001:db8:0:101::`,
 * and `::/64` is the suffix because what is advertised is the block rather
 * than an address in it. */
#define DELEGATION "\"delegations\":[{\"interface\":\"wan0\"," \
	"\"prefixes\":[\"2001:db8:0:100::/56\"]}]"

#define RADVD(advertised) \
	"\"backends\":[{\"kind\":\"router_advert\",\"interface\":\"lan0\"," \
	"\"running\":true,\"advertised\":[" advertised "]}]"

static void a_prefix_that_has_not_arrived_starts_nothing(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = planfix_plan(LAN_DEVICE, ADVERTISING_LAN, "", "",
	    "\"links\":[" PLANFIX_LINK("lan0", "") "]", &document, &observed);

	/*
	 * An action that must fail, planned before the one that would make it
	 * succeed, stops the apply and takes the rest with it -- and here the rest
	 * is the DHCPv6 client on the interface whose delegation this is waiting
	 * for, so the router would never have come up at all.
	 */
	check(plan && !has_name(plan, "backend.start"),
	    "an `advertise` block with no delegation yet starts no daemon");
	check(plan && planfix_warned(plan, "waiting on a delegated prefix from wan0"),
	    "and says which interface it is waiting on, rather than nothing");
	planfix_release(plan, document, observed);
}

static void a_delegated_prefix_starts_the_daemon(void)
{
	ncfg_document_t      *document;
	ncfg_observed_t      *observed;
	ncfg_plan_t          *plan = planfix_plan(LAN_DEVICE, ADVERTISING_LAN, "", "",
	    "\"links\":[" PLANFIX_LINK("lan0", "") "]," DELEGATION, &document, &observed);
	const ncfg_action_t  *start;

	start = plan ? planfix_for_field(plan, "backend.start", "advertise") : NULL;
	check(start != NULL, "a delegation that has arrived starts the advertisement daemon");
	check(start && start->reason.interface && strcmp(start->reason.interface, "lan0") == 0,
	    "and the reason names the interface the block is on");
	check(plan && !planfix_warned(plan, "does not act on it"),
	    "and the block is no longer reported as one this build reads and ignores");
	planfix_release(plan, document, observed);
}

static void the_daemon_waits_for_the_addressing(void)
{
	ncfg_document_t     *document;
	ncfg_observed_t     *observed;
	ncfg_plan_t         *plan = planfix_plan(LAN_DEVICE,
	    "{\"name\":\"lan0\",\"addressing\":[{\"source\":\"static\","
	    "\"address\":\"2001:db8:0:101::1/64\"}],\"advertise\":{\"backend\":\"radvd\","
	    "\"prefixes\":[{\"source\":\"wan0\",\"index\":0,\"subnet\":1}]}}", "", "",
	    "\"links\":[" PLANFIX_LINK("lan0", "") "]," DELEGATION, &document, &observed);
	const ncfg_action_t *start;
	const ncfg_action_t *added;

	start = plan ? planfix_for_field(plan, "backend.start", "advertise") : NULL;
	added = plan ? planfix_action(plan, "addr.add") : NULL;
	check(start && added && planfix_depends_on(start, added->id),
	    "the daemon waits for the address, not races it: a router advertising a "
	    "prefix it does not hold");
	check(plan && position(plan, "addr.add") < position(plan, "backend.start"),
	    "and the list order says the same thing, for an executor that reads no edges");
	planfix_release(plan, document, observed);
}

static void a_daemon_already_announcing_the_right_block_is_left_alone(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = planfix_plan(LAN_DEVICE, ADVERTISING_LAN, "", "",
	    "\"links\":[" PLANFIX_LINK("lan0", "") "]," DELEGATION ","
	    RADVD("\"2001:db8:0:101::/64\""), &document, &observed);

	check(plan && quiet(plan), "applying an `advertise` block twice plans nothing the second time");
	planfix_release(plan, document, observed);
}

static void a_daemon_announcing_a_block_the_isp_took_back_is_reloaded(void)
{
	ncfg_document_t     *document;
	ncfg_observed_t     *observed;
	ncfg_plan_t         *plan = planfix_plan(LAN_DEVICE, ADVERTISING_LAN, "", "",
	    "\"links\":[" PLANFIX_LINK("lan0", "") "]," DELEGATION ","
	    RADVD("\"2001:db8:0:9::/64\""), &document, &observed);
	const ncfg_action_t *reload;

	/*
	 * The prefix is the one value here that arrives after the document does.
	 * An ISP that renumbers leaves a daemon announcing a block the upstream
	 * has taken back, every host on the LAN holds an address that does not
	 * route, and nothing in the document changed to say so.
	 */
	reload = plan ? planfix_for_field(plan, "backend.reload", "advertise.prefixes") : NULL;
	check(reload != NULL, "a renumbering the daemon has not been told about is a reload");
	check(reload && reload->reason.desired &&
	    strcmp(reload->reason.desired, "2001:db8:0:101::/64") == 0,
	    "and the reason carries the block that should be announced");
	check(reload && reload->reason.observed &&
	    strcmp(reload->reason.observed, "2001:db8:0:9::/64") == 0,
	    "and the one that is being announced instead");
	check(plan && !has_name(plan, "backend.start"),
	    "and it is a reload rather than a restart: nothing on the wire is disturbed");
	planfix_release(plan, document, observed);
}

static void a_daemon_the_document_stopped_asking_for_is_stopped(void)
{
	ncfg_document_t     *document;
	ncfg_observed_t     *observed;
	ncfg_plan_t         *plan = planfix_plan(LAN_DEVICE, PLAIN_LAN, "", "",
	    "\"links\":[" PLANFIX_LINK("lan0", "") "]," RADVD("\"2001:db8:0:101::/64\""),
	    &document, &observed);
	const ncfg_action_t *stop;

	/* The half that lands with the pass: a build that starts something and
	 * cannot stop it leaves a daemon announcing a prefix the document has
	 * forgotten. */
	stop = plan ? planfix_for_field(plan, "backend.stop", "advertise") : NULL;
	check(stop != NULL, "an `advertise` block that was deleted stops the daemon");
	check(stop && stop->reason.field && strcmp(stop->reason.field, "advertise") == 0,
	    "and names the block rather than `addressing`, which is a different line");
	planfix_release(plan, document, observed);
}

/* ------------------------------------------------------------------------ *
 * `dot1x`
 * ------------------------------------------------------------------------ */

#define PORT_DEVICE "{\"name\":\"eth0\",\"kind\":{\"kind\":\"physical\"}}"

#define DOT1X \
	"\"dot1x\":{\"method\":\"peap\",\"identity\":\"dave\"," \
	"\"password\":{\"provider\":\"file\",\"name\":\"dot1x\"}}"

#define DOT1X_PORT \
	"{\"name\":\"eth0\",\"addressing\":[{\"source\":\"dhcp4\"}]," DOT1X "}"

#define SUPPLICANT(iface) \
	"\"backends\":[{\"kind\":\"supplicant\",\"interface\":\"" iface "\",\"running\":true}]"

static void an_authenticating_port_gets_its_supplicant_first(void)
{
	ncfg_document_t     *document;
	ncfg_observed_t     *observed;
	ncfg_plan_t         *plan = planfix_plan(PORT_DEVICE, DOT1X_PORT, "", "",
	    "\"links\":[" PLANFIX_LINK("eth0", "") "]", &document, &observed);
	const ncfg_action_t *supplicant;
	const ncfg_action_t *client;

	supplicant = plan ? planfix_for_field(plan, "backend.start", "dot1x") : NULL;
	client = plan ? planfix_for_field(plan, "backend.start", "addressing[0]") : NULL;
	check(supplicant != NULL, "a `dot1x` block starts a supplicant");
	check(client != NULL, "and the DHCP client the same interface asks for is still planned");
	/*
	 * A port that has not authenticated drops everything, so a client started
	 * first spends its whole backoff sequence talking to a switch that is not
	 * listening -- and then reports a failure whose real cause is two steps
	 * earlier. Decision 0008.
	 */
	check(supplicant && client && planfix_depends_on(client, supplicant->id),
	    "and the client waits for it rather than talking to a port that drops everything");
	check(plan && !planfix_warned(plan, "a `dot1x` block is carried"),
	    "and the block is no longer reported as one this build reads and ignores");
	planfix_release(plan, document, observed);
}

static void a_supplicant_already_running_is_not_started_again(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = planfix_plan(PORT_DEVICE,
	    "{\"name\":\"eth0\",\"addressing\":[]," DOT1X "}", "", "",
	    "\"links\":[" PLANFIX_LINK("eth0", "") "]," SUPPLICANT("eth0"),
	    &document, &observed);

	check(plan && quiet(plan), "applying a `dot1x` block twice plans nothing the second time");
	planfix_release(plan, document, observed);
}

static void the_rule_that_keeps_a_supplicant_is_the_rule_that_starts_one(void)
{
	ncfg_document_t     *document;
	ncfg_observed_t     *observed;
	const ncfg_action_t *stop;
	ncfg_plan_t         *plan;

	/*
	 * **The two rules have to stay the same.** Wrong in the permissive
	 * direction leaves a supplicant nobody owns; wrong in the other direction
	 * is netcfgd starting one and killing it on every reconcile, for ever --
	 * which is what the Rust's idempotence gate caught the day
	 * `supplicant_wanted` did not know a kind existed.
	 */
	plan = planfix_plan(PORT_DEVICE, "{\"name\":\"eth0\",\"addressing\":[]}", "", "",
	    "\"links\":[" PLANFIX_LINK("eth0", "") "]," SUPPLICANT("eth0"),
	    &document, &observed);
	stop = plan ? planfix_for_field(plan, "backend.stop", "wifi/dot1x") : NULL;
	check(stop != NULL, "a supplicant on a port whose `dot1x` block went is stopped");
	check(stop && stop->reason.field && strcmp(stop->reason.field, "wifi/dot1x") == 0,
	    "and the reason names both blocks, because one process cannot be half wanted");
	planfix_release(plan, document, observed);

	/* A radio that has been given an access point is not a station, so a
	 * supplicant left from before the `access_point` block was written is
	 * unwanted -- without this arm the two backends would each be started by
	 * the pass that wants one and stopped by the pass that does not. */
	plan = planfix_plan("{\"name\":\"wlan0\",\"kind\":{\"kind\":\"physical\"},\"wifi\":{}}",
	    "{\"name\":\"wlan0\",\"addressing\":[]}", "",
	    ",\"access_points\":[{\"id\":\"home\",\"ssid\":\"6161\",\"device\":\"wlan0\","
	    "\"security\":{\"type\":\"owe\"}}]",
	    "\"links\":[" PLANFIX_LINK("wlan0", "") "]," SUPPLICANT("wlan0"),
	    &document, &observed);
	check(plan && has_name(plan, "backend.stop"),
	    "a supplicant on a radio that now runs an access point is stopped");
	planfix_release(plan, document, observed);
}

/* ------------------------------------------------------------------------ *
 * `linkset`
 * ------------------------------------------------------------------------ */

#define TWO_PORTS \
	"{\"name\":\"eth0\",\"kind\":{\"kind\":\"physical\"}}," \
	"{\"name\":\"eth1\",\"kind\":{\"kind\":\"physical\"}}"

#define TWO_ROUTED_PORTS \
	"{\"name\":\"eth0\",\"addressing\":[],\"routes\":[{\"destination\":\"default\"," \
	"\"via\":\"10.0.0.254\"}]}," \
	"{\"name\":\"eth1\",\"addressing\":[],\"routes\":[{\"destination\":\"default\"," \
	"\"via\":\"10.0.1.254\"}]}"

#define UPLINK_SET ",\"linksets\":[{\"name\":\"uplink\",\"members\":[\"eth0\",\"eth1\"]}]"

/* A link, with carrier or without. `PLANFIX_LINK` always has it. */
#define DARK_LINK(name) \
	"{\"name\":\"" name "\",\"index\":3,\"mtu\":1500,\"up\":true,\"carrier\":false," \
	"\"ownership\":\"unknown\"}"

static void only_the_member_a_set_chose_gets_its_routes(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = planfix_plan(TWO_PORTS, TWO_ROUTED_PORTS, "", UPLINK_SET,
	    "\"links\":[" PLANFIX_LINK("eth0", "") "," PLANFIX_LINK("eth1", "") "]",
	    &document, &observed);

	/*
	 * A set's whole meaning is that one member carries traffic at a time. A
	 * spare that keeps a default route at a worse metric is not a spare -- it
	 * is a second path the kernel falls back to without anything having
	 * decided that it works.
	 */
	check(plan && planfix_count(plan, "route.add") == 1u,
	    "a set with two members installs one member's routes and not the other's");
	check(plan && planfix_mentions(plan, "10.0.0.254"),
	    "and it is the one the set chose");
	check(plan && planfix_warned(plan, "`uplink` is using eth0, so eth1's routes are not "
	    "installed"),
	    "and the spare is told which set decided and what it decided on");
	check(plan && !planfix_warned(plan, "a `linkset`, whose choice would decide"),
	    "and the set is no longer reported as something this build reads and ignores");
	planfix_release(plan, document, observed);
}

static void a_spare_that_already_has_a_route_has_it_withdrawn(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = planfix_plan(TWO_PORTS, TWO_ROUTED_PORTS, "", UPLINK_SET,
	    "\"links\":[" PLANFIX_LINK("eth0", "") "," PLANFIX_LINK("eth1", "") "],"
	    "\"routes\":[{\"interface\":\"eth1\",\"destination\":\"default\","
	    "\"via\":\"10.0.1.254\",\"proto\":110,\"ownership\":\"ours\","
	    "\"origin\":\"static\"}]",
	    &document, &observed);

	/*
	 * Withholding alone leaves the route that was installed before the set
	 * changed its mind, at whatever metric it had -- which is the black hole
	 * the withholding exists to prevent, arriving by the other door.
	 */
	check(plan && has_name(plan, "route.del"),
	    "a route already installed on a spare is withdrawn, which is how a set switches");
	planfix_release(plan, document, observed);
}

static void a_set_with_nothing_it_can_use_says_so(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = planfix_plan(TWO_PORTS, TWO_ROUTED_PORTS, "", UPLINK_SET,
	    "\"links\":[" DARK_LINK("eth0") "," DARK_LINK("eth1") "]",
	    &document, &observed);

	/* Two different sentences for an operator, and the one that matters most
	 * is this: a set with nothing it can use is a machine with no uplink, and
	 * "the routes are not installed" without it reads as a decision rather
	 * than a failure. */
	check(plan && planfix_warned(plan, "`uplink` has nothing it can use"),
	    "a set whose members are all unusable says that, rather than naming a winner");
	check(plan && !has_name(plan, "route.add"),
	    "and installs nothing, since there is nothing to install it on");
	planfix_release(plan, document, observed);
}

/* ------------------------------------------------------------------------ *
 * `on_unmanage = "clear"`
 * ------------------------------------------------------------------------ */

#define CLEARING_VETH \
	"{\"name\":\"veth0\",\"kind\":{\"kind\":\"veth\",\"peer\":\"veth1\"}," \
	"\"managed\":false,\"on_unmanage\":\"clear\"}"

#define LEAVING_VETH \
	"{\"name\":\"veth0\",\"kind\":{\"kind\":\"veth\",\"peer\":\"veth1\"}," \
	"\"managed\":false,\"on_unmanage\":\"leave\"}"

/* The document asks for a *different* address from the one the machine holds,
 * deliberately: a forward pass that was not stopped would plan an `addr.add`
 * for it, which is what makes "plans nothing forward on it" a check rather
 * than a sentence about an empty list. */
#define CONFIGURED_VETH \
	"{\"name\":\"veth0\",\"addressing\":[{\"source\":\"static\"," \
	"\"address\":\"10.9.0.2/24\"}]}"

#define OURS_LINK(name) \
	"{\"name\":\"" name "\",\"index\":4,\"mtu\":1500,\"up\":true,\"carrier\":true," \
	"\"kind\":\"veth\",\"ownership\":\"ours\"}"

#define OUR_ADDRESS \
	"\"addresses\":[{\"interface\":\"veth0\",\"address\":\"10.9.0.1/24\"," \
	"\"proto\":110,\"ownership\":\"ours\",\"origin\":\"static\"}]"

static void clearing_removes_what_netcfgd_owns_and_then_the_device(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = planfix_plan(CLEARING_VETH, CONFIGURED_VETH, "", "",
	    "\"links\":[" OURS_LINK("veth0") "]," OUR_ADDRESS,
	    &document, &observed);

	check(plan && has_name(plan, "addr.del"),
	    "`on_unmanage = \"clear\"` withdraws an address carrying netcfgd's tag");
	/*
	 * **And the device itself.** This is project.md 10.16: the Rust filtered
	 * only the interface list, which was complete while a link's existence was
	 * stated there. 0155 moved that onto the device, `teardown_links` reads
	 * the device list, and a clearing device stayed in it -- so `clear`
	 * withdrew the addresses and left the device standing, which is the one
	 * thing it exists to take away.
	 */
	check(plan && has_name(plan, "link.delete"),
	    "and deletes the device, which is the half filtering only interfaces missed");
	check(plan && !has_name(plan, "addr.add"),
	    "and plans nothing forward on it: adding and removing in one plan is a loop");
	planfix_release(plan, document, observed);
}

static void clearing_a_machine_it_has_already_cleared_plans_nothing(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = planfix_plan(CLEARING_VETH, CONFIGURED_VETH, "", "", "\"links\":[]",
	    &document, &observed);

	/* A state rather than a transition, which is why nothing detects an edge:
	 * once there is nothing of netcfgd's left, there is nothing to do, for
	 * ever. */
	check(plan && quiet(plan), "and once it is done, every plan after it is empty");
	planfix_release(plan, document, observed);
}

static void leaving_is_still_leaving(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = planfix_plan(LEAVING_VETH, CONFIGURED_VETH, "", "",
	    "\"links\":[" OURS_LINK("veth0") "]," OUR_ADDRESS,
	    &document, &observed);

	check(plan && quiet(plan),
	    "`managed = false` on its own still touches nothing, including the teardown");
	check(plan && planfix_warned(plan, "netcfgd will not touch it"),
	    "and says so in the sentence that is true of it");
	check(plan && !planfix_warned(plan, "removes everything it owns on it"),
	    "and not in the one that is true of the other policy");
	planfix_release(plan, document, observed);
}

static void the_clearing_sentence_says_what_will_happen(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = planfix_plan(CLEARING_VETH, CONFIGURED_VETH, "", "",
	    "\"links\":[" OURS_LINK("veth0") "]," OUR_ADDRESS,
	    &document, &observed);

	check(plan && planfix_warned(plan, "removes everything it owns on it"),
	    "a clearing device is described by what clearing does");
	check(plan && planfix_warned(plan, "an empty one means it is done"),
	    "and tells the operator how to know when it has finished");
	check(plan && !planfix_warned(plan, "would empty the device of everything netcfgd owns; "
	    "this build leaves it instead"),
	    "and the sentence saying this build does not do it is gone");
	planfix_release(plan, document, observed);
}

/* ------------------------------------------------------------------------ *
 * The ones that are not port gaps
 * ------------------------------------------------------------------------ */

static void a_bluetooth_block_is_not_something_to_wait_for(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = planfix_plan("", "", "",
	    ",\"bluetooth\":[{\"id\":\"headphones\",\"address\":\"AA:BB:CC:DD:EE:FF\","
	    "\"profile\":\"a2dp-sink\",\"autoconnect\":true}]", "\"links\":[]", &document, &observed);

	/*
	 * Nothing pairs the device, connects it or brings a `pan` link up -- and
	 * nothing in the Rust does either, which is the half the old sentence left
	 * out. "This build of the planner does not act on it" reads as a port
	 * catching up, so an operator keeps the block and waits for a release that
	 * is not coming.
	 */
	check(plan && planfix_warned(plan, "nothing acts on it in the Rust either"),
	    "a `bluetooth` block is reported as a product gap and not as a port gap");
	check(plan && !planfix_warned(plan, "a `bluetooth` block is carried in the document and "
	    "this build of the planner"),
	    "and no longer as something a later build of this port will do");
	planfix_release(plan, document, observed);
}

static void a_probe_block_is_the_daemons_and_its_answer_is_acted_on(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = planfix_plan(PORT_DEVICE,
	    "{\"name\":\"eth0\",\"addressing\":[],\"preference\":10,"
	    "\"routes\":[{\"destination\":\"default\",\"via\":\"10.0.0.254\"}],"
	    "\"probe\":{\"command\":\"/bin/ping\",\"args\":[],\"interval\":30,"
	    "\"timeout\":5,\"down_after\":3,\"up_after\":2,\"require_lease\":false}}", "", "",
	    "\"links\":[{\"name\":\"eth0\",\"index\":2,\"mtu\":1500,\"up\":true,"
	    "\"carrier\":true,\"reachable\":false,\"ownership\":\"unknown\"}]",
	    &document, &observed);

	check(plan && planfix_warned(plan, "run by the daemon rather than by the planner"),
	    "a `probe` block is reported as the daemon's, which is whose it is");
	/*
	 * And the second half, which is the one the old sentence got backwards:
	 * the planner *does* act on a probe -- on its answer. Saying it did not
	 * was false about code that has been here since the addressing pass
	 * landed.
	 */
	check(plan && !has_name(plan, "route.add"),
	    "and the verdict is acted on: a failing probe withholds the routes");
	check(plan && !planfix_warned(plan, "a `probe` block, whose answer would decide"),
	    "so the sentence promising that it would one day is gone");
	planfix_release(plan, document, observed);
}

static void a_modem_block_is_the_daemons_and_the_gap_is_named_exactly(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = planfix_plan(
	    "{\"name\":\"wwan0\",\"kind\":{\"kind\":\"physical\"},"
	    "\"modem\":{\"sim\":[\"esim\",\"socket\"],\"apn\":\"im.cxn\"}}",
	    "{\"name\":\"wwan0\",\"addressing\":[]}", "", "",
	    "\"links\":[" PLANFIX_LINK("wwan0", "") "]", &document, &observed);

	check(plan && planfix_warned(plan, "the daemon's SIM selection"),
	    "a `modem` block is reported as the daemon's, which is whose it is");
	check(plan && planfix_warned(plan, "cannot yet be asked to cycle the link"),
	    "and the part that really is missing here is named exactly rather than in general");
	planfix_release(plan, document, observed);
}

/*
 * Link-local addressing, which had the right judgement over the wrong sentence.
 *
 * The comment on the arm said in as many words that this is "the product's gap
 * rather than the port's", and the sentence under it -- kept because it is the
 * Rust's own -- told the operator their configuration was "not yet applied by
 * **this build**". Both cannot be true, and a reader gets the one addressed to
 * them. Re-checked against `crates/`: `lib.rs:4033` is the same warning on the
 * same arm, and `AddressSource::LinkLocal` has no reader outside the model and
 * the compiler in either language.
 */
static void link_local_addressing_is_not_something_to_wait_for(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = planfix_plan(PORT_DEVICE,
	    "{\"name\":\"eth0\",\"addressing\":[{\"source\":\"link_local\"}]}", "", "",
	    "\"links\":[" PLANFIX_LINK("eth0", "") "]", &document, &observed);

	check(plan && planfix_warned(plan, "nothing claims an RFC 3927 `169.254.0.0/16` address"),
	    "link-local addressing is named by what nobody does with it");
	check(planfix_whole(planfix_warning_with(plan, "link-local addressing is accepted"),
	    PLANFIX_UNBUILT_TAIL),
	    "and marked as nobody's gap, in a sentence that arrives whole");
	check(plan && !planfix_warned(plan, "not yet applied by this build"),
	    "and no longer as a release this port owes anybody");
	planfix_release(plan, document, observed);
}

/*
 * The half of an `ethtool` block nothing encodes, which is neither language's
 * to have encoded.
 *
 * **The reason was in the sentence and the blame was not.** "Recognised but not
 * applied by this build" sat immediately before the reason it will stay that
 * way -- that ring sizes, link modes and wake-on-LAN can only be exercised
 * against a physical NIC -- so the same sentence promised a release and
 * explained why there is not one. `crates/netcfgd-sys/src/ethtool.rs` defines
 * `ETHTOOL_MSG_FEATURES_GET` and `..._SET` and nothing else, which is what
 * `c/include/ncfg/ethtool.h` carries: the encoder does not exist on either
 * side.
 *
 * Six fields at once, because that is the longest this sentence gets and it is
 * the case that runs into `NCFG_ERROR_MAX`.
 */
static void the_ethtool_fields_nothing_encodes_are_not_something_to_wait_for(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = planfix_plan(
	    "{\"name\":\"eth0\",\"kind\":{\"kind\":\"physical\"},\"link_settings\":{"
	    "\"autoneg\":\"on\",\"speed\":1000,\"duplex\":\"full\",\"wol\":\"g\","
	    "\"rx_ring\":512,\"tx_ring\":512,\"gro\":\"on\"}}",
	    "{\"name\":\"eth0\",\"addressing\":[]}", "", "",
	    "\"links\":[" PLANFIX_LINK("eth0", "") "]", &document, &observed);

	check(plan && planfix_warned(plan,
	    "`autoneg`, `speed`, `duplex`, `wol`, `rx_ring`, `tx_ring` in the `ethtool` block"),
	    "every field the document stated is named, in the order the block lists them");
	check(planfix_whole(planfix_warning_with(plan, "in the `ethtool` block"),
	    PLANFIX_UNBUILT_TAIL),
	    "and the whole of the longest form arrives, marked as nobody's gap");
	check(plan && !planfix_warned(plan, "not applied by this build"),
	    "and not as a release this port owes anybody");
	/* That the sentence names only what was written, and that a block of
	 * offloads alone says nothing at all, is `plan_tc_test.c`'s -- the pass
	 * that owns the offloads owns the rule about naming them. What is here is
	 * the part that file cannot see: whose gap the other half is. */
	planfix_release(plan, document, observed);
}

/* ------------------------------------------------------------------------ *
 * A `network` block, which was four of one and one of the other
 * ------------------------------------------------------------------------ */

/*
 * The five things the wifi planner's own sentence named, and what each turned
 * out to be.
 *
 * It said a network's "addressing, routes, `dns` policy, hooks and metric" were
 * carried and not acted on by *this build of the planner*, which is the promise
 * the whole of this file is about. Four of the five are not this port's to
 * keep: nothing in either language reads a network's addressing, its routes or
 * its `dns` policy -- the Rust's passes all read an *interface*'s, and
 * `netcfgd_model::dns::scopes` builds its scope list from the globals and the
 * interfaces -- and a hook on a network is run at no phase, which the Rust says
 * itself in `warn_unfired_hooks`. The fifth, `metric`, really is missing here.
 *
 * So the wording is what these cases check, for the reason this file's header
 * gives: a sentence that tells an operator to wait for a release is checkable
 * only against whether there is a release to wait for.
 */

/* `warning_with` and `whole` used to stand here. They moved to `planfix.h`
 * when two more files needed them: three warnings now go through
 * `ncfg_plan_warn_unbuilt`, whose 196-character tail is what a cut takes
 * first, so checking a sentence by its last words stopped being this file's
 * private trick. */

/*
 * The widest id the model allows, because that is what these sentences have to
 * fit around: an SSID is up to 32 octets, and a network naming one that is not
 * valid text carries it as 64 hex characters. A case written with `office` in
 * it would prove the wording fits for six.
 */
#define WIDEST_ID "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

#define STATED_NETWORK \
	"{\"id\":\"" WIDEST_ID "\",\"security\":{\"type\":\"open\"}," \
	"\"addressing\":[{\"source\":\"static\",\"address\":\"10.0.0.8/24\"}]," \
	"\"routes\":[{\"destination\":\"default\",\"via\":\"10.0.0.254\"}]," \
	"\"dns\":{\"servers\":[{\"addr\":\"10.0.0.1\"}]}," \
	"\"hooks\":[{\"phase\":\"up\",\"path\":\"/run/netcfgd/hooks/o\",\"sha256\":\"ab\"}]}"

static void what_a_network_states_and_nothing_reads_is_not_something_to_wait_for(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = planfix_plan("", "", STATED_NETWORK, "", "\"links\":[]",
	    &document, &observed);

	check(plan && planfix_warned(plan,
	    "states addressing, `routes`, a `dns` policy and hooks"),
	    "a network's four inert halves are named, and only the ones it states");
	check(plan && planfix_warned(plan, "nothing acts on it in the Rust either"),
	    "and reported as a product gap rather than as a port gap");
	check(planfix_whole(planfix_warning_with(plan, "states addressing"),
	    "still means this when the code arrives"),
	    "and the whole sentence arrives, at the widest id the model allows");
	/*
	 * The two halves of the old sentence, each wrong on its own. The first
	 * promised a later release; the second described the op rather than what
	 * happens -- every network in the document reaches the supplicant, and its
	 * metric with it, as `priority`.
	 */
	check(plan && !planfix_warned(plan, "this build of the planner does not act on them"),
	    "and no longer as something a later build of this port will do");
	check(plan && !planfix_warned(plan, "only the set of network ids"),
	    "and no longer claims the supplicant is given nothing but the ids");
	planfix_release(plan, document, observed);
}

/*
 * The control, which is what keeps this quiet: the ordinary saved network --
 * an SSID and a credential -- states none of these and must say nothing at
 * all. `warn_device_policy` one function up has the same rule for the same
 * reason, and the old sentence had no such guard: it fired on every document
 * with a network in it.
 */
static void a_network_that_asks_for_none_of_it_says_nothing(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = planfix_plan("", "",
	    "{\"id\":\"home\",\"security\":{\"type\":\"open\"}}", "", "\"links\":[]",
	    &document, &observed);

	check(plan && !planfix_warned(plan, "nothing acts on it in the Rust either"),
	    "a network stating none of the inert halves is not warned about");
	check(plan && !planfix_warned(plan, "does not apply it"),
	    "and a network with no metric is not told about the metric that is missing");
	check(plan && plan->warning_count == 0u, "and the plan carries no warning at all");
	planfix_release(plan, document, observed);
}

/* One of the four, to prove the sentence names what was written rather than the
 * list it was drawn from -- which is the failure the `ethtool` warning's own
 * comment records and the reason it goes field by field. */
static void only_the_half_a_network_states_is_named(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = planfix_plan("", "",
	    "{\"id\":\"cafe\",\"security\":{\"type\":\"open\"},"
	    "\"dns\":{\"servers\":[{\"addr\":\"10.0.0.1\"}]}}", "", "\"links\":[]",
	    &document, &observed);

	check(plan && planfix_warned(plan,
	    "`cafe` states a `dns` policy, and nothing applies it: netcfgd plans"),
	    "a network stating one of the four is told about that one, in the singular");
	check(plan && !planfix_warned(plan, "states addressing"),
	    "and not about the three it did not write");
	planfix_release(plan, document, observed);
}

/*
 * `metric` no longer warns, because both halves of what it means are applied.
 *
 * **This case used to assert the warning and now asserts its absence**, which
 * is `build.c`'s rule rather than a deletion: a pass landing takes its warning
 * out in the same commit, and a warning that outlives the gap it describes
 * tells an operator a number they wrote is inert when it is not. The two
 * halves are checked for real by the cases below -- a route taking the
 * network's metric, and a client restarted when it is running with the old
 * one.
 *
 * The other four of the five still warn, and they are `warn_unbuilt`'s: a
 * network block's own addressing, routes, `dns` and hooks are read by nobody
 * in either language.
 */
static void a_networks_metric_no_longer_warns_because_it_is_applied(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = planfix_plan("", "",
	    "{\"id\":\"" WIDEST_ID "\",\"security\":{\"type\":\"open\"},\"metric\":100}", "",
	    "\"links\":[]", &document, &observed);

	check(plan && !planfix_warned(plan, "states `metric = 100`"),
	    "a network's metric is not reported as a gap, because it is applied");
	/*
	 * And nothing else started warning in its place. A network stating only a
	 * metric states none of the four `warn_unbuilt` covers, so a plan built
	 * from it should be quiet about this block entirely.
	 */
	check(plan && !planfix_warned(plan, WIDEST_ID),
	    "  and the block is not mentioned at all, since it states nothing else");
	planfix_release(plan, document, observed);
}

/*
 * The half that is no longer a gap: a route takes the metric of the network
 * the radio is associated to.
 *
 * **This is the check the warning above used to stand in for.** The rule is
 * `ncfg_observed_effective_metric`'s and it has three callers -- this pass, the
 * teardown arm that decides whether a route it sees is one of these, and the
 * daemon starting a DHCP client with `-m`. Two readings of it make the
 * comparison never match and the plan never converge, which is why the
 * sabotage for this one turns more than one file red.
 */
static void a_route_takes_the_metric_of_the_network_it_is_associated_to(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t         *plan;
	const ncfg_action_t *added;
	const char          *iface =
	    "{\"name\":\"wlan0\",\"addressing\":[{\"source\":\"static\","
	    "\"address\":\"10.0.0.2/24\"}],\"preference\":600,"
	    "\"routes\":[{\"destination\":\"default\",\"via\":\"10.0.0.1\"}]}";
	const char      *device = "{\"name\":\"wlan0\",\"kind\":{\"kind\":\"physical\"}}";
	const char      *associated =
	    "\"links\":[{\"name\":\"wlan0\",\"index\":2,\"mtu\":1500,\"up\":true,"
	    "\"carrier\":true,\"ownership\":\"unknown\",\"network\":\"cafe\"}]";

	plan = planfix_plan(device, iface,
	    "{\"id\":\"cafe\",\"security\":{\"type\":\"open\"},\"metric\":100}", "",
	    associated, &document, &observed);
	added = plan ? planfix_action(plan, "route.add") : NULL;
	check(added && added->op.u.route.route && added->op.u.route.route->metric.has &&
	    added->op.u.route.route->metric.value == 100,
	    "a radio associated to a network carrying a metric routes at the network's");
	check(added && added->op.u.route.route &&
	    added->op.u.route.route->metric.value != 600,
	    "  and not at the interface's preference, which is what it used to do");
	planfix_release(plan, document, observed);

	/*
	 * **A network with no metric of its own leaves the preference alone.**
	 * That is what the fallback means, and reading it as "the network's if
	 * there is a network" drops an operator's number because they also named
	 * an SSID.
	 */
	plan = planfix_plan(device, iface,
	    "{\"id\":\"cafe\",\"security\":{\"type\":\"open\"}}", "", associated,
	    &document, &observed);
	added = plan ? planfix_action(plan, "route.add") : NULL;
	check(added && added->op.u.route.route && added->op.u.route.route->metric.has &&
	    added->op.u.route.route->metric.value == 600,
	    "and a network with no metric of its own leaves the preference exactly as it was");
	planfix_release(plan, document, observed);

	/* A route that states its own is overridden by neither: what an operator
	 * wrote on the route is the most specific thing there is. */
	plan = planfix_plan(device,
	    "{\"name\":\"wlan0\",\"addressing\":[{\"source\":\"static\","
	    "\"address\":\"10.0.0.2/24\"}],\"preference\":600,"
	    "\"routes\":[{\"destination\":\"default\",\"via\":\"10.0.0.1\","
	    "\"metric\":7}]}",
	    "{\"id\":\"cafe\",\"security\":{\"type\":\"open\"},\"metric\":100}", "",
	    associated, &document, &observed);
	added = plan ? planfix_action(plan, "route.add") : NULL;
	check(added && added->op.u.route.route && added->op.u.route.route->metric.has &&
	    added->op.u.route.route->metric.value == 7,
	    "and a route that states its own metric is overridden by neither");
	planfix_release(plan, document, observed);
}

/* ------------------------------------------------------------------------ *
 * A client already running with the wrong metric
 * ------------------------------------------------------------------------ */

/*
 * The other half of what a network's `metric` means, and the half netcfgd
 * cannot do by editing anything: the lease's own route is installed by the
 * client from what it was started with, so the only way to move it is to start
 * the client again.
 */
#define METRIC_DEVICE "{\"name\":\"wlan0\",\"kind\":{\"kind\":\"physical\"}}"
#define METRIC_IFACE \
	"{\"name\":\"wlan0\",\"addressing\":[{\"source\":\"dhcp4\"}]," \
	"\"preference\":600}"
#define METRIC_NETWORK \
	"{\"id\":\"cafe\",\"security\":{\"type\":\"open\"},\"metric\":100}"
#define METRIC_LINK \
	"{\"name\":\"wlan0\",\"index\":2,\"mtu\":1500,\"up\":true,\"carrier\":true," \
	"\"ownership\":\"unknown\",\"network\":\"cafe\"}"
/* A lease route the kernel stamped with the DHCP protocol, at `metric`. */
#define METRIC_LEASE_ROUTE(metric) \
	"\"routes\":[{\"interface\":\"wlan0\",\"destination\":\"default\"," \
	"\"via\":\"10.0.0.1\",\"metric\":" metric ",\"proto\":16," \
	"\"ownership\":\"unknown\"}]"

static void a_client_installing_the_old_metric_is_restarted(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = planfix_plan(METRIC_DEVICE, METRIC_IFACE, METRIC_NETWORK, "",
	    "\"links\":[" METRIC_LINK "],"
	    "\"backends\":[{\"kind\":\"dhcp4\",\"interface\":\"wlan0\","
	    "\"running\":true}]," METRIC_LEASE_ROUTE("600"), &document, &observed);

	/*
	 * The route says what the client *did*, which is the half that catches one
	 * that ignored what it was told. 600 is the interface's preference, which
	 * is what it would have been started with before the network was joined.
	 */
	check(plan && planfix_count(plan, "backend.stop") == 1u &&
	    planfix_count(plan, "backend.start") == 1u,
	    "a lease route carrying the old metric restarts the client, stop then start");
	/*
	 * **The edge, not just the order.** A first draft asserted only that the
	 * stop came first in the list, and removing the dependency entirely left
	 * that green -- the list order happens to be the push order. An executor
	 * that reads `depends_on` and parallelises would have started a second
	 * client beside the one being stopped, both retrying for ever.
	 */
	{
		const ncfg_action_t *stop = plan ? planfix_action(plan, "backend.stop") : NULL;
		const ncfg_action_t *start = plan ? planfix_action(plan, "backend.start") : NULL;

		check(stop && start && planfix_depends_on(start, stop->id),
		    "  and the start waits on the stop by an edge, not by list order alone");
	}
	check(plan && position(plan, "backend.stop") < position(plan, "backend.start"),
	    "  and the list order says the same, for an executor that reads no edges");
	check(plan && planfix_warned(plan, "the lease is dropped for as long as the exchange"),
	    "  and the cost is said out loud, since a restart takes the network away");
	check(plan && planfix_warned(plan, "metric 100 rather than 600"),
	    "  naming what is wanted and what is there, both read off the machine");
	planfix_release(plan, document, observed);
}

static void a_client_started_with_the_old_metric_is_restarted_before_any_route(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	/*
	 * **No route at all, which is the half the route cannot answer.** A client
	 * that has not finished its first exchange has installed nothing, and
	 * `started_metric` is read out of its own `argv` at the moment it started
	 * -- so this is there at once and the route is not.
	 */
	ncfg_plan_t     *plan = planfix_plan(METRIC_DEVICE, METRIC_IFACE, METRIC_NETWORK, "",
	    "\"links\":[" METRIC_LINK "],"
	    "\"backends\":[{\"kind\":\"dhcp4\",\"interface\":\"wlan0\","
	    "\"running\":true,\"started_metric\":600}]", &document, &observed);

	check(plan && planfix_count(plan, "backend.stop") == 1u,
	    "a client started with the old metric is restarted before it has routed");
	planfix_release(plan, document, observed);
}

static void a_client_already_carrying_the_metric_is_left_alone(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = planfix_plan(METRIC_DEVICE, METRIC_IFACE, METRIC_NETWORK, "",
	    "\"links\":[" METRIC_LINK "],"
	    "\"backends\":[{\"kind\":\"dhcp4\",\"interface\":\"wlan0\","
	    "\"running\":true,\"started_metric\":100}]," METRIC_LEASE_ROUTE("100"),
	    &document, &observed);

	/* **The convergence check.** Both answers agree with what is wanted, so a
	 * second apply of a converged machine plans nothing -- which is the
	 * property `plan.h` names load-bearing, and the one a restart pass is
	 * most likely to break. */
	check(plan && planfix_count(plan, "backend.stop") == 0u,
	    "a client already carrying the metric is left alone, so the plan converges");
	planfix_release(plan, document, observed);
}

static void a_client_that_will_not_take_it_is_left_alone_after_the_cap(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = planfix_plan(METRIC_DEVICE, METRIC_IFACE, METRIC_NETWORK, "",
	    "\"links\":[" METRIC_LINK "],"
	    "\"backends\":[{\"kind\":\"dhcp4\",\"interface\":\"wlan0\","
	    "\"running\":true}],"
	    "\"backend_restarts\":[[\"dhcp4\",\"wlan0\",9]],"
	    METRIC_LEASE_ROUTE("600"), &document, &observed);

	/*
	 * **0079's cap, and it matters more here than anywhere else it applies.**
	 * A client that will not take the metric -- an operator's own
	 * `dhcpcd.conf` overriding it, say -- would otherwise be stopped and
	 * started on every reconcile for ever, and each round drops the lease. A
	 * machine whose network goes away every five seconds is worse than one
	 * whose route ranks wrongly.
	 */
	check(plan && planfix_count(plan, "backend.stop") == 0u,
	    "past the restart cap the client is left alone rather than looped on");
	check(plan && planfix_warned(plan, "leaving it alone rather than looping"),
	    "  and the plan says so, with the count that stopped it");
	planfix_release(plan, document, observed);
}

static void an_interface_asking_for_no_lease_is_not_restarted(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	/*
	 * A static interface whose network names a metric -- **and a dhcp4 client
	 * running on it anyway**, which is what makes this check the addressing
	 * and not something else. A first draft left the backend list empty, so
	 * the "is one running" guard declined it and removing the addressing guard
	 * entirely left the check green: it was passing for the wrong reason.
	 *
	 * A client running on an interface whose document asks for no lease is an
	 * ordinary machine, not a contrived one: it is what netcfgd's own teardown
	 * is about to stop.
	 */
	ncfg_plan_t     *plan = planfix_plan(METRIC_DEVICE,
	    "{\"name\":\"wlan0\",\"addressing\":[{\"source\":\"static\","
	    "\"address\":\"10.0.0.2/24\"}],\"preference\":600}",
	    METRIC_NETWORK, "", "\"links\":[" METRIC_LINK "],"
	    "\"backends\":[{\"kind\":\"dhcp4\",\"interface\":\"wlan0\","
	    "\"running\":true,\"started_metric\":600}]," METRIC_LEASE_ROUTE("600"),
	    &document, &observed);

	/*
	 * **Asserted on the restart and not on `backend.stop`**, because there is
	 * legitimately one of those: the teardown stops a client the document no
	 * longer asks for, which is right and is a different pass. A first draft
	 * counted stops and went red against correct behaviour.
	 */
	check(plan && planfix_count(plan, "backend.start") == 0u,
	    "an interface asking for no lease is not restarted over a route it did not ask for");
	check(plan && !planfix_warned(plan, "the lease is dropped for as long as the exchange"),
	    "  and nothing says a restart is happening, because none is");
	planfix_release(plan, document, observed);
}

int main(void)
{
	a_prefix_that_has_not_arrived_starts_nothing();
	a_delegated_prefix_starts_the_daemon();
	the_daemon_waits_for_the_addressing();
	a_daemon_already_announcing_the_right_block_is_left_alone();
	a_daemon_announcing_a_block_the_isp_took_back_is_reloaded();
	a_daemon_the_document_stopped_asking_for_is_stopped();

	an_authenticating_port_gets_its_supplicant_first();
	a_supplicant_already_running_is_not_started_again();
	the_rule_that_keeps_a_supplicant_is_the_rule_that_starts_one();

	only_the_member_a_set_chose_gets_its_routes();
	a_spare_that_already_has_a_route_has_it_withdrawn();
	a_set_with_nothing_it_can_use_says_so();

	clearing_removes_what_netcfgd_owns_and_then_the_device();
	clearing_a_machine_it_has_already_cleared_plans_nothing();
	leaving_is_still_leaving();
	the_clearing_sentence_says_what_will_happen();

	a_bluetooth_block_is_not_something_to_wait_for();
	link_local_addressing_is_not_something_to_wait_for();
	the_ethtool_fields_nothing_encodes_are_not_something_to_wait_for();
	a_probe_block_is_the_daemons_and_its_answer_is_acted_on();
	a_modem_block_is_the_daemons_and_the_gap_is_named_exactly();

	what_a_network_states_and_nothing_reads_is_not_something_to_wait_for();
	a_network_that_asks_for_none_of_it_says_nothing();
	only_the_half_a_network_states_is_named();
	a_networks_metric_no_longer_warns_because_it_is_applied();
	a_route_takes_the_metric_of_the_network_it_is_associated_to();
	a_client_installing_the_old_metric_is_restarted();
	a_client_started_with_the_old_metric_is_restarted_before_any_route();
	a_client_already_carrying_the_metric_is_left_alone();
	a_client_that_will_not_take_it_is_left_alone_after_the_cap();
	an_interface_asking_for_no_lease_is_not_restarted();

	printf("plan gaps: %d checks, %d failed\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
