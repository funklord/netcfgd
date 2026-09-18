/*
 * plan_radio_test.c -- the supplicant a wireless radio needs: started, not
 * started twice, and stopped.
 *
 * WHAT THESE ARE FOR
 *   **A machine whose wifi is an ordinary WPA network cannot come up without
 *   this pass**, which is why the gap it closes was worth a wave of its own:
 *   the planner started a supplicant for a wired 802.1X port and for nothing
 *   else, so a laptop with one radio and a `network` block got a `link.up`, no
 *   supplicant and no explanation.
 *
 *   The cases here are mostly about the *other* direction, because that is
 *   where the cost is. A supplicant started beside a hostapd on one phy, or a
 *   second one started beside the `dot1x` one, is two processes fighting over
 *   a radio; and a rule that starts one while the teardown does not want it is
 *   netcfgd starting a supplicant and killing it on every reconcile, for ever
 *   -- which is what the Rust's idempotence gate caught the day
 *   `supplicant_wanted` did not know a kind existed. So every start case has
 *   its teardown case beside it, and both are asked of one rule.
 *
 * WHAT A FIXTURE IS
 *   `planfix.h`'s: two JSON documents and nothing else. Nothing here touches a
 *   radio, talks to a supplicant, opens a socket or writes a file -- a plan is
 *   a pure function of a document and an observation, which is what lets this
 *   suite run on a workstation whose network must not be disturbed.
 */
/* The rule itself, which is not in the planner's public face: two of its
 * conditions produce the same plan whether or not it knows about them, and a
 * check that cannot see a condition is not a check on it. */
#include "../src/plan/plan_internal.h"
#include "planfix.h"

#include <stdio.h>

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

/* A plan that should have nothing in it, printing what it had if it does. */
static int quiet(const ncfg_plan_t *plan)
{
	char names[512];

	if (plan && ncfg_plan_is_empty(plan)) {
		return 1;
	}
	if (plan) {
		planfix_names(plan, names, sizeof(names));
		printf("  expected nothing to do; the plan is [%s]\n", names);
	}
	return 0;
}

/* A device the document says is a radio, and one it says nothing about. */
#define RADIO_DEVICE "{\"name\":\"wlan0\",\"kind\":{\"kind\":\"physical\"},\"wifi\":{}}"
#define UNMANAGED_RADIO_DEVICE \
	"{\"name\":\"wlan0\",\"kind\":{\"kind\":\"physical\"},\"managed\":false,\"wifi\":{}}"
#define PLAIN_DEVICE "{\"name\":\"wlan0\",\"kind\":{\"kind\":\"physical\"}}"

#define INTERFACE "{\"name\":\"wlan0\",\"addressing\":[]}"
#define ADDRESSED_INTERFACE \
	"{\"name\":\"wlan0\",\"addressing\":[{\"source\":\"static\"," \
	"\"address\":\"192.168.4.2/24\"}]}"
#define DOT1X_INTERFACE \
	"{\"name\":\"wlan0\",\"addressing\":[],\"dot1x\":{\"method\":\"peap\"," \
	"\"identity\":\"dave\",\"password\":{\"provider\":\"file\",\"name\":\"dot1x\"}}}"

/*
 * The kernel's answer, which is the half a `device` block cannot supply: a
 * `wifi { }` section is not a statement that the interface is a radio, and
 * `tests/live/portal.sh` puts one on a dummy.
 */
#define RADIO_LINK PLANFIX_LINK("wlan0", ",\"wireless\":true")
#define WIRED_LINK PLANFIX_LINK("wlan0", "")
/* A radio the kernel has and has not brought up, so `link.up` is planned and
 * something can be shown to wait for it. */
#define DOWN_RADIO_LINK \
	"{\"name\":\"wlan0\",\"index\":2,\"mtu\":1500,\"up\":false,\"carrier\":true," \
	"\"ownership\":\"unknown\",\"wireless\":true}"

#define ACCESS_POINT \
	",\"access_points\":[{\"id\":\"home\",\"ssid\":\"686f6d65\",\"device\":\"wlan0\"," \
	"\"security\":{\"type\":\"open\"}}]"

#define SUPPLICANT_RUNNING \
	"\"backends\":[{\"kind\":\"supplicant\",\"interface\":\"wlan0\",\"running\":true}]"

/* ------------------------------------------------------------------------ *
 * The start
 * ------------------------------------------------------------------------ */

static void a_radio_the_machine_has_gets_a_supplicant(void)
{
	ncfg_document_t     *document;
	ncfg_observed_t     *observed;
	ncfg_plan_t         *plan = planfix_plan(RADIO_DEVICE, INTERFACE, "", "",
	    "\"links\":[" DOWN_RADIO_LINK "]", &document, &observed);
	const ncfg_action_t *start = plan ? planfix_action(plan, "backend.start") : NULL;
	const ncfg_action_t *up = plan ? planfix_action(plan, "link.up") : NULL;

	check(start != NULL, "a managed radio the kernel reports starts a supplicant");
	check(start && start->op.u.backend.kind == NCFG_BACKEND_SUPPLICANT,
	    "as a supplicant rather than some other backend");
	/* The `device` block's `wifi`, not the interface's: that is where somebody
	 * would go to turn this off. */
	check(start && start->reason.field && strcmp(start->reason.field, "wifi") == 0,
	    "and the reason names the `wifi` block an operator would go and edit");
	check(start && start->reason.desired &&
	    strcmp(start->reason.desired, "supplicant") == 0,
	    "and says what is absent in the model's word for it");
	/* Rule 3: there is no interface for a supplicant to attach to before
	 * `link.up`, which is the same wait a DHCP client takes. */
	check(start && up && planfix_depends_on(start, up->id),
	    "and it waits for `link.up`, there being nothing to attach to before that");
	check(start && start->has_inverse && start->inverse.kind == NCFG_OP_BACKEND_STOP,
	    "and it can be undone, which is what commit-confirm reverts with");
	planfix_release(plan, document, observed);
}

/*
 * The addressing waits on it, which is the whole reason this is a prerequisite
 * and not an addressing action: a radio that has not associated carries
 * nothing, so a client started first spends its backoff talking to a network
 * this machine has not joined and then reports a failure whose cause is two
 * steps earlier.
 */
static void the_addressing_waits_for_the_supplicant(void)
{
	ncfg_document_t     *document;
	ncfg_observed_t     *observed;
	ncfg_plan_t         *plan = planfix_plan(RADIO_DEVICE, ADDRESSED_INTERFACE, "", "",
	    "\"links\":[" DOWN_RADIO_LINK "]", &document, &observed);
	const ncfg_action_t *start = plan ? planfix_action(plan, "backend.start") : NULL;
	const ncfg_action_t *address = plan ? planfix_action(plan, "addr.add") : NULL;

	check(start && address, "a radio with an address plans both the supplicant and the "
	    "address");
	check(start && address && planfix_depends_on(address, start->id),
	    "and the address waits for the supplicant rather than for a radio that has "
	    "joined nothing");
	/* `plan.h` says the action list is itself a valid execution order, so
	 * "before the addressing" has to mean earlier in the list as well. */
	check(start && address && start->id < address->id,
	    "and comes first in the list, which is itself a valid execution order");
	planfix_release(plan, document, observed);
}

static void a_supplicant_already_running_is_not_started_again(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = planfix_plan(RADIO_DEVICE, INTERFACE, "", "",
	    "\"links\":[" RADIO_LINK "]," SUPPLICANT_RUNNING, &document, &observed);

	check(quiet(plan), "applying a radio's configuration twice plans nothing the second time");
	planfix_release(plan, document, observed);
}

/* ------------------------------------------------------------------------ *
 * What is not a radio
 * ------------------------------------------------------------------------ */

/*
 * **Two facts from two places, and the document cannot supply the second.** A
 * `wifi { }` section carries `portal_check`, which is meaningful on anything,
 * so taking the block as a claim that the interface is a radio makes netcfgd
 * start a supplicant on a dummy -- which is what the Rust's live suite caught
 * and no unit test of its could.
 */
static void a_wifi_block_on_something_that_is_not_a_radio_starts_nothing(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = planfix_plan(RADIO_DEVICE, INTERFACE, "", "",
	    "\"links\":[" WIRED_LINK "]", &document, &observed);

	check(plan && !planfix_action(plan, "backend.start"),
	    "a `wifi` block on an interface the kernel does not call wireless starts nothing");
	planfix_release(plan, document, observed);
}

static void an_unmanaged_radio_starts_nothing(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = planfix_plan(UNMANAGED_RADIO_DEVICE, INTERFACE, "", "",
	    "\"links\":[" RADIO_LINK "]", &document, &observed);

	check(plan && !planfix_action(plan, "backend.start"),
	    "and neither does a radio the document says netcfgd does not manage");
	planfix_release(plan, document, observed);
}

/*
 * **The `managed` condition, asked of the rule directly, because the plan
 * cannot show it.** `ncfg_builder_push` drops every action on an unmanaged
 * device and the clearing filter takes one out of the document altogether, so
 * the check above answers the same whether or not this rule knows the word --
 * measured by deleting the condition and watching nothing go red. The rule is
 * where the answer belongs, being what the pass and the teardown both ask, so
 * it is checked where a mistake in it can be seen.
 *
 * The managed radio beside it is the control: without it this would pass
 * against a rule that answered no to everything.
 */
static void the_rule_answers_for_a_radio_the_document_does_not_manage(void)
{
	ncfg_document_t *unmanaged = planfix_document(UNMANAGED_RADIO_DEVICE, INTERFACE, "", "");
	ncfg_document_t *managed = planfix_document(RADIO_DEVICE, INTERFACE, "", "");
	ncfg_observed_t *observed = planfix_observed("\"links\":[" RADIO_LINK "]");

	check(unmanaged && observed &&
	    !ncfg_plan_radio_supplicant_wanted(unmanaged, observed, "wlan0"),
	    "the rule answers no for a radio the document says netcfgd does not manage");
	check(managed && observed &&
	    ncfg_plan_radio_supplicant_wanted(managed, observed, "wlan0"),
	    "and yes for the same radio managed, so the answer is about `managed`");
	/* The teardown's, which is the same rule reached from the other side: one
	 * process serves both blocks and cannot be half wanted. */
	check(unmanaged && observed &&
	    !ncfg_plan_supplicant_wanted(unmanaged, observed, "wlan0"),
	    "and the teardown's rule is the same rule, so it answers the same way");
	ncfg_document_free(unmanaged);
	ncfg_document_free(managed);
	ncfg_observed_free(observed);
}

/* ------------------------------------------------------------------------ *
 * One prerequisite per interface
 * ------------------------------------------------------------------------ */

/*
 * **A radio running an access point does not also join networks with the same
 * interface.** One radio does both only with a second virtual interface on the
 * phy, which netcfgd does not create -- so the two would be two processes
 * fighting over one device, and each pass would be doing exactly what it was
 * asked.
 */
static void a_radio_running_an_access_point_gets_hostapd_and_not_a_supplicant(void)
{
	ncfg_document_t     *document;
	ncfg_observed_t     *observed;
	ncfg_plan_t         *plan = planfix_plan(RADIO_DEVICE, INTERFACE, "", ACCESS_POINT,
	    "\"links\":[" RADIO_LINK "]", &document, &observed);
	const ncfg_action_t *start = plan ? planfix_action(plan, "backend.start") : NULL;

	check(start && start->op.u.backend.kind == NCFG_BACKEND_ACCESS_POINT,
	    "a radio with an `access_point` block starts hostapd");
	check(plan && planfix_count(plan, "backend.start") == 1u,
	    "and exactly one backend, the supplicant being what a radio that joins needs");
	planfix_release(plan, document, observed);
}

/*
 * And the arm above it. An interface carrying a `dot1x` block has said what
 * its supplicant is for; asking again because the device is also a radio is
 * two `backend.start` actions for one process, and the second would report
 * `wpa_supplicant` already running on every apply.
 */
static void a_radio_that_authenticates_gets_one_supplicant_and_not_two(void)
{
	ncfg_document_t     *document;
	ncfg_observed_t     *observed;
	ncfg_plan_t         *plan = planfix_plan(RADIO_DEVICE, DOT1X_INTERFACE, "", "",
	    "\"links\":[" RADIO_LINK "]", &document, &observed);
	const ncfg_action_t *start = plan ? planfix_action(plan, "backend.start") : NULL;

	check(plan && planfix_count(plan, "backend.start") == 1u,
	    "a radio with a `dot1x` block starts one supplicant and not two");
	check(start && start->reason.field && strcmp(start->reason.field, "dot1x") == 0,
	    "and the block it names is the one that decided, which is `dot1x`");
	planfix_release(plan, document, observed);
}

/* ------------------------------------------------------------------------ *
 * The teardown, which is the same rule
 * ------------------------------------------------------------------------ */

static void the_rule_that_keeps_a_radios_supplicant_is_the_rule_that_starts_one(void)
{
	ncfg_document_t     *document;
	ncfg_observed_t     *observed;
	const ncfg_action_t *stop;
	ncfg_plan_t         *plan;

	/*
	 * The `wifi` block deleted, so nothing would start one: the permissive
	 * direction here leaves a supplicant nobody owns.
	 */
	plan = planfix_plan(PLAIN_DEVICE, INTERFACE, "", "",
	    "\"links\":[" RADIO_LINK "]," SUPPLICANT_RUNNING, &document, &observed);
	stop = plan ? planfix_for_field(plan, "backend.stop", "wifi/dot1x") : NULL;
	check(stop != NULL, "a supplicant on a device whose `wifi` block went is stopped");
	/* `planfix_for_field` above is what asserts the field, which names both
	 * blocks because one process cannot be half wanted. */
	check(stop && stop->op.u.backend.kind == NCFG_BACKEND_SUPPLICANT,
	    "and it is the supplicant that is stopped and not something else on the radio");
	planfix_release(plan, document, observed);

	/*
	 * And the kernel's half of the same rule, which is the direction that
	 * matters: a supplicant this build would not start is one it must not
	 * keep, or the two answers disagree and the disagreement is a plan that
	 * starts something and stops it on alternate reconciles.
	 */
	plan = planfix_plan(RADIO_DEVICE, INTERFACE, "", "",
	    "\"links\":[" WIRED_LINK "]," SUPPLICANT_RUNNING, &document, &observed);
	check(plan && planfix_action(plan, "backend.stop") != NULL,
	    "and so is one on an interface the kernel does not call wireless");
	planfix_release(plan, document, observed);

	/* The access point's arm, from the teardown's side: a radio that has been
	 * given an access point is not a station, so a supplicant left over from
	 * before the block was written is unwanted. */
	plan = planfix_plan(RADIO_DEVICE, INTERFACE, "", ACCESS_POINT,
	    "\"links\":[" RADIO_LINK "]," SUPPLICANT_RUNNING, &document, &observed);
	check(plan && planfix_action(plan, "backend.stop") != NULL,
	    "and so is one on a radio that now runs an access point instead");
	planfix_release(plan, document, observed);
}

/* ------------------------------------------------------------------------ *
 * What is left of the warning
 * ------------------------------------------------------------------------ */

/*
 * **The blanket sentence is gone and one arrangement is left.** It said the
 * supplicant serving a radio was not started by this build of the planner,
 * which plans no backend actions at all; the pass above makes the first half
 * untrue and `dot1x.c`, `advertise.c` and `access_point.c` had already made
 * the second.
 *
 * What survives is the radio a `device` block declares and no `interface`
 * block names: the prerequisite is planned from the interface walk, so such a
 * radio gets no supplicant, no `link.up` and -- without this -- no explanation
 * either.
 *
 * **The tail of the sentence is what is asserted**, not a fragment near the
 * front: `ncfg_plan_warnf` formats into `NCFG_ERROR_MAX` and a warning that
 * did not fit is cut, so a check that reads only the opening words cannot
 * fail whatever happens to the rest.
 */
static void a_radio_with_no_interface_block_is_said_rather_than_passed_over(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = planfix_plan(RADIO_DEVICE, "", "", "",
	    "\"links\":[" RADIO_LINK "]", &document, &observed);

	check(plan && planfix_warned(plan, "`wlan0` is a radio with no `interface` block"),
	    "a radio the document declares and states no `interface` block for is said");
	check(plan && planfix_warned(plan, "Adding `interface wlan0 { }` is enough"),
	    "and the sentence arrives whole, which is what the remedy is in");
	check(plan && !planfix_warned(plan, "is not started by this build of the planner"),
	    "and the blanket sentence it narrowed from is gone");
	planfix_release(plan, document, observed);
}

static void the_radio_this_build_does_start_one_for_is_not_warned_about(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = planfix_plan(RADIO_DEVICE, INTERFACE, "", "",
	    "\"links\":[" RADIO_LINK "]", &document, &observed);

	check(plan && !planfix_warned(plan, "no `interface` block"),
	    "a radio with an `interface` block is not told about a block it has");
	planfix_release(plan, document, observed);

	/* And the arrangement that is not asking for a supplicant at all: a
	 * `wifi { portal_check = ... }` on something that is not a radio is what
	 * `tests/live/portal.sh` writes, and a sentence about every one of those
	 * is noise rather than news. */
	plan = planfix_plan(RADIO_DEVICE, "", "", "", "\"links\":[" WIRED_LINK "]",
	    &document, &observed);
	check(plan && !planfix_warned(plan, "no `interface` block"),
	    "and neither is a `wifi` block on something the kernel does not call wireless");
	planfix_release(plan, document, observed);

	/* A radio with an access point and no interface block is one missing
	 * block, and `access_point.c` already says so in its own words. */
	plan = planfix_plan(RADIO_DEVICE, "", "", ACCESS_POINT, "\"links\":[" RADIO_LINK "]",
	    &document, &observed);
	check(plan && planfix_warned(plan, "which has no `interface` block"),
	    "a radio with an access point and no `interface` block is told once");
	check(plan && !planfix_warned(plan, "is a radio with no `interface` block"),
	    "and not twice about the one block it is missing");
	planfix_release(plan, document, observed);
}

int main(void)
{
	a_radio_the_machine_has_gets_a_supplicant();
	the_addressing_waits_for_the_supplicant();
	a_supplicant_already_running_is_not_started_again();
	a_wifi_block_on_something_that_is_not_a_radio_starts_nothing();
	an_unmanaged_radio_starts_nothing();
	the_rule_answers_for_a_radio_the_document_does_not_manage();
	a_radio_running_an_access_point_gets_hostapd_and_not_a_supplicant();
	a_radio_that_authenticates_gets_one_supplicant_and_not_two();
	the_rule_that_keeps_a_radios_supplicant_is_the_rule_that_starts_one();
	a_radio_with_no_interface_block_is_said_rather_than_passed_over();
	the_radio_this_build_does_start_one_for_is_not_warned_about();

	printf("plan radio: %d checks, %d failed\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
