/*
 * plan_session_test.c -- the dial, which is the one action that makes a link.
 *
 * WHAT IS DIFFERENT ABOUT THIS PASS
 *   Every other backend is started for an interface that already exists. A
 *   PPPoE session and an OpenVPN tunnel are the other way round: `pppd` makes
 *   `ppp0` and `openvpn` makes `tun0`, so the link is absent *because* the
 *   daemon has not run -- and the absent link is what every other pass in the
 *   planner treats as a reason to plan nothing. So the cases here are mostly
 *   about where the call sits rather than about what it emits.
 *
 * THE COUNT IS THE CHECK, NOT THE PRESENCE
 *   The Rust planned this from the device walk *and* from the interface walk
 *   for a while, which is two `backend.start` actions for one session and a
 *   `pppd` run twice on every apply. Its fixture asserted the action was
 *   present and could not see it. Every case below counts.
 *
 * NOTHING HERE RUNS ANYTHING
 *   A plan is a value. `pppoe_test.c` is where a session is dialled, against a
 *   shell script it wrote; this file builds documents and observations and
 *   reads the actions that come out.
 */
#include "planfix.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

static void detail(const char *label, const char *text)
{
	printf("       %s: %s\n", label, text ? text : "(none)");
}

/* A DSL line: the device names its parent and the credential it dials with,
 * and the credential is a reference rather than a passphrase (constraint 5). */
#define SESSION                                                                      \
	"{\"name\":\"ppp0\",\"kind\":{\"kind\":\"pppoe\",\"parent\":\"eth0\","        \
	"\"username\":\"alice\",\"password\":{\"provider\":\"file\",\"name\":\"dsl\"}}}"
/* And a tunnel, which is the same shape with a different daemon. */
#define TUNNEL                                                                       \
	"{\"name\":\"tun0\",\"kind\":{\"kind\":\"open_vpn\","                         \
	"\"config\":\"/etc/openvpn/client.conf\"}}"

/* The interface block a DSL user writes: a default route over a
 * point-to-point link, which needs no gateway -- which is why netcfgd tells
 * pppd `nodefaultroute` and installs this one itself. */
#define SESSION_INTERFACE                                                            \
	"{\"name\":\"ppp0\",\"addressing\":[{\"source\":\"reported\"}],"                \
	"\"routes\":[{\"destination\":\"0.0.0.0/0\"}]}"

/* The link once the daemon has made it. */
#define LINK_UP                                                                      \
	"\"links\":[{\"name\":\"ppp0\",\"index\":7,\"mtu\":1492,\"up\":true,"         \
	"\"carrier\":true,\"ownership\":\"ours\"}]"

/* What the observation says about a session that is already dialled. */
#define RUNNING(kind, iface)                                                         \
	"\"backends\":[{\"kind\":\"" kind "\",\"interface\":\"" iface "\","           \
	"\"running\":true}]"

/*
 * A device with no link gets exactly one dial.
 *
 * The link is absent, which is where `ncfg_plan_link_is_plannable` stops every
 * other pass -- and rightly, since there is nothing to address. The dial is
 * the exception because it is what makes the link.
 */
static void a_session_with_no_link_is_dialled_once(void)
{
	ncfg_document_t     *document;
	ncfg_observed_t     *observed;
	ncfg_plan_t         *plan = planfix_plan(SESSION, SESSION_INTERFACE, "", "",
	    "\"links\":[]", &document, &observed);
	const ncfg_action_t *start = plan ? planfix_action(plan, "backend.start") : NULL;

	check(plan && planfix_count(plan, "backend.start") == 1u,
	    "a pppoe device with no link is dialled, exactly once");
	if (plan && planfix_count(plan, "backend.start") != 1u) {
		char names[512];

		planfix_names(plan, names, sizeof(names));
		detail("the plan", names);
	}
	check(start && start->op.u.backend.kind == (int)NCFG_BACKEND_PPPOE &&
	        start->op.u.backend.iface && strcmp(start->op.u.backend.iface, "ppp0") == 0,
	    "  and it is the pppoe backend on the interface the document names");
	check(start && start->reason.field && strcmp(start->reason.field, "pppoe") == 0,
	    "  with the block it came from as its reason, which is what an operator reads");
	/* Nothing else: the addressing and the routes wait for a link that does
	 * not exist yet, and a `link.create` for a device pppd makes would be an
	 * action that must fail. */
	check(plan && planfix_count(plan, "link.create") == 0u,
	    "and nothing tries to create the link netcfgd cannot create");
	check(plan && planfix_count(plan, "addr.add") == 0u &&
	        planfix_count(plan, "route.add") == 0u,
	    "and nothing is addressed or routed over a link that is not there");
	check(plan && planfix_warned(plan, "is not up yet"),
	    "and the plan says the addressing is waiting rather than missing");
	check(plan && planfix_count(plan, "link.up") == 0u,
	    "and nothing waits on a `link.up` for a device that has none");
	planfix_release(plan, document, observed);
}

/* A tunnel is the same pass with the other daemon, and a tunnel need not have
 * an interface block at all -- which is why this pass is driven from the
 * device walk. */
static void a_tunnel_with_no_interface_block_is_still_started(void)
{
	ncfg_document_t     *document;
	ncfg_observed_t     *observed;
	ncfg_plan_t         *plan = planfix_plan(TUNNEL, "", "", "", "\"links\":[]", &document,
	    &observed);
	const ncfg_action_t *start = plan ? planfix_action(plan, "backend.start") : NULL;

	check(plan && planfix_count(plan, "backend.start") == 1u,
	    "a tunnel with no `interface` block is started, exactly once");
	check(start && start->op.u.backend.kind == (int)NCFG_BACKEND_OPENVPN &&
	        start->op.u.backend.iface && strcmp(start->op.u.backend.iface, "tun0") == 0,
	    "  and it is the openvpn backend on the device the document names");
	check(start && start->reason.field && strcmp(start->reason.field, "openvpn") == 0,
	    "  naming the block it came from");
	planfix_release(plan, document, observed);
}

/*
 * A session already running plans nothing, which is the property that makes
 * this safe to run on a timer.
 *
 * A pass that planned the dial again would run `pppd` on every reconcile,
 * against a line that is already up.
 */
static void a_running_session_is_left_alone(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = planfix_plan(SESSION, SESSION_INTERFACE, "", "",
	    LINK_UP "," RUNNING("pppoe", "ppp0"), &document, &observed);

	check(plan && planfix_count(plan, "backend.start") == 0u,
	    "a session that is already running is not dialled again");
	check(plan && planfix_count(plan, "backend.stop") == 0u,
	    "  and is not stopped either, because the document still asks for it");
	planfix_release(plan, document, observed);
}

/*
 * **A daemon that died while its device lingered is dialled again.**
 *
 * This is why the pass is not inside an "is the link absent" branch: putting
 * it there meant a tunnel whose daemon had gone was never restarted, because
 * the interface it had made was still in the kernel (0155 pass 1b).
 */
static void a_session_whose_daemon_died_is_dialled_again(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = planfix_plan(SESSION, SESSION_INTERFACE, "", "", LINK_UP,
	    &document, &observed);

	check(plan && planfix_count(plan, "backend.start") == 1u,
	    "a link that is up with no daemon behind it is dialled again");
	planfix_release(plan, document, observed);
}

/*
 * A session the document no longer declares is hung up.
 *
 * Until the Rust had this, deleting the block failed the apply and left `pppd`
 * holding the line -- with `persist` and `maxfail 0` in the options netcfgd
 * had written it, so for ever. The question is asked of the *device* list,
 * because a tunnel need not have an interface block to be wanted.
 */
static void a_session_the_document_dropped_is_hung_up(void)
{
	ncfg_document_t     *document;
	ncfg_observed_t     *observed;
	ncfg_plan_t         *plan = planfix_plan("", "", "", "",
	    LINK_UP "," RUNNING("pppoe", "ppp0"), &document, &observed);
	const ncfg_action_t *stop = plan ? planfix_action(plan, "backend.stop") : NULL;

	check(plan && planfix_count(plan, "backend.stop") == 1u,
	    "a running session the document no longer declares is stopped");
	check(stop && stop->op.u.backend.kind == (int)NCFG_BACKEND_PPPOE,
	    "  and it is the session's own backend that is stopped");
	check(stop && stop->reason.field && strcmp(stop->reason.field, "pppoe") == 0,
	    "  named by the block that went, so an operator looks at the right one");
	planfix_release(plan, document, observed);

	/* And the same question for a tunnel, which is the arm that would have
	 * answered "nobody wants this" for every tunnel with no interface block
	 * if it asked the interface list. */
	plan = planfix_plan(TUNNEL, "", "", "", RUNNING("open_vpn", "tun0"), &document,
	    &observed);
	check(plan && planfix_count(plan, "backend.stop") == 0u,
	    "a running tunnel whose device is still declared is not stopped");
	planfix_release(plan, document, observed);
}

/*
 * A device the operator took out of netcfgd's hands is not dialled.
 *
 * `managed = false` is 0035's choke point, and it is `ncfg_builder_push` that
 * enforces it for every pass rather than each pass remembering to ask.
 */
static void an_unmanaged_session_is_not_dialled(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = planfix_plan(
	    "{\"name\":\"ppp0\",\"managed\":false,\"kind\":{\"kind\":\"pppoe\","
	    "\"parent\":\"eth0\",\"username\":\"alice\","
	    "\"password\":{\"provider\":\"file\",\"name\":\"dsl\"}}}",
	    "", "", "", "\"links\":[]", &document, &observed);

	check(plan && planfix_count(plan, "backend.start") == 0u,
	    "a device netcfgd was told not to manage is not dialled");
	planfix_release(plan, document, observed);
}

int main(void)
{
	a_session_with_no_link_is_dialled_once();
	a_tunnel_with_no_interface_block_is_still_started();
	a_running_session_is_left_alone();
	a_session_whose_daemon_died_is_dialled_again();
	a_session_the_document_dropped_is_hung_up();
	an_unmanaged_session_is_not_dialled();

	printf("plan_session_test: %d checks, %d failed\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
