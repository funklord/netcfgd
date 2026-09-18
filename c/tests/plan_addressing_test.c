/*
 * plan_addressing_test.c -- the planner's addressing, backend and host passes.
 *
 * WHAT IS UNDER TEST
 *   The half of the planner that decides what an address *is* when the
 *   document does not say: a DHCP client to start, a prefix somebody else was
 *   delegated, two sysctls that decide whether the kernel will build a SLAAC
 *   address at all -- and the two actions that configure the machine rather
 *   than an interface, the DNS delivery and the hostname.
 *
 * THE PROPERTY EVERY CASE HERE IS REALLY ABOUT
 *   `plan.h` names two and this file is arranged around the second:
 *   **applying a plan twice produces an empty second plan.** Every pass here
 *   compares something it computed against something the machine reported, and
 *   each of those comparisons is a place the plan can start adding and
 *   removing the same object for ever. So each pass has a case that plans the
 *   action, and a case that plans *nothing* against an observation carrying
 *   the result -- and for the delegated address there is a third, where the
 *   observation carries the same address in a spelling nobody would have
 *   typed. 10.169 is what that third one is for: an address compared as text
 *   rather than as an address is how `ncfg explain` came to say netcfgd did
 *   not ask for an address netcfgd had installed itself.
 *
 * WHY THE FIXTURES ARE JSON
 *   `planfix.h`'s arrangement, and for its reason: a document and an
 *   observation written as JSON are read by the same readers a daemon uses, so
 *   a fixture cannot be a shape the model would refuse. Nothing here needs a
 *   kernel, a socket or a second of waiting -- planning is pure, which is what
 *   lets this suite run on a workstation whose network must not be disturbed.
 *
 *   The one thing that header does not do is carry a `globals` block: it
 *   writes `"globals":{}` and takes the four lists after it. Three of the
 *   passes here are *about* a global block -- the host's DNS mode and its
 *   hostname policy -- so the document builder is spelled once more in this
 *   file and nothing else is. `planfix_document` growing that argument is
 *   what should happen when both halves of the planner have landed; until
 *   then this is one function rather than eleven.
 */
#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/document.h"
#include "ncfg/observed.h"
#include "ncfg/plan.h"
#include "ncfg/value.h"

/* The planner's own header, by path, for the two things under test that are
 * deliberately not in its public face: the resolution a `delegated` source
 * goes through, and the restart bound -- published so this file cannot spell
 * the number itself. */
#include "../src/plan/plan_internal.h"
#include "planfix.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
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

/* ------------------------------------------------------------------------ *
 * Fixtures
 * ------------------------------------------------------------------------ */

static ncfg_document_t *document_of(const char *globals, const char *body)
{
	char             text[8192];
	char             message[NCFG_ERROR_MAX];
	ncfg_document_t *document;

	(void)snprintf(text, sizeof(text),
	    "{\"schema_version\":{\"major\":1,\"minor\":1},\"generated_by\":\"plan_addressing\","
	    "\"globals\":%s,\"networks\":[],%s}",
	    globals, body);
	message[0] = '\0';
	document = ncfg_document_read(text, strlen(text), message, sizeof(message));
	if (!document) {
		printf("  fixture document did not read: %s\n", message);
	}
	return document;
}

/*
 * The three link shapes these cases need, on `PLANFIX_LINK`'s.
 *
 * `extra` is what a sysctl case is about, leading comma included -- an
 * `accept_ra` the kernel reported, a `privacy` it did not, a `forwarding`
 * that is on. Absent means the sysctl could not be read, which is a different
 * answer from false and is what two of the cases below turn on.
 */
#define LINK_UP(name)          PLANFIX_LINK(name, "")
#define LINK_SYSCTL(name, add) PLANFIX_LINK(name, "," add)
#define LINK_DOWN(name) \
	"{\"name\":\"" name "\",\"index\":2,\"mtu\":1500,\"up\":false,\"carrier\":true," \
	"\"ownership\":\"unknown\"}"

static ncfg_plan_t *plan_of(const char *globals, const char *body, const char *observation,
    ncfg_document_t **document_out, ncfg_observed_t **observed_out)
{
	char             message[NCFG_ERROR_MAX];
	ncfg_document_t *document = document_of(globals, body);
	ncfg_observed_t *observed = planfix_observed(observation);
	ncfg_plan_t     *plan;

	*document_out = document;
	*observed_out = observed;
	if (!document || !observed) {
		return NULL;
	}
	message[0] = '\0';
	plan = ncfg_plan_build(document, observed, NULL, message, sizeof(message));
	if (!plan) {
		printf("  could not build the plan: %s\n", message);
	}
	return plan;
}

/* Whether the plan holds an action of this name at all. */
static int has_name(const ncfg_plan_t *plan, const char *name)
{
	return planfix_action(plan, name) != NULL;
}

static long position(const ncfg_plan_t *plan, const char *name)
{
	size_t i;

	for (i = 0; i < plan->action_count; i++) {
		if (strcmp(ncfg_op_name(&plan->actions[i].op), name) == 0) {
			return (long)i;
		}
	}
	return -1;
}

/*
 * Whether the plan's first action of this name carries an inverse.
 *
 * Three-valued on purpose, and it exists because the two-valued form is a NULL
 * dereference waiting for the first sabotage that removes the action: a case
 * proving "this one has a way back" reads the action a case two lines above
 * has just proved is there, and a broken planner takes the test out with it
 * rather than reporting.
 */
static int reversible(const ncfg_plan_t *plan, const char *name)
{
	const ncfg_action_t *action = plan ? planfix_action(plan, name) : NULL;

	return action ? action->has_inverse : 0;
}

/* The plan as the control socket sends it, so a case can assert a value a
 * struct walk would have to reach three unions deep for. */
static char *written(const ncfg_plan_t *plan)
{
	ncfg_buf_t buf;
	char       message[NCFG_ERROR_MAX];
	char      *text;

	ncfg_buf_init(&buf, 0);
	if (!ncfg_plan_write(plan, &buf, message, sizeof(message))) {
		printf("  could not write the plan: %s\n", message);
		ncfg_buf_free(&buf);
		return NULL;
	}
	text = ncfg_buf_take(&buf, NULL);
	ncfg_buf_free(&buf);
	return text;
}

static int wrote(const ncfg_plan_t *plan, const char *fragment)
{
	char *text = written(plan);
	int   found;

	if (!text) {
		return 0;
	}
	found = strstr(text, fragment) != NULL;
	if (!found) {
		printf("  the plan does not carry `%s`\n", fragment);
	}
	free(text);
	return found;
}

/* ------------------------------------------------------------------------ *
 * accept_ra: whether the kernel will act on an advertisement at all
 * ------------------------------------------------------------------------ */

#define SLAAC_ETH0 \
	"\"devices\":[{\"name\":\"eth0\",\"kind\":{\"kind\":\"physical\"}}]," \
	"\"interfaces\":[{\"name\":\"eth0\",\"addressing\":[{\"source\":\"slaac\"}]}]"

/*
 * The trap decision 0073 exists for.
 *
 * `accept_ra` defaults to 1, which means "accept unless this interface
 * forwards". So `config = "slaac"` on a router's WAN -- or on any machine
 * whose `sysctl.conf` or container runtime turned IPv6 forwarding on --
 * obtains no address at all, and nothing says why: the document asked for
 * something, the apply succeeded, and `ip addr` shows a link-local and nothing
 * else.
 */
static void slaac_makes_the_kernel_listen_where_it_would_not(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = plan_of("{}", SLAAC_ETH0,
	    "\"links\":[" LINK_SYSCTL("eth0",
	        "\"accept_ra\":{\"value\":1,\"effective\":false}") "]",
	    &document, &observed);

	check(plan && has_name(plan, "sysctl.set_accept_ra"),
	    "an interface that forwards has accept_ra written, or SLAAC obtains nothing");
	check(plan && wrote(plan, "\"value\":2"),
	    "and what is written is 2 -- accept whether or not this interface forwards");
	check(plan && wrote(plan, "and eth0 forwards -- advertisements ignored"),
	    "and the reason says why 1 was not enough, which the number alone does not");
	planfix_release(plan, document, observed);

	/* An interface that already acts on advertisements is left alone, so an
	 * ordinary laptop has no sysctl written and no line in its plan. That is
	 * the difference between fixing what the document made untrue and setting
	 * a value everywhere because netcfgd can. */
	plan = plan_of("{}", SLAAC_ETH0,
	    "\"links\":[" LINK_SYSCTL("eth0",
	        "\"accept_ra\":{\"value\":1,\"effective\":true}") "]",
	    &document, &observed);
	check(plan && !has_name(plan, "sysctl.set_accept_ra"),
	    "an ordinary laptop, where advertisements already arrive, gets no sysctl at all");
	check(plan && ncfg_plan_is_empty(plan),
	    "  and applying that plan twice is the empty plan plan.h asks for");
	planfix_release(plan, document, observed);

	plan = plan_of("{}", SLAAC_ETH0,
	    "\"links\":[" LINK_SYSCTL("eth0",
	        "\"accept_ra\":{\"value\":2,\"effective\":true}") "]",
	    &document, &observed);
	check(plan && ncfg_plan_is_empty(plan),
	    "and neither does one netcfgd has already written 2 on");
	planfix_release(plan, document, observed);
}

/*
 * **Against the forwarding this plan will produce, not the one it observed.**
 *
 * `effective` is computed in the observer from the forwarding sysctl as it
 * was, and a plan turning forwarding on in the same pass invalidates it: the
 * interface reads as settled, no `accept_ra` is planned, and the apply leaves
 * it forwarding with `accept_ra` at 1 -- advertisements ignored -- until a
 * second apply happens to run. Two applies to converge where one should do,
 * which a daemon hides and `--oneshot` at boot does not.
 */
static void accept_ra_is_read_against_the_forwarding_this_plan_will_produce(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = plan_of("{}",
	    "\"devices\":[{\"name\":\"eth0\",\"kind\":{\"kind\":\"physical\"}}],"
	    "\"interfaces\":[{\"name\":\"eth0\",\"addressing\":[{\"source\":\"slaac\"}],"
	    "\"forwarding\":true}]",
	    "\"links\":[" LINK_SYSCTL("eth0",
	        "\"accept_ra\":{\"value\":1,\"effective\":true},\"forwarding\":false") "]",
	    &document, &observed);

	check(plan && has_name(plan, "sysctl.set_forwarding") &&
	    has_name(plan, "sysctl.set_accept_ra"),
	    "a plan that turns forwarding on writes accept_ra in the same pass");
	planfix_release(plan, document, observed);
}

/*
 * An interface that stops asking is handed back -- **only where netcfgd is
 * what changed it.**
 *
 * Without that half this is a one-way door: deleting the source from the
 * document leaves the machine as netcfgd left it, which is drift the config
 * can no longer describe. With it applied to everything, a machine whose
 * `sysctl.conf` sets these globally has netcfgd undo somebody else's choice
 * the first time it runs.
 */
static void a_sysctl_is_handed_back_only_where_netcfgd_changed_it(void)
{
	static const char *const body =
	    "\"devices\":[{\"name\":\"eth0\",\"kind\":{\"kind\":\"physical\"}}],"
	    "\"interfaces\":[{\"name\":\"eth0\",\"addressing\":[]}]";
	ncfg_document_t         *document;
	ncfg_observed_t         *observed;
	ncfg_plan_t             *plan;

	plan = plan_of("{}", body,
	    "\"links\":[" LINK_SYSCTL("eth0",
	        "\"accept_ra\":{\"value\":2,\"effective\":true},\"privacy\":true,"
	        "\"forwarding\":true") "],"
	    "\"accept_ra_applied\":[\"eth0\"],\"privacy_applied\":[\"eth0\"],"
	    "\"forwarding_applied\":[\"eth0\"]",
	    &document, &observed);
	check(plan && has_name(plan, "sysctl.set_accept_ra") && wrote(plan, "\"value\":1"),
	    "accept_ra netcfgd wrote goes back to the kernel's own default");
	check(plan && has_name(plan, "sysctl.set_privacy") &&
	    wrote(plan, "\"prefer_temporary\":false"),
	    "and use_tempaddr netcfgd wrote is turned off");
	check(plan && has_name(plan, "sysctl.set_forwarding") && wrote(plan, "\"enabled\":false"),
	    "and forwarding netcfgd switched on is switched off");
	planfix_release(plan, document, observed);

	plan = plan_of("{}", body,
	    "\"links\":[" LINK_SYSCTL("eth0",
	        "\"accept_ra\":{\"value\":2,\"effective\":true},\"privacy\":true,"
	        "\"forwarding\":true") "]",
	    &document, &observed);
	check(plan && ncfg_plan_is_empty(plan) && plan->warning_count == 0u,
	    "and nothing at all is written where netcfgd is not the one that set them");
	planfix_release(plan, document, observed);
}

/*
 * A sysctl that cannot be read is reported rather than written.
 *
 * An interface that *exists* and has no `accept_ra` is an IPv6-disabled kernel
 * or a container without `/proc/sys`. Writing there fails this apply and every
 * one after it -- an action planned before the thing that would make it
 * succeed. Said rather than skipped, because a key that quietly does nothing
 * is the reason these were implemented.
 */
static void a_sysctl_that_cannot_be_read_is_reported_not_written(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = plan_of("{}",
	    "\"devices\":[{\"name\":\"eth0\",\"kind\":{\"kind\":\"physical\"}}],"
	    "\"interfaces\":[{\"name\":\"eth0\",\"addressing\":["
	    "{\"source\":\"slaac\",\"privacy\":\"prefer_temporary\"}]}]",
	    "\"links\":[" LINK_UP("eth0") "]", &document, &observed);

	check(plan && !has_name(plan, "sysctl.set_accept_ra") &&
	    planfix_warned(plan, "the `accept_ra` sysctl for eth0 cannot be read"),
	    "an unreadable accept_ra is a sentence naming the interface, not an action");
	check(plan && !has_name(plan, "sysctl.set_privacy") &&
	    planfix_warned(plan, "the `use_tempaddr` sysctl for eth0 cannot be read"),
	    "and so is an unreadable use_tempaddr");
	planfix_release(plan, document, observed);
}

/*
 * An interface this plan is about to create has nothing to read yet, which is
 * not the same thing as a kernel that has none: the write is planned and gated
 * on the creation. Without this a virtual interface would need a second apply
 * to get what the document asked for on the first, and `ncfg apply` does not
 * get another go.
 */
static void a_link_being_created_gets_its_sysctls_on_the_first_apply(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = plan_of("{}",
	    "\"devices\":[{\"name\":\"dum0\",\"kind\":{\"kind\":\"dummy\"}}],"
	    "\"interfaces\":[{\"name\":\"dum0\",\"addressing\":[{\"source\":\"slaac\"}]}]",
	    "\"links\":[]", &document, &observed);
	const ncfg_action_t *created = plan ? planfix_action(plan, "link.create") : NULL;
	const ncfg_action_t *sysctl = plan ? planfix_action(plan, "sysctl.set_accept_ra") : NULL;

	check(created && sysctl && planfix_depends_on(sysctl, created->id),
	    "a sysctl on a link this plan creates waits for the creation");
	check(sysctl && !sysctl->has_inverse,
	    "and carries no inverse, because there was no previous value to go back to");
	planfix_release(plan, document, observed);
}

/*
 * `accept_ra` is written **before** `link.up`, and that is not tidiness.
 *
 * `link.up` is where the kernel decides whether to solicit a router at all,
 * and it does not solicit on an interface whose advertisements it would
 * ignore. Writing the sysctl afterwards leaves the interface waiting for the
 * router's own unsolicited timer -- 14.2 seconds against a dnsmasq set to
 * five, and minutes on a real network.
 */
static void the_kernel_is_told_to_listen_before_the_link_comes_up(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = plan_of("{}", SLAAC_ETH0,
	    "\"links\":[{\"name\":\"eth0\",\"index\":2,\"mtu\":1500,\"up\":false,"
	    "\"carrier\":true,\"ownership\":\"unknown\","
	    "\"accept_ra\":{\"value\":1,\"effective\":false}}]",
	    &document, &observed);
	char names[512];

	if (plan) {
		planfix_names(plan, names, sizeof(names));
		if (strcmp(names, "sysctl.set_accept_ra,link.up") != 0) {
			printf("  the plan is: %s\n", names);
		}
		check(strcmp(names, "sysctl.set_accept_ra,link.up") == 0,
		    "accept_ra is written before link.up, or the solicitation never happens");
	} else {
		check(0, "accept_ra is written before link.up, or the solicitation never happens");
	}
	planfix_release(plan, document, observed);
}

/* The privacy sysctl, whose shape is the forwarding one's exactly. */
static void temporary_addresses_are_asked_for_by_the_slaac_source(void)
{
	static const char *const body =
	    "\"devices\":[{\"name\":\"eth0\",\"kind\":{\"kind\":\"physical\"}}],"
	    "\"interfaces\":[{\"name\":\"eth0\",\"addressing\":["
	    "{\"source\":\"slaac\",\"privacy\":\"prefer_temporary\"}]}]";
	ncfg_document_t         *document;
	ncfg_observed_t         *observed;
	ncfg_plan_t             *plan;

	plan = plan_of("{}", body,
	    "\"links\":[" LINK_SYSCTL("eth0",
	        "\"accept_ra\":{\"value\":2,\"effective\":true},\"privacy\":false") "]",
	    &document, &observed);
	check(plan && has_name(plan, "sysctl.set_privacy") &&
	    wrote(plan, "\"prefer_temporary\":true"),
	    "`privacy = \"prefer_temporary\"` writes use_tempaddr");
	check(reversible(plan, "sysctl.set_privacy"),
	    "and the previous value is known, so the change can be reverted");
	planfix_release(plan, document, observed);

	plan = plan_of("{}", body,
	    "\"links\":[" LINK_SYSCTL("eth0",
	        "\"accept_ra\":{\"value\":2,\"effective\":true},\"privacy\":true") "]",
	    &document, &observed);
	check(plan && ncfg_plan_is_empty(plan),
	    "and an interface that already prefers them is left alone");
	planfix_release(plan, document, observed);

	/* A `slaac` source with no privacy setting asks for nothing here: the
	 * kernel's middle value prefers the stable address and no config can
	 * request it, so it reads as "not preferring temporary". */
	plan = plan_of("{}", SLAAC_ETH0,
	    "\"links\":[" LINK_SYSCTL("eth0",
	        "\"accept_ra\":{\"value\":2,\"effective\":true},\"privacy\":false") "]",
	    &document, &observed);
	check(plan && !has_name(plan, "sysctl.set_privacy"),
	    "and a slaac source that says nothing about privacy writes nothing");
	planfix_release(plan, document, observed);
}

/*
 * Forwarding is planned per interface and applied per interface, rather than
 * through the global `net.ipv4.ip_forward`: writing the global one sets every
 * device at once, so netcfgd would be turning forwarding on for interfaces the
 * document says nothing about -- and could never turn it off again without
 * guessing which of those it had been responsible for.
 */
static void forwarding_is_per_interface_and_reversible(void)
{
	static const char *const body =
	    "\"devices\":[{\"name\":\"eth0\",\"kind\":{\"kind\":\"physical\"}}],"
	    "\"interfaces\":[{\"name\":\"eth0\",\"addressing\":[],\"forwarding\":true}]";
	ncfg_document_t         *document;
	ncfg_observed_t         *observed;
	ncfg_plan_t             *plan;

	plan = plan_of("{}", body,
	    "\"links\":[" LINK_SYSCTL("eth0", "\"forwarding\":false") "]", &document, &observed);
	check(plan && has_name(plan, "sysctl.set_forwarding") && wrote(plan, "\"enabled\":true"),
	    "`forwarding = true` writes the interface's own sysctl");
	check(reversible(plan, "sysctl.set_forwarding"),
	    "and it can be reverted, the previous value having been read");
	planfix_release(plan, document, observed);

	plan = plan_of("{}", body,
	    "\"links\":[" LINK_SYSCTL("eth0", "\"forwarding\":true") "]", &document, &observed);
	check(plan && ncfg_plan_is_empty(plan), "and an interface already forwarding is left be");
	planfix_release(plan, document, observed);

	/*
	 * A sysctl that could not be read cannot be restored, and inventing
	 * `false` as the inverse would have commit-confirm turn forwarding off on
	 * a router that had it on before netcfgd ever ran.
	 */
	plan = plan_of("{}", body, "\"links\":[" LINK_UP("eth0") "]", &document, &observed);
	check(plan && has_name(plan, "sysctl.set_forwarding") &&
	    !reversible(plan, "sysctl.set_forwarding"),
	    "a forwarding sysctl that could not be read is written and not reverted");
	check(plan && wrote(plan, "<unreadable>"),
	    "and the reason says the observation was unreadable rather than false");
	planfix_release(plan, document, observed);
}

/* ------------------------------------------------------------------------ *
 * The client that serves a DHCP source
 * ------------------------------------------------------------------------ */

#define DHCP4_ETH0 \
	"\"devices\":[{\"name\":\"eth0\",\"kind\":{\"kind\":\"physical\"}}]," \
	"\"interfaces\":[{\"name\":\"eth0\",\"addressing\":[{\"source\":\"dhcp4\"}]}]"

static void a_dhcp_source_starts_the_client_that_serves_it(void)
{
	ncfg_document_t     *document;
	ncfg_observed_t     *observed;
	ncfg_plan_t         *plan = plan_of("{}", DHCP4_ETH0,
	    "\"links\":[" LINK_DOWN("eth0") "]", &document, &observed);
	const ncfg_action_t *start = plan ? planfix_action(plan, "backend.start") : NULL;
	const ncfg_action_t *up = plan ? planfix_action(plan, "link.up") : NULL;

	check(start != NULL, "a `dhcp4` source starts a client");
	check(plan && wrote(plan, "\"kind\":\"dhcp4\""),
	    "and the kind is the model's spelling, not a debug rendering of an enum");
	/* Rule 3: a lease needs a live link. */
	check(start && up && planfix_depends_on(start, up->id),
	    "and it waits for link.up, because a lease needs a live link");
	check(start && start->has_inverse &&
	    start->inverse.kind == NCFG_OP_BACKEND_STOP,
	    "and stopping it is how the start is undone");
	planfix_release(plan, document, observed);

	/* The idempotence half: a client already running is not started again. */
	plan = plan_of("{}", DHCP4_ETH0,
	    "\"links\":[" LINK_UP("eth0") "],"
	    "\"backends\":[{\"kind\":\"dhcp4\",\"interface\":\"eth0\",\"running\":true}]",
	    &document, &observed);
	check(plan && ncfg_plan_is_empty(plan),
	    "and a client already running is not started a second time");
	planfix_release(plan, document, observed);

	/* A dhcp6 source is the same pass with the other kind, and the two are
	 * told apart -- a `dhcp4` client running does not satisfy `dhcp6`. */
	plan = plan_of("{}",
	    "\"devices\":[{\"name\":\"eth0\",\"kind\":{\"kind\":\"physical\"}}],"
	    "\"interfaces\":[{\"name\":\"eth0\",\"addressing\":[{\"source\":\"dhcp6\"}]}]",
	    "\"links\":[" LINK_UP("eth0") "],"
	    "\"backends\":[{\"kind\":\"dhcp4\",\"interface\":\"eth0\",\"running\":true}]",
	    &document, &observed);
	check(plan && has_name(plan, "backend.start") && wrote(plan, "\"kind\":\"dhcp6\""),
	    "a dhcp6 source is not satisfied by a dhcp4 client that happens to be running");
	planfix_release(plan, document, observed);
}

/*
 * A daemon that dies as fast as netcfgd starts it.
 *
 * On an interface set to `reconcile` that produced 181 starts in twelve
 * seconds -- measured, with a fake that lived for half a second. So netcfgd
 * tries, and then stops trying and says so. Decision 0079.
 */
static void a_client_that_will_not_stay_up_is_not_started_for_ever(void)
{
	char             observation[512];
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan;

	/* The bound is read from the header, so this case cannot drift away from
	 * the number the planner uses by spelling its own. */
	(void)snprintf(observation, sizeof(observation),
	    "\"links\":[" LINK_UP("eth0") "],"
	    "\"backend_restarts\":[[\"dhcp4\",\"eth0\",%d]]",
	    NCFG_PLAN_RESTART_LIMIT);
	plan = plan_of("{}", DHCP4_ETH0, observation, &document, &observed);
	check(plan && !has_name(plan, "backend.start"),
	    "a client started to the limit and still gone is not started again");
	check(plan && planfix_warned(plan, "it has not stayed up; not starting it again"),
	    "and the operator is told, with the count and where to look");
	planfix_release(plan, document, observed);

	(void)snprintf(observation, sizeof(observation),
	    "\"links\":[" LINK_UP("eth0") "],"
	    "\"backend_restarts\":[[\"dhcp4\",\"eth0\",%d]]",
	    NCFG_PLAN_RESTART_LIMIT - 1);
	plan = plan_of("{}", DHCP4_ETH0, observation, &document, &observed);
	check(plan && has_name(plan, "backend.start"),
	    "and one short of the limit is still tried, so the bound is the bound");
	planfix_release(plan, document, observed);
}

static void a_client_the_document_no_longer_asks_for_is_stopped(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = plan_of("{}",
	    "\"devices\":[{\"name\":\"eth0\",\"kind\":{\"kind\":\"physical\"}}],"
	    "\"interfaces\":[{\"name\":\"eth0\",\"addressing\":["
	    "{\"source\":\"static\",\"address\":\"10.0.0.1/24\"}]}]",
	    "\"links\":[" LINK_UP("eth0") "],"
	    "\"backends\":[{\"kind\":\"dhcp4\",\"interface\":\"eth0\",\"running\":true}]",
	    &document, &observed);

	check(plan && has_name(plan, "backend.stop"),
	    "a client running for a source the document dropped is stopped");
	check(plan && position(plan, "addr.add") < position(plan, "backend.stop"),
	    "and the teardown comes after the addressing, so the address is in first");
	planfix_release(plan, document, observed);

	/*
	 * **A backend no pass here starts is not one this pass may stop.** The
	 * access point and the two tunnels are started by passes this build does
	 * not have, so answering "the document does not ask for this" about them
	 * would stop something netcfgd never started and start nothing in its
	 * place.
	 *
	 * The supplicant used to be in that list and is not any more: `dot1x.c`
	 * starts one, so this build decides about one. A **radio's** supplicant is
	 * still started by nothing here, which is the arm that keeps the rule safe
	 * -- so the case is now that a radio's is left alone, and
	 * `plan_gaps_test.c` walks the rest of the rule.
	 */
	plan = plan_of("{}",
	    "\"devices\":[{\"name\":\"wlan0\",\"kind\":{\"kind\":\"physical\"},"
	    "\"wifi\":{}}],"
	    "\"interfaces\":[{\"name\":\"wlan0\",\"addressing\":[]}]",
	    "\"links\":[" LINK_UP("wlan0") "],"
	    "\"backends\":[{\"kind\":\"supplicant\",\"interface\":\"wlan0\",\"running\":true}]",
	    &document, &observed);
	check(plan && !has_name(plan, "backend.stop"),
	    "and a radio's supplicant, which this build cannot start, is not one it stops");
	planfix_release(plan, document, observed);
}

/* ------------------------------------------------------------------------ *
 * A `delegated` source, and the idempotence it is really about
 * ------------------------------------------------------------------------ */

#define DELEGATED_LAN0 \
	"\"devices\":[{\"name\":\"lan0\",\"kind\":{\"kind\":\"physical\"}}]," \
	"\"interfaces\":[{\"name\":\"lan0\",\"addressing\":[{\"source\":\"delegated\"," \
	"\"prefix\":{\"source\":\"wan0\",\"index\":0,\"subnet\":1},\"suffix\":\"::1/64\"}]}]"

#define DELEGATION(prefix) \
	"\"delegations\":[{\"interface\":\"wan0\",\"prefixes\":[\"" prefix "\"]}]"

static void a_delegated_prefix_becomes_an_address(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = plan_of("{}", DELEGATED_LAN0,
	    "\"links\":[" LINK_UP("lan0") "]," DELEGATION("2001:db8:0:100::/56"),
	    &document, &observed);

	check(plan && has_name(plan, "addr.add"), "a delegated prefix produces an address");
	/* Subnet 1 of a /56 carved into /64s is the block whose 64th bit is set:
	 * `2001:db8:0:101::/64`, and the host part is the suffix's. */
	check(plan && wrote(plan, "\"addr\":\"2001:db8:0:101::1/64\""),
	    "and it is the sub-prefix the reference names, with the suffix underneath");
	check(plan && wrote(plan, "(from wan0)"),
	    "and the reason names the interface that was delegated it");
	planfix_release(plan, document, observed);
}

/*
 * **The property this whole file is arranged around.**
 *
 * The document holds a reference rather than the value, so answering "is this
 * address wanted?" in the teardown means resolving it again. A teardown that
 * could not would delete the address the same plan had just added, on every
 * reconcile, for ever.
 */
static void a_delegated_address_already_installed_plans_nothing(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = plan_of("{}", DELEGATED_LAN0,
	    "\"links\":[" LINK_UP("lan0") "]," DELEGATION("2001:db8:0:100::/56") ","
	    "\"addresses\":[{\"interface\":\"lan0\",\"address\":\"2001:db8:0:101::1/64\","
	    "\"proto\":110,\"ownership\":\"ours\",\"origin\":\"static\"}]",
	    &document, &observed);
	char names[512];

	if (plan) {
		planfix_names(plan, names, sizeof(names));
		if (!ncfg_plan_is_empty(plan)) {
			printf("  expected nothing to do: %s\n", names);
		}
	}
	check(plan && ncfg_plan_is_empty(plan),
	    "applying a delegated address twice produces an empty second plan");
	planfix_release(plan, document, observed);

	/*
	 * **And the same address in a spelling nobody would have typed.** 10.169:
	 * a report's address compared as text broke exactly this -- one address
	 * written twice reads as two, and netcfgd plans it again on every run.
	 * The kernel's own rendering is what the observation carries, so this is
	 * the case that says the comparison is an address comparison.
	 */
	plan = plan_of("{}", DELEGATED_LAN0,
	    "\"links\":[" LINK_UP("lan0") "]," DELEGATION("2001:db8:0:100::/56") ","
	    "\"addresses\":[{\"interface\":\"lan0\","
	    "\"address\":\"2001:0DB8:0000:0101:0000:0000:0000:0001/64\","
	    "\"proto\":110,\"ownership\":\"ours\",\"origin\":\"static\"}]",
	    &document, &observed);
	check(plan && ncfg_plan_is_empty(plan),
	    "and so does one the kernel spelled differently, because addresses are compared");
	planfix_release(plan, document, observed);
}

/*
 * Renumbering falls out of the ordinary diff: a new delegation produces a
 * different address, the old one is no longer wanted, and the plan is an
 * `addr.add` and an `addr.del` -- in that order, because teardown is last and
 * the new address is in place before the old one goes.
 */
static void a_renumbering_is_an_add_and_then_a_delete(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = plan_of("{}", DELEGATED_LAN0,
	    "\"links\":[" LINK_UP("lan0") "]," DELEGATION("2001:db8:0:200::/56") ","
	    "\"addresses\":[{\"interface\":\"lan0\",\"address\":\"2001:db8:0:101::1/64\","
	    "\"proto\":110,\"ownership\":\"ours\",\"origin\":\"static\"}]",
	    &document, &observed);

	check(plan && has_name(plan, "addr.add") && has_name(plan, "addr.del"),
	    "a prefix that moved is a new address and the old one withdrawn");
	check(plan && position(plan, "addr.add") < position(plan, "addr.del"),
	    "and the new one is in place before the old one goes");
	check(plan && wrote(plan, "\"addr\":\"2001:db8:0:201::1/64\""),
	    "and what is added is derived from the prefix that arrived");
	planfix_release(plan, document, observed);
}

/*
 * Ordering rule 4, over an address the document never spelled.
 *
 * A route whose next hop lies inside an address's subnet waits for that
 * address -- and the pass that adds a derived one has to record it for the
 * route pass to find, exactly as the static one does. Without that the route
 * is planned with no edge, the kernel is asked for a gateway that is not yet
 * reachable, and `route.add` fails on the first apply of a machine whose
 * addressing comes from a delegation.
 */
static void a_route_waits_for_the_derived_address_that_covers_its_gateway(void)
{
	ncfg_document_t     *document;
	ncfg_observed_t     *observed;
	ncfg_plan_t         *plan = plan_of("{}",
	    "\"devices\":[{\"name\":\"lan0\",\"kind\":{\"kind\":\"physical\"}}],"
	    "\"interfaces\":[{\"name\":\"lan0\",\"addressing\":[{\"source\":\"delegated\","
	    "\"prefix\":{\"source\":\"wan0\",\"index\":0,\"subnet\":1},\"suffix\":\"::1/64\"}],"
	    "\"routes\":[{\"destination\":\"default\",\"via\":\"2001:db8:0:101::ff\"}]}]",
	    "\"links\":[" LINK_UP("lan0") "]," DELEGATION("2001:db8:0:100::/56"),
	    &document, &observed);
	const ncfg_action_t *added = plan ? planfix_action(plan, "addr.add") : NULL;
	const ncfg_action_t *route = plan ? planfix_action(plan, "route.add") : NULL;

	check(added && route && planfix_depends_on(route, added->id),
	    "a route through a derived address waits for it, as it would a literal one");
	planfix_release(plan, document, observed);
}

/* None of the three ways a reference fails to resolve is an error, and each
 * says which it is: an operator with "no addresses here" needs to know whether
 * to look at netcfgd or at the thing that delegates. */
static void a_reference_that_cannot_be_resolved_is_said_rather_than_guessed(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = plan_of("{}", DELEGATED_LAN0,
	    "\"links\":[" LINK_UP("lan0") "]", &document, &observed);

	check(plan && !has_name(plan, "addr.add") &&
	    planfix_warned(plan, "waiting on a delegated prefix from wan0"),
	    "a delegation that has not arrived is waited for, not guessed at");
	planfix_release(plan, document, observed);

	plan = plan_of("{}",
	    "\"devices\":[{\"name\":\"lan0\",\"kind\":{\"kind\":\"physical\"}}],"
	    "\"interfaces\":[{\"name\":\"lan0\",\"addressing\":[{\"source\":\"delegated\","
	    "\"prefix\":{\"source\":\"wan0\",\"index\":3,\"subnet\":0},"
	    "\"suffix\":\"::1/64\"}]}]",
	    "\"links\":[" LINK_UP("lan0") "]," DELEGATION("2001:db8:0:100::/56"),
	    &document, &observed);
	check(plan && !has_name(plan, "addr.add") &&
	    planfix_warned(plan, "wan0 has 1 delegated prefix(es) and this source asks for index 3"),
	    "an index the lease does not carry is named, with how many there were");
	planfix_release(plan, document, observed);

	/*
	 * A sub-prefix shorter than the block it is carved from would silently
	 * widen the interface's route to cover addresses the ISP did not give this
	 * machine, so it is refused loudly rather than clamped.
	 */
	plan = plan_of("{}",
	    "\"devices\":[{\"name\":\"lan0\",\"kind\":{\"kind\":\"physical\"}}],"
	    "\"interfaces\":[{\"name\":\"lan0\",\"addressing\":[{\"source\":\"delegated\","
	    "\"prefix\":{\"source\":\"wan0\",\"index\":0,\"subnet\":0},"
	    "\"suffix\":\"::1/48\"}]}]",
	    "\"links\":[" LINK_UP("lan0") "]," DELEGATION("2001:db8:0:100::/56"),
	    &document, &observed);
	check(plan && !has_name(plan, "addr.add") &&
	    planfix_warned(plan, "a /48 cannot be carved out of a /56"),
	    "and a suffix that would widen the block names both lengths");
	planfix_release(plan, document, observed);
}

/* The arithmetic itself, which two passes and `ncfg explain` all now share. */
static void the_delegation_arithmetic(void)
{
	char out[NCFG_ADDRESS_MAX];
	char err[NCFG_ERROR_MAX];

	check(ncfg_address_from_delegation("2001:db8:0:100::/56", 0, "::1/64", out, sizeof(out),
	    err, sizeof(err)) && strcmp(out, "2001:db8:0:100::1/64") == 0,
	    "subnet 0 of a /56 is the block itself with the suffix underneath");
	check(ncfg_address_from_delegation("2001:db8:0:100::/56", 255, "::1/64", out, sizeof(out),
	    err, sizeof(err)) && strcmp(out, "2001:db8:0:1ff::1/64") == 0,
	    "and the selector's last bit lands on the sub-prefix boundary");
	/*
	 * An ISP that hands out `2001:db8:1234:5678::/56` -- and they do -- has
	 * bits below its own length that belong to nobody, and carrying them
	 * through would produce an address outside the block that was delegated.
	 */
	check(ncfg_address_from_delegation("2001:db8:1234:5678::/56", 1, "::1/64", out,
	    sizeof(out), err, sizeof(err)) && strcmp(out, "2001:db8:1234:5601::1/64") == 0,
	    "bits below the delegation's own length are cleared before anything is added");
	check(!ncfg_address_from_delegation("2001:db8::/56", 256, "::1/64", out, sizeof(out), err,
	    sizeof(err)) && strstr(err, "does not fit") != NULL,
	    "a selector with nowhere to go is refused with how many blocks there are");
	check(!ncfg_address_from_delegation("192.0.2.0/24", 0, "::1/64", out, sizeof(out), err,
	    sizeof(err)) && strstr(err, "not an IPv6 prefix") != NULL,
	    "a delegation that is not IPv6 is refused by name");
	check(!ncfg_address_from_delegation("2001:db8::/56", 0, "::1", out, sizeof(out), err,
	    sizeof(err)) && strstr(err, "prefix length") != NULL,
	    "and a suffix with no prefix length is refused, since it decides the sub-block");
	check(!ncfg_address_from_delegation(NULL, 0, "::1/64", out, sizeof(out), err, sizeof(err)),
	    "nothing in place of a prefix is a refusal rather than a walk through NULL");
	/* A selector wider than the field a prefix reference carries. */
	check(!ncfg_address_from_delegation("2001:db8::/56", 65536, "::1/64", out, sizeof(out),
	    err, sizeof(err)) && strstr(err, "0 to 65535") != NULL,
	    "and a selector outside what a prefix reference holds names the range");
}

/* ------------------------------------------------------------------------ *
 * DNS
 * ------------------------------------------------------------------------ */

#define RESOLV_GLOBALS \
	"{\"dns\":{\"mode\":\"write_resolv_conf\",\"servers\":[{\"addr\":\"9.9.9.9\"}]}}"

#define BARE_ETH0 \
	"\"devices\":[{\"name\":\"eth0\",\"kind\":{\"kind\":\"physical\"}}]," \
	"\"interfaces\":[{\"name\":\"eth0\",\"addressing\":[]}]"

static void a_global_dns_block_is_delivered_once(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = plan_of(RESOLV_GLOBALS, BARE_ETH0,
	    "\"links\":[" LINK_UP("eth0") "]", &document, &observed);

	check(plan && has_name(plan, "dns.apply") && wrote(plan, "\"scope\":\"globals\""),
	    "a global dns block is delivered");
	planfix_release(plan, document, observed);

	/*
	 * Read back from `<run>/dns/`. Without it a plan could not tell an
	 * already-applied policy from an unapplied one, and every run would emit a
	 * `dns.apply` -- which is the idempotence gate failing.
	 */
	plan = plan_of(RESOLV_GLOBALS, BARE_ETH0,
	    "\"links\":[" LINK_UP("eth0") "],"
	    "\"dns\":[{\"scope\":\"globals\",\"policy\":{\"mode\":\"write_resolv_conf\","
	    "\"servers\":[{\"addr\":\"9.9.9.9\"}]}}]",
	    &document, &observed);
	check(plan && ncfg_plan_is_empty(plan),
	    "and a policy already in force is not delivered a second time");
	planfix_release(plan, document, observed);

	/* A member that moved is a different policy, whichever member it is --
	 * which is what comparing through the writer buys. */
	plan = plan_of(RESOLV_GLOBALS, BARE_ETH0,
	    "\"links\":[" LINK_UP("eth0") "],"
	    "\"dns\":[{\"scope\":\"globals\",\"policy\":{\"mode\":\"write_resolv_conf\","
	    "\"servers\":[{\"addr\":\"9.9.9.9\"}],\"search\":[\"example\"]}}]",
	    &document, &observed);
	check(plan && has_name(plan, "dns.apply"),
	    "and a search suffix that is no longer asked for is a change like any other");
	check(reversible(plan, "dns.apply"),
	    "with what was delivered before as the way back");
	planfix_release(plan, document, observed);
}

/*
 * The mode is not a per-interface choice: a host cannot both own
 * `resolv.conf` and hand it to `resolvconf`, and the delivery refuses a set of
 * scopes that disagree. So `none` on a scope that has something to deliver can
 * only mean "not stated" -- and without this, `dns = "9.9.9.9"` on an
 * interface compiles to a policy with mode `none`, the scope is dropped, and
 * an operator wrote a nameserver down that netcfgd silently ignored.
 */
static void an_interface_scope_takes_the_hosts_mode_where_it_states_none(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = plan_of(RESOLV_GLOBALS,
	    "\"devices\":[{\"name\":\"eth0\",\"kind\":{\"kind\":\"physical\"}}],"
	    "\"interfaces\":[{\"name\":\"eth0\",\"addressing\":[],"
	    "\"dns\":{\"mode\":\"none\",\"servers\":[{\"addr\":\"10.0.0.53\"}]}}]",
	    "\"links\":[" LINK_UP("eth0") "]", &document, &observed);

	check(plan && wrote(plan, "\"scope\":\"eth0\""),
	    "an interface with servers and no mode of its own is still a scope");
	/* Named with the scope in front of it: the global scope carries the same
	 * mode, so a fragment naming the mode alone is satisfied by an `eth0`
	 * scope delivered as `none`. */
	check(plan && wrote(plan, "\"scope\":\"eth0\",\"policy\":{\"mode\":\"write_resolv_conf\""),
	    "and it takes the host's mode, or the delivery would drop it");
	planfix_release(plan, document, observed);

	/* `dns { }` with nothing in it asks for nothing, and a scope for it is an
	 * action that does nothing -- which somebody reads and dismisses on every
	 * run. */
	plan = plan_of(RESOLV_GLOBALS,
	    "\"devices\":[{\"name\":\"eth0\",\"kind\":{\"kind\":\"physical\"}}],"
	    "\"interfaces\":[{\"name\":\"eth0\",\"addressing\":[],\"dns\":{\"mode\":\"none\"}}]",
	    "\"links\":[" LINK_UP("eth0") "],"
	    "\"dns\":[{\"scope\":\"globals\",\"policy\":{\"mode\":\"write_resolv_conf\","
	    "\"servers\":[{\"addr\":\"9.9.9.9\"}]}}]",
	    &document, &observed);
	check(plan && ncfg_plan_is_empty(plan),
	    "and an empty `dns { }` with nothing reported contributes no scope at all");
	planfix_release(plan, document, observed);
}

/*
 * Rule 4: a source contributes nameservers and they merge with what the
 * document wrote -- **where the interface asked**, which an empty `dns { }`
 * block is how you say. A lease's nameservers offered to an interface that did
 * not ask are left alone: where an operator kept their own resolvers, a lease
 * does not get to redefine what a bare name means (0049).
 */
static void a_leases_nameservers_are_taken_only_where_the_interface_asked(void)
{
	static const char *const asked =
	    "\"devices\":[{\"name\":\"eth0\",\"kind\":{\"kind\":\"physical\"}}],"
	    "\"interfaces\":[{\"name\":\"eth0\",\"addressing\":[],"
	    "\"dns\":{\"mode\":\"none\"}}]";
	static const char *const reported =
	    "\"links\":[" LINK_UP("eth0") "],"
	    "\"reports\":[{\"interface\":\"eth0\",\"addresses\":[],\"gateways\":[],"
	    "\"nameservers\":[\"10.0.0.53\"],\"search\":[\"corp.example\"],\"routes\":[]}]";
	ncfg_document_t         *document;
	ncfg_observed_t         *observed;
	ncfg_plan_t             *plan;

	plan = plan_of(RESOLV_GLOBALS, asked, reported, &document, &observed);
	check(plan && wrote(plan, "\"addr\":\"10.0.0.53\""),
	    "an empty `dns { }` takes the nameservers the network handed out");
	check(plan && wrote(plan, "corp.example"),
	    "and the suffixes with them, which is the same gate for the same reason");
	/* The document's servers come first, so first-occurrence-wins means a
	 * server an operator chose beats one the network handed out -- and the
	 * global scope is untouched by any of it. */
	check(plan && wrote(plan, "\"scope\":\"eth0\""),
	    "and what it produces is that interface's own scope");
	planfix_release(plan, document, observed);

	plan = plan_of(RESOLV_GLOBALS, BARE_ETH0,
	    "\"links\":[" LINK_UP("eth0") "],"
	    "\"dns\":[{\"scope\":\"globals\",\"policy\":{\"mode\":\"write_resolv_conf\","
	    "\"servers\":[{\"addr\":\"9.9.9.9\"}]}}],"
	    "\"reports\":[{\"interface\":\"eth0\",\"addresses\":[],\"gateways\":[],"
	    "\"nameservers\":[\"10.0.0.53\"],\"search\":[],\"routes\":[]}]",
	    &document, &observed);
	check(plan && ncfg_plan_is_empty(plan),
	    "an interface that asked for nothing takes nothing, and plans nothing");
	planfix_release(plan, document, observed);

	/*
	 * **And a scope that states a mode of its own merges just the same.** The
	 * document's servers come first, so first-occurrence-wins means a server
	 * an operator chose beats one the network handed out -- which is the whole
	 * of rule 4's precedence, and is lost the moment a stated mode is taken as
	 * a reason to hand the document's own policy straight through.
	 */
	plan = plan_of(RESOLV_GLOBALS,
	    "\"devices\":[{\"name\":\"eth0\",\"kind\":{\"kind\":\"physical\"}}],"
	    "\"interfaces\":[{\"name\":\"eth0\",\"addressing\":[],"
	    "\"dns\":{\"mode\":\"write_resolv_conf\",\"servers\":[{\"addr\":\"1.1.1.1\"}]}}]",
	    "\"links\":[" LINK_UP("eth0") "],"
	    "\"reports\":[{\"interface\":\"eth0\",\"addresses\":[],\"gateways\":[],"
	    "\"nameservers\":[\"10.0.0.53\"],\"search\":[],\"routes\":[]}]",
	    &document, &observed);
	check(plan && wrote(plan, "{\"addr\":\"1.1.1.1\"},{\"addr\":\"10.0.0.53\"}"),
	    "a scope with a mode of its own still merges, with the document's server first");
	planfix_release(plan, document, observed);

	/*
	 * A report is text somebody's script wrote, and a nameserver is one
	 * address: `10.0.0.53/24` in a `nameserver` line is a resolver file
	 * nothing can use. Dropped rather than carried, and the rest of the report
	 * survives it -- which is why the reader keeps these as text in the first
	 * place.
	 */
	plan = plan_of(RESOLV_GLOBALS, asked,
	    "\"links\":[" LINK_UP("eth0") "],"
	    "\"reports\":[{\"interface\":\"eth0\",\"addresses\":[],\"gateways\":[],"
	    "\"nameservers\":[\"10.0.0.53/24\",\"10.0.0.54\"],\"search\":[],\"routes\":[]}]",
	    &document, &observed);
	check(plan && wrote(plan, "\"addr\":\"10.0.0.54\"") &&
	    !wrote(plan, "10.0.0.53"),
	    "a nameserver written as a prefix is dropped and the one beside it is kept");
	planfix_release(plan, document, observed);

	/*
	 * **And what a report contributes is the model's spelling of it.**
	 *
	 * A report is text somebody's script wrote and is deliberately kept as
	 * text by the reader, so one bad line does not discard the rest. The
	 * delivery records what it wrote and the observer reads that record back,
	 * so a server carried through in the author's spelling compares unequal
	 * against netcfgd's own record of having delivered it -- and `dns.apply`
	 * is planned on every single run. Same defect as 10.169, one field over.
	 */
	plan = plan_of(RESOLV_GLOBALS, asked,
	    "\"links\":[" LINK_UP("eth0") "],"
	    "\"dns\":[{\"scope\":\"globals\",\"policy\":{\"mode\":\"write_resolv_conf\","
	    "\"servers\":[{\"addr\":\"9.9.9.9\"}]}},"
	    "{\"scope\":\"eth0\",\"policy\":{\"mode\":\"write_resolv_conf\","
	    "\"servers\":[{\"addr\":\"2001:db8::53\"}]}}],"
	    "\"reports\":[{\"interface\":\"eth0\",\"addresses\":[],\"gateways\":[],"
	    "\"nameservers\":[\"2001:0DB8:0000::0053\"],\"search\":[],\"routes\":[]}]",
	    &document, &observed);
	check(plan && ncfg_plan_is_empty(plan),
	    "a nameserver a report spelled its own way is delivered once, not once a run");
	planfix_release(plan, document, observed);
}

/*
 * A delivery with no servers anywhere overwrites a working `resolv.conf` with
 * a file that resolves nothing, and said nothing about it: `ncfg plan` showed
 * `dns.apply` and the machine's DNS was gone. Nothing is planned, which is the
 * whole of the fix -- writing nothing preserves what is on disk, which is the
 * one behaviour that leaves the machine fixable.
 */
static void a_delivery_with_no_servers_is_not_written(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = plan_of("{\"dns\":{\"mode\":\"write_resolv_conf\"}}", BARE_ETH0,
	    "\"links\":[" LINK_UP("eth0") "]", &document, &observed);

	check(plan && !has_name(plan, "dns.apply"),
	    "a delivery with no servers in it is not written over a working resolver file");
	check(plan && planfix_warned(plan, "nothing in the configuration names a nameserver"),
	    "and the reason is the one netcfgd knows and the operator cannot see");
	planfix_release(plan, document, observed);

	/* The commonest case has an answer in one line, and the warning gives it. */
	plan = plan_of("{\"dns\":{\"mode\":\"write_resolv_conf\"}}", BARE_ETH0,
	    "\"links\":[" LINK_UP("eth0") "],"
	    "\"reports\":[{\"interface\":\"eth0\",\"addresses\":[],\"gateways\":[],"
	    "\"nameservers\":[\"10.0.0.53\"],\"search\":[],\"routes\":[]}]",
	    &document, &observed);
	check(plan && planfix_warned(plan, "a lease on eth0 offered nameservers and no interface "
	    "asked for them"),
	    "and a lease whose servers nothing asked for is named, with what to write");
	planfix_release(plan, document, observed);

	/* And a document that manages no DNS at all -- which is the default -- is
	 * told nothing, because "all of an empty list" is true. */
	plan = plan_of("{}", BARE_ETH0, "\"links\":[" LINK_UP("eth0") "]", &document, &observed);
	check(plan && plan->warning_count == 0u,
	    "a document that manages no DNS is not warned about a file it never writes");
	planfix_release(plan, document, observed);
}

/*
 * A scope netcfgd applied and the document no longer has.
 *
 * The delivery loop walks what is *desired*, so a scope that went away was
 * never visited and its nameservers stayed in the resolver file for ever, with
 * `ncfg plan` saying `nothing to do` beside them. The file is written whole on
 * any delivery, so one re-delivery is the whole of the repair.
 */
static void a_scope_that_left_the_document_is_delivered_away(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = plan_of(RESOLV_GLOBALS, BARE_ETH0,
	    "\"links\":[" LINK_UP("eth0") "],"
	    "\"dns\":[{\"scope\":\"globals\",\"policy\":{\"mode\":\"write_resolv_conf\","
	    "\"servers\":[{\"addr\":\"9.9.9.9\"}]}},"
	    "{\"scope\":\"eth0\",\"policy\":{\"mode\":\"write_resolv_conf\","
	    "\"servers\":[{\"addr\":\"10.0.0.53\"}]}}]",
	    &document, &observed);

	check(plan && has_name(plan, "dns.apply"),
	    "a scope netcfgd delivered and the document dropped is delivered away");
	check(plan && wrote(plan, "eth0"),
	    "and the reason names the scope that left, since the action cannot");
	planfix_release(plan, document, observed);
}

/*
 * An unmanaged device contributes no scope. `dns.apply` is host-wide, so it
 * names no interface and the planner's usual choke point never sees it -- this
 * is the one pass that has to ask for itself.
 */
static void an_unmanaged_device_contributes_no_scope(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = plan_of(RESOLV_GLOBALS,
	    "\"devices\":[{\"name\":\"eth0\",\"kind\":{\"kind\":\"physical\"},"
	    "\"managed\":false}],"
	    "\"interfaces\":[{\"name\":\"eth0\",\"addressing\":[],"
	    "\"dns\":{\"mode\":\"none\",\"servers\":[{\"addr\":\"10.0.0.53\"}]}}]",
	    "\"links\":[" LINK_UP("eth0") "],"
	    "\"dns\":[{\"scope\":\"globals\",\"policy\":{\"mode\":\"write_resolv_conf\","
	    "\"servers\":[{\"addr\":\"9.9.9.9\"}]}}]",
	    &document, &observed);
	char *text = plan ? written(plan) : NULL;

	check(text && strstr(text, "\"scope\":\"eth0\"") == NULL,
	    "an unmanaged device's dns block is not delivered");
	free(text);
	planfix_release(plan, document, observed);
}

/* ------------------------------------------------------------------------ *
 * The hostname
 * ------------------------------------------------------------------------ */

static void the_hostname_is_set_where_the_document_names_one(void)
{
	ncfg_document_t     *document;
	ncfg_observed_t     *observed;
	ncfg_plan_t         *plan = plan_of("{\"hostname_policy\":{\"static\":\"kitchen\"}}",
	    BARE_ETH0, "\"links\":[" LINK_UP("eth0") "],\"hostname\":\"localhost\"",
	    &document, &observed);
	const ncfg_action_t *set = plan ? planfix_action(plan, "hostname.set") : NULL;

	check(set != NULL && wrote(plan, "\"name\":\"kitchen\""),
	    "a static hostname the machine does not have is set");
	/* The previous name is known, so the revert is the real thing rather than
	 * a guess -- which is what makes this the one direction that has one. */
	check(set && set->has_inverse && set->inverse.kind == NCFG_OP_HOSTNAME_SET &&
	    set->inverse.u.named.name && strcmp(set->inverse.u.named.name, "localhost") == 0,
	    "and the name the machine had is what a revert puts back");
	planfix_release(plan, document, observed);

	plan = plan_of("{\"hostname_policy\":{\"static\":\"kitchen\"}}", BARE_ETH0,
	    "\"links\":[" LINK_UP("eth0") "],\"hostname\":\"kitchen\"", &document, &observed);
	check(plan && ncfg_plan_is_empty(plan),
	    "and a machine already carrying it is left alone, or the plan never converges");
	planfix_release(plan, document, observed);

	/*
	 * A hostname netcfgd cannot read is one it cannot tell whether it has
	 * already set, and writing it on every reconcile would be a plan that
	 * never converges.
	 */
	plan = plan_of("{\"hostname_policy\":{\"static\":\"kitchen\"}}", BARE_ETH0,
	    "\"links\":[" LINK_UP("eth0") "]", &document, &observed);
	check(plan && !has_name(plan, "hostname.set") &&
	    planfix_warned(plan, "the hostname cannot be read"),
	    "a hostname that cannot be read is reported rather than written blind");
	planfix_release(plan, document, observed);

	/*
	 * `hostname = "dhcp"` is refused with a sentence rather than obeyed:
	 * netcfgd delegates DHCP and never sees the lease, and a hostname is the
	 * machine's identity -- which 0049 already decided a remote server does
	 * not get to change by connecting.
	 */
	plan = plan_of("{\"hostname_policy\":\"from_dhcp\"}", BARE_ETH0,
	    "\"links\":[" LINK_UP("eth0") "],\"hostname\":\"localhost\"", &document, &observed);
	check(plan && !has_name(plan, "hostname.set") &&
	    planfix_warned(plan, "netcfgd delegates DHCP and never sees the lease"),
	    "`hostname = \"dhcp\"` is answered with the mechanism that does exist");
	planfix_release(plan, document, observed);

	/* And a document that says nothing says nothing: there is deliberately no
	 * withdraw direction, the value to put back being one netcfgd does not
	 * know and must not guess. */
	plan = plan_of("{}", BARE_ETH0,
	    "\"links\":[" LINK_UP("eth0") "],\"hostname\":\"localhost\"", &document, &observed);
	check(plan && ncfg_plan_is_empty(plan) && plan->warning_count == 0u,
	    "and a document with no hostname policy neither sets one nor takes one away");
	planfix_release(plan, document, observed);
}

int main(void)
{
	slaac_makes_the_kernel_listen_where_it_would_not();
	accept_ra_is_read_against_the_forwarding_this_plan_will_produce();
	a_sysctl_is_handed_back_only_where_netcfgd_changed_it();
	a_sysctl_that_cannot_be_read_is_reported_not_written();
	a_link_being_created_gets_its_sysctls_on_the_first_apply();
	the_kernel_is_told_to_listen_before_the_link_comes_up();
	temporary_addresses_are_asked_for_by_the_slaac_source();
	forwarding_is_per_interface_and_reversible();

	a_dhcp_source_starts_the_client_that_serves_it();
	a_client_that_will_not_stay_up_is_not_started_for_ever();
	a_client_the_document_no_longer_asks_for_is_stopped();

	a_delegated_prefix_becomes_an_address();
	a_delegated_address_already_installed_plans_nothing();
	a_renumbering_is_an_add_and_then_a_delete();
	a_route_waits_for_the_derived_address_that_covers_its_gateway();
	a_reference_that_cannot_be_resolved_is_said_rather_than_guessed();
	the_delegation_arithmetic();

	a_global_dns_block_is_delivered_once();
	an_interface_scope_takes_the_hosts_mode_where_it_states_none();
	a_leases_nameservers_are_taken_only_where_the_interface_asked();
	a_delivery_with_no_servers_is_not_written();
	a_scope_that_left_the_document_is_delivered_away();
	an_unmanaged_device_contributes_no_scope();

	the_hostname_is_set_where_the_document_names_one();

	printf("\nplan addressing: %d checks, %d failed\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
