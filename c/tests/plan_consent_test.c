/*
 * plan_consent_test.c -- the two consents that are not about disruption.
 *
 * WHAT THEY HAVE IN COMMON
 *   Each is a thing netcfgd will not do by default, says so in a way a script
 *   can read, and names the exact invocation that changes the answer.
 *   `--allow-disruption` is the third and older one; these two are 0042's and
 *   0141's, and both were parsed by the CLI, carried over the socket, and then
 *   dropped -- the planner had no option to put them in.
 *
 * WHY EACH DEFAULT IS THE WAY ROUND IT IS
 *   **A wedged backend is not restarted.** netcfgd cannot tell a wedged daemon
 *   from a slow answer on a loaded machine -- the deadline behind `answering`
 *   is one second, so that a wedged daemon cannot stall the reconcile loop --
 *   and killing a healthy access point drops every station on the radio. So
 *   the operator is told and the operator decides.
 *
 *   **An irrevocable credential is reported rather than silently left.** A
 *   WireGuard private key loaded in the kernel cannot be withdrawn from this
 *   host: its authority is the matching public key in every peer's
 *   configuration. Walking away from the device leaves it there, and the
 *   notice names both ways out -- the configuration change that destroys it,
 *   and the flag that consents to leaving it.
 *
 * NOTHING HERE IS A MACHINE
 *   A plan is a value: these cases build a document and an observation and
 *   read what comes out. Whether the *executor* can carry a restart out is
 *   `service_test.c`'s question.
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

/*
 * A plan built with options, which `planfix_plan` does not do -- it passes
 * NULL, which is every other pass's ordinary case and is exactly what these
 * two features are not about.
 */
static ncfg_plan_t *plan_with(const char *devices, const char *interfaces, const char *extra,
    const char *observation, const ncfg_plan_options_t *options,
    ncfg_document_t **document_out, ncfg_observed_t **observed_out)
{
	char             message[NCFG_ERROR_MAX];
	ncfg_document_t *document = planfix_document(devices, interfaces, "", extra);
	ncfg_observed_t *observed = planfix_observed(observation);
	ncfg_plan_t     *plan;

	*document_out = document;
	*observed_out = observed;
	if (!document || !observed) {
		return NULL;
	}
	message[0] = '\0';
	plan = ncfg_plan_build(document, observed, options, message, sizeof(message));
	if (!plan) {
		printf("  could not build the plan: %s\n", message);
	}
	return plan;
}

/* The refusal of this op, or NULL. */
static const ncfg_refusal_t *refusal_of(const ncfg_plan_t *plan, const char *op)
{
	size_t at;

	for (at = 0; at < plan->refusal_count; at++) {
		if (plan->refusals[at].op && strcmp(plan->refusals[at].op, op) == 0) {
			return &plan->refusals[at];
		}
	}
	return NULL;
}

/* ------------------------------------------------------------------------ *
 * A backend that is running and will not answer
 * ------------------------------------------------------------------------ */

/* A radio with an access point on it, so there is a backend to be wedged. */
#define RADIO "{\"name\":\"wlan0\",\"kind\":{\"kind\":\"physical\"}}"
/* No addressing on it, deliberately: a `dhcp4` source would plan a
 * `backend.start` of its own and every count below would be about two
 * backends at once. The subject here is the one that is wedged. */
#define RADIO_INTERFACE "{\"name\":\"wlan0\"}"
/* The access point the running backend belongs to. Without it the document is
 * one that no longer asks for the daemon, so the teardown pass stops it -- a
 * correct `backend.stop` about something else entirely, which is what every
 * count below would then be measuring. */
#define POINT                                                                        \
	",\"access_points\":[{\"id\":\"home\",\"ssid\":\"686f6d65\","              \
	"\"device\":\"wlan0\",\"security\":{\"type\":\"open\"}}]"

#define RADIO_LINK                                                                   \
	"\"links\":[{\"name\":\"wlan0\",\"index\":3,\"mtu\":1500,\"up\":true,"        \
	"\"carrier\":true,\"ownership\":\"ours\"}]"
/* Running, and silent when netcfgd last asked. `answering` absent is a
 * different answer and is the case two cases down. */
#define WEDGED(body)                                                                 \
	",\"backends\":[{\"kind\":\"access_point\",\"interface\":\"wlan0\","          \
	"\"running\":true,\"answering\":false" body "}]"

static void a_wedged_backend_is_reported_and_not_restarted(void)
{
	ncfg_document_t      *document;
	ncfg_observed_t      *observed;
	ncfg_plan_t          *plan = plan_with(RADIO, RADIO_INTERFACE, POINT, RADIO_LINK WEDGED(""),
	    NULL, &document, &observed);
	const ncfg_refusal_t *refusal = plan ? refusal_of(plan, "backend.restart") : NULL;

	check(plan && planfix_warned(plan, "did not answer its control socket"),
	    "a backend that is running and silent is reported");
	check(plan && planfix_warned(plan, "access point on wlan0"),
	    "  by the noun an operator would use for it");
	check(plan && planfix_warned(plan, "does not restart it by default"),
	    "  saying that netcfgd will not restart it, and why");
	check(refusal != NULL, "and the refusal is first-class, so a script can read it");
	check(refusal && refusal->override_with &&
	        strcmp(refusal->override_with, "ncfg apply --restart-wedged wlan0") == 0,
	    "  naming the exact invocation that consents");
	if (refusal && refusal->override_with) {
		detail("consent", refusal->override_with);
	}
	check(refusal && refusal->reason.field &&
	        strcmp(refusal->reason.field, "backend.answering") == 0,
	    "  and the reason names what was compared rather than the op");
	check(plan && planfix_count(plan, "backend.stop") == 0u &&
	        planfix_count(plan, "backend.start") == 0u,
	    "and nothing is killed, because a busy machine misses deadlines too");
	planfix_release(plan, document, observed);
}

static void the_operator_may_ask_for_the_restart(void)
{
	static const char *const named[] = { "wlan0" };
	ncfg_plan_options_t      options;
	ncfg_document_t         *document;
	ncfg_observed_t         *observed;
	ncfg_plan_t             *plan;
	const ncfg_action_t     *stop;
	const ncfg_action_t     *start;

	memset(&options, 0, sizeof(options));
	options.restart_wedged = named;
	options.restart_wedged_count = 1u;
	plan = plan_with(RADIO, RADIO_INTERFACE, POINT, RADIO_LINK WEDGED(""), &options, &document,
	    &observed);
	stop = plan ? planfix_action(plan, "backend.stop") : NULL;
	start = plan ? planfix_action(plan, "backend.start") : NULL;

	check(plan && planfix_count(plan, "backend.stop") == 1u &&
	        planfix_count(plan, "backend.start") == 1u,
	    "an interface named in `--restart-wedged` is stopped and started, once each");
	check(stop && start && planfix_depends_on(start, stop->id),
	    "  and the start waits for the stop, which is what a restart is");
	check(refusal_of(plan ? plan : NULL, "backend.restart") == NULL,
	    "  with no refusal left over, because nothing was refused");
	check(plan && planfix_warned(plan, "did not answer its control socket"),
	    "and the machine is still reported as it was found");
	/* The consent is for the interface named and no other: a second radio in
	 * the same state is still refused. */
	planfix_release(plan, document, observed);
}

/*
 * **Absent is not false.** `answering` says nothing where the kind has no
 * control socket or where nothing asked -- 0074 -- and reading it as a wedge
 * would put this warning on every DHCP client on the machine.
 */
static void a_backend_nobody_asked_is_not_wedged(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = plan_with(RADIO, RADIO_INTERFACE, POINT,
	    RADIO_LINK ",\"backends\":[{\"kind\":\"access_point\",\"interface\":\"wlan0\","
	    "\"running\":true}]",
	    NULL, &document, &observed);

	check(plan && !planfix_warned(plan, "did not answer its control socket"),
	    "a backend nothing asked is not reported as silent");
	check(plan && refusal_of(plan, "backend.restart") == NULL,
	    "  and nothing is refused about it");
	planfix_release(plan, document, observed);
}

/*
 * Consent is not consent to a loop.
 *
 * 0079's counter bounds this exactly as it bounds an ordinary start: a machine
 * that is merely slow would otherwise be restarted for ever by one
 * `--restart-wedged`.
 */
static void consent_does_not_outlive_the_restart_limit(void)
{
	static const char *const named[] = { "wlan0" };
	ncfg_plan_options_t      options;
	ncfg_document_t         *document;
	ncfg_observed_t         *observed;
	ncfg_plan_t             *plan;

	memset(&options, 0, sizeof(options));
	options.restart_wedged = named;
	options.restart_wedged_count = 1u;
	plan = plan_with(RADIO, RADIO_INTERFACE, POINT,
	    RADIO_LINK WEDGED("") ",\"backend_restarts\":[[\"access_point\",\"wlan0\",5]]",
	    &options, &document, &observed);

	check(plan && planfix_count(plan, "backend.stop") == 0u,
	    "a backend already restarted to the limit is not restarted again");
	check(plan && planfix_warned(plan, "did not answer its control socket"),
	    "  and is still reported, because it is still wedged");
	planfix_release(plan, document, observed);
}

/* ------------------------------------------------------------------------ *
 * A credential this plan walks away from
 * ------------------------------------------------------------------------ */

/* A WireGuard device the document has taken out of netcfgd's hands, and the
 * kernel still holding its key. */
#define UNMANAGED_WG                                                                 \
	"{\"name\":\"wg0\",\"managed\":false,\"kind\":{\"kind\":\"wire_guard\","       \
	"\"private_key\":{\"provider\":\"file\",\"name\":\"wg\"},\"peers\":[]}}"
#define CLEARING_WG                                                                  \
	"{\"name\":\"wg0\",\"managed\":false,\"on_unmanage\":\"clear\","              \
	"\"kind\":{\"kind\":\"wire_guard\","                                          \
	"\"private_key\":{\"provider\":\"file\",\"name\":\"wg\"},\"peers\":[]}}"
#define MANAGED_WG                                                                   \
	"{\"name\":\"wg0\",\"kind\":{\"kind\":\"wire_guard\","                         \
	"\"private_key\":{\"provider\":\"file\",\"name\":\"wg\"},\"peers\":[]}}"
#define KEYED_LINK                                                                   \
	"\"links\":[{\"name\":\"wg0\",\"index\":9,\"mtu\":1420,\"up\":true,"          \
	"\"carrier\":true,\"ownership\":\"ours\",\"private_key_loaded\":true}]"

static void a_key_left_on_an_unmanaged_device_is_reported(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = plan_with(UNMANAGED_WG, "", "", KEYED_LINK, NULL, &document,
	    &observed);

	check(plan && plan->stranded_count == 1u,
	    "a WireGuard key still loaded on a device netcfgd is walking away from is "
	    "reported");
	if (plan && plan->stranded_count == 1u) {
		const ncfg_stranded_t *stranded = &plan->stranded[0];

		check(stranded->interface && strcmp(stranded->interface, "wg0") == 0,
		    "  naming the interface it is loaded on");
		check(stranded->credential && strstr(stranded->credential, "WireGuard private key"),
		    "  and what it is");
		check(stranded->irrevocable &&
		        strstr(stranded->irrevocable, "every peer's configuration"),
		    "  and why it cannot simply be withdrawn from this host");
		check(stranded->remove_with &&
		        strcmp(stranded->remove_with,
		            "device wg0 { managed = false; on_unmanage = \"clear\" }") == 0,
		    "  with the configuration change that destroys it instead");
		check(stranded->consent_with &&
		        strcmp(stranded->consent_with,
		            "ncfg apply --strand-credentials wg0") == 0,
		    "  and the invocation that consents to leaving it");
		detail("remove with", stranded->remove_with);
	}
	check(plan && ncfg_plan_strands_credentials(plan),
	    "and the plan answers that it strands something, which is exit status 4");
	planfix_release(plan, document, observed);
}

static void the_operator_may_consent_to_leaving_it(void)
{
	static const char *const named[] = { "wg0" };
	ncfg_plan_options_t      options;
	ncfg_document_t         *document;
	ncfg_observed_t         *observed;
	ncfg_plan_t             *plan;

	memset(&options, 0, sizeof(options));
	options.strand_credentials = named;
	options.strand_credentials_count = 1u;
	plan = plan_with(UNMANAGED_WG, "", "", KEYED_LINK, &options, &document, &observed);

	check(plan && plan->stranded_count == 0u,
	    "a key the operator consented to leaving is not reported again");
	check(plan && !ncfg_plan_strands_credentials(plan),
	    "  and the plan no longer strands anything, so the exit status is 0");
	planfix_release(plan, document, observed);
}

/*
 * The two cases that are not a hazard at all.
 *
 * A device netcfgd still manages is not one it is walking away from, and a
 * device whose `on_unmanage` is `clear` has its link and its key removed --
 * reporting that would be reporting a hazard the operator has already dealt
 * with.
 */
static void a_key_that_is_nobodys_hazard_is_not_reported(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = plan_with(MANAGED_WG, "", "", KEYED_LINK, NULL, &document,
	    &observed);

	check(plan && plan->stranded_count == 0u,
	    "a key on a device netcfgd still manages is not stranded");
	planfix_release(plan, document, observed);

	plan = plan_with(CLEARING_WG, "", "", KEYED_LINK, NULL, &document, &observed);
	check(plan && plan->stranded_count == 0u,
	    "and neither is one on a device whose link is being cleared");
	check(plan && planfix_count(plan, "link.delete") == 1u,
	    "  because the clearing takes the key away with the link");
	planfix_release(plan, document, observed);
}

/*
 * **The observation decides, not the document.** A document declaring a key
 * for an interface that was never applied strands nothing, and a notice about
 * that would be a notice about a file.
 */
static void a_key_that_was_never_loaded_strands_nothing(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = plan_with(UNMANAGED_WG, "", "",
	    "\"links\":[{\"name\":\"wg0\",\"index\":9,\"mtu\":1420,\"up\":true,"
	    "\"carrier\":true,\"ownership\":\"ours\"}]",
	    NULL, &document, &observed);

	check(plan && plan->stranded_count == 0u,
	    "a device with no key loaded in the kernel strands nothing");
	planfix_release(plan, document, observed);
}

int main(void)
{
	a_wedged_backend_is_reported_and_not_restarted();
	the_operator_may_ask_for_the_restart();
	a_backend_nobody_asked_is_not_wedged();
	consent_does_not_outlive_the_restart_limit();

	a_key_left_on_an_unmanaged_device_is_reported();
	the_operator_may_consent_to_leaving_it();
	a_key_that_is_nobodys_hazard_is_not_reported();
	a_key_that_was_never_loaded_strands_nothing();

	printf("plan_consent_test: %d checks, %d failed\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
