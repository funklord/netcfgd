/*
 * plan_lock_test.c -- `global { locked = [...] }`, which refuses at plan time.
 *
 * WHAT IS WORTH CHECKING
 *   0290 says a lock means netcfgd may not *set* a value -- a different
 *   question from ownership's "may I remove this object" and from a guard's
 *   "may I disrupt this interface". So:
 *
 *     * **the refusal is in the plan, not at apply time.** 0010's reason: a
 *       veto that fires later means `ncfg plan` said "will set mtu 9000" and
 *       then nothing changed, and a plan that lies is worse than no plan.
 *     * **it names an edit, not an invocation.** A guard's refusal carries
 *       `ncfg apply --allow-disruption <iface>`; a lock has no per-apply
 *       waiver at all, and naming one would be a lie in the field an operator
 *       acts on.
 *     * **the control**: the same document without the lock plans the action,
 *       or the refusal above proves nothing about the lock.
 *     * **a lock is per value, so locking an MTU does not stop the link
 *       coming up** -- which is the whole difference from a guard, and the
 *       reason `ncfg_op_subject` gives an MTU a class of its own.
 *     * **and it does not reach another object of the same class**: locking
 *       one address leaves another alone.
 */
#include "planfix.h"

#include "ncfg/plan.h"

#include <stdio.h>
#include <string.h>

static int failures;

static void check(int condition, const char *what)
{
	printf("%-72s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

/* A document whose globals this case chooses, which `planfix_document` does
 * not allow -- it writes `"globals":{}`, and these cases are about one key in
 * there. */
static ncfg_document_t *document_with(const char *globals, const char *devices,
    const char *interfaces)
{
	char             text[4096];
	char             message[NCFG_ERROR_MAX];
	ncfg_document_t *document;

	(void)snprintf(text, sizeof(text),
	    "{\"schema_version\":{\"major\":1,\"minor\":1},\"generated_by\":\"plan_lock\","
	    "\"globals\":{%s},\"devices\":[%s],\"interfaces\":[%s],\"networks\":[]}",
	    globals, devices, interfaces);
	message[0] = '\0';
	document = ncfg_document_read(text, strlen(text), message, sizeof(message));
	if (!document) {
		printf("  fixture document did not read: %s\n", message);
	}
	return document;
}

static ncfg_plan_t *plan_of(const char *globals, const char *devices, const char *interfaces,
    const char *observation, ncfg_document_t **document_out, ncfg_observed_t **observed_out)
{
	char             message[NCFG_ERROR_MAX];
	ncfg_document_t *document = document_with(globals, devices, interfaces);
	ncfg_observed_t *observed = planfix_observed(observation);

	*document_out = document;
	*observed_out = observed;
	if (!document || !observed) {
		return NULL;
	}
	message[0] = '\0';
	return ncfg_plan_build(document, observed, NULL, message, sizeof(message));
}

static const ncfg_refusal_t *refusal_of(const ncfg_plan_t *plan, const char *op)
{
	size_t at;

	for (at = 0; plan && at < plan->refusal_count; at++) {
		if (plan->refusals[at].op && strcmp(plan->refusals[at].op, op) == 0) {
			return &plan->refusals[at];
		}
	}
	return NULL;
}

static int planned(const ncfg_plan_t *plan, const char *op)
{
	size_t at;

	for (at = 0; plan && at < plan->action_count; at++) {
		if (strcmp(ncfg_op_name(&plan->actions[at].op), op) == 0) {
			return 1;
		}
	}
	return 0;
}

/* eth0 as the kernel has it: mtu 1500 and down. The document below asks for
 * 9000 and up, so an unlocked plan has both actions in it. */
#define LINK  "\"links\":[" PLANFIX_LINK("eth0", "") "]"
/* **The MTU is a device's, not an interface's**, which the model decides and
 * the first version of this fixture got wrong: `an interface carries mtu,
 * which this build does not know`. The interface exists so the link is
 * planned at all. */
#define MTU_DEVICE "{\"name\":\"eth0\",\"managed\":true,\"mtu\":9000}"
/* An address as well, so that "the lock stopped one value and not another on
 * the same interface" has something to be true about. `link.up` was the first
 * choice and is not planned for this fixture with or without a lock, so it
 * proved nothing in either direction. */
#define PLAIN_IFACE                                                                  \
	"{\"name\":\"eth0\",\"addressing\":[{\"source\":\"static\","            \
	"\"address\":\"192.0.2.5/24\"}]}"

int main(void)
{
	ncfg_document_t      *document = NULL;
	ncfg_observed_t      *observed = NULL;
	ncfg_plan_t          *plan;
	const ncfg_refusal_t *refusal;

	/* The control first, so the refusal below has something to be measured
	 * against: without a lock, both actions are planned. */
	plan = plan_of("", MTU_DEVICE, PLAIN_IFACE, LINK, &document, &observed);
	check(plan && planned(plan, "link.set_mtu"),
	    "with no lock, an MTU the document asks for is planned");
	check(plan && planned(plan, "addr.add"), "  and so is the address beside it");
	ncfg_plan_free(plan);
	ncfg_observed_free(observed);
	ncfg_document_free(document);

	/* The same document, with the MTU locked. */
	plan = plan_of("\"locked\":[\"mtu:eth0\"]", MTU_DEVICE, PLAIN_IFACE, LINK, &document, &observed);
	check(plan && !planned(plan, "link.set_mtu"),
	    "a locked MTU is not planned, which is the refusal happening at plan time");
	refusal = refusal_of(plan, "link.set_mtu");
	check(refusal != NULL, "  and the refusal is first-class, so a client can read it");
	check(refusal && refusal->guard && strstr(refusal->guard, "`mtu:eth0` is locked") != NULL,
	    "  naming the subject that is locked rather than saying only `refused`");
	check(refusal && refusal->override_with &&
	    strstr(refusal->override_with, "remove `mtu:eth0`") != NULL &&
	    strstr(refusal->override_with, "locked") != NULL,
	    "  and naming the edit that lifts it");
	check(refusal && refusal->override_with &&
	    strstr(refusal->override_with, "--allow-disruption") == NULL,
	    "  never a per-apply flag, because a lock has no waiver (0290)");
	if (refusal) {
		printf("       locked:  %s\n", refusal->guard ? refusal->guard : "(none)");
		printf("       lift it: %s\n", refusal->override_with ? refusal->override_with : "");
	}

	/* The difference from a guard, in one assertion. */
	check(plan && planned(plan, "addr.add"),
	    "  while the address on the same interface is still planned, which is what "
	    "per-value means");
	ncfg_plan_free(plan);
	ncfg_observed_free(observed);
	ncfg_document_free(document);

	/* One address locked, another not. */
	plan = plan_of("\"locked\":[\"addr:eth0/192.0.2.5/24\"]", "",
	    "{\"name\":\"eth0\",\"addressing\":[{\"source\":\"static\","
	    "\"address\":\"192.0.2.5/24\"},{\"source\":\"static\","
	    "\"address\":\"192.0.2.6/24\"}]}",
	    LINK, &document, &observed);
	refusal = refusal_of(plan, "addr.add");
	check(refusal != NULL && refusal->guard &&
	    strstr(refusal->guard, "addr:eth0/192.0.2.5/24") != NULL,
	    "a locked address is refused by the address, not by the interface");
	check(plan && planned(plan, "addr.add"),
	    "  and the other address on the same interface is still planned");
	ncfg_plan_free(plan);
	ncfg_observed_free(observed);
	ncfg_document_free(document);

	if (failures > 0) {
		printf("plan_lock: %d check(s) failed\n", failures);
		return 1;
	}
	printf("plan_lock: every check passed\n");
	return 0;
}
