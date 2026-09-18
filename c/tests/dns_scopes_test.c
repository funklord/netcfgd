/*
 * dns_scopes_test.c -- the rule that says which scopes a machine has.
 *
 * WHY THIS IS ITS OWN FILE AND NOT MORE CASES IN `plan_addressing_test.c`
 *   The rule used to be a static inside the planner and the only way to see it
 *   was through a plan, so every check on it was really a check on a plan that
 *   had been built from it. It has two callers now -- the planner, and the
 *   daemon filling an executor's `dns_scopes` -- and the daemon's use has no
 *   plan in it at all: it asks for the list and hands it to a delivery. A rule
 *   with a caller that no existing test resembles needs checks at the rule.
 *
 *   The cases in `plan_addressing_test.c` stay exactly where they are. They are
 *   what proved the move behaviour-preserving -- three sabotages of this module
 *   were each caught there -- and they are about what a *plan* does, which is
 *   still the planner's question.
 *
 * THE ONE THAT IS THE WHOLE REASON THE DAEMON NEEDS THIS
 *   `a_plan_names_fewer_scopes_than_a_machine_has`. A plan carries a
 *   `dns.apply` per scope that *changed*, and a delivery writes the resolver
 *   file whole -- so an executor that built its list from the op it was handed
 *   would write a file holding one interface's servers and drop the rest. That
 *   is the Rust's recorded defect, and this is the check that says the two
 *   counts really do differ rather than being the same number twice.
 */
#include "ncfg/dns.h"

#include "ncfg/base.h"
#include "ncfg/plan.h"
#include "planfix.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;

static void check(int condition, const char *what)
{
	printf("%-72s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

/* ------------------------------------------------------------------------ *
 * Fixtures
 * ------------------------------------------------------------------------ */

/*
 * A document with a `globals` block of its own.
 *
 * `planfix_document` writes `"globals":{}`, which is right for every pass that
 * does not care and is exactly what this file does care about: the host's DNS
 * mode lives there, and half the rule is about what a scope inherits from it.
 */
static ncfg_document_t *document_of(const char *globals, const char *devices,
    const char *interfaces)
{
	char             text[8192];
	char             message[NCFG_ERROR_MAX];
	ncfg_document_t *document;

	(void)snprintf(text, sizeof(text),
	    "{\"schema_version\":{\"major\":1,\"minor\":1},\"generated_by\":\"dns_scopes_test\","
	    "\"globals\":%s,\"devices\":[%s],\"interfaces\":[%s],\"networks\":[]}",
	    globals, devices, interfaces);
	message[0] = '\0';
	document = ncfg_document_read(text, strlen(text), message, sizeof(message));
	if (!document) {
		printf("  fixture document did not read: %s\n", message);
	}
	return document;
}

#define RESOLV_GLOBALS \
	"{\"dns\":{\"mode\":\"write_resolv_conf\",\"servers\":[{\"addr\":\"9.9.9.9\"}]}}"
#define ETH0_DEVICE "{\"name\":\"eth0\",\"kind\":{\"kind\":\"physical\"}}"

/* The scope of that name, or NULL. */
static const ncfg_dns_scope_t *scope_named(const ncfg_dns_scope_t *scopes, size_t count,
    const char *name)
{
	size_t i;

	for (i = 0; i < count; i++) {
		if (scopes[i].name && strcmp(scopes[i].name, name) == 0) {
			return &scopes[i];
		}
	}
	return NULL;
}

/* ------------------------------------------------------------------------ *
 * What the rule answers
 * ------------------------------------------------------------------------ */

static void a_document_that_manages_no_dns_has_no_scopes(void)
{
	char                    message[NCFG_ERROR_MAX];
	ncfg_document_t        *document = document_of("{}", ETH0_DEVICE,
	    "{\"name\":\"eth0\",\"addressing\":[]}");
	ncfg_dns_scopes_t      *scopes;
	const ncfg_dns_scope_t *items;
	size_t                  count = 99u;

	message[0] = '\0';
	scopes = ncfg_dns_scopes_of(document, NULL, message, sizeof(message));
	check(scopes != NULL, "a document managing no DNS is an answer, not a failure");
	items = ncfg_dns_scopes_items(scopes, &count);
	check(count == 0u, "and the list is empty");
	/*
	 * The distinction `dns.h` promises, and it is not pedantry: a caller that
	 * read NULL as "could not be asked" would treat the default configuration
	 * -- which manages no DNS -- as a broken one, and on a daemon that is an
	 * executor refusing to open every five seconds.
	 */
	check(items != NULL, "and an empty list is still a pointer, not a refusal");
	ncfg_dns_scopes_free(scopes);
	ncfg_document_free(document);
}

static void no_document_is_refused_by_name(void)
{
	char message[NCFG_ERROR_MAX];

	message[0] = '\0';
	check(ncfg_dns_scopes_of(NULL, NULL, message, sizeof(message)) == NULL &&
	    strstr(message, "document") != NULL,
	    "no document at all is refused, and the sentence says what was missing");
}

static void a_machine_nobody_has_looked_at_still_has_the_documents_scopes(void)
{
	char                    message[NCFG_ERROR_MAX];
	ncfg_document_t        *document = document_of(RESOLV_GLOBALS, ETH0_DEVICE,
	    "{\"name\":\"eth0\",\"addressing\":[],"
	    "\"dns\":{\"mode\":\"write_resolv_conf\",\"servers\":[{\"addr\":\"10.0.0.53\"}]}}");
	ncfg_dns_scopes_t      *scopes;
	const ncfg_dns_scope_t *items;
	size_t                  count = 0;

	message[0] = '\0';
	/*
	 * NULL rather than an empty observation, because that is what a daemon has
	 * before its first round: `dns.h` says so, and the alternative -- treating
	 * it as a failure -- is a daemon that cannot deliver the operator's own
	 * nameservers until something has been leased.
	 */
	scopes = ncfg_dns_scopes_of(document, NULL, message, sizeof(message));
	items = ncfg_dns_scopes_items(scopes, &count);
	check(count == 2u, "a machine nothing has observed still has the document's two scopes");
	check(scope_named(items, count, "globals") != NULL &&
	    scope_named(items, count, "eth0") != NULL, "and they are the host's and eth0's");
	ncfg_dns_scopes_free(scopes);
	ncfg_document_free(document);
}

static void an_interface_that_asked_for_nothing_gets_no_lease(void)
{
	char                    message[NCFG_ERROR_MAX];
	ncfg_document_t        *document = document_of(RESOLV_GLOBALS, ETH0_DEVICE,
	    "{\"name\":\"eth0\",\"addressing\":[{\"source\":\"static\","
	    "\"address\":\"10.0.0.2/24\"}]}");
	ncfg_observed_t        *observed = planfix_observed(
	    "\"reports\":[{\"interface\":\"eth0\",\"addresses\":[],\"gateways\":[],"
	    "\"nameservers\":[\"10.0.0.53\"],\"search\":[\"lan.example\"],\"routes\":[]}]");
	ncfg_dns_scopes_t      *scopes;
	const ncfg_dns_scope_t *items;
	size_t                  count = 0;

	message[0] = '\0';
	scopes = ncfg_dns_scopes_of(document, observed, message, sizeof(message));
	items = ncfg_dns_scopes_items(scopes, &count);
	/*
	 * A static address and no `dns { }` block: the operator kept their own
	 * resolvers, and a lease does not get to redefine what a bare name means
	 * (0049). The same gate covers the suffixes, which is the point of it
	 * being one gate -- a suffix is only useful where that network's resolvers
	 * are already answering.
	 */
	check(scope_named(items, count, "eth0") == NULL,
	    "an interface that asked for nothing gets no scope from a lease");
	check(count == 1u && scope_named(items, count, "globals") != NULL,
	    "and the host's own scope is untouched by that");
	ncfg_dns_scopes_free(scopes);
	ncfg_observed_free(observed);
	ncfg_document_free(document);
}

static void an_unmanaged_device_contributes_nothing_to_the_daemon_either(void)
{
	char                    message[NCFG_ERROR_MAX];
	ncfg_document_t        *document = document_of(RESOLV_GLOBALS,
	    "{\"name\":\"eth0\",\"kind\":{\"kind\":\"physical\"},\"managed\":false}",
	    "{\"name\":\"eth0\",\"addressing\":[],"
	    "\"dns\":{\"mode\":\"write_resolv_conf\",\"servers\":[{\"addr\":\"10.0.0.53\"}]}}");
	ncfg_dns_scopes_t      *scopes;
	const ncfg_dns_scope_t *items;
	size_t                  count = 0;

	message[0] = '\0';
	scopes = ncfg_dns_scopes_of(document, NULL, message, sizeof(message));
	items = ncfg_dns_scopes_items(scopes, &count);
	/*
	 * Asked here rather than at the planner's choke point, because
	 * `dns.apply` names no interface and so never reaches it. The daemon asks
	 * the same function, so it cannot answer this differently -- which is the
	 * whole argument for one rule.
	 */
	check(scope_named(items, count, "eth0") == NULL,
	    "an unmanaged device contributes no scope, asked at the rule rather than a plan");
	ncfg_dns_scopes_free(scopes);
	ncfg_document_free(document);
}

static void the_documents_servers_come_before_the_networks(void)
{
	char                    message[NCFG_ERROR_MAX];
	ncfg_document_t        *document = document_of(RESOLV_GLOBALS, ETH0_DEVICE,
	    "{\"name\":\"eth0\",\"addressing\":[],"
	    "\"dns\":{\"mode\":\"write_resolv_conf\",\"servers\":[{\"addr\":\"10.0.0.53\"}]}}");
	ncfg_observed_t        *observed = planfix_observed(
	    "\"reports\":[{\"interface\":\"eth0\",\"addresses\":[],\"gateways\":[],"
	    "\"nameservers\":[\"192.168.1.1\"],\"search\":[],\"routes\":[]}]");
	ncfg_dns_scopes_t      *scopes;
	const ncfg_dns_scope_t *items;
	const ncfg_dns_scope_t *eth0;
	size_t                  count = 0;

	message[0] = '\0';
	scopes = ncfg_dns_scopes_of(document, observed, message, sizeof(message));
	items = ncfg_dns_scopes_items(scopes, &count);
	eth0 = scope_named(items, count, "eth0");
	check(eth0 && eth0->policy->server_count == 2u,
	    "an interface that asked gets its own servers and the lease's");
	check(eth0 && eth0->policy->server_count == 2u &&
	    strcmp(eth0->policy->servers[0].addr, "10.0.0.53") == 0 &&
	    strcmp(eth0->policy->servers[1].addr, "192.168.1.1") == 0,
	    "and the operator's comes first, so first-occurrence-wins picks theirs");
	ncfg_dns_scopes_free(scopes);
	ncfg_observed_free(observed);
	ncfg_document_free(document);
}

static void a_scope_borrows_where_it_did_not_have_to_merge(void)
{
	char                    message[NCFG_ERROR_MAX];
	/*
	 * Two interfaces and a lease on only one of them, because the borrowing
	 * branch is inside the per-interface merge and the `globals` scope never
	 * reaches it -- it is pushed straight from the document. A first draft of
	 * this case checked `globals` and passed a sabotage that removed the
	 * branch entirely: it was asserting something true for another reason.
	 */
	ncfg_document_t        *document = document_of(RESOLV_GLOBALS,
	    ETH0_DEVICE ",{\"name\":\"eth1\",\"kind\":{\"kind\":\"physical\"}}",
	    "{\"name\":\"eth0\",\"addressing\":[],"
	    "\"dns\":{\"mode\":\"write_resolv_conf\",\"servers\":[{\"addr\":\"10.0.0.53\"}]}},"
	    "{\"name\":\"eth1\",\"addressing\":[],"
	    "\"dns\":{\"mode\":\"write_resolv_conf\",\"servers\":[{\"addr\":\"10.0.1.53\"}]}}");
	ncfg_observed_t        *observed = planfix_observed(
	    "\"reports\":[{\"interface\":\"eth0\",\"addresses\":[],\"gateways\":[],"
	    "\"nameservers\":[\"192.168.1.1\"],\"search\":[],\"routes\":[]}]");
	ncfg_dns_scopes_t      *scopes;
	const ncfg_dns_scope_t *items;
	const ncfg_dns_scope_t *merged;
	const ncfg_dns_scope_t *borrowed;
	size_t                  count = 0;

	message[0] = '\0';
	scopes = ncfg_dns_scopes_of(document, observed, message, sizeof(message));
	items = ncfg_dns_scopes_items(scopes, &count);
	merged = scope_named(items, count, "eth0");
	borrowed = scope_named(items, count, "eth1");
	check(document && document->interface_count == 2u &&
	    strcmp(document->interfaces[1].name, "eth1") == 0,
	    "the fixture really has two interfaces, sorted, or the two checks below are one");
	/*
	 * `dns.h` says a scope borrows where it can and owns where it merged, and
	 * that sentence is what every caller's lifetime rule is built on. Checked
	 * by pointer rather than by value: the two are indistinguishable by
	 * content, and it is the ownership a caller has to get right.
	 */
	check(borrowed && borrowed->policy == document->interfaces[1].dns,
	    "an interface with nothing to merge points straight into the document");
	check(merged && merged->policy != document->interfaces[0].dns,
	    "and one that absorbed a lease does not, or the document would be rewritten");
	check(merged && merged->policy->server_count == 2u,
	    "and it is the merge that made the copy necessary, not a copy on principle");
	check(scope_named(items, count, "globals") != NULL &&
	    scope_named(items, count, "globals")->policy == &document->globals.dns,
	    "and the host's scope is the document's own block, never a copy of it");
	ncfg_dns_scopes_free(scopes);
	ncfg_observed_free(observed);
	ncfg_document_free(document);
}

/* ------------------------------------------------------------------------ *
 * Why the daemon cannot use the op it was handed
 * ------------------------------------------------------------------------ */

static void a_plan_names_fewer_scopes_than_a_machine_has(void)
{
	char                    message[NCFG_ERROR_MAX];
	ncfg_document_t        *document = document_of(RESOLV_GLOBALS, ETH0_DEVICE,
	    "{\"name\":\"eth0\",\"addressing\":[],"
	    "\"dns\":{\"mode\":\"write_resolv_conf\",\"servers\":[{\"addr\":\"10.0.0.53\"}]}}");
	/* The host's scope is already delivered and eth0's is not, so exactly one
	 * of the two differs. A converged half and a drifted half is the ordinary
	 * shape of a machine, not a contrived one. */
	ncfg_observed_t        *observed = planfix_observed(
	    "\"dns\":[{\"scope\":\"globals\",\"policy\":{\"mode\":\"write_resolv_conf\","
	    "\"servers\":[{\"addr\":\"9.9.9.9\"}]}}]");
	ncfg_plan_t            *plan;
	ncfg_dns_scopes_t      *scopes;
	size_t                  count = 0;

	message[0] = '\0';
	plan = ncfg_plan_build(document, observed, NULL, message, sizeof(message));
	scopes = ncfg_dns_scopes_of(document, observed, message, sizeof(message));
	(void)ncfg_dns_scopes_items(scopes, &count);
	check(plan && planfix_count(plan, "dns.apply") == 1u,
	    "a plan carries a dns.apply for the one scope that drifted");
	check(count == 2u,
	    "and the machine has two, so an executor reading the op alone drops one");
	ncfg_dns_scopes_free(scopes);
	ncfg_plan_free(plan);
	ncfg_observed_free(observed);
	ncfg_document_free(document);
}

/* ------------------------------------------------------------------------ *
 * What the plan does with the list
 * ------------------------------------------------------------------------ */

static int releases;

static void count_release(void *owned)
{
	free(owned);
	releases++;
}

static void an_adopted_aggregate_is_released_once(void)
{
	char         message[NCFG_ERROR_MAX];
	ncfg_plan_t *plan;
	void        *block = malloc(8u);

	message[0] = '\0';
	plan = ncfg_plan_new(message, sizeof(message));
	releases = 0;
	check(plan && block && ncfg_plan_adopt(plan, block, count_release),
	    "a plan adopts something with a free of its own");
	check(releases == 0, "and does not release it while the plan is alive");
	ncfg_plan_free(plan);
	/*
	 * Once, not twice and not never. The arena frees with `free` and this does
	 * not go in it -- an aggregate holding its own arena would have everything
	 * inside stranded by a flat free -- so "exactly once, through its own
	 * release" is the property the whole mechanism exists for.
	 */
	check(releases == 1, "and releases it exactly once when the plan is freed");
}

static void adopting_without_a_release_refuses_rather_than_leaking_quietly(void)
{
	char         message[NCFG_ERROR_MAX];
	ncfg_plan_t *plan;
	int          value = 0;

	message[0] = '\0';
	plan = ncfg_plan_new(message, sizeof(message));
	check(plan && !ncfg_plan_adopt(plan, &value, NULL),
	    "adopting with no release is refused");
	/*
	 * And the refusal is sticky, because the caller has already stopped
	 * thinking about that pointer. A plan that carried on would be built from
	 * a rule whose result was dropped -- which for the DNS scopes is a plan
	 * with no delivery in it and nothing saying why.
	 */
	check(plan && ncfg_plan_failed(plan), "and the plan's sticky failure is set");
	ncfg_plan_free(plan);
}

int main(void)
{
	a_document_that_manages_no_dns_has_no_scopes();
	no_document_is_refused_by_name();
	a_machine_nobody_has_looked_at_still_has_the_documents_scopes();
	an_interface_that_asked_for_nothing_gets_no_lease();
	an_unmanaged_device_contributes_nothing_to_the_daemon_either();
	the_documents_servers_come_before_the_networks();
	a_scope_borrows_where_it_did_not_have_to_merge();

	a_plan_names_fewer_scopes_than_a_machine_has();

	an_adopted_aggregate_is_released_once();
	adopting_without_a_release_refuses_rather_than_leaking_quietly();

	if (failures > 0) {
		printf("dns_scopes: %d check(s) failed\n", failures);
		return 1;
	}
	printf("dns_scopes: every check passed\n");
	return 0;
}
