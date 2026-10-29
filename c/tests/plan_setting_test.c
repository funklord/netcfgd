/*
 * plan_setting_test.c -- the `nat` setting and the `ipv6_token`.
 *
 * WHY THE TWO ARE ONE FILE
 *   They are the two per-interface settings that are neither an address nor an
 *   attribute of the link the kernel reports back in a dump, and each is one
 *   pass with no teardown half. What they share is the reason there is no
 *   teardown: netcfgd cannot tell a token it set from one an operator set by
 *   hand, and the NAT table is replaced whole rather than diffed, so an empty
 *   list *is* the removal. Both of those are cases here.
 *
 * THE PROPERTY BOTH PASSES HAVE TO KEEP
 *   **Applying a plan twice produces an empty second plan.** For the token
 *   that means comparing `::5` against the `0:0:0:0:0:0:0:5` the kernel may
 *   report as the same token rather than as two, which is 10.200's shape
 *   applied to something that is not an address the document installs. For NAT
 *   it means comparing two lists in one order, which is why the wanted list is
 *   sorted before it is compared and before it is sent.
 *
 *   Two JSON documents and nothing else: planning is pure, so nothing here
 *   opens a socket, reads a file or touches the machine's own network.
 */
#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/document.h"
#include "ncfg/nft.h"
#include "ncfg/observed.h"
#include "ncfg/plan.h"
#include "ncfg/sha256.h"

#include "planfix.h"

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

#define DEVICE(name) "{\"name\":\"" name "\",\"kind\":{\"kind\":\"physical\"}}"

static ncfg_plan_t *plan_of(const char *devices, const char *interfaces, const char *observation,
    ncfg_document_t **document_out, ncfg_observed_t **observed_out)
{
	return planfix_plan(devices, interfaces, "", "", observation, document_out, observed_out);
}

/* The plan as the control socket sends it, so a case can assert a field a
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

/* The same question asked the other way, and quiet about the answer it wants,
 * so a passing negative does not print a line saying the plan is right. */
static int lacks(const ncfg_plan_t *plan, const char *fragment)
{
	char *text = written(plan);
	int   absent;

	if (!text) {
		return 0;
	}
	absent = strstr(text, fragment) == NULL;
	if (!absent) {
		printf("  the plan carries `%s`, and should not\n", fragment);
	}
	free(text);
	return absent;
}

/* ------------------------------------------------------------------------ *
 * `nat`
 * ------------------------------------------------------------------------ */

/*
 * The whole diff, which is two sorted lists of names.
 *
 * Decision 0022 gives netcfgd one table and one thing to say with it, so there
 * is no per-rule reconciliation because there is no per-rule change. Sorted
 * because the comparison is against a list the observer produced, and a
 * comparison that depended on the order the operator wrote the blocks in would
 * replace the table on a document nobody edited.
 */
static void the_uplinks_are_a_sorted_list_replaced_whole(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = plan_of(DEVICE("wan1") "," DEVICE("wan0"),
	    "{\"name\":\"wan1\",\"addressing\":[],\"nat\":true},"
	    "{\"name\":\"wan0\",\"addressing\":[],\"nat\":true,\"forwarding\":true}",
	    "\"links\":[" PLANFIX_LINK("wan0", "") "," PLANFIX_LINK("wan1", "") "]",
	    &document, &observed);

	check(plan && planfix_count(plan, "nftables.replace") == 1u,
	    "two interfaces asking for NAT are one action, not two");
	check(plan && wrote(plan, "\"uplinks\":[\"wan0\",\"wan1\"]"),
	    "and the uplinks are sorted, whatever order the document put them in");
	check(plan && planfix_for_field(plan, "nftables.replace", "nat") != NULL,
	    "and the reason names the setting rather than an interface");
	check(plan && planfix_action(plan, "nftables.replace") &&
	    planfix_action(plan, "nftables.replace")->has_inverse,
	    "and it carries the table as it stands, which is a real way back");
	check(plan && !planfix_warned(plan, "does not act on it"),
	    "and nothing warns that this build is holding the setting and not acting on it");
	planfix_release(plan, document, observed);

	plan = plan_of(DEVICE("wan0") "," DEVICE("wan1"),
	    "{\"name\":\"wan0\",\"addressing\":[],\"nat\":true,\"forwarding\":true},"
	    "{\"name\":\"wan1\",\"addressing\":[],\"nat\":true}",
	    /* The link forwards already, so the sysctl pass has nothing to say
	     * either: an "empty" that one other pass was filling would prove
	     * nothing about this one. */
	    "\"links\":[" PLANFIX_LINK("wan0", ",\"forwarding\":true") ","
	    PLANFIX_LINK("wan1", "") "],\"nat\":[\"wan0\",\"wan1\"]",
	    &document, &observed);
	check(plan && ncfg_plan_is_empty(plan),
	    "and a table already holding exactly those plans nothing on the second run");
	planfix_release(plan, document, observed);
}

/*
 * The firewall rides the same op (10.592): the table is netcfgd's and is
 * replaced whole, so it is planned wherever NAT or the firewall differs, and a
 * machine already holding both plans nothing.
 */
#define FIREWALL_DOCUMENT \
	",\"firewall\":{\"input\":{\"policy\":\"drop\",\"rules\":[{\"name\":\"ssh\"," \
	"\"action\":\"accept\",\"protocol\":\"tcp\",\"ports\":[22]}]}," \
	"\"forward\":{\"policy\":\"drop\"},\"output\":{\"policy\":\"accept\"}}"

/* The installed `ssh` rule as the observer would report it, with the digest
 * the writer gives it -- computed rather than pasted, so this case does not go
 * stale when the digest's text does. `port` and `unread` vary per case. */
static void observed_firewall(char *out, size_t out_size, long port, const char *unread)
{
	int64_t              ports[1] = { 22 };
	ncfg_firewall_rule_t rule;
	ncfg_buf_t           text;
	char                 digest[NCFG_SHA256_HEX_SIZE];

	memset(&rule, 0, sizeof(rule));
	rule.name = (char *)"ssh";
	rule.action = NCFG_FIREWALL_ACCEPT;
	rule.protocol = NCFG_FIREWALL_PROTO_TCP;
	rule.ports = ports;
	rule.port_count = 1u;
	ncfg_buf_init(&text, 0);
	(void)ncfg_nft_firewall_rule_text("input", &rule, &text);
	ncfg_sha256_hex(text.data, text.length, digest);
	ncfg_buf_free(&text);
	(void)snprintf(out, out_size,
	    "\"links\":[],\"firewall\":{\"input\":\"drop\",\"forward\":\"drop\",\"output\":\"accept\","
	    "\"rules\":[{\"chain\":\"input\",\"name\":\"ssh\",\"digest\":\"%.16s\",\"action\":\"accept\","
	    "\"protocol\":\"tcp\",\"port\":%ld}]%s%s%s}",
	    digest, port, unread ? ",\"unread\":[\"" : "", unread ? unread : "", unread ? "\"]" : "");
}

static void the_firewall_is_planned_with_the_table(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	char             seen[1024];
	ncfg_plan_t     *plan = planfix_plan("", "", "", FIREWALL_DOCUMENT, "\"links\":[]", &document,
	    &observed);

	check(plan && planfix_count(plan, "nftables.replace") == 1u,
	    "a firewall the machine does not hold is one table replacement");
	check(plan && planfix_for_field(plan, "nftables.replace", "firewall") != NULL,
	    "  whose reason names the firewall");
	check(plan && wrote(plan, "\"firewall\":{\"input\":{\"policy\":\"drop\",\"rules\":[{\"name\":\"ssh\""),
	    "  and the plan carries each rule by its identity");
	planfix_release(plan, document, observed);

	/* 10.546: a firewall change with no confirm window says so, and one with a
	 * window, from the document's `confirm`, does not. */
	plan = planfix_plan("", "", "", FIREWALL_DOCUMENT, "\"links\":[]", &document, &observed);
	check(plan && planfix_warned(plan, "no confirm window armed"),
	    "a firewall change with no confirm window warns that it could cut this connection");
	planfix_release(plan, document, observed);
	{
		ncfg_document_t *armed = planfix_document("", "", "", FIREWALL_DOCUMENT);

		if (armed) {
			armed->globals.confirm_default.has = 1;
			armed->globals.confirm_default.value = 60;
			observed = planfix_observed("\"links\":[]");
			plan = observed ? ncfg_plan_build(armed, observed, NULL, NULL, 0) : NULL;
			check(plan && !planfix_warned(plan, "no confirm window armed"),
			    "  and one under the document's confirm window does not");
			planfix_release(plan, armed, observed);
		}
	}

	observed_firewall(seen, sizeof(seen), 22, NULL);
	plan = planfix_plan("", "", "", FIREWALL_DOCUMENT, seen, &document, &observed);
	check(plan && planfix_count(plan, "nftables.replace") == 0u,
	    "a machine already holding exactly that firewall plans nothing");
	planfix_release(plan, document, observed);

	observed_firewall(seen, sizeof(seen), 22, "a rule in chain `input` with no comment");
	plan = planfix_plan("", "", "", FIREWALL_DOCUMENT, seen, &document, &observed);
	check(plan && planfix_count(plan, "nftables.replace") == 1u,
	    "a rule netcfgd could not read in its table is replaced");
	planfix_release(plan, document, observed);

	/* The comment kept, the port changed: what the field-by-field comparison
	 * is for, since the identity alone would call this converged. */
	observed_firewall(seen, sizeof(seen), 2222, NULL);
	plan = planfix_plan("", "", "", FIREWALL_DOCUMENT, seen, &document, &observed);
	check(plan && planfix_count(plan, "nftables.replace") == 1u,
	    "a hand edit that kept the rule's comment is still a difference");
	planfix_release(plan, document, observed);

	observed_firewall(seen, sizeof(seen), 22, NULL);
	plan = planfix_plan("", "", "", "", seen, &document, &observed);
	check(plan && planfix_count(plan, "nftables.replace") == 1u &&
	    wrote(plan, "\"desired\":\"<none>\""),
	    "a document with no firewall plans the installed one away");
	check(plan && planfix_action(plan, "nftables.replace") &&
	    planfix_action(plan, "nftables.replace")->has_inverse &&
	    planfix_action(plan, "nftables.replace")->inverse.u.nftables.firewall &&
	    planfix_action(plan, "nftables.replace")->inverse.u.nftables.firewall->input.rule_count == 1u,
	    "  with an inverse that puts the installed firewall back, not an empty table");
	planfix_release(plan, document, observed);
}

/*
 * Taking `nat` out of the document is a `nftables.replace` with nothing in it.
 *
 * The removal has to be an action rather than an absence, because the table is
 * netcfgd's and nothing else will take it away -- a document that stopped
 * asking and planned nothing would leave a router translating for ever.
 */
static void a_document_that_stops_asking_removes_the_table(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = plan_of(DEVICE("wan0"),
	    "{\"name\":\"wan0\",\"addressing\":[]}",
	    "\"links\":[" PLANFIX_LINK("wan0", "") "],\"nat\":[\"wan0\"]",
	    &document, &observed);

	check(plan && planfix_count(plan, "nftables.replace") == 1u,
	    "a document that no longer asks for NAT plans the table away");
	check(plan && wrote(plan, "\"observed\":\"wan0\"") && wrote(plan, "\"desired\":\"<none>\""),
	    "and the reason says what the table held and that nothing is wanted now");
	planfix_release(plan, document, observed);

	plan = plan_of(DEVICE("wan0"), "{\"name\":\"wan0\",\"addressing\":[]}",
	    "\"links\":[" PLANFIX_LINK("wan0", "") "]", &document, &observed);
	check(plan && planfix_count(plan, "nftables.replace") == 0u,
	    "and a machine with no table and a document that wants none plans nothing");
	planfix_release(plan, document, observed);
}

/*
 * Two warnings, neither of them a refusal.
 *
 * A second source-NAT chain translates the same packets twice, which breaks
 * return paths in ways that look like packet loss -- and netcfgd will not
 * delete somebody else's table, because it cannot evaluate the filtering in
 * there. The operator is told and the operator decides.
 *
 * **Told whenever netcfgd has an opinion, including when the opinion is
 * "none"**: an operator who has just removed `nat` is exactly the person who
 * needs to know something else is still translating.
 */
static void a_second_table_translating_is_reported_and_not_deleted(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = plan_of(DEVICE("wan0"),
	    "{\"name\":\"wan0\",\"addressing\":[],\"nat\":true,\"forwarding\":true}",
	    "\"links\":[" PLANFIX_LINK("wan0", "") "],\"nat_conflicts\":[\"fw\",\"docker\"]",
	    &document, &observed);

	check(plan && planfix_warned(plan, "`fw`, `docker`"),
	    "the tables that also translate are named, all of them");
	check(plan && planfix_warned(plan, "netcfgd will not delete another table"),
	    "and the warning says netcfgd will not remove one, and what to do instead");
	planfix_release(plan, document, observed);

	plan = plan_of(DEVICE("wan0"), "{\"name\":\"wan0\",\"addressing\":[]}",
	    "\"links\":[" PLANFIX_LINK("wan0", "") "],\"nat\":[\"wan0\"],"
	    "\"nat_conflicts\":[\"fw\"]",
	    &document, &observed);
	check(plan && planfix_warned(plan, "`fw`"),
	    "an operator who has just removed `nat` is told what is still translating");
	planfix_release(plan, document, observed);

	plan = plan_of(DEVICE("wan0"), "{\"name\":\"wan0\",\"addressing\":[]}",
	    "\"links\":[" PLANFIX_LINK("wan0", "") "],\"nat_conflicts\":[\"fw\"]",
	    &document, &observed);
	check(plan && !planfix_warned(plan, "`fw`"),
	    "and a machine netcfgd has no opinion about is not lectured about somebody "
	    "else's table");
	planfix_release(plan, document, observed);
}

/*
 * NAT with nothing forwarded translates packets the kernel already dropped.
 *
 * The two are set independently, on different interfaces, and this is the
 * mistake that produces a router which quietly does nothing -- so the warning
 * says which side the missing setting goes on.
 */
static void nat_with_nothing_forwarded_is_a_router_that_does_nothing(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = plan_of(DEVICE("wan0"),
	    "{\"name\":\"wan0\",\"addressing\":[],\"nat\":true}",
	    "\"links\":[" PLANFIX_LINK("wan0", "") "]", &document, &observed);

	check(plan && planfix_warned(plan, "the LAN side, not the uplink"),
	    "`nat` with no interface forwarding is named, and so is where to set it");
	planfix_release(plan, document, observed);

	plan = plan_of(DEVICE("wan0") "," DEVICE("lan0"),
	    "{\"name\":\"wan0\",\"addressing\":[],\"nat\":true},"
	    "{\"name\":\"lan0\",\"addressing\":[],\"forwarding\":true}",
	    "\"links\":[" PLANFIX_LINK("wan0", "") "," PLANFIX_LINK("lan0", "") "]",
	    &document, &observed);
	check(plan && !planfix_warned(plan, "the LAN side, not the uplink"),
	    "and a router that does forward somewhere is not told it does not");
	planfix_release(plan, document, observed);
}

/* ------------------------------------------------------------------------ *
 * `ipv6_token`
 * ------------------------------------------------------------------------ */

static void a_token_is_set_where_the_document_names_one(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = plan_of(DEVICE("eth0"),
	    "{\"name\":\"eth0\",\"addressing\":[],\"ipv6_token\":\"::5\"}",
	    "\"links\":[" PLANFIX_LINK("eth0", "") "]", &document, &observed);

	check(plan && planfix_count(plan, "link.set_ipv6_token") == 1u,
	    "an interface naming a token gets one, the prefix still coming from the router");
	check(plan && wrote(plan, "\"token\":\"::5\"") && wrote(plan, "\"observed\":\"<absent>\""),
	    "and the reason says there was none before, which is not the same as a different one");
	check(plan && planfix_action(plan, "link.set_ipv6_token") &&
	    planfix_action(plan, "link.set_ipv6_token")->has_inverse,
	    "and the way back exists");
	check(plan && !planfix_warned(plan, "does not act on it"),
	    "and nothing warns that this build is holding the token and not acting on it");
	planfix_release(plan, document, observed);

	/* A token already there and a different one are different sentences, and
	 * the inverse of the second is the real previous value rather than a
	 * guess. */
	plan = plan_of(DEVICE("eth0"),
	    "{\"name\":\"eth0\",\"addressing\":[],\"ipv6_token\":\"::5\"}",
	    "\"links\":[" PLANFIX_LINK("eth0", ",\"ipv6_token\":\"::9\"") "]",
	    &document, &observed);
	check(plan && planfix_count(plan, "link.set_ipv6_token") == 1u &&
	    wrote(plan, "\"observed\":\"::9\""),
	    "a token that is the wrong one is replaced, and the reason names what was there");
	planfix_release(plan, document, observed);
}

/*
 * 10.200's shape, applied to a value that is not an address the document
 * installs.
 *
 * `::5` and `0:0:0:0:0:0:0:5` are one token, and the kernel reports its own
 * spelling of whatever was set. Compared as text this writes the token on
 * every reconcile for ever, against a kernel that already holds it -- and
 * every one of those writes succeeds, so nothing anywhere says so.
 */
static void a_token_spelled_two_ways_is_one_token(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = plan_of(DEVICE("eth0"),
	    "{\"name\":\"eth0\",\"addressing\":[],\"ipv6_token\":\"::5\"}",
	    "\"links\":[" PLANFIX_LINK("eth0", ",\"ipv6_token\":\"0:0:0:0:0:0:0:5\"") "]",
	    &document, &observed);

	check(plan && planfix_count(plan, "link.set_ipv6_token") == 0u,
	    "a kernel reporting the long form of the token asked for plans nothing");
	check(plan && ncfg_plan_is_empty(plan),
	    "  so the second plan is empty, which is the property this is really about");
	planfix_release(plan, document, observed);
}

/*
 * A token nobody asked for is not removed, and that is a decision.
 *
 * Unlike an address it carries no ownership tag, and the kernel offers no way
 * to tell one netcfgd set from one an operator set by hand -- so clearing it
 * would be undoing somebody else's choice on the first run.
 */
static void a_token_the_document_does_not_mention_is_left_alone(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = plan_of(DEVICE("eth0"), "{\"name\":\"eth0\",\"addressing\":[]}",
	    "\"links\":[" PLANFIX_LINK("eth0", ",\"ipv6_token\":\"::9\"") "]",
	    &document, &observed);

	check(plan && planfix_count(plan, "link.set_ipv6_token") == 0u,
	    "a token the document says nothing about is not netcfgd's to clear");
	check(plan && lacks(plan, "link.set_ipv6_token"),
	    "  and there is no action of that kind in the plan at all");
	planfix_release(plan, document, observed);
}

/*
 * The token waits for the link it is set on, like every other link attribute.
 *
 * A device this plan is creating has nothing to set a token on until the
 * `link.create` has run, and a plan that said otherwise would be an action
 * that fails on the first apply and succeeds on the second.
 */
static void a_token_on_a_new_link_waits_for_the_link(void)
{
	ncfg_document_t     *document;
	ncfg_observed_t     *observed;
	ncfg_plan_t         *plan = plan_of(
	    "{\"name\":\"veth0\",\"kind\":{\"kind\":\"veth\",\"peer\":\"veth1\"}}",
	    "{\"name\":\"veth0\",\"addressing\":[],\"ipv6_token\":\"::5\"}",
	    "\"links\":[]", &document, &observed);
	const ncfg_action_t *create = plan ? planfix_action(plan, "link.create") : NULL;
	const ncfg_action_t *token = plan ? planfix_action(plan, "link.set_ipv6_token") : NULL;

	check(create && token, "a device being created still gets the token the document names");
	check(create && token && planfix_depends_on(token, create->id),
	    "and the token waits for the creation rather than racing it");
	planfix_release(plan, document, observed);
}

int main(void)
{
	the_uplinks_are_a_sorted_list_replaced_whole();
	the_firewall_is_planned_with_the_table();
	a_document_that_stops_asking_removes_the_table();
	a_second_table_translating_is_reported_and_not_deleted();
	nat_with_nothing_forwarded_is_a_router_that_does_nothing();

	a_token_is_set_where_the_document_names_one();
	a_token_spelled_two_ways_is_one_token();
	a_token_the_document_does_not_mention_is_left_alone();
	a_token_on_a_new_link_waits_for_the_link();

	printf("\nplan settings: %d checks, %d failed\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
