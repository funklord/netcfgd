/*
 * plan_reported_test.c -- the addresses and routes a report carries.
 *
 * WHAT IS UNDER TEST
 *   The one addressing source whose value netcfgd neither chose nor asked a
 *   kernel for: a cellular bearer or a tunnel daemon writes what it negotiated
 *   into `/run/netcfgd/reported/<interface>`, and decision 0047 makes those
 *   addresses and routes netcfgd's to install. Both directions -- the pass
 *   that installs them and the teardown that withdraws them when the bearer
 *   drops -- and the gate that decides whether a file in `/run` is believed at
 *   all.
 *
 * THE PROPERTY EVERY CASE HERE IS REALLY ABOUT
 *   **Applying a plan twice produces an empty second plan**, which `plan.h`
 *   calls load-bearing, and which this source is the hardest place in the
 *   planner to keep. Every other address netcfgd installs went through the
 *   compiler's `canonical_address` on the way in, so it already reads the way
 *   the kernel prints it. A report went through nothing: it is the text
 *   somebody's shell script produced.
 *
 *   project.md 10.169 is what that costs when the comparison is `strcmp`,
 *   measured against the shipped Rust -- `0000:0000:...:0001/128` and
 *   `::1/128` read as two addresses, so an `addr.add` is planned for one the
 *   kernel is already holding, and where netcfgd owns it the teardown plans an
 *   `addr.del` beside the add. Forever, and silently, because both halves
 *   succeed. So the two spellings are a case here in each direction, for the
 *   address, for a route's next hop and for a route's destination.
 *
 * WHY THE FIXTURES CAN SAY IT AT ALL
 *   Because neither reader canonicalises. `ncfg_observed_read` keeps a
 *   report's addresses and an observed address as the text it was given --
 *   both are plain string fields -- so a fixture can hold one address in two
 *   spellings and the plan has to be the thing that reconciles them. (An
 *   observed *route's* `via` and `src` do go through the address custom, which
 *   is why the next-hop case puts the long spelling in the report rather than
 *   in the observation.)
 *
 *   Everything here is two JSON documents and nothing else. Planning is pure:
 *   no socket, no file, no kernel, and nothing that could touch the network of
 *   the machine this is built on.
 */
#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/document.h"
#include "ncfg/observed.h"
#include "ncfg/plan.h"

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

/* A modem's interface: a real device, addressed by whatever reports it. */
#define WWAN_DEVICE   "{\"name\":\"wwan0\",\"kind\":{\"kind\":\"physical\"}}"
#define WWAN_REPORTED "{\"name\":\"wwan0\",\"addressing\":[{\"source\":\"reported\"}]}"
/* The same device asking for something else, which is the negative case: a
 * report for an interface that did not claim one is an observation netcfgd has
 * no instruction for. */
#define WWAN_SLAAC    "{\"name\":\"wwan0\",\"addressing\":[{\"source\":\"slaac\"}]}"

/*
 * A tunnel netcfgd started itself, which claims its own report without the
 * document having to say `reported` (decision 0047).
 *
 * `open_vpn` and not `openvpn`: that is the *document's* spelling, where the
 * configuration language's is the other one. 0263 records this pair and
 * `wire_guard` as two keys this project has already shipped spelled the wrong
 * way round, each compiling into a block with the feature silently missing.
 */
#define TUN_DEVICE \
	"{\"name\":\"tun0\",\"kind\":{\"kind\":\"open_vpn\",\"config\":\"/etc/openvpn/w.conf\"}}"
#define TUN_INTERFACE "{\"name\":\"tun0\",\"addressing\":[]}"

/* `"reports":[...]` for one interface. `extra` is whatever a case adds, comma
 * included: `gateways`, `routes`. `nameservers` is required by the reader and
 * empty everywhere here, 0049 keeping a report away from the resolver. */
#define REPORT(iface, addresses, extra) \
	"\"reports\":[{\"interface\":\"" iface "\",\"addresses\":[" addresses "]," \
	"\"nameservers\":[],\"gateways\":[]" extra "}]"
#define REPORT_GW(iface, addresses, gateways) \
	"\"reports\":[{\"interface\":\"" iface "\",\"addresses\":[" addresses "]," \
	"\"nameservers\":[],\"gateways\":[" gateways "]}]"

/* An address netcfgd installed and may therefore remove. */
#define OURS(iface, address) \
	"{\"interface\":\"" iface "\",\"address\":\"" address "\",\"ownership\":\"ours\"," \
	"\"origin\":\"static\"}"
/* And a route, which the teardown reads the same two fields of. */
#define OURS_ROUTE(iface, destination, via) \
	"{\"interface\":\"" iface "\",\"destination\":\"" destination "\",\"via\":\"" via "\"," \
	"\"ownership\":\"ours\",\"origin\":\"static\"}"

static ncfg_plan_t *plan_of(const char *devices, const char *interfaces, const char *observation,
    ncfg_document_t **document_out, ncfg_observed_t **observed_out)
{
	return planfix_plan(devices, interfaces, "", "", observation, document_out, observed_out);
}

/* The plan as the control socket sends it, so a case can assert a field a
 * struct walk would have to reach three unions deep for. */
static int wrote(const ncfg_plan_t *plan, const char *fragment)
{
	ncfg_buf_t buf;
	char       message[NCFG_ERROR_MAX];
	char      *text;
	int        found;

	ncfg_buf_init(&buf, 0);
	if (!ncfg_plan_write(plan, &buf, message, sizeof(message))) {
		printf("  could not write the plan: %s\n", message);
		ncfg_buf_free(&buf);
		return 0;
	}
	text = ncfg_buf_take(&buf, NULL);
	ncfg_buf_free(&buf);
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

/*
 * The same question asked the other way, and quiet about it.
 *
 * `wrote` prints what it did not find, which is what makes a failed positive
 * readable -- and which would make every negative case here print a line
 * saying the plan is right. So the negative has its own name.
 */
static int lacks(const ncfg_plan_t *plan, const char *fragment)
{
	ncfg_buf_t buf;
	char       message[NCFG_ERROR_MAX];
	char      *text;
	int        absent;

	ncfg_buf_init(&buf, 0);
	if (!ncfg_plan_write(plan, &buf, message, sizeof(message))) {
		printf("  could not write the plan: %s\n", message);
		ncfg_buf_free(&buf);
		return 0;
	}
	text = ncfg_buf_take(&buf, NULL);
	ncfg_buf_free(&buf);
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
 * The addresses
 * ------------------------------------------------------------------------ */

static void a_report_is_where_the_addresses_come_from(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = plan_of(WWAN_DEVICE, WWAN_REPORTED,
	    "\"links\":[" PLANFIX_LINK("wwan0", "") "]," REPORT("wwan0", "\"10.64.0.5/32\"", ""),
	    &document, &observed);

	check(plan && planfix_count(plan, "addr.add") == 1u,
	    "the address a report names is netcfgd's to install");
	check(plan && planfix_for_field(plan, "addr.add", "addressing[0]") != NULL,
	    "and the reason names the line of the document that claimed the report");
	check(plan && wrote(plan, "10.64.0.5/32 (reported)"),
	    "and says the value came from a report rather than from the file");
	check(plan && planfix_action(plan, "addr.add") &&
	    planfix_action(plan, "addr.add")->has_inverse,
	    "and it carries the way back, like every other address netcfgd adds");
	check(plan && !planfix_warned(plan, "does not act on it"),
	    "and nothing warns that this build is holding the source and not acting on it");
	planfix_release(plan, document, observed);

	/* The second apply, which is the property `plan.h` calls load-bearing. */
	plan = plan_of(WWAN_DEVICE, WWAN_REPORTED,
	    "\"links\":[" PLANFIX_LINK("wwan0", "") "],"
	    "\"addresses\":[" OURS("wwan0", "10.64.0.5/32") "]," REPORT("wwan0",
	        "\"10.64.0.5/32\"", ""),
	    &document, &observed);
	check(plan && ncfg_plan_is_empty(plan),
	    "and applying that plan twice is the empty plan plan.h asks for");
	planfix_release(plan, document, observed);
}

/*
 * 10.169, in both directions, and the whole reason this file exists.
 *
 * The report's spelling is whoever wrote it and the kernel's is its own, so
 * either side may be the long one. A `strcmp` gets both of these wrong the
 * same way: it plans an `addr.add` for an address the kernel is already
 * holding, and -- because the address is netcfgd's -- an `addr.del` for it in
 * the same plan. Two actions that each succeed, on every reconcile, for ever.
 */
static void an_address_spelled_two_ways_is_one_address(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = plan_of(WWAN_DEVICE, WWAN_REPORTED,
	    "\"links\":[" PLANFIX_LINK("wwan0", "") "],"
	    "\"addresses\":[" OURS("wwan0", "2001:db8::5/64") "],"
	    REPORT("wwan0", "\"2001:0DB8:0000:0000:0000:0000:0000:0005/64\"", ""),
	    &document, &observed);

	check(plan && planfix_count(plan, "addr.add") == 0u,
	    "a report writing the long form of an address the kernel holds plans no add");
	check(plan && planfix_count(plan, "addr.del") == 0u,
	    "  and the teardown does not remove the address the same report asked for");
	check(plan && ncfg_plan_is_empty(plan), "  so the second plan is empty, which is the point");
	planfix_release(plan, document, observed);

	/* And the other way round: the kernel reported the long form -- which is
	 * what an address installed by something else on the same interface looks
	 * like -- and the report is compressed. */
	plan = plan_of(WWAN_DEVICE, WWAN_REPORTED,
	    "\"links\":[" PLANFIX_LINK("wwan0", "") "],"
	    "\"addresses\":[" OURS("wwan0", "2001:0DB8:0000:0000:0000:0000:0000:0005/64") "],"
	    REPORT("wwan0", "\"2001:db8::5/64\"", ""),
	    &document, &observed);
	check(plan && ncfg_plan_is_empty(plan),
	    "and the same when it is the observation carrying the spelling nobody types");
	planfix_release(plan, document, observed);
}

/*
 * No report and an empty report are different facts and get different
 * sentences.
 *
 * "No addresses here" has two very different causes and an operator needs to
 * know whether to look at netcfgd or at the thing that reports: a helper that
 * has not connected yet leaves no file at all, while a bearer that dropped
 * writes one saying so.
 */
static void nothing_reported_is_a_sentence_rather_than_a_silence(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = plan_of(WWAN_DEVICE, WWAN_REPORTED,
	    "\"links\":[" PLANFIX_LINK("wwan0", "") "]", &document, &observed);

	check(plan && planfix_count(plan, "addr.add") == 0u,
	    "an interface whose report has not arrived has nothing planned for it");
	check(plan && planfix_warned(plan, "/run/netcfgd/reported/wwan0"),
	    "and the warning names the file that is not there");
	planfix_release(plan, document, observed);

	plan = plan_of(WWAN_DEVICE, WWAN_REPORTED,
	    "\"links\":[" PLANFIX_LINK("wwan0", "") "]," REPORT("wwan0", "", ""),
	    &document, &observed);
	check(plan && planfix_warned(plan, "reported with no addresses, so the link is down"),
	    "and a report that arrived carrying none says the link is down instead");
	check(plan && !planfix_warned(plan, "/run/netcfgd/reported/wwan0"),
	    "  which is a different sentence from the one above, not the same one twice");
	planfix_release(plan, document, observed);
}

/*
 * The teardown's half, which is the half 10.169 says fires only where netcfgd
 * owns the address -- and which is rule 7 pointed the other way.
 *
 * A bearer that goes down empties the report, the address stops being wanted,
 * and it goes. Unlike a lease there is no client holding it and no backend to
 * restart, so leaving it would be an address on a link that cannot carry it.
 */
static void an_address_the_report_no_longer_names_is_withdrawn(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = plan_of(WWAN_DEVICE, WWAN_REPORTED,
	    "\"links\":[" PLANFIX_LINK("wwan0", "") "],"
	    "\"addresses\":[" OURS("wwan0", "10.64.0.9/32") "]," REPORT("wwan0",
	        "\"10.64.0.5/32\"", ""),
	    &document, &observed);

	check(plan && planfix_count(plan, "addr.add") == 1u &&
	    planfix_count(plan, "addr.del") == 1u,
	    "an address the bearer has stopped reporting goes, and the new one arrives");
	check(plan && wrote(plan, "10.64.0.9/32"),
	    "  and it is the one the report dropped that is removed");
	planfix_release(plan, document, observed);

	/* And nothing foreign is ever touched, which is the guard that holds
	 * whatever a report says. */
	plan = plan_of(WWAN_DEVICE, WWAN_REPORTED,
	    "\"links\":[" PLANFIX_LINK("wwan0", "") "],"
	    "\"addresses\":[{\"interface\":\"wwan0\",\"address\":\"10.64.0.9/32\","
	    "\"ownership\":\"foreign\",\"origin\":\"static\"}]," REPORT("wwan0",
	        "\"10.64.0.5/32\"", ""),
	    &document, &observed);
	check(plan && planfix_count(plan, "addr.del") == 0u,
	    "and an address netcfgd does not own is left where it is, report or no report");
	planfix_release(plan, document, observed);
}

/* ------------------------------------------------------------------------ *
 * The routes
 * ------------------------------------------------------------------------ */

/*
 * A default route per reported gateway -- two on a dual-stack bearer, which is
 * why the report's gateway list is a list.
 *
 * `default` for both families, because that is the one word the kernel gives
 * back: a dump carries no destination for either a v4 or a v6 default route.
 * Spelling the v6 one `::/0` made every comparison against the observation
 * fail in the Rust, so a dual-stack report added `::/0` and deleted `default`
 * on every single reconcile.
 */
static void a_reported_gateway_is_a_default_route(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = plan_of(WWAN_DEVICE, WWAN_REPORTED,
	    "\"links\":[" PLANFIX_LINK("wwan0", "") "],"
	    REPORT_GW("wwan0", "\"10.64.0.5/32\"", "\"10.64.0.1\",\"2001:db8::1\""),
	    &document, &observed);

	check(plan && planfix_count(plan, "route.add") == 2u,
	    "a dual-stack bearer's two gateways are two default routes");
	check(plan && wrote(plan, "\"destination\":\"default\"") &&
	    lacks(plan, "\"destination\":\"::/0\""),
	    "and both are spelled `default`, which is the only word the kernel gives back");
	check(plan && wrote(plan, "\"onlink\":true"),
	    "and onlink, since a bearer's next hop is routinely outside every address it gave");
	planfix_release(plan, document, observed);

	plan = plan_of(WWAN_DEVICE, WWAN_REPORTED,
	    "\"links\":[" PLANFIX_LINK("wwan0", "") "],"
	    "\"addresses\":[" OURS("wwan0", "10.64.0.5/32") "],"
	    "\"routes\":[" OURS_ROUTE("wwan0", "default", "10.64.0.1") "],"
	    REPORT_GW("wwan0", "\"10.64.0.5/32\"", "\"10.64.0.1\""),
	    &document, &observed);
	check(plan && ncfg_plan_is_empty(plan),
	    "and a machine already carrying it plans nothing at all on the second run");
	planfix_release(plan, document, observed);
}

/*
 * A route the report names outright, and the spellings it may arrive in.
 *
 * `0.0.0.0/0` and `::/0` are the two other ways to write a default route and
 * both become the kernel's word. Everything else is a prefix, canonicalised --
 * a VPN pushing `2001:0DB8:2::/64` is the same route the kernel reports as
 * `2001:db8:2::/64`, and the port notes record that the Rust hands that text
 * through unchanged.
 */
static void a_named_route_is_canonicalised_like_every_other(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = plan_of(WWAN_DEVICE, WWAN_REPORTED,
	    "\"links\":[" PLANFIX_LINK("wwan0", "") "]," REPORT("wwan0", "\"10.64.0.5/32\"",
	        ",\"routes\":[{\"destination\":\"2001:0DB8:2::/64\",\"via\":\"2001:db8::1\"}]"),
	    &document, &observed);

	check(plan && planfix_count(plan, "route.add") == 1u &&
	    wrote(plan, "\"destination\":\"2001:db8:2::/64\""),
	    "a route a report pushes is written the way the kernel writes it");
	planfix_release(plan, document, observed);

	/* And so the machine that already holds it plans nothing -- which the
	 * uncanonicalised spelling could not do, because the comparison against
	 * the observation is a string one. */
	plan = plan_of(WWAN_DEVICE, WWAN_REPORTED,
	    "\"links\":[" PLANFIX_LINK("wwan0", "") "],"
	    "\"addresses\":[" OURS("wwan0", "10.64.0.5/32") "],"
	    "\"routes\":[" OURS_ROUTE("wwan0", "2001:db8:2::/64", "2001:db8::1") "],"
	    REPORT("wwan0", "\"10.64.0.5/32\"",
	        ",\"routes\":[{\"destination\":\"2001:0DB8:2::/64\",\"via\":\"2001:0db8::1\"}]"),
	    &document, &observed);
	check(plan && ncfg_plan_is_empty(plan),
	    "  so the second plan is empty, next hop spelled the long way and all");
	planfix_release(plan, document, observed);

	plan = plan_of(WWAN_DEVICE, WWAN_REPORTED,
	    "\"links\":[" PLANFIX_LINK("wwan0", "") "]," REPORT("wwan0", "\"10.64.0.5/32\"",
	        ",\"routes\":[{\"destination\":\"0.0.0.0/0\",\"via\":\"10.64.0.1\"},"
	        "{\"destination\":\"::/0\",\"via\":\"2001:db8::1\"}]"),
	    &document, &observed);
	check(plan && planfix_count(plan, "route.add") == 2u &&
	    lacks(plan, "\"destination\":\"0.0.0.0/0\"") && lacks(plan, "\"destination\":\"::/0\""),
	    "and both other spellings of a default route become the kernel's one word");
	planfix_release(plan, document, observed);
}

/*
 * One bad line does not discard a report that also carried six good ones,
 * which is the contract's rule for every other malformed value in one.
 *
 * A destination with no prefix length is one of them: it is an address rather
 * than a prefix, and carrying it to a netlink refusal puts the error where the
 * operator cannot see which file it came from.
 */
static void a_line_that_is_not_a_route_is_skipped_rather_than_refused(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = plan_of(WWAN_DEVICE, WWAN_REPORTED,
	    "\"links\":[" PLANFIX_LINK("wwan0", "") "]," REPORT("wwan0", "\"10.64.0.5/32\"",
	        ",\"routes\":[{\"destination\":\"not-a-prefix\"},"
	        "{\"destination\":\"10.9.0.1\"},"
	        "{\"destination\":\"10.9.0.0/24\",\"via\":\"10.64.0.1\"}]"),
	    &document, &observed);

	check(plan && planfix_count(plan, "route.add") == 1u,
	    "a destination that is not one is skipped and the good line beside it survives");
	check(plan && wrote(plan, "\"destination\":\"10.9.0.0/24\""),
	    "  and it is the prefix, not the bare address and not the word");
	planfix_release(plan, document, observed);
}

/*
 * Whether a file in `/run` is believed at all, which is not "there is a file".
 *
 * A report for an interface the document says nothing about is an observation
 * netcfgd has no instruction for, and installing a default route off the
 * strength of it is not something to invent. Two ways in: the addressing list
 * says `reported`, or netcfgd started the writer itself -- a tunnel reports
 * through a script netcfgd generated, and requiring the word as well would
 * mean a tunnel that silently kept none of its routes until somebody added it.
 */
static void a_report_is_believed_only_where_the_document_gave_a_reason(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = plan_of(WWAN_DEVICE, WWAN_SLAAC,
	    "\"links\":[" PLANFIX_LINK("wwan0", "") "],"
	    REPORT_GW("wwan0", "\"10.64.0.5/32\"", "\"10.64.0.1\""),
	    &document, &observed);

	check(plan && planfix_count(plan, "route.add") == 0u &&
	    planfix_count(plan, "addr.add") == 0u,
	    "a report for an interface that claimed none is read and acted on by nothing");
	planfix_release(plan, document, observed);

	plan = plan_of(TUN_DEVICE, TUN_INTERFACE,
	    "\"links\":[" PLANFIX_LINK("tun0", "") "],"
	    REPORT_GW("tun0", "\"10.8.0.2/24\"", "\"10.8.0.1\""),
	    &document, &observed);
	check(plan && planfix_count(plan, "route.add") == 1u,
	    "and a tunnel netcfgd started claims its own report with no word in the file");
	check(plan && planfix_count(plan, "addr.add") == 0u,
	    "  though the addresses still wait for the word: the routes are 0047, the "
	    "addresses are the source");
	planfix_release(plan, document, observed);
}

/*
 * The teardown asks the same function the forward pass does.
 *
 * Two answers to "which routes does this interface want" is a plan that
 * installs a route and deletes it on the next reconcile -- the loud failure,
 * and the one worth a shared function rather than two lists that agree today.
 */
static void the_teardown_reads_the_report_the_forward_pass_read(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = plan_of(WWAN_DEVICE, WWAN_REPORTED,
	    "\"links\":[" PLANFIX_LINK("wwan0", "") "],"
	    "\"addresses\":[" OURS("wwan0", "10.64.0.5/32") "],"
	    "\"routes\":[" OURS_ROUTE("wwan0", "default", "10.64.0.1") "],"
	    REPORT_GW("wwan0", "\"10.64.0.5/32\"", "\"10.64.0.1\""),
	    &document, &observed);

	check(plan && planfix_count(plan, "route.del") == 0u,
	    "a route the report still asks for is not withdrawn by the teardown");
	planfix_release(plan, document, observed);

	/* The bearer drops: the report stops naming the gateway, so the route
	 * stops being wanted and goes -- the same withdrawal the address gets, for
	 * the same reason. */
	plan = plan_of(WWAN_DEVICE, WWAN_REPORTED,
	    "\"links\":[" PLANFIX_LINK("wwan0", "") "],"
	    "\"addresses\":[" OURS("wwan0", "10.64.0.5/32") "],"
	    "\"routes\":[" OURS_ROUTE("wwan0", "default", "10.64.0.1") "],"
	    REPORT("wwan0", "\"10.64.0.5/32\"", ""),
	    &document, &observed);
	check(plan && planfix_count(plan, "route.del") == 1u,
	    "and one it has stopped naming is, because the bearer that offered it is gone");
	planfix_release(plan, document, observed);
}

/* The document's own routes did not stop being planned when the report's
 * joined them, which is the thing a shared list is most likely to break. */
static void the_documents_own_routes_are_still_planned_beside_them(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = plan_of(WWAN_DEVICE,
	    "{\"name\":\"wwan0\",\"addressing\":[{\"source\":\"reported\"}],"
	    "\"routes\":[{\"destination\":\"10.20.0.0/16\",\"via\":\"10.64.0.1\"}]}",
	    "\"links\":[" PLANFIX_LINK("wwan0", "") "],"
	    REPORT_GW("wwan0", "\"10.64.0.5/32\"", "\"10.64.0.1\""),
	    &document, &observed);

	check(plan && planfix_count(plan, "route.add") == 2u,
	    "the document's route and the report's are both planned, in that order");
	check(plan && wrote(plan, "\"destination\":\"10.20.0.0/16\""),
	    "  and the document's is the one that is still there");
	planfix_release(plan, document, observed);
}

int main(void)
{
	a_report_is_where_the_addresses_come_from();
	an_address_spelled_two_ways_is_one_address();
	nothing_reported_is_a_sentence_rather_than_a_silence();
	an_address_the_report_no_longer_names_is_withdrawn();

	a_reported_gateway_is_a_default_route();
	a_named_route_is_canonicalised_like_every_other();
	a_line_that_is_not_a_route_is_skipped_rather_than_refused();
	a_report_is_believed_only_where_the_document_gave_a_reason();
	the_teardown_reads_the_report_the_forward_pass_read();
	the_documents_own_routes_are_still_planned_beside_them();

	printf("\nplan reported: %d checks, %d failed\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
