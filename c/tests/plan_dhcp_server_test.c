/*
 * plan_dhcp_server_test.c -- what an interface hands out by DHCPv4 (decision
 * 0297), as the planner decides it.
 *
 * WHAT IS CHECKED
 *   That a server is started after the address it serves, left alone where
 *   what its file says it serves is what the document says, restarted where
 *   that moved, and that a server offering no DNS server is said.
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

#define LAN_DEVICE "{\"name\":\"br0\",\"kind\":{\"kind\":\"physical\"}}"
#define SERVING(server) \
	"{\"name\":\"br0\",\"addressing\":[{\"source\":\"static\"," \
	"\"address\":\"192.168.1.1/24\"}],\"dhcp_server\":{" server "}}"
#define LAN_UP PLANFIX_LINK("br0", "")
#define LAN_ADDRESS \
	"\"addresses\":[{\"interface\":\"br0\",\"address\":\"192.168.1.1/24\"," \
	"\"proto\":110,\"ownership\":\"ours\",\"origin\":\"static\"}]"
#define DNSMASQ(served) \
	"\"backends\":[{\"kind\":\"dhcp_server\",\"interface\":\"br0\",\"running\":true," \
	"\"served\":\"" served "\"}]"
#define WANTED "192.168.1.100-192.168.1.249, 43200 s, dns 9.9.9.9"

/* Whether `later` in a plan depends, directly, on an action named `earlier`. */
static int depends_on(const ncfg_plan_t *plan, const char *later, const char *earlier)
{
	const ncfg_action_t *after = planfix_action(plan, later);
	size_t               at;

	for (at = 0; after && at < after->depends_count; at++) {
		if (after->depends_on[at] < plan->action_count &&
		    strcmp(ncfg_op_name(&plan->actions[after->depends_on[at]].op), earlier) == 0) {
			return 1;
		}
	}
	return 0;
}

static void a_server_starts_after_the_address_it_serves(void)
{
	ncfg_document_t     *document;
	ncfg_observed_t     *observed;
	ncfg_plan_t         *plan = planfix_plan(LAN_DEVICE,
	    SERVING("\"dns\":[\"9.9.9.9\"]"), "", "", "\"links\":[" LAN_UP "]", &document, &observed);
	const ncfg_action_t *start = plan ? planfix_action(plan, "backend.start") : NULL;

	check(start && start->op.u.backend.kind == NCFG_BACKEND_DHCP_SERVER &&
	    strcmp(start->op.u.backend.iface, "br0") == 0,
	    "an interface with a dhcp_server block starts one on it");
	check(plan && depends_on(plan, "backend.start", "addr.add"),
	    "  after the address it serves, which it would otherwise serve before having");
	check(plan && !planfix_warned(plan, "offers no DNS server"),
	    "  and says nothing about DNS when it offers some");
	planfix_release(plan, document, observed);
}

static void a_server_with_no_dns_is_said(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = planfix_plan(LAN_DEVICE, SERVING(""), "", "",
	    "\"links\":[" LAN_UP "]", &document, &observed);

	check(plan && planfix_warned(plan, "offers no DNS server") &&
	    planfix_warned(plan, "set `dns_forward = true`") && planfix_warned(plan, "or `dns`"),
	    "a server offering no DNS server is said, with what to set (0297: never guessed)");
	planfix_release(plan, document, observed);
}

/* A firewall whose input chain drops, with `rules` spliced in. */
#define DROPPING(rules) \
	",\"firewall\":{\"input\":{\"policy\":\"drop\",\"rules\":[" rules "]}," \
	"\"forward\":{\"policy\":\"accept\"},\"output\":{\"policy\":\"accept\"}}"

static void a_forwarder_answers_for_the_router(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = planfix_plan(LAN_DEVICE, SERVING("\"dns_forward\":true"), "", "",
	    "\"links\":[" LAN_UP "]", &document, &observed);

	/* 0301: with no `dns`, a forwarding server offers itself, so the hosts
	 * do resolve and the 0297 warning would be wrong. */
	check(plan && !planfix_warned(plan, "offers no DNS server"),
	    "a server forwarding DNS is not said to offer none");
	planfix_release(plan, document, observed);
}

static void a_firewall_that_drops_the_requests_is_said(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = planfix_plan(LAN_DEVICE, SERVING("\"dns_forward\":true"), "", DROPPING(""),
	    "\"links\":[" LAN_UP "]", &document, &observed);

	/* Warned, not opened (0301, as 0298 for a forward), with the rule to
	 * write -- spelled as the firewall's grammar takes it. */
	check(plan && planfix_warned(plan, "no rule accepting DHCP on br0") &&
	        planfix_warned(plan, "port = [67]; interface = \"br0\""),
	    "an input chain dropping DHCP is said, naming the rule that would let it in");
	check(plan && planfix_warned(plan, "no rule accepting DNS on br0") &&
	        planfix_warned(plan, "port = [53]; interface = \"br0\""),
	    "  and so is one dropping the forwarder's DNS");
	planfix_release(plan, document, observed);

	plan = planfix_plan(LAN_DEVICE, SERVING("\"dns_forward\":true"), "",
	    DROPPING("{\"name\":\"lan\",\"action\":\"accept\",\"interface\":\"br0\"}"),
	    "\"links\":[" LAN_UP "]", &document, &observed);
	check(plan && !planfix_warned(plan, "no rule accepting DHCP") &&
	        !planfix_warned(plan, "no rule accepting DNS"),
	    "  and neither once a rule accepts everything on that interface");
	planfix_release(plan, document, observed);

	plan = planfix_plan(LAN_DEVICE, SERVING("\"dns_forward\":true"), "",
	    DROPPING("{\"name\":\"dns\",\"action\":\"accept\",\"protocol\":\"udp\","
	             "\"ports\":[53],\"interface\":\"wan0\"}"),
	    "\"links\":[" LAN_UP "]", &document, &observed);
	check(plan && planfix_warned(plan, "no rule accepting DNS on br0"),
	    "  while one accepting DNS on another interface does not count");
	planfix_release(plan, document, observed);
}

/* DHCPv6 (0303): hosts ask only when an advertisement tells them to, and
 * the firewall's input chain has to let UDP 547 in. */
#define SERVING6(v6, advertise) \
	"{\"name\":\"br0\",\"addressing\":[{\"source\":\"static\"," \
	"\"address\":\"192.168.1.1/24\"}," v6 "]" advertise \
	",\"dhcp_server\":{\"dns_forward\":true,\"range6_start\":\"::100\"," \
	"\"range6_end\":\"::1ff\"}}"
#define STATIC6 "{\"source\":\"static\",\"address\":\"fd00::1/64\"}"
/* `advertise` takes a delegated prefix only, so the managed case is one. */
#define DELEGATED6 \
	"{\"source\":\"delegated\",\"prefix\":{\"source\":\"wan0\",\"index\":0," \
	"\"subnet\":1},\"suffix\":\"::1/64\"}"
#define MANAGED \
	",\"advertise\":{\"backend\":\"auto\",\"prefixes\":[{\"source\":\"wan0\"," \
	"\"index\":0,\"subnet\":1}],\"managed\":true,\"other_config\":false,\"dns\":true}"

static void a_dhcpv6_range_nobody_is_told_of_is_said(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = planfix_plan(LAN_DEVICE, SERVING6(STATIC6, ""), "", DROPPING(""),
	    "\"links\":[" LAN_UP "]", &document, &observed);

	check(plan && planfix_warned(plan, "no router advertisement on it tells the hosts") &&
	        planfix_warned(plan, "`managed = true`"),
	    "a DHCPv6 range with no managed advertisement is said");
	check(plan && planfix_warned(plan, "no rule accepting DHCPv6 on br0") &&
	        planfix_warned(plan, "port = [547]; interface = \"br0\""),
	    "  and so is a firewall dropping DHCPv6, naming the rule");
	planfix_release(plan, document, observed);

	plan = planfix_plan(LAN_DEVICE, SERVING6(DELEGATED6, MANAGED), "", "",
	    "\"links\":[" LAN_UP "]", &document, &observed);
	check(plan && !planfix_warned(plan, "tells the hosts to ask") &&
	        !planfix_warned(plan, "DHCPv6 on br0"),
	    "  and neither with the flag set and no firewall");
	planfix_release(plan, document, observed);

	/* A static prefix (0304) needs no lease, so the advertiser starts at
	 * once and the warning is satisfied the same way. */
	plan = planfix_plan(LAN_DEVICE,
	    SERVING6(STATIC6, ",\"advertise\":{\"backend\":\"auto\",\"prefixes\":[],"
	                      "\"static_prefixes\":[\"fd00::/64\"],\"managed\":true,"
	                      "\"other_config\":false,\"dns\":true}"),
	    "", "", "\"links\":[" LAN_UP "]", &document, &observed);
	check(plan && !planfix_warned(plan, "tells the hosts to ask") &&
	        planfix_action(plan, "backend.start") != NULL && !planfix_warned(plan, "waiting on"),
	    "  and a static prefix starts the advertiser with no lease to wait for");
	planfix_release(plan, document, observed);
}

static void a_server_serving_what_is_asked_is_left_alone(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = planfix_plan(LAN_DEVICE, SERVING("\"dns\":[\"9.9.9.9\"]"), "", "",
	    "\"links\":[" LAN_UP "]," LAN_ADDRESS "," DNSMASQ(WANTED), &document, &observed);

	check(plan && plan->action_count == 0u,
	    "a server whose file says it serves what the document asks plans nothing");
	planfix_release(plan, document, observed);
}

static void a_server_serving_something_else_restarts(void)
{
	ncfg_document_t     *document;
	ncfg_observed_t     *observed;
	ncfg_plan_t         *plan = planfix_plan(LAN_DEVICE,
	    SERVING("\"dns\":[\"9.9.9.9\"],\"lease\":3600"), "", "",
	    "\"links\":[" LAN_UP "]," LAN_ADDRESS "," DNSMASQ(WANTED), &document, &observed);
	const ncfg_action_t *stop = plan ? planfix_action(plan, "backend.stop") : NULL;

	check(stop && stop->op.u.backend.kind == NCFG_BACKEND_DHCP_SERVER &&
	    strcmp(stop->reason.field, "dhcp_server") == 0 &&
	    strstr(stop->reason.desired, "3600 s") && strstr(stop->reason.observed, "43200 s"),
	    "a changed lease restarts the server, the reason saying both in words");
	check(plan && planfix_count(plan, "backend.start") == 1u &&
	    depends_on(plan, "backend.start", "backend.stop"),
	    "  starting it again after the stop, since dnsmasq does not re-read its range");
	planfix_release(plan, document, observed);
}

/* A reservation added to a server already running: the summary differs by
 * its count and digest, so dnsmasq is restarted to give the host its address
 * (10.605). The plan names the count, which is what an operator reads. */
static void a_reservation_added_restarts_the_server(void)
{
	ncfg_document_t     *document;
	ncfg_observed_t     *observed;
	ncfg_plan_t         *plan = planfix_plan(LAN_DEVICE,
	    SERVING("\"dns\":[\"9.9.9.9\"],\"hosts\":[{\"name\":\"printer\","
	        "\"mac\":\"AA:BB:CC:DD:EE:01\",\"address\":\"192.168.1.10\"}]"),
	    "", "", "\"links\":[" LAN_UP "]," LAN_ADDRESS "," DNSMASQ(WANTED), &document, &observed);
	const ncfg_action_t *stop = plan ? planfix_action(plan, "backend.stop") : NULL;

	check(stop && strcmp(stop->reason.field, "dhcp_server") == 0 &&
	    strstr(stop->reason.desired, ", 1 host ") && !strstr(stop->reason.observed, "host"),
	    "a reservation added restarts the server, the plan counting the hosts");
	check(plan && planfix_count(plan, "backend.start") == 1u,
	    "  and starts it again");
	planfix_release(plan, document, observed);
}

static void a_server_the_document_dropped_is_stopped(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = planfix_plan(LAN_DEVICE,
	    "{\"name\":\"br0\",\"addressing\":[{\"source\":\"static\",\"address\":\"192.168.1.1/24\"}]}",
	    "", "", "\"links\":[" LAN_UP "]," LAN_ADDRESS "," DNSMASQ(WANTED), &document, &observed);
	const ncfg_action_t *stop = plan ? planfix_action(plan, "backend.stop") : NULL;

	check(stop && strcmp(stop->reason.field, "dhcp_server") == 0,
	    "a server on an interface whose dhcp_server block was removed is stopped");
	planfix_release(plan, document, observed);
}

/* 0305: DNS sent anywhere from the LAN answered by its forwarder, as two
 * port forwards to the router's own address -- the port forwards' kernel
 * path, which writes, reads back and compares them. */
static void an_intercepting_server_forwards_dns_to_itself(void)
{
	ncfg_document_t     *document;
	ncfg_observed_t     *observed;
	ncfg_plan_t         *plan = planfix_plan(LAN_DEVICE,
	    SERVING("\"dns_forward\":true,\"dns_intercept\":true"), "", "",
	    "\"links\":[" LAN_UP "]", &document, &observed);
	const ncfg_action_t *replace = plan ? planfix_action(plan, "nftables.replace") : NULL;
	int                  udp = 0;
	int                  tcp = 0;
	size_t               at;

	for (at = 0; replace && at < replace->op.u.nftables.forward_count; at++) {
		const ncfg_forward_rule_t *rule = &replace->op.u.nftables.forwards[at];
		int matches = rule->kind == NCFG_FORWARD_RULE_FORWARD &&
		    strcmp(rule->interface, "br0") == 0 && strcmp(rule->to, "192.168.1.1") == 0 &&
		    rule->port == 53u && rule->to_port == 53u;

		udp += matches && rule->protocol == NCFG_PORT_FORWARD_UDP &&
		    strcmp(rule->name, "dns+udp") == 0;
		tcp += matches && rule->protocol == NCFG_PORT_FORWARD_TCP &&
		    strcmp(rule->name, "dns+tcp") == 0;
	}
	check(replace && replace->op.u.nftables.forward_count == 2u && udp == 1 && tcp == 1,
	    "an intercepting server sends DNS on 53, both protocols, to its own address");
	planfix_release(plan, document, observed);

	plan = planfix_plan(LAN_DEVICE, SERVING("\"dns_forward\":true"), "", "",
	    "\"links\":[" LAN_UP "]", &document, &observed);
	check(plan && !planfix_action(plan, "nftables.replace"),
	    "  and one that does not intercept writes no rule");
	planfix_release(plan, document, observed);

	/* And IPv6 to the first global static address, not the link-local one
	 * listed before it, in the form the kernel's read-back prints. */
	plan = planfix_plan(LAN_DEVICE,
	    "{\"name\":\"br0\",\"addressing\":[{\"source\":\"static\","
	    "\"address\":\"192.168.1.1/24\"},{\"source\":\"static\","
	    "\"address\":\"fe80::1/64\"},{\"source\":\"static\","
	    "\"address\":\"fd00:0007:0000::0001/64\"}],"
	    "\"dhcp_server\":{\"dns_forward\":true,\"dns_intercept\":true}}",
	    "", "", "\"links\":[" LAN_UP "]", &document, &observed);
	replace = plan ? planfix_action(plan, "nftables.replace") : NULL;
	udp = 0;
	tcp = 0;
	for (at = 0; replace && at < replace->op.u.nftables.forward_count; at++) {
		const ncfg_forward_rule_t *rule = &replace->op.u.nftables.forwards[at];

		udp += strcmp(rule->name, "dns6+udp") == 0 && strcmp(rule->to, "fd00:7::1") == 0;
		tcp += strcmp(rule->name, "dns6+tcp") == 0 && strcmp(rule->to, "fd00:7::1") == 0;
	}
	check(replace && replace->op.u.nftables.forward_count == 4u && udp == 1 && tcp == 1,
	    "  and IPv6 too, to the global static address in canonical form");
	planfix_release(plan, document, observed);
}

int main(void)
{
	an_intercepting_server_forwards_dns_to_itself();
	a_server_starts_after_the_address_it_serves();
	a_server_with_no_dns_is_said();
	a_forwarder_answers_for_the_router();
	a_firewall_that_drops_the_requests_is_said();
	a_dhcpv6_range_nobody_is_told_of_is_said();
	a_server_serving_what_is_asked_is_left_alone();
	a_server_serving_something_else_restarts();
	a_reservation_added_restarts_the_server();
	a_server_the_document_dropped_is_stopped();
	printf("plan_dhcp_server_test: %d checks, %d failed\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
