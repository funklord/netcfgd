/*
 * plan_input_test.c -- what netcfgd runs, against what its own firewall drops
 * (project.md 10.620).
 *
 * WHAT IS CHECKED
 *   An `input` chain that drops by default is said, once, where it accepts no
 *   replies; and per interface where it would starve a DHCPv6 client or IPv6
 *   itself, and per WireGuard device where it would drop a peer's handshake.
 *   Each warning names the rule to write, and the rule named silences it --
 *   which is what proves the rule is the right one. And the regression the
 *   shared test had: a rule limited to `established` does not accept new
 *   traffic, so it no longer silences the DHCP server's warning.
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

#define DROPPING(rules) \
	",\"firewall\":{\"input\":{\"policy\":\"drop\",\"rules\":[" rules "]}," \
	"\"forward\":{\"policy\":\"accept\"},\"output\":{\"policy\":\"accept\"}}"
#define REPLIES \
	"{\"name\":\"established\",\"action\":\"accept\",\"states\":[\"established\",\"related\"]}"
#define WAN_DEVICE "{\"name\":\"wan0\",\"kind\":{\"kind\":\"physical\"}}"
#define WAN(sources) "{\"name\":\"wan0\",\"addressing\":[" sources "]}"
#define DHCP6 "{\"source\":\"dhcp6\",\"mode\":\"managed\",\"rapid_commit\":false}"
#define DHCP4 "{\"source\":\"dhcp4\"}"
#define WG_DEVICE \
	"{\"name\":\"wg0\",\"kind\":{\"kind\":\"wire_guard\"," \
	"\"private_key\":{\"provider\":\"keyring\",\"name\":\"wg\"},\"listen_port\":51820," \
	"\"peers\":[]}}"

static ncfg_plan_t *plan_of(const char *devices, const char *interfaces, const char *rules,
    ncfg_document_t **document, ncfg_observed_t **observed)
{
	return planfix_plan(devices, interfaces, "", rules, "\"links\":[]", document, observed);
}

static void no_replies_is_said_once(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = plan_of(WAN_DEVICE, WAN(DHCP4), DROPPING(""), &document,
	    &observed);

	check(plan && planfix_warned(plan, "accepts no replies") &&
	        planfix_warned(plan, "state = [\"established\", \"related\"]"),
	    "an input chain dropping every reply is said, with the rule that fixes it");
	planfix_release(plan, document, observed);

	plan = plan_of(WAN_DEVICE, WAN(DHCP4), DROPPING(REPLIES), &document, &observed);
	check(plan && !planfix_warned(plan, "accepts no replies"),
	    "  and is silent once that rule is there");
	planfix_release(plan, document, observed);

	plan = plan_of(WAN_DEVICE, WAN(DHCP4), "", &document, &observed);
	check(plan && !planfix_warned(plan, "input chain"),
	    "  and nothing is said with no firewall at all");
	planfix_release(plan, document, observed);
}

static void a_dhcpv6_client_and_ipv6_are_said(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = plan_of(WAN_DEVICE, WAN(DHCP6), DROPPING(REPLIES), &document,
	    &observed);

	check(plan && planfix_warned(plan, "no rule accepting DHCPv6 replies on wan0") &&
	        planfix_warned(plan, "port = [546]; interface = \"wan0\""),
	    "a DHCPv6 client behind a dropping input chain is said, even with replies accepted");
	check(plan && planfix_warned(plan, "no rule accepting ICMPv6 on wan0") &&
	        planfix_warned(plan, "protocol = \"icmpv6\"; interface = \"wan0\""),
	    "  and so is IPv6 itself, neighbour discovery being dropped");
	planfix_release(plan, document, observed);

	plan = plan_of(WAN_DEVICE, WAN(DHCP6), DROPPING(REPLIES
	    ",{\"name\":\"dhcpv6\",\"action\":\"accept\",\"protocol\":\"udp\",\"ports\":[546],"
	    "\"interface\":\"wan0\"},{\"name\":\"icmpv6\",\"action\":\"accept\","
	    "\"protocol\":\"icmpv6\",\"interface\":\"wan0\"}"), &document, &observed);
	check(plan && !planfix_warned(plan, "DHCPv6 replies") && !planfix_warned(plan, "ICMPv6"),
	    "  and neither once the rules each warning names are there");
	planfix_release(plan, document, observed);

	plan = plan_of(WAN_DEVICE, WAN(DHCP4), DROPPING(REPLIES), &document, &observed);
	check(plan && !planfix_warned(plan, "DHCPv6") && !planfix_warned(plan, "ICMPv6"),
	    "  while an IPv4-only interface is told about neither");
	planfix_release(plan, document, observed);
}

static void a_wireguard_listener_is_said(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = plan_of(WG_DEVICE, "", DROPPING(REPLIES), &document, &observed);

	check(plan && planfix_warned(plan, "no rule accepting UDP 51820, where wg0 listens") &&
	        planfix_warned(plan, "protocol = \"udp\"; port = [51820] }"),
	    "a WireGuard device listening behind a dropping input chain is said");
	planfix_release(plan, document, observed);

	plan = plan_of(WG_DEVICE, "", DROPPING(REPLIES
	    ",{\"name\":\"wg\",\"action\":\"accept\",\"protocol\":\"udp\",\"ports\":[51820]}"),
	    &document, &observed);
	check(plan && !planfix_warned(plan, "where wg0 listens"),
	    "  and is silent once its port is accepted");
	planfix_release(plan, document, observed);
}

/* The shared test counted any accept rule with no protocol and no port, so a
 * rule limited to replies silenced the DHCP server's warning while letting no
 * request in. */
static void a_rule_for_replies_lets_no_request_in(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	/* The link observed up, because the DHCP server is planned from inside
	 * the link loop and a link that is not there plans nothing. */
	ncfg_plan_t     *plan = planfix_plan(
	    "{\"name\":\"br0\",\"kind\":{\"kind\":\"physical\"}}",
	    "{\"name\":\"br0\",\"addressing\":[{\"source\":\"static\","
	    "\"address\":\"192.168.1.1/24\"}],\"dhcp_server\":{\"dns\":[\"9.9.9.9\"]}}",
	    "", DROPPING(REPLIES), "\"links\":[" PLANFIX_LINK("br0", "") "]", &document,
	    &observed);

	check(plan && planfix_warned(plan, "no rule accepting DHCP on br0"),
	    "a rule accepting only replies does not count as accepting DHCP requests");
	planfix_release(plan, document, observed);
}

/* A masquerading router whose forward chain drops the replies. */
#define FORWARD_DROPPING(rules) \
	",\"firewall\":{\"input\":{\"policy\":\"accept\"},\"forward\":{\"policy\":\"drop\"," \
	"\"rules\":[" rules "]},\"output\":{\"policy\":\"accept\"}}"
#define MASQUERADING "{\"name\":\"wan0\",\"nat\":true,\"addressing\":[" DHCP4 "]}"

static void a_masquerade_whose_replies_are_dropped_is_said(void)
{
	ncfg_document_t *document;
	ncfg_observed_t *observed;
	ncfg_plan_t     *plan = plan_of(WAN_DEVICE, MASQUERADING, FORWARD_DROPPING(""), &document,
	    &observed);

	check(plan && planfix_warned(plan, "wan0 masquerades and the firewall's forward chain") &&
	        planfix_warned(plan, "to `forward`"),
	    "a masquerade whose forward chain drops every reply is said");
	planfix_release(plan, document, observed);

	plan = plan_of(WAN_DEVICE, MASQUERADING, FORWARD_DROPPING(REPLIES), &document, &observed);
	check(plan && !planfix_warned(plan, "masquerades"),
	    "  and is silent once replies are accepted there");
	planfix_release(plan, document, observed);
}

int main(void)
{
	a_masquerade_whose_replies_are_dropped_is_said();
	no_replies_is_said_once();
	a_dhcpv6_client_and_ipv6_are_said();
	a_wireguard_listener_is_said();
	a_rule_for_replies_lets_no_request_in();
	printf("plan_input_test: %d checks, %d failed\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
