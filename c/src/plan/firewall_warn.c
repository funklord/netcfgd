/*
 * firewall_warn.c -- what netcfgd runs, against what its own firewall drops.
 *
 * WHY THIS EXISTS
 *   netcfgd's firewall adds no rule of its own (0294): every accept is one the
 *   operator wrote, which is what keeps the chain theirs. The cost is that an
 *   `input { policy = "drop" }` silently starves the services netcfgd itself
 *   runs on the router, and nothing said so. A DHCP server never asked
 *   (0297 had no warning until 0301), a DHCPv6 client whose reply comes from
 *   an address the request did not go to, IPv6 itself once neighbour
 *   discovery is dropped, a WireGuard peer whose handshake arrives as new.
 *   Each is a plan warning naming the rule that would let it in -- warned,
 *   never opened, as 0298 does for a forward (doc/journal.md 10.620).
 *
 * WHAT COUNTS AS ACCEPTING
 *   Deliberately generous, because this warns where nothing could let the
 *   traffic in: an accept rule of the right protocol or any, naming the port
 *   or none, on this interface or none. A rule narrowed by source or MAC still
 *   counts. **A rule limited to some states counts only for the states it
 *   names** -- `accept "established" { state = ["established"] }` has no
 *   protocol and no port, and before this it counted as accepting new DHCP
 *   requests, which is the one thing it does not do.
 */
#include "plan_internal.h"

#include <stdio.h>
#include <string.h>

static int names_state(const ncfg_firewall_rule_t *rule, const char *state)
{
	size_t at;

	if (rule->state_count == 0u) {
		return 1;
	}
	for (at = 0; at < rule->state_count; at++) {
		if (strcmp(rule->states[at], state) == 0) {
			return 1;
		}
	}
	return 0;
}

int ncfg_plan_input_drops(const ncfg_document_t *desired)
{
	return desired && desired->firewall &&
	    desired->firewall->input.policy == NCFG_FIREWALL_POLICY_DROP;
}

int ncfg_plan_forward_accepts_translated(const ncfg_document_t *desired)
{
	const ncfg_firewall_chain_t *chain;
	size_t                       r;

	if (!desired || !desired->firewall ||
	    desired->firewall->forward.policy != NCFG_FIREWALL_POLICY_DROP) {
		return 1;
	}
	chain = &desired->firewall->forward;
	for (r = 0; r < chain->rule_count; r++) {
		if (chain->rules[r].action == NCFG_FIREWALL_ACCEPT && chain->rules[r].translated) {
			return 1;
		}
	}
	return 0;
}

int ncfg_plan_input_accepts(const ncfg_document_t *desired, const char *iface, int protocol,
    int64_t port)
{
	const ncfg_firewall_chain_t *chain;
	size_t                       r;
	size_t                       p;

	if (!ncfg_plan_input_drops(desired)) {
		return 1;
	}
	chain = &desired->firewall->input;
	for (r = 0; r < chain->rule_count; r++) {
		const ncfg_firewall_rule_t *rule = &chain->rules[r];
		int                         named = rule->port_count == 0u &&
		    rule->port_range_count == 0u;

		if (rule->action != NCFG_FIREWALL_ACCEPT ||
		    (rule->protocol != NCFG_FIREWALL_PROTO_ANY && rule->protocol != protocol) ||
		    (rule->interface && iface && strcmp(rule->interface, iface) != 0) ||
		    !names_state(rule, "new")) {
			continue;
		}
		for (p = 0; port >= 0 && p < rule->port_count; p++) {
			named = named || rule->ports[p] == port;
		}
		/* And a range holding it (0331). */
		for (p = 0; port >= 0 && p < rule->port_range_count; p++) {
			unsigned long low = 0, high = 0;

			if (sscanf(rule->port_ranges[p], "%lu-%lu", &low, &high) == 2 &&
			    (unsigned long)port >= low && (unsigned long)port <= high) {
				named = 1;
			}
		}
		if (named) {
			return 1;
		}
	}
	return 0;
}

/* Whether a rule lets replies to the router's own traffic back in. */
static int accepts_replies(const ncfg_firewall_chain_t *chain)
{
	size_t r;

	for (r = 0; r < chain->rule_count; r++) {
		const ncfg_firewall_rule_t *rule = &chain->rules[r];

		if (rule->action == NCFG_FIREWALL_ACCEPT && !rule->interface &&
		    rule->state_count && names_state(rule, "established")) {
			return 1;
		}
	}
	return 0;
}

/* Whether an interface is addressed over IPv6 at all, and so needs
 * neighbour discovery and router advertisements to arrive. */
static int speaks_ipv6(const ncfg_interface_t *interface)
{
	size_t at;

	if (interface->advertise) {
		return 1;
	}
	for (at = 0; at < interface->addressing_count; at++) {
		const ncfg_address_source_t *source = &interface->addressing[at];

		switch (source->kind) {
		case NCFG_ADDRESS_SOURCE_DHCP6:
		case NCFG_ADDRESS_SOURCE_SLAAC:
		case NCFG_ADDRESS_SOURCE_DELEGATED:
			return 1;
		case NCFG_ADDRESS_SOURCE_STATIC:
			if (source->static_address.address &&
			    strchr(source->static_address.address, ':')) {
				return 1;
			}
			break;
		default:
			break;
		}
	}
	return 0;
}

static int asks_dhcp6(const ncfg_interface_t *interface)
{
	size_t at;

	for (at = 0; at < interface->addressing_count; at++) {
		if (interface->addressing[at].kind == NCFG_ADDRESS_SOURCE_DHCP6) {
			return 1;
		}
	}
	return 0;
}

/*
 * A masquerading router whose `forward` chain drops replies: every connection
 * the LAN opens goes out and its answer is dropped on the way back, which
 * reads as a dead uplink rather than a firewall.
 */
static void warn_forward_replies(ncfg_builder_t *builder)
{
	const ncfg_document_t *desired = builder->desired;
	const char            *masquerading = NULL;
	size_t                 at;

	if (!desired || !desired->firewall ||
	    desired->firewall->forward.policy != NCFG_FIREWALL_POLICY_DROP ||
	    accepts_replies(&desired->firewall->forward)) {
		return;
	}
	for (at = 0; !masquerading && at < desired->interface_count; at++) {
		if (desired->interfaces[at].nat.has && desired->interfaces[at].nat.value) {
			masquerading = desired->interfaces[at].name;
		}
	}
	if (masquerading) {
		ncfg_plan_warnf(builder->plan, masquerading,
		    "%s masquerades and the firewall's forward chain drops by default with nothing "
		    "accepting replies, so every connection the network behind it opens is answered "
		    "and the answer dropped. Add `accept \"established\" { state = "
		    "[\"established\", \"related\"] }` to `forward`, and a rule accepting what "
		    "may go out", masquerading);
	}
}

/*
 * A bridge whose forwarded frames a forward chain drops (10.891). With
 * br_netfilter loaded and `bridge-nf-call-iptables` on -- Docker does both --
 * a frame crossing a bridge from one port to another passes every table's
 * IP forward chain, and Docker leaves `ip filter/FORWARD` dropping by policy.
 * Traffic between two other machines through this one is then dropped, and
 * in a ring the box that forwards is the one carrying the failover, so it
 * works until the day a cable is cut. Said, not fought: the table is not
 * netcfgd's, and turning br_netfilter's switch off is Docker's business too.
 */
static void warn_bridged_filtered(ncfg_builder_t *builder)
{
	const ncfg_document_t *desired = builder->desired;
	const ncfg_observed_t *observed = builder->observed;
	int                    four, six;
	ncfg_buf_t             named;
	size_t                 at, d;

	if (!desired || !observed) {
		return;
	}
	four = observed->bridge_nf_call_iptables.has && observed->bridge_nf_call_iptables.value;
	six = observed->bridge_nf_call_ip6tables.has && observed->bridge_nf_call_ip6tables.value;
	if (!four && !six) {
		return;
	}
	ncfg_buf_init(&named, 0);
	for (at = 0; at < observed->forward_dropper_count; at++) {
		const char *one = observed->forward_droppers[at];

		if ((four && strncmp(one, "ip ", 3u) == 0) || (six && strncmp(one, "ip6 ", 4u) == 0) ||
		    strncmp(one, "inet ", 5u) == 0) {
			ncfg_buf_addf(&named, "%s`%s`", ncfg_buf_text(&named)[0] ? ", " : "", one);
		}
	}
	if (desired->firewall && desired->firewall->forward.policy == NCFG_FIREWALL_POLICY_DROP) {
		ncfg_buf_addf(&named, "%s%s", ncfg_buf_text(&named)[0] ? ", and " : "",
		    "this firewall's own `forward`");
	}
	for (d = 0; ncfg_buf_text(&named)[0] && d < desired->device_count; d++) {
		const ncfg_device_t *device = &desired->devices[d];

		if (device->kind.kind != NCFG_KIND_BRIDGE || device->kind.bridge.member_count < 2u) {
			continue;
		}
		ncfg_plan_warnf(builder->plan, device->name,
		    "%s forwards between its ports, and with bridge-nf-call-%s on (br_netfilter, "
		    "which Docker loads) those frames pass %s, which drops by default: traffic "
		    "between two other machines through this bridge is dropped -- in a ring, the "
		    "failover path. Accept it there (Docker's is `iptables -I DOCKER-USER -i %s "
		    "-o %s -j ACCEPT`), or set net.bridge.bridge-nf-call-iptables to 0; netcfgd "
		    "does not touch other tables",
		    device->name, four ? "iptables" : "ip6tables", ncfg_buf_text(&named),
		    device->name, device->name);
	}
	ncfg_buf_free(&named);
}

void ncfg_plan_input_warnings(ncfg_builder_t *builder)
{
	const ncfg_document_t *desired = builder->desired;
	size_t                 at;

	warn_bridged_filtered(builder);
	warn_forward_replies(builder);
	if (!ncfg_plan_input_drops(desired)) {
		return;
	}
	/* **The one that breaks everything**, said once: with nothing accepting
	 * established replies, the router's own DNS lookups, DHCP renewals and
	 * every connection it opens are answered and the answers dropped. */
	if (!accepts_replies(&desired->firewall->input)) {
		ncfg_plan_warn(builder->plan, NULL,
		    "the firewall's input chain drops by default and accepts no replies, so "
		    "everything this machine asks -- its own DNS, its DHCP renewals, every "
		    "connection it opens -- is answered and the answer dropped. Add `accept "
		    "\"established\" { state = [\"established\", \"related\"] }` to `input`");
	}
	for (at = 0; at < desired->interface_count; at++) {
		const ncfg_interface_t *interface = &desired->interfaces[at];
		const char             *name = interface->name;

		/* A DHCPv6 reply comes from the server's link-local address to 546,
		 * where the request went to a multicast group, so conntrack does not
		 * call it established -- which is why OpenWrt carries a rule for it. */
		if (asks_dhcp6(interface) &&
		    !ncfg_plan_input_accepts(desired, name, NCFG_FIREWALL_PROTO_UDP, 546)) {
			ncfg_plan_warnf(builder->plan, name,
			    "the firewall's input chain drops by default with no rule accepting DHCPv6 "
			    "replies on %s, which conntrack does not see as replies, so the lease and "
			    "any delegated prefix never arrive. Add `accept \"dhcpv6-%s\" { protocol = "
			    "\"udp\"; port = [546]; interface = \"%s\" }` to `input`", name, name, name);
		}
		/* Neighbour discovery and router advertisements are never
		 * established; without them IPv6 on the link stops. */
		if (speaks_ipv6(interface) &&
		    !ncfg_plan_input_accepts(desired, name, NCFG_FIREWALL_PROTO_ICMPV6, -1)) {
			ncfg_plan_warnf(builder->plan, name,
			    "the firewall's input chain drops by default with no rule accepting ICMPv6 "
			    "on %s, so neighbour discovery and router advertisements are dropped and "
			    "IPv6 there stops working. Add `accept \"icmpv6-%s\" { protocol = "
			    "\"icmpv6\"; interface = \"%s\" }` to `input`", name, name, name);
		}
	}
	for (at = 0; at < desired->device_count; at++) {
		const ncfg_device_t *device = &desired->devices[at];
		int64_t              port;

		if (device->kind.kind != NCFG_KIND_WIREGUARD ||
		    !device->kind.wireguard.listen_port.has) {
			continue;
		}
		/* On whichever interface it arrives -- the tunnel's packets come in
		 * over the uplink -- so the rule is not narrowed to one. */
		port = device->kind.wireguard.listen_port.value;
		if (!ncfg_plan_input_accepts(desired, NULL, NCFG_FIREWALL_PROTO_UDP, port)) {
			ncfg_plan_warnf(builder->plan, device->name,
			    "the firewall's input chain drops by default with no rule accepting UDP %lld, "
			    "where %s listens, so a peer that starts the handshake is never answered. "
			    "Add `accept \"wireguard-%s\" { protocol = \"udp\"; port = [%lld] }` to `input`",
			    (long long)port, device->name, device->name, (long long)port);
		}
	}
}
