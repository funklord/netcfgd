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
 *   never opened, as 0298 does for a forward (project.md 10.620).
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
		int                         named = rule->port_count == 0u;

		if (rule->action != NCFG_FIREWALL_ACCEPT ||
		    (rule->protocol != NCFG_FIREWALL_PROTO_ANY && rule->protocol != protocol) ||
		    (rule->interface && iface && strcmp(rule->interface, iface) != 0) ||
		    !names_state(rule, "new")) {
			continue;
		}
		for (p = 0; port >= 0 && p < rule->port_count; p++) {
			named = named || rule->ports[p] == port;
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

void ncfg_plan_input_warnings(ncfg_builder_t *builder)
{
	const ncfg_document_t *desired = builder->desired;
	size_t                 at;

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
