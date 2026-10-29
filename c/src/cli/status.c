/*
 * status.c -- `ncfg status`, which is the output this program is read for.
 *
 * WHY THE SHAPE IS WHAT IT IS
 *   A status listing is read to find out **why something is wrong**, so a line
 *   per feature per interface buries the one that matters. Every per-link
 *   setting below prints only when there is something to say: a radio that
 *   works needs no line about its kill switch, and an interface with no qdisc
 *   of netcfgd's needs no qdisc line. `ncfg explain interface` is the command
 *   that reports a field either way.
 *
 * THE ONE DISTINCTION THE FORMAT EXISTS TO CARRY
 *   `[reported, not applied]`. What something outside netcfgd published about
 *   an interface is shown **as reported**, because it is not applied: netcfgd
 *   reads that file and does nothing with it until an `addressing` source asks
 *   (0044, 0045, `doc/interface-report.md`). An operator who cannot see the
 *   difference between "the bearer is up" and "netcfgd configured the
 *   interface" has no way to tell which half is broken.
 */
#include "ncfg/cli.h"

#include "ncfg/log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/*
 * The word the Rust prints for an ownership, which is the enum's own name.
 *
 * **Not `ncfg_ownership_name`, and the difference is deliberate.** That one
 * gives the JSON spelling -- `ours`, `foreign` -- because that is what goes on
 * the wire. `ncfg status` prints the value with Rust's `Debug`, so what an
 * operator has been reading since M1 is `[Foreign]` with a capital letter, and
 * a port that printed the wire spelling here would have changed the output
 * while every test that reads JSON stayed green.
 */
static const char *ownership_word(int ownership)
{
	switch (ownership) {
	case NCFG_OWNERSHIP_OURS:
		return "Ours";
	case NCFG_OWNERSHIP_FOREIGN:
		return "Foreign";
	case NCFG_OWNERSHIP_UNKNOWN:
		return "Unknown";
	default:
		/* value.h's rule: a plausible word for a value that is not one is
		 * worse than no word. */
		return "?";
	}
}

/* Whether a name is in one of the observation's "netcfgd did this" lists. */
static int listed(char *const *names, size_t count, const char *name)
{
	size_t at;

	for (at = 0; at < count; at++) {
		if (names[at] && strcmp(names[at], name) == 0) {
			return 1;
		}
	}
	return 0;
}

/*
 * The per-link lines that are neither an address nor a VLAN.
 *
 * Split out when the radio line arrived and the function passed what the style
 * allows.
 */
static void print_link_settings(const ncfg_observed_link_t *link,
    const ncfg_observed_t *observed)
{
	size_t at;

	if (link->offload_count > 0) {
		ncfg_out_write("    offloads");
		for (at = 0; at < link->offload_count; at++) {
			ncfg_out_writef(" %s", link->offloads[at]);
		}
		ncfg_out_line("");
	}
	if (link->qdisc) {
		char shaped[96];
		const char *ours = listed(observed->qdisc_applied, observed->qdisc_applied_count,
		    link->name) ? "" : " [kernel default or set elsewhere]";

		shaped[0] = '\0';
		if (link->qdisc_bandwidth_bits.has) {
			const char *inbound = link->qdisc_ingress ? " inbound" : "";

			(void)snprintf(shaped, sizeof(shaped), " at %lld bit/s%s",
			    (long long)link->qdisc_bandwidth_bits.value, inbound);
		}
		ncfg_out_writef("    qdisc %s%s%s\n", link->qdisc, shaped, ours);
	}
	if (link->ingress_redirect) {
		ncfg_out_writef("    ingress redirected to %s\n", link->ingress_redirect);
	}
	if (listed(observed->nat, observed->nat_count, link->name)) {
		ncfg_out_line("    masquerade");
	}
	if (link->forwarding.has && link->forwarding.value) {
		ncfg_out_line("    forwarding");
	}
	/*
	 * Only when it is off. A radio that works needs no line, and an operator
	 * scanning this list is looking for the reason something does not work.
	 */
	if (link->rfkill && ncfg_rfkill_blocked(link->rfkill)) {
		const char *which = link->rfkill->hard ? "hardware" : "software";

		ncfg_out_writef("    radio off [%s block at %s]\n", which,
		    link->rfkill->switch_ ? link->rfkill->switch_ : "");
	}
}

/*
 * The Bluetooth adapters, which are not links and so are not in the walk above.
 *
 * **The observation has carried these all along and nothing showed them.**
 * `observed.json` holds them -- `tests/live/bluetooth.sh` asserts that and
 * always passed -- while `ncfg status` listed links only, so the check beside
 * it, "netcfgd reports the adapter it can see", had never passed for either
 * implementation. A reader with no adapter in the output cannot tell an absent
 * adapter from an unreported one.
 *
 * Its own section because an adapter is its own thing: `observed.h` says why it
 * is not a link -- no address, no mtu, no place in netlink -- and a PAN
 * connection through it produces a `bnep0` that IS a link and appears above
 * with no special case.
 *
 * Nothing at all where there are none, which is section 4.6's rule for the run
 * directory applied to the output: what is shown reflects use rather than
 * capability, and a machine with no Bluetooth should not gain a heading saying
 * so.
 *
 * The switch is spelled the way a link's is, deliberately -- the same words in
 * the same shape, because it is the same question about a different radio.
 */
static void print_bluetooth(const ncfg_observed_t *observed)
{
	size_t at;

	for (at = 0; at < observed->bluetooth_count; at++) {
		const ncfg_observed_bluetooth_t *adapter = &observed->bluetooth[at];

		if (!adapter->name) {
			continue;
		}
		ncfg_out_writef("%s bluetooth\n", adapter->name);
		if (adapter->rfkill && ncfg_rfkill_blocked(adapter->rfkill)) {
			const char *which = adapter->rfkill->hard ? "hardware" : "software";

			ncfg_out_writef("    radio off [%s block at %s]\n", which,
			    adapter->rfkill->switch_ ? adapter->rfkill->switch_ : "");
		}
	}
}

/*
 * What each linkset settled on, and why each loser lost.
 *
 * **The losers are the point.** "This machine is on the modem" is visible from
 * the routing table; "because the cable has no carrier and the office wifi is
 * out of range" is not visible anywhere else, and it is the whole of what
 * somebody asking "why am I on the modem" wants.
 */
/*
 * The firewall netcfgd's table holds, as rules (0295, 10.592): what the holder
 * asked `ncfg status` to show. One line per kernel rule, in the order they
 * run, so a written rule with several values reads as the several rules it
 * became; a rule netcfgd could not read is named with the reason, because it
 * is somebody's edit inside netcfgd's table and the next apply replaces it.
 */
static void print_firewall(const ncfg_observed_t *observed)
{
	static const char *const chains[3] = { "input", "forward", "output" };
	const ncfg_observed_firewall_t *firewall = observed->firewall;
	const char                     *policies[3];
	size_t                          c;
	size_t                          at;

	if (!firewall) {
		return;
	}
	policies[0] = firewall->input;
	policies[1] = firewall->forward;
	policies[2] = firewall->output;
	ncfg_out_line("");
	ncfg_out_line("firewall (netcfgd's nftables table)");
	for (c = 0; c < 3u; c++) {
		ncfg_out_writef("  %s: policy %s\n", chains[c], policies[c] ? policies[c] : "absent");
		for (at = 0; at < firewall->rule_count; at++) {
			const ncfg_observed_firewall_rule_t *rule = &firewall->rules[at];
			size_t                               state;

			if (strcmp(rule->chain, chains[c]) != 0) {
				continue;
			}
			ncfg_out_writef("    %s %s", rule->action, rule->name);
			if (rule->protocol && strcmp(rule->protocol, "any") != 0) {
				ncfg_out_writef(" protocol %s", rule->protocol);
			}
			if (rule->port.has) {
				ncfg_out_writef(" port %lld", (long long)rule->port.value);
			}
			if (rule->from) {
				ncfg_out_writef(" from %s", rule->from);
			}
			if (rule->to) {
				ncfg_out_writef(" to %s", rule->to);
			}
			if (rule->interface) {
				ncfg_out_writef(" interface %s", rule->interface);
			}
			for (state = 0; state < rule->state_count; state++) {
				ncfg_out_writef("%s%s", state ? "," : " state ", rule->states[state]);
			}
			if (rule->mac) {
				ncfg_out_writef(" mac %s", rule->mac);
			}
			ncfg_out_line("");
		}
	}
	for (at = 0; at < firewall->unread_count; at++) {
		ncfg_out_writef("  not netcfgd's as written: %s\n", firewall->unread[at]);
	}
}

static void print_linksets(const ncfg_observed_t *observed)
{
	size_t set;

	for (set = 0; set < observed->linkset_count; set++) {
		const ncfg_chosen_t *chosen = &observed->linksets[set];
		size_t member;

		ncfg_out_line("");
		if (chosen->active) {
			const char *on = "";
			char where[128];

			where[0] = '\0';
			if (chosen->interface && strcmp(chosen->interface, chosen->active) != 0) {
				(void)snprintf(where, sizeof(where), " on %s", chosen->interface);
				on = where;
			}
			ncfg_out_writef("linkset %s using %s%s\n", chosen->name, chosen->active, on);
		} else {
			ncfg_out_writef("linkset %s using nothing\n", chosen->name);
		}
		for (member = 0; member < chosen->member_count; member++) {
			const ncfg_standing_t *standing = &chosen->members[member];
			const char *why = "ready";

			/* The winner is named above; what each line adds is the standing
			 * of the ones that are not carrying anything. */
			if (chosen->active && standing->name &&
			    strcmp(chosen->active, standing->name) == 0) {
				continue;
			}
			if (standing->ineligible.has) {
				const char *named = ncfg_ineligible_name((int)standing->ineligible.value);

				why = named ? named : "?";
			}
			ncfg_out_writef("    %s [%s]\n", standing->name, why);
		}
	}
}

/* What something outside netcfgd published about this interface. */
static void print_report(const ncfg_observed_t *observed, const char *name)
{
	size_t at;

	for (at = 0; at < observed->report_count; at++) {
		const ncfg_observed_report_t *report = &observed->reports[at];
		size_t one;

		if (!report->interface || strcmp(report->interface, name) != 0) {
			continue;
		}
		for (one = 0; one < report->address_count; one++) {
			ncfg_out_writef("    %s [reported, not applied]\n", report->addresses[one]);
		}
		for (one = 0; one < report->gateway_count; one++) {
			ncfg_out_writef("    via %s [reported, not applied]\n",
			    report->gateways[one]);
		}
		if (report->nameserver_count > 0) {
			ncfg_out_write("    nameservers");
			for (one = 0; one < report->nameserver_count; one++) {
				ncfg_out_writef(" %s", report->nameservers[one]);
			}
			ncfg_out_line(" [reported, not applied]");
		}
		/* The Rust takes the first report for an interface and stops; a
		 * second one for the same name would be the writer's fault, and
		 * printing both would make one bearer look like two. */
		return;
	}
}

/*
 * A card's physical ports, and what each is running as.
 *
 * Said because one in InfiniBand mode has no Ethernet interface, and a
 * configuration naming one meets an interface that is not there with nothing
 * else on this screen saying why (project.md 10.586). A port running as
 * Ethernet names the interface it became; one running as InfiniBand says so,
 * names its RDMA device, and gives the command that switches it -- devlink's,
 * the vendor-neutral one, which lasts until the driver reloads.
 *
 * Nothing where devlink describes no physical port, which is most laptops.
 */
static void print_ports(const ncfg_observed_t *observed)
{
	size_t at;

	if (observed->port_count == 0) {
		return;
	}
	ncfg_out_line("");
	ncfg_out_line("card ports:");
	for (at = 0; at < observed->port_count; at++) {
		const ncfg_observed_port_t *port = &observed->ports[at];
		const char                 *device = port->device ? port->device : "?";
		const char                 *type = port->type ? port->type : "?";

		if (strcmp(type, "eth") == 0) {
			ncfg_out_writef("  %s port %lld: Ethernet, %s\n", device, (long long)port->index,
			    port->interface ? port->interface : "no interface yet");
		} else if (strcmp(type, "ib") == 0) {
			ncfg_out_writef("  %s port %lld: InfiniBand%s%s, so no Ethernet interface\n",
			    device, (long long)port->index, port->rdma ? ", " : "",
			    port->rdma ? port->rdma : "");
			ncfg_out_writef("    `devlink port set %s/%lld type eth` switches it until the "
			    "driver reloads\n", device, (long long)port->index);
		} else {
			ncfg_out_writef("  %s port %lld: %s\n", device, (long long)port->index,
			    strcmp(type, "auto") == 0 ? "chooses its type from what it is plugged into" :
			    "no type set yet");
		}
	}
}

/*
 * Who set it, in words, where a daemon heard. NULL for a word this build does
 * not know, which prints nothing rather than the raw word.
 *
 * `user` gets its three usual sources named, because the kernel cannot tell
 * them apart and "user" alone reads as "you", when the commonest one on a
 * machine netcfgd manages is netcfgd's own `global { regdom }`.
 */
static const char *regdom_setter_text(const char *set_by)
{
	if (strcmp(set_by, "access_point") == 0) {
		return "the access point this machine is associated to";
	}
	if (strcmp(set_by, "user") == 0) {
		return "user space -- global { regdom }, iw reg set, or an access point run here";
	}
	if (strcmp(set_by, "driver") == 0) {
		return "the wireless card's driver";
	}
	if (strcmp(set_by, "kernel") == 0) {
		return "the kernel's own default";
	}
	return NULL;
}

/*
 * The wireless regulatory domain the observation read.
 *
 * Decision 0296 is why it is said: project.md 10.585 measured that a country
 * set by hand strands a machine in that country's gaps and that the world
 * domain has no 6 GHz, and either way the network is simply not there. This
 * line is what makes that something to act on. The world domain gets the
 * consequence spelled out, since `00` alone says nothing to most people.
 *
 * Nothing where the observation has none -- no radio, or a kernel that would
 * not say -- by `print_bluetooth`'s rule; the observer has already left a note
 * where it could not ask.
 *
 * Who set it follows where a daemon heard the change (`regdom_set_by`), which
 * is what tells a country adopted from an access point from one set by hand
 * -- the two look identical otherwise, and only one of them moves with the
 * machine.
 */
static void print_regdom(const ncfg_observed_t *observed)
{
	const char *setter = observed->regdom_set_by ?
	    regdom_setter_text(observed->regdom_set_by) : NULL;

	if (!observed->regdom) {
		return;
	}
	ncfg_out_line("");
	if (strcmp(observed->regdom, "00") == 0) {
		ncfg_out_line("wireless regulatory domain: 00, the world domain. No country is set,");
		ncfg_out_line("so 6 GHz is off and some channels only listen until a network says");
		ncfg_out_line("where this machine is.");
		if (setter) {
			ncfg_out_writef("set by %s.\n", setter);
		}
		return;
	}
	if (setter) {
		ncfg_out_writef("wireless regulatory domain: %s, set by %s\n", observed->regdom,
		    setter);
		return;
	}
	ncfg_out_writef("wireless regulatory domain: %s\n", observed->regdom);
}

void ncfg_cli_take_regdom_setter(ncfg_observed_t *mine, const ncfg_observed_t *theirs)
{
	if (!mine || !theirs || !mine->regdom || mine->regdom_set_by || !theirs->regdom ||
	    !theirs->regdom_set_by || strcmp(mine->regdom, theirs->regdom) != 0) {
		return;
	}
	mine->regdom_set_by = strdup(theirs->regdom_set_by);
}

void ncfg_cli_print_status(const ncfg_observed_t *observed)
{
	size_t at;

	if (!observed) {
		return;
	}
	for (at = 0; at < observed->link_count; at++) {
		const ncfg_observed_link_t *link = &observed->links[at];
		const char *state = link->up ? "up" : "down";
		const char *carrier = link->carrier ? "" : ", no carrier";
		size_t one;

		ncfg_out_writef("%s %s%s mtu %lld\n", link->name, state, carrier,
		    (long long)link->mtu);
		for (one = 0; one < observed->address_count; one++) {
			const ncfg_observed_address_t *address = &observed->addresses[one];

			if (!address->interface || strcmp(address->interface, link->name) != 0) {
				continue;
			}
			ncfg_out_writef("    %s [%s]\n", address->address,
			    ownership_word(address->ownership));
		}
		for (one = 0; one < observed->bridge_vlan_count; one++) {
			const ncfg_observed_bridge_vlan_t *vlan = &observed->bridge_vlans[one];
			const char *flags;

			if (vlan->index != link->index) {
				continue;
			}
			if (vlan->pvid && vlan->untagged) {
				flags = " pvid untagged";
			} else if (vlan->pvid) {
				flags = " pvid";
			} else if (vlan->untagged) {
				flags = " untagged";
			} else {
				flags = "";
			}
			ncfg_out_writef("    vlan %lld%s\n", (long long)vlan->vid, flags);
		}
		print_link_settings(link, observed);
		print_report(observed, link->name);
		for (one = 0; one < observed->route_count; one++) {
			const ncfg_observed_route_t *route = &observed->routes[one];
			char via[128];

			if (!route->interface || strcmp(route->interface, link->name) != 0) {
				continue;
			}
			via[0] = '\0';
			if (route->via) {
				(void)snprintf(via, sizeof(via), " via %s", route->via);
			}
			ncfg_out_writef("    route %s%s [%s]\n", route->destination, via,
			    ownership_word(route->ownership));
		}
	}
	print_bluetooth(observed);
	print_ports(observed);
	print_regdom(observed);
	print_linksets(observed);
	print_firewall(observed);
	/*
	 * Printed once rather than per interface: the conflict is with a table,
	 * not with a device, and repeating it under every link would make one
	 * problem look like several.
	 */
	if (observed->nat_conflict_count > 0) {
		ncfg_out_line("");
		ncfg_out_write("note: nftables table(s) `");
		for (at = 0; at < observed->nat_conflict_count; at++) {
			if (at > 0) {
				ncfg_out_write("`, `");
			}
			ncfg_out_write(observed->nat_conflicts[at]);
		}
		ncfg_out_line("` also translate source addresses. netcfgd does not touch "
		    "tables it did not create, so this is a report, not something it will "
		    "resolve.");
	}
	if (!observed->address_proto_supported) {
		ncfg_out_line("");
		ncfg_out_line("note: no address carries a protocol tag yet, so address ownership "
		    "comes from recorded state and is weaker. It strengthens once netcfgd "
		    "installs its first address.");
	}
}

/*
 * Whether the machine is online, in the sense `network-online.target` means.
 *
 * The cheap half first: a machine with no default route cannot be online
 * however many addresses it has, and the address walk is the longer of the
 * two.
 */
int ncfg_cli_is_online(const ncfg_observed_t *observed)
{
	int routed = 0;
	size_t at;

	if (!observed) {
		return 0;
	}
	for (at = 0; at < observed->route_count; at++) {
		if (observed->routes[at].destination &&
		    strcmp(observed->routes[at].destination, "default") == 0) {
			routed = 1;
			break;
		}
	}
	if (!routed) {
		return 0;
	}
	for (at = 0; at < observed->address_count; at++) {
		const ncfg_observed_address_t *address = &observed->addresses[at];

		if (!address->interface || !address->address) {
			continue;
		}
		if (strcmp(address->interface, "lo") == 0) {
			continue;
		}
		/* **A link-local address is what a machine has when DHCP did not
		 * answer**, which is the state this is most needed to distinguish. */
		if (strncmp(address->address, "169.254.", 8) == 0) {
			continue;
		}
		if (strncasecmp(address->address, "fe80:", 5) == 0) {
			continue;
		}
		return 1;
	}
	return 0;
}
