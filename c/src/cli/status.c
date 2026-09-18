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
 * What each linkset settled on, and why each loser lost.
 *
 * **The losers are the point.** "This machine is on the modem" is visible from
 * the routing table; "because the cable has no carrier and the office wifi is
 * out of range" is not visible anywhere else, and it is the whole of what
 * somebody asking "why am I on the modem" wants.
 */
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
	print_linksets(observed);
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
