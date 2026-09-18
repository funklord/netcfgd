/*
 * reported.c -- the addresses and routes something outside netcfgd reported.
 *
 * WHAT A REPORT IS AND WHY THE PLANNER BELIEVES IT
 *   A cellular bearer or a tunnel daemon knows the configuration it
 *   negotiated; netcfgd does not, and is told through a file under
 *   `/run/netcfgd/reported/` (`doc/interface-report.md`). The writer
 *   deliberately installs nothing itself -- two writers on one interface is
 *   the failure this project is arranged around -- so what the report names is
 *   netcfgd's to install, tagged as netcfgd's. Decision 0047.
 *
 *   `ncfg_plan_takes_reports` is the gate, and it is not "there is a file": a
 *   report for an interface the document says nothing about is an observation
 *   with no instruction behind it, and installing a default route off the
 *   strength of a file somebody dropped in `/run` is not something to invent.
 *
 * THE COMPARISON THIS FILE IS REALLY ABOUT
 *   **A report's text never went through the compiler.** Every address in the
 *   document did -- `ncfg_address_canonical` is that step, and `value.h`
 *   records what each spelling cost when it was missing -- but a report is
 *   whatever a shell script printed, and the kernel reports back its own
 *   spelling of whatever was installed. So `0000:0000:...:0001/128` and
 *   `::1/128` are one address here and two to `strcmp`, and comparing them as
 *   text plans an `addr.add` for something the kernel already holds, on every
 *   single run. project.md 10.169 is that defect measured against the shipped
 *   Rust, which compares both halves -- the forward pass and the teardown --
 *   as strings.
 *
 *   **So every comparison in this file goes through the model.** The addresses
 *   through `ncfg_plan_address_equal`; a route's next hop and its destination
 *   are canonicalised as they are synthesised, which is where the Rust does it
 *   for the next hop and does not for the destination (see the port notes).
 *   That is what makes *applying a plan twice produces an empty second plan*
 *   true for an interface whose addresses netcfgd did not choose.
 *
 * ONE LIST, TWO READERS
 *   `ncfg_plan_routes_for` is the document's routes and the report's, in one
 *   function, because the forward pass and the teardown must not be able to
 *   disagree about what the list is. Two answers to "which routes does this
 *   interface want" is a plan that installs a route and deletes it on the next
 *   reconcile, for ever -- the loud failure, and the one worth a function.
 */
#include "plan_internal.h"

#include "ncfg/base.h"
#include "ncfg/value.h"

#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------------ *
 * Whether a report is one netcfgd was told to act on
 * ------------------------------------------------------------------------ */

/*
 * Two ways, and they are the same question asked of different documents.
 *
 * **The addressing list says `reported`**, which is how a modem helper's
 * report is claimed: netcfgd did not start that helper and has no idea it
 * exists, so the operator has to say that the file in `/run` is meant.
 *
 * **Or netcfgd started the writer itself.** A tunnel daemon or a PPPoE session
 * reports through a script netcfgd generated, launched by a process netcfgd
 * started, on an interface the document named -- there is nothing left to opt
 * into. Requiring `config = "reported"` as well would mean a tunnel that
 * silently kept none of its routes until somebody added a word whose absence
 * explained nothing.
 *
 * Not the gate for a *nameserver*, which is narrower still and is `dns.c`'s:
 * netcfgd having started the writer is enough to install a route down that
 * link and deliberately not enough to change where every query on the machine
 * goes (decision 0049).
 *
 * **The kind comes from the device**, which is where this port states it; the
 * Rust asks its own `kind_of`, which answers `Physical` for a name with no
 * device block. Same answer, one lookup.
 */
int ncfg_plan_takes_reports(const ncfg_document_t *desired, const ncfg_interface_t *interface)
{
	const ncfg_device_t *device;
	size_t               i;

	for (i = 0; i < interface->addressing_count; i++) {
		if (interface->addressing[i].kind == NCFG_ADDRESS_SOURCE_REPORTED) {
			return 1;
		}
	}
	device = ncfg_plan_device(desired, interface->name);
	if (!device) {
		return 0;
	}
	return device->kind.kind == NCFG_KIND_OPENVPN || device->kind.kind == NCFG_KIND_PPPOE;
}

const ncfg_observed_report_t *ncfg_plan_report_for(const ncfg_observed_t *observed,
    const char *name)
{
	size_t i;

	if (!name) {
		return NULL;
	}
	for (i = 0; i < observed->report_count; i++) {
		if (observed->reports[i].interface &&
		    strcmp(observed->reports[i].interface, name) == 0) {
			return &observed->reports[i];
		}
	}
	return NULL;
}

int ncfg_plan_reported_holds(const ncfg_observed_t *observed, const char *interface,
    const char *address)
{
	const ncfg_observed_report_t *report = ncfg_plan_report_for(observed, interface);
	size_t                        i;

	if (!report) {
		return 0;
	}
	for (i = 0; i < report->address_count; i++) {
		/* Canonically, which is the whole of 10.169: the report's spelling is
		 * whoever wrote it, and `seen->address` is the kernel's. */
		if (ncfg_plan_address_equal(report->addresses[i], address)) {
			return 1;
		}
	}
	return 0;
}

/* ------------------------------------------------------------------------ *
 * Forward: the addresses a report carries
 * ------------------------------------------------------------------------ */

/*
 * **No report is not an error.** A helper that has not connected yet, or a
 * tunnel still negotiating, leaves nothing to install -- exactly like a
 * delegation that has not arrived. The warning says which, because "no
 * addresses here" has two very different causes and an operator needs to know
 * whether to look at netcfgd or at the thing that reports.
 */
void ncfg_plan_reported(ncfg_builder_t *builder, const ncfg_interface_t *interface, size_t index,
    const ncfg_plan_ids_t *base, ncfg_plan_ids_t *out)
{
	const char                   *name = interface->name;
	const ncfg_observed_report_t *report = ncfg_plan_report_for(builder->observed, name);
	const char                   *field = ncfg_plan_internf(builder->plan, "addressing[%zu]",
	    index);
	size_t                        i;
	size_t                        j;

	if (!report) {
		ncfg_plan_warnf(builder->plan, name,
		    "`%s` takes its addresses from whatever reports them, and nothing has -- "
		    "there is no file at /run/netcfgd/reported/%s. Addresses are planned when a "
		    "report arrives; see doc/interface-report.md",
		    name, name);
		return;
	}
	if (report->address_count == 0u) {
		/* A report with no addresses is a link that is down, and whoever wrote
		 * it said so deliberately. Distinct from the case above, and worth
		 * distinguishing: this one means the reporting side is working and the
		 * network has not given us anything. */
		ncfg_plan_warnf(builder->plan, name,
		    "`%s` is reported with no addresses, so the link is down", name);
		return;
	}

	for (i = 0; i < report->address_count; i++) {
		const char   *address = report->addresses[i];
		ncfg_op_t     op;
		ncfg_op_t     inverse;
		ncfg_reason_t reason;
		uint32_t      id;
		int           held = 0;

		if (!address) {
			continue;
		}
		for (j = 0; j < builder->observed->address_count; j++) {
			const ncfg_observed_address_t *seen = &builder->observed->addresses[j];

			if (seen->interface && strcmp(seen->interface, name) == 0 &&
			    ncfg_plan_address_equal(seen->address, address)) {
				held = 1;
				break;
			}
		}
		if (held) {
			continue;
		}
		memset(&op, 0, sizeof(op));
		op.kind = NCFG_OP_ADDR_ADD;
		op.u.addr_add.iface = name;
		op.u.addr_add.addr = address;
		memset(&inverse, 0, sizeof(inverse));
		inverse.kind = NCFG_OP_ADDR_DEL;
		inverse.u.addr_del.iface = name;
		inverse.u.addr_del.addr = address;
		reason = ncfg_plan_reason_absent(name, field,
		    ncfg_plan_internf(builder->plan, "%s (reported)", address));

		/* Rule 3's second half, as for a static address: an address may go on
		 * a link that is down, so this does not wait for `link.up`. */
		id = ncfg_builder_push(builder, &op, &reason, base->ids, base->count, &inverse);
		if (id == NCFG_PLAN_NO_ACTION) {
			continue;
		}
		ncfg_plan_ids_push(builder->plan, out, id);
		ncfg_plan_note_added(builder, name, address, id);
	}
}

/* ------------------------------------------------------------------------ *
 * The routes a report implies
 * ------------------------------------------------------------------------ */

/*
 * The one word the kernel gives back for a default route in either family.
 *
 * A dump carries no destination for either a v4 or a v6 default route and the
 * observer renders both as `default`. Spelling the v6 one `::/0` here made
 * every comparison against the observation fail in the Rust, so a dual-stack
 * report produced a plan that added `::/0` and deleted `default` on every
 * single reconcile -- for ever, and silently, because each half succeeded.
 *
 * A writable array rather than a literal because `ncfg_route_t.destination` is
 * `char *` and `-Wwrite-strings` makes a literal `const`. Nothing writes to it.
 */
static char route_destination_default[] = "default";

/*
 * `destination` as the kernel would spell it, or 0 for one that is not a
 * destination at all.
 *
 * A bad line is skipped rather than refused, which is the contract's rule for
 * every other malformed value in a report: one bad line does not discard a
 * report that also carried six good ones.
 *
 * **Canonicalised, where the Rust hands the text back unchanged.** See the
 * port notes: a VPN pushing `2001:0DB8:2::/64` is a route the kernel reports
 * as `2001:db8:2::/64`, so the comparison never matches and the route is added
 * on every apply.
 */
static int destination_of(const char *text, char *out, size_t out_size)
{
	ncfg_address_t address;
	const char    *start = text;
	size_t         length;

	if (!text) {
		return 0;
	}
	while (*start == ' ' || *start == '\t' || *start == '\n' || *start == '\r') {
		start++;
	}
	length = strlen(start);
	while (length != 0u && (start[length - 1u] == ' ' || start[length - 1u] == '\t' ||
	    start[length - 1u] == '\n' || start[length - 1u] == '\r')) {
		length--;
	}
	if (length == 0u || length >= out_size) {
		return 0;
	}
	memcpy(out, start, length);
	out[length] = '\0';
	if (strcmp(out, "default") == 0 || strcmp(out, "0.0.0.0/0") == 0 ||
	    strcmp(out, "::/0") == 0) {
		if (out_size < sizeof(route_destination_default)) {
			return 0;
		}
		memcpy(out, route_destination_default, sizeof(route_destination_default));
		return 1;
	}
	/* A destination with no prefix length is not a prefix. The Rust's
	 * `parse_cidr` refuses one by splitting on the slash first, and a route
	 * netcfgd cannot install would otherwise be carried to a netlink refusal
	 * where the operator cannot see which file it came from. */
	if (!ncfg_address_parse(out, &address, NULL, 0) || !address.has_prefix) {
		return 0;
	}
	return ncfg_address_render(&address, out, out_size, NULL, 0);
}

/* A string of this block's own, or NULL with the plan marked. */
static char *own(ncfg_builder_t *builder, const char *text)
{
	size_t size = strlen(text) + 1u;
	char  *copy = malloc(size);

	if (!copy) {
		builder->plan->failed = 1;
		return NULL;
	}
	memcpy(copy, text, size);
	return copy;
}

static ncfg_route_t *room_for(ncfg_builder_t *builder, ncfg_plan_routes_t *out, size_t wanted)
{
	ncfg_route_t *grown = realloc(out->routes, wanted * sizeof(*grown));

	if (!grown) {
		builder->plan->failed = 1;
		return NULL;
	}
	out->routes = grown;
	return grown;
}

/*
 * Every route this interface should have: the document's, then the report's.
 *
 * The report's are **synthesised into `ncfg_route_t` rather than planned
 * separately**, so they go through the same path every other route does: the
 * carrier check that stops a dead link stealing the default route, the metric
 * derived from the interface's preference, ordering rule 4 putting `addr.add`
 * first when the next hop lies in a reported address's subnet, and the
 * teardown that removes what the document no longer asks for. A second route
 * planner would be a second set of those rules to keep in step.
 *
 * The document's entries are shallow copies whose strings are the document's;
 * everything from `owned_from` on carries strings this block allocated, which
 * is what `ncfg_plan_routes_free` gives back. A caller may copy a route by
 * value -- `with_metric` does -- as long as the copy does not outlive the
 * block.
 */
void ncfg_plan_routes_for(ncfg_builder_t *builder, const ncfg_interface_t *interface,
    ncfg_plan_routes_t *out)
{
	const ncfg_observed_report_t *report;
	ncfg_route_t                 *slot;
	size_t                        room;
	size_t                        i;

	memset(out, 0, sizeof(*out));
	if (interface->route_count != 0u) {
		slot = room_for(builder, out, interface->route_count);
		if (!slot) {
			return;
		}
		for (i = 0; i < interface->route_count; i++) {
			slot[i] = interface->routes[i];
		}
		out->count = interface->route_count;
	}
	out->owned_from = out->count;
	if (!ncfg_plan_takes_reports(builder->desired, interface)) {
		return;
	}
	report = ncfg_plan_report_for(builder->observed, interface->name);
	if (!report) {
		return;
	}

	room = out->count + report->gateway_count + report->route_count;
	if (room == out->count) {
		return;
	}
	slot = room_for(builder, out, room);
	if (!slot) {
		return;
	}
	/*
	 * A default route per reported gateway first, then whatever the report
	 * names outright -- the Rust's order, and an order at all because two
	 * routes that differ only in position would otherwise make the plan's
	 * action order depend on nothing.
	 *
	 * A cellular bearer usually names no routes, because it gives a way off
	 * the link rather than a topology; a VPN server routinely pushes a
	 * handful, and decision 0047 makes those netcfgd's to install rather than
	 * the daemon's.
	 */
	for (i = 0; i < report->gateway_count; i++) {
		char canonical[NCFG_ADDRESS_MAX];

		if (!report->gateways[i] ||
		    !ncfg_address_canonical(report->gateways[i], canonical, sizeof(canonical),
		        NULL, 0)) {
			continue;
		}
		memset(&slot[out->count], 0, sizeof(slot[out->count]));
		slot[out->count].destination = own(builder, route_destination_default);
		slot[out->count].via = own(builder, canonical);
		/* A reported gateway is very often outside every address the interface
		 * was given -- a /32 with a next hop elsewhere is the ordinary shape
		 * of a cellular link -- and the kernel refuses such a route without
		 * this. */
		slot[out->count].onlink = 1;
		if (!slot[out->count].destination || !slot[out->count].via) {
			free(slot[out->count].destination);
			free(slot[out->count].via);
			return;
		}
		out->count++;
	}
	for (i = 0; i < report->route_count; i++) {
		char destination[NCFG_ADDRESS_MAX];
		char canonical[NCFG_ADDRESS_MAX];
		int  has_via = 0;

		if (!destination_of(report->routes[i].destination, destination, sizeof(destination))) {
			continue;
		}
		if (report->routes[i].via) {
			if (!ncfg_address_canonical(report->routes[i].via, canonical,
			    sizeof(canonical), NULL, 0)) {
				continue;
			}
			has_via = 1;
		}
		memset(&slot[out->count], 0, sizeof(slot[out->count]));
		slot[out->count].destination = own(builder, destination);
		slot[out->count].via = has_via ? own(builder, canonical) : NULL;
		/* Only where there is a next hop to reach: `onlink` on a route with no
		 * gateway means nothing, and the reason for it where there is one is
		 * the reason above -- what a tunnel or a bearer hands over is
		 * routinely outside every address it also handed over. */
		slot[out->count].onlink = has_via;
		if (!slot[out->count].destination || (has_via && !slot[out->count].via)) {
			free(slot[out->count].destination);
			free(slot[out->count].via);
			return;
		}
		out->count++;
	}
}

void ncfg_plan_routes_free(ncfg_plan_routes_t *routes)
{
	size_t i;

	for (i = routes->owned_from; i < routes->count; i++) {
		free(routes->routes[i].destination);
		free(routes->routes[i].via);
	}
	free(routes->routes);
	routes->routes = NULL;
	routes->count = 0;
	routes->owned_from = 0;
}
