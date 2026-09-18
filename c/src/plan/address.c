/*
 * address.c -- addresses and routes, in both directions.
 *
 * THE ORDERING RULE THIS FILE OWNS
 *   **Addresses go in before the routes that need them, and not before
 *   anything else.** Rule 3's second half says an address may be added to a
 *   link that is down, so `addr.add` does not wait for `link.up`; a route on a
 *   down link is rejected by the kernel, so `route.add` does. Rule 4 says a
 *   route whose next hop lies inside an address's subnet waits for that
 *   address, and a route marked `onlink` is exempt -- which is what `onlink`
 *   means. A gateway outside every configured subnet gets no edge at all,
 *   because serialising work that need not be serialised is a cost with no
 *   payoff.
 *
 * THE OWNERSHIP GUARD
 *   Nothing foreign is ever removed. `ncfg_ownership_may_remove` is the single
 *   place that is decided (decision 0002) and both teardown passes ask it
 *   first. An address whose ownership the kernel could not report is treated
 *   as foreign: on a pre-5.18 kernel that is most of them, and deleting on a
 *   guess is the one mistake that cannot be walked back.
 *
 *   Rule 7 is the second half of the same idea: a lease's address belongs to
 *   the backend that holds it, so only what config put here comes out here.
 *   Removing a lease would fight the DHCP client for it.
 */
#include "plan_internal.h"

#include "ncfg/base.h"
#include "ncfg/value.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------------ *
 * The address arithmetic ordering rule 4 needs, and nothing more
 * ------------------------------------------------------------------------ */

/* Whether two addresses agree on their first `prefix` bits. */
static int same_prefix(const unsigned char *left, const unsigned char *right, unsigned prefix)
{
	unsigned      whole = prefix / 8u;
	unsigned      remainder = prefix % 8u;
	unsigned char mask;

	if (whole != 0u && memcmp(left, right, whole) != 0) {
		return 0;
	}
	if (remainder == 0u) {
		return 1;
	}
	/* A prefix of 0 bits would shift by 8 and overflow, which is why the
	 * remainder of zero returns above rather than falling through. */
	mask = (unsigned char)(0xffu << (8u - remainder));
	return (left[whole] & mask) == (right[whole] & mask);
}

int ncfg_plan_subnet_contains(const char *network_cidr, const char *candidate)
{
	ncfg_address_t network;
	ncfg_address_t other;

	if (!network_cidr || !candidate) {
		return 0;
	}
	if (!ncfg_address_parse(network_cidr, &network, NULL, 0) ||
	    !ncfg_address_parse(candidate, &other, NULL, 0)) {
		return 0;
	}
	if (!network.has_prefix) {
		return 0;
	}
	/* Different families never cover each other. */
	if (network.is_ipv6 != other.is_ipv6) {
		return 0;
	}
	return same_prefix(network.bytes, other.bytes, network.prefix);
}

/* ------------------------------------------------------------------------ *
 * Comparisons
 * ------------------------------------------------------------------------ */

static int text_equal(const char *left, const char *right)
{
	if (!left || !right) {
		return left == right;
	}
	return strcmp(left, right) == 0;
}

/*
 * Whether two addresses are the same address.
 *
 * **The way the model compares, never the way the text reads.** An address
 * this planner derives is rendered by `value.h` and the kernel prints its own
 * spelling of whatever was installed, and the two agree -- but agreeing by
 * construction is not the same as being compared, and 10.169 is what that
 * costs: one address written twice reads as two, and the plan installs it
 * again on every run. Text equality is the answer only where neither side
 * parses, which is where there is nothing better to say.
 */
int ncfg_plan_address_equal(const char *left, const char *right)
{
	char first[NCFG_ADDRESS_MAX];
	char second[NCFG_ADDRESS_MAX];

	if (!left || !right) {
		return left == right;
	}
	if (!ncfg_address_canonical(left, first, sizeof(first), NULL, 0) ||
	    !ncfg_address_canonical(right, second, sizeof(second), NULL, 0)) {
		return strcmp(left, right) == 0;
	}
	return strcmp(first, second) == 0;
}

/*
 * Whether a desired route is the one the kernel already holds.
 *
 * The table defaults on both sides, because a document that says nothing and a
 * kernel that reports 254 are describing the same route. The metric is
 * compared only where the document states one: a route with no metric is
 * asking for whatever it was given.
 */
int ncfg_plan_route_matches(const ncfg_route_t *desired, const ncfg_observed_route_t *observed)
{
	int64_t desired_table = desired->table.has ? desired->table.value : NCFG_ROUTE_MAIN_TABLE;
	int64_t observed_table = observed->table.has ? observed->table.value :
	    NCFG_ROUTE_MAIN_TABLE;

	return text_equal(desired->destination, observed->destination) &&
	    text_equal(desired->via, observed->via) && desired_table == observed_table &&
	    text_equal(desired->src, observed->src) &&
	    (!desired->metric.has ||
	        (observed->metric.has && desired->metric.value == observed->metric.value));
}

const char *ncfg_plan_render_route(ncfg_plan_t *plan, const ncfg_route_t *route)
{
	char   text[NCFG_ERROR_MAX];
	size_t at = 0;
	int    wrote;

	wrote = snprintf(text, sizeof(text), "%s", route->destination ? route->destination : "");
	at = wrote > 0 ? (size_t)wrote : 0u;
	if (route->via && at < sizeof(text)) {
		wrote = snprintf(text + at, sizeof(text) - at, " via %s", route->via);
		at += wrote > 0 ? (size_t)wrote : 0u;
	}
	if (route->metric.has && at < sizeof(text)) {
		(void)snprintf(text + at, sizeof(text) - at, " metric %lld",
		    (long long)route->metric.value);
	}
	return ncfg_plan_intern(plan, text);
}

/*
 * A route with the interface's preference filled in as its metric.
 *
 * Resolved here rather than at compile time so the document stays a literal
 * reading of the config -- `ncfg show` reports what was written, and the plan
 * reports what it means. **It also has to happen in exactly one place**,
 * because the comparison that decides "is this route already present" uses the
 * metric and would loop forever against a value computed differently on each
 * side. This build has one answer, `interface->preference`, in both
 * directions; see the port notes for where the Rust has two.
 */
static ncfg_route_t with_metric(const ncfg_route_t *route, const ncfg_interface_t *interface)
{
	ncfg_route_t copy = *route;

	if (!copy.metric.has && interface->preference.has) {
		copy.metric = interface->preference;
	}
	return copy;
}

/* ------------------------------------------------------------------------ *
 * Forward: addresses
 * ------------------------------------------------------------------------ */

void ncfg_plan_source(ncfg_builder_t *builder, const ncfg_interface_t *interface, size_t index,
    const ncfg_plan_ids_t *base, ncfg_plan_ids_t *out)
{
	const ncfg_address_source_t *source = &interface->addressing[index];
	const char                  *address;
	ncfg_op_t                    op;
	ncfg_op_t                    inverse;
	ncfg_reason_t                reason;
	uint32_t                     id;
	size_t                       i;

	/*
	 * Four sources are planned from here and each goes where its work is.
	 *
	 * SLAAC is deliberately not one of them and is not a gap either: given a
	 * router advertisement the kernel builds the address itself, so there is
	 * no addressing action to plan. What netcfgd owns there is two sysctls,
	 * and they are properties of the interface rather than of this source --
	 * `sysctl.c` writes both. Every source still not planned is named by
	 * `warn_unported`, with the block it is about, so a plan from this build
	 * is never quieter than the configuration it was given.
	 */
	switch (source->kind) {
	case NCFG_ADDRESS_SOURCE_STATIC:
		break;
	case NCFG_ADDRESS_SOURCE_DHCP4:
		ncfg_plan_backend(builder, interface->name, NCFG_BACKEND_DHCP4,
		    ncfg_plan_internf(builder->plan, "addressing[%zu]", index), base, out);
		return;
	case NCFG_ADDRESS_SOURCE_DHCP6:
		ncfg_plan_backend(builder, interface->name, NCFG_BACKEND_DHCP6,
		    ncfg_plan_internf(builder->plan, "addressing[%zu]", index), base, out);
		return;
	case NCFG_ADDRESS_SOURCE_DELEGATED:
		ncfg_plan_delegated(builder, interface, index, base, out);
		return;
	case NCFG_ADDRESS_SOURCE_REPORTED:
		ncfg_plan_reported(builder, interface, index, base, out);
		return;
	default:
		return;
	}
	address = source->static_address.address;
	if (!address) {
		return;
	}
	for (i = 0; i < builder->observed->address_count; i++) {
		const ncfg_observed_address_t *seen = &builder->observed->addresses[i];

		if (text_equal(seen->interface, interface->name) &&
		    text_equal(seen->address, address)) {
			return;
		}
	}

	memset(&op, 0, sizeof(op));
	op.kind = NCFG_OP_ADDR_ADD;
	op.u.addr_add.iface = interface->name;
	op.u.addr_add.addr = address;
	op.u.addr_add.preferred_lifetime = source->static_address.preferred_lifetime;
	op.u.addr_add.valid_lifetime = source->static_address.valid_lifetime;
	memset(&inverse, 0, sizeof(inverse));
	inverse.kind = NCFG_OP_ADDR_DEL;
	inverse.u.addr_del.iface = interface->name;
	inverse.u.addr_del.addr = address;
	reason = ncfg_plan_reason_absent(interface->name,
	    ncfg_plan_internf(builder->plan, "addressing[%zu]", index), address);

	/* Rule 3, second half: addresses may be added to a link that is down, so
	 * this does not wait for `link.up`. */
	id = ncfg_builder_push(builder, &op, &reason, base->ids, base->count, &inverse);
	if (id == NCFG_PLAN_NO_ACTION) {
		return;
	}
	ncfg_plan_ids_push(builder->plan, out, id);
	ncfg_plan_note_added(builder, interface->name, address, id);
}

/*
 * Record an `addr.add` so ordering rule 4 can find it.
 *
 * Its own function because there are two callers -- a static address and one
 * derived from a delegation -- and a route waiting for the address that covers
 * its gateway has no business knowing which of the two put it there.
 */
void ncfg_plan_note_added(ncfg_builder_t *builder, const char *interface, const char *address,
    uint32_t id)
{
	ncfg_plan_added_t *grown = realloc(builder->added,
	    (builder->added_count + 1u) * sizeof(*builder->added));

	if (!grown) {
		builder->plan->failed = 1;
		return;
	}
	builder->added = grown;
	grown[builder->added_count].interface = interface;
	grown[builder->added_count].address = address;
	grown[builder->added_count].id = id;
	builder->added_count++;
}

/* ------------------------------------------------------------------------ *
 * Forward: routes
 * ------------------------------------------------------------------------ */

void ncfg_plan_route(ncfg_builder_t *builder, const ncfg_interface_t *interface,
    const ncfg_route_t *route, const ncfg_plan_ids_t *base)
{
	const ncfg_observed_link_t *link = ncfg_observed_link(builder->observed,
	    interface->name);
	ncfg_route_t                wanted = with_metric(route, interface);
	ncfg_plan_ids_t             deps = { NULL, 0, 0 };
	ncfg_op_t                   op;
	ncfg_op_t                   inverse;
	ncfg_reason_t               reason;
	uint32_t                    up;
	size_t                      i;

	/*
	 * **A linkset is using something else, so this link is a spare.** The
	 * set's whole meaning is that one member carries traffic at a time, and a
	 * spare that keeps a default route at a worse metric is not a spare -- it
	 * is a second path the kernel falls back to without anything having
	 * decided that it works. Being in a set is the opt-in here, exactly as
	 * `preference` is for the two rules below.
	 */
	if (ncfg_plan_standby_of(builder, interface->name, NULL, NULL)) {
		ncfg_plan_standby_warn(builder, interface->name);
		return;
	}
	/*
	 * A route down a cable that is not plugged in is a black hole, and a lower
	 * metric would make the kernel prefer it over the wifi that works. So an
	 * interface with a preference does not get its routes while it has no
	 * carrier. Without a preference nothing here applies: a server with one
	 * uplink keeps its routes through a flap.
	 *
	 * An interface this plan is creating counts as having carrier: a veth or a
	 * bridge that does not exist yet reports nothing, and refusing its routes
	 * on that basis would mean they never landed on the first apply.
	 */
	if (interface->preference.has && link && !link->carrier) {
		ncfg_plan_warnf(builder->plan, interface->name,
		    "no carrier, so %s's routes are not installed", interface->name);
		return;
	}
	/*
	 * And the same answer for a link that has carrier and no path. A cable
	 * into a switch that has lost its own uplink looks identical to a working
	 * one from here, so the probe is what tells them apart (0119).
	 *
	 * Only an explicit `false` withholds. Absent is "nobody asked" or "no
	 * answer yet", and treating that as unreachable would take the network
	 * away from every interface on a machine that configured no probes.
	 */
	if (interface->preference.has && link && link->reachable.has && !link->reachable.value) {
		ncfg_plan_warnf(builder->plan, interface->name,
		    "%s's probe says it is not reaching anything, so its routes are not "
		    "installed",
		    interface->name);
		return;
	}
	for (i = 0; i < builder->observed->route_count; i++) {
		const ncfg_observed_route_t *seen = &builder->observed->routes[i];

		if (text_equal(seen->interface, interface->name) &&
		    ncfg_plan_route_matches(&wanted, seen)) {
			return;
		}
	}

	ncfg_plan_ids_extend(builder->plan, &deps, base);
	/* Not one of the eight rules, and stated here because it is an addition to
	 * them: a route on a down link is rejected by the kernel, so `route.add`
	 * waits for `link.up` even though `addr.add` does not. */
	up = ncfg_builder_link_up(builder, interface->name);
	if (up != NCFG_PLAN_NO_ACTION) {
		ncfg_plan_ids_push(builder->plan, &deps, up);
	}
	/* Rule 4: a route whose next hop lies in an address's subnet waits for
	 * that address. An onlink route is exempt, which is what onlink means. */
	if (!wanted.onlink && wanted.via) {
		for (i = 0; i < builder->added_count; i++) {
			if (!text_equal(builder->added[i].interface, interface->name)) {
				continue;
			}
			if (ncfg_plan_subnet_contains(builder->added[i].address, wanted.via)) {
				ncfg_plan_ids_push(builder->plan, &deps, builder->added[i].id);
			}
		}
	}

	memset(&op, 0, sizeof(op));
	op.kind = NCFG_OP_ROUTE_ADD;
	op.u.route.iface = interface->name;
	op.u.route.route = &wanted;
	memset(&inverse, 0, sizeof(inverse));
	inverse.kind = NCFG_OP_ROUTE_DEL;
	inverse.u.route.iface = interface->name;
	inverse.u.route.route = &wanted;
	reason = ncfg_plan_reason_absent(interface->name, "routes",
	    ncfg_plan_render_route(builder->plan, &wanted));
	(void)ncfg_builder_push(builder, &op, &reason, deps.ids, deps.count, &inverse);
	ncfg_plan_ids_free(&deps);
}

/* ------------------------------------------------------------------------ *
 * Teardown
 * ------------------------------------------------------------------------ */

static void teardown_routes(ncfg_builder_t *builder)
{
	size_t i;
	size_t j;

	for (i = 0; i < builder->observed->route_count; i++) {
		const ncfg_observed_route_t *seen = &builder->observed->routes[i];
		const ncfg_interface_t      *interface;
		const ncfg_observed_link_t  *link;
		ncfg_route_t                 model;
		ncfg_op_t                    op;
		ncfg_op_t                    inverse;
		ncfg_reason_t                reason;
		int                          wanted = 0;

		if (!ncfg_ownership_may_remove(seen->ownership)) {
			continue;
		}
		/*
		 * Only routes this build put there from config are removed. A route a
		 * DHCP client installed is the backend's to withdraw, and removing it
		 * here would fight the lease.
		 */
		if (!seen->origin.has || seen->origin.value != NCFG_ORIGIN_STATIC) {
			continue;
		}
		interface = ncfg_plan_interface(builder->desired, seen->interface);
		if (interface) {
			link = ncfg_observed_link(builder->observed, interface->name);
			/*
			 * A route on an interface that has lost carrier stops being
			 * wanted, which is what makes the switch happen: removing it is
			 * how the kernel starts using the other interface instead of
			 * black-holing traffic down this one. And one whose probe says it
			 * reaches nothing is the same black hole with the cable plugged
			 * in -- 0119 states both halves, and only the withholding half was
			 * ever written, so a route added before the probe first answered
			 * stayed installed for ever.
			 */
			if (interface->preference.has && link && !link->carrier) {
				wanted = 0;
			} else if (interface->preference.has && link && link->reachable.has &&
			    !link->reachable.value) {
				wanted = 0;
			} else if (ncfg_plan_standby_of(builder, interface->name, NULL, NULL)) {
				/*
				 * A linkset is using something else, so this link's routes
				 * stop being wanted -- the same sentence `ncfg_plan_route`
				 * says about adding them, and the half that makes a set
				 * actually switch over: withholding alone leaves the route
				 * that was installed before the set changed its mind.
				 */
				wanted = 0;
			} else {
				/*
				 * **The report's routes count as wanted alongside the
				 * document's**, and through the same function the forward pass
				 * uses: the document names a source and the value comes from
				 * the report, so a check that read only `interface->routes`
				 * would delete the default route the same plan had just added,
				 * on every reconcile, for ever.
				 *
				 * And when the bearer drops, the report stops naming the
				 * gateway, this stops being true, and the route goes -- the
				 * same withdrawal the address gets, for the same reason.
				 */
				ncfg_plan_routes_t routes;

				ncfg_plan_routes_for(builder, interface, &routes);
				for (j = 0; j < routes.count; j++) {
					ncfg_route_t candidate =
					    with_metric(&routes.routes[j], interface);

					if (ncfg_plan_route_matches(&candidate, seen)) {
						wanted = 1;
						break;
					}
				}
				ncfg_plan_routes_free(&routes);
			}
		}
		if (wanted) {
			continue;
		}
		memset(&model, 0, sizeof(model));
		model.destination = seen->destination;
		model.via = seen->via;
		model.metric = seen->metric;
		model.table = seen->table;
		model.src = seen->src;
		model.scope = seen->scope;
		model.onlink = 0;
		model.proto = seen->proto;

		memset(&op, 0, sizeof(op));
		op.kind = NCFG_OP_ROUTE_DEL;
		op.u.route.iface = seen->interface;
		op.u.route.route = &model;
		memset(&inverse, 0, sizeof(inverse));
		inverse.kind = NCFG_OP_ROUTE_ADD;
		inverse.u.route.iface = seen->interface;
		inverse.u.route.route = &model;
		reason = ncfg_plan_reason_unwanted(seen->interface, "routes",
		    ncfg_plan_render_route(builder->plan, &model));
		(void)ncfg_builder_push(builder, &op, &reason, NULL, 0, &inverse);
	}
}

static void teardown_addresses(ncfg_builder_t *builder)
{
	size_t i;
	size_t j;

	for (i = 0; i < builder->observed->address_count; i++) {
		const ncfg_observed_address_t *seen = &builder->observed->addresses[i];
		const ncfg_interface_t        *interface;
		ncfg_op_t                      op;
		ncfg_op_t                      inverse;
		ncfg_reason_t                  reason;
		int                            wanted = 0;

		if (!ncfg_ownership_may_remove(seen->ownership)) {
			continue;
		}
		/* Decision 0006 rule 7: a lease's address is the backend's, not the
		 * planner's. Only what config put here comes out here. */
		if (!seen->origin.has || seen->origin.value != NCFG_ORIGIN_STATIC) {
			continue;
		}
		interface = ncfg_plan_interface(builder->desired, seen->interface);
		if (interface) {
			for (j = 0; j < interface->addressing_count; j++) {
				const ncfg_address_source_t *source = &interface->addressing[j];
				char                         derived[NCFG_ADDRESS_MAX];

				if (source->kind == NCFG_ADDRESS_SOURCE_STATIC &&
				    text_equal(source->static_address.address, seen->address)) {
					wanted = 1;
					break;
				}
				/*
				 * **A derived address is as wanted as a literal one.** The
				 * document holds a reference rather than the value, so
				 * answering the question means resolving it again -- and a
				 * teardown that skipped that would delete the address the same
				 * plan had just added, on every reconcile, for ever. That is
				 * the property `plan.h` calls load-bearing, and it is why the
				 * resolution is one function two passes call rather than two
				 * that agree today.
				 */
				if (source->kind == NCFG_ADDRESS_SOURCE_DELEGATED &&
				    ncfg_plan_delegated_address(builder, source, derived,
				        sizeof(derived), NULL, 0) &&
				    ncfg_plan_address_equal(derived, seen->address)) {
					wanted = 1;
					break;
				}
				/*
				 * **And a reported address is as wanted as a literal one**,
				 * for the reason the arm above exists: the document names a
				 * source rather than a value, so answering the question means
				 * reading the report again. Without this the same plan would
				 * add the address and delete it, for ever.
				 *
				 * It is also rule 7 for this source, pointed the other way. A
				 * bearer that goes down empties the report, the address stops
				 * being wanted here, and the teardown removes it -- which is
				 * right, because unlike a lease there is no client holding it
				 * and no backend to restart.
				 */
				if (source->kind == NCFG_ADDRESS_SOURCE_REPORTED &&
				    ncfg_plan_reported_holds(builder->observed, seen->interface,
				        seen->address)) {
					wanted = 1;
					break;
				}
			}
		}
		if (wanted) {
			continue;
		}
		memset(&op, 0, sizeof(op));
		op.kind = NCFG_OP_ADDR_DEL;
		op.u.addr_del.iface = seen->interface;
		op.u.addr_del.addr = seen->address;
		memset(&inverse, 0, sizeof(inverse));
		inverse.kind = NCFG_OP_ADDR_ADD;
		inverse.u.addr_add.iface = seen->interface;
		inverse.u.addr_add.addr = seen->address;
		reason = ncfg_plan_reason_unwanted(seen->interface, "addressing", seen->address);
		(void)ncfg_builder_push(builder, &op, &reason, NULL, 0, &inverse);
	}
}

static void teardown_links(ncfg_builder_t *builder)
{
	size_t i;

	for (i = 0; i < builder->observed->link_count; i++) {
		const ncfg_observed_link_t *link = &builder->observed->links[i];
		ncfg_op_t                   op;
		ncfg_reason_t               reason;

		if (!ncfg_ownership_may_remove(link->ownership)) {
			continue;
		}
		/*
		 * **Devices, not interfaces.** What the document asks to exist is
		 * stated on the device, and a device need not have an interface: an
		 * `ifb` carries no address and never will, so asking the interface
		 * list whether anything wants it answers no and deletes the thing that
		 * was just created -- an apply that never converges.
		 */
		if (ncfg_plan_device(builder->desired, link->name)) {
			continue;
		}
		memset(&op, 0, sizeof(op));
		op.kind = NCFG_OP_LINK_DELETE;
		op.u.named.name = link->name;
		reason = ncfg_plan_reason_unwanted(link->name, "kind",
		    link->kind ? link->kind : "<absent>");
		/* A deleted link cannot be recreated without knowing how it was made,
		 * and the observed model records only what the kernel says.
		 * Irreversible, and the warning `ncfg_plan_add` emits says so. */
		(void)ncfg_builder_push(builder, &op, &reason, NULL, 0, NULL);
	}
}

/*
 * Rule 7: teardown is the reverse of dependency order -- routes, then
 * addresses, then backends, then links.
 *
 * The backends go between the addresses and the links because a client is
 * stopped after what it installed has been withdrawn and before the link it
 * was running on can go: stopping it first would leave netcfgd removing a
 * lease's address while the client that holds it is still there to put it
 * back, and stopping it last would mean signalling a process whose interface
 * had already been deleted.
 */
void ncfg_plan_teardown(ncfg_builder_t *builder)
{
	teardown_routes(builder);
	teardown_addresses(builder);
	ncfg_plan_teardown_backends(builder);
	teardown_links(builder);
}
