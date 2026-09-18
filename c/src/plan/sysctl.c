/*
 * sysctl.c -- the three per-interface sysctls netcfgd writes, and the one rule
 * all three are arranged around.
 *
 * WHY THESE ARE NOT ADDRESSING ACTIONS
 *   SLAAC plans no addressing action at all: given a router advertisement the
 *   kernel builds the address itself. What netcfgd owns is whether the kernel
 *   is listening, and whether the address it builds is a temporary one -- two
 *   properties of the interface, written here rather than in the addressing
 *   pass, which is also where the Rust puts them.
 *
 * THE ONE-WAY DOOR, WHICH IS WHAT `*_applied` IS FOR
 *   All three sysctls share a shape and the shape is the interesting part: an
 *   interface that *stops* asking is put back, **but only where netcfgd is
 *   what changed it**. Without that half, deleting `forwarding = true` from
 *   the document leaves the machine routing -- drift the config can no longer
 *   describe -- and a machine whose `sysctl.conf` sets `use_tempaddr` globally
 *   would have netcfgd undo somebody else's choice the first time it ran.
 *   `ncfg_observed_t` carries a list of names per sysctl for exactly this, and
 *   a list of names is all it carries: what "back" means is the kernel's
 *   default, said out loud rather than left to be discovered.
 *
 * AND AN INVERSE ONLY WHERE THERE WAS A VALUE TO GO BACK TO
 *   A sysctl that could not be read cannot be restored, and inventing one
 *   would have commit-confirm turn forwarding off on a router that had it on
 *   before netcfgd ever ran. An interface this plan is about to *create* has
 *   no previous value either; the write is still planned, gated on the
 *   creation, because without that a virtual interface would need a second
 *   apply to get what the document asked for on the first -- and `ncfg apply`
 *   does not get another go.
 */
#include "plan_internal.h"

#include "ncfg/base.h"

#include <string.h>

/* Whether this interface asks for SLAAC at all, and whether it asks for the
 * temporary addresses RFC 4941 describes. */
static int asks_for_slaac(const ncfg_interface_t *interface, int temporary_only)
{
	size_t i;

	for (i = 0; i < interface->addressing_count; i++) {
		if (interface->addressing[i].kind != NCFG_ADDRESS_SOURCE_SLAAC) {
			continue;
		}
		if (!temporary_only || interface->addressing[i].slaac.privacy ==
		    NCFG_SLAAC_PRIVACY_PREFER_TEMPORARY) {
			return 1;
		}
	}
	return 0;
}

static int applied_to(const char *const *list, size_t count, const char *name)
{
	return ncfg_plan_names(list, count, name);
}

/* ------------------------------------------------------------------------ *
 * accept_ra
 * ------------------------------------------------------------------------ */

/*
 * How the plan describes what the kernel is doing with advertisements now.
 *
 * Three sentences rather than a number, because the number is not enough to
 * act on: `accept_ra=1` is the kernel's default and means "accept unless this
 * interface forwards", so the same value is the working state on a laptop and
 * the broken one on a router -- and `ip addr` shows a link-local and nothing
 * else either way. Decision 0073.
 */
static const char *accept_ra_observed(ncfg_builder_t *builder, const char *name,
    const ncfg_observed_accept_ra_t *state)
{
	if (!state) {
		return "<absent>";
	}
	if (state->effective) {
		return ncfg_plan_internf(builder->plan, "accept_ra %lld, advertisements accepted",
		    (long long)state->value);
	}
	if (state->value == 1) {
		return ncfg_plan_internf(builder->plan,
		    "accept_ra %lld, and %s forwards -- advertisements ignored",
		    (long long)state->value, name);
	}
	return ncfg_plan_internf(builder->plan, "accept_ra %lld, advertisements ignored",
	    (long long)state->value);
}

/*
 * Whether there is nothing to do.
 *
 * **Against the forwarding this plan will produce, not the one it observed.**
 * `effective` is computed in the observer from the forwarding sysctl as it
 * was, and a plan turning forwarding on in the same pass invalidates it: the
 * interface reads as settled, no `accept_ra` is planned, and the apply leaves
 * it forwarding with `accept_ra` at 1 -- advertisements ignored, SLAAC
 * obtaining no address -- until a second apply happens to run. Measured in the
 * Rust: two applies to converge where one should do, which a daemon hides and
 * `--oneshot` at boot does not.
 *
 * Where the document says nothing about forwarding, the observation is still
 * the answer and can be recovered exactly: `effective` is false with
 * `value == 1` only when the interface forwards.
 */
static int accept_ra_settled(const ncfg_interface_t *interface,
    const ncfg_observed_accept_ra_t *state, int asked, int64_t wanted)
{
	int forwards;

	if (!state) {
		/* Nothing to read yet, so nothing is settled: the write is planned
		 * and gated on the creation, as this interface's forwarding is. */
		return 0;
	}
	if (!asked) {
		return state->value == wanted;
	}
	forwards = interface->forwarding.has ? interface->forwarding.value :
	    (state->value == 1 && !state->effective);
	return state->value == 2 || (state->value == 1 && !forwards);
}

void ncfg_plan_accept_ra(ncfg_builder_t *builder)
{
	size_t i;

	for (i = 0; i < builder->desired->interface_count; i++) {
		const ncfg_interface_t          *interface = &builder->desired->interfaces[i];
		const ncfg_observed_link_t      *link;
		const ncfg_observed_accept_ra_t *state;
		ncfg_plan_ids_t                  deps = { NULL, 0, 0 };
		ncfg_op_t                        op;
		ncfg_op_t                        inverse;
		ncfg_reason_t                    reason;
		int                              asked = asks_for_slaac(interface, 0);
		int64_t                          wanted;

		/*
		 * `2` to accept whatever this interface forwards, `1` to hand it back
		 * to the kernel's own default. Never `0`: netcfgd turning
		 * advertisements off outright is not something any document asks for,
		 * and "back" can only mean the default here -- the record is a list of
		 * names rather than the values that were found.
		 */
		if (asked) {
			wanted = 2;
		} else if (applied_to((const char *const *)builder->observed->accept_ra_applied,
		    builder->observed->accept_ra_applied_count, interface->name)) {
			wanted = 1;
		} else {
			continue;
		}
		link = ncfg_observed_link(builder->observed, interface->name);
		state = link ? link->accept_ra : NULL;
		/*
		 * An interface that exists and has no `accept_ra` is an IPv6-disabled
		 * kernel or a container without `/proc/sys`. Writing there fails this
		 * apply and every one after it, so it is reported instead -- an action
		 * planned before the thing that would make it succeed is a plan that
		 * never converges.
		 */
		if (link && !state) {
			ncfg_plan_warnf(builder->plan, interface->name,
			    "the `accept_ra` sysctl for %s cannot be read, so a router "
			    "advertisement may be ignored and SLAAC obtain no address -- an "
			    "IPv6-disabled kernel, or a container without /proc/sys",
			    interface->name);
			continue;
		}
		if (accept_ra_settled(interface, state, asked, wanted)) {
			continue;
		}

		memset(&op, 0, sizeof(op));
		op.kind = NCFG_OP_SYSCTL_SET_ACCEPT_RA;
		op.u.accept_ra.iface = interface->name;
		op.u.accept_ra.value = wanted;
		reason = ncfg_plan_reason_differs(interface->name, "addressing[slaac]",
		    asked ? "router advertisements accepted" :
		        "accept_ra back to the kernel default",
		    accept_ra_observed(builder, interface->name, state));
		ncfg_builder_gate(builder, interface->name, &deps);
		if (state) {
			memset(&inverse, 0, sizeof(inverse));
			inverse.kind = NCFG_OP_SYSCTL_SET_ACCEPT_RA;
			inverse.u.accept_ra.iface = interface->name;
			inverse.u.accept_ra.value = state->value;
			(void)ncfg_builder_push(builder, &op, &reason, deps.ids, deps.count, &inverse);
		} else {
			(void)ncfg_builder_push(builder, &op, &reason, deps.ids, deps.count, NULL);
		}
		ncfg_plan_ids_free(&deps);
	}
}

/* ------------------------------------------------------------------------ *
 * use_tempaddr
 * ------------------------------------------------------------------------ */

/*
 * RFC 4941 temporary addresses, per interface.
 *
 * The kernel's third value has no spelling in the document: `1` generates a
 * temporary address and prefers the stable one, which nothing here can ask
 * for -- so it reads as "not preferring temporary" and is left alone unless
 * netcfgd wrote it.
 */
void ncfg_plan_privacy(ncfg_builder_t *builder)
{
	size_t i;

	for (i = 0; i < builder->desired->interface_count; i++) {
		const ncfg_interface_t     *interface = &builder->desired->interfaces[i];
		const ncfg_observed_link_t *link;
		ncfg_optbool_t              current;
		ncfg_plan_ids_t             deps = { NULL, 0, 0 };
		ncfg_op_t                   op;
		ncfg_op_t                   inverse;
		ncfg_reason_t               reason;
		int                         wanted;

		if (asks_for_slaac(interface, 1)) {
			wanted = 1;
		} else if (applied_to((const char *const *)builder->observed->privacy_applied,
		    builder->observed->privacy_applied_count, interface->name)) {
			wanted = 0;
		} else {
			continue;
		}
		link = ncfg_observed_link(builder->observed, interface->name);
		current = link ? link->privacy : (ncfg_optbool_t){ 0, 0 };
		/*
		 * Absent on an interface that *exists* is a different answer from
		 * absent on one this plan is about to create: an IPv6-disabled kernel
		 * has no `use_tempaddr` at all, and a container may have no
		 * `/proc/sys`. Said rather than skipped, because a key that quietly
		 * does nothing is the reason this one was implemented.
		 */
		if (link && !current.has) {
			ncfg_plan_warnf(builder->plan, interface->name,
			    "the `use_tempaddr` sysctl for %s cannot be read, so temporary "
			    "addresses are not configured -- an IPv6-disabled kernel, or a "
			    "container without /proc/sys",
			    interface->name);
			continue;
		}
		if (current.has && current.value == wanted) {
			continue;
		}

		memset(&op, 0, sizeof(op));
		op.kind = NCFG_OP_SYSCTL_SET_PRIVACY;
		op.u.privacy.iface = interface->name;
		op.u.privacy.prefer_temporary = wanted;
		reason = ncfg_plan_reason_differs(interface->name, "addressing[slaac].privacy",
		    wanted ? "prefer_temporary" : "none",
		    current.has ? (current.value ? "prefer_temporary" : "none") : "<absent>");
		ncfg_builder_gate(builder, interface->name, &deps);
		if (current.has) {
			memset(&inverse, 0, sizeof(inverse));
			inverse.kind = NCFG_OP_SYSCTL_SET_PRIVACY;
			inverse.u.privacy.iface = interface->name;
			inverse.u.privacy.prefer_temporary = current.value;
			(void)ncfg_builder_push(builder, &op, &reason, deps.ids, deps.count, &inverse);
		} else {
			(void)ncfg_builder_push(builder, &op, &reason, deps.ids, deps.count, NULL);
		}
		ncfg_plan_ids_free(&deps);
	}
}

/* ------------------------------------------------------------------------ *
 * forwarding
 * ------------------------------------------------------------------------ */

/*
 * The `forwarding` sysctl on each interface that asks for one.
 *
 * Planned per interface and applied per interface, rather than through the
 * global `net.ipv4.ip_forward`. Writing the global one sets every device at
 * once, so netcfgd would be turning forwarding on for interfaces the document
 * says nothing about -- and it could never turn it off again without guessing
 * which of those it had been responsible for.
 */
void ncfg_plan_forwarding(ncfg_builder_t *builder)
{
	size_t i;

	for (i = 0; i < builder->desired->interface_count; i++) {
		const ncfg_interface_t     *interface = &builder->desired->interfaces[i];
		const ncfg_observed_link_t *link;
		ncfg_optbool_t              current;
		ncfg_plan_ids_t             deps = { NULL, 0, 0 };
		ncfg_op_t                   op;
		ncfg_op_t                   inverse;
		ncfg_reason_t               reason;
		int                         wanted;

		if (interface->forwarding.has) {
			wanted = interface->forwarding.value;
		} else if (applied_to((const char *const *)builder->observed->forwarding_applied,
		    builder->observed->forwarding_applied_count, interface->name)) {
			wanted = 0;
		} else {
			continue;
		}
		link = ncfg_observed_link(builder->observed, interface->name);
		current = link ? link->forwarding : (ncfg_optbool_t){ 0, 0 };
		if (current.has && current.value == wanted) {
			continue;
		}

		memset(&op, 0, sizeof(op));
		op.kind = NCFG_OP_SYSCTL_SET_FORWARDING;
		op.u.forwarding.iface = interface->name;
		op.u.forwarding.enabled = wanted;
		reason = ncfg_plan_reason_differs(interface->name, "forwarding",
		    wanted ? "true" : "false",
		    current.has ? (current.value ? "true" : "false") : "<unreadable>");
		ncfg_builder_gate(builder, interface->name, &deps);
		if (current.has) {
			memset(&inverse, 0, sizeof(inverse));
			inverse.kind = NCFG_OP_SYSCTL_SET_FORWARDING;
			inverse.u.forwarding.iface = interface->name;
			inverse.u.forwarding.enabled = current.value;
			(void)ncfg_builder_push(builder, &op, &reason, deps.ids, deps.count, &inverse);
		} else {
			(void)ncfg_builder_push(builder, &op, &reason, deps.ids, deps.count, NULL);
		}
		ncfg_plan_ids_free(&deps);
	}
}
