/*
 * ipv6_token.c -- the IPv6 interface identifier on each interface that names
 * one.
 *
 * WHAT IT IS FOR
 *   `ip token set ::5 dev eth0`: the prefix still comes from the router, the
 *   host part is chosen. The reason to want it is a server that must be
 *   reachable at a predictable address on a prefix that may change.
 *
 * ONLY WHERE THE DOCUMENT ASKS
 *   A token nobody asked for is not removed. Unlike an address it carries no
 *   ownership tag, and the kernel offers no way to tell one netcfgd set from
 *   one an operator set by hand -- so there is no teardown half here, and that
 *   is a decision rather than a gap.
 *
 * COMPARED AS AN ADDRESS, NEVER AS TEXT
 *   `::5` and `0:0:0:0:0:0:0:5` are the same token and the kernel reports its
 *   own spelling. A text comparison would write the token on every reconcile
 *   for ever against a kernel that already holds it, which is the shape
 *   project.md 10.169 measured elsewhere in this planner.
 */
#include "plan_internal.h"

#include "ncfg/base.h"

#include <string.h>

void ncfg_plan_ipv6_token(ncfg_builder_t *builder)
{
	size_t at;

	for (at = 0; at < builder->desired->interface_count; at++) {
		const ncfg_interface_t     *interface = &builder->desired->interfaces[at];
		const ncfg_observed_link_t *link;
		const char                 *current;
		ncfg_plan_ids_t             gate = { NULL, 0, 0 };
		ncfg_op_t                   op;
		ncfg_op_t                   inverse;
		ncfg_reason_t               reason;

		if (!interface->ipv6_token) {
			continue;
		}
		link = ncfg_observed_link(builder->observed, interface->name);
		current = link ? link->ipv6_token : NULL;
		if (current && ncfg_plan_address_equal(current, interface->ipv6_token)) {
			continue;
		}
		memset(&op, 0, sizeof(op));
		op.kind = NCFG_OP_LINK_SET_IPV6_TOKEN;
		op.u.set_ipv6_token.name = interface->name;
		op.u.set_ipv6_token.token = interface->ipv6_token;
		memset(&inverse, 0, sizeof(inverse));
		inverse.kind = NCFG_OP_LINK_SET_IPV6_TOKEN;
		inverse.u.set_ipv6_token.name = interface->name;
		/* The inverse clears it. Restoring a previous token would be wrong
		 * where there was none, and `::` is how the kernel spells "none". */
		inverse.u.set_ipv6_token.token = current ? current : "::";
		reason = ncfg_plan_reason_differs(interface->name, "ipv6_token",
		    interface->ipv6_token, current ? current : "<absent>");
		ncfg_builder_gate(builder, interface->name, &gate);
		(void)ncfg_builder_push(builder, &op, &reason, gate.ids, gate.count, &inverse);
		ncfg_plan_ids_free(&gate);
	}
}
