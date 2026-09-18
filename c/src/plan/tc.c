/*
 * tc.c -- the root qdisc, and the ingress redirect that turns arriving
 * traffic into something that can be shaped.
 *
 * WHY THIS IS IDEMPOTENT WITHOUT RECORDED STATE, AND WHERE IT IS NOT
 *   **Every interface always has a qdisc.** An interface netcfgd has never
 *   touched reports whatever `net.core.default_qdisc` gave it, so this is
 *   never "install where absent" -- it is always a comparison against
 *   something, which is what makes it converge on the first apply.
 *
 *   Recorded state is needed for exactly one question: whether netcfgd may
 *   *reset* one. A qdisc carries no owner, so an interface that was already
 *   running `cake` before netcfgd existed is not netcfgd's to put back to the
 *   default -- `qdisc_applied` is the record that says which ones are, and the
 *   same rule and the same record shape hold for the redirect.
 *
 * THE RATE IS PART OF THE COMPARISON, NOT AN AFTERTHOUGHT
 *   A `cake` already installed at the wrong bandwidth is the exact case where
 *   "the kind matches, nothing to do" shapes a line at somebody else's number.
 *
 * WHY THE REDIRECT RUNS AFTER THE QDISC
 *   So the `ifb` exists and is shaped before anything is pointed at it.
 *   Traffic redirected onto a device with no shaper is traffic that is not
 *   being shaped, which is worse than not redirecting it at all -- and the
 *   dependency is on the **target's** creation rather than on the interface's,
 *   because the `ifb` is the thing that has to be there.
 */
#include "plan_internal.h"

#include "ncfg/base.h"

#include <string.h>

/* `cake at 20000000 bit/s`, or the bare kind where nothing is shaped. */
static const char *describe(ncfg_plan_t *plan, const char *kind, ncfg_optint_t rate)
{
	if (!kind) {
		return "<absent>";
	}
	if (!rate.has) {
		return kind;
	}
	return ncfg_plan_internf(plan, "%s at %lld bit/s", kind, (long long)rate.value);
}

/* One `qdisc.set`, filled in. */
static void qdisc_op(ncfg_op_t *op, const char *iface, const char *kind, ncfg_optint_t rate,
    int ingress)
{
	memset(op, 0, sizeof(*op));
	op->kind = NCFG_OP_QDISC_SET;
	op->u.qdisc.iface = iface;
	op->u.qdisc.kind = kind;
	op->u.qdisc.bandwidth_bits = rate;
	op->u.qdisc.ingress = ingress;
}

/*
 * The root qdisc on every device whose block names one.
 *
 * **Devices, not interfaces**: a qdisc shapes the egress of hardware, and the
 * `ifb` an ingress shaper needs carries no address and never will.
 */
void ncfg_plan_qdisc(ncfg_builder_t *builder)
{
	size_t at;

	for (at = 0; at < builder->desired->device_count; at++) {
		const ncfg_device_t        *device = &builder->desired->devices[at];
		const ncfg_observed_link_t *link =
		    ncfg_observed_link(builder->observed, device->name);
		const char                 *current = link ? link->qdisc : NULL;
		ncfg_optint_t               current_rate = { 0, 0 };
		int                         current_ingress = link && link->qdisc_ingress;
		int                         ours = ncfg_plan_names(
		    (const char *const *)builder->observed->qdisc_applied,
		    builder->observed->qdisc_applied_count, device->name);
		const char                 *wanted;
		ncfg_plan_ids_t             gate = { NULL, 0, 0 };
		ncfg_op_t                   op;
		ncfg_op_t                   inverse;
		ncfg_reason_t               reason;

		if (link) {
			current_rate = link->qdisc_bandwidth_bits;
		}
		if (!device->qdisc) {
			/*
			 * Stopped asking. Put the kernel default back, but only where
			 * netcfgd is what moved it.
			 *
			 * `current` has to be there because nothing else enforced the
			 * sentence above: an observation carrying no qdisc produced a
			 * reset that could change nothing, and an action that cannot
			 * change anything is not an action.
			 */
			if (!ours || !current) {
				continue;
			}
			memset(&op, 0, sizeof(op));
			op.kind = NCFG_OP_QDISC_RESET;
			op.u.iface.iface = device->name;
			qdisc_op(&inverse, device->name, current, current_rate, current_ingress);
			reason = ncfg_plan_reason_unwanted(device->name, "qdisc", current);
			ncfg_builder_gate(builder, device->name, &gate);
			(void)ncfg_builder_push(builder, &op, &reason, gate.ids, gate.count,
			    &inverse);
			ncfg_plan_ids_free(&gate);
			continue;
		}
		wanted = ncfg_plan_qdisc_kind_word(device->qdisc->kind);
		if (!wanted) {
			continue;
		}
		if (current && strcmp(current, wanted) == 0 &&
		    current_rate.has == device->qdisc->bandwidth_bits.has &&
		    (!current_rate.has ||
		    current_rate.value == device->qdisc->bandwidth_bits.value) &&
		    current_ingress == device->qdisc->ingress) {
			continue;
		}
		qdisc_op(&op, device->name, wanted, device->qdisc->bandwidth_bits,
		    device->qdisc->ingress);
		reason = ncfg_plan_reason_differs(device->name, "qdisc",
		    describe(builder->plan, wanted, device->qdisc->bandwidth_bits),
		    describe(builder->plan, current, current_rate));
		ncfg_builder_gate(builder, device->name, &gate);
		if (current) {
			qdisc_op(&inverse, device->name, current, current_rate, current_ingress);
			(void)ncfg_builder_push(builder, &op, &reason, gate.ids, gate.count,
			    &inverse);
		} else {
			(void)ncfg_builder_push(builder, &op, &reason, gate.ids, gate.count, NULL);
		}
		ncfg_plan_ids_free(&gate);
	}
}

/* The ingress redirect on every device that asks for one. */
void ncfg_plan_ingress(ncfg_builder_t *builder)
{
	size_t at;

	for (at = 0; at < builder->desired->device_count; at++) {
		const ncfg_device_t        *device = &builder->desired->devices[at];
		const ncfg_observed_link_t *link =
		    ncfg_observed_link(builder->observed, device->name);
		const char                 *current = link ? link->ingress_redirect : NULL;
		int                         ours = ncfg_plan_names(
		    (const char *const *)builder->observed->ingress_applied,
		    builder->observed->ingress_applied_count, device->name);
		ncfg_plan_ids_t             gate = { NULL, 0, 0 };
		ncfg_op_t                   op;
		ncfg_op_t                   inverse;
		ncfg_reason_t               reason;

		if (device->ingress_redirect) {
			if (current && strcmp(current, device->ingress_redirect) == 0) {
				continue;
			}
			memset(&op, 0, sizeof(op));
			op.kind = NCFG_OP_INGRESS_REDIRECT;
			op.u.redirect.iface = device->name;
			op.u.redirect.target = device->ingress_redirect;
			memset(&inverse, 0, sizeof(inverse));
			inverse.kind = NCFG_OP_INGRESS_REDIRECT_CLEAR;
			inverse.u.iface.iface = device->name;
			reason = ncfg_plan_reason_differs(device->name, "ingress_redirect",
			    device->ingress_redirect, current ? current : "<absent>");
			/* The **target's** gate: the `ifb` has to exist before anything
			 * is pointed at it. */
			ncfg_builder_gate(builder, device->ingress_redirect, &gate);
			(void)ncfg_builder_push(builder, &op, &reason, gate.ids, gate.count,
			    &inverse);
			ncfg_plan_ids_free(&gate);
			continue;
		}
		/* Same ownership rule as the qdisc: a redirect somebody else put
		 * there is not netcfgd's to take away. */
		if (!current || !ours) {
			continue;
		}
		memset(&op, 0, sizeof(op));
		op.kind = NCFG_OP_INGRESS_REDIRECT_CLEAR;
		op.u.iface.iface = device->name;
		memset(&inverse, 0, sizeof(inverse));
		inverse.kind = NCFG_OP_INGRESS_REDIRECT;
		inverse.u.redirect.iface = device->name;
		inverse.u.redirect.target = current;
		reason = ncfg_plan_reason_unwanted(device->name, "ingress_redirect", current);
		(void)ncfg_builder_push(builder, &op, &reason, NULL, 0, &inverse);
	}
}
