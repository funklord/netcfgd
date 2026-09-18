/*
 * backend.c -- starting the helper that serves an addressing source, and
 * stopping the ones the document no longer asks for.
 *
 * WHAT THIS BUILD STARTS, AND THEREFORE WHAT IT STOPS
 *   netcfgd does not implement DHCP (0004): a `dhcp4` or `dhcp6` addressing
 *   source is a client process, and what the planner emits is the decision to
 *   run one. This pass carries those two kinds and no others.
 *
 *   **The teardown answers only for the kinds something here starts, and that
 *   is the rule rather than the gap.** The Rust's `backend_wanted` is
 *   exhaustive over all nine, which is right in a planner where every pass
 *   that starts one exists; here the access point and the two tunnels are
 *   started by passes this build does not have, so answering "the document
 *   does not ask for this" about them would stop something netcfgd never
 *   started -- and on the next reconcile, start nothing in its place. That is
 *   the Rust's own reasoning for `WireGuard` and `Dns`, which it excuses for
 *   exactly this reason, applied to the kinds this port has not reached yet.
 *   Each becomes ordinary the day its pass lands, and two just have:
 *   `dot1x.c` starts a supplicant and `advertise.c` a router advertisement
 *   daemon, so both are decided about here now.
 *
 *   **The supplicant's rule is the one to be careful with.** It is asked in
 *   `ncfg_plan_supplicant_wanted` rather than spelled here, beside the pass
 *   that starts one, because the conditions that start a supplicant and the
 *   conditions that keep one have to stay the same: wrong in the permissive
 *   direction leaves a process nobody owns, and wrong in the other direction
 *   is netcfgd starting a supplicant and killing it on every reconcile for
 *   ever. A radio's supplicant is *wanted* there and started by nothing here,
 *   which is the arm that keeps this build from stopping one it cannot
 *   replace.
 *
 * WHY A COUNT AND NOT A RETRY
 *   A daemon that dies as fast as netcfgd starts it produced 181 starts in
 *   twelve seconds on an interface set to `reconcile` -- measured, with a fake
 *   that lived for half a second. So netcfgd tries, and then stops trying and
 *   says so. Decision 0079. The count clears the moment the backend is seen
 *   running, or when the document stops asking for it.
 */
#include "plan_internal.h"

#include "ncfg/base.h"

#include <string.h>

/* Whether this interface's addressing asks for a client of this kind. */
static int addressing_asks_for(const ncfg_interface_t *interface, int kind)
{
	int    source_kind = kind == NCFG_BACKEND_DHCP4 ? NCFG_ADDRESS_SOURCE_DHCP4 :
	    NCFG_ADDRESS_SOURCE_DHCP6;
	size_t i;

	for (i = 0; i < interface->addressing_count; i++) {
		if (interface->addressing[i].kind == source_kind) {
			return 1;
		}
	}
	return 0;
}

void ncfg_plan_backend(ncfg_builder_t *builder, const char *name, int kind, const char *field,
    const ncfg_plan_ids_t *base, ncfg_plan_ids_t *out)
{
	ncfg_plan_ids_t deps = { NULL, 0, 0 };
	ncfg_op_t       op;
	ncfg_op_t       inverse;
	ncfg_reason_t   reason;
	int64_t         restarts;
	uint32_t        up;
	uint32_t        id;

	/*
	 * Running is enough for this build. The Rust goes on to re-hand a running
	 * *supplicant* its networks, which is the one backend whose contents can
	 * go stale while the process stays up; nothing here starts a supplicant,
	 * and a DHCP client's contents are its own lease.
	 */
	if (ncfg_observed_backend_running(builder->observed, kind, name)) {
		return;
	}
	restarts = ncfg_observed_backend_restarts(builder->observed, kind, name);
	if (restarts >= NCFG_PLAN_RESTART_LIMIT) {
		ncfg_plan_warnf(builder->plan, name,
		    "netcfgd has started the %s backend on %s %lld times and it has not stayed "
		    "up; not starting it again. Whatever it says about why is in /run/netcfgd, "
		    "and the count clears the moment it is seen running -- or when the document "
		    "stops asking for it",
		    ncfg_backend_kind_name(kind), name, (long long)restarts);
		return;
	}

	/* Rule 3: a lease needs a live link, so this waits for `link.up`. */
	ncfg_plan_ids_extend(builder->plan, &deps, base);
	up = ncfg_builder_link_up(builder, name);
	if (up != NCFG_PLAN_NO_ACTION) {
		ncfg_plan_ids_push(builder->plan, &deps, up);
	}

	memset(&op, 0, sizeof(op));
	op.kind = NCFG_OP_BACKEND_START;
	op.u.backend.kind = kind;
	op.u.backend.iface = name;
	memset(&inverse, 0, sizeof(inverse));
	inverse.kind = NCFG_OP_BACKEND_STOP;
	inverse.u.backend.kind = kind;
	inverse.u.backend.iface = name;
	/* The model's spelling of the kind, not a debug rendering of an enum:
	 * `dhcp4` is what `ncfg status` prints and what the JSON carries, and a
	 * second spelling entering the vocabulary through a reason line is how the
	 * two come to disagree. */
	reason = ncfg_plan_reason_absent(name, field, ncfg_backend_kind_name(kind));
	id = ncfg_builder_push(builder, &op, &reason, deps.ids, deps.count, &inverse);
	ncfg_plan_ids_free(&deps);
	if (id != NCFG_PLAN_NO_ACTION) {
		ncfg_plan_ids_push(builder->plan, out, id);
	}
}

/*
 * Whether a running backend is one the document asks for, and which field
 * decides it.
 *
 * **The field is answered alongside on purpose**: an operator told a
 * supplicant was stopped because of `addressing` goes and looks at the wrong
 * block, and the four kinds here are decided by four different ones.
 *
 * The default arm is the restriction the header describes, and it is the
 * permissive direction deliberately: a kind no pass here starts is one this
 * build would be stopping without ever putting back. `NCFG_BACKEND_WIREGUARD`
 * and `NCFG_BACKEND_DNS` are in it for the Rust's own reason and stay there
 * when the rest land -- a WireGuard device is configured at creation and a DNS
 * delivery is an action rather than a process.
 */
static int backend_wanted(const ncfg_builder_t *builder, const ncfg_observed_backend_t *backend,
    const char **field)
{
	const ncfg_interface_t *interface;

	switch (backend->kind) {
	case NCFG_BACKEND_DHCP4:
	case NCFG_BACKEND_DHCP6:
		*field = "addressing";
		interface = ncfg_plan_interface(builder->desired, backend->interface);
		return interface && addressing_asks_for(interface, backend->kind);
	case NCFG_BACKEND_SUPPLICANT:
		/* Both blocks, because 0008 puts wired 802.1X on the same supplicant
		 * as wifi and one process cannot be half wanted. */
		*field = "wifi/dot1x";
		return ncfg_plan_supplicant_wanted(builder->desired, backend->interface);
	case NCFG_BACKEND_ROUTER_ADVERT:
		*field = "advertise";
		interface = ncfg_plan_interface(builder->desired, backend->interface);
		return interface && interface->advertise;
	default:
		*field = "";
		return 1;
	}
}

void ncfg_plan_teardown_backends(ncfg_builder_t *builder)
{
	size_t i;

	for (i = 0; i < builder->observed->backend_count; i++) {
		const ncfg_observed_backend_t *backend = &builder->observed->backends[i];
		const char                    *field = "";
		ncfg_op_t                      op;
		ncfg_op_t                      inverse;
		ncfg_reason_t                  reason;

		if (!backend->running) {
			continue;
		}
		if (backend_wanted(builder, backend, &field)) {
			continue;
		}

		memset(&op, 0, sizeof(op));
		op.kind = NCFG_OP_BACKEND_STOP;
		op.u.backend.kind = backend->kind;
		op.u.backend.iface = backend->interface;
		memset(&inverse, 0, sizeof(inverse));
		inverse.kind = NCFG_OP_BACKEND_START;
		inverse.u.backend.kind = backend->kind;
		inverse.u.backend.iface = backend->interface;
		/* The block rather than the op's own name, because an operator told a
		 * client was stopped because of the backend goes and looks at the
		 * wrong block. */
		reason = ncfg_plan_reason_unwanted(backend->interface, field,
		    ncfg_backend_kind_name(backend->kind));
		(void)ncfg_builder_push(builder, &op, &reason, NULL, 0, &inverse);
	}
}
