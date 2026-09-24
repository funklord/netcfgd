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
 *   that starts one exists; here the two tunnels are started by passes this
 *   build does not have, so answering "the document does not ask for this"
 *   about them would stop something netcfgd never started -- and on the next
 *   reconcile, start nothing in its place. That is the Rust's own reasoning
 *   for `WireGuard` and `Dns`, which it excuses for exactly this reason,
 *   applied to the kinds this port has not reached yet. Each becomes ordinary
 *   the day its pass lands, and four have: `dot1x.c` starts a supplicant,
 *   `radio.c` the same supplicant for the other reason, `advertise.c` a router
 *   advertisement daemon and `access_point.c` a hostapd, so all four are
 *   decided about here now.
 *
 *   **The supplicant's rule is the one to be careful with.** It is asked in
 *   `ncfg_plan_supplicant_wanted` rather than spelled here, beside the pass
 *   that starts one, because the conditions that start a supplicant and the
 *   conditions that keep one have to stay the same: wrong in the permissive
 *   direction leaves a process nobody owns, and wrong in the other direction
 *   is netcfgd starting a supplicant and killing it on every reconcile for
 *   ever. A radio's supplicant used to be *wanted* there and started by
 *   nothing here, which was the arm that kept this build from stopping one it
 *   could not replace; `radio.c` starts one now, and that arm is the ordinary
 *   shape -- one rule, asked by the pass and by this teardown.
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
	 * Running is enough here. The Rust goes on to re-hand a running
	 * *supplicant* its networks, which is the one backend whose contents can
	 * go stale while the process stays up and which this build hands over in
	 * `wifi.c` instead; a DHCP client's contents are its own lease, and an
	 * access point cannot be handed anything at all -- what notices one
	 * running the wrong thing is the restart in `access_point.c`.
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
		return ncfg_plan_supplicant_wanted(builder->desired, builder->observed,
		    backend->interface);
	case NCFG_BACKEND_ROUTER_ADVERT:
		*field = "advertise";
		interface = ncfg_plan_interface(builder->desired, backend->interface);
		return interface && interface->advertise;
	case NCFG_BACKEND_ACCESS_POINT:
		/* Asked in `ncfg_plan_access_point_wanted` for the supplicant's
		 * reason, beside the pass that starts one. */
		*field = "access_point";
		return ncfg_plan_access_point_wanted(builder->desired, backend->interface);
	case NCFG_BACKEND_PPPOE:
	case NCFG_BACKEND_OPENVPN:
		/*
		 * **The device, not the interface**, which is `session.c`'s rule: a
		 * tunnel need not have an `interface` block at all, and asking the
		 * interface list would answer no and stop a working one.
		 *
		 * This is what makes deleting the block hang the line up. Without it a
		 * removed `pppoe` device left `pppd` holding the line with `persist`
		 * and `maxfail 0` in the options netcfgd wrote for it -- for ever.
		 */
		*field = backend->kind == NCFG_BACKEND_PPPOE ? "pppoe" : "openvpn";
		return ncfg_plan_session_wanted(builder->desired, backend->interface,
		    backend->kind);
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

/* ------------------------------------------------------------------------ *
 * A client running with a metric the document has moved on from
 * ------------------------------------------------------------------------ */

/*
 * The metric a running DHCP client's own default route carries, or absent.
 *
 * **Filtered by the protocol the kernel stamped on it**, which is what tells a
 * lease's route from a static one the document also asked for: whichever client
 * installed it -- dhcpcd, dhclient, udhcpc -- the kernel records
 * `NCFG_DHCP_ROUTE_PROTO`, and `observed.h` says that is why the protocol is
 * the normaliser rather than the client's own lease file.
 */
static ncfg_optint_t installed_metric(const ncfg_observed_t *observed, const char *name)
{
	ncfg_optint_t none;
	size_t        i;

	memset(&none, 0, sizeof(none));
	for (i = 0; observed && i < observed->route_count; i++) {
		const ncfg_observed_route_t *route = &observed->routes[i];

		if (!route->interface || !name || strcmp(route->interface, name) != 0) {
			continue;
		}
		if (!route->destination || strcmp(route->destination, "default") != 0) {
			continue;
		}
		if (!route->proto.has || route->proto.value != NCFG_DHCP_ROUTE_PROTO) {
			continue;
		}
		return route->metric;
	}
	return none;
}

/*
 * The metric a running client was started with, where it is not the one now
 * wanted.
 *
 * `observed.h` says this is read out of the client's own `argv` when it
 * started, so it is there **before any route exists** -- which is the half the
 * installed route cannot answer, because a client that has not finished its
 * first exchange has installed nothing.
 */
static ncfg_optint_t started_with_another(const ncfg_observed_t *observed, const char *name,
    int64_t wanted)
{
	ncfg_optint_t none;
	size_t        i;

	memset(&none, 0, sizeof(none));
	for (i = 0; observed && i < observed->backend_count; i++) {
		const ncfg_observed_backend_t *backend = &observed->backends[i];

		if (backend->kind != NCFG_BACKEND_DHCP4 || !backend->running) {
			continue;
		}
		if (!backend->interface || !name || strcmp(backend->interface, name) != 0) {
			continue;
		}
		if (backend->started_metric.has && backend->started_metric.value != wanted) {
			return backend->started_metric;
		}
		return none;
	}
	return none;
}

void ncfg_plan_metric_restart(ncfg_builder_t *builder, const ncfg_interface_t *interface,
    const ncfg_plan_ids_t *base)
{
	ncfg_optint_t   wanted;
	ncfg_optint_t   seen;
	ncfg_plan_ids_t deps = { NULL, 0, 0 };
	ncfg_op_t       op;
	ncfg_op_t       inverse;
	ncfg_reason_t   reason;
	int64_t         restarts;
	uint32_t        stop;

	if (!interface || !interface->name) {
		return;
	}
	wanted = ncfg_observed_effective_metric(builder->desired, builder->observed, interface);
	if (!wanted.has) {
		return;
	}
	/*
	 * Only where the document asks for a lease at all and one is running. A
	 * client netcfgd is not running is not one it can restart, and an
	 * interface with no `dhcp4` source has no lease route to be wrong.
	 */
	if (!addressing_asks_for(interface, NCFG_BACKEND_DHCP4) ||
	    !ncfg_observed_backend_running(builder->observed, NCFG_BACKEND_DHCP4,
	    interface->name)) {
		return;
	}
	/*
	 * **Two answers and neither subsumes the other.** The `argv` says what the
	 * client was *told* and is there at once; the route says what it *did* and
	 * catches a client that ignored what it was told. `seen` is whichever
	 * noticed, and it is what the sentence reports, so an operator is told the
	 * number that is actually on their machine.
	 */
	seen = installed_metric(builder->observed, interface->name);
	if (!seen.has || seen.value == wanted.value) {
		seen = started_with_another(builder->observed, interface->name, wanted.value);
	}
	if (!seen.has || seen.value == wanted.value) {
		return;
	}
	/*
	 * 0079's cap, and it matters more here than anywhere else it is applied: a
	 * client that will not take the metric -- because the operator's own
	 * `dhcpcd.conf` overrides it, say -- would otherwise be stopped and
	 * started on every reconcile for ever, and each round drops the lease for
	 * as long as the exchange takes. A machine whose network goes away every
	 * five seconds is worse than one whose route ranks wrongly.
	 */
	restarts = ncfg_observed_backend_restarts(builder->observed, NCFG_BACKEND_DHCP4,
	    interface->name);
	if (restarts >= NCFG_PLAN_RESTART_LIMIT) {
		ncfg_plan_warnf(builder->plan, interface->name,
		    "%s's lease route still carries metric %lld rather than the %lld its "
		    "network asks for, and the client has been restarted %lld times -- netcfgd "
		    "is leaving it alone rather than looping",
		    interface->name, (long long)seen.value, (long long)wanted.value,
		    (long long)restarts);
		return;
	}
	/*
	 * Said out loud because it is not free. A restart drops the lease for as
	 * long as the exchange takes, and an operator who sees their network blink
	 * deserves to find the reason in the plan rather than in a packet capture.
	 */
	ncfg_plan_warnf(builder->plan, interface->name,
	    "restarting the DHCP client on %s so its route takes metric %lld rather than "
	    "%lld; the lease is dropped for as long as the exchange takes", interface->name,
	    (long long)wanted.value, (long long)seen.value);

	reason = ncfg_plan_reason_differs(interface->name, "route.metric",
	    ncfg_plan_internf(builder->plan, "%lld", (long long)wanted.value),
	    ncfg_plan_internf(builder->plan, "%lld", (long long)seen.value));
	ncfg_plan_ids_extend(builder->plan, &deps, base);
	memset(&op, 0, sizeof(op));
	op.kind = NCFG_OP_BACKEND_STOP;
	op.u.backend.kind = NCFG_BACKEND_DHCP4;
	op.u.backend.iface = interface->name;
	memset(&inverse, 0, sizeof(inverse));
	inverse.kind = NCFG_OP_BACKEND_START;
	inverse.u.backend.kind = NCFG_BACKEND_DHCP4;
	inverse.u.backend.iface = interface->name;
	stop = ncfg_builder_push(builder, &op, &reason, deps.ids, deps.count, &inverse);
	ncfg_plan_ids_free(&deps);
	if (stop == NCFG_PLAN_NO_ACTION) {
		return;
	}
	/*
	 * **The start waits on the stop**, which is the whole of why this is two
	 * actions rather than a `backend.reload`: there is no reload for a DHCP
	 * client -- `ncfg_service_backend_supported` says only a router
	 * advertisement daemon has one -- and a start that raced its own stop
	 * would leave two clients on one interface, both retrying for ever.
	 */
	memset(&op, 0, sizeof(op));
	op.kind = NCFG_OP_BACKEND_START;
	op.u.backend.kind = NCFG_BACKEND_DHCP4;
	op.u.backend.iface = interface->name;
	memset(&inverse, 0, sizeof(inverse));
	inverse.kind = NCFG_OP_BACKEND_STOP;
	inverse.u.backend.kind = NCFG_BACKEND_DHCP4;
	inverse.u.backend.iface = interface->name;
	(void)ncfg_builder_push(builder, &op, &reason, &stop, 1u, &inverse);
}

/*
 * Restart a tunnel whose `.ovpn` is no longer the one it was started from.
 *
 * **The last of the "is what is running still what the document says"
 * questions** (0053), beside the wedged backend and the lease metric. netcfgd
 * never reads that file for meaning -- 0046 keeps it the operator's -- so what
 * is compared is a digest the observer took, the same trick a hook's `sha256`
 * plays on a script netcfgd equally does not interpret.
 *
 * **Devices rather than interfaces.** The `openvpn` block is a device's since
 * 0155 pass 1b, and a tunnel need not have an interface at all until it
 * reports an address -- so a tunnel with no `interface` block would never be
 * asked this if the walk were over interfaces.
 *
 * **Absent restarts nothing, and that was the whole of the hole it left.**
 * `config_matches` is deliberately absent where the file cannot be read, so a
 * working tunnel is never dropped over an unanswered question. What that cost
 * in the Rust was an operator who mistyped the path getting `nothing to do` on
 * every apply for ever, with the daemon running the configuration it was
 * started from and netcfgd calling the machine converged. The tunnel is still
 * left alone -- it is the best thing available -- and the operator is told.
 */
void ncfg_plan_stale_tunnel(ncfg_builder_t *builder, const ncfg_device_t *device)
{
	const ncfg_observed_backend_t *backend = NULL;
	ncfg_reason_t                  reason;
	ncfg_op_t                      op;
	ncfg_op_t                      inverse;
	uint32_t                       stop;
	size_t                         at;

	if (!device || !device->name || device->kind.kind != NCFG_KIND_OPENVPN) {
		return;
	}
	for (at = 0; at < builder->observed->backend_count; at++) {
		const ncfg_observed_backend_t *one = &builder->observed->backends[at];

		if (one->kind == (int)NCFG_BACKEND_OPENVPN && one->running && one->interface &&
		    strcmp(one->interface, device->name) == 0) {
			backend = one;
			break;
		}
	}
	if (!backend) {
		return;
	}
	if (backend->config_present.has && !backend->config_present.value) {
		ncfg_plan_warnf(builder->plan, device->name,
		    "the openvpn configuration for %s cannot be read, so netcfgd cannot tell "
		    "whether the running tunnel still matches it -- the tunnel is left alone "
		    "rather than dropped, and it is still running the file it was started with",
		    device->name);
		return;
	}
	if (!backend->config_matches.has || backend->config_matches.value) {
		return;
	}
	/*
	 * Said out loud because it is not free, which is `ncfg_plan_metric_restart`'s
	 * rule: openvpn reads its configuration once, so the only way to apply an
	 * edited file is to stop the daemon and start it again, and that drops the
	 * tunnel for as long as the handshake takes.
	 */
	ncfg_plan_warnf(builder->plan, device->name,
	    "the openvpn configuration for %s has changed since the tunnel was started, and "
	    "openvpn reads it once -- so the tunnel is restarted, which drops it for as long "
	    "as the handshake takes", device->name);

	reason = ncfg_plan_reason_differs(device->name, "openvpn.config",
	    "the file as it is now", "the file the tunnel was started from");
	memset(&op, 0, sizeof(op));
	op.kind = NCFG_OP_BACKEND_STOP;
	op.u.backend.kind = NCFG_BACKEND_OPENVPN;
	op.u.backend.iface = device->name;
	memset(&inverse, 0, sizeof(inverse));
	inverse.kind = NCFG_OP_BACKEND_START;
	inverse.u.backend.kind = NCFG_BACKEND_OPENVPN;
	inverse.u.backend.iface = device->name;
	stop = ncfg_builder_push(builder, &op, &reason, NULL, 0, &inverse);
	if (stop == NCFG_PLAN_NO_ACTION) {
		return;
	}
	/* The start waits on the stop, for `ncfg_plan_metric_restart`'s reason:
	 * there is no reload for a tunnel, and a start that raced its own stop
	 * would leave two openvpn daemons on one interface. */
	memset(&op, 0, sizeof(op));
	op.kind = NCFG_OP_BACKEND_START;
	op.u.backend.kind = NCFG_BACKEND_OPENVPN;
	op.u.backend.iface = device->name;
	memset(&inverse, 0, sizeof(inverse));
	inverse.kind = NCFG_OP_BACKEND_STOP;
	inverse.u.backend.kind = NCFG_BACKEND_OPENVPN;
	inverse.u.backend.iface = device->name;
	(void)ncfg_builder_push(builder, &op, &reason, &stop, 1u, &inverse);
}
