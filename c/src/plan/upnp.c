/*
 * upnp.c -- the router's UPnP and NAT-PMP server, planned (0310).
 *
 * THE WARNING IS THE HOLDER'S CONDITION
 *   UPnP was asked for on the condition that the plan says what it costs,
 *   every time it is on: any device on the LAN may open a port on this
 *   router without asking. A warning rather than a refusal, and written on
 *   every plan rather than once, because the plan is what is read before
 *   an apply and the cost does not go away by having been read last week.
 *
 * KEYED BY THE UPLINK
 *   There is one miniupnpd per machine, and a backend op names an interface,
 *   so it names the one miniupnpd maps ports on. The daemon starts after the
 *   uplink and every LAN interface it listens on is up and addressed.
 */
#include "plan_internal.h"

#include "ncfg/base.h"
#include "ncfg/upnp.h"

#include <stdio.h>
#include <string.h>

/* The running miniupnpd, or NULL. */
static const ncfg_observed_backend_t *running_upnp(const ncfg_observed_t *observed)
{
	size_t i;

	for (i = 0; observed && i < observed->backend_count; i++) {
		const ncfg_observed_backend_t *backend = &observed->backends[i];

		if (backend->kind == NCFG_BACKEND_UPNP && backend->running) {
			return backend;
		}
	}
	return NULL;
}

/* Whether an action is on one of the interfaces miniupnpd needs ready. */
static int on_upnp_interface(const ncfg_upnp_t *upnp, const ncfg_action_t *action)
{
	const char *iface = ncfg_op_interface(&action->op);
	size_t      at;

	if (!iface) {
		return 0;
	}
	if (strcmp(iface, upnp->uplink) == 0) {
		return 1;
	}
	for (at = 0; at < upnp->lan_count; at++) {
		if (strcmp(iface, upnp->lan[at]) == 0) {
			return 1;
		}
	}
	return 0;
}

void ncfg_plan_upnp(ncfg_builder_t *builder)
{
	const ncfg_upnp_t             *upnp = builder->desired ? builder->desired->globals.upnp
	                                                       : NULL;
	const ncfg_observed_backend_t *running = running_upnp(builder->observed);
	ncfg_plan_ids_t                started = { NULL, 0, 0 };
	char                           wanted[NCFG_UPNP_SUMMARY_MAX];
	size_t                         at;

	if (!upnp || !upnp->uplink) {
		if (running && running->interface) {
			ncfg_op_t     stop;
			ncfg_reason_t reason;

			memset(&stop, 0, sizeof(stop));
			stop.kind = NCFG_OP_BACKEND_STOP;
			stop.u.backend.kind = NCFG_BACKEND_UPNP;
			stop.u.backend.iface = running->interface;
			reason = ncfg_plan_reason_differs(running->interface, "upnp", "<absent>",
			    ncfg_plan_intern(builder->plan, running->served ? running->served : ""));
			(void)ncfg_builder_push(builder, &stop, &reason, NULL, 0, NULL);
		}
		return;
	}
	ncfg_plan_warnf(builder->plan, upnp->uplink,
	    "UPnP and NAT-PMP are on: any device on %s%s may open a port on this router "
	    "without asking, and a compromised one can expose itself to the internet. Each "
	    "can only open ports to itself (secure mode), and none below 1024",
	    upnp->lan[0], upnp->lan_count > 1u ? " and the other LAN interfaces" : "");
	/* Warned, not opened: 0298's rule for a port forward, held to again. */
	if (!ncfg_plan_forward_accepts_translated(builder->desired)) {
		ncfg_plan_warnf(builder->plan, upnp->uplink,
		    "the firewall's forward chain drops by default and accepts no translated "
		    "connection, so every port UPnP maps is opened and then dropped. Add `accept "
		    "\"mapped\" { interface = \"%s\"; translated = true }` to `forward`",
		    upnp->uplink);
	}
	for (at = 0; at < upnp->lan_count; at++) {
		if (builder->desired && !ncfg_plan_input_accepts(builder->desired, upnp->lan[at],
		        NCFG_FIREWALL_PROTO_UDP, 1900)) {
			ncfg_plan_warnf(builder->plan, upnp->lan[at],
			    "the firewall's input chain drops by default with no rule accepting SSDP on "
			    "%s, so no client there finds the router. Add `accept \"upnp-%s\" { protocol "
			    "= \"udp\"; port = [1900, 5351]; interface = \"%s\" }` to `input`, and the "
			    "TCP port miniupnpd answers on", upnp->lan[at], upnp->lan[at], upnp->lan[at]);
		}
	}
	if (!ncfg_upnp_summary(upnp, wanted, sizeof(wanted))) {
		return;
	}
	if (running && running->served && strcmp(running->served, wanted) != 0) {
		ncfg_op_t     stop;
		ncfg_op_t     start;
		ncfg_reason_t reason;
		uint32_t      id;

		memset(&stop, 0, sizeof(stop));
		stop.kind = NCFG_OP_BACKEND_STOP;
		stop.u.backend.kind = NCFG_BACKEND_UPNP;
		stop.u.backend.iface = running->interface;
		start = stop;
		start.kind = NCFG_OP_BACKEND_START;
		start.u.backend.iface = upnp->uplink;
		reason = ncfg_plan_reason_differs(upnp->uplink, "upnp",
		    ncfg_plan_intern(builder->plan, wanted),
		    ncfg_plan_intern(builder->plan, running->served));
		id = ncfg_builder_push(builder, &stop, &reason, NULL, 0, &start);
		if (id != NCFG_PLAN_NO_ACTION) {
			(void)ncfg_builder_push(builder, &start, &reason, &id, 1u, &stop);
		}
		return;
	}
	{
		ncfg_plan_ids_t ready = { NULL, 0, 0 };

		for (at = 0; at < builder->plan->action_count; at++) {
			if (on_upnp_interface(upnp, &builder->plan->actions[at])) {
				ncfg_plan_ids_push(builder->plan, &ready, builder->plan->actions[at].id);
			}
		}
		ncfg_plan_backend(builder, upnp->uplink, NCFG_BACKEND_UPNP, "upnp", &ready, &started);
		ncfg_plan_ids_free(&ready);
	}
	ncfg_plan_ids_free(&started);
}
