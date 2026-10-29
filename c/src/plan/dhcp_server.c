/*
 * dhcp_server.c -- what an interface hands out by DHCPv4 (decision 0297).
 *
 * WHERE THIS SITS IN THE ORDER
 *   After the interface's addressing, as `advertise` is: dnsmasq serves the
 *   network of the address it binds to, and one started before the address
 *   is there serves nothing.
 *
 * A CHANGED POLICY IS A RESTART
 *   dnsmasq re-reads its hosts and its leases on `SIGHUP`, and not its
 *   `dhcp-range`, so what the file says it serves is compared with what the
 *   document says, and a difference stops and starts it. The lease file is
 *   kept, so the hosts keep their addresses across it.
 */
#include "plan_internal.h"

#include "ncfg/base.h"
#include "ncfg/dhcp_server.h"

#include <string.h>

/* The running DHCP server on this interface, or NULL. */
static const ncfg_observed_backend_t *running_server(const ncfg_observed_t *observed,
    const char *name)
{
	size_t i;

	for (i = 0; i < observed->backend_count; i++) {
		const ncfg_observed_backend_t *backend = &observed->backends[i];

		if (backend->kind == NCFG_BACKEND_DHCP_SERVER && backend->running &&
		    backend->interface && name && strcmp(backend->interface, name) == 0) {
			return backend;
		}
	}
	return NULL;
}

void ncfg_plan_dhcp_server(ncfg_builder_t *builder, const ncfg_interface_t *interface,
    const ncfg_plan_ids_t *base, const ncfg_plan_ids_t *addressing)
{
	const ncfg_observed_backend_t *running;
	ncfg_plan_ids_t                deps = { NULL, 0, 0 };
	ncfg_plan_ids_t                started = { NULL, 0, 0 };
	char                           wanted[NCFG_DHCP_SERVER_SUMMARY_MAX];

	if (!interface->dhcp_server ||
	    !ncfg_dhcp_server_summary(interface, wanted, sizeof(wanted))) {
		return;
	}
	/* `dns` is never guessed (0297): say what an empty one means, since the
	 * hosts will join, get an address, and resolve nothing. */
	if (!interface->dhcp_server->dns_count) {
		ncfg_plan_warnf(builder->plan, interface->name,
		    "the DHCP server on %s offers no DNS server, so the hosts it serves get an "
		    "address and resolve no names: set `dns` in its `dhcp_server` block",
		    interface->name);
	}
	running = running_server(builder->observed, interface->name);
	if (running && running->served && strcmp(running->served, wanted) != 0) {
		ncfg_op_t     stop;
		ncfg_op_t     start;
		ncfg_reason_t reason;
		uint32_t      id;

		memset(&stop, 0, sizeof(stop));
		stop.kind = NCFG_OP_BACKEND_STOP;
		stop.u.backend.kind = NCFG_BACKEND_DHCP_SERVER;
		stop.u.backend.iface = interface->name;
		start = stop;
		start.kind = NCFG_OP_BACKEND_START;
		reason = ncfg_plan_reason_differs(interface->name, "dhcp_server",
		    ncfg_plan_intern(builder->plan, wanted),
		    ncfg_plan_intern(builder->plan, running->served));
		id = ncfg_builder_push(builder, &stop, &reason, NULL, 0, &start);
		if (id != NCFG_PLAN_NO_ACTION) {
			(void)ncfg_builder_push(builder, &start, &reason, &id, 1u, &stop);
		}
		return;
	}
	ncfg_plan_ids_extend(builder->plan, &deps, base);
	ncfg_plan_ids_extend(builder->plan, &deps, addressing);
	ncfg_plan_backend(builder, interface->name, NCFG_BACKEND_DHCP_SERVER, "dhcp_server", &deps,
	    &started);
	ncfg_plan_ids_free(&deps);
	ncfg_plan_ids_free(&started);
}
