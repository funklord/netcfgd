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
	    !ncfg_dhcp_server_summary(builder->desired, interface, wanted, sizeof(wanted))) {
		return;
	}
	/* `dns` is never guessed (0297): say what an empty one means, since the
	 * hosts will join, get an address, and resolve nothing -- unless this
	 * server also answers DNS, and then it offers itself (0301). */
	if (!interface->dhcp_server->dns_count && !interface->dhcp_server->dns_forward &&
	    !interface->dhcp_server->relay_count) {
		ncfg_plan_warnf(builder->plan, interface->name,
		    "the DHCP server on %s offers no DNS server, so the hosts it serves get an "
		    "address and resolve no names: set `dns_forward = true` to answer them from "
		    "this router, or `dns` to name a server, in its `dhcp_server` block",
		    interface->name);
	}
	/* **Warned, not opened** (0301, as 0298 for a forward): a firewall that
	 * drops what the server listens for is the operator's to open, and a rule
	 * nobody wrote is the opposite of layer one's named rules. 67 was missing
	 * from 0297; it is the same failure with less to show for it. */
	if (builder->desired && !ncfg_plan_input_accepts(builder->desired, interface->name,
	        NCFG_FIREWALL_PROTO_UDP, 67)) {
		ncfg_plan_warnf(builder->plan, interface->name,
		    "the firewall's input chain drops by default with no rule accepting DHCP on %s, "
		    "so the server there is never asked. Add `accept \"dhcp-%s\" { protocol = "
		    "\"udp\"; port = [67]; interface = \"%s\" }` to `input`", interface->name,
		    interface->name, interface->name);
	}
	if (interface->dhcp_server->dns_forward && builder->desired &&
	    !ncfg_plan_input_accepts(builder->desired, interface->name, NCFG_FIREWALL_PROTO_UDP,
	        53)) {
		ncfg_plan_warnf(builder->plan, interface->name,
		    "the firewall's input chain drops by default with no rule accepting DNS on %s, "
		    "so the forwarder there answers nobody. Add `accept \"dns-%s\" { protocol = "
		    "\"udp\"; port = [53]; interface = \"%s\" }` to `input`", interface->name,
		    interface->name, interface->name);
	}
	/* DHCPv6 (0303): a host asks only when a router advertisement tells it
	 * to, and that is the interface's `advertise`, not this server's. */
	if (interface->dhcp_server->range6_start &&
	    (!interface->advertise || !interface->advertise->managed)) {
		/* `advertise` takes a delegated prefix only, so on a static one there
		 * is no block to add the flag to; said, rather than advice that
		 * cannot be followed. */
		ncfg_plan_warnf(builder->plan, interface->name,
		    "the DHCP server on %s hands out IPv6 addresses, and no router advertisement on "
		    "it tells the hosts to ask: %s", interface->name,
		    interface->advertise
		        ? "add `managed = true` to its `advertise` block"
		        : "an `advertise` block with `managed = true` does, and it advertises a "
		          "delegated prefix only -- on a static prefix, hosts must be set to ask");
	}
	if (interface->dhcp_server->range6_start && builder->desired &&
	    !ncfg_plan_input_accepts(builder->desired, interface->name, NCFG_FIREWALL_PROTO_UDP,
	        547)) {
		ncfg_plan_warnf(builder->plan, interface->name,
		    "the firewall's input chain drops by default with no rule accepting DHCPv6 on %s, "
		    "so the server there is never asked. Add `accept \"dhcpv6-%s\" { protocol = "
		    "\"udp\"; port = [547]; interface = \"%s\" }` to `input`", interface->name,
		    interface->name, interface->name);
	}
	/* A list file not there yet, or past the bound, is left out and the
	 * server runs without it (0305): said, since the LAN looks filtered and
	 * is not. */
	for (size_t at = 0; interface->dhcp_server->dns_forward && builder->desired &&
	     at < interface->dhcp_server->block_count; at++) {
		size_t list;

		for (list = 0; list < builder->desired->block_list_count; list++) {
			const ncfg_block_list_t *named = &builder->desired->block_lists[list];
			size_t                   file;

			if (strcmp(named->name, interface->dhcp_server->block[at]) != 0) {
				continue;
			}
			for (file = 0; file < named->file_count; file++) {
				if (!ncfg_block_list_file_usable(named->file[file])) {
					ncfg_plan_warnf(builder->plan, interface->name,
					    "block list `%s` names %s, which is not there or is past %llu MiB, "
					    "so %s blocks without it",
					    named->name, named->file[file],
					    (unsigned long long)(NCFG_BLOCK_FILE_MAX / (1024u * 1024u)),
					    interface->name);
				}
			}
		}
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

void ncfg_plan_dns_record_warnings(ncfg_builder_t *builder)
{
	const ncfg_document_t *desired = builder->desired;
	size_t                 at;

	if (!desired || !desired->dns_record_count) {
		return;
	}
	for (at = 0; at < desired->interface_count; at++) {
		const ncfg_dhcp_server_t *server = desired->interfaces[at].dhcp_server;

		if (server && server->dns_forward) {
			return;
		}
	}
	/* Records are the forwarder's to answer, and nothing forwards: an
	 * operator who wrote `nas.home.lan` would find it resolving nowhere. */
	ncfg_plan_warnf(builder->plan, NULL,
	    "%zu DNS record%s, starting with `%s`, will not be answered: records are served by a "
	    "`dhcp_server` with `dns_forward = true`, and none has it",
	    desired->dns_record_count, desired->dns_record_count == 1u ? "" : "s",
	    desired->dns_records[0].name);
}

void ncfg_plan_block_list_warnings(ncfg_builder_t *builder)
{
	const ncfg_document_t *desired = builder->desired;
	size_t                 at;

	if (!desired) {
		return;
	}
	for (at = 0; at < desired->block_list_count; at++) {
		const char *name = desired->block_lists[at].name;
		size_t      one;
		int         used = 0;

		for (one = 0; !used && one < desired->interface_count; one++) {
			const ncfg_dhcp_server_t *server = desired->interfaces[one].dhcp_server;
			size_t                    named;

			for (named = 0; server && named < server->block_count; named++) {
				used = used || strcmp(server->block[named], name) == 0;
			}
		}
		/* A list is applied where a server names it (0305), so one nothing
		 * names blocks nothing -- the shape of a list somebody meant to turn
		 * on. */
		if (!used) {
			ncfg_plan_warnf(builder->plan, NULL,
			    "block list `%s` is applied by no DHCP server: add `block = [\"%s\"]` to "
			    "the `dhcp_server` of each network it should filter", name, name);
		}
	}
}
