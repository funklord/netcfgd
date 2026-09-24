/*
 * service.c -- the machine's paths in one place, and the dispatch over the
 * fourteen service-side ops.
 *
 * WHY THE DISPATCH IS HERE AND NOT IN `kernel.c`
 *   `kernel.c` owns a netlink socket and nothing else. Fourteen of the
 *   forty-eight ops need none of it and need a great deal this does -- a run
 *   directory, the document, a secret resolver, three programs -- so folding
 *   them into that file would put all of that in the public face of the
 *   netlink executor, which is the struct `ncfg_kernel_new` builds out of a
 *   socket alone. Here the seam is one function and one borrowed context, and
 *   `kernel.c`'s arms are a line each.
 *
 * WHY THERE IS NO `default:` IN THE SWITCH
 *   `apply.c`'s rule and for its reason: a wildcard is what let a kind be added
 *   twice in this project without an answer, and `-Wswitch` is the only thing
 *   that can notice. Every op in the taxonomy is listed, so an op added to it
 *   fails to compile here rather than falling quietly into the arm that says
 *   this module does not carry it.
 */
#include "ncfg/service.h"

#include "ncfg/base.h"
#include "ncfg/observe.h"
#include "ncfg/radio.h"
#include "ncfg/state.h"
#include "ncfg/supplicant.h"

#include <string.h>

void ncfg_service_machine(ncfg_service_t *out)
{
	/*
	 * Static because `ncfg_service_t` borrows every path in it and this one is
	 * resolved rather than a constant: `ncfg_radio_class_net` reads
	 * `NCFG_SYS_CLASS_NET` and falls back to the conventional directory, so
	 * there is no literal to point at. One machine per process, and the answer
	 * does not change while it runs.
	 */
	static char class_net[NCFG_SERVICE_CLASS_NET_MAX];

	if (!out) {
		return;
	}
	/*
	 * Named constants rather than literals, every one of them owned by the
	 * module that reads the same file: `observe.h` reads the sysctls this
	 * module writes, `dns.h` reads and writes the resolver's three, and
	 * `state.h` owns the run directory. A second spelling of any of them is a
	 * pair that can stop agreeing, and this is the pair where disagreeing
	 * means a value written where nothing looks for it.
	 */
	out->run_dir = NCFG_RUN_DIR_DEFAULT;
	out->proc_root = NCFG_OBSERVE_PROC_ROOT_DEFAULT;
	out->supplicant_dir = NCFG_SUPPLICANT_CTRL_DIR;
	out->dns.resolv_conf = NCFG_RESOLV_CONF;
	out->dns.dnsmasq_conf = NCFG_DNSMASQ_CONF;
	out->dns.unbound_conf = NCFG_UNBOUND_CONF;
	out->dns.run_dir = NCFG_RUN_DIR_DEFAULT;
	/* And the DHCP client's, which `dhcp.h` owns for the same reason: the hook
	 * netcfgd ships, dhcpcd's own run directory -- which is dhcpcd's and not
	 * netcfgd's, and is why a mark is still readable when `/run/netcfgd` has
	 * gone -- and the operator's configuration that `-f` points at. The three
	 * programs stay NULL, which means "find the conventional name". */
	ncfg_dhcp_machine(&out->dhcp);
	/* And a PPPoE session's, which `pppoe.h` owns for that reason: which pppd
	 * to run stays NULL, and the directories pppd's own pid file may be in
	 * are the list that header publishes. */
	ncfg_pppoe_machine(&out->pppoe);
	/*
	 * And what `backend.start` asks before it starts a supplicant, which
	 * `apply.h` owns and `radio.h` owns respectively. Named here for this
	 * function's reason: a test asserts what a daemon reads by reading this,
	 * rather than by anything writing near the machine's own `/run`.
	 *
	 * `ncfg_radio_class_net` can fail only by having nowhere to put the
	 * answer, and there is somewhere; an empty string then asks nothing, which
	 * is this member's documented absent state rather than an error to carry
	 * out of a function that reports none.
	 */
	ncfg_contention_machine(&out->contention);
	if (!ncfg_radio_class_net(class_net, sizeof(class_net), NULL, 0)) {
		class_net[0] = '\0';
	}
	out->class_net = class_net[0] ? class_net : NULL;
}

int ncfg_service_execute(const ncfg_service_t *service, const ncfg_op_t *op, char *err,
    size_t err_size)
{
	if (!op) {
		ncfg_error_set(err, err_size, "there is no op to carry out");
		return 0;
	}
	if (!service) {
		/*
		 * The case a caller is most likely to reach: an executor opened with
		 * `ncfg_kernel_new` alone can carry out the netlink half of a plan and
		 * none of this. Saying which half is missing beats a NULL dereference
		 * in the one module that changes machines, and beats a refusal that
		 * reads as "this op is not implemented" -- it is, and this executor was
		 * not given what it needs.
		 */
		ncfg_error_set(err, err_size,
		    "%s is carried out away from netlink, and this executor was given no "
		    "service context to do it with", ncfg_op_name(op));
		return 0;
	}
	switch ((ncfg_op_kind_t)op->kind) {
	case NCFG_OP_BACKEND_START:
		return ncfg_service_backend_start(service, op->u.backend.kind, op->u.backend.iface,
		    err, err_size);
	case NCFG_OP_BACKEND_STOP:
		return ncfg_service_backend_stop(service, op->u.backend.kind, op->u.backend.iface,
		    err, err_size);
	case NCFG_OP_BACKEND_RELOAD:
		return ncfg_service_backend_reload(service, op->u.backend.kind,
		    op->u.backend.iface, err, err_size);
	case NCFG_OP_DNS_APPLY:
		return ncfg_service_dns_apply(service, op->u.dns.scope, op->u.dns.policy, err,
		    err_size);
	case NCFG_OP_HOSTNAME_SET:
		return ncfg_service_set_hostname(service->proc_root, op->u.named.name, err,
		    err_size);
	case NCFG_OP_SYSCTL_SET_FORWARDING:
		return ncfg_service_set_forwarding(service->proc_root, op->u.forwarding.iface,
		    op->u.forwarding.enabled, err, err_size);
	case NCFG_OP_SYSCTL_SET_PRIVACY:
		return ncfg_service_set_privacy(service->proc_root, op->u.privacy.iface,
		    op->u.privacy.prefer_temporary, err, err_size);
	case NCFG_OP_SYSCTL_SET_ACCEPT_RA:
		return ncfg_service_set_accept_ra(service->proc_root, op->u.accept_ra.iface,
		    op->u.accept_ra.value, err, err_size);
	case NCFG_OP_WIFI_SET_PROFILES:
		return ncfg_service_set_profiles(service, op->u.set_profiles.device, err, err_size);
	case NCFG_OP_WIFI_ASSOCIATE:
		return ncfg_service_associate(service, op->u.associate.device,
		    op->u.associate.network_id, err, err_size);
	case NCFG_OP_WIFI_DISASSOCIATE:
		return ncfg_service_disassociate(service, op->u.device.device, err, err_size);
	case NCFG_OP_WIFI_SET_REGDOM:
		return ncfg_service_set_regdom(service, op->u.regdom.device, op->u.regdom.country,
		    err, err_size);
	case NCFG_OP_ACCESS_CONTROL_ADD:
		return ncfg_service_access_control(service->run_dir, op->u.access_control.iface,
		    op->u.access_control.list, op->u.access_control.station, 1,
		    service->patience_ms, err, err_size);
	case NCFG_OP_ACCESS_CONTROL_DEL:
		return ncfg_service_access_control(service->run_dir, op->u.access_control.iface,
		    op->u.access_control.list, op->u.access_control.station, 0,
		    service->patience_ms, err, err_size);
	/* Everything else, listed so that `-Wswitch` notices an op added to the
	 * taxonomy and not answered anywhere. */
	case NCFG_OP_LINK_CREATE:
	case NCFG_OP_LINK_DELETE:
	case NCFG_OP_LINK_SET_MTU:
	case NCFG_OP_LINK_SET_MAC:
	case NCFG_OP_LINK_SET_MASTER:
	case NCFG_OP_LINK_UNSET_MASTER:
	case NCFG_OP_LINK_UP:
	case NCFG_OP_LINK_DOWN:
	case NCFG_OP_ADDR_ADD:
	case NCFG_OP_ADDR_DEL:
	case NCFG_OP_ROUTE_ADD:
	case NCFG_OP_ROUTE_DEL:
	case NCFG_OP_BRIDGE_VLAN_ADD:
	case NCFG_OP_BRIDGE_VLAN_DEL:
	case NCFG_OP_LINK_SET_BOND:
	case NCFG_OP_LINK_SET_BRIDGE:
	case NCFG_OP_LINK_SET_MACVLAN:
	case NCFG_OP_LINK_SET_TUNNEL:
	case NCFG_OP_LINK_SET_VXLAN:
	case NCFG_OP_WG_SET_DEVICE:
	case NCFG_OP_WG_SET_PEERS:
	case NCFG_OP_LINK_SET_OFFLOADS:
	case NCFG_OP_LINK_SET_IPV6_TOKEN:
	case NCFG_OP_RULE_ADD:
	case NCFG_OP_RULE_DEL:
	case NCFG_OP_QDISC_SET:
	case NCFG_OP_QDISC_RESET:
	case NCFG_OP_INGRESS_REDIRECT:
	case NCFG_OP_INGRESS_REDIRECT_CLEAR:
	case NCFG_OP_NAT_REPLACE:
	case NCFG_OP_HOOK_RUN:
	case NCFG_OP_COMMIT_ARM:
	case NCFG_OP_COMMIT_CONFIRM:
	case NCFG_OP_COMMIT_REVERT:
		break;
	}
	ncfg_error_set(err, err_size,
	    "%s is not one of the ops carried out away from netlink; handing it here is a "
	    "defect in the executor, not in the plan", ncfg_op_name(op));
	return 0;
}
