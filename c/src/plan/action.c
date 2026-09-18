/*
 * action.c -- the four questions every op has to answer.
 *
 * Its name, whether it can cut somebody off, whether it is about the host
 * rather than an interface, and which interface it names. The Rust keeps them
 * as four `match`es over one enum and so does this, for the reason the frozen
 * witness exists: a fifth copy of the list is a fifth thing to disagree.
 *
 * **There is no `default:` arm in any of the four.** A wildcard is what let a
 * kind be added twice in this project without an answer, and `-Wswitch` is the
 * only thing here that can notice. Every switch lists every op.
 */
#include "ncfg/plan.h"

#include <stddef.h>

const char *ncfg_op_name(const ncfg_op_t *op)
{
	switch ((ncfg_op_kind_t)op->kind) {
	case NCFG_OP_LINK_CREATE:
		return "link.create";
	case NCFG_OP_LINK_DELETE:
		return "link.delete";
	case NCFG_OP_LINK_SET_MTU:
		return "link.set_mtu";
	case NCFG_OP_LINK_SET_MAC:
		return "link.set_mac";
	case NCFG_OP_LINK_SET_MASTER:
		return "link.set_master";
	case NCFG_OP_LINK_UNSET_MASTER:
		return "link.unset_master";
	case NCFG_OP_LINK_UP:
		return "link.up";
	case NCFG_OP_LINK_DOWN:
		return "link.down";
	case NCFG_OP_ADDR_ADD:
		return "addr.add";
	case NCFG_OP_ADDR_DEL:
		return "addr.del";
	case NCFG_OP_ROUTE_ADD:
		return "route.add";
	case NCFG_OP_ROUTE_DEL:
		return "route.del";
	case NCFG_OP_BACKEND_START:
		return "backend.start";
	case NCFG_OP_BACKEND_STOP:
		return "backend.stop";
	case NCFG_OP_BACKEND_RELOAD:
		return "backend.reload";
	case NCFG_OP_BRIDGE_VLAN_ADD:
		return "bridge.vlan.add";
	case NCFG_OP_BRIDGE_VLAN_DEL:
		return "bridge.vlan.del";
	case NCFG_OP_WIFI_SET_PROFILES:
		return "wifi.set_profiles";
	case NCFG_OP_WIFI_ASSOCIATE:
		return "wifi.associate";
	case NCFG_OP_WIFI_DISASSOCIATE:
		return "wifi.disassociate";
	case NCFG_OP_WIFI_SET_REGDOM:
		return "wifi.set_regdom";
	case NCFG_OP_ACCESS_CONTROL_ADD:
		return "access_control.add";
	case NCFG_OP_ACCESS_CONTROL_DEL:
		return "access_control.del";
	case NCFG_OP_LINK_SET_BOND:
		return "link.set_bond";
	case NCFG_OP_LINK_SET_BRIDGE:
		return "link.set_bridge";
	case NCFG_OP_LINK_SET_MACVLAN:
		return "link.set_macvlan";
	case NCFG_OP_LINK_SET_TUNNEL:
		return "link.set_tunnel";
	case NCFG_OP_LINK_SET_VXLAN:
		return "link.set_vxlan";
	case NCFG_OP_WG_SET_DEVICE:
		return "wg.set_device";
	case NCFG_OP_WG_SET_PEERS:
		return "wg.set_peers";
	case NCFG_OP_DNS_APPLY:
		return "dns.apply";
	case NCFG_OP_LINK_SET_OFFLOADS:
		return "link.set_offloads";
	case NCFG_OP_LINK_SET_IPV6_TOKEN:
		return "link.set_ipv6_token";
	case NCFG_OP_RULE_ADD:
		return "rule.add";
	case NCFG_OP_RULE_DEL:
		return "rule.del";
	case NCFG_OP_QDISC_SET:
		return "qdisc.set";
	case NCFG_OP_QDISC_RESET:
		return "qdisc.reset";
	case NCFG_OP_INGRESS_REDIRECT:
		return "ingress.redirect";
	case NCFG_OP_INGRESS_REDIRECT_CLEAR:
		return "ingress.redirect.clear";
	case NCFG_OP_SYSCTL_SET_FORWARDING:
		return "sysctl.set_forwarding";
	case NCFG_OP_SYSCTL_SET_PRIVACY:
		return "sysctl.set_privacy";
	case NCFG_OP_SYSCTL_SET_ACCEPT_RA:
		return "sysctl.set_accept_ra";
	case NCFG_OP_HOSTNAME_SET:
		return "hostname.set";
	case NCFG_OP_NAT_REPLACE:
		return "nat.replace";
	case NCFG_OP_HOOK_RUN:
		return "hook.run";
	case NCFG_OP_COMMIT_ARM:
		return "commit.arm";
	case NCFG_OP_COMMIT_CONFIRM:
		return "commit.confirm";
	case NCFG_OP_COMMIT_REVERT:
		return "commit.revert";
	}
	return "";
}

/*
 * Whether this action can interrupt traffic on the interface it touches.
 *
 * `link.set_mtu` counts as disruptive deliberately. Lowering an MTU interrupts
 * traffic in flight and raising it can black-hole a path until PMTU discovery
 * catches up; a guard that allowed it for convenience would be a guard nobody
 * could rely on.
 */
int ncfg_op_is_disruptive(const ncfg_op_t *op)
{
	switch ((ncfg_op_kind_t)op->kind) {
	case NCFG_OP_LINK_DELETE:
	case NCFG_OP_LINK_DOWN:
	case NCFG_OP_LINK_SET_MASTER:
	case NCFG_OP_LINK_UNSET_MASTER:
	case NCFG_OP_LINK_SET_MAC:
	case NCFG_OP_LINK_SET_MTU:
	case NCFG_OP_ADDR_DEL:
	case NCFG_OP_ROUTE_DEL:
	case NCFG_OP_BACKEND_STOP:
	case NCFG_OP_BACKEND_RELOAD:
	case NCFG_OP_WIFI_DISASSOCIATE:
	case NCFG_OP_WIFI_ASSOCIATE:
	case NCFG_OP_WG_SET_DEVICE:
	case NCFG_OP_WG_SET_PEERS:
	/* Spanning tree converging is a bridge not forwarding for as long as the
	 * forward delay says, which on a live bridge is traffic stopping. */
	case NCFG_OP_LINK_SET_BRIDGE:
	/* Changing a bond's mode restarts how traffic is distributed across its
	 * members, which on a live bond is a pause. */
	case NCFG_OP_LINK_SET_BOND:
	/* A macvlan's mode is how it sees the other macvlans on the same NIC, so
	 * changing it moves what can reach what -- and the kernel takes it on a
	 * live device, which is exactly when that matters. */
	case NCFG_OP_LINK_SET_MACVLAN:
	/* Moving a tunnel's endpoint moves the far end: everything inside the
	 * tunnel stops until the other side agrees. The same for a VXLAN, whose
	 * remote is where the encapsulated frames go. */
	case NCFG_OP_LINK_SET_TUNNEL:
	case NCFG_OP_LINK_SET_VXLAN:
	/* Removing a VLAN from a port stops traffic in it reaching that port,
	 * which is the same kind of interruption as taking an address away. */
	case NCFG_OP_BRIDGE_VLAN_DEL:
	/* Withdrawing a rule sends traffic back to the main table, which on a
	 * policy-routed host is the difference between reaching a network and
	 * not. Clearing a redirect stops everything arriving on the interface
	 * being shaped, which on a saturated line is the same kind of loss. */
	case NCFG_OP_RULE_DEL:
	case NCFG_OP_INGRESS_REDIRECT_CLEAR:
		return 1;
	/*
	 * Turning forwarding off cuts every host behind this interface off from
	 * everything in front of it, which is a worse interruption than taking one
	 * address away. Turning it on interrupts nothing, so a guard has no reason
	 * to block it and blocking it would leave a router that cannot route.
	 */
	case NCFG_OP_SYSCTL_SET_FORWARDING:
		return !op->u.forwarding.enabled;
	/*
	 * Directional, and it is hostapd that makes it so rather than a judgement
	 * here: `DENY_ACL ADD_MAC` calls `hostapd_disassoc_deny_mac` and
	 * `ACCEPT_ACL DEL_MAC` calls `hostapd_disassoc_accept_mac`, so those two
	 * take a device off the network as part of doing what they were asked. The
	 * other two directions grant access and interrupt nobody.
	 *
	 * A guard on the radio therefore blocks exactly the edit that disconnects
	 * somebody, which is what an operator adding a station to a deny list is
	 * doing on purpose -- and what an operator deleting the wrong line from an
	 * allow list is doing by accident.
	 */
	case NCFG_OP_ACCESS_CONTROL_ADD:
		return op->u.access_control.list == NCFG_ACL_POLICY_DENY;
	case NCFG_OP_ACCESS_CONTROL_DEL:
		return op->u.access_control.list == NCFG_ACL_POLICY_ALLOW;
	/*
	 * A hook is arbitrary shell and netcfgd cannot know what it does. What it
	 * does know is which transition the hook belongs to, and the down phases
	 * belong to one that takes the interface away -- so a guard has to refuse
	 * them with the `link.down` they bracket. Getting this wrong is worse than
	 * an unguarded interface: the script that unmounts the share runs, the
	 * guard keeps the interface up, and the operator is left with a working
	 * link and no mount. Found by a fixture asserting the pair, decision 0063.
	 *
	 * The up phases are not disruptive: they belong to bringing an interface
	 * *into* service, which a guard exists to protect rather than to prevent.
	 */
	case NCFG_OP_HOOK_RUN:
		return op->u.hook.phase == NCFG_HOOK_PHASE_PRE_DOWN ||
		    op->u.hook.phase == NCFG_HOOK_PHASE_DOWN ||
		    op->u.hook.phase == NCFG_HOOK_PHASE_POST_DOWN;
	case NCFG_OP_LINK_CREATE:
	case NCFG_OP_LINK_UP:
	case NCFG_OP_ADDR_ADD:
	case NCFG_OP_ROUTE_ADD:
	case NCFG_OP_BACKEND_START:
	case NCFG_OP_WIFI_SET_PROFILES:
	case NCFG_OP_WIFI_SET_REGDOM:
	case NCFG_OP_DNS_APPLY:
	case NCFG_OP_COMMIT_ARM:
	case NCFG_OP_COMMIT_CONFIRM:
	case NCFG_OP_BRIDGE_VLAN_ADD:
	/* Replacing a qdisc discards whatever is queued on the interface, which is
	 * a few milliseconds of loss that TCP absorbs -- not the kind of
	 * interruption a guard exists to prevent. Calling it disruptive would
	 * block the one change that fixes a link already dropping packets from
	 * bufferbloat. */
	case NCFG_OP_QDISC_SET:
	case NCFG_OP_QDISC_RESET:
	case NCFG_OP_INGRESS_REDIRECT:
	/* Not because replacing the table is harmless -- withdrawing NAT cuts off
	 * a whole LAN. It is because this op names no interface, so no guard can
	 * match it anyway, and claiming otherwise would suggest a protection that
	 * does not exist. The commit-confirm inverse is what covers this one. */
	case NCFG_OP_NAT_REPLACE:
	/* Adding a rule changes which table a packet consults, which can move
	 * traffic -- but a guard protects an interface, and a rule names at most
	 * one incidentally. Removing one is the disruptive direction, above. */
	case NCFG_OP_RULE_ADD:
	/* Changing the host half of an address the router supplies does change an
	 * address -- but SLAAC addresses are not netcfgd's and the old one lingers
	 * until it expires, so nothing is cut off at the moment of the change. */
	case NCFG_OP_LINK_SET_IPV6_TOKEN:
	/* The hostname is not traffic. Changing it can confuse something that
	 * cached it -- a Kerberos ticket, a shell prompt -- but nothing in flight
	 * is cut, and a guard exists to protect a connection. */
	case NCFG_OP_HOSTNAME_SET:
	/* Turning temporary addresses on adds an address and prefers it for new
	 * connections; turning them off stops new ones being made. The stable
	 * address is there throughout, unlike `addr.del`. */
	case NCFG_OP_SYSCTL_SET_PRIVACY:
	/* Making the kernel listen to advertisements adds an address; giving the
	 * interface back stops new ones arriving and takes nothing away that is
	 * already there. Neither cuts a connection. */
	case NCFG_OP_SYSCTL_SET_ACCEPT_RA:
	/* Toggling an offload re-initialises the driver's transmit path on some
	 * hardware, which drops what is queued. That is a packet or two, not a
	 * lost session -- and a guard that blocked it would block the change most
	 * often made to fix a NIC that is already corrupting traffic. */
	case NCFG_OP_LINK_SET_OFFLOADS:
	case NCFG_OP_COMMIT_REVERT:
		return 0;
	}
	return 0;
}

int ncfg_op_is_host_wide_config(const ncfg_op_t *op)
{
	return op->kind == NCFG_OP_DNS_APPLY || op->kind == NCFG_OP_HOSTNAME_SET;
}

const char *ncfg_op_interface(const ncfg_op_t *op)
{
	switch ((ncfg_op_kind_t)op->kind) {
	case NCFG_OP_LINK_CREATE:
		return op->u.link_create.name;
	case NCFG_OP_LINK_SET_MTU:
		return op->u.set_mtu.name;
	case NCFG_OP_LINK_SET_MAC:
		return op->u.set_mac.name;
	case NCFG_OP_LINK_SET_MASTER:
		return op->u.set_master.name;
	case NCFG_OP_LINK_SET_BOND:
		return op->u.set_bond.name;
	case NCFG_OP_LINK_SET_IPV6_TOKEN:
		return op->u.set_ipv6_token.name;
	case NCFG_OP_LINK_SET_OFFLOADS:
		return op->u.set_offloads.name;
	case NCFG_OP_LINK_DELETE:
	case NCFG_OP_LINK_UNSET_MASTER:
	case NCFG_OP_LINK_UP:
	case NCFG_OP_LINK_DOWN:
	case NCFG_OP_LINK_SET_BRIDGE:
	case NCFG_OP_LINK_SET_MACVLAN:
	case NCFG_OP_LINK_SET_TUNNEL:
	case NCFG_OP_LINK_SET_VXLAN:
		return op->u.named.name;
	case NCFG_OP_ADDR_ADD:
		return op->u.addr_add.iface;
	case NCFG_OP_ADDR_DEL:
		return op->u.addr_del.iface;
	case NCFG_OP_ROUTE_ADD:
	case NCFG_OP_ROUTE_DEL:
		return op->u.route.iface;
	case NCFG_OP_BACKEND_START:
	case NCFG_OP_BACKEND_STOP:
	case NCFG_OP_BACKEND_RELOAD:
		return op->u.backend.iface;
	case NCFG_OP_BRIDGE_VLAN_ADD:
	case NCFG_OP_BRIDGE_VLAN_DEL:
		return op->u.bridge_vlan.iface;
	case NCFG_OP_WIFI_SET_PROFILES:
		return op->u.set_profiles.device;
	case NCFG_OP_WIFI_ASSOCIATE:
		return op->u.associate.device;
	case NCFG_OP_WIFI_DISASSOCIATE:
		return op->u.device.device;
	case NCFG_OP_WIFI_SET_REGDOM:
		return op->u.regdom.device;
	case NCFG_OP_ACCESS_CONTROL_ADD:
	case NCFG_OP_ACCESS_CONTROL_DEL:
		return op->u.access_control.iface;
	case NCFG_OP_WG_SET_DEVICE:
		return op->u.wg_device.iface;
	case NCFG_OP_WG_SET_PEERS:
		return op->u.wg_peers.iface;
	case NCFG_OP_QDISC_SET:
		return op->u.qdisc.iface;
	case NCFG_OP_QDISC_RESET:
	case NCFG_OP_INGRESS_REDIRECT_CLEAR:
		return op->u.iface.iface;
	case NCFG_OP_INGRESS_REDIRECT:
		return op->u.redirect.iface;
	case NCFG_OP_SYSCTL_SET_FORWARDING:
		return op->u.forwarding.iface;
	case NCFG_OP_SYSCTL_SET_PRIVACY:
		return op->u.privacy.iface;
	case NCFG_OP_SYSCTL_SET_ACCEPT_RA:
		return op->u.accept_ra.iface;
	case NCFG_OP_HOOK_RUN:
		return op->u.hook.iface;
	/*
	 * Deliberately not attributed to an interface even though several name
	 * one. The nftables table is one object and replacing it is one change to
	 * the host, so a guard on any single uplink has no standing to refuse it.
	 * A rule is host-wide: `iif`/`oif` are selectors, not ownership. The
	 * hostname belongs to the machine, not to the device whose lease suggested
	 * it. And a DNS scope is delivered by a backend that serves the host.
	 */
	case NCFG_OP_RULE_ADD:
	case NCFG_OP_RULE_DEL:
	case NCFG_OP_NAT_REPLACE:
	case NCFG_OP_HOSTNAME_SET:
	case NCFG_OP_DNS_APPLY:
	case NCFG_OP_COMMIT_ARM:
	case NCFG_OP_COMMIT_CONFIRM:
	case NCFG_OP_COMMIT_REVERT:
		return NULL;
	}
	return NULL;
}
