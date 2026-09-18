/*
 * write.c -- a plan as the control socket sends it.
 *
 * WHAT THIS HAS TO GET RIGHT
 *   `ncfg plan --json` is what a script reads before deciding whether to
 *   apply, the TUI's plan pane is built from it, and
 *   `/run/netcfgd/plan.last.json` is how an interrupted apply says which
 *   actions ran. An op renamed here is renamed under all three silently, which
 *   is why `doc/schema/plan.json` is a frozen witness and why `plan_test.c`
 *   writes the whole surface back at it byte for byte.
 *
 * THE ONE RULE THAT IS NOT OBVIOUS
 *   **An absent optional member is written as `null`, not omitted.** Exactly
 *   three members in this whole surface are omitted when absent -- a hook's
 *   `value`, a reason's `interface` and an action's `inverse` -- because those
 *   three carry `skip_serializing_if` in the Rust and the rest do not. So an
 *   `addr.add` with no lifetimes writes `"preferred_lifetime":null`, and a
 *   writer that tidied that away would produce a line the Rust cannot read
 *   back into the same value. Whether an absent lifetime *should* be omitted
 *   is a question for the schema, not for a port.
 */
#include "plan_internal.h"

#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/json_write.h"
#include "ncfg/observed.h"
#include "ncfg/plan.h"
#include "ncfg/value.h"

#include <stddef.h>

/* An optional integer: its value, or `null`. See the file comment. */
static void member_optint(ncfg_json_writer_t *writer, const char *name, ncfg_optint_t value)
{
	ncfg_json_write_key(writer, name);
	if (value.has) {
		ncfg_json_write_int(writer, value.value);
	} else {
		ncfg_json_write_null(writer);
	}
}

static void member_text(ncfg_json_writer_t *writer, const char *name, const char *text)
{
	ncfg_json_write_key(writer, name);
	if (text) {
		ncfg_json_write_string(writer, text);
	} else {
		ncfg_json_write_null(writer);
	}
}

static void member_strings(ncfg_json_writer_t *writer, const char *name,
    const char *const *list, size_t count)
{
	size_t i;

	ncfg_json_write_key(writer, name);
	ncfg_json_write_array_begin(writer);
	for (i = 0; i < count; i++) {
		ncfg_json_write_string(writer, list[i]);
	}
	ncfg_json_write_array_end(writer);
}

/*
 * One op, tag first.
 *
 * The tag is `ncfg_op_name`, never a second spelling of it. The Rust records
 * why: the wire tag used to be serde's `snake_case` of the variant while the
 * name was `Op::name()`, so one operation had two spellings and only a client
 * outside the workspace could see both at once (0082).
 */
static void write_op(ncfg_json_writer_t *writer, const ncfg_op_t *op)
{
	size_t i;

	ncfg_json_write_object_begin(writer);
	ncfg_json_write_member_string(writer, "op", ncfg_op_name(op));
	switch ((ncfg_op_kind_t)op->kind) {
	case NCFG_OP_LINK_CREATE:
		member_text(writer, "name", op->u.link_create.name);
		ncfg_json_write_key(writer, "kind");
		if (op->u.link_create.kind) {
			ncfg_plan_write_interface_kind(writer, op->u.link_create.kind);
		} else {
			ncfg_json_write_null(writer);
		}
		break;
	case NCFG_OP_LINK_DELETE:
	case NCFG_OP_LINK_UNSET_MASTER:
	case NCFG_OP_LINK_UP:
	case NCFG_OP_LINK_DOWN:
	case NCFG_OP_LINK_SET_BRIDGE:
	case NCFG_OP_LINK_SET_MACVLAN:
	case NCFG_OP_LINK_SET_TUNNEL:
	case NCFG_OP_LINK_SET_VXLAN:
	case NCFG_OP_HOSTNAME_SET:
		member_text(writer, "name", op->u.named.name);
		break;
	case NCFG_OP_LINK_SET_MTU:
		member_text(writer, "name", op->u.set_mtu.name);
		ncfg_json_write_member_int(writer, "mtu", op->u.set_mtu.mtu);
		break;
	case NCFG_OP_LINK_SET_MAC:
		member_text(writer, "name", op->u.set_mac.name);
		member_text(writer, "mac", op->u.set_mac.mac);
		break;
	case NCFG_OP_LINK_SET_MASTER:
		member_text(writer, "name", op->u.set_master.name);
		member_text(writer, "master", op->u.set_master.master);
		break;
	case NCFG_OP_LINK_SET_BOND:
		member_text(writer, "name", op->u.set_bond.name);
		ncfg_json_write_member_bool(writer, "mode", op->u.set_bond.mode);
		break;
	case NCFG_OP_LINK_SET_IPV6_TOKEN:
		member_text(writer, "name", op->u.set_ipv6_token.name);
		member_text(writer, "token", op->u.set_ipv6_token.token);
		break;
	/*
	 * `[[name, wanted], ...]`, which is a list of pairs rather than an
	 * object because that is what the kernel takes: a features message
	 * carries a mask bitset saying "change exactly these", and the order
	 * the planner sorted them into is part of the value.
	 */
	case NCFG_OP_LINK_SET_OFFLOADS:
		member_text(writer, "name", op->u.set_offloads.name);
		ncfg_json_write_key(writer, "features");
		ncfg_json_write_array_begin(writer);
		for (i = 0; i < op->u.set_offloads.feature_count; i++) {
			ncfg_json_write_array_begin(writer);
			ncfg_json_write_string(writer, op->u.set_offloads.features[i].name);
			ncfg_json_write_bool(writer, op->u.set_offloads.features[i].wanted);
			ncfg_json_write_array_end(writer);
		}
		ncfg_json_write_array_end(writer);
		break;
	case NCFG_OP_ADDR_ADD:
		member_text(writer, "iface", op->u.addr_add.iface);
		member_text(writer, "addr", op->u.addr_add.addr);
		member_optint(writer, "preferred_lifetime", op->u.addr_add.preferred_lifetime);
		member_optint(writer, "valid_lifetime", op->u.addr_add.valid_lifetime);
		break;
	case NCFG_OP_ADDR_DEL:
		member_text(writer, "iface", op->u.addr_del.iface);
		member_text(writer, "addr", op->u.addr_del.addr);
		break;
	case NCFG_OP_ROUTE_ADD:
	case NCFG_OP_ROUTE_DEL:
		member_text(writer, "iface", op->u.route.iface);
		ncfg_json_write_key(writer, "route");
		if (op->u.route.route) {
			ncfg_plan_write_route(writer, op->u.route.route);
		} else {
			ncfg_json_write_null(writer);
		}
		break;
	case NCFG_OP_BACKEND_START:
	case NCFG_OP_BACKEND_STOP:
	case NCFG_OP_BACKEND_RELOAD:
		ncfg_json_write_member_string(writer, "kind",
		    ncfg_backend_kind_name(op->u.backend.kind));
		member_text(writer, "iface", op->u.backend.iface);
		break;
	case NCFG_OP_BRIDGE_VLAN_ADD:
		member_text(writer, "iface", op->u.bridge_vlan.iface);
		ncfg_json_write_member_int(writer, "vid", op->u.bridge_vlan.vid);
		ncfg_json_write_member_bool(writer, "pvid", op->u.bridge_vlan.pvid);
		ncfg_json_write_member_bool(writer, "untagged", op->u.bridge_vlan.untagged);
		ncfg_json_write_member_bool(writer, "on_self", op->u.bridge_vlan.on_self);
		break;
	case NCFG_OP_BRIDGE_VLAN_DEL:
		member_text(writer, "iface", op->u.bridge_vlan.iface);
		ncfg_json_write_member_int(writer, "vid", op->u.bridge_vlan.vid);
		ncfg_json_write_member_bool(writer, "on_self", op->u.bridge_vlan.on_self);
		break;
	case NCFG_OP_WIFI_SET_PROFILES:
		member_text(writer, "device", op->u.set_profiles.device);
		member_strings(writer, "profiles", op->u.set_profiles.profiles,
		    op->u.set_profiles.profile_count);
		break;
	case NCFG_OP_WIFI_ASSOCIATE:
		member_text(writer, "device", op->u.associate.device);
		member_text(writer, "network_id", op->u.associate.network_id);
		break;
	case NCFG_OP_WIFI_DISASSOCIATE:
		member_text(writer, "device", op->u.device.device);
		break;
	case NCFG_OP_WIFI_SET_REGDOM:
		member_text(writer, "device", op->u.regdom.device);
		member_text(writer, "country", op->u.regdom.country);
		break;
	case NCFG_OP_ACCESS_CONTROL_ADD:
	case NCFG_OP_ACCESS_CONTROL_DEL:
		member_text(writer, "iface", op->u.access_control.iface);
		ncfg_json_write_member_string(writer, "list",
		    ncfg_plan_acl_policy_word(op->u.access_control.list));
		member_text(writer, "station", op->u.access_control.station);
		break;
	case NCFG_OP_WG_SET_DEVICE:
		member_text(writer, "iface", op->u.wg_device.iface);
		member_text(writer, "private_key_ref", op->u.wg_device.private_key_ref);
		member_optint(writer, "listen_port", op->u.wg_device.listen_port);
		member_optint(writer, "fwmark", op->u.wg_device.fwmark);
		break;
	case NCFG_OP_WG_SET_PEERS:
		member_text(writer, "iface", op->u.wg_peers.iface);
		ncfg_json_write_key(writer, "peers");
		ncfg_json_write_array_begin(writer);
		for (i = 0; i < op->u.wg_peers.peer_count; i++) {
			ncfg_plan_write_wg_peer(writer, &op->u.wg_peers.peers[i]);
		}
		ncfg_json_write_array_end(writer);
		break;
	case NCFG_OP_DNS_APPLY:
		member_text(writer, "scope", op->u.dns.scope);
		ncfg_json_write_key(writer, "policy");
		if (op->u.dns.policy) {
			ncfg_plan_write_dns_policy(writer, op->u.dns.policy);
		} else {
			ncfg_json_write_null(writer);
		}
		break;
	case NCFG_OP_RULE_ADD:
	case NCFG_OP_RULE_DEL:
		ncfg_json_write_key(writer, "rule");
		if (op->u.rule.rule) {
			ncfg_plan_write_rule(writer, op->u.rule.rule);
		} else {
			ncfg_json_write_null(writer);
		}
		break;
	case NCFG_OP_QDISC_SET:
		member_text(writer, "iface", op->u.qdisc.iface);
		member_text(writer, "kind", op->u.qdisc.kind);
		member_optint(writer, "bandwidth_bits", op->u.qdisc.bandwidth_bits);
		ncfg_json_write_member_bool(writer, "ingress", op->u.qdisc.ingress);
		break;
	case NCFG_OP_QDISC_RESET:
	case NCFG_OP_INGRESS_REDIRECT_CLEAR:
		member_text(writer, "iface", op->u.iface.iface);
		break;
	case NCFG_OP_INGRESS_REDIRECT:
		member_text(writer, "iface", op->u.redirect.iface);
		member_text(writer, "target", op->u.redirect.target);
		break;
	case NCFG_OP_SYSCTL_SET_FORWARDING:
		member_text(writer, "iface", op->u.forwarding.iface);
		ncfg_json_write_member_bool(writer, "enabled", op->u.forwarding.enabled);
		break;
	case NCFG_OP_SYSCTL_SET_PRIVACY:
		member_text(writer, "iface", op->u.privacy.iface);
		ncfg_json_write_member_bool(writer, "prefer_temporary",
		    op->u.privacy.prefer_temporary);
		break;
	case NCFG_OP_SYSCTL_SET_ACCEPT_RA:
		member_text(writer, "iface", op->u.accept_ra.iface);
		ncfg_json_write_member_int(writer, "value", op->u.accept_ra.value);
		break;
	case NCFG_OP_NAT_REPLACE:
		member_strings(writer, "uplinks", op->u.nat.uplinks, op->u.nat.uplink_count);
		break;
	case NCFG_OP_HOOK_RUN:
		member_text(writer, "iface", op->u.hook.iface);
		ncfg_json_write_member_string(writer, "phase",
		    ncfg_hook_phase_name(op->u.hook.phase));
		member_text(writer, "path", op->u.hook.path);
		/* One of the three members in this surface that is omitted rather
		 * than written null: a lifecycle phase has no value, and `null`
		 * would be a third answer beside "absent" and "a reason". */
		if (op->u.hook.value) {
			ncfg_json_write_member_string(writer, "value", op->u.hook.value);
		}
		break;
	case NCFG_OP_COMMIT_ARM:
		ncfg_json_write_member_int(writer, "window_seconds", op->u.commit_arm.window_seconds);
		break;
	case NCFG_OP_COMMIT_CONFIRM:
		break;
	case NCFG_OP_COMMIT_REVERT:
		member_text(writer, "to_document_hash", op->u.commit_revert.to_document_hash);
		break;
	}
	ncfg_json_write_object_end(writer);
}

static void write_reason(ncfg_json_writer_t *writer, const ncfg_reason_t *reason)
{
	ncfg_json_write_object_begin(writer);
	if (reason->interface) {
		ncfg_json_write_member_string(writer, "interface", reason->interface);
	}
	member_text(writer, "field", reason->field);
	member_text(writer, "desired", reason->desired);
	member_text(writer, "observed", reason->observed);
	ncfg_json_write_object_end(writer);
}

static void write_action(ncfg_json_writer_t *writer, const ncfg_action_t *action)
{
	size_t i;

	ncfg_json_write_object_begin(writer);
	ncfg_json_write_member_int(writer, "id", (int64_t)action->id);
	ncfg_json_write_key(writer, "op");
	write_op(writer, &action->op);
	ncfg_json_write_key(writer, "reason");
	write_reason(writer, &action->reason);
	ncfg_json_write_key(writer, "depends_on");
	ncfg_json_write_array_begin(writer);
	for (i = 0; i < action->depends_count; i++) {
		ncfg_json_write_int(writer, (int64_t)action->depends_on[i]);
	}
	ncfg_json_write_array_end(writer);
	if (action->has_inverse) {
		ncfg_json_write_key(writer, "inverse");
		write_op(writer, &action->inverse);
	}
	ncfg_json_write_object_end(writer);
}

int ncfg_plan_write(const ncfg_plan_t *plan, ncfg_buf_t *buf, char *err, size_t err_size)
{
	ncfg_json_writer_t writer;
	size_t             i;

	/*
	 * A plan that failed while it was being built writes nothing. Half a plan
	 * that looks whole is the one that gets applied, and the one thing worse
	 * than "out of memory" is an apply that runs four of five actions.
	 */
	if (plan->failed) {
		ncfg_error_set(err, err_size, "the plan could not be built: out of memory");
		return 0;
	}
	ncfg_json_write_init(&writer, buf);
	ncfg_json_write_object_begin(&writer);

	ncfg_json_write_key(&writer, "actions");
	ncfg_json_write_array_begin(&writer);
	for (i = 0; i < plan->action_count; i++) {
		write_action(&writer, &plan->actions[i]);
	}
	ncfg_json_write_array_end(&writer);

	ncfg_json_write_key(&writer, "warnings");
	ncfg_json_write_array_begin(&writer);
	for (i = 0; i < plan->warning_count; i++) {
		ncfg_json_write_object_begin(&writer);
		member_text(&writer, "message", plan->warnings[i].message);
		if (plan->warnings[i].interface) {
			ncfg_json_write_member_string(&writer, "interface",
			    plan->warnings[i].interface);
		}
		ncfg_json_write_object_end(&writer);
	}
	ncfg_json_write_array_end(&writer);

	ncfg_json_write_key(&writer, "refusals");
	ncfg_json_write_array_begin(&writer);
	for (i = 0; i < plan->refusal_count; i++) {
		ncfg_json_write_object_begin(&writer);
		member_text(&writer, "interface", plan->refusals[i].interface);
		member_text(&writer, "op", plan->refusals[i].op);
		member_text(&writer, "guard", plan->refusals[i].guard);
		ncfg_json_write_key(&writer, "reason");
		write_reason(&writer, &plan->refusals[i].reason);
		member_text(&writer, "override_with", plan->refusals[i].override_with);
		ncfg_json_write_object_end(&writer);
	}
	ncfg_json_write_array_end(&writer);

	ncfg_json_write_key(&writer, "stranded");
	ncfg_json_write_array_begin(&writer);
	for (i = 0; i < plan->stranded_count; i++) {
		ncfg_json_write_object_begin(&writer);
		member_text(&writer, "interface", plan->stranded[i].interface);
		member_text(&writer, "credential", plan->stranded[i].credential);
		member_text(&writer, "irrevocable", plan->stranded[i].irrevocable);
		member_text(&writer, "remove_with", plan->stranded[i].remove_with);
		member_text(&writer, "consent_with", plan->stranded[i].consent_with);
		ncfg_json_write_object_end(&writer);
	}
	ncfg_json_write_array_end(&writer);

	ncfg_json_write_object_end(&writer);
	if (!ncfg_json_write_done(&writer)) {
		const char *why = ncfg_json_write_failure(&writer);

		ncfg_error_set(err, err_size, "could not write the plan: %s",
		    why ? why : "the buffer would not take it");
		return 0;
	}
	return 1;
}
