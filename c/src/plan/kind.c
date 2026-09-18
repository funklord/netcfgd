/*
 * kind.c -- what a device's `kind` says about itself, on a device that
 * already exists.
 *
 * WHY THIS IS A FILE AND NOT PART OF CREATION
 *   Every setting here is sent inside `link.create`, so on the first apply it
 *   is already right and this file does nothing. The failure it exists for is
 *   the second one: a bridge's `stp` and `forward_delay` were applied at
 *   creation and never compared again, so editing either planned nothing,
 *   changed nothing, and said nothing (0054, 0057). A VLAN at least usually
 *   carries its id in its name; a bridge gives no other signal at all.
 *
 * THE THREE ANSWERS A KERNEL GIVES, AND WHY EACH IS SPELLED OUT
 *   A setting on a live device is *taken*, *refused*, or *accepted and
 *   ignored*, and only the first is an action:
 *
 *     * A bond's mode moves on a bond with **no members** and answers
 *       `ENOTEMPTY` with any -- so a bond with members gets a sentence rather
 *       than an action that fails and is planned again on the next reconcile.
 *     * A macvlan moves freely among `private`, `vepa` and `bridge` and is
 *       refused in either direction with `passthru` (0058).
 *     * A geneve tunnel's VNI and a VXLAN's id and port are refused outright,
 *       and the nest the executor sends leaves them out -- which is what keeps
 *       an endpoint beside them correctable (0057's lesson that a refused
 *       attribute takes its neighbours with it).
 *     * A VLAN's id and protocol, and a macvlan's parent, are accepted and
 *       ignored. Those belong to the recreation pass, which is not in this
 *       build: `ncfg_plan_link_creation` says what it declines and this file
 *       does not pretend to fix them.
 *
 * WHAT IS COMPARED AT ALL
 *   **Only what the document states**, which is the rule an access point's
 *   band arrived at (0052) and a bridge's forward delay met again: an absent
 *   field means "whatever the kernel picked", and comparing that against what
 *   it picked rebuilds the device on every reconcile. A word netcfgd has no
 *   name for is not compared either -- that is somebody else's choice,
 *   expressed in something this build cannot describe, and correcting it would
 *   mean overwriting a value it cannot even print.
 *
 *   **And an endpoint is compared the way the model compares**, never as text.
 *   `plan.h`'s second load-bearing property is that applying a plan twice
 *   produces an empty second plan, and 10.169 is what a text comparison costs:
 *   one address written twice reads as two, and the same action is planned for
 *   ever. `ncfg_plan_address_equal` is the one place that is decided.
 */
#include "plan_internal.h"

#include "ncfg/base.h"

#include <string.h>

/* ------------------------------------------------------------------------ *
 * The comparisons every pass here makes
 * ------------------------------------------------------------------------ */

/*
 * Whether a value the document states differs from what is running.
 *
 * A field the document says nothing about is not a difference. See *What is
 * compared at all* above; this is that rule as three lines.
 */
static int stated_differs(ncfg_optint_t desired, ncfg_optint_t seen)
{
	return desired.has && (!seen.has || desired.value != seen.value);
}

/*
 * The same, for an endpoint.
 *
 * Its own function only to say why it is the same: an endpoint the kernel does
 * not have comes back as all zeroes rather than as an absent attribute, and
 * the observer has already turned that into NULL -- so a document that names a
 * remote where the kernel has none is a difference, and a document that names
 * none is not.
 */
static int address_differs(const char *desired, const char *seen)
{
	if (!desired) {
		return 0;
	}
	if (!seen) {
		return 1;
	}
	return !ncfg_plan_address_equal(desired, seen);
}

/*
 * Whether both sides name an endpoint and they are in different families.
 *
 * A geneve tunnel and a VXLAN both refuse this, and refuse it as the whole
 * message -- so it has to be told apart from an ordinary endpoint change,
 * which they take.
 */
static int family_differs(const char *desired, const char *seen)
{
	ncfg_address_t left;
	ncfg_address_t right;
	char           message[NCFG_ERROR_MAX];

	if (!desired || !seen) {
		return 0;
	}
	if (!ncfg_address_parse(desired, &left, message, sizeof(message)) ||
	    !ncfg_address_parse(seen, &right, message, sizeof(message))) {
		/* A value neither side can parse is not a family this build can
		 * name, and refusing to correct a tunnel over it is the same answer
		 * a mode netcfgd has no word for gets. */
		return 0;
	}
	return left.is_ipv6 != right.is_ipv6;
}

/*
 * Whether the document names a parent and the kernel has a different one.
 *
 * A parent the document does not name is not compared, which is the rule every
 * other field follows -- and here it also covers the interface whose parent
 * lives in another network namespace, where the observation has a number and
 * no name to put against the document's word.
 */
static int parent_differs(const char *desired, const char *seen)
{
	if (!desired) {
		return 0;
	}
	return !seen || strcmp(desired, seen) != 0;
}

/* A stated number with its unit, or `<absent>`. */
static const char *rendered(ncfg_plan_t *plan, ncfg_optint_t value, const char *unit)
{
	if (!value.has) {
		return "<absent>";
	}
	return ncfg_plan_internf(plan, "%lld%s", (long long)value.value, unit);
}

/* A string the document or the kernel may not have. */
static const char *or_absent(const char *text)
{
	return text ? text : "<absent>";
}

/* What a boolean renders as in a reason line: the document's own words. */
static const char *yes_no(int value)
{
	return value ? "true" : "false";
}

/*
 * One field's difference, gathered before anything is pushed.
 *
 * The passes below answer "which field moved" first and act once, rather than
 * emitting an action per field: every one of these ops re-sends the whole nest
 * the kind is described by, so two actions would be the same change twice and
 * the second would have nothing left to do.
 */
typedef struct {
	const char *field;
	const char *desired;
	const char *observed;
} ncfg_kind_difference_t;

/* The creation gate, and the push every pass here makes through it. */
static void push_kind(ncfg_builder_t *builder, const char *name, int op_kind,
    const ncfg_kind_difference_t *difference)
{
	ncfg_plan_ids_t gate = { NULL, 0, 0 };
	ncfg_op_t       op;
	ncfg_reason_t   reason;

	memset(&op, 0, sizeof(op));
	op.kind = op_kind;
	op.u.named.name = name;
	reason = ncfg_plan_reason_differs(name, difference->field, difference->desired,
	    difference->observed);
	ncfg_builder_gate(builder, name, &gate);
	/*
	 * No inverse, and it is a decision rather than an omission. What the
	 * device had is in the observation, but the op carries no values -- the
	 * executor reads them from the document, which by then says the new
	 * thing. An inverse that re-applied the document would be a revert that
	 * changes nothing, which is worse than saying there is none.
	 */
	(void)ncfg_builder_push(builder, &op, &reason, gate.ids, gate.count, NULL);
	ncfg_plan_ids_free(&gate);
}

/* ------------------------------------------------------------------------ *
 * A bond
 * ------------------------------------------------------------------------ */

/* Whether anything the kernel holds is enslaved to this name. */
static int has_members(const ncfg_builder_t *builder, const char *name)
{
	size_t i;

	for (i = 0; i < builder->observed->link_count; i++) {
		const char *master = builder->observed->links[i].master;

		if (master && strcmp(master, name) == 0) {
			return 1;
		}
	}
	return 0;
}

/*
 * Correct a bond whose own settings the document has moved.
 *
 * The bridge's story in a second kind (0057), and the kernel was asked rather
 * than assumed: `ip link set bond0 type bond mode balance-rr` moves a live
 * bond, where the same shape of request on a VLAN succeeds and changes
 * nothing.
 *
 * **A mode is only settable on a bond with no members.** The kernel answers
 * `ENOTEMPTY` otherwise, which the Rust's first version of this found by
 * failing an apply and then planning the same action again on the next
 * reconcile. `miimon` has no such rule and moves on a live bond -- so a bond
 * whose mode cannot move still gets its `miimon` corrected, and the sentence
 * about the mode stands beside it rather than instead of the rest of the plan.
 */
void ncfg_plan_bond(ncfg_builder_t *builder, const ncfg_device_t *device)
{
	const ncfg_observed_link_t *link;
	const ncfg_observed_bond_t *running;
	const char                 *wanted;
	ncfg_kind_difference_t      difference;
	int                         mode_differs;
	int                         enslaved;

	if (device->kind.kind != NCFG_KIND_BOND) {
		return;
	}
	link = ncfg_observed_link(builder->observed, device->name);
	if (!link || !link->bond) {
		return;
	}
	running = link->bond;
	wanted = ncfg_plan_bond_mode_word(device->kind.bond.mode);
	/* A mode netcfgd has no name for is not compared: that is a bond somebody
	 * else configured with something this build cannot express, and
	 * correcting it would mean overwriting a choice it cannot describe. */
	mode_differs = wanted && running->mode && strcmp(running->mode, wanted) != 0;
	enslaved = has_members(builder, device->name);

	if (mode_differs && enslaved) {
		ncfg_plan_warnf(builder->plan, device->name,
		    "the mode of %s is %s in the config and %s in the kernel, and the kernel "
		    "will not change it while the bond has members -- take them out, or recreate "
		    "the bond, or leave the mode alone",
		    device->name, wanted, running->mode);
	}
	if (mode_differs && !enslaved) {
		difference.field = "bond.mode";
		difference.desired = wanted;
		difference.observed = running->mode;
	} else if (stated_differs(device->kind.bond.miimon, running->miimon)) {
		difference.field = "bond.miimon";
		difference.desired = rendered(builder->plan, device->kind.bond.miimon, "ms");
		difference.observed = rendered(builder->plan, running->miimon, "ms");
	} else {
		return;
	}

	{
		ncfg_plan_ids_t gate = { NULL, 0, 0 };
		ncfg_op_t       op;
		ncfg_reason_t   reason;

		memset(&op, 0, sizeof(op));
		op.kind = NCFG_OP_LINK_SET_BOND;
		op.u.set_bond.name = device->name;
		/*
		 * Whether the mode is part of the message. The planner knows which
		 * case this is -- it has just asked whether the bond has members --
		 * and says so here rather than leaving the executor to ask, because
		 * a request carrying a mode the kernel will not take also fails to
		 * set the monitoring interval beside it.
		 */
		op.u.set_bond.mode = strcmp(difference.field, "bond.mode") == 0;
		reason = ncfg_plan_reason_differs(device->name, difference.field,
		    difference.desired, difference.observed);
		ncfg_builder_gate(builder, device->name, &gate);
		(void)ncfg_builder_push(builder, &op, &reason, gate.ids, gate.count, NULL);
		ncfg_plan_ids_free(&gate);
	}
}

/* ------------------------------------------------------------------------ *
 * A bridge
 * ------------------------------------------------------------------------ */

/*
 * Correct a bridge whose own settings the document has moved.
 *
 * **Every field of `ncfg_bridge_config_t` is here except `members`**, and the
 * exception is not a gap: a member is corrected through its own device's
 * `master`, which `ncfg_plan_master` owns. The Rust destructures the struct so
 * that a field added to it is a compile error here rather than a setting
 * nobody compares; C offers no such thing, so the count is said out loud --
 * **six settings and the member list** -- and `plan_kind_test.c` moves each of
 * the six in turn. Three of them arrived after the pass was written and
 * nothing said they had to be added to it, which is how `ageing_time`,
 * `priority` and `vlan_filtering` came to be parsed, sent at creation, read
 * back by the observer, and never compared.
 */
void ncfg_plan_bridge(ncfg_builder_t *builder, const ncfg_device_t *device)
{
	const ncfg_observed_link_t   *link;
	const ncfg_observed_bridge_t *running;
	const ncfg_bridge_config_t   *bridge;
	ncfg_kind_difference_t        difference;

	if (device->kind.kind != NCFG_KIND_BRIDGE) {
		return;
	}
	link = ncfg_observed_link(builder->observed, device->name);
	if (!link || !link->bridge) {
		return;
	}
	running = link->bridge;
	bridge = &device->kind.bridge;

	if (bridge->stp != running->stp) {
		difference.field = "bridge.stp";
		difference.desired = yes_no(bridge->stp);
		difference.observed = yes_no(running->stp);
	} else if (stated_differs(bridge->forward_delay, running->forward_delay)) {
		difference.field = "bridge.forward_delay";
		difference.desired = rendered(builder->plan, bridge->forward_delay, "s");
		difference.observed = rendered(builder->plan, running->forward_delay, "s");
	} else if (stated_differs(bridge->hello_time, running->hello_time)) {
		difference.field = "bridge.hello_time";
		difference.desired = rendered(builder->plan, bridge->hello_time, "s");
		difference.observed = rendered(builder->plan, running->hello_time, "s");
	} else if (stated_differs(bridge->ageing_time, running->ageing_time)) {
		difference.field = "bridge.ageing_time";
		difference.desired = rendered(builder->plan, bridge->ageing_time, "s");
		difference.observed = rendered(builder->plan, running->ageing_time, "s");
	} else if (stated_differs(bridge->priority, running->priority)) {
		difference.field = "bridge.priority";
		difference.desired = rendered(builder->plan, bridge->priority, "");
		difference.observed = rendered(builder->plan, running->priority, "");
	} else if (bridge->vlan_filtering != running->vlan_filtering) {
		/* A boolean, so compared like `stp` rather than through
		 * `stated_differs`: there is no "the document did not say" to
		 * distinguish, and a bridge whose per-port VLANs are configured needs
		 * this on -- the executor says so by name when it is off. */
		difference.field = "bridge.vlan_filtering";
		difference.desired = yes_no(bridge->vlan_filtering);
		difference.observed = yes_no(running->vlan_filtering);
	} else {
		return;
	}
	push_kind(builder, device->name, NCFG_OP_LINK_SET_BRIDGE, &difference);
}

/* ------------------------------------------------------------------------ *
 * A macvlan
 * ------------------------------------------------------------------------ */

/*
 * Correct a macvlan whose mode the document has moved.
 *
 * One field with two answers in it, asked a value at a time (0058): the kernel
 * moves the mode freely among `private`, `vepa` and `bridge`, and refuses
 * either direction between one of those and `passthru` with `EINVAL` --
 * `macvlan_changelink` calls that transition out by name. So the refused edit
 * gets a sentence, the way a bond's mode does on a bond with members. The
 * parent beside it is a third answer again and is not compared at all:
 * `IFLA_LINK` on a live macvlan is accepted and ignored.
 *
 * A mode netcfgd has no word for is not compared. That is the `source` mode,
 * or something newer, on a macvlan somebody else configured.
 */
void ncfg_plan_macvlan(ncfg_builder_t *builder, const ncfg_device_t *device)
{
	const ncfg_observed_link_t *link;
	const char                 *seen;
	const char                 *wanted;
	ncfg_kind_difference_t      difference;

	if (device->kind.kind != NCFG_KIND_MACVLAN) {
		return;
	}
	link = ncfg_observed_link(builder->observed, device->name);
	if (!link || !link->macvlan || !link->macvlan->mode) {
		return;
	}
	seen = link->macvlan->mode;
	wanted = ncfg_plan_macvlan_mode_word(device->kind.macvlan.mode);
	if (!wanted || strcmp(seen, wanted) == 0) {
		return;
	}
	if (strcmp(seen, "passthru") == 0 || strcmp(wanted, "passthru") == 0) {
		ncfg_plan_warnf(builder->plan, device->name,
		    "the mode of %s is %s in the config and %s in the kernel, and the kernel "
		    "will not move a macvlan into or out of passthru mode -- recreate the "
		    "interface, or leave the mode alone",
		    device->name, wanted, seen);
		return;
	}
	difference.field = "macvlan.mode";
	difference.desired = wanted;
	difference.observed = seen;
	push_kind(builder, device->name, NCFG_OP_LINK_SET_MACVLAN, &difference);
}

/* ------------------------------------------------------------------------ *
 * A tunnel
 * ------------------------------------------------------------------------ */

/*
 * The kernel's own fallback tunnel devices, which cannot be configured at all.
 *
 * Each tunnel module registers one when it loads, and that device refuses
 * everything: `ip link set gre0 type gre local ... remote ...` answers
 * `EINVAL`, `ip link del gre0` silently does nothing and leaves it there, and
 * `ip link add gre0 ...` answers `EEXIST`. All three measured with iproute2,
 * so the refusal is the kernel's rather than anything about how netcfgd
 * encodes the request -- an ordinary pre-existing tunnel of the same kind
 * takes the same change happily, which is what says ownership is not the
 * discriminator.
 *
 * It matters because `gre0` is the name an operator reaches for first.
 */
static int is_fallback_tunnel(const char *name)
{
	static const char *const fallbacks[] = { "gre0", "gretap0", "erspan0", "ip6gre0",
		"ip6gretap0", "tunl0", "sit0", "ip6tnl0" };
	size_t i;

	for (i = 0; i < sizeof(fallbacks) / sizeof(fallbacks[0]); i++) {
		if (strcmp(name, fallbacks[i]) == 0) {
			return 1;
		}
	}
	return 0;
}

/*
 * Correct a tunnel whose endpoints the document has moved.
 *
 * Seven kinds across three attribute families, and what the kernel takes
 * differs by family rather than by field: an endpoint or a TTL moves on any of
 * them, while a **geneve tunnel's VNI cannot change at all**. netcfgd's model
 * spells that VNI `key`, so an edited `key` on a geneve gets a sentence and an
 * edited one on a GRE tunnel gets an action.
 *
 * A geneve tunnel will also not have its remote replaced by an address of the
 * other family, which is the kernel refusing something no set could achieve --
 * so that is a sentence too, and it returns rather than emitting an action
 * beside it: the remote is the thing that would be sent.
 */
void ncfg_plan_tunnel(ncfg_builder_t *builder, const ncfg_device_t *device)
{
	const ncfg_observed_link_t   *link;
	const ncfg_observed_tunnel_t *running;
	const ncfg_tunnel_config_t   *tunnel;
	ncfg_kind_difference_t        difference;
	int                           geneve;

	if (device->kind.kind != NCFG_KIND_TUNNEL) {
		return;
	}
	link = ncfg_observed_link(builder->observed, device->name);
	if (!link || !link->tunnel) {
		return;
	}
	running = link->tunnel;
	tunnel = &device->kind.tunnel;

	if (is_fallback_tunnel(device->name)) {
		ncfg_plan_warnf(builder->plan, device->name,
		    "%s is the kernel's own fallback tunnel device, which is created when the "
		    "module loads and cannot be configured, deleted or replaced -- its endpoints "
		    "and ttl are refused with EINVAL however they are set. Give the tunnel "
		    "another name, such as `%s-wan`",
		    device->name, device->name);
		return;
	}
	geneve = tunnel->mode == NCFG_TUNNEL_KIND_GENEVE;
	/*
	 * A geneve VNI is refused outright, so it is said rather than tried. The
	 * nest the executor sends leaves the VNI out on a change for exactly this
	 * reason, which is what lets a remote beside it still be corrected.
	 */
	if (geneve && stated_differs(tunnel->key, running->key)) {
		ncfg_plan_warnf(builder->plan, device->name,
		    "the geneve id of %s is %s in the config and %s in the kernel, and the "
		    "kernel will not change the VNI of a geneve tunnel -- recreate the "
		    "interface, or leave the id alone",
		    device->name, rendered(builder->plan, tunnel->key, ""),
		    rendered(builder->plan, running->key, ""));
	}
	if (geneve && family_differs(tunnel->remote, running->remote)) {
		ncfg_plan_warnf(builder->plan, device->name,
		    "the remote of %s is %s in the config and %s in the kernel, and a geneve "
		    "tunnel cannot change which address family its remote is in -- recreate the "
		    "interface",
		    device->name, or_absent(tunnel->remote), or_absent(running->remote));
		return;
	}

	if (address_differs(tunnel->remote, running->remote)) {
		difference.field = "tunnel.remote";
		difference.desired = or_absent(tunnel->remote);
		difference.observed = or_absent(running->remote);
	} else if (address_differs(tunnel->local, running->local)) {
		difference.field = "tunnel.local";
		difference.desired = or_absent(tunnel->local);
		difference.observed = or_absent(running->local);
	} else if (parent_differs(tunnel->parent, link->parent)) {
		difference.field = "tunnel.parent";
		difference.desired = or_absent(tunnel->parent);
		difference.observed = or_absent(link->parent);
	} else if (stated_differs(tunnel->ttl, running->ttl)) {
		difference.field = "tunnel.ttl";
		difference.desired = rendered(builder->plan, tunnel->ttl, "");
		difference.observed = rendered(builder->plan, running->ttl, "");
	} else if (!geneve && stated_differs(tunnel->key, running->key)) {
		difference.field = "tunnel.key";
		difference.desired = rendered(builder->plan, tunnel->key, "");
		difference.observed = rendered(builder->plan, running->key, "");
	} else {
		return;
	}
	push_kind(builder, device->name, NCFG_OP_LINK_SET_TUNNEL, &difference);
}

/* ------------------------------------------------------------------------ *
 * A VXLAN
 * ------------------------------------------------------------------------ */

/*
 * Correct a VXLAN whose endpoints the document has moved.
 *
 * Two of its four settings cannot be corrected once the device exists, and the
 * second one is the surprise: the kernel refuses `IFLA_VXLAN_PORT` **whenever
 * it is present**, at any value, and a changed `id` when the value differs.
 * Both were measured (0058). So both get a sentence, and the nest the executor
 * sends omits them -- which is what leaves the endpoints correctable rather
 * than losing them to a refusal beside them.
 */
void ncfg_plan_vxlan(ncfg_builder_t *builder, const ncfg_device_t *device)
{
	const ncfg_observed_link_t  *link;
	const ncfg_observed_vxlan_t *running;
	const ncfg_vxlan_config_t   *vxlan;
	ncfg_kind_difference_t       difference;

	if (device->kind.kind != NCFG_KIND_VXLAN) {
		return;
	}
	link = ncfg_observed_link(builder->observed, device->name);
	if (!link || !link->vxlan) {
		return;
	}
	running = link->vxlan;
	vxlan = &device->kind.vxlan;

	if (running->id.has && running->id.value != vxlan->id) {
		ncfg_plan_warnf(builder->plan, device->name,
		    "the vxlan id of %s is %lld in the config and %s in the kernel, and the "
		    "kernel will not change the VNI of a VXLAN -- recreate the interface, or "
		    "leave the id alone",
		    device->name, (long long)vxlan->id,
		    rendered(builder->plan, running->id, ""));
	}
	if (stated_differs(vxlan->port, running->port)) {
		ncfg_plan_warnf(builder->plan, device->name,
		    "the port of %s is %s in the config and %s in the kernel, and the kernel "
		    "will not change the destination port of a VXLAN -- recreate the interface, "
		    "or leave the port alone",
		    device->name, rendered(builder->plan, vxlan->port, ""),
		    rendered(builder->plan, running->port, ""));
	}
	if (family_differs(vxlan->remote, running->remote)) {
		ncfg_plan_warnf(builder->plan, device->name,
		    "the remote of %s is %s in the config and %s in the kernel, and a VXLAN "
		    "cannot change which address family its group is in -- recreate the "
		    "interface",
		    device->name, or_absent(vxlan->remote), or_absent(running->remote));
		return;
	}

	if (address_differs(vxlan->remote, running->remote)) {
		difference.field = "vxlan.remote";
		difference.desired = or_absent(vxlan->remote);
		difference.observed = or_absent(running->remote);
	} else if (address_differs(vxlan->local, running->local)) {
		difference.field = "vxlan.local";
		difference.desired = or_absent(vxlan->local);
		difference.observed = or_absent(running->local);
	} else if (parent_differs(vxlan->parent, link->parent)) {
		difference.field = "vxlan.parent";
		difference.desired = or_absent(vxlan->parent);
		difference.observed = or_absent(link->parent);
	} else {
		return;
	}
	push_kind(builder, device->name, NCFG_OP_LINK_SET_VXLAN, &difference);
}

/* ------------------------------------------------------------------------ *
 * Per-port VLANs
 * ------------------------------------------------------------------------ */

/* `10 pvid untagged`, for a plan's reason line. */
static const char *render_vlan(ncfg_plan_t *plan, const ncfg_bridge_vlan_t *vlan)
{
	return ncfg_plan_internf(plan, "%lld%s%s", (long long)vlan->vid,
	    vlan->pvid ? " pvid" : "", vlan->untagged ? " untagged" : "");
}

/* One `bridge.vlan.add` or `bridge.vlan.del`, filled in. */
static void vlan_op(ncfg_op_t *op, int kind, const char *iface, int64_t vid, int pvid,
    int untagged, int on_self)
{
	memset(op, 0, sizeof(*op));
	op->kind = kind;
	op->u.bridge_vlan.iface = iface;
	op->u.bridge_vlan.vid = vid;
	op->u.bridge_vlan.pvid = pvid;
	op->u.bridge_vlan.untagged = untagged;
	op->u.bridge_vlan.on_self = on_self;
}

/*
 * The VLANs one port carries, made to be exactly the ones the document lists.
 *
 * **Authoritative where present.** A port whose config lists VLANs has exactly
 * those, and anything else the kernel holds for it is removed -- including the
 * VLAN 1 the kernel adds by itself the moment a port joins a filtering bridge.
 * Every real trunk setup begins by deleting that one. A port the document says
 * nothing about keeps whatever it has: the authority is over ports that are
 * configured, not over the bridge.
 *
 * **Per-port VLANs need a port.** A `vlans` on a device that is neither a
 * bridge nor enslaved to one produced a plan that could not converge: the
 * kernel answers `EOPNOTSUPP`, so the apply failed and the same action was
 * planned again on the next reconcile and every one after. Enslavement is
 * asked of the document *and* of the kernel, because either can be the honest
 * answer -- the document says `master` for a port netcfgd enslaves itself, and
 * a device already in a bridge reports one whether or not netcfgd put it
 * there. Only when both are silent is the configuration certainly impossible,
 * and then it is said once rather than attempted for ever (0061).
 *
 * **Driven from the device list rather than from the interfaces**, which is
 * where the Rust reaches it: `plan_bridge_vlans` is called from
 * `plan_interface_contents`, so a port with `vlans` and no `interface` block
 * of its own -- the ordinary shape of a trunk port, which carries no address
 * and never will -- has never had them planned at all. See 0263's divergence
 * list.
 */
void ncfg_plan_bridge_vlans(ncfg_builder_t *builder, const ncfg_device_t *device)
{
	const ncfg_observed_link_t *link;
	ncfg_plan_ids_t             gate = { NULL, 0, 0 };
	ncfg_op_t                   op;
	ncfg_op_t                   inverse;
	ncfg_reason_t               reason;
	int                         on_self;
	int                         wants_one = 0;
	size_t                      i;
	size_t                      j;

	if (device->bridge_vlan_count == 0u) {
		return;
	}
	/* A VLAN on the bridge device itself is a SELF operation; one on a port
	 * is MASTER. Getting it backwards is accepted by the kernel and
	 * configures the wrong device. */
	on_self = device->kind.kind == NCFG_KIND_BRIDGE;
	link = ncfg_observed_link(builder->observed, device->name);
	if (!on_self && !device->master && !(link && link->master)) {
		ncfg_plan_warnf(builder->plan, device->name,
		    "%s has `vlans` and is neither a bridge nor a member of one, so there are no "
		    "per-port vlans to set -- put it in a bridge with `master`, or give it a "
		    "`bridge` block of its own",
		    device->name);
		return;
	}
	ncfg_builder_gate(builder, device->name, &gate);

	/*
	 * The kernel puts VLAN 1 on a port the moment it joins a filtering
	 * bridge, which happens during *this* apply -- so it is not in the
	 * observed state the plan was computed from, and without this the removal
	 * would land on the next reconcile.
	 *
	 * Safe to plan unconditionally because removing a VLAN that is not there
	 * is a silent success: checked against the kernel with filtering both on
	 * and off, and with the id absent.
	 */
	for (i = 0; i < device->bridge_vlan_count; i++) {
		if (device->bridge_vlans[i].vid == 1) {
			wants_one = 1;
		}
	}
	if (!link && !wants_one) {
		vlan_op(&op, NCFG_OP_BRIDGE_VLAN_DEL, device->name, 1, 0, 0, on_self);
		reason = ncfg_plan_reason_unwanted(device->name, "vlans",
		    "1 (the kernel's default)");
		(void)ncfg_builder_push(builder, &op, &reason, gate.ids, gate.count, NULL);
	}

	for (i = 0; i < device->bridge_vlan_count; i++) {
		const ncfg_bridge_vlan_t *wanted = &device->bridge_vlans[i];
		int                       held = 0;

		for (j = 0; link && j < builder->observed->bridge_vlan_count; j++) {
			const ncfg_observed_bridge_vlan_t *vlan =
			    &builder->observed->bridge_vlans[j];

			/* Compared on the flags too: a VLAN that is present but tagged
			 * where the document says untagged is wrong in a way that shows
			 * up as traffic arriving with a tag nobody expected. */
			if (vlan->index == link->index && vlan->vid == wanted->vid &&
			    vlan->pvid == wanted->pvid && vlan->untagged == wanted->untagged) {
				held = 1;
				break;
			}
		}
		if (held) {
			continue;
		}
		vlan_op(&op, NCFG_OP_BRIDGE_VLAN_ADD, device->name, wanted->vid, wanted->pvid,
		    wanted->untagged, on_self);
		vlan_op(&inverse, NCFG_OP_BRIDGE_VLAN_DEL, device->name, wanted->vid, 0, 0,
		    on_self);
		reason = ncfg_plan_reason_absent(device->name, "vlans",
		    render_vlan(builder->plan, wanted));
		(void)ncfg_builder_push(builder, &op, &reason, gate.ids, gate.count, &inverse);
	}

	for (j = 0; link && j < builder->observed->bridge_vlan_count; j++) {
		const ncfg_observed_bridge_vlan_t *present = &builder->observed->bridge_vlans[j];
		int                                asked = 0;

		if (present->index != link->index) {
			continue;
		}
		for (i = 0; i < device->bridge_vlan_count; i++) {
			if (device->bridge_vlans[i].vid == present->vid) {
				asked = 1;
				break;
			}
		}
		if (asked) {
			continue;
		}
		vlan_op(&op, NCFG_OP_BRIDGE_VLAN_DEL, device->name, present->vid, 0, 0, on_self);
		vlan_op(&inverse, NCFG_OP_BRIDGE_VLAN_ADD, device->name, present->vid,
		    present->pvid, present->untagged, on_self);
		reason = ncfg_plan_reason_unwanted(device->name, "vlans",
		    ncfg_plan_internf(builder->plan, "%lld", (long long)present->vid));
		(void)ncfg_builder_push(builder, &op, &reason, gate.ids, gate.count, &inverse);
	}
	ncfg_plan_ids_free(&gate);
}
