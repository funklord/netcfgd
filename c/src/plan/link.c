/*
 * link.c -- the link itself: creating it, correcting it, bringing it up and
 * taking it down.
 *
 * ORDERING
 *   Rule 1: every link is created before anything references it, which is why
 *   the creation gate is a dependency of everything else on that name.
 *   Rule 2: an enslavement happens before the master is addressed or brought
 *   up, which is why a master's actions wait on `enslavements`.
 *   Rule 6: `pre_up` runs before `link.up` and `post_up` after the addressing.
 *   Deliberately not netifrc's order, which runs `up; preup; up` so that a
 *   preup hook can read carrier -- the kernel answers EINVAL for carrier on a
 *   down interface. Decision 0011 keeps this ordering and records the
 *   breakage; do not "fix" it to match netifrc without reading that.
 */
#include "plan_internal.h"

#include "ncfg/apply.h"
#include "ncfg/base.h"

#include <stdio.h>
#include <string.h>

/* ------------------------------------------------------------------------ *
 * Whether a name is worth planning against at all
 * ------------------------------------------------------------------------ */

int ncfg_plan_link_is_plannable(const ncfg_builder_t *builder, const char *name)
{
	const ncfg_device_t *device;

	if (ncfg_observed_link(builder->observed, name)) {
		return 1;
	}
	/*
	 * A PPP interface is created by `pppd` when the session comes up, and a
	 * tunnel by `openvpn`, not by netlink. Neither has anything to address or
	 * route until its daemon brings it into existence.
	 */
	device = ncfg_plan_device(builder->desired, name);
	if (device && (device->kind.kind == NCFG_KIND_PPPOE ||
	    device->kind.kind == NCFG_KIND_OPENVPN)) {
		return 0;
	}
	/*
	 * A device the creation pass declined, having said why. Nothing will bring
	 * it into existence, so an action against it is one that must fail -- the
	 * same reasoning as the absent hardware below, for a name absent by
	 * decision rather than by accident.
	 */
	if (ncfg_plan_names(builder->declined, builder->declined_count, name)) {
		return 0;
	}
	/*
	 * Absent hardware. Planning for a NIC that is not plugged in would fill
	 * every plan with actions that cannot run. A veth peer is the exception:
	 * creating one end creates both, so a name this plan is about to bring
	 * into being is not absent hardware.
	 */
	if ((!device || device->kind.kind == NCFG_KIND_PHYSICAL) &&
	    !ncfg_plan_names(builder->appearing, builder->appearing_count, name)) {
		return 0;
	}
	return 1;
}

/* ------------------------------------------------------------------------ *
 * Creation
 * ------------------------------------------------------------------------ */

void ncfg_plan_link_creation(ncfg_builder_t *builder, const ncfg_device_t *device)
{
	ncfg_plan_ids_t gate = { NULL, 0, 0 };
	ncfg_op_t       op;
	ncfg_op_t       inverse;
	ncfg_reason_t   reason;
	uint32_t        id;

	if (ncfg_observed_link(builder->observed, device->name)) {
		return;
	}
	if (device->kind.kind == NCFG_KIND_PPPOE || device->kind.kind == NCFG_KIND_OPENVPN) {
		/* Planning a `link.create` for either would emit an action that must
		 * fail; starting the backend is what brings it into existence, and
		 * that pass is not in this build. */
		ncfg_plan_warnf(builder->plan, device->name,
		    "`%s` is brought into existence by the daemon that dials it, and this "
		    "build of the planner does not start backends, so nothing here creates "
		    "it or configures what would run over it",
		    device->name);
		return;
	}
	if (device->kind.kind == NCFG_KIND_PHYSICAL) {
		/* A physical device that is not present is not something a plan can
		 * fix. Say so rather than emitting actions that must fail. */
		ncfg_plan_warnf(builder->plan, device->name,
		    "%s is configured but no such device is present; nothing planned for it",
		    device->name);
		return;
	}
	/*
	 * **A veth is created in pairs, so its peer's name has to be free too.**
	 * Creating one whose peer name is already taken answers EEXIST -- and the
	 * message names the device being created rather than the one in the way,
	 * so an operator reads "could not create w0: File exists" about a `w0`
	 * that does not exist. Worse, the same action is planned again on the next
	 * reconcile and every one after, because nothing about the failure changes
	 * the state it was computed from.
	 */
	if (device->kind.kind == NCFG_KIND_VETH && device->kind.veth.peer &&
	    ncfg_observed_link(builder->observed, device->kind.veth.peer)) {
		ncfg_plan_warnf(builder->plan, device->name,
		    "%s is a veth whose peer `%s` is a device that already exists, so the "
		    "pair cannot be created -- the kernel refuses both ends at once and "
		    "names only %s. Rename the peer, or remove the device holding the name",
		    device->name, device->kind.veth.peer, device->name);
		ncfg_builder_note_string(builder, &builder->declined, &builder->declined_count,
		    device->name);
		return;
	}
	/*
	 * **A kind the executor cannot create must not be planned**, which is the
	 * rule the arm above states and did not cover. `ncfg_apply_supported`
	 * refuses `link.create` for a bond, a macvlan, a tunnel and a vlan --
	 * `ncfg_kernel_newlink_of` builds no nest for them -- so emitting one puts
	 * an action in the plan that fails on every apply, for ever, while `ncfg
	 * plan` goes on listing it as work to do. That is the non-convergence this
	 * file's neighbours each carry an arm to prevent.
	 *
	 * **Last of the arms, deliberately.** Every one above refuses a kind for a
	 * reason of its own and says it in its own words -- a physical device that
	 * is not plugged in, a veth whose peer name is taken. Asking the executor
	 * first would answer all of them with one generic sentence, which a test
	 * caught: `eth9` stopped being reported as "no such device is present" and
	 * started being reported as a kind this build cannot create, which is true
	 * and is not what the operator needs to read.
	 *
	 * It became reachable when the planner learned to configure these kinds:
	 * the `link.set_bond` and `link.set_macvlan` passes make such a document
	 * worth writing, and until then nothing produced one. The `set_*` ops are
	 * still planned for a device that already exists, which is the case that
	 * works -- what is refused here is bringing one into being.
	 *
	 * The warning goes when `newlink_of` grows the nest; nothing else has to
	 * change, because this asks the executor rather than keeping its own list.
	 */
	{
		ncfg_op_t probe;
		char      why[NCFG_ERROR_MAX];

		memset(&probe, 0, sizeof(probe));
		probe.kind = NCFG_OP_LINK_CREATE;
		probe.u.link_create.name = device->name;
		probe.u.link_create.kind = &device->kind;
		why[0] = '\0';
		if (!ncfg_apply_supported(&probe, why, sizeof(why))) {
			ncfg_plan_warnf(builder->plan, device->name,
			    "%s is configured but this build cannot create it: %s", device->name,
			    why);
			ncfg_builder_note_string(builder, &builder->declined,
			    &builder->declined_count, device->name);
			return;
		}
	}

	memset(&op, 0, sizeof(op));
	op.kind = NCFG_OP_LINK_CREATE;
	op.u.link_create.name = device->name;
	op.u.link_create.kind = &device->kind;
	memset(&inverse, 0, sizeof(inverse));
	inverse.kind = NCFG_OP_LINK_DELETE;
	inverse.u.named.name = device->name;
	reason = ncfg_plan_reason_absent(device->name, "kind",
	    ncfg_interface_kind_name(device->kind.kind));

	ncfg_builder_gate(builder, device->name, &gate);
	id = ncfg_builder_push(builder, &op, &reason, gate.ids, gate.count, &inverse);
	ncfg_plan_ids_free(&gate);
	ncfg_builder_mark(builder, &builder->gates, &builder->gate_count, device->name, id);
}

/* ------------------------------------------------------------------------ *
 * MTU and MAC
 * ------------------------------------------------------------------------ */

/*
 * The adapter's settings, from the device of the same name.
 *
 * Absent is not an error: a `device` block is optional, and an interface with
 * no device simply states no MTU and no MAC.
 */
void ncfg_plan_link_attributes(ncfg_builder_t *builder, const ncfg_interface_t *interface)
{
	const ncfg_observed_link_t *link;
	const ncfg_device_t        *device;
	ncfg_plan_ids_t             gate = { NULL, 0, 0 };
	ncfg_op_t                   op;
	ncfg_op_t                   inverse;
	ncfg_reason_t               reason;
	char                        seen[32];

	if (!ncfg_plan_link_is_plannable(builder, interface->name)) {
		return;
	}
	link = ncfg_observed_link(builder->observed, interface->name);
	device = ncfg_plan_device(builder->desired, interface->name);
	if (!device) {
		return;
	}
	ncfg_builder_gate(builder, interface->name, &gate);

	if (device->mtu.has && (!link || link->mtu != device->mtu.value)) {
		memset(&op, 0, sizeof(op));
		op.kind = NCFG_OP_LINK_SET_MTU;
		op.u.set_mtu.name = interface->name;
		op.u.set_mtu.mtu = device->mtu.value;
		if (link) {
			(void)snprintf(seen, sizeof(seen), "%lld", (long long)link->mtu);
			memset(&inverse, 0, sizeof(inverse));
			inverse.kind = NCFG_OP_LINK_SET_MTU;
			inverse.u.set_mtu.name = interface->name;
			inverse.u.set_mtu.mtu = link->mtu;
		}
		reason = ncfg_plan_reason_differs(interface->name, "mtu",
		    ncfg_plan_internf(builder->plan, "%lld", (long long)device->mtu.value),
		    link ? ncfg_plan_intern(builder->plan, seen) : "<absent>");
		(void)ncfg_builder_push(builder, &op, &reason, gate.ids, gate.count,
		    link ? &inverse : NULL);
	}

	if (device->mac && (!link || !link->mac || strcmp(link->mac, device->mac) != 0)) {
		memset(&op, 0, sizeof(op));
		op.kind = NCFG_OP_LINK_SET_MAC;
		op.u.set_mac.name = interface->name;
		op.u.set_mac.mac = device->mac;
		if (link && link->mac) {
			memset(&inverse, 0, sizeof(inverse));
			inverse.kind = NCFG_OP_LINK_SET_MAC;
			inverse.u.set_mac.name = interface->name;
			inverse.u.set_mac.mac = link->mac;
		}
		reason = ncfg_plan_reason_differs(interface->name, "mac", device->mac,
		    (link && link->mac) ? link->mac : "<absent>");
		(void)ncfg_builder_push(builder, &op, &reason, gate.ids, gate.count,
		    (link && link->mac) ? &inverse : NULL);
	}
	ncfg_plan_ids_free(&gate);
}

/* ------------------------------------------------------------------------ *
 * Enslavement, and the links that have no interface block
 * ------------------------------------------------------------------------ */

uint32_t ncfg_plan_master(ncfg_builder_t *builder, const char *name)
{
	const ncfg_device_t        *device = ncfg_plan_device(builder->desired, name);
	const ncfg_observed_link_t *link = ncfg_observed_link(builder->observed, name);
	const char                 *wanted = device ? device->master : NULL;
	const char                 *current = link ? link->master : NULL;
	ncfg_plan_ids_t             gate = { NULL, 0, 0 };
	ncfg_op_t                   op;
	ncfg_op_t                   inverse;
	ncfg_reason_t               reason;
	uint32_t                    id = NCFG_PLAN_NO_ACTION;

	if (!wanted && !current) {
		return NCFG_PLAN_NO_ACTION;
	}
	ncfg_builder_gate(builder, name, &gate);
	if (wanted && (!current || strcmp(current, wanted) != 0)) {
		memset(&op, 0, sizeof(op));
		op.kind = NCFG_OP_LINK_SET_MASTER;
		op.u.set_master.name = name;
		op.u.set_master.master = wanted;
		memset(&inverse, 0, sizeof(inverse));
		inverse.kind = NCFG_OP_LINK_UNSET_MASTER;
		inverse.u.named.name = name;
		reason = ncfg_plan_reason_differs(name, "master", wanted,
		    current ? current : "<absent>");
		id = ncfg_builder_push(builder, &op, &reason, gate.ids, gate.count, &inverse);
		/* Rule 2: the master waits for this. */
		ncfg_builder_mark(builder, &builder->enslavements, &builder->enslavement_count,
		    wanted, id);
		ncfg_plan_ids_free(&gate);
		return id;
	}
	if (!wanted && current) {
		memset(&op, 0, sizeof(op));
		op.kind = NCFG_OP_LINK_UNSET_MASTER;
		op.u.named.name = name;
		memset(&inverse, 0, sizeof(inverse));
		inverse.kind = NCFG_OP_LINK_SET_MASTER;
		inverse.u.set_master.name = name;
		inverse.u.set_master.master = current;
		reason = ncfg_plan_reason_unwanted(name, "master", current);
		(void)ncfg_builder_push(builder, &op, &reason, gate.ids, gate.count, &inverse);
	}
	ncfg_plan_ids_free(&gate);
	return NCFG_PLAN_NO_ACTION;
}

/*
 * Bring up a device that has no interface block and must carry traffic.
 *
 * A bridge or bond member and the `ifb` synthesised for ingress shaping both
 * exist precisely so that something can be carried over them, and neither will
 * ever have an `interface` block, because neither carries an address. So they
 * were created, enslaved, and left administratively down -- a bridge port that
 * is down is in the disabled STP state and forwards nothing, so the bridge
 * never gets carrier, and `tc mirred` refuses a down target, so turning on
 * inbound shaping drops every packet that arrives.
 *
 * **Deliberately narrow: being a port, or being an `ifb`.** A plain
 * `device eth9 { mtu = 9000 }` with no interface block is an operator saying
 * something about the hardware and nothing about connecting over it, and
 * `enabled` lives on the interface -- so bringing up every device without a
 * block would be netcfgd deciding a question nobody asked it.
 */
void ncfg_plan_device_up(ncfg_builder_t *builder, const ncfg_device_t *device, uint32_t enslaved)
{
	const ncfg_observed_link_t *link;
	ncfg_plan_ids_t             deps = { NULL, 0, 0 };
	ncfg_op_t                   op;
	ncfg_op_t                   inverse;
	ncfg_reason_t               reason;

	if (!device->master && device->kind.kind != NCFG_KIND_IFB) {
		return;
	}
	if (ncfg_plan_interface(builder->desired, device->name)) {
		return;
	}
	link = ncfg_observed_link(builder->observed, device->name);
	if (link && link->up) {
		return;
	}
	/*
	 * The creation gate, plus this device's own enslavement where one was just
	 * planned. A root action was wrong on both counts: an `ifb` has to exist
	 * before it can be brought up, and a port brought up before it is enslaved
	 * is briefly a live link outside the bridge.
	 */
	ncfg_builder_gate(builder, device->name, &deps);
	ncfg_plan_ids_push(builder->plan, &deps, enslaved);

	memset(&op, 0, sizeof(op));
	op.kind = NCFG_OP_LINK_UP;
	op.u.named.name = device->name;
	memset(&inverse, 0, sizeof(inverse));
	inverse.kind = NCFG_OP_LINK_DOWN;
	inverse.u.named.name = device->name;
	/* Not `enabled`, which is what the interface walk says and what a device
	 * does not have: saying it here would name a key the operator never wrote,
	 * on a device that has no block to write it in. */
	reason = ncfg_plan_reason_differs(device->name, "link", "up", "down");
	(void)ncfg_builder_push(builder, &op, &reason, deps.ids, deps.count, &inverse);
	ncfg_plan_ids_free(&deps);
}

/* ------------------------------------------------------------------------ *
 * Hooks
 * ------------------------------------------------------------------------ */

/*
 * Every hook this interface declares for one phase.
 *
 * A refused or dropped action is `NCFG_PLAN_NO_ACTION` and is not in the plan,
 * so it must not be in anybody's dependency list either -- a dependency on an
 * action that does not exist is a DAG edge to nowhere.
 */
static void plan_hooks(ncfg_builder_t *builder, const ncfg_interface_t *interface, int phase,
    const ncfg_plan_ids_t *deps, ncfg_plan_ids_t *out)
{
	ncfg_op_t     op;
	ncfg_reason_t reason;
	size_t        i;

	for (i = 0; i < interface->hook_count; i++) {
		uint32_t id;

		if (interface->hooks[i].phase != phase) {
			continue;
		}
		memset(&op, 0, sizeof(op));
		op.kind = NCFG_OP_HOOK_RUN;
		op.u.hook.iface = interface->name;
		op.u.hook.phase = phase;
		op.u.hook.path = interface->hooks[i].path;
		/* NULL for the lifecycle phases: a `pre_up` hook runs before there is
		 * an address, and a `down` hook can read what is still on the
		 * interface itself. */
		op.u.hook.value = NULL;
		reason = ncfg_plan_reason_absent(interface->name,
		    ncfg_plan_internf(builder->plan, "hooks[%s]", ncfg_hook_phase_name(phase)),
		    interface->hooks[i].path);
		/* No inverse: netcfgd cannot know what a script did, so commit-confirm
		 * cannot undo it. The warning `ncfg_plan_add` emits says so. */
		id = ncfg_builder_push(builder, &op, &reason, deps ? deps->ids : NULL,
		    deps ? deps->count : 0u, NULL);
		if (out && id != NCFG_PLAN_NO_ACTION) {
			ncfg_plan_ids_push(builder->plan, out, id);
		}
	}
}

/*
 * Take an interface down, in the order the phases describe.
 *
 *   `pre_down`   the interface still works: addresses, routes, all of it.
 *                This is where a script that needs the network goes --
 *                unmounting a share, telling a peer.
 *   `addr.del`   what netcfgd installed, removed explicitly.
 *   `down`       the link is still up and the addresses are gone.
 *   `link.down`
 *   `post_down`  nothing is left to stop.
 *
 * The middle step is what makes the two phases different moments rather than
 * the same one. It is also a fix in its own right: `link.down` flushes IPv6 and
 * **leaves IPv4 behind** -- measured on a real kernel -- so a disabled
 * interface kept a stale address that netcfgd still recorded as its own.
 */
static uint32_t plan_disable(ncfg_builder_t *builder, const ncfg_interface_t *interface,
    const ncfg_plan_ids_t *base, const ncfg_plan_teardown_t *why)
{
	ncfg_plan_ids_t deps = { NULL, 0, 0 };
	ncfg_plan_ids_t withdrawn = { NULL, 0, 0 };
	ncfg_plan_ids_t before_down = { NULL, 0, 0 };
	ncfg_op_t       op;
	ncfg_op_t       inverse;
	ncfg_reason_t   reason;
	uint32_t        id;
	size_t          i;

	ncfg_plan_ids_extend(builder->plan, &deps, base);
	plan_hooks(builder, interface, NCFG_HOOK_PHASE_PRE_DOWN, base, &deps);
	ncfg_plan_ids_extend(builder->plan, &withdrawn, &deps);

	for (i = 0; i < builder->observed->address_count; i++) {
		const ncfg_observed_address_t *address = &builder->observed->addresses[i];

		if (!address->interface || strcmp(address->interface, interface->name) != 0) {
			continue;
		}
		if (!ncfg_ownership_may_remove(address->ownership)) {
			continue;
		}
		memset(&op, 0, sizeof(op));
		op.kind = NCFG_OP_ADDR_DEL;
		op.u.addr_del.iface = interface->name;
		op.u.addr_del.addr = address->address;
		memset(&inverse, 0, sizeof(inverse));
		inverse.kind = NCFG_OP_ADDR_ADD;
		inverse.u.addr_add.iface = interface->name;
		inverse.u.addr_add.addr = address->address;
		reason = ncfg_plan_reason_unwanted(interface->name, why->field, address->address);
		id = ncfg_builder_push(builder, &op, &reason, deps.ids, deps.count, &inverse);
		if (id != NCFG_PLAN_NO_ACTION) {
			ncfg_plan_ids_push(builder->plan, &withdrawn, id);
		}
	}

	ncfg_plan_ids_extend(builder->plan, &before_down, &withdrawn);
	plan_hooks(builder, interface, NCFG_HOOK_PHASE_DOWN, &withdrawn, &before_down);
	memset(&op, 0, sizeof(op));
	op.kind = NCFG_OP_LINK_DOWN;
	op.u.named.name = interface->name;
	memset(&inverse, 0, sizeof(inverse));
	inverse.kind = NCFG_OP_LINK_UP;
	inverse.u.named.name = interface->name;
	reason = ncfg_plan_reason_differs(interface->name, why->field, why->desired,
	    why->observed);
	id = ncfg_builder_push(builder, &op, &reason, before_down.ids, before_down.count,
	    &inverse);

	ncfg_plan_ids_free(&deps);
	ncfg_plan_ids_free(&withdrawn);
	ncfg_plan_ids_free(&before_down);
	if (id == NCFG_PLAN_NO_ACTION) {
		return id;
	}
	{
		ncfg_plan_ids_t after = { NULL, 0, 0 };

		ncfg_plan_ids_push(builder->plan, &after, id);
		plan_hooks(builder, interface, NCFG_HOOK_PHASE_POST_DOWN, &after, NULL);
		ncfg_plan_ids_free(&after);
	}
	return id;
}

/* ------------------------------------------------------------------------ *
 * The interface walk
 * ------------------------------------------------------------------------ */

void ncfg_plan_interface_contents(ncfg_builder_t *builder, const ncfg_interface_t *interface)
{
	const ncfg_observed_link_t *link;
	ncfg_plan_ids_t             base = { NULL, 0, 0 };
	ncfg_plan_ids_t             up_deps = { NULL, 0, 0 };
	ncfg_plan_ids_t             addressing = { NULL, 0, 0 };
	ncfg_plan_ids_t             authentication = { NULL, 0, 0 };
	ncfg_plan_ids_t             source_base = { NULL, 0, 0 };
	ncfg_op_t                   op;
	ncfg_op_t                   inverse;
	ncfg_reason_t               reason;
	int                         bringing_up;
	size_t                      i;

	if (!ncfg_plan_link_is_plannable(builder, interface->name)) {
		return;
	}
	link = ncfg_observed_link(builder->observed, interface->name);
	ncfg_builder_gate(builder, interface->name, &base);
	/* Rule 2: addressing the master, and bringing it up, waits for every
	 * member's enslavement. */
	for (i = 0; i < builder->enslavement_count; i++) {
		if (builder->enslavements[i].name &&
		    strcmp(builder->enslavements[i].name, interface->name) == 0) {
			ncfg_plan_ids_push(builder->plan, &base, builder->enslavements[i].id);
		}
	}

	/*
	 * Whether this plan is bringing the interface into service, which is what
	 * the up hooks are *for*. Both hooks used to be emitted unconditionally,
	 * and two things made that visible against a real kernel: a converged
	 * interface ran its `pre_up` and `post_up` on **every apply** -- so the
	 * second plan was never empty, against the promise that an already-correct
	 * state runs zero hooks -- and a *disabled* interface ran them too,
	 * producing a plan that went `pre_up`, `link.down`, `post_down`,
	 * `post_up`. Decision 0063.
	 */
	bringing_up = interface->enabled && (!link || !link->up);

	ncfg_plan_ids_extend(builder->plan, &up_deps, &base);
	if (bringing_up) {
		/* Rule 6: pre_up runs before link.up. */
		plan_hooks(builder, interface, NCFG_HOOK_PHASE_PRE_UP, &base, &up_deps);

		memset(&op, 0, sizeof(op));
		op.kind = NCFG_OP_LINK_UP;
		op.u.named.name = interface->name;
		memset(&inverse, 0, sizeof(inverse));
		inverse.kind = NCFG_OP_LINK_DOWN;
		inverse.u.named.name = interface->name;
		reason = ncfg_plan_reason_differs(interface->name, "enabled", "true", "false");
		{
			uint32_t        id = ncfg_builder_push(builder, &op, &reason, up_deps.ids,
			    up_deps.count, &inverse);
			ncfg_plan_ids_t after_up = { NULL, 0, 0 };

			ncfg_builder_mark(builder, &builder->link_up, &builder->link_up_count,
			    interface->name, id);
			/*
			 * `up` is the third distinct moment, and the only one of the three
			 * where the link is live and has nothing on it yet: `pre_up` runs
			 * before the kernel will answer for the interface at all (0011),
			 * and `post_up` after the addressing. So this is where a script
			 * sets something that has to be in place before an address exists
			 * -- and the addressing below waits for it, or the ordering would
			 * be a claim rather than a fact. Decision 0076.
			 */
			ncfg_plan_ids_extend(builder->plan, &after_up, &base);
			if (id != NCFG_PLAN_NO_ACTION) {
				ncfg_plan_ids_push(builder->plan, &after_up, id);
			}
			plan_hooks(builder, interface, NCFG_HOOK_PHASE_UP, &after_up, &base);
			ncfg_plan_ids_free(&after_up);
		}
	} else if (!interface->enabled && link && link->up) {
		ncfg_plan_teardown_t disabled = { "enabled", "false", "true" };

		(void)plan_disable(builder, interface, &base, &disabled);
	}

	/*
	 * 802.1X comes before addressing, not after. A port that has not
	 * authenticated drops everything, so a DHCP client started first would
	 * spend its whole backoff sequence talking to a switch that is not
	 * listening -- and then report a failure whose real cause is two steps
	 * earlier. Decision 0008 puts wired 802.1X on the same supplicant as wifi,
	 * so this is the same op either way.
	 *
	 * The addressing waits on it and the routes do not, which is the Rust's
	 * split: a route is installed against an interface rather than negotiated
	 * over it.
	 */
	ncfg_plan_dot1x(builder, interface, &base, &authentication);
	ncfg_plan_ids_extend(builder->plan, &source_base, &base);
	ncfg_plan_ids_extend(builder->plan, &source_base, &authentication);
	for (i = 0; i < interface->addressing_count; i++) {
		ncfg_plan_source(builder, interface, i, &source_base, &addressing);
	}
	/* The document's routes and the report's, through the one function that
	 * answers what the list is -- the teardown asks the same one, so the two
	 * cannot disagree and plan a route that is installed and withdrawn on
	 * alternate reconciles. */
	{
		ncfg_plan_routes_t routes;

		ncfg_plan_routes_for(builder, interface, &routes);
		for (i = 0; i < routes.count; i++) {
			ncfg_plan_route(builder, interface, &routes.routes[i], &base);
		}
		ncfg_plan_routes_free(&routes);
	}

	/* What this interface tells the hosts behind it, after the addressing it
	 * waits on: a router advertising a prefix it does not itself hold is
	 * advertising a route to nowhere. */
	ncfg_plan_advertise(builder, interface, &base, &addressing);

	/*
	 * Rule 6: post_up runs after the last addressing action completes -- and
	 * only where there was one, or where the interface was brought up. "After
	 * the last addressing action" is not a moment that exists in a plan with
	 * no addressing action in it.
	 */
	if (bringing_up || addressing.count != 0u) {
		ncfg_plan_ids_t deps = { NULL, 0, 0 };

		ncfg_plan_ids_extend(builder->plan, &deps, &base);
		ncfg_plan_ids_extend(builder->plan, &deps, &addressing);
		plan_hooks(builder, interface, NCFG_HOOK_PHASE_POST_UP, &deps, NULL);
		ncfg_plan_ids_free(&deps);
	}

	ncfg_plan_ids_free(&base);
	ncfg_plan_ids_free(&up_deps);
	ncfg_plan_ids_free(&addressing);
	ncfg_plan_ids_free(&authentication);
	ncfg_plan_ids_free(&source_base);
}
