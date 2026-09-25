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
#include <stdlib.h>
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

/*
 * The word a reason names a kind by, which is the **configuration language's**
 * and not the document's.
 *
 * `ncfg_interface_kind_name` answers what the document serialises --
 * `wire_guard`, `open_vpn` -- and `document.c` says in as many words that
 * those are not typos to tidy up. A reason is read by an operator against the
 * file they wrote, where the words are `wireguard` and `openvpn`, so the two
 * spellings are both right and each belongs to one surface.
 *
 * This port printed the document's in `ncfg plan` and in the reason's
 * `desired` field in the plan JSON, where the Rust prints the language's --
 * and beside an observed side that already said `wireguard`, so one line
 * carried both spellings of one kind.
 *
 * The table is the model's, so this is which of the two to ask and the one
 * kind that answers with something narrower than itself.
 */
static const char *kind_word(const ncfg_interface_kind_t *kind)
{
	if (!kind) {
		return NULL;
	}
	switch (kind->kind) {
	case NCFG_KIND_TUNNEL:
		/* Its encapsulation rather than the word "tunnel": `gre` is what the
		 * operator wrote and what the kernel calls it. The only kind whose
		 * reason names something narrower than its kind. */
		return ncfg_tunnel_kind_name(kind->tunnel.mode);
	default:
		return ncfg_interface_kind_language_name(kind->kind);
	}
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
		/*
		 * Planning a `link.create` for either would emit an action that must
		 * fail; starting the backend is what brings it into existence, and
		 * `ncfg_plan_session` is the pass that does it -- from this same
		 * device walk, one call earlier.
		 *
		 * **Silently, where this used to warn.** The sentence here said the
		 * planner started no such backend, which stopped being true when that
		 * pass landed; and the warning an operator wants -- that the
		 * addressing is waiting rather than missing -- is that pass's, said
		 * once. Two warnings about one device would be this file and that one
		 * both claiming the subject.
		 */
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
	reason = ncfg_plan_reason_absent(device->name, "kind", kind_word(&device->kind));

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
 * What a hook has already been told, for the two phases that remember.
 *
 * netcfgd's own memory rather than kernel state -- `observed.h` is careful
 * about the distinction, and it is the whole of what makes an event hook fire
 * once per event rather than once per reconcile. NULL where nothing has been
 * recorded, which is a hook that has never run and is not the same as one told
 * something that has since changed.
 */
static const char *hook_told(const ncfg_observed_t *observed, const char *interface, int phase)
{
	size_t at;

	if (!observed || !interface) {
		return NULL;
	}
	for (at = 0; at < observed->hook_state_count; at++) {
		const ncfg_observed_hook_state_t *state = &observed->hook_state[at];

		if (state->phase == phase && state->interface &&
		    strcmp(state->interface, interface) == 0) {
			return state->value;
		}
	}
	return NULL;
}

/* Whether this interface declares a hook for `phase`. */
static int declares_hook(const ncfg_interface_t *interface, int phase)
{
	size_t at;

	for (at = 0; at < interface->hook_count; at++) {
		if (interface->hooks[at].phase == phase) {
			return 1;
		}
	}
	return 0;
}

/*
 * Every hook for one phase, carrying a value, with a reason naming what moved.
 *
 * The lifecycle phases go through `plan_hooks` above: they carry no value and
 * their reason is the hook's own path, because "what changed" is the
 * transition the hook brackets. `lease` and `carrier` are the other kind --
 * they fire on a value moving, so the value is in the environment and the
 * reason says what it moved from.
 */
static void plan_event_hooks(ncfg_builder_t *builder, const ncfg_interface_t *interface,
    int phase, const char *now, const char *before, const ncfg_plan_ids_t *deps)
{
	ncfg_op_t     op;
	ncfg_reason_t reason;
	size_t        at;

	for (at = 0; at < interface->hook_count; at++) {
		if (interface->hooks[at].phase != phase) {
			continue;
		}
		memset(&op, 0, sizeof(op));
		op.kind = NCFG_OP_HOOK_RUN;
		op.u.hook.iface = interface->name;
		op.u.hook.phase = phase;
		op.u.hook.path = interface->hooks[at].path;
		op.u.hook.value = now;
		reason = ncfg_plan_reason_differs(interface->name,
		    ncfg_hook_phase_name((ncfg_hook_phase_t)phase), now,
		    before ? before : "<absent>");
		/* No inverse, as every hook: netcfgd cannot know what a script did. */
		(void)ncfg_builder_push(builder, &op, &reason, deps ? deps->ids : NULL,
		    deps ? deps->count : 0u, NULL);
	}
}

/*
 * Run a `carrier` hook where the cable has come or gone since it last ran.
 *
 * **The one event on a laptop that nothing else reports** (0068): `pre_up`
 * runs before there is a cable and `post_up` after the addressing, and neither
 * fires when somebody unplugs one.
 *
 * **Where in the plan it goes depends on which way it went**, which is the
 * reasoning `down` needed (0063). Lost: early, at the interface's own gate --
 * teardown runs last, so the routes and addresses are still there, which is
 * what lets a script stop a service that is using them. Gained: after the
 * addressing, like `post_up` -- a script that reacts to a cable by connecting
 * somewhere needs the network to work, and before the addresses it does not.
 */
static void plan_carrier_hook(ncfg_builder_t *builder, const ncfg_interface_t *interface,
    const ncfg_plan_ids_t *base, const ncfg_plan_ids_t *addressing)
{
	const ncfg_observed_link_t *link;
	ncfg_plan_ids_t             deps;
	const char                 *now;
	const char                 *told;
	size_t                      at;

	if (!declares_hook(interface, NCFG_HOOK_PHASE_CARRIER)) {
		return;
	}
	link = ncfg_observed_link(builder->observed, interface->name);
	if (!link) {
		return;
	}
	now = link->carrier ? "up" : "down";
	told = hook_told(builder->observed, interface->name, NCFG_HOOK_PHASE_CARRIER);
	if (told && strcmp(told, now) == 0) {
		return;
	}
	memset(&deps, 0, sizeof(deps));
	if (base) {
		for (at = 0; at < base->count; at++) {
			ncfg_plan_ids_push(builder->plan, &deps, base->ids[at]);
		}
	}
	if (link->carrier && addressing) {
		for (at = 0; at < addressing->count; at++) {
			ncfg_plan_ids_push(builder->plan, &deps, addressing->ids[at]);
		}
	}
	plan_event_hooks(builder, interface, NCFG_HOOK_PHASE_CARRIER, now, told, &deps);
}

/*
 * Whether this address is a lease rather than something the kernel made.
 *
 * netcfgd does not implement DHCP (0004) and never sees the protocol, so "a
 * lease arrived" is not an event it is told about. What it has is an address
 * on an interface that **it did not install**, and that works for any client.
 *
 * Three exclusions, each an address the kernel made rather than a lease: one
 * netcfgd owns or knows the origin of, one the kernel tags as its own -- the
 * `IFA_PROTO` values `kernel_lo`, `kernel_ra` and `kernel_ll` -- and, by value,
 * a link-local or loopback. The last is there because a kernel older than 5.18
 * reports no `IFA_PROTO` at all and every address would otherwise look like a
 * lease; a SLAAC address is the case that matters, being neither netcfgd's nor
 * a lease and indistinguishable from one without the tag.
 */
static int address_is_a_lease(const ncfg_observed_address_t *address)
{
	static const int64_t kernel_protos[] = { 1, 2, 3 };
	ncfg_address_t       value;
	size_t               at;

	if (address->origin.has || address->ownership == NCFG_OWNERSHIP_OURS) {
		return 0;
	}
	if (address->proto.has) {
		for (at = 0; at < sizeof(kernel_protos) / sizeof(kernel_protos[0]); at++) {
			if (address->proto.value == kernel_protos[at]) {
				return 0;
			}
		}
	}
	if (!address->address || !ncfg_address_parse(address->address, &value, NULL, 0)) {
		return 0;
	}
	if (!value.is_ipv6) {
		/* 169.254/16 and 127/8. */
		return !(value.bytes[0] == 169u && value.bytes[1] == 254u) && value.bytes[0] != 127u;
	}
	/* fe80::/10, and ::1. */
	if ((value.bytes[0] == 0xfeu) && (value.bytes[1] & 0xc0u) == 0x80u) {
		return 0;
	}
	for (at = 0; at < 15u; at++) {
		if (value.bytes[at] != 0u) {
			return 1;
		}
	}
	return value.bytes[15] != 1u;
}

/*
 * Run a `lease` hook where the lease has moved since it last ran.
 *
 * **It fires once per lease, not once per reconcile**, which is why there is a
 * record at all. The record is written whether or not the hook succeeded: a
 * failing `lease` hook that kept the plan non-empty would be a plan that never
 * converges, and the failure is in the journal instead.
 *
 * The first apply of a fresh interface will not fire it -- the client is being
 * started in this same plan and the address arrives seconds later. The daemon
 * gets there on the netlink event; `ncfg apply` needs a second run, which is
 * the shape a PPPoE session has too.
 */
void ncfg_plan_lease_hooks(ncfg_builder_t *builder)
{
	size_t i;

	for (i = 0; i < builder->desired->interface_count; i++) {
		const ncfg_interface_t *interface = &builder->desired->interfaces[i];
		ncfg_plan_ids_t         gate;
		const char             *leased = NULL;
		const char             *told;
		int                     wants_v4 = 0;
		int                     wants_v6 = 0;
		size_t                  at;

		if (!interface->name || !declares_hook(interface, NCFG_HOOK_PHASE_LEASE)) {
			continue;
		}
		for (at = 0; at < interface->addressing_count; at++) {
			if (interface->addressing[at].kind == (int)NCFG_ADDRESS_SOURCE_DHCP4) {
				wants_v4 = 1;
			} else if (interface->addressing[at].kind ==
			    (int)NCFG_ADDRESS_SOURCE_DHCP6) {
				wants_v6 = 1;
			}
		}
		if (!wants_v4 && !wants_v6) {
			continue;
		}
		for (at = 0; at < builder->observed->address_count && !leased; at++) {
			const ncfg_observed_address_t *address = &builder->observed->addresses[at];
			ncfg_address_t                 value;

			if (!address->interface || strcmp(address->interface, interface->name) != 0) {
				continue;
			}
			if (!address_is_a_lease(address) ||
			    !ncfg_address_parse(address->address, &value, NULL, 0)) {
				continue;
			}
			/* The family the document asked for, so a SLAAC address on an
			 * interface that asked only for DHCPv4 is not read as its lease. */
			if ((value.is_ipv6 && wants_v6) || (!value.is_ipv6 && wants_v4)) {
				leased = address->address;
			}
		}
		if (!leased) {
			continue;
		}
		told = hook_told(builder->observed, interface->name, NCFG_HOOK_PHASE_LEASE);
		if (told && strcmp(told, leased) == 0) {
			continue;
		}
		memset(&gate, 0, sizeof(gate));
		ncfg_builder_gate(builder, interface->name, &gate);
		plan_event_hooks(builder, interface, NCFG_HOOK_PHASE_LEASE, leased, told, &gate);
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
	ncfg_plan_ids_t             serving = { NULL, 0, 0 };
	ncfg_plan_ids_t             joining = { NULL, 0, 0 };
	ncfg_plan_ids_t             source_base = { NULL, 0, 0 };
	ncfg_op_t                   op;
	ncfg_op_t                   inverse;
	ncfg_reason_t               reason;
	int                         bringing_up;
	int                         cycling;
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
	/*
	 * **A cycle asked for by name, and it is a `link.down` like any other.**
	 * 0152's option half: the daemon advanced this modem to another SIM
	 * source and published the choice, and the `pre_up` hook that acts on the
	 * choice fires at bring-up -- so a link that is still up never sees it.
	 * Taking it down through `plan_disable` rather than emitting a bare
	 * `link.down` is what makes the rest of that function's work happen too:
	 * the `pre_down` hook, and the addresses that `link.down` would otherwise
	 * leave behind (it flushes IPv6 and keeps IPv4, measured on a real
	 * kernel).
	 *
	 * Folded into `base`, so the bring-up below waits for it and the order is
	 * down, `pre_up`, up. `cycling` then makes `bringing_up` true, because the
	 * link this plan is about to raise is one this plan just lowered.
	 */
	cycling = interface->enabled && link && link->up &&
	    ncfg_plan_names(builder->options ? builder->options->cycle : NULL,
	    builder->options ? builder->options->cycle_count : 0u, interface->name);
	if (cycling) {
		ncfg_plan_teardown_t switched = { "modem.sim", "the next source", "the one it had" };
		uint32_t             down = plan_disable(builder, interface, &base, &switched);

		if (down != NCFG_PLAN_NO_ACTION) {
			ncfg_plan_ids_push(builder->plan, &base, down);
		}
	}

	bringing_up = interface->enabled && (cycling || !link || !link->up);

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
	/*
	 * And the access point, in the same place and for a sharper version of the
	 * same reason: hostapd puts the radio into AP mode, which is a mode change
	 * the kernel takes only on a link that is down, so an address added first
	 * is an address that may not survive the start. `access_point.c` has the
	 * rest, including why one interface takes one prerequisite and not two.
	 */
	ncfg_plan_access_point(builder, interface, &base, &serving);
	/*
	 * And the radio that joins a network rather than offering one, last of the
	 * three for the reason `radio.c` gives: an interface carrying a `dot1x`
	 * block has already said what its supplicant is for, and a radio running
	 * hostapd does not also join networks with the same interface. The three
	 * calls in this order are what makes "one prerequisite per interface" true
	 * -- the Rust returns at the first that applies, and each of these three
	 * declines where an earlier one took it.
	 */
	ncfg_plan_radio_supplicant(builder, interface, &base, &joining);
	ncfg_plan_ids_extend(builder->plan, &source_base, &base);
	ncfg_plan_ids_extend(builder->plan, &source_base, &authentication);
	ncfg_plan_ids_extend(builder->plan, &source_base, &serving);
	/* The addressing waits on it for `dot1x.c`'s reason sharpened by one step:
	 * a radio that has not associated carries nothing at all, so a DHCP client
	 * started first talks to a network this machine has not joined. */
	ncfg_plan_ids_extend(builder->plan, &source_base, &joining);
	for (i = 0; i < interface->addressing_count; i++) {
		ncfg_plan_source(builder, interface, i, &source_base, &addressing);
	}
	/*
	 * And a client already running with a metric the document has moved on
	 * from, after the sources for a reason: `ncfg_plan_backend` starts one
	 * that is *not* running and returns at once when one is, so the two never
	 * both fire -- a client this pass just planned a start for has nothing
	 * running to restart, and one that is running is the only case this can
	 * see. Same prerequisites as the source it belongs to.
	 */
	ncfg_plan_metric_restart(builder, interface, &source_base);
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
	/*
	 * **Outside the `bringing_up` gate above**, and that is the whole
	 * difference between this and `post_up`: a cable going out is an event on
	 * an interface nothing else in this plan touches, so a pass that ran only
	 * where something was being brought up would never see one. The pass takes
	 * the addressing as a dependency only when the cable came *in*.
	 */
	plan_carrier_hook(builder, interface, &base, &addressing);

	ncfg_plan_ids_free(&base);
	ncfg_plan_ids_free(&up_deps);
	ncfg_plan_ids_free(&addressing);
	ncfg_plan_ids_free(&authentication);
	ncfg_plan_ids_free(&serving);
	ncfg_plan_ids_free(&joining);
	ncfg_plan_ids_free(&source_base);
}

/* ------------------------------------------------------------------------ *
 * Remaking a link the kernel will not change (0059)
 * ------------------------------------------------------------------------ */

/*
 * The word the kernel calls this kind, or NULL for one that is never remade.
 *
 * `netcfgd_plan::recreatable_kind`. Not `ncfg_interface_kind_name`, which is
 * the document's word, nor the language's: this is compared against
 * `IFLA_INFO_KIND`, so a tunnel answers with its mode and a `wire_guard`
 * answers `wireguard`.
 *
 * A physical device, a PPPoE session and an OpenVPN tunnel answer NULL. None
 * is made by netlink, so none can be remade by deleting it -- which is the
 * same set `ncfg_plan_link_creation` declines to create.
 */
static const char *recreatable_kind(const ncfg_interface_kind_t *kind)
{
	switch ((ncfg_interface_kind_tag_t)kind->kind) {
	case NCFG_KIND_BRIDGE:
		return "bridge";
	case NCFG_KIND_BOND:
		return "bond";
	case NCFG_KIND_VLAN:
		return "vlan";
	case NCFG_KIND_VXLAN:
		return "vxlan";
	case NCFG_KIND_WIREGUARD:
		return "wireguard";
	case NCFG_KIND_DUMMY:
		return "dummy";
	case NCFG_KIND_VETH:
		return "veth";
	case NCFG_KIND_VRF:
		return "vrf";
	case NCFG_KIND_MACVLAN:
		return "macvlan";
	case NCFG_KIND_TUNNEL:
		return ncfg_tunnel_kind_name(kind->tunnel.mode);
	case NCFG_KIND_IFB:
		return "ifb";
	/* **Both modes are `tun` to the kernel.** One `rtnl_link_ops` is
	 * registered for tun and tap alike, so this catches a `tun` block whose
	 * name is held by something else entirely and does not catch a block
	 * changed from `tun` to `tap`. The second wants `IFLA_TUN_TYPE`, which
	 * this observation does not read; recorded rather than worked around
	 * (0254). */
	case NCFG_KIND_TUN:
		return "tun";
	case NCFG_KIND_PHYSICAL:
	case NCFG_KIND_PPPOE:
	case NCFG_KIND_OPENVPN:
		break;
	}
	return NULL;
}

/*
 * Why this link has to be remade rather than corrected, or 0.
 *
 * `netcfgd_plan::recreation_reason`, and the three shapes it answers are the
 * three the kernel takes and ignores (0059, 0060): a kind that is not the one
 * asked for, a VLAN's or a macvlan's parent, and a VLAN's id or tag protocol.
 *
 * A VXLAN's and a tunnel's underlay is deliberately **not** here: it lives in
 * their own nest, the kernel moves it, and the set passes correct it in place.
 */
static int recreation_reason(const ncfg_interface_kind_t *kind,
    const ncfg_observed_link_t *link, const char **field, const char **wanted,
    const char **seen, char *scratch, size_t scratch_size)
{
	const char *kernel = recreatable_kind(kind);
	const char *parent = NULL;

	if (!kernel) {
		return 0;
	}
	/*
	 * An empty kind is a device with no `LINKINFO` at all -- a NIC, or the
	 * loopback. Not compared: the document says this is a dummy and the
	 * kernel says nothing, and the honest reading of that is "somebody else's
	 * device with a name netcfgd wants", which the ownership check turns into
	 * a sentence rather than a deletion.
	 */
	if (link->kind && link->kind[0] && strcmp(link->kind, kernel) != 0) {
		*field = "kind";
		*wanted = kernel;
		*seen = link->kind;
		return 1;
	}
	if (kind->kind == NCFG_KIND_VLAN) {
		parent = kind->vlan.parent;
	} else if (kind->kind == NCFG_KIND_MACVLAN) {
		parent = kind->macvlan.parent;
	}
	if (parent && link->parent && strcmp(parent, link->parent) != 0) {
		*field = "parent";
		*wanted = parent;
		*seen = link->parent;
		return 1;
	}
	if (kind->kind != NCFG_KIND_VLAN || !link->vlan) {
		return 0;
	}
	/*
	 * Only where the kernel answered. A VLAN whose `INFO_DATA` did not
	 * arrive, or whose tag protocol this build has no word for, is not
	 * compared -- an interface is not thrown away over an unanswered
	 * question, which is 0052's "absent is not false" applied to the most
	 * destructive action in the planner.
	 */
	if (link->vlan->id.has && link->vlan->id.value != kind->vlan.id) {
		int written = snprintf(scratch, scratch_size, "%lld|%lld",
		    (long long)kind->vlan.id, (long long)link->vlan->id.value);

		if (written < 0 || (size_t)written >= scratch_size) {
			return 0;
		}
		*field = "vlan.id";
		*wanted = scratch;
		*seen = strchr(scratch, '|') + 1;
		*(strchr(scratch, '|')) = '\0';
		return 1;
	}
	if (link->vlan->protocol) {
		const char *asked = ncfg_vlan_protocol_name(kind->vlan.protocol);

		if (asked && strcmp(asked, link->vlan->protocol) != 0) {
			*field = "vlan.protocol";
			*wanted = asked;
			*seen = link->vlan->protocol;
			return 1;
		}
	}
	return 0;
}

/*
 * Delete every link the kernel will not change, and say which they were.
 *
 * `netcfgd_plan::plan_recreation`, and 0059's three steps: find them, stop
 * what netcfgd runs on them and emit the delete, and hand back the names so
 * the rest of the plan can be made against an observation they are not in.
 *
 * **Devices, not interfaces.** A kind lives on a `device` and a device need
 * not have an `interface` block at all; walking the interfaces instead is how
 * the Rust once had a VXLAN that was a dummy in the kernel produce `nothing to
 * do` -- no recreation, and not even the warning this exists to print.
 *
 * **Only a link netcfgd created.** This is the one place in the planner that
 * throws an interface away, so the ownership rule that governs addresses and
 * routes governs it too: a link netcfgd has no record of making gets a
 * sentence naming what differs and what correcting it would cost, and is left
 * alone. That leaves a real gap and it is the right gap -- the alternative is
 * a config file that deletes interfaces netcfgd never made.
 *
 * Answers how many names were written into `gone`, which is at most
 * `gone_max`.
 */
size_t ncfg_plan_recreation(ncfg_builder_t *builder, const char **gone, size_t gone_max)
{
	size_t count = 0;
	size_t i;

	for (i = 0; i < builder->desired->device_count && count < gone_max; i++) {
		const ncfg_device_t        *device = &builder->desired->devices[i];
		const ncfg_observed_link_t *link =
		    ncfg_observed_link(builder->observed, device->name);
		const ncfg_interface_t     *interface = NULL;
		const char                 *field = NULL;
		const char                 *wanted = NULL;
		const char                 *seen = NULL;
		char                        scratch[64];
		ncfg_plan_ids_t             stopped;
		ncfg_reason_t               reason;
		ncfg_op_t                   op;
		uint32_t                    id;
		size_t                      at;

		if (!link ||
		    !recreation_reason(&device->kind, link, &field, &wanted, &seen, scratch,
		    sizeof(scratch))) {
			continue;
		}
		if (!ncfg_ownership_may_remove(link->ownership)) {
			ncfg_plan_warnf(builder->plan, device->name,
			    "the %s of %s is %s in the config and %s in the kernel, and the kernel "
			    "will not change it on an interface that exists -- correcting it means "
			    "deleting %s and making it again, which netcfgd will not do to a link "
			    "it did not create", field, device->name, wanted, seen, device->name);
			continue;
		}
		for (at = 0; at < builder->desired->interface_count; at++) {
			if (strcmp(builder->desired->interfaces[at].name, device->name) == 0) {
				interface = &builder->desired->interfaces[at];
				break;
			}
		}
		/*
		 * What runs on it stops first. A client bound to an interface that is
		 * about to be deleted would be left holding a name that comes back as
		 * a different device, with netcfgd's own record still saying it runs
		 * -- a plan that converges while nothing is leasing.
		 */
		memset(&stopped, 0, sizeof(stopped));
		for (at = 0; at < builder->observed->backend_count; at++) {
			const ncfg_observed_backend_t *backend = &builder->observed->backends[at];
			ncfg_op_t                      restart;
			uint32_t                       stop_id;

			if (!backend->interface || strcmp(backend->interface, device->name) != 0) {
				continue;
			}
			memset(&op, 0, sizeof(op));
			op.kind = NCFG_OP_BACKEND_STOP;
			op.u.backend.kind = backend->kind;
			op.u.backend.iface = device->name;
			memset(&restart, 0, sizeof(restart));
			restart.kind = NCFG_OP_BACKEND_START;
			restart.u.backend.kind = backend->kind;
			restart.u.backend.iface = device->name;
			memset(&reason, 0, sizeof(reason));
			reason.interface = device->name;
			reason.field = field;
			reason.desired = ncfg_plan_internf(builder->plan,
			    "%s, which needs %s remade", wanted, device->name);
			reason.observed = seen;
			stop_id = ncfg_builder_push(builder, &op, &reason, NULL, 0, &restart);
			if (stop_id != NCFG_PLAN_NO_ACTION) {
				ncfg_plan_ids_push(builder->plan, &stopped, stop_id);
			}
		}
		/*
		 * The interface is about to stop existing, so it goes down as far as a
		 * hook is concerned -- and it comes back in this same plan, where
		 * `pre_up` and `post_up` fire again because the creation pass plans it
		 * as absent. Firing `down` here is what makes those two symmetrical.
		 */
		if (interface) {
			plan_hooks(builder, interface, NCFG_HOOK_PHASE_DOWN, &stopped, &stopped);
		}
		memset(&op, 0, sizeof(op));
		op.kind = NCFG_OP_LINK_DELETE;
		op.u.named.name = device->name;
		memset(&reason, 0, sizeof(reason));
		reason.interface = device->name;
		reason.field = field;
		reason.desired = wanted;
		reason.observed = seen;
		/*
		 * No inverse. The create that follows is the inverse in every sense
		 * that matters and is in this same plan; offering `link.create` here
		 * would claim commit-confirm can put back an interface's addresses and
		 * routes, which it cannot -- what this deletes is remade from the
		 * document rather than from the observation.
		 */
		id = ncfg_builder_push(builder, &op, &reason, stopped.ids, stopped.count, NULL);
		ncfg_plan_ids_free(&stopped);
		/*
		 * Refused by a guard, or dropped because the device is unmanaged. The
		 * interface is then left exactly as it is: not deleted, and -- because
		 * its name does not go in the list -- not planned for as though it had
		 * been.
		 */
		if (id == NCFG_PLAN_NO_ACTION) {
			continue;
		}
		if (interface) {
			ncfg_plan_ids_t after;

			memset(&after, 0, sizeof(after));
			ncfg_plan_ids_push(builder->plan, &after, id);
			plan_hooks(builder, interface, NCFG_HOOK_PHASE_POST_DOWN, &after, NULL);
			ncfg_plan_ids_free(&after);
		}
		ncfg_builder_mark(builder, &builder->gates, &builder->gate_count, device->name,
		    id);
		gone[count++] = device->name;
	}
	return count;
}

/* Whether this name is one of the links about to be deleted. NULL is not. */
static int doomed(const char *const *gone, size_t count, const char *name)
{
	size_t i;

	if (!name) {
		return 0;
	}
	for (i = 0; i < count; i++) {
		if (gone[i] && strcmp(gone[i], name) == 0) {
			return 1;
		}
	}
	return 0;
}

/*
 * The same observation with some links, and everything the kernel holds on
 * them, taken out.
 *
 * **This is 0059's whole design.** Every pass below then plans for a remade
 * interface exactly as it plans for one that was never there: the creation
 * pass makes it, the addressing pass puts its addresses back, the routing pass
 * its routes, the backend pass restarts its client. None of them knows this
 * happened, and a pass added later gets it right without being told. The
 * alternative -- a flag threaded through eleven passes, each deciding what a
 * "being replaced" interface means for it -- is the same information written
 * eleven times.
 *
 * **A shallow copy, and it must never be freed as an observation.** The Rust
 * clones; this borrows every string from the original, which the builder holds
 * and which outlives the plan. `ncfg_plan_observed_release` frees the four
 * arrays and nothing inside them.
 *
 * What is taken out, each of which was a defect the Rust's first version had:
 *
 *   * the links themselves;
 *   * their **addresses and routes**, or the passes that would put them back
 *     see them already present and plan nothing -- the interface comes back
 *     bare and the plan says there was nothing to do;
 *   * their **backends**, so the client is started again;
 *   * the **`master` of every link enslaved to one**, or the enslavement pass
 *     sees the membership it wants and the remade bridge comes back empty;
 *   * an **`ingress_redirect` onto one**, which is about to be no redirect.
 *
 * What is deliberately **not** taken out is the three `*_applied` lists: those
 * record that netcfgd once set a qdisc, a redirect or a sysctl, which is still
 * true and is what makes deleting the setting from the document mean
 * something. What the kernel held went away with the link.
 *
 * 0 where there was nothing to take out, which is every ordinary plan -- this
 * must not copy an observation to change nothing.
 */
int ncfg_plan_observed_without(const ncfg_observed_t *observed, const char *const *gone,
    size_t gone_count, ncfg_observed_t *out)
{
	size_t i;
	size_t at;

	if (!gone_count) {
		return 0;
	}
	*out = *observed;
	out->links = calloc(observed->link_count ? observed->link_count : 1u,
	    sizeof(*out->links));
	out->addresses = calloc(observed->address_count ? observed->address_count : 1u,
	    sizeof(*out->addresses));
	out->routes = calloc(observed->route_count ? observed->route_count : 1u,
	    sizeof(*out->routes));
	out->backends = calloc(observed->backend_count ? observed->backend_count : 1u,
	    sizeof(*out->backends));
	if (!out->links || !out->addresses || !out->routes || !out->backends) {
		ncfg_plan_observed_release(out);
		return 0;
	}
	out->link_count = 0;
	out->address_count = 0;
	out->route_count = 0;
	out->backend_count = 0;
	/*
	 * Neither of these is read by the planner and both describe the machine as
	 * it is rather than as this hypothetical leaves it: a set's choice made
	 * against links that are about to be deleted would be a choice about
	 * nothing. Empty says "not computed", which is what it is.
	 */
	out->linksets = NULL;
	out->linkset_count = 0u;
	out->inventory = NULL;
	out->inventory_count = 0u;
	for (i = 0; i < observed->link_count; i++) {
		if (doomed(gone, gone_count, observed->links[i].name)) {
			continue;
		}
		at = out->link_count++;
		out->links[at] = observed->links[i];
		if (doomed(gone, gone_count, out->links[at].master)) {
			out->links[at].master = NULL;
		}
		if (doomed(gone, gone_count, out->links[at].ingress_redirect)) {
			out->links[at].ingress_redirect = NULL;
		}
	}
	for (i = 0; i < observed->address_count; i++) {
		if (!doomed(gone, gone_count, observed->addresses[i].interface)) {
			out->addresses[out->address_count++] = observed->addresses[i];
		}
	}
	for (i = 0; i < observed->route_count; i++) {
		if (!doomed(gone, gone_count, observed->routes[i].interface)) {
			out->routes[out->route_count++] = observed->routes[i];
		}
	}
	for (i = 0; i < observed->backend_count; i++) {
		if (!doomed(gone, gone_count, observed->backends[i].interface)) {
			out->backends[out->backend_count++] = observed->backends[i];
		}
	}
	return 1;
}

void ncfg_plan_observed_release(ncfg_observed_t *filtered)
{
	free(filtered->links);
	free(filtered->addresses);
	free(filtered->routes);
	free(filtered->backends);
	memset(filtered, 0, sizeof(*filtered));
}
