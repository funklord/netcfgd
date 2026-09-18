/*
 * build.c -- the builder, the one place a guard can stop an action, and the
 * order the passes run in.
 *
 * WHAT IS PORTED AND WHAT IS NOT
 *   The Rust planner is seven thousand lines and thirty passes. This is four
 *   of them -- link creation, link attributes, addressing and routes, and
 *   teardown -- and the rest is not here.
 *
 *   **That is a hazard rather than a gap, and `warn_unported` below is what
 *   makes it one the operator can see.** The contract this module is written
 *   against says it in as many words: *a plan that omits something without
 *   saying so reports "nothing to do" about a config that asked for two
 *   things*. Decision 0061 is the same rule for a feature the Rust itself has
 *   not built yet; this is that rule turned on the port. Every block the
 *   document carries that no pass here reads gets a sentence naming the block
 *   and the interface it is on, so a plan from this build is never quieter
 *   than the configuration it was given.
 *
 *   When a pass lands, its arm comes out of `warn_unported` in the same
 *   commit. A warning that outlives the gap it describes is the other way this
 *   goes wrong.
 */
#include "plan_internal.h"

#include "ncfg/base.h"

#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------------ *
 * The small lists
 * ------------------------------------------------------------------------ */

void ncfg_plan_ids_push(ncfg_plan_t *plan, ncfg_plan_ids_t *ids, uint32_t id)
{
	uint32_t *grown;
	size_t    wanted;

	if (ids->count == ids->capacity) {
		wanted = ids->capacity ? ids->capacity * 2u : 8u;
		grown = realloc(ids->ids, wanted * sizeof(*grown));
		if (!grown) {
			plan->failed = 1;
			return;
		}
		ids->ids = grown;
		ids->capacity = wanted;
	}
	ids->ids[ids->count++] = id;
}

void ncfg_plan_ids_extend(ncfg_plan_t *plan, ncfg_plan_ids_t *ids, const ncfg_plan_ids_t *from)
{
	size_t i;

	for (i = 0; i < from->count; i++) {
		ncfg_plan_ids_push(plan, ids, from->ids[i]);
	}
}

void ncfg_plan_ids_free(ncfg_plan_ids_t *ids)
{
	free(ids->ids);
	ids->ids = NULL;
	ids->count = 0;
	ids->capacity = 0;
}

int ncfg_plan_names(const char *const *list, size_t count, const char *name)
{
	size_t i;

	if (!name) {
		return 0;
	}
	for (i = 0; i < count; i++) {
		if (list[i] && strcmp(list[i], name) == 0) {
			return 1;
		}
	}
	return 0;
}

const ncfg_device_t *ncfg_plan_device(const ncfg_document_t *desired, const char *name)
{
	size_t i;

	for (i = 0; i < desired->device_count; i++) {
		if (desired->devices[i].name && name &&
		    strcmp(desired->devices[i].name, name) == 0) {
			return &desired->devices[i];
		}
	}
	return NULL;
}

const ncfg_interface_t *ncfg_plan_interface(const ncfg_document_t *desired, const char *name)
{
	size_t i;

	for (i = 0; i < desired->interface_count; i++) {
		if (desired->interfaces[i].name && name &&
		    strcmp(desired->interfaces[i].name, name) == 0) {
			return &desired->interfaces[i];
		}
	}
	return NULL;
}

void ncfg_builder_mark(ncfg_builder_t *builder, ncfg_plan_mark_t **list, size_t *count,
    const char *name, uint32_t id)
{
	ncfg_plan_mark_t *grown = realloc(*list, (*count + 1u) * sizeof(**list));

	if (!grown) {
		builder->plan->failed = 1;
		return;
	}
	*list = grown;
	grown[*count].name = name;
	grown[*count].id = id;
	(*count)++;
}

void ncfg_builder_note_string(ncfg_builder_t *builder, const char ***list, size_t *count,
    const char *value)
{
	const char **grown = realloc(*list, (*count + 1u) * sizeof(**list));

	if (!grown) {
		builder->plan->failed = 1;
		return;
	}
	*list = grown;
	grown[*count] = value;
	(*count)++;
}

void ncfg_builder_gate(ncfg_builder_t *builder, const char *name, ncfg_plan_ids_t *out)
{
	size_t i;

	for (i = 0; i < builder->gate_count; i++) {
		if (builder->gates[i].name && name &&
		    strcmp(builder->gates[i].name, name) == 0) {
			ncfg_plan_ids_push(builder->plan, out, builder->gates[i].id);
		}
	}
}

uint32_t ncfg_builder_link_up(const ncfg_builder_t *builder, const char *name)
{
	size_t i;

	for (i = 0; i < builder->link_up_count; i++) {
		if (builder->link_up[i].name && name &&
		    strcmp(builder->link_up[i].name, name) == 0) {
			return builder->link_up[i].id;
		}
	}
	return NCFG_PLAN_NO_ACTION;
}

ncfg_reason_t ncfg_plan_reason_absent(const char *interface, const char *field,
    const char *desired)
{
	ncfg_reason_t reason = { interface, field, desired, "<absent>" };

	return reason;
}

ncfg_reason_t ncfg_plan_reason_differs(const char *interface, const char *field,
    const char *desired, const char *observed)
{
	ncfg_reason_t reason = { interface, field, desired, observed };

	return reason;
}

ncfg_reason_t ncfg_plan_reason_unwanted(const char *interface, const char *field,
    const char *observed)
{
	ncfg_reason_t reason = { interface, field, "<absent>", observed };

	return reason;
}

/* ------------------------------------------------------------------------ *
 * The guard
 * ------------------------------------------------------------------------ */

/*
 * Whether a guard forbids this action, recording the refusal if it does.
 *
 * Every action passes through here, so there is one place that decides and no
 * planner path can route around it -- the same reasoning that puts
 * `ncfg_ownership_may_remove` in one function. Decision 0010.
 */
static int refused(ncfg_builder_t *builder, const ncfg_op_t *op, const ncfg_reason_t *reason)
{
	const char      *interface;
	ncfg_refusal_t   refusal;
	size_t           i;

	if (!ncfg_op_is_disruptive(op)) {
		return 0;
	}
	interface = ncfg_op_interface(op);
	if (!interface) {
		return 0;
	}
	if (builder->options && ncfg_plan_names(builder->options->allow_disruption,
	    builder->options->allow_disruption_count, interface)) {
		return 0;
	}
	for (i = 0; i < builder->guard_count; i++) {
		if (strcmp(builder->guards[i].interface, interface) != 0) {
			continue;
		}
		memset(&refusal, 0, sizeof(refusal));
		refusal.interface = interface;
		refusal.op = ncfg_op_name(op);
		refusal.guard = builder->guards[i].reason;
		refusal.reason = *reason;
		refusal.override_with = ncfg_plan_internf(builder->plan,
		    "ncfg apply --allow-disruption %s", interface);
		ncfg_plan_refuse(builder->plan, &refusal);
		return 1;
	}
	return 0;
}

uint32_t ncfg_builder_push(ncfg_builder_t *builder, const ncfg_op_t *op,
    const ncfg_reason_t *reason, const uint32_t *depends_on, size_t depends_count,
    const ncfg_op_t *inverse)
{
	const char *interface = ncfg_op_interface(op);

	/*
	 * `managed = false` means netcfgd never touches the device -- including
	 * not tearing down what it configured before the flag was set, which is
	 * what "no further operation" was decided to mean (0035). Dropped here
	 * rather than guarded at each pass that could emit one, because a pass
	 * added later would not know to ask.
	 *
	 * Silently, because the warning that explains it is emitted once per
	 * device up front. One warning naming the device beats three naming each
	 * action it did not take.
	 *
	 * **The one exemption is `on_unmanage = "clear"`, and only while the
	 * teardown is running.** That policy says the desired state is that
	 * netcfgd owns nothing on the device, so what it left behind has to come
	 * off -- and the forward passes must still be stopped, or the plan would
	 * add an address and remove it again in the same breath, for ever.
	 */
	if (interface &&
	    ncfg_plan_names(builder->unmanaged, builder->unmanaged_count, interface) &&
	    !(builder->tearing_down && ncfg_plan_clearing(builder, interface))) {
		return NCFG_PLAN_NO_ACTION;
	}
	/*
	 * **And the same for a device this plan declined to create**, for the
	 * reason the paragraph above gives: a pass added later would not know to
	 * ask. `link.create` for a bond, a macvlan or a tunnel is refused by this
	 * build's executor -- `ncfg_kernel_newlink_of` builds no nest for them --
	 * so the creation pass says so and notes the name, and every action
	 * against that name afterwards is one that must fail.
	 *
	 * Found by the frozen witness: `k-bond` is a bond, is not observed, and
	 * collected a `bridge.vlan.add`, two sysctls, a `qdisc.set`, an
	 * `ingress.redirect` and a `dns.apply` -- eighteen actions against a
	 * device nothing would bring into existence, planned again on every
	 * reconcile. The passes that emitted them are driven from the document
	 * rather than through `ncfg_plan_interface_contents`, which does ask, so
	 * each of them would have had to ask separately and one of them always
	 * forgets.
	 *
	 * Silently, like the one above and for the same reason: the creation pass
	 * has already said why, once, naming the device.
	 */
	if (interface && ncfg_plan_names(builder->declined, builder->declined_count, interface)) {
		return NCFG_PLAN_NO_ACTION;
	}
	if (refused(builder, op, reason)) {
		/* Nothing is emitted, so nothing downstream can depend on it. The
		 * refusal carries what would have happened. */
		return NCFG_PLAN_NO_ACTION;
	}
	return ncfg_plan_add(builder->plan, op, reason, depends_on, depends_count, inverse);
}

/* ------------------------------------------------------------------------ *
 * The confirm window
 * ------------------------------------------------------------------------ */

ncfg_optint_t ncfg_plan_confirm_window(const ncfg_document_t *desired,
    const ncfg_plan_options_t *options)
{
	ncfg_optint_t none = { 0, 0 };

	/*
	 * Zero is the caller saying *no* window despite the document's default,
	 * and is the only way to say it: a window of no seconds would arm and
	 * expire, which is two spellings of "no" where one of them reverts the
	 * change.
	 *
	 * **And a document saying `confirm = 0` means the same thing.** The guard
	 * covered only the caller's option, so `global { confirm = 0 }` fell
	 * through and armed a window of zero seconds -- the exact state that
	 * cannot be expressed, reachable by writing it in the file rather than
	 * passing it on the command line (0094).
	 */
	if (options && options->confirm_window.has) {
		return options->confirm_window.value > 0 ? options->confirm_window : none;
	}
	if (desired->globals.confirm_default.has && desired->globals.confirm_default.value > 0) {
		return desired->globals.confirm_default;
	}
	return none;
}

/* ------------------------------------------------------------------------ *
 * Warnings
 * ------------------------------------------------------------------------ */

static void warn_unmanaged(ncfg_builder_t *builder)
{
	size_t i;

	for (i = 0; i < builder->desired->device_count; i++) {
		const ncfg_device_t *device = &builder->desired->devices[i];

		if (device->managed || !ncfg_plan_interface(builder->desired, device->name)) {
			continue;
		}
		if (ncfg_plan_clearing(builder, device->name)) {
			/*
			 * The other policy, and a different sentence rather than the same
			 * one with a clause bolted on: what is left behind is the whole
			 * difference between them, and an operator reading "netcfgd will
			 * not touch it" about a device it is about to empty has been told
			 * the opposite of what the plan does.
			 */
			ncfg_plan_warnf(builder->plan, device->name,
			    "`%s` is `managed = false` with `on_unmanage = \"clear\"`: netcfgd "
			    "removes everything it owns on it -- addresses and routes carrying "
			    "its tag, backends it started, and the credentials those hold -- and "
			    "then leaves it alone. Anything it did not put there is left exactly "
			    "as it is. The plan above is what is left to remove; an empty one "
			    "means it is done",
			    device->name);
			continue;
		}
		/*
		 * Named specifically rather than as "left as it is", because three of
		 * the things left behind hold credentials: a WireGuard private key
		 * stays loaded in the kernel, a supplicant netcfgd started keeps the
		 * passphrases it was given, and a running hostapd keeps its generated
		 * configuration under /run. Withdrawing those on the way out is not
		 * implemented and is a decision rather than an oversight -- the flag
		 * means "stop operating", and taking a key out is an operation.
		 */
		ncfg_plan_warnf(builder->plan, device->name,
		    "`%s` is `managed = false`, so netcfgd will not touch it -- the `interface "
		    "%s` block is read and then not acted on. Whatever is already configured "
		    "stays exactly as it is, and that includes credentials: a WireGuard key "
		    "stays loaded, a supplicant netcfgd started keeps its passphrases, and a "
		    "running hostapd keeps its generated configuration",
		    device->name, device->name);
	}
}

/*
 * One sentence per block that nothing acts on, in either language.
 *
 * **There was a `warn_block` beside this one and it has gone, which is worth a
 * paragraph rather than a silent deletion.** It said "this build of the planner
 * does not act on it", which is a promise: it tells an operator that a later
 * release will, and that waiting is the right response. Every arm that made
 * that promise has now been kept -- `reported`, `nat` and `ipv6_token` were the
 * last three, and each is a pass -- so the function was left with no callers,
 * which is a warning at the full set and, worse, an invitation for the next arm
 * to reach for a sentence whose promise nobody has checked.
 *
 * A feature the Rust has not built either is not a port gap at all, and telling
 * somebody to wait for something that is not coming is worse than saying
 * nothing: they keep the block, re-read the release notes, and are still
 * holding a configuration that means nothing. So a block gets this sentence
 * once it has been checked against `crates/` and *not* found there, and the
 * wording below is the Rust's own, which says the same thing about itself. A
 * block that is a real port gap gets a sentence naming what is missing, in the
 * arm itself, where a reader can check it against the pass that will fill it.
 *
 * **Published in `plan_internal.h` rather than kept here**, because the wifi
 * passes draw the same distinction about the four halves of a `network` block
 * nothing reads, and the one thing that must not happen to this sentence is
 * for there to be two of it.
 */
void ncfg_plan_warn_unbuilt(ncfg_builder_t *builder, const char *interface, const char *block)
{
	ncfg_plan_warnf(builder->plan, interface,
	    "%s. That is not this port catching up: nothing acts on it in the Rust either, "
	    "so there is nothing to wait for. The block is kept so a configuration written "
	    "now still means this when the code arrives",
	    block);
}

/*
 * Everything the document asks for that no pass here reads.
 *
 * The list is the body of this function, and each arm says for itself what it
 * is about -- the shape `warn_unapplied` in the Rust arrived at after its own
 * list went stale twice while a comment above it claimed to enumerate them.
 */
static void warn_unported(ncfg_builder_t *builder)
{
	const ncfg_document_t *desired = builder->desired;
	size_t                 i;
	size_t                 j;

	for (i = 0; i < desired->interface_count; i++) {
		const ncfg_interface_t *interface = &desired->interfaces[i];

		for (j = 0; j < interface->addressing_count; j++) {
			switch (interface->addressing[j].kind) {
			case NCFG_ADDRESS_SOURCE_STATIC:
			/* SLAAC plans no addressing action -- the kernel builds the
			 * address itself -- and the two sysctls that decide whether it
			 * listens at all are `sysctl.c`'s, planned per interface rather
			 * than per source. DHCP starts a client and `delegated` resolves
			 * against the observation; both are acted on in
			 * `ncfg_plan_source`. */
			case NCFG_ADDRESS_SOURCE_SLAAC:
			case NCFG_ADDRESS_SOURCE_DHCP4:
			case NCFG_ADDRESS_SOURCE_DHCP6:
			case NCFG_ADDRESS_SOURCE_DELEGATED:
			/* `reported` is acted on in `ncfg_plan_reported`, which also
			 * synthesises the routes a report implies; the two warnings it
			 * emits are about a report that has not arrived or says the link
			 * is down, which are facts about the machine rather than about
			 * this build. */
			case NCFG_ADDRESS_SOURCE_REPORTED:
				break;
			case NCFG_ADDRESS_SOURCE_LINK_LOCAL:
				/*
				 * **The judgement above this arm was right and the sentence
				 * under it contradicted it.** "Not yet applied by this
				 * build" is a promise that a later release applies it, and
				 * the reason given for keeping the wording was that it is
				 * the Rust's own -- which is the argument 10.180 says does
				 * not settle anything, because the Rust's sentence is about
				 * the Rust. Re-checked against `crates/` rather than
				 * inherited: `crates/netcfgd-plan/src/lib.rs:4033` is this
				 * same warning on this same arm, and outside the model and
				 * the compiler `AddressSource::LinkLocal` has no reader in
				 * either language. So there is no release to wait for, and
				 * this is `warn_unbuilt`'s sentence rather than a promise.
				 */
				ncfg_plan_warn_unbuilt(builder, interface->name,
				    "link-local addressing is accepted and no pass applies "
				    "it: nothing claims an RFC 3927 `169.254.0.0/16` address "
				    "on the interface");
				break;
			default:
				break;
			}
		}
		if (interface->probe) {
			ncfg_plan_warnf(builder->plan, interface->name,
			    "a `probe` block is run by the daemon rather than by the planner, "
			    "so no action in the plan above is about it -- and its answer is "
			    "acted on here: an interface with a `preference` whose probe says "
			    "it is reaching nothing does not get its routes, and loses the "
			    "ones it has");
		}
	}
	for (i = 0; i < desired->device_count; i++) {
		const ncfg_device_t *device = &desired->devices[i];

		if (device->modem) {
			ncfg_plan_warnf(builder->plan, device->name,
			    "a `modem` block is read by the daemon's SIM selection rather "
			    "than by the planner, so no action in the plan above is about it. "
			    "What is missing here is only the other half of a switch: a plan "
			    "cannot yet be asked to cycle the link, so a modem that has moved "
			    "to another SIM source gets no `link.down` and no `link.up`, and "
			    "the `pre_up` hook that drives the mux does not fire");
		}
	}
	if (desired->bluetooth_count != 0u) {
		ncfg_plan_warn_unbuilt(builder, NULL,
		    "a `bluetooth` block: nothing pairs the device, connects it, or brings "
		    "a `pan` link up");
	}
}

/* ------------------------------------------------------------------------ *
 * The order the passes run in
 * ------------------------------------------------------------------------ */

static void prepare(ncfg_builder_t *builder)
{
	const ncfg_document_t *desired = builder->desired;
	size_t                 i;

	/*
	 * Collected before anything is planned, because a guard on one interface
	 * has to be known when an action against it is considered, whatever order
	 * the interfaces sort in.
	 */
	for (i = 0; i < desired->interface_count; i++) {
		const ncfg_interface_t *interface = &desired->interfaces[i];
		ncfg_plan_guard_t      *grown;

		if (!interface->guard || !interface->guard->reason) {
			continue;
		}
		grown = realloc(builder->guards,
		    (builder->guard_count + 1u) * sizeof(*builder->guards));
		if (!grown) {
			builder->plan->failed = 1;
			return;
		}
		builder->guards = grown;
		grown[builder->guard_count].interface = interface->name;
		grown[builder->guard_count].reason = interface->guard->reason;
		builder->guard_count++;
	}
	for (i = 0; i < desired->device_count; i++) {
		const ncfg_device_t *device = &desired->devices[i];

		if (!device->managed) {
			ncfg_builder_note_string(builder, &builder->unmanaged,
			    &builder->unmanaged_count, device->name);
		}
		/* Creating one end of a veth creates both, so a peer that has no
		 * `interface` block of its own -- or has one and is not present yet --
		 * is not absent hardware to be skipped. */
		if (device->kind.kind == NCFG_KIND_VETH && device->kind.veth.peer) {
			ncfg_builder_note_string(builder, &builder->appearing,
			    &builder->appearing_count, device->kind.veth.peer);
		}
	}
}

static void plan_commit_arm(ncfg_builder_t *builder)
{
	ncfg_optint_t window = ncfg_plan_confirm_window(builder->desired, builder->options);
	ncfg_op_t     op;
	ncfg_op_t     inverse;
	ncfg_reason_t reason;

	if (!window.has) {
		return;
	}
	/*
	 * Rule 8: the confirm window is armed first, and the revert is computed
	 * now rather than after a failure, when the network may already be
	 * unreachable.
	 */
	memset(&op, 0, sizeof(op));
	op.kind = NCFG_OP_COMMIT_ARM;
	op.u.commit_arm.window_seconds = window.value;
	memset(&reason, 0, sizeof(reason));
	reason.field = "globals.confirm_default";
	reason.desired = ncfg_plan_internf(builder->plan, "%llds", (long long)window.value);
	reason.observed = "<absent>";
	if (builder->options && builder->options->revert_to) {
		memset(&inverse, 0, sizeof(inverse));
		inverse.kind = NCFG_OP_COMMIT_REVERT;
		inverse.u.commit_revert.to_document_hash = builder->options->revert_to;
		(void)ncfg_builder_push(builder, &op, &reason, NULL, 0, &inverse);
		return;
	}
	(void)ncfg_builder_push(builder, &op, &reason, NULL, 0, NULL);
}

ncfg_plan_t *ncfg_plan_build(const ncfg_document_t *desired, const ncfg_observed_t *observed,
    const ncfg_plan_options_t *options, char *err, size_t err_size)
{
	ncfg_builder_t builder;
	ncfg_plan_t   *plan = ncfg_plan_new(err, err_size);
	size_t         i;

	if (!plan) {
		return NULL;
	}
	memset(&builder, 0, sizeof(builder));
	builder.plan = plan;
	builder.desired = desired;
	builder.observed = observed;
	builder.options = options;

	prepare(&builder);
	/*
	 * Before the warnings, because the sentence an operator reads about an
	 * unmanaged device depends on which of the two policies it carries, and
	 * before every pass, because `ncfg_builder_push` asks.
	 */
	ncfg_plan_clearing_collect(&builder);
	/*
	 * And before anything that plans a route: a set's choice cannot change
	 * inside one plan, and asking `ncfg_linkset_choose` per route would make
	 * planning cost scale with the number of routes an operator wrote.
	 */
	ncfg_plan_standby_collect(&builder);
	warn_unmanaged(&builder);
	warn_unported(&builder);
	plan_commit_arm(&builder);

	/*
	 * Three passes over the lists rather than one. Rule 1 wants every link
	 * created before anything references it, and rule 2 wants every
	 * enslavement done before the master is addressed or brought up -- and a
	 * master may sort before its own members. Passing over the list three
	 * times is simpler and more obviously correct than back-patching edges.
	 *
	 * **Devices, not interfaces**, for the creation: what netcfgd creates is
	 * stated on the device, and driving creation from that list is what lets a
	 * device exist with nothing running over it -- an `ifb` carries no address
	 * and never will.
	 */
	for (i = 0; i < desired->device_count; i++) {
		ncfg_plan_link_creation(&builder, &desired->devices[i]);
	}
	/*
	 * Before the attributes pass, and that is not tidiness: `link.up` is where
	 * the kernel decides whether to solicit a router at all, and it does not
	 * solicit on an interface whose advertisements it would ignore. Writing
	 * `accept_ra` afterwards leaves the interface waiting for the router's own
	 * unsolicited timer -- 14.2 seconds against a dnsmasq set to five, and
	 * minutes on a real network. Decision 0073.
	 */
	ncfg_plan_accept_ra(&builder);
	for (i = 0; i < desired->interface_count; i++) {
		ncfg_plan_link_attributes(&builder, &desired->interfaces[i]);
	}
	for (i = 0; i < desired->device_count; i++) {
		uint32_t enslaved;

		/*
		 * **A device that will never exist gets no configuration either.**
		 * `link_is_plannable` already answers this for the addressing and
		 * routing passes: a link that is observed is plannable, and one that
		 * is absent by decision -- a `pppoe`, an `openvpn`, absent hardware,
		 * or a kind the creation pass declined because this build cannot
		 * create it -- is not.
		 *
		 * The passes below are driven from the *device* list rather than the
		 * interface list, deliberately: a bridge port or an `ifb` often has no
		 * `interface` block, and the Rust's equivalent reaches them only
		 * through one, which is a defect this port does not have (project.md
		 * 10.170). That is right, and it meant these passes were the only ones
		 * asking nothing about whether the device can exist. Measured against
		 * the frozen witness: `k-bond` is a bond, is not observed, and cannot
		 * be created by this build, and it still collected a `bridge.vlan.add`
		 * -- an action that must fail, planned again on every reconcile.
		 */
		if (!ncfg_plan_link_is_plannable(&builder, desired->devices[i].name)) {
			continue;
		}
		enslaved = ncfg_plan_master(&builder, desired->devices[i].name);

		ncfg_plan_device_up(&builder, &desired->devices[i], enslaved);
		/*
		 * What the `kind` says about itself, in this loop rather than the
		 * interface walk below: a WireGuard device's port and peers, a
		 * bridge's own settings and a port's VLANs are properties of the
		 * link, and half of the devices that have them -- a bridge port, an
		 * `ifb` -- will never have an `interface` block to be walked.
		 *
		 * After the enslavement, so a port's VLANs are set on a port that is
		 * already in its bridge: the kernel answers `EOPNOTSUPP` otherwise.
		 */
		ncfg_plan_wireguard(&builder, &desired->devices[i]);
		ncfg_plan_bridge(&builder, &desired->devices[i]);
		ncfg_plan_bond(&builder, &desired->devices[i]);
		ncfg_plan_macvlan(&builder, &desired->devices[i]);
		ncfg_plan_tunnel(&builder, &desired->devices[i]);
		ncfg_plan_vxlan(&builder, &desired->devices[i]);
		ncfg_plan_bridge_vlans(&builder, &desired->devices[i]);
	}
	for (i = 0; i < desired->interface_count; i++) {
		ncfg_plan_interface_contents(&builder, &desired->interfaces[i]);
	}

	/*
	 * The host's own configuration, after everything that could change what it
	 * is derived from. The DNS scopes read a lease's nameservers, and the two
	 * remaining sysctls are per-interface settings that nothing above depends
	 * on -- `accept_ra` is the one that had to run early, and it did.
	 */
	ncfg_plan_dns(&builder);
	/*
	 * The driver, the traffic control and the wireless half, each over the
	 * whole document and none of them derived from anything above. The
	 * redirect follows the qdisc so the `ifb` it points at is shaped before
	 * anything arrives on it.
	 */
	ncfg_plan_offloads(&builder);
	/* After the offloads and before the rules, which is the Rust's position
	 * for it. Nothing here depends on that order: a token is a property of one
	 * interface and is gated on its creation like every other link
	 * attribute. */
	ncfg_plan_ipv6_token(&builder);
	ncfg_plan_rules(&builder);
	ncfg_plan_qdisc(&builder);
	ncfg_plan_ingress(&builder);
	ncfg_plan_forwarding(&builder);
	ncfg_plan_privacy(&builder);
	ncfg_plan_hostname(&builder);
	/* The one nftables table, after the forwarding sysctls it depends on for
	 * its effect and before the teardown, which is where the Rust puts it. The
	 * dependency is on the machine rather than in the plan -- translating
	 * without forwarding does nothing, and the pass warns where the document
	 * asks for one and not the other. */
	ncfg_plan_nat(&builder);
	ncfg_plan_wifi(&builder);
	ncfg_plan_access_control(&builder);

	/*
	 * Teardown comes last, so a change to an address is make-before-break: the
	 * new address is in place before the old one goes. On a machine being
	 * reconfigured over the network that ordering is the difference between a
	 * brief overlap and a lockout.
	 *
	 * Bracketed, because this is the only window in which a device carrying
	 * `on_unmanage = "clear"` is out of the document and an action against it
	 * is let through. Both are true together or neither is: a filter with no
	 * exemption removes nothing, and an exemption with no filter leaves the
	 * teardown reading the device as wanted.
	 */
	ncfg_plan_clearing_begin(&builder);
	ncfg_plan_teardown(&builder);
	ncfg_plan_clearing_end(&builder);

	ncfg_plan_standby_free(&builder);
	free(builder.guards);
	free(builder.gates);
	free(builder.enslavements);
	free(builder.link_up);
	free(builder.added);
	free(builder.declined);
	free(builder.appearing);
	free(builder.unmanaged);

	if (plan->failed) {
		ncfg_error_set(err, err_size, "out of memory building the plan");
		ncfg_plan_free(plan);
		return NULL;
	}
	return plan;
}
