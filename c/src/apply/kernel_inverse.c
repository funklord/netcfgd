/*
 * kernel_inverse.c -- which op undoes which, for the ops this module carries
 * out.
 *
 * WHY THE EXECUTOR HAS AN OPINION ABOUT THIS AT ALL
 *   The inverse a revert replays is the *plan's*: `ncfg_plan_add` takes one,
 *   `apply.h`'s revert walks the journal backwards and asks the plan for it,
 *   and an action with none contributes nothing. So the planner declares, and
 *   nothing here changes that.
 *
 *   What this file is, is the other half of the same sentence. **An op this
 *   build carries out whose inverse it could not carry out is a change that
 *   cannot be taken back**, and the moment that matters is the worst one --
 *   a confirm window closing on a machine that has just been cut off. A
 *   refusal at that point is not "the revert did less than it hoped": it is
 *   the executor declining to undo something it was happy to do.
 *
 *   `apply_kernel_test.c` walks this list against `ncfg_apply_supported`, so
 *   the pairing is checked rather than believed. The check is the reason the
 *   list is a function instead of a paragraph.
 *
 * WHAT HAS NO INVERSE, AND WHY THAT IS NOT A GAP
 *   Six of these ops replace a value rather than adding an object, so undoing
 *   one means re-stating **what was there before** -- a bridge's old forward
 *   delay, a bond's old mode, a tunnel's old endpoints, the offloads a driver
 *   had on. That is not an op kind, it is a value, and the only thing that
 *   holds it is the observation the plan was built against. So the inverse of
 *   `link.set_bridge` is another `link.set_bridge`, against the previous
 *   document -- which is `apply.h`'s "a declared inverse carries the value it
 *   replaced", and it is the planner that can carry it. Saying so here, rather
 *   than answering "none", is what keeps a reader from concluding these are
 *   irreversible.
 */
#include "kernel_internal.h"

int ncfg_kernel_inverse_kind(int op_kind)
{
	switch (op_kind) {
	/*
	 * The four that add or remove an object. Each pair is a true inverse:
	 * replaying one after the other leaves the kernel where it started, and
	 * both directions are ops this build executes -- which is the property
	 * the test checks.
	 */
	case NCFG_OP_RULE_ADD:
		return NCFG_OP_RULE_DEL;
	case NCFG_OP_RULE_DEL:
		return NCFG_OP_RULE_ADD;
	case NCFG_OP_BRIDGE_VLAN_ADD:
		return NCFG_OP_BRIDGE_VLAN_DEL;
	case NCFG_OP_BRIDGE_VLAN_DEL:
		return NCFG_OP_BRIDGE_VLAN_ADD;
	/*
	 * `qdisc.reset` is the inverse of `qdisc.set` and **not the other way
	 * round**, which is the asymmetry worth writing down: removing netcfgd's
	 * root qdisc restores `net.core.default_qdisc`, so the machine goes back
	 * to what it had. Undoing a *reset* means putting back the scheduler and
	 * the rate that were there, which is a value rather than an op -- see the
	 * file comment -- so this answers none for it rather than naming
	 * `qdisc.set` and sending a shaper nobody asked for.
	 */
	case NCFG_OP_QDISC_SET:
		return NCFG_OP_QDISC_RESET;
	/* Symmetrical, because the hook and everything hanging off it go
	 * together: removing the ingress qdisc takes every filter with it, so
	 * there is no half-cleared state either direction can leave. */
	case NCFG_OP_INGRESS_REDIRECT:
		return NCFG_OP_INGRESS_REDIRECT_CLEAR;
	case NCFG_OP_INGRESS_REDIRECT_CLEAR:
		return NCFG_OP_INGRESS_REDIRECT;
	/*
	 * `wg.set_peers` undoes `wg.set_peers`, and that is the one place a
	 * same-kind inverse is honest rather than a placeholder: the op replaces
	 * the whole list, so the inverse is the same op carrying the list the
	 * device had. `wg.set_device` is not here for the reason the file comment
	 * gives, with one thing on top of it -- the previous private key is a
	 * secret reference the old document held, and the kernel will not report
	 * the loaded key back, so nothing in a journal could reconstruct it.
	 */
	case NCFG_OP_WG_SET_PEERS:
		return NCFG_OP_WG_SET_PEERS;
	/*
	 * Replacing a table is its own inverse: `nat.replace` carries the whole
	 * uplink set, an empty set removes the table, and the previous set is a
	 * value the old document holds.
	 */
	case NCFG_OP_NAT_REPLACE:
		return NCFG_OP_NAT_REPLACE;
	default:
		/* Every other op of this module's -- the five link-kind ops, the
		 * token, the offloads, `qdisc.reset` and `wg.set_device` -- is a
		 * value replacement, and the file comment says what carries it. */
		return NCFG_OP_NONE_INVERSE;
	}
}
