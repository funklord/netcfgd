/*
 * apply.c -- the run loop, the revert, and the list of what this build can do.
 *
 * THE LOOP IS DELIBERATELY DULL
 *   It walks the plan front to back and hands each op to the seam. It does not
 *   sort, group, batch or parallelise, and the reason is that the order it is
 *   given is the whole product of the planner: `plan.h` says the action list
 *   is already a valid execution order, and three separate defects in this
 *   project were an ordering that had been got wrong rather than an action
 *   that had. An executor clever enough to reorder is an executor that can
 *   take them back.
 *
 * WHY THERE IS NO ROLLBACK ON FAILURE
 *   Section 4: execution stops at the first failure, everything after it is
 *   recorded as skipped, and the remainder is re-runnable. Unwinding here
 *   would be a second, implicit commit-confirm with different rules from the
 *   real one, and two mechanisms that both put a machine back produce
 *   behaviour nobody can predict from the outside. `ncfg_apply_revert` is the
 *   explicit one, and a caller asks for it.
 */
#include "ncfg/apply.h"

#include "ncfg/base.h"

#include <string.h>

/* ------------------------------------------------------------------------ *
 * What this build can carry out
 * ------------------------------------------------------------------------ */

/*
 * Whether a link of this kind can be created here, and why not.
 *
 * **Four kinds are refused for one reason**, and it is worth the sentence: a
 * VLAN's ethertype, a bond's mode number, a macvlan's mode number and a
 * tunnel's kind word are the *model's* numbering of a closed set, not the wire
 * layer's. `ops.h` says so outright -- "two lists of four numbers in two
 * places is how a mode comes to mean one thing on the way out and another on
 * the way back in" -- and `document.h`, which is final and not this module's
 * to change, carries no function that converts them. Writing the tables here
 * would be creating exactly that second list, in the module least likely to be
 * read when the first one changes.
 *
 * The kinds that need no such conversion are made normally.
 */
static int creatable(const ncfg_interface_kind_t *kind, const char *name, char *err,
    size_t err_size)
{
	const char *word;

	if (!kind) {
		ncfg_error_set(err, err_size,
		    "link.create for %s carries no kind, so there is nothing to create it as",
		    name ? name : "an unnamed link");
		return 0;
	}
	word = ncfg_interface_kind_name(kind->kind);
	switch ((ncfg_interface_kind_tag_t)kind->kind) {
	case NCFG_KIND_BRIDGE:
	case NCFG_KIND_DUMMY:
	case NCFG_KIND_IFB:
	case NCFG_KIND_VETH:
	case NCFG_KIND_VRF:
	case NCFG_KIND_VXLAN:
	case NCFG_KIND_TUN:
		return 1;
	case NCFG_KIND_WIREGUARD:
		/*
		 * The link only. Everything that makes it a tunnel -- the key, the
		 * peers, the allowed prefixes -- goes over generic netlink afterwards
		 * and is `wg.set_device`/`wg.set_peers`, neither of which this build
		 * executes. Said here rather than left implied, because a WireGuard
		 * device that exists and carries nothing is up, addressed and silently
		 * passing no traffic, which looks like a working interface.
		 */
		return 1;
	case NCFG_KIND_VLAN:
	case NCFG_KIND_BOND:
	case NCFG_KIND_MACVLAN:
	case NCFG_KIND_TUNNEL:
		ncfg_error_set(err, err_size,
		    "creating a %s link (%s) needs the kernel's numbering for its mode, "
		    "ethertype or kind word, which belongs with the model and is not in "
		    "document.h; a second copy of it here is how a mode comes to mean one "
		    "thing on the way out and another on the way back in",
		    word ? word : "link", name ? name : "?");
		return 0;
	case NCFG_KIND_PHYSICAL:
		ncfg_error_set(err, err_size,
		    "%s is a physical device: netcfgd configures one and cannot make one",
		    name ? name : "?");
		return 0;
	case NCFG_KIND_PPPOE:
	case NCFG_KIND_OPENVPN:
		ncfg_error_set(err, err_size,
		    "a %s interface (%s) is brought up by a helper rather than by a netlink "
		    "message, and no helper is started in this build",
		    word ? word : "link", name ? name : "?");
		return 0;
	}
	ncfg_error_set(err, err_size, "link.create for %s names a kind this build does not know",
	    name ? name : "?");
	return 0;
}

/*
 * The one place that says what is executable, so that a refusal is a value.
 *
 * **No `default:` arm**, which is `action.c`'s rule and for its reason: a
 * wildcard is what let a kind be added twice in this project without an
 * answer, and `-Wswitch` is the only thing that can notice. Every op is listed,
 * so an op added to the taxonomy makes this fail to compile rather than
 * quietly fall into whichever half it was not meant to be in.
 */
int ncfg_apply_supported(const ncfg_op_t *op, char *err, size_t err_size)
{
	const char *name;

	if (!op) {
		ncfg_error_set(err, err_size, "there is no op to carry out");
		return 0;
	}
	name = ncfg_op_name(op);
	switch ((ncfg_op_kind_t)op->kind) {
	case NCFG_OP_LINK_CREATE:
		return creatable(op->u.link_create.kind, op->u.link_create.name, err, err_size);
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
	case NCFG_OP_HOOK_RUN:
		return 1;
	/*
	 * The commit family is a marker in the plan rather than something the
	 * kernel does. The window lives with whoever opens it after the apply
	 * succeeds and owns the timer, so the executor's correct behaviour is to
	 * do nothing -- **not** to fail the very plan it is bracketing, which is
	 * what an unhandled op would do.
	 */
	case NCFG_OP_COMMIT_ARM:
	case NCFG_OP_COMMIT_CONFIRM:
	case NCFG_OP_COMMIT_REVERT:
		return 1;
	case NCFG_OP_BACKEND_START:
	case NCFG_OP_BACKEND_STOP:
	case NCFG_OP_BACKEND_RELOAD:
		ncfg_error_set(err, err_size,
		    "%s needs a DHCP client, a supplicant or a PPP daemon to be started and "
		    "adopted, and none of that is ported in this build", name);
		return 0;
	case NCFG_OP_WIFI_SET_PROFILES:
	case NCFG_OP_WIFI_ASSOCIATE:
	case NCFG_OP_WIFI_DISASSOCIATE:
	case NCFG_OP_ACCESS_CONTROL_ADD:
	case NCFG_OP_ACCESS_CONTROL_DEL:
		ncfg_error_set(err, err_size,
		    "%s is carried out over the supplicant's or the access point's control "
		    "socket, which is not ported in this build", name);
		return 0;
	case NCFG_OP_WIFI_SET_REGDOM:
	case NCFG_OP_WG_SET_DEVICE:
	case NCFG_OP_WG_SET_PEERS:
		ncfg_error_set(err, err_size,
		    "%s goes over generic netlink, and this executor holds an rtnetlink "
		    "socket only", name);
		return 0;
	case NCFG_OP_NAT_REPLACE:
		ncfg_error_set(err, err_size,
		    "%s replaces an nftables table, which needs a NETLINK_NETFILTER socket "
		    "this executor does not open", name);
		return 0;
	case NCFG_OP_LINK_SET_OFFLOADS:
		ncfg_error_set(err, err_size,
		    "%s needs the `ethtool` generic netlink family, which this executor "
		    "does not open", name);
		return 0;
	case NCFG_OP_BRIDGE_VLAN_ADD:
	case NCFG_OP_BRIDGE_VLAN_DEL:
	case NCFG_OP_LINK_SET_BOND:
	case NCFG_OP_LINK_SET_BRIDGE:
	case NCFG_OP_LINK_SET_MACVLAN:
	case NCFG_OP_LINK_SET_TUNNEL:
	case NCFG_OP_LINK_SET_VXLAN:
	case NCFG_OP_LINK_SET_IPV6_TOKEN:
	case NCFG_OP_RULE_ADD:
	case NCFG_OP_RULE_DEL:
		/*
		 * Every one of these has a builder in `ops.h` and none of them is
		 * planned by this build, so executing them would be untested code on a
		 * path nothing reaches -- with the machine on the other end of it. The
		 * planner names each by hand in a warning; when a pass lands, its arm
		 * moves up in the same commit.
		 */
		ncfg_error_set(err, err_size,
		    "%s is not planned by this build, so it is not executed by it either; "
		    "the planner warns by name about the block that asks for it", name);
		return 0;
	case NCFG_OP_QDISC_SET:
	case NCFG_OP_QDISC_RESET:
	case NCFG_OP_INGRESS_REDIRECT:
	case NCFG_OP_INGRESS_REDIRECT_CLEAR:
		ncfg_error_set(err, err_size,
		    "%s is traffic control, which is a second rtnetlink vocabulary this "
		    "build does not speak", name);
		return 0;
	case NCFG_OP_SYSCTL_SET_FORWARDING:
	case NCFG_OP_SYSCTL_SET_PRIVACY:
	case NCFG_OP_SYSCTL_SET_ACCEPT_RA:
	case NCFG_OP_HOSTNAME_SET:
		ncfg_error_set(err, err_size,
		    "%s writes to /proc or to the host's name rather than to netlink, and "
		    "that is not ported in this build", name);
		return 0;
	case NCFG_OP_DNS_APPLY:
		ncfg_error_set(err, err_size,
		    "%s delivers a resolver configuration, which is a backend rather than a "
		    "netlink message and is not ported in this build", name);
		return 0;
	}
	ncfg_error_set(err, err_size, "an op this build does not know cannot be carried out");
	return 0;
}

/* ------------------------------------------------------------------------ *
 * Running a plan
 * ------------------------------------------------------------------------ */

int ncfg_apply(const ncfg_plan_t *plan, const ncfg_executor_t *executor,
    ncfg_journal_t *journal, char *err, size_t err_size)
{
	int    stopped = 0;
	size_t i;

	if (!plan || !executor || !executor->execute || !journal) {
		ncfg_error_set(err, err_size,
		    "applying needs a plan, an executor with an `execute`, and a journal");
		return 0;
	}
	ncfg_journal_init(journal);
	/*
	 * A plan that ran out of memory while it was being built describes less
	 * than the machine needs, and it is indistinguishable from a complete one
	 * by looking at it. Half a plan that looks whole is the one that gets
	 * applied, so this refuses rather than carrying out the part that fitted.
	 */
	if (ncfg_plan_failed(plan)) {
		ncfg_error_set(err, err_size,
		    "this plan did not finish being built, so it does not say everything "
		    "that would have to change; nothing was applied");
		return 0;
	}

	for (i = 0; i < plan->action_count; i++) {
		const ncfg_action_t *action = &plan->actions[i];
		ncfg_record_t        record;
		char                 message[NCFG_ERROR_MAX];

		memset(&record, 0, sizeof(record));
		record.id = action->id;
		record.op = ncfg_op_name(&action->op);
		record.interface = ncfg_op_interface(&action->op);
		record.reason = action->reason;
		if (stopped) {
			record.outcome = NCFG_OUTCOME_SKIPPED;
			ncfg_journal_push(journal, &record);
			continue;
		}
		message[0] = '\0';
		if (executor->execute(executor->state, &action->op, message, sizeof(message))) {
			record.outcome = NCFG_OUTCOME_DONE;
		} else {
			stopped = 1;
			record.outcome = NCFG_OUTCOME_FAILED;
			/* An executor that failed without saying why is a defect in that
			 * executor, and a journal entry reading `"error":null` beside
			 * `"outcome":"failed"` is what makes it visible instead of
			 * reading as a failure nobody described. */
			record.error = message[0] ? message : "the executor failed and said nothing";
		}
		ncfg_journal_push(journal, &record);
	}

	if (journal->failed) {
		ncfg_error_set(err, err_size,
		    "the plan ran, and the journal ran out of memory recording it; "
		    "what happened to the machine is not written down");
		return 0;
	}
	return 1;
}

/* ------------------------------------------------------------------------ *
 * Putting it back
 * ------------------------------------------------------------------------ */

/* The action a record came from. Matched by id rather than by position: a
 * journal may be assembled from more than one apply, and a position that
 * happened to line up would be a coincidence this relied on. */
static const ncfg_action_t *action_with_id(const ncfg_plan_t *plan, uint32_t id)
{
	size_t i;

	for (i = 0; i < plan->action_count; i++) {
		if (plan->actions[i].id == id) {
			return &plan->actions[i];
		}
	}
	return NULL;
}

size_t ncfg_apply_revert(const ncfg_plan_t *plan, ncfg_journal_t *journal,
    const ncfg_executor_t *executor)
{
	size_t undone = 0;
	size_t i;

	if (!plan || !journal || !executor || !executor->execute) {
		return 0;
	}
	/*
	 * Newest first: the inverses undo in the reverse of the order they were
	 * applied, the way any stack of changes comes off. An address added after
	 * a link was brought up has to go before the link goes down, or the
	 * removal is aimed at something that is no longer there.
	 */
	for (i = journal->record_count; i-- > 0;) {
		ncfg_record_t       *record = &journal->records[i];
		const ncfg_action_t *action;
		char                 message[NCFG_ERROR_MAX];

		/* Only what reached the kernel. A failed or skipped action changed
		 * nothing, and its inverse would be netcfgd taking back a change it
		 * never made. A second revert finds `NCFG_OUTCOME_REVERTED` here and
		 * leaves it alone for the same reason. */
		if (record->outcome != NCFG_OUTCOME_DONE) {
			continue;
		}
		action = action_with_id(plan, record->id);
		/* No declared inverse contributes nothing. Those are the actions the
		 * plan's "cannot be undone" warning is about -- a hook is arbitrary
		 * shell -- and that warning was true before this and stays true. */
		if (!action || !action->has_inverse) {
			continue;
		}
		message[0] = '\0';
		if (executor->execute(executor->state, &action->inverse, message, sizeof(message))) {
			record->outcome = NCFG_OUTCOME_REVERTED;
			undone++;
		}
		/*
		 * A failed inverse is stepped over rather than stopping the revert:
		 * the remaining ones are for other actions and are still worth
		 * running, and stopping would leave a machine that is neither the new
		 * configuration nor the old one -- the one outcome a revert exists to
		 * prevent.
		 *
		 * **It leaves the record saying `done`, which is the honest answer**:
		 * that change is still in effect. So `ncfg_journal_done` after a
		 * revert counts exactly what did not come back, and names each one,
		 * which is more than the log line the Rust emits here can do.
		 */
	}
	return undone;
}
