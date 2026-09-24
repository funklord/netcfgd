/*
 * host_wide.c -- the two actions that configure the machine rather than an
 * interface: the DNS delivery and the hostname.
 *
 * WHY THESE TWO ARE ONE FILE
 *   They are the pair `ncfg_op_is_host_wide_config` names, and that list is
 *   deliberately a list of two rather than "names no interface" (0165): the
 *   three commit ops also name none and must never be swept into a drift pass.
 *   Whatever else this file grows, it grows because that list did.
 *
 * THE SCOPE LIST IS A RULE, NOT A LOOP, AND IT IS NO LONGER HERE
 *   In the Rust the list is `netcfgd_model::dns::scopes`, called by the
 *   planner and by the executor, and the comment above it says why: the
 *   planner learned that a report contributes nameservers (0006 rule 4) and
 *   the executor went on building its scope list from the document alone, so
 *   the plan said `dns.apply` and the delivery wrote a `resolv.conf` with
 *   nothing in it. This file had the only caller and so spelled the rule, on
 *   the condition written here that the second caller would take this one
 *   rather than write a third. The daemon is that caller -- an executor's
 *   `dns_scopes` is the same list -- so the rule is `ncfg_dns_scopes_of` in
 *   `dns.h` now, beside `ncfg_dns_flatten`, and this pass asks it.
 *
 *   What stayed is the part that is about *plans*: whether a delivery is worth
 *   making, which scopes have departed, and the warning that says why nothing
 *   is being written. Those are decisions, and the daemon inherits none of
 *   them by asking the same question.
 *
 *   The scope list is **adopted by the plan** rather than freed here, because
 *   a `dns.apply` op borrows the policy in it and `plan.h`'s borrow rule says
 *   that must outlive the plan. See `ncfg_plan_adopt`.
 *
 * AND WHY AN EMPTY DELIVERY IS NOT WRITTEN
 *   A delivery with no servers anywhere overwrites a working `resolv.conf`
 *   with a file that resolves nothing, and the plan said `dns.apply` while the
 *   machine's DNS went away. Measured against a real resolver file, and the
 *   mode the first-run guide recommends is the one that does it (0066). So
 *   nothing is planned -- writing nothing preserves what is on disk, which is
 *   the one behaviour that leaves the machine fixable -- and a warning says
 *   why, because netcfgd knows the reason and an operator staring at an empty
 *   file does not.
 *
 *   **A warning and not a refusal.** A refusal makes `ncfg apply` exit
 *   non-zero because a decision is outstanding (0010); on any DHCP machine the
 *   servers are absent between starting the client and the lease landing, so
 *   refusing turns the ordinary first apply into a failed one.
 */
#include "plan_internal.h"

#include "ncfg/base.h"
#include "ncfg/value.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------------ *
 * Comparing a policy against what was last delivered
 * ------------------------------------------------------------------------ */

/*
 * Whether this is the policy already in force.
 *
 * Rendered through the planner's own writer rather than walked field by field,
 * and that is the point: the writer is what a plan and the record under
 * `<run>/dns/` are both made of, so a member added to `ncfg_dns_policy_t` and
 * missed here is impossible rather than unlikely. A hand-written comparison is
 * the third list to keep in step with the struct and the writer, and the list
 * maintained by hand is the one this project has already got wrong twice.
 */
static int policy_matches(const ncfg_dns_policy_t *left, const ncfg_dns_policy_t *right)
{
	ncfg_buf_t         first;
	ncfg_buf_t         second;
	ncfg_json_writer_t writer;
	const char        *a;
	const char        *b;
	int                same;

	if (!left || !right) {
		return left == right;
	}
	ncfg_buf_init(&first, 0);
	ncfg_buf_init(&second, 0);
	ncfg_json_write_init(&writer, &first);
	ncfg_plan_write_dns_policy(&writer, left);
	ncfg_json_write_init(&writer, &second);
	ncfg_plan_write_dns_policy(&writer, right);
	a = ncfg_buf_text(&first);
	b = ncfg_buf_text(&second);
	/*
	 * A buffer that failed hands out the empty string, so two failures would
	 * compare equal and the pass would plan nothing at all. Answering "they
	 * differ" is the safe direction: the worst case is a delivery that was
	 * already in force being written again, and the alternative is a machine
	 * whose resolver was never configured reporting nothing to do.
	 */
	same = !ncfg_buf_failed(&first) && !ncfg_buf_failed(&second) && strcmp(a, b) == 0;
	ncfg_buf_free(&first);
	ncfg_buf_free(&second);
	return same;
}

/* ------------------------------------------------------------------------ *
 * The pass
 * ------------------------------------------------------------------------ */

/* The scopes netcfgd delivered that the document no longer has, joined. */
static const char *departed_scopes(ncfg_builder_t *builder, const ncfg_dns_scope_t *scopes,
    size_t count, int *any)
{
	char   joined[NCFG_ERROR_MAX];
	size_t at = 0;
	size_t i;
	size_t j;

	joined[0] = '\0';
	*any = 0;
	for (i = 0; i < builder->observed->dns_count; i++) {
		const char *scope = builder->observed->dns[i].scope;
		int         still_there = 0;

		for (j = 0; j < count; j++) {
			if (scope && scopes[j].name && strcmp(scope, scopes[j].name) == 0) {
				still_there = 1;
				break;
			}
		}
		if (still_there || !scope) {
			continue;
		}
		*any = 1;
		at += (size_t)snprintf(joined + at, sizeof(joined) - at, "%s%s", at ? ", " : "",
		    scope);
		if (at >= sizeof(joined)) {
			break;
		}
	}
	return ncfg_plan_intern(builder->plan, joined);
}

/*
 * Whether every scope would deliver nothing, and the sentence that says why.
 *
 * `count != 0` first, and it is not defensive: "all of an empty list" is true,
 * so without it every document that manages no DNS at all -- which is the
 * default -- is told its resolver file would resolve nothing.
 */
static int delivers_nothing(const ncfg_dns_scope_t *scopes, size_t count)
{
	size_t i;

	if (count == 0u) {
		return 0;
	}
	for (i = 0; i < count; i++) {
		if (scopes[i].policy->server_count != 0u ||
		    scopes[i].policy->mode.mode == NCFG_DNS_MODE_NONE) {
			return 0;
		}
	}
	return 1;
}

static void warn_empty_delivery(ncfg_builder_t *builder)
{
	char   offered[NCFG_ERROR_MAX];
	size_t at = 0;
	size_t i;

	offered[0] = '\0';
	for (i = 0; i < builder->observed->report_count; i++) {
		const ncfg_observed_report_t *report = &builder->observed->reports[i];

		if (report->nameserver_count == 0u || !report->interface) {
			continue;
		}
		at += (size_t)snprintf(offered + at, sizeof(offered) - at, "%s%s", at ? ", " : "",
		    report->interface);
		if (at >= sizeof(offered)) {
			break;
		}
	}
	if (at == 0u) {
		ncfg_plan_warn(builder->plan, NULL,
		    "the DNS delivery has no servers in it, so it would write a resolver file "
		    "that resolves nothing -- netcfgd is leaving the existing file alone "
		    "instead: nothing in the configuration names a nameserver");
		return;
	}
	ncfg_plan_warnf(builder->plan, NULL,
	    "the DNS delivery has no servers in it, so it would write a resolver file that "
	    "resolves nothing -- netcfgd is leaving the existing file alone instead: a lease on "
	    "%s offered nameservers and no interface asked for them -- add an empty `dns { }` "
	    "block to that interface to use what the network hands out",
	    offered);
}

/* `ncfg_plan_adopt`'s release, so that no function pointer has to be cast. */
static void release_scopes(void *scopes)
{
	ncfg_dns_scopes_free(scopes);
}

void ncfg_plan_dns(ncfg_builder_t *builder)
{
	ncfg_dns_scopes_t      *owner;
	const ncfg_dns_scope_t *scopes;
	size_t                  count = 0;
	const char             *departed;
	ncfg_op_t               op;
	ncfg_op_t               inverse;
	ncfg_reason_t           reason;
	int                     any_departed = 0;
	size_t                  i;

	owner = ncfg_dns_scopes_of(builder->desired, builder->observed, NULL, 0);
	if (!owner) {
		builder->plan->failed = 1;
		return;
	}
	/*
	 * Adopted before anything is read out of it, and not at the end: every
	 * path below that returns early would otherwise have to remember to free
	 * it, which is the shape of leak this file already had once. From here the
	 * plan owns it, including where the adoption itself failed -- that frees
	 * it -- so the two returns below are the plan's business and not this
	 * function's.
	 */
	if (!ncfg_plan_adopt(builder->plan, owner, release_scopes)) {
		return;
	}
	scopes = ncfg_dns_scopes_items(owner, &count);
	departed = departed_scopes(builder, scopes, count, &any_departed);

	if (delivers_nothing(scopes, count)) {
		warn_empty_delivery(builder);
		/*
		 * **Only when there is nothing of netcfgd's to take back.** A scope
		 * that has left the document still has its nameservers in the file,
		 * and the empty write is exactly how they are withdrawn -- so
		 * returning here would strand them for ever. Neither "always write"
		 * nor "never write" is right, and what separates them is whether the
		 * file holds a delivery of netcfgd's that the document no longer asks
		 * for.
		 */
		if (!any_departed) {
			return;
		}
	}

	/*
	 * A scope netcfgd applied and the document no longer has. The loop below
	 * walks what is *desired*, so a scope that went away is never visited and
	 * its nameservers stay in the resolver file for ever, with `ncfg plan`
	 * saying `nothing to do` beside them. The file is written whole on any
	 * delivery, so one re-delivery is the whole of the repair -- and the
	 * action is named for the reader rather than for the executor, which
	 * delivers every scope on any `dns.apply` whatever this says.
	 *
	 * Only where a scope remains to deliver, and that is not a detail: with
	 * none left netcfgd manages no DNS at all, and rewriting the file from
	 * nothing is the empty `resolv.conf` the warning above exists to prevent.
	 */
	if (any_departed && count != 0u) {
		memset(&op, 0, sizeof(op));
		op.kind = NCFG_OP_DNS_APPLY;
		op.u.dns.scope = scopes[0].name;
		op.u.dns.policy = scopes[0].policy;
		reason = ncfg_plan_reason_unwanted(scopes[0].name, "dns", departed);
		(void)ncfg_builder_push(builder, &op, &reason, NULL, 0, NULL);
	}

	for (i = 0; i < count; i++) {
		const ncfg_dns_policy_t *previous = ncfg_observed_dns_for(builder->observed,
		    scopes[i].name);
		int                      global = strcmp(scopes[i].name,
		    NCFG_DNS_GLOBAL_SCOPE) == 0;

		if (policy_matches(previous, scopes[i].policy)) {
			continue;
		}
		memset(&op, 0, sizeof(op));
		op.kind = NCFG_OP_DNS_APPLY;
		op.u.dns.scope = scopes[i].name;
		op.u.dns.policy = scopes[i].policy;
		reason = ncfg_plan_reason_differs(global ? NULL : scopes[i].name, "dns",
		    ncfg_dns_mode_name((ncfg_dns_mode_t)scopes[i].policy->mode.mode),
		    previous ? ncfg_dns_mode_name((ncfg_dns_mode_t)previous->mode.mode) :
		        "<absent>");
		if (previous) {
			memset(&inverse, 0, sizeof(inverse));
			inverse.kind = NCFG_OP_DNS_APPLY;
			inverse.u.dns.scope = scopes[i].name;
			inverse.u.dns.policy = previous;
			(void)ncfg_builder_push(builder, &op, &reason, NULL, 0, &inverse);
		} else {
			(void)ncfg_builder_push(builder, &op, &reason, NULL, 0, NULL);
		}
	}
}

/* ------------------------------------------------------------------------ *
 * The hostname
 * ------------------------------------------------------------------------ */

/*
 * The running hostname, where the document names one.
 *
 * Whole-host and one-directional: netcfgd sets the name when the config says
 * one and does nothing when it does not. There is deliberately no withdraw
 * direction, unlike every sysctl in this planner -- the value to put back
 * would be whatever the init system read out of `/etc/hostname` at boot, which
 * netcfgd does not know and must not guess.
 *
 * `hostname = "dhcp"` is refused with a sentence rather than obeyed. netcfgd
 * does not implement DHCP (0004), so the name a server offered is known only
 * to the client -- and a hostname is the machine's identity, which is the
 * class of thing 0049 already decided a remote server does not get to change
 * by connecting. The mechanism that does exist is the `lease` hook, which runs
 * with the client's environment.
 */
void ncfg_plan_hostname(ncfg_builder_t *builder)
{
	const ncfg_hostname_policy_t *policy = &builder->desired->globals.hostname_policy;
	const char                   *current = builder->observed->hostname;
	ncfg_op_t                     op;
	ncfg_op_t                     inverse;
	ncfg_reason_t                 reason;

	if (policy->kind == NCFG_HOSTNAME_POLICY_FROM_DHCP) {
		ncfg_plan_warn(builder->plan, NULL,
		    "`hostname = \"dhcp\"` is not applied: netcfgd delegates DHCP and never sees "
		    "the lease, so the name a server offered is the client's to act on -- run "
		    "`hostnamectl` or `hostname` from a `lease` hook if that is what you want");
		return;
	}
	if (policy->kind != NCFG_HOSTNAME_POLICY_STATIC || !policy->name) {
		return;
	}
	/* A hostname netcfgd cannot read is one it cannot tell whether it has
	 * already set, and writing it on every reconcile would be a plan that
	 * never converges. */
	if (!current) {
		ncfg_plan_warn(builder->plan, NULL,
		    "the hostname cannot be read, so it is not set -- a container without "
		    "/proc/sys");
		return;
	}
	if (strcmp(current, policy->name) == 0) {
		return;
	}

	memset(&op, 0, sizeof(op));
	op.kind = NCFG_OP_HOSTNAME_SET;
	op.u.named.name = policy->name;
	memset(&inverse, 0, sizeof(inverse));
	inverse.kind = NCFG_OP_HOSTNAME_SET;
	/* The previous name is known, so the revert is the real thing rather than
	 * a guess -- which is what makes this the one direction that has one. */
	inverse.u.named.name = current;
	reason = ncfg_plan_reason_differs(NULL, "globals.hostname", policy->name, current);
	(void)ncfg_builder_push(builder, &op, &reason, NULL, 0, &inverse);
}
