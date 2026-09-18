/*
 * nat.c -- netcfgd's one nftables table, replaced whole.
 *
 * WHY THERE IS NO PER-RULE DIFF
 *   Decision 0022 gives netcfgd exactly one table and one thing to say with
 *   it: these interfaces are uplinks and traffic leaving them is
 *   masqueraded. So the comparison is between two sorted lists of interface
 *   names, and that is the entire diff -- there is no per-rule
 *   reconciliation because there is no per-rule change. Deciding which
 *   packets may *pass* is security policy, which this project has no model
 *   of and will not grow one by accident.
 *
 * THE TWO WARNINGS, AND WHY NEITHER IS A REFUSAL
 *   A second source-NAT chain translates the same packets twice, which breaks
 *   return paths in ways that look like packet loss. netcfgd will not delete
 *   somebody else's table -- it cannot evaluate the filtering in there -- so
 *   the operator is told and the operator decides. And NAT with nothing
 *   forwarded translates packets the kernel already dropped, which is a router
 *   that silently does nothing; both halves are set independently and that is
 *   the mistake worth naming.
 */
#include "plan_internal.h"

#include "ncfg/base.h"
#include "ncfg/buf.h"

#include <stdlib.h>
#include <string.h>

static int by_name(const void *left, const void *right)
{
	const char *const *one = left;
	const char *const *other = right;

	if (!*one || !*other) {
		return *one ? 1 : (*other ? -1 : 0);
	}
	return strcmp(*one, *other);
}

/* `eth0, wwan0`, or the word for having none, for a plan's reason line. */
static const char *describe(ncfg_plan_t *plan, const char *const *names, size_t count)
{
	ncfg_buf_t  buf;
	const char *text;
	size_t      i;

	if (count == 0u) {
		return "<none>";
	}
	ncfg_buf_init(&buf, 0);
	for (i = 0; i < count; i++) {
		ncfg_buf_addf(&buf, "%s%s", i ? ", " : "", names[i] ? names[i] : "");
	}
	text = ncfg_plan_intern(plan, ncfg_buf_text(&buf));
	ncfg_buf_free(&buf);
	return text ? text : "<none>";
}

/* Whether two name lists are the same list in the same order. */
static int same_uplinks(const char *const *left, size_t left_count, const char *const *right,
    size_t right_count)
{
	size_t i;

	if (left_count != right_count) {
		return 0;
	}
	for (i = 0; i < left_count; i++) {
		if (by_name(&left[i], &right[i]) != 0) {
			return 0;
		}
	}
	return 1;
}

static void warn_conflicts(ncfg_builder_t *builder, size_t wanted_count)
{
	const ncfg_observed_t *observed = builder->observed;
	ncfg_buf_t             buf;
	size_t                 i;

	/*
	 * Reported whenever netcfgd has an opinion about NAT, **including when its
	 * opinion is "none"** -- an operator who has just removed `nat` from their
	 * configuration is exactly the person who needs to know something else is
	 * still translating.
	 */
	if (observed->nat_conflict_count == 0u ||
	    (wanted_count == 0u && observed->nat_count == 0u)) {
		return;
	}
	ncfg_buf_init(&buf, 0);
	for (i = 0; i < observed->nat_conflict_count; i++) {
		ncfg_buf_addf(&buf, "%s%s", i ? "`, `" : "",
		    observed->nat_conflicts[i] ? observed->nat_conflicts[i] : "");
	}
	ncfg_plan_warnf(builder->plan, NULL,
	    "nftables table(s) `%s` also translate source addresses. Traffic matching both is "
	    "translated twice, which breaks return paths in ways that look like packet loss. "
	    "netcfgd will not delete another table -- it cannot tell what filtering is in there "
	    "-- so remove the duplicate rule yourself, or drop `nat` here.",
	    ncfg_buf_text(&buf));
	ncfg_buf_free(&buf);
}

void ncfg_plan_nat(ncfg_builder_t *builder)
{
	const ncfg_document_t *desired = builder->desired;
	const char           **wanted;
	size_t                 count = 0;
	int                    forwarding = 0;
	ncfg_op_t              op;
	ncfg_op_t              inverse;
	ncfg_reason_t          reason;
	size_t                 i;

	if (desired->interface_count != 0u) {
		wanted = calloc(desired->interface_count, sizeof(*wanted));
		if (!wanted) {
			builder->plan->failed = 1;
			return;
		}
	} else {
		wanted = NULL;
	}
	for (i = 0; i < desired->interface_count; i++) {
		const ncfg_interface_t *interface = &desired->interfaces[i];

		if (interface->nat.has && interface->nat.value) {
			wanted[count++] = interface->name;
		}
		if (interface->forwarding.has && interface->forwarding.value) {
			forwarding = 1;
		}
	}
	if (count != 0u) {
		qsort(wanted, count, sizeof(*wanted), by_name);
	}

	warn_conflicts(builder, count);
	/*
	 * Forwarding is what makes NAT do anything, and the two are set
	 * independently, so this is the mistake that produces a router which
	 * translates nothing because nothing was forwarded to it.
	 */
	if (count != 0u && !forwarding) {
		ncfg_plan_warn(builder->plan, NULL,
		    "`nat` is set but no interface has `forwarding = true`, so nothing will "
		    "reach the translation. Set it on the interface the traffic arrives on -- "
		    "the LAN side, not the uplink.");
	}

	if (same_uplinks((const char *const *)wanted, count,
	    (const char *const *)builder->observed->nat,
	    builder->observed->nat_count)) {
		free(wanted);
		return;
	}
	memset(&op, 0, sizeof(op));
	op.kind = NCFG_OP_NAT_REPLACE;
	op.u.nat.uplinks = (const char *const *)wanted;
	op.u.nat.uplink_count = count;
	memset(&inverse, 0, sizeof(inverse));
	inverse.kind = NCFG_OP_NAT_REPLACE;
	/* The table as it stands, which is a real revert rather than a guess: an
	 * empty list removes the table, and that is what a machine with no table
	 * had. */
	inverse.u.nat.uplinks = (const char *const *)builder->observed->nat;
	inverse.u.nat.uplink_count = builder->observed->nat_count;
	reason = ncfg_plan_reason_differs(NULL, "nat",
	    describe(builder->plan, (const char *const *)wanted, count),
	    describe(builder->plan, (const char *const *)builder->observed->nat,
	        builder->observed->nat_count));
	(void)ncfg_builder_push(builder, &op, &reason, NULL, 0, &inverse);
	/* `ncfg_plan_add` copies the list into the plan's arena, so this one is
	 * the caller's to give back -- the same bargain every string an op names
	 * is under. */
	free(wanted);
}
