/*
 * delegated.c -- the addressing source whose value is not in the document.
 *
 * WHAT A `delegated` SOURCE IS
 *   A DHCPv6 client on some other interface obtains a prefix, netcfgd is told
 *   about it through a file that client's hook writes, and the document says
 *   how to build an address out of it: which interface was delegated it, which
 *   of its prefixes, which sub-block, and what host part to put underneath.
 *   The document carries the *reference* and never the value, because a
 *   document embedding a runtime value would stop being a pure function of the
 *   config files (0009).
 *
 * WHY THE RESOLUTION IS A FUNCTION TWO PASSES SHARE
 *   Renumbering falls out of the ordinary diff -- a new delegation produces a
 *   different address, the old one is no longer wanted, and the plan is an
 *   `addr.del` and an `addr.add`. That only works if the teardown resolves the
 *   reference the same way the forward pass does. A teardown that could not
 *   answer "is this wanted?" would delete the address the same plan had just
 *   added, on every reconcile, for ever -- which is the one property `plan.h`
 *   calls load-bearing. So `ncfg_plan_delegated_address` is the single answer
 *   and both callers ask it.
 *
 * AND NOTHING HERE IS AN ERROR
 *   A delegation that has not arrived, a prefix index the lease does not
 *   carry, and a suffix that cannot be carved out of the block are three
 *   different sentences and none of them fails the plan. A refusal is a guard
 *   declining a disruptive action and is answered by consent (0010); these are
 *   a configuration that cannot be satisfied yet, or at all, and are answered
 *   by waiting or by editing.
 */
#include "plan_internal.h"

#include "ncfg/base.h"
#include "ncfg/value.h"

#include <string.h>

int ncfg_plan_delegated_address(const ncfg_builder_t *builder,
    const ncfg_address_source_t *source, char *out, size_t out_size, char *err, size_t err_size)
{
	const ncfg_delegated_t  *delegated = &source->delegated;
	const ncfg_delegation_t *delegation;

	delegation = ncfg_observed_delegation(builder->observed, delegated->prefix.source);
	if (!delegation) {
		ncfg_error_set(err, err_size,
		    "waiting on a delegated prefix from %s, so nothing is planned for it",
		    delegated->prefix.source ? delegated->prefix.source : "<absent>");
		return 0;
	}
	if (delegated->prefix.index < 0 ||
	    (uint64_t)delegated->prefix.index >= (uint64_t)delegation->prefix_count) {
		ncfg_error_set(err, err_size,
		    "%s has %zu delegated prefix(es) and this source asks for index %lld",
		    delegated->prefix.source ? delegated->prefix.source : "<absent>",
		    delegation->prefix_count, (long long)delegated->prefix.index);
		return 0;
	}
	return ncfg_address_from_delegation(delegation->prefixes[(size_t)delegated->prefix.index],
	    delegated->prefix.subnet, delegated->suffix, out, out_size, err, err_size);
}

void ncfg_plan_delegated(ncfg_builder_t *builder, const ncfg_interface_t *interface, size_t index,
    const ncfg_plan_ids_t *base, ncfg_plan_ids_t *out)
{
	const ncfg_address_source_t *source = &interface->addressing[index];
	const char                  *address;
	char                         derived[NCFG_ADDRESS_MAX];
	char                         message[NCFG_ERROR_MAX];
	ncfg_op_t                    op;
	ncfg_op_t                    inverse;
	ncfg_reason_t                reason;
	uint32_t                     id;
	size_t                       i;

	message[0] = '\0';
	if (!ncfg_plan_delegated_address(builder, source, derived, sizeof(derived), message,
	    sizeof(message))) {
		/* The field is in front of every one of the three sentences rather
		 * than inside one of them: an interface may carry several of these
		 * sources and "waiting on a delegated prefix" names the interface it
		 * waits on, not the line that asked. */
		ncfg_plan_warnf(builder->plan, interface->name, "addressing[%zu]: %s", index,
		    message);
		return;
	}

	for (i = 0; i < builder->observed->address_count; i++) {
		const ncfg_observed_address_t *seen = &builder->observed->addresses[i];

		if (seen->interface && interface->name &&
		    strcmp(seen->interface, interface->name) == 0 &&
		    ncfg_plan_address_equal(seen->address, derived)) {
			return;
		}
	}

	/* Interned, because `builder->added` holds it for ordering rule 4 long
	 * after this frame is gone, and the op's own copy is the plan's. */
	address = ncfg_plan_intern(builder->plan, derived);
	if (!address) {
		return;
	}
	memset(&op, 0, sizeof(op));
	op.kind = NCFG_OP_ADDR_ADD;
	op.u.addr_add.iface = interface->name;
	op.u.addr_add.addr = address;
	memset(&inverse, 0, sizeof(inverse));
	inverse.kind = NCFG_OP_ADDR_DEL;
	inverse.u.addr_del.iface = interface->name;
	inverse.u.addr_del.addr = address;
	reason = ncfg_plan_reason_absent(interface->name,
	    ncfg_plan_internf(builder->plan, "addressing[%zu]", index),
	    ncfg_plan_internf(builder->plan, "%s (from %s)", address,
	        source->delegated.prefix.source ? source->delegated.prefix.source : "<absent>"));

	/*
	 * The source interface's lease has to exist before this address can, and
	 * it does -- the delegation was read from observed state. What this still
	 * waits for is the same base the interface's other addresses do, and rule
	 * 3's second half still holds: an address may go on a link that is down.
	 */
	id = ncfg_builder_push(builder, &op, &reason, base->ids, base->count, &inverse);
	if (id == NCFG_PLAN_NO_ACTION) {
		return;
	}
	ncfg_plan_ids_push(builder->plan, out, id);
	ncfg_plan_note_added(builder, interface->name, address, id);
}
