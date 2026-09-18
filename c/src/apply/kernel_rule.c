/*
 * kernel_rule.c -- installing and removing policy routing rules.
 *
 * WHAT A RULE IS, AND WHY THE OWNERSHIP TAG IS APPLIED HERE
 *   A route says where a packet goes; a rule says which set of routes is
 *   consulted in the first place, before any table is looked at. netcfgd
 *   stamps `FRA_PROTOCOL` 110 on every one it installs and refuses to remove
 *   anything not carrying it -- decision 0002, the same byte a route gets and
 *   for the same reason: a rule carries no other field that could say who put
 *   it there.
 *
 *   The tag is applied by `ops.h`'s builder rather than carried in the model,
 *   and this file leaves `protocol` absent so that it is. That is deliberate:
 *   ownership is netcfgd's own bookkeeping, and a model that carried it would
 *   be one an operator could forge by copying a configuration file.
 *
 * WHY THE SPEC BORROWS THE RULE
 *   `ncfg_ops_rule_t`'s `iif` and `oif` are `const char *` into the document
 *   being applied, which is what `rule.h` says about the same type on the
 *   reading side. So a spec must not outlive the rule it was built from, and
 *   nothing here copies a name -- a plan borrows its rule list from the
 *   document already (`plan.h`), so the lifetime is the document's either way.
 *
 * TWO REFUSALS THE RUST DOES NOT MAKE
 *   A selector whose family is not the rule's, and a selector written without
 *   a prefix length. The first is refused because the kernel's answer is a
 *   bare `EINVAL` naming nothing, and a `from` of an IPv6 address on an `inet`
 *   rule is a configuration mistake somebody can fix in a second once told.
 *   The second is *accepted* here and refused there -- see `selector`.
 */
#include "kernel_internal.h"

#include "ncfg/base.h"
#include "ncfg/value.h"
#include "ncfg/wire.h"

#include <stdio.h>
#include <string.h>

/*
 * One `from` or `to`, as an address and a length.
 *
 * **A selector written without a prefix length is a host selector**, which is
 * `ip rule from 10.0.0.5` and is what `kernel.c`'s `route_of` already does for
 * a route destination. The Rust's `parse_cidr` requires the slash and answers
 * `None` without one, so `from = "10.0.0.5"` compiles, plans, and fails at the
 * apply with "`10.0.0.5` is not a prefix" -- a refusal of the one spelling
 * every other tool accepts.
 */
static int selector(const char *text, uint8_t family, ncfg_wire_ip_t *out, uint8_t *length,
    char *err, size_t err_size)
{
	ncfg_address_t parsed;

	out->family = AF_UNSPEC;
	memset(out->bytes, 0, sizeof(out->bytes));
	*length = 0;
	if (!text) {
		return 1;
	}
	if (!ncfg_address_parse(text, &parsed, err, err_size)) {
		return 0;
	}
	if (!ncfg_ops_ip_from_address(&parsed, out, err, err_size)) {
		return 0;
	}
	if (out->family != (int)family) {
		/*
		 * The kernel takes the family from the message header and reads the
		 * selector as that many bytes, so a mismatched one is either
		 * `EINVAL` or -- worse -- four bytes of an IPv6 address read as an
		 * IPv4 selector. Refused by name rather than sent.
		 */
		ncfg_error_set(err, err_size,
		    "`%s` is not an address of the family this rule is for, and a rule's "
		    "family is stated rather than inferred from its selectors", text);
		out->family = AF_UNSPEC;
		return 0;
	}
	*length = parsed.has_prefix ? (uint8_t)parsed.prefix :
	    (uint8_t)(parsed.is_ipv6 ? 128 : 32);
	return 1;
}

/* A plain number narrowed to the width its field has. `ncfg_ops_narrow` takes
 * an optional, so a required one is wrapped rather than cast. */
static int narrow(int64_t value, int64_t ceiling, const char *what, uint32_t *out, char *err,
    size_t err_size)
{
	ncfg_optint_t held;

	held.has = 1;
	held.value = value;
	return ncfg_ops_narrow(held, ceiling, what, out, err, err_size);
}

int ncfg_kernel_rule_spec(const ncfg_routing_rule_t *rule, ncfg_ops_rule_t *out, char *err,
    size_t err_size)
{
	if (!rule || !out) {
		ncfg_error_set(err, err_size, "there is no rule to install or remove");
		return 0;
	}
	memset(out, 0, sizeof(*out));
	switch ((ncfg_rule_family_t)rule->family) {
	case NCFG_RULE_FAMILY_INET:
		out->family = AF_INET;
		break;
	case NCFG_RULE_FAMILY_INET6:
		out->family = AF_INET6;
		break;
	default:
		ncfg_error_set(err, err_size,
		    "rule `%s` names an address family this build does not know",
		    rule->id ? rule->id : "?");
		return 0;
	}
	switch ((ncfg_rule_action_t)rule->action) {
	case NCFG_RULE_ACTION_LOOKUP:
		out->action = FR_ACT_TO_TBL;
		break;
	case NCFG_RULE_ACTION_BLACKHOLE:
		out->action = FR_ACT_BLACKHOLE;
		break;
	case NCFG_RULE_ACTION_UNREACHABLE:
		out->action = FR_ACT_UNREACHABLE;
		break;
	case NCFG_RULE_ACTION_PROHIBIT:
		out->action = FR_ACT_PROHIBIT;
		break;
	default:
		ncfg_error_set(err, err_size, "rule `%s` names an action this build does not know",
		    rule->id ? rule->id : "?");
		return 0;
	}
	/*
	 * Checked rather than cast, everywhere the model's `int64_t` meets a
	 * kernel field -- `rule.rs` says what the cast costs in as many words:
	 * "truncating instead would send table 1000 as table 232", and table 232
	 * is a real table belonging to somebody else.
	 */
	if (!narrow(rule->priority, 0xffffffff, "priority", &out->priority, err, err_size)) {
		return 0;
	}
	if (rule->table.has &&
	    !ncfg_ops_narrow(rule->table, 0xffffffff, "table", &out->table, err, err_size)) {
		return 0;
	}
	/*
	 * The mark and its mask travel whole rather than narrowed-and-rebuilt:
	 * `ops.h` narrows them itself where it writes them, and doing it twice
	 * would put the refusal's wording in two places. What is checked here is
	 * only what `ops.h` cannot see -- that a mask with no mark beside it is a
	 * selector that matches nothing an operator meant.
	 */
	if (rule->fwmask.has && !rule->fwmark.has) {
		ncfg_error_set(err, err_size,
		    "rule `%s` has a firewall mask and no mark: the mask is applied before "
		    "the comparison, so on its own it selects packets marked zero",
		    rule->id ? rule->id : "?");
		return 0;
	}
	out->fwmark = rule->fwmark;
	out->fwmask = rule->fwmask;
	out->iif = rule->iif;
	out->oif = rule->oif;
	out->l3mdev = rule->l3mdev;
	out->invert = rule->invert;
	/* `suppress_prefixlength 0` is the whole `ip rule` trick, so absent and
	 * zero are different answers and the optional is passed through whole
	 * rather than defaulted. */
	out->suppress_prefixlength = rule->suppress_prefixlength;
	if (!selector(rule->from, out->family, &out->from, &out->from_len, err, err_size)) {
		return 0;
	}
	if (!selector(rule->to, out->family, &out->to, &out->to_len, err, err_size)) {
		return 0;
	}
	/* `protocol` is left absent, which `ops.h` reads as netcfgd's own 110. */
	return 1;
}

int ncfg_kernel_build_rule(ncfg_buf_t *out, uint32_t seq, const ncfg_op_t *op, int adding,
    char *err, size_t err_size)
{
	ncfg_ops_rule_t spec;

	if (!op || !op->u.rule.rule) {
		ncfg_error_set(err, err_size, "a rule action carries no rule");
		return 0;
	}
	if (!ncfg_kernel_rule_spec(op->u.rule.rule, &spec, err, err_size)) {
		return 0;
	}
	return adding ? ncfg_ops_add_rule(out, seq, &spec, err, err_size) :
	    ncfg_ops_del_rule(out, seq, &spec, err, err_size);
}

int ncfg_kernel_rule_op(const ncfg_kernel_world_t *world, const ncfg_op_t *op, int adding,
    char *err, size_t err_size)
{
	ncfg_buf_t  message;
	char        doing[NCFG_ERROR_MAX];
	const char *id = op->u.rule.rule && op->u.rule.rule->id ? op->u.rule.rule->id : "?";
	uint32_t    seq = ncfg_netlink_take_seq(world->socket);
	int         ok;

	ncfg_buf_init(&message, 0);
	ok = ncfg_kernel_build_rule(&message, seq, op, adding, err, err_size);
	if (ok) {
		(void)snprintf(doing, sizeof(doing), "%s rule `%s`",
		    adding ? "install" : "remove", id);
		ok = ncfg_kernel_send(world->socket, &message, seq, op->kind, doing, err,
		    err_size);
	}
	ncfg_buf_free(&message);
	return ok;
}
