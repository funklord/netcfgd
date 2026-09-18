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
 * THE SCOPE LIST IS A RULE, NOT A LOOP
 *   In the Rust the list is `netcfgd_model::dns::scopes`, called by the
 *   planner and by the executor, and the comment above it says why: the
 *   planner learned that a report contributes nameservers (0006 rule 4) and
 *   the executor went on building its scope list from the document alone, so
 *   the plan said `dns.apply` and the delivery wrote a `resolv.conf` with
 *   nothing in it. **This port has one caller for it so far** -- `dns.h`
 *   takes a scope list from whoever delivers, and nothing in `c/src/` composes
 *   one -- so the rule is spelled here, where the only caller is. It belongs
 *   beside `ncfg_dns_flatten` in `dns.h`, and the second caller takes this one
 *   rather than writing a third. That is `explain.c`'s arrangement for
 *   `takes_reports`, for the same reason and with the same obligation.
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
#include "ncfg/dns.h"
#include "ncfg/value.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* One scope to deliver: a name and a policy that outlives the plan. */
typedef struct {
	const char              *name;
	const ncfg_dns_policy_t *policy;
} scope_t;

typedef struct {
	scope_t *items;
	size_t   count;
	size_t   capacity;
} scopes_t;

static int scopes_push(scopes_t *scopes, const char *name, const ncfg_dns_policy_t *policy)
{
	scope_t *grown;
	size_t   wanted;

	if (!policy) {
		return 0;
	}
	if (scopes->count == scopes->capacity) {
		wanted = scopes->capacity ? scopes->capacity * 2u : 8u;
		grown = realloc(scopes->items, wanted * sizeof(*grown));
		if (!grown) {
			return 0;
		}
		scopes->items = grown;
		scopes->capacity = wanted;
	}
	scopes->items[scopes->count].name = name;
	scopes->items[scopes->count].policy = policy;
	scopes->count++;
	return 1;
}

/* ------------------------------------------------------------------------ *
 * What a report contributes
 * ------------------------------------------------------------------------ */

/*
 * Whether this interface asked for what a report has to offer.
 *
 * **The same gate for the servers and the suffixes, and that is the argument
 * rather than a convenience**: a suffix is only delivered where that network's
 * resolvers are already answering, and a party answering every query gains
 * nothing by also appending a suffix. Where an operator kept their own
 * resolvers, a lease does not get to redefine what a bare name means -- which
 * is the case 0049 was protecting.
 */
static int claimed(const ncfg_interface_t *interface)
{
	size_t i;

	if (interface->dns) {
		return 1;
	}
	for (i = 0; i < interface->addressing_count; i++) {
		if (interface->addressing[i].kind == NCFG_ADDRESS_SOURCE_REPORTED) {
			return 1;
		}
	}
	return 0;
}

static const ncfg_observed_report_t *report_for(const ncfg_observed_t *observed, const char *name)
{
	size_t i;

	for (i = 0; i < observed->report_count; i++) {
		if (observed->reports[i].interface && name &&
		    strcmp(observed->reports[i].interface, name) == 0) {
			return &observed->reports[i];
		}
	}
	return NULL;
}

/*
 * A nameserver a report named, as the model spells it.
 *
 * Kept as text by the reader on purpose, so one bad line does not discard a
 * whole report; this is where it has to become an address. A prefix is
 * refused rather than carried, because a nameserver is one address and
 * `10.0.0.53/24` in a `nameserver` line is a resolver file nothing can use.
 *
 * **Canonical, and that is what makes the pass idempotent.** The delivery
 * records what it wrote under `<run>/dns/`, the observer reads it back, and
 * this pass compares the two: a server carried through in whatever spelling
 * the report's author used would compare unequal against netcfgd's own record
 * of having delivered it, and `dns.apply` would be planned on every run.
 */
static const char *reported_server(ncfg_plan_t *plan, const char *text)
{
	ncfg_address_t parsed;
	char           canonical[NCFG_ADDRESS_MAX];

	if (!text || !ncfg_address_parse(text, &parsed, NULL, 0) || parsed.has_prefix) {
		return NULL;
	}
	if (!ncfg_address_render(&parsed, canonical, sizeof(canonical), NULL, 0)) {
		return NULL;
	}
	return ncfg_plan_intern(plan, canonical);
}

/* ------------------------------------------------------------------------ *
 * Building one scope
 * ------------------------------------------------------------------------ */

/*
 * A policy with the host's mode filled in where it states none of its own.
 *
 * **The mode is not a per-interface choice.** The delivery refuses a set of
 * scopes that disagree about it, because a host cannot both own `resolv.conf`
 * and hand it to `resolvconf`. So `none` on a scope that has something to
 * deliver can only mean "not stated", and the only value that is not an error
 * is the one the rest of the host uses. Without this, `dns = "9.9.9.9"` on an
 * interface compiles to a policy with mode `none`, the executor drops the
 * scope, and an operator wrote a nameserver down that netcfgd silently
 * ignored.
 *
 * Returns the document's own policy where it needs nothing added, so the
 * ordinary case borrows exactly as `plan.h` says a DNS policy does.
 */
static const ncfg_dns_policy_t *build_scope(ncfg_builder_t *builder,
    const ncfg_dns_policy_t *base, const ncfg_observed_report_t *report)
{
	const ncfg_dns_mode_value_t *host = &builder->desired->globals.dns.mode;
	ncfg_dns_policy_t           *copy;
	size_t                       extra_servers = report ? report->nameserver_count : 0u;
	size_t                       extra_search = report ? report->search_count : 0u;
	size_t                       i;

	if (base && base->mode.mode != NCFG_DNS_MODE_NONE && !extra_servers && !extra_search) {
		return base;
	}
	copy = ncfg_plan_intern_dns_policy(builder->plan, base, extra_servers, extra_search);
	if (!copy) {
		return NULL;
	}
	if (!base || base->mode.mode == NCFG_DNS_MODE_NONE) {
		copy->mode = *host;
	}
	/*
	 * Rule 4: a source contributes nameservers and they merge with what the
	 * document wrote. **The document's come first**, so first-occurrence-wins
	 * means a server an operator chose beats one the network handed out -- and
	 * the same for the suffixes, which resolution tries in order.
	 */
	for (i = 0; report && i < report->nameserver_count; i++) {
		const char *address = reported_server(builder->plan, report->nameservers[i]);

		if (!address) {
			continue;
		}
		/* Consecutive duplicates only, which is what the Rust's `dedup` does:
		 * a report repeating what the document already ends with contributes
		 * nothing, and two identical servers an operator wrote on purpose are
		 * left alone. */
		if (copy->server_count != 0u && copy->servers[copy->server_count - 1u].addr &&
		    strcmp(copy->servers[copy->server_count - 1u].addr, address) == 0) {
			continue;
		}
		memset(&copy->servers[copy->server_count], 0, sizeof(*copy->servers));
		copy->servers[copy->server_count].addr = (char *)(uintptr_t)address;
		copy->server_count++;
	}
	for (i = 0; report && i < report->search_count; i++) {
		if (!report->search[i]) {
			continue;
		}
		if (copy->search_count != 0u && copy->search[copy->search_count - 1u] &&
		    strcmp(copy->search[copy->search_count - 1u], report->search[i]) == 0) {
			continue;
		}
		copy->search[copy->search_count++] = report->search[i];
	}
	return copy;
}

static int policy_is_empty(const ncfg_dns_policy_t *policy)
{
	return policy->server_count == 0u && policy->search_count == 0u &&
	    policy->domain_count == 0u && policy->option_count == 0u;
}

/* Every scope this document asks for, given what has been observed. */
static int scopes_of(ncfg_builder_t *builder, scopes_t *scopes)
{
	const ncfg_document_t *desired = builder->desired;
	size_t                 i;

	if (desired->globals.dns.mode.mode != NCFG_DNS_MODE_NONE) {
		if (!scopes_push(scopes, NCFG_DNS_GLOBAL_SCOPE, &desired->globals.dns)) {
			return 0;
		}
	}
	for (i = 0; i < desired->interface_count; i++) {
		const ncfg_interface_t       *interface = &desired->interfaces[i];
		const ncfg_device_t          *device = ncfg_plan_device(desired, interface->name);
		const ncfg_observed_report_t *report;
		const ncfg_dns_policy_t      *policy;
		int                           offers = 0;

		/*
		 * An unmanaged device contributes no scope. `dns.apply` is host-wide,
		 * so it names no interface and `ncfg_builder_push`'s usual choke point
		 * does not see it -- this is where it has to be asked.
		 */
		if (device && !device->managed) {
			continue;
		}
		report = claimed(interface) ? report_for(builder->observed, interface->name) : NULL;
		offers = report && (report->nameserver_count != 0u || report->search_count != 0u);
		if (!interface->dns) {
			/*
			 * Servers reported and nowhere to put them, because this host
			 * manages no DNS. Skipped rather than pushed with a `none` mode: a
			 * scope that delivers nothing is still an action in the plan, and
			 * an action that does nothing is one somebody reads and dismisses
			 * on every run.
			 */
			if (!offers || desired->globals.dns.mode.mode == NCFG_DNS_MODE_NONE) {
				continue;
			}
		} else if (!offers && policy_is_empty(interface->dns)) {
			/* `dns { }` with nothing in it asks for nothing, and a scope for
			 * it is an action that does nothing. */
			continue;
		}
		policy = build_scope(builder, interface->dns, offers ? report : NULL);
		if (!policy || !scopes_push(scopes, interface->name, policy)) {
			return 0;
		}
	}
	return 1;
}

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
static const char *departed_scopes(ncfg_builder_t *builder, const scopes_t *scopes, int *any)
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

		for (j = 0; j < scopes->count; j++) {
			if (scope && scopes->items[j].name &&
			    strcmp(scope, scopes->items[j].name) == 0) {
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
static int delivers_nothing(const scopes_t *scopes)
{
	size_t i;

	if (scopes->count == 0u) {
		return 0;
	}
	for (i = 0; i < scopes->count; i++) {
		if (scopes->items[i].policy->server_count != 0u ||
		    scopes->items[i].policy->mode.mode == NCFG_DNS_MODE_NONE) {
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

void ncfg_plan_dns(ncfg_builder_t *builder)
{
	scopes_t      scopes = { NULL, 0, 0 };
	const char   *departed;
	ncfg_op_t     op;
	ncfg_op_t     inverse;
	ncfg_reason_t reason;
	int           any_departed = 0;
	size_t        i;

	if (!scopes_of(builder, &scopes)) {
		builder->plan->failed = 1;
		free(scopes.items);
		return;
	}
	departed = departed_scopes(builder, &scopes, &any_departed);

	if (delivers_nothing(&scopes)) {
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
			free(scopes.items);
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
	if (any_departed && scopes.count != 0u) {
		memset(&op, 0, sizeof(op));
		op.kind = NCFG_OP_DNS_APPLY;
		op.u.dns.scope = scopes.items[0].name;
		op.u.dns.policy = scopes.items[0].policy;
		reason = ncfg_plan_reason_unwanted(scopes.items[0].name, "dns", departed);
		(void)ncfg_builder_push(builder, &op, &reason, NULL, 0, NULL);
	}

	for (i = 0; i < scopes.count; i++) {
		const ncfg_dns_policy_t *previous = ncfg_observed_dns_for(builder->observed,
		    scopes.items[i].name);
		int                      global = strcmp(scopes.items[i].name,
		    NCFG_DNS_GLOBAL_SCOPE) == 0;

		if (policy_matches(previous, scopes.items[i].policy)) {
			continue;
		}
		memset(&op, 0, sizeof(op));
		op.kind = NCFG_OP_DNS_APPLY;
		op.u.dns.scope = scopes.items[i].name;
		op.u.dns.policy = scopes.items[i].policy;
		reason = ncfg_plan_reason_differs(global ? NULL : scopes.items[i].name, "dns",
		    ncfg_dns_mode_name((ncfg_dns_mode_t)scopes.items[i].policy->mode.mode),
		    previous ? ncfg_dns_mode_name((ncfg_dns_mode_t)previous->mode.mode) :
		        "<absent>");
		if (previous) {
			memset(&inverse, 0, sizeof(inverse));
			inverse.kind = NCFG_OP_DNS_APPLY;
			inverse.u.dns.scope = scopes.items[i].name;
			inverse.u.dns.policy = previous;
			(void)ncfg_builder_push(builder, &op, &reason, NULL, 0, &inverse);
		} else {
			(void)ncfg_builder_push(builder, &op, &reason, NULL, 0, NULL);
		}
	}
	free(scopes.items);
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
