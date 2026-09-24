/*
 * scopes.c -- which scopes a machine has, given a document and an observation.
 *
 * WHY THIS IS NOT IN THE PLANNER, WHERE IT WAS WRITTEN
 *   It arrived as a static in `plan/host_wide.c`, because the planner was the
 *   only thing that had ever needed it, and that file's header said what the
 *   condition for moving it was: a second caller takes this one rather than
 *   writing a third. The daemon is the second caller -- `ncfg_service_t` wants
 *   every scope so that one `dns.apply` delivers all of them -- and the Rust
 *   records what happens when the two lists are built separately: the planner
 *   learned that a lease contributes nameservers and the executor went on
 *   reading the document alone, so the plan said `dns.apply` and the delivery
 *   wrote a `resolv.conf` with nothing in it.
 *
 * WHY IT OWNS AN ARENA AND THE PLANNER'S VERSION DID NOT
 *   The old one interned its merged policies into the plan, which is where its
 *   one caller kept everything else. A rule with two callers cannot borrow one
 *   caller's arena, so it has its own -- a list of blocks and one loop, which
 *   is `ncfg_plan_t`'s arrangement and is here for its reason: a policy is a
 *   struct with two re-allocated lists hanging off it, and a free walk per
 *   scope is a second list to keep in step with the struct.
 *
 *   The consequence is the sentence in `dns.h`: what comes back must outlive
 *   anything holding a scope from it. A plan holds them -- its `dns.apply` ops
 *   borrow the policies -- so `ncfg_plan_dns` adopts the whole object rather
 *   than copying out of it.
 *
 * WHAT IS DELIBERATELY NOT HERE
 *   Whether a delivery is worth making. "Every scope would deliver nothing"
 *   produces a plan warning and a decision about what to write, and both are
 *   the planner's: this answers what the scopes *are*, and `host_wide.c`
 *   decides what to do about them. The split is the one that lets the daemon
 *   ask the question without inheriting an opinion about plans.
 */
#include "ncfg/observed.h"

#include "ncfg/base.h"
#include "ncfg/value.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct ncfg_dns_scopes {
	ncfg_dns_scope_t *items;
	size_t            count;
	size_t            capacity;
	/* Every block the merges allocated: the policy copies, their two grown
	 * lists, and the canonical spelling of each reported server. */
	void            **owned;
	size_t            owned_count;
	size_t            owned_capacity;
};

/* ------------------------------------------------------------------------ *
 * The arena
 * ------------------------------------------------------------------------ */

/* Record one allocation as the list's, or free it and answer NULL. */
static void *keep(ncfg_dns_scopes_t *scopes, void *block)
{
	void **grown;
	size_t wanted;

	if (!block) {
		return NULL;
	}
	if (scopes->owned_count == scopes->owned_capacity) {
		wanted = scopes->owned_capacity ? scopes->owned_capacity * 2u : 16u;
		grown = realloc(scopes->owned, wanted * sizeof(*grown));
		if (!grown) {
			free(block);
			return NULL;
		}
		scopes->owned = grown;
		scopes->owned_capacity = wanted;
	}
	scopes->owned[scopes->owned_count++] = block;
	return block;
}

static const char *intern(ncfg_dns_scopes_t *scopes, const char *text)
{
	size_t length;
	char  *copy;

	if (!text) {
		return NULL;
	}
	length = strlen(text);
	copy = malloc(length + 1u);
	if (copy) {
		memcpy(copy, text, length + 1u);
	}
	return keep(scopes, copy);
}

static int scopes_push(ncfg_dns_scopes_t *scopes, const char *name,
    const ncfg_dns_policy_t *policy)
{
	ncfg_dns_scope_t *grown;
	size_t            wanted;

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

	if (!observed) {
		return NULL;
	}
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
 * **Canonical, and that is what makes the pass idempotent.** What an apply
 * delivered is folded into `owned.json` and comes back as `observed.dns`, and
 * the planner compares the two: a server carried through in whatever spelling
 * the report's author used would compare unequal against netcfgd's own record
 * of having delivered it, and `dns.apply` would be planned on every run.
 */
static const char *reported_server(ncfg_dns_scopes_t *scopes, const char *text)
{
	ncfg_address_t parsed;
	char           canonical[NCFG_ADDRESS_MAX];

	if (!text || !ncfg_address_parse(text, &parsed, NULL, 0) || parsed.has_prefix) {
		return NULL;
	}
	if (!ncfg_address_render(&parsed, canonical, sizeof(canonical), NULL, 0)) {
		return NULL;
	}
	return intern(scopes, canonical);
}

/* ------------------------------------------------------------------------ *
 * Building one scope
 * ------------------------------------------------------------------------ */

/*
 * A copy of `policy` with room for what a report is about to add.
 *
 * Only the two lists a merge appends to are re-allocated; everything else stays
 * exactly the borrow it was. A scope whose servers came straight off the
 * document never reaches here at all -- `build_scope` hands the document's
 * policy back -- so the copy exists precisely because these two lists are about
 * to be something neither the document nor the observation holds.
 */
static ncfg_dns_policy_t *policy_copy(ncfg_dns_scopes_t *scopes, const ncfg_dns_policy_t *policy,
    size_t extra_servers, size_t extra_search)
{
	ncfg_dns_policy_t *copy = calloc(1u, sizeof(*copy));
	size_t             servers;
	size_t             search;

	if (!keep(scopes, copy)) {
		return NULL;
	}
	if (policy) {
		*copy = *policy;
	}
	servers = copy->server_count + extra_servers;
	search = copy->search_count + extra_search;
	if (servers != 0u) {
		ncfg_dns_server_t *room = calloc(servers, sizeof(*room));

		if (!keep(scopes, room)) {
			return NULL;
		}
		if (copy->server_count != 0u) {
			memcpy(room, copy->servers, copy->server_count * sizeof(*room));
		}
		copy->servers = room;
	}
	if (search != 0u) {
		char **room = calloc(search, sizeof(*room));

		if (!keep(scopes, room)) {
			return NULL;
		}
		if (copy->search_count != 0u) {
			memcpy(room, copy->search, copy->search_count * sizeof(*room));
		}
		copy->search = room;
	}
	return copy;
}

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
 * ordinary case borrows exactly as `dns.h` says a scope does.
 */
static const ncfg_dns_policy_t *build_scope(ncfg_dns_scopes_t *scopes,
    const ncfg_dns_mode_value_t *host, const ncfg_dns_policy_t *base,
    const ncfg_observed_report_t *report)
{
	ncfg_dns_policy_t *copy;
	size_t             extra_servers = report ? report->nameserver_count : 0u;
	size_t             extra_search = report ? report->search_count : 0u;
	size_t             i;

	if (base && base->mode.mode != NCFG_DNS_MODE_NONE && !extra_servers && !extra_search) {
		return base;
	}
	copy = policy_copy(scopes, base, extra_servers, extra_search);
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
		const char *address = reported_server(scopes, report->nameservers[i]);

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

/* ------------------------------------------------------------------------ *
 * The rule
 * ------------------------------------------------------------------------ */

ncfg_dns_scopes_t *ncfg_dns_scopes_of(const ncfg_document_t *desired,
    const ncfg_observed_t *observed, char *err, size_t err_size)
{
	ncfg_dns_scopes_t *scopes;
	size_t             i;

	if (!desired) {
		ncfg_error_set(err, err_size, "there is no document to take DNS scopes from");
		return NULL;
	}
	scopes = calloc(1u, sizeof(*scopes));
	if (!scopes) {
		ncfg_error_set(err, err_size, "out of memory taking the DNS scopes");
		return NULL;
	}
	if (desired->globals.dns.mode.mode != NCFG_DNS_MODE_NONE) {
		if (!scopes_push(scopes, NCFG_DNS_GLOBAL_SCOPE, &desired->globals.dns)) {
			goto no_memory;
		}
	}
	for (i = 0; i < desired->interface_count; i++) {
		const ncfg_interface_t       *interface = &desired->interfaces[i];
		const ncfg_device_t          *device = ncfg_document_device(desired, interface->name);
		const ncfg_observed_report_t *report;
		const ncfg_dns_policy_t      *policy;
		int                           offers = 0;

		/*
		 * An unmanaged device contributes no scope. `dns.apply` is host-wide,
		 * so it names no interface and the planner's usual choke point does
		 * not see it -- this is where it has to be asked.
		 */
		if (device && !device->managed) {
			continue;
		}
		report = claimed(interface) ? report_for(observed, interface->name) : NULL;
		offers = report && (report->nameserver_count != 0u || report->search_count != 0u);
		if (!interface->dns) {
			/*
			 * Servers reported and nowhere to put them, because this host
			 * manages no DNS. Skipped rather than pushed with a `none` mode: a
			 * scope that delivers nothing is still an action in a plan, and an
			 * action that does nothing is one somebody reads and dismisses on
			 * every run.
			 */
			if (!offers || desired->globals.dns.mode.mode == NCFG_DNS_MODE_NONE) {
				continue;
			}
		} else if (!offers && policy_is_empty(interface->dns)) {
			/* `dns { }` with nothing in it asks for nothing, and a scope for
			 * it is an action that does nothing. */
			continue;
		}
		policy = build_scope(scopes, &desired->globals.dns.mode, interface->dns,
		    offers ? report : NULL);
		if (!policy || !scopes_push(scopes, interface->name, policy)) {
			goto no_memory;
		}
	}
	return scopes;

no_memory:
	ncfg_dns_scopes_free(scopes);
	ncfg_error_set(err, err_size, "out of memory taking the DNS scopes");
	return NULL;
}

const ncfg_dns_scope_t *ncfg_dns_scopes_items(const ncfg_dns_scopes_t *scopes, size_t *count)
{
	static const ncfg_dns_scope_t none;

	if (count) {
		*count = scopes ? scopes->count : 0u;
	}
	if (!scopes) {
		return NULL;
	}
	/*
	 * An empty list answers a pointer rather than NULL, which `dns.h`
	 * promises: a caller that took NULL for "could not be asked" would
	 * otherwise read a document managing no DNS as a failure. `items` is NULL
	 * until the first push, so the answer comes from a value with a place in
	 * memory and a count of zero beside it.
	 */
	return scopes->items ? scopes->items : &none;
}

void ncfg_dns_scopes_free(ncfg_dns_scopes_t *scopes)
{
	size_t i;

	if (!scopes) {
		return;
	}
	for (i = 0; i < scopes->owned_count; i++) {
		free(scopes->owned[i]);
	}
	free(scopes->owned);
	free(scopes->items);
	free(scopes);
}
