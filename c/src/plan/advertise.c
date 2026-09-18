/*
 * advertise.c -- what an interface tells the hosts behind it.
 *
 * WHERE THIS SITS IN THE ORDER
 *   Not a prerequisite and not an addressing source: a LAN with a static
 *   address and an `advertise` block gets both. It waits on the addressing
 *   rather than racing it, because a router that advertises a prefix it does
 *   not itself hold is advertising a route to nowhere -- and because the
 *   prefix being advertised is very often the one the addressing just derived
 *   from a delegation.
 *
 * WHY NOTHING IS PLANNED UNTIL A PREFIX RESOLVES
 *   An action that must fail, planned before the one that would make it
 *   succeed, stops the apply and takes the rest with it -- and here the rest is
 *   the DHCPv6 client on the *other* interface, the one whose delegation this
 *   is waiting for, so the router would never have come up at all. So a policy
 *   whose every prefix reference resolves to nothing is a sentence naming the
 *   sources it is waiting on, and no action.
 *
 * WHY A RUNNING DAEMON IS NOT NECESSARILY A CORRECT ONE
 *   The prefix is the one value here that arrives after the document does, so
 *   an ISP that renumbers leaves a daemon announcing a block the upstream has
 *   taken back: every host on the LAN then holds an address that does not
 *   route, and nothing in the document changed to say so. radvd re-reads its
 *   configuration on `SIGHUP`, so that is a reload and not a restart -- unlike
 *   an access point (0026), nothing on the wire is disturbed by it.
 *
 * WHERE THIS DIFFERS FROM `plan_advertising` IN THE RUST
 *   The two prefix lists are compared as the single space-joined string each
 *   reason already renders, rather than element by element. No address
 *   contains a space, so the two questions have the same answer, and the
 *   comparison is then made of exactly the text an operator is shown -- a
 *   difference that did not show up in the sentence would be a plan nobody
 *   could read.
 */
#include "plan_internal.h"

#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/value.h"

#include <string.h>

/* `observed.h`'s, now that the daemon resolves the same references to fill an
 * executor's `advertising`. Kept as a name here so the pass below reads as it
 * did, and so the one place this file could disagree with the daemon about
 * what a router announces does not exist. */
static int resolve(const ncfg_builder_t *builder, const ncfg_prefix_ref_t *reference, char *out,
    size_t out_size)
{
	return ncfg_observed_prefix_of(builder->observed, reference, out, out_size);
}

/* Whether any of the policy's references names a delegation that has arrived
 * and carries the index it asks for. The arithmetic below it is deliberately
 * not part of the question: a suffix that cannot be carved out is a
 * configuration fault rather than something to wait for, and `radvd` started
 * with the prefixes that did resolve is the Rust's answer too. */
static int resolvable(const ncfg_builder_t *builder, const ncfg_ra_policy_t *policy)
{
	size_t i;

	for (i = 0; i < policy->prefix_count; i++) {
		const ncfg_delegation_t *delegation =
		    ncfg_observed_delegation(builder->observed, policy->prefixes[i].source);

		if (delegation && policy->prefixes[i].index >= 0 &&
		    (uint64_t)policy->prefixes[i].index < (uint64_t)delegation->prefix_count) {
			return 1;
		}
	}
	return 0;
}

/* The running router advertisement daemon on this interface, or NULL. One that
 * has told netcfgd nothing about what it is announcing is not one this can
 * compare against: an empty list would read as "announcing nothing" and plan a
 * reload on every reconcile. */
static const ncfg_observed_backend_t *running_daemon(const ncfg_observed_t *observed,
    const char *name)
{
	size_t i;

	for (i = 0; i < observed->backend_count; i++) {
		const ncfg_observed_backend_t *backend = &observed->backends[i];

		if (backend->kind != NCFG_BACKEND_ROUTER_ADVERT || !backend->running) {
			continue;
		}
		if (!backend->interface || !name || strcmp(backend->interface, name) != 0) {
			continue;
		}
		if (backend->advertised_count == 0u) {
			return NULL;
		}
		return backend;
	}
	return NULL;
}

static void join(ncfg_buf_t *buf, const char *text)
{
	if (buf->length != 0u) {
		ncfg_buf_add_char(buf, ' ');
	}
	ncfg_buf_add_text(buf, text);
}

void ncfg_plan_advertise(ncfg_builder_t *builder, const ncfg_interface_t *interface,
    const ncfg_plan_ids_t *base, const ncfg_plan_ids_t *addressing)
{
	const ncfg_ra_policy_t        *policy = interface->advertise;
	const ncfg_observed_backend_t *running;
	ncfg_plan_ids_t                deps = { NULL, 0, 0 };
	ncfg_plan_ids_t                started = { NULL, 0, 0 };
	ncfg_buf_t                     wanted;
	ncfg_buf_t                     announced;
	ncfg_op_t                      op;
	ncfg_reason_t                  reason;
	size_t                         i;

	if (!policy) {
		return;
	}
	if (!resolvable(builder, policy)) {
		ncfg_buf_t sources;

		ncfg_buf_init(&sources, 0);
		for (i = 0; i < policy->prefix_count; i++) {
			if (sources.length != 0u) {
				ncfg_buf_add_text(&sources, ", ");
			}
			ncfg_buf_add_text(&sources,
			    policy->prefixes[i].source ? policy->prefixes[i].source : "<absent>");
		}
		if (ncfg_buf_failed(&sources)) {
			builder->plan->failed = 1;
		} else {
			ncfg_plan_warnf(builder->plan, interface->name,
			    "waiting on a delegated prefix from %s before advertising",
			    ncfg_buf_text(&sources));
		}
		ncfg_buf_free(&sources);
		return;
	}

	ncfg_plan_ids_extend(builder->plan, &deps, base);
	ncfg_plan_ids_extend(builder->plan, &deps, addressing);
	ncfg_plan_backend(builder, interface->name, NCFG_BACKEND_ROUTER_ADVERT, "advertise", &deps,
	    &started);
	ncfg_plan_ids_free(&deps);
	ncfg_plan_ids_free(&started);

	running = running_daemon(builder->observed, interface->name);
	if (!running) {
		return;
	}
	ncfg_buf_init(&wanted, 0);
	ncfg_buf_init(&announced, 0);
	for (i = 0; i < policy->prefix_count; i++) {
		char prefix[NCFG_ADDRESS_MAX];

		if (resolve(builder, &policy->prefixes[i], prefix, sizeof(prefix))) {
			join(&wanted, prefix);
		}
	}
	for (i = 0; i < running->advertised_count; i++) {
		join(&announced, running->advertised[i] ? running->advertised[i] : "<absent>");
	}
	if (ncfg_buf_failed(&wanted) || ncfg_buf_failed(&announced)) {
		builder->plan->failed = 1;
	} else if (strcmp(ncfg_buf_text(&wanted), ncfg_buf_text(&announced)) != 0) {
		memset(&op, 0, sizeof(op));
		op.kind = NCFG_OP_BACKEND_RELOAD;
		op.u.backend.kind = NCFG_BACKEND_ROUTER_ADVERT;
		op.u.backend.iface = interface->name;
		reason = ncfg_plan_reason_differs(interface->name, "advertise.prefixes",
		    ncfg_plan_intern(builder->plan, ncfg_buf_text(&wanted)),
		    ncfg_plan_intern(builder->plan, ncfg_buf_text(&announced)));
		/*
		 * No inverse. What the daemon was announcing before is the machine's
		 * and not the document's, so a revert re-plans against the last-good
		 * document and hands it over again -- the arrangement
		 * `wifi.set_profiles` takes for the same reason.
		 */
		(void)ncfg_builder_push(builder, &op, &reason, NULL, 0, NULL);
	}
	ncfg_buf_free(&wanted);
	ncfg_buf_free(&announced);
}
