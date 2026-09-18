/*
 * derive.c -- the answers that are computed from an observation rather than
 * read off the machine.
 *
 * Four of them: which category each link falls into, the inventory a client
 * shows, what each linkset settled on, and how far this machine got. All are
 * functions of the links, the addresses, the routes, the probe verdicts and the
 * document, and nothing else -- which is what makes running them twice safe and
 * is why the daemon does.
 *
 * WHY THE VERDICT IS HERE AND NOT IN EACH CLIENT
 *   **Four clients were deriving it and no two agreed.** The Qt tray computed
 *   three rungs from the links, the TDE tray transcribed the same rule into
 *   TQt3, the NetworkManager shim answered a coarser pair and the text
 *   interface had no notion of it at all -- so each invented a slightly
 *   different verdict from one observation. The rule is not obvious, which is
 *   why copying it was expensive: associating is not addressing and addressing
 *   is not routing, and the middle rung exists because the icon used to lie.
 *
 * WHERE THIS FILE SITS RELATIVE TO THE RUST
 *   `connectivity::overall` is `netcfgd-model`'s and belongs there. The C model
 *   has not grown it and `derive` cannot be ported without it, so it is here
 *   under the name it would have in the model -- see observe.h's divergence
 *   list. Everything else in this file is `host::derive`.
 */
#include "ncfg/observe.h"

#include "ncfg/linkset.h"

#include "observe_internal.h"

#include <stdlib.h>
#include <string.h>

/* The loopback, which is never what anybody means by connected.
 *
 * Not in the ignore list and not overridable, because it is not a policy
 * question: a machine talking to itself is the definition of not being on a
 * network, on every machine there has ever been. */
static const char *const loopback = "lo";

/* What a default route's destination is spelled as, which is the model's word
 * rather than `0.0.0.0/0`. */
static const char *const default_route = "default";

/* ------------------------------------------------------------------------ *
 * Which links count
 * ------------------------------------------------------------------------ */

/*
 * Whether a name is covered by one pattern, where a trailing `*` is a prefix.
 *
 * **A bare `*` would match everything, including the link the machine is
 * actually on.** Refused rather than honoured: a document that ignores every
 * link is asking for a verdict that cannot be computed, and silently answering
 * "offline" for ever is the worst way to tell it so.
 */
static int pattern_matches(const char *pattern, const char *name)
{
	size_t length;

	if (!pattern || !name) {
		return 0;
	}
	length = strlen(pattern);
	if (length > 0u && pattern[length - 1u] == '*') {
		if (length == 1u) {
			return 0;
		}
		return strncmp(pattern, name, length - 1u) == 0;
	}
	return strcmp(pattern, name) == 0;
}

/*
 * Whether a link counts towards the verdict at all.
 *
 * **Down links do not, and that is separate from the ignore list.** The list is
 * for interfaces that are up and still not the operator's network; one that is
 * administratively down is not carrying anything for anybody, and no document
 * should have to say so. Measured on a machine with docker installed, where
 * `docker0` is down and holds `172.17.0.1/16` -- both trays counted every
 * addressed interface that was not `lo`, so a wired-only machine with no
 * network at all drew the amber icon and named a bridge to nowhere.
 */
static int link_counts(const ncfg_observed_link_t *link, const char *const *ignore,
    size_t ignore_count)
{
	size_t at;

	if (!link || !link->name || strcmp(link->name, loopback) == 0 || !link->up) {
		return 0;
	}
	for (at = 0; at < ignore_count; at++) {
		if (pattern_matches(ignore[at], link->name)) {
			return 0;
		}
	}
	return 1;
}

static const ncfg_observed_link_t *link_named(const ncfg_observed_t *observed, const char *name)
{
	return ncfg_observed_link(observed, name);
}

static int interface_counts(const ncfg_observed_t *observed, const char *name,
    const char *const *ignore, size_t ignore_count)
{
	return link_counts(link_named(observed, name), ignore, ignore_count);
}

/* ------------------------------------------------------------------------ *
 * The verdict
 * ------------------------------------------------------------------------ */

static int64_t route_metric(const ncfg_observed_route_t *route)
{
	/* A route with no metric reads as 0, the kernel's own default and the
	 * strongest -- which is also what an unnumbered route goes into the
	 * table at, so a ranking that read absence as weakest would choose one
	 * link while the routing table used the other. */
	return route->metric.has ? route->metric.value : 0;
}

/*
 * How the probe verdict moves the rung.
 *
 * **Present-and-false and absent are different answers**, which is the rule a
 * link's `reachable` states: a link nobody probed keeps its standing, and only
 * an explicit refusal takes it away. Asking for a probe does not invent a
 * refusal either -- a machine with none stops at `routed`, which is a working
 * icon and not a permanent red one.
 */
static int rung_for_probe(int requires_, ncfg_optbool_t probe)
{
	if (requires_ == NCFG_REQUIRES_PROBE && probe.has) {
		return probe.value ? NCFG_RUNG_ONLINE : NCFG_RUNG_LOCAL;
	}
	return NCFG_RUNG_ROUTED;
}

static ncfg_optbool_t probe_of(const ncfg_observed_link_t *link)
{
	ncfg_optbool_t none = { 0, 0 };

	return link ? link->reachable : none;
}

static int has_address_on(const ncfg_observed_t *observed, const char *interface)
{
	size_t at;

	for (at = 0; at < observed->address_count; at++) {
		if (observed->addresses[at].interface && interface &&
		    strcmp(observed->addresses[at].interface, interface) == 0) {
			return 1;
		}
	}
	return 0;
}

static int has_default_route_on(const ncfg_observed_t *observed, const char *interface)
{
	size_t at;

	for (at = 0; at < observed->route_count; at++) {
		const ncfg_observed_route_t *route = &observed->routes[at];

		if (route->destination && strcmp(route->destination, default_route) == 0 &&
		    route->interface && interface &&
		    strcmp(route->interface, interface) == 0) {
			return 1;
		}
	}
	return 0;
}

/* The verdict, with a primary built from `interface` and `label`. */
static int verdict(int rung, const char *interface, const char *label, int wireless,
    ncfg_connectivity_t **out, char *err, size_t err_size)
{
	ncfg_connectivity_t *answer = calloc(1, sizeof(*answer));

	*out = NULL;
	if (!answer) {
		ncfg_error_set(err, err_size, "out of memory deciding connectivity");
		return 0;
	}
	answer->rung = rung;
	if (interface) {
		answer->primary = calloc(1, sizeof(*answer->primary));
		if (!answer->primary) {
			free(answer);
			ncfg_error_set(err, err_size, "out of memory deciding connectivity");
			return 0;
		}
		answer->primary->interface = observe_dup(interface);
		answer->primary->label = observe_dup(label ? label : interface);
		answer->primary->wireless = wireless;
		if (!answer->primary->interface || !answer->primary->label) {
			free(answer->primary->interface);
			free(answer->primary->label);
			free(answer->primary);
			free(answer);
			ncfg_error_set(err, err_size, "out of memory deciding connectivity");
			return 0;
		}
	}
	*out = answer;
	return 1;
}

/*
 * The verdict as the `uplink` set sees it.
 *
 * The same ladder as below, asked about one link instead of about the machine:
 * the set has already decided which link that is, and asking again here would
 * be the fifth copy of a rule this file exists to have one of.
 */
static int through(const ncfg_observed_t *observed, int requires_, const ncfg_chosen_t *uplink,
    ncfg_connectivity_t **out, char *err, size_t err_size)
{
	const ncfg_observed_link_t *link;
	int                         routed;
	int                         addressed;
	int                         rung;

	if (!uplink->interface) {
		size_t at;

		/* The set has nothing usable. **Not "offline" by definition**: a
		 * member may still hold an address -- a cable into a switch with
		 * no uplink of its own does -- and the middle rung is exactly
		 * the state where a machine is configured and reaching
		 * nothing. */
		addressed = 0;
		for (at = 0; at < uplink->member_count && !addressed; at++) {
			addressed = uplink->members[at].interface &&
			    has_address_on(observed, uplink->members[at].interface);
		}
		return verdict(addressed ? NCFG_RUNG_LOCAL : NCFG_RUNG_OFFLINE, NULL, NULL, 0, out,
		    err, err_size);
	}
	link = link_named(observed, uplink->interface);
	routed = has_default_route_on(observed, uplink->interface);
	addressed = has_address_on(observed, uplink->interface);
	if (routed || (addressed && requires_ == NCFG_REQUIRES_ADDRESS)) {
		rung = rung_for_probe(requires_, probe_of(link));
	} else if (addressed) {
		rung = NCFG_RUNG_LOCAL;
	} else {
		rung = NCFG_RUNG_OFFLINE;
	}
	if (rung == NCFG_RUNG_OFFLINE) {
		return verdict(rung, NULL, NULL, 0, out, err, err_size);
	}
	/* **The set's own word for the member**: a `network` block's id where
	 * the member is a wifi network, an interface's name where it is an
	 * interface, and the inner set's name where it is a nested set -- which
	 * is the name the operator wrote in the set and so the one they will
	 * recognise in a tray. */
	return verdict(rung, uplink->interface, uplink->active ? uplink->active : uplink->interface,
	    link ? link->wireless : 0, out, err, err_size);
}

int ncfg_connectivity_overall(const ncfg_observed_t *observed,
    const ncfg_connectivity_policy_t *policy, ncfg_connectivity_t **out, char *err,
    size_t err_size)
{
	const char *const           *ignore = ncfg_connectivity_default_ignore;
	size_t                       ignore_count = ncfg_connectivity_default_ignore_count;
	int                          requires_ = NCFG_REQUIRES_ROUTE;
	const ncfg_observed_route_t *best = NULL;
	const ncfg_observed_link_t  *link;
	int                          addressed = 0;
	size_t                       at;

	if (!observed || !out) {
		ncfg_error_set(err, err_size, "there is no observation to judge");
		return 0;
	}
	*out = NULL;
	if (policy) {
		requires_ = policy->requires_;
		ignore = (const char *const *)policy->ignore;
		ignore_count = policy->ignore_count;
	}
	/* **Where the document declares an `uplink` set, that set is the
	 * answer.** A machine whose operator said which links carry its traffic
	 * has said what "connected" means on it, and a verdict assembled from
	 * every other link would contradict the thing they wrote down. */
	for (at = 0; at < observed->linkset_count; at++) {
		if (observed->linksets[at].name &&
		    strcmp(observed->linksets[at].name, NCFG_LINKSET_UPLINK) == 0) {
			return through(observed, requires_, &observed->linksets[at], out, err,
			    err_size);
		}
	}
	/* The best default route on a link that counts, where best is the lowest
	 * metric, ties going to the interface that sorts first. */
	for (at = 0; at < observed->route_count; at++) {
		const ncfg_observed_route_t *route = &observed->routes[at];

		if (!route->destination || strcmp(route->destination, default_route) != 0 ||
		    !route->interface ||
		    !interface_counts(observed, route->interface, ignore, ignore_count)) {
			continue;
		}
		if (!best || route_metric(route) < route_metric(best) ||
		    (route_metric(route) == route_metric(best) &&
		    strcmp(route->interface, best->interface) < 0)) {
			best = route;
		}
	}
	for (at = 0; at < observed->address_count && !addressed; at++) {
		addressed = observed->addresses[at].interface &&
		    interface_counts(observed, observed->addresses[at].interface, ignore,
		    ignore_count);
	}
	if (!best) {
		/* Nothing is carrying traffic, so there is no main link to name
		 * even where something holds an address. */
		int rung = NCFG_RUNG_OFFLINE;

		if (addressed) {
			rung = NCFG_RUNG_LOCAL;
			if (requires_ == NCFG_REQUIRES_ADDRESS) {
				rung = NCFG_RUNG_ROUTED;
			}
		}
		return verdict(rung, NULL, NULL, 0, out, err, err_size);
	}
	link = link_named(observed, best->interface);
	if (!link) {
		return verdict(rung_for_probe(requires_, probe_of(link)), NULL, NULL, 0, out, err,
		    err_size);
	}
	/* The `network` block's id where the radio is on one, because that is
	 * the name an operator recognises and the same string `ncfg wifi status`
	 * prints. */
	return verdict(rung_for_probe(requires_, probe_of(link)), link->name,
	    link->network ? link->network : link->name, link->wireless, out, err, err_size);
}

/* ------------------------------------------------------------------------ *
 * Everything derived, in the order the inputs allow
 * ------------------------------------------------------------------------ */

/*
 * Release a list of choices the previous pass left.
 *
 * Handed to an empty observation rather than freed field by field, because the
 * only code that knows how to take a `ncfg_chosen_t` apart is `ncfg_chosen_free`
 * and the model's own table -- and a second copy of either here would be a
 * second thing to keep in step. This is the same arrangement
 * `ncfg_observe_prior_free` uses.
 */
static void drop_linksets(ncfg_observed_t *observed)
{
	ncfg_observed_t *carrier;

	if (!observed->linksets) {
		return;
	}
	carrier = ncfg_observed_new(NULL, 0);
	if (!carrier) {
		return;
	}
	carrier->linksets = observed->linksets;
	carrier->linkset_count = observed->linkset_count;
	ncfg_observed_free(carrier);
	observed->linksets = NULL;
	observed->linkset_count = 0;
}

static int derive_linksets(ncfg_observed_t *observed, const ncfg_document_t *document, char *err,
    size_t err_size)
{
	size_t at;

	drop_linksets(observed);
	if (!document || document->linkset_count == 0) {
		return 1;
	}
	observed->linksets = calloc(document->linkset_count, sizeof(*observed->linksets));
	if (!observed->linksets) {
		ncfg_error_set(err, err_size, "out of memory choosing a link");
		return 0;
	}
	for (at = 0; at < document->linkset_count; at++) {
		ncfg_chosen_t *chosen = NULL;

		if (!ncfg_linkset_choose(document, observed, document->linksets[at].name, &chosen,
		    err, err_size)) {
			return 0;
		}
		if (!chosen) {
			continue;
		}
		/* The choice is moved rather than copied: the container is this
		 * module's to release and everything inside it belongs to the
		 * observation from here on. */
		observed->linksets[observed->linkset_count] = *chosen;
		observed->linkset_count++;
		free(chosen);
	}
	return 1;
}

int ncfg_observe_derive(ncfg_observed_t *observed, const ncfg_document_t *document, char *err,
    size_t err_size)
{
	ncfg_connectivity_t *connectivity = NULL;
	size_t               at;

	if (!observed) {
		ncfg_error_set(err, err_size, "there is no observation to derive from");
		return 0;
	}
	/* One rule, so the Qt window's filter, the text interface and the TDE
	 * module cannot each invent one. */
	for (at = 0; at < observed->link_count; at++) {
		observed->links[at].category.has = 1;
		observed->links[at].category.value =
		    ncfg_link_category_of(&observed->links[at], document);
	}
	/* After the categories, which it reads, and after whatever put a radio's
	 * network on its link -- which is what decides whether a configured
	 * network counts as associated. */
	ncfg_link_inventory_free(observed->inventory, observed->inventory_count);
	observed->inventory = NULL;
	observed->inventory_count = 0;
	if (!ncfg_link_inventory(document, observed, &observed->inventory,
	    &observed->inventory_count, err, err_size)) {
		return 0;
	}
	/* **Before the verdict, which reads it.** Where the document declares an
	 * `uplink` set, that set is what "connected" means, so the choice has to
	 * be made before the verdict asks -- and it is made once, here, rather
	 * than by each client, because two programs working out a failover
	 * separately is two programs that can disagree about which link this
	 * machine is on. */
	if (!derive_linksets(observed, document, err, err_size)) {
		return 0;
	}
	if (!ncfg_connectivity_overall(observed, document ? &document->globals.connectivity : NULL,
	    &connectivity, err, err_size)) {
		return 0;
	}
	if (observed->connectivity) {
		if (observed->connectivity->primary) {
			free(observed->connectivity->primary->interface);
			free(observed->connectivity->primary->label);
			free(observed->connectivity->primary);
		}
		free(observed->connectivity);
	}
	observed->connectivity = connectivity;
	return 1;
}
