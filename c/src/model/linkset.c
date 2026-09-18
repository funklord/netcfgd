/*
 * linkset.c -- which member of a named set of links is in use.
 *
 * THE RULE, AND WHY IT IS THE ONE THE TREE ALREADY HAD
 *   Eligible members ranked by metric, lowest wins, ties broken by the order
 *   the document lists them in. A member is eligible when the link carrying it
 *   has carrier and has not failed a probe -- the same facts an interface's
 *   `preference` already acted on, now naming the group they act within, and
 *   in one place so that a set and a ranked interface cannot come to disagree
 *   about what "working" means. 0248.
 *
 * THE THREE WAYS TO GET IT WRONG, EACH WRITTEN DOWN WHERE IT HAPPENS
 *   * **An absent metric reads as 0, which is the strongest.** Writing a
 *     metric on one member demotes it against a member with none. That looks
 *     backwards and is the only answer that keeps the set and the kernel
 *     agreeing: an unnumbered route goes into the table at metric 0 too.
 *   * **`up` is not consulted.** It is netcfgd's own setting and a plan is
 *     usually in the middle of applying it, so a set that called a down link
 *     unusable would withhold every route on the first pass and install them
 *     on the second -- a machine that needs two applies to come up.
 *   * **Absent is not false for a probe.** A link nobody probed keeps its
 *     standing, which is what stops every set emptying on a machine that
 *     configured no probes at all.
 *
 * WHY THE CYCLE GUARD IS A LIST OF NAMES AND NOT A COUNTER
 *   The two answers differ: a chain eight sets deep is legal and rare, a set
 *   that names itself is a mistake, and only naming the sets already in
 *   progress can tell them apart. The depth bound is carried as well because
 *   the list alone would not stop a document that nests forever without ever
 *   repeating a name, and a document that arrives over the socket or out of
 *   `/run` has not necessarily been through the compiler -- which is where a
 *   cycle is actually diagnosed, with the way round printed. This is the model
 *   refusing to hang on one anyway.
 */
#include "ncfg/linkset.h"

#include "ncfg/base.h"

#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------------ *
 * The small pieces
 * ------------------------------------------------------------------------ */

/* Two names, either of which a reader may have left NULL. */
static int same_text(const char *left, const char *right)
{
	if (!left || !right) {
		return left == right;
	}
	return strcmp(left, right) == 0;
}

/*
 * Copy a string, or nothing where there was nothing.
 *
 * **Absent is not a failure here**, which is why this returns a flag rather
 * than the pointer: half the strings in a standing are legitimately NULL, and
 * a copier that answered NULL for both "nothing to copy" and "no memory" would
 * turn an allocation failure into a member that quietly has no interface.
 */
static int copy_text(const char *text, char **out)
{
	size_t length;
	char  *copy;

	*out = NULL;
	if (!text) {
		return 1;
	}
	length = strlen(text);
	copy = malloc(length + 1u);
	if (!copy) {
		return 0;
	}
	memcpy(copy, text, length + 1u);
	*out = copy;
	return 1;
}

/* Lower wins, and absent is 0 -- the kernel's own default and the strongest,
 * exactly as an unnumbered route is. */
static int64_t rank_of(const ncfg_standing_t *standing)
{
	return standing->metric.has ? standing->metric.value : 0;
}

static void refuse(ncfg_standing_t *standing, int reason)
{
	standing->ineligible.has = 1;
	standing->ineligible.value = reason;
}

const ncfg_linkset_t *ncfg_linkset_find(const ncfg_document_t *document, const char *name)
{
	size_t i;

	if (!document || !name) {
		return NULL;
	}
	for (i = 0; i < document->linkset_count; i++) {
		if (same_text(document->linksets[i].name, name)) {
			return &document->linksets[i];
		}
	}
	return NULL;
}

static const ncfg_wifi_network_t *find_network(const ncfg_document_t *document, const char *id)
{
	size_t i;

	if (!document || !id) {
		return NULL;
	}
	for (i = 0; i < document->network_count; i++) {
		if (same_text(document->networks[i].id, id)) {
			return &document->networks[i];
		}
	}
	return NULL;
}

static const ncfg_interface_t *find_interface(const ncfg_document_t *document, const char *name)
{
	size_t i;

	if (!document || !name) {
		return NULL;
	}
	for (i = 0; i < document->interface_count; i++) {
		if (same_text(document->interfaces[i].name, name)) {
			return &document->interfaces[i];
		}
	}
	return NULL;
}

/* The radio a configured network is associated with, or NULL where nothing is
 * on it -- which is the ordinary state of every saved network but one. */
static const ncfg_observed_link_t *link_on_network(const ncfg_observed_t *observed,
    const char *id)
{
	size_t i;

	if (!observed || !id) {
		return NULL;
	}
	for (i = 0; i < observed->link_count; i++) {
		if (same_text(observed->links[i].network, id)) {
			return &observed->links[i];
		}
	}
	return NULL;
}

/*
 * Whether a link can carry traffic, and what stops it where it cannot.
 *
 * Returns 1 and a reason, or 0 where the link is usable. The three facts an
 * interface's `preference` already acted on, in one place.
 */
static int unusable(const ncfg_observed_t *observed, const char *interface, int *reason_out)
{
	const ncfg_observed_link_t *link = ncfg_observed_link(observed, interface);

	if (!link) {
		return 0;
	}
	if (!link->carrier) {
		/* **A link that is down reads as this too**, deliberately: carrier is
		 * the fact about the world, and a link the operator disabled loses it
		 * as soon as it goes down. */
		*reason_out = NCFG_INELIGIBLE_NO_CARRIER;
		return 1;
	}
	/* Only an explicit refusal. Absent is "nobody asked" or "no answer yet",
	 * and treating that as unreachable would empty every set on a machine that
	 * configured no probes. */
	if (link->reachable.has && !link->reachable.value) {
		*reason_out = NCFG_INELIGIBLE_PROBE;
		return 1;
	}
	return 0;
}

/* ------------------------------------------------------------------------ *
 * Choosing
 * ------------------------------------------------------------------------ */

/*
 * The sets already being resolved, innermost last.
 *
 * Pointers into the document rather than copies: the document outlives the
 * call, the depth bound already limits how many there can be, and a guard that
 * had to allocate could fail to -- on the malformed document it exists for.
 *
 * **The array is exactly the bound, and the two are one fact.** It starts with
 * the set being asked about and is only pushed while `count` is below the
 * bound, so it can hold at most that many. A push moved out from under that
 * test would run off the end of this array, which is the one way this guard
 * could become the thing it protects against.
 */
typedef struct {
	const char *names[NCFG_LINKSET_MAX_DEPTH];
	size_t      count;
} within_t;

static int choose_within(const ncfg_document_t *document, const ncfg_observed_t *observed,
    const char *name, within_t *within, ncfg_chosen_t **chosen_out, char *err, size_t err_size);

/* A member that is another set: it stands wherever its own choice does. */
static int stand_on_set(const ncfg_document_t *document, const ncfg_observed_t *observed,
    const char *member, within_t *within, ncfg_standing_t *out, char *err, size_t err_size)
{
	ncfg_chosen_t         *inner = NULL;
	const ncfg_standing_t *winner = NULL;
	size_t                 i;
	int                    ok;

	for (i = 0; i < within->count; i++) {
		if (same_text(within->names[i], member)) {
			refuse(out, NCFG_INELIGIBLE_CYCLE);
			return 1;
		}
	}
	/* The bound, reported as a cycle as well: a chain this deep is either a
	 * cycle whose names do not repeat or a document nobody meant to write, and
	 * both are answered by stopping. */
	if (within->count >= NCFG_LINKSET_MAX_DEPTH) {
		refuse(out, NCFG_INELIGIBLE_CYCLE);
		return 1;
	}

	within->names[within->count++] = member;
	ok = choose_within(document, observed, member, within, &inner, err, err_size);
	within->count--;
	if (!ok) {
		return 0;
	}
	if (!inner) {
		/* The caller only reaches here having found the set, so this is the
		 * shape of the Rust rather than a case that arises. */
		refuse(out, NCFG_INELIGIBLE_ABSENT);
		return 1;
	}
	if (inner->active) {
		for (i = 0; i < inner->member_count; i++) {
			if (same_text(inner->members[i].name, inner->active)) {
				winner = &inner->members[i];
				break;
			}
		}
	}
	/* **The nested set's metric is its winner's**, not one of its own. A set
	 * has no metric to have: what it contributes to an outer set is whichever
	 * link it settled on, and that link's ranking is the one that should
	 * compete outside. */
	if (winner) {
		out->metric = winner->metric;
	} else {
		refuse(out, NCFG_INELIGIBLE_EMPTY);
	}
	if (!copy_text(inner->interface, &out->interface)) {
		ncfg_error_set(err, err_size, "out of memory choosing within `%s`", member);
		ncfg_chosen_free(inner);
		return 0;
	}
	ncfg_chosen_free(inner);
	return 1;
}

/* A member that is a `network` block: it stands on the radio that joined it. */
static int stand_on_network(const ncfg_document_t *document, const ncfg_observed_t *observed,
    const char *member, ncfg_standing_t *out, char *err, size_t err_size)
{
	const ncfg_wifi_network_t  *network = find_network(document, member);
	const ncfg_observed_link_t *link = link_on_network(observed, member);
	int                         reason = 0;

	if (network) {
		out->metric = network->metric;
	}
	if (!link) {
		/* Configured, nothing on it. The ordinary state of every saved network
		 * but one, and not a fault -- which is why it is told apart from a
		 * member that names nothing at all. */
		refuse(out, NCFG_INELIGIBLE_UNJOINED);
		return 1;
	}
	/* **The radio, not the network.** These are two different strings for one
	 * member, and every caller needs the second: the routes, the metric and
	 * the probe all live on the interface. */
	if (!copy_text(link->name, &out->interface)) {
		ncfg_error_set(err, err_size, "out of memory naming the radio on `%s`", member);
		return 0;
	}
	if (unusable(observed, link->name, &reason)) {
		refuse(out, reason);
	}
	return 1;
}

/* A member that is an interface: it stands on itself. */
static int stand_on_interface(const ncfg_document_t *document, const ncfg_observed_t *observed,
    const char *member, ncfg_standing_t *out, char *err, size_t err_size)
{
	const ncfg_interface_t *interface = find_interface(document, member);
	int                     reason = 0;

	if (interface) {
		out->metric = interface->preference;
	}
	if (!ncfg_observed_link(observed, member)) {
		/* A member the document names and neither the kernel nor the document
		 * has: a card that is out, a block that was deleted, a typo the
		 * compiler would have caught in a document it compiled. */
		refuse(out, NCFG_INELIGIBLE_ABSENT);
		return 1;
	}
	/* An interface carries itself; there is nothing else to name. */
	if (!copy_text(member, &out->interface)) {
		ncfg_error_set(err, err_size, "out of memory naming `%s`", member);
		return 0;
	}
	if (unusable(observed, member, &reason)) {
		refuse(out, reason);
	}
	return 1;
}

/* Where one member stands, whatever kind of thing it is. */
static int stand(const ncfg_document_t *document, const ncfg_observed_t *observed,
    const char *member, within_t *within, ncfg_standing_t *out, char *err, size_t err_size)
{
	memset(out, 0, sizeof(*out));
	if (!copy_text(member, &out->name)) {
		ncfg_error_set(err, err_size, "out of memory naming a linkset member");
		return 0;
	}
	/* A nested set first, because a set and an interface could in principle
	 * share a name and the set is the more specific thing to have written. */
	if (ncfg_linkset_find(document, member)) {
		return stand_on_set(document, observed, member, within, out, err, err_size);
	}
	if (find_network(document, member)) {
		return stand_on_network(document, observed, member, out, err, err_size);
	}
	return stand_on_interface(document, observed, member, out, err, err_size);
}

static int choose_within(const ncfg_document_t *document, const ncfg_observed_t *observed,
    const char *name, within_t *within, ncfg_chosen_t **chosen_out, char *err, size_t err_size)
{
	const ncfg_linkset_t  *set = ncfg_linkset_find(document, name);
	ncfg_chosen_t         *chosen;
	const ncfg_standing_t *best = NULL;
	size_t                 i;

	*chosen_out = NULL;
	if (!set) {
		return 1;
	}
	chosen = calloc(1u, sizeof(*chosen));
	if (!chosen) {
		ncfg_error_set(err, err_size, "out of memory choosing a member of `%s`", name);
		return 0;
	}
	if (!copy_text(set->name, &chosen->name)) {
		ncfg_error_set(err, err_size, "out of memory choosing a member of `%s`", name);
		ncfg_chosen_free(chosen);
		return 0;
	}
	if (set->member_count > 0u) {
		chosen->members = calloc(set->member_count, sizeof(*chosen->members));
		if (!chosen->members) {
			ncfg_error_set(err, err_size, "out of memory ranking the members of `%s`",
			    name);
			ncfg_chosen_free(chosen);
			return 0;
		}
		/* Counted before they are filled, so that a failure half way through
		 * frees what was built rather than leaking the rest of the array. The
		 * entries are zeroed, and freeing a zeroed standing is nothing. */
		chosen->member_count = set->member_count;
	}
	for (i = 0; i < set->member_count; i++) {
		if (!stand(document, observed, set->members[i], within, &chosen->members[i], err,
		    err_size)) {
			ncfg_chosen_free(chosen);
			return 0;
		}
	}

	/*
	 * Lowest metric wins, ties going to whichever the document listed first.
	 * The walk keeps the first of an equal pair rather than sorting the list,
	 * because the list is not sorted at all -- the winner is picked out of it
	 * and it keeps its declared order for the caller to display. **A ranked
	 * list, not a set**: a bond's members are interchangeable and get
	 * canonicalised, and these are the operator saying which of two equally
	 * ranked links they would rather be on.
	 */
	for (i = 0; i < chosen->member_count; i++) {
		const ncfg_standing_t *member = &chosen->members[i];

		if (member->ineligible.has) {
			continue;
		}
		if (!best || rank_of(member) < rank_of(best)) {
			best = member;
		}
	}
	if (best) {
		if (!copy_text(best->name, &chosen->active) ||
		    !copy_text(best->interface, &chosen->interface)) {
			ncfg_error_set(err, err_size, "out of memory naming the member `%s` settled on",
			    name);
			ncfg_chosen_free(chosen);
			return 0;
		}
	}
	*chosen_out = chosen;
	return 1;
}

int ncfg_linkset_choose(const ncfg_document_t *document, const ncfg_observed_t *observed,
    const char *name, ncfg_chosen_t **chosen_out, char *err, size_t err_size)
{
	within_t within;

	if (!chosen_out) {
		ncfg_error_set(err, err_size, "a linkset choice was asked for with nowhere to put it");
		return 0;
	}
	*chosen_out = NULL;
	if (!name) {
		return 1;
	}
	/* **The set being asked about counts as in progress**, or a set naming
	 * itself directly is reported as empty rather than as the cycle it is: the
	 * inner call refuses it correctly and the outer one would only see that
	 * nothing came back. */
	within.names[0] = name;
	within.count = 1u;
	return choose_within(document, observed, name, &within, chosen_out, err, err_size);
}

void ncfg_chosen_free(ncfg_chosen_t *chosen)
{
	size_t i;

	if (!chosen) {
		return;
	}
	for (i = 0; i < chosen->member_count; i++) {
		free(chosen->members[i].name);
		free(chosen->members[i].interface);
	}
	free(chosen->members);
	free(chosen->name);
	free(chosen->active);
	free(chosen->interface);
	free(chosen);
}

/* ------------------------------------------------------------------------ *
 * Which sets a link is in, under either of its names
 * ------------------------------------------------------------------------ */

void ncfg_linkset_names_free(char **names, size_t count)
{
	size_t i;

	if (!names) {
		return;
	}
	for (i = 0; i < count; i++) {
		free(names[i]);
	}
	free(names);
}

int ncfg_linkset_sets_containing(const ncfg_document_t *document,
    const ncfg_observed_t *observed, const char *link, char ***names_out, size_t *count_out,
    char *err, size_t err_size)
{
	char **names;
	size_t count = 0;
	size_t i;

	if (!names_out || !count_out) {
		ncfg_error_set(err, err_size, "the sets a link is in were asked for with nowhere to "
		    "put them");
		return 0;
	}
	*names_out = NULL;
	*count_out = 0;
	if (!document || !link || document->linkset_count == 0u) {
		return 1;
	}
	names = calloc(document->linkset_count, sizeof(*names));
	if (!names) {
		ncfg_error_set(err, err_size, "out of memory listing the sets `%s` is in", link);
		return 0;
	}
	for (i = 0; i < document->linkset_count; i++) {
		const ncfg_linkset_t *set = &document->linksets[i];
		int                   member = 0;
		size_t                j;

		for (j = 0; j < set->member_count && !member; j++) {
			const ncfg_observed_link_t *carrier;

			if (same_text(set->members[j], link)) {
				member = 1;
				break;
			}
			/* **Both spellings.** A wifi member is named by its `network`
			 * block and carried by a radio, so the radio is in the set too --
			 * and a caller holding an interface must not have to join the two
			 * lists itself, which is how two callers come to disagree. */
			carrier = link_on_network(observed, set->members[j]);
			if (carrier && same_text(carrier->name, link)) {
				member = 1;
			}
		}
		if (!member) {
			continue;
		}
		if (!copy_text(set->name, &names[count])) {
			ncfg_error_set(err, err_size, "out of memory listing the sets `%s` is in", link);
			ncfg_linkset_names_free(names, count);
			return 0;
		}
		count++;
	}
	if (count == 0u) {
		/* Nothing rather than an empty allocation, so that a caller who frees
		 * only what it was given has nothing to free. */
		free(names);
		return 1;
	}
	*names_out = names;
	*count_out = count;
	return 1;
}
