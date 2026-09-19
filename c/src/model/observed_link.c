/*
 * observed_link.c -- canonicalisation, and the questions an observation is
 * asked.
 *
 * WHY THE SORT IS STABLE, AND WHY IT IS NOT `qsort`
 *   `canonical.c` states this for the document and it holds here word for
 *   word: Rust's `sort_by` is stable and every sort below is by a key that is
 *   not the whole value -- links by name, backends by interface and kind.
 *   Where two entries share a key, a stable sort leaves them in the order the
 *   observation had them and an unstable one leaves them in whatever order the
 *   algorithm happened to produce, which can differ between two runs on the
 *   same input. That is the byte-identical guarantee, lost quietly.
 *
 * WHY ONLY FIVE LISTS SORT
 *   `Observed::canonicalize` sorts links, addresses, routes, backends and the
 *   DNS scopes, and nothing else. The rest are already in an order somebody
 *   chose -- a linkset's members are the document's ranking, a report's
 *   addresses are the order the far end offered them -- and sorting one of
 *   those here would be this port deciding something the Rust does not.
 *
 * WHAT A FILTER CANNOT BE BUILT FROM
 *   `ncfg_link_category_of` exists because the kernel reports an empty kind
 *   for every real network card. Measured on the reporting machine:
 *
 *       enp0s31f6   kind=""           wireless=false
 *       wlp0s20f3   kind=""           wireless=true
 *       lo          kind=""           wireless=false
 *       docker0     kind="bridge"     wireless=false
 *       wg-test     kind="wireguard"  wireless=false
 *
 *   Three of those five are indistinguishable by kind, so a dropdown offering
 *   "ethernet" built on it would show the radio. **Here rather than in a
 *   client, before there are four of them**: a dropdown in the Qt window, a
 *   filter in the text interface and a column in the TDE module would be three
 *   rules, and the one that is wrong would be wrong quietly -- a link in no
 *   category is a row that simply does not appear.
 */
#include "ncfg/observed.h"

#include "ncfg/value.h"

#include "ncfg/base.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------------ *
 * A stable sort, and the comparisons the Rust names
 * ------------------------------------------------------------------------ */

typedef int (*compare_t)(const void *left, const void *right);

static void swap_bytes(char *left, char *right, size_t size)
{
	size_t i;

	for (i = 0; i < size; i++) {
		char held = left[i];

		left[i] = right[i];
		right[i] = held;
	}
}

static void stable_sort(void *base, size_t count, size_t size, compare_t compare)
{
	char  *items = base;
	size_t i;

	for (i = 1; i < count; i++) {
		size_t j;

		for (j = i; j > 0; j--) {
			char *earlier = items + (j - 1u) * size;
			char *later = items + j * size;

			/* Strictly greater, which is what keeps this stable: two entries
			 * with an equal key are never swapped. */
			if (compare(earlier, later) <= 0) {
				break;
			}
			swap_bytes(earlier, later, size);
		}
	}
}

static int compare_text(const char *left, const char *right)
{
	if (!left || !right) {
		return (left ? 1 : 0) - (right ? 1 : 0);
	}
	return strcmp(left, right);
}

/* `Option<T>`: absent sorts before present, as `None` does in Rust. */
static int compare_optint(const ncfg_optint_t *left, const ncfg_optint_t *right)
{
	if (left->has != right->has) {
		return left->has ? 1 : -1;
	}
	if (!left->has || left->value == right->value) {
		return 0;
	}
	return left->value < right->value ? -1 : 1;
}

static int compare_links(const void *left, const void *right)
{
	const ncfg_observed_link_t *one = left;
	const ncfg_observed_link_t *other = right;

	return compare_text(one->name, other->name);
}

static int compare_addresses(const void *left, const void *right)
{
	const ncfg_observed_address_t *one = left;
	const ncfg_observed_address_t *other = right;
	int                            difference = compare_text(one->interface, other->interface);

	if (difference != 0) {
		return difference;
	}
	/*
	 * **The address as text, and not as an address.** A document's routes sort
	 * the other way -- `canonical.c` parses them, because the Rust holds them
	 * as `IpAddr` there -- and an observation holds this one as a `String`, so
	 * `9.0.0.1` sorts after `10.0.0.1` here and before it there. Copying the
	 * document's comparison across would be canonical in this port and not
	 * canonical in the Rust.
	 */
	return compare_text(one->address, other->address);
}

static int compare_routes(const void *left, const void *right)
{
	const ncfg_observed_route_t *one = left;
	const ncfg_observed_route_t *other = right;
	int                          difference = compare_text(one->interface, other->interface);

	if (difference != 0) {
		return difference;
	}
	difference = compare_text(one->destination, other->destination);
	if (difference != 0) {
		return difference;
	}
	return compare_optint(&one->metric, &other->metric);
}

static int compare_backends(const void *left, const void *right)
{
	const ncfg_observed_backend_t *one = left;
	const ncfg_observed_backend_t *other = right;
	int                            difference = compare_text(one->interface, other->interface);

	if (difference != 0) {
		return difference;
	}
	/* The kind by its declaration order, which is what Rust's derived `Ord`
	 * compares and is not the alphabetical order of the words. */
	return one->kind - other->kind;
}

static int compare_dns(const void *left, const void *right)
{
	const ncfg_applied_dns_t *one = left;
	const ncfg_applied_dns_t *other = right;

	return compare_text(one->scope, other->scope);
}

void ncfg_observed_canonicalize(ncfg_observed_t *observed)
{
	if (!observed) {
		return;
	}
	stable_sort(observed->links, observed->link_count, sizeof(*observed->links), compare_links);
	stable_sort(observed->addresses, observed->address_count, sizeof(*observed->addresses),
	    compare_addresses);
	stable_sort(observed->routes, observed->route_count, sizeof(*observed->routes),
	    compare_routes);
	stable_sort(observed->backends, observed->backend_count, sizeof(*observed->backends),
	    compare_backends);
	stable_sort(observed->dns, observed->dns_count, sizeof(*observed->dns), compare_dns);
}

/* ------------------------------------------------------------------------ *
 * Ownership, and the one decision that may remove something
 * ------------------------------------------------------------------------ */

int ncfg_ownership_may_remove(int ownership)
{
	return ownership == NCFG_OWNERSHIP_OURS;
}

/* ------------------------------------------------------------------------ *
 * Words a column uses that are not the words the JSON carries
 * ------------------------------------------------------------------------ */

/*
 * **Deliberately not the wire spellings.** `no_carrier` is the JSON member's
 * value and `no carrier` is what a status line says, and the two must not be
 * one table: a reader that took its words from this function would accept
 * `probe failed` in a file, which the Rust refuses. The JSON set lives beside
 * the tables in `observed.c`, where nothing renders from it.
 */
const char *ncfg_ineligible_name(int reason)
{
	switch (reason) {
	case NCFG_INELIGIBLE_ABSENT:
		return "absent";
	case NCFG_INELIGIBLE_UNJOINED:
		return "unjoined";
	case NCFG_INELIGIBLE_NO_CARRIER:
		return "no carrier";
	case NCFG_INELIGIBLE_PROBE:
		return "probe failed";
	case NCFG_INELIGIBLE_EMPTY:
		return "empty";
	case NCFG_INELIGIBLE_CYCLE:
		return "cycle";
	default:
		/* value.h's rule: a plausible word for a value that is not one is
		 * worse than no word. */
		return NULL;
	}
}

/* ------------------------------------------------------------------------ *
 * An rfkill switch, and the sentence that says what would clear it
 * ------------------------------------------------------------------------ */

int ncfg_rfkill_blocked(const ncfg_observed_rfkill_t *rfkill)
{
	return rfkill && (rfkill->soft || rfkill->hard);
}

char *ncfg_rfkill_remedy(const ncfg_observed_rfkill_t *rfkill, char *out, size_t out_size)
{
	const char *at;
	int         written;

	if (!rfkill || !out || out_size == 0u) {
		return NULL;
	}
	at = rfkill->switch_ ? rfkill->switch_ : "an unnamed switch";
	/*
	 * **The two blocks have different answers and saying the wrong one wastes
	 * somebody's evening.** A soft block is software and one command clears
	 * it; a hard block is a slider or a firmware button and nothing in
	 * software will move it, so telling a person to run a command is telling
	 * them to do something that cannot work.
	 */
	if (rfkill->hard) {
		written = snprintf(out, out_size,
		    "the radio is switched off at %s by a hardware switch -- the button or slider "
		    "on the machine, which nothing in software can clear", at);
	} else {
		written = snprintf(out, out_size,
		    "the radio is switched off at %s in software, which `rfkill unblock wifi` "
		    "clears", at);
	}
	/* Half a sentence that still looks like one is the failure `ncfg_buf_t`
	 * refuses for a document, and it is refused here for the same reason. */
	if (written < 0 || (size_t)written >= out_size) {
		out[0] = '\0';
		return NULL;
	}
	return out;
}

/* ------------------------------------------------------------------------ *
 * The questions an observation is asked
 * ------------------------------------------------------------------------ */

int ncfg_connectivity_connected(const ncfg_connectivity_t *connectivity)
{
	/* True from `routed` up. Derived here rather than left to each caller so
	 * that "connected" means one thing across the tray, the shim and the text
	 * interface -- which is how the middle rung got lost the first time. */
	return connectivity && connectivity->rung >= NCFG_RUNG_ROUTED;
}

char *const *ncfg_observed_access_control_list(const ncfg_observed_access_control_t *control,
    int policy, size_t *count_out)
{
	if (count_out) {
		*count_out = 0;
	}
	if (!control) {
		return NULL;
	}
	if (policy == NCFG_ACL_POLICY_DENY) {
		if (count_out) {
			*count_out = control->denied_count;
		}
		return control->denied;
	}
	if (policy == NCFG_ACL_POLICY_ALLOW) {
		if (count_out) {
			*count_out = control->accepted_count;
		}
		return control->accepted;
	}
	return NULL;
}

const ncfg_observed_link_t *ncfg_observed_link(const ncfg_observed_t *observed, const char *name)
{
	size_t i;

	if (!observed || !name) {
		return NULL;
	}
	for (i = 0; i < observed->link_count; i++) {
		if (compare_text(observed->links[i].name, name) == 0) {
			return &observed->links[i];
		}
	}
	return NULL;
}

const ncfg_delegation_t *ncfg_observed_delegation(const ncfg_observed_t *observed,
    const char *interface)
{
	size_t i;

	if (!observed || !interface) {
		return NULL;
	}
	for (i = 0; i < observed->delegation_count; i++) {
		if (compare_text(observed->delegations[i].interface, interface) == 0) {
			return &observed->delegations[i];
		}
	}
	return NULL;
}

int ncfg_observed_prefix_of(const ncfg_observed_t *observed, const ncfg_prefix_ref_t *reference,
    char *out, size_t out_size)
{
	const ncfg_delegation_t *delegation;

	if (!reference || !out || out_size == 0u) {
		return 0;
	}
	out[0] = '\0';
	delegation = ncfg_observed_delegation(observed, reference->source);
	if (!delegation) {
		return 0;
	}
	if (reference->index < 0 ||
	    (uint64_t)reference->index >= (uint64_t)delegation->prefix_count) {
		return 0;
	}
	/*
	 * `::/64` as the suffix, so what comes back is the block and not a host in
	 * it. The sentence a failure would carry is dropped on purpose: the two
	 * callers want "did this resolve", and the one that owes the operator an
	 * explanation is the planner, which says it about the reference rather
	 * than about the arithmetic.
	 */
	return ncfg_address_from_delegation(delegation->prefixes[(size_t)reference->index],
	    reference->subnet, "::/64", out, out_size, NULL, 0);
}

ncfg_optint_t ncfg_observed_effective_metric(const ncfg_document_t *desired,
    const ncfg_observed_t *observed, const ncfg_interface_t *interface)
{
	ncfg_optint_t               none;
	const ncfg_observed_link_t *link;
	size_t                      i;

	memset(&none, 0, sizeof(none));
	if (!interface) {
		return none;
	}
	link = observed ? ncfg_observed_link(observed, interface->name) : NULL;
	for (i = 0; desired && link && link->network && i < desired->network_count; i++) {
		if (!desired->networks[i].id ||
		    strcmp(desired->networks[i].id, link->network) != 0) {
			continue;
		}
		/*
		 * Falls back rather than replacing: a network with no metric of its
		 * own leaves the preference exactly as it was. `break` and not
		 * `return`, so the one network that matched decides and a later id
		 * cannot.
		 */
		if (desired->networks[i].metric.has) {
			return desired->networks[i].metric;
		}
		break;
	}
	return interface->preference;
}

const ncfg_dns_policy_t *ncfg_observed_dns_for(const ncfg_observed_t *observed,
    const char *scope)
{
	size_t i;

	if (!observed || !scope) {
		return NULL;
	}
	for (i = 0; i < observed->dns_count; i++) {
		if (compare_text(observed->dns[i].scope, scope) == 0) {
			return &observed->dns[i].policy;
		}
	}
	return NULL;
}

int ncfg_observed_has_dhcp_lease(const ncfg_observed_t *observed, const char *interface)
{
	size_t i;

	if (!observed || !interface) {
		return 0;
	}
	for (i = 0; i < observed->route_count; i++) {
		const ncfg_observed_route_t *route = &observed->routes[i];

		/* **The route and not the address.** `IFA_PROTO` arrived in Linux 5.18
		 * and is absent on plenty of running kernels: measured here, a DHCP
		 * address came back with no proto while its route said 16. */
		if (compare_text(route->interface, interface) == 0 && route->proto.has &&
		    route->proto.value == NCFG_DHCP_ROUTE_PROTO) {
			return 1;
		}
	}
	return 0;
}

int64_t ncfg_observed_backend_restarts(const ncfg_observed_t *observed, int kind,
    const char *interface)
{
	size_t i;

	if (!observed || !interface) {
		return 0;
	}
	for (i = 0; i < observed->backend_restart_count; i++) {
		const ncfg_backend_restart_t *entry = &observed->backend_restarts[i];

		if (entry->kind == kind && compare_text(entry->interface, interface) == 0) {
			return entry->count;
		}
	}
	return 0;
}

int ncfg_observed_backend_running(const ncfg_observed_t *observed, int kind,
    const char *interface)
{
	size_t i;

	if (!observed || !interface) {
		return 0;
	}
	for (i = 0; i < observed->backend_count; i++) {
		const ncfg_observed_backend_t *backend = &observed->backends[i];

		if (backend->kind == kind && backend->running &&
		    compare_text(backend->interface, interface) == 0) {
			return 1;
		}
	}
	return 0;
}

/* ------------------------------------------------------------------------ *
 * Presence, and the third answer
 * ------------------------------------------------------------------------ */

int ncfg_presence_of_interface(const char *name, const ncfg_observed_t *observed)
{
	/* **Two-valued, and that asymmetry is the whole rule.** The kernel's link
	 * table is complete, so an interface netcfgd cannot find is one that does
	 * not exist: there is no question it was unable to ask. */
	return ncfg_observed_link(observed, name) ? NCFG_PRESENCE_PRESENT : NCFG_PRESENCE_ABSENT;
}

int ncfg_presence_of_network(int hidden, int associated, int seen_has, int seen)
{
	if (associated) {
		/* The strongest evidence there is, and it outranks a stale scan. */
		return NCFG_PRESENCE_PRESENT;
	}
	/* **A hidden network is unknown even when a scan has been read.** A hidden
	 * access point beacons with an empty name, so a scan cannot name it and
	 * "not in the scan" is not evidence of absence -- treating it as evidence
	 * would report a network that is right there as gone. */
	if (hidden) {
		return NCFG_PRESENCE_UNKNOWN;
	}
	if (!seen_has) {
		/* Nobody looked. Not the same as looking and finding nothing, which is
		 * the distinction every optional boolean in this tree is about. */
		return NCFG_PRESENCE_UNKNOWN;
	}
	return seen ? NCFG_PRESENCE_PRESENT : NCFG_PRESENCE_ABSENT;
}

/* ------------------------------------------------------------------------ *
 * What kind of thing a link is
 * ------------------------------------------------------------------------ */

/* The loopback, which no `kind` distinguishes from a wired card. */
static const char *const loopback_name = "lo";

/* Whether the document gives this link's device a modem policy. */
static int is_modem(const ncfg_observed_link_t *link, const ncfg_document_t *document)
{
	size_t i;

	for (i = 0; i < document->device_count; i++) {
		if (document->devices[i].modem &&
		    compare_text(document->devices[i].name, link->name) == 0) {
			return 1;
		}
	}
	return 0;
}

int ncfg_link_category_of(const ncfg_observed_link_t *link, const ncfg_document_t *document)
{
	/* An absent kind and an empty one are the same thing to this rule: the
	 * Rust holds a `String` that defaults to empty, and C holds a pointer that
	 * may not have been filled in. */
	const char *kind;

	if (!link) {
		return NCFG_LINK_CATEGORY_OTHER;
	}
	kind = link->kind ? link->kind : "";
	/* **The document first, because it knows something the link does not.** A
	 * modem's link is an ordinary one to the kernel -- often `ppp` or a plain
	 * card -- so asking `kind` first would classify it as something else and
	 * never reach here. */
	if (document && is_modem(link, document)) {
		return NCFG_LINK_CATEGORY_MODEM;
	}
	if (compare_text(link->name, loopback_name) == 0) {
		return NCFG_LINK_CATEGORY_LOOPBACK;
	}
	/* Before the kind check: a radio reports an empty kind like every other
	 * real card, so the flag is the only thing that separates them. */
	if (link->wireless) {
		return NCFG_LINK_CATEGORY_WIFI;
	}
	/* An empty kind is what the kernel reports for a real network card, and by
	 * here it is not loopback and not a radio. */
	if (strcmp(kind, "") == 0 || strcmp(kind, "ether") == 0) {
		return NCFG_LINK_CATEGORY_ETHERNET;
	}
	if (strcmp(kind, "bridge") == 0) {
		return NCFG_LINK_CATEGORY_BRIDGE;
	}
	if (strcmp(kind, "bond") == 0) {
		return NCFG_LINK_CATEGORY_BOND;
	}
	if (strcmp(kind, "vlan") == 0 || strcmp(kind, "macvlan") == 0 ||
	    strcmp(kind, "macvtap") == 0) {
		return NCFG_LINK_CATEGORY_VLAN;
	}
	if (strcmp(kind, "wireguard") == 0) {
		return NCFG_LINK_CATEGORY_WIREGUARD;
	}
	if (strcmp(kind, "gre") == 0 || strcmp(kind, "gretap") == 0 ||
	    strcmp(kind, "ip6gre") == 0 || strcmp(kind, "ip6tnl") == 0 ||
	    strcmp(kind, "ipip") == 0 || strcmp(kind, "sit") == 0 ||
	    strcmp(kind, "vxlan") == 0 || strcmp(kind, "tun") == 0 || strcmp(kind, "tap") == 0 ||
	    strcmp(kind, "ppp") == 0 || strcmp(kind, "vti") == 0 || strcmp(kind, "vti6") == 0) {
		return NCFG_LINK_CATEGORY_TUNNEL;
	}
	if (strcmp(kind, "veth") == 0 || strcmp(kind, "dummy") == 0 || strcmp(kind, "ifb") == 0 ||
	    strcmp(kind, "vrf") == 0) {
		return NCFG_LINK_CATEGORY_VIRTUAL;
	}
	/* **Not an error and not empty.** A kernel gains link kinds faster than
	 * this list does, and a row in no category vanishes from every filtered
	 * list -- the failure that would be hardest to notice. */
	return NCFG_LINK_CATEGORY_OTHER;
}
