/*
 * canonical.c -- canonicalisation and validation.
 *
 * THE GUARANTEE THIS FILE EXISTS TO PROVIDE
 *   One logical document has exactly one byte sequence. Plan diffs and caching
 *   are only trustworthy if that holds, so it is tested rather than asserted.
 *   Sorting is by the key the schema names -- interfaces by name, networks by
 *   id, WireGuard peers by name -- **never by insertion order**, which depends
 *   on which drop-in file happened to be read first.
 *
 * WHY THE SORT IS STABLE, AND WHY IT IS NOT `qsort`
 *   Rust's `sort_by` is stable and several of the sorts here are by a key that
 *   is not the whole value -- peers by name, devices by name. Where two
 *   entries share a key, a stable sort leaves them in the order the document
 *   had them and an unstable one leaves them in whatever order the algorithm
 *   happened to produce, which can differ between two runs on the same input.
 *   That is exactly the byte-identical guarantee above, lost quietly. The
 *   lists here are tens of entries, so an insertion sort is the whole of it.
 *
 * WHAT VALIDATION REFUSES
 *   Each check names the thing that was wrong specifically enough to fix, in
 *   the sentence `netcfgd-model`'s `Error` already prints: "invalid document"
 *   is not a diagnostic. The one that is not obvious is the DNS capability
 *   check, and its comment has the config it used to refuse.
 */
#include "ncfg/document.h"

#include "ncfg/base.h"

#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------------ *
 * A stable sort, and the comparisons the schema names
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

			/* Strictly greater, which is what keeps this stable: two
			 * entries with an equal key are never swapped. */
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

static int compare_flag(int left, int right)
{
	return (left ? 1 : 0) - (right ? 1 : 0);
}

/*
 * Two addresses as `IpAddr` compares them, and not as text.
 *
 * IPv4 before IPv6, then the octets -- which is the derived order on Rust's
 * enum and is not the order the strings are in: `9.0.0.1` sorts before
 * `10.0.0.1` as an address and after it as a string. A route list sorted the
 * other way would be canonical here and not canonical there, which is the
 * whole property this file exists for.
 */
static int compare_address(const char *left, const char *right)
{
	ncfg_address_t one;
	ncfg_address_t other;
	int            difference;

	if (!left || !right) {
		return (left ? 1 : 0) - (right ? 1 : 0);
	}
	if (!ncfg_address_parse(left, &one, NULL, 0) ||
	    !ncfg_address_parse(right, &other, NULL, 0)) {
		return strcmp(left, right);
	}
	if (one.is_ipv6 != other.is_ipv6) {
		return one.is_ipv6 ? 1 : -1;
	}
	difference = memcmp(one.bytes, other.bytes, one.is_ipv6 ? 16u : 4u);
	if (difference != 0) {
		return difference;
	}
	if (one.has_prefix != other.has_prefix) {
		return one.has_prefix ? 1 : -1;
	}
	if (one.prefix != other.prefix) {
		return one.prefix < other.prefix ? -1 : 1;
	}
	return 0;
}

static int compare_strings(const void *left, const void *right)
{
	return compare_text(*(char *const *)left, *(char *const *)right);
}

static int compare_device(const void *left, const void *right)
{
	return compare_text(((const ncfg_device_t *)left)->name,
	    ((const ncfg_device_t *)right)->name);
}

static int compare_interface(const void *left, const void *right)
{
	return compare_text(((const ncfg_interface_t *)left)->name,
	    ((const ncfg_interface_t *)right)->name);
}

static int compare_network(const void *left, const void *right)
{
	return compare_text(((const ncfg_wifi_network_t *)left)->id,
	    ((const ncfg_wifi_network_t *)right)->id);
}

static int compare_bluetooth(const void *left, const void *right)
{
	return compare_text(((const ncfg_bluetooth_device_t *)left)->id,
	    ((const ncfg_bluetooth_device_t *)right)->id);
}

static int compare_access_point(const void *left, const void *right)
{
	return compare_text(((const ncfg_access_point_t *)left)->id,
	    ((const ncfg_access_point_t *)right)->id);
}

static int compare_linkset(const void *left, const void *right)
{
	return compare_text(((const ncfg_linkset_t *)left)->name,
	    ((const ncfg_linkset_t *)right)->name);
}

static int compare_peer(const void *left, const void *right)
{
	return compare_text(((const ncfg_wg_peer_t *)left)->name,
	    ((const ncfg_wg_peer_t *)right)->name);
}

/*
 * Rules in the order the kernel consults them, then by everything else so that
 * two rules at one priority still have one canonical order.
 *
 * The family is compared **by its word** and not by the enum, because that is
 * what `RoutingRule::cmp` does. The two agree today -- `inet` before `inet6`
 * either way -- and a variant inserted in the middle of the enum would part
 * them, which is the kind of difference that shows up as a document that two
 * builds canonicalise differently.
 */
static int compare_rule(const void *left, const void *right)
{
	const ncfg_routing_rule_t *one = left;
	const ncfg_routing_rule_t *other = right;

	if (one->priority != other->priority) {
		return one->priority < other->priority ? -1 : 1;
	}
	{
		const char *first = ncfg_rule_family_name((ncfg_rule_family_t)one->family);
		const char *second = ncfg_rule_family_name((ncfg_rule_family_t)other->family);
		int         difference = compare_text(first, second);

		if (difference != 0) {
			return difference;
		}
	}
	return compare_text(one->id, other->id);
}

/* The derived `Ord` on `Route`, which follows the field declaration order. */
static int compare_route(const void *left, const void *right)
{
	const ncfg_route_t *one = left;
	const ncfg_route_t *other = right;
	int                 difference;

	difference = compare_text(one->destination, other->destination);
	if (difference != 0) {
		return difference;
	}
	difference = compare_address(one->via, other->via);
	if (difference != 0) {
		return difference;
	}
	difference = compare_optint(&one->metric, &other->metric);
	if (difference != 0) {
		return difference;
	}
	difference = compare_optint(&one->table, &other->table);
	if (difference != 0) {
		return difference;
	}
	difference = compare_address(one->src, other->src);
	if (difference != 0) {
		return difference;
	}
	difference = compare_optint(&one->scope, &other->scope);
	if (difference != 0) {
		return difference;
	}
	difference = compare_flag(one->onlink, other->onlink);
	if (difference != 0) {
		return difference;
	}
	return compare_optint(&one->proto, &other->proto);
}

/* The derived `Ord` on `HookRef`: the phase first, which is the declaration
 * order of the phases and so the order they run in. */
static int compare_hook(const void *left, const void *right)
{
	const ncfg_hook_ref_t *one = left;
	const ncfg_hook_ref_t *other = right;
	int                    difference;

	if (one->phase != other->phase) {
		return one->phase < other->phase ? -1 : 1;
	}
	difference = compare_text(one->path, other->path);
	if (difference != 0) {
		return difference;
	}
	difference = compare_text(one->sha256, other->sha256);
	if (difference != 0) {
		return difference;
	}
	difference = compare_text(one->run_as, other->run_as);
	if (difference != 0) {
		return difference;
	}
	return compare_optint(&one->timeout, &other->timeout);
}

static int compare_bridge_vlan(const void *left, const void *right)
{
	const ncfg_bridge_vlan_t *one = left;
	const ncfg_bridge_vlan_t *other = right;
	int                       difference;

	if (one->vid != other->vid) {
		return one->vid < other->vid ? -1 : 1;
	}
	difference = compare_flag(one->pvid, other->pvid);
	if (difference != 0) {
		return difference;
	}
	return compare_flag(one->untagged, other->untagged);
}

static int compare_prefix_ref(const void *left, const void *right)
{
	const ncfg_prefix_ref_t *one = left;
	const ncfg_prefix_ref_t *other = right;
	int                      difference = compare_text(one->source, other->source);

	if (difference != 0) {
		return difference;
	}
	if (one->index != other->index) {
		return one->index < other->index ? -1 : 1;
	}
	if (one->subnet != other->subnet) {
		return one->subnet < other->subnet ? -1 : 1;
	}
	return 0;
}

static int compare_dns_server(const void *left, const void *right)
{
	const ncfg_dns_server_t *one = left;
	const ncfg_dns_server_t *other = right;
	int                      difference = compare_address(one->addr, other->addr);

	if (difference != 0) {
		return difference;
	}
	difference = compare_optint(&one->port, &other->port);
	if (difference != 0) {
		return difference;
	}
	return compare_text(one->sni, other->sni);
}

static int compare_routing_domain(const void *left, const void *right)
{
	const ncfg_routing_domain_t *one = left;
	const ncfg_routing_domain_t *other = right;
	int                          difference = compare_text(one->suffix, other->suffix);

	if (difference != 0) {
		return difference;
	}
	return compare_flag(one->exclusive, other->exclusive);
}

/* ------------------------------------------------------------------------ *
 * Canonicalisation
 * ------------------------------------------------------------------------ */

static void canonicalize_dns(ncfg_dns_policy_t *dns)
{
	if (!dns) {
		return;
	}
	stable_sort(dns->servers, dns->server_count, sizeof(*dns->servers), compare_dns_server);
	stable_sort(dns->domains, dns->domain_count, sizeof(*dns->domains), compare_routing_domain);
	/*
	 * `search` and `options` are ordered by the author and stay that way:
	 * resolver search order is semantic, so sorting them would change what the
	 * config means rather than normalise how it is written.
	 */
}

void ncfg_document_canonicalize(ncfg_document_t *document)
{
	size_t i;

	if (!document) {
		return;
	}
	stable_sort(document->devices, document->device_count, sizeof(*document->devices),
	    compare_device);
	stable_sort(document->interfaces, document->interface_count, sizeof(*document->interfaces),
	    compare_interface);
	stable_sort(document->networks, document->network_count, sizeof(*document->networks),
	    compare_network);
	/*
	 * **Sorted for the same reason the others are, and missed for as long as
	 * the field existed.** It went unnoticed because the document's equality
	 * omitted `bluetooth` as well: with neither walk covering it, order could
	 * not produce a spurious difference because no difference was visible at
	 * all. Two documents differing only in a Bluetooth device compared EQUAL,
	 * the reconciler saw no change to apply, and `ncfg profile save` accepted
	 * a snapshot that did not reproduce the machine. Fixing equality is what
	 * made this line reachable.
	 */
	stable_sort(document->bluetooth, document->bluetooth_count, sizeof(*document->bluetooth),
	    compare_bluetooth);
	stable_sort(document->rules, document->rule_count, sizeof(*document->rules), compare_rule);
	stable_sort(document->access_points, document->access_point_count,
	    sizeof(*document->access_points), compare_access_point);
	/*
	 * The sets themselves sort by name; **their members deliberately do not.**
	 * A bridge's or a bond's members are a set and get sorted into canonical
	 * order below; a linkset's are a ranked list, and sorting them would
	 * silently rewrite which of two equally ranked links an operator said they
	 * would rather be on.
	 */
	stable_sort(document->linksets, document->linkset_count, sizeof(*document->linksets),
	    compare_linkset);

	for (i = 0; i < document->access_point_count; i++) {
		ncfg_access_control_t *acl = document->access_points[i].access_control;
		size_t                 kept;
		size_t                 at;

		if (!acl) {
			continue;
		}
		/*
		 * A station list is a set. Two operators writing the same stations in
		 * a different order mean the same access point, and an unsorted list
		 * would give them different document hashes and so a spurious change
		 * to reconcile.
		 */
		stable_sort(acl->stations, acl->station_count, sizeof(*acl->stations), compare_strings);
		kept = acl->station_count ? 1u : 0u;
		for (at = 1u; at < acl->station_count; at++) {
			if (compare_text(acl->stations[kept - 1u], acl->stations[at]) == 0) {
				free(acl->stations[at]);
				acl->stations[at] = NULL;
				continue;
			}
			acl->stations[kept++] = acl->stations[at];
		}
		acl->station_count = kept;
	}

	/* The device half of what used to be one loop: `kind` and `bridge_vlans`
	 * describe the hardware and moved with it (0155 pass 1b). */
	for (i = 0; i < document->device_count; i++) {
		ncfg_device_t *device = &document->devices[i];
		size_t         peer;

		stable_sort(device->bridge_vlans, device->bridge_vlan_count,
		    sizeof(*device->bridge_vlans), compare_bridge_vlan);
		switch (device->kind.kind) {
		case NCFG_KIND_WIREGUARD:
			stable_sort(device->kind.wireguard.peers, device->kind.wireguard.peer_count,
			    sizeof(*device->kind.wireguard.peers), compare_peer);
			for (peer = 0; peer < device->kind.wireguard.peer_count; peer++) {
				ncfg_wg_peer_t *entry = &device->kind.wireguard.peers[peer];

				stable_sort(entry->allowed_ips, entry->allowed_ip_count,
				    sizeof(*entry->allowed_ips), compare_strings);
			}
			break;
		case NCFG_KIND_BRIDGE:
			stable_sort(device->kind.bridge.members, device->kind.bridge.member_count,
			    sizeof(*device->kind.bridge.members), compare_strings);
			break;
		case NCFG_KIND_BOND:
			stable_sort(device->kind.bond.members, device->kind.bond.member_count,
			    sizeof(*device->kind.bond.members), compare_strings);
			break;
		default:
			break;
		}
	}

	for (i = 0; i < document->interface_count; i++) {
		ncfg_interface_t *interface = &document->interfaces[i];

		stable_sort(interface->routes, interface->route_count, sizeof(*interface->routes),
		    compare_route);
		stable_sort(interface->hooks, interface->hook_count, sizeof(*interface->hooks),
		    compare_hook);
		canonicalize_dns(interface->dns);
		if (interface->advertise) {
			stable_sort(interface->advertise->prefixes, interface->advertise->prefix_count,
			    sizeof(*interface->advertise->prefixes), compare_prefix_ref);
		}
	}

	for (i = 0; i < document->network_count; i++) {
		ncfg_wifi_network_t *network = &document->networks[i];

		stable_sort(network->routes, network->route_count, sizeof(*network->routes),
		    compare_route);
		stable_sort(network->hooks, network->hook_count, sizeof(*network->hooks), compare_hook);
		canonicalize_dns(network->dns);
	}

	canonicalize_dns(&document->globals.dns);
}

/* ------------------------------------------------------------------------ *
 * Validation
 * ------------------------------------------------------------------------ */

static int check_unique(const char *collection, const char *const *keys, size_t count,
    char *err, size_t err_size)
{
	size_t i;
	size_t j;

	for (i = 0; i < count; i++) {
		for (j = 0; j < i; j++) {
			if (compare_text(keys[i], keys[j]) == 0) {
				ncfg_error_set(err, err_size, "duplicate %s entry: %s", collection,
				    keys[i] ? keys[i] : "");
				return 0;
			}
		}
	}
	return 1;
}

/* Reject an entry that repeats a source which may appear at most once. */
static int check_multiplicity(const char *scope, const ncfg_address_source_t *sources,
    size_t count, char *err, size_t err_size)
{
	size_t i;
	size_t j;

	for (i = 0; i < count; i++) {
		if (!ncfg_address_source_is_singleton(sources[i].kind)) {
			continue;
		}
		for (j = 0; j < i; j++) {
			if (sources[j].kind != sources[i].kind) {
				continue;
			}
			ncfg_error_set(err, err_size,
			    "interface %s names %s more than once; at most one is allowed", scope,
			    ncfg_address_source_kind_name(sources[i].kind));
			return 0;
		}
	}
	return 1;
}

/*
 * Decision 0007's capability check, asked of the mode that will actually
 * deliver this scope.
 *
 * **The mode is not a per-interface choice**, and this used to be asked as
 * though it were. A scope states one only to override, so a document with
 * `dns_mode = "dnsmasq"` in globals and `domains = [..]` on an interface was
 * refused with "mode none cannot express routing domains" -- naming a mode
 * nobody wrote and no delivery would use, for a config that is the recommended
 * way to split DNS down a tunnel. The only way past it was to repeat the mode
 * in every interface block, which is a second place for the host's resolver to
 * be stated and disagree.
 */
static int check_dns_capability(const char *scope, const ncfg_dns_policy_t *dns, int host_mode,
    char *err, size_t err_size)
{
	int effective;

	if (!dns) {
		return 1;
	}
	effective = dns->mode.mode == NCFG_DNS_MODE_NONE ? host_mode : dns->mode.mode;
	if (ncfg_dns_policy_needs_routing(dns) && !ncfg_dns_mode_can_route(effective)) {
		ncfg_error_set(err, err_size,
		    "dns scope %s uses routing domains, which mode %s cannot express", scope,
		    ncfg_dns_mode_name((ncfg_dns_mode_t)effective));
		return 0;
	}
	return 1;
}

static int check_hooks(const ncfg_hook_ref_t *hooks, size_t count, char *err, size_t err_size)
{
	size_t i;

	for (i = 0; i < count; i++) {
		/*
		 * A hook is materialised under `/run` and executed, and a relative
		 * path would be resolved against whatever directory the daemon
		 * happens to be in. Refused here so that the document cannot describe
		 * a script nobody can point at.
		 */
		if (!hooks[i].path || hooks[i].path[0] != '/') {
			ncfg_error_set(err, err_size, "hook path %s is not absolute",
			    hooks[i].path ? hooks[i].path : "");
			return 0;
		}
	}
	return 1;
}

int ncfg_document_validate(const ncfg_document_t *document, char *err, size_t err_size)
{
	const char **keys = NULL;
	size_t       most;
	size_t       i;
	int          host_mode;

	if (!document) {
		ncfg_error_set(err, err_size, "no document");
		return 0;
	}
	if (document->schema_version.major != NCFG_SCHEMA_MAJOR) {
		ncfg_error_set(err, err_size,
		    "document schema %lld.%lld is not readable by this build, which speaks %d.%d",
		    (long long)document->schema_version.major,
		    (long long)document->schema_version.minor, NCFG_SCHEMA_MAJOR, NCFG_SCHEMA_MINOR);
		return 0;
	}

	most = document->device_count;
	if (document->interface_count > most) {
		most = document->interface_count;
	}
	if (document->network_count > most) {
		most = document->network_count;
	}
	if (most) {
		keys = calloc(most, sizeof(*keys));
		if (!keys) {
			ncfg_error_set(err, err_size, "out of memory checking a document");
			return 0;
		}
	}
	for (i = 0; i < document->device_count; i++) {
		keys[i] = document->devices[i].name;
	}
	if (!check_unique("device", keys, document->device_count, err, err_size)) {
		free(keys);
		return 0;
	}
	for (i = 0; i < document->interface_count; i++) {
		keys[i] = document->interfaces[i].name;
	}
	if (!check_unique("interface", keys, document->interface_count, err, err_size)) {
		free(keys);
		return 0;
	}
	for (i = 0; i < document->network_count; i++) {
		keys[i] = document->networks[i].id;
	}
	if (!check_unique("network", keys, document->network_count, err, err_size)) {
		free(keys);
		return 0;
	}
	free(keys);

	host_mode = document->globals.dns.mode.mode;
	if (!check_dns_capability("globals", &document->globals.dns, host_mode, err, err_size)) {
		return 0;
	}

	for (i = 0; i < document->interface_count; i++) {
		const ncfg_interface_t *interface = &document->interfaces[i];

		if (!check_multiplicity(interface->name, interface->addressing,
		    interface->addressing_count, err, err_size)) {
			return 0;
		}
		if (!check_dns_capability(interface->name, interface->dns, host_mode, err, err_size)) {
			return 0;
		}
		if (!check_hooks(interface->hooks, interface->hook_count, err, err_size)) {
			return 0;
		}
	}

	for (i = 0; i < document->network_count; i++) {
		const ncfg_wifi_network_t *network = &document->networks[i];

		if (!check_multiplicity(network->id, network->addressing, network->addressing_count,
		    err, err_size)) {
			return 0;
		}
		if (!check_dns_capability(network->id, network->dns, host_mode, err, err_size)) {
			return 0;
		}
		if (!check_hooks(network->hooks, network->hook_count, err, err_size)) {
			return 0;
		}
	}
	return 1;
}
