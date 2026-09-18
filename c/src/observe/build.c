/*
 * build.c -- a kernel snapshot and a record of what netcfgd did, as one
 * observation.
 *
 * WHY THIS FILE HAS NO FILE HANDLE AND NO SOCKET IN IT
 *   The ownership policy decided here is the one that can delete somebody's
 *   address, so it has to be testable against synthetic dumps -- no kernel, no
 *   privilege, no network namespace, and above all not the machine the
 *   developer is sitting at. The one thing it reads is `/sys/class/net/<name>`
 *   through radio.h's predicate, whose root is a parameter for exactly this
 *   reason.
 *
 * WHAT IS DELIBERATELY LEFT ABSENT HERE
 *   `reachable` and `probe_detail`, because the observer reads the kernel and
 *   no probe result comes from there -- leaving them absent is what makes an
 *   unprobed link keep its routes. `category`, the inventory, the linkset
 *   choices and the connectivity verdict, because they are derived and one of
 *   their inputs arrives after this runs (see `ncfg_observe_derive`). And
 *   every field `augment` fills, because a netlink dump has never heard of a
 *   sysctl.
 */
#include "ncfg/observe.h"

#include "observe_internal.h"

#include <linux/fib_rules.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

/* ------------------------------------------------------------------------ *
 * The small shapes
 * ------------------------------------------------------------------------ */

static ncfg_optint_t some_int(int64_t value)
{
	ncfg_optint_t result;

	result.has = 1;
	result.value = value;
	return result;
}

static ncfg_optint_t no_int(void)
{
	ncfg_optint_t result;

	result.has = 0;
	result.value = 0;
	return result;
}

/*
 * An address as text, where there is one.
 *
 * `AF_UNSPEC` is how netlink.h spells absence for an address, and it is read as
 * absence here rather than as `0.0.0.0` or `::` -- which would make every
 * tunnel and every default route differ from a document that cannot say it.
 *
 * 1 with `*out` a copy or NULL, 0 only when there was an address and it could
 * not be rendered or copied.
 */
static int ip_text(const ncfg_wire_ip_t *ip, char **out, char *err, size_t err_size)
{
	char text[NCFG_WIRE_IP_TEXT_MAX];

	*out = NULL;
	if (!ip || ip->family == AF_UNSPEC) {
		return 1;
	}
	if (!ncfg_wire_ip_text(ip, text, sizeof(text), err, err_size)) {
		return 0;
	}
	*out = observe_dup(text);
	if (!*out) {
		ncfg_error_set(err, err_size, "out of memory recording an address");
		return 0;
	}
	return 1;
}

/* An address and its prefix length, which is how a rule's selectors travel. */
static int ip_cidr(const ncfg_wire_ip_t *ip, uint8_t length, char **out, char *err,
    size_t err_size)
{
	char text[NCFG_CIDR_TEXT_MAX];
	char address[NCFG_WIRE_IP_TEXT_MAX];

	*out = NULL;
	if (!ip || ip->family == AF_UNSPEC) {
		return 1;
	}
	if (!ncfg_wire_ip_text(ip, address, sizeof(address), err, err_size)) {
		return 0;
	}
	(void)snprintf(text, sizeof(text), "%s/%u", address, (unsigned)length);
	*out = observe_dup(text);
	if (!*out) {
		ncfg_error_set(err, err_size, "out of memory recording a rule selector");
		return 0;
	}
	return 1;
}

/* ------------------------------------------------------------------------ *
 * Kernel numbers to the words the document uses
 * ------------------------------------------------------------------------ *
 *
 * All three translations happen here, once, for the reason the Rust gives at
 * each of them: the planner compares what the document says against a word
 * rather than against a number, and a comparison of `balance-rr` against 0 is
 * one that differs on every pass. A number this build has no name for stays
 * NULL and is not compared -- an interface is not deleted over a value this
 * build cannot describe.
 */

/* Index is the kernel's mode number, which is also `ncfg_bond_mode_t`'s
 * order. The spellings are `iproute2`'s, which is why `802.3ad` is not
 * kebab like the rest -- a tidier word would be a bond the kernel refuses. */
static const char *const bond_mode_words[] = { "balance-rr", "active-backup", "balance-xor",
	"broadcast", "802.3ad", "balance-tlb", "balance-alb" };

static const char *bond_mode_name(uint8_t number)
{
	if ((size_t)number >= sizeof(bond_mode_words) / sizeof(bond_mode_words[0])) {
		return NULL;
	}
	return bond_mode_words[number];
}

/*
 * `IFLA_MACVLAN_MODE` is **flags, not an enumeration**: the kernel numbers the
 * modes 1, 2, 4, 8 and 16 and its validator refuses anything else, so 0 and 3
 * are `EINVAL` rather than a mode nobody meant. 16 is the `source` mode netcfgd
 * cannot express and is deliberately not named.
 */
static const char *macvlan_mode_name(uint32_t number)
{
	switch (number) {
	case 1u:
		return "private";
	case 2u:
		return "vepa";
	case 4u:
		return "bridge";
	case 8u:
		return "passthru";
	default:
		return NULL;
	}
}

static const char *vlan_protocol_name(uint16_t ethertype)
{
	switch (ethertype) {
	case 0x8100u:
		return "dot1q";
	case 0x88a8u:
		return "dot1ad";
	default:
		return NULL;
	}
}

/* ------------------------------------------------------------------------ *
 * Looking things up in the snapshot
 * ------------------------------------------------------------------------ */

/*
 * The name of a link, by index.
 *
 * NULL for an index this dump did not mention, which is a device in another
 * namespace: "no parent netcfgd can talk about" rather than a failure. The
 * model holds names and not indices for the reason the document does -- the
 * document names interfaces, and an index is a number the kernel handed out.
 */
static const char *name_of(const ncfg_observe_snapshot_t *snapshot, uint32_t index)
{
	size_t at;

	for (at = 0; at < snapshot->link_count; at++) {
		if (snapshot->links[at].index == index) {
			return snapshot->links[at].name;
		}
	}
	return NULL;
}

/* The root qdisc on one link, from the dump. */
static const ncfg_qdisc_record_t *root_qdisc(const ncfg_observe_snapshot_t *snapshot,
    uint32_t index)
{
	size_t at;

	for (at = 0; at < snapshot->qdisc_root_count; at++) {
		if (snapshot->qdisc_roots[at].index == index) {
			return &snapshot->qdisc_roots[at];
		}
	}
	return NULL;
}

static const ncfg_observe_redirect_t *redirect_on(const ncfg_observe_snapshot_t *snapshot,
    uint32_t index)
{
	size_t at;

	for (at = 0; at < snapshot->redirect_count; at++) {
		if (snapshot->redirects[at].index == index) {
			return &snapshot->redirects[at];
		}
	}
	return NULL;
}

/* The origin recorded for one object, or absent. */
static ncfg_optint_t recorded_origin(const ncfg_observe_owned_t *list, size_t count,
    const char *interface, const char *key)
{
	size_t at;

	for (at = 0; at < count; at++) {
		if (list[at].interface && list[at].key &&
		    strcmp(list[at].interface, interface) == 0 &&
		    strcmp(list[at].key, key) == 0) {
			return some_int(list[at].origin);
		}
	}
	return no_int();
}

/* ------------------------------------------------------------------------ *
 * One link
 * ------------------------------------------------------------------------ */

static int build_bond(const ncfg_link_record_t *record, ncfg_observed_link_t *link, char *err,
    size_t err_size)
{
	const char *name;

	link->bond = calloc(1, sizeof(*link->bond));
	if (!link->bond) {
		ncfg_error_set(err, err_size, "out of memory recording a bond");
		return 0;
	}
	if (record->bond.has_mode) {
		name = bond_mode_name(record->bond.mode);
		if (name) {
			link->bond->mode = observe_dup(name);
			if (!link->bond->mode) {
				ncfg_error_set(err, err_size, "out of memory recording a bond");
				return 0;
			}
		}
	}
	link->bond->miimon = record->bond.has_miimon ? some_int(record->bond.miimon) : no_int();
	return 1;
}

/*
 * Hundredths of a second on the wire, seconds in the model.
 *
 * The conversion is here, once, beside nothing else that converts -- the
 * writing half is in ops.h, and the live links test exists partly because a
 * bridge once came up with a 40ms forward delay instead of 4s.
 */
static ncfg_optint_t centiseconds(int has, uint32_t value)
{
	return has ? some_int((int64_t)(value / 100u)) : no_int();
}

static int build_bridge(const ncfg_link_record_t *record, ncfg_observed_link_t *link, char *err,
    size_t err_size)
{
	link->bridge = calloc(1, sizeof(*link->bridge));
	if (!link->bridge) {
		ncfg_error_set(err, err_size, "out of memory recording a bridge");
		return 0;
	}
	link->bridge->stp = record->bridge.stp;
	link->bridge->forward_delay =
	    centiseconds(record->bridge.has_forward_delay, record->bridge.forward_delay);
	link->bridge->hello_time =
	    centiseconds(record->bridge.has_hello_time, record->bridge.hello_time);
	link->bridge->ageing_time =
	    centiseconds(record->bridge.has_ageing_time, record->bridge.ageing_time);
	link->bridge->priority =
	    record->bridge.has_priority ? some_int(record->bridge.priority) : no_int();
	link->bridge->vlan_filtering = record->bridge.vlan_filtering;
	return 1;
}

static int build_tunnel(const ncfg_link_record_t *record, ncfg_observed_link_t *link, char *err,
    size_t err_size)
{
	link->tunnel = calloc(1, sizeof(*link->tunnel));
	if (!link->tunnel) {
		ncfg_error_set(err, err_size, "out of memory recording a tunnel");
		return 0;
	}
	if (!ip_text(&record->tunnel.local, &link->tunnel->local, err, err_size) ||
	    !ip_text(&record->tunnel.remote, &link->tunnel->remote, err, err_size)) {
		return 0;
	}
	link->tunnel->ttl = record->tunnel.has_ttl ? some_int(record->tunnel.ttl) : no_int();
	link->tunnel->key = record->tunnel.has_key ? some_int(record->tunnel.key) : no_int();
	return 1;
}

static int build_vxlan(const ncfg_link_record_t *record, ncfg_observed_link_t *link, char *err,
    size_t err_size)
{
	link->vxlan = calloc(1, sizeof(*link->vxlan));
	if (!link->vxlan) {
		ncfg_error_set(err, err_size, "out of memory recording a vxlan");
		return 0;
	}
	if (!ip_text(&record->vxlan.local, &link->vxlan->local, err, err_size) ||
	    !ip_text(&record->vxlan.remote, &link->vxlan->remote, err, err_size)) {
		return 0;
	}
	link->vxlan->id = record->vxlan.has_id ? some_int(record->vxlan.id) : no_int();
	link->vxlan->port = record->vxlan.has_port ? some_int(record->vxlan.port) : no_int();
	return 1;
}

static int build_kinds(const ncfg_link_record_t *record, ncfg_observed_link_t *link, char *err,
    size_t err_size)
{
	const char *name;

	if (record->has_bond && !build_bond(record, link, err, err_size)) {
		return 0;
	}
	if (record->has_bridge && !build_bridge(record, link, err, err_size)) {
		return 0;
	}
	if (record->has_macvlan) {
		link->macvlan = calloc(1, sizeof(*link->macvlan));
		if (!link->macvlan) {
			ncfg_error_set(err, err_size, "out of memory recording a macvlan");
			return 0;
		}
		name = record->macvlan.has_mode ? macvlan_mode_name(record->macvlan.mode) : NULL;
		if (name) {
			link->macvlan->mode = observe_dup(name);
			if (!link->macvlan->mode) {
				ncfg_error_set(err, err_size,
				    "out of memory recording a macvlan");
				return 0;
			}
		}
	}
	if (record->has_vlan) {
		link->vlan = calloc(1, sizeof(*link->vlan));
		if (!link->vlan) {
			ncfg_error_set(err, err_size, "out of memory recording a vlan");
			return 0;
		}
		link->vlan->id = record->vlan.has_id ? some_int(record->vlan.id) : no_int();
		name = NULL;
		if (record->vlan.has_protocol) {
			name = vlan_protocol_name(record->vlan.protocol);
		}
		if (name) {
			link->vlan->protocol = observe_dup(name);
			if (!link->vlan->protocol) {
				ncfg_error_set(err, err_size, "out of memory recording a vlan");
				return 0;
			}
		}
	}
	if (record->has_tunnel && !build_tunnel(record, link, err, err_size)) {
		return 0;
	}
	if (record->has_vxlan && !build_vxlan(record, link, err, err_size)) {
		return 0;
	}
	return 1;
}

static int build_link(const ncfg_observe_snapshot_t *snapshot, const ncfg_link_record_t *record,
    const ncfg_observe_prior_t *prior, const char *class_net, ncfg_observed_link_t *link,
    char *err, size_t err_size)
{
	const ncfg_qdisc_record_t     *root = root_qdisc(snapshot, record->index);
	const ncfg_observe_redirect_t *redirect = redirect_on(snapshot, record->index);
	const char                    *other;

	link->name = observe_dup(record->name);
	/* Written even when empty, because the Rust's field is a `String` and
	 * not an `Option`: a NULL here would be omitted from the JSON and an
	 * observation would stop round-tripping. */
	link->kind = observe_dup(record->kind);
	if (!link->name || !link->kind) {
		ncfg_error_set(err, err_size, "out of memory recording a link");
		return 0;
	}
	if (!observe_widen(record->index, "a link's index", &link->index, err, err_size) ||
	    !observe_widen(record->mtu, "a link's mtu", &link->mtu, err, err_size)) {
		return 0;
	}
	/* The same predicate `ncfg wifi add` uses to pick a radio and the
	 * executor uses to choose a supplicant driver, shared rather than
	 * repeated: three copies of one fact is how they end up disagreeing. */
	link->wireless = ncfg_radio_is_wireless(class_net, record->name);
	link->up = record->up;
	link->carrier = record->carrier;
	if (record->has_mac) {
		link->mac = observe_dup(record->mac);
		if (!link->mac) {
			ncfg_error_set(err, err_size, "out of memory recording a link");
			return 0;
		}
	}
	if (record->has_master) {
		other = name_of(snapshot, record->master);
		if (other) {
			link->master = observe_dup(other);
			if (!link->master) {
				ncfg_error_set(err, err_size, "out of memory recording a link");
				return 0;
			}
		}
	}
	if (record->has_parent) {
		other = name_of(snapshot, record->parent);
		if (other) {
			link->parent = observe_dup(other);
			if (!link->parent) {
				ncfg_error_set(err, err_size, "out of memory recording a link");
				return 0;
			}
		}
	}
	if (!ip_text(&record->ipv6_token, &link->ipv6_token, err, err_size)) {
		return 0;
	}
	if (root) {
		link->qdisc = observe_dup(root->kind);
		if (!link->qdisc) {
			ncfg_error_set(err, err_size, "out of memory recording a qdisc");
			return 0;
		}
		link->qdisc_ingress = root->ingress;
		if (root->has_bandwidth) {
			int64_t bits;

			if (!observe_widen(root->bandwidth_bits, "a qdisc's bandwidth", &bits,
			    err, err_size)) {
				return 0;
			}
			link->qdisc_bandwidth_bits = some_int(bits);
		}
	}
	if (redirect) {
		other = name_of(snapshot, redirect->target);
		if (other) {
			link->ingress_redirect = observe_dup(other);
			if (!link->ingress_redirect) {
				ncfg_error_set(err, err_size,
				    "out of memory recording a redirect");
				return 0;
			}
		}
	}
	/* The kernel has no protocol field for links, so this can only come
	 * from the alternative name netcfgd stamps and from what it wrote
	 * down. A link nobody recorded is never deleted. */
	link->ownership = ncfg_observe_link_ownership(record->altnames, record->altname_count,
	    observe_list_has(prior->created_links, prior->created_link_count, record->name));
	return build_kinds(record, link, err, err_size);
}

/* ------------------------------------------------------------------------ *
 * Addresses, routes and rules
 * ------------------------------------------------------------------------ */

static int build_addresses(const ncfg_observe_snapshot_t *snapshot,
    const ncfg_observe_prior_t *prior, ncfg_observed_t *observed, char *err, size_t err_size)
{
	size_t at;

	if (snapshot->address_count == 0) {
		return 1;
	}
	observed->addresses = calloc(snapshot->address_count, sizeof(*observed->addresses));
	if (!observed->addresses) {
		ncfg_error_set(err, err_size, "out of memory recording the addresses");
		return 0;
	}
	for (at = 0; at < snapshot->address_count; at++) {
		const ncfg_address_record_t *record = &snapshot->addresses[at];
		ncfg_observed_address_t     *address;
		const char                  *interface = name_of(snapshot, record->index);
		char                         cidr[NCFG_CIDR_TEXT_MAX];
		ncfg_optint_t                recorded;

		/* An address on an interface the link dump did not mention is
		 * dropped rather than attributed to the wrong one. */
		if (!interface) {
			continue;
		}
		if (!ncfg_address_record_cidr(record, cidr, sizeof(cidr), err, err_size)) {
			return 0;
		}
		address = &observed->addresses[observed->address_count];
		address->interface = observe_dup(interface);
		address->address = observe_dup(cidr);
		if (!address->interface || !address->address) {
			ncfg_error_set(err, err_size, "out of memory recording an address");
			observed->address_count++;
			return 0;
		}
		recorded = recorded_origin(prior->address_origins, prior->address_origin_count,
		    interface, cidr);
		address->ownership = ncfg_observe_address_ownership(record->has_proto,
		    record->proto, snapshot->address_proto_supported, recorded.has);
		/* The record wins where it exists, which is what keeps the tag a
		 * fallback: a DHCP address recorded as `dhcp4` must stay `dhcp4`
		 * even where netcfgd's own tag is absent from it. */
		address->origin = recorded.has
		    ? recorded
		    : ncfg_observe_tagged_origin(record->has_proto, record->proto);
		address->proto = record->has_proto ? some_int(record->proto) : no_int();
		observed->address_count++;
	}
	return 1;
}

static int build_routes(const ncfg_observe_snapshot_t *snapshot,
    const ncfg_observe_prior_t *prior, ncfg_observed_t *observed, char *err, size_t err_size)
{
	size_t at;

	if (snapshot->route_count == 0) {
		return 1;
	}
	observed->routes = calloc(snapshot->route_count, sizeof(*observed->routes));
	if (!observed->routes) {
		ncfg_error_set(err, err_size, "out of memory recording the routes");
		return 0;
	}
	for (at = 0; at < snapshot->route_count; at++) {
		const ncfg_route_record_t *record = &snapshot->routes[at];
		ncfg_observed_route_t     *route;
		const char                *interface;
		char                       destination[NCFG_CIDR_TEXT_MAX];
		ncfg_optint_t              recorded;

		if (!record->has_index) {
			continue;
		}
		interface = name_of(snapshot, record->index);
		if (!interface) {
			continue;
		}
		if (!ncfg_route_record_destination(record, destination, sizeof(destination), err,
		    err_size)) {
			return 0;
		}
		route = &observed->routes[observed->route_count];
		route->interface = observe_dup(interface);
		route->destination = observe_dup(destination);
		if (!route->interface || !route->destination) {
			ncfg_error_set(err, err_size, "out of memory recording a route");
			observed->route_count++;
			return 0;
		}
		observed->route_count++;
		if (!ip_text(&record->gateway, &route->via, err, err_size) ||
		    !ip_text(&record->prefsrc, &route->src, err, err_size)) {
			return 0;
		}
		route->metric = record->has_metric ? some_int(record->metric) : no_int();
		route->table = some_int(record->table);
		/* **Absent, deliberately.** The record carries `rtm_scope` and
		 * the Rust drops it: a route's scope is not compared against
		 * anything, and an observation that reported one would be this
		 * port deciding something the Rust does not. */
		route->scope = no_int();
		route->proto = some_int(record->protocol);
		/* A route's protocol comes straight from the kernel on every
		 * supported version, so this needs no fallback and no recorded
		 * state -- which is exactly why 0002 picked a field the kernel
		 * round-trips. */
		route->ownership = record->protocol == NCFG_WIRE_RTPROT_NETCFGD
		    ? NCFG_OWNERSHIP_OURS
		    : NCFG_OWNERSHIP_FOREIGN;
		recorded = recorded_origin(prior->route_origins, prior->route_origin_count,
		    interface, destination);
		route->origin = recorded.has
		    ? recorded
		    : ncfg_observe_tagged_origin(1, record->protocol);
	}
	return 1;
}

/*
 * One rule, with ownership decided the way a route's is.
 *
 * `FRA_PROTOCOL` round-trips through the kernel, so unlike a link this needs no
 * recorded state: a rule carrying 110 is netcfgd's and nothing else is. A
 * kernel too old for the attribute reports 0 on everything, which reads as
 * foreign -- so netcfgd installs and never removes, which is the safe way to be
 * wrong.
 */
static int build_rule(const ncfg_rule_record_t *record, ncfg_observed_rule_t *rule, char *err,
    size_t err_size)
{
	rule->priority = record->priority;
	rule->family =
	    record->family == AF_INET6 ? NCFG_RULE_FAMILY_INET6 : NCFG_RULE_FAMILY_INET;
	if (!ip_cidr(&record->from, record->from_len, &rule->from, err, err_size) ||
	    !ip_cidr(&record->to, record->to_len, &rule->to, err, err_size)) {
		return 0;
	}
	if (record->has_iif) {
		rule->iif = observe_dup(record->iif);
		if (!rule->iif) {
			ncfg_error_set(err, err_size, "out of memory recording a rule");
			return 0;
		}
	}
	if (record->has_oif) {
		rule->oif = observe_dup(record->oif);
		if (!rule->oif) {
			ncfg_error_set(err, err_size, "out of memory recording a rule");
			return 0;
		}
	}
	rule->fwmark = record->has_fwmark ? some_int(record->fwmark) : no_int();
	rule->fwmask = record->has_fwmask ? some_int(record->fwmask) : no_int();
	/* Zero is `RT_TABLE_UNSPEC`, which for an action other than a lookup is
	 * simply "no table" rather than "table zero". */
	rule->table = record->table != 0u ? some_int(record->table) : no_int();
	switch (record->action) {
	case FR_ACT_BLACKHOLE:
		rule->action = NCFG_RULE_ACTION_BLACKHOLE;
		break;
	case FR_ACT_UNREACHABLE:
		rule->action = NCFG_RULE_ACTION_UNREACHABLE;
		break;
	case FR_ACT_PROHIBIT:
		rule->action = NCFG_RULE_ACTION_PROHIBIT;
		break;
	default:
		rule->action = NCFG_RULE_ACTION_LOOKUP;
		break;
	}
	rule->suppress_prefixlength = record->has_suppress_prefixlength
	    ? some_int(record->suppress_prefixlength)
	    : no_int();
	rule->l3mdev = record->l3mdev;
	rule->invert = record->invert;
	rule->ownership = record->protocol == NCFG_WIRE_RTPROT_NETCFGD
	    ? NCFG_OWNERSHIP_OURS
	    : NCFG_OWNERSHIP_FOREIGN;
	return 1;
}

/* ------------------------------------------------------------------------ *
 * The `tc` objects, whose ownership is a handle
 * ------------------------------------------------------------------------ */

/*
 * The interfaces a `tc` object is netcfgd's on: what the kernel says, plus what
 * was recorded.
 *
 * **A union rather than a replacement**, which is the difference from an
 * address. There the kernel is authoritative and a stale record must not be
 * able to claim an address back, because an address netcfgd did not install
 * carries somebody else's tag *or none* and both are legible. Here an unmarked
 * qdisc is ambiguous: it may be somebody else's, or it may be one an older
 * netcfgd installed before it stamped handles (0137). Dropping the record would
 * make every such qdisc foreign on the day this ships, and netcfgd would stop
 * being able to reset one it had set itself.
 */
static int marked_or_recorded(char *const *recorded, size_t recorded_count,
    char *const *marked, size_t marked_count, char ***out, size_t *out_count, char *err,
    size_t err_size)
{
	size_t at;

	if (!observe_list_copy(out, out_count, recorded, recorded_count)) {
		ncfg_error_set(err, err_size, "out of memory recording what netcfgd set");
		return 0;
	}
	for (at = 0; at < marked_count; at++) {
		if (observe_list_has(*out, *out_count, marked[at])) {
			continue;
		}
		if (!observe_list_add(out, out_count, marked[at])) {
			ncfg_error_set(err, err_size, "out of memory recording what netcfgd set");
			return 0;
		}
	}
	observe_list_sort(*out, *out_count);
	return 1;
}

/*
 * The interfaces whose root qdisc wears netcfgd's handle.
 *
 * A qdisc has no protocol field and no property list, but its handle is
 * netcfgd's to choose -- and until 0137 netcfgd let the kernel choose it, so
 * ownership lived only in `/run`, which a restart deletes.
 */
static int qdisc_marked(const ncfg_observe_snapshot_t *snapshot, char ***out, size_t *out_count)
{
	size_t at;

	for (at = 0; at < snapshot->qdisc_root_count; at++) {
		const char *name;

		if (snapshot->qdisc_roots[at].handle != NCFG_QDISC_HANDLE) {
			continue;
		}
		name = name_of(snapshot, snapshot->qdisc_roots[at].index);
		if (name && !observe_list_add(out, out_count, name)) {
			return 0;
		}
	}
	return 1;
}

/*
 * The interfaces whose ingress redirect wears netcfgd's filter handle.
 *
 * The handle rather than the priority: the priority has to stay 1 for the
 * redirect to see the packet at all, so overloading it would trade a
 * correctness property for a bookkeeping one.
 */
static int ingress_marked(const ncfg_observe_snapshot_t *snapshot, char ***out,
    size_t *out_count)
{
	size_t at;

	for (at = 0; at < snapshot->redirect_count; at++) {
		const char *name;

		if (!snapshot->redirects[at].ours) {
			continue;
		}
		name = name_of(snapshot, snapshot->redirects[at].index);
		if (name && !observe_list_add(out, out_count, name)) {
			return 0;
		}
	}
	return 1;
}

/* ------------------------------------------------------------------------ *
 * The whole observation
 * ------------------------------------------------------------------------ */

static int build_tc_applied(const ncfg_observe_snapshot_t *snapshot,
    const ncfg_observe_prior_t *prior, ncfg_observed_t *observed, char *err, size_t err_size)
{
	char **marked = NULL;
	size_t marked_count = 0;
	int    built;

	if (!qdisc_marked(snapshot, &marked, &marked_count)) {
		observe_names_free(marked, marked_count);
		ncfg_error_set(err, err_size, "out of memory recording a qdisc");
		return 0;
	}
	built = marked_or_recorded(prior->qdisc, prior->qdisc_count, marked, marked_count,
	    &observed->qdisc_applied, &observed->qdisc_applied_count, err, err_size);
	observe_names_free(marked, marked_count);
	if (!built) {
		return 0;
	}
	marked = NULL;
	marked_count = 0;
	if (!ingress_marked(snapshot, &marked, &marked_count)) {
		observe_names_free(marked, marked_count);
		ncfg_error_set(err, err_size, "out of memory recording an ingress redirect");
		return 0;
	}
	built = marked_or_recorded(prior->ingress, prior->ingress_count, marked, marked_count,
	    &observed->ingress_applied, &observed->ingress_applied_count, err, err_size);
	observe_names_free(marked, marked_count);
	return built;
}

static int build_lists(const ncfg_observe_snapshot_t *snapshot, ncfg_observe_prior_t *prior,
    const ncfg_observe_roots_t *roots, ncfg_observed_t *observed, char *err, size_t err_size)
{
	size_t at;

	if (snapshot->link_count > 0) {
		observed->links = calloc(snapshot->link_count, sizeof(*observed->links));
		if (!observed->links) {
			ncfg_error_set(err, err_size, "out of memory recording the links");
			return 0;
		}
		for (at = 0; at < snapshot->link_count; at++) {
			observed->link_count++;
			if (!build_link(snapshot, &snapshot->links[at], prior, roots->class_net,
			    &observed->links[at], err, err_size)) {
				return 0;
			}
		}
	}
	if (!build_addresses(snapshot, prior, observed, err, err_size) ||
	    !build_routes(snapshot, prior, observed, err, err_size)) {
		return 0;
	}
	if (snapshot->rule_count > 0) {
		observed->rules = calloc(snapshot->rule_count, sizeof(*observed->rules));
		if (!observed->rules) {
			ncfg_error_set(err, err_size, "out of memory recording the rules");
			return 0;
		}
		for (at = 0; at < snapshot->rule_count; at++) {
			observed->rule_count++;
			if (!build_rule(&snapshot->rules[at], &observed->rules[at], err,
			    err_size)) {
				return 0;
			}
		}
	}
	if (snapshot->bridge_vlan_count > 0) {
		observed->bridge_vlans =
		    calloc(snapshot->bridge_vlan_count, sizeof(*observed->bridge_vlans));
		if (!observed->bridge_vlans) {
			ncfg_error_set(err, err_size, "out of memory recording the bridge vlans");
			return 0;
		}
		for (at = 0; at < snapshot->bridge_vlan_count; at++) {
			ncfg_observed_bridge_vlan_t *vlan = &observed->bridge_vlans[at];

			observed->bridge_vlan_count++;
			vlan->index = snapshot->bridge_vlans[at].index;
			vlan->vid = snapshot->bridge_vlans[at].vid;
			vlan->pvid = snapshot->bridge_vlans[at].pvid;
			vlan->untagged = snapshot->bridge_vlans[at].untagged;
		}
	}
	if (!observe_list_copy(&observed->forwarding_applied, &observed->forwarding_applied_count,
	    prior->forwarding, prior->forwarding_count) ||
	    !observe_list_copy(&observed->privacy_applied, &observed->privacy_applied_count,
	    prior->privacy, prior->privacy_count) ||
	    !observe_list_copy(&observed->accept_ra_applied, &observed->accept_ra_applied_count,
	    prior->accept_ra, prior->accept_ra_count)) {
		ncfg_error_set(err, err_size, "out of memory recording what netcfgd set");
		return 0;
	}
	return build_tc_applied(snapshot, prior, observed, err, err_size);
}

int ncfg_observe_build(const ncfg_observe_snapshot_t *snapshot, ncfg_observe_prior_t *prior,
    const ncfg_observe_roots_t *roots, ncfg_observed_t **out, char *err, size_t err_size)
{
	ncfg_observed_t *observed;

	if (!snapshot || !prior || !roots || !out) {
		ncfg_error_set(err, err_size, "an observation needs a snapshot and a record");
		return 0;
	}
	*out = NULL;
	observed = ncfg_observed_new(err, err_size);
	if (!observed) {
		return 0;
	}
	if (!build_lists(snapshot, prior, roots, observed, err, err_size)) {
		ncfg_observed_free(observed);
		return 0;
	}
	observed->address_proto_supported = snapshot->address_proto_supported;
	/*
	 * **The hand-over is last, after everything that can fail.** A refusal
	 * therefore leaves the prior holding everything it arrived with, so one
	 * `ncfg_observe_prior_free` is correct on either answer -- which is the
	 * property that makes moving rather than copying defensible at all.
	 */
	observed->backends = prior->backends;
	observed->backend_count = prior->backend_count;
	prior->backends = NULL;
	prior->backend_count = 0;
	observed->dns = prior->dns;
	observed->dns_count = prior->dns_count;
	prior->dns = NULL;
	prior->dns_count = 0;
	observed->backend_restarts = prior->backend_restarts;
	observed->backend_restart_count = prior->backend_restart_count;
	prior->backend_restarts = NULL;
	prior->backend_restart_count = 0;
	observed->hook_state = prior->hook_state;
	observed->hook_state_count = prior->hook_state_count;
	prior->hook_state = NULL;
	prior->hook_state_count = 0;
	observed->delegations = prior->delegations;
	observed->delegation_count = prior->delegation_count;
	prior->delegations = NULL;
	prior->delegation_count = 0;
	observed->reports = prior->reports;
	observed->report_count = prior->report_count;
	prior->reports = NULL;
	prior->report_count = 0;

	ncfg_observed_canonicalize(observed);
	*out = observed;
	return 1;
}

/* ------------------------------------------------------------------------ *
 * Letting go of a prior
 * ------------------------------------------------------------------------ */

/*
 * The aggregates a prior still owns.
 *
 * Each list is freed through a one-element observation, because the field
 * tables that know how to take an `ncfg_observed_backend_t` apart are static
 * in `src/model/observed.c` and a second copy of them here is exactly the
 * duplication 0263 forbids. So the list is lent to an empty observation, which
 * frees it as its own.
 */
void ncfg_observe_prior_free(ncfg_observe_prior_t *prior)
{
	ncfg_observed_t *carrier;

	if (!prior) {
		return;
	}
	carrier = ncfg_observed_new(NULL, 0);
	if (!carrier) {
		/* Nothing can be freed without the model's tables, and an
		 * allocation failure while unwinding is not a thing to fail
		 * over: the lists stay where they are. */
		return;
	}
	carrier->backends = prior->backends;
	carrier->backend_count = prior->backend_count;
	carrier->dns = prior->dns;
	carrier->dns_count = prior->dns_count;
	carrier->backend_restarts = prior->backend_restarts;
	carrier->backend_restart_count = prior->backend_restart_count;
	carrier->hook_state = prior->hook_state;
	carrier->hook_state_count = prior->hook_state_count;
	carrier->delegations = prior->delegations;
	carrier->delegation_count = prior->delegation_count;
	carrier->reports = prior->reports;
	carrier->report_count = prior->report_count;
	ncfg_observed_free(carrier);
	prior->backends = NULL;
	prior->backend_count = 0;
	prior->dns = NULL;
	prior->dns_count = 0;
	prior->backend_restarts = NULL;
	prior->backend_restart_count = 0;
	prior->hook_state = NULL;
	prior->hook_state_count = 0;
	prior->delegations = NULL;
	prior->delegation_count = 0;
	prior->reports = NULL;
	prior->report_count = 0;
}
