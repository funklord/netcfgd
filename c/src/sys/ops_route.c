/*
 * ops_route.c -- the messages that carry an address, a route or a rule.
 *
 * The other half of `crates/netcfgd-sys/src/ops.rs`, plus the whole of
 * `rule.rs`, which belongs beside it: a rule is how a packet chooses a routing
 * table and a route is what it finds there, and the two carry the same
 * ownership mark for the same reason.
 *
 * **Decision 0002 is what this file is about.** Three of the objects netcfgd
 * creates can be stamped with a protocol number -- an address through
 * `IFA_PROTO`, a route through `rtm_protocol`, a rule through `FRA_PROTOCOL`
 * -- and 110 is netcfgd's. It is the only thing that distinguishes an object
 * netcfgd installed from one an operator added by hand, and without it
 * reconciliation has exactly two options, both wrong: remove theirs, or never
 * remove its own.
 *
 * The mark is applied here rather than carried in the document, so that it
 * cannot be forgotten by a caller and cannot be forged by a configuration. A
 * document may still name a different protocol for a route it does not want
 * netcfgd to own, which is why the field is optional rather than absent.
 */
#include "ncfg/ops.h"

#include <stdint.h>
#include <string.h>

/* ------------------------------------------------------------------------ *
 * Addresses
 * ------------------------------------------------------------------------ */

static int address_request(ncfg_buf_t *out, uint16_t kind, uint16_t flags, uint32_t seq,
    uint32_t index, const ncfg_wire_ip_t *address, uint8_t prefix_len, const uint8_t *proto,
    char *err, size_t err_size)
{
	ncfg_wire_ifaddr_t header;
	ncfg_buf_t body;
	ncfg_buf_t attrs;
	int built;

	if (!ncfg_ops_ip_present(address)) {
		ncfg_error_set(err, err_size, "an address operation needs an address");
		return 0;
	}
	header.family = ncfg_ops_family_byte(address);
	header.prefix_len = prefix_len;
	header.flags = 0;
	header.scope = 0;
	header.index = index;

	ncfg_buf_init(&body, 0);
	ncfg_buf_init(&attrs, 0);
	ncfg_wire_ifaddr_encode(&header, &body);
	/* `IFA_LOCAL` is this host's address. `IFA_ADDRESS` must be sent too, and
	 * for anything but a point-to-point link it is the same value. */
	ncfg_wire_attr_put_ip(&attrs, IFA_LOCAL, address);
	ncfg_wire_attr_put_ip(&attrs, IFA_ADDRESS, address);
	if (proto) {
		ncfg_wire_attr_put_u8(&attrs, IFA_PROTO, *proto);
	}
	built = ncfg_wire_build_request(out, kind, flags, seq, &body, &attrs, err, err_size);
	ncfg_buf_free(&body);
	ncfg_buf_free(&attrs);
	return built;
}

int ncfg_ops_add_address(ncfg_buf_t *out, uint32_t seq, uint32_t index,
    const ncfg_wire_ip_t *address, uint8_t prefix_len, uint8_t proto, char *err,
    size_t err_size)
{
	/*
	 * `CREATE | REPLACE`: an address that is already there is corrected
	 * rather than refused, which is what makes an apply re-runnable.
	 *
	 * The protocol tag is what makes the address ours for drift detection. A
	 * kernel before 5.18 ignores the unknown attribute, which is exactly the
	 * read-back decision 0002 relies on: the next dump says which happened.
	 */
	return address_request(out, RTM_NEWADDR,
	    (uint16_t)(NCFG_OPS_ACK_FLAGS | NLM_F_CREATE | NLM_F_REPLACE), seq, index, address,
	    prefix_len, &proto, err, err_size);
}

int ncfg_ops_del_address(ncfg_buf_t *out, uint32_t seq, uint32_t index,
    const ncfg_wire_ip_t *address, uint8_t prefix_len, char *err, size_t err_size)
{
	return address_request(out, RTM_DELADDR, NCFG_OPS_ACK_FLAGS, seq, index, address, prefix_len,
	    NULL, err, err_size);
}

/* ------------------------------------------------------------------------ *
 * Routes
 * ------------------------------------------------------------------------ */

static int route_request(ncfg_buf_t *out, uint16_t kind, uint16_t flags, uint32_t seq,
    const ncfg_ops_route_t *route, char *err, size_t err_size)
{
	ncfg_wire_rtmsg_t header;
	ncfg_buf_t body;
	ncfg_buf_t attrs;
	uint32_t table = NCFG_ROUTE_MAIN_TABLE;
	uint32_t proto = NCFG_WIRE_RTPROT_NETCFGD;
	uint32_t metric = 0;
	int table_in_attr;
	int built;

	if (!out || !route) {
		ncfg_error_set(err, err_size, "a route operation needs a route");
		return 0;
	}
	/* Absent means the main table, which is document.h's rule: the kernel
	 * always reports a table, so an unqualified route and a reported 254 are
	 * the same route and something has to normalise. */
	if (route->table.has &&
	    !ncfg_ops_narrow(route->table, UINT32_MAX, "a route's table", &table, err, err_size)) {
		return 0;
	}
	/*
	 * **The ownership mark.** Absent means netcfgd's own protocol number, and
	 * that one byte is the whole of decision 0002: it is what lets a later
	 * reconciliation say "this route is mine to remove" about a route it did
	 * not itself install, and say nothing about the operator's. A route has
	 * no other field that could carry the answer.
	 */
	if (route->proto.has &&
	    !ncfg_ops_narrow(route->proto, UINT8_MAX, "a route's protocol", &proto, err, err_size)) {
		return 0;
	}
	if (route->metric.has &&
	    !ncfg_ops_narrow(route->metric, UINT32_MAX, "a route's metric", &metric, err, err_size)) {
		return 0;
	}

	/* A table id above 255 does not fit `rtm_table` and goes in `RTA_TABLE`
	 * instead, with the byte set to unspec so the kernel knows to look. */
	table_in_attr = table > 255u;

	/*
	 * The family comes from the destination, or from the gateway where the
	 * route is a default one, or is `AF_INET` where it has neither. The Rust
	 * writes that last case as a bare 2.
	 */
	header.family = (uint8_t)AF_INET;
	if (ncfg_ops_ip_present(&route->destination)) {
		header.family = ncfg_ops_family_byte(&route->destination);
	} else if (ncfg_ops_ip_present(&route->gateway)) {
		header.family = ncfg_ops_family_byte(&route->gateway);
	}
	/*
	 * A prefix length belongs to the prefix beside it. `RouteSpec` in the
	 * Rust can only be built with the two together -- `(None, 0)` for a
	 * default route -- and a C struct cannot promise that, so the length goes
	 * with the destination or does not go at all: a `dst_len` of 24 with no
	 * `RTA_DST` is not a default route, it is `0.0.0.0/24`, which is a real
	 * and different route.
	 */
	header.dst_len = ncfg_ops_ip_present(&route->destination) ? route->dst_len : 0u;
	header.src_len = 0;
	header.tos = 0;
	header.table = table_in_attr ? (uint8_t)RT_TABLE_UNSPEC : (uint8_t)table;
	header.protocol = (uint8_t)proto;
	/* A route with a gateway reaches beyond the link; one without is on the
	 * link itself, and the kernel rejects it at universe scope. */
	header.scope = (uint8_t)(ncfg_ops_ip_present(&route->gateway) ? RT_SCOPE_UNIVERSE
	                                 : RT_SCOPE_LINK);
	header.kind = (uint8_t)RTN_UNICAST;
	header.flags = route->onlink ? (uint32_t)RTNH_F_ONLINK : 0u;

	ncfg_buf_init(&body, 0);
	ncfg_buf_init(&attrs, 0);
	ncfg_wire_rtmsg_encode(&header, &body);
	if (ncfg_ops_ip_present(&route->destination)) {
		ncfg_wire_attr_put_ip(&attrs, RTA_DST, &route->destination);
	}
	if (ncfg_ops_ip_present(&route->gateway)) {
		ncfg_wire_attr_put_ip(&attrs, RTA_GATEWAY, &route->gateway);
	}
	ncfg_wire_attr_put_u32(&attrs, RTA_OIF, route->index);
	if (route->metric.has) {
		ncfg_wire_attr_put_u32(&attrs, RTA_PRIORITY, metric);
	}
	if (ncfg_ops_ip_present(&route->source)) {
		ncfg_wire_attr_put_ip(&attrs, RTA_PREFSRC, &route->source);
	}
	if (table_in_attr) {
		ncfg_wire_attr_put_u32(&attrs, RTA_TABLE, table);
	}
	built = ncfg_wire_build_request(out, kind, flags, seq, &body, &attrs, err, err_size);
	ncfg_buf_free(&body);
	ncfg_buf_free(&attrs);
	return built;
}

int ncfg_ops_add_route(ncfg_buf_t *out, uint32_t seq, const ncfg_ops_route_t *route,
    char *err, size_t err_size)
{
	return route_request(out, RTM_NEWROUTE, (uint16_t)(NCFG_OPS_ACK_FLAGS | NLM_F_CREATE), seq,
	    route, err, err_size);
}

int ncfg_ops_del_route(ncfg_buf_t *out, uint32_t seq, const ncfg_ops_route_t *route,
    char *err, size_t err_size)
{
	return route_request(out, RTM_DELROUTE, NCFG_OPS_ACK_FLAGS, seq, route, err, err_size);
}


/* ------------------------------------------------------------------------ *
 * Policy routing rules
 * ------------------------------------------------------------------------ */

/*
 * `struct fib_rule_hdr` is twelve bytes and byte-for-byte the same shape as
 * `rtmsg` -- and deliberately not that type. Bytes five, six and seven are
 * `res1`, `res2` and `action` here against `protocol`, `scope` and `type`
 * there, so reusing `ncfg_wire_rtmsg_t` would compile and would put the action
 * where the kernel reads a route type.
 *
 * Built field by field rather than by copying the struct, so that a compiler's
 * padding rules are not part of what goes on the wire. The assert is what
 * keeps the hand-built version honest about its length.
 */
#define OPS_FIB_RULE_HDR_LEN 12u
_Static_assert(sizeof(struct fib_rule_hdr) == OPS_FIB_RULE_HDR_LEN,
    "a rule header is twelve bytes and this one is not");

static void rule_header(ncfg_buf_t *body, const ncfg_ops_rule_t *rule, uint8_t table_byte)
{
	uint8_t bytes[8];
	uint32_t flags = rule->invert ? (uint32_t)FIB_RULE_INVERT : 0u;

	bytes[0] = rule->family;
	/* A prefix length means nothing without the selector it belongs to, and
	 * the kernel matches on both: a `dst_len` with no `FRA_DST` is a rule
	 * that matches a prefix of nothing in particular. */
	bytes[1] = ncfg_ops_ip_present(&rule->to) ? rule->to_len : 0u;
	bytes[2] = ncfg_ops_ip_present(&rule->from) ? rule->from_len : 0u;
	bytes[3] = 0; /* tos */
	bytes[4] = table_byte;
	bytes[5] = 0; /* res1 */
	bytes[6] = 0; /* res2 */
	bytes[7] = rule->action;
	ncfg_buf_add(body, bytes, sizeof(bytes));
	/* Native order, like every other netlink integer. See wire.h. */
	ncfg_buf_add(body, &flags, sizeof(flags));
}

static int rule_request(ncfg_buf_t *out, uint16_t kind, uint16_t flags, uint32_t seq,
    const ncfg_ops_rule_t *rule, char *err, size_t err_size)
{
	ncfg_buf_t body;
	ncfg_buf_t attrs;
	uint32_t number = 0;
	uint32_t protocol = NCFG_WIRE_RTPROT_NETCFGD;
	int built = 1;

	if (!out || !rule) {
		ncfg_error_set(err, err_size, "a rule operation needs a rule");
		return 0;
	}
	/*
	 * **The ownership mark again**, and here it does more than mark: the
	 * kernel matches a delete against every attribute the request carries, so
	 * a delete asking for protocol 110 cannot match a rule that does not
	 * carry it. That is a second layer under the planner's ownership check,
	 * at the kernel rather than in netcfgd, and it means even a planner bug
	 * cannot remove somebody else's rule.
	 *
	 * A family the kernel does not know is left to the kernel, which answers
	 * `EAFNOSUPPORT` and says exactly what happened. The IPv6 token in ops.c
	 * is refused locally for the opposite reason: there, every refusal is the
	 * same bare `EINVAL`.
	 */
	if (rule->protocol.has && !ncfg_ops_narrow(rule->protocol, UINT8_MAX,
	    "a rule's protocol", &protocol, err, err_size)) {
		return 0;
	}

	ncfg_buf_init(&body, 0);
	ncfg_buf_init(&attrs, 0);
	/* Only a table that fits in a byte goes in the header; anything larger
	 * travels in `FRA_TABLE` and this stays unspecified. Truncating instead
	 * would send table 1000 as table 232. */
	rule_header(&body, rule, rule->table <= UINT8_MAX ? (uint8_t)rule->table
	                          : (uint8_t)RT_TABLE_UNSPEC);

	ncfg_wire_attr_put_u32(&attrs, FRA_PRIORITY, rule->priority);
	/* Zero is "no table named", not table zero: `RT_TABLE_UNSPEC` is what an
	 * action other than `FR_ACT_TO_TBL` leaves behind. */
	if (rule->table != 0) {
		ncfg_wire_attr_put_u32(&attrs, FRA_TABLE, rule->table);
	}
	if (ncfg_ops_ip_present(&rule->from)) {
		ncfg_wire_attr_put_ip(&attrs, FRA_SRC, &rule->from);
	}
	if (ncfg_ops_ip_present(&rule->to)) {
		ncfg_wire_attr_put_ip(&attrs, FRA_DST, &rule->to);
	}
	if (rule->iif) {
		ncfg_wire_attr_put_str(&attrs, FRA_IIFNAME, rule->iif);
	}
	if (rule->oif) {
		ncfg_wire_attr_put_str(&attrs, FRA_OIFNAME, rule->oif);
	}
	if (built && rule->fwmark.has) {
		built = ncfg_ops_narrow(rule->fwmark, UINT32_MAX, "a firewall mark", &number,
		    err, err_size);
		if (built) {
			ncfg_wire_attr_put_u32(&attrs, FRA_FWMARK, number);
		}
	}
	if (built && rule->fwmask.has) {
		built = ncfg_ops_narrow(rule->fwmask, UINT32_MAX, "a firewall mark's mask",
		    &number, err, err_size);
		if (built) {
			ncfg_wire_attr_put_u32(&attrs, FRA_FWMASK, number);
		}
	}
	/*
	 * Absent and zero are different answers here, which is the whole `ip
	 * rule` trick: `suppress_prefixlength 0` says "consult this table but
	 * skip its default route", so a more specific rule below can catch it.
	 * The kernel dumps the unset value as all-ones rather than as an absent
	 * attribute, which is a reader's problem and named here because the two
	 * halves have to agree about it.
	 */
	if (built && rule->suppress_prefixlength.has) {
		built = ncfg_ops_narrow(rule->suppress_prefixlength, UINT32_MAX,
		    "a suppressed prefix length", &number, err, err_size);
		if (built) {
			ncfg_wire_attr_put_u32(&attrs, FRA_SUPPRESS_PREFIXLEN, number);
		}
	}
	if (rule->l3mdev) {
		ncfg_wire_attr_put_u8(&attrs, FRA_L3MDEV, 1);
	}
	ncfg_wire_attr_put_u8(&attrs, FRA_PROTOCOL, (uint8_t)protocol);

	if (built) {
		built = ncfg_wire_build_request(out, kind, flags, seq, &body, &attrs, err,
		    err_size);
	}
	ncfg_buf_free(&body);
	ncfg_buf_free(&attrs);
	return built;
}

int ncfg_ops_add_rule(ncfg_buf_t *out, uint32_t seq, const ncfg_ops_rule_t *rule, char *err,
    size_t err_size)
{
	/* `EXCL` as well as `CREATE`: a rule is identified by priority and
	 * family, and quietly replacing one at the same priority would take out a
	 * rule netcfgd did not install. */
	return rule_request(out, RTM_NEWRULE,
	    (uint16_t)(NCFG_OPS_ACK_FLAGS | NLM_F_CREATE | NLM_F_EXCL), seq, rule, err,
	    err_size);
}

int ncfg_ops_del_rule(ncfg_buf_t *out, uint32_t seq, const ncfg_ops_rule_t *rule, char *err,
    size_t err_size)
{
	return rule_request(out, RTM_DELRULE, NCFG_OPS_ACK_FLAGS, seq, rule, err, err_size);
}
