/*
 * ops.h -- the mutating half of rtnetlink: the messages, not the sending.
 *
 * This is `crates/netcfgd-sys/src/ops.rs` and `rule.rs` in C: everything that
 * creates, changes or removes a link, an address, a route or a policy routing
 * rule. Every builder here turns a description into bytes and stops. The
 * socket is next door in `sys/socket.c`, and nothing in this file opens one,
 * holds one, or knows a sequence number it was not handed.
 *
 * **Why the split is worth having.** The Rust builds each request inside the
 * method that sends it, so the only way to know what netcfgd puts on the wire
 * is to have a kernel and root. Half the defects named in the comments below
 * were found that way, expensively -- a VXLAN whose underlay went in the outer
 * `IFLA_LINK`, where the kernel does not read it, and said nothing for as long
 * as VXLANs have existed. A builder that returns bytes is a builder a test can
 * read back attribute by attribute, on a laptop, with no privileges.
 *
 * EVERY REQUEST ASKS FOR AN ACKNOWLEDGEMENT
 *   `NLM_F_REQUEST | NLM_F_ACK` on all of them, so a failure surfaces as an
 *   errno at the call site rather than as state that quietly did not change.
 *   The flags are part of what a test asserts, because "it worked" and "the
 *   kernel never told us" look identical from here.
 *
 * WHAT A BUILDER TAKES, AND WHY IT IS THE MODEL'S TYPES
 *   `netcfgd-sys` in the Rust depends on nothing but libc, and holds its own
 *   `Option<u32>` and `IpAddr`. C has neither, and the port already has one of
 *   each: `ncfg_optint_t` in document.h for a number that may be absent, and
 *   `ncfg_wire_ip_t` in wire.h for an address in the form the wire carries.
 *   Inventing a second of either here is the divergence that would actually
 *   cost something -- two address types in one program is how a value gets
 *   byte-swapped on one path and not the other -- so this header includes the
 *   two and uses them. `ncfg_ops_ip_from_address` is the one conversion, for a
 *   caller holding the model's spelling-preserving `ncfg_address_t`.
 *
 *   **A number arrives as `int64_t` and leaves as what the field is.** The
 *   model stores every number at one width on purpose (document.h says why),
 *   so this module is where the narrowing happens, and it is checked rather
 *   than cast: a table of 1000 truncated to a byte is table 232, which is a
 *   real table belonging to somebody else. Out of range is a refusal with a
 *   sentence naming the field.
 *
 * WHERE THE NUMBERS COME FROM
 *   The kernel's own headers, as wire.h does. The Rust writes out sixty-odd
 *   attribute constants because `libc` exports almost none of them; every one
 *   of those was checked against `/usr/include/linux` during this port and all
 *   sixty agree, so copying them into C would be creating a second place for
 *   them to be wrong. The four that are still written out are in ops.c, each
 *   with the reason beside it.
 *
 * THE NUMBERING OF A MODE IS THE MODEL'S JOB, NOT THIS ONE'S
 *   A bond mode, a macvlan mode, a VLAN's ethertype and a tunnel's kind word
 *   arrive here already converted. That is the Rust's arrangement and the
 *   reason it gives is worth keeping: two lists of four numbers in two places
 *   is how a mode comes to mean one thing on the way out and another on the
 *   way back in, and the reader that has to agree with this writer lives with
 *   the model rather than with the wire.
 */
#ifndef NCFG_OPS_H
#define NCFG_OPS_H

#include <stddef.h>
#include <stdint.h>

/*
 * `FR_ACT_TO_TBL` and the three drop actions, which a caller chooses between.
 *
 * Included rather than copied: these are the only kernel constants a caller of
 * this header needs by name, and `linux/fib_rules.h` costs nothing here -- it
 * pulls in `linux/rtnetlink.h`, which wire.h has already.
 */
#include <linux/fib_rules.h>

#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/document.h"
#include "ncfg/value.h"
#include "ncfg/wire.h"

/*
 * An address that is not there.
 *
 * `ncfg_wire_ip_t` has a family, and `AF_UNSPEC` is a family no address has --
 * so absence is a value rather than a flag beside one. It is not a sentinel
 * anybody has to remember, either: `ncfg_wire_attr_put_ip` refuses a family it
 * does not recognise by failing the buffer, so an absent address that reaches
 * the encoder by mistake cannot be sent as anything.
 */
#define NCFG_OPS_IP_ABSENT { AF_UNSPEC, { 0 } }

/* Whether an address field carries an address at all. */
int ncfg_ops_ip_present(const ncfg_wire_ip_t *ip);

/* The family byte a payload carries for this address: `AF_INET` unless it is
 * plainly an IPv6 one, which is the Rust's `family_of` and its default. */
uint8_t ncfg_ops_family_byte(const ncfg_wire_ip_t *ip);

/*
 * The flags every request here carries. See the header comment: a request
 * without `NLM_F_ACK` fails silently, and "it worked" and "the kernel never
 * told us" are the same bytes from this side.
 */
#define NCFG_OPS_ACK_FLAGS ((uint16_t)(NLM_F_REQUEST | NLM_F_ACK))

/*
 * A model number narrowed to the width the wire gives its field.
 *
 * Call it where the value is present; `ceiling` is the largest the field
 * holds. Out of range is a refusal naming the field, never a cast -- rule.rs
 * says what the cast costs: "truncating instead would send table 1000 as table
 * 232", and table 232 is a real table belonging to somebody else.
 *
 * Public because this module is more than one source file, and because a
 * caller narrowing by hand is a caller narrowing with a cast.
 */
int ncfg_ops_narrow(ncfg_optint_t value, int64_t ceiling, const char *what, uint32_t *out,
    char *err, size_t err_size);

/*
 * The model's address as the wire wants it.
 *
 * `ncfg_address_t` keeps the prefix length and the spelling an operator wrote;
 * this takes the sixteen bytes, which are already network order in both types,
 * and the family. The prefix length is a separate argument everywhere it is
 * needed, because the kernel carries it in the family struct rather than
 * beside the address.
 */
int ncfg_ops_ip_from_address(const ncfg_address_t *address, ncfg_wire_ip_t *out,
    char *err, size_t err_size);

/* ------------------------------------------------------------------------ *
 * What kind of link to create
 *
 * Only the kinds this build can actually construct, as the Rust's `NewLink`
 * is. Anything else is refused by name rather than attempted and half made.
 * ------------------------------------------------------------------------ */

typedef enum {
	NCFG_OPS_LINK_BRIDGE,
	NCFG_OPS_LINK_DUMMY,
	NCFG_OPS_LINK_VLAN,
	NCFG_OPS_LINK_BOND,
	NCFG_OPS_LINK_VXLAN,
	/* An intermediate functional block, which exists to be redirected to.
	 * The kernel cannot shape traffic on the way in -- the packets have
	 * already arrived and there is no queue to hold them -- so received
	 * traffic is redirected onto one of these, where it becomes egress and
	 * can be queued like anything else. */
	NCFG_OPS_LINK_IFB,
	NCFG_OPS_LINK_VETH,
	NCFG_OPS_LINK_VRF,
	NCFG_OPS_LINK_MACVLAN,
	NCFG_OPS_LINK_TUNNEL,
	/* The link is ordinary rtnetlink; everything that makes it a tunnel --
	 * keys, peers, allowed IPs -- goes over generic netlink afterwards. */
	NCFG_OPS_LINK_WIREGUARD
} ncfg_ops_link_kind_t;

typedef struct {
	/* Index of the parent interface. A VLAN must have one. */
	uint32_t parent;
	uint16_t id;
	/* Tag protocol identifier, as an ethertype: 0x8100 or 0x88a8. */
	uint16_t protocol;
} ncfg_ops_vlan_t;

typedef struct {
	/* Bonding mode, as the kernel numbers them. */
	uint8_t       mode;
	/* Link monitoring interval in milliseconds. */
	ncfg_optint_t miimon;
} ncfg_ops_bond_t;

typedef struct {
	/* VXLAN network identifier. */
	uint32_t       id;
	/* Index of the underlay interface, where one is named. */
	ncfg_optint_t  parent;
	/* Source address for the outer header. */
	ncfg_wire_ip_t local;
	/* Remote unicast address, or the multicast group. */
	ncfg_wire_ip_t remote;
	/* Destination UDP port. */
	ncfg_optint_t  port;
} ncfg_ops_vxlan_t;

typedef struct {
	/* The name of the other end. Creating one end creates both. */
	const char *peer;
} ncfg_ops_veth_t;

typedef struct {
	/* The table its members' routes go into. */
	uint32_t table;
} ncfg_ops_vrf_t;

typedef struct {
	uint32_t parent;
	/* The kernel's mode number. */
	uint32_t mode;
} ncfg_ops_macvlan_t;

/*
 * What a point-to-point tunnel is made of.
 *
 * A struct rather than six loose fields, for the reason the Rust gives: the
 * encoder needs all of them, and two of the six are addresses of the same
 * type -- the pair a transposition would swap without the compiler noticing.
 */
typedef struct {
	/* The kernel's name for the encapsulation: `gre`, `gretap`, `ip6gre`,
	 * `ipip`, `sit`, `ip6tnl`, `geneve`. It decides the attribute numbering
	 * as well as the word sent in `IFLA_INFO_KIND`. */
	const char    *kind;
	/* Index of the underlay interface, where one is named. Sent inside the
	 * tunnel's own `INFO_DATA` nest, which is where the kernel reads it --
	 * not the outer `IFLA_LINK`, which it ignores. */
	ncfg_optint_t  parent;
	ncfg_wire_ip_t local;
	ncfg_wire_ip_t remote;
	/* Outer TTL. */
	ncfg_optint_t  ttl;
	/* GRE key, or a geneve tunnel's VNI, where the kind has one. */
	ncfg_optint_t  key;
} ncfg_ops_tunnel_t;

/*
 * A link to create, or to re-state to one that exists.
 *
 * Every arm, rather than a C union, which is document.h's choice and for its
 * reason: an arm added to the enum and missed somewhere is a compile the
 * compiler cannot help with, and the waste is a few dozen bytes on the stack.
 */
typedef struct {
	int                kind; /* ncfg_ops_link_kind_t */
	ncfg_ops_vlan_t    vlan;
	ncfg_ops_bond_t    bond;
	ncfg_ops_vxlan_t   vxlan;
	ncfg_ops_veth_t    veth;
	ncfg_ops_vrf_t     vrf;
	ncfg_ops_macvlan_t macvlan;
	ncfg_ops_tunnel_t  tunnel;
} ncfg_ops_newlink_t;

/* The word this kind goes on the wire as, in `IFLA_INFO_KIND`. NULL outside
 * the set, and NULL for a tunnel with no kind word -- value.h's convention,
 * and for its reason: a plausible word for a kind that is not one is worse
 * than no word. */
const char *ncfg_ops_link_kind_word(const ncfg_ops_newlink_t *link);

/* ------------------------------------------------------------------------ *
 * Links
 * ------------------------------------------------------------------------ */

/*
 * Create a link: `RTM_NEWLINK` with `CREATE | EXCL`.
 *
 * `out` is an initialised buffer and the whole request -- header, family
 * struct, attributes -- is appended to it, which is what
 * `ncfg_wire_build_request` does and there is no second convention here. The
 * caller frees it whether the build succeeded or not.
 */
int ncfg_ops_create_link(ncfg_buf_t *out, uint32_t seq, const char *name,
    const ncfg_ops_newlink_t *link, char *err, size_t err_size);

/*
 * Re-send a kind's own settings to a device that already exists.
 *
 * The same nest `ncfg_ops_create_link` builds, through the same function,
 * which is the property decision 0057 insisted on for a bridge: two encoders
 * for one kind is how the create path and the correct-an-existing path come to
 * disagree about what the kind is.
 *
 * **The whole nest, not the field that moved.** Measured, because the families
 * disagree: a request carrying only `IFLA_GRE_REMOTE` leaves a GRE tunnel with
 * no local address, no TTL and no key, since `ipgre_netlink_parms` starts from
 * a zeroed struct -- while a VXLAN and a geneve keep what the request leaves
 * out. `ip` hides this by reading the device and refilling every field before
 * it sends anything, so the obvious experiment says the kernel merges when it
 * does not.
 *
 * Not for a bridge or a bond: their settings are not part of the kind -- a
 * bridge takes none at creation -- and each has its own builder below.
 */
int ncfg_ops_set_link_kind(ncfg_buf_t *out, uint32_t seq, uint32_t index,
    const ncfg_ops_newlink_t *link, char *err, size_t err_size);

/* Delete a link: `RTM_DELLINK`. */
int ncfg_ops_delete_link(ncfg_buf_t *out, uint32_t seq, uint32_t index,
    char *err, size_t err_size);

/* Bring a link up or down. */
int ncfg_ops_set_link_up(ncfg_buf_t *out, uint32_t seq, uint32_t index, int up,
    char *err, size_t err_size);

int ncfg_ops_set_link_mtu(ncfg_buf_t *out, uint32_t seq, uint32_t index, uint32_t mtu,
    char *err, size_t err_size);

/* Set the hardware address. Six octets, as `ncfg_ops_parse_mac` produces. */
int ncfg_ops_set_link_mac(ncfg_buf_t *out, uint32_t seq, uint32_t index, const uint8_t mac[6],
    char *err, size_t err_size);

/* Enslave to a master, or release with index 0 -- which is how netlink spells
 * "no master". */
int ncfg_ops_set_link_master(ncfg_buf_t *out, uint32_t seq, uint32_t index, uint32_t master,
    char *err, size_t err_size);

/*
 * Give a link an alternative name: `RTM_NEWLINKPROP`.
 *
 * netcfgd stamps one on every link it creates, so that ownership is legible
 * from the kernel rather than only from `/run` -- decision 0136, which is
 * decision 0002's argument applied to the object kind that has no protocol
 * field to stamp.
 *
 * Its own message type, not an attribute on `RTM_NEWLINK`: the property list
 * is add-and-remove rather than set, and `IFLA_PROP_LIST` sent on an ordinary
 * `RTM_NEWLINK` is ignored -- the kind of silence that produces a marker
 * nobody notices is missing.
 *
 * A name outside 1 to `NCFG_WIRE_ALT_IFNAME_MAX - 1` bytes is refused here
 * rather than sent.
 */
int ncfg_ops_add_altname(ncfg_buf_t *out, uint32_t seq, uint32_t index, const char *altname,
    char *err, size_t err_size);

/* Bridge attributes, applied after creation. */
typedef struct {
	/* Spanning tree. */
	int           stp;
	/* In seconds, which is what every other tool and every piece of
	 * documentation uses. The kernel counts them in hundredths. */
	ncfg_optint_t forward_delay;
	ncfg_optint_t hello_time;
	/* Seconds here too, which is easy to miss: it is the one measured in
	 * minutes by habit. */
	ncfg_optint_t ageing_time;
	ncfg_optint_t priority;
	int           vlan_filtering;
} ncfg_ops_bridge_attrs_t;

/*
 * Set bridge attributes on an existing bridge.
 *
 * Separate from creation because they are separately reconcilable: a bridge
 * that exists with the wrong forward delay should be corrected, not deleted
 * and remade, and deleting a bridge takes its members down with it.
 */
int ncfg_ops_set_bridge_attrs(ncfg_buf_t *out, uint32_t seq, uint32_t index,
    const ncfg_ops_bridge_attrs_t *attrs, char *err, size_t err_size);

/*
 * Set a bond's mode and monitoring interval on a bond that exists.
 *
 * Either may be absent. The mode is left out where the caller says so, because
 * the kernel takes a mode only on a bond with no members and rejects the whole
 * message otherwise -- monitoring interval included.
 */
int ncfg_ops_set_bond_attrs(ncfg_buf_t *out, uint32_t seq, uint32_t index, ncfg_optint_t mode,
    ncfg_optint_t miimon, char *err, size_t err_size);

/*
 * One change to a bridge VLAN.
 *
 * A struct rather than five positional booleans: `set_bridge_vlan(i, 10, true,
 * true, false, true)` is a line nobody can read, and three of those five mean
 * something different if transposed.
 */
typedef struct {
	uint16_t vid;
	/* Untagged ingress joins this VLAN. */
	int      pvid;
	/* Egress leaves untagged. */
	int      untagged;
	/* The bridge device itself rather than a port. */
	int      on_self;
	/* Adding rather than removing. */
	int      add;
} ncfg_ops_vlan_change_t;

/*
 * Add or remove a VLAN on a bridge port, or on the bridge itself.
 *
 * `on_self` picks which, and getting it backwards is the mistake this
 * interface exists to make hard: a VLAN on a *port* is a MASTER operation,
 * because the bridge is being told what that port carries. A VLAN on the
 * *bridge device* is SELF, and is what lets the bridge terminate traffic in
 * that VLAN itself.
 */
int ncfg_ops_set_bridge_vlan(ncfg_buf_t *out, uint32_t seq, uint32_t index,
    const ncfg_ops_vlan_change_t *vlan, char *err, size_t err_size);

/*
 * Set the IPv6 interface identifier, or clear it with `::`.
 *
 * `ip token set ::5 dev eth0`. The prefix still comes from the router
 * advertisement; this fixes the host half, which is the only way to have a
 * predictable IPv6 address on a prefix that can change.
 *
 * The kernel is particular about when it will accept one, and each refusal is
 * `EINVAL` with nothing to distinguish it: the device must be up and ready, it
 * must accept router advertisements, and its router solicitation count must be
 * non-zero. A token on a device that forwards is therefore refused, because
 * forwarding turns RA acceptance off -- which is a real configuration somebody
 * will write, since a router is exactly the machine you want at a predictable
 * address.
 */
int ncfg_ops_set_ipv6_token(ncfg_buf_t *out, uint32_t seq, uint32_t index,
    const ncfg_wire_ip_t *token, char *err, size_t err_size);

/* ------------------------------------------------------------------------ *
 * Addresses
 * ------------------------------------------------------------------------ */

/*
 * Add an address, stamped with netcfgd's protocol tag.
 *
 * The tag is what makes the address ours for drift detection. A kernel before
 * 5.18 ignores the unknown attribute, which is exactly the read-back decision
 * 0002 relies on: the next dump says which happened.
 */
int ncfg_ops_add_address(ncfg_buf_t *out, uint32_t seq, uint32_t index,
    const ncfg_wire_ip_t *address, uint8_t prefix_len, uint8_t proto,
    char *err, size_t err_size);

/* Remove an address. No protocol tag: the kernel matches a delete on the
 * address, and `IFA_PROTO` on the way out is not part of that match. */
int ncfg_ops_del_address(ncfg_buf_t *out, uint32_t seq, uint32_t index,
    const ncfg_wire_ip_t *address, uint8_t prefix_len, char *err, size_t err_size);

/* ------------------------------------------------------------------------ *
 * Routes
 * ------------------------------------------------------------------------ */

/*
 * Everything needed to install or remove one route.
 *
 * **`proto` absent means netcfgd's own**, which document.h states as the
 * model's rule and this builder is where it is applied. Decision 0002: every
 * route netcfgd installs carries `rtm_protocol` 110, and that one byte is what
 * makes "remove only what netcfgd created" a question the kernel can answer.
 * Without it netcfgd would either delete an operator's static route or never
 * delete its own, and there is no third option -- a route carries no other
 * field that could say who put it there.
 *
 * `table` absent means `RT_TABLE_MAIN`, for document.h's reason: the kernel
 * always reports a table, so an unqualified route and a reported 254 are the
 * same route, and anything comparing the two has to normalise somewhere.
 */
typedef struct {
	/* Output interface index. */
	uint32_t       index;
	/* Destination, or absent for a default route. */
	ncfg_wire_ip_t destination;
	uint8_t        dst_len;
	/* Next hop. */
	ncfg_wire_ip_t gateway;
	ncfg_optint_t  metric;
	ncfg_optint_t  table;
	/* Preferred source. */
	ncfg_wire_ip_t source;
	/* Absent means `NCFG_WIRE_RTPROT_NETCFGD`. See above. */
	ncfg_optint_t  proto;
	/* Whether the gateway is reachable without a covering address. */
	int            onlink;
} ncfg_ops_route_t;

int ncfg_ops_add_route(ncfg_buf_t *out, uint32_t seq, const ncfg_ops_route_t *route,
    char *err, size_t err_size);
int ncfg_ops_del_route(ncfg_buf_t *out, uint32_t seq, const ncfg_ops_route_t *route,
    char *err, size_t err_size);

/* ------------------------------------------------------------------------ *
 * Policy routing rules
 *
 * A rule says *which routing table to consult*, before any table is consulted.
 * That is what makes source-based routing, VRFs and multi-uplink policy work.
 *
 * **Ownership comes from `FRA_PROTOCOL`**, exactly as it does for routes.
 * Decision 0002 stamps 110 on everything netcfgd installs and refuses to
 * delete anything not carrying it; rules get the same treatment from the same
 * constant.
 *
 * `FRA_PROTOCOL` arrived in Linux 4.17. On anything older the attribute is
 * ignored on the way in and absent on the way out, so every rule reads as
 * unowned and netcfgd installs but never removes. That is the safe direction,
 * and it is stated rather than discovered.
 * ------------------------------------------------------------------------ */

/*
 * One rule, as it goes out and comes back.
 *
 * The same type both ways, because a rule netcfgd installs and a rule it reads
 * have to be comparable field by field -- a separate "spec" and "record" pair
 * is two places for the comparison to drift.
 */
typedef struct {
	/* `AF_INET` or `AF_INET6`. Explicit rather than inferred from the
	 * selectors: the common shape has no address to infer from. */
	uint8_t        family;
	/* Consulted in ascending order. */
	uint32_t       priority;
	/* Which table to look up, for `FR_ACT_TO_TBL`. Zero means none, and no
	 * `FRA_TABLE` is sent. */
	uint32_t       table;
	/* What to do on a match: `FR_ACT_TO_TBL` and the three drop actions. */
	uint8_t        action;
	/* Source selector, with its prefix length. */
	ncfg_wire_ip_t from;
	uint8_t        from_len;
	/* Destination selector. */
	ncfg_wire_ip_t to;
	uint8_t        to_len;
	const char    *iif;
	const char    *oif;
	/* Firewall mark selector, and the mask applied before comparing it.
	 * netcfgd never sets a mark; routing on one somebody else set is what
	 * this is for. */
	ncfg_optint_t  fwmark;
	ncfg_optint_t  fwmask;
	/* Ignore routes shorter than this. Absent and zero are different
	 * answers: `suppress_prefixlength 0` is the whole `ip rule` trick. */
	ncfg_optint_t  suppress_prefixlength;
	/* Match packets belonging to an l3mdev master. */
	int            l3mdev;
	/* Invert the selectors. */
	int            invert;
	/* `FRA_PROTOCOL`. Absent means netcfgd's 110, as a route's does. */
	ncfg_optint_t  protocol;
} ncfg_ops_rule_t;

/* Install a rule: `RTM_NEWRULE` with `CREATE | EXCL`. `EEXIST` from the kernel
 * means a rule with this priority and family is already there. */
int ncfg_ops_add_rule(ncfg_buf_t *out, uint32_t seq, const ncfg_ops_rule_t *rule,
    char *err, size_t err_size);

/*
 * Remove a rule.
 *
 * The request carries `FRA_PROTOCOL`, and the kernel matches a delete against
 * every attribute it is given -- so a delete asking for protocol 110 cannot
 * match a rule that does not carry it. That is a second layer under the
 * planner's ownership check, at the kernel rather than in netcfgd, and it
 * means even a planner bug cannot remove somebody else's rule.
 *
 * Verified rather than assumed: a rule installed with protocol 0 survives a
 * delete sent with 110, and goes away when sent with 0.
 *
 * `ENOENT` from the kernel means it was already gone -- which is also what a
 * non-matching delete looks like, and the caller treats both as done.
 */
int ncfg_ops_del_rule(ncfg_buf_t *out, uint32_t seq, const ncfg_ops_rule_t *rule,
    char *err, size_t err_size);

/* ------------------------------------------------------------------------ *
 * Odds
 * ------------------------------------------------------------------------ */

/*
 * Parse `de:ad:be:ef:00:01` into six octets.
 *
 * Anything that is not six colon-separated hex octets is refused. Strict for
 * the reason value.h's strict hardware-address reader is strict, and this is
 * the kernel-facing half of the same job: what it produces goes in
 * `IFLA_ADDRESS`, where a wrong octet is a link with somebody else's address.
 */
int ncfg_ops_parse_mac(const char *text, uint8_t out[6], char *err, size_t err_size);

#endif /* NCFG_OPS_H */
