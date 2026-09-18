/*
 * ops.c -- building the rtnetlink messages that change things.
 *
 * `crates/netcfgd-sys/src/ops.rs` in C, less the sending: this file is the
 * links. The addresses, the routes and the rules are in ops_route.c -- the
 * last of those being `rule.rs` -- and the conversions both halves need are in
 * ops_value.c. See ops.h for what the split buys and for the conventions every
 * builder keeps.
 *
 * WHY ALMOST NOTHING IS WRITTEN OUT HERE
 *   The Rust writes out sixty-odd attribute numbers because `libc` exports
 *   almost none of them. C has the kernel's own headers, so they are included
 *   below rather than copied -- and every one of the Rust's sixty was checked
 *   against `/usr/include/linux` on the way past. All sixty agree, which
 *   includes `IFLA_GENEVE_TTL = 3`, the one its own comment says was wrong
 *   once in the writer and the reader at the same time and round-tripped.
 *
 *   One constant is still written out and the reason is not "libc does not
 *   have it": it is that the header carrying it would decide an include for
 *   every file that includes ours, or that its value is a trap to read. See
 *   `OPS_GRE_KEY_FLAG` and the include block below.
 */
#include "ncfg/ops.h"

#include <stdint.h>
#include <string.h>

/*
 * `linux/if.h`, for `IFF_UP`, and `linux/if_tunnel.h`, for the GRE and ip
 * tunnel attribute numbers.
 *
 * **Both are included here and never from ops.h.** `linux/if.h` and `net/if.h`
 * redefine each other's `struct ifreq` and `struct ifmap`, and a caller of
 * ops.h is very likely to want the second -- so pulling in the first through a
 * public header would decide that for them. wire.h refuses the same include
 * for the same reason and writes `ALTIFNAMSIZ` out instead. In a .c file
 * nothing is being decided for anybody.
 */
#include <linux/if.h>
#include <linux/if_bridge.h>
#include <linux/if_tunnel.h>
#include <linux/veth.h>

/*
 * `IFLA_INFO_DATA` is `linux/if_link.h`'s, through wire.h. So are the VLAN,
 * bridge, bond, VXLAN, VRF, macvlan and geneve numbers, `IFLA_AF_SPEC` and
 * `IFLA_INET6_TOKEN`; the bridge VLAN numbers are `linux/if_bridge.h`'s;
 * `VETH_INFO_PEER` is `linux/veth.h`'s; `RTN_UNICAST`, `RT_TABLE_MAIN`,
 * `RT_SCOPE_*` and `RTNH_F_ONLINK` are `linux/rtnetlink.h`'s.
 */

/*
 * `GRE_KEY`, the flag that says a key is present.
 *
 * `linux/if_tunnel.h` has it, and as `__cpu_to_be16(0x2000)` -- already
 * byte-swapped, so on this machine the macro's value is 0x0020 and on a
 * big-endian one it is 0x2000. That is correct for a field memcpy'd out, and
 * it is a trap for anybody who reads the constant and believes it. The value
 * is written here in the form a human recognises and swapped explicitly at the
 * one place it is sent, which is wire.h's rule about the two byte orders in
 * one message applied to a constant rather than to a field.
 *
 * GRE carries a key only if the corresponding flag bit is set in `IFLAGS` and
 * `OFLAGS`. Setting the key alone produces a tunnel that silently ignores it,
 * which is worse than an error: two ends configured with different keys would
 * pass traffic anyway.
 */
#define OPS_GRE_KEY_FLAG 0x2000u

/*
 * `IFF_UP` and the flag mask that goes with it.
 *
 * From `linux/if.h`, included above. Named here only to say what `change`
 * means: it is the mask of which flag bits a message sets, and omitting it is
 * how a request to bring one interface up silently clears every other flag.
 */
#define OPS_IFF_UP ((uint32_t)IFF_UP)

/*
 * The family byte in a netlink payload is the kernel's own numbering, which is
 * also libc's on Linux and need not be anywhere else. The Rust writes 2 and 10
 * literally; this asserts the two agree rather than picking one.
 */
_Static_assert(AF_INET == 2 && AF_INET6 == 10, "netlink wants the kernel's family numbers");

/*
 * The ownership mark, in the two places that have to agree.
 *
 * wire.h carries it because that module may depend on nothing but libc and the
 * kernel; document.h carries it because the model does. Decision 0002 fixes it
 * at 110 and the Rust keeps the two honest with a test in another crate. Here
 * it is a compile that fails, which is the cheapest form of the same check.
 */
_Static_assert(NCFG_WIRE_RTPROT_NETCFGD == NCFG_ROUTE_PROTO,
    "the wire and the model must stamp the same protocol on a route");

/*
 * An interface index as the kernel declares it: signed, and this one is not.
 *
 * The Rust writes `i32::try_from(index).unwrap_or(0)`, so an index above
 * `i32::MAX` becomes zero -- and zero is not a refusal on the way in, it is
 * "unspecified", which on an `RTM_DELLINK` is a message asking the kernel to
 * work out which link was meant. No machine has four billion interfaces, so
 * this has never fired; it is refused rather than clamped because a silent
 * zero is the one value that means something else.
 */
static int link_index(uint32_t index, int32_t *out, char *err, size_t err_size)
{
	if (index > (uint32_t)INT32_MAX) {
		ncfg_error_set(err, err_size,
		    "an interface index is signed on the wire and %lu does not fit it",
		    (unsigned long)index);
		return 0;
	}
	*out = (int32_t)index;
	return 1;
}

/*
 * A native-order integer attribute the wire layer has no call for.
 *
 * `memcpy` of the host representation, never shifts: an encoder that writes
 * the low byte first is correct on x86 and silently wrong on a big-endian
 * machine, where nothing here is tested. See wire.h.
 */
static void put_u16(ncfg_buf_t *out, uint16_t kind, uint16_t value)
{
	ncfg_wire_attr_put(out, kind, &value, sizeof(value));
}

/*
 * The other byte order, which some of these fields really are in.
 *
 * A VLAN's protocol is an ethertype, a VXLAN's port is a port number, and
 * GRE's flags and keys are header fields -- all of them big-endian wherever
 * they run. Written out a byte at a time so the result does not depend on the
 * machine, which is the same reason `put_u16` above does the opposite.
 */
static void put_be16(ncfg_buf_t *out, uint16_t kind, uint16_t value)
{
	uint8_t bytes[2];

	bytes[0] = (uint8_t)(value >> 8);
	bytes[1] = (uint8_t)(value & 0xffu);
	ncfg_wire_attr_put(out, kind, bytes, sizeof(bytes));
}

static void put_be32(ncfg_buf_t *out, uint16_t kind, uint32_t value)
{
	uint8_t bytes[4];

	bytes[0] = (uint8_t)(value >> 24);
	bytes[1] = (uint8_t)((value >> 16) & 0xffu);
	bytes[2] = (uint8_t)((value >> 8) & 0xffu);
	bytes[3] = (uint8_t)(value & 0xffu);
	ncfg_wire_attr_put(out, kind, bytes, sizeof(bytes));
}

/* An `ifinfomsg` body: the four fields every link message starts with. */
static int ifinfo_body(ncfg_buf_t *body, uint8_t family, uint32_t index, uint32_t flags,
    uint32_t change, char *err, size_t err_size)
{
	ncfg_wire_ifinfo_t info;

	if (!link_index(index, &info.index, err, err_size)) {
		return 0;
	}
	info.family = family;
	info.kind = 0;
	info.flags = flags;
	info.change = change;
	ncfg_wire_ifinfo_encode(&info, body);
	return 1;
}

/* A link message: `ifinfomsg` for this index, and the attributes given. */
static int link_request(ncfg_buf_t *out, uint16_t kind, uint16_t flags, uint32_t seq,
    uint32_t index, const ncfg_buf_t *attrs, char *err, size_t err_size)
{
	ncfg_buf_t body;
	int built;

	ncfg_buf_init(&body, 0);
	built = ifinfo_body(&body, 0, index, 0, 0, err, err_size) &&
	    ncfg_wire_build_request(out, kind, flags, seq, &body, attrs, err, err_size);
	ncfg_buf_free(&body);
	return built;
}

/* ------------------------------------------------------------------------ *
 * The `IFLA_INFO_DATA` nest
 * ------------------------------------------------------------------------ */

/*
 * The `INFO_DATA` for a tunnel.
 *
 * Its own function only because the three attribute families -- geneve, GRE
 * and the ip tunnels -- disagree about numbering, and saying so takes more
 * room than the code does. They do not share numbering, and assuming they did
 * is how the first version of this failed: GRE puts its flags and keys at 2..5
 * and the endpoints at 6 and 7, where an ip tunnel has the endpoints at 2 and
 * 3. Sending an ip tunnel's numbering to GRE puts the local address in
 * `IFLA_GRE_IFLAGS` and the kernel answers `EINVAL`.
 */
static int tunnel_data(ncfg_buf_t *data, const ncfg_ops_tunnel_t *tunnel, int changing,
    char *err, size_t err_size)
{
	uint32_t parent = 0;
	uint32_t key = 0;
	uint32_t ttl = 0;

	if (!tunnel->kind) {
		ncfg_error_set(err, err_size, "a tunnel has to say what encapsulation it is");
		return 0;
	}
	if (tunnel->parent.has &&
	    !ncfg_ops_narrow(tunnel->parent, UINT32_MAX, "an interface index", &parent, err, err_size)) {
		return 0;
	}
	if (tunnel->key.has && !ncfg_ops_narrow(tunnel->key, UINT32_MAX, "a tunnel key", &key, err,
	    err_size)) {
		return 0;
	}
	if (tunnel->ttl.has && !ncfg_ops_narrow(tunnel->ttl, UINT8_MAX, "a tunnel's TTL", &ttl, err,
	    err_size)) {
		return 0;
	}

	/*
	 * geneve numbers its attributes independently of the ip and GRE family,
	 * so it cannot share the block below -- and using the wrong numbers
	 * produces a tunnel the kernel accepts with the remote landing in a field
	 * that means something else.
	 */
	if (strcmp(tunnel->kind, "geneve") == 0) {
		/*
		 * A geneve tunnel has no underlay device: there is no attribute for
		 * one in its family, and `ip` offers no `dev` for it either. The
		 * Rust drops a parent here with `let _ = parent`, on the grounds
		 * that the compiler refused it first. This refuses it instead --
		 * quietly dropping a device somebody named is the shape of defect
		 * three comments in this file exist for, and a builder that can be
		 * called from anywhere should not rely on a check somewhere else.
		 */
		if (tunnel->parent.has) {
			ncfg_error_set(err, err_size,
			    "a geneve tunnel has no underlay device to name");
			return 0;
		}
		/*
		 * A geneve tunnel needs a VNI; the model has no separate field for
		 * one, so the tunnel key doubles as it. Named here because that
		 * reuse is not obvious from the config.
		 *
		 * Left out on a change, because the kernel refuses a VNI that
		 * differs and refuses it as the whole message -- which would take
		 * the remote beside it down too. A geneve keeps what a change
		 * request leaves out (measured), so omitting it is not the same as
		 * clearing it, and the planner is what says the VNI has moved.
		 */
		if (!changing) {
			ncfg_wire_attr_put_u32(data, IFLA_GENEVE_ID, key);
		}
		if (ncfg_ops_ip_present(&tunnel->remote)) {
			ncfg_wire_attr_put_ip(data,
			    tunnel->remote.family == AF_INET6 ? IFLA_GENEVE_REMOTE6
			                      : IFLA_GENEVE_REMOTE,
			    &tunnel->remote);
		}
		if (tunnel->ttl.has) {
			ncfg_wire_attr_put_u8(data, IFLA_GENEVE_TTL, (uint8_t)ttl);
		}
		return 1;
	}

	if (strstr(tunnel->kind, "gre")) {
		if (tunnel->parent.has) {
			ncfg_wire_attr_put_u32(data, IFLA_GRE_LINK, parent);
		}
		if (tunnel->key.has) {
			/* The flags first: a key with no flag bit is ignored, and
			 * two ends with different keys would then pass traffic as
			 * though neither had one. One key both ways -- separate in
			 * and out keys exist and nothing has asked for them. */
			put_be16(data, IFLA_GRE_IFLAGS, OPS_GRE_KEY_FLAG);
			put_be16(data, IFLA_GRE_OFLAGS, OPS_GRE_KEY_FLAG);
			put_be32(data, IFLA_GRE_IKEY, key);
			put_be32(data, IFLA_GRE_OKEY, key);
		}
		if (ncfg_ops_ip_present(&tunnel->local)) {
			ncfg_wire_attr_put_ip(data, IFLA_GRE_LOCAL, &tunnel->local);
		}
		if (ncfg_ops_ip_present(&tunnel->remote)) {
			ncfg_wire_attr_put_ip(data, IFLA_GRE_REMOTE, &tunnel->remote);
		}
		if (tunnel->ttl.has) {
			ncfg_wire_attr_put_u8(data, IFLA_GRE_TTL, (uint8_t)ttl);
		}
		return 1;
	}

	/*
	 * ipip, sit and ip6tnl. `IFLA_IPTUN_LINK` is the underlay device, in the
	 * nest for the reason a VXLAN's is: the kernel reads it from here and
	 * reports it in the outer `IFLA_LINK`, which is what makes `ip link show`
	 * print `tun0@base0` for a tunnel whose parent was never sent as an outer
	 * attribute.
	 */
	if (tunnel->parent.has) {
		ncfg_wire_attr_put_u32(data, IFLA_IPTUN_LINK, parent);
	}
	if (ncfg_ops_ip_present(&tunnel->local)) {
		ncfg_wire_attr_put_ip(data, IFLA_IPTUN_LOCAL, &tunnel->local);
	}
	if (ncfg_ops_ip_present(&tunnel->remote)) {
		ncfg_wire_attr_put_ip(data, IFLA_IPTUN_REMOTE, &tunnel->remote);
	}
	if (tunnel->ttl.has) {
		ncfg_wire_attr_put_u8(data, IFLA_IPTUN_TTL, (uint8_t)ttl);
	}
	return 1;
}

/* The peer's whole definition for a veth: an `ifinfomsg` followed by its own
 * attributes, nested inside this one. veth is the only link type created in
 * pairs and this is why its encoding looks unlike the others. */
static int veth_peer(ncfg_buf_t *data, const char *peer, char *err, size_t err_size)
{
	ncfg_buf_t nested;
	int built;

	if (!peer) {
		ncfg_error_set(err, err_size, "a veth needs the name of its other end");
		return 0;
	}
	ncfg_buf_init(&nested, 0);
	built = ifinfo_body(&nested, 0, 0, 0, 0, err, err_size);
	if (built) {
		ncfg_wire_attr_put_str(&nested, IFLA_IFNAME, peer);
		built = !ncfg_buf_failed(&nested);
		if (!built) {
			ncfg_error_set(err, err_size, "a veth peer's definition did not fit");
		}
	}
	if (built) {
		/*
		 * Plain, not `ncfg_wire_attr_put_nested`. The flag says "this value
		 * is a list of attributes", and this value is a struct with a list
		 * after it -- the one thing in this file that is nested without
		 * being a nest. `veth_policy` gives it `.len = sizeof(struct
		 * ifinfomsg)` rather than `NLA_NESTED` for the same reason.
		 */
		ncfg_wire_attr_put(data, VETH_INFO_PEER, nested.data, nested.length);
	}
	ncfg_buf_free(&nested);
	return built;
}

/*
 * The `IFLA_INFO_DATA` nest for this kind, where it has one.
 *
 * `changing` says whether this nest is for a device that already exists. Three
 * attributes come out when it is set, and every one was measured rather than
 * assumed: a VXLAN's `port`, which the kernel refuses **whether or not the
 * value differs** -- `vxlan_nl2conf` answers `EOPNOTSUPP` on the attribute's
 * presence, so a nest carrying it can never correct a remote -- and a VXLAN's
 * `id` and a geneve tunnel's, which are refused when they differ and would
 * take the endpoint beside them down with them. Decision 0058.
 *
 * `*present` says whether the kind has a nest at all.
 */
static int info_data(ncfg_buf_t *data, const ncfg_ops_newlink_t *link, int changing,
    int *present, char *err, size_t err_size)
{
	uint32_t number = 0;

	*present = 1;
	switch (link->kind) {
	case NCFG_OPS_LINK_BRIDGE:
	case NCFG_OPS_LINK_DUMMY:
	case NCFG_OPS_LINK_WIREGUARD:
	case NCFG_OPS_LINK_IFB:
		*present = 0;
		return 1;
	case NCFG_OPS_LINK_VLAN:
		/* Native order: the id is an integer the kernel reads as one. */
		put_u16(data, IFLA_VLAN_ID, link->vlan.id);
		/*
		 * Big-endian: it is an ethertype, and the kernel reads it as one.
		 * Sending it native-endian is refused outright -- the kernel knows
		 * only 0x8100 and 0x88a8 and rejects the byte-swapped values -- so
		 * this fails loudly rather than producing a link that tags with
		 * nonsense. Verified by sending the wrong one.
		 */
		put_be16(data, IFLA_VLAN_PROTOCOL, link->vlan.protocol);
		break;
	case NCFG_OPS_LINK_BOND:
		ncfg_wire_attr_put_u8(data, IFLA_BOND_MODE, link->bond.mode);
		if (link->bond.miimon.has) {
			if (!ncfg_ops_narrow(link->bond.miimon, UINT32_MAX, "a bond's miimon", &number,
			    err, err_size)) {
				return 0;
			}
			ncfg_wire_attr_put_u32(data, IFLA_BOND_MIIMON, number);
		}
		break;
	case NCFG_OPS_LINK_VXLAN:
		/*
		 * Left out on a change, for the reason the port below is and with
		 * one difference: the kernel refuses a VNI only when the value
		 * differs, so restating the current one would work. It is omitted
		 * anyway, because a VXLAN keeps what a change request leaves out
		 * (measured) and because sending a value whose only acceptable form
		 * is "the same as now" says nothing.
		 */
		if (!changing) {
			ncfg_wire_attr_put_u32(data, IFLA_VXLAN_ID, link->vxlan.id);
		}
		/*
		 * The underlay, which goes **here and not in the outer
		 * `IFLA_LINK`**. Measured, after the outer one was sent for as long
		 * as VXLANs have existed and did nothing at all: `vxlan_nl2conf`
		 * reads `data[IFLA_VXLAN_LINK]` and nothing reads `tb[IFLA_LINK]`,
		 * so a document naming a parent got a VXLAN whose outer packets the
		 * kernel routed itself. `ip` shows the difference in one word -- its
		 * VXLAN says `dev base0` and netcfgd's said nothing.
		 *
		 * The kernel takes it on a change too, so this one is not
		 * conditional on `changing`.
		 */
		if (link->vxlan.parent.has) {
			if (!ncfg_ops_narrow(link->vxlan.parent, UINT32_MAX, "an interface index",
			    &number, err, err_size)) {
				return 0;
			}
			ncfg_wire_attr_put_u32(data, IFLA_VXLAN_LINK, number);
		}
		/* The v4 and v6 attributes are different numbers, so the family
		 * decides which one is sent rather than the value being coerced into
		 * a single field. */
		if (ncfg_ops_ip_present(&link->vxlan.local)) {
			ncfg_wire_attr_put_ip(data,
			    link->vxlan.local.family == AF_INET6 ? IFLA_VXLAN_LOCAL6
			                     : IFLA_VXLAN_LOCAL,
			    &link->vxlan.local);
		}
		if (ncfg_ops_ip_present(&link->vxlan.remote)) {
			ncfg_wire_attr_put_ip(data,
			    link->vxlan.remote.family == AF_INET6 ? IFLA_VXLAN_GROUP6
			                      : IFLA_VXLAN_GROUP,
			    &link->vxlan.remote);
		}
		/* Only when the device is being made. On a change the kernel
		 * refuses this attribute's presence outright, at any value, and
		 * takes the whole message down with it. */
		if (link->vxlan.port.has && !changing) {
			if (!ncfg_ops_narrow(link->vxlan.port, UINT16_MAX, "a VXLAN's port", &number,
			    err, err_size)) {
				return 0;
			}
			/* Big-endian, like every port number on the wire. */
			put_be16(data, IFLA_VXLAN_PORT, (uint16_t)number);
		}
		break;
	case NCFG_OPS_LINK_VRF:
		ncfg_wire_attr_put_u32(data, IFLA_VRF_TABLE, link->vrf.table);
		break;
	case NCFG_OPS_LINK_MACVLAN:
		ncfg_wire_attr_put_u32(data, IFLA_MACVLAN_MODE, link->macvlan.mode);
		break;
	case NCFG_OPS_LINK_TUNNEL:
		return tunnel_data(data, &link->tunnel, changing, err, err_size);
	case NCFG_OPS_LINK_VETH:
		return veth_peer(data, link->veth.peer, err, err_size);
	default:
		ncfg_error_set(err, err_size, "%d is not a link kind this build can create",
		    link->kind);
		return 0;
	}
	return 1;
}

const char *ncfg_ops_link_kind_word(const ncfg_ops_newlink_t *link)
{
	if (!link) {
		return NULL;
	}
	switch (link->kind) {
	case NCFG_OPS_LINK_BRIDGE:
		return "bridge";
	case NCFG_OPS_LINK_DUMMY:
		return "dummy";
	case NCFG_OPS_LINK_VLAN:
		return "vlan";
	case NCFG_OPS_LINK_BOND:
		return "bond";
	case NCFG_OPS_LINK_VXLAN:
		return "vxlan";
	case NCFG_OPS_LINK_IFB:
		return "ifb";
	case NCFG_OPS_LINK_VETH:
		return "veth";
	case NCFG_OPS_LINK_WIREGUARD:
		/* The language spells this `wireguard` and the document spells it
		 * `wire_guard`; the kernel's word is the first, and it is the one
		 * this project has already shipped wrong twice. */
		return "wireguard";
	case NCFG_OPS_LINK_VRF:
		return "vrf";
	case NCFG_OPS_LINK_MACVLAN:
		return "macvlan";
	case NCFG_OPS_LINK_TUNNEL:
		return link->tunnel.kind;
	default:
		/* value.h's convention: a plausible word for a kind that is not one
		 * is worse than no word. */
		return NULL;
	}
}

/*
 * The `IFLA_LINKINFO` nest: the kind's word, and its own data where it has
 * any. One function for creation and for correction, which is the property
 * decision 0057 insisted on -- two encoders for one kind is how the two paths
 * come to disagree about what the kind is.
 */
static int link_info(ncfg_buf_t *info, const ncfg_ops_newlink_t *link, int changing,
    char *err, size_t err_size)
{
	const char *word = ncfg_ops_link_kind_word(link);
	ncfg_buf_t data;
	int present = 0;
	int built;

	if (!word) {
		ncfg_error_set(err, err_size, "%d is not a link kind this build can create",
		    link->kind);
		return 0;
	}
	ncfg_wire_attr_put_str(info, IFLA_INFO_KIND, word);
	ncfg_buf_init(&data, 0);
	built = info_data(&data, link, changing, &present, err, err_size);
	if (built && present) {
		/* A nest that failed to build is not an empty nest, and
		 * `ncfg_wire_attr_put_nested` carries that failure out rather than
		 * appending the empty string a failed buffer hands back. */
		ncfg_wire_attr_put_nested(info, IFLA_INFO_DATA, &data);
	}
	ncfg_buf_free(&data);
	if (built && ncfg_buf_failed(info)) {
		ncfg_error_set(err, err_size, "the link information for a %s did not fit", word);
		built = 0;
	}
	return built;
}

/* ------------------------------------------------------------------------ *
 * Links
 * ------------------------------------------------------------------------ */

int ncfg_ops_create_link(ncfg_buf_t *out, uint32_t seq, const char *name,
    const ncfg_ops_newlink_t *link, char *err, size_t err_size)
{
	ncfg_buf_t info;
	ncfg_buf_t attrs;
	ncfg_buf_t body;
	int built;

	if (!out || !name || !link) {
		ncfg_error_set(err, err_size, "creating a link needs a name and a kind");
		return 0;
	}
	ncfg_buf_init(&info, 0);
	ncfg_buf_init(&attrs, 0);
	ncfg_buf_init(&body, 0);
	built = link_info(&info, link, 0, err, err_size);
	if (built) {
		ncfg_wire_attr_put_str(&attrs, IFLA_IFNAME, name);
		/*
		 * The parent a virtual link rides on -- for the two kinds that read
		 * it here. A VLAN must have one and a macvlan must have one, and
		 * both take it as the outer `IFLA_LINK`.
		 *
		 * A VXLAN and a tunnel do not: their underlay is an attribute inside
		 * their own `INFO_DATA` nest, and the outer one is ignored. It was
		 * sent there for as long as both kinds have existed, so
		 * `parent = "base0"` on either produced a device with no underlay at
		 * all and nothing said so.
		 */
		if (link->kind == NCFG_OPS_LINK_VLAN) {
			ncfg_wire_attr_put_u32(&attrs, IFLA_LINK, link->vlan.parent);
		} else if (link->kind == NCFG_OPS_LINK_MACVLAN) {
			ncfg_wire_attr_put_u32(&attrs, IFLA_LINK, link->macvlan.parent);
		}
		ncfg_wire_attr_put_nested(&attrs, IFLA_LINKINFO, &info);
		/* Index zero and no flags: the kernel is being asked to make one,
		 * not to find one. */
		built = ifinfo_body(&body, 0, 0, 0, 0, err, err_size) &&
		    ncfg_wire_build_request(out, RTM_NEWLINK,
		    (uint16_t)(NCFG_OPS_ACK_FLAGS | NLM_F_CREATE | NLM_F_EXCL), seq, &body,
		    &attrs, err, err_size);
	}
	ncfg_buf_free(&info);
	ncfg_buf_free(&attrs);
	ncfg_buf_free(&body);
	return built;
}

int ncfg_ops_set_link_kind(ncfg_buf_t *out, uint32_t seq, uint32_t index,
    const ncfg_ops_newlink_t *link, char *err, size_t err_size)
{
	ncfg_buf_t info;
	ncfg_buf_t attrs;
	int built;

	if (!out || !link) {
		ncfg_error_set(err, err_size, "re-stating a link's kind needs a kind");
		return 0;
	}
	ncfg_buf_init(&info, 0);
	ncfg_buf_init(&attrs, 0);
	built = link_info(&info, link, 1, err, err_size);
	if (built) {
		ncfg_wire_attr_put_nested(&attrs, IFLA_LINKINFO, &info);
		built = link_request(out, RTM_NEWLINK, NCFG_OPS_ACK_FLAGS, seq, index, &attrs, err,
		    err_size);
	}
	ncfg_buf_free(&info);
	ncfg_buf_free(&attrs);
	return built;
}

int ncfg_ops_delete_link(ncfg_buf_t *out, uint32_t seq, uint32_t index, char *err,
    size_t err_size)
{
	return link_request(out, RTM_DELLINK, NCFG_OPS_ACK_FLAGS, seq, index, NULL, err, err_size);
}

int ncfg_ops_set_link_up(ncfg_buf_t *out, uint32_t seq, uint32_t index, int up, char *err,
    size_t err_size)
{
	ncfg_buf_t body;
	int built;

	ncfg_buf_init(&body, 0);
	/* `change` is the mask of which flag bits this message sets, and omitting
	 * it is how a request to bring one interface up silently clears every
	 * other flag. */
	built = ifinfo_body(&body, 0, index, up ? OPS_IFF_UP : 0, OPS_IFF_UP, err, err_size) &&
	    ncfg_wire_build_request(out, RTM_NEWLINK, NCFG_OPS_ACK_FLAGS, seq, &body, NULL, err,
	    err_size);
	ncfg_buf_free(&body);
	return built;
}

int ncfg_ops_set_link_mtu(ncfg_buf_t *out, uint32_t seq, uint32_t index, uint32_t mtu,
    char *err, size_t err_size)
{
	ncfg_buf_t attrs;
	int built;

	ncfg_buf_init(&attrs, 0);
	ncfg_wire_attr_put_u32(&attrs, IFLA_MTU, mtu);
	built = link_request(out, RTM_NEWLINK, NCFG_OPS_ACK_FLAGS, seq, index, &attrs, err, err_size);
	ncfg_buf_free(&attrs);
	return built;
}

int ncfg_ops_set_link_mac(ncfg_buf_t *out, uint32_t seq, uint32_t index, const uint8_t mac[6],
    char *err, size_t err_size)
{
	ncfg_buf_t attrs;
	int built;

	if (!mac) {
		ncfg_error_set(err, err_size, "setting a hardware address needs one");
		return 0;
	}
	ncfg_buf_init(&attrs, 0);
	ncfg_wire_attr_put(&attrs, IFLA_ADDRESS, mac, 6u);
	built = link_request(out, RTM_NEWLINK, NCFG_OPS_ACK_FLAGS, seq, index, &attrs, err, err_size);
	ncfg_buf_free(&attrs);
	return built;
}

int ncfg_ops_set_link_master(ncfg_buf_t *out, uint32_t seq, uint32_t index, uint32_t master,
    char *err, size_t err_size)
{
	ncfg_buf_t attrs;
	int built;

	ncfg_buf_init(&attrs, 0);
	/* Master index zero is how netlink spells "no master", so a release is
	 * this same message with a zero rather than a different one. */
	ncfg_wire_attr_put_u32(&attrs, IFLA_MASTER, master);
	built = link_request(out, RTM_NEWLINK, NCFG_OPS_ACK_FLAGS, seq, index, &attrs, err, err_size);
	ncfg_buf_free(&attrs);
	return built;
}

int ncfg_ops_add_altname(ncfg_buf_t *out, uint32_t seq, uint32_t index, const char *altname,
    char *err, size_t err_size)
{
	ncfg_buf_t props;
	ncfg_buf_t attrs;
	size_t length;
	int built;

	if (!altname) {
		ncfg_error_set(err, err_size, "an alternative name is a name");
		return 0;
	}
	length = strlen(altname);
	if (length == 0 || length >= NCFG_WIRE_ALT_IFNAME_MAX) {
		ncfg_error_set(err, err_size,
		    "an alternative name must be 1 to %u bytes, not %zu",
		    (unsigned)(NCFG_WIRE_ALT_IFNAME_MAX - 1u), length);
		return 0;
	}
	ncfg_buf_init(&props, 0);
	ncfg_buf_init(&attrs, 0);
	ncfg_wire_attr_put_str(&props, IFLA_ALT_IFNAME, altname);
	/*
	 * `IFLA_PROP_LIST` is the one nest netcfgd met the strict parser on:
	 * `RTM_NEWLINKPROP` is a newer message type and rejects a nest without
	 * `NLA_F_NESTED` with `EINVAL`, saying nothing about nesting. See wire.h,
	 * which sets the flag on every nest rather than per message type.
	 */
	ncfg_wire_attr_put_nested(&attrs, IFLA_PROP_LIST, &props);
	built = link_request(out, RTM_NEWLINKPROP, NCFG_OPS_ACK_FLAGS, seq, index, &attrs, err,
	    err_size);
	ncfg_buf_free(&props);
	ncfg_buf_free(&attrs);
	return built;
}

/* A `LINKINFO` nest carrying one kind's `INFO_DATA`, wrapped and sent to an
 * index. The three attribute setters below differ only in what goes in the
 * nest. */
static int kind_data_request(ncfg_buf_t *out, uint32_t seq, uint32_t index, const char *word,
    const ncfg_buf_t *data, char *err, size_t err_size)
{
	ncfg_buf_t info;
	ncfg_buf_t attrs;
	int built;

	ncfg_buf_init(&info, 0);
	ncfg_buf_init(&attrs, 0);
	ncfg_wire_attr_put_str(&info, IFLA_INFO_KIND, word);
	ncfg_wire_attr_put_nested(&info, IFLA_INFO_DATA, data);
	ncfg_wire_attr_put_nested(&attrs, IFLA_LINKINFO, &info);
	built = link_request(out, RTM_NEWLINK, NCFG_OPS_ACK_FLAGS, seq, index, &attrs, err, err_size);
	ncfg_buf_free(&info);
	ncfg_buf_free(&attrs);
	return built;
}

/*
 * Seconds as the kernel counts them.
 *
 * The kernel counts a bridge's timers in hundredths of a second and the config
 * counts them in seconds, because that is what every other tool and every
 * piece of documentation uses. Saturating rather than wrapping, as the Rust
 * does: a value that large is not a duration anybody typed, and the kernel
 * refuses it either way -- but a wrap would refuse it as some other number.
 */
static uint32_t centiseconds(uint32_t seconds)
{
	if (seconds > UINT32_MAX / 100u) {
		return UINT32_MAX;
	}
	return seconds * 100u;
}

int ncfg_ops_set_bridge_attrs(ncfg_buf_t *out, uint32_t seq, uint32_t index,
    const ncfg_ops_bridge_attrs_t *attrs, char *err, size_t err_size)
{
	ncfg_buf_t data;
	uint32_t number = 0;
	int built = 1;

	if (!attrs) {
		ncfg_error_set(err, err_size, "setting a bridge's attributes needs some");
		return 0;
	}
	ncfg_buf_init(&data, 0);
	ncfg_wire_attr_put_u32(&data, IFLA_BR_STP_STATE, attrs->stp ? 1u : 0u);
	if (built && attrs->forward_delay.has) {
		built = ncfg_ops_narrow(attrs->forward_delay, UINT32_MAX, "a bridge's forward delay",
		    &number, err, err_size);
		if (built) {
			ncfg_wire_attr_put_u32(&data, IFLA_BR_FORWARD_DELAY,
			    centiseconds(number));
		}
	}
	if (built && attrs->hello_time.has) {
		built = ncfg_ops_narrow(attrs->hello_time, UINT32_MAX, "a bridge's hello time", &number,
		    err, err_size);
		if (built) {
			ncfg_wire_attr_put_u32(&data, IFLA_BR_HELLO_TIME, centiseconds(number));
		}
	}
	/* Seconds here too, which is easy to miss: it is the one measured in
	 * minutes by habit. */
	if (built && attrs->ageing_time.has) {
		built = ncfg_ops_narrow(attrs->ageing_time, UINT32_MAX, "a bridge's ageing time",
		    &number, err, err_size);
		if (built) {
			ncfg_wire_attr_put_u32(&data, IFLA_BR_AGEING_TIME, centiseconds(number));
		}
	}
	if (built && attrs->priority.has) {
		built = ncfg_ops_narrow(attrs->priority, UINT16_MAX, "a bridge's priority", &number, err,
		    err_size);
		if (built) {
			/* Native order, unlike the ethertype above: this one is a
			 * number rather than a header field. */
			put_u16(&data, IFLA_BR_PRIORITY, (uint16_t)number);
		}
	}
	if (built) {
		ncfg_wire_attr_put_u8(&data, IFLA_BR_VLAN_FILTERING,
		    attrs->vlan_filtering ? 1u : 0u);
		built = kind_data_request(out, seq, index, "bridge", &data, err, err_size);
	}
	ncfg_buf_free(&data);
	return built;
}

int ncfg_ops_set_bond_attrs(ncfg_buf_t *out, uint32_t seq, uint32_t index, ncfg_optint_t mode,
    ncfg_optint_t miimon, char *err, size_t err_size)
{
	ncfg_buf_t data;
	uint32_t number = 0;
	int built = 1;

	ncfg_buf_init(&data, 0);
	/* Left out where the caller says so, because the kernel takes a mode only
	 * on a bond with no members and rejects the whole message otherwise --
	 * monitoring interval included. */
	if (mode.has) {
		built = ncfg_ops_narrow(mode, UINT8_MAX, "a bond's mode", &number, err, err_size);
		if (built) {
			ncfg_wire_attr_put_u8(&data, IFLA_BOND_MODE, (uint8_t)number);
		}
	}
	if (built && miimon.has) {
		built = ncfg_ops_narrow(miimon, UINT32_MAX, "a bond's miimon", &number, err, err_size);
		if (built) {
			ncfg_wire_attr_put_u32(&data, IFLA_BOND_MIIMON, number);
		}
	}
	if (built) {
		built = kind_data_request(out, seq, index, "bond", &data, err, err_size);
	}
	ncfg_buf_free(&data);
	return built;
}

int ncfg_ops_set_bridge_vlan(ncfg_buf_t *out, uint32_t seq, uint32_t index,
    const ncfg_ops_vlan_change_t *vlan, char *err, size_t err_size)
{
	ncfg_buf_t spec;
	ncfg_buf_t attrs;
	ncfg_buf_t body;
	uint8_t info[4];
	uint16_t flags = 0;
	int built;

	if (!vlan) {
		ncfg_error_set(err, err_size, "changing a bridge VLAN needs a change");
		return 0;
	}
	ncfg_buf_init(&spec, 0);
	ncfg_buf_init(&attrs, 0);
	ncfg_buf_init(&body, 0);
	put_u16(&spec, IFLA_BRIDGE_FLAGS,
	    (uint16_t)(vlan->on_self ? BRIDGE_FLAGS_SELF : BRIDGE_FLAGS_MASTER));

	if (vlan->pvid) {
		flags |= (uint16_t)BRIDGE_VLAN_INFO_PVID;
	}
	if (vlan->untagged) {
		flags |= (uint16_t)BRIDGE_VLAN_INFO_UNTAGGED;
	}
	/*
	 * `struct bridge_vlan_info { __u16 flags; __u16 vid; }`, in that order.
	 * Two little integers, and swapping them produces a request for VLAN 0
	 * with nonsense flags that the kernel may well accept.
	 *
	 * Built as two native `u16`s rather than as the struct, so that the
	 * padding rules of a C compiler are not part of what goes on the wire.
	 */
	memcpy(info, &flags, sizeof(flags));
	memcpy(info + sizeof(flags), &vlan->vid, sizeof(vlan->vid));
	ncfg_wire_attr_put(&spec, IFLA_BRIDGE_VLAN_INFO, info, sizeof(info));

	ncfg_wire_attr_put_nested(&attrs, IFLA_AF_SPEC, &spec);
	built = ifinfo_body(&body, (uint8_t)AF_BRIDGE, index, 0, 0, err, err_size) &&
	    ncfg_wire_build_request(out, (uint16_t)(vlan->add ? RTM_SETLINK : RTM_DELLINK),
	    NCFG_OPS_ACK_FLAGS, seq, &body, &attrs, err, err_size);
	ncfg_buf_free(&spec);
	ncfg_buf_free(&attrs);
	ncfg_buf_free(&body);
	return built;
}

int ncfg_ops_set_ipv6_token(ncfg_buf_t *out, uint32_t seq, uint32_t index,
    const ncfg_wire_ip_t *token, char *err, size_t err_size)
{
	ncfg_buf_t inet6;
	ncfg_buf_t spec;
	ncfg_buf_t attrs;
	ncfg_buf_t body;
	int built;

	/*
	 * An IPv6 interface identifier is sixteen bytes and there is no other
	 * kind. The Rust takes an `IpAddr` and would put four bytes in
	 * `IFLA_INET6_TOKEN`, where `inet6_af_policy` requires the length of a
	 * `struct in6_addr` -- so the kernel refuses it with the same bare
	 * `EINVAL` every other refusal of a token uses, and the operator is told
	 * their device is not ready when what happened is that somebody wrote an
	 * IPv4 address. Refused here, where the sentence can say which.
	 */
	if (!ncfg_ops_ip_present(token) || token->family != AF_INET6) {
		ncfg_error_set(err, err_size,
		    "an IPv6 token is an IPv6 address, and this is not one");
		return 0;
	}
	ncfg_buf_init(&inet6, 0);
	ncfg_buf_init(&spec, 0);
	ncfg_buf_init(&attrs, 0);
	ncfg_buf_init(&body, 0);
	ncfg_wire_attr_put_ip(&inet6, IFLA_INET6_TOKEN, token);
	/* The family is the attribute *type* here, not a field: `IFLA_AF_SPEC`
	 * holds one nest per address family, keyed by the family number. */
	ncfg_wire_attr_put_nested(&spec, (uint16_t)AF_INET6, &inet6);
	ncfg_wire_attr_put_nested(&attrs, IFLA_AF_SPEC, &spec);
	built = ifinfo_body(&body, 0, index, 0, 0, err, err_size) &&
	    ncfg_wire_build_request(out, RTM_SETLINK, NCFG_OPS_ACK_FLAGS, seq, &body, &attrs, err,
	    err_size);
	ncfg_buf_free(&inet6);
	ncfg_buf_free(&spec);
	ncfg_buf_free(&attrs);
	ncfg_buf_free(&body);
	return built;
}
