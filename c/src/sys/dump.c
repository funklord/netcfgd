/*
 * dump.c -- the facts a dump carries, out of the structures `wire.c` returns.
 *
 * No descriptor is opened, read or closed in this file. Everything takes bytes
 * the caller already has, which is what lets every case below be tested
 * against captured bytes with no kernel, no privilege and no hardware in
 * sight -- and what makes `socket.c` next door the only place a syscall can
 * hide.
 *
 * THE RULE THIS FILE FOLLOWS ABOUT ABSENCE, WHICH IS NOT ONE RULE
 *   * An attribute the kernel did not send is absent, and absence is ordinary:
 *     a plain ethernet device has no link kind, a kernel older than 5.18 has
 *     no `IFA_PROTO`.
 *   * An attribute of the wrong width is absent too, deliberately. `wire.c`
 *     refuses a value of the wrong size rather than truncating it, and reading
 *     one with the wrong accessor has to fail loudly or it returns a number
 *     that is merely wrong. The bridge priority below is the case that proves
 *     it: two bytes read as four, absent on every kernel, always.
 *   * An attribute *area* that does not make sense refuses the whole record.
 *     The Rust stops its iterator and keeps what it had, which reads a
 *     truncated message as a finished one; the wire layer exists to refuse
 *     that confusion, so a malformed area here is a message to throw away.
 *   * And an all-zero endpoint is the kernel's way of spelling "none" in an
 *     attribute it always sends. Read as absence rather than as the address
 *     `0.0.0.0`, which no document can ask for and nothing would ever match.
 */
#include "ncfg/netlink.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <linux/if_bridge.h>
#include <linux/if_tunnel.h>

/*
 * `GRE_KEY`, the flag bit that says a GRE tunnel's key field means anything.
 *
 * Written out rather than taken from `linux/if_tunnel.h`, which is the one
 * place in this port where the kernel's own constant is the wrong one: the
 * header's `GRE_KEY` is already byte-swapped for the wire, and the flags word
 * here has been read back into host order first. Using the kernel's would
 * compare a host value against a big-endian mask -- correct on nothing, and
 * silently correct-looking on a big-endian machine.
 */
#define NCFG_GRE_KEY_FLAG 0x2000u

/* `AF_INET6` as an attribute *type* inside `IFLA_AF_SPEC`, which is where the
 * per-device IPv6 settings hang. Not an address family in this position, which
 * is why it is not spelled `AF_INET6` at the use site. */
#define NCFG_AF_SPEC_INET6 10u

/* ------------------------------------------------------------------------ */
/* Reading one attribute out of an area.                                    */
/* ------------------------------------------------------------------------ */

/*
 * Find an attribute, distinguishing "not there" from "the area is nonsense".
 *
 * Returns 0 only for the second, with `err` set: a missing `IFA_PROTO` is a
 * kernel older than 5.18 and a missing `IFLA_INFO_KIND` is an ethernet card,
 * while a malformed area is a message nothing should be decoded out of.
 */
static int area_find(const ncfg_wire_attrs_t *area, uint16_t kind, ncfg_wire_attr_t *out,
    int *found, char *err, size_t err_size)
{
	ncfg_wire_step_t step = ncfg_wire_attrs_find(area, kind, out, err, err_size);

	*found = (step == NCFG_WIRE_OK);
	return step != NCFG_WIRE_BAD;
}

static int area_u8(const ncfg_wire_attrs_t *area, uint16_t kind, uint8_t *value, int *found,
    char *err, size_t err_size)
{
	ncfg_wire_attr_t attr;
	int              present = 0;

	*found = 0;
	if (!area_find(area, kind, &attr, &present, err, err_size)) {
		return 0;
	}
	if (!present || !ncfg_wire_attr_u8(&attr, value, NULL, 0)) {
		return 1;
	}
	*found = 1;
	return 1;
}

static int area_u16(const ncfg_wire_attrs_t *area, uint16_t kind, uint16_t *value, int *found,
    char *err, size_t err_size)
{
	ncfg_wire_attr_t attr;
	int              present = 0;

	*found = 0;
	if (!area_find(area, kind, &attr, &present, err, err_size)) {
		return 0;
	}
	if (!present || !ncfg_wire_attr_u16(&attr, value, NULL, 0)) {
		return 1;
	}
	*found = 1;
	return 1;
}

static int area_u32(const ncfg_wire_attrs_t *area, uint16_t kind, uint32_t *value, int *found,
    char *err, size_t err_size)
{
	ncfg_wire_attr_t attr;
	int              present = 0;

	*found = 0;
	if (!area_find(area, kind, &attr, &present, err, err_size)) {
		return 0;
	}
	if (!present || !ncfg_wire_attr_u32(&attr, value, NULL, 0)) {
		return 1;
	}
	*found = 1;
	return 1;
}

/*
 * A big-endian 16-bit value.
 *
 * Netlink is native-endian except where it carries something the *wire*
 * defines, which is why a UDP port and an ethertype need this and a bonding
 * mode does not. Read byte by byte rather than swapped after a native read:
 * the swap is a no-op on a big-endian machine and this is not, and nothing
 * here is ever tested on one.
 */
static int area_be16(const ncfg_wire_attrs_t *area, uint16_t kind, uint16_t *value, int *found,
    char *err, size_t err_size)
{
	ncfg_wire_attr_t attr;
	int              present = 0;

	*found = 0;
	if (!area_find(area, kind, &attr, &present, err, err_size)) {
		return 0;
	}
	if (!present || attr.length < 2u) {
		return 1;
	}
	*value = (uint16_t)(((uint16_t)attr.value[0] << 8) | (uint16_t)attr.value[1]);
	*found = 1;
	return 1;
}

/* The same for a GRE key, which is four bytes and equally the wire's. */
static int area_be32(const ncfg_wire_attrs_t *area, uint16_t kind, uint32_t *value, int *found,
    char *err, size_t err_size)
{
	ncfg_wire_attr_t attr;
	int              present = 0;

	*found = 0;
	if (!area_find(area, kind, &attr, &present, err, err_size)) {
		return 0;
	}
	if (!present || attr.length < 4u) {
		return 1;
	}
	*value = ((uint32_t)attr.value[0] << 24) | ((uint32_t)attr.value[1] << 16) |
	    ((uint32_t)attr.value[2] << 8) | (uint32_t)attr.value[3];
	*found = 1;
	return 1;
}

static int area_string(const ncfg_wire_attrs_t *area, uint16_t kind, char *out, size_t out_size,
    int *found, char *err, size_t err_size)
{
	ncfg_wire_attr_t attr;
	int              present = 0;

	*found = 0;
	out[0] = '\0';
	if (!area_find(area, kind, &attr, &present, err, err_size)) {
		return 0;
	}
	/* A name that does not fit, or that is not valid UTF-8, reads as absent
	 * rather than as a shortened name: `wire.c` refuses it for the reason
	 * that a truncated interface name is still a name, just somebody
	 * else's. */
	if (!present || !ncfg_wire_attr_string(&attr, out, out_size, NULL, 0)) {
		return 1;
	}
	*found = 1;
	return 1;
}

/* The nest an attribute's value is, ready to be walked. */
static int area_nest(const ncfg_wire_attrs_t *area, uint16_t kind, ncfg_wire_attrs_t *out,
    int *found, char *err, size_t err_size)
{
	ncfg_wire_attr_t attr;
	int              present = 0;

	*found = 0;
	if (!area_find(area, kind, &attr, &present, err, err_size)) {
		return 0;
	}
	if (!present) {
		return 1;
	}
	ncfg_wire_attrs_start(out, attr.value, attr.length);
	*found = 1;
	return 1;
}

/* Whether an address is the all-zero one, which is how the kernel says an
 * endpoint was never set. */
static int ip_is_unspecified(const ncfg_wire_ip_t *ip)
{
	size_t width = (ip->family == AF_INET) ? 4u : 16u;
	size_t at;

	for (at = 0; at < width; at++) {
		if (ip->bytes[at] != 0) {
			return 0;
		}
	}
	return 1;
}

/*
 * An address attribute, with `AF_UNSPEC` for absent.
 *
 * `strict` drops an all-zero address as absence. Every endpoint inside a
 * tunnel's or a VXLAN's nest is strict -- the kernel emits the attribute
 * whether or not the device has one -- and a route's destination is not, since
 * `0.0.0.0/0` there is a default route and means something.
 */
static int area_ip(const ncfg_wire_attrs_t *area, uint16_t kind, ncfg_wire_ip_t *out,
    int strict, char *err, size_t err_size)
{
	ncfg_wire_attr_t attr;
	int              present = 0;

	memset(out, 0, sizeof(*out));
	if (!area_find(area, kind, &attr, &present, err, err_size)) {
		return 0;
	}
	if (!present || !ncfg_wire_attr_ip(&attr, out, NULL, 0)) {
		memset(out, 0, sizeof(*out));
		return 1;
	}
	if (strict && ip_is_unspecified(out)) {
		memset(out, 0, sizeof(*out));
	}
	return 1;
}

/* The first of two attribute numbers that carries an address: the v4 and v6
 * endpoints of a VXLAN and a geneve tunnel are different attributes rather
 * than one attribute with two lengths. */
static int area_ip_either(const ncfg_wire_attrs_t *area, uint16_t first, uint16_t second,
    ncfg_wire_ip_t *out, char *err, size_t err_size)
{
	ncfg_wire_attr_t attr;
	int              present = 0;

	memset(out, 0, sizeof(*out));
	if (!area_find(area, first, &attr, &present, err, err_size)) {
		return 0;
	}
	if (!present) {
		if (!area_find(area, second, &attr, &present, err, err_size)) {
			return 0;
		}
	}
	if (!present || !ncfg_wire_attr_ip(&attr, out, NULL, 0) || ip_is_unspecified(out)) {
		memset(out, 0, sizeof(*out));
	}
	return 1;
}

/* ------------------------------------------------------------------------ */
/* The requests.                                                            */
/* ------------------------------------------------------------------------ */

uint16_t ncfg_dump_flags(void)
{
	return (uint16_t)(NLM_F_REQUEST | NLM_F_DUMP);
}

void ncfg_dump_link_request(ncfg_buf_t *body, ncfg_buf_t *attrs)
{
	ncfg_wire_ifinfo_t info;

	(void)attrs;
	memset(&info, 0, sizeof(info));
	ncfg_wire_ifinfo_encode(&info, body);
}

void ncfg_dump_address_request(ncfg_buf_t *body, ncfg_buf_t *attrs)
{
	ncfg_wire_ifaddr_t address;

	(void)attrs;
	/* Family 0 means "every family", which is what a dump wants: asking for
	 * `AF_INET` and then for `AF_INET6` is two dumps and a window between
	 * them in which the machine changed. */
	memset(&address, 0, sizeof(address));
	ncfg_wire_ifaddr_encode(&address, body);
}

void ncfg_dump_route_request(ncfg_buf_t *body, ncfg_buf_t *attrs)
{
	ncfg_wire_rtmsg_t route;

	(void)attrs;
	memset(&route, 0, sizeof(route));
	ncfg_wire_rtmsg_encode(&route, body);
}

void ncfg_dump_bridge_vlan_request(ncfg_buf_t *body, ncfg_buf_t *attrs)
{
	ncfg_wire_ifinfo_t info;

	memset(&info, 0, sizeof(info));
	info.family = AF_BRIDGE;
	ncfg_wire_ifinfo_encode(&info, body);
	/* Without `RTEXT_FILTER_BRVLAN` a bridge link dump reports no VLANs at
	 * all, which reads as "this bridge has none" rather than "you did not
	 * ask" -- and netcfgd would then delete every VLAN on the machine to
	 * make the observation match. */
	ncfg_wire_attr_put_u32(attrs, IFLA_EXT_MASK, RTEXT_FILTER_BRVLAN);
}

/* ------------------------------------------------------------------------ */
/* Links.                                                                   */
/* ------------------------------------------------------------------------ */

void ncfg_link_record_free(ncfg_link_record_t *record)
{
	size_t at;

	if (!record) {
		return;
	}
	for (at = 0; at < record->altname_count; at++) {
		free(record->altnames[at]);
	}
	free(record->altnames);
	record->altnames = NULL;
	record->altname_count = 0;
}

static int push_altname(ncfg_link_record_t *record, const char *name, char *err, size_t err_size)
{
	char  **grown;
	char   *copy;
	size_t  length = strlen(name) + 1u;

	grown = realloc(record->altnames, (record->altname_count + 1u) * sizeof(*grown));
	if (!grown) {
		ncfg_error_set(err, err_size, "no memory for an alternative interface name");
		return 0;
	}
	record->altnames = grown;
	copy = malloc(length);
	if (!copy) {
		ncfg_error_set(err, err_size, "no memory for an alternative interface name");
		return 0;
	}
	memcpy(copy, name, length);
	record->altnames[record->altname_count] = copy;
	record->altname_count++;
	return 1;
}

/*
 * Every `IFLA_ALT_IFNAME` in the `IFLA_PROP_LIST` nest.
 *
 * Walked rather than searched, because the attribute *repeats*: a search stops
 * at the first match and would read a device with three names as a device with
 * one -- and netcfgd's own ownership marker is not guaranteed to be the first,
 * so taking one name is how a link's ownership is lost (0136).
 */
static int read_altnames(ncfg_link_record_t *record, const ncfg_wire_attrs_t *area,
    char *err, size_t err_size)
{
	ncfg_wire_attrs_t nest;
	ncfg_wire_attr_t  attr;
	int               found = 0;

	if (!area_nest(area, IFLA_PROP_LIST, &nest, &found, err, err_size)) {
		return 0;
	}
	if (!found) {
		return 1;
	}
	for (;;) {
		ncfg_wire_step_t step = ncfg_wire_attrs_next(&nest, &attr, err, err_size);
		char             name[NCFG_WIRE_ALT_IFNAME_MAX];

		if (step == NCFG_WIRE_END) {
			return 1;
		}
		if (step == NCFG_WIRE_BAD) {
			return 0;
		}
		if (attr.kind != IFLA_ALT_IFNAME) {
			continue;
		}
		if (!ncfg_wire_attr_string(&attr, name, sizeof(name), NULL, 0)) {
			continue;
		}
		if (!push_altname(record, name, err, err_size)) {
			return 0;
		}
	}
}

/* A bond's own settings. Read with the bond's numbering and no other kind's:
 * every kind puts something different in this nest, and decoding one kind's
 * numbering out of another's is how a VXLAN comes to report a forward delay. */
static int read_bond(ncfg_bond_info_t *out, const ncfg_wire_attrs_t *data, char *err,
    size_t err_size)
{
	if (!area_u8(data, IFLA_BOND_MODE, &out->mode, &out->has_mode, err, err_size)) {
		return 0;
	}
	if (!area_u32(data, IFLA_BOND_MIIMON, &out->miimon, &out->has_miimon, err, err_size)) {
		return 0;
	}
	return 1;
}

static int read_bridge(ncfg_bridge_info_t *out, const ncfg_wire_attrs_t *data, char *err,
    size_t err_size)
{
	uint32_t state = 0;
	uint8_t  filtering = 0;
	int      found = 0;

	if (!area_u32(data, IFLA_BR_STP_STATE, &state, &found, err, err_size)) {
		return 0;
	}
	/* The kernel reports the STP *state*, which is 0 for off and non-zero
	 * for a running protocol; the document holds a boolean. */
	out->stp = found && state != 0;
	if (!area_u32(data, IFLA_BR_FORWARD_DELAY, &out->forward_delay, &out->has_forward_delay,
	    err, err_size)) {
		return 0;
	}
	if (!area_u32(data, IFLA_BR_HELLO_TIME, &out->hello_time, &out->has_hello_time, err,
	    err_size)) {
		return 0;
	}
	if (!area_u32(data, IFLA_BR_AGEING_TIME, &out->ageing_time, &out->has_ageing_time, err,
	    err_size)) {
		return 0;
	}
	/* **Two bytes, not four.** Read as a `u32` this was absent on every
	 * kernel, always, and nothing noticed until the planner started
	 * comparing it -- at which point the apply set the priority, the
	 * observation still said absent, and the plan asked for it again for
	 * ever. The writer had it right, which is what makes two bytes the
	 * answer rather than a guess. */
	if (!area_u16(data, IFLA_BR_PRIORITY, &out->priority, &out->has_priority, err,
	    err_size)) {
		return 0;
	}
	if (!area_u8(data, IFLA_BR_VLAN_FILTERING, &filtering, &found, err, err_size)) {
		return 0;
	}
	out->vlan_filtering = found && filtering != 0;
	return 1;
}

static int read_macvlan(ncfg_macvlan_info_t *out, const ncfg_wire_attrs_t *data, char *err,
    size_t err_size)
{
	return area_u32(data, IFLA_MACVLAN_MODE, &out->mode, &out->has_mode, err, err_size);
}

static int read_vlan(ncfg_vlan_info_t *out, const ncfg_wire_attrs_t *data, char *err,
    size_t err_size)
{
	if (!area_u16(data, IFLA_VLAN_ID, &out->id, &out->has_id, err, err_size)) {
		return 0;
	}
	/* Big-endian, because it is an ethertype and the kernel reads and
	 * reports it as one -- the same asymmetry the writing half has. */
	return area_be16(data, IFLA_VLAN_PROTOCOL, &out->protocol, &out->has_protocol, err,
	    err_size);
}

static int read_vxlan(ncfg_vxlan_info_t *out, const ncfg_wire_attrs_t *data, char *err,
    size_t err_size)
{
	if (!area_u32(data, IFLA_VXLAN_ID, &out->id, &out->has_id, err, err_size)) {
		return 0;
	}
	if (!area_u32(data, IFLA_VXLAN_LINK, &out->link, &out->has_link, err, err_size)) {
		return 0;
	}
	if (!area_ip_either(data, IFLA_VXLAN_LOCAL, IFLA_VXLAN_LOCAL6, &out->local, err,
	    err_size)) {
		return 0;
	}
	if (!area_ip_either(data, IFLA_VXLAN_GROUP, IFLA_VXLAN_GROUP6, &out->remote, err,
	    err_size)) {
		return 0;
	}
	/* Big-endian, like every port number on the wire. */
	return area_be16(data, IFLA_VXLAN_PORT, &out->port, &out->has_port, err, err_size);
}

ncfg_tunnel_family_t ncfg_tunnel_family(const char *kind)
{
	if (!kind) {
		return NCFG_TUNNEL_NONE;
	}
	if (strcmp(kind, "gre") == 0 || strcmp(kind, "gretap") == 0 ||
	    strcmp(kind, "ip6gre") == 0) {
		return NCFG_TUNNEL_GRE;
	}
	if (strcmp(kind, "ipip") == 0 || strcmp(kind, "sit") == 0 ||
	    strcmp(kind, "ip6tnl") == 0) {
		return NCFG_TUNNEL_IP;
	}
	if (strcmp(kind, "geneve") == 0) {
		return NCFG_TUNNEL_GENEVE;
	}
	return NCFG_TUNNEL_NONE;
}

static int read_tunnel(ncfg_tunnel_info_t *out, ncfg_tunnel_family_t family,
    const ncfg_wire_attrs_t *data, char *err, size_t err_size)
{
	uint16_t flags = 0;
	int      found = 0;

	switch (family) {
	case NCFG_TUNNEL_GRE:
		if (!area_ip(data, IFLA_GRE_LOCAL, &out->local, 1, err, err_size)) {
			return 0;
		}
		if (!area_ip(data, IFLA_GRE_REMOTE, &out->remote, 1, err, err_size)) {
			return 0;
		}
		if (!area_u8(data, IFLA_GRE_TTL, &out->ttl, &out->has_ttl, err, err_size)) {
			return 0;
		}
		/* The kernel emits `IKEY` whether or not the tunnel has a key, so
		 * a zero there is either no key or the key `0` -- which a
		 * document may legitimately ask for. The flag word is what
		 * distinguishes them, and reading it is what keeps `key = 0` from
		 * differing from itself for ever. */
		if (!area_be16(data, IFLA_GRE_IFLAGS, &flags, &found, err, err_size)) {
			return 0;
		}
		if (found && (flags & NCFG_GRE_KEY_FLAG) != 0) {
			if (!area_be32(data, IFLA_GRE_IKEY, &out->key, &out->has_key, err,
			    err_size)) {
				return 0;
			}
		}
		return 1;
	case NCFG_TUNNEL_IP:
		if (!area_ip(data, IFLA_IPTUN_LOCAL, &out->local, 1, err, err_size)) {
			return 0;
		}
		if (!area_ip(data, IFLA_IPTUN_REMOTE, &out->remote, 1, err, err_size)) {
			return 0;
		}
		/* No key on an ip tunnel. Absent is "nothing to compare", which
		 * is what the document's key means here too. */
		return area_u8(data, IFLA_IPTUN_TTL, &out->ttl, &out->has_ttl, err, err_size);
	case NCFG_TUNNEL_GENEVE:
		/* A geneve tunnel has no local endpoint netcfgd sets. */
		if (!area_ip_either(data, IFLA_GENEVE_REMOTE, IFLA_GENEVE_REMOTE6, &out->remote,
		    err, err_size)) {
			return 0;
		}
		/*
		 * `IFLA_GENEVE_TTL` is 3. This port reads the kernel's own
		 * constant, where the Rust wrote 4 by hand -- which is
		 * `IFLA_GENEVE_TOS`, and the writer said the same, so the two
		 * agreed with each other and with nothing else and the plan
		 * converged on a tunnel whose TTL had never been set.
		 */
		if (!area_u8(data, IFLA_GENEVE_TTL, &out->ttl, &out->has_ttl, err, err_size)) {
			return 0;
		}
		/* The VNI, which netcfgd's model spells `key` because a geneve
		 * tunnel needs one and there is no separate field for it. */
		return area_u32(data, IFLA_GENEVE_ID, &out->key, &out->has_key, err, err_size);
	case NCFG_TUNNEL_NONE:
	default:
		return 1;
	}
}

/* The `IFLA_INFO_DATA` nest, one attribute along from the kind in the
 * `LINKINFO` nest. */
static int info_data(const ncfg_wire_attrs_t *linkinfo, int have_linkinfo,
    ncfg_wire_attrs_t *out, int *found, char *err, size_t err_size)
{
	*found = 0;
	if (!have_linkinfo) {
		return 1;
	}
	return area_nest(linkinfo, IFLA_INFO_DATA, out, found, err, err_size);
}

int ncfg_dump_link(const void *payload, size_t length, ncfg_link_record_t *out, char *err,
    size_t err_size)
{
	ncfg_wire_ifinfo_t info;
	ncfg_wire_attrs_t  area;
	ncfg_wire_attrs_t  linkinfo;
	ncfg_wire_attrs_t  data;
	ncfg_wire_attrs_t  spec;
	ncfg_wire_attrs_t  inet6;
	ncfg_wire_attr_t   attr;
	uint8_t            carrier = 0;
	uint32_t           parent = 0;
	int                have_linkinfo = 0;
	int                have_data = 0;
	int                found = 0;
	int                have_parent = 0;

	if (!out) {
		ncfg_error_set(err, err_size, "a link record needs somewhere to go");
		return 0;
	}
	memset(out, 0, sizeof(*out));
	if (!ncfg_wire_ifinfo_decode(payload, length, &info, err, err_size)) {
		return 0;
	}
	ncfg_wire_attrs_start(&area, (const uint8_t *)payload + NCFG_WIRE_IFINFO_LEN,
	    length - NCFG_WIRE_IFINFO_LEN);

	/* A negative interface index is the kernel's to explain; reported as 0,
	 * which matches nothing, rather than as a huge unsigned number, which
	 * would match a device on a machine with enough of them. */
	out->index = info.index < 0 ? 0u : (uint32_t)info.index;
	/* `IFF_UP` is the administrative flag. Carrier is a separate attribute
	 * and a separate question: a link can be up with the cable out, and
	 * conflating the two is how a plan decides to reconfigure a perfectly
	 * good interface. */
	out->up = (info.flags & NCFG_LINK_IFF_UP) != 0;

	if (!area_string(&area, IFLA_IFNAME, out->name, sizeof(out->name), &found, err,
	    err_size)) {
		goto refused;
	}
	if (!found) {
		/* Not a link record at all, or one whose name this port will not
		 * carry. Either way there is nothing above here that can act on
		 * it: everything netcfgd does to a link, it does by name. */
		ncfg_error_set(err, err_size, "a link message with no name this port can read");
		goto refused;
	}
	if (!area_u32(&area, IFLA_MTU, &out->mtu, &found, err, err_size)) {
		goto refused;
	}
	if (!found) {
		out->mtu = 0;
	}
	if (!read_altnames(out, &area, err, err_size)) {
		goto refused;
	}
	if (!area_find(&area, IFLA_ADDRESS, &attr, &found, err, err_size)) {
		goto refused;
	}
	if (found && ncfg_wire_attr_mac(&attr, out->mac, sizeof(out->mac), NULL, 0)) {
		/* Not every `IFLA_ADDRESS` is a MAC: an InfiniBand link carries
		 * twenty bytes and a tunnel four, and `wire.c` refuses those
		 * rather than letting them into a field the rest of the port
		 * treats as a hardware address. */
		out->has_mac = 1;
	}
	if (!area_u32(&area, IFLA_MASTER, &out->master, &out->has_master, err, err_size)) {
		goto refused;
	}
	if (!area_u32(&area, IFLA_LINK, &parent, &have_parent, err, err_size)) {
		goto refused;
	}

	/* Two levels down: `IFLA_AF_SPEC`, then the `AF_INET6` block. Present in
	 * an ordinary link dump, so this needs no second request. */
	if (!area_nest(&area, IFLA_AF_SPEC, &spec, &found, err, err_size)) {
		goto refused;
	}
	if (found) {
		int have_inet6 = 0;

		if (!area_nest(&spec, NCFG_AF_SPEC_INET6, &inet6, &have_inet6, err, err_size)) {
			goto refused;
		}
		if (have_inet6) {
			/* Strict: the kernel reports `::` for a device with no
			 * token, and reading that as an address would make every
			 * interface look as though it had one. */
			if (!area_ip(&inet6, IFLA_INET6_TOKEN, &out->ipv6_token, 1, err,
			    err_size)) {
				goto refused;
			}
		}
	}

	/* The kind lives one level down, inside the `LINKINFO` nest. Its absence
	 * is normal: a plain ethernet device has no kind. */
	if (!area_nest(&area, IFLA_LINKINFO, &linkinfo, &have_linkinfo, err, err_size)) {
		goto refused;
	}
	if (have_linkinfo) {
		if (!area_string(&linkinfo, IFLA_INFO_KIND, out->kind, sizeof(out->kind), &found,
		    err, err_size)) {
			goto refused;
		}
	}
	if (!info_data(&linkinfo, have_linkinfo, &data, &have_data, err, err_size)) {
		goto refused;
	}
	if (have_data) {
		ncfg_tunnel_family_t family = ncfg_tunnel_family(out->kind);

		if (strcmp(out->kind, "bond") == 0) {
			if (!read_bond(&out->bond, &data, err, err_size)) {
				goto refused;
			}
			out->has_bond = 1;
		} else if (strcmp(out->kind, "bridge") == 0) {
			if (!read_bridge(&out->bridge, &data, err, err_size)) {
				goto refused;
			}
			out->has_bridge = 1;
		} else if (strcmp(out->kind, "macvlan") == 0) {
			if (!read_macvlan(&out->macvlan, &data, err, err_size)) {
				goto refused;
			}
			out->has_macvlan = 1;
		} else if (strcmp(out->kind, "vlan") == 0) {
			if (!read_vlan(&out->vlan, &data, err, err_size)) {
				goto refused;
			}
			out->has_vlan = 1;
		} else if (strcmp(out->kind, "vxlan") == 0) {
			if (!read_vxlan(&out->vxlan, &data, err, err_size)) {
				goto refused;
			}
			out->has_vxlan = 1;
		} else if (family != NCFG_TUNNEL_NONE) {
			if (!read_tunnel(&out->tunnel, family, &data, err, err_size)) {
				goto refused;
			}
			out->has_tunnel = 1;
		}
	}

	if (!area_u8(&area, IFLA_CARRIER, &carrier, &found, err, err_size)) {
		goto refused;
	}
	/* **Absent means carrier**, which is not obvious and is deliberate: a
	 * kernel that does not report the attribute is not a machine with every
	 * cable out, and treating it as one would have netcfgd stand down on
	 * every interface it has. Present and zero is the only "no carrier". */
	out->carrier = found ? (carrier != 0) : 1;

	/*
	 * A VXLAN reports its underlay inside its own nest and *not* in the
	 * outer attribute every other kind uses -- measured, because the two
	 * disagreeing is how a parent came to be sent to the wrong place for
	 * years. Everything else reports it outside, tunnels included: the
	 * kernel reads a tunnel's underlay from the nest and reports it here.
	 */
	if (have_parent) {
		out->has_parent = 1;
		out->parent = parent;
	} else if (out->has_vxlan && out->vxlan.has_link) {
		out->has_parent = 1;
		out->parent = out->vxlan.link;
	}
	return 1;

refused:
	ncfg_link_record_free(out);
	memset(out, 0, sizeof(*out));
	return 0;
}

/* ------------------------------------------------------------------------ */
/* Addresses and routes.                                                    */
/* ------------------------------------------------------------------------ */

int ncfg_dump_address(const void *payload, size_t length, ncfg_address_record_t *out, char *err,
    size_t err_size)
{
	ncfg_wire_ifaddr_t info;
	ncfg_wire_attrs_t  area;
	ncfg_wire_attr_t   attr;
	int                found = 0;

	if (!out) {
		ncfg_error_set(err, err_size, "an address record needs somewhere to go");
		return 0;
	}
	memset(out, 0, sizeof(*out));
	if (!ncfg_wire_ifaddr_decode(payload, length, &info, err, err_size)) {
		return 0;
	}
	ncfg_wire_attrs_start(&area, (const uint8_t *)payload + NCFG_WIRE_IFADDR_LEN,
	    length - NCFG_WIRE_IFADDR_LEN);

	/*
	 * `IFA_LOCAL` is the address on this host; `IFA_ADDRESS` is the peer on
	 * a point-to-point link and the same thing everywhere else. Preferring
	 * LOCAL is what makes a PPP interface report its own address rather than
	 * the far end's -- and the far end's, written into a document as this
	 * machine's, is an address netcfgd would then try to configure.
	 */
	if (!area_find(&area, IFA_LOCAL, &attr, &found, err, err_size)) {
		return 0;
	}
	if (!found) {
		if (!area_find(&area, IFA_ADDRESS, &attr, &found, err, err_size)) {
			return 0;
		}
	}
	if (!found || !ncfg_wire_attr_ip(&attr, &out->address, err, err_size)) {
		ncfg_error_set(err, err_size, "an address message with no address in it");
		memset(out, 0, sizeof(*out));
		return 0;
	}
	out->index = info.index;
	out->prefix_len = info.prefix_len;
	if (!area_u8(&area, IFA_PROTO, &out->proto, &out->has_proto, err, err_size)) {
		memset(out, 0, sizeof(*out));
		return 0;
	}
	return 1;
}

int ncfg_dump_route(const void *payload, size_t length, ncfg_route_record_t *out, char *err,
    size_t err_size)
{
	ncfg_wire_rtmsg_t info;
	ncfg_wire_attrs_t area;
	int               found = 0;

	if (!out) {
		ncfg_error_set(err, err_size, "a route record needs somewhere to go");
		return 0;
	}
	memset(out, 0, sizeof(*out));
	if (!ncfg_wire_rtmsg_decode(payload, length, &info, err, err_size)) {
		return 0;
	}
	ncfg_wire_attrs_start(&area, (const uint8_t *)payload + NCFG_WIRE_RTMSG_LEN,
	    length - NCFG_WIRE_RTMSG_LEN);

	if (!area_u32(&area, RTA_OIF, &out->index, &out->has_index, err, err_size)) {
		return 0;
	}
	/* Not strict: an all-zero destination with `dst_len` 0 is the default
	 * route, which is a fact rather than an absence -- but the attribute
	 * itself is what the kernel omits for one, and `AF_UNSPEC` here is what
	 * `destination_text` renders as `default`. */
	if (!area_ip(&area, RTA_DST, &out->destination, 0, err, err_size)) {
		return 0;
	}
	if (!area_ip(&area, RTA_GATEWAY, &out->gateway, 0, err, err_size)) {
		return 0;
	}
	if (!area_ip(&area, RTA_PREFSRC, &out->prefsrc, 0, err, err_size)) {
		return 0;
	}
	if (!area_u32(&area, RTA_PRIORITY, &out->metric, &out->has_metric, err, err_size)) {
		return 0;
	}
	/* `RTA_TABLE` carries the table id when it does not fit the byte-wide
	 * `rtm_table`, which is every table above 255. Reading only the byte
	 * reports table 300 as whatever the compat value happens to be -- 252,
	 * which is a real table and not that one. */
	if (!area_u32(&area, RTA_TABLE, &out->table, &found, err, err_size)) {
		return 0;
	}
	if (!found) {
		out->table = info.table;
	}
	out->dst_len = info.dst_len;
	out->protocol = info.protocol;
	out->scope = info.scope;
	return 1;
}

int ncfg_address_record_cidr(const ncfg_address_record_t *record, char *out, size_t out_size,
    char *err, size_t err_size)
{
	char text[NCFG_WIRE_IP_TEXT_MAX];

	if (!record || !out || out_size < NCFG_CIDR_TEXT_MAX) {
		ncfg_error_set(err, err_size, "an address in CIDR needs %u bytes to be written into",
		    (unsigned)NCFG_CIDR_TEXT_MAX);
		return 0;
	}
	out[0] = '\0';
	if (!ncfg_wire_ip_text(&record->address, text, sizeof(text), err, err_size)) {
		return 0;
	}
	(void)snprintf(out, out_size, "%s/%u", text, (unsigned)record->prefix_len);
	return 1;
}

int ncfg_route_record_destination(const ncfg_route_record_t *record, char *out, size_t out_size,
    char *err, size_t err_size)
{
	char text[NCFG_WIRE_IP_TEXT_MAX];

	if (!record || !out || out_size < NCFG_CIDR_TEXT_MAX) {
		ncfg_error_set(err, err_size, "a destination needs %u bytes to be written into",
		    (unsigned)NCFG_CIDR_TEXT_MAX);
		return 0;
	}
	out[0] = '\0';
	if (record->destination.family != AF_INET && record->destination.family != AF_INET6) {
		/* The model's word for a route with no destination attribute,
		 * and the one a document writes. */
		(void)snprintf(out, out_size, "default");
		return 1;
	}
	if (!ncfg_wire_ip_text(&record->destination, text, sizeof(text), err, err_size)) {
		return 0;
	}
	(void)snprintf(out, out_size, "%s/%u", text, (unsigned)record->dst_len);
	return 1;
}

/* ------------------------------------------------------------------------ */
/* Bridge VLANs.                                                            */
/* ------------------------------------------------------------------------ */

void ncfg_bridge_vlans_free(ncfg_bridge_vlans_t *vlans)
{
	if (!vlans) {
		return;
	}
	free(vlans->items);
	vlans->items = NULL;
	vlans->count = 0;
	vlans->capacity = 0;
}

static int push_vlan(ncfg_bridge_vlans_t *vlans, const ncfg_bridge_vlan_t *one, char *err,
    size_t err_size)
{
	if (vlans->count == vlans->capacity) {
		size_t              wanted = vlans->capacity ? vlans->capacity * 2u : 8u;
		ncfg_bridge_vlan_t *grown = realloc(vlans->items, wanted * sizeof(*grown));

		if (!grown) {
			ncfg_error_set(err, err_size, "no memory for %zu bridge VLANs", wanted);
			return 0;
		}
		vlans->items = grown;
		vlans->capacity = wanted;
	}
	vlans->items[vlans->count] = *one;
	vlans->count++;
	return 1;
}

/* Sorted the way the Rust's derived ordering sorts: index, then id, then the
 * two flags. A stable order is what lets an observation be compared with the
 * last one by bytes rather than by set membership. */
static int compare_vlans(const void *left, const void *right)
{
	const ncfg_bridge_vlan_t *one = left;
	const ncfg_bridge_vlan_t *two = right;

	if (one->index != two->index) {
		return one->index < two->index ? -1 : 1;
	}
	if (one->vid != two->vid) {
		return one->vid < two->vid ? -1 : 1;
	}
	if (one->pvid != two->pvid) {
		return one->pvid < two->pvid ? -1 : 1;
	}
	if (one->untagged != two->untagged) {
		return one->untagged < two->untagged ? -1 : 1;
	}
	return 0;
}

int ncfg_dump_bridge_vlans(const void *payload, size_t length, ncfg_bridge_vlans_t *out,
    char *err, size_t err_size)
{
	ncfg_wire_ifinfo_t info;
	ncfg_wire_attrs_t  area;
	ncfg_wire_attrs_t  spec;
	ncfg_bridge_vlan_t start;
	uint32_t           index;
	int                found = 0;
	int                in_range = 0;

	if (!out) {
		ncfg_error_set(err, err_size, "bridge VLANs need somewhere to go");
		return 0;
	}
	memset(out, 0, sizeof(*out));
	memset(&start, 0, sizeof(start));
	if (!ncfg_wire_ifinfo_decode(payload, length, &info, err, err_size)) {
		return 0;
	}
	ncfg_wire_attrs_start(&area, (const uint8_t *)payload + NCFG_WIRE_IFINFO_LEN,
	    length - NCFG_WIRE_IFINFO_LEN);
	index = info.index < 0 ? 0u : (uint32_t)info.index;

	if (!area_nest(&area, IFLA_AF_SPEC, &spec, &found, err, err_size)) {
		return 0;
	}
	if (!found) {
		/* A link with no `AF_SPEC` is a link with no VLANs to report,
		 * which is success with nothing in it -- an ordinary link dump
		 * and a bridge one arrive on the same socket. */
		return 1;
	}
	for (;;) {
		ncfg_wire_attr_t   attr;
		ncfg_bridge_vlan_t record;
		uint16_t           flags;
		ncfg_wire_step_t   step = ncfg_wire_attrs_next(&spec, &attr, err, err_size);

		if (step == NCFG_WIRE_END) {
			break;
		}
		if (step == NCFG_WIRE_BAD) {
			ncfg_bridge_vlans_free(out);
			return 0;
		}
		if (attr.kind != IFLA_BRIDGE_VLAN_INFO || attr.length < 4u) {
			continue;
		}
		/* Native order: `struct bridge_vlan_info` is two `__u16` the
		 * kernel writes in its own representation, like every netlink
		 * field that is not an address. */
		memcpy(&flags, attr.value, sizeof(flags));
		memset(&record, 0, sizeof(record));
		record.index = index;
		memcpy(&record.vid, attr.value + 2, sizeof(record.vid));
		record.pvid = (flags & BRIDGE_VLAN_INFO_PVID) != 0;
		record.untagged = (flags & BRIDGE_VLAN_INFO_UNTAGGED) != 0;

		/* The kernel compresses `vid 10` through `vid 20` into a pair of
		 * entries flagged BEGIN and END rather than eleven entries.
		 * Expanding here means everything above works in single VLANs and
		 * never has to know ranges exist. */
		if ((flags & BRIDGE_VLAN_INFO_RANGE_BEGIN) != 0) {
			start = record;
			in_range = 1;
			continue;
		}
		if ((flags & BRIDGE_VLAN_INFO_RANGE_END) != 0 && in_range) {
			uint32_t vid;

			in_range = 0;
			for (vid = start.vid; vid <= record.vid; vid++) {
				ncfg_bridge_vlan_t one = start;

				one.vid = (uint16_t)vid;
				if (!push_vlan(out, &one, err, err_size)) {
					ncfg_bridge_vlans_free(out);
					return 0;
				}
			}
			continue;
		}
		if (!push_vlan(out, &record, err, err_size)) {
			ncfg_bridge_vlans_free(out);
			return 0;
		}
	}
	if (in_range) {
		/* A range that never ended is a truncated message rather than a
		 * range to the end of the space; taking the first entry alone is
		 * the conservative reading, since inventing 4094 VLANs would have
		 * netcfgd delete them. */
		if (!push_vlan(out, &start, err, err_size)) {
			ncfg_bridge_vlans_free(out);
			return 0;
		}
	}
	if (out->count > 1u) {
		qsort(out->items, out->count, sizeof(*out->items), compare_vlans);
	}
	return 1;
}
