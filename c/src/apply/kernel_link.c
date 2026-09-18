/*
 * kernel_link.c -- a device's own settings, re-stated to a device that already
 * exists.
 *
 * WHAT THESE SIX OPS ARE FOR
 *   `link.create` makes a device and stops. Everything that makes it *the*
 *   device the document describes -- a bridge's forward delay, a bond's mode,
 *   a tunnel's endpoints, a VXLAN's underlay -- is separately reconcilable,
 *   and decision 0054 is why they are ops of their own: a device configured
 *   only at creation means an edited listen port, an edited forward delay or
 *   an edited remote address does nothing at all, for ever, on a machine
 *   whose plan looks converged.
 *
 * ONE ENCODER PER KIND, WHICH IS DECISION 0057 AND IS WHY `newlink_of` MOVED
 *   `ncfg_kernel_newlink_of` is the single conversion from the model's kind
 *   block to the wire layer's, and both `link.create` and the five
 *   `link.set_*` ops go through it. It used to be private to `kernel.c` and
 *   serve creation alone; a second copy here for the correct-an-existing path
 *   is exactly the failure 0057 records against bridges -- "two encoders for
 *   one kind is how the create path and the correct-an-existing path come to
 *   disagree about what a forward delay is" -- so there is one, and it is
 *   here because this is the file with five of its six callers.
 *
 * THE NUMBERING IS THE MODEL'S AND THE REFUSALS SAY SO
 *   A bond mode, a macvlan mode and a tunnel's kind word are the model's
 *   numbering of a closed set. `document.h` publishes each -- the reader that
 *   has to agree with this writer is `src/observe/`, which reads the same
 *   tables -- and nothing in this directory keeps a list of its own. A VLAN's
 *   ethertype has no such accessor yet and a VLAN is therefore still refused
 *   by name rather than guessed at.
 *
 * WHOLE NESTS, NOT THE FIELD THAT MOVED
 *   `ops.h` measured this and it is not obvious: a request carrying only
 *   `IFLA_GRE_REMOTE` leaves a GRE tunnel with no local address, no TTL and no
 *   key, because `ipgre_netlink_parms` starts from a zeroed struct -- while a
 *   VXLAN and a geneve keep what the request leaves out. `ip` hides it by
 *   reading the device and refilling every field before it sends anything, so
 *   the obvious experiment says the kernel merges when it does not.
 */
#include "kernel_internal.h"

#include "ncfg/base.h"
#include "ncfg/observe.h"
#include "ncfg/wire.h"

#include <stdio.h>
#include <string.h>

/* ------------------------------------------------------------------------ *
 * What the document says
 * ------------------------------------------------------------------------ */

const ncfg_interface_kind_t *ncfg_kernel_kind_of(const ncfg_document_t *document,
    const char *name, int want, char *err, size_t err_size)
{
	const char *wanted = ncfg_interface_kind_name(want);
	size_t      i;

	if (!name || name[0] == '\0') {
		ncfg_error_set(err, err_size, "an action names no device to configure");
		return NULL;
	}
	if (!document) {
		/*
		 * The executor was built without a document, which is not an
		 * operator's mistake and is said as such: what these ops change is
		 * the document's, and an executor with none would otherwise
		 * configure a device with nothing -- a bridge with every setting at
		 * the kernel's default, reported as a successful apply.
		 */
		ncfg_error_set(err, err_size,
		    "%s: the settings of a %s are the document's, and this executor was given "
		    "no document to read them from", name, wanted ? wanted : "link");
		return NULL;
	}
	for (i = 0; i < document->device_count; i++) {
		const ncfg_device_t *device = &document->devices[i];

		if (!device->name || strcmp(device->name, name) != 0) {
			continue;
		}
		if (device->kind.kind != want) {
			/*
			 * A plan built from another document. Sending the block the
			 * device *does* have under an op asking for a different kind is
			 * how an apply changes something nobody asked about, so this is
			 * a refusal naming both words rather than a best effort.
			 */
			const char *held = ncfg_interface_kind_name(device->kind.kind);

			ncfg_error_set(err, err_size,
			    "%s is a %s in the document being applied and this action is for a "
			    "%s; the plan was built from a different document", name,
			    held ? held : "link of another kind", wanted ? wanted : "link");
			return NULL;
		}
		return &device->kind;
	}
	ncfg_error_set(err, err_size, "%s: no %s settings in the document being applied", name,
	    wanted ? wanted : "link");
	return NULL;
}

/* ------------------------------------------------------------------------ *
 * The model's kind as the wire layer wants it
 * ------------------------------------------------------------------------ */

/*
 * A parent device's index, as an optional one.
 *
 * Resolved here rather than carried as a name, because the kernel wants an
 * index and the underlay may have been created earlier in this same plan --
 * which is also why the lookup is a seam and not `if_nametoindex` written out.
 */
static int parent_index(const char *parent, ncfg_kernel_index_fn resolve, void *context,
    ncfg_optint_t *out, char *err, size_t err_size)
{
	uint32_t index;

	out->has = 0;
	out->value = 0;
	if (!parent) {
		return 1;
	}
	if (!resolve) {
		ncfg_error_set(err, err_size,
		    "%s has to be looked up and this build was given no way to do it", parent);
		return 0;
	}
	index = resolve(context, parent, err, err_size);
	if (index == 0) {
		return 0;
	}
	out->has = 1;
	out->value = (int64_t)index;
	return 1;
}

int ncfg_kernel_newlink_of(const ncfg_interface_kind_t *kind, const char *name,
    ncfg_kernel_index_fn resolve, void *context, ncfg_ops_newlink_t *out, char *err,
    size_t err_size)
{
	const char *word;

	if (!out) {
		ncfg_error_set(err, err_size, "there is nowhere to put a link description");
		return 0;
	}
	memset(out, 0, sizeof(*out));
	if (!kind) {
		ncfg_error_set(err, err_size, "%s carries no kind, so there is nothing to build",
		    name ? name : "an unnamed link");
		return 0;
	}
	word = ncfg_interface_kind_name(kind->kind);
	switch ((ncfg_interface_kind_tag_t)kind->kind) {
	case NCFG_KIND_BRIDGE:
		/*
		 * The link and nothing else. A bridge takes no settings at creation
		 * -- the kernel would accept `IFLA_INFO_DATA` there, but changing
		 * them later has to be a separate `RTM_NEWLINK` anyway, and having
		 * one path rather than two is what stops the create case and the
		 * correct-an-existing-bridge case drifting apart (0057).
		 */
		out->kind = NCFG_OPS_LINK_BRIDGE;
		return 1;
	case NCFG_KIND_DUMMY:
		out->kind = NCFG_OPS_LINK_DUMMY;
		return 1;
	case NCFG_KIND_IFB:
		out->kind = NCFG_OPS_LINK_IFB;
		return 1;
	case NCFG_KIND_WIREGUARD:
		out->kind = NCFG_OPS_LINK_WIREGUARD;
		return 1;
	case NCFG_KIND_VETH:
		out->kind = NCFG_OPS_LINK_VETH;
		out->veth.peer = kind->veth.peer;
		if (!out->veth.peer) {
			ncfg_error_set(err, err_size, "%s is a veth with no peer named", name);
			return 0;
		}
		return 1;
	case NCFG_KIND_VRF:
		out->kind = NCFG_OPS_LINK_VRF;
		if (kind->vrf.table < 0 || kind->vrf.table > (int64_t)0xffffffff) {
			ncfg_error_set(err, err_size,
			    "%s asks for routing table %lld, which is not a table number",
			    name, (long long)kind->vrf.table);
			return 0;
		}
		out->vrf.table = (uint32_t)kind->vrf.table;
		return 1;
	case NCFG_KIND_VXLAN:
		out->kind = NCFG_OPS_LINK_VXLAN;
		if (kind->vxlan.id < 0 || kind->vxlan.id > 0xffffff) {
			ncfg_error_set(err, err_size,
			    "%s asks for VNI %lld, which does not fit the 24 bits a VXLAN "
			    "network identifier has", name, (long long)kind->vxlan.id);
			return 0;
		}
		out->vxlan.id = (uint32_t)kind->vxlan.id;
		out->vxlan.port = kind->vxlan.port;
		if (!parent_index(kind->vxlan.parent, resolve, context, &out->vxlan.parent, err,
		    err_size)) {
			return 0;
		}
		if (kind->vxlan.local &&
		    !ncfg_wire_ip_parse(kind->vxlan.local, &out->vxlan.local, err, err_size)) {
			return 0;
		}
		if (kind->vxlan.remote &&
		    !ncfg_wire_ip_parse(kind->vxlan.remote, &out->vxlan.remote, err, err_size)) {
			return 0;
		}
		return 1;
	case NCFG_KIND_MACVLAN: {
		int mode = ncfg_macvlan_mode_number(kind->macvlan.mode);
		ncfg_optint_t parent;

		out->kind = NCFG_OPS_LINK_MACVLAN;
		if (mode < 0) {
			ncfg_error_set(err, err_size,
			    "%s asks for a macvlan mode this build has no number for", name);
			return 0;
		}
		out->macvlan.mode = (uint32_t)mode;
		/*
		 * A macvlan without a parent is not a macvlan: it is a virtual
		 * device *on* something, and the kernel answers a bare `EINVAL`
		 * for the whole message rather than naming the missing link.
		 */
		if (!kind->macvlan.parent) {
			ncfg_error_set(err, err_size,
			    "%s is a macvlan with no parent device named", name);
			return 0;
		}
		if (!parent_index(kind->macvlan.parent, resolve, context, &parent, err,
		    err_size)) {
			return 0;
		}
		out->macvlan.parent = (uint32_t)parent.value;
		return 1;
	}
	case NCFG_KIND_TUNNEL:
		out->kind = NCFG_OPS_LINK_TUNNEL;
		/* The document's word for an encapsulation *is* the kernel's, which
		 * `document.h` says is deliberate -- so this reads the model's table
		 * rather than keeping a list of seven names in the executor. */
		out->tunnel.kind = ncfg_tunnel_kind_name(kind->tunnel.mode);
		if (!out->tunnel.kind) {
			ncfg_error_set(err, err_size,
			    "%s asks for a tunnel encapsulation this build has no word for",
			    name);
			return 0;
		}
		out->tunnel.ttl = kind->tunnel.ttl;
		out->tunnel.key = kind->tunnel.key;
		if (!parent_index(kind->tunnel.parent, resolve, context, &out->tunnel.parent, err,
		    err_size)) {
			return 0;
		}
		if (kind->tunnel.local &&
		    !ncfg_wire_ip_parse(kind->tunnel.local, &out->tunnel.local, err, err_size)) {
			return 0;
		}
		if (kind->tunnel.remote &&
		    !ncfg_wire_ip_parse(kind->tunnel.remote, &out->tunnel.remote, err, err_size)) {
			return 0;
		}
		return 1;
	case NCFG_KIND_BOND:
		/*
		 * A bond's settings are not part of its kind: the kernel takes a
		 * mode only on a bond with no members, so they go in their own
		 * `RTM_NEWLINK` through `ncfg_kernel_build_bond` -- which is the
		 * same split a bridge has and for a sharper reason.
		 */
		ncfg_error_set(err, err_size,
		    "a bond (%s) carries its mode and monitoring interval in a message of "
		    "their own, because the kernel takes a mode only on a bond with no "
		    "members", name ? name : "?");
		return 0;
	case NCFG_KIND_VLAN:
		ncfg_error_set(err, err_size,
		    "creating a vlan link (%s) needs the kernel's ethertype for its tag "
		    "protocol, which belongs with the model and is not published by "
		    "document.h; a second copy of it here is how a protocol comes to mean "
		    "one thing on the way out and another on the way back in",
		    name ? name : "?");
		return 0;
	case NCFG_KIND_TUN:
	case NCFG_KIND_PHYSICAL:
	case NCFG_KIND_PPPOE:
	case NCFG_KIND_OPENVPN:
		break;
	}
	/*
	 * A `tun` is made through `/dev/net/tun` and the other three are not made
	 * by a netlink message at all. Said rather than left as a fall-through, so
	 * that a caller finds a sentence instead of a link half made.
	 */
	ncfg_error_set(err, err_size,
	    "%s is a %s, which this executor does not build a netlink message for",
	    name ? name : "?", word ? word : "kind of its own");
	return 0;
}

/* ------------------------------------------------------------------------ *
 * The mark a created link wears
 * ------------------------------------------------------------------------ */

int ncfg_kernel_altname_of(const char *link, char *out, size_t out_size, char *err,
    size_t err_size)
{
	size_t needed;

	if (!out || out_size == 0u) {
		ncfg_error_set(err, err_size, "there is nowhere to put an alternative name");
		return 0;
	}
	out[0] = '\0';
	if (!link || link[0] == '\0') {
		ncfg_error_set(err, err_size,
		    "a link with no name cannot be marked as netcfgd's");
		return 0;
	}
	/*
	 * The prefix is `observe.h`'s constant and not a string written here. That
	 * header asks for exactly this -- "when the executor lands it should use
	 * this constant rather than write the string again" -- and the reason is
	 * the one failure this whole mechanism has: netcfgd stamping one spelling
	 * and reading back another makes every link it creates foreign to it.
	 */
	needed = strlen(NCFG_OBSERVE_ALTNAME_PREFIX) + strlen(link) + 1u;
	if (needed > out_size || needed > (size_t)NCFG_WIRE_ALT_IFNAME_MAX) {
		ncfg_error_set(err, err_size,
		    "netcfgd's mark for %s would be %zu bytes and an alternative name holds "
		    "%u", link, needed - 1u, (unsigned)(NCFG_WIRE_ALT_IFNAME_MAX - 1u));
		return 0;
	}
	(void)snprintf(out, out_size, "%s%s", NCFG_OBSERVE_ALTNAME_PREFIX, link);
	return 1;
}

int ncfg_kernel_build_altname(ncfg_buf_t *out, uint32_t seq, uint32_t index, const char *name,
    char *err, size_t err_size)
{
	char altname[NCFG_WIRE_ALT_IFNAME_MAX];

	if (!ncfg_kernel_altname_of(name, altname, sizeof(altname), err, err_size)) {
		return 0;
	}
	/* `ncfg_ops_add_altname` owns the message: `RTM_NEWLINKPROP` rather than an
	 * attribute on `RTM_NEWLINK`, and the `NLA_F_NESTED` that message type
	 * insists on. Nothing about either is spelled a second time here. */
	return ncfg_ops_add_altname(out, seq, index, altname, err, err_size);
}

/* ------------------------------------------------------------------------ *
 * The builders
 * ------------------------------------------------------------------------ */

int ncfg_kernel_build_bridge(ncfg_buf_t *out, uint32_t seq, uint32_t index,
    const ncfg_interface_kind_t *kind, char *err, size_t err_size)
{
	ncfg_ops_bridge_attrs_t attrs;

	if (!kind) {
		ncfg_error_set(err, err_size, "there are no bridge settings to send");
		return 0;
	}
	memset(&attrs, 0, sizeof(attrs));
	attrs.stp = kind->bridge.stp;
	attrs.forward_delay = kind->bridge.forward_delay;
	attrs.hello_time = kind->bridge.hello_time;
	attrs.ageing_time = kind->bridge.ageing_time;
	attrs.priority = kind->bridge.priority;
	attrs.vlan_filtering = kind->bridge.vlan_filtering;
	/* The three timers stay in seconds here: `ops.h` owns the conversion to
	 * the kernel's hundredths, and a second multiplication on the way in is
	 * how a bridge comes to differ from itself by a factor of a hundred. */
	return ncfg_ops_set_bridge_attrs(out, seq, index, &attrs, err, err_size);
}

int ncfg_kernel_build_bond(ncfg_buf_t *out, uint32_t seq, uint32_t index, const char *name,
    const ncfg_interface_kind_t *kind, int with_mode, char *err, size_t err_size)
{
	ncfg_optint_t mode;

	if (!kind) {
		ncfg_error_set(err, err_size, "there are no bond settings to send");
		return 0;
	}
	mode.has = 0;
	mode.value = 0;
	if (with_mode) {
		int number = ncfg_bond_mode_number(kind->bond.mode);

		if (number < 0) {
			ncfg_error_set(err, err_size,
			    "%s asks for a bonding mode this build has no number for",
			    name ? name : "?");
			return 0;
		}
		mode.has = 1;
		mode.value = number;
	}
	return ncfg_ops_set_bond_attrs(out, seq, index, mode, kind->bond.miimon, err, err_size);
}

int ncfg_kernel_build_kind(ncfg_buf_t *out, uint32_t seq, uint32_t index, const char *name,
    const ncfg_interface_kind_t *kind, ncfg_kernel_index_fn resolve, void *context, char *err,
    size_t err_size)
{
	ncfg_ops_newlink_t link;

	if (!ncfg_kernel_newlink_of(kind, name, resolve, context, &link, err, err_size)) {
		return 0;
	}
	return ncfg_ops_set_link_kind(out, seq, index, &link, err, err_size);
}

int ncfg_kernel_build_token(ncfg_buf_t *out, uint32_t seq, uint32_t index, const char *name,
    const char *token, char *err, size_t err_size)
{
	ncfg_wire_ip_t address;

	if (!token) {
		ncfg_error_set(err, err_size, "link.set_ipv6_token on %s carries no token",
		    name ? name : "?");
		return 0;
	}
	if (!ncfg_wire_ip_parse(token, &address, err, err_size)) {
		return 0;
	}
	/* An IPv4 address here is refused by `ncfg_ops_set_ipv6_token` and not a
	 * second time by this file: that builder already says which, and the
	 * sentence it gives is the one an operator needs. A check here as well
	 * would be a second rule about the same field, in the module least likely
	 * to be read when the first one changes. */
	return ncfg_ops_set_ipv6_token(out, seq, index, &address, err, err_size);
}

int ncfg_kernel_build_bridge_vlan(ncfg_buf_t *out, uint32_t seq, uint32_t index,
    const ncfg_op_t *op, int adding, char *err, size_t err_size)
{
	ncfg_ops_vlan_change_t change;

	if (!op) {
		ncfg_error_set(err, err_size, "there is no bridge vlan action to carry out");
		return 0;
	}
	memset(&change, 0, sizeof(change));
	/* Checked rather than cast, which is the port's rule wherever the model's
	 * `int64_t` meets a kernel field: a VLAN id is twelve bits, and truncating
	 * 4097 to 1 would put a port in the VLAN the kernel adds by itself -- the
	 * one every real trunk setup begins by deleting. */
	if (op->u.bridge_vlan.vid < 1 || op->u.bridge_vlan.vid > 4094) {
		ncfg_error_set(err, err_size,
		    "%lld is not a vlan id: they run from 1 to 4094, 0 meaning `no vlan` and "
		    "4095 being reserved", (long long)op->u.bridge_vlan.vid);
		return 0;
	}
	change.vid = (uint16_t)op->u.bridge_vlan.vid;
	change.on_self = op->u.bridge_vlan.on_self;
	change.add = adding;
	if (adding) {
		change.pvid = op->u.bridge_vlan.pvid;
		change.untagged = op->u.bridge_vlan.untagged;
	}
	/*
	 * The two flags are deliberately not sent on a removal. They say what a
	 * VLAN *is* on a port -- which untagged traffic joins it, whether egress
	 * leaves untagged -- and the kernel matches a delete on the id; carrying
	 * them would make a removal that failed to match look like one that
	 * succeeded against a differently flagged VLAN. The op does not carry
	 * them either, which is the planner saying the same thing.
	 */
	return ncfg_ops_set_bridge_vlan(out, seq, index, &change, err, err_size);
}

/* ------------------------------------------------------------------------ *
 * The arms
 * ------------------------------------------------------------------------ */

/*
 * Send what was built, and free the buffer either way.
 *
 * `built` comes in rather than being computed here because the three builders
 * take different arguments; what is shared is the part that must not be
 * forgotten -- checking the acknowledgement, and freeing a message whose build
 * failed.
 */
static int send_and_free(const ncfg_kernel_world_t *world, int op_kind, const char *doing,
    ncfg_buf_t *message, uint32_t seq, int built, char *err, size_t err_size)
{
	int ok = built;

	if (ok) {
		ok = ncfg_kernel_send(world->socket, message, seq, op_kind, doing, err, err_size);
	}
	ncfg_buf_free(message);
	return ok;
}

int ncfg_kernel_link_kind_op(const ncfg_kernel_world_t *world, const ncfg_op_t *op, char *err,
    size_t err_size)
{
	const ncfg_interface_kind_t *kind;
	ncfg_buf_t                   message;
	char                         doing[NCFG_ERROR_MAX];
	const char                  *name;
	uint32_t                     index;
	uint32_t                     seq;
	int                          want;
	int                          built;

	switch (op->kind) {
	case NCFG_OP_LINK_SET_BRIDGE:
		name = op->u.named.name;
		want = NCFG_KIND_BRIDGE;
		break;
	case NCFG_OP_LINK_SET_BOND:
		name = op->u.set_bond.name;
		want = NCFG_KIND_BOND;
		break;
	case NCFG_OP_LINK_SET_MACVLAN:
		name = op->u.named.name;
		want = NCFG_KIND_MACVLAN;
		break;
	case NCFG_OP_LINK_SET_TUNNEL:
		name = op->u.named.name;
		want = NCFG_KIND_TUNNEL;
		break;
	case NCFG_OP_LINK_SET_VXLAN:
		name = op->u.named.name;
		want = NCFG_KIND_VXLAN;
		break;
	default:
		ncfg_error_set(err, err_size,
		    "%s is not one of the link-kind actions this file carries out; that is a "
		    "defect in the executor, not in the plan", ncfg_op_name(op));
		return 0;
	}

	kind = ncfg_kernel_kind_of(world->document, name, want, err, err_size);
	if (!kind) {
		return 0;
	}
	index = world->resolve(world->context, name, err, err_size);
	if (index == 0) {
		return 0;
	}
	seq = ncfg_netlink_take_seq(world->socket);
	ncfg_buf_init(&message, 0);
	if (op->kind == NCFG_OP_LINK_SET_BRIDGE) {
		built = ncfg_kernel_build_bridge(&message, seq, index, kind, err, err_size);
	} else if (op->kind == NCFG_OP_LINK_SET_BOND) {
		built = ncfg_kernel_build_bond(&message, seq, index, name, kind,
		    op->u.set_bond.mode, err, err_size);
	} else {
		built = ncfg_kernel_build_kind(&message, seq, index, name, kind, world->resolve,
		    world->context, err, err_size);
	}
	(void)snprintf(doing, sizeof(doing), "set the settings of %s", name);
	return send_and_free(world, op->kind, doing, &message, seq, built, err, err_size);
}

int ncfg_kernel_token_op(const ncfg_kernel_world_t *world, const ncfg_op_t *op, char *err,
    size_t err_size)
{
	ncfg_buf_t message;
	char       doing[NCFG_ERROR_MAX];
	const char *name = op->u.set_ipv6_token.name;
	uint32_t   index = world->resolve(world->context, name, err, err_size);
	uint32_t   seq;
	int        built;

	if (index == 0) {
		return 0;
	}
	seq = ncfg_netlink_take_seq(world->socket);
	ncfg_buf_init(&message, 0);
	built = ncfg_kernel_build_token(&message, seq, index, name, op->u.set_ipv6_token.token,
	    err, err_size);
	(void)snprintf(doing, sizeof(doing), "set an IPv6 token on %s", name ? name : "?");
	return send_and_free(world, op->kind, doing, &message, seq, built, err, err_size);
}

int ncfg_kernel_bridge_vlan_op(const ncfg_kernel_world_t *world, const ncfg_op_t *op,
    int adding, char *err, size_t err_size)
{
	ncfg_buf_t  message;
	char        doing[NCFG_ERROR_MAX];
	const char *name = op->u.bridge_vlan.iface;
	uint32_t    index = world->resolve(world->context, name, err, err_size);
	uint32_t    seq;
	int         built;

	if (index == 0) {
		return 0;
	}
	seq = ncfg_netlink_take_seq(world->socket);
	ncfg_buf_init(&message, 0);
	built = ncfg_kernel_build_bridge_vlan(&message, seq, index, op, adding, err, err_size);
	(void)snprintf(doing, sizeof(doing), "%s vlan %lld %s %s", adding ? "put" : "remove",
	    (long long)op->u.bridge_vlan.vid, adding ? "on" : "from", name ? name : "?");
	return send_and_free(world, op->kind, doing, &message, seq, built, err, err_size);
}
