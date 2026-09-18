/*
 * kernel.c -- the executor that talks to the kernel.
 *
 * **Nothing under `tests/` constructs one of these.** Every property this
 * module has -- the order, the stop at the first failure, the journal, the
 * revert -- is checked against a recorder through `ncfg_executor_t`, which is
 * what the seam exists for. This file is the other side of it, and it opens a
 * netlink socket and changes the machine the process is running on.
 *
 * WHAT IT DOES, AND HOW LITTLE OF IT THERE IS
 *   Exactly the ops this build's planner emits: links, addresses, routes,
 *   hooks and the commit markers. `ncfg_apply_supported` is the list and the
 *   refusals, in one place, so that "what can this carry out?" is a value a
 *   test can ask about rather than a shape of the code. Every op reaches that
 *   question before it reaches anything else here.
 *
 * WHY THE INDEX IS LOOKED UP RATHER THAN CACHED
 *   The Rust keeps a `(name, index)` map and has to clear it after every
 *   `link.create`, because the map is stale the moment a link appears. That is
 *   a cache whose invalidation is a rule somebody has to remember. `if_name
 *   toindex` is one syscall, a plan is tens of actions, and a lookup taken at
 *   the moment of use cannot be stale -- so the rule disappears rather than
 *   being written down. Divergence, and a deliberate one.
 */
#include "ncfg/apply.h"

#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/netlink.h"
#include "ncfg/ops.h"
#include "ncfg/value.h"
#include "ncfg/wire.h"

#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct ncfg_kernel {
	ncfg_netlink_t         socket;
	/* Borrowed from the document; see `ncfg_kernel_set_hooks`. */
	const ncfg_hook_ref_t *hooks;
	size_t                 hook_count;
};

/* How long a request waits for the kernel before it is a failure rather than a
 * hang. A daemon holding CAP_NET_ADMIN that is wedged on a lost message is
 * worse than one that reports an error. */
#define REQUEST_SECONDS 5

ncfg_kernel_t *ncfg_kernel_new(char *err, size_t err_size)
{
	ncfg_kernel_t *kernel = calloc(1u, sizeof(*kernel));

	if (!kernel) {
		ncfg_error_set(err, err_size, "there was not enough memory for an executor");
		return NULL;
	}
	ncfg_netlink_init(&kernel->socket);
	if (!ncfg_netlink_open(&kernel->socket, err, err_size)) {
		free(kernel);
		return NULL;
	}
	if (!ncfg_netlink_set_timeout(&kernel->socket, REQUEST_SECONDS, err, err_size)) {
		ncfg_netlink_close(&kernel->socket);
		free(kernel);
		return NULL;
	}
	return kernel;
}

void ncfg_kernel_free(ncfg_kernel_t *kernel)
{
	if (!kernel) {
		return;
	}
	ncfg_netlink_close(&kernel->socket);
	free(kernel);
}

void ncfg_kernel_set_hooks(ncfg_kernel_t *kernel, const ncfg_hook_ref_t *hooks, size_t count)
{
	if (kernel) {
		kernel->hooks = hooks;
		kernel->hook_count = count;
	}
}

/* ------------------------------------------------------------------------ *
 * Talking to the socket
 * ------------------------------------------------------------------------ */

/*
 * The kernel's index for a name.
 *
 * 0 is not a valid index, so it doubles as the failure, and the sentence names
 * the interface rather than the call: an operator reading "eth0 is not an
 * interface this kernel knows" needs no further translation.
 */
static uint32_t index_of(const char *name, char *err, size_t err_size)
{
	unsigned index;

	if (!name || name[0] == '\0') {
		ncfg_error_set(err, err_size, "an action names no interface to act on");
		return 0;
	}
	index = if_nametoindex(name);
	if (index == 0) {
		ncfg_error_set(err, err_size, "%s is not an interface this kernel knows", name);
		return 0;
	}
	return (uint32_t)index;
}

/*
 * Send one built message and wait for its acknowledgement.
 *
 * `ncfg_netlink_send_batch` rather than `ncfg_netlink_request`, because the
 * `ncfg_ops_*` builders produce the whole request -- header and all -- and the
 * request call builds its own. Waiting on the sequence number the builder was
 * given is what turns "sent" into "the kernel took it".
 */
static int send_built(ncfg_kernel_t *kernel, const ncfg_buf_t *message, uint32_t seq,
    const char *doing, char *err, size_t err_size)
{
	ncfg_netlink_reply_t reply;
	char                 detail[NCFG_ERROR_MAX];
	int                  sent;

	if (ncfg_buf_failed(message)) {
		ncfg_error_set(err, err_size, "could not build the message to %s", doing);
		return 0;
	}
	detail[0] = '\0';
	memset(&reply, 0, sizeof(reply));
	sent = ncfg_netlink_send_batch(&kernel->socket, message->data, message->length, seq,
	    &reply, detail, sizeof(detail));
	ncfg_netlink_reply_free(&reply);
	if (!sent) {
		/* The builder's own sentence says which field; this one says which
		 * action, because a journal entry reading only "Invalid argument" is
		 * an operator's dead end. */
		ncfg_error_set(err, err_size, "could not %s: %s", doing, detail);
		return 0;
	}
	return 1;
}

/* ------------------------------------------------------------------------ *
 * Links
 * ------------------------------------------------------------------------ */

/*
 * The model's kind as the wire layer wants it.
 *
 * Only the kinds that need no numbering the model does not carry -- `apply.c`'s
 * `creatable` is where that boundary is drawn and why, and it has already been
 * asked by the time this runs. This is the conversion, not the decision.
 */
static int newlink_of(const ncfg_op_t *op, ncfg_ops_newlink_t *out, char *err, size_t err_size)
{
	const ncfg_interface_kind_t *kind = op->u.link_create.kind;
	const char                  *name = op->u.link_create.name;

	memset(out, 0, sizeof(*out));
	switch ((ncfg_interface_kind_tag_t)kind->kind) {
	case NCFG_KIND_BRIDGE:
		/*
		 * The link and nothing else. A bridge takes no settings at creation --
		 * the kernel would accept `IFLA_INFO_DATA` there, but changing them
		 * later has to be a separate `RTM_NEWLINK` anyway, and having one path
		 * rather than two is what stops the create case and the
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
		/* Resolved here rather than carried as a name, because the kernel
		 * wants an index and the underlay may have been created earlier in
		 * this same plan. */
		if (kind->vxlan.parent) {
			uint32_t parent = index_of(kind->vxlan.parent, err, err_size);

			if (parent == 0) {
				return 0;
			}
			out->vxlan.parent.has = 1;
			out->vxlan.parent.value = (int64_t)parent;
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
	case NCFG_KIND_TUN:
	case NCFG_KIND_PHYSICAL:
	case NCFG_KIND_PPPOE:
	case NCFG_KIND_OPENVPN:
	case NCFG_KIND_VLAN:
	case NCFG_KIND_BOND:
	case NCFG_KIND_MACVLAN:
	case NCFG_KIND_TUNNEL:
		break;
	}
	/*
	 * Unreachable through `execute`, which asks `ncfg_apply_supported` first.
	 * Said rather than left as a fall-through, so that a second caller finds a
	 * sentence instead of a link half made.
	 */
	ncfg_error_set(err, err_size,
	    "%s is a kind this executor does not build a netlink message for", name);
	return 0;
}

static int create_link(ncfg_kernel_t *kernel, const ncfg_op_t *op, char *err, size_t err_size)
{
	ncfg_ops_newlink_t link;
	ncfg_buf_t         message;
	uint32_t           seq;
	int                built;

	if (!newlink_of(op, &link, err, err_size)) {
		return 0;
	}
	seq = ncfg_netlink_take_seq(&kernel->socket);
	ncfg_buf_init(&message, 0);
	built = ncfg_ops_create_link(&message, seq, op->u.link_create.name, &link, err, err_size);
	if (built) {
		char doing[NCFG_ERROR_MAX];

		(void)snprintf(doing, sizeof(doing), "create %s", op->u.link_create.name);
		built = send_built(kernel, &message, seq, doing, err, err_size);
	}
	ncfg_buf_free(&message);
	return built;
}

/*
 * The shape every other link op has: resolve the index, build, send.
 *
 * A function pointer rather than nine near-identical blocks, because the three
 * steps are the same three every time and the only thing that differs is the
 * builder -- and nine copies of a send is nine places for one of them to
 * forget to check the acknowledgement.
 */
typedef int (*link_builder_t)(ncfg_buf_t *out, uint32_t seq, uint32_t index,
    const ncfg_op_t *op, char *err, size_t err_size);

static int on_link(ncfg_kernel_t *kernel, const char *name, const ncfg_op_t *op,
    link_builder_t build, const char *doing, char *err, size_t err_size)
{
	ncfg_buf_t message;
	uint32_t   index = index_of(name, err, err_size);
	uint32_t   seq;
	int        ok;

	if (index == 0) {
		return 0;
	}
	seq = ncfg_netlink_take_seq(&kernel->socket);
	ncfg_buf_init(&message, 0);
	ok = build(&message, seq, index, op, err, err_size);
	if (ok) {
		ok = send_built(kernel, &message, seq, doing, err, err_size);
	}
	ncfg_buf_free(&message);
	return ok;
}

static int build_delete(ncfg_buf_t *out, uint32_t seq, uint32_t index, const ncfg_op_t *op,
    char *err, size_t err_size)
{
	(void)op;
	return ncfg_ops_delete_link(out, seq, index, err, err_size);
}

static int build_up(ncfg_buf_t *out, uint32_t seq, uint32_t index, const ncfg_op_t *op,
    char *err, size_t err_size)
{
	return ncfg_ops_set_link_up(out, seq, index, op->kind == NCFG_OP_LINK_UP, err, err_size);
}

static int build_mtu(ncfg_buf_t *out, uint32_t seq, uint32_t index, const ncfg_op_t *op,
    char *err, size_t err_size)
{
	ncfg_optint_t mtu;
	uint32_t      narrowed;

	mtu.has = 1;
	mtu.value = op->u.set_mtu.mtu;
	/* Checked rather than cast, which is the port's rule wherever the model's
	 * `int64_t` meets a kernel field: `IFLA_MTU` is a `u32`, and truncating
	 * would set an MTU nobody asked for on an interface that was working. */
	if (!ncfg_ops_narrow(mtu, 0xffffffff, "mtu", &narrowed, err, err_size)) {
		return 0;
	}
	return ncfg_ops_set_link_mtu(out, seq, index, narrowed, err, err_size);
}

static int build_mac(ncfg_buf_t *out, uint32_t seq, uint32_t index, const ncfg_op_t *op,
    char *err, size_t err_size)
{
	uint8_t mac[6];

	if (!op->u.set_mac.mac) {
		ncfg_error_set(err, err_size, "link.set_mac on %s carries no address",
		    op->u.set_mac.name);
		return 0;
	}
	if (!ncfg_ops_parse_mac(op->u.set_mac.mac, mac, err, err_size)) {
		return 0;
	}
	return ncfg_ops_set_link_mac(out, seq, index, mac, err, err_size);
}

static int build_unset_master(ncfg_buf_t *out, uint32_t seq, uint32_t index,
    const ncfg_op_t *op, char *err, size_t err_size)
{
	(void)op;
	/* Zero is how the kernel is told "no master": there is no separate
	 * message for releasing one. */
	return ncfg_ops_set_link_master(out, seq, index, 0, err, err_size);
}

/* The master's index has to be resolved before the builder runs, and a
 * builder takes only the op -- so this one is written out rather than
 * squeezed through `on_link`. */
static int set_master(ncfg_kernel_t *kernel, const ncfg_op_t *op, char *err, size_t err_size)
{
	ncfg_buf_t message;
	uint32_t   index = index_of(op->u.set_master.name, err, err_size);
	uint32_t   master;
	uint32_t   seq;
	int        ok;

	if (index == 0) {
		return 0;
	}
	master = index_of(op->u.set_master.master, err, err_size);
	if (master == 0) {
		return 0;
	}
	seq = ncfg_netlink_take_seq(&kernel->socket);
	ncfg_buf_init(&message, 0);
	ok = ncfg_ops_set_link_master(&message, seq, index, master, err, err_size);
	if (ok) {
		char doing[NCFG_ERROR_MAX];

		(void)snprintf(doing, sizeof(doing), "enslave %s to %s", op->u.set_master.name,
		    op->u.set_master.master);
		ok = send_built(kernel, &message, seq, doing, err, err_size);
	}
	ncfg_buf_free(&message);
	return ok;
}

/* ------------------------------------------------------------------------ *
 * Addresses
 * ------------------------------------------------------------------------ */

static int address(ncfg_kernel_t *kernel, const char *iface, const char *cidr, int adding,
    char *err, size_t err_size)
{
	ncfg_address_t parsed;
	ncfg_wire_ip_t ip;
	ncfg_buf_t     message;
	char           doing[NCFG_ERROR_MAX];
	uint32_t       index;
	uint32_t       seq;
	int            ok;

	if (!cidr) {
		ncfg_error_set(err, err_size, "an address action on %s carries no address",
		    iface ? iface : "?");
		return 0;
	}
	if (!ncfg_address_parse(cidr, &parsed, err, err_size)) {
		return 0;
	}
	if (!parsed.has_prefix) {
		/* The kernel needs a prefix length and there is no sensible default:
		 * assuming /32 would put a host route where an operator wrote a
		 * network, and assuming the classful length is forty years out of
		 * date. */
		ncfg_error_set(err, err_size, "%s is not an address with a prefix length", cidr);
		return 0;
	}
	if (!ncfg_ops_ip_from_address(&parsed, &ip, err, err_size)) {
		return 0;
	}
	index = index_of(iface, err, err_size);
	if (index == 0) {
		return 0;
	}
	seq = ncfg_netlink_take_seq(&kernel->socket);
	ncfg_buf_init(&message, 0);
	if (adding) {
		ok = ncfg_ops_add_address(&message, seq, index, &ip, (uint8_t)parsed.prefix,
		    (uint8_t)NCFG_ROUTE_PROTO, err, err_size);
	} else {
		ok = ncfg_ops_del_address(&message, seq, index, &ip, (uint8_t)parsed.prefix, err,
		    err_size);
	}
	if (ok) {
		(void)snprintf(doing, sizeof(doing), "%s %s %s %s", adding ? "add" : "remove", cidr,
		    adding ? "to" : "from", iface);
		ok = send_built(kernel, &message, seq, doing, err, err_size);
	}
	ncfg_buf_free(&message);
	return ok;
}

/* ------------------------------------------------------------------------ *
 * Routes
 * ------------------------------------------------------------------------ */

/*
 * The model's route as the wire layer wants it.
 *
 * `default` is the destination with no prefix at all, which is the one
 * spelling the model uses for it: an absent destination and a zero length are
 * what the kernel reads as "everything".
 */
static int route_of(const ncfg_route_t *route, uint32_t index, ncfg_ops_route_t *out,
    char *err, size_t err_size)
{
	memset(out, 0, sizeof(*out));
	out->index = index;
	out->metric = route->metric;
	out->table = route->table;
	out->proto = route->proto;
	out->onlink = route->onlink;
	if (route->destination && strcmp(route->destination, "default") != 0) {
		ncfg_address_t parsed;

		if (!ncfg_address_parse(route->destination, &parsed, err, err_size)) {
			return 0;
		}
		if (!ncfg_ops_ip_from_address(&parsed, &out->destination, err, err_size)) {
			return 0;
		}
		/* A destination written without a length is a host route, which is
		 * what `ip route add 10.0.0.5 via ...` means and what the model
		 * records when an operator writes it that way. */
		out->dst_len = parsed.has_prefix ? (uint8_t)parsed.prefix :
		    (uint8_t)(parsed.is_ipv6 ? 128 : 32);
	}
	if (route->via && !ncfg_wire_ip_parse(route->via, &out->gateway, err, err_size)) {
		return 0;
	}
	if (route->src && !ncfg_wire_ip_parse(route->src, &out->source, err, err_size)) {
		return 0;
	}
	return 1;
}

static int route(ncfg_kernel_t *kernel, const ncfg_op_t *op, int adding, char *err,
    size_t err_size)
{
	const ncfg_route_t *wanted = op->u.route.route;
	ncfg_ops_route_t    spec;
	ncfg_buf_t          message;
	char                doing[NCFG_ERROR_MAX];
	uint32_t            index;
	uint32_t            seq;
	int                 ok;

	if (!wanted) {
		ncfg_error_set(err, err_size, "a route action on %s carries no route",
		    op->u.route.iface ? op->u.route.iface : "?");
		return 0;
	}
	index = index_of(op->u.route.iface, err, err_size);
	if (index == 0) {
		return 0;
	}
	if (!route_of(wanted, index, &spec, err, err_size)) {
		return 0;
	}
	seq = ncfg_netlink_take_seq(&kernel->socket);
	ncfg_buf_init(&message, 0);
	ok = adding ? ncfg_ops_add_route(&message, seq, &spec, err, err_size) :
	    ncfg_ops_del_route(&message, seq, &spec, err, err_size);
	if (ok) {
		(void)snprintf(doing, sizeof(doing), "%s route %s on %s",
		    adding ? "add" : "remove",
		    wanted->destination ? wanted->destination : "default", op->u.route.iface);
		ok = send_built(kernel, &message, seq, doing, err, err_size);
	}
	ncfg_buf_free(&message);
	return ok;
}

/* ------------------------------------------------------------------------ *
 * Hooks
 * ------------------------------------------------------------------------ */

static int run_hook(ncfg_kernel_t *kernel, const ncfg_op_t *op, char *err, size_t err_size)
{
	ncfg_hook_ref_t     reference;
	ncfg_hook_env_t     env;
	ncfg_hook_outcome_t outcome;
	size_t              i;

	memset(&reference, 0, sizeof(reference));
	reference.phase = op->u.hook.phase;
	reference.path = (char *)(uintptr_t)(const void *)op->u.hook.path;
	/* The hash is not on the op -- a plan goes to `/run` and over the socket,
	 * and a hash there would restate what the document says -- so it is looked
	 * up in the document the executor was given. Nothing found means nothing to
	 * check against, and `ncfg_hook_run` refuses rather than running whatever
	 * is on disk now. */
	for (i = 0; i < kernel->hook_count; i++) {
		if (kernel->hooks[i].path && op->u.hook.path &&
		    strcmp(kernel->hooks[i].path, op->u.hook.path) == 0) {
			reference.sha256 = kernel->hooks[i].sha256;
			reference.run_as = kernel->hooks[i].run_as;
			reference.timeout = kernel->hooks[i].timeout;
			break;
		}
	}

	memset(&env, 0, sizeof(env));
	env.iface = op->u.hook.iface;
	/*
	 * One field on the op, and the phase says which variable a script should
	 * see it in: a `lease` script reads `NCFG_ADDR` because the value is an
	 * address, and a `carrier` script reads `NCFG_REASON` because the value is
	 * `up` or `down`. Putting both variables on both phases would tell a
	 * script to look in a place its own phase never fills.
	 */
	if (op->u.hook.value) {
		if (op->u.hook.phase == NCFG_HOOK_PHASE_LEASE) {
			env.addr = op->u.hook.value;
		} else if (op->u.hook.phase == NCFG_HOOK_PHASE_CARRIER) {
			env.reason = op->u.hook.value;
		}
	}

	outcome = ncfg_hook_run(&reference, &env, err, err_size);
	if (outcome == NCFG_HOOK_VETOED) {
		/* Section 5.2's whole point: you can refuse a bring-up. The sentence
		 * is already in `err`. */
		return 0;
	}
	/*
	 * A `post_*` or event hook failing does not roll anything back. Failing the
	 * plan here would leave the rest of the machine unconfigured because a
	 * logging script exited 1.
	 *
	 * **The sentence is dropped on this path**, and that is the one thing this
	 * port loses relative to the Rust, which logs it. The seam answers 1 or 0
	 * and carries no third channel, and inventing one for a case nothing yet
	 * reads would be a second reporting path to keep in step with the journal.
	 */
	if (outcome == NCFG_HOOK_NOTED && err && err_size) {
		err[0] = '\0';
	}
	return 1;
}

/* ------------------------------------------------------------------------ *
 * The dispatch
 * ------------------------------------------------------------------------ */

static int execute(void *state, const ncfg_op_t *op, char *err, size_t err_size)
{
	ncfg_kernel_t *kernel = state;

	if (!kernel || !op) {
		ncfg_error_set(err, err_size, "there is no executor or no op");
		return 0;
	}
	/* Asked first, and once. An op this build cannot carry out is refused with
	 * the sentence that names it rather than falling through to a `default`
	 * that would report success for work nobody did. */
	if (!ncfg_apply_supported(op, err, err_size)) {
		return 0;
	}
	switch ((ncfg_op_kind_t)op->kind) {
	case NCFG_OP_LINK_CREATE:
		return create_link(kernel, op, err, err_size);
	case NCFG_OP_LINK_DELETE:
		return on_link(kernel, op->u.named.name, op, build_delete, "delete the link", err,
		    err_size);
	case NCFG_OP_LINK_UP:
		return on_link(kernel, op->u.named.name, op, build_up, "bring the link up", err,
		    err_size);
	case NCFG_OP_LINK_DOWN:
		return on_link(kernel, op->u.named.name, op, build_up, "take the link down", err,
		    err_size);
	case NCFG_OP_LINK_SET_MTU:
		return on_link(kernel, op->u.set_mtu.name, op, build_mtu, "set the mtu", err,
		    err_size);
	case NCFG_OP_LINK_SET_MAC:
		return on_link(kernel, op->u.set_mac.name, op, build_mac, "set the mac", err,
		    err_size);
	case NCFG_OP_LINK_UNSET_MASTER:
		return on_link(kernel, op->u.named.name, op, build_unset_master, "release the link",
		    err, err_size);
	case NCFG_OP_LINK_SET_MASTER:
		return set_master(kernel, op, err, err_size);
	case NCFG_OP_ADDR_ADD:
		return address(kernel, op->u.addr_add.iface, op->u.addr_add.addr, 1, err, err_size);
	case NCFG_OP_ADDR_DEL:
		return address(kernel, op->u.addr_del.iface, op->u.addr_del.addr, 0, err, err_size);
	case NCFG_OP_ROUTE_ADD:
		return route(kernel, op, 1, err, err_size);
	case NCFG_OP_ROUTE_DEL:
		return route(kernel, op, 0, err, err_size);
	case NCFG_OP_HOOK_RUN:
		return run_hook(kernel, op, err, err_size);
	/* Markers. `ncfg_apply_supported` says why doing nothing is right. */
	case NCFG_OP_COMMIT_ARM:
	case NCFG_OP_COMMIT_CONFIRM:
	case NCFG_OP_COMMIT_REVERT:
		return 1;
	/* Every one of these was refused above, and is listed so that `-Wswitch`
	 * can notice an op added to the taxonomy and not answered here. */
	case NCFG_OP_BACKEND_START:
	case NCFG_OP_BACKEND_STOP:
	case NCFG_OP_BACKEND_RELOAD:
	case NCFG_OP_BRIDGE_VLAN_ADD:
	case NCFG_OP_BRIDGE_VLAN_DEL:
	case NCFG_OP_WIFI_SET_PROFILES:
	case NCFG_OP_WIFI_ASSOCIATE:
	case NCFG_OP_WIFI_DISASSOCIATE:
	case NCFG_OP_WIFI_SET_REGDOM:
	case NCFG_OP_ACCESS_CONTROL_ADD:
	case NCFG_OP_ACCESS_CONTROL_DEL:
	case NCFG_OP_LINK_SET_BOND:
	case NCFG_OP_LINK_SET_BRIDGE:
	case NCFG_OP_LINK_SET_MACVLAN:
	case NCFG_OP_LINK_SET_TUNNEL:
	case NCFG_OP_LINK_SET_VXLAN:
	case NCFG_OP_WG_SET_DEVICE:
	case NCFG_OP_WG_SET_PEERS:
	case NCFG_OP_DNS_APPLY:
	case NCFG_OP_LINK_SET_OFFLOADS:
	case NCFG_OP_LINK_SET_IPV6_TOKEN:
	case NCFG_OP_RULE_ADD:
	case NCFG_OP_RULE_DEL:
	case NCFG_OP_QDISC_SET:
	case NCFG_OP_QDISC_RESET:
	case NCFG_OP_INGRESS_REDIRECT:
	case NCFG_OP_INGRESS_REDIRECT_CLEAR:
	case NCFG_OP_SYSCTL_SET_FORWARDING:
	case NCFG_OP_SYSCTL_SET_PRIVACY:
	case NCFG_OP_SYSCTL_SET_ACCEPT_RA:
	case NCFG_OP_HOSTNAME_SET:
	case NCFG_OP_NAT_REPLACE:
		break;
	}
	ncfg_error_set(err, err_size,
	    "%s passed the list of what this build executes and reached no arm; "
	    "that is a defect in the executor, not in the plan", ncfg_op_name(op));
	return 0;
}

void ncfg_kernel_executor(ncfg_kernel_t *kernel, ncfg_executor_t *out)
{
	if (!out) {
		return;
	}
	out->state = kernel;
	out->execute = execute;
}
