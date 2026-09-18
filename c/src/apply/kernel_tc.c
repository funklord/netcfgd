/*
 * kernel_tc.c -- the root qdisc, and the ingress hook a redirect hangs off.
 *
 * WHAT NETCFGD IS ALLOWED TO DO HERE
 *   Decision 0023, and `qdisc.h` enforces the whole of it: the **root** qdisc
 *   on an interface netcfgd manages -- a named algorithm and at most a rate --
 *   plus the ingress hook and one filter that redirects onto an `ifb`. No
 *   class tree, no filter language, nothing below the root. This file chooses
 *   none of that; it turns four ops into the requests that module already
 *   writes.
 *
 * THE `EINVAL` DANCE IS THE ONLY INTERESTING THING IN HERE, AND IT IS NOT
 * OPTIONAL
 *   `qdisc.h` spells it out: naming a handle turns a replace into a *change of
 *   the qdisc already wearing it*, and a qdisc cannot change kind -- so
 *   replacing `fq_codel 6e:` with `cake` at the same handle answers `EINVAL`,
 *   and `tc qdisc replace ... handle 6e: cake` fails identically. netcfgd
 *   names a handle so that the qdisc carries its own ownership (0137), so the
 *   caller has to answer `EINVAL` by deleting the root and **building this
 *   same request again**, at a fresh sequence number.
 *
 *   Both halves of that sentence matter. Building again rather than resending
 *   the buffer, because a resent buffer reuses a sequence number the reply
 *   loop has already matched an error against -- the next acknowledgement
 *   would be ambiguous. And at a fresh number for the same reason.
 *
 *   It reopens the unshaped window `NLM_F_REPLACE` was chosen to close, for
 *   one round trip, and only when the scheduler itself changes -- a
 *   configuration edit somebody made rather than something netcfgd does on its
 *   own.
 *
 * WHY THE REDIRECT IS TWO MESSAGES BUILT TOGETHER
 *   The kernel has nowhere to put a classifier until the ingress qdisc exists
 *   and the error for that is a bare `EINVAL`, so the hook goes first. Built
 *   as a pair rather than sent by two arms, so the order is a property of the
 *   module that a test can assert instead of a habit of its caller.
 */
#include "kernel_internal.h"

#include "ncfg/base.h"

#include <errno.h>
#include <stdio.h>

int ncfg_kernel_build_qdisc(ncfg_buf_t *out, uint32_t seq, uint32_t index,
    const ncfg_op_t *op, char *err, size_t err_size)
{
	ncfg_qdisc_root_t root;

	if (!op) {
		ncfg_error_set(err, err_size, "there is no qdisc action to carry out");
		return 0;
	}
	if (op->kind == NCFG_OP_QDISC_RESET) {
		return ncfg_qdisc_build_delete_root(out, seq, index, err, err_size);
	}
	root.kind = op->u.qdisc.kind;
	root.ingress = op->u.qdisc.ingress;
	root.has_bandwidth = op->u.qdisc.bandwidth_bits.has;
	root.bandwidth_bits = 0;
	if (root.has_bandwidth) {
		/*
		 * Checked rather than cast. The rate is the model's `int64_t` and
		 * the kernel's field is unsigned, so a negative one would arrive as
		 * an enormous rate -- which `ncfg_qdisc_rate_bytes` would accept and
		 * which reads in `tc qdisc show` as a line faster than the hardware.
		 */
		if (op->u.qdisc.bandwidth_bits.value < 0) {
			ncfg_error_set(err, err_size,
			    "%lld is not a rate: a bandwidth is bits per second and cannot be "
			    "negative", (long long)op->u.qdisc.bandwidth_bits.value);
			return 0;
		}
		root.bandwidth_bits = (uint64_t)op->u.qdisc.bandwidth_bits.value;
	}
	return ncfg_qdisc_build_set_root(out, seq, index, &root, err, err_size);
}

int ncfg_kernel_build_redirect(ncfg_buf_t *first, ncfg_buf_t *second, uint32_t seq,
    uint32_t index, uint32_t target, char *err, size_t err_size)
{
	if (!ncfg_qdisc_build_add_ingress(first, seq, index, err, err_size)) {
		return 0;
	}
	/* `seq + 1`, which the caller must not hand to anything else: the two are
	 * acknowledged separately and a shared number would make the second
	 * reply's match a coincidence. */
	return ncfg_qdisc_build_redirect(second, seq + 1u, index, target, err, err_size);
}

/* ------------------------------------------------------------------------ *
 * The arms
 * ------------------------------------------------------------------------ */

int ncfg_kernel_qdisc_op(const ncfg_kernel_world_t *world, const ncfg_op_t *op, char *err,
    size_t err_size)
{
	ncfg_buf_t  message;
	char        doing[NCFG_ERROR_MAX];
	const char *iface;
	uint32_t    index;
	uint32_t    seq;
	int         code = 0;
	int         ok;

	iface = op->kind == NCFG_OP_QDISC_RESET ? op->u.iface.iface : op->u.qdisc.iface;
	index = world->resolve(world->context, iface, err, err_size);
	if (index == 0) {
		return 0;
	}
	if (op->kind == NCFG_OP_QDISC_RESET) {
		seq = ncfg_netlink_take_seq(world->socket);
		ncfg_buf_init(&message, 0);
		ok = ncfg_kernel_build_qdisc(&message, seq, index, op, err, err_size);
		if (ok) {
			(void)snprintf(doing, sizeof(doing),
			    "restore the default qdisc on %s", iface ? iface : "?");
			ok = ncfg_kernel_send(world->socket, &message, seq, op->kind, doing, err,
			    err_size);
		}
		ncfg_buf_free(&message);
		return ok;
	}

	(void)snprintf(doing, sizeof(doing), "set %s on %s",
	    op->u.qdisc.kind ? op->u.qdisc.kind : "a qdisc", iface ? iface : "?");
	seq = ncfg_netlink_take_seq(world->socket);
	ncfg_buf_init(&message, 0);
	ok = ncfg_kernel_build_qdisc(&message, seq, index, op, err, err_size);
	if (ok) {
		ok = ncfg_kernel_send_reporting(world->socket, &message, seq, &code, doing, err,
		    err_size);
	}
	ncfg_buf_free(&message);
	if (ok || code != EINVAL) {
		if (!ok) {
			const char *hint = ncfg_kernel_hint(op->kind, code);

			if (hint) {
				char detail[NCFG_ERROR_MAX];

				(void)snprintf(detail, sizeof(detail), "%s", err);
				ncfg_error_set(err, err_size, "%s; %s", detail, hint);
			}
		}
		return ok;
	}

	/*
	 * `EINVAL` is the scheduler changing under a handle netcfgd owns. Delete
	 * the root -- which puts `net.core.default_qdisc` back for one round trip
	 * -- and build the request again.
	 */
	seq = ncfg_netlink_take_seq(world->socket);
	ncfg_buf_init(&message, 0);
	ok = ncfg_qdisc_build_delete_root(&message, seq, index, err, err_size);
	if (ok) {
		char clearing[NCFG_ERROR_MAX];

		(void)snprintf(clearing, sizeof(clearing),
		    "clear the old root qdisc on %s before changing its scheduler",
		    iface ? iface : "?");
		/* Tolerated as a `qdisc.reset` would be: `ENOENT` and `EINVAL` here
		 * mean there was nothing to remove, which is the state the second
		 * attempt wants anyway. */
		ok = ncfg_kernel_send(world->socket, &message, seq, NCFG_OP_QDISC_RESET, clearing,
		    err, err_size);
	}
	ncfg_buf_free(&message);
	if (!ok) {
		return 0;
	}
	seq = ncfg_netlink_take_seq(world->socket);
	ncfg_buf_init(&message, 0);
	ok = ncfg_kernel_build_qdisc(&message, seq, index, op, err, err_size);
	if (ok) {
		ok = ncfg_kernel_send(world->socket, &message, seq, op->kind, doing, err, err_size);
	}
	ncfg_buf_free(&message);
	return ok;
}

int ncfg_kernel_ingress_op(const ncfg_kernel_world_t *world, const ncfg_op_t *op,
    int redirecting, char *err, size_t err_size)
{
	ncfg_buf_t  hook;
	ncfg_buf_t  filter;
	char        doing[NCFG_ERROR_MAX];
	const char *iface = redirecting ? op->u.redirect.iface : op->u.iface.iface;
	uint32_t    index = world->resolve(world->context, iface, err, err_size);
	uint32_t    target;
	uint32_t    seq;
	int         ok;

	if (index == 0) {
		return 0;
	}
	if (!redirecting) {
		/* Removing the hook takes every filter hanging off it, so there is
		 * nothing to delete separately -- which is also why netcfgd never has
		 * to know which of the filters on an interface it wrote. */
		seq = ncfg_netlink_take_seq(world->socket);
		ncfg_buf_init(&hook, 0);
		ok = ncfg_qdisc_build_delete_ingress(&hook, seq, index, err, err_size);
		if (ok) {
			(void)snprintf(doing, sizeof(doing), "remove the ingress hook from %s",
			    iface ? iface : "?");
			ok = ncfg_kernel_send(world->socket, &hook, seq, op->kind, doing, err,
			    err_size);
		}
		ncfg_buf_free(&hook);
		return ok;
	}

	target = world->resolve(world->context, op->u.redirect.target, err, err_size);
	if (target == 0) {
		return 0;
	}
	/* Two numbers taken together, because `ncfg_kernel_build_redirect` uses
	 * `seq` and `seq + 1` and the second must not be handed out twice. */
	seq = ncfg_netlink_take_seq(world->socket);
	(void)ncfg_netlink_take_seq(world->socket);
	ncfg_buf_init(&hook, 0);
	ncfg_buf_init(&filter, 0);
	ok = ncfg_kernel_build_redirect(&hook, &filter, seq, index, target, err, err_size);
	if (ok) {
		(void)snprintf(doing, sizeof(doing), "attach the ingress hook to %s",
		    iface ? iface : "?");
		ok = ncfg_kernel_send(world->socket, &hook, seq, op->kind, doing, err, err_size);
	}
	if (ok) {
		(void)snprintf(doing, sizeof(doing), "redirect %s to %s", iface ? iface : "?",
		    op->u.redirect.target ? op->u.redirect.target : "?");
		ok = ncfg_kernel_send(world->socket, &filter, seq + 1u, op->kind, doing, err,
		    err_size);
	}
	ncfg_buf_free(&filter);
	ncfg_buf_free(&hook);
	return ok;
}
