/*
 * genl_socket.c -- a generic netlink socket with one family resolved on it.
 *
 * Moved out of `apply/kernel_genl.c`, unchanged, when `ncfg status` needed
 * the same lookup for nl80211 that the executor makes for WireGuard and
 * ethtool. It sits between `socket.c`, which holds descriptors and parses
 * nothing, and `genl.c`, which parses and holds nothing -- calling both, as
 * `kernel_genl.c` did, so neither file's rule bends.
 */
#include "ncfg/genl_socket.h"

#include "ncfg/wire.h"

#include <string.h>

/* The same five seconds `kernel.c` gives an rtnetlink request, and for its
 * reason: a daemon holding CAP_NET_ADMIN wedged on a lost message is worse
 * than one that reports an error. */
#define REQUEST_SECONDS 5

int ncfg_genl_family_open(const char *name, ncfg_netlink_t *socket, ncfg_genl_family_t *family,
    char *err, size_t err_size)
{
	ncfg_buf_t           message;
	ncfg_buf_t           body;
	ncfg_netlink_reply_t reply;
	uint16_t             kind = 0;
	uint16_t             flags = 0;
	uint32_t             seq;
	int                  ok;

	memset(family, 0, sizeof(*family));
	ncfg_netlink_init(socket);
	if (!ncfg_netlink_open_protocol(socket, NETLINK_GENERIC, 0, err, err_size)) {
		return 0;
	}
	if (!ncfg_netlink_set_timeout(socket, REQUEST_SECONDS, err, err_size)) {
		ncfg_netlink_close(socket);
		return 0;
	}
	seq = ncfg_netlink_take_seq(socket);
	ncfg_buf_init(&message, 0);
	ncfg_buf_init(&body, 0);
	memset(&reply, 0, sizeof(reply));
	ok = ncfg_genl_getfamily_request(&message, name, seq, err, err_size) &&
	    ncfg_wire_request_parts(&message, "generic netlink", &kind, &flags, &body, err, err_size);
	if (ok) {
		ok = ncfg_netlink_request(socket, kind, flags, &body, NULL, &reply, err, err_size);
		/* The kernel refused the lookup: say it as a lookup. The sentence
		 * `ncfg_netlink_request` wrote names the controller's message type,
		 * 16, as `RTM_NEWLINK`, so a missing WireGuard module read as a link
		 * that could not be created. */
		if (!ok && reply.refused != 0) {
			(void)ncfg_genl_lookup_failed(name, reply.refused, err, err_size);
		}
	}
	ncfg_buf_free(&message);
	ncfg_buf_free(&body);
	if (ok && reply.count == 0) {
		/*
		 * The controller answered and named no family. `ncfg_genl_lookup_
		 * failed` is for a kernel that refused; this is a reply that arrived
		 * and said nothing, which reads downstream as a family with id zero
		 * -- and `ncfg_genl_build_request` refuses that, five seconds later
		 * and about the wrong thing.
		 */
		ncfg_error_set(err, err_size,
		    "the generic netlink controller answered about `%s` without naming a "
		    "family", name);
		ok = 0;
	}
	if (ok) {
		ok = ncfg_genl_family_parse(name, reply.items[0].bytes, reply.items[0].length,
		    family, err, err_size);
	}
	ncfg_netlink_reply_free(&reply);
	if (!ok) {
		ncfg_netlink_close(socket);
	}
	return ok;
}
