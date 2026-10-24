/*
 * kernel_send.c -- getting one built message to the kernel, and reading what
 * came back as more than a sentence.
 *
 * WHY THIS IS NOT `kernel.c`'s `send_built`
 *   That one answers 1 or 0 and throws the errno away, which is right for the
 *   ops it serves: an address that could not be added has failed, and there is
 *   no code that would make it a success. Five of the ops here are different,
 *   and the difference is `plan.h`'s: **applying a plan twice must produce an
 *   empty second plan**, so the same op sent twice has to succeed twice. A
 *   rule that is already installed answers `EEXIST` and a qdisc that is
 *   already gone answers `ENOENT`, and both of those *are* the state the op
 *   asked for.
 *
 *   The code cannot be recovered from the message. `ncfg_netlink_fail` renders
 *   one string out of `strerror`, a name and a clause, and reading a decision
 *   back out of the words of a message is what `config.h` forbids by name --
 *   which is why `ncfg_netlink_reply_t` grew `refused` rather than this file
 *   growing a parser.
 *
 * TOLERATING IS A LIST, NOT A HABIT
 *   Every forgiving comparison is in `ncfg_kernel_tolerates` and nowhere else,
 *   so "which op forgives which code" is a value `apply_kernel_test.c`
 *   enumerates. The temptation this refuses is the general one -- treating
 *   `EEXIST` as success everywhere -- which would turn a `link.create` racing
 *   another daemon into a silent success and hand the rest of the plan an
 *   interface somebody else made.
 */
#include "kernel_internal.h"

#include "ncfg/base.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

int ncfg_kernel_tolerates(int op_kind, int code)
{
	switch (op_kind) {
	case NCFG_OP_RULE_ADD:
		/*
		 * `RTM_NEWRULE` carries `CREATE | EXCL`, and the kernel's
		 * `rule_exists` compares the selectors, the action and the table --
		 * so `EEXIST` means a rule netcfgd would have installed is already
		 * installed, which is exactly what the op asked for. It is not "a
		 * rule with this priority exists": a rule differing in any compared
		 * field is installed rather than refused.
		 */
		return code == EEXIST;
	case NCFG_OP_RULE_DEL:
		/* `ops.h`: `ENOENT` means it was already gone, which is also what a
		 * delete that matched nothing looks like, and the caller treats both
		 * as done. */
		return code == ENOENT;
	case NCFG_OP_BRIDGE_VLAN_DEL:
		/* A VLAN that is not on the port is the state asked for. The *add*
		 * needs no such arm: the kernel updates the flags of a VLAN that is
		 * already there and answers success. */
		return code == ENOENT;
	case NCFG_OP_QDISC_RESET:
	case NCFG_OP_INGRESS_REDIRECT_CLEAR:
		/* `qdisc.h` says both codes mean there was nothing to remove. There
		 * is no such thing as an interface without a root qdisc, so removing
		 * netcfgd's puts the kernel default back -- and doing that twice is
		 * the same machine either way. */
		return code == ENOENT || code == EINVAL;
	case NCFG_OP_INGRESS_REDIRECT:
		/*
		 * The ingress qdisc is a fixed singleton with no parameters, so
		 * `qdisc.h` sends it `EXCL` and calls `EEXIST` the success case --
		 * replacing it would take every filter hanging off it, including
		 * somebody else's. The filter that follows carries `CREATE |
		 * REPLACE` and never produces this code, so tolerating it for the op
		 * forgives exactly the message it is meant for.
		 */
		return code == EEXIST;
	default:
		return 0;
	}
}

const char *ncfg_kernel_hint(int op_kind, int code)
{
	switch (op_kind) {
	case NCFG_OP_BRIDGE_VLAN_ADD:
	case NCFG_OP_BRIDGE_VLAN_DEL:
		if (code == EOPNOTSUPP) {
			return "the bridge does not have `vlan_filtering = true`, so it has no "
			       "per-port vlans";
		}
		return NULL;
	case NCFG_OP_QDISC_SET:
		if (code == ENOENT) {
			return "this kernel has no such scheduler, and the module could not be "
			       "loaded";
		}
		return NULL;
	case NCFG_OP_INGRESS_REDIRECT:
		if (code == ENOENT) {
			return "this kernel is missing `cls_matchall` or `act_mirred`";
		}
		return NULL;
	case NCFG_OP_LINK_SET_IPV6_TOKEN:
		if (code == EINVAL) {
			/*
			 * The kernel returns a bare `EINVAL` for four different
			 * preconditions, so the message has to name them: "Invalid
			 * argument" on its own sends an operator looking at the
			 * address, which is the one thing that is usually right.
			 */
			return "a token needs a device that does neighbour discovery -- not a "
			       "dummy or any other NOARP device -- which is up, accepts router "
			       "advertisements, and sends router solicitations; forwarding turns "
			       "RA acceptance off, so a router interface cannot have one";
		}
		return NULL;
	case NCFG_OP_LINK_SET_OFFLOADS:
		if (code == EINVAL || code == EOPNOTSUPP) {
			return "a driver that does not know a feature refuses the whole request, "
			       "so nothing changed";
		}
		return NULL;
	case NCFG_OP_NAT_REPLACE:
		/*
		 * **ENOENT, measured, where this arm first hedged over two codes.**
		 * 0283 and 0287 both reasoned about `EOPNOTSUPP` from a construct a
		 * kernel does not support, and this arm was written keyed on
		 * `ENOENT` and `EOPNOTSUPP` together because the kernel that would
		 * say which could not be produced on a developer machine.
		 *
		 * It can be produced in a vm, which is what `tests/hull/natcap/`
		 * does: a guest boots with an empty module table and its own
		 * `/proc/sys/kernel/modprobe`, so blocking autoload makes a
		 * construct unreachable exactly as a kernel built without it would.
		 * Measured there 2026-10-24, kernel 6.12, three states and two
		 * controls:
		 *
		 *     no nft_chain_nat    NFT_MSG_NEWCHAIN refused, ENOENT
		 *     no nft_masq         NFT_MSG_NEWRULE refused, ENOENT
		 *     no nf_tables        the socket will not open, EPROTONOSUPPORT
		 *
		 * `EOPNOTSUPP` arrived in none of them, so it is gone from here: a
		 * second code nothing can produce is an untested arm wearing
		 * caution's clothes.
		 *
		 * **Confirmed on kernels built without the constructs**, 2026-10-24,
		 * `tests/kernel/` -- 6.12.113 with `CONFIG_MODULES` off entirely, so
		 * there is no loader to blame and "absent" means compiled out. Same
		 * `ENOENT`, same two messages, and a third kernel with both
		 * constructs built in applies NAT, which is what keeps the refusals
		 * from being a property of a small kernel. The third state never reaches this function --
		 * `kernel_nat.c` refuses at the socket and says `nf_tables` itself
		 * is missing -- which is why nothing here mentions it.
		 *
		 * **And the sentence stops claiming a cause the number cannot
		 * carry.** `kernel_nat.c`'s header notes that deleting a table
		 * which is not there is `ENOENT` too, and that delete is in this
		 * transaction whenever the dump saw the table -- so a table that
		 * vanished in the gap lands on the same errno as a missing module.
		 * Naming the refused message is what separates them, which nftables
		 * messages now have names for (`ncfg_nft_message_text`), and the
		 * hint points at it rather than asserting the likelier half.
		 */
		if (code == ENOENT) {
			/*
			 * **Both spellings, because they are not the same word and one
			 * of them does not exist.** The module is `nft_chain_nat` and
			 * the option that builds it is `CONFIG_NFT_NAT`: there is no
			 * `CONFIG_NFT_CHAIN_NAT`, as `net/netfilter/Makefile` shows --
			 * `obj-$(CONFIG_NFT_NAT) += nft_chain_nat.o`. An operator sent
			 * to their kernel config by a sentence naming only the module
			 * searches for a symbol that is not there, which is a thing
			 * that happened while the kernels for this measurement were
			 * being configured. The masquerade's two names agree, and are
			 * given anyway so the pair reads the same way.
			 */
			return "the refused message above says which step: a `nat` chain "
			       "type (module `nft_chain_nat`, CONFIG_NFT_NAT) or a "
			       "masquerade (module `nft_masq`, CONFIG_NFT_MASQ) this "
			       "kernel does not provide fails exactly here, and so does a "
			       "`netcfgd` table that went away between the dump and this "
			       "transaction";
		}
		return NULL;
	default:
		return NULL;
	}
}

/*
 * The one send, with the code kept.
 *
 * `ncfg_netlink_send_batch` rather than `ncfg_netlink_request`, for the reason
 * `kernel.c` gives: the builders produce the whole request -- header and all --
 * and the request call builds its own.
 */
static int send_keeping_code(ncfg_netlink_t *socket, const void *bytes, size_t length,
    uint32_t last_acked, int *code, char *detail, size_t detail_size)
{
	ncfg_netlink_reply_t reply;
	int                  sent;

	*code = 0;
	detail[0] = '\0';
	memset(&reply, 0, sizeof(reply));
	sent = ncfg_netlink_send_batch(socket, bytes, length, last_acked, &reply, detail,
	    detail_size);
	*code = reply.refused;
	ncfg_netlink_reply_free(&reply);
	return sent;
}

/* The whole of the reporting send, once the bytes are in hand. */
static int reporting_bytes(ncfg_netlink_t *socket, const void *bytes, size_t length,
    uint32_t last_acked, int *code, const char *doing, char *err, size_t err_size)
{
	char detail[NCFG_ERROR_MAX];

	*code = 0;
	if (!socket || !bytes || length == 0) {
		ncfg_error_set(err, err_size, "there is no message to %s with",
		    doing ? doing : "act");
		return 0;
	}
	if (send_keeping_code(socket, bytes, length, last_acked, code, detail, sizeof(detail))) {
		return 1;
	}
	/* The builder's own sentence says which field; this one says which action,
	 * because a journal entry reading only "Invalid argument" is an operator's
	 * dead end. */
	ncfg_error_set(err, err_size, "could not %s: %s", doing ? doing : "act", detail);
	return 0;
}

int ncfg_kernel_send_reporting(ncfg_netlink_t *socket, const ncfg_buf_t *message,
    uint32_t last_acked, int *code, const char *doing, char *err, size_t err_size)
{
	int ignored = 0;

	if (!code) {
		code = &ignored;
	}
	*code = 0;
	if (!message || ncfg_buf_failed(message)) {
		/* `buf.h`'s sticky failure: a buffer that failed hands out the empty
		 * string rather than the part that fitted, and half a netlink message
		 * that looks whole is the one thing this must not send. */
		ncfg_error_set(err, err_size, "could not build the message to %s",
		    doing ? doing : "act");
		return 0;
	}
	return reporting_bytes(socket, message->data, message->length, last_acked, code, doing,
	    err, err_size);
}

/* What both sends do with a code once the send has failed. */
static int forgive_or_explain(int op_kind, int code, char *err, size_t err_size)
{
	const char *hint;
	char        detail[NCFG_ERROR_MAX];

	if (code != 0 && ncfg_kernel_tolerates(op_kind, code)) {
		/* Already so. The sentence goes with it: an operator reading the
		 * journal wants to know what ran, and "it was already like that" is
		 * not a failure to report. */
		if (err && err_size) {
			err[0] = '\0';
		}
		return 1;
	}
	hint = ncfg_kernel_hint(op_kind, code);
	if (hint && err && err_size) {
		/* Copied out first: `err` is both the source and the destination, and
		 * `snprintf` into a buffer it is reading is undefined. */
		(void)snprintf(detail, sizeof(detail), "%s", err);
		ncfg_error_set(err, err_size, "%s; %s", detail, hint);
	}
	return 0;
}

int ncfg_kernel_send(ncfg_netlink_t *socket, const ncfg_buf_t *message, uint32_t last_acked,
    int op_kind, const char *doing, char *err, size_t err_size)
{
	int code = 0;

	if (ncfg_kernel_send_reporting(socket, message, last_acked, &code, doing, err, err_size)) {
		return 1;
	}
	return forgive_or_explain(op_kind, code, err, err_size);
}

int ncfg_kernel_send_bytes(ncfg_netlink_t *socket, const void *bytes, size_t length,
    uint32_t last_acked, int op_kind, const char *doing, char *err, size_t err_size)
{
	int code = 0;

	if (reporting_bytes(socket, bytes, length, last_acked, &code, doing, err, err_size)) {
		return 1;
	}
	return forgive_or_explain(op_kind, code, err, err_size);
}
