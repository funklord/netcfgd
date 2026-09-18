/*
 * kernel_internal.h -- the kernel-side ops, as messages rather than as sends.
 *
 * WHY THIS HEADER EXISTS AT ALL
 *   `apply.h` publishes a seam and an executor and deliberately publishes
 *   nothing about how an op becomes bytes. That is right for callers and wrong
 *   for the tests this module owes, because the whole of what these ops get
 *   wrong is *what goes on the wire* -- a mode number that means something else
 *   on the way back in, a rate in bits where the kernel wants bytes, a nest
 *   without `NLA_F_NESTED`. So every op below is split in two: a **builder**,
 *   which is a pure function of an op and a document and is what `apply_
 *   kernel_test.c` drives, and a two-line send in `kernel.c`'s dispatch.
 *
 *   The property that buys: **not one check in this module sends a byte.**
 *   These ops attach shapers to somebody's uplink, replace an nftables table
 *   and load private keys into a kernel; a suite that had to reach a kernel to
 *   test them is a suite nobody can run on the machine they are developing on,
 *   which is the machine netcfgd would reconfigure.
 *
 * WHAT A BUILDER MAY NOT DO
 *   Resolve a name to an index. `if_nametoindex` is a syscall and a parent
 *   interface may have been created earlier in the same plan, so the lookup is
 *   `ncfg_kernel_index_fn` -- the executor passes the real one, a test passes a
 *   table. That is `netlink.h`'s `ncfg_netlink_recv_t` one layer up and for the
 *   same reason: the seam is where the machine would otherwise be.
 *
 * IDEMPOTENCE IS AN ERRNO, FOR FIVE OF THESE OPS
 *   `plan.h` says applying a plan twice must produce an empty second plan, and
 *   the executor's half of that is that the *same op sent twice* succeeds
 *   twice. Most of these are idempotent by construction -- an attribute set is
 *   a set, `NLM_F_REPLACE` replaces, a table is replaced whole. Five are not,
 *   and the kernel says so with an errno rather than with a sentence:
 *   `EEXIST` for a rule already installed, `ENOENT` for a rule, a qdisc or an
 *   ingress hook already gone. `ncfg_kernel_tolerates` is the single list of
 *   which code means "already so" for which op, and `kernel_send.c` is what
 *   asks it -- so the rule is a value a test can enumerate rather than a
 *   scattering of `if (code == ...)`.
 *
 * AND AN INVERSE IS DECLARED RATHER THAN ASSUMED
 *   `apply.h`'s revert replays the inverse of every action that ran, and an op
 *   with none contributes nothing. The *planner* attaches the inverse; what
 *   this module owes is that the inverse of an op it executes is an op it can
 *   also execute -- otherwise a revert would refuse exactly when it is needed.
 *   `ncfg_kernel_inverse_kind` is that list and the test walks it.
 */
#ifndef NCFG_APPLY_KERNEL_INTERNAL_H
#define NCFG_APPLY_KERNEL_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#include "ncfg/buf.h"
#include "ncfg/document.h"
#include "ncfg/ethtool.h"
#include "ncfg/genl.h"
#include "ncfg/netlink.h"
#include "ncfg/nft.h"
#include "ncfg/ops.h"
#include "ncfg/plan.h"
#include "ncfg/qdisc.h"
#include "ncfg/secrets.h"
#include "ncfg/wg.h"

/* ------------------------------------------------------------------------ *
 * The seams
 * ------------------------------------------------------------------------ */

/*
 * A kernel index for a name, or 0 with a sentence.
 *
 * 0 doubles as the failure because it is not a valid index, which is
 * `kernel.c`'s `index_of` arrangement and is kept rather than re-decided.
 */
typedef uint32_t (*ncfg_kernel_index_fn)(void *context, const char *name, char *err,
    size_t err_size);

/* ------------------------------------------------------------------------ *
 * What the document says about a device
 * ------------------------------------------------------------------------ */

/*
 * The kind block of the device this op names, or NULL with a sentence.
 *
 * Six ops carry a name and nothing else -- `link.set_bridge`, `link.set_bond`,
 * `link.set_macvlan`, `link.set_tunnel`, `link.set_vxlan` and the device half
 * of `wg.set_device` -- because what they change is the document's, and a plan
 * that carried it would put a WireGuard private key reference, every peer's
 * public key and every allowed prefix into `/run/netcfgd/plan.last.json` for
 * nothing. So the executor is handed the document it is applying and looks
 * them up, which is the Rust's arrangement and its reason.
 *
 * `want` is the kind the op expects. A device whose block is a different kind
 * is refused by name rather than configured as whatever it is: a `link.set_
 * vxlan` against a document that has since made that device a bridge is a plan
 * built from another document, and sending the bridge's nest under a VXLAN op
 * is how an apply changes something nobody asked about.
 */
const ncfg_interface_kind_t *ncfg_kernel_kind_of(const ncfg_document_t *document,
    const char *name, int want, char *err, size_t err_size);

/* ------------------------------------------------------------------------ *
 * Links: the kind blocks, and the one attribute that is not one
 * ------------------------------------------------------------------------ */

/*
 * The model's kind block as the wire layer wants it.
 *
 * **The one conversion**, and it used to be `kernel.c`'s private `newlink_of`,
 * serving `link.create` alone. It is here because the five `link.set_*` ops
 * need the identical nest -- decision 0057's property, stated there about a
 * bridge and true of every kind: two encoders for one kind is how the create
 * path and the correct-an-existing path come to disagree about what a setting
 * is. A bond and a VLAN are refused by name, each for a reason the arm gives.
 */
int ncfg_kernel_newlink_of(const ncfg_interface_kind_t *kind, const char *name,
    ncfg_kernel_index_fn resolve, void *context, ncfg_ops_newlink_t *out, char *err,
    size_t err_size);

/*
 * A bridge's own settings, re-sent to a bridge that already exists.
 *
 * Through `ncfg_ops_set_bridge_attrs`, which is the encoder `link.create`
 * would use -- decision 0057's property, and the reason a bridge takes no
 * settings at creation: one path rather than two.
 */
int ncfg_kernel_build_bridge(ncfg_buf_t *out, uint32_t seq, uint32_t index,
    const ncfg_interface_kind_t *kind, char *err, size_t err_size);

/*
 * A bond's mode and monitoring interval.
 *
 * `with_mode` is the op's own field and is the planner's answer to a question
 * only it can answer: the kernel takes a mode **only on a bond with no
 * members** and rejects the whole message otherwise, so a request carrying a
 * mode it will not take also fails to set the monitoring interval beside it.
 */
int ncfg_kernel_build_bond(ncfg_buf_t *out, uint32_t seq, uint32_t index, const char *name,
    const ncfg_interface_kind_t *kind, int with_mode, char *err, size_t err_size);

/*
 * The kind nest of a macvlan, a tunnel or a VXLAN, re-sent whole.
 *
 * **Whole, not the field that moved**, which `ops.h` measured: a request
 * carrying only `IFLA_GRE_REMOTE` leaves a GRE tunnel with no local address,
 * no TTL and no key, because `ipgre_netlink_parms` starts from a zeroed
 * struct. One arm for three kinds, because what each needs is the nest its own
 * creation would build.
 */
int ncfg_kernel_build_kind(ncfg_buf_t *out, uint32_t seq, uint32_t index, const char *name,
    const ncfg_interface_kind_t *kind, ncfg_kernel_index_fn resolve, void *context, char *err,
    size_t err_size);

/* The IPv6 interface identifier, or `::` to clear it. The op carries the text
 * and this is where it becomes an address. */
int ncfg_kernel_build_token(ncfg_buf_t *out, uint32_t seq, uint32_t index, const char *name,
    const char *token, char *err, size_t err_size);

/* One VLAN on a bridge port, or on the bridge itself. `adding` picks the
 * direction; everything else is on the op. */
int ncfg_kernel_build_bridge_vlan(ncfg_buf_t *out, uint32_t seq, uint32_t index,
    const ncfg_op_t *op, int adding, char *err, size_t err_size);

/* ------------------------------------------------------------------------ *
 * Policy routing rules
 * ------------------------------------------------------------------------ */

/*
 * A model rule as the wire wants it.
 *
 * **The spec borrows the rule**: `iif` and `oif` point into it, which is
 * `ncfg_ops_rule_t`'s documented arrangement and is why nothing here copies.
 * The `FRA_PROTOCOL` tag is left absent, which `ops.h` reads as netcfgd's own
 * 110 -- applied by the builder rather than carried in the model, for decision
 * 0002's reason about routes: ownership is netcfgd's bookkeeping and not
 * something an operator can forge by copying a configuration file.
 */
int ncfg_kernel_rule_spec(const ncfg_routing_rule_t *rule, ncfg_ops_rule_t *out, char *err,
    size_t err_size);

/* Install or remove one rule. */
int ncfg_kernel_build_rule(ncfg_buf_t *out, uint32_t seq, const ncfg_op_t *op, int adding,
    char *err, size_t err_size);

/* ------------------------------------------------------------------------ *
 * Traffic control
 * ------------------------------------------------------------------------ */

/* The root qdisc the op asks for. `ncfg_qdisc_build_set_root`'s `EINVAL` dance
 * is the sender's, and `kernel_tc.c` says why it cannot be the builder's. */
int ncfg_kernel_build_qdisc(ncfg_buf_t *out, uint32_t seq, uint32_t index,
    const ncfg_op_t *op, char *err, size_t err_size);

/*
 * The two messages an ingress redirect is.
 *
 * The hook first and the filter second, in `first` and `second`, at `seq` and
 * `seq + 1`: the kernel has nowhere to put a classifier until the ingress
 * qdisc exists, and the error for that is a bare `EINVAL`. Built together
 * rather than sent by two arms, so that the order is a property of the module
 * instead of a habit of its caller.
 */
int ncfg_kernel_build_redirect(ncfg_buf_t *first, ncfg_buf_t *second, uint32_t seq,
    uint32_t index, uint32_t target, char *err, size_t err_size);

/* ------------------------------------------------------------------------ *
 * WireGuard and the offloads, both of which are generic netlink
 * ------------------------------------------------------------------------ */

/*
 * The `SET_DEVICE` messages for a `wg.set_device` or a `wg.set_peers`.
 *
 * Which half is meant comes from the op's kind, and the two are deliberately
 * different requests rather than one with a flag: `wg.set_device` sends the
 * private key, the listen port and the firewall mark and **no peer list at
 * all**, so it cannot quietly replace peers; `wg.set_peers` sends the list
 * with `WGDEVICE_F_REPLACE_PEERS` and nothing about the device, so the kernel
 * leaves the port alone. Decision 0054 is the whole reason the two ops exist.
 *
 * `document` is needed only by the device half, and only for one thing: the op
 * carries the private key's *name* and the document carries which provider it
 * lives in. A document whose reference has a different name is refused rather
 * than resolved, because that is a plan built from another document and the
 * key it would load is not the key that was planned.
 *
 * `resolver` may be NULL, which means the machine's own secrets directory.
 * `out` is filled in on success and the caller frees it with
 * `ncfg_wg_messages_free`, which scrubs the bytes -- they carry a private key.
 */
int ncfg_kernel_wg_build(ncfg_wg_messages_t *out, const ncfg_genl_family_t *family,
    uint32_t seq, const ncfg_op_t *op, const ncfg_document_t *document,
    const ncfg_secret_resolver_t *resolver, char *err, size_t err_size);

/*
 * A peer endpoint as the kernel wants it.
 *
 * A literal goes through `ncfg_wg_endpoint_parse` and touches nothing; a name
 * is a DNS lookup, and it happens **here rather than at compile time** because
 * a hostname endpoint is the ordinary shape for a roaming peer and resolving
 * it when the configuration was read would pin whatever the answer was then.
 * That is the one call in this module that reaches the network.
 */
int ncfg_kernel_endpoint(const char *text, ncfg_wire_ip_t *address, uint16_t *port, char *err,
    size_t err_size);

/* The `FEATURES_SET` for a `link.set_offloads`. Every feature the op names is
 * sent, on ones flagged and off ones not -- `ethtool.h`'s mask bitset, where
 * absent *is* the spelling of off. */
int ncfg_kernel_build_offloads(ncfg_buf_t *out, const ncfg_genl_family_t *family, uint32_t seq,
    const ncfg_op_t *op, char *err, size_t err_size);

/* ------------------------------------------------------------------------ *
 * NAT
 * ------------------------------------------------------------------------ */

/*
 * The transaction that replaces netcfgd's table.
 *
 * `table_exists` comes from a table dump the caller has already read, for
 * `nft.h`'s reason: deleting a table that is not there is `ENOENT`, and one
 * failure aborts the whole transaction -- so the error would not be "no table"
 * but "no NAT".
 *
 * A batch that comes back `empty` must not be sent: it would be a begin and an
 * end with no contents, which asks for no acknowledgement and leaves a reply
 * loop waiting for a message the kernel was never going to send.
 */
int ncfg_kernel_build_nat(ncfg_buf_t *out, uint32_t first_seq, int table_exists,
    const ncfg_op_t *op, ncfg_nft_batch_t *batch, char *err, size_t err_size);

/* Whether one table dump payload is netcfgd's own table, for `table_exists`. */
int ncfg_kernel_nat_table_seen(const ncfg_netlink_reply_t *reply);

/* ------------------------------------------------------------------------ *
 * Sending, with the two facts a sentence cannot carry
 * ------------------------------------------------------------------------ */

/*
 * Whether this errno means the op this build sent has already happened.
 *
 * The single list, so that "which op forgives which code" is a value a test
 * can enumerate rather than a scattering of comparisons. Everything not named
 * here is a failure and stays one -- `EPERM` on a rule is not idempotence, it
 * is a daemon that has lost `CAP_NET_ADMIN`.
 */
int ncfg_kernel_tolerates(int op_kind, int code);

/*
 * The clause that says what this errno means *for this op*, or NULL.
 *
 * The kernel answers `EINVAL` for an attribute it does not know, a nest that
 * arrived unflagged and a value out of range, and `EOPNOTSUPP` for a bridge
 * with no VLAN filtering; `netlink.h` already turns the code into a general
 * sentence, and this is the part only the op knows. A value rather than a
 * `format!` at each arm, because the Rust put the `EOPNOTSUPP` reading on the
 * bridge VLAN *add* and not on the *delete* -- and the delete is the half that
 * runs first, clearing the kernel's default VLAN 1, so the bare errno was the
 * message an operator actually met.
 */
const char *ncfg_kernel_hint(int op_kind, int code);

/*
 * The op that undoes this one, or `NCFG_OP_NONE_INVERSE` where it has none.
 *
 * Declared here and not discovered at the call site: `apply.h`'s revert
 * replays what the *plan* declared, and this is the executor's side of the
 * same statement -- an op this build carries out whose inverse it could not
 * carry out is a change that cannot be taken back, which is worse than one
 * that was refused.
 */
#define NCFG_OP_NONE_INVERSE (-1)
int ncfg_kernel_inverse_kind(int op_kind);

/* Send one built message, wait for its acknowledgement, and forgive the codes
 * `ncfg_kernel_tolerates` names for this op. */
int ncfg_kernel_send(ncfg_netlink_t *socket, const ncfg_buf_t *message, uint32_t last_acked,
    int op_kind, const char *doing, char *err, size_t err_size);

/*
 * The same, for bytes that are not in a buffer.
 *
 * One caller: the WireGuard split, whose messages are `ncfg_wg_message_t` and
 * are owned -- and scrubbed -- by `ncfg_wg_messages_free`. Copying each into a
 * `ncfg_buf_t` to send it would put a private key in a second allocation that
 * nothing wipes, and assembling a `ncfg_buf_t` around the bytes by hand would
 * be a struct this module fills in that its owner may later free.
 */
int ncfg_kernel_send_bytes(ncfg_netlink_t *socket, const void *bytes, size_t length,
    uint32_t last_acked, int op_kind, const char *doing, char *err, size_t err_size);

/*
 * The same, reporting the errno instead of forgiving it.
 *
 * One caller: `qdisc.set`, which `qdisc.h` requires to answer `EINVAL` by
 * deleting the root and **building the same request again** at a fresh
 * sequence number. That is a decision about a code rather than a tolerance of
 * one, so it is asked for explicitly instead of being folded into the list.
 */
int ncfg_kernel_send_reporting(ncfg_netlink_t *socket, const ncfg_buf_t *message,
    uint32_t last_acked, int *code, const char *doing, char *err, size_t err_size);

/* ------------------------------------------------------------------------ *
 * The arms `kernel.c` dispatches to
 * ------------------------------------------------------------------------ */

/*
 * What an op of this module's needs to reach the machine.
 *
 * A struct rather than five arguments, because three of the five are the same
 * three for every arm and a sixth would otherwise be a change to eighteen call
 * sites. The two generic netlink families and the netfilter socket are **not**
 * here: each is opened by the arm that needs it and closed again, for the
 * reason `kernel_genl.c` gives.
 */
typedef struct {
	/* The executor's own rtnetlink socket. */
	ncfg_netlink_t              *socket;
	/* The document being applied, borrowed. NULL where the caller set none,
	 * which the six ops that need one refuse by name. */
	const ncfg_document_t       *document;
	/* Where `file` secrets live. NULL means the machine's own directory. */
	const ncfg_secret_resolver_t *secrets;
	ncfg_kernel_index_fn         resolve;
	void                        *context;
} ncfg_kernel_world_t;

int ncfg_kernel_link_kind_op(const ncfg_kernel_world_t *world, const ncfg_op_t *op, char *err,
    size_t err_size);
int ncfg_kernel_bridge_vlan_op(const ncfg_kernel_world_t *world, const ncfg_op_t *op,
    int adding, char *err, size_t err_size);
int ncfg_kernel_token_op(const ncfg_kernel_world_t *world, const ncfg_op_t *op, char *err,
    size_t err_size);
int ncfg_kernel_rule_op(const ncfg_kernel_world_t *world, const ncfg_op_t *op, int adding,
    char *err, size_t err_size);
int ncfg_kernel_qdisc_op(const ncfg_kernel_world_t *world, const ncfg_op_t *op, char *err,
    size_t err_size);
int ncfg_kernel_ingress_op(const ncfg_kernel_world_t *world, const ncfg_op_t *op,
    int redirecting, char *err, size_t err_size);
int ncfg_kernel_wg_op(const ncfg_kernel_world_t *world, const ncfg_op_t *op, char *err,
    size_t err_size);
int ncfg_kernel_offloads_op(const ncfg_kernel_world_t *world, const ncfg_op_t *op, char *err,
    size_t err_size);
int ncfg_kernel_nat_op(const ncfg_kernel_world_t *world, const ncfg_op_t *op, char *err,
    size_t err_size);

#endif /* NCFG_APPLY_KERNEL_INTERNAL_H */
