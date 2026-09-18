/*
 * apply_kernel_test.c -- the executor's kernel-side ops, against bytes rather
 * than against a kernel.
 *
 * WHY EVERY CHECK HERE IS A BUILDER AND NOT A SEND
 *   These eighteen ops are the ones that change a machine: they attach shapers
 *   to an uplink, install policy routing rules, replace an nftables table and
 *   load private keys into a running kernel. **Not one line below opens a
 *   socket or sends a byte.** Each op is split into a builder -- a pure
 *   function of an op, a document and a name-to-index seam -- and a two-line
 *   send in `kernel.c`'s dispatch, and it is the builder that is checked.
 *
 *   That is `wire_test.c`'s and `netlink_test.c`'s standard and it is not a
 *   convenience here: the machine this suite is built on is somebody's
 *   workstation, and a test that proved `qdisc.set` by installing a shaper
 *   would prove it on their uplink.
 *
 * WHAT IS ASSERTED, AND HOW
 *   Every claim about a built message is made by **walking the bytes back with
 *   the wire layer**, never by comparing against a blob written out by hand: a
 *   hand-written blob is a second encoder with no tests of its own, and the
 *   first time the two disagree it is the test that is believed.
 *
 * THE THINGS MOST WORTH BREAKING
 *   * a mode number, which the model owns and which means something else if
 *     this module keeps a table of its own;
 *   * the units, because `TCA_CAKE_BASE_RATE64` is bytes and everything an
 *     operator writes is bits;
 *   * which errno means "already so" for which op, because forgiving one too
 *     widely turns a refused change into a reported success;
 *   * the two WireGuard halves, because a `wg.set_device` that carried the
 *     replace flag would clear a device's peers on every port change.
 */
#include "ncfg/apply.h"
#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/document.h"
#include "ncfg/ethtool.h"
#include "ncfg/genl.h"
#include "ncfg/netlink.h"
#include "ncfg/nft.h"
#include "ncfg/observe.h"
#include "ncfg/observed.h"
#include "ncfg/ops.h"
#include "ncfg/plan.h"
#include "ncfg/qdisc.h"
#include "ncfg/rule.h"
#include "ncfg/secrets.h"
#include "ncfg/value.h"
#include "ncfg/wg.h"
#include "ncfg/wire.h"

#include "../src/apply/kernel_internal.h"
#include "tempdir.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <linux/if_bridge.h>
#include <linux/if_link.h>
#include <linux/if_tunnel.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/pkt_sched.h>
#include <linux/rtnetlink.h>

static int failures;

static void check(int condition, const char *what)
{
	printf("%-72s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

/* ------------------------------------------------------------------------ *
 * Reading a built message back
 * ------------------------------------------------------------------------ */

/* The nth message of a built buffer. Messages are walked rather than indexed
 * by offset, because an offset computed here is a second encoder. */
static int message_at(const ncfg_buf_t *buf, size_t index, ncfg_wire_message_t *out)
{
	ncfg_wire_messages_t walk;
	size_t               at;

	ncfg_wire_messages_start(&walk, buf->data, buf->length);
	for (at = 0; at <= index; at++) {
		if (ncfg_wire_messages_next(&walk, out, NULL, 0) != NCFG_WIRE_OK) {
			return 0;
		}
	}
	return 1;
}

static int first_message(const ncfg_buf_t *buf, ncfg_wire_message_t *out)
{
	return message_at(buf, 0, out);
}

static int attrs_after(const ncfg_wire_message_t *message, size_t body, ncfg_wire_attrs_t *out)
{
	return ncfg_wire_message_attrs(message, body, out, NULL, 0);
}

static int find(const ncfg_wire_attrs_t *area, uint16_t kind, ncfg_wire_attr_t *out)
{
	return ncfg_wire_attrs_find(area, kind, out, NULL, 0) == NCFG_WIRE_OK;
}

static void nested(const ncfg_wire_attr_t *attr, ncfg_wire_attrs_t *out)
{
	ncfg_wire_attrs_start(out, attr->value, attr->length);
}

/* An attribute's value as a number of a given width, or 0 with `*found` clear.
 * Each width is a separate call because netlink is not consistent about them
 * and reading one with the wrong accessor returns a number that is merely
 * wrong. */
static uint32_t u32_of(const ncfg_wire_attrs_t *area, uint16_t kind, int *found)
{
	ncfg_wire_attr_t attr;
	uint32_t         value = 0;

	*found = find(area, kind, &attr) && ncfg_wire_attr_u32(&attr, &value, NULL, 0);
	return *found ? value : 0;
}

static uint16_t u16_of(const ncfg_wire_attrs_t *area, uint16_t kind, int *found)
{
	ncfg_wire_attr_t attr;
	uint16_t         value = 0;

	*found = find(area, kind, &attr) && ncfg_wire_attr_u16(&attr, &value, NULL, 0);
	return *found ? value : 0;
}

static uint8_t u8_of(const ncfg_wire_attrs_t *area, uint16_t kind, int *found)
{
	ncfg_wire_attr_t attr;
	uint8_t          value = 0;

	*found = find(area, kind, &attr) && ncfg_wire_attr_u8(&attr, &value, NULL, 0);
	return *found ? value : 0;
}

static uint64_t u64_of(const ncfg_wire_attrs_t *area, uint16_t kind, int *found)
{
	ncfg_wire_attr_t attr;
	uint64_t         value = 0;

	*found = 0;
	if (find(area, kind, &attr) && attr.length == sizeof(value)) {
		memcpy(&value, attr.value, sizeof(value));
		*found = 1;
	}
	return value;
}

static const char *text_of(const ncfg_wire_attrs_t *area, uint16_t kind, char *out,
    size_t out_size)
{
	ncfg_wire_attr_t attr;

	out[0] = '\0';
	if (find(area, kind, &attr)) {
		(void)ncfg_wire_attr_string(&attr, out, out_size, NULL, 0);
	}
	return out;
}

/*
 * The `IFLA_INFO_DATA` nest of a link message, and the kind word beside it.
 *
 * Both come out of one walk because they are one question: a nest read without
 * checking the word beside it is a nest read with somebody else's attribute
 * numbering -- which is exactly how `netlink.h` says a tunnel comes to report
 * another kind's field.
 */
static int kind_nest(const ncfg_buf_t *buf, char *word, size_t word_size,
    ncfg_wire_attrs_t *data)
{
	ncfg_wire_message_t message;
	ncfg_wire_attrs_t   attrs;
	ncfg_wire_attrs_t   info;
	ncfg_wire_attr_t    attr;

	word[0] = '\0';
	if (!first_message(buf, &message) ||
	    !attrs_after(&message, NCFG_WIRE_IFINFO_LEN, &attrs) ||
	    !find(&attrs, IFLA_LINKINFO, &attr)) {
		return 0;
	}
	nested(&attr, &info);
	(void)text_of(&info, IFLA_INFO_KIND, word, word_size);
	if (!find(&info, IFLA_INFO_DATA, &attr)) {
		return 0;
	}
	nested(&attr, data);
	return 1;
}

/* ------------------------------------------------------------------------ *
 * The index seam
 * ------------------------------------------------------------------------ */

/*
 * A table of names, in place of `if_nametoindex`.
 *
 * This is what makes every check below runnable with no interfaces: the real
 * resolver is a syscall against the machine the suite is built on, and a test
 * that used it would assert about whatever that machine happens to be running.
 */
typedef struct {
	const char *name;
	uint32_t    index;
} known_t;

static const known_t known[] = {
	{ "br0", 11u }, { "bond0", 12u }, { "eth0", 13u }, { "eth1", 14u },
	{ "gre0", 15u }, { "vx0", 16u }, { "wg0", 17u }, { "ifb0", 18u },
	{ "mv0", 19u }
};

static uint32_t resolve(void *context, const char *name, char *err, size_t err_size)
{
	size_t i;

	(void)context;
	if (!name) {
		ncfg_error_set(err, err_size, "an action names no interface to act on");
		return 0;
	}
	for (i = 0; i < sizeof(known) / sizeof(known[0]); i++) {
		if (strcmp(known[i].name, name) == 0) {
			return known[i].index;
		}
	}
	ncfg_error_set(err, err_size, "%s is not an interface this kernel knows", name);
	return 0;
}

/* ------------------------------------------------------------------------ *
 * What this build says it can carry out, and what undoes what
 * ------------------------------------------------------------------------ */

/* The eighteen this module owns. Written out rather than derived from the
 * enum, so that an op moving out of this half makes a check go red. */
static const int mine[] = {
	NCFG_OP_LINK_SET_BOND, NCFG_OP_LINK_SET_BRIDGE, NCFG_OP_LINK_SET_MACVLAN,
	NCFG_OP_LINK_SET_TUNNEL, NCFG_OP_LINK_SET_VXLAN, NCFG_OP_LINK_SET_IPV6_TOKEN,
	NCFG_OP_LINK_SET_OFFLOADS, NCFG_OP_BRIDGE_VLAN_ADD, NCFG_OP_BRIDGE_VLAN_DEL,
	NCFG_OP_WG_SET_DEVICE, NCFG_OP_WG_SET_PEERS, NCFG_OP_RULE_ADD, NCFG_OP_RULE_DEL,
	NCFG_OP_QDISC_SET, NCFG_OP_QDISC_RESET, NCFG_OP_INGRESS_REDIRECT,
	NCFG_OP_INGRESS_REDIRECT_CLEAR, NCFG_OP_NAT_REPLACE
};

#define COUNT(array) (sizeof(array) / sizeof((array)[0]))

static void check_supported(void)
{
	size_t i;
	int    all = 1;
	int    inverses = 1;
	char   err[NCFG_ERROR_MAX];

	for (i = 0; i < COUNT(mine); i++) {
		ncfg_op_t op;

		memset(&op, 0, sizeof(op));
		op.kind = mine[i];
		err[0] = '\0';
		if (!ncfg_apply_supported(&op, err, sizeof(err))) {
			printf("    %s is refused: %s\n", ncfg_op_name(&op), err);
			all = 0;
		}
	}
	check(all, "every kernel-side op is one this build carries out");

	/*
	 * The half of the inverse statement this module owes: an op it carries out
	 * whose inverse it could *not* carry out is a change that cannot be taken
	 * back, and the moment that matters is a confirm window closing on a
	 * machine that has just been cut off.
	 */
	for (i = 0; i < COUNT(mine); i++) {
		int       back = ncfg_kernel_inverse_kind(mine[i]);
		ncfg_op_t op;

		if (back == NCFG_OP_NONE_INVERSE) {
			continue;
		}
		memset(&op, 0, sizeof(op));
		op.kind = back;
		if (!ncfg_apply_supported(&op, NULL, 0)) {
			printf("    the inverse of op %d is op %d, which is refused\n", mine[i],
			    back);
			inverses = 0;
		}
	}
	check(inverses, "every declared inverse is itself an op this build carries out");

	check(ncfg_kernel_inverse_kind(NCFG_OP_RULE_ADD) == NCFG_OP_RULE_DEL &&
	    ncfg_kernel_inverse_kind(NCFG_OP_RULE_DEL) == NCFG_OP_RULE_ADD,
	    "the two rule ops undo each other");
	check(ncfg_kernel_inverse_kind(NCFG_OP_BRIDGE_VLAN_ADD) == NCFG_OP_BRIDGE_VLAN_DEL &&
	    ncfg_kernel_inverse_kind(NCFG_OP_BRIDGE_VLAN_DEL) == NCFG_OP_BRIDGE_VLAN_ADD,
	    "the two bridge vlan ops undo each other");
	check(ncfg_kernel_inverse_kind(NCFG_OP_QDISC_SET) == NCFG_OP_QDISC_RESET,
	    "qdisc.reset undoes qdisc.set");
	/* And not the other way round: undoing a reset means putting back the
	 * scheduler and the rate that were there, which is a value the old
	 * document holds rather than an op kind. */
	check(ncfg_kernel_inverse_kind(NCFG_OP_QDISC_RESET) == NCFG_OP_NONE_INVERSE,
	    "qdisc.set is not claimed as the inverse of qdisc.reset");
	check(ncfg_kernel_inverse_kind(NCFG_OP_LINK_SET_BRIDGE) == NCFG_OP_NONE_INVERSE &&
	    ncfg_kernel_inverse_kind(NCFG_OP_LINK_SET_OFFLOADS) == NCFG_OP_NONE_INVERSE,
	    "a value replacement declares no inverse of its own kind");
}

static void check_tolerance(void)
{
	check(ncfg_kernel_tolerates(NCFG_OP_RULE_ADD, EEXIST),
	    "a rule already installed is a rule.add that has already happened");
	check(ncfg_kernel_tolerates(NCFG_OP_RULE_DEL, ENOENT),
	    "a rule already gone is a rule.del that has already happened");
	check(ncfg_kernel_tolerates(NCFG_OP_BRIDGE_VLAN_DEL, ENOENT),
	    "a vlan already off the port is a bridge_vlan.del that has happened");
	check(!ncfg_kernel_tolerates(NCFG_OP_BRIDGE_VLAN_ADD, EEXIST),
	    "bridge_vlan.add forgives nothing: the kernel updates a vlan it has");
	check(ncfg_kernel_tolerates(NCFG_OP_QDISC_RESET, ENOENT) &&
	    ncfg_kernel_tolerates(NCFG_OP_QDISC_RESET, EINVAL),
	    "both of qdisc.h's codes mean there was no root qdisc to remove");
	check(ncfg_kernel_tolerates(NCFG_OP_INGRESS_REDIRECT_CLEAR, ENOENT) &&
	    ncfg_kernel_tolerates(NCFG_OP_INGRESS_REDIRECT_CLEAR, EINVAL),
	    "both mean there was no ingress hook to remove");
	check(ncfg_kernel_tolerates(NCFG_OP_INGRESS_REDIRECT, EEXIST),
	    "an ingress hook that is already there is already correct");
	/* The refusals matter more than the tolerances. A module that forgave
	 * `EEXIST` everywhere would turn a `link.create` racing another daemon
	 * into a silent success. */
	check(!ncfg_kernel_tolerates(NCFG_OP_RULE_ADD, EPERM) &&
	    !ncfg_kernel_tolerates(NCFG_OP_RULE_DEL, EPERM),
	    "a rule refused for want of privilege is not idempotence");
	check(!ncfg_kernel_tolerates(NCFG_OP_LINK_CREATE, EEXIST) &&
	    !ncfg_kernel_tolerates(NCFG_OP_QDISC_SET, EINVAL),
	    "nothing outside the list is forgiven, EEXIST and EINVAL included");
}

static void check_hints(void)
{
	const char *add = ncfg_kernel_hint(NCFG_OP_BRIDGE_VLAN_ADD, EOPNOTSUPP);
	const char *del = ncfg_kernel_hint(NCFG_OP_BRIDGE_VLAN_DEL, EOPNOTSUPP);

	/*
	 * The Rust put this reading on the *add* and not on the *del*, and the
	 * del is the half that runs first -- clearing the VLAN 1 the kernel adds
	 * by itself when a port joins a filtering bridge -- so the bare errno was
	 * the message an operator actually met.
	 */
	check(add && del && strcmp(add, del) == 0,
	    "EOPNOTSUPP reads the same on a bridge vlan add and on a del");
	check(add && strstr(add, "vlan_filtering") != NULL,
	    "and it names the setting that is missing");
	check(ncfg_kernel_hint(NCFG_OP_QDISC_SET, ENOENT) != NULL,
	    "ENOENT on qdisc.set says the scheduler's module could not be loaded");
	check(ncfg_kernel_hint(NCFG_OP_INGRESS_REDIRECT, ENOENT) != NULL,
	    "ENOENT on a redirect names cls_matchall and act_mirred");
	check(ncfg_kernel_hint(NCFG_OP_LINK_SET_IPV6_TOKEN, EINVAL) != NULL,
	    "EINVAL on a token names the four preconditions behind it");
	check(ncfg_kernel_hint(NCFG_OP_LINK_SET_IPV6_TOKEN, EPERM) == NULL &&
	    ncfg_kernel_hint(NCFG_OP_RULE_ADD, EINVAL) == NULL,
	    "a code with nothing to add gets nothing added");
}

/* ------------------------------------------------------------------------ *
 * A document to read settings out of
 * ------------------------------------------------------------------------ */

/*
 * Devices built by hand rather than compiled from text.
 *
 * The compiler is another module's and its own tests cover it; what is under
 * test here is what the executor does with a kind block, so the block is
 * written directly. Nothing below is freed by `ncfg_document_free` -- these
 * are stack values in a stack document, which is why the document is never
 * handed to anything that frees.
 */
typedef struct {
	ncfg_document_t document;
	ncfg_device_t   devices[5];
	char            names[5][8];
} fixture_t;

static void fixture_build(fixture_t *fixture)
{
	memset(fixture, 0, sizeof(*fixture));
	(void)snprintf(fixture->names[0], sizeof(fixture->names[0]), "br0");
	fixture->devices[0].name = fixture->names[0];
	fixture->devices[0].kind.kind = NCFG_KIND_BRIDGE;
	fixture->devices[0].kind.bridge.stp = 1;
	fixture->devices[0].kind.bridge.forward_delay.has = 1;
	fixture->devices[0].kind.bridge.forward_delay.value = 4;
	fixture->devices[0].kind.bridge.priority.has = 1;
	fixture->devices[0].kind.bridge.priority.value = 4096;
	fixture->devices[0].kind.bridge.vlan_filtering = 1;

	(void)snprintf(fixture->names[1], sizeof(fixture->names[1]), "bond0");
	fixture->devices[1].name = fixture->names[1];
	fixture->devices[1].kind.kind = NCFG_KIND_BOND;
	/* `802.3ad`, which is index 4 and kernel mode 4. */
	fixture->devices[1].kind.bond.mode = 4;
	fixture->devices[1].kind.bond.miimon.has = 1;
	fixture->devices[1].kind.bond.miimon.value = 100;

	(void)snprintf(fixture->names[2], sizeof(fixture->names[2]), "gre0");
	fixture->devices[2].name = fixture->names[2];
	fixture->devices[2].kind.kind = NCFG_KIND_TUNNEL;
	fixture->devices[2].kind.tunnel.mode = NCFG_TUNNEL_KIND_GRE;
	fixture->devices[2].kind.tunnel.local = (char *)(uintptr_t)"10.0.0.1";
	fixture->devices[2].kind.tunnel.remote = (char *)(uintptr_t)"10.0.0.2";
	fixture->devices[2].kind.tunnel.ttl.has = 1;
	fixture->devices[2].kind.tunnel.ttl.value = 64;

	(void)snprintf(fixture->names[3], sizeof(fixture->names[3]), "vx0");
	fixture->devices[3].name = fixture->names[3];
	fixture->devices[3].kind.kind = NCFG_KIND_VXLAN;
	fixture->devices[3].kind.vxlan.id = 4711;
	fixture->devices[3].kind.vxlan.parent = (char *)(uintptr_t)"eth0";

	(void)snprintf(fixture->names[4], sizeof(fixture->names[4]), "mv0");
	fixture->devices[4].name = fixture->names[4];
	fixture->devices[4].kind.kind = NCFG_KIND_MACVLAN;
	fixture->devices[4].kind.macvlan.mode = NCFG_MACVLAN_MODE_BRIDGE;
	fixture->devices[4].kind.macvlan.parent = (char *)(uintptr_t)"eth1";

	fixture->document.devices = fixture->devices;
	fixture->document.device_count = COUNT(fixture->devices);
}

/* ------------------------------------------------------------------------ *
 * The link-kind blocks
 * ------------------------------------------------------------------------ */

static void check_bridge(const fixture_t *fixture)
{
	const ncfg_interface_kind_t *kind;
	ncfg_buf_t                   message;
	ncfg_wire_attrs_t            data;
	ncfg_wire_message_t          parsed;
	char                         word[32];
	char                         err[NCFG_ERROR_MAX];
	int                          found = 0;
	uint32_t                     delay;
	uint16_t                     priority;

	kind = ncfg_kernel_kind_of(&fixture->document, "br0", NCFG_KIND_BRIDGE, err, sizeof(err));
	check(kind != NULL, "the document's bridge block is found by name");

	ncfg_buf_init(&message, 0);
	check(ncfg_kernel_build_bridge(&message, 7u, 11u, kind, err, sizeof(err)),
	    "a bridge's settings build into a message");
	check(first_message(&message, &parsed) && parsed.header.kind == RTM_NEWLINK &&
	    (parsed.header.flags & NLM_F_ACK) != 0,
	    "and it is an acknowledged RTM_NEWLINK");
	check(kind_nest(&message, word, sizeof(word), &data) && strcmp(word, "bridge") == 0,
	    "carrying a `bridge` kind nest");
	delay = u32_of(&data, IFLA_BR_FORWARD_DELAY, &found);
	/*
	 * Four seconds, and the kernel counts hundredths. A reader that divided
	 * and a writer that multiplied is how one bridge comes to differ from
	 * itself by a factor of a hundred, so the number is asserted rather than
	 * the presence of the attribute.
	 */
	check(found && delay == 400u, "a forward delay of 4 seconds goes out as 400");
	priority = u16_of(&data, IFLA_BR_PRIORITY, &found);
	/* Two bytes, not four. `netlink.h` records what a 32-bit read of this
	 * cost: the priority read as absent on every kernel, always. */
	check(found && priority == 4096u, "the priority is two bytes wide");
	check(u8_of(&data, IFLA_BR_VLAN_FILTERING, &found) == 1u && found,
	    "and vlan filtering is on");
	ncfg_buf_free(&message);
}

static void check_bond(const fixture_t *fixture)
{
	const ncfg_interface_kind_t *kind;
	ncfg_buf_t                   message;
	ncfg_wire_attrs_t            data;
	char                         word[32];
	char                         err[NCFG_ERROR_MAX];
	int                          found = 0;

	kind = ncfg_kernel_kind_of(&fixture->document, "bond0", NCFG_KIND_BOND, err, sizeof(err));
	check(kind != NULL, "the document's bond block is found by name");

	ncfg_buf_init(&message, 0);
	check(ncfg_kernel_build_bond(&message, 7u, 12u, "bond0", kind, 1, err, sizeof(err)),
	    "a bond's mode and interval build into a message");
	check(kind_nest(&message, word, sizeof(word), &data) && strcmp(word, "bond") == 0,
	    "carrying a `bond` kind nest");
	/*
	 * `802.3ad` is the model's fifth mode and the kernel's mode 4. The number
	 * comes from `ncfg_bond_mode_number`, which is the model's -- a table in
	 * the executor is how a mode comes to mean one thing on the way out and
	 * another on the way back in, and `src/observe/` reads the same table.
	 */
	check(u8_of(&data, IFLA_BOND_MODE, &found) == 4u && found,
	    "802.3ad goes out as the kernel's mode 4");
	check(u32_of(&data, IFLA_BOND_MIIMON, &found) == 100u && found,
	    "beside the monitoring interval");
	ncfg_buf_free(&message);

	ncfg_buf_init(&message, 0);
	check(ncfg_kernel_build_bond(&message, 7u, 12u, "bond0", kind, 0, err, sizeof(err)),
	    "a bond whose mode the planner says is not meant still builds");
	check(kind_nest(&message, word, sizeof(word), &data), "with its kind nest");
	(void)u8_of(&data, IFLA_BOND_MODE, &found);
	/* The kernel takes a mode only on a bond with no members and rejects the
	 * whole message otherwise, taking the monitoring interval with it. */
	check(!found, "and no mode at all");
	check(u32_of(&data, IFLA_BOND_MIIMON, &found) == 100u && found,
	    "so the interval survives a bond that already has members");
	ncfg_buf_free(&message);
}

static void check_macvlan_and_tunnel(const fixture_t *fixture)
{
	const ncfg_interface_kind_t *kind;
	ncfg_buf_t                   message;
	ncfg_wire_attrs_t            data;
	ncfg_wire_attr_t             attr;
	ncfg_wire_ip_t               address;
	char                         word[32];
	char                         err[NCFG_ERROR_MAX];
	int                          found = 0;

	kind = ncfg_kernel_kind_of(&fixture->document, "mv0", NCFG_KIND_MACVLAN, err,
	    sizeof(err));
	ncfg_buf_init(&message, 0);
	check(kind && ncfg_kernel_build_kind(&message, 7u, 19u, "mv0", kind, resolve, NULL, err,
	    sizeof(err)), "a macvlan's nest builds");
	check(kind_nest(&message, word, sizeof(word), &data) && strcmp(word, "macvlan") == 0,
	    "carrying a `macvlan` kind nest");
	/*
	 * **Flags, not an enumeration.** The kernel numbers the modes 1, 2, 4, 8
	 * and 16, so `bridge` is 4 -- and its validator refuses anything else, so
	 * a 0 or a 3 would be `EINVAL` rather than a mode nobody meant.
	 */
	check(u32_of(&data, IFLA_MACVLAN_MODE, &found) == 4u && found,
	    "and the `bridge` mode as the flag bit 4");
	ncfg_buf_free(&message);

	kind = ncfg_kernel_kind_of(&fixture->document, "gre0", NCFG_KIND_TUNNEL, err,
	    sizeof(err));
	ncfg_buf_init(&message, 0);
	check(kind && ncfg_kernel_build_kind(&message, 7u, 15u, "gre0", kind, resolve, NULL, err,
	    sizeof(err)), "a tunnel's nest builds");
	/* The document's word for an encapsulation is the kernel's, deliberately;
	 * `ncfg_tunnel_kind_name` is the model's one table. */
	check(kind_nest(&message, word, sizeof(word), &data) && strcmp(word, "gre") == 0,
	    "with `gre` as the kind word the model spells");
	check(find(&data, IFLA_GRE_REMOTE, &attr) &&
	    ncfg_wire_attr_ip(&attr, &address, NULL, 0) && address.family == AF_INET &&
	    address.bytes[3] == 2u, "the remote endpoint inside the nest");
	check(find(&data, IFLA_GRE_LOCAL, &attr), "and the local one beside it");
	check(u8_of(&data, IFLA_GRE_TTL, &found) == 64u && found, "and the outer TTL");
	ncfg_buf_free(&message);
}

static void check_vxlan(const fixture_t *fixture)
{
	const ncfg_interface_kind_t *kind;
	ncfg_buf_t                   message;
	ncfg_wire_attrs_t            data;
	char                         word[32];
	char                         err[NCFG_ERROR_MAX];
	int                          found = 0;

	kind = ncfg_kernel_kind_of(&fixture->document, "vx0", NCFG_KIND_VXLAN, err, sizeof(err));
	ncfg_buf_init(&message, 0);
	check(kind && ncfg_kernel_build_kind(&message, 7u, 16u, "vx0", kind, resolve, NULL, err,
	    sizeof(err)), "a vxlan's nest builds");
	check(kind_nest(&message, word, sizeof(word), &data) && strcmp(word, "vxlan") == 0,
	    "carrying a `vxlan` kind nest");
	/*
	 * **And deliberately no VNI.** `ops.h` leaves it out of a *change*: the
	 * kernel refuses one that differs, so the only acceptable value is the one
	 * the device already has, and sending that says nothing. A VXLAN keeps
	 * what a change request leaves out, which is measured and is the opposite
	 * of what a GRE tunnel does with the same omission.
	 */
	(void)u32_of(&data, IFLA_VXLAN_ID, &found);
	check(!found, "with no VNI, which a change may not carry");
	/*
	 * **In the nest and not in the outer `IFLA_LINK`.** `ops.h` records what
	 * the other spelling cost: a VXLAN whose underlay went where the kernel
	 * does not read it, silently, for as long as VXLANs have existed.
	 */
	check(u32_of(&data, IFLA_VXLAN_LINK, &found) == 13u && found,
	    "and the underlay's index inside the nest");
	{
		ncfg_wire_message_t parsed;
		ncfg_wire_attrs_t   outer;
		ncfg_wire_attr_t    attr;

		/*
		 * And **not** in the outer `IFLA_LINK`, which is where it used to
		 * go: `vxlan_nl2conf` reads `data[IFLA_VXLAN_LINK]` and nothing
		 * reads `tb[IFLA_LINK]`, so the wrong spelling was accepted and did
		 * nothing for as long as VXLANs have existed. Asserted as an
		 * absence, because that is the half a present-attribute check cannot
		 * see.
		 */
		check(first_message(&message, &parsed) &&
		    attrs_after(&parsed, NCFG_WIRE_IFINFO_LEN, &outer) &&
		    !find(&outer, IFLA_LINK, &attr),
		    "and nothing in the outer IFLA_LINK, which the kernel does not read");
	}
	ncfg_buf_free(&message);
}

static void check_kind_refusals(const fixture_t *fixture)
{
	fixture_t  broken;
	ncfg_buf_t message;
	char       err[NCFG_ERROR_MAX];

	err[0] = '\0';
	check(!ncfg_kernel_kind_of(NULL, "br0", NCFG_KIND_BRIDGE, err, sizeof(err)) &&
	    strstr(err, "no document") != NULL,
	    "an executor with no document refuses, and says why");
	err[0] = '\0';
	check(!ncfg_kernel_kind_of(&fixture->document, "nosuch", NCFG_KIND_BRIDGE, err,
	    sizeof(err)) && strstr(err, "nosuch") != NULL,
	    "a device the document does not name is refused by name");
	err[0] = '\0';
	/* A plan built from another document: the device is there and is
	 * something else. Sending the block it *does* have would change something
	 * nobody asked about. */
	check(!ncfg_kernel_kind_of(&fixture->document, "br0", NCFG_KIND_VXLAN, err, sizeof(err)) &&
	    strstr(err, "different document") != NULL,
	    "a device of the wrong kind is refused rather than configured");

	fixture_build(&broken);
	broken.devices[4].kind.macvlan.parent = NULL;
	ncfg_buf_init(&message, 0);
	err[0] = '\0';
	check(!ncfg_kernel_build_kind(&message, 1u, 19u, "mv0", &broken.devices[4].kind, resolve,
	    NULL, err, sizeof(err)) && strstr(err, "parent") != NULL,
	    "a macvlan with no parent is refused rather than sent");
	ncfg_buf_free(&message);

	fixture_build(&broken);
	broken.devices[3].kind.vxlan.id = 0x1000000;
	ncfg_buf_init(&message, 0);
	err[0] = '\0';
	check(!ncfg_kernel_build_kind(&message, 1u, 16u, "vx0", &broken.devices[3].kind, resolve,
	    NULL, err, sizeof(err)) && strstr(err, "24 bits") != NULL,
	    "a VNI past 24 bits is refused rather than truncated");
	ncfg_buf_free(&message);

	fixture_build(&broken);
	broken.devices[3].kind.vxlan.parent = (char *)(uintptr_t)"nosuch";
	ncfg_buf_init(&message, 0);
	err[0] = '\0';
	check(!ncfg_kernel_build_kind(&message, 1u, 16u, "vx0", &broken.devices[3].kind, resolve,
	    NULL, err, sizeof(err)) && strstr(err, "nosuch") != NULL,
	    "an underlay the kernel does not have is refused by name");
	ncfg_buf_free(&message);

	{
		ncfg_interface_kind_t      vlan;
		ncfg_ops_newlink_t         link;

		/*
		 * The one conversion refuses a bond and a VLAN by name, each for its
		 * own reason -- a bond's settings are a message of their own because
		 * the kernel takes a mode only on a bond with no members, and a
		 * VLAN's ethertype is a model numbering `document.h` does not yet
		 * publish. Checked here because `link.create` reaches the same
		 * function, and a silent fall-through would be a link half made.
		 */
		memset(&vlan, 0, sizeof(vlan));
		vlan.kind = NCFG_KIND_VLAN;
		err[0] = '\0';
		check(!ncfg_kernel_newlink_of(&vlan, "v10", resolve, NULL, &link, err,
		    sizeof(err)) && strstr(err, "ethertype") != NULL,
		    "a vlan is refused by name rather than built without its ethertype");
		memset(&vlan, 0, sizeof(vlan));
		vlan.kind = NCFG_KIND_BOND;
		err[0] = '\0';
		check(!ncfg_kernel_newlink_of(&vlan, "bond0", resolve, NULL, &link, err,
		    sizeof(err)) && strstr(err, "no members") != NULL,
		    "and a bond is refused, its settings being a message of their own");
		memset(&vlan, 0, sizeof(vlan));
		vlan.kind = NCFG_KIND_PHYSICAL;
		err[0] = '\0';
		check(!ncfg_kernel_newlink_of(&vlan, "eth0", resolve, NULL, &link, err,
		    sizeof(err)), "and a physical device, which netcfgd configures and cannot make");
		err[0] = '\0';
		check(!ncfg_kernel_newlink_of(NULL, "eth0", resolve, NULL, &link, err,
		    sizeof(err)), "and a kind block that is not there at all");
	}

	fixture_build(&broken);
	broken.devices[1].kind.bond.mode = 99;
	ncfg_buf_init(&message, 0);
	err[0] = '\0';
	check(!ncfg_kernel_build_bond(&message, 1u, 12u, "bond0", &broken.devices[1].kind, 1, err,
	    sizeof(err)) && strstr(err, "bonding mode") != NULL,
	    "a bonding mode outside the model's set is refused, not cast");
	ncfg_buf_free(&message);
}

/* ------------------------------------------------------------------------ *
 * The IPv6 token, and the bridge VLANs
 * ------------------------------------------------------------------------ */

static void check_token(void)
{
	ncfg_buf_t          message;
	ncfg_wire_message_t parsed;
	char                err[NCFG_ERROR_MAX];

	ncfg_buf_init(&message, 0);
	check(ncfg_kernel_build_token(&message, 3u, 13u, "eth0", "::5", err, sizeof(err)),
	    "an interface identifier builds into a message");
	check(first_message(&message, &parsed) && parsed.header.kind == RTM_SETLINK,
	    "and it is an RTM_SETLINK");
	ncfg_buf_free(&message);

	ncfg_buf_init(&message, 0);
	err[0] = '\0';
	check(!ncfg_kernel_build_token(&message, 3u, 13u, "eth0", NULL, err, sizeof(err)),
	    "a token action with no token is refused");
	ncfg_buf_free(&message);

	ncfg_buf_init(&message, 0);
	err[0] = '\0';
	/* Refused by `ncfg_ops_set_ipv6_token`, which is where the rule lives:
	 * four bytes in `IFLA_INET6_TOKEN` is the same bare `EINVAL` every other
	 * refusal of a token gives, and the operator would be told their device is
	 * not ready when what happened is that somebody wrote an IPv4 address. */
	check(!ncfg_kernel_build_token(&message, 3u, 13u, "eth0", "10.0.0.5", err, sizeof(err)),
	    "an IPv4 address is not an interface identifier");
	ncfg_buf_free(&message);
}

static void check_bridge_vlan(void)
{
	ncfg_op_t           op;
	ncfg_buf_t          message;
	ncfg_wire_message_t parsed;
	ncfg_wire_attrs_t   attrs;
	ncfg_wire_attrs_t   spec;
	ncfg_wire_attr_t    attr;
	char                err[NCFG_ERROR_MAX];
	uint16_t            flags = 0;
	uint16_t            vid = 0;

	memset(&op, 0, sizeof(op));
	op.kind = NCFG_OP_BRIDGE_VLAN_ADD;
	op.u.bridge_vlan.iface = "eth0";
	op.u.bridge_vlan.vid = 10;
	op.u.bridge_vlan.pvid = 1;
	op.u.bridge_vlan.untagged = 1;

	ncfg_buf_init(&message, 0);
	check(ncfg_kernel_build_bridge_vlan(&message, 5u, 13u, &op, 1, err, sizeof(err)),
	    "a bridge vlan add builds");
	check(first_message(&message, &parsed) && parsed.header.kind == RTM_SETLINK,
	    "and an add is an RTM_SETLINK");
	check(attrs_after(&parsed, NCFG_WIRE_IFINFO_LEN, &attrs) &&
	    find(&attrs, IFLA_AF_SPEC, &attr), "carrying an AF_SPEC nest");
	nested(&attr, &spec);
	check(find(&spec, IFLA_BRIDGE_VLAN_INFO, &attr) && attr.length == 4u,
	    "with a four-byte vlan info in it");
	memcpy(&flags, attr.value, sizeof(flags));
	memcpy(&vid, attr.value + sizeof(flags), sizeof(vid));
	/* `struct bridge_vlan_info { __u16 flags; __u16 vid; }`, in that order:
	 * swapping them produces a request for VLAN 0 with nonsense flags that the
	 * kernel may well accept. */
	check(vid == 10u, "the id in the second half");
	check((flags & BRIDGE_VLAN_INFO_PVID) != 0 &&
	    (flags & BRIDGE_VLAN_INFO_UNTAGGED) != 0, "and both flags in the first");
	ncfg_buf_free(&message);

	op.kind = NCFG_OP_BRIDGE_VLAN_DEL;
	ncfg_buf_init(&message, 0);
	check(ncfg_kernel_build_bridge_vlan(&message, 5u, 13u, &op, 0, err, sizeof(err)),
	    "a bridge vlan del builds");
	check(first_message(&message, &parsed) && parsed.header.kind == RTM_DELLINK,
	    "and a del is an RTM_DELLINK");
	check(attrs_after(&parsed, NCFG_WIRE_IFINFO_LEN, &attrs) &&
	    find(&attrs, IFLA_AF_SPEC, &attr), "carrying an AF_SPEC nest");
	nested(&attr, &spec);
	check(find(&spec, IFLA_BRIDGE_VLAN_INFO, &attr) && attr.length == 4u, "with vlan info");
	memcpy(&flags, attr.value, sizeof(flags));
	/*
	 * The two flags say what a VLAN *is* on a port, and the kernel matches a
	 * delete on the id. Carrying them would make a removal that failed to
	 * match look like one that succeeded against a differently flagged VLAN.
	 */
	check(flags == 0u, "and no flags at all on the way out");
	ncfg_buf_free(&message);

	op.kind = NCFG_OP_BRIDGE_VLAN_ADD;
	op.u.bridge_vlan.vid = 4095;
	ncfg_buf_init(&message, 0);
	err[0] = '\0';
	check(!ncfg_kernel_build_bridge_vlan(&message, 5u, 13u, &op, 1, err, sizeof(err)) &&
	    strstr(err, "4094") != NULL, "vlan 4095 is reserved and is refused by name");
	ncfg_buf_free(&message);

	op.u.bridge_vlan.vid = 4097;
	ncfg_buf_init(&message, 0);
	err[0] = '\0';
	/* Truncating 4097 to a `u16` gives 4097 and truncating to twelve bits
	 * gives 1 -- the VLAN the kernel adds by itself, which every real trunk
	 * setup begins by deleting. Checked rather than cast. */
	check(!ncfg_kernel_build_bridge_vlan(&message, 5u, 13u, &op, 1, err, sizeof(err)),
	    "and a vlan id past the twelve bits it has is refused, not truncated");
	ncfg_buf_free(&message);
}

/* ------------------------------------------------------------------------ *
 * Rules
 * ------------------------------------------------------------------------ */

static void check_rules(void)
{
	ncfg_routing_rule_t rule;
	ncfg_ops_rule_t     spec;
	ncfg_op_t           op;
	ncfg_buf_t          message;
	ncfg_wire_message_t parsed;
	ncfg_wire_attrs_t   attrs;
	char                err[NCFG_ERROR_MAX];
	int                 found = 0;

	memset(&rule, 0, sizeof(rule));
	rule.id = (char *)(uintptr_t)"uplink";
	rule.priority = 100;
	rule.family = NCFG_RULE_FAMILY_INET;
	rule.action = NCFG_RULE_ACTION_LOOKUP;
	rule.from = (char *)(uintptr_t)"10.0.0.0/24";
	rule.table.has = 1;
	rule.table.value = 1000;

	check(ncfg_kernel_rule_spec(&rule, &spec, err, sizeof(err)),
	    "a model rule becomes a wire spec");
	check(spec.family == AF_INET && spec.action == FR_ACT_TO_TBL && spec.priority == 100u,
	    "with the family, the action and the priority carried across");
	check(spec.table == 1000u, "and a table of 1000, not the 232 a byte would hold");
	check(spec.from.family == AF_INET && spec.from_len == 24u, "and the source selector");
	check(!spec.protocol.has,
	    "the ownership tag is left to ops.h, so an operator cannot forge it");

	/* A selector written without a length is a host selector, which is what
	 * `ip rule from 10.0.0.5` means. The Rust refuses it outright. */
	rule.from = (char *)(uintptr_t)"10.0.0.5";
	check(ncfg_kernel_rule_spec(&rule, &spec, err, sizeof(err)) && spec.from_len == 32u,
	    "a selector with no prefix length is a host selector");

	rule.from = (char *)(uintptr_t)"2001:db8::/32";
	err[0] = '\0';
	check(!ncfg_kernel_rule_spec(&rule, &spec, err, sizeof(err)) &&
	    strstr(err, "family") != NULL,
	    "an IPv6 selector on an inet rule is refused by name, not by EINVAL");

	rule.from = NULL;
	rule.fwmask.has = 1;
	rule.fwmask.value = 0xff;
	err[0] = '\0';
	check(!ncfg_kernel_rule_spec(&rule, &spec, err, sizeof(err)) &&
	    strstr(err, "mask") != NULL,
	    "a firewall mask with no mark selects packets marked zero, and is refused");
	rule.fwmask.has = 0;

	rule.priority = 0x100000000LL;
	err[0] = '\0';
	check(!ncfg_kernel_rule_spec(&rule, &spec, err, sizeof(err)),
	    "a priority past 32 bits is refused rather than wrapped");
	rule.priority = 100;

	memset(&op, 0, sizeof(op));
	op.kind = NCFG_OP_RULE_ADD;
	op.u.rule.rule = &rule;
	ncfg_buf_init(&message, 0);
	check(ncfg_kernel_build_rule(&message, 9u, &op, 1, err, sizeof(err)),
	    "a rule.add builds into a message");
	check(first_message(&message, &parsed) && parsed.header.kind == RTM_NEWRULE &&
	    (parsed.header.flags & NLM_F_EXCL) != 0,
	    "an RTM_NEWRULE with EXCL, so it cannot replace somebody else's");
	check(attrs_after(&parsed, NCFG_RULE_HDR_LEN, &attrs), "whose attributes parse");
	check(u32_of(&attrs, FRA_PRIORITY, &found) == 100u && found, "carrying the priority");
	check(u32_of(&attrs, FRA_TABLE, &found) == 1000u && found,
	    "and the table, which does not fit the header's byte");
	check(u8_of(&attrs, FRA_PROTOCOL, &found) == NCFG_WIRE_RTPROT_NETCFGD && found,
	    "and netcfgd's protocol tag");
	ncfg_buf_free(&message);

	op.kind = NCFG_OP_RULE_DEL;
	ncfg_buf_init(&message, 0);
	check(ncfg_kernel_build_rule(&message, 9u, &op, 0, err, sizeof(err)),
	    "a rule.del builds into a message");
	check(first_message(&message, &parsed) && parsed.header.kind == RTM_DELRULE,
	    "an RTM_DELRULE");
	check(attrs_after(&parsed, NCFG_RULE_HDR_LEN, &attrs) &&
	    u8_of(&attrs, FRA_PROTOCOL, &found) == NCFG_WIRE_RTPROT_NETCFGD && found,
	    "which also carries the tag, so it cannot match a rule netcfgd did not install");
	ncfg_buf_free(&message);

	op.u.rule.rule = NULL;
	ncfg_buf_init(&message, 0);
	err[0] = '\0';
	check(!ncfg_kernel_build_rule(&message, 9u, &op, 1, err, sizeof(err)),
	    "a rule action carrying no rule is refused");
	ncfg_buf_free(&message);
}

/* ------------------------------------------------------------------------ *
 * Traffic control
 * ------------------------------------------------------------------------ */

static void check_qdisc(void)
{
	ncfg_op_t           op;
	ncfg_buf_t          message;
	ncfg_wire_message_t parsed;
	ncfg_wire_attrs_t   attrs;
	ncfg_wire_attrs_t   options;
	ncfg_wire_attr_t    attr;
	ncfg_qdisc_tcmsg_t  header;
	char                word[32];
	char                err[NCFG_ERROR_MAX];
	uint64_t            rate;
	int                 found = 0;

	memset(&op, 0, sizeof(op));
	op.kind = NCFG_OP_QDISC_SET;
	op.u.qdisc.iface = "eth0";
	op.u.qdisc.kind = "cake";
	op.u.qdisc.bandwidth_bits.has = 1;
	op.u.qdisc.bandwidth_bits.value = 100000000; /* 100 Mbit */

	ncfg_buf_init(&message, 0);
	check(ncfg_kernel_build_qdisc(&message, 2u, 13u, &op, err, sizeof(err)),
	    "a root qdisc builds into a message");
	check(first_message(&message, &parsed) && parsed.header.kind == RTM_NEWQDISC,
	    "an RTM_NEWQDISC");
	check(ncfg_qdisc_tcmsg_decode(parsed.payload, parsed.payload_length, &header, NULL, 0) &&
	    header.handle == NCFG_QDISC_HANDLE,
	    "wearing netcfgd's own handle, which is how it is recognised later (0137)");
	check(attrs_after(&parsed, NCFG_QDISC_TCMSG_LEN, &attrs), "whose attributes parse");
	check(strcmp(text_of(&attrs, TCA_KIND, word, sizeof(word)), "cake") == 0,
	    "naming the scheduler the document asked for");
	check(find(&attrs, TCA_OPTIONS, &attr), "and carrying its options");
	nested(&attr, &options);
	rate = u64_of(&options, TCA_CAKE_BASE_RATE64, &found);
	/*
	 * **The units trap, and it is the whole of what this module can get
	 * silently wrong.** `tc` takes `bandwidth 100mbit`, the document stores
	 * bits, and this field is *bytes* -- a rate sent in bits is accepted and
	 * shapes at an eighth of what was asked for, which looks like a slow line
	 * rather than a bug, and it is somebody's uplink.
	 */
	check(found && rate == 12500000u, "and 100 Mbit as 12,500,000 bytes per second");
	ncfg_buf_free(&message);

	op.u.qdisc.bandwidth_bits.value = -1;
	ncfg_buf_init(&message, 0);
	err[0] = '\0';
	check(!ncfg_kernel_build_qdisc(&message, 2u, 13u, &op, err, sizeof(err)) &&
	    strstr(err, "negative") != NULL,
	    "a negative rate is refused rather than arriving as an enormous one");
	ncfg_buf_free(&message);

	op.u.qdisc.bandwidth_bits.has = 0;
	op.u.qdisc.kind = "fq_codel";
	ncfg_buf_init(&message, 0);
	check(ncfg_kernel_build_qdisc(&message, 2u, 13u, &op, err, sizeof(err)),
	    "a scheduler with no rate builds");
	ncfg_buf_free(&message);

	op.u.qdisc.bandwidth_bits.has = 1;
	op.u.qdisc.bandwidth_bits.value = 1000;
	ncfg_buf_init(&message, 0);
	err[0] = '\0';
	/* Refused by `ncfg_qdisc_build_set_root`, which is where the rule lives:
	 * attribute 2 is the rate under `cake` and a packet limit under
	 * `fq_codel`, and nested validation is liberal enough to accept it. */
	check(!ncfg_kernel_build_qdisc(&message, 2u, 13u, &op, err, sizeof(err)),
	    "a rate under a scheduler that cannot shape is refused");
	ncfg_buf_free(&message);

	memset(&op, 0, sizeof(op));
	op.kind = NCFG_OP_QDISC_RESET;
	op.u.iface.iface = "eth0";
	ncfg_buf_init(&message, 0);
	check(ncfg_kernel_build_qdisc(&message, 2u, 13u, &op, err, sizeof(err)),
	    "a qdisc.reset builds into a message");
	check(first_message(&message, &parsed) && parsed.header.kind == RTM_DELQDISC,
	    "an RTM_DELQDISC, which puts net.core.default_qdisc back");
	ncfg_buf_free(&message);
}

static void check_redirect(void)
{
	ncfg_buf_t          hook;
	ncfg_buf_t          filter;
	ncfg_wire_message_t parsed;
	ncfg_qdisc_tcmsg_t  header;
	ncfg_wire_attrs_t   attrs;
	char                word[32];
	char                err[NCFG_ERROR_MAX];

	ncfg_buf_init(&hook, 0);
	ncfg_buf_init(&filter, 0);
	check(ncfg_kernel_build_redirect(&hook, &filter, 40u, 13u, 18u, err, sizeof(err)),
	    "a redirect builds as two messages");
	/*
	 * The hook first: the kernel has nowhere to put a classifier until the
	 * ingress qdisc exists, and the error for that says only `EINVAL`. Built
	 * as a pair so the order is a property of the module rather than a habit
	 * of its caller.
	 */
	check(first_message(&hook, &parsed) && parsed.header.kind == RTM_NEWQDISC &&
	    parsed.header.seq == 40u, "the ingress hook first, at the sequence given");
	check(attrs_after(&parsed, NCFG_QDISC_TCMSG_LEN, &attrs) &&
	    strcmp(text_of(&attrs, TCA_KIND, word, sizeof(word)), "ingress") == 0,
	    "and it is the ingress qdisc");
	check(first_message(&filter, &parsed) && parsed.header.kind == RTM_NEWTFILTER &&
	    parsed.header.seq == 41u, "the filter second, one sequence number later");
	check(ncfg_qdisc_tcmsg_decode(parsed.payload, parsed.payload_length, &header, NULL, 0) &&
	    header.handle == NCFG_QDISC_FILTER_HANDLE,
	    "wearing netcfgd's filter handle, and not netcfgd's priority (0137)");
	check(attrs_after(&parsed, NCFG_QDISC_TCMSG_LEN, &attrs) &&
	    strcmp(text_of(&attrs, TCA_KIND, word, sizeof(word)), "matchall") == 0,
	    "a match-all classifier, which is the whole filter language netcfgd writes");
	ncfg_buf_free(&hook);
	ncfg_buf_free(&filter);

	ncfg_buf_init(&hook, 0);
	ncfg_buf_init(&filter, 0);
	err[0] = '\0';
	/* Refused by `ncfg_qdisc_build_redirect`: everything arriving would be
	 * sent straight back out, and the only thing stopping it is the kernel's
	 * recursion limit. */
	check(!ncfg_kernel_build_redirect(&hook, &filter, 40u, 13u, 13u, err, sizeof(err)),
	    "a redirect from an interface onto itself is a loop and is refused");
	ncfg_buf_free(&hook);
	ncfg_buf_free(&filter);
}

/* ------------------------------------------------------------------------ *
 * The offloads
 * ------------------------------------------------------------------------ */

static void check_offloads(void)
{
	ncfg_genl_family_t  family;
	ncfg_offload_t      features[2];
	ncfg_op_t           op;
	ncfg_buf_t          message;
	ncfg_wire_message_t parsed;
	ncfg_wire_attrs_t   attrs;
	ncfg_wire_attrs_t   bitset;
	ncfg_wire_attrs_t   bits;
	ncfg_wire_attrs_t   one;
	ncfg_wire_attr_t    attr;
	char                err[NCFG_ERROR_MAX];
	char                name[64];
	int                 sawgro = 0;
	int                 sawgso = 0;

	memset(&family, 0, sizeof(family));
	family.id = 24u;
	features[0].name = "rx-gro";
	features[0].wanted = 1;
	features[1].name = "tx-gso";
	features[1].wanted = 0;

	memset(&op, 0, sizeof(op));
	op.kind = NCFG_OP_LINK_SET_OFFLOADS;
	op.u.set_offloads.name = "eth0";
	op.u.set_offloads.features = features;
	op.u.set_offloads.feature_count = 2u;

	ncfg_buf_init(&message, 0);
	check(ncfg_kernel_build_offloads(&message, &family, 6u, &op, err, sizeof(err)),
	    "an offload change builds into a message");
	check(first_message(&message, &parsed) && parsed.header.kind == 24u &&
	    (parsed.header.flags & NLM_F_ACK) != 0,
	    "aimed at the resolved family, and acknowledged");
	check(attrs_after(&parsed, NCFG_GENL_HDR_LEN, &attrs) &&
	    find(&attrs, ETHTOOL_A_FEATURES_WANTED, &attr), "carrying a wanted bitset");
	nested(&attr, &bitset);
	/*
	 * **A mask bitset, deliberately without `NOMASK`.** It says "change
	 * exactly these and leave everything else alone"; the no-mask form would
	 * mean "this is the complete set of enabled features", which would turn
	 * off every offload the document does not mention.
	 */
	check(!find(&bitset, ETHTOOL_A_BITSET_NOMASK, &attr),
	    "which is a mask bitset, not the list form that would clear the rest");
	check(find(&bitset, ETHTOOL_A_BITSET_BITS, &attr), "with a bits nest");
	nested(&attr, &bits);
	while (ncfg_wire_attrs_next(&bits, &attr, NULL, 0) == NCFG_WIRE_OK) {
		nested(&attr, &one);
		(void)text_of(&one, ETHTOOL_A_BITSET_BIT_NAME, name, sizeof(name));
		if (strcmp(name, "rx-gro") == 0) {
			/* Within a mask bitset there is no "false" encoding: `BIT_VALUE`
			 * is a flag, so present means on and absent means off. Writing a
			 * zero-valued one would read as on. */
			sawgro = find(&one, ETHTOOL_A_BITSET_BIT_VALUE, &attr) ? 1 : -1;
		} else if (strcmp(name, "tx-gso") == 0) {
			sawgso = find(&one, ETHTOOL_A_BITSET_BIT_VALUE, &attr) ? -1 : 1;
		}
	}
	check(sawgro == 1, "a feature turned on carries the value flag");
	check(sawgso == 1, "and one turned off carries no flag, which is how off is spelled");
	ncfg_buf_free(&message);

	op.u.set_offloads.feature_count = 0u;
	ncfg_buf_init(&message, 0);
	err[0] = '\0';
	/* A request naming no feature is a bitset with nothing in it, which the
	 * kernel accepts and which changes nothing -- a successful apply for work
	 * nobody did. */
	check(!ncfg_kernel_build_offloads(&message, &family, 6u, &op, err, sizeof(err)),
	    "an offload change naming no feature is refused, not sent empty");
	ncfg_buf_free(&message);

	op.u.set_offloads.feature_count = 2u;
	op.u.set_offloads.features = NULL;
	ncfg_buf_init(&message, 0);
	err[0] = '\0';
	check(!ncfg_kernel_build_offloads(&message, &family, 6u, &op, err, sizeof(err)),
	    "and a count with no list behind it is refused rather than walked");
	ncfg_buf_free(&message);
}

/* ------------------------------------------------------------------------ *
 * WireGuard
 * ------------------------------------------------------------------------ */

/* A key the fixture store hands back. 44 characters of base64 ending in the
 * one pad, which is what 32 octets spells. */
#define A_KEY "iFyJd3O8wIhDF2tLMdC/2SVhgVs3xKDHKuCZ3TqRXVk="
#define B_KEY "qGpUZ0y4h1dlAZMDpXgw6gS4HGZPWv0PK3LzwjPHAV0="

static int write_secret(const char *dir, const char *name, const char *text)
{
	char path[512];
	int  fd;

	if ((size_t)snprintf(path, sizeof(path), "%s/%s", dir, name) >= sizeof(path)) {
		return 0;
	}
	/* 0600 by the open rather than after it: `secrets.h` refuses a key file
	 * anybody else can read, and a chmod afterwards leaves an instant in which
	 * one exists and is readable. */
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0) {
		return 0;
	}
	if (write(fd, text, strlen(text)) != (ssize_t)strlen(text)) {
		(void)close(fd);
		return 0;
	}
	return close(fd) == 0;
}

static void check_wireguard(void)
{
	char                    dir[256];
	char                    path[512];
	ncfg_secret_resolver_t  resolver;
	ncfg_genl_family_t      family;
	ncfg_document_t         document;
	ncfg_device_t           device;
	ncfg_wg_peer_t          peer;
	ncfg_secret_ref_t       preshared;
	ncfg_op_t               op;
	ncfg_wg_messages_t      messages;
	ncfg_wire_message_t     parsed;
	ncfg_wire_attrs_t       attrs;
	ncfg_wire_attr_t        attr;
	ncfg_buf_t              held;
	char                    err[NCFG_ERROR_MAX];
	char                    ifname[64];
	const char             *allowed[1];
	int                     found = 0;

	if (!tempdir_make("apply-kernel", dir, sizeof(dir))) {
		check(0, "a directory for the secrets fixture");
		return;
	}
	check(write_secret(dir, "wg0", A_KEY) && write_secret(dir, "psk", B_KEY),
	    "a private key and a preshared key in a store of the test's own");

	memset(&resolver, 0, sizeof(resolver));
	resolver.secrets_dir = dir;
	memset(&family, 0, sizeof(family));
	family.id = 31u;

	memset(&device, 0, sizeof(device));
	device.name = (char *)(uintptr_t)"wg0";
	device.kind.kind = NCFG_KIND_WIREGUARD;
	device.kind.wireguard.private_key.provider = NCFG_SECRET_PROVIDER_FILE;
	device.kind.wireguard.private_key.name = (char *)(uintptr_t)"wg0";
	memset(&document, 0, sizeof(document));
	document.devices = &device;
	document.device_count = 1u;

	/* ---- the device half ---- */
	memset(&op, 0, sizeof(op));
	op.kind = NCFG_OP_WG_SET_DEVICE;
	op.u.wg_device.iface = "wg0";
	op.u.wg_device.private_key_ref = "wg0";
	op.u.wg_device.listen_port.has = 1;
	op.u.wg_device.listen_port.value = 51820;

	memset(&messages, 0, sizeof(messages));
	check(ncfg_kernel_wg_build(&messages, &family, 12u, &op, &document, &resolver, err,
	    sizeof(err)), "a wg.set_device builds");
	check(messages.count == 1u, "as one message");
	held.data = NULL;
	check(messages.count == 1u &&
	    ncfg_wire_header_decode(messages.message[0].bytes, messages.message[0].length,
	    &parsed.header, NULL, 0), "whose header parses");
	if (messages.count == 1u) {
		ncfg_wire_messages_t walk;

		ncfg_wire_messages_start(&walk, messages.message[0].bytes,
		    messages.message[0].length);
		check(ncfg_wire_messages_next(&walk, &parsed, NULL, 0) == NCFG_WIRE_OK &&
		    attrs_after(&parsed, NCFG_GENL_HDR_LEN, &attrs),
		    "and whose attributes parse");
		check(strcmp(text_of(&attrs, WGDEVICE_A_IFNAME, ifname, sizeof(ifname)), "wg0") == 0,
		    "naming the device");
		check(find(&attrs, WGDEVICE_A_PRIVATE_KEY, &attr) &&
		    attr.length == NCFG_WG_KEY_LEN,
		    "carrying 32 octets of private key, not 44 of base64");
		check(u16_of(&attrs, WGDEVICE_A_LISTEN_PORT, &found) == 51820u && found,
		    "and the listen port");
		/*
		 * **No peers and no replace flag.** Decision 0054 split the two ops
		 * so that changing a port does not touch the peer list; a device half
		 * that carried the flag would clear every peer on every port change.
		 */
		check(!find(&attrs, WGDEVICE_A_PEERS, &attr), "and no peer list at all");
		check(!find(&attrs, WGDEVICE_A_FLAGS, &attr),
		    "and no replace flag, so a port change cannot clear the peers");
	}
	ncfg_wg_messages_free(&messages);

	/* ---- the peer half ---- */
	memset(&preshared, 0, sizeof(preshared));
	preshared.provider = NCFG_SECRET_PROVIDER_FILE;
	preshared.name = (char *)(uintptr_t)"psk";
	allowed[0] = "10.0.0.0/24";
	memset(&peer, 0, sizeof(peer));
	peer.name = (char *)(uintptr_t)"hub";
	peer.preshared_key = &preshared;
	peer.endpoint = (char *)(uintptr_t)"192.0.2.1:51820";
	peer.allowed_ips = (char **)(uintptr_t)(const void *)allowed;
	peer.allowed_ip_count = 1u;

	memset(&op, 0, sizeof(op));
	op.kind = NCFG_OP_WG_SET_PEERS;
	op.u.wg_peers.iface = "wg0";
	op.u.wg_peers.peers = &peer;
	op.u.wg_peers.peer_count = 1u;

	memset(&messages, 0, sizeof(messages));
	check(ncfg_kernel_wg_build(&messages, &family, 12u, &op, &document, &resolver, err,
	    sizeof(err)), "a wg.set_peers builds");
	if (messages.count >= 1u) {
		ncfg_wire_messages_t walk;
		uint32_t             flags;

		ncfg_wire_messages_start(&walk, messages.message[0].bytes,
		    messages.message[0].length);
		check(ncfg_wire_messages_next(&walk, &parsed, NULL, 0) == NCFG_WIRE_OK &&
		    attrs_after(&parsed, NCFG_GENL_HDR_LEN, &attrs), "and its attributes parse");
		flags = u32_of(&attrs, WGDEVICE_A_FLAGS, &found);
		/*
		 * **True even with an empty list, and that is the point**: true and
		 * no peers is how the last peer is removed, and without the flag a
		 * `SET_DEVICE` merges and a peer the document has removed goes on
		 * accepting traffic.
		 */
		check(found && (flags & WGDEVICE_F_REPLACE_PEERS) != 0,
		    "carrying the replace flag, which is how a removed peer stops working");
		check(find(&attrs, WGDEVICE_A_PEERS, &attr), "and a peer list");
		check(!find(&attrs, WGDEVICE_A_LISTEN_PORT, &attr) &&
		    !find(&attrs, WGDEVICE_A_PRIVATE_KEY, &attr),
		    "and nothing about the device, so the kernel leaves its port alone");
	}
	ncfg_wg_messages_free(&messages);

	/* ---- the refusals ---- */
	memset(&op, 0, sizeof(op));
	op.kind = NCFG_OP_WG_SET_DEVICE;
	op.u.wg_device.iface = "wg0";
	op.u.wg_device.private_key_ref = "somethingelse";
	memset(&messages, 0, sizeof(messages));
	err[0] = '\0';
	/* The op carries the reference's name and the document carries its
	 * provider, so both are needed and both must agree: a mismatch is a plan
	 * built from another document, and the key it would load is not the key
	 * that was planned. */
	check(!ncfg_kernel_wg_build(&messages, &family, 12u, &op, &document, &resolver, err,
	    sizeof(err)) && strstr(err, "different document") != NULL,
	    "a private key reference the document does not name is refused");
	ncfg_wg_messages_free(&messages);

	check(write_secret(dir, "broken", "this is not a key"),
	    "a store entry that is not a key");
	device.kind.wireguard.private_key.name = (char *)(uintptr_t)"broken";
	op.u.wg_device.private_key_ref = "broken";
	memset(&messages, 0, sizeof(messages));
	err[0] = '\0';
	check(!ncfg_kernel_wg_build(&messages, &family, 12u, &op, &document, &resolver, err,
	    sizeof(err)), "a key that does not decode is refused");
	check(strstr(err, "this is not a key") == NULL,
	    "and the refusal does not quote it: a key that failed to parse is still a key");
	ncfg_wg_messages_free(&messages);

	(void)snprintf(path, sizeof(path), "%s/wg0", dir);
	(void)unlink(path);
	(void)snprintf(path, sizeof(path), "%s/psk", dir);
	(void)unlink(path);
	(void)snprintf(path, sizeof(path), "%s/broken", dir);
	(void)unlink(path);
	(void)rmdir(dir);
	(void)held;
}

static void check_endpoints(void)
{
	ncfg_wire_ip_t address;
	uint16_t       port = 0;
	char           err[NCFG_ERROR_MAX];

	check(ncfg_kernel_endpoint("192.0.2.1:51820", &address, &port, err, sizeof(err)) &&
	    address.family == AF_INET && port == 51820u,
	    "an IPv4 literal endpoint resolves without touching the network");
	check(ncfg_kernel_endpoint("[2001:db8::1]:51820", &address, &port, err, sizeof(err)) &&
	    address.family == AF_INET6 && port == 51820u,
	    "and a bracketed IPv6 literal");
	err[0] = '\0';
	/*
	 * The brackets are required for the reason they exist at all:
	 * `fd00::1:51820` is a perfectly good address, and reading a port off the
	 * end of one would silently reconfigure a peer to talk somewhere else.
	 */
	check(!ncfg_kernel_endpoint("fd00::1:51820", &address, &port, err, sizeof(err)) &&
	    strstr(err, "brackets") != NULL,
	    "a bare IPv6 literal is refused rather than read as an address and a port");
	err[0] = '\0';
	check(!ncfg_kernel_endpoint("192.0.2.1", &address, &port, err, sizeof(err)),
	    "an endpoint with no port is refused");
	err[0] = '\0';
	check(!ncfg_kernel_endpoint("192.0.2.1:", &address, &port, err, sizeof(err)),
	    "and so is one with a colon and nothing after it");
}

/* ------------------------------------------------------------------------ *
 * NAT
 * ------------------------------------------------------------------------ */

static void check_nat(void)
{
	const char      *uplinks[1];
	ncfg_op_t        op;
	ncfg_buf_t       message;
	ncfg_nft_batch_t batch;
	char             err[NCFG_ERROR_MAX];

	uplinks[0] = "eth0";
	memset(&op, 0, sizeof(op));
	op.kind = NCFG_OP_NAT_REPLACE;
	op.u.nat.uplinks = uplinks;
	op.u.nat.uplink_count = 1u;

	memset(&batch, 0, sizeof(batch));
	ncfg_buf_init(&message, 0);
	check(ncfg_kernel_build_nat(&message, 100u, 0, &op, &batch, err, sizeof(err)),
	    "a nat.replace builds a transaction");
	check(!batch.empty && batch.last_acked >= 100u,
	    "with an acknowledged message inside it");
	/*
	 * Decision 0022 as a check rather than as a comment. `nft.h` audits what
	 * it built before handing it back; this asks the same question of the
	 * bytes that reached the caller, which is the artifact rather than a fresh
	 * measurement of where it came from.
	 */
	check(ncfg_nft_writes_only_our_table(message.data, message.length, err, sizeof(err)),
	    "and every message in it names netcfgd's own table and chain");
	ncfg_buf_free(&message);

	memset(&batch, 0, sizeof(batch));
	ncfg_buf_init(&message, 0);
	check(ncfg_kernel_build_nat(&message, 100u, 1, &op, &batch, err, sizeof(err)),
	    "a transaction against a table that already exists builds too");
	check(ncfg_nft_writes_only_our_table(message.data, message.length, NULL, 0),
	    "and it also touches nothing else");
	ncfg_buf_free(&message);

	op.u.nat.uplinks = NULL;
	op.u.nat.uplink_count = 0u;
	memset(&batch, 0, sizeof(batch));
	ncfg_buf_init(&message, 0);
	check(ncfg_kernel_build_nat(&message, 100u, 0, &op, &batch, err, sizeof(err)) &&
	    batch.empty,
	    "no uplinks and no table is an empty batch, which must not be sent");
	ncfg_buf_free(&message);

	op.u.nat.uplink_count = 2u;
	memset(&batch, 0, sizeof(batch));
	ncfg_buf_init(&message, 0);
	err[0] = '\0';
	check(!ncfg_kernel_build_nat(&message, 100u, 0, &op, &batch, err, sizeof(err)),
	    "a count with no uplink list behind it is refused rather than walked");
	ncfg_buf_free(&message);

	check(!ncfg_kernel_nat_table_seen(NULL),
	    "no reply at all is not a table that exists");

	{
		ncfg_netlink_reply_t   reply;
		ncfg_netlink_payload_t items[2];
		ncfg_buf_t             ours;
		ncfg_buf_t             theirs;

		/*
		 * Two table-dump payloads, built here rather than read off a machine:
		 * one is `inet netcfgd` and one is `inet filter`, which is what a
		 * container runtime or an operator's own firewall looks like from
		 * this side. The family and the name are compared *together*, because
		 * `ip netcfgd` would be somebody else's table with the same name.
		 */
		ncfg_buf_init(&ours, 0);
		ncfg_buf_add(&ours, "\x01\x00\x00\x00", NCFG_NFT_NFGENMSG_LEN);
		ncfg_wire_attr_put_str(&ours, NFTA_TABLE_NAME, NCFG_NFT_TABLE);
		ncfg_buf_init(&theirs, 0);
		ncfg_buf_add(&theirs, "\x01\x00\x00\x00", NCFG_NFT_NFGENMSG_LEN);
		ncfg_wire_attr_put_str(&theirs, NFTA_TABLE_NAME, "filter");

		memset(&reply, 0, sizeof(reply));
		items[0].bytes = (uint8_t *)theirs.data;
		items[0].length = theirs.length;
		reply.items = items;
		reply.count = 1u;
		check(!ncfg_kernel_nat_table_seen(&reply),
		    "somebody else's table is not netcfgd's");
		items[1].bytes = (uint8_t *)ours.data;
		items[1].length = ours.length;
		reply.count = 2u;
		check(ncfg_kernel_nat_table_seen(&reply),
		    "and netcfgd's own is found beside it");
		ncfg_buf_free(&ours);
		ncfg_buf_free(&theirs);
	}
}


/* ------------------------------------------------------------------------ *
 * The mark a created link wears
 * ------------------------------------------------------------------------ */

/*
 * `link.create` stamps the link as netcfgd's, and the proof goes all the way
 * round without a kernel.
 *
 * **Why this one is worth the length.** A link has no protocol field, so this
 * alternative name is the only mark it can carry (0136), and
 * `ncfg_observe_link_ownership` is the reader that decides from it whether
 * netcfgd may ever take the link down again. A stamp that went out under a
 * spelling the reader does not recognise is indistinguishable, from inside
 * either half, from a stamp that works -- so the last check below builds the
 * message, walks the name back out of the bytes and hands *that* to the
 * reader. Nothing in between is spelled twice, and the prefix is spelled in
 * neither half: it comes from `observe.h`.
 *
 * `ncfg_ops_add_altname` already has its own bytes checked in `ops_test.c` --
 * the `RTM_NEWLINKPROP` nest and the `NLA_F_NESTED` that message type insists
 * on are that file's subject and are not asserted a second time here. What is
 * checked here is what *this* module puts into it.
 */
static void check_mark(void)
{
	char             altname[NCFG_WIRE_ALT_IFNAME_MAX];
	char             err[NCFG_ERROR_MAX];
	char             expected[NCFG_WIRE_ALT_IFNAME_MAX];
	char             too_long[NCFG_WIRE_ALT_IFNAME_MAX + 8];
	ncfg_buf_t       buf;
	ncfg_wire_message_t message;
	ncfg_wire_attrs_t attrs;
	ncfg_wire_attrs_t props;
	ncfg_wire_attr_t  attr;

	(void)snprintf(expected, sizeof(expected), "%sbr0", NCFG_OBSERVE_ALTNAME_PREFIX);
	err[0] = '\0';
	check(ncfg_kernel_altname_of("br0", altname, sizeof(altname), err, sizeof(err)) &&
	    strcmp(altname, expected) == 0,
	    "a created link's mark is observe.h's prefix and the link's own name");

	err[0] = '\0';
	altname[0] = 'x';
	check(!ncfg_kernel_altname_of("", altname, sizeof(altname), err, sizeof(err)) &&
	    altname[0] == '\0' && err[0] != '\0',
	    "a link with no name is refused, and nothing half-built is left behind");

	memset(too_long, 'a', sizeof(too_long) - 1u);
	too_long[sizeof(too_long) - 1u] = '\0';
	err[0] = '\0';
	altname[0] = 'x';
	check(!ncfg_kernel_altname_of(too_long, altname, sizeof(altname), err, sizeof(err)) &&
	    altname[0] == '\0',
	    "  and so is a name the prefix would push past ALTIFNAMSIZ");

	/*
	 * The message. `RTM_NEWLINKPROP` rather than an attribute on an ordinary
	 * `RTM_NEWLINK`, which the kernel ignores -- `ops.h` says so and this is
	 * the caller that depends on it.
	 */
	ncfg_buf_init(&buf, 0);
	err[0] = '\0';
	if (ncfg_kernel_build_altname(&buf, 7u, 4u, "br0", err, sizeof(err)) &&
	    first_message(&buf, &message) &&
	    attrs_after(&message, NCFG_WIRE_IFINFO_LEN, &attrs) &&
	    find(&attrs, IFLA_PROP_LIST, &attr)) {
		char back[NCFG_WIRE_ALT_IFNAME_MAX];
		char *names[1];

		check(message.header.kind == RTM_NEWLINKPROP,
		    "the mark is RTM_NEWLINKPROP, which is the only message that adds one");
		check(message.header.seq == 7u,
		    "  at the sequence number its acknowledgement will be waited on under");
		nested(&attr, &props);
		(void)text_of(&props, IFLA_ALT_IFNAME, back, sizeof(back));
		check(strcmp(back, expected) == 0,
		    "  and the name in the bytes is the one netcfgd looks for");
		/*
		 * The round trip, and the only check here that is about both halves
		 * at once: the name the *builder* produced, read back out of the wire
		 * and handed to the observer's judgement.
		 */
		names[0] = back;
		check(ncfg_observe_link_ownership(names, 1u, 0) == NCFG_OWNERSHIP_OURS,
		    "  and a link wearing exactly those bytes reads back as netcfgd's own");
	} else {
		check(0, "the mark is RTM_NEWLINKPROP, which is the only message that adds one");
		check(0, "  at the sequence number its acknowledgement will be waited on under");
		check(0, "  and the name in the bytes is the one netcfgd looks for");
		check(0, "  and a link wearing exactly those bytes reads back as netcfgd's own");
	}
	ncfg_buf_free(&buf);

	/* And the marker is not the whole name: a link renamed after netcfgd made
	 * it still matches, which is `link_ownership`'s prefix rule and is why the
	 * builder may put the name in at all. */
	{
		char *names[1];

		names[0] = expected;
		check(ncfg_observe_link_ownership(names, 1u, 0) == NCFG_OWNERSHIP_OURS &&
		    ncfg_observe_link_ownership(names, 0u, 0) == NCFG_OWNERSHIP_UNKNOWN,
		    "an unmarked, unrecorded link stays unknown rather than becoming foreign");
	}
}

int main(void)
{
	fixture_t fixture;

	fixture_build(&fixture);

	check_supported();
	check_tolerance();
	check_hints();
	check_bridge(&fixture);
	check_bond(&fixture);
	check_macvlan_and_tunnel(&fixture);
	check_vxlan(&fixture);
	check_kind_refusals(&fixture);
	check_token();
	check_bridge_vlan();
	check_rules();
	check_qdisc();
	check_redirect();
	check_offloads();
	check_wireguard();
	check_endpoints();
	check_nat();
	check_mark();

	if (failures) {
		printf("apply_kernel_test: %d check(s) failed\n", failures);
		return 1;
	}
	printf("apply_kernel_test: every check passed\n");
	return 0;
}
