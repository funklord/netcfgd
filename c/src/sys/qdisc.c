/*
 * qdisc.c -- the traffic control described in qdisc.h.
 *
 * Nothing in this file opens, reads or writes a descriptor. Every function
 * either appends a request to a buffer the caller owns or reads bytes the
 * caller already has, and the ones that read treat those bytes as hostile: a
 * qdisc dump arrives through a socket anything on this machine with
 * `CAP_NET_ADMIN` can also write to.
 */
#include "ncfg/qdisc.h"

#include "ncfg/wire.h"

#include <arpa/inet.h>
#include <stddef.h>
#include <string.h>

#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <linux/pkt_sched.h>
#include <linux/tc_act/tc_mirred.h>

/*
 * The length qdisc.h publishes is the kernel's, and here is the proof.
 *
 * The Rust writes `const TCMSG_LEN: usize = 20;` because it has no access to
 * the struct; a C port that copied the 20 across would be carrying a number
 * nobody had checked against the machine it runs on. This fails the build
 * instead, which is the only kind of check that cannot be skipped.
 */
_Static_assert(sizeof(struct tcmsg) == NCFG_QDISC_TCMSG_LEN, "tcmsg is 20 bytes");

/*
 * And these are why the encoder may write field offsets rather than the struct
 * itself.
 *
 * `struct tcmsg` pads three bytes after `tcm_family` -- one named `tcm__pad1`
 * and a two-byte `tcm__pad2` -- and a port that encoded the fields in
 * declaration order with no gap would put every interface index three bytes
 * early, which is a message about a different interface rather than a message
 * the kernel refuses.
 */
_Static_assert(offsetof(struct tcmsg, tcm_ifindex) == 4, "tcm_ifindex sits at 4");
_Static_assert(offsetof(struct tcmsg, tcm_handle) == 8, "tcm_handle sits at 8");
_Static_assert(offsetof(struct tcmsg, tcm_parent) == 12, "tcm_parent sits at 12");
_Static_assert(offsetof(struct tcmsg, tcm_info) == 16, "tcm_info sits at 16");

/*
 * `struct tc_mirred` is written as a struct rather than as seven words.
 *
 * The Rust builds it by hand -- two zeros, then four ints, then the target --
 * which is a layout assertion spelled as an array literal, and the compiler
 * has nothing to say if the kernel ever grows the structure. These do.
 */
_Static_assert(sizeof(struct tc_mirred) == 28u, "tc_mirred is seven words");
_Static_assert(offsetof(struct tc_mirred, eaction) == 20u, "eaction sits at 20");
_Static_assert(offsetof(struct tc_mirred, ifindex) == 24u, "ifindex is the last word");

/*
 * `ffff:0000`, the handle the ingress qdisc takes and the parent every filter
 * on it names.
 *
 * Spelled with the kernel's own macro rather than written out: `tc qdisc show`
 * prints `ffff:` for it, the kernel's source says `TC_H_MAKE(TC_H_INGRESS, 0)`
 * in the one place it matters, and there is no exported constant.
 */
#define INGRESS_HANDLE TC_H_MAKE(TC_H_INGRESS, 0)

/*
 * The priority netcfgd's redirect filter takes.
 *
 * 1, and it is a correctness constraint rather than a preference: a redirect
 * that runs after another filter has already stolen the packet does nothing.
 * That is why the ownership mark went into the filter's handle instead -- see
 * `NCFG_QDISC_FILTER_HANDLE` and 0137.
 */
#define FILTER_PRIORITY 1u

/*
 * The attribute type one element of an action list carries.
 *
 * The list is indexed from one and **the index is the attribute type** rather
 * than a field inside the element, which is the part of `tc`'s encoding that
 * reads like a mistake and is not. The kernel exports no name for it.
 */
#define ACTION_LIST_FIRST 1u

/* Native-endian appends. `memcpy` of the host representation rather than
 * shifts, for the reason wire.h gives: shifts hardcode x86's answer and are
 * silently wrong anywhere else. */
static void put_u32(ncfg_buf_t *out, uint32_t value)
{
	ncfg_buf_add(out, &value, sizeof(value));
}

/*
 * A 64-bit attribute value, read and written here rather than in wire.h.
 *
 * wire.h publishes `u8`, `u16` and `u32` accessors and no `u64`, and that
 * header is final -- so the one 64-bit field in this module carries its own
 * accessor. It refuses a value of the wrong size for the reason the others do:
 * netlink is not consistent about integer widths and the header gives no hint,
 * so reading one with the wrong accessor returns a number that is merely
 * wrong.
 */
static int attr_u64(const ncfg_wire_attr_t *attr, uint64_t *out, char *err, size_t err_size)
{
	if (!attr || !out || !attr->value || attr->length < sizeof(*out)) {
		ncfg_error_set(err, err_size,
		    "a 64-bit attribute needs 8 bytes and this one has %zu",
		    attr && attr->value ? attr->length : (size_t)0);
		return 0;
	}
	memcpy(out, attr->value, sizeof(*out));
	return 1;
}

static void put_u64(ncfg_buf_t *out, uint16_t kind, uint64_t value)
{
	ncfg_wire_attr_put(out, kind, &value, sizeof(value));
}

/* The string value of one attribute of an area, or 0 where it is absent,
 * malformed or too long for `out`. */
static int find_string(const ncfg_wire_attrs_t *area, uint16_t kind, char *out, size_t out_size,
    char *err, size_t err_size)
{
	ncfg_wire_attr_t attr;

	if (ncfg_wire_attrs_find(area, kind, &attr, err, err_size) != NCFG_WIRE_OK) {
		ncfg_error_set(err, err_size, "no attribute %u where a name was expected",
		    (unsigned)kind);
		return 0;
	}
	return ncfg_wire_attr_string(&attr, out, out_size, err, err_size);
}

/* The attribute area of a dump payload, past the `tcmsg` at its front. */
static int payload_attrs(const void *payload, size_t length, ncfg_wire_attrs_t *out,
    char *err, size_t err_size)
{
	const uint8_t *raw = payload;

	if (!raw || length < NCFG_QDISC_TCMSG_LEN) {
		ncfg_error_set(err, err_size,
		    "a tc message is %u bytes and this payload has %zu",
		    (unsigned)NCFG_QDISC_TCMSG_LEN, raw ? length : (size_t)0);
		return 0;
	}
	/* `struct tcmsg` is already a multiple of four, so there is no padding
	 * between it and the attributes -- but it is skipped by its own length
	 * rather than by a constant, so a kernel that ever grows it does not
	 * silently move every attribute. */
	ncfg_wire_attrs_start(out, raw + NCFG_QDISC_TCMSG_LEN, length - NCFG_QDISC_TCMSG_LEN);
	return 1;
}

/* An interface index for the `tcm_ifindex` field, which the kernel declares
 * signed. Refused rather than folded to zero: the Rust's `unwrap_or(0)` turns
 * a request about one interface into a request about none, and on a delete
 * that is a message that looks like it worked. */
static int index_field(uint32_t index, int32_t *out, char *err, size_t err_size)
{
	if (index == 0 || index > 0x7fffffffu) {
		ncfg_error_set(err, err_size,
		    "%u is not an interface index a tc message can carry", index);
		return 0;
	}
	*out = (int32_t)index;
	return 1;
}

/* One request: header, `tcmsg`, attributes. */
static int build(ncfg_buf_t *out, uint16_t kind, uint16_t flags, uint32_t seq,
    const ncfg_qdisc_tcmsg_t *header, const ncfg_buf_t *attrs, char *err, size_t err_size)
{
	ncfg_buf_t body;
	int built;

	ncfg_buf_init(&body, 0);
	ncfg_qdisc_tcmsg_encode(header, &body);
	built = ncfg_wire_build_request(out, kind, flags, seq, &body, attrs, err, err_size);
	ncfg_buf_free(&body);
	return built;
}

/* ------------------------------------------------------------------------ *
 * The rate, and the factor of eight
 * ------------------------------------------------------------------------ */

int ncfg_qdisc_rate_bytes(uint64_t bits, uint64_t *out, char *err, size_t err_size)
{
	if (!out) {
		ncfg_error_set(err, err_size, "a converted rate needs somewhere to go");
		return 0;
	}
	if (bits == 0) {
		/* Zero in `TCA_CAKE_BASE_RATE64` is not a rate of zero, it is no
		 * shaper -- so a caller who reached here with zero would install
		 * the opposite of what was asked and see nothing in `tc qdisc
		 * show` either way. The compiler refuses `bandwidth = "0mbit"` for
		 * the same reason, in the same words. */
		ncfg_error_set(err, err_size, "a shaped rate of zero would pass nothing");
		return 0;
	}
	if (bits % 8u != 0) {
		/* Rounded down it shapes slower than asked, and below eight bits
		 * per second it rounds to zero, which is no shaper at all. Neither
		 * is visible afterwards, so neither is allowed to happen: the
		 * document can express a bare number of bits, so a rate finer than
		 * a byte reaches here rather than being rounded upstream. */
		ncfg_error_set(err, err_size,
		    "%llu bits per second is not a whole number of bytes per second, "
		    "which is the only rate the kernel can hold",
		    (unsigned long long)bits);
		return 0;
	}
	/* The whole of the units trap, in one line. The kernel's field is
	 * `rate_bps` and the `bps` is **bytes**; `tc` does this same division,
	 * and it is the one place a factor of eight can hide. */
	*out = bits / 8u;
	return 1;
}

int ncfg_qdisc_rate_bits(uint64_t bytes, uint64_t *out, char *err, size_t err_size)
{
	if (!out) {
		ncfg_error_set(err, err_size, "a converted rate needs somewhere to go");
		return 0;
	}
	if (bytes > UINT64_MAX / 8u) {
		ncfg_error_set(err, err_size,
		    "a rate of %llu bytes per second has no answer in bits",
		    (unsigned long long)bytes);
		return 0;
	}
	*out = bytes * 8u;
	return 1;
}

int ncfg_qdisc_shapes(const char *kind)
{
	/* `cake` and nothing else, which is what makes 0023's narrow model
	 * affordable: it shapes by itself, with no class tree and no filters
	 * underneath. Every other scheduler netcfgd will set needs the machinery
	 * that record refuses. */
	return kind && strcmp(kind, "cake") == 0;
}

/* ------------------------------------------------------------------------ *
 * The tc message
 * ------------------------------------------------------------------------ */

void ncfg_qdisc_tcmsg_encode(const ncfg_qdisc_tcmsg_t *message, ncfg_buf_t *out)
{
	static const uint8_t padding[3] = { 0, 0, 0 };

	if (!out || out->failed) {
		return;
	}
	if (!message) {
		out->failed = 1;
		return;
	}
	ncfg_buf_add(out, &message->family, sizeof(message->family));
	/* `tcm__pad1` and `tcm__pad2`, which the kernel declares and never
	 * reads. Written as zero rather than left as whatever the buffer held. */
	ncfg_buf_add(out, padding, sizeof(padding));
	ncfg_buf_add(out, &message->index, sizeof(message->index));
	put_u32(out, message->handle);
	put_u32(out, message->parent);
	put_u32(out, message->info);
}

int ncfg_qdisc_tcmsg_decode(const void *bytes, size_t length, ncfg_qdisc_tcmsg_t *out,
    char *err, size_t err_size)
{
	const uint8_t *raw = bytes;

	if (!raw || !out) {
		ncfg_error_set(err, err_size, "a tc message needs somewhere to come from and go");
		return 0;
	}
	if (length < NCFG_QDISC_TCMSG_LEN) {
		ncfg_error_set(err, err_size,
		    "a tc message is %u bytes and this payload has %zu",
		    (unsigned)NCFG_QDISC_TCMSG_LEN, length);
		return 0;
	}
	out->family = raw[0];
	memcpy(&out->index, raw + 4, sizeof(out->index));
	memcpy(&out->handle, raw + 8, sizeof(out->handle));
	memcpy(&out->parent, raw + 12, sizeof(out->parent));
	memcpy(&out->info, raw + 16, sizeof(out->info));
	return 1;
}

/* ------------------------------------------------------------------------ *
 * Building requests
 * ------------------------------------------------------------------------ */

int ncfg_qdisc_build_dump(ncfg_buf_t *out, uint32_t seq, char *err, size_t err_size)
{
	ncfg_qdisc_tcmsg_t header;

	memset(&header, 0, sizeof(header));
	/* Index zero, which here means every interface. It is the one request in
	 * this file allowed to name none: `RTM_GETQDISC` with a zero index is a
	 * machine-wide dump, where `RTM_GETTFILTER` with one is an empty answer
	 * that looks like a machine with no filters. */
	return build(out, RTM_GETQDISC, (uint16_t)(NLM_F_REQUEST | NLM_F_DUMP), seq, &header,
	    NULL, err, err_size);
}

int ncfg_qdisc_build_set_root(ncfg_buf_t *out, uint32_t seq, uint32_t index,
    const ncfg_qdisc_root_t *root, char *err, size_t err_size)
{
	ncfg_qdisc_tcmsg_t header;
	ncfg_buf_t attrs;
	ncfg_buf_t options;
	uint64_t bytes = 0;
	int built;

	if (!root || !root->kind || root->kind[0] == '\0') {
		ncfg_error_set(err, err_size, "a root qdisc needs a scheduler to be");
		return 0;
	}
	if (strlen(root->kind) >= NCFG_QDISC_KIND_MAX) {
		ncfg_error_set(err, err_size,
		    "`%s` is longer than the %u bytes the kernel holds a scheduler's name in",
		    root->kind, (unsigned)NCFG_QDISC_KIND_MAX);
		return 0;
	}
	memset(&header, 0, sizeof(header));
	if (!index_field(index, &header.index, err, err_size)) {
		return 0;
	}
	if (root->has_bandwidth && !ncfg_qdisc_shapes(root->kind)) {
		/*
		 * **A rate under the wrong scheduler is accepted and misread, not
		 * refused.** `TCA_OPTIONS` is not self-describing: attribute 2 is
		 * `TCA_CAKE_BASE_RATE64` under `cake` and `TCA_FQ_CODEL_LIMIT`
		 * under fq_codel, whose policy entry is a `u32` -- and nested
		 * attribute validation is liberal, so it takes the eight bytes and
		 * reads the low half of the rate as a packet limit. The result is
		 * a scheduler with a nonsense queue length and no shaping at all.
		 *
		 * The compiler refuses this too, and it is checked again here
		 * because this is where the bytes are made: a caller that builds a
		 * request without going through the compiler -- a test, a repair
		 * path, the next module -- would otherwise reach the kernel with
		 * it.
		 */
		ncfg_error_set(err, err_size,
		    "`%s` cannot shape to a rate; only `cake` shapes without a class tree",
		    root->kind);
		return 0;
	}
	if (root->ingress && !root->has_bandwidth) {
		/* Ingress mode changes how the shaper accounts for what it drops,
		 * so it means nothing without a rate to shape to -- and it travels
		 * inside the options, which only exist where there is one. Dropping
		 * it silently is how a caller ends up believing an ingress shaper
		 * was installed. */
		ncfg_error_set(err, err_size,
		    "an ingress shaper with no rate has nothing to shape to");
		return 0;
	}
	if (root->has_bandwidth &&
	    !ncfg_qdisc_rate_bytes(root->bandwidth_bits, &bytes, err, err_size)) {
		return 0;
	}

	header.parent = TC_H_ROOT;
	/* netcfgd's mark (0137). The kernel assigns a handle when none is given,
	 * which is what this used to let it do -- and an assigned handle says
	 * nothing about who asked for the qdisc, so a qdisc netcfgd had set and
	 * could not prove it set was a one-way door. */
	header.handle = NCFG_QDISC_HANDLE;

	ncfg_buf_init(&attrs, 0);
	ncfg_wire_attr_put_str(&attrs, TCA_KIND, root->kind);
	if (root->has_bandwidth) {
		ncfg_buf_init(&options, 0);
		put_u64(&options, TCA_CAKE_BASE_RATE64, bytes);
		if (root->ingress) {
			ncfg_wire_attr_put_u32(&options, TCA_CAKE_INGRESS, 1);
		}
		ncfg_wire_attr_put_nested(&attrs, TCA_OPTIONS, &options);
		ncfg_buf_free(&options);
	}
	built = build(out, RTM_NEWQDISC,
	    (uint16_t)(NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE), seq, &header,
	    &attrs, err, err_size);
	ncfg_buf_free(&attrs);
	return built;
}

int ncfg_qdisc_build_delete_root(ncfg_buf_t *out, uint32_t seq, uint32_t index,
    char *err, size_t err_size)
{
	ncfg_qdisc_tcmsg_t header;

	memset(&header, 0, sizeof(header));
	if (!index_field(index, &header.index, err, err_size)) {
		return 0;
	}
	header.parent = TC_H_ROOT;
	/* Handle zero: whatever root is there goes, not only one wearing
	 * netcfgd's mark. 0137 is explicit that an unmarked qdisc is ambiguous
	 * rather than foreign -- it may be one an older netcfgd installed before
	 * it stamped handles -- and naming the handle here would make netcfgd
	 * unable to reset a qdisc it had set itself. Which interfaces this may be
	 * called for is decided upstream, where ownership is known. */
	return build(out, RTM_DELQDISC, (uint16_t)(NLM_F_REQUEST | NLM_F_ACK), seq, &header,
	    NULL, err, err_size);
}

int ncfg_qdisc_build_add_ingress(ncfg_buf_t *out, uint32_t seq, uint32_t index,
    char *err, size_t err_size)
{
	ncfg_qdisc_tcmsg_t header;
	ncfg_buf_t attrs;
	int built;

	memset(&header, 0, sizeof(header));
	if (!index_field(index, &header.index, err, err_size)) {
		return 0;
	}
	header.handle = INGRESS_HANDLE;
	header.parent = TC_H_INGRESS;

	ncfg_buf_init(&attrs, 0);
	ncfg_wire_attr_put_str(&attrs, TCA_KIND, "ingress");
	/* `NLM_F_EXCL` rather than a replace: the ingress qdisc is a fixed
	 * singleton with no parameters, so one that is already there is already
	 * correct and `EEXIST` is the success case. Replacing it would take every
	 * filter hanging off it with it, including somebody else's. */
	built = build(out, RTM_NEWQDISC,
	    (uint16_t)(NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL), seq, &header,
	    &attrs, err, err_size);
	ncfg_buf_free(&attrs);
	return built;
}

int ncfg_qdisc_build_delete_ingress(ncfg_buf_t *out, uint32_t seq, uint32_t index,
    char *err, size_t err_size)
{
	ncfg_qdisc_tcmsg_t header;

	memset(&header, 0, sizeof(header));
	if (!index_field(index, &header.index, err, err_size)) {
		return 0;
	}
	header.handle = INGRESS_HANDLE;
	header.parent = TC_H_INGRESS;
	return build(out, RTM_DELQDISC, (uint16_t)(NLM_F_REQUEST | NLM_F_ACK), seq, &header,
	    NULL, err, err_size);
}

int ncfg_qdisc_build_redirect(ncfg_buf_t *out, uint32_t seq, uint32_t index, uint32_t target,
    char *err, size_t err_size)
{
	ncfg_qdisc_tcmsg_t header;
	struct tc_mirred mirred;
	ncfg_buf_t parameters;
	ncfg_buf_t action;
	ncfg_buf_t actions;
	ncfg_buf_t options;
	ncfg_buf_t attrs;
	int built;

	memset(&header, 0, sizeof(header));
	if (!index_field(index, &header.index, err, err_size)) {
		return 0;
	}
	if (target == 0 || target > 0x7fffffffu) {
		ncfg_error_set(err, err_size,
		    "%u is not an interface a redirect can land on", target);
		return 0;
	}
	if (target == index) {
		/* Everything arriving here would be sent back out of here, and the
		 * only thing stopping it is the kernel's recursion limit. The `ifb`
		 * this redirect exists for is always a different device. */
		ncfg_error_set(err, err_size,
		    "a redirect from interface %u onto itself is a loop", index);
		return 0;
	}
	header.parent = INGRESS_HANDLE;
	/*
	 * Priority in the top half, protocol in the bottom, and the protocol is
	 * **big-endian**: `tcm_info`'s low half is a `__be16`. The Rust writes
	 * the swapped constant 0x0300 directly, which is correct on x86 and
	 * installs a filter for protocol 0x0300 -- no protocol at all -- on a
	 * big-endian machine, where nothing would ever notice. `htons` is the
	 * same bytes here and the right ones there.
	 *
	 * `ETH_P_ALL` is the point: this has to see ARP and IPv6 as well as
	 * IPv4, and a filter installed for one protocol silently passes the rest
	 * unshaped.
	 */
	header.info = (FILTER_PRIORITY << 16) | (uint32_t)htons(ETH_P_ALL);
	/* netcfgd's mark (0137), in the handle and not in the priority, which
	 * has to stay 1. */
	header.handle = NCFG_QDISC_FILTER_HANDLE;

	memset(&mirred, 0, sizeof(mirred));
	/* What happens to the original packet: stolen, because it has been sent
	 * somewhere else. A mirror would copy it and leave the original to arrive
	 * here unshaped as well, which is the whole failure this redirect exists
	 * to avoid. */
	mirred.action = TC_ACT_STOLEN;
	mirred.eaction = TCA_EGRESS_REDIR;
	mirred.ifindex = target;

	ncfg_buf_init(&parameters, 0);
	ncfg_wire_attr_put(&parameters, TCA_MIRRED_PARMS, &mirred, sizeof(mirred));

	ncfg_buf_init(&action, 0);
	ncfg_wire_attr_put_str(&action, TCA_ACT_KIND, "mirred");
	ncfg_wire_attr_put_nested(&action, TCA_ACT_OPTIONS, &parameters);

	ncfg_buf_init(&actions, 0);
	ncfg_wire_attr_put_nested(&actions, ACTION_LIST_FIRST, &action);

	ncfg_buf_init(&options, 0);
	ncfg_wire_attr_put_nested(&options, TCA_MATCHALL_ACT, &actions);

	ncfg_buf_init(&attrs, 0);
	/* `matchall` and one action, which is the whole of the filter machinery
	 * netcfgd generates. It carries no policy: it matches every packet
	 * unconditionally, and the only configurable thing about it is which
	 * device the traffic lands on -- which is what keeps it inside 0023. */
	ncfg_wire_attr_put_str(&attrs, TCA_KIND, "matchall");
	ncfg_wire_attr_put_nested(&attrs, TCA_OPTIONS, &options);

	built = build(out, RTM_NEWTFILTER,
	    (uint16_t)(NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE), seq, &header,
	    &attrs, err, err_size);

	ncfg_buf_free(&attrs);
	ncfg_buf_free(&options);
	ncfg_buf_free(&actions);
	ncfg_buf_free(&action);
	ncfg_buf_free(&parameters);
	return built;
}

int ncfg_qdisc_build_filter_dump(ncfg_buf_t *out, uint32_t seq, uint32_t index,
    char *err, size_t err_size)
{
	ncfg_qdisc_tcmsg_t header;

	memset(&header, 0, sizeof(header));
	/* A zero index is refused rather than sent. `RTM_GETTFILTER` resolves the
	 * ifindex in the request and returns an *empty dump* for one it cannot
	 * find, so a zero index quietly succeeds and reports nothing -- which
	 * looks exactly like "no redirects are installed", and is a plan that
	 * reinstalls one on every apply. `index_field` is what refuses it. */
	if (!index_field(index, &header.index, err, err_size)) {
		return 0;
	}
	header.parent = INGRESS_HANDLE;
	return build(out, RTM_GETTFILTER, (uint16_t)(NLM_F_REQUEST | NLM_F_DUMP), seq, &header,
	    NULL, err, err_size);
}

/* ------------------------------------------------------------------------ *
 * Reading replies
 * ------------------------------------------------------------------------ */

/* The shaped rate out of a `cake` options blob, in bits per second. */
static int cake_options(const ncfg_wire_attr_t *options, ncfg_qdisc_record_t *record,
    char *err, size_t err_size)
{
	ncfg_wire_attrs_t area;
	ncfg_wire_attr_t attr;
	uint64_t bytes = 0;
	uint32_t ingress = 0;

	ncfg_wire_attrs_start(&area, options->value, options->length);
	if (ncfg_wire_attrs_find(&area, TCA_CAKE_BASE_RATE64, &attr, NULL, 0) == NCFG_WIRE_OK) {
		if (!attr_u64(&attr, &bytes, err, err_size)) {
			return 0;
		}
		/* Zero is the kernel saying "not shaping", not a rate of zero --
		 * the same asymmetry `ncfg_qdisc_rate_bytes` refuses to write. */
		if (bytes > 0) {
			if (!ncfg_qdisc_rate_bits(bytes, &record->bandwidth_bits, err,
			    err_size)) {
				return 0;
			}
			record->has_bandwidth = 1;
		}
	}
	if (ncfg_wire_attrs_find(&area, TCA_CAKE_INGRESS, &attr, NULL, 0) == NCFG_WIRE_OK) {
		if (!ncfg_wire_attr_u32(&attr, &ingress, err, err_size)) {
			return 0;
		}
		record->ingress = ingress != 0;
	}
	return 1;
}

int ncfg_qdisc_entry_read(const void *payload, size_t length, ncfg_qdisc_entry_t *what,
    ncfg_qdisc_record_t *record, char *err, size_t err_size)
{
	ncfg_qdisc_tcmsg_t header;
	ncfg_wire_attrs_t area;
	ncfg_wire_attr_t options;

	if (!what || !record) {
		ncfg_error_set(err, err_size, "a qdisc entry needs somewhere to go");
		return 0;
	}
	*what = NCFG_QDISC_ENTRY_OTHER;
	memset(record, 0, sizeof(*record));
	if (!ncfg_qdisc_tcmsg_decode(payload, length, &header, err, err_size)) {
		return 0;
	}
	if (header.index < 0) {
		/* The Rust folds this to interface zero, which is a record about an
		 * interface that does not exist rather than a message thrown away. */
		ncfg_error_set(err, err_size,
		    "a qdisc on interface %ld, which is not an interface",
		    (long)header.index);
		return 0;
	}
	record->index = (uint32_t)header.index;

	/*
	 * `tcm_parent` is what says which of the three this is. The dump returns
	 * every qdisc on the machine, including the ingress hook and the children
	 * of any class tree somebody else set up; only the root is in 0023's
	 * scope, and the hooks are worth knowing because they are where the
	 * filter dump has to be aimed.
	 */
	if (header.parent == TC_H_INGRESS) {
		*what = NCFG_QDISC_ENTRY_INGRESS;
		return 1;
	}
	if (header.parent != TC_H_ROOT) {
		return 1;
	}

	if (!payload_attrs(payload, length, &area, err, err_size)) {
		return 0;
	}
	if (!find_string(&area, TCA_KIND, record->kind, sizeof(record->kind), err, err_size)) {
		ncfg_error_set(err, err_size, "a root qdisc with no scheduler name");
		return 0;
	}
	record->handle = header.handle;
	*what = NCFG_QDISC_ENTRY_ROOT;

	/*
	 * **The options are read only where the scheduler is `cake`.**
	 *
	 * `TCA_OPTIONS` is not self-describing: the same attribute number means
	 * something different under every kind, so reading fq_codel's options
	 * with cake's numbering yields a plausible-looking integer that is not a
	 * rate. The Rust's comment says exactly this and its code does not do it
	 * -- it reads attribute 2 out of any scheduler's options and is saved
	 * only by requiring eight bytes, which is a length check standing in for
	 * a type check. Here the kind is the gate.
	 */
	if (!ncfg_qdisc_shapes(record->kind)) {
		return 1;
	}
	if (ncfg_wire_attrs_find(&area, TCA_OPTIONS, &options, NULL, 0) != NCFG_WIRE_OK) {
		return 1;
	}
	return cake_options(&options, record, err, err_size);
}

/* The target of one action-list element, if it is a `mirred` redirect. */
static int mirred_target(const ncfg_wire_attr_t *element, uint32_t *out,
    char *err, size_t err_size)
{
	ncfg_wire_attrs_t action;
	ncfg_wire_attrs_t parameters;
	ncfg_wire_attr_t attr;
	char kind[NCFG_QDISC_KIND_MAX];

	ncfg_wire_attrs_start(&action, element->value, element->length);
	if (!find_string(&action, TCA_ACT_KIND, kind, sizeof(kind), NULL, 0)) {
		return 0;
	}
	if (strcmp(kind, "mirred") != 0) {
		return 0;
	}
	if (ncfg_wire_attrs_find(&action, TCA_ACT_OPTIONS, &attr, NULL, 0) != NCFG_WIRE_OK) {
		ncfg_error_set(err, err_size, "a `mirred` action with no parameters");
		return 0;
	}
	ncfg_wire_attrs_start(&parameters, attr.value, attr.length);
	if (ncfg_wire_attrs_find(&parameters, TCA_MIRRED_PARMS, &attr, NULL, 0) != NCFG_WIRE_OK) {
		ncfg_error_set(err, err_size, "a `mirred` action with no `tc_mirred`");
		return 0;
	}
	if (attr.length < sizeof(struct tc_mirred)) {
		ncfg_error_set(err, err_size,
		    "a `tc_mirred` is %zu bytes and this one has %zu",
		    sizeof(struct tc_mirred), attr.length);
		return 0;
	}
	/* The last of the seven words, read by the field's own offset rather
	 * than by a hand-counted 24. */
	memcpy(out, attr.value + offsetof(struct tc_mirred, ifindex), sizeof(*out));
	return 1;
}

int ncfg_qdisc_redirect_read(const void *payload, size_t length, ncfg_qdisc_redirect_t *out,
    char *err, size_t err_size)
{
	ncfg_qdisc_tcmsg_t header;
	ncfg_wire_attrs_t area;
	ncfg_wire_attrs_t options;
	ncfg_wire_attrs_t actions;
	ncfg_wire_attr_t attr;
	ncfg_wire_attr_t element;
	char kind[NCFG_QDISC_KIND_MAX];

	if (!out) {
		ncfg_error_set(err, err_size, "a redirect needs somewhere to go");
		return 0;
	}
	memset(out, 0, sizeof(*out));
	if (!ncfg_qdisc_tcmsg_decode(payload, length, &header, err, err_size)) {
		return 0;
	}
	if (header.parent != INGRESS_HANDLE) {
		ncfg_error_set(err, err_size, "a filter that does not hang off the ingress hook");
		return 0;
	}
	/* Whose filter this is. netcfgd stamps its own handle (0137); anything
	 * else is a redirect somebody else installed, which is reported and never
	 * cleared. */
	out->ours = header.handle == NCFG_QDISC_FILTER_HANDLE;

	if (!payload_attrs(payload, length, &area, err, err_size)) {
		return 0;
	}
	if (!find_string(&area, TCA_KIND, kind, sizeof(kind), NULL, 0) ||
	    strcmp(kind, "matchall") != 0) {
		/* Anything else is ignored rather than guessed at, for the same
		 * reason the NAT reader ignores a rule that is not the exact shape
		 * netcfgd writes: a `u32` classifier somebody added by hand is not
		 * netcfgd's, and reporting it as one would produce a plan that
		 * removed it. */
		ncfg_error_set(err, err_size, "a filter that is not a `matchall`");
		return 0;
	}
	if (ncfg_wire_attrs_find(&area, TCA_OPTIONS, &attr, NULL, 0) != NCFG_WIRE_OK) {
		ncfg_error_set(err, err_size, "a `matchall` filter with no options");
		return 0;
	}
	ncfg_wire_attrs_start(&options, attr.value, attr.length);
	if (ncfg_wire_attrs_find(&options, TCA_MATCHALL_ACT, &attr, NULL, 0) != NCFG_WIRE_OK) {
		/* A classifier with no action matches every packet and does nothing
		 * to it. Calling that a redirect would report traffic landing
		 * somewhere it never goes. */
		ncfg_error_set(err, err_size, "a `matchall` filter with no action");
		return 0;
	}
	ncfg_wire_attrs_start(&actions, attr.value, attr.length);
	while (ncfg_wire_attrs_next(&actions, &element, err, err_size) == NCFG_WIRE_OK) {
		if (mirred_target(&element, &out->target, err, err_size)) {
			return 1;
		}
	}
	ncfg_error_set(err, err_size, "a `matchall` filter with no `mirred` action");
	return 0;
}
