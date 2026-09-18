/*
 * qdisc_test.c -- traffic control, against bytes rather than against a kernel.
 *
 * WHY THIS EXISTS
 *   Everything here runs with no socket, no privileges and no interface, which
 *   is what makes this layer reviewable at all -- and it matters more here than
 *   almost anywhere else in the port, because the thing under test attaches
 *   shapers to somebody's uplink. Nothing below sends a byte.
 *
 *   Every assertion about a built message is made by **walking the bytes back
 *   with the wire layer**, never by comparing against a blob written out by
 *   hand. A hand-written blob is a second encoder with no tests of its own, and
 *   the first time the two disagree it is the test that is believed.
 *
 * WHAT IS ACTUALLY AT STAKE
 *   The arithmetic. `tc` takes `bandwidth 100mbit`, the document stores bits,
 *   and `TCA_CAKE_BASE_RATE64` is bytes -- so the whole module turns on one
 *   division by eight, and a rate sent in the wrong unit is accepted by the
 *   kernel and shapes at an eighth of what was asked for. That looks like a
 *   slow line rather than a bug, which is why it gets the boundaries below and
 *   not just a round trip.
 */
#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/qdisc.h"
#include "ncfg/wire.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <linux/pkt_sched.h>
#include <linux/tc_act/tc_mirred.h>

static int failures;

static void check(int condition, const char *what)
{
	printf("%-70s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

/* See wire_test.c: a short read tested as a prefix of a longer buffer is not
 * tested at all, because an overread lands inside the same allocation and ASan
 * has nothing to say. This puts the end of the input at the end of a malloc. */
static uint8_t *exact_copy(const void *bytes, size_t length)
{
	uint8_t *copy;

	if (!bytes || length == 0) {
		return NULL;
	}
	copy = malloc(length);
	if (!copy) {
		return NULL;
	}
	memcpy(copy, bytes, length);
	return copy;
}

/* The first message of a built request, which is where every assertion about
 * one starts. */
static int first_message(const ncfg_buf_t *buf, ncfg_wire_message_t *out)
{
	ncfg_wire_messages_t walk;

	ncfg_wire_messages_start(&walk, buf->data, buf->length);
	return ncfg_wire_messages_next(&walk, out, NULL, 0) == NCFG_WIRE_OK;
}

/* The attribute area of a tc message. */
static int tc_attrs(const ncfg_wire_message_t *message, ncfg_wire_attrs_t *out)
{
	return ncfg_wire_message_attrs(message, NCFG_QDISC_TCMSG_LEN, out, NULL, 0);
}

static int find(const ncfg_wire_attrs_t *area, uint16_t kind, ncfg_wire_attr_t *out)
{
	return ncfg_wire_attrs_find(area, kind, out, NULL, 0) == NCFG_WIRE_OK;
}

/* An attribute's value read as another attribute area, which is what a nest
 * is. */
static void nested(const ncfg_wire_attr_t *attr, ncfg_wire_attrs_t *out)
{
	ncfg_wire_attrs_start(out, attr->value, attr->length);
}

/* A string attribute, or "" where it is absent. */
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

/* A `u64` attribute value, native order, which is how the kernel carries a
 * rate. */
static int u64_of(const ncfg_wire_attrs_t *area, uint16_t kind, uint64_t *out)
{
	ncfg_wire_attr_t attr;

	if (!find(area, kind, &attr) || attr.length < sizeof(*out)) {
		return 0;
	}
	memcpy(out, attr.value, sizeof(*out));
	return 1;
}

/* A dump payload: a `tcmsg` and its attributes, with no netlink header, which
 * is what the socket layer hands a reader. */
static void qdisc_payload(ncfg_buf_t *out, uint8_t family, int32_t index, uint32_t handle,
    uint32_t parent, const ncfg_buf_t *attrs)
{
	ncfg_qdisc_tcmsg_t header;

	memset(&header, 0, sizeof(header));
	header.family = family;
	header.index = index;
	header.handle = handle;
	header.parent = parent;
	ncfg_qdisc_tcmsg_encode(&header, out);
	if (attrs && attrs->length) {
		ncfg_buf_add(out, attrs->data, attrs->length);
	}
}

/* A root `cake` dump entry carrying a rate in the kernel's own unit. */
static void cake_payload(ncfg_buf_t *out, const char *kind, uint64_t rate_bytes, int ingress)
{
	ncfg_buf_t attrs;
	ncfg_buf_t options;

	ncfg_buf_init(&attrs, 0);
	ncfg_buf_init(&options, 0);
	ncfg_wire_attr_put_str(&attrs, TCA_KIND, kind);
	ncfg_wire_attr_put(&options, TCA_CAKE_BASE_RATE64, &rate_bytes, sizeof(rate_bytes));
	if (ingress) {
		ncfg_wire_attr_put_u32(&options, TCA_CAKE_INGRESS, 1);
	}
	ncfg_wire_attr_put_nested(&attrs, TCA_OPTIONS, &options);
	qdisc_payload(out, 0, 7, NCFG_QDISC_HANDLE, TC_H_ROOT, &attrs);
	ncfg_buf_free(&options);
	ncfg_buf_free(&attrs);
}

int main(void)
{
	char err[NCFG_ERROR_MAX];
	char text[64];

	/*
	 * **The two handles, held to the numbers decision 0137 fixed.**
	 *
	 * These are duplicated from the model rather than depended on, because
	 * this module must stay free of anything but libc and the kernel -- and a
	 * duplicate that drifts means netcfgd stamps one handle and looks for
	 * another, at which point every qdisc it installs becomes foreign to it
	 * and it can never reset one again. The Rust holds its copy to the
	 * model's with a test in `netcfgd-observe`; this holds the C copy to the
	 * same two numbers.
	 */
	{
		check(NCFG_QDISC_HANDLE == (110u << 16),
		    "the root qdisc wears handle 6e:, which is 110 in the major half");
		check(NCFG_QDISC_FILTER_HANDLE == 110u,
		    "and the redirect filter wears handle 110 (0137)");
	}

	/*
	 * **The factor of eight, which is the defect this module's comments are
	 * mostly about.**
	 *
	 * `tc` is asked for `100mbit`, the document holds 100,000,000 bits, and
	 * the kernel's field is bytes per second. A port that passed the bits
	 * through would be accepted by the kernel and would shape the line at
	 * 12.5 Mbit -- one eighth -- which nothing reports and which reads as a
	 * slow uplink. So the built message is opened and the number inside it is
	 * read, and the wrong answer is named as well as the right one.
	 */
	{
		ncfg_qdisc_root_t root = { "cake", 100000000u, 1, 0 };
		ncfg_buf_t request;
		ncfg_wire_message_t message;
		ncfg_wire_attrs_t area;
		ncfg_wire_attrs_t options;
		ncfg_wire_attr_t attr;
		uint64_t rate = 0;

		ncfg_buf_init(&request, 0);
		check(ncfg_qdisc_build_set_root(&request, 1, 7, &root, err, sizeof(err)),
		    "a 100mbit cake root builds");
		check(first_message(&request, &message) && tc_attrs(&message, &area),
		    "and walks back as one message with an attribute area");
		check(strcmp(text_of(&area, TCA_KIND, text, sizeof(text)), "cake") == 0,
		    "carrying the scheduler's name");
		check(find(&area, TCA_OPTIONS, &attr), "and its options");
		nested(&attr, &options);
		check(u64_of(&options, TCA_CAKE_BASE_RATE64, &rate),
		    "with a 64-bit base rate inside them");
		check(rate == 12500000u,
		    "which is 12,500,000 -- the bits divided by eight, as bytes per second");
		check(rate != 100000000u,
		    "and not the bits themselves, which would shape the line at an eighth");
		ncfg_buf_free(&request);
	}

	/*
	 * The boundaries of that division, which is where it was got wrong.
	 *
	 * Both roundings are silent and both fail in the dangerous direction, so
	 * neither is allowed to happen: below eight bits a rate truncates to
	 * zero, and zero in `TCA_CAKE_BASE_RATE64` means *no shaper at all* --
	 * the opposite of what was asked, and `tc qdisc show` prints no rate for
	 * either. The document can say `bandwidth = "12"`, so these reach the
	 * conversion rather than being rounded off upstream.
	 */
	{
		uint64_t bytes = 0;
		uint64_t bits = 0;

		check(ncfg_qdisc_rate_bytes(8, &bytes, err, sizeof(err)) && bytes == 1,
		    "eight bits per second is one byte per second, the finest rate there is");
		check(!ncfg_qdisc_rate_bytes(1, &bytes, err, sizeof(err)),
		    "one bit per second is refused: rounded down it is an unshaped link");
		check(!ncfg_qdisc_rate_bytes(12, &bytes, err, sizeof(err)),
		    "and so is 12, which is not a whole number of bytes per second");
		check(!ncfg_qdisc_rate_bytes(0, &bytes, err, sizeof(err)) &&
		    strstr(err, "would pass nothing") != NULL,
		    "a rate of zero is refused in the compiler's own words");
		check(ncfg_qdisc_rate_bytes(1000, &bytes, err, sizeof(err)) && bytes == 125,
		    "a kbit is 125 bytes, so every decimal rate the document takes converts");

		check(ncfg_qdisc_rate_bits(12500000u, &bits, err, sizeof(err)) &&
		    bits == 100000000u,
		    "and the inverse gives the operator's own number back");
		check(!ncfg_qdisc_rate_bits(UINT64_MAX / 8u + 1u, &bits, err, sizeof(err)),
		    "a byte rate with no answer in bits is refused, not wrapped");
		check(ncfg_qdisc_rate_bits(UINT64_MAX / 8u, &bits, err, sizeof(err)),
		    "one below that still converts");
	}

	/*
	 * **A rate under a scheduler that cannot shape is refused here as well as
	 * in the compiler.**
	 *
	 * `TCA_OPTIONS` is not self-describing: attribute 2 is the base rate
	 * under `cake` and `TCA_FQ_CODEL_LIMIT` under fq_codel, whose policy
	 * entry is a `u32` -- and nested validation is liberal, so the kernel
	 * takes the eight bytes and reads the low half of the rate as a packet
	 * limit. The result is a queue length of 12,500,000 packets and no
	 * shaping, reported by nothing. This is where the bytes are made, so this
	 * is where it is checked again.
	 */
	{
		ncfg_qdisc_root_t root = { "fq_codel", 100000000u, 1, 0 };
		ncfg_qdisc_root_t ingress_only = { "cake", 0, 0, 1 };
		ncfg_buf_t request;

		ncfg_buf_init(&request, 0);
		check(!ncfg_qdisc_build_set_root(&request, 1, 7, &root, err, sizeof(err)) &&
		    strstr(err, "cannot shape") != NULL,
		    "a rate on fq_codel is refused, and says which schedulers shape");
		check(!ncfg_qdisc_build_set_root(&request, 1, 7, &ingress_only, err, sizeof(err)),
		    "and an ingress shaper with no rate has nothing to shape to");
		check(ncfg_qdisc_shapes("cake") && !ncfg_qdisc_shapes("fq_codel") &&
		    !ncfg_qdisc_shapes(NULL),
		    "`cake` is the one scheduler that shapes without a class tree (0023)");
		ncfg_buf_free(&request);
	}

	/*
	 * The rest of what a `set_root` message says: the handle that makes it
	 * netcfgd's, the parent that makes it the root, and the flags that make
	 * it a replacement rather than a delete and an add -- the two-step
	 * version leaves the interface on the kernel default in between, which on
	 * a shaped uplink is a window where traffic is unshaped.
	 */
	{
		ncfg_qdisc_root_t root = { "cake", 50000000u, 1, 1 };
		ncfg_buf_t request;
		ncfg_wire_message_t message;
		ncfg_qdisc_tcmsg_t header;
		ncfg_wire_attrs_t area;
		ncfg_wire_attrs_t options;
		ncfg_wire_attr_t attr;
		uint32_t flag = 0;

		ncfg_buf_init(&request, 0);
		check(ncfg_qdisc_build_set_root(&request, 42, 7, &root, err, sizeof(err)) &&
		    first_message(&request, &message),
		    "an ingress cake root builds");
		check(message.header.kind == RTM_NEWQDISC && message.header.seq == 42,
		    "as an RTM_NEWQDISC with the sequence number it was given");
		check(message.header.flags ==
		    (NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE),
		    "replacing rather than deleting and adding, which would leave a gap");
		check(ncfg_qdisc_tcmsg_decode(message.payload, message.payload_length, &header,
		    NULL, 0), "with a tcmsg at the front");
		check(header.index == 7 && header.parent == TC_H_ROOT,
		    "naming the interface and the root");
		check(header.handle == NCFG_QDISC_HANDLE,
		    "and wearing netcfgd's handle, so reading it back says who asked (0137)");
		check(tc_attrs(&message, &area) && find(&area, TCA_OPTIONS, &attr),
		    "the options are there");
		nested(&attr, &options);
		check(find(&options, TCA_CAKE_INGRESS, &attr) &&
		    ncfg_wire_attr_u32(&attr, &flag, NULL, 0) && flag == 1,
		    "and say this shaper is metering traffic that has already arrived");
		ncfg_buf_free(&request);
	}

	/* And without `ingress`, the flag is absent rather than zero: a shaper
	 * told it is on the ingress path accounts for retransmissions, and one
	 * told nothing does not. */
	{
		ncfg_qdisc_root_t root = { "cake", 50000000u, 1, 0 };
		ncfg_buf_t request;
		ncfg_wire_message_t message;
		ncfg_wire_attrs_t area;
		ncfg_wire_attrs_t options;
		ncfg_wire_attr_t attr;

		ncfg_buf_init(&request, 0);
		check(ncfg_qdisc_build_set_root(&request, 1, 7, &root, err, sizeof(err)) &&
		    first_message(&request, &message) && tc_attrs(&message, &area) &&
		    find(&area, TCA_OPTIONS, &attr),
		    "an egress cake root builds with options");
		nested(&attr, &options);
		check(!find(&options, TCA_CAKE_INGRESS, &attr),
		    "and does not claim to be shaping on the way in");
		ncfg_buf_free(&request);
	}

	/*
	 * The delete names no handle, deliberately.
	 *
	 * 0137 is explicit that an unmarked qdisc is *ambiguous* rather than
	 * foreign -- it may be one an older netcfgd installed before it stamped
	 * handles -- so naming the handle here would make netcfgd unable to reset
	 * a qdisc it had set itself, on the day handles shipped.
	 */
	{
		ncfg_buf_t request;
		ncfg_wire_message_t message;
		ncfg_qdisc_tcmsg_t header;

		ncfg_buf_init(&request, 0);
		check(ncfg_qdisc_build_delete_root(&request, 1, 7, err, sizeof(err)) &&
		    first_message(&request, &message) &&
		    ncfg_qdisc_tcmsg_decode(message.payload, message.payload_length, &header,
		    NULL, 0),
		    "a root delete builds");
		check(message.header.kind == RTM_DELQDISC && header.parent == TC_H_ROOT,
		    "as an RTM_DELQDISC at the root");
		check(header.handle == 0,
		    "naming no handle, so an unmarked qdisc netcfgd set is still removable");
		ncfg_buf_free(&request);
	}

	/*
	 * The ingress qdisc: a fixed singleton at `ffff:` whose whole purpose is
	 * to give a classifier somewhere to live. `NLM_F_EXCL` rather than a
	 * replace, because replacing it would take every filter hanging off it --
	 * including somebody else's.
	 */
	{
		ncfg_buf_t request;
		ncfg_wire_message_t message;
		ncfg_qdisc_tcmsg_t header;
		ncfg_wire_attrs_t area;

		ncfg_buf_init(&request, 0);
		check(ncfg_qdisc_build_add_ingress(&request, 1, 7, err, sizeof(err)) &&
		    first_message(&request, &message) && tc_attrs(&message, &area) &&
		    ncfg_qdisc_tcmsg_decode(message.payload, message.payload_length, &header,
		    NULL, 0),
		    "an ingress qdisc builds");
		check(header.handle == 0xffff0000u && header.parent == TC_H_INGRESS,
		    "at handle ffff:0000 under the ingress parent");
		check(strcmp(text_of(&area, TCA_KIND, text, sizeof(text)), "ingress") == 0,
		    "and is spelled `ingress`");
		check((message.header.flags & NLM_F_EXCL) != 0,
		    "created exclusively, so one already there is left alone with EEXIST");
		ncfg_buf_free(&request);
	}

	/*
	 * **The redirect, which is four nests deep and the one place a hand-built
	 * blob would have been tempting.**
	 *
	 * `matchall` with one `mirred` action, and the action list is indexed
	 * from one with the index *as the attribute type*. Every layer below is
	 * opened with the wire layer, down to the `ifindex` in `struct
	 * tc_mirred`.
	 */
	{
		ncfg_buf_t request;
		ncfg_wire_message_t message;
		ncfg_qdisc_tcmsg_t header;
		ncfg_wire_attrs_t area;
		ncfg_wire_attrs_t options;
		ncfg_wire_attrs_t actions;
		ncfg_wire_attrs_t action;
		ncfg_wire_attrs_t parameters;
		ncfg_wire_attr_t attr;
		struct tc_mirred mirred;

		ncfg_buf_init(&request, 0);
		check(ncfg_qdisc_build_redirect(&request, 1, 7, 9, err, sizeof(err)) &&
		    first_message(&request, &message) && tc_attrs(&message, &area) &&
		    ncfg_qdisc_tcmsg_decode(message.payload, message.payload_length, &header,
		    NULL, 0),
		    "a redirect from interface 7 onto 9 builds");
		check(message.header.kind == RTM_NEWTFILTER, "as an RTM_NEWTFILTER");
		check(header.parent == 0xffff0000u,
		    "hanging off the ingress qdisc rather than off the root");
		check(header.handle == NCFG_QDISC_FILTER_HANDLE,
		    "wearing netcfgd's filter handle, which is where the mark goes (0137)");
		/*
		 * Priority in the top half, protocol in the bottom -- and the
		 * protocol half is a `__be16`. The Rust writes the swapped constant
		 * 0x0300 straight in, which is right on x86 and installs a filter
		 * for no protocol at all on a big-endian machine, where nothing
		 * would ever notice. `htons` is the same bytes here and the right
		 * ones there.
		 */
		check(header.info == ((1u << 16) | (uint32_t)htons(ETH_P_ALL)),
		    "at priority 1, for every protocol, with the protocol in network order");
		check(strcmp(text_of(&area, TCA_KIND, text, sizeof(text)), "matchall") == 0,
		    "classifying with `matchall`, which carries no policy at all");

		check(find(&area, TCA_OPTIONS, &attr), "the filter has options");
		nested(&attr, &options);
		check(find(&options, TCA_MATCHALL_ACT, &attr), "holding an action list");
		nested(&attr, &actions);
		check(ncfg_wire_attrs_next(&actions, &attr, NULL, 0) == NCFG_WIRE_OK &&
		    attr.kind == 1,
		    "whose first element is numbered one -- the index is the type");
		nested(&attr, &action);
		check(strcmp(text_of(&action, TCA_ACT_KIND, text, sizeof(text)), "mirred") == 0,
		    "and is a `mirred` action");
		check(find(&action, TCA_ACT_OPTIONS, &attr), "with parameters");
		nested(&attr, &parameters);
		check(find(&parameters, TCA_MIRRED_PARMS, &attr) &&
		    attr.length >= sizeof(mirred),
		    "carrying a whole struct tc_mirred");
		memcpy(&mirred, attr.value, sizeof(mirred));
		check(mirred.ifindex == 9u, "pointed at interface 9");
		check(mirred.eaction == TCA_EGRESS_REDIR,
		    "redirecting rather than mirroring, which would leave a copy arriving here");
		check(mirred.action == TC_ACT_STOLEN,
		    "and stealing the original, which is what a redirect does to it");
		ncfg_buf_free(&request);
	}

	/* The two redirects that are not redirects. */
	{
		ncfg_buf_t request;

		ncfg_buf_init(&request, 0);
		check(!ncfg_qdisc_build_redirect(&request, 1, 7, 7, err, sizeof(err)) &&
		    strstr(err, "loop") != NULL,
		    "a redirect from an interface onto itself is refused as the loop it is");
		check(!ncfg_qdisc_build_redirect(&request, 1, 7, 0, err, sizeof(err)),
		    "and so is one onto interface zero");
		ncfg_buf_free(&request);
	}

	/*
	 * **A filter dump with no interface is refused rather than sent.**
	 *
	 * `RTM_GETTFILTER` resolves the ifindex in the request and returns an
	 * *empty dump* for one it cannot find, so a request naming interface zero
	 * quietly succeeds and reports nothing at all. That looks exactly like
	 * "no redirects are installed", and the plan built from it reinstalls one
	 * on every apply, for ever.
	 */
	{
		ncfg_buf_t request;
		ncfg_wire_message_t message;
		ncfg_qdisc_tcmsg_t header;

		ncfg_buf_init(&request, 0);
		check(!ncfg_qdisc_build_filter_dump(&request, 1, 0, err, sizeof(err)),
		    "a filter dump naming no interface is refused, not quietly emptied");
		check(!ncfg_qdisc_build_delete_root(&request, 1, 0, err, sizeof(err)),
		    "and no per-interface request folds a bad index to zero");
		check(ncfg_qdisc_build_filter_dump(&request, 1, 7, err, sizeof(err)) &&
		    first_message(&request, &message) &&
		    ncfg_qdisc_tcmsg_decode(message.payload, message.payload_length, &header,
		    NULL, 0) && header.parent == 0xffff0000u,
		    "one naming an interface asks the ingress hook for its filters");
		ncfg_buf_free(&request);

		ncfg_buf_init(&request, 0);
		check(ncfg_qdisc_build_dump(&request, 1, err, sizeof(err)) &&
		    first_message(&request, &message) &&
		    (message.header.flags & NLM_F_DUMP) != 0 &&
		    message.header.kind == RTM_GETQDISC,
		    "the qdisc dump is the one request allowed to name no interface");
		ncfg_buf_free(&request);
	}

	/* A root record comes back with everything the operator wrote. */
	{
		ncfg_buf_t payload;
		ncfg_qdisc_entry_t what;
		ncfg_qdisc_record_t record;

		ncfg_buf_init(&payload, 0);
		cake_payload(&payload, "cake", 12500000u, 1);
		check(ncfg_qdisc_entry_read(payload.data, payload.length, &what, &record, err,
		    sizeof(err)) && what == NCFG_QDISC_ENTRY_ROOT,
		    "a root qdisc dump entry reads as a root");
		check(strcmp(record.kind, "cake") == 0 && record.index == 7,
		    "with its scheduler and its interface");
		check(record.handle == NCFG_QDISC_HANDLE,
		    "and the handle that says netcfgd installed it");
		check(record.has_bandwidth && record.bandwidth_bits == 100000000u,
		    "and the rate back in bits, which is the unit the operator wrote");
		check(record.ingress, "and the ingress flag");
		ncfg_buf_free(&payload);
	}

	/*
	 * **fq_codel's options are not read with cake's numbering.**
	 *
	 * `TCA_OPTIONS` is not self-describing, so attribute 2 means something
	 * different under every scheduler, and reading one kind's options with
	 * another's numbering yields a plausible integer that is not a rate. The
	 * Rust's comment says exactly this and its code does not do it: it reads
	 * attribute 2 out of any scheduler's options and is saved only by
	 * requiring eight bytes, which is a length check standing in for a type
	 * check. Here the kind is the gate, and this is the case that tells the
	 * two apart.
	 */
	{
		ncfg_buf_t payload;
		ncfg_qdisc_entry_t what;
		ncfg_qdisc_record_t record;

		ncfg_buf_init(&payload, 0);
		cake_payload(&payload, "fq_codel", 12500000u, 0);
		check(ncfg_qdisc_entry_read(payload.data, payload.length, &what, &record, err,
		    sizeof(err)) && what == NCFG_QDISC_ENTRY_ROOT,
		    "an fq_codel root with an eight-byte attribute 2 in its options reads");
		check(!record.has_bandwidth,
		    "and reports no rate, because only `cake`'s options are cake's");
		ncfg_buf_free(&payload);
	}

	/* A rate of zero in the dump is the kernel saying "not shaping", not a
	 * rate of zero -- the same asymmetry the encoder refuses to write. */
	{
		ncfg_buf_t payload;
		ncfg_qdisc_entry_t what;
		ncfg_qdisc_record_t record;

		ncfg_buf_init(&payload, 0);
		cake_payload(&payload, "cake", 0, 0);
		check(ncfg_qdisc_entry_read(payload.data, payload.length, &what, &record, err,
		    sizeof(err)) && !record.has_bandwidth,
		    "a base rate of zero is an unshaped cake, not a cake shaping to nothing");
		ncfg_buf_free(&payload);
	}

	/* And a rate the kernel could not have meant is refused rather than
	 * wrapped around into a small one. */
	{
		ncfg_buf_t payload;
		ncfg_qdisc_entry_t what;
		ncfg_qdisc_record_t record;

		ncfg_buf_init(&payload, 0);
		cake_payload(&payload, "cake", UINT64_MAX / 8u + 1u, 0);
		check(!ncfg_qdisc_entry_read(payload.data, payload.length, &what, &record, err,
		    sizeof(err)),
		    "a byte rate with no answer in bits is refused, not multiplied anyway");
		ncfg_buf_free(&payload);
	}

	/*
	 * The three kinds of dump entry, told apart by `tcm_parent`. The dump
	 * returns every qdisc on the machine, including the children of a class
	 * tree somebody else set up, and only the root is in 0023's scope -- but
	 * the ingress hooks are worth knowing, because they are where the filter
	 * dump has to be aimed.
	 */
	{
		ncfg_buf_t payload;
		ncfg_qdisc_entry_t what;
		ncfg_qdisc_record_t record;

		ncfg_buf_init(&payload, 0);
		qdisc_payload(&payload, 0, 3, 0xffff0000u, TC_H_INGRESS, NULL);
		check(ncfg_qdisc_entry_read(payload.data, payload.length, &what, &record, err,
		    sizeof(err)) && what == NCFG_QDISC_ENTRY_INGRESS && record.index == 3,
		    "an ingress hook is reported as one, with the interface it is on");
		ncfg_buf_free(&payload);

		ncfg_buf_init(&payload, 0);
		qdisc_payload(&payload, 0, 3, 0x00110001u, 0x00110000u, NULL);
		check(ncfg_qdisc_entry_read(payload.data, payload.length, &what, &record, err,
		    sizeof(err)) && what == NCFG_QDISC_ENTRY_OTHER,
		    "a child of somebody's class tree is neither, and is not read");
		ncfg_buf_free(&payload);
	}

	/* A truncated payload is a refusal with a sentence, never a partial
	 * answer. Copied to size so that a read past the end is a report rather
	 * than a byte of the same allocation. */
	{
		ncfg_buf_t payload;
		uint8_t *cut;
		ncfg_qdisc_entry_t what;
		ncfg_qdisc_record_t record;

		ncfg_buf_init(&payload, 0);
		cake_payload(&payload, "cake", 12500000u, 0);
		cut = exact_copy(payload.data, NCFG_QDISC_TCMSG_LEN - 1u);
		check(cut && !ncfg_qdisc_entry_read(cut, NCFG_QDISC_TCMSG_LEN - 1u, &what,
		    &record, err, sizeof(err)),
		    "a payload too short for a tcmsg is refused");
		free(cut);

		cut = exact_copy(payload.data, NCFG_QDISC_TCMSG_LEN);
		check(cut && !ncfg_qdisc_entry_read(cut, NCFG_QDISC_TCMSG_LEN, &what, &record,
		    err, sizeof(err)),
		    "and a root qdisc with no scheduler name is refused, not left blank");
		free(cut);
		ncfg_buf_free(&payload);
	}

	/* An interface index the kernel could not have meant is refused rather
	 * than folded to zero, which is what the Rust's `unwrap_or(0)` does --
	 * turning a record about one interface into a record about none. */
	{
		ncfg_buf_t payload;
		ncfg_qdisc_entry_t what;
		ncfg_qdisc_record_t record;

		ncfg_buf_init(&payload, 0);
		qdisc_payload(&payload, 0, -1, 0, TC_H_ROOT, NULL);
		check(!ncfg_qdisc_entry_read(payload.data, payload.length, &what, &record, err,
		    sizeof(err)),
		    "a negative interface index is refused rather than folded to zero");
		ncfg_buf_free(&payload);
	}

	/*
	 * The redirect reader, against the redirect writer: the round trip is the
	 * only honest check that the four nests are read at the depth they were
	 * written.
	 */
	{
		ncfg_buf_t request;
		ncfg_wire_message_t message;
		ncfg_qdisc_redirect_t redirect;

		ncfg_buf_init(&request, 0);
		check(ncfg_qdisc_build_redirect(&request, 1, 7, 9, err, sizeof(err)) &&
		    first_message(&request, &message) &&
		    ncfg_qdisc_redirect_read(message.payload, message.payload_length, &redirect,
		    err, sizeof(err)),
		    "a redirect netcfgd built reads back as a redirect");
		check(redirect.target == 9u, "onto the device it was pointed at");
		check(redirect.ours,
		    "and is recognised as netcfgd's by the handle it wears");
		ncfg_buf_free(&request);
	}

	/*
	 * And the three shapes that are not it. Each is ignored rather than
	 * guessed at, for the reason the NAT reader ignores a rule it did not
	 * write: a `u32` classifier somebody added by hand is not netcfgd's, and
	 * reporting it as one would produce a plan that removed it.
	 */
	{
		ncfg_buf_t payload;
		ncfg_buf_t attrs;
		ncfg_buf_t options;
		ncfg_buf_t actions;
		ncfg_qdisc_redirect_t redirect;

		ncfg_buf_init(&payload, 0);
		ncfg_buf_init(&attrs, 0);
		ncfg_wire_attr_put_str(&attrs, TCA_KIND, "u32");
		qdisc_payload(&payload, 0, 7, NCFG_QDISC_FILTER_HANDLE, 0xffff0000u, &attrs);
		check(!ncfg_qdisc_redirect_read(payload.data, payload.length, &redirect, err,
		    sizeof(err)) && strstr(err, "matchall") != NULL,
		    "a `u32` classifier is not a redirect netcfgd wrote");
		ncfg_buf_free(&attrs);
		ncfg_buf_free(&payload);

		ncfg_buf_init(&payload, 0);
		ncfg_buf_init(&attrs, 0);
		ncfg_buf_init(&options, 0);
		ncfg_buf_init(&actions, 0);
		ncfg_wire_attr_put_str(&attrs, TCA_KIND, "matchall");
		ncfg_wire_attr_put_nested(&options, TCA_MATCHALL_ACT, &actions);
		ncfg_wire_attr_put_nested(&attrs, TCA_OPTIONS, &options);
		qdisc_payload(&payload, 0, 7, NCFG_QDISC_FILTER_HANDLE, 0xffff0000u, &attrs);
		check(!ncfg_qdisc_redirect_read(payload.data, payload.length, &redirect, err,
		    sizeof(err)),
		    "a `matchall` with an empty action list matches traffic and does nothing");
		ncfg_buf_free(&actions);
		ncfg_buf_free(&options);
		ncfg_buf_free(&attrs);
		ncfg_buf_free(&payload);
	}

	/* A redirect somebody else installed is read and reported, and marked as
	 * not netcfgd's -- which is what stops a plan from clearing it. */
	{
		ncfg_buf_t request;
		ncfg_wire_message_t message;
		ncfg_buf_t forged;
		ncfg_qdisc_redirect_t redirect;
		uint32_t theirs = 0x1234u;

		ncfg_buf_init(&request, 0);
		check(ncfg_qdisc_build_redirect(&request, 1, 7, 9, err, sizeof(err)) &&
		    first_message(&request, &message), "a redirect builds");
		/* The same bytes with somebody else's handle in them, which is the
		 * only difference between netcfgd's redirect and anybody's. */
		ncfg_buf_init(&forged, 0);
		ncfg_buf_add(&forged, message.payload, message.payload_length);
		memcpy(forged.data + 8, &theirs, sizeof(theirs));
		check(ncfg_qdisc_redirect_read(forged.data, forged.length, &redirect, err,
		    sizeof(err)) && redirect.target == 9u && !redirect.ours,
		    "the same filter under another handle is reported and not claimed");
		ncfg_buf_free(&forged);
		ncfg_buf_free(&request);
	}

	if (failures) {
		printf("qdisc: %d check(s) failed\n", failures);
		return 1;
	}
	printf("qdisc: every check passed\n");
	return 0;
}
