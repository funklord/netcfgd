/*
 * collect_test.c -- the seven dumps, driven by datagrams this file wrote.
 *
 * WHY THERE IS NO KERNEL IN HERE
 *   This suite runs on the machine netcfgd configures, so a test that dumped
 *   the running kernel would assert against whatever that machine happened to
 *   be doing. Worse, it could not reach the cases that matter: a kernel will
 *   not truncate a message on request, will not claim a message is longer than
 *   the datagram carrying it, will not answer `ENOBUFS` in the middle of a
 *   dump, and will not grow one more interface than an observation holds.
 *   `ncfg_observe_exchange_replay` is the round with the send taken out, and
 *   the datagram source under it is `netlink.h`'s own seam.
 *
 * WHY THE FIXTURES COME FROM THE BUILDERS
 *   Every traffic-control fixture here is built by the request builder in
 *   `qdisc.h` and read back as though the kernel had sent it. That is not
 *   laziness: the kernel reports a qdisc and a filter in the same shape the
 *   request to install one carries, so a fixture assembled by hand is a second
 *   opinion about that shape, and the day the encoder changes the hand-written
 *   one goes on passing while the machine stops being read correctly.
 *
 * WHAT THE RECORDING EXCHANGE IS FOR
 *   It sits between the collector and the replay and keeps what each request
 *   was, which is how the order of the seven is asserted -- and how the two
 *   traffic-control requests are held, byte for byte, to what `qdisc.h` builds.
 *   `collect.c` takes those two apart to get at their bodies; this is the proof
 *   that taking them apart put back exactly what went in.
 */
#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/netlink.h"
#include "ncfg/observe.h"
#include "ncfg/observed.h"
#include "ncfg/qdisc.h"
#include "ncfg/rule.h"
#include "ncfg/wire.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The kernel headers `netlink.h` deliberately does not pull in: this file
 * builds the bytes a kernel would send. */
#include <linux/fib_rules.h>
#include <linux/if_bridge.h>

static int failures;

static void check(int condition, const char *what)
{
	printf("%-70s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

/* ------------------------------------------------------------------------ */
/* Building the bytes a kernel would send.                                  */
/* ------------------------------------------------------------------------ */

/* One complete message, appended to `out`. `body` and `attrs` may be NULL. */
static void append_message(ncfg_buf_t *out, uint16_t kind, uint32_t seq, const ncfg_buf_t *body,
    const ncfg_buf_t *attrs)
{
	ncfg_buf_t one;

	ncfg_buf_init(&one, 0);
	if (!ncfg_wire_build_request(&one, kind, 0, seq, body, attrs, NULL, 0)) {
		out->failed = 1;
	} else {
		ncfg_buf_add(out, one.data, one.length);
	}
	ncfg_buf_free(&one);
}

static void append_done(ncfg_buf_t *out)
{
	append_message(out, NLMSG_DONE, 0, NULL, NULL);
}

/* An `NLMSG_ERROR`: the negated errno, then the header of the request that
 * drew it, which is where the failure sentence learns what was refused. */
static void append_error(ncfg_buf_t *out, int32_t code, uint16_t refused)
{
	ncfg_buf_t         body;
	ncfg_wire_header_t original;
	uint32_t           bits;
	int32_t            negated = -code;

	ncfg_buf_init(&body, 0);
	memcpy(&bits, &negated, sizeof(bits));
	ncfg_buf_add(&body, &bits, sizeof(bits));
	memset(&original, 0, sizeof(original));
	original.len = NCFG_WIRE_NLMSG_HDR_LEN;
	original.kind = refused;
	ncfg_wire_header_encode(&original, &body);
	append_message(out, NLMSG_ERROR, 0, &body, NULL);
	ncfg_buf_free(&body);
}

static void append_link(ncfg_buf_t *out, int32_t index, const char *name, const char *altname)
{
	ncfg_buf_t body;
	ncfg_buf_t attrs;
	ncfg_buf_t props;
	ncfg_wire_ifinfo_t info;

	memset(&info, 0, sizeof(info));
	info.index = index;
	info.flags = NCFG_LINK_IFF_UP;
	ncfg_buf_init(&body, 0);
	ncfg_buf_init(&attrs, 0);
	ncfg_buf_init(&props, 0);
	ncfg_wire_ifinfo_encode(&info, &body);
	ncfg_wire_attr_put_str(&attrs, IFLA_IFNAME, name);
	ncfg_wire_attr_put_u32(&attrs, IFLA_MTU, 1500);
	if (altname) {
		ncfg_wire_attr_put_str(&props, IFLA_ALT_IFNAME, altname);
		ncfg_wire_attr_put_nested(&attrs, IFLA_PROP_LIST, &props);
	}
	append_message(out, RTM_NEWLINK, 0, &body, &attrs);
	ncfg_buf_free(&body);
	ncfg_buf_free(&attrs);
	ncfg_buf_free(&props);
}

static void append_address(ncfg_buf_t *out, uint32_t index, const char *text, uint8_t prefix,
    int tagged)
{
	ncfg_buf_t         body;
	ncfg_buf_t         attrs;
	ncfg_wire_ifaddr_t info;
	ncfg_wire_ip_t     local;

	if (!ncfg_wire_ip_parse(text, &local, NULL, 0)) {
		out->failed = 1;
		return;
	}
	memset(&info, 0, sizeof(info));
	/* `AF_INET` or `AF_INET6`, which is all `ncfg_wire_ip_parse` ever
	 * writes, so the narrowing is checked by construction. */
	info.family = (uint8_t)local.family;
	info.prefix_len = prefix;
	info.index = index;
	ncfg_buf_init(&body, 0);
	ncfg_buf_init(&attrs, 0);
	ncfg_wire_ifaddr_encode(&info, &body);
	ncfg_wire_attr_put_ip(&attrs, IFA_LOCAL, &local);
	if (tagged) {
		ncfg_wire_attr_put_u8(&attrs, IFA_PROTO, NCFG_WIRE_RTPROT_NETCFGD);
	}
	append_message(out, RTM_NEWADDR, 0, &body, &attrs);
	ncfg_buf_free(&body);
	ncfg_buf_free(&attrs);
}

/* A default route out of one interface. */
static void append_route(ncfg_buf_t *out, uint32_t index, const char *gateway)
{
	ncfg_buf_t        body;
	ncfg_buf_t        attrs;
	ncfg_wire_rtmsg_t route;
	ncfg_wire_ip_t    via;

	if (!ncfg_wire_ip_parse(gateway, &via, NULL, 0)) {
		out->failed = 1;
		return;
	}
	memset(&route, 0, sizeof(route));
	route.family = (uint8_t)via.family;
	route.table = RT_TABLE_MAIN;
	route.protocol = NCFG_WIRE_RTPROT_NETCFGD;
	route.kind = RTN_UNICAST;
	ncfg_buf_init(&body, 0);
	ncfg_buf_init(&attrs, 0);
	ncfg_wire_rtmsg_encode(&route, &body);
	ncfg_wire_attr_put_u32(&attrs, RTA_OIF, index);
	ncfg_wire_attr_put_ip(&attrs, RTA_GATEWAY, &via);
	append_message(out, RTM_NEWROUTE, 0, &body, &attrs);
	ncfg_buf_free(&body);
	ncfg_buf_free(&attrs);
}

/* One bridge port with one VLAN on it, which is what the `AF_BRIDGE` link dump
 * answers with. */
static void append_bridge_vlan(ncfg_buf_t *out, int32_t index, uint16_t vid)
{
	ncfg_buf_t              body;
	ncfg_buf_t              attrs;
	ncfg_buf_t              spec;
	ncfg_wire_ifinfo_t      info;
	struct bridge_vlan_info one;

	memset(&info, 0, sizeof(info));
	info.family = AF_BRIDGE;
	info.index = index;
	memset(&one, 0, sizeof(one));
	one.flags = BRIDGE_VLAN_INFO_PVID | BRIDGE_VLAN_INFO_UNTAGGED;
	one.vid = vid;
	ncfg_buf_init(&body, 0);
	ncfg_buf_init(&attrs, 0);
	ncfg_buf_init(&spec, 0);
	ncfg_wire_ifinfo_encode(&info, &body);
	ncfg_wire_attr_put(&spec, IFLA_BRIDGE_VLAN_INFO, &one, sizeof(one));
	ncfg_wire_attr_put_nested(&attrs, IFLA_AF_SPEC, &spec);
	append_message(out, RTM_NEWLINK, 0, &body, &attrs);
	ncfg_buf_free(&body);
	ncfg_buf_free(&attrs);
	ncfg_buf_free(&spec);
}

/* A policy routing rule: the twelve-byte header rule.h describes, and one
 * priority. Hand-built because nothing in this port encodes that header, and
 * the byte offsets are the ones `rule.h` warns are not `rtmsg`'s. */
static void append_rule(ncfg_buf_t *out, uint8_t family, uint8_t table, uint32_t priority)
{
	ncfg_buf_t body;
	ncfg_buf_t attrs;
	uint8_t    header[NCFG_RULE_HDR_LEN];

	memset(header, 0, sizeof(header));
	header[0] = family;
	header[4] = table;
	header[7] = FR_ACT_TO_TBL;
	ncfg_buf_init(&body, 0);
	ncfg_buf_init(&attrs, 0);
	ncfg_buf_add(&body, header, sizeof(header));
	ncfg_wire_attr_put_u32(&attrs, FRA_PRIORITY, priority);
	append_message(out, RTM_NEWRULE, 0, &body, &attrs);
	ncfg_buf_free(&body);
	ncfg_buf_free(&attrs);
}

/*
 * The payload of a message one of `qdisc.h`'s builders wrote, re-headed as a
 * dump reply.
 *
 * The kernel reports a qdisc and a filter in the shape the request to install
 * one carries, so this turns a builder into a fixture rather than writing a
 * second opinion about that shape by hand.
 */
static void append_built(ncfg_buf_t *out, uint16_t kind, const ncfg_buf_t *message)
{
	ncfg_wire_messages_t walk;
	ncfg_wire_message_t  parsed;
	ncfg_buf_t           body;

	ncfg_wire_messages_start(&walk, message->data, message->length);
	if (ncfg_wire_messages_next(&walk, &parsed, NULL, 0) != NCFG_WIRE_OK) {
		out->failed = 1;
		return;
	}
	ncfg_buf_init(&body, 0);
	ncfg_buf_add(&body, parsed.payload, parsed.payload_length);
	append_message(out, kind, 0, &body, NULL);
	ncfg_buf_free(&body);
}

static void append_qdisc_root(ncfg_buf_t *out, uint32_t index, const char *scheduler)
{
	ncfg_buf_t        message;
	ncfg_qdisc_root_t root;

	memset(&root, 0, sizeof(root));
	root.kind = scheduler;
	ncfg_buf_init(&message, 0);
	if (!ncfg_qdisc_build_set_root(&message, 1, index, &root, NULL, 0)) {
		out->failed = 1;
	} else {
		append_built(out, RTM_NEWQDISC, &message);
	}
	ncfg_buf_free(&message);
}

static void append_ingress_hook(ncfg_buf_t *out, uint32_t index)
{
	ncfg_buf_t message;

	ncfg_buf_init(&message, 0);
	if (!ncfg_qdisc_build_add_ingress(&message, 1, index, NULL, 0)) {
		out->failed = 1;
	} else {
		append_built(out, RTM_NEWQDISC, &message);
	}
	ncfg_buf_free(&message);
}

/*
 * One ingress redirect, wearing whichever handle the caller asks for.
 *
 * The handle is patched rather than parameterised because the builder only
 * ever writes netcfgd's own -- which is the point of the mark -- and a
 * redirect somebody else installed is exactly the case that must be reported
 * and never cleared.
 */
static void append_redirect(ncfg_buf_t *out, uint32_t index, uint32_t target, uint32_t handle)
{
	ncfg_buf_t           message;
	ncfg_buf_t           body;
	ncfg_buf_t           attrs;
	ncfg_wire_messages_t walk;
	ncfg_wire_message_t  parsed;
	ncfg_qdisc_tcmsg_t   header;

	ncfg_buf_init(&message, 0);
	ncfg_buf_init(&body, 0);
	ncfg_buf_init(&attrs, 0);
	if (!ncfg_qdisc_build_redirect(&message, 1, index, target, NULL, 0)) {
		out->failed = 1;
	} else {
		ncfg_wire_messages_start(&walk, message.data, message.length);
		if (ncfg_wire_messages_next(&walk, &parsed, NULL, 0) != NCFG_WIRE_OK ||
		    parsed.payload_length < NCFG_QDISC_TCMSG_LEN ||
		    !ncfg_qdisc_tcmsg_decode(parsed.payload, parsed.payload_length, &header, NULL,
		    0)) {
			out->failed = 1;
		} else {
			header.handle = handle;
			ncfg_qdisc_tcmsg_encode(&header, &body);
			ncfg_buf_add(&attrs, parsed.payload + NCFG_QDISC_TCMSG_LEN,
			    parsed.payload_length - NCFG_QDISC_TCMSG_LEN);
			append_message(out, RTM_NEWTFILTER, 0, &body, &attrs);
		}
	}
	ncfg_buf_free(&message);
	ncfg_buf_free(&body);
	ncfg_buf_free(&attrs);
}

/* ------------------------------------------------------------------------ */
/* The fake datagram source.                                                */
/* ------------------------------------------------------------------------ */

#define FAKE_MAX 24u

typedef struct {
	const uint8_t *bytes;
	size_t         length;
	/* Who sent it: 0 for the kernel, anything else for a process on this
	 * machine, which is a thing any local user can be. */
	uint32_t       from;
	/* -1 makes both the peek and the read fail with `code`, which is how a
	 * kernel answering `ENOBUFS` mid-dump is reached. */
	int            fails;
	int            code;
} datagram_t;

typedef struct {
	datagram_t datagrams[FAKE_MAX];
	size_t     count;
	size_t     at;
	size_t     reads;
	/* The errno once the queue is empty. A real socket answers a receive
	 * with no reply by timing out. */
	int        empty_code;
} script_t;

static ssize_t script_recv(void *context, void *bytes, size_t length, int peek, uint32_t *from)
{
	script_t         *script = context;
	const datagram_t *one;
	size_t            copy;

	/* Not the kernel until the queue says so, which is what the real source
	 * does on every path including the failing one. */
	*from = UINT32_MAX;
	if (script->at >= script->count) {
		errno = script->empty_code ? script->empty_code : EAGAIN;
		return -1;
	}
	one = &script->datagrams[script->at];
	if (one->fails) {
		if (!peek) {
			script->at++;
		}
		errno = one->code;
		return -1;
	}
	*from = one->from;
	copy = one->length < length ? one->length : length;
	if (copy) {
		memcpy(bytes, one->bytes, copy);
	}
	if (peek) {
		return (ssize_t)one->length;
	}
	script->reads++;
	script->at++;
	return (ssize_t)one->length;
}

static void queue_from(script_t *script, const ncfg_buf_t *buffer, uint32_t from)
{
	datagram_t *one;

	if (script->count >= FAKE_MAX) {
		return;
	}
	one = &script->datagrams[script->count];
	memset(one, 0, sizeof(*one));
	one->bytes = (const uint8_t *)buffer->data;
	one->length = buffer->length;
	one->from = from;
	script->count++;
}

static void queue(script_t *script, const ncfg_buf_t *buffer)
{
	queue_from(script, buffer, 0);
}

/* A receive that fails outright, which is what a kernel dropping messages on
 * an overflowing socket looks like from here. */
static void queue_failure(script_t *script, int code)
{
	datagram_t *one;

	if (script->count >= FAKE_MAX) {
		return;
	}
	one = &script->datagrams[script->count];
	memset(one, 0, sizeof(*one));
	one->fails = 1;
	one->code = code;
	script->count++;
}

/* ------------------------------------------------------------------------ */
/* The recording exchange.                                                  */
/* ------------------------------------------------------------------------ */

#define ASKED_MAX 16u

typedef struct {
	uint16_t   kind;
	uint16_t   flags;
	ncfg_buf_t body;
} asked_t;

typedef struct {
	ncfg_observe_replay_t replay;
	asked_t               asked[ASKED_MAX];
	size_t                count;
} recorder_t;

static int recording_exchange(void *context, uint16_t kind, uint16_t flags,
    const ncfg_buf_t *body, const ncfg_buf_t *attrs, ncfg_netlink_reply_t *out, char *err,
    size_t err_size)
{
	recorder_t *recorder = context;

	if (recorder->count < ASKED_MAX) {
		asked_t *one = &recorder->asked[recorder->count];

		one->kind = kind;
		one->flags = flags;
		ncfg_buf_init(&one->body, 0);
		if (body && body->length) {
			ncfg_buf_add(&one->body, body->data, body->length);
		}
		recorder->count++;
	}
	return ncfg_observe_exchange_replay(&recorder->replay, kind, flags, body, attrs, out, err,
	    err_size);
}

static void recorder_start(recorder_t *recorder, script_t *script)
{
	memset(recorder, 0, sizeof(*recorder));
	recorder->replay.recv = script_recv;
	recorder->replay.context = script;
}

static void recorder_free(recorder_t *recorder)
{
	size_t at;

	for (at = 0; at < recorder->count; at++) {
		ncfg_buf_free(&recorder->asked[at].body);
	}
	recorder->count = 0;
}

static void kernel_of(ncfg_observe_kernel_t *kernel, recorder_t *recorder, size_t max)
{
	memset(kernel, 0, sizeof(*kernel));
	kernel->exchange = recording_exchange;
	kernel->context = recorder;
	kernel->records_max = max;
}

/* Whether the body of the nth request is byte for byte what `message` carries
 * after its own netlink header. */
static int body_matches(const recorder_t *recorder, size_t nth, const ncfg_buf_t *message)
{
	ncfg_wire_messages_t walk;
	ncfg_wire_message_t  parsed;

	if (nth >= recorder->count) {
		return 0;
	}
	ncfg_wire_messages_start(&walk, message->data, message->length);
	if (ncfg_wire_messages_next(&walk, &parsed, NULL, 0) != NCFG_WIRE_OK) {
		return 0;
	}
	if (recorder->asked[nth].body.length != parsed.payload_length) {
		return 0;
	}
	return memcmp(recorder->asked[nth].body.data, parsed.payload, parsed.payload_length) == 0;
}

/* ------------------------------------------------------------------------ */
/* One machine, queued dump by dump.                                        */
/* ------------------------------------------------------------------------ */

/*
 * The seven buffers a round reads, plus one per ingress hook.
 *
 * Held together so that a case can change one of them and queue the rest
 * unchanged -- most of these cases are about exactly one dump going wrong.
 */
typedef struct {
	ncfg_buf_t links;
	ncfg_buf_t addresses;
	ncfg_buf_t routes;
	ncfg_buf_t bridge_vlans;
	ncfg_buf_t qdiscs;
	ncfg_buf_t filters;
	ncfg_buf_t rules;
} machine_t;

static void machine_init(machine_t *machine)
{
	memset(machine, 0, sizeof(*machine));
	ncfg_buf_init(&machine->links, 0);
	ncfg_buf_init(&machine->addresses, 0);
	ncfg_buf_init(&machine->routes, 0);
	ncfg_buf_init(&machine->bridge_vlans, 0);
	ncfg_buf_init(&machine->qdiscs, 0);
	ncfg_buf_init(&machine->filters, 0);
	ncfg_buf_init(&machine->rules, 0);
}

static void machine_free(machine_t *machine)
{
	ncfg_buf_free(&machine->links);
	ncfg_buf_free(&machine->addresses);
	ncfg_buf_free(&machine->routes);
	ncfg_buf_free(&machine->bridge_vlans);
	ncfg_buf_free(&machine->qdiscs);
	ncfg_buf_free(&machine->filters);
	ncfg_buf_free(&machine->rules);
}

/*
 * A machine with two links, two addresses, a route, a bridge VLAN, a root
 * qdisc, an ingress hook and the redirect hanging off it, and one rule.
 *
 * `eth0` wears netcfgd's alternative name and carries the tagged address, so
 * the ownership half of an observation has something to answer about.
 */
static void machine_fill(machine_t *machine)
{
	append_link(&machine->links, 2, "eth0", NCFG_OBSERVE_ALTNAME_PREFIX "eth0");
	append_link(&machine->links, 3, "br0", NULL);
	append_done(&machine->links);

	append_address(&machine->addresses, 2, "192.168.1.10", 24, 1);
	append_address(&machine->addresses, 3, "10.0.0.1", 8, 0);
	append_done(&machine->addresses);

	append_route(&machine->routes, 2, "192.168.1.1");
	append_done(&machine->routes);

	/* Reported highest first, so that the order asserted of them is the
	 * sort's doing rather than the order the kernel sent. */
	append_bridge_vlan(&machine->bridge_vlans, 3, 7);
	append_bridge_vlan(&machine->bridge_vlans, 3, 4);
	append_done(&machine->bridge_vlans);

	append_qdisc_root(&machine->qdiscs, 2, "fq_codel");
	append_ingress_hook(&machine->qdiscs, 2);
	append_done(&machine->qdiscs);

	append_redirect(&machine->filters, 2, 3, NCFG_QDISC_FILTER_HANDLE);
	append_done(&machine->filters);

	append_rule(&machine->rules, AF_INET, RT_TABLE_MAIN, 32766);
	append_done(&machine->rules);
}

static void machine_queue(script_t *script, const machine_t *machine)
{
	queue(script, &machine->links);
	queue(script, &machine->addresses);
	queue(script, &machine->routes);
	queue(script, &machine->bridge_vlans);
	queue(script, &machine->qdiscs);
	queue(script, &machine->filters);
	queue(script, &machine->rules);
}

/* ------------------------------------------------------------------------ */
/* The cases.                                                               */
/* ------------------------------------------------------------------------ */

/*
 * A round that works, end to end, and the order it asked in.
 */
static void a_round_of_dumps(void)
{
	machine_t              machine;
	script_t               script;
	recorder_t             recorder;
	ncfg_observe_kernel_t  kernel;
	ncfg_observe_capture_t capture;
	ncfg_buf_t             qdisc_request;
	ncfg_buf_t             filter_request;
	char                   err[NCFG_ERROR_MAX];

	machine_init(&machine);
	machine_fill(&machine);
	check(!ncfg_buf_failed(&machine.links) && !ncfg_buf_failed(&machine.qdiscs) &&
	    !ncfg_buf_failed(&machine.filters), "the fixtures assemble");

	memset(&script, 0, sizeof(script));
	machine_queue(&script, &machine);
	recorder_start(&recorder, &script);
	kernel_of(&kernel, &recorder, 0);

	check(ncfg_observe_collect_from(&kernel, &capture, err, sizeof(err)),
	    "a round of seven dumps comes back");
	check(capture.link_count == 2u && capture.address_count == 2u &&
	    capture.route_count == 1u, "with the links, the addresses and the route");
	check(capture.bridge_vlan_count == 2u && capture.bridge_vlans[0].vid == 4u &&
	    capture.bridge_vlans[1].vid == 7u && capture.bridge_vlans[0].index == 3u,
	    "the bridge VLANs, sorted, each on the port it is on");
	check(capture.qdisc_root_count == 1u && capture.qdisc_roots[0].index == 2u &&
	    strcmp(capture.qdisc_roots[0].kind, "fq_codel") == 0, "the root qdisc");
	check(capture.ingress_hook_count == 1u && capture.ingress_hooks[0] == 2u,
	    "the interface carrying an ingress hook");
	check(capture.redirect_count == 1u && capture.redirects[0].index == 2u &&
	    capture.redirects[0].target == 3u && capture.redirects[0].ours,
	    "and the redirect hanging off it, marked as netcfgd's");
	check(capture.rule_count == 1u && capture.rules[0].priority == 32766u,
	    "and the routing rule");
	check(capture.skipped == 0 && capture.redirects_unreadable == 0 &&
	    capture.dropped == 0 && capture.note[0] == '\0',
	    "nothing skipped, nothing unreadable, nothing discarded");

	/* The snapshot borrows: the same storage, not a copy of it. That is the
	 * whole reason the capture exists, so it is asserted rather than
	 * assumed. */
	check(capture.snapshot.links == capture.links &&
	    capture.snapshot.addresses == capture.addresses &&
	    capture.snapshot.routes == capture.routes &&
	    capture.snapshot.bridge_vlans == capture.bridge_vlans &&
	    capture.snapshot.qdisc_roots == capture.qdisc_roots &&
	    capture.snapshot.redirects == capture.redirects &&
	    capture.snapshot.rules == capture.rules,
	    "the snapshot borrows the capture's own arrays");
	check(capture.snapshot.link_count == 2u && capture.snapshot.rule_count == 1u,
	    "and carries the counts beside them");
	check(capture.snapshot.address_proto_supported == 1,
	    "one tagged address calibrates the IFA_PROTO flag");

	/* The order of the seven, which is load-bearing: the qdisc dump decides
	 * how many filter dumps there are. */
	check(recorder.count == 7u, "seven requests went out");
	check(recorder.count == 7u && recorder.asked[0].kind == NCFG_DUMP_LINK &&
	    recorder.asked[1].kind == NCFG_DUMP_ADDRESS &&
	    recorder.asked[2].kind == NCFG_DUMP_ROUTE &&
	    recorder.asked[3].kind == NCFG_DUMP_BRIDGE_VLAN &&
	    recorder.asked[4].kind == RTM_GETQDISC &&
	    recorder.asked[5].kind == RTM_GETTFILTER &&
	    recorder.asked[6].kind == NCFG_DUMP_RULE,
	    "links, addresses, routes, bridge VLANs, qdiscs, filters, rules");
	check(recorder.count == 7u && recorder.asked[0].flags == ncfg_dump_flags() &&
	    recorder.asked[4].flags == ncfg_dump_flags(), "each of them a dump");
	check(recorder.count == 7u &&
	    recorder.asked[0].body.length == recorder.asked[3].body.length &&
	    memcmp(recorder.asked[0].body.data, recorder.asked[3].body.data,
	    recorder.asked[0].body.length) != 0,
	    "the bridge VLAN dump is the same message type asking a different question");

	/*
	 * And the two traffic-control requests are `qdisc.h`'s own bytes.
	 * `collect.c` takes those messages apart to get at their bodies; this is
	 * the proof that nothing was lost or respelled on the way.
	 */
	ncfg_buf_init(&qdisc_request, 0);
	ncfg_buf_init(&filter_request, 0);
	check(ncfg_qdisc_build_dump(&qdisc_request, 0, err, sizeof(err)) &&
	    body_matches(&recorder, 4u, &qdisc_request),
	    "the qdisc dump is the body ncfg_qdisc_build_dump writes");
	check(ncfg_qdisc_build_filter_dump(&filter_request, 0, 2u, err, sizeof(err)) &&
	    body_matches(&recorder, 5u, &filter_request),
	    "and the filter dump is aimed by ncfg_qdisc_build_filter_dump");
	ncfg_buf_free(&qdisc_request);
	ncfg_buf_free(&filter_request);

	check(script.at == script.count, "every queued datagram was read, and none twice");

	ncfg_observe_capture_free(&capture);
	check(capture.links == NULL && capture.link_count == 0 && capture.snapshot.links == NULL,
	    "freeing a capture leaves it empty");
	ncfg_observe_capture_free(&capture);
	check(1, "and freeing it again is nothing");

	recorder_free(&recorder);
	machine_free(&machine);
}

/*
 * The capture is an argument for `ncfg_observe_build`, which is the only
 * reason it holds a snapshot at all.
 */
static void a_capture_becomes_an_observation(void)
{
	machine_t              machine;
	script_t               script;
	recorder_t             recorder;
	ncfg_observe_kernel_t  kernel;
	ncfg_observe_capture_t capture;
	ncfg_observe_prior_t   prior;
	ncfg_observe_roots_t   roots;
	ncfg_observed_t       *observed = NULL;
	char                   err[NCFG_ERROR_MAX];

	machine_init(&machine);
	machine_fill(&machine);
	memset(&script, 0, sizeof(script));
	machine_queue(&script, &machine);
	recorder_start(&recorder, &script);
	kernel_of(&kernel, &recorder, 0);

	memset(&prior, 0, sizeof(prior));
	/* A root that is not there, so that "is this a radio" answers no for
	 * every link without reading the machine this test runs on. */
	memset(&roots, 0, sizeof(roots));
	(void)snprintf(roots.class_net, sizeof(roots.class_net), "%s",
	    "tests/collect_test.no-such-root");

	check(ncfg_observe_collect_from(&kernel, &capture, err, sizeof(err)),
	    "a round of dumps for an observation");
	check(ncfg_observe_build(&capture.snapshot, &prior, &roots, &observed, err, sizeof(err)),
	    "and the snapshot it carries builds one");
	check(observed && observed->link_count == 2u, "with both links in it");

	ncfg_observed_free(observed);
	ncfg_observe_prior_free(&prior);
	ncfg_observe_capture_free(&capture);
	recorder_free(&recorder);
	machine_free(&machine);
}

/* A machine with nothing on it: seven dumps, seven `NLMSG_DONE`s, no records
 * and no filter dumps at all. */
static void an_empty_machine(void)
{
	machine_t              machine;
	script_t               script;
	recorder_t             recorder;
	ncfg_observe_kernel_t  kernel;
	ncfg_observe_capture_t capture;
	char                   err[NCFG_ERROR_MAX];

	machine_init(&machine);
	append_done(&machine.links);
	append_done(&machine.addresses);
	append_done(&machine.routes);
	append_done(&machine.bridge_vlans);
	append_done(&machine.qdiscs);
	append_done(&machine.rules);
	memset(&script, 0, sizeof(script));
	queue(&script, &machine.links);
	queue(&script, &machine.addresses);
	queue(&script, &machine.routes);
	queue(&script, &machine.bridge_vlans);
	queue(&script, &machine.qdiscs);
	queue(&script, &machine.rules);
	recorder_start(&recorder, &script);
	kernel_of(&kernel, &recorder, 0);

	check(ncfg_observe_collect_from(&kernel, &capture, err, sizeof(err)),
	    "an empty dump is an answer, not a failure");
	check(capture.link_count == 0 && capture.address_count == 0 &&
	    capture.route_count == 0 && capture.rule_count == 0, "with nothing in it");
	check(capture.snapshot.links == NULL && capture.snapshot.link_count == 0,
	    "and a snapshot that borrows nothing");
	check(capture.snapshot.address_proto_supported == 0,
	    "no evidence of IFA_PROTO, which is not the same as a kernel without it");
	check(recorder.count == 6u,
	    "and no filter dump is sent, there being no ingress hook to aim one at");

	ncfg_observe_capture_free(&capture);
	recorder_free(&recorder);
	machine_free(&machine);
}

/*
 * The four ways a dump can go wrong on the wire, each failing the round.
 *
 * A snapshot missing its routes is not a smaller answer to the same question,
 * it is a plan that installs them all again -- so each of these is a refusal
 * with a sentence rather than a shorter capture.
 */
static void a_dump_that_goes_wrong(void)
{
	machine_t              machine;
	script_t               script;
	recorder_t             recorder;
	ncfg_observe_kernel_t  kernel;
	ncfg_observe_capture_t capture;
	ncfg_buf_t             broken;
	char                   err[NCFG_ERROR_MAX];

	/* --- a dump that ends with NLMSG_ERROR ---------------------------- */
	{
		machine_init(&machine);
		machine_fill(&machine);
		ncfg_buf_init(&broken, 0);
		append_link(&broken, 2, "eth0", NULL);
		append_error(&broken, EPERM, RTM_GETLINK);
		memset(&script, 0, sizeof(script));
		queue(&script, &broken);
		recorder_start(&recorder, &script);
		kernel_of(&kernel, &recorder, 0);

		err[0] = '\0';
		check(!ncfg_observe_collect_from(&kernel, &capture, err, sizeof(err)),
		    "a dump answered with NLMSG_ERROR fails the round");
		check(err[0] != '\0' && strstr(err, "RTM_GETLINK") != NULL,
		    "and the sentence names the request that was refused");
		check(capture.links == NULL && capture.link_count == 0,
		    "and the link it had already decoded is not left behind");
		ncfg_observe_capture_free(&capture);
		recorder_free(&recorder);
		ncfg_buf_free(&broken);
		machine_free(&machine);
	}

	/* --- a truncated final message ------------------------------------ */
	{
		machine_init(&machine);
		machine_fill(&machine);
		ncfg_buf_init(&broken, 0);
		append_link(&broken, 2, "eth0", NULL);
		append_done(&broken);
		/* Cut four bytes off the end, so the last message claims a
		 * length the datagram does not carry. */
		broken.length -= 4u;
		memset(&script, 0, sizeof(script));
		queue(&script, &broken);
		recorder_start(&recorder, &script);
		kernel_of(&kernel, &recorder, 0);

		err[0] = '\0';
		check(!ncfg_observe_collect_from(&kernel, &capture, err, sizeof(err)) &&
		    err[0] != '\0', "a truncated final message fails the round");
		check(capture.link_count == 0, "rather than reading as a dump that ended");
		ncfg_observe_capture_free(&capture);
		recorder_free(&recorder);
		ncfg_buf_free(&broken);
		machine_free(&machine);
	}

	/* --- a message longer than the datagram that arrived --------------- */
	{
		uint32_t claimed;

		machine_init(&machine);
		machine_fill(&machine);
		ncfg_buf_init(&broken, 0);
		append_link(&broken, 2, "eth0", NULL);
		append_done(&broken);
		/* The first message says it is longer than everything that
		 * arrived, which is the shape a lost tail leaves behind. */
		claimed = (uint32_t)broken.length + 64u;
		memcpy(broken.data, &claimed, sizeof(claimed));
		memset(&script, 0, sizeof(script));
		queue(&script, &broken);
		recorder_start(&recorder, &script);
		kernel_of(&kernel, &recorder, 0);

		err[0] = '\0';
		check(!ncfg_observe_collect_from(&kernel, &capture, err, sizeof(err)) &&
		    err[0] != '\0',
		    "a message claiming more bytes than arrived fails the round");
		ncfg_observe_capture_free(&capture);
		recorder_free(&recorder);
		ncfg_buf_free(&broken);
		machine_free(&machine);
	}

	/* --- ENOBUFS in the middle of a dump ------------------------------- */
	{
		machine_init(&machine);
		machine_fill(&machine);
		memset(&script, 0, sizeof(script));
		queue(&script, &machine.links);
		queue(&script, &machine.addresses);
		/* The route dump's first datagram never arrives: the socket
		 * buffer overflowed and the kernel dropped what was queued. */
		queue_failure(&script, ENOBUFS);
		recorder_start(&recorder, &script);
		kernel_of(&kernel, &recorder, 0);

		err[0] = '\0';
		check(!ncfg_observe_collect_from(&kernel, &capture, err, sizeof(err)) &&
		    err[0] != '\0', "ENOBUFS mid-round fails the round");
		check(capture.link_count == 0 && capture.address_count == 0,
		    "and the two dumps that did arrive are freed rather than handed back");
		check(recorder.count == 3u, "the round stops at the dump that failed");
		ncfg_observe_capture_free(&capture);
		recorder_free(&recorder);
		machine_free(&machine);
	}
}

/*
 * More records than an observation will hold.
 *
 * The ceiling is an argument for the reason `ncfg_netlink_request_from`'s
 * initial buffer size is one: the kernel will not grow a machine a million
 * interfaces on request, so a test that could not lower it could never reach
 * the refusal at all.
 */
static void more_than_this_will_hold(void)
{
	machine_t              machine;
	script_t               script;
	recorder_t             recorder;
	ncfg_observe_kernel_t  kernel;
	ncfg_observe_capture_t capture;
	char                   err[NCFG_ERROR_MAX];

	machine_init(&machine);
	/* Each carrying an alternative name, which is the one thing a link
	 * record owns: the record the ceiling refuses is the one whose names
	 * would otherwise be dropped on the floor, and a test whose links own
	 * nothing cannot tell whether they were. */
	append_link(&machine.links, 2, "eth0", NCFG_OBSERVE_ALTNAME_PREFIX "eth0");
	append_link(&machine.links, 3, "eth1", NCFG_OBSERVE_ALTNAME_PREFIX "eth1");
	append_link(&machine.links, 4, "eth2", NCFG_OBSERVE_ALTNAME_PREFIX "eth2");
	append_done(&machine.links);
	append_done(&machine.addresses);
	append_done(&machine.routes);
	append_done(&machine.bridge_vlans);
	append_done(&machine.qdiscs);
	append_done(&machine.rules);
	memset(&script, 0, sizeof(script));
	queue(&script, &machine.links);
	recorder_start(&recorder, &script);
	kernel_of(&kernel, &recorder, 2u);

	err[0] = '\0';
	check(!ncfg_observe_collect_from(&kernel, &capture, err, sizeof(err)),
	    "a dump one record past the ceiling is refused");
	check(strstr(err, "links") != NULL && strstr(err, "2") != NULL,
	    "and the refusal names the kind and the number");
	check(capture.links == NULL, "with nothing handed back half-filled");
	ncfg_observe_capture_free(&capture);
	recorder_free(&recorder);

	/* Exactly the ceiling is not past it, which is the boundary the two
	 * cases share and the one an off-by-one moves. */
	memset(&script, 0, sizeof(script));
	queue(&script, &machine.links);
	queue(&script, &machine.addresses);
	queue(&script, &machine.routes);
	queue(&script, &machine.bridge_vlans);
	queue(&script, &machine.qdiscs);
	queue(&script, &machine.rules);
	recorder_start(&recorder, &script);
	kernel_of(&kernel, &recorder, 3u);
	check(ncfg_observe_collect_from(&kernel, &capture, err, sizeof(err)) &&
	    capture.link_count == 3u, "a dump of exactly the ceiling is held");
	ncfg_observe_capture_free(&capture);
	recorder_free(&recorder);
	machine_free(&machine);
}

/*
 * What a payload nobody can decode does, and what a forged datagram does.
 *
 * `netlink.h` asks a caller that dumps to skip what it cannot read **and say
 * how many**, which is the half the Rust's `filter_map` leaves out: a
 * truncated dump and a quiet machine look the same afterwards.
 */
static void what_is_skipped_is_counted(void)
{
	machine_t              machine;
	script_t               script;
	recorder_t             recorder;
	ncfg_observe_kernel_t  kernel;
	ncfg_observe_capture_t capture;
	ncfg_buf_t             forged;
	char                   err[NCFG_ERROR_MAX];

	machine_init(&machine);
	machine_fill(&machine);
	/* A link message with no body at all, between two good ones. A link
	 * dump under AF_BRIDGE arrives on the same socket, so a payload this
	 * cannot read is ordinary rather than alarming. */
	ncfg_buf_init(&forged, 0);
	append_link(&forged, 2, "eth0", NULL);
	append_message(&forged, RTM_NEWLINK, 0, NULL, NULL);
	append_link(&forged, 3, "eth1", NULL);
	append_done(&forged);
	memset(&script, 0, sizeof(script));
	queue(&script, &forged);
	queue(&script, &machine.addresses);
	queue(&script, &machine.routes);
	queue(&script, &machine.bridge_vlans);
	queue(&script, &machine.qdiscs);
	queue(&script, &machine.filters);
	queue(&script, &machine.rules);
	recorder_start(&recorder, &script);
	kernel_of(&kernel, &recorder, 0);

	check(ncfg_observe_collect_from(&kernel, &capture, err, sizeof(err)),
	    "a payload nobody can decode does not fail the round");
	check(capture.link_count == 2u, "the two either side of it are kept");
	check(capture.skipped == 1u, "the one that was skipped is counted");
	check(capture.note[0] != '\0', "and the first sentence is kept, so the count can be read");
	ncfg_observe_capture_free(&capture);
	recorder_free(&recorder);
	ncfg_buf_free(&forged);

	/* --- and a datagram that did not come from the kernel -------------- */
	memset(&script, 0, sizeof(script));
	queue_from(&script, &machine.links, 4242u);
	machine_queue(&script, &machine);
	recorder_start(&recorder, &script);
	kernel_of(&kernel, &recorder, 0);
	check(ncfg_observe_collect_from(&kernel, &capture, err, sizeof(err)),
	    "a datagram from a local process is discarded, not obeyed");
	check(capture.link_count == 2u, "the kernel's own reply behind it is still read");
	check(capture.dropped == 1u, "and the discard is counted, since silence would hide it");
	ncfg_observe_capture_free(&capture);
	recorder_free(&recorder);
	machine_free(&machine);
}

/*
 * A filter dump that fails is counted, not fatal.
 *
 * The interface was reported as carrying an ingress hook by a dump taken a
 * moment earlier, so a failure now is a machine that moved between two of the
 * seven -- a USB device unplugged, which is also what generates the event the
 * observation is running on. Denying the whole observation over it would
 * withhold the answer at the moment somebody is asking why the device went.
 */
static void a_filter_dump_that_fails(void)
{
	machine_t              machine;
	script_t               script;
	recorder_t             recorder;
	ncfg_observe_kernel_t  kernel;
	ncfg_observe_capture_t capture;
	ncfg_buf_t             refused;
	char                   err[NCFG_ERROR_MAX];

	machine_init(&machine);
	machine_fill(&machine);
	ncfg_buf_init(&refused, 0);
	append_error(&refused, ENODEV, RTM_GETTFILTER);
	memset(&script, 0, sizeof(script));
	queue(&script, &machine.links);
	queue(&script, &machine.addresses);
	queue(&script, &machine.routes);
	queue(&script, &machine.bridge_vlans);
	queue(&script, &machine.qdiscs);
	queue(&script, &refused);
	queue(&script, &machine.rules);
	recorder_start(&recorder, &script);
	kernel_of(&kernel, &recorder, 0);

	check(ncfg_observe_collect_from(&kernel, &capture, err, sizeof(err)),
	    "a filter dump that fails does not fail the round");
	check(capture.redirect_count == 0 && capture.redirects_unreadable == 1u,
	    "it is counted instead, so no redirects is told from not asked");
	check(capture.ingress_hook_count == 1u,
	    "the hook it was aimed at stays in the capture, which is what says so");
	check(capture.note[0] != '\0' && capture.link_count == 2u,
	    "the sentence is kept and the rest of the round stands");
	check(recorder.count == 7u, "and the rule dump after it still went out");
	ncfg_observe_capture_free(&capture);
	recorder_free(&recorder);
	ncfg_buf_free(&refused);
	machine_free(&machine);
}

/*
 * Hooks are sorted and deduplicated before the filter dumps are aimed.
 *
 * A qdisc dump reports one entry per qdisc, and an interface can appear more
 * than once; asking twice would report the same redirect twice, and asking in
 * the kernel's order would make two observations of one unchanged machine
 * differ.
 */
static void hooks_are_sorted_and_asked_once(void)
{
	machine_t              machine;
	script_t               script;
	recorder_t             recorder;
	ncfg_observe_kernel_t  kernel;
	ncfg_observe_capture_t capture;
	ncfg_buf_t             filters_on_two;
	char                   err[NCFG_ERROR_MAX];

	machine_init(&machine);
	machine_fill(&machine);
	ncfg_buf_free(&machine.qdiscs);
	ncfg_buf_init(&machine.qdiscs, 0);
	append_ingress_hook(&machine.qdiscs, 9);
	append_ingress_hook(&machine.qdiscs, 2);
	append_ingress_hook(&machine.qdiscs, 9);
	append_done(&machine.qdiscs);

	ncfg_buf_init(&filters_on_two, 0);
	append_done(&filters_on_two);

	memset(&script, 0, sizeof(script));
	queue(&script, &machine.links);
	queue(&script, &machine.addresses);
	queue(&script, &machine.routes);
	queue(&script, &machine.bridge_vlans);
	queue(&script, &machine.qdiscs);
	/* Interface 2 first, because the hooks are sorted before they are
	 * asked: if they were not, this empty answer would go to interface 9
	 * and the redirect below would be reported on the wrong interface. */
	queue(&script, &filters_on_two);
	queue(&script, &machine.filters);
	queue(&script, &machine.rules);
	recorder_start(&recorder, &script);
	kernel_of(&kernel, &recorder, 0);

	check(ncfg_observe_collect_from(&kernel, &capture, err, sizeof(err)),
	    "a qdisc dump naming one interface twice");
	check(capture.ingress_hook_count == 2u && capture.ingress_hooks[0] == 2u &&
	    capture.ingress_hooks[1] == 9u, "reports two hooks, sorted");
	check(recorder.count == 8u, "and asks for filters once per interface, not once per entry");
	check(capture.redirect_count == 1u && capture.redirects[0].index == 9u,
	    "the redirect is attributed to the interface its dump was aimed at");
	ncfg_observe_capture_free(&capture);
	recorder_free(&recorder);
	ncfg_buf_free(&filters_on_two);
	machine_free(&machine);
}

/*
 * A redirect somebody else installed is reported and not claimed.
 *
 * `ours` comes from the filter's handle (0137), which is the only thing left
 * saying whose a redirect is once `/run` has gone -- and a redirect wrongly
 * claimed is a plan that removes somebody's traffic.
 */
static void a_redirect_that_is_not_ours(void)
{
	machine_t              machine;
	script_t               script;
	recorder_t             recorder;
	ncfg_observe_kernel_t  kernel;
	ncfg_observe_capture_t capture;
	char                   err[NCFG_ERROR_MAX];

	machine_init(&machine);
	machine_fill(&machine);
	ncfg_buf_free(&machine.filters);
	ncfg_buf_init(&machine.filters, 0);
	append_redirect(&machine.filters, 2, 3, NCFG_QDISC_FILTER_HANDLE + 1u);
	append_done(&machine.filters);

	memset(&script, 0, sizeof(script));
	machine_queue(&script, &machine);
	recorder_start(&recorder, &script);
	kernel_of(&kernel, &recorder, 0);

	check(ncfg_observe_collect_from(&kernel, &capture, err, sizeof(err)) &&
	    capture.redirect_count == 1u, "a redirect wearing somebody else's handle is reported");
	check(capture.redirect_count == 1u && !capture.redirects[0].ours,
	    "and is not claimed as netcfgd's");
	ncfg_observe_capture_free(&capture);
	recorder_free(&recorder);
	machine_free(&machine);
}

/*
 * An ingress hook on interface zero never becomes a filter dump.
 *
 * `RTM_GETTFILTER` answers a zero index with an *empty dump*, which looks
 * exactly like a machine with no redirects installed -- and is a plan that
 * reinstalls one on every apply. `qdisc.h` refuses it rather than sending it,
 * and this is the path that refusal is reached by.
 */
static void a_hook_on_no_interface(void)
{
	machine_t              machine;
	script_t               script;
	recorder_t             recorder;
	ncfg_observe_kernel_t  kernel;
	ncfg_observe_capture_t capture;
	ncfg_buf_t             hook;
	ncfg_buf_t             body;
	ncfg_qdisc_tcmsg_t     header;
	char                   err[NCFG_ERROR_MAX];

	machine_init(&machine);
	machine_fill(&machine);
	/* Built by hand, because the builder refuses a zero index -- which is
	 * the point: only a kernel could put this in a dump. */
	memset(&header, 0, sizeof(header));
	header.parent = 0xfffffff1u; /* TC_H_INGRESS */
	ncfg_buf_init(&body, 0);
	ncfg_qdisc_tcmsg_encode(&header, &body);
	ncfg_buf_init(&hook, 0);
	append_message(&hook, RTM_NEWQDISC, 0, &body, NULL);
	append_done(&hook);

	memset(&script, 0, sizeof(script));
	queue(&script, &machine.links);
	queue(&script, &machine.addresses);
	queue(&script, &machine.routes);
	queue(&script, &machine.bridge_vlans);
	queue(&script, &hook);
	queue(&script, &machine.rules);
	recorder_start(&recorder, &script);
	kernel_of(&kernel, &recorder, 0);

	check(ncfg_observe_collect_from(&kernel, &capture, err, sizeof(err)),
	    "an ingress hook on interface zero does not fail the round");
	check(recorder.count == 6u, "no filter dump is aimed at an index that is not one");
	check(capture.redirects_unreadable == 1u, "and the interface is counted as unreadable");
	ncfg_observe_capture_free(&capture);
	recorder_free(&recorder);
	ncfg_buf_free(&hook);
	ncfg_buf_free(&body);
	machine_free(&machine);
}

/*
 * A qdisc that is neither the root nor the ingress hook.
 *
 * `RTM_GETQDISC` dumps every qdisc on the machine, including the children of
 * somebody's class tree -- which is outside 0023's scope. Three outcomes and
 * not two is what `qdisc.h` exists to say here: a child is read perfectly well
 * and is not ours to hold, so it is neither a root, nor a hook, nor a skip.
 */
static void a_qdisc_that_is_neither(void)
{
	machine_t              machine;
	script_t               script;
	recorder_t             recorder;
	ncfg_observe_kernel_t  kernel;
	ncfg_observe_capture_t capture;
	ncfg_buf_t             body;
	ncfg_qdisc_tcmsg_t     header;
	char                   err[NCFG_ERROR_MAX];

	machine_init(&machine);
	machine_fill(&machine);
	ncfg_buf_free(&machine.qdiscs);
	ncfg_buf_init(&machine.qdiscs, 0);
	append_qdisc_root(&machine.qdiscs, 2, "htb");
	/* A leaf under the class `1:10` of that tree. */
	memset(&header, 0, sizeof(header));
	header.index = 2;
	header.handle = 20u << 16;
	header.parent = (1u << 16) | 10u;
	ncfg_buf_init(&body, 0);
	ncfg_qdisc_tcmsg_encode(&header, &body);
	append_message(&machine.qdiscs, RTM_NEWQDISC, 0, &body, NULL);
	append_done(&machine.qdiscs);

	memset(&script, 0, sizeof(script));
	queue(&script, &machine.links);
	queue(&script, &machine.addresses);
	queue(&script, &machine.routes);
	queue(&script, &machine.bridge_vlans);
	queue(&script, &machine.qdiscs);
	queue(&script, &machine.rules);
	recorder_start(&recorder, &script);
	kernel_of(&kernel, &recorder, 0);

	check(ncfg_observe_collect_from(&kernel, &capture, err, sizeof(err)),
	    "a class tree's child does not fail the round");
	check(capture.qdisc_root_count == 1u &&
	    strcmp(capture.qdisc_roots[0].kind, "htb") == 0,
	    "only the root is held, not the leaf hanging under it");
	check(capture.ingress_hook_count == 0, "and it is not mistaken for an ingress hook");
	check(capture.skipped == 0,
	    "nor counted as a payload nobody could read, which it plainly was");
	ncfg_observe_capture_free(&capture);
	recorder_free(&recorder);
	ncfg_buf_free(&body);
	machine_free(&machine);
}

/*
 * Two redirects to one device, one netcfgd's and one not.
 *
 * They are the same but for `ours`, which is the field that decides whether a
 * plan may remove one -- so a comparison that stopped at the target would
 * fold them together and netcfgd would claim a filter it did not install.
 */
static void two_redirects_that_differ_only_in_whose_they_are(void)
{
	machine_t              machine;
	script_t               script;
	recorder_t             recorder;
	ncfg_observe_kernel_t  kernel;
	ncfg_observe_capture_t capture;
	char                   err[NCFG_ERROR_MAX];

	machine_init(&machine);
	machine_fill(&machine);
	ncfg_buf_free(&machine.filters);
	ncfg_buf_init(&machine.filters, 0);
	/* netcfgd's first, so that the order asserted below is the sort's doing
	 * and not the order the kernel happened to report them in. */
	append_redirect(&machine.filters, 2, 3, NCFG_QDISC_FILTER_HANDLE);
	append_redirect(&machine.filters, 2, 3, NCFG_QDISC_FILTER_HANDLE + 1u);
	append_done(&machine.filters);

	memset(&script, 0, sizeof(script));
	machine_queue(&script, &machine);
	recorder_start(&recorder, &script);
	kernel_of(&kernel, &recorder, 0);

	check(ncfg_observe_collect_from(&kernel, &capture, err, sizeof(err)) &&
	    capture.redirect_count == 2u,
	    "two redirects to one device are two, where only the handle differs");
	check(capture.redirect_count == 2u && !capture.redirects[0].ours &&
	    capture.redirects[1].ours, "and the sort is total, so the order is the same twice");
	ncfg_observe_capture_free(&capture);
	recorder_free(&recorder);
	machine_free(&machine);
}

/*
 * A reply too big for the buffer it started in is read again, not truncated.
 *
 * The buffer size is the replay's for the same reason it is a parameter of
 * `ncfg_netlink_request_from`: the kernel caps a dump's datagrams just under
 * 32 KiB whatever the interface count, so starting deliberately small reaches
 * the growth the way a single oversized message does on a real machine.
 */
static void a_reply_too_big_for_its_buffer(void)
{
	machine_t              machine;
	script_t               script;
	recorder_t             recorder;
	ncfg_observe_kernel_t  kernel;
	ncfg_observe_capture_t cramped;
	ncfg_observe_capture_t roomy;
	char                   err[NCFG_ERROR_MAX];
	size_t                 at;

	machine_init(&machine);
	for (at = 0; at < 12u; at++) {
		char name[NCFG_LINK_NAME_MAX];

		(void)snprintf(name, sizeof(name), "eth%zu", at);
		append_link(&machine.links, (int32_t)at + 1, name, NULL);
	}
	append_done(&machine.links);
	append_done(&machine.addresses);
	append_done(&machine.routes);
	append_done(&machine.bridge_vlans);
	append_done(&machine.qdiscs);
	append_done(&machine.rules);

	memset(&script, 0, sizeof(script));
	queue(&script, &machine.links);
	queue(&script, &machine.addresses);
	queue(&script, &machine.routes);
	queue(&script, &machine.bridge_vlans);
	queue(&script, &machine.qdiscs);
	queue(&script, &machine.rules);
	recorder_start(&recorder, &script);
	recorder.replay.initial = 128u;
	kernel_of(&kernel, &recorder, 0);
	check(ncfg_observe_collect_from(&kernel, &cramped, err, sizeof(err)),
	    "a dump larger than the buffer it started in comes back whole");
	check(script.reads == 6u, "read once per dump and never re-asked");
	recorder_free(&recorder);

	memset(&script, 0, sizeof(script));
	queue(&script, &machine.links);
	queue(&script, &machine.addresses);
	queue(&script, &machine.routes);
	queue(&script, &machine.bridge_vlans);
	queue(&script, &machine.qdiscs);
	queue(&script, &machine.rules);
	recorder_start(&recorder, &script);
	kernel_of(&kernel, &recorder, 0);
	check(ncfg_observe_collect_from(&kernel, &roomy, err, sizeof(err)) &&
	    roomy.link_count == cramped.link_count && roomy.link_count == 12u,
	    "and is the same dump the roomy buffer got");
	for (at = 0; at < roomy.link_count && at < cramped.link_count; at++) {
		if (strcmp(roomy.links[at].name, cramped.links[at].name) != 0) {
			break;
		}
	}
	check(at == 12u, "link for link, in the same order");

	ncfg_observe_capture_free(&cramped);
	ncfg_observe_capture_free(&roomy);
	recorder_free(&recorder);
	machine_free(&machine);
}

/* The arguments nobody should pass, and what happens when they do. */
static void the_arguments_that_are_refused(void)
{
	ncfg_observe_capture_t capture;
	ncfg_observe_kernel_t  kernel;
	ncfg_observe_replay_t  replay;
	ncfg_netlink_reply_t   reply;
	char                   err[NCFG_ERROR_MAX];

	memset(&kernel, 0, sizeof(kernel));
	err[0] = '\0';
	check(!ncfg_observe_collect_from(&kernel, &capture, err, sizeof(err)) && err[0] != '\0',
	    "a round with no exchange is refused rather than silently empty");
	check(!ncfg_observe_collect_from(NULL, &capture, NULL, 0),
	    "and so is one with no kernel at all");
	kernel.exchange = ncfg_observe_exchange_replay;
	check(!ncfg_observe_collect_from(&kernel, NULL, NULL, 0),
	    "and one with nowhere to put the answer");
	check(!ncfg_observe_collect_on(NULL, &capture, NULL, 0),
	    "a round over no socket is refused");
	check(!ncfg_observe_exchange_socket(NULL, NCFG_DUMP_LINK, ncfg_dump_flags(), NULL, NULL,
	    &reply, NULL, 0), "the socket exchange needs a socket");
	memset(&replay, 0, sizeof(replay));
	check(!ncfg_observe_exchange_replay(&replay, NCFG_DUMP_LINK, ncfg_dump_flags(), NULL,
	    NULL, &reply, NULL, 0), "and the replay exchange needs a source");
	ncfg_observe_capture_free(NULL);
	check(1, "freeing nothing is nothing");
}

/*
 * The one check that opens a socket, behind `NCFG_OBSERVE_LIVE=1`.
 *
 * It sends nothing but the seven dump requests, which are `GET`s and change
 * nothing, and asserts only what is true of every Linux machine: there is at
 * least one interface, and it is called `lo`. Opt-in because reading is safe
 * in principle and a hang on somebody's desk is not, and it says loudly that
 * it was skipped rather than passing silently.
 */
static void the_live_check(void)
{
	ncfg_observe_capture_t capture;
	char                   err[NCFG_ERROR_MAX];
	const char            *live = getenv("NCFG_OBSERVE_LIVE");
	size_t                 at;
	int                    loopback = 0;

	if (!live || strcmp(live, "1") != 0) {
		check(1, "the live round is skipped; set NCFG_OBSERVE_LIVE=1 to run it");
		return;
	}
	if (!ncfg_observe_collect(&capture, err, sizeof(err))) {
		check(0, "a live round of dumps");
		printf("  %s\n", err);
		return;
	}
	check(1, "a live round of dumps");
	for (at = 0; at < capture.link_count; at++) {
		if (strcmp(capture.links[at].name, "lo") == 0) {
			loopback = 1;
		}
	}
	check(capture.link_count > 0 && loopback, "finds this machine's loopback");
	printf("  %zu link(s), %zu address(es), %zu route(s), %zu rule(s), %zu skipped\n",
	    capture.link_count, capture.address_count, capture.route_count, capture.rule_count,
	    capture.skipped);
	ncfg_observe_capture_free(&capture);
}

int main(void)
{
	a_round_of_dumps();
	a_capture_becomes_an_observation();
	an_empty_machine();
	a_dump_that_goes_wrong();
	more_than_this_will_hold();
	what_is_skipped_is_counted();
	a_filter_dump_that_fails();
	hooks_are_sorted_and_asked_once();
	a_redirect_that_is_not_ours();
	a_hook_on_no_interface();
	a_qdisc_that_is_neither();
	two_redirects_that_differ_only_in_whose_they_are();
	a_reply_too_big_for_its_buffer();
	the_arguments_that_are_refused();
	the_live_check();

	if (failures) {
		printf("%d check(s) failed\n", failures);
		return 1;
	}
	printf("all checks passed\n");
	return 0;
}
