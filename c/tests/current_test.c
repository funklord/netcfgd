/*
 * current_test.c -- the join between the kernel, the record and the files.
 *
 * WHAT THIS IS ABOUT THAT THE OTHER TWO ARE NOT
 *   `collect_test.c` drives the seven dumps and stops at a capture;
 *   `observe_test.c` drives the ownership rules against a snapshot and a
 *   prior a test filled in by hand. Neither of them ever reads `owned.json`,
 *   `prefixes/` or a report, because neither of them is the thing that does.
 *   `ncfg_observe_current_from` is, and what it can get wrong is exactly what
 *   nothing above or below it can:
 *
 *     * a list the prior **borrows** freed on this side while the observation
 *       still points at it, or freed twice;
 *     * a list the prior **hands over** left in both places, which is one
 *       array with two owners and two frees -- ASan is the assertion, and
 *       `make -C c SANITIZE=1 test` is where it fires;
 *     * a pass skipped. An observation with no `derive` names no linkset and
 *       no connectivity rung, which reads as a machine that has neither.
 *
 * WHY THE RECORD IS WRITTEN BY `ncfg_owned_write`
 *   Hand-writing `owned.json` here would be a second opinion about a file
 *   format `state.h` already owns, and the day the writer changes the fixture
 *   goes on passing while the daemon stops reading what it wrote. So the
 *   record is built as a value, written by the writer, and read back by the
 *   composition -- which makes the round trip part of the subject.
 *
 * WHY THERE IS NO KERNEL IN HERE
 *   `collect_test.c`'s reason, unchanged: this suite runs on the machine
 *   netcfgd configures. The one check that opens a socket is behind
 *   `NCFG_OBSERVE_LIVE=1`, the way that file does it, and it sends nothing but
 *   `GET`s.
 */
#include "ncfg/observe.h"

#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/daemon.h"
#include "ncfg/document.h"
#include "ncfg/ethtool.h"
#include "ncfg/genl.h"
#include "ncfg/netlink.h"
#include "ncfg/nft.h"
#include "ncfg/observed.h"
#include "ncfg/state.h"
#include "ncfg/wire.h"

#include "testdir.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/* The kernel headers `nft.h` deliberately does not pull in: this file builds
 * the bytes an nftables kernel would send. */
#include <linux/genetlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nfnetlink.h>

static int failures;

static int check(int condition, const char *what)
{
	printf("%-72s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
	return condition;
}

static void detail(const char *what, const char *value)
{
	printf("  %s: %s\n", what, value ? value : "(none)");
}

/* ------------------------------------------------------------------------ *
 * The bytes a kernel would send
 * ------------------------------------------------------------------------ */

static void append_message(ncfg_buf_t *out, uint16_t kind, const ncfg_buf_t *body,
    const ncfg_buf_t *attrs)
{
	ncfg_buf_t one;

	ncfg_buf_init(&one, 0);
	if (!ncfg_wire_build_request(&one, kind, 0, 0, body, attrs, NULL, 0)) {
		out->failed = 1;
	} else {
		ncfg_buf_add(out, one.data, one.length);
	}
	ncfg_buf_free(&one);
}

static void append_done(ncfg_buf_t *out)
{
	append_message(out, NLMSG_DONE, NULL, NULL);
}

static void append_link(ncfg_buf_t *out, int32_t index, const char *name)
{
	ncfg_buf_t         body;
	ncfg_buf_t         attrs;
	ncfg_wire_ifinfo_t info;

	memset(&info, 0, sizeof(info));
	info.index = index;
	info.flags = NCFG_LINK_IFF_UP;
	ncfg_buf_init(&body, 0);
	ncfg_buf_init(&attrs, 0);
	ncfg_wire_ifinfo_encode(&info, &body);
	ncfg_wire_attr_put_str(&attrs, IFLA_IFNAME, name);
	ncfg_wire_attr_put_u32(&attrs, IFLA_MTU, 1500);
	append_message(out, RTM_NEWLINK, &body, &attrs);
	ncfg_buf_free(&body);
	ncfg_buf_free(&attrs);
}

/* One address, wearing netcfgd's own `IFA_PROTO`. */
static void append_address(ncfg_buf_t *out, uint32_t index, const char *text, uint8_t prefix)
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
	info.family = (uint8_t)local.family;
	info.prefix_len = prefix;
	info.index = index;
	ncfg_buf_init(&body, 0);
	ncfg_buf_init(&attrs, 0);
	ncfg_wire_ifaddr_encode(&info, &body);
	ncfg_wire_attr_put_ip(&attrs, IFA_LOCAL, &local);
	ncfg_wire_attr_put_u8(&attrs, IFA_PROTO, NCFG_WIRE_RTPROT_NETCFGD);
	append_message(out, RTM_NEWADDR, &body, &attrs);
	ncfg_buf_free(&body);
	ncfg_buf_free(&attrs);
}

/* A default route out of one interface, carrying netcfgd's protocol number. */
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
	append_message(out, RTM_NEWROUTE, &body, &attrs);
	ncfg_buf_free(&body);
	ncfg_buf_free(&attrs);
}

/* ------------------------------------------------------------------------ *
 * And the bytes an nftables kernel would send
 * ------------------------------------------------------------------------ */

/* A payload the caller already has, with a header put in front of it. The
 * rule below is taken out of a transaction nft.c built, so what has to be
 * appended is bytes rather than a body and its attributes. */
static void append_payload(ncfg_buf_t *out, uint16_t kind, const void *payload, size_t length)
{
	ncfg_buf_t body;

	ncfg_buf_init(&body, 0);
	ncfg_buf_add(&body, payload, length);
	append_message(out, kind, &body, NULL);
	ncfg_buf_free(&body);
}

static uint16_t nft_type(uint16_t kind)
{
	return (uint16_t)(((unsigned)NFNL_SUBSYS_NFTABLES << 8) | (unsigned)kind);
}

/* nftables integers are big-endian, which is the opposite of every other
 * integer in this port -- so this is deliberately not `ncfg_wire_attr_put_u32`,
 * which would agree with a broken decoder. nft_test.c says the same thing
 * where it builds the same attribute. */
static void put_be32(ncfg_buf_t *out, uint16_t kind, uint32_t value)
{
	uint32_t wire = htonl(value);

	ncfg_wire_attr_put(out, kind, &wire, sizeof(wire));
}

static void put_nfgenmsg(ncfg_buf_t *out, uint8_t family)
{
	uint16_t res_id = 0;

	ncfg_buf_add(out, &family, sizeof(family));
	ncfg_buf_add_char(out, 0);
	ncfg_buf_add(out, &res_id, sizeof(res_id));
}

/*
 * One masquerade rule, **as nft.c writes one**.
 *
 * Built by `ncfg_nft_build_replace_nat` and picked out of the transaction by
 * asking the reader which message it accepts, rather than by index. A
 * hand-written rule here would be a second encoder with no tests of its own,
 * and the day the expressions change it is the fixture that would be believed
 * -- which is `collect_test.c`'s rule about the traffic-control fixtures,
 * applied to the one dump whose shape a writer in this tree decides.
 */
static void append_uplink_rule(ncfg_buf_t *out, const char *iface)
{
	const char          *uplinks[1];
	ncfg_buf_t           transaction;
	ncfg_nft_batch_t     batch;
	ncfg_wire_messages_t walk;
	ncfg_wire_message_t  message;
	char                 name[NCFG_NFT_IFNAME_MAX];
	char                 err[NCFG_ERROR_MAX];
	int                  found = 0;

	uplinks[0] = iface;
	ncfg_buf_init(&transaction, 0);
	if (!ncfg_nft_build_replace_nat(&transaction, 1, 0, uplinks, 1, &batch, err,
	    sizeof(err))) {
		out->failed = 1;
		ncfg_buf_free(&transaction);
		return;
	}
	ncfg_wire_messages_start(&walk, transaction.data, transaction.length);
	while (ncfg_wire_messages_next(&walk, &message, NULL, 0) == NCFG_WIRE_OK) {
		if (!ncfg_nft_rule_uplink(message.payload, message.payload_length, name,
		    sizeof(name), NULL, 0)) {
			continue;
		}
		append_payload(out, nft_type(NFT_MSG_NEWRULE), message.payload,
		    message.payload_length);
		found = 1;
	}
	if (!found) {
		out->failed = 1;
	}
	ncfg_buf_free(&transaction);
}

/* One chain, which is a shape no writer in this tree produces -- netcfgd
 * creates exactly one chain and this fixture is mostly about somebody else's.
 * `hook` of -1 is a regular chain, which has neither a type nor a hook. */
static void append_chain(ncfg_buf_t *out, const char *table, const char *name,
    const char *kind, int hook)
{
	ncfg_buf_t payload;
	ncfg_buf_t attrs;
	ncfg_buf_t nest;

	ncfg_buf_init(&payload, 0);
	ncfg_buf_init(&attrs, 0);
	ncfg_buf_init(&nest, 0);
	ncfg_wire_attr_put_str(&attrs, NFTA_CHAIN_TABLE, table);
	ncfg_wire_attr_put_str(&attrs, NFTA_CHAIN_NAME, name);
	if (hook >= 0) {
		ncfg_wire_attr_put_str(&attrs, NFTA_CHAIN_TYPE, kind);
		put_be32(&nest, NFTA_HOOK_HOOKNUM, (uint32_t)hook);
		ncfg_wire_attr_put_nested(&attrs, NFTA_CHAIN_HOOK, &nest);
	}
	put_nfgenmsg(&payload, NFPROTO_INET);
	ncfg_buf_add(&payload, attrs.data, attrs.length);
	append_payload(out, nft_type(NFT_MSG_NEWCHAIN), payload.data, payload.length);
	ncfg_buf_free(&nest);
	ncfg_buf_free(&attrs);
	ncfg_buf_free(&payload);
}

/* ------------------------------------------------------------------------ *
 * The fake datagram source
 * ------------------------------------------------------------------------ */

#define QUEUED_MAX 12u

typedef struct {
	const uint8_t *bytes;
	size_t         length;
	int            fails;
	int            code;
} queued_t;

typedef struct {
	queued_t at[QUEUED_MAX];
	size_t   count;
	size_t   next;
} script_t;

static ssize_t script_recv(void *context, void *bytes, size_t length, int peek, uint32_t *from)
{
	script_t       *script = context;
	const queued_t *one;
	size_t          copy;

	*from = UINT32_MAX;
	if (script->next >= script->count) {
		errno = EAGAIN;
		return -1;
	}
	one = &script->at[script->next];
	if (one->fails) {
		if (!peek) {
			script->next++;
		}
		errno = one->code;
		return -1;
	}
	*from = 0u;
	copy = one->length < length ? one->length : length;
	if (copy) {
		memcpy(bytes, one->bytes, copy);
	}
	if (peek) {
		return (ssize_t)one->length;
	}
	script->next++;
	return (ssize_t)one->length;
}

static void queue(script_t *script, const ncfg_buf_t *buffer)
{
	if (script->count < QUEUED_MAX) {
		script->at[script->count].bytes = (const uint8_t *)buffer->data;
		script->at[script->count].length = buffer->length;
		script->at[script->count].fails = 0;
		script->at[script->count].code = 0;
		script->count++;
	}
}

static void queue_failure(script_t *script, int code)
{
	if (script->count < QUEUED_MAX) {
		memset(&script->at[script->count], 0, sizeof(script->at[script->count]));
		script->at[script->count].fails = 1;
		script->at[script->count].code = code;
		script->count++;
	}
}

/* ------------------------------------------------------------------------ *
 * One machine, in six dumps
 * ------------------------------------------------------------------------ */

/*
 * Two links, one tagged address, one default route, and nothing else.
 *
 * Small on purpose: what is being checked here is the join rather than the
 * decoding, and `collect_test.c` already drives every shape a dump can take.
 * The three empty dumps still have to be queued, because a round asks seven
 * times whatever the machine holds -- and the qdisc dump being empty is what
 * makes the filter round zero requests rather than one.
 */
typedef struct {
	ncfg_buf_t links;
	ncfg_buf_t addresses;
	ncfg_buf_t routes;
	ncfg_buf_t empty;
} machine_t;

static void machine_init(machine_t *machine)
{
	memset(machine, 0, sizeof(*machine));
	ncfg_buf_init(&machine->links, 0);
	ncfg_buf_init(&machine->addresses, 0);
	ncfg_buf_init(&machine->routes, 0);
	ncfg_buf_init(&machine->empty, 0);

	append_link(&machine->links, 2, "eth0");
	append_link(&machine->links, 3, "br0");
	append_done(&machine->links);
	append_address(&machine->addresses, 2u, "192.0.2.10", 24u);
	append_done(&machine->addresses);
	append_route(&machine->routes, 2u, "192.0.2.1");
	append_done(&machine->routes);
	append_done(&machine->empty);
}

static void machine_free(machine_t *machine)
{
	ncfg_buf_free(&machine->links);
	ncfg_buf_free(&machine->addresses);
	ncfg_buf_free(&machine->routes);
	ncfg_buf_free(&machine->empty);
}

/* Links, addresses, routes, bridge VLANs, qdiscs, rules. No filter dump,
 * because no interface reported an ingress hook. */
static void queue_machine(script_t *script, const machine_t *machine)
{
	queue(script, &machine->links);
	queue(script, &machine->addresses);
	queue(script, &machine->routes);
	queue(script, &machine->empty);
	queue(script, &machine->empty);
	queue(script, &machine->empty);
}

static void kernel_of(ncfg_observe_kernel_t *kernel, ncfg_observe_replay_t *replay,
    script_t *script)
{
	memset(replay, 0, sizeof(*replay));
	replay->recv = script_recv;
	replay->context = script;
	memset(kernel, 0, sizeof(*kernel));
	kernel->exchange = ncfg_observe_exchange_replay;
	kernel->context = replay;
}

/* ------------------------------------------------------------------------ *
 * The fixture: a run directory and a /proc of this test's own
 * ------------------------------------------------------------------------ */

static char fixture[256];
static char run_dir[320];
static char proc_root[320];
static char sys_root[320];
static char class_net[320];

static void make_dir(const char *path)
{
	if (mkdir(path, 0700) != 0) {
		printf("current_test: could not make %s\n", path);
		exit(1);
	}
}

static void put(const char *path, const char *contents)
{
	if (!testdir_write(path, contents, strlen(contents))) {
		printf("current_test: could not write %s\n", path);
		exit(1);
	}
}

/*
 * The record, written by the writer.
 *
 * `br0` is a link netcfgd created and the kernel reports without an
 * alternative name, which is the additive case `ncfg_observe_link_ownership`
 * exists for. The address is recorded as `dhcp4` **while wearing netcfgd's own
 * tag**, which is the discriminating pair: the tag alone would make it
 * `static` through `ncfg_observe_tagged_origin`, so reading `dhcp4` back is
 * proof the borrowed origin list arrived rather than the fallback firing.
 */
static void write_the_record(void)
{
	ncfg_owned_state_t      owned;
	ncfg_owned_object_t     address;
	ncfg_observed_backend_t backend;
	ncfg_applied_dns_t      scope;
	char                   *created[1];
	char                    err[NCFG_ERROR_MAX];

	memset(&owned, 0, sizeof(owned));
	memset(&address, 0, sizeof(address));
	memset(&backend, 0, sizeof(backend));
	memset(&scope, 0, sizeof(scope));
	created[0] = (char *)"br0";
	address.interface = (char *)"eth0";
	address.key = (char *)"192.0.2.10/24";
	address.origin = NCFG_ORIGIN_DHCP4;
	owned.created_links = created;
	owned.created_link_count = 1u;
	owned.addresses = &address;
	owned.address_count = 1u;
	/*
	 * The two lists the record grew, and they are here because this is the
	 * seam they travel through: `read_record` hands them to the prior and
	 * `build` hands them to the observation. Neither was in the record at all
	 * for several waves, so `observed.backends` and `observed.dns` were empty
	 * on every machine and six observation passes had nothing to walk.
	 */
	backend.kind = (int)NCFG_BACKEND_DHCP4;
	backend.interface = (char *)"eth0";
	backend.running = 1;
	owned.backends = &backend;
	owned.backend_count = 1u;
	scope.scope = (char *)"eth0";
	owned.dns = &scope;
	owned.dns_count = 1u;
	if (!ncfg_owned_note_hook_state(&owned, "eth0", NCFG_HOOK_PHASE_POST_UP, "ran")) {
		printf("current_test: could not note a hook state\n");
		exit(1);
	}
	if (!ncfg_owned_write(run_dir, &owned, err, sizeof(err))) {
		printf("current_test: could not write the record: %s\n", err);
		exit(1);
	}
	/* Only the hook state was allocated here; the other five are this
	 * function's own storage and the record must not be asked to free them. */
	owned.created_links = NULL;
	owned.created_link_count = 0;
	owned.addresses = NULL;
	owned.address_count = 0;
	owned.backends = NULL;
	owned.backend_count = 0;
	owned.dns = NULL;
	owned.dns_count = 0;
	ncfg_owned_free(&owned);
}

static void make_fixture(void)
{
	char path[512];

	(void)snprintf(fixture, sizeof(fixture), "%s", testdir_make("current"));
	(void)snprintf(run_dir, sizeof(run_dir), "%s/run", fixture);
	(void)snprintf(proc_root, sizeof(proc_root), "%s/proc", fixture);
	(void)snprintf(sys_root, sizeof(sys_root), "%s/sys", fixture);
	(void)snprintf(class_net, sizeof(class_net), "%s/sys/class/net", fixture);
	make_dir(run_dir);
	make_dir(proc_root);
	make_dir(sys_root);
	(void)snprintf(path, sizeof(path), "%s/class", sys_root);
	make_dir(path);
	make_dir(class_net);

	(void)snprintf(path, sizeof(path), "%s/sys", proc_root);
	make_dir(path);
	(void)snprintf(path, sizeof(path), "%s/sys/kernel", proc_root);
	make_dir(path);
	(void)snprintf(path, sizeof(path), "%s/sys/kernel/hostname", proc_root);
	put(path, "fixture-host\n");

	(void)snprintf(path, sizeof(path), "%s/prefixes", run_dir);
	make_dir(path);
	(void)snprintf(path, sizeof(path), "%s/prefixes/wan0", run_dir);
	put(path, "2001:db8:1::/56\n");

	(void)snprintf(path, sizeof(path), "%s/reported", run_dir);
	make_dir(path);
	(void)snprintf(path, sizeof(path), "%s/reported/wan0", run_dir);
	put(path, "address=203.0.113.5/24\ndns=203.0.113.53\n");

	write_the_record();
}

static void remove_fixture(void)
{
	testdir_remove(fixture);
}

static ncfg_observe_roots_t fixture_roots(void)
{
	ncfg_observe_roots_t roots;

	memset(&roots, 0, sizeof(roots));
	(void)snprintf(roots.class_net, sizeof(roots.class_net), "%s", class_net);
	(void)snprintf(roots.proc, sizeof(roots.proc), "%s", proc_root);
	(void)snprintf(roots.sys, sizeof(roots.sys), "%s", sys_root);
	return roots;
}

static const ncfg_observed_address_t *find_address(const ncfg_observed_t *observed,
    const char *cidr)
{
	size_t at;

	for (at = 0; at < observed->address_count; at++) {
		if (strcmp(observed->addresses[at].address, cidr) == 0) {
			return &observed->addresses[at];
		}
	}
	return NULL;
}

/* ------------------------------------------------------------------------ *
 * The four passes, in one call
 * ------------------------------------------------------------------------ */

/*
 * Every one of the four leaves a mark, and each mark is one no other pass can
 * make.
 *
 * That is the whole design of this case: a check that the observation "looks
 * right" would pass with `augment` or `derive` missing, since both of them
 * write fields whose empty value is also a legitimate answer.
 */
static void the_whole_of_an_observation(void)
{
	machine_t                      machine;
	script_t                       script;
	ncfg_observe_replay_t          replay;
	ncfg_observe_kernel_t          kernel;
	ncfg_observe_roots_t           roots = fixture_roots();
	ncfg_observed_t               *observed = NULL;
	const ncfg_observed_link_t    *br0;
	const ncfg_observed_address_t *address;
	char                           err[NCFG_ERROR_MAX];

	machine_init(&machine);
	memset(&script, 0, sizeof(script));
	queue_machine(&script, &machine);
	kernel_of(&kernel, &replay, &script);

	if (!check(ncfg_observe_current_from(&kernel, NULL, NULL, run_dir, &roots, NULL, NULL, &observed, err,
	    sizeof(err)), "the kernel, the record and the files become one observation") ||
	    !observed) {
		detail("it said", err);
		machine_free(&machine);
		return;
	}

	/* collect: what the dumps said. */
	check(observed->link_count == 2u, "collect: both links are in it");
	check(observed->address_count == 1u && observed->route_count == 1u,
	    "and the address and the route the dumps carried");

	/* build: what the record said, which the kernel could not have. */
	br0 = ncfg_observed_link(observed, "br0");
	check(br0 && br0->ownership == NCFG_OWNERSHIP_OURS,
	    "build: a link the record says netcfgd created is ours");
	check(ncfg_observed_link(observed, "eth0") &&
	    ncfg_observed_link(observed, "eth0")->ownership == NCFG_OWNERSHIP_UNKNOWN,
	    "and one nobody has a record of is unknown");
	address = find_address(observed, "192.0.2.10/24");
	if (check(address != NULL, "and the tagged address is in the observation")) {
		check(address->ownership == NCFG_OWNERSHIP_OURS,
		    "which the kernel's tag makes netcfgd's");
		/*
		 * The discriminating one. `ncfg_observe_tagged_origin` answers
		 * `static` for exactly this tag, so a prior whose origin list never
		 * arrived reads `static` here and looks perfectly reasonable.
		 */
		check(address->origin.has && address->origin.value == NCFG_ORIGIN_DHCP4,
		    "and whose origin is the record's dhcp4 rather than the tag's static");
	}
	check(observed->hook_state_count == 1u,
	    "build: the hook state the record carried was handed over");
	check(observed->backend_count == 1u && observed->backends[0].interface &&
	    strcmp(observed->backends[0].interface, "eth0") == 0,
	    "and the backend, which is the list six observation passes walk");
	check(observed->dns_count == 1u && observed->dns[0].scope &&
	    strcmp(observed->dns[0].scope, "eth0") == 0,
	    "and the delivered dns scope, which is what stops a re-delivery every pass");
	check(observed->delegation_count == 1u,
	    "and the delegated prefix, which is in no dump and in no owned.json");
	check(observed->report_count == 1u, "and what a helper reported about wan0");

	/* augment_host: the files under the three roots. */
	check(observed->hostname && strcmp(observed->hostname, "fixture-host") == 0,
	    "augment: the hostname is read from the fixture's /proc, trimmed");

	/* derive: the answers computed from all three. */
	check(observed->inventory_count == 2u,
	    "derive: the link inventory has an entry per link");
	check(observed->connectivity != NULL, "and a connectivity verdict was reached");

	ncfg_observed_free(observed);
	machine_free(&machine);
}

/*
 * The document reaches `derive`, and NULL is an ordinary answer rather than a
 * failure.
 *
 * Two observations of one machine, differing only in whether a document was
 * handed in. The linkset is the thing only the document can produce, so it is
 * what tells them apart -- and the second half is the case `ncfg status` on a
 * configuration that has stopped compiling actually takes.
 */
static void the_document_is_wanted_and_not_required(void)
{
	static const char     text[] =
	    "{\"schema_version\":{\"major\":1,\"minor\":1},\"generated_by\":\"current_test\","
	    "\"globals\":{},\"devices\":[],\"interfaces\":[],\"networks\":[],"
	    "\"bluetooth\":[],\"rules\":[],\"access_points\":[],"
	    "\"linksets\":[{\"name\":\"uplink\",\"members\":[\"eth0\"]}]}";
	machine_t             machine;
	script_t              script;
	ncfg_observe_replay_t replay;
	ncfg_observe_kernel_t kernel;
	ncfg_observe_roots_t  roots = fixture_roots();
	ncfg_document_t      *document;
	ncfg_observed_t      *with = NULL;
	ncfg_observed_t      *without = NULL;
	char                  err[NCFG_ERROR_MAX];

	document = ncfg_document_read(text, strlen(text), err, sizeof(err));
	if (!check(document != NULL, "a document naming one linkset")) {
		detail("it said", err);
		return;
	}

	machine_init(&machine);
	memset(&script, 0, sizeof(script));
	queue_machine(&script, &machine);
	kernel_of(&kernel, &replay, &script);
	check(ncfg_observe_current_from(&kernel, NULL, NULL, run_dir, &roots, NULL, document, &with, err,
	    sizeof(err)), "an observation taken against a document");

	memset(&script, 0, sizeof(script));
	queue_machine(&script, &machine);
	kernel_of(&kernel, &replay, &script);
	check(ncfg_observe_current_from(&kernel, NULL, NULL, run_dir, &roots, NULL, NULL, &without, err,
	    sizeof(err)), "and one taken with no document at all");

	/*
	 * The linkset is what only the document can produce, so it is what tells
	 * the two apart. A check on the links would pass with the document
	 * dropped on the floor -- the kernel half is identical either way, which
	 * is the point of the second assertion.
	 */
	check(with && with->linkset_count == 1u,
	    "the document reaches derive: the linkset it names was chosen");
	check(without && without->linkset_count == 0u,
	    "and with no document there is no linkset, which is an answer not a failure");
	check(with && without && with->link_count == without->link_count,
	    "while the machine is seen the same way either way");

	ncfg_observed_free(with);
	ncfg_observed_free(without);
	ncfg_document_free(document);
	machine_free(&machine);
}

/*
 * A dump that fails, fails the whole observation -- and leaves nothing behind.
 *
 * `*out` is NULL on the way out, which is the half a caller acts on: the
 * daemon keeps its previous observation on a failure, and a pointer left
 * pointing at half of one would be the observation it kept.
 */
static void a_round_that_goes_wrong(void)
{
	machine_t             machine;
	script_t              script;
	ncfg_observe_replay_t replay;
	ncfg_observe_kernel_t kernel;
	ncfg_observe_roots_t  roots = fixture_roots();
	ncfg_observed_t      *observed = (ncfg_observed_t *)&script;
	char                  err[NCFG_ERROR_MAX];

	machine_init(&machine);
	memset(&script, 0, sizeof(script));
	queue(&script, &machine.links);
	queue_failure(&script, ENOBUFS);
	kernel_of(&kernel, &replay, &script);

	err[0] = '\0';
	check(!ncfg_observe_current_from(&kernel, NULL, NULL, run_dir, &roots, NULL, NULL, &observed, err,
	    sizeof(err)), "a dump that fails fails the observation");
	check(observed == NULL, "and nothing is left in the caller's pointer");
	check(err[0] != '\0', "and it says what went wrong");
	machine_free(&machine);
}

/* Every argument that is not optional, refused by name rather than crashed
 * on. The daemon installs this seam once and a NULL through it is a null
 * dereference in a loop nobody is watching. */
static void the_arguments_that_are_refused(void)
{
	ncfg_observe_kernel_t kernel;
	ncfg_observe_replay_t replay;
	script_t              script;
	ncfg_observe_roots_t  roots = fixture_roots();
	ncfg_observed_t      *observed = NULL;

	memset(&script, 0, sizeof(script));
	kernel_of(&kernel, &replay, &script);
	check(!ncfg_observe_current_from(&kernel, NULL, NULL, run_dir, &roots, NULL, NULL, NULL, NULL, 0),
	    "an observation with nowhere to put it is refused");
	check(!ncfg_observe_current_from(NULL, NULL, NULL, run_dir, &roots, NULL, NULL, &observed, NULL, 0),
	    "and one with no round of dumps");
	check(!ncfg_observe_current_from(&kernel, NULL, NULL, NULL, &roots, NULL, NULL, &observed, NULL, 0),
	    "and one with no run directory to read the record out of");
	check(!ncfg_observe_current_from(&kernel, NULL, NULL, run_dir, NULL, NULL, NULL, &observed, NULL, 0),
	    "and one with no roots to read under");
	check(!ncfg_observe_current(run_dir, &roots, NULL, NULL, NULL, NULL, 0),
	    "the socket form refuses the same way");
	check(!ncfg_observe_source_machine(NULL, run_dir, NULL, NULL, 0),
	    "and a source with nowhere to put it");
	check(!ncfg_observe_source_observe(NULL, NULL, &observed, NULL, 0),
	    "an observer installed with no source is refused");
	check(!ncfg_observe_source_observe(NULL, NULL, NULL, NULL, 0),
	    "and so is one with nowhere to put the answer");
}

/* ------------------------------------------------------------------------ *
 * The seam the daemon installs
 * ------------------------------------------------------------------------ */

/*
 * It is `ncfg_daemon_observe_fn`, and the compiler is what says so.
 *
 * `observe.h` may not name that type -- `daemon.h` is the layer above it, and
 * an include pointing back down would invert the order 0263 sets out -- so the
 * agreement between the two signatures is checked here, where both headers are
 * in scope. A drift in either is a build that fails rather than a seam nothing
 * can be installed in.
 */
static void the_adapter_is_the_daemon_s_seam(void)
{
	ncfg_daemon_observe_fn seam = ncfg_observe_source_observe;

	check(seam == ncfg_observe_source_observe,
	    "the adapter has ncfg_daemon_observe_fn's signature, per the compiler");
}

/*
 * A source, driven through the seam and then through the daemon that holds it.
 *
 * `ncfg_daemon_state_reobserve` is the call the loop makes on every tick, and
 * driving it here is what proves the adapter is installable rather than merely
 * assignable: the state calls it, keeps what came back, and answers whether the
 * link set moved.
 */
static void a_source_is_what_the_daemon_observes_through(void)
{
	machine_t             machine;
	script_t              script;
	ncfg_observe_replay_t replay;
	ncfg_observe_source_t source;
	ncfg_daemon_state_t   state;
	ncfg_observed_t      *observed = NULL;
	int                   moved = 0;
	char                  err[NCFG_ERROR_MAX];

	machine_init(&machine);
	memset(&source, 0, sizeof(source));
	(void)snprintf(source.run_dir, sizeof(source.run_dir), "%s", run_dir);
	source.roots = fixture_roots();
	memset(&script, 0, sizeof(script));
	queue_machine(&script, &machine);
	kernel_of(&source.kernel, &replay, &script);

	if (check(ncfg_observe_source_observe(&source, NULL, &observed, err, sizeof(err)),
	    "a source with a stand-in kernel observes through the seam") && observed) {
		check(observed->hostname && strcmp(observed->hostname, "fixture-host") == 0,
		    "and reads the run directory and the roots the source named");
	} else {
		detail("it said", err);
	}
	ncfg_observed_free(observed);

	/* And through the thing that holds the seam. */
	memset(&script, 0, sizeof(script));
	queue_machine(&script, &machine);
	if (!check(ncfg_daemon_state_init(&state, run_dir, run_dir, run_dir, err, sizeof(err)),
	    "a daemon state over the fixture")) {
		detail("it said", err);
		machine_free(&machine);
		return;
	}
	state.observe = ncfg_observe_source_observe;
	state.observe_context = &source;
	check(ncfg_daemon_state_reobserve(&state, &moved, err, sizeof(err)),
	    "and the daemon reobserves through it");
	check(state.observed && state.observed->link_count == 2u,
	    "keeping what the seam handed back");
	check(moved == 1, "and reporting that the link set moved, there having been none");
	ncfg_daemon_state_free(&state);
	machine_free(&machine);
}

/*
 * `ncfg_observe_source_machine` resolves once, from the environment.
 *
 * The run directory is `ncfg_state_resolve_dir`'s answer and the roots are
 * `ncfg_observe_roots_default`'s, so a test that set the variables reads them
 * back here rather than anything falling through to the machine's own `/proc`.
 */
static void a_source_pointed_at_this_machine(void)
{
	ncfg_observe_source_t source;
	char                  err[NCFG_ERROR_MAX];

	if (setenv(NCFG_OBSERVE_PROC_ROOT_ENV, proc_root, 1) != 0 ||
	    setenv(NCFG_OBSERVE_SYS_ROOT_ENV, sys_root, 1) != 0) {
		check(0, "the fixture roots can be put in the environment");
		return;
	}
	check(ncfg_observe_source_machine(&source, run_dir, NULL, err, sizeof(err)),
	    "a source is resolved for this machine");
	check(strcmp(source.run_dir, run_dir) == 0,
	    "the run directory it was handed is the one it holds");
	check(strcmp(source.roots.proc, proc_root) == 0,
	    "and /proc comes from the environment, read once");
	check(source.kernel.exchange == NULL,
	    "and it installs no stand-in, which is this machine's own socket");

	/* And with nothing named, the default -- asserted by reading the constant
	 * rather than by letting anything go near it. */
	check(ncfg_observe_source_machine(&source, NULL, NULL, err, sizeof(err)) &&
	    strcmp(source.run_dir, NCFG_RUN_DIR_DEFAULT) == 0,
	    "and with no run directory named, state.h's default");
	(void)unsetenv(NCFG_OBSERVE_PROC_ROOT_ENV);
	(void)unsetenv(NCFG_OBSERVE_SYS_ROOT_ENV);
}

/*
 * The one check that opens a socket, behind `NCFG_OBSERVE_LIVE=1`.
 *
 * `collect_test.c`'s arrangement, for its reason and one more: what this adds
 * over that one is the three file-reading passes and `derive`, which is the
 * half that cannot be exercised against a replay and the machine's own `/proc`
 * at the same time. It sends nothing but the seven dumps, which are `GET`s,
 * and it reads the machine's real run directory -- so it asserts only what is
 * true of every Linux machine.
 */
static void the_live_check(void)
{
	ncfg_observe_source_t source;
	ncfg_observed_t      *observed = NULL;
	const char           *live = getenv("NCFG_OBSERVE_LIVE");
	char                  err[NCFG_ERROR_MAX];

	if (!live || strcmp(live, "1") != 0) {
		check(1, "the live observation is skipped; set NCFG_OBSERVE_LIVE=1 to run it");
		return;
	}
	if (!check(ncfg_observe_source_machine(&source, NULL, NULL, err, sizeof(err)),
	    "a source for this machine")) {
		return;
	}
	if (!check(ncfg_observe_source_observe(&source, NULL, &observed, err, sizeof(err)),
	    "a live observation through the seam") || !observed) {
		detail("it said", err);
		return;
	}
	check(ncfg_observed_link(observed, "lo") != NULL, "finds this machine's loopback");
	check(observed->hostname != NULL && observed->hostname[0] != '\0',
	    "and its hostname");
	check(observed->inventory_count == observed->link_count,
	    "and derived an inventory entry per link");
	printf("  %zu link(s), %zu address(es), %zu route(s)\n", observed->link_count,
	    observed->address_count, observed->route_count);
	ncfg_observed_free(observed);
}

/* ------------------------------------------------------------------------ *
 * The nftables round
 * ------------------------------------------------------------------------ */

/* A queue of nftables answers, and the seam over it. Two questions are asked
 * in a fixed order -- the rules first, then the chains -- so what is queued
 * first is what the uplinks are read from. */
typedef struct {
	script_t              script;
	ncfg_observe_replay_t replay;
	ncfg_observe_kernel_t kernel;
	ncfg_buf_t            rules;
	ncfg_buf_t            chains;
} nft_t;

static void nft_init(nft_t *nft)
{
	memset(nft, 0, sizeof(*nft));
	ncfg_buf_init(&nft->rules, 0);
	ncfg_buf_init(&nft->chains, 0);
}

static void nft_ready(nft_t *nft)
{
	queue(&nft->script, &nft->rules);
	queue(&nft->script, &nft->chains);
	kernel_of(&nft->kernel, &nft->replay, &nft->script);
}

static void nft_free(nft_t *nft)
{
	ncfg_buf_free(&nft->rules);
	ncfg_buf_free(&nft->chains);
}

/* What the observation says about NAT, given one machine and one ruleset. */
static ncfg_observed_t *observed_with(script_t *script, const machine_t *machine, nft_t *nft,
    const char *what)
{
	ncfg_observe_replay_t replay;
	ncfg_observe_kernel_t kernel;
	ncfg_observe_roots_t  roots = fixture_roots();
	ncfg_observed_t      *observed = NULL;
	char                  err[NCFG_ERROR_MAX];

	memset(script, 0, sizeof(*script));
	queue_machine(script, machine);
	kernel_of(&kernel, &replay, script);
	err[0] = '\0';
	if (!check(ncfg_observe_current_from(&kernel, nft ? &nft->kernel : NULL, NULL, run_dir, &roots, NULL,
	    NULL, &observed, err, sizeof(err)), what)) {
		detail("it said", err);
		return NULL;
	}
	return observed;
}

static int names_are(char *const *names, size_t count, const char *joined)
{
	char written[256];
	size_t at;
	size_t length = 0;

	written[0] = '\0';
	for (at = 0; at < count && length < sizeof(written); at++) {
		length += (size_t)snprintf(written + length, sizeof(written) - length, "%s%s",
		    length ? " " : "", names[at] ? names[at] : "(null)");
	}
	return strcmp(written, joined) == 0;
}

/*
 * The uplinks netcfgd's table masquerades, and the tables that fight it.
 *
 * **Sorted and deduplicated is the assertion rather than a tidiness.** The
 * planner sorts the document's uplinks and compares the two lists in order, so
 * an observation in the kernel's order would differ from a machine that is
 * already right -- and `nat.replace` would be planned on every pass for ever,
 * which is exactly what an empty list did before this pass existed.
 */
static void the_nat_the_kernel_holds(void)
{
	machine_t        machine;
	script_t         script;
	nft_t            nft;
	ncfg_observed_t *observed;

	machine_init(&machine);
	nft_init(&nft);
	/* Out of order and with a repeat, which is what a kernel is free to
	 * send: a rule is identified by a handle and nothing sorts them. */
	append_uplink_rule(&nft.rules, "wan1");
	append_uplink_rule(&nft.rules, "wan0");
	append_uplink_rule(&nft.rules, "wan0");
	append_done(&nft.rules);
	append_chain(&nft.chains, "fw4", "srcnat", "nat", NF_INET_POST_ROUTING);
	append_chain(&nft.chains, NCFG_NFT_TABLE, NCFG_NFT_CHAIN, "nat", NF_INET_POST_ROUTING);
	append_chain(&nft.chains, "fw4", "srcnat_lan", "nat", NF_INET_POST_ROUTING);
	append_chain(&nft.chains, "dockerish", "prerouting", "nat", NF_INET_PRE_ROUTING);
	append_chain(&nft.chains, "fw4", "helper", "nat", -1);
	append_done(&nft.chains);
	nft_ready(&nft);

	observed = observed_with(&script, &machine, &nft, "the nftables round joins the round of dumps");
	if (observed) {
		check(observed->nat_count == 2u &&
		    names_are(observed->nat, observed->nat_count, "wan0 wan1"),
		    "the uplinks netcfgd masquerades are read back, sorted and deduplicated");
		check(observed->nat_conflict_count == 1u &&
		    names_are(observed->nat_conflicts, observed->nat_conflict_count, "fw4"),
		    "one conflicting table is named once however many chains it has");
	}
	ncfg_observed_free(observed);
	nft_free(&nft);
	machine_free(&machine);
}

/*
 * The three ways a chain is not a conflict, each of which would be a warning
 * an operator cannot act on.
 *
 * netcfgd's own chain is the one that would be reported on every machine
 * netcfgd manages; a `nat` chain at prerouting is destination NAT and
 * translates nothing on the way out; a regular chain has no hook at all. They
 * are asserted together because a check that only had the first would pass
 * with the hook comparison inverted.
 */
static void the_chains_that_are_not_a_conflict(void)
{
	machine_t        machine;
	script_t         script;
	nft_t            nft;
	ncfg_observed_t *observed;

	machine_init(&machine);
	nft_init(&nft);
	append_done(&nft.rules);
	append_chain(&nft.chains, NCFG_NFT_TABLE, NCFG_NFT_CHAIN, "nat", NF_INET_POST_ROUTING);
	append_chain(&nft.chains, "fw4", "mangle", "filter", NF_INET_POST_ROUTING);
	append_chain(&nft.chains, "fw4", "dstnat", "nat", NF_INET_PRE_ROUTING);
	append_chain(&nft.chains, "fw4", "helper", "nat", -1);
	append_done(&nft.chains);
	nft_ready(&nft);

	observed = observed_with(&script, &machine, &nft,
	    "a machine whose only source NAT is netcfgd's own");
	if (observed) {
		check(observed->nat_conflict_count == 0u,
		    "netcfgd's own chain, a filter chain, a prerouting one and a regular one "
		    "are no conflict");
		check(observed->nat_count == 0u,
		    "and a table with no rules in it masquerades nothing");
	}
	ncfg_observed_free(observed);
	nft_free(&nft);
	machine_free(&machine);
}

/*
 * A kernel that will not answer is not a failure, and neither is a seam that
 * was never installed.
 *
 * No `nf_tables`, a netlink this process may not ask and a machine where
 * netcfgd never installed a table are one answer to a planner -- no NAT is
 * installed -- which is what `observed.h` says where the field is declared. An
 * observation refused over it would be a `ncfg status` that fails on a kernel
 * built without a feature nobody asked for.
 */
static void a_kernel_that_will_not_answer(void)
{
	machine_t        machine;
	script_t         script;
	nft_t            nft;
	ncfg_observed_t *observed;

	machine_init(&machine);
	nft_init(&nft);
	memset(&nft.script, 0, sizeof(nft.script));
	queue_failure(&nft.script, EPERM);
	queue_failure(&nft.script, EPERM);
	kernel_of(&nft.kernel, &nft.replay, &nft.script);

	observed = observed_with(&script, &machine, &nft,
	    "a netfilter socket that refuses does not fail the observation");
	if (observed) {
		check(observed->nat_count == 0u && observed->nat_conflict_count == 0u,
		    "and reports no NAT installed and no conflicting table");
		check(observed->link_count == 2u,
		    "while the rest of the machine is observed as usual");
	}
	ncfg_observed_free(observed);

	observed = observed_with(&script, &machine, NULL,
	    "and a caller that installed no netfilter seam at all");
	if (observed) {
		check(observed->nat_count == 0u && observed->nat_conflict_count == 0u,
		    "asks nothing and says so with two empty lists");
	}
	ncfg_observed_free(observed);
	nft_free(&nft);
	machine_free(&machine);
}

/*
 * A payload that will not read is skipped, and an answer past the ceiling is
 * refused.
 *
 * The two halves are the same distinction `collect.c` draws and are drawn
 * differently here on purpose: a rule netcfgd did not write is an ordinary
 * answer to a dump the kernel was asked to filter and is counted, while a
 * chain holding more masquerade rules than an observation carries is input to
 * a planner and is refused with a sentence. A truncated list would plan a
 * machine back to a state nobody asked for.
 */
static void a_payload_that_will_not_read_and_an_answer_too_large(void)
{
	machine_t             machine;
	script_t              script;
	nft_t                 nft;
	ncfg_observe_replay_t replay;
	ncfg_observe_kernel_t kernel;
	ncfg_observe_roots_t  roots = fixture_roots();
	ncfg_observed_t      *observed = NULL;
	char                  err[NCFG_ERROR_MAX];

	machine_init(&machine);
	nft_init(&nft);
	/* A chain record where a rule was asked for: the reader refuses it,
	 * because a rule netcfgd did not write is not netcfgd's to describe. */
	append_chain(&nft.rules, "fw4", "srcnat", "nat", NF_INET_POST_ROUTING);
	append_uplink_rule(&nft.rules, "wan0");
	append_done(&nft.rules);
	append_done(&nft.chains);
	nft_ready(&nft);

	observed = observed_with(&script, &machine, &nft,
	    "a dump carrying a payload that is not a masquerade rule");
	if (observed) {
		check(observed->nat_count == 1u &&
		    names_are(observed->nat, observed->nat_count, "wan0"),
		    "the rule that reads is kept and the one that does not is skipped");
	}
	ncfg_observed_free(observed);
	observed = NULL;
	nft_free(&nft);

	/* And the ceiling, which is a field so that a test can reach it: the
	 * kernel will not produce an oversized answer on demand. */
	nft_init(&nft);
	append_uplink_rule(&nft.rules, "wan0");
	append_uplink_rule(&nft.rules, "wan1");
	append_done(&nft.rules);
	append_done(&nft.chains);
	nft_ready(&nft);
	nft.kernel.records_max = 1u;

	memset(&script, 0, sizeof(script));
	queue_machine(&script, &machine);
	kernel_of(&kernel, &replay, &script);
	err[0] = '\0';
	check(!ncfg_observe_current_from(&kernel, &nft.kernel, NULL, run_dir, &roots, NULL, NULL, &observed,
	    err, sizeof(err)), "more masquerade rules than an observation holds is refused");
	check(observed == NULL, "and nothing is left in the caller's pointer");
	check(strstr(err, "1") != NULL, "and the refusal names the number");
	nft_free(&nft);
	machine_free(&machine);
}

/* ------------------------------------------------------------------------ *
 * The offloads round
 * ------------------------------------------------------------------------ */

/*
 * The third seam, checked here for the reason the second one is: what
 * `observe_offloads_test.c` cannot see is whether the pass is *called*.
 *
 * It drives `ncfg_observe_offloads_from` directly, so deleting the one line in
 * `ncfg_observe_current_from` that reaches it would leave every one of its
 * cases green and every machine reporting no offload on anything -- which is
 * exactly the state this wave found. That line is what this asserts, and it is
 * the one property that belongs in this file rather than that one.
 */

/* Any runtime id but zero, which `ncfg_genl_build_request` refuses. */
#define ETHTOOL_FAMILY_ID 23u

/* The first kernel feature name of one offload field, from the model's table
 * rather than spelled again here. */
static const char *offload_name(int field)
{
	size_t             count = 0;
	const char *const *names = ncfg_offload_field_names(field, &count);

	return (names && count > 0) ? names[0] : "";
}

/* What the controller answers a `GETFAMILY` for `ethtool` with. */
static void append_ethtool_family(ncfg_buf_t *out)
{
	ncfg_genl_header_t header;
	ncfg_buf_t         body;
	ncfg_buf_t         attrs;
	uint16_t           id = ETHTOOL_FAMILY_ID;

	header.cmd = CTRL_CMD_NEWFAMILY;
	header.version = 2;
	ncfg_buf_init(&body, 0);
	ncfg_buf_init(&attrs, 0);
	ncfg_genl_header_encode(&header, &body);
	ncfg_wire_attr_put(&attrs, CTRL_ATTR_FAMILY_ID, &id, sizeof(id));
	ncfg_wire_attr_put_str(&attrs, CTRL_ATTR_FAMILY_NAME, NCFG_ETHTOOL_FAMILY);
	append_message(out, GENL_ID_CTRL, &body, &attrs);
	ncfg_buf_free(&body);
	ncfg_buf_free(&attrs);
}

/* One `FEATURES_GET` reply naming one active feature, or none. The bitset
 * carries `NOMASK` because `ACTIVE` is a list; `ethtool.h` says what reading
 * the other form as one would mean. */
static void append_active(ncfg_buf_t *out, const char *device, const char *feature)
{
	ncfg_genl_header_t header;
	ncfg_buf_t         body;
	ncfg_buf_t         attrs;
	ncfg_buf_t         nest;
	ncfg_buf_t         bitset;
	ncfg_buf_t         bits;

	header.cmd = ETHTOOL_MSG_FEATURES_GET_REPLY;
	header.version = 1;
	ncfg_buf_init(&body, 0);
	ncfg_buf_init(&attrs, 0);
	ncfg_buf_init(&nest, 0);
	ncfg_buf_init(&bits, 0);
	ncfg_buf_init(&bitset, 0);
	ncfg_genl_header_encode(&header, &body);
	ncfg_wire_attr_put_str(&nest, ETHTOOL_A_HEADER_DEV_NAME, device);
	ncfg_wire_attr_put_nested(&attrs, ETHTOOL_A_FEATURES_HEADER, &nest);
	if (feature) {
		ncfg_buf_t bit;

		ncfg_buf_init(&bit, 0);
		ncfg_wire_attr_put_str(&bit, ETHTOOL_A_BITSET_BIT_NAME, feature);
		ncfg_wire_attr_put_nested(&bits, ETHTOOL_A_BITSET_BITS_BIT, &bit);
		ncfg_buf_free(&bit);
	}
	ncfg_wire_attr_put(&bitset, ETHTOOL_A_BITSET_NOMASK, NULL, 0);
	ncfg_wire_attr_put_nested(&bitset, ETHTOOL_A_BITSET_BITS, &bits);
	ncfg_wire_attr_put_nested(&attrs, ETHTOOL_A_FEATURES_ACTIVE, &bitset);
	append_message(out, ETHTOOL_FAMILY_ID, &body, &attrs);
	ncfg_buf_free(&body);
	ncfg_buf_free(&attrs);
	ncfg_buf_free(&nest);
	ncfg_buf_free(&bits);
	ncfg_buf_free(&bitset);
}

static void the_offloads_the_kernel_reports(void)
{
	machine_t                   machine;
	script_t                    script;
	script_t                    asked;
	ncfg_observe_replay_t       replay;
	ncfg_observe_replay_t       genl_replay;
	ncfg_observe_kernel_t       kernel;
	ncfg_observe_kernel_t       genl;
	ncfg_observe_roots_t        roots = fixture_roots();
	ncfg_buf_t                  family;
	ncfg_buf_t                  first;
	ncfg_buf_t                  second;
	ncfg_observed_t            *observed = NULL;
	const ncfg_observed_link_t *link;
	char                        err[NCFG_ERROR_MAX];

	machine_init(&machine);
	ncfg_buf_init(&family, 0);
	ncfg_buf_init(&first, 0);
	ncfg_buf_init(&second, 0);
	append_ethtool_family(&family);
	/* One request per interface, in the order the observation holds them --
	 * **sorted by name**, which is `br0` and then `eth0` rather than the order
	 * the link dump was written in. The first answer carries no active
	 * feature, which is what keeps this a check about which answer reached
	 * which link rather than about whether any answer arrived at all. */
	append_active(&first, "br0", NULL);
	append_active(&second, "eth0", offload_name(NCFG_OFFLOAD_GRO));
	memset(&asked, 0, sizeof(asked));
	queue(&asked, &family);
	queue(&asked, &first);
	queue(&asked, &second);
	kernel_of(&genl, &genl_replay, &asked);

	memset(&script, 0, sizeof(script));
	queue_machine(&script, &machine);
	kernel_of(&kernel, &replay, &script);
	err[0] = '\0';
	if (!check(ncfg_observe_current_from(&kernel, NULL, &genl, run_dir, &roots, NULL, NULL,
	    &observed, err, sizeof(err)),
	    "the offloads round joins the round of dumps")) {
		detail("it said", err);
	}
	link = observed ? ncfg_observed_link(observed, "eth0") : NULL;
	check(link && link->offload_count == 1u && link->offloads[0] &&
	    strcmp(link->offloads[0], offload_name(NCFG_OFFLOAD_GRO)) == 0,
	    "and a composed observation carries what ethtool said about each link");
	link = observed ? ncfg_observed_link(observed, "br0") : NULL;
	check(link && link->offload_count == 0u,
	    "the interface whose answer named nothing carries nothing");
	ncfg_observed_free(observed);
	ncfg_buf_free(&family);
	ncfg_buf_free(&first);
	ncfg_buf_free(&second);
	machine_free(&machine);
}

int main(void)
{
	make_fixture();

	the_whole_of_an_observation();
	the_nat_the_kernel_holds();
	the_offloads_the_kernel_reports();
	the_chains_that_are_not_a_conflict();
	a_kernel_that_will_not_answer();
	a_payload_that_will_not_read_and_an_answer_too_large();
	the_document_is_wanted_and_not_required();
	a_round_that_goes_wrong();
	the_arguments_that_are_refused();
	the_adapter_is_the_daemon_s_seam();
	a_source_is_what_the_daemon_observes_through();
	a_source_pointed_at_this_machine();
	the_live_check();

	remove_fixture();
	if (failures) {
		printf("%d check(s) failed\n", failures);
		return 1;
	}
	printf("current_test: all checks passed\n");
	return 0;
}
