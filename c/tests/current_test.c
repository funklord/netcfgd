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
#include "ncfg/netlink.h"
#include "ncfg/observed.h"
#include "ncfg/state.h"
#include "ncfg/wire.h"

#include "testdir.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

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
	ncfg_owned_state_t  owned;
	ncfg_owned_object_t address;
	char               *created[1];
	char                err[NCFG_ERROR_MAX];

	memset(&owned, 0, sizeof(owned));
	memset(&address, 0, sizeof(address));
	created[0] = (char *)"br0";
	address.interface = (char *)"eth0";
	address.key = (char *)"192.0.2.10/24";
	address.origin = NCFG_ORIGIN_DHCP4;
	owned.created_links = created;
	owned.created_link_count = 1u;
	owned.addresses = &address;
	owned.address_count = 1u;
	if (!ncfg_owned_note_hook_state(&owned, "eth0", NCFG_HOOK_PHASE_POST_UP, "ran")) {
		printf("current_test: could not note a hook state\n");
		exit(1);
	}
	if (!ncfg_owned_write(run_dir, &owned, err, sizeof(err))) {
		printf("current_test: could not write the record: %s\n", err);
		exit(1);
	}
	/* Only the hook state was allocated here; the other three are this
	 * function's own storage and the record must not be asked to free them. */
	owned.created_links = NULL;
	owned.created_link_count = 0;
	owned.addresses = NULL;
	owned.address_count = 0;
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

	if (!check(ncfg_observe_current_from(&kernel, run_dir, &roots, NULL, &observed, err,
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
	check(ncfg_observe_current_from(&kernel, run_dir, &roots, document, &with, err,
	    sizeof(err)), "an observation taken against a document");

	memset(&script, 0, sizeof(script));
	queue_machine(&script, &machine);
	kernel_of(&kernel, &replay, &script);
	check(ncfg_observe_current_from(&kernel, run_dir, &roots, NULL, &without, err,
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
	check(!ncfg_observe_current_from(&kernel, run_dir, &roots, NULL, &observed, err,
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
	check(!ncfg_observe_current_from(&kernel, run_dir, &roots, NULL, NULL, NULL, 0),
	    "an observation with nowhere to put it is refused");
	check(!ncfg_observe_current_from(NULL, run_dir, &roots, NULL, &observed, NULL, 0),
	    "and one with no round of dumps");
	check(!ncfg_observe_current_from(&kernel, NULL, &roots, NULL, &observed, NULL, 0),
	    "and one with no run directory to read the record out of");
	check(!ncfg_observe_current_from(&kernel, run_dir, NULL, NULL, &observed, NULL, 0),
	    "and one with no roots to read under");
	check(!ncfg_observe_current(run_dir, &roots, NULL, NULL, NULL, 0),
	    "the socket form refuses the same way");
	check(!ncfg_observe_source_machine(NULL, run_dir, NULL, 0),
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
	check(ncfg_observe_source_machine(&source, run_dir, err, sizeof(err)),
	    "a source is resolved for this machine");
	check(strcmp(source.run_dir, run_dir) == 0,
	    "the run directory it was handed is the one it holds");
	check(strcmp(source.roots.proc, proc_root) == 0,
	    "and /proc comes from the environment, read once");
	check(source.kernel.exchange == NULL,
	    "and it installs no stand-in, which is this machine's own socket");

	/* And with nothing named, the default -- asserted by reading the constant
	 * rather than by letting anything go near it. */
	check(ncfg_observe_source_machine(&source, NULL, err, sizeof(err)) &&
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
	if (!check(ncfg_observe_source_machine(&source, NULL, err, sizeof(err)),
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

int main(void)
{
	make_fixture();

	the_whole_of_an_observation();
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
