/*
 * observe_test.c -- the observation, built from bytes and from a fixture
 * directory, and never from this machine.
 *
 * WHY NOTHING HERE OPENS A SOCKET
 *   The real netcfgd is configuring the network of the machine this is built
 *   on. A test that dumped the kernel would be asserting against whatever that
 *   machine happens to be doing, and one that opened a netlink socket as root
 *   would be one edit away from changing it. So the observer takes its input as
 *   a structure -- `ncfg_observe_snapshot_t` -- and every path it reads is a
 *   parameter. Both halves are exercised below against records this file fills
 *   in and a directory it makes, fills, asserts against and removes by name.
 *
 * WHAT IS ASSERTED, AND WHY EACH CASE IS HERE
 *   The Rust's own cases come across with the code, because the case is the
 *   expensive half. In particular:
 *
 *     * the five link-ownership cases, each of which is a way `/run` and the
 *       kernel can disagree about who made a link (0136);
 *     * the address-ownership ladder and its calibration, which is the one
 *       judgement in this module that can delete somebody's address (0002);
 *     * a route's protocol deciding ownership outright, with a DHCP client's
 *       route beside netcfgd's so that "ours" is not merely the only answer
 *       the fixture can give;
 *     * the rfkill search, with the platform button in the fixture as a decoy
 *       and an unreadable entry sorted in front of the match -- the two ways
 *       that search has been wrong (0062);
 *     * the probe ladder, and `derive` run twice across a stamped verdict,
 *       which is the defect the derived answers were split out for.
 *
 * WHAT IT MAKES AND WHAT IT REMOVES
 *   One directory under `TMPDIR`, from `mkdtemp`, and every path inside it is
 *   remembered as it is made and removed by name in reverse at the end. Nothing
 *   is removed by a pattern and nothing outside that directory is touched.
 */
#include "ncfg/base.h"
#include "ncfg/document.h"
#include "ncfg/observe.h"
#include "ncfg/observed.h"

#include "tempdir.h"

#include <linux/fib_rules.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static int failures;

/* Returns the condition, so that a case which cannot go on after a failure can
 * say so in one line rather than repeating the test. */
static int check(int condition, const char *what)
{
	printf("%-66s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
	return condition;
}

/* ------------------------------------------------------------------------ *
 * The fixture, made by name and removed by name
 * ------------------------------------------------------------------------ */

#define MADE_MAX 96
#define PATH_MAX_LOCAL 512

/* Every path this test made, in the order it made them, so that the cleanup
 * removes exactly those and nothing by a pattern. Directories and files are
 * kept apart because they come off in different ways. */
static char made_dirs[MADE_MAX][PATH_MAX_LOCAL];
static size_t made_dir_count;
static char made_files[MADE_MAX][PATH_MAX_LOCAL];
static size_t made_file_count;

static char root[PATH_MAX_LOCAL];

/* `mkdir -p` under the fixture root, remembering every level it creates. */
static int make_dirs(const char *relative)
{
	char   path[PATH_MAX_LOCAL];
	char   partial[PATH_MAX_LOCAL];
	size_t at;

	if (snprintf(path, sizeof(path), "%s/%s", root, relative) < 0) {
		return 0;
	}
	(void)snprintf(partial, sizeof(partial), "%s", path);
	for (at = strlen(root) + 1u; at <= strlen(path); at++) {
		char saved;

		if (path[at] != '/' && path[at] != '\0') {
			continue;
		}
		saved = partial[at];
		partial[at] = '\0';
		if (mkdir(partial, 0700) == 0) {
			if (made_dir_count >= MADE_MAX) {
				return 0;
			}
			(void)snprintf(made_dirs[made_dir_count++], PATH_MAX_LOCAL, "%s",
			    partial);
		}
		partial[at] = saved;
	}
	return 1;
}

/* A file under the fixture root, with its directory made first. */
static int make_file(const char *relative, const char *contents)
{
	char        path[PATH_MAX_LOCAL];
	char        directory[PATH_MAX_LOCAL];
	char       *cut;
	FILE       *file;
	size_t      length = strlen(contents);

	(void)snprintf(directory, sizeof(directory), "%s", relative);
	cut = strrchr(directory, '/');
	if (cut) {
		*cut = '\0';
		if (!make_dirs(directory)) {
			return 0;
		}
	}
	if (snprintf(path, sizeof(path), "%s/%s", root, relative) < 0 ||
	    made_file_count >= MADE_MAX) {
		return 0;
	}
	file = fopen(path, "wb");
	if (!file) {
		return 0;
	}
	if (length > 0u && fwrite(contents, 1u, length, file) != length) {
		(void)fclose(file);
		return 0;
	}
	if (fclose(file) != 0) {
		return 0;
	}
	(void)snprintf(made_files[made_file_count++], PATH_MAX_LOCAL, "%s", path);
	return 1;
}

static void remove_fixture(void)
{
	size_t at;

	for (at = made_file_count; at > 0u; at--) {
		if (unlink(made_files[at - 1u]) != 0) {
			printf("observe_test: could not remove %s\n", made_files[at - 1u]);
			failures++;
		}
	}
	for (at = made_dir_count; at > 0u; at--) {
		if (rmdir(made_dirs[at - 1u]) != 0) {
			printf("observe_test: could not remove %s\n", made_dirs[at - 1u]);
			failures++;
		}
	}
	if (root[0] && rmdir(root) != 0) {
		printf("observe_test: could not remove %s\n", root);
		failures++;
	}
}

/* ------------------------------------------------------------------------ *
 * Records a test writes
 * ------------------------------------------------------------------------ */

static ncfg_link_record_t link_record(uint32_t index, const char *name)
{
	ncfg_link_record_t record;

	memset(&record, 0, sizeof(record));
	record.index = index;
	(void)snprintf(record.name, sizeof(record.name), "%s", name);
	/* Unmarked and unrecorded: the fixture stands for a link netcfgd did not
	 * create, and the cases that want one of netcfgd's say so explicitly. */
	record.up = 1;
	record.carrier = 1;
	record.mtu = 1500u;
	return record;
}

static ncfg_address_record_t address_record(uint32_t index, const char *text, uint8_t prefix,
    int has_proto, uint8_t proto)
{
	ncfg_address_record_t record;
	char                  message[NCFG_ERROR_MAX];

	memset(&record, 0, sizeof(record));
	record.index = index;
	if (!ncfg_wire_ip_parse(text, &record.address, message, sizeof(message))) {
		printf("observe_test: %s is not an address (%s)\n", text, message);
		exit(1);
	}
	record.prefix_len = prefix;
	record.has_proto = has_proto;
	record.proto = proto;
	return record;
}

static ncfg_route_record_t route_record(uint32_t index, const char *gateway, uint32_t metric,
    uint8_t protocol)
{
	ncfg_route_record_t record;
	char                message[NCFG_ERROR_MAX];

	memset(&record, 0, sizeof(record));
	record.has_index = 1;
	record.index = index;
	record.table = 254u;
	record.protocol = protocol;
	if (metric > 0u) {
		record.has_metric = 1;
		record.metric = metric;
	}
	if (gateway && !ncfg_wire_ip_parse(gateway, &record.gateway, message, sizeof(message))) {
		printf("observe_test: %s is not a gateway (%s)\n", gateway, message);
		exit(1);
	}
	return record;
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

static const ncfg_observed_route_t *find_route(const ncfg_observed_t *observed,
    const char *interface)
{
	size_t at;

	for (at = 0; at < observed->route_count; at++) {
		if (strcmp(observed->routes[at].interface, interface) == 0) {
			return &observed->routes[at];
		}
	}
	return NULL;
}

/* The roots a test uses: the fixture, everywhere. Nothing here ever falls back
 * to the machine's own `/proc` or `/sys`. */
static ncfg_observe_roots_t fixture_roots(void)
{
	ncfg_observe_roots_t roots;

	memset(&roots, 0, sizeof(roots));
	(void)snprintf(roots.class_net, sizeof(roots.class_net), "%s/class/net", root);
	(void)snprintf(roots.proc, sizeof(roots.proc), "%s/proc", root);
	(void)snprintf(roots.sys, sizeof(roots.sys), "%s", root);
	return roots;
}

/* ------------------------------------------------------------------------ *
 * The three judgements
 * ------------------------------------------------------------------------ */

static void the_marks_are_one_number_wearing_three_shapes(void)
{
	/* The constant is spelled in three places -- the wire layer, the qdisc
	 * module and the filter handle -- because neither of those may depend on
	 * the model. If they ever disagree, netcfgd stamps one mark and looks
	 * for another, and every object it installs becomes foreign to it. */
	check(NCFG_WIRE_RTPROT_NETCFGD == 110u, "netcfgd's protocol number is 110");
	check((uint32_t)NCFG_WIRE_RTPROT_NETCFGD == (NCFG_QDISC_HANDLE >> 16),
	    "the qdisc handle carries the same number in its major");
	check((uint32_t)NCFG_WIRE_RTPROT_NETCFGD == NCFG_QDISC_FILTER_HANDLE,
	    "and so does the redirect filter's handle");
	check(strcmp(NCFG_OBSERVE_ALTNAME_PREFIX, "netcfgd:") == 0,
	    "a link netcfgd made is marked with `netcfgd:`");
}

static void link_ownership_cases(void)
{
	char *ours[] = { (char *)"netcfgd:br0" };
	char *renamed[] = { (char *)"netcfgd:whatever-it-was-called" };
	char *theirs[] = { (char *)"prettyname", (char *)"enp0s1" };

	/* The whole point: a restart deletes the record, and this must not
	 * change the answer. */
	check(ncfg_observe_link_ownership(ours, 1u, 0) == NCFG_OWNERSHIP_OURS,
	    "a link wearing our alternative name is ours with no record");
	/* The mark carries the name the link had when netcfgd created it, and a
	 * link can be renamed afterwards -- so the two disagree and the answer
	 * must not. The suffix here matches nothing, since the property is that
	 * the suffix is not consulted at all. */
	check(ncfg_observe_link_ownership(renamed, 1u, 0) == NCFG_OWNERSHIP_OURS,
	    "a renamed link is still ours");
	/* Additive: a link an older netcfgd created carries no alternative name
	 * and must not stop being netcfgd's on the day 0136 ships. */
	check(ncfg_observe_link_ownership(NULL, 0u, 1) == NCFG_OWNERSHIP_OURS,
	    "a recorded link with no mark is still ours");
	check(ncfg_observe_link_ownership(theirs, 2u, 0) == NCFG_OWNERSHIP_UNKNOWN,
	    "somebody else's alternative name does not make a link ours");
	/* netcfgd did not make eth0, and saying so positively would be a claim
	 * about every physical device on the machine. */
	check(ncfg_observe_link_ownership(NULL, 0u, 0) == NCFG_OWNERSHIP_UNKNOWN,
	    "an unmarked, unrecorded link is unknown rather than foreign");
}

static void address_ownership_cases(void)
{
	check(ncfg_observe_address_ownership(1, NCFG_WIRE_RTPROT_NETCFGD, 1, 0) ==
	    NCFG_OWNERSHIP_OURS, "our tag makes an address ours on a modern kernel");
	/* A stale record must not be able to claim back an address the kernel
	 * says belongs to somebody else. */
	check(ncfg_observe_address_ownership(1, 4u, 1, 1) == NCFG_OWNERSHIP_FOREIGN,
	    "another tag is foreign even where netcfgd recorded it");
	check(ncfg_observe_address_ownership(0, 0u, 1, 1) == NCFG_OWNERSHIP_FOREIGN,
	    "an untagged address is foreign on a modern kernel");
	/* The whole point of 0002's fallback being weaker: under-claiming costs
	 * convenience, over-claiming deletes an address somebody typed. */
	check(ncfg_observe_address_ownership(0, 0u, 0, 1) == NCFG_OWNERSHIP_UNKNOWN,
	    "the pre-5.18 fallback never reaches ours");
	check(ncfg_observe_address_ownership(0, 0u, 0, 0) == NCFG_OWNERSHIP_FOREIGN,
	    "and an unrecorded one there is foreign");
	check(!ncfg_ownership_may_remove(NCFG_OWNERSHIP_UNKNOWN),
	    "and unknown may not be removed");
}

static void the_tag_implies_an_origin(void)
{
	ncfg_optint_t tagged = ncfg_observe_tagged_origin(1, NCFG_WIRE_RTPROT_NETCFGD);
	ncfg_optint_t other = ncfg_observe_tagged_origin(1, 16u);
	ncfg_optint_t none = ncfg_observe_tagged_origin(0, 0u);

	/* Ownership survives the loss of `/run` because the kernel carries the
	 * tag; origin did not, and every teardown path gates on `static` before
	 * it gates on anything else -- so netcfgd could tell an address was its
	 * own and not that it was allowed to remove it. */
	check(tagged.has && tagged.value == NCFG_ORIGIN_STATIC,
	    "netcfgd's own tag implies a static origin");
	check(!other.has, "a DHCP client's tag implies nothing about netcfgd's sources");
	check(!none.has, "and an untagged object implies nothing at all");
}

/* ------------------------------------------------------------------------ *
 * A snapshot becoming a model
 * ------------------------------------------------------------------------ */

static void a_snapshot_becomes_a_model(void)
{
	ncfg_link_record_t      links[2] = { link_record(2u, "eth0"), link_record(3u, "br0") };
	ncfg_address_record_t   addresses[2] = {
		address_record(2u, "192.168.1.10", 24u, 1, NCFG_WIRE_RTPROT_NETCFGD),
		address_record(3u, "10.0.0.1", 24u, 1, 4u)
	};
	ncfg_route_record_t     routes[2] = {
		route_record(2u, "192.168.1.1", 100u, NCFG_WIRE_RTPROT_NETCFGD),
		/* A DHCP client's default route, beside netcfgd's, so that
		 * "ours" is not merely the only answer this fixture can give. */
		route_record(3u, "10.0.0.254", 200u, NCFG_DHCP_ROUTE_PROTO)
	};
	ncfg_observe_owned_t    owned[1] = {
		{ "eth0", "192.168.1.10/24", NCFG_ORIGIN_STATIC }
	};
	ncfg_observe_snapshot_t snapshot;
	ncfg_observe_prior_t    prior;
	ncfg_observe_roots_t    roots = fixture_roots();
	ncfg_observed_t        *observed = NULL;
	char                    message[NCFG_ERROR_MAX];

	memset(&snapshot, 0, sizeof(snapshot));
	memset(&prior, 0, sizeof(prior));
	snapshot.links = links;
	snapshot.link_count = 2u;
	snapshot.addresses = addresses;
	snapshot.address_count = 2u;
	snapshot.routes = routes;
	snapshot.route_count = 2u;
	snapshot.address_proto_supported = 1;
	prior.address_origins = owned;
	prior.address_origin_count = 1u;

	if (!check(ncfg_observe_build(&snapshot, &prior, &roots, &observed, message,
	    sizeof(message)), "a snapshot becomes an observation") || !observed) {
		return;
	}
	check(observed->link_count == 2u, "with one row per link");
	{
		const ncfg_observed_address_t *ours = find_address(observed, "192.168.1.10/24");
		const ncfg_observed_address_t *theirs = find_address(observed, "10.0.0.1/24");
		const ncfg_observed_route_t   *route = find_route(observed, "eth0");
		const ncfg_observed_route_t   *lease = find_route(observed, "br0");

		check(ours && strcmp(ours->interface, "eth0") == 0 &&
		    ours->ownership == NCFG_OWNERSHIP_OURS && ours->origin.has &&
		    ours->origin.value == NCFG_ORIGIN_STATIC,
		    "the address netcfgd installed is ours, and static");
		check(theirs && theirs->ownership == NCFG_OWNERSHIP_FOREIGN && !theirs->origin.has,
		    "somebody else's tag is foreign, with no origin to claim");
		check(route && strcmp(route->destination, "default") == 0 &&
		    route->ownership == NCFG_OWNERSHIP_OURS && route->origin.has &&
		    route->origin.value == NCFG_ORIGIN_STATIC,
		    "a route carrying netcfgd's protocol number is ours");
		check(lease && lease->ownership == NCFG_OWNERSHIP_FOREIGN && !lease->origin.has,
		    "and one carrying a DHCP client's is not");
		check(route && route->proto.has && route->proto.value == NCFG_WIRE_RTPROT_NETCFGD &&
		    route->table.has && route->table.value == 254 && !route->scope.has,
		    "a route reports its protocol and table, and no scope");
		check(route && route->via && strcmp(route->via, "192.168.1.1") == 0 &&
		    route->metric.has && route->metric.value == 100,
		    "and the gateway and metric the kernel gave it");
	}
	ncfg_observed_free(observed);
	ncfg_observe_prior_free(&prior);
}

static void names_are_resolved_or_dropped(void)
{
	ncfg_link_record_t      links[3] = { link_record(2u, "eth0"), link_record(3u, "br0"),
		link_record(4u, "eth1") };
	ncfg_address_record_t   orphan[1] = { address_record(77u, "10.0.0.1", 24u, 0, 0u) };
	ncfg_observe_snapshot_t snapshot;
	ncfg_observe_prior_t    prior;
	ncfg_observe_roots_t    roots = fixture_roots();
	ncfg_observed_t        *observed = NULL;
	char                    message[NCFG_ERROR_MAX];

	links[0].has_master = 1;
	links[0].master = 3u;
	/* An index this dump does not mention is a device in another namespace,
	 * which reads as "no parent netcfgd can talk about" rather than as a
	 * crash. */
	links[2].has_master = 1;
	links[2].master = 99u;

	memset(&snapshot, 0, sizeof(snapshot));
	memset(&prior, 0, sizeof(prior));
	snapshot.links = links;
	snapshot.link_count = 3u;
	snapshot.addresses = orphan;
	snapshot.address_count = 1u;

	if (!check(ncfg_observe_build(&snapshot, &prior, &roots, &observed, message,
	    sizeof(message)), "a master index becomes a name or nothing") || !observed) {
		return;
	}
	{
		const ncfg_observed_link_t *eth0 = ncfg_observed_link(observed, "eth0");
		const ncfg_observed_link_t *eth1 = ncfg_observed_link(observed, "eth1");

		check(eth0 && eth0->master && strcmp(eth0->master, "br0") == 0,
		    "an enslaved link names its master");
		check(eth1 && !eth1->master, "and an index nobody knows names nothing");
	}
	/* An address on an interface the link dump did not mention is dropped
	 * rather than attributed to the wrong interface. */
	check(observed->address_count == 0u, "an address with no matching link is dropped");
	ncfg_observed_free(observed);
	ncfg_observe_prior_free(&prior);
}

static void only_recorded_links_are_ours(void)
{
	ncfg_link_record_t      links[2] = { link_record(2u, "eth0"), link_record(3u, "br0") };
	char                   *created[1] = { (char *)"br0" };
	ncfg_observe_snapshot_t snapshot;
	ncfg_observe_prior_t    prior;
	ncfg_observe_roots_t    roots = fixture_roots();
	ncfg_observed_t        *observed = NULL;
	char                    message[NCFG_ERROR_MAX];

	memset(&snapshot, 0, sizeof(snapshot));
	memset(&prior, 0, sizeof(prior));
	snapshot.links = links;
	snapshot.link_count = 2u;
	prior.created_links = created;
	prior.created_link_count = 1u;

	if (!check(ncfg_observe_build(&snapshot, &prior, &roots, &observed, message,
	    sizeof(message)), "a record of what netcfgd created is read back") || !observed) {
		return;
	}
	check(ncfg_observed_link(observed, "br0")->ownership == NCFG_OWNERSHIP_OURS,
	    "a link netcfgd recorded creating is ours");
	check(ncfg_observed_link(observed, "eth0")->ownership == NCFG_OWNERSHIP_UNKNOWN,
	    "and a link nobody has a record of is unknown");
	ncfg_observed_free(observed);
	ncfg_observe_prior_free(&prior);
}

/*
 * The flag is a lower bound: a live 6.12 kernel reports no `IFA_PROTO` on any
 * address until netcfgd installs one, so a fresh system starts in the weak mode
 * and calibrates into the strong one.
 */
static void ownership_calibrates_once_we_own_an_address(void)
{
	ncfg_link_record_t      links[1] = { link_record(1u, "lo") };
	ncfg_address_record_t   fresh[1] = { address_record(1u, "127.0.0.1", 8u, 0, 0u) };
	ncfg_address_record_t   tagged[1] = {
		address_record(1u, "127.0.0.1", 8u, 1, NCFG_WIRE_RTPROT_NETCFGD)
	};
	ncfg_observe_owned_t    owned[1] = { { "lo", "127.0.0.1/8", NCFG_ORIGIN_STATIC } };
	ncfg_observe_snapshot_t snapshot;
	ncfg_observe_prior_t    prior;
	ncfg_observe_roots_t    roots = fixture_roots();
	ncfg_observed_t        *observed = NULL;
	char                    message[NCFG_ERROR_MAX];

	memset(&snapshot, 0, sizeof(snapshot));
	memset(&prior, 0, sizeof(prior));
	snapshot.links = links;
	snapshot.link_count = 1u;
	snapshot.addresses = fresh;
	snapshot.address_count = 1u;
	prior.address_origins = owned;
	prior.address_origin_count = 1u;

	if (ncfg_observe_build(&snapshot, &prior, &roots, &observed, message, sizeof(message))) {
		/* Recorded, but the kernel offered no tag: unknown, and not
		 * removable. */
		check(observed->addresses[0].ownership == NCFG_OWNERSHIP_UNKNOWN,
		    "a recorded address on a kernel with no tag is unknown");
		check(!observed->address_proto_supported,
		    "and the observation says which mechanism produced that");
		ncfg_observed_free(observed);
	} else {
		check(0, "a recorded address on a kernel with no tag is unknown");
	}
	snapshot.addresses = tagged;
	snapshot.address_proto_supported = 1;
	observed = NULL;
	if (ncfg_observe_build(&snapshot, &prior, &roots, &observed, message, sizeof(message))) {
		check(observed->addresses[0].ownership == NCFG_OWNERSHIP_OURS,
		    "and once one address comes back tagged, the same address is ours");
		ncfg_observed_free(observed);
	} else {
		check(0, "and once one address comes back tagged, the same address is ours");
	}
	ncfg_observe_prior_free(&prior);
}

/* ------------------------------------------------------------------------ *
 * The `tc` objects, whose ownership is a handle
 * ------------------------------------------------------------------------ */

static void a_tc_object_is_ours_by_handle_or_by_record(void)
{
	ncfg_link_record_t      links[3] = { link_record(2u, "eth0"), link_record(3u, "wan0"),
		link_record(4u, "ifb0") };
	ncfg_qdisc_record_t     roots_of[2];
	ncfg_observe_redirect_t redirects[2];
	char                   *recorded_qdisc[1] = { (char *)"old0" };
	ncfg_observe_snapshot_t snapshot;
	ncfg_observe_prior_t    prior;
	ncfg_observe_roots_t    roots = fixture_roots();
	ncfg_observed_t        *observed = NULL;
	char                    message[NCFG_ERROR_MAX];

	memset(roots_of, 0, sizeof(roots_of));
	roots_of[0].index = 2u;
	roots_of[0].handle = NCFG_QDISC_HANDLE;
	(void)snprintf(roots_of[0].kind, sizeof(roots_of[0].kind), "%s", "cake");
	roots_of[0].has_bandwidth = 1;
	roots_of[0].bandwidth_bits = 100000000u;
	roots_of[0].ingress = 1;
	roots_of[1].index = 3u;
	/* A handle the kernel assigned, which is what every interface netcfgd
	 * never touched carries. */
	roots_of[1].handle = 0u;
	(void)snprintf(roots_of[1].kind, sizeof(roots_of[1].kind), "%s", "fq_codel");

	memset(redirects, 0, sizeof(redirects));
	redirects[0].index = 2u;
	redirects[0].target = 4u;
	redirects[0].ours = 1;
	redirects[1].index = 3u;
	redirects[1].target = 4u;
	redirects[1].ours = 0;

	memset(&snapshot, 0, sizeof(snapshot));
	memset(&prior, 0, sizeof(prior));
	snapshot.links = links;
	snapshot.link_count = 3u;
	snapshot.qdisc_roots = roots_of;
	snapshot.qdisc_root_count = 2u;
	snapshot.redirects = redirects;
	snapshot.redirect_count = 2u;
	prior.qdisc = recorded_qdisc;
	prior.qdisc_count = 1u;

	if (!check(ncfg_observe_build(&snapshot, &prior, &roots, &observed, message,
	    sizeof(message)), "the tc objects are read off the dump") || !observed) {
		return;
	}
	{
		const ncfg_observed_link_t *eth0 = ncfg_observed_link(observed, "eth0");

		check(eth0 && eth0->qdisc && strcmp(eth0->qdisc, "cake") == 0 &&
		    eth0->qdisc_bandwidth_bits.has &&
		    eth0->qdisc_bandwidth_bits.value == 100000000 && eth0->qdisc_ingress,
		    "a shaped link reports its scheduler, its rate in bits and its hook");
		check(eth0 && eth0->ingress_redirect &&
		    strcmp(eth0->ingress_redirect, "ifb0") == 0,
		    "and the device its ingress is redirected to, by name");
	}
	/* A union rather than a replacement: an unmarked qdisc may be one an
	 * older netcfgd installed before it stamped handles, and dropping the
	 * record would make every such qdisc foreign on the day 0137 ships. */
	check(observed->qdisc_applied_count == 2u &&
	    strcmp(observed->qdisc_applied[0], "eth0") == 0 &&
	    strcmp(observed->qdisc_applied[1], "old0") == 0,
	    "a qdisc is netcfgd's by its handle or by the record, and the list is sorted");
	check(observed->ingress_applied_count == 1u &&
	    strcmp(observed->ingress_applied[0], "eth0") == 0,
	    "and a redirect only where the filter wears netcfgd's handle");
	ncfg_observed_free(observed);
	ncfg_observe_prior_free(&prior);
}

/* ------------------------------------------------------------------------ *
 * The kinds, and the translations that happen once
 * ------------------------------------------------------------------------ */

static void kernel_numbers_become_the_words_the_document_uses(void)
{
	ncfg_link_record_t      links[4] = { link_record(2u, "bond0"), link_record(3u, "br0"),
		link_record(4u, "vlan0"), link_record(5u, "mac0") };
	ncfg_observe_snapshot_t snapshot;
	ncfg_observe_prior_t    prior;
	ncfg_observe_roots_t    roots = fixture_roots();
	ncfg_observed_t        *observed = NULL;
	char                    message[NCFG_ERROR_MAX];

	links[0].has_bond = 1;
	links[0].bond.has_mode = 1;
	links[0].bond.mode = 4u;
	links[0].bond.has_miimon = 1;
	links[0].bond.miimon = 100u;
	links[1].has_bridge = 1;
	links[1].bridge.stp = 1;
	links[1].bridge.has_forward_delay = 1;
	/* Hundredths of a second on the wire: a bridge once came up with a 40ms
	 * forward delay instead of 4s, which is what the conversion living in
	 * one place is for. */
	links[1].bridge.forward_delay = 400u;
	links[1].bridge.has_priority = 1;
	links[1].bridge.priority = 32768u;
	links[2].has_vlan = 1;
	links[2].vlan.has_id = 1;
	links[2].vlan.id = 42u;
	links[2].vlan.has_protocol = 1;
	links[2].vlan.protocol = 0x88a8u;
	links[3].has_macvlan = 1;
	links[3].macvlan.has_mode = 1;
	links[3].macvlan.mode = 4u;

	memset(&snapshot, 0, sizeof(snapshot));
	memset(&prior, 0, sizeof(prior));
	snapshot.links = links;
	snapshot.link_count = 4u;

	if (!check(ncfg_observe_build(&snapshot, &prior, &roots, &observed, message,
	    sizeof(message)), "the kind nests are read") || !observed) {
		return;
	}
	check(ncfg_observed_link(observed, "bond0")->bond->mode &&
	    strcmp(ncfg_observed_link(observed, "bond0")->bond->mode, "802.3ad") == 0,
	    "a bond's mode number becomes the word the document spells");
	check(ncfg_observed_link(observed, "br0")->bridge->forward_delay.value == 4,
	    "a bridge's hundredths of a second become seconds");
	check(ncfg_observed_link(observed, "br0")->bridge->priority.has &&
	    ncfg_observed_link(observed, "br0")->bridge->priority.value == 32768,
	    "and its priority, which is two bytes wide and read as absent for years");
	check(ncfg_observed_link(observed, "vlan0")->vlan->protocol &&
	    strcmp(ncfg_observed_link(observed, "vlan0")->vlan->protocol, "dot1ad") == 0,
	    "an ethertype becomes the name the config uses");
	check(ncfg_observed_link(observed, "mac0")->macvlan->mode &&
	    strcmp(ncfg_observed_link(observed, "mac0")->macvlan->mode, "bridge") == 0,
	    "and a macvlan's mode, which is flags rather than an enumeration");
	ncfg_observed_free(observed);
	ncfg_observe_prior_free(&prior);

	/* A number this build has no name for is left unnamed and is therefore
	 * not compared: an interface is not deleted over a value this build
	 * cannot describe. */
	links[0].bond.mode = 9u;
	links[2].vlan.protocol = 0x1234u;
	links[3].macvlan.mode = 16u;
	observed = NULL;
	memset(&prior, 0, sizeof(prior));
	if (ncfg_observe_build(&snapshot, &prior, &roots, &observed, message, sizeof(message))) {
		check(!ncfg_observed_link(observed, "bond0")->bond->mode &&
		    !ncfg_observed_link(observed, "vlan0")->vlan->protocol &&
		    !ncfg_observed_link(observed, "mac0")->macvlan->mode,
		    "a value this build has no word for is left unnamed rather than guessed");
		ncfg_observed_free(observed);
	} else {
		check(0, "a value this build has no word for is left unnamed rather than guessed");
	}
	ncfg_observe_prior_free(&prior);
}

/* ------------------------------------------------------------------------ *
 * Rules
 * ------------------------------------------------------------------------ */

static void a_rule_is_ours_by_its_protocol(void)
{
	ncfg_rule_record_t      rules[2];
	ncfg_observe_snapshot_t snapshot;
	ncfg_observe_prior_t    prior;
	ncfg_observe_roots_t    roots = fixture_roots();
	ncfg_observed_t        *observed = NULL;
	char                    message[NCFG_ERROR_MAX];

	memset(rules, 0, sizeof(rules));
	rules[0].family = AF_INET;
	rules[0].priority = 100u;
	rules[0].table = 42u;
	rules[0].action = FR_ACT_TO_TBL;
	rules[0].protocol = NCFG_WIRE_RTPROT_NETCFGD;
	rules[0].has_fwmark = 1;
	rules[0].fwmark = 1u;
	if (!ncfg_wire_ip_parse("10.0.0.0", &rules[0].from, message, sizeof(message))) {
		check(0, "the fixture's selector parses");
		return;
	}
	rules[0].from_len = 8u;
	rules[1].family = AF_INET6;
	rules[1].priority = 200u;
	/* Zero is `RT_TABLE_UNSPEC`, which for an action other than a lookup is
	 * simply "no table" rather than "table zero". */
	rules[1].table = 0u;
	rules[1].action = FR_ACT_BLACKHOLE;
	rules[1].protocol = 0u;

	memset(&snapshot, 0, sizeof(snapshot));
	memset(&prior, 0, sizeof(prior));
	snapshot.rules = rules;
	snapshot.rule_count = 2u;

	if (!check(ncfg_observe_build(&snapshot, &prior, &roots, &observed, message,
	    sizeof(message)), "the rule dump becomes the observation's rules") || !observed) {
		return;
	}
	check(observed->rule_count == 2u, "with one row per rule");
	{
		const ncfg_observed_rule_t *ours = &observed->rules[0];
		const ncfg_observed_rule_t *theirs = &observed->rules[1];
		size_t                      at;

		/* Sorted by family then priority, so the v4 rule comes first
		 * whatever order the kernel dumped them in. */
		for (at = 0; at < observed->rule_count; at++) {
			if (observed->rules[at].family == NCFG_RULE_FAMILY_INET) {
				ours = &observed->rules[at];
			} else {
				theirs = &observed->rules[at];
			}
		}
		check(ours->ownership == NCFG_OWNERSHIP_OURS &&
		    ours->action == NCFG_RULE_ACTION_LOOKUP && ours->table.has &&
		    ours->table.value == 42,
		    "a rule carrying netcfgd's protocol is ours, and looks a table up");
		check(ours->from && strcmp(ours->from, "10.0.0.0/8") == 0 && ours->fwmark.has,
		    "with its selector and mark as the kernel reported them");
		/* A kernel too old for `FRA_PROTOCOL` reports 0 on everything,
		 * which reads as foreign -- so netcfgd installs and never
		 * removes, which is the safe way to be wrong. */
		check(theirs->ownership == NCFG_OWNERSHIP_FOREIGN &&
		    theirs->action == NCFG_RULE_ACTION_BLACKHOLE && !theirs->table.has &&
		    theirs->family == NCFG_RULE_FAMILY_INET6,
		    "an untagged rule is foreign, and table zero is no table");
	}
	ncfg_observed_free(observed);
	ncfg_observe_prior_free(&prior);
}

/* ------------------------------------------------------------------------ *
 * The fixture directory
 * ------------------------------------------------------------------------ */

/*
 * A `/sys` and a `/proc` with one radio, one wired interface and two `wlan`
 * switches.
 *
 * **The second switch is the point.** A laptop registers one for the platform
 * button beside the phy's own -- `dell-wifi` and `phy0` on the machine 0062 was
 * written on -- and a reader that took the first `wlan` entry it found would
 * report the button's state for the card, which on a machine with two cards is
 * somebody else's radio.
 */
static int build_fixture(void)
{
	return make_file("class/net/wlan0/phy80211/name", "phy0\n") &&
	    /* The wired interface has no `phy80211` at all, which is how the
	     * reader tells them apart with no special case. */
	    make_file("class/net/eth0/mtu", "1500\n") &&
	    make_file("class/rfkill/rfkill0/name", "dell-wifi\n") &&
	    make_file("class/rfkill/rfkill0/soft", "1\n") &&
	    make_file("class/rfkill/rfkill0/hard", "0\n") &&
	    make_file("class/rfkill/rfkill1/name", "phy0\n") &&
	    make_file("class/rfkill/rfkill1/soft", "1\n") &&
	    make_file("class/rfkill/rfkill1/hard", "0\n") &&
	    /* An entry with no readable `name` at all, sorting *after* the
	     * match, which was always harmless -- it is here so that the
	     * sorted-in-front case below is what pins the behaviour. */
	    make_dirs("class/rfkill/rfkill9") &&
	    make_file("class/bluetooth/hci0/rfkill0/name", "hci0\n") &&
	    make_file("class/bluetooth/hci0/rfkill0/soft", "1\n") &&
	    make_file("class/bluetooth/hci0/rfkill0/hard", "0\n") &&
	    /* The decoy: a platform button in the global list, unblocked. A
	     * reader that searched by type would find this and report the radio
	     * as fine while the adapter's own switch says otherwise. */
	    make_file("class/rfkill/rfkill3/name", "dell-bluetooth\n") &&
	    make_file("class/rfkill/rfkill3/soft", "0\n") &&
	    make_file("class/rfkill/rfkill3/hard", "0\n") &&
	    /* An adapter whose driver registers no switch. It is still an
	     * adapter: it exists, and that is the fact. */
	    make_dirs("class/bluetooth/hci1") &&
	    make_file("proc/sys/kernel/hostname", "workshop\n") &&
	    make_file("proc/sys/net/ipv4/conf/eth0/forwarding", "1\n") &&
	    make_file("proc/sys/net/ipv6/conf/eth0/forwarding", "1\n") &&
	    make_file("proc/sys/net/ipv6/conf/eth0/use_tempaddr", "2\n") &&
	    make_file("proc/sys/net/ipv6/conf/eth0/accept_ra", "1\n") &&
	    /* Only the v4 half, which is an IPv6-disabled kernel. */
	    make_file("proc/sys/net/ipv4/conf/wlan0/forwarding", "1\n") &&
	    make_file("proc/sys/net/ipv6/conf/wlan0/use_tempaddr", "1\n") &&
	    make_file("proc/sys/net/ipv6/conf/wlan0/accept_ra", "2\n");
}

static void the_sysctls_are_read_from_a_fixture(void)
{
	ncfg_observe_roots_t      roots = fixture_roots();
	ncfg_optbool_t            answer;
	ncfg_observed_accept_ra_t accept_ra;
	char                     *hostname;

	answer = ncfg_observe_forwarding(roots.proc, "eth0");
	check(answer.has && answer.value, "an interface forwarding both families says so");
	/* One family present and the other missing means an IPv6-disabled
	 * kernel, where reporting the IPv4 answer alone would have the planner
	 * satisfied by half a change it can never complete. */
	answer = ncfg_observe_forwarding(roots.proc, "wlan0");
	check(!answer.has, "and one whose second family cannot be read says nothing");
	answer = ncfg_observe_forwarding(roots.proc, "nonesuch");
	check(!answer.has, "an interface with no sysctls at all is not `false`");

	answer = ncfg_observe_privacy(roots.proc, "eth0");
	check(answer.has && answer.value, "use_tempaddr 2 is the privacy the document asks for");
	/* `1` generates a temporary address and prefers the stable one, which is
	 * a state nothing in the document can request. */
	answer = ncfg_observe_privacy(roots.proc, "wlan0");
	check(answer.has && !answer.value, "and 1 is not, because no config can ask for it");

	check(ncfg_observe_accept_ra(roots.proc, "eth0", &accept_ra) && accept_ra.value == 1 &&
	    !accept_ra.effective,
	    "accept_ra 1 on a forwarding interface accepts nothing");
	check(ncfg_observe_accept_ra(roots.proc, "wlan0", &accept_ra) && accept_ra.value == 2 &&
	    accept_ra.effective, "and 2 accepts whether the interface forwards or not");
	check(!ncfg_observe_accept_ra(roots.proc, "nonesuch", &accept_ra),
	    "an interface with no accept_ra reports nothing rather than zero");

	hostname = ncfg_observe_hostname(roots.proc);
	check(hostname && strcmp(hostname, "workshop") == 0,
	    "the hostname is read and trimmed of the kernel's newline");
	free(hostname);
	check(ncfg_observe_hostname("/nonesuch") == NULL,
	    "and a container with no /proc/sys reports none, which is not a name");
}

static void a_radio_reports_its_own_switch(void)
{
	ncfg_observe_roots_t    roots = fixture_roots();
	ncfg_observed_rfkill_t *state = NULL;
	char                    message[NCFG_ERROR_MAX];

	check(ncfg_observe_rfkill(roots.sys, "wlan0", &state, message, sizeof(message)) && state &&
	    strcmp(state->switch_, "phy0") == 0,
	    "a radio reports the switch its own driver obeys");
	check(state && state->soft && !state->hard && ncfg_rfkill_blocked(state),
	    "and a soft block and a hard block are told apart");
	free(state ? state->switch_ : NULL);
	free(state);

	state = NULL;
	check(ncfg_observe_rfkill(roots.sys, "eth0", &state, message, sizeof(message)) && !state,
	    "anything that is not a radio reports nothing");
	state = NULL;
	check(ncfg_observe_rfkill(roots.sys, "nonesuch", &state, message, sizeof(message)) &&
	    !state, "and so does an interface that is not there");
	state = NULL;
	check(ncfg_observe_rfkill("/nonesuch", "wlan0", &state, message, sizeof(message)) &&
	    !state, "a kernel without rfkill reports nothing, which is not a clear switch");
}

/*
 * The entry that sorts in front of the match and cannot be read.
 *
 * **The Rust's first version returned from the whole function here**, so one
 * unreadable `name` on an unrelated entry abandoned the search -- and since the
 * listing is sorted, an entry sorting before the phy's own decided for every
 * entry after it. Measured against a fabricated `/sys`: the radio is
 * soft-blocked, the scan comes back empty, and `link.rfkill` is null so nothing
 * says why.
 *
 * The fixture's `rfkill0` is `dell-wifi` and readable, so this renames the phy's
 * own entry out of first place by adding one that sorts before both and has no
 * `name` in it at all.
 */
static void an_unreadable_entry_in_front_does_not_end_the_search(void)
{
	ncfg_observe_roots_t    roots = fixture_roots();
	ncfg_observed_rfkill_t *state = NULL;
	char                    message[NCFG_ERROR_MAX];

	if (!check(make_dirs("class/rfkill/rfkill-aaa"),
	    "an entry with no name sorts in front of the match")) {
		return;
	}
	check(ncfg_observe_rfkill(roots.sys, "wlan0", &state, message, sizeof(message)) && state &&
	    strcmp(state->switch_, "phy0") == 0,
	    "an unreadable entry is skipped rather than ending the search");
	free(state ? state->switch_ : NULL);
	free(state);
}

/*
 * A switch whose flags cannot be read is not a switch that is clear.
 *
 * `None` is not `false` (0052's rule): a truncated entry -- a name with no
 * `soft` beside it, which is what a partially populated sysfs looks like --
 * must report nothing rather than a radio that appears to be working.
 */
static void a_switch_with_no_flags_reports_nothing(void)
{
	ncfg_observe_roots_t    roots = fixture_roots();
	ncfg_observed_rfkill_t *state = NULL;
	char                    message[NCFG_ERROR_MAX];

	if (!check(make_file("class/net/wlan9/phy80211/name", "phy9\n") &&
	    make_file("class/rfkill/rfkill8/name", "phy9\n"),
	    "a partially populated switch is fabricated")) {
		return;
	}
	check(ncfg_observe_rfkill(roots.sys, "wlan9", &state, message, sizeof(message)) && !state,
	    "a switch with a name and no flags reports nothing");
}

static void an_adapter_reports_its_own_switch(void)
{
	ncfg_observe_roots_t       roots = fixture_roots();
	ncfg_observed_bluetooth_t *found = NULL;
	size_t                     count = 0;
	char                       message[NCFG_ERROR_MAX];
	size_t                     at;

	if (!check(ncfg_observe_bluetooth(roots.sys, &found, &count, message, sizeof(message)) &&
	    count == 2u, "the Bluetooth adapters are read from sysfs, sorted")) {
		return;
	}
	check(strcmp(found[0].name, "hci0") == 0 && strcmp(found[1].name, "hci1") == 0,
	    "and named as the kernel names them");
	check(found[0].rfkill && strcmp(found[0].rfkill->switch_, "hci0") == 0 &&
	    found[0].rfkill->soft,
	    "an adapter reports the switch inside its own directory, not the platform button");
	/* `None` is "netcfgd cannot tell", which 0062 says nothing is planned
	 * on. The adapter is still listed: it exists, and that is the fact. */
	check(!found[1].rfkill, "an adapter with no switch is still an adapter");
	for (at = 0; at < count; at++) {
		free(found[at].name);
		if (found[at].rfkill) {
			free(found[at].rfkill->switch_);
			free(found[at].rfkill);
		}
	}
	free(found);

	found = NULL;
	count = 1u;
	check(ncfg_observe_bluetooth("/nonesuch", &found, &count, message, sizeof(message)) &&
	    count == 0u && !found,
	    "a machine without Bluetooth reports an empty list rather than failing");
}

static void the_fixture_decides_which_link_is_a_radio(void)
{
	ncfg_link_record_t      links[2] = { link_record(2u, "eth0"), link_record(3u, "wlan0") };
	ncfg_observe_snapshot_t snapshot;
	ncfg_observe_prior_t    prior;
	ncfg_observe_roots_t    roots = fixture_roots();
	ncfg_observed_t        *observed = NULL;
	char                    message[NCFG_ERROR_MAX];

	memset(&snapshot, 0, sizeof(snapshot));
	memset(&prior, 0, sizeof(prior));
	snapshot.links = links;
	snapshot.link_count = 2u;

	if (!check(ncfg_observe_build(&snapshot, &prior, &roots, &observed, message,
	    sizeof(message)), "a link's `wireless` comes from the fixture's sysfs") ||
	    !observed) {
		return;
	}
	/* A real wireless device is a plain device and reports an empty kind,
	 * the same as an ethernet port -- so the kind cannot answer this and the
	 * document must not. */
	check(ncfg_observed_link(observed, "wlan0")->wireless,
	    "the interface with a phy80211 is a radio");
	check(!ncfg_observed_link(observed, "eth0")->wireless, "and the one without is not");

	if (check(ncfg_observe_augment_host(observed, &roots, message, sizeof(message)),
	    "and augment fills in what the snapshot could not")) {
		const ncfg_observed_link_t *eth0 = ncfg_observed_link(observed, "eth0");
		const ncfg_observed_link_t *wlan0 = ncfg_observed_link(observed, "wlan0");

		check(eth0->forwarding.has && eth0->forwarding.value && eth0->privacy.has &&
		    eth0->accept_ra && eth0->accept_ra->value == 1,
		    "the sysctls land on the link they belong to");
		check(wlan0->rfkill && strcmp(wlan0->rfkill->switch_, "phy0") == 0,
		    "the radio's switch lands on the radio");
		check(!eth0->rfkill, "and nothing lands on the wired port");
		check(observed->hostname && strcmp(observed->hostname, "workshop") == 0 &&
		    observed->bluetooth_count == 2u,
		    "with the hostname and the adapters beside them");
		/* Idempotent: a second pass must say what the machine says now
		 * rather than doubling anything, which is the property that lets
		 * the daemon augment a fresh observation every cycle. */
		if (check(ncfg_observe_augment_host(observed, &roots, message, sizeof(message)),
		    "a second augment succeeds")) {
			check(observed->bluetooth_count == 2u &&
			    ncfg_observed_link(observed, "wlan0")->rfkill,
			    "and changes nothing that was already right");
		}
	}
	ncfg_observed_free(observed);
	ncfg_observe_prior_free(&prior);
}

/* ------------------------------------------------------------------------ *
 * The verdict
 * ------------------------------------------------------------------------ */

/* An observation assembled by hand, which is what the Rust's connectivity tests
 * do with `serde_json::json!`: a literal would have to be edited every time a
 * link gains a field, which is how a test comes to assert a shape nobody
 * meant. */
static ncfg_observed_t *bare_observation(void)
{
	ncfg_observed_t *observed = ncfg_observed_new(NULL, 0);

	if (!observed) {
		printf("observe_test: out of memory building an observation\n");
		exit(1);
	}
	return observed;
}

static void add_link(ncfg_observed_t *observed, const char *name, int up, int wireless)
{
	ncfg_observed_link_t *grown =
	    realloc(observed->links, (observed->link_count + 1u) * sizeof(*grown));

	if (!grown) {
		exit(1);
	}
	observed->links = grown;
	memset(&grown[observed->link_count], 0, sizeof(grown[0]));
	grown[observed->link_count].name = strdup(name);
	grown[observed->link_count].kind = strdup("");
	grown[observed->link_count].up = up;
	grown[observed->link_count].carrier = up;
	grown[observed->link_count].wireless = wireless;
	observed->link_count++;
}

static void add_address(ncfg_observed_t *observed, const char *interface, const char *cidr)
{
	ncfg_observed_address_t *grown =
	    realloc(observed->addresses, (observed->address_count + 1u) * sizeof(*grown));

	if (!grown) {
		exit(1);
	}
	observed->addresses = grown;
	memset(&grown[observed->address_count], 0, sizeof(grown[0]));
	grown[observed->address_count].interface = strdup(interface);
	grown[observed->address_count].address = strdup(cidr);
	grown[observed->address_count].ownership = NCFG_OWNERSHIP_FOREIGN;
	observed->address_count++;
}

static void add_default_route(ncfg_observed_t *observed, const char *interface, int has_metric,
    int64_t metric)
{
	ncfg_observed_route_t *grown =
	    realloc(observed->routes, (observed->route_count + 1u) * sizeof(*grown));

	if (!grown) {
		exit(1);
	}
	observed->routes = grown;
	memset(&grown[observed->route_count], 0, sizeof(grown[0]));
	grown[observed->route_count].interface = strdup(interface);
	grown[observed->route_count].destination = strdup("default");
	grown[observed->route_count].metric.has = has_metric;
	grown[observed->route_count].metric.value = metric;
	grown[observed->route_count].ownership = NCFG_OWNERSHIP_FOREIGN;
	observed->route_count++;
}

static int rung_of(const ncfg_observed_t *observed, const ncfg_connectivity_policy_t *policy)
{
	ncfg_connectivity_t *answer = NULL;
	char                 message[NCFG_ERROR_MAX];
	int                  rung;

	if (!ncfg_connectivity_overall(observed, policy, &answer, message, sizeof(message))) {
		printf("observe_test: no verdict (%s)\n", message);
		exit(1);
	}
	rung = answer->rung;
	if (answer->primary) {
		free(answer->primary->interface);
		free(answer->primary->label);
		free(answer->primary);
	}
	free(answer);
	return rung;
}

/*
 * A policy built around storage the caller owns.
 *
 * The patterns are the caller's array rather than a static one here: two
 * policies alive at once would otherwise share it, and the second would
 * silently rewrite the first -- a fixture built so that two different
 * assertions test the same thing.
 */
static ncfg_connectivity_policy_t policy_of(int requires_, char **patterns, size_t count)
{
	ncfg_connectivity_policy_t policy;

	memset(&policy, 0, sizeof(policy));
	policy.requires_ = requires_;
	policy.ignore = count ? patterns : NULL;
	policy.ignore_count = count;
	return policy;
}

static void an_address_without_a_route_is_not_connected(void)
{
	ncfg_observed_t           *observed = bare_observation();
	ncfg_connectivity_policy_t address_is_enough =
	    policy_of(NCFG_REQUIRES_ADDRESS, NULL, 0u);
	ncfg_connectivity_t       *answer = NULL;
	char                       message[NCFG_ERROR_MAX];

	add_link(observed, "eth0", 1, 0);
	add_address(observed, "eth0", "192.168.1.10/24");

	/* The rung that exists because it was once reported as connected: a
	 * machine here reaches its own subnet and fails everything else, which
	 * looks like a working configuration to anybody reading an icon. */
	if (check(ncfg_connectivity_overall(observed, NULL, &answer, message, sizeof(message)),
	    "a machine with an address and no route has a verdict")) {
		check(answer->rung == NCFG_RUNG_LOCAL && !ncfg_connectivity_connected(answer),
		    "which is locally connected and not connected");
		/* Nothing is carrying traffic, so there is no main link to
		 * name. */
		check(!answer->primary, "and there is no main link to name");
		free(answer);
	}
	/* Unless the document says an address is what it means, which is the
	 * appliance on its own subnet. */
	check(rung_of(observed, &address_is_enough) == NCFG_RUNG_ROUTED,
	    "a document that says an address is enough gets one");
	ncfg_observed_free(observed);
}

static void a_down_interface_holding_an_address_is_not_a_connection(void)
{
	ncfg_observed_t           *observed = bare_observation();
	ncfg_connectivity_policy_t nothing_ignored = policy_of(NCFG_REQUIRES_ROUTE, NULL, 0u);

	add_link(observed, "lo", 1, 0);
	add_link(observed, "docker0", 0, 0);
	add_address(observed, "lo", "127.0.0.1/8");
	add_address(observed, "docker0", "172.17.0.1/16");
	check(rung_of(observed, NULL) == NCFG_RUNG_OFFLINE,
	    "a machine with nothing but a bridge to nowhere is offline");

	/* **A name the ignore list says nothing about, so this is the `up` check
	 * and only the `up` check.** The assertion above stopped being one when
	 * `docker*` joined the default list: a sabotage removing the `up` test
	 * passed. A down wired NIC that kept a stale address is the case that
	 * would have reported a machine locally connected. */
	add_link(observed, "eth1", 0, 0);
	add_address(observed, "eth1", "192.0.2.9/24");
	check(rung_of(observed, NULL) == NCFG_RUNG_OFFLINE,
	    "a down interface with a stale address is still offline");
	observed->links[2].up = 1;
	check(rung_of(observed, NULL) == NCFG_RUNG_LOCAL, "and bringing it up changes that");
	observed->links[2].up = 0;

	/* Bringing the bridge up changes nothing, because the default group is
	 * every link except the absurd ones and a container bridge is one of
	 * them. */
	observed->links[1].up = 1;
	check(rung_of(observed, NULL) == NCFG_RUNG_OFFLINE, "`docker0` matches `docker*`");
	/* A document that wants it counted says so, and `ignore` replaces the
	 * default rather than adding to it -- otherwise an operator whose real
	 * uplink is one of these families could never get it back. */
	check(rung_of(observed, &nothing_ignored) == NCFG_RUNG_LOCAL,
	    "and a document that ignores nothing counts it");
	ncfg_observed_free(observed);
}

static void the_default_group_is_every_link_but_the_absurd_ones(void)
{
	static const char *const families[] = { "docker0", "br-1a2b3c", "veth9f2", "virbr0",
		"vnet7" };
	char                      *everything[] = { (char *)"*" };
	char                      *by_name[] = { (char *)"wg0" };
	ncfg_observed_t           *observed = bare_observation();
	ncfg_connectivity_policy_t ignore_all = policy_of(NCFG_REQUIRES_ROUTE, everything, 1u);
	ncfg_connectivity_policy_t ignore_one = policy_of(NCFG_REQUIRES_ROUTE, by_name, 1u);
	size_t                     at;

	for (at = 0; at < sizeof(families) / sizeof(families[0]); at++) {
		add_link(observed, families[at], 1, 0);
		add_address(observed, families[at], "172.17.0.1/16");
	}
	check(rung_of(observed, NULL) == NCFG_RUNG_OFFLINE,
	    "the five families nobody calls an uplink are ignored by default");

	/* **Not in the list, deliberately.** A laptop whose real uplink is a VPN
	 * is ordinary, so excluding these by default would be netcfgd deciding
	 * somebody's network for them. */
	add_link(observed, "wg0", 1, 0);
	add_address(observed, "wg0", "10.9.0.2/24");
	check(rung_of(observed, NULL) == NCFG_RUNG_LOCAL, "and a VPN is not one of them");
	/* A bare `*` would ignore every link, including the one the machine is
	 * on, and answer offline for ever. */
	check(rung_of(observed, &ignore_all) == NCFG_RUNG_LOCAL,
	    "a bare `*` is refused rather than honoured");
	check(rung_of(observed, &ignore_one) == NCFG_RUNG_LOCAL,
	    "and an exact name still means an exact name");
	ncfg_observed_free(observed);
}

static void the_primary_is_the_best_route_and_carries_the_networks_name(void)
{
	ncfg_observed_t     *observed = bare_observation();
	ncfg_connectivity_t *answer = NULL;
	char                 message[NCFG_ERROR_MAX];

	add_link(observed, "eth0", 1, 0);
	add_link(observed, "wlan0", 1, 1);
	observed->links[1].network = strdup("EMP-XYLEM");
	add_address(observed, "eth0", "192.168.1.10/24");
	add_address(observed, "wlan0", "10.78.60.134/22");
	add_default_route(observed, "eth0", 1, 400);
	add_default_route(observed, "wlan0", 1, 200);

	if (check(ncfg_connectivity_overall(observed, NULL, &answer, message, sizeof(message)) &&
	    answer->primary, "a machine with a default route names what carries it")) {
		/* Lower wins, which is what a metric means and what a network's
		 * `metric` is expressed in. */
		check(answer->rung == NCFG_RUNG_ROUTED && ncfg_connectivity_connected(answer) &&
		    strcmp(answer->primary->interface, "wlan0") == 0 && answer->primary->wireless,
		    "the best metric wins, and a client can pick an icon");
		/* The name an operator recognises, not the interface. */
		check(strcmp(answer->primary->label, "EMP-XYLEM") == 0,
		    "and it is called what the operator called the network");
		free(answer->primary->interface);
		free(answer->primary->label);
		free(answer->primary);
		free(answer);
	}
	observed->routes[0].metric.value = 100;
	answer = NULL;
	if (check(ncfg_connectivity_overall(observed, NULL, &answer, message, sizeof(message)) &&
	    answer->primary, "giving the wire the better metric moves the answer")) {
		check(strcmp(answer->primary->interface, "eth0") == 0 &&
		    !answer->primary->wireless &&
		    strcmp(answer->primary->label, "eth0") == 0,
		    "a wired link has no network block, so it is called what it is");
		free(answer->primary->interface);
		free(answer->primary->label);
		free(answer->primary);
		free(answer);
	}
	ncfg_observed_free(observed);
}

static void a_probe_separates_a_route_from_a_connection(void)
{
	ncfg_observed_t           *observed = bare_observation();
	ncfg_connectivity_policy_t wants_a_probe = policy_of(NCFG_REQUIRES_PROBE, NULL, 0u);

	add_link(observed, "wlan0", 1, 1);
	add_address(observed, "wlan0", "10.0.0.5/24");
	add_default_route(observed, "wlan0", 1, 200);

	/* No probe has answered. Asking for one does not invent a refusal: a
	 * machine with none stops at `routed`, which is a working icon and not a
	 * permanent red one. */
	check(rung_of(observed, &wants_a_probe) == NCFG_RUNG_ROUTED,
	    "a document asking for a probe is not punished for having none");
	observed->links[0].reachable.has = 1;
	observed->links[0].reachable.value = 1;
	check(rung_of(observed, &wants_a_probe) == NCFG_RUNG_ONLINE,
	    "a probe that answered yes is the only way to the top rung");
	observed->links[0].reachable.value = 0;
	/* A default route, and nothing at the other end of it. */
	check(rung_of(observed, &wants_a_probe) == NCFG_RUNG_LOCAL,
	    "and one that answered no is the captive portal");
	/* A document that did not ask for a probe is not overruled by one:
	 * present-and-false withholding a route from a machine that never asked
	 * is the mistake `reachable`'s comment warns about. */
	check(rung_of(observed, NULL) == NCFG_RUNG_ROUTED,
	    "a document that did not ask for a probe is not overruled by one");
	ncfg_observed_free(observed);
}

/* A choice, appended to an observation the way `derive` would have. */
static void add_uplink_choice(ncfg_observed_t *observed, const char *active,
    const char *interface, const char *member, const char *member_interface)
{
	ncfg_chosen_t *grown =
	    realloc(observed->linksets, (observed->linkset_count + 1u) * sizeof(*grown));

	if (!grown) {
		exit(1);
	}
	observed->linksets = grown;
	memset(&grown[observed->linkset_count], 0, sizeof(grown[0]));
	grown[observed->linkset_count].name = strdup(NCFG_LINKSET_UPLINK);
	grown[observed->linkset_count].active = active ? strdup(active) : NULL;
	grown[observed->linkset_count].interface = interface ? strdup(interface) : NULL;
	if (member) {
		grown[observed->linkset_count].members =
		    calloc(1, sizeof(*grown[observed->linkset_count].members));
		if (!grown[observed->linkset_count].members) {
			exit(1);
		}
		grown[observed->linkset_count].members[0].name = strdup(member);
		grown[observed->linkset_count].members[0].interface =
		    member_interface ? strdup(member_interface) : NULL;
		grown[observed->linkset_count].members[0].ineligible.has = 1;
		grown[observed->linkset_count].members[0].ineligible.value =
		    NCFG_INELIGIBLE_NO_CARRIER;
		grown[observed->linkset_count].member_count = 1u;
	}
	observed->linkset_count++;
}

static void where_an_uplink_set_is_declared_it_is_the_answer(void)
{
	ncfg_observed_t     *observed = bare_observation();
	ncfg_connectivity_t *answer = NULL;
	char                 message[NCFG_ERROR_MAX];

	add_link(observed, "eth0", 1, 0);
	add_link(observed, "wlan0", 1, 1);
	add_address(observed, "eth0", "10.0.0.2/24");
	add_address(observed, "wlan0", "192.168.1.5/24");
	/* The radio holds the better route, so the ruleless answer is the radio.
	 * The set says the cable. */
	add_default_route(observed, "wlan0", 1, 600);
	add_default_route(observed, "eth0", 1, 100);

	if (check(ncfg_connectivity_overall(observed, NULL, &answer, message, sizeof(message)) &&
	    answer->primary && strcmp(answer->primary->interface, "eth0") == 0,
	    "with no set, the best metric wins")) {
		free(answer->primary->interface);
		free(answer->primary->label);
		free(answer->primary);
		free(answer);
	}
	add_uplink_choice(observed, "office", "wlan0", NULL, NULL);
	answer = NULL;
	if (check(ncfg_connectivity_overall(observed, NULL, &answer, message, sizeof(message)) &&
	    answer->primary, "a declared uplink set is the answer")) {
		check(strcmp(answer->primary->interface, "wlan0") == 0 &&
		    answer->primary->wireless && answer->rung == NCFG_RUNG_ROUTED,
		    "the set's choice decides, and the rest of the machine does not vote");
		/* Named as the set names it, which is what an operator
		 * recognises. */
		check(strcmp(answer->primary->label, "office") == 0,
		    "and it is named as the set names it");
		free(answer->primary->interface);
		free(answer->primary->label);
		free(answer->primary);
		free(answer);
	}
	ncfg_observed_free(observed);
}

static void a_set_with_no_usable_member_stops_at_what_it_is_holding(void)
{
	ncfg_observed_t *observed = bare_observation();

	add_link(observed, "eth0", 1, 0);
	add_address(observed, "eth0", "10.0.0.2/24");
	/* Something else entirely is routing. It is not in the set, so it is not
	 * this machine's uplink and does not make it connected. */
	add_link(observed, "wg0", 1, 0);
	add_address(observed, "wg0", "10.9.0.2/32");
	add_default_route(observed, "wg0", 1, 50);
	add_uplink_choice(observed, NULL, NULL, "eth0", "eth0");

	check(rung_of(observed, NULL) == NCFG_RUNG_LOCAL,
	    "a set with nothing usable is what its members are holding");
	free(observed->addresses[0].interface);
	free(observed->addresses[0].address);
	observed->addresses[0].interface = strdup("wg0");
	observed->addresses[0].address = strdup("10.9.0.3/32");
	check(rung_of(observed, NULL) == NCFG_RUNG_OFFLINE,
	    "and with nothing held anywhere in the set, offline");
	ncfg_observed_free(observed);
}

/* ------------------------------------------------------------------------ *
 * Deriving, twice
 * ------------------------------------------------------------------------ */

/*
 * **The reason `derive` is a function of its own.** Probe verdicts are stamped
 * onto a fresh observation after it is built, so everything derived inside
 * `augment` was derived from an absent `reachable` on every link: the published
 * choice named the better-ranked link while the planner, which reads the stamped
 * observation, had just taken that link's routes away, and `connectivity` with
 * `requires = "probe"` could never reach `online` because the verdict it asks
 * for had not been written yet. So the daemon runs this again once the verdicts
 * are on -- and everything here being derived is what makes running it twice
 * cost one pass and change nothing that was already right.
 */
static void derive_runs_again_once_the_verdicts_are_on(void)
{
	ncfg_observed_t *observed = bare_observation();
	ncfg_document_t *document = ncfg_document_new(NULL, 0);
	char             message[NCFG_ERROR_MAX];

	if (!document) {
		check(0, "a document to derive against");
		ncfg_observed_free(observed);
		return;
	}
	document->globals.connectivity.requires_ = NCFG_REQUIRES_PROBE;
	add_link(observed, "lo", 1, 0);
	add_link(observed, "wlan0", 1, 1);
	add_address(observed, "wlan0", "10.0.0.5/24");
	add_default_route(observed, "wlan0", 1, 200);

	if (!check(ncfg_observe_derive(observed, document, message, sizeof(message)),
	    "the derived answers are computed")) {
		ncfg_document_free(document);
		ncfg_observed_free(observed);
		return;
	}
	check(ncfg_observed_link(observed, "lo")->category.has &&
	    ncfg_observed_link(observed, "lo")->category.value == NCFG_LINK_CATEGORY_LOOPBACK &&
	    ncfg_observed_link(observed, "wlan0")->category.value == NCFG_LINK_CATEGORY_WIFI,
	    "every link is stamped with its category");
	check(observed->inventory_count == 2u, "and the inventory is the union it should be");
	check(observed->connectivity && observed->connectivity->rung == NCFG_RUNG_ROUTED,
	    "a machine whose probe has not answered stops at routed");

	/* The daemon stamps the verdict here, after the observation exists. */
	observed->links[1].reachable.has = 1;
	observed->links[1].reachable.value = 0;
	if (check(ncfg_observe_derive(observed, document, message, sizeof(message)),
	    "and derive runs again with the verdicts on")) {
		check(observed->connectivity->rung == NCFG_RUNG_LOCAL,
		    "the stamped refusal moves the rung, which it could not inside augment");
	}
	/* Pure, and therefore safe to run twice on the same input: a third pass
	 * over an unchanged observation changes nothing. */
	if (check(ncfg_observe_derive(observed, document, message, sizeof(message)),
	    "a third pass over an unchanged observation succeeds")) {
		check(observed->connectivity->rung == NCFG_RUNG_LOCAL &&
		    observed->inventory_count == 2u && observed->linkset_count == 0u,
		    "and changes nothing, which is what makes running it twice free");
	}
	ncfg_document_free(document);
	ncfg_observed_free(observed);
}

/* ------------------------------------------------------------------------ *
 * The prior, handed over
 * ------------------------------------------------------------------------ */

/*
 * `build` takes the prior's aggregate lists rather than copying them, which is
 * this module's largest divergence -- so it is asserted rather than described.
 * The hand-over is last, after everything that can fail, so one
 * `ncfg_observe_prior_free` is correct on either answer.
 */
static void the_prior_hands_its_aggregates_over(void)
{
	ncfg_observe_snapshot_t snapshot;
	ncfg_observe_prior_t    prior;
	ncfg_observe_roots_t    roots = fixture_roots();
	ncfg_observed_t        *observed = NULL;
	char                    message[NCFG_ERROR_MAX];

	memset(&snapshot, 0, sizeof(snapshot));
	memset(&prior, 0, sizeof(prior));
	prior.delegations = calloc(1, sizeof(*prior.delegations));
	if (!prior.delegations) {
		check(0, "a delegation to hand over");
		return;
	}
	prior.delegation_count = 1u;
	prior.delegations[0].interface = strdup("wan0");
	prior.delegations[0].prefixes = calloc(1, sizeof(*prior.delegations[0].prefixes));
	if (!prior.delegations[0].interface || !prior.delegations[0].prefixes) {
		check(0, "a delegation to hand over");
		return;
	}
	prior.delegations[0].prefixes[0] = strdup("2001:db8::/56");
	prior.delegations[0].prefix_count = 1u;

	if (!check(ncfg_observe_build(&snapshot, &prior, &roots, &observed, message,
	    sizeof(message)), "an empty machine still observes")) {
		return;
	}
	check(observed->delegation_count == 1u && !prior.delegations && prior.delegation_count == 0u,
	    "the prior's aggregates are in the observation and no longer in the prior");
	check(ncfg_observed_delegation(observed, "wan0") != NULL,
	    "and the observation can be asked about them");
	ncfg_observed_free(observed);
	/* Freeing a prior that has handed everything over is nothing, which is
	 * what makes one free correct on either answer. */
	ncfg_observe_prior_free(&prior);
	ncfg_observe_prior_free(&prior);
	check(1, "freeing a prior twice, and one that was emptied, is nothing");
}

int main(void)
{
	if (!tempdir_make("observe", root, sizeof(root))) {
		printf("observe_test: could not make a fixture directory\n");
		return 1;
	}
	if (!build_fixture()) {
		printf("observe_test: could not build the fixture under %s\n", root);
		remove_fixture();
		return 1;
	}

	the_marks_are_one_number_wearing_three_shapes();
	link_ownership_cases();
	address_ownership_cases();
	the_tag_implies_an_origin();

	a_snapshot_becomes_a_model();
	names_are_resolved_or_dropped();
	only_recorded_links_are_ours();
	ownership_calibrates_once_we_own_an_address();
	a_tc_object_is_ours_by_handle_or_by_record();
	kernel_numbers_become_the_words_the_document_uses();
	a_rule_is_ours_by_its_protocol();

	the_sysctls_are_read_from_a_fixture();
	a_radio_reports_its_own_switch();
	an_unreadable_entry_in_front_does_not_end_the_search();
	a_switch_with_no_flags_reports_nothing();
	an_adapter_reports_its_own_switch();
	the_fixture_decides_which_link_is_a_radio();

	an_address_without_a_route_is_not_connected();
	a_down_interface_holding_an_address_is_not_a_connection();
	the_default_group_is_every_link_but_the_absurd_ones();
	the_primary_is_the_best_route_and_carries_the_networks_name();
	a_probe_separates_a_route_from_a_connection();
	where_an_uplink_set_is_declared_it_is_the_answer();
	a_set_with_no_usable_member_stops_at_what_it_is_holding();

	derive_runs_again_once_the_verdicts_are_on();
	the_prior_hands_its_aggregates_over();

	remove_fixture();
	if (failures == 0) {
		printf("observe_test: all checks passed\n");
	} else {
		printf("observe_test: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
