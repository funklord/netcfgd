/*
 * authorize_test.c -- who may ask for what, which is the part that must not be
 * got wrong.
 *
 * WHY THIS ONE GETS THE MOST
 *   Everything else in this port is wrong in ways somebody notices: a route
 *   does not appear, a diff is empty, a test goes red. A permission system is
 *   wrong in a way nobody notices until it matters, and the two shapes it
 *   takes are both silent -- a verb nobody remembered to classify, and a
 *   `group:` rule checked against a primary gid that denies everybody it was
 *   meant to allow while looking configured.
 *
 *   So this file asserts three things the code cannot assert about itself:
 *   that **every** request kind has a tier and that each one is the tier the
 *   protocol document and the Rust agree on; that a group membership is
 *   genuinely resolved through the supplementary set rather than the primary
 *   gid; and that the content gate stops a hook, a probe, an `exec` secret
 *   provider and a control-policy widening from a caller who is not root.
 *
 * NOTHING HERE TOUCHES THE MACHINE
 *   The real netcfgd is running on the machine this is built on. Every path is
 *   a fixture under a directory this binary made: `/etc/group`, `/etc/passwd`
 *   and `/proc` are all arguments to this module, which is the divergence from
 *   the Rust that makes `satisfies` testable at all -- its own tests say twice
 *   that resolving a group asks this machine's `/etc/group` and check the tier
 *   mapping instead.
 */
#include "ncfg/base.h"
#include "ncfg/daemon.h"
#include "ncfg/parse.h"

#include "testdir.h"

#include <stdio.h>
#include <string.h>

static int failures;

static void check(int condition, const char *what)
{
	printf("%-72s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

static void detail(const char *label, const char *text)
{
	printf("       %s: %s\n", label, text ? text : "(none)");
}

/* ------------------------------------------------------------- fixtures */

static char group_file[512];
static char passwd_file[512];
static char proc_root[512];

static ncfg_authz_roots_t fixture_roots(void)
{
	ncfg_authz_roots_t roots;

	roots.proc_root = proc_root;
	roots.group_file = group_file;
	roots.passwd_file = passwd_file;
	return roots;
}

/* A peer built by hand, which is how the Rust's tests build one too: a real
 * socket cannot be made to have a peer in an arbitrary group. */
static ncfg_peer_t peer_of(uid_t uid, gid_t gid, const gid_t *groups, size_t count)
{
	ncfg_peer_t peer;
	size_t      at;

	memset(&peer, 0, sizeof(peer));
	peer.pid = 1234;
	peer.uid = uid;
	peer.gid = gid;
	for (at = 0; at < count && at < NCFG_PEER_GROUPS_MAX; at++) {
		peer.groups[at] = groups[at];
	}
	peer.group_count = count;
	peer.group_total = count;
	peer.groups_known = 1;
	return peer;
}

static ncfg_principal_t principal(ncfg_principal_kind_t kind, char *name)
{
	ncfg_principal_t one;

	one.kind = (int)kind;
	one.name = name;
	return one;
}

static ncfg_control_t control_of(ncfg_principal_t observe, ncfg_principal_t wifi,
    ncfg_principal_t admin)
{
	ncfg_control_t control;

	control.observe = observe;
	control.wifi = wifi;
	control.admin = admin;
	return control;
}

/* Root for every tier, which is the default a machine that never edits the
 * block runs under. */
static ncfg_control_t control_default(void)
{
	return control_of(principal(NCFG_PRINCIPAL_ROOT, NULL), principal(NCFG_PRINCIPAL_ROOT, NULL),
	    principal(NCFG_PRINCIPAL_ROOT, NULL));
}

static ncfg_remote_policy_t remote_default(void)
{
	ncfg_remote_policy_t remote;

	memset(&remote, 0, sizeof(remote));
	remote.agent = principal(NCFG_PRINCIPAL_ROOT, NULL);
	return remote;
}

static ncfg_proto_request_t request_of(ncfg_proto_request_kind_t kind)
{
	ncfg_proto_request_t request;

	memset(&request, 0, sizeof(request));
	request.kind = kind;
	return request;
}

/* The local path, which is what most of the cases below are about. Wrapped so
 * that a test naming an arrival is a test that is *about* arrivals, and the
 * ones that are not stay about what they were about. */
static int check_local(const ncfg_control_t *control, const ncfg_peer_t *peer,
    const ncfg_proto_request_t *request, char *err, size_t err_size)
{
	ncfg_authz_roots_t   roots = fixture_roots();
	ncfg_remote_policy_t remote = remote_default();

	return ncfg_authz_check(&roots, control, &remote, NCFG_ARRIVED_LOCAL, peer, request, err,
	    err_size);
}

/* ------------------------------------------------------------ the tiers */

/*
 * Every request kind, with the tier the protocol document and `authorize.rs`
 * agree on, written out here rather than read from the table under test.
 *
 * **A table compared against itself proves nothing**, which is why this list
 * is spelled out by hand from `doc/socket-protocol.md` section 4 and the
 * `tier_of` match. The Rust gets this from an exhaustive match; C cannot, so
 * the exhaustiveness is the assertion at the bottom of this function: every
 * kind from 0 to `NCFG_PROTO_REQ_COUNT` must appear here exactly once, so a
 * request added to the protocol and forgotten by the table fails here rather
 * than defaulting to something nobody chose.
 */
static void every_request_has_the_tier_the_document_gives_it(void)
{
	static const struct {
		ncfg_proto_request_kind_t kind;
		ncfg_tier_t               tier;
	} expected[] = {
		{ NCFG_PROTO_REQ_HELLO, NCFG_TIER_OBSERVE },
		{ NCFG_PROTO_REQ_STATUS, NCFG_TIER_OBSERVE },
		{ NCFG_PROTO_REQ_PLAN, NCFG_TIER_OBSERVE },
		{ NCFG_PROTO_REQ_SHOW, NCFG_TIER_OBSERVE },
		{ NCFG_PROTO_REQ_EXPLAIN, NCFG_TIER_OBSERVE },
		{ NCFG_PROTO_REQ_MONITOR, NCFG_TIER_OBSERVE },
		{ NCFG_PROTO_REQ_WIFI_STATUS, NCFG_TIER_OBSERVE },
		{ NCFG_PROTO_REQ_AP_STATIONS, NCFG_TIER_OBSERVE },
		{ NCFG_PROTO_REQ_RADIOS, NCFG_TIER_OBSERVE },
		{ NCFG_PROTO_REQ_PROBE_LIST, NCFG_TIER_OBSERVE },
		{ NCFG_PROTO_REQ_CONFIG_LIST, NCFG_TIER_OBSERVE },
		{ NCFG_PROTO_REQ_PROFILE_LIST, NCFG_TIER_OBSERVE },
		{ NCFG_PROTO_REQ_MODEM_LIST, NCFG_TIER_OBSERVE },
		{ NCFG_PROTO_REQ_SECRET_LIST, NCFG_TIER_OBSERVE },
		{ NCFG_PROTO_REQ_WIFI_SCAN, NCFG_TIER_WIFI },
		{ NCFG_PROTO_REQ_WIFI_CONNECT, NCFG_TIER_WIFI },
		{ NCFG_PROTO_REQ_WIFI_DISCONNECT, NCFG_TIER_WIFI },
		{ NCFG_PROTO_REQ_WIFI_ADD, NCFG_TIER_WIFI },
		{ NCFG_PROTO_REQ_WIFI_FORGET, NCFG_TIER_WIFI },
		{ NCFG_PROTO_REQ_RADIO_SET, NCFG_TIER_WIFI },
		{ NCFG_PROTO_REQ_APPLY, NCFG_TIER_ADMIN },
		{ NCFG_PROTO_REQ_CONFIRM, NCFG_TIER_ADMIN },
		{ NCFG_PROTO_REQ_REVERT, NCFG_TIER_ADMIN },
		{ NCFG_PROTO_REQ_RELOAD, NCFG_TIER_ADMIN },
		{ NCFG_PROTO_REQ_PROFILE_SET, NCFG_TIER_ADMIN },
		{ NCFG_PROTO_REQ_PROFILE_SAVE, NCFG_TIER_ADMIN },
		{ NCFG_PROTO_REQ_HOOK_LIST, NCFG_TIER_ADMIN },
		{ NCFG_PROTO_REQ_CONFIG_PUT, NCFG_TIER_ADMIN },
		{ NCFG_PROTO_REQ_PROBE_PUT, NCFG_TIER_ADMIN },
		{ NCFG_PROTO_REQ_SECRET_PUT, NCFG_TIER_ADMIN },
		{ NCFG_PROTO_REQ_CONFIG_DELETE, NCFG_TIER_ADMIN },
		{ NCFG_PROTO_REQ_SECRET_DELETE, NCFG_TIER_ADMIN }
	};
	unsigned char seen[NCFG_PROTO_REQ_COUNT];
	int           agreed = 1;
	int           covered = 1;
	size_t        at;
	char          complaint[256] = "";

	memset(seen, 0, sizeof(seen));
	for (at = 0; at < sizeof(expected) / sizeof(expected[0]); at++) {
		ncfg_tier_t found = ncfg_tier_of(expected[at].kind);

		seen[expected[at].kind] = 1;
		if (found != expected[at].tier) {
			agreed = 0;
			if (!complaint[0]) {
				(void)snprintf(complaint, sizeof(complaint),
				    "%s is `%s` and should be `%s`",
				    ncfg_proto_request_name(expected[at].kind),
				    ncfg_tier_name(found), ncfg_tier_name(expected[at].tier));
			}
		}
	}
	check(agreed, "every request sits in the tier the protocol document gives it");
	if (!agreed) {
		detail("first disagreement", complaint);
	}
	for (at = 0; at < (size_t)NCFG_PROTO_REQ_COUNT; at++) {
		if (!seen[at]) {
			covered = 0;
			if (!complaint[0]) {
				(void)snprintf(complaint, sizeof(complaint),
				    "%s is classified nowhere",
				    ncfg_proto_request_name((ncfg_proto_request_kind_t)at));
			}
		}
	}
	check(covered, "and every request the protocol has is classified somewhere");
	if (!covered) {
		detail("first gap", complaint);
	}
}

/*
 * `apply` is admin even though a plan may contain nothing but a wifi
 * association, because a tier that can call apply can apply anything.
 */
static void apply_is_admin_whatever_it_would_do(void)
{
	check(ncfg_tier_of(NCFG_PROTO_REQ_APPLY) == NCFG_TIER_ADMIN,
	    "apply is admin whatever the plan would do");
}

/*
 * Asking what the radio is doing is reading. A status display that needs the
 * wifi tier is one that ends up being given it -- and scanning transmits, so
 * it is not reading.
 */
static void wifi_status_is_only_observe(void)
{
	ncfg_control_t       control = control_of(principal(NCFG_PRINCIPAL_ANY, NULL),
	    principal(NCFG_PRINCIPAL_ROOT, NULL), principal(NCFG_PRINCIPAL_ROOT, NULL));
	ncfg_peer_t          user = peer_of(1000, 1000, NULL, 0);
	ncfg_proto_request_t status = request_of(NCFG_PROTO_REQ_WIFI_STATUS);
	ncfg_proto_request_t scan = request_of(NCFG_PROTO_REQ_WIFI_SCAN);
	char                 err[NCFG_ERROR_MAX];

	status.u.interface = ncfg_proto_str("wlan0");
	scan.u.interface = ncfg_proto_str("wlan0");
	check(check_local(&control, &user, &status, err, sizeof(err)),
	    "asking what the radio is doing is observe");
	check(!check_local(&control, &user, &scan, err, sizeof(err)),
	    "and scanning, which transmits, is not");
}

/*
 * 0124: the wifi tier adds a network, and that is the whole of what it gained.
 *
 * Stated as a pair, because one half alone would pass for the wrong reason.
 * Moving `wifi_add` to `wifi` is only correct if `admin` still holds
 * everything that changes the machine -- a change that opened the tier by
 * widening it, rather than by moving one request into it, would satisfy the
 * first assertion and fail every one below it.
 *
 * The policy names `any` rather than `group:netcfgd`, deliberately: resolving
 * a group asks a file, and a fixture with no such group would make the whole
 * test pass for the wrong reason. That groups resolve at all is
 * `a_supplementary_group_satisfies_a_group_rule`'s job.
 */
static void the_wifi_tier_adds_a_network_and_nothing_else(void)
{
	ncfg_control_t       control = control_of(principal(NCFG_PRINCIPAL_ROOT, NULL),
	    principal(NCFG_PRINCIPAL_ANY, NULL), principal(NCFG_PRINCIPAL_ROOT, NULL));
	ncfg_peer_t          member = peer_of(1000, 1000, NULL, 0);
	ncfg_proto_request_t add = request_of(NCFG_PROTO_REQ_WIFI_ADD);
	ncfg_proto_request_t join = request_of(NCFG_PROTO_REQ_WIFI_CONNECT);
	char                 err[NCFG_ERROR_MAX];
	int                  denied = 1;
	size_t               at;
	static const ncfg_proto_request_kind_t admins[] = { NCFG_PROTO_REQ_RELOAD,
		NCFG_PROTO_REQ_CONFIRM, NCFG_PROTO_REQ_REVERT, NCFG_PROTO_REQ_APPLY };

	add.u.wifi_add.ssid = ncfg_proto_str("43616665");
	add.u.wifi_add.passphrase = ncfg_proto_str("hunter2hunter2");
	join.u.wifi_connect.interface = ncfg_proto_str("wlan0");
	join.u.wifi_connect.network = ncfg_proto_str("Cafe");

	check(ncfg_tier_of(NCFG_PROTO_REQ_WIFI_ADD) == NCFG_TIER_WIFI, "adding a network is wifi");
	check(check_local(&control, &member, &add, err, sizeof(err)),
	    "and a wifi-tier caller may add one");
	/* Joining what it just wrote, which is the point of the change: adding
	 * and connecting are one tier, so a new network needs no root shell. */
	check(check_local(&control, &member, &join, err, sizeof(err)),
	    "and may join what it just wrote");
	for (at = 0; at < sizeof(admins) / sizeof(admins[0]); at++) {
		ncfg_proto_request_t one = request_of(admins[at]);

		if (check_local(&control, &member, &one, err, sizeof(err))) {
			denied = 0;
			detail("reached", ncfg_proto_request_name(admins[at]));
		}
	}
	check(denied, "and nothing else moved into the wifi tier");
}

/* ----------------------------------------------- principals and the peer */

/*
 * Every tier against every principal, in one sweep.
 *
 * The cheap way to write this is one case per interesting pair, which is how
 * a pair gets left out. `alice` is uid 1000 in the fixture passwd and a member
 * of `netdev`, gid 44, in the fixture group file; `bob` is 1001 and is in
 * neither.
 */
static void every_tier_against_every_principal(void)
{
	static const gid_t          member_groups[] = { 27, 44 };
	static char                 alice[] = "alice";
	static char                 netdev[] = "netdev";
	static char                 nobody_real[] = "nobody-real";
	static const struct {
		ncfg_principal_kind_t kind;
		char                 *name;
		int                   alice_may;
		int                   bob_may;
	} cases[] = {
		{ NCFG_PRINCIPAL_ROOT, NULL, 0, 0 },
		{ NCFG_PRINCIPAL_ANY, NULL, 1, 1 },
		{ NCFG_PRINCIPAL_USER, alice, 1, 0 },
		{ NCFG_PRINCIPAL_GROUP, netdev, 1, 0 },
		/* A name that resolves to nothing denies rather than grants: a
		 * policy naming a user who does not exist must not be a policy
		 * naming everybody. */
		{ NCFG_PRINCIPAL_USER, nobody_real, 0, 0 },
		{ NCFG_PRINCIPAL_GROUP, nobody_real, 0, 0 }
	};
	static const ncfg_proto_request_kind_t per_tier[NCFG_TIER_COUNT] = {
		NCFG_PROTO_REQ_STATUS, NCFG_PROTO_REQ_WIFI_SCAN, NCFG_PROTO_REQ_RELOAD
	};
	ncfg_peer_t alice_peer = peer_of(1000, 1000, member_groups, 2);
	ncfg_peer_t bob_peer = peer_of(1001, 1001, NULL, 0);
	ncfg_peer_t root_peer = peer_of(0, 0, NULL, 0);
	int         agreed = 1;
	int         root_always = 1;
	size_t      one;
	int         tier;
	char        complaint[256] = "";

	for (one = 0; one < sizeof(cases) / sizeof(cases[0]); one++) {
		for (tier = 0; tier < (int)NCFG_TIER_COUNT; tier++) {
			ncfg_principal_t     open = principal(cases[one].kind, cases[one].name);
			ncfg_principal_t     shut = principal(NCFG_PRINCIPAL_ROOT, NULL);
			ncfg_control_t       control;
			ncfg_proto_request_t request = request_of(per_tier[tier]);
			char                 err[NCFG_ERROR_MAX];
			int                  got;

			/* One tier open and the other two shut, so a pass cannot come
			 * from the tier next door. */
			control.observe = (tier == 0) ? open : shut;
			control.wifi = (tier == 1) ? open : shut;
			control.admin = (tier == 2) ? open : shut;
			request.u.interface = ncfg_proto_str("wlan0");

			got = check_local(&control, &alice_peer, &request, err, sizeof(err)) ? 1 : 0;
			if (got != cases[one].alice_may) {
				agreed = 0;
				if (!complaint[0]) {
					(void)snprintf(complaint, sizeof(complaint),
					    "alice at `%s` under principal %d/%s: got %d",
					    ncfg_tier_name((ncfg_tier_t)tier), (int)cases[one].kind,
					    cases[one].name ? cases[one].name : "-", got);
				}
			}
			got = check_local(&control, &bob_peer, &request, err, sizeof(err)) ? 1 : 0;
			if (got != cases[one].bob_may) {
				agreed = 0;
				if (!complaint[0]) {
					(void)snprintf(complaint, sizeof(complaint),
					    "bob at `%s` under principal %d/%s: got %d",
					    ncfg_tier_name((ncfg_tier_t)tier), (int)cases[one].kind,
					    cases[one].name ? cases[one].name : "-", got);
				}
			}
			if (!check_local(&control, &root_peer, &request, err, sizeof(err))) {
				root_always = 0;
			}
		}
	}
	check(agreed, "every tier answers every principal the way the policy says");
	if (!agreed) {
		detail("first disagreement", complaint);
	}
	/*
	 * Root satisfies every tier, always. A config that locked root out would
	 * be unrecoverable without editing the file the daemon will not let you
	 * reach.
	 */
	check(root_always, "and root is never locked out, whatever the policy names");
}

/*
 * Supplementary groups count.
 *
 * Checking the primary gid alone would deny nearly everybody a `group:` rule
 * is meant to allow, while appearing to work -- the worst kind of security
 * control. So this asks the question through the whole path, with a peer whose
 * *primary* group is their own and whose membership is supplementary, which is
 * the ordinary shape on every desktop.
 */
static void a_supplementary_group_satisfies_a_group_rule(void)
{
	static const gid_t   groups[] = { 27, 44 };
	static char          netdev[] = "netdev";
	ncfg_peer_t          member = peer_of(1000, 1000, groups, 2);
	ncfg_peer_t          outsider = peer_of(1000, 1000, NULL, 0);
	ncfg_control_t       control = control_of(principal(NCFG_PRINCIPAL_GROUP, netdev),
	    principal(NCFG_PRINCIPAL_ROOT, NULL), principal(NCFG_PRINCIPAL_ROOT, NULL));
	ncfg_proto_request_t status = request_of(NCFG_PROTO_REQ_STATUS);
	char                 err[NCFG_ERROR_MAX];

	check(ncfg_peer_in_group(&member, 44), "a supplementary membership counts");
	check(ncfg_peer_in_group(&member, 1000), "and so does the primary group");
	check(!ncfg_peer_in_group(&member, 999), "and a group they are not in does not");
	check(check_local(&control, &member, &status, err, sizeof(err)),
	    "a peer in the named group is served");
	check(!check_local(&control, &outsider, &status, err, sizeof(err)),
	    "and a peer whose primary gid is their own, and nothing else, is not");
}

/*
 * Groups that could not be read deny rather than allow.
 *
 * The defect this is about: an empty supplementary set means "could not tell"
 * and not "in no group", and a reader that treated the two as the same in the
 * *permissive* direction would serve a `group:` rule to anybody whose `/proc`
 * entry was unreadable -- which is every peer in a different pid namespace.
 * The peer here is genuinely in the group; what is broken is the reading.
 */
static void groups_that_could_not_be_read_deny(void)
{
	static char          netdev[] = "netdev";
	ncfg_peer_t          peer;
	ncfg_control_t       control = control_of(principal(NCFG_PRINCIPAL_GROUP, netdev),
	    principal(NCFG_PRINCIPAL_ROOT, NULL), principal(NCFG_PRINCIPAL_ROOT, NULL));
	ncfg_proto_request_t status = request_of(NCFG_PROTO_REQ_STATUS);
	char                 err[NCFG_ERROR_MAX];
	char                 path[640];
	char                 body[256];

	/* A pid with no `status` file at all. */
	memset(&peer, 0, sizeof(peer));
	peer.pid = 4242;
	peer.uid = 1000;
	peer.gid = 1000;
	check(!ncfg_peer_groups_from(proc_root, 4242, 1000, &peer),
	    "a process with no status file yields no groups");
	check(peer.groups_known == 0, "and says so rather than reporting an empty set");
	check(!check_local(&control, &peer, &status, err, sizeof(err)),
	    "and a group rule against it denies");

	/*
	 * And the recycled pid, which is the case the uid cross-check exists for:
	 * the file is there, it lists the group, and it belongs to somebody else.
	 * A reader that took the groups without checking the uid would hand this
	 * caller the membership of whoever now holds that pid.
	 */
	(void)snprintf(path, sizeof(path), "%s/7777", proc_root);
	check(mkdir(path, 0700) == 0 || testdir_exists(path), "a fixture process directory");
	(void)snprintf(path, sizeof(path), "%s/7777/status", proc_root);
	(void)snprintf(body, sizeof(body), "Name:\tsomebody\nUid:\t1001\t1001\t1001\t1001\n"
	    "Groups:\t27 44 \n");
	check(testdir_write(path, body, strlen(body)), "written with a different owner");

	memset(&peer, 0, sizeof(peer));
	peer.pid = 7777;
	peer.uid = 1000;
	peer.gid = 1000;
	check(!ncfg_peer_groups_from(proc_root, 7777, 1000, &peer),
	    "a recycled pid belonging to another user yields no groups");
	check(peer.group_count == 0, "and nothing it listed is kept");
	check(!check_local(&control, &peer, &status, err, sizeof(err)),
	    "so the group rule denies rather than borrowing somebody else's membership");

	/* The same file, read for the user it actually belongs to, does resolve --
	 * without which the assertions above would pass on a reader that always
	 * returned nothing. */
	memset(&peer, 0, sizeof(peer));
	peer.pid = 7777;
	peer.uid = 1001;
	peer.gid = 1001;
	check(ncfg_peer_groups_from(proc_root, 7777, 1001, &peer),
	    "and the same file read for its real owner does resolve");
	check(peer.group_count == 2 && peer.groups[1] == 44,
	    "with the supplementary set the kernel wrote");
}

/*
 * A process genuinely in no supplementary group is a known empty set, not an
 * unknown one.
 *
 * The other half of the pair above: if "could not tell" were the only answer
 * this module could give, a machine whose users are in no groups would look
 * like a machine whose `/proc` is unreadable, and nobody would ever find out.
 */
static void no_groups_and_unknown_groups_are_different_answers(void)
{
	ncfg_peer_t peer;
	char        path[640];
	const char *body = "Name:\tlonely\nUid:\t1002\t1002\t1002\t1002\nGroups:\t\n";

	(void)snprintf(path, sizeof(path), "%s/8888", proc_root);
	(void)mkdir(path, 0700);
	(void)snprintf(path, sizeof(path), "%s/8888/status", proc_root);
	check(testdir_write(path, body, strlen(body)), "a process in no supplementary group");

	memset(&peer, 0, sizeof(peer));
	check(ncfg_peer_groups_from(proc_root, 8888, 1002, &peer),
	    "an empty Groups: line is a set that was read");
	check(peer.groups_known == 1 && peer.group_count == 0,
	    "and it is known and empty, which is not the same as unknown");
}

/* ----------------------------------------------------- what hello answers */

/*
 * What a peer is told it may do is what `check` allows.
 *
 * 0092's rule. The whole value of answering this in `hello` is that a client
 * stops having to find out by being refused, so the answer has to agree with
 * `check` for every tier -- a list that said more would put a button on a
 * screen that fails when pressed, and one that said less would hide a thing
 * the operator is allowed to do.
 */
static void what_a_peer_is_told_it_may_do_is_what_check_allows(void)
{
	static const ncfg_proto_request_kind_t per_tier[NCFG_TIER_COUNT] = {
		NCFG_PROTO_REQ_STATUS, NCFG_PROTO_REQ_WIFI_SCAN, NCFG_PROTO_REQ_RELOAD
	};
	ncfg_control_t       control = control_of(principal(NCFG_PRINCIPAL_ANY, NULL),
	    principal(NCFG_PRINCIPAL_ROOT, NULL), principal(NCFG_PRINCIPAL_ROOT, NULL));
	ncfg_authz_roots_t   roots = fixture_roots();
	ncfg_remote_policy_t remote = remote_default();
	ncfg_peer_t          who[2];
	int                  agreed = 1;
	size_t               person;
	int                  tier;

	who[0] = peer_of(1000, 1000, NULL, 0);
	who[1] = peer_of(0, 0, NULL, 0);
	for (person = 0; person < 2; person++) {
		ncfg_tier_t told[NCFG_TIER_COUNT];
		size_t      count = ncfg_authz_granted(&roots, &control, &remote, NCFG_ARRIVED_LOCAL,
		    &who[person], told);

		for (tier = 0; tier < (int)NCFG_TIER_COUNT; tier++) {
			ncfg_proto_request_t request = request_of(per_tier[tier]);
			char                 err[NCFG_ERROR_MAX];
			int                  listed = 0;
			size_t               at;

			request.u.interface = ncfg_proto_str("wlan0");
			for (at = 0; at < count; at++) {
				if (told[at] == (ncfg_tier_t)tier) {
					listed = 1;
				}
			}
			if (listed != (check_local(&control, &who[person], &request, err,
			        sizeof(err)) ? 1 : 0)) {
				agreed = 0;
				detail("disagreed about", ncfg_tier_name((ncfg_tier_t)tier));
			}
		}
	}
	check(agreed, "what a peer is told it may do is what check allows");
}

/*
 * The tiers are three memberships, not a ladder.
 *
 * A machine may grant `admin` to a group somebody is in and `wifi` to one they
 * are not. Reporting a highest tier, or filling in the ones below it, would
 * tell them they can do something they cannot.
 */
static void the_tiers_are_not_a_ladder(void)
{
	static char          netdev[] = "netdev";
	ncfg_control_t       control = control_of(principal(NCFG_PRINCIPAL_ANY, NULL),
	    principal(NCFG_PRINCIPAL_GROUP, netdev), principal(NCFG_PRINCIPAL_ANY, NULL));
	ncfg_authz_roots_t   roots = fixture_roots();
	ncfg_remote_policy_t remote = remote_default();
	/* In no group, so the tier that is out of reach is the middle one. */
	ncfg_peer_t          user = peer_of(1000, 1000, NULL, 0);
	ncfg_tier_t          told[NCFG_TIER_COUNT];
	size_t               count = ncfg_authz_granted(&roots, &control, &remote,
	    NCFG_ARRIVED_LOCAL, &user, told);

	check(count == 2 && told[0] == NCFG_TIER_OBSERVE && told[1] == NCFG_TIER_ADMIN,
	    "a peer may hold admin and not wifi, and is told exactly that");
}

/*
 * A refusal names the tier, the policy and where to change it.
 *
 * "Denied" on its own sends the reader to the source code, and section 7 asks
 * a client to pass this sentence on unreworded for that reason.
 */
static void a_refusal_says_what_to_do_about_it(void)
{
	static char netdev[] = "netdev";
	ncfg_principal_t group = principal(NCFG_PRINCIPAL_GROUP, netdev);
	char             message[NCFG_ERROR_MAX];

	ncfg_authz_refusal(NCFG_TIER_WIFI, &group, message, sizeof(message));
	check(strstr(message, "wifi") != NULL, "a refusal names the tier that was needed");
	check(strstr(message, "group:netdev") != NULL, "and what the configuration opens it to");
	check(strstr(message, "netcfgd.conf") != NULL, "and where to change it");
}

/* ----------------------------------------------------------- the arrivals */

/*
 * 0128: a wide-open local policy does not reach the network.
 *
 * The property the split exists for, and the one that would be worth nothing
 * if it held only when local was closed. The holder's intent is that a
 * distribution could put every user in the `netcfgd` group, so this sets local
 * to the widest thing expressible -- `any` on all three tiers -- and asserts
 * that a remote caller still reaches nothing.
 */
static void an_open_local_policy_opens_nothing_remotely(void)
{
	ncfg_control_t       control = control_of(principal(NCFG_PRINCIPAL_ANY, NULL),
	    principal(NCFG_PRINCIPAL_ANY, NULL), principal(NCFG_PRINCIPAL_ANY, NULL));
	ncfg_remote_policy_t remote = remote_default();
	ncfg_authz_roots_t   roots = fixture_roots();
	ncfg_peer_t          caller = peer_of(1000, 1000, NULL, 0);
	static const ncfg_proto_request_kind_t both[] = { NCFG_PROTO_REQ_STATUS,
		NCFG_PROTO_REQ_RELOAD };
	int                  local_open = 1;
	int                  remote_shut = 1;
	size_t               at;

	for (at = 0; at < sizeof(both) / sizeof(both[0]); at++) {
		ncfg_proto_request_t request = request_of(both[at]);
		char                 err[NCFG_ERROR_MAX];

		if (!ncfg_authz_check(&roots, &control, &remote, NCFG_ARRIVED_LOCAL, &caller,
		        &request, err, sizeof(err))) {
			local_open = 0;
		}
		if (ncfg_authz_check(&roots, &control, &remote, NCFG_ARRIVED_REMOTE, &caller,
		        &request, err, sizeof(err))) {
			remote_shut = 0;
			detail("reached the machine from off it", ncfg_proto_request_name(both[at]));
		}
	}
	check(local_open, "local is wide open here");
	check(remote_shut, "and a remote caller reaches nothing the remote policy did not name");
}

/*
 * Peer credentials are not consulted for a remote caller.
 *
 * The one that would pass by accident if `check` fell through to the local
 * path: root satisfies every local principal, so a remote connection whose
 * peer happens to be root would reach everything if the arrival were not
 * decided first. `agent/` running as root is a plausible deployment, which
 * makes this the case to pin rather than a contrived one.
 */
static void a_remote_caller_that_is_root_is_still_bounded_by_the_remote_policy(void)
{
	ncfg_control_t       control = control_default();
	ncfg_remote_policy_t remote = remote_default();
	ncfg_authz_roots_t   roots = fixture_roots();
	ncfg_peer_t          root = peer_of(0, 0, NULL, 0);
	ncfg_proto_request_t status = request_of(NCFG_PROTO_REQ_STATUS);
	ncfg_proto_request_t reload = request_of(NCFG_PROTO_REQ_RELOAD);
	char                 err[NCFG_ERROR_MAX];

	remote.observe = 1;
	check(ncfg_authz_check(&roots, &control, &remote, NCFG_ARRIVED_REMOTE, &root, &status, err,
	          sizeof(err)),
	    "a remote caller reaches what the remote policy names");
	check(!ncfg_authz_check(&roots, &control, &remote, NCFG_ARRIVED_REMOTE, &root, &reload, err,
	          sizeof(err)),
	    "and root over the remote socket does not reach admin");
	check(strstr(err, "off this machine") != NULL,
	    "and the refusal says the request came from off the machine");
}

/*
 * What a remote peer is told it may do is what it may do.
 *
 * 0092's rule, which the split could have broken quietly: `granted` answers
 * `hello`, and answering it from the local policy while `check` answers from
 * the remote one puts buttons on a screen that fail when pressed.
 */
static void a_remote_peer_is_told_what_the_remote_policy_allows(void)
{
	ncfg_control_t       control = control_of(principal(NCFG_PRINCIPAL_ROOT, NULL),
	    principal(NCFG_PRINCIPAL_ROOT, NULL), principal(NCFG_PRINCIPAL_ANY, NULL));
	ncfg_remote_policy_t remote = remote_default();
	ncfg_authz_roots_t   roots = fixture_roots();
	ncfg_peer_t          caller = peer_of(1000, 1000, NULL, 0);
	ncfg_tier_t          told[NCFG_TIER_COUNT];
	size_t               count;

	remote.observe = 1;
	remote.wifi = 1;
	count = ncfg_authz_granted(&roots, &control, &remote, NCFG_ARRIVED_REMOTE, &caller, told);
	check(count == 2 && told[0] == NCFG_TIER_OBSERVE && told[1] == NCFG_TIER_WIFI,
	    "a remote peer is told what the remote policy allows, not what local does");
}

/* ------------------------------------------------------ the content gate */

static ncfg_proto_request_t config_put(const char *text)
{
	ncfg_proto_request_t request = request_of(NCFG_PROTO_REQ_CONFIG_PUT);

	request.u.put.name = ncfg_proto_str("from-a-client");
	request.u.put.text = ncfg_proto_str(text);
	return request;
}

/*
 * Both gates are in the path a request actually takes.
 *
 * Written in the Rust after removing the content gate from the daemon and
 * watching every test still pass: they called it directly, so they proved the
 * function right and proved nothing about it being called. A correct function
 * nobody invokes is the shape this tree keeps finding, and it is why there is
 * one `permitted` rather than two calls to remember.
 */
static void permitted_asks_both_gates(void)
{
	ncfg_control_t       open_admin = control_of(principal(NCFG_PRINCIPAL_ROOT, NULL),
	    principal(NCFG_PRINCIPAL_ROOT, NULL), principal(NCFG_PRINCIPAL_ANY, NULL));
	ncfg_control_t       closed = control_default();
	ncfg_remote_policy_t remote = remote_default();
	ncfg_authz_roots_t   roots = fixture_roots();
	ncfg_peer_t          member = peer_of(1000, 1000, NULL, 0);
	ncfg_proto_request_t hook = config_put("interface eth0 {\n\tpost_up {\n\t\tid\n\t}\n}\n");
	ncfg_proto_request_t reload = request_of(NCFG_PROTO_REQ_RELOAD);
	char                 err[NCFG_ERROR_MAX];

	check(ncfg_authz_check(&roots, &open_admin, &remote, NCFG_ARRIVED_LOCAL, &member, &hook,
	          err, sizeof(err)),
	    "the tier gate alone admits a config_put carrying a hook");
	check(!ncfg_authz_permitted(&roots, &open_admin, &remote, NCFG_ARRIVED_LOCAL, &member,
	          &hook, err, sizeof(err)),
	    "and the one the daemon calls does not");
	/* And the tier gate still refuses what it always refused, so this is both
	 * gates rather than the second one wearing both hats. */
	check(!ncfg_authz_permitted(&roots, &closed, &remote, NCFG_ARRIVED_LOCAL, &member, &reload,
	          err, sizeof(err)),
	    "the tier gate still refuses a closed policy");
	check(ncfg_authz_permitted(&roots, &open_admin, &remote, NCFG_ARRIVED_LOCAL, &member,
	          &reload, err, sizeof(err)),
	    "and still admits an open one");
}

/*
 * 0127: opening `admin` to a group does not hand that group root.
 *
 * The property the whole classification exists for. `admin` is what writing
 * configuration needs, and a site that opens it -- which is the stated intent
 * for local -- would be granting root outright if config text could carry a
 * hook, because a hook with no `run_as` runs as the daemon's user. So the tier
 * lets the request through and the content gate stops it.
 */
static void an_admin_group_member_may_send_config_but_not_a_hook(void)
{
	ncfg_peer_t          member = peer_of(1000, 1000, NULL, 0);
	ncfg_peer_t          root = peer_of(0, 0, NULL, 0);
	ncfg_proto_request_t ordinary = config_put("interface eth0 {\n\tconfig = \"dhcp\"\n}\n");
	ncfg_proto_request_t with_hook = config_put(
	    "interface eth0 {\n\tconfig = \"dhcp\"\n\tpost_up {\n\t\tid\n\t}\n}\n");
	char                 err[NCFG_ERROR_MAX];

	check(ncfg_authz_check_content(NCFG_ARRIVED_LOCAL, &member, &ordinary, err, sizeof(err)),
	    "an ordinary interface block is not privileged");
	check(!ncfg_authz_check_content(NCFG_ARRIVED_LOCAL, &member, &with_hook, err, sizeof(err)),
	    "a hook from a non-root caller is refused");
	check(strstr(err, "root") != NULL && strstr(err, "shell") != NULL,
	    "and the refusal names what it grants");
	detail("refusal", err);
	/* Root on this machine may send it, or the gate would forbid the
	 * configuration rather than bounding who writes it. */
	check(ncfg_authz_check_content(NCFG_ARRIVED_LOCAL, &root, &with_hook, err, sizeof(err)),
	    "and root on this machine may send one");
}

/*
 * A hook never arrives from off the machine, whatever the remote policy says.
 *
 * A remote caller has no uid the daemon can check, so there is no version of
 * "is this root" to ask. The peer here *is* root -- `agent/` running as root is
 * a plausible deployment -- which is exactly the case that would pass if the
 * check asked about the peer before asking about the arrival.
 */
static void a_hook_never_arrives_from_off_the_machine(void)
{
	ncfg_peer_t          root = peer_of(0, 0, NULL, 0);
	ncfg_proto_request_t with_hook = config_put("interface eth0 {\n\tpost_up {\n\t\tid\n\t}\n}\n");
	char                 err[NCFG_ERROR_MAX];

	check(!ncfg_authz_check_content(NCFG_ARRIVED_REMOTE, &root, &with_hook, err, sizeof(err)),
	    "a hook from off the machine is refused even when the peer is root");
}

/*
 * The four productions the brief names, each from a caller who is not root.
 *
 * A hook, a probe block, an `exec` secret provider and a control-policy
 * widening. The last two are the ones a list written from memory misses:
 * `@secret:exec:` lives inside the secrets feature where nobody auditing for
 * code execution would look, and `control { admin = "any" }` is neither a path
 * nor a command -- it is escalation by configuration, and a caller able to
 * send it could grant itself what it was not given.
 */
static void the_content_gate_refuses_each_privileged_production(void)
{
	static const struct {
		const char *text;
		const char *what;
		const char *names;
	} cases[] = {
		{ "interface eth0 {\n\tpost_up {\n\t\tid\n\t}\n}\n", "a hook", "shell" },
		{ "interface eth0 {\n\tprobe {\n\t\tcommand = \"/bin/true\"\n\t}\n}\n",
		    "a probe block", "program" },
		{ "network \"Corp\" {\n\twifi {\n\t\tpsk = \"@secret:exec:fetch\"\n\t}\n}\n",
		    "an exec secret provider", "command" },
		{ "global {\n\tcontrol {\n\t\tadmin = \"any\"\n\t}\n}\n",
		    "a control-policy widening", "who may ask" },
		{ "interface tun0 {\n\topenvpn {\n\t\tconfig = \"/etc/openvpn/c.conf\"\n\t}\n}\n",
		    "another program's configuration file", "as root" },
		{ "include \"/etc/netcfgd/site.conf\"\n", "an include", "another file" },
		{ "interface tun0 {\n\ttun {\n\t\towner = \"nobody\"\n\t}\n}\n",
		    "a tun device given away", "user or group" }
	};
	ncfg_peer_t member = peer_of(1000, 1000, NULL, 0);
	size_t      at;

	for (at = 0; at < sizeof(cases) / sizeof(cases[0]); at++) {
		ncfg_proto_request_t request = config_put(cases[at].text);
		char                 err[NCFG_ERROR_MAX];
		char                 what[128];

		(void)snprintf(what, sizeof(what), "%s is refused from a caller who is not root",
		    cases[at].what);
		check(!ncfg_authz_check_content(NCFG_ARRIVED_LOCAL, &member, &request, err,
		    sizeof(err)), what);
		(void)snprintf(what, sizeof(what), "and the refusal says why: `%s`",
		    cases[at].names);
		check(strstr(err, cases[at].names) != NULL, what);
		if (strstr(err, cases[at].names) == NULL) {
			detail("refusal", err);
		}
	}
}

/*
 * The ordinary desktop case is ordinary, which is the half that matters most:
 * a classifier that refused everything would pass every case above and make
 * the feature pointless.
 */
static void an_ordinary_configuration_is_not_privileged(void)
{
	static const char *const ordinary[] = {
		"interface eth0 {\n\tconfig = [\"dhcp\", \"192.0.2.10/24\"]\n\t"
		"routes = \"default via 192.0.2.1\"\n}\n",
		"network \"Cafe\" {\n\twifi {\n\t\tpsk = \"@secret:cafe\"\n\t}\n}\n",
		/* A `file` provider is not an `exec` one, in the same position. */
		"network \"Corp\" {\n\twifi {\n\t\tpsk = \"@secret:file:home\"\n\t}\n}\n",
		/* `interval` inside a privileged block is ordinary, which is what
		 * makes this a classification rather than a block-level refusal. */
		"interface eth0 {\n\tprobe {\n\t\tinterval = 30\n\t}\n}\n",
		/* A vxlan `group` is a multicast address and shares the word with
		 * the tun key that gives a device away. */
		"interface vx0 {\n\tvxlan {\n\t\tid = 100\n\t\tgroup = \"239.1.1.1\"\n\t}\n}\n"
	};
	ncfg_peer_t member = peer_of(1000, 1000, NULL, 0);
	size_t      at;
	int         all_ordinary = 1;

	for (at = 0; at < sizeof(ordinary) / sizeof(ordinary[0]); at++) {
		ncfg_proto_request_t request = config_put(ordinary[at]);
		char                 err[NCFG_ERROR_MAX];

		if (!ncfg_authz_check_content(NCFG_ARRIVED_LOCAL, &member, &request, err,
		        sizeof(err))) {
			all_ordinary = 0;
			detail("refused", ordinary[at]);
			detail("because", err);
		}
	}
	check(all_ordinary, "an ordinary configuration is sent by a caller who is not root");
}

/*
 * The pair that proves the table is keyed on the block and not the key.
 *
 * `config` means an addressing list in one block and the path to a `.ovpn`
 * file in another. A key-only table gets one of them wrong, and gets it wrong
 * silently -- which is the whole reason the table carries a block.
 */
static void config_is_privileged_in_openvpn_and_ordinary_in_an_interface(void)
{
	ncfg_peer_t          member = peer_of(1000, 1000, NULL, 0);
	ncfg_proto_request_t foreign = config_put(
	    "interface tun0 {\n\topenvpn {\n\t\tconfig = \"/etc/openvpn/c.conf\"\n\t}\n}\n");
	ncfg_proto_request_t ours = config_put("interface eth0 {\n\tconfig = \"dhcp\"\n}\n");
	char                 err[NCFG_ERROR_MAX];

	check(!ncfg_authz_check_content(NCFG_ARRIVED_LOCAL, &member, &foreign, err, sizeof(err)),
	    "`config` inside openvpn names a foreign file and is privileged");
	check(ncfg_authz_check_content(NCFG_ARRIVED_LOCAL, &member, &ours, err, sizeof(err)),
	    "and `config` inside an interface is an addressing list and is not");
}

/*
 * A certificate path is privileged and stored content is not.
 *
 * The pair 0127 predicted. A path is an instruction to open a file as root,
 * and `@secret:name` refers to something netcfgd already holds because a
 * caller sent it. Without the second half an enterprise network is unreachable
 * from any client that is not root, which is most of them; without the first,
 * a caller could point a supplicant running as root at any file on the
 * machine.
 */
static void a_certificate_path_is_privileged_and_stored_content_is_not(void)
{
	ncfg_peer_t          member = peer_of(1000, 1000, NULL, 0);
	ncfg_proto_request_t path = config_put("network \"eduroam\" {\n\twifi {\n\t\t"
	    "eap = \"peap\"\n\t\tca_cert = \"/etc/ssl/x.pem\"\n\t}\n}\n");
	ncfg_proto_request_t stored = config_put("network \"eduroam\" {\n\twifi {\n\t\t"
	    "eap = \"peap\"\n\t\tca_cert = \"@secret:corp-ca\"\n\t}\n}\n");
	ncfg_proto_request_t key_path = config_put("network \"corp\" {\n\twifi {\n\t\t"
	    "eap = \"tls\"\n\t\tprivate_key = \"/etc/ssl/k.pem\"\n\t}\n}\n");
	ncfg_proto_request_t key_stored = config_put("network \"corp\" {\n\twifi {\n\t\t"
	    "eap = \"tls\"\n\t\tprivate_key = \"@secret:corp-key\"\n\t}\n}\n");
	char                 err[NCFG_ERROR_MAX];

	check(!ncfg_authz_check_content(NCFG_ARRIVED_LOCAL, &member, &path, err, sizeof(err)),
	    "a certificate that names a path is privileged");
	check(ncfg_authz_check_content(NCFG_ARRIVED_LOCAL, &member, &stored, err, sizeof(err)),
	    "and one that names a stored secret is not");
	check(!ncfg_authz_check_content(NCFG_ARRIVED_LOCAL, &member, &key_path, err, sizeof(err)),
	    "a private key that names a path is privileged");
	check(ncfg_authz_check_content(NCFG_ARRIVED_LOCAL, &member, &key_stored, err, sizeof(err)),
	    "and a stored one is not");
}

/*
 * Writing a probe is root in fact, without the text being parsed at all.
 *
 * A probe script is the program a privileged production would merely have
 * *named*, so it takes the same answer without needing to be classified: there
 * is no shape of shell that grants less than root here.
 */
static void a_probe_script_needs_root_whatever_is_in_it(void)
{
	ncfg_peer_t          member = peer_of(1000, 1000, NULL, 0);
	ncfg_peer_t          root = peer_of(0, 0, NULL, 0);
	ncfg_proto_request_t put = request_of(NCFG_PROTO_REQ_PROBE_PUT);
	char                 err[NCFG_ERROR_MAX];

	put.u.put.name = ncfg_proto_str("wan-up");
	put.u.put.text = ncfg_proto_str("#!/bin/sh\nexit 0\n");
	check(!ncfg_authz_check_content(NCFG_ARRIVED_LOCAL, &member, &put, err, sizeof(err)),
	    "writing a link-detection script needs root");
	check(strstr(err, "wan-up") != NULL, "and the refusal names the script");
	check(ncfg_authz_check_content(NCFG_ARRIVED_LOCAL, &root, &put, err, sizeof(err)),
	    "root on this machine may write one");
	check(!ncfg_authz_check_content(NCFG_ARRIVED_REMOTE, &root, &put, err, sizeof(err)),
	    "and it never arrives from off the machine");
}

/*
 * Text that does not parse is not this gate's to refuse.
 *
 * The writer compiles it and reports diagnostics pointing at the line.
 * Answering a syntax error with a sentence about privilege would send the
 * reader looking for a permission problem they do not have.
 */
static void unparseable_text_is_left_to_the_compiler(void)
{
	ncfg_peer_t          member = peer_of(1000, 1000, NULL, 0);
	ncfg_proto_request_t broken = config_put("interface {{{");
	char                 err[NCFG_ERROR_MAX];

	check(ncfg_authz_check_content(NCFG_ARRIVED_LOCAL, &member, &broken, err, sizeof(err)),
	    "text that does not parse is left to the compiler");
}

/*
 * More than one privileged production says how many there were.
 *
 * The count comes from `total`, which goes on counting past the bound the
 * findings are kept to -- so a file with a hundred hooks still reports a
 * hundred rather than sixty-four.
 */
static void several_privileged_productions_are_counted(void)
{
	ncfg_peer_t          member = peer_of(1000, 1000, NULL, 0);
	ncfg_proto_request_t many = config_put(
	    "interface eth0 {\n\tpost_up {\n\t\tid\n\t}\n\tpost_down {\n\t\tid\n\t}\n}\n");
	char                 err[NCFG_ERROR_MAX];

	check(!ncfg_authz_check_content(NCFG_ARRIVED_LOCAL, &member, &many, err, sizeof(err)),
	    "a configuration with two hooks is refused");
	check(strstr(err, "2 such productions") != NULL, "and the refusal counts them");
	detail("refusal", err);
}

/*
 * The findings are bounded and the count is not.
 *
 * `NCFG_DIAGS_MAX` bounds what is kept for the reason the parser's diagnostics
 * are bounded: a finding per line is a file-sized allocation bought with a
 * file a client sent. The divergence is only worth having if `total` still
 * tells the truth, which is what this measures at the boundary.
 */
static void the_findings_are_bounded_and_the_total_is_not(void)
{
	ncfg_buf_t                text;
	ncfg_ast_file_t          *file = NULL;
	ncfg_privilege_findings_t findings = { 0 };
	char                      err[NCFG_ERROR_MAX];
	int                       at;

	ncfg_buf_init(&text, 0);
	ncfg_buf_add_text(&text, "interface eth0 {\n");
	for (at = 0; at < NCFG_DIAGS_MAX + 10; at++) {
		ncfg_buf_addf(&text, "\tinclude \"site-%d.conf\"\n", at);
	}
	ncfg_buf_add_text(&text, "}\n");
	check(ncfg_parse(ncfg_buf_text(&text), text.length, &file, NULL, err, sizeof(err)),
	    "a file with more privileged productions than the bound parses");
	check(ncfg_privilege_findings(file, &findings, err, sizeof(err)),
	    "and it classifies");
	check(findings.count == NCFG_DIAGS_MAX, "the kept findings stop at the bound");
	check(findings.total == (size_t)(NCFG_DIAGS_MAX + 10),
	    "and the total goes on counting past it");
	ncfg_privilege_findings_free(&findings);
	ncfg_ast_file_free(file);
	ncfg_buf_free(&text);
}

/* Freeing what was never filled in is nothing, which is the rule every error
 * path in this module is written on. */
static void freeing_what_was_never_filled_in_is_nothing(void)
{
	ncfg_privilege_findings_t findings = { 0 };

	ncfg_privilege_findings_free(&findings);
	ncfg_privilege_findings_free(&findings);
	ncfg_privilege_findings_free(NULL);
	check(findings.at == NULL && findings.count == 0, "freeing what was never filled in");
}

/* --------------------------------------------------------------- fixtures */

static void write_fixtures(const char *base)
{
	static const char *const group_text =
	    "root:x:0:\n"
	    "netdev:x:44:alice\n"
	    "plugdev:x:46:\n"
	    "broken:x:notanumber:\n";
	static const char *const passwd_text =
	    "root:x:0:0:root:/root:/bin/sh\n"
	    "alice:x:1000:1000::/home/alice:/bin/sh\n"
	    "bob:x:1001:1001::/home/bob:/bin/sh\n";

	(void)testdir_in(base, "group", group_file, sizeof(group_file));
	(void)testdir_in(base, "passwd", passwd_file, sizeof(passwd_file));
	(void)testdir_in(base, "proc", proc_root, sizeof(proc_root));
	if (!testdir_write(group_file, group_text, strlen(group_text)) ||
	    !testdir_write(passwd_file, passwd_text, strlen(passwd_text)) ||
	    mkdir(proc_root, 0700) != 0) {
		printf("the fixtures could not be written under %s\n", base);
		failures++;
	}
}

/* The lookups themselves, since every case above depends on them resolving. */
static void the_fixture_databases_resolve(void)
{
	uid_t uid = 0;
	gid_t gid = 0;

	check(ncfg_peer_user_id(passwd_file, "alice", &uid) && uid == 1000,
	    "a user resolves out of the passwd file");
	check(ncfg_peer_group_id(group_file, "netdev", &gid) && gid == 44,
	    "a group resolves out of the group file");
	check(!ncfg_peer_user_id(passwd_file, "nobody-real", &uid), "and an absent user does not");
	check(!ncfg_peer_group_id(group_file, "broken", &gid),
	    "and a group whose id is not a number resolves to nothing rather than to zero");
	check(!ncfg_peer_group_id(group_file, "", &gid), "and an empty name resolves to nothing");
}

int main(void)
{
	const char *base = testdir_make("authorize");

	write_fixtures(base);
	the_fixture_databases_resolve();

	every_request_has_the_tier_the_document_gives_it();
	apply_is_admin_whatever_it_would_do();
	wifi_status_is_only_observe();
	the_wifi_tier_adds_a_network_and_nothing_else();

	every_tier_against_every_principal();
	a_supplementary_group_satisfies_a_group_rule();
	groups_that_could_not_be_read_deny();
	no_groups_and_unknown_groups_are_different_answers();

	what_a_peer_is_told_it_may_do_is_what_check_allows();
	the_tiers_are_not_a_ladder();
	a_refusal_says_what_to_do_about_it();

	an_open_local_policy_opens_nothing_remotely();
	a_remote_caller_that_is_root_is_still_bounded_by_the_remote_policy();
	a_remote_peer_is_told_what_the_remote_policy_allows();

	permitted_asks_both_gates();
	an_admin_group_member_may_send_config_but_not_a_hook();
	a_hook_never_arrives_from_off_the_machine();
	the_content_gate_refuses_each_privileged_production();
	an_ordinary_configuration_is_not_privileged();
	config_is_privileged_in_openvpn_and_ordinary_in_an_interface();
	a_certificate_path_is_privileged_and_stored_content_is_not();
	a_probe_script_needs_root_whatever_is_in_it();
	unparseable_text_is_left_to_the_compiler();
	several_privileged_productions_are_counted();
	the_findings_are_bounded_and_the_total_is_not();
	freeing_what_was_never_filled_in_is_nothing();

	testdir_remove(base);
	if (failures == 0) {
		printf("authorize_test: all checks passed\n");
	} else {
		printf("authorize_test: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
