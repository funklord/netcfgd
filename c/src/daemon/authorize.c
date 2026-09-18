/*
 * authorize.c -- deciding whether a caller may do what they asked.
 *
 * One function answers "who may do this?" -- `ncfg_authz_permitted` -- so
 * there is one place to read and one place a mistake can be. 0013 has the
 * reasoning; this is the part that runs.
 */
#include "ncfg/daemon.h"

#include "ncfg/parse.h"

#include <stdio.h>
#include <string.h>

const char *ncfg_tier_name(ncfg_tier_t tier)
{
	switch (tier) {
	case NCFG_TIER_OBSERVE:
		return "observe";
	case NCFG_TIER_WIFI:
		return "wifi";
	case NCFG_TIER_ADMIN:
		return "admin";
	case NCFG_TIER_COUNT:
	default:
		return NULL;
	}
}

/*
 * Which tier each request belongs to, one row per kind.
 *
 * Designated initialisers, so the table is read as a list of claims rather
 * than as a run of values whose meaning is their position -- an inserted enum
 * member would otherwise shift every tier below it by one and compile
 * perfectly. `authorize_test.c` asserts that every kind is covered, which is the
 * exhaustive `match` the Rust gets from its compiler.
 *
 * **The test is what the caller is asking netcfgd to do, and nothing else.**
 * An observer may request the data netcfgd holds; an admin may write all of it
 * through netcfgd. A file's mode is not an argument for a tier -- it is a fact
 * about the filesystem, and these tiers are about netcfgd, which is answering
 * over a socket a remote caller may be on the other end of (0128).
 */
static const ncfg_tier_t tier_table[NCFG_PROTO_REQ_COUNT] = {
	/*
	 * Reading. `hello` is here rather than unauthenticated because even
	 * knowing which versions a daemon speaks is more than a stranger needs.
	 */
	[NCFG_PROTO_REQ_HELLO] = NCFG_TIER_OBSERVE,
	[NCFG_PROTO_REQ_STATUS] = NCFG_TIER_OBSERVE,
	[NCFG_PROTO_REQ_PLAN] = NCFG_TIER_OBSERVE,
	[NCFG_PROTO_REQ_SHOW] = NCFG_TIER_OBSERVE,
	[NCFG_PROTO_REQ_EXPLAIN] = NCFG_TIER_OBSERVE,
	[NCFG_PROTO_REQ_MONITOR] = NCFG_TIER_OBSERVE,
	/* Asking what the radio is doing is reading, and a status display that
	 * needs the wifi tier is a status display that ends up being given it. */
	[NCFG_PROTO_REQ_WIFI_STATUS] = NCFG_TIER_OBSERVE,
	/*
	 * Listing associated stations is reading too. It is worth naming what it
	 * exposes, because it is not the same kind of reading as the rest of this
	 * tier: other people's hardware addresses and how strong their signal is,
	 * which is a proximity sensor for anybody granted `observe`. Under the
	 * default policy that is root; a site that opens `observe` to `any` is
	 * opening this too, deliberately.
	 */
	[NCFG_PROTO_REQ_AP_STATIONS] = NCFG_TIER_OBSERVE,
	/* Listing radios is the list a client needs before it can offer anything
	 * wireless at all, and nothing in it is other people's: an interface
	 * name, whether netcfgd was given it, and whether a supplicant answers.
	 * All three are visible to anybody who can run `ip link`. */
	[NCFG_PROTO_REQ_RADIOS] = NCFG_TIER_OBSERVE,
	/* Listing the link-detection scripts is reading what netcfgd holds. */
	[NCFG_PROTO_REQ_PROBE_LIST] = NCFG_TIER_OBSERVE,
	/* `show` already returns the compiled result; what this adds is which
	 * file each part came from, which is the provenance `explain` gives per
	 * interface and is `observe` for the same reason. */
	[NCFG_PROTO_REQ_CONFIG_LIST] = NCFG_TIER_OBSERVE,
	[NCFG_PROTO_REQ_PROFILE_LIST] = NCFG_TIER_OBSERVE,
	[NCFG_PROTO_REQ_MODEM_LIST] = NCFG_TIER_OBSERVE,
	/* Names only, never values -- and the names are already in the document
	 * `show` returns, since `@secret:` references live there. What this adds
	 * is whether the file behind each one exists, which is a diagnostic
	 * rather than a disclosure. */
	[NCFG_PROTO_REQ_SECRET_LIST] = NCFG_TIER_OBSERVE,

	/*
	 * Scanning is not reading: it transmits probe requests and interrupts
	 * whatever the radio was doing.
	 *
	 * `wifi_add` is here since 0124. It was `admin` because 0013 wrote the
	 * wifi tier as "join, leave and scan *known* networks" -- but 0013 named
	 * that a gap and said "until that exists", waiting on a mechanism that
	 * could write a network safely. 0117 built one: a typed request whose
	 * privilege is bounded by the shape of the message rather than by the
	 * caller's manners. What the tier now grants is exactly one `network`
	 * block and one secret at 0600; there is no field here that could name a
	 * hook, a path, a `run_as`, an interface, a device or a control policy.
	 * Adding does not apply -- `apply` stays `admin` -- so a wifi-tier caller
	 * writes a network and joins it, and can apply nothing else.
	 */
	[NCFG_PROTO_REQ_WIFI_SCAN] = NCFG_TIER_WIFI,
	[NCFG_PROTO_REQ_WIFI_CONNECT] = NCFG_TIER_WIFI,
	[NCFG_PROTO_REQ_WIFI_DISCONNECT] = NCFG_TIER_WIFI,
	[NCFG_PROTO_REQ_WIFI_ADD] = NCFG_TIER_WIFI,
	/* **Forgetting one is `wifi` because adding one is.** The message is an
	 * id and nothing else, and what it removes is the block that id names
	 * plus a credential nothing else refers to -- strictly less reach than
	 * the request that wrote both. A tier that may create a network and not
	 * remove one leaves a client able to fill a machine with networks it
	 * cannot take back. */
	[NCFG_PROTO_REQ_WIFI_FORGET] = NCFG_TIER_WIFI,
	/* Taking a radio on is `wifi` for the same reason. What it writes is a
	 * `device` block, and a client sending one as *text* would be sending
	 * configuration -- 0117's remote code execution, and `admin`. An
	 * interface name and a boolean can name no hook, no path and no `run_as`,
	 * so a member of the `netcfgd` group can turn on the radio in their own
	 * laptop without being able to decide who else may. */
	[NCFG_PROTO_REQ_RADIO_SET] = NCFG_TIER_WIFI,

	/*
	 * Everything that changes the machine. `apply` is `admin` even when the
	 * only thing in the plan is a wifi association: a tier that could call it
	 * could apply any config change at all, which would make the wifi tier
	 * `admin` wearing a hat.
	 */
	[NCFG_PROTO_REQ_APPLY] = NCFG_TIER_ADMIN,
	[NCFG_PROTO_REQ_CONFIRM] = NCFG_TIER_ADMIN,
	[NCFG_PROTO_REQ_REVERT] = NCFG_TIER_ADMIN,
	[NCFG_PROTO_REQ_RELOAD] = NCFG_TIER_ADMIN,
	[NCFG_PROTO_REQ_PROFILE_SET] = NCFG_TIER_ADMIN,
	[NCFG_PROTO_REQ_PROFILE_SAVE] = NCFG_TIER_ADMIN,
	/*
	 * **Reading a hook body is `admin`, where reading a probe is not.** Both
	 * are programs netcfgd runs as root, and the difference is who wrote them
	 * into what. A probe is a command the document states in the open, in a
	 * file netcfgd keeps at 0755 so somebody debugging a link can run it by
	 * hand; a hook body is whatever an operator put in it, in a file the
	 * materialiser opens 0700 because nobody else needs to read it. Serving
	 * that at `observe` would publish the contents of the one file this
	 * daemon takes care to keep to itself, and the client that wants it is an
	 * editor, which is `admin` to save anyway.
	 */
	[NCFG_PROTO_REQ_HOOK_LIST] = NCFG_TIER_ADMIN,
	/* Writing configuration is what `admin` names, and `config_put` writes
	 * arbitrary configuration -- which is why the tier is not the whole
	 * answer for it. `ncfg_authz_check_content` runs afterwards. */
	[NCFG_PROTO_REQ_CONFIG_PUT] = NCFG_TIER_ADMIN,
	/* Writing a probe is `admin` for the tier system's sake and root in fact:
	 * the content gate refuses it from anyone else. A probe is a program
	 * netcfgd runs as root on an interval, which is strictly more than the
	 * privileged *productions* that rule exists for -- those name a program,
	 * and this one is the program. */
	[NCFG_PROTO_REQ_PROBE_PUT] = NCFG_TIER_ADMIN,
	/* Storing a credential is `admin` and not `wifi`, even though `wifi_add`
	 * carries one at the wifi tier. The difference is the blast radius of the
	 * *name*: `wifi_add` writes a secret it also names, for a network it is
	 * creating, and this writes any name the configuration might refer to --
	 * including one a `wireguard` block reads, which 0042 calls the one thing
	 * on a machine nobody can get back. */
	[NCFG_PROTO_REQ_SECRET_PUT] = NCFG_TIER_ADMIN,
	/* Deleting is writing. `secret_delete` in particular is the one verb here
	 * with no way back, and no `replace` flag to make somebody say it twice,
	 * because a caller asking to delete has already said it once. What guards
	 * it is this tier and nothing else. */
	[NCFG_PROTO_REQ_CONFIG_DELETE] = NCFG_TIER_ADMIN,
	[NCFG_PROTO_REQ_SECRET_DELETE] = NCFG_TIER_ADMIN
};

ncfg_tier_t ncfg_tier_of(ncfg_proto_request_kind_t kind)
{
	if ((int)kind < 0 || (int)kind >= (int)NCFG_PROTO_REQ_COUNT) {
		/* A kind outside the enum is not a request this build knows, and the
		 * direction that denies is the one to take. */
		return NCFG_TIER_ADMIN;
	}
	return tier_table[kind];
}

int ncfg_authz_satisfies(const ncfg_authz_roots_t *roots, const ncfg_peer_t *peer,
    const ncfg_principal_t *principal)
{
	ncfg_authz_roots_t where = roots ? *roots : ncfg_authz_roots_default();

	if (!peer || !principal) {
		return 0;
	}
	/*
	 * **Root satisfies everything**, and that is not a special case bolted
	 * on: a configuration that named a group and thereby locked root out
	 * would be unrecoverable without editing the file the daemon is refusing
	 * to let you reach.
	 */
	if (ncfg_peer_is_root(peer)) {
		return 1;
	}
	switch (principal->kind) {
	case NCFG_PRINCIPAL_ROOT:
		return 0;
	case NCFG_PRINCIPAL_ANY:
		return 1;
	case NCFG_PRINCIPAL_USER: {
		uid_t uid;

		if (!principal->name || !ncfg_peer_user_id(where.passwd_file, principal->name, &uid)) {
			/* A name that does not resolve denies. A policy naming a user
			 * who does not exist grants nothing rather than everything. */
			return 0;
		}
		return peer->uid == uid;
	}
	case NCFG_PRINCIPAL_GROUP: {
		gid_t gid;

		if (!principal->name || !ncfg_peer_group_id(where.group_file, principal->name, &gid)) {
			return 0;
		}
		/* `ncfg_peer_in_group` counts the primary gid and every
		 * supplementary one that was read. Groups that could not be read are
		 * not there, which denies -- see `NCFG_PEER_GROUPS_MAX`. */
		return ncfg_peer_in_group(peer, gid);
	}
	default:
		return 0;
	}
}

/* `root`, `any`, `user:NAME`, `group:NAME` -- how it is written in a config
 * file, which is what the refusal has to quote so the reader can find it. */
static void render_principal(const ncfg_principal_t *principal, char *out, size_t out_size)
{
	const char *name = (principal && principal->name) ? principal->name : "";

	switch (principal ? principal->kind : NCFG_PRINCIPAL_ROOT) {
	case NCFG_PRINCIPAL_ANY:
		(void)snprintf(out, out_size, "any");
		return;
	case NCFG_PRINCIPAL_USER:
		(void)snprintf(out, out_size, "user:%s", name);
		return;
	case NCFG_PRINCIPAL_GROUP:
		(void)snprintf(out, out_size, "group:%s", name);
		return;
	case NCFG_PRINCIPAL_ROOT:
	default:
		(void)snprintf(out, out_size, "root");
		return;
	}
}

void ncfg_authz_refusal(ncfg_tier_t tier, const ncfg_principal_t *principal, char *err,
    size_t err_size)
{
	char        rendered[128];
	const char *name = ncfg_tier_name(tier);

	render_principal(principal, rendered, sizeof(rendered));
	ncfg_error_set(err, err_size,
	    "not permitted: this needs the `%s` tier, which the configuration opens to `%s`. "
	    "Change it in the `control` block of netcfgd.conf.",
	    name ? name : "admin", rendered);
}

/* Which tiers the remote policy opens. */
static int remote_allows(const ncfg_remote_policy_t *remote, ncfg_tier_t tier)
{
	if (!remote) {
		return 0;
	}
	switch (tier) {
	case NCFG_TIER_OBSERVE:
		return remote->observe != 0;
	case NCFG_TIER_WIFI:
		return remote->wifi != 0;
	case NCFG_TIER_ADMIN:
		return remote->admin != 0;
	case NCFG_TIER_COUNT:
	default:
		return 0;
	}
}

/* The principal a control policy opens a tier to. */
static const ncfg_principal_t *principal_of(const ncfg_control_t *control, ncfg_tier_t tier)
{
	switch (tier) {
	case NCFG_TIER_OBSERVE:
		return &control->observe;
	case NCFG_TIER_WIFI:
		return &control->wifi;
	case NCFG_TIER_ADMIN:
		return &control->admin;
	case NCFG_TIER_COUNT:
	default:
		return &control->admin;
	}
}

/*
 * Decide for a remote caller: may this tier be reached from off the machine?
 *
 * **Peer credentials are not consulted, and that is deliberate.** Every remote
 * caller arrives as the agent, so its uid says who is running the agent rather
 * than who is calling -- checking it would be checking the wrong thing while
 * appearing to check the right one. The agent decides who the caller is; this
 * decides what remote can ever reach, whoever they are.
 */
static int check_remote(const ncfg_remote_policy_t *remote, const ncfg_proto_request_t *request,
    char *err, size_t err_size)
{
	ncfg_tier_t tier = ncfg_tier_of(request->kind);
	const char *name;

	if (remote_allows(remote, tier)) {
		return 1;
	}
	name = ncfg_tier_name(tier);
	ncfg_error_set(err, err_size,
	    "not permitted from off this machine: this needs the `%s` tier, which the "
	    "configuration does not open remotely. Change it in the `remote` block of "
	    "netcfgd.conf.",
	    name ? name : "admin");
	return 0;
}

int ncfg_authz_check(const ncfg_authz_roots_t *roots, const ncfg_control_t *control,
    const ncfg_remote_policy_t *remote, ncfg_arrival_t arrival, const ncfg_peer_t *peer,
    const ncfg_proto_request_t *request, char *err, size_t err_size)
{
	ncfg_tier_t             tier;
	const ncfg_principal_t *principal;

	if (!control || !request) {
		ncfg_error_set(err, err_size, "not permitted: there is no policy to judge this by");
		return 0;
	}
	/*
	 * Origin is decided first, and the order is the whole of it. Root
	 * satisfies every local principal, so a remote connection whose peer
	 * happens to be root would reach everything if this fell through -- and
	 * `agent/` running as root is a plausible deployment, which makes it the
	 * case to pin rather than a contrived one.
	 */
	if (arrival == NCFG_ARRIVED_REMOTE) {
		return check_remote(remote, request, err, err_size);
	}
	tier = ncfg_tier_of(request->kind);
	principal = principal_of(control, tier);
	if (ncfg_authz_satisfies(roots, peer, principal)) {
		return 1;
	}
	ncfg_authz_refusal(tier, principal, err, err_size);
	return 0;
}

int ncfg_authz_check_content(ncfg_arrival_t arrival, const ncfg_peer_t *peer,
    const ncfg_proto_request_t *request, char *err, size_t err_size)
{
	ncfg_ast_file_t          *file = NULL;
	ncfg_privilege_findings_t findings = { 0 };
	const char               *why;
	int                       allowed;

	if (!request) {
		return 1;
	}
	/*
	 * A probe script is the program a privileged production would merely have
	 * named, so it takes the same answer without needing to be parsed: there
	 * is no shape of shell that grants less than root here.
	 */
	if (request->kind == NCFG_PROTO_REQ_PROBE_PUT) {
		char name[256];

		if (arrival == NCFG_ARRIVED_LOCAL && ncfg_peer_is_root(peer)) {
			return 1;
		}
		(void)snprintf(name, sizeof(name), "%.*s",
		    (int)(request->u.put.name.length < 200u ? request->u.put.name.length : 200u),
		    request->u.put.name.bytes ? request->u.put.name.bytes : "");
		ncfg_error_set(err, err_size,
		    "writing the link-detection script `%s` needs root on this machine: a probe "
		    "is a program netcfgd runs as root, on an interval. Send it as root.",
		    name);
		return 0;
	}
	if (request->kind != NCFG_PROTO_REQ_CONFIG_PUT) {
		return 1;
	}
	/*
	 * Unparseable text is not this gate's to refuse: the writer compiles it
	 * and reports diagnostics that point at the line. Refusing here would
	 * answer a syntax error with a sentence about privilege, and send the
	 * reader looking for a permission problem they do not have.
	 */
	if (!ncfg_parse(request->u.put.text.bytes ? request->u.put.text.bytes : "",
	        request->u.put.text.length, &file, NULL, NULL, 0)) {
		return 1;
	}
	if (!ncfg_privilege_findings(file, &findings, err, err_size)) {
		ncfg_ast_file_free(file);
		/* Refusing is the direction that denies: a classification that could
		 * not be run has said nothing, and nothing is not permission. */
		return 0;
	}
	ncfg_ast_file_free(file);
	if (findings.count == 0) {
		ncfg_privilege_findings_free(&findings);
		return 1;
	}
	/*
	 * **Root on this machine, and nothing else.** Asked after the
	 * classification rather than before it so that the refusal has something
	 * to name -- and asked about the arrival as well as the peer, because a
	 * remote caller's uid is the agent's and there is no version of "is this
	 * root" to ask about it.
	 */
	allowed = (arrival == NCFG_ARRIVED_LOCAL && ncfg_peer_is_root(peer));
	if (allowed) {
		ncfg_privilege_findings_free(&findings);
		return 1;
	}
	why = ncfg_privilege_why(findings.at[0].reason);
	/*
	 * Both the production and what it grants, because "not permitted" sends
	 * the reader to the source and the reason is usually something they did
	 * not know their configuration could do.
	 */
	if (findings.total > 1) {
		ncfg_error_set(err, err_size, "`%s` needs root on this machine: %s. %lu such "
		    "productions in this configuration.",
		    findings.at[0].what, why ? why : "it grants more than configuring a network",
		    (unsigned long)findings.total);
	} else {
		ncfg_error_set(err, err_size,
		    "`%s` needs root on this machine: %s. Send it as root, or leave it out.",
		    findings.at[0].what, why ? why : "it grants more than configuring a network");
	}
	ncfg_privilege_findings_free(&findings);
	return 0;
}

int ncfg_authz_permitted(const ncfg_authz_roots_t *roots, const ncfg_control_t *control,
    const ncfg_remote_policy_t *remote, ncfg_arrival_t arrival, const ncfg_peer_t *peer,
    const ncfg_proto_request_t *request, char *err, size_t err_size)
{
	if (!ncfg_authz_check(roots, control, remote, arrival, peer, request, err, err_size)) {
		return 0;
	}
	return ncfg_authz_check_content(arrival, peer, request, err, err_size);
}

size_t ncfg_authz_granted(const ncfg_authz_roots_t *roots, const ncfg_control_t *control,
    const ncfg_remote_policy_t *remote, ncfg_arrival_t arrival, const ncfg_peer_t *peer,
    ncfg_tier_t *out)
{
	static const ncfg_tier_t every[] = { NCFG_TIER_OBSERVE, NCFG_TIER_WIFI, NCFG_TIER_ADMIN };
	size_t                   written = 0;
	size_t                   at;

	if (!out || !control) {
		return 0;
	}
	for (at = 0; at < sizeof(every) / sizeof(every[0]); at++) {
		/*
		 * The same answer `ncfg_authz_check` gives, reached the same way.
		 * 0092 exists because a client that finds out by being refused puts
		 * a button on a screen that fails when pressed, and a second
		 * implementation of "may I" is how the two come to disagree.
		 */
		int allowed = (arrival == NCFG_ARRIVED_REMOTE)
		    ? remote_allows(remote, every[at])
		    : ncfg_authz_satisfies(roots, peer, principal_of(control, every[at]));

		if (allowed) {
			out[written] = every[at];
			written++;
		}
	}
	return written;
}
