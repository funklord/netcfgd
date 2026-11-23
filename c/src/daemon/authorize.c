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

const char *ncfg_tier_name(int tier)
{
	switch (tier) {
	case NCFG_TIER_VIEW:
		return "view";
	case NCFG_TIER_LAPTOP:
		return "laptop";
	case NCFG_TIER_ROOT:
		return "root";
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
 * A viewer may request the data netcfgd holds; `root` may write all of it
 * through netcfgd, and `laptop` sits between only in the sense that its
 * requests are typed and carry no configuration text (0327). A file's mode is not an argument for a tier -- it is a fact
 * about the filesystem, and these tiers are about netcfgd, which is answering
 * over a socket a remote caller may be on the other end of (0128).
 */
static const ncfg_tier_t tier_table[NCFG_PROTO_REQ_COUNT] = {
	/*
	 * Reading. `hello` is here rather than unauthenticated because even
	 * knowing which versions a daemon speaks is more than a stranger needs.
	 */
	[NCFG_PROTO_REQ_HELLO] = NCFG_TIER_VIEW,
	[NCFG_PROTO_REQ_STATUS] = NCFG_TIER_VIEW,
	[NCFG_PROTO_REQ_PLAN] = NCFG_TIER_VIEW,
	[NCFG_PROTO_REQ_SHOW] = NCFG_TIER_VIEW,
	[NCFG_PROTO_REQ_EXPLAIN] = NCFG_TIER_VIEW,
	[NCFG_PROTO_REQ_MONITOR] = NCFG_TIER_VIEW,
	/* Asking what the radio is doing is reading, and a status display that
	 * needs the laptop tier is a status display that ends up being given it. */
	[NCFG_PROTO_REQ_WIFI_STATUS] = NCFG_TIER_VIEW,
	/*
	 * Listing associated stations is reading too. It is worth naming what it
	 * exposes, because it is not the same kind of reading as the rest of this
	 * tier: other people's hardware addresses and how strong their signal is,
	 * which is a proximity sensor for anybody granted `view`. The shipped
	 * policy opens `view` to the `netcfgd` group (0118); a site that opens it
	 * to `any` is opening this too, deliberately.
	 */
	[NCFG_PROTO_REQ_AP_STATIONS] = NCFG_TIER_VIEW,
	/* Listing radios is the list a client needs before it can offer anything
	 * wireless at all, and nothing in it is other people's: an interface
	 * name, whether netcfgd was given it, and whether a supplicant answers.
	 * All three are visible to anybody who can run `ip link`. */
	[NCFG_PROTO_REQ_RADIOS] = NCFG_TIER_VIEW,
	/* Listing the link-detection scripts is reading what netcfgd holds. */
	[NCFG_PROTO_REQ_PROBE_LIST] = NCFG_TIER_VIEW,
	/* `show` already returns the compiled result; what this adds is which
	 * file each part came from, which is the provenance `explain` gives per
	 * interface and is `view` for the same reason. */
	[NCFG_PROTO_REQ_CONFIG_LIST] = NCFG_TIER_VIEW,
	[NCFG_PROTO_REQ_PROFILE_LIST] = NCFG_TIER_VIEW,
	[NCFG_PROTO_REQ_MODEM_LIST] = NCFG_TIER_VIEW,
	/* Names only, never values -- and the names are already in the document
	 * `show` returns, since `@secret:` references live there. What this adds
	 * is whether the file behind each one exists, which is a diagnostic
	 * rather than a disclosure. */
	[NCFG_PROTO_REQ_SECRET_LIST] = NCFG_TIER_VIEW,

	/*
	 * **The laptop tier: what a person at their own machine must be able to
	 * do** (0327). Wide and dangerous, and necessary anyway -- joining a
	 * network chooses where the machine's traffic goes. What bounds it is the
	 * shape of these requests: each is typed and carries no configuration
	 * text, so none can name a hook, a path, a resolver or a
	 * control policy (0117).
	 *
	 * Scanning is not reading: it transmits probe requests and interrupts
	 * whatever the radio was doing.
	 *
	 * `wifi_add` writes exactly one `network` block and one secret at 0600,
	 * since 0124; there is no field in it for anything else. Adding does not
	 * apply -- `apply` is `root` -- so a laptop-tier caller writes a network
	 * and joins it, and can apply nothing else.
	 */
	[NCFG_PROTO_REQ_WIFI_SCAN] = NCFG_TIER_LAPTOP,
	[NCFG_PROTO_REQ_WIFI_CONNECT] = NCFG_TIER_LAPTOP,
	[NCFG_PROTO_REQ_WIFI_DISCONNECT] = NCFG_TIER_LAPTOP,
	[NCFG_PROTO_REQ_WIFI_ADD] = NCFG_TIER_LAPTOP,
	/* **Forgetting one is `laptop` because adding one is.** The message is an
	 * id and nothing else, and what it removes is the block that id names
	 * plus a credential nothing else refers to -- strictly less reach than
	 * the request that wrote both. A tier that may create a network and not
	 * remove one leaves a client able to fill a machine with networks it
	 * cannot take back. */
	[NCFG_PROTO_REQ_WIFI_FORGET] = NCFG_TIER_LAPTOP,
	/* Taking a radio on is `laptop` for the same reason. What it writes is a
	 * `device` block, and a client sending one as *text* would be sending
	 * configuration -- 0117's remote code execution, and `root`. An
	 * interface name and a boolean can name no hook and no path,
	 * so a member of the `netcfgd` group can turn on the radio in their own
	 * laptop without being able to decide who else may. */
	[NCFG_PROTO_REQ_RADIO_SET] = NCFG_TIER_LAPTOP,
	/* Connecting the VPN is the act joining a network is, for a person at
	 * their own machine (10.864): a device name and up or down, no text. */
	[NCFG_PROTO_REQ_TUNNEL_SET] = NCFG_TIER_LAPTOP,

	/*
	 * **The root tier: everything else, and it is root** (0327). Writing
	 * configuration chooses the machine's routes, resolvers, NAT and which
	 * access point a credential is offered to, and a machine whose traffic
	 * somebody else chooses is theirs by an ordinary path. A site may open
	 * this to a group; that hands the group root, and the word says so.
	 *
	 * `apply` is here even when the only thing in the plan is a wifi
	 * association: a tier that could call it could apply any config change at
	 * all, which would make `laptop` root wearing a hat.
	 */
	[NCFG_PROTO_REQ_APPLY] = NCFG_TIER_ROOT,
	[NCFG_PROTO_REQ_CONFIRM] = NCFG_TIER_ROOT,
	[NCFG_PROTO_REQ_REVERT] = NCFG_TIER_ROOT,
	[NCFG_PROTO_REQ_RELOAD] = NCFG_TIER_ROOT,
	[NCFG_PROTO_REQ_PROFILE_SET] = NCFG_TIER_ROOT,
	[NCFG_PROTO_REQ_PROFILE_SAVE] = NCFG_TIER_ROOT,
	/*
	 * **Reading a hook body is `root`, where reading a probe is not.** Both
	 * are programs netcfgd runs as root, and the difference is who wrote them
	 * into what. A probe is a command the document states in the open, in a
	 * file netcfgd keeps at 0755 so somebody debugging a link can run it by
	 * hand; a hook body is whatever an operator put in it, in a file the
	 * materialiser opens 0700 because nobody else needs to read it. Serving
	 * that at `view` would publish the contents of the one file this
	 * daemon takes care to keep to itself, and the client that wants it is an
	 * editor, which is `root` to save anyway.
	 */
	[NCFG_PROTO_REQ_HOOK_LIST] = NCFG_TIER_ROOT,
	/* Writing configuration is what `root` names. `ncfg_authz_check_content`
	 * runs afterwards and refuses the productions that name a program netcfgd
	 * would run as root to anybody but uid 0. */
	[NCFG_PROTO_REQ_CONFIG_PUT] = NCFG_TIER_ROOT,
	/* Writing a probe is the `root` tier and uid 0 in fact: the content gate
	 * refuses it from anyone else. A probe is a program
	 * netcfgd runs as root on an interval, which is strictly more than the
	 * privileged *productions* that rule exists for -- those name a program,
	 * and this one is the program. */
	[NCFG_PROTO_REQ_PROBE_PUT] = NCFG_TIER_ROOT,
	/* Storing a credential is `root` and not `laptop`, even though `wifi_add`
	 * carries one at the laptop tier. The difference is the blast radius of the
	 * *name*: `wifi_add` writes a secret it also names, for a network it is
	 * creating, and this writes any name the configuration might refer to --
	 * including one a `wireguard` block reads, which 0042 calls the one thing
	 * on a machine nobody can get back. */
	[NCFG_PROTO_REQ_SECRET_PUT] = NCFG_TIER_ROOT,
	/* Deleting is writing. `secret_delete` in particular is the one verb here
	 * with no way back, and no `replace` flag to make somebody say it twice,
	 * because a caller asking to delete has already said it once. What guards
	 * it is this tier and nothing else. */
	[NCFG_PROTO_REQ_CONFIG_DELETE] = NCFG_TIER_ROOT,
	/* As `profile_save`, which made what this takes away. */
	[NCFG_PROTO_REQ_PROFILE_DELETE] = NCFG_TIER_ROOT,
	[NCFG_PROTO_REQ_SECRET_DELETE] = NCFG_TIER_ROOT,
	/* **Showing a credential is `root`, and only there does it stop being a
	 * question** (0327): a caller who may choose the resolvers and repoint an
	 * SSID gains nothing from a passphrase, where `laptop` is the tier meant
	 * to be less. Never from off the machine, whatever the remote policy
	 * opens: `check_remote` refuses it by kind, because a credential does not
	 * travel (0029). */
	[NCFG_PROTO_REQ_SECRET_GET] = NCFG_TIER_ROOT
};

ncfg_tier_t ncfg_tier_of(ncfg_proto_request_kind_t kind)
{
	if ((int)kind < 0 || (int)kind >= (int)NCFG_PROTO_REQ_COUNT) {
		/* A kind outside the enum is not a request this build knows, and the
		 * direction that denies is the one to take. */
		return NCFG_TIER_ROOT;
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
	const char *name = ncfg_tier_name((int)tier);

	render_principal(principal, rendered, sizeof(rendered));
	ncfg_error_set(err, err_size,
	    "not permitted: this needs the `%s` tier, which the configuration opens to `%s`. "
	    "Change it in the `control` block of netcfgd.conf.",
	    name ? name : "root", rendered);
}

/* Whether the remote policy opens exactly this tier, before nesting. */
static int remote_flag(const ncfg_remote_policy_t *remote, ncfg_tier_t tier)
{
	switch (tier) {
	case NCFG_TIER_VIEW:
		return remote->view != 0;
	case NCFG_TIER_LAPTOP:
		return remote->laptop != 0;
	case NCFG_TIER_ROOT:
		return remote->root != 0;
	case NCFG_TIER_COUNT:
	default:
		return 0;
	}
}

/*
 * Which tiers the remote policy opens. **They nest** (0327): `root = true`
 * opens `laptop` and `view` from off the machine as well, since a caller who
 * may write the configuration remotely and not read it is a policy nobody
 * means.
 */
static int remote_allows(const ncfg_remote_policy_t *remote, ncfg_tier_t tier)
{
	int at;

	if (!remote || (int)tier < 0 || (int)tier >= (int)NCFG_TIER_COUNT) {
		return 0;
	}
	for (at = (int)tier; at < (int)NCFG_TIER_COUNT; at++) {
		if (remote_flag(remote, (ncfg_tier_t)at)) {
			return 1;
		}
	}
	return 0;
}

/* The principal a control policy opens a tier to. */
static const ncfg_principal_t *principal_of(const ncfg_control_t *control, ncfg_tier_t tier)
{
	switch (tier) {
	case NCFG_TIER_VIEW:
		return &control->view;
	case NCFG_TIER_LAPTOP:
		return &control->laptop;
	case NCFG_TIER_ROOT:
		return &control->root;
	case NCFG_TIER_COUNT:
	default:
		return &control->root;
	}
}

/*
 * Whether a local peer holds a tier: its own principal, or any above it
 * (0327). The one place the nesting is decided, so `ncfg_authz_check` and
 * `ncfg_authz_granted` cannot come to disagree about it.
 */
static int local_holds(const ncfg_authz_roots_t *roots, const ncfg_control_t *control,
    const ncfg_peer_t *peer, ncfg_tier_t tier)
{
	int at;

	if ((int)tier < 0 || (int)tier >= (int)NCFG_TIER_COUNT) {
		return 0;
	}
	for (at = (int)tier; at < (int)NCFG_TIER_COUNT; at++) {
		if (ncfg_authz_satisfies(roots, peer, principal_of(control, (ncfg_tier_t)at))) {
			return 1;
		}
	}
	return 0;
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

	/*
	 * **A credential's value is not sent off the machine, whatever the policy
	 * opens** (0327, 0029). Remote `root` is root on this machine, and could
	 * point a credential at an access point of its own -- but that attack
	 * needs the radio here, and handing over the value would make the
	 * passphrase itself travel, which nothing else in netcfgd does.
	 */
	if (request->kind == NCFG_PROTO_REQ_SECRET_GET) {
		ncfg_error_set(err, err_size,
		    "not permitted from off this machine: a stored credential's value is shown "
		    "only to a caller on the machine that holds it, whatever the `remote` block "
		    "opens");
		return 0;
	}
	if (remote_allows(remote, tier)) {
		return 1;
	}
	name = ncfg_tier_name((int)tier);
	ncfg_error_set(err, err_size,
	    "not permitted from off this machine: this needs the `%s` tier, which the "
	    "configuration does not open remotely. Change it in the `remote` block of "
	    "netcfgd.conf.",
	    name ? name : "root");
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
	if (local_holds(roots, control, peer, tier)) {
		return 1;
	}
	principal = principal_of(control, tier);
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
		    "writing the link-detection script `%s` needs uid 0 on this machine, not only "
		    "the `root` tier: a probe is a program netcfgd runs as root, on an interval. "
		    "Send it as root.",
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
	 * **Uid 0 on this machine, and nothing else** -- not the `root` tier
	 * opened to a group, since these name a program netcfgd runs as root and
	 * refusing that closes the direct route (0327). Asked after the
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
		ncfg_error_set(err, err_size, "`%s` needs uid 0 on this machine, not only the "
		    "`root` tier: %s. %lu such productions in this configuration.",
		    findings.at[0].what, why ? why : "it grants more than configuring a network",
		    (unsigned long)findings.total);
	} else {
		ncfg_error_set(err, err_size,
		    "`%s` needs uid 0 on this machine, not only the `root` tier: %s. Send it as "
		    "root, or leave it out.",
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
	static const ncfg_tier_t every[] = { NCFG_TIER_VIEW, NCFG_TIER_LAPTOP, NCFG_TIER_ROOT };
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
		    : local_holds(roots, control, peer, every[at]);

		if (allowed) {
			out[written] = every[at];
			written++;
		}
	}
	return written;
}
