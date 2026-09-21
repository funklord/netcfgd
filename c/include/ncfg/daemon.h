/*
 * daemon.h -- who may ask, how the asking arrives, and what the daemon holds.
 *
 * This is `crates/netcfgd-daemon` in C: `authorize.rs`, `server.rs`, the part
 * of `state.rs` that is a document and a reload, and -- since the second wave
 * -- `probe.rs`, `sim.rs`, `confirm.rs` and `resolv_guard.rs`, which are the
 * pieces of the reconcile loop that decide something rather than merely
 * sequence it, and `wifi.rs`, which is every wireless request. **The loop that
 * drives all of them is the last section of this header**: what it decides and
 * the order it does it in, which are two files because they are two different
 * kinds of thing.
 *
 * WHAT THIS MODULE IS FOR, IN ONE SENTENCE
 *   Everything a stranger can reach passes through `ncfg_authz_permitted`, and
 *   nothing else in this library decides who may do what.
 *
 * THE THREE TIERS, AND WHY THE SECOND GATE EXISTS
 *   0013 splits what a caller may ask into `observe`, `wifi` and `admin`, and
 *   a site may open each to a principal. That is enough for every request but
 *   one: `config_put` carries *text*, and the same request can hold a wifi
 *   network or a shell script. So the text is classified and a production
 *   granting more than configuring a network needs **root on this machine** --
 *   not the `admin` tier, which a site may have opened to a group. That is
 *   what makes opening `admin` survivable rather than equivalent to handing
 *   out root (0117, 0127), and it is why `ncfg_authz_permitted` exists as one
 *   call: the Rust briefly had two, and a caller that forgot the second was
 *   invisible -- every test of the content gate called it directly and passed
 *   whether or not the daemon did.
 *
 * THE SUPPLEMENTARY GROUPS ARE NOT OPTIONAL
 *   `SO_PEERCRED` reports a pid, a uid and the *primary* gid, and a user's
 *   primary group is usually their own. A `group:netdev` policy checked
 *   against that alone would deny nearly everybody it is meant to allow while
 *   looking configured, which is the worst kind of access control. So the
 *   supplementary set is read from `/proc/<pid>/status`, and a set that could
 *   not be read is **no membership**, which denies.
 *
 * WHERE THE PATHS COME FROM, AND WHY THEY ARE ARGUMENTS
 *   The Rust reads `/etc/group`, `/etc/passwd` and `/proc` from constants, so
 *   `satisfies` can only be exercised where the machine happens to have the
 *   right group -- and its own tests say so, twice, and check the tier mapping
 *   instead. Here the three roots are a struct the caller passes, defaulted by
 *   `ncfg_authz_roots_default()`. Nothing in this module ever falls back to a
 *   path of its own: the daemon that runs on a machine passes the machine's,
 *   and a test passes a fixture directory it made. The reason is the one
 *   `tests/testdir.h` gives -- **the real netcfgd runs on the machine these
 *   tests are built on** -- and it applies to the socket path too, which is
 *   an argument here and has no default at all.
 *
 * THE CONVENTIONS ARE `base.h`'S
 *   1 for success, 0 for failure, `char *err` last, `NULL` for a pointer, one
 *   `_free` per aggregate, and freeing something never filled in is nothing.
 *   A refusal is a sentence: `ncfg_authz_permitted` returning 0 with `err`
 *   full is an *answer* to send the caller, not a transport failure.
 */
#ifndef NCFG_DAEMON_H
#define NCFG_DAEMON_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "ncfg/apply.h"
#include "ncfg/ast.h"
#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/config.h"
#include "ncfg/document.h"
#include "ncfg/explain.h"
#include "ncfg/hooks.h"
#include "ncfg/lex.h"
#include "ncfg/observed.h"
#include "ncfg/secrets.h"
#include "ncfg/portal.h"
#include "ncfg/process.h"
#include "ncfg/proto.h"

/* ------------------------------------------------------------- the peer */

/*
 * How many supplementary groups are kept.
 *
 * `/proc/<pid>/status` writes the whole set on one line and the kernel bounds
 * it at `NGROUPS_MAX`, which is 65536 -- an allocation a local process
 * chooses the size of, in a daemon holding `CAP_NET_ADMIN`. The Rust collects
 * them into a `Vec` with no bound; this keeps a fixed set and counts what it
 * had to drop, which is `NCFG_DIAGS_MAX`'s bargain applied to the same
 * problem.
 *
 * **Overflowing it cannot grant anything.** A membership that did not fit is
 * a membership that is not there, and a missing membership denies. Sixty-four
 * is past what any real login has; `setgroups` on a Debian desktop user
 * installs about a dozen.
 */
#define NCFG_PEER_GROUPS_MAX 64

/*
 * Who connected.
 *
 * `groups_known` is the field a reader must not skip. An empty set means
 * "could not tell" when it is 0 and "in no supplementary group" when it is 1,
 * and the two are the same answer here only because both deny -- which is why
 * they are still spelled apart: a future reader tempted to treat an empty set
 * as "read it again" would otherwise have nothing to look at.
 */
typedef struct {
	pid_t  pid;
	uid_t  uid;
	/* The primary group, which `SO_PEERCRED` reports and which counts. */
	gid_t  gid;
	gid_t  groups[NCFG_PEER_GROUPS_MAX];
	size_t group_count;
	/* How many the process was in, which differs from `group_count` only
	 * past the bound. Kept so a diagnostic can say a set was truncated
	 * rather than leaving it looking short. */
	size_t group_total;
	int    groups_known;
} ncfg_peer_t;

/* Whether this peer is root. Root satisfies every principal; see
 * `ncfg_authz_satisfies` for why that is not a bolted-on special case. */
int ncfg_peer_is_root(const ncfg_peer_t *peer);

/* Whether this peer is in a group, by id. The primary gid counts, and so does
 * every supplementary one that was read. */
int ncfg_peer_in_group(const ncfg_peer_t *peer, gid_t gid);

/*
 * Where the identity of a caller is looked up.
 *
 * Every field may be NULL, which means the machine's own: `/proc`,
 * `/etc/group`, `/etc/passwd`. A test fills all three in and touches none of
 * the real ones.
 */
typedef struct {
	const char *proc_root;
	const char *group_file;
	const char *passwd_file;
} ncfg_authz_roots_t;

ncfg_authz_roots_t ncfg_authz_roots_default(void);

/*
 * The credentials of whoever holds the other end of `socket`.
 *
 * Read once, when the connection is accepted, rather than per request: the
 * credentials belong to the connection, and re-reading them would only widen
 * the window in which the peer's pid can be recycled.
 *
 * A failure to read the supplementary set is **not** a failure of this call.
 * The peer is still identified by uid and primary gid, `groups_known` is 0,
 * and every `group:` rule then denies -- which is the answer a security
 * control should give when it cannot tell.
 */
int ncfg_peer_credentials(int socket, const ncfg_authz_roots_t *roots, ncfg_peer_t *out,
    char *err, size_t err_size);

/*
 * The supplementary set from `/proc/<pid>/status`, on its own.
 *
 * Public because it is the half a test can drive: a real socket cannot be
 * made to have a peer in an arbitrary group, and the rule being tested is
 * about a file's contents.
 *
 * **The uid is cross-checked and that is the whole point.** A pid can be
 * recycled between `SO_PEERCRED` returning and this file being opened.
 * Comparing the real uid the file reports against the one the kernel gave
 * closes every recycling that lands on a different user; one landing on the
 * same user is not a privilege boundary. On any doubt -- unreadable, no
 * `Uid:` line, a mismatch -- this fills in no groups and leaves
 * `groups_known` 0, which denies.
 *
 * Returns 1 when a set was read and 0 otherwise; `out` is written either way.
 */
int ncfg_peer_groups_from(const char *proc_root, pid_t pid, uid_t expected, ncfg_peer_t *out);

/*
 * A group's id by name, and a user's by name.
 *
 * `/etc/group` and `/etc/passwd` are read as files rather than through
 * `getgrnam`/`getpwnam`, which would pull in NSS and with it whatever modules
 * the host has configured -- LDAP, SSSD, a network round trip inside an
 * accept. **A network configuration daemon resolving a group over the network
 * to decide who may configure the network is a dependency loop with a bad
 * failure mode**, and it is one that only shows up on the machine whose
 * network is broken.
 *
 * 1 with the id, 0 where there is no such entry or the file cannot be read.
 */
int ncfg_peer_group_id(const char *group_file, const char *name, gid_t *out);
int ncfg_peer_user_id(const char *passwd_file, const char *name, uid_t *out);

/* ------------------------------------------------------- tiers and arrival */

/*
 * What a caller is trying to do.
 *
 * Three separate memberships, **not a ladder**. A machine may grant `admin`
 * to a group somebody is in and `wifi` to one they are not, so nothing here
 * reports a highest tier or fills in the ones below it.
 */
typedef enum {
	NCFG_TIER_OBSERVE = 0,
	NCFG_TIER_WIFI,
	NCFG_TIER_ADMIN,
	/* Not a tier: the bound every walk over them uses. */
	NCFG_TIER_COUNT
} ncfg_tier_t;

/* `observe`, `wifi`, `admin`. NULL outside the enum. */
const char *ncfg_tier_name(ncfg_tier_t tier);

/*
 * Which tier a request belongs to.
 *
 * **The test is what the caller is asking netcfgd to do, and nothing else.**
 * An observer may *request* the data netcfgd holds; an admin may *write* all
 * of it through netcfgd. A file's mode is not an argument for a tier: that is
 * a fact about the filesystem, these tiers are about netcfgd, and the
 * reasoning evaporates the moment a mode changes while the tier it justified
 * stays.
 *
 * The Rust gets this checked by an exhaustive `match`, so a request added
 * without a tier fails to compile. C has no such compiler, and the failure
 * mode of a permission system is a verb nobody remembered to cover -- so the
 * table is indexed by kind for all `NCFG_PROTO_REQ_COUNT` of them and
 * `authorize_test.c` asserts that every one is classified. That assertion is the
 * `match`, moved from the compiler to a test.
 *
 * A kind outside the enum answers `NCFG_TIER_ADMIN`, which is the direction
 * that denies.
 */
ncfg_tier_t ncfg_tier_of(ncfg_proto_request_kind_t kind);

/*
 * Where a connection came from (0128).
 *
 * **Observed rather than claimed**: it is which socket the connection arrived
 * on, so there is no field for a caller to set and nothing for the daemon to
 * evaluate.
 *
 * Named `arrival` and not `origin`, which is what the Rust calls it, because
 * `observed.h` already spells `ncfg_origin_t` and means *which addressing
 * source produced an address*. One word with two meanings in one library is
 * what the block-qualified privilege table exists to survive -- `config` in
 * two blocks, `group` in two others -- and a type is worse than a key, because
 * the compiler will happily take either one.
 */
typedef enum {
	/* On this machine, identified by peer credentials. */
	NCFG_ARRIVED_LOCAL = 0,
	/* Terminated by `agent/`, which arrived from off the machine. */
	NCFG_ARRIVED_REMOTE
} ncfg_arrival_t;

/* ------------------------------------------------------- the privilege gate */

/*
 * Why a production needs more than the network-configuration right.
 *
 * Enumerated against the compiler rather than from memory, which is what
 * found six where a list written from memory names hooks and stops.
 * `@secret:exec:` is the one that makes the point: a command run as root,
 * living inside the *secrets* feature, where somebody auditing for code
 * execution would not think to look.
 */
typedef enum {
	/* A hook body is shell, and `run_as` absent means the daemon's own user,
	 * which is root. */
	NCFG_PRIV_HOOK = 0,
	/* 0119's probe block: a program, how often to run it, how long to wait. */
	NCFG_PRIV_PROBE,
	/* A secret fetched by running a command. */
	NCFG_PRIV_SECRET_EXEC,
	/* A path to another program's configuration, read as root, which may
	 * itself name scripts. */
	NCFG_PRIV_FOREIGN_CONFIG,
	/* A filesystem path opened by something running as root. */
	NCFG_PRIV_PATH,
	/* `include` pulls another file into the configuration wholesale. */
	NCFG_PRIV_INCLUDE,
	/* Changes who may ask netcfgd for what -- the one an audit for paths and
	 * commands cannot find, because it is neither. */
	NCFG_PRIV_AUTHORIZATION,
	/* Hands a device netcfgd creates to a named user or group. */
	NCFG_PRIV_PRINCIPAL,
	NCFG_PRIV_COUNT
} ncfg_privilege_reason_t;

/* A sentence naming what it grants rather than what it is. NULL outside the
 * enum. */
const char *ncfg_privilege_why(ncfg_privilege_reason_t reason);

/* One production that needs more than an ordinary caller has. */
typedef struct {
	ncfg_privilege_reason_t reason;
	/* What it was, as written: `post_up`, `openvpn.config`,
	 * `psk= @secret:exec:`. Owned. */
	char                   *what;
	/* Where, so a diagnostic can point at it. */
	ncfg_span_t             span;
} ncfg_privilege_finding_t;

/*
 * Every privileged production in a parsed file.
 *
 * `count` is how many are kept and `total` how many were found; they differ
 * only past `NCFG_DIAGS_MAX`, which bounds this for the reason the parser's
 * diagnostics are bounded -- a finding per line is a file-sized allocation
 * bought with a file a client sent. Only the first is ever rendered and the
 * count of the rest is the other thing the refusal says, so nothing is lost.
 */
typedef struct {
	ncfg_privilege_finding_t *at;
	size_t                    count;
	size_t                    total;
	size_t                    capacity;
} ncfg_privilege_findings_t;

/*
 * Walk a parsed file and classify it.
 *
 * **Walks rather than compiles, deliberately**: this has to answer for text
 * that may not compile at all, since a caller sending something malformed
 * should be told what is wrong with it rather than what it would have been
 * allowed to do.
 *
 * Declare the findings as `= {0}` and free them with
 * `ncfg_privilege_findings_free`. 0 with `err` only where memory ran out.
 */
int ncfg_privilege_findings(const ncfg_ast_file_t *file, ncfg_privilege_findings_t *out,
    char *err, size_t err_size);
void ncfg_privilege_findings_free(ncfg_privilege_findings_t *findings);

/* ---------------------------------------------------------- the decisions */

/*
 * Whether a peer satisfies a principal.
 *
 * **Root satisfies everything**, and that is not a special case bolted on: a
 * configuration naming a group and thereby locking root out would be
 * unrecoverable without editing the file the daemon is refusing to let you
 * reach.
 *
 * A `user:` or `group:` name that does not resolve denies, and so does a
 * `group:` rule against a peer whose supplementary set could not be read.
 */
int ncfg_authz_satisfies(const ncfg_authz_roots_t *roots, const ncfg_peer_t *peer,
    const ncfg_principal_t *principal);

/*
 * Why a request was refused, in words the caller can act on.
 *
 * A permission error that says only "denied" sends the reader to the source.
 * This one names the tier, what the policy says, and where to change it --
 * and section 7 of the protocol document asks a client to pass it on
 * unreworded for exactly that reason.
 */
void ncfg_authz_refusal(ncfg_tier_t tier, const ncfg_principal_t *principal, char *err,
    size_t err_size);

/*
 * The tier gate: may this caller make a request of this kind?
 *
 * A remote connection is judged by `remote` alone. **Its peer credentials are
 * not consulted**, because its uid is the agent's -- checking it would be
 * checking the wrong thing while appearing to check the right one.
 */
int ncfg_authz_check(const ncfg_authz_roots_t *roots, const ncfg_control_t *control,
    const ncfg_remote_policy_t *remote, ncfg_arrival_t arrival, const ncfg_peer_t *peer,
    const ncfg_proto_request_t *request, char *err, size_t err_size);

/*
 * The content gate: may this caller send *this content*?
 *
 * **Root on this machine, and nothing else.** Not the `admin` tier, which a
 * site may have opened to a group -- that is the whole point, since 0127's
 * architecture only survives an open local policy if opening it cannot grant
 * root. And never from off the machine whatever the remote policy says: a
 * remote caller has no uid the daemon can check, so there is no version of
 * "is this root" to ask, and inventing one would be trusting the agent for
 * the one thing the split exists to avoid.
 *
 * Text that does not parse is **not** this gate's to refuse. The writer
 * compiles it and reports diagnostics pointing at the line; answering a
 * syntax error with a sentence about privilege sends the reader looking for a
 * permission problem they do not have.
 */
int ncfg_authz_check_content(ncfg_arrival_t arrival, const ncfg_peer_t *peer,
    const ncfg_proto_request_t *request, char *err, size_t err_size);

/*
 * May this caller do this, all of it?
 *
 * **The one call the daemon makes.** The module's claim is that one function
 * answers "who may do this?", so there is one place to read and one place a
 * mistake can be; 0127's second gate briefly made that untrue, and forgetting
 * it is invisible because every test of the content gate calls it directly
 * and passes whether or not anything in the daemon does.
 */
int ncfg_authz_permitted(const ncfg_authz_roots_t *roots, const ncfg_control_t *control,
    const ncfg_remote_policy_t *remote, ncfg_arrival_t arrival, const ncfg_peer_t *peer,
    const ncfg_proto_request_t *request, char *err, size_t err_size);

/*
 * Every tier this peer satisfies, written into `out` in tier order.
 *
 * The same question `ncfg_authz_check` asks per request, asked once for all
 * three, because a client that finds out by being refused puts a button on a
 * screen that fails when pressed (0092). Returns how many were written; `out`
 * holds at least `NCFG_TIER_COUNT`.
 */
size_t ncfg_authz_granted(const ncfg_authz_roots_t *roots, const ncfg_control_t *control,
    const ncfg_remote_policy_t *remote, ncfg_arrival_t arrival, const ncfg_peer_t *peer,
    ncfg_tier_t *out);

/* ------------------------------------------------------------ the answers */

/*
 * The three responses this module can write for itself.
 *
 * `proto.h` decodes every response and encodes no response: the encoder is
 * the daemon's half and the rest of it belongs with the requests that produce
 * it. These three do not -- `error` and `hello` are answers the authorization
 * path itself produces, and `ok` is what a permitted request that says
 * nothing else comes back as -- so they live here, beside the code that
 * decides them.
 *
 * Each appends one JSON object and no newline. `ncfg_daemon_line_write`
 * frames one and is what puts it on a socket.
 */

/*
 * What `hello` answers about itself.
 *
 * The protocol version is the daemon's, so it is stated by the daemon: the
 * Rust keeps it in `netcfgd-proto` because that crate is both halves, and the
 * C `proto.h` is the codec both halves share -- a number a client would then
 * be claiming as its own. The minor is what a client reads to know whether a
 * verb is there; a major stays reserved for a change that makes an old client
 * wrong rather than merely incomplete.
 *
 * The schema version is the document's and comes from `document.h`, because
 * two spellings of it is how a `hello` comes to promise a schema the documents
 * do not carry.
 */
#define NCFG_DAEMON_PROTOCOL_MAJOR 1
#define NCFG_DAEMON_PROTOCOL_MINOR 3

int ncfg_daemon_error_encode(const char *message, ncfg_buf_t *out, char *err, size_t err_size);
int ncfg_daemon_ok_encode(ncfg_buf_t *out, char *err, size_t err_size);
int ncfg_daemon_hello_encode(const ncfg_tier_t *tiers, size_t tier_count, ncfg_buf_t *out,
    char *err, size_t err_size);

/*
 * What this daemon can see, as the `status` response.
 *
 * **The observation flattened into the envelope**, which is the wire shape the
 * Rust's `Response::Status(Box<Observed>)` has and `doc/schema/socket.json`
 * pins: `{"response":"status",<every member of the observation>}`. The members
 * are written by the model's own tables through
 * `ncfg_observed_write_members`, so this encoder cannot come to disagree with
 * `observed.json` about a member name or its order.
 *
 * **A daemon that has not observed the machine refuses rather than answering
 * an empty observation**, and that is the whole judgement in this call: an
 * observation with no links reads as a machine with no interfaces, which a
 * client cannot tell from one nothing has looked at. The refusal says which it
 * is.
 */
int ncfg_daemon_status_encode(const ncfg_observed_t *observed, ncfg_buf_t *out, char *err,
    size_t err_size);

/*
 * The desired state, as the `document` response.
 *
 * The same shape and the same argument, one model along:
 * `{"response":"document",<every member of the document>}`.
 *
 * A daemon holding no compiled configuration refuses with `diagnostics` where
 * it has them, which is what the Rust answers: the reason the configuration
 * did not compile is the answer to "show me the configuration", and "no
 * configuration" is what is left when nothing said why.
 */
int ncfg_daemon_document_encode(const ncfg_document_t *desired, const char *diagnostics,
    ncfg_buf_t *out, char *err, size_t err_size);

/*
 * What netcfgd would do, as the `plan` response.
 *
 * `{"response":"plan",<the plan's four members>}`, flattened like the two
 * above and written by `ncfg_plan_write_members` for the same reason.
 *
 * **A plan that failed while it was being built is refused rather than sent.**
 * `plan.h` says why at its own writer: half a plan that looks whole is the one
 * that gets applied, and a client cannot tell a plan with three actions from a
 * plan that ran out of memory after three.
 */
int ncfg_daemon_plan_encode(const ncfg_plan_t *plan, ncfg_buf_t *out, char *err,
    size_t err_size);

/*
 * Every credential name this machine knows about, as the `secrets` response.
 *
 * The entries are `ncfg_secret_list`'s and are borrowed. **Nothing here reads a
 * value**, which is that call's own property and is what makes this answerable
 * to a client at all: the store is consulted for whether a file exists and for
 * nothing else.
 *
 * `used_by` is **omitted rather than empty** where nothing refers to a name,
 * because the two are different answers: a machine whose configuration does
 * not compile can say which credentials it holds and cannot say who wants
 * them, and an empty list would claim the second.
 *
 * An empty list of entries is an answer -- a machine with no credentials --
 * and is written as one.
 */
int ncfg_daemon_secrets_encode(const ncfg_secret_entry_t *entries, size_t count,
    ncfg_buf_t *out, char *err, size_t err_size);

/*
 * The profiles this machine has and the one in force, as the `profiles`
 * response.
 *
 * `chosen` is **omitted where none is selected**, which is the common case and
 * not an error; a client reads its absence as "none" rather than as a name it
 * has to compare against.
 */
int ncfg_daemon_profiles_encode(const ncfg_profile_entry_t *entries, size_t count,
    const char *chosen, ncfg_buf_t *out, char *err, size_t err_size);

/*
 * Every configuration file netcfgd reads, as the `configs` response.
 *
 * The entries are `ncfg_config_list_drop_ins`'. `name` is **omitted where the
 * file is not a drop-in**, because `name` is what `config put` and
 * `config delete` take: a client shown one for `netcfgd.conf` would offer a
 * delete that is refused.
 */
int ncfg_daemon_configs_encode(const ncfg_config_entry_t *entries, size_t count,
    ncfg_buf_t *out, char *err, size_t err_size);

/*
 * Every hook the document declares, as the `hooks` response.
 *
 * The entries are `ncfg_hooks_list`'. `text` is written even where the script
 * could not be read, because `readable` is what says which of the two an empty
 * one is.
 */
int ncfg_daemon_hooks_encode(const ncfg_hook_script_t *scripts, size_t count, ncfg_buf_t *out,
    char *err, size_t err_size);

/*
 * Why something is the way it is, as the `explanation` response.
 *
 * `{"response":"explanation","subject":...,"facts":[...]}`, and `source` is
 * omitted for a fact that came from nowhere nameable -- a derived answer, or a
 * policy read off the document without a recorded position. An empty string
 * there would be a file called nothing.
 *
 * **Where the bound bit, the last fact says so.** `explain.h` holds an
 * explanation at `NCFG_EXPLAIN_FACTS_MAX` with `total` counting past it, and
 * the wire has nowhere to put that number: the Rust has no bound, so its
 * `Explanation` carries a subject and facts and nothing else. Adding a member
 * would be a response a client built against the Rust refuses to decode, and
 * saying nothing would be an answer silently missing most of itself. A fact is
 * what this protocol has for saying something, so the truncation is one --
 * last, where a reader meets it after what was shown rather than instead of
 * it.
 */
int ncfg_daemon_explanation_encode(const ncfg_explanation_t *explanation, ncfg_buf_t *out,
    char *err, size_t err_size);

/* ------------------------------------------------------------- the server */

/*
 * How many connections may be open at once.
 *
 * The socket already bounds one connection: `NCFG_PROTO_MAX_LINE` refuses a
 * client that sends a gigabyte without a newline, because the daemon holds
 * `CAP_NET_ADMIN` and making it allocate its way to being killed is a denial
 * of service with extra steps. The same sentence applies to ten thousand
 * connections, each of which is a thread. Generous for what actually
 * connects: a tray, a window, a TUI, a monitor stream and whatever `ncfg`
 * invocations are in flight is under ten.
 */
#define NCFG_DAEMON_MAX_CONNECTIONS 64

/*
 * How long an accepted connection has to make its first request.
 *
 * **A connection that has said nothing is not a client** (0183). Without this
 * one could hold a slot for ever, so sixty-four silent connections take every
 * slot the cap allows and the daemon answers "too many connections" to
 * everybody else -- measured against a real daemon, with `ncfg reload`
 * refused for as long as they were held. On a machine whose policy opens
 * `observe` to `any`, that is any local user.
 *
 * Generous, because it is only about *silence*: the deadline is cleared once
 * a request has been read, so a tray holding an idle connection between
 * clicks and a `monitor` stream that says nothing for hours are untouched.
 *
 * What it does not close, said plainly: a caller that sends one valid request
 * and then idles still holds its slot. The cap is what bounds that.
 */
#define NCFG_DAEMON_FIRST_REQUEST_SECONDS 10

/*
 * What answers a request.
 *
 * **The seam, and the reason the server is testable at all.** Everything
 * above this line is sockets and threads; everything a request *means* is on
 * the other side of it. A test drives real connections against a handler that
 * answers from a fixture, which is `apply.h`'s recorder wearing a different
 * hat.
 *
 * The request has already passed `ncfg_authz_permitted` when this is called,
 * so an implementation never re-decides authorization -- two answers to "may
 * I" is the thing 0092 exists to prevent.
 *
 * **`hello` never reaches it**, for the same reason: everything that answer
 * carries is this module's -- the two versions and the tiers this connection
 * satisfies -- and a seam computing the tier list would be that second
 * implementation.
 *
 * Fill `out` with one JSON object and no newline; the server frames it.
 * Return 0 with a sentence in `err` and the server answers `error` with that
 * sentence, which is still an answer.
 *
 * **It is called with the server's lock held**, so implementations may touch
 * shared state without one of their own, and must not block on anything but
 * their own work -- the socket write happens after the lock is released.
 */
typedef int (*ncfg_daemon_answer_fn)(void *context, const ncfg_proto_request_t *request,
    const ncfg_peer_t *peer, ncfg_arrival_t arrival, ncfg_buf_t *out, char *err, size_t err_size);

/*
 * What takes a subscribed connection.
 *
 * **`monitor` is the one request that is not answered**, and the reason is
 * structural rather than a preference: every other request is a question with
 * a reply, and this one turns the connection into a stream that somebody else
 * writes to for as long as the client is there. `ncfg_daemon_answer_fn` is
 * handed a request and a buffer and has no descriptor at all, so there is
 * nothing it could hand over -- which is why the Rust special-cases `monitor`
 * in its server too, beside the loop it hands the stream to, rather than in
 * the dispatcher behind it.
 *
 * It is called **after `ncfg_authz_permitted` has said yes**, so an
 * implementation never re-decides authorization; `monitor` needs the
 * `observe` tier and the gate has already asked.
 *
 * **The descriptor becomes the seam's on success**, and stays the server's on
 * failure. Return 1 and this server never touches that number again -- it is
 * a `dup` of the connection made for the purpose, so the server goes on
 * closing its own in the ordinary way and neither close can reach the other's.
 * Return 0 with a sentence and the server closes it and answers `error` with
 * that sentence, which is still an answer.
 *
 * **It is called with the server's lock held**, as the answer seam is, and it
 * may block for as long as that one may: `ncfg_daemon_server_stop` locks the
 * same mutex, so whoever installs a seam that parks owes the same release
 * `ncfg_daemon_answer_fn`'s does.
 */
typedef int (*ncfg_daemon_stream_fn)(void *context, int fd, char *err, size_t err_size);

/*
 * What to serve, and where.
 *
 * `path` has **no default**, deliberately: the real daemon's socket is
 * `/run/netcfgd/netcfgd.sock` on the machine this is built on, and a struct
 * that defaulted to it would be one mistake away from a test binding the live
 * one. Whoever serves says where.
 *
 * `reach` is who may open the file, **which is not who may do anything**. The
 * local socket passes its three principals because those are the people the
 * local policy speaks about; the remote socket passes one, naming who may act
 * as the agent. Passing the *local* policy for both is what 0159 fixes: a
 * `control` block opening `observe` was opening a socket that grants the
 * remote tiers, since a remote connection consults no principal at all.
 */
typedef struct {
	const char                   *path;
	ncfg_arrival_t                arrival;
	const ncfg_principal_t *const *reach;
	size_t                        reach_count;
	/* The policies every connection on this socket is judged by. Borrowed,
	 * and they must outlive the server. */
	const ncfg_control_t         *control;
	const ncfg_remote_policy_t   *remote;
	ncfg_authz_roots_t            roots;
	ncfg_daemon_answer_fn         answer;
	/* What a `monitor` hands its connection to. A server with none refuses
	 * `monitor` by name -- a daemon that accepted the request and streamed
	 * nothing would leave a client watching a socket that can never say
	 * anything. */
	ncfg_daemon_stream_fn         stream;
	/* Shared by both seams, deliberately: they are two halves of one
	 * answer -- what a request means -- and two contexts would be two
	 * implementations of the daemon's state with nothing keeping them in
	 * step. The Rust sends a request and a subscription down the same
	 * channel to the same loop for the same reason. */
	void                         *context;
} ncfg_daemon_serve_t;

typedef struct ncfg_daemon_server ncfg_daemon_server_t;

/*
 * Bind and serve, returning as soon as the socket is listening.
 *
 * The listener is bound before this returns, so a client cannot race the
 * bind. A stale socket from a previous run is removed first: leaving the
 * daemon unable to start because it did not shut down cleanly last time is a
 * worse failure than removing a file nothing is listening on.
 *
 * The socket's mode follows the policy, because a policy naming a group is a
 * lie if the socket stays root-only -- the caller cannot connect to be told
 * yes. `0666` where any tier is `any`, `0660` where the policy opens beyond
 * root, `0600` otherwise, and the socket is given to the first named group.
 * Where that cannot be done -- no such group, or this process is not root --
 * it is said loudly rather than left with the two disagreeing, because that
 * combination produces a bug report about wifi not working which takes an
 * afternoon to trace.
 */
ncfg_daemon_server_t *ncfg_daemon_serve(const ncfg_daemon_serve_t *how, char *err,
    size_t err_size);

/*
 * Stop accepting, end every connection, join every thread, unlink the socket.
 *
 * **It leaves nothing behind**, which is a requirement rather than a courtesy:
 * a test that left a thread blocked in `read` would leave it blocked for the
 * life of the binary. Passing NULL is nothing.
 */
void ncfg_daemon_server_stop(ncfg_daemon_server_t *server);

/* How many connections are open. For a test asserting that a slot is held for
 * as long as the connection is, and released when it closes: a counter that
 * never fell would pass every other check and then refuse everything once the
 * daemon had served `NCFG_DAEMON_MAX_CONNECTIONS` in total. */
size_t ncfg_daemon_server_open(const ncfg_daemon_server_t *server);

/* The path it is listening on, for a caller that wants to connect to it. */
const char *ncfg_daemon_server_path(const ncfg_daemon_server_t *server);

/*
 * Put one built object on a descriptor, framed.
 *
 * `ncfg_proto_line_finish`'s newline rule applies: a message containing a raw
 * newline would frame as two and the peer would mis-parse both halves, so it
 * is refused here rather than sent.
 */
int ncfg_daemon_line_write(int socket, ncfg_buf_t *object, char *err, size_t err_size);

/* ------------------------------------------------------------- the state */

/* Where the daemon reads and writes. Every one is a copy this owns. */
typedef struct {
	/* The factory-default config directory, read before the writable one. */
	char *factory;
	/* The writable config directory. */
	char *config;
	/* The runtime state directory. */
	char *run;
} ncfg_daemon_paths_t;

/*
 * How an observation is built.
 *
 * **A seam rather than a call, because the kernel is on the other side of
 * it.** `observe.h` builds an observation from a snapshot; taking that
 * snapshot is netlink, sysfs and `/proc`, and a daemon test that did it for
 * real would be reading the developer's own machine. So the daemon is handed
 * this and a test hands it a fixture.
 *
 * Fill `*out` with a fresh observation the caller then owns. 0 with `err`
 * where the kernel could not be read, which is not fatal: the previous
 * observation is kept, because an unreadable kernel silently disarming drift
 * detection is the moment it is most wanted.
 */
typedef int (*ncfg_daemon_observe_fn)(void *context, const ncfg_document_t *desired,
    ncfg_observed_t **out, char *err, size_t err_size);

/*
 * What the daemon knows.
 *
 * Deliberately free of threads, sockets and signals: everything here is a
 * call taking the state and returning what happened, which is the seam that
 * makes it testable without hardware.
 *
 * **The probe verdicts and the SIM selection are not fields here**, although
 * they are in the Rust's `State`. Each is a module of its own below with its
 * own lifetime, and a caller holds one beside a state rather than inside it:
 * a reload replaces the document and must not replace a tally that has been
 * counting across ticks, which is exactly what a field freed with the state
 * would invite. `ncfg_confirm_armed_t` is the third and the strongest case of
 * the same rule: what an open window covers legitimately outlives a reload,
 * which is the whole reason a revert knows what it is putting back.
 */
typedef struct {
	ncfg_daemon_paths_t     paths;
	/* The compiled desired state, or NULL when the config does not compile.
	 * **Kept across a failed reload, deliberately**: dropping it would mean
	 * an unreadable directory silently disarms drift detection. */
	ncfg_document_t        *desired;
	/* Why it does not compile, when it does not. NULL when it does. */
	char                   *diagnostics;
	/*
	 * The hash of a configuration a revert rejected, if there is one.
	 *
	 * Compared against every recompile. Without it, anything that triggers a
	 * reload -- a spurious inotify event, an explicit request -- would adopt
	 * the config that just broke the machine and drift-reconcile the
	 * breakage straight back. A hash rather than a flag so that *fixing* the
	 * config clears it automatically: a different document is a different
	 * answer.
	 */
	char                   *rejected;
	/* What the kernel last reported, or NULL before the first observation. */
	ncfg_observed_t        *observed;
	ncfg_daemon_observe_fn  observe;
	void                   *observe_context;
} ncfg_daemon_state_t;

/*
 * Set one up over three directories, reading nothing yet.
 *
 * No path has a default and none is resolved from the environment here: the
 * caller that knows which machine this is passes them. `ncfg_daemon_state_free`
 * releases everything, and freeing one that was never initialised is nothing.
 */
int ncfg_daemon_state_init(ncfg_daemon_state_t *state, const char *factory_dir,
    const char *config_dir, const char *run_dir, char *err, size_t err_size);
void ncfg_daemon_state_free(ncfg_daemon_state_t *state);

/*
 * Recompile the config directory, and say what happened.
 *
 * Returns 1 where a document was adopted. 0 is not fatal and never leaves the
 * daemon without a desired state it already had: `diagnostics` carries why,
 * and `err` carries the same sentence for a caller that wants only that.
 *
 * Three ways it can answer no, and they are different:
 *
 *   * the directory could not be read -- `diagnostics` names it;
 *   * it did not compile -- `diagnostics` is the compiler's rendering;
 *   * it compiled to the document a revert rejected, which is refused
 *     **without recording diagnostics**, because adopting it would undo the
 *     revert on the next drift check and the operator would watch that happen
 *     and be unable to explain it. Reading `diagnostics` to answer a reload
 *     is wrong twice over for this reason and because a previous failure's
 *     text is still sitting there, which is why this returns its own answer.
 *
 * Hooks are written **after** the compile succeeds, not during it: the daemon
 * is about to apply from this document so the hooks it names have to exist,
 * but a compile that failed should leave nothing behind rather than whichever
 * hooks it reached before the diagnostic.
 */
int ncfg_daemon_state_reload(ncfg_daemon_state_t *state, char *err, size_t err_size);

/*
 * Re-read the kernel through the seam, reporting whether the link set moved.
 *
 * **The link set rather than the whole observation**, because a caller uses
 * this to decide whether to tell subscribers the machine changed, and the
 * rest of an observation carries values that move on their own -- a probe
 * verdict, a lease timer -- which would make an idle machine emit events for
 * ever. Names and their up state: a device appearing or going away is what a
 * client's device list is built from, and a link going down without leaving
 * is the other thing that changes what a device is to somebody watching.
 *
 * `*moved` is set to 1 or 0. Returns 0 where the kernel could not be read, in
 * which case the previous observation is kept and `moved` is 0.
 */
int ncfg_daemon_state_reobserve(ncfg_daemon_state_t *state, int *moved, char *err,
    size_t err_size);

/*
 * The identity of a document, as 64 hex digits plus a NUL.
 *
 * `generated_by` is cleared before hashing, because it names the version that
 * produced the document: leaving it in would make an upgrade look like an
 * edit, and the whole use of this is telling "the same configuration" from "a
 * different one". `out` is at least `NCFG_DAEMON_HASH_MAX`.
 */
#define NCFG_DAEMON_HASH_MAX 65
int ncfg_daemon_document_hash(const ncfg_document_t *document, char *out, char *err,
    size_t err_size);

/* ------------------------------------------------------- the probe verdicts */

/*
 * Asking an uplink whether it actually carries traffic (0119).
 *
 * **A probe is an observation.** It runs a program the operator named, takes
 * the exit status as the answer, and the verdict joins observed state beside
 * carrier -- where the planner already knows what to do with a link that is
 * not carrying anything.
 *
 * **The verdict lives here and not in the observation**, because the observer
 * reads the kernel and no probe result comes from there.
 * `ncfg_daemon_state_reobserve` builds a fresh observation every time, so a
 * verdict written into one would be gone on the next tick; this keeps the
 * tally across ticks and `ncfg_probes_apply` stamps it on.
 */
typedef struct ncfg_probes ncfg_probes_t;

/*
 * How many consecutive failures to *start* a probe before it is set aside.
 *
 * Only start failures count. A program that runs and exits non-zero is the
 * feature working -- that is a link that is down -- and no number of those
 * ever sets a probe aside. Published so a test cannot spell the number itself
 * and go on passing when the number changes.
 */
#define NCFG_PROBE_START_FAILURES_BEFORE_SET_ASIDE 5

/*
 * The most of a probe's standard error that is kept.
 *
 * It crosses the socket to every client, and a script can write without end.
 * The tail rather than the head: a shell script's last words are the ones
 * about the thing that just failed.
 */
#define NCFG_PROBE_DETAIL_MAX 400

/*
 * Where "now" comes from, in monotonic milliseconds.
 *
 * **A seam, for the reason `ncfg_daemon_observe_fn` is one**: the thing on the
 * other side is not something a test can arrange. The Rust's dwell tests pace
 * themselves against the real clock -- six runs a second apart, twice -- and
 * one of them is the flake its own comments record. Here a test hands over a
 * counter it moves itself, and the hysteresis is measured rather than waited
 * for.
 *
 * **It is the scheduling clock only.** The deadline a running program is
 * killed at is read from `CLOCK_MONOTONIC` directly and is not this, because
 * a frozen clock against a live child is a wait that never ends -- which is
 * the one thing a probe timeout exists to prevent.
 */
typedef int64_t (*ncfg_probes_clock_fn)(void *context);

/* An empty tally set. NULL with a sentence where memory ran out. */
ncfg_probes_t *ncfg_probes_new(char *err, size_t err_size);

/* Release it. Freeing NULL is nothing. */
void ncfg_probes_free(ncfg_probes_t *probes);

/* Take "now" from somewhere else. Passing NULL puts `CLOCK_MONOTONIC` back. */
void ncfg_probes_clock(ncfg_probes_t *probes, ncfg_probes_clock_fn clock, void *context);

/*
 * Run whatever is due, and say whether any verdict changed.
 *
 * `*changed` is what the caller needs, because it is the only reason to
 * re-plan: a probe that agrees with itself for an hour should cost nothing but
 * the program it runs. A NULL document clears every tally, which is what a
 * daemon holding no desired state knows about the links.
 *
 * **`observed` is here for the lease precondition and nothing else** (0191). A
 * probe is still an observation of the *link*, made by running the operator's
 * program; what the kernel's own state decides is whether running it could
 * tell us anything.
 *
 * Returns 1, or 0 with a sentence where memory ran out. A probe that could not
 * be started is not a failure of this call -- it is an answer, and it is
 * counted.
 */
int ncfg_probes_run_due(ncfg_probes_t *probes, const ncfg_document_t *desired,
    const ncfg_observed_t *observed, int *changed, char *err, size_t err_size);

/*
 * The interfaces whose probe has decided the link does not work.
 *
 * A decided `false` only: an interface with no probe, or one whose probe has
 * not yet agreed with itself `down_after` times, is not in here. That is
 * 0119's rule and it is what stops a SIM being switched on no information
 * (0152).
 *
 * In name order, so a machine with two failing modems advances them in the
 * same order every time and a test can say what it expects. Counted and
 * indexed rather than collected into an array the caller frees: the answer is
 * usually empty, and a walk that cannot fail is one a caller will not skip
 * checking. The names belong to `probes` and last until the next `run_due`.
 */
size_t ncfg_probes_failing_count(const ncfg_probes_t *probes);
const char *ncfg_probes_failing_at(const ncfg_probes_t *probes, size_t at);

/*
 * Stamp the verdicts onto a fresh observation.
 *
 * Only a decided verdict is written. A link with no probe, or one whose probe
 * has not yet agreed with itself enough times, is left absent -- and the
 * planner treats absent as "nobody asked", which is what stops this taking the
 * network away from a machine that configured no probes.
 *
 * Returns 1, or 0 with a sentence where a detail could not be copied; every
 * link it reached before that is still stamped, because a half-stamped
 * observation is closer to the truth than an unstamped one.
 */
int ncfg_probes_apply(const ncfg_probes_t *probes, ncfg_observed_t *observed, char *err,
    size_t err_size);

/*
 * What this module has decided about one interface, and why.
 *
 * Read by the tests that are about the decision rather than about the stamping
 * -- going through `ncfg_probes_apply` would mean hand-building a link and its
 * thirty fields for one optional boolean. The detail belongs to `probes` and
 * is NULL where the probe has said nothing.
 */
ncfg_optbool_t ncfg_probes_verdict(const ncfg_probes_t *probes, const char *interface);
const char *ncfg_probes_detail(const ncfg_probes_t *probes, const char *interface);

/* ---------------------------------------------------------- the SIM sources */

/*
 * Which SIM source netcfgd wants, per modem device (0150, 0152).
 *
 * **The choice lives in `/run` and the preference lives in the document.** The
 * ordered list is the operator's intent and is never written to. What moves is
 * the index, which is derived and disposable and gone after a reboot, so a
 * cold start begins at the preference again.
 *
 * netcfgd says which source is wanted; a `pre_up` hook makes the hardware do
 * it, because driving a mux select line is board enablement and netcfgd has no
 * GPIO anywhere.
 */
typedef struct ncfg_sims ncfg_sims_t;

/* An empty selection. NULL with a sentence where memory ran out. */
ncfg_sims_t *ncfg_sims_new(char *err, size_t err_size);

/* Release it. Freeing NULL is nothing. */
void ncfg_sims_free(ncfg_sims_t *sims);

/*
 * Bring the selection into line with a document, and publish it.
 *
 * Called on every reload. A device that gains a modem block starts at its
 * first source; one that loses it, or leaves the document, has its file
 * removed rather than left behind to be read as current by a hook that has no
 * other way of knowing.
 *
 * The index is **clamped rather than reset**, so shortening the list of a
 * device already on a later source moves it to the last one that still exists
 * instead of silently taking it back to the first -- which would be a SIM
 * switch nobody asked for, arriving through an edit to an unrelated part of
 * the list.
 *
 * Returns 1, or 0 with a sentence naming the file that could not be written.
 * The in-memory selection is brought into line either way: a `/run` that
 * cannot be written is a fact to report, and refusing to track the document as
 * well would make the next reload publish from a selection that had stopped
 * following it.
 */
int ncfg_sims_sync(ncfg_sims_t *sims, const ncfg_document_t *document, const char *run_dir,
    char *err, size_t err_size);

/*
 * Move a device to its next SIM source, if it has one.
 *
 * `*moved_to` names the source it moved to, borrowed from `document`, or is
 * left NULL where it is already on the last one -- 0152 stops there rather
 * than wrapping, because a machine whose subscription has lapsed would
 * otherwise reset its modem for ever and be permanently offline rather than
 * offline until somebody looked.
 *
 * Returns 1 where the call did what was asked, **whether or not it moved**,
 * and 0 with a sentence for a device this document gives no modem policy, a
 * selection that could not be published, or no memory. The Rust answers `None`
 * to all four of those and to "there is nowhere to go"; a caller cannot tell
 * the one that is normal from the three that are not.
 */
int ncfg_sims_advance(ncfg_sims_t *sims, const ncfg_document_t *document, const char *device,
    const char *run_dir, const char **moved_to, char *err, size_t err_size);

/*
 * Devices whose link has to be cycled for the new selection to take.
 *
 * Publishing the choice is not applying it: a `pre_up` hook is what acts on
 * the file, and `pre_up` fires on the way up. So an advance leaves a note
 * here, the reconcile turns it into a plan's cycle list, and it is cleared
 * once a plan carrying that cycle has been **applied** -- not when it is
 * planned, so a plan that could not run is tried again rather than leaving the
 * machine on a source nothing ever selected.
 *
 * In name order. The names belong to `sims` and a caller that collects them
 * and then calls `ncfg_sims_cycled` is holding pointers into this module's own
 * storage: that is safe and is what the reconcile loop does, because `cycled`
 * decides everything it is going to drop before it drops any of it.
 */
size_t ncfg_sims_pending_count(const ncfg_sims_t *sims);
const char *ncfg_sims_pending_at(const ncfg_sims_t *sims, size_t at);
int ncfg_sims_is_pending(const ncfg_sims_t *sims, const char *device);

/*
 * Forget the notes that a plan has now acted on.
 *
 * **A note is dropped only where its cycle actually happened.** Both Rust call
 * sites once cleared every note the moment `apply` returned, and `apply`
 * returns a journal rather than a result -- so a `link.down` that failed
 * forgot the note anyway and nothing retried. The modem then sat on the source
 * it had, with the new one published to `/run` and `pre_up` never fired, until
 * something unrelated cycled the link.
 *
 * The condition is **per device rather than per plan**, and that matters in
 * both directions. Clearing on a whole-plan success would keep the note alive
 * whenever anything else in the plan failed -- a wifi backend, an unrelated
 * address -- and every apply after would take a working link down and up
 * again.
 *
 * A device with no records at all clears, and that is the right answer rather
 * than an oversight: the planner emits a cycle only for a link that is *up*,
 * because a link that is down runs `pre_up` on its way up regardless. No
 * records means no cycle was needed.
 */
void ncfg_sims_cycled(ncfg_sims_t *sims, const char *const *devices, size_t device_count,
    const ncfg_journal_t *journal);

/*
 * Take note of the cards helpers have reported, so a status can show them.
 *
 * **The pairing comes from the report, not from the current selection.**
 * netcfgd publishes the source it wants and a helper reads the card some
 * seconds later, across a modem reset -- so pairing the current selection with
 * whatever ICCID last appeared would file one card under the other's name
 * every time a source advanced. An advance publishes immediately while the
 * module is still reading the old card, which is exactly the window where that
 * mistake would be made and would then persist.
 *
 * So a report without a `sim` field contributes nothing. It is not an error,
 * and older helpers write exactly that: an ICCID with no idea which source it
 * belongs to is a fact netcfgd cannot use, and guessing would be worse than
 * not showing it. A source is only accepted if the document lists it, so a
 * stale report naming a source that has been edited out cannot resurrect it.
 *
 * Returns 1, or 0 with a sentence where memory ran out.
 */
int ncfg_sims_observe(ncfg_sims_t *sims, const ncfg_document_t *document,
    const ncfg_observed_report_t *reports, size_t report_count, char *err, size_t err_size);

/*
 * Every modem device, what it asks for and what is in force.
 *
 * Joined here rather than by the client, because the two halves live apart:
 * the order comes from the document and the choice from this module's own
 * state. A client stitching them together would be a second copy of a rule
 * that belongs to the daemon.
 *
 * **Every string in the result is borrowed** -- from `document` and from
 * `sims` -- so both must outlive it and neither may be changed while it is
 * held. Only the arrays are allocated; `ncfg_sims_status_free` releases them
 * and freeing what was never filled in is nothing. A daemon holding no
 * document answers an empty list rather than an error: no configuration is a
 * state.
 */
int ncfg_sims_status(const ncfg_sims_t *sims, const ncfg_document_t *document,
    ncfg_proto_modem_t **out, size_t *count_out, char *err, size_t err_size);
void ncfg_sims_status_free(ncfg_proto_modem_t *modems, size_t count);

/*
 * The source a device is on, or NULL where it has none.
 *
 * Borrowed from `document`. For a caller reporting what is in force, and for
 * the tests about clamping and advancing, which are about the index and not
 * about the file.
 */
const char *ncfg_sims_current(const ncfg_sims_t *sims, const ncfg_document_t *document,
    const char *device);

/* ------------------------------------------------------ the confirm window */

/*
 * Apply, start a timer, and put the last-good configuration back unless
 * somebody confirms (design section 4.5).
 *
 * The point is a machine you are connected *through*: if the change severs
 * your session, the box comes back on the old configuration by itself. So
 * everything here is arranged around the operator not being able to speak
 * afterwards, and the questions that matter are what survives a restart and
 * what happens when nobody answers.
 *
 * WHERE THE PROMISE IS KEPT, AND WHY IT IS NOT THE RUN DIRECTORY
 *   Everything else netcfgd records is a claim about an object that still
 *   exists, so it can be rebuilt by asking the object. A window is not that:
 *   it asserts that somebody applied a change and *did not come back*, which
 *   nothing in the world holds a copy of, so losing the file is losing the
 *   thing itself. `systemd.exec(5)` deletes a `RuntimeDirectory=` on a real
 *   stop, so a window written inside `/run/netcfgd` survived `systemctl
 *   restart` and was destroyed by a stop and a start -- two spellings of one
 *   operator intent with opposite outcomes, and the safe-looking spelling was
 *   the losing one. Both files therefore live in a **sibling** of the run
 *   directory: `/run/netcfgd` gives `/run/netcfgd-confirm` (0163).
 *
 * WHY THE FILES ARE IN THIS MODULE AND NOT THE HOST ONE
 *   The Rust splits them -- `netcfgd-host::confirm` holds the two files and
 *   `netcfgd-daemon::confirm` the state machine -- and nothing outside the
 *   daemon calls either half. One module, and the file format beside the only
 *   code that reads it.
 *
 * WHAT IS DELIBERATELY NOT HERE
 *   The replay of the inverses is `ncfg_apply_revert`. It is a pure function
 *   of a plan, a journal and an executor -- no window file, no last-good
 *   document, no socket -- so it lives where the same double that drives every
 *   other apply can drive it too.
 */

/* A path this module composes. `NCFG_RA_PATH_MAX`'s number, for its reason. */
#define NCFG_CONFIRM_PATH_MAX 512

/*
 * Where the window and the last-good document are written.
 *
 * `<parent>/<name>-confirm`, and `<run>/confirm` for a run directory with no
 * final component: `/` and the empty string are not real configurations, and a
 * subdirectory is the answer that cannot escape upwards. A trailing slash
 * names the same directory and must not answer differently.
 *
 * Copies into `out` and returns it, which is `ncfg_state_resolve_dir`'s shape
 * -- one buffer and no ownership question. NULL where it would not fit.
 */
const char *ncfg_confirm_dir(const char *run_dir, char *out, size_t out_size);

/*
 * An open commit-confirm window.
 *
 * The deadline is **absolute and wall-clock**, and both halves of that are
 * load-bearing. Absolute, so a daemon that restarts inside the window knows
 * how much is left without having to trust its own uptime. Wall-clock, so a
 * machine that sleeps through a window wakes with it already closed -- a
 * monotonic instant does not advance across a suspend, so a window stored that
 * way would come back with its whole duration still to run and would revert a
 * change the operator had been living with all night. The cost is that a clock
 * step moves an open window, which `confirm_test.c` pins in both directions so
 * that changing it is a decision with a number attached rather than an
 * accident.
 */
typedef struct {
	uint64_t deadline_epoch;
	/* How long the window was, for reporting. */
	uint32_t window_seconds;
	/* The document to go back to, by `ncfg_daemon_document_hash`. */
	char     last_good_hash[NCFG_DAEMON_HASH_MAX];
} ncfg_confirm_window_t;

/* Seconds since the epoch, or 0 where this machine's clock is before it. */
uint64_t ncfg_confirm_now(void);

/*
 * Whether the window has closed, and how long is left, against a clock the
 * caller supplies.
 *
 * **The clock is always an argument, and there is no form that reads it.** The
 * Rust has both, and its own tests say what that cost: the two cases that
 * matter -- a machine that slept through the window, and a clock somebody
 * moved -- were unwritable until the split was made, so neither had ever been
 * checked. One form, and the shape that cannot be tested cannot be spelled.
 * `ncfg_confirm_now()` is what an ordinary caller passes.
 */
int ncfg_confirm_expired_at(const ncfg_confirm_window_t *window, uint64_t now);
uint64_t ncfg_confirm_remaining_at(const ncfg_confirm_window_t *window, uint64_t now);

/*
 * The open window, if there is one. 1 where one was read, 0 otherwise, and
 * `out` is written either way.
 *
 * **Absent and unreadable are one answer**, which is the Rust's behaviour and
 * is the direction that leaves a change standing. It is kept rather than
 * corrected because the alternative is reverting a machine on the strength of
 * a corrupt byte, and the file is netcfgd's own and written atomically, so a
 * half-written one cannot be observed. What it costs is said in
 * `ncfg_confirm_write_window`, which is where something can still be done
 * about it.
 *
 * A member that is not one of the three refuses the file, as the Rust's
 * `deny_unknown_fields` does.
 */
int ncfg_confirm_read_window(const char *run_dir, ncfg_confirm_window_t *out);

/*
 * Record an open window.
 *
 * **A window that could not be written is not a window.** The Rust logs that
 * and carries on, so a full or read-only `/run` produced a `confirm_armed`
 * event, a recorded undo list and no window on disk -- and the expiry then
 * found nothing to resolve, so the change stood while every client had been
 * told it was covered. That is the worst direction to be wrong in: an operator
 * relies on a safety net exactly when they cannot see the machine. Here it is
 * 0 and a sentence, and `ncfg_confirm_arm` refuses rather than announcing a
 * window that does not exist.
 */
int ncfg_confirm_write_window(const char *run_dir, const ncfg_confirm_window_t *window,
    char *err, size_t err_size);

/*
 * Close it.
 *
 * Removing one that is not there is success: an expiry and an explicit revert
 * can both reach this and neither should fail because the other won.
 */
int ncfg_confirm_clear_window(const char *run_dir, char *err, size_t err_size);

/*
 * The last configuration that was applied and stood, or NULL.
 *
 * The caller owns what comes back and frees it with `ncfg_document_free`.
 */
ncfg_document_t *ncfg_confirm_read_last_good(const char *run_dir, char *err, size_t err_size);

/*
 * Record one as the configuration to fall back to.
 *
 * Written canonically, which is what makes a hash identify a *configuration*
 * rather than a compilation: two compiles of one config produce the same bytes
 * and therefore the same hash. Canonicalises in place, as
 * `ncfg_document_write_canonical` does.
 */
int ncfg_confirm_write_last_good(const char *run_dir, ncfg_document_t *document, char *err,
    size_t err_size);

/*
 * What an open window covers: the inverses of the actions that actually ran,
 * in the order they ran, and the hash of the document they came from.
 *
 * **One aggregate rather than two fields, because the two must move together.**
 * The inverses and the hash are recorded at the same instant, cleared at the
 * same instant and consumed at the same instant; apart they would be a second
 * list nothing compels to track the first.
 *
 * **A plan of its own rather than a list of ops, and that is ownership rather
 * than taste.** `plan.h` says a plan owns every string interned into it and
 * borrows four deep trees from the document it was built from -- an interface
 * kind, a DNS policy, a WireGuard peer list, a routing rule list. None of the
 * ops that declare an inverse carries any of those four, so copying the pairs
 * into a plan of their own makes this record self-contained. It has to be: a
 * reload *inside* a window replaces the daemon's desired document with an edit
 * that was deferred and never applied, so a record borrowing from that
 * document would be reading freed memory at the moment the revert runs.
 * `confirm_test.c` frees the document and the plan before reverting, which
 * under ASan is an assertion rather than a claim.
 *
 * **In memory rather than in the window file, which is a limit rather than an
 * oversight.** Writing the inverses out would mean reading them back, and an
 * op is a union of forty-eight arms. So a daemon that restarts inside a window
 * has none of this, and `ncfg_confirm_revert` falls back to re-planning
 * against the last-good document -- the weaker path, and still a correct one.
 */
typedef struct {
	/* The actions that ran and declared an inverse, in plan order. */
	ncfg_plan_t   *undo;
	/* One `NCFG_OUTCOME_DONE` record per action above, which is what lets
	 * `ncfg_apply_revert` drive this: it replays the inverse of every record
	 * saying the machine changed, newest first, and marks what it put back. */
	ncfg_journal_t journal;
	/* The hash of the document those actions were applied from. */
	char           document[NCFG_DAEMON_HASH_MAX];
} ncfg_confirm_armed_t;

/*
 * What to undo if nobody confirms, taken from the plan that ran and the
 * journal saying which of it reached the kernel.
 *
 * **Driven by the journal rather than by the plan alone**, because an action
 * that failed or never ran has nothing to undo -- replaying its inverse would
 * be netcfgd removing an address it never added, or bringing down a link
 * somebody else owns, on a machine that is already in the state a revert
 * exists to rescue. `NCFG_OUTCOME_DONE` is the only outcome that means the
 * machine changed.
 *
 * An action with no declared inverse contributes nothing, which is what the
 * plan's "cannot be undone" warning is about: those are the actions a revert
 * cannot take back, and the warning was true before this and stays true.
 *
 * `commit.arm` is kept and is deliberately left there. Its inverse is
 * `commit.revert`, and all three commit ops are no-ops in the executor -- the
 * window is this module's bookkeeping, not the kernel's -- so replaying it
 * changes nothing and keeps the count a revert reports equal to the count the
 * apply reported.
 *
 * Declare `out` as `= {0}` and free it with `ncfg_confirm_armed_free`.
 */
int ncfg_confirm_armed_from(const ncfg_plan_t *plan, const ncfg_journal_t *journal,
    const ncfg_document_t *document, ncfg_confirm_armed_t *out, char *err, size_t err_size);
void ncfg_confirm_armed_free(ncfg_confirm_armed_t *armed);

/*
 * Check that a window may be opened, and answer what it would revert to.
 *
 * NULL with a sentence where one is already open -- naming how many seconds it
 * has left -- or where there is nothing to fall back to. Arming without a
 * last-good document is refused rather than allowed with an empty target: a
 * window whose revert does nothing is worse than no window, because the
 * operator believes they have a safety net. The daemon applies on start and
 * records a last-good then, so in ordinary use one always exists by the time
 * anybody asks.
 *
 * The caller owns the document that comes back.
 */
ncfg_document_t *ncfg_confirm_may_arm(const ncfg_daemon_state_t *state, char *err,
    size_t err_size);

/*
 * Open the window. Called after the apply has run.
 *
 * `last_good` is what `ncfg_confirm_may_arm` answered: the document a revert
 * will go back to, which is **not** the one that was just applied.
 *
 * Fills `event` with `confirm_armed` and returns 1. 0 with a sentence where
 * the window could not be written, and `event` is then untouched -- see
 * `ncfg_confirm_write_window` for why this refuses where the Rust logs.
 */
int ncfg_confirm_arm(const ncfg_daemon_state_t *state, uint32_t window_seconds,
    const ncfg_document_t *last_good, ncfg_proto_event_t *event, char *err, size_t err_size);

/*
 * Keep the change: close the window, drop what it covered, and record what
 * stood as the configuration a future revert falls back to.
 *
 * **`applied` is the document the window covered, and it is an argument for a
 * reason.** The Rust reads the daemon's *current* desired state here, which a
 * reload inside the window may have replaced with an edit that was deferred
 * and never applied -- so confirming can record as last-good a configuration
 * the machine has never been in, and the next window's revert then takes the
 * machine somewhere it has never been. The same hazard is recognised and
 * handled two functions down, where the hash a revert blacklists comes from
 * the armed record rather than from `desired`. Passing it in is what lets a
 * caller be right about it.
 *
 * `armed` may be NULL, and is emptied where it is not. 0 with a sentence where
 * no window is open, which is an answer to send the caller rather than a
 * failure.
 */
int ncfg_confirm_keep(ncfg_daemon_state_t *state, ncfg_confirm_armed_t *armed,
    ncfg_document_t *applied, ncfg_proto_event_t *event, char *err, size_t err_size);

/*
 * Put the last-good configuration back.
 *
 * **Two steps, and both are needed.** The declared inverses of what was
 * applied run first, newest first, because an action knows how to undo itself
 * in a way a re-plan cannot work out afterwards: a re-plan compares the machine
 * against a document, so it can only take back what that document *disagrees*
 * with. Measured, on a window that moved an address, a route and the MTU, with
 * the document restore alone as the control:
 *
 *     document restore only   addr restored   route restored   mtu 1400
 *     declared inverses       addr restored   route restored   mtu 1500
 *
 * The MTU is the case and it is the general shape rather than one field: the
 * last-good document states no MTU for that device, so 1400 agrees with it as
 * well as 1500 does and the re-plan has nothing to say -- while `link.set_mtu`
 * declared an inverse carrying the value it replaced. The machine was left one
 * revert away from the configuration the operator thought they had returned to.
 *
 * Then the desired state becomes the last-good document and a plan is built and
 * applied against it. That is the safety net rather than a duplicate: it
 * converges from wherever the machine actually is -- including from a
 * half-applied plan that stopped at a failure, and from a restart, which loses
 * the inverses entirely. If the inverses were complete it finds nothing to do.
 *
 * **What was rejected is remembered by identity**, so a reload of the *same*
 * configuration is refused and a genuinely edited one is not -- and it is the
 * hash the window covered rather than what is on disk now. An operator editing
 * twice inside one window leaves `desired` holding an edit that was deferred
 * and never applied; blacklisting that one refuses the operator's newest
 * configuration for something it never did. Where `armed` is NULL -- a
 * restarted daemon, which has lost the record -- `desired` is the fallback,
 * which is the old behaviour.
 *
 * `reason` is what the log line says the revert was for. Fills `event` with
 * `confirm_resolved` and returns 1. 0 with a sentence where no window is open,
 * or where the last-good document is unreadable -- in which case the window is
 * closed anyway, since a window nothing can resolve is a timer that never
 * stops.
 *
 * Nothing here needs the network: the inverses are in memory, the target
 * document is on disk, and the machine's state comes from the observe seam.
 */
int ncfg_confirm_revert(ncfg_daemon_state_t *state, ncfg_confirm_armed_t *armed,
    const ncfg_executor_t *executor, const char *reason, ncfg_proto_event_t *event, char *err,
    size_t err_size);

/*
 * What to do about a window found at startup.
 *
 * A daemon that died inside a window cannot have received a confirmation, so
 * the window is resolved by reverting whether or not the deadline has passed.
 * The alternative -- honouring the remaining time -- assumes the operator is
 * still there and still able to reach a socket that has been gone for however
 * long the daemon was down, which is exactly the assumption commit-confirm
 * exists because you cannot make.
 *
 * `*resolved` says whether there was a window at all, which is the ordinary
 * answer and not a failure; `event` is filled only when there was one. 0 with a
 * sentence where a window was found and the revert refused.
 */
int ncfg_confirm_resolve_on_startup(ncfg_daemon_state_t *state, ncfg_confirm_armed_t *armed,
    const ncfg_executor_t *executor, int *resolved, ncfg_proto_event_t *event, char *err,
    size_t err_size);

/* --------------------------------------------------------- the resolv guard */

/*
 * Removing what keeps taking `/etc/resolv.conf` back.
 *
 * 0165 made netcfgd notice a foreign write and put its own file back, which is
 * enough to win every round. What it does not do is stop the rounds: a writer
 * that rewrites the file every few seconds leaves the machine's resolver
 * flapping between two answers, and a name looked up in the wrong second gets
 * the wrong server.
 *
 * **This is the last resort and it is deliberately hard to reach.** It fires
 * only where netcfgd was told to own the file outright, and only after the file
 * has been taken away and put back several times in a row -- so a single write
 * during boot, which is ordinary, never reaches it.
 *
 * **It cannot tell who wrote the file, and the consequence is blunt.** There is
 * no way to ask the kernel which process last wrote a path -- `fanotify` could
 * report it and needs `CAP_SYS_ADMIN`, which netcfgd does not take. So what
 * this actually does is signal **every** known resolver-writing program netcfgd
 * did not start, not the one that is interfering. An idle `dhclient` that has
 * written nothing is terminated alongside the one that will not stop.
 *
 * That is defensible and it is not what the instruction sounds like, so it is
 * written here rather than discovered: on a machine where netcfgd has been told
 * to own `resolv.conf`, a foreign DHCP client that is running *will* write that
 * file when its lease renews, so the distinction between "is interfering" and
 * "is going to" is thinner than it looks. It is still a bystander at the moment
 * it is killed.
 *
 * **A supervised process is reported and not signalled.** Killing
 * `systemd-resolved` buys seconds: its unit carries `Restart=`, so the
 * supervisor puts it straight back and netcfgd would be fighting something that
 * cannot lose. The answer there is `Conflicts=` in a unit, and saying so is
 * worth more than a signal that achieves nothing.
 */

/*
 * How many reclaims in a row before netcfgd stops merely rewriting.
 *
 * Three rather than one, because one is ordinary. A DHCP client that took a
 * lease, a hook that ran, an operator with an editor -- each writes the file
 * once, netcfgd puts its own back, and nothing else should happen. Something
 * that has done it three times running is not passing through.
 *
 * **The counting is the loop's and not this module's**, in the Rust as here:
 * only the caller knows that a write was a *reclaim* -- a pass that had to put
 * back something netcfgd had already delivered -- and that the count means
 * "in a row" rather than "ever".
 */
#define NCFG_RESOLV_PATIENCE 3

/*
 * How many of netcfgd's own pids the sweep can hold.
 *
 * **Overflowing it stops the sweep, which is the opposite of what
 * `NCFG_PEER_GROUPS_MAX` does, and the two are right for the same reason.** A
 * membership that did not fit denies, so dropping one there is safe; a pid of
 * netcfgd's own that did not fit would make its own DHCP client look foreign,
 * and terminating the client holding this machine's lease is the worst outcome
 * available. So a set that does not fit signals nobody and says so.
 */
#define NCFG_RESOLV_OURS_MAX 256

/* How many candidate writers one sweep looks at. Generous: the whole list is
 * six program names, and a machine running more than this many copies of them
 * has a problem netcfgd is not going to fix. */
#define NCFG_RESOLV_CANDIDATES_MAX 64

/*
 * Programs known to write `/etc/resolv.conf`, and how many there are.
 *
 * **`/proc/<pid>/comm` is truncated to 15 characters**, which is why
 * `systemd-resolved` is spelled `systemd-resolve` in the list. A name one
 * character too long never matches, and the sweep would report nothing while
 * looking like it had looked -- the vacuous pass in its most literal form.
 * `confirm_test.c` measures every name against `NCFG_PROGRAM_MAX` so that a
 * seventh added later cannot be silently too long.
 *
 * `dhcpcd` is on the list and netcfgd starts its own, which is exactly why the
 * pids netcfgd recorded starting are excluded before anything is signalled.
 */
const char *const *ncfg_resolv_writers(size_t *count_out);

/*
 * Every pid netcfgd recorded starting, so none of them is a target.
 *
 * The backends write `<run>/<kind>/<iface>.pid`, one directory down. A file
 * that cannot be read or does not hold a number is skipped rather than guessed
 * at: the cost of missing one is signalling something netcfgd owns, so the
 * reading is deliberately strict. netcfgd's own pid is first -- it is not
 * called any of the names in the list, but a future rename should not be able
 * to make it kill itself.
 *
 * Answers how many there are, which may be more than `out_max`; the caller is
 * expected to refuse to sweep when it is. Writes the lowest `out_max` of them.
 */
size_t ncfg_resolv_ours(const char *run_dir, pid_t *out, size_t out_max);

/*
 * The machine a sweep asks about processes and signals.
 *
 * **A seam, and this is the module that most needs one.** Every other question
 * here is about a file; this one ends with `SIGTERM` to a process id, and the
 * daemon under test is running on the machine the tests are built on. The Rust
 * has no unit tests for its sweep at all -- it has a live script instead -- and
 * the reason is visible in the shape: the decision and the signal are the same
 * function. Here a test hands over a machine it made up, and the four exclusions
 * are checked without a process being signalled.
 *
 * `ncfg_resolv_machine_default` answers the real one. There is **no default in
 * the struct and none inside the sweep**, for the reason the server's socket
 * path has none: whoever sweeps says what they are sweeping.
 */
typedef struct {
	/* Whatever the implementation keeps. Never touched by this module. */
	void *state;
	/* Every process running one of the writer names, lowest pid first.
	 * Answers how many there are, as `ncfg_process_pids_of_programs` does. */
	size_t (*candidates)(void *state, ncfg_process_ref_t *out, size_t out_max);
	/* Whether this pid is in netcfgd's own service: the positive
	 * identification of children netcfgd has no pid file for. */
	int (*in_our_service)(void *state, pid_t pid);
	/* Whether it is in this network namespace. A daemon in another one is not
	 * configuring netcfgd's interfaces, so it cannot be interfering. */
	int (*shares_network_namespace)(void *state, pid_t pid);
	/* Whether *another* service manager holds it up, which is not the same as
	 * any service manager: everything netcfgd starts inherits netcfgd's own
	 * cgroup (0198). */
	int (*is_service_supervised)(void *state, pid_t pid);
	/* Ask it to stop. 1, or 0 with a sentence. */
	int (*terminate)(void *state, pid_t pid, char *err, size_t err_size);
} ncfg_resolv_machine_t;

/* The real machine: `/proc`, this process' cgroup and namespace, and
 * `SIGTERM`. */
ncfg_resolv_machine_t ncfg_resolv_machine_default(void);

/*
 * Signal whatever is taking the file back, and say what was left alone.
 *
 * Answers how many processes were signalled, so the caller can say whether the
 * sweep did anything rather than inferring it. A NULL machine, or one missing
 * any of its five calls, signals nobody: this is the one place in the library
 * where doing nothing on a malformed argument is the point rather than the
 * fallback.
 */
size_t ncfg_resolv_sweep(const char *run_dir, const ncfg_resolv_machine_t *machine);

/* ---------------------------------------------------------- the wifi half */

/*
 * `wifi.rs`: the wireless requests, and the supplicant behind them.
 *
 * **Every call here opens a control socket, uses it and drops it.** Decision
 * 0015 says the supplicant holds no state, and a daemon keeping a long-lived
 * connection to it would start caching what it last saw. A datagram socket and
 * a `PING` cost a round trip on a local socket, which is nothing next to the
 * scan they precede.
 *
 * **A caller in the `wifi` tier can join a network the configuration already
 * describes, and nothing else.** Nothing below can create one -- `wifi_add`
 * writes a `network` block and is `admin` -- so the tier cannot be talked into
 * writing config (0013).
 *
 * WHY THESE FILL A BUFFER RATHER THAN RETURNING A RESPONSE
 *   The Rust returns `Response`, an enum with an `Error` arm, so a refusal and
 *   an answer come back the same way. Here the module already has a way to say
 *   both: **1 with one JSON object in `out`, or 0 with a sentence in `err`**,
 *   which is `ncfg_daemon_answer_fn`'s contract -- "the server answers `error`
 *   with that sentence, which is still an answer". So every `Response::error`
 *   in `wifi.rs` is a 0 here and the sentence is unchanged, and each of these
 *   is usable as the body of a handler without a translation step in between.
 *
 *   The encoders are here for `proto.h`'s reason: it decodes every response
 *   and encodes none, because an encoder belongs beside the request that
 *   produces it.
 *
 * WHERE THE PATHS COME FROM
 *   `ncfg_wifi_where_t`, passed by the caller, for the reason
 *   `ncfg_authz_roots_t` is passed: **the real netcfgd runs on the machine
 *   these tests are built on and its wifi is real**. Nothing here falls back
 *   to `/run/wpa_supplicant`, to `/sys/class/net` or to `/run/netcfgd`, and
 *   there is no default to reach for by mistake.
 *
 * THE RFKILL SWITCH IS LOOKED UP RATHER THAN PASSED
 *   The Rust hands `scan` and `status` an `Option<&ObservedRfkill>` that both
 *   call sites build the same way -- `observed.link(interface).rfkill`. Here
 *   the observation is passed and the lookup happens once, inside: a fact two
 *   callers each dig out of the same structure is a fact one of them will
 *   eventually dig out differently.
 */

/*
 * Where the wifi half looks. **No field has a default and none may be NULL.**
 *
 * `ctrl_dir` is `wpa_supplicant`'s control directory, `class_net` is where the
 * kernel publishes per-interface attributes, and `run_dir` is netcfgd's own
 * runtime directory -- which holds both the supplicant pid files and hostapd's
 * control sockets.
 */
typedef struct {
	const char *ctrl_dir;
	const char *class_net;
	const char *run_dir;
} ncfg_wifi_where_t;

/*
 * Refuse a device the configuration points at a supplicant netcfgd cannot
 * drive.
 *
 * 0014: asking for `iwd` is refused **by name** rather than quietly served by
 * `wpa_supplicant`. Substituting a different supplicant would produce
 * different roaming behaviour than the config asked for, which is exactly the
 * sort of thing nobody thinks to check.
 *
 * 1 for a device netcfgd can drive, for one the document says nothing about,
 * and where there is no document at all.
 */
int ncfg_wifi_check_backend(const ncfg_document_t *document, const char *interface, char *err,
    size_t err_size);

/*
 * Which configured network an association is on.
 *
 * By SSID, and by BSSID for a network that has no SSID to match on -- one that
 * names access points instead and learns the name from them. Without the
 * second, exactly the networks whose whole point is being identified by
 * address would show as unconfigured.
 *
 * **A block that names this access point answers first** (0239). Taking the
 * first block matching on *either* rule meant two blocks sharing an SSID and
 * pinned to different access points -- which compiles with no diagnostic --
 * were both answered with whichever sorted earlier, so the station on the
 * second was reported as being on the first and took the first one's `metric`.
 *
 * A block that states no SSID is matched on its addresses alone; one that
 * states an SSID must agree on both, so a listed address that has moved to a
 * different network is not answered with the block that used to name it.
 *
 * **This is `netcfgd_model::wifi::network_for` and it belongs in the model**,
 * which is where the Rust keeps it and says why: the socket answers "which
 * network is this radio on?" for a client and the observation answers it for
 * the planner, and two copies could disagree about a route metric. It is here
 * because this port has only the first caller so far. The second one takes
 * this rather than writing its own, and moves it down when it lands.
 *
 * Borrowed from `networks`, or NULL.
 */
const ncfg_wifi_network_t *ncfg_wifi_network_for(const ncfg_wifi_network_t *networks,
    size_t count, const ncfg_ssid_t *ssid, const char *bssid);

/*
 * Why there is no supplicant on an interface, in words that say what to do.
 *
 * **The control socket's own message cannot answer this and should not try.**
 * It says "no control socket at ...: is `wpa_supplicant` running?", which is
 * true, unhelpful, and points at the wrong program: the question is not
 * whether somebody started a supplicant, it is why *netcfgd* did not. Only the
 * document knows, and the document is here.
 *
 * The case this was written for: a machine with no `device` block at all,
 * where scanning worked until `NetworkManager` was stopped. NM adds the
 * interface to the system `wpa_supplicant`, which creates the socket, so
 * netcfgd was scanning through a supplicant it had not started and had no
 * opinion about.
 *
 * **The question is who bound the socket, not whether it answers.** The first
 * fix asked whether the socket replied and so said nothing in exactly the
 * reported case: NetworkManager drives its supplicant over D-Bus and it does
 * not reply on the control interface, so the socket exists and stays mute.
 *
 * 1 where there is a diagnosis, with it in `out`; 0 where the caller's own
 * message is the right one -- an interface that is not a radio at all, and a
 * radio netcfgd has simply not got to yet. `out` is `NCFG_ERROR_MAX` or more.
 */
int ncfg_wifi_why_no_supplicant(const ncfg_wifi_where_t *where, const ncfg_document_t *document,
    const char *interface, char *out, size_t out_size);

/*
 * The drop-in a radio's activation is filed under, and what goes in it.
 *
 * **These are `netcfgd_host::config`'s, and they land here only because that
 * module's port does not carry them yet.** Two commands write this block --
 * `ncfg wifi activate` through the daemon and `ncfg wifi add` locally on a
 * machine where nothing is listening -- so when the CLI half arrives it calls
 * these rather than growing a second copy, and both move to `config.h`
 * together.
 *
 * One file per radio, named for it, so activating a second radio does not
 * rewrite the first one's and `ncfg config rm` can undo it by a name somebody
 * can guess.
 *
 * **Two blocks, and the second is not optional.** The first draft wrote only
 * the `device` block, on the reasoning that it is the smallest thing that says
 * netcfgd manages the radio. It plans nothing at all: the planner walks the
 * interfaces, so a device nothing has an `interface` block for is never
 * visited, and activation reported success for a file that changed no
 * behaviour. The empty `dns { }` is load-bearing for the same kind of reason
 * -- a lease's nameservers are offered to an interface and taken only where
 * one asks -- and `daemon_wifi_test.c` asserts both outcomes by compiling what
 * this writes and asking the planner, rather than by comparing the text.
 */
#define NCFG_WIFI_DROP_IN_MAX 64
int ncfg_wifi_radio_drop_in(const char *interface, char *out, size_t out_size, char *err,
    size_t err_size);
int ncfg_wifi_radio_blocks(const char *interface, ncfg_buf_t *out, char *err, size_t err_size);

/*
 * The radios this machine has, and what netcfgd is doing about each.
 *
 * **From the kernel, not from the document.** A list built out of `device`
 * blocks would show only the radios already taken on, and this list exists so
 * that somebody can take one on -- it has to name the ones netcfgd is not
 * managing, because those are the interesting ones.
 *
 * `supplicant` is asked separately from `activated` because the gap between
 * them is what a person needs to see. Activated with nothing answering is a
 * fault; not activated with something answering is another manager holding
 * this radio, which netcfgd declines to take rather than fighting over.
 */
int ncfg_wifi_radios(const ncfg_wifi_where_t *where, const ncfg_document_t *document,
    const ncfg_observed_t *observed, ncfg_buf_t *out, char *err, size_t err_size);

/*
 * Start the backends one interface now wants, before answering.
 *
 * **A seam, and it is the half that makes activation truthful.** netcfgd
 * applies nothing on a configuration change by itself -- `on_drift` defaults
 * to `report` -- so activation used to leave a correct plan that nothing had
 * run, and the operator got "cannot reach the supplicant" from the very next
 * scan. Reported as "the buttons don't work properly", which is what a switch
 * that changes a file and nothing else looks like.
 *
 * **Not the whole interface plan, and the reason is a failure.** It was the
 * whole plan for a day; addressing is in that plan, and activating a radio ran
 * `dhcpcd`, which cannot get a lease on a link with nothing behind it, so the
 * activation *failed* -- handing netcfgd a radio was refused because DHCP had
 * not finished on it. So an implementation restricts the plan to this
 * interface and to **starting a supplicant**: `BackendStart` covers the DHCP
 * client too, and filtering on the op alone still ran `dhcpcd`.
 *
 * It is a seam rather than a call because the plan restriction and the
 * reconcile loop's executor are not in this port yet, and because a test that
 * did this for real would start a supplicant on the developer's own radio.
 * **Nothing to do is success**: the radio may already be up from a previous
 * activation, and reporting that as a failure would make a switch complain
 * about being already on.
 */
typedef int (*ncfg_wifi_apply_fn)(void *context, const char *interface, char *err,
    size_t err_size);

/*
 * Take a radio on, or hand it back.
 *
 * Named rather than silent for an interface that is not a radio: activating
 * `eth0` is a mistake worth a sentence, and the alternative is a `device`
 * block that quietly does nothing. The answer is whether the *kernel* calls it
 * a radio, read from the observation the state already holds.
 *
 * Activation writes the drop-in, reloads, and then **applies**, because a
 * client that scans the moment it is told the radio is netcfgd's must not scan
 * a radio with no supplicant. Handing one back writes nothing further: the
 * reconcile loop takes the backend down on its own pass, and a synchronous
 * stop here would disconnect an operator who had only meant to stop managing
 * the interface.
 *
 * `apply` is required when activating and is refused when absent, rather than
 * skipped -- a caller with no way to apply would be reproducing the defect
 * above, silently.
 */
int ncfg_wifi_set_radio(ncfg_daemon_state_t *state, const char *interface, int activate,
    ncfg_wifi_apply_fn apply, void *apply_context, ncfg_buf_t *out, char *err, size_t err_size);

/*
 * `SCAN`, then `SCAN_RESULTS`.
 *
 * **Attached before `SCAN` is sent, and that order is the whole of it** (0194).
 * The completion event only reaches connections that asked for events, and
 * asking afterwards would race the scan finishing on a radio with little to
 * look at. A failure to attach is not a failure to scan: what is lost is the
 * wait, so the old behaviour returns -- results one scan out of date, said in
 * `stale` rather than swallowed.
 *
 * **A switched-off radio cannot scan, so it is not asked to.** Without that
 * check the scan is sent, the supplicant answers with a failure or nothing at
 * all, and the report says the results are stale "because the supplicant could
 * not scan (ret=-100)" -- a translation of ENETDOWN rather than the fact that
 * somebody pressed the button. The cached results are still returned, because
 * they are what the radio last saw.
 */
int ncfg_wifi_scan(const ncfg_wifi_where_t *where, const ncfg_document_t *document,
    const ncfg_observed_t *observed, const char *interface, ncfg_buf_t *out, char *err,
    size_t err_size);

/*
 * `STATUS`, resolved back to the document where possible.
 *
 * The kill switch is asked about here because **this is the command somebody
 * runs when wifi is not working**, and a kill switch is one keystroke away on
 * any laptop (0199).
 *
 * `not_trying` comes from `LIST_NETWORKS`, which is the only place the
 * difference lives: `STATUS` describes the one association an interface has,
 * so an interface with none reads `SCANNING` whether the supplicant is
 * scanning hopefully or has given up on every network it was given. A failure
 * to read it is not a failure of the status.
 */
int ncfg_wifi_status(const ncfg_wifi_where_t *where, const ncfg_document_t *document,
    const ncfg_observed_t *observed, const char *interface, ncfg_buf_t *out, char *err,
    size_t err_size);

/*
 * Join a network the configuration already describes.
 *
 * The lookup is what makes this mean "join one of these" rather than "join
 * anything", and the refusal says so plainly or it reads as the network being
 * missing rather than the name being unknown.
 *
 * `SELECT_NETWORK` rather than `ENABLE_NETWORK`: it disables the others, which
 * is what "join this one" means. **OK to that command means the supplicant
 * took it, not that anything joined** -- association, the key exchange and any
 * EAP handshake all happen after it, and every way they fail arrives as an
 * event (0197). So this attaches first and waits for the outcome.
 *
 * `secrets_dir` and `certs_dir` are the resolver's two halves and neither has
 * a default here. `certs_dir` is where a stored certificate is materialised
 * for the supplicant to open; a resolver that could read secrets but not write
 * a certificate would join the same network from the command line and refuse
 * it from a connect.
 */
int ncfg_wifi_connect(const ncfg_wifi_where_t *where, const ncfg_document_t *document,
    const char *secrets_dir, const char *certs_dir, const char *interface, const char *wanted,
    ncfg_buf_t *out, char *err, size_t err_size);

/*
 * Leave the current network without forgetting it.
 *
 * `DISCONNECT`, not `REMOVE_NETWORK`: the network stays configured and stays
 * in the supplicant, so reconnecting does not need the credential resolved
 * again -- and the next reconcile does not see a network missing and put it
 * back, which would undo the disconnect a second later.
 */
int ncfg_wifi_disconnect(const ncfg_wifi_where_t *where, const ncfg_document_t *document,
    const char *interface, ncfg_buf_t *out, char *err, size_t err_size);

/*
 * Who is associated with an access point this machine runs.
 *
 * The `access_point` block is found first, and its absence is the answer
 * rather than an error about a socket: an interface with no access point on it
 * has no stations, and saying "no control socket" would send an operator
 * looking for a broken hostapd that was never meant to exist.
 *
 * Whether the ACL names a station is answered **from the document rather than
 * from hostapd**, deliberately: the document is the authority, and the
 * difference between the two is the thing worth seeing -- a station connected
 * *and* on a deny list means hostapd has not been told about a list that
 * changed.
 *
 * The walk is `STA-FIRST` then `STA-NEXT <address>`, over hostapd's control
 * socket, which is `wpa_ctrl` and so is the supplicant module's client.
 * `hostapd.h` says that round trip was the half it did not carry; it is here
 * because this is its only caller, and it moves down beside
 * `ncfg_hostapd_parse_station` when a second one arrives. **Bounded rather
 * than a loop**: hostapd walks its own list and terminates, but this is one
 * daemon reading another's answers and a reply echoing an address back
 * unchanged would spin for ever.
 */
int ncfg_wifi_ap_stations(const ncfg_wifi_where_t *where, const ncfg_document_t *document,
    const char *interface, ncfg_buf_t *out, char *err, size_t err_size);

/* ------------------------------------------------ adding a network (0117) */

/* What protects a network this daemon is asked to write down. */
typedef enum {
	NCFG_WIFI_SECURITY_OPEN = 0,
	NCFG_WIFI_SECURITY_PSK,
	NCFG_WIFI_SECURITY_EAP
} ncfg_wifi_security_t;

/*
 * The `network` block a `wifi_add` asks for, validated.
 *
 * **Every string is borrowed and lives only for the installer call** -- some
 * point into the request and some into the caller's own stack -- so an
 * implementation copies anything it keeps. There is nothing to free.
 *
 * `ca_cert` and `client_cert` are already in their `@secret:<name>` form,
 * which is **the one place the socket's names turn into configuration and the
 * only form they can take**: a request carries a *name*, the configuration
 * written from it says `@secret:<name>`, and the compiler lowers that to a
 * stored source and never to a path. A caller cannot reach the path form from
 * here because there is nothing to write it in.
 */
typedef struct {
	const char          *id;
	ncfg_ssid_t          ssid;
	int                  hidden;
	ncfg_optint_t        metric;
	ncfg_wifi_security_t security;
	/* `psk`: the generation to pin, or NULL for both. */
	const char          *proto;
	/* `eap`: peap, ttls, tls or pwd. NULL for the other two. */
	const char          *method;
	const char          *identity;
	const char          *anonymous_identity;
	const char          *phase2;
	const char          *ca_cert;
	const char          *client_cert;
} ncfg_wifi_profile_t;

/*
 * Write the block and store the credential.
 *
 * **A seam, because `netcfgd_host::wifi_profile` is not in this port yet.**
 * The write, the credential, the 0700 directory and the compile-it-back check
 * are that module's and are shared with `ncfg wifi add` -- two implementations
 * of "what a `network` block looks like" is the drift this tree keeps finding
 * -- so this port refuses to grow a second one and names the gap instead.
 *
 * **The credential is passed by count and is never copied here.** A
 * `ncfg_proto_str_t` points into the decoded line, so handing over the bytes
 * and the length means the passphrase exists in exactly one place for exactly
 * as long as the line does. NULL for a network that carries none; a `tls`
 * network's private key travels this way too, which is why the length is not
 * assumed to be small.
 */
typedef int (*ncfg_wifi_install_fn)(void *context, const ncfg_wifi_profile_t *profile,
    const char *credential, size_t credential_length, char *err, size_t err_size);

/*
 * Add a wireless network to the configuration, for a client that cannot write
 * the file itself (0117).
 *
 * The request carries typed fields and never config text, so the daemon
 * renders the block and **this function's shape is what bounds the
 * privilege**: there is no field here that could name a hook, a path or a
 * `run_as`, and a hook's `run_as` defaults to root.
 *
 * Named `configure_network` in the Rust and not `add_network`, because
 * `ncfg_supplicant_add_network` already means something different one layer
 * down -- telling a running supplicant about a network. This writes a config
 * file.
 *
 * What it refuses, before anything is written: an ssid that is not lowercase
 * hex of 0 to 32 octets; an ssid that is not text with no `id` to name it by,
 * since a label is a filename and this will not invent one -- and **an ssid or
 * an `id` carrying a NUL**, which the Rust refuses a layer down in `usable_id`
 * as a control character and which here has to be refused before the value
 * exists, because a counted string with a NUL in it cannot become a C string
 * without becoming a shorter one nobody asked for; an `id` a
 * `network` block already uses, because a second block with the same label is
 * a compile error that would break every interface on the machine to add one
 * network; a `proto` beside an `eap` block, since `proto` pins the generation
 * protecting a passphrase and an enterprise network negotiates its own; a
 * `proto` with no passphrase; a `proto` that is neither `wpa2` nor `wpa3`; an
 * EAP method netcfgd does not implement, named rather than silently accepted
 * because the supplicant would refuse the network later and say so only in its
 * log; and an enterprise network with no `identity`.
 *
 * **A `metric` outside `u32` is refused here**, which the Rust does at the
 * decode: its request type says `Option<u32>` and serde will not build one out
 * of range, while `ncfg_proto_int_t` carries whatever integer arrived.
 */
int ncfg_wifi_configure_network(const ncfg_document_t *document,
    const ncfg_proto_wifi_add_t *wanted, ncfg_wifi_install_fn install, void *install_context,
    ncfg_buf_t *out, char *err, size_t err_size);

/* ---------------------------------------------------- the reconcile loop */

/*
 * `lib.rs`: the pass that drives every module above it.
 *
 * WHAT IS SPLIT FROM WHAT, AND WHY THAT IS THE WHOLE DESIGN
 *   A loop that owns a `poll`, a clock, an inotify descriptor and a socket is
 *   a loop nothing can test. The Rust says so about itself in one place --
 *   `a_window_is_requested` is split out of `defers_to_a_window` because the
 *   tuples arriving at the loop carry a `SyncSender`, and "a predicate that
 *   cannot be exercised without building one is a predicate nothing
 *   exercises". That split is made once there and everywhere here.
 *
 *   So this module is two files. `reconcile.c` is what the loop **decides**:
 *   every call in it takes values and answers one, it opens nothing, writes
 *   nothing and runs nothing, and `reconcile_test.c` walks its cases rather
 *   than sampling them. `reconcile_pass.c` is the **order** those decisions
 *   are carried out in, and it decides nothing: everything it reaches the
 *   world through is a seam in `ncfg_reconcile_world_t`, so the orderings the
 *   Rust's comments call load-bearing -- the drift hooks before the reconcile,
 *   the portal checks after them, the contended radio given back before the
 *   reconcile rather than inside it -- are a list a test reads back rather
 *   than a claim a reader has to take on trust.
 *
 * WHAT IS DELIBERATELY NOT HERE
 *   **The threads.** The Rust has four watchers and a one-shot timer feeding
 *   one `mpsc`; what reaches this module is their result. A burst is folded
 *   into `ncfg_reconcile_wake_t` by `ncfg_reconcile_collapse`, and whoever
 *   owns the descriptors goes on owning them.
 *
 *   **Serving the requests.** `ncfg_daemon_answer_fn` is that seam and
 *   already says what a handler owes. The loop is handed the requests that
 *   are waiting because two of its decisions turn on them -- a pending window
 *   defers the reconcile, an explicit apply releases the hold -- and it
 *   answers none of them.
 *
 *   **Giving a radio back, and asking a URL a question.** Both reach the
 *   machine this is built on -- one stops a backend, the other execs this
 *   process' own image -- so each is a seam with a real implementation named
 *   beside it. A build with neither observes, reports drift and reconciles
 *   exactly as before; what it does not do is give a radio back or ask.
 */

/* ------------------------------------------------------------ what woke it */

/*
 * One thing the loop was told, before the burst is collapsed.
 *
 * `roamed` and a client's request are not in here, and that is the rule
 * rather than an omission: **two roams are two events**, and a station that
 * moved twice moved twice. They travel as lists beside the wake.
 */
typedef enum {
	/* Netlink said the machine moved. */
	NCFG_WOKE_KERNEL = 0,
	/* Something wrote in the configuration directory. Not "the configuration
	 * changed" -- see `ncfg_reconcile_report_t::config_is_new`. */
	NCFG_WOKE_CONFIG,
	/* A commit-confirm timer fired. It carries no identity, so it is a
	 * prompt to ask the window rather than an instruction to revert. */
	NCFG_WOKE_CONFIRM_EXPIRED,
	/*
	 * Nothing arrived in time.
	 *
	 * **The backstop, which the Rust discarded for a while.** It is what
	 * makes this a verification loop rather than an apply: the plan computed
	 * on a tick *is* the verification and its actions are the fix, so a
	 * machine that drifted in a way netlink does not announce costs seconds
	 * rather than for ever. A tick that finds nothing outstanding costs one
	 * observation and stops.
	 */
	NCFG_WOKE_TICK
} ncfg_woke_t;

/*
 * A burst of those, collapsed.
 *
 * Bringing an interface up produces a run of netlink messages, and re-reading
 * once per message would make the daemon's cost scale with the kernel's
 * chattiness. Declare one as `= {0}` per pass.
 */
typedef struct {
	int kernel_changed;
	int config_changed;
	int confirm_expired;
	int ticked;
} ncfg_reconcile_wake_t;

/* Fold one command in. Passing the same one twice is the point. */
void ncfg_reconcile_collapse(ncfg_reconcile_wake_t *wake, ncfg_woke_t woke);

/*
 * Whether this pass has any reason to look at the machine.
 *
 * `probe_changed` is not part of the wake because it is not something the
 * loop was told: it is what running the due probes turned out to answer, and
 * a *changed* verdict is movement for the same reason a carrier change is
 * (0119). A probe that has agreed with itself for an hour costs the program
 * it runs and nothing else.
 */
int ncfg_reconcile_looks(const ncfg_reconcile_wake_t *wake, int probe_changed);

/*
 * Whether this pass should ask the confirm window whether it closed.
 *
 * A named decision rather than an inline `||`, because the second half reads
 * like an accident and was absent (0234): **a tick must ask, not only the
 * timer's own message.** The Rust's `spawn_expiry_timer` discarded the result
 * of `spawn`, so a timer that could not start left the window open for ever
 * -- and this was the only thing that closed one, which turned the silent
 * failure of a safety mechanism into a change that never reverted.
 *
 * The timer stays, for the reason its own comment gives: a safety mechanism
 * that fires up to five seconds late is one whose window is not the length it
 * says. What the tick adds is that a *missing* timer costs seconds rather
 * than the window. Asking on every pass is free because the resolver asks the
 * window whether it has really expired, and a window with time left is not
 * one that closed.
 */
int ncfg_reconcile_should_resolve_window(int confirm_expired, int ticked);

/* One station that moved, on its way to the `roam` hooks. Both strings are
 * the caller's and live only for the pass. */
typedef struct {
	const char *interface;
	const char *bssid;
} ncfg_reconcile_roam_t;

/* ---------------------------------------------- what the waiting requests say */

/*
 * Does any pending request ask for a commit-confirm window?
 *
 * **The reconcile runs before the requests are served**, so an operator's
 * `ncfg apply --confirm-within 60` landing in the same burst as the write it
 * accompanies would otherwise be answered after the change had already been
 * applied -- and the window would then cover nothing, which is worse than no
 * window because the operator believes they have a way back.
 *
 * `--confirm-within 0` is how an operator says *no* window on a machine whose
 * configuration sets one (0094), so it is not a window and must not hold the
 * reconcile off.
 */
int ncfg_reconcile_window_requested(const ncfg_proto_request_t *requests, size_t count);

/*
 * Whether this batch is the operator taking their turn.
 *
 * `--no-apply-on-start` holds the acting until somebody applies deliberately,
 * so that the *first* apply after a boot is the one carrying a window -- it is
 * the one that can take the network away. An explicit apply is what the hold
 * was waiting for; nothing else releases it, because nothing else is the
 * operator saying go.
 */
int ncfg_reconcile_releases_hold(const ncfg_proto_request_t *requests, size_t count);

/*
 * Whether the loop should stand back and let a window cover this change.
 *
 * Two cases and they are different questions. A pending apply carrying a
 * window is the operator saying they want this change to be revertible, and
 * deferring costs one pass. An **open** window means a change is already
 * awaiting confirmation: reconciling over it would apply something the
 * operator has not accepted yet, on top of something they may be about to
 * reject, and the revert would then undo a state nobody ever chose.
 *
 * `window_open` is passed rather than read, which is this module's rule and
 * `ncfg_confirm_expired_at`'s: the file is the caller's to read and this is
 * the decision.
 */
int ncfg_reconcile_defers(int window_open, const ncfg_proto_request_t *requests, size_t count);

/* ------------------------------------------------------------------ drift */

/*
 * The drift policy in force for one interface.
 *
 * The interface's own where it states one, the document's default otherwise,
 * and `report` where there is no document at all -- which is the direction
 * that changes nothing on a machine netcfgd cannot compile a configuration
 * for.
 */
ncfg_drift_policy_t ncfg_reconcile_policy_for(const ncfg_document_t *document,
    const char *interface);

/*
 * Whether netcfgd may put the *host's* configuration back.
 *
 * Separate from the per-interface question because `resolv.conf` and the
 * hostname belong to no interface, so no per-interface policy can speak for
 * them. This is what an operator writing `global { on_drift = "reconcile" }`
 * is setting, and it is the half whose absence meant a foreign overwrite of
 * `resolv.conf` was never put back (0165).
 */
int ncfg_reconcile_host_wide(const ncfg_document_t *document);

/*
 * Whether this interface's drift is netcfgd's to put back.
 *
 * A predicate rather than the Rust's list of names, so that nothing has to
 * bound a list whose length is the operator's to choose -- and so that
 * `ncfg_reconcile_restrict` asks the question per action instead of searching
 * a vector it was handed.
 *
 * Two exceptions, and neither is drift. An interface with a `preference` is
 * always reconciled, because losing carrier is the configuration's own
 * meaning changing rather than something else moving the machine -- a laptop
 * that announces "your cable is out" while still routing down it is not the
 * feature anybody asked for. A **pending SIM cycle** is the same shape:
 * netcfgd decided the modem should be on another source and the only way to
 * act on that is to take the link down and up, so leaving it out of this
 * answer would have the cycle planned and then dropped, with the machine
 * sitting on a source nothing ever selected.
 */
int ncfg_reconcile_reconciles(const ncfg_document_t *document, const ncfg_sims_t *sims,
    const char *interface);

/*
 * Keep only the actions netcfgd may act on, and say what was dropped.
 *
 * Reconciling drift on one interface must not drag along a change to another
 * the operator has set to `report`. Filtering an ordered DAG can orphan a
 * dependency, so an action whose `depends_on` names something that was not
 * kept is dropped as well and named: applying it would run out of order, and
 * silently applying a subset that happens to work is how a reconciler becomes
 * unpredictable.
 *
 * `host_wide` decides the actions that belong to no interface, which the
 * per-interface filter could only ever drop (0165). The three commit ops name
 * no interface either and are deliberately not swept in by it.
 *
 * `dropped` takes one sentence per orphan, newline-terminated, and may be
 * NULL. It is an `ncfg_buf_t` for the reason every accumulation in this port
 * is one: a ceiling and a sticky failure, so a malformed day cannot buy an
 * allocation.
 *
 * **The warnings are not copied and the refusals are.** A plan copies the
 * "cannot be undone" warning in as each action is added, so carrying the
 * source's warning list across would say it twice; the restricted plan is
 * applied and never rendered, and what a client is shown is the full plan.
 * The refusals and the stranded credentials are copied, because restricting a
 * plan changes what will be *done* and not what is true about the
 * configuration.
 *
 * NULL with a sentence where memory ran out. The result borrows from the same
 * document the source plan does, so it must not outlive it, and
 * `ncfg_plan_free` releases it.
 */
ncfg_plan_t *ncfg_reconcile_restrict(const ncfg_plan_t *plan, const ncfg_document_t *document,
    const ncfg_sims_t *sims, int host_wide, ncfg_buf_t *dropped, char *err, size_t err_size);

/* The longest thing said about one piece of drift, and about what netcfgd is
 * doing with it. Sentences an operator reads, bounded for `NCFG_LOG_MAX`'s
 * reason: anything longer is a payload. */
#define NCFG_DRIFT_SUMMARY_MAX 200
#define NCFG_DRIFT_ACTION_MAX  128

/*
 * How many pieces of drift are kept, with `total` counting past it.
 *
 * `NCFG_DIAGS_MAX`'s bargain again: a machine fighting netcfgd over every
 * interface it has produces one of these per action, and a client that shows
 * "32 of 60" is showing more than one that shows sixty nobody scrolls
 * through. The Rust grows a `Vec` from whatever the plan holds.
 */
#define NCFG_DRIFT_MAX 32

/* One thing that has moved away from the configuration. */
typedef struct {
	/* Borrowed from the plan this was read out of, which outlives it. */
	const char *interface;
	/* `addr.add: addressing[0] is <absent> but should be 10.0.0.5/24`. */
	char        summary[NCFG_DRIFT_SUMMARY_MAX];
	/* `reconciling`, `reported only`, or what to do about a refusal. */
	char        action[NCFG_DRIFT_ACTION_MAX];
} ncfg_drift_t;

typedef struct {
	ncfg_drift_t at[NCFG_DRIFT_MAX];
	size_t       count;
	size_t       total;
} ncfg_drifts_t;

/*
 * Read the drift out of a plan.
 *
 * One entry per drifting interface -- the *first* action that names it, since
 * a second is the same fight -- plus one per refusal and one per stranded
 * credential. A refusal is worth saying out loud because it is exactly the
 * case where an operator is waiting for a change that is never going to
 * happen; a stranded credential is the stronger version of the same reason,
 * since nothing is waiting on that one at all.
 *
 * An interface whose policy is `ignore` produces nothing. Declare `out` as
 * `= {0}`; it owns nothing and there is nothing to free.
 */
void ncfg_reconcile_drift(const ncfg_plan_t *plan, const ncfg_document_t *document,
    ncfg_drifts_t *out);

/*
 * The same thing as a `drift` event, for a monitor stream.
 *
 * `out` borrows every string from `drift`, which must outlive it -- the event
 * is sent inside the pass that read it.
 */
void ncfg_drift_event(const ncfg_drift_t *drift, ncfg_proto_event_t *out);

/*
 * What a phase was last told about an interface, or NULL.
 *
 * Through the `/run` record the `carrier` and `lease` phases use, and through
 * that alone. It is what makes "fire on the change" possible for `drift` and
 * for `portal` without either keeping state of its own: the record is read
 * back by every observation, so an in-memory copy beside it would be a second
 * answer that can disagree (0084).
 */
const char *ncfg_reconcile_told(const ncfg_observed_t *observed, const char *interface,
    int phase);

/*
 * Whether the `drift` hooks should fire for this drift.
 *
 * Fires when drift **appears**, not while it persists. Under `report` the
 * drift is still there on the next netlink event and the one after it, so
 * firing on presence would run somebody else's script on every observation
 * for as long as the operator left it alone. What the script is told is what
 * changed rather than what netcfgd did about it, so a hook that has already
 * seen this drift stays quiet even if the policy moved underneath it.
 */
int ncfg_reconcile_tells(const char *last_told, const char *summary);

/* ---------------------------------------------------------- captive portal */

/*
 * **The asking is `portal.h`'s and only the record is here.** That module
 * carries the verdict, `ncfg_portal_is_routable`, and the child that does the
 * fetching; what this one decides is when to ask at all and what to write
 * down afterwards, which is the half that lives in the loop and the half the
 * Rust could only reach with a network behind a captive portal.
 */

/* `trying:6` and a NUL, with room to spare. */
#define NCFG_PORTAL_RECORD_MAX 16

/*
 * What the record under the `portal` phase is written as.
 *
 * Spelled here rather than in the source, because a test that spelled them
 * itself would go on passing the day one changed -- and because the record is
 * read back out of `/run` by the next pass, which makes these three words a
 * format rather than an implementation detail.
 */
#define NCFG_PORTAL_RECORD_DONE   "addressed"
#define NCFG_PORTAL_RECORD_BARE   "bare"
#define NCFG_PORTAL_RECORD_TRYING "trying:"

/*
 * How many times an inconclusive check is retried before it gives up.
 *
 * The retry exists because the probe runs before the reconcile that delivers
 * DNS, so a fresh join can fail to resolve for a pass or two through nothing
 * being wrong -- and DNS is exactly what a portal hijacks, so recording that
 * as "checked, and clear" meant the one network behind a portal and slow to
 * come up was the one netcfgd never told anybody about.
 *
 * The *bound* exists because the loop has a five-second backstop, and a
 * question asked for ever is a request to somebody else's server every five
 * seconds for as long as the machine sits on a network with no route. Six is
 * about thirty seconds of a quiet loop.
 */
#define NCFG_PORTAL_RECORD_ATTEMPTS 6

/* Whether to ask at all, and what to record when the answer is not wanted. */
typedef enum {
	/* Nothing to do: already answered for this joining, or already bare. */
	NCFG_PORTAL_STEP_NOTHING = 0,
	/* No address worth asking about; the record goes back to `bare`. The
	 * record holds the *state* rather than the verdict, because what this
	 * fires on is the transition and not what it turned out to mean. */
	NCFG_PORTAL_STEP_BARE,
	/* Ask. */
	NCFG_PORTAL_STEP_ASK
} ncfg_portal_step_t;

/*
 * Decide the step from what the interface looks like and what it was last
 * told.
 *
 * `*attempts_out` is the count read out of a `trying:N` record, and 0 for a
 * record that is absent or that this build does not recognise. It is written
 * whatever the answer is.
 */
ncfg_portal_step_t ncfg_portal_step(int addressed, const char *was, unsigned *attempts_out);

/* What to do with the answer that came back. */
typedef struct {
	/* What the record should say now: `addressed`, or `trying:N`. */
	char     record[NCFG_PORTAL_RECORD_MAX];
	/* Whether the `portal` hooks should run, which is a portal and nothing
	 * else. `Clear` is said to the log and to nobody else: a hook that ran on
	 * every successful join is a hook nobody keeps. */
	int      run_hooks;
	/* Whether this attempt was inconclusive and will be tried again. */
	int      retrying;
	/* Which attempt this was, for the warning that names it. */
	unsigned attempt;
} ncfg_portal_answer_t;

/*
 * Turn a verdict and the attempts so far into the next record.
 *
 * **An answer that was not an answer must not consume the transition**, which
 * is the whole of the retry; and the giving up is said once, loudly, rather
 * than kept quiet, because the operator asked for this network to be checked
 * and it was not.
 */
void ncfg_portal_answered(int verdict, unsigned attempts, ncfg_portal_answer_t *out);

/* ------------------------------------------------------- the resolv counting */

/*
 * Whether this pass had to put `/etc/resolv.conf` back.
 *
 * **Asked of the plan that is about to run rather than of the file**, because
 * this is the only place that knows the write is a *reclaim* -- a pass that
 * had to deliver again something netcfgd had already delivered. The executor
 * writing the file on a first apply is not interference.
 */
int ncfg_reconcile_reclaimed(const ncfg_plan_t *plan);

/*
 * Move the reclaim count, and say whether it is time to sweep.
 *
 * Reset on any drift pass that did not have to reclaim, so the count means
 * "in a row" rather than "ever": a machine where something rewrites the file
 * once an hour never reaches the threshold, which is the intent -- that is
 * somebody's cron, not a fight. Answering 1 starts the count again rather
 * than sweeping on every pass afterwards, because whatever was signalled
 * needs a moment to go and a sweep per tick would be its own storm.
 */
int ncfg_reconcile_sweeps(unsigned *reclaims, int reclaimed);

/* ---------------------------------------------------- arming for a change */

/* Whether a configuration change gets a window, and what refused it. */
typedef enum {
	NCFG_ARM_YES = 0,
	/*
	 * Not a configuration change.
	 *
	 * A drift reconcile is netcfgd putting back what something else changed.
	 * Arming there would revert netcfgd's own correction when nobody
	 * confirmed, the drift would be found again on the next pass, and the
	 * machine would oscillate -- spending half its time in the state the
	 * reconcile exists to leave. Nobody is waiting to confirm a correction
	 * they did not ask for (0157).
	 */
	NCFG_ARM_NOT_A_CHANGE,
	/* The document asks for no window, or asks for one of no seconds --
	 * which is two spellings of "no", one of which reverts the change. */
	NCFG_ARM_NO_WINDOW,
	/* A window is already open, or there is nothing to fall back to.
	 * `ncfg_confirm_may_arm` is what answered, and it said why. */
	NCFG_ARM_REFUSED,
	/*
	 * The last-good configuration is the empty placeholder.
	 *
	 * **A window whose fall-back is that is not a safety net, it is a
	 * scheduled outage.** `ncfg_reconcile_establish_last_good` writes an
	 * empty document before the first apply so that `--confirm-within` works
	 * from the very beginning, where "revert to nothing" really is the exact
	 * undo of a first apply -- an operator asked, is watching, and can
	 * confirm. Nobody asked for this one, and the placeholder outlives the
	 * moment it was written for, because the startup apply only replaces it
	 * where it had no failure at all. An operator then changing one field
	 * would arm a window whose revert removes *every* address, route and
	 * backend netcfgd has installed.
	 */
	NCFG_ARM_EMPTY_LAST_GOOD
} ncfg_arm_t;

/*
 * Whether to arm, given what the caller has already read.
 *
 * `window` is `ncfg_plan_confirm_window`'s answer, asked of the planner
 * rather than re-derived: the rule has three cases -- the caller's number, the
 * caller's zero meaning "no window despite the default", and the document's
 * own -- and a second copy beside this one is how the two would stop agreeing.
 *
 * `last_good` is what `ncfg_confirm_may_arm` answered, and NULL is its
 * refusal. Nothing here opens a file, which is what lets every one of the
 * five answers be a check.
 */
ncfg_arm_t ncfg_reconcile_arms(int config_is_new, ncfg_optint_t window,
    const ncfg_document_t *last_good);

/* What to say about an answer that was not yes. NULL for `NCFG_ARM_YES`, and
 * for a value outside the enum. */
const char *ncfg_reconcile_arm_why(ncfg_arm_t answer);

/*
 * Whether this document is the empty placeholder.
 *
 * By identity rather than by field, so that it cannot come to disagree with
 * `ncfg_document_new` about what a default is: both are hashed and the hashes
 * are compared. **Doubt answers yes**, which is the direction that refuses a
 * window rather than arming one whose revert undoes everything netcfgd has
 * done.
 */
int ncfg_reconcile_document_is_empty(const ncfg_document_t *document);

/* --------------------------------------------------------------- the pass */

/*
 * How a hook is run.
 *
 * **A seam because running one forks and execs**, and a test that drove the
 * real thing would run the developer's own scripts. `ncfg_reconcile_hook_run`
 * is the implementation that does it for real.
 *
 * `variable` and `value` are the second environment variable each of the
 * three event phases carries -- `NCFG_ACTION` for `drift`, `NCFG_BSSID` for
 * `roam`, `NCFG_URL` for `portal` -- and are NULL where a phase has none.
 * They are passed here rather than in `ncfg_hook_env_t` because that struct
 * carries four fixed members and is `apply.h`'s; the day it grows a general
 * pair, the default runner below is where the two lines go and nothing else
 * changes.
 */
typedef void (*ncfg_reconcile_hook_fn)(void *context, const ncfg_hook_ref_t *hook,
    const ncfg_hook_env_t *env, const char *variable, const char *value);

/*
 * Run it for real, through `ncfg_hook_run`.
 *
 * Never a veto at any of these three phases: the drift has happened, the
 * station has moved, the portal has answered, and there is nothing left to
 * stop. A failing script is a line in the log and nothing else.
 *
 * `context` is ignored, so this may be installed with none.
 */
void ncfg_reconcile_hook_run(void *context, const ncfg_hook_ref_t *hook,
    const ncfg_hook_env_t *env, const char *variable, const char *value);

/*
 * Ask for real, through `ncfg_portal_probe` and this process' own image.
 *
 * The daemon passes `NCFG_PORTAL_OWN_IMAGE` and the default expectation,
 * which is what `portal.h` says a caller in the daemon does. `context` is
 * ignored, so this may be installed with none. **Nothing under `tests/` calls
 * it**: it forks, execs and reaches the network.
 */
void ncfg_reconcile_portal_probe(void *context, const char *url, ncfg_portal_result_t *out);

/*
 * Everything the pass reaches the world through.
 *
 * Every member may be NULL and the pass says what a NULL one costs rather
 * than refusing: a build with no portal probe checks no URLs, one with no
 * hook runner runs no scripts, one with no executor observes and reports and
 * changes nothing. That is the same bargain `ncfg_resolv_machine_t` takes --
 * **doing nothing on a missing seam is the point rather than the fallback** --
 * and it is what makes a test able to install exactly the two seams its case
 * is about.
 */
typedef struct {
	/* Whatever the implementation keeps. Never touched by this module. */
	void *context;
	/*
	 * Take the apply lock, open a netlink socket, and fill in the seam.
	 *
	 * Opened per operation rather than per pass, which is the Rust's
	 * lifetime: the lock covers the plan as well as the actions, and a pass
	 * that only observes never takes it. 0 with a sentence holds the acting
	 * rather than failing the pass -- an apply that cannot start is a fact to
	 * report, not a reason to stop watching.
	 */
	int  (*executor_open)(void *context, ncfg_executor_t *out, char *err, size_t err_size);
	/* Release what `executor_open` filled in. */
	void (*executor_close)(void *context, ncfg_executor_t *executor);
	/* Tell every subscriber. NULL is nobody listening, which is an ordinary
	 * daemon with no monitor attached. */
	void (*announce)(void *context, const ncfg_proto_event_t *event);
	/* Run one hook. */
	ncfg_reconcile_hook_fn hook;
	/*
	 * Ask a URL whether something is in the way.
	 *
	 * A seam although `ncfg_portal_probe` exists, because that call forks and
	 * execs this process' own image: a test that drove it would run the
	 * developer's netcfgd. `ncfg_reconcile_portal_probe` is the
	 * implementation that does it for real, and it always produces a verdict
	 * -- a probe that could not be run has not found a portal, so everything
	 * that can go wrong is `unreachable` with a sentence and is retried.
	 */
	void (*portal)(void *context, const char *url, ncfg_portal_result_t *out);
	/*
	 * Give a radio back that netcfgd should not be holding.
	 *
	 * `ncfg_contenders_find` landed in the same wave and is what an
	 * implementation calls; it is a seam rather than a call because giving a
	 * radio back means stopping a backend on the machine this is built on.
	 * The boot race is the
	 * part netcfgd can fix: it starts `Before=network-pre.target`, so it can
	 * take a radio before `NetworkManager` has written anything that says the
	 * device is NM's, and two supplicants on one radio drop the association.
	 * Called on every pass and not only at start, because once netcfgd holds
	 * a backend the plan says "nothing to do" for that interface and nothing
	 * would ever look again.
	 *
	 * **An implementation asks who the contenders are before it opens an
	 * executor.** The Rust does it the other way round -- it opens one as soon
	 * as netcfgd is running any backend at all -- so on every machine it
	 * manages it takes the apply lock and a netlink socket every five seconds
	 * to find out there is nothing to give back, against the same lock `ncfg
	 * apply` waits on (0184).
	 */
	int  (*release_contended)(void *context, ncfg_daemon_state_t *state, char *err,
	    size_t err_size);
	/* Wake the loop when a window closes. NULL leaves the tick to close it,
	 * which costs seconds rather than the window. */
	void (*expiry)(void *context, uint32_t seconds);
	/* Seconds since the epoch. NULL is `ncfg_confirm_now`, and a test hands
	 * over a counter it moves itself -- `ncfg_confirm_expired_at`'s rule,
	 * applied to the caller that reads the clock. */
	uint64_t (*now)(void *context);
	/* The machine the resolv sweep asks about processes and signals. NULL
	 * never sweeps, which that seam's own rule requires. */
	const ncfg_resolv_machine_t *resolv;
} ncfg_reconcile_world_t;

/*
 * The loop's own state, beside the modules it drives.
 *
 * `probes`, `sims` and `armed` are held *beside* `ncfg_daemon_state_t` rather
 * than inside it, for the reason that header gives: a reload replaces the
 * document and must not replace a tally that has been counting across ticks,
 * and what an open window covers legitimately outlives a reload. This struct
 * is where the four meet, and it owns none of them.
 */
typedef struct {
	ncfg_daemon_state_t   *state;
	ncfg_probes_t         *probes;
	ncfg_sims_t           *sims;
	/* What an open window covers. May be NULL, which is a caller that does
	 * not arm from this loop; a daemon that restarted inside a window has one
	 * that is empty, and `ncfg_confirm_revert` says what that falls back to. */
	ncfg_confirm_armed_t  *armed;
	ncfg_reconcile_world_t world;
	/*
	 * `--no-apply-on-start`, as a latch rather than a startup skip.
	 *
	 * The flag says the daemon should observe and be told when to act, and
	 * once the loop reconciles on its own that has to keep meaning something
	 * -- otherwise it delays acting by one tick and no more, and the
	 * *protected first apply* it exists for cannot happen. Set by
	 * `ncfg_reconcile_start` and cleared by the first explicit apply.
	 */
	int      holding;
	/* Reclaims in a row, which `NCFG_RESOLV_PATIENCE` bounds. */
	unsigned reclaims;
} ncfg_reconcile_t;

/* What one pass did. For a caller that wants to say so, and for a test that
 * would otherwise have to infer it from the machine. */
typedef struct {
	/* A window was found closed and put back. */
	int    window_resolved;
	/* The configuration directory was recompiled. */
	int    reloaded;
	/*
	 * And the document that came out of it is a different one.
	 *
	 * **"The file was written" is not "the configuration changed"**, and the
	 * confirm window turns on the difference: an editor writing the same
	 * bytes, or a configuration-management tool rewriting the file on a
	 * timer, is a write -- and a reload that fails to compile is a write that
	 * leaves the desired document exactly as it was. Either of those on a
	 * pass that is also correcting drift used to arm a window over the drift
	 * correction, which 0157 says never happens; on expiry that reverts
	 * netcfgd's own repair, the drift is found again, and the machine
	 * oscillates. Comparing the document either side of the reload is what
	 * makes the exclusion true rather than intended.
	 */
	int    config_is_new;
	int    probes_changed;
	/* The pass looked at the machine at all. */
	int    looked;
	/* The link set the kernel reports moved. */
	int    links_moved;
	size_t drift_count;
	/* A restricted plan was applied. */
	int    reconciled;
	size_t actions_done;
	/* A window was armed over the change. */
	int    armed;
	/* The resolv sweep ran, and how many it signalled. */
	int    swept;
	size_t signalled;
	/* The hold was released by an explicit apply. */
	int    released_hold;
} ncfg_reconcile_report_t;

/*
 * Make a confirm window possible on the very first apply.
 *
 * A window reverts to the last-good configuration, and until netcfgd has
 * applied once there is none -- so `ncfg apply --confirm-within` was refused
 * exactly when an operator most wanted it, on the first apply on a machine
 * they were still unsure about.
 *
 * The missing document is an empty one, and that is not a placeholder: before
 * netcfgd's first apply its desired state genuinely was nothing. Reverting to
 * it removes every address, route, link and backend netcfgd installed and
 * touches nothing it did not, which is the exact undo of a first apply. What
 * it does not do is restore connectivity netcfgd was not providing.
 *
 * Written only where none exists, so the ordinary reboot case is untouched.
 * Answers 1 where one was already there as well as where one was written; 0
 * with a sentence only where the write was refused.
 */
int ncfg_reconcile_establish_last_good(const ncfg_daemon_state_t *state, char *err,
    size_t err_size);

/*
 * Apply everything the configuration asks for, and record it as last-good.
 *
 * The startup apply, and deliberately **not** a path that ever arms a window:
 * `ncfg_reconcile_establish_last_good` writes an empty document before this
 * runs, so a window armed at boot and left unconfirmed on a machine that has
 * never applied would revert to *nothing* -- taking down every address, route
 * and backend netcfgd had just brought up, N seconds after start, with no
 * operator present. It is exempt by construction in the Rust as well, and
 * this sentence is here to stop somebody wiring it in later.
 *
 * The configuration in force becomes the last-good only where the apply had
 * no failure at all. Without recording it the first `apply --confirm-within`
 * after a boot is refused for having nothing to revert to, which is safe and
 * useless.
 */
int ncfg_reconcile_converge(ncfg_reconcile_t *loop, ncfg_reconcile_report_t *report, char *err,
    size_t err_size);

/*
 * Configure the machine at startup, and set the latch.
 *
 * `reverted` is whether a window found at startup was resolved by reverting:
 * a machine that has just been put back is not one to apply over.
 *
 * A network configuration daemon that starts and configures nothing is not
 * doing its job -- design section 4.4 makes oneshot the alternative rather
 * than the default -- so `apply_on_start` converges here, and only the
 * *acting* is what `--no-apply-on-start` holds.
 */
int ncfg_reconcile_start(ncfg_reconcile_t *loop, int apply_on_start, int reverted, char *err,
    size_t err_size);

/*
 * One pass of the loop.
 *
 * The order is the whole of this function and every step of it is written
 * down in the Rust with a reason:
 *
 *   1. a window whose timer fired -- or whose timer never started, which is
 *      what the tick is for -- is asked whether it has really closed;
 *   2. the `roam` hooks run, before anything re-observes, so a script sees
 *      the machine as the move left it;
 *   3. the configuration is recompiled where something wrote in the
 *      directory, and the documents either side are compared;
 *   4. whatever probes are due are run, and a SIM is advanced where one has
 *      just been declared dead;
 *   5. and where anything at all moved: the kernel is re-read, the drift is
 *      broadcast, the `drift` hooks run **before** the reconcile so a script
 *      sees the machine as it drifted rather than as netcfgd has just put it
 *      back, the portal checks run after them and before the reconcile for
 *      the same reason, a contended radio is given back **before** the
 *      reconcile and not inside it -- once netcfgd holds a backend the plan
 *      says "nothing to do" for that interface and a claim appearing later
 *      would never be looked at again -- and then the restricted plan is
 *      applied.
 *
 * **Only step 5's last part is held by `--no-apply-on-start`.** Gating the
 * observation too left the daemon planning against what it saw at startup,
 * which is worse than not looking: it answers `apply` with a plan for a
 * machine that has since moved, and the operator gets an apply that does the
 * wrong work and reports success.
 *
 * `requests` is what is waiting to be answered, and this answers none of them.
 * `report` may be NULL. Returns 0 with a sentence only where the pass could
 * not be carried out at all; everything a machine can refuse is reported
 * through the log and the report and leaves the loop running, because a
 * daemon that stopped reconciling on a failed apply is a daemon that stopped.
 */
int ncfg_reconcile_pass(ncfg_reconcile_t *loop, const ncfg_reconcile_wake_t *wake,
    const ncfg_reconcile_roam_t *roams, size_t roam_count,
    const ncfg_proto_request_t *requests, size_t request_count,
    ncfg_reconcile_report_t *report, char *err, size_t err_size);

#endif /* NCFG_DAEMON_H */
