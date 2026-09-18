/*
 * daemon.h -- who may ask, how the asking arrives, and what the daemon holds.
 *
 * This is `crates/netcfgd-daemon` in C: `authorize.rs`, `server.rs` and the
 * part of `state.rs` that is a document and a reload. The parts that are a
 * reconcile loop -- confirm windows, probes, sims, the resolv guard -- are not
 * here yet and are named in the port's notes rather than stubbed, because a
 * stub that answers is worse than a symbol that is missing.
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
#include <sys/types.h>

#include "ncfg/ast.h"
#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/document.h"
#include "ncfg/lex.h"
#include "ncfg/observed.h"
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
 * Not here yet, and named rather than stubbed: the confirm window, the probe
 * verdicts, the SIM pairings and the resolv guard. Each is its own module in
 * the Rust and each lands with its own tests.
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

#endif /* NCFG_DAEMON_H */
