/*
 * dns.h -- delivering DNS configuration to whatever resolver the host runs.
 *
 * WHAT THIS IS
 *   Decision 0007 makes each mode a contract with a specific tool, and makes
 *   the compiler refuse a config asking a mode for something it cannot
 *   express. By the time anything here runs, the policy is known to fit the
 *   mode -- so this module delivers and does not judge.
 *
 * THE RULE THE WHOLE MODULE IS ARRANGED AROUND
 *   **The scope-capable modes never flatten.** Silently collapsing split DNS
 *   sends internal queries to a public resolver, which is a disclosure rather
 *   than a degradation. A mode that cannot route refuses the config at compile
 *   time (0007); a mode that can route is delivered here with its scopes
 *   intact.
 *
 * EVERY PATH IS A PARAMETER, AND THAT IS NOT A CONVENIENCE
 *   The Rust reads `NCFG_RESOLV_CONF`, `NCFG_DNSMASQ_CONF` and
 *   `NCFG_UNBOUND_CONF` out of the environment, and its own comment says why
 *   those variables exist: "a test very nearly rewrote this machine's". An
 *   environment variable is a default that a caller can forget to set and a
 *   test can forget to unset, and the file at the other end of it is the one
 *   that decides whether this machine can resolve a name at all. So there is
 *   no environment here: `ncfg_dns_targets_t` carries every path, and a
 *   delivery with nothing to write to fails rather than falling back to
 *   `/etc`. The constants below are what a caller *chooses*, spelled once.
 *
 * WHAT IS RECORDED, AND WHY IT IS NOT WHAT IS RETURNED
 *   0007's partial mitigation for the one place principle 2 bends: once DNS is
 *   handed to another daemon, the effective behaviour lives in that daemon's
 *   head, so netcfgd makes its own half greppable under `<run>/dns/`. The
 *   observer reads those files back as `ncfg_applied_dns_t`.
 *
 *   **The delivery reports scope names and not policies**, which is where this
 *   differs from the Rust. There, `deliver` returns `Vec<AppliedDns>`, each
 *   carrying a *clone* of the policy the caller passed in. In C that would be
 *   a deep copy of something the caller already owns, handed back to the
 *   caller, with a matching free -- three chances to get ownership wrong for a
 *   value nobody learns anything from. The names say which scopes were
 *   delivered, which is the part the caller did not already know.
 */
#ifndef NCFG_DNS_H
#define NCFG_DNS_H

#include <stddef.h>

#include "ncfg/document.h"
#include "ncfg/observed.h"

/* Where `resolv.conf` lives when a caller has no other opinion. */
#define NCFG_RESOLV_CONF "/etc/resolv.conf"

/* And the two forwarding resolvers' drop-ins. Both are in directories netcfgd
 * will not create: an absent `/etc/dnsmasq.d` means dnsmasq is not installed
 * or does not read that directory, and creating it would leave a file nothing
 * consumes while reporting success. Constraint 2 -- the filesystem reflects
 * use -- cuts both ways. */
#define NCFG_DNSMASQ_CONF "/etc/dnsmasq.d/netcfgd.conf"
#define NCFG_UNBOUND_CONF "/etc/unbound/unbound.conf.d/netcfgd.conf"

/* The scope that is not an interface. `resolvconf` keys on an interface name
 * so it becomes `lo.netcfgd`, and resolved is per-link so it becomes `lo`. */
#define NCFG_DNS_GLOBAL_SCOPE "globals"

/* glibc reads at most this many `nameserver` lines and silently ignores the
 * rest. Published so a test cannot spell the number itself. */
#define NCFG_DNS_MAXNS 3

/*
 * One scope to deliver: an interface's, a network's, or the host-wide
 * fallback.
 *
 * Borrowed, not owned. A scope is a name and a pointer to a policy the caller
 * already holds, and nothing here outlives the call it was passed to.
 */
typedef struct {
	const char              *name; /* an interface name, or `globals` */
	const ncfg_dns_policy_t *policy;
} ncfg_dns_scope_t;

/* ------------------------------------------------------------------------ *
 * Which scopes a machine has, which is a rule and not a loop
 * ------------------------------------------------------------------------ */

/*
 * Every scope a document asks for, given what has been observed.
 *
 * **One rule with two callers, and that is the whole reason it is here.** In
 * the Rust this is `netcfgd_model::dns::scopes`, and the comment above it
 * records what happened before it was: the planner learned that a lease
 * contributes nameservers (0006 rule 4) and the executor went on building its
 * list from the document alone, so the plan said `dns.apply` and the delivery
 * wrote a `resolv.conf` with nothing in it. The planner asks this to decide
 * what to plan; the daemon asks it to fill `ncfg_service_t::dns_scopes`, so
 * that one `dns.apply` delivers every scope rather than the one the op names.
 * A third spelling is the defect, not the duplication.
 *
 * The rule, in the order it is applied:
 *
 *   * The host's own `global { dns { } }` is a scope named `globals`, unless
 *     its mode is `none`.
 *   * Each interface of a **managed** device contributes one. An unmanaged
 *     device contributes nothing, and it has to be asked here: `dns.apply` is
 *     host-wide, so it names no interface and the planner's usual choke point
 *     never sees it.
 *   * An interface contributes its lease's nameservers and search suffixes
 *     only where it **asked** for what the network offers -- a `dns { }` block
 *     of its own, or an address from a reported source. The same gate for both
 *     lists: where an operator kept their own resolvers, a lease does not get
 *     to redefine what a bare name means (0049).
 *   * The document's servers come first, so first-occurrence-wins means a
 *     server an operator chose beats one the network handed out.
 *   * A scope that would deliver nothing is left out rather than carried with
 *     mode `none`, because an action that does nothing is one somebody reads
 *     and dismisses on every run.
 *   * A policy that states no mode takes the host's. The mode is not a
 *     per-interface choice -- a host cannot both own `resolv.conf` and hand it
 *     to `resolvconf` -- so `none` on a scope with something to deliver can
 *     only mean "not stated".
 *
 * `observed` may be NULL, which is a machine nothing has looked at yet: the
 * document's own scopes come back and no lease contributes to any of them.
 *
 * **What comes back owns the policies it had to merge and borrows the rest.**
 * A scope whose servers came straight off the document points into the
 * document, exactly as `ncfg_dns_scope_t` says; one that absorbed a lease
 * points into this object's own arena. So the document must outlive this, and
 * this must outlive anything still holding a `ncfg_dns_scope_t` it handed out
 * -- which for a plan is what `ncfg_plan_adopt` exists to arrange.
 *
 * Returns NULL with a sentence in `err` where there was nothing to allocate
 * with. A document with no DNS anywhere is an empty list and not a failure.
 */
typedef struct ncfg_dns_scopes ncfg_dns_scopes_t;

ncfg_dns_scopes_t *ncfg_dns_scopes_of(const ncfg_document_t *desired,
    const ncfg_observed_t *observed, char *err, size_t err_size);

/*
 * What it found, in document order: `globals` first, then the interfaces.
 *
 * The document's interface list is sorted by name, so the result is
 * deterministic rather than dependent on which drop-in was read first. `count`
 * may be NULL. Both answers are valid until the scopes are freed, and an empty
 * list answers a non-NULL pointer with a count of zero rather than NULL --
 * "no scopes" and "could not be asked" are different facts.
 */
const ncfg_dns_scope_t *ncfg_dns_scopes_items(const ncfg_dns_scopes_t *scopes, size_t *count);

/* Release the list and everything it had to merge. NULL is nothing. */
void ncfg_dns_scopes_free(ncfg_dns_scopes_t *scopes);

/*
 * The flattened result: what a single-list resolver ends up with.
 *
 * **The entries point into the scopes' own policies.** The Rust clones; this
 * borrows, because the flattening is consumed by a renderer in the same
 * statement and copying a server list to render it once is work nobody asked
 * for. It is valid only as long as the scopes are.
 */
typedef struct {
	const ncfg_dns_server_t **servers; /* in precedence order */
	size_t                    server_count;
	const char              **search;
	size_t                    search_count;
	const char              **options;
	size_t                    option_count;
} ncfg_dns_flat_t;

/*
 * Merge scopes into one flat answer.
 *
 * Per-interface scopes come before the global one, and within each list the
 * first occurrence wins -- 0006 rule 4, applied to the only mechanism a flat
 * resolver has. The order of the interfaces themselves is the document's,
 * which is sorted by name, so the result is deterministic rather than
 * dependent on which interface came up first.
 *
 * This is lossy and that is the whole point of 0007: a flat resolver cannot
 * express "these servers for that domain", so the compiler refuses configs
 * that ask for it rather than letting the loss happen quietly here.
 */
int ncfg_dns_flatten(const ncfg_dns_scope_t *scopes, size_t count, ncfg_dns_flat_t *out, char *err,
    size_t err_size);

/* Release what the flattening allocated. Freeing one never filled in is
 * nothing. */
void ncfg_dns_flat_free(ncfg_dns_flat_t *flat);

/*
 * Render `resolv.conf`.
 *
 * **The three-server limit is glibc's, not netcfgd's**: the resolver reads at
 * most `MAXNS` nameserver lines and silently ignores the rest. Writing more
 * would look like it worked and quietly not. The extras are listed in a
 * comment instead, so somebody reading the file can see what was dropped and
 * why.
 *
 * Allocated; free it with `free`. NULL with a sentence on failure.
 */
char *ncfg_dns_resolv_conf(const ncfg_dns_flat_t *flat, const char *generator, char *err,
    size_t err_size);

/*
 * Render the blob `resolvconf -a <iface>` reads on stdin.
 *
 * Same format as `resolv.conf`, **one scope at a time**, because that is the
 * interface `resolvconf(8)` defines: each subscriber hands over what it knows
 * about one interface and the implementation decides how to combine them.
 * Handing it a pre-merged file would throw away the one thing it is for.
 */
char *ncfg_dns_resolvconf_blob(const ncfg_dns_policy_t *policy, char *err, size_t err_size);

/*
 * dnsmasq configuration for a set of scopes.
 *
 * `server=/suffix/address` is dnsmasq's routing domain: queries for that suffix
 * go to that server and nowhere else. A scope with no routing domain
 * contributes a plain `server=address`, which is the flat behaviour, so a mixed
 * document produces a file that does both.
 */
char *ncfg_dns_dnsmasq_conf(const ncfg_dns_scope_t *scopes, size_t count, char *err,
    size_t err_size);

/*
 * unbound configuration for a set of scopes.
 *
 * A `forward-zone` with `name: "."` is the catch-all and a named one is a
 * routing domain. Unlike dnsmasq, unbound distinguishes them only by the zone
 * name, so the exclusive flag has no separate spelling here either.
 */
char *ncfg_dns_unbound_conf(const ncfg_dns_scope_t *scopes, size_t count, char *err,
    size_t err_size);

/*
 * Every scope, as JSON, for the exec mode.
 *
 * Hand-rolled rather than run through the document writer: a script reading
 * this is an integration somebody wrote once and expects to keep working, and
 * a wire format that changed whenever an internal type did would break it.
 */
char *ncfg_dns_scopes_json(const ncfg_dns_scope_t *scopes, size_t count, char *err,
    size_t err_size);

/*
 * Put `text` at `path`, through a temporary in the same directory.
 *
 * A resolver reading during the write must see the old file or the new one and
 * never half of each: a truncated `resolv.conf` is a machine that cannot
 * resolve anything.
 *
 * **The temporary's name is what makes that true for more than one writer.**
 * Both Rust call sites named it after the target alone -- `resolv.netcfgd.tmp`
 * for every writer there will ever be -- and netcfgd applies from two
 * processes, `ncfg apply` and the daemon, either of which may deliver DNS.
 * Interleaved, one writer's bytes are renamed into place by the other writer's
 * rename and the loser's rename fails with `ENOENT` on a file it had just
 * written. So the pid and a counter are in the name: the pid because the second
 * writer is another process, the counter because it need not be.
 *
 * **The leading dot is not decoration.** One of these directories is read by a
 * glob and the other by a program: a `*.conf` glob over `unbound.conf.d` does not match a
 * name beginning with a dot, and dnsmasq's `conf-dir` always skips one.
 *
 * **It falls back to writing in place where it may not stage.**
 * `ProtectSystem=full` mounts `/etc` read-only and the unit opens one path back
 * up with `ReadWritePaths=-/etc/resolv.conf`, which grants the *file*; creating
 * a new entry in `/etc` is still refused, and staging a temporary beside the
 * target is creating a new entry. So on every systemd machine this failed with
 * a permission error naming a dotfile the operator has never seen. Only for a
 * permission or read-only refusal: a full disk also fails to stage, and falling
 * back there would truncate the resolver's configuration and then fail to
 * refill it.
 *
 * **And the fallback will not write through a symlink.** `/etc/resolv.conf` is
 * a symlink into another resolver's runtime state on a great many machines.
 * The rename path *replaces* such a link, which is what `write_resolv_conf`
 * mode asks for; writing through it would scribble in a daemon's own state,
 * which nothing here has ever been asked to do.
 */
int ncfg_dns_replace(const char *path, const char *text, char *err, size_t err_size);

/*
 * Where each mode's delivery goes.
 *
 * Every field is required by the mode that uses it and ignored by the rest. A
 * mode whose target is NULL fails by name rather than reaching for `/etc`.
 */
typedef struct {
	/* `write_resolv_conf` writes here. */
	const char *resolv_conf;
	/* `dnsmasq` and `unbound` write here. */
	const char *dnsmasq_conf;
	const char *unbound_conf;
	/* Where the scope record goes: `<run_dir>/dns/<scope>.conf`. */
	const char *run_dir;
	/* The programs the three handing-over modes run. NULL means the
	 * conventional name, found on `PATH` -- which is right for a daemon and is
	 * why a check passes its own. */
	const char *resolvconf_program;
	const char *resolvectl_program;
} ncfg_dns_targets_t;

/*
 * Deliver every scope, and say which were delivered.
 *
 * **Every scope in one delivery must agree on the mode**: a host cannot both
 * own `resolv.conf` and hand it to resolvconf. Disagreement is a config error
 * rather than something to resolve by picking one.
 *
 * `delivered_out` receives an allocated array of scope names, freed with
 * `ncfg_dns_delivered_free`. Either may be NULL for a caller that does not want
 * them.
 */
int ncfg_dns_deliver(const ncfg_dns_scope_t *scopes, size_t count,
    const ncfg_dns_targets_t *targets, char ***delivered_out, size_t *delivered_count, char *err,
    size_t err_size);

void ncfg_dns_delivered_free(char **delivered, size_t count);

/*
 * Write the rendered scope table where `cat` can reach it.
 *
 * Separate from the delivery because the observer's round trip is the real
 * contract: without this a plan could not tell an already-applied policy from
 * an unapplied one, and every run would emit a `dns.apply` -- which would fail
 * the plan-idempotence gate.
 */
int ncfg_dns_record(const ncfg_dns_scope_t *scopes, size_t count, const char *run_dir, char *err,
    size_t err_size);

#endif /* NCFG_DNS_H */
