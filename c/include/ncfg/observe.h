/*
 * observe.h -- kernel dumps plus what netcfgd wrote down, turned into an
 * observation.
 *
 * WHERE DECISION 0002 BECOMES CODE
 *   Two questions are answered here and nowhere else:
 *
 *     * **Is this object ours?** A route carrying `rtm_protocol` 110 is; an
 *       address carrying `IFA_PROTO` 110 is, on a kernel new enough to report
 *       it; a link wearing an alternative name that begins `netcfgd:` is
 *       (0136). Everything else is foreign or unknown, and **neither may be
 *       removed**. An observation that guesses wrong here either strands
 *       somebody's address or deletes it, which is why the three judgements
 *       have names of their own below and are testable one at a time.
 *     * **Which source produced it?** Decision 0006 rule 7 needs that to tell
 *       a missing static address from an expired lease -- the remedy for the
 *       second is to restart the client, not to add the address back -- and
 *       the kernel does not know, so it comes from recorded prior state.
 *
 * WHAT IS PURE AND WHAT READS THE MACHINE, AND WHY THE SPLIT IS THE POINT
 *   `ncfg_observe_build` is a function of a snapshot and a record. That is
 *   what makes the ownership policy testable with no kernel, no privilege and
 *   no network namespace -- the property the Rust states for `build` and the
 *   only reason this module's rules can be exercised on a workstation whose
 *   real network the real netcfgd is configuring.
 *
 *   Everything that reads a file is in `ncfg_observe_augment_host`, and
 *   **every root it reads under is a parameter**: `ncfg_observe_roots_t`
 *   carries `/sys/class/net`, `/proc` and `/sys`, resolved once from the
 *   environment by `ncfg_observe_roots_default`. A predicate that read the
 *   environment for itself would be a predicate whose answer depends on hidden
 *   global state, which is radio.h's argument and is why that module already
 *   takes its root as an argument.
 *
 * WHAT THIS PORT DOES NOT CARRY YET, SAID OUT LOUD
 *   `host.rs`'s `augment` calls eleven passes by name, beside the four small
 *   readers this port has -- the sysctls, the hostname, rfkill and Bluetooth --
 *   and `derive`. **This entry said for several waves that six of the eleven
 *   were deferred, while naming nine and while every one of them was.**
 *   Counted against the tree instead: seven are deferred, four are here, and
 *   the reason most of them are deferred has now moved twice -- once because
 *   the blockers that were written down had been overtaken, and once because
 *   the record they actually waited on arrived. Each is named below with what
 *   it waits on **today**, because a list nobody re-checks is worse than none:
 *   it is addressed to somebody who cannot check it (project.md 10.180,
 *   10.182, 10.183).
 *
 *     * **Six walk `observed.backends`, and that list is no longer always
 *       empty.** `ask_supplicants`, `read_access_control`, `read_advertised`,
 *       `read_secret_currency`, `read_tunnel_currency` and
 *       `read_backend_liveness` each iterate it. It is filled from the prior
 *       state and from nowhere else, and `ncfg_owned_state_t` now carries
 *       `backends` -- so the blocker this entry named twice is gone and these
 *       six are writable rather than waiting.
 *     * `read_backend_liveness` **is written**, as
 *       `ncfg_observe_backend_liveness`. What it waited on was a backend kind
 *       mapped to the pid file and the `argv` marker netcfgd started that
 *       daemon with -- the Rust's `netcfgd_apply::backend_pid_file`, seven
 *       kinds in one function. This port has the per-module answers instead,
 *       one per marker, and the missing sixth (`ncfg_hostapd_running_pid`)
 *       landed with the pass; the mapping is a switch over the taxonomy with
 *       no `default:`. So `running` is a fact about a process rather than
 *       netcfgd's memory of having started one, and 0079's third clear has its
 *       precondition (`apply.h`, project.md 10.183, 10.191).
 *
 *       **The `/proc` it reads under is still not a parameter**, which is this
 *       module's rule broken and is recorded rather than worked around: the
 *       answers come from `process.h`, where finding a process is a security
 *       property, and a second reader taking a root would be two answers to
 *       who owns a pid. What it costs is that `liveness_test.c` starts real
 *       children instead of pointing at a tree it made.
 *
 *       The four remaining are simply not written yet, each being a round trip
 *       to the daemon it asks.
 *     * `read_resolv_currency` walks `observed.dns`, which the record now
 *       carries too -- but only carries: nothing in this build *writes* a
 *       delivered scope into it, because `dns.apply` is the one op that is not
 *       its own effect. `apply.h` has the argument and `dns.h` names the
 *       producer that would close it, a reader of `<run>/dns/`.
 *
 *   `read_netfilter`, `read_offloads`, `read_wireguard_keys` and
 *   `read_wireguard_currency` **are** ported, as `ncfg_observe_netfilter_from`,
 *   `ncfg_observe_offloads_from`, `ncfg_observe_wireguard_from` and
 *   `ncfg_observe_wireguard_currency`: they are the four whose input comes
 *   from the kernel and from the store rather than from the record, and whose
 *   answers the planner already reads. See the note above each for what its
 *   absence cost -- the first two the same cost, one field apart, and the
 *   WireGuard pair a different one, which is said where they are declared.
 *
 *   **One input of the fourth is not written by this build.** The currency
 *   question compares a digest of what the store holds now against a digest of
 *   what netcfgd loaded, and the second is a record under `/run` that the
 *   executor writes when the kernel accepts a key. `apply/kernel_genl.c` does
 *   not write it yet, so `key_matches` and `preshared_matches` come back absent
 *   on a real machine until it does -- which is a question left unanswered
 *   rather than answered wrongly, and is the one shape the planner is built to
 *   do nothing about. `ncfg_observe_wg_key_record_path` and
 *   `ncfg_observe_wg_preset_record_path` are declared here so that the writer,
 *   when it lands, names the file through them rather than spelling the path a
 *   second time: `NCFG_OBSERVE_ALTNAME_PREFIX` above is the same arrangement
 *   for the same reason, and two spellings of one path is a reader looking
 *   where nothing was written.
 *
 *   What is here is the whole of `lib.rs`, the four file readers of `host.rs`,
 *   the nftables round, the offloads round, the WireGuard round, and the whole
 *   of `derive`.
 *
 * WHERE THIS DIVERGES FROM THE RUST, ON PURPOSE
 *   0263 collects the port's divergences; these are this module's.
 *
 *   * **The snapshot is declared here.** `netcfgd_sys::Snapshot` is the sys
 *     crate's aggregate of four dumps; the C's sys module stopped at the
 *     records and has no aggregate, so the observer's input type is declared
 *     beside the observer. It **borrows**: every array in it belongs to
 *     whoever filled it in, which is why there is no free beside it.
 *   * **`build` takes the prior's aggregates rather than copying them.** The
 *     Rust clones a `PriorState` into the observation; a deep copy of an
 *     `ncfg_dns_policy_t` or an `ncfg_observed_backend_t` exists nowhere in
 *     this port, and writing one here would be a second thing to keep in step
 *     with `document.c`'s and `observed.c`'s field tables -- exactly the
 *     duplication 0263 forbids. So the six aggregate lists are handed over and
 *     the prior is left holding none of them; see `ncfg_observe_prior_t`.
 *   * **`connectivity::overall` is here rather than in the model.** It is the
 *     model's in the Rust and belongs there; the C model has not grown it, and
 *     `derive` cannot be ported without it. It is declared with the name it
 *     would have in the model (`ncfg_connectivity_overall`) so that moving it
 *     is a file move rather than a rename at every call site.
 *   * **A number the kernel reports is checked rather than cast** on the way
 *     into the model's `int64_t`, with the field named in the refusal, which
 *     is 0263's rule pointed in the reading direction.
 */
#ifndef NCFG_OBSERVE_H
#define NCFG_OBSERVE_H

#include <stddef.h>
#include <stdint.h>

#include "ncfg/base.h"
#include "ncfg/document.h"
#include "ncfg/hooks.h"
#include "ncfg/netlink.h"
#include "ncfg/observed.h"
#include "ncfg/qdisc.h"
#include "ncfg/radio.h"
#include "ncfg/rule.h"
/* For `ncfg_secret_resolver_t`, which the WireGuard currency question takes.
 * The store is an argument to this module and never a default it reaches for
 * -- see that call. */
#include "ncfg/secrets.h"

/* ------------------------------------------------------------------------ *
 * The marks netcfgd stamps, and the one this port had to spell first
 * ------------------------------------------------------------------------ */

/*
 * The prefix on the alternative name netcfgd gives every link it creates.
 *
 * **A link has no protocol field**, so decision 0002's tag had nothing to
 * stamp and link ownership lived only in `/run` -- which a restart deletes.
 * 0136 gives the link an alternative name instead, and this is what reads it
 * back.
 *
 * Spelled here because nothing in this port spells it yet: `ncfg_ops_add_
 * altname` takes a name and does not build one. The Rust keeps it in the
 * model's `route.rs` beside the protocol number, and when the executor lands
 * it should use this constant rather than write the string again -- two
 * spellings of one marker means netcfgd stamps one and looks for the other,
 * and every link it creates becomes foreign to it.
 */
#define NCFG_OBSERVE_ALTNAME_PREFIX "netcfgd:"

/* ------------------------------------------------------------------------ *
 * Where the observer reads from
 * ------------------------------------------------------------------------ */

/* Room for any of the three roots. `NCFG_RADIO_ROOT_MAX` is the number
 * radio.h already chose for the same question, borrowed rather than a second
 * opinion. */
#define NCFG_OBSERVE_ROOT_MAX NCFG_RADIO_ROOT_MAX

/* What overrides `/proc`, for a test. Spelled as the Rust spells it, because
 * the two halves' tests set one name. */
#define NCFG_OBSERVE_PROC_ROOT_ENV "NCFG_PROC_ROOT"
/* And `/sys`, which is where rfkill and the Bluetooth adapters live. */
#define NCFG_OBSERVE_SYS_ROOT_ENV "NCFG_SYS_ROOT"

#define NCFG_OBSERVE_PROC_ROOT_DEFAULT "/proc"
#define NCFG_OBSERVE_SYS_ROOT_DEFAULT "/sys"

/*
 * The three directories an observation reads under.
 *
 * Storage inside the struct rather than three pointers, so that there is no
 * ownership question and a caller can put one on the stack -- which is what
 * `ncfg_state_resolve_dir` does for the run directory and for the same reason.
 */
typedef struct {
	/* radio.h's, because "is this a radio" is its question and this must
	 * not become a second answer to it. */
	char class_net[NCFG_OBSERVE_ROOT_MAX];
	char proc[NCFG_OBSERVE_ROOT_MAX];
	char sys[NCFG_OBSERVE_ROOT_MAX];
} ncfg_observe_roots_t;

/*
 * The roots the environment names, and the kernel's where it names none.
 *
 * Read once, here, rather than inside each reader: two tests setting one
 * environment variable while running in parallel is a race, and a reader whose
 * answer depends on hidden global state is one nobody can test twice.
 */
int ncfg_observe_roots_default(ncfg_observe_roots_t *out, char *err, size_t err_size);

/* ------------------------------------------------------------------------ *
 * What the kernel said
 * ------------------------------------------------------------------------ */

/* One ingress redirect, as the qdisc dumps report it. */
typedef struct {
	/* The interface traffic arrives on. */
	uint32_t index;
	/* The interface it is redirected to. */
	uint32_t target;
	/* Whether the filter wears netcfgd's handle (0137), which is how a
	 * redirect stays recognisable as netcfgd's after `/run` is gone. */
	int      ours;
} ncfg_observe_redirect_t;

/*
 * One round of dumps.
 *
 * **Borrowed, every field.** The arrays belong to whoever filled them in, and
 * a link record's alternative names belong to the record -- so there is no
 * `ncfg_observe_snapshot_free`, which is said here because "there isn't one"
 * is a thing a reader has to be able to find out without reading the source.
 */
typedef struct {
	const ncfg_link_record_t        *links;
	size_t                           link_count;
	const ncfg_address_record_t     *addresses;
	size_t                           address_count;
	const ncfg_route_record_t       *routes;
	size_t                           route_count;
	const ncfg_bridge_vlan_record_t *bridge_vlans;
	size_t                           bridge_vlan_count;
	/* The root qdisc on each interface that has one. The ingress hooks are
	 * not in here: what an observation wants from them is the redirect
	 * hanging off them, which is `redirects`. */
	const ncfg_qdisc_record_t       *qdisc_roots;
	size_t                           qdisc_root_count;
	const ncfg_observe_redirect_t   *redirects;
	size_t                           redirect_count;
	const ncfg_rule_record_t        *rules;
	size_t                           rule_count;
	/*
	 * Whether any address in this dump carried `IFA_PROTO`.
	 *
	 * **A lower bound, not a kernel capability check.** A live 6.12 kernel
	 * reports no `IFA_PROTO` on any address until netcfgd installs one --
	 * measured, and `ip -d addr` agreed -- so a fresh system starts in the
	 * weak mode and calibrates into the strong one the moment netcfgd owns
	 * its first address. `0` means "no evidence seen", never "the kernel
	 * cannot do this".
	 */
	int                              address_proto_supported;
} ncfg_observe_snapshot_t;

/* ------------------------------------------------------------------------ *
 * Taking the dumps that fill one
 * ------------------------------------------------------------------------ */

/*
 * The most records of one kind a round of dumps will hold.
 *
 * **Chosen for the routing table**, which is the only one of the seven a
 * *network* can make large: a machine carrying a full BGP feed has a million
 * routes and refusing to read them would be a daemon that cannot see its own
 * machine, which is the argument `netlink.h` makes about the reply buffer. The
 * other six reach this only on a machine that has already stopped working, and
 * the ceiling is there so that growth is bounded rather than because this is
 * the right number of links.
 *
 * A dump past it is refused **naming the kind and the number**, which is the
 * pair whoever raises it needs. It is not truncated: an observation quietly
 * missing half the routes plans a machine back to a state nobody asked for,
 * and `total`-past-the-bound -- the parser's arrangement -- is right for a
 * renderer and wrong for the input to a planner.
 */
#define NCFG_OBSERVE_RECORDS_MAX 1048576u

/*
 * How long one receive waits before a round of dumps gives up.
 *
 * The Rust's, unchanged. It applies only where this module opens the socket:
 * a caller handing one over has already decided, and `ncfg_netlink_set_timeout`
 * is how it decided.
 */
#define NCFG_OBSERVE_TIMEOUT_SECONDS 5

/*
 * One request and the replies it drew, however the caller performs one.
 *
 * **The seam that keeps a kernel out of the tests.** Everything below it is
 * the same code on a live machine and on bytes a test wrote: the requests are
 * built by the modules that own them, the replies are decoded by the decoders,
 * and the only thing that changes is where the datagrams came from. Without it
 * the seven dumps could be exercised only against whatever the developer's
 * machine happened to be doing at the time -- and never at all against a
 * truncated final message, a kernel answering `ENOBUFS` mid-dump, or a dump one
 * record past what this will hold, none of which a kernel produces on demand.
 *
 * The signature is `ncfg_netlink_request`'s without its socket, so the live
 * implementation is a forwarding call and cannot drift from it.
 */
typedef int (*ncfg_observe_exchange_t)(void *context, uint16_t kind, uint16_t flags,
    const ncfg_buf_t *body, const ncfg_buf_t *attrs, ncfg_netlink_reply_t *out, char *err,
    size_t err_size);

/* Whatever performs this round's requests, and the ceiling it holds records
 * to. */
typedef struct {
	ncfg_observe_exchange_t exchange;
	void                   *context;
	/* 0 means `NCFG_OBSERVE_RECORDS_MAX`. It is a field for the reason
	 * `ncfg_netlink_request_from`'s initial size is a parameter: the kernel
	 * will not produce an oversized answer on demand, so a test that could
	 * not lower this could never reach the refusal at all. */
	size_t                  records_max;
} ncfg_observe_kernel_t;

/* The exchange that speaks to a socket. `context` is an open `ncfg_netlink_t
 * *`, and this is exactly `ncfg_netlink_request` with its arguments in the
 * seam's order. */
int ncfg_observe_exchange_socket(void *context, uint16_t kind, uint16_t flags,
    const ncfg_buf_t *body, const ncfg_buf_t *attrs, ncfg_netlink_reply_t *out, char *err,
    size_t err_size);

/*
 * Where a replayed round of dumps reads its datagrams from.
 *
 * `ncfg_netlink_change_from` is split out of the watcher for this reason and
 * this is the same split one layer up: the whole of a round of dumps minus the
 * send. `recv` is the source `netlink.h` already defines, and it is asked for
 * datagrams until each dump is complete.
 */
typedef struct {
	ncfg_netlink_recv_t recv;
	void               *context;
	/* The buffer each reply starts in. 0 means
	 * `NCFG_NETLINK_REPLY_INITIAL`, and a small number reaches the growth
	 * path the way a single oversized message does. */
	size_t              initial;
	/*
	 * The sequence number the next reply is matched against, incremented
	 * per exchange as a socket's is.
	 *
	 * Left at 0 it matches everything, since netlink's own "nobody asked for
	 * this" is sequence number 0 and `ncfg_netlink_collect` lets it through.
	 * That is the useful default for a source whose datagrams were written
	 * by hand.
	 */
	uint32_t            seq;
} ncfg_observe_replay_t;

/* The exchange that sends nothing and reads from `context`, an
 * `ncfg_observe_replay_t *`. The request is still built, and a buffer that
 * failed building it is still refused: what is dropped is only the send. */
int ncfg_observe_exchange_replay(void *context, uint16_t kind, uint16_t flags,
    const ncfg_buf_t *body, const ncfg_buf_t *attrs, ncfg_netlink_reply_t *out, char *err,
    size_t err_size);

/*
 * One round of dumps, and the storage the snapshot in it borrows.
 *
 * `ncfg_observe_snapshot_t` borrows every field and has no free, which its own
 * comment says in as many words -- so something has to own the arrays, and this
 * is it. `snapshot` is filled in pointing at the arrays beside it, so a caller
 * that has a capture has an argument for `ncfg_observe_build` without writing
 * fourteen assignments and getting one of them wrong.
 *
 * **Do not copy it by value.** `snapshot` points into *this* capture, so a
 * copy's snapshot describes the original's arrays and outlives them the moment
 * the original is freed. Pass a pointer, and free the one that was filled in.
 */
typedef struct {
	ncfg_link_record_t        *links;
	size_t                     link_count;
	ncfg_address_record_t     *addresses;
	size_t                     address_count;
	ncfg_route_record_t       *routes;
	size_t                     route_count;
	ncfg_bridge_vlan_record_t *bridge_vlans;
	size_t                     bridge_vlan_count;
	ncfg_qdisc_record_t       *qdisc_roots;
	size_t                     qdisc_root_count;
	ncfg_observe_redirect_t   *redirects;
	size_t                     redirect_count;
	ncfg_rule_record_t        *rules;
	size_t                     rule_count;
	/*
	 * Interfaces carrying an ingress qdisc, sorted and deduplicated.
	 *
	 * Not part of the snapshot and kept anyway: it is what the filter dumps
	 * were aimed at, so an empty `redirects` beside an empty list of hooks
	 * is a machine with no ingress shaping, and an empty `redirects` beside
	 * three hooks is three dumps that found nothing. Those are different
	 * facts and the snapshot cannot tell them apart.
	 */
	uint32_t                  *ingress_hooks;
	size_t                     ingress_hook_count;
	/*
	 * Payloads a decoder refused, across every dump.
	 *
	 * `netlink.h` says a caller that dumps and decodes skips what it cannot
	 * read **and says how many**, which is the half the Rust's `filter_map`
	 * leaves out: a truncated dump and a quiet machine look the same
	 * afterwards.
	 */
	size_t                     skipped;
	/* Interfaces whose filter dump could not be read. See
	 * `ncfg_observe_collect_from` for why that is a count rather than a
	 * refusal. */
	size_t                     redirects_unreadable;
	/*
	 * Datagrams discarded across this round because they did not come from
	 * the kernel. Nonzero means somebody local is writing to the socket,
	 * which is worth a line in a log even though nothing went wrong.
	 */
	size_t                     dropped;
	/*
	 * The first sentence either count above produced, or empty.
	 *
	 * One buffer and not one per event: a count with no sentence is a number
	 * nobody can act on, and a sentence per payload is a log nobody reads.
	 */
	char                       note[NCFG_ERROR_MAX];
	/* Borrowing every array above. */
	ncfg_observe_snapshot_t    snapshot;
} ncfg_observe_capture_t;

/* Release everything a capture owns, including each link record's alternative
 * names, and leave it empty. Freeing one that was never filled in is nothing,
 * which is what makes every failure path here one line. */
void ncfg_observe_capture_free(ncfg_observe_capture_t *capture);

/*
 * Take one round of dumps over `kernel` and decode it.
 *
 * Seven requests in a fixed order -- links, addresses, routes, bridge VLANs,
 * qdiscs, one filter dump per ingress hook, rules -- which is the Rust's order
 * and is kept because the fifth decides how many the sixth is.
 *
 * **A dump that fails, fails the round.** A snapshot missing its routes is not
 * a smaller answer to the same question, it is a plan that installs them all
 * again; so the capture is freed and a sentence comes back. The one exception
 * is a *filter* dump, which is asked per interface and is counted in
 * `redirects_unreadable` instead: the interface was reported as carrying an
 * ingress hook by a dump taken a moment earlier, so a failure now is a machine
 * that moved between two requests, and a USB device being unplugged must not
 * be able to deny an observation to the operator looking at why it went.
 *
 * A payload a decoder refuses is skipped and counted, which is what
 * `netlink.h` asks of a caller that dumps.
 */
int ncfg_observe_collect_from(const ncfg_observe_kernel_t *kernel,
    ncfg_observe_capture_t *out, char *err, size_t err_size);

/* The same over an open socket, whose timeout is the caller's to have set. */
int ncfg_observe_collect_on(ncfg_netlink_t *netlink, ncfg_observe_capture_t *out, char *err,
    size_t err_size);

/*
 * The same, opening and closing a socket of its own.
 *
 * `NCFG_OBSERVE_TIMEOUT_SECONDS` is set on it, because a receive with no
 * timeout wedges the caller for ever and this one has no caller to have
 * decided otherwise.
 */
int ncfg_observe_collect(ncfg_observe_capture_t *out, char *err, size_t err_size);

/* ------------------------------------------------------------------------ *
 * What netcfgd wrote down
 * ------------------------------------------------------------------------ */

/*
 * One object netcfgd installed, and which source asked for it.
 *
 * Field for field `ncfg_owned_object_t`, which is the on-disk form; borrowed
 * here rather than copied, because a prior state is read once and thrown away
 * and a second allocation of two strings buys nothing.
 */
typedef struct {
	const char *interface;
	/* The address in CIDR form, or the route's destination. */
	const char *key;
	int         origin; /* ncfg_origin_t */
} ncfg_observe_owned_t;

/*
 * What netcfgd recorded about its own past actions.
 *
 * Read from `/run/netcfgd/` by whoever calls this, which is the arrangement
 * the Rust has: `netcfgd-host` reads the files and this module consumes the
 * result, so the observer stays testable against a record a test wrote in ten
 * lines.
 *
 * Three things the kernel cannot tell us live here: which links netcfgd
 * created, which source produced each address and route, and which backends it
 * started.
 *
 * **The name lists are borrowed and the six aggregate lists are handed over.**
 * `ncfg_observe_build` takes `backends`, `dns`, `backend_restarts`,
 * `hook_state`, `delegations` and `reports` into the observation and leaves
 * these members NULL and zero -- see the divergence note at the top of this
 * file for why a copy is not made. A prior is therefore good for exactly one
 * `build`, which is how many any caller performs: the daemon reads `/run`
 * afresh on every cycle.
 */
typedef struct {
	/* Names of links netcfgd created. Borrowed. */
	char *const               *created_links;
	size_t                     created_link_count;
	/* `(interface, cidr, origin)` for each address netcfgd installed. */
	const ncfg_observe_owned_t *address_origins;
	size_t                      address_origin_count;
	/* `(interface, destination, origin)` for each route. */
	const ncfg_observe_owned_t *route_origins;
	size_t                      route_origin_count;
	/* Interfaces netcfgd turned each sysctl on for. Borrowed and copied
	 * into the observation, because `qdisc` and `ingress` are folded with
	 * what the kernel says and the other three are not. */
	char *const               *forwarding;
	size_t                     forwarding_count;
	char *const               *privacy;
	size_t                     privacy_count;
	char *const               *accept_ra;
	size_t                     accept_ra_count;
	char *const               *qdisc;
	size_t                     qdisc_count;
	char *const               *ingress;
	size_t                     ingress_count;
	/* Handed over. */
	ncfg_observed_backend_t    *backends;
	size_t                      backend_count;
	ncfg_applied_dns_t         *dns;
	size_t                      dns_count;
	ncfg_backend_restart_t     *backend_restarts;
	size_t                      backend_restart_count;
	ncfg_observed_hook_state_t *hook_state;
	size_t                      hook_state_count;
	/*
	 * Prefixes a DHCPv6 client reported.
	 *
	 * Prior state rather than a kernel read because a delegated prefix is
	 * not kernel state: nothing in the kernel knows the machine was given a
	 * /56 until an address is derived from it. The client is the only
	 * source, and netcfgd does not implement the client (0004).
	 */
	ncfg_delegation_t          *delegations;
	size_t                      delegation_count;
	/*
	 * What helpers and daemons reported about interfaces.
	 *
	 * Prior state for the reason a delegation is: the configuration a
	 * cellular bearer or a tunnel comes up with is known to whatever
	 * negotiated it, and netcfgd negotiates neither (0044, 0045, 0047).
	 */
	ncfg_observed_report_t     *reports;
	size_t                      report_count;
} ncfg_observe_prior_t;

/* Free what a prior still owns -- which after a `build` is nothing. Freeing
 * one that was never filled in is nothing, and the borrowed members are left
 * alone. */
void ncfg_observe_prior_free(ncfg_observe_prior_t *prior);

/* ------------------------------------------------------------------------ *
 * The three judgements that decide what may be deleted
 * ------------------------------------------------------------------------ */

/*
 * Whether a link is netcfgd's, from the kernel first and the record second.
 *
 * The marker is matched **by its prefix rather than by the whole name**,
 * because the name carries what the link was *called* when netcfgd made it and
 * a link can be renamed afterwards. Matching the whole string would make a
 * rename look like a change of owner.
 *
 * **A recorded link with no marker is still ours**, which is what keeps this
 * additive: a link created by an older netcfgd carries no alternative name,
 * and a kernel that refused `RTM_NEWLINKPROP` left one unmarked on purpose.
 *
 * **An unmarked, unrecorded link is `unknown` rather than `foreign`.** netcfgd
 * did not make `eth0`, and saying so positively would claim to know something
 * about every physical device on the machine.
 */
int ncfg_observe_link_ownership(char *const *altnames, size_t altname_count, int recorded);

/*
 * Whether an address is netcfgd's.
 *
 * Given a name of its own because it is the one judgement here that can lose a
 * user their address, and it should be reviewable on its own.
 *
 * Where the kernel supports `IFA_PROTO` it is **authoritative**: an address
 * with somebody else's tag, or with none, is theirs whatever netcfgd wrote
 * down, because a stale record must not be able to claim an address back.
 * Pre-5.18 there is no tag to read, so the record is all there is -- and it
 * cannot tell netcfgd's address from an identical one added by hand, so a
 * match is `unknown` and nothing is removed on the strength of it. Decision
 * 0002 says the fallback is weaker; this is how much.
 */
int ncfg_observe_address_ownership(int has_proto, uint8_t proto, int proto_supported,
    int recorded);

/*
 * The origin an object's kernel tag implies, when nothing was recorded.
 *
 * **netcfgd's tag has exactly one producer, and that is what makes this
 * sound.** The one call site that adds an address and the one that adds a
 * route both stamp 110 and both record `static`, so an object wearing the tag
 * was put there by netcfgd from config and there is no other way for it to be
 * wearing it. A lease's address belongs to the DHCP client, which installs it
 * under its own protocol number and never under this one.
 *
 * **Why it is needed.** Ownership survives the loss of `/run` because the
 * kernel carries the tag, but origin did not, and every teardown path gates on
 * `origin == static` before it gates on anything else. So a netcfgd that lost
 * its record kept the tag, read the address as ours, and then declined to
 * touch it -- it could tell the address was its own and not that it was
 * allowed to remove it.
 *
 * The record still wins where it exists, which is what keeps this a fallback:
 * a pre-5.18 kernel has no `IFA_PROTO` to read, and a DHCP address recorded as
 * `dhcp4` must stay `dhcp4` even though netcfgd's own tag is absent from it.
 */
ncfg_optint_t ncfg_observe_tagged_origin(int has_proto, uint8_t proto);

/* ------------------------------------------------------------------------ *
 * The observation
 * ------------------------------------------------------------------------ */

/*
 * Turn a kernel snapshot plus recorded state into the observed model.
 *
 * `roots` supplies `/sys/class/net`, which is the one thing this reads: a
 * link's `wireless` cannot come from its kind -- a radio reports an empty kind
 * exactly as an ethernet port does -- and it must not come from the document,
 * because a `device` block's `wifi` section carries things meaningful on
 * anything. It is the same predicate `ncfg wifi add` uses, shared rather than
 * repeated.
 *
 * The lists come back canonicalised, so two observations of one machine
 * compare equal regardless of the order netlink dumped them in.
 *
 * `prior` is left holding none of its aggregate lists; see its comment.
 */
int ncfg_observe_build(const ncfg_observe_snapshot_t *snapshot, ncfg_observe_prior_t *prior,
    const ncfg_observe_roots_t *roots, ncfg_observed_t **out, char *err, size_t err_size);

/* ------------------------------------------------------------------------ *
 * The parts that are not netlink
 * ------------------------------------------------------------------------ *
 *
 * **Nothing in here fails an observation.** A container with no writable
 * `/proc/sys`, a kernel without `CONFIG_RFKILL`, a machine with no Bluetooth:
 * all ordinary, and the honest reading in each case is "netcfgd cannot tell",
 * which is what an absent optional and an empty list say. A daemon that
 * refused to start on a kernel that simply lacks a feature nobody asked for
 * would be worse than one that says nothing about it.
 */

/*
 * Whether an interface forwards, from both families' sysctls.
 *
 * Present and true needs **both**. A machine with IPv4 forwarding on and IPv6
 * off routes half its traffic and drops the other half at the router, which is
 * a state worth planning a change out of rather than reporting as configured.
 * One family readable and the other missing is an IPv6-disabled kernel, where
 * reporting the IPv4 answer alone would have the planner satisfied by half a
 * change it can never complete -- so that is absent.
 */
ncfg_optbool_t ncfg_observe_forwarding(const char *proc_root, const char *name);

/*
 * Whether one interface prefers a temporary address.
 *
 * True for the kernel's `2` and nothing else: `1` generates a temporary
 * address and prefers the stable one, which is a state nothing in the document
 * can request and netcfgd therefore does not claim as its own. Absent where
 * the file is not there at all.
 */
ncfg_optbool_t ncfg_observe_privacy(const char *proc_root, const char *name);

/*
 * What this interface will do with a router advertisement.
 *
 * Two files, read together, because neither answers on its own: `accept_ra=1`
 * is the kernel's default and means "accept unless this interface forwards",
 * so the same value is the working state on a laptop and the broken one on a
 * router (0073).
 *
 * The forwarding file read here is the **IPv6** one alone. A link's
 * `forwarding` is true only when both families forward, which is the right
 * answer to a different question. A forwarding sysctl that cannot be read is
 * taken as off, which is the kernel's own default for an interface: the value
 * that is *there* is `accept_ra`, and refusing to answer because its neighbour
 * is missing would report "cannot tell" on a machine where it plainly can.
 *
 * 1 with `*out` filled in, 0 where there is no `accept_ra` to read -- which is
 * absence rather than a failure, so there is no error buffer.
 */
int ncfg_observe_accept_ra(const char *proc_root, const char *name,
    ncfg_observed_accept_ra_t *out);

/*
 * The running hostname, or NULL where it could not be read.
 *
 * `/proc/sys/kernel/hostname` rather than `gethostname`, because the file is
 * the same value and is a path a test can point somewhere else. Trimmed: the
 * kernel's file ends in a newline and the config's string does not. The caller
 * owns what comes back.
 */
char *ncfg_observe_hostname(const char *proc_root);

/*
 * Whether one interface's radio is switched off.
 *
 * Two reads and a search. `class/net/<iface>/phy80211/name` is the phy this
 * interface belongs to and exists only for a radio, so anything wired answers
 * with no switch and no special case. Then the `class/rfkill` entry whose
 * `name` is that phy carries `soft` and `hard`.
 *
 * **The phy's own switch, deliberately.** A laptop has a second `wlan` entry
 * for the platform button -- `dell-wifi` beside `phy0` on the machine 0062 was
 * written on -- and reading that one would report a block for a different
 * radio on a machine with two cards.
 *
 * **An entry whose `name` cannot be read is skipped rather than fatal.** The
 * Rust's first version returned from the whole function there, and since the
 * search is sorted, an unreadable entry sorting before the phy's own decided
 * for every entry after it: a soft-blocked radio came back with no switch at
 * all and the warning that explains an empty scan vanished. A USB dongle being
 * unplugged tears its directory down between the listing and the read, and
 * that teardown is also what generates the event the observation runs on, so
 * the window and the trigger coincide.
 *
 * **A flag that cannot be read is not a flag that is clear**, which is the
 * other half and points the other way: both flags are required on the entry
 * that *is* ours, so a truncated entry reports nothing rather than a radio
 * that looks fine.
 *
 * Returns 1 with `*out` set, or 1 with `*out` NULL where there is no switch to
 * report -- which is not a failure and is what nothing is planned on (0062).
 * 0 with a sentence is a real failure. The caller frees `*out`.
 */
int ncfg_observe_rfkill(const char *sys_root, const char *iface, ncfg_observed_rfkill_t **out,
    char *err, size_t err_size);

/*
 * The Bluetooth adapters this machine has, and whether each is blocked.
 *
 * **`class/bluetooth`, and nothing else.** BlueZ is D-Bus and nothing else,
 * and 0014 keeps D-Bus out of the core -- so what is read is what the kernel
 * puts in sysfs, which is the adapter's existence and its rfkill node. An
 * address, a name and a powered state all come from the management socket or
 * from bluetoothd, and neither is the core's to hold.
 *
 * **The switch is found through the adapter's own directory, not by name.** A
 * laptop has a platform Bluetooth switch as well as the adapter's, and
 * searching `class/rfkill` for a bluetooth entry would find whichever came
 * first. `class/bluetooth/hci0/rfkill*` is the adapter's own, which is the one
 * its driver obeys -- the same mistake the wifi search records having made,
 * avoided here by construction rather than by remembering.
 *
 * Sorted by name. An empty list is the honest answer for a machine with no
 * adapter, which is most servers.
 */
int ncfg_observe_bluetooth(const char *sys_root, ncfg_observed_bluetooth_t **out,
    size_t *count_out, char *err, size_t err_size);

/*
 * Fill in everything a netlink snapshot could not supply and this port can.
 *
 * The sysctls on every link, the hostname, each radio's switch and the
 * Bluetooth adapters. See the header comment for the passes that are deferred
 * and what each waits on.
 *
 * **It does not derive.** `ncfg_observe_derive` is separate for the reason
 * that function's comment gives, and a caller that wants both calls both --
 * which is what the daemon does, twice.
 */
int ncfg_observe_augment_host(ncfg_observed_t *observed, const ncfg_observe_roots_t *roots,
    char *err, size_t err_size);

/* ------------------------------------------------------------------------ *
 * The NAT this machine has, netcfgd's and anybody else's
 * ------------------------------------------------------------------------ */

/*
 * Fill in `nat` and `nat_conflicts` from a round of nftables dumps.
 *
 * **Its own exchange, because nftables is its own protocol.** `collect.c`'s
 * seven dumps go over `NETLINK_ROUTE`; these two go over
 * `NCFG_NFT_NETLINK_PROTOCOL`, which is a different socket, so this is a
 * second `ncfg_observe_kernel_t` rather than an eighth dump in the first
 * round. The seam is the same one and for the same reason: the cases that
 * matter here -- a rule from a table netcfgd does not own, a chain dump with a
 * payload in it that will not read, a kernel that answers nothing at all --
 * are not cases a kernel produces on demand.
 *
 * **What its absence cost, said once here.** `nat` is what netcfgd's own table
 * masquerades now, and the planner compares the document against it; with
 * nothing filling it the comparison was against an empty list, so a machine
 * whose NAT was already right was planned a `nat.replace` on every pass and
 * never converged -- and the op's *inverse* is that same list, so a revert
 * would have removed the table rather than putting back what was there.
 * `nat_conflicts` is decision 0022's other half: a second table doing source
 * NAT at the same hook double-translates, and netcfgd reports it and touches
 * nothing.
 *
 * **A kernel that will not answer is not a failure.** No `nf_tables`, a
 * netlink this process may not ask, and a machine where netcfgd never
 * installed a table are the same answer to a planner -- no NAT is installed --
 * which is what `observed.h` says where the field is declared. Both lists come
 * back empty and a note says which it was. `kernel` may itself be NULL, which
 * is the seam left out: the lists are cleared and nothing is asked.
 *
 * 0 with a sentence is a fault in netcfgd rather than in the machine: an
 * allocation that failed, a request this port could not build, or netcfgd's
 * own chain holding more masquerade rules than an observation carries.
 */
int ncfg_observe_netfilter_from(const ncfg_observe_kernel_t *kernel, ncfg_observed_t *observed,
    char *err, size_t err_size);

/*
 * The same, opening and closing a netfilter socket of its own.
 *
 * `NCFG_OBSERVE_TIMEOUT_SECONDS` on it, for `ncfg_observe_collect`'s reason. A
 * socket that will not open is the commonest way a kernel says it has no
 * nftables, so it is a note and an empty answer rather than a refusal.
 */
int ncfg_observe_netfilter(ncfg_observed_t *observed, char *err, size_t err_size);

/* ------------------------------------------------------------------------ *
 * Which driver offloads each interface has on
 * ------------------------------------------------------------------------ */

/*
 * Fill in each link's `offloads` from one `FEATURES_GET` per interface.
 *
 * **A third exchange, because ethtool is a third protocol.** It is a generic
 * netlink family, and `netlink.h` says a family id resolved on one socket is
 * meaningless on another -- so this is neither an eighth dump on the route
 * socket nor a third question on the netfilter one. The seam is named for the
 * protocol rather than for the family: one generic netlink socket carries
 * every family, and the two WireGuard passes above will ask theirs over this
 * one rather than open a fourth.
 *
 * **One request per link and no dump**, because ethtool has none: its messages
 * are per-device by construction. A handful of round trips on a laptop and a
 * few dozen on a router, each costing microseconds.
 *
 * **What its absence cost, said once here.** `link.set_offloads` is planned by
 * comparing the document's `ethtool` block against this list, and with nothing
 * filling it the comparison was against an empty one: a machine whose offloads
 * were already right was planned a `link.set_offloads` on every pass and never
 * converged, and the op's inverse -- built out of the same list -- would have
 * turned every named feature off rather than putting back what was there. That
 * is `ncfg_observe_netfilter_from`'s paragraph one field along, and it is the
 * same paragraph because it was the same defect.
 *
 * **Only the names the model can express**, which is `ncfg_offload_field_names`
 * and nothing else: a device reports dozens and `observed.h` says where the
 * field is declared why storing all of them would be a page of driver detail
 * in `/run` for five fields. The list comes back sorted and without repeats, so
 * two observations of one machine compare equal.
 *
 * **What `ACTIVE` does not say.** The reply also carries `WANTED` and
 * `NOCHANGE`, and this reads neither -- so a feature the device forces on is
 * reported on although a `link.set_offloads` cannot move it, and the planner
 * asks again on every pass. Measured on a live machine; project.md 10.185 has
 * it, and closing it needs a third state on this field rather than a change
 * here.
 *
 * **A kernel or a device that will not answer is not a failure.** A kernel
 * older than 5.6 has no `ethtool` family; a device with no ethtool operations
 * answers `EOPNOTSUPP`, which is most virtual interfaces; a container's
 * netlink may be denied. All three leave a list empty, which `observed.h`
 * already says means off or unsupported, and a note says which it was.
 * `genl` may itself be NULL, which is the seam left out: every list is cleared
 * and nothing is asked.
 *
 * 0 with a sentence is an allocation that failed, and nothing else.
 */
int ncfg_observe_offloads_from(const ncfg_observe_kernel_t *genl, ncfg_observed_t *observed,
    char *err, size_t err_size);

/*
 * The same, opening and closing a generic netlink socket of its own.
 *
 * `NCFG_OBSERVE_TIMEOUT_SECONDS` on it, for `ncfg_observe_collect`'s reason. A
 * socket that will not open is a note and an empty answer rather than a
 * refusal.
 */
int ncfg_observe_offloads(ncfg_observed_t *observed, char *err, size_t err_size);

/* ------------------------------------------------------------------------ *
 * What each WireGuard device is running, and whether it is current
 * ------------------------------------------------------------------------ */

/*
 * Fill in each WireGuard link's device state from one `GET_DEVICE` per
 * interface.
 *
 * **The offloads round's socket, a second family on it.** `wireguard` is
 * another generic netlink family, so this takes the same `genl` exchange
 * rather than a fourth socket -- which is why `observe_genl_open` is named for
 * the protocol. The family id is resolved once per observation, and **only
 * where a link of kind `wireguard` exists**: a machine with none makes no
 * controller request at all, on every tick, for ever.
 *
 * **Nothing observed here is secret, and the asymmetry is the kernel's.** A
 * `GET_DEVICE` reports the public key it derived from the private one and
 * never the private one; a peer's preshared key comes back as 32 zero octets,
 * which `sys/wg.c` reads as a boolean and drops. `private_key_loaded` is asked
 * as "does the kernel report a public key", which is the only reason that key
 * is reported at all.
 *
 * **What its absence cost is not what NAT's or the offloads' was.** Those two
 * filled a list the planner compared against, so an empty one planned the same
 * op for ever. `ncfg_plan_wireguard` returns without planning anything for a
 * link with no `wireguard` observation at all, so what this pass was missing
 * bought the opposite failure: an edited listen port, an edited mark, a
 * rotated key and a **deleted peer** each planned nothing whatever, on a
 * tunnel that looked configured (0054).
 *
 * **So a device that could not be read stays NULL rather than becoming an
 * empty one.** A device the kernel would not answer for, a family that would
 * not resolve and a reply that would not read all leave `link->wireguard` at
 * NULL, which the model already means "not observed" by -- an observed device
 * with no key is present with `public_key.has` clear. Reporting one as the
 * other would tell the planner every peer was missing and have it replace a
 * peer list it never saw, which is a working tunnel rebuilt from a guess. That
 * is the one place this pass reads an absence differently from
 * `ncfg_observe_netfilter_from`, which is right to call a socket it could not
 * open "no NAT installed".
 *
 * `genl` may itself be NULL, which is the seam left out: every link's
 * observation is cleared and nothing is asked.
 *
 * 0 with a sentence is an allocation that failed, and nothing else.
 */
int ncfg_observe_wireguard_from(const ncfg_observe_kernel_t *genl, ncfg_observed_t *observed,
    char *err, size_t err_size);

/*
 * The same, opening and closing a generic netlink socket of its own.
 *
 * `NCFG_OBSERVE_TIMEOUT_SECONDS` on it, for `ncfg_observe_collect`'s reason. A
 * socket that will not open is a note and nothing observed rather than a
 * refusal.
 */
int ncfg_observe_wireguard(ncfg_observed_t *observed, char *err, size_t err_size);

/*
 * Whether the key each device is running is the key its configuration names.
 *
 * **A currency question, not an observation of a secret.** The kernel reports
 * the public key it derived and nothing that could be compared against a
 * private one, and deriving a public key from the store's would mean
 * curve25519 -- which project.md carried for a long time as the reason a
 * rotated key could not be noticed. It is not the reason: netcfgd hashes the
 * key it loaded when the kernel accepted it and writes the digest under
 * `/run`, this hashes what the store holds now, and what comes out of the
 * comparison is a boolean. Decision 0052's shape, which 0053 and 0055 already
 * use for an access point's passphrase and a tunnel's configuration file.
 *
 * **A digest of a WireGuard key is not a way back to one**: it is 32 octets of
 * kernel randomness, with no dictionary and no structure to attack -- which is
 * why the same technique would be a poor answer for a passphrase. The record
 * is netcfgd's to write 0600; nothing here writes one, and what leaves this
 * call is `key_matches` and `preshared_matches` and nothing else. No key, no
 * digest and nothing else that would identify one reaches an error buffer, a
 * log line or the observation written to `/run`.
 *
 * **Absent is not false, in either answer.** A device netcfgd never
 * configured, a `/run` cleared under a running daemon, a peer with no record
 * and a secret that will not resolve all leave the question unanswered -- and
 * an unanswered question is not a reason to rekey a working tunnel, which is
 * why `plan/wireguard.c` reads `has` before `value`.
 *
 * `secrets` of NULL is the seam left out and means the question is not asked;
 * it never means the machine's own store. An observer that reached
 * `NCFG_SECRETS_DIR_DEFAULT` for itself would read the developer's real
 * credentials the first time a test forgot to override it, which is this
 * header's rule about the three roots pointed at the one directory where it
 * matters most. `desired` of NULL and an empty `run_dir` are the same "nothing
 * to ask", and both are ordinary.
 *
 * 0 with a sentence only where there is no observation to write into.
 */
int ncfg_observe_wireguard_currency(ncfg_observed_t *observed, const char *run_dir,
    const ncfg_secret_resolver_t *secrets, const ncfg_document_t *desired, char *err,
    size_t err_size);

/*
 * Where netcfgd records which key it loaded into a device, and which preshared
 * key each of its peers was given.
 *
 * `<run>/wireguard/<iface>.key.sha256` and `<run>/wireguard/<iface>.psk.sha256`,
 * which are the Rust's two spellings. Declared here rather than beside the
 * writer because **there is no writer yet**: `NCFG_OBSERVE_ALTNAME_PREFIX`
 * above is the same arrangement for the same reason, and the point of both is
 * that the half which lands second uses the spelling the first agreed to
 * rather than writing the string again.
 *
 * The preshared record is one line per peer that has one, `<public key in
 * base64> <digest>`, keyed by the only name the kernel and the document share.
 *
 * `out_size` should be `NCFG_OBSERVE_WG_RECORD_PATH_MAX`. 1 with the path; 0
 * with a sentence for a run directory or an interface that was not given, or a
 * join that did not fit -- `err` may be NULL, which every caller here uses,
 * because a path that did not fit names some other file rather than a longer
 * version of this one and the answer is the same either way: no record.
 */
#define NCFG_OBSERVE_WG_RECORD_PATH_MAX (NCFG_OBSERVE_RUN_DIR_MAX + 256u)

int ncfg_observe_wg_key_record_path(const char *run_dir, const char *iface, char *out,
    size_t out_size, char *err, size_t err_size);

int ncfg_observe_wg_preset_record_path(const char *run_dir, const char *iface, char *out,
    size_t out_size, char *err, size_t err_size);

/*
 * The digest netcfgd records for a key it handed the kernel.
 *
 * **One rule, because the two halves of a comparison must not spell it
 * differently.** The observer digests what the store holds now and compares it
 * against this record; the executor digests what it just sent and writes it.
 * A writer that hashed the base64 text while the reader hashed the octets
 * would produce a record that never matches, so `key_matches` would be false
 * for ever and the planner would re-send a key the kernel already holds on
 * every reconcile.
 *
 * The rule: trim the material, and **if it parses as a WireGuard key, hash the
 * thirty-two octets** rather than the text. That is what makes two spellings
 * of one key compare equal -- base64's final character carries four
 * significant bits, so `document.h` says the same key has more than one
 * spelling, and hashing the text would make a re-encoded store entry read as a
 * rotation. Anything that does not parse is hashed as it stands, which is the
 * honest answer for material that is not a key at all.
 *
 * `out` is `NCFG_SHA256_HEX_SIZE` bytes and is always filled. The octets are
 * wiped before returning, which is `secrets.h`'s discipline: a digest is not a
 * secret, and the buffer it was computed from is.
 */
void ncfg_observe_wg_digest(const char *material, size_t length, char *out);

/* ------------------------------------------------------------------------ *
 * The answers that are computed rather than read
 * ------------------------------------------------------------------------ */

/*
 * How far this machine has got, and through what.
 *
 * **One function, four callers.** The Qt tray computed three rungs from the
 * links, the TDE tray transcribed the same rule into TQt3, the NetworkManager
 * shim answered a coarser pair and the text interface had no notion of it --
 * so each invented a slightly different verdict from one observation.
 *
 * Where the document declares an `uplink` set, **that set is the answer**: a
 * machine whose operator said which links carry its traffic has said what
 * connected means on it, and a verdict assembled from every other link would
 * contradict the thing they wrote down.
 *
 * `policy` may be NULL, which is the default policy -- a default route, and
 * the ignore list every document gets that says nothing.
 *
 * 1 with an allocated verdict in `*out`, which the caller frees; 0 with a
 * sentence.
 */
int ncfg_connectivity_overall(const ncfg_observed_t *observed,
    const ncfg_connectivity_policy_t *policy, ncfg_connectivity_t **out, char *err,
    size_t err_size);

/*
 * The answers that are computed from an observation rather than read: the
 * categories, the link inventory, what each linkset chose and the connectivity
 * verdict.
 *
 * Four things that are functions of the links, the addresses, the routes, the
 * probe verdicts and the document, and nothing else. Pure, and therefore safe
 * to run twice.
 *
 * **Separate from `augment` because one of its inputs arrives after it.** The
 * daemon stamps probe verdicts onto a fresh observation *after* the
 * observation is built -- the observer reads the kernel and no probe result
 * comes from there -- so an `uplink` set computed inside `augment` was computed
 * from an absent `reachable` on every link, and the published choice named the
 * better-ranked link while the planner, which reads the stamped observation,
 * had just taken that link's routes away. `connectivity` with
 * `requires = "probe"` had it too: the rung could never reach `online`,
 * because the verdict it asks for had not been written yet. Both were found by
 * the live linkset test, on the case metrics cannot handle -- a link that is
 * up, has carrier and reaches nothing looks identical to a working one from
 * the routing table.
 *
 * **So the daemon calls this again once the verdicts are on.** Everything here
 * is derived, so running it twice costs one pass over the links and changes
 * nothing that was already right.
 *
 * `document` may be NULL, which classifies links by their kernel kind, lists
 * no sets and judges connectivity by the default policy.
 */
int ncfg_observe_derive(ncfg_observed_t *observed, const ncfg_document_t *document, char *err,
    size_t err_size);

/* ------------------------------------------------------------------------ *
 * The four of them, in one call
 * ------------------------------------------------------------------------ */

/*
 * Room for the run directory the record is read out of.
 *
 * `NCFG_OBSERVE_ROOT_MAX` again rather than a fourth opinion about how long a
 * directory may be: it is the same question the three roots ask, and a second
 * number here would be a ceiling that disagrees with `ncfg_state_resolve_dir`'s
 * caller on one machine and nowhere else.
 */
#define NCFG_OBSERVE_RUN_DIR_MAX NCFG_OBSERVE_ROOT_MAX

/*
 * Collect, build, augment and derive: the machine, as an observation.
 *
 * **One call because there are two callers.** The daemon reobserves on every
 * tick and `ncfg status`, `ncfg plan`, `ncfg explain` and `ncfg wait-online`
 * each take one of their own, and a second copy of this sequence is how the
 * two would come to disagree about what netcfgd can see -- which is not a
 * hypothetical in this tree: `netcfgd_host::prior_state` exists in the Rust
 * with that reason written above it, because the delegations had been folded
 * in on one side and not the other.
 *
 * The order is `netcfgd_observe::current`'s with `derive` after it: the
 * kernel, then what netcfgd wrote down, then the nftables round, then the
 * files the kernel cannot answer for, then the answers computed from all four.
 * **`derive` is inside rather than left to the caller** because a caller that
 * forgot it gets an observation with no link inventory, no linkset choices and no connectivity
 * rung -- and that is not an error, it reads as a machine that has none of
 * those things. The daemon calls `ncfg_observe_derive` a second time once the
 * probe verdicts are stamped on, which is what that function's own comment
 * asks for and is why running it twice has to cost nothing.
 *
 * `run_dir` is where `owned.json`, `prefixes/` and the reports are read from.
 * **An unreadable ownership record is not a failure and an unreadable report
 * is**, which is a distinction rather than an inconsistency: `ncfg_owned_read`
 * says why the first fails open -- the worst case is netcfgd under-claiming
 * what is its own, which is the safe direction -- while a delegation or a
 * report carries addressing a helper negotiated and netcfgd did not, so an
 * observation quietly missing them is the input-to-a-planner case that
 * `NCFG_OBSERVE_RECORDS_MAX` refuses for.
 *
 * `desired` may be NULL, and that is an ordinary answer rather than an edge
 * case: `ncfg status` on a machine whose configuration has stopped compiling
 * still observes the kernel, and is exactly when somebody runs it.
 *
 * `netfilter` and `genl` are the second and third exchanges -- the ones
 * `ncfg_observe_netfilter_from` and `ncfg_observe_offloads_from` take -- and
 * **either may be NULL, which is that seam left out**: everything else is
 * observed and the NAT lists, or every link's offloads, come back empty. A
 * test that is not about NAT or about offloads installs nothing, which is
 * `ncfg_reconcile_world_t`'s bargain -- and a test that is about one installs
 * a replay rather than reaching a kernel.
 *
 * **Three arguments and not one**, though all three are the same type: they
 * are three protocols on three sockets, a test drives them one at a time, and
 * a struct holding all three would be a fourth thing to keep in step with the
 * source below, which already holds them.
 *
 * `secrets` is the store the WireGuard currency question is asked of, and
 * **NULL is the seam left out rather than the machine's own store**: an
 * observer that reached `NCFG_SECRETS_DIR_DEFAULT` for itself would read the
 * developer's real credentials the first time a test forgot to override it.
 * It is the only argument here that is not a socket or a path to read under,
 * and it is one for the reason every root is: nothing in this module resolves
 * where to look.
 *
 * 1 with a fresh observation in `*out`, which the caller frees with
 * `ncfg_observed_free`; 0 with a sentence and `*out` NULL.
 */
int ncfg_observe_current_from(const ncfg_observe_kernel_t *kernel,
    const ncfg_observe_kernel_t *netfilter, const ncfg_observe_kernel_t *genl,
    const char *run_dir, const ncfg_observe_roots_t *roots,
    const ncfg_secret_resolver_t *secrets, const ncfg_document_t *desired,
    ncfg_observed_t **out, char *err, size_t err_size);

/*
 * The same, opening and closing a socket of its own.
 *
 * `ncfg_observe_collect`'s round, with `NCFG_OBSERVE_TIMEOUT_SECONDS` on it,
 * for the same reason that call gives: a receive with no timeout wedges the
 * caller for ever and this one has no caller to have decided otherwise.
 */
/*
 * Ask each backend netcfgd believes it is running whether it still is.
 *
 * **`running` in an observation was netcfgd's memory, and this makes it a
 * fact** -- which is what the field has claimed to be all along: *a fact about
 * a process: something is there under that pid*. The record is filled from the
 * prior state, so a daemon that crashed an hour ago went on being reported as
 * running for ever, and 0079's restart could not fire because the cap counts
 * starts of something the record says is already up.
 *
 * **It only ever clears.** A backend the record does not have is not invented
 * here: the record is netcfgd's account of what it started, and a process
 * netcfgd did not start is not netcfgd's whatever its command line says. So
 * this can disprove `running` and never assert it, and a kind it cannot answer
 * for is left exactly as it was.
 *
 * Five of the nine kinds carry a handle netcfgd chose and can be answered:
 * a supplicant and an access point by the pid file `-P` names, a router
 * advertisement daemon by its generated configuration, a tunnel by its
 * management socket, and a DHCP client by the pid file `-p` names.
 * **`dhcpcd` cannot be**, and that is `dhcp.h`'s sentence rather than a gap
 * here: it has no pid file of netcfgd's and no mark in its process image, so
 * `ncfg_dhcpcd_whose` is the question to ask about one. PPPoE, WireGuard and
 * DNS are not processes this port starts.
 *
 * **The `/proc` this reads under is not a parameter, and that is a divergence
 * from every other pass in this header.** The handle answers come from
 * `process.h`, which reaches `/proc` at a fixed path -- that module's right,
 * and this module's rule broken. What it costs is that a test cannot point
 * this at a tree it made; what it does *not* cost is testability, because the
 * backends' own tests already prove this shape by starting real children
 * carrying real markers, which is what `liveness_test.c` does. Recorded rather
 * than worked around: a second `/proc` reader taking a root would be two
 * answers to who owns a pid, and that one is a security property.
 *
 * Answers 1 always, unless there is nothing to walk. Nothing here can fail in
 * a way that should cost the observation: not knowing whether a daemon is
 * alive is an answer, and it is the one already in the record.
 */
int ncfg_observe_backend_liveness(ncfg_observed_t *observed, const char *run_dir, char *err,
    size_t err_size);

int ncfg_observe_current(const char *run_dir, const ncfg_observe_roots_t *roots,
    const ncfg_secret_resolver_t *secrets, const ncfg_document_t *desired,
    ncfg_observed_t **out, char *err, size_t err_size);

/*
 * Everything an observation needs that `ncfg_daemon_observe_fn` cannot carry.
 *
 * That seam takes a document and a `void *`, so the run directory and the
 * three roots have to travel inside the context -- and they travel as storage
 * rather than as pointers for `ncfg_observe_roots_t`'s reason: a caller can
 * put one on the stack and there is no ownership question about it.
 *
 * **Resolved once, by `ncfg_observe_source_machine`, rather than per
 * observation.** A reader whose answer depends on the environment at the
 * moment it is called is one nobody can test twice, which is what that
 * function and `ncfg_observe_roots_default` exist to prevent; the daemon
 * resolves a source at startup and the answer stops moving.
 */
typedef struct {
	/* Where `owned.json`, `prefixes/` and the reports are. */
	char                  run_dir[NCFG_OBSERVE_RUN_DIR_MAX];
	/*
	 * Where the `file` provider looks, for the one question an observation
	 * asks the store: whether a WireGuard device is running the key its
	 * configuration names.
	 *
	 * **Empty means the question is not asked.** It is storage rather than a
	 * pointer for `run_dir`'s reason, and it has no default for
	 * `ncfg_observe_wireguard_currency`'s: this is where `--config-dir` ends
	 * up, and a source that invented `/etc/netcfgd/secrets` would read the
	 * machine's real credentials on a daemon pointed somewhere else.
	 */
	char                  secrets_dir[NCFG_OBSERVE_ROOT_MAX];
	/* `/sys/class/net`, `/proc` and `/sys`. */
	ncfg_observe_roots_t  roots;
	/*
	 * The round of dumps.
	 *
	 * **An `exchange` of NULL is this machine's own socket**, which is not a
	 * default hiding a decision but the same choice `ncfg_observe_collect`
	 * offers next to `ncfg_observe_collect_from` -- a round of `GET`s that
	 * changes nothing, on the machine the caller is already the daemon of.
	 * `ncfg_observe_source_machine` leaves it NULL and a test replaces it, so
	 * the seam the daemon actually installs is the one a test drives rather
	 * than a second path that only ever runs against a live kernel.
	 *
	 * That is the opposite of `ncfg_resolv_machine_t`, whose seam has no
	 * default, and deliberately: the sweep's default ends in a signal to a
	 * process on the developer's machine, and this one reads.
	 */
	ncfg_observe_kernel_t kernel;
	/*
	 * The nftables round, which is a socket of a different protocol.
	 *
	 * Read the same way as `kernel` and with one difference that is the whole
	 * of the divergence: an exchange of NULL **here alone** means "do not
	 * ask". On the machine path both sockets are this module's to open, so a
	 * source with neither exchange installed asks the kernel both questions;
	 * a source that has been given a route exchange has been given a machine
	 * a test made up, and opening a real netfilter socket beside it would be
	 * the one half of that observation that reached the developer's own
	 * ruleset.
	 */
	ncfg_observe_kernel_t netfilter;
	/*
	 * The offloads round, which is a socket of a third protocol.
	 *
	 * Read exactly as `netfilter` is, and absent for the same reason: an
	 * exchange of NULL here means "do not ask", so a source that has been
	 * given a route exchange -- a machine a test made up -- does not have one
	 * half of its observation reach the developer's own network card. On the
	 * machine path all three sockets are this module's to open.
	 */
	ncfg_observe_kernel_t genl;
} ncfg_observe_source_t;

/*
 * A source pointed at this machine, with `run_dir` resolved the way every
 * other caller resolves it.
 *
 * `run_dir` may be NULL, which means `ncfg_state_resolve_dir`'s answer --
 * `NCFG_RUN_DIR`, then the default. `ncfg_contention_machine` is the same
 * shape for the same reason: one place where `/run`, `/proc` and `/sys` are
 * written down.
 *
 * **`secrets_dir` has no such answer and may not acquire one.** NULL leaves
 * the WireGuard currency question unasked, which is what a caller that does
 * not know where the store is should get; a default here would be this module
 * deciding where the machine's credentials live, which is `--config-dir`'s
 * decision and nobody else's. A name too long to hold is the same as none.
 */
int ncfg_observe_source_machine(ncfg_observe_source_t *out, const char *run_dir,
    const char *secrets_dir, char *err, size_t err_size);

/*
 * One observation, through a source.
 *
 * **This is `ncfg_daemon_observe_fn`, signature for signature**, and it is
 * spelled out here rather than declared with that type because `daemon.h` is
 * the layer above this one and an include pointing back down it would invert
 * the order 0263 sets out. What checks the two still agree is a test that
 * assigns this to one: a drift in either signature is then a build that fails
 * rather than a seam nothing can be installed in.
 *
 * `context` is an `ncfg_observe_source_t *` the caller owns and keeps alive
 * for as long as the daemon holds the seam.
 */
int ncfg_observe_source_observe(void *context, const ncfg_document_t *desired,
    ncfg_observed_t **out, char *err, size_t err_size);

#endif /* NCFG_OBSERVE_H */
