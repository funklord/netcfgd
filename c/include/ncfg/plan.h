/*
 * plan.h -- diff(desired, observed) -> an ordered list of typed actions.
 *
 * WHAT THIS MODULE IS FOR
 *   Not being a black box is what netcfgd sells, and this is where "what will
 *   change?" becomes an answerable question. Two properties are load-bearing
 *   and are tested rather than asserted:
 *
 *     * **An already-correct system produces an empty plan.** Zero actions,
 *       nothing touched. That is the normal case, not the edge case.
 *     * **Applying a plan twice produces an empty second plan.** A pass that
 *       adds something and removes it again on the next reconcile is the
 *       failure this module is arranged to make visible.
 *
 *   The safety property that outranks both: **nothing foreign is ever
 *   removed.** Only objects carrying netcfgd's own tag may be deleted to
 *   satisfy the desired state, and the single place that is decided is
 *   `ncfg_ownership_may_remove` in `observed.h` (decision 0002).
 *
 * WHAT A PLAN OWNS, AND WHAT IT BORROWS
 *   **Every string, every list and every route and rule in a plan is the
 *   plan's own**, interned when the action was added and freed by
 *   `ncfg_plan_free`. A caller builds an op on the stack pointing at whatever
 *   it has to hand and never thinks about lifetimes again.
 *
 *   **Four values are borrowed rather than copied**, and they are named here
 *   because a borrow nobody wrote down is a use-after-free waiting for a
 *   caller who kept the plan: an interface kind, a DNS policy, a WireGuard
 *   peer list and a routing rule list. Each is a deep tree the document
 *   already holds, each reaches a plan exactly as the document spells it, and
 *   a deep copy of all four would be a second reading of the model to keep in
 *   step with the first. **So a plan must not outlive the document it was
 *   built from.** That is true of every caller in this project -- a plan is
 *   built, written or applied, and dropped, inside one call -- and it is a
 *   divergence from the Rust, where `Op` owns everything it carries.
 *
 * THE ID SENTINEL
 *   `ncfg_plan_add` answers `NCFG_PLAN_NO_ACTION` for an action that was not
 *   emitted -- a guard refused it, or the device is unmanaged. Callers
 *   accumulate ids into dependency lists, so the sentinel would otherwise
 *   travel into a plan as a dependency on action 4294967295; it is dropped
 *   where dependency lists are built rather than at each call site, because a
 *   site added later would not know to ask. The Rust records this as a defect
 *   that shipped: guarding a bridge member made the bridge's `link.up` and
 *   `addr.add` depend on an action that did not exist (0097).
 *
 * ERRORS
 *   base.h's convention throughout: 1 or 0, and a sentence.
 */
#ifndef NCFG_PLAN_H
#define NCFG_PLAN_H

#include <stddef.h>
#include <stdint.h>

#include "ncfg/buf.h"
#include "ncfg/document.h"
#include "ncfg/observed.h"
#include "ncfg/value.h"

/* ------------------------------------------------------------------------ *
 * The action taxonomy
 * ------------------------------------------------------------------------ */

/*
 * What an action does.
 *
 * **The whole taxonomy is here even where this build emits only part of it.**
 * It is the vocabulary the control socket speaks, and a reader comparing this
 * against the Rust's `Op` should find the same list rather than the subset
 * that happens to match what the port has reached. `doc/schema/plan.json`
 * carries one sample of each, and `plan_test.c` writes all forty-eight back.
 */
typedef enum {
	NCFG_OP_LINK_CREATE,
	NCFG_OP_LINK_DELETE,
	NCFG_OP_LINK_SET_MTU,
	NCFG_OP_LINK_SET_MAC,
	NCFG_OP_LINK_SET_MASTER,
	NCFG_OP_LINK_UNSET_MASTER,
	NCFG_OP_LINK_UP,
	NCFG_OP_LINK_DOWN,
	NCFG_OP_ADDR_ADD,
	NCFG_OP_ADDR_DEL,
	NCFG_OP_ROUTE_ADD,
	NCFG_OP_ROUTE_DEL,
	NCFG_OP_BACKEND_START,
	NCFG_OP_BACKEND_STOP,
	NCFG_OP_BACKEND_RELOAD,
	NCFG_OP_BRIDGE_VLAN_ADD,
	NCFG_OP_BRIDGE_VLAN_DEL,
	NCFG_OP_WIFI_SET_PROFILES,
	NCFG_OP_WIFI_ASSOCIATE,
	NCFG_OP_WIFI_DISASSOCIATE,
	NCFG_OP_WIFI_SET_REGDOM,
	NCFG_OP_ACCESS_CONTROL_ADD,
	NCFG_OP_ACCESS_CONTROL_DEL,
	NCFG_OP_LINK_SET_BOND,
	NCFG_OP_LINK_SET_BRIDGE,
	NCFG_OP_LINK_SET_MACVLAN,
	NCFG_OP_LINK_SET_TUNNEL,
	NCFG_OP_LINK_SET_VXLAN,
	NCFG_OP_WG_SET_DEVICE,
	NCFG_OP_WG_SET_PEERS,
	NCFG_OP_DNS_APPLY,
	NCFG_OP_LINK_SET_OFFLOADS,
	NCFG_OP_LINK_SET_IPV6_TOKEN,
	NCFG_OP_RULE_ADD,
	NCFG_OP_RULE_DEL,
	NCFG_OP_QDISC_SET,
	NCFG_OP_QDISC_RESET,
	NCFG_OP_INGRESS_REDIRECT,
	NCFG_OP_INGRESS_REDIRECT_CLEAR,
	NCFG_OP_SYSCTL_SET_FORWARDING,
	NCFG_OP_SYSCTL_SET_PRIVACY,
	NCFG_OP_SYSCTL_SET_ACCEPT_RA,
	NCFG_OP_HOSTNAME_SET,
	NCFG_OP_NAT_REPLACE,
	NCFG_OP_HOOK_RUN,
	NCFG_OP_COMMIT_ARM,
	NCFG_OP_COMMIT_CONFIRM,
	NCFG_OP_COMMIT_REVERT
} ncfg_op_kind_t;

/* One driver offload and the state it is being moved to. */
typedef struct {
	/* The kernel's own spelling, e.g. `rx-checksum`. */
	const char *name;
	int         wanted;
} ncfg_offload_t;

/*
 * An action's payload.
 *
 * A union rather than one flat struct with fifty members: the Rust this
 * replaces is an enum, and a reader checking that the two carry the same
 * fields can do it arm by arm. Every `const char *` in here is the plan's own
 * (see the note at the top); the four pointers into the model are not.
 */
typedef struct {
	int kind; /* ncfg_op_kind_t */
	union {
		/* `{ "name": ... }` and nothing else. Nine ops share the shape. */
		struct {
			const char *name;
		} named;
		struct {
			const char                  *name;
			/* Borrowed from the document. */
			const ncfg_interface_kind_t *kind;
		} link_create;
		struct {
			const char *name;
			int64_t     mtu;
		} set_mtu;
		struct {
			const char *name;
			const char *mac;
		} set_mac;
		struct {
			const char *name;
			const char *master;
		} set_master;
		/*
		 * Whether the mode is part of this.
		 *
		 * It can only be on a bond with no members: the kernel answers
		 * `ENOTEMPTY` otherwise and rejects the whole message, so a request
		 * carrying a mode it will not take also fails to set the monitoring
		 * interval beside it. The planner knows which case this is and says
		 * so here rather than leaving the executor to ask.
		 */
		struct {
			const char *name;
			int         mode;
		} set_bond;
		struct {
			const char *name;
			const char *token;
		} set_ipv6_token;
		struct {
			const char           *name;
			const ncfg_offload_t *features;
			size_t                feature_count;
		} set_offloads;
		struct {
			const char   *iface;
			const char   *addr;
			ncfg_optint_t preferred_lifetime;
			ncfg_optint_t valid_lifetime;
		} addr_add;
		struct {
			const char *iface;
			const char *addr;
		} addr_del;
		struct {
			const char         *iface;
			const ncfg_route_t *route;
		} route;
		struct {
			int         kind; /* ncfg_backend_kind_t */
			const char *iface;
		} backend;
		struct {
			const char *iface;
			int64_t     vid;
			int         pvid;
			int         untagged;
			int         on_self;
		} bridge_vlan;
		struct {
			const char        *device;
			const char *const *profiles;
			size_t             profile_count;
		} set_profiles;
		struct {
			const char *device;
			const char *network_id;
		} associate;
		struct {
			const char *device;
		} device;
		struct {
			const char *device;
			const char *country;
		} regdom;
		struct {
			const char *iface;
			int         list; /* ncfg_acl_policy_t */
			const char *station;
		} access_control;
		struct {
			const char   *iface;
			/* A reference, never a key: a plan goes to /run and over the
			 * socket, and constraint 5 holds for both. */
			const char   *private_key_ref;
			ncfg_optint_t listen_port;
			ncfg_optint_t fwmark;
		} wg_device;
		struct {
			const char           *iface;
			/* Borrowed from the document. */
			const ncfg_wg_peer_t *peers;
			size_t                peer_count;
		} wg_peers;
		struct {
			/* An interface name, or `globals`. */
			const char              *scope;
			/* Borrowed from the document, or from the observer. */
			const ncfg_dns_policy_t *policy;
		} dns;
		struct {
			const ncfg_routing_rule_t *rule;
		} rule;
		struct {
			const char   *iface;
			/* The scheduler, as the kernel spells it. */
			const char   *kind;
			ncfg_optint_t bandwidth_bits;
			int           ingress;
		} qdisc;
		struct {
			const char *iface;
		} iface;
		struct {
			const char *iface;
			const char *target;
		} redirect;
		struct {
			const char *iface;
			int         enabled;
		} forwarding;
		struct {
			const char *iface;
			int         prefer_temporary;
		} privacy;
		struct {
			const char *iface;
			/* `2` to accept, `1` to hand the interface back. Never `0`. */
			int64_t     value;
		} accept_ra;
		struct {
			/* Sorted. Empty removes the table. */
			const char *const *uplinks;
			size_t             uplink_count;
		} nat;
		struct {
			const char *iface;
			int         phase; /* ncfg_hook_phase_t */
			const char *path;
			/* A lease's address or a carrier's `up`/`down`, for the phases
			 * that are events rather than lifecycle points. NULL otherwise. */
			const char *value;
		} hook;
		struct {
			int64_t window_seconds;
		} commit_arm;
		struct {
			const char *to_document_hash;
		} commit_revert;
	} u;
} ncfg_op_t;

/* A stable short name, for logs, for `ncfg plan` and for the wire tag. */
const char *ncfg_op_name(const ncfg_op_t *op);

/*
 * Whether this action can interrupt traffic on the interface it touches.
 *
 * A guard blocks the disruptive ones (decision 0010). The list is wider than
 * "removes the link" on purpose: changing the address on an interface carrying
 * an NFS mount breaks it exactly as thoroughly as downing it, and enslaving an
 * interface to a bridge moves its addresses.
 */
int ncfg_op_is_disruptive(const ncfg_op_t *op);

/*
 * Whether this op configures the whole host rather than one interface.
 *
 * `ncfg_op_interface` answering NULL is not the same question. The daemon's
 * drift loop restricts a plan to the interfaces that opted into reconciling,
 * so anything answering NULL was dropped -- and a `resolv.conf` another
 * resolver had overwritten could never be put back. Deliberately a list of two
 * rather than "names no interface": the three commit ops also name none and
 * must never be swept into a drift pass. Decision 0165.
 */
int ncfg_op_is_host_wide_config(const ncfg_op_t *op);

/* Which interface this acts on, where it acts on one, and NULL otherwise. */
const char *ncfg_op_interface(const ncfg_op_t *op);

/* ------------------------------------------------------------------------ *
 * What an action carries besides the op
 * ------------------------------------------------------------------------ */

/*
 * Which desired field differs from which observed field, and how.
 *
 * Carried on every action so that `ncfg plan` can say *why* rather than only
 * *what*. An action list without reasons is a black box with extra steps.
 */
typedef struct {
	/* NULL where the action names no interface. */
	const char *interface;
	/* A dotted path into the document, for example `addressing[0]`. */
	const char *field;
	/* The desired value, rendered, or `<absent>`. */
	const char *desired;
	/* The observed value, rendered, or `<absent>`. */
	const char *observed;
} ncfg_reason_t;

/* One step of a plan. */
typedef struct {
	/* Position in the plan, and the handle `depends_on` refers to. */
	uint32_t        id;
	ncfg_op_t       op;
	ncfg_reason_t   reason;
	const uint32_t *depends_on;
	size_t          depends_count;
	/* How to undo it. `has_inverse == 0` means irreversible, and the plan
	 * carries a warning saying commit-confirm will not revert it. */
	int             has_inverse;
	ncfg_op_t       inverse;
} ncfg_action_t;

/* Something the operator should know that is not an action. */
typedef struct {
	const char *message;
	/* NULL where it concerns no single interface. */
	const char *interface;
} ncfg_warning_t;

/*
 * An action netcfgd declined to plan, and why.
 *
 * First-class rather than a warning string, because "what did it decline?" is
 * a question a script has to answer as well as a human, and because burying it
 * among warnings is how it gets ignored (decision 0010).
 */
typedef struct {
	const char   *interface;
	/* The op that was not planned, by name. */
	const char   *op;
	/* What the guard says depends on this interface. */
	const char   *guard;
	/* Why the action existed, so the reader knows what is not happening. */
	ncfg_reason_t reason;
	/* The exact invocation that consents to it. */
	const char   *override_with;
} ncfg_refusal_t;

/*
 * Secret material a plan walks away from and cannot take back.
 *
 * Not a refusal, which is an *action* a guard dropped and can name. Nothing is
 * dropped here: `managed = false` already means netcfgd plans nothing for the
 * device (0035), and the hazard is that absence continuing. Only for
 * credentials that cannot be revoked from this host -- a notice that fires for
 * everything is one people learn to pass over (0042).
 */
typedef struct {
	const char *interface;
	/* What stays behind, and where. */
	const char *credential;
	/* Why it cannot simply be withdrawn later. */
	const char *irrevocable;
	/* The configuration change that removes it instead. */
	const char *remove_with;
	/* The exact invocation that consents to leaving it, for this run. */
	const char *consent_with;
} ncfg_stranded_t;

/* ------------------------------------------------------------------------ *
 * The plan
 * ------------------------------------------------------------------------ */

/* The answer `ncfg_plan_add` gives for an action it did not emit. */
#define NCFG_PLAN_NO_ACTION ((uint32_t)0xffffffffu)

/*
 * An ordered DAG of actions, plus what could not be planned.
 *
 * The action list is already in a valid execution order, so an executor that
 * ignores `depends_on` entirely still behaves correctly. The edges are there
 * so an executor that wants to parallelise, or a reader who wants to know
 * *why* this comes before that, has the information.
 */
typedef struct ncfg_plan ncfg_plan_t;

struct ncfg_plan {
	ncfg_action_t   *actions;
	size_t           action_count;
	ncfg_warning_t  *warnings;
	size_t           warning_count;
	ncfg_refusal_t  *refusals;
	size_t           refusal_count;
	ncfg_stranded_t *stranded;
	size_t           stranded_count;

	/*
	 * Everything above points into here.
	 *
	 * One array of allocations rather than a `free` walk per action: an op is
	 * a union of thirty arms and a walk over it would be a third list to keep
	 * in step with the enum and the writer. Interning makes every string in a
	 * plan the plan's, freed in one loop, and makes the ownership rule one
	 * sentence instead of thirty.
	 */
	void   **owned;
	size_t   owned_count;
	size_t   owned_capacity;
	/* Set by the first allocation failure and never cleared, so a caller may
	 * build a whole plan and check once -- `ncfg_buf_t`'s discipline. */
	int      failed;
};

/* How to build the plan. */
typedef struct {
	/*
	 * Seconds before an unconfirmed change reverts.
	 *
	 * Absent means the caller did not say and the document's
	 * `globals.confirm_default` answers instead. **Zero is how a caller says
	 * *no* window despite that default, and is the only way to say it**: a
	 * window of no seconds would arm and expire, which is two spellings of
	 * "no" where one of them reverts the change. A document saying
	 * `confirm = 0` means the same thing, which is where the defect was: that
	 * guard covered only the caller's option, so `global { confirm = 0 }`
	 * armed a window of zero seconds (0094).
	 */
	ncfg_optint_t      confirm_window;
	/* Hash of the document to revert to, computed at plan time rather than
	 * after a failure, when the network may already be unreachable. */
	const char        *revert_to;
	/*
	 * Interfaces the operator has explicitly consented to disrupt.
	 *
	 * Named rather than a blanket `--force`, because a blanket override is the
	 * flag people alias and stop reading, and it consents to disrupting the
	 * interfaces they had not thought about as well.
	 */
	const char *const *allow_disruption;
	size_t             allow_disruption_count;
} ncfg_plan_options_t;

/* An empty plan, or NULL. */
ncfg_plan_t *ncfg_plan_new(char *err, size_t err_size);

void ncfg_plan_free(ncfg_plan_t *plan);

/*
 * Append an action, copying everything it names into the plan.
 *
 * `depends_on` is copied with the sentinel removed, so a caller may pass the
 * ids it collected without filtering them. `inverse` may be NULL, which is
 * what "cannot be undone" means -- and which makes this push a warning saying
 * so, exactly as the Rust does.
 *
 * Answers the new action's id, or `NCFG_PLAN_NO_ACTION` if the plan has
 * already failed. **The guards do not live here**: this is the list, and
 * `ncfg_plan_build` is what decides. A caller assembling a plan by hand -- a
 * test, a witness -- gets exactly what it asked for.
 */
uint32_t ncfg_plan_add(ncfg_plan_t *plan, const ncfg_op_t *op, const ncfg_reason_t *reason,
    const uint32_t *depends_on, size_t depends_count, const ncfg_op_t *inverse);

/* Append a warning, copying both strings. `interface` may be NULL. */
void ncfg_plan_warn(ncfg_plan_t *plan, const char *interface, const char *message);

/* The same, building the message with a format. */
void ncfg_plan_warnf(ncfg_plan_t *plan, const char *interface, const char *format, ...);

/* Append a refusal and a stranded credential, copying everything. */
void ncfg_plan_refuse(ncfg_plan_t *plan, const ncfg_refusal_t *refusal);
void ncfg_plan_strand(ncfg_plan_t *plan, const ncfg_stranded_t *stranded);

/*
 * Take a copy of `text` that the plan owns and frees.
 *
 * Public because a caller building an op out of pieces -- a rendered route, a
 * formatted reason -- needs somewhere to put the result that lives exactly as
 * long as the plan does. NULL in is NULL out, which is what an absent optional
 * member means everywhere in this project.
 */
const char *ncfg_plan_intern(ncfg_plan_t *plan, const char *text);

/* The same, with a format. */
const char *ncfg_plan_internf(ncfg_plan_t *plan, const char *format, ...);

/* A copy of `route` that the plan owns, strings and all. */
const ncfg_route_t *ncfg_plan_intern_route(ncfg_plan_t *plan, const ncfg_route_t *route);

/* Whether anything went wrong while the plan was being built. */
int ncfg_plan_failed(const ncfg_plan_t *plan);

/* Whether there is nothing to do. The normal case on a correct system. */
int ncfg_plan_is_empty(const ncfg_plan_t *plan);

/* Whether a guard stopped anything being planned. */
int ncfg_plan_was_refused(const ncfg_plan_t *plan);

/*
 * Whether this plan leaves behind a credential nobody can withdraw.
 *
 * Separate from `ncfg_plan_was_refused` because the remedies differ, and a
 * script that handled one as the other would do the wrong thing: a refusal is
 * re-run with `--allow-disruption`, and this is answered by deciding what
 * should happen to a key.
 */
int ncfg_plan_strands_credentials(const ncfg_plan_t *plan);

/*
 * Write the plan as the control socket sends it.
 *
 * Compact rather than indented, which is the port's convention: the Rust
 * writes `doc/schema/plan.json` with `to_string_pretty` and the two differ by
 * whitespace and by nothing else. `plan_test.c` proves that byte for byte.
 */
int ncfg_plan_write(const ncfg_plan_t *plan, ncfg_buf_t *buf, char *err, size_t err_size);

/*
 * Compute what would have to change for `observed` to satisfy `desired`.
 *
 * `options` may be NULL, which means every default. The plan borrows from both
 * arguments (see the note at the top of this file) and must not outlive them.
 */
ncfg_plan_t *ncfg_plan_build(const ncfg_document_t *desired, const ncfg_observed_t *observed,
    const ncfg_plan_options_t *options, char *err, size_t err_size);

/*
 * How long the confirm window is, if there is one.
 *
 * Public because the daemon has to reach the same answer, and a second copy of
 * this rule is how the two would stop agreeing.
 */
ncfg_optint_t ncfg_plan_confirm_window(const ncfg_document_t *desired,
    const ncfg_plan_options_t *options);

/*
 * Whether a report about this interface is one netcfgd was told to act on.
 *
 * Public for `ncfg_plan_confirm_window`'s reason and a sharper one: `ncfg
 * explain` has to answer the same question, and the Rust makes this `pub`
 * precisely so the explanation and the planner cannot disagree about which
 * reports are believed. An operator asking why a route is there would
 * otherwise get "the configuration does not ask for it" about a route netcfgd
 * installed itself.
 *
 * Two ways in, and they are the same question asked of different documents:
 * the addressing list says `reported`, which is how a modem helper's file is
 * claimed, or netcfgd started the writer itself -- a tunnel or a PPPoE session
 * reports through a script netcfgd generated, and there is nothing left to opt
 * into. What it is *not* is "there is a file": a report for an interface the
 * document says nothing about is an observation with no instruction behind it.
 *
 * Not the gate for a *nameserver*, which is narrower and lives with the DNS
 * rules: having started the writer is enough to install a route down that link
 * and deliberately not enough to change where every query on the machine goes
 * (decision 0049).
 */
int ncfg_plan_takes_reports(const ncfg_document_t *desired, const ncfg_interface_t *interface);

#endif /* NCFG_PLAN_H */
