/*
 * plan_internal.h -- what the planner's own files share and nothing else does.
 *
 * Three groups: the JSON writers for the model values a plan embeds, the
 * builder state the planning passes accumulate, and the small comparisons the
 * passes make about routes and addresses.
 */
#ifndef NCFG_PLAN_INTERNAL_H
#define NCFG_PLAN_INTERNAL_H

#include "ncfg/document.h"
#include "ncfg/json_write.h"
#include "ncfg/observed.h"
#include "ncfg/plan.h"

#include <stddef.h>
#include <stdint.h>

/* ------------------------------------------------------------------------ *
 * The model values a plan embeds
 * ------------------------------------------------------------------------ */

/*
 * A second writer for values `src/model/document.c` can already write.
 *
 * **This is a copy, and it is worth saying why rather than leaving a reader to
 * find out.** The model writes through a table engine whose tables are static
 * to that file, so there is no function to call: a plan that embeds a route
 * has either to duplicate the writing or to export the engine, and exporting
 * it is a change to a module this port is not allowed to touch. What stops the
 * two copies drifting is not discipline but a test: `plan_test.c` reads
 * `doc/schema/document.json`, writes every interface kind, route, rule, DNS
 * policy and peer in it back through these functions, and compares bytes. A
 * member added on one side and not the other fails there.
 *
 * The right end state is one writer, reached by exporting the model's. That is
 * a change to `document.c` and belongs to whoever owns it.
 */
void ncfg_plan_write_route(ncfg_json_writer_t *writer, const ncfg_route_t *route);
void ncfg_plan_write_rule(ncfg_json_writer_t *writer, const ncfg_routing_rule_t *rule);
void ncfg_plan_write_dns_policy(ncfg_json_writer_t *writer, const ncfg_dns_policy_t *policy);
void ncfg_plan_write_wg_peer(ncfg_json_writer_t *writer, const ncfg_wg_peer_t *peer);
void ncfg_plan_write_interface_kind(ncfg_json_writer_t *writer,
    const ncfg_interface_kind_t *kind);

/* The word sets this module owns that neither `value.h` nor `document.h`
 * publishes. The first is what an op writes directly; the other three are what
 * the kind and qdisc passes compare a document's closed set against, since the
 * observer reports the kernel's answer as the document's word. All four are
 * checked against the frozen witness like every other spelling here. */
const char *ncfg_plan_acl_policy_word(int policy);
const char *ncfg_plan_bond_mode_word(int mode);
const char *ncfg_plan_macvlan_mode_word(int mode);
const char *ncfg_plan_qdisc_kind_word(int kind);

/* A Curve25519 key's base64, and a buffer that holds one. 32 octets is 44
 * characters and a terminator; 32 is not a multiple of three, which is where
 * the single `=` comes from. A buffer that could truncate is refused rather
 * than truncated into. */
#define NCFG_PLAN_KEY_TEXT_MAX 45u
void ncfg_plan_render_key(const unsigned char *key, char *out, size_t out_size);

/* ------------------------------------------------------------------------ *
 * The builder
 * ------------------------------------------------------------------------ */

/*
 * A growing list of action ids, which is what every dependency list is.
 *
 * A fixed array would need a bound on "how many members can a bridge have",
 * and a dependency list that silently stopped at eight would be an ordering
 * rule that holds for small configurations. On failure the plan is marked, so
 * an edge is never quietly lost.
 */
typedef struct {
	uint32_t *ids;
	size_t    count;
	size_t    capacity;
} ncfg_plan_ids_t;

void ncfg_plan_ids_push(ncfg_plan_t *plan, ncfg_plan_ids_t *ids, uint32_t id);
void ncfg_plan_ids_extend(ncfg_plan_t *plan, ncfg_plan_ids_t *ids, const ncfg_plan_ids_t *from);
void ncfg_plan_ids_free(ncfg_plan_ids_t *ids);

/* One `(name, id)` pair: a gate, an enslavement, a `link.up`. */
typedef struct {
	const char *name;
	uint32_t    id;
} ncfg_plan_mark_t;

/* What one interface's guard says depends on it. */
typedef struct {
	const char *interface;
	const char *reason;
} ncfg_plan_guard_t;

/* An `addr.add`, with the address it adds, for ordering rule 4. */
typedef struct {
	const char *interface;
	const char *address;
	uint32_t    id;
} ncfg_plan_added_t;

/*
 * An interface a `linkset` is not currently using, and why.
 *
 * `instead` is the member the set chose, or NULL where it could use none of
 * them -- two different sentences for an operator, and the one that matters
 * most is the second: a set with nothing it can use is a machine with no
 * uplink, and "the routes are not installed" without it reads as a decision
 * rather than a failure. Every string is interned into the plan, because the
 * choice these came out of is freed before the first route is planned.
 */
typedef struct {
	const char *interface;
	const char *set;
	const char *instead;
} ncfg_plan_standby_t;

/*
 * Everything the passes accumulate while a plan is being assembled.
 *
 * Held in one struct rather than threaded through, which is the Rust's shape
 * too: the alternative is eleven passes each taking nine arguments, and a pass
 * added later getting eight of them.
 */
typedef struct {
	ncfg_plan_t            *plan;
	const ncfg_document_t  *desired;
	const ncfg_observed_t  *observed;
	/* NULL is every default. */
	const ncfg_plan_options_t *options;

	/* `(interface, reason)` for every guarded interface, collected before
	 * anything is planned -- a guard on one interface has to be known when an
	 * action against it is considered, whatever order the interfaces sort
	 * in. */
	ncfg_plan_guard_t *guards;
	size_t             guard_count;

	/* Ids every later action on an interface must wait for: its creation. */
	ncfg_plan_mark_t *gates;
	size_t            gate_count;
	/* `link.set_master` ids, keyed by the master they enslave to. */
	ncfg_plan_mark_t *enslavements;
	size_t            enslavement_count;
	/* `link.up` id per interface. */
	ncfg_plan_mark_t *link_up;
	size_t            link_up_count;
	/* `addr.add` ids per interface, with the address each one adds. */
	ncfg_plan_added_t *added;
	size_t             added_count;

	/* Devices this plan has declined to create, having already said why. */
	const char **declined;
	size_t       declined_count;
	/* Names that will exist by the end of this plan without anything creating
	 * them directly. Only veth peers, so far: creating one end creates both. */
	const char **appearing;
	size_t       appearing_count;
	/* Devices a `device` block marks `managed = false`. */
	const char **unmanaged;
	size_t       unmanaged_count;
	/* Of those, the ones whose `on_unmanage` is `clear`: netcfgd owns nothing
	 * on them, so the teardown removes what it left behind. */
	const char **clearing;
	size_t       clearing_count;
	/* Whether the teardown passes are running. The forward passes must not
	 * touch a clearing device -- planning an address and removing it in the
	 * same plan is a loop, not a convergence -- so the exemption in
	 * `ncfg_builder_push` applies during teardown only. */
	int          tearing_down;
	/* The document the forward passes read, held while the teardown reads a
	 * copy with the clearing devices filtered out. Both NULL otherwise. */
	const ncfg_document_t *unfiltered;
	ncfg_document_t       *filtered;

	/* Interfaces a linkset has not chosen, collected once before anything is
	 * planned: `ncfg_linkset_choose` walks nested sets, the link table and the
	 * probe verdicts, and the answer cannot change inside one plan. */
	ncfg_plan_standby_t *standby;
	size_t               standby_count;
} ncfg_builder_t;

/* The ids every later action on this interface must wait for: its creation. */
void ncfg_builder_gate(ncfg_builder_t *builder, const char *name, ncfg_plan_ids_t *out);

/* The `link.up` id for this interface, or `NCFG_PLAN_NO_ACTION`. */
uint32_t ncfg_builder_link_up(const ncfg_builder_t *builder, const char *name);

/* The one place an action becomes part of the plan, and the one place a guard
 * can stop it. Answers the id, or `NCFG_PLAN_NO_ACTION`. */
uint32_t ncfg_builder_push(ncfg_builder_t *builder, const ncfg_op_t *op,
    const ncfg_reason_t *reason, const uint32_t *depends_on, size_t depends_count,
    const ncfg_op_t *inverse);

/* Record a `(name, id)` in one of the mark lists. */
void ncfg_builder_mark(ncfg_builder_t *builder, ncfg_plan_mark_t **list, size_t *count,
    const char *name, uint32_t id);
void ncfg_builder_note_string(ncfg_builder_t *builder, const char ***list, size_t *count,
    const char *value);

int ncfg_plan_names(const char *const *list, size_t count, const char *name);

/* The device of this name, or NULL. */
const ncfg_device_t *ncfg_plan_device(const ncfg_document_t *desired, const char *name);
/* The interface of this name, or NULL. */
const ncfg_interface_t *ncfg_plan_interface(const ncfg_document_t *desired, const char *name);

/*
 * One sentence per block that nothing acts on **in either language**.
 *
 * "This build of the planner does not act on it" is a promise that a later
 * release will, so it belongs to a real port gap and to nothing else. A block
 * the Rust has not built either gets this instead, which says out loud that
 * there is nothing to wait for. `build.c` carries the argument and the three
 * warnings that made it necessary.
 *
 * `block` is the clause naming what is not acted on, with no trailing stop:
 * the sentence that follows it is appended here, so the two halves cannot
 * drift apart in one caller and not another.
 *
 * Not `static` in `build.c` any more, because the wifi passes have the same
 * distinction to draw about a `network` block and a second copy of the
 * sentence is a second thing to keep true.
 */
void ncfg_plan_warn_unbuilt(ncfg_builder_t *builder, const char *interface, const char *block);

/*
 * The three shapes a reason comes in.
 *
 * Named constructors rather than four assignments at each of the call sites,
 * because the pair that goes wrong is `desired`/`observed`: a reason with them
 * the wrong way round reads as a plan doing the opposite of what it does, and
 * nothing but a reader would notice.
 */
ncfg_reason_t ncfg_plan_reason_absent(const char *interface, const char *field,
    const char *desired);
ncfg_reason_t ncfg_plan_reason_differs(const char *interface, const char *field,
    const char *desired, const char *observed);
ncfg_reason_t ncfg_plan_reason_unwanted(const char *interface, const char *field,
    const char *observed);

/*
 * Why an interface is being taken down, as the plan will explain it.
 *
 * Taking a link down used to mean one thing -- `enabled = false` -- so the
 * reason was a literal inside the teardown. A cycle for a SIM switch is the
 * second reason, and a plan that told the operator `enabled` had changed when
 * it had not would be worse than one that said nothing.
 */
typedef struct {
	const char *field;
	const char *desired;
	const char *observed;
} ncfg_plan_teardown_t;

/* ------------------------------------------------------------------------ *
 * The passes
 * ------------------------------------------------------------------------ */

void ncfg_plan_link_creation(ncfg_builder_t *builder, const ncfg_device_t *device);
void ncfg_plan_link_attributes(ncfg_builder_t *builder, const ncfg_interface_t *interface);
uint32_t ncfg_plan_master(ncfg_builder_t *builder, const char *name);
void ncfg_plan_device_up(ncfg_builder_t *builder, const ncfg_device_t *device, uint32_t enslaved);
void ncfg_plan_interface_contents(ncfg_builder_t *builder, const ncfg_interface_t *interface);
void ncfg_plan_source(ncfg_builder_t *builder, const ncfg_interface_t *interface, size_t index,
    const ncfg_plan_ids_t *base, ncfg_plan_ids_t *out);
void ncfg_plan_route(ncfg_builder_t *builder, const ncfg_interface_t *interface,
    const ncfg_route_t *route, const ncfg_plan_ids_t *base);
void ncfg_plan_teardown(ncfg_builder_t *builder);

/*
 * The three sysctls that are properties of an interface rather than addressing
 * actions, and the two whole-host passes.
 *
 * `ncfg_plan_accept_ra` runs **before the link attributes**, and that is not
 * tidiness: `link.up` is where the kernel decides whether to solicit a router
 * at all, and it does not solicit on an interface whose advertisements it
 * would ignore. Writing `accept_ra` afterwards leaves the interface waiting
 * for the router's own unsolicited timer -- 14.2 seconds against a dnsmasq set
 * to five, and minutes on a real network. Decision 0073.
 */
void ncfg_plan_accept_ra(ncfg_builder_t *builder);
void ncfg_plan_privacy(ncfg_builder_t *builder);
void ncfg_plan_forwarding(ncfg_builder_t *builder);
void ncfg_plan_dns(ncfg_builder_t *builder);
void ncfg_plan_hostname(ncfg_builder_t *builder);

/*
 * What a device's `kind` says about itself, corrected on one that exists.
 *
 * **Creation is not enough and that is the whole subject.** A bridge's `stp`,
 * a bond's `miimon`, a tunnel's endpoints and a WireGuard device's peer list
 * are all sent inside `link.create` -- so on a device the kernel already has,
 * editing any of them planned nothing and changed nothing (0054, 0057). Each
 * pass reads the kind's own observation, compares only what the document
 * states, and says what the kernel will not take rather than planning an
 * action that must fail.
 *
 * Driven from the device list rather than the interface list: what netcfgd
 * creates is stated on the device, and a bridge port or an `ifb` need not have
 * an `interface` block at all.
 */
void ncfg_plan_wireguard(ncfg_builder_t *builder, const ncfg_device_t *device);
void ncfg_plan_bridge(ncfg_builder_t *builder, const ncfg_device_t *device);
void ncfg_plan_bond(ncfg_builder_t *builder, const ncfg_device_t *device);
void ncfg_plan_macvlan(ncfg_builder_t *builder, const ncfg_device_t *device);
void ncfg_plan_tunnel(ncfg_builder_t *builder, const ncfg_device_t *device);
void ncfg_plan_vxlan(ncfg_builder_t *builder, const ncfg_device_t *device);
void ncfg_plan_bridge_vlans(ncfg_builder_t *builder, const ncfg_device_t *device);

/*
 * The driver, traffic-control and wireless passes, each over the whole
 * document.
 *
 * `ncfg_plan_ingress` runs **after** `ncfg_plan_qdisc`, so the `ifb` exists
 * and is shaped before anything is pointed at it: traffic redirected onto a
 * device with no shaper is traffic that is not being shaped, which is worse
 * than not redirecting it at all.
 */
void ncfg_plan_offloads(ncfg_builder_t *builder);
/*
 * The IPv6 interface identifier, and netcfgd's one nftables table.
 *
 * Neither has a teardown half and each says why where it is defined: a token
 * carries no ownership tag, and the NAT table is replaced whole rather than
 * diffed, so an empty list *is* the removal.
 */
void ncfg_plan_ipv6_token(ncfg_builder_t *builder);
void ncfg_plan_nat(ncfg_builder_t *builder);
void ncfg_plan_rules(ncfg_builder_t *builder);
void ncfg_plan_qdisc(ncfg_builder_t *builder);
void ncfg_plan_ingress(ncfg_builder_t *builder);
void ncfg_plan_wifi(ncfg_builder_t *builder);
void ncfg_plan_access_control(ncfg_builder_t *builder);

/*
 * A copy of `rule` the plan owns, strings and all.
 *
 * `ncfg_plan_intern_route`'s shape and here for the same reason a merged DNS
 * scope needs one: a `rule.del` for something only the *kernel* has is built
 * out of the observation, which the plan may not borrow from -- `plan.h`'s
 * borrow is from the document. The rules a document states are passed through
 * unchanged and stay borrowed.
 */
const ncfg_routing_rule_t *ncfg_plan_intern_rule(ncfg_plan_t *plan,
    const ncfg_routing_rule_t *rule);

/*
 * Start the helper that serves an addressing source, and stop the ones the
 * document no longer asks for.
 *
 * `field` is the dotted path the reason carries, so an operator told a client
 * was started because of `addressing[1]` can go and look at the right line.
 */
/*
 * Restart a DHCP client whose route carries a metric the document has moved on
 * from.
 *
 * The second half of `netcfgd_model::wifi::effective_metric`'s meaning: the
 * first is that a route the interface declares takes the effective metric,
 * which `address.c` does, and this is the lease's own route -- which netcfgd
 * does not install and cannot edit, because the client installs it from what it
 * was started with. So the only way to move it is to start the client again.
 *
 * **It looks at two things and neither subsumes the other.** The client's own
 * `argv`, recorded as `started_metric`, says what it was *told* and is there
 * before any route exists; the installed default route with the kernel's DHCP
 * protocol on it says what the client *did*, and catches one that ignored what
 * it was told.
 *
 * Bounded by 0079's restart cap, which matters more here than anywhere else it
 * is applied: each round drops the lease for as long as the exchange takes, so
 * a client that will not take the metric would otherwise take the machine's
 * network away every reconcile, for ever.
 *
 * Nothing where the document asks for no lease, where none is running, or
 * where neither answer differs from what is wanted.
 */
void ncfg_plan_metric_restart(ncfg_builder_t *builder, const ncfg_interface_t *interface,
    const ncfg_plan_ids_t *base);

void ncfg_plan_backend(ncfg_builder_t *builder, const char *name, int kind, const char *field,
    const ncfg_plan_ids_t *base, ncfg_plan_ids_t *out);
void ncfg_plan_teardown_backends(ncfg_builder_t *builder);

/* ------------------------------------------------------------------------ *
 * 802.1X, router advertisements, failover sets and `on_unmanage = "clear"`
 * ------------------------------------------------------------------------ */

/*
 * The supplicant a wired 802.1X port needs, and whether a running one is still
 * asked for.
 *
 * Planned before any address, because a port that has not authenticated drops
 * everything and a DHCP client started first spends its whole backoff talking
 * to a switch that is not listening. The two are one file for the reason
 * `dot1x.c` gives: the conditions that start a supplicant and the conditions
 * that keep one have to stay the same, and a rule in two files is one that
 * eventually disagrees with itself.
 */
/*
 * Start the daemon that brings a ppp link or a tunnel into existence.
 *
 * Driven from the device walk and **before the plannability guard**, because
 * the link this would create is exactly the link whose absence that guard
 * stops everything else for. `session.c` has the rest, including why planning
 * it from the interface walk as well cost a session once already.
 */
void ncfg_plan_session(ncfg_builder_t *builder, const ncfg_device_t *device);

/*
 * Report every backend that is running and will not answer, and restart the
 * ones the operator named.
 *
 * `wedged.c` has the argument: netcfgd cannot tell a wedged daemon from a slow
 * answer, so the default is a warning and a refusal naming what consents, and
 * `--restart-wedged` is what turns it into a stop and a start.
 */
void ncfg_plan_wedged_backends(ncfg_builder_t *builder);

/*
 * Report every irrevocable credential this plan walks away from.
 *
 * Driven by the observation rather than the document -- `strand.c` says why
 * twice over -- and silent for a device the operator consented to with
 * `--strand-credentials`, or one whose `on_unmanage = "clear"` takes the key
 * away with the link.
 */
void ncfg_plan_stranded_credentials(ncfg_builder_t *builder);

/*
 * Whether a running pppoe or openvpn backend is one the document still asks
 * for, asked of the device list rather than the interface list.
 *
 * Beside the pass that starts one, for `ncfg_plan_supplicant_wanted`'s reason:
 * the conditions that start a daemon and the conditions that keep one have to
 * stay the same, and two copies is how they come to disagree.
 */
int ncfg_plan_session_wanted(const ncfg_document_t *desired, const char *name, int kind);

void ncfg_plan_dot1x(ncfg_builder_t *builder, const ncfg_interface_t *interface,
    const ncfg_plan_ids_t *base, ncfg_plan_ids_t *out);
int ncfg_plan_supplicant_wanted(const ncfg_document_t *desired, const ncfg_observed_t *observed,
    const char *name);

/*
 * The supplicant a wireless radio needs, and its half of the rule above.
 *
 * The same op as `dot1x.c`'s and in the same place in the order -- 0008 puts
 * wired 802.1X and wifi on one supplicant -- so the two are one question to
 * the teardown and `ncfg_plan_supplicant_wanted` asks this one.
 *
 * **Planned last of the prerequisites**, which is the Rust's order and not an
 * arrangement of convenience: an interface carrying a `dot1x` block has
 * already said what its supplicant is for, and a radio running an access point
 * does not also join networks with the same interface. `radio.c` says what
 * getting either backwards costs.
 *
 * `observed` is an argument because being a radio is two facts from two
 * places: the `device` block says `managed` and that there is radio policy
 * here, and only the kernel can say the interface is a radio at all.
 */
void ncfg_plan_radio_supplicant(ncfg_builder_t *builder, const ncfg_interface_t *interface,
    const ncfg_plan_ids_t *base, ncfg_plan_ids_t *out);
int  ncfg_plan_radio_supplicant_wanted(const ncfg_document_t *desired,
    const ncfg_observed_t *observed, const char *name);
void ncfg_plan_radio_warn(ncfg_builder_t *builder);

/*
 * The hostapd a radio runs, and whether a running one is still asked for.
 *
 * `dot1x.c`'s arrangement and for its reason: both halves of the rule in one
 * file, because the conditions that start a backend and the conditions that
 * keep one have to stay the same. Planned in the same place in the order as
 * the supplicant -- before any address -- and `access_point.c` says what
 * getting that backwards costs on a radio.
 *
 * The restart is here rather than beside the station lists because it is the
 * same question: hostapd reads its file once and has no reload, so every
 * change to an access point but its station lists is a stop and a start.
 * `ncfg_plan_access_point_restart_identity` answers whether it planned one, so
 * a caller can leave the lists alone -- an access point that is coming back
 * rebuilds them from the file anyway.
 */
void ncfg_plan_access_point(ncfg_builder_t *builder, const ncfg_interface_t *interface,
    const ncfg_plan_ids_t *base, ncfg_plan_ids_t *out);
int  ncfg_plan_access_point_wanted(const ncfg_document_t *desired, const char *name);
void ncfg_plan_access_point_warn(ncfg_builder_t *builder);
int  ncfg_plan_access_point_restart_identity(ncfg_builder_t *builder,
    const ncfg_access_point_t *point, const ncfg_observed_backend_t *running);
void ncfg_plan_access_point_restart_policy(ncfg_builder_t *builder, const char *device,
    const ncfg_observed_policy_t *live, const ncfg_access_control_t *wanted);

/*
 * What this interface tells the hosts behind it.
 *
 * Takes the addressing ids as well as the base, because a router advertising a
 * prefix it does not itself hold is advertising a route to nowhere -- and the
 * prefix is very often the one the addressing just derived from a delegation.
 */
void ncfg_plan_advertise(ncfg_builder_t *builder, const ncfg_interface_t *interface,
    const ncfg_plan_ids_t *base, const ncfg_plan_ids_t *addressing);

/*
 * Which interfaces a `linkset` is not using, and the sentence that says so.
 *
 * Collected before anything is planned and released at the end. Two passes ask:
 * the route pass withholds a spare's routes, and the teardown withdraws the
 * ones already installed -- which is how the set actually switches over, since
 * a second default route at a worse metric is a black hole with a fallback
 * rather than a spare.
 */
void ncfg_plan_standby_collect(ncfg_builder_t *builder);
void ncfg_plan_standby_free(ncfg_builder_t *builder);
int  ncfg_plan_standby_of(const ncfg_builder_t *builder, const char *name, const char **set_out,
    const char **instead_out);
void ncfg_plan_standby_warn(ncfg_builder_t *builder, const char *name);

/*
 * `on_unmanage = "clear"`: the devices netcfgd is to own nothing on.
 *
 * `collect` runs before the warnings, because the sentence an operator reads
 * about an unmanaged device depends on which of the two policies it carries.
 * `begin` and `end` bracket the teardown: between them the document has the
 * clearing devices filtered out and `ncfg_builder_push` lets an action through
 * for one, which is the only window in which either is true.
 */
void ncfg_plan_clearing_collect(ncfg_builder_t *builder);
int  ncfg_plan_clearing(const ncfg_builder_t *builder, const char *name);
void ncfg_plan_clearing_begin(ncfg_builder_t *builder);
void ncfg_plan_clearing_end(ncfg_builder_t *builder);

/*
 * The address a `delegated` source names, resolved against the observation.
 *
 * Two callers, which is the whole reason it is here: the forward pass adds the
 * address, and the teardown asks whether an address it is about to remove is
 * this one. A second answer to that question is a plan that adds an address
 * and deletes it again on every reconcile.
 */
void ncfg_plan_delegated(ncfg_builder_t *builder, const ncfg_interface_t *interface, size_t index,
    const ncfg_plan_ids_t *base, ncfg_plan_ids_t *out);
int ncfg_plan_delegated_address(const ncfg_builder_t *builder,
    const ncfg_address_source_t *source, char *out, size_t out_size, char *err, size_t err_size);

/* ------------------------------------------------------------------------ *
 * What something outside netcfgd reported
 * ------------------------------------------------------------------------ */

/*
 * The report for this interface, where there is one.
 *
 * Shared for the reason `ncfg_plan_delegated_address` is: the addressing pass,
 * the route list and the teardown each have to answer "is this still wanted?"
 * about a value the document does not hold, and a second answer to that
 * question is a plan that adds something and deletes it again for ever.
 *
 * The rule that decides whether a report is believed at all is
 * `ncfg_plan_takes_reports`, and it is in `plan.h` rather than here because
 * `ncfg explain` is its second caller -- which is what 0263 said should happen
 * to it the moment this planner acted on `reported` rather than holding it.
 */
const ncfg_observed_report_t *ncfg_plan_report_for(const ncfg_observed_t *observed,
    const char *name);

/* The addresses a report carries, planned as netcfgd's own (decision 0047). */
void ncfg_plan_reported(ncfg_builder_t *builder, const ncfg_interface_t *interface, size_t index,
    const ncfg_plan_ids_t *base, ncfg_plan_ids_t *out);

/*
 * Whether the report for this interface still names this address.
 *
 * The teardown's half of the pass above, and **compared canonically**: a
 * report's text is whatever its writer printed and never went through the
 * compiler, while the kernel reports its own spelling. project.md 10.169 is
 * what comparing the two as text costs.
 */
int ncfg_plan_reported_holds(const ncfg_observed_t *observed, const char *interface,
    const char *address);

/*
 * Every route an interface should have: the document's, then the report's.
 *
 * Entries below `owned_from` are shallow copies whose strings are the
 * document's; from there on the strings are this block's and
 * `ncfg_plan_routes_free` gives them back. A caller may copy a route by value
 * so long as the copy does not outlive the block.
 */
typedef struct {
	ncfg_route_t *routes;
	size_t        count;
	size_t        owned_from;
} ncfg_plan_routes_t;

void ncfg_plan_routes_for(ncfg_builder_t *builder, const ncfg_interface_t *interface,
    ncfg_plan_routes_t *out);
void ncfg_plan_routes_free(ncfg_plan_routes_t *routes);

/*
 * How many times netcfgd starts a backend that does not stay up before it
 * stops trying.
 *
 * A daemon that dies as fast as netcfgd starts it produced 181 starts in
 * twelve seconds -- measured, with a fake that lived for half a second
 * (0079). Published so a test cannot spell the number itself.
 */
#define NCFG_PLAN_RESTART_LIMIT 5

/* Whether this interface's link is one the passes may plan against at all:
 * absent hardware and a declined create are both "nothing will bring this into
 * being", and planning for either fills a plan with actions that must fail. */
int ncfg_plan_link_is_plannable(const ncfg_builder_t *builder, const char *name);

/* ------------------------------------------------------------------------ *
 * The comparisons
 * ------------------------------------------------------------------------ */

/* Whether `candidate` falls inside the subnet `network/prefix`, where both are
 * written as CIDR and as a bare address. Ordering rule 4's whole question. */
int ncfg_plan_subnet_contains(const char *network_cidr, const char *candidate);

/*
 * Whether two addresses are the same address.
 *
 * **Compared the way the model compares and never the way the text reads.**
 * The document's addresses come through the compiler's `canonical_address`
 * already; an address this planner *derives* is rendered by `value.h` and so
 * does too -- but the question is asked against the kernel's own spelling, and
 * a comparison that happened to work for one pair is the defect 10.169
 * records: one address written twice reads as two, and the plan installs it
 * again for ever. Text equality is the answer only where neither side parses,
 * which is where there is nothing better to say.
 */
int ncfg_plan_address_equal(const char *left, const char *right);

/* Record an `addr.add` so ordering rule 4 can find it. The address must
 * outlive the plan -- the document's own, or one interned into it. */
void ncfg_plan_note_added(ncfg_builder_t *builder, const char *interface, const char *address,
    uint32_t id);

/*
 * A copy of `policy` the plan owns, with room for `extra` servers and search
 * suffixes appended by the caller.
 *
 * `ncfg_plan_intern_route`'s shape, and here for the reason plan.h gives for
 * *not* copying a DNS policy: a policy that came straight off the document is
 * borrowed, and a plan must not outlive the document anyway. A **merged**
 * scope is neither the document's nor the observer's -- it is the document's
 * servers with a lease's appended -- so it has to be somebody's, and the plan
 * is the only thing on the right side of every one of those lifetimes.
 *
 * Shallow: every string is still the document's or the observation's, which is
 * the same borrow the policy itself would have been.
 */
ncfg_dns_policy_t *ncfg_plan_intern_dns_policy(ncfg_plan_t *plan, const ncfg_dns_policy_t *policy,
    size_t extra_servers, size_t extra_search);

/* Whether a desired route is the one the kernel already holds. */
int ncfg_plan_route_matches(const ncfg_route_t *desired, const ncfg_observed_route_t *observed);

/* A route's `destination via X metric N`, for a plan's reason line. */
const char *ncfg_plan_render_route(ncfg_plan_t *plan, const ncfg_route_t *route);

#endif /* NCFG_PLAN_INTERNAL_H */
