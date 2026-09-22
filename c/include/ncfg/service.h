/*
 * service.h -- the half of the executor that is not netlink.
 *
 * WHAT THIS MODULE IS FOR
 *   `kernel.c` speaks rtnetlink: links, addresses, routes. Fourteen ops in the
 *   taxonomy change a machine by other means -- a daemon started or stopped, a
 *   control socket written to, a file under `/proc`, a resolver configuration
 *   delivered -- and every one of them has a module under `src/backend/` that
 *   already knows how. This is the joining, and **it writes none of that a
 *   second time**: every verb below is a lookup, a refusal or a call into
 *   `dns.h`, `hostapd.h`, `ra.h`, `openvpn.h` or `supplicant.h`.
 *
 * THE SEAM, AND WHY EVERY PATH IS A MEMBER OF IT
 *   `ncfg_service_t` is where `/run`, `/proc`, the control directories, the
 *   resolver's three files and the three daemons' programs are written down by
 *   the caller. **Nothing here has a default and nothing here reads the
 *   environment.** That is `ncfg_resolv_machine_t`'s bargain and
 *   `ncfg_dns_targets_t`'s, taken for the same reason: the machine these tests
 *   are built on is a workstation whose network is live, and a default would
 *   make the difference between a test and an outage a variable somebody
 *   remembered to set. A member left NULL refuses the ops that need it, **by
 *   name**, rather than reaching for the machine's own path.
 *
 *   `ncfg_service_machine` is the one place the real paths are spelled, so a
 *   test asserts what a daemon would use by reading it rather than by letting
 *   anything write there. That is `ncfg_contention_machine`'s arrangement and
 *   it is here for its reason.
 *
 * IDEMPOTENCE IS A PROPERTY OF EACH VERB, NOT OF THE PLAN
 *   `plan.h` names plan idempotence as load-bearing: applying a plan twice
 *   produces an empty second plan. That holds only if each op, run twice,
 *   leaves the machine where the first run left it -- so every verb here is
 *   written to be safe to repeat, and where the underlying daemon is not, the
 *   question is **asked before it is answered**:
 *
 *     * `access_control.add` and `.del` read the list back over hostapd's
 *       control socket first. hostapd's `ADD_MAC` for an address already on
 *       the list answers `FAIL` (`hostapd_add_acl_maclist` refuses a
 *       duplicate), so an executor that simply sent it would fail the second
 *       apply of a converged machine. The Rust sends it blind and its own
 *       comment claims the command is idempotent; see the divergence list.
 *     * `wifi.associate` asks `STATUS` before `SELECT_NETWORK`, so a radio
 *       already on the network it was told to join is left alone rather than
 *       being made to re-associate -- which on a working link is a visible
 *       outage produced by a plan that had nothing to do.
 *     * `backend.start` asks whether netcfgd's own daemon is already running
 *       before starting a second one, and `backend.stop` treats nothing
 *       listening as the state it was asked to produce.
 *     * The four `/proc` writers are idempotent because writing a value that
 *       is already there is the same write.
 *
 * WHERE AN INVERSE COMES FROM
 *   The planner declares an action's inverse and `ncfg_apply_revert` replays
 *   it; nothing here chooses one. What this header owes is to say **which of
 *   these verbs can be undone at all**, since a revert that silently skips an
 *   op is what `plan.h`'s "cannot be undone" warning is about:
 *
 *     * `sysctl.set_forwarding`, `.set_privacy`, `.set_accept_ra` and
 *       `hostname.set` each invert to the same op carrying the previous
 *       value, which the observation has.
 *     * `backend.start` inverts to `backend.stop` on the same kind and
 *       interface, and `backend.stop` to `backend.start`.
 *     * `access_control.add` inverts to `access_control.del` on the same list
 *       and station, and back.
 *     * `wifi.associate` inverts to `wifi.disassociate`; **`wifi.disassociate`
 *       has no inverse**, because rejoining needs a network the op does not
 *       carry.
 *     * `dns.apply`, `wifi.set_profiles` and `wifi.set_regdom` have no
 *       inverse. Each replaces a whole set with another, and the value it
 *       replaced is not in the op -- a `dns.apply` carrying the previous
 *       policy would put a resolver configuration in `/run/netcfgd/
 *       plan.last.json` for the sake of an undo the next reconcile performs
 *       anyway.
 *
 * ERRORS
 *   base.h's convention throughout: 1 or 0, and a sentence.
 */
#ifndef NCFG_SERVICE_H
#define NCFG_SERVICE_H

#include <stddef.h>

#include "ncfg/apply.h"
#include "ncfg/dhcp.h"
#include "ncfg/dns.h"
#include "ncfg/document.h"
#include "ncfg/plan.h"
#include "ncfg/pppoe.h"
#include "ncfg/secrets.h"

/* ------------------------------------------------------------------------ *
 * Where a machine keeps the things this module writes
 * ------------------------------------------------------------------------ */

/*
 * Nothing is spelled a second time here, and the three that could be are named
 * instead: `NCFG_RUN_DIR_DEFAULT` for netcfgd's own runtime state,
 * `NCFG_OBSERVE_PROC_ROOT_DEFAULT` for the sysctls and the hostname -- the
 * same constant the observer reads them through, so a test that writes with
 * this module and reads with that one is pointed at one place -- and
 * `NCFG_SUPPLICANT_CTRL_DIR` for the control sockets.
 *
 * How long a control socket gets is `NCFG_SUPPLICANT_IMPATIENT_MS`, for 0114's
 * reason: every one of these runs inside an apply, and the thing waiting
 * behind it is the reconcile loop.
 */

/* ------------------------------------------------------------------------ *
 * What the ops do not carry
 * ------------------------------------------------------------------------ */

/*
 * What one interface advertises, resolved.
 *
 * **The prefixes are an argument rather than something this resolves**, and
 * that is a divergence recorded in 0263 -- but not the one this comment used
 * to give. It said the arithmetic had no port, naming
 * `derive_from_delegation`; `value.h` has had `ncfg_address_from_delegation`
 * since the planner needed it, and `ncfg_observed_prefix_of` is the resolution
 * built on it, which the planner's `advertise` pass and the daemon both call.
 * There is one reading of the rule, not three.
 *
 * The divergence that is real is **when** it is resolved. The Rust resolves at
 * the moment of the start, reading the delegations off disk; this resolves
 * when the executor is opened, which is once per apply. A delegation landing
 * between those two points is announced a pass later. That is the price of the
 * prefixes being a value the caller owns, and it is a pass rather than a
 * lease: the alternative is an executor that reaches the filesystem, which is
 * what this header's whole seam exists to prevent.
 *
 * So whoever holds the delegations resolves them and hands the result over.
 * An interface with no entry is a refusal naming it, never a router
 * advertising nothing -- and an interface whose references have not resolved
 * yet is one of those, deliberately.
 */
typedef struct {
	const char        *iface;
	/* Borrowed from the document. */
	const ncfg_ra_policy_t *policy;
	const char *const *prefixes;
	size_t             prefix_count;
	/* The nameservers the LAN's own DNS scope carries, for `RDNSS`. */
	const char *const *servers;
	size_t             server_count;
} ncfg_service_advertise_t;

/*
 * One tunnel, with its credentials already resolved.
 *
 * `ncfg_openvpn_start` takes the username and the password as values and
 * writes them to a file only it knows the name of, which is the arrangement
 * that keeps them off a command line. Resolving them is the caller's because
 * the resolver is the caller's; this carries what came back.
 */
typedef struct {
	const char *iface;
	/* The `.ovpn` netcfgd hands over unread. */
	const char *config;
	/* NULL for a tunnel that authenticates without them. */
	const char *username;
	const char *password;
	/* Where the tunnel's `--up` script writes what it was given. */
	const char *report;
} ncfg_service_tunnel_t;

/*
 * One PPPoE session, with its password already resolved.
 *
 * `ncfg_service_tunnel_t`'s arrangement and for its reason: the credential is
 * written to a file only pppd and netcfgd know the name of, and resolving it
 * is the caller's because the resolver is the caller's. What is borrowed from
 * the document is the block itself -- the parent interface, the username, the
 * optional service and access concentrator -- because the options file is
 * rendered from all of it and a copy here would be a second spelling of the
 * same five fields.
 *
 * **A session whose password cannot be resolved gets no entry**, and
 * `backend.start` then refuses it by name. pppd dialling with the wrong
 * credential retries for ever -- `persist` and `maxfail 0` are in the options
 * netcfgd writes -- which reads to an operator as a line fault rather than as
 * a secret netcfgd could not read.
 */
typedef struct {
	const char *iface;
	/* Borrowed from the document. */
	const ncfg_pppoe_config_t *config;
	/* The resolved password, or NULL for a document that named none. */
	const char *password;
} ncfg_service_session_t;

/*
 * The route metric one interface's DHCP client is started with.
 *
 * **Resolved by the caller rather than read out of the document here**, which
 * is `ncfg_service_advertise_t`'s arrangement and is here for a measured
 * reason: the rule is `netcfgd_model::wifi::effective_metric`'s -- *the
 * network's `metric` where the radio is associated to one that carries it, and
 * the interface's own `preference` otherwise* -- and half of it comes from the
 * observation rather than from the document. The Rust built this list from
 * `interface.preference` alone and so missed `network { metric = N }`
 * entirely: measured on a veth with a real server, the lease's route carried
 * 1003, dhcpcd's own default, on a document whose network said 100, and it
 * stayed 1003 across a switch to a network saying 400. An executor holding
 * only the document cannot answer it, so it does not try.
 *
 * An interface with no entry starts a client with no `-m`, which is the
 * client's own default and the honest answer for a document that named no
 * preference. It is **not** a refusal: no metric is an ordinary document.
 */
typedef struct {
	const char   *iface;
	ncfg_optint_t metric;
} ncfg_service_client_metric_t;

/*
 * Everything the service-side ops need and no op carries.
 *
 * Borrowed throughout and there is no free: every member points at something
 * the caller already holds, and **the document in particular must outlive
 * this**, which is `plan.h`'s rule for the four values a plan borrows and is
 * here for the same reason.
 */
typedef struct {
	/* `<run>/netcfgd`. NULL refuses every backend op and `dns.apply`. */
	const char *run_dir;
	/* Where `sys/net/...` and `sys/kernel/hostname` are. NULL refuses the
	 * four sysctl and hostname ops. */
	const char *proc_root;
	/* Where the supplicant control sockets are. NULL refuses the wifi ops. */
	const char *supplicant_dir;
	/*
	 * The document the plan was built from, for what an op names rather than
	 * carries: an access point's block, a radio's networks and its
	 * `mac_policy`. A plan goes to `/run` and over the socket, so a passphrase
	 * or a whole block in one would be constraint 5 broken for nothing.
	 */
	const ncfg_document_t *document;
	/* What resolves a credential hostapd or the supplicant is given. NULL
	 * refuses the two ops that need one, rather than sending an empty
	 * passphrase. */
	const ncfg_secret_resolver_t *secrets;
	/*
	 * The four daemons, by path.
	 *
	 * NULL means "find the conventional name", which `ncfg_hostapd_start`,
	 * `ncfg_ra_start`, `ncfg_openvpn_start` and `ncfg_supplicant_start` each do
	 * for a daemon and which `backend_internal.h` records the cost of for a
	 * test: 20 of 45 checks in the Rust's live openvpn script were silently
	 * exercising the machine's own openvpn. **A test passes a program it
	 * wrote.**
	 *
	 * `supplicant_program` in particular is the seam the Rust spells
	 * `NCFG_WPA_SUPPLICANT`, and its own comment says what the absence cost:
	 * the fixed directories were searched before `PATH`, so on any machine
	 * that has `wpa_supplicant` installed -- which is every machine this runs
	 * on -- a test could not put a stand-in in front of it, and the one thing
	 * that function does was only ever exercised by hand. Here it is an
	 * argument rather than a variable, for this header's reason.
	 */
	const char *hostapd_program;
	const char *radvd_program;
	const char *openvpn_program;
	const char *supplicant_program;
	/* Where a resolver configuration is delivered. */
	ncfg_dns_targets_t dns;
	/*
	 * Every scope, so that one `dns.apply` delivers all of them.
	 *
	 * `dns.h`'s flattening is over a set, and a delivery of one scope would
	 * write a `resolv.conf` holding one interface's servers -- which is the
	 * Rust's reason for the same list and is the trap its own comment records:
	 * an executor that rebuilt the scopes from the document alone delivered an
	 * empty file while the plan said it had applied one. A scope can come from
	 * an observation rather than from the document.
	 *
	 * Empty falls back to the single scope the op carries, which is what a
	 * caller with no context gets and is better than delivering nothing.
	 */
	const ncfg_dns_scope_t *dns_scopes;
	size_t                  dns_scope_count;
	/* What each advertising interface announces, resolved. */
	const ncfg_service_advertise_t *advertising;
	size_t                          advertise_count;
	/* Each tunnel, with its credentials resolved. */
	const ncfg_service_tunnel_t *tunnels;
	size_t                       tunnel_count;
	/* Each PPPoE session, with its password resolved. */
	const ncfg_service_session_t *sessions;
	size_t                        session_count;
	/*
	 * What a PPPoE session needs from the machine: which pppd to run and
	 * where pppd's own pid file may be.
	 *
	 * A struct for `dhcp`'s reason -- they are one subject and `pppoe.h` owns
	 * it. Left zero, a session start finds pppd by name and looks for a pid
	 * file in the machine's own directories, which is what
	 * `ncfg_pppoe_machine` would have answered; unlike the DHCP clients there
	 * is nothing here a wrong answer could write to, because the only thing
	 * netcfgd does with a pid it finds is check whose it is.
	 */
	ncfg_pppoe_machine_t pppoe;
	/*
	 * What a DHCP client needs from the machine: the three programs, the
	 * shipped hook, dhcpcd's own run directory and what `-f` points at.
	 *
	 * A struct rather than five members here because they are one subject and
	 * `dhcp.h` owns it -- and because `ncfg_dhcp_machine` is the one place
	 * this machine's answers are written down, exactly as
	 * `ncfg_service_machine` is for everything else in this header. Left zero,
	 * a DHCP start refuses by name rather than reaching for `/run/dhcpcd` and
	 * `/usr/libexec`.
	 */
	ncfg_dhcp_machine_t dhcp;
	/* What each interface's client is started with, resolved. */
	const ncfg_service_client_metric_t *client_metrics;
	size_t                              client_metric_count;
	/*
	 * How long a control socket gets. 0 means `NCFG_SUPPLICANT_IMPATIENT_MS`.
	 *
	 * An argument because a test drives a fake that is deliberately silent and
	 * should not wait a second per case to find out.
	 */
	int patience_ms;
} ncfg_service_t;

/*
 * The machine's own paths, in one place.
 *
 * Fills `run_dir`, `proc_root` and `supplicant_dir` with this machine's,
 * `dns.resolv_conf`, `dns.dnsmasq_conf`, `dns.unbound_conf` and `dns.run_dir`
 * with `dns.h`'s, and `dhcp` with `ncfg_dhcp_machine`'s. Everything else is
 * left as it was, since a document, a resolver and a program list are the
 * caller's and there is no machine-wide answer for them.
 *
 * **Nothing in this project calls it from a test to write anything.** It
 * exists so that the paths a daemon would use are a value a check can read.
 */
void ncfg_service_machine(ncfg_service_t *out);

/* ------------------------------------------------------------------------ *
 * The four that write to /proc
 * ------------------------------------------------------------------------ *
 *
 * Each takes the root as its first argument and refuses a NULL or empty one
 * by name. `observe.h`'s readers take the same argument and the same shape, so
 * a test can write a value with one of these and read it back with one of
 * those against the same fixture -- which is the only way "the write landed
 * where the observation looks" is a checked property rather than two paths
 * spelled twice.
 */

/*
 * Forward on one interface, in both families.
 *
 * The per-device sysctl, never the global `net.ipv4.ip_forward`, which would
 * set every interface on the machine including the ones the document says
 * nothing about.
 *
 * **An IPv6 failure is a warning and an IPv4 one is fatal.** A kernel built
 * with `ipv6.disable=1` has no IPv6 sysctl at all, and refusing there would
 * make netcfgd unable to configure an IPv4 router. The IPv4 path has no such
 * excuse. The Rust makes the same split; what is added here is that the
 * warning names what it costs.
 */
int ncfg_service_set_forwarding(const char *proc_root, const char *iface, int enabled, char *err,
    size_t err_size);

/*
 * RFC 4941 temporary addresses on one interface.
 *
 * `2` prefers the temporary address and `0` turns the mechanism off. The
 * kernel's `1` -- generate one and prefer the stable address -- has no
 * spelling in the document and is never written.
 */
int ncfg_service_set_privacy(const char *proc_root, const char *iface, int prefer_temporary,
    char *err, size_t err_size);

/*
 * Whether the kernel acts on a router advertisement here.
 *
 * **Only `1` and `2` are written, and anything else is refused by name.** `2`
 * is accept-even-while-forwarding and `1` is the kernel's own default, which
 * is what an interface that stops asking for SLAAC gets back. `0` is a thing
 * an operator may have chosen and no document here asks for (0073) -- so
 * writing it would be netcfgd switching something off that it was never told
 * to own. The Rust takes a `u8` and writes whatever arrives; the model's field
 * is an `int64_t` here, so the check lands where the value is used and names
 * the range.
 */
int ncfg_service_set_accept_ra(const char *proc_root, const char *iface, int64_t value, char *err,
    size_t err_size);

/*
 * The running hostname.
 *
 * `sys/kernel/hostname`, not `sethostname(2)` and not `/etc/hostname`: the
 * first is the same value through a path a test can point elsewhere, and the
 * third is what the init system reads at boot and is not netcfgd's to write.
 * So this does not survive a reboot on its own, which is the honest behaviour
 * -- netcfgd sets the name on every apply and the first apply after boot is
 * what puts it back.
 *
 * A name carrying a newline, a NUL or a byte below `0x20` is refused rather
 * than written: the file is a line, and a value that ends it early is a
 * hostname neither end would agree about.
 */
int ncfg_service_set_hostname(const char *proc_root, const char *name, char *err, size_t err_size);

/* ------------------------------------------------------------------------ *
 * hostapd's access control lists
 * ------------------------------------------------------------------------ */

/*
 * The control command that names one of hostapd's two lists.
 *
 * `ACCEPT_ACL` or `DENY_ACL`, NULL outside the set -- value.h's convention,
 * that a plausible word for something that is not in the set is worse than no
 * word. **Spelled here rather than in the model**, which is where the Rust
 * keeps it as `AclPolicy::ctrl_command`, because this build has one caller for
 * it; the second caller takes this one rather than writing a third.
 */
const char *ncfg_service_acl_command(int policy);

/*
 * Put one station on one of a running access point's lists, or take it off.
 *
 * **The list is read back first**, which is what makes this idempotent -- see
 * the note at the top of this file about `ADD_MAC` refusing a duplicate. The
 * reply is parsed by `ncfg_hostapd_parse_acl_show`, which is hostapd.h's and
 * is the half of that round trip its header says is missing; this is the other
 * half.
 *
 * The address is normalised before it is compared or sent. Everything reaching
 * here has been through the compiler, so that is a backstop -- but it is the
 * backstop that keeps a value from a configuration file out of a control
 * command unexamined, and a mismatched case would re-send the same command for
 * ever.
 *
 * `run_dir` is netcfgd's own, under which `ncfg_hostapd_ctrl_dir` is where the
 * socket lives.
 */
int ncfg_service_access_control(const char *run_dir, const char *iface, int policy,
    const char *station, int adding, int patience_ms, char *err, size_t err_size);

/* ------------------------------------------------------------------------ *
 * The supplicant-side wifi ops
 * ------------------------------------------------------------------------ */

/*
 * Where netcfgd records the digest of what a supplicant was handed.
 *
 * `<run>/supplicant/<iface>.networks.sha256`, which is the Rust's spelling and
 * is what an observation reads to answer `networks_match`. Published because
 * two readers of one path is how two readers of one path come to disagree --
 * and `ncfg_observe_supplicants` is that second reader now, taking this rather
 * than spelling the name again.
 *
 * 1 with the path in `out`; a path that would not fit is a failure rather than
 * a shorter one.
 */
/*
 * The three device-wide settings a supplicant is configured with.
 *
 * `mac_policy`, scan randomisation and autoconnect, from the `wifi` block of
 * the device -- or their defaults where it has none: permanent address, no
 * randomisation, joins.
 *
 * **Published because the fingerprint is computed twice and must match.** The
 * executor digests these three alongside the networks when it records what a
 * supplicant was handed; the observer digests them again to answer
 * `networks_match`. Two spellings of the defaults is a digest that never
 * matches, so `networks_match` would be false for ever and the planner would
 * re-hand the whole set on every reconcile.
 */
void ncfg_service_radio_policy(const ncfg_document_t *document, const char *device,
    int *mac_policy, int *randomise, int *joins);

int ncfg_service_networks_record_path(const char *run_dir, const char *iface, char *out,
    size_t out_size, char *err, size_t err_size);

/*
 * Replace the set of networks a radio's supplicant holds.
 *
 * 0015's rule: the supplicant holds no state of its own, so the whole set is
 * what netcfgd is authoritative about -- clear first, then add each network the
 * document describes, then record the digest. A wired 802.1X port is a
 * different population rather than a smaller one and takes
 * `ncfg_supplicant_configure_wired` instead.
 *
 * **The `profiles` the op carries are not read**, which is the Rust's
 * behaviour and is deliberate: the op names which device, and what that device
 * gets is every network in the document, chosen among by the supplicant.
 * Filtering here would make the plan's list a second authority over the
 * document's.
 *
 * The digest is best effort and its failure is a warning: 0180's rule, that a
 * record which could not be kept must not fail an apply that worked. What it
 * costs is said out loud, because "the planner sees no reason to act" is
 * indistinguishable from a correct machine unless somebody says so.
 */
int ncfg_service_set_profiles(const ncfg_service_t *service, const char *device, char *err,
    size_t err_size);

/*
 * Join the network a profile names.
 *
 * `network_id` is the document's `network` block id, not a supplicant slot
 * number: a plan is written before anything is added to a supplicant and
 * cannot name a slot. So the SSID is taken from the document, the supplicant's
 * own `LIST_NETWORKS` is searched for it, and that slot is selected.
 *
 * **Asks `STATUS` first.** A radio already associated with that network is
 * left alone: re-selecting is a disassociation and a rejoin, which on a
 * working link is an outage produced by a plan that had nothing to do -- and
 * `plan.h` names exactly this as the property that must hold.
 *
 * Waits for the join to resolve, because `SELECT_NETWORK` answering `OK` means
 * the supplicant accepted the command and not that anything was joined (0197).
 */
int ncfg_service_associate(const ncfg_service_t *service, const char *device,
    const char *network_id, char *err, size_t err_size);

/*
 * Leave whatever this radio is on.
 *
 * `DISCONNECT`, which also stops the supplicant reconnecting on its own until
 * something selects a network again. **Idempotent without asking**: it names a
 * state rather than a transition, so a radio that is already disconnected
 * answers `OK` to it -- and a read first would be a round trip whose answer can
 * change before the command that follows it.
 */
int ncfg_service_disassociate(const ncfg_service_t *service, const char *device, char *err,
    size_t err_size);

/*
 * Set the regulatory domain a radio obeys.
 *
 * `SET country <XX>` on the supplicant's control socket, which is what
 * `wpa_supplicant` turns into the `nl80211` regulatory request -- so this
 * needs a supplicant on the device and refuses by name where there is none.
 *
 * **A divergence, and the largest one in this module.** `apply.c` used to
 * refuse this op saying it "goes over generic netlink, and this executor holds
 * an rtnetlink socket only", and the Rust never implements it at all --
 * `WifiSetRegdom` is a variant nothing constructs, which
 * `netcfgd-plan/src/lib.rs` records as one of the three radio settings with no
 * consumer anywhere while the README advertises them. Going through the
 * supplicant is what makes it executable without opening a second netlink
 * family, and it is the same route `wpa_supplicant`'s own `country=` takes.
 *
 * The country is checked as ISO 3166-1 alpha-2 -- two ASCII letters, upper
 * cased -- before it is sent. A value from a configuration file reaching a
 * control command unexamined is the thing this module refuses everywhere else.
 */
int ncfg_service_set_regdom(const ncfg_service_t *service, const char *device,
    const char *country, char *err, size_t err_size);

/* ------------------------------------------------------------------------ *
 * Backends
 * ------------------------------------------------------------------------ */

/*
 * Whether this build can start, stop or reload this backend, and why not.
 *
 * Asked by `ncfg_apply_supported`, which is the single list of what this build
 * carries out, so that the refusal is a value rather than a branch inside the
 * executor. Separate from that function because the answer turns on the
 * backend's *kind* as well as on the op -- the same shape `creatable` has for
 * `link.create`, and for the same reason: three kinds have a module under
 * `src/backend/` and the rest do not.
 *
 * `op` must be one of the three backend ops.
 */
int ncfg_service_backend_supported(const ncfg_op_t *op, char *err, size_t err_size);

/*
 * Start one backend on one interface.
 *
 * **Already running is success and nothing is started.** netcfgd's own daemon
 * is identified by a path it chose -- `ncfg_ra_running_pid`,
 * `ncfg_openvpn_running_pid` and `ncfg_supplicant_running_pid` all check
 * `/proc/<pid>/cmdline` against it -- so this is a claim about netcfgd's own
 * process rather than a search for something that looks like one. Without it a
 * second apply of a converged machine starts a second daemon beside the first.
 *
 * **A supplicant is also populated here**, which is the one start that is not
 * finished when the process is up: a freshly launched supplicant holds nothing
 * (0015), so `ncfg_service_set_profiles` runs inside this call and a
 * population that failed fails the start. Reporting a start done while the
 * supplicant knows no networks is reporting a port authenticated that is not.
 */
int ncfg_service_backend_start(const ncfg_service_t *service, int kind, const char *iface,
    char *err, size_t err_size);

/*
 * Stop one backend on one interface.
 *
 * **Nothing running is the state this was asked to produce, so that is
 * success** -- but only nothing running. A daemon that has bound its socket
 * and gone silent is a failure here rather than a success, which is 0109: a
 * stop that swallowed it reported success without a byte having been sent,
 * with the access point still on the air and its passphrase still in memory.
 */
int ncfg_service_backend_stop(const ncfg_service_t *service, int kind, const char *iface,
    char *err, size_t err_size);

/*
 * Re-read one backend's configuration.
 *
 * Only a router advertisement daemon has one. radvd re-reads on `SIGHUP`, so a
 * changed prefix costs nothing on the wire -- unlike an access point, where
 * the same question means a restart and a deauthenticated LAN (0026).
 * Everything else is refused by name rather than being given a reload that
 * stops and starts, which would hide that difference behind a word.
 *
 * **Rewriting before signalling is the order that matters**, and it is
 * `ncfg_ra_reload`'s: radvd reads the file when it is told to, so a signal
 * sent first reloads the old contents.
 */
int ncfg_service_backend_reload(const ncfg_service_t *service, int kind, const char *iface,
    char *err, size_t err_size);

/* ------------------------------------------------------------------------ *
 * DNS
 * ------------------------------------------------------------------------ */

/*
 * Deliver a resolver configuration, and record what was delivered.
 *
 * Every scope the context carries, not the one the op names -- see
 * `dns_scopes` above for why. The record under `<run>/dns/` is `ncfg_dns_
 * deliver`'s own last step and is not written again here; what this adds is
 * that the run directory is **demanded before anything is delivered**, so that
 * a delivery nobody could write down is refused rather than made.
 *
 * That record is for a person with `grep`, and it is not what the planner
 * reads: the scopes an apply delivered are folded into `owned.json` by
 * `ncfg_apply_record`, and `observed.dns` comes from there. Without that fold
 * a plan cannot tell an already-applied policy from an unapplied one and every
 * run emits a `dns.apply` -- the plan-idempotence property failing, with the
 * machine already changed.
 *
 * `scope` and `policy` are the op's own and are used only where the context
 * carries no scope list.
 */
int ncfg_service_dns_apply(const ncfg_service_t *service, const char *scope,
    const ncfg_dns_policy_t *policy, char *err, size_t err_size);

/* ------------------------------------------------------------------------ *
 * Carrying out one op
 * ------------------------------------------------------------------------ */

/*
 * Carry out one service-side op.
 *
 * The dispatch `kernel.c` hands its fourteen arms to. An op that is not one of
 * those fourteen is refused by name rather than reported as done -- an
 * executor that answered success for work it did not do would report a
 * converged machine that had not been touched, which is what
 * `ncfg_apply_supported` exists to make impossible.
 *
 * A NULL `service` is refused by name too, and that is the case a caller is
 * most likely to reach: an executor opened without a context can carry out the
 * netlink half of a plan and none of this, and saying so beats a NULL
 * dereference in the one module that changes machines.
 */
int ncfg_service_execute(const ncfg_service_t *service, const ncfg_op_t *op, char *err,
    size_t err_size);

/*
 * Give the kernel executor its service-side context.
 *
 * Declared here rather than in `apply.h` so that the netlink half of the
 * module does not grow a member of this one in its public face. Borrowed: the
 * context, and everything it points at, must outlive the executor.
 *
 * An executor with none refuses every op in this file by name, which is the
 * honest answer for a caller that built one out of `ncfg_kernel_new` alone.
 */
void ncfg_kernel_set_service(ncfg_kernel_t *kernel, const ncfg_service_t *service);

#endif /* NCFG_SERVICE_H */
