/*
 * observed.h -- what the kernel and the backends currently say is true.
 *
 * The other half of the desired/observed pair (`doc/decision/0005`), and the
 * sibling of `document.h`: a document says what the machine should look like,
 * this says what it does. Both live in the model rather than in the observer,
 * because the producer and the planner both depend on it and because this is
 * written to `/run/netcfgd/observed/` where it is as much a documented
 * artifact as the desired-state document is.
 *
 * Everything `document.h` says about representation holds here unchanged and
 * is not repeated: every number is `int64_t` with the Rust's own width checked
 * on the way in, every closed-set field is `int` holding one of the constants
 * beside it, a list is a counted array, and one free takes the tree apart.
 * What follows is only what is different about an observation.
 *
 * ABSENT IS NOT FALSE, AND THIS MODULE IS WHERE THAT RULE LIVES
 *
 *   Nearly every `ncfg_optbool_t` below is an answer netcfgd could not get,
 *   and it is **not** the same as `false`:
 *
 *     * `reachable` absent means no probe is configured or none has finished.
 *       A reader that conflated it with `false` would take the network away
 *       from every interface on a machine that configured no probes at all.
 *     * `answering` absent means the kind has no control socket, or nothing
 *       asked. Reading that as "not answering" would put a warning on every
 *       dhcpcd on every machine.
 *     * `secret_matches`, `key_matches`, `config_matches`, `networks_match`
 *       absent mean netcfgd could not compare. Nothing is restarted on one: a
 *       restart deauthenticates every station, and "I could not check" is not
 *       a reason to.
 *     * `forwarding`, `privacy`, `accept_ra` absent mean the sysctl could not
 *       be read -- a container without `/proc/sys`, an IPv6-disabled kernel.
 *
 *   `ncfg_presence_t` is the same rule given a name of its own rather than an
 *   `ncfg_optbool_t`, and the reason is the rendering: unknown must never be
 *   drawn as absent, because a hidden network shown as "not present" looks
 *   permanently gone and the operator's correct response -- try it -- is the
 *   one thing that display argues against (0245).
 *
 * NOTHING SECRET IS IN HERE, AND THE ANSWERS ARE WHY
 *
 *   This goes over the control socket, into `/run` and out of `ncfg status
 *   --json`, so what travels is never a value that could be compared but the
 *   *answer* to the comparison, computed where both halves were already in
 *   hand. A WireGuard device reports the public key the kernel derived and
 *   never the private one; a peer's preshared key is a boolean, because the
 *   kernel hands one back zeroed; an access point's passphrase is absent and
 *   `secret_matches` stands in its place (decisions 0052, 0053, 0054).
 *
 * WHAT THIS DOES NOT CARRY
 *
 *   `crate::link::inventory` and `crate::linkset::choose` are not here. Their
 *   *results* are -- `ncfg_link_entry_t` and `ncfg_chosen_t` travel in the
 *   observation and are read and written in full -- but working them out needs
 *   a document, the linkset nesting rules and the cycle bound, which is
 *   `linkset.rs`'s module rather than this one. The pure rules that need no
 *   document beyond one lookup are here: `ncfg_link_category_of`,
 *   `ncfg_presence_of_interface`, `ncfg_presence_of_network`.
 */
#ifndef NCFG_OBSERVED_H
#define NCFG_OBSERVED_H

#include <stddef.h>
#include <stdint.h>

#include "ncfg/buf.h"
#include "ncfg/document.h"
#include "ncfg/json_write.h"
#include "ncfg/value.h"

/* ------------------------------------------------------------------------ *
 * Ownership and origin
 * ------------------------------------------------------------------------ */

/*
 * Whether netcfgd installed an object.
 *
 * **The asymmetry between the variants is deliberate**: under-claiming
 * ownership costs a little convenience, over-claiming it deletes somebody's
 * manual change. `unknown` is the default and is treated as `foreign` by every
 * decision that would remove something -- pre-5.18 kernels have no
 * `IFA_PROTO`, so address ownership falls back to recorded prior state, which
 * cannot tell our address from an identical one added by hand (0002).
 */
typedef enum {
	NCFG_OWNERSHIP_OURS,
	NCFG_OWNERSHIP_FOREIGN,
	NCFG_OWNERSHIP_UNKNOWN
} ncfg_ownership_t;

/*
 * Whether an object may be removed to satisfy the desired state.
 *
 * Only `ours` qualifies, and **this is the single place that decision is
 * made**, so that no planner path can accidentally widen it.
 */
int ncfg_ownership_may_remove(int ownership);

/* NULL outside the set, which is value.h's rule: a plausible word for a value
 * that is not one is worse than no word. */
const char *ncfg_ownership_name(int ownership);

/*
 * Which addressing source produced an object.
 *
 * Decision 0006 rule 7 turns on this: a missing static address is re-added,
 * but a missing DHCP address means the *lease* is gone, so the remedy is to
 * restart the backend rather than to add the address back. Without it the
 * planner would fight the DHCP client for ownership of its own lease.
 */
typedef enum {
	NCFG_ORIGIN_STATIC,
	NCFG_ORIGIN_DHCP4,
	NCFG_ORIGIN_DHCP6,
	NCFG_ORIGIN_SLAAC,
	NCFG_ORIGIN_LINK_LOCAL,
	NCFG_ORIGIN_DELEGATED
} ncfg_origin_t;

const char *ncfg_origin_name(int origin);

/* ------------------------------------------------------------------------ *
 * The link vocabulary: what a row is, and whether it is there
 * ------------------------------------------------------------------------ */

/*
 * What kind of thing a link is, for choosing an icon or filtering a list.
 *
 * **A filter cannot be built from the kernel's `kind`, and that is why this
 * exists.** Measured on the reporting machine: `enp0s31f6`, `wlp0s20f3` and
 * `lo` all report an empty kind, so a wired card, a radio and the loopback
 * land in one bucket and a dropdown offering "ethernet" shows the radio.
 *
 * **Coarser than the kernel's kind, deliberately.** `gre`, `sit`, `ipip` and
 * `vxlan` are one answer and not four: an operator filtering a list is not
 * asking which encapsulation is in use, and the exact kind is in the row
 * beside it.
 */
typedef enum {
	NCFG_LINK_CATEGORY_LOOPBACK,
	NCFG_LINK_CATEGORY_ETHERNET,
	NCFG_LINK_CATEGORY_WIFI,
	/* **The only category that needs the document.** Nothing on the link says
	 * modem: a `device` block's `modem` section is the one place it is marked,
	 * and the link it produces looks ordinary to the kernel. */
	NCFG_LINK_CATEGORY_MODEM,
	NCFG_LINK_CATEGORY_BRIDGE,
	NCFG_LINK_CATEGORY_BOND,
	NCFG_LINK_CATEGORY_VLAN,
	/* Its own category rather than folded into tunnel, because it is the
	 * tunnel people have, and a list that hides it among five encapsulations
	 * nobody configured is a list nobody filters. */
	NCFG_LINK_CATEGORY_WIREGUARD,
	NCFG_LINK_CATEGORY_TUNNEL,
	NCFG_LINK_CATEGORY_VIRTUAL,
	/* Not a kernel kind at all: a set has no index and no link table entry,
	 * and only the document knows it exists. It is a category because it is a
	 * row an operator filters for. */
	NCFG_LINK_CATEGORY_LINKSET,
	/* **Not an error and not empty.** A kernel gains link kinds faster than
	 * this list does, and a row in no category at all vanishes from every
	 * filtered list -- the quiet failure this whole vocabulary avoids. */
	NCFG_LINK_CATEGORY_OTHER
} ncfg_link_category_t;

const char *ncfg_link_category_name(int category);

/*
 * Whether a link is there, with a third answer for when nobody can say.
 *
 * **Not a boolean, and the third value is the point.** A hidden network cannot
 * be found by looking: a hidden access point beacons with an empty name, so
 * its address is observable and the name-to-address mapping is not. The
 * directed probe that would resolve it is forbidden on a `no IR` channel, so
 * the only evidence left is an attempt to associate. 0245.
 */
typedef enum {
	NCFG_PRESENCE_PRESENT,
	/* Looked for, with a method that would have found it, and not there. */
	NCFG_PRESENCE_ABSENT,
	/* No method available that could have found it. */
	NCFG_PRESENCE_UNKNOWN
} ncfg_presence_t;

const char *ncfg_presence_name(int presence);

/*
 * Which of the document's link-shaped things a row is.
 *
 * **A row has to know, because acting on it differs.** Selecting a network and
 * pressing configure opened an *interface* dialog for an interface that does
 * not exist, which is what happens when a list mixes two kinds of thing
 * without saying which is which. 0247.
 */
typedef enum {
	NCFG_SUBJECT_INTERFACE,
	NCFG_SUBJECT_NETWORK,
	NCFG_SUBJECT_LINKSET
} ncfg_subject_t;

const char *ncfg_subject_name(int subject);

/* One row of the link list: what netcfgd knows about one link. */
typedef struct {
	/* An interface's name, or a `network` block's id for a wifi network --
	 * which is the identity a wifi link has, since the operator names every
	 * block and one name can cover a whole set of access points (0245). */
	char  *name;
	int    category; /* ncfg_link_category_t */
	int    presence; /* ncfg_presence_t */
	/* False for a link the machine has and nobody configured -- a container
	 * bridge, a card another manager owns. Those are in the list because
	 * hiding something demonstrably on the machine is worse than showing
	 * something netcfgd does not manage. */
	int    configured;
	int    subject; /* ncfg_subject_t */
	/* The interface carrying this link right now, where that is not itself.
	 * **Only a wifi network has one**: a network is not hardware, it runs on
	 * whichever radio joined it, and which one belongs in the row rather than
	 * being inferred by whoever is reading. NULL for an interface. */
	char  *carrier;
	/* The linksets this link is a member of. A list rather than one, because a
	 * link may legitimately be in two -- the modem that is both the `uplink`'s
	 * last resort and the out-of-band set's only member. */
	char **sets;
	size_t set_count;
} ncfg_link_entry_t;

/* ------------------------------------------------------------------------ *
 * What a linkset settled on
 * ------------------------------------------------------------------------ */

/*
 * Why a member of a set cannot be used right now.
 *
 * **Named rather than counted**, because every one of these is a different
 * thing to do about it: a cable to plug in, a network out of range, a set
 * whose own members are all down.
 */
typedef enum {
	/* Nothing on this machine answers to the name. */
	NCFG_INELIGIBLE_ABSENT,
	/* A configured network no radio is associated with. Separate from
	 * `absent` because the network exists and is perfectly fine -- nothing is
	 * on it, which is the ordinary state of every saved network but one. */
	NCFG_INELIGIBLE_UNJOINED,
	/* The cable is not in, or the radio is not associated. **A link that is
	 * down reads as this too**, deliberately: `up` is netcfgd's own setting
	 * and a plan is usually in the middle of applying it, so a set that called
	 * a down link unusable would need two applies to bring a machine up. */
	NCFG_INELIGIBLE_NO_CARRIER,
	/* The probe says it is not reaching anything. Only an explicit refusal. */
	NCFG_INELIGIBLE_PROBE,
	/* A nested set with no usable member of its own. */
	NCFG_INELIGIBLE_EMPTY,
	/* A set that names itself, directly or through a chain. Reported rather
	 * than followed: the compiler refuses such a document, and one that did
	 * not come through the compiler gets this instead of a stack overflow. */
	NCFG_INELIGIBLE_CYCLE
} ncfg_ineligible_t;

/* The word a status line or a column uses: `no carrier` and `probe failed`
 * read as sentences, and are not the JSON spellings. NULL outside the set. */
const char *ncfg_ineligible_name(int reason);

/* Where one member of a set stands. */
typedef struct {
	char         *name;
	/* A member's own name for an interface; the radio for a network; the
	 * nested set's own answer for a set. NULL when nothing carries it, which
	 * is also when it is ineligible. */
	char         *interface;
	/* Lower wins; absent reads as 0, the kernel's own default and the
	 * strongest, exactly as an unnumbered route does. */
	ncfg_optint_t metric;
	ncfg_optint_t ineligible; /* ncfg_ineligible_t where `has` */
} ncfg_standing_t;

/*
 * What a set decided, and what it decided it from.
 *
 * The whole standing rather than the winner alone, because "why am I on the
 * modem" is answered by the members that lost and not by the one that won.
 */
typedef struct {
	char            *name;
	char            *active;
	/* Carried beside `active` rather than looked up again, because for a
	 * network member they are different strings and every caller needs the
	 * second one: the routes, the metric and the probe all live on the
	 * interface. */
	char            *interface;
	ncfg_standing_t *members; /* in the order the document lists them */
	size_t           member_count;
} ncfg_chosen_t;

/* ------------------------------------------------------------------------ *
 * How far this machine got, and through what
 * ------------------------------------------------------------------------ */

/*
 * **One answer, because four clients were each working one out.** The Qt tray
 * computed three rungs from the links, the TDE tray transcribed the same rule
 * into TQt3, the NetworkManager shim answered a coarser pair and the text
 * interface had no notion of it -- so each invented a slightly different
 * verdict from the same raw observation.
 *
 * Ordered, and comparable: each rung implies the ones below it.
 */
typedef enum {
	/* Nothing to work with: no interface that counts holds an address. */
	NCFG_RUNG_OFFLINE,
	/* Addressed, and nothing to route through. **The rung that exists because
	 * it was once reported as connected**: a machine here reaches its own
	 * subnet and fails everything else, which looks like a working
	 * configuration to anybody reading an icon. */
	NCFG_RUNG_LOCAL,
	/* A default route exists. As far as netcfgd can tell without asking -- a
	 * captive portal looks exactly like this. */
	NCFG_RUNG_ROUTED,
	/* A probe has confirmed traffic actually reaches somewhere. */
	NCFG_RUNG_ONLINE
} ncfg_rung_t;

const char *ncfg_rung_name(int rung);

/* What this machine is mainly connected through. */
typedef struct {
	char *interface;
	/* The `network` block's id where the link is a radio associated with one,
	 * which is the name an operator recognises, and the interface's own name
	 * otherwise. Never empty. */
	char *label;
	/* So a client can pick an icon without guessing from the name. */
	int   wireless;
} ncfg_primary_t;

typedef struct {
	int             rung; /* ncfg_rung_t */
	/* NULL at `offline`, and also where the machine is addressed on something
	 * but has no default route to rank -- there is no *main* link when nothing
	 * is carrying anything. */
	ncfg_primary_t *primary;
} ncfg_connectivity_t;

/*
 * The plain yes or no, for a client that wants one.
 *
 * True from `routed` up. Here rather than left to each caller so that
 * "connected" means one thing across the tray, the shim and the text
 * interface -- which is the whole reason the verdict is in the model.
 */
int ncfg_connectivity_connected(const ncfg_connectivity_t *connectivity);

/* ------------------------------------------------------------------------ *
 * The pieces of a link
 * ------------------------------------------------------------------------ */

/*
 * Whether a radio is switched off, and by which of the two switches.
 *
 * Both are read because the remedy differs and nothing else can tell them
 * apart. netcfgd reads the **phy's own** switch, which is the one the driver
 * obeys; a laptop usually has a second platform switch beside it -- a Dell
 * here reports `dell-wifi` next to `phy0` -- and whether blocking that one
 * propagates to the phy was not measured, because doing so means switching off
 * somebody's real radio. Decision 0062 says what is known and what is not.
 */
typedef struct {
	/* Which switch this was read from, as the kernel names it: `phy0`.
	 * Trailing underscore because `switch` is a keyword; the JSON member is
	 * spelled `switch`, as the Rust spells it. */
	char *switch_;
	/* Blocked in software. `rfkill unblock wifi` clears it. */
	int   soft;
	/* A physical switch, or a firmware one the kernel cannot override.
	 * Nothing in software clears this. */
	int   hard;
} ncfg_observed_rfkill_t;

/* Whether the radio is off, by either switch. */
int ncfg_rfkill_blocked(const ncfg_observed_rfkill_t *rfkill);

/*
 * What is holding it off and what would clear it, in one clause.
 *
 * **The two blocks have different answers and saying the wrong one wastes
 * somebody's evening**: telling a person to run `rfkill unblock wifi` against
 * a slider on the side of the machine is telling them to do something that
 * cannot work. Here rather than at each caller because the sentence is needed
 * in three places and a wording that drifts between them contradicts itself.
 *
 * Writes into `out` and returns it, or returns NULL where it would not fit.
 */
char *ncfg_rfkill_remedy(const ncfg_observed_rfkill_t *rfkill, char *out, size_t out_size);

/*
 * What the kernel will do with a router advertisement on this interface.
 *
 * Two fields because one of them is not enough to act on and the other is not
 * enough to explain. `accept_ra=1` -- the kernel's default -- means "accept
 * unless this interface forwards", so the same value is the working state on a
 * laptop and the broken one on a router, and `ip addr` shows nothing either
 * way. Decision 0073.
 */
typedef struct {
	/* The sysctl itself: 0 never, 1 unless this interface forwards, 2 always.
	 * netcfgd writes only 1 and 2, and reports whatever it finds. */
	int64_t value;
	/* Whether an advertisement would actually be acted on, which is `value`
	 * read against this interface's **IPv6** forwarding sysctl. The v4 one has
	 * nothing to do with it, which is why this deliberately does not use
	 * `ncfg_observed_link_t.forwarding` -- that is set only when both families
	 * forward. */
	int     effective;
} ncfg_observed_accept_ra_t;

/* A bond's own settings, as the kernel reports them. The kernel takes both of
 * these on a bond that already exists -- checked by asking it -- which is what
 * makes correcting them a set rather than the delete and create a VLAN needs
 * (0057). */
typedef struct {
	/* The mode, **as the document spells it**, translated in the observer so
	 * that the planner compares a `balance-rr` against a `balance-rr` rather
	 * than a number against a name. NULL for a mode netcfgd has no word for. */
	char         *mode;
	ncfg_optint_t miimon; /* milliseconds */
} ncfg_observed_bond_t;

/*
 * A bridge's own settings, as the kernel reports them.
 *
 * Only the ones netcfgd can set: a bridge has dozens of parameters and
 * carrying all of them would put a page of kernel detail in `/run` to answer a
 * question about six. `stp` and `forward_delay` were applied at creation and
 * never compared again, so editing either did nothing and said nothing (0054's
 * question asked of the kind whose name encodes nothing).
 *
 * In **seconds**, as the document spells them and as every tool does. The
 * kernel counts hundredths, and the conversion lives beside the one that
 * writes them.
 */
typedef struct {
	int           stp;
	ncfg_optint_t forward_delay;
	ncfg_optint_t hello_time;
	ncfg_optint_t ageing_time;
	ncfg_optint_t priority;
	int           vlan_filtering;
} ncfg_observed_bridge_t;

/* A macvlan's own settings. One field, and the kernel has three answers for
 * it: it moves the mode freely among `private`, `vepa` and `bridge`, and
 * refuses either direction between any of those and `passthru` (0058). NULL is
 * a mode netcfgd has no name for, and nothing is corrected on one. */
typedef struct {
	char *mode;
} ncfg_observed_macvlan_t;

/*
 * A VLAN's id and tag protocol.
 *
 * Neither can be corrected in place: `vlan_changelink` accepts a request to
 * change either and ignores it, so an edited id is applied by deleting the
 * interface and making it again. This is what says one has moved -- and a VLAN
 * is usually named for its id, so the operator who gets any use out of it is
 * the one who named it something else. Decision 0059.
 */
typedef struct {
	ncfg_optint_t id;
	/* `dot1q` or `dot1ad`, as the document spells it rather than as an
	 * ethertype, so the planner compares what the config says against a word.
	 * NULL for one netcfgd has no name for, which is not compared: an
	 * interface is not deleted over a value this build cannot describe. */
	char         *protocol;
} ncfg_observed_vlan_t;

/* A tunnel's endpoints. One struct for seven kinds across three attribute
 * families, because what the document says about all of them is one struct
 * too: the reading is per family, the comparison is not. */
typedef struct {
	char         *local;
	char         *remote;
	/* Outer TTL. Zero is the kernel's word for "inherit from the inner
	 * packet". */
	ncfg_optint_t ttl;
	/* The GRE key, or a geneve tunnel's VNI -- one field for both because the
	 * document has one. Absent for the ip tunnels, which have neither. */
	ncfg_optint_t key;
} ncfg_observed_tunnel_t;

/* A VXLAN's own settings. Two of these four cannot be corrected on a device
 * that exists (0058), and they are observed anyway, because a plan that cannot
 * fix something should still say it is wrong. */
typedef struct {
	ncfg_optint_t id;
	char         *local;
	char         *remote;
	ncfg_optint_t port;
} ncfg_observed_vxlan_t;

/* One peer of a WireGuard device, as the kernel reports it. */
typedef struct {
	/* The peer's identity, and the sorting key the kernel and the document
	 * share -- the document sorts by the operator's label, which the kernel
	 * has never heard of. */
	unsigned char  public_key[32];
	/* A boolean because the kernel reports one: `WGPEER_A_PRESHARED_KEY` comes
	 * back zeroed for a peer that has one, which is the kernel refusing to
	 * hand back a secret and not an accident to work around. */
	int            preshared_key;
	/* Whether the preshared key this peer holds is the one the store has now,
	 * by a digest comparison for the reason above. Absent where netcfgd has no
	 * record, where the secret will not resolve, and for every peer that has
	 * no preshared key at all. */
	ncfg_optbool_t preshared_matches;
	char          *endpoint; /* `host:port` */
	char         **allowed_ips;
	size_t         allowed_ip_count;
	ncfg_optint_t  keepalive; /* seconds */
} ncfg_observed_wg_peer_t;

/* The public key the kernel derived, where a private one is loaded. Held as
 * octets and re-rendered for `document.h`'s reason: base64 has more than one
 * spelling of one key, and two spellings must compare equal. */
typedef struct {
	int           has;
	unsigned char bytes[32];
} ncfg_observed_key_t;

/*
 * What a WireGuard device actually holds.
 *
 * The kernel reports all of this for free on the request that answers
 * `private_key_loaded`, and netcfgd threw it away for as long as WireGuard has
 * existed here -- which is why an edited listen port or a **deleted peer**
 * planned nothing at all. Decision 0054.
 *
 * Nothing secret is in it: the device's own public key is the thing a peer is
 * given, a preshared key is a boolean, and the private key has no field here
 * for the same reason it has none in the layer that reads it.
 */
typedef struct {
	/* Present exactly when a private key is loaded, which is what
	 * `private_key_loaded` says in a boolean. It is here as well because it is
	 * the value an operator hands a peer, and `ncfg explain` having to say
	 * "yes, a key" rather than *which* key was a gap somebody filled by hand. */
	ncfg_observed_key_t      public_key;
	/* Absent where the kernel reports none. A document that names no port
	 * leaves the kernel to choose one, so absent here against absent in the
	 * document is agreement rather than a difference -- getting that backwards
	 * would reconfigure the device on every reconcile. */
	ncfg_optint_t            listen_port;
	ncfg_optint_t            fwmark;
	/* Whether the private key the kernel holds is the one the store has now.
	 * A boolean, because the kernel reports nothing that could be compared
	 * against a secret reference: netcfgd compares a digest of what it loaded
	 * against a digest of what the store holds. Absent means it could not
	 * tell, and a tunnel is not torn down over an unanswered question. */
	ncfg_optbool_t           key_matches;
	/* **Sorted by public key.** The kernel's own order is the order it happens
	 * to hold them in, which is not stable and is not the document's either --
	 * sorting by the one field both sides have is what makes the comparison a
	 * comparison rather than a diff of two arbitrary orders. */
	ncfg_observed_wg_peer_t *peers;
	size_t                   peer_count;
} ncfg_observed_wireguard_t;

/* ------------------------------------------------------------------------ *
 * A link
 * ------------------------------------------------------------------------ */

typedef struct {
	char   *name;
	int64_t index; /* the kernel's interface index */
	/* Link kind as the kernel spells it: `veth`, `bridge`, `vlan`, or empty
	 * for a plain device. Written even when empty, because the Rust's field is
	 * a `String` and not an `Option`. */
	char   *kind;
	/* **The kernel's answer, not the document's.** `kind` cannot supply it --
	 * a real wireless device is a plain device and reports an empty kind, the
	 * same as an ethernet port -- and the document cannot either, because a
	 * `device` block's `wifi` section carries things meaningful on anything.
	 * The planner needs the difference to decide whether a supplicant belongs
	 * on an interface, and reading sysfs from the planner would make it
	 * untestable against fixtures whose interfaces do not exist. */
	int     wireless;
	/* **Carried rather than derived, before four clients derive it.** Absent
	 * where nothing has computed it: a bare netlink snapshot. */
	ncfg_optint_t category; /* ncfg_link_category_t where `has` */
	/* The configured network this link is associated to. **The id from the
	 * document, not the SSID**, so the planner can look the network up and
	 * take its metric. NULL for a wired link, for a radio that is not
	 * associated, and for one joined to a network the document does not
	 * describe -- a real state, since an operator may join by hand. */
	char   *network;
	int     up;      /* administrative state */
	/* Distinct from `up`: an interface can be administratively up with the
	 * cable out. */
	int     carrier;
	/* Whether this uplink's probe says it carries traffic. Absent is **not**
	 * false: a link nobody asked about must keep its routes. */
	ncfg_optbool_t reachable;
	/* Why the probe last said what it said, in its own words. **A probe that
	 * fails silently is a probe nobody can fix**: the exit status says whether
	 * the link works and nothing about why not, so the program's standard
	 * error is kept. Also carries the reason a probe was set aside, which is
	 * the one case an exit status cannot express. */
	char   *probe_detail;
	int64_t mtu;
	char   *mac;
	char   *master; /* bridge or bond this link is enslaved to */
	/* The device this virtual link rides on. A VLAN's and a macvlan's parent,
	 * a tunnel's and a VXLAN's underlay: one field, because the document has
	 * one word for all four. What the kernel does with a *changed* one is two
	 * answers, though -- a VXLAN and a tunnel move, while a VLAN and a macvlan
	 * accept the request and ignore it (0059, 0060). */
	char   *parent;
	/* Which of the offloads netcfgd manages are currently on. Kernel feature
	 * names, and only the ones the model can express -- a device reports
	 * dozens. A name absent here is off or unsupported, which the kernel does
	 * not distinguish either. */
	char  **offloads;
	size_t  offload_count;
	/* Absent covers both "no token" and "this device cannot have one": a dummy
	 * or any other NOARP device does no neighbour discovery, and the kernel
	 * refuses a token on it. */
	char   *ipv6_token;
	/* The root qdisc the kernel currently runs. Always present in practice --
	 * an interface netcfgd never touched reports whatever
	 * `net.core.default_qdisc` gave it -- so absent means the dump did not
	 * mention it, not that there is none. */
	char   *qdisc;
	/* The shaped rate in **bits** per second, where the qdisc shapes. */
	ncfg_optint_t qdisc_bandwidth_bits;
	int           qdisc_ingress;
	char         *ingress_redirect;
	/* True only when both the IPv4 and the IPv6 sysctl are set: half a
	 * forwarding interface routes one family and silently blackholes the
	 * other, and reporting that as "on" would make a plan claim there was
	 * nothing to do. */
	ncfg_optbool_t forwarding;
	/* NULL for anything that is not a radio, and for a radio whose rfkill
	 * switch could not be found. Nothing is planned on a NULL. */
	ncfg_observed_rfkill_t *rfkill;
	/* Whether this interface prefers a temporary address, from `use_tempaddr`.
	 * True for the kernel's `2`, which is the only thing the document can ask
	 * for; false covers both `0` and `1`, since the middle value prefers the
	 * stable address and no config here can request it. */
	ncfg_optbool_t privacy;
	ncfg_observed_accept_ra_t *accept_ra;
	/* Netlink has no protocol field for links, so unlike an address or a route
	 * this cannot be read back from the kernel: it comes from recorded prior
	 * state in `/run` and defaults to `unknown`, which means a link nobody has
	 * a record of is never deleted. */
	int     ownership; /* ncfg_ownership_t */
	/* Read as the *presence of the derived public key*, never by asking for
	 * the private one. False for every link that is not WireGuard, and for a
	 * WireGuard device created and not yet configured. */
	int     private_key_loaded;
	ncfg_observed_bond_t      *bond;
	ncfg_observed_bridge_t    *bridge;
	ncfg_observed_macvlan_t   *macvlan;
	ncfg_observed_vlan_t      *vlan;
	ncfg_observed_tunnel_t    *tunnel;
	ncfg_observed_vxlan_t     *vxlan;
	ncfg_observed_wireguard_t *wireguard;
} ncfg_observed_link_t;

/*
 * One Bluetooth adapter, as the kernel presents it.
 *
 * **Not a link, which is why it is its own list.** `hci0` has no address, no
 * mtu and no place in netlink, so it cannot be a link and the rfkill attached
 * to a link never finds it. A PAN connection through it produces a `bnep0`
 * that *is* a link, and that one goes through the ordinary model with no
 * special case. Read from `/sys/class/bluetooth`, so it needs no D-Bus.
 */
typedef struct {
	char                   *name; /* the kernel's: `hci0` */
	ncfg_observed_rfkill_t *rfkill;
} ncfg_observed_bluetooth_t;

/* ------------------------------------------------------------------------ *
 * Addresses, routes, rules and bridge VLANs
 * ------------------------------------------------------------------------ */

typedef struct {
	char         *interface;
	char         *address; /* CIDR, as the kernel reports it */
	ncfg_optint_t proto;   /* `IFA_PROTO`, where the kernel supports it */
	int           ownership; /* ncfg_ownership_t */
	ncfg_optint_t origin;    /* ncfg_origin_t where `has` */
} ncfg_observed_address_t;

/*
 * `RTPROT_DHCP`: the route protocol a DHCP client stamps on what it installs.
 *
 * **The kernel is what normalises the clients.** dhcpcd keeps leases in
 * `/var/lib/dhcpcd`, dhclient in `dhclient.leases`, udhcpc keeps none at all
 * -- but whichever installed the route, the kernel records this on it.
 */
#define NCFG_DHCP_ROUTE_PROTO 16

typedef struct {
	char         *interface;
	char         *destination; /* CIDR, or `default` */
	char         *via;
	ncfg_optint_t metric;
	ncfg_optint_t table;
	char         *src;
	ncfg_optint_t scope; /* ncfg_route_scope_t where `has` */
	ncfg_optint_t proto; /* `rtm_protocol` */
	int           ownership; /* ncfg_ownership_t */
	ncfg_optint_t origin;    /* ncfg_origin_t where `has` */
} ncfg_observed_route_t;

/*
 * A policy routing rule as the kernel reports it.
 *
 * The same fields as the document's rule minus the `id`, which is netcfgd's
 * own handle and has no kernel counterpart, plus the ownership the
 * `FRA_PROTOCOL` tag establishes.
 */
typedef struct {
	/* With the family, this is the kernel's key. */
	int64_t       priority;
	int           family; /* ncfg_rule_family_t, from value.h */
	char         *from;
	char         *to;
	char         *iif;
	char         *oif;
	ncfg_optint_t fwmark;
	ncfg_optint_t fwmask;
	ncfg_optint_t table;
	int           action; /* ncfg_rule_action_t, from value.h */
	ncfg_optint_t suppress_prefixlength;
	int           l3mdev;
	int           invert;
	int           ownership; /* ncfg_ownership_t */
} ncfg_observed_rule_t;

/*
 * One VLAN the kernel holds on one interface.
 *
 * **No ownership field, unlike an address.** There is no protocol tag for a
 * bridge VLAN, and unlike a link there is no useful `/run` record either -- the
 * kernel creates VLAN 1 by itself, so "netcfgd did not add this" does not mean
 * "somebody else did". Authority comes from the document instead.
 */
typedef struct {
	int64_t index; /* which interface carries it */
	int64_t vid;
	int     pvid;     /* untagged ingress joins this VLAN */
	int     untagged; /* egress leaves untagged */
} ncfg_observed_bridge_vlan_t;

/* ------------------------------------------------------------------------ *
 * What netcfgd was told rather than read
 * ------------------------------------------------------------------------ */

/*
 * What a DHCPv6 client obtained by prefix delegation.
 *
 * Not read from the kernel: a delegated prefix is not kernel state at all
 * until something derives an address from it. It comes from the client, which
 * netcfgd does not implement (0004) and therefore has to be told by, through a
 * file the client's hook writes and the observer reads.
 */
typedef struct {
	char  *interface;
	/* In the order the lease listed them. A list rather than one, because a
	 * lease may carry several and a prefix reference's `index` selects between
	 * them. Most connections deliver exactly one. */
	char **prefixes;
	size_t prefix_count;
} ncfg_delegation_t;

/*
 * One route a report names.
 *
 * Both parts stay text, as every other address in a report does: parsing them
 * in the reader would put the refusal where the operator cannot see which line
 * of whose file was wrong.
 */
typedef struct {
	char *destination; /* CIDR, or `default` */
	/* NULL where the report names none: a point-to-point link has no next hop
	 * and a route down one needs none. */
	char *via;
} ncfg_reported_route_t;

/*
 * What something that is not netcfgd reported about one interface.
 *
 * Not kernel state and not netcfgd's own record: the configuration a cellular
 * bearer or a tunnel comes up with is known to whatever negotiated it, and
 * netcfgd is told through a file (`doc/interface-report.md`). Named for what it
 * is rather than for the first thing that wrote one -- a modem helper was, and
 * decision 0047 says why that name had to stop being the contract's.
 *
 * Every field is what the *network* assigned, not what the document asked for.
 * An empty report is a link that is down, which differs from no report at all
 * only in that somebody said so.
 */
typedef struct {
	char  *interface;
	char **addresses; /* CIDR, in the order reported */
	size_t address_count;
	char **gateways;  /* both families on a dual-stack bearer */
	size_t gateway_count;
	char **nameservers;
	size_t nameserver_count;
	/* **Not routing domains, and netcfgd will never make them into any.** A
	 * search suffix says what to append to a bare name; a routing domain says
	 * which resolver answers for a zone, and 0049 refuses one from a report. */
	char **search;
	size_t search_count;
	/* Routes beyond the default one. A cellular bearer usually names none --
	 * it gives a way off the link, not a topology -- but a VPN server
	 * routinely pushes a handful, and those are the routes 0047 says are
	 * netcfgd's to install rather than the daemon's. */
	ncfg_reported_route_t *routes;
	size_t                 route_count;
	/* **Not addressing, and the only field here that is not.** It exists
	 * because a board that muxes two SIMs cannot be asked which one is
	 * selected: the mux sits outside the module, so the card's own identifier
	 * is the only fact that says which is being read. Nothing plans on it. */
	char *iccid;
	/* Which SIM source the writer had been asked for when it read that card.
	 * **Paired by the writer, because only the writer saw both at once**:
	 * netcfgd publishes the source it wants and the helper reads the card
	 * seconds later, across a modem reset, so netcfgd pairing its own current
	 * selection with whatever ICCID last appeared would file one card under
	 * the other's name. */
	char *sim;
} ncfg_observed_report_t;

/* ------------------------------------------------------------------------ *
 * Backends
 * ------------------------------------------------------------------------ */

/*
 * Which helper a backend entry describes.
 *
 * **`wire_guard` and `open_vpn` are this set's spellings**, for the same
 * reason and from the same `rename_all = "snake_case"` as the document's
 * interface kinds. See `document.h`: that pair is the one this project has
 * already shipped wrong twice, and it is preserved rather than tidied.
 */
typedef enum {
	NCFG_BACKEND_DHCP4,
	NCFG_BACKEND_DHCP6,
	/* A supplicant, for a radio or a wired 802.1X port. */
	NCFG_BACKEND_SUPPLICANT,
	/* An access point this machine runs, rather than joins. */
	NCFG_BACKEND_ACCESS_POINT,
	NCFG_BACKEND_WIREGUARD,
	NCFG_BACKEND_PPPOE,
	NCFG_BACKEND_OPENVPN,
	NCFG_BACKEND_DNS,
	NCFG_BACKEND_ROUTER_ADVERT
} ncfg_backend_kind_t;

const char *ncfg_backend_kind_name(int kind);

/*
 * Which policy a running access point is enforcing.
 *
 * **Three answers rather than an option, because the two ways of having no
 * policy lead to opposite actions.** `macaddr_acl` is not readable over the
 * control socket -- `GET_CONFIG` reports the SSID, the BSSID and the ciphers
 * and says nothing about it -- so this comes from netcfgd's own record of what
 * it started hostapd with, and the record's *absence* is itself informative.
 */
typedef enum {
	/* Started with no `access_control` block, so `macaddr_acl` was never set.
	 * Both of hostapd's lists exist and neither is consulted for admission the
	 * way a configured one is, which is exactly why anything in them is worth
	 * reporting rather than converging away as though it were inert. */
	NCFG_OBSERVED_POLICY_UNSET,
	/* Started with this policy, and still enforcing it. */
	NCFG_OBSERVED_POLICY_SET,
	/* netcfgd has no record and cannot tell: an access point started by a
	 * netcfgd too old to write one, or a `/run` cleared underneath a running
	 * one. **Nothing may be converged from here**, because emptying a list
	 * without knowing which one hostapd reads either opens a network or closes
	 * it, and there is no way to know which. */
	NCFG_OBSERVED_POLICY_UNKNOWN
} ncfg_observed_policy_kind_t;

typedef struct {
	int kind;   /* ncfg_observed_policy_kind_t */
	int policy; /* ncfg_acl_policy_t, meaningful only for SET */
} ncfg_observed_policy_t;

/*
 * hostapd's in-memory station lists, and the policy it is running under.
 *
 * Both lists, because hostapd holds both regardless of which one `macaddr_acl`
 * selects. The document names only one (0039), so the other has to be observed
 * to notice that it is not empty -- which is the only way to see, from
 * outside, that an operator flipped the policy under a running access point.
 */
typedef struct {
	ncfg_observed_policy_t policy;
	char                 **denied;   /* normalised and sorted */
	size_t                 denied_count;
	char                 **accepted;
	size_t                 accepted_count;
} ncfg_observed_access_control_t;

/* The list one policy reads. Returns NULL and a zero count outside the set. */
char *const *ncfg_observed_access_control_list(const ncfg_observed_access_control_t *control,
    int policy, size_t *count_out);

/*
 * The identity a running access point was started with.
 *
 * In netcfgd's own vocabulary rather than hostapd's: the observer maps
 * `hw_mode` back to the band the document spells, so the planner compares
 * model values against model values and can name the field that differs.
 *
 * **The passphrase is deliberately not here.** A secret does not belong in an
 * observation that goes over the socket and into `/run`, and the planner could
 * not compare one anyway. An edited passphrase is noticed by `secret_matches`
 * instead, which carries the answer and never the value.
 */
typedef struct {
	ncfg_ssid_t   ssid;
	char         *band;
	/* Absent where hostapd was told to choose one. */
	ncfg_optint_t channel;
	/* The `wpa_key_mgmt` it is running, NULL for an open network. **The
	 * generation, which nothing used to notice changing**: hostapd reads its
	 * file once, so an access point started as WPA2 goes on offering WPA2
	 * however the document is edited -- and the passphrase comparison says
	 * nothing about it, because changing the generation changes no secret. */
	char         *key_mgmt;
	int           hidden;
	/* Upper case, which is what the renderer writes -- so a document saying
	 * `se` and a file saying `SE` are the same access point, and comparing
	 * them as written would restart it on every reconcile. */
	char         *regdom;
} ncfg_observed_access_point_t;

/* A backend process as netcfgd currently believes it to be. */
typedef struct {
	int   kind; /* ncfg_backend_kind_t */
	char *interface;
	/* A fact about a *process*: something is there under that pid. */
	int   running;
	/* Whether it answered when netcfgd last asked it something -- a different
	 * question from `running`, and 0078 is why they are kept apart: a wedged
	 * hostapd holds its socket, holds its pid, serves nobody, and answered
	 * `running: true` to every question netcfgd had until this field. */
	ncfg_optbool_t answering;
	/* Only ever present for an access point, and only while it is running -- a
	 * list read out of a process that has exited is not an observation of
	 * anything. NULL rather than an empty list, because "netcfgd could not
	 * ask" and "hostapd denies nobody" are different answers and only the
	 * second may be reconciled against. */
	ncfg_observed_access_control_t *access_control;
	/* The route metric a running DHCP client was started with, read from its
	 * own `argv`. **The metric is read once, when the client starts**, so a
	 * radio that moves to a network asking for a different one keeps the old
	 * metric on its lease's default route -- and until 0241 the only way
	 * netcfgd noticed was by comparing the installed route, which cannot exist
	 * until the exchange that installs it has finished. */
	ncfg_optint_t started_metric;
	ncfg_observed_access_point_t *started_with;
	/* Whether the secret a running daemon holds is still the one the store
	 * has. A boolean rather than a value, and that is the whole design
	 * (0052). */
	ncfg_optbool_t secret_matches;
	/* Whether a running supplicant still holds what the document asks for,
	 * again as the answer rather than the values. Absent has three causes: not
	 * a supplicant, no record of what netcfgd handed over, or a network that
	 * names access points instead of an SSID -- which is resolved from a scan
	 * at the moment it is sent, so what will be sent is not knowable from the
	 * document alone. */
	ncfg_optbool_t networks_match;
	/* Whether a running tunnel's configuration file is still the one it was
	 * started from: netcfgd hashes the `.ovpn` and hashes it again, and never
	 * reads the file for meaning, which is what 0046 protects. */
	ncfg_optbool_t config_matches;
	/* Whether the `.ovpn` the document names could be read at all. `config_
	 * matches` is deliberately absent when it cannot be, so a working tunnel
	 * is never dropped over a question nobody answered -- and that left the
	 * operator with silence: a document pointing at a file that is not there
	 * produced `nothing to do` on every apply, for ever, while the daemon went
	 * on running what it was started with. This carries the half of that
	 * absence which is a fault rather than an unknown. */
	ncfg_optbool_t config_present;
	/* The prefixes a running router advertisement daemon was last given. It
	 * exists because a prefix is the one value in the document that arrives
	 * after the document does: an ISP renumbers, the LAN's address moves, and
	 * a daemon still announcing the old block is telling every host on the
	 * wire to use an address the upstream will not route. */
	char **advertised;
	size_t advertised_count;
} ncfg_observed_backend_t;

/* How many times netcfgd has started one backend without it staying up. Reset
 * the moment the backend is observed running. A daemon that dies as fast as it
 * is started would otherwise be started again on every reconcile for ever --
 * measured at 181 starts in twelve seconds (0079). */
typedef struct {
	int     kind; /* ncfg_backend_kind_t */
	char   *interface;
	int64_t count;
} ncfg_backend_restart_t;

/*
 * A DNS scope netcfgd last delivered, and what it delivered.
 *
 * Read back from `/run/netcfgd/dns/`. Without it a plan could not tell an
 * already-applied policy from an unapplied one, and every run would emit a
 * `dns.apply` -- which would fail the plan-idempotence gate.
 */
typedef struct {
	char             *scope; /* an interface name, or `globals` */
	ncfg_dns_policy_t policy;
} ncfg_applied_dns_t;

/*
 * The two lists above, read and written on their own.
 *
 * **`owned.json` carries both, and this is where they come from.** The record
 * is what fills `backends` and `dns` in an observation -- nothing else does --
 * so `state.h` needs a reader and a writer for exactly these two element
 * types, and a second copy of either in that module would be a DNS policy
 * codec written twice. The field tables stay private here; what travels is the
 * list walk.
 *
 * The reader hands back a list the caller frees with the matching call, and it
 * does so **even when it fails part way**: a half-read list is still a list,
 * and leaving it unreachable would be the leak a refusal is supposed to avoid.
 * `node` is the array; anything else is refused with a sentence.
 */
int ncfg_observed_backends_read(const ncfg_json_doc_t *doc, uint32_t node,
    ncfg_observed_backend_t **out, size_t *count_out, char *err, size_t err_size);
void ncfg_observed_backends_write(ncfg_json_writer_t *writer,
    const ncfg_observed_backend_t *backends, size_t count);
void ncfg_observed_backends_free(ncfg_observed_backend_t *backends, size_t count);
/* Free what one backend holds, leaving it usable and empty. Here as well as the
 * list's free because a caller taking one entry *out* of a list cannot use the
 * list's -- that one frees the array too. `ncfg_state_report_free` is beside
 * `ncfg_state_reports_free` for the same reason. */
void ncfg_observed_backend_free(ncfg_observed_backend_t *backend);

int ncfg_applied_dns_read(const ncfg_json_doc_t *doc, uint32_t node, ncfg_applied_dns_t **out,
    size_t *count_out, char *err, size_t err_size);
void ncfg_applied_dns_write(ncfg_json_writer_t *writer, const ncfg_applied_dns_t *dns,
    size_t count);
void ncfg_applied_dns_free(ncfg_applied_dns_t *dns, size_t count);

/*
 * What one event hook on one interface was last told.
 *
 * netcfgd's own memory rather than kernel state, and named carefully for that
 * reason: this is not what is true now, it is what a hook has already been
 * told about. The comparison between the two is what makes an event hook fire
 * once per event instead of once per reconcile.
 */
typedef struct {
	char *interface;
	/* `lease` and `carrier` are the two phases that have one. */
	int   phase; /* ncfg_hook_phase_t, from value.h */
	/* A lease's address in CIDR notation, a carrier's `up` or `down`. A string
	 * rather than a per-phase type: what netcfgd does with it is compare it to
	 * the next one, and a type per phase would be three types for one
	 * comparison. */
	char *value;
} ncfg_observed_hook_state_t;

/* ------------------------------------------------------------------------ *
 * The observation
 * ------------------------------------------------------------------------ */

/* Everything netcfgd can currently see. */
typedef struct {
	/* NULL where nothing has computed it -- a bare netlink snapshot, or an
	 * observation written by a netcfgd from before this existed. */
	ncfg_connectivity_t *connectivity;
	/* Every link this machine has or has been told about, sorted by name.
	 * **A union, and `links` is only half of it**: this adds the links the
	 * document names and the kernel does not have -- a saved wifi network, an
	 * `interface` whose card is not plugged in. Beside `links` rather than
	 * replacing it, deliberately: the planner iterates `links` as "what the
	 * kernel has", and a synthetic row for something that does not exist would
	 * be read as one that does. */
	ncfg_link_entry_t *inventory;
	size_t             inventory_count;
	/* What each linkset settled on, in document order. Carried here rather
	 * than recomputed by each client: a failover decision two programs work
	 * out separately is one they can disagree about, and the disagreement
	 * looks like a machine that cannot decide which link it is on. */
	ncfg_chosen_t *linksets;
	size_t         linkset_count;
	ncfg_observed_link_t *links; /* sorted by name */
	size_t                link_count;
	/* Separate from `links` because an adapter is not one. Empty on a machine
	 * with no Bluetooth, which is most servers, and left out of the output
	 * entirely rather than shown as an empty list nobody asked about. */
	ncfg_observed_bluetooth_t *bluetooth;
	size_t                     bluetooth_count;
	ncfg_observed_address_t *addresses; /* sorted by interface then address */
	size_t                   address_count;
	ncfg_observed_route_t *routes; /* sorted canonically */
	size_t                 route_count;
	ncfg_observed_backend_t *backends; /* sorted by interface then kind */
	size_t                   backend_count;
	ncfg_applied_dns_t *dns; /* sorted by scope */
	size_t              dns_count;
	ncfg_observed_rule_t *rules; /* sorted by family then priority */
	size_t                rule_count;
	ncfg_observed_bridge_vlan_t *bridge_vlans;
	size_t                       bridge_vlan_count;
	ncfg_delegation_t *delegations;
	size_t             delegation_count;
	ncfg_observed_report_t *reports;
	size_t                  report_count;
	/* Interfaces netcfgd set the root qdisc on. Recorded rather than inferred,
	 * because a qdisc carries no owner and every interface has one whether or
	 * not anybody chose it: an interface already running `cake` when netcfgd
	 * first started is not netcfgd's to reset. */
	char **qdisc_applied;
	size_t qdisc_applied_count;
	char **ingress_applied;
	size_t ingress_applied_count;
	/* The same record, for a sysctl that equally carries no owner: a machine
	 * that had `use_tempaddr` set globally before netcfgd existed is not
	 * netcfgd's to undo. */
	char **privacy_applied;
	size_t privacy_applied_count;
	ncfg_backend_restart_t *backend_restarts;
	size_t                  backend_restart_count;
	/* Without this, putting an interface that stops asking for SLAAC back
	 * would be a one-way door. */
	char **accept_ra_applied;
	size_t accept_ra_applied_count;
	/* An interface that was already forwarding when netcfgd first ran is not
	 * in here and never gets turned off -- somebody else's `sysctl.conf` is
	 * not netcfgd's to undo. One that netcfgd switched on is, which is what
	 * makes deleting `forwarding` from the document mean something. */
	char **forwarding_applied;
	size_t forwarding_applied_count;
	/* Interfaces netcfgd's own nftables table currently masquerades. Empty
	 * where the table does not exist, and also where the kernel has no
	 * `nf_tables` at all -- indistinguishable from here, and the planner
	 * treats them the same because "no NAT is installed" is true in both. */
	char **nat;
	size_t nat_count;
	/* Tables other than netcfgd's that translate source addresses. Decision
	 * 0022 refuses to delete these and reports them instead: a second
	 * source-NAT chain on the same hook translates the same packets twice, and
	 * the table it lives in almost certainly holds filtering netcfgd cannot
	 * evaluate. */
	char **nat_conflicts;
	size_t nat_conflict_count;
	/* One list for every phase rather than one per phase. It was a lease-only
	 * list for two commits, until `carrier` arrived wanting exactly the same
	 * thing with a different value in it (0064, 0068). */
	ncfg_observed_hook_state_t *hook_state;
	size_t                      hook_state_count;
	/* NULL where it could not be read, which is a container with no
	 * `/proc/sys`. Nothing is planned on a NULL: a hostname netcfgd cannot see
	 * is one it cannot tell whether it has already set. */
	char *hostname;
	/* Whether address ownership came from `IFA_PROTO` or from the weaker
	 * `/run` fallback. Reported, because an operator deciding whether to trust
	 * a drift report needs to know which mechanism produced it (0002). */
	int   address_proto_supported;
} ncfg_observed_t;

/*
 * An empty observation.
 *
 * Every default here is C's zero -- unlike a document, whose drift policy and
 * ignore list are not -- so this is a `calloc` with a name. It exists anyway,
 * so that there is one way to free an observation however it was made.
 */
ncfg_observed_t *ncfg_observed_new(char *err, size_t err_size);

/*
 * Parse an observation, **refusing anything this build cannot fully
 * represent**.
 *
 * `document.h`'s argument applies here unchanged and is if anything stronger:
 * an observation is written by one netcfgd and read by a client that may be
 * older, and a client acting on a subset of what it was sent is the failure
 * `deny_unknown_fields` exists to prevent. Every member of every struct here
 * is either known or the observation is refused, with the member named.
 *
 * `text` need not be NUL-terminated. Returns NULL with a sentence in `err`.
 */
ncfg_observed_t *ncfg_observed_read(const char *text, size_t length, char *err,
    size_t err_size);

/* Free the tree. A NULL observation, and one never filled in, are nothing. */
void ncfg_observed_free(ncfg_observed_t *observed);

/*
 * Put every list in a stable order, so two observations of one system compare
 * equal regardless of the order netlink dumped them in.
 *
 * **Exactly the five lists the Rust sorts, and no more.** The rest arrive in
 * an order netcfgd chose rather than one the kernel happened to produce, and
 * sorting them here would be this port deciding something the Rust does not --
 * which the witness would catch and a reader would not.
 */
void ncfg_observed_canonicalize(ncfg_observed_t *observed);

/*
 * Write the observation into `buf`.
 *
 * Member order is declaration order and a member at its default is omitted
 * exactly where the Rust omits it, so an observation read and written back is
 * the one that arrived.
 */
int ncfg_observed_write(const ncfg_observed_t *observed, ncfg_buf_t *buf, char *err,
    size_t err_size);

/* Canonicalise and write. **Canonicalises in place**, for `document.h`'s
 * reason: there is no caller who wanted the unsorted order back. */
int ncfg_observed_write_canonical(ncfg_observed_t *observed, ncfg_buf_t *buf, char *err,
    size_t err_size);

/* ------------------------------------------------------------------------ *
 * The questions the planner asks an observation
 * ------------------------------------------------------------------------ */

/* The link of this name, if the kernel has one. NULL otherwise. */
const ncfg_observed_link_t *ncfg_observed_link(const ncfg_observed_t *observed,
    const char *name);

/* The prefixes delegated on an interface. */
const ncfg_delegation_t *ncfg_observed_delegation(const ncfg_observed_t *observed,
    const char *interface);

/*
 * The block a prefix reference resolves to, as a prefix rather than an address
 * in it.
 *
 * `@pd:wan0`, an index and a subnet selector become `2001:db8:1:2::/64` --
 * `ncfg_address_from_delegation`'s arithmetic with `::/64` as the suffix,
 * which is what the LAN's own address used with a host part instead. Answers 1
 * and fills `out` (`NCFG_ADDRESS_MAX`), or 0 where the delegation has not
 * arrived, does not carry that index, or the suffix cannot be carved out of
 * it.
 *
 * **Here rather than in whichever module wanted it first, and that is the same
 * argument `ncfg_dns_scopes_of` is here for.** The planner resolves references
 * to decide what to advertise; the daemon resolves them again to fill
 * `ncfg_service_advertise_t`, because a delegation arrives after the document
 * does and no op can carry the answer. Two spellings of it disagree about what
 * a router announces to every host on the wire, which is not a difference
 * anything downstream could notice.
 *
 * **Zero, not a refusal, for a delegation that has not arrived.** That is the
 * ordinary state of a machine between starting a DHCPv6 client and the lease
 * landing, and a router started with the prefixes that did resolve is the
 * Rust's answer as well. A suffix that cannot be carved out is a configuration
 * fault rather than something to wait for, and it is reported where a plan can
 * put a sentence in front of the operator -- not here.
 */
int ncfg_observed_prefix_of(const ncfg_observed_t *observed, const ncfg_prefix_ref_t *reference,
    char *out, size_t out_size);

/*
 * The route metric an interface's routes take, given what it is associated to.
 *
 * `netcfgd_model::wifi::effective_metric`: **the metric of the network this
 * radio is associated to, where that network carries one, and the interface's
 * own `preference` otherwise.** Absent where neither states anything, which is
 * an ordinary document and not a failure.
 *
 * **It falls back rather than replacing**, and that is the whole of the rule
 * that is easy to get wrong: a network with no `metric` of its own leaves the
 * interface's `preference` exactly as it was, so every machine that never
 * needed this is unaffected. Reading it as "the network's if there is a
 * network" drops an operator's number because they also named an SSID.
 *
 * **Here because three callers need one answer.** The planner fills in a
 * route's metric with it; the planner's *teardown* fills in the same value to
 * decide whether a route it is looking at is one of these -- and `address.c`
 * says why that pair must agree, because a metric computed differently on each
 * side makes the comparison never match and the plan loop for ever. The third
 * is the daemon, which starts a DHCP client with `-m` so the lease's own route
 * carries it. The Rust delegates for exactly this reason and records what
 * happened before it did: its executor built the list from `preference` alone,
 * so the metric a network carried never reached the client that installs the
 * route -- measured on a veth with a real server, 1003 on a document whose
 * network said 100.
 *
 * `observed` may be NULL, which is a machine nothing has looked at: nothing is
 * associated, so the answer is the interface's own.
 *
 * **The gating is deliberately not this question.** Carrier and probe decide
 * whether an interface's routes go in at all, and both key on `preference`,
 * because that is a property of the link rather than of the network on it -- a
 * radio whose network names a metric but whose interface names no preference
 * is asking to be ranked, not asking to have its routes withheld when the
 * cable is out.
 */
ncfg_optint_t ncfg_observed_effective_metric(const ncfg_document_t *desired,
    const ncfg_observed_t *observed, const ncfg_interface_t *interface);

/* What was last delivered for a DNS scope. */
const ncfg_dns_policy_t *ncfg_observed_dns_for(const ncfg_observed_t *observed,
    const char *scope);

/*
 * Whether a DHCP client has installed a route on `interface`.
 *
 * **The route and not the address.** `IFA_PROTO` arrived in Linux 5.18 and is
 * absent on plenty of running kernels: measured on the reporting machine, a
 * DHCP address came back with no proto while its route said 16. `RTPROT_DHCP`
 * is old enough to rely on.
 *
 * This is a *lease*, which is a weaker claim than connectivity and is not a
 * substitute for it -- a local DHCP server hands out leases happily on a
 * network whose uplink is dead. What it is good for is the other direction: an
 * interface that asked for DHCP and has no lease has nothing a probe could
 * succeed over (0191).
 */
int ncfg_observed_has_dhcp_lease(const ncfg_observed_t *observed, const char *interface);

/* How many times netcfgd has started this backend without it staying up. */
int64_t ncfg_observed_backend_restarts(const ncfg_observed_t *observed, int kind,
    const char *interface);

/* Whether a backend of this kind is running on an interface. */
int ncfg_observed_backend_running(const ncfg_observed_t *observed, int kind,
    const char *interface);

/*
 * Whether an interface named by the document is there.
 *
 * **Two-valued, unlike a network's, and that asymmetry is the whole rule.**
 * The kernel's link table is complete: netcfgd has seen every interface there
 * is, so one it cannot find is one that does not exist. There is no third
 * answer because there is no question netcfgd was unable to ask.
 */
int ncfg_presence_of_interface(const char *name, const ncfg_observed_t *observed);

/*
 * Whether a configured wifi network is within reach.
 *
 * `associated` is whether some radio is on it now, which settles the question
 * outright. `seen` is what a scan said, and `seen_has` is whether a scan has
 * been read at all.
 *
 * **A hidden network is `unknown` even when a scan has been read**, and that
 * is the case this function exists for: a scan cannot name a hidden access
 * point, so "not in the scan" is not evidence of absence for one. Treating it
 * as evidence would report a network that is right there as gone.
 */
int ncfg_presence_of_network(int hidden, int associated, int seen_has, int seen);

/*
 * Which category a link falls into.
 *
 * `document` supplies the one thing the observation cannot: whether the device
 * behind this link is a modem. NULL where there is no document, which
 * classifies such a link by its kernel kind instead of guessing.
 */
int ncfg_link_category_of(const ncfg_observed_link_t *link, const ncfg_document_t *document);

#endif /* NCFG_OBSERVED_H */
