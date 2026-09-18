/*
 * document.h -- the desired-state document, which is what netcfgd is about.
 *
 * This is `crates/netcfgd-model` in C: the one artifact every other part of
 * the program hangs off. A compiler produces it, a planner reads it against
 * what the machine actually looks like, a daemon writes it to `/run`, and a
 * client reads it back. Nothing here does I/O, touches hardware or reads a
 * clock, because the planner's testability depends on the whole path from
 * config text to action list being a function (`project.md` section 5).
 *
 * THREE INVARIANTS, ENFORCED RATHER THAN DOCUMENTED
 *
 *   * **Determinism.** One logical document has exactly one byte sequence.
 *     Every list sorts by a key the schema names, member order is declaration
 *     order, and there are no floats and no unordered maps anywhere in these
 *     types. `ncfg_document_canonicalize` is the sorting half.
 *   * **No silent field-dropping.** A member this build does not know is
 *     **refused, and named**. See below; it is the rule most likely to be
 *     softened by somebody in a hurry, and softening it is the defect.
 *   * **No secret material.** A secret appears only as `ncfg_secret_ref_t`
 *     and a delegated prefix only as `ncfg_prefix_ref_t`. Neither type can
 *     hold a value, which is what makes a document safe to write to `/run`.
 *
 * DENY UNKNOWN FIELDS, AND WHY IT IS NOT MERELY STRICTNESS
 *
 *   `#[serde(deny_unknown_fields)]` is on every struct in the Rust, and
 *   `ncfg_document_read` reproduces it: a document carrying a member this
 *   build does not understand is rejected whole, with the member named and
 *   the block it was in named. `project.md` section 2 has the argument --
 *   **a consumer acting on something it only half read is worse than one that
 *   refuses.** A document is written by a newer netcfgd and read by an older
 *   one all the time, and the older one silently dropping the field that says
 *   "this interface is guarded" would take down the link the operator said
 *   not to touch. Refusing is legible; half-reading is not.
 *
 *   The same rule is why a spelling here is read out of the Rust rather than
 *   remembered. Two document spellings in this file are not what a config
 *   author writes: an interface kind is `wire_guard` and `open_vpn` in JSON,
 *   because serde's `rename_all = "snake_case"` split the Rust variant names
 *   -- and the configuration language spells the same two `wireguard` and
 *   `openvpn`. That mismatch has already cost this project twice, compiling a
 *   block with the feature silently missing, and it is preserved here rather
 *   than tidied because the witness carries it and a document that arrived
 *   from the Rust is the thing being read.
 *
 * OWNERSHIP
 *
 *   **One `ncfg_document_free` frees the tree**, and freeing something never
 *   filled in is nothing. Rust had ownership in the type system; here it is a
 *   rule, so it is written down and tested rather than assumed.
 *
 *   **A list is a counted array**, a `T *` beside a `size_t`, not a linked
 *   list. Every list in this model is built once, sorted, and then walked --
 *   sorting is half of what canonicalisation *is* -- and a linked list makes
 *   the operation the document's determinism rests on into the awkward one.
 *
 *   **A tagged union carries every arm rather than a C union**, and is freed
 *   without consulting its tag. The arms are small, the waste is a few dozen
 *   bytes per entry, and what it buys is that the free walk cannot go wrong
 *   when a variant is added: a union has to be freed by tag, and a tag added
 *   to the enum and missed in the free is a leak nothing reports.
 *
 * TWO REPRESENTATION CHOICES THAT LOOK ODD AND ARE DELIBERATE
 *
 *   * **Every number is `int64_t`,** whatever width the Rust gave it. The
 *     range is checked on the way in, against the Rust's own type -- a `u16`
 *     port refuses 70000 and says so -- so nothing is lost but the storage is
 *     uniform, which is what lets one table-driven reader serve fifty
 *     structs. A `uint8_t` field read through a generic reader is a cast per
 *     field, and a cast per field is where a truncation hides.
 *   * **Every closed-set field is `int`,** holding one of the enum constants
 *     beside it. Same reason: the reader stores through an `int *`, and an
 *     `enum` in C has an implementation-defined underlying type that need not
 *     be `int`. Compare against the constants; they are the values.
 */
#ifndef NCFG_DOCUMENT_H
#define NCFG_DOCUMENT_H

#include <stddef.h>
#include <stdint.h>

#include "ncfg/buf.h"
#include "ncfg/value.h"

/* ------------------------------------------------------------------------ *
 * The two optional scalars
 *
 * Rust has `Option<u32>` and `Option<bool>`; C has a value and a flag. Absent
 * and zero are different answers throughout this model -- `suppress_prefixlength
 * = 0` is the whole `ip rule` trick and is not the same as no suppression, and
 * `forwarding = false` is "netcfgd requires this off" while absent is "netcfgd
 * does not manage it".
 * ------------------------------------------------------------------------ */

typedef struct {
	int     has;
	int64_t value;
} ncfg_optint_t;

typedef struct {
	int has;
	int value;
} ncfg_optbool_t;

/* ------------------------------------------------------------------------ *
 * The schema version
 * ------------------------------------------------------------------------ */

/*
 * The schema version this build produces and accepts.
 *
 * **Pinned until netcfgd ships, deliberately** (decision 0038): versioning is
 * a promise to consumers and before a release there are none. A differing
 * `major` is a hard refusal -- see `ncfg_document_validate`. A higher `minor`
 * is left to the unknown-member rule, because a newer minor that happens to
 * use no new member is genuinely readable.
 */
#define NCFG_SCHEMA_MAJOR 1
#define NCFG_SCHEMA_MINOR 1

typedef struct {
	int64_t major;
	int64_t minor;
} ncfg_version_t;

/* ------------------------------------------------------------------------ *
 * Secrets, and the indirection a delegated prefix arrives through
 * ------------------------------------------------------------------------ */

/* Where a secret is stored. `secret.rs`, `SecretProvider`. */
typedef enum {
	NCFG_SECRET_PROVIDER_FILE,
	NCFG_SECRET_PROVIDER_KEYRING,
	NCFG_SECRET_PROVIDER_PASS,
	NCFG_SECRET_PROVIDER_EXEC
} ncfg_secret_provider_t;

/*
 * A reference to secret material, **never the material itself**.
 *
 * The document is written to `/run`, read by adapters and may eventually be
 * transmitted. Making the type incapable of carrying a passphrase closes that
 * door structurally rather than by policy -- the same reasoning that makes a
 * hook a path rather than inline shell.
 */
typedef struct {
	int   provider; /* ncfg_secret_provider_t */
	char *name;     /* provider-scoped */
} ncfg_secret_ref_t;

/*
 * A reference to a prefix another interface obtains by delegation.
 *
 * The prefix is not known until a lease arrives, so the document carries the
 * reference and never the value: a document embedding a runtime value would
 * stop being a pure function of the config files, and two compiles of one
 * config would differ (`doc/decision/0009`).
 */
typedef struct {
	char   *source; /* interface whose delegation supplies it */
	int64_t index;  /* which delegated prefix; u8 */
	int64_t subnet; /* sub-prefix selector; u16 */
} ncfg_prefix_ref_t;

/* ------------------------------------------------------------------------ *
 * Addressing sources
 * ------------------------------------------------------------------------ */

/* Whether and how to send a hostname in a DHCP request. */
typedef enum {
	NCFG_HOSTNAME_MODE_NONE,
	NCFG_HOSTNAME_MODE_SEND,
	NCFG_HOSTNAME_MODE_SEND_FQDN
} ncfg_hostname_mode_t;

/*
 * Which DHCPv4 client runs.
 *
 * `builtin` is recognised and unimplemented. It is in the set because adding a
 * variant after the freeze is a major version bump, and a build without the
 * client must fail with "this build has no built-in DHCP client" rather than
 * "unknown value" (`doc/decision/0004`).
 */
typedef enum {
	NCFG_DHCP4_BACKEND_AUTO,
	NCFG_DHCP4_BACKEND_DHCPCD,
	NCFG_DHCP4_BACKEND_UDHCPC,
	NCFG_DHCP4_BACKEND_BUILTIN
} ncfg_dhcp4_backend_t;

/* DHCPv6 operating mode. */
typedef enum {
	NCFG_DHCP6_MODE_MANAGED,
	NCFG_DHCP6_MODE_OTHER_CONF
} ncfg_dhcp6_mode_t;

/* IPv6 privacy address handling. */
typedef enum {
	NCFG_SLAAC_PRIVACY_NONE,
	NCFG_SLAAC_PRIVACY_PREFER_TEMPORARY
} ncfg_slaac_privacy_t;

/* A statically configured address. */
typedef struct {
	char         *address; /* CIDR, `192.168.1.10/24` */
	char         *peer;    /* point-to-point peer */
	ncfg_optint_t preferred_lifetime;
	ncfg_optint_t valid_lifetime;
} ncfg_static_t;

/* An address derived from a delegated prefix. */
typedef struct {
	ncfg_prefix_ref_t prefix;
	char             *suffix; /* host part and length, `::1/64` */
} ncfg_delegated_t;

/* A request for a delegated prefix. */
typedef struct {
	char         *hint;
	ncfg_optint_t length;
} ncfg_pd_request_t;

/* A DHCPv4 lease. */
typedef struct {
	int           hostname_mode; /* ncfg_hostname_mode_t */
	char         *client_id;
	ncfg_optint_t metric;
	int64_t      *request_options; /* DHCP option numbers */
	size_t        request_option_count;
	int           backend; /* ncfg_dhcp4_backend_t */
} ncfg_dhcp4_t;

/* A DHCPv6 lease, optionally including prefix delegation. */
typedef struct {
	int                mode; /* ncfg_dhcp6_mode_t */
	int                rapid_commit;
	ncfg_pd_request_t *prefix_delegation; /* NULL where none is asked for */
} ncfg_dhcp6_t;

/* Stateless address autoconfiguration. */
typedef struct {
	int privacy; /* ncfg_slaac_privacy_t */
} ncfg_slaac_t;

/*
 * One way an interface acquires addresses.
 *
 * The list of these is a **composition, not a set of alternatives** -- dual
 * stack alone requires it. Order is significant for exactly two things,
 * default route metrics and DNS merge precedence, and is not an execution
 * sequence (`doc/decision/0006`).
 *
 * `reported` carries no payload here, where the Rust has a field-less struct
 * so that the first thing worth configuring becomes a field rather than a
 * second variant. `link_local` has none either: IPv4 link-local coexists with
 * routable addresses rather than being a fallback, because a timeout-triggered
 * fallback would be state hidden in the reconciler that no config explains.
 */
typedef enum {
	NCFG_ADDRESS_SOURCE_STATIC,
	NCFG_ADDRESS_SOURCE_DELEGATED,
	NCFG_ADDRESS_SOURCE_DHCP4,
	NCFG_ADDRESS_SOURCE_DHCP6,
	NCFG_ADDRESS_SOURCE_SLAAC,
	NCFG_ADDRESS_SOURCE_LINK_LOCAL,
	NCFG_ADDRESS_SOURCE_REPORTED
} ncfg_address_source_kind_t;

typedef struct {
	int              kind; /* ncfg_address_source_kind_t */
	ncfg_static_t    static_address;
	ncfg_delegated_t delegated;
	ncfg_dhcp4_t     dhcp4;
	ncfg_dhcp6_t     dhcp6;
	ncfg_slaac_t     slaac;
} ncfg_address_source_t;

/* The word `AddressSource::kind_name` returns, and what the multiplicity
 * check reports. NULL outside the set. */
const char *ncfg_address_source_kind_name(int kind);

/*
 * Whether at most one of this kind may appear on one interface.
 *
 * Two DHCP clients on one link is always a bug, so it is refused at compile
 * time rather than raced at runtime. Any number of `static` and `delegated`
 * entries is legitimate.
 */
int ncfg_address_source_is_singleton(int kind);

/* ------------------------------------------------------------------------ *
 * Routes and hooks
 * ------------------------------------------------------------------------ */

/* The `rtm_protocol` netcfgd stamps on every route it installs. 110 sits mid
 * gap in the largest unallocated run in `linux/rtnetlink.h`; anything without
 * it is somebody else's object (`doc/decision/0002`). */
#define NCFG_ROUTE_PROTO 110

/* `RT_TABLE_MAIN`: the table a route goes into when the config names none.
 * The kernel always reports a table, so an absent `table` here and a reported
 * 254 are the same table, and anything comparing the two normalises through
 * this or every unqualified route looks absent and is reinstalled. */
#define NCFG_ROUTE_MAIN_TABLE 254

typedef enum {
	NCFG_ROUTE_SCOPE_GLOBAL,
	NCFG_ROUTE_SCOPE_LINK,
	NCFG_ROUTE_SCOPE_HOST
} ncfg_route_scope_t;

typedef struct {
	char         *destination; /* CIDR, or `default` */
	char         *via;         /* next hop; an address, never a prefix */
	ncfg_optint_t metric;
	ncfg_optint_t table;
	char         *src; /* preferred source address */
	ncfg_optint_t scope; /* ncfg_route_scope_t where `has` */
	/* Next hop is on-link though no address covers it. Exempts this route
	 * from the ordering rule that puts `addr.add` before `route.add`. */
	int           onlink;
	ncfg_optint_t proto; /* absent means NCFG_ROUTE_PROTO on install */
} ncfg_route_t;

/*
 * A reference to a hook script on disk.
 *
 * The DSL lets an author write inline shell in a `post_up { ... }` block; the
 * compiler materialises those into files and the document carries only this.
 * **A document that could carry shell would be remote code execution with
 * extra steps**, and this closes that structurally rather than by policy.
 */
typedef struct {
	int           phase; /* ncfg_hook_phase_t, from value.h */
	char         *path;  /* absolute; `validate` refuses anything else */
	char         *sha256; /* content hash, so drift can notice a changed hook */
	char         *run_as; /* absent means the daemon's own user, which is root */
	ncfg_optint_t timeout;
} ncfg_hook_ref_t;

/* ------------------------------------------------------------------------ *
 * DNS
 * ------------------------------------------------------------------------ */

/*
 * A mode, and the command the one open-ended mode carries.
 *
 * `exec` hands the whole scoped structure to a script as JSON on stdin -- the
 * escape hatch, and the reason `ncfg_dns_mode_t` alone is not enough to hold a
 * mode. `command` is meaningful only for `NCFG_DNS_MODE_EXEC`.
 */
typedef struct {
	int   mode; /* ncfg_dns_mode_t, from value.h */
	char *command;
} ncfg_dns_mode_value_t;

typedef struct {
	char         *addr; /* an address, never a prefix */
	ncfg_optint_t port;
	char         *sni; /* name to expect in the certificate, for TLS */
} ncfg_dns_server_t;

/*
 * A suffix whose queries route to this scope's servers.
 *
 * Kept separate from `search`, which is suffix completion. resolved spells
 * both as one list distinguished by a `~`; that is an accident of its config
 * format, a reliable source of confusion, and only one of the two is
 * universally supported.
 */
typedef struct {
	char *suffix; /* or `"."` for the catch-all scope */
	int   exclusive;
} ncfg_routing_domain_t;

typedef enum {
	NCFG_DNSSEC_NO,
	NCFG_DNSSEC_ALLOW,
	NCFG_DNSSEC_YES
} ncfg_dnssec_t;

typedef enum {
	NCFG_DNS_TRANSPORT_PLAIN,
	NCFG_DNS_TRANSPORT_TLS,
	NCFG_DNS_TRANSPORT_HTTPS
} ncfg_dns_transport_t;

/*
 * One DNS scope: an interface's, a network's, or the host-wide fallback.
 *
 * A per-interface policy is a scope in its own right and is never merged into
 * one global server list at compile time, because doing so destroys the
 * per-link structure at the earliest and least recoverable moment
 * (`doc/decision/0007`).
 */
typedef struct {
	ncfg_dns_mode_value_t  mode;
	ncfg_dns_server_t     *servers;
	size_t                 server_count;
	char                 **search; /* author-ordered; see canonicalize */
	size_t                 search_count;
	ncfg_routing_domain_t *domains;
	size_t                 domain_count;
	char                 **options; /* author-ordered */
	size_t                 option_count;
	ncfg_optint_t          dnssec;    /* ncfg_dnssec_t where `has` */
	ncfg_optint_t          transport; /* ncfg_dns_transport_t where `has` */
} ncfg_dns_policy_t;

/* Whether this scope asks for anything a flat mode cannot deliver. */
int ncfg_dns_policy_needs_routing(const ncfg_dns_policy_t *policy);

/* Whether this mode can express per-domain query routing. `resolv.conf`
 * cannot: its `search` line is suffix completion, not routing. A config that
 * asks a flat mode for routing domains is an error rather than something to
 * flatten, because flattening sends internal queries to a public resolver. */
int ncfg_dns_mode_can_route(int mode);

/* ------------------------------------------------------------------------ *
 * Link security
 * ------------------------------------------------------------------------ */

typedef enum {
	NCFG_EAP_METHOD_PEAP,
	NCFG_EAP_METHOD_TTLS,
	NCFG_EAP_METHOD_TLS,
	NCFG_EAP_METHOD_PWD
} ncfg_eap_method_t;

/*
 * Where a certificate or key comes from, and **the difference is who has to
 * be able to read the file.**
 *
 * `path` names a file already on this machine, which is an instruction to open
 * it *as root*; a caller who is not root cannot send one. `stored` names
 * content netcfgd already holds, put there by a client that cannot write
 * system files (0127), so it grants nothing the caller did not already give --
 * which is what makes an enterprise network reachable from a desktop client.
 */
typedef enum {
	NCFG_CERT_SOURCE_PATH,
	NCFG_CERT_SOURCE_STORED
} ncfg_cert_source_kind_t;

typedef struct {
	int               has;
	int               kind; /* ncfg_cert_source_kind_t */
	char             *path;
	ncfg_secret_ref_t stored;
} ncfg_cert_source_t;

/*
 * An 802.1X supplicant configuration.
 *
 * Top-level rather than nested under wifi security, because 802.1X is
 * port-based access control that predates its use on radios and is ordinary on
 * wired campus networks (`doc/decision/0008`). Nesting it under an SSID
 * profile made the wired case inexpressible.
 */
typedef struct {
	int   method; /* ncfg_eap_method_t */
	char *identity;
	char *anonymous_identity;
	/* NULL where the method uses no password. */
	ncfg_secret_ref_t *password;
	/*
	 * Which server name the certificate must carry.
	 *
	 * **`ca_cert` alone answers "who signed this", not "who is this".** It
	 * accepts any certificate the pinned issuer signed, which is right when
	 * the issuer is the organisation's own CA and nearly worthless when it is
	 * a public one -- and a commercial certificate on a RADIUS server is
	 * ordinary. Decision 0206.
	 */
	char              *domain_suffix_match;
	ncfg_cert_source_t ca_cert;
	ncfg_cert_source_t client_cert;
	ncfg_cert_source_t private_key;
	char              *phase2;
} ncfg_eap_config_t;

/* WPA protocol generation for a pre-shared key network. */
typedef enum {
	NCFG_PSK_PROTO_WPA2,
	NCFG_PSK_PROTO_WPA3,
	NCFG_PSK_PROTO_WPA2_WPA3
} ncfg_psk_proto_t;

typedef struct {
	ncfg_secret_ref_t passphrase;
	int               proto; /* ncfg_psk_proto_t */
} ncfg_psk_config_t;

/*
 * How a wifi network is secured. Wifi only: a wired port carries an
 * `ncfg_eap_config_t` directly on its interface, so that `psk` and `owe` are
 * not reachable where they mean nothing -- a type that cannot express the
 * wrong thing beats a rule that rejects it.
 */
typedef enum {
	NCFG_SECURITY_OPEN,
	NCFG_SECURITY_PSK,
	NCFG_SECURITY_EAP,
	NCFG_SECURITY_OWE
} ncfg_security_kind_t;

typedef struct {
	int               kind; /* ncfg_security_kind_t */
	ncfg_psk_config_t psk;
	ncfg_eap_config_t eap;
} ncfg_security_t;

/* ------------------------------------------------------------------------ *
 * What a device is, and therefore what netcfgd creates
 * ------------------------------------------------------------------------ */

typedef enum {
	NCFG_VLAN_PROTOCOL_DOT1Q,
	NCFG_VLAN_PROTOCOL_DOT1AD
} ncfg_vlan_protocol_t;

/*
 * How a bond distributes traffic.
 *
 * A closed set rather than the string it used to be: a string accepts
 * `active_backup` and `activebackup` and `ActiveBackup`, all of which the
 * kernel rejects at apply time -- so the config compiles, the plan looks
 * right, and the failure arrives with the interface half-built. The spellings
 * are `iproute2`'s, which is why they are the one kebab-and-digits set here.
 */
typedef enum {
	NCFG_BOND_MODE_BALANCE_RR,
	NCFG_BOND_MODE_ACTIVE_BACKUP,
	NCFG_BOND_MODE_BALANCE_XOR,
	NCFG_BOND_MODE_BROADCAST,
	NCFG_BOND_MODE_IEEE_8023AD,
	NCFG_BOND_MODE_BALANCE_TLB,
	NCFG_BOND_MODE_BALANCE_ALB
} ncfg_bond_mode_t;

typedef enum {
	NCFG_MACVLAN_MODE_PRIVATE,
	NCFG_MACVLAN_MODE_VEPA,
	NCFG_MACVLAN_MODE_BRIDGE,
	NCFG_MACVLAN_MODE_PASSTHRU
} ncfg_macvlan_mode_t;

/* One variant per kernel link kind and one model type for all of them: they
 * take the same parameters and differ only in the name sent to the kernel. */
typedef enum {
	NCFG_TUNNEL_KIND_GRE,
	NCFG_TUNNEL_KIND_GRETAP,
	NCFG_TUNNEL_KIND_IP6GRE,
	NCFG_TUNNEL_KIND_IPIP,
	NCFG_TUNNEL_KIND_SIT,
	NCFG_TUNNEL_KIND_IP6TNL,
	NCFG_TUNNEL_KIND_GENEVE
} ncfg_tunnel_kind_t;

typedef enum {
	NCFG_TUN_MODE_TUN,
	NCFG_TUN_MODE_TAP
} ncfg_tun_mode_t;

typedef struct {
	char  **members;
	size_t  member_count;
	int     stp;
	ncfg_optint_t forward_delay;
	ncfg_optint_t hello_time;
	ncfg_optint_t ageing_time;
	ncfg_optint_t priority;
	/* Off by default, as in the kernel. Never inferred from the presence of
	 * VLAN interfaces elsewhere: a bridge quietly becoming VLAN-aware would
	 * drop untagged traffic that used to pass. */
	int     vlan_filtering;
} ncfg_bridge_config_t;

typedef struct {
	char        **members;
	size_t        member_count;
	int           mode; /* ncfg_bond_mode_t */
	ncfg_optint_t miimon;
} ncfg_bond_config_t;

typedef struct {
	char   *parent;
	int64_t id;
	int     protocol; /* ncfg_vlan_protocol_t */
} ncfg_vlan_config_t;

typedef struct {
	int64_t       id; /* VNI */
	/* Optional, and the difference matters: without it the kernel routes the
	 * outer packets itself, which is usually what is wanted on a host with one
	 * uplink and never what is wanted on a host with several. */
	char         *parent;
	char         *local;
	char         *remote;
	ncfg_optint_t port;
} ncfg_vxlan_config_t;

/* A Curve25519 key: 32 octets, and the 44 characters of base64 one is written
 * as -- 32 is not a multiple of three, which is where the single `=` comes
 * from. */
#define NCFG_KEY_LEN 32u
#define NCFG_KEY_TEXT_LEN 44u

/*
 * The 32 octets a key's base64 spells, into `out`.
 *
 * The one decoder, public because a private key arrives as *text* from
 * `secrets.h` while a public key arrives as *JSON* from the document, and two
 * base64 readers of one format is how the two halves of one program come to
 * disagree about a key -- which is exactly what `public_key`'s comment below
 * says the octets exist to prevent.
 *
 * `length` is the text's, not counting a terminator. **The refusal never
 * quotes the value**: a private key that failed to parse is still a private
 * key, so the sentence names the offending character or the length and
 * nothing else. `out` is zeroed on a refusal rather than left half decoded.
 */
int ncfg_key_parse(const char *text, size_t length, unsigned char out[NCFG_KEY_LEN], char *err,
    size_t err_size);

typedef struct {
	char             *name; /* local label, and the sorting key */
	/*
	 * The peer's public key, as 32 octets.
	 *
	 * Held as octets and re-rendered rather than kept as text, because base64
	 * has more than one spelling of one key -- the final character carries
	 * four significant bits -- and two spellings must compare equal for a plan
	 * to tell "unchanged" from "different".
	 */
	unsigned char     public_key[NCFG_KEY_LEN];
	ncfg_secret_ref_t *preshared_key;
	char             *endpoint;
	char            **allowed_ips;
	size_t            allowed_ip_count;
	ncfg_optint_t     keepalive;
} ncfg_wg_peer_t;

typedef struct {
	ncfg_secret_ref_t private_key;
	ncfg_optint_t     listen_port;
	ncfg_optint_t     fwmark;
	ncfg_wg_peer_t   *peers;
	size_t            peer_count;
} ncfg_wireguard_config_t;

/*
 * An OpenVPN tunnel: **a path to the operator's `.ovpn`, not a rendering of
 * one.** Decision 0046 has the number behind that -- `openvpn --help` lists
 * 253 top-level options -- so netcfgd expressing the surface would be a second
 * OpenVPN configuration language permanently behind the first.
 */
typedef struct {
	char             *config; /* passed to `openvpn --config`, never read */
	char              *username;
	ncfg_secret_ref_t *password;
} ncfg_openvpn_config_t;

typedef struct {
	char             *parent;
	char             *username;
	ncfg_secret_ref_t password;
	char             *service;
	char             *ac;
} ncfg_pppoe_config_t;

typedef struct {
	char *peer;
} ncfg_veth_config_t;

/*
 * A VRF: a routing table with an interface in front of it.
 *
 * It exists because the pre-freeze audit found a routing rule with an `l3mdev`
 * flag -- "match packets belonging to a VRF master" -- and nothing that could
 * create the master. A rule that can only ever match something the tool cannot
 * build is a field that reads as supported and is not.
 */
typedef struct {
	int64_t table;
} ncfg_vrf_config_t;

typedef struct {
	char *parent;
	int   mode; /* ncfg_macvlan_mode_t */
} ncfg_macvlan_config_t;

typedef struct {
	/*
	 * Which encapsulation.
	 *
	 * **Named `mode` and not `kind`, which is what it wants to be called.**
	 * The kind is serialised with an internal tag named `kind`, so a variant
	 * whose inner struct also had one would produce JSON with the member twice
	 * -- which serde writes happily and refuses to read back. Found by the
	 * schema witness the moment every variant was serialised in one document.
	 */
	int           mode; /* ncfg_tunnel_kind_t */
	char         *local;
	char         *remote;
	char         *parent;
	ncfg_optint_t ttl; /* zero means inherit from the inner packet */
	ncfg_optint_t key;
} ncfg_tunnel_config_t;

typedef struct {
	int   mode; /* ncfg_tun_mode_t */
	char *owner;
	char *group;
} ncfg_tun_config_t;

/*
 * What kind of thing a device is.
 *
 * **`wire_guard` and `open_vpn` are the document's spellings**, and the
 * configuration language's are `wireguard` and `openvpn`. See the header
 * comment: this is serde's `snake_case` applied to the Rust variant names, it
 * is what the witness carries, and it is the exact pair of words this project
 * has already shipped wrong twice.
 */
typedef enum {
	NCFG_KIND_PHYSICAL,
	NCFG_KIND_BRIDGE,
	NCFG_KIND_BOND,
	NCFG_KIND_VLAN,
	NCFG_KIND_VXLAN,
	NCFG_KIND_WIREGUARD,
	NCFG_KIND_PPPOE,
	NCFG_KIND_OPENVPN,
	NCFG_KIND_DUMMY,
	NCFG_KIND_VETH,
	NCFG_KIND_VRF,
	NCFG_KIND_MACVLAN,
	NCFG_KIND_TUNNEL,
	NCFG_KIND_TUN,
	/* An intermediate functional block, which exists to be redirected to.
	 * Never written by hand: netcfgd synthesises one per interface asking for
	 * `ingress_bandwidth`, so creation, ownership and teardown all work on it
	 * without knowing what it is for. */
	NCFG_KIND_IFB
} ncfg_interface_kind_tag_t;

typedef struct {
	int                     kind; /* ncfg_interface_kind_tag_t */
	ncfg_bridge_config_t    bridge;
	ncfg_bond_config_t      bond;
	ncfg_vlan_config_t      vlan;
	ncfg_vxlan_config_t     vxlan;
	ncfg_wireguard_config_t wireguard;
	ncfg_pppoe_config_t     pppoe;
	ncfg_openvpn_config_t   openvpn;
	ncfg_veth_config_t      veth;
	ncfg_vrf_config_t       vrf;
	ncfg_macvlan_config_t   macvlan;
	ncfg_tunnel_config_t    tunnel;
	ncfg_tun_config_t       tun;
} ncfg_interface_kind_t;

/* The document's word for a kind, which is not always the language's. NULL
 * outside the set. */
const char *ncfg_interface_kind_name(int kind);

/*
 * The word a tunnel encapsulation goes on the wire as, or NULL outside the set.
 *
 * The document's spelling and the kernel's `IFLA_INFO_KIND` are the same word,
 * deliberately -- see the definition. The executor reads this rather than
 * keeping a list of seven names of its own.
 */
const char *ncfg_tunnel_kind_name(int kind);

/*
 * A mode as the kernel numbers it, or -1 outside the set.
 *
 * **The model owns the numbering**, which is the rule `ops.h` states and the
 * reason `src/apply/` may not keep tables of its own: "two lists of four
 * numbers in two places is how a mode comes to mean one thing on the way out
 * and another on the way back in", and the reader that has to agree with the
 * writer is `src/observe/`, which is already here. A bond's number is its own
 * ordinal; a macvlan's is a flag bit, and 16 -- the `source` mode netcfgd
 * cannot express -- is outside the set in both directions.
 */
int ncfg_bond_mode_number(int mode);
int ncfg_macvlan_mode_number(int mode);

/*
 * The ethertype the kernel wants in `IFLA_VLAN_PROTOCOL`, or -1 outside the set.
 *
 * **Published late, and the reason it was not is worth keeping.** 0263 records
 * it as deliberately absent -- `link.set_vlan` is not an op, so nothing needed
 * it. `link.create` for a vlan does, and that is the whole of what changed: a
 * vlan's id and tag protocol are fixed at creation (the kernel's
 * `vlan_changelink` reads neither), so creation is the *only* place either one
 * can be stated, and a vlan netcfgd cannot create is a vlan netcfgd can never
 * have. The alternative was a two-entry table in `src/apply/`, which is what
 * the paragraph above refuses for a mode.
 *
 * An `int` rather than a `uint16_t` for the same reason a mode number is one:
 * -1 is a protocol outside the set, and a plausible ethertype for a protocol
 * that is not one is worse than no ethertype. `src/observe/build.c` reads the
 * same two numbers the other way, which is the reader this writer has to agree
 * with.
 */
int ncfg_vlan_protocol_ethertype(int protocol);

/* ------------------------------------------------------------------------ *
 * Per-device policy
 * ------------------------------------------------------------------------ */

/*
 * Which queueing discipline a link drains its transmit queue with.
 *
 * A closed set, not a free string. Decision 0023 keeps netcfgd to the root
 * qdisc and to schedulers that need no classes or filters underneath, and an
 * open string would make that line invisible: `htb` would compile, apply, and
 * produce a class-less shaper that drops everything.
 */
typedef enum {
	NCFG_QDISC_FQ_CODEL,
	NCFG_QDISC_CAKE,
	NCFG_QDISC_FQ,
	NCFG_QDISC_PFIFO_FAST,
	NCFG_QDISC_NOQUEUE
} ncfg_qdisc_kind_t;

typedef struct {
	int kind; /* ncfg_qdisc_kind_t */
	/* **Bits**, because that is what an operator writes and what every tool
	 * prints; the kernel wants bytes and the conversion happens once, at the
	 * netlink boundary. */
	ncfg_optint_t bandwidth_bits;
	/* The kernel cannot queue on the way in, so this is not another number on
	 * the same qdisc: it makes netcfgd build an `ifb`, redirect everything
	 * arriving here onto it, and shape it there, where it has become egress. */
	ncfg_optint_t ingress_bandwidth_bits;
	/* Set on the `cake` that sits on the `ifb`, never on an interface the
	 * operator named. */
	int           ingress;
} ncfg_qdisc_policy_t;

/*
 * One VLAN on a bridge port, or on the bridge device itself.
 *
 * Per-port VLAN membership is how a switch is provisioned on any current
 * kernel: DSA presents switch ports as ordinary interfaces.
 */
typedef struct {
	int64_t vid;
	/* At most one per port, which the compiler checks -- the kernel accepts a
	 * second and silently moves the PVID, so two ports' worth of config merged
	 * from drop-ins could change which VLAN untagged traffic lands in with
	 * nothing reporting it. */
	int     pvid;
	int     untagged;
} ncfg_bridge_vlan_t;

/*
 * Whether a tunable is left alone, turned on, or turned off.
 *
 * Three states rather than a `bool`, because "netcfgd does not manage this"
 * and "netcfgd requires this off" are different instructions and produce
 * different plans.
 */
typedef enum {
	NCFG_TOGGLE_UNMANAGED,
	NCFG_TOGGLE_ON,
	NCFG_TOGGLE_OFF
} ncfg_toggle_t;

/*
 * Driver-level link settings, the `ethtool` surface.
 *
 * **The offloads are applied; the rest is not**, and the reason is
 * verification rather than effort: a veth takes a features message and refuses
 * a link-modes set with a bare `EINVAL`, while ring and wake-on-LAN messages
 * are `EOPNOTSUPP` on anything that is not a physical NIC. Every netlink bug
 * this project has shipped was found by writing to a real kernel and reading
 * it back, so settings that can only be exercised against hardware the test
 * suite cannot safely write to are left alone and reported in the plan.
 */
typedef struct {
	int           autoneg; /* ncfg_toggle_t */
	ncfg_optint_t speed;
	char         *duplex;
	char         *wol;
	ncfg_optint_t rx_ring;
	ncfg_optint_t tx_ring;
	int           gro;
	int           gso;
	int           tso;
	int           rx_checksum;
	int           tx_checksum;
} ncfg_link_settings_t;

/*
 * The five offloads netcfgd manages, as one closed set.
 *
 * An enumerator rather than five call sites naming five struct members,
 * because two modules have to walk the same five in the same order: the
 * planner turns each into a `link.set_offloads`, and `src/observe/offloads.c`
 * reads the kernel's active features back and keeps the ones this set can
 * express. A loop over an enum is a loop neither of them can write a
 * different length.
 */
typedef enum {
	NCFG_OFFLOAD_GRO,
	NCFG_OFFLOAD_GSO,
	NCFG_OFFLOAD_TSO,
	NCFG_OFFLOAD_RX_CHECKSUM,
	NCFG_OFFLOAD_TX_CHECKSUM
} ncfg_offload_field_t;

/* How many there are, so a caller can walk them without a terminator. */
#define NCFG_OFFLOAD_FIELD_COUNT 5u

/*
 * The kernel's own feature names one offload field covers.
 *
 * **The model owns the numbering**, which is `ncfg_bond_mode_number`'s rule
 * with strings instead of numbers and is the same rule for the same reason:
 * the writer is `src/plan/offload.c`, which turns a field into a features
 * message, and the reader that has to agree with it is
 * `src/observe/offloads.c`, which fills `ncfg_observed_link_t.offloads` with
 * exactly these strings. Two lists of feature names in two places is how a
 * feature comes to be turned on under one spelling and read back under
 * another -- and since a name absent from a device's active set means "off",
 * a disagreement is not a failure anywhere: it is an offload planned on every
 * pass for ever.
 *
 * **One field is several features.** Transmit checksumming is three, because a
 * driver offers whichever of them its hardware has -- so "on" for such a field
 * means *any* of them and "off" means *all* of them, which is what
 * `ethtool -K dev tx on|off` does.
 *
 * The names rather than the kernel's bit indices, which are not stable across
 * versions and are not a wire contract; `ethtool.h` says why at length.
 *
 * `count` is filled in with how many there are, and NULL with a `count` of 0
 * is a field outside the set -- `ncfg_tunnel_kind_name`'s convention.
 */
const char *const *ncfg_offload_field_names(int field, size_t *count);

/*
 * What an `ethtool` block asks of one offload field.
 *
 * `NCFG_TOGGLE_UNMANAGED` for a field the document does not state and for a
 * field outside the set, which are the same instruction: leave it alone. Here
 * rather than in the planner so that the enumerator and the member it names
 * are decided in one place -- a second mapping would be free to disagree about
 * which member `NCFG_OFFLOAD_TSO` reads, and nothing would fail to compile.
 */
int ncfg_link_settings_offload(const ncfg_link_settings_t *settings, int field);

/*
 * How a device is identified. Every present field must match.
 *
 * Matching is preferred over naming because a name is assigned by the kernel
 * and can move between boots, while a MAC or a PCI path does not.
 */
typedef struct {
	char *mac;
	char *path;
	char *driver;
	char *name_glob;
} ncfg_device_match_t;

typedef enum {
	NCFG_WIFI_BACKEND_AUTO,
	NCFG_WIFI_BACKEND_IWD,
	NCFG_WIFI_BACKEND_WPA_SUPPLICANT
} ncfg_wifi_backend_t;

typedef enum {
	NCFG_POWERSAVE_DEFAULT,
	NCFG_POWERSAVE_ON,
	NCFG_POWERSAVE_OFF
} ncfg_powersave_t;

/*
 * What hardware address a radio presents.
 *
 * A client that always uses its permanent address is trackable across every
 * network it has ever joined, by anyone who has seen it twice. netcfgd could
 * not express the alternative, which meant the answer was "whatever the
 * supplicant's default happens to be" -- a privacy property nobody chose.
 */
typedef enum {
	NCFG_MAC_POLICY_PERMANENT,
	NCFG_MAC_POLICY_PER_NETWORK,
	NCFG_MAC_POLICY_PER_CONNECTION
} ncfg_mac_policy_t;

typedef struct {
	int  backend; /* ncfg_wifi_backend_t */
	int  autoconnect;
	/*
	 * The URL to fetch to find out whether something is intercepting traffic.
	 *
	 * **The operator's URL, never netcfgd's** (0061): a network daemon that
	 * reaches a fixed address to decide whether the internet works is a third
	 * party learning when this machine joins a network. Absent probes nothing.
	 * `http://` only, and that is not a limitation -- a check that cannot be
	 * intercepted cannot detect interception (0095).
	 */
	char *portal_check;
	char *regdom;
	int   powersave;  /* ncfg_powersave_t */
	int   mac_policy; /* ncfg_mac_policy_t */
	/* Separate from `mac_policy` because it is a different exposure: scanning
	 * broadcasts probe requests to everyone in range whether or not anything
	 * is ever joined, so a device that randomises on association and not on
	 * scan is trackable by a passive listener in a cafe it never joined. */
	int   scan_randomization;
} ncfg_wifi_device_policy_t;

/*
 * Cellular policy, for a modem device (0150).
 *
 * netcfgd says which SIM source is wanted; a `pre_up` hook makes the hardware
 * do it, because driving a mux select line is board enablement and netcfgd has
 * no GPIO anywhere. The names are the board's and netcfgd does not interpret
 * them.
 */
typedef struct {
	char  **sim; /* ordered: "which do you want, and what next" is one statement */
	size_t  sim_count;
	/* Provisioning data, and it cannot be discovered -- nor validated by
	 * connecting, since asking for an APN the subscription does not carry gets
	 * the network's own default rather than an error. */
	char   *apn;
} ncfg_modem_policy_t;

/* What netcfgd does with a device it is about to stop managing. A policy
 * rather than an action, so it can sit in the configuration while the device
 * is still managed and mean "if you ever stop, do this". */
typedef enum {
	/* Walk away and change nothing. The right answer when handing an interface
	 * to another daemon. */
	NCFG_ON_UNMANAGE_LEAVE,
	/* Remove everything netcfgd owns first. The right answer when the hardware
	 * is leaving your hands, because walking away otherwise strands
	 * credentials: a WireGuard key stays loaded in the kernel and a supplicant
	 * keeps its passphrases. */
	NCFG_ON_UNMANAGE_CLEAR
} ncfg_on_unmanage_t;

typedef struct {
	char                *name; /* kernel name, and the sorting key */
	ncfg_device_match_t *match; /* NULL where the name alone is enough */
	/* When false, netcfgd never touches this device at all. Enforced at the
	 * planner's action choke point (0035); before that it was honoured only by
	 * the filter deciding which devices are radios, so the flag read as
	 * documentation rather than as a control. */
	int                  managed;
	int                  on_unmanage; /* ncfg_on_unmanage_t */
	ncfg_wifi_device_policy_t *wifi;
	ncfg_modem_policy_t       *modem;
	/* ---- what 0155 pass 1a moved off `Interface`: settings of the hardware
	 * itself, which mean something whether or not anything is connected. ---- */
	ncfg_optint_t         mtu;
	char                 *mac;
	ncfg_link_settings_t *link_settings;
	/* ---- and pass 1b's structural half: what netcfgd creates, what it is a
	 * port of, and how its egress is shaped. Defaulted where `Interface`
	 * required it, because most devices are physical and say nothing. ---- */
	ncfg_interface_kind_t kind;
	char                 *master; /* bridge or bond this is a member of */
	ncfg_qdisc_policy_t  *qdisc;
	/* Synthesised, never written: the `ifb` that `ingress_bandwidth` asks for.
	 * Named in the document rather than derived at apply time so that `ncfg
	 * plan` can say which device the redirect points at. */
	char                 *ingress_redirect;
	/*
	 * **Authoritative where present.** A port whose config lists VLANs has
	 * exactly those, and anything else the kernel holds for it is removed --
	 * including the VLAN 1 the kernel adds by itself the moment a port joins a
	 * filtering bridge. Every real trunk setup begins by deleting that one. A
	 * port the document says nothing about keeps whatever it has.
	 */
	ncfg_bridge_vlan_t   *bridge_vlans;
	size_t                bridge_vlan_count;
} ncfg_device_t;

/* ------------------------------------------------------------------------ *
 * Interfaces
 * ------------------------------------------------------------------------ */

/* Which daemon sends router advertisements. netcfgd does not send them
 * itself, because it configures and does not serve (`doc/decision/0009`). */
typedef enum {
	NCFG_RA_BACKEND_AUTO,
	NCFG_RA_BACKEND_ODHCPD,
	NCFG_RA_BACKEND_RADVD,
	NCFG_RA_BACKEND_EXEC
} ncfg_ra_backend_kind_t;

typedef struct {
	int   kind;    /* ncfg_ra_backend_kind_t */
	char *command; /* meaningful only for NCFG_RA_BACKEND_EXEC */
} ncfg_ra_backend_t;

typedef struct {
	ncfg_ra_backend_t  backend;
	ncfg_prefix_ref_t *prefixes;
	size_t             prefix_count;
	int                managed;
	int                other_config;
	int                dns; /* defaults to true */
	ncfg_optint_t      lifetime;
} ncfg_ra_policy_t;

/*
 * Why an interface must not be disrupted.
 *
 * The reason is a string rather than a flag because the refusal text is the
 * whole value: "eth0 is critical" sends the reader looking for what is
 * critical about it, and "eth0: nfs root" tells them what to go and stop.
 */
typedef struct {
	char *reason;
} ncfg_guard_t;

/*
 * What to run to find out whether an uplink carries traffic.
 *
 * **The exit status is the answer**, which is why an arbitrary program is the
 * interface rather than a lowered ambition: `ping`, `curl -f` and a script
 * somebody wrote all agree that zero means it worked, and on a captive-portal
 * network the operator's definition of reachable is the one that matters. A
 * path with a timeout and never inline shell, the shape a hook already has.
 */
typedef struct {
	char   *command; /* absolute */
	char  **args;
	size_t  arg_count;
	int64_t interval;
	int64_t timeout;
	/* Asymmetric with `up_after` on purpose: symmetric counts make a marginal
	 * link oscillate at whatever period `interval` sets. One lost packet is
	 * not an outage, so this is larger. Named `down_after` and not `down`
	 * because the config language reserves `up` and `down` as hook phases. */
	int64_t down_after;
	/* Only where the interface asked for DHCP, and default on: an interface
	 * configured for DHCP with no lease has nothing a probe could succeed
	 * over. It is a precondition, not a verdict -- a lease says a DHCP server
	 * answered, which a local server on a network with a dead uplink does
	 * happily (0191). */
	int     require_lease;
	int64_t up_after;
	/* Seconds a verdict must stand before it may change again; 0 for none.
	 * The counts are the first brake and not the whole one: a link that
	 * alternates in runs -- three bad, two good, three bad -- satisfies both
	 * and moves the default route on every cycle, just at a longer period. */
	int64_t hold_down;
} ncfg_probe_policy_t;

typedef struct {
	char                  *name; /* the sorting key */
	int                    enabled;
	ncfg_address_source_t *addressing;
	size_t                 addressing_count;
	ncfg_route_t          *routes;
	size_t                 route_count;
	ncfg_dns_policy_t     *dns;
	ncfg_hook_ref_t       *hooks;
	size_t                 hook_count;
	ncfg_optint_t          on_drift; /* ncfg_drift_policy_t where `has` */
	ncfg_eap_config_t     *dot1x;    /* wired 802.1X */
	ncfg_ra_policy_t      *advertise;
	/*
	 * IP forwarding sysctl, and only that. Never a filter rule: decision 0022
	 * lets netcfgd own one nftables table for NAT, on the grounds that
	 * translating addresses is addressing -- deciding which packets may pass
	 * is security policy, which this project has no model of.
	 *
	 * Set on the interface packets *arrive* on, which is the LAN side of a
	 * router and not the uplink.
	 */
	ncfg_optbool_t         forwarding;
	/* The other half of `forwarding`, and neither works alone: forwarding
	 * without NAT sends private addresses at the internet, NAT without
	 * forwarding translates packets the kernel already dropped. */
	ncfg_optbool_t         nat;
	ncfg_guard_t          *guard;
	/* `ip token set ::5 dev eth0`: the prefix still comes from the router, the
	 * host part is chosen. The reason to want it is a server that must be
	 * reachable at a predictable address on a prefix that may change. */
	char                  *ipv6_token;
	/*
	 * How this interface ranks against others that can reach the same place.
	 * Lower wins, as in a route metric -- which is what it becomes.
	 *
	 * Setting it also ties the interface's routes to its carrier, which is the
	 * half that makes a laptop work: a default route down a cable that is not
	 * plugged in is a black hole, and a lower metric makes the kernel prefer
	 * it over the wifi that does work.
	 */
	ncfg_optint_t          preference;
	ncfg_probe_policy_t   *probe;
} ncfg_interface_t;

/* ------------------------------------------------------------------------ *
 * Wifi networks and access points
 * ------------------------------------------------------------------------ */

#define NCFG_SSID_MAX_LEN 32

/*
 * An SSID: 0 to 32 arbitrary octets.
 *
 * **Not a string.** 802.11 places no encoding requirement on an SSID and real
 * networks ship ones that are not valid UTF-8, so this is bytes and the JSON
 * encoding is lowercase hex rather than a string that would have to lie about
 * what it holds or fail to round-trip. Uppercase hex is refused on the way in,
 * because two spellings of one SSID would break the byte-identical guarantee.
 */
typedef struct {
	int           has;
	unsigned char bytes[NCFG_SSID_MAX_LEN];
	size_t        length;
} ncfg_ssid_t;

/*
 * When a client should look for a better access point on the same network.
 *
 * Stated as an intent rather than as `wpa_supplicant`'s string: a
 * `bgscan="simple:30:-70:300"` in a config file would be netcfgd asking the
 * operator to know which supplicant is underneath.
 */
typedef struct {
	int64_t signal;   /* dBm; below this the radio is weak enough to look */
	int64_t interval; /* seconds between scans while below `signal` */
	/* Not zero and not absent: a station that stops looking once it is
	 * comfortable never notices the access point it walked past, which is the
	 * failure this whole policy exists to avoid. */
	int64_t slow_interval;
} ncfg_roam_policy_t;

typedef struct {
	char       *id; /* the sorting key */
	/* Absent means "whatever the access points in `bssid` call themselves".
	 * Not a convenience: WPA derives its key from the passphrase *and* the
	 * SSID, so a secured network cannot be joined without one. */
	ncfg_ssid_t ssid;
	int         hidden;
	ncfg_security_t security;
	/* Lower wins, and it is a route metric -- the same scale as an interface's
	 * `preference`, because it becomes the same thing. It is also the only way
	 * to rank a wired link against a *network*, and it decides which network
	 * to join (0154). */
	ncfg_optint_t metric;
	int           autoconnect;
	int           metered;
	/* **One entry pins; several choose.** A single entry is the opposite of a
	 * roam policy and refused alongside it: a network pinned to one access
	 * point has nowhere to roam. */
	char        **bssid;
	size_t        bssid_count;
	ncfg_roam_policy_t    *roam;
	ncfg_address_source_t *addressing;
	size_t                 addressing_count;
	ncfg_route_t          *routes;
	size_t                 route_count;
	ncfg_dns_policy_t     *dns;
	ncfg_hook_ref_t       *hooks;
	size_t                 hook_count;
} ncfg_wifi_network_t;

/*
 * Which way an access control list reads. One list rather than two, because
 * hostapd has one: `macaddr_acl` selects *either* `accept_mac_file` or
 * `deny_mac_file`, and a configuration naming both would have half of it
 * silently ignored.
 */
typedef enum {
	NCFG_ACL_POLICY_DENY,
	NCFG_ACL_POLICY_ALLOW
} ncfg_acl_policy_t;

typedef struct {
	int     policy; /* ncfg_acl_policy_t */
	/* Lowercase `aa:bb:cc:dd:ee:ff`, sorted and deduplicated, so two documents
	 * meaning the same thing hash the same and a comparison against what
	 * hostapd reports is a string comparison rather than a parse. */
	char  **stations;
	size_t  station_count;
} ncfg_access_control_t;

/*
 * An access point netcfgd runs, rather than joins.
 *
 * Bound to a device, unlike a wifi network which deliberately is not: a
 * station profile describes a network that may be in range of any radio, while
 * an access point is a thing one specific radio is doing. Unimplemented, and
 * in the schema for a milestone before anything implemented it, because the
 * model freezes and adding it afterwards is a major version bump.
 */
typedef struct {
	char                  *id; /* the sorting key */
	ncfg_ssid_t            ssid;
	char                  *device;
	ncfg_security_t        security;
	ncfg_optint_t          channel; /* absent means the implementation chooses */
	char                  *band;
	/* Not a security measure and not documented as one: it stops the network
	 * appearing in a list and makes every client that knows it broadcast the
	 * name while probing, which is worse than the problem. */
	int                    hidden;
	char                  *regdom;
	/* Absent means everyone. */
	ncfg_access_control_t *access_control;
} ncfg_access_point_t;

/* ------------------------------------------------------------------------ *
 * Policy routing rules
 * ------------------------------------------------------------------------ */

/*
 * One policy routing rule.
 *
 * A route says where a packet goes; a rule says which set of routes is
 * consulted in the first place. Host-wide rather than per-interface: rules are
 * selected by priority across the whole system and two interfaces' rules
 * interleave by number, so attaching them to an interface would make the
 * ordering something you had to reconstruct by reading every block.
 *
 * The field set is deliberately the one `ip rule` exposes and no more.
 */
typedef struct {
	/* A handle from the block label. Rules are the one thing here the kernel
	 * identifies purely by number, and "rule 100 conflicts with rule 200"
	 * tells an operator nothing they did not already see. */
	char         *id;
	/* Required, not defaulted. The kernel will assign one, but an unnumbered
	 * rule lands wherever the kernel puts it and two applies can produce
	 * different orders -- which makes the document stop describing the
	 * system. */
	int64_t       priority;
	int           family; /* ncfg_rule_family_t, from value.h */
	char         *from;
	char         *to;
	char         *iif;
	char         *oif;
	/* netcfgd never sets a mark; routing on one somebody else set is exactly
	 * what this is for. Marking a packet is classification, which would be the
	 * first step across the line 0022 draws. */
	ncfg_optint_t fwmark;
	ncfg_optint_t fwmask;
	ncfg_optint_t table;
	int           action; /* ncfg_rule_action_t, from value.h */
	/* The `suppress_prefixlength 0` trick: consult the main table but skip its
	 * default route, so a more specific rule below can catch it. */
	ncfg_optint_t suppress_prefixlength;
	int           l3mdev;
	int           invert;
} ncfg_routing_rule_t;

/* ------------------------------------------------------------------------ *
 * Bluetooth devices and linksets
 * ------------------------------------------------------------------------ */

/*
 * One Bluetooth device the configuration describes (0149).
 *
 * A device is a block like a network -- labelled by a handle the operator
 * chose, carrying the address as a fact. **No pairing state and no codec**:
 * whether a device is paired is a fact about the adapter's key store,
 * established interactively, and writing it here would be a second source of
 * truth for something netcfgd does not own.
 */
typedef struct {
	char *id;      /* the operator's handle, and the sorting key */
	char *address; /* uppercase and colon-separated, which is the fact */
	int   profile; /* ncfg_bluetooth_profile_t, from value.h */
	int   autoconnect;
} ncfg_bluetooth_device_t;

/* The set that carries the default route, by name. A name rather than an
 * `uplink = true` field, because a flag would need a rule saying what two of
 * them mean and a name cannot be ambiguous. */
#define NCFG_LINKSET_UPLINK "uplink"

/*
 * A named set of links, one of which is used at a time.
 *
 * Failover said once, for links of any kind: a laptop with a cable and two
 * saved networks, a router with fibre and an LTE modem behind it. **A linkset
 * is itself a link**, so a set composes into another set.
 */
typedef struct {
	char  *name; /* the sorting key */
	/* **A ranked list, not a set**, which is why nothing sorts it: a bond's
	 * members are interchangeable and get sorted into canonical order, and
	 * these are not -- the order is the operator saying which of two equally
	 * ranked links they would rather be on. */
	char **members;
	size_t member_count;
} ncfg_linkset_t;

/* ------------------------------------------------------------------------ *
 * Host-wide policy
 * ------------------------------------------------------------------------ */

/*
 * Who a tier is open to.
 *
 * Four shapes, deliberately, and no expression language: every authorisation
 * system that grew one did so a reasonable extension at a time and ended up as
 * something operators copy from forums without understanding.
 */
typedef enum {
	NCFG_PRINCIPAL_ROOT, /* the default for every tier */
	NCFG_PRINCIPAL_ANY,
	NCFG_PRINCIPAL_USER,
	NCFG_PRINCIPAL_GROUP
} ncfg_principal_kind_t;

typedef struct {
	int   kind; /* ncfg_principal_kind_t */
	char *name; /* for USER and GROUP */
} ncfg_principal_t;

typedef struct {
	ncfg_principal_t observe;
	ncfg_principal_t wifi;
	ncfg_principal_t admin;
} ncfg_control_t;

/*
 * Which tiers a caller that arrived on the remote socket may use at all.
 *
 * **Booleans and not principals**, which is 0128's substance: the local policy
 * names `user:alice` and checks it against `SO_PEERCRED`, and none of that can
 * mean anything for a connection the agent terminated, because every remote
 * caller arrives as the agent. Everything is false by default.
 */
typedef struct {
	int              observe;
	int              wifi;
	int              admin;
	/* A principal where the tiers are booleans, and not the asymmetry 0128
	 * rejected: this describes the process on *this* machine holding the other
	 * end of the unix socket, which is exactly what `SO_PEERCRED` answers.
	 * Root by default, so a machine that opens remote access without saying
	 * who runs the agent has a socket only root can reach (0159). */
	ncfg_principal_t agent;
} ncfg_remote_policy_t;

/* What the document says should count as connected. */
typedef enum {
	NCFG_REQUIRES_ROUTE, /* a default route; what a machine with no probe can know */
	NCFG_REQUIRES_PROBE, /* for a machine behind a captive portal, where a route proves nothing */
	NCFG_REQUIRES_ADDRESS /* for a machine whose job is its own subnet */
} ncfg_requires_t;

/*
 * Which links count, and what counts as connected.
 *
 * **`docker0` is why `ignore` exists.** It is down and holds `172.17.0.1/16`
 * on any machine with docker installed, and both trays counted any addressed
 * interface that was not `lo` -- so a wired-only machine with no network at
 * all reported itself locally connected, naming a bridge to nowhere. Writing
 * `ignore` **replaces** the default list rather than adding to it.
 */
typedef struct {
	int     requires_; /* ncfg_requires_t; `requires` is C++'s and reads worse */
	char  **ignore;
	size_t  ignore_count;
} ncfg_connectivity_policy_t;

/* The patterns a document that says nothing gets. A trailing `*` is a prefix,
 * and there is no other wildcard: this is a short list of families, not a
 * matching language. */
extern const char *const ncfg_connectivity_default_ignore[];
extern const size_t      ncfg_connectivity_default_ignore_count;

/* Where the system hostname comes from. */
typedef enum {
	NCFG_HOSTNAME_POLICY_NONE, /* netcfgd does not manage it */
	NCFG_HOSTNAME_POLICY_FROM_DHCP,
	NCFG_HOSTNAME_POLICY_STATIC
} ncfg_hostname_policy_kind_t;

typedef struct {
	int   kind; /* ncfg_hostname_policy_kind_t */
	char *name; /* for STATIC */
} ncfg_hostname_policy_t;

/*
 * Whether this host does networking at all.
 *
 * The switch a "no networking" profile needs: a profile is a set of drop-ins
 * and the config language has no wildcard, so a profile cannot say "every
 * interface on this machine, down" -- it would have to name them, and the
 * names differ per machine. It is not `managed = false`: unmanaged means
 * netcfgd does not touch the interface and the machine keeps talking, off
 * means the links go down and the addresses are withdrawn.
 */
typedef enum {
	NCFG_NETWORKING_ON,
	NCFG_NETWORKING_OFF
} ncfg_networking_t;

typedef struct {
	/* The fallback DNS scope. Per-interface policies are scopes in their own
	 * right rather than overlays on this one (`doc/decision/0007`). */
	ncfg_dns_policy_t          dns;
	/* **Defaults to reconcile, which is not C's zero value**; see value.h. */
	int                        on_drift_default; /* ncfg_drift_policy_t */
	ncfg_optint_t              confirm_default;  /* seconds */
	int                        networking;       /* ncfg_networking_t */
	/* **Absent is the default and is not a profile called "none"** (0151): a
	 * machine with hand-written configuration and no selection is not running
	 * a profile, and spelling that state as one would make it permanently
	 * confusable with the shipped `offline` profile in every diagnostic. */
	char                      *profile;
	ncfg_hostname_policy_t     hostname_policy;
	ncfg_control_t             control;
	/* Separate from `control` because the two cannot be one sentence: the
	 * local policy is principals checked against peer credentials, and a
	 * remote caller has none the daemon can see (0128). */
	ncfg_remote_policy_t       remote;
	/* Host-wide rather than per-interface, because the question is about the
	 * machine: a tray icon says whether *this computer* is on the network, and
	 * an answer assembled per interface is the thing four clients were each
	 * assembling differently. */
	ncfg_connectivity_policy_t connectivity;
} ncfg_globals_t;

/* ------------------------------------------------------------------------ *
 * The document
 * ------------------------------------------------------------------------ */

/*
 * The whole-host desired state.
 *
 * This is the canonical form; the per-interface files under
 * `/run/netcfgd/desired/` are projections of it for convenience, not separate
 * documents.
 */
typedef struct {
	ncfg_version_t           schema_version;
	/* Informational provenance, and **excluded from equality**: two documents
	 * that differ only here describe the same desired state, and a plan
	 * computed from either must be identical. */
	char                    *generated_by;
	ncfg_globals_t           globals;
	ncfg_device_t           *devices; /* sorted by name */
	size_t                   device_count;
	ncfg_interface_t        *interfaces; /* sorted by name */
	size_t                   interface_count;
	ncfg_wifi_network_t     *networks; /* sorted by id */
	size_t                   network_count;
	/* Sorted by id, and not bound to an adapter for the reason a network is
	 * not bound to a radio: a device is a thing the machine uses, and which
	 * adapter reaches it is the machine's business. */
	ncfg_bluetooth_device_t *bluetooth;
	size_t                   bluetooth_count;
	ncfg_routing_rule_t     *rules; /* sorted by priority */
	size_t                   rule_count;
	ncfg_access_point_t     *access_points; /* sorted by id */
	size_t                   access_point_count;
	ncfg_linkset_t          *linksets; /* sorted by name */
	size_t                   linkset_count;
} ncfg_document_t;

/*
 * An empty document with every default in place.
 *
 * Worth having rather than a `calloc`, because two of the defaults are not the
 * zero value and one of them matters: `on_drift_default` is `reconcile`, and a
 * zeroed document means `report` -- a daemon that watches its configuration go
 * unimplemented and changes nothing. That default was changed by the copyright
 * holder for exactly that reason. `connectivity.ignore` is the other, and it
 * is five strings that have to be allocated, which is why this can fail.
 *
 * Allocated rather than filled in for a caller, so that there is one way to
 * free a document however it was made.
 */
ncfg_document_t *ncfg_document_new(char *err, size_t err_size);

/*
 * Parse a document, **refusing anything this build cannot fully represent**,
 * and validate it.
 *
 * This is `Document::from_json`: an unknown member is refused rather than
 * ignored, because silently dropping one would mean acting on a subset of what
 * the author wrote. `text` need not be NUL-terminated.
 *
 * Returns NULL with a sentence in `err` naming the member, the block it was
 * in, or the invariant that failed.
 */
ncfg_document_t *ncfg_document_read(const char *text, size_t length, char *err, size_t err_size);

/* Free the tree. A NULL document, and one never filled in, are nothing. */
void ncfg_document_free(ncfg_document_t *document);

/*
 * The device block of that name, or NULL where the document has none.
 *
 * A linear scan, and here rather than in whichever module wanted it first:
 * "is this device managed" is asked by the planner, by the DNS scope rule and
 * by the daemon, and a lookup spelled once per asker is three places to get
 * the NULL handling wrong. The document's own lists are this header's to walk.
 *
 * **A device and an interface of one name are two blocks**, and a document may
 * have either without the other. An interface with no device block is the
 * ordinary case and it is managed, so a NULL answer here must not be read as
 * "unmanaged" -- every caller asks `device && !device->managed`.
 */
const ncfg_device_t *ncfg_document_device(const ncfg_document_t *document, const char *name);

/*
 * Put every list in its declared order.
 *
 * Sorting is by the key the schema names -- interfaces by name, networks by
 * id, WireGuard peers by name -- never by insertion order, which depends on
 * which drop-in file happened to be read first.
 */
void ncfg_document_canonicalize(ncfg_document_t *document);

/*
 * Check every invariant that makes a document meaningful.
 *
 * Returns the first violation, named specifically enough to fix: "invalid
 * document" is not a diagnostic.
 */
int ncfg_document_validate(const ncfg_document_t *document, char *err, size_t err_size);

/*
 * Write the document into `buf`.
 *
 * Member order is declaration order and a member that is at its default is
 * omitted exactly where the Rust omits it, so a document read and written back
 * is the document that arrived.
 */
int ncfg_document_write(const ncfg_document_t *document, ncfg_buf_t *buf, char *err,
    size_t err_size);

/*
 * Canonicalise, validate and write, which is `to_json_canonical`.
 *
 * **Canonicalises in place**, where the Rust clones first. A clone of this
 * tree is a second full traversal for the benefit of a caller who wanted the
 * unsorted order back, and there is no such caller: sorting is what makes two
 * documents comparable.
 */
int ncfg_document_write_canonical(ncfg_document_t *document, ncfg_buf_t *buf, char *err,
    size_t err_size);

#endif /* NCFG_DOCUMENT_H */
