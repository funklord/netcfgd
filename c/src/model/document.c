/*
 * document.c -- the desired-state document: its tables, its tagged unions,
 * and the four operations `document.h` publishes.
 *
 * Every table below is `crates/netcfgd-model` read out field by field --
 * **which member is required, which has a default, and which is left out of
 * the output when it is at that default.** That last one is not cosmetic.
 * `doc/schema/document.json` is a frozen witness that has to be blessed
 * deliberately when it moves (decision 0020), so a field that starts writing
 * itself when it did not before re-blesses a witness for no change in what the
 * machine does -- and an upgrade then looks like a configuration change to
 * everything downstream.
 *
 * The spellings are read from the Rust and never from memory. Two of them are
 * not what a config author writes -- `wire_guard` and `open_vpn` -- and that
 * pair is exactly the one this project has shipped wrong twice, compiling a
 * block with the feature silently missing. They are in `document.h`'s comment
 * as well, because somebody will try to tidy them.
 */
#include "field.h"

#include "ncfg/document.h"

#include <stdlib.h>
#include <string.h>

#define COUNT_OF(array) (sizeof(array) / sizeof((array)[0]))
#define WORD_SET(what_, table_) { what_, table_, COUNT_OF(table_), NULL, NULL }
#define VALUE_SET(what_, namer_, reader_) { what_, NULL, 0, namer_, reader_ }
#define TYPE(what_, fields_) { what_, fields_, COUNT_OF(fields_), NULL }
#define TAGGED(what_, fields_, tag_) { what_, fields_, COUNT_OF(fields_), tag_ }

/* The Rust's own widths, checked on the way in so that nothing is lost by
 * storing every number as an `int64_t`. A `u16` port refuses 70000 and says
 * what the range was. */
#define R_U8  .low = 0, .high = 255
#define R_U16 .low = 0, .high = 65535
#define R_U32 .low = 0, .high = 4294967295LL
/* A `u64` in the Rust; the reader's own integer is signed, so this is where
 * the two meet. No shaped rate comes near it. */
#define R_U64 .low = 0, .high = INT64_MAX
#define R_I32 .low = -2147483647LL - 1, .high = 2147483647LL

/* ------------------------------------------------------------------------ *
 * The six sets value.h owns
 *
 * Reached through its own functions rather than copied, because a second table
 * of those spellings is the defect value.h exists to prevent. The shims are
 * here because this engine stores a closed set as an `int`, and C does not
 * promise that an `enum` is one.
 * ------------------------------------------------------------------------ */

#define VALUE_SHIM(prefix, type)                                                            \
	static const char *prefix##_word(int value)                                             \
	{                                                                                       \
		return prefix##_name((type)value);                                                  \
	}                                                                                       \
	static int prefix##_read(const char *name, int *out, char *err, size_t err_size)         \
	{                                                                                       \
		type value = (type)0;                                                               \
		if (!prefix##_from_name(name, &value, err, err_size)) {                             \
			return 0;                                                                       \
		}                                                                                   \
		*out = (int)value;                                                                  \
		return 1;                                                                           \
	}

VALUE_SHIM(ncfg_hook_phase, ncfg_hook_phase_t)
VALUE_SHIM(ncfg_rule_action, ncfg_rule_action_t)
VALUE_SHIM(ncfg_rule_family, ncfg_rule_family_t)
VALUE_SHIM(ncfg_bluetooth_profile, ncfg_bluetooth_profile_t)
VALUE_SHIM(ncfg_drift_policy, ncfg_drift_policy_t)
VALUE_SHIM(ncfg_dns_mode, ncfg_dns_mode_t)

static const ncfg_enum_t hook_phase_set =
    VALUE_SET("hook phase", ncfg_hook_phase_word, ncfg_hook_phase_read);
static const ncfg_enum_t rule_action_set =
    VALUE_SET("rule action", ncfg_rule_action_word, ncfg_rule_action_read);
static const ncfg_enum_t rule_family_set =
    VALUE_SET("rule family", ncfg_rule_family_word, ncfg_rule_family_read);
static const ncfg_enum_t bluetooth_profile_set =
    VALUE_SET("bluetooth profile", ncfg_bluetooth_profile_word, ncfg_bluetooth_profile_read);
static const ncfg_enum_t drift_policy_set =
    VALUE_SET("drift policy", ncfg_drift_policy_word, ncfg_drift_policy_read);
static const ncfg_enum_t dns_mode_set =
    VALUE_SET("dns mode", ncfg_dns_mode_word, ncfg_dns_mode_read);

/* ------------------------------------------------------------------------ *
 * The sets this module owns
 * ------------------------------------------------------------------------ */

static const char *const secret_provider_words[] = { "file", "keyring", "pass", "exec" };
static const ncfg_enum_t secret_provider_set = WORD_SET("secret provider", secret_provider_words);

static const char *const hostname_mode_words[] = { "none", "send", "send_fqdn" };
static const ncfg_enum_t hostname_mode_set = WORD_SET("hostname mode", hostname_mode_words);

static const char *const dhcp4_backend_words[] = { "auto", "dhcpcd", "udhcpc", "builtin" };
static const ncfg_enum_t dhcp4_backend_set = WORD_SET("dhcp4 backend", dhcp4_backend_words);

static const char *const dhcp6_mode_words[] = { "managed", "other_conf" };
static const ncfg_enum_t dhcp6_mode_set = WORD_SET("dhcp6 mode", dhcp6_mode_words);

static const char *const slaac_privacy_words[] = { "none", "prefer_temporary" };
static const ncfg_enum_t slaac_privacy_set = WORD_SET("slaac privacy", slaac_privacy_words);

static const char *const address_source_words[] = { "static", "delegated", "dhcp4", "dhcp6",
	"slaac", "link_local", "reported" };
static const ncfg_enum_t address_source_set = WORD_SET("addressing source", address_source_words);

static const char *const route_scope_words[] = { "global", "link", "host" };
static const ncfg_enum_t route_scope_set = WORD_SET("route scope", route_scope_words);

static const char *const dnssec_words[] = { "no", "allow", "yes" };
static const ncfg_enum_t dnssec_set = WORD_SET("dnssec posture", dnssec_words);

static const char *const dns_transport_words[] = { "plain", "tls", "https" };
static const ncfg_enum_t dns_transport_set = WORD_SET("dns transport", dns_transport_words);

static const char *const eap_method_words[] = { "peap", "ttls", "tls", "pwd" };
static const ncfg_enum_t eap_method_set = WORD_SET("eap method", eap_method_words);

static const char *const psk_proto_words[] = { "wpa2", "wpa3", "wpa2_wpa3" };
static const ncfg_enum_t psk_proto_set = WORD_SET("wpa generation", psk_proto_words);

static const char *const security_words[] = { "open", "psk", "eap", "owe" };
static const ncfg_enum_t security_set = WORD_SET("security type", security_words);

static const char *const vlan_protocol_words[] = { "dot1q", "dot1ad" };
static const ncfg_enum_t vlan_protocol_set = WORD_SET("vlan protocol", vlan_protocol_words);

/* `iproute2`'s spellings, and the one set here that is neither snake nor
 * kebab all through: `802.3ad` is what every piece of bonding documentation
 * calls LACP, and a tidier word would be a bond the kernel refuses. */
static const char *const bond_mode_words[] = { "balance-rr", "active-backup", "balance-xor",
	"broadcast", "802.3ad", "balance-tlb", "balance-alb" };
static const ncfg_enum_t bond_mode_set = WORD_SET("bond mode", bond_mode_words);

static const char *const macvlan_mode_words[] = { "private", "vepa", "bridge", "passthru" };
static const ncfg_enum_t macvlan_mode_set = WORD_SET("macvlan mode", macvlan_mode_words);

static const char *const tunnel_kind_words[] = { "gre", "gretap", "ip6gre", "ipip", "sit",
	"ip6tnl", "geneve" };
static const ncfg_enum_t tunnel_kind_set = WORD_SET("tunnel encapsulation", tunnel_kind_words);

static const char *const tun_mode_words[] = { "tun", "tap" };
static const ncfg_enum_t tun_mode_set = WORD_SET("tun mode", tun_mode_words);

/* **`wire_guard` and `open_vpn`, and neither is a typo to tidy up.** See the
 * file comment and `document.h`: these are the document's spellings and the
 * configuration language's are `wireguard` and `openvpn`. */
static const char *const interface_kind_words[] = { "physical", "bridge", "bond", "vlan",
	"vxlan", "wire_guard", "pppoe", "open_vpn", "dummy", "veth", "vrf", "macvlan", "tunnel",
	"tun", "ifb" };
static const ncfg_enum_t interface_kind_set = WORD_SET("interface kind", interface_kind_words);

static const char *const qdisc_kind_words[] = { "fq_codel", "cake", "fq", "pfifo_fast",
	"noqueue" };
static const ncfg_enum_t qdisc_kind_set = WORD_SET("queueing discipline", qdisc_kind_words);

static const char *const toggle_words[] = { "unmanaged", "on", "off" };
static const ncfg_enum_t toggle_set = WORD_SET("toggle", toggle_words);

static const char *const wifi_backend_words[] = { "auto", "iwd", "wpa_supplicant" };
static const ncfg_enum_t wifi_backend_set = WORD_SET("wifi backend", wifi_backend_words);

static const char *const powersave_words[] = { "default", "on", "off" };
static const ncfg_enum_t powersave_set = WORD_SET("powersave setting", powersave_words);

static const char *const mac_policy_words[] = { "permanent", "per_network", "per_connection" };
static const ncfg_enum_t mac_policy_set = WORD_SET("mac policy", mac_policy_words);

static const char *const on_unmanage_words[] = { "leave", "clear" };
static const ncfg_enum_t on_unmanage_set = WORD_SET("unmanage policy", on_unmanage_words);

static const char *const acl_policy_words[] = { "deny", "allow" };
static const ncfg_enum_t acl_policy_set = WORD_SET("access control policy", acl_policy_words);

static const char *const requires_words[] = { "route", "probe", "address" };
static const ncfg_enum_t requires_set = WORD_SET("connectivity requirement", requires_words);

static const char *const networking_words[] = { "on", "off" };
static const ncfg_enum_t networking_set = WORD_SET("networking setting", networking_words);

static const char *const cert_source_words[] = { "path", "stored" };
static const char *const principal_words[] = { "root", "any", "user", "group" };
static const char *const hostname_policy_words[] = { "none", "from_dhcp", "static" };
static const char *const ra_backend_words[] = { "auto", "odhcpd", "radvd", "exec" };

const char *ncfg_address_source_kind_name(int kind)
{
	return ncfg_field_enum_name(&address_source_set, kind);
}

const char *ncfg_interface_kind_name(int kind)
{
	return ncfg_field_enum_name(&interface_kind_set, kind);
}

/*
 * The word a tunnel encapsulation goes on the wire as.
 *
 * **The document's spelling and the kernel's are the same word**, deliberately
 * rather than by luck: `TunnelKind::name` in the Rust is documented as "the
 * kernel's name for this link kind" and serde's `snake_case` of the variant
 * produces the identical string, so the model holds one table and the executor
 * reads it. A second list here -- or in `src/apply/` -- is how a `gretap`
 * comes to mean one thing on the way out and another on the way back in, which
 * is what `ops.h` refuses to have happen to a mode number.
 *
 * NULL outside the set, `value.h`'s convention.
 */
const char *ncfg_tunnel_kind_name(int kind)
{
	return ncfg_field_enum_name(&tunnel_kind_set, kind);
}

/*
 * The number the kernel wants in `IFLA_BOND_MODE`.
 *
 * `ncfg_bond_mode_t`'s order **is** the kernel's numbering -- `src/observe/
 * build.c` already reads a kernel mode back by indexing `bond_mode_words` with
 * it -- so this is that fact written down once and bounded, not a second
 * table. -1 for a value outside the set, which is a mode this build has no
 * word for and must not send as some other mode.
 */
int ncfg_bond_mode_number(int mode)
{
	if (!ncfg_field_enum_name(&bond_mode_set, mode)) {
		return -1;
	}
	return mode;
}

/*
 * The number the kernel wants in `IFLA_MACVLAN_MODE`.
 *
 * **Flags, not an enumeration**: the kernel numbers the modes 1, 2, 4, 8 and
 * 16 and its validator refuses anything else, so 0 for the first mode and 3
 * for the fourth are `EINVAL` rather than a mode nobody meant. The document's
 * order is private, vepa, bridge, passthru, which is the same order, so the
 * mapping is a shift -- and 16, the `source` mode netcfgd cannot express, is
 * outside the set and answers -1 here as it reads back as no mode at all in
 * `src/observe/build.c`.
 */
int ncfg_macvlan_mode_number(int mode)
{
	if (!ncfg_field_enum_name(&macvlan_mode_set, mode)) {
		return -1;
	}
	return 1 << mode;
}

/*
 * The ethertype the kernel wants in `IFLA_VLAN_PROTOCOL`.
 *
 * **Not an ordinal and not a flag bit**, unlike the two above: it is the
 * ethertype an 802.1Q or an 802.1ad tag carries, which the kernel reads
 * big-endian and refuses at any other value -- so there is nothing here to
 * derive and the two numbers are written out.
 *
 * No `default:`, which is `apply.c`'s rule and for its reason: a protocol
 * added to the enum makes this fail to compile rather than quietly answering
 * -1 for a tag the document can express. -1 for a value outside the set, which
 * is `ncfg_bond_mode_number`'s convention and means a protocol this build must
 * not send as some other protocol.
 */
int ncfg_vlan_protocol_ethertype(int protocol)
{
	switch ((ncfg_vlan_protocol_t)protocol) {
	case NCFG_VLAN_PROTOCOL_DOT1Q:
		return 0x8100;
	case NCFG_VLAN_PROTOCOL_DOT1AD:
		return 0x88a8;
	}
	return -1;
}

/*
 * The kernel's own feature names, per offload field.
 *
 * **One table, in the model, for the two modules that must agree on it.** It
 * lived privately in `src/plan/offload.c` while the planner was the only
 * caller, above a comment saying the second caller takes this one rather than
 * writing its own; `src/observe/offloads.c` is that caller, and this is the
 * move that comment asked for rather than the copy it refused. `interface.rs`
 * keeps it in the model in the Rust for the same reason and says so: the
 * planner needs it and the planner is pure.
 *
 * `static const char *const` per field rather than one flattened array with
 * offsets, so that the length of each is the array's own and cannot be got
 * wrong by a second constant.
 */
static const char *const offload_gro[] = { "rx-gro" };
static const char *const offload_gso[] = { "tx-generic-segmentation" };
static const char *const offload_tso[] = { "tx-tcp-segmentation" };
static const char *const offload_rx_checksum[] = { "rx-checksum" };
static const char *const offload_tx_checksum[] = { "tx-checksum-ip-generic",
	"tx-checksum-ipv4", "tx-checksum-ipv6" };

#define OFFLOAD_NAMES(array) \
	do { \
		*count = sizeof(array) / sizeof((array)[0]); \
		return array; \
	} while (0)

/*
 * No `default:`, which is `apply.c`'s rule and for its reason: a field added
 * to the enum makes this fail to compile rather than quietly answering "no
 * names", which downstream reads as an offload nobody manages.
 */
const char *const *ncfg_offload_field_names(int field, size_t *count)
{
	size_t ignored = 0;

	if (!count) {
		count = &ignored;
	}
	*count = 0;
	switch ((ncfg_offload_field_t)field) {
	case NCFG_OFFLOAD_GRO:
		OFFLOAD_NAMES(offload_gro);
	case NCFG_OFFLOAD_GSO:
		OFFLOAD_NAMES(offload_gso);
	case NCFG_OFFLOAD_TSO:
		OFFLOAD_NAMES(offload_tso);
	case NCFG_OFFLOAD_RX_CHECKSUM:
		OFFLOAD_NAMES(offload_rx_checksum);
	case NCFG_OFFLOAD_TX_CHECKSUM:
		OFFLOAD_NAMES(offload_tx_checksum);
	}
	return NULL;
}

/* The member of the `ethtool` block one field names. Absent settings are
 * `NCFG_TOGGLE_UNMANAGED`, which is what the whole block being absent means
 * too. */
int ncfg_link_settings_offload(const ncfg_link_settings_t *settings, int field)
{
	if (!settings) {
		return NCFG_TOGGLE_UNMANAGED;
	}
	switch ((ncfg_offload_field_t)field) {
	case NCFG_OFFLOAD_GRO:
		return settings->gro;
	case NCFG_OFFLOAD_GSO:
		return settings->gso;
	case NCFG_OFFLOAD_TSO:
		return settings->tso;
	case NCFG_OFFLOAD_RX_CHECKSUM:
		return settings->rx_checksum;
	case NCFG_OFFLOAD_TX_CHECKSUM:
		return settings->tx_checksum;
	}
	return NCFG_TOGGLE_UNMANAGED;
}

/*
 * Whether at most one of this kind may appear on one interface.
 *
 * Two DHCP clients on one link is always a bug, so it is refused at compile
 * time rather than raced at runtime. Any number of `static` and `delegated`
 * entries is legitimate: the list is a composition, not a set of alternatives.
 */
int ncfg_address_source_is_singleton(int kind)
{
	switch (kind) {
	case NCFG_ADDRESS_SOURCE_DHCP4:
	case NCFG_ADDRESS_SOURCE_DHCP6:
	case NCFG_ADDRESS_SOURCE_SLAAC:
	case NCFG_ADDRESS_SOURCE_LINK_LOCAL:
	case NCFG_ADDRESS_SOURCE_REPORTED:
		return 1;
	default:
		return 0;
	}
}

int ncfg_dns_mode_can_route(int mode)
{
	switch (mode) {
	case NCFG_DNS_MODE_NONE:
	case NCFG_DNS_MODE_WRITE_RESOLV_CONF:
	case NCFG_DNS_MODE_RESOLVCONF:
		return 0;
	default:
		return 1;
	}
}

int ncfg_dns_policy_needs_routing(const ncfg_dns_policy_t *policy)
{
	return policy && policy->domain_count != 0;
}

const char *const ncfg_connectivity_default_ignore[] = { "docker*", "br-*", "veth*", "virbr*",
	"vnet*" };
const size_t ncfg_connectivity_default_ignore_count =
    COUNT_OF(ncfg_connectivity_default_ignore);

/* ------------------------------------------------------------------------ *
 * An address that is an address, and never a prefix
 *
 * The Rust holds these as `IpAddr`, so a document naming `192.0.2.1/24` as a
 * next hop is refused by the parse rather than by a later check, and what is
 * written back is the address re-rendered. That re-rendering is the point:
 * `value.h`'s `ncfg_address_canonical` records what it cost when it was
 * missing -- a rule written `2001:0DB8::/32` was torn down and reinstalled on
 * every apply, for ever, because the comparison against what the kernel
 * reports is a string comparison.
 * ------------------------------------------------------------------------ */

static int address_text_read(const ncfg_json_doc_t *doc, uint32_t node, void *field, char *err,
    size_t err_size)
{
	char         **slot = field;
	ncfg_address_t address;
	char           rendered[NCFG_ADDRESS_MAX];
	char          *text = ncfg_field_string(doc, node, "an address", err, err_size);

	if (!text) {
		return 0;
	}
	if (!ncfg_address_parse(text, &address, err, err_size)) {
		free(text);
		return 0;
	}
	if (address.has_prefix) {
		ncfg_error_set(err, err_size, "`%s` carries a prefix length, and this is an address",
		    text);
		free(text);
		return 0;
	}
	free(text);
	if (!ncfg_address_render(&address, rendered, sizeof(rendered), err, err_size)) {
		return 0;
	}
	free(*slot);
	*slot = malloc(strlen(rendered) + 1u);
	if (!*slot) {
		ncfg_error_set(err, err_size, "out of memory reading an address");
		return 0;
	}
	memcpy(*slot, rendered, strlen(rendered) + 1u);
	return 1;
}

static void address_text_write(ncfg_json_writer_t *writer, const void *field)
{
	char *const *slot = field;

	ncfg_json_write_string(writer, *slot);
}

static int address_text_omit(const void *field)
{
	char *const *slot = field;

	return *slot == NULL;
}

static void address_text_release(void *field)
{
	char **slot = field;

	free(*slot);
	*slot = NULL;
}

static const ncfg_custom_t address_text = { address_text_read, address_text_write,
	address_text_omit, address_text_release, NULL };

/* ------------------------------------------------------------------------ *
 * The leaves
 * ------------------------------------------------------------------------ */

static const ncfg_field_t version_fields[] = {
	{ .name = "major", .kind = NCFG_F_INT, .flags = NCFG_FF_REQUIRED, R_U16,
	    .offset = offsetof(ncfg_version_t, major) },
	{ .name = "minor", .kind = NCFG_F_INT, .flags = NCFG_FF_REQUIRED, R_U16,
	    .offset = offsetof(ncfg_version_t, minor) }
};
static const ncfg_type_t version_type = TYPE("schema version", version_fields);

static const ncfg_field_t secret_ref_fields[] = {
	{ .name = "provider", .kind = NCFG_F_ENUM, .choices = &secret_provider_set,
	    .fallback = NCFG_SECRET_PROVIDER_FILE, .offset = offsetof(ncfg_secret_ref_t, provider) },
	{ .name = "name", .kind = NCFG_F_STR, .flags = NCFG_FF_REQUIRED,
	    .offset = offsetof(ncfg_secret_ref_t, name) }
};
static const ncfg_type_t secret_ref_type = TYPE("secret reference", secret_ref_fields);

static const ncfg_field_t prefix_ref_fields[] = {
	{ .name = "source", .kind = NCFG_F_STR, .flags = NCFG_FF_REQUIRED,
	    .offset = offsetof(ncfg_prefix_ref_t, source) },
	{ .name = "index", .kind = NCFG_F_INT, R_U8, .offset = offsetof(ncfg_prefix_ref_t, index) },
	{ .name = "subnet", .kind = NCFG_F_INT, R_U16,
	    .offset = offsetof(ncfg_prefix_ref_t, subnet) }
};
static const ncfg_type_t prefix_ref_type = TYPE("prefix reference", prefix_ref_fields);

/* ------------------------------------------------------------------------ *
 * Addressing sources, and the tag that chooses between them
 * ------------------------------------------------------------------------ */

static const ncfg_field_t static_fields[] = {
	{ .name = "address", .kind = NCFG_F_STR, .flags = NCFG_FF_REQUIRED,
	    .offset = offsetof(ncfg_static_t, address) },
	{ .name = "peer", .kind = NCFG_F_STR, .offset = offsetof(ncfg_static_t, peer) },
	{ .name = "preferred_lifetime", .kind = NCFG_F_OPT_INT, R_U32,
	    .offset = offsetof(ncfg_static_t, preferred_lifetime) },
	{ .name = "valid_lifetime", .kind = NCFG_F_OPT_INT, R_U32,
	    .offset = offsetof(ncfg_static_t, valid_lifetime) }
};
static const ncfg_type_t static_type = TAGGED("static address", static_fields, "source");

static const ncfg_field_t delegated_fields[] = {
	{ .name = "prefix", .kind = NCFG_F_STRUCT, .flags = NCFG_FF_REQUIRED,
	    .type = &prefix_ref_type, .offset = offsetof(ncfg_delegated_t, prefix) },
	{ .name = "suffix", .kind = NCFG_F_STR, .flags = NCFG_FF_REQUIRED,
	    .offset = offsetof(ncfg_delegated_t, suffix) }
};
static const ncfg_type_t delegated_type = TAGGED("delegated address", delegated_fields, "source");

static const ncfg_field_t pd_request_fields[] = {
	{ .name = "hint", .kind = NCFG_F_STR, .offset = offsetof(ncfg_pd_request_t, hint) },
	{ .name = "length", .kind = NCFG_F_OPT_INT, R_U8,
	    .offset = offsetof(ncfg_pd_request_t, length) }
};
static const ncfg_type_t pd_request_type = TYPE("prefix delegation request", pd_request_fields);

static const ncfg_field_t dhcp4_fields[] = {
	{ .name = "hostname_mode", .kind = NCFG_F_ENUM, .choices = &hostname_mode_set,
	    .fallback = NCFG_HOSTNAME_MODE_NONE, .offset = offsetof(ncfg_dhcp4_t, hostname_mode) },
	{ .name = "client_id", .kind = NCFG_F_STR, .offset = offsetof(ncfg_dhcp4_t, client_id) },
	{ .name = "metric", .kind = NCFG_F_OPT_INT, R_U32, .offset = offsetof(ncfg_dhcp4_t, metric) },
	{ .name = "request_options", .kind = NCFG_F_INT_LIST, R_U8,
	    .offset = offsetof(ncfg_dhcp4_t, request_options),
	    .count_offset = offsetof(ncfg_dhcp4_t, request_option_count) },
	{ .name = "backend", .kind = NCFG_F_ENUM, .choices = &dhcp4_backend_set,
	    .fallback = NCFG_DHCP4_BACKEND_AUTO, .offset = offsetof(ncfg_dhcp4_t, backend) }
};
static const ncfg_type_t dhcp4_type = TAGGED("dhcp4 lease", dhcp4_fields, "source");

static const ncfg_field_t dhcp6_fields[] = {
	{ .name = "mode", .kind = NCFG_F_ENUM, .choices = &dhcp6_mode_set,
	    .fallback = NCFG_DHCP6_MODE_MANAGED, .offset = offsetof(ncfg_dhcp6_t, mode) },
	{ .name = "rapid_commit", .kind = NCFG_F_BOOL,
	    .offset = offsetof(ncfg_dhcp6_t, rapid_commit) },
	{ .name = "prefix_delegation", .kind = NCFG_F_OPT_STRUCT, .type = &pd_request_type,
	    .element_size = sizeof(ncfg_pd_request_t),
	    .offset = offsetof(ncfg_dhcp6_t, prefix_delegation) }
};
static const ncfg_type_t dhcp6_type = TAGGED("dhcp6 lease", dhcp6_fields, "source");

static const ncfg_field_t slaac_fields[] = {
	{ .name = "privacy", .kind = NCFG_F_ENUM, .choices = &slaac_privacy_set,
	    .fallback = NCFG_SLAAC_PRIVACY_NONE, .offset = offsetof(ncfg_slaac_t, privacy) }
};
static const ncfg_type_t slaac_type = TAGGED("slaac", slaac_fields, "source");

/* Two variants with nothing inside them, and a table each so that a member
 * added to one of them is still refused by name. */
static const ncfg_type_t link_local_type = { "link-local addressing", NULL, 0, "source" };
static const ncfg_type_t reported_type = { "reported addressing", NULL, 0, "source" };

static int address_source_read(const ncfg_json_doc_t *doc, uint32_t node, void *field,
    char *err, size_t err_size)
{
	ncfg_address_source_t *source = field;
	uint32_t               tag;
	int                    kind = 0;
	const ncfg_type_t     *type;
	void                  *payload;

	if (ncfg_json_type(doc, node) != NCFG_JSON_OBJECT) {
		ncfg_error_set(err, err_size, "an addressing source is an object, and this is not one");
		return 0;
	}
	tag = ncfg_json_member(doc, node, "source");
	if (tag == NCFG_JSON_NONE) {
		ncfg_error_set(err, err_size, "an addressing source has no `source`");
		return 0;
	}
	if (!ncfg_field_enum(&address_source_set, doc, tag, &kind, err, err_size)) {
		return 0;
	}
	source->kind = kind;
	switch (kind) {
	case NCFG_ADDRESS_SOURCE_STATIC:
		type = &static_type;
		payload = &source->static_address;
		break;
	case NCFG_ADDRESS_SOURCE_DELEGATED:
		type = &delegated_type;
		payload = &source->delegated;
		break;
	case NCFG_ADDRESS_SOURCE_DHCP4:
		type = &dhcp4_type;
		payload = &source->dhcp4;
		break;
	case NCFG_ADDRESS_SOURCE_DHCP6:
		type = &dhcp6_type;
		payload = &source->dhcp6;
		break;
	case NCFG_ADDRESS_SOURCE_SLAAC:
		type = &slaac_type;
		payload = &source->slaac;
		break;
	case NCFG_ADDRESS_SOURCE_LINK_LOCAL:
		type = &link_local_type;
		payload = &source->kind;
		break;
	default:
		type = &reported_type;
		payload = &source->kind;
		break;
	}
	if (!ncfg_type_init(type, payload)) {
		ncfg_error_set(err, err_size, "out of memory reading an addressing source");
		return 0;
	}
	return ncfg_type_read(type, doc, node, payload, err, err_size);
}

static void address_source_write(ncfg_json_writer_t *writer, const void *field)
{
	const ncfg_address_source_t *source = field;
	const char                  *word = ncfg_field_enum_name(&address_source_set, source->kind);

	ncfg_json_write_object_begin(writer);
	if (word) {
		ncfg_json_write_member_string(writer, "source", word);
	}
	switch (source->kind) {
	case NCFG_ADDRESS_SOURCE_STATIC:
		ncfg_type_write(&static_type, writer, &source->static_address);
		break;
	case NCFG_ADDRESS_SOURCE_DELEGATED:
		ncfg_type_write(&delegated_type, writer, &source->delegated);
		break;
	case NCFG_ADDRESS_SOURCE_DHCP4:
		ncfg_type_write(&dhcp4_type, writer, &source->dhcp4);
		break;
	case NCFG_ADDRESS_SOURCE_DHCP6:
		ncfg_type_write(&dhcp6_type, writer, &source->dhcp6);
		break;
	case NCFG_ADDRESS_SOURCE_SLAAC:
		ncfg_type_write(&slaac_type, writer, &source->slaac);
		break;
	default:
		break;
	}
	ncfg_json_write_object_end(writer);
}

/*
 * Freed without consulting the tag, which is the whole reason the arms are a
 * struct rather than a union: an arm added to the enum and missed here would
 * be a leak nothing reports, and the arms that were never read are zeroed.
 */
static void address_source_release(void *field)
{
	ncfg_address_source_t *source = field;

	ncfg_type_free(&static_type, &source->static_address);
	ncfg_type_free(&delegated_type, &source->delegated);
	ncfg_type_free(&dhcp4_type, &source->dhcp4);
	ncfg_type_free(&dhcp6_type, &source->dhcp6);
	ncfg_type_free(&slaac_type, &source->slaac);
}

static const ncfg_custom_t address_source_custom = { address_source_read, address_source_write,
	NULL, address_source_release, NULL };

/* ------------------------------------------------------------------------ *
 * Routes, hooks, DNS
 * ------------------------------------------------------------------------ */

static const ncfg_field_t route_fields[] = {
	{ .name = "destination", .kind = NCFG_F_STR, .flags = NCFG_FF_REQUIRED,
	    .offset = offsetof(ncfg_route_t, destination) },
	{ .name = "via", .kind = NCFG_F_CUSTOM, .custom = &address_text,
	    .offset = offsetof(ncfg_route_t, via) },
	{ .name = "metric", .kind = NCFG_F_OPT_INT, R_U32, .offset = offsetof(ncfg_route_t, metric) },
	{ .name = "table", .kind = NCFG_F_OPT_INT, R_U32, .offset = offsetof(ncfg_route_t, table) },
	{ .name = "src", .kind = NCFG_F_CUSTOM, .custom = &address_text,
	    .offset = offsetof(ncfg_route_t, src) },
	{ .name = "scope", .kind = NCFG_F_OPT_ENUM, .choices = &route_scope_set,
	    .offset = offsetof(ncfg_route_t, scope) },
	{ .name = "onlink", .kind = NCFG_F_BOOL, .offset = offsetof(ncfg_route_t, onlink) },
	{ .name = "proto", .kind = NCFG_F_OPT_INT, R_U8, .offset = offsetof(ncfg_route_t, proto) }
};
static const ncfg_type_t route_type = TYPE("route", route_fields);

static const ncfg_field_t hook_fields[] = {
	{ .name = "phase", .kind = NCFG_F_ENUM, .flags = NCFG_FF_REQUIRED, .choices = &hook_phase_set,
	    .offset = offsetof(ncfg_hook_ref_t, phase) },
	{ .name = "path", .kind = NCFG_F_STR, .flags = NCFG_FF_REQUIRED,
	    .offset = offsetof(ncfg_hook_ref_t, path) },
	{ .name = "sha256", .kind = NCFG_F_STR, .flags = NCFG_FF_REQUIRED,
	    .offset = offsetof(ncfg_hook_ref_t, sha256) },
	{ .name = "run_as", .kind = NCFG_F_STR, .offset = offsetof(ncfg_hook_ref_t, run_as) },
	{ .name = "timeout", .kind = NCFG_F_OPT_INT, R_U32,
	    .offset = offsetof(ncfg_hook_ref_t, timeout) }
};
static const ncfg_type_t hook_type = TYPE("hook", hook_fields);

/*
 * The mode, which is a word except for the one variant that carries a command.
 *
 * `exec` is a mode the model has and the configuration language cannot yet
 * write -- `lower.rs` has no arm for the word -- but a document arriving as
 * JSON carries it, so this reads and writes it.
 */
static int dns_mode_read(const ncfg_json_doc_t *doc, uint32_t node, void *field, char *err,
    size_t err_size)
{
	ncfg_dns_mode_value_t *value = field;
	uint32_t               only;

	if (ncfg_json_type(doc, node) == NCFG_JSON_STRING) {
		return ncfg_field_enum(&dns_mode_set, doc, node, &value->mode, err, err_size);
	}
	only = ncfg_field_only_member(doc, node);
	if (only == NCFG_JSON_NONE || ncfg_json_member(doc, node, "exec") != only) {
		ncfg_error_set(err, err_size,
		    "a dns mode is a word, or `{\"exec\": \"...\"}` for the one that runs a script");
		return 0;
	}
	value->mode = NCFG_DNS_MODE_EXEC;
	free(value->command);
	value->command = ncfg_field_string(doc, only, "the command of dns mode `exec`", err,
	    err_size);
	return value->command != NULL;
}

static void dns_mode_write(ncfg_json_writer_t *writer, const void *field)
{
	const ncfg_dns_mode_value_t *value = field;
	const char                  *word = ncfg_field_enum_name(&dns_mode_set, value->mode);

	if (value->mode == NCFG_DNS_MODE_EXEC) {
		ncfg_json_write_object_begin(writer);
		ncfg_json_write_member_string(writer, "exec", value->command);
		ncfg_json_write_object_end(writer);
		return;
	}
	if (word) {
		ncfg_json_write_string(writer, word);
	}
}

static void dns_mode_release(void *field)
{
	ncfg_dns_mode_value_t *value = field;

	free(value->command);
	value->command = NULL;
}

static const ncfg_custom_t dns_mode_custom = { dns_mode_read, dns_mode_write, NULL,
	dns_mode_release, NULL };

static const ncfg_field_t dns_server_fields[] = {
	{ .name = "addr", .kind = NCFG_F_CUSTOM, .flags = NCFG_FF_REQUIRED, .custom = &address_text,
	    .offset = offsetof(ncfg_dns_server_t, addr) },
	{ .name = "port", .kind = NCFG_F_OPT_INT, R_U16,
	    .offset = offsetof(ncfg_dns_server_t, port) },
	{ .name = "sni", .kind = NCFG_F_STR, .offset = offsetof(ncfg_dns_server_t, sni) }
};
static const ncfg_type_t dns_server_type = TYPE("dns server", dns_server_fields);

static const ncfg_field_t routing_domain_fields[] = {
	{ .name = "suffix", .kind = NCFG_F_STR, .flags = NCFG_FF_REQUIRED,
	    .offset = offsetof(ncfg_routing_domain_t, suffix) },
	{ .name = "exclusive", .kind = NCFG_F_BOOL,
	    .offset = offsetof(ncfg_routing_domain_t, exclusive) }
};
static const ncfg_type_t routing_domain_type = TYPE("routing domain", routing_domain_fields);

static const ncfg_field_t dns_policy_fields[] = {
	{ .name = "mode", .kind = NCFG_F_CUSTOM, .custom = &dns_mode_custom,
	    .offset = offsetof(ncfg_dns_policy_t, mode) },
	{ .name = "servers", .kind = NCFG_F_LIST, .type = &dns_server_type,
	    .element_size = sizeof(ncfg_dns_server_t),
	    .offset = offsetof(ncfg_dns_policy_t, servers),
	    .count_offset = offsetof(ncfg_dns_policy_t, server_count) },
	{ .name = "search", .kind = NCFG_F_STR_LIST, .offset = offsetof(ncfg_dns_policy_t, search),
	    .count_offset = offsetof(ncfg_dns_policy_t, search_count) },
	{ .name = "domains", .kind = NCFG_F_LIST, .type = &routing_domain_type,
	    .element_size = sizeof(ncfg_routing_domain_t),
	    .offset = offsetof(ncfg_dns_policy_t, domains),
	    .count_offset = offsetof(ncfg_dns_policy_t, domain_count) },
	{ .name = "options", .kind = NCFG_F_STR_LIST, .offset = offsetof(ncfg_dns_policy_t, options),
	    .count_offset = offsetof(ncfg_dns_policy_t, option_count) },
	{ .name = "dnssec", .kind = NCFG_F_OPT_ENUM, .choices = &dnssec_set,
	    .offset = offsetof(ncfg_dns_policy_t, dnssec) },
	{ .name = "transport", .kind = NCFG_F_OPT_ENUM, .choices = &dns_transport_set,
	    .offset = offsetof(ncfg_dns_policy_t, transport) }
};
static const ncfg_type_t dns_policy_type = TYPE("dns policy", dns_policy_fields);

/* ------------------------------------------------------------------------ *
 * Security
 * ------------------------------------------------------------------------ */

static int cert_source_read(const ncfg_json_doc_t *doc, uint32_t node, void *field, char *err,
    size_t err_size)
{
	ncfg_cert_source_t *source = field;
	uint32_t            only = ncfg_field_only_member(doc, node);

	if (only != NCFG_JSON_NONE && ncfg_json_member(doc, node, "path") == only) {
		source->has = 1;
		source->kind = NCFG_CERT_SOURCE_PATH;
		free(source->path);
		source->path = ncfg_field_string(doc, only, "a certificate path", err, err_size);
		return source->path != NULL;
	}
	if (only != NCFG_JSON_NONE && ncfg_json_member(doc, node, "stored") == only) {
		source->has = 1;
		source->kind = NCFG_CERT_SOURCE_STORED;
		if (!ncfg_type_init(&secret_ref_type, &source->stored)) {
			ncfg_error_set(err, err_size, "out of memory reading stored certificate material");
			return 0;
		}
		return ncfg_type_read(&secret_ref_type, doc, only, &source->stored, err, err_size);
	}
	ncfg_error_set(err, err_size,
	    "certificate material is `{\"%s\": ...}` or `{\"%s\": ...}` and this is neither",
	    cert_source_words[0], cert_source_words[1]);
	return 0;
}

static void cert_source_write(ncfg_json_writer_t *writer, const void *field)
{
	const ncfg_cert_source_t *source = field;

	ncfg_json_write_object_begin(writer);
	if (source->kind == NCFG_CERT_SOURCE_PATH) {
		ncfg_json_write_member_string(writer, cert_source_words[0], source->path);
	} else {
		ncfg_json_write_key(writer, cert_source_words[1]);
		ncfg_json_write_object_begin(writer);
		ncfg_type_write(&secret_ref_type, writer, &source->stored);
		ncfg_json_write_object_end(writer);
	}
	ncfg_json_write_object_end(writer);
}

static int cert_source_omit(const void *field)
{
	const ncfg_cert_source_t *source = field;

	return !source->has;
}

static void cert_source_release(void *field)
{
	ncfg_cert_source_t *source = field;

	free(source->path);
	source->path = NULL;
	ncfg_type_free(&secret_ref_type, &source->stored);
	source->has = 0;
}

static const ncfg_custom_t cert_source_custom = { cert_source_read, cert_source_write,
	cert_source_omit, cert_source_release, NULL };

static const ncfg_field_t eap_fields[] = {
	{ .name = "method", .kind = NCFG_F_ENUM, .flags = NCFG_FF_REQUIRED, .choices = &eap_method_set,
	    .offset = offsetof(ncfg_eap_config_t, method) },
	{ .name = "identity", .kind = NCFG_F_STR, .flags = NCFG_FF_REQUIRED,
	    .offset = offsetof(ncfg_eap_config_t, identity) },
	{ .name = "anonymous_identity", .kind = NCFG_F_STR,
	    .offset = offsetof(ncfg_eap_config_t, anonymous_identity) },
	{ .name = "password", .kind = NCFG_F_OPT_STRUCT, .type = &secret_ref_type,
	    .element_size = sizeof(ncfg_secret_ref_t),
	    .offset = offsetof(ncfg_eap_config_t, password) },
	{ .name = "domain_suffix_match", .kind = NCFG_F_STR,
	    .offset = offsetof(ncfg_eap_config_t, domain_suffix_match) },
	{ .name = "ca_cert", .kind = NCFG_F_CUSTOM, .custom = &cert_source_custom,
	    .offset = offsetof(ncfg_eap_config_t, ca_cert) },
	{ .name = "client_cert", .kind = NCFG_F_CUSTOM, .custom = &cert_source_custom,
	    .offset = offsetof(ncfg_eap_config_t, client_cert) },
	{ .name = "private_key", .kind = NCFG_F_CUSTOM, .custom = &cert_source_custom,
	    .offset = offsetof(ncfg_eap_config_t, private_key) },
	{ .name = "phase2", .kind = NCFG_F_STR, .offset = offsetof(ncfg_eap_config_t, phase2) }
};
static const ncfg_type_t eap_type = TYPE("802.1X configuration", eap_fields);
static const ncfg_type_t eap_security_type = TAGGED("eap network", eap_fields, "type");

static const ncfg_field_t psk_fields[] = {
	{ .name = "passphrase", .kind = NCFG_F_STRUCT, .flags = NCFG_FF_REQUIRED,
	    .type = &secret_ref_type, .offset = offsetof(ncfg_psk_config_t, passphrase) },
	{ .name = "proto", .kind = NCFG_F_ENUM, .choices = &psk_proto_set,
	    .fallback = NCFG_PSK_PROTO_WPA2_WPA3, .offset = offsetof(ncfg_psk_config_t, proto) }
};
static const ncfg_type_t psk_type = TAGGED("psk network", psk_fields, "type");

static const ncfg_type_t open_security_type = { "open network", NULL, 0, "type" };
static const ncfg_type_t owe_security_type = { "owe network", NULL, 0, "type" };

static int security_read(const ncfg_json_doc_t *doc, uint32_t node, void *field, char *err,
    size_t err_size)
{
	ncfg_security_t   *security = field;
	uint32_t           tag;
	int                kind = 0;
	const ncfg_type_t *type;
	void              *payload;

	if (ncfg_json_type(doc, node) != NCFG_JSON_OBJECT) {
		ncfg_error_set(err, err_size, "a security choice is an object, and this is not one");
		return 0;
	}
	tag = ncfg_json_member(doc, node, "type");
	if (tag == NCFG_JSON_NONE) {
		ncfg_error_set(err, err_size, "a security choice has no `type`");
		return 0;
	}
	if (!ncfg_field_enum(&security_set, doc, tag, &kind, err, err_size)) {
		return 0;
	}
	security->kind = kind;
	switch (kind) {
	case NCFG_SECURITY_PSK:
		type = &psk_type;
		payload = &security->psk;
		break;
	case NCFG_SECURITY_EAP:
		type = &eap_security_type;
		payload = &security->eap;
		break;
	case NCFG_SECURITY_OWE:
		type = &owe_security_type;
		payload = &security->kind;
		break;
	default:
		type = &open_security_type;
		payload = &security->kind;
		break;
	}
	if (!ncfg_type_init(type, payload)) {
		ncfg_error_set(err, err_size, "out of memory reading a security choice");
		return 0;
	}
	return ncfg_type_read(type, doc, node, payload, err, err_size);
}

static void security_write(ncfg_json_writer_t *writer, const void *field)
{
	const ncfg_security_t *security = field;
	const char            *word = ncfg_field_enum_name(&security_set, security->kind);

	ncfg_json_write_object_begin(writer);
	if (word) {
		ncfg_json_write_member_string(writer, "type", word);
	}
	if (security->kind == NCFG_SECURITY_PSK) {
		ncfg_type_write(&psk_type, writer, &security->psk);
	} else if (security->kind == NCFG_SECURITY_EAP) {
		ncfg_type_write(&eap_security_type, writer, &security->eap);
	}
	ncfg_json_write_object_end(writer);
}

static void security_release(void *field)
{
	ncfg_security_t *security = field;

	ncfg_type_free(&psk_type, &security->psk);
	ncfg_type_free(&eap_security_type, &security->eap);
}

static const ncfg_custom_t security_custom = { security_read, security_write, NULL,
	security_release, NULL };

/* ------------------------------------------------------------------------ *
 * Link kinds
 * ------------------------------------------------------------------------ */

static const ncfg_field_t bridge_fields[] = {
	{ .name = "members", .kind = NCFG_F_STR_LIST,
	    .offset = offsetof(ncfg_bridge_config_t, members),
	    .count_offset = offsetof(ncfg_bridge_config_t, member_count) },
	{ .name = "stp", .kind = NCFG_F_BOOL, .offset = offsetof(ncfg_bridge_config_t, stp) },
	{ .name = "forward_delay", .kind = NCFG_F_OPT_INT, R_U32,
	    .offset = offsetof(ncfg_bridge_config_t, forward_delay) },
	{ .name = "hello_time", .kind = NCFG_F_OPT_INT, R_U32,
	    .offset = offsetof(ncfg_bridge_config_t, hello_time) },
	{ .name = "ageing_time", .kind = NCFG_F_OPT_INT, R_U32,
	    .offset = offsetof(ncfg_bridge_config_t, ageing_time) },
	{ .name = "priority", .kind = NCFG_F_OPT_INT, R_U16,
	    .offset = offsetof(ncfg_bridge_config_t, priority) },
	{ .name = "vlan_filtering", .kind = NCFG_F_BOOL,
	    .offset = offsetof(ncfg_bridge_config_t, vlan_filtering) }
};
static const ncfg_type_t bridge_type = TAGGED("bridge", bridge_fields, "kind");

static const ncfg_field_t bond_fields[] = {
	{ .name = "members", .kind = NCFG_F_STR_LIST, .flags = NCFG_FF_REQUIRED,
	    .offset = offsetof(ncfg_bond_config_t, members),
	    .count_offset = offsetof(ncfg_bond_config_t, member_count) },
	{ .name = "mode", .kind = NCFG_F_ENUM, .choices = &bond_mode_set,
	    .fallback = NCFG_BOND_MODE_ACTIVE_BACKUP, .offset = offsetof(ncfg_bond_config_t, mode) },
	{ .name = "miimon", .kind = NCFG_F_OPT_INT, R_U32,
	    .offset = offsetof(ncfg_bond_config_t, miimon) }
};
static const ncfg_type_t bond_type = TAGGED("bond", bond_fields, "kind");

static const ncfg_field_t vlan_fields[] = {
	{ .name = "parent", .kind = NCFG_F_STR, .flags = NCFG_FF_REQUIRED,
	    .offset = offsetof(ncfg_vlan_config_t, parent) },
	{ .name = "id", .kind = NCFG_F_INT, .flags = NCFG_FF_REQUIRED, R_U16,
	    .offset = offsetof(ncfg_vlan_config_t, id) },
	{ .name = "protocol", .kind = NCFG_F_ENUM, .choices = &vlan_protocol_set,
	    .fallback = NCFG_VLAN_PROTOCOL_DOT1Q,
	    .offset = offsetof(ncfg_vlan_config_t, protocol) }
};
static const ncfg_type_t vlan_type = TAGGED("vlan", vlan_fields, "kind");

static const ncfg_field_t vxlan_fields[] = {
	{ .name = "id", .kind = NCFG_F_INT, .flags = NCFG_FF_REQUIRED, R_U32,
	    .offset = offsetof(ncfg_vxlan_config_t, id) },
	{ .name = "parent", .kind = NCFG_F_STR, .offset = offsetof(ncfg_vxlan_config_t, parent) },
	{ .name = "local", .kind = NCFG_F_CUSTOM, .custom = &address_text,
	    .offset = offsetof(ncfg_vxlan_config_t, local) },
	{ .name = "remote", .kind = NCFG_F_CUSTOM, .custom = &address_text,
	    .offset = offsetof(ncfg_vxlan_config_t, remote) },
	{ .name = "port", .kind = NCFG_F_OPT_INT, R_U16,
	    .offset = offsetof(ncfg_vxlan_config_t, port) }
};
static const ncfg_type_t vxlan_type = TAGGED("vxlan", vxlan_fields, "kind");

/*
 * A Curve25519 key, held as octets and written back as base64.
 *
 * `key.rs` keeps the octets rather than the text because base64 has more than
 * one spelling of one key -- the final character carries four significant bits
 * -- and two spellings have to compare equal for a plan to tell "unchanged"
 * from "different". No base64 dependency: a fixed-length codec is thirty lines.
 */
static const char base64_alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int base64_value(char digit, unsigned *out)
{
	const char *found = digit ? strchr(base64_alphabet, digit) : NULL;

	if (!found) {
		return 0;
	}
	*out = (unsigned)(found - base64_alphabet);
	return 1;
}

int ncfg_key_parse(const char *text, size_t length, unsigned char out[NCFG_KEY_LEN], char *err,
    size_t err_size)
{
	unsigned accumulator = 0;
	unsigned bits = 0;
	size_t   written = 0;
	size_t   i;

	if (!out) {
		ncfg_error_set(err, err_size, "there is nowhere to put a key");
		return 0;
	}
	memset(out, 0, NCFG_KEY_LEN);
	/* 44 characters, the last of which is the one pad: 32 octets is not a
	 * multiple of three, which is where the single `=` comes from. */
	if (!text || length != NCFG_KEY_TEXT_LEN || text[43] != '=') {
		ncfg_error_set(err, err_size,
		    "a key is 44 characters of base64 ending in `=`, and this one is %zu",
		    text ? length : (size_t)0);
		return 0;
	}
	for (i = 0; i < 43u; i++) {
		unsigned digit = 0;

		if (!base64_value(text[i], &digit)) {
			/* The character is named and the key is not: a private key
			 * that failed to parse is still a private key, and the one
			 * byte that is wrong is what an operator needs. */
			ncfg_error_set(err, err_size, "a key is base64, and `%c` is not", text[i]);
			return 0;
		}
		accumulator = (accumulator << 6) | digit;
		bits += 6u;
		if (bits >= 8u) {
			bits -= 8u;
			if (written < NCFG_KEY_LEN) {
				out[written++] = (unsigned char)((accumulator >> bits) & 0xffu);
			}
		}
	}
	/* The low two bits of the last character are not decoded. A key that sets
	 * them is still a valid key -- `wg` emits them -- so they are ignored
	 * rather than refused, and the re-rendering clears them. */
	if (written != NCFG_KEY_LEN) {
		ncfg_error_set(err, err_size, "a key decodes to 32 octets, and this one to %zu",
		    written);
		return 0;
	}
	return 1;
}

static int public_key_read(const ncfg_json_doc_t *doc, uint32_t node, void *field, char *err,
    size_t err_size)
{
	size_t      length = 0;
	const char *text = ncfg_json_string(doc, node, &length);

	return ncfg_key_parse(text, text ? length : 0, field, err, err_size);
}

int ncfg_key_render(const unsigned char key[NCFG_KEY_LEN], char *out, size_t out_size,
    char *err, size_t err_size)
{
	size_t at = 0;
	size_t i;

	if (!key || !out || out_size < NCFG_KEY_TEXT_SIZE) {
		/* Named by its size and never by its value: a key that would not fit
		 * is still a key. */
		ncfg_error_set(err, err_size, "a key needs %u bytes to render into",
		    (unsigned)NCFG_KEY_TEXT_SIZE);
		return 0;
	}
	for (i = 0; i < NCFG_KEY_LEN; i += 3u) {
		size_t   have = NCFG_KEY_LEN - i < 3u ? NCFG_KEY_LEN - i : 3u;
		unsigned block = 0;
		size_t   j;

		for (j = 0; j < have; j++) {
			block |= (unsigned)key[i + j] << (16u - 8u * (unsigned)j);
		}
		for (j = 0; j < 4u; j++) {
			out[at++] = j < have + 1u ?
			    base64_alphabet[(block >> (18u - 6u * (unsigned)j)) & 0x3fu] : '=';
		}
	}
	out[at] = '\0';
	return 1;
}

static void public_key_write(ncfg_json_writer_t *writer, const void *field)
{
	char text[NCFG_KEY_TEXT_SIZE];

	if (!ncfg_key_render(field, text, sizeof(text), NULL, 0)) {
		return;
	}
	ncfg_json_write_string(writer, text);
}

static const ncfg_custom_t public_key_custom = { public_key_read, public_key_write, NULL, NULL,
	NULL };

static const ncfg_field_t wg_peer_fields[] = {
	{ .name = "name", .kind = NCFG_F_STR, .flags = NCFG_FF_REQUIRED,
	    .offset = offsetof(ncfg_wg_peer_t, name) },
	{ .name = "public_key", .kind = NCFG_F_CUSTOM, .flags = NCFG_FF_REQUIRED,
	    .custom = &public_key_custom, .offset = offsetof(ncfg_wg_peer_t, public_key) },
	{ .name = "preshared_key", .kind = NCFG_F_OPT_STRUCT, .type = &secret_ref_type,
	    .element_size = sizeof(ncfg_secret_ref_t),
	    .offset = offsetof(ncfg_wg_peer_t, preshared_key) },
	{ .name = "endpoint", .kind = NCFG_F_STR, .offset = offsetof(ncfg_wg_peer_t, endpoint) },
	{ .name = "allowed_ips", .kind = NCFG_F_STR_LIST, .flags = NCFG_FF_REQUIRED,
	    .offset = offsetof(ncfg_wg_peer_t, allowed_ips),
	    .count_offset = offsetof(ncfg_wg_peer_t, allowed_ip_count) },
	{ .name = "keepalive", .kind = NCFG_F_OPT_INT, R_U16,
	    .offset = offsetof(ncfg_wg_peer_t, keepalive) }
};
static const ncfg_type_t wg_peer_type = TYPE("wireguard peer", wg_peer_fields);

static const ncfg_field_t wireguard_fields[] = {
	{ .name = "private_key", .kind = NCFG_F_STRUCT, .flags = NCFG_FF_REQUIRED,
	    .type = &secret_ref_type, .offset = offsetof(ncfg_wireguard_config_t, private_key) },
	{ .name = "listen_port", .kind = NCFG_F_OPT_INT, R_U16,
	    .offset = offsetof(ncfg_wireguard_config_t, listen_port) },
	{ .name = "fwmark", .kind = NCFG_F_OPT_INT, R_U32,
	    .offset = offsetof(ncfg_wireguard_config_t, fwmark) },
	{ .name = "peers", .kind = NCFG_F_LIST, .flags = NCFG_FF_REQUIRED, .type = &wg_peer_type,
	    .element_size = sizeof(ncfg_wg_peer_t),
	    .offset = offsetof(ncfg_wireguard_config_t, peers),
	    .count_offset = offsetof(ncfg_wireguard_config_t, peer_count) }
};
static const ncfg_type_t wireguard_type = TAGGED("wireguard tunnel", wireguard_fields, "kind");

static const ncfg_field_t pppoe_fields[] = {
	{ .name = "parent", .kind = NCFG_F_STR, .flags = NCFG_FF_REQUIRED,
	    .offset = offsetof(ncfg_pppoe_config_t, parent) },
	{ .name = "username", .kind = NCFG_F_STR, .flags = NCFG_FF_REQUIRED,
	    .offset = offsetof(ncfg_pppoe_config_t, username) },
	{ .name = "password", .kind = NCFG_F_STRUCT, .flags = NCFG_FF_REQUIRED,
	    .type = &secret_ref_type, .offset = offsetof(ncfg_pppoe_config_t, password) },
	{ .name = "service", .kind = NCFG_F_STR, .offset = offsetof(ncfg_pppoe_config_t, service) },
	{ .name = "ac", .kind = NCFG_F_STR, .offset = offsetof(ncfg_pppoe_config_t, ac) }
};
static const ncfg_type_t pppoe_type = TAGGED("pppoe session", pppoe_fields, "kind");

static const ncfg_field_t openvpn_fields[] = {
	{ .name = "config", .kind = NCFG_F_STR, .flags = NCFG_FF_REQUIRED,
	    .offset = offsetof(ncfg_openvpn_config_t, config) },
	{ .name = "username", .kind = NCFG_F_STR,
	    .offset = offsetof(ncfg_openvpn_config_t, username) },
	{ .name = "password", .kind = NCFG_F_OPT_STRUCT, .type = &secret_ref_type,
	    .element_size = sizeof(ncfg_secret_ref_t),
	    .offset = offsetof(ncfg_openvpn_config_t, password) }
};
static const ncfg_type_t openvpn_type = TAGGED("openvpn tunnel", openvpn_fields, "kind");

static const ncfg_field_t veth_fields[] = {
	{ .name = "peer", .kind = NCFG_F_STR, .flags = NCFG_FF_REQUIRED,
	    .offset = offsetof(ncfg_veth_config_t, peer) }
};
static const ncfg_type_t veth_type = TAGGED("veth", veth_fields, "kind");

static const ncfg_field_t vrf_fields[] = {
	{ .name = "table", .kind = NCFG_F_INT, .flags = NCFG_FF_REQUIRED, R_U32,
	    .offset = offsetof(ncfg_vrf_config_t, table) }
};
static const ncfg_type_t vrf_type = TAGGED("vrf", vrf_fields, "kind");

static const ncfg_field_t macvlan_fields[] = {
	{ .name = "parent", .kind = NCFG_F_STR, .flags = NCFG_FF_REQUIRED,
	    .offset = offsetof(ncfg_macvlan_config_t, parent) },
	{ .name = "mode", .kind = NCFG_F_ENUM, .choices = &macvlan_mode_set,
	    .fallback = NCFG_MACVLAN_MODE_PRIVATE,
	    .offset = offsetof(ncfg_macvlan_config_t, mode) }
};
static const ncfg_type_t macvlan_type = TAGGED("macvlan", macvlan_fields, "kind");

static const ncfg_field_t tunnel_fields[] = {
	{ .name = "mode", .kind = NCFG_F_ENUM, .flags = NCFG_FF_REQUIRED, .choices = &tunnel_kind_set,
	    .offset = offsetof(ncfg_tunnel_config_t, mode) },
	{ .name = "local", .kind = NCFG_F_CUSTOM, .custom = &address_text,
	    .offset = offsetof(ncfg_tunnel_config_t, local) },
	{ .name = "remote", .kind = NCFG_F_CUSTOM, .custom = &address_text,
	    .offset = offsetof(ncfg_tunnel_config_t, remote) },
	{ .name = "parent", .kind = NCFG_F_STR, .offset = offsetof(ncfg_tunnel_config_t, parent) },
	{ .name = "ttl", .kind = NCFG_F_OPT_INT, R_U8,
	    .offset = offsetof(ncfg_tunnel_config_t, ttl) },
	{ .name = "key", .kind = NCFG_F_OPT_INT, R_U32,
	    .offset = offsetof(ncfg_tunnel_config_t, key) }
};
static const ncfg_type_t tunnel_type = TAGGED("tunnel", tunnel_fields, "kind");

static const ncfg_field_t tun_fields[] = {
	{ .name = "mode", .kind = NCFG_F_ENUM, .choices = &tun_mode_set,
	    .fallback = NCFG_TUN_MODE_TUN, .offset = offsetof(ncfg_tun_config_t, mode) },
	{ .name = "owner", .kind = NCFG_F_STR, .offset = offsetof(ncfg_tun_config_t, owner) },
	{ .name = "group", .kind = NCFG_F_STR, .offset = offsetof(ncfg_tun_config_t, group) }
};
static const ncfg_type_t tun_type = TAGGED("tun device", tun_fields, "kind");

static const ncfg_type_t physical_type = { "physical device", NULL, 0, "kind" };
static const ncfg_type_t dummy_type = { "dummy device", NULL, 0, "kind" };
static const ncfg_type_t ifb_type = { "ifb device", NULL, 0, "kind" };

/* Which table and which arm each kind uses. One switch rather than three,
 * because a kind added to two of them and not the third is the shape of defect
 * this whole file is arranged to make impossible. */
static const ncfg_type_t *kind_arm(int kind, ncfg_interface_kind_t *value, void **payload)
{
	switch (kind) {
	case NCFG_KIND_BRIDGE:
		*payload = &value->bridge;
		return &bridge_type;
	case NCFG_KIND_BOND:
		*payload = &value->bond;
		return &bond_type;
	case NCFG_KIND_VLAN:
		*payload = &value->vlan;
		return &vlan_type;
	case NCFG_KIND_VXLAN:
		*payload = &value->vxlan;
		return &vxlan_type;
	case NCFG_KIND_WIREGUARD:
		*payload = &value->wireguard;
		return &wireguard_type;
	case NCFG_KIND_PPPOE:
		*payload = &value->pppoe;
		return &pppoe_type;
	case NCFG_KIND_OPENVPN:
		*payload = &value->openvpn;
		return &openvpn_type;
	case NCFG_KIND_VETH:
		*payload = &value->veth;
		return &veth_type;
	case NCFG_KIND_VRF:
		*payload = &value->vrf;
		return &vrf_type;
	case NCFG_KIND_MACVLAN:
		*payload = &value->macvlan;
		return &macvlan_type;
	case NCFG_KIND_TUNNEL:
		*payload = &value->tunnel;
		return &tunnel_type;
	case NCFG_KIND_TUN:
		*payload = &value->tun;
		return &tun_type;
	case NCFG_KIND_DUMMY:
		*payload = &value->kind;
		return &dummy_type;
	case NCFG_KIND_IFB:
		*payload = &value->kind;
		return &ifb_type;
	default:
		*payload = &value->kind;
		return &physical_type;
	}
}

static int interface_kind_read(const ncfg_json_doc_t *doc, uint32_t node, void *field,
    char *err, size_t err_size)
{
	ncfg_interface_kind_t *value = field;
	uint32_t               tag;
	int                    kind = 0;
	const ncfg_type_t     *type;
	void                  *payload = NULL;

	if (ncfg_json_type(doc, node) != NCFG_JSON_OBJECT) {
		ncfg_error_set(err, err_size, "an interface kind is an object, and this is not one");
		return 0;
	}
	tag = ncfg_json_member(doc, node, "kind");
	if (tag == NCFG_JSON_NONE) {
		ncfg_error_set(err, err_size, "an interface kind has no `kind`");
		return 0;
	}
	if (!ncfg_field_enum(&interface_kind_set, doc, tag, &kind, err, err_size)) {
		return 0;
	}
	value->kind = kind;
	type = kind_arm(kind, value, &payload);
	if (!ncfg_type_init(type, payload)) {
		ncfg_error_set(err, err_size, "out of memory reading an interface kind");
		return 0;
	}
	return ncfg_type_read(type, doc, node, payload, err, err_size);
}

static void interface_kind_write(ncfg_json_writer_t *writer, const void *field)
{
	/* The arm is chosen by the same switch the reader used, and reading a
	 * const value through it is the one place a cast earns its keep: the
	 * switch is what must not be written twice. */
	ncfg_interface_kind_t *value = (ncfg_interface_kind_t *)(uintptr_t)field;
	void                  *payload = NULL;
	const ncfg_type_t     *type = kind_arm(value->kind, value, &payload);
	const char            *word = ncfg_field_enum_name(&interface_kind_set, value->kind);

	ncfg_json_write_object_begin(writer);
	if (word) {
		ncfg_json_write_member_string(writer, "kind", word);
	}
	ncfg_type_write(type, writer, payload);
	ncfg_json_write_object_end(writer);
}

static void interface_kind_release(void *field)
{
	ncfg_interface_kind_t *value = field;

	ncfg_type_free(&bridge_type, &value->bridge);
	ncfg_type_free(&bond_type, &value->bond);
	ncfg_type_free(&vlan_type, &value->vlan);
	ncfg_type_free(&vxlan_type, &value->vxlan);
	ncfg_type_free(&wireguard_type, &value->wireguard);
	ncfg_type_free(&pppoe_type, &value->pppoe);
	ncfg_type_free(&openvpn_type, &value->openvpn);
	ncfg_type_free(&veth_type, &value->veth);
	ncfg_type_free(&vrf_type, &value->vrf);
	ncfg_type_free(&macvlan_type, &value->macvlan);
	ncfg_type_free(&tunnel_type, &value->tunnel);
	ncfg_type_free(&tun_type, &value->tun);
}

static const ncfg_custom_t interface_kind_custom = { interface_kind_read, interface_kind_write,
	NULL, interface_kind_release, NULL };

/* ------------------------------------------------------------------------ *
 * Devices
 * ------------------------------------------------------------------------ */

static const ncfg_field_t bridge_vlan_fields[] = {
	{ .name = "vid", .kind = NCFG_F_INT, .flags = NCFG_FF_REQUIRED, R_U16,
	    .offset = offsetof(ncfg_bridge_vlan_t, vid) },
	{ .name = "pvid", .kind = NCFG_F_BOOL, .offset = offsetof(ncfg_bridge_vlan_t, pvid) },
	{ .name = "untagged", .kind = NCFG_F_BOOL, .offset = offsetof(ncfg_bridge_vlan_t, untagged) }
};
static const ncfg_type_t bridge_vlan_type = TYPE("bridge vlan", bridge_vlan_fields);

static const ncfg_field_t qdisc_fields[] = {
	{ .name = "kind", .kind = NCFG_F_ENUM, .flags = NCFG_FF_REQUIRED, .choices = &qdisc_kind_set,
	    .offset = offsetof(ncfg_qdisc_policy_t, kind) },
	{ .name = "bandwidth_bits", .kind = NCFG_F_OPT_INT, R_U64,
	    .offset = offsetof(ncfg_qdisc_policy_t, bandwidth_bits) },
	{ .name = "ingress_bandwidth_bits", .kind = NCFG_F_OPT_INT, R_U64,
	    .offset = offsetof(ncfg_qdisc_policy_t, ingress_bandwidth_bits) },
	{ .name = "ingress", .kind = NCFG_F_BOOL, .flags = NCFG_FF_OMIT_FALSE,
	    .offset = offsetof(ncfg_qdisc_policy_t, ingress) }
};
static const ncfg_type_t qdisc_type = TYPE("qdisc policy", qdisc_fields);

static const ncfg_field_t link_settings_fields[] = {
	{ .name = "autoneg", .kind = NCFG_F_ENUM, .choices = &toggle_set,
	    .offset = offsetof(ncfg_link_settings_t, autoneg) },
	{ .name = "speed", .kind = NCFG_F_OPT_INT, R_U32,
	    .offset = offsetof(ncfg_link_settings_t, speed) },
	{ .name = "duplex", .kind = NCFG_F_STR, .offset = offsetof(ncfg_link_settings_t, duplex) },
	{ .name = "wol", .kind = NCFG_F_STR, .offset = offsetof(ncfg_link_settings_t, wol) },
	{ .name = "rx_ring", .kind = NCFG_F_OPT_INT, R_U32,
	    .offset = offsetof(ncfg_link_settings_t, rx_ring) },
	{ .name = "tx_ring", .kind = NCFG_F_OPT_INT, R_U32,
	    .offset = offsetof(ncfg_link_settings_t, tx_ring) },
	{ .name = "gro", .kind = NCFG_F_ENUM, .choices = &toggle_set,
	    .offset = offsetof(ncfg_link_settings_t, gro) },
	{ .name = "gso", .kind = NCFG_F_ENUM, .choices = &toggle_set,
	    .offset = offsetof(ncfg_link_settings_t, gso) },
	{ .name = "tso", .kind = NCFG_F_ENUM, .choices = &toggle_set,
	    .offset = offsetof(ncfg_link_settings_t, tso) },
	{ .name = "rx_checksum", .kind = NCFG_F_ENUM, .choices = &toggle_set,
	    .offset = offsetof(ncfg_link_settings_t, rx_checksum) },
	{ .name = "tx_checksum", .kind = NCFG_F_ENUM, .choices = &toggle_set,
	    .offset = offsetof(ncfg_link_settings_t, tx_checksum) }
};
static const ncfg_type_t link_settings_type = TYPE("link settings", link_settings_fields);

static const ncfg_field_t device_match_fields[] = {
	{ .name = "mac", .kind = NCFG_F_STR, .offset = offsetof(ncfg_device_match_t, mac) },
	{ .name = "path", .kind = NCFG_F_STR, .offset = offsetof(ncfg_device_match_t, path) },
	{ .name = "driver", .kind = NCFG_F_STR, .offset = offsetof(ncfg_device_match_t, driver) },
	{ .name = "name_glob", .kind = NCFG_F_STR,
	    .offset = offsetof(ncfg_device_match_t, name_glob) }
};
static const ncfg_type_t device_match_type = TYPE("device match", device_match_fields);

static const ncfg_field_t wifi_device_fields[] = {
	{ .name = "backend", .kind = NCFG_F_ENUM, .choices = &wifi_backend_set,
	    .fallback = NCFG_WIFI_BACKEND_AUTO,
	    .offset = offsetof(ncfg_wifi_device_policy_t, backend) },
	{ .name = "autoconnect", .kind = NCFG_F_BOOL, .fallback = 1,
	    .offset = offsetof(ncfg_wifi_device_policy_t, autoconnect) },
	{ .name = "portal_check", .kind = NCFG_F_STR,
	    .offset = offsetof(ncfg_wifi_device_policy_t, portal_check) },
	{ .name = "regdom", .kind = NCFG_F_STR,
	    .offset = offsetof(ncfg_wifi_device_policy_t, regdom) },
	{ .name = "powersave", .kind = NCFG_F_ENUM, .choices = &powersave_set,
	    .fallback = NCFG_POWERSAVE_DEFAULT,
	    .offset = offsetof(ncfg_wifi_device_policy_t, powersave) },
	{ .name = "mac_policy", .kind = NCFG_F_ENUM, .choices = &mac_policy_set,
	    .fallback = NCFG_MAC_POLICY_PERMANENT,
	    .offset = offsetof(ncfg_wifi_device_policy_t, mac_policy) },
	{ .name = "scan_randomization", .kind = NCFG_F_BOOL,
	    .offset = offsetof(ncfg_wifi_device_policy_t, scan_randomization) }
};
static const ncfg_type_t wifi_device_type = TYPE("wifi device policy", wifi_device_fields);

static const ncfg_field_t modem_fields[] = {
	{ .name = "sim", .kind = NCFG_F_STR_LIST, .flags = NCFG_FF_OMIT_EMPTY,
	    .offset = offsetof(ncfg_modem_policy_t, sim),
	    .count_offset = offsetof(ncfg_modem_policy_t, sim_count) },
	{ .name = "apn", .kind = NCFG_F_STR, .offset = offsetof(ncfg_modem_policy_t, apn) }
};
static const ncfg_type_t modem_type = TYPE("modem policy", modem_fields);

static const ncfg_field_t device_fields[] = {
	{ .name = "name", .kind = NCFG_F_STR, .flags = NCFG_FF_REQUIRED,
	    .offset = offsetof(ncfg_device_t, name) },
	{ .name = "match", .kind = NCFG_F_OPT_STRUCT, .type = &device_match_type,
	    .element_size = sizeof(ncfg_device_match_t), .offset = offsetof(ncfg_device_t, match) },
	{ .name = "managed", .kind = NCFG_F_BOOL, .fallback = 1,
	    .offset = offsetof(ncfg_device_t, managed) },
	{ .name = "on_unmanage", .kind = NCFG_F_ENUM, .choices = &on_unmanage_set,
	    .fallback = NCFG_ON_UNMANAGE_LEAVE, .offset = offsetof(ncfg_device_t, on_unmanage) },
	{ .name = "wifi", .kind = NCFG_F_OPT_STRUCT, .type = &wifi_device_type,
	    .element_size = sizeof(ncfg_wifi_device_policy_t),
	    .offset = offsetof(ncfg_device_t, wifi) },
	{ .name = "modem", .kind = NCFG_F_OPT_STRUCT, .type = &modem_type,
	    .element_size = sizeof(ncfg_modem_policy_t), .offset = offsetof(ncfg_device_t, modem) },
	{ .name = "mtu", .kind = NCFG_F_OPT_INT, R_U32, .offset = offsetof(ncfg_device_t, mtu) },
	{ .name = "mac", .kind = NCFG_F_STR, .offset = offsetof(ncfg_device_t, mac) },
	{ .name = "link_settings", .kind = NCFG_F_OPT_STRUCT, .type = &link_settings_type,
	    .element_size = sizeof(ncfg_link_settings_t),
	    .offset = offsetof(ncfg_device_t, link_settings) },
	{ .name = "kind", .kind = NCFG_F_CUSTOM, .custom = &interface_kind_custom,
	    .offset = offsetof(ncfg_device_t, kind) },
	{ .name = "master", .kind = NCFG_F_STR, .offset = offsetof(ncfg_device_t, master) },
	{ .name = "qdisc", .kind = NCFG_F_OPT_STRUCT, .type = &qdisc_type,
	    .element_size = sizeof(ncfg_qdisc_policy_t), .offset = offsetof(ncfg_device_t, qdisc) },
	{ .name = "ingress_redirect", .kind = NCFG_F_STR,
	    .offset = offsetof(ncfg_device_t, ingress_redirect) },
	{ .name = "bridge_vlans", .kind = NCFG_F_LIST, .type = &bridge_vlan_type,
	    .element_size = sizeof(ncfg_bridge_vlan_t),
	    .offset = offsetof(ncfg_device_t, bridge_vlans),
	    .count_offset = offsetof(ncfg_device_t, bridge_vlan_count) }
};
static const ncfg_type_t device_type = TYPE("device", device_fields);

/* ------------------------------------------------------------------------ *
 * Interfaces
 * ------------------------------------------------------------------------ */

static int ra_backend_read(const ncfg_json_doc_t *doc, uint32_t node, void *field, char *err,
    size_t err_size)
{
	ncfg_ra_backend_t *value = field;
	uint32_t           only;
	size_t             i;

	if (ncfg_json_type(doc, node) == NCFG_JSON_STRING) {
		for (i = 0; i < COUNT_OF(ra_backend_words) - 1u; i++) {
			if (ncfg_json_string_equals(doc, node, ra_backend_words[i])) {
				value->kind = (int)i;
				return 1;
			}
		}
		ncfg_error_set(err, err_size, "that is not a router advertisement backend");
		return 0;
	}
	only = ncfg_field_only_member(doc, node);
	if (only == NCFG_JSON_NONE || ncfg_json_member(doc, node, "exec") != only) {
		ncfg_error_set(err, err_size,
		    "a router advertisement backend is a word, or `{\"exec\": \"...\"}`");
		return 0;
	}
	value->kind = NCFG_RA_BACKEND_EXEC;
	free(value->command);
	value->command = ncfg_field_string(doc, only, "the command of backend `exec`", err,
	    err_size);
	return value->command != NULL;
}

static void ra_backend_write(ncfg_json_writer_t *writer, const void *field)
{
	const ncfg_ra_backend_t *value = field;

	if (value->kind == NCFG_RA_BACKEND_EXEC) {
		ncfg_json_write_object_begin(writer);
		ncfg_json_write_member_string(writer, "exec", value->command);
		ncfg_json_write_object_end(writer);
		return;
	}
	if (value->kind >= 0 && (size_t)value->kind < COUNT_OF(ra_backend_words)) {
		ncfg_json_write_string(writer, ra_backend_words[value->kind]);
	}
}

static void ra_backend_release(void *field)
{
	ncfg_ra_backend_t *value = field;

	free(value->command);
	value->command = NULL;
}

static const ncfg_custom_t ra_backend_custom = { ra_backend_read, ra_backend_write, NULL,
	ra_backend_release, NULL };

static const ncfg_field_t ra_fields[] = {
	{ .name = "backend", .kind = NCFG_F_CUSTOM, .custom = &ra_backend_custom,
	    .offset = offsetof(ncfg_ra_policy_t, backend) },
	{ .name = "prefixes", .kind = NCFG_F_LIST, .type = &prefix_ref_type,
	    .element_size = sizeof(ncfg_prefix_ref_t),
	    .offset = offsetof(ncfg_ra_policy_t, prefixes),
	    .count_offset = offsetof(ncfg_ra_policy_t, prefix_count) },
	{ .name = "managed", .kind = NCFG_F_BOOL, .offset = offsetof(ncfg_ra_policy_t, managed) },
	{ .name = "other_config", .kind = NCFG_F_BOOL,
	    .offset = offsetof(ncfg_ra_policy_t, other_config) },
	{ .name = "dns", .kind = NCFG_F_BOOL, .fallback = 1,
	    .offset = offsetof(ncfg_ra_policy_t, dns) },
	{ .name = "lifetime", .kind = NCFG_F_OPT_INT, R_U32,
	    .offset = offsetof(ncfg_ra_policy_t, lifetime) }
};
static const ncfg_type_t ra_type = TYPE("router advertisement policy", ra_fields);

static const ncfg_field_t guard_fields[] = {
	{ .name = "reason", .kind = NCFG_F_STR, .flags = NCFG_FF_REQUIRED,
	    .offset = offsetof(ncfg_guard_t, reason) }
};
static const ncfg_type_t guard_type = TYPE("guard", guard_fields);

static const ncfg_field_t probe_fields[] = {
	{ .name = "command", .kind = NCFG_F_STR, .flags = NCFG_FF_REQUIRED,
	    .offset = offsetof(ncfg_probe_policy_t, command) },
	{ .name = "args", .kind = NCFG_F_STR_LIST, .flags = NCFG_FF_OMIT_EMPTY,
	    .offset = offsetof(ncfg_probe_policy_t, args),
	    .count_offset = offsetof(ncfg_probe_policy_t, arg_count) },
	{ .name = "interval", .kind = NCFG_F_INT, .flags = NCFG_FF_REQUIRED, R_U32,
	    .offset = offsetof(ncfg_probe_policy_t, interval) },
	{ .name = "timeout", .kind = NCFG_F_INT, .flags = NCFG_FF_REQUIRED, R_U32,
	    .offset = offsetof(ncfg_probe_policy_t, timeout) },
	{ .name = "down_after", .kind = NCFG_F_INT, .flags = NCFG_FF_REQUIRED, R_U32,
	    .offset = offsetof(ncfg_probe_policy_t, down_after) },
	{ .name = "require_lease", .kind = NCFG_F_BOOL, .flags = NCFG_FF_OMIT_TRUE, .fallback = 1,
	    .offset = offsetof(ncfg_probe_policy_t, require_lease) },
	{ .name = "up_after", .kind = NCFG_F_INT, .flags = NCFG_FF_REQUIRED, R_U32,
	    .offset = offsetof(ncfg_probe_policy_t, up_after) },
	{ .name = "hold_down", .kind = NCFG_F_INT, .flags = NCFG_FF_OMIT_ZERO, R_U32,
	    .offset = offsetof(ncfg_probe_policy_t, hold_down) }
};
static const ncfg_type_t probe_type = TYPE("probe policy", probe_fields);

static const ncfg_field_t interface_fields[] = {
	{ .name = "name", .kind = NCFG_F_STR, .flags = NCFG_FF_REQUIRED,
	    .offset = offsetof(ncfg_interface_t, name) },
	{ .name = "enabled", .kind = NCFG_F_BOOL, .fallback = 1,
	    .offset = offsetof(ncfg_interface_t, enabled) },
	{ .name = "addressing", .kind = NCFG_F_LIST, .custom = &address_source_custom,
	    .element_size = sizeof(ncfg_address_source_t),
	    .offset = offsetof(ncfg_interface_t, addressing),
	    .count_offset = offsetof(ncfg_interface_t, addressing_count) },
	{ .name = "routes", .kind = NCFG_F_LIST, .type = &route_type,
	    .element_size = sizeof(ncfg_route_t), .offset = offsetof(ncfg_interface_t, routes),
	    .count_offset = offsetof(ncfg_interface_t, route_count) },
	{ .name = "dns", .kind = NCFG_F_OPT_STRUCT, .type = &dns_policy_type,
	    .element_size = sizeof(ncfg_dns_policy_t), .offset = offsetof(ncfg_interface_t, dns) },
	{ .name = "hooks", .kind = NCFG_F_LIST, .type = &hook_type,
	    .element_size = sizeof(ncfg_hook_ref_t), .offset = offsetof(ncfg_interface_t, hooks),
	    .count_offset = offsetof(ncfg_interface_t, hook_count) },
	{ .name = "on_drift", .kind = NCFG_F_OPT_ENUM, .choices = &drift_policy_set,
	    .offset = offsetof(ncfg_interface_t, on_drift) },
	{ .name = "dot1x", .kind = NCFG_F_OPT_STRUCT, .type = &eap_type,
	    .element_size = sizeof(ncfg_eap_config_t), .offset = offsetof(ncfg_interface_t, dot1x) },
	{ .name = "advertise", .kind = NCFG_F_OPT_STRUCT, .type = &ra_type,
	    .element_size = sizeof(ncfg_ra_policy_t),
	    .offset = offsetof(ncfg_interface_t, advertise) },
	{ .name = "forwarding", .kind = NCFG_F_OPT_BOOL,
	    .offset = offsetof(ncfg_interface_t, forwarding) },
	{ .name = "nat", .kind = NCFG_F_OPT_BOOL, .offset = offsetof(ncfg_interface_t, nat) },
	{ .name = "guard", .kind = NCFG_F_OPT_STRUCT, .type = &guard_type,
	    .element_size = sizeof(ncfg_guard_t), .offset = offsetof(ncfg_interface_t, guard) },
	{ .name = "ipv6_token", .kind = NCFG_F_STR,
	    .offset = offsetof(ncfg_interface_t, ipv6_token) },
	{ .name = "preference", .kind = NCFG_F_OPT_INT, R_U32,
	    .offset = offsetof(ncfg_interface_t, preference) },
	{ .name = "probe", .kind = NCFG_F_OPT_STRUCT, .type = &probe_type,
	    .element_size = sizeof(ncfg_probe_policy_t), .offset = offsetof(ncfg_interface_t, probe) }
};
static const ncfg_type_t interface_type = TYPE("interface", interface_fields);

/* ------------------------------------------------------------------------ *
 * Wifi networks and access points
 * ------------------------------------------------------------------------ */

static int ssid_read(const ncfg_json_doc_t *doc, uint32_t node, void *field, char *err,
    size_t err_size)
{
	ncfg_ssid_t *ssid = field;
	size_t       length = 0;
	const char  *text = ncfg_json_string(doc, node, &length);
	size_t       i;

	if (!text) {
		ncfg_error_set(err, err_size, "an ssid is lowercase hex, and this is not a string");
		return 0;
	}
	if (length % 2u != 0u) {
		ncfg_error_set(err, err_size, "an ssid is an even number of hex digits, and this is %zu",
		    length);
		return 0;
	}
	if (length / 2u > NCFG_SSID_MAX_LEN) {
		ncfg_error_set(err, err_size, "an ssid is %zu octets, and the maximum is %d",
		    length / 2u, NCFG_SSID_MAX_LEN);
		return 0;
	}
	for (i = 0; i < length; i += 2u) {
		unsigned value = 0;
		size_t   half;

		for (half = 0; half < 2u; half++) {
			char digit = text[i + half];
			unsigned nibble;

			/* **Lowercase only, and uppercase is refused rather than
			 * accepted**: two spellings of one ssid would break the
			 * byte-identical guarantee the whole document rests on. */
			if (digit >= '0' && digit <= '9') {
				nibble = (unsigned)(digit - '0');
			} else if (digit >= 'a' && digit <= 'f') {
				nibble = (unsigned)(digit - 'a') + 10u;
			} else {
				ncfg_error_set(err, err_size,
				    "an ssid is lowercase hex, and `%c` is not a digit of it", digit);
				return 0;
			}
			value = (value << 4) | nibble;
		}
		ssid->bytes[i / 2u] = (unsigned char)value;
	}
	ssid->length = length / 2u;
	ssid->has = 1;
	return 1;
}

static void ssid_write(ncfg_json_writer_t *writer, const void *field)
{
	static const char hex[] = "0123456789abcdef";
	const ncfg_ssid_t *ssid = field;
	char               text[NCFG_SSID_MAX_LEN * 2u + 1u];
	size_t             i;

	for (i = 0; i < ssid->length && i < NCFG_SSID_MAX_LEN; i++) {
		text[i * 2u] = hex[ssid->bytes[i] >> 4];
		text[i * 2u + 1u] = hex[ssid->bytes[i] & 0x0fu];
	}
	text[i * 2u] = '\0';
	ncfg_json_write_string(writer, text);
}

static int ssid_omit(const void *field)
{
	const ncfg_ssid_t *ssid = field;

	return !ssid->has;
}

static const ncfg_custom_t ssid_custom = { ssid_read, ssid_write, ssid_omit, NULL, NULL };
/* An access point states one or it is not an access point, so there is nothing
 * to omit and the required check is the table's. */
static const ncfg_custom_t ssid_required_custom = { ssid_read, ssid_write, NULL, NULL, NULL };

static const ncfg_field_t roam_fields[] = {
	{ .name = "signal", .kind = NCFG_F_INT, .flags = NCFG_FF_REQUIRED, R_I32,
	    .offset = offsetof(ncfg_roam_policy_t, signal) },
	{ .name = "interval", .kind = NCFG_F_INT, .flags = NCFG_FF_REQUIRED, R_U32,
	    .offset = offsetof(ncfg_roam_policy_t, interval) },
	{ .name = "slow_interval", .kind = NCFG_F_INT, .flags = NCFG_FF_REQUIRED, R_U32,
	    .offset = offsetof(ncfg_roam_policy_t, slow_interval) }
};
static const ncfg_type_t roam_type = TYPE("roam policy", roam_fields);

static const ncfg_field_t network_fields[] = {
	{ .name = "id", .kind = NCFG_F_STR, .flags = NCFG_FF_REQUIRED,
	    .offset = offsetof(ncfg_wifi_network_t, id) },
	{ .name = "ssid", .kind = NCFG_F_CUSTOM, .custom = &ssid_custom,
	    .offset = offsetof(ncfg_wifi_network_t, ssid) },
	{ .name = "hidden", .kind = NCFG_F_BOOL, .offset = offsetof(ncfg_wifi_network_t, hidden) },
	{ .name = "security", .kind = NCFG_F_CUSTOM, .flags = NCFG_FF_REQUIRED,
	    .custom = &security_custom, .offset = offsetof(ncfg_wifi_network_t, security) },
	{ .name = "metric", .kind = NCFG_F_OPT_INT, R_U32,
	    .offset = offsetof(ncfg_wifi_network_t, metric) },
	{ .name = "autoconnect", .kind = NCFG_F_BOOL, .fallback = 1,
	    .offset = offsetof(ncfg_wifi_network_t, autoconnect) },
	{ .name = "metered", .kind = NCFG_F_BOOL, .offset = offsetof(ncfg_wifi_network_t, metered) },
	{ .name = "bssid", .kind = NCFG_F_STR_LIST, .flags = NCFG_FF_OMIT_EMPTY,
	    .offset = offsetof(ncfg_wifi_network_t, bssid),
	    .count_offset = offsetof(ncfg_wifi_network_t, bssid_count) },
	{ .name = "roam", .kind = NCFG_F_OPT_STRUCT, .type = &roam_type,
	    .element_size = sizeof(ncfg_roam_policy_t),
	    .offset = offsetof(ncfg_wifi_network_t, roam) },
	{ .name = "addressing", .kind = NCFG_F_LIST, .custom = &address_source_custom,
	    .element_size = sizeof(ncfg_address_source_t),
	    .offset = offsetof(ncfg_wifi_network_t, addressing),
	    .count_offset = offsetof(ncfg_wifi_network_t, addressing_count) },
	{ .name = "routes", .kind = NCFG_F_LIST, .type = &route_type,
	    .element_size = sizeof(ncfg_route_t), .offset = offsetof(ncfg_wifi_network_t, routes),
	    .count_offset = offsetof(ncfg_wifi_network_t, route_count) },
	{ .name = "dns", .kind = NCFG_F_OPT_STRUCT, .type = &dns_policy_type,
	    .element_size = sizeof(ncfg_dns_policy_t),
	    .offset = offsetof(ncfg_wifi_network_t, dns) },
	{ .name = "hooks", .kind = NCFG_F_LIST, .type = &hook_type,
	    .element_size = sizeof(ncfg_hook_ref_t), .offset = offsetof(ncfg_wifi_network_t, hooks),
	    .count_offset = offsetof(ncfg_wifi_network_t, hook_count) }
};
static const ncfg_type_t network_type = TYPE("wifi network", network_fields);

static const ncfg_field_t access_control_fields[] = {
	{ .name = "policy", .kind = NCFG_F_ENUM, .flags = NCFG_FF_REQUIRED, .choices = &acl_policy_set,
	    .offset = offsetof(ncfg_access_control_t, policy) },
	{ .name = "stations", .kind = NCFG_F_STR_LIST, .flags = NCFG_FF_REQUIRED,
	    .offset = offsetof(ncfg_access_control_t, stations),
	    .count_offset = offsetof(ncfg_access_control_t, station_count) }
};
static const ncfg_type_t access_control_type = TYPE("access control list", access_control_fields);

static const ncfg_field_t access_point_fields[] = {
	{ .name = "id", .kind = NCFG_F_STR, .flags = NCFG_FF_REQUIRED,
	    .offset = offsetof(ncfg_access_point_t, id) },
	{ .name = "ssid", .kind = NCFG_F_CUSTOM, .flags = NCFG_FF_REQUIRED,
	    .custom = &ssid_required_custom, .offset = offsetof(ncfg_access_point_t, ssid) },
	{ .name = "device", .kind = NCFG_F_STR, .flags = NCFG_FF_REQUIRED,
	    .offset = offsetof(ncfg_access_point_t, device) },
	{ .name = "security", .kind = NCFG_F_CUSTOM, .flags = NCFG_FF_REQUIRED,
	    .custom = &security_custom, .offset = offsetof(ncfg_access_point_t, security) },
	{ .name = "channel", .kind = NCFG_F_OPT_INT, R_U16,
	    .offset = offsetof(ncfg_access_point_t, channel) },
	{ .name = "band", .kind = NCFG_F_STR, .offset = offsetof(ncfg_access_point_t, band) },
	{ .name = "hidden", .kind = NCFG_F_BOOL, .offset = offsetof(ncfg_access_point_t, hidden) },
	{ .name = "regdom", .kind = NCFG_F_STR, .offset = offsetof(ncfg_access_point_t, regdom) },
	{ .name = "access_control", .kind = NCFG_F_OPT_STRUCT, .type = &access_control_type,
	    .element_size = sizeof(ncfg_access_control_t),
	    .offset = offsetof(ncfg_access_point_t, access_control) }
};
static const ncfg_type_t access_point_type = TYPE("access point", access_point_fields);

/* ------------------------------------------------------------------------ *
 * Rules, bluetooth devices, linksets
 * ------------------------------------------------------------------------ */

static const ncfg_field_t rule_fields[] = {
	{ .name = "id", .kind = NCFG_F_STR, .flags = NCFG_FF_REQUIRED,
	    .offset = offsetof(ncfg_routing_rule_t, id) },
	{ .name = "priority", .kind = NCFG_F_INT, .flags = NCFG_FF_REQUIRED, R_U32,
	    .offset = offsetof(ncfg_routing_rule_t, priority) },
	{ .name = "family", .kind = NCFG_F_ENUM, .choices = &rule_family_set,
	    .fallback = NCFG_RULE_FAMILY_INET, .offset = offsetof(ncfg_routing_rule_t, family) },
	{ .name = "from", .kind = NCFG_F_STR, .offset = offsetof(ncfg_routing_rule_t, from) },
	{ .name = "to", .kind = NCFG_F_STR, .offset = offsetof(ncfg_routing_rule_t, to) },
	{ .name = "iif", .kind = NCFG_F_STR, .offset = offsetof(ncfg_routing_rule_t, iif) },
	{ .name = "oif", .kind = NCFG_F_STR, .offset = offsetof(ncfg_routing_rule_t, oif) },
	{ .name = "fwmark", .kind = NCFG_F_OPT_INT, R_U32,
	    .offset = offsetof(ncfg_routing_rule_t, fwmark) },
	{ .name = "fwmask", .kind = NCFG_F_OPT_INT, R_U32,
	    .offset = offsetof(ncfg_routing_rule_t, fwmask) },
	{ .name = "table", .kind = NCFG_F_OPT_INT, R_U32,
	    .offset = offsetof(ncfg_routing_rule_t, table) },
	{ .name = "action", .kind = NCFG_F_ENUM, .choices = &rule_action_set,
	    .fallback = NCFG_RULE_ACTION_LOOKUP, .offset = offsetof(ncfg_routing_rule_t, action) },
	{ .name = "suppress_prefixlength", .kind = NCFG_F_OPT_INT, R_U32,
	    .offset = offsetof(ncfg_routing_rule_t, suppress_prefixlength) },
	{ .name = "l3mdev", .kind = NCFG_F_BOOL, .offset = offsetof(ncfg_routing_rule_t, l3mdev) },
	{ .name = "invert", .kind = NCFG_F_BOOL, .offset = offsetof(ncfg_routing_rule_t, invert) }
};
static const ncfg_type_t rule_type = TYPE("routing rule", rule_fields);

static const ncfg_field_t bluetooth_fields[] = {
	{ .name = "id", .kind = NCFG_F_STR, .flags = NCFG_FF_REQUIRED,
	    .offset = offsetof(ncfg_bluetooth_device_t, id) },
	{ .name = "address", .kind = NCFG_F_STR, .flags = NCFG_FF_REQUIRED,
	    .offset = offsetof(ncfg_bluetooth_device_t, address) },
	{ .name = "profile", .kind = NCFG_F_ENUM, .flags = NCFG_FF_REQUIRED,
	    .choices = &bluetooth_profile_set,
	    .offset = offsetof(ncfg_bluetooth_device_t, profile) },
	{ .name = "autoconnect", .kind = NCFG_F_BOOL, .flags = NCFG_FF_REQUIRED,
	    .offset = offsetof(ncfg_bluetooth_device_t, autoconnect) }
};
static const ncfg_type_t bluetooth_type = TYPE("bluetooth device", bluetooth_fields);

static const ncfg_field_t linkset_fields[] = {
	{ .name = "name", .kind = NCFG_F_STR, .flags = NCFG_FF_REQUIRED,
	    .offset = offsetof(ncfg_linkset_t, name) },
	{ .name = "members", .kind = NCFG_F_STR_LIST, .flags = NCFG_FF_REQUIRED,
	    .offset = offsetof(ncfg_linkset_t, members),
	    .count_offset = offsetof(ncfg_linkset_t, member_count) }
};
static const ncfg_type_t linkset_type = TYPE("linkset", linkset_fields);

/* ------------------------------------------------------------------------ *
 * Host-wide policy
 * ------------------------------------------------------------------------ */

static int principal_read(const ncfg_json_doc_t *doc, uint32_t node, void *field, char *err,
    size_t err_size)
{
	ncfg_principal_t *principal = field;
	uint32_t          only;
	size_t            i;

	if (ncfg_json_type(doc, node) == NCFG_JSON_STRING) {
		for (i = 0; i < 2u; i++) {
			if (ncfg_json_string_equals(doc, node, principal_words[i])) {
				principal->kind = (int)i;
				return 1;
			}
		}
		ncfg_error_set(err, err_size, "a principal is root, any, a user or a group");
		return 0;
	}
	only = ncfg_field_only_member(doc, node);
	for (i = 2u; only != NCFG_JSON_NONE && i < COUNT_OF(principal_words); i++) {
		if (ncfg_json_member(doc, node, principal_words[i]) == only) {
			principal->kind = (int)i;
			free(principal->name);
			principal->name = ncfg_field_string(doc, only, "the name of a principal", err,
			    err_size);
			return principal->name != NULL;
		}
	}
	ncfg_error_set(err, err_size,
	    "a principal is `\"root\"`, `\"any\"`, `{\"user\": ...}` or `{\"group\": ...}`");
	return 0;
}

static void principal_write(ncfg_json_writer_t *writer, const void *field)
{
	const ncfg_principal_t *principal = field;

	if (principal->kind == NCFG_PRINCIPAL_USER || principal->kind == NCFG_PRINCIPAL_GROUP) {
		ncfg_json_write_object_begin(writer);
		ncfg_json_write_member_string(writer, principal_words[principal->kind],
		    principal->name);
		ncfg_json_write_object_end(writer);
		return;
	}
	if (principal->kind >= 0 && (size_t)principal->kind < COUNT_OF(principal_words)) {
		ncfg_json_write_string(writer, principal_words[principal->kind]);
	}
}

static void principal_release(void *field)
{
	ncfg_principal_t *principal = field;

	free(principal->name);
	principal->name = NULL;
}

static const ncfg_custom_t principal_custom = { principal_read, principal_write, NULL,
	principal_release, NULL };

static const ncfg_field_t control_fields[] = {
	{ .name = "observe", .kind = NCFG_F_CUSTOM, .custom = &principal_custom,
	    .offset = offsetof(ncfg_control_t, observe) },
	{ .name = "wifi", .kind = NCFG_F_CUSTOM, .custom = &principal_custom,
	    .offset = offsetof(ncfg_control_t, wifi) },
	{ .name = "admin", .kind = NCFG_F_CUSTOM, .custom = &principal_custom,
	    .offset = offsetof(ncfg_control_t, admin) }
};
static const ncfg_type_t control_type = TYPE("control policy", control_fields);

static const ncfg_field_t remote_fields[] = {
	{ .name = "observe", .kind = NCFG_F_BOOL, .offset = offsetof(ncfg_remote_policy_t, observe) },
	{ .name = "wifi", .kind = NCFG_F_BOOL, .offset = offsetof(ncfg_remote_policy_t, wifi) },
	{ .name = "admin", .kind = NCFG_F_BOOL, .offset = offsetof(ncfg_remote_policy_t, admin) },
	{ .name = "agent", .kind = NCFG_F_CUSTOM, .custom = &principal_custom,
	    .offset = offsetof(ncfg_remote_policy_t, agent) }
};
static const ncfg_type_t remote_type = TYPE("remote policy", remote_fields);

static const ncfg_field_t connectivity_fields[] = {
	{ .name = "requires", .kind = NCFG_F_ENUM, .choices = &requires_set,
	    .fallback = NCFG_REQUIRES_ROUTE,
	    .offset = offsetof(ncfg_connectivity_policy_t, requires_) },
	{ .name = "ignore", .kind = NCFG_F_STR_LIST,
	    .offset = offsetof(ncfg_connectivity_policy_t, ignore),
	    .count_offset = offsetof(ncfg_connectivity_policy_t, ignore_count) }
};
static const ncfg_type_t connectivity_type = TYPE("connectivity policy", connectivity_fields);

/* The five patterns a document that says nothing gets, materialised. */
static int connectivity_default_ignore(ncfg_connectivity_policy_t *policy)
{
	size_t i;

	policy->ignore = calloc(ncfg_connectivity_default_ignore_count, sizeof(*policy->ignore));
	if (!policy->ignore) {
		return 0;
	}
	policy->ignore_count = ncfg_connectivity_default_ignore_count;
	for (i = 0; i < policy->ignore_count; i++) {
		size_t length = strlen(ncfg_connectivity_default_ignore[i]) + 1u;

		policy->ignore[i] = malloc(length);
		if (!policy->ignore[i]) {
			return 0;
		}
		memcpy(policy->ignore[i], ncfg_connectivity_default_ignore[i], length);
	}
	return 1;
}

static int connectivity_init(void *field)
{
	return connectivity_default_ignore(field);
}

static int connectivity_read(const ncfg_json_doc_t *doc, uint32_t node, void *field, char *err,
    size_t err_size)
{
	ncfg_connectivity_policy_t *policy = field;
	int                         stated = ncfg_json_member(doc, node, "ignore") != NCFG_JSON_NONE;

	if (!ncfg_type_read(&connectivity_type, doc, node, policy, err, err_size)) {
		return 0;
	}
	/* Stating `ignore` **replaces** the default rather than adding to it, so
	 * an operator who needs one of those links counted can have it -- and a
	 * block that states none keeps all five. */
	if (!stated && !connectivity_default_ignore(policy)) {
		ncfg_error_set(err, err_size, "out of memory reading a connectivity policy");
		return 0;
	}
	return 1;
}

static void connectivity_write(ncfg_json_writer_t *writer, const void *field)
{
	ncfg_json_write_object_begin(writer);
	ncfg_type_write(&connectivity_type, writer, field);
	ncfg_json_write_object_end(writer);
}

/*
 * Written only where it says something the default does not.
 *
 * A machine that has never written a `connectivity` block has the same bytes
 * it had before the block existed, which is the rule every optional field in
 * this model follows and the one that keeps an upgrade from looking like a
 * configuration change.
 */
static int connectivity_omit(const void *field)
{
	const ncfg_connectivity_policy_t *policy = field;
	size_t                            i;

	if (policy->requires_ != NCFG_REQUIRES_ROUTE ||
	    policy->ignore_count != ncfg_connectivity_default_ignore_count) {
		return 0;
	}
	for (i = 0; i < policy->ignore_count; i++) {
		if (!policy->ignore[i] ||
		    strcmp(policy->ignore[i], ncfg_connectivity_default_ignore[i]) != 0) {
			return 0;
		}
	}
	return 1;
}

static void connectivity_release(void *field)
{
	ncfg_type_free(&connectivity_type, field);
}

static const ncfg_custom_t connectivity_custom = { connectivity_read, connectivity_write,
	connectivity_omit, connectivity_release, connectivity_init };

static int hostname_policy_read(const ncfg_json_doc_t *doc, uint32_t node, void *field,
    char *err, size_t err_size)
{
	ncfg_hostname_policy_t *policy = field;
	uint32_t                only;

	if (ncfg_json_type(doc, node) == NCFG_JSON_STRING) {
		size_t i;

		for (i = 0; i < 2u; i++) {
			if (ncfg_json_string_equals(doc, node, hostname_policy_words[i])) {
				policy->kind = (int)i;
				return 1;
			}
		}
		ncfg_error_set(err, err_size, "a hostname policy is none, from_dhcp or a static name");
		return 0;
	}
	only = ncfg_field_only_member(doc, node);
	if (only == NCFG_JSON_NONE ||
	    ncfg_json_member(doc, node, hostname_policy_words[2]) != only) {
		ncfg_error_set(err, err_size,
		    "a hostname policy is `\"none\"`, `\"from_dhcp\"` or `{\"static\": \"...\"}`");
		return 0;
	}
	policy->kind = NCFG_HOSTNAME_POLICY_STATIC;
	free(policy->name);
	policy->name = ncfg_field_string(doc, only, "a static hostname", err, err_size);
	return policy->name != NULL;
}

static void hostname_policy_write(ncfg_json_writer_t *writer, const void *field)
{
	const ncfg_hostname_policy_t *policy = field;

	if (policy->kind == NCFG_HOSTNAME_POLICY_STATIC) {
		ncfg_json_write_object_begin(writer);
		ncfg_json_write_member_string(writer, hostname_policy_words[2], policy->name);
		ncfg_json_write_object_end(writer);
		return;
	}
	if (policy->kind >= 0 && (size_t)policy->kind < COUNT_OF(hostname_policy_words)) {
		ncfg_json_write_string(writer, hostname_policy_words[policy->kind]);
	}
}

static void hostname_policy_release(void *field)
{
	ncfg_hostname_policy_t *policy = field;

	free(policy->name);
	policy->name = NULL;
}

static const ncfg_custom_t hostname_policy_custom = { hostname_policy_read,
	hostname_policy_write, NULL, hostname_policy_release, NULL };

static const ncfg_field_t globals_fields[] = {
	{ .name = "dns", .kind = NCFG_F_STRUCT, .type = &dns_policy_type,
	    .offset = offsetof(ncfg_globals_t, dns) },
	/* **`reconcile`, and it is not C's zero value.** A calloc'd document
	 * would mean `report` -- a daemon that watches its configuration go
	 * unimplemented and changes nothing, which is what every symptom of that
	 * milestone looked like. */
	{ .name = "on_drift_default", .kind = NCFG_F_ENUM, .choices = &drift_policy_set,
	    .fallback = NCFG_DRIFT_POLICY_RECONCILE,
	    .offset = offsetof(ncfg_globals_t, on_drift_default) },
	/* The one field in the model whose Rust counterpart has no
	 * `skip_serializing_if`, so it is written as `null` rather than omitted.
	 * The witness states a window, so only a comparison against the installed
	 * Rust on a machine that states none could have found it. */
	{ .name = "confirm_default", .kind = NCFG_F_OPT_INT, R_U32,
	    .flags = NCFG_FF_NULL_ABSENT,
	    .offset = offsetof(ncfg_globals_t, confirm_default) },
	{ .name = "networking", .kind = NCFG_F_ENUM, .choices = &networking_set,
	    .fallback = NCFG_NETWORKING_ON, .offset = offsetof(ncfg_globals_t, networking) },
	{ .name = "profile", .kind = NCFG_F_STR, .offset = offsetof(ncfg_globals_t, profile) },
	{ .name = "hostname_policy", .kind = NCFG_F_CUSTOM, .custom = &hostname_policy_custom,
	    .offset = offsetof(ncfg_globals_t, hostname_policy) },
	{ .name = "control", .kind = NCFG_F_STRUCT, .type = &control_type,
	    .offset = offsetof(ncfg_globals_t, control) },
	{ .name = "remote", .kind = NCFG_F_STRUCT, .type = &remote_type,
	    .offset = offsetof(ncfg_globals_t, remote) },
	{ .name = "connectivity", .kind = NCFG_F_CUSTOM, .custom = &connectivity_custom,
	    .offset = offsetof(ncfg_globals_t, connectivity) }
};
static const ncfg_type_t globals_type = TYPE("globals block", globals_fields);

static const ncfg_field_t document_fields[] = {
	{ .name = "schema_version", .kind = NCFG_F_STRUCT, .flags = NCFG_FF_REQUIRED,
	    .type = &version_type, .offset = offsetof(ncfg_document_t, schema_version) },
	{ .name = "generated_by", .kind = NCFG_F_STR,
	    .offset = offsetof(ncfg_document_t, generated_by) },
	{ .name = "globals", .kind = NCFG_F_STRUCT, .flags = NCFG_FF_REQUIRED, .type = &globals_type,
	    .offset = offsetof(ncfg_document_t, globals) },
	{ .name = "devices", .kind = NCFG_F_LIST, .flags = NCFG_FF_REQUIRED, .type = &device_type,
	    .element_size = sizeof(ncfg_device_t), .offset = offsetof(ncfg_document_t, devices),
	    .count_offset = offsetof(ncfg_document_t, device_count) },
	{ .name = "interfaces", .kind = NCFG_F_LIST, .flags = NCFG_FF_REQUIRED,
	    .type = &interface_type, .element_size = sizeof(ncfg_interface_t),
	    .offset = offsetof(ncfg_document_t, interfaces),
	    .count_offset = offsetof(ncfg_document_t, interface_count) },
	{ .name = "networks", .kind = NCFG_F_LIST, .flags = NCFG_FF_REQUIRED, .type = &network_type,
	    .element_size = sizeof(ncfg_wifi_network_t),
	    .offset = offsetof(ncfg_document_t, networks),
	    .count_offset = offsetof(ncfg_document_t, network_count) },
	{ .name = "bluetooth", .kind = NCFG_F_LIST, .flags = NCFG_FF_OMIT_EMPTY,
	    .type = &bluetooth_type, .element_size = sizeof(ncfg_bluetooth_device_t),
	    .offset = offsetof(ncfg_document_t, bluetooth),
	    .count_offset = offsetof(ncfg_document_t, bluetooth_count) },
	{ .name = "rules", .kind = NCFG_F_LIST, .type = &rule_type,
	    .element_size = sizeof(ncfg_routing_rule_t), .offset = offsetof(ncfg_document_t, rules),
	    .count_offset = offsetof(ncfg_document_t, rule_count) },
	{ .name = "access_points", .kind = NCFG_F_LIST, .type = &access_point_type,
	    .element_size = sizeof(ncfg_access_point_t),
	    .offset = offsetof(ncfg_document_t, access_points),
	    .count_offset = offsetof(ncfg_document_t, access_point_count) },
	{ .name = "linksets", .kind = NCFG_F_LIST, .flags = NCFG_FF_OMIT_EMPTY, .type = &linkset_type,
	    .element_size = sizeof(ncfg_linkset_t), .offset = offsetof(ncfg_document_t, linksets),
	    .count_offset = offsetof(ncfg_document_t, linkset_count) }
};
static const ncfg_type_t document_type = TYPE("document", document_fields);

/* ------------------------------------------------------------------------ *
 * The four operations
 * ------------------------------------------------------------------------ */

ncfg_document_t *ncfg_document_new(char *err, size_t err_size)
{
	ncfg_document_t *document = calloc(1, sizeof(*document));

	if (!document || !ncfg_type_init(&document_type, document)) {
		ncfg_error_set(err, err_size, "out of memory building an empty document");
		ncfg_document_free(document);
		return NULL;
	}
	document->schema_version.major = NCFG_SCHEMA_MAJOR;
	document->schema_version.minor = NCFG_SCHEMA_MINOR;
	return document;
}

void ncfg_document_free(ncfg_document_t *document)
{
	if (!document) {
		return;
	}
	ncfg_type_free(&document_type, document);
	free(document);
}

const ncfg_device_t *ncfg_document_device(const ncfg_document_t *document, const char *name)
{
	size_t i;

	if (!document || !name) {
		return NULL;
	}
	for (i = 0; i < document->device_count; i++) {
		if (document->devices[i].name && strcmp(document->devices[i].name, name) == 0) {
			return &document->devices[i];
		}
	}
	return NULL;
}

ncfg_document_t *ncfg_document_read(const char *text, size_t length, char *err, size_t err_size)
{
	ncfg_json_doc_t *json = ncfg_json_parse(text, length, err, err_size);
	ncfg_document_t *document;

	if (!json) {
		return NULL;
	}
	document = calloc(1, sizeof(*document));
	if (!document) {
		ncfg_json_free(json);
		ncfg_error_set(err, err_size, "out of memory reading a document");
		return NULL;
	}
	if (!ncfg_type_init(&document_type, document)) {
		ncfg_error_set(err, err_size, "out of memory reading a document");
		goto refused;
	}
	if (!ncfg_type_read(&document_type, json, ncfg_json_root(json), document, err, err_size)) {
		goto refused;
	}
	ncfg_json_free(json);
	if (!ncfg_document_validate(document, err, err_size)) {
		ncfg_document_free(document);
		return NULL;
	}
	return document;

refused:
	ncfg_json_free(json);
	ncfg_document_free(document);
	return NULL;
}

int ncfg_document_write(const ncfg_document_t *document, ncfg_buf_t *buf, char *err,
    size_t err_size)
{
	ncfg_json_writer_t writer;

	if (!document || !buf) {
		ncfg_error_set(err, err_size, "no document to write");
		return 0;
	}
	ncfg_json_write_init(&writer, buf);
	ncfg_json_write_object_begin(&writer);
	ncfg_type_write(&document_type, &writer, document);
	ncfg_json_write_object_end(&writer);
	if (!ncfg_json_write_done(&writer)) {
		const char *why = ncfg_json_write_failure(&writer);

		ncfg_error_set(err, err_size, "the document could not be written: %s",
		    why ? why : "it did not fit");
		return 0;
	}
	return 1;
}

int ncfg_document_write_canonical(ncfg_document_t *document, ncfg_buf_t *buf, char *err,
    size_t err_size)
{
	if (!document) {
		ncfg_error_set(err, err_size, "no document to write");
		return 0;
	}
	ncfg_document_canonicalize(document);
	if (!ncfg_document_validate(document, err, err_size)) {
		return 0;
	}
	return ncfg_document_write(document, buf, err, err_size);
}
