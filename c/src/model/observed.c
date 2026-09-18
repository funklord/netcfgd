/*
 * observed.c -- the observation: its tables, its tagged unions, and the
 * operations `observed.h` publishes.
 *
 * Every table below is `crates/netcfgd-model/src/observed.rs` read out field
 * by field -- **which member is required, which has a default, and which is
 * left out of the output when it is at that default.** That last one is not
 * cosmetic: `doc/schema/observed.json` is a frozen witness that has to be
 * blessed deliberately when it moves, so a field that starts writing itself
 * when it did not before re-blesses a witness for no change in what the
 * machine does.
 *
 * THE RUST'S THREE SHAPES, AND WHICH FLAG EACH ONE IS
 *
 *   A member with no serde attribute at all is **required**: `up`, `carrier`,
 *   `mtu`, an address's `ownership`, a rule's `action`.
 *
 *   `#[serde(default)]` alone is optional on the way in and **always written**
 *   on the way out. That is the pair a reader gets wrong most easily, because
 *   the two halves look like one statement and are not: a link's `kind` is a
 *   `String` and not an `Option<String>`, so an empty one writes `""` and does
 *   not vanish. `text_always` below is that one member's whole reason.
 *
 *   `skip_serializing_if` is what omits, and only that. `NCFG_FF_OMIT_EMPTY`
 *   is on exactly the lists the Rust marks `Vec::is_empty` and deliberately
 *   not on the others -- `"routes": []` goes on being written because an
 *   upgrade must not look like a configuration change.
 *
 * WHAT IS COPIED FROM document.c, AND WHY IT HAD TO BE
 *
 *   An address that is an address, a 32-octet key in base64, an SSID in
 *   lowercase hex, and the whole DNS-policy table are declared here a second
 *   time. They are private to `document.c` and that file belongs to somebody
 *   else, so there was no third choice: either this module reads a DNS policy
 *   with its own table or it cannot read the `dns` list at all.
 *
 *   **That is the hazard `field.h` opens with** -- a list that must agree with
 *   a struct and is maintained by hand does not stay agreeing -- so the
 *   agreement is not left to care. The witness carries a DNS policy with
 *   servers, a search list, an empty `domains` and an option; it carries an
 *   SSID, a device key and a peer key; and it carries addresses in a tunnel
 *   and a route. A member added to `ncfg_dns_policy_t` and missed here is a
 *   byte that does not match in `observed_test`, named with its offset. The
 *   right repair is for `document.c` to publish the table; until it does, the
 *   test is what holds the two copies together.
 */
#include "field.h"

#include "ncfg/observed.h"

#include <stdlib.h>
#include <string.h>

#define COUNT_OF(array) (sizeof(array) / sizeof((array)[0]))
#define WORD_SET(what_, table_) { what_, table_, COUNT_OF(table_), NULL, NULL }
#define VALUE_SET(what_, namer_, reader_) { what_, NULL, 0, namer_, reader_ }
#define TYPE(what_, fields_) { what_, fields_, COUNT_OF(fields_), NULL }

/* The Rust's own widths, checked on the way in so that nothing is lost by
 * storing every number as an `int64_t`. */
#define R_U8  .low = 0, .high = 255
#define R_U16 .low = 0, .high = 65535
#define R_U32 .low = 0, .high = 4294967295LL
/* A `u64` in the Rust; the reader's own integer is signed, so this is where
 * the two meet. No shaped rate comes near it. */
#define R_U64 .low = 0, .high = INT64_MAX

/* ------------------------------------------------------------------------ *
 * The sets value.h owns
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
VALUE_SHIM(ncfg_dns_mode, ncfg_dns_mode_t)

static const ncfg_enum_t hook_phase_set =
    VALUE_SET("hook phase", ncfg_hook_phase_word, ncfg_hook_phase_read);
static const ncfg_enum_t rule_action_set =
    VALUE_SET("rule action", ncfg_rule_action_word, ncfg_rule_action_read);
static const ncfg_enum_t rule_family_set =
    VALUE_SET("rule family", ncfg_rule_family_word, ncfg_rule_family_read);
static const ncfg_enum_t dns_mode_set =
    VALUE_SET("dns mode", ncfg_dns_mode_word, ncfg_dns_mode_read);

/* ------------------------------------------------------------------------ *
 * The sets this module owns
 *
 * Every word was read out of `observed.rs` and `link.rs` rather than
 * remembered. **`wire_guard` and `open_vpn` are here too**, for the same
 * `rename_all = "snake_case"` reason as the document's interface kinds and the
 * same pair this project has already shipped wrong twice.
 * ------------------------------------------------------------------------ */

static const char *const ownership_words[] = { "ours", "foreign", "unknown" };
static const ncfg_enum_t ownership_set = WORD_SET("ownership", ownership_words);

static const char *const origin_words[] = { "static", "dhcp4", "dhcp6", "slaac", "link_local",
	"delegated" };
static const ncfg_enum_t origin_set = WORD_SET("addressing origin", origin_words);

static const char *const backend_kind_words[] = { "dhcp4", "dhcp6", "supplicant",
	"access_point", "wire_guard", "pppoe", "open_vpn", "dns", "router_advert" };
static const ncfg_enum_t backend_kind_set = WORD_SET("backend kind", backend_kind_words);

static const char *const link_category_words[] = { "loopback", "ethernet", "wifi", "modem",
	"bridge", "bond", "vlan", "wireguard", "tunnel", "virtual", "linkset", "other" };
static const ncfg_enum_t link_category_set = WORD_SET("link category", link_category_words);

static const char *const presence_words[] = { "present", "absent", "unknown" };
static const ncfg_enum_t presence_set = WORD_SET("presence", presence_words);

static const char *const subject_words[] = { "interface", "network", "linkset" };
static const ncfg_enum_t subject_set = WORD_SET("row subject", subject_words);

static const char *const rung_words[] = { "offline", "local", "routed", "online" };
static const ncfg_enum_t rung_set = WORD_SET("connectivity rung", rung_words);

/* The JSON spellings, which are snake_case. `ncfg_ineligible_name` deliberately
 * answers with a different set of words -- see `observed_link.c`. */
static const char *const ineligible_words[] = { "absent", "unjoined", "no_carrier", "probe",
	"empty", "cycle" };
static const ncfg_enum_t ineligible_set = WORD_SET("ineligibility", ineligible_words);

static const char *const route_scope_words[] = { "global", "link", "host" };
static const ncfg_enum_t route_scope_set = WORD_SET("route scope", route_scope_words);

static const char *const acl_policy_words[] = { "deny", "allow" };
static const ncfg_enum_t acl_policy_set = WORD_SET("access control policy", acl_policy_words);

/* Copied from `document.c` with the DNS policy table below, and for the same
 * reason: that table is private there. */
static const char *const dnssec_words[] = { "no", "allow", "yes" };
static const ncfg_enum_t dnssec_set = WORD_SET("dnssec posture", dnssec_words);

static const char *const dns_transport_words[] = { "plain", "tls", "https" };
static const ncfg_enum_t dns_transport_set = WORD_SET("dns transport", dns_transport_words);

const char *ncfg_ownership_name(int ownership)
{
	return ncfg_field_enum_name(&ownership_set, ownership);
}

const char *ncfg_origin_name(int origin)
{
	return ncfg_field_enum_name(&origin_set, origin);
}

const char *ncfg_backend_kind_name(int kind)
{
	return ncfg_field_enum_name(&backend_kind_set, kind);
}

const char *ncfg_link_category_name(int category)
{
	return ncfg_field_enum_name(&link_category_set, category);
}

const char *ncfg_presence_name(int presence)
{
	return ncfg_field_enum_name(&presence_set, presence);
}

const char *ncfg_subject_name(int subject)
{
	return ncfg_field_enum_name(&subject_set, subject);
}

const char *ncfg_rung_name(int rung)
{
	return ncfg_field_enum_name(&rung_set, rung);
}

/* ------------------------------------------------------------------------ *
 * A string the Rust holds as a `String` and not an `Option<String>`
 *
 * One member: a link's `kind`. The engine's ordinary string omits a NULL, which
 * is right for every `Option<String>` here and wrong for this one -- an
 * observation of a plain ethernet card carries `"kind": ""`, and a reader that
 * dropped it would write a document the Rust cannot round-trip to.
 * ------------------------------------------------------------------------ */

static int text_always_read(const ncfg_json_doc_t *doc, uint32_t node, void *field, char *err,
    size_t err_size)
{
	char **slot = field;
	char  *text = ncfg_field_string(doc, node, "a link kind", err, err_size);

	if (!text) {
		return 0;
	}
	free(*slot);
	*slot = text;
	return 1;
}

static void text_always_write(ncfg_json_writer_t *writer, const void *field)
{
	char *const *slot = field;

	ncfg_json_write_string(writer, *slot ? *slot : "");
}

static void text_always_release(void *field)
{
	char **slot = field;

	free(*slot);
	*slot = NULL;
}

static const ncfg_custom_t text_always = { text_always_read, text_always_write, NULL,
	text_always_release, NULL };

/* ------------------------------------------------------------------------ *
 * An address that is an address, and never a prefix
 *
 * The Rust holds a tunnel endpoint and a route's next hop as `IpAddr`, so a
 * value carrying `/24` is refused by the parse rather than by a later check,
 * and what is written back is the address re-rendered. That re-rendering is
 * the point: `value.h`'s `ncfg_address_canonical` records what it cost when it
 * was missing -- a rule written `2001:0DB8::/32` was torn down and reinstalled
 * on every apply, for ever, because the comparison against what the kernel
 * reports is a string comparison.
 * ------------------------------------------------------------------------ */

static int address_text_read(const ncfg_json_doc_t *doc, uint32_t node, void *field, char *err,
    size_t err_size)
{
	char         **slot = field;
	ncfg_address_t address;
	char           rendered[NCFG_ADDRESS_MAX];
	char          *text = ncfg_field_string(doc, node, "an address", err, err_size);
	size_t         size;

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
	size = strlen(rendered) + 1u;
	free(*slot);
	*slot = malloc(size);
	if (!*slot) {
		ncfg_error_set(err, err_size, "out of memory reading an address");
		return 0;
	}
	memcpy(*slot, rendered, size);
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

static const ncfg_custom_t address_text = { address_text_read, address_text_write,
	address_text_omit, text_always_release, NULL };

/* ------------------------------------------------------------------------ *
 * A 32-octet key, in the base64 every WireGuard tool shows
 *
 * Held as octets and re-rendered rather than kept as text, because base64 has
 * more than one spelling of one key -- the final character carries four
 * significant bits -- and two spellings must compare equal for a plan to tell
 * "unchanged" from "different".
 * ------------------------------------------------------------------------ */

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

static int key_octets_read(const ncfg_json_doc_t *doc, uint32_t node, unsigned char *key,
    char *err, size_t err_size)
{
	size_t      length = 0;
	const char *text = ncfg_json_string(doc, node, &length);
	unsigned    accumulator = 0;
	unsigned    bits = 0;
	size_t      written = 0;
	size_t      i;

	/* 44 characters, the last of which is the one pad: 32 octets is not a
	 * multiple of three, which is where the single `=` comes from. */
	if (!text || length != 44u || text[43] != '=') {
		ncfg_error_set(err, err_size,
		    "a key is 44 characters of base64 ending in `=`, and this one is %zu",
		    text ? length : (size_t)0);
		return 0;
	}
	for (i = 0; i < 43u; i++) {
		unsigned digit = 0;

		if (!base64_value(text[i], &digit)) {
			ncfg_error_set(err, err_size, "a key is base64, and `%c` is not", text[i]);
			return 0;
		}
		accumulator = (accumulator << 6) | digit;
		bits += 6u;
		if (bits >= 8u) {
			bits -= 8u;
			if (written < 32u) {
				key[written++] = (unsigned char)((accumulator >> bits) & 0xffu);
			}
		}
	}
	/* The low two bits of the last character are not decoded. A key that sets
	 * them is still a valid key -- `wg` emits them -- so they are ignored
	 * rather than refused, and the re-rendering clears them. */
	if (written != 32u) {
		ncfg_error_set(err, err_size, "a key decodes to 32 octets, and this one to %zu",
		    written);
		return 0;
	}
	return 1;
}

static void key_octets_write(ncfg_json_writer_t *writer, const unsigned char *key)
{
	char   text[45];
	size_t at = 0;
	size_t i;

	for (i = 0; i < 32u; i += 3u) {
		size_t   have = 32u - i < 3u ? 32u - i : 3u;
		unsigned block = 0;
		size_t   j;

		for (j = 0; j < have; j++) {
			block |= (unsigned)key[i + j] << (16u - 8u * (unsigned)j);
		}
		for (j = 0; j < 4u; j++) {
			text[at++] = j < have + 1u ?
			    base64_alphabet[(block >> (18u - 6u * (unsigned)j)) & 0x3fu] : '=';
		}
	}
	text[at] = '\0';
	ncfg_json_write_string(writer, text);
}

static int public_key_read(const ncfg_json_doc_t *doc, uint32_t node, void *field, char *err,
    size_t err_size)
{
	return key_octets_read(doc, node, field, err, err_size);
}

static void public_key_write(ncfg_json_writer_t *writer, const void *field)
{
	key_octets_write(writer, field);
}

static const ncfg_custom_t public_key_custom = { public_key_read, public_key_write, NULL, NULL,
	NULL };

/* The device's own key, which is present exactly when a private key is loaded
 * -- so unlike a peer's it is an option and omits itself when absent. */
static int device_key_read(const ncfg_json_doc_t *doc, uint32_t node, void *field, char *err,
    size_t err_size)
{
	ncfg_observed_key_t *key = field;

	if (!key_octets_read(doc, node, key->bytes, err, err_size)) {
		return 0;
	}
	key->has = 1;
	return 1;
}

static void device_key_write(ncfg_json_writer_t *writer, const void *field)
{
	const ncfg_observed_key_t *key = field;

	key_octets_write(writer, key->bytes);
}

static int device_key_omit(const void *field)
{
	const ncfg_observed_key_t *key = field;

	return !key->has;
}

static const ncfg_custom_t device_key_custom = { device_key_read, device_key_write,
	device_key_omit, NULL, NULL };

/* ------------------------------------------------------------------------ *
 * An SSID: 0 to 32 arbitrary octets, in lowercase hex
 *
 * **Not a string.** 802.11 places no encoding requirement on an SSID and real
 * networks ship ones that are not valid UTF-8. Uppercase hex is refused on the
 * way in, because two spellings of one SSID would break the byte-identical
 * guarantee this module's witness rests on.
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
			char     digit = text[i + half];
			unsigned nibble;

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
	static const char  hex[] = "0123456789abcdef";
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

/* A running access point announces one or it is not an access point, so there
 * is nothing to omit and the required check is the table's. */
static const ncfg_custom_t ssid_custom = { ssid_read, ssid_write, NULL, NULL, NULL };

/* ------------------------------------------------------------------------ *
 * The DNS policy, copied from document.c because it is private there
 * ------------------------------------------------------------------------ */

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
 * The link vocabulary that travels in the observation
 * ------------------------------------------------------------------------ */

static const ncfg_field_t link_entry_fields[] = {
	{ .name = "name", .kind = NCFG_F_STR, .flags = NCFG_FF_REQUIRED,
	    .offset = offsetof(ncfg_link_entry_t, name) },
	{ .name = "category", .kind = NCFG_F_ENUM, .flags = NCFG_FF_REQUIRED,
	    .choices = &link_category_set, .offset = offsetof(ncfg_link_entry_t, category) },
	{ .name = "presence", .kind = NCFG_F_ENUM, .flags = NCFG_FF_REQUIRED,
	    .choices = &presence_set, .offset = offsetof(ncfg_link_entry_t, presence) },
	{ .name = "configured", .kind = NCFG_F_BOOL, .flags = NCFG_FF_REQUIRED,
	    .offset = offsetof(ncfg_link_entry_t, configured) },
	{ .name = "subject", .kind = NCFG_F_ENUM, .flags = NCFG_FF_REQUIRED, .choices = &subject_set,
	    .offset = offsetof(ncfg_link_entry_t, subject) },
	{ .name = "carrier", .kind = NCFG_F_STR, .offset = offsetof(ncfg_link_entry_t, carrier) },
	{ .name = "sets", .kind = NCFG_F_STR_LIST, .flags = NCFG_FF_OMIT_EMPTY,
	    .offset = offsetof(ncfg_link_entry_t, sets),
	    .count_offset = offsetof(ncfg_link_entry_t, set_count) }
};
static const ncfg_type_t link_entry_type = TYPE("link row", link_entry_fields);

static const ncfg_field_t standing_fields[] = {
	{ .name = "name", .kind = NCFG_F_STR, .flags = NCFG_FF_REQUIRED,
	    .offset = offsetof(ncfg_standing_t, name) },
	{ .name = "interface", .kind = NCFG_F_STR, .offset = offsetof(ncfg_standing_t, interface) },
	{ .name = "metric", .kind = NCFG_F_OPT_INT, R_U32,
	    .offset = offsetof(ncfg_standing_t, metric) },
	{ .name = "ineligible", .kind = NCFG_F_OPT_ENUM, .choices = &ineligible_set,
	    .offset = offsetof(ncfg_standing_t, ineligible) }
};
static const ncfg_type_t standing_type = TYPE("linkset member", standing_fields);

static const ncfg_field_t chosen_fields[] = {
	{ .name = "name", .kind = NCFG_F_STR, .flags = NCFG_FF_REQUIRED,
	    .offset = offsetof(ncfg_chosen_t, name) },
	{ .name = "active", .kind = NCFG_F_STR, .offset = offsetof(ncfg_chosen_t, active) },
	{ .name = "interface", .kind = NCFG_F_STR, .offset = offsetof(ncfg_chosen_t, interface) },
	{ .name = "members", .kind = NCFG_F_LIST, .flags = NCFG_FF_REQUIRED, .type = &standing_type,
	    .element_size = sizeof(ncfg_standing_t), .offset = offsetof(ncfg_chosen_t, members),
	    .count_offset = offsetof(ncfg_chosen_t, member_count) }
};
static const ncfg_type_t chosen_type = TYPE("linkset choice", chosen_fields);

static const ncfg_field_t primary_fields[] = {
	{ .name = "interface", .kind = NCFG_F_STR, .flags = NCFG_FF_REQUIRED,
	    .offset = offsetof(ncfg_primary_t, interface) },
	{ .name = "label", .kind = NCFG_F_STR, .flags = NCFG_FF_REQUIRED,
	    .offset = offsetof(ncfg_primary_t, label) },
	{ .name = "wireless", .kind = NCFG_F_BOOL, .flags = NCFG_FF_REQUIRED,
	    .offset = offsetof(ncfg_primary_t, wireless) }
};
static const ncfg_type_t primary_type = TYPE("primary link", primary_fields);

static const ncfg_field_t connectivity_fields[] = {
	{ .name = "rung", .kind = NCFG_F_ENUM, .flags = NCFG_FF_REQUIRED, .choices = &rung_set,
	    .offset = offsetof(ncfg_connectivity_t, rung) },
	{ .name = "primary", .kind = NCFG_F_OPT_STRUCT, .type = &primary_type,
	    .element_size = sizeof(ncfg_primary_t),
	    .offset = offsetof(ncfg_connectivity_t, primary) }
};
static const ncfg_type_t connectivity_type = TYPE("connectivity verdict", connectivity_fields);

/* ------------------------------------------------------------------------ *
 * The pieces of a link
 * ------------------------------------------------------------------------ */

static const ncfg_field_t rfkill_fields[] = {
	{ .name = "switch", .kind = NCFG_F_STR, .flags = NCFG_FF_REQUIRED,
	    .offset = offsetof(ncfg_observed_rfkill_t, switch_) },
	{ .name = "soft", .kind = NCFG_F_BOOL, .offset = offsetof(ncfg_observed_rfkill_t, soft) },
	{ .name = "hard", .kind = NCFG_F_BOOL, .offset = offsetof(ncfg_observed_rfkill_t, hard) }
};
static const ncfg_type_t rfkill_type = TYPE("rfkill switch", rfkill_fields);

static const ncfg_field_t accept_ra_fields[] = {
	{ .name = "value", .kind = NCFG_F_INT, .flags = NCFG_FF_REQUIRED, R_U8,
	    .offset = offsetof(ncfg_observed_accept_ra_t, value) },
	{ .name = "effective", .kind = NCFG_F_BOOL, .flags = NCFG_FF_REQUIRED,
	    .offset = offsetof(ncfg_observed_accept_ra_t, effective) }
};
static const ncfg_type_t accept_ra_type = TYPE("accept_ra state", accept_ra_fields);

static const ncfg_field_t observed_bond_fields[] = {
	{ .name = "mode", .kind = NCFG_F_STR, .offset = offsetof(ncfg_observed_bond_t, mode) },
	{ .name = "miimon", .kind = NCFG_F_OPT_INT, R_U32,
	    .offset = offsetof(ncfg_observed_bond_t, miimon) }
};
static const ncfg_type_t observed_bond_type = TYPE("observed bond", observed_bond_fields);

static const ncfg_field_t observed_bridge_fields[] = {
	{ .name = "stp", .kind = NCFG_F_BOOL, .offset = offsetof(ncfg_observed_bridge_t, stp) },
	{ .name = "forward_delay", .kind = NCFG_F_OPT_INT, R_U32,
	    .offset = offsetof(ncfg_observed_bridge_t, forward_delay) },
	{ .name = "hello_time", .kind = NCFG_F_OPT_INT, R_U32,
	    .offset = offsetof(ncfg_observed_bridge_t, hello_time) },
	{ .name = "ageing_time", .kind = NCFG_F_OPT_INT, R_U32,
	    .offset = offsetof(ncfg_observed_bridge_t, ageing_time) },
	{ .name = "priority", .kind = NCFG_F_OPT_INT, R_U16,
	    .offset = offsetof(ncfg_observed_bridge_t, priority) },
	{ .name = "vlan_filtering", .kind = NCFG_F_BOOL,
	    .offset = offsetof(ncfg_observed_bridge_t, vlan_filtering) }
};
static const ncfg_type_t observed_bridge_type = TYPE("observed bridge", observed_bridge_fields);

static const ncfg_field_t observed_macvlan_fields[] = {
	{ .name = "mode", .kind = NCFG_F_STR, .offset = offsetof(ncfg_observed_macvlan_t, mode) }
};
static const ncfg_type_t observed_macvlan_type =
    TYPE("observed macvlan", observed_macvlan_fields);

static const ncfg_field_t observed_vlan_fields[] = {
	{ .name = "id", .kind = NCFG_F_OPT_INT, R_U16,
	    .offset = offsetof(ncfg_observed_vlan_t, id) },
	{ .name = "protocol", .kind = NCFG_F_STR,
	    .offset = offsetof(ncfg_observed_vlan_t, protocol) }
};
static const ncfg_type_t observed_vlan_type = TYPE("observed vlan", observed_vlan_fields);

static const ncfg_field_t observed_tunnel_fields[] = {
	{ .name = "local", .kind = NCFG_F_CUSTOM, .custom = &address_text,
	    .offset = offsetof(ncfg_observed_tunnel_t, local) },
	{ .name = "remote", .kind = NCFG_F_CUSTOM, .custom = &address_text,
	    .offset = offsetof(ncfg_observed_tunnel_t, remote) },
	{ .name = "ttl", .kind = NCFG_F_OPT_INT, R_U8,
	    .offset = offsetof(ncfg_observed_tunnel_t, ttl) },
	{ .name = "key", .kind = NCFG_F_OPT_INT, R_U32,
	    .offset = offsetof(ncfg_observed_tunnel_t, key) }
};
static const ncfg_type_t observed_tunnel_type = TYPE("observed tunnel", observed_tunnel_fields);

static const ncfg_field_t observed_vxlan_fields[] = {
	{ .name = "id", .kind = NCFG_F_OPT_INT, R_U32,
	    .offset = offsetof(ncfg_observed_vxlan_t, id) },
	{ .name = "local", .kind = NCFG_F_CUSTOM, .custom = &address_text,
	    .offset = offsetof(ncfg_observed_vxlan_t, local) },
	{ .name = "remote", .kind = NCFG_F_CUSTOM, .custom = &address_text,
	    .offset = offsetof(ncfg_observed_vxlan_t, remote) },
	{ .name = "port", .kind = NCFG_F_OPT_INT, R_U16,
	    .offset = offsetof(ncfg_observed_vxlan_t, port) }
};
static const ncfg_type_t observed_vxlan_type = TYPE("observed vxlan", observed_vxlan_fields);

static const ncfg_field_t wg_peer_fields[] = {
	{ .name = "public_key", .kind = NCFG_F_CUSTOM, .flags = NCFG_FF_REQUIRED,
	    .custom = &public_key_custom, .offset = offsetof(ncfg_observed_wg_peer_t, public_key) },
	{ .name = "preshared_key", .kind = NCFG_F_BOOL, .flags = NCFG_FF_OMIT_FALSE,
	    .offset = offsetof(ncfg_observed_wg_peer_t, preshared_key) },
	{ .name = "preshared_matches", .kind = NCFG_F_OPT_BOOL,
	    .offset = offsetof(ncfg_observed_wg_peer_t, preshared_matches) },
	{ .name = "endpoint", .kind = NCFG_F_STR,
	    .offset = offsetof(ncfg_observed_wg_peer_t, endpoint) },
	{ .name = "allowed_ips", .kind = NCFG_F_STR_LIST, .flags = NCFG_FF_OMIT_EMPTY,
	    .offset = offsetof(ncfg_observed_wg_peer_t, allowed_ips),
	    .count_offset = offsetof(ncfg_observed_wg_peer_t, allowed_ip_count) },
	{ .name = "keepalive", .kind = NCFG_F_OPT_INT, R_U16,
	    .offset = offsetof(ncfg_observed_wg_peer_t, keepalive) }
};
static const ncfg_type_t wg_peer_type = TYPE("observed wireguard peer", wg_peer_fields);

static const ncfg_field_t observed_wireguard_fields[] = {
	{ .name = "public_key", .kind = NCFG_F_CUSTOM, .custom = &device_key_custom,
	    .offset = offsetof(ncfg_observed_wireguard_t, public_key) },
	{ .name = "listen_port", .kind = NCFG_F_OPT_INT, R_U16,
	    .offset = offsetof(ncfg_observed_wireguard_t, listen_port) },
	{ .name = "fwmark", .kind = NCFG_F_OPT_INT, R_U32,
	    .offset = offsetof(ncfg_observed_wireguard_t, fwmark) },
	{ .name = "key_matches", .kind = NCFG_F_OPT_BOOL,
	    .offset = offsetof(ncfg_observed_wireguard_t, key_matches) },
	{ .name = "peers", .kind = NCFG_F_LIST, .flags = NCFG_FF_OMIT_EMPTY, .type = &wg_peer_type,
	    .element_size = sizeof(ncfg_observed_wg_peer_t),
	    .offset = offsetof(ncfg_observed_wireguard_t, peers),
	    .count_offset = offsetof(ncfg_observed_wireguard_t, peer_count) }
};
static const ncfg_type_t observed_wireguard_type =
    TYPE("observed wireguard device", observed_wireguard_fields);

/* ------------------------------------------------------------------------ *
 * A link
 * ------------------------------------------------------------------------ */

static const ncfg_field_t observed_link_fields[] = {
	{ .name = "name", .kind = NCFG_F_STR, .flags = NCFG_FF_REQUIRED,
	    .offset = offsetof(ncfg_observed_link_t, name) },
	{ .name = "index", .kind = NCFG_F_INT, .flags = NCFG_FF_REQUIRED, R_U32,
	    .offset = offsetof(ncfg_observed_link_t, index) },
	{ .name = "kind", .kind = NCFG_F_CUSTOM, .custom = &text_always,
	    .offset = offsetof(ncfg_observed_link_t, kind) },
	{ .name = "wireless", .kind = NCFG_F_BOOL,
	    .offset = offsetof(ncfg_observed_link_t, wireless) },
	{ .name = "category", .kind = NCFG_F_OPT_ENUM, .choices = &link_category_set,
	    .offset = offsetof(ncfg_observed_link_t, category) },
	{ .name = "network", .kind = NCFG_F_STR,
	    .offset = offsetof(ncfg_observed_link_t, network) },
	{ .name = "up", .kind = NCFG_F_BOOL, .flags = NCFG_FF_REQUIRED,
	    .offset = offsetof(ncfg_observed_link_t, up) },
	{ .name = "carrier", .kind = NCFG_F_BOOL, .flags = NCFG_FF_REQUIRED,
	    .offset = offsetof(ncfg_observed_link_t, carrier) },
	{ .name = "reachable", .kind = NCFG_F_OPT_BOOL,
	    .offset = offsetof(ncfg_observed_link_t, reachable) },
	{ .name = "probe_detail", .kind = NCFG_F_STR,
	    .offset = offsetof(ncfg_observed_link_t, probe_detail) },
	{ .name = "mtu", .kind = NCFG_F_INT, .flags = NCFG_FF_REQUIRED, R_U32,
	    .offset = offsetof(ncfg_observed_link_t, mtu) },
	{ .name = "mac", .kind = NCFG_F_STR, .offset = offsetof(ncfg_observed_link_t, mac) },
	{ .name = "master", .kind = NCFG_F_STR, .offset = offsetof(ncfg_observed_link_t, master) },
	{ .name = "parent", .kind = NCFG_F_STR, .offset = offsetof(ncfg_observed_link_t, parent) },
	{ .name = "offloads", .kind = NCFG_F_STR_LIST,
	    .offset = offsetof(ncfg_observed_link_t, offloads),
	    .count_offset = offsetof(ncfg_observed_link_t, offload_count) },
	{ .name = "ipv6_token", .kind = NCFG_F_STR,
	    .offset = offsetof(ncfg_observed_link_t, ipv6_token) },
	{ .name = "qdisc", .kind = NCFG_F_STR, .offset = offsetof(ncfg_observed_link_t, qdisc) },
	{ .name = "qdisc_bandwidth_bits", .kind = NCFG_F_OPT_INT, R_U64,
	    .offset = offsetof(ncfg_observed_link_t, qdisc_bandwidth_bits) },
	{ .name = "qdisc_ingress", .kind = NCFG_F_BOOL,
	    .offset = offsetof(ncfg_observed_link_t, qdisc_ingress) },
	{ .name = "ingress_redirect", .kind = NCFG_F_STR,
	    .offset = offsetof(ncfg_observed_link_t, ingress_redirect) },
	{ .name = "forwarding", .kind = NCFG_F_OPT_BOOL,
	    .offset = offsetof(ncfg_observed_link_t, forwarding) },
	{ .name = "rfkill", .kind = NCFG_F_OPT_STRUCT, .type = &rfkill_type,
	    .element_size = sizeof(ncfg_observed_rfkill_t),
	    .offset = offsetof(ncfg_observed_link_t, rfkill) },
	{ .name = "privacy", .kind = NCFG_F_OPT_BOOL,
	    .offset = offsetof(ncfg_observed_link_t, privacy) },
	{ .name = "accept_ra", .kind = NCFG_F_OPT_STRUCT, .type = &accept_ra_type,
	    .element_size = sizeof(ncfg_observed_accept_ra_t),
	    .offset = offsetof(ncfg_observed_link_t, accept_ra) },
	/* Defaults to `unknown`, which is why a link nobody has a record of is
	 * never deleted -- and it is not this enum's zero value, so the fallback
	 * is spelled out. */
	{ .name = "ownership", .kind = NCFG_F_ENUM, .choices = &ownership_set,
	    .fallback = NCFG_OWNERSHIP_UNKNOWN,
	    .offset = offsetof(ncfg_observed_link_t, ownership) },
	{ .name = "private_key_loaded", .kind = NCFG_F_BOOL,
	    .offset = offsetof(ncfg_observed_link_t, private_key_loaded) },
	{ .name = "bond", .kind = NCFG_F_OPT_STRUCT, .type = &observed_bond_type,
	    .element_size = sizeof(ncfg_observed_bond_t),
	    .offset = offsetof(ncfg_observed_link_t, bond) },
	{ .name = "bridge", .kind = NCFG_F_OPT_STRUCT, .type = &observed_bridge_type,
	    .element_size = sizeof(ncfg_observed_bridge_t),
	    .offset = offsetof(ncfg_observed_link_t, bridge) },
	{ .name = "macvlan", .kind = NCFG_F_OPT_STRUCT, .type = &observed_macvlan_type,
	    .element_size = sizeof(ncfg_observed_macvlan_t),
	    .offset = offsetof(ncfg_observed_link_t, macvlan) },
	{ .name = "vlan", .kind = NCFG_F_OPT_STRUCT, .type = &observed_vlan_type,
	    .element_size = sizeof(ncfg_observed_vlan_t),
	    .offset = offsetof(ncfg_observed_link_t, vlan) },
	{ .name = "tunnel", .kind = NCFG_F_OPT_STRUCT, .type = &observed_tunnel_type,
	    .element_size = sizeof(ncfg_observed_tunnel_t),
	    .offset = offsetof(ncfg_observed_link_t, tunnel) },
	{ .name = "vxlan", .kind = NCFG_F_OPT_STRUCT, .type = &observed_vxlan_type,
	    .element_size = sizeof(ncfg_observed_vxlan_t),
	    .offset = offsetof(ncfg_observed_link_t, vxlan) },
	{ .name = "wireguard", .kind = NCFG_F_OPT_STRUCT, .type = &observed_wireguard_type,
	    .element_size = sizeof(ncfg_observed_wireguard_t),
	    .offset = offsetof(ncfg_observed_link_t, wireguard) }
};
static const ncfg_type_t observed_link_type = TYPE("observed link", observed_link_fields);

static const ncfg_field_t observed_bluetooth_fields[] = {
	{ .name = "name", .kind = NCFG_F_STR, .flags = NCFG_FF_REQUIRED,
	    .offset = offsetof(ncfg_observed_bluetooth_t, name) },
	{ .name = "rfkill", .kind = NCFG_F_OPT_STRUCT, .type = &rfkill_type,
	    .element_size = sizeof(ncfg_observed_rfkill_t),
	    .offset = offsetof(ncfg_observed_bluetooth_t, rfkill) }
};
static const ncfg_type_t observed_bluetooth_type =
    TYPE("bluetooth adapter", observed_bluetooth_fields);

/* ------------------------------------------------------------------------ *
 * Addresses, routes, rules, bridge VLANs
 * ------------------------------------------------------------------------ */

static const ncfg_field_t observed_address_fields[] = {
	{ .name = "interface", .kind = NCFG_F_STR, .flags = NCFG_FF_REQUIRED,
	    .offset = offsetof(ncfg_observed_address_t, interface) },
	{ .name = "address", .kind = NCFG_F_STR, .flags = NCFG_FF_REQUIRED,
	    .offset = offsetof(ncfg_observed_address_t, address) },
	{ .name = "proto", .kind = NCFG_F_OPT_INT, R_U8,
	    .offset = offsetof(ncfg_observed_address_t, proto) },
	/* Required here and defaulted on a link, which is the Rust's own
	 * asymmetry: an address's ownership is read from `IFA_PROTO` or from the
	 * `/run` fallback, and either way somebody has decided. */
	{ .name = "ownership", .kind = NCFG_F_ENUM, .flags = NCFG_FF_REQUIRED,
	    .choices = &ownership_set, .offset = offsetof(ncfg_observed_address_t, ownership) },
	{ .name = "origin", .kind = NCFG_F_OPT_ENUM, .choices = &origin_set,
	    .offset = offsetof(ncfg_observed_address_t, origin) }
};
static const ncfg_type_t observed_address_type =
    TYPE("observed address", observed_address_fields);

static const ncfg_field_t observed_route_fields[] = {
	{ .name = "interface", .kind = NCFG_F_STR, .flags = NCFG_FF_REQUIRED,
	    .offset = offsetof(ncfg_observed_route_t, interface) },
	{ .name = "destination", .kind = NCFG_F_STR, .flags = NCFG_FF_REQUIRED,
	    .offset = offsetof(ncfg_observed_route_t, destination) },
	{ .name = "via", .kind = NCFG_F_CUSTOM, .custom = &address_text,
	    .offset = offsetof(ncfg_observed_route_t, via) },
	{ .name = "metric", .kind = NCFG_F_OPT_INT, R_U32,
	    .offset = offsetof(ncfg_observed_route_t, metric) },
	{ .name = "table", .kind = NCFG_F_OPT_INT, R_U32,
	    .offset = offsetof(ncfg_observed_route_t, table) },
	{ .name = "src", .kind = NCFG_F_CUSTOM, .custom = &address_text,
	    .offset = offsetof(ncfg_observed_route_t, src) },
	{ .name = "scope", .kind = NCFG_F_OPT_ENUM, .choices = &route_scope_set,
	    .offset = offsetof(ncfg_observed_route_t, scope) },
	{ .name = "proto", .kind = NCFG_F_OPT_INT, R_U8,
	    .offset = offsetof(ncfg_observed_route_t, proto) },
	{ .name = "ownership", .kind = NCFG_F_ENUM, .flags = NCFG_FF_REQUIRED,
	    .choices = &ownership_set, .offset = offsetof(ncfg_observed_route_t, ownership) },
	{ .name = "origin", .kind = NCFG_F_OPT_ENUM, .choices = &origin_set,
	    .offset = offsetof(ncfg_observed_route_t, origin) }
};
static const ncfg_type_t observed_route_type = TYPE("observed route", observed_route_fields);

static const ncfg_field_t observed_rule_fields[] = {
	{ .name = "priority", .kind = NCFG_F_INT, .flags = NCFG_FF_REQUIRED, R_U32,
	    .offset = offsetof(ncfg_observed_rule_t, priority) },
	{ .name = "family", .kind = NCFG_F_ENUM, .flags = NCFG_FF_REQUIRED,
	    .choices = &rule_family_set, .offset = offsetof(ncfg_observed_rule_t, family) },
	{ .name = "from", .kind = NCFG_F_STR, .offset = offsetof(ncfg_observed_rule_t, from) },
	{ .name = "to", .kind = NCFG_F_STR, .offset = offsetof(ncfg_observed_rule_t, to) },
	{ .name = "iif", .kind = NCFG_F_STR, .offset = offsetof(ncfg_observed_rule_t, iif) },
	{ .name = "oif", .kind = NCFG_F_STR, .offset = offsetof(ncfg_observed_rule_t, oif) },
	{ .name = "fwmark", .kind = NCFG_F_OPT_INT, R_U32,
	    .offset = offsetof(ncfg_observed_rule_t, fwmark) },
	{ .name = "fwmask", .kind = NCFG_F_OPT_INT, R_U32,
	    .offset = offsetof(ncfg_observed_rule_t, fwmask) },
	{ .name = "table", .kind = NCFG_F_OPT_INT, R_U32,
	    .offset = offsetof(ncfg_observed_rule_t, table) },
	{ .name = "action", .kind = NCFG_F_ENUM, .flags = NCFG_FF_REQUIRED,
	    .choices = &rule_action_set, .offset = offsetof(ncfg_observed_rule_t, action) },
	{ .name = "suppress_prefixlength", .kind = NCFG_F_OPT_INT, R_U32,
	    .offset = offsetof(ncfg_observed_rule_t, suppress_prefixlength) },
	{ .name = "l3mdev", .kind = NCFG_F_BOOL,
	    .offset = offsetof(ncfg_observed_rule_t, l3mdev) },
	{ .name = "invert", .kind = NCFG_F_BOOL,
	    .offset = offsetof(ncfg_observed_rule_t, invert) },
	{ .name = "ownership", .kind = NCFG_F_ENUM, .flags = NCFG_FF_REQUIRED,
	    .choices = &ownership_set, .offset = offsetof(ncfg_observed_rule_t, ownership) }
};
static const ncfg_type_t observed_rule_type = TYPE("observed routing rule", observed_rule_fields);

static const ncfg_field_t bridge_vlan_fields[] = {
	{ .name = "index", .kind = NCFG_F_INT, .flags = NCFG_FF_REQUIRED, R_U32,
	    .offset = offsetof(ncfg_observed_bridge_vlan_t, index) },
	{ .name = "vid", .kind = NCFG_F_INT, .flags = NCFG_FF_REQUIRED, R_U16,
	    .offset = offsetof(ncfg_observed_bridge_vlan_t, vid) },
	{ .name = "pvid", .kind = NCFG_F_BOOL, .flags = NCFG_FF_REQUIRED,
	    .offset = offsetof(ncfg_observed_bridge_vlan_t, pvid) },
	{ .name = "untagged", .kind = NCFG_F_BOOL, .flags = NCFG_FF_REQUIRED,
	    .offset = offsetof(ncfg_observed_bridge_vlan_t, untagged) }
};
static const ncfg_type_t bridge_vlan_type = TYPE("observed bridge vlan", bridge_vlan_fields);

/* ------------------------------------------------------------------------ *
 * What netcfgd was told rather than read
 * ------------------------------------------------------------------------ */

static const ncfg_field_t delegation_fields[] = {
	{ .name = "interface", .kind = NCFG_F_STR, .flags = NCFG_FF_REQUIRED,
	    .offset = offsetof(ncfg_delegation_t, interface) },
	{ .name = "prefixes", .kind = NCFG_F_STR_LIST, .flags = NCFG_FF_REQUIRED,
	    .offset = offsetof(ncfg_delegation_t, prefixes),
	    .count_offset = offsetof(ncfg_delegation_t, prefix_count) }
};
static const ncfg_type_t delegation_type = TYPE("delegation", delegation_fields);

static const ncfg_field_t reported_route_fields[] = {
	{ .name = "destination", .kind = NCFG_F_STR, .flags = NCFG_FF_REQUIRED,
	    .offset = offsetof(ncfg_reported_route_t, destination) },
	/* A plain string and deliberately not an address: parsing it here would
	 * put the refusal where the operator cannot see which line of whose file
	 * was wrong. */
	{ .name = "via", .kind = NCFG_F_STR, .offset = offsetof(ncfg_reported_route_t, via) }
};
static const ncfg_type_t reported_route_type = TYPE("reported route", reported_route_fields);

static const ncfg_field_t observed_report_fields[] = {
	{ .name = "interface", .kind = NCFG_F_STR, .flags = NCFG_FF_REQUIRED,
	    .offset = offsetof(ncfg_observed_report_t, interface) },
	{ .name = "addresses", .kind = NCFG_F_STR_LIST, .flags = NCFG_FF_REQUIRED,
	    .offset = offsetof(ncfg_observed_report_t, addresses),
	    .count_offset = offsetof(ncfg_observed_report_t, address_count) },
	{ .name = "gateways", .kind = NCFG_F_STR_LIST, .flags = NCFG_FF_REQUIRED,
	    .offset = offsetof(ncfg_observed_report_t, gateways),
	    .count_offset = offsetof(ncfg_observed_report_t, gateway_count) },
	{ .name = "nameservers", .kind = NCFG_F_STR_LIST, .flags = NCFG_FF_REQUIRED,
	    .offset = offsetof(ncfg_observed_report_t, nameservers),
	    .count_offset = offsetof(ncfg_observed_report_t, nameserver_count) },
	{ .name = "search", .kind = NCFG_F_STR_LIST, .flags = NCFG_FF_OMIT_EMPTY,
	    .offset = offsetof(ncfg_observed_report_t, search),
	    .count_offset = offsetof(ncfg_observed_report_t, search_count) },
	/* Defaulted on the way in so a report written before this existed still
	 * parses, and written even when empty because the Rust does not skip it. */
	{ .name = "routes", .kind = NCFG_F_LIST, .type = &reported_route_type,
	    .element_size = sizeof(ncfg_reported_route_t),
	    .offset = offsetof(ncfg_observed_report_t, routes),
	    .count_offset = offsetof(ncfg_observed_report_t, route_count) },
	{ .name = "iccid", .kind = NCFG_F_STR, .offset = offsetof(ncfg_observed_report_t, iccid) },
	{ .name = "sim", .kind = NCFG_F_STR, .offset = offsetof(ncfg_observed_report_t, sim) }
};
static const ncfg_type_t observed_report_type = TYPE("interface report", observed_report_fields);

/* ------------------------------------------------------------------------ *
 * Backends, and the one tagged union in this module
 * ------------------------------------------------------------------------ */

/*
 * `unset` and `unknown` are bare words; `set` carries the policy it is
 * enforcing, so it arrives as `{"set": "deny"}` -- serde's external tagging of
 * an enum with one payload-carrying variant.
 *
 * Three answers rather than an option, because the two ways of having no
 * policy lead to opposite actions: `unset` may be reported and converged
 * against, `unknown` may not.
 */
static int observed_policy_read(const ncfg_json_doc_t *doc, uint32_t node, void *field,
    char *err, size_t err_size)
{
	ncfg_observed_policy_t *value = field;
	uint32_t                only;
	int                     policy = 0;

	if (ncfg_json_type(doc, node) == NCFG_JSON_STRING) {
		if (ncfg_json_string_equals(doc, node, "unset")) {
			value->kind = NCFG_OBSERVED_POLICY_UNSET;
			return 1;
		}
		if (ncfg_json_string_equals(doc, node, "unknown")) {
			value->kind = NCFG_OBSERVED_POLICY_UNKNOWN;
			return 1;
		}
		ncfg_error_set(err, err_size,
		    "an access point policy is `unset`, `unknown`, or `{\"set\": ...}`");
		return 0;
	}
	only = ncfg_field_only_member(doc, node);
	if (only == NCFG_JSON_NONE || ncfg_json_member(doc, node, "set") != only) {
		ncfg_error_set(err, err_size,
		    "an access point policy is `unset`, `unknown`, or `{\"set\": ...}`");
		return 0;
	}
	if (!ncfg_field_enum(&acl_policy_set, doc, only, &policy, err, err_size)) {
		return 0;
	}
	value->kind = NCFG_OBSERVED_POLICY_SET;
	value->policy = policy;
	return 1;
}

static void observed_policy_write(ncfg_json_writer_t *writer, const void *field)
{
	const ncfg_observed_policy_t *value = field;
	const char                   *word;

	if (value->kind == NCFG_OBSERVED_POLICY_SET) {
		word = ncfg_field_enum_name(&acl_policy_set, value->policy);
		ncfg_json_write_object_begin(writer);
		if (word) {
			ncfg_json_write_member_string(writer, "set", word);
		}
		ncfg_json_write_object_end(writer);
		return;
	}
	/* A plausible word for a value that is not one is worse than no word, and
	 * the writer's own rule then makes the observation unfinishable rather
	 * than letting half of one be sent. */
	if (value->kind == NCFG_OBSERVED_POLICY_UNSET) {
		ncfg_json_write_string(writer, "unset");
	} else if (value->kind == NCFG_OBSERVED_POLICY_UNKNOWN) {
		ncfg_json_write_string(writer, "unknown");
	}
}

static const ncfg_custom_t observed_policy_custom = { observed_policy_read,
	observed_policy_write, NULL, NULL, NULL };

static const ncfg_field_t access_control_fields[] = {
	{ .name = "policy", .kind = NCFG_F_CUSTOM, .flags = NCFG_FF_REQUIRED,
	    .custom = &observed_policy_custom,
	    .offset = offsetof(ncfg_observed_access_control_t, policy) },
	{ .name = "denied", .kind = NCFG_F_STR_LIST, .flags = NCFG_FF_REQUIRED,
	    .offset = offsetof(ncfg_observed_access_control_t, denied),
	    .count_offset = offsetof(ncfg_observed_access_control_t, denied_count) },
	{ .name = "accepted", .kind = NCFG_F_STR_LIST, .flags = NCFG_FF_REQUIRED,
	    .offset = offsetof(ncfg_observed_access_control_t, accepted),
	    .count_offset = offsetof(ncfg_observed_access_control_t, accepted_count) }
};
static const ncfg_type_t access_control_type =
    TYPE("observed access control", access_control_fields);

static const ncfg_field_t observed_access_point_fields[] = {
	{ .name = "ssid", .kind = NCFG_F_CUSTOM, .flags = NCFG_FF_REQUIRED, .custom = &ssid_custom,
	    .offset = offsetof(ncfg_observed_access_point_t, ssid) },
	{ .name = "band", .kind = NCFG_F_STR,
	    .offset = offsetof(ncfg_observed_access_point_t, band) },
	{ .name = "channel", .kind = NCFG_F_OPT_INT, R_U16,
	    .offset = offsetof(ncfg_observed_access_point_t, channel) },
	{ .name = "key_mgmt", .kind = NCFG_F_STR,
	    .offset = offsetof(ncfg_observed_access_point_t, key_mgmt) },
	{ .name = "hidden", .kind = NCFG_F_BOOL,
	    .offset = offsetof(ncfg_observed_access_point_t, hidden) },
	{ .name = "regdom", .kind = NCFG_F_STR,
	    .offset = offsetof(ncfg_observed_access_point_t, regdom) }
};
static const ncfg_type_t observed_access_point_type =
    TYPE("running access point", observed_access_point_fields);

static const ncfg_field_t observed_backend_fields[] = {
	{ .name = "kind", .kind = NCFG_F_ENUM, .flags = NCFG_FF_REQUIRED,
	    .choices = &backend_kind_set, .offset = offsetof(ncfg_observed_backend_t, kind) },
	{ .name = "interface", .kind = NCFG_F_STR, .flags = NCFG_FF_REQUIRED,
	    .offset = offsetof(ncfg_observed_backend_t, interface) },
	{ .name = "running", .kind = NCFG_F_BOOL, .flags = NCFG_FF_REQUIRED,
	    .offset = offsetof(ncfg_observed_backend_t, running) },
	{ .name = "answering", .kind = NCFG_F_OPT_BOOL,
	    .offset = offsetof(ncfg_observed_backend_t, answering) },
	{ .name = "access_control", .kind = NCFG_F_OPT_STRUCT, .type = &access_control_type,
	    .element_size = sizeof(ncfg_observed_access_control_t),
	    .offset = offsetof(ncfg_observed_backend_t, access_control) },
	{ .name = "started_metric", .kind = NCFG_F_OPT_INT, R_U32,
	    .offset = offsetof(ncfg_observed_backend_t, started_metric) },
	{ .name = "started_with", .kind = NCFG_F_OPT_STRUCT, .type = &observed_access_point_type,
	    .element_size = sizeof(ncfg_observed_access_point_t),
	    .offset = offsetof(ncfg_observed_backend_t, started_with) },
	{ .name = "secret_matches", .kind = NCFG_F_OPT_BOOL,
	    .offset = offsetof(ncfg_observed_backend_t, secret_matches) },
	{ .name = "networks_match", .kind = NCFG_F_OPT_BOOL,
	    .offset = offsetof(ncfg_observed_backend_t, networks_match) },
	{ .name = "config_matches", .kind = NCFG_F_OPT_BOOL,
	    .offset = offsetof(ncfg_observed_backend_t, config_matches) },
	{ .name = "config_present", .kind = NCFG_F_OPT_BOOL,
	    .offset = offsetof(ncfg_observed_backend_t, config_present) },
	{ .name = "advertised", .kind = NCFG_F_STR_LIST, .flags = NCFG_FF_OMIT_EMPTY,
	    .offset = offsetof(ncfg_observed_backend_t, advertised),
	    .count_offset = offsetof(ncfg_observed_backend_t, advertised_count) }
};
static const ncfg_type_t observed_backend_type = TYPE("backend", observed_backend_fields);

/*
 * `(kind, interface, count)`, which serde writes as a three-element array.
 *
 * A custom rather than a table, because a table reads members by name and this
 * has none: the tuple is positional, and a reader that accepted an object here
 * would accept something the Rust refuses.
 */
static int backend_restart_read(const ncfg_json_doc_t *doc, uint32_t node, void *field,
    char *err, size_t err_size)
{
	ncfg_backend_restart_t *entry = field;
	int64_t                 count = 0;
	int                     kind = 0;

	if (ncfg_json_type(doc, node) != NCFG_JSON_ARRAY || ncfg_json_count(doc, node) != 3u) {
		ncfg_error_set(err, err_size,
		    "a backend restart count is a list of a kind, an interface and a number");
		return 0;
	}
	if (!ncfg_field_enum(&backend_kind_set, doc, ncfg_json_at(doc, node, 0), &kind, err,
	    err_size)) {
		return 0;
	}
	free(entry->interface);
	entry->interface = ncfg_field_string(doc, ncfg_json_at(doc, node, 1),
	    "the interface of a backend restart count", err, err_size);
	if (!entry->interface) {
		return 0;
	}
	count = ncfg_json_int(doc, ncfg_json_at(doc, node, 2), -1);
	if (ncfg_json_type(doc, ncfg_json_at(doc, node, 2)) != NCFG_JSON_NUMBER || count < 0 ||
	    count > 4294967295LL) {
		ncfg_error_set(err, err_size,
		    "a backend restart count is a whole number from 0 to 4294967295");
		return 0;
	}
	entry->kind = kind;
	entry->count = count;
	return 1;
}

static void backend_restart_write(ncfg_json_writer_t *writer, const void *field)
{
	const ncfg_backend_restart_t *entry = field;
	const char                   *word = ncfg_field_enum_name(&backend_kind_set, entry->kind);

	ncfg_json_write_array_begin(writer);
	if (word) {
		ncfg_json_write_string(writer, word);
	}
	ncfg_json_write_string(writer, entry->interface);
	ncfg_json_write_int(writer, entry->count);
	ncfg_json_write_array_end(writer);
}

static void backend_restart_release(void *field)
{
	ncfg_backend_restart_t *entry = field;

	free(entry->interface);
	entry->interface = NULL;
}

static const ncfg_custom_t backend_restart_custom = { backend_restart_read,
	backend_restart_write, NULL, backend_restart_release, NULL };

static const ncfg_field_t applied_dns_fields[] = {
	{ .name = "scope", .kind = NCFG_F_STR, .flags = NCFG_FF_REQUIRED,
	    .offset = offsetof(ncfg_applied_dns_t, scope) },
	{ .name = "policy", .kind = NCFG_F_STRUCT, .flags = NCFG_FF_REQUIRED,
	    .type = &dns_policy_type, .offset = offsetof(ncfg_applied_dns_t, policy) }
};
static const ncfg_type_t applied_dns_type = TYPE("applied dns scope", applied_dns_fields);

static const ncfg_field_t hook_state_fields[] = {
	{ .name = "interface", .kind = NCFG_F_STR, .flags = NCFG_FF_REQUIRED,
	    .offset = offsetof(ncfg_observed_hook_state_t, interface) },
	{ .name = "phase", .kind = NCFG_F_ENUM, .flags = NCFG_FF_REQUIRED, .choices = &hook_phase_set,
	    .offset = offsetof(ncfg_observed_hook_state_t, phase) },
	{ .name = "value", .kind = NCFG_F_STR, .flags = NCFG_FF_REQUIRED,
	    .offset = offsetof(ncfg_observed_hook_state_t, value) }
};
static const ncfg_type_t hook_state_type = TYPE("hook state", hook_state_fields);

/* ------------------------------------------------------------------------ *
 * The observation
 *
 * `#[serde(default)]` on the struct itself, so **every member here is
 * optional**: a bare netlink snapshot carries a handful of these and an
 * observation written by an older netcfgd carries fewer still. That is the one
 * place this module is more permissive than the document, and it is the Rust's
 * choice rather than this port's.
 * ------------------------------------------------------------------------ */

static const ncfg_field_t observed_fields[] = {
	{ .name = "connectivity", .kind = NCFG_F_OPT_STRUCT, .type = &connectivity_type,
	    .element_size = sizeof(ncfg_connectivity_t),
	    .offset = offsetof(ncfg_observed_t, connectivity) },
	{ .name = "inventory", .kind = NCFG_F_LIST, .flags = NCFG_FF_OMIT_EMPTY,
	    .type = &link_entry_type, .element_size = sizeof(ncfg_link_entry_t),
	    .offset = offsetof(ncfg_observed_t, inventory),
	    .count_offset = offsetof(ncfg_observed_t, inventory_count) },
	{ .name = "linksets", .kind = NCFG_F_LIST, .flags = NCFG_FF_OMIT_EMPTY, .type = &chosen_type,
	    .element_size = sizeof(ncfg_chosen_t), .offset = offsetof(ncfg_observed_t, linksets),
	    .count_offset = offsetof(ncfg_observed_t, linkset_count) },
	{ .name = "links", .kind = NCFG_F_LIST, .type = &observed_link_type,
	    .element_size = sizeof(ncfg_observed_link_t), .offset = offsetof(ncfg_observed_t, links),
	    .count_offset = offsetof(ncfg_observed_t, link_count) },
	{ .name = "bluetooth", .kind = NCFG_F_LIST, .flags = NCFG_FF_OMIT_EMPTY,
	    .type = &observed_bluetooth_type, .element_size = sizeof(ncfg_observed_bluetooth_t),
	    .offset = offsetof(ncfg_observed_t, bluetooth),
	    .count_offset = offsetof(ncfg_observed_t, bluetooth_count) },
	{ .name = "addresses", .kind = NCFG_F_LIST, .type = &observed_address_type,
	    .element_size = sizeof(ncfg_observed_address_t),
	    .offset = offsetof(ncfg_observed_t, addresses),
	    .count_offset = offsetof(ncfg_observed_t, address_count) },
	{ .name = "routes", .kind = NCFG_F_LIST, .type = &observed_route_type,
	    .element_size = sizeof(ncfg_observed_route_t),
	    .offset = offsetof(ncfg_observed_t, routes),
	    .count_offset = offsetof(ncfg_observed_t, route_count) },
	{ .name = "backends", .kind = NCFG_F_LIST, .type = &observed_backend_type,
	    .element_size = sizeof(ncfg_observed_backend_t),
	    .offset = offsetof(ncfg_observed_t, backends),
	    .count_offset = offsetof(ncfg_observed_t, backend_count) },
	{ .name = "dns", .kind = NCFG_F_LIST, .type = &applied_dns_type,
	    .element_size = sizeof(ncfg_applied_dns_t), .offset = offsetof(ncfg_observed_t, dns),
	    .count_offset = offsetof(ncfg_observed_t, dns_count) },
	{ .name = "rules", .kind = NCFG_F_LIST, .type = &observed_rule_type,
	    .element_size = sizeof(ncfg_observed_rule_t), .offset = offsetof(ncfg_observed_t, rules),
	    .count_offset = offsetof(ncfg_observed_t, rule_count) },
	{ .name = "bridge_vlans", .kind = NCFG_F_LIST, .type = &bridge_vlan_type,
	    .element_size = sizeof(ncfg_observed_bridge_vlan_t),
	    .offset = offsetof(ncfg_observed_t, bridge_vlans),
	    .count_offset = offsetof(ncfg_observed_t, bridge_vlan_count) },
	{ .name = "delegations", .kind = NCFG_F_LIST, .type = &delegation_type,
	    .element_size = sizeof(ncfg_delegation_t),
	    .offset = offsetof(ncfg_observed_t, delegations),
	    .count_offset = offsetof(ncfg_observed_t, delegation_count) },
	{ .name = "reports", .kind = NCFG_F_LIST, .type = &observed_report_type,
	    .element_size = sizeof(ncfg_observed_report_t),
	    .offset = offsetof(ncfg_observed_t, reports),
	    .count_offset = offsetof(ncfg_observed_t, report_count) },
	{ .name = "qdisc_applied", .kind = NCFG_F_STR_LIST,
	    .offset = offsetof(ncfg_observed_t, qdisc_applied),
	    .count_offset = offsetof(ncfg_observed_t, qdisc_applied_count) },
	{ .name = "ingress_applied", .kind = NCFG_F_STR_LIST,
	    .offset = offsetof(ncfg_observed_t, ingress_applied),
	    .count_offset = offsetof(ncfg_observed_t, ingress_applied_count) },
	{ .name = "privacy_applied", .kind = NCFG_F_STR_LIST,
	    .offset = offsetof(ncfg_observed_t, privacy_applied),
	    .count_offset = offsetof(ncfg_observed_t, privacy_applied_count) },
	{ .name = "backend_restarts", .kind = NCFG_F_LIST, .custom = &backend_restart_custom,
	    .element_size = sizeof(ncfg_backend_restart_t),
	    .offset = offsetof(ncfg_observed_t, backend_restarts),
	    .count_offset = offsetof(ncfg_observed_t, backend_restart_count) },
	{ .name = "accept_ra_applied", .kind = NCFG_F_STR_LIST,
	    .offset = offsetof(ncfg_observed_t, accept_ra_applied),
	    .count_offset = offsetof(ncfg_observed_t, accept_ra_applied_count) },
	{ .name = "forwarding_applied", .kind = NCFG_F_STR_LIST,
	    .offset = offsetof(ncfg_observed_t, forwarding_applied),
	    .count_offset = offsetof(ncfg_observed_t, forwarding_applied_count) },
	{ .name = "nat", .kind = NCFG_F_STR_LIST, .offset = offsetof(ncfg_observed_t, nat),
	    .count_offset = offsetof(ncfg_observed_t, nat_count) },
	{ .name = "nat_conflicts", .kind = NCFG_F_STR_LIST,
	    .offset = offsetof(ncfg_observed_t, nat_conflicts),
	    .count_offset = offsetof(ncfg_observed_t, nat_conflict_count) },
	{ .name = "hook_state", .kind = NCFG_F_LIST, .type = &hook_state_type,
	    .element_size = sizeof(ncfg_observed_hook_state_t),
	    .offset = offsetof(ncfg_observed_t, hook_state),
	    .count_offset = offsetof(ncfg_observed_t, hook_state_count) },
	{ .name = "hostname", .kind = NCFG_F_STR, .offset = offsetof(ncfg_observed_t, hostname) },
	{ .name = "address_proto_supported", .kind = NCFG_F_BOOL,
	    .offset = offsetof(ncfg_observed_t, address_proto_supported) }
};
static const ncfg_type_t observed_type = TYPE("observation", observed_fields);

/* ------------------------------------------------------------------------ *
 * The operations
 * ------------------------------------------------------------------------ */

ncfg_observed_t *ncfg_observed_new(char *err, size_t err_size)
{
	ncfg_observed_t *observed = calloc(1, sizeof(*observed));

	if (!observed || !ncfg_type_init(&observed_type, observed)) {
		ncfg_error_set(err, err_size, "out of memory building an empty observation");
		ncfg_observed_free(observed);
		return NULL;
	}
	return observed;
}

void ncfg_observed_free(ncfg_observed_t *observed)
{
	if (!observed) {
		return;
	}
	ncfg_type_free(&observed_type, observed);
	free(observed);
}

ncfg_observed_t *ncfg_observed_read(const char *text, size_t length, char *err, size_t err_size)
{
	ncfg_json_doc_t *json = ncfg_json_parse(text, length, err, err_size);
	ncfg_observed_t *observed;

	if (!json) {
		return NULL;
	}
	observed = calloc(1, sizeof(*observed));
	if (!observed) {
		ncfg_json_free(json);
		ncfg_error_set(err, err_size, "out of memory reading an observation");
		return NULL;
	}
	if (!ncfg_type_init(&observed_type, observed)) {
		ncfg_error_set(err, err_size, "out of memory reading an observation");
		goto refused;
	}
	if (!ncfg_type_read(&observed_type, json, ncfg_json_root(json), observed, err, err_size)) {
		goto refused;
	}
	ncfg_json_free(json);
	return observed;

refused:
	ncfg_json_free(json);
	ncfg_observed_free(observed);
	return NULL;
}

int ncfg_observed_write(const ncfg_observed_t *observed, ncfg_buf_t *buf, char *err,
    size_t err_size)
{
	ncfg_json_writer_t writer;

	if (!observed || !buf) {
		ncfg_error_set(err, err_size, "no observation to write");
		return 0;
	}
	ncfg_json_write_init(&writer, buf);
	ncfg_json_write_object_begin(&writer);
	ncfg_type_write(&observed_type, &writer, observed);
	ncfg_json_write_object_end(&writer);
	if (!ncfg_json_write_done(&writer)) {
		const char *why = ncfg_json_write_failure(&writer);

		ncfg_error_set(err, err_size, "the observation could not be written: %s",
		    why ? why : "it did not fit");
		return 0;
	}
	return 1;
}

int ncfg_observed_write_canonical(ncfg_observed_t *observed, ncfg_buf_t *buf, char *err,
    size_t err_size)
{
	if (!observed) {
		ncfg_error_set(err, err_size, "no observation to write");
		return 0;
	}
	ncfg_observed_canonicalize(observed);
	return ncfg_observed_write(observed, buf, err, err_size);
}

/* ------------------------------------------------------------------------ *
 * Two of these lists, published for the ownership record
 * ------------------------------------------------------------------------ */

/*
 * `owned.json` carries a backend list and a DNS scope list of exactly the
 * shapes above, because it is where the observation's own two come *from*.
 * These six calls are that, and they exist so that `src/host/state.c` reads
 * and writes them through the tables here rather than through a second copy:
 * a DNS policy codec written twice is the duplication 0263 forbids, and the
 * half that drifts is whichever one nobody is looking at.
 *
 * The element tables stay private. What is published is the list walk, which
 * is a loop rather than a codec -- `ncfg_type_read`, `ncfg_type_write` and
 * `ncfg_type_free` were already published for exactly this reason.
 */
static int read_elements(const ncfg_type_t *type, size_t element_size,
    const ncfg_json_doc_t *doc, uint32_t node, void **out, size_t *count_out, char *err,
    size_t err_size)
{
	const ncfg_json_node_t *array = ncfg_json_node(doc, node);
	uint32_t                child;
	size_t                  count;
	size_t                  index = 0;
	char                   *items;

	*out = NULL;
	*count_out = 0;
	if (!array || array->type != NCFG_JSON_ARRAY) {
		ncfg_error_set(err, err_size, "the %ss of this record are not a list", type->what);
		return 0;
	}
	count = array->child_count;
	if (count == 0) {
		return 1;
	}
	items = calloc(count, element_size);
	if (!items) {
		ncfg_error_set(err, err_size, "out of memory reading %zu recorded %s(s)", count,
		    type->what);
		return 0;
	}
	/*
	 * Both handed to the caller before an element is read, so that a failure
	 * half way leaves a list the caller's own free walk can still take apart
	 * -- `read_list` in `field.c` does the same thing for the same reason.
	 */
	*out = items;
	*count_out = count;
	for (child = array->first_child; child != NCFG_JSON_NONE; index++) {
		const ncfg_json_node_t *element = ncfg_json_node(doc, child);
		void                   *slot = items + index * element_size;

		if (!element || index >= count) {
			ncfg_error_set(err, err_size,
			    "the %ss of this record are a list that changed under the reader",
			    type->what);
			return 0;
		}
		if (!ncfg_type_init(type, slot)) {
			ncfg_error_set(err, err_size, "out of memory reading a recorded %s",
			    type->what);
			return 0;
		}
		if (!ncfg_type_read(type, doc, child, slot, err, err_size)) {
			return 0;
		}
		child = element->next_sibling;
	}
	return 1;
}

static void write_elements(const ncfg_type_t *type, size_t element_size,
    ncfg_json_writer_t *writer, const void *items, size_t count)
{
	size_t index;

	ncfg_json_write_array_begin(writer);
	for (index = 0; items && index < count; index++) {
		const char *slot = (const char *)items + index * element_size;

		ncfg_json_write_object_begin(writer);
		ncfg_type_write(type, writer, slot);
		ncfg_json_write_object_end(writer);
	}
	ncfg_json_write_array_end(writer);
}

static void free_elements(const ncfg_type_t *type, size_t element_size, void *items, size_t count)
{
	size_t index;

	for (index = 0; items && index < count; index++) {
		ncfg_type_free(type, (char *)items + index * element_size);
	}
	free(items);
}

int ncfg_observed_backends_read(const ncfg_json_doc_t *doc, uint32_t node,
    ncfg_observed_backend_t **out, size_t *count_out, char *err, size_t err_size)
{
	if (!doc || !out || !count_out) {
		ncfg_error_set(err, err_size, "a backend list was asked for with nowhere to put it");
		return 0;
	}
	return read_elements(&observed_backend_type, sizeof(ncfg_observed_backend_t), doc, node,
	    (void **)out, count_out, err, err_size);
}

void ncfg_observed_backends_write(ncfg_json_writer_t *writer,
    const ncfg_observed_backend_t *backends, size_t count)
{
	if (!writer) {
		return;
	}
	write_elements(&observed_backend_type, sizeof(*backends), writer, backends, count);
}

void ncfg_observed_backends_free(ncfg_observed_backend_t *backends, size_t count)
{
	free_elements(&observed_backend_type, sizeof(*backends), backends, count);
}

void ncfg_observed_backend_free(ncfg_observed_backend_t *backend)
{
	if (!backend) {
		return;
	}
	ncfg_type_free(&observed_backend_type, backend);
}

int ncfg_applied_dns_read(const ncfg_json_doc_t *doc, uint32_t node, ncfg_applied_dns_t **out,
    size_t *count_out, char *err, size_t err_size)
{
	if (!doc || !out || !count_out) {
		ncfg_error_set(err, err_size,
		    "a list of delivered dns scopes was asked for with nowhere to put it");
		return 0;
	}
	return read_elements(&applied_dns_type, sizeof(ncfg_applied_dns_t), doc, node, (void **)out,
	    count_out, err, err_size);
}

void ncfg_applied_dns_write(ncfg_json_writer_t *writer, const ncfg_applied_dns_t *dns,
    size_t count)
{
	if (!writer) {
		return;
	}
	write_elements(&applied_dns_type, sizeof(*dns), writer, dns, count);
}

void ncfg_applied_dns_free(ncfg_applied_dns_t *dns, size_t count)
{
	free_elements(&applied_dns_type, sizeof(*dns), dns, count);
}
