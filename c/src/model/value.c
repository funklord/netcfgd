/*
 * value.c -- the values described in value.h.
 */
#include "ncfg/value.h"

#include "ncfg/base.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

#define COUNT_OF(array) (sizeof(array) / sizeof((array)[0]))

/* ------------------------------------------------------------------------ *
 * The closed sets, as tables
 * ------------------------------------------------------------------------ */

/*
 * Every set is one array indexed by its enum, and the two directions share it.
 *
 * Not two `switch` statements, which is what the Rust has and what a first
 * port would write: there the compiler checks exhaustiveness and a forgotten
 * variant will not build, and here it would build and return NULL for the
 * variant nobody wrote an arm for. One table cannot disagree with itself, and
 * a variant added without its word is a hole the tests see immediately because
 * the round trip is what they check.
 */
static const char *const hook_phase_names[] = {
	"pre_up", "up", "post_up", "pre_down", "down", "post_down",
	"carrier", "lease", "roam", "portal", "drift"
};

static const char *const rule_action_names[] = {
	"lookup", "blackhole", "unreachable", "prohibit"
};

static const char *const rule_family_names[] = { "inet", "inet6" };

static const char *const bluetooth_profile_names[] = {
	"a2dp-sink", "a2dp-source", "hfp", "pan", "nap"
};

static const char *const drift_policy_names[] = { "report", "reconcile", "ignore" };

static const char *const dns_mode_names[] = {
	"none", "write_resolv_conf", "resolvconf", "openresolv", "resolved",
	"dnsmasq", "unbound", "exec"
};

static const char *name_of(const char *const *names, size_t count, unsigned int which)
{
	if ((size_t)which >= count) {
		return NULL;
	}
	return names[which];
}

/*
 * A word to its index, or 0 with the word and the alternatives said.
 *
 * **The list in the diagnostic is built from the table the match was made
 * against**, rather than written out beside it. A hand-written list is a
 * second copy of the spellings, and the copy that goes stale is always the one
 * in the error message -- so the operator who misspelled a word is told about
 * a set that no longer exists.
 */
static int value_of(const char *const *names, size_t count, const char *kind, const char *word,
    unsigned int *out, char *err, size_t err_size)
{
	char known[256];
	size_t at = 0;
	size_t i;

	if (word) {
		for (i = 0; i < count; i++) {
			if (strcmp(names[i], word) == 0) {
				*out = (unsigned int)i;
				return 1;
			}
		}
	}

	known[0] = '\0';
	for (i = 0; i < count; i++) {
		int written = snprintf(known + at, sizeof(known) - at, "%s%s",
		    at ? ", " : "", names[i]);

		if (written < 0 || (size_t)written >= sizeof(known) - at) {
			break;
		}
		at += (size_t)written;
	}
	ncfg_error_set(err, err_size, "`%s` is not a %s; the %ss are: %s", word ? word : "", kind,
	    kind, known);
	return 0;
}

const char *ncfg_hook_phase_name(ncfg_hook_phase_t phase)
{
	return name_of(hook_phase_names, COUNT_OF(hook_phase_names), (unsigned int)phase);
}

int ncfg_hook_phase_from_name(const char *name, ncfg_hook_phase_t *out, char *err, size_t err_size)
{
	unsigned int which;

	if (!out) {
		ncfg_error_set(err, err_size, "a hook phase was asked for with nowhere to put it");
		return 0;
	}
	if (!value_of(hook_phase_names, COUNT_OF(hook_phase_names), "hook phase", name, &which, err,
	    err_size)) {
		return 0;
	}
	*out = (ncfg_hook_phase_t)which;
	return 1;
}

const char *ncfg_rule_action_name(ncfg_rule_action_t action)
{
	return name_of(rule_action_names, COUNT_OF(rule_action_names), (unsigned int)action);
}

int ncfg_rule_action_from_name(const char *name, ncfg_rule_action_t *out, char *err,
    size_t err_size)
{
	unsigned int which;

	if (!out) {
		ncfg_error_set(err, err_size, "a rule action was asked for with nowhere to put it");
		return 0;
	}
	if (!value_of(rule_action_names, COUNT_OF(rule_action_names), "rule action", name, &which,
	    err, err_size)) {
		return 0;
	}
	*out = (ncfg_rule_action_t)which;
	return 1;
}

const char *ncfg_rule_family_name(ncfg_rule_family_t family)
{
	return name_of(rule_family_names, COUNT_OF(rule_family_names), (unsigned int)family);
}

int ncfg_rule_family_from_name(const char *name, ncfg_rule_family_t *out, char *err,
    size_t err_size)
{
	unsigned int which;

	if (!out) {
		ncfg_error_set(err, err_size, "a rule family was asked for with nowhere to put it");
		return 0;
	}
	if (!value_of(rule_family_names, COUNT_OF(rule_family_names), "rule family", name, &which,
	    err, err_size)) {
		return 0;
	}
	*out = (ncfg_rule_family_t)which;
	return 1;
}

const char *ncfg_bluetooth_profile_name(ncfg_bluetooth_profile_t profile)
{
	return name_of(bluetooth_profile_names, COUNT_OF(bluetooth_profile_names),
	    (unsigned int)profile);
}

int ncfg_bluetooth_profile_from_name(const char *name, ncfg_bluetooth_profile_t *out, char *err,
    size_t err_size)
{
	unsigned int which;

	if (!out) {
		ncfg_error_set(err, err_size,
		    "a bluetooth profile was asked for with nowhere to put it");
		return 0;
	}
	if (!value_of(bluetooth_profile_names, COUNT_OF(bluetooth_profile_names),
	    "bluetooth profile", name, &which, err, err_size)) {
		return 0;
	}
	*out = (ncfg_bluetooth_profile_t)which;
	return 1;
}

const char *ncfg_drift_policy_name(ncfg_drift_policy_t policy)
{
	return name_of(drift_policy_names, COUNT_OF(drift_policy_names), (unsigned int)policy);
}

int ncfg_drift_policy_from_name(const char *name, ncfg_drift_policy_t *out, char *err,
    size_t err_size)
{
	unsigned int which;

	if (!out) {
		ncfg_error_set(err, err_size, "a drift policy was asked for with nowhere to put it");
		return 0;
	}
	if (!value_of(drift_policy_names, COUNT_OF(drift_policy_names), "drift policy", name,
	    &which, err, err_size)) {
		return 0;
	}
	*out = (ncfg_drift_policy_t)which;
	return 1;
}

const char *ncfg_dns_mode_name(ncfg_dns_mode_t mode)
{
	return name_of(dns_mode_names, COUNT_OF(dns_mode_names), (unsigned int)mode);
}

int ncfg_dns_mode_from_name(const char *name, ncfg_dns_mode_t *out, char *err, size_t err_size)
{
	unsigned int which;

	if (!out) {
		ncfg_error_set(err, err_size, "a dns mode was asked for with nowhere to put it");
		return 0;
	}
	/* The file's own name, which `lower.rs` accepts beside the underscored
	 * spelling because that is what an operator reaches for. It is an alias
	 * and not a mode: `ncfg_dns_mode_name` renders the underscored one back,
	 * so a document that arrives spelled either way leaves spelled one way. */
	if (name && strcmp(name, "resolv.conf") == 0) {
		*out = NCFG_DNS_MODE_WRITE_RESOLV_CONF;
		return 1;
	}
	if (!value_of(dns_mode_names, COUNT_OF(dns_mode_names), "dns mode", name, &which, err,
	    err_size)) {
		return 0;
	}
	*out = (ncfg_dns_mode_t)which;
	return 1;
}

/* ------------------------------------------------------------------------ *
 * Addresses
 * ------------------------------------------------------------------------ */

int ncfg_address_parse(const char *text, ncfg_address_t *out, char *err, size_t err_size)
{
	ncfg_address_t parsed;
	char plain[INET6_ADDRSTRLEN];
	const char *slash;
	const char *digits;
	size_t length;
	size_t i;
	unsigned int max;
	int family;

	if (!out) {
		ncfg_error_set(err, err_size, "an address was asked for with nowhere to put it");
		return 0;
	}
	if (!text || !*text) {
		ncfg_error_set(err, err_size, "an empty string is not an address");
		return 0;
	}

	memset(&parsed, 0, sizeof(parsed));
	/* The first slash, so that `2001:db8::/32/24` fails on its prefix rather
	 * than parsing as something. `split_once` on the Rust side does the same. */
	slash = strchr(text, '/');
	length = slash ? (size_t)(slash - text) : strlen(text);
	if (length == 0 || length >= sizeof(plain)) {
		ncfg_error_set(err, err_size, "`%s` is not an IPv4 or IPv6 address", text);
		return 0;
	}
	memcpy(plain, text, length);
	plain[length] = '\0';

	/* A colon is the whole of the family question -- no IPv4 address has one
	 * and no IPv6 address lacks one -- and asking it this way means
	 * `inet_pton` is told which family to be strict about. Handing an IPv4
	 * text to the IPv6 parser and falling back would accept a different set
	 * of strings than the Rust does. */
	family = strchr(plain, ':') ? AF_INET6 : AF_INET;
	if (inet_pton(family, plain, parsed.bytes) != 1) {
		ncfg_error_set(err, err_size, "`%s` is not an IPv4 or IPv6 address", plain);
		return 0;
	}
	parsed.is_ipv6 = (family == AF_INET6);
	max = parsed.is_ipv6 ? 128u : 32u;

	if (slash) {
		digits = slash + 1;
		/* Leading zeros first, so `/024` reads as the 24 that Rust's
		 * `u8::from_str` makes of it. What is deliberately not accepted is
		 * the `+24` that same parser would take, or the whitespace and the
		 * sign `strtoul` would: a prefix length is digits, and a language
		 * that grows a spelling by accident cannot take it back. */
		while (*digits == '0' && digits[1] != '\0') {
			digits++;
		}
		length = strlen(digits);
		if (length == 0 || length > 3) {
			ncfg_error_set(err, err_size, "`%s` is not a prefix length", slash + 1);
			return 0;
		}
		for (i = 0; i < length; i++) {
			if (digits[i] < '0' || digits[i] > '9') {
				ncfg_error_set(err, err_size, "`%s` is not a prefix length",
				    slash + 1);
				return 0;
			}
			parsed.prefix = parsed.prefix * 10u + (unsigned int)(digits[i] - '0');
		}
		if (parsed.prefix > max) {
			ncfg_error_set(err, err_size,
			    "a prefix length of /%u is out of range for %s, which goes up to /%u",
			    parsed.prefix, parsed.is_ipv6 ? "IPv6" : "IPv4", max);
			return 0;
		}
		parsed.has_prefix = 1;
	}

	*out = parsed;
	return 1;
}

int ncfg_address_render(const ncfg_address_t *address, char *out, size_t out_size, char *err,
    size_t err_size)
{
	char plain[INET6_ADDRSTRLEN];
	unsigned int max;
	int family;
	int written;

	if (!address || !out) {
		ncfg_error_set(err, err_size, "an address was asked to render into nothing");
		return 0;
	}
	/* Refused rather than truncated into. Half an address is still a string
	 * that looks like one, and it would be compared against the kernel's
	 * rendering exactly as though it were whole. */
	if (out_size < NCFG_ADDRESS_MAX) {
		ncfg_error_set(err, err_size,
		    "a buffer of %zu bytes cannot hold an address; NCFG_ADDRESS_MAX is %d",
		    out_size, NCFG_ADDRESS_MAX);
		return 0;
	}

	family = address->is_ipv6 ? AF_INET6 : AF_INET;
	max = address->is_ipv6 ? 128u : 32u;
	if (address->has_prefix && address->prefix > max) {
		ncfg_error_set(err, err_size,
		    "a prefix length of /%u is out of range for %s, which goes up to /%u",
		    address->prefix, address->is_ipv6 ? "IPv6" : "IPv4", max);
		return 0;
	}
	if (!inet_ntop(family, address->bytes, plain, (socklen_t)sizeof(plain))) {
		ncfg_error_set(err, err_size, "an address of %d bytes could not be rendered",
		    address->is_ipv6 ? 16 : 4);
		return 0;
	}

	if (address->has_prefix) {
		written = snprintf(out, out_size, "%s/%u", plain, address->prefix);
	} else {
		written = snprintf(out, out_size, "%s", plain);
	}
	if (written < 0 || (size_t)written >= out_size) {
		ncfg_error_set(err, err_size, "`%s` did not fit the buffer it was rendered into",
		    plain);
		return 0;
	}
	return 1;
}

int ncfg_address_canonical(const char *text, char *out, size_t out_size, char *err,
    size_t err_size)
{
	ncfg_address_t address;

	if (!ncfg_address_parse(text, &address, err, err_size)) {
		return 0;
	}
	return ncfg_address_render(&address, out, out_size, err, err_size);
}

/* ------------------------------------------------------------------------ *
 * Hardware addresses
 * ------------------------------------------------------------------------ */

/*
 * A hex digit's value, or -1.
 *
 * Written out rather than `isxdigit`, for two reasons that are the same
 * reason: that function's argument is an `int` holding an `unsigned char`, so
 * a plain `char` with the high bit set is the classic way a scanner reads off
 * the end of a table; and it answers for the current locale, while the set
 * this language accepts is ASCII and does not move.
 */
static int hex_value(char one)
{
	if (one >= '0' && one <= '9') {
		return one - '0';
	}
	if (one >= 'a' && one <= 'f') {
		return one - 'a' + 10;
	}
	if (one >= 'A' && one <= 'F') {
		return one - 'A' + 10;
	}
	return -1;
}

static char hex_digit(int value)
{
	static const char digits[] = "0123456789ABCDEF";

	return digits[value & 0xf];
}

/* What `QString::trimmed` removes, which is what the dialog's field had
 * already removed before this was ported out of it. */
static int is_blank(char one)
{
	return one == ' ' || one == '\t' || one == '\n' || one == '\v' || one == '\f' ||
	    one == '\r';
}

static int hardware_room(char *out, size_t out_size, char *err, size_t err_size)
{
	if (!out) {
		ncfg_error_set(err, err_size,
		    "a hardware address was asked to render into nothing");
		return 0;
	}
	if (out_size < NCFG_HARDWARE_ADDRESS_MAX) {
		ncfg_error_set(err, err_size,
		    "a buffer of %zu bytes cannot hold a hardware address; "
		    "NCFG_HARDWARE_ADDRESS_MAX is %d",
		    out_size, NCFG_HARDWARE_ADDRESS_MAX);
		return 0;
	}
	return 1;
}

static void write_octets(char *out, const int *values)
{
	size_t octet;

	for (octet = 0; octet < 6u; octet++) {
		out[octet * 3u] = hex_digit(values[octet] >> 4);
		out[octet * 3u + 1u] = hex_digit(values[octet]);
		out[octet * 3u + 2u] = ':';
	}
	out[17] = '\0';
}

int ncfg_hardware_address_strict(const char *text, char *out, size_t out_size, char *err,
    size_t err_size)
{
	int values[6];
	size_t octet;
	size_t at;
	int high;
	int low;

	if (!hardware_room(out, out_size, err, err_size)) {
		return 0;
	}
	/* **The length check is the split.** Six parts of two digits joined by
	 * colons is seventeen characters and nothing else is, so testing it first
	 * makes every index below safe -- which the Rust got for free from
	 * `split(':')` and C does not. Five octets are sixteen characters, seven
	 * are twenty, and both stop here rather than by reading past the NUL. */
	if (!text || strlen(text) != 17u) {
		ncfg_error_set(err, err_size,
		    "`%s` is not a hardware address: six colon-separated hex octets, "
		    "as in AA:BB:CC:DD:EE:FF",
		    text ? text : "");
		return 0;
	}
	for (octet = 0; octet < 6u; octet++) {
		at = octet * 3u;
		high = hex_value(text[at]);
		low = hex_value(text[at + 1u]);
		if (high < 0 || low < 0 || (octet < 5u && text[at + 2u] != ':')) {
			ncfg_error_set(err, err_size,
			    "`%s` is not a hardware address: six colon-separated hex octets, "
			    "as in AA:BB:CC:DD:EE:FF",
			    text);
			return 0;
		}
		values[octet] = (high << 4) | low;
	}

	write_octets(out, values);
	return 1;
}

int ncfg_hardware_address_typed(const char *text, char *out, size_t out_size, char *err,
    size_t err_size)
{
	int values[6];
	const char *at;
	const char *end;
	size_t seen = 0;
	int high = 0;

	if (!hardware_room(out, out_size, err, err_size)) {
		return 0;
	}
	if (!text) {
		text = "";
	}
	at = text;
	while (*at && is_blank(*at)) {
		at++;
	}
	end = at + strlen(at);
	while (end > at && is_blank(end[-1])) {
		end--;
	}

	for (; at < end; at++) {
		int value;

		/* Both separators and neither. An address read off a label has
		 * colons, one out of a Windows dialog or a DHCP lease has dashes,
		 * and one pasted out of a serial number has nothing -- a person
		 * with all three in front of them learns nothing from being told
		 * which one this field wanted. */
		if (*at == ':' || *at == '-') {
			continue;
		}
		value = hex_value(*at);
		if (value < 0) {
			ncfg_error_set(err, err_size,
			    "`%s` is not a hardware address: twelve hex digits, separated by "
			    "colons, by dashes, or by nothing",
			    text);
			return 0;
		}
		if (seen < 12u) {
			if (seen % 2u == 0) {
				high = value;
			} else {
				values[seen / 2u] = (high << 4) | value;
			}
		}
		seen++;
	}
	/* Counted rather than stopped at twelve, so that too many digits is
	 * refused as loudly as too few. Truncating would hand back a canonical
	 * address the person never typed, and it would look right. */
	if (seen != 12u) {
		ncfg_error_set(err, err_size,
		    "`%s` is not a hardware address: twelve hex digits, separated by colons, "
		    "by dashes, or by nothing",
		    text);
		return 0;
	}

	write_octets(out, values);
	return 1;
}
