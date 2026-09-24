/*
 * lower_value.c -- reading one value out of the tree.
 *
 * Every reader here answers one question -- is this a string, a number, a
 * secret reference, an interface name -- and says so in the operator's words
 * when it is not. They are in one file so that there is exactly one
 * `as_string`: three copies of one reader is three chances to accept a
 * spelling the other two do not, which is the drift `lower_regdom` records
 * costing a whole key its capital letters.
 *
 * The addresses go through `value.h` rather than through anything written
 * here. `ncfg_address_canonical` carries the measurement in its own comment:
 * a rule written `2001:0DB8::/32` was torn down and reinstalled on every
 * apply, for ever, because the desired side is compared against the kernel's
 * rendering as a string.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lower_internal.h"

#include "ncfg/base.h"
#include "ncfg/value.h"

/* ------------------------------------------------------------------------ *
 * Releasing what a refusal built
 * ------------------------------------------------------------------------ */

void ncfg_strings_free(char **list, size_t count)
{
	size_t i;

	for (i = 0; i < count; i++) {
		free(list[i]);
	}
	free(list);
}

static void cert_source_release(ncfg_cert_source_t *source)
{
	free(source->path);
	free(source->stored.name);
	memset(source, 0, sizeof(*source));
}

void ncfg_security_free(ncfg_security_t *security)
{
	free(security->psk.passphrase.name);
	free(security->eap.identity);
	free(security->eap.anonymous_identity);
	if (security->eap.password) {
		free(security->eap.password->name);
		free(security->eap.password);
	}
	free(security->eap.domain_suffix_match);
	cert_source_release(&security->eap.ca_cert);
	cert_source_release(&security->eap.client_cert);
	cert_source_release(&security->eap.private_key);
	free(security->eap.phase2);
	memset(security, 0, sizeof(*security));
}

void ncfg_dns_policy_free(ncfg_dns_policy_t *dns)
{
	size_t i;

	if (!dns) {
		return;
	}
	free(dns->mode.command);
	for (i = 0; i < dns->server_count; i++) {
		free(dns->servers[i].addr);
		free(dns->servers[i].sni);
	}
	free(dns->servers);
	ncfg_strings_free(dns->search, dns->search_count);
	for (i = 0; i < dns->domain_count; i++) {
		free(dns->domains[i].suffix);
	}
	free(dns->domains);
	ncfg_strings_free(dns->options, dns->option_count);
	memset(dns, 0, sizeof(*dns));
}

void ncfg_address_sources_free(ncfg_address_source_t *list, size_t count)
{
	size_t i;

	for (i = 0; i < count; i++) {
		free(list[i].static_address.address);
		free(list[i].static_address.peer);
		free(list[i].delegated.prefix.source);
		free(list[i].delegated.suffix);
		free(list[i].dhcp4.client_id);
		free(list[i].dhcp4.request_options);
		if (list[i].dhcp6.prefix_delegation) {
			free(list[i].dhcp6.prefix_delegation->hint);
			free(list[i].dhcp6.prefix_delegation);
		}
	}
	free(list);
}

void ncfg_routes_free(ncfg_route_t *list, size_t count)
{
	size_t i;

	for (i = 0; i < count; i++) {
		free(list[i].destination);
		free(list[i].via);
		free(list[i].src);
	}
	free(list);
}

void ncfg_hooks_free(ncfg_hook_ref_t *list, size_t count)
{
	size_t i;

	for (i = 0; i < count; i++) {
		free(list[i].path);
		free(list[i].sha256);
		free(list[i].run_as);
	}
	free(list);
}

/* ------------------------------------------------------------------------ *
 * The scalars
 * ------------------------------------------------------------------------ */

char *ncfg_as_string(ncfg_lower_ctx_t *ctx, const ncfg_ast_value_t *value)
{
	if (value->kind != NCFG_AST_STRING) {
		ncfg_diag(ctx, value->span, "expected a string, found %s",
		    ncfg_ast_value_describe(value));
		return NULL;
	}
	return ncfg_dup(ctx, value->string);
}

int ncfg_as_bool(ncfg_lower_ctx_t *ctx, const ncfg_ast_value_t *value, int *out)
{
	if (value->kind != NCFG_AST_BOOL) {
		ncfg_diag(ctx, value->span, "expected true or false, found %s",
		    ncfg_ast_value_describe(value));
		return 0;
	}
	*out = value->boolean;
	return 1;
}

int ncfg_as_i64(ncfg_lower_ctx_t *ctx, const ncfg_ast_value_t *value, int64_t *out)
{
	if (value->kind != NCFG_AST_NUMBER) {
		ncfg_diag(ctx, value->span, "expected a number, found %s",
		    ncfg_ast_value_describe(value));
		return 0;
	}
	*out = value->number;
	return 1;
}

int ncfg_as_u32(ncfg_lower_ctx_t *ctx, const ncfg_ast_value_t *value, int64_t *out)
{
	int64_t number;

	if (!ncfg_as_i64(ctx, value, &number)) {
		return 0;
	}
	if (number < 0 || number > 4294967295LL) {
		ncfg_diag(ctx, value->span, "%lld is out of range here", (long long)number);
		return 0;
	}
	*out = number;
	return 1;
}

void ncfg_as_u32_opt(ncfg_lower_ctx_t *ctx, const ncfg_ast_value_t *value, ncfg_optint_t *out)
{
	int64_t number;

	if (!ncfg_as_u32(ctx, value, &number)) {
		return;
	}
	out->has = 1;
	out->value = number;
}

void ncfg_as_narrow_opt(ncfg_lower_ctx_t *ctx, const ncfg_ast_value_t *value, int64_t high,
    ncfg_optint_t *out)
{
	int64_t number;

	if (!ncfg_as_u32(ctx, value, &number)) {
		return;
	}
	/* Out of range is dropped with nothing said. See the header: this is the
	 * Rust's `.and_then(|n| u16::try_from(n).ok())`, preserved deliberately. */
	if (number > high) {
		return;
	}
	out->has = 1;
	out->value = number;
}

int ncfg_as_drift(ncfg_lower_ctx_t *ctx, const ncfg_ast_value_t *value, int *out)
{
	char             *name = ncfg_as_string(ctx, value);
	ncfg_drift_policy_t policy;
	int                 ok;

	if (!name) {
		return 0;
	}
	ok = ncfg_drift_policy_from_name(name, &policy, NULL, 0);
	if (!ok) {
		ncfg_diag(ctx, value->span, "unknown drift policy `%s`", name);
	} else {
		*out = (int)policy;
	}
	free(name);
	return ok;
}

/* ------------------------------------------------------------------------ *
 * Lists
 * ------------------------------------------------------------------------ */

static int keep_word(ncfg_lower_ctx_t *ctx, ncfg_words_t *out, const char *text, size_t length,
    ncfg_span_t span)
{
	ncfg_word_t *grown = realloc(out->at, (out->count + 1u) * sizeof(*grown));
	char        *copy;

	if (!grown) {
		ncfg_lower_oom(ctx);
		return 0;
	}
	out->at = grown;
	copy = malloc(length + 1u);
	if (!copy) {
		ncfg_lower_oom(ctx);
		return 0;
	}
	memcpy(copy, text, length);
	copy[length] = '\0';
	out->at[out->count].text = copy;
	out->at[out->count].span = span;
	out->count++;
	return 1;
}

static int is_space(char one)
{
	return one == ' ' || one == '\t' || one == '\r' || one == '\n' || one == '\v' || one == '\f';
}

/* A string splits with `split`, a list gives its elements whole. */
static int split_value(ncfg_lower_ctx_t *ctx, const ncfg_ast_value_t *value, ncfg_words_t *out,
    int by_line)
{
	size_t i;

	memset(out, 0, sizeof(*out));
	if (value->kind == NCFG_AST_STRING) {
		const char *text = value->string;
		size_t      at = 0;

		while (text[at]) {
			size_t start;

			if (by_line) {
				size_t end;

				start = at;
				while (text[at] && text[at] != '\n') {
					at++;
				}
				end = at;
				/* Trimmed, and empty lines dropped: a `routes` value written
				 * across lines has one entry per line and the indentation is
				 * the file's rather than the value's. */
				while (start < end && is_space(text[start])) {
					start++;
				}
				while (end > start && is_space(text[end - 1u])) {
					end--;
				}
				if (end > start && !keep_word(ctx, out, text + start, end - start, value->span)) {
					return 0;
				}
				if (text[at]) {
					at++;
				}
				continue;
			}
			while (text[at] && is_space(text[at])) {
				at++;
			}
			start = at;
			while (text[at] && !is_space(text[at])) {
				at++;
			}
			if (at > start && !keep_word(ctx, out, text + start, at - start, value->span)) {
				return 0;
			}
		}
		return 1;
	}
	if (value->kind == NCFG_AST_LIST) {
		for (i = 0; i < value->entries.count; i++) {
			const ncfg_ast_value_t *entry = value->entries.at[i];

			if (entry->kind != NCFG_AST_STRING) {
				ncfg_diag(ctx, entry->span, "expected a string in this list, found %s",
				    ncfg_ast_value_describe(entry));
				continue;
			}
			if (!keep_word(ctx, out, entry->string, strlen(entry->string), entry->span)) {
				return 0;
			}
		}
		return 1;
	}
	ncfg_diag(ctx, value->span, "expected a string or a list, found %s",
	    ncfg_ast_value_describe(value));
	return 1;
}

int ncfg_as_words(ncfg_lower_ctx_t *ctx, const ncfg_ast_value_t *value, ncfg_words_t *out)
{
	return split_value(ctx, value, out, 0);
}

int ncfg_as_lines(ncfg_lower_ctx_t *ctx, const ncfg_ast_value_t *value, ncfg_words_t *out)
{
	return split_value(ctx, value, out, 1);
}

/* ------------------------------------------------------------------------ *
 * Secrets and certificates
 * ------------------------------------------------------------------------ */

int ncfg_as_secret(ncfg_lower_ctx_t *ctx, const ncfg_ast_value_t *value, ncfg_secret_ref_t *out)
{
	char       *text = ncfg_as_string(ctx, value);
	const char *rest;
	const char *colon;
	const char *name;
	int         provider;

	if (!text) {
		return 0;
	}
	if (strncmp(text, "@secret:", 8u) != 0) {
		/*
		 * The whole point of the indirection is that a config file stays safe
		 * to commit. Accepting a bare string here would make that a convention
		 * rather than a property, and the first person to paste a passphrase
		 * in would find it works.
		 *
		 * The help names the file and the command: the file is what the `file`
		 * provider reads, and the command is what writes one without an editor
		 * or a chmod.
		 */
		ncfg_diag(ctx, value->span,
		    "a credential must be a secret reference: write `@secret:NAME`, then "
		    "`ncfg secret set NAME` -- which asks for the value with echo off and writes "
		    "/etc/netcfgd/secrets/NAME at 0600, outside the config, which is what keeps the "
		    "config safe to commit");
		free(text);
		return 0;
	}
	rest = text + 8;
	colon = strchr(rest, ':');
	if (colon) {
		char word[32];
		size_t length = (size_t)(colon - rest);

		if (length >= sizeof(word)) {
			length = sizeof(word) - 1u;
		}
		memcpy(word, rest, length);
		word[length] = '\0';
		name = colon + 1;
		if (strcmp(word, "file") == 0) {
			provider = NCFG_SECRET_PROVIDER_FILE;
		} else if (strcmp(word, "exec") == 0) {
			provider = NCFG_SECRET_PROVIDER_EXEC;
		} else if (strcmp(word, "keyring") == 0) {
			provider = NCFG_SECRET_PROVIDER_KEYRING;
		} else if (strcmp(word, "pass") == 0) {
			provider = NCFG_SECRET_PROVIDER_PASS;
		} else {
			ncfg_diag(ctx, value->span,
			    "`%s` is not a secret provider: one of file, exec, keyring, pass", word);
			free(text);
			return 0;
		}
	} else {
		provider = NCFG_SECRET_PROVIDER_FILE;
		name = rest;
	}
	if (name[0] == '\0') {
		ncfg_diag(ctx, value->span, "a secret reference needs a name");
		free(text);
		return 0;
	}
	out->provider = provider;
	free(out->name);
	out->name = ncfg_dup(ctx, name);
	free(text);
	return out->name != NULL;
}

int ncfg_as_cert_source(ncfg_lower_ctx_t *ctx, const ncfg_ast_value_t *value,
    ncfg_cert_source_t *out)
{
	char *text;

	if (value->kind == NCFG_AST_STRING && strncmp(value->string, "@secret:", 8u) == 0) {
		/*
		 * **A path and stored content are not equivalent, and the
		 * classification knows it.** A path is an instruction to open a file
		 * as root, so it is privileged and a caller who is not root cannot
		 * send one; a stored reference grants nothing the caller did not
		 * already give netcfgd.
		 */
		if (!ncfg_as_secret(ctx, value, &out->stored)) {
			return 0;
		}
		out->kind = NCFG_CERT_SOURCE_STORED;
		out->has = 1;
		return 1;
	}
	text = ncfg_as_string(ctx, value);
	if (!text) {
		return 0;
	}
	free(out->path);
	out->path = text;
	out->kind = NCFG_CERT_SOURCE_PATH;
	out->has = 1;
	return 1;
}

/* ------------------------------------------------------------------------ *
 * Names
 * ------------------------------------------------------------------------ */

/* Why the name matters, where a link is referred to. */
const char *const ncfg_link_name_help = "netcfgd uses this name for the link and for the files "
    "it keeps about it, so it has to be a name the kernel would take";
/* The same, where a block is named for the link it declares. */
const char *const ncfg_link_label_help = "a `device` or `interface` block is named for the link "
    "itself, so the label has to be a name the kernel would take";

/*
 * The one place the "not an interface name" diagnostic is built.
 *
 * Three callers, three spans, one message. It was written out three times
 * first; three copies of one sentence is worse code whatever it measures.
 */
int ncfg_name_ok(ncfg_lower_ctx_t *ctx, const char *text, ncfg_span_t span, const char *help)
{
	const char *why = ncfg_usable_name(text);

	if (!why) {
		return 1;
	}
	ncfg_diag(ctx, span, "`%s` is not an interface name: %s: %s", text ? text : "", why, help);
	return 0;
}

char *ncfg_as_interface_name(ncfg_lower_ctx_t *ctx, const ncfg_ast_value_t *value)
{
	char *text = ncfg_as_string(ctx, value);

	if (!text) {
		return NULL;
	}
	if (!ncfg_name_ok(ctx, text, value->span, ncfg_link_name_help)) {
		free(text);
		return NULL;
	}
	return text;
}

char *ncfg_require_label(ncfg_lower_ctx_t *ctx, const ncfg_ast_block_t *block)
{
	if (!block->label) {
		ncfg_diag(ctx, block->span, "`%s` needs a name", block->head);
		return NULL;
	}
	return ncfg_dup(ctx, block->label);
}

/*
 * The same, for a block whose label names a link.
 *
 * `device` and `interface` only: the other five labelled blocks name a rule, a
 * network, an access point, a bluetooth device or a wireguard peer, and those
 * are netcfgd's own handles rather than the kernel's.
 */
char *ncfg_require_interface_label(ncfg_lower_ctx_t *ctx, const ncfg_ast_block_t *block)
{
	char *label = ncfg_require_label(ctx, block);

	if (!label) {
		return NULL;
	}
	if (!ncfg_name_ok(ctx, label, block->span, ncfg_link_label_help)) {
		free(label);
		return NULL;
	}
	return label;
}

/* ------------------------------------------------------------------------ *
 * Addresses
 * ------------------------------------------------------------------------ */

char *ncfg_canonical_address(ncfg_lower_ctx_t *ctx, const char *text)
{
	char rendered[NCFG_ADDRESS_MAX];

	if (!ncfg_address_canonical(text, rendered, sizeof(rendered), NULL, 0)) {
		return NULL;
	}
	return ncfg_dup(ctx, rendered);
}

int ncfg_is_bare_address(const char *text)
{
	ncfg_address_t address;

	return ncfg_address_parse(text, &address, NULL, 0) && !address.has_prefix;
}

int ncfg_is_prefix(const char *text)
{
	ncfg_address_t address;

	return ncfg_address_parse(text, &address, NULL, 0) && address.has_prefix;
}

int ncfg_check_cidr(ncfg_lower_ctx_t *ctx, const char *text, ncfg_span_t span)
{
	const char    *slash = strchr(text, '/');
	char           head[NCFG_ADDRESS_MAX];
	ncfg_address_t address;
	size_t         length;
	unsigned long  prefix;
	char          *end;
	unsigned       max;

	if (!slash) {
		ncfg_diag(ctx, span,
		    "`%s` is not an address: write an address with a prefix length, or one of dhcp, "
		    "dhcp6, slaac", text);
		return 0;
	}
	length = (size_t)(slash - text);
	if (length >= sizeof(head)) {
		length = sizeof(head) - 1u;
	}
	memcpy(head, text, length);
	head[length] = '\0';
	if (!ncfg_address_parse(head, &address, NULL, 0) || address.has_prefix) {
		ncfg_diag(ctx, span, "`%s` is not an IP address", head);
		return 0;
	}
	max = address.is_ipv6 ? 128u : 32u;
	prefix = strtoul(slash + 1, &end, 10);
	if (end == slash + 1 || *end != '\0' || prefix > max) {
		ncfg_diag(ctx, span, "prefix length `%s` is not between 0 and %u", slash + 1, max);
		return 0;
	}
	return 1;
}

/*
 * **A route destination is masked by the kernel and an address is not**, which
 * is why this is separate from `ncfg_canonical_address`. `ip route add
 * 10.1.2.3/8` is refused outright with `EINVAL`, and `2001:db8:1::5/64` is
 * accepted and stored as `2001:db8:1::/64` -- so the desired text never
 * matches what comes back, `route.add` is planned again, and the second apply
 * fails `EEXIST`.
 *
 * Measured, and the blast radius is what makes it worth a compile-time refusal
 * rather than a silent mask: execution stops at the first failed action, so one
 * destination with host bits abandons every later action in the plan, on every
 * apply, for ever.
 */
int ncfg_network_of(ncfg_lower_ctx_t *ctx, const char *text, char **out)
{
	ncfg_address_t address;
	unsigned char  original[16];
	char           rendered[NCFG_ADDRESS_MAX];
	unsigned       width;
	unsigned       i;
	int            same = 1;

	*out = NULL;
	if (!strchr(text, '/') || !ncfg_address_parse(text, &address, NULL, 0) ||
	    !address.has_prefix) {
		return -1;
	}
	memcpy(original, address.bytes, sizeof(original));
	width = address.is_ipv6 ? 16u : 4u;
	for (i = 0; i < width; i++) {
		unsigned bits = i * 8u;
		unsigned char mask;

		if (address.prefix >= bits + 8u) {
			mask = 0xffu;
		} else if (address.prefix <= bits) {
			mask = 0;
		} else {
			mask = (unsigned char)(0xffu << (8u - (address.prefix - bits)));
		}
		address.bytes[i] = (unsigned char)(address.bytes[i] & mask);
		if (address.bytes[i] != original[i]) {
			same = 0;
		}
	}
	if (!ncfg_address_render(&address, rendered, sizeof(rendered), NULL, 0)) {
		return -1;
	}
	*out = ncfg_dup(ctx, rendered);
	if (!*out) {
		return -1;
	}
	return same;
}

/*
 * An IPv4 netmask as a prefix length, rejecting a non-contiguous one.
 *
 * 255.0.255.0 has four leading ones and is not a mask. Rebuilding from the
 * count and comparing is the cheapest way to insist it is contiguous.
 */
int ncfg_netmask_to_prefix(const char *text)
{
	ncfg_address_t mask;
	unsigned       ones = 0;
	unsigned       i;
	unsigned char  rebuilt[4];

	if (!ncfg_address_parse(text, &mask, NULL, 0) || mask.has_prefix || mask.is_ipv6) {
		return -1;
	}
	for (i = 0; i < 32u; i++) {
		unsigned bit = (unsigned)(mask.bytes[i / 8u] >> (7u - (i % 8u))) & 1u;

		if (!bit) {
			break;
		}
		ones++;
	}
	for (i = 0; i < 4u; i++) {
		unsigned bits = i * 8u;

		if (ones >= bits + 8u) {
			rebuilt[i] = 0xffu;
		} else if (ones <= bits) {
			rebuilt[i] = 0;
		} else {
			rebuilt[i] = (unsigned char)(0xffu << (8u - (ones - bits)));
		}
	}
	if (memcmp(rebuilt, mask.bytes, 4u) != 0) {
		return -1;
	}
	return (int)ones;
}

/*
 * Whether a string is a hostname the kernel will take.
 *
 * Deliberately narrow: letters, digits, hyphens and dots, with the label and
 * total lengths RFC 1035 gives. A leading hyphen or an empty label is refused
 * too, because both are names that resolve to arguments in somebody's shell
 * script.
 */
int ncfg_is_hostname(const char *name)
{
	size_t at = 0;

	if (!name || name[0] == '\0' || strlen(name) > 253u) {
		return 0;
	}
	while (1) {
		size_t start = at;
		size_t length;

		while (name[at] && name[at] != '.') {
			at++;
		}
		length = at - start;
		if (length == 0 || length > 63u) {
			return 0;
		}
		if (name[start] == '-' || name[at - 1u] == '-') {
			return 0;
		}
		for (; start < at; start++) {
			char one = name[start];
			int  alnum = (one >= '0' && one <= '9') || (one >= 'a' && one <= 'z') ||
			    (one >= 'A' && one <= 'Z');

			if (!alnum && one != '-') {
				return 0;
			}
		}
		if (!name[at]) {
			return 1;
		}
		at++;
	}
}

/* ------------------------------------------------------------------------ *
 * SSIDs, stations and keys
 * ------------------------------------------------------------------------ */

int ncfg_ssid_from_bytes(const char *text, size_t length, ncfg_ssid_t *out, const char **why)
{
	if (length > NCFG_SSID_MAX_LEN) {
		*why = "an ssid is at most 32 octets";
		return 0;
	}
	memset(out, 0, sizeof(*out));
	memcpy(out->bytes, text, length);
	out->length = length;
	out->has = 1;
	return 1;
}

static int hex_digit(char one, unsigned *out)
{
	if (one >= '0' && one <= '9') {
		*out = (unsigned)(one - '0');
		return 1;
	}
	/* Uppercase is refused rather than accepted, because two spellings of one
	 * SSID would break the byte-identical guarantee. */
	if (one >= 'a' && one <= 'f') {
		*out = (unsigned)(one - 'a') + 10u;
		return 1;
	}
	return 0;
}

int ncfg_ssid_from_hex(const char *text, ncfg_ssid_t *out, const char **why)
{
	size_t length = strlen(text);
	size_t i;

	if (length % 2u != 0) {
		*why = "an ssid given as hex is an even number of lowercase hex digits";
		return 0;
	}
	if (length / 2u > NCFG_SSID_MAX_LEN) {
		*why = "an ssid is at most 32 octets";
		return 0;
	}
	memset(out, 0, sizeof(*out));
	for (i = 0; i < length; i += 2u) {
		unsigned high;
		unsigned low;

		if (!hex_digit(text[i], &high) || !hex_digit(text[i + 1u], &low)) {
			*why = "an ssid given as hex is lowercase hex digits and nothing else";
			return 0;
		}
		out->bytes[i / 2u] = (unsigned char)((high << 4u) | low);
	}
	out->length = length / 2u;
	out->has = 1;
	return 1;
}

char *ncfg_normalize_station(ncfg_lower_ctx_t *ctx, const char *text, char *why, size_t why_size)
{
	char out[NCFG_STATION_ADDRESS_SIZE];

	/* The rule is the model's -- see `ncfg_station_address_normalize`. What is
	 * this module's is the arena: a lowered document owns its strings, so the
	 * answer is duplicated into `ctx` rather than handed back on the stack. */
	if (!ncfg_station_address_normalize(text, out, sizeof(out), why, why_size)) {
		return NULL;
	}
	return ncfg_dup(ctx, out);
}

