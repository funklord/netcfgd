/*
 * lower_address.c -- a `config` value, and a `routes` one.
 *
 * These two keys are where netifrc's phrasing survives into netcfgd, and the
 * splitting is the part that is not obvious. netifrc separates addresses with
 * **spaces**, and uses newlines only when an entry carries modifiers that
 * themselves contain spaces:
 *
 *     config_eth0="192.168.0.2/24 192.168.0.3/24 192.168.0.4/24"
 *     config_eth0="192.168.0.2/24 scope host
 *     4321:0:1:2:3:4:567:89ab/64 nodad home preferred_lft 0"
 *
 * Splitting on newlines alone -- which this did until a real config failed to
 * compile -- treats the first line as one malformed address. Both separators
 * are honoured, with the modifier table below deciding where an entry really
 * ends: without it, `192.168.0.2 netmask 255.255.255.0` splits into two
 * addresses, because the netmask is itself address-shaped.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lower_internal.h"

#include "ncfg/base.h"
#include "ncfg/value.h"

/* One `keyword argument` pair following the head of an entry. */
typedef struct {
	char *keyword;
	char *argument;
} modifier_t;

/* One addressing entry: a head, plus the modifier words that follow it. */
typedef struct {
	char       *head;
	modifier_t *modifiers;
	size_t      modifier_count;
	ncfg_span_t span;
} entry_t;

/*
 * Modifier keywords and how many words each consumes after itself.
 *
 * Taken from net.example's documented forms. `pd` and its two settings belong
 * to the `dhcp6` entry rather than to an address, and `privacy` belongs to
 * `slaac` the same way; they are in one table because the split has to happen
 * before anything knows which source the head names.
 */
static const struct {
	const char *word;
	unsigned    arity;
} modifiers[] = {
	{ "netmask", 1u },
	{ "peer", 1u },
	{ "pointopoint", 1u },
	{ "scope", 1u },
	{ "brd", 1u },
	{ "broadcast", 1u },
	{ "label", 1u },
	{ "metric", 1u },
	{ "preferred_lft", 1u },
	{ "valid_lft", 1u },
	{ "pd", 0u },
	{ "pd_hint", 1u },
	{ "pd_length", 1u },
	{ "privacy", 1u },
	{ "nodad", 0u },
	{ "home", 0u },
	{ "mngtmpaddr", 0u },
	{ "noprefixroute", 0u }
};

static int modifier_arity(const char *word, unsigned *arity)
{
	size_t i;

	for (i = 0; i < sizeof(modifiers) / sizeof(modifiers[0]); i++) {
		if (strcmp(modifiers[i].word, word) == 0) {
			*arity = modifiers[i].arity;
			return 1;
		}
	}
	return 0;
}

/* Whether a word begins a new addressing entry. */
static int starts_entry(const char *word)
{
	static const char *const keywords[] = { "dhcp", "dhcp4", "dhcpv6", "dhcp6", "slaac",
		"link-local", "link_local", "reported", "null", "noop" };
	const char *slash;
	char        head[NCFG_ADDRESS_MAX];
	size_t      length;
	size_t      i;

	for (i = 0; i < sizeof(keywords) / sizeof(keywords[0]); i++) {
		if (strcmp(keywords[i], word) == 0) {
			return 1;
		}
	}
	if (strncmp(word, "@pd:", 4u) == 0) {
		return 1;
	}
	slash = strchr(word, '/');
	length = slash ? (size_t)(slash - word) : strlen(word);
	if (length >= sizeof(head)) {
		return 0;
	}
	memcpy(head, word, length);
	head[length] = '\0';
	return ncfg_is_bare_address(head);
}

static void entries_free(entry_t *entries, size_t count)
{
	size_t i;
	size_t j;

	for (i = 0; i < count; i++) {
		for (j = 0; j < entries[i].modifier_count; j++) {
			free(entries[i].modifiers[j].keyword);
			free(entries[i].modifiers[j].argument);
		}
		free(entries[i].modifiers);
		free(entries[i].head);
	}
	free(entries);
}

/* ------------------------------------------------------------------------ *
 * The address sources
 * ------------------------------------------------------------------------ */

/*
 * A keyword source that takes no modifiers says so.
 *
 * These arms used to `return` before the modifier loop ran, so
 * `config = "dhcp4 metric 100"` compiled and dropped the metric. Section 2's
 * rule about unknown fields is a rule about the language too: acting on a
 * subset of what the author wrote is the failure mode, and it is worse here
 * than in the document because the author is looking at the line.
 */
static int no_modifiers(ncfg_lower_ctx_t *ctx, const entry_t *entry, const char *source)
{
	if (entry->modifier_count == 0) {
		return 1;
	}
	ncfg_diag(ctx, entry->span,
	    "`%s` is not something `%s` takes: modifiers belong to an address; `pd` and its two "
	    "settings belong to dhcp6", entry->modifiers[0].keyword, source);
	return 0;
}

/*
 * `slaac`, and whether it prefers a temporary address.
 *
 * `privacy prefer_temporary` is RFC 4941: the host generates a second address
 * from a random interface identifier, ages it out, and prefers it for outgoing
 * connections -- so what a server on the far side records is not the same value
 * for weeks at a time. It is not free: anything that authenticates a host by
 * the address it comes from will see it move, which is why it is spelled out
 * rather than defaulted.
 */
static int slaac_source(ncfg_lower_ctx_t *ctx, const entry_t *entry, ncfg_address_source_t *out)
{
	size_t i;

	out->kind = NCFG_ADDRESS_SOURCE_SLAAC;
	out->slaac.privacy = NCFG_SLAAC_PRIVACY_NONE;
	for (i = 0; i < entry->modifier_count; i++) {
		const char *keyword = entry->modifiers[i].keyword;
		const char *argument = entry->modifiers[i].argument;

		if (strcmp(keyword, "privacy") != 0) {
			ncfg_diag(ctx, entry->span,
			    "`%s` is not something `slaac` takes: `privacy` is the only one, and it "
			    "takes prefer_temporary or none", keyword);
			return 0;
		}
		if (!argument) {
			ncfg_diag(ctx, entry->span,
			    "`privacy` needs a value: `slaac privacy prefer_temporary`");
			return 0;
		}
		if (strcmp(argument, "prefer_temporary") == 0 ||
		    strcmp(argument, "prefer-temporary") == 0) {
			out->slaac.privacy = NCFG_SLAAC_PRIVACY_PREFER_TEMPORARY;
		} else if (strcmp(argument, "none") == 0) {
			out->slaac.privacy = NCFG_SLAAC_PRIVACY_NONE;
		} else {
			ncfg_diag(ctx, entry->span,
			    "`%s` is not a privacy setting for `slaac`: one of prefer_temporary, none",
			    argument);
			return 0;
		}
	}
	return 1;
}

/*
 * `dhcp6`, and the prefix delegation it may ask for.
 *
 * `pd` alone asks for whatever the ISP offers. `pd_length 56` asks for a size,
 * and `pd_hint 2001:db8::` asks for a particular block -- both of which a
 * server may ignore, which is why they are a request and not a value. Each
 * implies `pd`, so a length with no `pd` beside it is not silently inert.
 */
static int dhcp6_source(ncfg_lower_ctx_t *ctx, const entry_t *entry, ncfg_address_source_t *out)
{
	ncfg_pd_request_t request;
	int               asked = 0;
	size_t            i;

	memset(&request, 0, sizeof(request));
	out->kind = NCFG_ADDRESS_SOURCE_DHCP6;
	out->dhcp6.mode = NCFG_DHCP6_MODE_MANAGED;
	for (i = 0; i < entry->modifier_count; i++) {
		const char *keyword = entry->modifiers[i].keyword;
		const char *argument = entry->modifiers[i].argument;

		if (strcmp(keyword, "pd") == 0) {
			asked = 1;
			continue;
		}
		if (strcmp(keyword, "pd_length") == 0 && argument) {
			char         *end;
			unsigned long length = strtoul(argument, &end, 10);

			if (end == argument || *end != '\0' || length > 255u) {
				ncfg_diag(ctx, entry->span, "`%s` is not a prefix length", argument);
				free(request.hint);
				return 0;
			}
			if (length > 128u) {
				ncfg_diag(ctx, entry->span,
				    "a prefix length is between 0 and 128, not %lu", length);
				free(request.hint);
				return 0;
			}
			request.length.has = 1;
			request.length.value = (int64_t)length;
			asked = 1;
			continue;
		}
		if (strcmp(keyword, "pd_hint") == 0 && argument) {
			ncfg_address_t parsed;

			if (!ncfg_address_parse(argument, &parsed, NULL, 0) || parsed.has_prefix ||
			    !parsed.is_ipv6) {
				ncfg_diag(ctx, entry->span,
				    "`%s` is not an IPv6 prefix to ask for: a hint is an address without a "
				    "length, such as 2001:db8::", argument);
				free(request.hint);
				return 0;
			}
			free(request.hint);
			request.hint = ncfg_dup(ctx, argument);
			asked = 1;
			continue;
		}
		ncfg_diag(ctx, entry->span,
		    "`%s` is not something `dhcp6` takes: dhcp6 takes pd, pd_hint and pd_length",
		    keyword);
		free(request.hint);
		return 0;
	}

	if (asked) {
		out->dhcp6.prefix_delegation = calloc(1, sizeof(*out->dhcp6.prefix_delegation));
		if (!out->dhcp6.prefix_delegation) {
			ncfg_lower_oom(ctx);
			free(request.hint);
			return 0;
		}
		*out->dhcp6.prefix_delegation = request;
	} else {
		free(request.hint);
	}
	return 1;
}

/*
 * `@pd:wan0` and `@pd:wan0/2`, the DSL spelling of a delegated prefix.
 *
 * Matching `@secret:` in shape because both are indirections the document
 * carries instead of a value: no config file can contain a prefix an ISP has
 * not handed out yet.
 */
static int delegated_source(ncfg_lower_ctx_t *ctx, const entry_t *entry,
    ncfg_address_source_t *out)
{
	const char *rest = entry->head + 4;
	const char *equals = strchr(rest, '=');
	const char *suffix = equals ? equals + 1 : "::1/64";
	char        source[64];
	const char *slash;
	size_t      length = equals ? (size_t)(equals - rest) : strlen(rest);
	int64_t     subnet = 0;

	if (length >= sizeof(source)) {
		length = sizeof(source) - 1u;
	}
	memcpy(source, rest, length);
	source[length] = '\0';
	slash = strchr(source, '/');
	if (slash) {
		char         *end;
		unsigned long index = strtoul(slash + 1, &end, 10);

		if (end == slash + 1 || *end != '\0' || index > 65535u) {
			ncfg_diag(ctx, entry->span, "`%s` is not a subnet number", slash + 1);
			return 0;
		}
		subnet = (int64_t)index;
		source[(size_t)(slash - source)] = '\0';
	}
	out->kind = NCFG_ADDRESS_SOURCE_DELEGATED;
	out->delegated.prefix.source = ncfg_dup(ctx, source);
	out->delegated.prefix.index = 0;
	out->delegated.prefix.subnet = subnet;
	out->delegated.suffix = ncfg_dup(ctx, suffix);
	return 1;
}

/*
 * Set a lifetime, where netifrc's `forever` means "no limit" and so leaves the
 * slot empty. Returns 0 where the value was not a lifetime at all.
 */
static int set_lifetime(ncfg_lower_ctx_t *ctx, ncfg_optint_t *slot, const char *text,
    ncfg_span_t span)
{
	char         *end;
	unsigned long seconds;

	if (strcmp(text, "forever") == 0) {
		slot->has = 0;
		return 1;
	}
	seconds = strtoul(text, &end, 10);
	if (end == text || *end != '\0' || seconds > 4294967295UL) {
		ncfg_diag(ctx, span, "`%s` is not a number of seconds", text);
		return 0;
	}
	slot->has = 1;
	slot->value = (int64_t)seconds;
	return 1;
}

/* One entry of a `config` value. Returns 0 where it contributes nothing,
 * whether because it was refused or because it was `null`. */
static int address_source(ncfg_lower_ctx_t *ctx, const entry_t *entry, ncfg_address_source_t *out)
{
	const char *text = entry->head;
	char       *address;
	char       *canonical;
	size_t      i;

	if (strcmp(text, "dhcp") == 0 || strcmp(text, "dhcp4") == 0) {
		if (!no_modifiers(ctx, entry, "dhcp4")) {
			return 0;
		}
		out->kind = NCFG_ADDRESS_SOURCE_DHCP4;
		out->dhcp4.hostname_mode = NCFG_HOSTNAME_MODE_NONE;
		out->dhcp4.backend = NCFG_DHCP4_BACKEND_AUTO;
		return 1;
	}
	if (strcmp(text, "dhcp6") == 0 || strcmp(text, "dhcpv6") == 0) {
		return dhcp6_source(ctx, entry, out);
	}
	if (strcmp(text, "slaac") == 0) {
		return slaac_source(ctx, entry, out);
	}
	if (strcmp(text, "link-local") == 0 || strcmp(text, "link_local") == 0) {
		if (!no_modifiers(ctx, entry, "link-local")) {
			return 0;
		}
		out->kind = NCFG_ADDRESS_SOURCE_LINK_LOCAL;
		return 1;
	}
	/*
	 * Whatever something outside netcfgd reported for this interface -- a
	 * modem helper, or the tunnel daemon netcfgd itself started. There is no
	 * backend to name and no value to carry: the report is the value.
	 *
	 * Spelled `reported` rather than `modem` because the writer is not a
	 * modem's (0047), and there is deliberately no second spelling: two words
	 * for one source is how a config language stops being greppable.
	 */
	if (strcmp(text, "reported") == 0) {
		if (!no_modifiers(ctx, entry, "reported")) {
			return 0;
		}
		out->kind = NCFG_ADDRESS_SOURCE_REPORTED;
		return 1;
	}
	/* netifrc's "no address at all", used on bridge members. An empty
	 * addressing list is already legal (0006 rule 6), so this contributes
	 * nothing rather than being an error. */
	if (strcmp(text, "null") == 0) {
		return 0;
	}
	/* "keep whatever is already there" cannot be expressed by a reconciler:
	 * there is no state to converge on, so every run would have to decide
	 * afresh what it meant. */
	if (strcmp(text, "noop") == 0) {
		ncfg_diag(ctx, entry->span,
		    "`noop` has no meaning in a reconciled model: state what the interface should "
		    "have; an empty config keeps nothing");
		return 0;
	}
	if (strncmp(text, "@pd:", 4u) == 0) {
		return delegated_source(ctx, entry, out);
	}

	address = ncfg_dup(ctx, text);
	if (!address) {
		return 0;
	}
	out->kind = NCFG_ADDRESS_SOURCE_STATIC;
	for (i = 0; i < entry->modifier_count; i++) {
		const char *keyword = entry->modifiers[i].keyword;
		const char *argument = entry->modifiers[i].argument;

		if (strcmp(keyword, "netmask") == 0 && argument) {
			/* netifrc's pre-CIDR spelling. Converting rather than refusing
			 * costs fifteen lines and is the second form net.example
			 * documents, so a converted config is likelier to work. */
			int   prefix = ncfg_netmask_to_prefix(argument);
			char *widened;

			if (prefix < 0) {
				ncfg_diag(ctx, entry->span, "`%s` is not a contiguous netmask", argument);
				goto refused;
			}
			if (strchr(address, '/')) {
				ncfg_diag(ctx, entry->span,
				    "an address may carry a prefix length or a netmask, not both");
				goto refused;
			}
			widened = malloc(strlen(address) + 6u);
			if (!widened) {
				ncfg_lower_oom(ctx);
				goto refused;
			}
			(void)snprintf(widened, strlen(address) + 6u, "%s/%d", address, prefix);
			free(address);
			address = widened;
			continue;
		}
		if ((strcmp(keyword, "peer") == 0 || strcmp(keyword, "pointopoint") == 0) && argument) {
			free(out->static_address.peer);
			out->static_address.peer = ncfg_dup(ctx, argument);
			continue;
		}
		if (strcmp(keyword, "preferred_lft") == 0 && argument) {
			if (!set_lifetime(ctx, &out->static_address.preferred_lifetime, argument,
			    entry->span)) {
				goto refused;
			}
			continue;
		}
		if (strcmp(keyword, "valid_lft") == 0 && argument) {
			if (!set_lifetime(ctx, &out->static_address.valid_lifetime, argument,
			    entry->span)) {
				goto refused;
			}
			continue;
		}
		/* Recognised, and not silently dropped. Section 2's rule about unknown
		 * fields applies to the language too: acting on a subset of what the
		 * author wrote is the failure mode. */
		ncfg_diag(ctx, entry->span,
		    "`%s` is not supported by this build: supported modifiers: netmask, peer, "
		    "preferred_lft, valid_lft", keyword);
		goto refused;
	}

	/* A bare address with no prefix and no netmask is still an error, and the
	 * message says which of the two spellings to reach for. */
	if (!ncfg_check_cidr(ctx, address, entry->span)) {
		goto refused;
	}
	/* The kernel's spelling, not the operator's: the comparison against what
	 * the kernel reports is a string comparison, so a leading zero or an
	 * uppercase digit made the address add and delete itself on every apply. */
	canonical = ncfg_canonical_address(ctx, address);
	if (canonical) {
		free(address);
		address = canonical;
	}
	out->static_address.address = address;
	return 1;

refused:
	free(address);
	free(out->static_address.peer);
	memset(out, 0, sizeof(*out));
	return 0;
}

/* ------------------------------------------------------------------------ *
 * Splitting a `config` value into entries
 * ------------------------------------------------------------------------ */

void ncfg_lower_config(ncfg_lower_ctx_t *ctx, const ncfg_ast_value_t *value,
    ncfg_address_source_t **list, size_t *count, const char *owner)
{
	ncfg_words_t lines;
	entry_t     *entries = NULL;
	size_t       entry_count = 0;
	size_t       line;
	size_t       i;

	if (!ncfg_as_lines(ctx, value, &lines)) {
		ncfg_words_free(&lines);
		return;
	}
	for (line = 0; line < lines.count; line++) {
		ncfg_words_t words;
		size_t       at;
		entry_t     *current = NULL;

		/* The line is split again on whitespace: both separators are honoured,
		 * and the modifier table decides where an entry really ends. */
		memset(&words, 0, sizeof(words));
		{
			ncfg_ast_value_t fake;

			memset(&fake, 0, sizeof(fake));
			fake.kind = NCFG_AST_STRING;
			fake.span = lines.at[line].span;
			fake.string = lines.at[line].text;
			fake.string_length = strlen(lines.at[line].text);
			if (!ncfg_as_words(ctx, &fake, &words)) {
				ncfg_words_free(&words);
				break;
			}
		}

		for (at = 0; at < words.count; at++) {
			const char *word = words.at[at].text;
			unsigned    arity;

			if (modifier_arity(word, &arity)) {
				modifier_t *slot;
				char       *argument = NULL;

				if (arity != 0) {
					at++;
					if (at >= words.count) {
						ncfg_diag(ctx, lines.at[line].span, "`%s` needs a value", word);
						break;
					}
					argument = ncfg_dup(ctx, words.at[at].text);
				}
				if (!current) {
					ncfg_diag(ctx, lines.at[line].span, "`%s` has no address to apply to",
					    word);
					free(argument);
					continue;
				}
				slot = ncfg_push(ctx, &current->modifiers, &current->modifier_count,
				    sizeof(*current->modifiers));
				if (!slot) {
					free(argument);
					break;
				}
				slot->keyword = ncfg_dup(ctx, word);
				slot->argument = argument;
				continue;
			}
			if (starts_entry(word)) {
				current = ncfg_push(ctx, &entries, &entry_count, sizeof(*entries));
				if (!current) {
					break;
				}
				current->head = ncfg_dup(ctx, word);
				current->span = lines.at[line].span;
				continue;
			}
			ncfg_diag(ctx, lines.at[line].span,
			    "`%s` is not an address or keyword: an entry is an address, or one of dhcp, "
			    "dhcp6, slaac, link-local", word);
		}
		ncfg_words_free(&words);
	}
	ncfg_words_free(&lines);

	for (i = 0; i < entry_count; i++) {
		ncfg_address_source_t built;

		memset(&built, 0, sizeof(built));
		if (!address_source(ctx, &entries[i], &built)) {
			continue;
		}
		{
			ncfg_address_source_t *slot = ncfg_push(ctx, list, count, sizeof(*slot));

			if (!slot) {
				break;
			}
			*slot = built;
			if (owner) {
				ncfg_record(ctx, ctx->source, entries[i].span,
				    "interfaces[%s].addressing[%zu]", owner, *count - 1u);
			}
		}
	}
	entries_free(entries, entry_count);
}

/* ------------------------------------------------------------------------ *
 * Routes
 * ------------------------------------------------------------------------ */

/* One entry of a `routes` value: `default via 10.0.0.1 metric 100`.
 *
 * Built into a local and handed over whole, so that a route refused halfway
 * leaves the caller's slot untouched rather than holding half of one. */
int ncfg_lower_route(ncfg_lower_ctx_t *ctx, const ncfg_word_t *entry, ncfg_route_t *out)
{
	ncfg_words_t     words;
	ncfg_ast_value_t fake;
	ncfg_route_t     route;
	char            *network = NULL;
	size_t           at;
	int              masked;

	memset(&route, 0, sizeof(route));
	memset(&fake, 0, sizeof(fake));
	fake.kind = NCFG_AST_STRING;
	fake.span = entry->span;
	fake.string = entry->text;
	fake.string_length = strlen(entry->text);
	if (!ncfg_as_words(ctx, &fake, &words) || words.count == 0) {
		ncfg_words_free(&words);
		return 0;
	}

	/* `default` and the other non-prefix spellings pass through untouched;
	 * anything that is a prefix is checked and canonicalised. */
	masked = ncfg_network_of(ctx, words.at[0].text, &network);
	if (masked == 0) {
		ncfg_diag(ctx, entry->span,
		    "`%s` has host bits set, so it is not a network: write `%s`, which is the network "
		    "it names", words.at[0].text, network ? network : "");
		free(network);
		ncfg_words_free(&words);
		return 0;
	}
	if (masked < 0) {
		/*
		 * **`default`, or a prefix, and nothing else.** This used to let any
		 * word through on the grounds that `default` is not a prefix, so a
		 * typo compiled, planned, and failed at `route.add` -- measured, after
		 * three other actions had already been carried out, leaving the
		 * machine half configured over a spelling.
		 */
		if (strcmp(words.at[0].text, "default") != 0) {
			ncfg_diag(ctx, entry->span,
			    "`%s` is not a route destination: a destination is `default` or a network "
			    "like `10.0.0.0/8`; the gateway goes after `via`", words.at[0].text);
			ncfg_words_free(&words);
			return 0;
		}
		network = ncfg_dup(ctx, "default");
	}
	route.destination = network;

	for (at = 1u; at < words.count; at++) {
		const char *word = words.at[at].text;
		const char *argument = (at + 1u < words.count) ? words.at[at + 1u].text : NULL;

		if (strcmp(word, "onlink") == 0) {
			route.onlink = 1;
			continue;
		}
		if (strcmp(word, "via") == 0 || strcmp(word, "src") == 0) {
			char *canonical = NULL;

			if (argument && ncfg_is_bare_address(argument)) {
				canonical = ncfg_canonical_address(ctx, argument);
			}
			if (!canonical) {
				ncfg_diag(ctx, entry->span, "`%s` needs an IP address", word);
				goto refused;
			}
			if (word[0] == 'v') {
				route.via = canonical;
			} else {
				route.src = canonical;
			}
			at++;
			continue;
		}
		if (strcmp(word, "metric") == 0 || strcmp(word, "table") == 0) {
			char         *end;
			unsigned long number = argument ? strtoul(argument, &end, 10) : 0;

			if (!argument || end == argument || *end != '\0' || number > 4294967295UL) {
				ncfg_diag(ctx, entry->span, "`%s` needs a number", word);
				goto refused;
			}
			if (word[0] == 'm') {
				route.metric.has = 1;
				route.metric.value = (int64_t)number;
			} else {
				route.table.has = 1;
				route.table.value = (int64_t)number;
			}
			at++;
			continue;
		}
		ncfg_diag(ctx, entry->span,
		    "unknown route keyword `%s`: keywords: via, metric, table, src, onlink", word);
		goto refused;
	}
	ncfg_words_free(&words);
	*out = route;
	return 1;

refused:
	ncfg_words_free(&words);
	free(route.destination);
	free(route.via);
	free(route.src);
	return 0;
}
