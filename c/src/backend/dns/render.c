/*
 * render.c -- turning DNS scopes into what each resolver wants.
 *
 * Pure, and separate from the writing, because "what would this produce?" is a
 * question worth answering without touching `/etc/resolv.conf` -- both in
 * checks and, eventually, in `ncfg plan`. See `dns.h` for the rule these all
 * serve: a scope-capable mode never flattens.
 */
#include "ncfg/dns.h"

#include "ncfg/base.h"
#include "ncfg/buf.h"

#include <stdlib.h>
#include <string.h>

/*
 * A rendered resolver configuration. Generous, because a forwarder's file
 * carries a stanza per scope per domain -- and bounded because the scope list
 * comes from a document a client may have sent.
 */
#define DNS_RENDER_MAX (512u * 1024u)

/* Append to a growable array of pointers. 1, or 0 with the array unchanged. */
static int push(const void ***items, size_t *count, size_t *capacity, const void *one)
{
	if (*count == *capacity) {
		size_t       wanted = *capacity ? *capacity * 2u : 8u;
		const void **grown = realloc((void *)*items, wanted * sizeof(*grown));

		if (!grown) {
			return 0;
		}
		*items = grown;
		*capacity = wanted;
	}
	(*items)[(*count)++] = one;
	return 1;
}

/* Whether two servers are the same server. The Rust compares the whole struct,
 * so a second scope naming the same address on a different port is a second
 * server -- which is right: they are two resolvers. */
static int same_server(const ncfg_dns_server_t *one, const ncfg_dns_server_t *two)
{
	const char *one_sni = one->sni ? one->sni : "";
	const char *two_sni = two->sni ? two->sni : "";

	if ((one->addr == NULL) != (two->addr == NULL)) {
		return 0;
	}
	if (one->addr && strcmp(one->addr, two->addr) != 0) {
		return 0;
	}
	if (one->port.has != two->port.has || one->port.value != two->port.value) {
		return 0;
	}
	return strcmp(one_sni, two_sni) == 0;
}

static int holds_server(const ncfg_dns_flat_t *flat, const ncfg_dns_server_t *one)
{
	size_t at;

	for (at = 0u; at < flat->server_count; at++) {
		if (same_server(flat->servers[at], one)) {
			return 1;
		}
	}
	return 0;
}

static int holds_text(const char *const *items, size_t count, const char *one)
{
	size_t at;

	for (at = 0u; at < count; at++) {
		if (strcmp(items[at], one) == 0) {
			return 1;
		}
	}
	return 0;
}

static int is_global(const ncfg_dns_scope_t *scope)
{
	return scope->name != NULL && strcmp(scope->name, NCFG_DNS_GLOBAL_SCOPE) == 0;
}

/* Fold one scope into the flat answer, first occurrence winning. */
static int absorb(ncfg_dns_flat_t *flat, const ncfg_dns_scope_t *scope, size_t *server_capacity,
    size_t *search_capacity, size_t *option_capacity)
{
	const ncfg_dns_policy_t *policy = scope->policy;
	size_t                   at;

	if (!policy) {
		return 1;
	}
	for (at = 0u; at < policy->server_count; at++) {
		if (!holds_server(flat, &policy->servers[at]) &&
		    !push((const void ***)&flat->servers, &flat->server_count, server_capacity,
		    &policy->servers[at])) {
			return 0;
		}
	}
	for (at = 0u; at < policy->search_count; at++) {
		if (!holds_text(flat->search, flat->search_count, policy->search[at]) &&
		    !push((const void ***)&flat->search, &flat->search_count, search_capacity,
		    policy->search[at])) {
			return 0;
		}
	}
	for (at = 0u; at < policy->option_count; at++) {
		if (!holds_text(flat->options, flat->option_count, policy->options[at]) &&
		    !push((const void ***)&flat->options, &flat->option_count, option_capacity,
		    policy->options[at])) {
			return 0;
		}
	}
	return 1;
}

int ncfg_dns_flatten(const ncfg_dns_scope_t *scopes, size_t count, ncfg_dns_flat_t *out, char *err,
    size_t err_size)
{
	size_t server_capacity = 0;
	size_t search_capacity = 0;
	size_t option_capacity = 0;
	size_t at;

	if (!out) {
		ncfg_error_set(err, err_size, "the dns scopes were flattened with nowhere to put the "
		                 "answer");
		return 0;
	}
	memset(out, 0, sizeof(*out));

	/* **Interfaces first, globals last**: a specific answer should be consulted
	 * before the fallback, and a flat resolver's only notion of "specific" is
	 * "earlier in the list". Two passes rather than a sort, because the order
	 * within each group is the caller's and must not move. */
	for (at = 0u; at < count; at++) {
		if (!is_global(&scopes[at]) &&
		    !absorb(out, &scopes[at], &server_capacity, &search_capacity, &option_capacity)) {
			ncfg_dns_flat_free(out);
			ncfg_error_set(err, err_size, "out of memory flattening the dns scopes");
			return 0;
		}
	}
	for (at = 0u; at < count; at++) {
		if (is_global(&scopes[at]) &&
		    !absorb(out, &scopes[at], &server_capacity, &search_capacity, &option_capacity)) {
			ncfg_dns_flat_free(out);
			ncfg_error_set(err, err_size, "out of memory flattening the dns scopes");
			return 0;
		}
	}
	return 1;
}

void ncfg_dns_flat_free(ncfg_dns_flat_t *flat)
{
	if (!flat) {
		return;
	}
	free((void *)flat->servers);
	free((void *)flat->search);
	free((void *)flat->options);
	memset(flat, 0, sizeof(*flat));
}

/* Take the rendered text out of a buffer, or say what went wrong. One place,
 * because six renderers end the same way. */
static char *finish(ncfg_buf_t *buf, const char *what, char *err, size_t err_size)
{
	char *out;

	if (ncfg_buf_failed(buf)) {
		ncfg_error_set(err, err_size, "the %s is larger than this build will render", what);
		ncfg_buf_free(buf);
		return NULL;
	}
	out = ncfg_buf_take(buf, NULL);
	if (!out) {
		/* **Nothing appended is a rendering and not a failure.** `ncfg_buf_take`
		 * hands back NULL for a buffer that never allocated, and an empty scope
		 * renders to an empty blob on purpose -- `resolvconf -a` handed a header
		 * with nothing under it is handed a file that says nothing in several
		 * lines. So the empty string is allocated here rather than reported as
		 * an error the caller would have to distinguish from a real one. */
		out = calloc(1u, 1u);
		if (!out) {
			ncfg_error_set(err, err_size, "out of memory rendering the %s", what);
		}
	}
	ncfg_buf_free(buf);
	return out;
}

/* A list joined by single spaces, under a keyword. Nothing at all where the
 * list is empty -- `resolvconf -a` must not be handed a file that says nothing
 * in several lines. */
static void add_list(ncfg_buf_t *buf, const char *keyword, const char *const *items, size_t count)
{
	size_t at;

	if (count == 0u) {
		return;
	}
	ncfg_buf_add_text(buf, keyword);
	for (at = 0u; at < count; at++) {
		ncfg_buf_add_char(buf, ' ');
		ncfg_buf_add_text(buf, items[at]);
	}
	ncfg_buf_add_char(buf, '\n');
}

char *ncfg_dns_resolv_conf(const ncfg_dns_flat_t *flat, const char *generator, char *err,
    size_t err_size)
{
	ncfg_buf_t buf;
	size_t     at;

	if (!flat) {
		ncfg_error_set(err, err_size, "resolv.conf was rendered with no scopes");
		return NULL;
	}
	ncfg_buf_init(&buf, DNS_RENDER_MAX);
	ncfg_buf_addf(&buf, "# Generated by %s. Edits will be overwritten.\n",
	    generator ? generator : "netcfgd");
	add_list(&buf, "search", flat->search, flat->search_count);
	for (at = 0u; at < flat->server_count && at < (size_t)NCFG_DNS_MAXNS; at++) {
		ncfg_buf_addf(&buf, "nameserver %s\n", flat->servers[at]->addr);
	}
	if (flat->server_count > (size_t)NCFG_DNS_MAXNS) {
		/* **Listed rather than dropped.** glibc reads at most three and
		 * silently ignores the rest, so writing more would look like it worked
		 * and quietly not -- and a reader of the file can see what was left
		 * out, which is the half that makes this a fact rather than a policy. */
		ncfg_buf_addf(&buf, "# %zu further server(s) omitted: the resolver reads at most %d\n",
		    flat->server_count - (size_t)NCFG_DNS_MAXNS, NCFG_DNS_MAXNS);
		for (at = (size_t)NCFG_DNS_MAXNS; at < flat->server_count; at++) {
			ncfg_buf_addf(&buf, "#   %s\n", flat->servers[at]->addr);
		}
	}
	add_list(&buf, "options", flat->options, flat->option_count);
	return finish(&buf, "resolv.conf", err, err_size);
}

char *ncfg_dns_resolvconf_blob(const ncfg_dns_policy_t *policy, char *err, size_t err_size)
{
	ncfg_buf_t buf;
	size_t     at;

	if (!policy) {
		ncfg_error_set(err, err_size, "a resolvconf blob was rendered with no policy");
		return NULL;
	}
	ncfg_buf_init(&buf, DNS_RENDER_MAX);
	add_list(&buf, "search", (const char *const *)policy->search, policy->search_count);
	for (at = 0u; at < policy->server_count; at++) {
		ncfg_buf_addf(&buf, "nameserver %s\n", policy->servers[at].addr);
	}
	add_list(&buf, "options", (const char *const *)policy->options, policy->option_count);
	return finish(&buf, "resolvconf blob", err, err_size);
}

/* A routing domain without its trailing dot, into `out`. dnsmasq's
 * `server=/suffix/` wants the bare label and the model permits `"."` as the
 * catch-all spelling. */
static const char *without_trailing_dot(const char *suffix, char *out, size_t out_size)
{
	size_t length = strlen(suffix);

	while (length > 0u && suffix[length - 1u] == '.') {
		length--;
	}
	if (length + 1u > out_size) {
		length = out_size - 1u;
	}
	memcpy(out, suffix, length);
	out[length] = '\0';
	return out;
}

char *ncfg_dns_dnsmasq_conf(const ncfg_dns_scope_t *scopes, size_t count, char *err,
    size_t err_size)
{
	ncfg_buf_t buf;
	size_t     scope_at;

	ncfg_buf_init(&buf, DNS_RENDER_MAX);
	ncfg_buf_add_text(&buf, "# Generated by netcfgd. Edits will be overwritten.\n");
	for (scope_at = 0u; scope_at < count; scope_at++) {
		const ncfg_dns_policy_t *policy = scopes[scope_at].policy;
		size_t                   at;

		ncfg_buf_addf(&buf, "\n# scope: %s\n", scopes[scope_at].name);
		if (!policy) {
			continue;
		}
		for (at = 0u; at < policy->server_count; at++) {
			const char *addr = policy->servers[at].addr;
			size_t      which;

			if (policy->domain_count == 0u) {
				ncfg_buf_addf(&buf, "server=%s\n", addr);
				continue;
			}
			for (which = 0u; which < policy->domain_count; which++) {
				char bare[256];

				/* A non-exclusive domain still routes in dnsmasq -- there is
				 * no "prefer but do not restrict" -- so the distinction the
				 * model draws is flattened here, and the difference shows up
				 * as the scope's servers also being usable generally. */
				ncfg_buf_addf(&buf, "server=/%s/%s\n",
				    without_trailing_dot(policy->domains[which].suffix, bare,
				    sizeof(bare)),
				    addr);
				if (!policy->domains[which].exclusive) {
					ncfg_buf_addf(&buf, "server=%s\n", addr);
				}
			}
		}
		for (at = 0u; at < policy->search_count; at++) {
			ncfg_buf_addf(&buf, "domain=%s\n", policy->search[at]);
		}
	}
	return finish(&buf, "dnsmasq configuration", err, err_size);
}

char *ncfg_dns_unbound_conf(const ncfg_dns_scope_t *scopes, size_t count, char *err,
    size_t err_size)
{
	ncfg_buf_t buf;
	size_t     scope_at;

	ncfg_buf_init(&buf, DNS_RENDER_MAX);
	ncfg_buf_add_text(&buf, "# Generated by netcfgd. Edits will be overwritten.\n");
	for (scope_at = 0u; scope_at < count; scope_at++) {
		const ncfg_dns_policy_t *policy = scopes[scope_at].policy;
		size_t                   zones;
		size_t                   which;

		ncfg_buf_addf(&buf, "\n# scope: %s\n", scopes[scope_at].name);
		if (!policy) {
			continue;
		}
		/* A `forward-zone` named `"."` is the catch-all and a named one is a
		 * routing domain; unbound distinguishes them only by the zone name, so
		 * the exclusive flag has no separate spelling here either. */
		zones = policy->domain_count ? policy->domain_count : 1u;
		for (which = 0u; which < zones; which++) {
			const char *zone = policy->domain_count ? policy->domains[which].suffix : ".";
			size_t      at;

			ncfg_buf_add_text(&buf, "forward-zone:\n");
			ncfg_buf_addf(&buf, "\tname: \"%s\"\n", zone);
			for (at = 0u; at < policy->server_count; at++) {
				ncfg_buf_addf(&buf, "\tforward-addr: %s\n", policy->servers[at].addr);
			}
			if (policy->transport.has &&
			    policy->transport.value == (int64_t)NCFG_DNS_TRANSPORT_TLS) {
				ncfg_buf_add_text(&buf, "\tforward-tls-upstream: yes\n");
			}
		}
	}
	return finish(&buf, "unbound configuration", err, err_size);
}

/* A JSON string. Escapes what JSON requires and nothing else. */
static void quote(ncfg_buf_t *buf, const char *text)
{
	ncfg_buf_add_char(buf, '"');
	for (; text != NULL && *text != '\0'; text++) {
		unsigned char one = (unsigned char)*text;

		switch (one) {
		case '"':
			ncfg_buf_add_text(buf, "\\\"");
			break;
		case '\\':
			ncfg_buf_add_text(buf, "\\\\");
			break;
		case '\n':
			ncfg_buf_add_text(buf, "\\n");
			break;
		case '\r':
			ncfg_buf_add_text(buf, "\\r");
			break;
		case '\t':
			ncfg_buf_add_text(buf, "\\t");
			break;
		default:
			if (one < 0x20u) {
				/* JSON requires escaping every control character, not only
				 * the ones with short forms. */
				ncfg_buf_addf(buf, "\\u%04x", (unsigned int)one);
			} else {
				ncfg_buf_add_char(buf, (char)one);
			}
			break;
		}
	}
	ncfg_buf_add_char(buf, '"');
}

char *ncfg_dns_scopes_json(const ncfg_dns_scope_t *scopes, size_t count, char *err,
    size_t err_size)
{
	ncfg_buf_t buf;
	size_t     scope_at;

	ncfg_buf_init(&buf, DNS_RENDER_MAX);
	ncfg_buf_add_text(&buf, "{\"scopes\":[");
	for (scope_at = 0u; scope_at < count; scope_at++) {
		const ncfg_dns_policy_t *policy = scopes[scope_at].policy;
		size_t                   at;

		if (scope_at > 0u) {
			ncfg_buf_add_char(&buf, ',');
		}
		ncfg_buf_add_char(&buf, '{');
		ncfg_buf_add_text(&buf, "\"name\":");
		quote(&buf, scopes[scope_at].name);
		ncfg_buf_add_text(&buf, ",\"servers\":[");
		for (at = 0u; policy && at < policy->server_count; at++) {
			if (at > 0u) {
				ncfg_buf_add_char(&buf, ',');
			}
			quote(&buf, policy->servers[at].addr);
		}
		ncfg_buf_add_text(&buf, "],\"search\":[");
		for (at = 0u; policy && at < policy->search_count; at++) {
			if (at > 0u) {
				ncfg_buf_add_char(&buf, ',');
			}
			quote(&buf, policy->search[at]);
		}
		ncfg_buf_add_text(&buf, "],\"domains\":[");
		for (at = 0u; policy && at < policy->domain_count; at++) {
			if (at > 0u) {
				ncfg_buf_add_char(&buf, ',');
			}
			ncfg_buf_add_text(&buf, "{\"suffix\":");
			quote(&buf, policy->domains[at].suffix);
			ncfg_buf_addf(&buf, ",\"exclusive\":%s}",
			    policy->domains[at].exclusive ? "true" : "false");
		}
		ncfg_buf_add_text(&buf, "]}");
	}
	ncfg_buf_add_text(&buf, "]}\n");
	return finish(&buf, "dns scope document", err, err_size);
}
