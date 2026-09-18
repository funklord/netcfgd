/*
 * lower_global.c -- `global`, and the DNS scope that appears in three places.
 *
 * `global` is the block with no interface to attach to: name resolution, who
 * may ask netcfgd for what, what to do when the machine stops matching the
 * document, and whether this machine does networking at all. It is also the
 * one block a drop-in may add to rather than replace, which is `merge.c`'s
 * business and not this file's -- by the time anything here runs, the folding
 * has happened and what arrives is one block's worth of items.
 *
 * The `dns` reader lives here rather than with the interface because the same
 * scope is written in three places -- `global`, an interface and a network --
 * and three readers is three chances to accept `servers` in one and not in
 * another.
 */
#include <stdlib.h>
#include <string.h>

#include "lower_internal.h"

#include "ncfg/base.h"
#include "ncfg/value.h"

/* ------------------------------------------------------------------------ *
 * Principals
 * ------------------------------------------------------------------------ */

/* Parse `root`, `any`, `user:NAME` or `group:NAME`. Returns 1, or 0 with the
 * offending text explained in `why`, for a diagnostic that can quote it. */
static int principal_parse(ncfg_lower_ctx_t *ctx, const char *text, ncfg_principal_t *out,
    char *why, size_t why_size)
{
	const char *name;

	if (strcmp(text, "root") == 0) {
		out->kind = NCFG_PRINCIPAL_ROOT;
		return 1;
	}
	if (strcmp(text, "any") == 0) {
		out->kind = NCFG_PRINCIPAL_ANY;
		return 1;
	}
	if (strncmp(text, "user:", 5u) == 0) {
		name = text + 5;
		if (name[0] == '\0') {
			ncfg_error_set(why, why_size, "user: needs a name after it");
			return 0;
		}
		out->kind = NCFG_PRINCIPAL_USER;
	} else if (strncmp(text, "group:", 6u) == 0) {
		name = text + 6;
		if (name[0] == '\0') {
			ncfg_error_set(why, why_size, "group: needs a name after it");
			return 0;
		}
		out->kind = NCFG_PRINCIPAL_GROUP;
	} else {
		ncfg_error_set(why, why_size, "`%s` is not root, any, user:NAME or group:NAME", text);
		return 0;
	}
	free(out->name);
	out->name = ncfg_dup(ctx, name);
	return out->name != NULL;
}

/* ------------------------------------------------------------------------ *
 * The DNS scope
 * ------------------------------------------------------------------------ */

void ncfg_lower_dns_key(ncfg_lower_ctx_t *ctx, ncfg_dns_policy_t *policy,
    const ncfg_ast_assignment_t *assignment)
{
	const char  *key = assignment->key;
	ncfg_words_t words;
	size_t       i;

	/* netifrc spells this as a space-separated string, so accept that as well
	 * as a list. The two spellings mean exactly the same thing. */
	if (strcmp(key, "dns") == 0 || strcmp(key, "servers") == 0) {
		if (!ncfg_as_words(ctx, assignment->value, &words)) {
			ncfg_words_free(&words);
			return;
		}
		for (i = 0; i < words.count; i++) {
			ncfg_dns_server_t *server;
			char              *canonical;

			if (!ncfg_is_bare_address(words.at[i].text)) {
				ncfg_diag(ctx, words.at[i].span, "`%s` is not an IP address",
				    words.at[i].text);
				continue;
			}
			canonical = ncfg_canonical_address(ctx, words.at[i].text);
			server = ncfg_push(ctx, &policy->servers, &policy->server_count,
			    sizeof(*policy->servers));
			if (!server) {
				free(canonical);
				break;
			}
			server->addr = canonical;
		}
		ncfg_words_free(&words);
		return;
	}
	if (strcmp(key, "dns_search") == 0 || strcmp(key, "search") == 0) {
		if (!ncfg_as_words(ctx, assignment->value, &words)) {
			ncfg_words_free(&words);
			return;
		}
		for (i = 0; i < words.count; i++) {
			(void)ncfg_push_string(ctx, &policy->search, &policy->search_count,
			    words.at[i].text);
		}
		ncfg_words_free(&words);
		return;
	}
	if (strcmp(key, "dns_domains") == 0 || strcmp(key, "domains") == 0) {
		if (!ncfg_as_words(ctx, assignment->value, &words)) {
			ncfg_words_free(&words);
			return;
		}
		for (i = 0; i < words.count; i++) {
			ncfg_routing_domain_t *domain;
			const char            *suffix = words.at[i].text;
			int                    exclusive = 0;

			/* A leading `~` is resolved's spelling for a routing-only domain.
			 * Accept it so a config copied from resolved does the same thing,
			 * but store the flag rather than the sigil. */
			if (suffix[0] == '~') {
				suffix++;
				exclusive = 1;
			}
			domain = ncfg_push(ctx, &policy->domains, &policy->domain_count,
			    sizeof(*policy->domains));
			if (!domain) {
				break;
			}
			domain->suffix = ncfg_dup(ctx, suffix);
			domain->exclusive = exclusive;
		}
		ncfg_words_free(&words);
		return;
	}
	if (strcmp(key, "dns_mode") == 0 || strcmp(key, "mode") == 0) {
		char           *name = ncfg_as_string(ctx, assignment->value);
		ncfg_dns_mode_t mode;

		if (!name) {
			return;
		}
		/*
		 * The spellings are `value.h`'s, which also takes `resolv.conf` for
		 * `write_resolv_conf` -- the file's own name, which is what an
		 * operator reaches for. **`exec` is refused here**, and that is the
		 * one place this reader is narrower than the enum: `DnsMode::Exec`
		 * carries a command, the language has no way to write one, and
		 * accepting the word would compile a mode with nothing to run.
		 */
		if (!ncfg_dns_mode_from_name(name, &mode, NULL, 0) || mode == NCFG_DNS_MODE_EXEC) {
			ncfg_diag(ctx, assignment->value->span,
			    "unknown dns mode `%s`: one of: none, write_resolv_conf, resolvconf, "
			    "openresolv, resolved, dnsmasq, unbound", name);
		} else {
			policy->mode.mode = (int)mode;
		}
		free(name);
		return;
	}
	ncfg_diag(ctx, assignment->span, "unknown dns key `%s`", key);
}

/* ------------------------------------------------------------------------ *
 * control, remote and connectivity
 * ------------------------------------------------------------------------ */

static void lower_control_key(ncfg_lower_ctx_t *ctx, ncfg_control_t *control,
    const ncfg_ast_assignment_t *assignment)
{
	char             *text = ncfg_as_string(ctx, assignment->value);
	ncfg_principal_t  principal;
	ncfg_principal_t *target;
	char              why[NCFG_ERROR_MAX];

	if (!text) {
		return;
	}
	memset(&principal, 0, sizeof(principal));
	if (!principal_parse(ctx, text, &principal, why, sizeof(why))) {
		ncfg_diag(ctx, assignment->value->span, "%s: for example: group:netdev, user:alice, "
		    "any, root", why);
		free(principal.name);
		free(text);
		return;
	}
	free(text);
	if (strcmp(assignment->key, "observe") == 0) {
		target = &control->observe;
	} else if (strcmp(assignment->key, "wifi") == 0) {
		target = &control->wifi;
	} else if (strcmp(assignment->key, "admin") == 0) {
		target = &control->admin;
	} else {
		ncfg_diag(ctx, assignment->span,
		    "unknown control key `%s`: the tiers are observe, wifi and admin",
		    assignment->key);
		free(principal.name);
		return;
	}
	free(target->name);
	*target = principal;
}

/*
 * One key of the `remote` block: which tiers reach the machine from off it.
 *
 * Booleans, where `control` takes principals, and the asymmetry is 0128's
 * point rather than an omission. A remote caller arrives as `agent/`, so
 * `user:alice` here would be a sentence the daemon cannot evaluate. The
 * diagnostic says so rather than saying "unknown value", because somebody
 * writing it has a reasonable model that happens to be wrong.
 */
static void lower_remote_key(ncfg_lower_ctx_t *ctx, ncfg_remote_policy_t *remote,
    const ncfg_ast_assignment_t *assignment)
{
	int *tier;
	int  flag;

	/*
	 * **Who may connect, which is a different question from which tiers are
	 * open.** The tiers describe a caller the daemon cannot see; this
	 * describes the local process holding the other end of the socket, which
	 * `SO_PEERCRED` answers exactly as it does for `control`. It decides the
	 * socket's mode and group, and it is `root` when unwritten (0159).
	 */
	if (strcmp(assignment->key, "agent") == 0) {
		char            *text = ncfg_as_string(ctx, assignment->value);
		ncfg_principal_t principal;
		char             why[NCFG_ERROR_MAX];

		if (!text) {
			return;
		}
		memset(&principal, 0, sizeof(principal));
		if (!principal_parse(ctx, text, &principal, why, sizeof(why))) {
			ncfg_diag(ctx, assignment->value->span,
			    "%s: `agent` says who on this machine may act as the agent: root, any, "
			    "user:NAME or group:NAME", why);
			free(principal.name);
		} else {
			free(remote->agent.name);
			remote->agent = principal;
		}
		free(text);
		return;
	}
	if (strcmp(assignment->key, "observe") == 0) {
		tier = &remote->observe;
	} else if (strcmp(assignment->key, "wifi") == 0) {
		tier = &remote->wifi;
	} else if (strcmp(assignment->key, "admin") == 0) {
		tier = &remote->admin;
	} else {
		ncfg_diag(ctx, assignment->span,
		    "unknown remote key `%s`: the tiers are observe, wifi and admin; `agent` says "
		    "who may connect", assignment->key);
		return;
	}
	if (!ncfg_as_bool(ctx, assignment->value, &flag)) {
		if (assignment->value->kind == NCFG_AST_STRING &&
		    strchr(assignment->value->string, ':')) {
			ncfg_diag(ctx, assignment->value->span,
			    "a remote tier is true or false: `remote` says which tiers reach this "
			    "machine from off it, not who -- every remote caller arrives as the agent, "
			    "so netcfgd has no principal to check. Who the caller is is the agent's to "
			    "decide (0128)");
		}
		return;
	}
	*tier = flag;
}

/*
 * What a word in `requires` means, or 0 if it means nothing.
 *
 * **A separate function, and the reason is the privilege gate.** That gate
 * reads the keys the compiler accepts out of the key matches, collecting every
 * arm until the `unknown ... key` line -- so a nested match on a *value* puts
 * its arms in the key list. Two of these words are `probe` and `route`, which
 * are plausible future keys in a way `on` and `off` are not, and classifying
 * them as ordinary now would pre-approve a key nobody has written yet.
 */
static int connectivity_requires(const char *word, int *out)
{
	if (strcmp(word, "route") == 0) {
		*out = NCFG_REQUIRES_ROUTE;
	} else if (strcmp(word, "probe") == 0) {
		*out = NCFG_REQUIRES_PROBE;
	} else if (strcmp(word, "address") == 0) {
		*out = NCFG_REQUIRES_ADDRESS;
	} else {
		return 0;
	}
	return 1;
}

/*
 * `connectivity { requires = "..."; ignore = [...] }` inside `global`.
 *
 * **Host-wide, because the question is about the machine.** A tray icon says
 * whether *this computer* is on the network; an answer assembled per interface
 * is what four clients were each assembling differently (0243).
 */
static void lower_connectivity_key(ncfg_lower_ctx_t *ctx, ncfg_connectivity_policy_t *policy,
    const ncfg_ast_assignment_t *assignment)
{
	if (strcmp(assignment->key, "requires") == 0) {
		char *word = ncfg_as_string(ctx, assignment->value);
		int   requires_;

		if (!word) {
			return;
		}
		if (connectivity_requires(word, &requires_)) {
			policy->requires_ = requires_;
		} else {
			ncfg_diag(ctx, assignment->span,
			    "`%s` is not something to require for connectivity: one of: route (a default "
			    "route, the default), probe (a probe that answered, for a captive portal), "
			    "address (an address is enough, for a machine on its own subnet)", word);
		}
		free(word);
		return;
	}
	if (strcmp(assignment->key, "ignore") == 0) {
		ncfg_words_t words;
		size_t       i;

		/* **Writing `ignore` replaces the default list rather than adding to
		 * it**, so the five families `document.h` ships are cleared first. */
		for (i = 0; i < policy->ignore_count; i++) {
			free(policy->ignore[i]);
		}
		free(policy->ignore);
		policy->ignore = NULL;
		policy->ignore_count = 0;

		if (!ncfg_as_words(ctx, assignment->value, &words)) {
			ncfg_words_free(&words);
			return;
		}
		for (i = 0; i < words.count; i++) {
			(void)ncfg_push_string(ctx, &policy->ignore, &policy->ignore_count,
			    words.at[i].text);
		}
		ncfg_words_free(&words);
		return;
	}
	ncfg_diag(ctx, assignment->span, "unknown connectivity key `%s`", assignment->key);
}

/* ------------------------------------------------------------------------ *
 * The keys `global` holds directly, and the ones written at the top level
 * ------------------------------------------------------------------------ */

void ncfg_lower_global_key(ncfg_lower_ctx_t *ctx, const ncfg_ast_assignment_t *assignment)
{
	ncfg_globals_t *globals = &ctx->document->globals;
	const char     *key = assignment->key;

	if (strcmp(key, "hostname") == 0) {
		char *name = ncfg_as_string(ctx, assignment->value);

		if (!name) {
			return;
		}
		if (strcmp(name, "dhcp") == 0) {
			globals->hostname_policy.kind = NCFG_HOSTNAME_POLICY_FROM_DHCP;
			free(globals->hostname_policy.name);
			globals->hostname_policy.name = NULL;
		} else if (ncfg_is_hostname(name)) {
			globals->hostname_policy.kind = NCFG_HOSTNAME_POLICY_STATIC;
			free(globals->hostname_policy.name);
			globals->hostname_policy.name = name;
			return;
		} else {
			/* Checked here because the kernel's refusal arrives at apply time
			 * as `EINVAL` on a file write, which names neither the key nor the
			 * line. */
			ncfg_diag(ctx, assignment->span,
			    "`%s` is not a hostname: letters, digits, hyphens and dots; each label at "
			    "most 63 characters and the whole name at most 253", name);
		}
		free(name);
		return;
	}
	if (strcmp(key, "confirm") == 0) {
		ncfg_as_u32_opt(ctx, assignment->value, &globals->confirm_default);
		return;
	}
	if (strcmp(key, "on_drift") == 0) {
		int policy;

		if (ncfg_as_drift(ctx, assignment->value, &policy)) {
			globals->on_drift_default = policy;
		}
		return;
	}
	if (strcmp(key, "profile") == 0) {
		char *name = ncfg_as_string(ctx, assignment->value);

		if (!name) {
			return;
		}
		/* The same rule a drop-in name follows, and for the same reason: this
		 * becomes a directory netcfgd opens, and a name carrying a separator
		 * would let the configuration choose where that is rather than
		 * netcfgd. */
		if (name[0] == '\0' || strchr(name, '/') || name[0] == '.') {
			ncfg_diag(ctx, assignment->span,
			    "`%s` cannot be a profile name: a plain name -- netcfgd chooses the "
			    "directory it is read from", name);
			free(name);
		} else {
			free(globals->profile);
			globals->profile = name;
		}
		return;
	}
	if (strcmp(key, "networking") == 0) {
		char *word = ncfg_as_string(ctx, assignment->value);

		if (!word) {
			return;
		}
		if (strcmp(word, "on") == 0) {
			globals->networking = NCFG_NETWORKING_ON;
		} else if (strcmp(word, "off") == 0) {
			globals->networking = NCFG_NETWORKING_OFF;
		} else {
			ncfg_diag(ctx, assignment->span, "`%s` is not a networking setting: one of: on, "
			    "off", word);
		}
		free(word);
		return;
	}
	if (strcmp(key, "dns") == 0 || strcmp(key, "dns_search") == 0 ||
	    strcmp(key, "dns_mode") == 0 || strcmp(key, "dns_domains") == 0) {
		ncfg_lower_dns_key(ctx, &globals->dns, assignment);
		return;
	}
	ncfg_diag(ctx, assignment->span, "unknown top-level key `%s`", key);
}

/* The four sub-blocks of `global`, each of which holds assignments and
 * nothing else. */
static void lower_global_sub_block(ncfg_lower_ctx_t *ctx, const ncfg_ast_block_t *inner)
{
	ncfg_globals_t *globals = &ctx->document->globals;
	size_t          i;

	for (i = 0; i < inner->items.count; i++) {
		const ncfg_ast_item_t *item = inner->items.at[i];

		if (item->kind != NCFG_AST_ITEM_ASSIGNMENT) {
			continue;
		}
		if (strcmp(inner->head, "dns") == 0) {
			ncfg_lower_dns_key(ctx, &globals->dns, &item->as.assignment);
		} else if (strcmp(inner->head, "control") == 0) {
			lower_control_key(ctx, &globals->control, &item->as.assignment);
		} else if (strcmp(inner->head, "connectivity") == 0) {
			lower_connectivity_key(ctx, &globals->connectivity, &item->as.assignment);
		} else {
			lower_remote_key(ctx, &globals->remote, &item->as.assignment);
		}
	}
}

void ncfg_lower_global_block(ncfg_lower_ctx_t *ctx, const ncfg_merged_block_t *block)
{
	size_t i;

	for (i = 0; i < block->item_count; i++) {
		const ncfg_ast_item_t *item = block->items[i].item;

		/* Each item is answered against the file it was written in, because
		 * `global` is the one block assembled from several. */
		ctx->source = block->items[i].source;
		switch (item->kind) {
		case NCFG_AST_ITEM_ASSIGNMENT:
			ncfg_lower_global_key(ctx, &item->as.assignment);
			break;
		case NCFG_AST_ITEM_BLOCK: {
			const char *head = item->as.block.head;

			if (strcmp(head, "dns") == 0 || strcmp(head, "control") == 0 ||
			    strcmp(head, "connectivity") == 0 || strcmp(head, "remote") == 0) {
				lower_global_sub_block(ctx, &item->as.block);
			} else {
				ncfg_diag(ctx, item->as.block.span, "`%s` is not valid inside `global`", head);
			}
			break;
		}
		case NCFG_AST_ITEM_HOOK:
			ncfg_diag(ctx, item->as.hook.span, "hooks belong to an interface, not to `global`");
			break;
		case NCFG_AST_ITEM_INCLUDE:
			ncfg_diag(ctx, item->as.include.span,
			    "include was not resolved before compiling");
			break;
		default:
			break;
		}
	}
}
