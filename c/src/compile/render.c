/*
 * render.c -- the renderer's machinery, its host-wide policy, and the walk.
 *
 * Lives beside the parser deliberately, so that a key added to one is under
 * the nose of whoever adds it to the other. `render_private.h` says why this
 * module is three files and which one holds what.
 *
 * THE SPELLINGS ARE THE LANGUAGE'S, NEVER THE DOCUMENT'S
 *   Several word sets across these three files duplicate tables that already
 *   exist in the model, and the duplication is the point rather than an
 *   oversight: the document spells an interface kind `wire_guard` and
 *   `open_vpn`, and the configuration language spells the same two `wireguard`
 *   and `openvpn`. It spells a WPA generation `wpa2_wpa3`, and the language
 *   reads `wpa2+wpa3` and `wpa2wpa3` and neither of those. Reaching for
 *   `ncfg_interface_kind_name` here would compile a block with the feature
 *   silently missing, which is a defect this project has shipped twice. Each
 *   table says in its own comment which side it is on.
 *
 * A DEFAULT IS OMITTED, WITH ONE EXCEPTION THAT IS NOT A STYLE CHOICE
 *   A value equal to the parser's default is not written, so a person reading
 *   the profile afterwards can tell what was chosen from what was merely true.
 *   A bond's `mode` breaks that and has to: the *parser* requires the key even
 *   though the model defaults it, so a bond whose mode happened to equal the
 *   default would render as a block that no longer compiles. A model default
 *   and a language default are not the same fact.
 */
#include "ncfg/render.h"

#include "render_private.h"

#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/document.h"
#include "ncfg/value.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The three words `connectivity { requires = ... }` takes, from
 * `netcfgd-model/src/connectivity.rs`. The same on both sides. */
static const char *const requires_words[] = { "route", "probe", "address" };

const char *ncfg_render_word(const char *const *words, size_t count, int which)
{
	if (which < 0 || (size_t)which >= count) {
		return NULL;
	}
	return words[(size_t)which];
}

const char *ncfg_render_word_or_gap(const char *word)
{
	return word ? word : "?";
}

/* ------------------------------------------------------------------------ *
 * The override set
 * ------------------------------------------------------------------------ */

void ncfg_overrides_init(ncfg_overrides_t *overrides)
{
	if (!overrides) {
		return;
	}
	overrides->keys = NULL;
	overrides->count = 0;
	overrides->capacity = 0;
}

void ncfg_overrides_free(ncfg_overrides_t *overrides)
{
	size_t i;

	if (!overrides) {
		return;
	}
	for (i = 0; i < overrides->count; i++) {
		free(overrides->keys[i]);
	}
	free(overrides->keys);
	ncfg_overrides_init(overrides);
}

/* Grow a `char **` by one slot. Shared by the override set and the refusal
 * list because they are the same list with different contents, and two copies
 * of a growth loop is two places for an off-by-one. */
static int push_string(char ***items, size_t *count, size_t *capacity, char *owned)
{
	if (*count == *capacity) {
		size_t wanted = *capacity ? *capacity * 2u : 8u;
		char **grown = realloc(*items, wanted * sizeof(*grown));

		if (!grown) {
			return 0;
		}
		*items = grown;
		*capacity = wanted;
	}
	(*items)[(*count)++] = owned;
	return 1;
}

/* `"<kind> <name>"`, which is the Rust's key spelling kept exactly, so a
 * caller ported from that side needs no translation. */
static char *override_key(const char *kind, const char *name)
{
	size_t kind_length = strlen(kind ? kind : "");
	size_t name_length = strlen(name ? name : "");
	char  *key = malloc(kind_length + name_length + 2u);

	if (!key) {
		return NULL;
	}
	memcpy(key, kind ? kind : "", kind_length);
	key[kind_length] = ' ';
	memcpy(key + kind_length + 1u, name ? name : "", name_length);
	key[kind_length + 1u + name_length] = '\0';
	return key;
}

int ncfg_overrides_add(ncfg_overrides_t *overrides, const char *kind, const char *name, char *err,
    size_t err_size)
{
	char *key;

	if (!overrides) {
		ncfg_error_set(err, err_size, "an override was recorded with nowhere to put it");
		return 0;
	}
	key = override_key(kind, name);
	if (!key || !push_string(&overrides->keys, &overrides->count, &overrides->capacity, key)) {
		free(key);
		ncfg_error_set(err, err_size, "out of memory recording an override");
		return 0;
	}
	return 1;
}

int ncfg_overrides_has(const ncfg_overrides_t *overrides, const char *kind, const char *name)
{
	size_t i;
	char  *key;
	int    found = 0;

	if (!overrides || overrides->count == 0) {
		return 0;
	}
	key = override_key(kind, name);
	if (!key) {
		return 0;
	}
	for (i = 0; i < overrides->count && !found; i++) {
		found = strcmp(overrides->keys[i], key) == 0;
	}
	free(key);
	return found;
}

/* ------------------------------------------------------------------------ *
 * The refusal list
 * ------------------------------------------------------------------------ */

void ncfg_unrenderable_init(ncfg_unrenderable_t *missing)
{
	if (!missing) {
		return;
	}
	missing->items = NULL;
	missing->count = 0;
	missing->capacity = 0;
	missing->failed = 0;
}

void ncfg_unrenderable_free(ncfg_unrenderable_t *missing)
{
	size_t i;

	if (!missing) {
		return;
	}
	for (i = 0; i < missing->count; i++) {
		free(missing->items[i]);
	}
	free(missing->items);
	ncfg_unrenderable_init(missing);
}

void ncfg_render_refuse(ncfg_unrenderable_t *missing, const char *scope, const char *name,
    const char *format, ...)
{
	va_list args;
	int     wanted;
	size_t  prefix;
	char   *text;

	if (!missing || missing->failed) {
		return;
	}
	va_start(args, format);
	wanted = vsnprintf(NULL, 0, format, args);
	va_end(args);
	if (wanted < 0) {
		missing->failed = 1;
		return;
	}
	prefix = 0;
	if (scope) {
		prefix = strlen(scope) + 2u; /* the scope and the ": " after it */
		if (name) {
			prefix += strlen(name) + 1u; /* and a space before the name */
		}
	}
	text = malloc(prefix + (size_t)wanted + 1u);
	if (!text) {
		missing->failed = 1;
		return;
	}
	if (scope) {
		int written = name ? snprintf(text, prefix + 1u, "%s %s: ", scope, name)
		                   : snprintf(text, prefix + 1u, "%s: ", scope);

		if (written < 0) {
			free(text);
			missing->failed = 1;
			return;
		}
	}
	va_start(args, format);
	wanted = vsnprintf(text + prefix, (size_t)wanted + 1u, format, args);
	va_end(args);
	if (wanted < 0 ||
	    !push_string(&missing->items, &missing->count, &missing->capacity, text)) {
		free(text);
		missing->failed = 1;
	}
}

/* ------------------------------------------------------------------------ *
 * Writing values the lexer reads back
 * ------------------------------------------------------------------------ */

/* The one escape loop, so that a key added anywhere cannot be written through
 * a second one that forgot the backslash. */
static void add_escaped(ncfg_buf_t *out, const char *value)
{
	const char *at;

	for (at = value ? value : ""; *at; at++) {
		if (*at == '\\' || *at == '"') {
			ncfg_buf_add_char(out, '\\');
		}
		ncfg_buf_add_char(out, *at);
	}
}

void ncfg_render_quote(ncfg_buf_t *out, const char *value)
{
	ncfg_buf_add_char(out, '"');
	add_escaped(out, value);
	ncfg_buf_add_char(out, '"');
}

void ncfg_render_quote_secret(ncfg_buf_t *out, const ncfg_secret_ref_t *reference)
{
	static const char *const prefixes[] = { "@secret:", "@secret:keyring:", "@secret:pass:",
		"@secret:exec:" };
	const char *prefix = ncfg_render_word(prefixes, NCFG_COUNT_OF(prefixes),
	    reference->provider);

	ncfg_buf_add_char(out, '"');
	ncfg_buf_add_text(out, prefix ? prefix : "@secret:");
	add_escaped(out, reference->name);
	ncfg_buf_add_char(out, '"');
}

/* ------------------------------------------------------------------------ *
 * Lists
 * ------------------------------------------------------------------------ */

void ncfg_render_list_init(ncfg_render_list_t *list)
{
	ncfg_buf_init(&list->joined, 0);
	list->count = 0;
}

void ncfg_render_list_free(ncfg_render_list_t *list)
{
	ncfg_buf_free(&list->joined);
	list->count = 0;
}

ncfg_buf_t *ncfg_render_list_next(ncfg_render_list_t *list)
{
	if (list->count > 0) {
		ncfg_buf_add_text(&list->joined, ", ");
	}
	list->count++;
	return &list->joined;
}

void ncfg_render_list_emit(ncfg_buf_t *body, const char *indent, const char *key,
    const ncfg_render_list_t *list, int always_bracket)
{
	if (list->count == 0) {
		return;
	}
	ncfg_buf_addf(body, "%s%s = ", indent, key);
	if (always_bracket || list->count > 1u) {
		ncfg_buf_addf(body, "[%s]\n", ncfg_buf_text(&list->joined));
	} else {
		ncfg_buf_addf(body, "%s\n", ncfg_buf_text(&list->joined));
	}
}

void ncfg_render_opening(ncfg_buf_t *text, const char *kind, const char *name,
    const ncfg_overrides_t *overrides)
{
	ncfg_buf_add_char(text, '\n');
	if (ncfg_overrides_has(overrides, kind, name)) {
		ncfg_buf_add_text(text, "override ");
	}
	ncfg_buf_add_text(text, kind);
	ncfg_buf_add_char(text, ' ');
}

/* ------------------------------------------------------------------------ *
 * DNS
 * ------------------------------------------------------------------------ */

/*
 * A DNS scope, and whether it wrote anything.
 *
 * The answer matters to the two callers that have one: **an empty `dns { }` is
 * a statement, not an absence.** On an interface or a network it says "use the
 * nameservers this network hands out" -- decision 0007 makes a per-interface
 * policy a scope in its own right rather than an overlay -- so the block being
 * present and empty differs from its being absent, and a profile that lost it
 * would come back ignoring the lease's resolvers. Writing nothing when every
 * field is at its default is right for `global`, where the block carries no
 * meaning of its own, and was wrong for the other two.
 */
int ncfg_render_dns(const ncfg_dns_policy_t *dns, const char *indent, ncfg_buf_t *body,
    ncfg_unrenderable_t *missing, const char *scope, const char *name)
{
	ncfg_render_list_t servers;
	ncfg_render_list_t search;
	ncfg_render_list_t domains;
	const char        *mode = NULL;
	int                mode_differs;
	size_t             i;

	/* Four facts the model has and the configuration language cannot write:
	 * `lower_dns` reads `servers`, `search`, `domains` and `mode` and nothing
	 * else, and hardcodes a server's port and sni to absent. So these
	 * refusals cannot fire from a document the compiler produced. They cost
	 * nothing and are kept, because this takes a document rather than a config
	 * file and a missing refusal costs a silent drop. */
	if (dns->option_count > 0) {
		ncfg_render_refuse(missing, scope, name, "dns options");
	}
	if (dns->dnssec.has) {
		ncfg_render_refuse(missing, scope, name, "dnssec");
	}
	if (dns->transport.has) {
		ncfg_render_refuse(missing, scope, name, "dns transport");
	}

	ncfg_render_list_init(&servers);
	for (i = 0; i < dns->server_count; i++) {
		if (dns->servers[i].port.has || dns->servers[i].sni) {
			ncfg_render_refuse(missing, scope, name, "a dns server with a port or sni");
		}
		ncfg_render_quote(ncfg_render_list_next(&servers), dns->servers[i].addr);
	}
	ncfg_render_list_init(&search);
	for (i = 0; i < dns->search_count; i++) {
		ncfg_render_quote(ncfg_render_list_next(&search), dns->search[i]);
	}
	ncfg_render_list_init(&domains);
	for (i = 0; i < dns->domain_count; i++) {
		ncfg_buf_t *slot = ncfg_render_list_next(&domains);

		/* The `~` is the exclusive marker the parser reads back. A routing
		 * domain and a search suffix are two lists here and one list
		 * distinguished by that prefix in the text. */
		ncfg_buf_add_char(slot, '"');
		if (dns->domains[i].exclusive) {
			ncfg_buf_add_char(slot, '~');
		}
		ncfg_buf_add_text(slot, dns->domains[i].suffix ? dns->domains[i].suffix : "");
		ncfg_buf_add_char(slot, '"');
	}

	if (dns->mode.mode == NCFG_DNS_MODE_EXEC) {
		/* The model has the mode and the language has no word for it:
		 * `lower.rs` has no arm for `exec`, so there is nothing to write and
		 * the command it carries has nowhere to go. */
		ncfg_render_refuse(missing, scope, name, "dns mode exec");
	} else {
		mode = ncfg_dns_mode_name((ncfg_dns_mode_t)dns->mode.mode);
	}
	mode_differs = dns->mode.mode != NCFG_DNS_MODE_NONE;

	if (servers.count == 0 && search.count == 0 && domains.count == 0 && !mode_differs) {
		ncfg_render_list_free(&servers);
		ncfg_render_list_free(&search);
		ncfg_render_list_free(&domains);
		return 0;
	}
	ncfg_buf_addf(body, "%sdns {\n", indent);
	if (mode && mode_differs) {
		ncfg_buf_addf(body, "%s\tmode = \"%s\"\n", indent, mode);
	}
	ncfg_render_list_emit(body, indent, "\tservers", &servers, 1);
	ncfg_render_list_emit(body, indent, "\tsearch", &search, 1);
	ncfg_render_list_emit(body, indent, "\tdomains", &domains, 1);
	ncfg_buf_addf(body, "%s}\n", indent);
	ncfg_render_list_free(&servers);
	ncfg_render_list_free(&search);
	ncfg_render_list_free(&domains);
	return 1;
}

/* ------------------------------------------------------------------------ *
 * Host-wide policy
 * ------------------------------------------------------------------------ */

/* `root`, `any`, `user:NAME` or `group:NAME`, which is the whole shape -- four
 * of them, deliberately, and no expression language. */
static void quote_principal(ncfg_buf_t *body, const ncfg_principal_t *principal)
{
	ncfg_buf_t text;

	ncfg_buf_init(&text, 0);
	switch (principal->kind) {
	case NCFG_PRINCIPAL_ANY:
		ncfg_buf_add_text(&text, "any");
		break;
	case NCFG_PRINCIPAL_USER:
		ncfg_buf_addf(&text, "user:%s", principal->name ? principal->name : "");
		break;
	case NCFG_PRINCIPAL_GROUP:
		ncfg_buf_addf(&text, "group:%s", principal->name ? principal->name : "");
		break;
	default:
		ncfg_buf_add_text(&text, "root");
		break;
	}
	ncfg_render_quote(body, ncfg_buf_text(&text));
	ncfg_buf_free(&text);
}

static int principal_is_root(const ncfg_principal_t *principal)
{
	return principal->kind == NCFG_PRINCIPAL_ROOT;
}

static void render_control(const ncfg_control_t *control, ncfg_buf_t *body)
{
	static const char *const keys[] = { "observe", "wifi", "admin" };
	const ncfg_principal_t  *tiers[3];
	size_t                   i;

	tiers[0] = &control->observe;
	tiers[1] = &control->wifi;
	tiers[2] = &control->admin;
	if (principal_is_root(tiers[0]) && principal_is_root(tiers[1]) &&
	    principal_is_root(tiers[2])) {
		return;
	}
	ncfg_buf_add_text(body, "\tcontrol {\n");
	for (i = 0; i < NCFG_COUNT_OF(keys); i++) {
		ncfg_buf_addf(body, "\t\t%s = ", keys[i]);
		quote_principal(body, tiers[i]);
		ncfg_buf_add_char(body, '\n');
	}
	ncfg_buf_add_text(body, "\t}\n");
}

static void render_remote(const ncfg_remote_policy_t *remote, ncfg_buf_t *body)
{
	static const char *const keys[] = { "observe", "wifi", "admin" };
	int                      tiers[3];
	size_t                   i;

	tiers[0] = remote->observe;
	tiers[1] = remote->wifi;
	tiers[2] = remote->admin;
	if (!tiers[0] && !tiers[1] && !tiers[2] && principal_is_root(&remote->agent)) {
		return;
	}
	ncfg_buf_add_text(body, "\tremote {\n");
	for (i = 0; i < NCFG_COUNT_OF(keys); i++) {
		ncfg_buf_addf(body, "\t\t%s = %s\n", keys[i], tiers[i] ? "true" : "false");
	}
	/*
	 * **Dropped in silence by the Rust this ports, and reachable from the
	 * language** -- `lower_remote_key` reads it. `agent` is not a fourth tier:
	 * it says who on *this* machine may hold the other end of the socket, and
	 * it decides that socket's mode and group (0159). Root when unwritten, so
	 * a profile that lost it would close a socket the operator had opened to a
	 * group, with nothing said. See render.h on why a drop is worse than a
	 * refusal; this is now neither.
	 */
	if (!principal_is_root(&remote->agent)) {
		ncfg_buf_add_text(body, "\t\tagent = ");
		quote_principal(body, &remote->agent);
		ncfg_buf_add_char(body, '\n');
	}
	ncfg_buf_add_text(body, "\t}\n");
}

/*
 * `connectivity { requires = ...; ignore = [...] }`.
 *
 * **Also neither rendered nor refused by the Rust this ports**, and also
 * reachable from the language (`lower_connectivity_key`). Losing it puts a
 * machine back on the default ignore list, which is how a wired-only machine
 * with no network at all came to report itself connected by naming `docker0`
 * -- the defect the key was added for. Writing `ignore` **replaces** the
 * default rather than adding to it, so the list is written whole or not at
 * all, and an empty one is a statement in the way an empty `dns { }` is.
 */
static void render_connectivity(const ncfg_connectivity_policy_t *policy, ncfg_buf_t *body)
{
	const char *word = ncfg_render_word(requires_words, NCFG_COUNT_OF(requires_words),
	    policy->requires_);
	int         ignore_differs;
	size_t      i;

	ignore_differs = policy->ignore_count != ncfg_connectivity_default_ignore_count;
	for (i = 0; !ignore_differs && i < policy->ignore_count; i++) {
		ignore_differs = strcmp(policy->ignore[i] ? policy->ignore[i] : "",
		    ncfg_connectivity_default_ignore[i]) != 0;
	}
	if (policy->requires_ == NCFG_REQUIRES_ROUTE && !ignore_differs) {
		return;
	}
	ncfg_buf_add_text(body, "\tconnectivity {\n");
	if (word && policy->requires_ != NCFG_REQUIRES_ROUTE) {
		ncfg_buf_addf(body, "\t\trequires = \"%s\"\n", word);
	}
	if (ignore_differs) {
		ncfg_render_list_t ignore;

		ncfg_render_list_init(&ignore);
		for (i = 0; i < policy->ignore_count; i++) {
			ncfg_render_quote(ncfg_render_list_next(&ignore), policy->ignore[i]);
		}
		if (ignore.count == 0) {
			ncfg_buf_add_text(body, "\t\tignore = []\n");
		} else {
			ncfg_render_list_emit(body, "\t\t", "ignore", &ignore, 0);
		}
		ncfg_render_list_free(&ignore);
	}
	ncfg_buf_add_text(body, "\t}\n");
}

static void render_globals(const ncfg_document_t *document, ncfg_buf_t *text,
    ncfg_unrenderable_t *missing)
{
	const ncfg_globals_t *globals = &document->globals;
	ncfg_buf_t            body;

	ncfg_buf_init(&body, 0);

	/* `globals.profile` is deliberately not written. `ncfg profile save`
	 * selects the profile afterwards through its own drop-in, and a profile
	 * that named itself would make the loader choose again -- which the
	 * loader refuses. */
	if (globals->confirm_default.has) {
		ncfg_buf_addf(&body, "\tconfirm = %lld\n",
		    (long long)globals->confirm_default.value);
	}
	if (globals->on_drift_default != NCFG_DRIFT_POLICY_RECONCILE) {
		ncfg_buf_addf(&body, "\ton_drift = \"%s\"\n", ncfg_render_word_or_gap(
		    ncfg_drift_policy_name((ncfg_drift_policy_t)globals->on_drift_default)));
	}
	if (globals->networking != NCFG_NETWORKING_ON) {
		ncfg_buf_add_text(&body, "\tnetworking = \"off\"\n");
	}
	switch (globals->hostname_policy.kind) {
	case NCFG_HOSTNAME_POLICY_FROM_DHCP:
		ncfg_buf_add_text(&body, "\thostname = \"from_dhcp\"\n");
		break;
	case NCFG_HOSTNAME_POLICY_STATIC:
		ncfg_buf_add_text(&body, "\thostname = ");
		ncfg_render_quote(&body, globals->hostname_policy.name);
		ncfg_buf_add_char(&body, '\n');
		break;
	default:
		break;
	}
	(void)ncfg_render_dns(&globals->dns, "\t", &body, missing, "global", NULL);
	render_control(&globals->control, &body);
	render_remote(&globals->remote, &body);
	render_connectivity(&globals->connectivity, &body);

	if (ncfg_buf_text(&body)[0] != '\0') {
		/* `global` is a singleton whose sub-blocks merge (0147), so this is
		 * never `override`: writing one that replaced the block would discard
		 * whatever the base said about the parts this does not mention. */
		ncfg_buf_add_text(text, "\nglobal {\n");
		ncfg_buf_add_text(text, ncfg_buf_text(&body));
		ncfg_buf_add_text(text, "}\n");
	}
	ncfg_buf_free(&body);
}

/* ------------------------------------------------------------------------ *
 * The whole document
 * ------------------------------------------------------------------------ */

/*
 * The header the snapshot carries.
 *
 * **Its last sentence overstates what is below it**, and that is a known open
 * question rather than an oversight: this writes a value only where it differs
 * from a default, so `on_drift`, `autoconnect`, `networking`, the control and
 * remote blocks and the probe's numbers are left out when they are ordinary.
 * Both behaviours are defensible and a round trip cannot tell them apart,
 * since a written default compiles equal to an absent one. The wording is kept
 * exactly as the Rust has it rather than settled here by whoever ported it.
 */
static const char header[] = "# Written by netcfgd from what this machine was running.\n"
    "#\n"
    "# This is ordinary netcfgd configuration: edit it, diff it, commit it.\n"
    "# It is a snapshot rather than a hand-written profile, so it says\n"
    "# everything explicitly -- including things a person would have left to\n"
    "# a default.\n";

int ncfg_render(const ncfg_document_t *document, const ncfg_overrides_t *overrides,
    ncfg_buf_t *text, ncfg_unrenderable_t *missing, char *err, size_t err_size)
{
	size_t i;

	if (!document || !text) {
		ncfg_error_set(err, err_size,
		    "a document was rendered with nothing to render it into");
		return 0;
	}
	/* See render.h: a caller with nowhere to put the refusals is a caller
	 * discarding them, which is the silent drop this module exists to refuse
	 * wearing a different hat. */
	if (!missing) {
		ncfg_error_set(err, err_size,
		    "a document was rendered with nowhere to report what it could not render");
		return 0;
	}

	/* `schema_version` and `generated_by` are deliberately not written: the
	 * configuration language cannot express either, and the compiler
	 * regenerates both. */
	ncfg_buf_add_text(text, header);
	render_globals(document, text, missing);
	for (i = 0; i < document->interface_count; i++) {
		ncfg_render_interface(&document->interfaces[i], overrides, text, missing);
	}
	for (i = 0; i < document->network_count; i++) {
		ncfg_render_network(&document->networks[i], overrides, text, missing);
	}
	for (i = 0; i < document->device_count; i++) {
		ncfg_render_device(&document->devices[i], overrides, text, missing);
	}

	/* Named rather than skipped: these have no rendering yet, and a profile
	 * that quietly lacked them would be wrong in a way nobody would see until
	 * the rule or the access point was needed. */
	if (document->rule_count > 0) {
		ncfg_render_refuse(missing, NULL, NULL, "%zu routing rule(s)",
		    document->rule_count);
	}
	if (document->access_point_count > 0) {
		ncfg_render_refuse(missing, NULL, NULL, "%zu access_point block(s)",
		    document->access_point_count);
	}
	for (i = 0; i < document->bluetooth_count; i++) {
		ncfg_render_bluetooth(&document->bluetooth[i], overrides, text);
	}
	for (i = 0; i < document->linkset_count; i++) {
		ncfg_render_linkset(&document->linksets[i], overrides, text);
	}

	if (missing->failed) {
		ncfg_error_set(err, err_size,
		    "out of memory collecting what could not be rendered");
		ncfg_buf_free(text);
		return 0;
	}
	if (missing->count > 0) {
		ncfg_error_set(err, err_size, "%zu part(s) of this document have no rendering here",
		    missing->count);
		/* Half a profile that looks whole is worse than none, which is
		 * buf.h's argument about a failed buffer one level up. */
		ncfg_buf_free(text);
		return 0;
	}
	if (ncfg_buf_failed(text)) {
		ncfg_error_set(err, err_size, "the rendered configuration did not fit");
		return 0;
	}
	return 1;
}
