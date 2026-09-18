/*
 * privilege.c -- what a configuration asks for beyond configuring a network.
 *
 * 0127 makes netcfgd the only writer of `/etc/netcfgd`, so config text arrives
 * from clients that are not root, and 0117's line is what has to be decided:
 *
 *   > A request that carries config text is remote code execution. A request
 *   > that carries an SSID and a passphrase is not.
 *
 * This tells the two apart. Given a parsed file it returns every production in
 * it that grants more than "configure this machine's network", so a caller who
 * is not root can be refused with the reason rather than with a shrug.
 *
 * **It is not a hook check.** Enumerating against the compiler rather than
 * from memory found six, three of which execute code, and only one is hooks.
 * `@secret:exec:` is the one that makes the point: a command run as root,
 * living inside the *secrets* feature, where somebody auditing for code
 * execution would not think to look.
 *
 * **The table is keyed on the block as well as the key, and that is load
 * bearing.** `config` inside `openvpn` is the path to a `.ovpn` file, which
 * carries `up` and `down` scripts; `config` inside `interface` is the
 * addressing list. Same word, and one of them is code execution. A key-only
 * table classifies one of the two wrongly and does it silently.
 *
 * WHERE THIS LIVES, AND WHY IT IS NOT IN `compile`
 *   The Rust keeps it in `netcfgd-compile`, beside the parser whose tree it
 *   walks. The C compile module landed without it and nothing but the content
 *   gate asks the question, so it is here, next to the gate that is the only
 *   caller. Moving it back is a rename; splitting it in two would be a second
 *   classification, which is the thing the Rust's own module comment warns
 *   about.
 */
#include "ncfg/daemon.h"

#include "ncfg/parse.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Assignments that are privileged, by the block they appear in.
 *
 * Every key the compiler accepts is classified, here or in
 * `tool/privilege-ordinary.txt`, and `tool/privilege_gate.py` fails when one
 * is neither. That gate reads the Rust, so what keeps *this* copy honest is
 * `authorize_test.c`, which pins the table entry for entry against the list the
 * Rust holds -- a table that quietly lost a row would otherwise let a
 * production through with nothing said.
 */
static const struct {
	const char             *block;
	const char             *key;
	ncfg_privilege_reason_t reason;
} privileged[] = {
	/* 0119's probe. `command` and `args` are the program and its arguments. */
	{ "probe", "command", NCFG_PRIV_PROBE },
	{ "probe", "args", NCFG_PRIV_PROBE },
	/* An .ovpn file, read by openvpn as root. 0046 puts everything else in
	 * that file, which is exactly why naming one is not an ordinary thing to
	 * be able to do. */
	{ "openvpn", "config", NCFG_PRIV_FOREIGN_CONFIG },
	{ "openvpn", "file", NCFG_PRIV_FOREIGN_CONFIG },
	/* 802.1X certificates and the key that goes with them. **Privileged only
	 * when they name a path**: a path is an instruction to open a file as
	 * root, and `@secret:name` is a reference to something netcfgd already
	 * holds. So an enterprise network is reachable from a desktop client, and
	 * pointing the supplicant at an arbitrary file still is not. */
	{ "wifi", "ca_cert", NCFG_PRIV_PATH },
	{ "wifi", "client_cert", NCFG_PRIV_PATH },
	{ "wifi", "private_key", NCFG_PRIV_PATH },
	/* The authorization policy itself, local and remote. Everything that
	 * decides who may do what is decided by root and nobody else, or the
	 * tiers below it mean nothing. */
	{ "control", "observe", NCFG_PRIV_AUTHORIZATION },
	{ "control", "wifi", NCFG_PRIV_AUTHORIZATION },
	{ "control", "admin", NCFG_PRIV_AUTHORIZATION },
	{ "remote", "observe", NCFG_PRIV_AUTHORIZATION },
	{ "remote", "wifi", NCFG_PRIV_AUTHORIZATION },
	{ "remote", "admin", NCFG_PRIV_AUTHORIZATION },
	/* A tun device handed to a principal the caller chose. `vxlan`'s `group`
	 * is a multicast address and is nothing to do with this -- the same word,
	 * two meanings, which is the second time the block qualifier has earned
	 * its place in this table. */
	{ "tun", "owner", NCFG_PRIV_PRINCIPAL },
	{ "tun", "group", NCFG_PRIV_PRINCIPAL }
};

const char *ncfg_privilege_why(ncfg_privilege_reason_t reason)
{
	switch (reason) {
	case NCFG_PRIV_HOOK:
		return "a hook body is shell, and a hook with no `run_as` runs as the daemon's "
		       "own user, which is root";
	case NCFG_PRIV_PROBE:
		return "a probe block is a program netcfgd runs, as root";
	case NCFG_PRIV_SECRET_EXEC:
		return "an `exec` secret provider is a command netcfgd runs, as root, to fetch "
		       "the value";
	case NCFG_PRIV_FOREIGN_CONFIG:
		return "that names another program's configuration file, which netcfgd hands to "
		       "it as root and which may itself name scripts to run";
	case NCFG_PRIV_PATH:
		return "that names a path on this machine, which is opened by a program running "
		       "as root -- send the contents instead and netcfgd will store them";
	case NCFG_PRIV_INCLUDE:
		return "`include` reads another file into this configuration, and a client "
		       "cannot know what is in it";
	case NCFG_PRIV_AUTHORIZATION:
		return "that changes who may ask netcfgd for what, so a caller who could send "
		       "it could widen its own rights";
	case NCFG_PRIV_PRINCIPAL:
		return "that hands a device netcfgd creates to a named user or group, which "
		       "gives them the traffic on it";
	case NCFG_PRIV_COUNT:
	default:
		return NULL;
	}
}

/* Whether an assignment is privileged, given the block it sits in. */
static int assignment_reason(const char *block, const char *key, ncfg_privilege_reason_t *out)
{
	size_t at;

	for (at = 0; at < sizeof(privileged) / sizeof(privileged[0]); at++) {
		if (strcmp(privileged[at].block, block) == 0 &&
		    strcmp(privileged[at].key, key) == 0) {
			*out = privileged[at].reason;
			return 1;
		}
	}
	return 0;
}

/* Whether a string value begins with `prefix`, over its counted length. A
 * value may carry a NUL, so this never uses `strncmp` on the byte array. */
static int string_starts_with(const ncfg_ast_value_t *value, const char *prefix)
{
	size_t length = strlen(prefix);

	if (!value || value->kind != NCFG_AST_STRING || !value->string) {
		return 0;
	}
	return value->string_length >= length && memcmp(value->string, prefix, length) == 0;
}

/*
 * Whether a certificate field names a path rather than stored content.
 *
 * `@secret:name` refers to something netcfgd holds, put there by a caller who
 * had it already -- so sending it grants nothing new. Anything else is a path,
 * which is an instruction to open a file as root and is the reason these
 * fields are on the table at all.
 *
 * A non-string value is treated as a path, which is the safe direction: it
 * will fail to compile anyway, and a classification that guessed "ordinary"
 * for something it could not read would be guessing in the direction that
 * grants.
 */
static int cert_is_a_path(const ncfg_ast_value_t *value)
{
	if (!value || value->kind != NCFG_AST_STRING) {
		return 1;
	}
	return !string_starts_with(value, "@secret:");
}

/*
 * The `@secret:exec:` provider, wherever a value can carry one.
 *
 * A value and not a key, which is why the table cannot express it: any key
 * taking a secret reference can carry this, and the provider is the third
 * field of a string.
 */
static int secret_exec(const ncfg_ast_value_t *value)
{
	size_t at;

	if (!value) {
		return 0;
	}
	if (value->kind == NCFG_AST_STRING) {
		return string_starts_with(value, "@secret:exec:");
	}
	if (value->kind != NCFG_AST_LIST) {
		return 0;
	}
	for (at = 0; at < value->entries.count; at++) {
		if (secret_exec(value->entries.at[at])) {
			return 1;
		}
	}
	return 0;
}

/*
 * Record one, or count it past the bound.
 *
 * `NCFG_DIAGS_MAX` bounds this for the reason it bounds the parser's
 * diagnostics: a finding per line is a file-sized allocation bought with a
 * file a client sent, and only the first is ever rendered. `total` goes on
 * counting, which is what the refusal's "N such productions" reads.
 */
static int record(ncfg_privilege_findings_t *out, ncfg_privilege_reason_t reason, char *what,
    ncfg_span_t span)
{
	if (!what) {
		return 0;
	}
	out->total++;
	if (out->count >= NCFG_DIAGS_MAX) {
		free(what);
		return 1;
	}
	if (out->count == out->capacity) {
		size_t                    wanted = out->capacity ? out->capacity * 2u : 8u;
		ncfg_privilege_finding_t *grown;

		if (wanted > NCFG_DIAGS_MAX) {
			wanted = NCFG_DIAGS_MAX;
		}
		grown = realloc(out->at, wanted * sizeof(*grown));
		if (!grown) {
			free(what);
			return 0;
		}
		out->at = grown;
		out->capacity = wanted;
	}
	out->at[out->count].reason = reason;
	out->at[out->count].what = what;
	out->at[out->count].span = span;
	out->count++;
	return 1;
}

/* `head.key`, or `key` at the top level where there is no block. */
static char *joined(const char *block, const char *key)
{
	size_t length = strlen(block) + 1u + strlen(key) + 1u;
	char  *text = malloc(length);

	if (!text) {
		return NULL;
	}
	(void)snprintf(text, length, "%s.%s", block, key);
	return text;
}

static char *surrounded(const char *before, const char *middle, const char *after)
{
	size_t length = strlen(before) + strlen(middle) + strlen(after) + 1u;
	char  *text = malloc(length);

	if (!text) {
		return NULL;
	}
	(void)snprintf(text, length, "%s%s%s", before, middle, after);
	return text;
}

static int walk(const ncfg_ast_items_t *items, const char *block,
    ncfg_privilege_findings_t *out);

static int walk_item(const ncfg_ast_item_t *item, const char *block,
    ncfg_privilege_findings_t *out)
{
	/*
	 * Every kind of item, and that is the statement half of the guarantee.
	 * The Rust gets an exhaustive `match` here so an `Item` variant added
	 * later fails to compile rather than slipping through unclassified; C
	 * cannot, so this switch names all four with no `default` -- which makes
	 * a fifth a `-Wswitch` warning under the tree's strict set, and the tree
	 * builds with warnings as failures.
	 */
	switch (item->kind) {
	case NCFG_AST_ITEM_HOOK:
		return record(out, NCFG_PRIV_HOOK,
		    surrounded("", item->as.hook.phase ? item->as.hook.phase : "", ""),
		    item->as.hook.span);
	case NCFG_AST_ITEM_INCLUDE:
		return record(out, NCFG_PRIV_INCLUDE,
		    surrounded("include \"", item->as.include.path ? item->as.include.path : "",
		        "\""),
		    item->as.include.span);
	case NCFG_AST_ITEM_ASSIGNMENT: {
		ncfg_privilege_reason_t reason;
		const ncfg_ast_value_t *value = item->as.assignment.value;

		if (item->as.assignment.key &&
		    assignment_reason(block, item->as.assignment.key, &reason)) {
			/* The one entry in the table that is conditional, and it is
			 * conditional on the value rather than the key. */
			if (reason != NCFG_PRIV_PATH || cert_is_a_path(value)) {
				if (!record(out, reason,
				        joined(block, item->as.assignment.key),
				        item->as.assignment.span)) {
					return 0;
				}
			}
		}
		if (secret_exec(value)) {
			return record(out, NCFG_PRIV_SECRET_EXEC,
			    surrounded(item->as.assignment.key ? item->as.assignment.key : "",
			        "= @secret:exec:", ""),
			    value->span);
		}
		return 1;
	}
	case NCFG_AST_ITEM_BLOCK:
		return walk(&item->as.block.items,
		    item->as.block.head ? item->as.block.head : "", out);
	}
	return 1;
}

static int walk(const ncfg_ast_items_t *items, const char *block, ncfg_privilege_findings_t *out)
{
	size_t at;

	for (at = 0; at < items->count; at++) {
		if (!items->at[at]) {
			continue;
		}
		if (!walk_item(items->at[at], block, out)) {
			return 0;
		}
	}
	return 1;
}

int ncfg_privilege_findings(const ncfg_ast_file_t *file, ncfg_privilege_findings_t *out,
    char *err, size_t err_size)
{
	if (!out) {
		ncfg_error_set(err, err_size, "nowhere to put the findings");
		return 0;
	}
	memset(out, 0, sizeof(*out));
	if (!file) {
		return 1;
	}
	if (!walk(&file->items, "", out)) {
		ncfg_privilege_findings_free(out);
		ncfg_error_set(err, err_size, "the configuration could not be classified: out of memory");
		return 0;
	}
	return 1;
}

void ncfg_privilege_findings_free(ncfg_privilege_findings_t *findings)
{
	size_t at;

	if (!findings) {
		return;
	}
	for (at = 0; at < findings->count; at++) {
		free(findings->at[at].what);
	}
	free(findings->at);
	memset(findings, 0, sizeof(*findings));
}
