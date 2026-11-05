/*
 * daemon_node.c -- what the daemon answers an operator of its estate, over
 * fuzznet's remote hop (decision 0311, project.md 10.685).
 *
 * THE FLEET'S SIMPLE CASE
 *   Every node of one estate does what an authenticated operator of that
 *   estate asks, and each node decides in detail what that is (the holder,
 *   2026-11-03). fuzznet authenticates the operator -- a request reaches this
 *   only from a member of the estate, or from a contact, which is said -- and
 *   this node's `remote` block decides what it may do: the same booleans per
 *   tier (0128) that judged a caller arriving through the agent before.
 *
 * THE VOCABULARY IS THE LOCAL ONE
 *   A request is a line, as on the local socket, so a verb means one thing
 *   wherever it is asked. `get status [FROM]` answers
 *   `ok TOTAL FROM COUNT DIGEST`, a newline, and COUNT bytes of the
 *   observation's JSON from offset FROM: paged, because a remote reply has a
 *   cap this side does not choose, and the status of a busy router is tens of
 *   kilobytes. A caller asks again from FROM + COUNT until it has TOTAL.
 *
 *   DIGEST is of the whole status the page was cut from, so pages of two
 *   statuses are never joined: `client/ncfg_fuzznet.h` says why, and joins
 *   them.
 *
 * Kept apart from `daemon_main.c` so a test can ask it without a node.
 */
#include "main_internal.h"
#include "loop_internal.h"

#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/daemon.h"
#include "ncfg/observed.h"
#include "ncfg/proto.h"
#include "ncfg_fuzznet.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The line, NUL-ended, into `out`: 0 where it does not fit or holds a NUL. */
static int line_of(const char *request, size_t length, char *out, size_t out_size)
{
	if (length >= out_size || memchr(request, '\0', length) != NULL) {
		return 0;
	}
	memcpy(out, request, length);
	out[length] = '\0';
	while (length && (out[length - 1u] == '\n' || out[length - 1u] == '\r')) {
		out[--length] = '\0';
	}
	return 1;
}

static size_t say(char *reply, size_t cap, const char *word, const char *sentence)
{
	int wrote = snprintf(reply, cap, "%s %s\n", word, sentence);

	return wrote > 0 && (size_t)wrote < cap ? (size_t)wrote : 0u;
}

/*
 * The length of `text` as fuzznet's local grammar escapes it (its sec 668): a
 * byte up to a space, a `%`, a comma or DEL takes three.
 */
static size_t escaped_length(const char *text, size_t length)
{
	size_t at;
	size_t total = 0;

	for (at = 0; at < length; at++) {
		unsigned char c = (unsigned char)text[at];

		total += c <= ' ' || c == '%' || c == ',' || c == 0x7fu ? 3u : 1u;
	}
	return total;
}

/*
 * One page of `status`, whatever it holds: the header and as much from `from` as
 * fits `cap`, and `escaped_cap` escaped where that is not 0. 0 where not even the
 * header would.
 */
static size_t page_of(const ncfg_buf_t *whole, unsigned long from, char *reply, size_t cap,
    size_t escaped_cap)
{
	const ncfg_buf_t *status = whole;
	uint64_t          digest;
	size_t            header;
	size_t            count;
	int               wrote;

	if (from > status->length) {
		from = status->length;
	}
	/* The header at its longest, so the page is sized before it is written. */
	digest = ncfg_status_page_digest(status->data, status->length);
	wrote = snprintf(reply, cap, "ok %zu %lu %zu %016llx\n", status->length, from, status->length,
	    (unsigned long long)digest);
	if (wrote <= 0 || (size_t)wrote >= cap ||
	    (escaped_cap && escaped_length(reply, (size_t)wrote) >= escaped_cap)) {
		return 0u;
	}
	count = status->length - (size_t)from;
	if (count > cap - (size_t)wrote) {
		count = cap - (size_t)wrote;
	}
	if (escaped_cap) {
		size_t room = escaped_cap - escaped_length(reply, (size_t)wrote);
		size_t take = 0;

		while (take < count) {
			size_t one = escaped_length(status->data + from + take, 1u);

			if (one > room) {
				break;
			}
			room -= one;
			take++;
		}
		count = take;
	}
	wrote = snprintf(reply, cap, "ok %zu %lu %zu %016llx\n", status->length, from, count,
	    (unsigned long long)digest);
	header = (size_t)wrote;
	memcpy(reply + header, status->data + from, count);
	return header + count;
}


/*
 * The status, one page of it, for a caller already identified: `local` the
 * peer of a caller on this machine, judged by the control tiers as the socket
 * judges one; NULL for an operator of the estate, judged by the `remote`
 * block. `args` is the offset, or nothing. Where `escaped_cap` is not 0 the
 * page is also no longer than that once escaped, which is how fuzznet hands a
 * procedure's answer to a local client.
 */
size_t ncfg_main_node_status(const ncfg_main_policy_t *policy, const ncfg_observed_t *observed,
    const ncfg_peer_t *local, const char *args, size_t length, char *reply, size_t cap,
    size_t escaped_cap)
{
	ncfg_proto_request_t asked;
	ncfg_authz_roots_t   roots = ncfg_authz_roots_default();
	ncfg_buf_t           status;
	char                 line[64];
	char                 err[NCFG_ERROR_MAX];
	const char          *rest = line;
	unsigned long        from = 0;
	size_t               wrote_all;
	int                  allowed;

	if (!policy || !reply || cap == 0u) {
		return 0u;
	}
	if (!line_of(args ? args : "", args ? length : 0u, line, sizeof(line))) {
		return say(reply, cap, "malformed", "`status` takes an offset, or nothing");
	}
	while (*rest == ' ') {
		rest++;
	}
	if (*rest) {
		char *end = NULL;

		if (*rest < '0' || *rest > '9') {
			return say(reply, cap, "malformed", "`status` takes an offset, or nothing");
		}
		from = strtoul(rest, &end, 10);
		if (!end || *end != '\0') {
			return say(reply, cap, "malformed", "`status` takes an offset, or nothing");
		}
	}
	memset(&asked, 0, sizeof(asked));
	asked.kind = NCFG_PROTO_REQ_STATUS;
	err[0] = '\0';
	allowed = local ? ncfg_authz_permitted(&roots, &policy->control, &policy->remote,
	                      NCFG_ARRIVED_LOCAL, local, &asked, err, sizeof(err))
	                : ncfg_authz_check(&roots, &policy->control, &policy->remote,
	                      NCFG_ARRIVED_REMOTE, NULL, &asked, err, sizeof(err));
	if (!allowed) {
		return say(reply, cap, "denied", err);
	}
	ncfg_buf_init(&status, NCFG_PROTO_MAX_LINE);
	if (!observed || !ncfg_daemon_status_encode(observed, &status, err, sizeof(err))) {
		ncfg_buf_free(&status);
		return say(reply, cap, "error", err[0] ? err : "there is no observation to answer with");
	}
	wrote_all = page_of(&status, from, reply, cap, escaped_cap);
	ncfg_buf_free(&status);
	return wrote_all;
}

size_t ncfg_main_node_events(const ncfg_main_policy_t *policy,
    const ncfg_main_subscribers_t *subscribers, const ncfg_peer_t *local, const char *args,
    size_t length, char *reply, size_t cap, size_t escaped_cap)
{
	ncfg_proto_request_t asked;
	ncfg_authz_roots_t   roots = ncfg_authz_roots_default();
	ncfg_buf_t           lines;
	char                 line[64];
	char                 err[NCFG_ERROR_MAX];
	long                 since = -1;
	unsigned long        from = 0;
	size_t               wrote;

	if (!policy || !reply || cap == 0u) {
		return 0u;
	}
	/* SINCE FROM, or `-` for only where to ask from. */
	if (!line_of(args ? args : "", args ? length : 0u, line, sizeof(line)) ||
	    (line[0] != '-' && sscanf(line, "%ld %lu", &since, &from) != 2)) {
		return say(reply, cap, "malformed", "`eventlog` takes SINCE FROM, or `-`");
	}
	/* What may read the status may read what it says happened. */
	memset(&asked, 0, sizeof(asked));
	asked.kind = NCFG_PROTO_REQ_STATUS;
	err[0] = '\0';
	if (!(local ? ncfg_authz_permitted(&roots, &policy->control, &policy->remote,
	                  NCFG_ARRIVED_LOCAL, local, &asked, err, sizeof(err))
	            : ncfg_authz_check(&roots, &policy->control, &policy->remote,
	                  NCFG_ARRIVED_REMOTE, NULL, &asked, err, sizeof(err)))) {
		return say(reply, cap, "denied", err);
	}
	ncfg_buf_init(&lines, NCFG_PROTO_MAX_LINE);
	if (!ncfg_main_subscribers_since(subscribers, since, &lines)) {
		ncfg_buf_free(&lines);
		return say(reply, cap, "error", "the events would not fit an answer");
	}
	wrote = page_of(&lines, from, reply, cap, escaped_cap);
	ncfg_buf_free(&lines);
	return wrote;
}

size_t ncfg_main_node_remote(const ncfg_main_policy_t *policy, const ncfg_observed_t *observed,
    int contact, const char *request, size_t length, char *reply, size_t cap)
{
	static const char verb[] = "get status";
	char              line[128];

	if (!policy || !request || !reply || cap == 0u) {
		return 0u;
	}
	if (!line_of(request, length, line, sizeof(line)) ||
	    strncmp(line, verb, sizeof(verb) - 1u) != 0 ||
	    (line[sizeof(verb) - 1u] != '\0' && line[sizeof(verb) - 1u] != ' ')) {
		return 0u; /* not one of netcfgd's: fuzznet answers `unsupported` */
	}
	/*
	 * **A contact is not an operator.** fuzznet hands a contact's request on
	 * and says so; the fleet's simple case is the estate's operators, and a
	 * contact is somebody this estate shares with, not somebody it is run by.
	 */
	if (contact) {
		return say(reply, cap, "denied",
		    "a contact is not an operator of this estate, so this node answers it nothing");
	}
	return ncfg_main_node_status(policy, observed, NULL, line + sizeof(verb) - 1u,
	    strlen(line + sizeof(verb) - 1u), reply, cap, 0u);
}

int ncfg_main_node_permit(const ncfg_principal_t *observe, char *out, size_t size)
{
	const char *at;
	int         wrote;

	if (!observe || !out || size == 0u) {
		return -1;
	}
	out[0] = '\0';
	if (observe->kind == NCFG_PRINCIPAL_ROOT) {
		return 0; /* the node's own user, whom fuzznet serves without a grant */
	}
	/* Every local user may call (fuzznet sec 883), and netcfgd's tiers judge
	 * what they asked behind the procedure. */
	if (observe->kind == NCFG_PRINCIPAL_ANY) {
		(void)snprintf(out, size, "any=x");
		return 1;
	}
	if (observe->kind != NCFG_PRINCIPAL_USER && observe->kind != NCFG_PRINCIPAL_GROUP) {
		return -1;
	}
	if (!observe->name || !observe->name[0]) {
		return -1;
	}
	/* fuzznet's grant takes a name of these bytes only (its `permit.c`), and a
	 * grant it cannot parse would refuse the whole setting. */
	for (at = observe->name; *at; at++) {
		char c = *at;

		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
		        c == '-' || c == '_' || c == '.')) {
			return -1;
		}
	}
	wrote = snprintf(out, size, "%s:%s=x",
	    observe->kind == NCFG_PRINCIPAL_GROUP ? "group" : "user", observe->name);
	if (wrote <= 0 || (size_t)wrote >= size || (size_t)(at - observe->name) >= 64u) {
		out[0] = '\0';
		return -1;
	}
	return 1;
}

int ncfg_main_node_permit_any_of(const ncfg_principal_t *const *tiers, size_t count, char *out,
    size_t size)
{
	size_t used = 0;
	size_t at;

	if (!tiers || !out || size == 0u) {
		return -1;
	}
	out[0] = '\0';
	for (at = 0; at < count; at++) {
		char   grant[96];
		size_t length;
		int    want = ncfg_main_node_permit(tiers[at], grant, sizeof(grant));
		char  *seen;

		if (want < 0) {
			out[0] = '\0';
			return -1;
		}
		if (want == 0) {
			continue;
		}
		/* Anybody covers everybody else named. */
		if (strcmp(grant, "any=x") == 0) {
			(void)snprintf(out, size, "any=x");
			return 1;
		}
		length = strlen(grant);
		/* A whole grant already here, not one that merely starts the same. */
		for (seen = out; (seen = strstr(seen, grant)) != NULL; seen += length) {
			if ((seen == out || seen[-1] == ' ') && (seen[length] == ' ' || !seen[length])) {
				break;
			}
		}
		if (seen) {
			continue;
		}
		if (used + length + 2u > size) {
			out[0] = '\0';
			return -1;
		}
		used += (size_t)snprintf(out + used, size - used, "%s%s", used ? " " : "", grant);
	}
	return used ? 1 : 0;
}
