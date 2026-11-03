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
 *   `ok TOTAL FROM COUNT`, a newline, and COUNT bytes of the observation's
 *   JSON from offset FROM: paged, because a remote reply has a cap this side
 *   does not choose, and the status of a busy router is tens of kilobytes. A
 *   caller asks again from FROM + COUNT until it has TOTAL.
 *
 * Kept apart from `daemon_main.c` so a test can ask it without a node.
 */
#include "main_internal.h"

#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/daemon.h"
#include "ncfg/observed.h"
#include "ncfg/proto.h"

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

size_t ncfg_main_node_remote(const ncfg_main_policy_t *policy, const ncfg_observed_t *observed,
    int contact, const char *request, size_t length, char *reply, size_t cap)
{
	static const char    verb[] = "get status";
	ncfg_proto_request_t asked;
	ncfg_authz_roots_t   roots = ncfg_authz_roots_default();
	ncfg_buf_t           status;
	char                 line[128];
	char                 err[NCFG_ERROR_MAX];
	const char          *rest;
	unsigned long        from = 0;
	size_t               header;
	size_t               count;
	int                  wrote;

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
	rest = line + sizeof(verb) - 1u;
	while (*rest == ' ') {
		rest++;
	}
	if (*rest) {
		char *end = NULL;

		if (*rest < '0' || *rest > '9') {
			return say(reply, cap, "malformed", "`get status` takes an offset, or nothing");
		}
		from = strtoul(rest, &end, 10);
		if (!end || *end != '\0') {
			return say(reply, cap, "malformed", "`get status` takes an offset, or nothing");
		}
	}
	memset(&asked, 0, sizeof(asked));
	asked.kind = NCFG_PROTO_REQ_STATUS;
	err[0] = '\0';
	if (!ncfg_authz_check(&roots, &policy->control, &policy->remote, NCFG_ARRIVED_REMOTE, NULL,
	        &asked, err, sizeof(err))) {
		return say(reply, cap, "denied", err);
	}
	ncfg_buf_init(&status, NCFG_PROTO_MAX_LINE);
	if (!observed || !ncfg_daemon_status_encode(observed, &status, err, sizeof(err))) {
		ncfg_buf_free(&status);
		return say(reply, cap, "error", err[0] ? err : "there is no observation to answer with");
	}
	if (from > status.length) {
		from = status.length;
	}
	/* The header at its longest, so the page is sized before it is written. */
	wrote = snprintf(reply, cap, "ok %zu %lu %zu\n", status.length, from, status.length);
	if (wrote <= 0 || (size_t)wrote >= cap) {
		ncfg_buf_free(&status);
		return 0u;
	}
	count = status.length - (size_t)from;
	if (count > cap - (size_t)wrote) {
		count = cap - (size_t)wrote;
	}
	wrote = snprintf(reply, cap, "ok %zu %lu %zu\n", status.length, from, count);
	header = (size_t)wrote;
	memcpy(reply + header, status.data + from, count);
	ncfg_buf_free(&status);
	return header + count;
}
