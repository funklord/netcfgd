/*
 * node_answer_test.c -- what the daemon answers an operator of its estate
 * over fuzznet's remote hop (`src/main/daemon_node.c`, decision 0311,
 * project.md 10.685), asked without a node: the line as fuzznet would hand it,
 * the policy as this node's configuration would set it.
 *
 * What has to hold: the node's own `remote` block decides (each node is
 * configured in detail, the holder's word), so `observe` closed is a denial
 * and open is the status; a contact is no operator; and the status comes in
 * pages that put back together are exactly what the control socket's status
 * says, however small the reply it has to fit.
 */
#include "../src/main/main_internal.h"

#include "ncfg/buf.h"
#include "ncfg/daemon.h"
#include "ncfg/proto.h"
#include "ncfg_fuzznet.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;

static void check(int condition, const char *what)
{
	printf("%-72s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

static size_t ask(const ncfg_main_policy_t *policy, const ncfg_observed_t *observed,
    int contact, const char *line, char *reply, size_t cap)
{
	size_t n = ncfg_main_node_remote(policy, observed, contact, line, strlen(line), reply, cap);

	if (n < cap) {
		reply[n] = '\0';
	}
	return n;
}

/* Every page of the status at a reply of `cap`, joined, into `out`; the
 * number of pages, or 0 where an answer was not a page. */
static const ncfg_buf_t *whole_status; /* what every page's digest must name */

static size_t pages(const ncfg_main_policy_t *policy, const ncfg_observed_t *observed,
    size_t cap, ncfg_buf_t *out)
{
	char   *reply = malloc(cap + 1u);
	size_t  from = 0;
	size_t  count = 0;
	size_t  total = 0;

	if (!reply) {
		return 0;
	}
	do {
		char               line[64];
		size_t             n;
		ncfg_status_page_t page;

		(void)snprintf(line, sizeof(line), "get status %zu", from);
		n = ask(policy, observed, 0, line, reply, cap);
		if (n == 0 || !ncfg_status_page_read(reply, n, &page) || page.from != from ||
		    page.digest != ncfg_status_page_digest(whole_status->data, whole_status->length) ||
		    ++count > 100000u) {
			free(reply);
			return 0;
		}
		ncfg_buf_add(out, page.bytes, page.count);
		total = page.total;
		from += page.count;
		if (page.count == 0 && from < total) {
			free(reply);
			return 0; /* no progress: a page too small to carry anything */
		}
	} while (from < total);
	free(reply);
	return count;
}

int main(void)
{
	ncfg_main_policy_t policy;
	ncfg_observed_t    observed;
	ncfg_buf_t         whole;
	ncfg_buf_t         joined;
	char               reply[4096];
	char               err[NCFG_ERROR_MAX];
	size_t             n;
	size_t             count;
	ncfg_status_page_t past;

	memset(&policy, 0, sizeof(policy));
	memset(&observed, 0, sizeof(observed));
	ncfg_buf_init(&whole, NCFG_PROTO_MAX_LINE);
	check(ncfg_daemon_status_encode(&observed, &whole, err, sizeof(err)) && whole.length > 20u,
	    "the control socket's status, to compare against");
	whole_status = &whole;

	n = ask(&policy, &observed, 0, "get status", reply, sizeof(reply));
	check(n > 0 && strncmp(reply, "denied ", 7) == 0 && strstr(reply, "`observe`") != NULL,
	    "with the node's remote observe tier closed, an operator is denied");

	policy.remote.observe = 1;
	n = ask(&policy, &observed, 1, "get status", reply, sizeof(reply));
	check(n > 0 && strncmp(reply, "denied ", 7) == 0 && strstr(reply, "contact") != NULL,
	    "a contact is no operator, whatever the tier");

	n = ask(&policy, &observed, 0, "get status", reply, sizeof(reply));
	check(n > 0 && strncmp(reply, "ok ", 3) == 0,
	    "with it open, an operator of the estate gets the status");

	ncfg_buf_init(&joined, NCFG_PROTO_MAX_LINE);
	count = pages(&policy, &observed, sizeof(reply), &joined);
	check(count == 1u && joined.length == whole.length &&
	        memcmp(joined.data, whole.data, whole.length) == 0,
	    "  in one page where it fits, the socket's status byte for byte");
	ncfg_buf_free(&joined);

	ncfg_buf_init(&joined, NCFG_PROTO_MAX_LINE);
	count = pages(&policy, &observed, 40u, &joined);
	check(count > 3u && joined.length == whole.length &&
	        memcmp(joined.data, whole.data, whole.length) == 0,
	    "  and in many where the reply is small, put back together exactly");
	ncfg_buf_free(&joined);

	/* As a procedure (10.688): every page fits once escaped -- a small bound
	 * here, so there are many; node_serve.sh asks fuzznet's own -- and the
	 * pages still join to the socket's status. */
	count = 0;
	{
		size_t from = 0;
		size_t worst = 0;
		int    fine = 1;

		ncfg_buf_init(&joined, NCFG_PROTO_MAX_LINE);
		while (fine && from < whole.length) {
			char               offset[32];
			ncfg_status_page_t page;
			size_t             escaped = 0;
			size_t             at;

			(void)snprintf(offset, sizeof(offset), "%zu", from);
			n = ncfg_main_node_status(&policy, &observed, NULL, offset, strlen(offset), reply,
			    sizeof(reply) - 1u, 120u);
			reply[n] = '\0';
			for (at = 0; at < n; at++) {
				unsigned char b = (unsigned char)reply[at];

				escaped += b <= ' ' || b == '%' || b == ',' || b == 0x7fu ? 3u : 1u;
			}
			worst = escaped > worst ? escaped : worst;
			fine = n > 0 && escaped <= 120u && ++count < 100000u &&
			    ncfg_status_page_read(reply, n, &page) && page.from == from && page.count > 0;
			if (fine) {
				ncfg_buf_add(&joined, page.bytes, page.count);
				from += page.count;
			}
		}
		check(fine && joined.length == whole.length &&
		        memcmp(joined.data, whole.data, whole.length) == 0 &&
		        count > 3u && worst > 100u,
		    "as a procedure, each page fits its bound escaped, and they join");
		ncfg_buf_free(&joined);
	}

	n = ask(&policy, &observed, 0, "get status 99999999", reply, sizeof(reply));
	check(n > 0 && ncfg_status_page_read(reply, n, &past) && past.count == 0u &&
	        past.from == past.total,
	    "an offset past the end is an empty page, not an error");
	n = ask(&policy, &observed, 0, "get status -1", reply, sizeof(reply));
	check(n > 0 && strncmp(reply, "malformed ", 10) == 0, "a signed offset is malformed");
	n = ask(&policy, &observed, 0, "get statusx", reply, sizeof(reply));
	check(n == 0, "a verb that only begins like it is not answered here");
	n = ask(&policy, &observed, 0, "get sticker 1", reply, sizeof(reply));
	check(n == 0, "nor is another verb, which fuzznet then answers unsupported");
	n = ask(&policy, NULL, 0, "get status", reply, sizeof(reply));
	check(n > 0 && strncmp(reply, "error ", 6) == 0,
	    "a daemon with no observation says so rather than answering empty");

	/* fuzznet's grant from the observe tier (10.688). */
	{
		ncfg_principal_t who;
		char             grant[96];

		memset(&who, 0, sizeof(who));
		who.kind = NCFG_PRINCIPAL_GROUP;
		who.name = (char *)"netcfgd";
		check(ncfg_main_node_permit(&who, grant, sizeof(grant)) == 1 &&
		        strcmp(grant, "group:netcfgd=x") == 0,
		    "observe = group:netcfgd grants that group fuzznet's call");
		who.kind = NCFG_PRINCIPAL_USER;
		who.name = (char *)"alice";
		check(ncfg_main_node_permit(&who, grant, sizeof(grant)) == 1 &&
		        strcmp(grant, "user:alice=x") == 0,
		    "  a user, that user");
		who.name = (char *)"al ice";
		check(ncfg_main_node_permit(&who, grant, sizeof(grant)) == -1 && grant[0] == '\0',
		    "  a name fuzznet's grant cannot carry is no grant, not a broken setting");
		who.kind = NCFG_PRINCIPAL_ROOT;
		who.name = NULL;
		check(ncfg_main_node_permit(&who, grant, sizeof(grant)) == 0,
		    "  root's needs none: fuzznet serves the node's own user");
		who.kind = NCFG_PRINCIPAL_ANY;
		check(ncfg_main_node_permit(&who, grant, sizeof(grant)) == -1,
		    "  and `any` is none a grant can say");
	}

	ncfg_buf_free(&whole);
	if (failures) {
		printf("\nnode_answer_test: %d check(s) FAILED\n", failures);
		return 1;
	}
	printf("\nnode_answer_test: all checks passed\n");
	return 0;
}
