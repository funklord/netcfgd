/*
 * ask_test.c -- `ask`, the control vocabulary as one fuzznet procedure
 * (`src/main/daemon_ask.c`, decision 0312, project.md 10.693), driven with an
 * answer of its own that counts how often it ran.
 *
 * WHAT HAS TO HOLD
 *   An answer is made once and paged from the copy, joining to exactly what
 *   the dispatcher wrote; a change is never run twice, a later page of one
 *   with no copy behind it being refused; an operator's apply needs a window
 *   and is refused without reaching the dispatcher; the node's `remote`
 *   block and `control` tiers decide, as on the socket; `hello` is answered
 *   with the caller's own tiers and `monitor` is refused as a stream; and two
 *   callers' answers are kept apart.
 */
#include "../src/main/main_internal.h"

#include "ncfg_fuzznet.h"

#include "ncfg/buf.h"
#include "ncfg/daemon.h"
#include "ncfg/proto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int    failures;
static size_t runs;
static char   long_answer[3001];

static void check(int condition, const char *what)
{
	printf("%-72s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

/* The dispatcher, faked: a long answer for anything, counted. */
static int fake_answer(void *context, const ncfg_proto_request_t *request,
    const ncfg_peer_t *peer, ncfg_arrival_t arrival, ncfg_buf_t *out, char *err,
    size_t err_size)
{
	(void)context;
	(void)request;
	(void)peer;
	(void)arrival;
	(void)err;
	(void)err_size;
	runs++;
	ncfg_buf_add_text(out, long_answer);
	ncfg_buf_add_char(out, '\n');
	return 1;
}

/* The dispatcher, answering every request with the socket's `ok`. */
static int ok_answer(void *context, const ncfg_proto_request_t *request,
    const ncfg_peer_t *peer, ncfg_arrival_t arrival, ncfg_buf_t *out, char *err,
    size_t err_size)
{
	(void)context;
	(void)request;
	(void)peer;
	(void)arrival;
	(void)err;
	(void)err_size;
	runs++;
	ncfg_buf_add_text(out, "{\"response\":\"ok\"}\n");
	return 1;
}

/* The dispatcher, answering every request with the socket's error document. */
static int error_answer(void *context, const ncfg_proto_request_t *request,
    const ncfg_peer_t *peer, ncfg_arrival_t arrival, ncfg_buf_t *out, char *err,
    size_t err_size)
{
	(void)context;
	(void)request;
	(void)peer;
	(void)arrival;
	runs++;
	return ncfg_daemon_error_encode("the machine said no", out, err, err_size);
}

/* Every page of `request` from this caller, joined into `out`; the number of
 * pages, or 0 where one was not a page of the same answer. */
static size_t gather(ncfg_main_ask_t *ask, const uint8_t *key, const ncfg_peer_t *peer,
    const char *request, size_t escaped_cap, uint64_t now, ncfg_buf_t *out)
{
	char               args[512];
	char               reply[2048];
	ncfg_status_page_t page;
	uint64_t           digest = 0;
	size_t             from = 0;
	size_t             pages = 0;
	size_t             n;

	ncfg_buf_free(out);
	do {
		(void)snprintf(args, sizeof(args), "%zu %s", from, request);
		n = ncfg_main_ask(ask, key, peer, args, strlen(args), reply, sizeof(reply),
		    escaped_cap, now);
		if (!n || !ncfg_status_page_read(reply, n, &page) || page.from != from ||
		    (pages && page.digest != digest) || ++pages > 1000u) {
			return 0;
		}
		digest = page.digest;
		ncfg_buf_add(out, page.bytes, page.count);
		from += page.count;
	} while (from < page.total && page.count > 0u);
	return pages;
}

/* The one page answering `request` from 0, as text. */
static const char *once(ncfg_main_ask_t *ask, const uint8_t *key, const ncfg_peer_t *peer,
    const char *request, uint64_t now)
{
	static char        text[2048];
	char               args[512];
	char               reply[2048];
	ncfg_status_page_t page;
	size_t             n;

	(void)snprintf(args, sizeof(args), "0 %s", request);
	n = ncfg_main_ask(ask, key, peer, args, strlen(args), reply, sizeof(reply), 0u, now);
	if (!n || !ncfg_status_page_read(reply, n, &page) || page.count >= sizeof(text)) {
		return "";
	}
	memcpy(text, page.bytes, page.count);
	text[page.count] = '\0';
	return text;
}

int main(void)
{
	static const uint8_t operator_key[32] = { 7 };
	static const uint8_t other_key[32] = { 9 };
	ncfg_control_t       control;
	ncfg_remote_policy_t remote;
	ncfg_main_ask_t      ask;
	ncfg_peer_t          root;
	ncfg_peer_t          user;
	ncfg_buf_t           joined;
	char                 args[256];
	char                 reply[2048];
	size_t               pages;
	size_t               at;
	size_t               n;
	const char          *said;

	for (at = 0; at < sizeof(long_answer) - 1u; at++) {
		long_answer[at] = (char)('a' + at % 26u);
	}
	/* The prefix without its NUL, which would end the answer at 23 bytes. */
	memcpy(long_answer, "{\"response\":\"x\",\"pad\":\"", 23u);
	memcpy(long_answer + sizeof(long_answer) - 3u, "\"}", 2u);
	long_answer[sizeof(long_answer) - 1u] = '\0';

	memset(&control, 0, sizeof(control)); /* every tier root's */
	memset(&remote, 0, sizeof(remote));   /* every remote tier closed */
	memset(&ask, 0, sizeof(ask));
	ask.answer = fake_answer;
	ask.control = &control;
	ask.remote = &remote;
	ask.roots = ncfg_authz_roots_default();
	memset(&root, 0, sizeof(root));
	root.groups_known = 1;
	memset(&user, 0, sizeof(user));
	user.uid = 1000;
	user.gid = 1000;
	user.groups_known = 1;
	ncfg_buf_init(&joined, 0);

	runs = 0;
	pages = gather(&ask, NULL, &root, "{\"request\":\"plan\"}", 200u, 1000u, &joined);
	check(pages > 10u && runs == 1u && joined.length == strlen(long_answer) &&
	        memcmp(joined.data, long_answer, joined.length) == 0,
	    "an answer is made once and paged from the copy, byte for byte");

	runs = 0;
	pages = gather(&ask, NULL, &root, "{\"request\":\"apply\",\"confirm\":null}", 200u, 2000u,
	    &joined);
	check(pages > 10u && runs == 1u, "a change runs once, however many pages it answers in");

	runs = 0;
	(void)snprintf(args, sizeof(args), "0 {\"request\":\"apply\",\"confirm\":null}");
	(void)ncfg_main_ask(&ask, NULL, &root, args, strlen(args), reply, sizeof(reply), 200u,
	    3000u);
	(void)snprintf(args, sizeof(args), "40 {\"request\":\"apply\",\"confirm\":null}");
	n = ncfg_main_ask(&ask, NULL, &root, args, strlen(args), reply, sizeof(reply), 0u,
	    3000u + 61000u);
	reply[n < sizeof(reply) ? n : sizeof(reply) - 1u] = '\0';
	check(runs == 1u && strstr(reply, "not run again") != NULL,
	    "  and a later page of one no longer kept is refused, not run again");
	(void)snprintf(args, sizeof(args), "40 {\"request\":\"plan\"}");
	n = ncfg_main_ask(&ask, NULL, &root, args, strlen(args), reply, sizeof(reply), 200u,
	    70000u);
	check(runs == 2u && n > 0u && strncmp(reply, "ok ", 3) == 0,
	    "  where a read no longer kept is answered afresh");

	runs = 0;
	said = once(&ask, operator_key, NULL, "{\"request\":\"plan\"}", 80000u);
	check(runs == 0u && strstr(said, "error") && strstr(said, "observe"),
	    "an operator is judged by the node's remote block: observe closed, denied");
	remote.observe = 1;
	said = once(&ask, operator_key, NULL, "{\"request\":\"plan\"}", 81000u);
	check(runs == 1u && strncmp(said, "{\"response\":\"x\"", 15) == 0,
	    "  and with it open, answered");

	remote.admin = 1;
	runs = 0;
	said = once(&ask, operator_key, NULL, "{\"request\":\"apply\",\"confirm\":null}", 82000u);
	check(runs == 0u && strstr(said, "confirm window") != NULL,
	    "an operator's apply without a window is refused before it reaches the daemon");
	said = once(&ask, operator_key, NULL, "{\"request\":\"apply\",\"confirm\":90}", 83000u);
	check(runs == 1u && strncmp(said, "{\"response\":\"x\"", 15) == 0,
	    "  and with one, applied");

	runs = 0;
	said = once(&ask, NULL, &user, "{\"request\":\"plan\"}", 84000u);
	check(runs == 0u && strstr(said, "error") != NULL,
	    "a caller on this machine is judged by the control tiers: not root, denied");
	said = once(&ask, NULL, &root, "{\"request\":\"apply\",\"confirm\":null}", 85000u);
	check(runs == 1u, "  and root may apply with no window, being at the console");
	/* 0316: a window of no seconds is no window, whoever's client sent it, and
	 * the way round says why. `runs` counts what reached the daemon. */
	{
		static const struct {
			const char *request;
			const char *says;
		} refused[] = {
			{ "{\"request\":\"apply\",\"confirm\":0}", "needs a confirm window" },
			{ "{\"request\":\"apply\",\"no_rollback\":\"x\"}", "has to be 0" },
			{ "{\"request\":\"apply\",\"confirm\":60,\"no_rollback\":\"x\"}", "has to be 0" },
			{ "{\"request\":\"apply\",\"confirm\":0,\"no_rollback\":\"\"}", "a reason of 1" },
			{ "{\"request\":\"apply\",\"confirm\":0,\"no_rollback\":\"a\\nb\"}", "control" },
		};
		size_t  before = runs;
		size_t  which;
		uint64_t when = 86000u;

		for (which = 0; which < sizeof(refused) / sizeof(refused[0]); which++) {
			said = once(&ask, operator_key, NULL, refused[which].request, when++);
			check(strstr(said, refused[which].says) != NULL && runs == before,
			    "an operator's apply with no real window or reason is refused");
		}
		said = once(&ask, operator_key, NULL,
		    "{\"request\":\"apply\",\"confirm\":0,\"no_rollback\":\"flashed\"}", when++);
		check(runs == before + 1u, "  and one that says why reaches the daemon");
		runs = before;
	}

	runs = 0;
	said = once(&ask, NULL, &root, "{\"request\":\"hello\"}", 86000u);
	check(runs == 0u && strstr(said, "hello") != NULL && strstr(said, "admin") != NULL,
	    "hello is answered here, with the tiers this caller holds");
	said = once(&ask, NULL, &root, "{\"request\":\"monitor\"}", 87000u);
	check(runs == 0u && strstr(said, "stream") != NULL, "monitor is refused as the stream it is");
	said = once(&ask, NULL, &root, "{\"request\":\"nonsense\"}", 88000u);
	check(runs == 0u && strstr(said, "error") != NULL, "a request the reader refuses is refused");
	n = ncfg_main_ask(&ask, NULL, &root, "x", 1u, reply, sizeof(reply), 0u, 89000u);
	reply[n < sizeof(reply) ? n : sizeof(reply) - 1u] = '\0';
	check(n > 0u && strstr(reply, "offset") != NULL, "and so are arguments without an offset");

	/* Two operators, each part-way through an answer: each gets its own. */
	runs = 0;
	(void)snprintf(args, sizeof(args), "0 {\"request\":\"plan\"}");
	(void)ncfg_main_ask(&ask, operator_key, NULL, args, strlen(args), reply, sizeof(reply),
	    200u, 90000u);
	(void)ncfg_main_ask(&ask, other_key, NULL, args, strlen(args), reply, sizeof(reply), 200u,
	    90000u);
	pages = gather(&ask, operator_key, NULL, "{\"request\":\"plan\"}", 200u, 90000u, &joined);
	check(pages > 10u && runs == 3u, "two callers' answers are kept apart");

	/* A request too long for one line, in pieces (10.695). */
	{
		static char big[2200];
		char        piece_args[1200];
		char        digest_text[20];
		uint64_t    digest;
		size_t      total;
		size_t      offset = 0;
		int         whole = 1;

		(void)snprintf(big, sizeof(big), "{\"request\":\"config_put\",\"name\":\"big\","
		    "\"text\":\"");
		at = strlen(big);
		while (at < sizeof(big) - 3u) {
			big[at++] = 'x';
		}
		memcpy(big + at, "\"}", 3u);
		total = strlen(big);
		digest = ncfg_status_page_digest(big, total);
		(void)snprintf(digest_text, sizeof(digest_text), "%016llx", (unsigned long long)digest);

		(void)snprintf(piece_args, sizeof(piece_args), "%zu 600 %s %.600s", total, digest_text,
		    big + 600);
		n = ncfg_main_ask_part(&ask, NULL, &root, piece_args, strlen(piece_args), reply,
		    sizeof(reply), 100000u);
		reply[n < sizeof(reply) ? n : 0] = '\0';
		check(strncmp(reply, "error ", 6) == 0, "a piece out of order is refused");

		runs = 0;
		while (offset < total) {
			size_t piece = total - offset < 600u ? total - offset : 600u;

			(void)snprintf(piece_args, sizeof(piece_args), "%zu %zu %s %.*s", total, offset,
			    digest_text, (int)piece, big + offset);
			n = ncfg_main_ask_part(&ask, NULL, &root, piece_args, strlen(piece_args), reply,
			    sizeof(reply), 100000u);
			reply[n < sizeof(reply) ? n : 0] = '\0';
			whole = whole && strncmp(reply, "ok ", 3) == 0;
			offset += piece;
		}
		check(whole && runs == 0u, "a long request is staged in pieces, none of them run");
		(void)snprintf(args, sizeof(args), "@%s", digest_text);
		pages = gather(&ask, NULL, &root, args, 200u, 100000u, &joined);
		check(pages > 10u && runs == 1u && joined.length == strlen(long_answer),
		    "  and `ask FROM @DIGEST` runs it once, paged from its kept answer");
		said = once(&ask, NULL, &root, args, 100001u);
		check(runs == 1u && strstr(said, "staged") != NULL,
		    "  and once run it is staged no longer");

		/* Refused rather than run, it goes all the same: what was staged may
		 * carry a secret, and it has no reason to wait for an expiry. */
		{
			static const char junk[] = "{\"request\":\"no-such-request\"}";

			(void)snprintf(args, sizeof(args), "@%016llx",
			    (unsigned long long)ncfg_status_page_digest(junk, strlen(junk)));
			(void)snprintf(piece_args, sizeof(piece_args), "%zu 0 %s %s", strlen(junk),
			    args + 1, junk);
			n = ncfg_main_ask_part(&ask, NULL, &root, piece_args, strlen(piece_args), reply,
			    sizeof(reply), 100002u);
			reply[n < sizeof(reply) ? n : 0] = '\0';
			check(strncmp(reply, "ok ", 3) == 0, "a request the reader refuses is staged");
			said = once(&ask, NULL, &root, args, 100003u);
			check(strstr(said, "staged") == NULL, "  and asked for, is refused for itself");
			said = once(&ask, NULL, &root, args, 100004u);
			check(strstr(said, "staged") != NULL, "  and is staged no longer");
		}

		/* Joined pieces that are not the request their digest names. */
		(void)snprintf(piece_args, sizeof(piece_args), "%zu 0 0000000000000001 %.600s", total,
		    big);
		(void)ncfg_main_ask_part(&ask, NULL, &root, piece_args, strlen(piece_args), reply,
		    sizeof(reply), 100002u);
		offset = 600u;
		while (offset < total) {
			size_t piece = total - offset < 600u ? total - offset : 600u;

			(void)snprintf(piece_args, sizeof(piece_args), "%zu %zu 0000000000000001 %.*s",
			    total, offset, (int)piece, big + offset);
			n = ncfg_main_ask_part(&ask, NULL, &root, piece_args, strlen(piece_args), reply,
			    sizeof(reply), 100002u);
			reply[n < sizeof(reply) ? n : 0] = '\0';
			offset += piece;
		}
		check(strstr(reply, "digest") != NULL, "pieces that are not their digest are refused");
	}

	/* `do` (10.708): `ok` only where the daemon carried the request out, and
	 * nothing where it refused -- which fuzznet's propagation reports as
	 * `failed`, where `ask`'s page would have read `ok`. */
	{
		ncfg_main_ask_t refusing;
		static const char apply[] = "{\"request\":\"apply\",\"confirm\":60}";

		runs = 0;
		remote.admin = 1;
		ask.answer = ok_answer;
		n = ncfg_main_do(&ask, operator_key, NULL, apply, strlen(apply), reply, sizeof(reply),
		    120000u);
		check(n == 3u && memcmp(reply, "ok\n", 3u) == 0 && runs == 1u,
		    "do answers ok where the daemon carried the request out");
		remote.admin = 0;
		n = ncfg_main_do(&ask, operator_key, NULL, apply, strlen(apply), reply, sizeof(reply),
		    120001u);
		check(n == 0u && runs == 1u,
		    "  and nothing where the node's remote tier refused it, so fuzznet says failed");
		remote.admin = 1;
		n = ncfg_main_do(&ask, operator_key, NULL, "{\"request\":\"apply\",\"confirm\":null}",
		    strlen("{\"request\":\"apply\",\"confirm\":null}"), reply, sizeof(reply), 120002u);
		check(n == 0u && runs == 1u, "  nor where an operator's apply had no window");

		/* A dispatcher that answers with the socket's error document. */
		refusing = ask;
		memset(refusing.slots, 0, sizeof(refusing.slots));
		memset(refusing.parts, 0, sizeof(refusing.parts));
		refusing.answer = error_answer;
		n = ncfg_main_do(&refusing, operator_key, NULL, apply, strlen(apply), reply,
		    sizeof(reply), 120003u);
		check(n == 0u, "  nor where the daemon answered with an error");
	}

	ncfg_buf_free(&joined);
	ncfg_main_ask_free(&ask);
	if (failures) {
		printf("\nask_test: %d check(s) FAILED\n", failures);
		return 1;
	}
	printf("\nask_test: all checks passed\n");
	return 0;
}
