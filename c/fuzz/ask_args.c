/*
 * `ask` and `askpart`'s arguments, as a caller's line (0312, project.md
 * 10.693, 10.695, 10.701).
 *
 * WHY THIS DESERVES A TARGET OF ITS OWN
 *   `rrpc ask FROM REQUEST` and `rrpc askpart TOTAL OFFSET DIGEST PIECE`
 *   reach the daemon from an estate operator's host as well as from this
 *   machine, and the daemon parses both before anything judges them: an
 *   offset, a digest, a staged request, a request line. A number read past
 *   its digits or a piece copied past its slot is reached from the network.
 *
 * THE INVARIANTS WORTH ASSERTING
 *   Every answer of `ask` is a page that reads back as one, within the
 *   reply; every answer of `askpart` is one line beginning `ok`, `error` or
 *   `malformed`; and what is kept between calls is let go at the end
 *   (`ncfg_main_ask_free`), which the leak checker holds it to.
 *
 *   The input is split at its first byte: an even one is `ask`, an odd one
 *   `askpart`; a second byte picks a remote caller or root on this machine.
 *   A few calls are made from one state, so a staged request and a kept
 *   answer meet the next call.
 */
#include "fuzz.h"

#include "../src/main/main_internal.h"

#include "ncfg_fuzznet.h"

#include "ncfg/buf.h"

#include <stdlib.h>
#include <string.h>

static int answer(void *context, const ncfg_proto_request_t *request, const ncfg_peer_t *peer,
    ncfg_arrival_t arrival, ncfg_buf_t *out, char *err, size_t err_size)
{
	(void)context;
	(void)request;
	(void)peer;
	(void)arrival;
	(void)err;
	(void)err_size;
	ncfg_buf_add_text(out, "{\"response\":\"ok\",\"padding\":\"0123456789abcdef0123456789\"}\n");
	return 1;
}

int ncfg_fuzz_one(const unsigned char *data, size_t length)
{
	static const uint8_t key[32] = { 1 };
	static ncfg_control_t control;
	static ncfg_remote_policy_t remote;
	ncfg_main_ask_t      ask;
	ncfg_peer_t          root;
	char                 reply[2048];
	size_t               at = 2;
	int                  call;

	if (length < 2u) {
		return 0;
	}
	memset(&ask, 0, sizeof(ask));
	memset(&root, 0, sizeof(root));
	root.groups_known = 1;
	remote.observe = 1;
	remote.admin = 1;
	ask.answer = answer;
	ask.control = &control;
	ask.remote = &remote;
	ask.roots = ncfg_authz_roots_default();

	/* The rest, in up to four calls split at newlines, as several lines. */
	for (call = 0; call < 4 && at < length; call++) {
		const char *line = (const char *)data + at;
		const char *end = memchr(line, '\n', length - at);
		size_t      n = end ? (size_t)(end - line) : length - at;
		const uint8_t *caller = (data[1] & 1u) ? key : NULL;
		size_t      wrote;

		if (data[0] & 1u) {
			wrote = ncfg_main_ask_part(&ask, caller, caller ? NULL : &root, line, n, reply,
			    sizeof(reply), 1000u + (uint64_t)call);
			if (wrote > sizeof(reply) ||
			    (wrote && strncmp(reply, "ok ", 3) != 0 && strncmp(reply, "error ", 6) != 0 &&
			        strncmp(reply, "malformed ", 10) != 0)) {
				abort(); /* an askpart answer that is not one of its three */
			}
		} else {
			ncfg_status_page_t page;

			wrote = ncfg_main_ask(&ask, caller, caller ? NULL : &root, line, n, reply,
			    sizeof(reply), 1019u, 1000u + (uint64_t)call);
			if (wrote > sizeof(reply) ||
			    (wrote && !ncfg_status_page_read(reply, wrote, &page))) {
				abort(); /* an ask answer that is not a page */
			}
		}
		at += n + 1u;
	}
	ncfg_main_ask_free(&ask);
	return 0;
}
