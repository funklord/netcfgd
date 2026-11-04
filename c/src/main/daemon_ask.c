/*
 * daemon_ask.c -- the control vocabulary as one fuzznet procedure, `ask`
 * (decision 0312, project.md 10.693).
 *
 * `call ask FROM REQUEST`: REQUEST is the line the control socket reads, and
 * it is answered as the socket answers it -- the same reader, the same gate,
 * the same dispatcher -- in pages of fuzznet's size (`ok TOTAL FROM COUNT
 * DIGEST`, `client/ncfg_fuzznet.h`).
 *
 * THE ORDER IS THE SOCKET'S (`src/daemon/server.c`, `serve_one`)
 *   Read strictly; then `ncfg_authz_permitted`, the one gate, with the caller
 *   fuzznet identified -- a peer on this machine under the `control` tiers,
 *   or an operator of the estate under the `remote` block; then `hello`
 *   answered here with the tiers this caller holds, `monitor` refused as the
 *   stream it is, and everything else handed to the dispatcher.
 *
 * EVERY ANSWER IS MADE ONCE
 *   At FROM 0, and kept for that caller until it has been read to its end or
 *   a minute has passed; later pages are cut from the copy. A later page
 *   with no copy behind it is answered afresh only for a read -- an
 *   `observe`-tier request, by `ncfg_tier_of` -- the digest keeping pages of
 *   two answers apart, and refused for anything else, which is never run a
 *   second time to make a page. Not the order class (10.351): `apply` is
 *   idempotent there, and rightly, but running it again for a page would open
 *   a second confirm window.
 *
 * Kept apart from `daemon_main.c` so a test can drive it with an answer of
 * its own, counting how often it ran.
 */
#include "main_internal.h"

#include "ncfg_fuzznet.h"

#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/daemon.h"
#include "ncfg/proto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ASK_KEPT_MS 60000u

/* The same caller, asking the same thing: a remote key, or a local uid. */
static int same_caller(const ncfg_main_ask_slot_t *slot, const uint8_t *key,
    const ncfg_peer_t *peer)
{
	if (key) {
		return slot->remote && memcmp(slot->key, key, sizeof(slot->key)) == 0;
	}
	return !slot->remote && peer && slot->uid == (unsigned long)peer->uid;
}

static void slot_clear(ncfg_main_ask_slot_t *slot)
{
	free(slot->answer);
	memset(slot, 0, sizeof(*slot));
}

/*
 * **Wiped**: a staged request can carry a secret, a long `secret_put` or a
 * network with its passphrase, and every local client sends through here now
 * (10.712), so this is not only an operator's rare long line.
 */
static void part_clear(ncfg_main_ask_part_t *part)
{
	if (part->bytes) {
		explicit_bzero(part->bytes, part->total);
	}
	free(part->bytes);
	memset(part, 0, sizeof(*part));
}

void ncfg_main_ask_free(ncfg_main_ask_t *ask)
{
	size_t at;

	if (!ask) {
		return;
	}
	for (at = 0; at < NCFG_MAIN_ASK_SLOTS; at++) {
		slot_clear(&ask->slots[at]);
		part_clear(&ask->parts[at]);
	}
}

static int part_caller(const ncfg_main_ask_part_t *part, const uint8_t *key,
    const ncfg_peer_t *peer)
{
	if (key) {
		return part->remote && memcmp(part->key, key, sizeof(part->key)) == 0;
	}
	return !part->remote && peer && part->uid == (unsigned long)peer->uid;
}

/* This caller's staged request named by `digest`, or NULL; expired ones go. */
static ncfg_main_ask_part_t *part_of(ncfg_main_ask_t *ask, const uint8_t *key,
    const ncfg_peer_t *peer, uint64_t digest, uint64_t now_ms)
{
	size_t at;

	for (at = 0; at < NCFG_MAIN_ASK_SLOTS; at++) {
		ncfg_main_ask_part_t *part = &ask->parts[at];

		if (part->bytes && now_ms >= part->until) {
			part_clear(part);
		}
		if (part->bytes && part->digest == digest && part_caller(part, key, peer)) {
			return part;
		}
	}
	return NULL;
}

static size_t part_said(char *reply, size_t cap, const char *word, const char *sentence)
{
	int wrote = snprintf(reply, cap, "%s %s\n", word, sentence);

	return wrote > 0 && (size_t)wrote < cap ? (size_t)wrote : 0u;
}

/* A decimal number at `*at`, then a space: 1, or 0. */
static int part_number(const char *args, size_t length, size_t *at, size_t *out)
{
	size_t value = 0;
	size_t start = *at;

	while (*at < length && args[*at] >= '0' && args[*at] <= '9' && *at - start < 10u) {
		value = value * 10u + (size_t)(args[*at] - '0');
		(*at)++;
	}
	if (*at == start || *at >= length || args[*at] != ' ') {
		return 0;
	}
	(*at)++;
	*out = value;
	return 1;
}

size_t ncfg_main_ask_part(ncfg_main_ask_t *ask, const uint8_t *key, const ncfg_peer_t *peer,
    const char *args, size_t length, char *reply, size_t cap, uint64_t now_ms)
{
	ncfg_main_ask_part_t *part;
	size_t                at = 0;
	size_t                total;
	size_t                offset;
	size_t                digits;
	size_t                piece;
	uint64_t              digest = 0;
	char                  said[64];

	if (!ask || !args || !reply || cap == 0u || (!key && !peer)) {
		return 0u;
	}
	if (!part_number(args, length, &at, &total) || !part_number(args, length, &at, &offset)) {
		return part_said(reply, cap, "malformed", "askpart takes TOTAL OFFSET DIGEST PIECE");
	}
	for (digits = 0; digits < 16u; digits++, at++) {
		char c = at < length ? args[at] : '\0';
		int  v = c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;

		if (v < 0) {
			return part_said(reply, cap, "malformed", "a digest is sixteen hex digits");
		}
		digest = (digest << 4) | (uint64_t)v;
	}
	if (at >= length || args[at] != ' ') {
		return part_said(reply, cap, "malformed", "askpart takes TOTAL OFFSET DIGEST PIECE");
	}
	at++;
	piece = length - at;
	if (total == 0u || total > NCFG_MAIN_ASK_PART_MAX) {
		return part_said(reply, cap, "error", "a request staged in pieces is at most 256 KiB");
	}
	part = part_of(ask, key, peer, digest, now_ms);
	if (offset == 0u) {
		size_t slot;

		if (part) {
			part_clear(part);
		}
		/* A caller stages one request at a time: its earlier one goes. */
		for (slot = 0; slot < NCFG_MAIN_ASK_SLOTS; slot++) {
			if (ask->parts[slot].bytes && part_caller(&ask->parts[slot], key, peer)) {
				part_clear(&ask->parts[slot]);
			}
		}
		part = NULL;
		for (slot = 0; slot < NCFG_MAIN_ASK_SLOTS && !part; slot++) {
			if (!ask->parts[slot].bytes) {
				part = &ask->parts[slot];
			}
		}
		if (!part) {
			return part_said(reply, cap, "error", "every staging place is in use; try again");
		}
		part->bytes = malloc(total);
		if (!part->bytes) {
			return part_said(reply, cap, "error", "no memory to stage the request");
		}
		part->total = total;
		part->have = 0;
		part->digest = digest;
		part->until = now_ms + 60000u;
		part->remote = key != NULL;
		if (key) {
			memcpy(part->key, key, sizeof(part->key));
		} else {
			part->uid = (unsigned long)peer->uid;
		}
	}
	if (!part || part->total != total || offset != part->have) {
		return part_said(reply, cap, "error",
		    "the pieces of a request arrive in order from 0, and this is not the next one");
	}
	if (piece == 0u || piece > total - part->have) {
		return part_said(reply, cap, "error", "that piece does not fit the request");
	}
	memcpy(part->bytes + part->have, args + at, piece);
	part->have += piece;
	if (part->have == part->total &&
	    ncfg_status_page_digest(part->bytes, part->total) != part->digest) {
		part_clear(part);
		return part_said(reply, cap, "error", "the pieces joined are not the request their "
		                                      "digest names; send it again from 0");
	}
	(void)snprintf(said, sizeof(said), "%zu %zu", part->have, part->total);
	return part_said(reply, cap, "ok", said);
}

/* The slot holding this caller's answer to `request`, or NULL. */
static ncfg_main_ask_slot_t *kept(ncfg_main_ask_t *ask, const uint8_t *key,
    const ncfg_peer_t *peer, uint64_t asked, uint64_t now_ms)
{
	size_t at;

	for (at = 0; at < NCFG_MAIN_ASK_SLOTS; at++) {
		ncfg_main_ask_slot_t *slot = &ask->slots[at];

		if (slot->answer && now_ms >= slot->until) {
			slot_clear(slot);
		}
		if (slot->answer && slot->asked == asked && same_caller(slot, key, peer)) {
			return slot;
		}
	}
	return NULL;
}

/* A slot for a new answer: this caller's own, else an empty one, else the
 * one nearest its end -- a caller holds one answer at a time. */
static ncfg_main_ask_slot_t *slot_for(ncfg_main_ask_t *ask, const uint8_t *key,
    const ncfg_peer_t *peer)
{
	ncfg_main_ask_slot_t *empty = NULL;
	ncfg_main_ask_slot_t *oldest = &ask->slots[0];
	size_t                at;

	for (at = 0; at < NCFG_MAIN_ASK_SLOTS; at++) {
		ncfg_main_ask_slot_t *slot = &ask->slots[at];

		if (slot->answer && same_caller(slot, key, peer)) {
			slot_clear(slot);
			return slot;
		}
		if (!slot->answer && !empty) {
			empty = slot;
		}
		if (slot->until < oldest->until) {
			oldest = slot;
		}
	}
	if (empty) {
		return empty;
	}
	slot_clear(oldest);
	return oldest;
}

/* The length of `text` as fuzznet's local grammar escapes it (its sec 668). */
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
 * One page of `whole` from `from` into `reply`: the header and as many bytes
 * as fit `cap`, and fit `escaped_cap` once escaped where that is not 0.
 */
static size_t page_of(const char *whole, size_t total, uint64_t digest, size_t from,
    char *reply, size_t cap, size_t escaped_cap)
{
	size_t count;
	int    wrote;

	if (from > total) {
		from = total;
	}
	wrote = snprintf(reply, cap, "ok %zu %zu %zu %016llx\n", total, from, total,
	    (unsigned long long)digest);
	if (wrote <= 0 || (size_t)wrote >= cap ||
	    (escaped_cap && escaped_length(reply, (size_t)wrote) >= escaped_cap)) {
		return 0u;
	}
	count = total - from;
	if (count > cap - (size_t)wrote) {
		count = cap - (size_t)wrote;
	}
	if (escaped_cap) {
		size_t room = escaped_cap - escaped_length(reply, (size_t)wrote);
		size_t take = 0;

		while (take < count) {
			size_t one = escaped_length(whole + from + take, 1u);

			if (one > room) {
				break;
			}
			room -= one;
			take++;
		}
		count = take;
	}
	wrote = snprintf(reply, cap, "ok %zu %zu %zu %016llx\n", total, from, count,
	    (unsigned long long)digest);
	memcpy(reply + wrote, whole + from, count);
	return (size_t)wrote + count;
}

/* A refusal, as the socket writes one, as a one-page answer. */
static size_t refused(const char *why, char *reply, size_t cap, size_t escaped_cap)
{
	ncfg_buf_t line;
	char       err[NCFG_ERROR_MAX];
	size_t     n = 0;

	ncfg_buf_init(&line, NCFG_PROTO_MAX_LINE);
	if (ncfg_daemon_error_encode(why, &line, err, sizeof(err)) && !ncfg_buf_failed(&line)) {
		n = page_of(line.data, line.length, ncfg_status_page_digest(line.data, line.length),
		    0u, reply, cap, escaped_cap);
	}
	ncfg_buf_free(&line);
	return n;
}

/*
 * The answer to `request` from this caller, as the socket would write it,
 * into `out`: 1, or 0 with the refusal in `err`.
 */
static int answer(ncfg_main_ask_t *ask, const ncfg_proto_request_t *request,
    const ncfg_peer_t *peer, ncfg_arrival_t arrival, ncfg_buf_t *out, char *err,
    size_t err_size)
{
	if (!ncfg_authz_permitted(&ask->roots, ask->control, ask->remote, arrival, peer, request,
	        err, err_size)) {
		return 0;
	}
	if (request->kind == NCFG_PROTO_REQ_MONITOR) {
		ncfg_error_set(err, err_size,
		    "`monitor` is a stream rather than a request, and is not carried as one: "
		    "fuzznet's `get events` is the estate's stream");
		return 0;
	}
	/* **An operator's apply carries a window** (0312): across the estate a
	 * change that cuts the caller off has no other way back. */
	if (arrival == NCFG_ARRIVED_REMOTE && request->kind == NCFG_PROTO_REQ_APPLY &&
	    !request->u.apply.confirm.present) {
		ncfg_error_set(err, err_size,
		    "an apply from another host needs a confirm window (--confirm-within), so "
		    "that a change which cuts you off undoes itself");
		return 0;
	}
	if (request->kind == NCFG_PROTO_REQ_HELLO) {
		ncfg_tier_t told[NCFG_TIER_COUNT];
		size_t      count = ncfg_authz_granted(&ask->roots, ask->control, ask->remote,
		    arrival, peer, told);

		return ncfg_daemon_hello_encode(told, count, out, err, err_size);
	}
	if (!ask->answer) {
		ncfg_error_set(err, err_size, "this daemon takes no requests over fuzznet yet");
		return 0;
	}
	return ask->answer(ask->context, request, peer, arrival, out, err, err_size);
}

size_t ncfg_main_ask(ncfg_main_ask_t *ask, const uint8_t *key, const ncfg_peer_t *peer,
    const char *args, size_t length, char *reply, size_t cap, size_t escaped_cap,
    uint64_t now_ms)
{
	ncfg_proto_message_t  message;
	ncfg_main_ask_slot_t *slot;
	ncfg_main_ask_part_t *staged;
	ncfg_buf_t            out;
	char                  err[NCFG_ERROR_MAX];
	const char           *line;
	size_t                from = 0;
	size_t                at = 0;
	size_t                n;
	uint64_t              asked;
	ncfg_arrival_t        arrival = key ? NCFG_ARRIVED_REMOTE : NCFG_ARRIVED_LOCAL;

	if (!ask || !args || !reply || cap == 0u || (!key && !peer)) {
		return 0u;
	}
	/* FROM, digits; then one space and the request. */
	while (at < length && args[at] >= '0' && args[at] <= '9' && at < 10u) {
		from = from * 10u + (size_t)(args[at] - '0');
		at++;
	}
	if (at == 0u || at >= length || args[at] != ' ') {
		return refused("`ask` takes an offset and a request: ask FROM {\"request\":...}",
		    reply, cap, escaped_cap);
	}
	line = args + at + 1u;
	length -= at + 1u;
	/* `@DIGEST`: a request staged in pieces by `askpart` (10.695), whole. */
	staged = NULL;
	if (length == 17u && line[0] == '@') {
		uint64_t named = 0;
		size_t   digit;

		for (digit = 1; digit < 17u; digit++) {
			char c = line[digit];
			int  v = c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;

			if (v < 0) {
				break;
			}
			named = (named << 4) | (uint64_t)v;
		}
		/* A later page of one already run is cut from its kept answer, which
		 * is filed under the same digest: the digest of the whole line. */
		if (digit == 17u && from > 0u && (slot = kept(ask, key, peer, named, now_ms))) {
			n = page_of(slot->answer, slot->length, slot->digest, from, reply, cap,
			    escaped_cap);
			if (n && from + (n - (size_t)(strchr(reply, '\n') - reply + 1)) >= slot->length) {
				slot_clear(slot);
			}
			return n;
		}
		staged = digit == 17u ? part_of(ask, key, peer, named, now_ms) : NULL;
		if (!staged || staged->have != staged->total) {
			return refused("no whole request is staged under that digest; send it with "
			               "askpart from 0", reply, cap, escaped_cap);
		}
		line = staged->bytes;
		length = staged->total;
	}
	asked = ncfg_status_page_digest(line, length);

	slot = kept(ask, key, peer, asked, now_ms);
	if (slot && from > 0u) {
		n = page_of(slot->answer, slot->length, slot->digest, from, reply, cap, escaped_cap);
		if (n && from + (n - (size_t)(strchr(reply, '\n') - reply + 1)) >= slot->length) {
			slot_clear(slot); /* read to its end */
		}
		return n;
	}

	memset(&message, 0, sizeof(message));
	if (!ncfg_proto_request_read(line, length, &message, err, sizeof(err))) {
		ncfg_proto_message_free(&message);
		if (staged) {
			part_clear(staged); /* asked once, whatever became of it */
		}
		return refused(err, reply, cap, escaped_cap);
	}
	/* **Only a read is made again for a page.** Anything else -- even a change
	 * the order table calls idempotent, as `apply` is -- has its effect again
	 * when run again, and a page is no reason for that. */
	if (from > 0u && ncfg_tier_of(message.u.request.kind) != NCFG_TIER_OBSERVE) {
		ncfg_proto_message_free(&message);
		if (staged) {
			part_clear(staged);
		}
		return refused("that answer is no longer kept, and the request changes the machine, "
		               "so it is not run again to make another; ask from 0 for a new one",
		    reply, cap, escaped_cap);
	}
	ncfg_buf_init(&out, NCFG_PROTO_MAX_LINE * 64u);
	err[0] = '\0';
	if (!answer(ask, &message.u.request, key ? NULL : peer, arrival, &out, err, sizeof(err))) {
		ncfg_buf_free(&out);
		ncfg_proto_message_free(&message);
		if (staged) {
			part_clear(staged);
		}
		return refused(err[0] ? err : "the request was not answered", reply, cap, escaped_cap);
	}
	ncfg_proto_message_free(&message);
	if (staged) {
		part_clear(staged); /* run; a staged request is run once */
	}
	if (ncfg_buf_failed(&out)) {
		ncfg_buf_free(&out);
		return refused("the answer did not fit in memory", reply, cap, escaped_cap);
	}
	/* The socket writes a line; the page carries the line without its newline. */
	while (out.length && out.data[out.length - 1u] == '\n') {
		out.length--;
	}
	slot = slot_for(ask, key, peer);
	slot->length = out.length;
	slot->answer = ncfg_buf_take(&out, NULL);
	if (!slot->answer) {
		ncfg_buf_free(&out);
		return refused("the answer did not fit in memory", reply, cap, escaped_cap);
	}
	slot->asked = asked;
	slot->digest = ncfg_status_page_digest(slot->answer, slot->length);
	slot->until = now_ms + ASK_KEPT_MS;
	slot->remote = key != NULL;
	if (key) {
		memcpy(slot->key, key, sizeof(slot->key));
	} else {
		slot->uid = (unsigned long)peer->uid;
	}
	n = page_of(slot->answer, slot->length, slot->digest, from, reply, cap, escaped_cap);
	if (n && from + (n - (size_t)(strchr(reply, '\n') - reply + 1)) >= slot->length) {
		slot_clear(slot);
	}
	return n;
}

/*
 * `do REQUEST` or `do @DIGEST` (10.708): the request carried out, for
 * fuzznet's propagation (`call do at estate`, its sec 872), which reports
 * each host only as ok, failed and the rest and carries no answer. So the
 * answer here is `ok` where the daemon carried the request out and nothing
 * where it refused or failed -- which fuzznet reports as `failed` -- rather
 * than `ask`'s page, which is a page for a refusal too and would read `ok`.
 * The same gate as `ask`: the reader, `ncfg_authz_permitted`, an operator's
 * apply needing a window.
 */
size_t ncfg_main_do(ncfg_main_ask_t *ask, const uint8_t *key, const ncfg_peer_t *peer,
    const char *args, size_t length, char *reply, size_t cap, uint64_t now_ms)
{
	ncfg_proto_message_t  message;
	ncfg_proto_message_t  answered;
	ncfg_main_ask_part_t *staged = NULL;
	ncfg_buf_t            out;
	char                  err[NCFG_ERROR_MAX];
	int                   carried = 0;
	ncfg_arrival_t        arrival = key ? NCFG_ARRIVED_REMOTE : NCFG_ARRIVED_LOCAL;

	if (!ask || !args || !reply || cap < 3u || (!key && !peer)) {
		return 0u;
	}
	if (length == 17u && args[0] == '@') {
		uint64_t named = 0;
		size_t   digit;

		for (digit = 1; digit < 17u; digit++) {
			char c = args[digit];
			int  v = c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;

			if (v < 0) {
				return 0u;
			}
			named = (named << 4) | (uint64_t)v;
		}
		staged = part_of(ask, key, peer, named, now_ms);
		if (!staged || staged->have != staged->total) {
			return 0u;
		}
		args = staged->bytes;
		length = staged->total;
	}
	memset(&message, 0, sizeof(message));
	if (!ncfg_proto_request_read(args, length, &message, err, sizeof(err))) {
		ncfg_proto_message_free(&message);
		if (staged) {
			part_clear(staged);
		}
		return 0u;
	}
	ncfg_buf_init(&out, NCFG_PROTO_MAX_LINE * 64u);
	err[0] = '\0';
	if (answer(ask, &message.u.request, key ? NULL : peer, arrival, &out, err, sizeof(err)) &&
	    !ncfg_buf_failed(&out)) {
		memset(&answered, 0, sizeof(answered));
		carried = ncfg_proto_response_read(out.data, out.length, &answered, err, sizeof(err)) &&
		    answered.kind == NCFG_PROTO_MESSAGE_RESPONSE &&
		    answered.u.response.kind != NCFG_PROTO_RESP_ERROR;
		ncfg_proto_message_free(&answered);
	}
	ncfg_buf_free(&out);
	ncfg_proto_message_free(&message);
	if (staged) {
		part_clear(staged); /* run, or refused: a staged request is asked once */
	}
	if (!carried) {
		return 0u;
	}
	memcpy(reply, "ok\n", 3u);
	return 3u;
}
