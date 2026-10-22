/*
 * socket_witness_test.c -- building `doc/schema/socket.json` from this build.
 *
 * WHY THIS FILE EXISTS
 *   0279 moved the four frozen witnesses to the C and left this one out: the
 *   other three are written by the module that owns them, and the socket's was
 *   still a file nobody here produced. `proto_test.c` proves every line
 *   DECODES and that every request re-encodes to the same bytes, which is a
 *   round trip; what it cannot say is that this build can PRODUCE the file.
 *
 * WHAT IT DOES
 *   Produces every line this build has an encoder for, claims each against the
 *   file byte for byte, and reports what is left. Three groups:
 *
 *     requests   decoded from the witness and re-encoded, which is the path
 *                `proto_test` already proves. The VALUES come from the file and
 *                the BYTES from this build's encoder, which is the half that
 *                goes stale when an encoder changes
 *     responses  built from values here and written by the same functions the
 *                daemon answers with -- never a second encoder, which is the
 *                thing this tree refuses everywhere else
 *     events     both shapes, wrapped and bare, from the one writer that takes
 *                the wrapper as an argument (0280)
 *
 *   61 of the 67. The six it cannot are the wifi answers, which are written as
 *   a live supplicant is read and whose values no fixture here reproduces --
 *   0280 names the two ways to finish it and whose decision it is.
 *
 * WHAT IT WILL NOT DO
 *   **Write a partial witness.** The bless arm writes only when every line in
 *   the file has been produced, so a builder that has reached 61 of 67 cannot
 *   quietly drop the other six over a file that has them. It prints them
 *   instead, and `SHORTFALL` holds the number in both directions so that it
 *   cannot move without somebody deciding it should.
 */
#include "ncfg/apply.h"
#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/config.h"
#include "ncfg/daemon.h"
#include "ncfg/document.h"
#include "ncfg/explain.h"
#include "ncfg/hooks.h"
#include "ncfg/observed.h"
#include "ncfg/plan.h"
#include "ncfg/proto.h"
#include "ncfg/secrets.h"
#include "ncfg/value.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;
static int produced;

static void check(int condition, const char *what)
{
	printf("%-70s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

/* ------------------------------------------------------------- the witness */

#define LINE_MAX 131072u
#define WITNESS_LINES 128u

/*
 * How many of the witness's lines this build cannot produce.
 *
 * Asserted in both directions, which is what makes it a ratchet rather than a
 * note: one more and an encoder has drifted away from the frozen file, one
 * fewer and this number is the stale thing. The six are the wifi answers, for
 * the reason the refusal prints.
 */
#define SHORTFALL 6u

static char  *lines[WITNESS_LINES];
/* What this build produced for that line, or NULL where nothing did. The file
 * is written from these and never from `lines`, so a line nothing produced
 * cannot be copied back out of the file it is supposed to be checking. */
static char  *made[WITNESS_LINES];
static size_t line_count;

static const char *witness_path(int argc, char **argv)
{
	static const char *const candidates[] = { "../doc/schema/socket.json",
		"doc/schema/socket.json", "../../doc/schema/socket.json" };
	size_t at;

	if (argc > 1) {
		return argv[1];
	}
	for (at = 0u; at < sizeof(candidates) / sizeof(candidates[0]); at++) {
		FILE *file = fopen(candidates[at], "rb");

		if (file) {
			(void)fclose(file);
			return candidates[at];
		}
	}
	return candidates[0];
}

static int read_witness(const char *path)
{
	FILE *file = fopen(path, "rb");
	char *buffer;

	if (!file) {
		return 0;
	}
	buffer = malloc(LINE_MAX);
	if (!buffer) {
		(void)fclose(file);
		return 0;
	}
	while (fgets(buffer, (int)LINE_MAX, file)) {
		size_t length = strlen(buffer);

		while (length > 0u && (buffer[length - 1u] == '\n' || buffer[length - 1u] == '\r')) {
			buffer[--length] = '\0';
		}
		if (length == 0u || line_count >= WITNESS_LINES) {
			continue;
		}
		lines[line_count] = malloc(length + 1u);
		if (!lines[line_count]) {
			break;
		}
		memcpy(lines[line_count], buffer, length + 1u);
		line_count++;
	}
	free(buffer);
	(void)fclose(file);
	return line_count > 0u;
}

/*
 * Claim one line.
 *
 * The produced bytes have to BE a line of the witness, and the line has to be
 * unclaimed: two producers answering with the same bytes would otherwise count
 * twice and leave a line nobody made.
 */
static int claim(const char *what, const char *bytes)
{
	size_t at;

	for (at = 0u; at < line_count; at++) {
		if (!made[at] && strcmp(lines[at], bytes) == 0) {
			made[at] = malloc(strlen(bytes) + 1u);
			if (!made[at]) {
				printf("  out of memory claiming a line\n");
				failures++;
				return 0;
			}
			memcpy(made[at], bytes, strlen(bytes) + 1u);
			produced++;
			return 1;
		}
	}
	printf("  %s produced bytes no unclaimed witness line matches:\n    %.160s\n", what,
	    bytes);
	failures++;
	return 0;
}

/* ------------------------------------------------------------- the requests */

/*
 * Every request line, through this build's encoder.
 *
 * Decoded from the witness and written back: the request VALUES are the file's
 * and the bytes are this build's, which is the half `proto_test` asserts and
 * the half that matters for producing the file. Constructing forty-one request
 * values here would be a second copy of the samples with nothing holding the
 * two in step.
 */
static void the_requests(void)
{
	size_t at;
	size_t done = 0u;

	for (at = 0u; at < line_count; at++) {
		ncfg_proto_message_t message;
		ncfg_buf_t           out;
		char                 err[NCFG_ERROR_MAX] = "";

		if (strncmp(lines[at], "{\"request\":", 11u) != 0) {
			continue;
		}
		if (!ncfg_proto_request_read(lines[at], strlen(lines[at]), &message, err,
		        sizeof(err))) {
			printf("  the witness request on line %zu does not decode: %s\n", at + 1u,
			    err);
			failures++;
			continue;
		}
		ncfg_buf_init(&out, 0);
		if (ncfg_proto_request_encode(&message.u.request, &out, err, sizeof(err))) {
			if (claim("a request", ncfg_buf_text(&out))) {
				done++;
			}
		} else {
			printf("  a request does not encode: %s\n", err);
			failures++;
		}
		ncfg_buf_free(&out);
		ncfg_proto_message_free(&message);
	}
	check(done == 41u, "every request line is produced by this build's encoder");
}

/* ------------------------------------------------------------ the responses */

static void one(const char *what, int ok, ncfg_buf_t *out, const char *err)
{
	if (!ok) {
		printf("  %s does not encode: %s\n", what, err);
		failures++;
		return;
	}
	(void)claim(what, ncfg_buf_text(out));
}

/* A counted string over a literal, for the modem list's `ncfg_proto_str_t`
 * members: the wire type carries bytes and a length, and a NUL-terminated
 * literal is the one case where `strlen` is the length. */
static ncfg_proto_str_t text_of(const char *literal)
{
	ncfg_proto_str_t text;

	text.bytes = literal;
	text.length = strlen(literal);
	return text;
}

static void the_small_responses(void)
{
	ncfg_buf_t out;
	char       err[NCFG_ERROR_MAX] = "";

	ncfg_buf_init(&out, 0);
	one("ok", ncfg_daemon_ok_encode(&out, err, sizeof(err)), &out, err);
	ncfg_buf_free(&out);

	ncfg_buf_init(&out, 0);
	one("error", ncfg_daemon_error_encode("not permitted", &out, err, sizeof(err)), &out,
	    err);
	ncfg_buf_free(&out);

	{
		/* `observe` and `admin`, which is what the witness says this
		 * connection holds. */
		static const ncfg_tier_t tiers[] = { NCFG_TIER_OBSERVE, NCFG_TIER_ADMIN };

		ncfg_buf_init(&out, 0);
		one("hello", ncfg_daemon_hello_encode(tiers, 2u, &out, err, sizeof(err)), &out,
		    err);
		ncfg_buf_free(&out);
	}
	{
		ncfg_profile_entry_t profiles[2];

		memset(profiles, 0, sizeof(profiles));
		profiles[0].name = (char *)(uintptr_t)"offline";
		profiles[0].shipped = 1;
		profiles[1].name = (char *)(uintptr_t)"office";
		profiles[1].shipped = 0;
		ncfg_buf_init(&out, 0);
		one("profiles",
		    ncfg_daemon_profiles_encode(profiles, 2u, "office", &out, err, sizeof(err)),
		    &out, err);
		ncfg_buf_free(&out);
	}
}

/*
 * The listings, each through the function the daemon answers with.
 *
 * The VALUES are this file's: a witness line is a sample somebody chose, and
 * the C cannot invent `8946080023614318322`. What this build owns is the
 * BYTES, which is the half that goes stale when an encoder changes and the
 * half a hand-edited witness cannot check.
 */
static void the_listings(void)
{
	ncfg_buf_t out;
	char       err[NCFG_ERROR_MAX] = "";

	{
		/* One fact, and `total` equal to `count`: a truncated explanation
		 * says so in a fact of its own, which is `answer_test`'s case and
		 * not a shape the witness carries. */
		ncfg_explain_fact_t fact;
		ncfg_explanation_t  explanation;

		memset(&fact, 0, sizeof(fact));
		fact.topic = (char *)(uintptr_t)"desired";
		fact.detail = (char *)(uintptr_t)"static 192.0.2.1/24";
		fact.source = (char *)(uintptr_t)"netcfgd.conf:3";
		memset(&explanation, 0, sizeof(explanation));
		explanation.subject = (char *)(uintptr_t)"eth0";
		explanation.facts = &fact;
		explanation.count = 1u;
		explanation.total = 1u;
		ncfg_buf_init(&out, 0);
		one("explanation",
		    ncfg_daemon_explanation_encode(&explanation, &out, err, sizeof(err)), &out,
		    err);
		ncfg_buf_free(&out);
	}
	{
		ncfg_secret_entry_t entries[3];
		char               *cafe[1];
		char               *campus[1];

		cafe[0] = (char *)(uintptr_t)"network Cafe";
		campus[0] = (char *)(uintptr_t)"network Campus";
		memset(entries, 0, sizeof(entries));
		entries[0].name = (char *)(uintptr_t)"cafe";
		entries[0].stored = 1;
		entries[0].used_by = cafe;
		entries[0].used_by_count = 1u;
		entries[1].name = (char *)(uintptr_t)"campus";
		entries[1].stored = 0;
		entries[1].used_by = campus;
		entries[1].used_by_count = 1u;
		/* Stored and referred to by nothing, which is the entry that says
		 * `used_by` is omitted rather than written empty: a credential no
		 * block mentions any more is the one worth deleting. */
		entries[2].name = (char *)(uintptr_t)"old-vpn";
		entries[2].stored = 1;
		ncfg_buf_init(&out, 0);
		one("secrets", ncfg_daemon_secrets_encode(entries, 3u, &out, err, sizeof(err)),
		    &out, err);
		ncfg_buf_free(&out);
	}
	{
		/* The first has no `name`, which is a file a client cannot address,
		 * and the second is the drop-in that has one. */
		ncfg_config_entry_t entries[2];

		memset(entries, 0, sizeof(entries));
		entries[0].name = (char *)(uintptr_t)"";
		entries[0].file = (char *)(uintptr_t)"netcfgd.conf";
		entries[0].removable = 0;
		entries[0].text = (char *)(uintptr_t)"global { }\n";
		entries[1].name = (char *)(uintptr_t)"wifi-home";
		entries[1].file = (char *)(uintptr_t)"conf.d/wifi-home.conf";
		entries[1].removable = 1;
		entries[1].text = (char *)(uintptr_t)"network \"home\" { }\n";
		ncfg_buf_init(&out, 0);
		one("configs", ncfg_daemon_configs_encode(entries, 2u, &out, err, sizeof(err)),
		    &out, err);
		ncfg_buf_free(&out);
	}
	{
		ncfg_probe_entry_t entries[2];

		memset(entries, 0, sizeof(entries));
		entries[0].name = (char *)(uintptr_t)"default";
		entries[0].directory = (char *)(uintptr_t)"/usr/share/netcfgd/probe";
		entries[0].text = (char *)(uintptr_t)"#!/bin/sh\nexit 0\n";
		entries[0].editable = 0;
		entries[1].name = (char *)(uintptr_t)"office";
		entries[1].directory = (char *)(uintptr_t)"/etc/netcfgd/probe";
		entries[1].text = (char *)(uintptr_t)"#!/bin/sh\nexit 1\n";
		entries[1].editable = 1;
		ncfg_buf_init(&out, 0);
		one("probes", ncfg_daemon_probes_encode(entries, 2u, &out, err, sizeof(err)),
		    &out, err);
		ncfg_buf_free(&out);
	}
	{
		/* The second is unreadable, so its text is empty -- and the two are
		 * not the same answer, which is why `readable` is on the wire. */
		ncfg_hook_script_t scripts[2];

		memset(scripts, 0, sizeof(scripts));
		scripts[0].interface = (char *)(uintptr_t)"eth0";
		scripts[0].phase = NCFG_HOOK_PHASE_POST_UP;
		scripts[0].path = (char *)(uintptr_t)"/run/netcfgd/hooks/eth0.post_up.0";
		scripts[0].readable = 1;
		scripts[0].text = (char *)(uintptr_t)"#!/bin/sh\nlogger up\n";
		scripts[1].interface = (char *)(uintptr_t)"eth1";
		scripts[1].phase = NCFG_HOOK_PHASE_DRIFT;
		scripts[1].path = (char *)(uintptr_t)"/run/netcfgd/hooks/eth1.drift.1";
		scripts[1].readable = 0;
		scripts[1].text = (char *)(uintptr_t)"";
		ncfg_buf_init(&out, 0);
		one("hooks", ncfg_daemon_hooks_encode(scripts, 2u, &out, err, sizeof(err)), &out,
		    err);
		ncfg_buf_free(&out);
	}
	{
		ncfg_proto_sim_card_t cards[1];
		ncfg_proto_str_t      wwan0_sim[2];
		ncfg_proto_str_t      wwan1_sim[1];
		ncfg_proto_modem_t    modems[2];

		memset(cards, 0, sizeof(cards));
		cards[0].source = text_of("socket");
		cards[0].iccid = text_of("8946080023614318322");
		wwan0_sim[0] = text_of("esim");
		wwan0_sim[1] = text_of("socket");
		wwan1_sim[0] = text_of("socket");
		memset(modems, 0, sizeof(modems));
		modems[0].device = text_of("wwan0");
		modems[0].sim.items = wwan0_sim;
		modems[0].sim.count = 2u;
		modems[0].selected = text_of("socket");
		modems[0].apn = text_of("im.cxn");
		modems[0].cycle_pending = 1;
		modems[0].cards = cards;
		modems[0].card_count = 1u;
		/* Nothing has reported a card for this one, which is the only way to
		 * say "the other socket has not been looked in". */
		modems[1].device = text_of("wwan1");
		modems[1].sim.items = wwan1_sim;
		modems[1].sim.count = 1u;
		modems[1].selected = text_of("socket");
		ncfg_buf_init(&out, 0);
		one("modems", ncfg_daemon_modems_encode(modems, 2u, &out, err, sizeof(err)), &out,
		    err);
		ncfg_buf_free(&out);
	}
	{
		ncfg_journal_t journal;
		ncfg_record_t  record;

		ncfg_journal_init(&journal);
		memset(&record, 0, sizeof(record));
		record.id = 1u;
		record.op = "addr.add";
		record.interface = "eth0";
		record.reason.interface = "eth0";
		record.reason.field = "addressing[0]";
		record.reason.desired = "192.0.2.1/24";
		record.reason.observed = "<absent>";
		record.outcome = NCFG_OUTCOME_DONE;
		ncfg_journal_push(&journal, &record);
		ncfg_buf_init(&out, 0);
		one("journal", ncfg_daemon_journal_encode(&journal, &out, err, sizeof(err)), &out,
		    err);
		ncfg_buf_free(&out);
		ncfg_journal_free(&journal);
	}
	{
		/* Empty, because the witness's plan is empty: a plan with actions in
		 * it is `plan_test`'s witness and the two files are not the same
		 * surface. */
		ncfg_plan_t *plan;

		/*
		 * `ncfg_plan_new` rather than a zeroed struct on the stack, which
		 * aborted here: `ncfg_plan_free` ends with `free(plan)` because a
		 * plan is always heap, so a plan that encodes correctly is not a
		 * plan that can be freed, and the constructor is the only shape
		 * that is both.
		 */
		plan = ncfg_plan_new(err, sizeof(err));
		if (!plan) {
			printf("  an empty plan does not build: %s\n", err);
			failures++;
		} else {
			ncfg_buf_init(&out, 0);
			one("plan", ncfg_daemon_plan_encode(plan, &out, err, sizeof(err)), &out,
			    err);
			ncfg_buf_free(&out);
			ncfg_plan_free(plan);
		}
	}
}

/*
 * The two that are whole models rather than lists.
 *
 * Built by the model's own reader and constructor rather than filled in field
 * by field, which is this port's rule everywhere: a struct assembled by hand
 * is quietly missing whatever the model grows next, and these two lines are
 * the ones that would then be blessed wrong.
 */
static void the_whole_models(void)
{
	ncfg_observed_t *observed;
	ncfg_document_t *desired;
	ncfg_buf_t       out;
	char             err[NCFG_ERROR_MAX] = "";

	observed = ncfg_observed_read("{}", 2u, err, sizeof(err));
	if (!observed) {
		printf("  an empty observation does not read: %s\n", err);
		failures++;
	} else {
		ncfg_buf_init(&out, 0);
		one("status", ncfg_daemon_status_encode(observed, &out, err, sizeof(err)), &out,
		    err);
		ncfg_buf_free(&out);
		ncfg_observed_free(observed);
	}

	desired = ncfg_document_new(err, sizeof(err));
	if (!desired) {
		printf("  an empty document does not build: %s\n", err);
		failures++;
	} else {
		/* No diagnostics, which the witness spells as the member being
		 * absent rather than as an empty string. */
		ncfg_buf_init(&out, 0);
		one("document",
		    ncfg_daemon_document_encode(desired, NULL, &out, err, sizeof(err)), &out,
		    err);
		ncfg_buf_free(&out);
		ncfg_document_free(desired);
	}
}

/* --------------------------------------------------------------- the events */

/*
 * Both shapes of every event.
 *
 * The witness carries each event twice over: once wrapped, as a monitor
 * stream delivers it, and once as the payload on its own, which is the shape
 * the decoder also accepts. **Only the wrapped form had a writer** until this
 * file needed the other -- `ncfg_main_event_encode` in `src/main/` wrote
 * `"response":"event"` unconditionally -- so five of the witness's lines were
 * a shape this build could read and never produce. That is now the `wrapped`
 * argument of one writer in `src/proto/`, beside the reader, rather than two
 * writers with two member orders.
 *
 * The witness has one wrapped line and five bare ones, which is why the
 * wrapped loop claims only `confirm_armed`: the other four wrapped lines are
 * not in the file, and claiming a line that is not there is this harness's
 * own failure rather than a missing encoder.
 */
static void the_events(void)
{
	ncfg_proto_event_t event;
	ncfg_buf_t         out;
	char               err[NCFG_ERROR_MAX] = "";
	size_t             kind;
	size_t             done = 0u;

	for (kind = 0u; kind < NCFG_PROTO_EVENT_COUNT; kind++) {
		memset(&event, 0, sizeof(event));
		event.kind = (ncfg_proto_event_kind_t)kind;
		switch (event.kind) {
		case NCFG_PROTO_EVENT_OBSERVED:
			event.summary = text_of("eth0 gained an address");
			break;
		case NCFG_PROTO_EVENT_RELOADED:
			event.ok = 0;
			event.diagnostics = text_of("netcfgd.conf:3: unknown key");
			break;
		case NCFG_PROTO_EVENT_DRIFT:
			event.interface = text_of("eth0");
			event.summary = text_of("an address we installed is gone");
			event.action = text_of("reconciled");
			break;
		case NCFG_PROTO_EVENT_CONFIRM_ARMED:
			event.seconds = 90;
			break;
		case NCFG_PROTO_EVENT_CONFIRM_RESOLVED:
		case NCFG_PROTO_EVENT_COUNT:
		default:
			event.confirmed = 1;
			break;
		}
		ncfg_buf_init(&out, 0);
		if (!ncfg_proto_event_encode(&event, 0, &out, err, sizeof(err))) {
			printf("  the %s event does not encode: %s\n",
			    ncfg_proto_event_name(event.kind), err);
			failures++;
		} else if (claim("an event payload", ncfg_buf_text(&out))) {
			done++;
		}
		ncfg_buf_free(&out);

		/* And the same event wrapped, which is what the daemon writes. Only
		 * one of the five is in the witness, so the rest are produced and
		 * discarded -- the encoder is still exercised, and a line that is
		 * not in the file is not a line to claim. */
		ncfg_buf_init(&out, 0);
		if (!ncfg_proto_event_encode(&event, 1, &out, err, sizeof(err))) {
			printf("  the wrapped %s event does not encode: %s\n",
			    ncfg_proto_event_name(event.kind), err);
			failures++;
		} else if (strstr(ncfg_buf_text(&out), "\"response\":\"event\"") == NULL) {
			printf("  the wrapped %s event carries no response tag\n",
			    ncfg_proto_event_name(event.kind));
			failures++;
		} else if (event.kind == NCFG_PROTO_EVENT_CONFIRM_ARMED) {
			(void)claim("the wrapped confirm_armed event", ncfg_buf_text(&out));
		}
		ncfg_buf_free(&out);
	}
	check(done == 5u, "every event's payload shape is produced as the witness pins it");
}

/*
 * Write the witness, from what this build produced.
 *
 * Every line or none: the caller has already established that each line was
 * produced, and the length is read before anything is freed -- which is the
 * mistake the other three blessers made on their first run, writing
 * `17114 of 0` bytes because `ncfg_buf_free` had zeroed the length the
 * `fwrite` was given (0279).
 */
static int bless(const char *path)
{
	FILE  *file;
	size_t at;

	for (at = 0u; at < line_count; at++) {
		if (!made[at]) {
			return 0;
		}
	}
	file = fopen(path, "wb");
	if (!file) {
		return 0;
	}
	for (at = 0u; at < line_count; at++) {
		size_t wanted = strlen(made[at]);

		if (fwrite(made[at], 1u, wanted, file) != wanted || fputc('\n', file) == EOF) {
			(void)fclose(file);
			return 0;
		}
	}
	return fclose(file) == 0;
}

int main(int argc, char **argv)
{
	const char *path = witness_path(argc, argv);
	size_t      at;
	size_t      unclaimed = 0u;

	if (!read_witness(path)) {
		printf("socket_witness_test: cannot read %s\n", path);
		return 1;
	}
	printf("socket_witness_test: %zu lines in %s\n", line_count, path);

	the_requests();
	the_small_responses();
	the_listings();
	the_whole_models();
	the_events();

	for (at = 0u; at < line_count; at++) {
		if (!made[at]) {
			unclaimed++;
		}
	}
	printf("\nsocket_witness_test: produced %d of %zu lines\n", produced, line_count);
	if (unclaimed) {
		printf("socket_witness_test: %zu line(s) this build does not produce yet:\n",
		    unclaimed);
		for (at = 0u; at < line_count; at++) {
			if (!made[at]) {
				printf("  %3zu %.110s\n", at + 1u, lines[at]);
			}
		}
		printf("socket_witness_test: see project.md 10.522 -- the wifi answers are\n"
		       "  written as a live supplicant is read, and this tree's fakes answer\n"
		       "  with other values than these lines carry\n");
	}
	/*
	 * **No bless while a line is unclaimed.** A generator that wrote what it
	 * had would drop the rest, and a witness with lines missing is worse than
	 * one nobody generates: every gate that reads it would then agree with a
	 * file that had quietly shrunk.
	 */
	/*
	 * A shortfall is a state of the tree and not a failing check, so it does
	 * not turn this red -- a gate that is red while a decision is open is one
	 * somebody learns to walk past, and the thing that must stay true is that
	 * the number does not move on its own.
	 */
	check(unclaimed == SHORTFALL,
	    "and the six lines nothing here produces are exactly the six named");
	if (unclaimed != SHORTFALL) {
		printf("  SHORTFALL says %u and %zu line(s) are unproduced\n", SHORTFALL,
		    unclaimed);
	}
	if (getenv("NCFG_BLESS")) {
		if (unclaimed) {
			printf("socket_witness_test: NOT written, %zu of %zu lines produced\n",
			    line_count - unclaimed, line_count);
		} else if (!bless(path)) {
			printf("socket_witness_test: %s could not be written\n", path);
			failures++;
		} else {
			printf("socket_witness_test: %s written, %zu lines\n", path, line_count);
		}
	}
	for (at = 0u; at < line_count; at++) {
		free(lines[at]);
		free(made[at]);
	}
	if (failures == 0) {
		printf("socket_witness_test: all checks passed\n");
	} else {
		printf("socket_witness_test: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
