/*
 * socket_witness_test.c -- writing `doc/schema/socket.json` from this build.
 *
 * WHY THIS FILE EXISTS
 *   0279 moved the four frozen witnesses to the C and left this one: the other
 *   three are written by the module that owns them, and the socket's was still
 *   a file nobody here produced. `proto_test.c` proves every line DECODES and
 *   that every request re-encodes to the same bytes, which is a round trip;
 *   what it cannot say is that this build can PRODUCE the file.
 *
 * WHAT IT DOES
 *   Writes all 67 lines, in the file's order, each through the encoder the
 *   daemon answers with -- and compares what it wrote against what is
 *   committed, so the comparison and the bless are the same program. Four
 *   groups:
 *
 *     requests   decoded from the witness and re-encoded, which is the path
 *                `proto_test` already proves. The VALUES are the file's and the
 *                BYTES are this build's, which is the half that goes stale when
 *                an encoder changes
 *     responses  built from values here and written by the same functions the
 *                daemon answers with -- never a second encoder, which is the
 *                thing this tree refuses everywhere else
 *     wifi       asked of the repository's fake supplicant and fake hostapd,
 *                because those six answers are written as a live control
 *                socket is read and there is no encoder to call with a value
 *     events     both shapes, wrapped and bare, from the one writer that takes
 *                the wrapper as an argument (0280)
 *
 * **THE ORDER IS THIS FILE'S, NOT THE WITNESS'S**, and that is the whole
 * difference between a builder and a checker. Producing lines in a sequence
 * written here means a line whose bytes have changed is a line this can
 * REPLACE; matching produced bytes against whatever the file happens to say
 * would have made the bless a no-op by construction -- it could only ever
 * write back what it had just read, which is `evidence.md`'s gate that
 * compares an artifact to itself.
 *
 * TERMINATION, SINCE THIS FORKS
 *   Three python fakes, each under `timeout 60`, started once and stopped on
 *   every exit path including the failing ones. No loop over anything but the
 *   67 lines. `fakewifi.h` carries the detail and the reason the kill has to
 *   reach a process group.
 */
#include "fakewifi.h"
#include "testdir.h"

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
#include "ncfg/supplicant.h"
#include "ncfg/value.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;
static int differences;

static void check(int condition, const char *what)
{
	printf("%-70s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

static void detail(const char *what, const char *why)
{
	if (failures) {
		printf("  %s: %s\n", what, why ? why : "(nothing said)");
	}
}

/* ------------------------------------------------------------- the witness */

#define LINE_MAX      131072u
#define WITNESS_LINES 128u
/* What the file holds, and what this must therefore produce. Asserted rather
 * than assumed: a builder that wrote 61 lines over a 67-line file would be a
 * silent truncation of the frozen surface. */
#define WITNESS_COUNT 67u

static char  *lines[WITNESS_LINES];
/* What this build produced, in the order it produced it. The file is written
 * from these and never from `lines`, so nothing can be copied back out of the
 * file it is supposed to be checking. */
static char  *made[WITNESS_LINES];
static size_t line_count;
static size_t made_count;

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
 * One line, at the position this build has reached.
 *
 * Kept whatever the file says, because this is what will be written. A
 * difference is counted and printed rather than being made the caller's
 * problem: the caller is producing the protocol's surface, and whether a
 * changed surface is a failure or a bless is `main`'s question.
 */
static void emit(const char *what, const char *bytes)
{
	size_t at = made_count;

	if (at >= WITNESS_LINES) {
		printf("  more lines than this holds, at %s\n", what);
		failures++;
		return;
	}
	made[at] = malloc(strlen(bytes) + 1u);
	if (!made[at]) {
		printf("  out of memory at %s\n", what);
		failures++;
		return;
	}
	memcpy(made[at], bytes, strlen(bytes) + 1u);
	made_count++;
	if (at < line_count && strcmp(lines[at], bytes) != 0) {
		differences++;
		printf("  line %zu (%s) differs from the witness:\n    was %.100s\n    now %.100s\n",
		    at + 1u, what, lines[at], bytes);
	}
}

/* Encode-and-emit, for the response writers that all return the same way. */
static void one(const char *what, int ok, ncfg_buf_t *out, const char *err)
{
	if (!ok) {
		printf("  %s does not encode: %s\n", what, err);
		failures++;
		return;
	}
	emit(what, ncfg_buf_text(out));
}

/* A counted string over a literal, for the wire types whose members carry
 * bytes and a length rather than a NUL. */
static ncfg_proto_str_t text_of(const char *literal)
{
	ncfg_proto_str_t text;

	text.bytes = literal;
	text.length = strlen(literal);
	return text;
}

/* ------------------------------------------------------------- the requests */

/*
 * Every request line, through this build's encoder.
 *
 * Decoded from the witness and written back: the request VALUES are the file's
 * and the bytes are this build's, which is the half that matters for producing
 * the file. Constructing forty-one request values here would be a second copy
 * of the samples with nothing holding the two in step.
 *
 * They are the file's first lines and this asserts it, because everything
 * below emits by position: a request line further down would be produced in
 * the wrong place and the difference would read as an encoder change.
 */
static void the_requests(void)
{
	size_t at;

	for (at = 0u; at < line_count; at++) {
		ncfg_proto_message_t message;
		ncfg_buf_t           out;
		char                 err[NCFG_ERROR_MAX] = "";

		if (strncmp(lines[at], "{\"request\":", 11u) != 0) {
			break;
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
			emit("a request", ncfg_buf_text(&out));
		} else {
			printf("  a request does not encode: %s\n", err);
			failures++;
		}
		ncfg_buf_free(&out);
		ncfg_proto_message_free(&message);
	}
	check(made_count == 41u, "the first 41 lines are requests, each re-encoded here");
	for (; at < line_count; at++) {
		if (strncmp(lines[at], "{\"request\":", 11u) == 0) {
			check(0, "and no request line sits below them, which the order needs");
			break;
		}
	}
}

/* ------------------------------------------------------- the fakes' fixtures */

static char base[256];
static char ctrl_dir[320];
static char run_dir[320];
static char class_net[320];
static char hostapd_dir[384];
static char supplicant_log[384];

static ncfg_wifi_where_t where;

/* One configuration file's text, as the loader would hand it over. */
static int add_source(ncfg_config_sources_t *sources, const char *name, const char *text)
{
	ncfg_config_file_t *grown = realloc(sources->at, (sources->count + 1u) * sizeof(*grown));

	if (!grown) {
		return 0;
	}
	sources->at = grown;
	sources->capacity = sources->count + 1u;
	grown[sources->count].name = strdup(name);
	grown[sources->count].text = strdup(text);
	grown[sources->count].length = strlen(text);
	if (!grown[sources->count].name || !grown[sources->count].text) {
		return 0;
	}
	sources->count++;
	return 1;
}

/* Compiled to read, so the hook sink refuses: every document here is a
 * question about what netcfgd would answer and is thrown away after. */
static ncfg_document_t *compiled(const char *name, const char *text)
{
	ncfg_config_sources_t sources = { 0 };
	ncfg_document_t      *document = NULL;
	char                  err[NCFG_ERROR_MAX];

	if (add_source(&sources, name, text)) {
		document = ncfg_config_compile(&sources, ncfg_hook_sink_unwritten(), NULL, err,
		    sizeof(err));
		if (!document) {
			failures++;
			detail("this fixture does not compile", err);
		}
	}
	ncfg_config_sources_free(&sources);
	return document;
}

/* An observation from JSON, which is how every other test here builds one:
 * the model's own reader rather than a struct filled in by hand and quietly
 * missing whatever the model grows next. */
static ncfg_observed_t *observation(const char *text)
{
	char             err[NCFG_ERROR_MAX];
	ncfg_observed_t *observed = ncfg_observed_read(text, strlen(text), err, sizeof(err));

	if (!observed) {
		failures++;
		detail("this observation does not parse", err);
	}
	return observed;
}

#define TWO_RADIOS                                                                            \
	"{\"links\":["                                                                        \
	"{\"name\":\"wlan0\",\"index\":2,\"kind\":\"\",\"wireless\":true,\"up\":true,"        \
	"\"carrier\":true,\"mtu\":1500,\"offloads\":[],\"ownership\":\"unknown\","            \
	"\"private_key_loaded\":false},"                                                      \
	"{\"name\":\"wlan1\",\"index\":3,\"kind\":\"\",\"wireless\":true,\"up\":false,"       \
	"\"carrier\":false,\"mtu\":1500,\"offloads\":[],\"ownership\":\"unknown\","           \
	"\"private_key_loaded\":false},"                                                      \
	"{\"name\":\"eth0\",\"index\":1,\"kind\":\"\",\"wireless\":false,\"up\":true,"        \
	"\"carrier\":true,\"mtu\":1500,\"offloads\":[],\"ownership\":\"unknown\","            \
	"\"private_key_loaded\":false}]}"

/* The same, with the kill switch on `wlan0` pressed. */
#define RADIO_SWITCHED_OFF                                                                    \
	"{\"links\":["                                                                        \
	"{\"name\":\"wlan0\",\"index\":2,\"kind\":\"\",\"wireless\":true,\"up\":true,"        \
	"\"carrier\":true,\"mtu\":1500,\"offloads\":[],\"ownership\":\"unknown\","            \
	"\"private_key_loaded\":false,"                                                       \
	"\"rfkill\":{\"switch\":\"phy0\",\"soft\":true,\"hard\":false}}]}"

/*
 * Stand the fakes up. 0 and a sentence where anything is missing.
 *
 * Not skipped: a builder that carried on here would write six lines of
 * `[]` over six lines of real answers and report success for a witness it had
 * just emptied -- the vacuous pass `evidence.md` opens with, aimed at the one
 * file in this tree nothing else can check.
 */
static int start_the_radios(const char *fakes)
{
	const char *argument[4];
	char        supplicant_script[384];
	char        hostapd_script[384];
	/* Longer than the directories it is built from, which is what the
	 * truncation warning asks for: a path this clipped would bind nothing. */
	char        socket_path[448];

	if (!testdir_make("socket-witness")) {
		printf("no fixture directory\n");
		return 0;
	}
	(void)snprintf(base, sizeof(base), "%s", testdir_path);
	(void)snprintf(ctrl_dir, sizeof(ctrl_dir), "%s/ctrl", base);
	(void)snprintf(run_dir, sizeof(run_dir), "%s/run", base);
	(void)snprintf(class_net, sizeof(class_net), "%s/sys", base);
	(void)snprintf(hostapd_dir, sizeof(hostapd_dir), "%s/hostapd", run_dir);
	(void)snprintf(supplicant_log, sizeof(supplicant_log), "%s/supplicant.log", base);
	make_directory(ctrl_dir);
	make_directory(run_dir);
	make_directory(class_net);
	make_directory(hostapd_dir);
	make_radio(class_net, "wlan0", 1);
	make_radio(class_net, "wlan1", 1);
	make_radio(class_net, "eth0", 0);
	where.ctrl_dir = ctrl_dir;
	where.class_net = class_net;
	where.run_dir = run_dir;

	(void)snprintf(supplicant_script, sizeof(supplicant_script), "%s/fake_supplicant.py",
	    fakes);
	(void)snprintf(hostapd_script, sizeof(hostapd_script), "%s/fake_hostapd.py", fakes);
	if (!testdir_exists(supplicant_script) || !testdir_exists(hostapd_script)) {
		printf("the repository's fakes are not at `%s`; pass their directory as the "
		       "second argument\n",
		    fakes);
		return 0;
	}
	argument[0] = ctrl_dir;
	argument[1] = "wlan0";
	(void)snprintf(socket_path, sizeof(socket_path), "%s/wlan0", ctrl_dir);
	if (!start_fake(supplicant_script, argument, 2u, socket_path, supplicant_log)) {
		printf("the fake supplicant for wlan0 never bound its socket\n");
		return 0;
	}
	/* `wlan1` answers too, which is what makes the radio list's two columns
	 * mean different things: it is not activated and it is answering. */
	argument[1] = "wlan1";
	(void)snprintf(socket_path, sizeof(socket_path), "%s/wlan1", ctrl_dir);
	if (!start_fake(supplicant_script, argument, 2u, socket_path, supplicant_log)) {
		printf("the fake supplicant for wlan1 never bound its socket\n");
		return 0;
	}
	argument[0] = hostapd_dir;
	argument[1] = "wlan0";
	argument[2] = "--deny";
	argument[3] = "00:11:22:33:44:55";
	(void)snprintf(socket_path, sizeof(socket_path), "%s/wlan0", hostapd_dir);
	if (!start_fake(hostapd_script, argument, 4u, socket_path, supplicant_log)) {
		printf("the fake hostapd never bound its socket\n");
		return 0;
	}
	return 1;
}

/* `HomeFiber` as the octets it is, which is how a `network` block names an
 * ssid and how the scan row reports one. */
#define HOMEFIBER_HEX "486f6d654669626572"

/*
 * The six the fakes answer: lines 44 to 48 and 54.
 *
 * **Every value here is the fake's, not this file's**, which is what 0281
 * decided. The witness said `home` at -40 dBm where the fake has answered
 * `HomeFiber` at -53 since it was written, so these lines were the only ones
 * in the file that no program in this tree could produce.
 */
static void the_wifi_answers(void)
{
	ncfg_document_t *known = compiled("known.conf",
	    "network \"home\" {\n\tssid = \"" HOMEFIBER_HEX "\"\n\twifi { open = true }\n}\n");
	ncfg_document_t *devices = compiled("devices.conf",
	    "device wlan0 {\n\twifi {\n\t\tautoconnect = true\n\t}\n}\n"
	    "device wlan1 {\n\tmanaged = false\n\twifi {\n\t\tautoconnect = true\n\t}\n}\n");
	ncfg_document_t *access_point = compiled("ap.conf",
	    "access_point \"guest\" {\n\tdevice = \"wlan0\"\n\tchannel = 11\n"
	    "\twifi { psk = \"@secret:guest\"; proto = \"wpa2\" }\n"
	    "\taccess_control { deny = [\"00:11:22:33:44:55\"] }\n}\n");
	ncfg_observed_t *observed = observation(TWO_RADIOS);
	ncfg_observed_t *off = observation(RADIO_SWITCHED_OFF);
	ncfg_buf_t       out;
	char             err[NCFG_ERROR_MAX] = "";

	if (!known || !devices || !access_point || !observed || !off) {
		return;
	}
	/* 44: a scan nothing has interfered with. */
	ncfg_buf_init(&out, 0);
	one("a fresh scan",
	    ncfg_wifi_scan(&where, known, ncfg_wifi_blocked_switch(observed, "wlan0"), "wlan0",
	        &out, err, sizeof(err)),
	    &out, err);
	ncfg_buf_free(&out);

	/* 45: and one the supplicant refused, which answers with what it last saw
	 * and says why that is what it is. */
	check(tell_fake(ctrl_dir, "wlan0", "FAIL_NEXT_SCAN -16"),
	    "the radio is told to refuse the next scan");
	ncfg_buf_init(&out, 0);
	one("a stale scan",
	    ncfg_wifi_scan(&where, known, ncfg_wifi_blocked_switch(observed, "wlan0"), "wlan0",
	        &out, err, sizeof(err)),
	    &out, err);
	ncfg_buf_free(&out);

	/* 46: the radios the kernel reports, and the gap between activated and
	 * answering. */
	ncfg_buf_init(&out, 0);
	one("the radio list", ncfg_wifi_radios(&where, devices, observed, &out, err, sizeof(err)),
	    &out, err);
	ncfg_buf_free(&out);

	/* 47: what one radio is doing, with two networks it has given up on --
	 * which `STATUS` never carried and `LIST_NETWORKS` is asked for. */
	check(tell_fake(ctrl_dir, "wlan0", "DISABLE [TEMP-DISABLED] Office") &&
	        tell_fake(ctrl_dir, "wlan0", "DISABLE [DISABLED] Lab"),
	    "and given two networks it is not trying");
	ncfg_buf_init(&out, 0);
	one("a radio's status",
	    ncfg_wifi_status(&where, known, observed, "wlan0", &out, err, sizeof(err)), &out,
	    err);
	ncfg_buf_free(&out);

	/* 48: the same radio with its kill switch pressed, which is the answer
	 * `STATUS` cannot distinguish from "nothing is there". */
	ncfg_buf_init(&out, 0);
	one("a switched-off radio's status",
	    ncfg_wifi_status(&where, known, off, "wlan0", &out, err, sizeof(err)), &out, err);
	ncfg_buf_free(&out);

	ncfg_document_free(known);
	ncfg_document_free(devices);
	ncfg_observed_free(observed);
	ncfg_observed_free(off);
	/* 54's document is wanted later, so it is freed by its own producer. */
	ncfg_document_free(access_point);
}

/* 54, which is hostapd's rather than the supplicant's and so is produced
 * where the witness puts it. */
static void the_stations(void)
{
	ncfg_document_t *access_point = compiled("ap.conf",
	    "access_point \"guest\" {\n\tdevice = \"wlan0\"\n\tchannel = 11\n"
	    "\twifi { psk = \"@secret:guest\"; proto = \"wpa2\" }\n"
	    "\taccess_control { deny = [\"00:11:22:33:44:55\"] }\n}\n");
	ncfg_buf_t       out;
	char             err[NCFG_ERROR_MAX] = "";

	if (!access_point) {
		return;
	}
	ncfg_buf_init(&out, 0);
	one("the stations",
	    ncfg_wifi_ap_stations(&where, access_point, "wlan0", &out, err, sizeof(err)), &out,
	    err);
	ncfg_buf_free(&out);
	ncfg_document_free(access_point);
}

/* ------------------------------------------------------------ the responses */

static void the_hello(void)
{
	/* `observe` and `admin`, which is what the witness says this connection
	 * holds. */
	static const ncfg_tier_t tiers[] = { NCFG_TIER_OBSERVE, NCFG_TIER_ADMIN };
	ncfg_buf_t               out;
	char                     err[NCFG_ERROR_MAX] = "";

	ncfg_buf_init(&out, 0);
	one("hello", ncfg_daemon_hello_encode(tiers, 2u, &out, err, sizeof(err)), &out, err);
	ncfg_buf_free(&out);
}

static void the_explanation(void)
{
	/* One fact, and `total` equal to `count`: a truncated explanation says so
	 * in a fact of its own, which is `answer_test`'s case and not a shape the
	 * witness carries. */
	ncfg_explain_fact_t fact;
	ncfg_explanation_t  explanation;
	ncfg_buf_t          out;
	char                err[NCFG_ERROR_MAX] = "";

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
	one("explanation", ncfg_daemon_explanation_encode(&explanation, &out, err, sizeof(err)),
	    &out, err);
	ncfg_buf_free(&out);
}

/*
 * The two that are whole models rather than lists, and the empty plan.
 *
 * Built by the model's own reader and constructor rather than field by field,
 * which is this port's rule everywhere: a struct assembled by hand is quietly
 * missing whatever the model grows next, and these are the lines that would
 * then be blessed wrong.
 */
static void the_whole_models(void)
{
	ncfg_observed_t *observed;
	ncfg_document_t *desired;
	ncfg_plan_t     *plan;
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

	/*
	 * Empty, because the witness's plan is empty: a plan with actions in it is
	 * `plan_test`'s witness, and the two files are not the same surface.
	 *
	 * `ncfg_plan_new` rather than a zeroed struct on the stack, which aborted
	 * here: `ncfg_plan_free` ends with `free(plan)` because a plan is always
	 * heap, so a plan that encodes correctly is not a plan that can be freed,
	 * and the constructor is the only shape that is both.
	 */
	plan = ncfg_plan_new(err, sizeof(err));
	if (!plan) {
		printf("  an empty plan does not build: %s\n", err);
		failures++;
	} else {
		ncfg_buf_init(&out, 0);
		one("plan", ncfg_daemon_plan_encode(plan, &out, err, sizeof(err)), &out, err);
		ncfg_buf_free(&out);
		ncfg_plan_free(plan);
	}

	desired = ncfg_document_new(err, sizeof(err));
	if (!desired) {
		printf("  an empty document does not build: %s\n", err);
		failures++;
	} else {
		/* No diagnostics, which the witness spells as the member being absent
		 * rather than as an empty string. */
		ncfg_buf_init(&out, 0);
		one("document", ncfg_daemon_document_encode(desired, NULL, &out, err, sizeof(err)),
		    &out, err);
		ncfg_buf_free(&out);
		ncfg_document_free(desired);
	}
}

static void the_journal(void)
{
	ncfg_journal_t journal;
	ncfg_record_t  record;
	ncfg_buf_t     out;
	char           err[NCFG_ERROR_MAX] = "";

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
	one("journal", ncfg_daemon_journal_encode(&journal, &out, err, sizeof(err)), &out, err);
	ncfg_buf_free(&out);
	ncfg_journal_free(&journal);
}

/*
 * One event, wrapped, which is what a monitor stream carries.
 *
 * The witness holds exactly one of these -- `confirm_armed` -- and the five
 * payload lines below. `the_bare_events` writes the wrapped form of all five
 * as well and discards four of them, so the wrapper is exercised for every
 * kind without inventing lines the file does not have.
 */
static void the_wrapped_event(void)
{
	ncfg_proto_event_t event;
	ncfg_buf_t         out;
	char               err[NCFG_ERROR_MAX] = "";

	memset(&event, 0, sizeof(event));
	event.kind = NCFG_PROTO_EVENT_CONFIRM_ARMED;
	event.seconds = 90;
	ncfg_buf_init(&out, 0);
	one("the wrapped confirm_armed event",
	    ncfg_proto_event_encode(&event, 1, &out, err, sizeof(err)), &out, err);
	ncfg_buf_free(&out);
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
}

static void the_secrets(void)
{
	ncfg_secret_entry_t entries[3];
	char               *cafe[1];
	char               *campus[1];
	ncfg_buf_t          out;
	char                err[NCFG_ERROR_MAX] = "";

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
	 * `used_by` is omitted rather than written empty: a credential no block
	 * mentions any more is the one worth deleting. */
	entries[2].name = (char *)(uintptr_t)"old-vpn";
	entries[2].stored = 1;
	ncfg_buf_init(&out, 0);
	one("secrets", ncfg_daemon_secrets_encode(entries, 3u, &out, err, sizeof(err)), &out,
	    err);
	ncfg_buf_free(&out);
}

static void the_modems(void)
{
	ncfg_proto_sim_card_t cards[1];
	ncfg_proto_str_t      wwan0_sim[2];
	ncfg_proto_str_t      wwan1_sim[1];
	ncfg_proto_modem_t    modems[2];
	ncfg_buf_t            out;
	char                  err[NCFG_ERROR_MAX] = "";

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
	/* Nothing has reported a card for this one, which is the only way to say
	 * "the other socket has not been looked in". */
	modems[1].device = text_of("wwan1");
	modems[1].sim.items = wwan1_sim;
	modems[1].sim.count = 1u;
	modems[1].selected = text_of("socket");
	ncfg_buf_init(&out, 0);
	one("modems", ncfg_daemon_modems_encode(modems, 2u, &out, err, sizeof(err)), &out, err);
	ncfg_buf_free(&out);
}

static void the_profiles(void)
{
	ncfg_profile_entry_t profiles[2];
	ncfg_buf_t           out;
	char                 err[NCFG_ERROR_MAX] = "";

	memset(profiles, 0, sizeof(profiles));
	profiles[0].name = (char *)(uintptr_t)"offline";
	profiles[0].shipped = 1;
	profiles[1].name = (char *)(uintptr_t)"office";
	profiles[1].shipped = 0;
	ncfg_buf_init(&out, 0);
	one("profiles",
	    ncfg_daemon_profiles_encode(profiles, 2u, "office", &out, err, sizeof(err)), &out,
	    err);
	ncfg_buf_free(&out);
}

static void the_file_listings(void)
{
	ncfg_config_entry_t configs[2];
	ncfg_probe_entry_t  probes[2];
	ncfg_hook_script_t  scripts[2];
	ncfg_buf_t          out;
	char                err[NCFG_ERROR_MAX] = "";

	/* The first has no `name`, which is a file a client cannot address, and
	 * the second is the drop-in that has one. */
	memset(configs, 0, sizeof(configs));
	configs[0].name = (char *)(uintptr_t)"";
	configs[0].file = (char *)(uintptr_t)"netcfgd.conf";
	configs[0].removable = 0;
	configs[0].text = (char *)(uintptr_t)"global { }\n";
	configs[1].name = (char *)(uintptr_t)"wifi-home";
	configs[1].file = (char *)(uintptr_t)"conf.d/wifi-home.conf";
	configs[1].removable = 1;
	configs[1].text = (char *)(uintptr_t)"network \"home\" { }\n";
	ncfg_buf_init(&out, 0);
	one("configs", ncfg_daemon_configs_encode(configs, 2u, &out, err, sizeof(err)), &out,
	    err);
	ncfg_buf_free(&out);

	memset(probes, 0, sizeof(probes));
	probes[0].name = (char *)(uintptr_t)"default";
	probes[0].directory = (char *)(uintptr_t)"/usr/share/netcfgd/probe";
	probes[0].text = (char *)(uintptr_t)"#!/bin/sh\nexit 0\n";
	probes[0].editable = 0;
	probes[1].name = (char *)(uintptr_t)"office";
	probes[1].directory = (char *)(uintptr_t)"/etc/netcfgd/probe";
	probes[1].text = (char *)(uintptr_t)"#!/bin/sh\nexit 1\n";
	probes[1].editable = 1;
	ncfg_buf_init(&out, 0);
	one("probes", ncfg_daemon_probes_encode(probes, 2u, &out, err, sizeof(err)), &out, err);
	ncfg_buf_free(&out);

	/* The second is unreadable, so its text is empty -- and the two are not
	 * the same answer, which is why `readable` is on the wire. */
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
	one("hooks", ncfg_daemon_hooks_encode(scripts, 2u, &out, err, sizeof(err)), &out, err);
	ncfg_buf_free(&out);
}

/*
 * Every event's payload, and every event's wrapper.
 *
 * The witness carries each event twice over: once wrapped, as a monitor stream
 * delivers it, and once as the payload on its own, which is the shape the
 * decoder also accepts. **Only the wrapped form had a writer** until this file
 * needed the other -- `ncfg_main_event_encode` in `src/main/` wrote
 * `"response":"event"` unconditionally -- so five of the witness's lines were a
 * shape this build could read and never produce (0280).
 */
static void the_bare_events(void)
{
	size_t kind;
	size_t done = 0u;

	for (kind = 0u; kind < NCFG_PROTO_EVENT_COUNT; kind++) {
		ncfg_proto_event_t event;
		ncfg_buf_t         out;
		char               err[NCFG_ERROR_MAX] = "";

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
			    ncfg_proto_event_name((int)event.kind), err);
			failures++;
		} else {
			emit("an event payload", ncfg_buf_text(&out));
			done++;
		}
		ncfg_buf_free(&out);

		/* And the same event wrapped, which the witness holds one of. Produced
		 * for every kind and kept for none: this is the encoder being
		 * exercised, not a line of the file. */
		ncfg_buf_init(&out, 0);
		if (!ncfg_proto_event_encode(&event, 1, &out, err, sizeof(err))) {
			printf("  the wrapped %s event does not encode: %s\n",
			    ncfg_proto_event_name((int)event.kind), err);
			failures++;
		} else if (strstr(ncfg_buf_text(&out), "\"response\":\"event\"") == NULL) {
			printf("  the wrapped %s event carries no response tag\n",
			    ncfg_proto_event_name((int)event.kind));
			failures++;
		}
		ncfg_buf_free(&out);
	}
	check(done == 5u, "every event's payload shape is produced as the witness pins it");
}

/*
 * Write the witness, from what this build produced.
 *
 * The length is read before anything is freed, which is the mistake the other
 * three blessers made on their first run -- writing `17114 of 0` bytes because
 * `ncfg_buf_free` had zeroed the length the `fwrite` was given (0279).
 */
static int bless(const char *path)
{
	FILE  *file;
	size_t at;

	if (made_count != WITNESS_COUNT) {
		return 0;
	}
	for (at = 0u; at < made_count; at++) {
		if (!made[at]) {
			return 0;
		}
	}
	file = fopen(path, "wb");
	if (!file) {
		return 0;
	}
	for (at = 0u; at < made_count; at++) {
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
	const char *fakes = argc > 2 ? argv[2] : "../tests/live";
	size_t      at;

	if (!read_witness(path)) {
		printf("socket_witness_test: cannot read %s\n", path);
		return 1;
	}
	printf("socket_witness_test: %zu lines in %s\n", line_count, path);
	if (!start_the_radios(fakes)) {
		stop_fakes();
		testdir_remove(testdir_path);
		return 1;
	}

	the_requests();
	the_hello();
	the_explanation();
	the_wifi_answers();
	the_whole_models();
	the_journal();
	the_wrapped_event();
	the_stations();
	the_small_responses();
	the_secrets();
	the_modems();
	the_profiles();
	the_file_listings();
	the_bare_events();

	stop_fakes();
	testdir_remove(testdir_path);

	check(made_count == WITNESS_COUNT, "this build produces all 67 lines of the witness");
	if (made_count != WITNESS_COUNT) {
		printf("  %zu produced, %zu in the file\n", made_count, line_count);
	}
	/*
	 * A difference is the frozen surface moving, so outside a bless it is a
	 * failure: that is what freezing means. Inside one it is the point.
	 */
	if (getenv("NCFG_BLESS")) {
		if (!bless(path)) {
			printf("socket_witness_test: %s could not be written\n", path);
			failures++;
		} else {
			printf("socket_witness_test: %s written, %zu line(s), %d changed\n", path,
			    made_count, differences);
		}
	} else {
		check(differences == 0,
		    "and every line is the one the witness holds, byte for byte");
		if (differences) {
			printf("  `make schema-bless` is the deliberate way to move these, and\n"
			       "  the commit message is the review\n");
		}
	}
	for (at = 0u; at < line_count; at++) {
		free(lines[at]);
	}
	for (at = 0u; at < made_count; at++) {
		free(made[at]);
	}
	if (failures == 0) {
		printf("socket_witness_test: all checks passed\n");
	} else {
		printf("socket_witness_test: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
