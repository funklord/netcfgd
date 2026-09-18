/*
 * proto_test.c -- the socket protocol, against the witness it is frozen to.
 *
 * WHY THIS EXISTS
 *   `doc/schema/socket.json` is generated from the daemon's own types by an
 *   exhaustive match, so a message that exists and is never sampled is a
 *   compile error on that side rather than a silent gap. That makes it the
 *   acceptance criterion for a second implementation: **every line of it must
 *   decode, and every request in it must re-encode to the same bytes.** A port
 *   that cannot round-trip the witness is not the same protocol.
 *
 *   `client/tests/client_test.c` already feeds the witness to the JSON
 *   reader and counts what parses. This does the thing that one cannot: it
 *   decodes each line into the typed message, checks that every request,
 *   response and event kind this module knows was actually exercised, and
 *   sends the requests back out through the encoder to compare bytes.
 *
 * WHAT THE ROUND TRIP PROVES, AND WHAT IT DOES NOT
 *   It proves the encoder emits the members the daemon emits, in the order it
 *   emits them, with the same skipping of unset ones -- because the witness is
 *   what serde produced. It does **not** prove that byte equality is required
 *   of anybody: section 7 says messages are not canonical, and a client that
 *   spelled `"hidden":false` explicitly would decode to the same message and
 *   re-encode shorter. Byte equality is used here because it is the sharpest
 *   available check against a file that is already frozen, not because the
 *   protocol demands one representation.
 */
#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/proto.h"

#include "ncfg_json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;

static void check(int condition, const char *what)
{
	printf("%-64s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

static void detail(const char *label, const char *text)
{
	printf("       %s: %s\n", label, text ? text : "(none)");
}

/* ------------------------------------------------------------ the witness */

/*
 * Every line of the witness, decoded, and every request re-encoded.
 *
 * The coverage counters are the part that keeps this from passing vacuously:
 * a gate over an empty file list reports success exactly as loudly as a real
 * one, and the witness is read from a path that could be wrong. So the run
 * ends by asserting that *every* kind this module names was seen -- which the
 * witness can satisfy because it is generated from an exhaustive match.
 */
static void the_witness_round_trips(const char *path)
{
	FILE *file = fopen(path, "r");
	char line[1024 * 128];
	unsigned requests = 0;
	unsigned responses = 0;
	unsigned events = 0;
	unsigned reencoded = 0;
	unsigned refused = 0;
	unsigned differed = 0;
	char first_refusal[NCFG_ERROR_MAX + 160] = "";
	char first_difference[1024] = "";
	unsigned char seen_request[NCFG_PROTO_REQ_COUNT];
	unsigned char seen_response[NCFG_PROTO_RESP_COUNT];
	unsigned char seen_event[NCFG_PROTO_EVENT_COUNT];
	int at;
	int complete;

	memset(seen_request, 0, sizeof(seen_request));
	memset(seen_response, 0, sizeof(seen_response));
	memset(seen_event, 0, sizeof(seen_event));

	if (!file) {
		check(0, "the witness can be opened");
		detail("path", path);
		return;
	}
	while (fgets(line, sizeof(line), file)) {
		size_t length = strlen(line);
		ncfg_proto_message_t message;
		char err[NCFG_ERROR_MAX];

		while (length && (line[length - 1] == '\n' || line[length - 1] == '\r')) {
			length--;
		}
		if (!length || line[0] == '#') {
			continue; /* the witness carries comments for its readers */
		}
		if (!ncfg_proto_message_read(line, length, &message, err, sizeof(err))) {
			if (!refused) {
				snprintf(first_refusal, sizeof(first_refusal), "%.320s: %.120s",
				    err, line);
			}
			refused++;
			continue;
		}
		switch (message.kind) {
		case NCFG_PROTO_MESSAGE_REQUEST: {
			ncfg_buf_t out;

			requests++;
			seen_request[message.u.request.kind] = 1;
			ncfg_buf_init(&out, 0);
			if (!ncfg_proto_request_encode(&message.u.request, &out, err,
			        sizeof(err))) {
				if (!differed) {
					snprintf(first_difference, sizeof(first_difference),
					    "%.200s could not be re-encoded: %.200s", line, err);
				}
				differed++;
			} else if (out.length != length ||
			    memcmp(ncfg_buf_text(&out), line, length) != 0) {
				if (!differed) {
					snprintf(first_difference, sizeof(first_difference),
					    "in  %.400s\n       out %.400s", line,
					    ncfg_buf_text(&out));
				}
				differed++;
			} else {
				reencoded++;
			}
			ncfg_buf_free(&out);
			break;
		}
		case NCFG_PROTO_MESSAGE_RESPONSE:
			responses++;
			seen_response[message.u.response.kind] = 1;
			if (message.u.response.kind == NCFG_PROTO_RESP_EVENT) {
				/* The wrapped payload is the same shape as a bare
				 * event line, and a monitor stream carries it this
				 * way -- so it counts for the event coverage too. */
				seen_event[message.u.response.u.event.kind] = 1;
			}
			break;
		case NCFG_PROTO_MESSAGE_EVENT:
		default:
			events++;
			seen_event[message.u.event.kind] = 1;
			break;
		}
		ncfg_proto_message_free(&message);
	}
	fclose(file);

	check(refused == 0, "every line of the socket witness decodes");
	if (refused) {
		detail("first refusal", first_refusal);
	}
	check(differed == 0, "and every request in it re-encodes to the same bytes");
	if (differed) {
		detail("first difference", first_difference);
	}
	check(requests > 20 && responses > 10 && events > 0,
	    "and there were lines of all three kinds, so this is not vacuous");
	check(reencoded == requests, "every request that decoded was also re-encoded");

	complete = 1;
	for (at = 0; at < NCFG_PROTO_REQ_COUNT; at++) {
		if (!seen_request[at]) {
			complete = 0;
			detail("no witness line for request", ncfg_proto_request_name(
			    (ncfg_proto_request_kind_t)at));
		}
	}
	check(complete, "the witness exercises every request this module names");

	complete = 1;
	for (at = 0; at < NCFG_PROTO_RESP_COUNT; at++) {
		if (!seen_response[at]) {
			complete = 0;
			detail("no witness line for response", ncfg_proto_response_name(
			    (ncfg_proto_response_kind_t)at));
		}
	}
	check(complete, "and every response");

	complete = 1;
	for (at = 0; at < NCFG_PROTO_EVENT_COUNT; at++) {
		if (!seen_event[at]) {
			complete = 0;
			detail("no witness line for event", ncfg_proto_event_name(
			    (ncfg_proto_event_kind_t)at));
		}
	}
	check(complete, "and every event");
}

/* ------------------------------------------------------- the member table */

/*
 * Every request, with every member it has filled in.
 *
 * The skipped members are the reason this exists: with any of them unset the
 * encoder emits fewer members than the request has, and the comparison below
 * would pass while proving less than it claims. Returning 0 for a kind it has
 * never heard of is what makes the walk over `NCFG_PROTO_REQ_COUNT` an
 * exhaustiveness check rather than a list somebody remembered to extend.
 */
static int fully_populated(ncfg_proto_request_kind_t kind, ncfg_proto_request_t *out)
{
	static ncfg_proto_str_t one[1];

	one[0] = ncfg_proto_str("eth0");
	memset(out, 0, sizeof(*out));
	out->kind = kind;
	switch (kind) {
	case NCFG_PROTO_REQ_HELLO:
	case NCFG_PROTO_REQ_STATUS:
	case NCFG_PROTO_REQ_PLAN:
	case NCFG_PROTO_REQ_CONFIRM:
	case NCFG_PROTO_REQ_REVERT:
	case NCFG_PROTO_REQ_RELOAD:
	case NCFG_PROTO_REQ_SHOW:
	case NCFG_PROTO_REQ_CONFIG_LIST:
	case NCFG_PROTO_REQ_MONITOR:
	case NCFG_PROTO_REQ_PROBE_LIST:
	case NCFG_PROTO_REQ_HOOK_LIST:
	case NCFG_PROTO_REQ_PROFILE_LIST:
	case NCFG_PROTO_REQ_MODEM_LIST:
	case NCFG_PROTO_REQ_SECRET_LIST:
	case NCFG_PROTO_REQ_RADIOS:
		return 1;
	case NCFG_PROTO_REQ_APPLY:
		out->u.apply.confirm.present = 1;
		out->u.apply.confirm.value = 30;
		out->u.apply.allow_disruption.items = one;
		out->u.apply.allow_disruption.count = 1u;
		out->u.apply.strand_credentials.items = one;
		out->u.apply.strand_credentials.count = 1u;
		out->u.apply.restart_wedged.items = one;
		out->u.apply.restart_wedged.count = 1u;
		return 1;
	case NCFG_PROTO_REQ_EXPLAIN:
		out->u.explain.kind = NCFG_PROTO_SUBJECT_INTERFACE;
		out->u.explain.name = ncfg_proto_str("eth0");
		return 1;
	case NCFG_PROTO_REQ_WIFI_SCAN:
	case NCFG_PROTO_REQ_WIFI_STATUS:
	case NCFG_PROTO_REQ_WIFI_DISCONNECT:
	case NCFG_PROTO_REQ_AP_STATIONS:
		out->u.interface = ncfg_proto_str("wlan0");
		return 1;
	case NCFG_PROTO_REQ_WIFI_ADD:
		out->u.wifi_add.ssid = ncfg_proto_str("686f6d65");
		out->u.wifi_add.id = ncfg_proto_str("home");
		out->u.wifi_add.passphrase = ncfg_proto_str("NOT-A-REAL-SECRET");
		out->u.wifi_add.proto = ncfg_proto_str("wpa3");
		out->u.wifi_add.hidden = 1;
		out->u.wifi_add.metric.present = 1;
		out->u.wifi_add.metric.value = 10;
		/* Populated, because this fixture exists so the encoder emits
		 * every member and the table can be compared against it. Absent
		 * here would leave `eap` out of the emitted keys and the check
		 * would report the table as wrong rather than the sample as
		 * incomplete. */
		out->u.wifi_add.eap.present = 1;
		out->u.wifi_add.eap.method = ncfg_proto_str("peap");
		out->u.wifi_add.eap.identity = ncfg_proto_str("you@corp.example");
		out->u.wifi_add.eap.anonymous_identity = ncfg_proto_str("anonymous@corp.example");
		out->u.wifi_add.eap.phase2 = ncfg_proto_str("mschapv2");
		out->u.wifi_add.eap.ca_cert = ncfg_proto_str("corp-ca");
		out->u.wifi_add.eap.client_cert = ncfg_proto_str("corp-crt");
		return 1;
	case NCFG_PROTO_REQ_WIFI_CONNECT:
		out->u.wifi_connect.interface = ncfg_proto_str("wlan0");
		out->u.wifi_connect.network = ncfg_proto_str("home");
		return 1;
	case NCFG_PROTO_REQ_WIFI_FORGET:
		out->u.id = ncfg_proto_str("home");
		return 1;
	case NCFG_PROTO_REQ_CONFIG_PUT:
	case NCFG_PROTO_REQ_PROBE_PUT:
		out->u.put.name = ncfg_proto_str("office");
		out->u.put.text = ncfg_proto_str("#!/bin/sh\nexit 0\n");
		out->u.put.replace = 1;
		return 1;
	case NCFG_PROTO_REQ_SECRET_PUT:
		out->u.secret_put.name = ncfg_proto_str("vpn");
		out->u.secret_put.value = ncfg_proto_str("NOT-A-REAL-SECRET");
		out->u.secret_put.replace = 1;
		return 1;
	case NCFG_PROTO_REQ_PROFILE_SET:
	case NCFG_PROTO_REQ_CONFIG_DELETE:
	case NCFG_PROTO_REQ_SECRET_DELETE:
		out->u.name = ncfg_proto_str("office");
		return 1;
	case NCFG_PROTO_REQ_PROFILE_SAVE:
		out->u.profile_save.name = ncfg_proto_str("office");
		out->u.profile_save.replace = 1;
		return 1;
	case NCFG_PROTO_REQ_RADIO_SET:
		out->u.radio_set.interface = ncfg_proto_str("wlan0");
		out->u.radio_set.activate = 1;
		return 1;
	case NCFG_PROTO_REQ_COUNT:
	default:
		return 0;
	}
}

/*
 * The member table against the only authority there is: what the encoder
 * emits.
 *
 * Both directions, rather than asserting the table is a subset. A table that
 * drifts is worse than no table, because the envelope check would then refuse
 * a member the protocol had just gained -- so a member the encoder emits and
 * the table has not got is caught by the count, and one the table has and the
 * encoder does not emit is caught by the lookup.
 */
static void the_member_table_matches_the_encoder(void)
{
	int at;
	int table_ok = 1;
	int fixture_ok = 1;
	int named_ok = 1;

	for (at = 0; at < NCFG_PROTO_REQ_COUNT; at++) {
		ncfg_proto_request_kind_t kind = (ncfg_proto_request_kind_t)at;
		ncfg_proto_request_t request;
		ncfg_buf_t out;
		char err[NCFG_ERROR_MAX];
		ncfg_json_doc_t *doc;
		const char *const *members;
		size_t count = 0;
		size_t which;

		if (!ncfg_proto_request_name(kind)) {
			named_ok = 0;
			continue;
		}
		if (!fully_populated(kind, &request)) {
			fixture_ok = 0;
			detail("no fully-populated fixture for", ncfg_proto_request_name(kind));
			continue;
		}
		ncfg_buf_init(&out, 0);
		if (!ncfg_proto_request_encode(&request, &out, err, sizeof(err))) {
			table_ok = 0;
			detail("would not encode", err);
			ncfg_buf_free(&out);
			continue;
		}
		doc = ncfg_json_parse(ncfg_buf_text(&out), out.length, err, sizeof(err));
		if (!doc) {
			table_ok = 0;
			detail("the encoder wrote something unreadable", err);
			ncfg_buf_free(&out);
			continue;
		}
		members = ncfg_proto_request_members(kind, &count);
		for (which = 0; which < count; which++) {
			if (ncfg_json_member(doc, ncfg_json_root(doc), members[which]) ==
			    NCFG_JSON_NONE) {
				table_ok = 0;
				detail("the table names a member the encoder does not emit",
				    members[which]);
			}
		}
		/*
		 * The tag, plus one member per table entry, and nothing else. This
		 * is the half that catches a member the encoder has gained and the
		 * table has not -- which the envelope check would then refuse, on
		 * a request the protocol says is valid.
		 */
		if ((size_t)ncfg_json_count(doc, ncfg_json_root(doc)) != count + 1u) {
			table_ok = 0;
			detail("the encoder emits a different number of members than the "
			    "table declares, for", ncfg_proto_request_name(kind));
		}
		ncfg_json_free(doc);
		ncfg_buf_free(&out);
	}
	check(named_ok, "every request kind has a name");
	check(fixture_ok, "every request kind is in the fully-populated fixture");
	check(table_ok, "and the member table is exactly what the encoder emits");
}

/* ---------------------------------------------------------- the two rules */

static void a_request_refuses_a_member_it_does_not_define(void)
{
	ncfg_proto_message_t message;
	char err[NCFG_ERROR_MAX];
	static const char bogus[] = "{\"request\":\"status\",\"bogus\":1}";
	static const char nested[] =
	    "{\"request\":\"explain\",\"subject\":{\"subject\":\"interface\","
	    "\"name\":\"eth0\",\"run_as\":\"root\"}}";
	static const char in_eap[] =
	    "{\"request\":\"wifi_add\",\"ssid\":\"63616665\",\"eap\":{\"method\":\"tls\","
	    "\"identity\":\"me\",\"private_key_file\":\"/etc/shadow\"}}";

	/* Section 7, item 6, which the daemon itself was not keeping for a
	 * while: the payload structs refused an unknown member and the envelope
	 * did not, so the permissive half was the one reading untrusted bytes
	 * into a process holding CAP_NET_ADMIN. */
	check(!ncfg_proto_request_read(bogus, sizeof(bogus) - 1u, &message, err, sizeof(err)),
	    "an unknown member on a request is refused");
	check(strstr(err, "bogus") != NULL, "and the refusal names the member");
	if (!strstr(err, "bogus")) {
		detail("said instead", err);
	}
	ncfg_proto_message_free(&message);

	/* The payload as well as the envelope, which is what the document asks
	 * for. `Subject` is an internally-tagged enum, so serde cannot deny
	 * unknown fields on it and the Rust still accepts this one; a table has
	 * no such limitation, so this keeps the stated rule. */
	check(!ncfg_proto_request_read(nested, sizeof(nested) - 1u, &message, err, sizeof(err)),
	    "and one inside an `explain` subject is refused too");
	check(strstr(err, "run_as") != NULL, "naming it as well");
	ncfg_proto_message_free(&message);

	/* An eap arm carrying a *path* is the shape 0117 exists to make
	 * unsendable, and `EapRequest` is deny_unknown_fields in the Rust for
	 * exactly this. */
	check(!ncfg_proto_request_read(in_eap, sizeof(in_eap) - 1u, &message, err, sizeof(err)),
	    "and a field a certificate path could go in is refused");
	check(strstr(err, "private_key_file") != NULL, "by name");
	ncfg_proto_message_free(&message);
}

static void a_known_member_sent_as_null_is_accepted(void)
{
	ncfg_proto_message_t message;
	char err[NCFG_ERROR_MAX];
	static const char line[] = "{\"request\":\"apply\",\"confirm\":null}";

	/*
	 * The case that rules out the cheaper implementation. Refusing any
	 * member a re-encode drops needs no table and cannot drift -- and it
	 * would refuse this, because `confirm` is skipped when unset. Item 5 of
	 * section 10 is "tell absent from null, and from empty", so a client is
	 * entitled to send it.
	 */
	check(ncfg_proto_request_read(line, sizeof(line) - 1u, &message, err, sizeof(err)),
	    "a known member sent as null is accepted");
	check(message.u.request.kind == NCFG_PROTO_REQ_APPLY &&
	        !message.u.request.u.apply.confirm.present &&
	        message.u.request.u.apply.allow_disruption.count == 0 &&
	        message.u.request.u.apply.strand_credentials.count == 0 &&
	        message.u.request.u.apply.restart_wedged.count == 0,
	    "and reads as an apply with no confirm and no consent");
	ncfg_proto_message_free(&message);
}

static void a_response_is_read_leniently(void)
{
	ncfg_proto_message_t message;
	char err[NCFG_ERROR_MAX];
	static const char future[] =
	    "{\"response\":\"hello\",\"protocol\":{\"major\":1,\"minor\":9},"
	    "\"schema\":{\"major\":1,\"minor\":1},\"tiers\":[\"observe\"],"
	    "\"quota\":{\"connections\":64},\"motd\":\"hello from a newer daemon\"}";
	static const char ok_line[] = "{\"response\":\"ok\",\"bogus\":1}";
	static const char unknown[] = "{\"response\":\"telemetry\",\"rows\":[]}";

	/*
	 * The other direction stays lenient, deliberately. A client may be older
	 * than the daemon it is talking to, so refusing a member it does not
	 * recognise is how an upgrade breaks a working client -- these are the
	 * same bytes the request test above refuses, pointed the other way.
	 */
	check(ncfg_proto_response_read(future, sizeof(future) - 1u, &message, err, sizeof(err)),
	    "a response carrying members this build never heard of is accepted");
	check(message.u.response.u.hello.protocol.minor == 9 &&
	        message.u.response.u.hello.tiers.count == 1u &&
	        ncfg_proto_str_equals(message.u.response.u.hello.tiers.items[0], "observe"),
	    "and everything this build does know is still there");
	ncfg_proto_message_free(&message);

	check(ncfg_proto_response_read(ok_line, sizeof(ok_line) - 1u, &message, err,
	        sizeof(err)),
	    "and so is an `ok` with a member beside it");
	ncfg_proto_message_free(&message);

	/*
	 * The leniency is about members and not about the tag, and the Rust
	 * draws the line in the same place: a message whose kind is unknown is
	 * one a client cannot act on, and guessing an arm for it is how a client
	 * renders the wrong thing.
	 */
	check(!ncfg_proto_response_read(unknown, sizeof(unknown) - 1u, &message, err,
	        sizeof(err)),
	    "but a response kind this build does not know is still refused");
	ncfg_proto_message_free(&message);
}

/* ------------------------------------------------------------ the framing */

static void a_message_may_not_carry_a_newline(void)
{
	ncfg_buf_t line;
	char err[NCFG_ERROR_MAX];
	ncfg_proto_request_t request;

	/*
	 * A message containing a newline would frame as two and the peer would
	 * mis-parse both halves. The writer escapes newlines inside strings, so
	 * on an encoded request this can only fire on a bug here -- which is why
	 * the gate is public and checked rather than assumed.
	 */
	ncfg_buf_init(&line, 0);
	ncfg_buf_add_text(&line, "{\"request\":\"status\"}\n{\"request\":\"plan\"}");
	check(!ncfg_proto_line_finish(&line, err, sizeof(err)),
	    "a message with an embedded newline is refused");
	check(strstr(err, "newline") != NULL, "saying so");
	ncfg_buf_free(&line);

	/* And the ordinary path: a `config_put` body is full of newlines, and
	 * they come out escaped rather than raw. */
	memset(&request, 0, sizeof(request));
	request.kind = NCFG_PROTO_REQ_CONFIG_PUT;
	request.u.put.name = ncfg_proto_str("from-a-client");
	request.u.put.text = ncfg_proto_str("interface eth0 {\n\tconfig = \"dhcp\"\n}\n");
	ncfg_buf_init(&line, 0);
	check(ncfg_proto_request_write(&request, &line, err, sizeof(err)),
	    "a config_put whose body is all newlines still frames");
	check(line.length && ncfg_buf_text(&line)[line.length - 1u] == '\n' &&
	        !memchr(ncfg_buf_text(&line), '\n', line.length - 1u),
	    "as exactly one line, with the body's newlines escaped");
	ncfg_buf_free(&line);
}

static void the_line_bound_is_enforced(void)
{
	ncfg_proto_framer_t framer;
	char err[NCFG_ERROR_MAX];
	char *flood;
	const char *got = NULL;
	size_t length = 0;

	/*
	 * The bound that stops a hostile client allocating the daemon to death.
	 * A client that sends a gigabyte without a newline must be refused
	 * rather than absorbed: the daemon holds CAP_NET_ADMIN and being killed
	 * by the OOM killer is a denial of service with extra steps.
	 */
	flood = malloc(NCFG_PROTO_MAX_LINE + 16u);
	if (!flood) {
		check(0, "the bound check has memory to run in");
		return;
	}
	memset(flood, 'x', NCFG_PROTO_MAX_LINE + 16u);

	ncfg_proto_framer_init(&framer);
	check(!ncfg_proto_framer_add(&framer, flood, NCFG_PROTO_MAX_LINE + 16u, err,
	        sizeof(err)),
	    "an unterminated flood is refused rather than absorbed");
	check(strstr(err, "without a newline") != NULL, "and says what was wrong with it");
	check(ncfg_proto_framer_next(&framer, &got, &length, err, sizeof(err)) ==
	        NCFG_PROTO_LINE_FAILED,
	    "and the connection does not carry on afterwards");
	ncfg_proto_framer_free(&framer);

	/*
	 * The boundary, which is the part a copied number gets wrong: the bound
	 * counts the newline, so a line of one byte less than it plus its
	 * terminator is accepted and a byte more is not.
	 */
	flood[NCFG_PROTO_MAX_LINE - 1u] = '\n';
	ncfg_proto_framer_init(&framer);
	check(ncfg_proto_framer_add(&framer, flood, NCFG_PROTO_MAX_LINE, err, sizeof(err)) &&
	        ncfg_proto_framer_next(&framer, &got, &length, err, sizeof(err)) ==
	        NCFG_PROTO_LINE && length == NCFG_PROTO_MAX_LINE - 1u,
	    "a line of exactly the bound, terminator included, is taken");
	ncfg_proto_framer_free(&framer);

	flood[NCFG_PROTO_MAX_LINE - 1u] = 'x';
	flood[NCFG_PROTO_MAX_LINE] = '\n';
	ncfg_proto_framer_init(&framer);
	check(ncfg_proto_framer_add(&framer, flood, NCFG_PROTO_MAX_LINE + 1u, err, sizeof(err)),
	    "one byte longer arrives");
	check(ncfg_proto_framer_next(&framer, &got, &length, err, sizeof(err)) ==
	        NCFG_PROTO_LINE_FAILED,
	    "and is refused when it is framed");
	ncfg_proto_framer_free(&framer);
	free(flood);
}

static void the_framer_reads_lines_however_they_arrive(void)
{
	ncfg_proto_framer_t framer;
	char err[NCFG_ERROR_MAX];
	const char *line = NULL;
	size_t length = 0;
	static const char both[] = "{\"request\":\"status\"}\n{\"request\":\"plan\"}\n";
	ncfg_proto_message_t message;
	size_t at;

	/* Two messages in one read, which is what a pipelining client produces
	 * -- and throwing the second away would lose a request somebody is
	 * waiting for. */
	ncfg_proto_framer_init(&framer);
	check(ncfg_proto_framer_add(&framer, both, sizeof(both) - 1u, err, sizeof(err)),
	    "two messages arrive in one read");
	check(ncfg_proto_framer_next(&framer, &line, &length, err, sizeof(err)) ==
	        NCFG_PROTO_LINE &&
	        ncfg_proto_request_read(line, length, &message, err, sizeof(err)) &&
	        message.u.request.kind == NCFG_PROTO_REQ_STATUS,
	    "and the first is a status");
	ncfg_proto_message_free(&message);
	check(ncfg_proto_framer_next(&framer, &line, &length, err, sizeof(err)) ==
	        NCFG_PROTO_LINE &&
	        ncfg_proto_request_read(line, length, &message, err, sizeof(err)) &&
	        message.u.request.kind == NCFG_PROTO_REQ_PLAN,
	    "the second a plan, still intact after the first was handed back");
	ncfg_proto_message_free(&message);
	check(ncfg_proto_framer_next(&framer, &line, &length, err, sizeof(err)) ==
	        NCFG_PROTO_LINE_INCOMPLETE,
	    "and there is no third");
	/* A clean end of stream is a client disconnecting and is not an error
	 * (section 10, item 4): a client that reported one as a failure would
	 * tell an operator the daemon had gone wrong when it had gone away. */
	check(ncfg_proto_framer_finish(&framer, err, sizeof(err)),
	    "a clean end of stream is a disconnect, not a failure");
	ncfg_proto_framer_free(&framer);

	/* And a line delivered one byte at a time, which is what a slow socket
	 * or a deliberate client does. */
	ncfg_proto_framer_init(&framer);
	for (at = 0; at < sizeof(both) - 1u; at++) {
		if (!ncfg_proto_framer_add(&framer, &both[at], 1u, err, sizeof(err))) {
			break;
		}
	}
	check(at == sizeof(both) - 1u, "a message split byte by byte arrives");
	check(ncfg_proto_framer_next(&framer, &line, &length, err, sizeof(err)) ==
	        NCFG_PROTO_LINE && length == 20u,
	    "and frames as one line all the same");
	ncfg_proto_framer_free(&framer);
}

static void a_truncated_message_is_refused_rather_than_half_read(void)
{
	ncfg_proto_framer_t framer;
	char err[NCFG_ERROR_MAX];
	ncfg_proto_message_t message;
	static const char cut[] = "{\"request\":\"wifi_connect\",\"interface\":\"wlan0\"";

	/*
	 * The stream ended in the middle of a message. Parsing what arrived
	 * would be reading half a request as a whole one -- a request nobody
	 * sent, on the surface that reaches a process holding CAP_NET_ADMIN.
	 */
	ncfg_proto_framer_init(&framer);
	check(ncfg_proto_framer_add(&framer, cut, sizeof(cut) - 1u, err, sizeof(err)),
	    "a message that stops halfway arrives");
	check(ncfg_proto_framer_finish(&framer, err, sizeof(err)) == 0,
	    "and the end of stream is refused rather than taken as a disconnect");
	ncfg_proto_framer_free(&framer);

	/* And the decoder refuses the same bytes, rather than returning the
	 * members it managed to read. */
	check(!ncfg_proto_request_read(cut, sizeof(cut) - 1u, &message, err, sizeof(err)),
	    "a truncated line does not decode");
	check(ncfg_proto_message_doc(&message) == NULL,
	    "and hands back nothing rather than the part it understood");
	ncfg_proto_message_free(&message);
}

/* --------------------------------------------------------- reading answers */

static void the_three_name_cases_survive_decoding(void)
{
	ncfg_proto_message_t message;
	char err[NCFG_ERROR_MAX];
	static const char line[] =
	    "{\"response\":\"wifi_scan\",\"interface\":\"wlan0\",\"access_points\":["
	    "{\"bssid\":\"00:11:22:33:44:55\",\"frequency\":2412,\"signal\":-40,"
	    "\"secured\":true,\"owe\":false,\"enterprise\":false,\"ssid\":\"686f6d65\","
	    "\"name\":\"home\",\"configured\":\"home\"},"
	    "{\"bssid\":\"00:11:22:33:44:66\",\"frequency\":5180,\"signal\":-58,"
	    "\"secured\":false,\"owe\":false,\"enterprise\":false,\"ssid\":\"\",\"name\":\"\"},"
	    "{\"bssid\":\"00:11:22:33:44:77\",\"frequency\":2437,\"signal\":-71,"
	    "\"secured\":true,\"owe\":false,\"enterprise\":true,\"ssid\":\"ff00ff\"}]}";
	const ncfg_proto_scan_entry_t *points;

	check(ncfg_proto_response_read(line, sizeof(line) - 1u, &message, err, sizeof(err)),
	    "a scan with all three name cases decodes");
	if (failures) {
		detail("refused with", err);
	}
	points = message.u.response.u.wifi_scan.access_points;
	check(message.u.response.u.wifi_scan.access_point_count == 3u, "with three entries");
	/*
	 * Section 8's three cases, which an implementation that drew two of them
	 * alike would merge into one row. A present and empty name is a hidden
	 * network; an absent one is an SSID that is not valid UTF-8 and renders
	 * as `hex:<ssid>`.
	 */
	check(ncfg_proto_str_present(points[0].name) && points[0].name.length == 4u,
	    "a text name is present and non-empty");
	check(ncfg_proto_str_present(points[1].name) && points[1].name.length == 0,
	    "a hidden network's name is present and empty");
	check(!ncfg_proto_str_present(points[2].name),
	    "and an SSID that is not text has no name at all");
	check(points[2].ssid.length == 6u && !ncfg_proto_str_present(points[2].configured),
	    "with the hex identity still there and nothing configured for it");
	/* 0013's boundary, made visible rather than discovered by being
	 * refused. */
	check(ncfg_proto_str_equals(points[0].configured, "home"),
	    "and the entry the configuration describes says which block");
	check(points[0].signal == -40 && points[1].frequency == 5180,
	    "a negative signal is still negative and a frequency unrounded");
	ncfg_proto_message_free(&message);
}

static void a_refusal_is_an_answer(void)
{
	ncfg_proto_message_t message;
	char err[NCFG_ERROR_MAX];
	static const char line[] =
	    "{\"response\":\"error\",\"message\":\"this needs the admin tier\"}";

	/*
	 * A refusal means the daemon replied, which is a different thing from
	 * not reaching it -- so it decodes, and the sentence is handed over
	 * unchanged. The sentence names the tier that would have been needed,
	 * and rewording it throws away the part that says what to do.
	 */
	check(ncfg_proto_response_read(line, sizeof(line) - 1u, &message, err, sizeof(err)),
	    "an error response is an answer that decodes");
	check(message.u.response.kind == NCFG_PROTO_RESP_ERROR &&
	        ncfg_proto_str_equals(message.u.response.u.error.message,
	        "this needs the admin tier"),
	    "carrying the daemon's own sentence, unreworded");
	ncfg_proto_message_free(&message);
}

static void an_event_reads_the_same_wrapped_and_bare(void)
{
	ncfg_proto_message_t wrapped;
	ncfg_proto_message_t bare;
	char err[NCFG_ERROR_MAX];
	static const char in_stream[] = "{\"response\":\"event\",\"event\":\"confirm_armed\","
	    "\"seconds\":90}";
	static const char on_its_own[] = "{\"event\":\"confirm_armed\",\"seconds\":90}";

	/* The third kind of line, which the C client found on its first run: a
	 * monitor stream carries an event inside the response wrapper and the
	 * payload is its own pinned shape, so a client that knew only the two
	 * would read a stream and recognise nothing. */
	check(ncfg_proto_response_read(in_stream, sizeof(in_stream) - 1u, &wrapped, err,
	        sizeof(err)) &&
	        wrapped.kind == NCFG_PROTO_MESSAGE_RESPONSE &&
	        wrapped.u.response.kind == NCFG_PROTO_RESP_EVENT,
	    "an event inside a response wrapper decodes");
	check(ncfg_proto_response_read(on_its_own, sizeof(on_its_own) - 1u, &bare, err,
	        sizeof(err)) && bare.kind == NCFG_PROTO_MESSAGE_EVENT,
	    "and the same payload on its own decodes as an event");
	check(wrapped.u.response.u.event.kind == bare.u.event.kind &&
	        wrapped.u.response.u.event.seconds == bare.u.event.seconds &&
	        bare.u.event.seconds == 90,
	    "reading as the same thing either way");
	ncfg_proto_message_free(&wrapped);
	ncfg_proto_message_free(&bare);
}

static void garbage_is_an_error_and_not_a_crash(void)
{
	static const char *const junk[] = {
		"", "{", "]", "null", "[]", "\"status\"", "{}", "\0", "{\"request\":1}",
		"{\"request\":\"format_the_disk\"}", "{\"request\":\"wifi_scan\"}",
		"{\"request\":\"radio_set\",\"interface\":\"wlan0\"}",
		"{\"request\":\"apply\",\"confirm\":\"soon\"}",
		"{\"request\":\"apply\",\"allow_disruption\":\"eth0\"}",
		"{\"request\":\"explain\",\"subject\":\"eth0\"}",
		"{\"request\":\"explain\",\"subject\":{\"subject\":\"weather\"}}",
		"{\"response\":\"radios\"}",
		"{\"response\":\"radios\",\"radios\":[{\"interface\":\"wlan0\"}]}",
		"{\"response\":\"hello\",\"protocol\":{\"major\":1}}",
		"{\"event\":\"confirm_armed\"}",
		"{\"event\":\"confirm_armed\",\"seconds\":1e9}",
		"{\"nothing\":true}",
		/* A repeated key: the reader does not merge duplicates, so the
		 * second belongs to nobody and the envelope check reports it --
		 * which is the answer that cannot be got wrong, since the two
		 * halves of a conversation might otherwise disagree about which
		 * value won. */
		"{\"request\":\"status\",\"request\":\"plan\"}",
		"{\"request\":\"wifi_forget\",\"id\":\"a\",\"id\":\"b\"}",
	};
	size_t at;
	int all_refused = 1;

	/* The socket is reachable by anything that can open it, so every one of
	 * these is a refusal with a sentence rather than a crash -- and a
	 * *refusal*, because a half-understood message acted on is worse than
	 * one that was turned away. */
	for (at = 0; at < sizeof(junk) / sizeof(junk[0]); at++) {
		ncfg_proto_message_t message;
		char err[NCFG_ERROR_MAX];

		err[0] = '\0';
		if (ncfg_proto_message_read(junk[at], strlen(junk[at]), &message, err,
		        sizeof(err))) {
			all_refused = 0;
			detail("accepted", junk[at]);
		} else if (!err[0]) {
			all_refused = 0;
			detail("refused with no sentence", junk[at]);
		}
		ncfg_proto_message_free(&message);
	}
	check(all_refused, "malformed and incomplete messages are refused, each with a reason");
}

static void freeing_what_was_never_filled_in_is_nothing(void)
{
	ncfg_proto_message_t message;
	ncfg_proto_framer_t framer;

	/* 0263's third convention. A caller that declared one and never decoded
	 * into it still frees it on the error path, and that path is the one
	 * nobody runs. */
	memset(&message, 0, sizeof(message));
	ncfg_proto_message_free(&message);
	ncfg_proto_message_free(&message);
	ncfg_proto_message_free(NULL);
	memset(&framer, 0, sizeof(framer));
	ncfg_proto_framer_free(&framer);
	ncfg_proto_framer_free(NULL);
	check(1, "freeing something that was never filled in is nothing");
}

static void an_encoder_says_which_member_it_wanted(void)
{
	ncfg_proto_request_t request;
	ncfg_buf_t out;
	char err[NCFG_ERROR_MAX];

	/* A library never exits, never asserts and never prints (0263), so a
	 * caller that forgot a required member gets a sentence naming it rather
	 * than a line with a hole in it. */
	memset(&request, 0, sizeof(request));
	request.kind = NCFG_PROTO_REQ_WIFI_CONNECT;
	request.u.wifi_connect.interface = ncfg_proto_str("wlan0");
	ncfg_buf_init(&out, 0);
	check(!ncfg_proto_request_encode(&request, &out, err, sizeof(err)),
	    "a request missing a required member will not encode");
	check(strstr(err, "network") != NULL, "and the refusal names the member");
	check(ncfg_buf_text(&out)[0] == '\0',
	    "and the buffer hands out nothing, not half a request");
	ncfg_buf_free(&out);
}

int main(int argc, char **argv)
{
	/* The witness lives beside the daemon it was generated from, and this
	 * runs from `c/`. A path may be given for a caller that runs it from
	 * somewhere else. */
	const char *witness = (argc > 1) ? argv[1] : "../doc/schema/socket.json";

	the_witness_round_trips(witness);
	the_member_table_matches_the_encoder();
	a_request_refuses_a_member_it_does_not_define();
	a_known_member_sent_as_null_is_accepted();
	a_response_is_read_leniently();
	a_message_may_not_carry_a_newline();
	the_line_bound_is_enforced();
	the_framer_reads_lines_however_they_arrive();
	a_truncated_message_is_refused_rather_than_half_read();
	the_three_name_cases_survive_decoding();
	a_refusal_is_an_answer();
	an_event_reads_the_same_wrapped_and_bare();
	garbage_is_an_error_and_not_a_crash();
	freeing_what_was_never_filled_in_is_nothing();
	an_encoder_says_which_member_it_wanted();

	if (failures == 0) {
		printf("proto_test: all checks passed\n");
	} else {
		printf("proto_test: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
