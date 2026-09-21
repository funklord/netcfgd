/*
 * answer_test.c -- the request dispatcher, against a machine this file made.
 *
 * NOTHING HERE TOUCHES THE MACHINE THIS IS BUILT ON
 *   The dispatcher writes drop-ins, secrets and profiles, and it reloads a
 *   configuration directory. Every one of those paths is under a directory
 *   `mkdtemp` made; none of them has a default and `ncfg_daemon_state_init`
 *   takes all three, so a test that forgot one would not compile rather than
 *   edit the developer's `/etc/netcfgd`. No socket is bound, no supplicant is
 *   asked anything, and no executor is opened.
 *
 * WHAT IS WORTH CHECKING IN A DISPATCHER
 *   Not that one request works -- that is the case every version of this has,
 *   including the wrong ones. What separates them:
 *
 *     * **every one of the thirty-two request kinds is either answered or
 *       refused with a sentence naming it**, walked as a set rather than as
 *       the handful somebody remembered. A daemon that answers a bare `error`
 *       is the thing `daemon_main.c` refused to start over, because an
 *       operator reads it as a request that was not recognised;
 *     * the two lists that can drift -- what the table says is unported and
 *       what the switch has an arm for -- are checked against each other,
 *       since a kind in neither would be a bug reported as a refusal;
 *     * a field carrying a NUL, a field that is absent, and a field past its
 *       ceiling, each refused by name rather than taken as the part that fits.
 */
#include "../src/main/loop_internal.h"

#include "ncfg/base.h"
#include "ncfg/config.h"
#include "ncfg/daemon.h"
#include "ncfg/json_write.h"
#include "ncfg/log.h"
#include "ncfg/observed.h"
#include "ncfg/proto.h"
#include "ncfg/secrets.h"

#include "testdir.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

static int failures;
static int checks;

static void check(int condition, const char *what)
{
	checks++;
	printf("%-72s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

static void detail(const char *label, const char *text)
{
	printf("       %s: %s\n", label, text ? text : "(none)");
}

/* ------------------------------------------------------------------------ *
 * A daemon's state, over directories this file made
 * ------------------------------------------------------------------------ */

static char                base[256];
static char                config_dir[512];
static char                factory_dir[512];
static char                run_dir[512];
static ncfg_daemon_state_t state;
static ncfg_main_desk_t    desk;

static void make_dir(const char *path)
{
	(void)mkdir(path, 0700);
}

/*
 * Ask the dispatcher one request.
 *
 * The peer and the arrival are handed over because the seam takes them, and
 * the dispatcher reads neither -- the request has already been through
 * `ncfg_authz_permitted`, and an arm here consulting the peer would be the
 * second implementation of "may I" that 0092 forbids.
 */
static int ask(const ncfg_proto_request_t *request, ncfg_buf_t *out, char *err, size_t err_size)
{
	ncfg_peer_t peer;

	memset(&peer, 0, sizeof(peer));
	err[0] = '\0';
	ncfg_buf_init(out, NCFG_PROTO_MAX_LINE);
	return ncfg_main_answer(&desk, request, &peer, NCFG_ARRIVED_LOCAL, out, err, err_size);
}

/* A copy this file owns, for a document member that has to be replaced. */
static char *duplicate_text(const char *text)
{
	size_t size = strlen(text) + 1u;
	char  *copy = malloc(size);

	if (copy) {
		memcpy(copy, text, size);
	}
	return copy;
}

/* A document from the members a case cares about, the rest being the empty
 * defaults. JSON rather than the configuration language, because what is being
 * driven here is the dispatcher and not the compiler. */
static ncfg_document_t *document_of(const char *body)
{
	char             text[2048];
	char             err[NCFG_ERROR_MAX];
	ncfg_document_t *document;

	/* The body carries `networks` where a case cares about one; otherwise the
	 * empty list is appended, because the reader refuses a member stated
	 * twice and a document with none is not the same as one with an empty
	 * list. */
	(void)snprintf(text, sizeof(text),
	    "{\"schema_version\":{\"major\":1,\"minor\":1},\"generated_by\":\"answer_test\","
	    "\"globals\":{},%s%s}", body,
	    strstr(body, "\"networks\"") ? "" : ",\"networks\":[]");
	err[0] = '\0';
	document = ncfg_document_read(text, strlen(text), err, sizeof(err));
	if (!document) {
		detail("the document fixture did not read", err);
	}
	return document;
}

/* Whether what came back is the `ok` object, read by the client's decoder
 * rather than compared as text. */
static int is_ok(ncfg_buf_t *out)
{
	ncfg_proto_message_t message;
	char                 err[NCFG_ERROR_MAX];
	int                  answered;

	memset(&message, 0, sizeof(message));
	err[0] = '\0';
	if (!ncfg_proto_response_read(ncfg_buf_text(out), out->length, &message, err,
	    sizeof(err))) {
		detail("the answer did not decode", err);
		return 0;
	}
	answered = message.u.response.kind == NCFG_PROTO_RESP_OK;
	ncfg_proto_message_free(&message);
	return answered;
}

/* ------------------------------------------------------------------------ *
 * The set of kinds, walked rather than sampled
 * ------------------------------------------------------------------------ */

/*
 * Every kind is either answered or refused **by name**.
 *
 * The whole argument for starting this daemon at all rests on this: with no
 * dispatcher it would bind the control socket, let a client through and answer
 * `error` to everything, which an operator reads as a request the daemon did
 * not recognise. A refusal that names the request and says what is missing
 * cannot be read that way, and this is the check that the naming happens for
 * all thirty-two rather than for the ones somebody wrote out.
 */
static void every_request_is_answered_or_refused_by_name(void)
{
	unsigned answered = 0;
	unsigned refused = 0;
	int      kind;

	for (kind = 0; kind < NCFG_PROTO_REQ_COUNT; kind++) {
		const char *why = ncfg_main_answer_unported((ncfg_proto_request_kind_t)kind);
		const char *name = ncfg_proto_request_name((ncfg_proto_request_kind_t)kind);

		if (!name) {
			detail("a request kind with no tag", NULL);
			check(0, "every request kind has a name");
			continue;
		}
		if (!why) {
			answered++;
			continue;
		}
		refused++;
		if (strlen(why) < 20u) {
			detail("a refusal too short to say anything", name);
			check(0, "a refusal says what is missing");
		}
	}
	check(answered + refused == (unsigned)NCFG_PROTO_REQ_COUNT,
	    "every request kind has a row, and the walk was not vacuous");
	check(answered >= 10u, "a useful number of them are answered rather than refused");
	check(refused > 0u, "and the ones that are not are named rather than silently missing");
}

/*
 * The refusal an unported kind actually produces carries the request's name.
 *
 * Separate from the table above, because the table could be perfect and the
 * dispatcher could still hand back a sentence with nothing in it -- which is
 * exactly the shape that reads as "unrecognised request".
 */
static void a_refusal_names_the_request_it_refused(void)
{
	unsigned checked = 0;
	int      kind;

	for (kind = 0; kind < NCFG_PROTO_REQ_COUNT; kind++) {
		ncfg_proto_request_t request;
		ncfg_buf_t           out;
		char                 err[NCFG_ERROR_MAX];
		const char          *name;

		if (!ncfg_main_answer_unported((ncfg_proto_request_kind_t)kind)) {
			continue;
		}
		name = ncfg_proto_request_name((ncfg_proto_request_kind_t)kind);
		memset(&request, 0, sizeof(request));
		request.kind = (ncfg_proto_request_kind_t)kind;
		if (ask(&request, &out, err, sizeof(err))) {
			detail("answered a kind the table says is unported", name);
			check(0, "the table and the dispatch agree");
			ncfg_buf_free(&out);
			continue;
		}
		ncfg_buf_free(&out);
		if (!name || strstr(err, name) == NULL) {
			detail("a refusal that does not name its request", err);
			check(0, "a refusal names the request");
			continue;
		}
		if (strstr(err, "bug rather than a refusal") != NULL) {
			detail("reached the arm that should be unreachable", name);
			check(0, "the table answered before the switch did");
			continue;
		}
		checked++;
	}
	/*
	 * **A floor rather than a figure**, and it moved when `status` and `show`
	 * stopped being refused. What this guards against is the walk finding
	 * nothing -- a loop whose body never runs passes every check inside it --
	 * so it is the count that has to stay well above zero rather than the
	 * count that has to match. Nineteen kinds are answered now; the rest
	 * are what this walks.
	 */
	check(checked >= 9u, "every unported kind refuses with its own name in the sentence");
}

/*
 * And a kind the table says is answered really has an arm.
 *
 * The other direction, and the one that would rot in silence: a row moved from
 * "unported" to "answered" without an arm being written falls through the
 * switch to the sentence that says it is a bug, and the walk above skips
 * exactly that kind because the table told it to. So every answered kind is
 * asked here, with an empty request. Most refuse -- a `wifi_scan` with no
 * interface is a refusal and should be -- and what may not appear is the arm
 * that admits there is no arm.
 */
static void a_kind_the_table_answers_has_an_arm(void)
{
	unsigned checked = 0;
	int      kind;

	for (kind = 0; kind < NCFG_PROTO_REQ_COUNT; kind++) {
		ncfg_proto_request_t request;
		ncfg_buf_t           out;
		char                 err[NCFG_ERROR_MAX];

		if (ncfg_main_answer_unported((ncfg_proto_request_kind_t)kind)) {
			continue;
		}
		memset(&request, 0, sizeof(request));
		request.kind = (ncfg_proto_request_kind_t)kind;
		(void)ask(&request, &out, err, sizeof(err));
		ncfg_buf_free(&out);
		if (strstr(err, "bug rather than a refusal") != NULL) {
			detail("the table says this is answered and nothing answers it",
			    ncfg_proto_request_name((ncfg_proto_request_kind_t)kind));
			check(0, "a kind the table answers has an arm");
			continue;
		}
		checked++;
	}
	check(checked >= 10u, "every kind the table says is answered has an arm to answer it");
}

/* ------------------------------------------------------------------------ *
 * The arms that write something
 * ------------------------------------------------------------------------ */

static void a_drop_in_is_written_and_taken_away(void)
{
	ncfg_proto_request_t request;
	ncfg_buf_t           out;
	char                 err[NCFG_ERROR_MAX];
	char                 path[640];

	memset(&request, 0, sizeof(request));
	request.kind = NCFG_PROTO_REQ_CONFIG_PUT;
	request.u.put.name = ncfg_proto_str("ten-office");
	request.u.put.text = ncfg_proto_str("interface eth1 {\n\tconfig = \"dhcp\"\n}\n");
	if (!ask(&request, &out, err, sizeof(err))) {
		detail("config_put refused", err);
		check(0, "a `config_put` writes a drop-in");
	} else {
		check(is_ok(&out), "a `config_put` answers `ok`");
	}
	ncfg_buf_free(&out);
	(void)snprintf(path, sizeof(path), "%s/conf.d/ten-office.conf", config_dir);
	check(testdir_exists(path), "and the file is where a drop-in goes");

	/* The same name again is refused unless `replace`, which is the store's
	 * rule rather than this file's -- checked because a dispatcher that
	 * dropped the flag would overwrite somebody's file in silence. */
	if (ask(&request, &out, err, sizeof(err))) {
		check(0, "a second `config_put` under one name is refused");
	} else {
		check(1, "a second `config_put` under one name is refused");
	}
	ncfg_buf_free(&out);
	request.u.put.replace = 1;
	check(ask(&request, &out, err, sizeof(err)), "and taken where the request says replace");
	ncfg_buf_free(&out);

	memset(&request, 0, sizeof(request));
	request.kind = NCFG_PROTO_REQ_CONFIG_DELETE;
	request.u.name = ncfg_proto_str("ten-office");
	check(ask(&request, &out, err, sizeof(err)) && is_ok(&out),
	    "a `config_delete` takes it away and answers `ok`");
	ncfg_buf_free(&out);
	check(!testdir_exists(path), "and the file is gone");

	/* Absent is success, which is what `ncfg config rm` reporting "is not in"
	 * on the success path got wrong the other way round. */
	check(ask(&request, &out, err, sizeof(err)),
	    "and removing one that is not there is success rather than a failure");
	ncfg_buf_free(&out);
}

static void a_secret_is_stored_and_removed(void)
{
	ncfg_proto_request_t request;
	ncfg_buf_t           out;
	char                 err[NCFG_ERROR_MAX];

	memset(&request, 0, sizeof(request));
	request.kind = NCFG_PROTO_REQ_SECRET_PUT;
	request.u.secret_put.name = ncfg_proto_str("office-psk");
	request.u.secret_put.value = ncfg_proto_str("correct horse battery staple");
	if (!ask(&request, &out, err, sizeof(err))) {
		detail("secret_put refused", err);
		check(0, "a `secret_put` stores a credential");
	} else {
		check(is_ok(&out), "a `secret_put` answers `ok`");
	}
	ncfg_buf_free(&out);

	memset(&request, 0, sizeof(request));
	request.kind = NCFG_PROTO_REQ_SECRET_DELETE;
	request.u.name = ncfg_proto_str("office-psk");
	check(ask(&request, &out, err, sizeof(err)) && is_ok(&out),
	    "and a `secret_delete` takes it away");
	ncfg_buf_free(&out);
}

/*
 * A field with a NUL in it is refused rather than taken as the part before it.
 *
 * `ncfg_proto_str_t` is bytes and a length, so a request can carry one; every
 * call below it reads a C string. Taken as the prefix, `office\0anything`
 * writes the secret `office` -- a credential quietly under a name nobody
 * chose, which is the `NCFG_EXPLAIN_SUBJECT_MAX` refusal pointed at a store.
 */
static void a_field_carrying_a_nul_is_refused(void)
{
	ncfg_proto_request_t request;
	ncfg_buf_t           out;
	char                 err[NCFG_ERROR_MAX];
	static const char    bytes[] = "office\0extra";

	memset(&request, 0, sizeof(request));
	request.kind = NCFG_PROTO_REQ_SECRET_PUT;
	request.u.secret_put.name.bytes = bytes;
	request.u.secret_put.name.length = sizeof(bytes) - 1u;
	request.u.secret_put.value = ncfg_proto_str("x");
	check(!ask(&request, &out, err, sizeof(err)), "a name carrying a NUL is refused");
	check(strstr(err, "NUL") != NULL, "and the refusal says what was wrong with it");
	ncfg_buf_free(&out);

	memset(&request, 0, sizeof(request));
	request.kind = NCFG_PROTO_REQ_CONFIG_PUT;
	request.u.put.name = ncfg_proto_str("with-nul");
	request.u.put.text.bytes = bytes;
	request.u.put.text.length = sizeof(bytes) - 1u;
	check(!ask(&request, &out, err, sizeof(err)),
	    "and so is configuration text carrying one");
	ncfg_buf_free(&out);
}

static void an_absent_field_is_refused_rather_than_defaulted(void)
{
	ncfg_proto_request_t request;
	ncfg_buf_t           out;
	char                 err[NCFG_ERROR_MAX];

	memset(&request, 0, sizeof(request));
	request.kind = NCFG_PROTO_REQ_CONFIG_PUT;
	request.u.put.text = ncfg_proto_str("interface eth1 {\n}\n");
	check(!ask(&request, &out, err, sizeof(err)), "a `config_put` with no name is refused");
	check(strstr(err, "drop-in name") != NULL, "and names the field it wanted");
	ncfg_buf_free(&out);

	memset(&request, 0, sizeof(request));
	request.kind = NCFG_PROTO_REQ_WIFI_SCAN;
	check(!ask(&request, &out, err, sizeof(err)), "a `wifi_scan` with no interface is refused");
	check(strstr(err, "interface") != NULL, "and says which field");
	ncfg_buf_free(&out);
}

static void a_credential_past_its_ceiling_names_the_ceiling(void)
{
	ncfg_proto_request_t request;
	ncfg_buf_t           out;
	char                 err[NCFG_ERROR_MAX];
	char                *huge = malloc(70u * 1024u);

	if (!huge) {
		check(0, "the oversize fixture can be allocated");
		return;
	}
	memset(huge, 'x', 70u * 1024u);
	memset(&request, 0, sizeof(request));
	request.kind = NCFG_PROTO_REQ_SECRET_PUT;
	request.u.secret_put.name = ncfg_proto_str("big");
	request.u.secret_put.value.bytes = huge;
	request.u.secret_put.value.length = 70u * 1024u;
	check(!ask(&request, &out, err, sizeof(err)),
	    "a credential past its ceiling is refused rather than truncated");
	check(strstr(err, "65536") != NULL,
	    "and the refusal names the ceiling, which is what an operator acts on");
	ncfg_buf_free(&out);
	free(huge);
}

/*
 * A reload answers `ok` and tells whoever is watching, either way.
 *
 * The second half is the part that would rot silently: a client watching a
 * machine learns that the configuration did not compile only from the
 * `reloaded` event's diagnostics, and a dispatcher that answered `ok` without
 * announcing would leave a window showing a configuration that is not in
 * force.
 */
static void a_reload_answers_and_announces(void)
{
	ncfg_main_subscribers_t subscribers;
	ncfg_proto_request_t    request;
	ncfg_buf_t              out;
	char                    err[NCFG_ERROR_MAX];
	char                    seen[1024];
	char                    path[640];
	int                     ends[2];
	ssize_t                 got;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, ends) != 0) {
		check(0, "a socket pair could be made");
		return;
	}
	ncfg_main_subscribers_init(&subscribers);
	err[0] = '\0';
	if (!ncfg_main_subscribers_add(&subscribers, ends[1], err, sizeof(err))) {
		check(0, "a subscriber could be taken");
		return;
	}
	desk.subscribers = &subscribers;

	memset(&request, 0, sizeof(request));
	request.kind = NCFG_PROTO_REQ_RELOAD;
	check(ask(&request, &out, err, sizeof(err)) && is_ok(&out),
	    "a `reload` over a directory that compiles answers `ok`");
	ncfg_buf_free(&out);
	got = recv(ends[0], seen, sizeof(seen) - 1u, MSG_DONTWAIT);
	seen[got > 0 ? (size_t)got : 0u] = '\0';
	check(got > 0 && strstr(seen, "\"event\":\"reloaded\"") != NULL,
	    "and whoever is watching is told it happened");
	check(strstr(seen, "\"ok\":true") != NULL, "with the fact that it compiled");

	/* And a directory that does not compile: the refusal is an answer, and
	 * the event carries the diagnostics. */
	(void)snprintf(path, sizeof(path), "%s/conf.d/broken.conf", config_dir);
	check(testdir_write(path, "interface {{{\n", 14u), "a broken drop-in is written");
	check(!ask(&request, &out, err, sizeof(err)),
	    "a `reload` over a directory that does not compile refuses");
	ncfg_buf_free(&out);
	got = recv(ends[0], seen, sizeof(seen) - 1u, MSG_DONTWAIT);
	seen[got > 0 ? (size_t)got : 0u] = '\0';
	check(got > 0 && strstr(seen, "\"ok\":false") != NULL,
	    "and the watcher is told that too, rather than hearing nothing");
	check(strstr(seen, "diagnostics") != NULL,
	    "with the diagnostics, which is the only place a client learns why");
	(void)unlink(path);

	desk.subscribers = NULL;
	ncfg_main_subscribers_close(&subscribers);
	(void)close(ends[0]);
}

/*
 * Handing a radio back is answered; taking one on is refused by name.
 *
 * `ncfg_wifi_set_radio` requires a way to apply when activating and refuses
 * where there is none, rather than skipping it -- a caller with no way to
 * apply would reproduce the defect the synchronous step closed, silently: a
 * correct file written and the operator told the radio is netcfgd's, followed
 * by "cannot reach the supplicant" from the very next scan. This build has no
 * apply seam to give it, because `backend.start` is one of the ops its
 * executor refuses.
 */
static void taking_a_radio_on_is_refused_rather_than_half_done(void)
{
	ncfg_proto_request_t request;
	ncfg_buf_t           out;
	char                 err[NCFG_ERROR_MAX];

	static const char machine[] =
	    "{\"links\":[{\"name\":\"wlan0\",\"index\":3,\"mtu\":1500,\"up\":true,"
	    "\"carrier\":true,\"wireless\":true,\"ownership\":\"unknown\"}]}";

	/* The kernel has to call it a radio, or the refusal is about the name
	 * rather than about the apply -- which would leave this check passing
	 * against an answer that says nothing about the seam. */
	state.observed = ncfg_observed_read(machine, strlen(machine), err, sizeof(err));
	if (!state.observed) {
		detail("the radio fixture did not read", err);
		check(0, "the radio fixture reads");
		return;
	}
	memset(&request, 0, sizeof(request));
	request.kind = NCFG_PROTO_REQ_RADIO_SET;
	request.u.radio_set.interface = ncfg_proto_str("wlan0");
	request.u.radio_set.activate = 1;
	check(!ask(&request, &out, err, sizeof(err)),
	    "activating a radio with no way to apply is refused");
	check(strstr(err, "no way to start") != NULL,
	    "and the refusal is about the missing apply rather than about the name");
	detail("what it says", err);
	ncfg_buf_free(&out);
}

/*
 * The two responses that are a model and an envelope, byte for byte.
 *
 * **Compared against `doc/schema/socket.json` rather than decoded**, which is
 * `daemon_wifi_test.c`'s rule and the reason the witness exists: a decode
 * accepts a member in the wrong order or an omitted default, and what is being
 * asserted is that a client built against the Rust reads this. The two lines
 * here are the witness' own, copied.
 *
 * The flattening is the part worth pinning. `Response::Status(Box<Observed>)`
 * puts the observation's members in the envelope rather than under a key, so
 * an encoder that wrapped them -- the obvious thing to write -- produces
 * something every existing client ignores.
 */
static void the_status_and_the_document_are_the_witness_shape(void)
{
	static const char *const status_witness =
	    "{\"response\":\"status\",\"links\":[],\"addresses\":[],\"routes\":[],"
	    "\"backends\":[],\"dns\":[],\"rules\":[],\"bridge_vlans\":[],\"delegations\":[],"
	    "\"reports\":[],\"qdisc_applied\":[],\"ingress_applied\":[],"
	    "\"privacy_applied\":[],\"backend_restarts\":[],\"accept_ra_applied\":[],"
	    "\"forwarding_applied\":[],\"nat\":[],\"nat_conflicts\":[],\"hook_state\":[],"
	    "\"address_proto_supported\":false}";
	static const char *const document_witness =
	    "{\"response\":\"document\",\"schema_version\":{\"major\":1,\"minor\":1},"
	    "\"globals\":{\"dns\":{\"mode\":\"none\",\"servers\":[],\"search\":[],"
	    "\"domains\":[],\"options\":[]},\"on_drift_default\":\"reconcile\","
	    "\"confirm_default\":null,\"networking\":\"on\",\"hostname_policy\":\"none\","
	    "\"control\":{\"observe\":\"root\",\"wifi\":\"root\",\"admin\":\"root\"},"
	    "\"remote\":{\"observe\":false,\"wifi\":false,\"admin\":false,"
	    "\"agent\":\"root\"}},\"devices\":[],\"interfaces\":[],\"networks\":[],"
	    "\"rules\":[],\"access_points\":[]}";
	static char          said[] = "netcfgd.conf:3: `mtu` wants a number";
	ncfg_observed_t     *kept_observed = state.observed;
	ncfg_document_t     *kept_desired = state.desired;
	char                *kept_diagnostics = state.diagnostics;
	ncfg_proto_request_t request;
	ncfg_buf_t           out;
	char                 err[NCFG_ERROR_MAX];

	err[0] = '\0';
	state.observed = ncfg_observed_read("{}", 2u, err, sizeof(err));
	state.desired = ncfg_document_new(err, sizeof(err));
	state.diagnostics = NULL;
	if (!state.observed || !state.desired) {
		detail("the empty fixtures did not build", err);
		check(0, "an empty observation and an empty document");
	} else {
		memset(&request, 0, sizeof(request));
		request.kind = NCFG_PROTO_REQ_STATUS;
		check(ask(&request, &out, err, sizeof(err)), "`status` is answered");
		check(strcmp(ncfg_buf_text(&out), status_witness) == 0,
		    "  and it is the witness' spelling, the observation flattened into the "
		    "envelope");
		if (strcmp(ncfg_buf_text(&out), status_witness) != 0) {
			detail("what was written", ncfg_buf_text(&out));
		}
		ncfg_buf_free(&out);

		memset(&request, 0, sizeof(request));
		request.kind = NCFG_PROTO_REQ_SHOW;
		check(ask(&request, &out, err, sizeof(err)), "`show` is answered");
		check(strcmp(ncfg_buf_text(&out), document_witness) == 0,
		    "  and it is the witness' spelling too, member for member");
		if (strcmp(ncfg_buf_text(&out), document_witness) != 0) {
			detail("what was written", ncfg_buf_text(&out));
		}
		ncfg_buf_free(&out);
	}

	/*
	 * And what each refuses, which is the judgement rather than the shape. An
	 * observation with no links is a machine with nothing on it and a daemon
	 * that has not looked is not, so the second may not be answered as the
	 * first -- and the caller asking to see a configuration that did not
	 * compile wants the reason rather than a sentence about there being none.
	 */
	ncfg_observed_free(state.observed);
	ncfg_document_free(state.desired);
	state.observed = NULL;
	state.desired = NULL;
	/* This file's own storage, never freed by the state: `state.diagnostics`
	 * is owned, and the pointer is put back below before anything frees it. */
	state.diagnostics = said;
	memset(&request, 0, sizeof(request));
	request.kind = NCFG_PROTO_REQ_STATUS;
	check(!ask(&request, &out, err, sizeof(err)) && strstr(err, "not managed to observe") &&
	        strstr(err, "nothing on it") != NULL,
	    "a daemon that has not observed the machine says so rather than reporting an "
	    "empty one");
	ncfg_buf_free(&out);
	memset(&request, 0, sizeof(request));
	request.kind = NCFG_PROTO_REQ_SHOW;
	check(!ask(&request, &out, err, sizeof(err)) && strstr(err, "wants a number") != NULL,
	    "and one whose configuration does not compile answers with the reason it did not");
	ncfg_buf_free(&out);

	state.observed = kept_observed;
	state.desired = kept_desired;
	state.diagnostics = kept_diagnostics;
}

/*
 * The plan a client is served, and the warnings that are only in this one.
 *
 * The shape is the witness'. The contention warning is the part that was
 * missing from every client but `ncfg plan`: the daemon works contention out
 * for its own log and the plan it serves said nothing about it, so a GUI
 * showing a radio had no way to say why its scans fail every other attempt.
 *
 * `NetworkManager`'s state file is written here rather than the machine's
 * being read, and the desk is pointed at this test's own root -- the daemon
 * reads `/run`, and a test that did would be reading whatever the workstation
 * it was built on happens to be running.
 */
static void the_served_plan_says_who_else_manages_an_interface(void)
{
	static const char *const witness =
	    "{\"response\":\"plan\",\"actions\":[],\"warnings\":[],\"refusals\":[],"
	    "\"stranded\":[]}";
	static const char *const machine =
	    "{\"links\":[{\"name\":\"wlan0\",\"index\":3,\"mtu\":1500,\"up\":true,"
	    "\"carrier\":true,\"wireless\":true,\"ownership\":\"unknown\"}]}";
	ncfg_observed_t     *kept_observed = state.observed;
	ncfg_document_t     *kept_desired = state.desired;
	char                *kept_diagnostics = state.diagnostics;
	ncfg_proto_request_t request;
	ncfg_buf_t           out;
	char                 err[NCFG_ERROR_MAX];
	char                 path[640];
	static char          proc_root[640];

	err[0] = '\0';
	state.observed = ncfg_observed_read("{}", 2u, err, sizeof(err));
	state.desired = ncfg_document_new(err, sizeof(err));
	state.diagnostics = NULL;
	if (!state.observed || !state.desired) {
		detail("the empty fixtures did not build", err);
		check(0, "an empty observation and an empty document");
	} else {
		memset(&request, 0, sizeof(request));
		request.kind = NCFG_PROTO_REQ_PLAN;
		check(ask(&request, &out, err, sizeof(err)), "`plan` is answered");
		check(strcmp(ncfg_buf_text(&out), witness) == 0,
		    "  and an empty one is the witness' spelling, flattened into the envelope");
		if (strcmp(ncfg_buf_text(&out), witness) != 0) {
			detail("what was written", ncfg_buf_text(&out));
		}
		ncfg_buf_free(&out);
	}
	/*
	 * **A plan that failed while it was being built is not sent.** Driven at
	 * the encoder, because the only way through the dispatcher is an
	 * allocation that fails -- and a client cannot tell a plan with no
	 * actions from a plan that ran out of memory before it had any, which is
	 * the whole reason the flag is checked rather than the count.
	 */
	if (state.observed && state.desired) {
		ncfg_plan_t *half = ncfg_plan_build(state.desired, state.observed, NULL, err,
		    sizeof(err));

		if (half) {
			half->failed = 1;
			ncfg_buf_init(&out, 0);
			check(!ncfg_daemon_plan_encode(half, &out, err, sizeof(err)) &&
			        strstr(err, "could not be built") != NULL,
			    "  and a plan that failed while it was built is refused rather than "
			    "sent as an empty one");
			ncfg_buf_free(&out);
			ncfg_plan_free(half);
		} else {
			check(0, "a plan to spoil");
		}
	}
	ncfg_observed_free(state.observed);
	ncfg_document_free(state.desired);

	/*
	 * And the same request against a machine another daemon is managing. The
	 * document claims `wlan0`, the kernel gives it index 3, and
	 * `NetworkManager` has a file saying it manages index 3.
	 */
	(void)snprintf(path, sizeof(path), "%s/NetworkManager", run_dir);
	make_dir(path);
	(void)snprintf(path, sizeof(path), "%s/NetworkManager/devices", run_dir);
	make_dir(path);
	(void)snprintf(path, sizeof(path), "%s/NetworkManager/devices/3", run_dir);
	(void)testdir_write(path, "[device]\nmanaged=true\nconnection-uuid=abc\n",
	    strlen("[device]\nmanaged=true\nconnection-uuid=abc\n"));
	/* And a `/proc` saying it is running: the check asks both, because a
	 * state file left behind by a daemon that has stopped claims nothing. */
	(void)snprintf(path, sizeof(path), "%s/proc", base);
	make_dir(path);
	(void)snprintf(path, sizeof(path), "%s/proc/100", base);
	make_dir(path);
	(void)snprintf(path, sizeof(path), "%s/proc/100/comm", base);
	(void)testdir_write(path, "NetworkManager\n", strlen("NetworkManager\n"));
	(void)snprintf(proc_root, sizeof(proc_root), "%s/proc", base);
	desk.contention.run_root = run_dir;
	desk.contention.proc_root = proc_root;
	desk.contention.run_root_is_the_machines = 0;
	err[0] = '\0';
	state.observed = ncfg_observed_read(machine, strlen(machine), err, sizeof(err));
	state.desired = document_of(
	    "\"devices\":[{\"name\":\"wlan0\",\"kind\":{\"kind\":\"physical\"}}],"
	    "\"interfaces\":[{\"name\":\"wlan0\"}]");
	if (!state.observed || !state.desired) {
		detail("the contended fixture did not build", err);
		check(0, "a contended machine reads");
	} else {
		memset(&request, 0, sizeof(request));
		request.kind = NCFG_PROTO_REQ_PLAN;
		check(ask(&request, &out, err, sizeof(err)), "a plan over a contended radio is "
		    "answered rather than refused");
		check(strstr(ncfg_buf_text(&out), "NetworkManager") != NULL,
		    "  and it names the daemon that also manages the interface");
		check(strstr(ncfg_buf_text(&out), "\"interface\":\"wlan0\"") != NULL,
		    "  against the interface it is about, so a client can filter by the one it "
		    "is showing");
		if (failures) {
			detail("what was written", ncfg_buf_text(&out));
		}
		ncfg_buf_free(&out);
	}
	ncfg_observed_free(state.observed);
	ncfg_document_free(state.desired);
	desk.contention.run_root = NULL;

	/* And what it answers with no configuration at all, which is the reason
	 * the configuration did not compile rather than a plan for the last one
	 * that did. */
	state.observed = NULL;
	state.desired = NULL;
	state.diagnostics = NULL;
	memset(&request, 0, sizeof(request));
	request.kind = NCFG_PROTO_REQ_PLAN;
	check(!ask(&request, &out, err, sizeof(err)) && strstr(err, "no configuration") != NULL,
	    "a daemon with no compiled configuration says so rather than planning against "
	    "nothing");
	ncfg_buf_free(&out);

	state.observed = kept_observed;
	state.desired = kept_desired;
	state.diagnostics = kept_diagnostics;
}

/*
 * The two lists whose producers were already here.
 *
 * `ncfg_secret_list` and `ncfg_profile_list` are `secrets.h`'s and
 * `config.h`'s, tested where they live; what was missing was the envelope, so
 * what is checked here is the envelope -- member for member, in the spelling
 * `doc/schema/socket.json` uses, because a decode would accept a member in the
 * wrong order or an omitted default and the point is that a client built
 * against the Rust reads this.
 *
 * **The two omissions are the subject.** `used_by` is absent rather than empty
 * for a credential nothing refers to, and `chosen` is absent where no profile
 * is selected: in both cases an empty value would be a claim -- "nothing wants
 * this" and "a profile called nothing" -- where the truth is "there is nothing
 * to say".
 */
static void the_two_lists_are_the_envelope_the_witness_spells(void)
{
	ncfg_observed_t     *kept_observed = state.observed;
	ncfg_document_t     *kept_desired = state.desired;
	ncfg_proto_request_t request;
	ncfg_buf_t           out;
	char                 err[NCFG_ERROR_MAX];
	char                 path[700];

	/* Two stored credentials, one of which nothing refers to, and one
	 * referenced name with no file -- `secrets.h` says the interesting faults
	 * are those two ways round. */
	err[0] = '\0';
	if (!ncfg_secret_store_put(config_dir, "cafe", "hunter2", 1, NULL, err, sizeof(err)) ||
	    !ncfg_secret_store_put(config_dir, "old-vpn", "hunter2", 1, NULL, err, sizeof(err))) {
		detail("the store fixture did not write", err);
		check(0, "a credential store to list");
		return;
	}
	state.desired = document_of("\"devices\":[],\"interfaces\":[],\"networks\":["
	    "{\"id\":\"Cafe\",\"security\":{\"type\":\"psk\","
	    "\"passphrase\":{\"provider\":\"file\",\"name\":\"cafe\"}}},"
	    "{\"id\":\"Campus\",\"security\":{\"type\":\"psk\","
	    "\"passphrase\":{\"provider\":\"file\",\"name\":\"campus\"}}}]");
	if (!state.desired) {
		check(0, "a document naming two networks");
		state.desired = kept_desired;
		return;
	}
	memset(&request, 0, sizeof(request));
	request.kind = NCFG_PROTO_REQ_SECRET_LIST;
	check(ask(&request, &out, err, sizeof(err)), "`secret list` is answered");
	check(strcmp(ncfg_buf_text(&out),
	    "{\"response\":\"secrets\",\"secrets\":["
	    "{\"name\":\"cafe\",\"stored\":true,\"used_by\":[\"network Cafe\"]},"
	    "{\"name\":\"campus\",\"stored\":false,\"used_by\":[\"network Campus\"]},"
	    "{\"name\":\"old-vpn\",\"stored\":true}]}") == 0,
	    "  in the witness' spelling, with `used_by` absent where nothing refers to it");
	if (failures) {
		detail("what was written", ncfg_buf_text(&out));
	}
	ncfg_buf_free(&out);
	ncfg_document_free(state.desired);
	state.desired = NULL;

	/* And the profiles: one shipped, one the operator's, and the one in force
	 * taken from the compiled document rather than from the directory. */
	(void)snprintf(path, sizeof(path), "%s/profile", factory_dir);
	make_dir(path);
	(void)snprintf(path, sizeof(path), "%s/profile/offline", factory_dir);
	make_dir(path);
	(void)snprintf(path, sizeof(path), "%s/profile/offline/10-offline.conf", factory_dir);
	(void)testdir_write(path, "global { }\n", strlen("global { }\n"));
	(void)snprintf(path, sizeof(path), "%s/profile", config_dir);
	make_dir(path);
	(void)snprintf(path, sizeof(path), "%s/profile/office", config_dir);
	make_dir(path);
	(void)snprintf(path, sizeof(path), "%s/profile/office/10-office.conf", config_dir);
	(void)testdir_write(path, "global { }\n", strlen("global { }\n"));

	memset(&request, 0, sizeof(request));
	request.kind = NCFG_PROTO_REQ_PROFILE_LIST;
	check(ask(&request, &out, err, sizeof(err)),
	    "`profile list` is answered with no profile chosen");
	check(strstr(ncfg_buf_text(&out), "\"chosen\"") == NULL,
	    "  and `chosen` is absent rather than empty, which is what none means");
	if (failures) {
		detail("what was written", ncfg_buf_text(&out));
	}
	ncfg_buf_free(&out);

	state.desired = document_of("\"devices\":[],\"interfaces\":[],\"networks\":[]");
	if (state.desired) {
		free(state.desired->globals.profile);
		state.desired->globals.profile = duplicate_text("office");
	}
	memset(&request, 0, sizeof(request));
	request.kind = NCFG_PROTO_REQ_PROFILE_LIST;
	check(ask(&request, &out, err, sizeof(err)), "and answered with one chosen");
	/*
	 * The members and their spelling are the witness'; the *order of the
	 * array* is `ncfg_profile_list`'s, which puts the operator's first so
	 * that a name in both layers reads as theirs. The witness line lists them
	 * the other way round, and that is its fixture rather than a promise --
	 * pinning a sample's array order here would make this red the first time
	 * somebody added a profile to it.
	 */
	check(strcmp(ncfg_buf_text(&out),
	    "{\"response\":\"profiles\",\"profiles\":["
	    "{\"name\":\"office\",\"shipped\":false},"
	    "{\"name\":\"offline\",\"shipped\":true}],\"chosen\":\"office\"}") == 0,
	    "  in the witness' spelling, with the profile the document names");
	if (failures) {
		detail("what was written", ncfg_buf_text(&out));
	}
	ncfg_buf_free(&out);
	ncfg_document_free(state.desired);

	state.observed = kept_observed;
	state.desired = kept_desired;
}

static void a_dispatcher_with_nothing_behind_it_refuses(void)
{
	ncfg_proto_request_t request;
	ncfg_peer_t          peer;
	ncfg_buf_t           out;
	char                 err[NCFG_ERROR_MAX];

	memset(&request, 0, sizeof(request));
	memset(&peer, 0, sizeof(peer));
	request.kind = NCFG_PROTO_REQ_RELOAD;
	ncfg_buf_init(&out, NCFG_PROTO_MAX_LINE);
	err[0] = '\0';
	check(!ncfg_main_answer(NULL, &request, &peer, NCFG_ARRIVED_LOCAL, &out, err, sizeof(err)),
	    "a dispatcher with no state refuses rather than reading through a null");
	check(err[0] != '\0', "and says so");
	ncfg_buf_free(&out);
}

/* ------------------------------------------------------------------------ *
 * Writing a `network` block for a client that may not
 * ------------------------------------------------------------------------ */

/*
 * 0117's path, which was refused with a sentence that had stopped being true.
 *
 * The daemon's arm said "the profile writer is a seam with no implementation
 * in the C port" long after `wifi_profile.h` had landed -- so a client with no
 * permission to write the file itself, which is what that path exists for, was
 * being told netcfgd could not do something it could.
 */
static void a_network_block_is_written_for_a_client_that_may_not(void)
{
	ncfg_proto_request_t request;
	ncfg_buf_t           out;
	char                 err[NCFG_ERROR_MAX];
	char                 path[640];
	char                *written;

	memset(&request, 0, sizeof(request));
	request.kind = NCFG_PROTO_REQ_WIFI_ADD;
	/* Hex, as an SSID is everywhere in this model: 0..32 arbitrary octets and
	 * never guaranteed text. `63616665` is `cafe`, which is also what the
	 * block gets named when the request sends no `id`. */
	request.u.wifi_add.ssid.bytes = "63616665";
	request.u.wifi_add.ssid.length = 8u;
	request.u.wifi_add.passphrase.bytes = "a-passphrase-of-some-length";
	request.u.wifi_add.passphrase.length = 27u;
	err[0] = '\0';
	check(ask(&request, &out, err, sizeof(err)) && is_ok(&out),
	    "a `wifi add` over the socket is answered rather than refused");
	detail("it said", err);
	ncfg_buf_free(&out);

	/*
	 * **Written where the document is read from**, which is the whole of what
	 * the client could not do for itself. Checked on disk rather than by the
	 * reply, because an `ok` for a file nobody wrote is exactly the shape this
	 * path must not have.
	 */
	/* `wifi-<id>`, which is `ncfg_wifi_profile_drop_in`'s naming -- and the
	 * loader's own `conf.d`, so a fixture cannot look where nothing was
	 * written. */
	(void)snprintf(path, sizeof(path), "%s/conf.d/wifi-cafe.conf", config_dir);
	written = testdir_read(path, NULL);
	check(written != NULL, "  and the `network` block is on disk where the document reads");
	/* And the credential is not in it: the block carries an `@secret:`
	 * reference and the passphrase went to the store, which is what keeps a
	 * document free of secret material whichever caller asked. */
	check(written && strstr(written, "a-passphrase-of-some-length") == NULL,
	    "  carrying no passphrase, only a reference to one");
	free(written);
}

static void a_network_block_is_taken_away_again(void)
{
	ncfg_proto_request_t request;
	ncfg_buf_t           out;
	char                 err[NCFG_ERROR_MAX];
	char                 path[640];

	/* The document has to hold it before it can be forgotten, which is a
	 * reload away: the arm refuses a network the document does not have. */
	memset(&request, 0, sizeof(request));
	request.kind = NCFG_PROTO_REQ_RELOAD;
	err[0] = '\0';
	(void)ask(&request, &out, err, sizeof(err));
	ncfg_buf_free(&out);

	memset(&request, 0, sizeof(request));
	request.kind = NCFG_PROTO_REQ_WIFI_FORGET;
	request.u.id.bytes = "cafe";
	request.u.id.length = 4u;
	err[0] = '\0';
	check(ask(&request, &out, err, sizeof(err)) && is_ok(&out),
	    "a `wifi forget` over the socket is answered rather than refused");
	detail("it said", err);
	ncfg_buf_free(&out);
	/* `wifi-<id>`, which is `ncfg_wifi_profile_drop_in`'s naming -- and the
	 * loader's own `conf.d`, so a fixture cannot look where nothing was
	 * written. */
	(void)snprintf(path, sizeof(path), "%s/conf.d/wifi-cafe.conf", config_dir);
	check(!testdir_exists(path), "  and the block is gone from where the document reads");
}

static void writing_is_refused_where_this_daemon_was_told_nowhere(void)
{
	ncfg_proto_request_t request;
	ncfg_buf_t           out;
	char                 err[NCFG_ERROR_MAX];
	const char          *kept = desk.config_dir;

	/*
	 * **No default, which is `ncfg_wifi_where_t`'s rule one field along.** A
	 * daemon pointed at a scratch tree must not fall back to the machine's own
	 * configuration directory, so being told nowhere is a refusal by name
	 * rather than a write somewhere nobody asked for.
	 */
	desk.config_dir = NULL;
	memset(&request, 0, sizeof(request));
	request.kind = NCFG_PROTO_REQ_WIFI_ADD;
	request.u.wifi_add.ssid.bytes = "63616665";
	request.u.wifi_add.ssid.length = 8u;
	err[0] = '\0';
	check(!ask(&request, &out, err, sizeof(err)) &&
	    strstr(err, "where configuration is written") != NULL,
	    "a daemon told nowhere to write refuses by name rather than choosing");
	ncfg_buf_free(&out);
	desk.config_dir = kept;
}

int main(void)
{
	const char *made;
	char        err[NCFG_ERROR_MAX];

	ncfg_log_accept(NCFG_LOG_CRITICAL);

	made = testdir_make("answer");
	(void)snprintf(base, sizeof(base), "%s", made);
	(void)snprintf(config_dir, sizeof(config_dir), "%s/etc", base);
	(void)snprintf(factory_dir, sizeof(factory_dir), "%s/factory", base);
	(void)snprintf(run_dir, sizeof(run_dir), "%s/run", base);
	make_dir(config_dir);
	make_dir(factory_dir);
	make_dir(run_dir);
	{
		char conf_d[640];

		(void)snprintf(conf_d, sizeof(conf_d), "%s/conf.d", config_dir);
		make_dir(conf_d);
	}
	printf("== answer_test in %s\n", base);

	err[0] = '\0';
	if (!ncfg_daemon_state_init(&state, factory_dir, config_dir, run_dir, err, sizeof(err))) {
		printf("could not hold a daemon state: %s\n", err);
		testdir_remove(made);
		return 1;
	}
	memset(&desk, 0, sizeof(desk));
	desk.state = &state;
	/* Three directories that do not exist, on purpose: a wifi request must
	 * reach a refusal about a control socket rather than the machine's own
	 * supplicant, and none of these has a default for exactly that reason. */
	desk.where.ctrl_dir = base;
	desk.where.class_net = base;
	desk.where.run_dir = run_dir;
	desk.secrets_dir = config_dir;
	desk.certs_dir = run_dir;
	desk.config_dir = config_dir;
	desk.factory_dir = factory_dir;

	every_request_is_answered_or_refused_by_name();
	a_refusal_names_the_request_it_refused();
	a_kind_the_table_answers_has_an_arm();
	a_drop_in_is_written_and_taken_away();
	a_secret_is_stored_and_removed();
	a_network_block_is_written_for_a_client_that_may_not();
	a_network_block_is_taken_away_again();
	writing_is_refused_where_this_daemon_was_told_nowhere();
	a_field_carrying_a_nul_is_refused();
	an_absent_field_is_refused_rather_than_defaulted();
	a_credential_past_its_ceiling_names_the_ceiling();
	a_reload_answers_and_announces();
	taking_a_radio_on_is_refused_rather_than_half_done();
	the_status_and_the_document_are_the_witness_shape();
	the_served_plan_says_who_else_manages_an_interface();
	the_two_lists_are_the_envelope_the_witness_spells();
	a_dispatcher_with_nothing_behind_it_refuses();

	ncfg_daemon_state_free(&state);
	testdir_remove(made);

	printf("answer_test: %d check(s)\n", checks);
	if (failures == 0) {
		printf("answer_test: all checks passed\n");
	} else {
		printf("answer_test: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
