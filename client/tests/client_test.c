/*
 * client_test.c -- the reader and the connection, checked against real bytes.
 *
 * THE FIXTURE IS NOT A FIXTURE
 *   Every line of docs/schema/socket.json is fed to the reader. That file is
 *   the daemon's own frozen witness -- `make schema-bless` moves it and a
 *   change to it is a change somebody reviews -- so this is not a copy of what
 *   netcfgd sends, it is what netcfgd sends. A fixture written by hand to match
 *   would agree with itself and prove nothing, which is the mistake the sibling
 *   project records having made in its own wire tests.
 *
 *   It also means this test goes red when the protocol changes, which is the
 *   point: a second implementation of a pinned surface should find out at build
 *   time, not on somebody's laptop.
 *
 * THE CONNECTION IS A REAL SOCKET
 *   A fake daemon on a real AF_UNIX socket, answering in pieces chosen to be
 *   awkward: a reply split across two writes, and two replies in one. Both are
 *   things a real daemon does and both are where a hand-written line reader
 *   goes wrong.
 */
#include "../ncfg_client.h"
#include "../ncfg_json.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static int failures;

static void ok(const char *what, int condition, const char *detail)
{
	if (condition) {
		printf("ok   %s\n", what);
		return;
	}
	printf("FAIL %s\n", what);
	if (detail && *detail) {
		printf("       %s\n", detail);
	}
	failures++;
}

static void equals(const char *what, const char *actual, const char *expected)
{
	if (actual && strcmp(actual, expected) == 0) {
		printf("ok   %s\n", what);
		return;
	}
	printf("FAIL %s\n", what);
	printf("       expected: %s\n", expected);
	printf("       actual:   %s\n", actual ? actual : "(null)");
	failures++;
}

/* ------------------------------------------------------------------ reader */

static void reader_accepts_the_witness(const char *path)
{
	FILE *file = fopen(path, "r");
	if (!file) {
		printf("FAIL the witness at %s can be read\n", path);
		failures++;
		return;
	}

	char line[65536];
	unsigned parsed = 0;
	unsigned tagged = 0;
	unsigned refused = 0;
	char first_refusal[NCFG_ERROR_MAX] = "";

	while (fgets(line, sizeof(line), file)) {
		size_t length = strlen(line);
		while (length && (line[length - 1] == '\n' || line[length - 1] == '\r')) {
			length--;
		}
		if (!length || line[0] == '#') {
			continue; /* the witness carries comments for its readers */
		}

		char err[NCFG_ERROR_MAX];
		ncfg_json_doc_t *doc = ncfg_json_parse(line, length, err, sizeof(err));
		if (!doc) {
			if (!refused) {
				/* Both halves are bounded, and the message's bound is
				 * what leaves room for the line: err is allowed to
				 * fill the whole buffer on its own, and then the
				 * ": " that says which line it was about is what
				 * gets cut. */
				snprintf(first_refusal, sizeof(first_refusal), "%.320s: %.120s",
					 err, line);
			}
			refused++;
			continue;
		}
		parsed++;

		/* Three kinds, and knowing which is the first thing any caller
		 * does. The third was a surprise: the witness pins `event`
		 * payloads on their own as well as wrapped, because a monitor
		 * stream carries them inside `{"response":"event",...}` and the
		 * payload is its own frozen shape. A client that only knew the
		 * two would read a stream and find nothing it recognised. */
		uint32_t root = ncfg_json_root(doc);
		if (ncfg_json_member(doc, root, "request") != NCFG_JSON_NONE ||
		    ncfg_json_member(doc, root, "response") != NCFG_JSON_NONE ||
		    ncfg_json_member(doc, root, "event") != NCFG_JSON_NONE) {
			tagged++;
		}
		ncfg_json_free(doc);
	}
	fclose(file);

	ok("every line of the socket witness parses", refused == 0, first_refusal);
	ok("and there were lines to parse, so this is not vacuous", parsed > 20, NULL);
	if (parsed != tagged) {
		char detail[128];
		snprintf(detail, sizeof(detail), "%u of %u lines are none of the three",
			 parsed - tagged, parsed);
			ok("and each is a request, a response or an event", 0, detail);
	} else {
		ok("and each is a request, a response or an event", 1, NULL);
	}
}

static void reader_reads_what_it_should(void)
{
	char err[NCFG_ERROR_MAX];
	const char *text =
		"{\"response\":\"status\",\"links\":[{\"name\":\"eth0\",\"mtu\":1500,"
		"\"up\":true,\"mac\":null}],\"count\":-2}";
	ncfg_json_doc_t *doc = ncfg_json_parse(text, strlen(text), err, sizeof(err));

	if (!doc) {
		ok("a status parses", 0, err);
		return;
	}
	uint32_t root = ncfg_json_root(doc);
	uint32_t links = ncfg_json_member(doc, root, "links");
	uint32_t first = ncfg_json_at(doc, links, 0);
	char name[32];

	ncfg_json_copy_member(doc, first, "name", name, sizeof(name));
	equals("a nested member reads back", name, "eth0");
	ok("a number reads as an integer",
	   ncfg_json_int(doc, ncfg_json_member(doc, first, "mtu"), -1) == 1500, NULL);
	ok("a negative number too",
	   ncfg_json_int(doc, ncfg_json_member(doc, root, "count"), 0) == -2, NULL);
	ok("a boolean reads back",
	   ncfg_json_bool(doc, ncfg_json_member(doc, first, "up"), 0) == 1, NULL);
	ok("an array knows how long it is", ncfg_json_count(doc, links) == 1u, NULL);

	/* Absent and null are different answers, and netcfgd relies on the
	 * difference: it omits what it has nothing to say about and writes null
	 * where the answer is known to be nothing. */
	ok("null is a value that is present",
	   ncfg_json_member(doc, first, "mac") != NCFG_JSON_NONE &&
		   ncfg_json_type(doc, ncfg_json_member(doc, first, "mac")) == NCFG_JSON_NULL,
	   NULL);
	ok("and an absent member is not",
	   ncfg_json_member(doc, first, "carrier") == NCFG_JSON_NONE, NULL);
	ncfg_json_free(doc);
}

static void reader_unescapes(void)
{
	char err[NCFG_ERROR_MAX];
	/* A tab, a quote, a BMP escape and a surrogate pair -- the last because
	 * an SSID or an interface description may carry one, and half a pair
	 * written out would be invalid UTF-8 that Qt then refuses. */
	const char *text = "{\"s\":\"a\\tb\\\"c\\u00e5\\ud83d\\ude00\"}";
	ncfg_json_doc_t *doc = ncfg_json_parse(text, strlen(text), err, sizeof(err));

	if (!doc) {
		ok("an escaped string parses", 0, err);
		return;
	}
	size_t length = 0;
	const char *value = ncfg_json_string(doc, ncfg_json_member(doc, ncfg_json_root(doc), "s"),
					     &length);
	const char expected[] = "a\tb\"c\xc3\xa5\xf0\x9f\x98\x80";

	ok("escapes and a surrogate pair come out as UTF-8",
	   value && length == sizeof(expected) - 1u && memcmp(value, expected, length) == 0,
	   value ? value : "(null)");
	ncfg_json_free(doc);
}

static void reader_refuses(void)
{
	static const struct {
		const char *what;
		const char *text;
	} bad[] = {
		{ "trailing data after the value", "{\"a\":1} {\"b\":2}" },
		{ "an unterminated string", "{\"a\":\"x}" },
		{ "an unterminated object", "{\"a\":1" },
		{ "a raw newline in a string", "{\"a\":\"x\ny\"}" },
		{ "an escape JSON does not have", "{\"a\":\"\\q\"}" },
		{ "a lone high surrogate", "{\"a\":\"\\ud83d\"}" },
		{ "a lone low surrogate", "{\"a\":\"\\ude00\"}" },
		{ "a number with a leading zero", "{\"a\":007}" },
		{ "a number that is only a sign", "{\"a\":-}" },
		{ "a member with no name", "{1:2}" },
		{ "a member with no colon", "{\"a\" 1}" },
		{ "a trailing comma", "{\"a\":1,}" },
		{ "a word that is not a literal", "{\"a\":tru}" },
		{ "nothing at all", "" },
	};

	for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
		char err[NCFG_ERROR_MAX];
		ncfg_json_doc_t *doc = ncfg_json_parse(bad[i].text, strlen(bad[i].text), err,
						       sizeof(err));
		char what[128];
		snprintf(what, sizeof(what), "refused: %s", bad[i].what);
		if (doc) {
			ok(what, 0, "it was accepted");
			ncfg_json_free(doc);
		} else {
			/* The message has to say something, because a reader that
			 * refuses without saying why turns a protocol change into
			 * an afternoon. */
			ok(what, err[0] != '\0', "refused with no message");
		}
	}

	/* Deeper than the reader goes. Iterative parsing is what stops this
	 * being a stack overflow, and the cap is what stops it being a very long
	 * wait -- so the check is that it is refused rather than that it crashes,
	 * which is not something a test can assert about a crash. */
	char deep[NCFG_JSON_MAX_DEPTH * 2 + 16];
	size_t at = 0;
	for (int i = 0; i < NCFG_JSON_MAX_DEPTH + 2; i++) {
		deep[at++] = '[';
	}
	for (int i = 0; i < NCFG_JSON_MAX_DEPTH + 2; i++) {
		deep[at++] = ']';
	}
	char err[NCFG_ERROR_MAX];
	ncfg_json_doc_t *doc = ncfg_json_parse(deep, at, err, sizeof(err));
	ok("refused: nesting deeper than the reader goes", doc == NULL, "it was accepted");
	ncfg_json_free(doc);
}

static void quoting_escapes_what_it_must(void)
{
	char out[64];

	ncfg_client_quote("eth0", out, sizeof(out));
	equals("a plain name quotes to itself", out, "\"eth0\"");

	/* An interface name or an SSID is not a safe thing to interpolate: the
	 * model says an SSID is arbitrary octets, and a name with a quote in it
	 * would otherwise produce a request that means something else. */
	ncfg_client_quote("ev\"il\\", out, sizeof(out));
	equals("a quote and a backslash are escaped", out, "\"ev\\\"il\\\\\"");

	ncfg_client_quote("a\tb", out, sizeof(out));
	equals("a tab is escaped", out, "\"a\\tb\"");

	ok("a buffer too small writes nothing rather than half a string",
	   ncfg_client_quote("abcdefgh", out, 4) == 0, NULL);
}

/* -------------------------------------------------------------- connection */

/*
 * A fake daemon that answers awkwardly on purpose.
 *
 * The two answers are written in three pieces: half of the first, then the
 * rest of the first *and* all of the second in one write. A reader that
 * assumed one read is one line would pass the first check and lose the second
 * answer entirely.
 */
static void fake_daemon(int fd)
{
	const char *first_half = "{\"response\":\"hello\",\"ver";
	const char *rest_and_second = "sion\":1}\n{\"response\":\"ok\"}\n";
	char scratch[512];

	/* Read the first request, answer in two writes. */
	if (read(fd, scratch, sizeof(scratch)) <= 0) {
		return;
	}
	if (write(fd, first_half, strlen(first_half)) < 0) {
		return;
	}
	usleep(20000);
	if (write(fd, rest_and_second, strlen(rest_and_second)) < 0) {
		return;
	}
	/* The second request arrives after its answer already has. */
	if (read(fd, scratch, sizeof(scratch)) <= 0) {
		return;
	}
	/* Nothing more to send: the second answer is already in the client's
	 * buffer, and a client that dropped it will hang here rather than
	 * quietly passing. */
	usleep(200000);
}

static void connection_reads_lines_however_they_arrive(void)
{
	/* Sized from sun_path rather than from a round number: a path longer
	 * than that cannot be connected to by anybody, so a buffer that could
	 * hold one only makes the truncation harder to see. */
	struct sockaddr_un address;
	char path[sizeof(address.sun_path)];

	snprintf(path, sizeof(path), "/tmp/ncfg-client-test-%d.sock", (int)getpid());
	unlink(path);

	int listener = socket(AF_UNIX, SOCK_STREAM, 0);
	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	snprintf(address.sun_path, sizeof(address.sun_path), "%s", path);
	if (listener < 0 || bind(listener, (struct sockaddr *)&address, sizeof(address)) < 0 ||
	    listen(listener, 1) < 0) {
		ok("a fake daemon can be started", 0, strerror(errno));
		return;
	}

	pid_t child = fork();
	if (child == 0) {
		int fd = accept(listener, NULL, NULL);
		if (fd >= 0) {
			fake_daemon(fd);
			close(fd);
		}
		close(listener);
		_exit(0);
	}

	char err[NCFG_ERROR_MAX];
	ncfg_client_t *client = ncfg_client_open(path, err, sizeof(err));
	if (!client) {
		ok("the client connects to it", 0, err);
		kill(child, SIGTERM);
		waitpid(child, NULL, 0);
		unlink(path);
		close(listener);
		return;
	}
	ok("the client connects to it", 1, NULL);

	ncfg_json_doc_t *hello = ncfg_client_hello(client, err, sizeof(err));
	ok("an answer split across two writes is read as one line", hello != NULL, err);
	if (hello) {
		ok("and its contents survive",
		   ncfg_json_string_equals(hello, ncfg_json_member(hello, ncfg_json_root(hello),
								   "response"),
					   "hello"),
		   NULL);
		ncfg_json_free(hello);
	}

	ncfg_json_doc_t *second = ncfg_client_status(client, err, sizeof(err));
	ok("and a second answer that arrived early is not lost", second != NULL, err);
	if (second) {
		ok("and is the right one",
		   ncfg_json_string_equals(second, ncfg_json_member(second, ncfg_json_root(second),
								    "response"),
					   "ok"),
		   NULL);
		ncfg_json_free(second);
	}

	ncfg_client_close(client);
	kill(child, SIGTERM);
	waitpid(child, NULL, 0);
	close(listener);
	unlink(path);
}

static void a_refusal_is_an_answer_not_a_failure(void)
{
	char err[NCFG_ERROR_MAX];
	const char *text = "{\"response\":\"error\",\"message\":\"the wifi tier is root's\"}";
	ncfg_json_doc_t *doc = ncfg_json_parse(text, strlen(text), err, sizeof(err));

	if (!doc) {
		ok("an error response parses", 0, err);
		return;
	}
	size_t length = 0;
	const char *message = ncfg_client_error_message(doc, &length);

	ok("a refusal is recognised and its message read",
	   message && length == strlen("the wifi tier is root's") &&
		   memcmp(message, "the wifi tier is root's", length) == 0,
	   message ? message : "(null)");

	ncfg_json_free(doc);

	const char *fine = "{\"response\":\"ok\"}";
	doc = ncfg_json_parse(fine, strlen(fine), err, sizeof(err));
	ok("and a response that is not one is not mistaken for it",
	   doc && ncfg_client_error_message(doc, NULL) == NULL, NULL);
	ncfg_json_free(doc);
}

/* ------------------------------------------------------------------ models
 *
 * The fixtures below are copied out of docs/schema/plan.json and
 * docs/schema/socket.json rather than written to suit the code -- same reason
 * as the witness above, and the same failure mode if they were not: a plan
 * fixture invented here would agree with this implementation about a shape
 * neither of them had checked with the daemon.
 *
 * THE DAEMON IS STAGED, NOT FORKED
 *   These tests listen, connect, accept and write the answers into the socket
 *   before anything asks for them. The connection already has a check that an
 *   answer arriving early is kept, so leaning on that here costs nothing and
 *   buys determinism -- and the monitor check, which has to assert that
 *   *nothing* complete has arrived yet, cannot be sharing a stopwatch with a
 *   child process and still mean anything.
 */

static int listen_somewhere(char *path, size_t path_size)
{
	static int serial;
	struct sockaddr_un address;

	snprintf(path, path_size, "/tmp/ncfg-client-test-%d-%d.sock", (int)getpid(), ++serial);
	unlink(path);

	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	snprintf(address.sun_path, sizeof(address.sun_path), "%s", path);

	int listener = socket(AF_UNIX, SOCK_STREAM, 0);
	if (listener < 0) {
		return -1;
	}
	if (bind(listener, (struct sockaddr *)&address, sizeof(address)) < 0 ||
	    listen(listener, 1) < 0) {
		close(listener);
		return -1;
	}
	return listener;
}

static void send_bytes(int fd, const char *text)
{
	if (write(fd, text, strlen(text)) < 0) {
		printf("       (the test's own write failed: %s)\n", strerror(errno));
	}
}

/* What the client put on the wire, as a C string. Nothing here ever blocks:
 * every request checked this way was written before its answer was read. */
static const char *received(int fd, char *out, size_t out_size)
{
	ssize_t got = read(fd, out, out_size - 1u);

	out[got > 0 ? (size_t)got : 0u] = '\0';
	return out;
}

struct staged {
	char           path[128];
	int            listener;
	int            server;
	ncfg_client_t *client;
};

static void staged_close(struct staged *staged)
{
	ncfg_client_close(staged->client);
	if (staged->server >= 0) {
		close(staged->server);
	}
	if (staged->listener >= 0) {
		close(staged->listener);
	}
	unlink(staged->path);
	memset(staged, 0, sizeof(*staged));
}

static int staged_open(struct staged *staged, const char *what, const char *answers)
{
	char err[NCFG_ERROR_MAX];

	memset(staged, 0, sizeof(*staged));
	staged->server = -1;
	staged->listener = listen_somewhere(staged->path, sizeof(staged->path));
	if (staged->listener < 0) {
		ok(what, 0, strerror(errno));
		return 0;
	}
	staged->client = ncfg_client_open(staged->path, err, sizeof(err));
	if (!staged->client) {
		ok(what, 0, err);
		staged_close(staged);
		return 0;
	}
	staged->server = accept(staged->listener, NULL, NULL);
	if (staged->server < 0) {
		ok(what, 0, strerror(errno));
		staged_close(staged);
		return 0;
	}
	send_bytes(staged->server, answers);
	ok(what, 1, NULL);
	return 1;
}

/*
 * A plan, in the shapes docs/schema/plan.json pins.
 *
 * Three actions on purpose: one with an inverse, one whose inverse is an
 * explicit null, and one with no inverse member at all. netcfgd omits the field
 * today, but the model says "not reversible" for both spellings and a check
 * that only knew one would pass against a daemon that changed its mind.
 * The third also carries a reason with no interface, which is what a host-wide
 * action -- nat.replace, hostname.set -- looks like.
 */
static const char plan_response[] =
	"{\"response\":\"plan\",\"actions\":["
	"{\"id\":0,\"op\":{\"op\":\"bridge.vlan.add\",\"name\":\"br0\",\"vid\":7},"
	"\"reason\":{\"interface\":\"eth0\",\"field\":\"addressing[0]\","
	"\"desired\":\"192.168.1.10/24\",\"observed\":\"<absent>\"},\"depends_on\":[],"
	"\"inverse\":{\"op\":\"bridge.vlan.del\",\"name\":\"br0\",\"vid\":7}},"
	"{\"id\":45,\"op\":{\"op\":\"commit.arm\",\"window_seconds\":90},"
	"\"reason\":{\"interface\":\"eth0\",\"field\":\"confirm\",\"desired\":\"90\","
	"\"observed\":\"<absent>\"},\"depends_on\":[0],\"inverse\":null},"
	"{\"id\":43,\"op\":{\"op\":\"nat.replace\",\"uplinks\":[\"eth0\"]},"
	"\"reason\":{\"field\":\"nat\",\"desired\":\"eth0\",\"observed\":\"<absent>\"},"
	"\"depends_on\":[0]}"
	"],\"warnings\":[{\"message\":\"slaac is accepted but not yet applied by this build\","
	"\"interface\":\"eth0\"}],"
	"\"refusals\":[{\"interface\":\"eth0\",\"op\":\"link.down\","
	"\"guard\":\"the office runs on this\",\"reason\":{\"interface\":\"eth0\","
	"\"field\":\"enabled\",\"desired\":\"false\",\"observed\":\"true\"},"
	"\"override_with\":\"ncfg apply --allow-disruption eth0\"}],"
	"\"stranded\":[{\"interface\":\"wg0\",\"credential\":\"the WireGuard private key\","
	"\"irrevocable\":\"only every peer's administrator can revoke it\","
	"\"remove_with\":\"on_unmanage = \\\"clear\\\"\","
	"\"consent_with\":\"ncfg apply --strand-credentials wg0\"}]}\n";

static void a_plan_becomes_a_model(void)
{
	struct staged staged;
	char err[NCFG_ERROR_MAX];
	ncfg_plan_t plan;

	if (!staged_open(&staged, "a plan answer can be staged", plan_response)) {
		return;
	}
	if (!ncfg_client_plan_of(staged.client, &plan, err, sizeof(err))) {
		ok("a plan converts to a model", 0, err);
		staged_close(&staged);
		return;
	}
	ok("a plan converts to a model", 1, NULL);
	ok("with every action in it", plan.action_count == 3u, NULL);

	if (plan.action_count == 3u) {
		/* The op is a tagged object in the wire shape and a name in the
		 * model, and since 0083 the tag is the name -- so this is a read
		 * rather than a translation, and no client carries a table of
		 * forty-seven strings that netcfgd would then be free to change.
		 *
		 * `bridge.vlan.add` on purpose. It is one of the three whose old
		 * tag differed from its name by more than a separator, so a client
		 * still guessing from `bridge_vlan_add` would say `bridge.vlan_add`
		 * and be right about the other forty-four. */
		equals("an op is the name the wire calls it", plan.actions[0].op,
		       "bridge.vlan.add");
		equals("and every op reads the same way", plan.actions[1].op, "commit.arm");
		ok("an id survives", plan.actions[0].id == 0 && plan.actions[1].id == 45, NULL);

		/* The reason is the half that matters: an action without it is
		 * the black box netcfgd exists not to be. */
		equals("a reason's interface reaches the model", plan.actions[0].interface,
		       "eth0");
		equals("and its field", plan.actions[0].field, "addressing[0]");
		equals("and what was wanted", plan.actions[0].desired, "192.168.1.10/24");
		equals("and what is there instead", plan.actions[0].observed, "<absent>");

		ok("an action with an inverse is reversible", plan.actions[0].reversible == 1,
		   NULL);
		ok("an action whose inverse is null is not", plan.actions[1].reversible == 0,
		   NULL);
		ok("and neither is one with no inverse at all", plan.actions[2].reversible == 0,
		   NULL);
		equals("an action the planner gave no interface names none",
		       plan.actions[2].interface, "");
	}

	ok("the warning is there", plan.warning_count == 1u, NULL);
	if (plan.warning_count == 1u) {
		equals("and says what it says", plan.warnings[0].message,
		       "slaac is accepted but not yet applied by this build");
		equals("and which interface it is about", plan.warnings[0].interface, "eth0");
		equals("and a plain warning has nothing to pass", plan.warnings[0].consent, "");
		equals("and nothing to change either", plan.warnings[0].remedy, "");
		equals("and no reason, being a sentence and not a dropped action",
		       plan.warnings[0].field, "");
	}

	ok("the refusal is there", plan.refusal_count == 1u, NULL);
	if (plan.refusal_count == 1u) {
		equals("and names the op it dropped", plan.refusals[0].message, "link.down");
		equals("and quotes the guard", plan.refusals[0].detail, "the office runs on this");
		/* Verbatim, because a refusal the operator cannot act on is just
		 * a complaint. */
		equals("and the exact command that consents to it", plan.refusals[0].consent,
		       "ncfg apply --allow-disruption eth0");
		equals("and nothing to change, a guard being a decision and not a typo",
		       plan.refusals[0].remedy, "");
		/* Constraint 7 in the place it matters most. A refusal that cannot
		 * say what the action would have been leaves an operator told no
		 * with no way to judge whether the no is right. */
		equals("and what the refused action would have been", plan.refusals[0].field,
		       "enabled");
		equals("and what it wanted to make it", plan.refusals[0].desired, "false");
		equals("and what it found instead", plan.refusals[0].observed, "true");
	}

	ok("the stranded credential is there", plan.stranded_count == 1u, NULL);
	if (plan.stranded_count == 1u) {
		equals("and names what is being left behind", plan.stranded[0].message,
		       "the WireGuard private key");
		equals("and on what", plan.stranded[0].interface, "wg0");
		equals("and why it cannot be taken back", plan.stranded[0].detail,
		       "only every peer's administrator can revoke it");
		equals("and how to mean it", plan.stranded[0].consent,
		       "ncfg apply --strand-credentials wg0");
		/* Both, and this is the one the first draft dropped: consent tells
		 * an operator how to walk away from a key, and only this tells them
		 * how to stop leaving it behind. `ncfg` prints this one first for
		 * the same reason. */
		equals("and how to not have to", plan.stranded[0].remedy,
		       "on_unmanage = \"clear\"");
	}

	ncfg_plan_free(&plan);
	/* Twice, because the error paths inside the conversion free a plan the
	 * caller will free again, and "it depends" is not a rule anybody keeps. */
	ncfg_plan_free(&plan);
	ok("and freeing a plan twice leaves it zeroed",
	   plan.actions == NULL && plan.action_count == 0u && plan.refusals == NULL, NULL);
	staged_close(&staged);
}

static const char status_response[] =
	"{\"response\":\"status\",\"links\":["
	"{\"name\":\"eth0\",\"kind\":\"\",\"up\":true,\"carrier\":false,\"mtu\":1500,"
	"\"mac\":\"02:00:00:00:00:01\"},"
	"{\"name\":\"br0\",\"kind\":\"bridge\",\"up\":true,\"carrier\":true,\"mtu\":9000}],"
	"\"addresses\":[{\"interface\":\"eth0\",\"address\":\"192.0.2.1/24\"},"
	"{\"interface\":\"br0\",\"address\":\"10.0.0.1/24\"},"
	"{\"interface\":\"eth0\",\"address\":\"fe80::1/64\"}]}\n";

static void a_status_becomes_links(void)
{
	struct staged staged;
	char err[NCFG_ERROR_MAX];
	ncfg_links_t links;

	if (!staged_open(&staged, "a status answer can be staged", status_response)) {
		return;
	}
	if (!ncfg_client_links(staged.client, &links, err, sizeof(err))) {
		ok("a status converts to links", 0, err);
		staged_close(&staged);
		return;
	}
	ok("a status converts to links", 1, NULL);
	ok("one row per link", links.count == 2u, NULL);

	if (links.count == 2u) {
		/* The addresses arrive as their own flat list keyed by
		 * interface, and joining them is the one thing in this
		 * conversion that two frontends would have done differently. */
		equals("every address of an interface is gathered, in the daemon's order",
		       links.items[0].addresses, "192.0.2.1/24, fe80::1/64");
		equals("and only that interface's", links.items[1].addresses, "10.0.0.1/24");
		/* An empty kind is what the kernel says about a real NIC, and it
		 * stays empty: `eth0` is a convention, not a fact. */
		equals("a real NIC keeps its empty kind", links.items[0].kind, "");
		equals("and a virtual link its own", links.items[1].kind, "bridge");
		/* Up and carrier are separate answers: no cable is not the same
		 * state as not configured. */
		ok("up and carrier are two answers",
		   links.items[0].up == 1 && links.items[0].carrier == 0, NULL);
		equals("a link with no mac gets an empty string rather than a null",
		       links.items[1].mac, "");
		ok("the mtu comes through", links.items[1].mtu == 9000, NULL);
	}
	ncfg_links_free(&links);
	staged_close(&staged);
}

static const char journal_response[] =
	"{\"response\":\"journal\",\"records\":["
	"{\"id\":1,\"op\":\"addr.add\",\"interface\":\"eth0\","
	"\"reason\":{\"interface\":\"eth0\",\"field\":\"addressing[0]\","
	"\"desired\":\"192.0.2.1/24\",\"observed\":\"<absent>\"},\"outcome\":\"done\"},"
	"{\"id\":2,\"op\":\"link.up\",\"interface\":\"eth0\","
	"\"reason\":{\"interface\":\"eth0\",\"field\":\"enabled\",\"desired\":\"true\","
	"\"observed\":\"false\"},\"outcome\":\"failed\","
	"\"error\":\"the kernel refused: Operation not permitted\"}]}\n";

static void an_apply_becomes_a_journal(void)
{
	struct staged staged;
	char err[NCFG_ERROR_MAX];
	char sent[256];
	ncfg_journal_t journal;

	/* Three answers for three requests, queued in the order they are asked
	 * for. */
	char answers[4096];
	snprintf(answers, sizeof(answers), "%s{\"response\":\"ok\"}\n%s", journal_response,
		 journal_response);
	if (!staged_open(&staged, "an apply answer can be staged", answers)) {
		return;
	}

	if (!ncfg_client_apply(staged.client, 90, NULL, &journal, err, sizeof(err))) {
		ok("an apply converts to a journal", 0, err);
		staged_close(&staged);
		return;
	}
	ok("an apply converts to a journal", 1, NULL);
	equals("and the confirm window goes out the way the daemon spells it",
	       received(staged.server, sent, sizeof(sent)),
	       "{\"request\":\"apply\",\"confirm\":90}\n");
	ok("one record per action", journal.count == 2u, NULL);
	if (journal.count == 2u) {
		ok("an id survives", journal.items[0].id == 1 && journal.items[1].id == 2, NULL);
		/* The op is a bare name here and an object in a plan; both read
		 * the same, so a screen showing the two lists side by side does
		 * not have a gap in one of them. */
		equals("an op reads the same as it does in a plan", journal.items[0].op,
		       "addr.add");
		equals("the outcome is the daemon's own word", journal.items[0].outcome, "done");
		equals("a record that went fine has no detail", journal.items[0].detail, "");
		equals("and a failure carries what the kernel said", journal.items[1].detail,
		       "the kernel refused: Operation not permitted");
		equals("with the daemon's word for it", journal.items[1].outcome, "failed");
	}
	ncfg_journal_free(&journal);

	ok("a confirm is answered", ncfg_client_confirm(staged.client, err, sizeof(err)) == 1, err);
	equals("and asks for exactly that", received(staged.server, sent, sizeof(sent)),
	       "{\"request\":\"confirm\"}\n");

	/* No window means the field is left out rather than sent as zero: a
	 * window of zero seconds is one that arms and expires, which is not what
	 * "do not arm one" means. */
	if (ncfg_client_apply(staged.client, 0, NULL, &journal, err, sizeof(err))) {
		equals("an apply with no window does not mention confirm at all",
		       received(staged.server, sent, sizeof(sent)), "{\"request\":\"apply\"}\n");
		ncfg_journal_free(&journal);
	} else {
		ok("an apply with no window is still an apply", 0, err);
	}
	staged_close(&staged);
}

static void a_daemon_refusal_is_a_zero_and_its_own_message(void)
{
	struct staged staged;
	char err[NCFG_ERROR_MAX];
	ncfg_plan_t plan;
	ncfg_journal_t journal;

	static const char refusal[] =
		"{\"response\":\"error\",\"message\":\"the admin tier is root's\"}\n"
		"{\"response\":\"error\",\"message\":\"the admin tier is root's\"}\n";

	if (!staged_open(&staged, "a refusal can be staged", refusal)) {
		return;
	}
	/* The daemon's sentence and not one of this library's: a refusal names
	 * the tier that would have been needed, and replacing it would throw
	 * away the half that says what to do about it. */
	ok("a refused plan is a zero, not a failure to reach anything",
	   ncfg_client_plan_of(staged.client, &plan, err, sizeof(err)) == 0, NULL);
	equals("and err holds the daemon's own words", err, "the admin tier is root's");
	ok("and the model is left empty rather than half filled in",
	   plan.actions == NULL && plan.action_count == 0u, NULL);

	ok("the same for an apply",
	   ncfg_client_apply(staged.client, 0, NULL, &journal, err, sizeof(err)) == 0, NULL);
	equals("with the same message", err, "the admin tier is root's");
	staged_close(&staged);
}

/* ----------------------------------------------------------------- monitor */

static void the_monitor_hands_over_one_event_at_a_time(void)
{
	char path[128];
	char err[NCFG_ERROR_MAX];
	char sent[256];
	ncfg_event_t event;

	int listener = listen_somewhere(path, sizeof(path));
	if (listener < 0) {
		ok("a socket to monitor can be made", 0, strerror(errno));
		return;
	}
	ncfg_monitor_t *monitor = ncfg_monitor_open(path, err, sizeof(err));
	if (!monitor) {
		ok("a monitor connects", 0, err);
		close(listener);
		unlink(path);
		return;
	}
	ok("a monitor connects", 1, NULL);

	int server = accept(listener, NULL, NULL);
	if (server < 0) {
		ok("and the daemon side accepts it", 0, strerror(errno));
		ncfg_monitor_close(monitor);
		close(listener);
		unlink(path);
		return;
	}
	equals("and asks for a stream", received(server, sent, sizeof(sent)),
	       "{\"request\":\"monitor\"}\n");
	ok("and offers a descriptor an event loop can watch", ncfg_monitor_fd(monitor) >= 0, NULL);

	/* Two events in one write and the front half of a third: what a daemon
	 * that emitted a burst and then began another line looks like. */
	send_bytes(server,
		   "{\"response\":\"event\",\"event\":\"observed\","
		   "\"summary\":\"eth0 gained an address\"}\n"
		   "{\"response\":\"event\",\"event\":\"drift\",\"interface\":\"eth0\","
		   "\"summary\":\"an address we installed is gone\",\"action\":\"reconciled\"}\n");
	send_bytes(server, "{\"response\":\"event\",\"event\":\"confirm_armed\",\"sec");

	int got = ncfg_monitor_next(monitor, &event, err, sizeof(err));
	ok("the first event arrives", got == 1, err);
	if (got == 1) {
		equals("with the daemon's own kind", event.kind, "observed");
		equals("and its own sentence", event.summary, "eth0 gained an address");
		ok("and the whole line, for a pane that wants everything",
		   strstr(event.raw, "\"response\":\"event\"") != NULL, event.raw);
		equals("and an event about no interface says so with an empty string",
		       event.interface, "");
		ncfg_event_free(&event);
	}

	got = ncfg_monitor_next(monitor, &event, err, sizeof(err));
	ok("the second is not lost to the read that fetched the first", got == 1, err);
	if (got == 1) {
		equals("and is the other one", event.kind, "drift");
		equals("with the interface it is about", event.interface, "eth0");
		equals("and the daemon's summary rather than one of ours", event.summary,
		       "an address we installed is gone");
		ncfg_event_free(&event);
	}

	/* The ordinary answer, and the one a UI must not treat as trouble: a
	 * monitor that returned -1 here would put an error in a pane every time
	 * the daemon paused mid-line. */
	got = ncfg_monitor_next(monitor, &event, err, sizeof(err));
	ok("half an event is nothing yet rather than an error", got == 0, err);
	ok("and says nothing, since there is nothing wrong", err[0] == '\0', err);

	send_bytes(server, "onds\":90}\n");
	got = ncfg_monitor_next(monitor, &event, err, sizeof(err));
	ok("and the half that was kept completes the line", got == 1, err);
	if (got == 1) {
		equals("into the event it was", event.kind, "confirm_armed");
		/* Composed, because this event carries a number and nothing a
		 * pane could draw. Every kind that has words of its own keeps
		 * them. */
		equals("with a summary made for an event that has none of its own",
		       event.summary, "a confirm window is open for 90 seconds");
		ncfg_event_free(&event);
	}

	/* The other two kinds that carry no summary. A reload that failed has
	 * the compiler's diagnostics, which are words netcfgd already chose --
	 * so they are used rather than summarised into "reload failed", which
	 * is the sentence that sends somebody to the log to find out which
	 * line. */
	send_bytes(server,
		   "{\"response\":\"event\",\"event\":\"reloaded\",\"ok\":false,"
		   "\"diagnostics\":\"netcfgd.conf:3: unknown key\"}\n"
		   "{\"response\":\"event\",\"event\":\"confirm_resolved\","
		   "\"confirmed\":false}\n");

	got = ncfg_monitor_next(monitor, &event, err, sizeof(err));
	ok("a failed reload arrives", got == 1, err);
	if (got == 1) {
		equals("and shows the compiler's own diagnostics", event.summary,
		       "netcfgd.conf:3: unknown key");
		ncfg_event_free(&event);
	}

	got = ncfg_monitor_next(monitor, &event, err, sizeof(err));
	ok("a resolved confirm window arrives", got == 1, err);
	if (got == 1) {
		/* Confirmed and reverted are the two things that window can end
		 * as, and a pane that said "resolved" for both would be telling
		 * an operator nothing at the one moment they are watching. */
		equals("and says which way it went", event.summary, "the change was reverted");
		ncfg_event_free(&event);
	}

	/* A monitor that silently stopped would leave a pane looking merely
	 * quiet, which is the failure the header names. */
	close(server);
	got = ncfg_monitor_next(monitor, &event, err, sizeof(err));
	ok("a stream that ends says so rather than going quiet", got == -1, NULL);
	ok("and names what happened", err[0] != '\0', NULL);

	ncfg_monitor_close(monitor);
	close(listener);
	unlink(path);
}

/*
 * Consent goes out as the daemon spells it, or not at all.
 *
 * The exact bytes, because this is the one request where being wrong is worse
 * than failing: a client that put an interface in the wrong list would have the
 * operator agreeing to leave a private key behind when they agreed to a brief
 * outage, and the daemon would do it. Two lists and never one flag, which is
 * `ncfg`'s own shape -- "deliberately not a blanket --force".
 */
static void consent_goes_out_the_way_the_daemon_spells_it(void)
{
	struct staged staged;
	char err[NCFG_ERROR_MAX];
	char sent[512];
	ncfg_journal_t journal;

	char answers[4096];
	snprintf(answers, sizeof(answers), "%s%s%s", journal_response, journal_response,
		 journal_response);
	if (!staged_open(&staged, "an apply with consent can be staged", answers)) {
		return;
	}

	const char *const disrupt[] = { "eth0", "wlan0" };
	const char *const strand[] = { "wg0" };

	/* Both lists, and a window, in the order the witness pins them. */
	ncfg_consent_t both = { disrupt, 2u, strand, 1u };
	if (ncfg_client_apply(staged.client, 90, &both, &journal, err, sizeof(err))) {
		equals("both consent lists reach the daemon",
		       received(staged.server, sent, sizeof(sent)),
		       "{\"request\":\"apply\",\"confirm\":90,"
		       "\"allow_disruption\":[\"eth0\",\"wlan0\"],"
		       "\"strand_credentials\":[\"wg0\"]}\n");
		ncfg_journal_free(&journal);
	} else {
		ok("both consent lists reach the daemon", 0, err);
	}

	/* One list alone leaves the other out entirely rather than sending an
	 * empty array: absent and empty mean the same thing to the daemon, and
	 * only one of them makes "did somebody consent to anything" answerable by
	 * looking at the request. */
	ncfg_consent_t one = { NULL, 0u, strand, 1u };
	if (ncfg_client_apply(staged.client, 0, &one, &journal, err, sizeof(err))) {
		equals("a list nobody filled in is not mentioned",
		       received(staged.server, sent, sizeof(sent)),
		       "{\"request\":\"apply\",\"strand_credentials\":[\"wg0\"]}\n");
		ncfg_journal_free(&journal);
	} else {
		ok("a list nobody filled in is not mentioned", 0, err);
	}

	/* An interface name is not guaranteed to be a bare word. Interpolated,
	 * this one would end the string and consent to something else. */
	const char *const odd[] = { "we\"ird" };
	ncfg_consent_t quoted = { odd, 1u, NULL, 0u };
	if (ncfg_client_apply(staged.client, 0, &quoted, &journal, err, sizeof(err))) {
		equals("and a name with a quote in it is escaped rather than interpolated",
		       received(staged.server, sent, sizeof(sent)),
		       "{\"request\":\"apply\",\"allow_disruption\":[\"we\\\"ird\"]}\n");
		ncfg_journal_free(&journal);
	} else {
		ok("and a name with a quote in it is escaped rather than interpolated", 0, err);
	}
	staged_close(&staged);
}

/*
 * The stream's other first line: a refusal.
 *
 * netcfgd answers `monitor` by saying nothing and streaming, so the only line
 * it ever writes for a client it will not serve is the refusal itself, and then
 * it closes. That makes this the ordinary experience of an unprivileged desktop
 * user opening the events pane -- not an edge case -- and the two ways to get
 * it wrong both end with a pane that lies: parse the refusal as an event and it
 * is drawn as a line of network activity, or notice only the close and report
 * "the stream ended" instead of the sentence naming the tier (0013) that would
 * have been needed.
 */
static void a_refused_stream_says_which_tier_it_wanted(void)
{
	char path[128];
	char err[NCFG_ERROR_MAX];
	char sent[256];
	ncfg_event_t event;

	int listener = listen_somewhere(path, sizeof(path));
	if (listener < 0) {
		ok("a socket to refuse on can be made", 0, strerror(errno));
		return;
	}
	ncfg_monitor_t *monitor = ncfg_monitor_open(path, err, sizeof(err));
	if (!monitor) {
		/* Opening still succeeds: the tier check happens on the daemon's
		 * side after the request, so there is nothing to refuse yet. */
		ok("a monitor connects before it is refused", 0, err);
		close(listener);
		unlink(path);
		return;
	}
	ok("a monitor connects before it is refused", 1, NULL);

	int server = accept(listener, NULL, NULL);
	if (server < 0) {
		ok("and the daemon side accepts it", 0, strerror(errno));
		ncfg_monitor_close(monitor);
		close(listener);
		unlink(path);
		return;
	}
	(void)received(server, sent, sizeof(sent));

	send_bytes(server, "{\"response\":\"error\",\"message\":\"monitor needs the observe "
			   "tier; you are in none of its groups\"}\n");
	close(server);

	int got = ncfg_monitor_next(monitor, &event, err, sizeof(err));
	ok("a refusal is a failure of the stream, not an event on it", got == -1, NULL);
	equals("and arrives as the daemon's own sentence", err,
	       "monitor needs the observe tier; you are in none of its groups");

	ncfg_monitor_close(monitor);
	close(listener);
	unlink(path);
}

static void freeing_what_was_never_filled_in_is_nothing(void)
{
	ncfg_links_t links;
	ncfg_plan_t plan;
	ncfg_journal_t journal;
	ncfg_event_t event;

	memset(&links, 0, sizeof(links));
	memset(&plan, 0, sizeof(plan));
	memset(&journal, 0, sizeof(journal));
	memset(&event, 0, sizeof(event));

	/* A caller that never made the request still has one of these on its
	 * stack, and the error paths inside the library free structs they only
	 * half filled. Both end up here. */
	ncfg_links_free(&links);
	ncfg_plan_free(&plan);
	ncfg_journal_free(&journal);
	ncfg_event_free(&event);
	ncfg_links_free(NULL);
	ncfg_plan_free(NULL);
	ncfg_journal_free(NULL);
	ncfg_event_free(NULL);

	ok("freeing a model that was never filled in is nothing",
	   links.items == NULL && links.count == 0u && plan.actions == NULL &&
		   plan.warnings == NULL && plan.stranded_count == 0u &&
		   journal.items == NULL && event.kind == NULL && event.raw == NULL,
	   NULL);
}

int main(int argc, char **argv)
{
	const char *witness = (argc > 1) ? argv[1] : "../docs/schema/socket.json";

	reader_accepts_the_witness(witness);
	reader_reads_what_it_should();
	reader_unescapes();
	reader_refuses();
	quoting_escapes_what_it_must();
	connection_reads_lines_however_they_arrive();
	a_refusal_is_an_answer_not_a_failure();
	a_plan_becomes_a_model();
	a_status_becomes_links();
	an_apply_becomes_a_journal();
	a_daemon_refusal_is_a_zero_and_its_own_message();
	consent_goes_out_the_way_the_daemon_spells_it();
	the_monitor_hands_over_one_event_at_a_time();
	a_refused_stream_says_which_tier_it_wanted();
	freeing_what_was_never_filled_in_is_nothing();

	printf("\n");
	if (failures) {
		printf("client_test: %d failed\n", failures);
		return 1;
	}
	printf("client_test: all checks passed\n");
	return 0;
}
