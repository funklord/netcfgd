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
				snprintf(first_refusal, sizeof(first_refusal), "%s: %.120s",
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
	char path[128];
	snprintf(path, sizeof(path), "/tmp/ncfg-client-test-%d.sock", (int)getpid());
	unlink(path);

	int listener = socket(AF_UNIX, SOCK_STREAM, 0);
	struct sockaddr_un address;
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

	printf("\n");
	if (failures) {
		printf("client_test: %d failed\n", failures);
		return 1;
	}
	printf("client_test: all checks passed\n");
	return 0;
}
