/*
 * cli_secret_test.c -- `ncfg secret set`, and the one rule it must never break.
 *
 * THE RULE, ASSERTED RATHER THAN STATED
 *   **No secret material reaches a diagnostic, a log line or a rendered
 *   document.** `secrets_test.c` proves that for the store; this proves it for
 *   the command, which is the half a person actually types into. Every case
 *   below that supplies a value supplies the same sentinel, and the output and
 *   the error buffer are read back for it afterwards -- because a rule nothing
 *   checks is a rule that holds until somebody adds a `%s`.
 *
 * WHY THE READ IS TESTED SEPARATELY FROM THE WRITE
 *   The defect this command shipped was in the read: `ncfg secret set corp-ca
 *   < /etc/ssl/certs/corp.pem` stored the twenty-seven bytes `-----BEGIN
 *   CERTIFICATE-----` and nothing else, because a terminal gives one line and
 *   a redirect gives a file and the reader did not know the difference. The
 *   symptom was an association failing with nothing from netcfgd, since
 *   nothing will print the value. So `ncfg_cli_read_secret` is reachable on its
 *   own and every shape of input has a case.
 *
 * WHAT `--json` IS ASSERTED ABOUT
 *   The same rule, one layer stricter. A document is a worse place to leak a
 *   credential than a sentence, because a script writes what it reads into a
 *   log -- so the sentinel is swept through the `--json` output too, and the
 *   sweep is proved non-vacuous by reading the value back out of the file it
 *   was meant for in the same case. The object carries `name` and `used_by`
 *   spelled as `doc/schema/socket.json` spells them, and **`used_by` is absent
 *   rather than empty where the configuration could not be compiled**: the two
 *   are different answers and the text distinguishes them.
 *
 * WHAT THIS DOES NOT DO
 *   **Nothing touches the machine's own configuration.** `/etc/netcfgd/secrets`
 *   on the machine this builds on holds this developer's real credentials; every
 *   fixture here names a config directory of its own, and a run directory of
 *   its own so that the netcfgd actually running is never asked anything.
 */
#include "ncfg/cli.h"

#include "ncfg/base.h"
#include "ncfg/config.h"
#include "ncfg/secrets.h"

#include "testdir.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int failures;

/*
 * Where a result goes, which is deliberately not `stdout`.
 *
 * The cases below point descriptor 1 at a file to read back what the command
 * printed, and a check that reported into *that* would be counted and never
 * seen -- a failure inside a capture would raise the count with no line saying
 * which. So the real standard output is duplicated once, before any capture,
 * and every result is written there.
 */
static FILE *report;

static void report_opens_before_any_capture(void)
{
	int fd = dup(STDOUT_FILENO);

	report = fd >= 0 ? fdopen(fd, "w") : NULL;
	if (!report) {
		printf("could not keep a handle on the real standard output\n");
		exit(1);
	}
}

static void check(int condition, const char *what)
{
	(void)fprintf(report, "%-72s %s\n", what, condition ? "ok" : "FAILED");
	(void)fflush(report);
	if (!condition) {
		failures++;
	}
}

static void detail(const char *label, const char *text)
{
	(void)fprintf(report, "       %s: %s\n", label, text ? text : "(none)");
	(void)fflush(report);
}

/*
 * A value nothing in this program may repeat.
 *
 * One string, used everywhere a value is supplied, so that the sweep at the
 * end of each case is a single `strstr` over everything that was produced.
 */
static const char *const sentinel = "correct-horse-battery-staple";

/* ------------------------------------------------------------------------ *
 * Capturing what the program printed
 * ------------------------------------------------------------------------ */

static int   saved_stdout = -1;
static char  capture_file[512];
static char *captured;

static void capture_begin(void)
{
	int fd;

	(void)fflush(stdout);
	saved_stdout = dup(STDOUT_FILENO);
	fd = open(capture_file, O_RDWR | O_CREAT | O_TRUNC, 0600);
	if (fd < 0 || saved_stdout < 0) {
		printf("could not redirect stdout to %s\n", capture_file);
		exit(1);
	}
	(void)dup2(fd, STDOUT_FILENO);
	(void)close(fd);
}

static const char *capture_end(void)
{
	(void)fflush(stdout);
	(void)dup2(saved_stdout, STDOUT_FILENO);
	(void)close(saved_stdout);
	saved_stdout = -1;

	free(captured);
	captured = testdir_read(capture_file, NULL);
	return captured ? captured : "";
}

static int has_line(const char *text, const char *wanted)
{
	size_t      length = strlen(wanted);
	const char *at = text;

	while (at && *at) {
		const char *end = strchr(at, '\n');
		size_t      run = end ? (size_t)(end - at) : strlen(at);

		if (run == length && memcmp(at, wanted, length) == 0) {
			return 1;
		}
		if (!end) {
			return 0;
		}
		at = end + 1;
	}
	return 0;
}

/*
 * Whether what was printed is one JSON object and nothing else.
 *
 * `--json` promises stdout is one value, and this verb prints as it goes.
 */
static int one_json_line(const char *text)
{
	size_t length = text ? strlen(text) : 0u;

	if (length < 3u || text[0] != '{' || text[length - 1u] != '\n') {
		return 0;
	}
	return strchr(text, '\n') == text + length - 1u && text[length - 2u] == '}';
}

static void line(const char *text, const char *wanted, const char *what)
{
	int found = has_line(text, wanted);

	check(found, what);
	if (!found) {
		detail("wanted", wanted);
	}
}

/* ------------------------------------------------------------------------ *
 * The fixture
 * ------------------------------------------------------------------------ */

/* The directory this test made; every path below is under it. */
static const char *root;
static char config_dir[320];
static char factory_dir[320];
static char run_dir[320];
static char input_file[512];
static ncfg_cli_options_t options;

static const char *base_config = "interface eth0 {\n\tconfig = \"dhcp\"\n}\n";

static void fixture(const char *text)
{
	char path[512];

	(void)snprintf(config_dir, sizeof(config_dir), "%s/etc", root);
	(void)snprintf(factory_dir, sizeof(factory_dir), "%s/factory", root);
	(void)snprintf(run_dir, sizeof(run_dir), "%s/run", root);
	(void)mkdir(config_dir, 0755);
	(void)mkdir(run_dir, 0755);
	(void)snprintf(path, sizeof(path), "%s/netcfgd.conf", config_dir);
	(void)testdir_write(path, text, strlen(text));

	memset(&options, 0, sizeof(options));
	options.config_dir = config_dir;
	options.factory_dir = factory_dir;
	options.run_dir = run_dir;
}

/* Take away what a case here can have written, by name. */
static void reset(void)
{
	static const char *const names[] = { "vpn", "corp-ca", "wg-key" };
	char                     path[512];
	size_t                   which;

	for (which = 0; which < sizeof(names) / sizeof(names[0]); which++) {
		(void)snprintf(path, sizeof(path), "%s/secrets/%s", config_dir, names[which]);
		(void)unlink(path);
	}
	(void)snprintf(path, sizeof(path), "%s/secrets", config_dir);
	(void)rmdir(path);
}

/*
 * Point standard input at a file holding `text`.
 *
 * `freopen` rather than a `dup2` onto descriptor 0, because the reader goes
 * through `stdin` and a descriptor swapped underneath a stream leaves whatever
 * the stream had already buffered in front of it.
 */
static void stdin_is(const char *text, size_t length)
{
	(void)testdir_write(input_file, text, length);
	if (!freopen(input_file, "rb", stdin)) {
		printf("could not point standard input at %s\n", input_file);
		exit(1);
	}
}

static void stdin_is_empty_again(void)
{
	(void)freopen("/dev/null", "rb", stdin);
}

/* ------------------------------------------------------------------------ *
 * Reading the value
 * ------------------------------------------------------------------------ */

/*
 * **A terminal gives one line; a redirect gives a file.**
 *
 * The first case is the whole of the defect: a PEM handed in on standard input
 * has to arrive whole, not truncated at its first newline.
 */
static void a_redirect_gives_the_whole_file(void)
{
	static const char *const pem =
	    "-----BEGIN CERTIFICATE-----\nMIIBogIBADAN\nBgkqhkiG9w0B\n"
	    "-----END CERTIFICATE-----\n";
	char *value = NULL;
	char  err[NCFG_ERROR_MAX];

	stdin_is(pem, strlen(pem));
	check(ncfg_cli_read_secret("value for `corp-ca`", &value, err, sizeof(err)),
	    "a credential arrives from a redirect");
	check(value != NULL && strlen(value) == strlen(pem) - 1u,
	    "and it is the whole file, not its first line");
	check(value != NULL && strstr(value, "-----END CERTIFICATE-----") != NULL,
	    "so a certificate arrives with its end in it");
	check(value != NULL && strchr(value, '\n') != NULL,
	    "and the newlines inside it are kept, since a PEM is made of them");
	free(value);
	stdin_is_empty_again();
}

/* One line terminator is stripped and no other whitespace is. */
static void one_terminator_comes_off_and_nothing_else_does(void)
{
	struct {
		const char *given;
		const char *wanted;
		const char *what;
	} cases[] = {
		{ "hunter2\n", "hunter2", "a trailing newline comes off" },
		{ "hunter2\r\n", "hunter2", "and so does a carriage return before it" },
		{ "hunter2", "hunter2", "a value with no terminator is itself" },
		{ "hunter2\n\n", "hunter2\n",
		    "and only one comes off, because the second is the value's" },
		{ "  padded  \n", "  padded  ",
		    "a secret may begin and end with a space, and keeps them" },
	};
	size_t which;

	for (which = 0; which < sizeof(cases) / sizeof(cases[0]); which++) {
		char *value = NULL;
		char  err[NCFG_ERROR_MAX];

		stdin_is(cases[which].given, strlen(cases[which].given));
		if (!ncfg_cli_read_secret("value", &value, err, sizeof(err))) {
			check(0, cases[which].what);
			detail("said", err);
			continue;
		}
		check(strcmp(value, cases[which].wanted) == 0, cases[which].what);
		if (strcmp(value, cases[which].wanted) != 0) {
			detail("wanted", cases[which].wanted);
			detail("got", value);
		}
		free(value);
	}
	stdin_is_empty_again();
}

static void nothing_given_is_a_refusal(void)
{
	char *value = NULL;
	char  err[NCFG_ERROR_MAX];

	stdin_is("", 0);
	err[0] = '\0';
	check(!ncfg_cli_read_secret("value for `vpn`", &value, err, sizeof(err)),
	    "an empty standard input is refused rather than stored");
	check(strstr(err, "nothing was given") != NULL, "and the sentence says so");
	check(value == NULL, "and nothing is handed back to free");
	stdin_is_empty_again();
}

/* ------------------------------------------------------------------------ *
 * `ncfg secret set`
 * ------------------------------------------------------------------------ */

static void a_name_that_is_not_a_filename_is_refused(void)
{
	static const char *const bad[] = { "", "../shadow", "a/b", ".hidden", "quote\"here",
		"back\\slash" };
	const char              *positional[2];
	char                     err[NCFG_ERROR_MAX];
	char                     path[512];
	size_t                   which;

	fixture(base_config);
	positional[0] = "set";
	for (which = 0; which < sizeof(bad) / sizeof(bad[0]); which++) {
		positional[1] = bad[which];
		err[0] = '\0';
		stdin_is(sentinel, strlen(sentinel));
		capture_begin();
		check(!ncfg_cli_secret(&options, positional, 2u, err, sizeof(err)),
		    "a name that cannot be a filename is refused");
		(void)capture_end();
		check(strstr(err, "cannot be used as a secret name") != NULL,
		    "and the sentence says which part of it was the problem");
		if (strstr(err, "cannot be used as a secret name") == NULL) {
			detail("said", err);
		}
	}
	stdin_is_empty_again();
	(void)snprintf(path, sizeof(path), "%s/secrets", config_dir);
	check(!testdir_exists(path), "and none of them created the directory");
	reset();
}

/*
 * One name, and never a value.
 *
 * `ps` shows an argument to every user on the machine and the shell writes it
 * to a history file, and neither is undone by noticing afterwards.
 */
static void the_value_is_never_an_argument(void)
{
	const char *positional[3];
	char        err[NCFG_ERROR_MAX];
	char        path[512];

	fixture(base_config);
	positional[0] = "set";
	positional[1] = "vpn";
	positional[2] = "hunter2";
	err[0] = '\0';
	capture_begin();
	check(!ncfg_cli_secret(&options, positional, 3u, err, sizeof(err)),
	    "a second argument is refused rather than taken as the value");
	(void)capture_end();
	check(strstr(err, "never an argument") != NULL, "and the sentence says why");
	(void)snprintf(path, sizeof(path), "%s/secrets/vpn", config_dir);
	check(!testdir_exists(path), "and nothing was written anyway");
	reset();
}

static void set_needs_a_name_and_names_the_reference_it_is_for(void)
{
	const char *positional[1];
	char        err[NCFG_ERROR_MAX];

	fixture(base_config);
	positional[0] = "set";
	err[0] = '\0';
	capture_begin();
	check(!ncfg_cli_secret(&options, positional, 1u, err, sizeof(err)),
	    "`secret set` with no name is refused");
	(void)capture_end();
	check(strstr(err, "@secret:vpn") != NULL,
	    "and the sentence shows what a name is for, which is the reference in the config");
	reset();
}

/*
 * The file is 0600 from the moment it exists, and the directory 0700.
 *
 * Asserted on the mode rather than on a `chmod` having been called, because the
 * window between creating and tightening is the thing that must not exist.
 */
static void what_it_writes_is_readable_by_nobody_else(void)
{
	const char *positional[2];
	const char *printed;
	char        err[NCFG_ERROR_MAX];
	char        path[512];
	char        directory[512];
	char       *stored;

	fixture(base_config);
	positional[0] = "set";
	positional[1] = "vpn";
	stdin_is(sentinel, strlen(sentinel));
	err[0] = '\0';
	capture_begin();
	check(ncfg_cli_secret(&options, positional, 2u, err, sizeof(err)),
	    "`secret set vpn` stores a credential");
	printed = capture_end();
	if (err[0] != '\0') {
		detail("said", err);
	}
	stdin_is_empty_again();

	(void)snprintf(path, sizeof(path), "%s/secrets/vpn", config_dir);
	(void)snprintf(directory, sizeof(directory), "%s/secrets", config_dir);
	check(testdir_mode(path) == 0600, "the secret is readable by nobody else");
	check(testdir_mode(directory) == 0700, "and so is the directory it sits in");

	stored = testdir_read(path, NULL);
	check(stored != NULL && strcmp(stored, sentinel) == 0,
	    "and what was stored is what was typed, byte for byte");
	free(stored);

	check(strstr(printed, "stored ") != NULL && strstr(printed, "(0600)") != NULL,
	    "it says what it wrote and at what mode");
	line(printed, "note: nothing in the configuration refers to `@secret:vpn` yet",
	    "and that nothing refers to it yet, which is how a typo becomes a sentence");

	/* **The rule.** Neither the output nor the error may carry the value. */
	check(strstr(printed, sentinel) == NULL, "and the value is nowhere in the output");
	check(strstr(err, sentinel) == NULL, "nor in the error buffer");

	/* A second `set` refuses rather than overwriting, because one of these is a
	 * key nobody can get back. */
	stdin_is(sentinel, strlen(sentinel));
	err[0] = '\0';
	capture_begin();
	check(!ncfg_cli_secret(&options, positional, 2u, err, sizeof(err)),
	    "a second `set` refuses rather than overwriting");
	printed = capture_end();
	check(strstr(err, "--replace") != NULL, "naming the flag");
	check(strstr(err, "0042") != NULL, "and the decision that says why it is a flag");
	check(strstr(err, sentinel) == NULL, "and still no value in the refusal");
	stdin_is_empty_again();

	/* The refusal happens before the prompt, so nothing was consumed. */
	options.replace = 1;
	stdin_is("second-value", strlen("second-value"));
	capture_begin();
	check(ncfg_cli_secret(&options, positional, 2u, err, sizeof(err)),
	    "and `--replace` overwrites it");
	printed = capture_end();
	check(strstr(printed, "replaced ") != NULL,
	    "saying `replaced` rather than `stored`, which is the fact a reader wants");
	stdin_is_empty_again();
	options.replace = 0;

	stored = testdir_read(path, NULL);
	check(stored != NULL && strcmp(stored, "second-value") == 0, "with the new value in it");
	check(testdir_mode(path) == 0600, "still readable by nobody else");
	free(stored);
	reset();
}

/*
 * The report's useful half: which blocks refer to this name.
 *
 * A secret whose name does not match the reference in the document is a file
 * that will be read by nothing, and the failure arrives later as "no such
 * secret" from a backend.
 */
static void the_report_says_what_refers_to_the_name(void)
{
	const char *positional[2];
	const char *printed;
	char        err[NCFG_ERROR_MAX];

	fixture("interface eth0 {\n\tconfig = \"dhcp\"\n}\n"
	    "device dsl0 {\n\tpppoe {\n\t\tparent = \"eth0\"\n\t\tusername = \"user\"\n"
	    "\t\tpassword = \"@secret:vpn\"\n\t}\n}\n");
	positional[0] = "set";
	positional[1] = "vpn";
	stdin_is(sentinel, strlen(sentinel));
	err[0] = '\0';
	capture_begin();
	check(ncfg_cli_secret(&options, positional, 2u, err, sizeof(err)),
	    "a credential the configuration names is stored");
	printed = capture_end();
	if (err[0] != '\0') {
		detail("said", err);
	}
	stdin_is_empty_again();
	check(strstr(printed, "used by:") != NULL, "and the report says what refers to it");
	check(strstr(printed, "dsl0") != NULL, "naming the block");
	check(strstr(printed, sentinel) == NULL, "and never the value");
	detail("report", printed);
	reset();
	fixture(base_config);
}

/*
 * A configuration that does not compile is not an error here.
 *
 * The secret is written either way: an operator storing a credential before
 * writing the block that names it is the ordinary order to do things in.
 */
static void a_config_that_does_not_compile_still_stores_the_secret(void)
{
	const char *positional[2];
	const char *printed;
	char        err[NCFG_ERROR_MAX];
	char        path[512];

	fixture("interface eth0 { nonsense = 1 }\n");
	positional[0] = "set";
	positional[1] = "vpn";
	stdin_is(sentinel, strlen(sentinel));
	err[0] = '\0';
	capture_begin();
	check(ncfg_cli_secret(&options, positional, 2u, err, sizeof(err)),
	    "a configuration that does not compile does not stop the write");
	printed = capture_end();
	stdin_is_empty_again();
	(void)snprintf(path, sizeof(path), "%s/secrets/vpn", config_dir);
	check(testdir_exists(path), "and the credential is there");
	check(strstr(printed, "stored ") != NULL, "and it said so");
	check(strstr(printed, "used by:") == NULL,
	    "with nothing claimed about who refers to it, since nothing could be read");
	reset();
	fixture(base_config);
}

/*
 * The document, and the canary swept through it.
 *
 * Three shapes of `used_by` in one case, because the difference between them
 * is the whole reason the member is written the way it is: a name nothing
 * refers to gets `[]` from a configuration that compiled, a name something
 * refers to gets the blocks, and a configuration that would not compile gets
 * **no member at all** -- the text says nothing there too, and an empty list
 * would be this command reporting an emptiness it never looked at.
 */
static void json_says_what_was_stored_and_never_the_value(void)
{
	const char *positional[2];
	const char *printed;
	char        err[NCFG_ERROR_MAX];
	char        path[512];
	char        wanted[700];
	char       *stored;

	fixture(base_config);
	options.json = 1;
	positional[0] = "set";
	positional[1] = "vpn";
	(void)snprintf(path, sizeof(path), "%s/secrets/vpn", config_dir);

	stdin_is(sentinel, strlen(sentinel));
	err[0] = '\0';
	capture_begin();
	check(ncfg_cli_secret(&options, positional, 2u, err, sizeof(err)),
	    "`secret set vpn --json` stores a credential");
	printed = capture_end();
	stdin_is_empty_again();
	if (err[0] != '\0') {
		detail("said", err);
	}
	check(one_json_line(printed), "  one object on one line and nothing else");
	(void)snprintf(wanted, sizeof(wanted),
	    "{\"name\":\"vpn\",\"path\":\"%s\",\"replaced\":false,\"daemon\":false,"
	    "\"used_by\":[]}", path);
	line(printed, wanted,
	    "  the name, where the `file` provider will look, and that nothing refers to it");
	check(strstr(printed, "stored ") == NULL && strstr(printed, "(0600)") == NULL &&
	    strstr(printed, "note:") == NULL,
	    "  and not one line of the table survived beside it");

	/*
	 * **Non-vacuity.** The sweep below means nothing unless the value really
	 * travelled through this command, so it is read back out of the file it
	 * was meant for, byte for byte, first.
	 */
	stored = testdir_read(path, NULL);
	check(stored != NULL && strcmp(stored, sentinel) == 0,
	    "  the value is in the file it was meant for, byte for byte");
	free(stored);
	check(printed[0] != '\0', "  and the sweep has something to sweep");
	check(strstr(printed, sentinel) == NULL, "  and the document does not carry it");
	check(strstr(err, sentinel) == NULL, "  nor the error buffer");

	/* `--replace` is the other value of the member the text says in a word. */
	options.replace = 1;
	stdin_is(sentinel, strlen(sentinel));
	capture_begin();
	check(ncfg_cli_secret(&options, positional, 2u, err, sizeof(err)),
	    "`--replace` overwrites it");
	printed = capture_end();
	stdin_is_empty_again();
	options.replace = 0;
	check(strstr(printed, "\"replaced\":true") != NULL,
	    "  and the document says `replaced`, which is the fact a reader wants");
	check(strstr(printed, sentinel) == NULL, "  still with no value anywhere in it");
	reset();

	/* A configuration that names it: the blocks, spelled as the table spells
	 * them. */
	fixture("interface eth0 {\n\tconfig = \"dhcp\"\n}\n"
	    "device dsl0 {\n\tpppoe {\n\t\tparent = \"eth0\"\n\t\tusername = \"user\"\n"
	    "\t\tpassword = \"@secret:vpn\"\n\t}\n}\n");
	options.json = 1;
	stdin_is(sentinel, strlen(sentinel));
	capture_begin();
	check(ncfg_cli_secret(&options, positional, 2u, err, sizeof(err)),
	    "a credential the configuration names is stored");
	printed = capture_end();
	stdin_is_empty_again();
	check(strstr(printed, "\"used_by\":[\"") != NULL && strstr(printed, "dsl0") != NULL,
	    "  and `used_by` names the block, in the socket's own word for it");
	check(strstr(printed, sentinel) == NULL, "  and still never the value");
	detail("document", printed);
	reset();

	/* A configuration that does not compile: no member at all. */
	fixture("interface eth0 { nonsense = 1 }\n");
	options.json = 1;
	stdin_is(sentinel, strlen(sentinel));
	capture_begin();
	check(ncfg_cli_secret(&options, positional, 2u, err, sizeof(err)),
	    "a configuration that does not compile does not stop the write");
	printed = capture_end();
	stdin_is_empty_again();
	check(testdir_exists(path), "  and the credential is there");
	check(strstr(printed, "\"used_by\"") == NULL,
	    "  with no `used_by` at all, because nothing could be read to look in");
	check(strstr(printed, "\"name\":\"vpn\"") != NULL,
	    "  and the rest of the answer is still an answer");
	check(strstr(printed, sentinel) == NULL, "  and still never the value");
	options.json = 0;
	reset();
	fixture(base_config);
}

/*
 * A name that is not valid UTF-8 fails the command and prints nothing.
 *
 * 0263's rule reaching a verb that writes. The JSON writer refuses the string
 * rather than repairing it -- every repair puts a value in front of somebody
 * that nobody typed -- and `ncfg_buf_t` hands out the empty string for a
 * buffer that failed, so a caller that printed anyway would emit half an
 * object that looks whole.
 *
 * **The credential is on disk when this fails**, which is why the sentence has
 * to say that what stopped is the rendering: a reader told only that a
 * document could not be written concludes the write did not happen and stores
 * the value somewhere else.
 */
static void a_name_that_is_not_utf8_fails_the_rendering_and_not_the_write(void)
{
	const char *positional[2];
	const char *printed;
	char        name[8];
	char        path[512];
	char        err[NCFG_ERROR_MAX];

	fixture(base_config);
	/* One stray octet in the middle, which is the shape that arrives off a
	 * command line rather than a shape anybody types. */
	(void)snprintf(name, sizeof(name), "vp?n");
	name[2] = (char)0xffu;
	options.json = 1;
	positional[0] = "set";
	positional[1] = name;
	stdin_is(sentinel, strlen(sentinel));
	err[0] = '\0';
	capture_begin();
	check(!ncfg_cli_secret(&options, positional, 2u, err, sizeof(err)),
	    "a name that is not valid UTF-8 fails the command under `--json`");
	printed = capture_end();
	stdin_is_empty_again();
	check(printed[0] == '\0',
	    "  and nothing at all is printed, never half an object that looks whole");
	check(strstr(err, "not UTF-8") != NULL,
	    "  the sentence names the rule that stopped it");
	check(strstr(err, "already done what it was asked") != NULL,
	    "  and says the command happened, so nobody stores the value twice");
	check(strstr(err, "without `--json`") != NULL,
	    "  and points at the form that has no such rule");
	check(strstr(err, sentinel) == NULL, "  and still never the value");
	(void)snprintf(path, sizeof(path), "%s/secrets/%s", config_dir, name);
	check(testdir_exists(path),
	    "  and the credential really is on disk, which is what makes that clause true");

	/* Without the flag the same name renders, because a table is text for a
	 * terminal and has no such rule. */
	options.json = 0;
	options.replace = 1;
	stdin_is(sentinel, strlen(sentinel));
	err[0] = '\0';
	capture_begin();
	check(ncfg_cli_secret(&options, positional, 2u, err, sizeof(err)),
	    "and the same command without `--json` succeeds");
	printed = capture_end();
	stdin_is_empty_again();
	options.replace = 0;
	check(strstr(printed, "replaced ") != NULL, "  printing the table it always did");
	check(strstr(printed, sentinel) == NULL, "  and still never the value");
	(void)unlink(path);
	reset();
}

/*
 * There is no `ncfg secret get`, and that is the point.
 *
 * The whole of a secret reference is that the value travels to the backend that
 * needs it and nowhere else (0075).
 */
static void there_is_no_way_to_read_one_back(void)
{
	static const char *const asked[] = { "get", "show", "print" };
	const char              *positional[2];
	char                     err[NCFG_ERROR_MAX];
	size_t                   which;

	fixture(base_config);
	for (which = 0; which < sizeof(asked) / sizeof(asked[0]); which++) {
		positional[0] = asked[which];
		err[0] = '\0';
		check(!ncfg_cli_secret(&options, positional, 1u, err, sizeof(err)),
		    "`ncfg secret get` is refused rather than absent");
		check(strstr(err, "that is the point") != NULL,
		    "and says why, rather than reading as an unimplemented command");
	}

	positional[0] = "rm";
	err[0] = '\0';
	check(!ncfg_cli_secret(&options, positional, 1u, err, sizeof(err)),
	    "and a subcommand this port does not have is named");
	check(strstr(err, "there is one: set") != NULL, "saying what there is");
	detail("said", err);

	err[0] = '\0';
	check(!ncfg_cli_secret(&options, positional, 0u, err, sizeof(err)),
	    "`ncfg secret` with nothing after it is refused");
	check(strstr(err, "needs a subcommand") != NULL, "and asks for one");
	reset();
}

int main(void)
{
	report_opens_before_any_capture();
	(void)testdir_make("cli-secret");
	root = testdir_path;
	(void)snprintf(capture_file, sizeof(capture_file), "%s/out", testdir_path);
	(void)snprintf(input_file, sizeof(input_file), "%s/in", testdir_path);
	fixture(base_config);

	a_redirect_gives_the_whole_file();
	one_terminator_comes_off_and_nothing_else_does();
	nothing_given_is_a_refusal();

	a_name_that_is_not_a_filename_is_refused();
	the_value_is_never_an_argument();
	set_needs_a_name_and_names_the_reference_it_is_for();
	what_it_writes_is_readable_by_nobody_else();
	the_report_says_what_refers_to_the_name();
	a_config_that_does_not_compile_still_stores_the_secret();
	json_says_what_was_stored_and_never_the_value();
	a_name_that_is_not_utf8_fails_the_rendering_and_not_the_write();
	there_is_no_way_to_read_one_back();

	{
		char path[512];

		(void)snprintf(path, sizeof(path), "%s/etc/netcfgd.conf", root);
		(void)unlink(path);
		(void)snprintf(path, sizeof(path), "%s/etc", root);
		(void)rmdir(path);
	}
	free(captured);
	testdir_remove(testdir_path);

	if (failures == 0) {
		(void)fprintf(report, "cli_secret_test: all checks passed\n");
	} else {
		(void)fprintf(report, "cli_secret_test: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
