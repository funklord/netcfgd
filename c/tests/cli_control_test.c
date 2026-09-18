/*
 * cli_control_test.c -- `ncfg control`, and the client half underneath it.
 *
 * WHY THE SPLICE IS THE LARGEST PART OF THIS FILE
 *   `ncfg control set` edits a file somebody else wrote, on the machine whose
 *   bootstrap depends on the command working, and the file it edits is the one
 *   that decides who may configure the network. Every case below is a shape
 *   that makes a naive scanner find the wrong end of a block: a brace in a
 *   string, a brace in a comment, a head that is a prefix of a longer word.
 *   The damage from getting one wrong is silent, which is why they are here
 *   rather than left to the invariant that catches them afterwards.
 *
 * WHY THE HELPER'S GRAMMAR IS A LIST OF REFUSALS
 *   That parser runs as root. What matters is not that `set` works -- it is
 *   that nothing else does, and that a refusal happens before anything is
 *   written. Every line in the list was chosen because it is a shape somebody
 *   would try if they found the pipe: a shell command, a path, a file, an
 *   extra argument, a missing one.
 *
 * WHAT THIS DOES NOT DO
 *   **Nothing talks to the running daemon.** The machine this builds on is the
 *   reporting machine, with its real network on it and a real netcfgd on a
 *   real socket. Every fixture here names its own config, factory and run
 *   directories, and the socket conversation is against a fake on an `AF_UNIX`
 *   socket in a directory this test made.
 */
#include "ncfg/cli.h"

#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/config.h"
#include "ncfg/document.h"
#include "ncfg/hooks.h"
#include "ncfg/render.h"

#include "testdir.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
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

/* ------------------------------------------------------------------------ *
 * Capturing what the program printed
 * ------------------------------------------------------------------------ *
 *
 * Every line `ncfg` prints goes through `ncfg_out_*`, which writes to `stdout`
 * and leaves at 141 when the reader has gone (0261). So the only honest way to
 * assert the output is to *be* the reader: file descriptor 1 is pointed at a
 * file in this test's own directory, the command runs, and the descriptor is
 * put back.
 */

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

/* Whether `text` holds `wanted` as a whole line. */
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

static void line(const char *text, const char *wanted, const char *what)
{
	int found = has_line(text, wanted);

	check(found, what);
	if (!found) {
		detail("wanted", wanted);
	}
}

/* How many times `needle` appears. */
static size_t times(const char *text, const char *needle)
{
	size_t      count = 0;
	const char *at = text;

	while ((at = strstr(at, needle)) != NULL) {
		count++;
		at += strlen(needle);
	}
	return count;
}

/* ------------------------------------------------------------------------ *
 * Fixtures
 * ------------------------------------------------------------------------ */

/* The directory this test made; every path below is under it. */
static const char *root;
static char config_dir[320];
static char factory_dir[320];
static char run_dir[320];

/*
 * A config directory with a compilable document and nothing else.
 *
 * `factory` and `run` are named even though nothing is put in them, because a
 * fixture that leaves one unset gets the machine's own: `/etc/netcfgd`,
 * `/usr/share/netcfgd` and the socket of the netcfgd that is running on the
 * developer's laptop.
 */
static void fixture(const ncfg_cli_options_t **out, const char *base_text)
{
	static ncfg_cli_options_t options;
	char                      path[512];

	(void)snprintf(config_dir, sizeof(config_dir), "%s/etc", root);
	(void)snprintf(factory_dir, sizeof(factory_dir), "%s/factory", root);
	(void)snprintf(run_dir, sizeof(run_dir), "%s/run", root);
	(void)mkdir(config_dir, 0755);
	(void)mkdir(run_dir, 0755);
	(void)snprintf(path, sizeof(path), "%s/netcfgd.conf", config_dir);
	(void)testdir_write(path, base_text, strlen(base_text));

	memset(&options, 0, sizeof(options));
	options.config_dir = config_dir;
	options.factory_dir = factory_dir;
	options.run_dir = run_dir;
	*out = &options;
}

/* Take the whole `etc` tree away, so the next fixture starts clean. */
static void fixture_clear(void)
{
	char path[512];

	(void)snprintf(path, sizeof(path), "%s/etc/conf.d/00-control.conf", root);
	(void)unlink(path);
	(void)snprintf(path, sizeof(path), "%s/etc/conf.d", root);
	(void)rmdir(path);
	(void)snprintf(path, sizeof(path), "%s/etc/netcfgd.conf", root);
	(void)unlink(path);
	(void)snprintf(path, sizeof(path), "%s/factory/netcfgd.conf", root);
	(void)unlink(path);
	(void)snprintf(path, sizeof(path), "%s/factory", root);
	(void)rmdir(path);
}

static const char *base_config = "interface eth0 {\n\tconfig = \"dhcp\"\n}\n";

/* The policy the splice cases are asked to write. */
static void policy(ncfg_control_t *control)
{
	char why[NCFG_ERROR_MAX];

	memset(control, 0, sizeof(*control));
	(void)ncfg_cli_principal_parse("group:netcfgd", &control->observe, why, sizeof(why));
	(void)ncfg_cli_principal_parse("any", &control->wifi, why, sizeof(why));
	(void)ncfg_cli_principal_parse("root", &control->admin, why, sizeof(why));
}

static void policy_free(ncfg_control_t *control)
{
	free(control->observe.name);
	free(control->wifi.name);
	free(control->admin.name);
	memset(control, 0, sizeof(*control));
}

/* ------------------------------------------------------------------------ *
 * Principals
 * ------------------------------------------------------------------------ */

/*
 * Four shapes, and the spelling the configuration language uses.
 *
 * **The round trip is checked against the renderer rather than against
 * itself.** `cli.h` says why this rule is spelled here at all -- the model
 * carries neither half in C -- and a copy that agreed only with its own tests
 * is exactly how one access point's name came to be spelled three ways. So the
 * policy goes through a real compile and a real render, and the line that
 * comes out has to be the one this wrote.
 */
static void a_principal_is_spelled_one_way(void)
{
	static const char *const good[] = { "root", "any", "user:alice", "group:netcfgd" };
	static const char *const bad[] = { "", "user:", "group:", "bogus", "/etc/passwd",
		"user", "USER:alice" };
	size_t which;

	for (which = 0; which < sizeof(good) / sizeof(good[0]); which++) {
		ncfg_principal_t parsed;
		char             rendered[128];
		char             why[NCFG_ERROR_MAX];

		memset(&parsed, 0, sizeof(parsed));
		if (!ncfg_cli_principal_parse(good[which], &parsed, why, sizeof(why))) {
			check(0, "a principal the language has is parsed");
			detail("refused", good[which]);
			continue;
		}
		(void)ncfg_cli_principal_render(&parsed, rendered, sizeof(rendered));
		check(strcmp(rendered, good[which]) == 0,
		    "a principal renders back to what it was parsed from");
		if (strcmp(rendered, good[which]) != 0) {
			detail("wanted", good[which]);
			detail("got", rendered);
		}
		free(parsed.name);
	}
	for (which = 0; which < sizeof(bad) / sizeof(bad[0]); which++) {
		ncfg_principal_t parsed;
		char             why[NCFG_ERROR_MAX];
		int              took;

		memset(&parsed, 0, sizeof(parsed));
		took = ncfg_cli_principal_parse(bad[which], &parsed, why, sizeof(why));
		check(!took, "a principal the language does not have is refused");
		if (took) {
			detail("accepted", bad[which]);
			free(parsed.name);
		}
	}
}

/* And the renderer writes the same word into a configuration file. */
static void the_renderer_agrees_about_how_a_principal_is_written(void)
{
	static const char *const text =
	    "global {\n\tcontrol {\n\t\tobserve = \"group:netcfgd\"\n\t\twifi = \"user:alice\"\n"
	    "\t\tadmin = \"any\"\n\t}\n}\n";
	ncfg_config_file_t    file;
	ncfg_config_sources_t sources;
	ncfg_document_t      *document;
	ncfg_buf_t            written;
	ncfg_unrenderable_t   missing;
	char                  err[NCFG_ERROR_MAX];
	char                  rendered[128];

	file.name = (char *)(uintptr_t)"netcfgd.conf";
	file.text = (char *)(uintptr_t)text;
	file.length = strlen(text);
	sources.at = &file;
	sources.count = 1;
	sources.capacity = 1;

	document = ncfg_config_compile(&sources, ncfg_hook_sink_unwritten(), NULL, err,
	    sizeof(err));
	if (!document) {
		check(0, "the witness policy compiles");
		detail("said", err);
		return;
	}
	(void)ncfg_cli_principal_render(&document->globals.control.observe, rendered,
	    sizeof(rendered));
	check(strcmp(rendered, "group:netcfgd") == 0,
	    "what the compiler read back is what this renders");

	ncfg_buf_init(&written, 0);
	ncfg_unrenderable_init(&missing);
	if (ncfg_render(document, NULL, &written, &missing, err, sizeof(err))) {
		check(strstr(ncfg_buf_text(&written), "observe = \"group:netcfgd\"") != NULL,
		    "and the configuration renderer writes the same word");
		check(strstr(ncfg_buf_text(&written), "wifi = \"user:alice\"") != NULL,
		    "for a user as well as a group");
	} else {
		check(0, "the witness policy renders");
		detail("said", err);
	}
	ncfg_unrenderable_free(&missing);
	ncfg_buf_free(&written);
	ncfg_document_free(document);
}

/*
 * The drop-in this writes is ordinary configuration, and says so.
 *
 * **The comment is the part that matters and is the part nothing else checks.**
 * The file decides who may configure the network, and an operator who wants the
 * root-only default back has to be told that deleting it is how. A block with
 * no comment above it would compile exactly as well and leave them guessing --
 * so the text is asserted, and then compiled, so that neither half can be
 * right while the other is wrong.
 */
static void the_drop_in_it_writes_says_how_to_undo_it(void)
{
	ncfg_control_t        control;
	ncfg_buf_t            text;
	ncfg_config_file_t    file;
	ncfg_config_sources_t sources;
	ncfg_document_t      *document;
	char                  err[NCFG_ERROR_MAX];
	char                  rendered[128];

	policy(&control);
	ncfg_buf_init(&text, 0);
	ncfg_cli_control_render(&control, &text);
	check(!ncfg_buf_failed(&text), "the drop-in renders");
	check(strstr(ncfg_buf_text(&text), "Written by `ncfg control set`") != NULL,
	    "and says what wrote it");
	check(strstr(ncfg_buf_text(&text),
	    "delete it. Deleting it restores the default, which is root only.") != NULL,
	    "and that deleting it restores the root-only default");
	check(strstr(ncfg_buf_text(&text), "observe -- ask what the network looks like") != NULL,
	    "and says what each tier is for, since nothing else will");

	file.name = (char *)(uintptr_t)"00-control.conf";
	file.text = (char *)(uintptr_t)ncfg_buf_text(&text);
	file.length = text.length;
	sources.at = &file;
	sources.count = 1;
	sources.capacity = 1;
	document = ncfg_config_compile(&sources, ncfg_hook_sink_unwritten(), NULL, err,
	    sizeof(err));
	if (document) {
		(void)ncfg_cli_principal_render(&document->globals.control.observe, rendered,
		    sizeof(rendered));
		check(strcmp(rendered, "group:netcfgd") == 0,
		    "and what it compiles to is the policy it was given");
		ncfg_document_free(document);
	} else {
		check(0, "the drop-in it writes compiles");
		detail("said", err);
	}
	ncfg_buf_free(&text);
	policy_free(&control);
}

/* ------------------------------------------------------------------------ *
 * Splicing into a file somebody wrote
 * ------------------------------------------------------------------------ */

/* Splice, and hand back the text, which the caller frees. */
static char *spliced(const char *text, const char **why_out)
{
	static char    why[NCFG_ERROR_MAX];
	ncfg_control_t control;
	ncfg_buf_t     out;
	char          *result = NULL;

	why[0] = '\0';
	policy(&control);
	if (ncfg_cli_control_splice(text, &control, &out, why, sizeof(why))) {
		size_t length = out.length;

		result = malloc(length + 1u);
		if (result) {
			memcpy(result, ncfg_buf_text(&out), length + 1u);
		}
	}
	if (why_out) {
		*why_out = why;
	}
	ncfg_buf_free(&out);
	policy_free(&control);
	return result;
}

/* A block that is not there is inserted, and everything else is kept. */
static void a_missing_control_block_is_inserted_without_touching_the_rest(void)
{
	char *out = spliced("# mine\nglobal {\n\tdns { mode = \"none\" }\n}\n\n"
	    "interface eth0 { }\n", NULL);

	if (!out) {
		check(0, "a `global` block with no `control` in it splices");
		return;
	}
	check(strstr(out, "# mine") != NULL, "a comment before the block is kept");
	check(strstr(out, "dns { mode = \"none\" }") != NULL, "and so is the block beside it");
	check(strstr(out, "interface eth0 { }") != NULL, "and everything after the block");
	check(strstr(out, "observe = \"group:netcfgd\"") != NULL, "and the policy went in");
	free(out);
}

/* One that is there is replaced rather than added beside. */
static void an_existing_control_block_is_replaced_not_doubled(void)
{
	char *out = spliced("global {\n\tcontrol {\n\t\tobserve = \"root\"\n\t}\n"
	    "\tdns { mode = \"none\" }\n}\n", NULL);

	if (!out) {
		check(0, "a `global` block with a `control` in it splices");
		return;
	}
	check(times(out, "control {") == 1, "one control block, not two");
	check(strstr(out, "observe = \"group:netcfgd\"") != NULL, "with the new policy in it");
	check(strstr(out, "observe = \"root\"") == NULL, "and the old one gone");
	check(strstr(out, "dns { mode = \"none\" }") != NULL, "and the block beside it kept");
	free(out);
}

/*
 * A brace inside a string is not a brace.
 *
 * An SSID may be written `"weird {name}"`, and a scanner that counted it would
 * find the wrong end of the block and splice into somebody else's network.
 */
static void a_brace_inside_a_string_does_not_move_the_end_of_the_block(void)
{
	char *out = spliced("global {\n\tdns { mode = \"none\" }\n}\n"
	    "network \"weird {name}\" {\n\twifi { open = true }\n}\n", NULL);
	const char *network;

	if (!out) {
		check(0, "a file with a brace in a string splices");
		return;
	}
	check(strstr(out, "network \"weird {name}\" {") != NULL, "the network is untouched");
	check(strstr(out, "wifi { open = true }") != NULL, "and so is what is inside it");
	network = strstr(out, "\nnetwork");
	check(network != NULL, "the network is still there at all");
	if (network) {
		char head[4096];
		size_t length = (size_t)(network - out);

		if (length < sizeof(head)) {
			memcpy(head, out, length);
			head[length] = '\0';
			check(strstr(head, "control {") != NULL,
			    "and the policy went into `global`, not into the network");
		}
	}
	free(out);
}

/* `controller` is not `control`. */
static void a_head_is_a_word_and_not_a_prefix(void)
{
	char *out = spliced("global {\n\tcontroller { x = \"y\" }\n}\n", NULL);

	if (!out) {
		check(0, "a file with a `controller` block splices");
		return;
	}
	check(strstr(out, "controller { x = \"y\" }") != NULL, "`controller` is left alone");
	check(times(out, "control {") == 1, "and one `control` block was added beside it");
	free(out);
}

/*
 * **A comment that mentions a block is not a block, and in the Rust it is.**
 *
 * `block_span` there is `str::find` plus a check of the character before the
 * match, with no notion of a string or a comment -- so `# the control { block`
 * inside `global` is found as the block, `matching_brace` counts from a brace
 * that is inside a comment, and the span runs to the end of `global`. Spliced,
 * that deletes everything between the comment and the closing brace. The
 * invariant in `splice_into` catches the result and puts the file back, so
 * nothing is lost -- what is lost is the command, on the one machine whose
 * bootstrap is `ncfg control set`.
 */
static void a_comment_that_mentions_a_block_is_not_a_block(void)
{
	char *out = spliced("global {\n\t# the control { block is written by ncfg\n"
	    "\tdns { mode = \"none\" }\n}\n\ninterface eth0 { }\n", NULL);

	if (!out) {
		check(0, "a file whose comment mentions a block splices");
		return;
	}
	check(strstr(out, "dns { mode = \"none\" }") != NULL,
	    "a block after a comment naming `control {` survives the splice");
	check(strstr(out, "# the control { block is written by ncfg") != NULL,
	    "and the comment itself is kept");
	check(strstr(out, "interface eth0 { }") != NULL, "and so is the rest of the file");
	check(times(out, "control {") == 2,
	    "the comment's mention and the block, which is two and not one");
	free(out);
}

/* And a `global` that is only mentioned is not a `global` block. */
static void a_file_with_no_global_block_says_so(void)
{
	const char *why = NULL;
	char       *out = spliced("# global is not set here\ninterface eth0 { }\n", &why);

	check(out == NULL, "a file with no `global` block is refused rather than guessed at");
	check(why && strstr(why, "no `global` block") != NULL, "and the sentence says which");
	free(out);
}

/* ------------------------------------------------------------------------ *
 * The privileged helper's grammar
 * ------------------------------------------------------------------------ */

static void the_helper_accepts_one_verb_and_three_principals(void)
{
	static const char *const refused[] = { "", "   ", "rm -rf /", "show",
		"SET root root root", "set", "set root", "set root root",
		"set root root root extra", "set bogus root root", "set user: root root",
		"set group: root root", "set /etc/passwd root root", "set root root root; sh",
		"setx root root root" };
	const ncfg_cli_options_t *options;
	char                      path[NCFG_ERROR_MAX];
	char                      why[NCFG_ERROR_MAX];
	char                      written[512];
	char                     *before;
	size_t                    which;

	fixture(&options, base_config);
	capture_begin();
	check(ncfg_cli_control_command("set group:netcfgd any root", options, path, sizeof(path),
	    why, sizeof(why)), "the one command the helper exists for works");
	(void)capture_end();

	(void)snprintf(written, sizeof(written), "%s/conf.d/00-control.conf", config_dir);
	before = testdir_read(written, NULL);
	check(before != NULL, "and it wrote a policy");

	for (which = 0; which < sizeof(refused) / sizeof(refused[0]); which++) {
		char *now;

		capture_begin();
		check(!ncfg_cli_control_command(refused[which], options, path, sizeof(path), why,
		    sizeof(why)), "the helper refuses everything that is not `set`");
		(void)capture_end();
		if (!before) {
			continue;
		}
		/*
		 * "Returned an error" and "changed nothing" are different claims, and
		 * it is the second that matters when the process making the change is
		 * root.
		 */
		now = testdir_read(written, NULL);
		check(now != NULL && strcmp(now, before) == 0,
		    "and a refused command leaves the policy exactly as it was");
		if (!now || strcmp(now, before) != 0) {
			detail("after", refused[which]);
		}
		free(now);
	}
	free(before);
	fixture_clear();
}

/* ------------------------------------------------------------------------ *
 * `ncfg control show|set`
 * ------------------------------------------------------------------------ */

static void show_prints_three_tiers_and_says_what_root_only_means(void)
{
	const ncfg_cli_options_t *options;
	const char               *positional[1];
	const char               *printed;
	char                      err[NCFG_ERROR_MAX];

	fixture(&options, base_config);
	positional[0] = "show";
	capture_begin();
	check(ncfg_cli_control(options, positional, 1u, err, sizeof(err)), "`control show` runs");
	printed = capture_end();
	line(printed, "observe  root", "a default policy is root at every tier");
	line(printed, "wifi     root", "including wifi");
	line(printed, "admin    root", "including admin");
	line(printed, "every tier is root, so the socket is root-only and no client run",
	    "and the note says why no client can reach the socket");
	fixture_clear();
}

static void set_writes_the_drop_in_it_owns_and_reports_the_path(void)
{
	ncfg_cli_options_t options;
	const char        *positional[1];
	const char        *printed;
	char               expected[512];
	char               err[NCFG_ERROR_MAX];
	const ncfg_cli_options_t *base;

	fixture(&base, base_config);
	options = *base;
	options.control.observe = "group:netcfgd";
	positional[0] = "set";

	capture_begin();
	check(ncfg_cli_control(&options, positional, 1u, err, sizeof(err)), "`control set` runs");
	printed = capture_end();

	/* The path this composes to read the previous contents has to be the path
	 * the installer writes, or a failed verification would put bytes back into
	 * a file nobody wrote. */
	(void)snprintf(expected, sizeof(expected), "%s/conf.d/00-control.conf", config_dir);
	line(printed, expected, "it reports the drop-in it owns, by the path it composed");
	check(testdir_exists(expected), "and the file is there");
	line(printed, "observe  group:netcfgd", "the tier that was named changed");
	line(printed, "wifi     root", "and one that was not is left alone");
	line(printed, "netcfgd applies this when it next reads its configuration. A member of",
	    "and a policy beyond root says what still has to happen");

	/* And what was written compiles back to the policy that was asked for,
	 * which is what `verify` refuses to skip. */
	capture_begin();
	positional[0] = "show";
	(void)ncfg_cli_control(&options, positional, 1u, err, sizeof(err));
	printed = capture_end();
	line(printed, "observe  group:netcfgd", "and `control show` reads it back");
	fixture_clear();
}

/*
 * Whether what was printed is one JSON object and nothing else.
 *
 * The contract `--json` makes is that stdout is one value, so a prose line
 * surviving beside the document is the flag being half-answered rather than an
 * untidiness -- and these verbs print as they go, which is why it is checked.
 */
static int one_json_line(const char *text)
{
	size_t length = text ? strlen(text) : 0u;

	if (length < 3u || text[0] != '{' || text[length - 1u] != '\n') {
		return 0;
	}
	return strchr(text, '\n') == text + length - 1u && text[length - 2u] == '}';
}

/*
 * `--json` at both subcommands: the three tiers, and the file `set` wrote.
 *
 * The principal is rendered by `ncfg_cli_principal_render`, so the document
 * and the configuration file spell `group:NAME` the same way by construction
 * -- a fourth spelling in the one output a script parses is exactly the drift
 * this file's other cases exist to prevent.
 */
static void json_prints_the_tiers_and_nothing_addressed_to_a_person(void)
{
	ncfg_cli_options_t        options;
	const ncfg_cli_options_t *base;
	const char               *positional[1];
	const char               *printed;
	char                      expected[512];
	char                      wanted[600];
	char                      err[NCFG_ERROR_MAX];

	fixture(&base, base_config);
	options = *base;
	options.json = 1;
	positional[0] = "show";
	capture_begin();
	check(ncfg_cli_control(&options, positional, 1u, err, sizeof(err)),
	    "`control show --json` runs");
	printed = capture_end();
	check(one_json_line(printed), "  it prints one object on one line and nothing else");
	line(printed, "{\"observe\":\"root\",\"wifi\":\"root\",\"admin\":\"root\"}",
	    "  the three tiers, in the order the block writes them");
	check(strstr(printed, "every tier is root") == NULL,
	    "  and the paragraph explaining root-only is not on the stream");
	check(strstr(printed, "\"path\"") == NULL,
	    "  and `show` names no file: it compiled the whole layered configuration");

	options.control.observe = "group:netcfgd";
	positional[0] = "set";
	capture_begin();
	check(ncfg_cli_control(&options, positional, 1u, err, sizeof(err)),
	    "`control set --json` runs");
	printed = capture_end();
	check(one_json_line(printed), "  it prints one object on one line and nothing else");
	(void)snprintf(expected, sizeof(expected), "%s/conf.d/00-control.conf", config_dir);
	(void)snprintf(wanted, sizeof(wanted), "\"path\":\"%s\"", expected);
	check(strstr(printed, wanted) != NULL,
	    "  and names the drop-in it wrote, which the table printed on its own line");
	check(testdir_exists(expected), "  and the file is there");
	check(strstr(printed, "\"observe\":\"group:netcfgd\"") != NULL,
	    "  the tier that was named is spelled as the renderer spells it");
	check(strstr(printed, "\"wifi\":\"root\"") != NULL,
	    "  and one that was not is left alone");
	check(strstr(printed, "netcfgd applies this") == NULL &&
	    strstr(printed, "log out") == NULL,
	    "  and what an operator still has to do is not a member of the answer");

	/* Read back through the flag as well, so the write and the read agree
	 * about the spelling rather than about the table's columns. */
	positional[0] = "show";
	capture_begin();
	(void)ncfg_cli_control(&options, positional, 1u, err, sizeof(err));
	printed = capture_end();
	check(strstr(printed, "\"observe\":\"group:netcfgd\"") != NULL,
	    "  and `control show --json` reads back what `set --json` wrote");
	fixture_clear();
}

static void set_with_no_tier_named_refuses(void)
{
	const ncfg_cli_options_t *options;
	const char               *positional[1];
	char                      err[NCFG_ERROR_MAX];

	fixture(&options, base_config);
	positional[0] = "set";
	err[0] = '\0';
	check(!ncfg_cli_control(options, positional, 1u, err, sizeof(err)),
	    "`control set` with nothing named is refused");
	check(strstr(err, "--observe") != NULL && strstr(err, "control show") != NULL,
	    "and the sentence names the flags and how to read the policy now");
	fixture_clear();
}

static void an_unknown_subcommand_is_named_and_helper_is_not_offered(void)
{
	const ncfg_cli_options_t *options;
	const char               *positional[1];
	char                      err[NCFG_ERROR_MAX];

	fixture(&options, base_config);
	positional[0] = "wibble";
	err[0] = '\0';
	check(!ncfg_cli_control(options, positional, 1u, err, sizeof(err)),
	    "an unknown control subcommand is refused");
	check(strstr(err, "wibble") != NULL && strstr(err, "`show` or `set`") != NULL,
	    "and the sentence quotes it and says what there is");
	check(strstr(err, "helper") == NULL,
	    "and does not offer `helper`, which is not a command for a person");
	fixture_clear();
}

/*
 * A `global` block in a file the operator owns is edited where it lives.
 *
 * A drop-in cannot add one key to a `global` block: redefining it is a compile
 * error and `override global` replaces it whole, which is measured to have
 * turned a machine's DNS mode from `write_resolv_conf` into `none`.
 */
static void a_global_block_in_the_writable_layer_is_edited_in_place(void)
{
	const ncfg_cli_options_t *base;
	ncfg_cli_options_t        options;
	const char               *positional[1];
	const char               *printed;
	char                      path[512];
	char                     *now;

	fixture(&base, "global {\n\tdns { mode = \"none\" }\n}\n"
	    "interface eth0 {\n\tconfig = \"dhcp\"\n}\n");
	options = *base;
	options.control.admin = "group:netcfgd";
	positional[0] = "set";

	capture_begin();
	{
		char err[NCFG_ERROR_MAX];

		err[0] = '\0';
		check(ncfg_cli_control(&options, positional, 1u, err, sizeof(err)),
		    "a `global` block that exists is edited rather than overridden");
		if (err[0] != '\0') {
			detail("said", err);
		}
	}
	printed = capture_end();

	(void)snprintf(path, sizeof(path), "%s/netcfgd.conf", config_dir);
	line(printed, path, "and the file it reports is the one that had the block");
	now = testdir_read(path, NULL);
	check(now != NULL && strstr(now, "admin = \"group:netcfgd\"") != NULL,
	    "the policy is in it");
	check(now != NULL && strstr(now, "dns { mode = \"none\" }") != NULL,
	    "and the DNS mode beside it is still there, which is the whole invariant");
	free(now);

	(void)snprintf(path, sizeof(path), "%s/conf.d/00-control.conf", config_dir);
	check(!testdir_exists(path), "and no drop-in was written beside it");
	fixture_clear();
}

/*
 * **A `global` block that is only in the factory layer is refused by name.**
 *
 * The Rust looks for the block in the *layered* source set, which puts the
 * factory files first -- so on an image that ships one this command edits
 * `/usr/share/netcfgd`, which is part of the image rather than part of the
 * machine's configuration. On a read-only root that is a refusal about a file
 * the operator did not name; on a writable one the edit is silently lost at the
 * next upgrade, while `ncfg control show` goes on reporting the policy
 * correctly in the meantime. 0263 has the entry.
 */
static void a_global_block_that_is_only_shipped_is_not_edited(void)
{
	const ncfg_cli_options_t *base;
	ncfg_cli_options_t        options;
	const char               *positional[1];
	char                      path[512];
	char                      err[NCFG_ERROR_MAX];
	char                     *now;

	fixture(&base, base_config);
	options = *base;
	options.control.admin = "group:netcfgd";
	positional[0] = "set";

	(void)mkdir(factory_dir, 0755);
	(void)snprintf(path, sizeof(path), "%s/netcfgd.conf", factory_dir);
	(void)testdir_write(path, "global {\n\tdns { mode = \"none\" }\n}\n",
	    strlen("global {\n\tdns { mode = \"none\" }\n}\n"));

	err[0] = '\0';
	capture_begin();
	check(!ncfg_cli_control(&options, positional, 1u, err, sizeof(err)),
	    "a `global` block that is only in the image is not edited");
	(void)capture_end();
	check(strstr(err, path) != NULL, "and the refusal names the file that has it");
	check(strstr(err, "part of the image") != NULL,
	    "and says why a drop-in cannot add a key to it");

	now = testdir_read(path, NULL);
	check(now != NULL && strstr(now, "control") == NULL,
	    "and the image's own file is untouched");
	free(now);
	fixture_clear();
}

/* ------------------------------------------------------------------------ *
 * The client half
 * ------------------------------------------------------------------------ */

static void an_answer_nobody_expected_is_named(void)
{
	ncfg_proto_response_t response;
	char                  what[NCFG_ERROR_MAX];

	memset(&response, 0, sizeof(response));
	response.kind = NCFG_PROTO_RESP_OK;
	check(strcmp(ncfg_cli_describe_answer(&response, what, sizeof(what)), "ok") == 0,
	    "`ok` is named `ok`");

	response.kind = NCFG_PROTO_RESP_PROFILES;
	check(strcmp(ncfg_cli_describe_answer(&response, what, sizeof(what)), "a profile list") ==
	    0, "a profile list is named as one");

	response.kind = NCFG_PROTO_RESP_ERROR;
	response.u.error.message = ncfg_proto_str("this needs the admin tier");
	check(strcmp(ncfg_cli_describe_answer(&response, what, sizeof(what)),
	    "an error: this needs the admin tier") == 0,
	    "and an error carries the daemon's own sentence");

	response.kind = NCFG_PROTO_RESP_HELLO;
	check(strstr(ncfg_cli_describe_answer(&response, what, sizeof(what)),
	    "an unexpected answer") != NULL,
	    "an answer this verb did not ask for is named rather than treated as success");
	detail("said", what);
}

/* A daemon on a socket in this test's own directory, answering one line. */
static pid_t fake_daemon(const char *path, const char *answer, int *listener_out)
{
	struct sockaddr_un address;
	pid_t              child;
	int                listener;

	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	if (strlen(path) >= sizeof(address.sun_path)) {
		return -1;
	}
	memcpy(address.sun_path, path, strlen(path));
	listener = socket(AF_UNIX, SOCK_STREAM, 0);
	if (listener < 0 || bind(listener, (const struct sockaddr *)&address, sizeof(address)) < 0 ||
	    listen(listener, 1) < 0) {
		if (listener >= 0) {
			(void)close(listener);
		}
		return -1;
	}
	child = fork();
	if (child == 0) {
		int fd = accept(listener, NULL, NULL);

		if (fd >= 0) {
			char    ignored[4096];
			ssize_t got = recv(fd, ignored, sizeof(ignored), 0);

			(void)got;
			if (answer) {
				(void)send(fd, answer, strlen(answer), MSG_NOSIGNAL);
			}
			(void)close(fd);
		}
		(void)close(listener);
		_exit(0);
	}
	if (child < 0) {
		(void)close(listener);
		return -1;
	}
	*listener_out = listener;
	return child;
}

/*
 * A request whose whole answer is `ok`.
 *
 * **A refusal and a transport failure are one arm on purpose**, and the
 * assertion is that the daemon's own sentence survives: it names the tier that
 * would have been needed (0013), which is the part that says what to do.
 */
static void one_request_whose_whole_answer_is_ok(void)
{
	ncfg_proto_request_t request;
	char                 path[512];
	char                 err[NCFG_ERROR_MAX];
	int                  listener = -1;
	pid_t                child;

	memset(&request, 0, sizeof(request));
	request.kind = NCFG_PROTO_REQ_CONFIG_DELETE;
	request.u.name = ncfg_proto_str("site");

	(void)snprintf(path, sizeof(path), "%s/ok.sock", root);
	child = fake_daemon(path, "{\"response\":\"ok\"}\n", &listener);
	if (child < 0) {
		check(0, "a fake daemon can be started");
		return;
	}
	check(ncfg_cli_daemon_listening(path), "a socket that is there is found");
	check(ncfg_cli_ask_ok(path, &request, err, sizeof(err)), "and `ok` is success");
	(void)waitpid(child, NULL, 0);
	(void)close(listener);
	(void)unlink(path);

	(void)snprintf(path, sizeof(path), "%s/no.sock", root);
	child = fake_daemon(path,
	    "{\"response\":\"error\",\"message\":\"this needs the admin tier\"}\n", &listener);
	if (child >= 0) {
		err[0] = '\0';
		check(!ncfg_cli_ask_ok(path, &request, err, sizeof(err)),
		    "a refusal is a failure of the command");
		check(strcmp(err, "this needs the admin tier") == 0,
		    "and the daemon's own sentence is what comes back, unwrapped");
		(void)waitpid(child, NULL, 0);
		(void)close(listener);
		(void)unlink(path);
	}

	(void)snprintf(path, sizeof(path), "%s/odd.sock", root);
	child = fake_daemon(path, "{\"response\":\"profiles\",\"profiles\":[],\"chosen\":null}\n",
	    &listener);
	if (child >= 0) {
		err[0] = '\0';
		check(!ncfg_cli_ask_ok(path, &request, err, sizeof(err)),
		    "an answer of another kind is not quietly treated as success");
		check(strstr(err, "the daemon sent a profile list") != NULL,
		    "and the sentence says what did arrive");
		detail("said", err);
		(void)waitpid(child, NULL, 0);
		(void)close(listener);
		(void)unlink(path);
	}

	(void)snprintf(path, sizeof(path), "%s/absent.sock", root);
	check(!ncfg_cli_daemon_listening(path), "and a socket that is not there is not found");
}

static void the_socket_lives_under_the_run_directory(void)
{
	ncfg_cli_options_t options;
	char               where[NCFG_ERROR_MAX];

	memset(&options, 0, sizeof(options));
	options.run_dir = "/run/example";
	check(ncfg_cli_daemon_socket(&options, where, sizeof(where)) != NULL &&
	    strcmp(where, "/run/example/netcfgd.sock") == 0,
	    "the socket is `netcfgd.sock` under the run directory");

	/* A run directory that does not fit is refused rather than truncated: a
	 * truncated unix address connects to a shorter path that may well exist. */
	{
		char tiny[8];

		check(ncfg_cli_daemon_socket(&options, tiny, sizeof(tiny)) == NULL,
		    "and a path that will not fit is refused rather than shortened");
	}
}

int main(void)
{
	report_opens_before_any_capture();
	(void)testdir_make("cli-control");
	root = testdir_path;
	(void)snprintf(capture_file, sizeof(capture_file), "%s/out", testdir_path);

	a_principal_is_spelled_one_way();
	the_renderer_agrees_about_how_a_principal_is_written();
	the_drop_in_it_writes_says_how_to_undo_it();

	a_missing_control_block_is_inserted_without_touching_the_rest();
	an_existing_control_block_is_replaced_not_doubled();
	a_brace_inside_a_string_does_not_move_the_end_of_the_block();
	a_head_is_a_word_and_not_a_prefix();
	a_comment_that_mentions_a_block_is_not_a_block();
	a_file_with_no_global_block_says_so();

	the_helper_accepts_one_verb_and_three_principals();

	show_prints_three_tiers_and_says_what_root_only_means();
	set_writes_the_drop_in_it_owns_and_reports_the_path();
	json_prints_the_tiers_and_nothing_addressed_to_a_person();
	set_with_no_tier_named_refuses();
	an_unknown_subcommand_is_named_and_helper_is_not_offered();
	a_global_block_in_the_writable_layer_is_edited_in_place();
	a_global_block_that_is_only_shipped_is_not_edited();

	an_answer_nobody_expected_is_named();
	one_request_whose_whole_answer_is_ok();
	the_socket_lives_under_the_run_directory();

	free(captured);
	testdir_remove(testdir_path);

	if (failures == 0) {
		(void)fprintf(report, "cli_control_test: all checks passed\n");
	} else {
		(void)fprintf(report, "cli_control_test: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
