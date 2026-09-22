/*
 * cli_test.c -- `ncfg`, against the lines it is supposed to print.
 *
 * WHY THE ASSERTIONS ARE WHOLE LINES
 *   The output is the product. `ncfg status` is what an operator reads at the
 *   moment something is wrong, and its wording, its columns and what it leaves
 *   out are decisions rather than incidental formatting -- so a check that the
 *   renderer "produced something" would pass over every one of them. Every
 *   assertion here is an exact line, matched whole, in a capture of what the
 *   program actually wrote to its own stdout.
 *
 * WHERE THE SUBJECTS COME FROM
 *   `doc/schema/observed.json` and `doc/schema/document.json` are generated
 *   from the daemon's own types, so they are a subject nobody here chose.
 *
 *   **The plan is built from those two rather than read from
 *   `doc/schema/plan.json`**, and not by preference: `plan.h` has a writer and
 *   no reader, because a plan is something netcfgd computes and never
 *   something it is handed. Compiling the witness document against the witness
 *   observation is the same subject arrived at the way the program arrives at
 *   it, and it exercises the planner's own reasons rather than a file's.
 *
 *   Two things are built by hand instead, and both deliberately: a plan
 *   carrying a stranding, because neither witness produces one and the
 *   stranding block is four lines nothing else would check; and a small
 *   observation carrying an interface report and a weak ownership mode,
 *   because the witness's one report is for an interface its link table does
 *   not have -- which is right, and means the `[reported, not applied]` lines
 *   are in it nowhere.
 *
 * WHAT IS NOT DONE HERE
 *   **Nothing talks to the running daemon.** The machine this builds on is the
 *   reporting machine, with its real network on it. The socket conversation is
 *   exercised against a fake on an `AF_UNIX` socket in a directory of this
 *   test's own, the way `client/tests/client_test.c` does it.
 */
#include "ncfg/cli.h"

#include "ncfg/base.h"
#include "ncfg/config.h"
#include "ncfg/log.h"
#include "ncfg/observe.h"

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

static void check(int condition, const char *what)
{
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
 * Capturing what the program printed
 * ------------------------------------------------------------------------ *
 *
 * Every line `ncfg` prints goes through `ncfg_out_*`, which writes to `stdout`
 * and leaves at 141 when the reader has gone (0261). So the only honest way to
 * assert the output is to *be* the reader: file descriptor 1 is pointed at a
 * file in this test's own directory, the renderer runs, and the descriptor is
 * put back. Rendering into a buffer instead would be testing a second printer
 * that the program does not use.
 */

static int   saved_stdout = -1;
static char  capture_file[320];
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

/* What was written, owned by this file and replaced by the next capture. */
static const char *capture_end(void)
{
	FILE  *file;
	long   size;
	size_t got;

	(void)fflush(stdout);
	(void)dup2(saved_stdout, STDOUT_FILENO);
	(void)close(saved_stdout);
	saved_stdout = -1;

	free(captured);
	captured = NULL;
	file = fopen(capture_file, "rb");
	if (!file) {
		return "";
	}
	(void)fseek(file, 0, SEEK_END);
	size = ftell(file);
	(void)fseek(file, 0, SEEK_SET);
	if (size < 0) {
		(void)fclose(file);
		return "";
	}
	captured = malloc((size_t)size + 1);
	if (!captured) {
		(void)fclose(file);
		return "";
	}
	got = fread(captured, 1, (size_t)size, file);
	captured[got] = '\0';
	(void)fclose(file);
	return captured;
}

/*
 * Whether `text` contains `wanted` as a whole line.
 *
 * Whole-line rather than `strstr`, because a substring match would pass on a
 * line that had grown a column or lost one -- which is exactly the change this
 * file exists to notice.
 */
static int has_line(const char *text, const char *wanted)
{
	size_t length = strlen(wanted);
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

/* The same, reported with the line when it is not there. */
static void line(const char *text, const char *wanted, const char *what)
{
	int found = has_line(text, wanted);

	check(found, what);
	if (!found) {
		detail("wanted", wanted);
	}
}

/* Whether `first` appears before `second`, both as whole lines. */
static int before(const char *text, const char *first, const char *second)
{
	const char *a = strstr(text, first);
	const char *b = strstr(text, second);

	return a && b && a < b;
}

/* ------------------------------------------------------------------------ *
 * Fixtures
 * ------------------------------------------------------------------------ */

/*
 * A witness, from wherever this was run.
 *
 * The same candidate list `document_test.c` uses: the tests run from `c/`
 * under the Makefile and from elsewhere under a sanitizer build, and a path
 * that is wrong produces a *vacuous* pass -- the whole file is skipped and the
 * run is green. So a witness that cannot be opened is a failure, named.
 */
static char *witness(const char *name, size_t *length_out)
{
	static const char *const roots[] = { "../doc/schema/", "doc/schema/",
		"../../doc/schema/" };
	size_t at;

	for (at = 0; at < sizeof(roots) / sizeof(roots[0]); at++) {
		char   path[512];
		FILE  *file;
		long   size;
		char  *text;

		(void)snprintf(path, sizeof(path), "%s%s", roots[at], name);
		file = fopen(path, "rb");
		if (!file) {
			continue;
		}
		(void)fseek(file, 0, SEEK_END);
		size = ftell(file);
		(void)fseek(file, 0, SEEK_SET);
		if (size < 0) {
			(void)fclose(file);
			continue;
		}
		text = malloc((size_t)size + 1);
		if (!text) {
			(void)fclose(file);
			continue;
		}
		*length_out = fread(text, 1, (size_t)size, file);
		text[*length_out] = '\0';
		(void)fclose(file);
		return text;
	}
	return NULL;
}

/* ------------------------------------------------------------------------ *
 * The usage, and the list it is checked against
 * ------------------------------------------------------------------------ */

/*
 * Every command the help text offers has an arm to dispatch it.
 *
 * `reload` drifted the other way for a whole milestone: the request was in the
 * protocol, in `doc/schema/socket.json` and in the authorisation table, and no
 * shipped client could send it. Nothing was red, because nothing compared the
 * two lists.
 *
 * The Rust reads its own source with `include_str!`; this reads `run.c`, which
 * is the same check with the file opened at run time -- and a source that
 * cannot be found fails rather than passing over an empty comparison.
 */
static void every_command_in_the_help_text_is_dispatched(void)
{
	static const char *const roots[] = { "../src/cli/run.c", "src/cli/run.c",
		"../../src/cli/run.c" };
	char       *source = NULL;
	size_t      length = 0;
	const char *usage = ncfg_cli_usage();
	const char *at = usage;
	unsigned    checked = 0;
	size_t      root;

	for (root = 0; root < sizeof(roots) / sizeof(roots[0]) && !source; root++) {
		FILE *file = fopen(roots[root], "rb");
		long  size;

		if (!file) {
			continue;
		}
		(void)fseek(file, 0, SEEK_END);
		size = ftell(file);
		(void)fseek(file, 0, SEEK_SET);
		if (size >= 0) {
			source = malloc((size_t)size + 1);
			if (source) {
				length = fread(source, 1, (size_t)size, file);
				source[length] = '\0';
			}
		}
		(void)fclose(file);
	}
	if (!source) {
		check(0, "the dispatcher's source can be read");
		return;
	}

	while (at && *at) {
		const char *end = strchr(at, '\n');
		const char *word = at;
		char        name[64];
		size_t      taken = 0;
		int         lowercase = 1;

		while (*word == ' ') {
			word++;
		}
		if (strncmp(word, "ncfg ", 5) != 0) {
			at = end ? end + 1 : NULL;
			continue;
		}
		word += 5;
		while (taken + 1 < sizeof(name) && word[taken] && word[taken] != ' ' &&
		    word[taken] != '\n') {
			name[taken] = word[taken];
			taken++;
		}
		name[taken] = '\0';
		/* Only the command lines. The options block wraps continuation text
		 * under the same indent, and none of it starts with `ncfg `. */
		for (root = 0; root < taken; root++) {
			if (name[root] < 'a' || name[root] > 'z') {
				if (name[root] != '-') {
					lowercase = 0;
				}
			}
		}
		if (taken > 0 && lowercase && name[0] != '-') {
			char wanted[96];
			int  found;

			(void)snprintf(wanted, sizeof(wanted), "\"%s\") == 0", name);
			found = strstr(source, wanted) != NULL;
			if (!found) {
				detail("offered with nothing to dispatch it", name);
			}
			check(found, "a command in the help text has an arm");
			checked++;
		}
		at = end ? end + 1 : NULL;
	}
	free(source);
	/* The vacuous-pass guard: a reformatted usage that stopped matching would
	 * otherwise report a clean run having compared nothing. */
	check(checked > 10, "and the usage text was walked, not merely opened");
}

/*
 * The copyright surface exists and names somebody.
 *
 * `harmonization.md` asks for the holder in `--version`, and a version string
 * is the kind of thing that is edited for an unrelated reason and quietly loses
 * a line. Asserted on the shape rather than against a literal copy of the
 * string, so this checks that the surface carries a notice rather than
 * restating the fact and agreeing with itself.
 */
static void the_version_surface_names_the_copyright_holder(void)
{
	const char *printed;

	check(strstr(NCFG_CLI_COPYRIGHT, "Copyright (C)") != NULL,
	    "the line is recognisable as a copyright notice");
	check(strchr(NCFG_CLI_COPYRIGHT, '<') && strchr(NCFG_CLI_COPYRIGHT, '@'),
	    "and carries the name and the address harmonization.md asks for");
	check(strstr(ncfg_cli_usage(), "--version") != NULL,
	    "`ncfg --help` mentions --version, or nobody will run it");

	capture_begin();
	ncfg_cli_print_version();
	printed = capture_end();
	line(printed, "ncfg " NCFG_CLI_VERSION, "--version prints the version first");
	line(printed, NCFG_CLI_COPYRIGHT, "and the copyright line under it");
}

/* ------------------------------------------------------------------------ *
 * The parser
 * ------------------------------------------------------------------------ */

/* Parse, and hand back whether it did. */
static int split(const char *const *arguments, int count, ncfg_cli_options_t *options,
    const char **positional, size_t *positional_count, char *err, size_t err_size)
{
	err[0] = '\0';
	return ncfg_cli_parse(count, (char *const *)(const void *)arguments, options, positional,
	    positional_count, err, err_size);
}

/*
 * A bare `-` reaches a command as a filename rather than as an option.
 *
 * The help documents three ways to give `ncfg config put` its text -- a file,
 * `-`, or nothing -- and `put` implements all three. The classifier caught
 * anything starting with a dash first and answered `unknown option -`, so the
 * one form the help spells out by name was the one that could not be used.
 */
static void a_bare_dash_is_a_filename_and_not_an_option(void)
{
	static const char *const arguments[] = { "put", "site", "-" };
	static const char *const typo[] = { "put", "--nope" };
	ncfg_cli_options_t options;
	const char        *positional[8];
	size_t             count = 0;
	char               err[NCFG_ERROR_MAX];

	check(split(arguments, 3, &options, positional, &count, err, sizeof(err)) && count == 3 &&
	    strcmp(positional[2], "-") == 0, "a bare dash parses as a positional");
	check(!split(typo, 2, &options, positional, &count, err, sizeof(err)),
	    "and a real typo is still refused, which is what that arm is for");
}

/*
 * Every option that takes a value consumes it.
 *
 * The regression the one-pass parse fixes: the value used to become a
 * subcommand, for the two options that were in this parser and not in the
 * separate list the subcommands used. Paired with a value each option actually
 * accepts, because two of them check what they are given -- and a test that fed
 * every flag the word `value` would be asserting the parse *and* the
 * validation, and would go red for the second while claiming the first.
 */
static void a_value_is_never_mistaken_for_a_subcommand(void)
{
	static const char *const pairs[][2] = {
		{ "--config-dir", "value" },
		{ "--factory-dir", "value" },
		{ "--run-dir", "value" },
		{ "--allow-disruption", "value" },
		{ "--strand-credentials", "value" },
		{ "--restart-wedged", "value" },
		{ "--id", "value" },
		/* The enterprise flags. Every one takes a value that can look like a
		 * subcommand -- an identity is a word, a phase2 name is `mschapv2`, a
		 * certificate is a path -- which is exactly the shape that broke
		 * `wifi add` before the parse became one pass. */
		{ "--eap", "peap" },
		{ "--identity", "value" },
		{ "--anonymous-identity", "value" },
		{ "--ca-cert", "value" },
		{ "--client-cert", "value" },
		{ "--phase2", "value" },
		{ "--observe", "any" },
		{ "--wifi", "any" },
		{ "--admin", "any" },
		{ "--interface", "value" },
		{ "--sys-class-net", "value" }
	};
	size_t at;
	int    all = 1;

	for (at = 0; at < sizeof(pairs) / sizeof(pairs[0]); at++) {
		const char        *arguments[3];
		ncfg_cli_options_t options;
		const char        *positional[8];
		size_t             count = 0;
		char               err[NCFG_ERROR_MAX];

		arguments[0] = pairs[at][0];
		arguments[1] = pairs[at][1];
		arguments[2] = "scan";
		if (!split(arguments, 3, &options, positional, &count, err, sizeof(err)) ||
		    count != 1 || strcmp(positional[0], "scan") != 0) {
			detail("left its value behind as a positional", pairs[at][0]);
			all = 0;
		}
	}
	check(all, "every value-taking option consumes its value");

	{
		static const char *const seconds[] = { "--confirm-within", "30", "scan" };
		static const char *const metric[] = { "--metric", "30", "add", "Home" };
		ncfg_cli_options_t options;
		const char        *positional[8];
		size_t             count = 0;
		char               err[NCFG_ERROR_MAX];

		check(split(seconds, 3, &options, positional, &count, err, sizeof(err)) &&
		    count == 1 && options.confirm.has && options.confirm.value == 30,
		    "and the two that parse a number keep it: --confirm-within");
		check(split(metric, 4, &options, positional, &count, err, sizeof(err)) &&
		    count == 2 && options.wifi.metric.has && options.wifi.metric.value == 30,
		    "and --metric");
	}
}

/* A flag before the positionals no longer hides them, which `explain` did. */
static void a_flag_may_come_first(void)
{
	static const char *const arguments[] = { "--json", "interface", "eth0" };
	ncfg_cli_options_t options;
	const char        *positional[8];
	size_t             count = 0;
	char               err[NCFG_ERROR_MAX];

	check(split(arguments, 3, &options, positional, &count, err, sizeof(err)) &&
	    options.json && count == 2 && strcmp(positional[0], "interface") == 0 &&
	    strcmp(positional[1], "eth0") == 0, "a flag may come before the positionals");
}

/* The refusals, each of which is a sentence somebody reads. */
static void the_parser_refuses_and_says_why(void)
{
	ncfg_cli_options_t options;
	const char        *positional[64];
	size_t             count = 0;
	char               err[NCFG_ERROR_MAX];

	{
		static const char *const missing[] = { "--metric" };

		check(!split(missing, 1, &options, positional, &count, err, sizeof(err)) &&
		    strstr(err, "needs a value"),
		    "a value-taking option with no value is refused, not defaulted");
	}
	{
		static const char *const mistyped[] = { "--jsonn" };

		check(!split(mistyped, 1, &options, positional, &count, err, sizeof(err)) &&
		    strstr(err, "unknown option `--jsonn`"),
		    "a mistyped flag is refused rather than ignored");
	}
	{
		static const char *const words[] = { "--confirm-within", "30s" };

		check(!split(words, 2, &options, positional, &count, err, sizeof(err)) &&
		    strstr(err, "not `30s`"),
		    "--confirm-within refuses what is not a number of seconds");
	}
	{
		/*
		 * **The one that must not be silently accepted.** Somebody's script
		 * has `--priority` in it, and the replacement runs the OTHER WAY UP --
		 * so the one thing they must not do is pass the same number through.
		 */
		static const char *const old[] = { "--priority", "5" };

		check(!split(old, 2, &options, positional, &count, err, sizeof(err)) &&
		    strstr(err, "--metric") && strstr(err, "lower wins"),
		    "--priority is named, and says which way the replacement ranks");
	}
	{
		/*
		 * Named here as well as in the compiler, because this is the one an
		 * operator sees first and "unknown wifi key" an hour later -- after
		 * the network has been written -- is not the same sentence.
		 */
		static const char *const bogus[] = { "--eap", "kerberos" };

		check(!split(bogus, 2, &options, positional, &count, err, sizeof(err)) &&
		    strstr(err, "is not an EAP method") && strstr(err, "peap, ttls, tls, pwd"),
		    "an EAP method outside the four is refused at the parse, by name");
	}
	{
		/*
		 * The ceiling is this port's, and it refuses rather than truncating:
		 * a consent flag quietly dropped is consent nobody gave.
		 */
		const char *many[2 * (NCFG_CLI_LIST_MAX + 1)];
		size_t      at;

		for (at = 0; at < NCFG_CLI_LIST_MAX + 1; at++) {
			many[at * 2] = "--allow-disruption";
			many[at * 2 + 1] = "eth0";
		}
		check(!split(many, (int)(2 * (NCFG_CLI_LIST_MAX + 1)), &options, positional,
		    &count, err, sizeof(err)) && strstr(err, "--allow-disruption") &&
		    strstr(err, "at most"),
		    "a repeatable option past its ceiling is refused, naming the flag");
	}
}

/* ------------------------------------------------------------------------ *
 * The rules every client of this daemon has to spell the same way
 * ------------------------------------------------------------------------ */

/*
 * The word a scan row is labelled with, for each shape it can be.
 *
 * **`owe` is the one that had no word.** An access point doing opportunistic
 * wireless encryption asks for no credential, so `secured` is false for it
 * exactly as for an open network -- and the two are different networks to
 * join. The TUI groups rows by this word, with a comment saying a key coarser
 * than what is displayed merges two networks under a heading describing one of
 * them; that is what it did. 0227.
 */
static void every_security_shape_has_its_own_word(void)
{
	check(strcmp(ncfg_cli_access_point_security(1, 0, 0), "secured") == 0, "secured");
	check(strcmp(ncfg_cli_access_point_security(1, 1, 0), "enterprise") == 0, "enterprise");
	check(strcmp(ncfg_cli_access_point_security(0, 0, 0), "open") == 0, "open");
	check(strcmp(ncfg_cli_access_point_security(0, 0, 1), "owe") == 0, "owe");
	check(strcmp(ncfg_cli_access_point_security(0, 0, 1),
	    ncfg_cli_access_point_security(0, 0, 0)) != 0,
	    "an OWE network and an open one must not share a word");
}

/* Three cases, because the daemon sends three and every client draws them. */
static void an_access_point_is_named_three_ways_and_never_two(void)
{
	char a[64];
	char b[64];

	check(strcmp(ncfg_cli_access_point_name("home", "686f6d65", a, sizeof(a)), "home") == 0,
	    "a name that arrived is the name");
	check(strcmp(ncfg_cli_access_point_name("", "00", a, sizeof(a)), "(hidden)") == 0,
	    "a name that arrived empty is a hidden network, not a blank cell");
	check(strcmp(ncfg_cli_access_point_name(NULL, "ff00ff", a, sizeof(a)), "hex:ff00ff") == 0,
	    "a name that did not arrive is hex, prefixed so nobody reads it as the name");

	/* The hex is kept, not summarised, so two unprintable networks are two
	 * rows. This is the assertion the old TUI wording could not have passed. */
	(void)ncfg_cli_access_point_name(NULL, "ff00ff", a, sizeof(a));
	(void)ncfg_cli_access_point_name(NULL, "ff00fe", b, sizeof(b));
	check(strcmp(a, b) != 0, "two unprintable networks do not become one row");
}

/*
 * What the radio rule is *for*, which `make conformance` cannot say.
 *
 * That target diffs this implementation against `client/`'s, and both were
 * written from each other -- so they agree by construction and would agree
 * just as loudly about a wrong answer. This is the second witness, and it
 * asserts the ordering rather than the two easy cases: a kind the kernel gave
 * decides on its own, and the name is consulted only where there is no kind.
 *
 * The last two are the ones that were wrong. A VLAN on a radio inherits the
 * radio's name, and a client that finds "the radio" over a name-sorted list
 * put `wl-br0` on the screen where the radio belonged.
 */
static void a_kind_the_kernel_gave_wins_over_the_name(void)
{
	check(ncfg_cli_is_radio("", "wlp0s20f3"), "no kind: the name convention is all there is");
	check(ncfg_cli_is_radio(NULL, "wlan0"), "and a missing kind reads the same as an empty one");
	check(!ncfg_cli_is_radio("", "eth0"), "eth0 is not a radio");
	check(!ncfg_cli_is_radio(NULL, "wwan0"), "and neither is a modem");
	check(ncfg_cli_is_radio("wlan", "enp1s0"),
	    "a kind the kernel gave answers, and the name is not consulted");
	check(!ncfg_cli_is_radio("vlan", "wlan0.10"), "a VLAN on a radio is not a radio");
	check(!ncfg_cli_is_radio("bridge", "wl-br0"), "and a bridge named like one is not either");
}

/*
 * What "online" means here, and why it is not "every interface".
 *
 * `network-online.target` is a promise to docker, a mail spool and a package
 * refresh that the machine can reach the network. A global address and a
 * default route is what the other wait-online helpers wait for and what those
 * services need. Waiting for every interface the document names would keep a
 * laptop waiting for a dock it is not plugged into.
 */
static void online_means_a_global_address_and_a_default_route(void)
{
	static char             loopback[] = "lo";
	static char             ethernet[] = "eth0";
	static char             local_v4[] = "127.0.0.1/8";
	static char             link_v4[] = "169.254.7.7/16";
	static char             link_v6[] = "fe80::1/64";
	static char             global[] = "10.0.0.5/24";
	static char             anywhere[] = "default";
	ncfg_observed_t         observed;
	ncfg_observed_address_t address;
	ncfg_observed_route_t   route;

	memset(&observed, 0, sizeof(observed));
	memset(&address, 0, sizeof(address));
	memset(&route, 0, sizeof(route));
	route.interface = ethernet;
	route.destination = anywhere;

	check(!ncfg_cli_is_online(&observed), "an empty machine is not online");

	observed.addresses = &address;
	observed.address_count = 1;
	observed.routes = &route;
	observed.route_count = 1;

	address.interface = loopback;
	address.address = local_v4;
	check(!ncfg_cli_is_online(&observed), "loopback is not being online");

	/* **A link-local address is what a machine has when DHCP did not answer**,
	 * which is the state this is most needed to distinguish. */
	address.interface = ethernet;
	address.address = link_v4;
	check(!ncfg_cli_is_online(&observed), "169.254 is not being online");
	address.address = link_v6;
	check(!ncfg_cli_is_online(&observed), "fe80:: is not being online");

	address.address = global;
	observed.route_count = 0;
	check(!ncfg_cli_is_online(&observed), "an address with no way out is not online");

	observed.route_count = 1;
	check(ncfg_cli_is_online(&observed), "an address and a way out is");
}

/* A duration a person reads at a glance, and bytes in the units they are in. */
static void a_number_is_rendered_in_the_units_it_is_in(void)
{
	char out[32];

	check(strcmp(ncfg_cli_duration(45, out, sizeof(out)), "45s") == 0, "seconds alone");
	check(strcmp(ncfg_cli_duration(125, out, sizeof(out)), "2m05s") == 0,
	    "minutes pad their seconds, so a column stays a column");
	check(strcmp(ncfg_cli_duration(3725, out, sizeof(out)), "1h02m") == 0,
	    "and hours drop the seconds rather than growing the column");
	check(strcmp(ncfg_cli_bytes(512, out, sizeof(out)), "512B") == 0, "bytes below a kilobyte");
	check(strcmp(ncfg_cli_bytes(1500, out, sizeof(out)), "1.5k") == 0, "one decimal place");
	check(strcmp(ncfg_cli_bytes(2500000, out, sizeof(out)), "2.5M") == 0, "megabytes");
	check(strcmp(ncfg_cli_bytes(3100000000LL, out, sizeof(out)), "3.1G") == 0,
	    "and gigabytes, by integer arithmetic rather than a float divide");
}

/* ------------------------------------------------------------------------ *
 * `ncfg status`
 * ------------------------------------------------------------------------ */

static void the_status_listing_is_what_an_operator_reads(const char *text, size_t length)
{
	ncfg_observed_t *observed;
	const char      *printed;
	char             err[NCFG_ERROR_MAX];

	observed = ncfg_observed_read(text, length, err, sizeof(err));
	if (!observed) {
		check(0, "the observed witness parses");
		detail("why", err);
		return;
	}
	capture_begin();
	ncfg_cli_print_status(observed);
	printed = capture_end();

	line(printed, "eth0 up mtu 1500", "a link's line is its name, its state and its mtu");
	line(printed, "eth2 up mtu 1500", "and every link gets one");

	/*
	 * **The capital letter is the assertion.** `ncfg status` prints Rust's
	 * `Debug` for an ownership, so an operator has been reading `[Foreign]`
	 * since M1; `ncfg_ownership_name` gives the wire spelling `foreign`, and a
	 * port that reached for it here would have changed the output while every
	 * test that reads JSON stayed green.
	 */
	line(printed, "    192.168.0.1/24 [Ours]", "an address carries its ownership");
	line(printed, "    172.16.1.1/24 [Foreign]", "and somebody else's says so");
	line(printed, "    172.16.2.1/24 [Unknown]",
	    "and the third answer is a third word, not a blank");

	line(printed, "    vlan 10 pvid untagged", "a bridge vlan says which flags it carries");
	line(printed, "    offloads rx-checksum tx-checksum-ip-generic",
	    "offloads are one line, space-joined");
	/*
	 * A qdisc carries no owner and every interface has one whether or not
	 * anybody chose it, so the note is the difference between netcfgd's shaping
	 * and what was already there.
	 */
	line(printed, "    qdisc cake at 20000000 bit/s inbound",
	    "a qdisc netcfgd applied is reported plainly");
	line(printed, "    qdisc cake at 20000000 bit/s inbound [kernel default or set elsewhere]",
	    "and one it did not is marked, because a qdisc carries no owner");
	line(printed, "    ingress redirected to ifb-eth0", "an ingress redirect names its target");
	line(printed, "    masquerade", "an interface netcfgd's own table translates");
	line(printed, "    forwarding", "and one it switched forwarding on for");
	/* Only when it is off: a radio that works needs no line, and the two
	 * blocks have different remedies. */
	line(printed, "    radio off [software block at phy0]",
	    "a blocked radio names which switch is holding it");

	line(printed, "    route default via 192.168.0.254 [Foreign]",
	    "a route with a gateway says via, and carries its ownership");
	line(printed, "    route 10.0.0.0/16 via 10.0.0.1 [Ours]", "and one netcfgd installed");

	/*
	 * **The losers are the point.** "This machine is on the modem" is visible
	 * from the routing table; "because the cable has no carrier" is not visible
	 * anywhere else.
	 */
	line(printed, "linkset uplink using n-cafe on wlan0",
	    "a linkset names what it chose and the interface under it");
	line(printed, "    eth1 [absent]", "and every member that lost says why it lost");

	line(printed, "note: nftables table(s) `somebody-elses-table` also translate source "
	    "addresses. netcfgd does not touch tables it did not create, so this is a report, "
	    "not something it will resolve.",
	    "a second source-NAT table is reported once, not per interface");

	check(before(printed, "eth0 up mtu 1500", "    192.168.0.1/24 [Ours]") &&
	    before(printed, "    192.168.0.1/24 [Ours]", "    vlan 10 pvid untagged") &&
	    before(printed, "    vlan 10 pvid untagged", "    offloads rx-checksum") &&
	    before(printed, "    forwarding", "    route default via 192.168.0.254 [Foreign]"),
	    "and the order under a link is address, vlan, settings, route");

	ncfg_observed_free(observed);
}

/*
 * The two things the witness cannot show, on an observation built for them.
 *
 * The witness's one interface report is for `vpn0`, which its link table does
 * not have -- which is correct, and means the `[reported, not applied]` lines
 * are in it nowhere. **That distinction is the one the status format exists to
 * carry**: netcfgd reads that file and does nothing with it until an
 * `addressing` source asks (0044, 0045), and an operator who cannot tell "the
 * bearer is up" from "netcfgd configured the interface" has no way to know
 * which half is broken. So it gets a subject of its own rather than going
 * unchecked.
 */
static void what_something_else_reported_is_marked_as_reported(void)
{
	static const char observation[] =
	    "{\"links\":[{\"name\":\"vpn0\",\"index\":9,\"up\":true,\"carrier\":false,"
	    "\"mtu\":1400}],"
	    "\"reports\":[{\"interface\":\"vpn0\",\"addresses\":[\"10.8.0.2/24\"],"
	    "\"gateways\":[\"10.8.0.1\"],\"nameservers\":[\"10.0.0.53\",\"10.0.0.54\"]}],"
	    "\"address_proto_supported\":false}";
	ncfg_observed_t *observed;
	const char      *printed;
	char             err[NCFG_ERROR_MAX];

	observed = ncfg_observed_read(observation, sizeof(observation) - 1, err, sizeof(err));
	if (!observed) {
		check(0, "an observation carrying a report parses");
		detail("why", err);
		return;
	}
	capture_begin();
	ncfg_cli_print_status(observed);
	printed = capture_end();

	line(printed, "vpn0 up, no carrier mtu 1400",
	    "a link with no carrier says so, because up and carrier are two answers");
	line(printed, "    10.8.0.2/24 [reported, not applied]",
	    "a reported address is marked as reported");
	line(printed, "    via 10.8.0.1 [reported, not applied]", "and so is a reported gateway");
	line(printed, "    nameservers 10.0.0.53 10.0.0.54 [reported, not applied]",
	    "and the nameservers, space-joined, on one line");
	line(printed, "note: no address carries a protocol tag yet, so address ownership comes "
	    "from recorded state and is weaker. It strengthens once netcfgd installs its first "
	    "address.",
	    "a weak ownership mode is said, because it decides how much to trust a drift report");

	ncfg_observed_free(observed);
}

/* ------------------------------------------------------------------------ *
 * `ncfg plan` and `ncfg show`
 * ------------------------------------------------------------------------ */

static void a_plan_says_what_and_why(const char *document_text, size_t document_length,
    const char *observed_text, size_t observed_length)
{
	ncfg_document_t    *document;
	ncfg_observed_t    *observed;
	ncfg_plan_t        *plan;
	ncfg_plan_options_t options;
	const char         *printed;
	char                err[NCFG_ERROR_MAX];

	document = ncfg_document_read(document_text, document_length, err, sizeof(err));
	observed = ncfg_observed_read(observed_text, observed_length, err, sizeof(err));
	if (!document || !observed) {
		check(0, "the document and observed witnesses parse together");
		detail("why", err);
		ncfg_document_free(document);
		ncfg_observed_free(observed);
		return;
	}
	memset(&options, 0, sizeof(options));
	plan = ncfg_plan_build(document, observed, &options, err, sizeof(err));
	if (!plan) {
		check(0, "a plan can be built from the two witnesses");
		detail("why", err);
		ncfg_document_free(document);
		ncfg_observed_free(observed);
		return;
	}
	capture_begin();
	ncfg_cli_print_plan(plan);
	printed = capture_end();

	/*
	 * **An action list without reasons is a black box with extra steps.** The
	 * id is right-aligned in three columns so the list reads as a list, and
	 * `<absent>` is the planner's word for a field that is not there -- an
	 * empty string would make "the document says nothing" and "the document
	 * says the empty string" the same line.
	 */
	/*
	 * **The subject was `k-bond`, became `k-bridge`, and is `k-bond` again.**
	 * It moved away when the planner stopped planning a creation the executor
	 * refused, and it has moved back now that `ncfg_kernel_newlink_of` builds
	 * a bond's nest: `plan/link.c` asks `ncfg_apply_supported` rather than
	 * keeping a list, so the witness's bond is planned again without that file
	 * being touched. What these four checks are about is the *rendering* --
	 * three right-aligned columns, the field that differs, and `<absent>` for
	 * a field that is not there -- and any action shows that, which is why the
	 * subject follows the plan rather than the checks being deleted.
	 */
	line(printed, "  1  link.create k-bond  kind: bond (was <absent>)",
	    "an action says what it does, to what, and which field differs");
	{
		/*
		 * **The property, not a particular action.** This named one by id and
		 * broke twice in one afternoon as the planner grew passes -- each
		 * time for a reason that had nothing to do with what it checks, which
		 * is that the id column stays three wide once the ids reach two
		 * digits. A check that has to be edited whenever unrelated work lands
		 * is one that gets edited without being read.
		 */
		const char *at = printed;
		int         aligned = 0;

		while (at && *at) {
			if (at[0] == ' ' && at[1] >= '1' && at[1] <= '9' && at[2] >= '0' &&
			    at[2] <= '9' && at[3] == ' ' && at[4] == ' ') {
				aligned = 1;
				break;
			}
			at = strchr(at, '\n');
			if (at) {
				at++;
			}
		}
		check(aligned, "and the id stays in its column past nine");
	}

	line(printed, "refused: link.set_mtu on k-bridge -- nfs depends on it",
	    "a refusal names the op, the interface and the guard");
	line(printed, "         would have been: link.set_mtu k-bridge  mtu: 1400 (was <absent>)",
	    "and says what is not happening, so the reader knows what was lost");
	/* A refusal the operator cannot act on is just a complaint, so the
	 * override is quoted verbatim rather than described. */
	line(printed, "         to allow it:     ncfg apply --allow-disruption k-bridge",
	    "and quotes the exact invocation that consents to it");

	check(strstr(printed, "warning: d-0: ") != NULL,
	    "a warning about one interface names it before the message");

	ncfg_plan_free(plan);
	ncfg_document_free(document);
	ncfg_observed_free(observed);
}

/*
 * The blocks the witness has none of.
 *
 * A stranding is not a refusal: nothing is dropped, because `managed = false`
 * already means netcfgd plans nothing for the device, and the hazard is that
 * absence continuing (0042). Its four lines print both ways out with the
 * config one first, because the flag consents for one run and the config key is
 * the answer that is still there next time somebody reads the file -- the other
 * way round would make the flag look like the fix.
 *
 * Built by hand because the printer only reads: a plan the planner would have
 * to be steered into producing is a test of the planner, and this is a test of
 * four lines of text.
 */
static void an_empty_plan_still_prints_what_is_not_an_action(void)
{
	ncfg_plan_t     plan;
	ncfg_warning_t  warning;
	ncfg_stranded_t stranded;
	const char     *printed;

	memset(&plan, 0, sizeof(plan));
	memset(&warning, 0, sizeof(warning));
	memset(&stranded, 0, sizeof(stranded));

	warning.message = "the machine has no default route";
	warning.interface = NULL;
	stranded.interface = "wg0";
	stranded.credential = "the private key in @secret:wg0";
	stranded.irrevocable = "the peer would have to be told to drop it";
	stranded.remove_with = "on_unmanage = \"clear\"";
	stranded.consent_with = "ncfg apply --strand-credentials wg0";

	plan.warnings = &warning;
	plan.warning_count = 1;
	plan.stranded = &stranded;
	plan.stranded_count = 1;

	capture_begin();
	ncfg_cli_print_plan(&plan);
	printed = capture_end();

	line(printed, "nothing to do", "an empty plan says so");
	line(printed, "warning: the machine has no default route",
	    "a warning about no single interface carries no interface");
	line(printed, "stranded: unmanaging wg0 leaves the private key in @secret:wg0",
	    "a stranding names the device and what stays behind");
	line(printed, "          it cannot be revoked: the peer would have to be told to drop it",
	    "and why it cannot simply be withdrawn later");
	line(printed, "          to remove it:  on_unmanage = \"clear\"",
	    "and the configuration change that removes it");
	line(printed, "          to leave it:   ncfg apply --strand-credentials wg0",
	    "and the flag that consents to it for this run");
	check(before(printed, "          to remove it:", "          to leave it:"),
	    "the config answer is printed first, so the flag does not look like the fix");
}

static void show_prints_the_document_canonically(const char *text, size_t length)
{
	ncfg_document_t *document;
	const char      *printed;
	char             err[NCFG_ERROR_MAX];
	int              wrote;

	document = ncfg_document_read(text, length, err, sizeof(err));
	if (!document) {
		check(0, "the document witness parses");
		detail("why", err);
		return;
	}
	/* Nothing may `check` between these two: this test's own reporting goes to
	 * the same stdout the renderer is being watched on, and a line printed
	 * inside the capture would land in the thing being asserted. */
	capture_begin();
	wrote = ncfg_cli_print_document(document, err, sizeof(err));
	printed = capture_end();
	check(wrote, "`ncfg show` writes a document");
	check(printed[0] == '{' && strchr(printed, '\n') == strrchr(printed, '\n') &&
	    strrchr(printed, '\n') != NULL,
	    "and it is one object on one line, which is what `jq` was going to get");
	check(strstr(printed, "\"schema_version\"") != NULL,
	    "and it is the whole document, not a summary of one");
	ncfg_document_free(document);
}

/* ------------------------------------------------------------------------ *
 * What the daemon answers
 * ------------------------------------------------------------------------ */

static void a_scan_is_a_column_per_fact(void)
{
	ncfg_proto_scan_entry_t entries[4];
	ncfg_proto_scan_t       scan;
	const char             *printed;

	memset(entries, 0, sizeof(entries));
	memset(&scan, 0, sizeof(scan));

	entries[0].bssid = ncfg_proto_str("f0:9f:c2:7e:bd:7d");
	entries[0].frequency = 5220;
	entries[0].signal = -45;
	entries[0].secured = 1;
	entries[0].ssid = ncfg_proto_str("4f70656e50432e7365");
	entries[0].name = ncfg_proto_str("OpenPC.se");
	entries[0].configured = ncfg_proto_str("OpenPC.se");

	entries[1].frequency = 2427;
	entries[1].signal = -51;
	entries[1].secured = 1;
	entries[1].enterprise = 1;
	entries[1].ssid = ncfg_proto_str("656475726f616d");
	entries[1].name = ncfg_proto_str("eduroam");

	/* A hidden network, which is a fact worth saying rather than a blank
	 * cell. */
	entries[2].frequency = 5200;
	entries[2].signal = -60;
	entries[2].owe = 1;
	entries[2].ssid = ncfg_proto_str("");
	entries[2].name = ncfg_proto_str("");

	/* And one whose SSID is not text: the daemon omits the name rather than
	 * mangling it, so the hex is the only honest name there is. */
	entries[3].frequency = 2412;
	entries[3].signal = -70;
	entries[3].ssid = ncfg_proto_str("ff00ff");

	scan.interface = ncfg_proto_str("wlan0");
	scan.access_points = entries;
	scan.access_point_count = 4;

	capture_begin();
	ncfg_cli_print_scan(&scan);
	printed = capture_end();

	line(printed, " -45 dBm   5220 MHz  secured  OpenPC.se  [OpenPC.se]",
	    "a configured network is named in brackets, which is 0013's boundary made visible");
	line(printed, " -51 dBm   2427 MHz  enterprise  eduroam",
	    "an 802.1X network says enterprise, not secured");
	line(printed, " -60 dBm   5200 MHz  owe      (hidden)",
	    "an OWE network gets its own word, and a hidden one gets its own name");
	line(printed, " -70 dBm   2412 MHz  open     hex:ff00ff",
	    "and an SSID that is not text keeps its hex, prefixed");
	line(printed, "a name in brackets is a `network` block: `ncfg wifi connect ID` joins it. "
	    "The rest need config written first, which needs the admin tier.",
	    "and the note appears because something was unconfigured");

	/*
	 * Before the list, not after it: a person reads the first line and then
	 * the networks, and a caveat printed underneath is one they have already
	 * acted on.
	 */
	scan.stale = ncfg_proto_str("the radio was busy associating");
	capture_begin();
	ncfg_cli_print_scan(&scan);
	printed = capture_end();
	line(printed, "these are the previous scan's results: the radio was busy associating",
	    "a stale scan says so");
	check(before(printed, "these are the previous scan's results", " -45 dBm"),
	    "and says it above the list rather than under it");

	/*
	 * "nothing is in range" and "netcfgd could not scan" are different
	 * answers, and the second printed as the first is the whole complaint that
	 * ordering fixes.
	 */
	scan.access_point_count = 0;
	capture_begin();
	ncfg_cli_print_scan(&scan);
	printed = capture_end();
	line(printed, "no access points in range of wlan0", "an empty scan names the interface");
	check(before(printed, "these are the previous scan's results", "no access points in range"),
	    "and a stale empty scan still says which of the two answers it is");
}

static void a_radio_status_says_what_is_stopping_it(void)
{
	ncfg_proto_disabled_t    not_trying[2];
	ncfg_proto_wifi_status_t state;
	const char              *printed;

	memset(not_trying, 0, sizeof(not_trying));
	memset(&state, 0, sizeof(state));

	state.interface = ncfg_proto_str("wlan0");
	state.state = ncfg_proto_str("SCANNING");
	state.blocked = ncfg_proto_str("the radio is switched off at a hardware switch");
	not_trying[0].ssid = ncfg_proto_str("63616665");
	not_trying[0].name = ncfg_proto_str("cafe");
	not_trying[0].flags = ncfg_proto_str("[TEMP-DISABLED]");
	not_trying[1].ssid = ncfg_proto_str("ff00ff");
	not_trying[1].flags = ncfg_proto_str("[DISABLED]");
	state.not_trying = not_trying;
	state.not_trying_count = 2;

	capture_begin();
	ncfg_cli_print_wifi_status(&state);
	printed = capture_end();

	line(printed, "wlan0 SCANNING", "the interface and the supplicant's own word");
	/* **First, above the association.** A switched-off radio is the answer to
	 * "why is there no network", and printing it under the details of what the
	 * supplicant is not doing buries the one line that explains all of them. */
	line(printed, "    the radio is switched off at a hardware switch", "why the radio is off");
	check(before(printed, "    the radio is switched off", "    not being tried:"),
	    "said above everything else, because it explains all of it");
	line(printed, "    not being tried:",
	    "the half `wpa_state` cannot say: looking hopefully, or given up");
	line(printed, "        cafe [TEMP-DISABLED]", "a network it has stopped trying, and why");
	line(printed, "        hex:ff00ff [DISABLED]", "rendered by the one namer, hex and all");
	line(printed, "    a temporary disable is the supplicant giving up after repeated "
	    "failures and waiting before it tries again. It is not a network out of range -- "
	    "that one is absent from a scan, not disabled. `journalctl -u netcfgd | grep "
	    "supplicant` has the count and the reason.",
	    "and a temporary disable is explained once, not per line");

	memset(&state, 0, sizeof(state));
	state.interface = ncfg_proto_str("wlan0");
	state.state = ncfg_proto_str("COMPLETED");
	state.ssid = ncfg_proto_str("4f70656e50432e7365");
	state.name = ncfg_proto_str("OpenPC.se");
	state.bssid = ncfg_proto_str("f0:9f:c2:7e:bd:7d");
	state.network = ncfg_proto_str("OpenPC.se");
	capture_begin();
	ncfg_cli_print_wifi_status(&state);
	printed = capture_end();
	line(printed, "    OpenPC.se (f0:9f:c2:7e:bd:7d)", "an association names the access point");
	line(printed, "    from the `OpenPC.se` network block", "and which block it came from");

	/* netcfgd supplies every network the supplicant knows, so an association
	 * from none of them is a fault rather than a blank. */
	state.network = ncfg_proto_str_none();
	capture_begin();
	ncfg_cli_print_wifi_status(&state);
	printed = capture_end();
	line(printed, "    not from any `network` block, which should not happen: netcfgd "
	    "supplies every network the supplicant knows. Worth reporting.",
	    "an association from no block is reported rather than left blank");
}

static void a_station_list_shows_who_is_there_and_what_is_surprising(void)
{
	ncfg_proto_station_t  stations[3];
	ncfg_proto_stations_t report;
	const char           *printed;

	memset(stations, 0, sizeof(stations));
	memset(&report, 0, sizeof(report));

	stations[0].address = ncfg_proto_str("aa:bb:cc:dd:ee:01");
	stations[0].authorized = 1;
	stations[0].signal.present = 1;
	stations[0].signal.value = -52;
	stations[0].connected_seconds.present = 1;
	stations[0].connected_seconds.value = 3725;
	stations[0].inactive_msec.present = 1;
	stations[0].inactive_msec.value = 4000;
	stations[0].rx_bytes.present = 1;
	stations[0].rx_bytes.value = 2500000;
	stations[0].tx_bytes.present = 1;
	stations[0].tx_bytes.value = 512;

	/*
	 * A station hostapd could not read statistics for still appears, with
	 * dashes where the numbers would be. Hiding it would be the worst way for
	 * this to be wrong: the whole point is knowing who is connected.
	 */
	stations[1].address = ncfg_proto_str("aa:bb:cc:dd:ee:02");
	stations[1].authorized = 0;

	/* On the deny list and connected anyway, which should be impossible. */
	stations[2].address = ncfg_proto_str("aa:bb:cc:dd:ee:03");
	stations[2].authorized = 1;
	stations[2].listed = 1;

	report.interface = ncfg_proto_str("wlan0");
	report.access_point = ncfg_proto_str("guest");
	report.access_control = ncfg_proto_str("deny");
	report.stations = stations;
	report.station_count = 3;

	capture_begin();
	ncfg_cli_print_stations(&report);
	printed = capture_end();

	line(printed, "3 stations on `guest` (wlan0)", "the count, the access point and the radio");
	line(printed, "ADDRESS             SIGNAL  CONNECTED     IDLE        RX        TX",
	    "the heading, in the columns the rows use");
	line(printed, "aa:bb:cc:dd:ee:01  -52 dBm      1h02m       4s      2.5M      512B",
	    "a station's row, right-aligned so the numbers line up");
	/*
	 * The note says what is *surprising*, which is the opposite thing under
	 * the two policies: a listed station is expected under `allow` and should
	 * be impossible under `deny`.
	 */
	line(printed, "aa:bb:cc:dd:ee:02       --         --       --        --        --"
	    "  (associated, not authorized)",
	    "a station with no statistics keeps its row, with dashes");
	line(printed, "aa:bb:cc:dd:ee:03       --         --       --        --        --"
	    "  <- on the deny list and still connected",
	    "and one that should not be there gets an arrow");
	/*
	 * What an arrow means changed with 0041, and saying the old thing would
	 * send an operator to restart an access point that was about to fix
	 * itself: netcfgd converges hostapd's live list over the control socket,
	 * so an arrow lasts until the next reconcile rather than until somebody
	 * intervenes.
	 */
	check(strstr(printed, "An arrow means hostapd's live list does not match the document "
	    "yet") != NULL && strstr(printed, "`ncfg apply` does it now") != NULL,
	    "and the paragraph under the table says an arrow is not permanent");

	report.station_count = 0;
	capture_begin();
	ncfg_cli_print_stations(&report);
	printed = capture_end();
	line(printed, "nothing is associated with `guest` on wlan0",
	    "an access point nobody is on says so, naming both");
}

/*
 * Three states rather than two, because the third is the one somebody is stuck
 * in: a radio nothing has activated but where a supplicant is answering belongs
 * to another manager, and netcfgd declines those rather than taking them.
 * Saying "not activated" there and nothing else would invite an `activate` that
 * changes nothing.
 */
static void a_radio_list_has_three_states_and_not_two(void)
{
	ncfg_proto_radio_t radios[4];
	const char        *printed;

	memset(radios, 0, sizeof(radios));
	radios[0].interface = ncfg_proto_str("wlan0");
	radios[0].activated = 1;
	radios[0].supplicant = 1;
	radios[1].interface = ncfg_proto_str("wlan1");
	radios[1].activated = 1;
	radios[2].interface = ncfg_proto_str("wlan2");
	radios[2].supplicant = 1;
	radios[3].interface = ncfg_proto_str("wlan3");

	capture_begin();
	ncfg_cli_print_radios(radios, 4);
	printed = capture_end();

	line(printed, "wlan0            netcfgd's", "a radio netcfgd holds and is running");
	line(printed, "wlan1            netcfgd's, but no supplicant is answering",
	    "one it holds with nothing answering on it");
	line(printed, "wlan2            another manager's -- a supplicant is answering that "
	    "netcfgd did not start",
	    "and the third state, which is the one somebody is stuck in");
	line(printed, "wlan3            not activated", "and one nothing has taken");
	line(printed, "`ncfg wifi activate <radio>` hands one to netcfgd.",
	    "with the command that takes one, because something was not activated");

	capture_begin();
	ncfg_cli_print_radios(radios, 0);
	printed = capture_end();
	line(printed, "no radios on this machine", "a machine with none says so");
}

/*
 * `cycle_pending` is the column this verb was written for.
 *
 * It is the difference between a modem that has switched and one that is still
 * waiting for its link to come back, and until `ncfg modem` existed it was
 * reachable only through the gui -- so a fault that left the flag set had
 * nothing that could see it from a script.
 */
static void a_modem_says_what_it_is_on_and_whether_it_got_there(void)
{
	ncfg_proto_str_t      sim[2];
	ncfg_proto_sim_card_t cards[2];
	ncfg_proto_modem_t    modems[3];
	const char           *printed;

	memset(cards, 0, sizeof(cards));
	memset(modems, 0, sizeof(modems));
	sim[0] = ncfg_proto_str("socket");
	sim[1] = ncfg_proto_str("esim");
	cards[0].source = ncfg_proto_str("socket");
	cards[0].iccid = ncfg_proto_str("8946080023614318322");
	cards[1].source = ncfg_proto_str("esim");
	cards[1].iccid = ncfg_proto_str("8946080023614318999");

	modems[0].device = ncfg_proto_str("wwan0");
	modems[0].sim.items = sim;
	modems[0].sim.count = 2;
	modems[0].selected = ncfg_proto_str("esim");
	modems[0].apn = ncfg_proto_str("internet");
	modems[0].cards = cards;
	modems[0].card_count = 2;

	modems[1].device = ncfg_proto_str("wwan1");
	modems[1].sim.items = sim;
	modems[1].sim.count = 2;
	modems[1].selected = ncfg_proto_str("socket");
	modems[1].cycle_pending = 1;

	modems[2].device = ncfg_proto_str("wwan2");
	modems[2].sim.items = sim;
	modems[2].sim.count = 2;
	modems[2].selected = ncfg_proto_str("socket");

	capture_begin();
	ncfg_cli_print_modems(modems, 3);
	printed = capture_end();

	line(printed, "wwan0  esim  fallen back",
	    "a modem not on the document's first source has fallen back");
	line(printed, "wwan1  socket  switching",
	    "and one whose link has not been cycled yet is still switching, not there");
	line(printed, "wwan2  socket  on its first choice", "and one that got what was asked for");
	line(printed, "    sources: socket, esim",
	    "the order asked for, which never moves on its own");
	line(printed, "    apn: internet", "the apn where the document names one");
	/*
	 * **Only the sources a card has actually been read on.** The mux shows the
	 * module one SIM at a time, so `in use` is the answer to a question a
	 * muxed board cannot be asked directly: the card's own identifier is the
	 * only fact that says which source is being read.
	 */
	line(printed, "    socket card: 8946080023614318322", "a card seen in a source");
	line(printed, "    esim card: 8946080023614318999  (in use)",
	    "and the one the module is reading now");
	{
		const char *at = printed;
		unsigned    cards_shown = 0;

		while ((at = strstr(at, " card: ")) != NULL) {
			cards_shown++;
			at += 7;
		}
		check(cards_shown == 2, "and a source no helper has reported a card for is left "
		    "out rather than filled in with a placeholder");
	}

	capture_begin();
	ncfg_cli_print_modems(modems, 0);
	printed = capture_end();
	line(printed, "no device in the configuration has a `modem` block",
	    "a machine with no modem block says so");
}

/* ------------------------------------------------------------------------ *
 * The socket conversation, against a fake
 * ------------------------------------------------------------------------ */

/*
 * A daemon that answers one line and goes away.
 *
 * On a real `AF_UNIX` socket in this test's own directory, the way
 * `client/tests/client_test.c` does it -- and never the running daemon, which
 * on this machine is configuring somebody's actual network. `answer` of NULL is
 * the case that has to be told from a refusal: a peer that closes without
 * saying anything.
 */
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

static void the_conversation_is_one_request_and_one_answer(void)
{
	ncfg_proto_request_t request;
	ncfg_proto_message_t message;
	char                 path[320];
	char                 err[NCFG_ERROR_MAX];
	int                  listener = -1;
	pid_t                child;

	memset(&request, 0, sizeof(request));
	request.kind = NCFG_PROTO_REQ_RELOAD;

	/* The ordinary answer. */
	(void)snprintf(path, sizeof(path), "%s/ok.sock", testdir_path);
	child = fake_daemon(path, "{\"response\":\"ok\"}\n", &listener);
	if (child < 0) {
		check(0, "a fake daemon can be started");
		return;
	}
	check(ncfg_cli_ask(path, &request, &message, err, sizeof(err)) &&
	    message.kind == NCFG_PROTO_MESSAGE_RESPONSE &&
	    message.u.response.kind == NCFG_PROTO_RESP_OK,
	    "a request goes out and one answer comes back");
	ncfg_proto_message_free(&message);
	(void)waitpid(child, NULL, 0);
	(void)close(listener);
	(void)unlink(path);

	/*
	 * **A refusal is an answer**, which is a different thing from not reaching
	 * the daemon, and only the caller knows whether it is fatal. The sentence
	 * names the tier that would have been needed (0013), so it is handed back
	 * rather than replaced with wording of this program's own.
	 */
	(void)snprintf(path, sizeof(path), "%s/no.sock", testdir_path);
	child = fake_daemon(path,
	    "{\"response\":\"error\",\"message\":\"this needs the admin tier\"}\n", &listener);
	if (child >= 0) {
		char said[NCFG_ERROR_MAX];

		check(ncfg_cli_ask(path, &request, &message, err, sizeof(err)) &&
		    message.kind == NCFG_PROTO_MESSAGE_RESPONSE &&
		    message.u.response.kind == NCFG_PROTO_RESP_ERROR,
		    "a refusal arrives as an answer, not as a broken transport");
		if (message.kind == NCFG_PROTO_MESSAGE_RESPONSE) {
			size_t length = message.u.response.u.error.message.length;

			(void)snprintf(said, sizeof(said), "%.*s", (int)length,
			    message.u.response.u.error.message.bytes);
			check(strcmp(said, "this needs the admin tier") == 0,
			    "and the daemon's own sentence is what comes back");
		}
		ncfg_proto_message_free(&message);
		(void)waitpid(child, NULL, 0);
		(void)close(listener);
		(void)unlink(path);
	}

	/* A peer that closes without answering, which is not the same as a refusal
	 * and must not be reported as one. */
	(void)snprintf(path, sizeof(path), "%s/quiet.sock", testdir_path);
	child = fake_daemon(path, NULL, &listener);
	if (child >= 0) {
		err[0] = '\0';
		check(!ncfg_cli_ask(path, &request, &message, err, sizeof(err)) &&
		    strstr(err, "closed the connection without answering") != NULL,
		    "a daemon that closes without answering says exactly that");
		(void)waitpid(child, NULL, 0);
		(void)close(listener);
		(void)unlink(path);
	}

	/*
	 * And nothing listening at all. "connection refused" alone sends the
	 * reader looking for a network problem, so the sentence names the socket
	 * and says which program answers this command.
	 */
	(void)snprintf(path, sizeof(path), "%s/absent.sock", testdir_path);
	err[0] = '\0';
	check(!ncfg_cli_ask(path, &request, &message, err, sizeof(err)) &&
	    strstr(err, "cannot reach the daemon at") != NULL &&
	    strstr(err, "the daemon has to be running") != NULL,
	    "and an absent daemon is named, with the path it was looked for at");
	detail("said", err);
}

/* Where the socket is, which is one join and not a second spelling of a path. */
static void the_socket_lives_under_the_run_directory(void)
{
	char path[64];

	check(ncfg_cli_socket_path("/run/netcfgd", path, sizeof(path)) != NULL &&
	    strcmp(path, "/run/netcfgd/netcfgd.sock") == 0, "the socket is under the run directory");
	check(ncfg_cli_socket_path("/run/netcfgd", path, 8) == NULL,
	    "and a path that would not fit is refused rather than truncated");
}

/* ------------------------------------------------------------------------ *
 * A monitor stream
 * ------------------------------------------------------------------------ */

static void an_event_is_one_line(void)
{
	ncfg_proto_event_t event;
	const char        *printed;

	memset(&event, 0, sizeof(event));
	event.kind = NCFG_PROTO_EVENT_OBSERVED;
	event.summary = ncfg_proto_str("eth0 gained 10.0.0.5/24");
	capture_begin();
	ncfg_cli_print_event(&event, NULL, 0);
	printed = capture_end();
	line(printed, "observed  eth0 gained 10.0.0.5/24", "an observation is one line");

	memset(&event, 0, sizeof(event));
	event.kind = NCFG_PROTO_EVENT_DRIFT;
	event.interface = ncfg_proto_str("eth0");
	event.summary = ncfg_proto_str("the address is gone");
	event.action = ncfg_proto_str("reconcile");
	capture_begin();
	ncfg_cli_print_event(&event, NULL, 0);
	printed = capture_end();
	line(printed, "drift     eth0: the address is gone (reconcile)",
	    "a drift says where, what and what netcfgd will do about it");

	memset(&event, 0, sizeof(event));
	event.kind = NCFG_PROTO_EVENT_CONFIRM_RESOLVED;
	capture_begin();
	ncfg_cli_print_event(&event, NULL, 0);
	printed = capture_end();
	line(printed, "confirm   reverted to the last-good configuration",
	    "an unconfirmed window says what happened, not that it expired");

	/*
	 * A monitor that printed nothing for an event it does not know would be
	 * worse than one that prints the line: a newer daemon must not make an
	 * older `ncfg monitor` useless for the events it does understand.
	 */
	capture_begin();
	ncfg_cli_print_event(NULL, "{\"event\":\"something-new\"}", 25);
	printed = capture_end();
	line(printed, "{\"event\":\"something-new\"}",
	    "and an event this build does not know is shown whole rather than dropped");

	/*
	 * **And "whole" means whole.** The five sentences above are rendered by
	 * `ncfg_cli_event_text`, which composes into a caller's buffer, and the
	 * obvious tidy-up is to route this arm through it too. That would cut the
	 * line to the buffer: measured, a 4096-byte event came back at 511. The
	 * one arm whose entire purpose is to lose nothing would have lost the
	 * most, and it would have looked like a two-line simplification. So this
	 * arm still streams, and this check is what says so.
	 */
	{
		char big[4096];
		size_t at;

		for (at = 0; at < sizeof(big); at++) {
			big[at] = 'x';
		}
		capture_begin();
		ncfg_cli_print_event(NULL, big, sizeof(big));
		printed = capture_end();
		check(strlen(printed) == sizeof(big) + 1,
		    "an unknown event longer than any render buffer arrives whole");
		check(strlen(printed) > 4u * 512u,
		    "  and past the buffer the recognised kinds are rendered in");
	}
}

/* ------------------------------------------------------------------------ *
 * What each verb that waited on the observer does now
 * ------------------------------------------------------------------------ *
 *
 * Five arms said `it needs the netlink dump the observer is built from`. That
 * dump landed, so the sentence became false, and what replaces it is a
 * decision per verb rather than one answer for all five. These are the checks
 * that the decisions are the ones that were made.
 *
 * **Nothing here reads the kernel.** Each case reaches the arm through a
 * refusal that comes before the observation would: a subject that is not one,
 * a `--json` this wave does not carry, a number that is not a number, and --
 * for `apply` -- the refusal itself.
 */

static int   saved_stderr = -1;
static char  complaint_file[320];
static char *complained;

/* The same trick as `capture_begin`, pointed at descriptor 2. `run.c` writes
 * every diagnostic straight to the stream rather than through `out.c`, which
 * is 0261's rule, so being the reader is again the only honest way to read
 * one. */
static void complaint_begin(void)
{
	int fd;

	(void)fflush(stderr);
	saved_stderr = dup(STDERR_FILENO);
	fd = open(complaint_file, O_RDWR | O_CREAT | O_TRUNC, 0600);
	if (fd < 0 || saved_stderr < 0) {
		printf("could not redirect stderr to %s\n", complaint_file);
		exit(1);
	}
	(void)dup2(fd, STDERR_FILENO);
	(void)close(fd);
}

static const char *complaint_end(void)
{
	FILE  *file;
	long   size;
	size_t got;

	(void)fflush(stderr);
	(void)dup2(saved_stderr, STDERR_FILENO);
	(void)close(saved_stderr);
	saved_stderr = -1;

	free(complained);
	complained = NULL;
	file = fopen(complaint_file, "rb");
	if (!file) {
		return "";
	}
	(void)fseek(file, 0, SEEK_END);
	size = ftell(file);
	(void)fseek(file, 0, SEEK_SET);
	if (size < 0) {
		(void)fclose(file);
		return "";
	}
	complained = malloc((size_t)size + 1);
	if (!complained) {
		(void)fclose(file);
		return "";
	}
	got = fread(complained, 1, (size_t)size, file);
	complained[got] = '\0';
	(void)fclose(file);
	return complained;
}

/* One run of the program, with what it said on stderr and what it left with. */
static const char *ran(char **argv, int argc, int *code)
{
	complaint_begin();
	*code = ncfg_cli_main(argc, argv);
	return complaint_end();
}

/*
 * The sentence that stopped being true is gone from the source.
 *
 * Read out of `run.c` rather than out of a constant, because the constant is
 * what was deleted: a check naming it would not compile, and one naming
 * nothing would pass. A refusal pointing at a module that is present is worse
 * than one pointing at a module that is absent, because it looks right.
 */
static void the_sentence_that_stopped_being_true_is_gone(void)
{
	static const char *const roots[] = { "../src/cli/run.c", "src/cli/run.c",
		"../../src/cli/run.c" };
	char  *source = NULL;
	size_t root;

	for (root = 0; root < sizeof(roots) / sizeof(roots[0]) && !source; root++) {
		FILE *file = fopen(roots[root], "rb");
		long  size;

		if (!file) {
			continue;
		}
		(void)fseek(file, 0, SEEK_END);
		size = ftell(file);
		(void)fseek(file, 0, SEEK_SET);
		if (size >= 0) {
			source = malloc((size_t)size + 1);
			if (source) {
				source[fread(source, 1, (size_t)size, file)] = '\0';
			}
		}
		(void)fclose(file);
	}
	check(source != NULL, "the dispatcher's source can be read");
	if (!source) {
		return;
	}
	check(strstr(source, "the netlink dump the observer is built from") == NULL,
	    "no arm still says it is waiting for the observer, which landed");
	/*
	 * And the second, which cost an answer rather than only a sentence.
	 * `explain` said 0263 did not port `compile_with_provenance` and handed
	 * `ncfg_explain` nothing, so every line declined to name a file -- while
	 * the compiler had been recording positions for waves. The sentence and
	 * the argument are asserted together on purpose: deleting the comment
	 * without passing the table would leave the command exactly as wrong and
	 * this check green (project.md 10.208).
	 */
	check(strstr(source, "does not port `compile_with_provenance`") == NULL,
	    "no arm still says the compiler records no positions, which it does");
	check(strstr(source, "&provenance, err, sizeof(err))") != NULL &&
	    strstr(source, "ncfg_explain(&subject, document, observed, &provenance") != NULL,
	    "  and `explain` compiles with a positions table and hands it on");
	/*
	 * The vacuous-pass guard: a file that failed to open reads as a file with
	 * nothing objectionable in it. The anchor used to be `ncfg apply`'s "not
	 * in this wave", which is gone -- that command is written now -- so it is
	 * the refusal that replaced it: the one an `ncfg` built without a way to
	 * reach the machine gives.
	 */
	check(strstr(source, "no way to reach the ") != NULL,
	    "  and the file was read, the refusal that remains being in it");
	free(source);
}

/*
 * `ncfg apply` with no way to reach the machine refuses, and writes nothing.
 *
 * **This is the seam's whole point, driven through the program.** `cli.h`
 * keeps the library half unable to change anything: `ncfg_cli_main` installs
 * no machine, so this suite -- which runs on a developer's workstation and on
 * whatever builds the package -- cannot apply even by mistake. The check that
 * says so has to run the command, because what is being asserted is that the
 * refusal comes before anything else happens.
 *
 * `cli_apply_test.c` drives the other side: the same command with a recorder
 * installed, where the plan is carried out and nothing touches a kernel.
 */
static void apply_with_no_machine_refuses_and_changes_nothing(void)
{
	char       *argv[] = { (char *)"ncfg", (char *)"apply" };
	int         code = 0;
	const char *said = ran(argv, 2, &code);

	check(code == NCFG_CLI_EXIT_FAILED, "`ncfg apply` with no machine is refused");
	check(strstr(said, "no way to reach the machine") != NULL,
	    "  naming what is missing, which is the seam rather than the command");
	check(strstr(said, "can plan and explain") != NULL,
	    "  and what is still there, so the refusal is somewhere to go from");
}

static void the_four_that_read_the_machine_are_wired(void)
{
	char       *explain[] = { (char *)"ncfg", (char *)"explain" };
	char       *wait[] = { (char *)"ncfg", (char *)"wait-online", (char *)"soon" };
	int         code = 0;
	const char *said;

	said = ran(explain, 2, &code);
	check(strstr(said, "explain what?") != NULL,
	    "`ncfg explain` with no subject says what a subject looks like");
	check(strstr(said, "ncfg explain route eth0 default") != NULL,
	    "  in the Rust's own three examples");

	said = ran(wait, 3, &code);
	check(code == NCFG_CLI_EXIT_FAILED &&
	    strstr(said, "is not a number of seconds") != NULL,
	    "`ncfg wait-online` refuses a count that is not one");
}

/*
 * The default it waits for is the help's, and there is one of it.
 *
 * `daemon_main.c`'s rule applied to this program: the Rust writes `30 by
 * default` in the help beside a constant holding the same number, and the help
 * is the copy nobody recompiles.
 */
static void the_wait_default_is_written_down_once(void)
{
	check(strstr(ncfg_cli_usage(), NCFG_CLI_SPELL(NCFG_CLI_WAIT_ONLINE_DEFAULT) " by") !=
	    NULL, "the wait-online default in the help is the constant behind it");
	check(NCFG_CLI_WAIT_ONLINE_DEFAULT == 30,
	    "  and it is NetworkManager-wait-online.service's thirty seconds");
}

/* ------------------------------------------------------------------------ *
 * `--json`
 * ------------------------------------------------------------------------ *
 *
 * WHY THE SUBJECT IS `doc/schema/socket.json` AND NOT A STRING WRITTEN HERE
 *   `--json` prints the payload of the answer the daemon sends, with the
 *   `"response"` member left off (`cli.h` argues why). That makes the witness
 *   the whole specification: a line out of it, decoded by `proto.h` and
 *   written back by `cli.h`, has to be that line again. A case spelling the
 *   expected object here instead would be this file agreeing with itself, and
 *   would pass over the day the daemon renames a member.
 *
 *   The expected text is derived from the witness rather than typed: the tag
 *   is cut off the front mechanically, so nothing in these checks knows what
 *   the members are called.
 */

/* The witness line beginning with `head`, copied out whole. */
static int witness_line(const char *text, const char *head, char *out, size_t out_size)
{
	size_t      wanted = strlen(head);
	const char *at = text;

	while (at && *at) {
		const char *end = strchr(at, '\n');
		size_t      run = end ? (size_t)(end - at) : strlen(at);

		if (run >= wanted && memcmp(at, head, wanted) == 0) {
			if (run >= out_size) {
				return 0;
			}
			memcpy(out, at, run);
			out[run] = '\0';
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
 * The same line with its `"response":"..."` member removed, which is what
 * `--json` prints.
 *
 * Cut mechanically rather than by knowing where the members end: the tag is
 * always the first member, so this is "past the name, past the comma". A
 * response that carries nothing else -- `{"response":"ok"}` -- reduces to
 * `{}`, which is exactly why `ncfg_cli_json_ok` exists and does not print it.
 */
static int payload_of(const char *line, char *out, size_t out_size)
{
	static const char tag[] = "{\"response\":\"";
	const char       *close;

	if (strncmp(line, tag, sizeof(tag) - 1u) != 0) {
		return 0;
	}
	close = strchr(line + sizeof(tag) - 1u, '"');
	if (!close) {
		return 0;
	}
	if (close[1] == '}') {
		return snprintf(out, out_size, "{}") < (int)out_size;
	}
	if (close[1] != ',') {
		return 0;
	}
	return snprintf(out, out_size, "{%s", close + 2) < (int)out_size;
}

/* One witness response, decoded and written back through the CLI's writers. */
static void json_is_the_witness(const char *socket_text, const char *head, const char *what)
{
	char                 line[8192];
	char                 wanted[8192];
	char                 err[NCFG_ERROR_MAX];
	ncfg_proto_message_t message;
	ncfg_buf_t           buf;
	int                  wrote = 0;
	int                  same;

	if (!witness_line(socket_text, head, line, sizeof(line)) ||
	    !payload_of(line, wanted, sizeof(wanted))) {
		/* A head that matches nothing would otherwise be a vacuous pass: the
		 * comparison would simply not happen and the suite would be green. */
		check(0, what);
		detail("no witness line begins", head);
		return;
	}
	if (!ncfg_proto_response_read(line, strlen(line), &message, err, sizeof(err)) ||
	    message.kind != NCFG_PROTO_MESSAGE_RESPONSE) {
		check(0, what);
		detail("the witness did not decode", err);
		return;
	}
	ncfg_buf_init(&buf, 0);
	switch (message.u.response.kind) {
	case NCFG_PROTO_RESP_WIFI_SCAN:
		wrote = ncfg_cli_json_scan(&message.u.response.u.wifi_scan, &buf, err,
		    sizeof(err));
		break;
	case NCFG_PROTO_RESP_WIFI_STATUS:
		wrote = ncfg_cli_json_wifi_status(&message.u.response.u.wifi_status, &buf, err,
		    sizeof(err));
		break;
	case NCFG_PROTO_RESP_AP_STATIONS:
		wrote = ncfg_cli_json_stations(&message.u.response.u.ap_stations, &buf, err,
		    sizeof(err));
		break;
	case NCFG_PROTO_RESP_RADIOS:
		wrote = ncfg_cli_json_radios(message.u.response.u.radios.items,
		    message.u.response.u.radios.count, &buf, err, sizeof(err));
		break;
	case NCFG_PROTO_RESP_MODEMS:
		wrote = ncfg_cli_json_modems(message.u.response.u.modems.items,
		    message.u.response.u.modems.count, &buf, err, sizeof(err));
		break;
	default:
		ncfg_error_set(err, sizeof(err), "this test has no writer for that answer");
		break;
	}
	same = wrote && strcmp(ncfg_buf_text(&buf), wanted) == 0;
	check(same, what);
	if (!same) {
		detail("wanted", wanted);
		detail("got", wrote ? ncfg_buf_text(&buf) : err);
	}
	ncfg_buf_free(&buf);
	ncfg_proto_message_free(&message);
}

/*
 * Every answer `--json` renders is the witness with its tag cut off.
 *
 * Seven lines rather than five: the two `wifi_scan` shapes differ by `stale`
 * and the two `wifi_status` shapes differ by `blocked` and by having no
 * `not_trying` at all, and an optional member that is written when it should
 * be absent is the way a writer of a skip-when-empty format goes wrong.
 */
static void the_json_form_is_the_witness_with_its_tag_removed(const char *socket_text)
{
	json_is_the_witness(socket_text,
	    "{\"response\":\"wifi_scan\",\"interface\":\"wlan0\",\"access_points\":[{",
	    "a scan as JSON is the wire's scan without its tag");
	json_is_the_witness(socket_text,
	    "{\"response\":\"wifi_scan\",\"interface\":\"wlan0\",\"access_points\":[]",
	    "  and a stale scan still says why it is the previous one");
	json_is_the_witness(socket_text,
	    "{\"response\":\"wifi_status\",\"interface\":\"wlan0\",\"state\":\"COMPLETED\"",
	    "a radio status carries what it has stopped trying");
	json_is_the_witness(socket_text,
	    "{\"response\":\"wifi_status\",\"interface\":\"wlan0\",\"state\":\"SCANNING\"",
	    "  and one with nothing to say omits those members rather than nulling them");
	json_is_the_witness(socket_text, "{\"response\":\"radios\"",
	    "the radios keep the object the socket wraps them in");
	json_is_the_witness(socket_text, "{\"response\":\"ap_stations\"",
	    "a station list carries the policy its `listed` column is read under");
	json_is_the_witness(socket_text, "{\"response\":\"modems\"",
	    "and a modem that is not switching says nothing about switching");
}

/*
 * An explanation as JSON, which is the one shape that is not the socket's.
 *
 * `total` is this port's and 0263 records it: the text form ends with "showing
 * 256 of 1202" where `NCFG_EXPLAIN_FACTS_MAX` bit, and a machine-readable form
 * that dropped the count would be the one place `--json` says less than the
 * table. The expected object is still the witness's -- the member is appended
 * to it here, so the subject, the facts and their spellings are not this
 * file's idea of them.
 */
static void an_explanation_says_how_many_facts_there_were(const char *socket_text)
{
	char                line[4096];
	char                wanted[4096];
	char                err[NCFG_ERROR_MAX];
	char                subject[] = "eth0";
	char                topic[] = "desired";
	char                statement[] = "static 192.0.2.1/24";
	char                source[] = "netcfgd.conf:3";
	ncfg_explain_fact_t fact;
	ncfg_explanation_t  explanation;
	ncfg_buf_t          buf;
	size_t              end;

	if (!witness_line(socket_text, "{\"response\":\"explanation\"", line, sizeof(line)) ||
	    !payload_of(line, wanted, sizeof(wanted))) {
		check(0, "the explanation witness can be read");
		return;
	}
	end = strlen(wanted);
	if (end == 0u || wanted[end - 1u] != '}') {
		check(0, "the explanation witness is an object");
		return;
	}
	(void)snprintf(wanted + end - 1u, sizeof(wanted) - (end - 1u), ",\"total\":1}");

	fact.topic = topic;
	fact.detail = statement;
	fact.source = source;
	explanation.subject = subject;
	explanation.facts = &fact;
	explanation.count = 1u;
	explanation.total = 1u;

	ncfg_buf_init(&buf, 0);
	{
		int same = ncfg_cli_json_explanation(&explanation, &buf, err, sizeof(err)) &&
		    strcmp(ncfg_buf_text(&buf), wanted) == 0;

		check(same, "an explanation is the socket's facts with a count beside them");
		if (!same) {
			detail("wanted", wanted);
			detail("got", ncfg_buf_text(&buf));
		}
	}
	ncfg_buf_free(&buf);

	/* The case the member exists for: more facts than were kept. A reader
	 * compares `total` against the length of `facts` and sees the difference,
	 * which is what the last line of the text form says in words. */
	explanation.total = 1202u;
	ncfg_buf_init(&buf, 0);
	check(ncfg_cli_json_explanation(&explanation, &buf, err, sizeof(err)) &&
	    strstr(ncfg_buf_text(&buf), "\"total\":1202") != NULL,
	    "  and a bounded one says how many there were, not how many it kept");
	ncfg_buf_free(&buf);

	/* A fact from nowhere nameable has no `source`, absent rather than null:
	 * absent, null and empty are three answers on this socket. */
	fact.source = NULL;
	explanation.total = 1u;
	ncfg_buf_init(&buf, 0);
	check(ncfg_cli_json_explanation(&explanation, &buf, err, sizeof(err)) &&
	    strstr(ncfg_buf_text(&buf), "source") == NULL,
	    "  and a fact with no place to point at omits `source` rather than nulling it");
	ncfg_buf_free(&buf);
}

/*
 * A name that is not valid UTF-8 is refused, and nothing is printed.
 *
 * Reachable rather than theoretical: the JSON *reader* does not check a
 * string's bytes, so a stray octet inside a `name` travels from the daemon
 * into a decoded answer intact -- and 0263 refuses to repair it, because the
 * raw bytes, `\u00XX` per byte and U+FFFD each put a value in front of
 * somebody that nobody typed.
 *
 * **The buffer is checked as well as the answer.** `ncfg_buf_t` hands out the
 * empty string for a buffer that failed rather than the part that fitted, and
 * a caller that printed anyway would emit half an object that looks whole.
 */
static void a_name_that_is_not_text_is_refused_rather_than_repaired(void)
{
	static const char       latin1[] = { 'c', 'a', 'f', (char)0xe9 };
	ncfg_proto_scan_entry_t point;
	ncfg_proto_scan_t       scan;
	ncfg_buf_t              buf;
	char                    err[NCFG_ERROR_MAX];

	memset(&point, 0, sizeof(point));
	point.bssid = ncfg_proto_str("00:11:22:33:44:55");
	point.frequency = 2412;
	point.signal = -40;
	point.ssid = ncfg_proto_str("636166e9");
	point.name.bytes = latin1;
	point.name.length = sizeof(latin1);

	memset(&scan, 0, sizeof(scan));
	scan.interface = ncfg_proto_str("wlan0");
	scan.access_points = &point;
	scan.access_point_count = 1u;

	err[0] = '\0';
	ncfg_buf_init(&buf, 0);
	check(!ncfg_cli_json_scan(&scan, &buf, err, sizeof(err)),
	    "a name that is not UTF-8 is refused rather than repaired");
	check(strstr(err, "not UTF-8") != NULL, "  and the sentence says which rule it broke");
	check(strcmp(ncfg_buf_text(&buf), "") == 0,
	    "  and nothing is left in the buffer, not the part that fitted");
	detail("said", err);
	ncfg_buf_free(&buf);

	/* The hex form is the canonical identity and is always text, so the same
	 * access point still renders once the unrepairable half is absent -- which
	 * is what the daemon does with it, and why `name` is optional at all. */
	point.name = ncfg_proto_str_none();
	ncfg_buf_init(&buf, 0);
	check(ncfg_cli_json_scan(&scan, &buf, err, sizeof(err)) &&
	    strstr(ncfg_buf_text(&buf), "\"ssid\":\"636166e9\"") != NULL &&
	    strstr(ncfg_buf_text(&buf), "\"name\"") == NULL,
	    "  and the same access point still renders by the identity that is not text");
	ncfg_buf_free(&buf);
}

/* ------------------------------------------------------------------------ *
 * `--json` through the program, against a fake daemon
 * ------------------------------------------------------------------------ */

/* One run of the program, with what it printed on stdout. */
static const char *ran_printing(char **argv, int argc, int *code)
{
	const char *printed;

	complaint_begin();
	capture_begin();
	*code = ncfg_cli_main(argc, argv);
	printed = capture_end();
	(void)complaint_end();
	return printed;
}

/*
 * The same, with a fake daemon on the socket the run directory implies.
 *
 * `--run-dir` rather than the default, for the reason at the top of this file:
 * the machine this builds on has a real netcfgd on it, configuring somebody's
 * actual network, and a test that reached `/run/netcfgd/netcfgd.sock` would be
 * talking to it.
 */
static const char *answered(const char *answer, char **argv, int argc, int *code)
{
	char        path[320];
	const char *printed;
	pid_t       child;
	int         listener = -1;

	(void)snprintf(path, sizeof(path), "%s/netcfgd.sock", testdir_path);
	(void)unlink(path);
	child = fake_daemon(path, answer, &listener);
	if (child < 0) {
		*code = -1;
		return "";
	}
	printed = ran_printing(argv, argc, code);
	(void)waitpid(child, NULL, 0);
	(void)close(listener);
	(void)unlink(path);
	return printed;
}

/*
 * Each verb that renders an answer renders it both ways, from one request.
 *
 * Driven through `ncfg_cli_main` rather than by calling the writers, because
 * what is being asserted is the arm: these six used to refuse the flag, and a
 * check against the writer alone would stay green over an arm that still did.
 * The table is asserted beside every one of them, because the fault the flag
 * exists to avoid is a table printed where a document was asked for -- and a
 * document printed where a table was asked for is the same fault backwards.
 */
static void every_verb_that_renders_answers_json_too(const char *socket_text)
{
	char       *radios[] = { (char *)"ncfg", (char *)"wifi", (char *)"radios",
		(char *)"--run-dir", testdir_path, (char *)"--json" };
	char       *table[] = { (char *)"ncfg", (char *)"wifi", (char *)"radios",
		(char *)"--run-dir", testdir_path };
	char       *modem[] = { (char *)"ncfg", (char *)"modem", (char *)"--run-dir",
		testdir_path, (char *)"--json" };
	char       *scan[] = { (char *)"ncfg", (char *)"wifi", (char *)"scan",
		(char *)"wlan0", (char *)"--run-dir", testdir_path, (char *)"--json" };
	char       *reload[] = { (char *)"ncfg", (char *)"reload", (char *)"--run-dir",
		testdir_path, (char *)"--json" };
	char        line[8192];
	char        wanted[8192];
	char        sent[8194];
	const char *printed;
	int         code = -1;

	if (!witness_line(socket_text, "{\"response\":\"radios\"", line, sizeof(line)) ||
	    !payload_of(line, wanted, sizeof(wanted))) {
		check(0, "the radios witness can be read");
		return;
	}
	/* The framer wants a whole line: a witness read without its newline would
	 * arrive as a message cut in half, which is a different check. */
	(void)snprintf(sent, sizeof(sent), "%s\n", line);
	printed = answered(sent, radios, 6, &code);
	check(code == NCFG_CLI_EXIT_OK && has_line(printed, wanted),
	    "`ncfg wifi radios --json` prints the answer as one object");
	if (!has_line(printed, wanted)) {
		detail("wanted", wanted);
		detail("got", printed);
	}

	printed = answered(sent, table, 5, &code);
	check(code == NCFG_CLI_EXIT_OK && !has_line(printed, wanted) &&
	    strstr(printed, "wlan0") != NULL,
	    "  and without the flag the same request still prints the table");

	if (witness_line(socket_text, "{\"response\":\"modems\"", line, sizeof(line)) &&
	    payload_of(line, wanted, sizeof(wanted))) {
		(void)snprintf(sent, sizeof(sent), "%s\n", line);
		printed = answered(sent, modem, 5, &code);
		check(code == NCFG_CLI_EXIT_OK && has_line(printed, wanted),
		    "`ncfg modem --json` prints the modems as one object");
	} else {
		check(0, "the modems witness can be read");
	}

	if (witness_line(socket_text,
	    "{\"response\":\"wifi_scan\",\"interface\":\"wlan0\",\"access_points\":[{", line,
	    sizeof(line)) && payload_of(line, wanted, sizeof(wanted))) {
		(void)snprintf(sent, sizeof(sent), "%s\n", line);
		printed = answered(sent, scan, 7, &code);
		check(code == NCFG_CLI_EXIT_OK && has_line(printed, wanted),
		    "`ncfg wifi scan wlan0 --json` prints the scan as one object");
	} else {
		check(0, "the scan witness can be read");
	}

	/*
	 * **`reload` was never one of the six that refused the flag**, which made
	 * it the place `--json` was still accepted and ignored: a script asking
	 * for a document got "reloaded; the configuration compiles". The payload
	 * rule alone would make this `{}` -- `{"response":"ok"}` carries nothing
	 * beside its tag -- so it is `{"ok":true}`, which is a fact a script can
	 * act on and the protocol's own word for it.
	 */
	printed = answered("{\"response\":\"ok\"}\n", reload, 5, &code);
	check(code == NCFG_CLI_EXIT_OK && has_line(printed, "{\"ok\":true}"),
	    "a verb whose whole answer is `ok` says so as an object");
	check(!has_line(printed, "reloaded; the configuration compiles"),
	    "  rather than the sentence it prints for a person");

	printed = answered("{\"response\":\"ok\"}\n", reload, 4, &code);
	check(code == NCFG_CLI_EXIT_OK && has_line(printed, "reloaded; the configuration "
	    "compiles"), "  and the sentence is still what it prints without the flag");
}

/*
 * A refusal the writer makes, met through the program.
 *
 * The daemon's line carries a raw octet inside a JSON string, which the reader
 * passes through and the writer will not emit. What that must produce is a
 * sentence and an empty stdout -- and the same command without the flag must
 * still answer, because the table is text for a terminal and has no such rule.
 */
static void a_scan_that_cannot_be_written_says_so_and_prints_nothing(void)
{
	static const char answer[] =
	    "{\"response\":\"wifi_scan\",\"interface\":\"wlan0\",\"access_points\":"
	    "[{\"bssid\":\"00:11:22:33:44:55\",\"frequency\":2412,\"signal\":-40,"
	    "\"secured\":false,\"owe\":false,\"enterprise\":false,\"ssid\":\"6361ff\","
	    "\"name\":\"ca\xff\"}]}\n";
	char       *json[] = { (char *)"ncfg", (char *)"wifi", (char *)"scan",
		(char *)"wlan0", (char *)"--run-dir", testdir_path, (char *)"--json" };
	const char *printed;
	const char *said;
	int         code = 0;

	printed = answered(answer, json, 7, &code);
	said = complained ? complained : "";
	check(code == NCFG_CLI_EXIT_FAILED, "a scan that cannot be written as JSON fails");
	check(strcmp(printed, "") == 0, "  and prints nothing at all on stdout");
	check(strstr(said, "not UTF-8") != NULL, "  and says which rule the answer broke");
	check(strstr(said, "without `--json`") != NULL,
	    "  and points at the form that can still show it");
	detail("said", said);

	printed = answered(answer, json, 6, &code);
	check(code == NCFG_CLI_EXIT_OK && strstr(printed, "2412 MHz") != NULL,
	    "  and the table prints the same access point, having no such rule");
}

/*
 * `ncfg monitor --json` is the line the daemon sent, decoded by nobody.
 *
 * The one `--json` in this program that switches a rendering off rather than a
 * writer on. An event is already one JSON value on a line; composing one back
 * from `ncfg_proto_event_t` would drop every member this build has never heard
 * of, on the one verb whose argument for existing is that it does not swallow
 * what it cannot name.
 */
static void a_monitor_in_json_is_the_line_the_daemon_sent(const char *socket_text)
{
	char       *json[] = { (char *)"ncfg", (char *)"monitor", (char *)"--run-dir",
		testdir_path, (char *)"--json" };
	char        stream[4096];
	char        observed[2048];
	const char *printed;
	int         code = -1;

	if (!witness_line(socket_text, "{\"event\":\"observed\"", observed,
	    sizeof(observed))) {
		check(0, "the observed-event witness can be read");
		return;
	}
	(void)snprintf(stream, sizeof(stream), "%s\n{\"event\":\"nothing-this-build-knows\","
	    "\"detail\":\"kept whole\"}\n", observed);

	printed = answered(stream, json, 5, &code);
	check(code == NCFG_CLI_EXIT_OK && has_line(printed, observed),
	    "`ncfg monitor --json` prints the event line as it arrived");
	check(has_line(printed, "{\"event\":\"nothing-this-build-knows\",\"detail\":\"kept "
	    "whole\"}"), "  including one this build has never heard of, whole");
	if (!has_line(printed, observed)) {
		detail("wanted", observed);
		detail("got", printed);
	}

	printed = answered(stream, json, 4, &code);
	check(code == NCFG_CLI_EXIT_OK && has_line(printed, "observed  eth0 gained an "
	    "address"), "  and without the flag it is the sentence a person reads");
}

/*
 * No arm refuses the flag any more, said against the source.
 *
 * `status`, `plan` and `explain` answer it from a document this test cannot
 * reach: each one's next step is `ncfg_observe_current`, which is a netlink
 * dump of the machine the suite is built on -- and this file's rule is that
 * nothing here touches that machine. So what is checked is that the refusal is
 * gone and that those three arms call the writers whose output is pinned
 * elsewhere: `observed_test.c` and `plan_test.c` hold `ncfg_observed_write`
 * and `ncfg_plan_write` against `doc/schema/`, and the check above holds the
 * explanation's shape against `doc/schema/socket.json`.
 *
 * It is a weaker check than the ones above it and is named as one. What it
 * cannot see is an arm that renders the right document and prints it wrongly.
 */
static void no_arm_refuses_the_flag_any_more(void)
{
	static const char *const roots[] = { "../src/cli/run.c", "src/cli/run.c",
		"../../src/cli/run.c" };
	char  *source = NULL;
	size_t root;

	for (root = 0; root < sizeof(roots) / sizeof(roots[0]) && !source; root++) {
		FILE *file = fopen(roots[root], "rb");
		long  size;

		if (!file) {
			continue;
		}
		(void)fseek(file, 0, SEEK_END);
		size = ftell(file);
		(void)fseek(file, 0, SEEK_SET);
		if (size >= 0) {
			source = malloc((size_t)size + 1);
			if (source) {
				source[fread(source, 1, (size_t)size, file)] = '\0';
			}
		}
		(void)fclose(file);
	}
	check(source != NULL, "the dispatcher's source can be read");
	if (!source) {
		return;
	}
	check(strstr(source, "json_not_in_this_wave") == NULL,
	    "no arm still refuses `--json`");
	check(strstr(source, "ncfg_observed_write(observed") != NULL,
	    "  `ncfg status --json` writes the observation `/run` gets");
	check(strstr(source, "ncfg_plan_write(plan") != NULL,
	    "  `ncfg plan --json` writes the plan `doc/schema/plan.json` pins");
	check(strstr(source, "ncfg_cli_json_explanation(explanation") != NULL,
	    "  and `ncfg explain --json` writes the explanation");
	/*
	 * The vacuous-pass guard: a file read short reads as a file with nothing
	 * objectionable in it, and one of the four checks above is an absence.
	 * `dispatch` is looked for rather than a sentence, because a sentence is
	 * what a wave deletes -- the guard that first stood here named the
	 * refusals that remain, and removing refusals is what this port is
	 * spending itself on. One of the two it named has already gone.
	 */
	check(strstr(source, "static int dispatch(") != NULL,
	    "  and the file was read to the end, the dispatcher being near it");
	free(source);
}

int main(void)
{
	char *observed_text;
	char *document_text;
	char *socket_text;
	size_t observed_length = 0;
	size_t document_length = 0;
	size_t socket_length = 0;

	(void)testdir_make("cli");
	(void)snprintf(capture_file, sizeof(capture_file), "%s/out", testdir_path);
	(void)snprintf(complaint_file, sizeof(complaint_file), "%s/err", testdir_path);

	every_command_in_the_help_text_is_dispatched();
	the_version_surface_names_the_copyright_holder();
	the_sentence_that_stopped_being_true_is_gone();
	apply_with_no_machine_refuses_and_changes_nothing();
	the_four_that_read_the_machine_are_wired();
	the_wait_default_is_written_down_once();

	a_bare_dash_is_a_filename_and_not_an_option();
	a_value_is_never_mistaken_for_a_subcommand();
	a_flag_may_come_first();
	the_parser_refuses_and_says_why();

	every_security_shape_has_its_own_word();
	an_access_point_is_named_three_ways_and_never_two();
	a_kind_the_kernel_gave_wins_over_the_name();
	online_means_a_global_address_and_a_default_route();
	a_number_is_rendered_in_the_units_it_is_in();

	socket_text = witness("socket.json", &socket_length);
	if (!socket_text) {
		check(0, "the socket witness can be opened");
	} else {
		the_json_form_is_the_witness_with_its_tag_removed(socket_text);
		an_explanation_says_how_many_facts_there_were(socket_text);
		every_verb_that_renders_answers_json_too(socket_text);
		a_monitor_in_json_is_the_line_the_daemon_sent(socket_text);
	}
	free(socket_text);

	observed_text = witness("observed.json", &observed_length);
	document_text = witness("document.json", &document_length);
	if (!observed_text || !document_text) {
		/* A path that is wrong produces a vacuous pass -- the checks below
		 * would simply not run, and the suite would be green having compared
		 * nothing. So it is a failure, named. */
		check(0, "the schema witnesses can be opened");
	} else {
		the_status_listing_is_what_an_operator_reads(observed_text, observed_length);
		a_plan_says_what_and_why(document_text, document_length, observed_text,
		    observed_length);
		show_prints_the_document_canonically(document_text, document_length);
	}
	free(observed_text);
	free(document_text);

	what_something_else_reported_is_marked_as_reported();
	an_empty_plan_still_prints_what_is_not_an_action();

	a_scan_is_a_column_per_fact();
	a_radio_status_says_what_is_stopping_it();
	a_station_list_shows_who_is_there_and_what_is_surprising();
	a_radio_list_has_three_states_and_not_two();
	a_modem_says_what_it_is_on_and_whether_it_got_there();

	the_socket_lives_under_the_run_directory();
	the_conversation_is_one_request_and_one_answer();
	an_event_is_one_line();

	a_name_that_is_not_text_is_refused_rather_than_repaired();
	no_arm_refuses_the_flag_any_more();
	a_scan_that_cannot_be_written_says_so_and_prints_nothing();

	free(captured);
	free(complained);
	testdir_remove(testdir_path);

	if (failures == 0) {
		printf("cli_test: all checks passed\n");
	} else {
		printf("cli_test: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
