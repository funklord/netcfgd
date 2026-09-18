/*
 * main_test.c -- the multi-call entry point, without starting anything.
 *
 * WHAT CAN BE CHECKED HERE AND WHAT MAY NOT BE RUN
 *   This is a network configuration daemon and the machine these tests build
 *   on is somebody's workstation. So nothing here execs the program, opens a
 *   netlink socket, takes the apply lock or touches the daemon's socket.
 *   Everything below calls the entry points as functions -- which is what the
 *   multi-call shape buys and why `main.c` is four lines: the dispatch, the
 *   option parsing, the usage text, the version surface and every exit status
 *   are ordinary calls, and only `main` itself is out of reach.
 *
 *   `ncfg_main_probe` is called for one case only: the one where no URL was
 *   given, which returns before `ncfg_portal_helper` is reached. Calling it
 *   with a URL would shed every privilege in this process and never give them
 *   back, and would then resolve a name on whatever network this machine is
 *   on. `portal_test.c` drives the helper properly, in children of its own.
 *
 * WHY THE REFUSAL IS CHECKED AGAINST `daemon.h`
 *   `netcfgd` will not start, and it says so by naming the seam it is waiting
 *   for: `ncfg_daemon_observe_fn`. A sentence naming a symbol is only worth
 *   more than a vague one for as long as the symbol is spelt that way, and
 *   nothing in a string literal goes red when a type is renamed. So the header
 *   is read at run time and the name is looked up in it. A header that cannot
 *   be found fails rather than passing over an empty comparison, which is the
 *   shape `cli_test.c` uses for the same kind of check.
 */
#include "../src/main/main_internal.h"

#include "ncfg/base.h"
#include "ncfg/cli.h"
#include "ncfg/config.h"
#include "ncfg/log.h"
#include "ncfg/portal.h"
#include "ncfg/state.h"

#include "testdir.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
 * Capturing what a program printed
 * ------------------------------------------------------------------------ *
 *
 * Both streams, because these entry points use both and the difference is a
 * decision rather than an accident: what a program produces goes to stdout
 * through `ncfg_out_*` and leaves at 141 when the reader has gone (0261),
 * while a refusal goes to stderr without going through it. Rendering into a
 * buffer instead would be testing a second printer the program does not use.
 */

static int   saved[2] = { -1, -1 };
static char  capture_file[320];
static char *captured;

static void capture_begin(int which)
{
	int fd;

	(void)fflush(stdout);
	(void)fflush(stderr);
	saved[which == STDERR_FILENO ? 1 : 0] = dup(which);
	fd = open(capture_file, O_RDWR | O_CREAT | O_TRUNC, 0600);
	if (fd < 0 || saved[which == STDERR_FILENO ? 1 : 0] < 0) {
		printf("could not redirect %d to %s\n", which, capture_file);
		exit(1);
	}
	(void)dup2(fd, which);
	(void)close(fd);
}

/* What was written, owned by this file and replaced by the next capture. */
static const char *capture_end(int which)
{
	int    slot = which == STDERR_FILENO ? 1 : 0;
	FILE  *file;
	long   size;
	size_t got;

	(void)fflush(stdout);
	(void)fflush(stderr);
	(void)dup2(saved[slot], which);
	(void)close(saved[slot]);
	saved[slot] = -1;

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
	captured = malloc((size_t)size + 1u);
	if (!captured) {
		(void)fclose(file);
		return "";
	}
	got = fread(captured, 1, (size_t)size, file);
	captured[got] = '\0';
	(void)fclose(file);
	return captured;
}

/* Whether `text` holds `wanted` as a whole line. */
static int has_line(const char *text, const char *wanted)
{
	const char *at = text;
	size_t      length = strlen(wanted);

	while (at) {
		if (strncmp(at, wanted, length) == 0 && (at[length] == '\n' || at[length] == '\0')) {
			return 1;
		}
		at = strchr(at, '\n');
		if (at) {
			at++;
		}
	}
	return 0;
}

static void line(const char *text, const char *wanted, const char *what)
{
	int found = has_line(text, wanted);

	if (!found) {
		detail("wanted this line", wanted);
	}
	check(found, what);
}

/* A source file of this tree's, read from wherever the test was started --
 * `cli_test.c`'s arrangement, which is how these binaries are run both from
 * `c/` and from `c/tests/`. NULL where none of the three roots held it. */
static char *read_source(const char *relative)
{
	static const char *const roots[] = { "..", ".", "../.." };
	size_t root;

	for (root = 0; root < sizeof(roots) / sizeof(roots[0]); root++) {
		char  path[320];
		FILE *file;
		long  size;

		(void)snprintf(path, sizeof(path), "%s/%s", roots[root], relative);
		file = fopen(path, "rb");
		if (!file) {
			continue;
		}
		(void)fseek(file, 0, SEEK_END);
		size = ftell(file);
		(void)fseek(file, 0, SEEK_SET);
		if (size >= 0) {
			char *source = malloc((size_t)size + 1u);

			if (source) {
				source[fread(source, 1, (size_t)size, file)] = '\0';
				(void)fclose(file);
				return source;
			}
		}
		(void)fclose(file);
	}
	return NULL;
}

/*
 * The first `ncfg_`-shaped word in a sentence, into `out`.
 *
 * What a refusal names has to be pulled out of the refusal, not written down
 * beside it: a second copy here would agree with a stale sentence for ever.
 * Returns 0 where the sentence carries no such word, which is itself a finding.
 */
static int identifier_in(const char *sentence, char *out, size_t out_size)
{
	const char *at = strstr(sentence, "ncfg_");
	size_t      taken = 0;

	if (!at || out_size == 0u) {
		return 0;
	}
	while (taken + 1u < out_size && (at[taken] == '_' ||
	    (at[taken] >= 'a' && at[taken] <= 'z') || (at[taken] >= 'A' && at[taken] <= 'Z') ||
	    (at[taken] >= '0' && at[taken] <= '9'))) {
		out[taken] = at[taken];
		taken++;
	}
	out[taken] = '\0';
	return taken > 5u;
}

/* ------------------------------------------------------------------------ *
 * The dispatch
 * ------------------------------------------------------------------------ */

/*
 * One image, three programs, and no fourth.
 *
 * The three shapes `argv[0]` actually arrives in are all here, because they
 * are the three ways the binary is reached: a symlink through `PATH`, an
 * absolute path from an init system, and a relative one out of a build tree.
 */
static void the_name_chooses_the_program(void)
{
	check(ncfg_main_program_for("ncfg") == NCFG_MAIN_PROGRAM_CLIENT,
	    "`ncfg` through PATH is the client");
	check(ncfg_main_program_for("/usr/bin/ncfg") == NCFG_MAIN_PROGRAM_CLIENT,
	    "and so is an absolute path to it");
	check(ncfg_main_program_for("./c/ncfg") == NCFG_MAIN_PROGRAM_CLIENT,
	    "and so is one out of a build tree");
	check(ncfg_main_program_for("netcfgd") == NCFG_MAIN_PROGRAM_DAEMON,
	    "`netcfgd` is the daemon");
	check(ncfg_main_program_for("/usr/sbin/netcfgd") == NCFG_MAIN_PROGRAM_DAEMON,
	    "and so is the path an init system would use");
	check(ncfg_main_program_for(NCFG_PORTAL_HELPER_NAME) == NCFG_MAIN_PROGRAM_PROBE,
	    "the third name is the captive-portal child");

	/*
	 * Everything else refuses, and the near misses are the point: a prefix
	 * match or a `strncmp` with the wrong length would start a daemon for
	 * somebody who typed a client's name, which is the one wrong answer this
	 * dispatch can give.
	 */
	check(ncfg_main_program_for("ncfgd") == NCFG_MAIN_PROGRAM_NONE,
	    "a name that is neither is neither");
	check(ncfg_main_program_for("netcfg") == NCFG_MAIN_PROGRAM_NONE,
	    "a prefix of the daemon's name is not the daemon");
	check(ncfg_main_program_for("ncfg2") == NCFG_MAIN_PROGRAM_NONE,
	    "and a name the client's is a prefix of is not the client");
	check(ncfg_main_program_for("netcfgd-probe-x") == NCFG_MAIN_PROGRAM_NONE,
	    "nor is one the helper's name is a prefix of");
	check(ncfg_main_program_for("") == NCFG_MAIN_PROGRAM_NONE,
	    "an empty argv[0] is not a program");
	check(ncfg_main_program_for(NULL) == NCFG_MAIN_PROGRAM_NONE,
	    "and neither is none at all -- execve takes an empty vector");

	/* A path that ends in a separator names a directory, and this answers no
	 * name rather than the component above it. Rust's `file_name` answers
	 * `bin` here, which is a directory being read as a program. */
	check(ncfg_main_program_for("/usr/bin/") == NCFG_MAIN_PROGRAM_NONE,
	    "a trailing slash resolves to no name, not to the directory above");
	check(strcmp(ncfg_main_basename("/usr/bin/ncfg"), "ncfg") == 0,
	    "the name is the text after the last separator");
	check(strcmp(ncfg_main_basename("ncfg"), "ncfg") == 0,
	    "and a bare name is already that text");
	check(strcmp(ncfg_main_basename(NULL), "") == 0, "NULL is the empty name");
}

/*
 * Called as neither: it says what the two names are, and it does not guess.
 *
 * The exit status is its own, and it is not the daemon's `1`: a script that
 * saw "this image does not know which program it is" as "the daemon would not
 * start" would be told the machine's configuration failed by an installation
 * mistake.
 */
static void neither_name_says_what_the_names_are(void)
{
	const char *printed;
	int         code;

	capture_begin(STDERR_FILENO);
	code = ncfg_main_miscalled("netcfgd-typo");
	printed = capture_end(STDERR_FILENO);

	check(code == NCFG_MAIN_EXIT_MISCALLED, "being called by neither name exits 2");
	check(code != NCFG_MAIN_EXIT_FAILED,
	    "and that is not the status a daemon that would not start leaves");
	check(strstr(printed, "`netcfgd`") != NULL, "the refusal names the daemon");
	check(strstr(printed, "`ncfg`") != NULL, "and the client");
	check(strstr(printed, "netcfgd-typo") != NULL, "and repeats what it was called as");
	line(printed, "install it as `netcfgd` and symlink `ncfg` to it",
	    "and says what the install looks like");
}

/*
 * `argv[0]` is made legible before it is printed back.
 *
 * It is chosen by whoever ran the program, the refusal above repeats it to a
 * terminal, and the one thing known at that moment is that the name is wrong.
 * The Rust prints it raw. Here an escape sequence arrives as dots.
 */
static void the_name_it_repeats_cannot_drive_a_terminal(void)
{
	char        legible[NCFG_MAIN_NAME_MAX];
	char        long_name[NCFG_MAIN_NAME_KEEP + 40];
	const char *printed;

	ncfg_main_legible_name("a\033[2Jb", legible, sizeof(legible));
	check(strchr(legible, '\033') == NULL, "an escape byte does not survive the copy");
	check(strcmp(legible, "a.[2Jb") == 0, "it is a dot, and the rest is left alone");

	ncfg_main_legible_name("/usr/local/libexec/net cfgd", legible, sizeof(legible));
	check(strcmp(legible, "/usr/local/libexec/net cfgd") == 0,
	    "a path with a space in it is a path, and is kept whole");

	memset(long_name, 'x', sizeof(long_name));
	long_name[sizeof(long_name) - 1u] = '\0';
	ncfg_main_legible_name(long_name, legible, sizeof(legible));
	check(strlen(legible) == (size_t)NCFG_MAIN_NAME_KEEP + 3u,
	    "a name past the ceiling is cut to it");
	check(strcmp(legible + NCFG_MAIN_NAME_KEEP, "...") == 0,
	    "and says there was more, rather than reading as the whole name");

	/* And the refusal actually uses it, which is the part that would rot: a
	 * legible copy nothing printed would pass every check above. */
	capture_begin(STDERR_FILENO);
	(void)ncfg_main_miscalled("bad\033[2Jname");
	printed = capture_end(STDERR_FILENO);
	check(strchr(printed, '\033') == NULL, "and the refusal prints that copy, not argv[0]");
}

/* ------------------------------------------------------------------------ *
 * `netcfgd`
 * ------------------------------------------------------------------------ */

/* A command line, built where a test needs one. Nothing is owned: these point
 * at literals that outlive the call, which is what `argv` does. */
static int run_netcfgd(const char *one, const char *two)
{
	char *argv[3];
	int   count = 1;

	argv[0] = (char *)(uintptr_t)(const void *)"netcfgd";
	argv[1] = NULL;
	argv[2] = NULL;
	if (one) {
		argv[count++] = (char *)(uintptr_t)(const void *)one;
	}
	if (two) {
		argv[count++] = (char *)(uintptr_t)(const void *)two;
	}
	return ncfg_main_netcfgd(count, argv);
}


/*
 * Every option the help text offers has an arm that dispatches it.
 *
 * `reload` drifted out of `ncfg` for a whole milestone: the request was in the
 * protocol, in the schema and in the authorisation table, and no shipped
 * client could send it, because nothing compared the two lists. A daemon's
 * help is worse -- it is read by exactly the person who has no other way to
 * find out what the flags are.
 */
static void every_option_in_the_help_text_is_parsed(void)
{
	char       *source = read_source("src/main/daemon_main.c");
	const char *at = ncfg_main_netcfgd_usage();
	unsigned    checked = 0;

	if (!source) {
		check(0, "the parser's source can be read");
		return;
	}

	while (at && *at) {
		const char *end = strchr(at, '\n');
		const char *word = at;
		char        name[64];
		size_t      taken = 0;

		while (*word == ' ') {
			word++;
		}
		if (word[0] != '-' || word[1] != '-') {
			at = end ? end + 1 : NULL;
			continue;
		}
		while (taken + 1u < sizeof(name) && word[taken] &&
		    (word[taken] == '-' || (word[taken] >= 'a' && word[taken] <= 'z'))) {
			name[taken] = word[taken];
			taken++;
		}
		name[taken] = '\0';
		if (taken > 2u) {
			char wanted[96];
			int  found;

			(void)snprintf(wanted, sizeof(wanted), "\"%s\") == 0", name);
			found = strstr(source, wanted) != NULL;
			if (!found) {
				detail("offered with nothing to parse it", name);
			}
			check(found, "an option in the help text has an arm");
			checked++;
		}
		at = end ? end + 1 : NULL;
	}
	free(source);
	/* The vacuous-pass guard: a reformatted usage that stopped matching would
	 * otherwise report a clean run having compared nothing. */
	check(checked >= 6u, "and the usage text was walked, not merely opened");
}

/*
 * The help text says where the daemon reads from, and says it once.
 *
 * The Rust writes those paths out as literal text beside the constants that
 * decide them, which is the same path in two places and the help is the copy
 * nobody recompiles. Here they are pasted in from the constants, so this check
 * is that the paste actually happened rather than that two strings agree.
 */
static void the_help_text_carries_the_real_defaults(void)
{
	const char *usage = ncfg_main_netcfgd_usage();
	const char *printed;
	int         code;

	check(strstr(usage, NCFG_CONFIG_DIR_DEFAULT) != NULL,
	    "the help names the configuration directory it would read");
	check(strstr(usage, NCFG_FACTORY_DIR_DEFAULT) != NULL, "and the factory one");
	check(strstr(usage, NCFG_RUN_DIR_DEFAULT) != NULL, "and the run directory");
	check(strstr(usage, NCFG_CONFIG_DIR_ENV) != NULL,
	    "and the environment variable that overrides the first");
	check(strstr(usage, "--version") != NULL,
	    "and mentions --version, or nobody will run it");

	/* Nothing is asserted between these two calls: a `check` writes to stdout
	 * too, and would land in the capture it is checking. */
	capture_begin(STDOUT_FILENO);
	code = run_netcfgd("--help", NULL);
	printed = capture_end(STDOUT_FILENO);
	check(code == NCFG_MAIN_EXIT_OK, "`--help` exits 0");
	line(printed, "netcfgd -- network configuration daemon",
	    "and prints the help on stdout, where a pager can read it");
	check(strcmp(printed, ncfg_main_netcfgd_usage()) == 0,
	    "and prints exactly the text this test walked");
}

/*
 * The version surface, and the one fact it may not have two spellings of.
 *
 * `harmonization.md` asks for the holder in `--version`, and the Rust shares
 * `CARGO_PKG_VERSION` and `netcfgd_model::COPYRIGHT` between the two programs
 * so they cannot come to disagree about a fact neither owns. The C port has no
 * constants module, so `cli.h` holds the only spelling and the daemon reads
 * it; this checks that it is read rather than restated.
 */
static void the_version_agrees_with_the_client(void)
{
	const char *printed;
	int         code;

	check(strstr(NCFG_CLI_COPYRIGHT, "Copyright (C)") != NULL,
	    "the line is recognisable as a copyright notice");
	check(strchr(NCFG_CLI_COPYRIGHT, '<') && strchr(NCFG_CLI_COPYRIGHT, '@'),
	    "and carries the name and the address harmonization.md asks for");

	capture_begin(STDOUT_FILENO);
	code = run_netcfgd("--version", NULL);
	printed = capture_end(STDOUT_FILENO);
	check(code == NCFG_MAIN_EXIT_OK, "`--version` exits 0");
	line(printed, "netcfgd " NCFG_CLI_VERSION, "the daemon prints the version first");
	line(printed, NCFG_CLI_COPYRIGHT, "and the copyright line under it");

	capture_begin(STDOUT_FILENO);
	ncfg_cli_print_version();
	printed = capture_end(STDOUT_FILENO);
	line(printed, "ncfg " NCFG_CLI_VERSION, "and the client prints the same version");
	line(printed, NCFG_CLI_COPYRIGHT, "and the same copyright line");
}

/*
 * A command line that was wrong is refused, by name, on stderr.
 *
 * An option silently ignored is the fault this arm exists to prevent:
 * `--no-apply-on-start` misspelt and skipped is a daemon that applies on start,
 * which is the one thing that flag is for. And a missing value is not read from
 * the option after it -- `--config-dir --poll-config` would otherwise put the
 * machine's configuration in a directory named after a flag and say nothing.
 */
static void a_wrong_command_line_is_refused_by_name(void)
{
	const char *printed;
	int         code;

	capture_begin(STDERR_FILENO);
	code = run_netcfgd("--no-apply-on-strat", NULL);
	printed = capture_end(STDERR_FILENO);
	check(code == NCFG_MAIN_EXIT_FAILED, "an unknown option exits 1");
	line(printed, "netcfgd: unknown option `--no-apply-on-strat`",
	    "and is named rather than skipped");

	capture_begin(STDERR_FILENO);
	code = run_netcfgd("--config-dir", NULL);
	printed = capture_end(STDERR_FILENO);
	check(code == NCFG_MAIN_EXIT_FAILED, "an option with no value exits 1");
	line(printed, "netcfgd: --config-dir needs a value", "and says which option it was");

	capture_begin(STDERR_FILENO);
	code = run_netcfgd("--socket", NULL);
	printed = capture_end(STDERR_FILENO);
	line(printed, "netcfgd: --socket needs a value", "and the same for every one that takes one");
	check(code == NCFG_MAIN_EXIT_FAILED, "which is the same status");

	/* The value is taken even where it looks like a flag: `--config-dir
	 * --poll-config` is a wrong command line, but it is the operator's and
	 * guessing at it would be worse than obeying it. What must not happen is
	 * the flag being silently consumed as an option in its own right. */
	capture_begin(STDERR_FILENO);
	code = run_netcfgd("--config-dir", "--poll-config");
	printed = capture_end(STDERR_FILENO);
	check(strstr(printed, "unknown option") == NULL,
	    "a value that looks like a flag is a value, not an unknown option");
	check(code == NCFG_MAIN_EXIT_FAILED, "and the command line then reaches the refusal");

	/* An escape sequence in an option name is an option name somebody chose,
	 * and it reaches the same terminal `argv[0]` does. */
	capture_begin(STDERR_FILENO);
	(void)run_netcfgd("--we\033[2Jird", NULL);
	printed = capture_end(STDERR_FILENO);
	check(strchr(printed, '\033') == NULL,
	    "and an option name it repeats back cannot drive a terminal either");
}

/*
 * It refuses to start, and the name it refuses with is a name something has.
 *
 * A daemon that started and silently did nothing would be worse than this in
 * the specific way 0263 keeps refusing: `ncfg_reconcile_pass` with no observe
 * seam runs on every tick, reports no drift because it can see none, and
 * answers `ncfg plan` with an empty plan -- which a reader cannot tell from a
 * converged machine.
 */
static void it_refuses_to_start_and_names_the_seam(void)
{
	const char *printed;
	const char *waits = ncfg_main_netcfgd_waits_for();
	char        identifier[64];
	char       *header;
	int         code;

	capture_begin(STDERR_FILENO);
	code = run_netcfgd(NULL, NULL);
	printed = capture_end(STDERR_FILENO);

	check(code == NCFG_MAIN_EXIT_FAILED, "with nothing to do it exits 1 rather than running");
	check(strncmp(printed, "netcfgd: ", 9) == 0, "the refusal says which program is speaking");
	check(strstr(printed, waits) != NULL, "and names the seam it is waiting for");
	check(strstr(printed, "the netlink socket") != NULL,
	    "and the descriptors this program would own, which are its own half");
	check(strstr(printed, "the reconcile pass") != NULL,
	    "and says what is already here, so it does not read as an unwritten port");

	/* The same for a command line that parsed perfectly: the refusal is the
	 * program's state, not a reaction to the arguments. */
	capture_begin(STDERR_FILENO);
	code = run_netcfgd("--no-apply-on-start", "--poll-config");
	printed = capture_end(STDERR_FILENO);
	check(code == NCFG_MAIN_EXIT_FAILED, "and a command line it understood does not start it");
	check(strstr(printed, waits) != NULL, "with the same sentence");

	/*
	 * And the symbol it names is still spelt that way where it is declared.
	 * Nothing in a string literal goes red when a type is renamed, so a
	 * refusal sending somebody to look up a seam would go on sending them
	 * there after the name had gone.
	 *
	 * The name is taken **out of the sentence** rather than written here a
	 * second time. Spelling it in the test would check that two literals in
	 * this repository agree and nothing else -- the rename would move the
	 * header and the refusal would keep its stale name, which is exactly the
	 * case this exists to catch.
	 */
	if (!identifier_in(waits, identifier, sizeof(identifier))) {
		detail("the refusal carries no ncfg_ name at all", waits);
		check(0, "the refusal names the seam as an identifier");
		return;
	}
	check(1, "the refusal names the seam as an identifier");
	header = read_source("include/ncfg/daemon.h");
	if (!header) {
		check(0, "the daemon's header can be read");
		return;
	}
	if (!strstr(header, identifier)) {
		detail("the refusal sends a reader to look up", identifier);
		detail("and daemon.h declares nothing by that name", NULL);
	}
	check(strstr(header, identifier) != NULL,
	    "and daemon.h declares something under exactly that name");
	free(header);
}

/* ------------------------------------------------------------------------ *
 * `netcfgd-probe`
 * ------------------------------------------------------------------------ */

/*
 * The one arm of the helper that can be called in this process.
 *
 * Everything past it sheds every privilege and cannot give them back, so the
 * case with a URL belongs to `portal_test.c`, which drives real children. What
 * is checked here is that the argument is required rather than defaulted: a
 * helper that fetched something when told nothing would be a process with no
 * capabilities reaching a network nobody named.
 */
static void the_probe_child_needs_a_url(void)
{
	const char *printed;
	char       *argv[1];
	int         code;

	argv[0] = (char *)(uintptr_t)(const void *)NCFG_PORTAL_HELPER_NAME;
	capture_begin(STDOUT_FILENO);
	code = ncfg_main_probe(1, argv);
	printed = capture_end(STDOUT_FILENO);

	check(code == NCFG_MAIN_EXIT_FAILED, "the helper with no URL exits 1");
	line(printed, "usage: netcfgd-probe <url>", "and says what it wanted");
	check(strcmp(NCFG_PORTAL_HELPER_NAME, "netcfgd-probe") == 0,
	    "and the name in that line is the one the daemon execs it under");
	check(ncfg_main_program_for(NCFG_PORTAL_HELPER_NAME) == NCFG_MAIN_PROGRAM_PROBE,
	    "which this image answers to");
}

/* ------------------------------------------------------------------------ *
 * The exit statuses, as a set
 * ------------------------------------------------------------------------ */

/*
 * Three statuses that mean three things, and the client's five are not these.
 *
 * `ncfg` promises four in its usage text plus a fifth for a usage error, and a
 * script reading a daemon's status for that shape would be reading something
 * that was never promised. What matters here is only that these three are
 * distinct: success, would not start, and does not know which program it is.
 */
static void the_statuses_are_three_different_things(void)
{
	check(NCFG_MAIN_EXIT_OK == 0, "success is 0, as every program's is");
	check(NCFG_MAIN_EXIT_FAILED != NCFG_MAIN_EXIT_OK,
	    "a daemon that would not start is not success");
	check(NCFG_MAIN_EXIT_MISCALLED != NCFG_MAIN_EXIT_FAILED,
	    "and an image called by the wrong name is not a daemon that would not start");
	check(NCFG_MAIN_EXIT_OK == NCFG_CLI_EXIT_OK,
	    "the two programs agree about what success is");
}

int main(void)
{
	const char *dir = testdir_make("main");

	(void)snprintf(capture_file, sizeof(capture_file), "%s/printed", dir);

	the_name_chooses_the_program();
	neither_name_says_what_the_names_are();
	the_name_it_repeats_cannot_drive_a_terminal();
	every_option_in_the_help_text_is_parsed();
	the_help_text_carries_the_real_defaults();
	the_version_agrees_with_the_client();
	a_wrong_command_line_is_refused_by_name();
	it_refuses_to_start_and_names_the_seam();
	the_probe_child_needs_a_url();
	the_statuses_are_three_different_things();

	free(captured);
	testdir_remove(dir);
	if (failures) {
		printf("\n%d check(s) failed\n", failures);
		return 1;
	}
	printf("\nmain: every check passed\n");
	return 0;
}
