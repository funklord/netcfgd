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
 * WHY THE ONE THING THIS FILE MAY NOT DO IS CHECKED RATHER THAN AGREED
 *   `netcfgd` used to refuse to start, which is what made calling its entry
 *   point from here harmless. It starts now: it binds a control socket, takes
 *   the apply lock and begins reconciling. So the rule is that this file calls
 *   `ncfg_main_netcfgd_parse` and never `ncfg_main_netcfgd`, and the rule
 *   enforces itself -- this file reads its own source and refuses to contain
 *   the call, and reads `main_internal.h` to check that the assembly has no
 *   other name to reach it by. A comment asking the next person to remember is
 *   not a guard; it is a note next to the thing that went wrong.
 */
#include "../src/main/main_internal.h"

#include "ncfg/apply.h"
#include "ncfg/base.h"
#include "ncfg/cli.h"
#include "ncfg/document.h"
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
/*
 * What `run_netcfgd` answers for a command line that parsed and left something
 * to do. No real exit status is 120, and a test that expects it is saying "the
 * parse got this far", which is the whole of what a test may ask for here.
 */
#define WOULD_START 120

static int run_netcfgd(const char *one, const char *two)
{
	char                     *argv[3];
	int                       count = 1;
	struct ncfg_main_options  options;
	int                       done = 0;
	int                       code = NCFG_MAIN_EXIT_OK;

	memset(&options, 0, sizeof(options));
	argv[0] = (char *)(uintptr_t)(const void *)"netcfgd";
	argv[1] = NULL;
	argv[2] = NULL;
	if (one) {
		argv[count++] = (char *)(uintptr_t)(const void *)one;
	}
	if (two) {
		argv[count++] = (char *)(uintptr_t)(const void *)two;
	}
	/*
	 * **`_parse`, never `ncfg_main_netcfgd`, and that is a safety rule rather
	 * than a style one.** This runs the daemon's entry point inside the test
	 * process, which is what the multi-call shape is for and is right for
	 * everything below. It is also one wiring commit away from starting a
	 * network configuration daemon inside `make check`, on a machine with a
	 * real network -- the one this suite is developed on. That stopped being
	 * hypothetical the day the assembly was written: the entry point now binds
	 * a control socket, takes the apply lock and reconciles.
	 *
	 * So the parse is a function of its own and this calls that. A parse that
	 * says nothing follows returns the terminal exit code; a command line
	 * that would have gone on to start something returns
	 * `WOULD_START`, which is a value no real run produces.
	 */
	if (!ncfg_main_netcfgd_parse(count, argv, &options, &done, &code)) {
		return code;
	}
	return done ? NCFG_MAIN_EXIT_OK : WOULD_START;
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
	check(code == WOULD_START,
	    "and the command line parses, with the flag taken as the value it was put after");

	/* An escape sequence in an option name is an option name somebody chose,
	 * and it reaches the same terminal `argv[0]` does. */
	capture_begin(STDERR_FILENO);
	(void)run_netcfgd("--we\033[2Jird", NULL);
	printed = capture_end(STDERR_FILENO);
	check(strchr(printed, '\033') == NULL,
	    "and an option name it repeats back cannot drive a terminal either");
}


/* ------------------------------------------------------------------------ *
 * Where a daemon would read, write and listen
 * ------------------------------------------------------------------------ */

/*
 * The four paths, resolved the way every other caller resolves them.
 *
 * Worth a check rather than taken on trust because the Rust wrote the same
 * defaults out as literal text beside the constants holding them, and the help
 * was the copy nobody recompiled. Here they are `config.h`'s and `state.h`'s
 * own answers, called -- so what this asserts is that they were called.
 */
static void the_paths_are_the_ones_every_other_caller_resolves(void)
{
	struct ncfg_main_options options;
	ncfg_main_where_t        where;
	char                     err[NCFG_ERROR_MAX];

	memset(&options, 0, sizeof(options));
	err[0] = '\0';
	check(ncfg_main_netcfgd_where(&options, &where, err, sizeof(err)),
	    "an empty command line resolves to somewhere");
	check(strcmp(where.config, NCFG_CONFIG_DIR_DEFAULT) == 0,
	    "the configuration directory is the one the help names");
	check(strcmp(where.factory, NCFG_FACTORY_DIR_DEFAULT) == 0, "and so is the factory one");
	check(strcmp(where.run, NCFG_RUN_DIR_DEFAULT) == 0, "and so is the run directory");
	/*
	 * The socket is `netcfgd.sock` under the run directory and is written down
	 * in exactly one place. The help says so too, which is the pair that would
	 * otherwise drift.
	 */
	check(strcmp(where.socket, NCFG_RUN_DIR_DEFAULT "/netcfgd.sock") == 0,
	    "and the socket is under the run directory, as the help says");
	check(strstr(ncfg_main_netcfgd_usage(), "/netcfgd.sock") != NULL,
	    "and the help says the same thing this resolved");
	/*
	 * And the two credential directories, which are under the directories this
	 * daemon was given rather than under `/etc` and `/run`. A daemon pointed at
	 * a scratch tree that read the machine's real credentials would be the
	 * `testdir.h` hazard with the defaults moved one layer up.
	 */
	check(strcmp(where.secrets, NCFG_CONFIG_DIR_DEFAULT "/secrets") == 0,
	    "the secrets directory is under the configuration directory in force");
	check(strcmp(where.certs, NCFG_RUN_DIR_DEFAULT "/certs") == 0,
	    "and the certificate directory is under the run directory in force");

	/* What was typed wins over the environment and over the default. */
	options.config_dir = "/tmp/not-a-real-config";
	options.run_dir = "/tmp/not-a-real-run";
	err[0] = '\0';
	check(ncfg_main_netcfgd_where(&options, &where, err, sizeof(err)) &&
	    strcmp(where.config, "/tmp/not-a-real-config") == 0,
	    "what was typed wins over the default");
	check(strcmp(where.socket, "/tmp/not-a-real-run/netcfgd.sock") == 0,
	    "and the socket follows the run directory it was given");
	check(strcmp(where.secrets, "/tmp/not-a-real-config/secrets") == 0 &&
	    strcmp(where.certs, "/tmp/not-a-real-run/certs") == 0,
	    "and so do both credential directories, rather than staying on the defaults");

	/*
	 * **The remote socket is beside the socket, not under the run
	 * directory.** A second netcfgd told to listen elsewhere would otherwise
	 * put its remote socket back in `/run/netcfgd`, which is the one place it
	 * must not write.
	 */
	options.socket = "/tmp/elsewhere/ctl.sock";
	err[0] = '\0';
	check(ncfg_main_netcfgd_where(&options, &where, err, sizeof(err)) &&
	    strcmp(where.socket, "/tmp/elsewhere/ctl.sock") == 0,
	    "an explicit socket path is kept as it was typed");
	check(strcmp(where.remote_socket, "/tmp/elsewhere/remote.sock") == 0,
	    "and the remote socket is beside it rather than under the run directory");

	/* A path that does not fit is refused rather than truncated: a daemon
	 * whose configuration directory is a prefix of the one somebody named is
	 * worse than one that will not start. */
	{
		char long_one[NCFG_MAIN_PATH_MAX + 32];

		memset(long_one, 'x', sizeof(long_one));
		long_one[0] = '/';
		long_one[sizeof(long_one) - 1u] = '\0';
		memset(&options, 0, sizeof(options));
		options.socket = long_one;
		err[0] = '\0';
		check(!ncfg_main_netcfgd_where(&options, &where, err, sizeof(err)),
		    "a path that does not fit is refused rather than cut down");
		check(strstr(err, "does not fit") != NULL, "and says so");
	}
	check(!ncfg_main_netcfgd_where(NULL, &where, err, sizeof(err)),
	    "and there is nothing to resolve without a command line");
}

/* ------------------------------------------------------------------------ *
 * The policy the sockets are bound under
 * ------------------------------------------------------------------------ */

/*
 * The control policy is **copied**, and the copy outlives the document.
 *
 * `ncfg_daemon_serve_t` borrows the policies and they must outlive the server,
 * while `state->desired` is replaced by every reload -- so a socket pointed at
 * the document's own block would read freed memory the first time somebody
 * wrote in the configuration directory. The document is freed here before the
 * copy is read, and ASan is the assertion.
 */
static void the_control_policy_is_copied_and_outlives_its_document(void)
{
	ncfg_main_policy_t policy;
	ncfg_document_t   *document;
	char               text[512];
	char               err[NCFG_ERROR_MAX];

	err[0] = '\0';
	check(ncfg_main_policy_copy(NULL, &policy, err, sizeof(err)),
	    "a machine with no compiled configuration still has a policy");
	check(policy.control.observe.kind == NCFG_PRINCIPAL_ROOT &&
	    policy.control.wifi.kind == NCFG_PRINCIPAL_ROOT &&
	    policy.control.admin.kind == NCFG_PRINCIPAL_ROOT,
	    "and it is root everywhere, which is the safe reading of a file that would "
	    "not compile");
	check(!ncfg_main_remote_is_open(&policy.remote),
	    "with nothing open to anything off this machine");
	ncfg_main_policy_free(&policy);

	(void)snprintf(text, sizeof(text),
	    "{\"schema_version\":{\"major\":1,\"minor\":1},\"globals\":{\"control\":"
	    "{\"observe\":{\"group\":\"netdev\"},\"wifi\":\"any\"},\"remote\":"
	    "{\"observe\":true,\"agent\":{\"user\":\"agent\"}}},"
	    "\"devices\":[],\"interfaces\":[],\"networks\":[]}");
	err[0] = '\0';
	document = ncfg_document_read(text, strlen(text), err, sizeof(err));
	if (!document) {
		detail("the policy fixture did not read", err);
		check(0, "the policy fixture reads");
		return;
	}
	err[0] = '\0';
	check(ncfg_main_policy_copy(document, &policy, err, sizeof(err)),
	    "a document's control policy is copied");
	ncfg_document_free(document);

	check(policy.control.observe.kind == NCFG_PRINCIPAL_GROUP &&
	    policy.control.observe.name && strcmp(policy.control.observe.name, "netdev") == 0,
	    "and the copy is readable after the document it came from is gone");
	check(policy.control.wifi.kind == NCFG_PRINCIPAL_ANY,
	    "with every tier carried over, not just the first");
	check(ncfg_main_remote_is_open(&policy.remote),
	    "a remote policy that opens one tier is open");
	check(policy.remote.agent.name && strcmp(policy.remote.agent.name, "agent") == 0,
	    "and the agent it names comes across too");
	ncfg_main_policy_free(&policy);
	ncfg_main_policy_free(&policy);
	check(1, "and freeing it twice is nothing");

	{
		ncfg_remote_policy_t shut;

		memset(&shut, 0, sizeof(shut));
		check(!ncfg_main_remote_is_open(&shut),
		    "a remote policy that opens nothing is not open");
		check(!ncfg_main_remote_is_open(NULL), "and neither is none at all");
		shut.admin = 1;
		check(ncfg_main_remote_is_open(&shut),
		    "one that opens only admin is open, which is the arm a two-tier check "
		    "would miss");
	}
}

/* ------------------------------------------------------------------------ *
 * The one thing this file may not do
 * ------------------------------------------------------------------------ */

/*
 * **The tests may not start the daemon, checked rather than agreed.**
 *
 * Everything above runs the daemon's command line inside the test process.
 * That was harmless while the entry point refused to start; it is not now.
 * What would happen is a network configuration daemon binding a control
 * socket, taking the apply lock and reconciling, inside `make check`, on
 * whatever workstation ran it.
 *
 * Two things stop that and neither is a comment. This file does not call the
 * entry point, which it checks by reading itself; and the assembly behind the
 * entry point is `static`, so there is no second name to reach it by, which it
 * checks by reading the header that would have to declare one.
 */
static void nothing_here_can_start_a_daemon(void)
{
	char *own = read_source("tests/main_test.c");
	char *header = read_source("src/main/main_internal.h");
	char *source = read_source("src/main/daemon_main.c");
	char  forbidden[64];

	/*
	 * Joined here rather than written out, because the first version of this
	 * check failed against a file that does not make the call: the needle was
	 * a literal, so the check found *itself*. A test that reads its own source
	 * has to be written so that saying what it forbids is not doing it.
	 */
	(void)snprintf(forbidden, sizeof(forbidden), "%s(count, argv)", "ncfg_main_netcfgd");
	check(own != NULL, "this file can read itself");
	if (own) {
		check(strstr(own, forbidden) == NULL,
		    "and no check here starts the daemon by calling its entry point");
		free(own);
	}

	check(header != NULL, "the header that declares this program's parts can be read");
	if (header) {
		/* The assembly has no declaration, so nothing outside its own file can
		 * name it -- which is a stronger guarantee than a rule about what a
		 * test calls, because it is the linker's rather than a reader's. */
		check(strstr(header, "ncfg_main_netcfgd_start") == NULL,
		    "and the assembly is not declared anywhere a test could reach it");
		free(header);
	}
	check(source != NULL, "and the daemon's own source can be read");
	if (source) {
		check(strstr(source, "static int start(const options_t *options)") != NULL,
		    "and the assembly it holds is static, which is what makes that true");
		free(source);
	}
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

/*
 * This build does not reconcile, and the reason is no longer the ownership
 * record.
 *
 * **What this check is for has not changed: the guard must not be deleted
 * quietly.** What has changed is the reason it guards, so the check moves with
 * it -- and it moves in both directions, because a guard still standing for a
 * fact that is no longer true is the other way this goes wrong.
 *
 * The version before this one asserted that nothing in `src/apply/kernel_link.c`
 * mentioned an alternative name. That file has never held `create_link` -- it
 * is `kernel.c`'s -- so the grep could not have gone red however the marking
 * landed. It is replaced here by two behavioural checks and one that reads the
 * file the marking is actually in.
 *
 * So: the two facts that used to stop this build are closed and are asserted
 * closed; the facts that stop it now are asserted still true; and the guard
 * itself still answers 0 and is still asked.
 */
static void this_build_does_not_reconcile(void)
{
	char              *main_source = read_source("src/main/daemon_main.c");
	char              *executor = read_source("src/apply/kernel.c");
	ncfg_owned_state_t owned;
	ncfg_op_t          op;
	char               message[NCFG_ERROR_MAX];

	check(!ncfg_main_netcfgd_may_reconcile(),
	    "this build does not reconcile, and says so rather than starting");
	if (main_source) {
		check(strstr(main_source, "may_reconcile()") != NULL,
		    "  and the entry point still asks before it starts anything");
		free(main_source);
	} else {
		check(0, "  and the entry point still asks before it starts anything");
	}

	/*
	 * The first of the two old reasons, read from the file that creates a
	 * link. A source read rather than a call, because what is being asserted
	 * is that `create_link` reaches the marking at all -- the bytes it builds
	 * are `apply_kernel_test.c`'s subject and are checked there against the
	 * wire layer.
	 */
	if (executor) {
		/* The definition *and* the call: a marker nothing invokes is the
		 * same machine as no marker at all, and a grep for the name alone
		 * would find the one without the other. */
		check(strstr(executor, "static void mark_as_ours") != NULL &&
		    strstr(executor, "ncfg_kernel_build_altname") != NULL &&
		    strstr(executor, "mark_as_ours(kernel,") != NULL,
		    "  a link this build creates is marked as netcfgd's, which it was not");
		free(executor);
	} else {
		check(0, "  a link this build creates is marked as netcfgd's, which it was not");
	}

	/* And the second: an apply's effects reach the ownership record. */
	memset(&owned, 0, sizeof(owned));
	memset(&op, 0, sizeof(op));
	op.kind = NCFG_OP_LINK_CREATE;
	op.u.link_create.name = "br0";
	check(ncfg_owned_absorb(&owned, &op) && owned.created_link_count == 1u,
	    "  and what an apply did is folded into the ownership record, which it was not");
	ncfg_owned_free(&owned);

	/*
	 * And the third, which was a reason of its own until this wave: an apply
	 * that stopped halfway left nothing under `/run` saying where. The writer
	 * exists and the pass reaches it -- `reconcile_test.c` drives a pass and
	 * reads the file back, and this asserts the two facts that check cannot
	 * see from inside: that the call is declared at all, and that the daemon's
	 * pass is the file that makes it.
	 */
	message[0] = '\0';
	check(!ncfg_apply_write_journal(NULL, NULL, message, sizeof(message)) &&
	    message[0] != '\0',
	    "  and the journal of an apply has a writer, which it did not");
	{
		char *pass = read_source("src/daemon/reconcile_pass.c");

		/* The file that would have to change, which is 10.177's rule about
		 * asserting a negative over a location: `record_what_ran` is
		 * `reconcile_pass.c`'s and nowhere else. */
		check(pass && strstr(pass, "ncfg_apply_write_journal(run_dir") != NULL,
		    "  and the pass that reconciles a machine writes one");
		free(pass);
	}

	/*
	 * What stops it now, checked rather than described. `ncfg_apply_supported`
	 * is asked by `execute` one action at a time and `ncfg_apply` stops at the
	 * first failure, so an op it refuses is a plan that changes a machine and
	 * stops halfway -- and a `link.create` for a bond is one of them.
	 */
	memset(&op, 0, sizeof(op));
	op.kind = NCFG_OP_LINK_CREATE;
	op.u.link_create.name = "bond0";
	{
		static ncfg_interface_kind_t bond;

		bond.kind = (int)NCFG_KIND_BOND;
		op.u.link_create.kind = &bond;
	}
	message[0] = '\0';
	check(!ncfg_apply_supported(&op, message, sizeof(message)) && message[0] != '\0',
	    "  and the executor still refuses an op it cannot carry out, while a plan runs");

	/*
	 * The other half of that sentence, which is the one that can rot silently:
	 * every kind this list says it *can* create must have a path in the
	 * executor. A tun is the case where the two can disagree without anything
	 * failing to compile -- `ncfg_kernel_newlink_of` refuses one by design, so
	 * a `link.create` for a tun would be refused in the middle of a plan by
	 * the very arrangement `ncfg_apply_supported` exists to prevent.
	 *
	 * Read from `kernel.c`, which is where `create_link` is. The file matters:
	 * the check this replaced read `kernel_link.c`, which has never held
	 * `create_link`, so it could not have gone red however the wiring landed.
	 */
	memset(&op, 0, sizeof(op));
	op.kind = NCFG_OP_LINK_CREATE;
	op.u.link_create.name = "tap0";
	{
		static ncfg_interface_kind_t tun;
		char                        *source = read_source("src/apply/kernel.c");

		tun.kind = (int)NCFG_KIND_TUN;
		op.u.link_create.kind = &tun;
		check(ncfg_apply_supported(&op, NULL, 0),
		    "  a tun is a kind this build says it can create");
		check(source && strstr(source, "static int create_tun") != NULL &&
		    strstr(source, "ncfg_tun_create(NCFG_TUN_CLONE_DEVICE") != NULL &&
		    strstr(source, "create_tun(kernel,") != NULL,
		    "  and `create_link` has the path that makes one, rather than saying so later");
		/*
		 * And that the path marks what it made, read **inside that function's
		 * body** rather than anywhere in the file -- `mark_as_ours` is called
		 * by the netlink path too, so a search of the whole file finds it
		 * whether or not the tun arm reaches it. That is the Rust's defect
		 * exactly (project.md 10.173): its tun arm returns twenty lines above
		 * the block that marks a created link, so the one kind whose
		 * ownership has nowhere else to live is the one kind without a mark.
		 * A sabotage that deleted the call from `create_tun` alone went
		 * unnoticed until this was narrowed to the body.
		 */
		if (source) {
			const char *body = strstr(source, "static int create_tun");
			const char *ends = body ? strstr(body, "static int create_link") : NULL;
			const char *marks = body ? strstr(body, "mark_as_ours(kernel,") : NULL;

			check(body && ends && marks && marks < ends,
			    "  and marks the device it made, which the Rust's own tun arm does not");
		} else {
			check(0, "  and marks the device it made, which the Rust's own tun arm does not");
		}
		free(source);
	}
}

int main(void)
{
	const char *dir = testdir_make("main");

	(void)snprintf(capture_file, sizeof(capture_file), "%s/printed", dir);

	the_name_chooses_the_program();
	this_build_does_not_reconcile();
	neither_name_says_what_the_names_are();
	the_name_it_repeats_cannot_drive_a_terminal();
	every_option_in_the_help_text_is_parsed();
	the_help_text_carries_the_real_defaults();
	the_version_agrees_with_the_client();
	a_wrong_command_line_is_refused_by_name();
	the_paths_are_the_ones_every_other_caller_resolves();
	the_control_policy_is_copied_and_outlives_its_document();
	nothing_here_can_start_a_daemon();
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
