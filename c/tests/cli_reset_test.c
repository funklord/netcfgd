/*
 * cli_reset_test.c -- `ncfg reset`, the most destructive verb the program has.
 *
 * WHAT THESE CASES ARE FOR
 *   `command_reset`'s own, carried across, plus the four places this diverges.
 *   The groups are the three questions a reader of that verb has:
 *
 *   * **What does it remove?** Exactly the loader's own enumeration of the
 *     writable layer: `netcfgd.conf` and every `*.conf` under `conf.d`. A file
 *     that is not configuration, a profile's directory, the factory layer and
 *     the credentials are each checked for still being there afterwards --
 *     because a reset that removed a different set from the one that gets
 *     loaded would leave files behind that still configure the machine, and
 *     one that removed more would take something nobody asked it to.
 *   * **What does it say before it does it?** The list, and what will be left:
 *     a machine with no factory layer is being emptied rather than restored,
 *     which is the thing people are surprised by, and the credentials outlive
 *     the configuration that referred to them.
 *   * **What does it refuse?** A config directory that is the factory
 *     directory -- including where the two are spelled differently and are the
 *     same directory, which is what a resolved comparison buys over the text
 *     one -- and an argument it cannot place.
 *
 * NOTHING OUTSIDE ITS OWN DIRECTORY
 *   Every directory here is under one `mkdtemp` tree and is passed explicitly.
 *   This verb removes files, so that is not a convention here but the whole
 *   safety of the test: nothing falls back to `/etc/netcfgd`, and the default
 *   is asserted by reading the constant rather than by pointing this at it.
 */
#include "ncfg/base.h"
#include "ncfg/cli.h"
#include "ncfg/config.h"

#include "testdir.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static int failures;

/* The real standard output, kept before any capture, so that a failure inside
 * a capture is still seen. */
static FILE *report;

static void check(int condition, const char *what)
{
	(void)fprintf(report, "%-72s %s\n", what, condition ? "ok" : "FAILED");
	(void)fflush(report);
	if (!condition) {
		failures++;
	}
}

static void note(const char *what)
{
	(void)fprintf(report, "       %s\n", what);
	(void)fflush(report);
}

/* ------------------------------------------------------------------------ *
 * The tree and the capture
 * ------------------------------------------------------------------------ */

static char root[256];
static char config_dir[320];
static char factory_dir[320];
static char run_dir[320];
static char capture_file[384];

static ncfg_cli_options_t options;

static const char *in(const char *dir, const char *leaf)
{
	static char   buffers[8][512];
	static size_t next;
	char         *out = buffers[next];

	next = (next + 1u) % 8u;
	(void)snprintf(out, sizeof(buffers[0]), "%s/%s", dir, leaf);
	return out;
}

static void make_directory(const char *path)
{
	(void)mkdir(path, 0755);
}

static int   saved_stdout = -1;
static char *captured;

static void capture_begin(void)
{
	int fd;

	(void)fflush(stdout);
	saved_stdout = dup(STDOUT_FILENO);
	fd = open(capture_file, O_RDWR | O_CREAT | O_TRUNC, 0600);
	if (fd < 0 || saved_stdout < 0) {
		(void)fprintf(report, "could not redirect stdout to %s\n", capture_file);
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

/* One `ncfg reset`, with whatever `options` currently says. */
static int reset(char *err, size_t err_size)
{
	int ok;

	err[0] = '\0';
	capture_begin();
	ok = ncfg_cli_reset(&options, NULL, 0u, err, err_size);
	(void)capture_end();
	return ok;
}

/*
 * The machine this suite resets: a base file, two drop-ins, a file that is not
 * configuration, a profile's own directory, a credential, and a factory layer
 * that the caller says whether to fill.
 */
static void fixture(int with_factory)
{
	make_directory(config_dir);
	make_directory(in(config_dir, "conf.d"));
	make_directory(in(config_dir, "secrets"));
	make_directory(in(config_dir, "profile"));
	make_directory(in(in(config_dir, "profile"), "office"));
	make_directory(factory_dir);
	make_directory(in(factory_dir, "conf.d"));

	(void)testdir_write(in(config_dir, "netcfgd.conf"),
	    "interface eth0 {\n\tconfig = \"dhcp\"\n}\n", 34u);
	(void)testdir_write(in(in(config_dir, "conf.d"), "10-site.conf"),
	    "global { hostname = \"one\" }\n", 28u);
	(void)testdir_write(in(in(config_dir, "conf.d"), "20-more.conf"),
	    "global { }\n", 11u);
	/* Not configuration, and not the loader's to read -- so not this verb's
	 * to remove either. */
	(void)testdir_write(in(in(config_dir, "conf.d"), "notes.txt"), "mine\n", 5u);
	(void)testdir_write(in(in(in(config_dir, "profile"), "office"), "10-office.conf"),
	    "global { }\n", 11u);
	(void)testdir_write(in(in(config_dir, "secrets"), "vpn"), "x\n", 2u);
	(void)chmod(in(in(config_dir, "secrets"), "vpn"), 0600);

	(void)unlink(in(in(factory_dir, "conf.d"), "00-image.conf"));
	if (with_factory) {
		(void)testdir_write(in(in(factory_dir, "conf.d"), "00-image.conf"),
		    "global { }\n", 11u);
	}
}

/* Whether `text` has a line exactly equal to `wanted`. */
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
			break;
		}
		at = end + 1;
	}
	return 0;
}

/* ------------------------------------------------------------------------ *
 * What it refuses
 * ------------------------------------------------------------------------ */

/*
 * Resetting into the factory directory would delete the thing being reset to.
 *
 * The Rust compares two `PathBuf`s, which is component-wise: the trailing
 * slash below is seen through there too, and the symlink is not. Measured
 * against the shipped binary, that one removed the factory layer and then
 * reported the files it had just deleted as the ones that remain. The guard's
 * own comment says what it exists for: a misconfigured unit file, "which is
 * exactly when nobody is watching".
 */
static void the_defaults_are_not_reset_into(void)
{
	char err[NCFG_ERROR_MAX];
	char slashed[384];
	char linked[384];

	(void)fprintf(report, "\n-- the directory it falls back to is not one it deletes\n");
	fixture(1);
	options.factory_dir = config_dir;
	check(!reset(err, sizeof(err)) && strstr(err, "reset would delete the defaults") != NULL,
	    "the same directory twice is refused");

	(void)snprintf(slashed, sizeof(slashed), "%s/", config_dir);
	options.factory_dir = slashed;
	check(!reset(err, sizeof(err)) && strstr(err, "reset would delete the defaults") != NULL,
	    "  and so is the same directory with a trailing slash");

	(void)snprintf(linked, sizeof(linked), "%s/link-to-etc", root);
	(void)unlink(linked);
	if (symlink(config_dir, linked) == 0) {
		options.factory_dir = linked;
		check(!reset(err, sizeof(err)) &&
		    strstr(err, "reset would delete the defaults") != NULL,
		    "  and so is a symlink to it, which the Rust's comparison walks past");
		(void)unlink(linked);
	} else {
		check(0, "  a symlink could not be made, so that spelling was not driven");
	}
	options.factory_dir = factory_dir;
	check(testdir_exists(in(config_dir, "netcfgd.conf")) &&
	    testdir_exists(in(in(config_dir, "conf.d"), "10-site.conf")),
	    "  and every one of those refusals removed nothing");
}

static void an_argument_it_cannot_place(void)
{
	const char *positional[1];
	char        err[NCFG_ERROR_MAX];
	int         ok;

	(void)fprintf(report, "\n-- a word it does not understand\n");
	fixture(1);
	positional[0] = "office";
	err[0] = '\0';
	capture_begin();
	ok = ncfg_cli_reset(&options, positional, 1u, err, sizeof(err));
	(void)capture_end();
	/*
	 * The Rust's dispatch drops every positional here, so somebody reaching
	 * for `profile unset` and typing this instead empties the machine's
	 * configuration and says nothing about the word it ignored.
	 */
	check(!ok && strstr(err, "takes no arguments") != NULL,
	    "`ncfg reset office` is refused rather than treated as `ncfg reset`");
	check(testdir_exists(in(config_dir, "netcfgd.conf")), "  and nothing was removed");
}

/* ------------------------------------------------------------------------ *
 * What it says before it does anything
 * ------------------------------------------------------------------------ */

static void a_run_without_yes_changes_nothing(void)
{
	char        err[NCFG_ERROR_MAX];
	const char *printed;
	int         ok;

	(void)fprintf(report, "\n-- without `--yes` it says what it would do and stops\n");
	fixture(1);
	options.yes = 0;
	ok = reset(err, sizeof(err));
	printed = captured ? captured : "";
	check(ok, err[0] ? err : "a dry run succeeds");
	{
		char line[600];

		(void)snprintf(line, sizeof(line), "would remove %s",
		    in(config_dir, "netcfgd.conf"));
		check(has_line(printed, line), "  it lists what it would remove, one per line");
	}
	check(strstr(printed, "10-site.conf") != NULL && strstr(printed, "20-more.conf") != NULL &&
	    strstr(printed, "netcfgd.conf") != NULL,
	    "  and the list is the loader's: the base file and every drop-in");
	check(strstr(printed, "notes.txt") == NULL,
	    "  and nothing that is not configuration");
	check(strstr(printed, "nothing was removed; add --yes to do it") != NULL,
	    "  it says nothing happened and how to make it happen");
	check(strstr(printed, "\nremoved ") == NULL,
	    "  and never says `removed`, which nothing yet has been");
	check(testdir_exists(in(config_dir, "netcfgd.conf")) &&
	    testdir_exists(in(in(config_dir, "conf.d"), "10-site.conf")) &&
	    testdir_exists(in(in(config_dir, "conf.d"), "20-more.conf")),
	    "  and every file is still there");
}

static void what_is_left_is_said_before_it_happens(void)
{
	char        err[NCFG_ERROR_MAX];
	const char *printed;

	(void)fprintf(report, "\n-- what will be left, said before rather than discovered\n");
	fixture(1);
	options.yes = 0;
	(void)reset(err, sizeof(err));
	printed = captured ? captured : "";
	check(strstr(printed, "1 file remains, from ") != NULL,
	    "a machine with a factory layer is told how much of one is left");

	fixture(0);
	(void)reset(err, sizeof(err));
	printed = captured ? captured : "";
	check(strstr(printed, "no factory config") != NULL &&
	    strstr(printed, "no configuration at all") != NULL,
	    "and one without is told this empties it rather than restoring anything");
	check(strstr(printed, "every address, route and link netcfgd installed") != NULL,
	    "  naming what the next pass would take off the machine");
	check(strstr(printed, "1 credential stays") != NULL &&
	    strstr(printed, "secrets") != NULL,
	    "and the credentials that outlive the configuration are counted, not removed");
}

/* ------------------------------------------------------------------------ *
 * What it removes
 * ------------------------------------------------------------------------ */

static void what_yes_removes_and_what_it_leaves(void)
{
	char        err[NCFG_ERROR_MAX];
	const char *printed;
	int         ok;

	(void)fprintf(report, "\n-- with `--yes`, exactly the writable layer and nothing "
	    "else\n");
	fixture(1);
	options.yes = 1;
	ok = reset(err, sizeof(err));
	printed = captured ? captured : "";
	check(ok, err[0] ? err : "a reset with --yes succeeds");
	check(!testdir_exists(in(config_dir, "netcfgd.conf")), "  the base file is gone");
	check(!testdir_exists(in(in(config_dir, "conf.d"), "10-site.conf")) &&
	    !testdir_exists(in(in(config_dir, "conf.d"), "20-more.conf")),
	    "  and both drop-ins with it");
	{
		char line[600];

		(void)snprintf(line, sizeof(line), "removed %s", in(config_dir, "netcfgd.conf"));
		check(has_line(printed, line), "  and it says so, naming each file it removed");
	}

	check(testdir_exists(in(in(config_dir, "conf.d"), "notes.txt")),
	    "  a file that is not configuration is left, because the loader never read it");
	check(testdir_exists(in(in(in(config_dir, "profile"), "office"), "10-office.conf")),
	    "  a profile's own directory is left: it is a snapshot, not what is in force");
	check(testdir_exists(in(in(config_dir, "secrets"), "vpn")),
	    "  the credentials are left, because one nobody has a copy of cannot be got back");
	check(testdir_exists(in(in(factory_dir, "conf.d"), "00-image.conf")),
	    "  and the factory layer is left, which is the whole point of the verb");

	/* A second run has nothing to do and says which directory it looked in. */
	ok = reset(err, sizeof(err));
	printed = captured ? captured : "";
	check(ok && strstr(printed, "nothing to reset") != NULL &&
	    strstr(printed, config_dir) != NULL,
	    "a second run says there is nothing to reset, naming where it looked");
}

/*
 * A removal that fails says what stands, and stops.
 *
 * **Driven only where the mode can refuse this process.** Running as root,
 * `unlink` is not stopped by a directory's permissions, so there is no way
 * from inside a test to make one fail -- and this says so rather than counting
 * a check that inspected nothing, which is how a suite reports success for a
 * case it never ran.
 */
static void a_removal_that_could_not_happen(void)
{
	char        err[NCFG_ERROR_MAX];
	const char *printed;
	int         ok;

	(void)fprintf(report, "\n-- a removal the filesystem refuses\n");
	if (geteuid() == 0) {
		note("not driven: this process is root, and `unlink` is not stopped by the "
		    "mode that would refuse anybody else");
		return;
	}
	fixture(1);
	options.yes = 1;
	(void)chmod(in(config_dir, "conf.d"), 0500);
	ok = reset(err, sizeof(err));
	printed = captured ? captured : "";
	(void)chmod(in(config_dir, "conf.d"), 0755);
	check(!ok && strstr(err, "conf.d") != NULL && strstr(err, "still there") != NULL,
	    "it refuses, names the file, and says how much had already gone");
	check(strstr(printed, "10-site.conf") == NULL ||
	    strstr(printed, "removed ") == NULL ||
	    testdir_exists(in(in(config_dir, "conf.d"), "10-site.conf")) == 0,
	    "  and never printed `removed` for a file that is still on disk");
	check(testdir_exists(in(in(config_dir, "conf.d"), "10-site.conf")),
	    "  the file it could not remove is still there");
}

/* ================================================================== main */

int main(void)
{
	int fd = dup(STDOUT_FILENO);

	report = fd >= 0 ? fdopen(fd, "w") : NULL;
	if (!report) {
		printf("could not keep a handle on the real standard output\n");
		return 1;
	}

	(void)testdir_make("cli-reset");
	(void)snprintf(root, sizeof(root), "%s", testdir_path);
	(void)snprintf(config_dir, sizeof(config_dir), "%s/etc", root);
	(void)snprintf(factory_dir, sizeof(factory_dir), "%s/factory", root);
	(void)snprintf(run_dir, sizeof(run_dir), "%s/run", root);
	(void)snprintf(capture_file, sizeof(capture_file), "%s/stdout.log", root);
	make_directory(run_dir);

	memset(&options, 0, sizeof(options));
	options.config_dir = config_dir;
	options.factory_dir = factory_dir;
	options.run_dir = run_dir;

	/* The real directories are asserted by reading the constants, never by
	 * pointing this verb at them. */
	check(strcmp(NCFG_CONFIG_DIR_DEFAULT, "/etc/netcfgd") == 0 &&
	    strcmp(NCFG_FACTORY_DIR_DEFAULT, "/usr/share/netcfgd") == 0,
	    "the defaults this verb would remove are checked by reading them");

	the_defaults_are_not_reset_into();
	an_argument_it_cannot_place();
	a_run_without_yes_changes_nothing();
	what_is_left_is_said_before_it_happens();
	what_yes_removes_and_what_it_leaves();
	a_removal_that_could_not_happen();

	free(captured);
	testdir_remove(testdir_path);
	if (failures) {
		(void)fprintf(report, "\n%d check(s) failed\n", failures);
		return 1;
	}
	(void)fprintf(report, "\n`ncfg reset`: every check passed\n");
	return 0;
}
