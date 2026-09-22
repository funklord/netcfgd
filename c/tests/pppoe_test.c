/*
 * pppoe_test.c -- what pppd is handed, and what happens to the files after.
 *
 * NOTHING HERE DIALS ANYTHING
 *   This machine's real netcfgd is managing its real network, and a DSL line
 *   is something a machine has one of. So **the program that is run is a shell
 *   script this test wrote**: `ncfg_pppoe_start` takes the machine as a
 *   parameter precisely so that a check cannot reach `/usr/sbin/pppd`. Every
 *   path is under one `mkdtemp` directory, and the pid directories a stop
 *   looks in are this test's own rather than `/run`.
 *
 * WHAT THE CASES ARE ABOUT
 *   * **The options file is asserted whole**, because it is the product: it is
 *     what an operator reads when a line will not come up, and every line in it
 *     is a decision -- `nodefaultroute` and `noipdefault` because netcfgd owns
 *     routes, `usepeerdns` because the ISP's resolvers are the one thing only
 *     pppd learns, two scripts rather than one because pppd leaves `DNS1` set
 *     on the way down.
 *   * **A password with a space and a quote in it**, which is the case the
 *     quoting exists for: an unquoted one ends the option and turns the rest
 *     into pppd directives.
 *   * **The two scripts differ**, and the difference is the defect they were
 *     split over.
 *   * **A dial that failed keeps its options file**, deliberately, and a stop
 *     takes every file back -- including from a session that died on its own,
 *     which is the case where a password would otherwise stay readable under
 *     `/run` until the machine was rebooted.
 *   * **A stop signals only a process that proves whose it is.** The pid file
 *     here names this test's own sleeping process, and the case checks both
 *     answers: with the marker, and without it.
 */
#include "ncfg/base.h"
#include "ncfg/document.h"
#include "ncfg/pppoe.h"

#include "testdir.h"

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int failures;
static int checks;

static void check(int condition, const char *what)
{
	checks++;
	printf("%-70s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

static void detail(const char *label, const char *text)
{
	printf("       %s: %s\n", label, text ? text : "(none)");
}

/* A rendering compared by equality is unreadable as a boolean. */
static void check_text(const char *got, const char *want, const char *what)
{
	int same = got && strcmp(got, want) == 0;

	check(same, what);
	if (!same) {
		detail("wanted", want);
		detail("got", got);
	}
}

static ncfg_pppoe_config_t plain(void)
{
	ncfg_pppoe_config_t config;

	memset(&config, 0, sizeof(config));
	config.parent = (char *)"eth0";
	config.username = (char *)"alice@isp";
	return config;
}

/* ------------------------------------------------------------------------ *
 * What pppd is told
 * ------------------------------------------------------------------------ */

/* The fixed middle of every options file, which no case varies. */
#define OPTIONS_BODY                                                                 \
	"noauth\n"                                                                   \
	"persist\n"                                                                  \
	"maxfail 0\n"                                                                \
	"# netcfgd owns routes. `defaultroute` here would install one nobody\n"      \
	"# wrote down; a ppp link needs no gateway, so the config says\n"            \
	"# `routes = \"default\"` and netcfgd installs it.\n"                        \
	"nodefaultroute\n"                                                           \
	"noipdefault\n"                                                              \
	"# And the ISP's resolvers, which are the one thing only pppd learns.\n"     \
	"# `usepeerdns` sets DNS1 and DNS2 for the scripts below; it also writes\n"  \
	"# /etc/ppp/resolv.conf, which is pppd's own file and not the system\n"      \
	"# one -- checked in ipcp.c rather than assumed, because this option was\n"  \
	"# left out for years on the belief that it rewrote /etc/resolv.conf.\n"     \
	"usepeerdns\n"                                                               \
	"# Two scripts rather than one told apart by its environment: pppd\n"        \
	"# leaves DNS1 and DNS2 set for the ip-down call as well, so a single\n"     \
	"# script would report the same servers as the session went away.\n"

static void the_options_file_is_what_an_operator_reads(void)
{
	ncfg_pppoe_config_t config = plain();
	char               *text;
	char                err[NCFG_ERROR_MAX];

	err[0] = '\0';
	text = ncfg_pppoe_options("ppp0", &config, "hunter2", "/run/ncfg/ppp/ppp0.up",
	    "/run/ncfg/ppp/ppp0.down", err, sizeof(err));
	check_text(text,
	    "# Written by netcfgd for ppp0. Do not edit; it is rewritten on apply.\n"
	    "plugin pppoe.so\n"
	    "nic-eth0\n"
	    "user \"alice@isp\"\n"
	    "password \"hunter2\"\n" OPTIONS_BODY
	    "ip-up-script /run/ncfg/ppp/ppp0.up\n"
	    "ip-down-script /run/ncfg/ppp/ppp0.down\n"
	    "unit 0\n",
	    "the options file is the whole of what pppd is told");
	free(text);

	/* The unit is the interface's, so `interface ppp3` is ppp3 rather than
	 * whichever unit happened to be free -- without it the document stops
	 * describing the system after the second session. */
	err[0] = '\0';
	text = ncfg_pppoe_options("ppp3", &config, "x", "/u", "/d", err, sizeof(err));
	check(text && strstr(text, "\nunit 3\n") != NULL,
	    "the unit number is taken from the interface name");
	free(text);

	/* And a name that is not `pppN` asks for no unit at all, rather than one
	 * this module invented. */
	err[0] = '\0';
	text = ncfg_pppoe_options("dsl0", &config, "x", "/u", "/d", err, sizeof(err));
	check(text && strstr(text, "\nunit ") == NULL,
	    "an interface that is not pppN asks pppd for no unit");
	free(text);

	/* The service and the access concentrator are written only where the
	 * document names them: an empty `rp_pppoe_service` is not the same
	 * request as none. */
	config.service = (char *)"internet";
	config.ac = (char *)"isp-ac1";
	err[0] = '\0';
	text = ncfg_pppoe_options("ppp0", &config, "x", "/u", "/d", err, sizeof(err));
	check(text && strstr(text, "rp_pppoe_service \"internet\"\n") != NULL &&
	        strstr(text, "rp_pppoe_ac \"isp-ac1\"\n") != NULL,
	    "a named service and concentrator are written, quoted");
	free(text);

	config = plain();
	err[0] = '\0';
	text = ncfg_pppoe_options("ppp0", &config, "x", "/u", "/d", err, sizeof(err));
	check(text && strstr(text, "rp_pppoe_") == NULL,
	    "and a document naming neither asks for neither");
	free(text);
}

/*
 * A credential with a space and a quote in it.
 *
 * pppd splits on whitespace and understands double quotes with backslash
 * escapes, so an unquoted password with a space is two options and one
 * carrying a quote turns the rest of the line into pppd directives -- which is
 * a dial that authenticates as somebody else, or does not dial at all.
 */
static void a_password_survives_quoting(void)
{
	ncfg_pppoe_config_t config = plain();
	char               *text;
	char                err[NCFG_ERROR_MAX];

	config.username = (char *)"al ice";
	err[0] = '\0';
	text = ncfg_pppoe_options("ppp0", &config, "a \"quoted\" pass\\word", "/u", "/d", err,
	    sizeof(err));
	check(text && strstr(text, "user \"al ice\"\n") != NULL,
	    "a username with a space in it stays one option");
	check(text && strstr(text, "password \"a \\\"quoted\\\" pass\\\\word\"\n") != NULL,
	    "and a password's quotes and backslashes are escaped rather than ending it");
	if (text && strstr(text, "password \"a \\\"quoted\\\" pass\\\\word\"\n") == NULL) {
		detail("got", text);
	}
	free(text);
}

/*
 * The two scripts, and the difference they were split over.
 *
 * pppd hands both calls the same argv and leaves `DNS1` and `DNS2` set on the
 * way down, so a single script told apart by its environment would report the
 * same nameservers as the session went away -- netcfgd would then hold an
 * ISP's resolvers for a line that is down.
 */
static void the_two_scripts_differ_in_the_way_that_matters(void)
{
	char *up;
	char *down;
	char  err[NCFG_ERROR_MAX];

	err[0] = '\0';
	up = ncfg_pppoe_script("ppp0", "/run/ncfg/reported/ppp0", 1, err, sizeof(err));
	down = ncfg_pppoe_script("ppp0", "/run/ncfg/reported/ppp0", 0, err, sizeof(err));
	check(up != NULL && down != NULL, "both scripts render");
	check(up && strstr(up, "\"$DNS1\"") != NULL && strstr(up, "\"$DNS2\"") != NULL,
	    "the ip-up script reports what the peer offered");
	check(down && strstr(down, "$DNS1") == NULL,
	    "and the ip-down script reports no nameserver at all");
	/*
	 * `if` rather than `[ ... ] && ...`: a failing test is the last command
	 * of the group, so the group's status is 1, `|| exit 1` fires, and the
	 * `mv` never runs -- which made a peer offering one nameserver
	 * indistinguishable from a peer offering none. Measured in the Rust.
	 */
	check(up && strstr(up, "if [ -n \"${DNS1:-}\" ]; then") != NULL,
	    "each nameserver is its own `if`, so one server is not the same as none");
	check(up && strstr(up, "tmp=\"$dir/.$(basename \"$target\")\"") != NULL,
	    "the report is staged under a dotted name, which the contract skips");
	check(down && strstr(down, "} > \"$tmp\" || exit 1\nmv \"$tmp\" \"$target\"\n") != NULL,
	    "and the way down empties the report rather than removing it");
	free(up);
	free(down);
}

/* ------------------------------------------------------------------------ *
 * The lifecycle
 * ------------------------------------------------------------------------ */

static void write_fake(const char *path, const char *body)
{
	check(testdir_write(path, body, strlen(body)), "the stand-in pppd is written");
	check(chmod(path, 0755) == 0, "and is executable");
}

static void a_dial_writes_three_files_and_runs_pppd(const char *base)
{
	ncfg_pppoe_config_t  config = plain();
	ncfg_pppoe_machine_t machine;
	char                 fake[512];
	char                 seen[512];
	char                 options[NCFG_PPPOE_PATH_MAX];
	char                 script[NCFG_PPPOE_PATH_MAX];
	char                 body[1024];
	char                 err[NCFG_ERROR_MAX];
	char                *written;

	(void)testdir_in(base, "fake-pppd", fake, sizeof(fake));
	(void)testdir_in(base, "arguments", seen, sizeof(seen));
	(void)snprintf(body, sizeof(body), "#!/bin/sh\nprintf '%%s\\n' \"$@\" > '%s'\nexit 0\n",
	    seen);
	write_fake(fake, body);

	ncfg_pppoe_machine(&machine);
	machine.program = fake;
	err[0] = '\0';
	check(ncfg_pppoe_start(base, "ppp0", &config, "hunter2", &machine, err, sizeof(err)),
	    "a dial runs the program it was given");
	detail("if not", err);

	written = testdir_read(seen, NULL);
	check(ncfg_pppoe_options_path(base, "ppp0", options, sizeof(options), NULL, 0),
	    "the options path is spelled");
	if (written) {
		char wanted[640];

		(void)snprintf(wanted, sizeof(wanted), "file\n%s\n", options);
		check_text(written, wanted, "and pppd is pointed at the options file and nothing else");
		free(written);
	} else {
		check(0, "and pppd is pointed at the options file and nothing else");
	}

	/*
	 * **0600, because the password is in these bytes**, and the mode is what
	 * this check is about: `/run/netcfgd` is traversable by anyone on the
	 * machine -- `RuntimeDirectoryMode=0755` in the unit -- so a file left at
	 * 0644 is a DSL password every process can read.
	 */
	check(testdir_mode(options) == 0600, "the options file is readable only by root");
	written = testdir_read(options, NULL);
	check(written && strstr(written, "password \"hunter2\"") != NULL,
	    "and it carries the credential pppd could not be given any other way");
	free(written);

	check(ncfg_pppoe_script_path(base, "ppp0", 1, script, sizeof(script), NULL, 0) &&
	        testdir_mode(script) == 0755,
	    "the ip-up script is executable, because pppd runs it");
	check(ncfg_pppoe_script_path(base, "ppp0", 0, script, sizeof(script), NULL, 0) &&
	        testdir_mode(script) == 0755,
	    "and so is the ip-down script");
}

/*
 * A dial that failed says what pppd said, and keeps the options file.
 *
 * The file is 0600 and netcfgd runs as root, so the only reader is somebody
 * who can already read `/etc/netcfgd/secrets` -- and keeping it is the only
 * way to check what netcfgd hands pppd on a machine with no DSL line.
 */
static void a_dial_that_failed_says_why_and_keeps_the_evidence(const char *base)
{
	ncfg_pppoe_config_t  config = plain();
	ncfg_pppoe_machine_t machine;
	char                 fake[512];
	char                 options[NCFG_PPPOE_PATH_MAX];
	char                 err[NCFG_ERROR_MAX];

	(void)testdir_in(base, "fake-pppd-angry", fake, sizeof(fake));
	write_fake(fake,
	    "#!/bin/sh\n"
	    "echo 'Cannot open /dev/ppp: No such file or directory' >&2\n"
	    "echo 'Please load the ppp_generic kernel module.' >&2\n"
	    "exit 1\n");

	ncfg_pppoe_machine(&machine);
	machine.program = fake;
	err[0] = '\0';
	check(!ncfg_pppoe_start(base, "ppp1", &config, "hunter2", &machine, err, sizeof(err)),
	    "a pppd that would not dial is a failed start");
	check(strstr(err, "Cannot open /dev/ppp") != NULL,
	    "and the refusal quotes what pppd said rather than its exit status");
	detail("said", err);
	check(ncfg_pppoe_options_path(base, "ppp1", options, sizeof(options), NULL, 0) &&
	        testdir_exists(options),
	    "the options file is deliberately left for whoever looks next");
}

/*
 * A stand-in for a running pppd: a shell that sleeps, carrying `marker` as a
 * whole argument of its own -- which is what `ncfg_process_pid_of` reads out
 * of `/proc/<pid>/cmdline`.
 *
 * **`sleep 30; :` rather than `sleep 30`**, and that is not decoration: dash
 * execs the last command of a `-c` script in place of itself, so a shell told
 * only to sleep becomes `sleep 30` and the marker this test put in its argv is
 * gone. The first version did exactly that, and the case that was supposed to
 * *recognise* netcfgd's own session went red -- while the case that checks
 * netcfgd does **not** claim somebody else's passed for the wrong reason, the
 * marker having disappeared from both.
 */
static pid_t sleeper(const char *marker)
{
	pid_t pid = fork();

	if (pid == 0) {
		execl("/bin/sh", "sh", "-c", "sleep 30; :", marker, (char *)NULL);
		_exit(127);
	}
	return pid;
}

/*
 * Wait until the child has actually exec'd, or give up.
 *
 * **Between the fork and the exec the child's command line is this test
 * binary's**, so a check made in that window asks about the wrong process --
 * and it fails in the *quiet* direction for the case that matters: "netcfgd
 * does not claim somebody else's pppd" passes because the marker has not
 * appeared yet, rather than because the rule works. The second case caught it
 * by going red, which is the only reason this is here.
 *
 * Bounded at two seconds in twenty-millisecond steps: what it waits for is one
 * `execve` on an idle machine, and a loop with no ceiling in a test suite is
 * what `~/.claude/guidelines` is about.
 */
static int exec_happened(pid_t pid, const char *marker)
{
	char            path[64];
	struct timespec pause = { 0, 20L * 1000L * 1000L };
	int             attempt;

	(void)snprintf(path, sizeof(path), "/proc/%ld/cmdline", (long)pid);
	for (attempt = 0; attempt < 100; attempt++) {
		char    cmdline[4096];
		ssize_t got = -1;
		int     fd = open(path, O_RDONLY);
		size_t  at;
		int     found = 0;

		/* **Read rather than sized first.** A file under `/proc` reports a
		 * length of zero, so `testdir_read` -- which seeks to the end to find
		 * out how much to allocate -- hands back an empty string for a command
		 * line that is there. That is how the first version of this helper
		 * came to answer "not yet" about a process it could see. */
		if (fd >= 0) {
			got = read(fd, cmdline, sizeof(cmdline) - 1u);
			(void)close(fd);
		}
		if (got > 0) {
			cmdline[got] = '\0';
			/* NUL-separated, so a `strstr` over the buffer would match a
			 * marker spanning two arguments. Walked argument by argument,
			 * which is the reading `ncfg_process_pid_of` does. */
			for (at = 0; at < (size_t)got; at += strlen(cmdline + at) + 1u) {
				if (strcmp(cmdline + at, marker) == 0) {
					found = 1;
					break;
				}
			}
		}
		if (found) {
			return 1;
		}
		(void)nanosleep(&pause, NULL);
	}
	return 0;
}

/*
 * A stop signals a process only where the pid file names one that proves whose
 * it is, and takes every file back either way.
 */
static void a_stop_takes_the_files_back(const char *base)
{
	ncfg_pppoe_machine_t machine;
	const char          *dirs[1];
	char                 pid_dir[512];
	char                 pid_path[640];
	char                 options[NCFG_PPPOE_PATH_MAX];
	char                 script[NCFG_PPPOE_PATH_MAX];
	char                 text[64];
	char                 err[NCFG_ERROR_MAX];
	pid_t                other;
	int                  status = 0;

	(void)testdir_in(base, "pids", pid_dir, sizeof(pid_dir));
	testdir_mkdirp(pid_dir);
	dirs[0] = pid_dir;
	ncfg_pppoe_machine(&machine);
	machine.pid_dirs = dirs;
	machine.pid_dir_count = 1u;

	check(ncfg_pppoe_options_path(base, "ppp0", options, sizeof(options), NULL, 0) &&
	        testdir_exists(options),
	    "the session dialled above left its files");

	/*
	 * A pid file naming a process that is running and is **not** netcfgd's:
	 * its command line does not carry the options path. Nothing may be
	 * signalled for it, which is the whole of 0014 applied to a daemon with no
	 * control socket.
	 */
	/*
	 * **It carries the interface name as an argument**, which is what an
	 * operator's own `pppd ... ppp0` looks like -- and is the whole point of
	 * the marker being the options path instead. A fixture carrying some other
	 * word would pass whether the rule were the path or the interface, which
	 * is a check that cannot fail in the direction that matters.
	 */
	other = sleeper("ppp0");
	check(other > 0 && exec_happened(other, "ppp0"),
	    "a process that is not netcfgd's is running, carrying the interface name");
	(void)snprintf(pid_path, sizeof(pid_path), "%s/ppp0.pid", pid_dir);
	(void)snprintf(text, sizeof(text), "%ld\n", (long)other);
	check(testdir_write(pid_path, text, strlen(text)), "and a pid file names it");
	check(ncfg_pppoe_running_pid(base, "ppp0", &machine) == 0,
	    "netcfgd does not claim a pppd whose command line is not its own");

	err[0] = '\0';
	check(ncfg_pppoe_stop(base, "ppp0", NULL, &machine, err, sizeof(err)),
	    "stopping where nothing of netcfgd's is running is the state asked for");
	check(kill(other, 0) == 0, "and the process that was not netcfgd's is untouched");
	(void)kill(other, SIGKILL);
	(void)waitpid(other, &status, 0);

	/*
	 * And the files, which is the half that matters most here: a session that
	 * died on its own leaves its options file -- with the password in it --
	 * behind, and nobody comes back to tidy up.
	 */
	check(!testdir_exists(options), "the options file goes, password and all");
	check(ncfg_pppoe_script_path(base, "ppp0", 1, script, sizeof(script), NULL, 0) &&
	        !testdir_exists(script),
	    "and so does the ip-up script");
	check(ncfg_pppoe_script_path(base, "ppp0", 0, script, sizeof(script), NULL, 0) &&
	        !testdir_exists(script),
	    "and the ip-down script");
}

/*
 * And the other answer: a pid file naming a process whose command line does
 * carry netcfgd's options path is netcfgd's own, and is stopped.
 */
static void a_session_of_netcfgds_own_is_stopped(const char *base)
{
	ncfg_pppoe_machine_t machine;
	const char          *dirs[1];
	char                 pid_dir[512];
	char                 pid_path[640];
	char                 options[NCFG_PPPOE_PATH_MAX];
	char                 text[64];
	char                 err[NCFG_ERROR_MAX];
	pid_t                ours;
	pid_t                waited;
	int                  status = 0;

	(void)testdir_in(base, "pids-ours", pid_dir, sizeof(pid_dir));
	testdir_mkdirp(pid_dir);
	dirs[0] = pid_dir;
	ncfg_pppoe_machine(&machine);
	machine.pid_dirs = dirs;
	machine.pid_dir_count = 1u;

	check(ncfg_pppoe_options_path(base, "ppp9", options, sizeof(options), NULL, 0),
	    "the options path this session would be identified by");
	/* The marker is the options path as a whole argument, which is what
	 * `ncfg_process_pid_of` reads out of `/proc/<pid>/cmdline`. */
	ours = sleeper(options);
	check(ours > 0 && exec_happened(ours, options),
	    "a stand-in session carrying netcfgd's own options path is running");
	(void)snprintf(pid_path, sizeof(pid_path), "%s/ppp9.pid", pid_dir);
	(void)snprintf(text, sizeof(text), "%ld\n", (long)ours);
	check(testdir_write(pid_path, text, strlen(text)), "and a pid file names it");
	check(ncfg_pppoe_running_pid(base, "ppp9", &machine) == ours,
	    "netcfgd recognises it as its own by the options file in its command line");

	err[0] = '\0';
	check(ncfg_pppoe_stop(base, "ppp9", NULL, &machine, err, sizeof(err)),
	    "and stops it");
	detail("if not", err);
	waited = waitpid(ours, &status, 0);
	check(waited == ours, "the session is gone rather than left running");
	if (waited != ours) {
		(void)kill(ours, SIGKILL);
		(void)waitpid(ours, &status, 0);
	}
}

int main(void)
{
	const char *base = testdir_make("pppoe");

	printf("== pppoe_test in %s\n", base);

	the_options_file_is_what_an_operator_reads();
	a_password_survives_quoting();
	the_two_scripts_differ_in_the_way_that_matters();
	a_dial_writes_three_files_and_runs_pppd(base);
	a_dial_that_failed_says_why_and_keeps_the_evidence(base);
	a_stop_takes_the_files_back(base);
	a_session_of_netcfgds_own_is_stopped(base);

	testdir_remove(base);

	printf("pppoe_test: %d check(s)\n", checks);
	if (failures == 0) {
		printf("pppoe_test: all checks passed\n");
	} else {
		printf("pppoe_test: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
