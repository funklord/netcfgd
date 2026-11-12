/*
 * ra_test.c -- what is advertised, and what is refused before anything starts.
 *
 * WHAT THESE CASES ARE FOR
 *   Every one of them is the Rust's, with the sentence that says which defect
 *   it is about kept beside it:
 *
 *   * **A prefix is advertised on-link *and* autonomous.** Either alone is
 *     useless on a delegated prefix: on-link without autonomous makes a host
 *     treat the prefix as local and never configure an address from it, which
 *     is the whole point behind a router.
 *   * **The two flags that send hosts to a DHCPv6 server are the document's.**
 *   * **Nameservers go out only where the document says so.**
 *   * **A zero lifetime is a value and not an absence.** Zero is how a host is
 *     told this router is not a default gateway, so it is passed through rather
 *     than read as "unset" -- the case an `Option<u32>` makes obvious and a
 *     plain integer loses.
 *   * **An unimplemented backend is refused by name.** odhcpd takes entirely
 *     different configuration, and handing it radvd's would be a document that
 *     stopped describing the system.
 *   * **Nothing to advertise is refused before anything starts.**
 *
 *   And three the C port adds, because the C has code the Rust got from its
 *   standard library: a rendered file asserted whole rather than by `contains`,
 *   a start whose daemon refuses the configuration, and a reload against a
 *   daemon that is not running.
 *
 * NOTHING OUTSIDE ITS OWN DIRECTORY, AND NO radvd
 *   This machine's real netcfgd is managing its real network. Every path here
 *   is under one `mkdtemp` directory, the run directory is a parameter of every
 *   call, and **the program that is started is a shell script this test wrote**
 *   -- `ncfg_ra_start` takes the program precisely so that a check never
 *   reaches `/usr/sbin/radvd`. Nothing here sends a router advertisement.
 */
#include "ncfg/base.h"
#include "ncfg/document.h"
#include "ncfg/ra.h"

#include "testdir.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int failures;

static void check(int condition, const char *what)
{
	printf("%-70s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

/* Show the text when an assertion about it fails: a rendering compared by
 * equality is unreadable as a boolean. */
static void check_text(const char *got, const char *want, const char *what)
{
	int same = got != NULL && strcmp(got, want) == 0;

	check(same, what);
	if (!same) {
		printf("  wanted:\n%s\n  got:\n%s\n", want, got ? got : "(null)");
	}
}

static ncfg_ra_policy_t plain(void)
{
	ncfg_ra_policy_t policy;

	memset(&policy, 0, sizeof(policy));
	policy.backend.kind = NCFG_RA_BACKEND_AUTO;
	policy.dns = 1;
	return policy;
}

static char *render(const ncfg_ra_policy_t *policy, const char *const *prefixes, size_t prefixes_n,
    const char *const *servers, size_t servers_n)
{
	char message[NCFG_ERROR_MAX];

	return ncfg_ra_render("lan0", policy, prefixes, prefixes_n, servers, servers_n, message,
	    sizeof(message));
}

/* ------------------------------------------------------------- rendering */

/*
 * A prefix is advertised on-link and autonomous, and the file says so whole.
 *
 * Asserted as one string rather than by six `contains` calls: the Rust can
 * afford the looser form because its renderer is a format string the compiler
 * checks, and this one is a buffer with a ceiling. What a `contains` sweep
 * cannot see is a stray line, a lost tab, or a block that never closed -- and
 * radvd's parser is the thing that would notice, on a machine with a radio.
 */
static void a_prefix_is_advertised_on_link_and_autonomous(void)
{
	static const char *const prefixes[] = { "2001:db8:1234::/64" };
	ncfg_ra_policy_t         policy = plain();
	char                    *text = render(&policy, prefixes, 1u, NULL, 0u);

	check_text(text,
	    "# Written by netcfgd for lan0. Do not edit; it is rewritten on apply.\n"
	    "interface lan0\n"
	    "{\n"
	    "\tAdvSendAdvert on;\n"
	    "\tAdvManagedFlag off;\n"
	    "\tAdvOtherConfigFlag off;\n"
	    "\tprefix 2001:db8:1234::/64\n"
	    "\t{\n"
	    "\t\tAdvOnLink on;\n"
	    "\t\tAdvAutonomous on;\n"
	    "\t};\n"
	    "};\n",
	    "a prefix is advertised on-link and autonomous, and nothing else is");
	free(text);
}

/* The two flags that send hosts to a DHCPv6 server are the document's. */
static void the_two_flags_that_send_hosts_to_a_server_are_the_documents(void)
{
	static const char *const prefixes[] = { "2001:db8::/64" };
	ncfg_ra_policy_t         policy = plain();
	char                    *text;

	policy.managed = 1;
	policy.other_config = 1;
	text = render(&policy, prefixes, 1u, NULL, 0u);
	check(text && strstr(text, "\tAdvManagedFlag on;\n") != NULL &&
	    strstr(text, "\tAdvOtherConfigFlag on;\n") != NULL,
	    "the managed and other-config flags are on where the document says so");
	free(text);

	policy = plain();
	text = render(&policy, prefixes, 1u, NULL, 0u);
	check(text && strstr(text, "\tAdvManagedFlag off;\n") != NULL &&
	    strstr(text, "\tAdvOtherConfigFlag off;\n") != NULL,
	    "and off where it does not, rather than left out");
	free(text);
}

/* Nameservers go out only where the document says so. */
static void nameservers_go_out_only_where_the_document_says_so(void)
{
	static const char *const prefixes[] = { "2001:db8::/64" };
	static const char *const servers[] = { "2001:db8:1234::1", "2001:db8:1234::2" };
	ncfg_ra_policy_t         policy = plain();
	char                    *text = render(&policy, prefixes, 1u, servers, 2u);

	check(text && strstr(text, "\tRDNSS 2001:db8:1234::1 2001:db8:1234::2 { };\n") != NULL,
	    "the scope's nameservers go out as one RDNSS option");
	free(text);

	policy.dns = 0;
	text = render(&policy, prefixes, 1u, servers, 2u);
	check(text && strstr(text, "RDNSS") == NULL,
	    "and not at all where the document turns them off");
	free(text);

	policy = plain();
	text = render(&policy, prefixes, 1u, NULL, 0u);
	check(text && strstr(text, "RDNSS") == NULL,
	    "nor an empty RDNSS where the scope named no server");
	free(text);
}

/*
 * A zero lifetime is a value and not an absence.
 *
 * Zero is a lifetime and means "I am not a default gateway". The model carries
 * an optional integer for exactly this, and a port that read `value` without
 * `has` would advertise `AdvDefaultLifetime 0` on every interface -- turning
 * every netcfgd router into a non-router.
 */
static void a_zero_lifetime_is_a_value_and_not_an_absence(void)
{
	static const char *const prefixes[] = { "2001:db8::/64" };
	ncfg_ra_policy_t         policy = plain();
	char                    *text;

	policy.lifetime.has = 1;
	policy.lifetime.value = 0;
	text = render(&policy, prefixes, 1u, NULL, 0u);
	check(text && strstr(text, "\tAdvDefaultLifetime 0;\n") != NULL,
	    "a zero lifetime is written, because zero means `not a default gateway`");
	free(text);

	policy = plain();
	text = render(&policy, prefixes, 1u, NULL, 0u);
	check(text && strstr(text, "AdvDefaultLifetime") == NULL,
	    "and an absent one writes no line at all");
	free(text);
}

/* ----------------------------------------------------------- the refusals */

/*
 * An unimplemented backend is refused by name.
 *
 * Driven against a run directory that does not exist, which is the Rust's own
 * arrangement and the assertion that matters: the refusal comes before
 * anything is created, so a document naming odhcpd leaves nothing behind.
 */
static void an_unimplemented_backend_is_refused_by_name(const char *run)
{
	static const char *const prefixes[] = { "2001:db8::/64" };
	char                     message[NCFG_ERROR_MAX];
	char                     dir[NCFG_RA_PATH_MAX];
	ncfg_ra_policy_t         policy = plain();

	policy.backend.kind = NCFG_RA_BACKEND_ODHCPD;
	message[0] = '\0';
	check(!ncfg_ra_start(run, "lan0", &policy, prefixes, 1u, NULL, 0u, "/nonexistent/radvd",
	      message, sizeof(message)) &&
	    strstr(message, "odhcpd") != NULL,
	    "odhcpd is refused by name rather than handed radvd's configuration");

	policy.backend.kind = NCFG_RA_BACKEND_EXEC;
	policy.backend.command = (char *)(void *)"/usr/bin/somethingelse";
	message[0] = '\0';
	check(!ncfg_ra_start(run, "lan0", &policy, prefixes, 1u, NULL, 0u, "/nonexistent/radvd",
	      message, sizeof(message)) &&
	    strstr(message, "somethingelse") != NULL,
	    "and an exec backend is named rather than substituted too");

	check(ncfg_ra_run_dir(run, dir, sizeof(dir), NULL, 0) && !testdir_exists(dir),
	    "neither refusal created the run directory on the way to refusing");
}

/*
 * Nothing to advertise is refused before anything starts.
 *
 * A policy whose references all resolved to nothing would produce a file radvd
 * accepts and an advertisement that configures nobody -- an RA with no prefix
 * still makes the router a default gateway, which is a thing to ask for
 * deliberately rather than to arrive at by a reference that resolved to
 * nothing.
 */
static void nothing_to_advertise_is_refused_before_anything_starts(const char *run)
{
	char             message[NCFG_ERROR_MAX];
	ncfg_ra_policy_t policy = plain();

	message[0] = '\0';
	check(!ncfg_ra_start(run, "lan0", &policy, NULL, 0u, NULL, 0u, "/nonexistent/radvd",
	      message, sizeof(message)) &&
	    strstr(message, "advertises no prefix") != NULL,
	    "a policy with no prefix left is refused rather than advertised");

	message[0] = '\0';
	check(!ncfg_ra_reload(run, "lan0", &policy, NULL, 0u, NULL, 0u, message, sizeof(message)) &&
	    strstr(message, "stop advertising instead") != NULL,
	    "and reloading into nothing says to stop advertising instead");
}

/* ------------------------------------------------------------ the daemon */

/* A stand-in for radvd: it records its argument list and either succeeds or
 * writes what a refusing radvd writes and exits nonzero. Never radvd. */
static void write_fake(const char *path, const char *body)
{
	check(testdir_write(path, body, strlen(body)), "the stand-in daemon is written");
	check(chmod(path, 0755) == 0, "and is executable");
}

static void a_start_writes_the_configuration_and_runs_the_daemon(const char *run)
{
	static const char *const prefixes[] = { "2001:db8:1234::/64" };
	char                     fake[512];
	char                     seen[512];
	char                     config[NCFG_RA_PATH_MAX];
	char                     message[NCFG_ERROR_MAX];
	char                     body[1024];
	char                    *written;
	char                    *arguments;
	ncfg_ra_policy_t         policy = plain();

	(void)testdir_in(run, "fake-radvd", fake, sizeof(fake));
	(void)testdir_in(run, "arguments", seen, sizeof(seen));
	(void)snprintf(body, sizeof(body), "#!/bin/sh\nprintf '%%s\\n' \"$@\" > '%s'\nexit 0\n",
	    seen);
	write_fake(fake, body);

	message[0] = '\0';
	check(ncfg_ra_start(run, "lan0", &policy, prefixes, 1u, NULL, 0u, fake, message,
	      sizeof(message)),
	    "a start with a prefix writes the file and runs the daemon");
	if (message[0] != '\0') {
		printf("  said: %s\n", message);
	}

	check(ncfg_ra_config_path(run, "lan0", config, sizeof(config), NULL, 0), "the config path");
	written = testdir_read(config, NULL);
	check(written != NULL && strstr(written, "interface lan0\n") != NULL,
	    "and the configuration radvd was pointed at is the rendered one");
	free(written);

	arguments = testdir_read(seen, NULL);
	/* The whole list, in radvd's order. **`--logmethod stderr` is not
	 * decoration**: its own file rather than syslog is what makes the reason an
	 * advertisement did not start readable after the fact on a machine with no
	 * syslog at all, which is the embedded case this project is built for. */
	if (arguments) {
		char want[1024];

		(void)snprintf(want, sizeof(want),
		    "--config\n%s/radvd/lan0.conf\n--pidfile\n%s/radvd/lan0.pid\n--logmethod\n"
		    "stderr\n",
		    run, run);
		check_text(arguments, want, "the daemon is told the config, the pid file and stderr");
	} else {
		check(0, "the daemon is told the config, the pid file and stderr");
	}
	free(arguments);
}

/*
 * A daemon that refuses the configuration is quoted, not summarised.
 *
 * radvd announces the reason and then narrates its shutdown, so the tail is the
 * wrong lines: `exiting, failed to parse config file` is true and useless next
 * to `syntax error in /path:3`. The marker list is what picks the first out of
 * the second, and a test that only checked "the start failed" would pass
 * against a message carrying the exit status alone.
 */
static void a_daemon_that_will_not_start_is_quoted(const char *run)
{
	static const char *const prefixes[] = { "2001:db8:1234::/64" };
	char                     fake[512];
	char                     message[NCFG_ERROR_MAX];
	char                     body[1024];
	ncfg_ra_policy_t         policy = plain();

	(void)testdir_in(run, "fake-radvd-angry", fake, sizeof(fake));
	(void)snprintf(body, sizeof(body),
	    "#!/bin/sh\n"
	    "echo 'version 2.20 started'\n"
	    "echo 'syntax error in lan0.conf, line 3.'\n"
	    "echo 'sending stop signal to children'\n"
	    "echo 'removing pid file'\n"
	    "exit 1\n");
	write_fake(fake, body);

	message[0] = '\0';
	check(!ncfg_ra_start(run, "lan0", &policy, prefixes, 1u, NULL, 0u, fake, message,
	      sizeof(message)),
	    "a daemon that refuses the configuration fails the start");
	check(strstr(message, "syntax error in lan0.conf, line 3") != NULL,
	    "and the refusal quotes the line that said why");
	check(strstr(message, "removing pid file") == NULL &&
	    strstr(message, "sending stop signal") == NULL,
	    "rather than the tail, which is the daemon narrating its own shutdown");
	/* The quote sits mid-sentence, so the daemon's own full stop is trimmed and
	 * the one that follows is this sentence's. Untrimmed it would read
	 * `line 3.. Its output`, which is how a reader can tell the two apart. */
	check(strstr(message, "line 3. Its output is in ") != NULL,
	    "with the daemon's trailing full stop trimmed, since this sits mid-sentence");
	check(strstr(message, ".log") != NULL, "and says where the rest of the output is");
}

/*
 * A reload is not a start, and says so.
 *
 * Quietly doing nothing for a daemon that is not running would leave the
 * document and the wire disagreeing with nothing to say so.
 */
static void a_reload_with_no_daemon_is_not_success(const char *run)
{
	static const char *const prefixes[] = { "2001:db8:1234::/64" };
	char                     message[NCFG_ERROR_MAX];
	ncfg_ra_policy_t         policy = plain();

	message[0] = '\0';
	check(!ncfg_ra_reload(run, "nosuchif", &policy, prefixes, 1u, NULL, 0u, message,
	      sizeof(message)) &&
	    strstr(message, "started rather than reloaded") != NULL,
	    "reloading a daemon that is not running is refused, not silently accepted");
}

/*
 * Stopping something that is not running is the state that was asked for.
 *
 * And a pid file naming a process that is not netcfgd's radvd must not be
 * signalled: the check is `/proc/<pid>/cmdline` against the configuration path
 * netcfgd chose, which an operator's own radvd cannot match.
 */
/*
 * Is the pid still a process reciting what netcfgd gave it?
 *
 * `/proc/<pid>/cmdline` rather than `kill(pid, 0)`, which `running-code.md`
 * records as a false pass: a process nothing has reaped is a zombie and
 * `kill -0` calls it alive, while its command line is empty. The same
 * question production asks, asked here about one pid.
 */
static int still_reciting(pid_t pid, const char *needle)
{
	char   path[64];
	char   buffer[4096];
	FILE  *file;
	size_t got;
	size_t at;

	(void)snprintf(path, sizeof(path), "/proc/%ld/cmdline", (long)pid);
	file = fopen(path, "rb");
	if (!file) {
		return 0;
	}
	got = fread(buffer, 1u, sizeof(buffer) - 1u, file);
	fclose(file);
	buffer[got] = '\0';
	/* The arguments are NUL-separated, so the needle is looked for in each
	 * rather than across the whole buffer. */
	for (at = 0; at < got; at += strlen(buffer + at) + 1u) {
		if (strstr(buffer + at, needle) != NULL) {
			return 1;
		}
	}
	return 0;
}

/*
 * A daemon slow to exit is waited for, and the record outlives it.
 *
 * **The defect this was written against**, the same class as `autoip`'s
 * (10.565) with a different ending: `ncfg_ra_stop` signalled, unlinked the pid
 * file and returned, and `ncfg_ra_running_pid` reads only that file -- so a
 * radvd still exiting read as *absent*. A restart, which is a stop and then a
 * start, would therefore launch a second radvd while the first still held the
 * interface, and two daemons sending conflicting advertisements on one link is
 * a fault nobody would trace back to a stop that said it had succeeded.
 *
 * The holder traps `TERM` and takes half a second over it, so the window is
 * open on every run rather than on the loaded ones.
 */
static void a_daemon_slow_to_exit_is_waited_for(const char *run)
{
	static const char *const prefixes[] = { "2001:db8:1234::/64" };
	char                     fake[512];
	char                     config[NCFG_RA_PATH_MAX];
	char                     message[NCFG_ERROR_MAX];
	char                     body[1024];
	ncfg_ra_policy_t         policy = plain();
	pid_t                    pid;

	(void)testdir_in(run, "fake-slow-radvd", fake, sizeof(fake));
	(void)ncfg_ra_config_path(run, "lan0", config, sizeof(config), NULL, 0);
	/*
	 * The fake leaves a holder whose command line carries the config path --
	 * which is what `ncfg_ra_running_pid` matches on -- and writes that
	 * holder's pid where radvd would write its own.
	 */
	(void)snprintf(body, sizeof(body),
	    "#!/bin/sh\n"
	    "# A radvd that answers SIGTERM and takes half a second over it. The\n"
	    "# loop of short sleeps is deliberate: a trap does not interrupt a\n"
	    "# foreground child, so a single long sleep would never run it.\n"
	    "# It removes its pid file first, as radvd does on the way out, so a\n"
	    "# stop that waited on the file returns while it runs (10.661).\n"
	    "setsid sh -c 'trap \"rm -f \\\"$1\\\"; sleep 0.5; exit 0\" TERM; n=0; while [ $n -lt 1200 ]; do sleep 0.1; n=$((n+1)); done' "
	    "radvd \"$4\" --config %s >/dev/null 2>&1 &\n"
	    "# `$4` is the pidfile: the argument list is `--config X --pidfile Y\n"
	    "# --logmethod stderr`, which the start test above asserts in full, so\n"
	    "# a change to the order fails there loudly rather than here subtly.\n"
	    "echo $! > \"$4\"\n"
	    "sleep 0.3\n"
	    "exit 0\n",
	    config);
	write_fake(fake, body);

	message[0] = '\0';
	check(ncfg_ra_start(run, "lan0", &policy, prefixes, 1u, NULL, 0u, fake, message,
	      sizeof(message)),
	    "a radvd that is slow to exit starts like any other");
	pid = ncfg_ra_running_pid(run, "lan0");
	check(pid > 0, "  and is netcfgd's while it runs");

	message[0] = '\0';
	check(ncfg_ra_stop(run, "lan0", message, sizeof(message)),
	    "  the stop waits for it rather than returning when the signal is queued");
	if (message[0] != '\0') {
		printf("  said: %s\n", message);
	}
	check(pid <= 0 || !still_reciting(pid, config),
	    "  so a start that follows cannot meet the daemon it replaced");
}

static void stopping_nothing_is_success(const char *run)
{
	char message[NCFG_ERROR_MAX];
	char pid_file[NCFG_RA_PATH_MAX];
	char dir[NCFG_RA_PATH_MAX];
	char mine[32];

	message[0] = '\0';
	check(ncfg_ra_stop(run, "nosuchif", message, sizeof(message)),
	    "stopping an interface with no daemon is the state that was asked for");

	check(ncfg_ra_run_dir(run, dir, sizeof(dir), NULL, 0) &&
	    ncfg_ra_pid_path(run, "otherif", pid_file, sizeof(pid_file), NULL, 0),
	    "the pid path for a second interface");
	(void)snprintf(mine, sizeof(mine), "%d\n", (int)getpid());
	check(testdir_write(pid_file, mine, strlen(mine)), "a pid file naming this very process");
	check(ncfg_ra_running_pid(run, "otherif") == 0,
	    "a pid whose command line does not name netcfgd's config is not netcfgd's radvd");
	message[0] = '\0';
	check(ncfg_ra_stop(run, "otherif", message, sizeof(message)),
	    "so stopping it signals nothing and reports the state asked for");
	check(getpid() > 0, "and this process is still here to say so");
}

/* ------------------------------------------------------------ uradvd */

static char *render_uradvd(const ncfg_ra_policy_t *policy, const char *const *prefixes,
    size_t prefixes_n, const char *const *servers, size_t servers_n, char *message,
    size_t message_size)
{
	message[0] = '\0';
	return ncfg_ra_uradvd_render("lan0", policy, prefixes, prefixes_n, servers, servers_n,
	    message, message_size);
}

/*
 * uradvd's record, whole: the arguments it is started with, one to a line.
 *
 * **The lifetime is there although the document gave none**, and that line is
 * the one this test exists for: uradvd's own default router lifetime is 0,
 * which tells every host the router is not a default gateway, where radvd's is
 * 1800. A record without it would advertise the prefix and take the hosts'
 * route away.
 */
static void uradvd_is_given_its_arguments_and_radvds_lifetime(void)
{
	static const char *const prefixes[] = { "2001:db8:1234::/64", "fd00:1::/64" };
	static const char *const servers[] = { "2001:db8:1234::1" };
	char                     message[NCFG_ERROR_MAX];
	char                    *text;
	ncfg_ra_policy_t         policy = plain();

	text = render_uradvd(&policy, prefixes, 2u, servers, 1u, message, sizeof(message));
	check_text(text,
	    "# uradvd for lan0, written by netcfgd. Do not edit; it is rewritten on apply.\n"
	    "# uradvd reads no file: these are the arguments it was started with, one\n"
	    "# to a line, and this file's path follows them, which is how netcfgd knows\n"
	    "# its process from anybody else's.\n"
	    "-i\nlan0\n-p\n2001:db8:1234::/64\n-p\nfd00:1::/64\n--default-lifetime\n1800\n"
	    "--rdnss\n2001:db8:1234::1\n",
	    "uradvd's record is its arguments, radvd's default lifetime among them");
	free(text);

	policy.dns = 0;
	policy.lifetime.has = 1;
	policy.lifetime.value = 0;
	text = render_uradvd(&policy, prefixes, 1u, servers, 1u, message, sizeof(message));
	check(text != NULL && strstr(text, "--default-lifetime\n0\n") != NULL &&
	        strstr(text, "--rdnss") == NULL,
	    "a lifetime of zero is passed as zero, and no name server where dns is off");
	free(text);
}

/* What uradvd cannot say is refused rather than advertised as something else. */
static void what_uradvd_cannot_carry_is_refused(void)
{
	static const char *const one[] = { "2001:db8:1234::/64" };
	static const char *const wide[] = { "2001:db8:1234::/56" };
	static const char *const nine[] = { "2001:db8:1::/64", "2001:db8:2::/64", "2001:db8:3::/64",
		"2001:db8:4::/64", "2001:db8:5::/64", "2001:db8:6::/64", "2001:db8:7::/64",
		"2001:db8:8::/64", "2001:db8:9::/64" };
	static const char *const four[] = { "2001:db8::1", "2001:db8::2", "2001:db8::3",
		"2001:db8::4" };
	char                     message[NCFG_ERROR_MAX];
	char                    *text;
	ncfg_ra_policy_t         policy = plain();

	policy.managed = 1;
	text = render_uradvd(&policy, one, 1u, NULL, 0u, message, sizeof(message));
	check(text == NULL && strstr(message, "managed") != NULL,
	    "the managed flag is refused: uradvd sends it as off");
	free(text);
	policy = plain();
	policy.other_config = 1;
	text = render_uradvd(&policy, one, 1u, NULL, 0u, message, sizeof(message));
	check(text == NULL && strstr(message, "other-config") != NULL,
	    "and so is the other-config flag");
	free(text);
	policy = plain();
	text = render_uradvd(&policy, wide, 1u, NULL, 0u, message, sizeof(message));
	check(text == NULL && strstr(message, "/64") != NULL,
	    "a prefix that is not a /64 is refused");
	free(text);
	text = render_uradvd(&policy, nine, 9u, NULL, 0u, message, sizeof(message));
	check(text == NULL && strstr(message, "at most 8") != NULL,
	    "nine prefixes are refused: uradvd takes eight");
	free(text);
	text = render_uradvd(&policy, one, 1u, four, 4u, message, sizeof(message));
	check(text == NULL && strstr(message, "at most 3") != NULL,
	    "four name servers are refused: uradvd takes three");
	free(text);
	policy.lifetime.has = 1;
	policy.lifetime.value = 9001;
	text = render_uradvd(&policy, one, 1u, NULL, 0u, message, sizeof(message));
	check(text == NULL && strstr(message, "9000") != NULL,
	    "a router lifetime past 9000 s is refused");
	free(text);
}

/*
 * A uradvd started, reloaded and stopped, with a stand-in that does what
 * uradvd does: stays in the foreground and writes no pid file.
 *
 * The stand-in records its arguments and then waits, bounded, so a test that
 * failed to stop it leaves nothing past a minute. Its command line carries the
 * record's path after `--`, which is the whole of how netcfgd knows it.
 */
static void a_uradvd_is_started_restarted_on_reload_and_stopped(const char *run)
{
	static const char *const first[] = { "2001:db8:1234::/64" };
	static const char *const second[] = { "2001:db8:5678::/64" };
	char                     fake[512];
	char                     seen[512];
	char                     message[NCFG_ERROR_MAX];
	char                     body[1024];
	char                     want[1024];
	char                    *arguments;
	pid_t                    before;
	pid_t                    after;
	ncfg_ra_policy_t         policy = plain();

	(void)testdir_in(run, "fake-uradvd", fake, sizeof(fake));
	(void)testdir_in(run, "uradvd-arguments", seen, sizeof(seen));
	(void)snprintf(body, sizeof(body),
	    "#!/bin/sh\nprintf '%%s\\n' \"$@\" > '%s'\nn=0\n"
	    "while [ $n -lt 60 ]; do sleep 1; n=$((n + 1)); done\n",
	    seen);
	write_fake(fake, body);
	policy.backend.kind = NCFG_RA_BACKEND_URADVD;
	policy.dns = 0;

	message[0] = '\0';
	check(ncfg_ra_start(run, "uradvd0", &policy, first, 1u, NULL, 0u, fake, message,
	      sizeof(message)),
	    "a uradvd is started");
	if (message[0] != '\0') {
		printf("  said: %s\n", message);
	}
	before = ncfg_ra_running_pid(run, "uradvd0");
	check(before > 0, "and is known by the pid file written for it and its record's path");
	arguments = testdir_read(seen, NULL);
	(void)snprintf(want, sizeof(want),
	    "-i\nuradvd0\n-p\n2001:db8:1234::/64\n--default-lifetime\n1800\n--\n"
	    "%s/radvd/uradvd0.conf\n",
	    run);
	check_text(arguments, want, "uradvd is given its arguments, then `--` and the record");
	free(arguments);

	message[0] = '\0';
	check(ncfg_ra_reload(run, "uradvd0", &policy, second, 1u, NULL, 0u, message,
	      sizeof(message)),
	    "a reload of a uradvd succeeds");
	if (message[0] != '\0') {
		printf("  said: %s\n", message);
	}
	after = ncfg_ra_running_pid(run, "uradvd0");
	arguments = testdir_read(seen, NULL);
	check(after > 0 && after != before && arguments != NULL &&
	        strstr(arguments, "2001:db8:5678::/64") != NULL,
	    "and is a restart: another process, with the new prefix");
	free(arguments);

	message[0] = '\0';
	check(ncfg_ra_stop(run, "uradvd0", message, sizeof(message)) &&
	        ncfg_ra_running_pid(run, "uradvd0") == 0,
	    "and a stop leaves none running");
}

/* A uradvd that exits at once is quoted: the shell that started it said 0. */
static void a_uradvd_that_exits_at_once_is_quoted(const char *run)
{
	static const char *const prefixes[] = { "2001:db8:1234::/64" };
	char                     fake[512];
	char                     message[NCFG_ERROR_MAX];
	ncfg_ra_policy_t         policy = plain();

	(void)testdir_in(run, "fake-uradvd-angry", fake, sizeof(fake));
	write_fake(fake, "#!/bin/sh\necho 'uradvd: error: interface and prefix arguments are "
	    "required.' >&2\nexit 1\n");
	policy.backend.kind = NCFG_RA_BACKEND_URADVD;
	message[0] = '\0';
	check(!ncfg_ra_start(run, "uradvd1", &policy, prefixes, 1u, NULL, 0u, fake, message,
	      sizeof(message)) &&
	    strstr(message, "arguments are required") != NULL,
	    "a uradvd gone at once is a failed start, in its own words");
	check(ncfg_ra_running_pid(run, "uradvd1") == 0, "and nothing is left recorded as running");
}

int main(void)
{
	const char *run = testdir_make("ra");
	char        absent[512];

	a_prefix_is_advertised_on_link_and_autonomous();
	the_two_flags_that_send_hosts_to_a_server_are_the_documents();
	nameservers_go_out_only_where_the_document_says_so();
	a_zero_lifetime_is_a_value_and_not_an_absence();
	uradvd_is_given_its_arguments_and_radvds_lifetime();
	what_uradvd_cannot_carry_is_refused();

	/* The refusals run against a directory inside ours that does not exist, so
	 * that "nothing was created" is a statement about a path nothing else
	 * touches. */
	(void)testdir_in(run, "never-made", absent, sizeof(absent));
	an_unimplemented_backend_is_refused_by_name(absent);
	nothing_to_advertise_is_refused_before_anything_starts(absent);

	a_start_writes_the_configuration_and_runs_the_daemon(run);
	a_daemon_that_will_not_start_is_quoted(run);
	a_reload_with_no_daemon_is_not_success(run);
	a_daemon_slow_to_exit_is_waited_for(run);
	stopping_nothing_is_success(run);
	a_uradvd_is_started_restarted_on_reload_and_stopped(run);
	a_uradvd_that_exits_at_once_is_quoted(run);

	testdir_remove(run);
	if (failures > 0) {
		printf("ra: %d check(s) failed\n", failures);
		return 1;
	}
	printf("ra: every check passed\n");
	return 0;
}
