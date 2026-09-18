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

int main(void)
{
	const char *run = testdir_make("ra");
	char        absent[512];

	a_prefix_is_advertised_on_link_and_autonomous();
	the_two_flags_that_send_hosts_to_a_server_are_the_documents();
	nameservers_go_out_only_where_the_document_says_so();
	a_zero_lifetime_is_a_value_and_not_an_absence();

	/* The refusals run against a directory inside ours that does not exist, so
	 * that "nothing was created" is a statement about a path nothing else
	 * touches. */
	(void)testdir_in(run, "never-made", absent, sizeof(absent));
	an_unimplemented_backend_is_refused_by_name(absent);
	nothing_to_advertise_is_refused_before_anything_starts(absent);

	a_start_writes_the_configuration_and_runs_the_daemon(run);
	a_daemon_that_will_not_start_is_quoted(run);
	a_reload_with_no_daemon_is_not_success(run);
	stopping_nothing_is_success(run);

	testdir_remove(run);
	if (failures > 0) {
		printf("ra: %d check(s) failed\n", failures);
		return 1;
	}
	printf("ra: every check passed\n");
	return 0;
}
