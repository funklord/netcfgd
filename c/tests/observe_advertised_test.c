/*
 * observe_advertised_test.c -- what a running radvd is announcing, read back.
 *
 * WHY THIS MATTERS MORE THAN IT LOOKS
 *   `plan/advertise.c` reads an **empty** `advertised` list as "netcfgd cannot
 *   tell" rather than as "announcing nothing", deliberately: the second
 *   reading plans a reload on every reconcile. So until something filled the
 *   list the comparison never ran at all, and a renumbered prefix left radvd
 *   announcing the old block for ever. The planner's half of that comparison
 *   is already checked in `plan_gaps_test.c` against a hand-written
 *   observation; this is the half that makes the observation real.
 *
 *   The two cases that matter most here are therefore the ones that say
 *   *nothing*: a file that is not there, and one with no prefix in it. Both
 *   have to leave the list empty, because answering "nothing is announced"
 *   from either would plan a reload against a guess.
 */
#include "ncfg/base.h"
#include "ncfg/observe.h"
#include "ncfg/ra.h"

#include "planfix.h"
#include "testdir.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int checks;
static int failures;

static void check(int condition, const char *what)
{
	checks++;
	printf("%-72s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

static const char *base;
static char        run_dir[512];

/*
 * An observation carrying one backend record, as the prior state would --
 * optionally already announcing something.
 *
 * The prior list matters for the "file is gone" case: with an empty one,
 * "left alone" and "cleared" are the same bytes and a check cannot tell them
 * apart. A sabotage that cleared it turned nothing red until this took an
 * argument.
 */
static ncfg_observed_t *observed_announcing(const char *kind, const char *iface, int running,
    const char *already)
{
	char             text[512];
	char             message[NCFG_ERROR_MAX];
	ncfg_observed_t *observed;

	(void)snprintf(text, sizeof(text),
	    "{\"links\":[],\"backends\":[{\"kind\":\"%s\",\"interface\":\"%s\","
	    "\"running\":%s%s%s%s}]}", kind, iface, running ? "true" : "false",
	    already ? ",\"advertised\":[\"" : "", already ? already : "",
	    already ? "\"]" : "");
	message[0] = '\0';
	observed = ncfg_observed_read(text, strlen(text), message, sizeof(message));
	if (!observed) {
		printf("  fixture observation did not read: %s\n", message);
	}
	return observed;
}

static ncfg_observed_t *observed_with(const char *kind, const char *iface, int running)
{
	return observed_announcing(kind, iface, running, NULL);
}

/* Write a generated `radvd.conf` where netcfgd would have written one. */
static int write_config(const char *iface, const char *body)
{
	char path[640];
	char dir[640];

	/* `<run>/radvd/`, which is `ncfg_ra_config_path`'s own directory --
	 * derived from the path it answers rather than spelled again, so a
	 * fixture cannot write where the reader does not look. */
	(void)snprintf(dir, sizeof(dir), "%s/radvd", run_dir);
	testdir_mkdirp(dir);
	if (!ncfg_ra_config_path(run_dir, iface, path, sizeof(path), NULL, 0)) {
		return 0;
	}
	return testdir_write(path, body, strlen(body));
}

/* The list a backend carries, joined, so a mismatch prints readably. */
static void joined(const ncfg_observed_t *observed, char *out, size_t out_size)
{
	size_t length = 0;
	size_t at;

	out[0] = '\0';
	for (at = 0; observed->backend_count == 1u && at < observed->backends[0].advertised_count &&
	    length < out_size; at++) {
		length += (size_t)snprintf(out + length, out_size - length, "%s%s", length ? " " : "",
		    observed->backends[0].advertised[at]);
	}
}

static int announces(const ncfg_observed_t *observed, const char *expected)
{
	char written[256];

	joined(observed, written, sizeof(written));
	if (strcmp(written, expected) == 0) {
		return 1;
	}
	printf("  it announces [%s]; expected [%s]\n", written, expected);
	return 0;
}

/*
 * What `ncfg_ra_config` writes, abbreviated to the shape rather than copied:
 * a `prefix` line per block, tab-indented, each opening a brace block, with
 * other directives around them.
 */
#define RA_CONFIG(prefixes) \
	"interface lan0\n{\n\tAdvSendAdvert on;\n" prefixes "\tRDNSS 2001:db8::1 { };\n};\n"
#define RA_PREFIX(block) \
	"\tprefix " block "\n\t{\n\t\tAdvOnLink on;\n\t\tAdvAutonomous on;\n\t};\n"

/* ------------------------------------------------------------------------ *
 * The cases
 * ------------------------------------------------------------------------ */

static void what_a_running_daemon_was_given_is_read_back(void)
{
	ncfg_observed_t *observed = observed_with("router_advert", "lan0", 1);
	char             message[NCFG_ERROR_MAX];

	if (!observed) {
		check(0, "the fixture for a running daemon reads");
		return;
	}
	check(write_config("lan0", RA_CONFIG(RA_PREFIX("2001:db8:0:101::/64"))),
	    "netcfgd's own generated configuration is on disk");
	message[0] = '\0';
	check(ncfg_observe_advertised(observed, run_dir, message, sizeof(message)),
	    "the round reads it");
	check(announces(observed, "2001:db8:0:101::/64"),
	    "  and the daemon is recorded as announcing what its file says");
	ncfg_observed_free(observed);
}

static void the_order_the_file_declares_them_in_is_kept(void)
{
	ncfg_observed_t *observed = observed_with("router_advert", "lan0", 1);
	char             message[NCFG_ERROR_MAX];

	if (!observed) {
		check(0, "the fixture for two prefixes reads");
		return;
	}
	/*
	 * **Descending on purpose.** `plan/advertise.c` joins both sides into a
	 * string and compares those, against the policy's own order -- so sorting
	 * this side would compare unequal for any document whose prefixes are not
	 * ascending, and plan a reload on every reconcile for ever.
	 */
	(void)write_config("lan0", RA_CONFIG(RA_PREFIX("2001:db8:0:102::/64")
	    RA_PREFIX("2001:db8:0:101::/64")));
	message[0] = '\0';
	(void)ncfg_observe_advertised(observed, run_dir, message, sizeof(message));
	check(announces(observed, "2001:db8:0:102::/64 2001:db8:0:101::/64"),
	    "the order the file declares them in is kept, not sorted");
	ncfg_observed_free(observed);
}

static void a_file_that_is_not_there_says_nothing(void)
{
	/*
	 * **Already announcing something, and that is what makes this a check.**
	 * With an empty prior list, "left alone" and "cleared" are the same bytes:
	 * a sabotage that cleared the list turned nothing red until this fixture
	 * carried one.
	 */
	ncfg_observed_t *observed = observed_announcing("router_advert", "lan-gone", 1,
	    "2001:db8:0:9::/64");
	char             message[NCFG_ERROR_MAX];

	if (!observed) {
		check(0, "the fixture for a missing file reads");
		return;
	}
	check(announces(observed, "2001:db8:0:9::/64"),
	    "a record that already says what a daemon announces reads back");
	message[0] = '\0';
	check(ncfg_observe_advertised(observed, run_dir, message, sizeof(message)),
	    "  and a file gone from under that daemon is not a failure");
	/*
	 * Left as it was, which the planner reads as what it had. Clearing here
	 * would plan a reload against a guess: a `/run` cleared under a daemon
	 * that is still running is exactly this case, and the daemon is announcing
	 * whatever it read before the file went.
	 */
	check(announces(observed, "2001:db8:0:9::/64"),
	    "  and leaves the record alone, rather than saying it announces nothing");
	ncfg_observed_free(observed);
}

static void a_configuration_with_no_prefix_says_nothing_either(void)
{
	ncfg_observed_t *observed = observed_announcing("router_advert", "lan-bare", 1,
	    "2001:db8:0:9::/64");
	char             message[NCFG_ERROR_MAX];

	if (!observed) {
		check(0, "the fixture for a prefixless file reads");
		return;
	}
	(void)write_config("lan-bare", RA_CONFIG(""));
	message[0] = '\0';
	(void)ncfg_observe_advertised(observed, run_dir, message, sizeof(message));
	/* `ncfg_ra_start` refuses to start a daemon with no prefix, so a generated
	 * file without one is a file netcfgd did not write -- and is not evidence
	 * about what the daemon on that interface is doing. */
	check(announces(observed, "2001:db8:0:9::/64"),
	    "a configuration with no prefix in it leaves the record rather than emptying it");
	ncfg_observed_free(observed);
}

static void only_a_running_router_advertisement_daemon_is_asked(void)
{
	ncfg_observed_t *stopped = observed_with("router_advert", "lan0", 0);
	ncfg_observed_t *other = observed_with("dhcp4", "lan0", 1);
	char             message[NCFG_ERROR_MAX];

	if (!stopped || !other) {
		check(0, "the fixtures for the two that are not asked read");
		ncfg_observed_free(stopped);
		ncfg_observed_free(other);
		return;
	}
	/* The file is there -- `what_a_running_daemon_was_given_is_read_back`
	 * wrote it -- so the only thing declining these is the record. */
	message[0] = '\0';
	(void)ncfg_observe_advertised(stopped, run_dir, message, sizeof(message));
	check(announces(stopped, ""),
	    "a daemon the record says is not running is not asked what it announces");
	(void)ncfg_observe_advertised(other, run_dir, message, sizeof(message));
	check(announces(other, ""),
	    "and neither is a backend of another kind on the same interface");
	ncfg_observed_free(stopped);
	ncfg_observed_free(other);
}

static void the_round_refuses_what_it_cannot_be_asked(void)
{
	ncfg_observed_t *observed = observed_with("router_advert", "lan0", 1);
	char             message[NCFG_ERROR_MAX];

	message[0] = '\0';
	check(!ncfg_observe_advertised(NULL, run_dir, message, sizeof(message)) &&
	    message[0] != '\0', "no observation at all is refused with a sentence");
	message[0] = '\0';
	check(observed && !ncfg_observe_advertised(observed, NULL, message, sizeof(message)) &&
	    strstr(message, "run directory") != NULL,
	    "and so is a round with no run directory, naming what was missing");
	ncfg_observed_free(observed);
}

int main(void)
{
	const char *made = testdir_make("advertised");

	base = made;
	(void)snprintf(run_dir, sizeof(run_dir), "%s/run", base);
	testdir_mkdirp(run_dir);
	printf("== observe_advertised_test in %s\n", base);

	what_a_running_daemon_was_given_is_read_back();
	the_order_the_file_declares_them_in_is_kept();
	a_file_that_is_not_there_says_nothing();
	a_configuration_with_no_prefix_says_nothing_either();
	only_a_running_router_advertisement_daemon_is_asked();
	the_round_refuses_what_it_cannot_be_asked();

	testdir_remove(made);
	printf("observe_advertised_test: %d check(s)\n", checks);
	if (failures == 0) {
		printf("observe_advertised_test: all checks passed\n");
	} else {
		printf("observe_advertised_test: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
