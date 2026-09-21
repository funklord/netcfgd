/*
 * observe_resolv_test.c -- whether the resolver file is still netcfgd's own.
 *
 * WHY THIS PASS IS DIFFERENT FROM EVERY OTHER ONE
 *   The others add to an observation. This one takes something away: it empties
 *   `observed.dns`, which the planner reads as "already delivered", so clearing
 *   it is how netcfgd is told to deliver again. Every case here is therefore
 *   about *when the list survives*, because a pass that cleared too eagerly
 *   would rewrite `/etc/resolv.conf` on every reconcile -- and one that never
 *   cleared would leave a machine whose resolver somebody else replaced with
 *   netcfgd reporting nothing to do.
 *
 * NOTHING HERE READS THE MACHINE'S RESOLVER
 *   Every case names a file in this test's own directory. `/etc/resolv.conf` on
 *   the machine this builds on is the one that decides whether it can resolve a
 *   name, and a pass that was given no path deliberately says nothing -- which
 *   is the last case.
 */
#include "ncfg/base.h"
#include "ncfg/dns.h"
#include "ncfg/observe.h"

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
static char        resolv[640];

/* An observation carrying one delivered scope in the given mode. */
static ncfg_observed_t *delivered(const char *mode, const char *server)
{
	char             text[512];
	char             message[NCFG_ERROR_MAX];
	ncfg_observed_t *observed;

	(void)snprintf(text, sizeof(text),
	    "{\"links\":[],\"dns\":[{\"scope\":\"globals\",\"policy\":{\"mode\":\"%s\","
	    "\"servers\":[{\"addr\":\"%s\"}],\"search\":[],\"domains\":[],\"options\":[]}}]}",
	    mode, server);
	message[0] = '\0';
	observed = ncfg_observed_read(text, strlen(text), message, sizeof(message));
	if (!observed) {
		printf("  fixture did not read: %s\n", message);
	}
	return observed;
}

/* What a delivery of that scope would have written, through the same renderer
 * the delivery uses -- which is the point: a second spelling here would make
 * every comparison differ and prove nothing. */
static char *as_delivered(const ncfg_observed_t *observed)
{
	ncfg_dns_scope_t scope;
	ncfg_dns_flat_t  flat;
	char             message[NCFG_ERROR_MAX];
	char            *text;

	scope.name = observed->dns[0].scope;
	scope.policy = &observed->dns[0].policy;
	message[0] = '\0';
	if (!ncfg_dns_flatten(&scope, 1u, &flat, message, sizeof(message))) {
		printf("  the fixture would not flatten: %s\n", message);
		return NULL;
	}
	text = ncfg_dns_resolv_conf(&flat, "netcfgd", message, sizeof(message));
	ncfg_dns_flat_free(&flat);
	return text;
}

static void the_file_that_is_still_netcfgds_leaves_the_record_alone(void)
{
	ncfg_observed_t *observed = delivered("write_resolv_conf", "10.0.0.53");
	char            *wanted;
	char             message[NCFG_ERROR_MAX];

	if (!observed) {
		check(0, "a delivered scope reads");
		return;
	}
	wanted = as_delivered(observed);
	if (!wanted || !testdir_write(resolv, wanted, strlen(wanted))) {
		check(0, "the resolver file this test compares against is written");
		free(wanted);
		ncfg_observed_free(observed);
		return;
	}
	message[0] = '\0';
	check(ncfg_observe_resolv_currency(observed, resolv, message, sizeof(message)),
	    "a resolver file holding what netcfgd delivered is checked");
	check(observed->dns_count == 1u,
	    "  and the delivered scope stands, so the planner has nothing to do");
	free(wanted);
	ncfg_observed_free(observed);
}

static void a_file_somebody_else_wrote_takes_the_record_away(void)
{
	ncfg_observed_t *observed = delivered("write_resolv_conf", "10.0.0.53");
	char             message[NCFG_ERROR_MAX];

	if (!observed) {
		check(0, "a delivered scope reads");
		return;
	}
	(void)testdir_write(resolv, "nameserver 192.0.2.1\n", strlen("nameserver 192.0.2.1\n"));
	message[0] = '\0';
	check(ncfg_observe_resolv_currency(observed, resolv, message, sizeof(message)),
	    "a resolver file somebody else wrote is checked");
	/*
	 * **All of it, not the one scope.** The file is written whole from every
	 * scope at once, so "this is not what netcfgd wrote" is a statement about
	 * the delivery. Clearing one entry would be a guess about which scope the
	 * other program meant to replace.
	 */
	check(observed->dns_count == 0u,
	    "  and the whole delivery is taken back, which is what makes netcfgd write again");
	ncfg_observed_free(observed);
}

static void a_file_that_is_gone_reads_as_different(void)
{
	ncfg_observed_t *observed = delivered("write_resolv_conf", "10.0.0.53");
	char             message[NCFG_ERROR_MAX];

	if (!observed) {
		check(0, "a delivered scope reads");
		return;
	}
	(void)remove(resolv);
	message[0] = '\0';
	check(ncfg_observe_resolv_currency(observed, resolv, message, sizeof(message)) &&
	        observed->dns_count == 0u,
	    "a resolver file that is not there is a delivery to make again, not an error");
	ncfg_observed_free(observed);
}

static void a_mode_netcfgd_does_not_own_the_file_in_is_left_alone(void)
{
	ncfg_observed_t *observed = delivered("resolved", "10.0.0.53");
	char             message[NCFG_ERROR_MAX];

	if (!observed) {
		check(0, "a scope delivered through resolved reads");
		return;
	}
	(void)testdir_write(resolv, "# somebody else's\n", strlen("# somebody else's\n"));
	message[0] = '\0';
	check(ncfg_observe_resolv_currency(observed, resolv, message, sizeof(message)) &&
	        observed->dns_count == 1u,
	    "a delivery through resolved is not judged by `/etc/resolv.conf`");
	/*
	 * The file is `systemd-resolved`'s to write in that mode, and netcfgd
	 * comparing it would report drift it must not correct -- the other daemon
	 * doing its job would look like an overwrite on every pass.
	 */
	ncfg_observed_free(observed);
}

static void a_pass_given_no_path_says_nothing(void)
{
	ncfg_observed_t *observed = delivered("write_resolv_conf", "10.0.0.53");
	char             message[NCFG_ERROR_MAX];

	if (!observed) {
		check(0, "a delivered scope reads");
		return;
	}
	message[0] = '\0';
	check(ncfg_observe_resolv_currency(observed, NULL, message, sizeof(message)) &&
	        observed->dns_count == 1u,
	    "an observation given no resolver path leaves the delivery alone");
	check(ncfg_observe_resolv_currency(observed, "", message, sizeof(message)) &&
	        observed->dns_count == 1u,
	    "  and so does one given an empty one, rather than reading this machine's");
	ncfg_observed_free(observed);
}

static void nothing_at_all_is_refused_by_name(void)
{
	char message[NCFG_ERROR_MAX];

	message[0] = '\0';
	check(!ncfg_observe_resolv_currency(NULL, resolv, message, sizeof(message)) &&
	        message[0] != '\0',
	    "and a round with no observation is refused with a sentence");
}

int main(void)
{
	const char *made = testdir_make("observe-resolv");

	base = made;
	(void)testdir_in(base, "resolv.conf", resolv, sizeof(resolv));
	printf("== observe_resolv_test in %s\n", base);

	the_file_that_is_still_netcfgds_leaves_the_record_alone();
	a_file_somebody_else_wrote_takes_the_record_away();
	a_file_that_is_gone_reads_as_different();
	a_mode_netcfgd_does_not_own_the_file_in_is_left_alone();
	a_pass_given_no_path_says_nothing();
	nothing_at_all_is_refused_by_name();

	(void)remove(resolv);
	testdir_remove(made);
	printf("observe_resolv_test: %d check(s)\n", checks);
	if (failures == 0) {
		printf("observe_resolv_test: all checks passed\n");
	} else {
		printf("observe_resolv_test: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
