/*
 * log_test.c -- the subsystem path, its boundary, and what actually gets
 * rendered.
 *
 * WHY THE BOUNDARY IS THE POINT
 *   A subsystem is a path now -- `dhcp/wlp0s20f3` -- so that one machine's log
 *   reads as one timeline and still filters down to a link. The filter is
 *   therefore a prefix test, and a prefix test that ignores the level boundary
 *   accepts `dhcpcd` when asked for `dhcp`.
 *
 *   **That is not a hypothetical, it is the same fault this tree met one layer
 *   up on the same day**: a record claiming a backend on `wlan0` must not
 *   quieten an alarm about `wlan01` (0268). Same shape, same remedy, and the
 *   reason the match is a named function rather than a `strncmp` at the point
 *   of use.
 *
 * WHAT IS CHECKED AGAINST WHAT IS RENDERED
 *   The composing half is checked by capturing stderr and reading the line
 *   back, not by asserting that the composer was called. A test that stopped
 *   at "the path was built" would pass against an emitter that built the path
 *   and then logged the root -- which is exactly the bug worth catching, since
 *   nothing else in the tree pins the rendered prefix.
 */
#include "ncfg/log.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int failures;
static int checks;

static void check(int condition, const char *what)
{
	checks++;
	printf("%-72s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

/* ------------------------------------------------------------------------ *
 * The match, which has no filesystem in it
 * ------------------------------------------------------------------------ */

static void a_filter_matches_its_own_level_and_below(void)
{
	check(ncfg_log_subsystem_matches("dhcp", "dhcp"), "a path matches itself");
	check(ncfg_log_subsystem_matches("dhcp/wlp0s20f3", "dhcp"),
	    "and a path below it matches");
	check(ncfg_log_subsystem_matches("dhcp/wlp0s20f3/lease", "dhcp"),
	    "however deep it goes");
	check(ncfg_log_subsystem_matches("dhcp/wlp0s20f3", "dhcp/wlp0s20f3"),
	    "and a filter may name the whole path");
}

/*
 * **The case the function exists for.** `dhcp` is a prefix of `dhcpcd` as a
 * string and is not an ancestor of it as a path. A `strncmp` alone accepts it.
 */
static void a_neighbour_is_not_a_child(void)
{
	check(!ncfg_log_subsystem_matches("dhcpcd", "dhcp"),
	    "`dhcpcd` does not match a filter of `dhcp`");
	check(!ncfg_log_subsystem_matches("dhcp-relay", "dhcp"),
	    "nor does `dhcp-relay`, since `-` joins words inside one level");
	check(!ncfg_log_subsystem_matches("supplicant", "dhcp"),
	    "and an unrelated path does not match at all");
	check(!ncfg_log_subsystem_matches("dhcp", "dhcp/wlp0s20f3"),
	    "a parent does not match a filter naming its child");
}

static void an_absent_filter_matches_everything(void)
{
	check(ncfg_log_subsystem_matches("anything/at/all", NULL),
	    "a NULL filter accepts everything, which is the default");
	check(ncfg_log_subsystem_matches("anything/at/all", ""),
	    "and so does an empty one");
	check(!ncfg_log_subsystem_matches(NULL, "dhcp"),
	    "a path that is not there matches a filter that is");
}

static void the_filter_round_trips(void)
{
	ncfg_log_accept_subsystem("dhcp/wlp0s20f3");
	check(strcmp(ncfg_log_accepted_subsystem(), "dhcp/wlp0s20f3") == 0,
	    "the filter reads back as it was set");
	ncfg_log_accept_subsystem(NULL);
	check(ncfg_log_accepted_subsystem()[0] == '\0',
	    "and NULL clears it rather than leaving it");
	check(ncfg_log_accepted_subsystem() != NULL, "which is never NULL to read");
}

/* ------------------------------------------------------------------------ *
 * What is rendered, read back off stderr
 * ------------------------------------------------------------------------ */

/*
 * Run `emit` with stderr pointed at a temporary file, and hand back what it
 * wrote. `tmpfile` rather than a named path: it is unlinked already, so a test
 * that dies leaves nothing behind -- the cleanup rule met at its cheapest.
 */
static int captured(void (*emit)(void), char *out, size_t out_size)
{
	FILE  *scratch;
	int    saved;
	long   length;
	size_t got;

	out[0] = '\0';
	scratch = tmpfile();
	if (!scratch) {
		return 0;
	}
	fflush(stderr);
	saved = dup(STDERR_FILENO);
	if (saved < 0 || dup2(fileno(scratch), STDERR_FILENO) < 0) {
		(void)fclose(scratch);
		return 0;
	}
	emit();
	fflush(stderr);
	(void)dup2(saved, STDERR_FILENO);
	(void)close(saved);

	if (fseek(scratch, 0L, SEEK_END) != 0 || (length = ftell(scratch)) < 0 ||
	    fseek(scratch, 0L, SEEK_SET) != 0) {
		(void)fclose(scratch);
		return 0;
	}
	if ((size_t)length + 1u > out_size) {
		length = (long)out_size - 1;
	}
	got = fread(out, 1u, (size_t)length, scratch);
	out[got] = '\0';
	(void)fclose(scratch);
	return 1;
}

static void emit_with_an_interface(void)
{
	ncfg_log_aboutf("dhcp", "wlp0s20f3", NCFG_LOG_INFO, "leased %s", "10.0.0.1");
}

static void emit_with_no_interface(void)
{
	ncfg_log_aboutf("dhcp", NULL, NCFG_LOG_INFO, "nothing to name");
}

static void emit_with_an_empty_interface(void)
{
	ncfg_log_aboutf("dhcp", "", NCFG_LOG_INFO, "nothing to name");
}

static void emit_a_neighbour(void)
{
	ncfg_log_emitf("dhcpcd", NCFG_LOG_INFO, "from a neighbouring path");
}

static void emit_under_the_filter(void)
{
	ncfg_log_aboutf("dhcp", "wlp0s20f3", NCFG_LOG_INFO, "under the filter");
}

static void the_path_reaches_the_rendered_line(void)
{
	char line[512];

	ncfg_log_accept_subsystem(NULL);
	ncfg_log_accept(NCFG_LOG_INFO);

	check(captured(emit_with_an_interface, line, sizeof(line)) &&
	        strstr(line, "[dhcp/wlp0s20f3]") != NULL,
	    "an interface reaches the rendered prefix as a second level");
	check(strstr(line, "leased 10.0.0.1") != NULL, "and the message survives with it");

	check(captured(emit_with_no_interface, line, sizeof(line)) &&
	        strstr(line, "[dhcp]") != NULL,
	    "a NULL instance renders exactly what a flat subsystem renders");
	check(captured(emit_with_an_empty_interface, line, sizeof(line)) &&
	        strstr(line, "[dhcp]") != NULL,
	    "and so does an empty one, so a caller need not invent a name");
}

/*
 * **The boundary, end to end.** The pure match is checked above; this is the
 * same question asked of the emitter, because a correct matcher wired to the
 * wrong string would pass every case above it.
 */
static void the_filter_keeps_a_neighbour_out(void)
{
	char line[512];

	ncfg_log_accept(NCFG_LOG_INFO);
	ncfg_log_accept_subsystem("dhcp");

	check(captured(emit_under_the_filter, line, sizeof(line)) &&
	        strstr(line, "[dhcp/wlp0s20f3]") != NULL,
	    "a path under the filter is still emitted");
	check(captured(emit_a_neighbour, line, sizeof(line)) && line[0] == '\0',
	    "and `dhcpcd` is not emitted under a filter of `dhcp`");

	ncfg_log_accept_subsystem(NULL);
	check(captured(emit_a_neighbour, line, sizeof(line)) &&
	        strstr(line, "[dhcpcd]") != NULL,
	    "which comes back the moment the filter is cleared");
}

/*
 * **The environment read, because the setter having a caller is not the same
 * as the variable having a reader.**
 *
 * Every case above drives `ncfg_log_accept_subsystem` directly, which is
 * exactly how a filter that nothing reads from the environment would pass all
 * of them. Measured: pointing `NCFG_LOG_SUBSYSTEM` at `./ncfg status` changed
 * nothing, because `ncfg_log_accept_from_env` is called from `daemon_main.c`
 * and from nowhere else -- the CLI has never honoured `NCFG_LOG` either. That
 * is a real gap and it is the daemon's path this pins.
 */
static void the_environment_is_actually_read(void)
{
	ncfg_log_accept_subsystem(NULL);
	if (setenv("NCFG_LOG_SUBSYSTEM", "dhcp/wlp0s20f3", 1) != 0) {
		check(0, "the environment could be set for the test");
		return;
	}
	ncfg_log_accept_from_env();
	check(strcmp(ncfg_log_accepted_subsystem(), "dhcp/wlp0s20f3") == 0,
	    "NCFG_LOG_SUBSYSTEM reaches the filter through accept_from_env");

	/* And it is read even with no level asked for beside it, which is the
	 * early return that would otherwise skip it. */
	ncfg_log_accept_subsystem(NULL);
	(void)unsetenv("NCFG_LOG");
	ncfg_log_accept_from_env();
	check(strcmp(ncfg_log_accepted_subsystem(), "dhcp/wlp0s20f3") == 0,
	    "and is read with no NCFG_LOG set beside it");
	(void)unsetenv("NCFG_LOG_SUBSYSTEM");
	ncfg_log_accept_subsystem(NULL);
}

int main(void)
{
	a_filter_matches_its_own_level_and_below();
	a_neighbour_is_not_a_child();
	an_absent_filter_matches_everything();
	the_filter_round_trips();
	the_path_reaches_the_rendered_line();
	the_filter_keeps_a_neighbour_out();
	the_environment_is_actually_read();

	printf("log_test: %d check(s)\n", checks);
	if (failures == 0) {
		printf("log_test: all checks passed\n");
	} else {
		printf("log_test: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
