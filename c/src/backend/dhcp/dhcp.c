/*
 * dhcp.c -- which DHCP client to run, what to run it with, and whose the one
 * already running is.
 *
 * `dhcp.h` carries the reasoning: why netcfgd does not speak DHCP, where each
 * client keeps the mark that says it is netcfgd's, and why adoption is the
 * ordinary case rather than the exceptional one. What is here is the paths,
 * the two argument vectors, the ownership question and the two verbs around
 * them.
 */
#include "ncfg/dhcp.h"

#include "../backend_internal.h"
#include "ncfg/apply.h"
#include "ncfg/base.h"
#include "ncfg/log.h"
#include "ncfg/process.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/*
 * A client's vocabulary for a start that failed.
 *
 * Both clients announce the reason and then say very little else, so unlike
 * radvd's the tail is usually right too -- but dhcpcd's `-b` returns the
 * moment it has forked, so what is in the log at that point is the parse and
 * nothing after it. Matched case-insensitively, one line at a time.
 */
static const char *const DHCP_MARKERS[] = { "error", "cannot", "could not", "failed", "no such",
	"unknown option", "invalid", "not permitted", "usage:" };

/* How long a confirm waits between looks. Short enough that a stop that
 * worked returns promptly, long enough not to be a spin. */
#define CONFIRM_STEP_MILLISECONDS 100

/* ------------------------------------------------------------------------ *
 * The machine
 * ------------------------------------------------------------------------ */

void ncfg_dhcp_machine(ncfg_dhcp_machine_t *out)
{
	if (!out) {
		return;
	}
	memset(out, 0, sizeof(*out));
	/* The three programs stay NULL: "find the conventional name" is what a
	 * daemon means, and a path is what a test passes. */
	out->hook = NCFG_DHCP_HOOK_DEFAULT;
	out->dhcpcd_run_dir = NCFG_DHCPCD_RUN_DIR_DEFAULT;
	out->dhcpcd_config = NCFG_DHCPCD_CONFIG_DEFAULT;
}

/* ------------------------------------------------------------------------ *
 * The paths
 * ------------------------------------------------------------------------ */

int ncfg_dhcp_client_dir(const char *run, const char *program, char *out, size_t out_size,
    char *err, size_t err_size)
{
	return ncfg_backend_join(out, out_size, run, program, err, err_size);
}

int ncfg_dhcp_pid_path(const char *run, const char *program, const char *iface, char *out,
    size_t out_size, char *err, size_t err_size)
{
	return ncfg_backend_path(out, out_size, run, program, iface, ".pid", err, err_size);
}

int ncfg_dhcp_script_path(const char *run, const char *iface, char *out, size_t out_size,
    char *err, size_t err_size)
{
	return ncfg_backend_path(out, out_size, run, "udhcpc", iface, ".script", err, err_size);
}

int ncfg_dhcp_address_path(const char *run, const char *iface, char *out, size_t out_size,
    char *err, size_t err_size)
{
	return ncfg_backend_path(out, out_size, run, "udhcpc", iface, ".address", err, err_size);
}

/* `-<family>.conf` and `-<family>.log`, which is dhcpcd's own naming: a client
 * started with `-4` writes `<iface>-4.pid`, and everything netcfgd names
 * beside it carries the family for the same reason (0070). */
static int with_family(const char *family, const char *extension, char *out, size_t out_size)
{
	int written;

	if (!family || (strcmp(family, NCFG_DHCP_FAMILY_V4) != 0 &&
	    strcmp(family, NCFG_DHCP_FAMILY_V6) != 0)) {
		return 0;
	}
	written = snprintf(out, out_size, "-%s%s", family, extension);
	return written > 0 && (size_t)written < out_size;
}

int ncfg_dhcp_config_path(const char *run, const char *iface, const char *family, char *out,
    size_t out_size, char *err, size_t err_size)
{
	char suffix[16];

	if (!with_family(family, ".conf", suffix, sizeof(suffix))) {
		if (out && out_size > 0u) {
			out[0] = '\0';
		}
		ncfg_error_set(err, err_size,
		    "a dhcp client's configuration was asked for in the family `%s`, and dhcpcd "
		    "knows `4` and `6`", family ? family : "");
		return 0;
	}
	return ncfg_backend_path(out, out_size, run, "dhcpcd", iface, suffix, err, err_size);
}

int ncfg_dhcp_metric_path(const char *run, const char *iface, char *out, size_t out_size,
    char *err, size_t err_size)
{
	return ncfg_backend_path(out, out_size, run, "dhcpcd", iface, ".metric", err, err_size);
}

int ncfg_dhcp_log_path(const char *run, const char *iface, const char *family, char *out,
    size_t out_size, char *err, size_t err_size)
{
	char suffix[16];

	if (!with_family(family, ".log", suffix, sizeof(suffix))) {
		if (out && out_size > 0u) {
			out[0] = '\0';
		}
		ncfg_error_set(err, err_size,
		    "a dhcp client's log was asked for in the family `%s`, and dhcpcd knows `4` "
		    "and `6`", family ? family : "");
		return 0;
	}
	return ncfg_backend_path(out, out_size, run, "dhcp", iface, suffix, err, err_size);
}

int ncfg_dhcp_report_path(const char *run, const char *iface, char *out, size_t out_size,
    char *err, size_t err_size)
{
	return ncfg_backend_path(out, out_size, run, "reported", iface, NULL, err, err_size);
}

/* ------------------------------------------------------------------------ *
 * The argument vectors
 * ------------------------------------------------------------------------ */

/* Append one, refusing to overrun rather than truncating: a command line that
 * lost its last argument is a different command. */
static int push(ncfg_dhcp_args_t *args, const char *one)
{
	if (!one || args->count + 2u > NCFG_DHCP_ARGV_MAX) {
		return 0;
	}
	args->argv[args->count++] = one;
	args->argv[args->count] = NULL;
	return 1;
}

static int too_long(const char *program, char *err, size_t err_size)
{
	ncfg_error_set(err, err_size, "the command line for %s is longer than this build will build",
	    program ? program : "a dhcp client");
	return 0;
}

int ncfg_dhcp_udhcpc_args(const char *program, const char *applet, const char *iface,
    const char *script, const char *pid_path, ncfg_dhcp_args_t *out, char *err, size_t err_size)
{
	if (!out) {
		ncfg_error_set(err, err_size, "a command line was asked for with nowhere to put it");
		return 0;
	}
	memset(out, 0, sizeof(*out));
	out->argv[0] = NULL;
	if (!program || !iface || !script || !pid_path) {
		ncfg_error_set(err, err_size,
		    "udhcpc was asked for without a program, an interface, a script or a pid file");
		return 0;
	}
	if (!push(out, program)) {
		return too_long(program, err, err_size);
	}
	/* busybox is one binary with the applet named first. Debian ships no
	 * `udhcpc` symlink beside it, so a machine that has the client at all
	 * often cannot be found by that name -- which made the fallback
	 * unreachable exactly where it was most likely to be wanted. */
	if (applet && !push(out, applet)) {
		return too_long(program, err, err_size);
	}
	if (!push(out, "-b") || !push(out, "-i") || !push(out, iface) || !push(out, "-s") ||
	    !push(out, script) || !push(out, "-p") || !push(out, pid_path) ||
	    /* Release the lease on the way out, which is also what makes the
	     * script run `deconfig` on a `SIGTERM`. Without it a stopped client
	     * leaves its address on the interface -- measured -- where `dhcpcd -k`
	     * takes it away, and two clients that disagree about what stopping
	     * means is two behaviours for one `backend.stop`. */
	    !push(out, "-R") ||
	    /* **udhcpc does not request option 119 unless it is asked to**: its
	     * default list is 1, 3, 6, 12, 15, 28, 42, so a server that honours the
	     * request list never sends a search list at all. See `dhcp.h`. */
	    !push(out, "-O") || !push(out, "search")) {
		return too_long(program, err, err_size);
	}
	return 1;
}

int ncfg_dhcp_dhcpcd_args(const char *program, const char *family, const char *iface,
    const ncfg_optint_t *metric, const char *hook, const char *config, ncfg_dhcp_args_t *out,
    char *err, size_t err_size)
{
	char family_flag[4];

	if (!out) {
		ncfg_error_set(err, err_size, "a command line was asked for with nowhere to put it");
		return 0;
	}
	memset(out, 0, sizeof(*out));
	out->argv[0] = NULL;
	if (!program || !iface || !hook || !config) {
		ncfg_error_set(err, err_size,
		    "dhcpcd was asked for without a program, an interface, a hook or a config");
		return 0;
	}
	if (!family || (strcmp(family, NCFG_DHCP_FAMILY_V4) != 0 &&
	    strcmp(family, NCFG_DHCP_FAMILY_V6) != 0)) {
		ncfg_error_set(err, err_size,
		    "dhcpcd was asked to run in the family `%s`, and it knows `4` and `6`; one "
		    "family at a time is netcfgd's decision rather than dhcpcd's, because a "
		    "client left to itself does DHCPv4, DHCPv6 and SLAAC on one interface",
		    family ? family : "");
		return 0;
	}
	(void)snprintf(family_flag, sizeof(family_flag), "-%s", family);
	/* The flag is formatted into the caller's struct, beside the metric, so
	 * `argv` does not point at a local that has gone. */
	if (strlen(family_flag) + 1u > sizeof(out->metric)) {
		return too_long(program, err, err_size);
	}

	/* `-c` and `-f` before the interface, because dhcpcd parses options first
	 * -- and `-f` is netcfgd's only handle on this client after a restart
	 * (0143). */
	if (!push(out, program) || !push(out, "-c") || !push(out, hook) || !push(out, "-f") ||
	    !push(out, config) || !push(out, "-b")) {
		return too_long(program, err, err_size);
	}
	memcpy(out->metric, family_flag, strlen(family_flag) + 1u);
	if (!push(out, out->metric)) {
		return too_long(program, err, err_size);
	}
	if (metric && metric->has) {
		size_t at = strlen(out->metric) + 1u;
		int    written;

		/* **The metric matters as much as the address on a machine with two
		 * uplinks**: the lease's default route has to lose to the wired one or
		 * win over the wifi, and the client is what installs it. busybox
		 * udhcpc has no metric option -- its script does the routing -- so
		 * this is the one thing the two clients cannot do the same way. */
		written = snprintf(out->metric + at, sizeof(out->metric) - at, "%lld",
		    (long long)metric->value);
		if (written <= 0 || (size_t)written >= sizeof(out->metric) - at) {
			return too_long(program, err, err_size);
		}
		if (!push(out, "-m") || !push(out, out->metric + at)) {
			return too_long(program, err, err_size);
		}
	}
	if (!push(out, iface)) {
		return too_long(program, err, err_size);
	}
	return 1;
}

int ncfg_dhcp_dhcpcd_stop_args(const char *program, const char *family, const char *iface,
    ncfg_dhcp_args_t *out, char *err, size_t err_size)
{
	if (!out) {
		ncfg_error_set(err, err_size, "a command line was asked for with nowhere to put it");
		return 0;
	}
	memset(out, 0, sizeof(*out));
	out->argv[0] = NULL;
	if (!program || !iface) {
		ncfg_error_set(err, err_size, "dhcpcd was asked to stop without a program or an "
		                  "interface");
		return 0;
	}
	if (!family || (strcmp(family, NCFG_DHCP_FAMILY_V4) != 0 &&
	    strcmp(family, NCFG_DHCP_FAMILY_V6) != 0)) {
		ncfg_error_set(err, err_size,
		    "dhcpcd was asked to stop in the family `%s`, and it knows `4` and `6`; the "
		    "family is not optional here, because its pid file carries it (0070)",
		    family ? family : "");
		return 0;
	}
	(void)snprintf(out->metric, sizeof(out->metric), "-%s", family);
	if (!push(out, program) || !push(out, out->metric) || !push(out, "-k") ||
	    !push(out, iface)) {
		return too_long(program, err, err_size);
	}
	return 1;
}

/* ------------------------------------------------------------------------ *
 * Whose client is this
 * ------------------------------------------------------------------------ */

ncfg_dhcpcd_whose_t ncfg_dhcpcd_whose(const char *run, const char *iface, const char *family,
    const ncfg_dhcp_machine_t *machine, char *recited, size_t recited_size)
{
	char                mine[NCFG_DHCP_PATH_MAX];
	char               *seen;
	ncfg_dhcpcd_whose_t answer;

	if (recited && recited_size > 0u) {
		recited[0] = '\0';
	}
	if (!machine || !machine->dhcpcd_run_dir || machine->dhcpcd_run_dir[0] == '\0') {
		/* Nowhere to ask. Not "no client": `NCFG_DHCPCD_SILENT` is exactly the
		 * answer "netcfgd could not tell", and the callers act on that
		 * differently from "somebody else's". */
		return NCFG_DHCPCD_SILENT;
	}
	if (!ncfg_dhcp_config_path(run, iface, family, mine, sizeof(mine), NULL, 0)) {
		return NCFG_DHCPCD_SILENT;
	}
	seen = ncfg_dhcpcd_config_file_of(machine->dhcpcd_run_dir, iface, family);
	if (!seen) {
		return NCFG_DHCPCD_SILENT;
	}
	if (recited && recited_size > 0u) {
		(void)snprintf(recited, recited_size, "%s", seen);
	}
	answer = strcmp(seen, mine) == 0 ? NCFG_DHCPCD_OURS : NCFG_DHCPCD_THEIRS;
	free(seen);
	return answer;
}

pid_t ncfg_dhcp_running_pid(const char *run, const char *program, const char *iface)
{
	char pid_path[NCFG_DHCP_PATH_MAX];

	if (!ncfg_dhcp_pid_path(run, program, iface, pid_path, sizeof(pid_path), NULL, 0)) {
		return 0;
	}
	/* **The pid file's own path is the marker**, which is the strongest kind:
	 * netcfgd chose it, it names the interface, and `-p` puts it in the
	 * client's command line. The same arrangement the supplicant's `-P` has
	 * (0080), and the reason `ncfg_ra_running_pid` uses a generated
	 * configuration rather than the interface name. */
	return ncfg_process_pid_of(pid_path, pid_path);
}

int ncfg_dhcp_adopt(const char *run, const char *program, const char *iface, pid_t *pid_out,
    char *err, size_t err_size)
{
	char  pid_path[NCFG_DHCP_PATH_MAX];
	char  dir[NCFG_DHCP_PATH_MAX];
	char  text[32];
	pid_t pid;

	if (pid_out) {
		*pid_out = 0;
	}
	if (!ncfg_dhcp_pid_path(run, program, iface, pid_path, sizeof(pid_path), err, err_size)) {
		return 0;
	}
	/* Already recorded and alive is not an adoption and is not a failure: the
	 * caller's own "is one running" question has already answered it. */
	if (ncfg_process_pid_of(pid_path, pid_path) > 0) {
		return 1;
	}
	pid = ncfg_process_pid_by_marker(pid_path);
	if (pid <= 0) {
		return 1;
	}
	if (!ncfg_dhcp_client_dir(run, program, dir, sizeof(dir), err, err_size) ||
	    !ncfg_backend_make_dir(dir, 0755, err, err_size)) {
		return 0;
	}
	(void)snprintf(text, sizeof(text), "%d\n", (int)pid);
	if (!ncfg_backend_write_file(pid_path, text, strlen(text), 0644, err, err_size)) {
		/* The client is running and netcfgd cannot write down which one. That
		 * is a failure rather than a shrug: the next pass would find no
		 * record, adopt again, and go on adopting for ever -- or start a
		 * second client the moment the marker scan misses. */
		return 0;
	}
	if (pid_out) {
		*pid_out = pid;
	}
	return 1;
}

/* ------------------------------------------------------------------------ *
 * The metric netcfgd started a client with
 * ------------------------------------------------------------------------ */

int ncfg_dhcp_record_metric(const char *run, const char *iface, const ncfg_optint_t *metric,
    char *err, size_t err_size)
{
	char path[NCFG_DHCP_PATH_MAX];
	char dir[NCFG_DHCP_PATH_MAX];
	char text[24];
	int  written;

	if (!ncfg_dhcp_metric_path(run, iface, path, sizeof(path), err, err_size)) {
		return 0;
	}
	if (!metric || !metric->has) {
		/* **Removed rather than left.** A record from the previous network
		 * would say the running client carries a metric it was never given. */
		if (unlink(path) != 0 && errno != ENOENT) {
			ncfg_error_set(err, err_size, "cannot clear %s: %s", path, strerror(errno));
			return 0;
		}
		return 1;
	}
	written = snprintf(text, sizeof(text), "%lld", (long long)metric->value);
	if (written <= 0 || (size_t)written >= sizeof(text)) {
		ncfg_error_set(err, err_size, "the metric for %s does not fit a record", iface);
		return 0;
	}
	if (!ncfg_backend_join(dir, sizeof(dir), run, "dhcpcd", err, err_size) ||
	    !ncfg_backend_make_dir(dir, 0755, err, err_size)) {
		return 0;
	}
	return ncfg_backend_write_file(path, text, strlen(text), 0644, err, err_size);
}

ncfg_optint_t ncfg_dhcp_started_metric(const char *run, const char *iface)
{
	ncfg_optint_t answer;
	char          path[NCFG_DHCP_PATH_MAX];
	char         *text;
	char         *end;
	long long     value;

	answer.has = 0;
	answer.value = 0;
	if (!ncfg_dhcp_metric_path(run, iface, path, sizeof(path), NULL, 0)) {
		return answer;
	}
	text = ncfg_backend_read_file(path, NULL, 64u);
	if (!text) {
		return answer;
	}
	errno = 0;
	value = strtoll(text, &end, 10);
	/* Trailing space is what a shell's `echo` leaves; anything else is not a
	 * number netcfgd wrote, and reading it as one would be a confident wrong
	 * answer where "cannot tell" is available and correct. */
	while (end && (*end == '\n' || *end == '\r' || *end == ' ' || *end == '\t')) {
		end++;
	}
	if (end != text && end && *end == '\0' && errno == 0) {
		answer.has = 1;
		answer.value = (int64_t)value;
	}
	free(text);
	return answer;
}

/* ------------------------------------------------------------------------ *
 * Starting
 * ------------------------------------------------------------------------ */

char *ncfg_dhcp_binary(const char *name)
{
	return ncfg_backend_find_program(name);
}

/*
 * Which program to run for one candidate, or NULL where it is not installed.
 *
 * **An explicit path that is not there reads as "not installed"**, which is
 * what lets a check say "this machine has no dhcpcd" by naming a path in its
 * own directory rather than by having no dhcpcd. The same test
 * `ncfg_backend_find_program` applies -- a regular file -- so the two answers
 * cannot disagree about what counts as installed.
 *
 * `*owned` is set where the answer was allocated and the caller must free it.
 */
static const char *program_for(const char *named, const char *name, char **owned)
{
	struct stat about;

	*owned = NULL;
	if (named) {
		if (stat(named, &about) == 0 && S_ISREG(about.st_mode)) {
			return named;
		}
		return NULL;
	}
	*owned = ncfg_dhcp_binary(name);
	return *owned;
}

/* The `-f` symlink, which is the mark a running dhcpcd recites.
 *
 * Replaced rather than left: the operator's file may have moved, and a symlink
 * netcfgd wrote is netcfgd's to rewrite. A dangling one is not a failure --
 * dhcpcd prints `read_config: ...: No such file or directory`, takes a normal
 * lease and applies its defaults. */
static int write_mark(const char *run, const char *iface, const char *family,
    const ncfg_dhcp_machine_t *machine, char *path, size_t path_size, char *err, size_t err_size)
{
	char        dir[NCFG_DHCP_PATH_MAX];
	const char *target = machine->dhcpcd_config ? machine->dhcpcd_config :
	    NCFG_DHCPCD_CONFIG_DEFAULT;

	if (!ncfg_backend_join(dir, sizeof(dir), run, "dhcpcd", err, err_size) ||
	    !ncfg_backend_make_dir(dir, 0755, err, err_size) ||
	    !ncfg_dhcp_config_path(run, iface, family, path, path_size, err, err_size)) {
		return 0;
	}
	(void)unlink(path);
	if (symlink(target, path) != 0) {
		ncfg_error_set(err, err_size, "cannot point %s at the operator's config: %s", path,
		    strerror(errno));
		return 0;
	}
	return 1;
}

/* The script udhcpc runs, and the two paths it needs. */
static int write_script(const char *run, const char *iface, char *script, size_t script_size,
    char *err, size_t err_size)
{
	char  dir[NCFG_DHCP_PATH_MAX];
	char  state[NCFG_DHCP_PATH_MAX];
	char  report[NCFG_DHCP_PATH_MAX];
	char *text;
	int   ok;

	if (!ncfg_dhcp_client_dir(run, "udhcpc", dir, sizeof(dir), err, err_size) ||
	    !ncfg_backend_make_dir(dir, 0755, err, err_size) ||
	    !ncfg_dhcp_script_path(run, iface, script, script_size, err, err_size) ||
	    !ncfg_dhcp_address_path(run, iface, state, sizeof(state), err, err_size) ||
	    !ncfg_dhcp_report_path(run, iface, report, sizeof(report), err, err_size)) {
		return 0;
	}
	/* The report directory is made here because the hook no longer makes it: a
	 * generated script was written into a directory netcfgd had just created,
	 * and a shipped one arrives with nothing around it. */
	if (!ncfg_backend_join(dir, sizeof(dir), run, "reported", err, err_size) ||
	    !ncfg_backend_make_dir(dir, 0755, err, err_size)) {
		return 0;
	}
	text = ncfg_dhcp_udhcpc_script(iface, state, report, err, err_size);
	if (!text) {
		return 0;
	}
	/* **0755 and under `/run`, which systemd mounts `noexec` by default.** The
	 * mode is netcfgd's half of that and the mount is not: this is the script
	 * udhcpc execs, and 0178 is what an unexecutable one costs. udhcpc is not
	 * dhcpcd, whose hook moved out of `/run` for exactly that reason -- busybox
	 * runs this through `/bin/sh` rather than execing it, so a `noexec` `/run`
	 * does not stop it. Recorded here because the two clients differ. */
	ok = ncfg_backend_write_file(script, text, strlen(text), 0755, err, err_size);
	free(text);
	return ok;
}

/* Run one candidate. 1 where it started, 0 with a sentence where it refused. */
static int run_client(const char *program, const ncfg_dhcp_args_t *args, const char *log,
    const char *iface, char *err, size_t err_size)
{
	char said[NCFG_ERROR_MAX];
	int  exited_ok = 0;
	int  status = 0;

	if (!ncfg_backend_run(program, args->argv, log, &exited_ok, &status, err, err_size)) {
		return 0;
	}
	if (exited_ok) {
		return 1;
	}
	if (ncfg_backend_complaints(log, DHCP_MARKERS,
	    sizeof(DHCP_MARKERS) / sizeof(DHCP_MARKERS[0]), NULL, 0u, 2u, said, sizeof(said))) {
		ncfg_error_set(err, err_size, "%s would not start on %s: %s. Its output is in %s",
		    program, iface, said, log);
	} else {
		ncfg_error_set(err, err_size,
		    "%s would not start on %s: it exited with status %d. Its output is in %s",
		    program, iface, status, log);
	}
	return 0;
}

int ncfg_dhcp_start(const char *run, const char *iface, const ncfg_optint_t *metric,
    const ncfg_dhcp_machine_t *machine, char *err, size_t err_size)
{
	char             script[NCFG_DHCP_PATH_MAX];
	char             pid_path[NCFG_DHCP_PATH_MAX];
	char             config[NCFG_DHCP_PATH_MAX];
	char             log[NCFG_DHCP_PATH_MAX];
	char             dir[NCFG_DHCP_PATH_MAX];
	char             recited[NCFG_DHCP_PATH_MAX];
	char             said[NCFG_ERROR_MAX];
	ncfg_dhcp_args_t args;
	pid_t            adopted = 0;
	size_t           at;

	if (!machine) {
		ncfg_error_set(err, err_size,
		    "a dhcp client was started with no machine: this build has no default for the "
		    "hook, dhcpcd's run directory or the programs, because a default is how a "
		    "check comes to start a client on the machine it is running on");
		return 0;
	}
	if (!run || run[0] == '\0' || !iface || iface[0] == '\0') {
		ncfg_error_set(err, err_size,
		    "a dhcp client was started without a run directory or an interface");
		return 0;
	}

	/*
	 * **A client netcfgd's own record already names is already running**, and
	 * starting a second is the thing this exists to prevent. Asked first
	 * because it is the case a converged machine is in on every reconcile.
	 */
	if (ncfg_dhcp_running_pid(run, "udhcpc", iface) > 0) {
		return 1;
	}

	/* Both marks are rewritten before anything is adopted or started: each
	 * carries the interface name, and an adopted client is still using the one
	 * it was started with. dhcpcd's in particular must not be left dangling --
	 * the `-f` string in its memory survives a wipe of `/run/netcfgd`, and a
	 * later `dhcpcd -n` would read a path that is not there and silently drop
	 * the operator's options. */
	if (!write_script(run, iface, script, sizeof(script), err, err_size) ||
	    !write_mark(run, iface, NCFG_DHCP_FAMILY_V4, machine, config, sizeof(config), err,
	    err_size) ||
	    !ncfg_dhcp_pid_path(run, "udhcpc", iface, pid_path, sizeof(pid_path), err, err_size) ||
	    !ncfg_dhcp_log_path(run, iface, NCFG_DHCP_FAMILY_V4, log, sizeof(log), err,
	    err_size)) {
		return 0;
	}
	if (!ncfg_backend_join(dir, sizeof(dir), run, "dhcp", err, err_size) ||
	    !ncfg_backend_make_dir(dir, 0755, err, err_size)) {
		return 0;
	}

	/* A udhcpc whose pid file went with the run directory. */
	if (!ncfg_dhcp_adopt(run, "udhcpc", iface, &adopted, err, err_size)) {
		return 0;
	}
	if (adopted > 0) {
		ncfg_log_emitf("dhcp", NCFG_LOG_INFO,
		    "adopted the dhcp client already running on %s (pid %d); it is netcfgd's, by "
		    "the `-p %s` it was started with and the privilege it runs with", iface,
		    (int)adopted, pid_path);
		return 1;
	}

	/* And a dhcpcd, which keeps its mark nowhere but its own memory. */
	recited[0] = '\0';
	switch (ncfg_dhcpcd_whose(run, iface, NCFG_DHCP_FAMILY_V4, machine, recited,
	    sizeof(recited))) {
	case NCFG_DHCPCD_OURS:
		ncfg_log_emitf("dhcp", NCFG_LOG_INFO,
		    "adopted the dhcp client already running on %s; it is netcfgd's, by the `-f "
		    "%s` it recites", iface, config);
		return 1;
	case NCFG_DHCPCD_THEIRS:
		/*
		 * **Refused rather than spawned beside**, which is this port's
		 * divergence and 0141's rule. A second `dhcpcd -b` against a running
		 * one is a silent no-op: it prints "sending commands to dhcpcd
		 * process" and exits 0 having started nothing. So going on would
		 * record a start netcfgd did not make, on a client it cannot stop,
		 * and report a converged machine.
		 */
		ncfg_error_set(err, err_size,
		    "a dhcpcd is already running on %s and it is not netcfgd's: it recites `-f "
		    "%s` where netcfgd's would recite `%s`. Starting a second would be a silent "
		    "no-op -- dhcpcd refuses a second instance and exits 0 -- so netcfgd is not "
		    "doing it. Stop that client, or take %s out of netcfgd's configuration",
		    iface, recited, config, iface);
		return 0;
	case NCFG_DHCPCD_SILENT:
	default:
		break;
	}

	/*
	 * Three candidates, in order. The first that is installed and runs is the
	 * answer; one that is installed and refuses fails the start rather than
	 * falling through, because a machine with a dhcpcd that will not take this
	 * configuration has a fault to report and not a second client to try.
	 */
	for (at = 0u; at < 3u; at++) {
		const char *named = at == 0u ? machine->dhcpcd_program :
		    at == 1u ? machine->udhcpc_program : machine->busybox_program;
		const char *name = at == 0u ? "dhcpcd" : at == 1u ? "udhcpc" : "busybox";
		char       *owned = NULL;
		const char *program = program_for(named, name, &owned);
		int         ok;

		if (!program) {
			continue;
		}
		if (at == 0u) {
			/*
			 * **The hook is checked here rather than before the loop**, which
			 * is a divergence with a measured reason: it is dhcpcd's and
			 * udhcpc never runs it, so a machine whose only client is busybox
			 * was refused its lease over a file that would not have been
			 * used. See 0263.
			 */
			struct stat about;

			if (!machine->hook || machine->hook[0] == '\0' ||
			    stat(machine->hook, &about) != 0) {
				free(owned);
				ncfg_error_set(err, err_size,
				    "the dhcpcd hook is not installed at %s, so a lease's nameservers "
				    "would never reach netcfgd and the resolver would be written "
				    "empty. It ships with netcfgd; `make install` places it",
				    machine->hook && machine->hook[0] != '\0' ? machine->hook :
				    NCFG_DHCP_HOOK_DEFAULT);
				return 0;
			}
			ok = ncfg_dhcp_dhcpcd_args(program, NCFG_DHCP_FAMILY_V4, iface, metric,
			    machine->hook, config, &args, err, err_size);
		} else {
			ok = ncfg_dhcp_udhcpc_args(program, at == 2u ? "udhcpc" : NULL, iface, script,
			    pid_path, &args, err, err_size);
		}
		if (!ok || !run_client(program, &args, log, iface, err, err_size)) {
			free(owned);
			return 0;
		}
		free(owned);
		/*
		 * **The record is written after the client is up, and only for the
		 * client that was given a metric.** busybox udhcpc has no `-m`, so
		 * writing the document's number down after starting one would have the
		 * planner believe a metric had been applied that the client never
		 * heard -- and that record is read *instead of* the route comparison
		 * that would have caught it. See 0263; the Rust writes it for
		 * whichever of the three ran.
		 *
		 * Reported and not returned: the client is up, and a record that could
		 * not be kept must not turn a working start into a failure. The
		 * planner then reads "cannot tell", which is what it read before this
		 * record existed.
		 */
		said[0] = '\0';
		if (!ncfg_dhcp_record_metric(run, iface, at == 0u ? metric : NULL, said,
		    sizeof(said))) {
			ncfg_log_emitf("dhcp", NCFG_LOG_WARNING, "%s", said);
		}
		return 1;
	}
	ncfg_error_set(err, err_size,
	    "no DHCPv4 client found for %s; install dhcpcd, udhcpc or busybox", iface);
	return 0;
}

/* ------------------------------------------------------------------------ *
 * Stopping
 * ------------------------------------------------------------------------ */

/* Wait for the `dhcpcd -k` just sent to take effect. */
static int confirm_stopped(const char *run, const char *iface, const char *family,
    const ncfg_dhcp_machine_t *machine, char *err, size_t err_size)
{
	char mine[NCFG_DHCP_PATH_MAX];
	int  patience = machine->patience_ms > 0 ? machine->patience_ms :
	    NCFG_DHCP_STOP_PATIENCE_MS;
	int  waited = 0;

	for (;;) {
		struct timespec step;

		if (ncfg_dhcpcd_whose(run, iface, family, machine, NULL, 0) != NCFG_DHCPCD_OURS) {
			/*
			 * Gone, or somebody else's, or netcfgd could not tell. **The last
			 * of those is deliberately not a failure**: on a udhcpc machine
			 * there is no dhcpcd socket at all and never was, so reading
			 * silence as a client that would not die would fail every stop on
			 * every such machine.
			 */
			return 1;
		}
		if (waited >= patience) {
			break;
		}
		step.tv_sec = 0;
		step.tv_nsec = (long)CONFIRM_STEP_MILLISECONDS * 1000000L;
		(void)nanosleep(&step, NULL);
		waited += CONFIRM_STEP_MILLISECONDS;
	}
	mine[0] = '\0';
	(void)ncfg_dhcp_config_path(run, iface, family, mine, sizeof(mine), NULL, 0);
	ncfg_error_set(err, err_size,
	    "the dhcp client on %s is still running after `dhcpcd -%s -k`: it answers its "
	    "control socket and still recites `-f %s`. dhcpcd runs as its own user, so "
	    "stopping it needs CAP_KILL -- being root is not enough", iface, family, mine);
	return 0;
}

/*
 * Stop a client by the pid it was told to record.
 *
 * The pid is checked against `/proc/<pid>/cmdline` before anything is
 * signalled, for `ncfg_process_pid_of`'s reason: a pid file outlives the
 * process it names and pids are recycled. A stale file is removed and nothing
 * is signalled, which is the whole of the correct action.
 *
 * `SIGTERM` rather than a control socket because neither client has one.
 * odhcp6c answers it by sending a RELEASE, calling its script one last time
 * with no prefixes -- which is what empties the report -- and exiting; read out
 * of its `odhcp6c.c` rather than assumed, because "does it release?" decides
 * whether an ISP still believes the prefix is ours.
 */
static int stop_recorded(const char *run, const char *program, const char *iface, char *err,
    size_t err_size)
{
	char  pid_path[NCFG_DHCP_PATH_MAX];
	char  detail[NCFG_ERROR_MAX];
	pid_t pid;

	if (!ncfg_dhcp_pid_path(run, program, iface, pid_path, sizeof(pid_path), err, err_size)) {
		return 0;
	}
	pid = ncfg_process_pid_of(pid_path, pid_path);
	if (pid <= 0) {
		(void)unlink(pid_path);
		return 1;
	}
	detail[0] = '\0';
	if (!ncfg_process_terminate(pid, detail, sizeof(detail))) {
		ncfg_error_set(err, err_size, "could not stop %s on %s (pid %d): %s", program, iface,
		    (int)pid, detail);
		return 0;
	}
	(void)unlink(pid_path);
	return 1;
}

int ncfg_dhcp_stop(const char *run, const char *iface, const char *family,
    const ncfg_dhcp_machine_t *machine, char *err, size_t err_size)
{
	char                recited[NCFG_DHCP_PATH_MAX];
	char                log[NCFG_DHCP_PATH_MAX];
	char                said[NCFG_ERROR_MAX];
	ncfg_dhcp_args_t    args;
	ncfg_dhcpcd_whose_t whose;
	int                 is_v4;

	if (!machine) {
		ncfg_error_set(err, err_size,
		    "a dhcp client was stopped with no machine: without dhcpcd's own run "
		    "directory netcfgd cannot tell whose client it is about to signal");
		return 0;
	}
	if (!run || run[0] == '\0' || !iface || iface[0] == '\0') {
		ncfg_error_set(err, err_size,
		    "a dhcp client was stopped without a run directory or an interface");
		return 0;
	}
	if (!family || (strcmp(family, NCFG_DHCP_FAMILY_V4) != 0 &&
	    strcmp(family, NCFG_DHCP_FAMILY_V6) != 0)) {
		ncfg_error_set(err, err_size,
		    "a dhcp client was stopped in the family `%s`, and there are two: `4` and "
		    "`6`. The family is not optional, because dhcpcd's pid file carries it and a "
		    "`-k` without one reports a client stopped that is still renewing (0070)",
		    family ? family : "");
		return 0;
	}
	is_v4 = strcmp(family, NCFG_DHCP_FAMILY_V4) == 0;

	recited[0] = '\0';
	whose = ncfg_dhcpcd_whose(run, iface, family, machine, recited, sizeof(recited));
	if (whose == NCFG_DHCPCD_THEIRS) {
		/*
		 * **Asked before the signal rather than after it**, which is this
		 * port's divergence and 0014's rule where the Rust does not apply it:
		 * `dhcpcd -k <iface>` finds a client by convention, so sending it
		 * first and checking ownership afterwards signals a stranger's client
		 * and then reports that the stop "neither reached nor disturbed" it.
		 * What netcfgd was asked for is that *its* client is not running here,
		 * and a client that was never netcfgd's satisfies that -- so this is
		 * success with a note naming the daemon, which is 0141 keeping a
		 * stranger's process a person's decision rather than this function's.
		 */
		ncfg_log_emitf("dhcp", NCFG_LOG_NOTE,
		    "not stopping the dhcpcd on %s: it recites `-f %s`, which is not netcfgd's, "
		    "so netcfgd has no client of its own to stop there", iface, recited);
	} else {
		char       *owned = NULL;
		const char *program = program_for(machine->dhcpcd_program, "dhcpcd", &owned);

		if (program) {
			char dir[NCFG_DHCP_PATH_MAX];

			if (!ncfg_backend_join(dir, sizeof(dir), run, "dhcp", err, err_size) ||
			    !ncfg_backend_make_dir(dir, 0755, err, err_size) ||
			    !ncfg_dhcp_log_path(run, iface, family, log, sizeof(log), err, err_size) ||
			    !ncfg_dhcp_dhcpcd_stop_args(program, family, iface, &args, err,
			    err_size)) {
				free(owned);
				return 0;
			}
			/*
			 * **The exit status is deliberately not read.** "dhcpcd is not
			 * running" is exit 1, and that is the ordinary answer on every
			 * machine whose client is udhcpc -- which is why the missing `-4`
			 * went unnoticed for a milestone (0070). What answers whether the
			 * stop worked is the control socket, below.
			 */
			said[0] = '\0';
			(void)ncfg_backend_run(program, args.argv, log, NULL, NULL, said,
			    sizeof(said));
			free(owned);
			if (!confirm_stopped(run, iface, family, machine, err, err_size)) {
				return 0;
			}
		} else {
			free(owned);
		}
	}

	if (!stop_recorded(run, is_v4 ? "udhcpc" : "odhcp6c", iface, err, err_size)) {
		return 0;
	}
	/*
	 * The metric record is netcfgd's account of a *running* client, so it goes
	 * with the client. Best effort and not a failure: a stale one is caught by
	 * the route comparison, which is still there for exactly that reason.
	 */
	if (is_v4) {
		(void)ncfg_dhcp_record_metric(run, iface, NULL, NULL, 0);
	}
	return 1;
}
