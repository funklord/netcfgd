/*
 * pppoe.c -- pppd's options file, its two scripts, and the session around them.
 *
 * See `pppoe.h` for why the password is in a file rather than on a command
 * line, why pppd is told to install neither a route nor a resolver, why there
 * are two scripts and not one, and why a pid has to prove whose it is. What is
 * here is the rendering and the three calls around it.
 */
#include "ncfg/pppoe.h"

#include "../backend_internal.h"
#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/process.h"
#include "ncfg/state.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* An options file is a dozen short lines plus two paths and a password; a
 * script is a fixed body plus a path. Bounded like everything rendered in this
 * port, because a password and an interface name are somebody else's length. */
#define PPPOE_TEXT_MAX (16u * 1024u)

/*
 * pppd's own vocabulary for a dial that would not start.
 *
 * Its complaints go to stderr before it detaches -- an options file it cannot
 * parse, a plugin it cannot load, a `/dev/ppp` that is not there -- and the
 * tail of a log is the wrong lines for the same reason radvd's is.
 */
static const char *const PPPOE_MARKERS[] = { "error", "cannot", "could not", "unrecognized",
	"unable", "failed", "no such" };

static const char *const PPPOE_PID_DIRS[] = { NCFG_PPPOE_PID_DIRS_DEFAULT };

void ncfg_pppoe_machine(ncfg_pppoe_machine_t *out)
{
	if (!out) {
		return;
	}
	out->program = NULL;
	out->pid_dirs = PPPOE_PID_DIRS;
	out->pid_dir_count = sizeof(PPPOE_PID_DIRS) / sizeof(PPPOE_PID_DIRS[0]);
}

/* ------------------------------------------------------------------------ *
 * The paths
 * ------------------------------------------------------------------------ */

int ncfg_pppoe_run_dir(const char *run, char *out, size_t out_size, char *err, size_t err_size)
{
	return ncfg_backend_join(out, out_size, run, "ppp", err, err_size);
}

int ncfg_pppoe_options_path(const char *run, const char *iface, char *out, size_t out_size,
    char *err, size_t err_size)
{
	return ncfg_backend_path(out, out_size, run, "ppp", iface, NULL, err, err_size);
}

int ncfg_pppoe_script_path(const char *run, const char *iface, int going_up, char *out,
    size_t out_size, char *err, size_t err_size)
{
	return ncfg_backend_path(out, out_size, run, "ppp", iface, going_up ? ".up" : ".down", err,
	    err_size);
}

int ncfg_pppoe_log_path(const char *run, const char *iface, char *out, size_t out_size,
    char *err, size_t err_size)
{
	return ncfg_backend_path(out, out_size, run, "ppp", iface, ".log", err, err_size);
}

/* ------------------------------------------------------------------------ *
 * What pppd is told
 * ------------------------------------------------------------------------ */

/*
 * Quote a value for pppd's options file.
 *
 * pppd splits on whitespace and understands double quotes with backslash
 * escapes. A DSL password with a space in it is ordinary, and one carrying a
 * quote would otherwise end the option and turn the rest of the password into
 * pppd directives.
 */
static void add_quoted(ncfg_buf_t *buf, const char *value)
{
	size_t at;

	ncfg_buf_add_text(buf, "\"");
	for (at = 0; value && value[at] != '\0'; at++) {
		if (value[at] == '"' || value[at] == '\\') {
			ncfg_buf_add_text(buf, "\\");
		}
		ncfg_buf_addf(buf, "%c", value[at]);
	}
	ncfg_buf_add_text(buf, "\"");
}

/*
 * The unit number, from the interface name, or -1.
 *
 * `interface ppp0` is ppp0 and not whichever unit happened to be free.
 * Without it the document stops describing the system after the second
 * session, which is the same reason a routing rule's priority is mandatory.
 */
static long unit_of(const char *iface)
{
	const char *rest;
	char       *end;
	long        unit;

	if (!iface || strncmp(iface, "ppp", 3u) != 0) {
		return -1;
	}
	rest = iface + 3;
	if (*rest == '\0') {
		return -1;
	}
	unit = strtol(rest, &end, 10);
	if (*end != '\0' || unit < 0) {
		return -1;
	}
	return unit;
}

char *ncfg_pppoe_options(const char *iface, const ncfg_pppoe_config_t *config,
    const char *password, const char *up, const char *down, char *err, size_t err_size)
{
	ncfg_buf_t buf;
	long       unit;
	char      *out;

	if (!iface || !config || !up || !down) {
		ncfg_error_set(err, err_size,
		    "an options file was rendered without an interface, a configuration and the "
		    "two scripts");
		return NULL;
	}
	if (!config->parent || config->parent[0] == '\0') {
		ncfg_error_set(err, err_size,
		    "the pppoe session on %s names no parent interface to dial over", iface);
		return NULL;
	}
	ncfg_buf_init(&buf, PPPOE_TEXT_MAX);
	ncfg_buf_addf(&buf,
	    "# Written by netcfgd for %s. Do not edit; it is rewritten on apply.\n"
	    "plugin pppoe.so\n"
	    /* **`nic-<name>` rather than a bare device argument.** Both are
	     * accepted and the difference could not be settled on the machine the
	     * Rust was written on -- pppd gives up at `/dev/ppp` before it
	     * validates a device name -- so neither form could be shown wrong.
	     * This one cannot be mistaken for something else and needs no quoting,
	     * where a quoted device argument leaves open whether the quotes end up
	     * in the name. */
	    "nic-%s\n",
	    iface, config->parent);
	ncfg_buf_add_text(&buf, "user ");
	add_quoted(&buf, config->username);
	ncfg_buf_add_text(&buf, "\npassword ");
	add_quoted(&buf, password);
	ncfg_buf_add_text(&buf,
	    "\nnoauth\n"
	    "persist\n"
	    "maxfail 0\n"
	    "# netcfgd owns routes. `defaultroute` here would install one nobody\n"
	    "# wrote down; a ppp link needs no gateway, so the config says\n"
	    "# `routes = \"default\"` and netcfgd installs it.\n"
	    "nodefaultroute\n"
	    "noipdefault\n"
	    "# And the ISP's resolvers, which are the one thing only pppd learns.\n"
	    "# `usepeerdns` sets DNS1 and DNS2 for the scripts below; it also writes\n"
	    "# /etc/ppp/resolv.conf, which is pppd's own file and not the system\n"
	    "# one -- checked in ipcp.c rather than assumed, because this option was\n"
	    "# left out for years on the belief that it rewrote /etc/resolv.conf.\n"
	    "usepeerdns\n"
	    "# Two scripts rather than one told apart by its environment: pppd\n"
	    "# leaves DNS1 and DNS2 set for the ip-down call as well, so a single\n"
	    "# script would report the same servers as the session went away.\n");
	ncfg_buf_addf(&buf, "ip-up-script %s\nip-down-script %s\n", up, down);
	unit = unit_of(iface);
	if (unit >= 0) {
		ncfg_buf_addf(&buf, "unit %ld\n", unit);
	}
	if (config->service) {
		ncfg_buf_add_text(&buf, "rp_pppoe_service ");
		add_quoted(&buf, config->service);
		ncfg_buf_add_text(&buf, "\n");
	}
	if (config->ac) {
		ncfg_buf_add_text(&buf, "rp_pppoe_ac ");
		add_quoted(&buf, config->ac);
		ncfg_buf_add_text(&buf, "\n");
	}
	if (ncfg_buf_failed(&buf)) {
		ncfg_error_set(err, err_size,
		    "the options file for %s is larger than this build will render", iface);
		ncfg_buf_free(&buf);
		return NULL;
	}
	out = ncfg_buf_take(&buf, NULL);
	if (!out) {
		ncfg_error_set(err, err_size, "out of memory rendering the options file for %s",
		    iface);
	}
	ncfg_buf_free(&buf);
	return out;
}

char *ncfg_pppoe_script(const char *iface, const char *report, int going_up, char *err,
    size_t err_size)
{
	ncfg_buf_t  buf;
	const char *when = going_up ? "ip-up" : "ip-down";
	char       *out;

	if (!iface || !report) {
		ncfg_error_set(err, err_size,
		    "a session script was rendered with no interface or no report");
		return NULL;
	}
	ncfg_buf_init(&buf, PPPOE_TEXT_MAX);
	ncfg_buf_addf(&buf,
	    "#!/bin/sh\n"
	    "# Written by netcfgd for %s. Do not edit; it is rewritten on apply,\n"
	    "# and pppd is the only thing that runs it.\n"
	    "#\n"
	    "# pppd's %s-script. doc/interface-report.md is the format; only the\n"
	    "# nameservers are reported, because the address is IPCP's and the routes\n"
	    "# are the document's.\n"
	    "set -u\n"
	    "\n"
	    "target='%s'\n",
	    iface, when, report);
	/* A dotted name, for the reason openvpn's script gives: netcfgd skips a
	 * staging file by the contract's rule, which is a leading dot, and a
	 * `.tmp` suffix does not satisfy it -- so a half-written report was read
	 * as an interface of its own (0113). */
	ncfg_buf_add_text(&buf,
	    "dir=$(dirname \"$target\")\n"
	    "tmp=\"$dir/.$(basename \"$target\")\"\n"
	    "mkdir -p \"$dir\" || exit 1\n"
	    "\n"
	    "{\n");
	ncfg_buf_addf(&buf, "\tprintf '# %%s, written by netcfgd from pppd %s\\n' '%s'\n", when,
	    iface);
	if (going_up) {
		/*
		 * **`if` rather than `[ ... ] && ...`, and that is not a style
		 * choice.** A test that fails is the last command of the group, so the
		 * group's status is 1, `|| exit 1` fires, and the `mv` never runs --
		 * so the report was written only when the peer offered *both*
		 * nameservers. Measured in the Rust by running the generated script:
		 * DNS1 and DNS2 set wrote a report, DNS1 alone wrote none at all, and
		 * a peer offering one nameserver in IPCP is ordinary. Both of its
		 * tests set both, which is why nothing caught it.
		 */
		ncfg_buf_add_text(&buf,
		    "\tif [ -n \"${DNS1:-}\" ]; then printf 'dns=%s\\n' \"$DNS1\"; fi\n"
		    "\tif [ -n \"${DNS2:-}\" ]; then printf 'dns=%s\\n' \"$DNS2\"; fi\n");
	} else {
		ncfg_buf_add_text(&buf,
		    "\t# Nothing. The session is gone, and pppd leaves DNS1 and DNS2 set\n"
		    "\t# in the environment of this very call -- which is why this is a\n"
		    "\t# separate script rather than a branch.\n");
	}
	/* Emptied on the way down rather than removed, which the contract makes
	 * mean "nothing, deliberately" -- pppd running this is somebody watching. */
	ncfg_buf_add_text(&buf, "} > \"$tmp\" || exit 1\nmv \"$tmp\" \"$target\"\n");

	if (ncfg_buf_failed(&buf)) {
		ncfg_error_set(err, err_size,
		    "the %s script for %s is larger than this build will render", when, iface);
		ncfg_buf_free(&buf);
		return NULL;
	}
	out = ncfg_buf_take(&buf, NULL);
	if (!out) {
		ncfg_error_set(err, err_size, "out of memory rendering the %s script for %s", when,
		    iface);
	}
	ncfg_buf_free(&buf);
	return out;
}

/* ------------------------------------------------------------------------ *
 * The lifecycle
 * ------------------------------------------------------------------------ */

char *ncfg_pppoe_binary(void)
{
	return ncfg_backend_find_program("pppd");
}

/* One script, rendered and written executable. */
static int write_script(const char *run, const char *iface, const char *report, int going_up,
    char *path, size_t path_size, char *err, size_t err_size)
{
	char *text;
	int   ok;

	if (!ncfg_pppoe_script_path(run, iface, going_up, path, path_size, err, err_size)) {
		return 0;
	}
	text = ncfg_pppoe_script(iface, report, going_up, err, err_size);
	if (!text) {
		return 0;
	}
	ok = ncfg_backend_write_file(path, text, strlen(text), 0755, err, err_size);
	free(text);
	return ok;
}

int ncfg_pppoe_start(const char *run, const char *iface, const ncfg_pppoe_config_t *config,
    const char *password, const ncfg_pppoe_machine_t *machine, char *err, size_t err_size)
{
	ncfg_pppoe_machine_t defaults;
	char                 dir[NCFG_PPPOE_PATH_MAX];
	char                 options[NCFG_PPPOE_PATH_MAX];
	char                 report[NCFG_PPPOE_PATH_MAX];
	char                 up[NCFG_PPPOE_PATH_MAX];
	char                 down[NCFG_PPPOE_PATH_MAX];
	char                 log[NCFG_PPPOE_PATH_MAX];
	char                 said[NCFG_ERROR_MAX];
	const char          *program;
	const char          *argv[4];
	char                *found = NULL;
	char                *text;
	int                  exited_ok = 0;
	int                  status = 0;

	if (!run || !iface || !config) {
		ncfg_error_set(err, err_size,
		    "a session needs a run directory, an interface and a configuration");
		return 0;
	}
	if (!machine) {
		ncfg_pppoe_machine(&defaults);
		machine = &defaults;
	}
	if (!ncfg_pppoe_run_dir(run, dir, sizeof(dir), err, err_size) ||
	    !ncfg_backend_make_dir(dir, 0755, err, err_size)) {
		return 0;
	}
	if (!ncfg_state_report_path(run, iface, report, sizeof(report), err, err_size)) {
		return 0;
	}
	/* The scripts before the options file, because the options file names
	 * them: pppd is handed a path to each, and a session that dialled before
	 * the script existed would report nothing and say nothing about why. */
	if (!write_script(run, iface, report, 1, up, sizeof(up), err, err_size) ||
	    !write_script(run, iface, report, 0, down, sizeof(down), err, err_size)) {
		return 0;
	}
	if (!ncfg_pppoe_options_path(run, iface, options, sizeof(options), err, err_size)) {
		return 0;
	}
	text = ncfg_pppoe_options(iface, config, password, up, down, err, err_size);
	if (!text) {
		return 0;
	}
	/* 0600, and `ncfg_backend_write_file` puts the mode on the open and
	 * tightens a file that already existed: the password is in these bytes. */
	if (!ncfg_backend_write_file(options, text, strlen(text), 0600, err, err_size)) {
		free(text);
		return 0;
	}
	free(text);

	program = machine->program;
	if (!program) {
		found = ncfg_pppoe_binary();
		if (!found) {
			ncfg_error_set(err, err_size,
			    "no pppd found for %s; a pppoe session needs the ppp package", iface);
			return 0;
		}
		program = found;
	}
	if (!ncfg_pppoe_log_path(run, iface, log, sizeof(log), err, err_size)) {
		free(found);
		return 0;
	}
	argv[0] = program;
	argv[1] = "file";
	argv[2] = options;
	argv[3] = NULL;
	/*
	 * **Its output is kept, where the Rust lets it go to the terminal.** pppd
	 * detaches and logs to syslog afterwards, but what it says about an
	 * options file it will not read is said before that, on stderr, to
	 * whoever started it -- which for a daemon is nobody. The same file every
	 * other backend here keeps, for the same reason: the cause of a start
	 * that failed should be readable on a machine with no syslog at all.
	 */
	if (!ncfg_backend_run(program, argv, log, &exited_ok, &status, err, err_size)) {
		free(found);
		return 0;
	}
	free(found);
	if (!exited_ok) {
		if (ncfg_backend_complaints(log, PPPOE_MARKERS,
		        sizeof(PPPOE_MARKERS) / sizeof(PPPOE_MARKERS[0]), NULL, 0u, 2u, said,
		        sizeof(said))) {
			ncfg_error_set(err, err_size,
			    "pppd would not dial %s: %s. Its output is in %s", iface, said, log);
		} else {
			ncfg_error_set(err, err_size,
			    "pppd exited with status %d for %s; the usual causes are a wrong "
			    "username, a parent interface that is down, or no access "
			    "concentrator answering. Its output is in %s",
			    status, iface, log);
		}
		return 0;
	}
	return 1;
}

pid_t ncfg_pppoe_running_pid(const char *run, const char *iface,
    const ncfg_pppoe_machine_t *machine)
{
	ncfg_pppoe_machine_t defaults;
	char                 options[NCFG_PPPOE_PATH_MAX];
	char                 path[NCFG_PPPOE_PATH_MAX];
	char                 scratch[NCFG_ERROR_MAX];
	size_t               at;

	if (!run || !iface) {
		return 0;
	}
	if (!machine) {
		ncfg_pppoe_machine(&defaults);
		machine = &defaults;
	}
	if (!ncfg_pppoe_options_path(run, iface, options, sizeof(options), scratch,
	        sizeof(scratch))) {
		return 0;
	}
	for (at = 0; at < machine->pid_dir_count; at++) {
		pid_t pid;

		if (!machine->pid_dirs[at] ||
		    !ncfg_backend_path(path, sizeof(path), machine->pid_dirs[at], NULL, iface,
		        ".pid", scratch, sizeof(scratch))) {
			continue;
		}
		pid = ncfg_process_pid_of(path, options);
		if (pid > 0) {
			return pid;
		}
	}
	return 0;
}

/*
 * The files one session leaves behind, by name.
 *
 * Named rather than swept: a wildcard over `<run>/ppp` would take a concurrent
 * session's files, and every name here is knowable from the interface. The
 * `.pid` is netcfgd's own record rather than pppd's, which is why it is in
 * this list and not left to pppd's exit.
 */
static void remove_files(const char *run, const char *iface)
{
	static const char *const suffixes[] = { NULL, ".up", ".down", ".pid", ".log" };
	char                     path[NCFG_PPPOE_PATH_MAX];
	char                     scratch[NCFG_ERROR_MAX];
	size_t                   at;

	for (at = 0; at < sizeof(suffixes) / sizeof(suffixes[0]); at++) {
		if (ncfg_backend_path(path, sizeof(path), run, "ppp", iface, suffixes[at], scratch,
		        sizeof(scratch))) {
			(void)unlink(path);
		}
	}
}

int ncfg_pppoe_stop(const char *run, const char *iface, const char *report,
    const ncfg_pppoe_machine_t *machine, char *err, size_t err_size)
{
	char  spelled[NCFG_PPPOE_PATH_MAX];
	char  scratch[NCFG_ERROR_MAX];
	pid_t pid;

	if (!run || !iface) {
		ncfg_error_set(err, err_size, "a session needs a run directory and an interface");
		return 0;
	}
	/* The report first, and whether or not anything is listening: it is a
	 * claim about resolvers a session is providing, and the session is going
	 * either way. pppd's own ip-down script may write an empty one afterwards,
	 * which means the same thing. */
	if (!report) {
		if (ncfg_state_report_path(run, iface, spelled, sizeof(spelled), scratch,
		        sizeof(scratch))) {
			report = spelled;
		}
	}
	if (report) {
		(void)unlink(report);
	}
	pid = ncfg_pppoe_running_pid(run, iface, machine);
	if (pid <= 0) {
		/* Nothing netcfgd can identify as its own is running, which is the
		 * state this was asked to produce. The files still go, and this branch
		 * is the one that matters most for them: a session that died on its
		 * own leaves its options file -- with the password in it -- behind. */
		remove_files(run, iface);
		return 1;
	}
	if (!ncfg_process_terminate(pid, scratch, sizeof(scratch))) {
		ncfg_error_set(err, err_size, "could not stop the pppoe session on %s (pid %ld): %s",
		    iface, (long)pid, scratch);
		return 0;
	}
	/* After the signal, never before: the options file is what identifies the
	 * process, so a stop that failed must leave the evidence for the next
	 * attempt to find. */
	remove_files(run, iface);
	return 1;
}
