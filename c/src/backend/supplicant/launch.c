/*
 * launch.c -- starting a `wpa_supplicant`, recognising the one already
 * running, and stopping netcfgd's own.
 *
 * `supplicant.h` carries the reasoning: where the mark is, why adoption is the
 * ordinary case rather than the exceptional one, and why a stranger is
 * identified by a socket that answers rather than by a process that carries no
 * mark. What is here is the paths, the argument vector, the ownership question
 * and the two verbs around them -- `dhcp.c`'s arrangement, because it is the
 * same problem and was solved there first.
 *
 * WHY THIS IS IN THE SUPPLICANT MODULE AND THE ACCESS POINT'S STOP IS NOT
 *   `backend_ops.c` writes hostapd's stop out of this module's client, and
 *   0263 records that it belongs in `src/backend/hostapd/` the day a second
 *   caller wants it. The supplicant's stop has no such excuse: the client and
 *   the launcher are one module, so `ncfg_supplicant_stop` connects with the
 *   same functions it is declared beside and crosses nothing.
 */
#include "ncfg/supplicant.h"

#include "../backend_internal.h"
#include "ncfg/base.h"
#include "ncfg/log.h"
#include "ncfg/process.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/*
 * `wpa_supplicant`'s vocabulary for a start that failed.
 *
 * Read out of the daemon rather than guessed: an interface that is not there
 * is `Could not read interface wlan0 flags: No such device`, a driver it was
 * not built with is `Unsupported driver 'xyz'`, and both are followed by
 * `Failed to initialize interface` and then `Failed to initialize
 * wpa_supplicant`. So the reason is at the top and the tail is the narration,
 * which is `ncfg_backend_complaints`' whole assumption. Matched
 * case-insensitively, one line at a time.
 */
static const char *const SUPPLICANT_MARKERS[] = { "error", "cannot", "could not", "failed",
	"unsupported", "unknown", "invalid", "no such", "usage:" };

/* Mode 0700 for `<run>/supplicant`, which is the mode `ncfg_service_set_
 * profiles` already makes it with: the digest of what a radio was handed sits
 * in there beside the pid file, and neither is for everybody. An existing
 * directory is success, which is what both callers mean. */
#define SUPPLICANT_DIR_MODE 0700

/* And 0755 for the control directory, which is `wpa_supplicant`'s own and is
 * what it would create for itself. It holds sockets rather than files, and the
 * clients that bind a reply address in it are not always root. */
#define SUPPLICANT_CTRL_DIR_MODE 0755

/* ------------------------------------------------------------------------ *
 * The paths, which are the mark
 * ------------------------------------------------------------------------ */

int ncfg_supplicant_pid_path(const char *run, const char *iface, char *out, size_t out_size,
    char *err, size_t err_size)
{
	return ncfg_backend_path(out, out_size, run, "supplicant", iface, ".pid", err, err_size);
}

int ncfg_supplicant_log_path(const char *run, const char *iface, char *out, size_t out_size,
    char *err, size_t err_size)
{
	return ncfg_backend_path(out, out_size, run, "supplicant", iface, ".log", err, err_size);
}

/* `<dir>/<iface>` -- the control socket, which is not netcfgd's to name and is
 * therefore built rather than composed by `ncfg_backend_path`. */
static int socket_path_of(const char *dir, const char *iface, char *out, size_t out_size)
{
	int written = snprintf(out, out_size, "%s/%s", dir, iface);

	if (written <= 0 || (size_t)written >= out_size) {
		out[0] = '\0';
		return 0;
	}
	return 1;
}

/* ------------------------------------------------------------------------ *
 * The argument vector
 * ------------------------------------------------------------------------ */

/* Append one, refusing to overrun rather than truncating: a command line that
 * lost its last argument is a different command. */
static int push(ncfg_supplicant_args_t *args, const char *one)
{
	if (!one || args->count + 2u > NCFG_SUPPLICANT_ARGV_MAX) {
		return 0;
	}
	args->argv[args->count++] = one;
	args->argv[args->count] = NULL;
	return 1;
}

int ncfg_supplicant_arguments(const char *program, const char *driver, const char *iface,
    const char *dir, const char *pid_path, ncfg_supplicant_args_t *out, char *err,
    size_t err_size)
{
	int written;

	if (!out) {
		ncfg_error_set(err, err_size, "a command line was asked for with nowhere to put it");
		return 0;
	}
	memset(out, 0, sizeof(*out));
	out->argv[0] = NULL;
	if (!program || !iface || !dir || !pid_path) {
		ncfg_error_set(err, err_size,
		    "wpa_supplicant was asked for without a program, an interface, a control "
		    "directory or a pid file");
		return 0;
	}
	if (!driver || driver[0] == '\0') {
		/* **Never defaulted.** A radio started with `wired`, or a wired port
		 * started with `nl80211`, is a supplicant that comes up and never
		 * authenticates -- which looks configured from every angle netcfgd
		 * has. See `supplicant.h`. */
		ncfg_error_set(err, err_size,
		    "wpa_supplicant on %s was asked for with no driver, and the two are not "
		    "interchangeable: `%s` is a radio and `%s` is a wired 802.1X port",
		    iface, NCFG_SUPPLICANT_DRIVER_RADIO, NCFG_SUPPLICANT_DRIVER_WIRED);
		return 0;
	}
	written = snprintf(out->driver, sizeof(out->driver), "-D%s", driver);
	if (written <= 0 || (size_t)written >= sizeof(out->driver)) {
		ncfg_error_set(err, err_size,
		    "the driver `%s` is longer than this build will name on a command line",
		    driver);
		return 0;
	}
	/*
	 * `-s` is not decoration. `-B` daemonises, and a daemonised supplicant
	 * that was not told to use syslog writes to a stdout nothing is reading --
	 * so every association failure, authentication error, disconnect reason
	 * and roaming decision is gone, on the one component whose faults an
	 * operator most needs to read. The Rust's comment records an hour of a
	 * real outage diagnosed without it.
	 */
	if (!push(out, program) || !push(out, "-B") || !push(out, out->driver) ||
	    !push(out, "-s") || !push(out, "-i") || !push(out, iface) || !push(out, "-C") ||
	    !push(out, dir) || !push(out, "-P") || !push(out, pid_path)) {
		ncfg_error_set(err, err_size,
		    "the command line for wpa_supplicant on %s is longer than this build will "
		    "build", iface);
		return 0;
	}
	return 1;
}

/* ------------------------------------------------------------------------ *
 * Whose supplicant is this
 * ------------------------------------------------------------------------ */

pid_t ncfg_supplicant_running_pid(const char *run, const char *iface)
{
	char pid_path[NCFG_SUPPLICANT_PATH_MAX];

	if (!ncfg_supplicant_pid_path(run, iface, pid_path, sizeof(pid_path), NULL, 0)) {
		return 0;
	}
	/* **The pid file's own path is the marker**, which is the strongest kind:
	 * netcfgd chose it, it names the interface, and `-P` puts it in the
	 * supplicant's command line. `ncfg_dhcp_running_pid` is the same line for
	 * the same reason (0080). */
	return ncfg_process_pid_of(pid_path, pid_path);
}

int ncfg_supplicant_adopt(const char *run, const char *dir, const char *iface, pid_t *pid_out,
    char *err, size_t err_size)
{
	char  pid_path[NCFG_SUPPLICANT_PATH_MAX];
	char  parent[NCFG_SUPPLICANT_PATH_MAX];
	char  text[32];
	pid_t pid;

	if (pid_out) {
		*pid_out = 0;
	}
	if (!dir || dir[0] == '\0') {
		/* Refused by name rather than answered "nothing to adopt": without a
		 * control directory the answering half of the question cannot be
		 * asked, and a silent no here is exactly 0140's fault. */
		ncfg_error_set(err, err_size,
		    "a supplicant on %s cannot be adopted without being told where the control "
		    "sockets are; whether it answers is half the question",
		    iface ? iface : "?");
		return 0;
	}
	if (!ncfg_supplicant_pid_path(run, iface, pid_path, sizeof(pid_path), err, err_size)) {
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
	/* And it has to be usable. See `supplicant.h`: a process carrying the mark
	 * whose socket says nothing is netcfgd's and no use to it, and recording
	 * it would claim a radio netcfgd cannot drive. */
	if (!ncfg_supplicant_answers(dir, iface)) {
		return 1;
	}
	if (!ncfg_backend_join(parent, sizeof(parent), run, "supplicant", err, err_size) ||
	    !ncfg_backend_make_dir(parent, SUPPLICANT_DIR_MODE, err, err_size)) {
		return 0;
	}
	(void)snprintf(text, sizeof(text), "%d\n", (int)pid);
	if (!ncfg_backend_write_file(pid_path, text, strlen(text), 0644, err, err_size)) {
		/* The supplicant is running and netcfgd cannot write down which one.
		 * That is a failure rather than a shrug: the next pass would find no
		 * record, adopt again, and go on adopting for ever. */
		return 0;
	}
	if (pid_out) {
		*pid_out = pid;
	}
	return 1;
}

/* ------------------------------------------------------------------------ *
 * Starting
 * ------------------------------------------------------------------------ */

int ncfg_supplicant_start(const char *run, const char *dir, const char *iface,
    const char *driver, const char *program, char *err, size_t err_size)
{
	char                   pid_path[NCFG_SUPPLICANT_PATH_MAX];
	char                   log[NCFG_SUPPLICANT_PATH_MAX];
	char                   socket_path[NCFG_SUPPLICANT_PATH_MAX];
	char                   parent[NCFG_SUPPLICANT_PATH_MAX];
	char                   said[NCFG_ERROR_MAX];
	ncfg_supplicant_args_t args;
	struct stat            about;
	char                  *found = NULL;
	pid_t                  adopted = 0;
	int                    exited_ok = 0;
	int                    status = 0;

	if (!run || run[0] == '\0' || !dir || dir[0] == '\0' || !iface || iface[0] == '\0') {
		ncfg_error_set(err, err_size,
		    "a supplicant was started without a run directory, a control directory or "
		    "an interface; this build has no default for either path, because a "
		    "default is how a check comes to start one on the machine's own radio");
		return 0;
	}

	/*
	 * **One netcfgd's own record already names is already running**, and
	 * starting a second is the thing this exists to prevent. Asked first
	 * because it is the case a converged machine is in on every reconcile.
	 */
	if (ncfg_supplicant_running_pid(run, iface) > 0) {
		return 1;
	}

	if (!ncfg_supplicant_pid_path(run, iface, pid_path, sizeof(pid_path), err, err_size) ||
	    !ncfg_supplicant_log_path(run, iface, log, sizeof(log), err, err_size) ||
	    !ncfg_backend_join(parent, sizeof(parent), run, "supplicant", err, err_size) ||
	    !ncfg_backend_make_dir(parent, SUPPLICANT_DIR_MODE, err, err_size) ||
	    !ncfg_backend_make_dir(dir, SUPPLICANT_CTRL_DIR_MODE, err, err_size)) {
		return 0;
	}
	if (!socket_path_of(dir, iface, socket_path, sizeof(socket_path))) {
		ncfg_error_set(err, err_size,
		    "the control socket for %s under %s is a longer path than this build will "
		    "name", iface, dir);
		return 0;
	}

	/* A supplicant whose pid file went with the run directory. 0140. */
	if (!ncfg_supplicant_adopt(run, dir, iface, &adopted, err, err_size)) {
		return 0;
	}
	if (adopted > 0) {
		ncfg_log_emitf("supplicant", NCFG_LOG_INFO,
		    "adopted the supplicant already running on %s (pid %d); it is netcfgd's, by "
		    "the `-P %s` it was started with and the privilege it runs with", iface,
		    (int)adopted, pid_path);
		return 1;
	}

	if (lstat(socket_path, &about) == 0) {
		/*
		 * **A socket with no netcfgd pid behind it is not automatically
		 * stale.** It is stale only if nothing answers it. If something does,
		 * another manager is running a supplicant on this radio -- and
		 * removing the file would take away the rendezvous point every one of
		 * its clients uses while leaving the process running, then bind a
		 * second supplicant to the same path. Two supplicants on one radio is
		 * worse than either: the association collapses and the address and the
		 * default route go with it, measured, which is the fault 0140 reports.
		 *
		 * So netcfgd declines the interface and says so, which keeps 0080
		 * intact -- the case 0080 is about is a supplicant that *died*, and a
		 * dead one does not answer, falls through, and is cleared below.
		 */
		if (ncfg_supplicant_answers(dir, iface)) {
			/*
			 * **The message names the test it applied**, which is 0140: the
			 * old one asserted that something else was running a supplicant,
			 * and this one says no process carries the mark -- a claim an
			 * operator can disprove. It names both units for that record's
			 * other reason: on Debian `wpa_supplicant.service` is enabled and
			 * runs independently of NetworkManager, so the old advice left
			 * the socket answering and netcfgd declining.
			 *
			 * The socket's own path is deliberately not in it. `err` is 512
			 * bytes and two absolute paths do not both fit beside this much
			 * prose; the `-P` path is the one that has to be there, because
			 * it is the check that was made.
			 */
			ncfg_error_set(err, err_size,
			    "a supplicant netcfgd did not start is answering on %s, and no "
			    "process on this machine carries `-P %s` -- which is how netcfgd "
			    "marks its own. netcfgd will not take a radio from a manager that "
			    "is still running: stop the other one and it picks the radio up on "
			    "the next reconcile. On Debian that means BOTH `systemctl stop "
			    "NetworkManager` and `systemctl stop wpa_supplicant`, the second "
			    "running on its own. Or set `managed = false` on the device",
			    iface, pid_path);
			return 0;
		}
		/* Removed rather than bound around: the next supplicant would fail to
		 * bind a path that is already there. 0080. */
		(void)unlink(socket_path);
		(void)unlink(pid_path);
	}

	if (!program) {
		found = ncfg_backend_find_program("wpa_supplicant");
		if (!found) {
			ncfg_error_set(err, err_size,
			    "no wpa_supplicant found for %s; a radio and a wired 802.1X port "
			    "both need the wpa_supplicant package. netcfgd does not implement "
			    "one itself (doc/decision/0014)", iface);
			return 0;
		}
		program = found;
	}
	if (!ncfg_supplicant_arguments(program, driver, iface, dir, pid_path, &args, err,
	    err_size)) {
		free(found);
		return 0;
	}
	/* The two streams go to a file rather than a pipe, which is
	 * `ncfg_hostapd_start`'s arrangement: the supplicant closes them when it
	 * daemonises, and a file leaves the reason it would not start somewhere an
	 * operator can read after the fact rather than only in whatever captured
	 * netcfgd's own stderr. */
	if (!ncfg_backend_run(program, args.argv, log, &exited_ok, &status, err, err_size)) {
		free(found);
		return 0;
	}
	free(found);
	if (!exited_ok) {
		/*
		 * `-B` forks only after the interface is initialised and the control
		 * interface is up, so a nonzero exit is a real refusal rather than a
		 * race -- which is what makes this check worth making and is the same
		 * property `backend.stop` relies on when it reads nothing listening as
		 * nothing running.
		 */
		if (ncfg_backend_complaints(log, SUPPLICANT_MARKERS,
		    sizeof(SUPPLICANT_MARKERS) / sizeof(SUPPLICANT_MARKERS[0]), NULL, 0u, 2u,
		    said, sizeof(said))) {
			ncfg_error_set(err, err_size,
			    "wpa_supplicant would not start on %s (driver %s): %s. Its output is "
			    "in %s", iface, driver ? driver : "", said, log);
		} else {
			ncfg_error_set(err, err_size,
			    "wpa_supplicant would not start on %s (driver %s): it exited with "
			    "status %d. Its output is in %s", iface, driver ? driver : "",
			    status, log);
		}
		return 0;
	}
	return 1;
}

/* ------------------------------------------------------------------------ *
 * Stopping
 * ------------------------------------------------------------------------ */

int ncfg_supplicant_stop(const char *run, const char *dir, const char *iface, int patience_ms,
    char *err, size_t err_size)
{
	char                      pid_path[NCFG_SUPPLICANT_PATH_MAX];
	char                      socket_path[NCFG_SUPPLICANT_PATH_MAX];
	char                      detail[NCFG_ERROR_MAX];
	struct stat               about;
	ncfg_supplicant_client_t *client;
	int                       ok = 1;

	if (!run || run[0] == '\0' || !dir || dir[0] == '\0' || !iface || iface[0] == '\0') {
		ncfg_error_set(err, err_size,
		    "a supplicant was stopped without a run directory, a control directory or "
		    "an interface");
		return 0;
	}
	if (!socket_path_of(dir, iface, socket_path, sizeof(socket_path))) {
		ncfg_error_set(err, err_size,
		    "the control socket for %s under %s is a longer path than this build will "
		    "name", iface, dir);
		return 0;
	}
	detail[0] = '\0';
	client = ncfg_supplicant_connect_within(dir, iface,
	    patience_ms > 0 ? patience_ms : NCFG_SUPPLICANT_IMPATIENT_MS, detail, sizeof(detail));
	if (client) {
		ok = ncfg_supplicant_command(client, "TERMINATE", detail, sizeof(detail));
		if (!ok) {
			ncfg_error_set(err, err_size, "could not stop the supplicant on %s: %s",
			    iface, detail);
		}
		ncfg_supplicant_client_free(client);
	} else if (lstat(socket_path, &about) == 0) {
		/*
		 * **Absence is the socket file not being there**, which is the
		 * divergence 0263 records against the access point's stop and is here
		 * for the same reason: `ncfg_supplicant_connect_within` releases the
		 * half-built client before it returns NULL, and that release closes
		 * and unlinks, so `errno` at this call site is the last of those calls
		 * rather than the connect's. A timeout is deliberately not read as
		 * absence -- doing so tells the operator a radio was released while
		 * the supplicant is still on it with its credentials in memory.
		 */
		ok = 0;
		ncfg_error_set(err, err_size,
		    "could not stop the supplicant on %s: its control socket at %s is there "
		    "and did not answer: %s", iface, socket_path, detail);
	}

	/* And the pid file, whether or not it answered. `wpa_supplicant` removes
	 * its own on a clean exit, one that was killed leaves it, and a stale file
	 * would have the next observation asking about a pid that belongs to
	 * somebody else by then (0080). */
	if (ncfg_supplicant_pid_path(run, iface, pid_path, sizeof(pid_path), detail,
	    sizeof(detail))) {
		(void)unlink(pid_path);
	}
	return ok;
}
