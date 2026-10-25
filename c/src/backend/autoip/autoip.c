/*
 * autoip.c -- starting, stopping and recognising netcfgd's IPv4LL client.
 *
 * `autoip.h` carries the whole argument: why a client rather than netcfgd
 * itself, why `dhcpcd` is excluded although it can speak IPv4LL, why
 * `--force-bind` is a correctness requirement rather than a convenience, and
 * how strong the ownership claim is. This file is that decided.
 */
#include "../backend_internal.h"

#include "ncfg/autoip.h"
#include "ncfg/base.h"
#include "ncfg/process.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

/*
 * What the client says when it will not do it.
 *
 * Matched case-insensitively, one line at a time, the way every module here
 * reads a backend's log. `avahi-autoipd` announces a conflict storm and a
 * refusal to bind in prose rather than by status, so the tail is usually right
 * too -- which is `ncfg_backend_complaints`' fall-back.
 */
static const char *const AUTOIP_MARKERS[] = { "error", "cannot", "could not", "failed",
	"no such", "unknown option", "invalid", "not permitted", "usage:", "refus" };

/* How many of those lines a refusal quotes. One is the shape of this tree's
 * other backends and is what fits a journal record. */
#define AUTOIP_COMPLAINT_LINES 1

/*
 * How long a start waits for the client it has just detached to appear, and
 * how often it looks.
 *
 * **The wait exists because the question is asked at the one moment it can be
 * answered wrongly.** This client writes no pid file, so a start that has
 * succeeded is confirmed by finding a process carrying netcfgd's two markers
 * -- and the process netcfgd waited for is not that process. With `-w` a real
 * `avahi-autoipd` holds its detach until an address has been acquired, so its
 * child is long since in place; nothing requires that of a client, and a
 * `cmdline` is briefly empty while a child is in `execve` regardless. Looking
 * once turns either into a start reported as failed while the client runs on,
 * which is the worst answer available here: `--force-bind` means it keeps the
 * address alongside whatever replaced it, and with no pid recorded netcfgd
 * will never stop it. The error says as much in as many words.
 *
 * A second, which is long enough for a child to be scheduled on a loaded
 * machine and short enough that the case this cannot help -- a client that
 * really started nothing, which is what a wrong flag looks like -- still fails
 * promptly. The step is small because the common case returns on the first
 * look and pays nothing.
 */
#define AUTOIP_APPEAR_PATIENCE_MILLISECONDS 1000
#define AUTOIP_APPEAR_STEP_MILLISECONDS 25

/*
 * And the same patience pointed the other way, for the stop.
 *
 * **Without it the stop had a window in which netcfgd adopted the client it
 * had just killed.** `ncfg_autoip_stop` sent `SIGTERM`, removed the pid
 * record and returned; `ncfg_autoip_running_pid` then found no record, fell
 * through to the adoption path below -- which exists for `KillMode=process`
 * leaving a client across a netcfgd stop -- scanned `/proc` by marker, and
 * found the process that had the signal but had not yet exited. So a stop
 * reported success while the next look said a client was running, and a
 * reconcile reading that does nothing: link-local addressing silently absent
 * after a restart.
 *
 * Found as an intermittent in `autoip_test` -- "after which netcfgd has no
 * client on that interface", failing about one run in five -- which is what
 * the race looks like from outside. `dhcp.c`'s `confirm_stopped` is the same
 * shape and the same answer, and is kept rather than re-decided.
 */
#define AUTOIP_EXIT_PATIENCE_MILLISECONDS 1000

int ncfg_autoip_run_dir(const char *run, char *out, size_t out_size, char *err, size_t err_size)
{
	return ncfg_backend_join(out, out_size, run, "autoip", err, err_size);
}

int ncfg_autoip_pid_path(const char *run, const char *iface, char *out, size_t out_size, char *err,
    size_t err_size)
{
	return ncfg_backend_path(out, out_size, run, "autoip", iface, ".pid", err, err_size);
}

int ncfg_autoip_log_path(const char *run, const char *iface, char *out, size_t out_size, char *err,
    size_t err_size)
{
	return ncfg_backend_path(out, out_size, run, "autoip", iface, ".log", err, err_size);
}

/*
 * What says a running client is netcfgd's, for this interface.
 *
 * **Two whole arguments, not one string with a space in it.**
 * `cmdline_has_argument` matches a marker as a complete NUL-delimited
 * argument, deliberately, so that a substring in somebody's `argv` cannot
 * forge one -- and `"--force-bind lan0"` is therefore a marker that can never
 * match anything. Measured the hard way: the first version of this module
 * wrote exactly that and its own test said no client was running.
 *
 * Both are needed and neither alone will do. `--force-bind` is on every client
 * netcfgd starts whichever interface it is for, so searching by it alone could
 * hand a start on one interface the pid of a client on another and then stop
 * the wrong one; the interface name alone is in the command line of anything
 * that mentions it.
 */
static void marker_for(const char *iface, const char *out[2])
{
	out[0] = NCFG_AUTOIP_FORCE_BIND;
	out[1] = iface;
}

/*
 * Wait for a client carrying `marker` to appear, and say which pid it is.
 *
 * `dhcp.c`'s `confirm_stopped` is the same shape pointed the other way -- look,
 * sleep a named step, give up at a named patience -- and is kept rather than
 * re-decided.
 */
static pid_t wait_for_client(const char *const *marker, int patience_ms)
{
	int waited = 0;

	for (;;) {
		struct timespec step;
		pid_t           pid = ncfg_process_pid_by_markers(marker, 2u);

		if (pid > 0) {
			return pid;
		}
		if (waited >= patience_ms) {
			return 0;
		}
		step.tv_sec = 0;
		step.tv_nsec = (long)AUTOIP_APPEAR_STEP_MILLISECONDS * 1000000L;
		(void)nanosleep(&step, NULL);
		waited += AUTOIP_APPEAR_STEP_MILLISECONDS;
	}
}

/*
 * Wait for a signalled client to go, and say whether it did.
 *
 * Asks `/proc` for the pid's own arguments rather than `kill -0`, which
 * `running-code.md` records as a false pass: a reparented process that nothing
 * reaps is a zombie, and `kill -0` calls one alive. The check is the same
 * question `ncfg_process_pid_by_markers` answers -- is a process reciting
 * these arguments still there -- narrowed to the one pid that was signalled,
 * so another client of netcfgd's on another interface cannot hold this open.
 */
static int wait_for_exit(const char *const *marker, pid_t pid, int patience_ms)
{
	int waited = 0;

	for (;;) {
		struct timespec step;

		if (ncfg_process_pid_by_markers(marker, 2u) != pid) {
			return 1;
		}
		if (waited >= patience_ms) {
			return 0;
		}
		step.tv_sec = 0;
		step.tv_nsec = (long)AUTOIP_APPEAR_STEP_MILLISECONDS * 1000000L;
		(void)nanosleep(&step, NULL);
		waited += AUTOIP_APPEAR_STEP_MILLISECONDS;
	}
}

pid_t ncfg_autoip_running_pid(const char *run, const char *iface)
{
	char        pid_path[NCFG_AUTOIP_PATH_MAX];
	char        quiet[NCFG_ERROR_MAX];
	const char *marker[2];
	pid_t       recorded;

	if (!run || !iface) {
		return 0;
	}
	if (!ncfg_autoip_pid_path(run, iface, pid_path, sizeof(pid_path), quiet, sizeof(quiet))) {
		return 0;
	}
	marker_for(iface, marker);
	/* The file says which pid, and `/proc` says whether that pid is still the
	 * process the file names -- both arguments, not just the flag. Asking both is
	 * the whole of the ownership claim: a pid file outlives its process and pids
	 * are recycled. */
	recorded = ncfg_process_pid_of(pid_path, marker[0]);
	if (recorded > 0) {
		return ncfg_process_pid_by_markers(marker, 2u) == recorded ? recorded : 0;
	}
	/*
	 * **No record, so ask the machine** -- which is this module's whole
	 * adoption, and it lives here because `backend_adopt.c` keys on a pid
	 * file the daemon wrote plus a path it recites, and this client has
	 * neither. `KillMode=process` leaves backends running across a netcfgd
	 * stop and the stop takes `/run/netcfgd` with it (0134, 0142), so after
	 * one the record is gone and the client is not. Starting a second would
	 * put two processes probing for the same address.
	 *
	 * The markers are what make the question answerable at all, and they are
	 * the weakest of the ten -- `autoip.h` says so rather than letting this
	 * read as the equal of radvd's.
	 */
	return ncfg_process_pid_by_markers(marker, 2u);
}

int ncfg_autoip_stop(const char *run, const char *iface, char *err, size_t err_size)
{
	char        pid_path[NCFG_AUTOIP_PATH_MAX];
	const char *marker[2];
	pid_t       pid;

	if (!run || !iface) {
		ncfg_error_set(err, err_size,
		    "stopping link-local addressing needs a run directory and an interface");
		return 0;
	}
	marker_for(iface, marker);
	pid = ncfg_autoip_running_pid(run, iface);
	if (pid <= 0) {
		/*
		 * Nothing of netcfgd's is running, which is what this was asked to
		 * produce. **Deliberately not `--kill`**, which would stop whatever
		 * client is on the interface whether netcfgd started it or not; see
		 * `autoip.h`. A stale record is cleared so the next look is cheap.
		 */
		if (ncfg_autoip_pid_path(run, iface, pid_path, sizeof(pid_path), err, err_size)) {
			(void)remove(pid_path);
		}
		return 1;
	}
	if (!ncfg_process_terminate(pid, err, err_size)) {
		return 0;
	}
	/*
	 * **Waited for, and the record kept until it is gone.** The order is the
	 * fix: removing the record first is what let the adoption path below see
	 * the dying client as one to keep, and a stop that returns before the
	 * process has exited is a stop whose next reconcile reads "already
	 * running".
	 */
	if (!wait_for_exit(marker, pid, AUTOIP_EXIT_PATIENCE_MILLISECONDS)) {
		ncfg_error_set(err, err_size,
		    "the link-local client on %s is still running %d ms after SIGTERM, still "
		    "reciting the arguments netcfgd gave it. Its pid record is left in place, so "
		    "the next pass sees the same process rather than adopting it",
		    iface, AUTOIP_EXIT_PATIENCE_MILLISECONDS);
		return 0;
	}
	if (ncfg_autoip_pid_path(run, iface, pid_path, sizeof(pid_path), err, err_size)) {
		(void)remove(pid_path);
	}
	return 1;
}

/* Write down which pid netcfgd started, because the client writes none. */
static int record_pid(const char *run, const char *iface, pid_t pid, char *err, size_t err_size)
{
	char path[NCFG_AUTOIP_PATH_MAX];
	char text[32];
	int  put;

	if (!ncfg_autoip_pid_path(run, iface, path, sizeof(path), err, err_size)) {
		return 0;
	}
	put = snprintf(text, sizeof(text), "%ld\n", (long)pid);
	if (put <= 0 || (size_t)put >= sizeof(text)) {
		ncfg_error_set(err, err_size, "a pid that does not fit in a pid file");
		return 0;
	}
	return ncfg_backend_write_file(path, text, (size_t)put, 0644, err, err_size);
}

int ncfg_autoip_start(const char *run, const char *iface, const char *program, char *err,
    size_t err_size)
{
	char        dir[NCFG_AUTOIP_PATH_MAX];
	char        log[NCFG_AUTOIP_PATH_MAX];
	const char *marker[2];
	char        said[NCFG_ERROR_MAX];
	char       *found = NULL;
	const char *argv[6];
	const char *use;
	pid_t       pid;
	int         exited_ok = 0;
	int         status = 0;
	int         ok;

	if (!run || run[0] == '\0' || !iface || iface[0] == '\0') {
		ncfg_error_set(err, err_size,
		    "link-local addressing was started without a run directory or an "
		    "interface");
		return 0;
	}
	marker_for(iface, marker);
	/*
	 * **Asked before anything is started**, which is 0141's rule one client
	 * over: netcfgd's own already running is the state this produces, and a
	 * second client probing for the same address would fight the first.
	 */
	pid = ncfg_autoip_running_pid(run, iface);
	if (pid > 0) {
		/* Re-recorded rather than merely accepted: the one netcfgd found may
		 * have been adopted from a run directory that is gone, and a stop
		 * later needs the file. Writing it is idempotent. */
		return record_pid(run, iface, pid, err, err_size);
	}
	if (!ncfg_autoip_run_dir(run, dir, sizeof(dir), err, err_size) ||
	    !ncfg_backend_make_dir(dir, 0755, err, err_size) ||
	    !ncfg_autoip_log_path(run, iface, log, sizeof(log), err, err_size)) {
		return 0;
	}
	/*
	 * **An explicit path that is not there reads as "not installed"**, which is
	 * `dhcp.c`'s `program_for` and is kept rather than re-decided: it is what
	 * lets a check say "this machine has no IPv4LL client" by naming a path in
	 * its own directory instead of by having none. The same test either way --
	 * a regular file -- so the two answers cannot disagree about what counts as
	 * installed.
	 */
	if (!program || program[0] == '\0') {
		found = ncfg_backend_find_program(NCFG_AUTOIP_PROGRAM);
		use = found;
	} else {
		struct stat about;

		use = (stat(program, &about) == 0 && S_ISREG(about.st_mode)) ? program : NULL;
	}
	if (!use) {
		/* **The thing looked for, not the conventional name.** An operator who
		 * pointed `NCFG_AVAHI_AUTOIPD` at a path wants to be told that path is
		 * not there; being told `avahi-autoipd` is not installed sends them to
		 * look at a machine that may well have one. */
		ncfg_error_set(err, err_size,
		    "no IPv4LL client found for %s: `%s` is not installed, so a `link-local` "
		    "address cannot be claimed; install avahi-autoipd", iface,
		    (program && program[0]) ? program : NCFG_AUTOIP_PROGRAM);
		return 0;
	}
	/*
	 * `-D -w --force-bind <iface>`, and every one of the four is load-bearing.
	 * `-D` detaches, `-w` holds the detach until an address has been acquired
	 * so the status means something, `--force-bind` is `document.h`'s rule that
	 * link-local coexists with a routable address, and the interface is the one
	 * positional argument this client takes.
	 */
	argv[0] = use;
	argv[1] = "-D";
	argv[2] = "-w";
	argv[3] = NCFG_AUTOIP_FORCE_BIND;
	argv[4] = iface;
	argv[5] = NULL;

	ok = ncfg_backend_run(use, argv, log, &exited_ok, &status, err, err_size);
	if (ok && (!exited_ok || status != 0)) {
		said[0] = '\0';
		if (ncfg_backend_complaints(log, AUTOIP_MARKERS,
		        sizeof(AUTOIP_MARKERS) / sizeof(AUTOIP_MARKERS[0]), NULL, 0,
		        AUTOIP_COMPLAINT_LINES, said, sizeof(said))) {
			ncfg_error_set(err, err_size,
			    "`%s` would not claim a link-local address on %s: %s", NCFG_AUTOIP_PROGRAM,
			    iface, said);
		} else {
			ncfg_error_set(err, err_size,
			    "`%s` exited with %d without claiming a link-local address on %s",
			    NCFG_AUTOIP_PROGRAM, status, iface);
		}
		ok = 0;
	}
	free(found);
	if (!ok) {
		return 0;
	}
	/*
	 * **Found after the start rather than reported by it**, because this client
	 * writes no pid file and `-D` means the process netcfgd waited for is not
	 * the one still running. The marker is what makes the search safe: it is
	 * the argument netcfgd passed, on the interface netcfgd named.
	 *
	 * Waited for rather than looked for once, which the constant above argues.
	 */
	pid = wait_for_client(marker, AUTOIP_APPEAR_PATIENCE_MILLISECONDS);
	if (pid <= 0) {
		ncfg_error_set(err, err_size,
		    "`%s` reported success on %s and no client of netcfgd's was running there "
		    "%d ms later, so netcfgd has nothing it could stop later",
		    NCFG_AUTOIP_PROGRAM, iface, AUTOIP_APPEAR_PATIENCE_MILLISECONDS);
		return 0;
	}
	return record_pid(run, iface, pid, err, err_size);
}
