/*
 * leftovers.c -- reading netcfgd's own control group at startup.
 *
 * The reasoning is in `leftovers.h`. What is here is the gathering, the walk
 * and the wording.
 */
#include "ncfg/leftovers.h"

#include "ncfg/log.h"
#include "ncfg/observed.h"
#include "ncfg/state.h"
#include "ncfg/process.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define LEFTOVER_PATH_MAX 4096u

/*
 * A pid out of a file netcfgd wrote.
 *
 * Deliberately not `ncfg_process_pid_of`, which takes a marker and answers
 * "is the process this file names still the one netcfgd started". That is the
 * right question for adoption and the wrong one here: this wants the number
 * the previous run wrote down, including where the process behind it has gone,
 * because a recorded pid that is absent from the control group is simply not
 * mentioned by anything below.
 */
static int pid_from_file(const char *path, pid_t *out)
{
	FILE *file;
	long  value = 0;
	int   got;

	file = fopen(path, "re");
	if (!file) {
		return 0;
	}
	got = fscanf(file, "%ld", &value);
	(void)fclose(file);
	if (got != 1 || value <= 0 || value > (long)0x7fffffff) {
		return 0;
	}
	*out = (pid_t)value;
	return 1;
}

/* Whether a name ends in `.pid`. */
static int is_pid_file(const char *name)
{
	size_t length = strlen(name);

	return length > 4u && strcmp(name + length - 4u, ".pid") == 0;
}

size_t ncfg_leftovers_recorded_pids(const char *run_dir, pid_t *out, size_t out_max)
{
	DIR           *top;
	struct dirent *entry;
	size_t         total = 0u;

	if (!run_dir) {
		return 0u;
	}
	top = opendir(run_dir);
	if (!top) {
		return 0u;
	}
	/*
	 * One level down, because that is the shape: `<run>/supplicant/wlan0.pid`,
	 * `<run>/dhcpcd/wlan0.pid`, `<run>/openvpn/tun0.pid`. A recursive walk
	 * would be a promise about a layout nobody has made, and this directory is
	 * netcfgd's own -- if a backend ever nests deeper, the gate that notices is
	 * this reporting a process it cannot account for, which is the right
	 * failure rather than a silent one.
	 */
	while ((entry = readdir(top)) != NULL) {
		char           path[LEFTOVER_PATH_MAX];
		DIR           *inner;
		struct dirent *file;

		if (entry->d_name[0] == '.') {
			continue;
		}
		if ((size_t)snprintf(path, sizeof(path), "%s/%s", run_dir, entry->d_name) >=
		    sizeof(path)) {
			continue;
		}
		inner = opendir(path);
		if (!inner) {
			continue;
		}
		while ((file = readdir(inner)) != NULL) {
			char  full[LEFTOVER_PATH_MAX];
			pid_t pid = 0;

			if (file->d_name[0] == '.' || !is_pid_file(file->d_name)) {
				continue;
			}
			if ((size_t)snprintf(full, sizeof(full), "%s/%s", path, file->d_name) >=
			    sizeof(full)) {
				continue;
			}
			if (!pid_from_file(full, &pid)) {
				continue;
			}
			if (out && total < out_max) {
				out[total] = pid;
			}
			total++;
		}
		(void)closedir(inner);
	}
	(void)closedir(top);
	return total;
}

/* A pid from a `/proc` entry name, or 0 for anything that is not one. */
static pid_t pid_of_name(const char *name)
{
	long value;
	char *end = NULL;

	if (name[0] < '1' || name[0] > '9') {
		return 0;
	}
	value = strtol(name, &end, 10);
	if (!end || *end != '\0' || value <= 0) {
		return 0;
	}
	return (pid_t)value;
}

/*
 * A process' command line, NULs turned into spaces.
 *
 * Empty rather than absent on failure, which is the honest reading: a kernel
 * thread has no command line at all, and a process that has gone since the
 * `readdir` has nothing left to read. Both mean "no interface name here", and
 * `is_claimed` treats an empty command as matching nothing.
 */
static void read_command(pid_t pid, char *out, size_t out_size)
{
	char   path[64];
	FILE  *file;
	size_t got;
	size_t at;

	out[0] = '\0';
	if ((size_t)snprintf(path, sizeof(path), "/proc/%d/cmdline", (int)pid) >= sizeof(path)) {
		return;
	}
	file = fopen(path, "re");
	if (!file) {
		return;
	}
	got = fread(out, 1u, out_size - 1u, file);
	(void)fclose(file);
	for (at = 0u; at < got; at++) {
		if (out[at] == '\0') {
			out[at] = ' ';
		}
	}
	out[got] = '\0';
}

size_t ncfg_leftovers_in_our_service(ncfg_leftover_process_t *out, size_t out_max)
{
	DIR           *proc;
	struct dirent *entry;
	size_t         total = 0u;
	pid_t          self = getpid();

	proc = opendir("/proc");
	if (!proc) {
		return 0u;
	}
	while ((entry = readdir(proc)) != NULL) {
		pid_t pid = pid_of_name(entry->d_name);

		if (pid == 0 || pid == self) {
			continue;
		}
		/*
		 * The membership test is `ncfg_process_in_our_service`, which compares
		 * the `.service` unit rather than looking for the word -- the
		 * distinction `process.h` records, and the one that stops this
		 * reporting on every service on the machine.
		 */
		if (!ncfg_process_in_our_service(pid)) {
			continue;
		}
		if (out && total < out_max) {
			out[total].pid = pid;
			out[total].parent = ncfg_process_parent_of(pid);
			read_command(pid, out[total].command, sizeof(out[total].command));
			if (!ncfg_process_program_of(pid, out[total].program,
			        sizeof(out[total].program))) {
				/* A process that went between the readdir and the read. It
				 * was in the control group a moment ago, so it is reported
				 * with what is known rather than dropped: an exiting process
				 * is exactly what a caller is trying to see. */
				(void)snprintf(out[total].program, sizeof(out[total].program), "?");
			}
		}
		total++;
	}
	(void)closedir(proc);
	return total;
}

size_t ncfg_leftovers_claimed_interfaces(const char *run_dir,
    char out[][NCFG_LEFTOVER_IFACE_MAX], size_t out_max)
{
	ncfg_owned_state_t owned;
	char               why[NCFG_ERROR_MAX];
	size_t             at;
	size_t             total = 0u;

	memset(&owned, 0, sizeof(owned));
	why[0] = '\0';
	if (!run_dir || !ncfg_owned_read(run_dir, &owned, why, sizeof(why))) {
		return 0u;
	}
	for (at = 0u; at < owned.backend_count; at++) {
		const ncfg_observed_backend_t *backend = &owned.backends[at];
		size_t                         seen;

		/* `running` is a memory rather than an observation (0078), which is
		 * exactly what is wanted: the question is what the previous run
		 * believed it had left behind. */
		if (!backend->running || !backend->interface) {
			continue;
		}
		if (strlen(backend->interface) + 1u > NCFG_LEFTOVER_IFACE_MAX) {
			/* Skipped rather than truncated: a truncated name matches the
			 * wrong interface by prefix, and this verdict withholds an
			 * alarm. */
			continue;
		}
		/* One entry per name, since several kinds share an interface. */
		for (seen = 0u; seen < total && seen < out_max; seen++) {
			if (strcmp(out[seen], backend->interface) == 0) {
				break;
			}
		}
		if (seen < total && seen < out_max) {
			continue;
		}
		if (out && total < out_max) {
			(void)snprintf(out[total], NCFG_LEFTOVER_IFACE_MAX, "%s",
			    backend->interface);
		}
		total++;
	}
	ncfg_owned_free(&owned);
	return total;
}

/* Whether `pid` is one of the recorded ones. */
static int is_recorded(pid_t pid, const pid_t *recorded, size_t recorded_count)
{
	size_t at;

	for (at = 0u; at < recorded_count; at++) {
		if (recorded[at] == pid) {
			return 1;
		}
	}
	return 0;
}

/* The entry in `found` with this pid, or NULL. */
static const ncfg_leftover_process_t *entry_for(const ncfg_leftover_process_t *found,
    size_t found_count, pid_t pid)
{
	size_t at;

	if (pid <= 0) {
		return NULL;
	}
	for (at = 0u; at < found_count; at++) {
		if (found[at].pid == pid) {
			return &found[at];
		}
	}
	return NULL;
}

/* Whether `command` names `iface` as a whole word.
 *
 * Whole word because interface names nest: `wlan0` is a prefix of `wlan01`, and
 * a substring test would let a claim about one withhold an alarm about the
 * other. The separators are what a command line puts around an argument, plus
 * the `:` and brackets dhcpcd's `setproctitle` uses. */
static int names_interface(const char *command, const char *iface)
{
	size_t      length = strlen(iface);
	const char *at = command;

	if (length == 0u) {
		return 0;
	}
	while ((at = strstr(at, iface)) != NULL) {
		char before = at == command ? ' ' : at[-1];
		char after = at[length];

		if (!(before >= 'a' && before <= 'z') && !(before >= 'A' && before <= 'Z') &&
		    !(before >= '0' && before <= '9') &&
		    !(after >= 'a' && after <= 'z') && !(after >= 'A' && after <= 'Z') &&
		    !(after >= '0' && after <= '9')) {
			return 1;
		}
		at += length;
	}
	return 0;
}

/* Whether the record claims a backend on an interface this process names. */
static int is_claimed(const ncfg_leftover_process_t *process, const char *const *claimed,
    size_t claimed_count)
{
	size_t at;

	if (process->command[0] == '\0') {
		return 0;
	}
	for (at = 0u; at < claimed_count; at++) {
		if (claimed[at] && names_interface(process->command, claimed[at])) {
			return 1;
		}
	}
	return 0;
}

size_t ncfg_leftovers_classify(const ncfg_leftover_process_t *found, size_t found_count,
    const pid_t *recorded, size_t recorded_count, const char *const *claimed,
    size_t claimed_count, ncfg_leftover_finding_t *out, size_t out_max)
{
	size_t at;
	size_t written = 0u;

	if (!found || !out || out_max == 0u) {
		return 0u;
	}
	/*
	 * **Two passes, because a helper's anchor may itself be claimed rather than
	 * recorded.** dhcpcd is exactly that: the client is known only through the
	 * record's claim on its interface, and its three helpers are known only
	 * through the client. A single pass that resolved each process
	 * independently would ask the helpers' own command lines -- and dhcpcd's
	 * `[privileged proxy]` title does not always carry the interface.
	 */
	for (at = 0u; at < found_count && at < out_max; at++) {
		out[at].process = found[at];
		out[at].anchor = 0;
		if (is_recorded(found[at].pid, recorded, recorded_count)) {
			out[at].verdict = NCFG_LEFTOVER_RECORDED;
		} else if (is_claimed(&found[at], claimed, claimed_count)) {
			out[at].verdict = NCFG_LEFTOVER_CLAIMED;
		} else {
			out[at].verdict = NCFG_LEFTOVER_UNACCOUNTED;
		}
		written++;
	}
	for (at = 0u; at < written; at++) {
		pid_t  parent;
		size_t steps;

		if (out[at].verdict != NCFG_LEFTOVER_UNACCOUNTED) {
			continue;
		}
		/*
		 * Upwards, through the control group only. The bound is not defensive
		 * decoration: `parent` comes from `/proc`, and a chain that loops
		 * because two reads caught the table mid-change would otherwise be an
		 * unbounded loop at daemon startup.
		 */
		parent = out[at].process.parent;
		for (steps = 0u; steps < NCFG_LEFTOVER_WALK_MAX; steps++) {
			const ncfg_leftover_process_t *above;
			size_t                         index;

			if (parent <= 0) {
				break;
			}
			if (is_recorded(parent, recorded, recorded_count)) {
				out[at].verdict = NCFG_LEFTOVER_HELPER;
				out[at].anchor = parent;
				break;
			}
			above = entry_for(found, found_count, parent);
			if (!above) {
				/* Outside the control group, so not netcfgd's and not a route
				 * to anything of netcfgd's. See the header: every orphan's
				 * chain reaches pid 1, and following it would judge this
				 * process by whatever pid 1 is. */
				break;
			}
			/* A claimed ancestor anchors just as a recorded one does; that is
			 * what the first pass was for. */
			for (index = 0u; index < written; index++) {
				if (out[index].process.pid == parent &&
				    out[index].verdict == NCFG_LEFTOVER_CLAIMED) {
					out[at].verdict = NCFG_LEFTOVER_HELPER;
					out[at].anchor = parent;
					break;
				}
			}
			if (out[at].verdict == NCFG_LEFTOVER_HELPER) {
				break;
			}
			parent = above->parent;
		}
	}
	return written;
}

/* What to call a verdict in the log. */
static const char *verdict_name(ncfg_leftover_verdict_t verdict)
{
	switch (verdict) {
	case NCFG_LEFTOVER_RECORDED:
		return "recorded by the previous run";
	case NCFG_LEFTOVER_CLAIMED:
		return "a backend the record claims on an interface it names, with no pid "
		       "written down";
	case NCFG_LEFTOVER_HELPER:
		return "a helper of";
	case NCFG_LEFTOVER_UNACCOUNTED:
		break;
	}
	return "accounted for by nothing netcfgd wrote down";
}

void ncfg_leftovers_report(const char *run_dir)
{
	static ncfg_leftover_process_t found[NCFG_LEFTOVER_MAX];
	static ncfg_leftover_finding_t findings[NCFG_LEFTOVER_MAX];
	static pid_t                   recorded[NCFG_LEFTOVER_MAX];
	static char                    claimed[NCFG_LEFTOVER_MAX][NCFG_LEFTOVER_IFACE_MAX];
	static const char             *claimed_names[NCFG_LEFTOVER_MAX];
	size_t                         claimed_count;
	size_t                         found_count;
	size_t                         recorded_count;
	size_t                         count;
	size_t                         at;
	size_t                         unaccounted = 0u;

	/*
	 * `static` rather than automatic: three arrays of 64 is about a kilobyte,
	 * and the daemon's stack is the one this project measures (`make rss`).
	 * Safe because this runs once, from the startup path, before any thread
	 * exists.
	 */
	found_count = ncfg_leftovers_in_our_service(found, NCFG_LEFTOVER_MAX);
	if (found_count == 0u) {
		/* No control group, or an empty one: the ordinary first start, and
		 * every run of the live suite, which is under `unshare`. */
		return;
	}
	recorded_count = ncfg_leftovers_recorded_pids(run_dir, recorded, NCFG_LEFTOVER_MAX);
	claimed_count = ncfg_leftovers_claimed_interfaces(run_dir, claimed, NCFG_LEFTOVER_MAX);
	if (claimed_count > NCFG_LEFTOVER_MAX) {
		claimed_count = NCFG_LEFTOVER_MAX;
	}
	for (at = 0u; at < claimed_count; at++) {
		claimed_names[at] = claimed[at];
	}
	count = ncfg_leftovers_classify(found, found_count < NCFG_LEFTOVER_MAX ? found_count :
	                                                                        NCFG_LEFTOVER_MAX,
	    recorded, recorded_count < NCFG_LEFTOVER_MAX ? recorded_count : NCFG_LEFTOVER_MAX,
	    claimed_names, claimed_count, findings, NCFG_LEFTOVER_MAX);
	for (at = 0u; at < count; at++) {
		if (findings[at].verdict == NCFG_LEFTOVER_UNACCOUNTED) {
			unaccounted++;
		}
	}

	/*
	 * The total first, and it names systemd's message rather than leaving a
	 * reader to connect the two. Somebody reading a journal sees systemd's
	 * "unclean termination of a previous run" immediately above this, and the
	 * whole point of the line is to answer it.
	 */
	/*
	 * **`INFO` for the all-clear and `ERROR` for the finding, and the split is
	 * the whole point of the file.**
	 *
	 * This shipped at `NOTE`, which `ncfg_log_label` renders as `!` -- so the
	 * line saying everything is accounted for arrived looking like a warning,
	 * six times, directly under systemd's warning. That is this file's own
	 * argument used against it: a reader skimming for trouble sees seven
	 * alarming lines where the truth is "nothing here needs you". `INFO` has
	 * no label at all, deliberately, because the ordinary line is a sentence.
	 */
	if (unaccounted == 0u) {
		ncfg_log_emitf("adopt", NCFG_LOG_INFO,
		    "%zu process(es) in netcfgd's control group, all accounted for; systemd "
		    "reports these as left over on every start because `KillMode=process` is "
		    "what keeps the network up across a restart (0134, 0142)",
		    found_count);
	} else {
		ncfg_log_emitf("adopt", NCFG_LOG_ERROR,
		    "%zu process(es) in netcfgd's control group and %zu of them match nothing "
		    "the previous run wrote down, so it did not stop cleanly",
		    found_count, unaccounted);
	}
	for (at = 0u; at < count; at++) {
		const ncfg_leftover_finding_t *finding = &findings[at];

		if (finding->verdict == NCFG_LEFTOVER_HELPER) {
			ncfg_log_emitf("adopt", NCFG_LOG_INFO, "  %s %d, %s pid %d",
			    finding->process.program, (int)finding->process.pid,
			    verdict_name(finding->verdict), (int)finding->anchor);
			continue;
		}
		if (finding->verdict == NCFG_LEFTOVER_CLAIMED ||
		    finding->verdict == NCFG_LEFTOVER_RECORDED) {
			ncfg_log_emitf("adopt", NCFG_LOG_INFO, "  %s %d, %s",
			    finding->process.program, (int)finding->process.pid,
			    verdict_name(finding->verdict));
			continue;
		}
		/*
		 * The one line somebody has to act on, and it says what it does not
		 * know. 0177 is what decides whether such a process is terminated, and
		 * it decides per backend with a marker and a reachability test -- so
		 * this must not read as a verdict that one is about to be reached.
		 */
		ncfg_log_emitf("adopt", NCFG_LOG_ERROR,
		    "  !: %s %d is in netcfgd's control group and is %s; a pass may still adopt "
		    "it by its own mark, and nothing here signals it",
		    finding->process.program, (int)finding->process.pid,
		    verdict_name(finding->verdict));
	}
	if (found_count > count) {
		ncfg_log_emitf("adopt", NCFG_LOG_INFO,
		    "  and %zu more not listed; %u is as many as this reports",
		    found_count - count, (unsigned)NCFG_LEFTOVER_MAX);
	}
}
