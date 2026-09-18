/*
 * resolv_guard.c -- removing what keeps taking `/etc/resolv.conf` back.
 *
 * `daemon.h` carries the whole argument: why this exists, why it is hard to
 * reach, why it cannot tell who wrote the file, and why a supervised process is
 * reported rather than signalled. What is here is the sweep itself, and the one
 * thing worth saying twice is the order of the four exclusions, because each of
 * them was paid for:
 *
 *   1. a pid netcfgd recorded starting, from the backends' pid files;
 *   2. a process in netcfgd's own service, which is how netcfgd finds the
 *      children it has no record of -- dhcpcd writes its pid file to
 *      `/run/dhcpcd/<iface>-4.pid`, where netcfgd does not look, and forks
 *      three helpers that appear in no pid file at all (0198);
 *   3. a process in another network namespace, which is not configuring
 *      netcfgd's interfaces whatever it is called;
 *   4. a process *another* service manager holds up, which is not the same as
 *      any service manager: everything netcfgd starts inherits netcfgd's own
 *      cgroup, so "is in a service" used to answer yes about netcfgd's own
 *      dhcpcd and the sweep declined to signal a process it had started --
 *      leaving in place exactly the interference it exists to remove.
 *
 * The first three are quiet. On a machine running containers the third is most
 * of what the scan finds, and saying so every three reclaims would bury the
 * lines that matter.
 */
#include "ncfg/daemon.h"

#include "ncfg/log.h"
#include "ncfg/process.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

/*
 * Programs known to write `/etc/resolv.conf`.
 *
 * `systemd-resolved` is spelled `systemd-resolve` because `/proc/<pid>/comm` is
 * truncated to fifteen characters; see `ncfg_resolv_writers`.
 */
static const char *const writers[] = {
	"NetworkManager",
	"systemd-resolve",
	"connmand",
	"dhclient",
	"dhcpcd",
	"resolvconf"
};

const char *const *ncfg_resolv_writers(size_t *count_out)
{
	if (count_out) {
		*count_out = sizeof(writers) / sizeof(writers[0]);
	}
	return writers;
}

/* ------------------------------------------------------------------------ *
 * The pids netcfgd knows are its own
 * ------------------------------------------------------------------------ */

/* Keep `pid`, lowest first and without repeats, and answer the new total. */
static size_t remember(pid_t pid, pid_t *out, size_t out_max, size_t total)
{
	size_t kept = total < out_max ? total : out_max;
	size_t at;
	size_t i;

	for (at = 0; at < kept; at++) {
		if (out[at] == pid) {
			return total;
		}
	}
	/* Sorted, so that overflowing keeps the lowest rather than the first ones
	 * `readdir` happened to hand over. The order is not what makes the answer
	 * right -- the caller refuses to sweep at all when the set did not fit --
	 * but an answer that depends on directory order is one nobody can
	 * reproduce. */
	for (at = 0; at < kept && out[at] < pid; at++) {
	}
	for (i = kept; i > at; i--) {
		if (i < out_max) {
			out[i] = out[i - 1u];
		}
	}
	if (at < out_max) {
		out[at] = pid;
	}
	return total + 1u;
}

/* The number in a pid file, or 0 for anything this cannot vouch for. */
static pid_t pid_in_file(const char *path)
{
	FILE         *file = fopen(path, "r");
	char          line[64];
	char         *end = NULL;
	long          value;
	const char   *at;

	if (!file) {
		return 0;
	}
	if (!fgets(line, sizeof(line), file)) {
		(void)fclose(file);
		return 0;
	}
	(void)fclose(file);
	line[strcspn(line, "\r\n")] = '\0';
	for (at = line; *at == ' ' || *at == '\t'; at++) {
	}
	value = strtol(at, &end, 10);
	/*
	 * Strict on purpose: the cost of missing one of netcfgd's own pids is
	 * signalling something netcfgd started, so a file that cannot be read or
	 * does not hold a number is skipped rather than guessed at.
	 */
	if (end == at || value <= 0 || value > (long)0x7fffffff) {
		return 0;
	}
	while (*end == ' ' || *end == '\t') {
		end++;
	}
	if (*end != '\0') {
		return 0;
	}
	return (pid_t)value;
}

/* Whether a name ends in `.pid`. */
static int is_pid_file(const char *name)
{
	size_t length = strlen(name);

	return length > 4u && strcmp(name + length - 4u, ".pid") == 0;
}

size_t ncfg_resolv_ours(const char *run_dir, pid_t *out, size_t out_max)
{
	DIR    *kinds;
	size_t  total = 0u;

	if (!out) {
		out_max = 0u;
	}
	/*
	 * Own pid first: netcfgd is not called any of the writer names, but a
	 * future rename should not be able to make it kill itself.
	 */
	total = remember(getpid(), out, out_max, total);
	if (!run_dir) {
		return total;
	}
	kinds = opendir(run_dir);
	if (!kinds) {
		return total;
	}
	/*
	 * The backends write `<run>/<kind>/<iface>.pid`, one directory down, so
	 * this walk is exactly two levels and is not a recursion. Nothing here
	 * follows a symlink into a third.
	 */
	for (;;) {
		const struct dirent *kind = readdir(kinds);
		char                 directory[NCFG_CONFIRM_PATH_MAX];
		DIR                 *entries;
		int                  written;

		if (!kind) {
			break;
		}
		if (strcmp(kind->d_name, ".") == 0 || strcmp(kind->d_name, "..") == 0) {
			continue;
		}
		written = snprintf(directory, sizeof(directory), "%s/%s", run_dir, kind->d_name);
		if (written < 0 || (size_t)written >= sizeof(directory)) {
			continue;
		}
		entries = opendir(directory);
		if (!entries) {
			continue;
		}
		for (;;) {
			const struct dirent *entry = readdir(entries);
			char                 path[NCFG_CONFIRM_PATH_MAX];
			pid_t                pid;

			if (!entry) {
				break;
			}
			if (!is_pid_file(entry->d_name)) {
				continue;
			}
			written = snprintf(path, sizeof(path), "%s/%s", directory, entry->d_name);
			if (written < 0 || (size_t)written >= sizeof(path)) {
				continue;
			}
			pid = pid_in_file(path);
			if (pid > 0) {
				total = remember(pid, out, out_max, total);
			}
		}
		(void)closedir(entries);
	}
	(void)closedir(kinds);
	return total;
}

/* ------------------------------------------------------------------------ *
 * The real machine
 * ------------------------------------------------------------------------ */

static size_t real_candidates(void *state, ncfg_process_ref_t *out, size_t out_max)
{
	size_t count = 0u;
	const char *const *names = ncfg_resolv_writers(&count);

	(void)state;
	return ncfg_process_pids_of_programs(names, count, out, out_max);
}

static int real_in_our_service(void *state, pid_t pid)
{
	(void)state;
	return ncfg_process_in_our_service(pid);
}

static int real_shares_network_namespace(void *state, pid_t pid)
{
	(void)state;
	return ncfg_process_shares_network_namespace(pid);
}

static int real_is_service_supervised(void *state, pid_t pid)
{
	(void)state;
	return ncfg_process_is_service_supervised(pid);
}

static int real_terminate(void *state, pid_t pid, char *err, size_t err_size)
{
	(void)state;
	return ncfg_process_terminate(pid, err, err_size);
}

ncfg_resolv_machine_t ncfg_resolv_machine_default(void)
{
	ncfg_resolv_machine_t machine;

	machine.state = NULL;
	machine.candidates = real_candidates;
	machine.in_our_service = real_in_our_service;
	machine.shares_network_namespace = real_shares_network_namespace;
	machine.is_service_supervised = real_is_service_supervised;
	machine.terminate = real_terminate;
	return machine;
}

/* ------------------------------------------------------------------------ *
 * The sweep
 * ------------------------------------------------------------------------ */

static int is_ours(const pid_t *ours, size_t count, pid_t pid)
{
	size_t at;

	for (at = 0; at < count; at++) {
		if (ours[at] == pid) {
			return 1;
		}
	}
	return 0;
}

size_t ncfg_resolv_sweep(const char *run_dir, const ncfg_resolv_machine_t *machine)
{
	pid_t              ours[NCFG_RESOLV_OURS_MAX];
	ncfg_process_ref_t found[NCFG_RESOLV_CANDIDATES_MAX];
	size_t             our_total;
	size_t             found_total;
	size_t             looked_at;
	size_t             at;
	size_t             signalled = 0u;

	if (!machine || !machine->candidates || !machine->in_our_service ||
	    !machine->shares_network_namespace || !machine->is_service_supervised ||
	    !machine->terminate) {
		/* The one place in this library where an incomplete argument means do
		 * nothing rather than fail: what this call does is send signals, and a
		 * caller that has not said which machine has not asked for that. */
		return 0u;
	}
	our_total = ncfg_resolv_ours(run_dir, ours, sizeof(ours) / sizeof(ours[0]));
	if (our_total > sizeof(ours) / sizeof(ours[0])) {
		/*
		 * **Fail closed.** A pid of netcfgd's own that did not fit would look
		 * foreign, and terminating the DHCP client holding this machine's
		 * lease is the worst outcome available.
		 */
		ncfg_log_emitf("resolv", NCFG_LOG_ERROR,
		    "netcfgd has started %lu processes, more than the %d this sweep can account "
		    "for, so nothing will be signalled", (unsigned long)our_total,
		    (int)NCFG_RESOLV_OURS_MAX);
		return 0u;
	}
	found_total = machine->candidates(machine->state, found,
	    sizeof(found) / sizeof(found[0]));
	looked_at = found_total < sizeof(found) / sizeof(found[0])
	    ? found_total
	    : sizeof(found) / sizeof(found[0]);
	if (found_total > looked_at) {
		ncfg_log_emitf("resolv", NCFG_LOG_WARNING,
		    "%lu programs known to write resolv.conf are running and this sweep looks at "
		    "%lu of them", (unsigned long)found_total, (unsigned long)looked_at);
	}

	for (at = 0; at < looked_at; at++) {
		pid_t       pid = found[at].pid;
		const char *program = found[at].program;
		char        why[NCFG_ERROR_MAX];

		/* Not a diagnostic anybody needs on every pass: netcfgd's own dhcpcd
		 * is on the list by construction and is not interference. */
		if (is_ours(ours, our_total, pid)) {
			continue;
		}
		if (machine->in_our_service(machine->state, pid)) {
			continue;
		}
		if (!machine->shares_network_namespace(machine->state, pid)) {
			continue;
		}
		if (machine->is_service_supervised(machine->state, pid)) {
			ncfg_log_emitf("resolv", NCFG_LOG_WARNING,
			    "%s (pid %ld) keeps rewriting resolv.conf and another service manager "
			    "restarts it, so netcfgd is not signalling it. A killed service comes "
			    "straight back; stand it down with Conflicts= -- see "
			    "packaging/systemd/netcfgd-exclusive.conf", program, (long)pid);
			continue;
		}
		why[0] = '\0';
		if (machine->terminate(machine->state, pid, why, sizeof(why))) {
			ncfg_log_emitf("resolv", NCFG_LOG_WARNING,
			    "terminated %s (pid %ld): it took /etc/resolv.conf back %d times "
			    "running and netcfgd owns that file", program, (long)pid,
			    (int)NCFG_RESOLV_PATIENCE);
			signalled++;
		} else {
			ncfg_log_emitf("resolv", NCFG_LOG_ERROR, "could not terminate %s (pid %ld): %s",
			    program, (long)pid, why);
		}
	}

	if (signalled == 0u) {
		ncfg_log_emitf("resolv", NCFG_LOG_WARNING,
		    "resolv.conf has been taken back %d times and netcfgd found nothing it could "
		    "signal", (int)NCFG_RESOLV_PATIENCE);
	}
	return signalled;
}
