/*
 * process.c -- finding, identifying and stopping the processes netcfgd
 * started, as process.h describes.
 *
 * **Everything here reads `/proc` and nothing here trusts it.** A pid file
 * outlives the process it names, pids are recycled, a `/proc` entry vanishes
 * between the scan and the read, and a marker in somebody's `argv` is a claim
 * rather than a fact. So every read is bounded, every parse refuses rather than
 * guesses, and the two identifications -- the whole-argument marker and the
 * owning uid -- are applied together or not at all.
 */
#include "ncfg/process.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/*
 * As much of a `/proc` file as any question here needs.
 *
 * The fields this file reads -- `Uid:` from a status file, a cgroup line --
 * are within the first few hundred bytes of files that are themselves a page
 * or two. A file longer than this is read short, which means a field that was
 * not seen; every caller below treats a field it could not read as "cannot
 * tell", which is the refusing direction for ownership and the conservative one
 * for supervision. A growable buffer would buy nothing and would allocate on a
 * path that runs once per process on the machine.
 */
#define PROC_TEXT_MAX 4096

/* An executable path this will build while searching `PATH`. */
#define CANDIDATE_MAX 4096

/*
 * Read a file whole into `out`, NUL-terminated, or fail.
 *
 * `open`/`read` rather than `fopen`: a `/proc` file reports a size of zero, so
 * anything that sizes a buffer from `stat` reads nothing at all, and stdio
 * buffering adds a second copy for no purpose. `O_CLOEXEC` because this runs in
 * a daemon that spawns backends, and a descriptor leaked into `pppd` is a
 * descriptor `pppd` holds open for the life of the link.
 */
static int read_proc_text(const char *path, char *out, size_t out_size)
{
	int fd;
	size_t filled = 0;

	if (out_size == 0) {
		return 0;
	}
	out[0] = '\0';
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		return 0;
	}
	while (filled + 1 < out_size) {
		ssize_t got = read(fd, out + filled, out_size - filled - 1);

		if (got < 0) {
			if (errno == EINTR) {
				continue;
			}
			(void)close(fd);
			return 0;
		}
		if (got == 0) {
			break;
		}
		filled += (size_t)got;
	}
	out[filled] = '\0';
	(void)close(fd);
	return 1;
}

/*
 * `/proc/<pid>/<leaf>`, or `/proc/self/<leaf>` for a negative pid.
 *
 * One spelling of the path, because the Rust reached these files with a string
 * that was sometimes a number and sometimes the word `self`, and two spellings
 * of that in C is how one of them ends up asking about pid 0.
 */
static int proc_path(char *out, size_t out_size, pid_t pid, const char *leaf)
{
	int written;

	if (pid < 0) {
		written = snprintf(out, out_size, "/proc/self/%s", leaf);
	} else {
		written = snprintf(out, out_size, "/proc/%ld/%s", (long)pid, leaf);
	}
	return written > 0 && (size_t)written < out_size;
}

/* The line beginning with `prefix`, or NULL. */
static const char *line_with_prefix(const char *text, const char *prefix)
{
	size_t length = strlen(prefix);
	const char *at = text;

	while (*at != '\0') {
		if (strncmp(at, prefix, length) == 0) {
			return at + length;
		}
		at = strchr(at, '\n');
		if (!at) {
			break;
		}
		at++;
	}
	return NULL;
}

/* The `count`th whitespace-separated unsigned field of `text`, counting from
 * zero, or a refusal. */
static int field_u32(const char *text, size_t count, uint32_t *out)
{
	const char *at = text;
	size_t seen = 0;

	for (;;) {
		char *end;
		unsigned long value;

		while (*at == ' ' || *at == '\t') {
			at++;
		}
		if (*at == '\0' || *at == '\n') {
			return 0;
		}
		errno = 0;
		value = strtoul(at, &end, 10);
		if (end == at || errno != 0 || value > 0xffffffffUL) {
			return 0;
		}
		if (seen == count) {
			*out = (uint32_t)value;
			return 1;
		}
		seen++;
		at = end;
	}
}

int ncfg_process_uids(pid_t pid, uid_t *real_out, uid_t *effective_out)
{
	char path[64];
	char text[PROC_TEXT_MAX];
	const char *line;
	uint32_t real = 0;
	uint32_t effective = 0;

	if (!proc_path(path, sizeof(path), pid, "status") ||
	    !read_proc_text(path, text, sizeof(text))) {
		return 0;
	}
	line = line_with_prefix(text, "Uid:");
	if (!line || !field_u32(line, 0, &real) || !field_u32(line, 1, &effective)) {
		return 0;
	}
	if (real_out) {
		*real_out = (uid_t)real;
	}
	if (effective_out) {
		*effective_out = (uid_t)effective;
	}
	return 1;
}

/*
 * Whoever is asking.
 *
 * `geteuid` rather than the `Uid:` line the Rust reads for `self`. The reason
 * that line exists is that `stat` on *another* process' `/proc` directory
 * reports the effective uid and lies for a setuid binary; about this process
 * the kernel answers directly and there is nothing to be misled by. One fewer
 * file to be unable to open.
 */
static uid_t my_uid(void)
{
	return geteuid();
}

int ncfg_process_ours(pid_t pid, uid_t asking)
{
	uid_t real = 0;

	if (!ncfg_process_uids(pid, &real, NULL)) {
		return 0;
	}
	return real == 0 || real == asking;
}

/*
 * Whether `/proc/<pid>/cmdline` carries `marker` as a **whole** argument.
 *
 * Streamed rather than read into a buffer, and matched a byte at a time against
 * the marker: a command line can be `ARG_MAX` long, and a fixed buffer would
 * silently stop matching partway through somebody's argv -- which is a miss
 * rather than a false match, but a miss here is netcfgd failing to recognise
 * its own supplicant, which is decision 0140's fault all over again.
 *
 * `alive` is what makes this a whole-argument test: once a byte of the current
 * argument has diverged the argument is out, so neither a proper prefix of the
 * marker nor a longer string containing it can match. `matched == length` is
 * only accepted at an argument boundary.
 */
static int cmdline_has_argument(pid_t pid, const char *marker)
{
	char path[64];
	char chunk[1024];
	size_t length = strlen(marker);
	size_t matched = 0;
	int alive = 1;
	int fd;

	if (length == 0 || !proc_path(path, sizeof(path), pid, "cmdline")) {
		return 0;
	}
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		return 0;
	}
	for (;;) {
		ssize_t got = read(fd, chunk, sizeof(chunk));
		ssize_t i;

		if (got < 0) {
			if (errno == EINTR) {
				continue;
			}
			(void)close(fd);
			return 0;
		}
		if (got == 0) {
			break;
		}
		for (i = 0; i < got; i++) {
			if (chunk[i] == '\0') {
				if (alive && matched == length) {
					(void)close(fd);
					return 1;
				}
				matched = 0;
				alive = 1;
				continue;
			}
			if (!alive) {
				continue;
			}
			if (matched < length && chunk[i] == marker[matched]) {
				matched++;
			} else {
				alive = 0;
			}
		}
	}
	(void)close(fd);
	/* A last argument with no trailing NUL, which the kernel does not write
	 * but a `/proc` replacement in a container might. */
	return alive && matched == length;
}

pid_t ncfg_process_pid_of_as(const char *path, const char *marker, uid_t asking)
{
	char text[64];
	char *end;
	long value;
	pid_t pid;

	if (!path || !marker || !read_proc_text(path, text, sizeof(text))) {
		return 0;
	}
	errno = 0;
	value = strtol(text, &end, 10);
	if (end == text || errno != 0 || value <= 0 || value > 0x7fffffffL) {
		return 0;
	}
	/* The rest of the first line must be blank. A pid file holding `123abc`
	 * is a file somebody else writes in a format this does not know, and
	 * signalling pid 123 on the strength of its first three characters is
	 * exactly the kind of guess this module refuses. */
	while (*end == ' ' || *end == '\t' || *end == '\r') {
		end++;
	}
	if (*end != '\0' && *end != '\n') {
		return 0;
	}
	pid = (pid_t)value;
	if (!cmdline_has_argument(pid, marker) || !ncfg_process_ours(pid, asking)) {
		return 0;
	}
	return pid;
}

pid_t ncfg_process_pid_of(const char *path, const char *marker)
{
	return ncfg_process_pid_of_as(path, marker, my_uid());
}

/* The pid a `/proc` entry names, or 0 for an entry that is not a process. */
static pid_t pid_of_entry(const char *name)
{
	char *end;
	long value;

	if (name[0] < '1' || name[0] > '9') {
		return 0;
	}
	errno = 0;
	value = strtol(name, &end, 10);
	if (*end != '\0' || errno != 0 || value <= 0 || value > 0x7fffffffL) {
		return 0;
	}
	return (pid_t)value;
}

pid_t ncfg_process_pid_by_marker_as(const char *marker, uid_t asking)
{
	DIR *proc;
	struct dirent *entry;
	pid_t found = 0;

	if (!marker || marker[0] == '\0') {
		return 0;
	}
	proc = opendir("/proc");
	if (!proc) {
		return 0;
	}
	while ((entry = readdir(proc)) != NULL) {
		pid_t pid = pid_of_entry(entry->d_name);

		if (pid == 0 || (found != 0 && pid > found)) {
			continue;
		}
		if (cmdline_has_argument(pid, marker) && ncfg_process_ours(pid, asking)) {
			found = pid;
		}
	}
	(void)closedir(proc);
	return found;
}

pid_t ncfg_process_pid_by_marker(const char *marker)
{
	return ncfg_process_pid_by_marker_as(marker, my_uid());
}

int ncfg_process_program_of(pid_t pid, char *name, size_t name_size)
{
	char path[64];
	char text[NCFG_PROGRAM_MAX * 4];
	size_t length;

	if (!name || name_size == 0) {
		return 0;
	}
	name[0] = '\0';
	if (!proc_path(path, sizeof(path), pid, "comm") ||
	    !read_proc_text(path, text, sizeof(text))) {
		return 0;
	}
	length = strlen(text);
	while (length > 0 && text[length - 1] == '\n') {
		length--;
	}
	text[length] = '\0';
	if (length == 0 || length + 1 > name_size) {
		return 0;
	}
	memcpy(name, text, length + 1);
	return 1;
}

size_t ncfg_process_pids_of_programs(const char *const *names, size_t name_count,
    ncfg_process_ref_t *out, size_t out_max)
{
	DIR *proc;
	struct dirent *entry;
	size_t total = 0;
	size_t held = 0;

	if (!names || name_count == 0) {
		return 0;
	}
	proc = opendir("/proc");
	if (!proc) {
		return 0;
	}
	while ((entry = readdir(proc)) != NULL) {
		pid_t pid = pid_of_entry(entry->d_name);
		char program[NCFG_PROGRAM_MAX];
		size_t i;
		size_t at;

		if (pid == 0 || !ncfg_process_program_of(pid, program, sizeof(program))) {
			continue;
		}
		for (i = 0; i < name_count; i++) {
			if (names[i] && strcmp(names[i], program) == 0) {
				break;
			}
		}
		if (i == name_count) {
			continue;
		}
		total++;
		if (!out || out_max == 0) {
			continue;
		}
		/* Kept sorted by insertion, and the *lowest* pids are the ones
		 * kept when there is not room for all of them. An answer cut at
		 * whatever `readdir` happened to return first would differ
		 * between two calls a second apart, which is the property a
		 * caller comparing two sweeps depends on. */
		at = held < out_max ? held : out_max;
		while (at > 0 && out[at - 1].pid > pid) {
			if (at < out_max) {
				out[at] = out[at - 1];
			}
			at--;
		}
		if (at < out_max) {
			out[at].pid = pid;
			memcpy(out[at].program, program, sizeof(program));
		}
		if (held < out_max) {
			held++;
		}
	}
	(void)closedir(proc);
	return total;
}

/* Whether `text` of `length` bytes ends with `suffix`. */
static int ends_with(const char *text, size_t length, const char *suffix)
{
	size_t suffix_length = strlen(suffix);

	return length >= suffix_length &&
	    memcmp(text + length - suffix_length, suffix, suffix_length) == 0;
}

/*
 * The nearest `.service` component of one cgroup line.
 *
 * Walked from the right, because a delegated child sits *below* its unit --
 * `/system.slice/netcfgd.service/something.scope` -- and the last component is
 * then the scope rather than the service.
 */
static int service_in_line(const char *line, size_t length, char *out, size_t out_size)
{
	size_t end = length;

	for (;;) {
		size_t start = end;

		while (start > 0 && line[start - 1] != '/') {
			start--;
		}
		if (ends_with(line + start, end - start, ".service")) {
			size_t size = end - start;

			if (size + 1 > out_size) {
				return 0;
			}
			memcpy(out, line + start, size);
			out[size] = '\0';
			return 1;
		}
		if (start == 0) {
			return 0;
		}
		end = start - 1;
	}
}

int ncfg_process_service_of(pid_t pid, char *unit, size_t unit_size)
{
	char path[64];
	char text[PROC_TEXT_MAX];
	const char *at;

	if (!unit || unit_size == 0) {
		return 0;
	}
	unit[0] = '\0';
	if (!proc_path(path, sizeof(path), pid, "cgroup") ||
	    !read_proc_text(path, text, sizeof(text))) {
		return 0;
	}
	at = text;
	while (*at != '\0') {
		const char *newline = strchr(at, '\n');
		size_t length = newline ? (size_t)(newline - at) : strlen(at);

		if (service_in_line(at, length, unit, unit_size)) {
			return 1;
		}
		if (!newline) {
			break;
		}
		at = newline + 1;
	}
	unit[0] = '\0';
	return 0;
}

int ncfg_process_supervised_by_another(const char *theirs, const char *ours)
{
	return theirs != NULL && (ours == NULL || strcmp(theirs, ours) != 0);
}

int ncfg_process_is_service_supervised(pid_t pid)
{
	char theirs[NCFG_UNIT_MAX];
	char ours[NCFG_UNIT_MAX];
	int have_theirs = ncfg_process_service_of(pid, theirs, sizeof(theirs));
	int have_ours = ncfg_process_service_of(-1, ours, sizeof(ours));

	return ncfg_process_supervised_by_another(have_theirs ? theirs : NULL,
	    have_ours ? ours : NULL);
}

int ncfg_process_in_our_service(pid_t pid)
{
	char theirs[NCFG_UNIT_MAX];
	char ours[NCFG_UNIT_MAX];

	if (!ncfg_process_service_of(-1, ours, sizeof(ours))) {
		return 0;
	}
	if (!ncfg_process_service_of(pid, theirs, sizeof(theirs))) {
		return 0;
	}
	return strcmp(theirs, ours) == 0;
}

int ncfg_process_shares_network_namespace(pid_t pid)
{
	char path[64];
	char mine[128];
	char theirs[128];
	ssize_t got;

	got = readlink("/proc/self/ns/net", mine, sizeof(mine) - 1);
	if (got < 0) {
		return 0;
	}
	mine[got] = '\0';
	if (!proc_path(path, sizeof(path), pid, "ns/net")) {
		return 0;
	}
	got = readlink(path, theirs, sizeof(theirs) - 1);
	if (got < 0) {
		return 0;
	}
	theirs[got] = '\0';
	return strcmp(mine, theirs) == 0;
}

/*
 * The one place a signal is sent, so that the two guards are written once.
 *
 * `group` decides the sign, and the negation is this file's job rather than the
 * caller's: a caller that passes a negative pid to signal a group is a caller
 * one typo away from `-1`, which is every process it may signal.
 */
static int signal_one(pid_t target, int number, int group, int tolerate_gone,
    char *err, size_t err_size)
{
	if (target <= 0) {
		ncfg_error_set(err, err_size, group ?
		    "a process group id must be positive; negating it is this function's job" :
		    "a pid must be positive: 0 and -1 mean process groups");
		return 0;
	}
	if (kill(group ? -target : target, number) == 0) {
		return 1;
	}
	if (errno == ESRCH && tolerate_gone) {
		/* Nothing there to stop, which is what was asked for. */
		return 1;
	}
	ncfg_error_set(err, err_size, "cannot signal %s %ld: %s",
	    group ? "process group" : "process", (long)target, strerror(errno));
	return 0;
}

int ncfg_process_terminate(pid_t pid, char *err, size_t err_size)
{
	return signal_one(pid, SIGTERM, 0, 1, err, err_size);
}

int ncfg_process_kill(pid_t pid, char *err, size_t err_size)
{
	return signal_one(pid, SIGKILL, 0, 1, err, err_size);
}

int ncfg_process_terminate_group(pid_t pgid, char *err, size_t err_size)
{
	return signal_one(pgid, SIGTERM, 1, 1, err, err_size);
}

int ncfg_process_kill_group(pid_t pgid, char *err, size_t err_size)
{
	return signal_one(pgid, SIGKILL, 1, 1, err, err_size);
}

int ncfg_process_hangup(pid_t pid, char *err, size_t err_size)
{
	/* `ESRCH` is *not* success here: a reload asked of a process that is
	 * gone did not happen, and the caller has a document that no longer
	 * matches anything. */
	return signal_one(pid, SIGHUP, 0, 0, err, err_size);
}

int ncfg_process_become(uid_t uid, gid_t gid, const gid_t *groups, size_t group_count)
{
	if (setgroups(group_count, groups) != 0) {
		return 0;
	}
	if (setgid(gid) != 0) {
		return 0;
	}
	if (setuid(uid) != 0) {
		return 0;
	}
	return 1;
}

/* The first `PATH` entry that has `program` in it, as an exec would find it. */
static int along_path(const char *program, char *out, size_t out_size, struct stat *info)
{
	const char *path = getenv("PATH");
	const char *at;

	if (!path) {
		return 0;
	}
	at = path;
	for (;;) {
		const char *colon = strchr(at, ':');
		size_t length = colon ? (size_t)(colon - at) : strlen(at);
		int written;

		/* An empty entry means the current directory, which is what an
		 * exec does with it and what makes it a hazard worth naming
		 * rather than skipping. */
		if (length == 0) {
			written = snprintf(out, out_size, "%s", program);
		} else {
			written = snprintf(out, out_size, "%.*s/%s", (int)length, at, program);
		}
		if (written > 0 && (size_t)written < out_size && stat(out, info) == 0) {
			return 1;
		}
		if (!colon) {
			out[0] = '\0';
			return 0;
		}
		at = colon + 1;
	}
}

int ncfg_process_exec_refusal(const char *program, int error_number, char *text, size_t text_size)
{
	char candidate[CANDIDATE_MAX];
	struct stat info;

	if (text && text_size > 0) {
		text[0] = '\0';
	}
	/* The question is the one `EACCES` raises. `EPERM` reaches a caller as
	 * the same four words -- Rust folds both into `PermissionDenied` -- so
	 * both are taken; any other errno is somebody else's question. */
	if (error_number != EACCES && error_number != EPERM) {
		return 0;
	}
	if (!program || program[0] == '\0' || !text || text_size == 0) {
		return 0;
	}
	if (strchr(program, '/') != NULL) {
		int written = snprintf(candidate, sizeof(candidate), "%s", program);

		if (written < 0 || (size_t)written >= sizeof(candidate) ||
		    stat(candidate, &info) != 0) {
			return 0;
		}
	} else if (!along_path(program, candidate, sizeof(candidate), &info)) {
		return 0;
	}
	if ((info.st_mode & 0111) == 0) {
		ncfg_error_set(text, text_size,
		    "%s is there with mode %04o, which has no executable bit",
		    candidate, (unsigned int)(info.st_mode & 07777));
	} else {
		ncfg_error_set(text, text_size,
		    "%s is there and executable, so the refusal is the filesystem it is on -- "
		    "a `noexec` mount. systemd mounts /run that way by default, and often /tmp",
		    candidate);
	}
	return 1;
}
