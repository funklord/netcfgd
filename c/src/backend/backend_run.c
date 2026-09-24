/*
 * backend_run.c -- the operations the four backends share.
 *
 * See `backend_internal.h` for why these are here rather than in the host
 * module's private header, and why a program is a parameter everywhere.
 */
#include "backend_internal.h"

#include "ncfg/base.h"
#include "ncfg/process.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/*
 * A log a failed daemon wrote. Generous, because openvpn at verb 3 is chatty
 * and the interesting lines are at the top -- and a ceiling at all because
 * this is a file another program appends to for as long as it runs.
 */
#define LOG_CEILING (1024u * 1024u)

int ncfg_backend_join(char *out, size_t out_size, const char *dir, const char *leaf, char *err,
    size_t err_size)
{
	return ncfg_backend_path(out, out_size, dir, NULL, leaf, NULL, err, err_size);
}

int ncfg_backend_path(char *out, size_t out_size, const char *dir, const char *middle,
    const char *leaf, const char *suffix, char *err, size_t err_size)
{
	int written;

	if (!out || out_size == 0u) {
		ncfg_error_set(err, err_size, "a path was asked for with nowhere to put it");
		return 0;
	}
	out[0] = '\0';
	if (!dir || !leaf) {
		ncfg_error_set(err, err_size, "a path was asked for without a directory or a name");
		return 0;
	}
	written = snprintf(out, out_size, "%s%s%s%s%s%s", dir, middle ? "/" : "",
	    middle ? middle : "", "/", leaf, suffix ? suffix : "");
	if (written < 0 || (size_t)written >= out_size) {
		/* **Truncation is a failure and not a shorter path.** Every caller
		 * here is about to write to what comes back, and a path that lost its
		 * last component names a different file -- which under `/run` is
		 * somebody else's. */
		out[0] = '\0';
		ncfg_error_set(err, err_size, "the path under %s is longer than this build will build",
		    dir);
		return 0;
	}
	return 1;
}

int ncfg_backend_make_dir(const char *path, mode_t mode, char *err, size_t err_size)
{
	char   work[1024];
	size_t at;
	size_t length;

	if (!path || path[0] == '\0') {
		ncfg_error_set(err, err_size, "a directory was asked for with no name");
		return 0;
	}
	length = strlen(path);
	if (length + 1u > sizeof(work)) {
		ncfg_error_set(err, err_size, "%s is a longer path than this build will create", path);
		return 0;
	}
	memcpy(work, path, length + 1u);

	for (at = 1u; at <= length; at++) {
		char held;

		if (work[at] != '/' && work[at] != '\0') {
			continue;
		}
		held = work[at];
		work[at] = '\0';
		if (mkdir(work, mode) != 0 && errno != EEXIST) {
			ncfg_error_set(err, err_size, "%s: %s", work, strerror(errno));
			return 0;
		}
		work[at] = held;
	}
	return 1;
}

char *ncfg_backend_read_file(const char *path, size_t *length_out, size_t ceiling)
{
	int    fd;
	char  *bytes;
	size_t filled = 0;

	if (length_out) {
		*length_out = 0;
	}
	if (!path) {
		errno = EINVAL;
		return NULL;
	}
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		return NULL;
	}
	bytes = malloc(ceiling + 1u);
	if (!bytes) {
		int kept = errno;
		(void)close(fd);
		errno = kept;
		return NULL;
	}
	for (;;) {
		ssize_t got = read(fd, bytes + filled, ceiling - filled);

		if (got < 0) {
			int kept = errno;

			if (kept == EINTR) {
				continue;
			}
			free(bytes);
			(void)close(fd);
			errno = kept;
			return NULL;
		}
		if (got == 0) {
			break;
		}
		filled += (size_t)got;
		if (filled >= ceiling) {
			break;
		}
	}
	(void)close(fd);
	bytes[filled] = '\0';
	if (length_out) {
		*length_out = filled;
	}
	return bytes;
}

int ncfg_backend_write_file(const char *path, const void *bytes, size_t length, mode_t mode,
    char *err, size_t err_size)
{
	int         fd;
	const char *at = bytes;
	size_t      left = length;

	if (!path) {
		ncfg_error_set(err, err_size, "a file was written with no name");
		return 0;
	}
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
	if (fd < 0) {
		ncfg_error_set(err, err_size, "cannot write %s: %s", path, strerror(errno));
		return 0;
	}
	/* **Before a byte is written, and on the handle rather than the path.**
	 * `open`'s mode applies only where the call created the file, so a
	 * configuration that already exists keeps the mode it had -- and the one
	 * this matters most for holds a passphrase in the clear. Correcting it on
	 * the path afterwards would leave a window in which anybody could read it,
	 * and a mode that was wrong once is a mode that was wrong. */
	if (fchmod(fd, mode) != 0) {
		ncfg_error_set(err, err_size, "cannot secure %s: %s", path, strerror(errno));
		(void)close(fd);
		return 0;
	}
	while (left > 0u) {
		ssize_t put = write(fd, at, left);

		if (put < 0) {
			if (errno == EINTR) {
				continue;
			}
			ncfg_error_set(err, err_size, "cannot write %s: %s", path, strerror(errno));
			(void)close(fd);
			return 0;
		}
		at += put;
		left -= (size_t)put;
	}
	if (close(fd) != 0) {
		ncfg_error_set(err, err_size, "cannot write %s: %s", path, strerror(errno));
		return 0;
	}
	return 1;
}

int ncfg_backend_run(const char *program, const char *const *argv, const char *log_path,
    int *exited_ok, int *status_out, char *err, size_t err_size)
{
	pid_t child;
	int   log;
	int   status = 0;
	/*
	 * **How the parent learns why the exec failed.** `execv` reports to the
	 * child and the child is about to stop existing, so without this the
	 * parent has only "exited 127" and has to guess -- and it guessed
	 * `ENOENT`, so a program that is there and not executable was reported as
	 * missing. 0182 is the fault: `Permission denied` is two different faults,
	 * a file with no executable bit and a file on a filesystem mounted
	 * `noexec`, and `ncfg_process_exec_refusal` tells them apart. That
	 * function existed, was tested, and had no caller anywhere
	 * (project.md 10.258, 10.267).
	 *
	 * Close-on-exec, so a successful exec closes the write end and the
	 * parent's read gets zero bytes. That is also what separates "could not
	 * become the program" from "the program ran and exited 127", which the
	 * old code could not and reported as the first.
	 */
	int   complaint[2] = { -1, -1 };
	int   failed_to_exec = 0;

	if (exited_ok) {
		*exited_ok = 0;
	}
	if (status_out) {
		*status_out = 0;
	}
	if (!program || !argv) {
		ncfg_error_set(err, err_size, "a program was asked for with no name");
		return 0;
	}
	log = open(log_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (log < 0) {
		ncfg_error_set(err, err_size, "cannot write %s: %s", log_path, strerror(errno));
		return 0;
	}

	/*
	 * `pipe` and then the flag rather than `pipe2`, which this build does not
	 * reach: the tree compiles with `_DEFAULT_SOURCE` and `pipe2` wants
	 * `_GNU_SOURCE`, which is a build-wide change and not this function's to
	 * make. The window between the two calls is a descriptor another thread
	 * could carry through an exec of its own; it is named rather than
	 * ignored, and it is the same window every `open` in this tree avoids by
	 * passing `O_CLOEXEC` outright.
	 */
	if (pipe(complaint) != 0 ||
	    fcntl(complaint[0], F_SETFD, FD_CLOEXEC) != 0 ||
	    fcntl(complaint[1], F_SETFD, FD_CLOEXEC) != 0) {
		ncfg_error_set(err, err_size, "could not make a pipe to run %s: %s", program,
		    strerror(errno));
		if (complaint[0] >= 0) {
			(void)close(complaint[0]);
		}
		if (complaint[1] >= 0) {
			(void)close(complaint[1]);
		}
		(void)close(log);
		return 0;
	}
	child = fork();
	if (child < 0) {
		ncfg_error_set(err, err_size, "could not run %s: %s", program, strerror(errno));
		(void)close(complaint[0]);
		(void)close(complaint[1]);
		(void)close(log);
		return 0;
	}
	if (child == 0) {
		/* **Its own process group, before the exec.** A daemon that fails to
		 * daemonize, or a test's stand-in, must be killable as a group rather
		 * than leaving whatever it spawned attached to netcfgd's. */
		(void)setpgid(0, 0);
		if (dup2(log, STDOUT_FILENO) < 0 || dup2(log, STDERR_FILENO) < 0) {
			_exit(127);
		}
		(void)close(log);
		(void)close(complaint[0]);
		/* The cast is const-correctness only: `execv` does not modify the
		 * vector, and C has no way to say so in the prototype. */
		execv(program, (char *const *)(const void *)argv);
		{
			int why = errno;

			/* Best effort: a parent that is gone leaves nobody to tell, and
			 * the exit status still says the exec did not happen. */
			(void)!write(complaint[1], &why, sizeof(why));
		}
		_exit(127);
	}
	(void)close(log);
	(void)close(complaint[1]);
	{
		int why = 0;

		if (read(complaint[0], &why, sizeof(why)) == (ssize_t)sizeof(why)) {
			failed_to_exec = why;
		}
		(void)close(complaint[0]);
	}
	for (;;) {
		pid_t got = waitpid(child, &status, 0);

		if (got == child) {
			break;
		}
		if (got < 0 && errno == EINTR) {
			continue;
		}
		ncfg_error_set(err, err_size, "could not wait for %s: %s", program, strerror(errno));
		return 0;
	}
	if (status_out) {
		*status_out = status;
	}
	if (failed_to_exec != 0) {
		/*
		 * The child could not become the program at all, which is a different
		 * failure from the program refusing its configuration -- and the one
		 * an operator can do something about immediately. The errno is the
		 * child's own now rather than a guess, so the sentence separates a
		 * missing file from one that is there and will not run.
		 */
		char        why[NCFG_ERROR_MAX];
		/*
		 * **The bare name leads and the path follows.** `program` here is a
		 * resolved path, and the refusal below already names it in full while
		 * saying what is wrong with it -- so leading with the path says it
		 * twice and buries the word an operator is looking for. The Rust
		 * leads with the name because that is all it has; this leads with the
		 * name and keeps the path where it is doing work.
		 */
		const char *slash = strrchr(program, '/');
		const char *named = slash && slash[1] ? slash + 1 : program;

		if (ncfg_process_exec_refusal(program, failed_to_exec, why, sizeof(why))) {
			ncfg_error_set(err, err_size, "could not run %s: %s -- %s", named,
			    strerror(failed_to_exec), why);
		} else {
			ncfg_error_set(err, err_size, "could not run %s: %s", program,
			    strerror(failed_to_exec));
		}
		return 0;
	}
	if (exited_ok) {
		*exited_ok = WIFEXITED(status) && WEXITSTATUS(status) == 0;
	}
	return 1;
}

/* Whether `haystack` holds `needle`, ignoring case in both. */
static int holds_ignoring_case(const char *haystack, const char *needle)
{
	size_t length = strlen(needle);
	size_t at;

	if (length == 0u) {
		return 0;
	}
	for (at = 0u; haystack[at] != '\0'; at++) {
		size_t step;

		for (step = 0u; step < length; step++) {
			int one = tolower((unsigned char)haystack[at + step]);
			int two = tolower((unsigned char)needle[step]);

			if (haystack[at + step] == '\0' || one != two) {
				break;
			}
		}
		if (step == length) {
			return 1;
		}
	}
	return 0;
}

/* Trim ASCII space from both ends, in place, and report the length. */
static size_t trim(char *text)
{
	size_t length = strlen(text);
	size_t start = 0;

	while (length > start && isspace((unsigned char)text[length - 1u])) {
		text[--length] = '\0';
	}
	while (start < length && isspace((unsigned char)text[start])) {
		start++;
	}
	if (start > 0u) {
		memmove(text, text + start, length - start + 1u);
		length -= start;
	}
	return length;
}

int ncfg_backend_complaints(const char *log_path, const char *const *markers, size_t marker_count,
    const char *const *line_prefixes, size_t prefix_count, size_t count, char *out,
    size_t out_size)
{
	char  *text;
	char **lines;
	size_t line_count = 0;
	size_t at;
	size_t taken = 0;
	size_t filled = 0;
	char  *walk;
	char  *saved;

	if (!out || out_size == 0u) {
		return 0;
	}
	out[0] = '\0';
	text = ncfg_backend_read_file(log_path, NULL, LOG_CEILING);
	if (!text) {
		return 0;
	}
	/* One pass to count, one to point: a log is read once and thrown away, so
	 * counting is cheaper than growing an array. */
	for (walk = text; *walk != '\0'; walk++) {
		if (*walk == '\n') {
			line_count++;
		}
	}
	line_count++;
	lines = calloc(line_count, sizeof(*lines));
	if (!lines) {
		free(text);
		return 0;
	}
	line_count = 0;
	walk = text;
	while (walk != NULL && *walk != '\0') {
		saved = strchr(walk, '\n');
		if (saved) {
			*saved = '\0';
		}
		if (trim(walk) > 0u) {
			lines[line_count++] = walk;
		}
		walk = saved ? saved + 1u : NULL;
	}
	if (line_count == 0u) {
		free(lines);
		free(text);
		return 0;
	}

	/* Append one chosen line, joined with `; `. */
#define TAKE(line)                                                                                 \
	do {                                                                                       \
		int put = snprintf(out + filled, out_size - filled, "%s%s",                        \
		    filled > 0u ? "; " : "", (line));                                              \
		if (put < 0 || (size_t)put >= out_size - filled) {                                 \
			break;                                                                     \
		}                                                                                  \
		filled += (size_t)put;                                                             \
		taken++;                                                                           \
	} while (0)

	for (at = 0u; at < line_count && taken < count; at++) {
		size_t which;
		int    telling = 0;

		for (which = 0u; !telling && which < prefix_count; which++) {
			telling = strncmp(lines[at], line_prefixes[which],
			    strlen(line_prefixes[which])) == 0;
		}
		for (which = 0u; !telling && which < marker_count; which++) {
			telling = holds_ignoring_case(lines[at], markers[which]);
		}
		if (telling) {
			TAKE(lines[at]);
		}
	}
	if (taken == 0u) {
		/* Nothing recognisable: the tail, which is at least the most recent
		 * thing the daemon had to say, and better than the exit status alone. */
		at = line_count > count ? line_count - count : 0u;
		for (; at < line_count; at++) {
			TAKE(lines[at]);
		}
	}
#undef TAKE

	/* These lines end in a full stop about half the time and the caller puts
	 * this in the middle of a sentence. Trimmed here, because here is where it
	 * is known the text came from somebody else. */
	while (filled > 0u && out[filled - 1u] == '.') {
		out[--filled] = '\0';
	}
	free(lines);
	free(text);
	return filled > 0u;
}

char *ncfg_backend_strdup(const char *text)
{
	size_t length;
	char  *out;

	if (!text) {
		return NULL;
	}
	length = strlen(text);
	out = malloc(length + 1u);
	if (!out) {
		return NULL;
	}
	memcpy(out, text, length + 1u);
	return out;
}

/*
 * A program by name: `PATH` first, then the places an unprivileged `PATH` does
 * not have.
 *
 * **The order is the whole of this function and it was the wrong way round.**
 * `backend_internal.h` opens by recording what searching `/usr/sbin` first
 * cost the Rust: `tests/live/openvpn.sh` faked the daemon on `PATH` to check
 * the command line netcfgd builds, the search reached the real one first, and
 * 20 of its 45 checks were silently exercising the machine's openvpn (0101).
 * This function reproduced that exactly -- four system directories, then
 * `PATH` -- so every live script that puts a stand-in on `PATH` was answered
 * with the machine's own program instead (project.md 10.267).
 *
 * **And the fallback now applies only where `PATH` cannot answer at all.**
 * The Rust's `which` is `PATH` and nothing else. This port added four system
 * directories for a real reason -- `wpa_supplicant`, `resolvconf` and `tc`
 * live in `/sbin` and `/usr/sbin`, which are on root's `PATH` and not on an
 * ordinary user's -- but consulting them whenever `PATH` comes up empty makes
 * *no client is installed* a state nothing can express: `exec_refused.sh`
 * points `PATH` at an empty directory and netcfgd answered with the machine's
 * own dhcpcd.
 *
 * Nothing reachable needed it. systemd gives a unit with no `Environment=PATH`
 * its own default, which carries all four; root's login `PATH` and sudo's
 * `secure_path` carry them too; and the `live` target appends `/sbin` and
 * `/usr/sbin` for exactly this. What `PATH` genuinely cannot answer is a
 * process started with no environment at all, and that is what is left.
 *
 * A caller that knows which program it wants passes a path instead; every seam
 * under `src/backend/` takes one, which is what this is the fallback for.
 */
char *ncfg_backend_find_program(const char *name)
{
	/* Only what an unprivileged `PATH` is missing. `/usr/bin` is on every
	 * `PATH` there is and is listed because a fallback that has to be
	 * exhaustive is one nobody has to reason about. */
	static const char *const sbin[] = { "/usr/sbin", "/sbin", "/usr/local/sbin", "/usr/bin" };
	char                     path[1024];
	size_t                   at;
	const char              *env;

	if (!name) {
		return NULL;
	}
	env = getenv("PATH");
	while (env != NULL && *env != '\0') {
		const char *end = strchr(env, ':');
		size_t      length = end ? (size_t)(end - env) : strlen(env);
		struct stat about;

		if (length > 0u && length + strlen(name) + 2u < sizeof(path)) {
			memcpy(path, env, length);
			path[length] = '/';
			memcpy(path + length + 1u, name, strlen(name) + 1u);
			if (stat(path, &about) == 0 && S_ISREG(about.st_mode)) {
				return ncfg_backend_strdup(path);
			}
		}
		env = end ? end + 1u : NULL;
	}
	/* A `PATH` that exists and does not hold it is an answer: this machine
	 * does not have it. Only the absence of any `PATH` is a question nobody
	 * has answered. */
	env = getenv("PATH");
	if (env && env[0]) {
		return NULL;
	}
	for (at = 0u; at < sizeof(sbin) / sizeof(sbin[0]); at++) {
		struct stat about;

		if (snprintf(path, sizeof(path), "%s/%s", sbin[at], name) < 0) {
			continue;
		}
		if (stat(path, &about) == 0 && S_ISREG(about.st_mode)) {
			return ncfg_backend_strdup(path);
		}
	}
	return NULL;
}
