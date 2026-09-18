/*
 * probe.c -- asking an uplink whether it actually carries traffic (0119).
 *
 * A probe runs a program the operator named and takes its exit status as the
 * answer. The verdict joins observed state beside carrier, where the planner
 * already knows what to do with a link that is not carrying anything -- and it
 * is kept here rather than in the observation, because `reobserve` builds a
 * fresh one every tick and a verdict written into one would be gone on the
 * next.
 *
 * WHAT THIS FILE SPAWNS, AND WHAT STOPS IT
 *   One child per due probe, in its own process group, with a deadline taken
 *   from `CLOCK_MONOTONIC` before the fork. There is no loop that spawns, no
 *   recursion and no path that leaves a process behind: at the deadline the
 *   whole *group* gets `SIGTERM`, then `SIGKILL` after a grace period, and the
 *   child is reaped before this returns. The group and not the child, because
 *   a probe is usually a script and the `curl` it started is a grandchild --
 *   signalling only the shell leaves the grandchild running and reparented to
 *   init, with the daemon no longer waiting for work that is still happening.
 *
 *   Every read of the child's standard error is bounded too, twice over: at
 *   most `DRAIN_READS` reads before the deadline is looked at again, and at
 *   most `FINAL_DRAINS` rounds of those once the child has been reaped. A
 *   program writing without end cannot hold this loop.
 *
 * WHY THE STANDARD ERROR IS DRAINED WHILE THE PROGRAM RUNS
 *   **The Rust reads it only after the child has exited**, which is a deadlock
 *   on any probe that says more than a pipe buffer holds: the child blocks in
 *   `write`, never exits, the deadline passes, and a link that works is
 *   reported as "no answer within 5s, so it was killed" and loses its routes.
 *   See the divergence list in 0263. Here the pipe is drained in the same loop
 *   that watches the clock, and only the tail is kept -- `NCFG_PROBE_DETAIL_MAX`
 *   of it reaches a client, so holding more than a window of it would be
 *   buying an allocation with somebody else's `echo`.
 */
#include "ncfg/daemon.h"

#include "ncfg/process.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* How often the wait wakes to look. Small enough not to add meaningfully to a
 * probe's runtime, large enough not to spin. `apply/hook.c`'s number, for the
 * same wait. */
#define POLL_MILLISECONDS 20

/* How long a killed probe gets between `SIGTERM` and `SIGKILL`. */
#define GRACE_SECONDS 5

/*
 * How much of the standard error is held while the program runs.
 *
 * Ten times what any client is shown, so that the *last non-empty line* rule
 * still has something to choose from when a program signs off with a blank
 * line or two -- and small enough that a probe printing a megabyte costs
 * nothing but the reads.
 */
#define STDERR_KEEP 4096

/* How many reads one drain does before the deadline is looked at again. */
#define DRAIN_READS 16

/* How many drains happen after the child has been reaped. Bounds what a
 * grandchild still holding the pipe open can make this read: at most
 * `FINAL_DRAINS * DRAIN_READS` reads, and then it stops whatever is arriving. */
#define FINAL_DRAINS 64

/* One read's worth. */
#define DRAIN_CHUNK 1024

/* What one interface's probe has been saying. */
typedef struct {
	char          *name;
	/* Consecutive results in the current direction. */
	uint32_t       successes;
	uint32_t       failures;
	/*
	 * What netcfgd currently believes, once enough results agree.
	 *
	 * Absent until the first run finishes, which is why an interface that has
	 * just been configured keeps its routes rather than losing them for the
	 * length of one interval.
	 */
	ncfg_optbool_t verdict;
	/* When to run again, in the scheduling clock's milliseconds. */
	int            due_set;
	int64_t        due;
	/* The earliest the verdict may change again, where a dwell is configured. */
	int            settled_set;
	int64_t        settled_until;
	/*
	 * Consecutive failures to *start* the program.
	 *
	 * Separate from `failures`, which counts a program that ran and said no.
	 * The two mean different things and only one of them is about the link.
	 */
	uint32_t       start_failures;
	/* Set aside: the program could not be started enough times running that
	 * asking again is not going to help. */
	int            set_aside;
	/* What the program last said, or why it was set aside. Owned. */
	char          *detail;
} tally_t;

struct ncfg_probes {
	/* Sorted by name, which is what makes `failing` answer in a stable order
	 * without sorting anything at the moment it is asked. */
	tally_t             *at;
	size_t               count;
	size_t               capacity;
	ncfg_probes_clock_fn clock;
	void                *clock_context;
};

/* What one run of a probe did. */
typedef struct {
	/* Whether the program ran and exited zero. */
	int   ok;
	/* Whether it ran at all. A program that could not be started says nothing
	 * about the link, which is a different fact from one that ran and failed. */
	int   started;
	/* Its standard error, tail-trimmed, or the reason it could not be run.
	 * Owned, and NULL where there was nothing to say. */
	char *detail;
} outcome_t;

/* ------------------------------------------------------------------------ *
 * Small things
 * ------------------------------------------------------------------------ */

/* A copy of `text`, or NULL. */
static char *duplicate(const char *text)
{
	size_t length;
	char  *copy;

	if (!text) {
		return NULL;
	}
	length = strlen(text) + 1u;
	copy = malloc(length);
	if (copy) {
		memcpy(copy, text, length);
	}
	return copy;
}

/* A formatted sentence, allocated. NULL where memory ran out. */
static char *sentence(const char *format, ...)
{
	char    text[NCFG_ERROR_MAX];
	va_list args;

	va_start(args, format);
	(void)vsnprintf(text, sizeof(text), format, args);
	va_end(args);
	return duplicate(text);
}

/* `CLOCK_MONOTONIC` in milliseconds. **Not the scheduling clock**: this is
 * what a running child is killed by, and a clock a test can freeze would be a
 * wait that never ends. */
static int64_t monotonic_milliseconds(void)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
		return 0;
	}
	return (int64_t)now.tv_sec * 1000 + (int64_t)(now.tv_nsec / 1000000L);
}

/* Now, as the scheduling half reckons it. */
static int64_t scheduled_now(const ncfg_probes_t *probes)
{
	if (probes->clock) {
		return probes->clock(probes->clock_context);
	}
	return monotonic_milliseconds();
}

/* Sleep for a bounded number of milliseconds. */
static void rest(long milliseconds)
{
	struct timespec wait;

	wait.tv_sec = milliseconds / 1000L;
	wait.tv_nsec = (milliseconds % 1000L) * 1000000L;
	(void)nanosleep(&wait, NULL);
}

/* One more, and never past the top. A counter that wrapped would take a probe
 * that has failed four billion times back to "no evidence yet". */
static uint32_t one_more(uint32_t count)
{
	return count == UINT32_MAX ? count : count + 1u;
}

/* Whether the document asks this interface for DHCP.
 *
 * The precondition hangs on this: a statically addressed interface has no
 * lease to wait for, and requiring one would take its routes away and never
 * give them back. */
static int wants_dhcp(const ncfg_interface_t *interface)
{
	size_t i;

	for (i = 0; i < interface->addressing_count; i++) {
		int kind = interface->addressing[i].kind;

		if (kind == NCFG_ADDRESS_SOURCE_DHCP4 || kind == NCFG_ADDRESS_SOURCE_DHCP6) {
			return 1;
		}
	}
	return 0;
}

/* ------------------------------------------------------------------------ *
 * The tallies
 * ------------------------------------------------------------------------ */

static void tally_release(tally_t *tally)
{
	free(tally->name);
	free(tally->detail);
	memset(tally, 0, sizeof(*tally));
}

static void tallies_clear(ncfg_probes_t *probes)
{
	size_t i;

	for (i = 0; i < probes->count; i++) {
		tally_release(&probes->at[i]);
	}
	probes->count = 0;
}

/* Where `name` is, or would be. `*found` says which. */
static size_t tally_place(const ncfg_probes_t *probes, const char *name, int *found)
{
	size_t at;

	*found = 0;
	for (at = 0; at < probes->count; at++) {
		int order = strcmp(probes->at[at].name, name);

		if (order == 0) {
			*found = 1;
			return at;
		}
		if (order > 0) {
			return at;
		}
	}
	return probes->count;
}

static tally_t *tally_find(const ncfg_probes_t *probes, const char *name)
{
	int    found;
	size_t at;

	if (!probes || !name) {
		return NULL;
	}
	at = tally_place(probes, name, &found);
	return found ? (tally_t *)&probes->at[at] : NULL;
}

/* The tally for `name`, made if it is not there. NULL with a sentence only
 * where memory ran out. */
static tally_t *tally_for(ncfg_probes_t *probes, const char *name, char *err, size_t err_size)
{
	int    found;
	size_t at = tally_place(probes, name, &found);
	char  *copy;

	if (found) {
		return &probes->at[at];
	}
	if (probes->count == probes->capacity) {
		size_t   want = probes->capacity ? probes->capacity * 2u : 4u;
		tally_t *grown = realloc(probes->at, want * sizeof(*grown));

		if (!grown) {
			ncfg_error_set(err, err_size, "there was no memory for a probe's tally");
			return NULL;
		}
		probes->at = grown;
		probes->capacity = want;
	}
	copy = duplicate(name);
	if (!copy) {
		ncfg_error_set(err, err_size, "there was no memory for a probe's tally");
		return NULL;
	}
	memmove(&probes->at[at + 1u], &probes->at[at], (probes->count - at) * sizeof(*probes->at));
	memset(&probes->at[at], 0, sizeof(probes->at[at]));
	probes->at[at].name = copy;
	probes->count++;
	return &probes->at[at];
}

static void tally_remove(ncfg_probes_t *probes, size_t at)
{
	tally_release(&probes->at[at]);
	memmove(&probes->at[at], &probes->at[at + 1u],
	    (probes->count - at - 1u) * sizeof(*probes->at));
	probes->count--;
}

/* ------------------------------------------------------------------------ *
 * The detail
 * ------------------------------------------------------------------------ */

/* Whether this byte is one the trimming treats as space. */
static int blank(char one)
{
	return one == ' ' || one == '\t' || one == '\r' || one == '\n' || one == '\f' ||
	    one == '\v';
}

/*
 * The last non-empty line, tail-trimmed to `NCFG_PROBE_DETAIL_MAX` bytes.
 *
 * The last line rather than the first: a program that printed a banner and
 * then an error should report the error. The *tail* of that line rather than
 * its head, for the same reason -- and the cut is moved forward off any UTF-8
 * continuation byte, so what comes back is still text rather than the second
 * half of a character.
 *
 * NULL where there is nothing to say, and also where memory ran out: a missing
 * explanation is not a failure of the probe, and the verdict is the part that
 * matters.
 */
static char *trim_detail(const char *text, size_t length)
{
	size_t end = length;
	size_t start;
	size_t width;
	size_t cut;
	char  *held;

	while (end > 0u && blank(text[end - 1u])) {
		end--;
	}
	if (end == 0u) {
		return NULL;
	}
	start = end;
	while (start > 0u && text[start - 1u] != '\n') {
		start--;
	}
	while (start < end && blank(text[start])) {
		start++;
	}
	width = end - start;
	if (width <= (size_t)NCFG_PROBE_DETAIL_MAX) {
		held = malloc(width + 1u);
		if (!held) {
			return NULL;
		}
		memcpy(held, text + start, width);
		held[width] = '\0';
		return held;
	}
	cut = start + (width - (size_t)NCFG_PROBE_DETAIL_MAX);
	while (cut < end && ((unsigned char)text[cut] & 0xC0u) == 0x80u) {
		cut++;
	}
	held = malloc((end - cut) + 4u);
	if (!held) {
		return NULL;
	}
	held[0] = '.';
	held[1] = '.';
	held[2] = '.';
	memcpy(held + 3, text + cut, end - cut);
	held[(end - cut) + 3u] = '\0';
	return held;
}

/*
 * Keep the last `STDERR_KEEP` bytes of everything written so far.
 *
 * One chunk always fits in the window, which is what lets this shift rather
 * than having a second path for a chunk larger than the window -- a path
 * nothing could reach and nothing would test. The assertion is what keeps that
 * true if either number is ever changed.
 */
_Static_assert(DRAIN_CHUNK <= STDERR_KEEP, "a drain's chunk has to fit in the window");

static void keep_tail(char *window, size_t *held, const char *bytes, size_t length)
{
	if (*held + length > (size_t)STDERR_KEEP) {
		size_t drop = (*held + length) - (size_t)STDERR_KEEP;

		memmove(window, window + drop, *held - drop);
		*held -= drop;
	}
	memcpy(window + *held, bytes, length);
	*held += length;
}

/* What one drain found. */
typedef enum {
	/* End of file, or a pipe that is no use: stop reading it. */
	DRAIN_DONE = 0,
	/* Bytes arrived, and more may be waiting. */
	DRAIN_MORE,
	/* Nothing waiting just now. */
	DRAIN_IDLE
} drain_t;

/* Read what is waiting, bounded by `DRAIN_READS`, keeping the tail. */
static drain_t drain(int fd, char *window, size_t *held)
{
	unsigned attempt;

	for (attempt = 0; attempt < (unsigned)DRAIN_READS; attempt++) {
		char    chunk[DRAIN_CHUNK];
		ssize_t got = read(fd, chunk, sizeof(chunk));

		if (got > 0) {
			keep_tail(window, held, chunk, (size_t)got);
			continue;
		}
		if (got == 0) {
			return DRAIN_DONE;
		}
		if (errno == EINTR) {
			continue;
		}
		return errno == EAGAIN ? DRAIN_IDLE : DRAIN_DONE;
	}
	return DRAIN_MORE;
}

/* ------------------------------------------------------------------------ *
 * Running one
 * ------------------------------------------------------------------------ */

/*
 * The argument vector, `command` first. NULL where memory ran out.
 *
 * The strings are the document's and are not copied; `execv` takes a mutable
 * vector and never writes through it, which is what the cast costs under
 * `-Wwrite-strings`.
 */
static char **argument_vector(const ncfg_probe_policy_t *policy)
{
	char **argv = calloc(policy->arg_count + 2u, sizeof(*argv));
	size_t i;

	if (!argv) {
		return NULL;
	}
	argv[0] = (char *)(uintptr_t)(const void *)policy->command;
	for (i = 0; i < policy->arg_count; i++) {
		argv[i + 1u] = (char *)(uintptr_t)(const void *)policy->args[i];
	}
	return argv;
}

/*
 * Start the program, or say why not.
 *
 * The child's `execv` failure comes back through a close-on-exec pipe, which
 * is the only way the parent can tell "started and exited 127" from "never
 * started": both leave a child that is gone by the time it is waited for, and
 * the difference decides whether the probe is set aside or the link is judged
 * down.
 */
static pid_t spawn(const char *command, char **argv, int said_write, int *exec_errno)
{
	int   report[2];
	pid_t child;
	int   got = 0;

	*exec_errno = 0;
	if (pipe(report) != 0) {
		return -1;
	}
	if (fcntl(report[1], F_SETFD, FD_CLOEXEC) != 0) {
		(void)close(report[0]);
		(void)close(report[1]);
		return -1;
	}
	child = fork();
	if (child < 0) {
		(void)close(report[0]);
		(void)close(report[1]);
		return -1;
	}
	if (child == 0) {
		int null = open("/dev/null", O_RDWR);

		/* Its own process group, so that killing it kills what it started. */
		(void)setpgid(0, 0);
		(void)close(report[0]);
		if (null >= 0) {
			/* Standard input is `/dev/null` so a program waiting to be typed
			 * at fails rather than holding the daemon, and standard output
			 * goes there because the exit status is the answer and nothing
			 * reads what it prints. */
			(void)dup2(null, STDIN_FILENO);
			(void)dup2(null, STDOUT_FILENO);
			if (null > STDERR_FILENO) {
				(void)close(null);
			}
		}
		if (dup2(said_write, STDERR_FILENO) < 0) {
			_exit(127);
		}
		if (said_write > STDERR_FILENO) {
			(void)close(said_write);
		}
		(void)execv(command, argv);
		got = errno;
		/* A short write is as good as none: the parent treats anything but a
		 * whole int as "it started". */
		(void)write(report[1], &got, sizeof(got));
		_exit(127);
	}
	(void)close(report[1]);
	/*
	 * The parent sets the group too. Whichever of the two runs first wins and
	 * the other is a no-op -- doing it in one place only is the classic race,
	 * where the parent signals a group the child has not joined yet.
	 */
	(void)setpgid(child, child);
	if (read(report[0], &got, sizeof(got)) == (ssize_t)sizeof(got)) {
		*exec_errno = got;
	}
	(void)close(report[0]);
	if (*exec_errno != 0) {
		/* It never ran, so it is a zombie already. Reaped here rather than
		 * left for the timeout path, which is not reached on this branch. */
		(void)waitpid(child, NULL, 0);
		return -1;
	}
	return child;
}

/*
 * Kill the whole group, give it a moment, then kill it outright, and reap.
 *
 * **The `SIGKILL` goes out even where the leader has already gone**, which is
 * the part it is tempting to skip. A probe is a script, and a shell that exited
 * on the `SIGTERM` says nothing about the `sleep` or the `curl` it forked: that
 * grandchild is reparented to init, and it is work the daemon has stopped
 * waiting for and can no longer stop.
 *
 * The wait before it uses `WNOWAIT`, so the child stays a zombie until the very
 * end. That is not tidiness: the child is the group leader, so its pid *is* the
 * group id being signalled, and reaping it first would let the kernel recycle
 * that number -- putting a `SIGKILL` into somebody else's process group.
 */
static void end_it(pid_t child)
{
	char ignored[NCFG_ERROR_MAX];
	int  status = 0;
	int  waited = 0;

	(void)ncfg_process_terminate_group(child, ignored, sizeof(ignored));
	while (waited < GRACE_SECONDS * 1000) {
		siginfo_t about;

		memset(&about, 0, sizeof(about));
		if (waitid(P_PID, (id_t)child, &about, WEXITED | WNOWAIT | WNOHANG) == 0 &&
		    about.si_pid == child) {
			break;
		}
		rest(POLL_MILLISECONDS);
		waited += POLL_MILLISECONDS;
	}
	(void)ncfg_process_kill_group(child, ignored, sizeof(ignored));
	/* Reaped so it does not sit as a zombie for the life of the daemon. */
	while (waitpid(child, &status, 0) < 0 && errno == EINTR) {
		continue;
	}
}

/*
 * Run one probe and say what happened.
 *
 * The timeout is enforced here rather than trusted to the program, because a
 * probe that hangs is the failure mode a probe is for: a `curl` against a
 * black hole does not exit, and a runner that waited would stop asking about
 * every other interface too.
 */
static void run(const ncfg_probe_policy_t *policy, outcome_t *out)
{
	char  **argv;
	int     said[2];
	pid_t   child;
	int64_t deadline;
	char    window[STDERR_KEEP];
	size_t  held = 0;
	int     reading = 1;
	int     status = 0;
	int     exec_errno = 0;
	int     ended = 0;
	unsigned round;

	out->ok = 0;
	out->started = 0;
	out->detail = NULL;

	argv = argument_vector(policy);
	if (!argv) {
		out->detail = sentence("cannot run %s: there was no memory to build its "
		    "arguments", policy->command);
		return;
	}
	if (pipe(said) != 0) {
		free(argv);
		out->detail = sentence("cannot run %s: %s", policy->command, strerror(errno));
		return;
	}
	/*
	 * The read end is non-blocking, because the drain happens in the same loop
	 * that watches the clock and a blocking read would be exactly the stall the
	 * deadline exists to prevent. Close-on-exec, so the child does not keep the
	 * read end open and leave the parent waiting for an end of file that its
	 * own descriptor is holding shut.
	 */
	if (fcntl(said[0], F_SETFL, O_NONBLOCK) != 0 ||
	    fcntl(said[0], F_SETFD, FD_CLOEXEC) != 0) {
		(void)close(said[0]);
		(void)close(said[1]);
		free(argv);
		out->detail = sentence("cannot run %s: %s", policy->command, strerror(errno));
		return;
	}

	/*
	 * A probe that cannot be started is a probe that is not answering yes.
	 * Treated as a failure rather than as an absence, because the alternative
	 * is a typo in `command` quietly meaning "always up" -- but counted
	 * separately, so a program that can never run is set aside rather than
	 * withholding an interface's routes for ever on no information.
	 */
	child = spawn(policy->command, argv, said[1], &exec_errno);
	free(argv);
	(void)close(said[1]);
	if (child <= 0) {
		(void)close(said[0]);
		out->detail = sentence("cannot run %s: %s", policy->command,
		    exec_errno ? strerror(exec_errno) : "the process could not be started");
		return;
	}
	out->started = 1;

	deadline = monotonic_milliseconds() +
	    (policy->timeout > 0 ? policy->timeout * 1000 : 0);
	for (;;) {
		pid_t answered;

		if (reading && drain(said[0], window, &held) == DRAIN_DONE) {
			reading = 0;
		}
		answered = waitpid(child, &status, WNOHANG);
		if (answered == child) {
			ended = 1;
			break;
		}
		if (answered < 0 && errno != EINTR) {
			(void)close(said[0]);
			out->detail = sentence("cannot wait for the probe: %s", strerror(errno));
			return;
		}
		if (monotonic_milliseconds() >= deadline) {
			break;
		}
		rest(POLL_MILLISECONDS);
	}

	if (!ended) {
		end_it(child);
		(void)close(said[0]);
		/*
		 * A hanging probe is a failing link rather than a broken script: it
		 * started, so it is answering, just not in time. Timing out for ever
		 * must not set it aside -- that is exactly the black hole 0119 is
		 * about.
		 */
		out->detail = sentence("no answer within %llds, so it was killed",
		    (long long)policy->timeout);
		return;
	}

	/* Whatever was still in the pipe when it exited, bounded. */
	for (round = 0; reading && round < (unsigned)FINAL_DRAINS; round++) {
		if (drain(said[0], window, &held) != DRAIN_MORE) {
			break;
		}
	}
	(void)close(said[0]);
	out->ok = WIFEXITED(status) && WEXITSTATUS(status) == 0;
	out->detail = trim_detail(window, held);
}

/* ------------------------------------------------------------------------ *
 * The module
 * ------------------------------------------------------------------------ */

ncfg_probes_t *ncfg_probes_new(char *err, size_t err_size)
{
	ncfg_probes_t *probes = calloc(1u, sizeof(*probes));

	if (!probes) {
		ncfg_error_set(err, err_size, "there was no memory for the probe verdicts");
	}
	return probes;
}

void ncfg_probes_free(ncfg_probes_t *probes)
{
	if (!probes) {
		return;
	}
	tallies_clear(probes);
	free(probes->at);
	free(probes);
}

void ncfg_probes_clock(ncfg_probes_t *probes, ncfg_probes_clock_fn clock, void *context)
{
	if (!probes) {
		return;
	}
	probes->clock = clock;
	probes->clock_context = context;
}

/* When a verdict that has just changed may change again. */
static void dwell(tally_t *tally, const ncfg_probe_policy_t *policy, int64_t now)
{
	if (policy->hold_down > 0) {
		tally->settled_set = 1;
		tally->settled_until = now + policy->hold_down * 1000;
		return;
	}
	tally->settled_set = 0;
	tally->settled_until = 0;
}

/* Whether the tally already says this. */
static int already(const tally_t *tally, int value)
{
	return tally->verdict.has && tally->verdict.value == value;
}

/*
 * An interface whose probe was removed from the config stops having a verdict,
 * rather than keeping the last one for ever. Returns whether anything went.
 */
static int forget_the_unconfigured(ncfg_probes_t *probes, const ncfg_document_t *document)
{
	size_t at = 0;
	int    dropped = 0;

	while (at < probes->count) {
		size_t i;
		int    configured = 0;

		for (i = 0; i < document->interface_count; i++) {
			if (document->interfaces[i].probe &&
			    strcmp(document->interfaces[i].name, probes->at[at].name) == 0) {
				configured = 1;
				break;
			}
		}
		if (configured) {
			at++;
			continue;
		}
		tally_remove(probes, at);
		dropped = 1;
	}
	return dropped;
}

int ncfg_probes_run_due(ncfg_probes_t *probes, const ncfg_document_t *desired,
    const ncfg_observed_t *observed, int *changed, char *err, size_t err_size)
{
	size_t  i;
	int64_t now;
	int     moved = 0;

	if (changed) {
		*changed = 0;
	}
	if (!probes) {
		ncfg_error_set(err, err_size, "there are no probe verdicts to run");
		return 0;
	}
	if (!desired) {
		tallies_clear(probes);
		return 1;
	}

	now = scheduled_now(probes);
	for (i = 0; i < desired->interface_count; i++) {
		const ncfg_interface_t    *interface = &desired->interfaces[i];
		const ncfg_probe_policy_t *policy = interface->probe;
		tally_t                   *tally;
		outcome_t                  outcome;
		int                        held;

		if (!policy || !interface->name) {
			continue;
		}
		tally = tally_for(probes, interface->name, err, err_size);
		if (!tally) {
			return 0;
		}
		if (tally->due_set && now < tally->due) {
			continue;
		}
		tally->due_set = 1;
		tally->due = now + policy->interval * 1000;

		/*
		 * Set aside stays set aside until the configuration changes, which
		 * drops the tally entirely. Re-trying a command that does not exist,
		 * every interval, for ever, is noise rather than resilience.
		 */
		if (tally->set_aside) {
			continue;
		}
		/*
		 * A dwell suppresses the *change*, not the running: the program keeps
		 * being asked, so the counts stay current and the moment the dwell
		 * expires the verdict reflects what has been happening rather than one
		 * stale result.
		 */
		held = tally->settled_set && now < tally->settled_until;

		/*
		 * **The precondition, and only where there is a lease to want** (0191).
		 * An interface the document configures statically has none and never
		 * will, so requiring one there would hold a working link down for ever.
		 * Where DHCP *was* asked for and no client has installed a route, the
		 * reachability probe can only fail: this says so without spawning
		 * anything, which is a process per interval per interface saved on
		 * exactly the links that are already in trouble.
		 */
		if (policy->require_lease && wants_dhcp(interface) &&
		    !ncfg_observed_has_dhcp_lease(observed, interface->name)) {
			outcome.ok = 0;
			/* Started, because this *is* an answer about the link rather than
			 * a probe that could not be run -- setting aside counts the second
			 * kind and must not count this. */
			outcome.started = 1;
			outcome.detail = duplicate("no DHCP lease on this interface, so the "
			    "probe was not run: a client has installed no route here");
		} else {
			run(policy, &outcome);
		}
		free(tally->detail);
		tally->detail = outcome.detail;

		/*
		 * **A program that cannot be started says nothing about the link.**
		 * Counted apart, and after enough of them the probe is set aside and
		 * its verdict cleared rather than left at false: withholding an
		 * interface's routes for ever because of a typo in `command` is how a
		 * probe takes a machine off the network and keeps it there. The verdict
		 * going absent means "nobody asked", which is what a probe that never
		 * ran amounts to -- and it is loud rather than quiet, which is the half
		 * the original concern was really about.
		 */
		if (!outcome.started) {
			tally->start_failures = one_more(tally->start_failures);
			if (tally->start_failures >=
			    (uint32_t)NCFG_PROBE_START_FAILURES_BEFORE_SET_ASIDE) {
				char *why = sentence("set aside after %lu attempts: %s",
				    (unsigned long)tally->start_failures,
				    tally->detail ? tally->detail : "it could not be started");

				tally->set_aside = 1;
				if (why) {
					free(tally->detail);
					tally->detail = why;
				}
				if (tally->verdict.has) {
					tally->verdict.has = 0;
					tally->verdict.value = 0;
					moved = 1;
				}
			}
			continue;
		}
		tally->start_failures = 0;

		/*
		 * Counted as consecutive runs in one direction: a success resets the
		 * failure run and the other way about. Hysteresis is the whole feature,
		 * and a tally that let them accumulate independently would flip on a
		 * link that alternated.
		 */
		if (outcome.ok) {
			tally->failures = 0;
			tally->successes = one_more(tally->successes);
			if (!held && (int64_t)tally->successes >= policy->up_after &&
			    !already(tally, 1)) {
				tally->verdict.has = 1;
				tally->verdict.value = 1;
				dwell(tally, policy, now);
				moved = 1;
			}
		} else {
			tally->successes = 0;
			tally->failures = one_more(tally->failures);
			if (!held && (int64_t)tally->failures >= policy->down_after &&
			    !already(tally, 0)) {
				tally->verdict.has = 1;
				tally->verdict.value = 0;
				dwell(tally, policy, now);
				moved = 1;
			}
		}
	}

	if (forget_the_unconfigured(probes, desired)) {
		moved = 1;
	}
	if (changed) {
		*changed = moved;
	}
	return 1;
}

size_t ncfg_probes_failing_count(const ncfg_probes_t *probes)
{
	size_t i;
	size_t count = 0;

	if (!probes) {
		return 0;
	}
	for (i = 0; i < probes->count; i++) {
		if (probes->at[i].verdict.has && !probes->at[i].verdict.value) {
			count++;
		}
	}
	return count;
}

const char *ncfg_probes_failing_at(const ncfg_probes_t *probes, size_t at)
{
	size_t i;
	size_t seen = 0;

	if (!probes) {
		return NULL;
	}
	for (i = 0; i < probes->count; i++) {
		if (!probes->at[i].verdict.has || probes->at[i].verdict.value) {
			continue;
		}
		if (seen == at) {
			return probes->at[i].name;
		}
		seen++;
	}
	return NULL;
}

int ncfg_probes_apply(const ncfg_probes_t *probes, ncfg_observed_t *observed, char *err,
    size_t err_size)
{
	size_t i;
	int    ok = 1;

	if (!probes || !observed) {
		return 1;
	}
	for (i = 0; i < observed->link_count; i++) {
		ncfg_observed_link_t *link = &observed->links[i];
		const tally_t        *tally = tally_find(probes, link->name);
		char                 *copy = NULL;

		if (!tally) {
			continue;
		}
		if (tally->detail) {
			copy = duplicate(tally->detail);
			if (!copy) {
				/* **The verdict is still stamped**, because it is the half
				 * routes hang off; only the explanation is lost, and a link
				 * judged down with no reason is closer to the truth than one
				 * left unjudged. */
				ncfg_error_set(err, err_size,
				    "there was no memory to record why %s's probe said what it did",
				    link->name ? link->name : "an interface");
				ok = 0;
			}
		}
		link->reachable = tally->verdict;
		free(link->probe_detail);
		link->probe_detail = copy;
	}
	return ok;
}

ncfg_optbool_t ncfg_probes_verdict(const ncfg_probes_t *probes, const char *interface)
{
	const tally_t *tally = tally_find(probes, interface);
	ncfg_optbool_t absent = { 0, 0 };

	return tally ? tally->verdict : absent;
}

const char *ncfg_probes_detail(const ncfg_probes_t *probes, const char *interface)
{
	const tally_t *tally = tally_find(probes, interface);

	return tally ? tally->detail : NULL;
}
