/*
 * hook.c -- running hooks, with the contract design section 5.2 specifies.
 *
 * Three things it gets right that a bare `fork`, `exec`, `wait` does not: the
 * environment is the documented one, the content hash is checked before
 * execution, and **a failure means different things in different phases**.
 *
 * WHAT THIS FILE SPAWNS, AND WHAT STOPS IT
 *   One child per call, in its own process group, with a deadline. If it
 *   outstays the deadline the whole group gets `SIGTERM`, then `SIGKILL` after
 *   a grace period, and the child is reaped before this returns. There is no
 *   loop that spawns, no recursion, and no path that leaves a process behind:
 *   the group signal is what makes that true, because a hook is a script and
 *   `sleep 300 &` inside it is a *grandchild*. Signalling only the shell left
 *   the sleep running and reparented to init -- the daemon stopped waiting and
 *   the work it was waiting for carried on.
 *
 * WHAT IS DELIBERATELY NOT HERE
 *   **`run_as` is refused rather than honoured.** The Rust resolves the user
 *   with `getpwnam` and drops privilege in the child; `process.h` says outright
 *   that this port keeps NSS away from the privileged process, and it is final.
 *   So a hook naming a user does not run at all -- which is the direction the
 *   Rust's own test insists on: "the wrong answer here is not an error but
 *   `runs anyway, as root`". A hook that asked to be unprivileged can never
 *   run privileged instead. See the sentence in `drop_refusal`.
 */
#include "ncfg/apply.h"

#include "ncfg/base.h"
#include "ncfg/hooks.h"
#include "ncfg/process.h"
#include "ncfg/value.h"

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

/* The environment this process was started with, which a hook inherits. */
extern char **environ;

/*
 * The largest script this will read in order to hash it.
 *
 * A hook is shell somebody wrote in a configuration file. A megabyte is four
 * orders of magnitude more than any of them and small enough that a file
 * swapped for something enormous is refused rather than read -- the check
 * before execution has to bound its own input, or the check is the attack.
 */
#define HOOK_MAX_SCRIPT (1024u * 1024u)

/* How often the wait wakes to look. Small enough not to add meaningfully to a
 * hook's runtime, large enough not to spin. */
#define POLL_MILLISECONDS 20

/* How long a killed hook gets between `SIGTERM` and `SIGKILL`. A script that
 * traps `TERM` to tear down what it built deserves the chance to, and a
 * `SIGKILL` that arrives first is how a half-configured interface is left
 * behind. */
#define GRACE_SECONDS 5

/*
 * How many times a spawn is retried when the kernel says the file is busy.
 *
 * Six attempts over roughly 84 ms. The window being waited out is one
 * `fork`-to-`exec` in another thread, which is microseconds; anything still
 * busy after that is somebody genuinely holding the file open for writing, and
 * that is a fault to report rather than to keep waiting on.
 */
#define ETXTBSY_ATTEMPTS 6

int ncfg_hook_is_veto_phase(int phase)
{
	/*
	 * Section 5.2: "A non-zero exit from a `pre_*` hook **aborts** the
	 * transition -- you can veto a bring-up. `post_*` and event hook failures
	 * are logged, don't roll back." `up` and `down` are the two lifecycle
	 * moments in the middle of a transition, so a veto there still means
	 * something; by the time `post_*` runs the transition has happened.
	 */
	return phase == NCFG_HOOK_PHASE_PRE_UP || phase == NCFG_HOOK_PHASE_PRE_DOWN ||
	    phase == NCFG_HOOK_PHASE_UP || phase == NCFG_HOOK_PHASE_DOWN;
}

/* The outcome a failure in this phase produces, with the sentence. */
static ncfg_hook_outcome_t fail(int phase, char *err, size_t err_size, const char *format, ...)
{
	va_list args;

	va_start(args, format);
	ncfg_error_setv(err, err_size, format, args);
	va_end(args);
	return ncfg_hook_is_veto_phase(phase) ? NCFG_HOOK_VETOED : NCFG_HOOK_NOTED;
}

/* ------------------------------------------------------------------------ *
 * The hash check
 * ------------------------------------------------------------------------ */

/*
 * The script's bytes, bounded, or NULL with `*why` set.
 *
 * `stat` is not consulted for the size: the file may change between the stat
 * and the read, and what is hashed has to be what was read. So it reads until
 * the ceiling and refuses anything that reaches it.
 */
static char *script_bytes(const char *path, size_t *length_out, const char **why)
{
	FILE   *file = fopen(path, "rb");
	char   *bytes;
	size_t  at = 0;

	if (!file) {
		*why = strerror(errno);
		return NULL;
	}
	bytes = malloc(HOOK_MAX_SCRIPT);
	if (!bytes) {
		fclose(file);
		*why = "there was not enough memory to read it";
		return NULL;
	}
	while (at < HOOK_MAX_SCRIPT) {
		size_t got = fread(bytes + at, 1u, HOOK_MAX_SCRIPT - at, file);

		at += got;
		if (got == 0) {
			break;
		}
	}
	if (ferror(file) || at == HOOK_MAX_SCRIPT) {
		fclose(file);
		free(bytes);
		*why = at == HOOK_MAX_SCRIPT ? "it is at least a megabyte, which is larger "
		    "than a hook script may be" : "it could not be read to the end";
		return NULL;
	}
	fclose(file);
	*length_out = at;
	return bytes;
}

/*
 * Whether the file on disk is the one the configuration was compiled against.
 *
 * Section 2.2 records the content hash so drift detection can notice a hook
 * changing underneath the document that references it. Checking it here makes
 * that a *control* rather than a report: a hook file swapped after the
 * configuration was compiled does not run as root on the strength of the old
 * approval.
 */
static int unchanged(const ncfg_hook_ref_t *hook, char *err, size_t err_size,
    ncfg_hook_outcome_t *refused)
{
	char        actual[NCFG_SHA256_HEX_SIZE];
	const char *why = NULL;
	size_t      length = 0;
	char       *bytes;

	if (!hook->sha256 || hook->sha256[0] == '\0') {
		/*
		 * **Not a pass.** The op carries a path and no hash, so the executor
		 * looks the hash up in the document it was given; an empty one means
		 * it had none to look up, and running the file anyway would make the
		 * whole check conditional on a lookup succeeding.
		 */
		*refused = fail(hook->phase, err, err_size,
		    "%s: this build was given no content hash for it, so there is nothing "
		    "to check it against; not running it", hook->path);
		return 0;
	}
	bytes = script_bytes(hook->path, &length, &why);
	if (!bytes) {
		*refused = fail(hook->phase, err, err_size, "cannot read %s: %s", hook->path,
		    why ? why : "no detail");
		return 0;
	}
	ncfg_sha256_hex(bytes, length, actual);
	free(bytes);
	if (strcmp(actual, hook->sha256) != 0) {
		/* Twelve digits of each, which is what the Rust prints: enough to
		 * recognise, short enough to read out. */
		*refused = fail(hook->phase, err, err_size,
		    "%s has changed since the configuration was compiled (expected %.12s, "
		    "found %.12s); not running it", hook->path, hook->sha256, actual);
		return 0;
	}
	return 1;
}

/* ------------------------------------------------------------------------ *
 * The environment
 * ------------------------------------------------------------------------ */

/* The five names this sets, so an inherited one cannot shadow ours. */
static const char *const ours[] = { "NCFG_IFACE=", "NCFG_PHASE=", "NCFG_REASON=",
	"NCFG_ADDR=", "NCFG_GW=" };

static int is_ours(const char *entry)
{
	size_t i;

	for (i = 0; i < sizeof(ours) / sizeof(ours[0]); i++) {
		if (strncmp(entry, ours[i], strlen(ours[i])) == 0) {
			return 1;
		}
	}
	return 0;
}

/* One `NAME=value` the caller frees, or NULL. */
static char *entry(const char *name, const char *value)
{
	size_t size = strlen(name) + strlen(value) + 2u;
	char  *text = malloc(size);

	if (text) {
		(void)snprintf(text, size, "%s%s", name, value);
	}
	return text;
}

/*
 * The child's environment: what this process has, plus section 5.2's names.
 *
 * Inherited rather than replaced, which is what the Rust's `Command::env`
 * does: a hook is a shell script and one started with no `PATH` is a script
 * that cannot find `ip`. The five netcfgd names are filtered out of the
 * inherited set first, so a value in the daemon's own environment cannot
 * shadow the one the phase is telling the hook about.
 *
 * An absent member sets **no variable at all** rather than an empty one: a
 * script testing `[ -n "$NCFG_ADDR" ]` has to be able to tell the difference.
 */
static char **environment(const ncfg_hook_ref_t *hook, const ncfg_hook_env_t *env)
{
	char  **made;
	size_t  inherited = 0;
	size_t  at = 0;
	size_t  first_ours;
	size_t  i;
	int     short_of_memory = 0;

	while (environ && environ[inherited]) {
		inherited++;
	}
	/* Five of ours, and the terminator. */
	made = calloc(inherited + 6u, sizeof(*made));
	if (!made) {
		return NULL;
	}
	for (i = 0; i < inherited; i++) {
		if (!is_ours(environ[i])) {
			made[at++] = environ[i];
		}
	}
	first_ours = at;
	if (env && env->iface) {
		made[at++] = entry("NCFG_IFACE=", env->iface);
	}
	{
		const char *phase = ncfg_hook_phase_name((ncfg_hook_phase_t)hook->phase);

		if (phase) {
			made[at++] = entry("NCFG_PHASE=", phase);
		}
	}
	if (env && env->reason) {
		made[at++] = entry("NCFG_REASON=", env->reason);
	}
	if (env && env->addr) {
		made[at++] = entry("NCFG_ADDR=", env->addr);
	}
	if (env && env->gateway) {
		made[at++] = entry("NCFG_GW=", env->gateway);
	}
	made[at] = NULL;
	/* One `entry` that failed leaves a NULL in the middle, which `execve`
	 * reads as the end of the list -- so the hook would run with some of its
	 * variables missing and nothing said. Refuse the lot instead. */
	for (i = first_ours; i < at; i++) {
		if (!made[i]) {
			short_of_memory = 1;
		}
	}
	if (short_of_memory) {
		for (i = first_ours; i < at; i++) {
			free(made[i]);
		}
		free(made);
		return NULL;
	}
	return made;
}

/* Free the entries this made, which are the ones after the inherited block. */
static void environment_free(char **made)
{
	size_t i;

	if (!made) {
		return;
	}
	for (i = 0; made[i]; i++) {
		if (is_ours(made[i])) {
			free(made[i]);
		}
	}
	free(made);
}

/* ------------------------------------------------------------------------ *
 * Spawning
 * ------------------------------------------------------------------------ */

/* Sleep for a bounded number of milliseconds. */
static void rest(long milliseconds)
{
	struct timespec wait;

	wait.tv_sec = milliseconds / 1000L;
	wait.tv_nsec = (milliseconds % 1000L) * 1000000L;
	(void)nanosleep(&wait, NULL);
}

/*
 * Start the script, or say why not.
 *
 * The child's `execve` failure comes back through a close-on-exec pipe, which
 * is the only way the parent can tell "started and exited 127" from "never
 * started": both leave a child that is gone by the time it is waited for.
 *
 * `*exec_errno` is the child's `errno` where the exec failed, and 0 otherwise.
 */
static pid_t spawn(const char *path, char *const envp[], int *exec_errno)
{
	int   report[2];
	pid_t child;
	int   got = 0;

	*exec_errno = 0;
	if (pipe(report) != 0) {
		return -1;
	}
	if (fcntl(report[1], F_SETFD, FD_CLOEXEC) != 0) {
		close(report[0]);
		close(report[1]);
		return -1;
	}
	child = fork();
	if (child < 0) {
		close(report[0]);
		close(report[1]);
		return -1;
	}
	if (child == 0) {
		char *argv[2];

		/* Its own process group, so that killing it kills what it started. */
		(void)setpgid(0, 0);
		close(report[0]);
		/* `execve` takes a mutable `argv` and never writes through it; the
		 * cast is what `-Wwrite-strings` costs for a path this does not own. */
		argv[0] = (char *)(uintptr_t)(const void *)path;
		argv[1] = NULL;
		(void)execve(path, argv, envp);
		got = errno;
		/* A short write is as good as none: the parent treats anything but a
		 * whole int as "it started". */
		(void)write(report[1], &got, sizeof(got));
		_exit(127);
	}
	close(report[1]);
	/*
	 * The parent sets the group too. Whichever of the two runs first wins and
	 * the other is a no-op or an `EACCES` after the exec -- doing it in one
	 * place only is the classic race, where the parent signals a group the
	 * child has not joined yet.
	 */
	(void)setpgid(child, child);
	if (read(report[0], &got, sizeof(got)) == (ssize_t)sizeof(got)) {
		*exec_errno = got;
	}
	close(report[0]);
	if (*exec_errno != 0) {
		/* It never ran, so it is a zombie already. Reaped here rather than
		 * left for the timeout path, which is not reached on this branch. */
		(void)waitpid(child, NULL, 0);
		return -1;
	}
	return child;
}

/*
 * Spawn, retrying while the kernel says the text file is busy.
 *
 * **`ETXTBSY` here is not a fault in the hook, and it is not rare.** `execve`
 * refuses a file that any process holds open for writing, and netcfgd
 * materialises hooks under `/run` and spawns helpers from other threads. A
 * `fork` duplicates every open descriptor into the child, so a hook written a
 * moment earlier can be held open by a child that has not reached its own
 * `exec` yet. `O_CLOEXEC` does not close that window -- it closes the
 * descriptor *at* exec, and the window is before it.
 *
 * **What not retrying costs is not a confusing message.** `pre_up` is a veto
 * phase, so a spurious failure to start stops the transition: an interface does
 * not come up, and the reason is a race that nothing in the log explains.
 *
 * Linear rather than exponential: the total is bounded by design, and a
 * doubling backoff would spend most of its budget on the last attempt -- the
 * one least likely to be needed, since the window is one fork-to-exec.
 */
static pid_t spawn_despite_etxtbsy(const char *path, char *const envp[], int *exec_errno)
{
	unsigned attempt;

	for (attempt = 0; attempt <= ETXTBSY_ATTEMPTS; attempt++) {
		pid_t child = spawn(path, envp, exec_errno);

		if (child > 0 || *exec_errno != ETXTBSY || attempt == ETXTBSY_ATTEMPTS) {
			return child;
		}
		rest((long)(attempt + 1u) * 4L);
	}
	return -1;
}

/* ------------------------------------------------------------------------ *
 * Waiting
 * ------------------------------------------------------------------------ */

/*
 * Wait for `child` for at most `seconds`.
 *
 * Polled rather than blocked on, because the wait has to be interruptible by a
 * clock: the reconcile loop is single threaded and calls this inline, so a hook
 * that never exits used to stall every request the daemon could otherwise
 * answer -- `status` and `plan` included, which is what an operator reaches for
 * when the network stops.
 *
 * 1 where it ended, with `*status` from `waitpid`; 0 where the deadline
 * passed; -1 where it can no longer be waited for at all.
 *
 * The third answer is not pedantry. Folding it into "ended" would hand the
 * caller a `*status` of zero, which reads as a clean exit -- so a hook nobody
 * can account for would report success.
 */
static int poll_until(pid_t child, unsigned seconds, int *status)
{
	long waited = 0;
	long limit = (long)seconds * 1000L;

	for (;;) {
		pid_t answered = waitpid(child, status, WNOHANG);

		if (answered == child) {
			return 1;
		}
		if (answered < 0 && errno != EINTR) {
			return -1;
		}
		if (waited >= limit) {
			return 0;
		}
		rest(POLL_MILLISECONDS);
		waited += POLL_MILLISECONDS;
	}
}

/*
 * Wait, killing the whole group if it outstays `seconds`.
 *
 * 1 where it finished in time, 0 for a timeout -- after which nothing it
 * started is still running -- and -1 where it could not be waited for.
 */
static int wait_within(pid_t child, unsigned seconds, int *status)
{
	char ignored[NCFG_ERROR_MAX];
	int  ended = poll_until(child, seconds, status);

	if (ended != 0) {
		return ended;
	}
	/* `setpgid(child, child)` made the child a group leader, so its pid is the
	 * group id and the whole tree it started goes with it. */
	(void)ncfg_process_terminate_group((pid_t)child, ignored, sizeof(ignored));
	/*
	 * The leader usually goes on the TERM. Still a timeout as far as the
	 * caller is concerned -- the hook did not finish its work -- and the group
	 * is killed below regardless, because a leader that exited says nothing
	 * about what it forked.
	 */
	(void)poll_until(child, GRACE_SECONDS, status);
	(void)ncfg_process_kill_group((pid_t)child, ignored, sizeof(ignored));
	/* Reaped so it does not sit as a zombie for the life of the daemon. */
	(void)waitpid(child, status, 0);
	return 0;
}

/* ------------------------------------------------------------------------ *
 * The runner
 * ------------------------------------------------------------------------ */

/*
 * Why a hook naming a user does not run.
 *
 * The Rust resolves the name and drops privilege in the child, and fails
 * closed in both directions: an unknown user does not run at all rather than
 * running as whoever the daemon happens to be. This port cannot resolve the
 * name -- `process.h` keeps NSS out of the privileged process, deliberately
 * and permanently -- so it takes the same closed direction for every name
 * rather than the privileged one for any.
 */
static ncfg_hook_outcome_t drop_refusal(const ncfg_hook_ref_t *hook, char *err, size_t err_size)
{
	return fail(hook->phase, err, err_size,
	    "%s asks to run as `%s`, and this build resolves no user names in the "
	    "privileged process (see process.h); not running it, rather than running it "
	    "as root instead", hook->path, hook->run_as);
}

ncfg_hook_outcome_t ncfg_hook_run(const ncfg_hook_ref_t *hook, const ncfg_hook_env_t *env,
    char *err, size_t err_size)
{
	ncfg_hook_outcome_t refused = NCFG_HOOK_NOTED;
	char              **made;
	pid_t               child;
	unsigned            seconds;
	int                 exec_errno = 0;
	int                 status = 0;
	int                 ended;

	if (!hook || !hook->path) {
		ncfg_error_set(err, err_size, "there is no hook to run");
		return NCFG_HOOK_NOTED;
	}
	if (hook->run_as) {
		return drop_refusal(hook, err, err_size);
	}
	if (!unchanged(hook, err, err_size, &refused)) {
		return refused;
	}

	made = environment(hook, env);
	if (!made) {
		return fail(hook->phase, err, err_size,
		    "%s: there was not enough memory to build its environment; not running it",
		    hook->path);
	}
	child = spawn_despite_etxtbsy(hook->path, made, &exec_errno);
	environment_free(made);
	if (child <= 0) {
		return fail(hook->phase, err, err_size, "could not run %s: %s", hook->path,
		    exec_errno ? strerror(exec_errno) : "the process could not be started");
	}

	/*
	 * `ncfg_hook_ref_t::timeout` is never anything but absent -- the
	 * configuration language has no key for it -- so this number is what every
	 * hook on every machine gets. The field is read anyway, because a
	 * mechanism that ignores its own input is one that silently stops working
	 * the day the key arrives.
	 */
	seconds = NCFG_HOOK_DEFAULT_TIMEOUT_SECONDS;
	if (hook->timeout.has && hook->timeout.value > 0 && hook->timeout.value <= 86400) {
		seconds = (unsigned)hook->timeout.value;
	}
	ended = wait_within(child, seconds, &status);
	if (ended < 0) {
		return fail(hook->phase, err, err_size,
		    "could not wait for %s: %s", hook->path, strerror(errno));
	}
	if (ended == 0) {
		/* A hook that never answered did not say yes, so a timeout follows the
		 * phase exactly as a non-zero exit does. */
		return fail(hook->phase, err, err_size, "%s did not finish within %us and was killed",
		    hook->path, seconds);
	}
	if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
		return NCFG_HOOK_OK;
	}
	if (WIFSIGNALED(status)) {
		return fail(hook->phase, err, err_size, "%s was killed by signal %d", hook->path,
		    WTERMSIG(status));
	}
	return fail(hook->phase, err, err_size, "%s exited with %d", hook->path,
	    WIFEXITED(status) ? WEXITSTATUS(status) : -1);
}
