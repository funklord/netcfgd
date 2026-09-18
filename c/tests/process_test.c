/*
 * process_test.c -- the ownership rule, the process group, and the two streams.
 *
 * WHY THIS EXISTS
 *   Two properties here are security properties rather than conveniences, and
 *   both are invisible in a passing daemon:
 *
 *     * **A marker is a whole argument and the process must be the right
 *       user's.** The marker is a predictable path, so a local user can type it
 *       into their own `argv` -- measured, and netcfgd adopted an ordinary
 *       `sh` as its `OpenVPN` backend, recorded the start as done and reported
 *       the tunnel up. The negative halves below are the whole defensibility of
 *       scanning `/proc` at all.
 *     * **A signal goes to the group.** `sh -c 'sleep 300'` forks, so
 *       signalling the child kills the shell and leaves the work running,
 *       reparented to init. Measured: two `sleep 300` processes outlived a run
 *       that believed it had killed them. That defect is asserted here in both
 *       directions -- the child signal leaving the grandchild, and the group
 *       signal taking it.
 *
 * WHY EVERY CHILD IS IN ITS OWN GROUP, AND EVERY WAIT HAS A CEILING
 *   A `sh -c 'sleep 30'` orphan holding this binary's stderr cost the Rust
 *   suite thirty seconds on every run, after the last assertion, for tests that
 *   had already passed -- see `tool/disarm_gate.py`, which is a gate rather
 *   than a test because the failure never mentions its cause. So: every child
 *   is spawned into a group of its own, every one is registered before it can
 *   be lost, every wait is a bounded poll rather than a blocking `waitpid`, and
 *   the last check in this file is that nothing of this test's is still
 *   running.
 *
 * WHAT CANNOT BE TESTED WITHOUT PRIVILEGE, AND WHAT IS TESTED INSTEAD
 *   `ours` answers "root, or whoever is asking", so a root-owned child is
 *   netcfgd's whatever uid asks and there is no refusal to observe -- which is
 *   why the Rust's two ownership tests skip when its suite runs as root. Where
 *   this suite *is* root it does the stronger thing instead: it puts its child
 *   at the unprivileged id and watches root be refused, which is the real
 *   arrangement rather than a stand-in. As an ordinary user it falls back to
 *   the Rust's: its own child, asked about on behalf of a uid nothing on the
 *   machine runs as.
 */
#include "ncfg/base.h"
#include "ncfg/log.h"
#include "ncfg/process.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int failures;

static void check(int condition, const char *what)
{
	printf("%-58s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

/* A ceiling on every wait in this file. Nothing here takes more than a few
 * tens of milliseconds when it works; this is how long it is allowed to take
 * before the answer is "it did not happen". */
#define PATIENCE_MS 3000

/* Children this file has started, so that the cleanup at the bottom can prove
 * it took them all back. Registered by pid, which is also the group id, because
 * every one of them is a group leader. */
#define SPAWN_MAX 8
static pid_t spawned[SPAWN_MAX];
static size_t spawn_count;

static void sleep_ms(long milliseconds)
{
	struct timespec wanted;

	wanted.tv_sec = milliseconds / 1000;
	wanted.tv_nsec = (milliseconds % 1000) * 1000000L;
	(void)nanosleep(&wanted, NULL);
}

/*
 * A shell carrying `marker` as a whole argument, in a process group of its own.
 *
 * `sh -c CMD NAME` puts NAME in the shell's own argv and keeps it there while
 * it waits. `sleep 30 <path>` would not: sleep rejects a non-numeric argument
 * and the child would be gone before `/proc` could be asked, which is a test
 * that proves nothing rather than a fix.
 *
 * `setpgid` in **both** processes, which is not belt and braces: the parent
 * races the child's `exec`, and whichever gets there first is the one that
 * makes the group exist. A parent that only asked afterwards could signal
 * netcfgd's own group instead, and a child that only asked itself could be
 * signalled before it had.
 *
 * `become` before the exec where an id is asked for, which is also a test of
 * that function's ordering: it is the only unprivileged-drop path in this
 * library, and a child that failed to drop must not go on to exec.
 */
static pid_t spawn_shell(const char *command, const char *marker, uid_t as_uid)
{
	pid_t child;

	if (spawn_count >= SPAWN_MAX) {
		return 0;
	}
	/* Nothing half-written may be inherited: a buffered line in this
	 * process' stdout would be flushed a second time by the child. */
	fflush(NULL);
	child = fork();
	if (child < 0) {
		return 0;
	}
	if (child == 0) {
		if (setpgid(0, 0) != 0) {
			_exit(120);
		}
		if (as_uid != (uid_t)-1 &&
		    !ncfg_process_become(as_uid, (gid_t)as_uid, NULL, 0)) {
			_exit(121);
		}
		execlp("sh", "sh", "-c", command, marker, (char *)NULL);
		_exit(122);
	}
	/* EACCES here means the child has already exec'd, which means it has
	 * already put itself in the group. */
	(void)setpgid(child, child);
	spawned[spawn_count++] = child;
	return child;
}

/* A bounded `waitpid`. 1 where the child was reaped. */
static int reap_status(pid_t child, int *status, int patience_ms)
{
	int waited = 0;

	for (;;) {
		pid_t got = waitpid(child, status, WNOHANG);

		if (got == child) {
			return 1;
		}
		if (got < 0 && errno != EINTR) {
			return 0;
		}
		if (waited >= patience_ms) {
			return 0;
		}
		sleep_ms(10);
		waited += 10;
	}
}

static int reap(pid_t child, int patience_ms)
{
	int status = 0;

	return reap_status(child, &status, patience_ms);
}

/* The pid carrying `marker`, waited for: a child that has forked but not yet
 * exec'd is not in `/proc` with its argv, so a single look proves nothing. */
static pid_t wait_for_marker(const char *marker, uid_t asking, int patience_ms)
{
	int waited = 0;

	for (;;) {
		pid_t found = ncfg_process_pid_by_marker_as(marker, asking);

		if (found != 0 || waited >= patience_ms) {
			return found;
		}
		sleep_ms(20);
		waited += 20;
	}
}

/* And the other direction, which is how "it is gone" is asserted. A zombie
 * carries no `argv`, so this cannot mistake one for a live process. */
static int wait_for_marker_gone(const char *marker, uid_t asking, int patience_ms)
{
	int waited = 0;

	for (;;) {
		if (ncfg_process_pid_by_marker_as(marker, asking) == 0) {
			return 1;
		}
		if (waited >= patience_ms) {
			return 0;
		}
		sleep_ms(20);
		waited += 20;
	}
}

/* Somewhere to put a pid file and a program that will not run. Named after
 * this process, because two runs at once must not share one. */
static char workdir[192];

static void make_workdir(void)
{
	const char *base = getenv("TMPDIR");

	if (!base || base[0] != '/') {
		base = "/tmp";
	}
	(void)snprintf(workdir, sizeof(workdir), "%s/netcfgd-c-process-%ld", base, (long)getpid());
	(void)mkdir(workdir, 0700);
}

static void in_workdir(char *out, size_t out_size, const char *leaf)
{
	(void)snprintf(out, out_size, "%s/%s", workdir, leaf);
}

/*
 * Remove what this file made, **by name**.
 *
 * Not a wildcard and not an `rm -rf` of a variable: a `find -delete` under a
 * directory built from an environment variable is the classic way a clean step
 * eats something it should not, and every name here is one this file wrote.
 */
static void remove_workdir(void)
{
	static const char *const leaves[] = { "client", "live.pid", "garbage.pid", "stale.pid" };
	size_t i;
	char path[256];

	for (i = 0; i < sizeof(leaves) / sizeof(leaves[0]); i++) {
		in_workdir(path, sizeof(path), leaves[i]);
		(void)unlink(path);
	}
	(void)rmdir(workdir);
}

static void write_file(const char *path, const char *text, mode_t mode)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);

	if (fd < 0) {
		return;
	}
	(void)write(fd, text, strlen(text));
	(void)close(fd);
	(void)chmod(path, mode);
}

/* A pipe with no reader, so that a write into it fails at once rather than
 * racing the parent's `close`. The read end is closed before the fork, which is
 * what makes this deterministic. */
static pid_t fork_with_broken_stream(int target_fd, int ignore_sigpipe)
{
	int fds[2];
	pid_t child;

	if (pipe(fds) != 0) {
		return -1;
	}
	(void)close(fds[0]);
	fflush(NULL);
	child = fork();
	if (child == 0) {
		if (ignore_sigpipe) {
			(void)signal(SIGPIPE, SIG_IGN);
		}
		if (dup2(fds[1], target_fd) < 0) {
			_exit(119);
		}
		(void)close(fds[1]);
		return 0;
	}
	(void)close(fds[1]);
	return child;
}

int main(void)
{
	char marker[128];
	char inner[128];
	char path[256];
	char text[NCFG_ERROR_MAX];
	char message[NCFG_ERROR_MAX];
	uid_t mine = geteuid();
	uid_t nobody = ncfg_privilege_unprivileged_id();
	/* A uid nothing on the machine runs as, so `ours` can answer only "not
	 * root and not you". `mine + 1` would be a real account. */
	uid_t stranger = (uid_t)0xfffffffeu;
	int as_root = mine == 0;

	make_workdir();

	/* ---------------------------------------------------------------
	 * The marker: a whole argument, and only from the right user.
	 * --------------------------------------------------------------- */
	{
		pid_t child;
		pid_t found;
		pid_t prefix_match;
		pid_t longer_match;

		/* The suffix is per test, not per process: two tests using one
		 * marker race for each other's child, and the lowest-pid rule
		 * then picks the wrong one. */
		(void)snprintf(marker, sizeof(marker),
		    "/run/netcfgd-test-%ld-found/supplicant/x.pid", (long)getpid());
		child = spawn_shell("sleep 30", marker, (uid_t)-1);
		check(child > 0, "a child can be started at all");
		found = wait_for_marker(marker, mine, PATIENCE_MS);
		check(found == child, "a marker in argv finds netcfgd's own process");

		/* **A substring must not match.** This is the whole
		 * defensibility of scanning `/proc`: loosen it and netcfgd
		 * adopts another manager's supplicant. */
		marker[strlen(marker) - 4] = '\0';
		prefix_match = ncfg_process_pid_by_marker_as(marker, mine);
		(void)snprintf(marker, sizeof(marker),
		    "/run/netcfgd-test-%ld-found/supplicant/x.pid.more", (long)getpid());
		longer_match = ncfg_process_pid_by_marker_as(marker, mine);
		check(prefix_match == 0, "a proper prefix of an argument does not match");
		check(longer_match == 0, "and neither does a longer string containing it");

		(void)snprintf(marker, sizeof(marker),
		    "/run/netcfgd-test-%ld-found/supplicant/x.pid", (long)getpid());
		/* The group, not the child: `sh` may have forked. */
		check(ncfg_process_terminate_group(child, message, sizeof(message)),
		    "a group signal to a live group succeeds");
		check(reap(child, PATIENCE_MS), "and the child is reaped within the ceiling");
		check(wait_for_marker_gone(marker, mine, PATIENCE_MS),
		    "after which nothing carries the marker");
	}

	check(ncfg_process_pid_by_marker("/run/netcfgd-nothing-carries-this-9c1f2e/x.pid") == 0,
	    "a marker nothing carries finds nothing at all");

	/* ---------------------------------------------------------------
	 * A marker carried by somebody else's process is refused.
	 * --------------------------------------------------------------- */
	{
		pid_t child;
		pid_t found;
		pid_t refused;
		uid_t owner = as_root ? nobody : mine;
		uid_t asker = as_root ? mine : stranger;

		(void)snprintf(marker, sizeof(marker),
		    "/run/netcfgd-test-%ld-foreign/openvpn/vpn0.sock", (long)getpid());
		child = spawn_shell("sleep 30", marker, as_root ? nobody : (uid_t)-1);
		found = wait_for_marker(marker, owner, PATIENCE_MS);
		/* Asked on behalf of somebody the child does not belong to. As
		 * root that is the real arrangement -- a root netcfgd looking at
		 * a user's process; unprivileged it is a uid nothing runs as,
		 * because a root-owned child is netcfgd's for every caller by
		 * design and there would be no refusal to see. */
		refused = ncfg_process_pid_by_marker_as(marker, asker);
		check(found == child, "a marked child is found by the uid that owns it");
		check(refused == 0, "and a process another user started is not adopted");
		if (as_root) {
			check(!ncfg_process_ours(child, 0),
			    "ownership, not the scan, is what refuses it");
		}
		check(ncfg_process_terminate_group(child, message, sizeof(message)) &&
		    reap(child, PATIENCE_MS), "the foreign-uid child is taken back");
	}

	/* ---------------------------------------------------------------
	 * The same guard on the pid-file path, which is what signals.
	 * --------------------------------------------------------------- */
	{
		pid_t child;
		char pidtext[32];
		uid_t owner = as_root ? nobody : mine;
		uid_t asker = as_root ? mine : stranger;

		(void)snprintf(marker, sizeof(marker),
		    "/run/netcfgd-test-%ld-owner/supplicant.pid", (long)getpid());
		child = spawn_shell("sleep 30", marker, as_root ? nobody : (uid_t)-1);
		check(wait_for_marker(marker, owner, PATIENCE_MS) == child,
		    "the pid-file test's child is up");
		in_workdir(path, sizeof(path), "live.pid");
		(void)snprintf(pidtext, sizeof(pidtext), "%ld\n", (long)child);
		write_file(path, pidtext, 0644);
		check(ncfg_process_pid_of_as(path, marker, owner) == child,
		    "a pid file naming its own process is taken");
		check(ncfg_process_pid_of_as(path, marker, asker) == 0,
		    "and one naming another user's process is not signalled");
		check(ncfg_process_pid_of_as(path, "/run/netcfgd-not-this-marker", owner) == 0,
		    "a live pid whose argv lacks the marker is refused");

		in_workdir(path, sizeof(path), "garbage.pid");
		write_file(path, "not a pid\n", 0644);
		check(ncfg_process_pid_of_as(path, marker, owner) == 0,
		    "a pid file with no number in it is refused");
		(void)snprintf(pidtext, sizeof(pidtext), "%ldabc\n", (long)child);
		write_file(path, pidtext, 0644);
		check(ncfg_process_pid_of_as(path, marker, owner) == 0,
		    "and so is one whose first line is a number and more");

		in_workdir(path, sizeof(path), "stale.pid");
		write_file(path, "4194304\n", 0644);
		check(ncfg_process_pid_of_as(path, marker, owner) == 0,
		    "a pid file outliving its process names nothing");
		in_workdir(path, sizeof(path), "never-written.pid");
		check(ncfg_process_pid_of_as(path, marker, owner) == 0,
		    "and a pid file that is not there is not an answer either");

		check(ncfg_process_terminate_group(child, message, sizeof(message)) &&
		    reap(child, PATIENCE_MS), "the pid-file child is taken back");
	}

	/* ---------------------------------------------------------------
	 * The real uid is read before the effective one.
	 * --------------------------------------------------------------- */
	{
		uid_t real = (uid_t)-1;
		uid_t effective = (uid_t)-1;

		check(ncfg_process_uids(-1, &real, &effective),
		    "this process has a status file with a Uid: line");
		check(real == effective, "an unprivileged test is not setuid");
		check(ncfg_process_ours(getpid(), real), "its own uid is its own");
		if (as_root) {
			/* `ours` accepts a root-owned process for every caller by
			 * design, so the refusal is not this process' to
			 * demonstrate -- the child at the unprivileged id above
			 * is where it is asserted. */
			printf("%-58s %s\n", "the refusal, on a root-owned process",
			    "skipped: shown on the unprivileged child instead");
		} else {
			check(!ncfg_process_ours(getpid(), stranger), "and no other's is");
		}
		check(ncfg_process_uids(0x00400000, NULL, NULL) == 0,
		    "a pid that cannot exist has no uids to read");
	}

	/* ---------------------------------------------------------------
	 * The process group, which is the whole reason a group is signalled.
	 * --------------------------------------------------------------- */
	{
		char command[256];
		pid_t child;
		pid_t grandchild;
		int survived;

		(void)snprintf(marker, sizeof(marker),
		    "/run/netcfgd-test-%ld-outer/hook.sock", (long)getpid());
		(void)snprintf(inner, sizeof(inner),
		    "/run/netcfgd-test-%ld-inner/hook.sock", (long)getpid());
		/* The work is a grandchild, which is what a hook that runs
		 * anything looks like. A second `sh` rather than `sleep` so that
		 * the grandchild carries a marker of its own and can be found --
		 * and so that a *zombie* grandchild cannot be mistaken for a
		 * live one, since a zombie carries no argv. */
		(void)snprintf(command, sizeof(command), "sh -c 'sleep 300' '%s' & wait", inner);
		child = spawn_shell(command, marker, (uid_t)-1);
		check(wait_for_marker(marker, mine, PATIENCE_MS) == child,
		    "the hook shell is up");
		grandchild = wait_for_marker(inner, mine, PATIENCE_MS);
		check(grandchild > 0 && grandchild != child,
		    "and it has forked the work into a grandchild");

		/* **The defect, asserted.** Signalling the child kills the shell
		 * and leaves the work running, reparented to init. Two `sleep
		 * 300` processes outlived a run that believed it had killed
		 * them. */
		check(ncfg_process_terminate(child, message, sizeof(message)),
		    "the child alone can be signalled");
		check(reap(child, PATIENCE_MS), "and it goes");
		survived = ncfg_process_pid_by_marker_as(inner, mine) == grandchild;
		check(survived, "which leaves the grandchild running: the measured defect");

		/* And the repair. The group outlives its dead leader, which is
		 * what makes this reach the orphan. */
		check(ncfg_process_terminate_group(child, message, sizeof(message)),
		    "the group can still be signalled after its leader has gone");
		check(wait_for_marker_gone(inner, mine, PATIENCE_MS),
		    "and the grandchild goes with it");
	}

	/* ---------------------------------------------------------------
	 * The signals, and the guards on what may be signalled.
	 * --------------------------------------------------------------- */
	{
		/* 0 and -1 are process groups, and "stop every process I may
		 * signal" is not a thing this should be able to express by
		 * accident. */
		static const pid_t refused[] = { 0, -1 };
		size_t i;
		int guarded = 1;
		int said = 1;

		for (i = 0; i < sizeof(refused) / sizeof(refused[0]); i++) {
			message[0] = '\0';
			if (ncfg_process_terminate(refused[i], message, sizeof(message))) {
				guarded = 0;
			}
			said = said && message[0] != '\0';
			message[0] = '\0';
			if (ncfg_process_kill(refused[i], message, sizeof(message))) {
				guarded = 0;
			}
			said = said && message[0] != '\0';
			message[0] = '\0';
			if (ncfg_process_hangup(refused[i], message, sizeof(message))) {
				guarded = 0;
			}
			said = said && message[0] != '\0';
			message[0] = '\0';
			if (ncfg_process_terminate_group(refused[i], message, sizeof(message))) {
				guarded = 0;
			}
			said = said && message[0] != '\0';
			message[0] = '\0';
			if (ncfg_process_kill_group(refused[i], message, sizeof(message))) {
				guarded = 0;
			}
			said = said && message[0] != '\0';
		}
		check(guarded, "0 and -1 are refused by every signal here");
		check(said, "and every refusal says why, which is base.h's convention");

		/* The state the caller asked for. A pid that cannot exist stands
		 * in for one that has exited: the kernel answers ESRCH either
		 * way. */
		check(ncfg_process_terminate(0x00400000, message, sizeof(message)),
		    "a process that is already gone is a stop that succeeded");
		check(ncfg_process_kill(0x00400000, message, sizeof(message)),
		    "and so is a kill of one");
		message[0] = '\0';
		check(!ncfg_process_hangup(0x00400000, message, sizeof(message)) &&
		    message[0] != '\0',
		    "but a reload of one did not happen, and says so");
	}

	/* ---------------------------------------------------------------
	 * Whose service, and which namespace.
	 * --------------------------------------------------------------- */
	{
		char unit[NCFG_UNIT_MAX];
		const char *ours = "netcfgd.service";
		size_t i;
		int exclusive = 1;
		static const struct {
			const char *theirs;
			const char *ours;
		} pairs[] = {
			{ "netcfgd.service", "netcfgd.service" },
			{ "dhcpcd.service",  "netcfgd.service" },
			{ NULL,              "netcfgd.service" },
			{ "dhcpcd.service",  NULL              },
			{ NULL,              NULL              }
		};

		/* The bug, as an assertion: netcfgd's own child. */
		check(!ncfg_process_supervised_by_another("netcfgd.service", ours),
		    "a process in netcfgd's own service is netcfgd's to signal");
		/* Somebody else's, which is the whole reason the guard exists: a
		 * killed `systemd-resolved` comes straight back. */
		check(ncfg_process_supervised_by_another("systemd-resolved.service", ours) &&
		    ncfg_process_supervised_by_another("dhcpcd.service", ours),
		    "and another manager's is not");
		/* In no service at all -- a shell, a hook, an init script that
		 * does not supervise. A kill holds for these. */
		check(!ncfg_process_supervised_by_another(NULL, ours),
		    "a process in no service at all is killable");
		/* Not being able to prove it is ours is not evidence that it
		 * is. */
		check(ncfg_process_supervised_by_another("dhcpcd.service", NULL),
		    "a service netcfgd cannot prove is its own may come back");
		check(!ncfg_process_supervised_by_another(NULL, NULL),
		    "and nothing supervised by nobody is held up by anybody");

		/* The pair guards one sweep, one arm skipping and one
		 * terminating, so an overlap would mean netcfgd killing its own
		 * client. */
		for (i = 0; i < sizeof(pairs) / sizeof(pairs[0]); i++) {
			int mine_ = pairs[i].ours != NULL && pairs[i].theirs != NULL &&
			    strcmp(pairs[i].theirs, pairs[i].ours) == 0;

			if (mine_ && ncfg_process_supervised_by_another(pairs[i].theirs, pairs[i].ours)) {
				exclusive = 0;
			}
		}
		check(exclusive, "a process is never both ours and another manager's");

		/* Whatever is running this may be in a service, a user scope or
		 * neither; what it may not do is fail to answer. */
		(void)ncfg_process_service_of(-1, unit, sizeof(unit));
		check(ncfg_process_service_of(0x00400000, unit, sizeof(unit)) == 0 &&
		    unit[0] == '\0', "a pid that cannot exist is in no service");
		check(!ncfg_process_in_our_service(0x00400000),
		    "and is not one of netcfgd's own children");

		check(ncfg_process_shares_network_namespace(getpid()),
		    "this process shares its own network namespace");
		check(!ncfg_process_shares_network_namespace(0x00400000),
		    "and a process that is not there fails closed");
	}

	/* ---------------------------------------------------------------
	 * Programs, by the kernel's name for them.
	 * --------------------------------------------------------------- */
	{
		char program[NCFG_PROGRAM_MAX];
		const char *names[1];
		ncfg_process_ref_t found[4];
		size_t total;
		size_t i;
		int saw_me = 0;

		check(ncfg_process_program_of(getpid(), program, sizeof(program)) &&
		    program[0] != '\0', "this process has a program name");
		check(strlen(program) <= 15,
		    "and comm is truncated to 15, which callers' lists must allow for");
		check(!ncfg_process_program_of(0x00400000, program, sizeof(program)),
		    "a pid that cannot exist has none");

		(void)ncfg_process_program_of(getpid(), program, sizeof(program));
		names[0] = program;
		total = ncfg_process_pids_of_programs(names, 1, found, 4);
		for (i = 0; i < total && i < 4; i++) {
			if (found[i].pid == getpid()) {
				saw_me = 1;
			}
		}
		check(total >= 1 && saw_me, "a program sweep finds this very process");
		check(ncfg_process_pids_of_programs(names, 1, NULL, 0) == total,
		    "and counts what it found even with nowhere to put it");
		names[0] = "netcfgd-no-such-program";
		check(ncfg_process_pids_of_programs(names, 1, found, 4) == 0,
		    "a program nothing runs is found nowhere");
	}

	/* ---------------------------------------------------------------
	 * `Permission denied` on an exec is two faults with two repairs.
	 * --------------------------------------------------------------- */
	{
		char *saved_path = getenv("PATH");
		char keep[4096];

		keep[0] = '\0';
		if (saved_path) {
			(void)snprintf(keep, sizeof(keep), "%s", saved_path);
		}
		in_workdir(path, sizeof(path), "client");
		write_file(path, "#!/bin/sh\nexit 0\n", 0644);
		check(ncfg_process_exec_refusal(path, EACCES, text, sizeof(text)) &&
		    strstr(text, "0644") != NULL && strstr(text, "no executable bit") != NULL,
		    "a program with no executable bit is named with its mode");

		/* And a file that *is* executable and was refused anyway: the
		 * mount. No mount is made here and none is needed -- the whole
		 * job is to read what is on disk and say which of the two
		 * remains. 0178 cost a day with the answer sitting in
		 * `findmnt`. */
		write_file(path, "#!/bin/sh\nexit 0\n", 0755);
		check(ncfg_process_exec_refusal(path, EACCES, text, sizeof(text)) &&
		    strstr(text, "noexec") != NULL && strstr(text, path) != NULL,
		    "an executable program refused anyway points at the mount");

		/* **Nothing to add is said by saying nothing**, so the caller's
		 * own message stands. */
		text[0] = '\0';
		check(!ncfg_process_exec_refusal(path, ENOENT, text, sizeof(text)) &&
		    text[0] == '\0', "a different errno is not this function's question");
		in_workdir(path, sizeof(path), "never-installed");
		check(!ncfg_process_exec_refusal(path, EACCES, text, sizeof(text)),
		    "and a program that is not there has nothing to look at");

		/* The `PATH` branch, which an absolute path never reaches: a
		 * bare name is looked up the way an exec looks it up. */
		(void)setenv("PATH", workdir, 1);
		check(ncfg_process_exec_refusal("client", EACCES, text, sizeof(text)) &&
		    strstr(text, "noexec") != NULL,
		    "a bare name is found along PATH, as an exec would find it");
		check(!ncfg_process_exec_refusal("netcfgd-never-installed", EACCES, text, sizeof(text)),
		    "and a bare name that is on no PATH entry is not invented");
		if (keep[0] != '\0') {
			(void)setenv("PATH", keep, 1);
		} else {
			(void)unsetenv("PATH");
		}
	}

	/* ---------------------------------------------------------------
	 * Privilege, read-only: the shed itself is `shed_test.c`, and has to
	 * be. A test that sheds disarms every other test in its binary.
	 * --------------------------------------------------------------- */
	{
		uint64_t effective = 1;
		uint64_t permitted = 1;
		uint64_t inheritable = 1;
		FILE *published = fopen("/proc/sys/kernel/overflowuid", "re");
		unsigned long kernels = 0;

		/* **The id to become is the kernel's, and it is never root.** Not
		 * `nobody` by name -- that means `getpwnam`, which means NSS,
		 * which is the C library this whole exercise keeps away from the
		 * privileged process. */
		check(nobody != 0, "becoming root is not dropping privilege");
		if (published && fscanf(published, "%lu", &kernels) == 1 && kernels != 0) {
			check((uid_t)kernels == nobody, "the kernel's own answer is the one used");
		} else {
			check(nobody == 65534, "and the compiled-in default where it publishes none");
		}
		if (published) {
			(void)fclose(published);
		}

		check(ncfg_privilege_held_capabilities(&effective, &permitted, &inheritable),
		    "what this thread holds can be read back from /proc");
		check(ncfg_privilege_effective_capabilities(&effective),
		    "and the effective set on its own");
		check(as_root == ncfg_privilege_is_root(),
		    "root by any of the three uids agrees with geteuid here");
		check(strstr(ncfg_shed_describe(NCFG_SHED_FULLY), "not root") != NULL &&
		    strstr(ncfg_shed_describe(NCFG_SHED_CAPABILITIES_ONLY), "still uid 0") != NULL,
		    "the two outcomes describe themselves differently");
	}

	/*
	 * `ncfg_process_become` in a child, because it is one-way.
	 *
	 * The security property is that a failure stops the exec: a hook that
	 * asked to be unprivileged must never run privileged instead. As root
	 * the drop succeeds and the child comes out at the unprivileged id; as
	 * an ordinary user `setgroups` refuses first, which is the failure the
	 * caller must not walk past.
	 */
	{
		pid_t child;
		int status = 0;

		fflush(NULL);
		child = fork();
		if (child == 0) {
			if (!ncfg_process_become(nobody, (gid_t)nobody, NULL, 0)) {
				_exit(1);
			}
			_exit(getuid() == nobody && geteuid() == nobody ? 0 : 2);
		}
		check(child > 0 && reap_status(child, &status, PATIENCE_MS) &&
		    WIFEXITED(status) &&
		    WEXITSTATUS(status) == (as_root ? 0 : 1),
		    as_root ? "a drop to the unprivileged id leaves nothing of root" :
		    "a drop that cannot be done fails rather than half-happening");
	}

	/* ---------------------------------------------------------------
	 * The two streams: which half exits, and which half must never.
	 * --------------------------------------------------------------- */
	{
		size_t i;
		int round_trip = 1;
		static const ncfg_severity_t levels[] = {
			NCFG_LOG_CRITICAL, NCFG_LOG_ERROR, NCFG_LOG_WARNING, NCFG_LOG_NOTE,
			NCFG_LOG_INFO, NCFG_LOG_VERBOSE, NCFG_LOG_DEBUG
		};
		static const char *const words[] = {
			"critical", "error", "warning", "note", "info", "verbose", "debug"
		};

		/* The order is the whole mechanism: a threshold only works if a
		 * more severe message compares as smaller. */
		check(NCFG_LOG_CRITICAL < NCFG_LOG_ERROR && NCFG_LOG_ERROR < NCFG_LOG_WARNING &&
		    NCFG_LOG_WARNING < NCFG_LOG_NOTE && NCFG_LOG_NOTE < NCFG_LOG_INFO &&
		    NCFG_LOG_INFO < NCFG_LOG_VERBOSE && NCFG_LOG_VERBOSE < NCFG_LOG_DEBUG,
		    "severities are ordered from most severe");

		/* **Info by default**, because a change of shape must not be a
		 * change of what an ordinary machine prints. */
		check(ncfg_log_accepted() == NCFG_LOG_INFO,
		    "the default level is what netcfgd printed before it had levels");
		check(NCFG_LOG_ERROR <= ncfg_log_accepted() &&
		    NCFG_LOG_NOTE <= ncfg_log_accepted() &&
		    NCFG_LOG_DEBUG > ncfg_log_accepted(),
		    "an error and a note are taken at it, and debug is not");

		/* Every level round-trips through the name `NCFG_LOG` takes, or
		 * the environment variable can name a level nothing selects.
		 * The words are literals on purpose: the enum is C's and the
		 * word is the operator's, and nothing but a test holds the two
		 * together. */
		for (i = 0; i < sizeof(levels) / sizeof(levels[0]); i++) {
			ncfg_severity_t back = NCFG_LOG_DEBUG;

			if (strcmp(ncfg_log_name(levels[i]), words[i]) != 0 ||
			    !ncfg_log_from_name(words[i], &back) || back != levels[i]) {
				round_trip = 0;
			}
			/* And the discriminant survives the atomic, which a
			 * wrong `accepted` arm would break silently. */
			ncfg_log_accept(levels[i]);
			if (ncfg_log_accepted() != levels[i]) {
				round_trip = 0;
			}
		}
		ncfg_log_accept(NCFG_LOG_INFO);
		check(round_trip, "every level is reachable by the name it prints");
		check(!ncfg_log_from_name("shouting", NULL),
		    "and a word that is not a level is not one");

		/* flog prints no label for the ordinary levels and a word for
		 * the rest, and this is the one place that could drift from it.
		 */
		check(strcmp(ncfg_log_label(NCFG_LOG_CRITICAL), "Critical") == 0 &&
		    strcmp(ncfg_log_label(NCFG_LOG_ERROR), "Error") == 0 &&
		    strcmp(ncfg_log_label(NCFG_LOG_WARNING), "Warning") == 0 &&
		    strcmp(ncfg_log_label(NCFG_LOG_NOTE), "!") == 0 &&
		    ncfg_log_label(NCFG_LOG_INFO) == NULL &&
		    ncfg_log_label(NCFG_LOG_VERBOSE) == NULL &&
		    strcmp(ncfg_log_label(NCFG_LOG_DEBUG), "Debug") == 0,
		    "the labels are flog's, including the ones it does not print");
	}

	{
		pid_t child;
		int status = 0;

		/*
		 * **A library never exits.** With stderr broken and `SIGPIPE`
		 * ignored -- which is what a daemon that talks to sockets does
		 * -- a log line that cannot be delivered is dropped and the
		 * process carries on to its own exit code. A daemon whose
		 * journal went away is still doing its job.
		 */
		child = fork_with_broken_stream(STDERR_FILENO, 1);
		if (child == 0) {
			ncfg_log_emit("test", NCFG_LOG_ERROR, "into a pipe nobody is reading");
			ncfg_log_emitf("test", NCFG_LOG_ERROR, "%s", "and again, formatted");
			_exit(7);
		}
		check(child > 0 && reap_status(child, &status, PATIENCE_MS) &&
		    WIFEXITED(status) && WEXITSTATUS(status) == 7,
		    "a log line nobody can receive does not end the process");

		/*
		 * **A program's output does end it, quietly, at 141.**
		 * `ncfg status | head -1` aborted with a Rust panic and four
		 * lines about `stdio.rs` at somebody who had done nothing
		 * wrong.
		 */
		child = fork_with_broken_stream(STDOUT_FILENO, 1);
		if (child == 0) {
			ncfg_out_line("a line nobody is reading");
			_exit(0);
		}
		check(child > 0 && reap_status(child, &status, PATIENCE_MS) &&
		    WIFEXITED(status) && WEXITSTATUS(status) == 141,
		    "a write to a reader that has gone leaves quietly at 141");

		/*
		 * And with the signal left at its default, which is the other
		 * half of what log.h promises: C has no Rust runtime ignoring
		 * `SIGPIPE`, so the kernel gets there first and the shell
		 * reports the same 141. The two dispositions have to be
		 * indistinguishable from outside or `| head` behaves
		 * differently depending on who called `signal`.
		 */
		child = fork_with_broken_stream(STDOUT_FILENO, 0);
		if (child == 0) {
			ncfg_out_line("a line nobody is reading");
			_exit(0);
		}
		check(child > 0 && reap_status(child, &status, PATIENCE_MS) &&
		    ((WIFSIGNALED(status) && WTERMSIG(status) == SIGPIPE) ||
		    (WIFEXITED(status) && WEXITSTATUS(status) == 141)),
		    "and 128 + 13 is what a shell reports either way");
	}

	/* ---------------------------------------------------------------
	 * Nothing of this test's is still running.
	 *
	 * The last check, and the one the rest of the file is arranged around:
	 * an orphan holding this binary's stderr is thirty seconds on every
	 * run, after the last assertion, for a test that had already passed.
	 * --------------------------------------------------------------- */
	{
		size_t i;
		int all_gone = 1;

		for (i = 0; i < spawn_count; i++) {
			/* Already reaped above; this is the backstop for a check
			 * that failed on the way and left one behind. */
			(void)ncfg_process_kill_group(spawned[i], NULL, 0);
			(void)reap(spawned[i], PATIENCE_MS);
		}
		for (;;) {
			int status = 0;
			pid_t got = waitpid(-1, &status, WNOHANG);

			if (got > 0) {
				continue;
			}
			/* `ECHILD` is the answer wanted: no child of this
			 * process remains, reaped or otherwise. A 0 means one is
			 * still running, which is the failure this exists to
			 * catch. */
			all_gone = got < 0 && errno == ECHILD;
			break;
		}
		check(all_gone, "no child of this suite outlives it");
	}

	remove_workdir();

	if (failures == 0) {
		printf("process_test: all checks passed\n");
	} else {
		printf("process_test: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
