/*
 * shed_test.c -- shedding privilege, in a process of its own.
 *
 * WHY THIS IS A BINARY OF ITS OWN, AND WHY NOTHING ELSE IS IN IT
 *   **This test disarms the process it runs in, so it may not share one.**
 *   Where the shed reaches `NCFG_SHED_FULLY` there is an unprivileged id to
 *   become, and POSIX makes credentials a property of the *process*: glibc
 *   broadcasts the change to every thread, so the whole binary is uid 65534
 *   from that moment.
 *
 *   What that cost when it shared a binary, measured rather than supposed: an
 *   intermittent `chmod: PermissionDenied` in a test about file modes, and
 *   **thirty seconds on the clock of every run of that crate's tests** -- a
 *   `kill` of a root-owned child returning `EPERM` after the broadcast, leaving
 *   a `wait` blocked on a `sleep 30` that nothing could signal. Neither failure
 *   mentions privilege. Decision 0262, and `tool/disarm_gate.py` is the gate
 *   that keeps it from coming back.
 *
 *   So: one file, one subject. Everything else about `process.h` is in
 *   `process_test.c`, which stays root for as long as it needs to signal its
 *   own children.
 *
 * WHAT IT CAN PROVE, AND FROM WHERE
 *   **Shedding is only observable from something that had something**, and a
 *   process can be measured shedding exactly once -- it is one-way, which is
 *   the property that makes it worth having. As an ordinary user the effective
 *   set is already empty, so "zero afterwards" would hold without the call: the
 *   run says so rather than claiming a drop it did not make, and what it still
 *   asserts is real -- that the call succeeds, that `no_new_privs` is set, and
 *   that there is no way back to uid 0. As root, or under `unshare -r`, the
 *   set starts full and the drop is the whole thing.
 *
 * WHY NO THREAD, WHERE THE RUST USES ONE
 *   The Rust sheds on a worker thread to show the two halves of the fact above:
 *   capabilities are per-thread and the uid is not, so `NCFG_SHED_FULLY` takes
 *   the other threads' capabilities with it and `NCFG_SHED_CAPABILITIES_ONLY`
 *   leaves them exactly as they were. Measured, one thread calling `setuid`
 *   while another read `/proc/thread-self`:
 *
 *       main before: uid 0     CapEff 000001ffffffffff
 *       main after:  uid 65534 CapEff 0000000000000000
 *
 *   That is glibc's behaviour rather than netcfgd's -- nptl calls it setxid --
 *   and asserting it here would mean linking a thread library into a suite
 *   whose Makefile links none, for a fact about the C library. The part that is
 *   netcfgd's is which outcome the shed reaches and what it promises about the
 *   calling thread, and that is what is asserted. process.h carries the
 *   reasoning where a caller will read it: **call this from `main` in a freshly
 *   `exec`ed image that has not spawned anything**, because a worker that sheds
 *   in a threaded process looks like it has disarmed one and has not.
 *
 * WHY IT LEAVES BY A DIFFERENT DOOR UNDER ASan
 *   **A process that has fully shed cannot be leak-checked, and this one ends
 *   by saying so rather than by dying.** LSan runs at exit and stops the world
 *   to do it, which means reading `/proc/self/task` -- and a `setuid` away from
 *   uid 0 clears the process' dumpable flag, so those files become root's and
 *   this process is no longer allowed to read its own. As root, a sanitized
 *   build therefore used to end with `LeakSanitizer has encountered a fatal
 *   error` and status 1 **after every check above had passed**, taking the
 *   checks' own output with it, because LSan dies without flushing stdio. It
 *   was this test succeeding that broke it, and it broke `make SANITIZE=1 test`
 *   for the whole suite: forty-one other binaries reported through a target
 *   that failed.
 *
 *   So where the shed reached `NCFG_SHED_FULLY`, the exit is `_exit`, which
 *   runs no `atexit` handler and so never reaches the leak check. What is given
 *   up is real and is only what was never available: leak coverage of this one
 *   binary on a root run. Under `unshare -r` the shed reaches capabilities-only,
 *   uid 0 remains, the process stays dumpable, and the return is an ordinary
 *   one with the leak check behind it. `ASAN_OPTIONS=detect_leaks=0` is no
 *   longer needed for either.
 */
#include "ncfg/base.h"
#include "ncfg/process.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

#ifndef PR_GET_NO_NEW_PRIVS
#define PR_GET_NO_NEW_PRIVS 39
#endif

static int failures;

static void check(int condition, const char *what)
{
	printf("%-58s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

int main(void)
{
	char err[NCFG_ERROR_MAX];
	uint64_t effective = 0;
	uint64_t permitted = 0;
	uint64_t inheritable = 0;
	uint64_t before = 0;
	ncfg_shed_t reached = NCFG_SHED_CAPABILITIES_ONLY;
	ncfg_shed_t again = NCFG_SHED_CAPABILITIES_ONLY;
	int was_root;

	/* A ceiling on the whole binary, using the thing it is testing. Nothing
	 * here blocks, and a shed that somehow did would otherwise hang a suite
	 * that has no other timeout. */
	ncfg_privilege_die_after(30);

	check(ncfg_privilege_effective_capabilities(&before),
	    "what this thread holds is readable before anything is given up");
	was_root = ncfg_privilege_is_root();
	if (before == 0) {
		printf("shed_test: this thread starts with no capabilities (CapEff 0), so\n"
		    "           the drop below proves the call rather than the loss.\n"
		    "           `unshare -r` gives a full set, which is how `make live`\n"
		    "           runs the Rust equivalent.\n");
	} else {
		printf("shed_test: starting from CapEff %llx, root=%s\n",
		    (unsigned long long)before, was_root ? "yes" : "no");
	}

	err[0] = '\0';
	check(ncfg_privilege_shed(&reached, err, sizeof(err)) && err[0] == '\0',
	    "the shed succeeds, and says nothing when it does");
	printf("shed_test: reached %s\n", ncfg_shed_describe(reached));

	/* **The outcome, not the steps.** Two of the calls inside are allowed to
	 * fail on a machine that had nothing to give up, so what is asserted is
	 * the end state: nothing effective, nothing permitted, nothing
	 * inheritable. */
	check(ncfg_privilege_held_capabilities(&effective, &permitted, &inheritable),
	    "and what this thread holds is still readable afterwards");
	check(effective == 0 && permitted == 0 && inheritable == 0,
	    "the calling thread keeps no capability of any of the three kinds");

	/* Step 1, which is what makes the rest of the order forgiving: nothing
	 * from here on can be undone by executing something with a setuid bit. */
	check(prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1,
	    "no_new_privs is set, so no setuid binary is a way back");

	if (reached == NCFG_SHED_FULLY) {
		check(!ncfg_privilege_is_root(),
		    "a full shed leaves none of the three uids at 0");
		/* **It has no inverse**, which is the whole point. The assertion
		 * is available to an ordinary user too, where it is trivially
		 * true; the case it is written for is the one where this process
		 * was root a moment ago and a saved-set uid of 0 would have been
		 * a `seteuid` away. */
		check(setuid(0) != 0 && errno == EPERM, "and uid 0 cannot be taken back");
		printf("%-58s %s\n", "started as root with something to drop",
		    was_root && before != 0 ? "yes" : "no: nothing was given up here");
	} else {
		/* `unshare -r` maps uid 0 and nothing else, so 65534 does not
		 * exist to move to and the kernel refuses. Being uid 0 there is
		 * not being the machine's root: it is a mapped id with no
		 * authority outside the namespace, so capabilities-only is the
		 * whole of what privilege there was. */
		check(ncfg_privilege_is_root(),
		    "capabilities-only is exactly the case where uid 0 remains");
	}

	/* Calling it twice is safe and reports the same thing, which is what
	 * one-way means: there is no state left for a second call to find. */
	check(ncfg_privilege_shed(&again, err, sizeof(err)) && again == reached,
	    "a second shed finds nothing left and says the same as the first");

	if (failures == 0) {
		printf("shed_test: all checks passed\n");
	} else {
		printf("shed_test: %d check(s) failed\n", failures);
	}

	/* The header's last section. `_exit` skips every `atexit` handler, and
	 * the one that matters is LSan's -- which would abort this process for
	 * being unable to read its own `/proc` rather than for anything it
	 * allocated. The flush is not optional: `_exit` does not do it, and
	 * everything printed above is still in the buffer when stdout is a pipe.
	 * Where nothing was shed there is nothing to work around, so that case
	 * returns and keeps its leak check. */
	if (reached == NCFG_SHED_FULLY) {
		fflush(stdout);
		_exit(failures == 0 ? 0 : 1);
	}
	return failures == 0 ? 0 : 1;
}
