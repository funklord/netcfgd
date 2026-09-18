# 0262: a test that disarms the process it shares

Status: accepted
Date: 2026-09-18
Milestone: M9; the window can configure the machine

## Two symptoms, neither of which mentioned the cause

**Thirty seconds.** Every run of `cargo test -p netcfgd-sys` sat for thirty
seconds after its last assertion. The harness said `finished in 30.00s` and the
wall clock agreed; the same suite with one test filtered out said
`finished in 0.02s` and still took thirty seconds.

**An intermittent `chmod: PermissionDenied`**, as root, in
`a_program_with_no_executable_bit_is_named_with_its_mode` -- a test about file
modes, which passes alone and passed on the next run.

Both are one cause and one accomplice.

## The cause: a test that sheds privilege

`shed` takes a thread's capabilities and, where there is an unprivileged id to
become, its uid. POSIX makes credentials a property of the **process**, so
glibc broadcasts the change to every thread -- nptl calls it setxid -- and the
whole binary is uid 65534 from that moment. Rust runs the tests of one binary
as threads in one process.

**The crate said so itself.** The test's own doc comment: *"It is also why every
test that runs after this one in a root run is running as 65534."* It was
written as an observation about the shed and read by nobody as a fact about the
suite.

What that does to siblings still running: a `chmod` on a file made a moment
earlier as root becomes `EPERM`, and a `kill` of a root-owned child becomes
`EPERM` too -- and the test that had just killed its child then calls `wait`,
which blocks until the `sleep 30` inside it finishes on its own.

So the thirty seconds and the chmod are the same disarmament, landing on
whichever test the scheduler had in flight.

**The remedy is that an integration test is a binary of its own.** The shed
moved to `crates/netcfgd-sys/tests/shed.rs`, unchanged in what it asserts, and
disarms nothing but itself. It needed one thing it could not take with it --
the crate's private `is_root` -- and asks `/proc/thread-self/status` for the
same four uids instead, which is the file the test already reads for
capabilities.

## The accomplice: a shell that forks

Underneath that, four tests spawn `sh -c 'sleep 30' <marker>` and kill the
child. `sh -c` with a command to wait for **forks** it, so the sleep is a
grandchild: killing the child kills the shell and leaves the sleep reparented
to init, holding the test binary's stderr -- which `cargo test` reads until
every writer is gone. Thirty seconds, for a test that had already passed.

This is the defect `netcfgd_sys::process::terminate_group` exists for, in the
same file, whose documentation says *"the caller must have put the child in its
own group -- `Command::process_group(0)`"* and records having measured two
`sleep 300` processes outliving a run that believed it had killed them. The
production code learned it; the tests beside it did not.

Measured separately, so that each half is known to matter: with the shed moved
out and the groups not fixed, thirty seconds. With the groups fixed and the
shed left in, thirty seconds. With both, **3.94 seconds** -- ten consecutive
runs between 3.92 and 3.96, no failures.

## The gate

Neither regression is visible in a failure: one line removed brings back a
thirty-second suite and an `EPERM` about file modes. `tool/disarm_gate.py`
refuses both -- a `shed()` in a unit test, and a `Command::new("sh")` that is
`spawn`ed in a test without `process_group`.

It reads only the test halves, and only shells that are **spawned**: `.output()`
and `.status()` wait for the shell, which waits for its own child, so nothing
can be left behind. Narrowing it to that turned four false positives in other
crates -- `sh -n` syntax checks and scripts run to completion -- into no
findings at all.

Its own first version was wrong in the direction that passes: the pattern for
the call forbade a `:` before it, which excluded `super::shed()`, the one
spelling that matters. The sabotage found it, which is the argument for running
one against a gate as well as against the code.
