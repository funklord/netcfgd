# 0123: a hook that never exits is killed, because the loop is behind it

Status: accepted
Date: 2026-08-19
Milestone: bounding the last unbounded thing the daemon does inline

## Context

`hooks::run` executed a hook with `Command::status()` and waited for as long
as the hook took. There was no bound.

The reconcile loop is single threaded on purpose -- `server.rs` says so in its
first paragraph, "one channel to the loop", which is what keeps the daemon's
state free of locks -- and the executor is called inline from it
(`netcfgd-daemon/src/lib.rs`). So a hook that never exits does not stall its
own transition. It stalls **everything**: no `status`, no `plan`, no reply to
any request, no netlink processing, in a process holding `CAP_NET_ADMIN`. The
daemon looks dead, and the two commands an operator reaches for when the
network stops are the two that cannot answer.

Hooks are operator-authored, so this is self-inflicted rather than an attack.
That does not make it less worth bounding: a script that reads from a pipe
nobody writes, or waits on a host that has gone away, is an ordinary mistake,
and "my daemon hung and I cannot ask it why" is the worst shape a diagnosis
can take.

Design section 5.2 fixes what a hook's *exit status* means -- non-zero from a
`pre_*` aborts the transition, `post_*` failures are logged and do not roll
back -- and says nothing about one that never exits. `HookRef` has carried a
`timeout: Option<u32>` field since the model was written; nothing ever set it
and nothing ever read it.

## Decision

**A hook is bounded in time, and a timeout is a failure.**

- **Sixty seconds by default**, from `HookRef::timeout` where the hook sets
  one. Sixty because the honest slow cases are real: a `pre_up` waiting for a
  peer, or a `post_up` bringing a tunnel to a far end, takes tens of seconds
  and is not misbehaving. It bounds damage rather than expressing a target.
- **`SIGTERM`, then `SIGKILL` after five seconds** -- to the process
  **group**, not the process. The same argument
  `netcfgd-sys::process::terminate` already makes everywhere else: a script
  that traps `TERM` to tear down what it built deserves the chance, and a
  `SIGKILL` arriving first is how a half-configured interface is left behind.
  The child is reaped either way, so a killed hook does not become a zombie
  for the life of the daemon.

  **The group is the part that was got wrong first, and it matters.** A hook
  is a script: `sleep 300` in a `#!/bin/sh` file is a *grandchild*, because
  the shell forks it. The first version of this signalled the child, killed
  the shell, and left the sleep running and reparented to init -- so the
  daemon stopped waiting and the work it was waiting for carried on. That is
  half the point of a bound, and the missing half does not show up in any
  assertion about return values: the suite reported success and left two
  orphans behind. It was found by `running-code.md`'s check for what is still
  running after a run, and the test asserts the grandchild's death by reading
  `/proc/<pid>/cmdline` rather than with `kill -0`, which calls a zombie
  alive.
- **The phase decides what the failure means**, exactly as it does for a
  non-zero exit. A hung `pre_up` vetoes the transition; a hung `post_up` is
  noted. This is not a new rule, it is section 5.2 applied to one more way of
  failing.

## Why a timeout is a failure rather than a pass

The alternative is to kill the hook and carry on. It is tempting for
`pre_*`, because vetoing means a hook bug takes the network down.

It is the wrong way round. A `pre_up` hook exists to be able to say no --
that is the whole of what a veto phase is for -- and a hook that was asked
and did not answer has not said yes. Treating silence as consent means the
one case where the check mattered most, the check that got stuck, is the case
it does not run. An operator who wants a hook that cannot veto has a phase
for that already.

## Rejected

**Running hooks on their own thread.** It removes the stall without needing a
number, and it breaks the property the loop is built on: the state is free of
locks *because* one thread touches it, and a hook that outlives its
transition would be running against a state that has moved on. The bound is
cheaper and does not trade away the design.

**No default, only per-hook timeouts.** A field nobody sets is what this
already had, and it bounded nothing. The default is what makes the bound
real; the field is what makes it adjustable.

## What is not settled

**The config language has no `timeout` key on a hook block.** `HookRef` can
carry one and the runner honours it, but nothing lowers one from config, so
today every hook gets the default. Adding the key is a small change to the
hook lowering and is worth doing when somebody has a hook that needs it --
writing grammar for a case nobody has met is how a config language grows
options nobody uses.

**`run_as` has the same shape and is worse.** It is also `Option` on
`HookRef`, also always `None`, and also never read -- but where an unread
`timeout` merely fails to bound, an unread `run_as` means a hook that asked
to drop privilege does not. Nothing sets it today so nothing is broken, and
it is recorded here rather than fixed because the fix is a separate piece of
work with its own security argument.
