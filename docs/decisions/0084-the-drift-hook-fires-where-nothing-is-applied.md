# 0084: the drift hook fires where nothing is applied

Status: accepted
Date: 2026-08-04
Milestone: one of the four hook phases §10 lists as recognised and never run

## Context

Eleven hook phases are declared, seven fire, and four have never run: `pre_down`,
`roam`, `portal` and `drift`. Each has a different reason. `pre_down` is deferred
with a stated one -- it and `down` would fire at the same point, and telling them
apart needs a teardown ordering netcfgd does not have (0063). `roam` wants the
supplicant's event socket. `portal` wants captive-portal detection, which does
not exist anywhere in the tree.

`drift` wanted nothing. Detection has been there since M2: the daemon plans on
every netlink and config event, and any action on an interface whose policy is
not `ignore` becomes an `Event::Drift` on the socket. The event has the interface,
what moved, and what netcfgd is about to do about it. Nothing ran a script.

## Why it could not be a plan action

Every other phase is an `Op::HookRun` in a plan, which is what lets `ncfg apply`
exercise all of them and `tests/live/hooks.sh` drive the lot with one command.

That does not work here, and the reason is the phase's whole point. Under
`on_drift = "report"` netcfgd plans and **applies nothing** -- that is what
`report` means. A `HookRun` action would be planned and never executed, so the
one policy whose entire purpose is *"tell me, do not touch it"* would be the one
where nothing told anybody. Under `reconcile` it would work, which is the half
that needs it least: something is already putting the machine back.

**The hook is the telling.** So it runs from the daemon at detection, beside the
broadcast that already goes to socket subscribers, and before the reconcile --
so a script sees the machine as it drifted rather than as netcfgd has just put it
back. Under `reconcile` that window is milliseconds and the ordering is the only
thing that makes the hook worth having there at all.

`FIRED_PHASES` in the planner therefore does not list it, and a second list does:
the warning an operator reads is answering "will my script run", not "will it
appear in a plan".

## Firing once

Drift under `report` does not go away. The address stays deleted, and the next
netlink event -- any netlink event, on any interface -- re-runs detection and
finds it again. A hook that fired on the drift being *present* rather than on its
*appearance* would run somebody else's script for as long as the operator left
the situation alone.

That is [0079](0079-netcfgd-stops-restarting-what-will-not-stay-up.md)'s restart
storm in a different costume, and worse: this one executes an arbitrary script.
Measured rather than argued -- with the guard removed, three unrelated interface
add/deletes turn one hook run into **seven**.

The guard is the record `carrier` and `lease` already keep: what a phase was last
told, per interface, in `/run`. Same mechanism, no new state. What it compares is
the summary -- what changed -- and not the action, so a hook that has already seen
this drift stays quiet even if the policy moved underneath it.

It is recorded whether or not the script succeeded, and whether or not the
interface declared one. The first is 0064's call for `lease` and the same
argument: a hook that failed and was retried on every observation is the storm
again. The second keeps "has this drift been seen" independent of whether
anybody was listening.

## What the script is told

`NCFG_REASON` is what drifted, in the daemon's own words -- the same sentence the
socket event carries. `NCFG_ACTION` is what netcfgd is going to do about it:
`reported only`, `reconciling`, or `blocked; <what to pass>` where a guard is
refusing. That second variable is the only thing that differs between the
policies, which is what lets one script be written and behave correctly under
both.

`NCFG_ACTION` goes through `HookEnv::with` rather than a new field. The named
fields are the ones several phases share; a phase with something of its own puts
it in `extra` rather than growing a field every other phase leaves empty.

Never a veto. The drift has happened, and whether netcfgd reconciles it is not
this script's to decide.

## The gates

`tests/live/drift.sh`, against a real kernel and **a running daemon** -- the first
live script here that needs one rather than an `ncfg apply`, which is exactly the
consequence of not being a plan action. Twelve checks over both policies: it
fires, it is told the interface, the action and the reason, netcfgd still
reconciles under `reconcile`, and it does not fire again while the same drift
persists.

Three breaks:

- **not running the hooks at all** -- six checks red;
- **removing the de-duplication** -- one hook run becomes seven;
- **not persisting what was told** -- one becomes seven again, which is what
  proves the `/run` write is where the memory lives.

The third break is the useful one, because a fourth did *not* fail. The first
version also copied the record into the in-memory observation, with a comment
explaining why that was necessary. Breaking that line changed nothing:
`reobserve` reads the record back and runs before every drift check. The line
went rather than the comment -- an explanation of why something is load-bearing,
sitting above something that is not, is the same disease as a gate that cannot
fail.

## What this does not settle

The other three phases are untouched and their reasons are unchanged. `drift` was
reachable because netcfgd already knew the thing the phase is named after; none
of the other three is in that position.
