# 0132: netcfgd applies its configuration

Status: accepted
Date: 2026-08-21
Milestone: M8, decided by the copyright holder after a week of symptoms

Reverses the default of `on_drift`, and makes the tick that was already
documented as a backstop actually be one.

## What was wrong

`DriftPolicy::Report` was the default, with this reasoning:

> Say so and change nothing. The default, deliberately: over-claiming ownership
> deletes somebody's manual change, under-claiming only costs convenience.

Both halves are wrong.

**The first is a fear the design already answers, twice.**
`Ownership::may_remove` lets netcfgd remove only what netcfgd created, in one
function that no planner path routes around; and the planner's guards refuse a
disruptive action without explicit consent, in another. A reconciling daemon
cannot delete a hand-added address, because the ownership model does not let
it.

**The second cost far more than convenience.** netcfgd exists to configure a
machine's networking. A daemon that watches its own configuration go
unimplemented is not doing that -- it is a very careful observer. The holder
put it plainly: apart from an explicit `config -> apply` cycle it should always
apply settings, and re-apply one that has deviated.

Every symptom of this milestone was the same shape underneath: a configuration
written, a plan that was correct, and nothing that ran it. "Cannot reach the
supplicant" was the operator's name for it, and "the buttons don't work
properly" was the same fault seen from the other side -- a wifi pane whose
controls are all disabled because the radio has no supplicant, on a machine
whose configuration says it should.

## The tick was already a verification loop, unwired

`TICK_MS` is five seconds and its comment says it "catches anything neither
netlink nor the config watcher reports, and it is what makes a missed event
cost seconds rather than forever". The loop matched `Command::Tick => {}`.

So the backstop was described, built, delivered to the loop, and discarded. It
is consumed now, and that is what makes this a **verification and fix** loop
rather than an apply: the plan computed on each pass *is* the verification, and
its actions are the fix. A tick that finds nothing outstanding costs one
observation and stops.

## Decision

- **`DriftPolicy::Reconcile` is the default.** `report` and `ignore` remain,
  per interface, for somebody who wants them.
- **A tick verifies and fixes**, so a deviation nothing announced is corrected
  within seconds rather than never.
- **`radio_set` applies before it answers.** The daemon would reach the same
  state within a tick; what the synchronous apply buys is a truthful reply, and
  a client that scans the moment it is told the radio is netcfgd's does not
  scan a radio with no supplicant.

## `--no-apply-on-start` becomes a latch

The flag says the daemon should observe and be told when to act. Once the loop
reconciles on its own, that has to keep meaning something -- otherwise the flag
delays acting by one tick and no more, and the **protected first apply** it
exists for cannot happen. The confirm window on `ncfg apply` is there because
the first apply after a boot is the one that can take the network away.

So it holds until an explicit apply arrives, and then the machine is netcfgd's
like any other.

**Only the acting is held.** The first version of this gated the observation
too, and that is worse than not looking: the daemon went on planning against
what it saw at startup, so it answered `apply` with work for a machine that had
since moved -- and reported success. `hooks.sh` caught it, because its tampered
hook was never reached by an apply whose plan predated the tampering.

## What the live suite had to be told

Two checks described a machine that no longer exists, and both are the decision
working rather than breaking:

- **`nm.sh`** deleted a dummy and waited for it to leave NetworkManager's
  device list. netcfgd creates it again, correctly and within a tick, so it
  never left. The check hands the interface over with `managed = false` first,
  which is the documented way to say a device is somebody else's -- and is what
  makes "gone" stay gone.
- **`confirm.sh`** asserts nothing is configured before the first apply, which
  is exactly what the latch above preserves.

## Consequences

**A machine's networking now follows its configuration without being asked**,
which is the program's purpose and was not its behaviour.

**An operator who wants the old behaviour writes it down**: `on_drift =
"report"` per interface, or `--no-apply-on-start` for a daemon that waits to be
told. Both are still there; neither is the default.

**The socket's `on_drift_default` moved from `report` to `reconcile`**, which
is a minor witness change and a visible one: a client that reads globals sees
the new default.
