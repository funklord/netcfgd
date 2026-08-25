# 0079: netcfgd stops restarting what will not stay up

Status: accepted
Date: 2026-08-03
Milestone: the same session as 0078, and the defect 0078 introduced

## Context

[0078](0078-a-record-is-a-memory-and-a-process-is-a-fact.md) made the observation
notice a daemon that died on its own, and the planner restart it -- which is what
a reconciler is for. Its own "what is still open" said the restarting was
unconditional and that a daemon dying immediately would be restarted forever, and
called that a thing to think about later.

Measured instead of thought about later. A fake tunnel that starts, lives half a
second and exits, on an interface with `on_drift = "reconcile"`, with the daemon
running:

```
starts in 12 seconds, before 0078:            1
starts in 12 seconds, after 0078:           181
```

Fifteen a second. Every one forks a process, writes a log line and produces
netlink events that wake the reconcile loop again. On the default drift policy --
`report` -- the daemon does not act at all and the count stays at one, which is
why this did not turn up in any test: **the storm needs an interface somebody set
to `reconcile`, which is exactly the operator who asked netcfgd to keep things
running.**

So the note in 0078 was describing a live defect rather than a future concern, and
this is the same session correcting it.

## Decision

**netcfgd starts a backend five times, and then stops and says so.**

The count is of *consecutive starts that did not lead to a live process*, kept in
`/run/netcfgd/state.json` beside everything else netcfgd remembers, and it is
cleared by three things:

- **the backend being seen running.** A daemon that is alive has stayed up, and
  whatever it did last week is not a reason to stop trying now. This is the one
  that keeps the counter honest, and it arrives through the effects: the executor
  already receives the observation, so what it saw travels to the recorded state
  along with what it did;
- **a deliberate stop.** The document stopped asking; nothing is being attempted;
- **the plan that gives up**, once the operator has changed something -- because
  the first clear above fires the moment the daemon does stay up.

**No clock, deliberately.** A plan is pure, and a count of consecutive starts says
the same thing about a daemon that dies instantly and one that dies after a
minute -- with the difference that the second takes five minutes to reach the
limit, which is the right shape: something that nearly works gets more patience
than something that never starts.

**Five.** Enough for a daemon that is slow to settle, few enough that a flapping
one stops within a second or two rather than filling a log.

And it says why, per interface, in the plan's warnings: *"netcfgd has started the
`OpenVpn` backend on vpn0 5 times and it has not stayed up; not starting it again.
Whatever it says about why is in /run/netcfgd, and the count clears the moment it
is seen running -- or when the document stops asking for it."* A tunnel that
silently stopped being retried would be the same shape of defect as one retried
forever.

## What it does not stop, and that is deliberate

The same measurement afterwards:

```
starts in 12 seconds, with the limit:        10
```

Ten, not five, because that fake genuinely *does* come up -- it writes its pid,
an observation catches it alive, and the counter clears. What is left is a daemon
that starts, works briefly and dies, restarted about once per second-and-a-half:
each of those is a real "it died again" event and restarting is the correct answer
to it. **A flapping daemon is still restarted indefinitely; a daemon that never
comes up is not.** That is the line this draws, and it is the line worth drawing:
the first is a network that keeps coming back, the second is a loop.

## Consequences

- The observed model carries `backend_restarts`, so the witness moved. Minor:
  a field was added and nothing that existed changed shape.
- A backend that has hit the limit is not started even by an explicit `ncfg
  apply`, until something clears the count -- which the operator does by fixing
  the daemon (it stays up, the count clears) or by taking it out of the document
  and putting it back. That is a deliberate trade against a retry that a person
  has to watch fail five more times.
- `+4 KB`, ratcheted, for this and 0078 together.

## What is still open

**Nothing tells the operator how to clear it in the moment.** The warning says
what clears the count; it does not offer a command. `ncfg apply --retry` or
similar would be one line of argument parsing and a reset -- worth adding the
first time somebody hits this on a real machine and finds the sentence
insufficient, and not before, because a flag nobody needs is another key that
compiles and does nothing (0061).

**A daemon that is alive and wedged still counts as up**, unchanged from 0078: the
pid says the process exists, not that it is doing its job.
