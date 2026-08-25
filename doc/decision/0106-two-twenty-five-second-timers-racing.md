# 0106: two twenty-five-second timers racing

Status: accepted
Date: 2026-08-04
Milestone: the nm.sh flake 0105 left open, diagnosed

## Context

[0105](0105-a-fake-that-stopped-being-believable.md) closed nm.sh's seven
consistent failures and left one intermittent check: *"a cancelled prompt is
reported as such"*, roughly one run in five, with the mechanism recorded as a
guess — the wait for the fake agent's `registered` line breaking silently.

**That guess was wrong**, and so was the shape of the question. This is not a
test flake.

## What it actually is

`Register` is a synchronous D-Bus call, so the agent prints `registered` only
after the shim has taken it. The readiness signal was never the problem.

Measuring the activation instead, over eight runs:

```
took 0s status=4     (x7)
took 25s status=4    (x1)
```

**Twenty-five seconds is GDBus's default method-reply timeout**, and the guard
around the call was `timeout 25`. Two timers with the same value, racing:
whichever fired first decided what the failure looked like, and when the guard
won it killed nmcli and hid the only output worth reading.

With the guard moved off that number, the slow case gets to speak:

```
nmcli said: Warning: nmcli (1.52.1) and NetworkManager (1.44.0) versions don't match.
agent log:  registered
```

That is the whole finding. nmcli printed **nothing but its version warning** —
no cancellation message, no error — and **the agent was never asked for a
secret**, its log stopping at `registered`. So `ActivateConnection` returned no
reply at all for the full default timeout. It is a stall, not slowness, which is
why raising the guard does not fix it: the reply never comes.

## Where the stall is

In the shim, and its shape is legible from the code. `netcfgd-nm` uses zbus's
**blocking** connection, with a job queue that exists because — in its own
words — *"registering an object and emitting a signal are the two things a
D-Bus method handler cannot do from zbus's blocking API"*.

Asking an agent for a secret is an **outgoing** D-Bus call made while handling
an **incoming** one. That is the re-entrancy hazard the job queue was built to
avoid for two other operations, and the secret bridge (0031) makes a third
call of that shape without going through it. An intermittent no-reply that
unwinds exactly at the default timeout is what that looks like from outside.

**Not fixed here.** The fix is in the adapter's D-Bus re-entrancy and deserves
its own change with its own reasoning, not a hurried one at the end of a long
session. What is fixed is that the next person to see it is told what it is.

## Decision

**The guard is 60 seconds, off the value it was colliding with**, so nmcli's own
output survives to be read.

**The failure explains itself.** Where the message is absent, the check prints
what nmcli said, the agent's log, and the sentence that matters: *if the agent
log stops at `registered`, the shim never asked it.*

**The two silent give-ups in that section are loud.** The readiness wait
declares a failure of its own instead of breaking and running the activation
anyway; a killed nmcli says it was killed instead of contributing a zero to a
count.

## What building it found

**The same `set -e` mistake as `ppp.sh`, in the same session.** Capturing
nmcli's exit status meant assigning from a command that is *expected* to fail —
the agent cancels — and a bare assignment under `set -e` aborted the script
mid-way, leaving no summary and every later check unrun. `|| status=$?` is the
shape. Twice in one session is not bad luck; it is what this failure mode looks
like, and it is why "0 failed" must never be read as "all checks passed".

**A second, independent flake exists and is now isolated**: *"the nameservers
come from what was applied, not from the config"*, three checks together, about
two runs in ten. It is not this one — different section, different symptom — and
it is recorded rather than folded in.

## The lesson

**A guard set to the same number as the thing it guards will hide it.** Twenty-
five seconds was chosen for the timeout in this test and twenty-five seconds is
what GDBus waits for a reply; the collision meant that every occurrence
presented as "the test's timeout fired" rather than "the shim did not answer".
The information was one number apart the whole time.
