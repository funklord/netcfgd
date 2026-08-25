# 0111: a stop is not a scan

Status: accepted
Date: 2026-08-05
Milestone: measuring a note instead of filing it

## Context

0109 ended with a paragraph that read like housekeeping:

> **The ten-second wait before that failure is left alone.** It is `connect`'s
> default reply timeout, generous because `SCAN_RESULTS` on a busy band is not
> instant. A stop is not a scan and could reasonably use the one-second deadline
> 0085 gave the ACL read -- but shortening a deadline is its own decision with
> its own measurements, and a stop happens when the document changes rather than
> on every netlink event, so it does not hold the reconcile loop the way the ACL
> read did. Recorded as open rather than changed in passing.

Every clause of that is true except the one that matters, and the project had
already written down how to catch it: *a note in "what is still open" is worth
measuring before it is believed*, the lesson 0079 paid for when "restarting is
unconditional" turned out to be 181 starts in twelve seconds.

## What the measurement said

A stop does not happen on every netlink event. But it is *retried* on the next
reconcile, because 0109 made a failed stop fail-stop -- and the reconcile loop
is what runs it. So the wait is not once, and it is not off the loop.

The laptop feature is the one to measure it on, because it is the one with no
operator in it: cable out, wifi takes over, nobody runs a command. With a wedged
access point recorded and the document no longer asking for it:

| | switch to wifi |
|---|---|
| nothing wedged | **106ms** |
| wedged access point | **12.2 seconds** |

Twice each, ~100ms and ~12.2s both times. The carrier event is sitting behind a
`PING` inside `connect`, in a stop for an entirely unrelated interface.

That is the same stall 0085 measured at 10.2 seconds on the ACL read and cured
with a deadline. The read got one. The stop kept the client's default, and the
default was chosen for `SCAN_RESULTS` on a busy band.

## Decision

**`STOP_TIMEOUT`, one second, used by both stops.** The same number 0085 gave
the read, deliberately: it is enormous for a local unix datagram round trip, and
the symmetry is worth more than a tighter figure nobody can justify later.

Both, because they are one mechanism -- the hostapd stop and the supplicant stop
in `netcfgd-apply` -- and 0109 already established that fixing one of these and
not the other leaves a daemon that netcfgd reports as stopped while it holds a
radio.

Afterwards: **106ms clean, 3.0 seconds wedged.** The remaining three seconds are
three one-second deadlines and not one -- the observation reads the ACL of a
running access point, the stop connects, and the observation runs again after
the apply. Each is 0085's deadline doing what it was put there to do, and
shortening *those* is a different decision that has not been measured.

**What this costs.** A healthy hostapd that is merely slow now fails its stop
instead of being waited for; `acl.sh` has seen a healthy fake miss a one-second
deadline on a saturated machine. That failure is loud, fail-stop and
re-runnable, and it leaves the backend recorded (0109). The thing it replaces is
neither loud nor recoverable, and it happens on a *working* machine rather than
a busy one -- every other interface waits ten seconds because one access point
is wedged.

## The gates

`acl.sh` already runs an apply against a wedged access point, for 0109. It is
timed now, against the same four-second threshold the wedged-plan check beside
it uses and for the same reason: wall clock on whatever machine runs the suite,
still nowhere near ten. Restoring `Client::connect` turns it red with
`slow: 11s`.

The 12.2-second figure came from a probe rather than a suite script, and the
probe is not kept. What it needs -- a daemon, two veth uplinks, a wedged access
point and a carrier event -- is `switch.sh` plus `acl.sh`'s fake, and building
that into a permanent script would be a third copy of both. The timed check
above catches the regression this record is about, in the place the defect
lives.

## What this says about the method

**An open note is a claim, and claims get measured.** This one was written
carefully, cited the right precedent, drew the right distinction between a stop
and a scan -- and then reasoned its way to "so it does not hold the reconcile
loop", which was the only part that could have been checked in ten minutes and
the only part that was wrong.

Twice now, in the same tree: 0079's "a backoff needs state that needs a home"
and this one. Both were accurate about the design and wrong about the urgency,
and both read as something to file. The tell is the same each time -- a note
that says what *would* be needed rather than what is happening now.
