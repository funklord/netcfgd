# 0109: a daemon that does not answer has not stopped

Status: accepted
Date: 2026-08-05
Milestone: found by chasing a flaky live check to the end

## Context

`acl.sh` failed about one run in ten under load, on the check that stopping an
access point asks hostapd to `TERMINATE`. The apply said:

```
ok   backend.stop ap0  access_point: <absent> (was AccessPoint)
```

and the fake hostapd's log held six bytes: `ready`. It had been sent nothing.

Two readings were possible -- netcfgd never sent the command, or the fake had
not been scheduled to write its log inside the test's bound -- and load is a bad
place to tell them apart. So the state was produced deliberately instead:
`SIGSTOP` the fake, which is a hostapd that is running, has its socket bound,
and does not answer. That is a state a real hostapd reaches, and one nothing
else in this tree had ever asked netcfgd about.

## What it found

```
apply exit: 0  elapsed: 11s
  ok   backend.stop ap0  access_point: <absent> (was AccessPoint)
fake still alive: YES
run state backends: []
```

Three separate wrongs in four lines:

- **The operator was told the access point stopped.** It is still on the air,
  still authenticating clients with the passphrase it read at startup.
- **`ncfg apply` exited 0**, so anything scripted around it carried on.
- **The run state came back with no backend in it.** That is the one that has no
  recovery: the record is what the next plan reasons from, so nothing would ever
  try to stop it again. A failure an operator can read is recoverable; a
  forgotten access point is not.

The cause is one line in `netcfgd-hostapd`'s `stop`:

```rust
Err(_) => Ok(()),
```

with a comment justifying it that is true and does not cover it -- "nothing
listening is taken as nothing running, and that is safe *here* because hostapd's
`-B` returns only after the control interface is up". That reasoning is about a
socket that is **not there**. The match is over every error `connect` can
return, and `connect` opens with a `PING` (0085 put the deadline inside the
connect for exactly this daemon). So the failure it is most wrong about is the
one that has to travel furthest to be wrong: a `WouldBlock` off the read
timeout, eleven seconds in, from a daemon that is unambiguously alive.

The identical shape sat in `netcfgd-apply`'s supplicant stop, with the identical
comment.

## Decision

**Absence and silence are different answers, and one function decides which is
which.** `netcfgd_supplicant::nothing_is_listening` takes exactly two error
kinds: `NotFound`, which `connect` raises by name when the socket is not there,
and `ConnectionRefused`, which is the kernel's answer for a unix datagram
address left behind by a process that is gone. Everything else is a daemon that
is there, and a stop that could not be delivered is an error.

One function rather than two matching arms, because the two call sites are one
mechanism. Fixing either alone would leave the other reporting that a daemon had
stopped while it was still holding a radio.

**A failed stop is fail-stop**, and the rest follows from section 4 without any
further code: the apply halts at that action, says which of the two states it
found, and leaves the backend in the run state, so `ncfg apply` again retries
it. That last part is the fix's whole value and it is free.

Behaviour on the same probe afterwards:

```
apply exit: 1
  FAIL backend.stop ap0
       could not stop the access point on ap0: it is running and did not
       answer its control socket: Resource temporarily unavailable
  ncfg: stopped at action 3 (backend.stop); 3 done, 0 not attempted
  ncfg: re-run `ncfg apply` to resume from current state
run state backends: [access_point ap0 running]
```

**The ten-second wait before that failure is left alone.** It is `connect`'s
default reply timeout, generous because `SCAN_RESULTS` on a busy band is not
instant. A stop is not a scan and could reasonably use the one-second deadline
0085 gave the ACL read -- but shortening a deadline is its own decision with its
own measurements, and a stop happens when the document changes rather than on
every netlink event, so it does not hold the reconcile loop the way the ACL read
did. Recorded as open rather than changed in passing.

## The gates

**Live, on the state itself.** `acl.sh` already starts a socket that binds and
sleeps, to prove a wedged hostapd does not stall the reconcile loop. It is now
also asked to stop -- the same process, not a second one, because it is the only
thing in the suite that produces the state. Three checks: the stop is reported as
a failure, the message names which of the two states it found, and the access
point is still in the run state afterwards.

Reverting the classifier turns all three red, with `expected: failed, actual:
reported success` -- which is the sentence the defect deserves.

**A unit test for the classification**, because it is a pure function over
`io::ErrorKind` and needs no daemon. It asserts `WouldBlock` and `TimedOut` are
*not* absence, so a rewrite that widens the match has to delete an assertion
rather than merely relax a condition.

## What this says about the method

**The flake was the product telling the truth.** One run in ten, on a check
about a fake, in a script that had been green for weeks -- and the honest
diagnosis was that netcfgd reports a stop it did not perform. Two turns were
spent on test-side waiting before that, and one of them was right for a
different reason: an earlier section really was cold, and warming it took the
failure rate from five in eight to one in eight. That fix was correct and it was
also what made the remaining failure legible.

**A diagnostic taken after the failure describes the state afterwards.** The
first reading of this said the apply "did not converge for a reason no test-side
wait can fix", on the evidence that 0085's wedged-daemon warning was absent.
The warning was sampled after the run had failed, by which time the fake had
warmed up and was answering. It was evidence about the wrong moment.

**And the load was never the way to see it.** Saturating twelve cores produced
one failure in ten and a log that could be read two ways. `SIGSTOP` produced it
every time, in eleven seconds, with nothing to interpret. When a race is a state
rather than a timing, produce the state.
