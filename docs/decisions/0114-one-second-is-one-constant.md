# 0114: one second is one constant

Status: accepted
Date: 2026-08-06
Milestone: measuring the last claim 0112's sweep left unmeasured

## Context

0112's sweep found three callers still taking `Client::connect`'s ten-second
default, fixed one, and dismissed the other two in a sentence:

> Two are correct: `ncfg wifi` is an operator's command where a scan
> legitimately takes that long, and `populate_supplicant` talks to a supplicant
> it has just started.

The first half is right. The second is reasoning, not measurement, and this tree
has now recorded twice that such a claim is worth ten minutes -- 0079's "a
backoff needs state that needs a home" and 0111's "so it does not hold the
reconcile loop" were both accurate about the design and wrong about what was
happening.

## What the measurement said

`populate_supplicant` runs inside `start_backend`, on the apply path, so the
reconcile loop is what waits for it. "It has just started" is true and does not
help: `connect` proves the supplicant answered *one* `PING`, and everything
after that is a separate question.

Against a fake that answered the opening `PING` and then nothing:

```
  PING                     answered after 0.0s
  SET update_config 0      TIMED OUT after 10.0s
  ADD_NETWORK              TIMED OUT after 10.0s
```

So a supplicant that comes up and wedges costs the loop the full ten seconds at
the first real command -- the same order as the 12.2 seconds 0111 measured and
fixed, reached by a different route, and the connect's own deadline does not
cover it.

And from the other end, against a **real** `wpa_supplicant` on a dummy
interface, every command `populate_supplicant` sends:

```
  PING                             0.13ms
  SET update_config 0              0.07ms
  ADD_NETWORK                      0.07ms
  SET_NETWORK 0 ssid "example"     0.07ms
  SET_NETWORK 0 key_mgmt NONE      0.07ms
  ENABLE_NETWORK 0                 0.07ms
```

A one-second deadline is some four orders of magnitude beyond the worst of them.
There is no supplicant that is merely busy which this can fail.

## Decision

**`populate_supplicant` connects within `IMPATIENT`**, and the deadline matters
after the connect rather than during it -- `connect_within` sets the timeout on
the connection it returns as well as on its opening `PING`.

**And one second is one constant now.** Before this there were three: a private
`IMPATIENT` in `netcfgd-supplicant` for the observation, a private `IMPATIENT`
in `netcfgd-hostapd` for the ACL read, and `STOP_TIMEOUT` from 0111. Three
copies of `Duration::from_secs(1)` in two crates, each with its own doc comment
saying the same thing, and this change would have added a fourth use.

The consolidation is a rename rather than a decision, which is the point: every
caller arrived at one second independently -- 0085 for the ACL read, then the
observation, then 0111 for the stop -- before there was anything to share.
`IMPATIENT` is the name the tree chose first and it says *why* without
overclaiming *where*, which matters because the roam watcher is not on the
reconcile loop and wants the same impatience for a related reason.

## The gates

**A unit test times a command taken after the connect**, which is the half
`populate_supplicant` depends on and the half that is easy to lose: a deadline
covering only the connect leaves every later command on the default. It is timed
rather than merely checked for an error, because the wrong behaviour returns an
error too -- just far too late to matter.

Breaking it was where the interesting part was. **The first break did not
fail.** Setting the client's `timeout` field to the default changed nothing,
because the blocking is `recv` honouring the socket's *read timeout*, and
`self.timeout` governs only the deadline that skips unsolicited events inside
`request`. Two mechanisms, one of which looks like the one that matters.
Breaking `set_read_timeout` instead fails with `a command after the connect
waited 10.120029335s, so it took the default rather than the deadline the
connect was given`.

That is the third vacuous-looking gate in three days, and the first one whose
emptiness was in the *break* rather than the test. A break that leaves the
behaviour intact reads exactly like a test that cannot fail.

**Live**, once there was room to run it: `make live` green, 32 scripts, with
`wifi.sh` driving a real `wpa_supplicant` all the way through
`populate_supplicant` -- which is the path this change is on, and the only one
that exercises the shortened deadline against a daemon rather than a fake.

That run had to wait. `/tmp` on this machine is a 16 GB tmpfs and was 100% full
-- 8.3 GB held by another project's session, 1.8 GB by a second netcfgd session
-- and every live script takes its working directory from a hardcoded
`mktemp -d /tmp/...`, so nothing in the suite could run at all. Two unit tests
failed first with `StorageFull`, which is what a full disk looks like when you
are expecting a regression: `TMPDIR` pointed at disk turned them green again and
identified the cause.

**The live scripts ignoring `TMPDIR` is worth raising on its own.** A suite that
can only run in one directory cannot run beside anything else, and the failure it
produces names this change rather than the disk. Not fixed here -- it is thirty
scripts and a convention, so it belongs to a deliberate pass rather than to
whoever hit it.

## What this says about the method

**A dismissal in a sentence is a claim.** 0112 disposed of two callers in half a
line, and half of that half was wrong -- not badly wrong, and it would have
stayed wrong indefinitely, because nothing about the code looks suspicious. What
made it findable was that the sentence existed to be re-read.

The same shape as 0111 and 0079, three times now, and the tell has been the same
every time: **a claim about what would happen, written in the calm voice of
something already checked.**
