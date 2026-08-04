# 0098: a supplicant that bound its socket and stopped answering

Status: accepted
Date: 2026-08-04
Milestone: 0085's stated gap, re-measured rather than believed

## Context

[0085](0085-a-daemon-that-does-not-answer-is-not-running-well.md) gave a backend
an `answering` field beside `running`, and closed with what it could not reach:

> A supplicant has a control socket and netcfgd does not read it during
> observation; giving it the same treatment is a real piece of work rather than
> a line, and it is worth doing when something wants the answer.

That was true when it was written and is not now, which is `project.md`'s own
lesson about notes in "what is still open" applying to a note this project
wrote. Three things changed underneath it:

- [0080](0080-a-socket-outlives-the-process-that-bound-it.md) added
  `Client::connect_within`, which **pings inside the connect** with a deadline
  as a parameter — built for exactly this, and its doc records a wedged
  supplicant measured at ten seconds;
- `netcfgd-observe` already depends on a backend crate, `netcfgd-hostapd`, for
  the one observation that is a question to another process. A second is
  symmetric rather than novel;
- the planner's warning was written with a fallback arm and a comment saying
  the fallback would hold *until a second kind gained a round trip*.

So the work is an observation pass and a noun.

**What it is for.** 0080 made a *dead* supplicant visible: it writes a pid file,
and a pid file naming nothing is a process that has gone. A **wedged** one has a
live pid, a socket on disk, and — from every other angle netcfgd has — looks
exactly like a supplicant that is working and has not associated yet. The plan
said everything was fine while the radio joined nothing.

## Decision

**Every running supplicant is asked, on every observation, whether it answers.**

Under a one-second deadline, for the same reason and with the same wording as
hostapd's access-control read: this is in the reconcile loop, so a supplicant
eating the ten-second reply timeout would hold that loop on every netlink
event. Being wrong impatiently costs a warning the operator can act on; being
wrong the other way stalls the daemon.

**Asked only of one netcfgd's record says is running.** A control socket
outlives the process that bound it, so the file alone would happily describe a
supplicant that exited an hour ago — the same guard, for the same reason, as
`read_access_control`.

**A warning and never a restart**, which is 0085's decision unchanged: netcfgd
cannot tell a wedged supplicant from a busy one, and acting on a missed deadline
would take working radios off the air on loaded machines.

**Its own noun.** The warning said "the backend on wlan0" through the fallback
arm. On a machine running both an access point and a supplicant that is the
least useful true thing available.

**One resolver for the control directory.** `NCFG_WPA_CTRL_DIR` and the default
path were written out three times — in `netcfgd-apply`, in the daemon, and in
the daemon's wifi commands — byte for byte identical. This needed a fourth, so
instead the crate that owns `DEFAULT_CTRL_DIR` owns the question, and the three
call it. Not a behaviour change; three copies of a path is three chances for
them to stop agreeing.

## The gates

Unit: a wedged supplicant is called a supplicant, exactly once. 0085's own
three-state test (`Some(false)` warns, `Some(true)` and `None` do not) already
covers the shape.

Live, `tests/live/wedged.sh`, against a socket rather than a mock — eight
checks over three states. The one that answers, the one that binds and says
nothing, and the one netcfgd's record calls stopped.

Four breaks:

- never asking — the state before this — fails three checks;
- the patient deadline instead of the impatient one fails the timing check at
  **10 seconds**, which is the number 0080's doc comment claims and this is the
  second measurement of;
- dropping the supplicant's noun fails the unit test and the live one;
- asking a supplicant the record calls stopped **passed at first**.

That fourth one is the finding. The planner skips a stopped backend whatever
the observation put in the field, so removing the observation's own guard
changes no plan — it just costs a round trip per pass to a process netcfgd
believes is gone, and a control socket outliving its process means that round
trip could even succeed. The check was named "is not asked, and not named" and
only verified the second half. It counts `PING`s in the fake's log now, which
required restarting the *answering* fake for that section: against the mute
socket, "never asked" and "asked and said nothing" produce the same silent plan.

## What the RSS gate turned out to be measuring

`make check` went red on `rss` for this change, and the reason was not the
change. The gate measured the **debug** binary, and adding an *unused*
dependency edge to a crate moves that figure by ~190 KB — on a binary whose
release build is byte-for-byte the same size.

Measured A/B interleaved, six runs each, because the first two batches were run
back to back and the drift between them was the same size as the effect:

| binary                    | debug        | release |
| ------------------------- | ------------ | ------- |
| before                    | 9011 KB      | 4307 KB |
| the unused dep edge alone | 9199 KB      | —       |
| with this change          | 9302 KB      | 4315 KB |

A 51 MB debug binary's resident set is dominated by metadata layout. The gate's
own comment says "section 10.4: under 4 MB resident", and the thing that section
is about was never the number being measured.

So the gate measures `target/release/netcfgd` now, which `size` already builds
and which runs before it in `check` — no extra cost. The limit is the observed
peak plus a noise band, as the previous comment asked for and was no longer
getting: HEAD had ~100 KB of headroom against ~350 KB of run-to-run spread,
which is a gate about to go red on noise.

**And it says something the old measurement was hiding:** the shipped daemon is
~4.3 MB resident, which is over section 10.4's stated 4 MB. Recorded rather than
fixed here; it is a different piece of work from a supplicant's liveness.

## What is left

hostapd's own liveness, which is 0080's open item for its own reason and is
unchanged: nothing here can run a real hostapd on a dummy interface, and code
with no test is what this project removes rather than adds.
