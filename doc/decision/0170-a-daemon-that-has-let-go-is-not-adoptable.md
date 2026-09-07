# 0170: a daemon that has let go of its socket is not adoptable

Status: accepted
Date: 2026-09-07
Milestone: M8; narrows
[0140](0140-a-handle-must-be-recoverable-from-the-process.md) and extends the
reachability rule
[0141](0141-a-wedged-backend-fails-loudly-and-is-restarted-only-when-asked.md)
started

## What happened

`tests/live/openvpn.sh` failed one check in about one run in three:

    FAIL a daemon that refuses to stop is reported, not recorded as stopped
           expected: 1
           actual:   0

The apply that should have been refused said `nothing to do`. Instrumented,
the apply before it said this:

    netcfgd: adopted the OpenVpn backend already running on vpn0 (pid 21748);
    it is netcfgd's, by the `.../run/openvpn/vpn0.sock` it was started with
    and the privilege it runs with

pid 21748 was the tunnel the *previous* section had stopped. It had already
unlinked its management socket and its pid file, and had not yet exited.

## The window

A daemon told to stop lets go before it is gone. openvpn unlinks the
management socket, unlinks the pid file, and then takes its time over the
rest of its shutdown. For that time it is:

  * alive, so `/proc` has it and it is not a zombie;
  * carrying netcfgd's socket path in its own `argv`, so `pid_by_marker`
    matches it;
  * unreachable, because the socket it is named by is gone.

`adopt_running_backend` asked the first two questions and not the third. It
wrote that pid into the pid file, reported the tunnel started, and **started
nothing**. The daemon then finished exiting, so the next apply found a dead
pid, planned no stop, and said there was nothing to do -- about a tunnel that
had never come back.

## The rule this should have had

0141 already wrote it, for the supplicant: a process carrying netcfgd's
marker that cannot be reached is not an adoption candidate, it is a corpse
holding a radio. `backend_is_reachable` implemented that for
`BackendKind::Supplicant` and answered `true` for every other kind, with a
reason that was right at the time -- a probe that has never seen its failure
is one nobody should trust, and no other kind's failure had been seen.

openvpn's has been seen now, so openvpn gets the probe and nothing else does.
The check is the cheapest one available and it is exact: connect to the
management socket and drop it. No command is sent, because the connect is the
whole question.

**This is not the probe [0158](0158-a-marker-is-a-claim-not-a-credential.md)
rejected.** That record turned one down as a defence against an *impostor* --
a process carrying netcfgd's marker that netcfgd never started -- and it was
right to: a probe says a process works, not that it is netcfgd's, and an
impostor that answers would pass it. The uid rule is what answers that
question and it still does. This one answers the other question 0158 named as
worth having and separate: whether the process netcfgd has established is its
own is any use to it.

**The two questions are one question here, which is what makes declining
safe.** The marker *is* the management socket. Unreachable therefore means
the path is free, so the `start` that follows a refusal binds where the
daemon that is leaving cannot -- there is no window in which netcfgd declines
to adopt and then collides with what it declined.

## Why it was not caught

The suite worked around it. `settle` between sections waits for every fake to
be gone precisely because a leftover in this state confused netcfgd, and the
note above it names this signature exactly: "a leftover that had already
removed its socket made netcfgd adopt it and bind no socket at all, so a
teardown found nothing running and planned nothing -- which is the `nothing
to do` the refusal check reported for months." The mechanism was written
down. What was missing is that it was read as a property of the test rather
than of netcfgd, and the one place with no `settle` between a stop and a
start went on failing intermittently.

**A race waited for is not a race tested.** The regression check asks the
fake for the window instead: `FAKE_OPENVPN_EXIT_DELAY` holds the daemon
between letting go and exiting, which is the same kind of knob
`FAKE_OPENVPN_BIND_DELAY` already is at the other end of the life. The window
then arrives on every run rather than one in three.

It carries its own control, because every assertion under it would pass on a
machine where the window never opened: the section asserts that the stopped
tunnel has let go of its socket **and is still running**, before it asks
anything about adoption.

## Measured

    with the fix reverted    the check fails, naming adoption:
                             `a daemon that cannot be reached is not adopted`
                             expected 0, actual 1
    with the fix             8 runs of openvpn.sh, 0 failures

Before it, the same script failed the refusal check on 2 of 3 runs.
