# 0152: a SIM source is kept until the probe says otherwise

Status: accepted
Date: 2026-09-01
Milestone: M9; LTE, generalised from one board's bringup

[0150](0150-a-sim-source-is-chosen-the-way-an-uplink-is.md) settled that
choosing a SIM source belongs in netcfgd and that driving the mux does not. It
did not settle three things the policy cannot be written without, and this
record answers them. The holder's instruction was to pick defaults and record
them, so these are defaults chosen by a worker rather than requirements handed
down -- which is exactly why they are written here where a later reader can
disagree with something specific.

## What 0150 left open

- **When has a source failed?**
- **What happens when the last source fails?**
- **Does a working source stay selected, or is the first one retried?**

## The answers

### Registration is 0119's probe, not a new observation

**A source has failed when the interface's probe says the link does not
work.** netcfgd adds no cellular-specific notion of "registered".

The alternative was to watch for the link coming up, or for an interface report
to arrive, and both are weaker claims than they look. This is the case
`project.md` already records from the board that produced 0150: a modem
attached on the wrong APN produces a link that is up, reports an address, and
answers ICMP everywhere while blackholing every other SYN. A link-up test would
call that source good and stop, having switched away from the SIM that worked.

So the judgement is already built and already correct:
[0119](0119-a-probe-is-an-observation-and-a-failing-uplink-loses-its-routes.md)
runs the operator's program, counts `down_after` consecutive failures, and
withholds the routes. This record consumes that verdict and adds nothing to it.

**The consequence is worth stating plainly: a modem interface with no `probe`
block never falls back.** Its verdict is `None`, which 0119 defines as "nobody
asked", and taking a machine's SIM away on no information is exactly what that
rule exists to prevent. A board that wants fallback configures a probe, and the
probe should test the thing it actually needs rather than pinging a public
resolver.

### The last source is where it stops

**When the last source in the list fails, netcfgd stays on it and says so.** It
does not wrap around to the first.

Wrapping is the tempting answer and it is wrong twice. A machine whose
subscription has lapsed, or whose APN is wrong on both SIMs, would reset the
modem for ever at whatever period the probe sets -- and every reset takes the
link down, so the failure mode is a machine that is *permanently* offline
rather than one that is offline until somebody looks. It also destroys the
evidence: an operator arriving at a wrapping machine cannot tell which source
was tried last or how many times.

Stopping is honest. The selection stays where it ended, the file in `/run` says
which source that is, and the probe goes on reporting the link as down. Nothing
is hidden and nothing thrashes.

This is the same shape as
[0079](0079-netcfgd-stops-restarting-what-will-not-stay-up.md), which stops
restarting a backend that will not stay up, and for the same reason: a retry
loop with no ceiling converts a fixable fault into an unfixable one.

### The choice is sticky, and the configuration is never rewritten

**A source that is selected stays selected until its probe fails.** netcfgd
does not return to the first source when it starts working again, and does not
re-read the preference on every reconcile.

The alternative -- always try `sim[0]` first -- makes a machine on a marginal
primary SIM flap between sources at the probe's period, which is the
oscillation [0151](0151-a-profile-is-a-directory-and-it-is-switched-by-hand.md)
refuses for profiles and 0119's `hold_down` damps for uplinks. A SIM switch is
far more expensive than a route change: it resets the modem and drops the link.

**Constraint 1 is untouched by this and that is the point.** The ordered list
in the document is the operator's intent and netcfgd never writes to it. What
moves is a *runtime* choice in `/run`, which is derived and disposable by
constraint 1 and gone after a reboot -- so a cold start begins at the
preference again, which is the correct behaviour rather than an accident. This
is the distinction the component that solved this on one board had to
rediscover: it kept its state in `/data` only because nothing else was holding
observed state for it.

## How netcfgd says which source it wants

**A file in `/run`, not an environment variable**, because that is already this
project's contract with the things that touch hardware:

```
/run/netcfgd/modem/<device>
```

The mirror of `/run/netcfgd/reported/<interface>`, which
[the interface report](../interface-report.md) defines as the whole interface
between netcfgd and a helper -- no library, no socket, no bus. Same format,
`key=value` lines with `#` comments, written atomically through a temporary
file:

```
# wwan0, netcfgd's SIM selection
sim=esim
apn=im.cxn
```

A `pre_up` hook reads it and drives the mux. The APN is in the same file
because the hook that selects the source is the hook that starts the bearer,
and two files for one act would let them disagree about which SIM an APN
belongs to.

**Why not the hook environment.** `Op::HookRun` carries a single `value` that
the executor maps to one variable per phase, so two values would need the op to
grow a field, the plan witness to move, and a second mechanism to exist beside
the report contract. A file costs none of that, is readable with `cat` while
debugging, and is the shape a helper author already knows from
`doc/interface-report.md`.

**It is written for every device with a `modem` block**, including one with a
single source or none listed, so a hook can read it unconditionally rather than
having to tell "no file yet" from "no modem policy".

## What this does not do, and one gap that is not yet closed

It does not reset the modem, drive a GPIO, or know what a SIM source name
means. 0150 settled that and nothing here moves it: netcfgd writes down which
source it wants and why, and a hook makes the hardware agree.

**netcfgd does not cycle the interface when the selection advances, and until
it does the fallback is not automatic.** A `pre_up` hook runs when an interface
is brought up, and a link whose probe is failing is still up -- 0119 withholds
its routes rather than taking it down. So the new selection is published
immediately and is acted on at the *next* bring-up, which today means a reboot,
a `down`/`up`, or a helper that watches the file itself. The mbim helper's
`monitor` mode is the shape that would.

This is named rather than papered over because the obvious fix is worse than
the gap. Taking the link down needs an action the planner does not currently
produce: `link.down` today means `enabled = false`, and a second reason for it
has to go through the planner's `managed` choke point (0035) rather than being
assembled by hand in the daemon and handed to an executor. Building that in the
same pass as the policy would have put a hand-made action outside the one place
that decides what netcfgd is allowed to touch.

So the next piece is a planner-level reason to cycle a link, and it is the
thing that turns this from a published intention into an automatic fallback.
