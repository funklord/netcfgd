# 0119: A probe is an observation, and a failing uplink loses its routes

Status: accepted
Date: 2026-08-07
Milestone: section 10 item 7

## Context

netcfgd chooses an uplink by **carrier** and never asks whether it works. A
cable plugged into a switch that has lost its own uplink has carrier and no
path: netcfgd keeps preferring it, and the wifi that does work sits at a worse
metric doing nothing.

`preference` is already the switching feature -- it becomes the route metric,
and the planner already **withholds a preference-ranked interface's routes
while it has no carrier**, because "a route down a cable that is not plugged in
is a black hole, and a lower metric would make the kernel prefer it over the
wifi that works".

That sentence is the whole design. A link that fails a reachability probe is a
black hole for the same reason and wants the same answer.

## Decision

**A probe is an observation, and a failing probe withholds routes exactly as a
missing carrier does.**

Concretely: `interface X { probe { ... } }` names a program. netcfgd runs it on
an interval, and its **exit status is the answer** -- zero is reachable. The
result joins observed state beside carrier and addresses, and the planner's
existing condition grows one term:

    preference.is_some() && (!has_carrier || probe_failing)

Nothing else moves. No new action, no new op, no second mechanism for choosing
an uplink, and `preference` keeps meaning what it meant.

### Why an exit status, and an arbitrary program

`ping`, `curl -f`, `wget -q` and a script an operator wrote already agree that
zero means it worked. That is why an arbitrary program is the right interface
here and not a lowered ambition: netcfgd would otherwise be choosing whose
definition of reachable is correct, and on a captive-portal network, a
split-horizon DNS site or a machine behind a proxy, the operator's definition
is the one that matters.

It is a **reference with a timeout**, the shape `HookRef` already has, and for
the reason section 2.2 gives: a document that can carry shell is remote code
execution with extra steps.

### Hysteresis is the feature, not a refinement

A probe-driven failover that flaps moves the default route under live
connections. So `up` and `down` are **consecutive-result counts in the config**,
not constants, and the default is asymmetric on purpose:

- **down: 3** -- three consecutive failures before routes are withheld. One
  lost packet is not an outage.
- **up: 2** -- two consecutive successes before they come back. Returning is
  cheaper to get wrong than leaving, and a link that has just failed three
  times deserves less trust than one that never failed.

Asymmetry is the point. Symmetric counts make a marginal link oscillate at
whatever period the interval sets.

## What this is not

**Not `portal_check`, and conflating them is a bug.**
[0095](0095-a-portal-check-fetches-the-operators-url.md) makes portal detection
plain `http://` **because** a portal intercepts and TLS prevents exactly that.
A reachability probe wants the opposite guarantee -- that it reached the real
destination -- so an operator's probe will often be `https` or a known
response. Two questions that look alike and want contrary transports. They stay
separate keys with separate defaults and neither is derived from the other.

**Not a health check for the machine.** It answers "does this *uplink* carry
traffic", and its only effect is on that interface's routes. It does not
restart backends, does not mark an interface down, and does not touch anything
another interface owns.

## The hazard, named

This changes the route the operator may be connected through, which is the
thing commit-confirm exists for -- except netcfgd initiates it, on a timer, with
nobody watching.

**It is deliberately not armed with a confirm window**, and the reasoning is
the asymmetry of the two failures. A confirm window protects against a change
that *breaks* connectivity, by reverting when nobody confirms. A probe-driven
withdrawal happens because connectivity is *already* broken: reverting it would
restore a route to a black hole, and "nobody confirmed" is exactly what a
machine whose uplink just died looks like. The window would fire on precisely
the evidence that the withdrawal was right.

What follows is that this feature can take a working route away on a bad probe,
and there is no timer that puts it back. That is why `down` defaults to three
and why the probe is the operator's own program: both of them are the brake.

## What this leaves open

- **Probing something other than an uplink.** Nothing here is specific to a
  default route, and the restriction to preference-ranked interfaces is
  deliberate caution rather than a discovered limit.

## Since accepted

Two of the three things this left open are built, and the design changed only
in the first.

**A hold-down**, as `hold_down` in the probe block, seconds, **zero by
default**. It is the minimum dwell a verdict must stand before it may change
again, and it exists because the counts are not the whole brake: a link that
alternates in *runs* -- three bad, two good, three bad -- satisfies both counts
and moves the default route on every cycle, just at a longer period than the
interval.

The dwell suppresses the *change* and not the running. The program keeps being
asked throughout, so the counts stay current and the moment the dwell expires
the verdict reflects what has been happening rather than one stale result from
when it started.

It defaults to zero deliberately, so the counts remain the only mandatory brake
and a machine that names no dwell behaves exactly as it did before this
existed. A dwell is something an operator adds once they have watched a link
misbehave, and its value is the period of the flapping they saw -- which is not
a number netcfgd can guess.

The test is the flapping link itself, alternating on every single run, and it
comes in a pair: with no dwell the verdict changes nearly every run, and with
one it changes once. The first is what makes the second mean anything, and
deleting the dwell enforcement was checked to turn the second red and leave the
first green.

**`ncfg explain` names the probe**, next to carrier rather than after the
addresses, because it answers the same question and is the harder one to guess
at: a link with carrier and no routes reads as a netcfgd bug until something
says a program was asked and said no. It names the command, so the output is
`/bin/false says it is not, so this interface's routes are not installed`
rather than a verdict with no author.
