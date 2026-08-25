# 0091: a roam is something the supplicant tells netcfgd

Status: accepted
Date: 2026-08-04
Milestone: the third of the four phases that did not fire

## Context

[0089](0089-a-station-picks-the-loudest-access-point-and-netcfgd-must-say-so.md)
made a station roam. Nothing told anybody it had. `roam` was one of the phases
recognised, materialised, hashed and never run, and
[0084](0084-the-drift-hook-fires-where-nothing-is-applied.md) left it with a
note: it "wants the supplicant's event socket rather than an observation".

That note was right, and worth re-checking rather than inheriting. The
alternative was to observe the associated BSSID and fire when it changed —
which is exactly the shape 0084 built for `drift`, so it would have been the
cheaper path. It is the wrong one here:

- netcfgd asks a station **nothing** during an observation today. That route
  means a `STATUS` round trip per radio on every netlink event — work added to
  the reconcile loop, needing its own deadline for the reason 0085's does.
- It can still miss. A station that moved and moved back between two
  observations moved twice and would be seen as never having moved.

`wpa_supplicant` will simply say so. Push beats poll when the thing being
watched is an event rather than a condition.

## Decision

**A watcher thread attaches to each radio's control socket and reports a
`CONNECTED` naming a different access point than the last one.**

`ATTACH` is per connection, not per supplicant, and that is the whole difference
between a connection that can watch a radio and one that can only interrogate
it. It is a separate call from `connect` deliberately: the request path *drops*
events while waiting for a reply, so a connection doing both would throw away
the ones that arrived at the wrong moment.

One thread for all radios, polled in turn with a short timeout: a machine with
two radios costs one thread, and a supplicant that goes away is picked up again
on a later pass rather than taking a thread with it.

**The first association is not a roam.** There is nothing to have moved from,
and firing then would run the hook on every boot.

**No de-duplication, unlike `drift`.** Drift is a condition that persists, so
firing on presence would run a script forever; that is why 0084 remembers what
it last said. A roam is a thing that happened once, and the watcher already
reports only a *change* of access point — so suppressing a repeat would mean a
station that moved back and forth told the script once.

`NCFG_BSSID` is the access point now in use. Not a veto phase: the move has
happened.

The event's shape is `wpa_supplicant`'s own, read out of the binary rather than
from documentation, which does not give it:

```
CTRL-EVENT-CONNECTED - Connection to %02x:...:%02x completed [id=%d id_str=%s%s]
```

The address is the fifth word, read positionally and then shape-checked. Keyed
on position rather than on the phrase "Connection to", because the prose is
prose and the format string is what fixes the shape.

## What the tests found

**The fake supplicant answered `FAIL` to `ATTACH`.** Its default is to fail
anything it does not model — deliberately, so an unmodelled command cannot look
like success. So the watcher attached, was refused, dropped the connection, and
reconnected on the next pass, forever. The fake's log showed `PING`/`ATTACH`
repeating.

The first version of the live check counted `ATTACH` and asserted 1 — and
**passed**, because it looked early enough that only one had happened yet. It
asserts exactly one now, at the start *and* at the end, which is the difference
between "it attached" and "it attached and stayed".

Nothing else here would have caught that: against a real supplicant the watcher
works, and the reconnect loop is correct behaviour for a supplicant that refuses.
What was wrong was a fake that refused something a real one accepts.

**A guard with no input that reached it.** `connected_bssid` checks the event's
name before reading the address, and the three negative cases in its test were
all rejected by the *shape* check instead — their fifth word is absent or not an
address. Deleting the name check left the test green. There is a case that
reaches it now: an event with an address in the fifth position and a different
name, which is a thing `wpa_supplicant` could add without asking.

## The gates

`tests/live/roam.sh`, against a running netcfgd — the second live script that
needs one, and for the same reason `drift.sh` does: this is not a plan action,
so no `ncfg apply` can exercise it. Seven checks: it attaches exactly once, the
first association is not a roam, a move runs the hook, the script is told the
interface and the new access point, moving back is a *second* roam, the same
access point again is not a move, and the connection was held throughout.

The supplicant is faked because the one thing this repository cannot produce on
demand is a radio, and a roam needs two access points to move between. The
protocol is not faked: the event is the real format string, and the fake sends
events only to connections that attached — so a netcfgd that forgot to attach
sees nothing there, exactly as it would against the real thing.

Against a real `wpa_supplicant` 2.10: an attached connection is sent unsolicited
traffic and an unattached one is not. Breaking `attach` to a no-op turns that
red. It does not produce a `CONNECTED`, which needs an association and therefore
a radio — 0014's standing limit, stated rather than implied.

## What is left

`pre_down` and `portal`. `pre_down` is deferred with a reason (0063): it and
`down` fire at the same point until there is a teardown ordering. `portal` has
no captive-portal detection anywhere in the tree, so there is nothing to fire it
from — the phase is a place to put a script, not a feature.
