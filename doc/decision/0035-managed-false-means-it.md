# 0035: `managed = false` means it

Status: accepted
Date: 2026-07-31
Milestone: fixes a defect present since M1

## Context

`Device.managed` has carried this doc comment since the model was written:

> When false, netcfgd never touches this device at all.

It did not. The planner consulted the flag in exactly one place -- the filter
deciding which devices are radios -- and every other pass ignored it:

```
device probe0 { managed = false }
interface probe0 { kind = "dummy"; config = "10.5.5.1/24" }

  0  link.create probe0  kind: dummy (was <absent>)
  1  link.up probe0      enabled: true (was false)
  2  addr.add probe0     addressing[0]: 10.5.5.1/24 (was <absent>)
```

This is the escape hatch `doc/first-run.md` tells people to reach for when
handing an interface to another daemon, and the mechanism by which two network
managers are kept off each other's interfaces. It silently did nothing.

Found while implementing NM's `Device.Managed` property, which cannot be
truthful until this is.

## Decision

**Enforced in `Builder::push`, which every action goes through.**

Not guarded at each of the eleven passes that can emit an action against an
interface. That would work today and fail the first time somebody adds a
twelfth, because a new pass has no reason to know it must ask. The codebase
already uses this reasoning for guards and for `Ownership::may_remove`; this is
the same shape of problem and gets the same answer.

`Op::interface()` names the interface for every per-interface operation, so one
check covers link creation, addressing, routes, backends, offloads, qdiscs,
ingress, forwarding, bridge VLANs, hooks and **teardown** -- teardown being the
one that matters most, and the one a per-pass guard would most likely have
missed.

`dns.apply` is the single exception: DNS delivery is host-wide, so it names no
interface and `push` cannot see it. `plan_dns` asks directly.

## Walking away means walking away

A device that netcfgd configured *before* the flag was set is left exactly as
it is. No teardown, no drift reconciliation, nothing.

The alternative -- release what we own, then stop -- would mean that marking
something unmanaged briefly disrupts it, which is the opposite of what the flag
is reached for. You set `managed = false` because something else is about to
take over, and having netcfgd pull the addresses out on its way past is the
failure the flag exists to prevent.

A `pre-unmanage` hook, so an operator can say what should happen at the
transition, is a good idea and is deliberately not in this decision. It is
noted here so the next person finds the thought rather than re-deriving it.

## What walking away strands, and why the warning says so

Three of the things left behind hold credentials:

- A **WireGuard private key** is set into the kernel by `wg.set_device` and
  stays loaded on the interface.
- A **supplicant** netcfgd started keeps every passphrase it was handed over
  the control socket (decision 0015 means netcfgd put them there).
- A running **hostapd** keeps its generated configuration under `/run`, which
  holds the passphrase at 0600 (decision 0026).

None of those is removed, because removing them is an operation and the flag
says not to operate. That is the right steady-state answer and an incomplete
answer for the *transition*, which is a separate question this decision does
not settle -- see 0036's roadmap note.

What is settled is that the plan says so. The warning names the three cases
rather than saying "left as it is", because an operator marking a device
unmanaged in order to hand hardware to somebody else needs to know a key is
still on it. A plan that stays quiet about that is the failure this project
keeps refusing to ship.

## The shim follows

`org.freedesktop.NetworkManager.Device.Managed` now reads the document, and an
unmanaged device reports `NM_DEVICE_STATE_UNMANAGED` whatever else is true of
it -- including when it has an address and is working, because netcfgd is not
the reason it is. That is NM's own idiom: a client shows the device and offers
nothing, rather than offering a connect button that quietly does nothing.

This is the first piece of design section 9.5's tier 3 done honestly rather
than by omission.
