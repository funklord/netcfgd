# 0057: A link kind is compared like a daemon

Status: accepted; the bridge is done and the other kinds are named, not built
Date: 2026-08-03
Milestone: [0054](0054-a-kernel-object-is-compared-like-a-daemon.md) again, in the kinds it did not look at

## Context

0054 found that a `WireGuard` device was configured inside `Op::LinkCreate` and
never afterwards, so an edited listen port did nothing and a deleted peer kept
its access. It fixed that kind and did not ask whether the shape repeated.

It repeats in every other kind. Everything the kernel takes as
`IFLA_INFO_DATA` -- a bridge's `stp` and `forward_delay`, a bond's `mode` and
`miimon`, a VLAN's id, a VXLAN's remote, a tunnel's endpoints -- goes over the
wire when the link is made and is never sent again. Measured before any of this
was written:

```
interface work-net { vlan { parent = "base0"; id = 42 } }   # apply
# edit the id to 43, under the same interface name
$ ncfg plan
nothing to do
$ ip -d link show work-net
vlan protocol 802.1Q id 42
```

**The common case hides it**, which is why it survived this long. A VLAN is
usually named for its id, so editing `base0.42` to `base0.43` renames the
interface, and a renamed interface is a create and a delete -- correct, visible,
and nothing to do with this. The operator who names a VLAN `work-net` is the one
who gets silence.

**A bridge has no such luck.** Its name encodes nothing, ever. `stp` and
`forward_delay` are the settings most likely to be edited on a bridge that is
already carrying traffic, and editing them produced an empty plan.

## Decision

**The bridge is done here; the other kinds are named and left.**

The observation reads the `INFO_DATA` nest back out of the link dump -- the same
nest the kind already comes from, one attribute along -- and carries it as
`ObservedLink::bridge`. The planner compares it against the document and emits
`link.set_bridge`, which the executor answers by calling the same function
`link.create` calls.

That last point is the one worth insisting on. The comment above the create path
has said since bridges arrived that a bridge's settings cannot ride along with
creation and that having one path rather than two is what stops the create case
and the correct-an-existing case drifting apart. It was true and there was only
ever one caller, so nothing was kept from drifting. Now there are two callers and
one function.

**Only what the document states is compared.** An absent `forward_delay` means
"whatever the kernel picked", and comparing that against the kernel's answer
would rebuild a bridge on every reconcile -- 0052's band rule, met for the third
time.

**Units live in one place each way.** The kernel counts hundredths of a second
and the document counts seconds. `netcfgd-sys` multiplies on the way out and the
observer divides on the way in, and neither does anything else.

## What is deliberately left

VLAN, VXLAN, bond, tunnel, macvlan and veth. Each needs its own `INFO_DATA`
decoding -- the numbering is per kind and decoding one kind's attributes with
another's constants is how a VXLAN comes to report a forward delay -- and each
wants its own live test against a real kernel. That is a session per two or
three kinds, not a paragraph.

The bridge is first because it is the one with no second signal, and because its
executor half already existed.

## Consequences

- Editing a bridge's `stp`, `forward_delay` or `hello_time` is planned, applied
  and reported. `link.set_bridge` is disruptive -- spanning tree converging is a
  bridge not forwarding for as long as the forward delay says -- so a plan says
  so, and `--allow-disruption` gates it like any other interruption.
- The op carries no values: the executor reads the settings from the document it
  was given, the way `wg.set_device` does. A plan is a statement about what
  moved, not a copy of the configuration.
- It has no inverse. What the bridge had is in the observation, but an inverse
  built from the document would re-apply what the document says *now*, which is
  a revert that changes nothing -- worse than saying there is none.
- The plan schema gains an op and the observed schema gains a struct; both
  witnesses moved. Minor additions.
- **A units error is invisible to a fixture.** The pure tests build an
  observation in model units, so the conversion is not on their path; breaking
  the divide leaves them green. `tests/live/links.sh` catches it, because there
  the observation comes from a real dump -- and what it asserts is that a bridge
  which was *just applied* plans nothing.
