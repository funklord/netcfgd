# 0255: there is no `ifb` to write

Status: accepted
Date: 2026-09-17
Milestone: M9; the window can configure the machine

## The kind that is not an operator's

`ifb` was the last entry on the device editor's refusal list, and the natural
next round would have been "add a form for it". That would have been wrong, and
the compiler says so in one line:

```quote from=crates/netcfgd-compile/src/lower.rs
is not a device kind
```

The config language refuses `kind = "ifb"` outright. One is **synthesised**, one
per interface that asks for `ingress_bandwidth`, because the kernel cannot queue
traffic on the way in -- by the time a packet can be classified it has already
arrived. The standard answer, and the only one, is to redirect everything
arriving onto an intermediate device where it has become egress and can be
shaped like anything else. netcfgd builds that device, names it `ifb-<link>`,
and gives it the rate.

So the gap was never the `ifb`. **It was the `qdisc` block that makes one**, and
that block had no field anywhere -- which also meant the device editor refused
to save any device carrying one at all.

## Queueing, in the window

A scheduler, a rate out and a rate in, on every kind of device: a cable, a
radio, a bridge, a tunnel can each be shaped.

* **kbit/s, not megabits.** An operator writes `20000 kbit` for a 20 Mbit link
  and `2500 kbit` for a 2.5 Mbit one; writing megabits would round the second to
  2 and shape somebody's line a fifth slow. The document holds bits, and a rate
  that is not a whole kbit -- somebody wrote `1234567bit` by hand -- is reported
  as unrepresentable rather than rounded, which is the rule every other field
  here follows.
* **A scheduler with no rate is ordinary** and writes no rate: `fq_codel` on a
  link whose speed nobody knows is the common case. A rate with no scheduler is
  refused, because there is nothing to shape with.
* **Only `cake` can shape arriving traffic**, which is the compiler's rule said
  beside the field rather than after a round trip -- ingress shaping puts `cake`
  on the `ifb`.
* **An empty `qdisc { }` is not nothing.** It compiles to a policy, and netcfgd
  then has an opinion about a queue nobody asked it to touch, so a device with
  no scheduler gets no block.

## The join: one block written, two read back

`qdisc { ingress_bandwidth = "8mbit" }` compiles into a scheduler on *this*
device plus an `ifb-<name>` device carrying the arriving rate. Reading it back
naively shows a device whose ingress rate has vanished -- it is on a device the
operator never wrote.

So the client joins the halves: a device with an `ingress_redirect` reads that
`ifb`'s own rate as its ingress rate. The operator wrote one block and sees one
block. Sabotaging the join -- reading `ingress_bandwidth_bits` off the device
itself, where it is never present -- is caught by the live probe.

And the `ifb` itself appears in the device list as what it is, with the editor
saying so rather than offering a form:

> ifb (netcfgd makes this one; shape the interface it belongs to)

## Five sabotages, all caught

An empty `qdisc` block written for a device with no scheduler; the rate written
in megabits and rounded; ingress shaping accepted with any scheduler; the
ingress rate read off the device rather than off its `ifb`; an `ifb` offering
itself for editing.

## What this closes

Every `device` key the model has is now reachable from the window, and every
link kind but the one no operator writes. The refusal list the device editor
carries is down to a single entry, and that entry is a sentence explaining who
made the device rather than a gap.
