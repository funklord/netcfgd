# 0023: netcfgd owns the root qdisc, and nothing below it

Status: accepted
Date: 2026-07-30
Milestone: M5

## Context

Queueing came up in the same breath as netfilter and switch VLANs: netcfgd now
configures multiple kinds of device, and the question was whether it should
also be setting qdiscs.

The easy half is whether it is in scope at all. A root qdisc is kernel state on
an interface netcfgd already owns, set over the rtnetlink socket it already
holds, and it is the same category of thing as the MTU: a property of how the
link behaves, not a service offered to other machines. Decision 0009's rule --
"netcfgd configures; it does not serve" -- admits it without argument.

The hard half is how much. `tc` is not one feature. It is a class hierarchy, a
filter language, an action framework and about thirty schedulers, and a
configuration language that covers it is larger than the one netcfgd has for
addressing. That is precisely the argument [0022](0022-netcfgd-may-own-one-nftables-table.md)
used to refuse a general firewall model, and it applies here unchanged.

## Decision

**netcfgd may set the root qdisc on an interface it manages: a named algorithm
and at most a rate. It does not create classes, filters or actions, and it does
not touch anything below the root.**

The line, in the same shape as 0022's:

> netcfgd sets how a link drains its queue, because that is a property of the
> link. It does not decide which traffic wins, because that is policy.

`qdisc = "fq_codel"` says how this interface should behave when it is
congested, and the answer does not depend on knowing anything about the
traffic. `tc filter ... match ip dport 22 flowid 1:10` is a statement about
which traffic matters more, and netcfgd has no model of that, exactly as it has
no model of risk.

### Why a rate is still inside the line

A shaped rate looks like the first step across it, and it is not. `bandwidth
100mbit` is a statement about the link -- what this DSL circuit actually
carries, as opposed to what the ethernet interface in front of it claims. It is
the same kind of fact as the MTU, and like the MTU it is something the operator
knows and the kernel cannot discover.

What makes it affordable is `cake`. Shaping normally means an HTB class tree
with filters underneath it, which is the machinery this record refuses. `cake`
shapes by itself: one qdisc, one rate, no classes and no filters. So the single
most valuable thing traffic control can do for a router -- fix bufferbloat on
the uplink -- happens to be the thing that fits in the narrow model. If it
needed a class tree it would have been left out.

### There is no "no qdisc"

Every interface always has one. Removing netcfgd's means the kernel puts
`net.core.default_qdisc` back, immediately, and there is no state in between.
So "delete" here is not deletion in the sense an address is deleted, and
nothing has to record what the default was in order to restore it.

What does need recording is whether netcfgd set the current one, for the same
reason as the `forwarding` sysctl: a qdisc carries no owner. An interface that
was already running `cake` when netcfgd first started is not netcfgd's to
reset, and an operator who deletes `qdisc` from the document should get the
kernel default back rather than silence.

### Bits in the config, bytes on the wire

`TCA_CAKE_BASE_RATE64` is bytes per second. Every human-facing tool, including
`tc` itself, takes bits. The conversion is a division by eight that nothing
validates: a rate sent in bits is accepted and shapes at one eighth of what was
asked for, which presents as a slow link rather than as a bug.

The model holds bits, the wire gets bytes, and the conversion happens in one
place each way. It was checked against `tc(8)` rather than against itself --
netcfgd wrote 100000000 and `tc qdisc show` reported `bandwidth 100Mbit`, and
then `tc` wrote `50mbit` and netcfgd read 50000000. A round-trip through
netcfgd alone proves nothing here, because a factor of eight wrong in both
directions round-trips perfectly.

## What is out

**Classful hierarchies.** HTB, HFSC, DRR and the class trees they carry. This
is where the configuration language explodes, and `cake` removes the main
reason to want them.

**Filters and actions.** `u32`, `flower`, `bpf`, `mirred`. Classification is
policy, and a filter that matched on `fwmark` would additionally depend on
something 0022 says netcfgd never sets.

**Ingress shaping.** Genuinely useful -- it is the other half of fixing
bufferbloat on an asymmetric line -- and out anyway, because it needs an `ifb`
device and a `mirred` redirect filter, which is the filter machinery this
record just refused. An operator who wants it has `pre_up`.

**Per-queue and multiqueue configuration.** `mq`, per-txq qdiscs, XPS. These
are driver tuning, and design section 8.4 already puts driver tuning with
`ethtool` rather than here.

## Consequences

**No new netlink protocol.** Unlike NAT, this is rtnetlink on the socket
netcfgd already has -- `RTM_NEWQDISC` is 36, and `struct tcmsg` is twenty
bytes. The cost is a message encoder and a dump decoder, not a subsystem.

**The observed side reads the qdisc back**, so `ncfg status` reports what the
kernel actually runs and a wrong rate is visible rather than assumed. This also
makes the qdisc a drift-detectable object like everything else.

**An unavailable scheduler fails loudly.** `cake` on a kernel without
`sch_cake` gives `ENOENT` on apply, which is the honest outcome; the
alternative is a plan that silently leaves the default in place on exactly the
machines that most need shaping.

**The rate is not validated against the link.** netcfgd will happily shape a
gigabit interface to 1 kbit, because it has no way to know what the circuit
behind it carries -- that is the operator's fact, which is why it is in the
config at all.

## Alternatives considered

**Model all of `tc`.** Rejected on the size of the language, and on the same
ground as a general firewall model: it is a different product. `tc` exists, and
an operator who needs a class tree needs `tc`'s full expressiveness, not a
lossy re-spelling of it.

**Shell out to `tc`.** Rejected for the reason 0014 gave about `iwctl` and 0022
repeated about `nft`: it makes a tool a dependency, and reading state back
means parsing human-facing output that is not a stable interface.

**Set `net.core.default_qdisc` instead**, and let every interface inherit it.
Tempting because it is one sysctl. Rejected: it is machine-wide, so it cannot
say "shape the uplink and leave the LAN alone", which is the only configuration
anybody actually wants. It also only affects interfaces brought up afterwards,
so its effect depends on ordering.

**A `bufferbloat = true` flag** that picks a qdisc automatically. Rejected as
the kind of magic that is unexplainable when wrong: the operator cannot tell
what it did, and the right answer differs between a LAN bridge and a shaped
DSL uplink. Naming the qdisc is barely longer and says what happened.
